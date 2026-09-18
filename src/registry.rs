//! Two-tier fan-out.
//!
//! ```text
//!   engine  --1 pull per content id-->  EngineStream
//!                                          |  raw MPEG-TS
//!                    +---------------------+---------------------+
//!                    v                                           v
//!            Encoder (adts)   <-- 1 ffmpeg per format -->  Encoder (fmp4)
//!                    |                                           |
//!            +-------+-------+                           +-------+
//!            v               v                           v
//!        listener        listener                     listener
//! ```
//!
//! Lifetime is refcounted downward: a `Subscription` holds `Arc<Encoder>`, an
//! `Encoder` holds `Arc<EngineStream>`, and the registry holds only `Weak`s. So
//! the last listener leaving an encoder tears down its ffmpeg, and the last
//! encoder leaving a content id closes the engine connection.
//!
//! Not immediately, though. A reconnect is the common case for a live viewer —
//! a phone changing networks, a player restarting, a listener evicted for
//! falling behind — and a cold start costs the engine's swarm discovery, which
//! is 10–25s. So the last leaver's `Arc` is held for a **linger** period on a
//! detached thread (see [`linger_encoder`] and [`linger_engine`]): the encoder
//! keeps running with no listeners, and the engine pull keeps pulling with no
//! encoders, until either a new listener claims them or the period lapses.
//!
//! # Locking rule
//!
//! Never drop an `Arc<Encoder>` while holding `EngineStream::encoders`.
//! `Encoder::drop` takes that same lock to deregister itself, so doing this
//! self-deadlocks. Use [`EngineStream::live_encoders`], which upgrades under the
//! lock and returns after releasing it.
//!
//! Where `encoders` and `replay` are both needed, `encoders` is taken first
//! (see `start_encoder`). The puller never holds them together — it appends to
//! `replay` and releases it before touching `encoders` — so that ordering is
//! the only one in play and no cycle exists.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::engine::{self, log, Session};
use crate::format::{self, OutputFormat};
use crate::mp4;
use crate::probe::Probe;
use crate::replay::{Policy, Replay};

/// Read size for the engine pull and for ffmpeg output. A pipe read returns as
/// soon as any data is there, so this is an upper bound, not a batching delay.
const CHUNK: usize = 64 * 1024;
/// How much of the engine stream ffprobe gets when the PMT could not name the
/// source. Sized to match ffprobe's `-probesize`.
const PREROLL: usize = 256 * 1024;
/// Per-encoder raw-TS backlog. Bounded deliberately small: the response to a
/// full queue is backpressure onto the engine socket, not buffering.
const TS_QUEUE: usize = 64;
/// How long an encoder may go without consuming *any* raw TS before it is
/// torn down.
///
/// Only lack of progress counts, not a full queue. An AceStream engine
/// prebuffers tens of megabytes and then releases the lot at link speed, so at
/// stream start the queue fills instantly through no fault of the encoder.
/// Blocking the puller is the correct response: it stops reading, TCP flow
/// control throttles the engine, and the burst drains at the rate the encoders
/// can actually consume. An encoder that is draining, however slowly, is never
/// torn down; one whose ffmpeg has stopped reading is, after this long.
const TS_STALL: Duration = Duration::from_secs(8);
/// A listener further behind the encoder than this is disconnected. See
/// `Encoder::fan_out`.
const SUB_MAX_LAG: Duration = Duration::from_secs(8);
/// Memory guard on a listener's unsent backlog, for when the lag bound has not
/// yet tripped (a burst of many fragments at once).
const SUB_MAX_BYTES: usize = 16 * 1024 * 1024;
const STATS_INTERVAL: Duration = Duration::from_secs(5);
/// How long a request will wait for a cold stream to connect and probe.
const START_TIMEOUT: Duration = Duration::from_secs(45);
/// How long an fMP4 joiner waits for the first fragment. A fragment closes on a
/// keyframe, so this must comfortably exceed the source GOP.
const INIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds on the replay window of raw TS kept per engine pull. It must hold at
/// least one GOP plus the video analysis window, so that a new video encoder
/// can be primed from a keyframe with enough behind it; the byte cap only
/// guards memory on a very high-bitrate source. See `replay`.
const REPLAY_MAX_AGE: Duration = Duration::from_secs(12);
const REPLAY_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Raw TS replayed into a new audio encoder: its 1s analysis window plus
/// margin, from wherever that lands. Audio needs no keyframe.
const AUDIO_TAIL: Duration = Duration::from_millis(1500);
/// Content a cold video encoder is primed with when the window can supply it:
/// the keyframe-start analysis window (2s, see `format::probe_window`) plus
/// margin so ffmpeg's analysis completes from the buffer. Also the encoder's
/// steady lag behind live, so kept as small as the analysis allows.
const PRIME_CONTENT: Duration = Duration::from_millis(2500);
/// How long the first video encoder on a cold pull will wait for the window to
/// reach `PRIME_CONTENT`. Only spent while the engine is bursting faster than
/// real time (which is what makes the wait pay off); a real-time source stops
/// it after `BURST_SAMPLE`, so it never delays startup beyond that.
const PRIME_WAIT: Duration = Duration::from_secs(3);
/// The shortest window over which "arriving faster than real time" is judged,
/// and so the most a non-bursting source is ever delayed by the wait above.
const BURST_SAMPLE: Duration = Duration::from_millis(150);

/// Lock, recovering from poisoning. A request thread that panics must not
/// take every other listener's stream down with it — which is why the binary
/// is not built with `panic = "abort"` — and a poisoned mutex would do exactly
/// that on the next lock. Nothing guarded here is left half-updated by a
/// panic: every critical section is a single push, remove or read.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_pid() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("proxy-{nanos:x}")
}

/// A thread name prefix from a content id.
fn short(content_id: &str) -> &str {
    &content_id[..8.min(content_id.len())]
}

#[derive(Debug, Clone)]
enum Start {
    Pending,
    Ready,
    Failed(String),
}

pub struct Config {
    pub engine_host: String,
    pub frag_duration_ms: format::FragDurationMs,
    /// How long an encoder outlives its last listener. Zero disables.
    pub encoder_linger: Duration,
    /// How long an engine pull outlives its last encoder. Zero disables.
    pub engine_linger: Duration,
}

// ---------------------------------------------------------------------------
// Tier 1: one engine pull per content id
// ---------------------------------------------------------------------------

/// The puller's handle on one encoder.
struct Feed {
    encoder: Weak<Encoder>,
    /// Sender side lives here alone: dropping the entry closes the channel,
    /// which is how a wedged encoder gets torn down.
    tx: SyncSender<Bytes>,
    /// Bytes the feeder has written into ffmpeg so far; the puller's evidence
    /// that a full queue is draining.
    fed: Arc<AtomicU64>,
}

pub struct EngineStream {
    pub content_id: String,
    pub started: Instant,
    pub bytes_in: AtomicU64,
    session: OnceLock<Session>,
    probe: OnceLock<Probe>,
    /// A clone of the pull socket, kept solely so teardown can interrupt a
    /// puller blocked in a 30s read instead of leaving the engine connection
    /// open until it times out.
    socket: OnceLock<TcpStream>,
    stats: Mutex<Option<(Instant, serde_json::Value)>>,
    /// Trailing raw TS, from which each new encoder is primed.
    replay: Mutex<Replay>,
    /// Signalled by the puller after each push, so a video encoder waiting for
    /// the window to buffer enough to prime from a keyframe wakes promptly.
    replay_progress: Condvar,
    encoders: Mutex<HashMap<OutputFormat, Feed>>,
    /// Serialises get-or-create so two simultaneous requests for the same
    /// format cannot both spawn an ffmpeg. Held only by would-be creators, so
    /// the puller is never blocked behind a process spawn.
    creating: Mutex<()>,
    start: (Mutex<Start>, Condvar),
    config: Arc<Config>,
}

impl EngineStream {
    pub fn probe(&self) -> Option<&Probe> {
        self.probe.get()
    }

    pub fn stats(&self) -> Option<serde_json::Value> {
        lock(&self.stats).as_ref().map(|(_, v)| v.clone())
    }

    fn stat_url(&self) -> Option<String> {
        self.session.get().and_then(|s| s.stat_url.clone())
    }

    /// Upgrade every live encoder, releasing the lock before the returned
    /// `Arc`s can drop. See the locking rule in the module docs.
    pub fn live_encoders(&self) -> Vec<Arc<Encoder>> {
        let map = lock(&self.encoders);
        let live: Vec<_> = map.values().filter_map(|f| f.encoder.upgrade()).collect();
        drop(map);
        live
    }

    /// True while the pull is being kept alive with no encoder on it.
    pub fn lingering(&self) -> bool {
        lock(&self.encoders).is_empty()
    }

    /// Append a chunk to the replay window and wake anyone waiting to prime.
    fn feed_replay(&self, chunk: Bytes) {
        lock(&self.replay).push(chunk);
        self.replay_progress.notify_all();
    }

    /// Give the first video encoder on a cold pull a brief chance to start from
    /// buffered content instead of waiting on live data. Returns as soon as the
    /// window holds [`PRIME_CONTENT`] after a keyframe; or the source proves to
    /// be arriving no faster than real time, so waiting cannot help; or
    /// [`PRIME_WAIT`] elapses. A warm encoder, an audio format, or a source
    /// with no video track skip it entirely.
    fn wait_video_prime(&self, fmt: OutputFormat) {
        if !fmt.has_video() || lock(&self.encoders).contains_key(&fmt) {
            return;
        }
        let mut replay = lock(&self.replay);
        if !replay.has_video() {
            return; // nothing to align to; audio-only inside an fMP4 request
        }
        let start = Instant::now();
        let base = replay.latest_video_pts();
        loop {
            if replay.video_prime_ready(PRIME_CONTENT) {
                return;
            }
            let elapsed = start.elapsed();
            if elapsed >= PRIME_WAIT {
                return;
            }
            // Keep waiting only while content is arriving faster than it plays:
            // that burst is what lets the window reach PRIME_CONTENT in a
            // fraction of the wall time. A real-time source gains nothing.
            if elapsed >= BURST_SAMPLE && replay.content_growth(base) <= elapsed {
                return;
            }
            let left = PRIME_WAIT.saturating_sub(elapsed).min(BURST_SAMPLE);
            let (g, _) = self
                .replay_progress
                .wait_timeout(replay, left)
                .unwrap_or_else(|e| e.into_inner());
            replay = g;
        }
    }

    fn wait_ready(&self) -> Result<(), String> {
        let (lk, cv) = &self.start;
        let mut state = lock(lk);
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            match &*state {
                Start::Ready => return Ok(()),
                Start::Failed(e) => return Err(e.clone()),
                Start::Pending => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("timed out waiting for the engine stream to start".into());
            }
            let (s, _) = cv
                .wait_timeout(state, left)
                .unwrap_or_else(|e| e.into_inner());
            state = s;
        }
    }

    fn publish(&self, outcome: Result<(), String>) {
        let (lk, cv) = &self.start;
        let mut state = lock(lk);
        *state = match outcome {
            Ok(()) => Start::Ready,
            Err(e) => Start::Failed(e),
        };
        cv.notify_all();
    }
}

impl Drop for EngineStream {
    fn drop(&mut self) {
        // Unblock the puller immediately rather than waiting out its read
        // timeout; it will see the closed socket, stop the engine session and
        // exit.
        if let Some(s) = self.socket.get() {
            let _ = s.shutdown(Shutdown::Both);
        }
        log::info(&format!("{}: engine stream closed", self.content_id));
    }
}

/// Keep an engine pull alive for the configured linger after its last encoder
/// has gone, so a viewer who reconnects skips swarm discovery. The puller keeps
/// filling the replay window meanwhile, so the rejoin also primes instantly.
fn linger_engine(stream: Arc<EngineStream>) {
    let d = stream.config.engine_linger;
    if d.is_zero() {
        return;
    }
    let name = format!("linger-{}", short(&stream.content_id));
    log::info(&format!(
        "{}: no encoders; keeping the engine pull for {}s",
        stream.content_id,
        d.as_secs()
    ));
    // If the thread cannot be spawned the closure drops with the Arc, which
    // is simply the un-lingered teardown.
    let _ = thread::Builder::new().name(name).spawn(move || {
        thread::sleep(d);
        drop(stream);
    });
}

/// The puller: one thread per content id, holding the sole engine connection.
fn pull(stream: Weak<EngineStream>, content_id: String, config: Arc<Config>) {
    let pid = now_pid();
    let session = match engine::open_session(&config.engine_host, &content_id, &pid) {
        Ok(s) => s,
        Err(e) => {
            if let Some(s) = stream.upgrade() {
                s.publish(Err(e));
            }
            return;
        }
    };
    // Kept on the thread so teardown can stop the engine session even as the
    // EngineStream is being dropped out from under us.
    let command_url = session.command_url.clone();
    let stop_engine = || {
        if let Some(url) = &command_url {
            engine::send_stop(url);
        }
    };

    let mut resp = match engine::get(&session.playback_url, engine::STALL_TIMEOUT) {
        Ok(r) if r.status == 200 => r,
        Ok(r) => {
            if let Some(s) = stream.upgrade() {
                s.publish(Err(format!("engine returned http {}", r.status)));
            }
            stop_engine();
            return;
        }
        Err(e) => {
            if let Some(s) = stream.upgrade() {
                s.publish(Err(format!("could not open engine stream: {e}")));
            }
            stop_engine();
            return;
        }
    };

    // Register the socket before the first blocking read, so a teardown during
    // startup interrupts the puller rather than waiting out the stall timeout.
    match stream.upgrade() {
        Some(s) => {
            if let Ok(sock) = resp.socket.try_clone() {
                let _ = s.socket.set(sock);
            }
        }
        None => {
            stop_engine();
            return;
        }
    }

    // Identify the source from its PMT as the first packets arrive. Every
    // format and every later listener reuses the answer. ffprobe over a
    // preroll is only the fallback, for a stream the scanner cannot name.
    let mut buf = vec![0u8; CHUNK];
    let (probed, how) = match identify(&mut resp.body, &stream, &mut buf) {
        Ok(found) => found,
        Err(e) => {
            if let Some(s) = stream.upgrade() {
                s.publish(Err(e));
            }
            stop_engine();
            return;
        }
    };

    {
        let Some(s) = stream.upgrade() else {
            stop_engine();
            return;
        };
        let _ = s.session.set(session);
        log::info(&format!(
            "{}: engine stream up, video={} audio={} ({how})",
            content_id,
            probed.video.as_deref().unwrap_or("none"),
            probed.audio.as_deref().unwrap_or("none"),
        ));
        let _ = s.probe.set(probed);
        s.publish(Ok(()));
    }

    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match resp.body.read(&mut buf) {
            Ok(0) => {
                log::info(&format!("{content_id}: engine closed the stream"));
                break;
            }
            Ok(n) => n,
            Err(e) => {
                // A read timeout here is the stall guard that -rw_timeout used
                // to provide inside ffmpeg. But teardown also breaks this read,
                // by design — EngineStream::drop shuts the socket down so the
                // puller stops promptly — and that is not a failure worth
                // reporting. If the stream is already gone, this is that.
                if stream.upgrade().is_some() {
                    log::warn(&format!("{content_id}: engine read failed: {e}"));
                }
                break;
            }
        };

        // Liveness is the Arc, never the encoder map: the map is legitimately
        // empty between `wait_ready` returning and the first encoder
        // registering, and while the pull lingers.
        let Some(s) = stream.upgrade() else { break };
        s.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        let chunk = Bytes::copy_from_slice(&buf[..n]);
        s.feed_replay(chunk.clone());

        // Snapshot the senders so the lock is not held across a blocking send.
        // Never upgrade the Weak<Encoder> here either: dropping the last Arc
        // under this lock would re-enter Encoder::drop and deadlock.
        let targets: Vec<(OutputFormat, SyncSender<Bytes>, Arc<AtomicU64>)> = {
            let map = lock(&s.encoders);
            map.iter()
                .map(|(f, feed)| (*f, feed.tx.clone(), feed.fed.clone()))
                .collect()
        };

        let mut wedged = Vec::new();
        for (fmt, tx, fed) in &targets {
            if let Err(reason) = send_backpressured(tx, fed, chunk.clone()) {
                wedged.push((*fmt, reason));
            }
        }

        if !wedged.is_empty() {
            let mut map = lock(&s.encoders);
            for (fmt, reason) in wedged {
                if map.remove(&fmt).is_some() && reason != "gone" {
                    log::error(&format!("{content_id}/{fmt}: encoder {reason}; torn down"));
                }
            }
        }
    }

    stop_engine();
}

/// Read from the engine until the source is identified, feeding the replay
/// window as we go so nothing read here is lost to the encoders.
///
/// The PMT settles it within the first packets. If it has not by
/// [`PREROLL`] bytes — a first audio stream the scanner cannot name — ffprobe
/// gets what was read so far.
fn identify(
    body: &mut impl Read,
    stream: &Weak<EngineStream>,
    buf: &mut [u8],
) -> Result<(Probe, String), String> {
    let mut preroll: Vec<u8> = Vec::new();
    loop {
        let n = match body.read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(format!("engine stream failed during preroll: {e}")),
        };
        let s = stream.upgrade().ok_or("stream torn down during startup")?;
        s.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        let chunk = Bytes::copy_from_slice(&buf[..n]);
        if preroll.len() < PREROLL {
            preroll.extend_from_slice(&chunk);
        }
        let program = {
            let mut replay = lock(&s.replay);
            replay.push(chunk);
            replay.program()
        };
        s.replay_progress.notify_all();
        if let Some(p) = program {
            return Ok((
                Probe::from(p),
                format!("from the PMT, {} bytes in", preroll.len()),
            ));
        }
        if preroll.len() >= PREROLL {
            break;
        }
    }
    if preroll.is_empty() {
        return Err("engine stream ended before sending anything".into());
    }
    let probed = crate::probe::run(&preroll).map_err(|e| format!("could not probe stream: {e}"))?;
    Ok((probed, format!("ffprobe over {} bytes", preroll.len())))
}

/// Hand a chunk to one encoder, waiting for room rather than giving up.
///
/// This is the opposite policy from [`Encoder::fan_out`], deliberately. Evicting
/// a *listener* costs that listener alone and it can reconnect; dropping an
/// *encoder* kills every listener on it and restarts ffmpeg. So here the puller
/// blocks — which is also the only way to signal the engine to slow down — and
/// only gives up once the encoder has made no progress at all for [`TS_STALL`].
fn send_backpressured(
    tx: &SyncSender<Bytes>,
    fed: &AtomicU64,
    chunk: Bytes,
) -> Result<(), &'static str> {
    let mut seen = fed.load(Ordering::Relaxed);
    let mut deadline = Instant::now() + TS_STALL;
    let mut chunk = chunk;
    loop {
        match tx.try_send(chunk) {
            Ok(()) => return Ok(()),
            // ffmpeg exited and its feeder went with it.
            Err(TrySendError::Disconnected(_)) => return Err("gone"),
            Err(TrySendError::Full(returned)) => {
                let now = fed.load(Ordering::Relaxed);
                if now != seen {
                    seen = now;
                    deadline = Instant::now() + TS_STALL;
                } else if Instant::now() >= deadline {
                    return Err("stopped consuming input");
                }
                chunk = returned;
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tier 2: one ffmpeg per (content id, output format)
// ---------------------------------------------------------------------------

struct Listener {
    id: u64,
    /// Unbounded on purpose: the bound is bytes and lag, enforced in
    /// `fan_out`, not a chunk count that means 45KB of audio and 4MB of video.
    tx: Sender<(u64, Bytes)>,
    /// Bytes sent but not yet taken by the request thread.
    queued: Arc<AtomicUsize>,
    /// Arrival time (nanos on the encoder clock) of the chunk the request
    /// thread most recently took.
    consumed_at: Arc<AtomicU64>,
    /// Arrival time of the chunk that was sent while the queue was empty, i.e.
    /// the oldest unread one, until the reader has passed it.
    oldest_unread: u64,
    /// fMP4 only: true until this listener has been aligned to a keyframe `moof`.
    awaiting_fragment: bool,
    peer: String,
    joined: Instant,
    bytes: Arc<AtomicU64>,
    /// The listener's own socket, so eviction can unblock a request thread
    /// stuck in a write instead of leaving it there until the write times out.
    kick: Option<TcpStream>,
}

impl Listener {
    fn kick(&self) {
        if let Some(s) = &self.kick {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

pub struct Encoder {
    pub content_id: String,
    pub fmt: OutputFormat,
    pub started: Instant,
    pub bytes_out: AtomicU64,
    pub video: format::TrackMode,
    pub audio: format::TrackMode,
    /// Cached fMP4 init segment, replayed to every late joiner. Joiners block
    /// on `init_ready` until the first `moof` has been written.
    init: Mutex<Option<Bytes>>,
    init_ready: Condvar,
    /// Set if the fMP4 byte stream did not parse; late joiners are refused
    /// rather than served something they cannot decode.
    unjoinable: AtomicBool,
    /// Set when ffmpeg's output ends, so joiners stop waiting on an init
    /// segment that will never arrive.
    finished: AtomicBool,
    listeners: Mutex<Vec<Listener>>,
    next_id: AtomicU64,
    child: Mutex<Option<Child>>,
    engine: Arc<EngineStream>,
}

impl Encoder {
    #[cfg(test)]
    fn listener_count(&self) -> usize {
        lock(&self.listeners).len()
    }

    pub fn listener_info(&self) -> Vec<(String, u64, u64)> {
        lock(&self.listeners)
            .iter()
            .map(|l| {
                (
                    l.peer.clone(),
                    l.joined.elapsed().as_secs(),
                    l.bytes.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// True while ffmpeg is being kept alive with no listener on it.
    pub fn lingering(&self) -> bool {
        lock(&self.listeners).is_empty()
    }

    /// Nanoseconds since the encoder started: the clock listener lag is kept in.
    fn now(&self) -> u64 {
        self.started.elapsed().as_nanos() as u64
    }

    /// Takes `Arc<Self>` because the returned `Subscription` must keep the
    /// encoder alive — that refcount is what stops ffmpeg when the last
    /// listener leaves.
    ///
    /// `kick` is the listener's socket, used only to unblock its request
    /// thread on eviction; `None` is fine (tests, HEAD).
    fn subscribe(
        self: Arc<Self>,
        peer: String,
        kick: Option<TcpStream>,
    ) -> Result<Subscription, String> {
        let init = if self.fmt.needs_init_segment() {
            Some(self.await_init_segment()?)
        } else {
            None
        };

        let (tx, rx) = channel();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let bytes = Arc::new(AtomicU64::new(0));
        let queued = Arc::new(AtomicUsize::new(0));
        let now = self.now();
        let consumed_at = Arc::new(AtomicU64::new(now));

        if let Some(init) = init {
            // Must land before any media.
            queued.fetch_add(init.len(), Ordering::Relaxed);
            let _ = tx.send((now, init));
        }

        lock(&self.listeners).push(Listener {
            id,
            tx,
            queued: queued.clone(),
            consumed_at: consumed_at.clone(),
            oldest_unread: now,
            awaiting_fragment: self.fmt.needs_init_segment(),
            peer,
            joined: Instant::now(),
            bytes: bytes.clone(),
            kick,
        });
        Ok(Subscription {
            rx,
            leftover: Bytes::new(),
            bytes,
            queued,
            consumed_at,
            id,
            encoder: self,
        })
    }

    /// Deregister a listener; true if it was the last one.
    fn remove_listener(&self, id: u64) -> bool {
        let mut listeners = lock(&self.listeners);
        listeners.retain(|l| l.id != id);
        listeners.is_empty()
    }

    /// Block until the first `moof` has been written, so an fMP4 joiner gets a
    /// complete init segment.
    ///
    /// The caller holds `Arc<Self>` throughout, which is what makes this
    /// correct: tearing down and retrying would restart ffmpeg each time and
    /// never converge, since the fragment clock restarts with it.
    fn await_init_segment(&self) -> Result<Bytes, String> {
        let mut init = lock(&self.init);
        let deadline = Instant::now() + INIT_TIMEOUT;
        loop {
            // Checked before the cached segment: once the box structure has
            // broken, fragment boundaries are no longer reliable, so a joiner
            // would take the init segment and then never attach.
            if self.unjoinable.load(Ordering::Relaxed) {
                return Err("stream is not valid fragmented mp4".into());
            }
            if let Some(i) = init.as_ref() {
                return Ok(i.clone());
            }
            if self.finished.load(Ordering::Relaxed) {
                return Err("encoder stopped before producing a fragment".into());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "no fragment within {}s; the source keyframe interval may exceed it",
                    INIT_TIMEOUT.as_secs()
                ));
            }
            let (g, _) = self
                .init_ready
                .wait_timeout(init, left)
                .unwrap_or_else(|e| e.into_inner());
            init = g;
        }
    }

    /// Wake anything waiting on the init segment after a terminal state change.
    fn notify_joiners(&self) {
        let _guard = lock(&self.init);
        self.init_ready.notify_all();
    }

    /// Deliver one scanned piece to every listener.
    ///
    /// A listener that is not keeping up is disconnected rather than allowed
    /// to accumulate a backlog: a shared producer cannot block on its slowest
    /// consumer, and for a live stream a viewer several seconds behind is
    /// better served by a reconnect at the live edge (cheap, thanks to the
    /// linger) than by catching up through stale data. For fMP4 a dropped
    /// chunk would be unrecoverable anyway.
    fn fan_out(&self, piece: &mp4::Piece) {
        let data = piece.data();
        let attach_here = piece.fragment_start() && piece.keyframe();
        let now = self.now();
        let mut listeners = lock(&self.listeners);
        listeners.retain_mut(|l| {
            if l.awaiting_fragment {
                if !attach_here {
                    // Mid-fragment bytes, or a fragment that does not open on a
                    // keyframe, are useless to a client that has only had the
                    // init segment; hold it until one that does.
                    return true;
                }
                l.awaiting_fragment = false;
            }

            let queued = l.queued.load(Ordering::Relaxed);
            if queued == 0 {
                l.oldest_unread = now;
            }
            // How far behind the reader is: the age of its oldest unread
            // chunk, bounded below by the chunk it most recently took.
            let behind = Duration::from_nanos(
                now.saturating_sub(l.oldest_unread.max(l.consumed_at.load(Ordering::Relaxed))),
            );
            if behind > SUB_MAX_LAG || queued + data.len() > SUB_MAX_BYTES {
                log::warn(&format!(
                    "{}/{}: {} fell {:.1}s and {}KB behind; disconnecting",
                    self.content_id,
                    self.fmt,
                    l.peer,
                    behind.as_secs_f64(),
                    queued / 1024
                ));
                l.kick();
                return false;
            }

            l.queued.fetch_add(data.len(), Ordering::Relaxed);
            match l.tx.send((now, data.clone())) {
                Ok(()) => {
                    l.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                    true
                }
                Err(_) => false,
            }
        });
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        if let Some(mut c) = lock(&self.child).take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        // Deregister so the puller stops feeding this format and /status stops
        // reporting it. Safe here: nothing holds `encoders` while dropping an
        // Arc<Encoder> (see the module locking rule).
        //
        // Remove only our own entry: a replacement encoder may already have
        // taken this slot. Compared by pointer rather than by upgrading, since
        // dropping an upgraded Arc under this lock is exactly what the locking
        // rule forbids.
        let mut map = lock(&self.engine.encoders);
        let ours = map
            .get(&self.fmt)
            .is_some_and(|f| std::ptr::eq(f.encoder.as_ptr(), self as *const Encoder));
        if ours {
            map.remove(&self.fmt);
        }
        let last = map.is_empty();
        drop(map);
        log::info(&format!(
            "{}/{}: encoder stopped after {}s, {} bytes",
            self.content_id,
            self.fmt,
            self.started.elapsed().as_secs(),
            self.bytes_out.load(Ordering::Relaxed)
        ));
        if last {
            // Our Arc<EngineStream> is about to drop with us; hand the pull to
            // a linger thread instead of letting that close it.
            linger_engine(self.engine.clone());
        }
    }
}

/// Keep an encoder alive for the configured linger after its last listener
/// has left, so a reconnecting viewer joins a running ffmpeg — sub-second,
/// versus a fresh start.
fn linger_encoder(enc: Arc<Encoder>) {
    let d = enc.engine.config.encoder_linger;
    if d.is_zero() {
        return;
    }
    let name = format!("linger-{}-{}", short(&enc.content_id), enc.fmt);
    let _ = thread::Builder::new().name(name).spawn(move || {
        thread::sleep(d);
        drop(enc);
    });
}

// ---------------------------------------------------------------------------
// Tier 3: one listener per HTTP request
// ---------------------------------------------------------------------------

/// A listener's handle on an encoder. Dropping it deregisters the listener and,
/// if it was the last one, starts the encoder's linger.
pub struct Subscription {
    rx: Receiver<(u64, Bytes)>,
    leftover: Bytes,
    bytes: Arc<AtomicU64>,
    queued: Arc<AtomicUsize>,
    consumed_at: Arc<AtomicU64>,
    id: u64,
    encoder: Arc<Encoder>,
}

impl Read for Subscription {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.leftover.is_empty() {
            match self.rx.recv() {
                Ok((at, b)) => {
                    self.queued.fetch_sub(b.len(), Ordering::Relaxed);
                    self.consumed_at.store(at, Ordering::Relaxed);
                    self.leftover = b;
                }
                // Encoder gone or listener evicted: a clean end of response.
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.leftover.len());
        buf[..n].copy_from_slice(&self.leftover[..n]);
        self.leftover = self.leftover.slice(n..);
        Ok(n)
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if self.encoder.remove_listener(self.id) {
            linger_encoder(self.encoder.clone());
        }
    }
}

impl Subscription {
    #[cfg(test)]
    fn bytes_sent(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// A handle on the byte counter that outlives the subscription being moved
    /// into a response body, so the request thread can still log a total.
    pub fn counter(&self) -> Arc<AtomicU64> {
        self.bytes.clone()
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub struct Registry {
    streams: Mutex<HashMap<String, Weak<EngineStream>>>,
    config: Arc<Config>,
}

impl Registry {
    pub fn new(config: Config) -> Arc<Self> {
        let reg = Arc::new(Registry {
            streams: Mutex::new(HashMap::new()),
            config: Arc::new(config),
        });
        spawn_stats_poller(Arc::downgrade(&reg));
        reg
    }

    pub fn live_streams(&self) -> Vec<Arc<EngineStream>> {
        let map = lock(&self.streams);
        let live: Vec<_> = map.values().filter_map(|w| w.upgrade()).collect();
        drop(map);
        live
    }

    /// Get or start the engine pull for `content_id`, blocking until it has
    /// connected and probed.
    fn engine_stream(&self, content_id: &str) -> Result<Arc<EngineStream>, String> {
        let (stream, fresh) = {
            let mut map = lock(&self.streams);
            match map.get(content_id).and_then(|w| w.upgrade()) {
                Some(s) => (s, false),
                None => {
                    // Entries outlive their streams; sweep the dead ones now
                    // rather than growing by one per content id ever seen.
                    map.retain(|_, w| w.strong_count() > 0);
                    let s = Arc::new(EngineStream {
                        content_id: content_id.to_owned(),
                        started: Instant::now(),
                        bytes_in: AtomicU64::new(0),
                        session: OnceLock::new(),
                        probe: OnceLock::new(),
                        socket: OnceLock::new(),
                        stats: Mutex::new(None),
                        replay: Mutex::new(Replay::new(REPLAY_MAX_AGE, REPLAY_MAX_BYTES)),
                        replay_progress: Condvar::new(),
                        encoders: Mutex::new(HashMap::new()),
                        creating: Mutex::new(()),
                        start: (Mutex::new(Start::Pending), Condvar::new()),
                        config: self.config.clone(),
                    });
                    map.insert(content_id.to_owned(), Arc::downgrade(&s));
                    (s, true)
                }
            }
        };

        if fresh {
            let weak = Arc::downgrade(&stream);
            let id = content_id.to_owned();
            let cfg = self.config.clone();
            thread::Builder::new()
                .name(format!("pull-{}", short(content_id)))
                .spawn(move || pull(weak, id, cfg))
                .map_err(|e| format!("could not start puller: {e}"))?;
        }

        // Concurrent requests for the same cold id all wait here on one pull.
        stream.wait_ready()?;
        Ok(stream)
    }

    /// Subscribe to `content_id` in `fmt`, starting the engine pull and the
    /// format's ffmpeg if they are not already running.
    pub fn subscribe(
        &self,
        content_id: &str,
        fmt: OutputFormat,
        peer: &str,
        kick: Option<TcpStream>,
    ) -> Result<Subscription, String> {
        let stream = self.engine_stream(content_id)?;
        // For the first video encoder, let a start-up burst fill the replay
        // window first, so ffmpeg can be primed from a keyframe with its
        // analysis content already buffered instead of waiting on live data.
        // Held before `creating` so a concurrent audio request is not blocked.
        stream.wait_video_prime(fmt);
        // The Arc is held across subscribe, so the encoder cannot be torn down
        // underneath a joiner waiting for its first fragment.
        get_or_start_encoder(&stream, fmt)?.subscribe(peer.to_owned(), kick)
    }
}

fn get_or_start_encoder(
    stream: &Arc<EngineStream>,
    fmt: OutputFormat,
) -> Result<Arc<Encoder>, String> {
    // Without this, two requests arriving together both find an empty slot,
    // both spawn ffmpeg, and the second insert orphans the first — its listener
    // then streams from an encoder the puller no longer feeds.
    let _creating = lock(&stream.creating);
    {
        let map = lock(&stream.encoders);
        let existing = map.get(&fmt).and_then(|f| f.encoder.upgrade());
        drop(map);
        // A finished encoder is still registered while its last listener drains;
        // start a replacement rather than joining a dead one.
        if let Some(e) = existing {
            if !e.finished.load(Ordering::Relaxed) {
                return Ok(e);
            }
        }
    }
    start_encoder(stream, fmt)
}

fn start_encoder(stream: &Arc<EngineStream>, fmt: OutputFormat) -> Result<Arc<Encoder>, String> {
    let probe = stream
        .probe()
        .ok_or_else(|| "engine stream has no probe result".to_string())?;
    let (video, audio) = format::modes(fmt, probe.audio.as_deref());

    let encoder = Arc::new(Encoder {
        content_id: stream.content_id.clone(),
        fmt,
        started: Instant::now(),
        bytes_out: AtomicU64::new(0),
        video,
        audio,
        init: Mutex::new(None),
        init_ready: Condvar::new(),
        unjoinable: AtomicBool::new(false),
        finished: AtomicBool::new(false),
        listeners: Mutex::new(Vec::new()),
        next_id: AtomicU64::new(0),
        child: Mutex::new(None),
        engine: stream.clone(),
    });

    let (tx, rx) = sync_channel::<Bytes>(TS_QUEUE);
    let fed = Arc::new(AtomicU64::new(0));
    // Snapshot the replay window and register in one step, holding the map lock
    // across both. The puller appends to `replay` before sending to registered
    // encoders, so taking these separately could duplicate a chunk (in the
    // window and again live) or drop one. Registered before ffmpeg is spawned,
    // since the analysis window depends on what the snapshot starts with; the
    // queue simply fills for the few milliseconds that takes.
    let policy = if fmt.has_video() {
        Policy::FromKeyframe(PRIME_CONTENT)
    } else {
        Policy::Tail(AUDIO_TAIL)
    };
    let primed = {
        let mut map = lock(&stream.encoders);
        let primed = lock(&stream.replay).snapshot(policy);
        map.insert(
            fmt,
            Feed {
                encoder: Arc::downgrade(&encoder),
                tx,
                fed: fed.clone(),
            },
        );
        primed
    };

    let plan = format::plan(
        fmt,
        probe.audio.as_deref(),
        stream.config.frag_duration_ms,
        primed.from_keyframe,
    );
    let mut child = match Command::new("ffmpeg")
        .args(&plan.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Inherited, as the Go service did: with -loglevel error this is nearly
        // silent, and it is the only diagnostic when a stream fails to start.
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            // Undo the registration; the Arc<Encoder> drops with this frame.
            lock(&stream.encoders).remove(&fmt);
            return Err(format!("could not start ffmpeg: {e}"));
        }
    };

    let stdin = child.stdin.take().expect("stdin piped");
    let stdout = child.stdout.take().expect("stdout piped");
    *lock(&encoder.child) = Some(child);

    // stdin and stdout MUST be serviced by different threads: ffmpeg blocks
    // writing output once its stdout pipe fills, so a single thread doing both
    // would deadlock the moment either pipe backs up.
    let name = format!("{}-{}", short(&stream.content_id), fmt);
    let primed_len = primed.data.len();
    let from_keyframe = primed.from_keyframe;
    thread::Builder::new()
        .name(format!("feed-{name}"))
        .spawn(move || feed_ffmpeg(rx, stdin, primed.data, fed))
        .map_err(|e| format!("could not start feeder: {e}"))?;

    let weak = Arc::downgrade(&encoder);
    thread::Builder::new()
        .name(format!("emit-{name}"))
        .spawn(move || drain_ffmpeg(weak, stdout, fmt))
        .map_err(|e| format!("could not start drainer: {e}"))?;

    log::info(&format!(
        "{}/{}: encoder started (video {}, audio {}, {} bytes replayed{})",
        stream.content_id,
        fmt,
        plan.video,
        plan.audio,
        primed_len,
        if from_keyframe {
            " from a keyframe"
        } else {
            ""
        }
    ));
    Ok(encoder)
}

/// Pump raw TS into ffmpeg's stdin. Exits when the puller drops the sender,
/// closing stdin so ffmpeg sees EOF and shuts down cleanly.
///
/// `prime` is the replay snapshot, written before any live data so ffmpeg
/// starts from a keyframe rather than wherever this encoder happened to
/// attach. `fed` counts what ffmpeg has accepted, for the puller's stall check.
fn feed_ffmpeg(
    rx: Receiver<Bytes>,
    mut stdin: std::process::ChildStdin,
    prime: Vec<u8>,
    fed: Arc<AtomicU64>,
) {
    if !prime.is_empty() {
        if stdin.write_all(&prime).is_err() {
            return;
        }
        fed.fetch_add(prime.len() as u64, Ordering::Relaxed);
    }
    while let Ok(chunk) = rx.recv() {
        if stdin.write_all(&chunk).is_err() {
            break; // ffmpeg exited; the drainer reports why
        }
        fed.fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
}

/// Read ffmpeg's output, track fMP4 structure, and fan out to listeners.
fn drain_ffmpeg(encoder: Weak<Encoder>, mut stdout: std::process::ChildStdout, fmt: OutputFormat) {
    let mut scanner = fmt.needs_init_segment().then(mp4::Scanner::new);
    let mut buf = vec![0u8; CHUNK];

    loop {
        let n = match stdout.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        // Upgrade per chunk so the last holder leaving ends this thread.
        let Some(enc) = encoder.upgrade() else { break };
        enc.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
        let chunk = Bytes::copy_from_slice(&buf[..n]);

        match scanner.as_mut() {
            None => enc.fan_out(&mp4::Piece::Media {
                data: chunk,
                fragment_start: true,
                keyframe: true,
            }),
            Some(s) => {
                for piece in s.push(chunk) {
                    enc.fan_out(&piece);
                }
                if s.failed() && !enc.unjoinable.load(Ordering::Relaxed) {
                    log::error(&format!(
                        "{}/{}: output is not valid fragmented mp4; late joiners refused",
                        enc.content_id, fmt
                    ));
                    enc.unjoinable.store(true, Ordering::Relaxed);
                    enc.notify_joiners();
                } else {
                    let mut init = lock(&enc.init);
                    if init.is_none() {
                        if let Some(segment) = s.init_segment() {
                            *init = Some(segment);
                            enc.init_ready.notify_all();
                        }
                    }
                }
            }
        }
    }

    // Release anyone still waiting for a first fragment that will not come.
    if let Some(enc) = encoder.upgrade() {
        enc.finished.store(true, Ordering::Relaxed);
        enc.notify_joiners();
    }
}

/// One thread polls every live stream's engine statistics, rather than one per
/// stream.
fn spawn_stats_poller(reg: Weak<Registry>) {
    thread::Builder::new()
        .name("engine-stats".into())
        .spawn(move || loop {
            thread::sleep(STATS_INTERVAL);
            let Some(reg) = reg.upgrade() else { return };
            let streams = reg.live_streams();
            drop(reg);
            for s in streams {
                let Some(url) = s.stat_url() else { continue };
                match engine::fetch_stats(&url) {
                    Ok(v) => *lock(&s.stats) = Some((Instant::now(), v)),
                    Err(e) => log::warn(&format!("{}: stat poll failed: {e}", s.content_id)),
                }
            }
        })
        .expect("could not start the stats poller");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::TrackMode;

    fn test_config(encoder_linger: Duration) -> Arc<Config> {
        Arc::new(Config {
            engine_host: "127.0.0.1:6878".into(),
            frag_duration_ms: None,
            encoder_linger,
            engine_linger: Duration::ZERO,
        })
    }

    fn test_engine_with(config: Arc<Config>) -> Arc<EngineStream> {
        Arc::new(EngineStream {
            content_id: "a".repeat(40),
            started: Instant::now(),
            bytes_in: AtomicU64::new(0),
            session: OnceLock::new(),
            probe: OnceLock::new(),
            socket: OnceLock::new(),
            stats: Mutex::new(None),
            replay: Mutex::new(Replay::new(REPLAY_MAX_AGE, REPLAY_MAX_BYTES)),
            replay_progress: Condvar::new(),
            encoders: Mutex::new(HashMap::new()),
            creating: Mutex::new(()),
            start: (Mutex::new(Start::Ready), Condvar::new()),
            config,
        })
    }

    fn test_engine() -> Arc<EngineStream> {
        test_engine_with(test_config(Duration::ZERO))
    }

    /// An encoder with no ffmpeg behind it, for exercising the fan-out policy.
    fn test_encoder_on(engine: Arc<EngineStream>, fmt: OutputFormat) -> Arc<Encoder> {
        Arc::new(Encoder {
            content_id: engine.content_id.clone(),
            fmt,
            started: Instant::now(),
            bytes_out: AtomicU64::new(0),
            video: TrackMode::Copy,
            audio: TrackMode::Copy,
            init: Mutex::new(None),
            init_ready: Condvar::new(),
            unjoinable: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            listeners: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            child: Mutex::new(None),
            engine,
        })
    }

    fn test_encoder(fmt: OutputFormat) -> Arc<Encoder> {
        test_encoder_on(test_engine(), fmt)
    }

    fn media(len: usize, fragment_start: bool, keyframe: bool) -> mp4::Piece {
        mp4::Piece::Media {
            data: Bytes::from(vec![0xAB; len]),
            fragment_start,
            keyframe,
        }
    }

    fn sub(enc: &Arc<Encoder>, peer: &str) -> Subscription {
        enc.clone().subscribe(peer.into(), None).unwrap()
    }

    #[test]
    fn audio_listeners_start_receiving_immediately() {
        let enc = test_encoder(OutputFormat::Adts);
        let s = sub(&enc, "peer");
        // ADTS is self-synchronising, so there is nothing to wait for.
        enc.fan_out(&media(10, false, false));
        assert_eq!(s.bytes_sent(), 10);
    }

    #[test]
    fn fmp4_listeners_wait_for_a_keyframe_fragment() {
        let enc = test_encoder(OutputFormat::Fmp4);
        *lock(&enc.init) = Some(Bytes::from_static(b"ftypmoov"));
        let s = sub(&enc, "peer");

        // Mid-fragment bytes are useless to a client holding only the init
        // segment, so they must be withheld.
        enc.fan_out(&media(10, false, false));
        assert_eq!(s.bytes_sent(), 0, "mid-fragment data must be held back");

        // So is a fragment that opens mid-GOP: the client would decode garbage
        // until the next keyframe.
        enc.fan_out(&media(15, true, false));
        enc.fan_out(&media(10, false, false));
        assert_eq!(s.bytes_sent(), 0, "a non-keyframe fragment must be skipped");

        enc.fan_out(&media(20, true, true));
        assert_eq!(s.bytes_sent(), 20, "must attach at the keyframe moof");

        // Once attached, everything flows, keyframe or not.
        enc.fan_out(&media(5, false, false));
        enc.fan_out(&media(7, true, false));
        assert_eq!(s.bytes_sent(), 32);
    }

    #[test]
    fn fmp4_subscribe_blocks_until_the_first_fragment_arrives() {
        let enc = test_encoder(OutputFormat::Fmp4);
        let writer = enc.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            *lock(&writer.init) = Some(Bytes::from_static(b"ftypmoov"));
            writer.init_ready.notify_all();
        });

        // Waiting is the whole point: tearing down and retrying would restart
        // ffmpeg and never converge.
        let began = Instant::now();
        assert!(enc.subscribe("peer".into(), None).is_ok());
        assert!(began.elapsed() >= Duration::from_millis(150));
    }

    #[test]
    fn fmp4_subscribe_fails_fast_once_the_encoder_has_finished() {
        let enc = test_encoder(OutputFormat::Fmp4);
        enc.finished.store(true, Ordering::Relaxed);
        let began = Instant::now();
        assert!(enc.subscribe("peer".into(), None).is_err());
        // Must not sit out the full INIT_TIMEOUT waiting on a dead encoder.
        assert!(began.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn fmp4_subscribe_is_refused_when_the_stream_did_not_parse() {
        let enc = test_encoder(OutputFormat::Fmp4);
        // Init was cached before the structure broke. Serving it anyway would
        // leave the joiner waiting forever for a boundary that never comes.
        *lock(&enc.init) = Some(Bytes::from_static(b"ftypmoov"));
        enc.unjoinable.store(true, Ordering::Relaxed);
        let began = Instant::now();
        assert!(enc.subscribe("peer".into(), None).is_err());
        assert!(began.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_listener_with_too_much_backlog_is_evicted_rather_than_blocking_the_others() {
        let enc = test_encoder(OutputFormat::Adts);
        let slow = sub(&enc, "slow");
        let _fast = sub(&enc, "fast");
        assert_eq!(enc.listener_count(), 2);

        // Neither reads, so both back up. A shared producer must not block on
        // its slowest consumer.
        let piece = media(1024 * 1024, true, true);
        for _ in 0..(SUB_MAX_BYTES / (1024 * 1024) + 1) {
            enc.fan_out(&piece);
        }
        assert_eq!(enc.listener_count(), 0, "both should have been evicted");
        drop(slow);
    }

    #[test]
    fn a_listener_that_keeps_up_is_never_evicted_on_bytes_alone() {
        let enc = test_encoder(OutputFormat::Adts);
        let mut s = sub(&enc, "peer");
        let piece = media(1024 * 1024, true, true);
        let mut buf = vec![0u8; 1024 * 1024];
        for _ in 0..(SUB_MAX_BYTES / (1024 * 1024) * 3) {
            enc.fan_out(&piece);
            assert_eq!(s.read(&mut buf).unwrap(), buf.len());
        }
        assert_eq!(enc.listener_count(), 1);
    }

    #[test]
    fn dropping_a_subscription_deregisters_its_listener() {
        let enc = test_encoder(OutputFormat::Adts);
        let a = sub(&enc, "a");
        let b = sub(&enc, "b");
        assert_eq!(enc.listener_count(), 2);
        drop(a);
        assert_eq!(enc.listener_count(), 1);
        drop(b);
        assert_eq!(enc.listener_count(), 0);
    }

    #[test]
    fn the_last_listener_leaving_lingers_the_encoder() {
        let engine = test_engine_with(test_config(Duration::from_millis(100)));
        let enc = test_encoder_on(engine, OutputFormat::Adts);
        let a = sub(&enc, "a");
        let b = sub(&enc, "b");
        drop(a);
        assert_eq!(
            Arc::strong_count(&enc),
            2,
            "not the last to leave: no linger"
        );
        drop(b);
        assert_eq!(Arc::strong_count(&enc), 2, "the linger thread holds it");
        assert!(enc.lingering());
        // A rejoin within the linger finds the same encoder, still registered.
        let c = sub(&enc, "c");
        assert!(!enc.lingering());
        drop(c);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(Arc::strong_count(&enc), 1, "the linger has lapsed");
    }

    #[test]
    fn no_linger_when_disabled() {
        let enc = test_encoder(OutputFormat::Adts);
        drop(sub(&enc, "a"));
        assert_eq!(Arc::strong_count(&enc), 1);
    }

    #[test]
    fn subscription_read_hands_back_partial_chunks() {
        let enc = test_encoder(OutputFormat::Adts);
        let mut s = sub(&enc, "peer");
        enc.fan_out(&media(10, true, true));

        // The request thread reads with whatever buffer it likes; a chunk larger
        // than the buffer must be handed out across successive reads.
        let mut buf = [0u8; 3];
        let mut total = 0;
        for _ in 0..4 {
            let n = s.read(&mut buf).unwrap();
            total += n;
            if total == 10 {
                break;
            }
        }
        assert_eq!(total, 10);
    }

    #[test]
    fn subscription_read_ends_cleanly_when_the_encoder_stops() {
        let enc = test_encoder(OutputFormat::Adts);
        let mut s = sub(&enc, "peer");
        // Dropping every listener handle closes the channel.
        lock(&enc.listeners).clear();
        let mut buf = [0u8; 8];
        assert_eq!(s.read(&mut buf).unwrap(), 0, "must EOF, not error");
    }

    #[test]
    fn fmp4_listeners_receive_the_init_segment_first() {
        let enc = test_encoder(OutputFormat::Fmp4);
        *lock(&enc.init) = Some(Bytes::from_static(b"ftypmoov"));
        let mut s = sub(&enc, "peer");
        enc.fan_out(&media(4, true, true));

        let mut buf = [0u8; 8];
        assert_eq!(s.read(&mut buf).unwrap(), 8);
        assert_eq!(&buf, b"ftypmoov", "init segment must precede all media");
    }

    #[test]
    fn encoder_deregisters_itself_from_the_engine_on_drop() {
        let engine = test_engine();
        let enc = test_encoder_on(engine.clone(), OutputFormat::Adts);
        let (tx, _rx) = sync_channel::<Bytes>(TS_QUEUE);
        lock(&engine.encoders).insert(
            OutputFormat::Adts,
            Feed {
                encoder: Arc::downgrade(&enc),
                tx,
                fed: Arc::new(AtomicU64::new(0)),
            },
        );
        assert_eq!(engine.live_encoders().len(), 1);
        assert!(!engine.lingering());

        drop(enc);
        // Deadlocks if Drop is reached while `encoders` is held; see the
        // locking rule in the module docs.
        assert!(lock(&engine.encoders).is_empty());
        assert!(engine.lingering());
    }

    #[test]
    fn the_last_encoder_leaving_lingers_the_engine() {
        let config = Arc::new(Config {
            engine_host: "127.0.0.1:6878".into(),
            frag_duration_ms: None,
            encoder_linger: Duration::ZERO,
            engine_linger: Duration::from_millis(100),
        });
        let engine = test_engine_with(config);
        let enc = test_encoder_on(engine.clone(), OutputFormat::Adts);
        let (tx, _rx) = sync_channel::<Bytes>(TS_QUEUE);
        lock(&engine.encoders).insert(
            OutputFormat::Adts,
            Feed {
                encoder: Arc::downgrade(&enc),
                tx,
                fed: Arc::new(AtomicU64::new(0)),
            },
        );
        drop(enc);
        assert_eq!(
            Arc::strong_count(&engine),
            2,
            "the linger thread holds the pull"
        );
        thread::sleep(Duration::from_millis(300));
        assert_eq!(Arc::strong_count(&engine), 1);
    }

    #[test]
    fn backpressure_gives_up_only_without_progress() {
        let (tx, rx) = sync_channel::<Bytes>(1);
        let fed = Arc::new(AtomicU64::new(0));
        tx.try_send(Bytes::from_static(b"x")).unwrap();
        // A full queue that is draining must never trip the stall: simulate a
        // feeder that makes progress and frees a slot shortly.
        let fed2 = fed.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fed2.fetch_add(1, Ordering::Relaxed);
            rx.recv().unwrap();
            // Keep the receiver alive long enough for the send to land.
            thread::sleep(Duration::from_millis(200));
            drop(rx);
        });
        assert_eq!(
            send_backpressured(&tx, &fed, Bytes::from_static(b"y")),
            Ok(())
        );
    }

    #[test]
    fn backpressure_reports_a_gone_encoder() {
        let (tx, rx) = sync_channel::<Bytes>(1);
        drop(rx);
        let fed = AtomicU64::new(0);
        assert_eq!(
            send_backpressured(&tx, &fed, Bytes::from_static(b"y")),
            Err("gone")
        );
    }

    #[test]
    fn wait_video_prime_does_not_block_audio_or_a_video_less_source() {
        let engine = test_engine(); // empty replay: no video track known
        let began = Instant::now();
        engine.wait_video_prime(OutputFormat::Fmp4);
        engine.wait_video_prime(OutputFormat::Adts);
        assert!(began.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn wait_video_prime_is_skipped_once_an_encoder_exists() {
        let engine = test_engine();
        let enc = test_encoder_on(engine.clone(), OutputFormat::Fmp4);
        let (tx, _rx) = sync_channel::<Bytes>(TS_QUEUE);
        lock(&engine.encoders).insert(
            OutputFormat::Fmp4,
            Feed {
                encoder: Arc::downgrade(&enc),
                tx,
                fed: Arc::new(AtomicU64::new(0)),
            },
        );
        let began = Instant::now();
        engine.wait_video_prime(OutputFormat::Fmp4); // warm: reused as-is
        assert!(began.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn wait_video_prime_returns_at_once_when_the_window_can_prime() {
        use crate::ts::fixtures::*;
        let engine = test_engine();
        {
            let mut r = lock(&engine.replay);
            let (_, tables) = h264_stream();
            r.push(Bytes::from(tables));
            r.push(Bytes::from(pes_at(
                0x101,
                0,
                None,
                &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
            )));
            // Live edge well past PRIME_CONTENT behind a keyframe.
            r.push(Bytes::from(pes_at(
                0x101,
                3 * 90_000,
                None,
                &[AUD.as_slice(), SLICE.as_slice()].concat(),
            )));
            assert!(r.video_prime_ready(PRIME_CONTENT));
        }
        let began = Instant::now();
        engine.wait_video_prime(OutputFormat::Fmp4);
        assert!(
            began.elapsed() < Duration::from_millis(100),
            "already primeable"
        );
    }

    #[test]
    fn wait_video_prime_gives_up_quickly_on_a_real_time_source() {
        use crate::ts::fixtures::*;
        let engine = test_engine();
        {
            // A video track and a keyframe, but no content after it, and no
            // more arriving: the burst check must abandon the wait fast.
            let mut r = lock(&engine.replay);
            let (_, tables) = h264_stream();
            r.push(Bytes::from(tables));
            r.push(Bytes::from(pes_at(
                0x101,
                0,
                None,
                &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
            )));
            assert!(r.has_video());
            assert!(!r.video_prime_ready(PRIME_CONTENT));
        }
        let began = Instant::now();
        engine.wait_video_prime(OutputFormat::Fmp4);
        let waited = began.elapsed();
        assert!(waited >= BURST_SAMPLE, "samples the fill rate first");
        assert!(
            waited < PRIME_WAIT,
            "but does not sit out the full cap: {waited:?}"
        );
    }

    #[test]
    fn dead_stream_entries_are_swept() {
        let reg = Registry::new(Config {
            engine_host: "127.0.0.1:1".into(),
            frag_duration_ms: None,
            encoder_linger: Duration::ZERO,
            engine_linger: Duration::ZERO,
        });
        lock(&reg.streams).insert("dead".into(), Weak::new());
        lock(&reg.streams).insert("gone".into(), Weak::new());
        // Starting a fresh id sweeps the dead entries first. The puller for
        // it fails fast (nothing listens on port 1), which is fine here.
        let _ = reg.engine_stream(&"b".repeat(40));
        let map = lock(&reg.streams);
        assert!(!map.contains_key("dead"));
        assert!(!map.contains_key("gone"));
    }
}
