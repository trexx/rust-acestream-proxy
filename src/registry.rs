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
//! is 10–25s. So the last leaver's `Arc` is parked in [`crate::linger`] for a
//! period (see [`linger_encoder`] and [`linger_engine`]): the encoder keeps
//! running with no listeners, and the engine pull keeps pulling with no
//! encoders, until either a new listener claims them or the period lapses.
//!
//! # When the engine stops
//!
//! Refcounts cannot end a stream from the top. Listeners hold the encoder, the
//! encoder holds the engine stream, and the engine stream holds the channels
//! every one of them is blocked on, so a pull the engine has closed would
//! otherwise stay open forever, and new listeners would join it. So the end is
//! pushed down explicitly: [`EngineStream::end`] drops every feed, each ffmpeg
//! sees EOF on stdin, flushes what it has and exits, and its drainer then
//! [`Encoder::finish`]es, dropping every listener's channel so each request
//! thread sees the end of its response. The registry treats an ended pull as
//! absent, so the next request starts a fresh one.
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
use std::fmt;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::engine::{self, Session};
use crate::format::{self, OutputFormat};
use crate::probe::Probe;
use crate::replay::{Policy, Replay};
use crate::{linger, log, mp4};

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

/// Why the puller gave up on an encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wedged {
    /// ffmpeg exited and its feeder went with it.
    Gone,
    /// ffmpeg took no input at all for [`TS_STALL`].
    Stalled,
}

impl fmt::Display for Wedged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Wedged::Gone => "exited",
            Wedged::Stalled => "stopped consuming input",
        })
    }
}

/// How far a feeder has got, shared with the puller so that it can sleep on a
/// full queue until the feeder moves, rather than polling.
#[derive(Default)]
struct Progress {
    state: Mutex<Fed>,
    moved: Condvar,
}

#[derive(Default)]
struct Fed {
    /// Bytes written into ffmpeg so far: the puller's evidence that a full
    /// queue is draining.
    bytes: u64,
    /// The feeder has exited; nothing more will be taken from the queue.
    closed: bool,
}

impl Progress {
    fn advance(&self, n: usize) {
        lock(&self.state).bytes += n as u64;
        self.moved.notify_all();
    }

    fn close(&self) {
        lock(&self.state).closed = true;
        self.moved.notify_all();
    }
}

/// The puller's handle on one encoder.
struct Feed {
    encoder: Weak<Encoder>,
    /// Sender side lives here alone: dropping the entry closes the channel,
    /// which is how an encoder's input is ended.
    tx: SyncSender<Bytes>,
    progress: Arc<Progress>,
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
    stats: Mutex<Option<serde_json::Value>>,
    /// Trailing raw TS, from which each new encoder is primed.
    replay: Mutex<Replay>,
    encoders: Mutex<HashMap<OutputFormat, Feed>>,
    /// Serialises get-or-create so two simultaneous requests for the same
    /// format cannot both spawn an ffmpeg. Held only by would-be creators, so
    /// the puller is never blocked behind a process spawn.
    creating: Mutex<()>,
    start: (Mutex<Start>, Condvar),
    /// Set once the puller has stopped. Written under `encoders`, so no
    /// encoder can register after [`EngineStream::end`] has cleared them.
    ended: AtomicBool,
    config: Arc<Config>,
}

impl EngineStream {
    fn new(content_id: &str, config: Arc<Config>) -> Self {
        EngineStream {
            content_id: content_id.to_owned(),
            started: Instant::now(),
            bytes_in: AtomicU64::new(0),
            session: OnceLock::new(),
            probe: OnceLock::new(),
            socket: OnceLock::new(),
            stats: Mutex::new(None),
            replay: Mutex::new(Replay::new(REPLAY_MAX_AGE, REPLAY_MAX_BYTES)),
            encoders: Mutex::new(HashMap::new()),
            creating: Mutex::new(()),
            start: (Mutex::new(Start::Pending), Condvar::new()),
            ended: AtomicBool::new(false),
            config,
        }
    }

    pub fn probe(&self) -> Option<&Probe> {
        self.probe.get()
    }

    pub fn stats(&self) -> Option<serde_json::Value> {
        lock(&self.stats).clone()
    }

    fn stat_url(&self) -> Option<String> {
        self.session.get().and_then(|s| s.stat_url.clone())
    }

    /// True once the engine pull has stopped for good.
    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::Relaxed)
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

    /// Time since the source's video content clock last advanced, for /status.
    pub fn live_edge_age(&self) -> Option<Duration> {
        lock(&self.replay).live_edge_age()
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

    /// Settle startup. Only the first outcome counts: a pull that fails after
    /// it was ready has ended, which is [`EngineStream::end`]'s business.
    fn publish(&self, outcome: Result<(), String>) {
        let (lk, cv) = &self.start;
        let mut state = lock(lk);
        if matches!(*state, Start::Pending) {
            *state = match outcome {
                Ok(()) => Start::Ready,
                Err(e) => Start::Failed(e),
            };
            cv.notify_all();
        }
    }

    /// The pull is over: drop every feed, so each ffmpeg sees EOF on stdin,
    /// flushes what it has, and exits — and its drainer then ends its
    /// listeners' responses. See "When the engine stops" in the module docs.
    fn end(&self) {
        let feeds = {
            let mut map = lock(&self.encoders);
            self.ended.store(true, Ordering::Relaxed);
            std::mem::take(&mut *map)
        };
        // Weak handles and senders only, so dropping them under the lock would
        // be safe too; there is just no reason to hold it.
        drop(feeds);
    }

    /// Stop feeding the encoders the puller has given up on, unless a
    /// replacement has taken the slot meanwhile (`progress` tells them apart).
    ///
    /// A stalled ffmpeg is killed as well: it has stopped reading, so closing
    /// its stdin may never end it, and until it ends its listeners wait on it.
    fn drop_wedged(&self, wedged: Vec<(OutputFormat, Arc<Progress>, Wedged)>) {
        let removed: Vec<(OutputFormat, Feed, Wedged)> = {
            let mut map = lock(&self.encoders);
            let mut removed = Vec::new();
            for (fmt, progress, why) in wedged {
                if map
                    .get(&fmt)
                    .is_some_and(|f| Arc::ptr_eq(&f.progress, &progress))
                {
                    removed.extend(map.remove(&fmt).map(|f| (fmt, f, why)));
                }
            }
            removed
        };
        for (fmt, feed, why) in removed {
            if why == Wedged::Stalled {
                log::error(&format!(
                    "{}/{fmt}: encoder {why}; torn down",
                    self.content_id
                ));
                // Upgraded only now, outside the lock: see the locking rule.
                if let Some(enc) = feed.encoder.upgrade() {
                    enc.kill();
                }
            }
        }
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
    if d.is_zero() || stream.ended() {
        return;
    }
    log::info(&format!(
        "{}: no encoders; keeping the engine pull for {}s",
        stream.content_id,
        d.as_secs()
    ));
    linger::hold(stream, d);
}

/// The puller: one thread per content id, holding the sole engine connection.
fn pull(stream: Weak<EngineStream>, content_id: String, config: Arc<Config>) {
    let outcome = match engine::open_session(&config.engine_host, &content_id, &now_pid()) {
        Ok(session) => {
            let command_url = session.command_url.clone();
            let outcome = relay(&stream, &content_id, session);
            if let Some(url) = &command_url {
                engine::send_stop(url);
            }
            outcome
        }
        Err(e) => Err(e),
    };
    if let Some(s) = stream.upgrade() {
        // Reaches anyone still waiting on a startup that failed; a no-op once
        // the stream was ready.
        s.publish(outcome);
        s.end();
    }
}

/// Open the engine stream, identify it, then hand every chunk to the replay
/// window and the encoders until the engine stops or the stream is dropped.
fn relay(stream: &Weak<EngineStream>, content_id: &str, session: Session) -> Result<(), String> {
    let gone = || "stream torn down during startup".to_string();
    let mut resp = match engine::get(&session.playback_url, engine::STALL_TIMEOUT) {
        Ok(r) if r.status == 200 => r,
        Ok(r) => return Err(format!("engine returned http {}", r.status)),
        Err(e) => return Err(format!("could not open engine stream: {e}")),
    };

    // Register the socket before the first blocking read, so a teardown during
    // startup interrupts the puller rather than waiting out the stall timeout.
    {
        let s = stream.upgrade().ok_or_else(gone)?;
        if let Ok(sock) = resp.socket.try_clone() {
            let _ = s.socket.set(sock);
        }
    }

    // Identify the source from its PMT as the first packets arrive. Every
    // format and every later listener reuses the answer. ffprobe over a
    // preroll is only the fallback, for a stream the scanner cannot name.
    let (probed, how) = identify(&mut resp.body, stream)?;
    {
        let s = stream.upgrade().ok_or_else(gone)?;
        let _ = s.session.set(session);
        log::info(&format!(
            "{content_id}: engine stream up, video={} audio={} ({how})",
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
        lock(&s.replay).push(chunk.clone());

        // Snapshot the senders so the lock is not held across a blocking send.
        // Never upgrade the Weak<Encoder> here either: dropping the last Arc
        // under this lock would re-enter Encoder::drop and deadlock.
        let targets: Vec<(OutputFormat, SyncSender<Bytes>, Arc<Progress>)> = {
            let map = lock(&s.encoders);
            map.iter()
                .map(|(f, feed)| (*f, feed.tx.clone(), feed.progress.clone()))
                .collect()
        };

        let mut wedged = Vec::new();
        for (fmt, tx, progress) in targets {
            if let Err(why) = send_backpressured(&tx, &progress, chunk.clone()) {
                wedged.push((fmt, progress, why));
            }
        }
        if !wedged.is_empty() {
            s.drop_wedged(wedged);
        }
    }
    Ok(())
}

/// Read from the engine until the source is identified, feeding the replay
/// window as we go so nothing read here is lost to the encoders.
///
/// The PMT settles it within the first packets. If it has not by
/// [`PREROLL`] bytes — a first audio stream the scanner cannot name — ffprobe
/// gets what was read so far, straight from the replay window.
fn identify(body: &mut impl Read, stream: &Weak<EngineStream>) -> Result<(Probe, String), String> {
    let gone = || "stream torn down during startup".to_string();
    let mut buf = vec![0u8; CHUNK];
    let mut read = 0usize;
    while read < PREROLL {
        let n = match body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(format!("engine stream failed during preroll: {e}")),
        };
        read += n;
        let s = stream.upgrade().ok_or_else(gone)?;
        s.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        let program = {
            let mut replay = lock(&s.replay);
            replay.push(Bytes::copy_from_slice(&buf[..n]));
            replay.program()
        };
        if let Some(p) = program {
            return Ok((Probe::from(p), format!("from the PMT, {read} bytes in")));
        }
    }
    if read == 0 {
        return Err("engine stream ended before sending anything".into());
    }
    let preroll = {
        let s = stream.upgrade().ok_or_else(gone)?;
        let preroll = lock(&s.replay).snapshot(Policy::Tail(REPLAY_MAX_AGE));
        preroll.data
    };
    let probed = crate::probe::run(preroll).map_err(|e| format!("could not probe stream: {e}"))?;
    Ok((probed, format!("ffprobe over {read} bytes")))
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
    progress: &Progress,
    chunk: Bytes,
) -> Result<(), Wedged> {
    let mut seen = lock(&progress.state).bytes;
    let mut deadline = Instant::now() + TS_STALL;
    let mut chunk = chunk;
    loop {
        chunk = match tx.try_send(chunk) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Disconnected(_)) => return Err(Wedged::Gone),
            Err(TrySendError::Full(returned)) => returned,
        };
        // The queue is full: sleep until the feeder writes something.
        let mut fed = lock(&progress.state);
        loop {
            if fed.closed {
                return Err(Wedged::Gone);
            }
            if fed.bytes != seen {
                seen = fed.bytes;
                deadline = Instant::now() + TS_STALL;
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Wedged::Stalled);
            }
            fed = progress
                .moved
                .wait_timeout(fed, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
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

/// One listener, as /status reports it.
pub struct ListenerInfo {
    pub peer: String,
    pub uptime_s: u64,
    pub bytes_sent: u64,
}

/// Where an encoder's output stands, as far as a joiner is concerned. One
/// value behind one lock, so a joiner reading it and the drainer changing it
/// cannot interleave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Output {
    /// Running. For fMP4, the init segment is not complete yet.
    Starting,
    /// fMP4 only: the init segment, replayed to every late joiner.
    Ready(Bytes),
    /// fMP4 only: the byte stream stopped parsing, so fragment boundaries are
    /// no longer reliable. Late joiners are refused rather than served
    /// something they cannot decode.
    Unjoinable,
    /// ffmpeg's output has ended, in any format.
    Finished,
}

pub struct Encoder {
    pub content_id: String,
    pub fmt: OutputFormat,
    pub started: Instant,
    pub bytes_out: AtomicU64,
    pub video: format::TrackMode,
    pub audio: format::TrackMode,
    /// Content-seconds behind the live edge at which this encoder was primed
    /// (its newest-keyframe lag at start). A copy encoder holds this offset,
    /// so it is roughly how far behind live its listeners sit. `None` when it
    /// could not be primed from a keyframe. Reported by /status.
    pub primed_behind_live: Option<Duration>,
    output: Mutex<Output>,
    /// Signalled on every change to `output`; joiners wait on it.
    output_changed: Condvar,
    listeners: Mutex<Vec<Listener>>,
    next_id: AtomicU64,
    child: Mutex<Option<Child>>,
    engine: Arc<EngineStream>,
}

impl Encoder {
    fn new(
        engine: Arc<EngineStream>,
        fmt: OutputFormat,
        video: format::TrackMode,
        audio: format::TrackMode,
        primed_behind_live: Option<Duration>,
    ) -> Self {
        Encoder {
            content_id: engine.content_id.clone(),
            fmt,
            started: Instant::now(),
            bytes_out: AtomicU64::new(0),
            video,
            audio,
            primed_behind_live,
            output: Mutex::new(Output::Starting),
            output_changed: Condvar::new(),
            listeners: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            child: Mutex::new(None),
            engine,
        }
    }

    #[cfg(test)]
    fn listener_count(&self) -> usize {
        lock(&self.listeners).len()
    }

    pub fn listener_info(&self) -> Vec<ListenerInfo> {
        lock(&self.listeners)
            .iter()
            .map(|l| ListenerInfo {
                peer: l.peer.clone(),
                uptime_s: l.joined.elapsed().as_secs(),
                bytes_sent: l.bytes.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// True while ffmpeg is being kept alive with no listener on it.
    pub fn lingering(&self) -> bool {
        lock(&self.listeners).is_empty()
    }

    /// True once ffmpeg's output has ended.
    fn finished(&self) -> bool {
        *lock(&self.output) == Output::Finished
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
            bytes,
            queued,
            consumed_at,
            id,
            encoder: self,
        })
    }

    /// Deregister a listener; true if it was registered and was the last one.
    /// An encoder that has finished has already let every listener go, and
    /// their departures must not each look like the last.
    fn remove_listener(&self, id: u64) -> bool {
        let mut listeners = lock(&self.listeners);
        let before = listeners.len();
        listeners.retain(|l| l.id != id);
        listeners.len() < before && listeners.is_empty()
    }

    /// Block until the first `moof` has been written, so an fMP4 joiner gets a
    /// complete init segment.
    ///
    /// The caller holds `Arc<Self>` throughout, which is what makes this
    /// correct: tearing down and retrying would restart ffmpeg each time and
    /// never converge, since the fragment clock restarts with it.
    fn await_init_segment(&self) -> Result<Bytes, String> {
        let mut output = lock(&self.output);
        let deadline = Instant::now() + INIT_TIMEOUT;
        loop {
            match &*output {
                Output::Ready(init) => return Ok(init.clone()),
                Output::Unjoinable => return Err("stream is not valid fragmented mp4".into()),
                Output::Finished => {
                    return Err("encoder stopped before producing a fragment".into())
                }
                Output::Starting => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "no fragment within {}s; the source keyframe interval may exceed it",
                    INIT_TIMEOUT.as_secs()
                ));
            }
            output = self
                .output_changed
                .wait_timeout(output, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn set_output(&self, output: Output) {
        *lock(&self.output) = output;
        self.output_changed.notify_all();
    }

    /// ffmpeg's output has ended: release anyone waiting for a first fragment,
    /// and end every listener's response. Dropping a listener's sender is what
    /// makes its `Subscription::recv` return `None`; without this they would
    /// wait forever on an encoder their own subscriptions keep alive.
    fn finish(&self) {
        self.set_output(Output::Finished);
        lock(&self.listeners).clear();
    }

    /// Kill ffmpeg. Its output then ends, and the drainer finishes the encoder.
    fn kill(&self) {
        if let Some(c) = lock(&self.child).as_mut() {
            let _ = c.kill();
        }
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
            // the linger instead of letting that close it.
            linger_engine(self.engine.clone());
        }
    }
}

/// Keep an encoder alive for the configured linger after its last listener
/// has left, so a reconnecting viewer joins a running ffmpeg — sub-second,
/// versus a fresh start. A finished encoder is no use to anyone and goes now.
fn linger_encoder(enc: Arc<Encoder>) {
    let d = enc.engine.config.encoder_linger;
    if !enc.finished() {
        linger::hold(enc, d);
    }
}

// ---------------------------------------------------------------------------
// Tier 3: one listener per HTTP request
// ---------------------------------------------------------------------------

/// A listener's handle on an encoder. Dropping it deregisters the listener and,
/// if it was the last one, starts the encoder's linger.
pub struct Subscription {
    rx: Receiver<(u64, Bytes)>,
    bytes: Arc<AtomicU64>,
    queued: Arc<AtomicUsize>,
    consumed_at: Arc<AtomicU64>,
    id: u64,
    encoder: Arc<Encoder>,
}

impl Subscription {
    /// The next chunk, blocking until there is one. `None` is the clean end of
    /// the response: the encoder has finished, or this listener was evicted.
    pub fn recv(&self) -> Option<Bytes> {
        self.rx.recv().ok().map(|(at, b)| self.took(at, b))
    }

    /// The next chunk if one is already queued.
    pub fn try_recv(&self) -> Option<Bytes> {
        self.rx.try_recv().ok().map(|(at, b)| self.took(at, b))
    }

    fn took(&self, at: u64, chunk: Bytes) -> Bytes {
        self.queued.fetch_sub(chunk.len(), Ordering::Relaxed);
        self.consumed_at.store(at, Ordering::Relaxed);
        chunk
    }

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

impl Drop for Subscription {
    fn drop(&mut self) {
        if self.encoder.remove_listener(self.id) {
            linger_encoder(self.encoder.clone());
        }
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
            // An ended pull can outlive its end, held by encoders flushing
            // their last output, but it will never carry anything again:
            // start a fresh one rather than join it.
            match map
                .get(content_id)
                .and_then(Weak::upgrade)
                .filter(|s| !s.ended())
            {
                Some(s) => (s, false),
                None => {
                    // Entries outlive their streams; sweep the dead ones now
                    // rather than growing by one per content id ever seen.
                    map.retain(|_, w| w.strong_count() > 0);
                    let s = Arc::new(EngineStream::new(content_id, self.config.clone()));
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
            if !e.finished() {
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
    let policy = if fmt.has_video() {
        Policy::FromKeyframe
    } else {
        Policy::Tail(AUDIO_TAIL)
    };
    let (tx, rx) = sync_channel::<Bytes>(TS_QUEUE);
    let progress = Arc::new(Progress::default());

    // Snapshot the replay window and register in one step, holding the map lock
    // across both. The puller appends to `replay` before sending to registered
    // encoders, so taking these separately could duplicate a chunk (in the
    // window and again live) or drop one. Registered before ffmpeg is spawned,
    // since the analysis window depends on what the snapshot starts with; the
    // queue simply fills for the few milliseconds that takes.
    let (encoder, plan, primed) = {
        let mut map = lock(&stream.encoders);
        if stream.ended() {
            // The puller has gone; nothing would ever feed this encoder.
            return Err("engine stream has ended".into());
        }
        let replay = lock(&stream.replay);
        let primed = replay.snapshot(policy);
        // How far behind live this encoder starts, for /status. Only meaningful
        // for video, which is primed from a keyframe; audio has no keyframe lag.
        let behind = fmt
            .has_video()
            .then(|| replay.newest_keyframe_lag())
            .flatten();
        drop(replay);
        let plan = format::plan(
            fmt,
            probe.audio.as_deref(),
            stream.config.frag_duration_ms,
            primed.from_keyframe,
        );
        let encoder = Arc::new(Encoder::new(
            stream.clone(),
            fmt,
            plan.video,
            plan.audio,
            behind,
        ));
        map.insert(
            fmt,
            Feed {
                encoder: Arc::downgrade(&encoder),
                tx,
                progress: progress.clone(),
            },
        );
        (encoder, plan, primed)
    };

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
            // Undo the registration; the Arc<Encoder> drops with this frame,
            // after the lock is released.
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
    let primed_len = primed.byte_count();
    let from_keyframe = primed.from_keyframe;
    thread::Builder::new()
        .name(format!("feed-{name}"))
        .spawn(move || feed_ffmpeg(rx, stdin, primed.data, &progress))
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
/// attach. `progress` counts what ffmpeg has accepted, for the puller's stall
/// check.
fn feed_ffmpeg(rx: Receiver<Bytes>, mut stdin: ChildStdin, prime: Vec<Bytes>, progress: &Progress) {
    for chunk in prime.into_iter().chain(rx) {
        if stdin.write_all(&chunk).is_err() {
            break; // ffmpeg exited; the drainer reports why
        }
        progress.advance(chunk.len());
    }
    // The receiver has dropped with the loop, so a puller woken by this finds
    // the queue disconnected.
    progress.close();
}

/// Read ffmpeg's output, track fMP4 structure, and fan out to listeners.
fn drain_ffmpeg(encoder: Weak<Encoder>, mut stdout: ChildStdout, fmt: OutputFormat) {
    let mut scanner = fmt.needs_init_segment().then(mp4::Scanner::new);
    let mut have_init = false;
    let mut gave_up = false;
    let mut buf = vec![0u8; CHUNK];

    loop {
        let n = match stdout.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
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
                // Once the structure has broken, fragment boundaries are no
                // longer reliable, so a joiner would take the init segment and
                // then never attach: refuse joiners from here on.
                if s.failed() {
                    if !gave_up {
                        gave_up = true;
                        log::error(&format!(
                            "{}/{}: output is not valid fragmented mp4; late joiners refused",
                            enc.content_id, fmt
                        ));
                        enc.set_output(Output::Unjoinable);
                    }
                } else if !have_init {
                    if let Some(segment) = s.init_segment() {
                        have_init = true;
                        enc.set_output(Output::Ready(segment));
                    }
                }
            }
        }
    }

    if let Some(enc) = encoder.upgrade() {
        enc.finish();
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
            // Weak handles only across the fetches, so an engine slow to answer
            // cannot keep a stream alive past its linger.
            let targets: Vec<(Weak<EngineStream>, String)> = reg
                .live_streams()
                .iter()
                .filter(|s| !s.ended())
                .filter_map(|s| Some((Arc::downgrade(s), s.stat_url()?)))
                .collect();
            drop(reg);
            for (stream, url) in targets {
                let polled = engine::fetch_stats(&url);
                let Some(s) = stream.upgrade() else { continue };
                match polled {
                    Ok(v) => *lock(&s.stats) = Some(v),
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
    use std::net::TcpListener;

    /// Poll `cond` until it holds or a generous deadline passes. Timing-based
    /// assertions wait on the outcome rather than on a fixed sleep, so a slow
    /// runner is not a failure.
    fn eventually(cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    fn config(encoder_linger: Duration, engine_linger: Duration) -> Arc<Config> {
        Arc::new(Config {
            engine_host: "127.0.0.1:6878".into(),
            frag_duration_ms: None,
            encoder_linger,
            engine_linger,
        })
    }

    fn test_engine_with(config: Arc<Config>) -> Arc<EngineStream> {
        let engine = EngineStream::new(&"a".repeat(40), config);
        engine.publish(Ok(()));
        Arc::new(engine)
    }

    fn test_engine() -> Arc<EngineStream> {
        test_engine_with(config(Duration::ZERO, Duration::ZERO))
    }

    /// An encoder with no ffmpeg behind it, for exercising the fan-out policy.
    fn test_encoder_on(engine: Arc<EngineStream>, fmt: OutputFormat) -> Arc<Encoder> {
        Arc::new(Encoder::new(
            engine,
            fmt,
            TrackMode::Copy,
            TrackMode::Copy,
            None,
        ))
    }

    fn test_encoder(fmt: OutputFormat) -> Arc<Encoder> {
        test_encoder_on(test_engine(), fmt)
    }

    /// Register `enc` with its engine as the puller would see it. The receiver
    /// is returned so the feed stays connected for as long as the test wants.
    fn register(enc: &Arc<Encoder>) -> Receiver<Bytes> {
        let (tx, rx) = sync_channel::<Bytes>(TS_QUEUE);
        lock(&enc.engine.encoders).insert(
            enc.fmt,
            Feed {
                encoder: Arc::downgrade(enc),
                tx,
                progress: Arc::default(),
            },
        );
        rx
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
        enc.set_output(Output::Ready(Bytes::from_static(b"ftypmoov")));
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
            writer.set_output(Output::Ready(Bytes::from_static(b"ftypmoov")));
        });

        // Waiting is the whole point: tearing down and retrying would restart
        // ffmpeg and never converge.
        let began = Instant::now();
        assert!(enc.clone().subscribe("peer".into(), None).is_ok());
        assert!(began.elapsed() >= Duration::from_millis(150));
    }

    #[test]
    fn fmp4_subscribe_fails_fast_once_the_encoder_has_finished() {
        let enc = test_encoder(OutputFormat::Fmp4);
        enc.finish();
        let began = Instant::now();
        assert!(enc.clone().subscribe("peer".into(), None).is_err());
        // Must not sit out the full INIT_TIMEOUT waiting on a dead encoder.
        assert!(began.elapsed() < INIT_TIMEOUT / 3);
    }

    #[test]
    fn fmp4_subscribe_is_refused_when_the_stream_did_not_parse() {
        let enc = test_encoder(OutputFormat::Fmp4);
        // Init was cached before the structure broke. Serving it anyway would
        // leave the joiner waiting forever for a boundary that never comes.
        enc.set_output(Output::Ready(Bytes::from_static(b"ftypmoov")));
        enc.set_output(Output::Unjoinable);
        let began = Instant::now();
        assert!(enc.clone().subscribe("peer".into(), None).is_err());
        assert!(began.elapsed() < INIT_TIMEOUT / 3);
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
        let s = sub(&enc, "peer");
        let piece = media(1024 * 1024, true, true);
        for _ in 0..(SUB_MAX_BYTES / (1024 * 1024) * 3) {
            enc.fan_out(&piece);
            assert_eq!(s.recv().map(|b| b.len()), Some(1024 * 1024));
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
        let engine = test_engine_with(config(Duration::from_millis(100), Duration::ZERO));
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
        assert_eq!(Arc::strong_count(&enc), 2, "the linger holds it");
        assert!(enc.lingering());
        // A rejoin within the linger finds the same encoder, still registered.
        let c = sub(&enc, "c");
        assert!(!enc.lingering());
        drop(c);
        assert!(
            eventually(|| Arc::strong_count(&enc) == 1),
            "the linger has lapsed"
        );
    }

    #[test]
    fn no_linger_when_disabled() {
        let enc = test_encoder(OutputFormat::Adts);
        drop(sub(&enc, "a"));
        assert_eq!(Arc::strong_count(&enc), 1);
    }

    #[test]
    fn subscription_hands_out_chunks_in_order() {
        let enc = test_encoder(OutputFormat::Adts);
        let s = sub(&enc, "peer");
        enc.fan_out(&media(10, true, true));
        enc.fan_out(&media(3, true, true));
        assert_eq!(s.recv().map(|b| b.len()), Some(10));
        assert_eq!(s.try_recv().map(|b| b.len()), Some(3));
        assert_eq!(s.try_recv(), None, "nothing more is queued");
    }

    #[test]
    fn subscription_ends_cleanly_when_the_listener_is_dropped() {
        let enc = test_encoder(OutputFormat::Adts);
        let s = sub(&enc, "peer");
        // Dropping every listener handle closes the channel.
        lock(&enc.listeners).clear();
        assert_eq!(s.recv(), None);
    }

    #[test]
    fn fmp4_listeners_receive_the_init_segment_first() {
        let enc = test_encoder(OutputFormat::Fmp4);
        enc.set_output(Output::Ready(Bytes::from_static(b"ftypmoov")));
        let s = sub(&enc, "peer");
        enc.fan_out(&media(4, true, true));
        assert_eq!(
            s.recv().as_deref(),
            Some(&b"ftypmoov"[..]),
            "init segment must precede all media"
        );
    }

    #[test]
    fn encoder_deregisters_itself_from_the_engine_on_drop() {
        let engine = test_engine();
        let enc = test_encoder_on(engine.clone(), OutputFormat::Adts);
        let _rx = register(&enc);
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
        let engine = test_engine_with(config(Duration::ZERO, Duration::from_millis(100)));
        let enc = test_encoder_on(engine.clone(), OutputFormat::Adts);
        let _rx = register(&enc);
        drop(enc);
        assert_eq!(Arc::strong_count(&engine), 2, "the linger holds the pull");
        assert!(eventually(|| Arc::strong_count(&engine) == 1));
    }

    // -- The engine stopping -------------------------------------------------

    #[test]
    fn a_finished_encoder_ends_every_listener() {
        let enc = test_encoder(OutputFormat::Adts);
        let a = sub(&enc, "a");
        let b = sub(&enc, "b");
        enc.fan_out(&media(10, true, true));
        // The regression: listeners keep the encoder alive, so nothing but
        // `finish` can close their channels, and before it existed they
        // blocked in recv forever after ffmpeg exited.
        enc.finish();
        assert_eq!(
            a.recv().map(|b| b.len()),
            Some(10),
            "queued data still arrives"
        );
        assert_eq!(a.recv(), None);
        assert_eq!(b.try_recv().map(|b| b.len()), Some(10));
        assert_eq!(b.recv(), None);
    }

    #[test]
    fn a_finished_encoder_does_not_linger() {
        let engine = test_engine_with(config(Duration::from_secs(3600), Duration::ZERO));
        let enc = test_encoder_on(engine, OutputFormat::Adts);
        let a = sub(&enc, "a");
        let b = sub(&enc, "b");
        enc.finish();
        drop(a);
        drop(b);
        assert_eq!(Arc::strong_count(&enc), 1, "nothing left to reconnect to");
    }

    #[test]
    fn ending_the_pull_closes_every_feed() {
        let engine = test_engine();
        let enc = test_encoder_on(engine.clone(), OutputFormat::Adts);
        let rx = register(&enc);
        engine.end();
        assert!(engine.ended());
        assert!(rx.recv().is_err(), "the feeder sees its input end");
        assert!(lock(&engine.encoders).is_empty());
    }

    #[test]
    fn no_encoder_starts_on_an_ended_pull() {
        let engine = test_engine();
        let _ = engine.probe.set(Probe::default());
        engine.end();
        let err = start_encoder(&engine, OutputFormat::Adts).err();
        assert_eq!(err.as_deref(), Some("engine stream has ended"));
        assert!(lock(&engine.encoders).is_empty());
    }

    #[test]
    fn a_startup_outcome_is_not_overwritten() {
        let engine = EngineStream::new("x", config(Duration::ZERO, Duration::ZERO));
        engine.publish(Ok(()));
        engine.publish(Err("later".into()));
        assert_eq!(engine.wait_ready(), Ok(()));
    }

    #[test]
    fn an_ended_pull_is_replaced_rather_than_joined() {
        let reg = Registry::new(Config {
            engine_host: "127.0.0.1:1".into(),
            frag_duration_ms: None,
            encoder_linger: Duration::ZERO,
            engine_linger: Duration::ZERO,
        });
        let id = "c".repeat(40);
        let old = Arc::new(EngineStream::new(&id, reg.config.clone()));
        old.publish(Ok(()));
        old.end();
        lock(&reg.streams).insert(id.clone(), Arc::downgrade(&old));
        // The fresh puller fails fast (nothing listens on port 1); what matters
        // is that the ended stream was not handed out as a ready one.
        assert!(reg.engine_stream(&id).is_err());
        let now = lock(&reg.streams).get(&id).and_then(Weak::upgrade);
        assert!(now.is_none_or(|s| !Arc::ptr_eq(&s, &old)));
    }

    /// End to end, against a stand-in engine that serves a few seconds of real
    /// TS and then closes the connection: the listener's response must end,
    /// and the content id must not be left holding a dead pull. Skips itself
    /// where there is no ffmpeg.
    #[test]
    fn a_stream_the_engine_closes_ends_for_its_listeners() {
        let Some(ts) = test_ts() else { return };
        let engine = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = engine.local_addr().unwrap().to_string();
        thread::spawn(move || {
            for conn in engine.incoming() {
                let Ok(mut conn) = conn else { continue };
                let ts = ts.clone();
                thread::spawn(move || {
                    let mut head = [0u8; 1024];
                    let n = conn.read(&mut head).unwrap_or(0);
                    if String::from_utf8_lossy(&head[..n]).contains("format=json") {
                        // No JSON handshake: the proxy falls back to a direct pull.
                        let _ =
                            conn.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                        return;
                    }
                    let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\n\r\n");
                    for chunk in ts.chunks(32 * 1024) {
                        if conn.write_all(chunk).is_err() {
                            return;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    // Dropping the connection is the engine ending the stream.
                });
            }
        });

        let reg = Registry::new(Config {
            engine_host: host,
            frag_duration_ms: None,
            encoder_linger: Duration::from_secs(3600),
            engine_linger: Duration::from_secs(3600),
        });
        let id = "d".repeat(40);
        let s = reg
            .subscribe(&id, OutputFormat::Adts, "peer", None)
            .unwrap();
        let (done, ended) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut bytes = 0;
            while let Some(chunk) = s.recv() {
                bytes += chunk.len();
            }
            let _ = done.send(bytes);
        });
        let bytes = ended
            .recv_timeout(Duration::from_secs(30))
            .expect("the listener's response never ended");
        assert!(bytes > 0, "audio arrived before the end");
        // Even with lingers that would outlast the test, the ended pull is not
        // handed to the next request.
        assert!(lock(&reg.streams)
            .get(&id)
            .and_then(Weak::upgrade)
            .is_none_or(|s| s.ended()));
    }

    /// A few seconds of H.264 + AAC in MPEG-TS, or `None` without ffmpeg.
    fn test_ts() -> Option<Arc<Vec<u8>>> {
        let out = std::process::Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=160x120:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine",
                "-t",
                "3",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-g",
                "25",
                "-c:a",
                "aac",
                "-f",
                "mpegts",
                "-",
            ])
            .output()
            .ok()?;
        (out.status.success() && !out.stdout.is_empty()).then(|| Arc::new(out.stdout))
    }

    // -- Backpressure --------------------------------------------------------

    #[test]
    fn backpressure_waits_for_a_draining_encoder() {
        let (tx, rx) = sync_channel::<Bytes>(1);
        let progress = Arc::new(Progress::default());
        tx.try_send(Bytes::from_static(b"x")).unwrap();
        // A full queue that is draining must never trip the stall: a feeder
        // that takes the chunk and reports progress a little later.
        let feeder = progress.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            let chunk = rx.recv().unwrap();
            feeder.advance(chunk.len());
            rx.recv().unwrap()
        });
        assert_eq!(
            send_backpressured(&tx, &progress, Bytes::from_static(b"y")),
            Ok(())
        );
        assert_eq!(handle.join().unwrap(), Bytes::from_static(b"y"));
    }

    #[test]
    fn backpressure_reports_a_gone_encoder() {
        let (tx, rx) = sync_channel::<Bytes>(1);
        drop(rx);
        assert_eq!(
            send_backpressured(&tx, &Progress::default(), Bytes::from_static(b"y")),
            Err(Wedged::Gone)
        );
    }

    #[test]
    fn backpressure_wakes_promptly_when_the_feeder_exits() {
        let (tx, rx) = sync_channel::<Bytes>(1);
        let progress = Arc::new(Progress::default());
        tx.try_send(Bytes::from_static(b"x")).unwrap();
        let feeder = progress.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(rx);
            feeder.close();
        });
        let began = Instant::now();
        assert_eq!(
            send_backpressured(&tx, &progress, Bytes::from_static(b"y")),
            Err(Wedged::Gone)
        );
        assert!(
            began.elapsed() < TS_STALL,
            "must not wait out the stall timeout"
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
