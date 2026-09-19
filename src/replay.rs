//! The replay window: the trailing seconds of raw TS from one engine pull,
//! used to prime each new encoder.
//!
//! An encoder started on live bytes alone attaches at an arbitrary mid-GOP
//! point, and ffmpeg then has to wait for the next keyframe to recover the
//! H.264 parameters it needs — measured on a real 720p broadcast stream, that
//! took 14s in one trial and simply never succeeded in another. Priming it
//! with recent data fixes that. But every replayed byte is content the
//! encoder's listeners watch late for as long as it runs, because ffmpeg in
//! copy mode cannot skip ahead. So the window is never replayed whole: a video
//! encoder starts from the newest keyframe ([`Policy::FromKeyframe`]), which
//! bounds its lag by one GOP, and an audio encoder from the last second or so
//! ([`Policy::Tail`]), which needs no keyframe at all.
//!
//! Keyframes are tagged with their presentation timestamp as they are found,
//! and the scanner tracks the live-edge PTS, so the window can report how far
//! behind live a new encoder starts and whether the source clock is still
//! advancing. See [`Replay::newest_keyframe_lag`] and [`Replay::live_edge_age`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::ts;

const TS_PACKET: usize = 188;

/// The 90 kHz MPEG presentation clock.
const PTS_HZ: u64 = 90_000;
const PTS_MASK: u64 = (1 << 33) - 1;
/// A PTS gap longer than this is read as a wrap or a reordered frame, not a
/// real gap: the window holds at most tens of seconds of content, so anything
/// approaching the 26.5-hour PTS period is an artefact.
const MAX_SANE_GAP: Duration = Duration::from_secs(300);

/// A forward PTS distance as a duration, or `None` if it is out of range —
/// a wrap, or a `to` that precedes `from` (frame reordering near the edge).
fn pts_gap(from: u64, to: u64) -> Option<Duration> {
    let d = to.wrapping_sub(from) & PTS_MASK;
    let dur = Duration::from_secs_f64(d as f64 / PTS_HZ as f64);
    (dur <= MAX_SANE_GAP).then_some(dur)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// From the most recent video keyframe to the end of the window. Falls
    /// back to the whole window when no keyframe has been seen.
    FromKeyframe,
    /// The last `Duration` of the window.
    Tail(Duration),
}

/// What a new encoder is fed before live data.
#[derive(Debug, PartialEq, Eq)]
pub struct Primed {
    pub data: Vec<u8>,
    /// True when `data` begins on a video keyframe, so ffmpeg's stream
    /// analysis can be short.
    pub from_keyframe: bool,
}

struct Chunk {
    at: Instant,
    /// Absolute offset of `data[0]`, counted from the first byte ever pushed.
    start: u64,
    data: Bytes,
}

pub struct Replay {
    chunks: VecDeque<Chunk>,
    bytes: usize,
    /// Absolute offset of the next byte to be pushed.
    head: u64,
    /// Keyframe packets still inside the window, oldest first, each tagged
    /// with its presentation timestamp.
    keyframes: VecDeque<ts::Keyframe>,
    scanner: ts::Scanner,
    /// When the live-edge video PTS last advanced, for staleness reporting.
    latest_pts_at: Option<Instant>,
    max_age: Duration,
    max_bytes: usize,
}

impl Replay {
    /// A window holding at most `max_age` of arrival time and `max_bytes`,
    /// whichever bound is hit first. The byte cap is a memory guard; the age
    /// cap is what keeps a low-bitrate stream from accumulating a long window.
    pub fn new(max_age: Duration, max_bytes: usize) -> Self {
        Replay {
            chunks: VecDeque::new(),
            bytes: 0,
            head: 0,
            keyframes: VecDeque::new(),
            scanner: ts::Scanner::new(),
            latest_pts_at: None,
            max_age,
            max_bytes,
        }
    }

    pub fn push(&mut self, data: Bytes) {
        let at = Instant::now();
        let before = self.scanner.latest_video_pts();
        self.keyframes.extend(self.scanner.feed(&data));
        if self.scanner.latest_video_pts() != before {
            self.latest_pts_at = Some(at);
        }
        self.bytes += data.len();
        self.chunks.push_back(Chunk {
            at,
            start: self.head,
            data,
        });
        self.head += self.chunks.back().map_or(0, |c| c.data.len() as u64);
        self.trim(at);
    }

    fn trim(&mut self, now: Instant) {
        while self.chunks.len() > 1 {
            let oldest = &self.chunks[0];
            if self.bytes <= self.max_bytes && now.duration_since(oldest.at) <= self.max_age {
                break;
            }
            self.bytes -= oldest.data.len();
            self.chunks.pop_front();
        }
        let floor = self.floor();
        while self.keyframes.front().is_some_and(|k| k.at < floor) {
            self.keyframes.pop_front();
        }
    }

    /// Absolute offset of the oldest byte still held.
    fn floor(&self) -> u64 {
        self.chunks.front().map_or(self.head, |c| c.start)
    }

    /// What the stream carries, once the scanner has settled it. See
    /// `ts::Scanner::program`.
    pub fn program(&self) -> Option<ts::Program> {
        self.scanner.program()
    }

    /// How far behind the live edge a new video encoder would start: the
    /// content between the newest keyframe (its prime point) and the live
    /// edge. `None` if there is no keyframe or no PTS yet. A copy encoder
    /// holds this offset, so it is the lag the proxy adds for that encoder's
    /// listeners.
    pub fn newest_keyframe_lag(&self) -> Option<Duration> {
        let latest = self.scanner.latest_video_pts()?;
        let kf = self.keyframes.back()?.pts?;
        pts_gap(kf, latest)
    }

    /// Time since the source's video content clock last advanced — a
    /// freshness signal. `None` before any video PTS has been seen.
    pub fn live_edge_age(&self) -> Option<Duration> {
        self.latest_pts_at.map(|t| t.elapsed())
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }

    /// Assemble what a new encoder should be primed with.
    pub fn snapshot(&self, policy: Policy) -> Primed {
        match policy {
            Policy::FromKeyframe => match self.keyframes.back() {
                Some(kf) => Primed {
                    data: self.bytes_from(kf.at),
                    from_keyframe: true,
                },
                None => Primed {
                    data: sync_trim(self.bytes_from(self.floor())),
                    from_keyframe: false,
                },
            },
            Policy::Tail(d) => {
                let newest = self.chunks.back().map(|c| c.at);
                let start = self
                    .chunks
                    .iter()
                    .find(|c| newest.is_some_and(|n| n.duration_since(c.at) <= d))
                    .map_or(self.floor(), |c| c.start);
                Primed {
                    data: sync_trim(self.bytes_from(start)),
                    from_keyframe: false,
                }
            }
        }
    }

    /// Everything from absolute offset `off` to the head, as one buffer.
    fn bytes_from(&self, off: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.head.saturating_sub(off) as usize);
        for c in &self.chunks {
            let end = c.start + c.data.len() as u64;
            if end <= off {
                continue;
            }
            let skip = off.saturating_sub(c.start) as usize;
            out.extend_from_slice(&c.data[skip..]);
        }
        out
    }
}

/// Trim to the first TS packet boundary. Handing ffmpeg a partial packet only
/// costs it a resync, but starting clean keeps the "could not find codec
/// parameters" failure mode off the table for the sake of a few bytes.
///
/// A sync byte is only convincing if the next packet has one too.
fn sync_trim(mut bytes: Vec<u8>) -> Vec<u8> {
    let start = (0..bytes.len().min(TS_PACKET))
        .find(|&i| bytes[i] == 0x47 && bytes.get(i + TS_PACKET).is_none_or(|&b| b == 0x47));
    if let Some(i) = start {
        bytes.drain(..i);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ts::fixtures::*;
    use std::thread::sleep;

    const LONG: Duration = Duration::from_secs(3600);
    const BIG: usize = 64 * 1024 * 1024;

    /// Build `count` TS packets whose payload byte identifies the packet.
    fn ts_packets(count: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(count * 188);
        for i in 0..count {
            v.push(0x47);
            v.extend_from_slice(&[0x01, 0x00, 0x10]);
            v.extend(std::iter::repeat_n((i & 0xFF) as u8, 184));
        }
        v
    }

    fn keyframe_pes() -> Vec<u8> {
        pes(
            0x101,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        )
    }

    /// A video keyframe PES carrying an explicit PTS in seconds.
    fn keyframe_at(secs: f64) -> Vec<u8> {
        pes_at(
            0x101,
            (secs * 90_000.0) as u64,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        )
    }

    /// A non-keyframe video PES carrying an explicit PTS, to advance the clock.
    fn slice_at(secs: f64) -> Vec<u8> {
        pes_at(
            0x101,
            (secs * 90_000.0) as u64,
            None,
            &[AUD.as_slice(), SLICE.as_slice()].concat(),
        )
    }

    fn whole(r: &Replay) -> Vec<u8> {
        r.snapshot(Policy::Tail(LONG)).data
    }

    #[test]
    fn keeps_the_most_recent_bytes_under_the_byte_cap() {
        let cap = 4 * 1024 * 1024;
        let mut r = Replay::new(LONG, cap);
        let data = ts_packets(cap / 188 + 500);
        for chunk in data.chunks(64 * 1024) {
            r.push(Bytes::copy_from_slice(chunk));
        }
        let window = whole(&r);
        assert!(window.len() <= cap);
        assert!(window.len() > cap - 64 * 1024 - 188);
        assert_eq!(&window[window.len() - 184..], &data[data.len() - 184..]);
    }

    #[test]
    fn window_starts_on_a_packet_boundary() {
        let mut r = Replay::new(LONG, BIG);
        r.push(Bytes::copy_from_slice(&ts_packets(10)[57..]));
        let window = whole(&r);
        assert_eq!(window.first(), Some(&0x47), "must begin at a sync byte");
        assert_eq!(window[188], 0x47, "and the next packet must line up");
    }

    #[test]
    fn is_empty_before_any_data() {
        let r = Replay::new(LONG, BIG);
        assert!(r.is_empty());
        assert!(whole(&r).is_empty());
        assert_eq!(
            r.snapshot(Policy::FromKeyframe),
            Primed {
                data: vec![],
                from_keyframe: false
            }
        );
    }

    #[test]
    fn survives_a_stream_with_no_sync_bytes() {
        let mut r = Replay::new(LONG, BIG);
        r.push(Bytes::from(vec![0x00; 1000]));
        assert_eq!(whole(&r).len(), 1000);
    }

    #[test]
    fn primes_a_video_encoder_from_the_newest_keyframe() {
        let (_, tables) = h264_stream();
        let mut r = Replay::new(LONG, BIG);
        r.push(Bytes::from(tables));
        r.push(Bytes::from(keyframe_pes()));
        r.push(Bytes::from(ts_packets(5)));
        let second = keyframe_pes();
        r.push(Bytes::from(second.clone()));
        let tail = ts_packets(3);
        r.push(Bytes::from(tail.clone()));

        let p = r.snapshot(Policy::FromKeyframe);
        assert!(p.from_keyframe);
        assert_eq!(
            p.data,
            [second, tail].concat(),
            "newest keyframe to the head"
        );
    }

    #[test]
    fn falls_back_to_the_whole_window_without_a_keyframe() {
        let mut r = Replay::new(LONG, BIG);
        let data = ts_packets(20);
        r.push(Bytes::copy_from_slice(&data[..1000]));
        r.push(Bytes::copy_from_slice(&data[1000..]));
        let p = r.snapshot(Policy::FromKeyframe);
        assert!(!p.from_keyframe);
        assert_eq!(p.data, data);
    }

    #[test]
    fn forgets_keyframes_that_have_left_the_window() {
        let (_, tables) = h264_stream();
        let mut r = Replay::new(LONG, 2000);
        r.push(Bytes::from(tables));
        r.push(Bytes::from(keyframe_pes()));
        assert!(r.snapshot(Policy::FromKeyframe).from_keyframe);
        r.push(Bytes::from(ts_packets(20)));
        // The keyframe chunk was trimmed to stay under the byte cap.
        assert!(!r.snapshot(Policy::FromKeyframe).from_keyframe);
    }

    #[test]
    fn drops_chunks_older_than_the_age_cap() {
        let mut r = Replay::new(Duration::from_millis(30), BIG);
        r.push(Bytes::from(ts_packets(4)));
        sleep(Duration::from_millis(80));
        let fresh = ts_packets(2);
        r.push(Bytes::from(fresh.clone()));
        assert_eq!(whole(&r), fresh);
        assert_eq!(r.len(), fresh.len());
    }

    #[test]
    fn tail_takes_only_recent_chunks() {
        let mut r = Replay::new(LONG, BIG);
        r.push(Bytes::from(ts_packets(4)));
        sleep(Duration::from_millis(80));
        let fresh = ts_packets(2);
        r.push(Bytes::from(fresh.clone()));
        assert_eq!(
            r.snapshot(Policy::Tail(Duration::from_millis(10))).data,
            fresh
        );
        assert_eq!(r.snapshot(Policy::Tail(LONG)).data.len(), 6 * 188);
    }

    #[test]
    fn never_trims_the_only_chunk() {
        let mut r = Replay::new(Duration::ZERO, 10);
        r.push(Bytes::from(ts_packets(2)));
        assert_eq!(r.len(), 2 * 188);
    }

    // -- lag reporting --------------------------------------------------------

    #[test]
    fn newest_keyframe_lag_is_the_gap_from_the_prime_point_to_live() {
        let (_, tables) = h264_stream();
        let mut r = Replay::new(LONG, BIG);
        r.push(Bytes::from(tables));
        assert_eq!(r.newest_keyframe_lag(), None, "no keyframe yet");
        r.push(Bytes::from(keyframe_at(10.0))); // newest keyframe at 10s
        r.push(Bytes::from(slice_at(11.5))); // live edge advances to 11.5s
        assert_eq!(r.newest_keyframe_lag(), Some(Duration::from_millis(1500)));
        // A newer keyframe closer to live shrinks the lag.
        r.push(Bytes::from(keyframe_at(11.5)));
        r.push(Bytes::from(slice_at(11.8)));
        assert_eq!(r.newest_keyframe_lag(), Some(Duration::from_millis(300)));
    }

    #[test]
    fn newest_keyframe_lag_survives_a_pts_wrap() {
        let (_, tables) = h264_stream();
        let mut r = Replay::new(LONG, BIG);
        r.push(Bytes::from(tables));
        let top = (1u64 << 33) - 45_000; // keyframe 0.5s before the wrap
        r.push(Bytes::from(pes_at(
            0x101,
            top,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        )));
        r.push(Bytes::from(pes_at(
            0x101,
            45_000,
            None,
            &[AUD.as_slice(), SLICE.as_slice()].concat(),
        ))); // live edge 0.5s after the wrap
        assert_eq!(r.newest_keyframe_lag(), Some(Duration::from_secs(1)));
    }

    #[test]
    fn live_edge_age_tracks_the_last_video_pts_advance() {
        let (_, tables) = h264_stream();
        let mut r = Replay::new(LONG, BIG);
        r.push(Bytes::from(tables));
        assert_eq!(r.live_edge_age(), None, "no video PTS seen yet");
        r.push(Bytes::from(keyframe_at(1.0)));
        sleep(Duration::from_millis(60));
        // Non-video packets do not reset the clock.
        r.push(Bytes::from(ts_packets(2)));
        assert!(r.live_edge_age().unwrap() >= Duration::from_millis(60));
        // A fresh video PTS does.
        r.push(Bytes::from(slice_at(1.5)));
        assert!(r.live_edge_age().unwrap() < Duration::from_millis(30));
    }
}
