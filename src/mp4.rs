//! Fragmented-MP4 box scanning for late joiners.
//!
//! A client that attaches mid-stream cannot just be handed live bytes: fMP4
//! needs the init segment (`ftyp` + `moov`) before any media, and must start on
//! a fragment boundary — and, since fragments are cut on a timer as well as on
//! keyframes, on a fragment whose video begins with a keyframe, or it decodes
//! garbage until the next one. This scanner is a pass-through: it never
//! consumes bytes, it only reports where the structure boundaries fall and
//! which fragments are safe to join at, so the fan-out layer can cache the
//! init segment and align newcomers.
//!
//! ADTS and MP3 need none of this: they are self-synchronising, so every byte
//! offset is a valid join point.

use std::collections::HashMap;

use bytes::Bytes;

/// ISO-BMFF box header: 4-byte big-endian size, then 4-byte ASCII type.
const SHORT_HEADER: usize = 8;
/// `size == 1` means a 64-bit `largesize` follows the type.
const LONG_HEADER: usize = 16;
/// A `moof` is held back until it is complete so its sample flags can be read.
/// A real one is a few KB; anything near this is not a moof at all.
const MAX_MOOF: u64 = 4 * 1024 * 1024;
/// `sample_is_non_sync_sample` in ISO-BMFF sample flags.
const NON_SYNC: u32 = 0x0001_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    /// Part of the init segment: everything preceding the first `moof`.
    Init(Bytes),
    /// Media bytes. `fragment_start` marks a run beginning at a `moof` header;
    /// `keyframe` says its video begins on a sync sample, which together mark
    /// where a late joiner may safely be attached.
    Media {
        data: Bytes,
        fragment_start: bool,
        keyframe: bool,
    },
}

impl Piece {
    pub fn data(&self) -> &Bytes {
        match self {
            Piece::Init(d) => d,
            Piece::Media { data, .. } => data,
        }
    }

    pub fn fragment_start(&self) -> bool {
        matches!(
            self,
            Piece::Media {
                fragment_start: true,
                ..
            }
        )
    }

    /// True for a fragment start whose first video sample is a keyframe. Also
    /// true when the stream has no video track: audio fragments are all
    /// joinable.
    pub fn keyframe(&self) -> bool {
        matches!(self, Piece::Media { keyframe: true, .. })
    }
}

/// Media bytes accumulated within a single `push`, held only long enough to
/// coalesce a run into one piece. Never held across calls: that would trade
/// latency for tidiness, which is the wrong way round here.
#[derive(Debug, Default)]
struct Pending {
    parts: Vec<Bytes>,
    starts: bool,
    keyframe: bool,
}

impl Pending {
    fn take(&mut self) -> Option<Piece> {
        let (starts, keyframe) = (self.starts, self.keyframe);
        self.starts = false;
        self.keyframe = false;
        match self.parts.len() {
            0 => None,
            // The common case: one contiguous slice, so no copy at all.
            1 => Some(Piece::Media {
                data: self.parts.pop().unwrap(),
                fragment_start: starts,
                keyframe,
            }),
            _ => {
                let len = self.parts.iter().map(|p| p.len()).sum();
                let mut merged = Vec::with_capacity(len);
                for p in self.parts.drain(..) {
                    merged.extend_from_slice(&p);
                }
                Some(Piece::Media {
                    data: Bytes::from(merged),
                    fragment_start: starts,
                    keyframe,
                })
            }
        }
    }
}

/// What the init segment says about the tracks, as far as keyframes go.
#[derive(Debug, Default)]
struct Tracks {
    /// Track ids whose handler is `vide`.
    video: Vec<u32>,
    /// `trex` default sample flags per track, the last resort when a fragment
    /// carries no flags of its own.
    trex_flags: HashMap<u32, u32>,
}

impl Tracks {
    fn parse(init: &[u8]) -> Tracks {
        let mut t = Tracks::default();
        for (_, moov) in boxes(init).filter(|(k, _)| k == b"moov") {
            for (kind, body) in boxes(moov) {
                match &kind {
                    b"trak" => {
                        let mut id = None;
                        let mut handler: Option<[u8; 4]> = None;
                        for (k2, b2) in boxes(body) {
                            match &k2 {
                                b"tkhd" => {
                                    // Version 1 widens the two timestamps before track_ID.
                                    id = u32_at(b2, if b2.first() == Some(&1) { 20 } else { 12 });
                                }
                                b"mdia" => {
                                    handler = boxes(b2)
                                        .find(|(k3, _)| k3 == b"hdlr")
                                        .and_then(|(_, h)| h.get(8..12)?.try_into().ok());
                                }
                                _ => {}
                            }
                        }
                        if let (Some(id), Some(b"vide")) = (id, handler.as_ref()) {
                            t.video.push(id);
                        }
                    }
                    b"mvex" => {
                        for (_, b2) in boxes(body).filter(|(k, _)| k == b"trex") {
                            if let (Some(id), Some(flags)) = (u32_at(b2, 4), u32_at(b2, 20)) {
                                t.trex_flags.insert(id, flags);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        t
    }

    /// Whether a complete `moof` (header included) begins every video track
    /// on a sync sample. A stream without video is joinable at any fragment.
    fn keyframe_fragment(&self, moof: &[u8]) -> bool {
        if self.video.is_empty() {
            return true;
        }
        let Some((_, body)) = boxes(moof).next() else {
            return false;
        };
        let mut video_seen = false;
        for (_, traf) in boxes(body).filter(|(k, _)| k == b"traf") {
            let Some((id, sync)) = self.first_sample(traf) else {
                continue;
            };
            if self.video.contains(&id) {
                video_seen = true;
                if !sync {
                    return false;
                }
            }
        }
        video_seen
    }

    /// The track id of a `traf` and whether its first sample is a sync sample,
    /// taking the flags from wherever the muxer put them: `trun`
    /// first_sample_flags, the first sample's own flags, the `tfhd` default,
    /// or the `trex` default. Unknown means non-sync.
    fn first_sample(&self, traf: &[u8]) -> Option<(u32, bool)> {
        let mut track = None;
        let mut tfhd_flags = None;
        let mut trun_flags = None;
        for (kind, b) in boxes(traf) {
            match &kind {
                b"tfhd" => {
                    let flags = u32_at(b, 0)? & 0x00FF_FFFF;
                    track = u32_at(b, 4);
                    let mut k = 8;
                    if flags & 0x01 != 0 {
                        k += 8; // base_data_offset
                    }
                    if flags & 0x02 != 0 {
                        k += 4; // sample_description_index
                    }
                    if flags & 0x08 != 0 {
                        k += 4; // default_sample_duration
                    }
                    if flags & 0x10 != 0 {
                        k += 4; // default_sample_size
                    }
                    if flags & 0x20 != 0 {
                        tfhd_flags = u32_at(b, k);
                    }
                }
                b"trun" if trun_flags.is_none() => {
                    let flags = u32_at(b, 0)? & 0x00FF_FFFF;
                    let count = u32_at(b, 4)?;
                    let mut k = 8;
                    if flags & 0x01 != 0 {
                        k += 4; // data_offset
                    }
                    if flags & 0x04 != 0 {
                        trun_flags = u32_at(b, k);
                    } else if flags & 0x400 != 0 && count > 0 {
                        if flags & 0x100 != 0 {
                            k += 4; // sample_duration
                        }
                        if flags & 0x200 != 0 {
                            k += 4; // sample_size
                        }
                        trun_flags = u32_at(b, k);
                    }
                }
                _ => {}
            }
        }
        let id = track?;
        let flags = trun_flags
            .or(tfhd_flags)
            .or_else(|| self.trex_flags.get(&id).copied());
        Some((id, flags.is_some_and(|f| f & NON_SYNC == 0)))
    }
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
}

/// Iterate `(type, body)` over the boxes packed in `b`, stopping at the first
/// one that does not fit.
fn boxes(b: &[u8]) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        let size32 = u32_at(b, i)? as usize;
        let kind: [u8; 4] = b.get(i + 4..i + 8)?.try_into().ok()?;
        let (total, header) = match size32 {
            1 => {
                let large = u64::from_be_bytes(b.get(i + 8..i + 16)?.try_into().ok()?);
                (usize::try_from(large).ok()?, LONG_HEADER)
            }
            0 => (b.len() - i, SHORT_HEADER),
            n => (n, SHORT_HEADER),
        };
        if total < header || i + total > b.len() {
            return None;
        }
        let body = &b[i + header..i + total];
        i += total;
        Some((kind, body))
    })
}

#[derive(Debug, Default)]
pub struct Scanner {
    /// Partial top-level box header carried across a chunk boundary.
    header: Vec<u8>,
    /// Bytes still to come in the current box body.
    body_left: u64,
    /// True until the first `moof` is seen.
    in_init: bool,
    init: Vec<u8>,
    /// Set when the box structure stops making sense. The scanner degrades to a
    /// pass-through rather than corrupting the stream; late joiners can no
    /// longer be served, which the caller checks via `failed`.
    failed: bool,
    started: bool,
    pending: Pending,
    /// The `moof` in progress, header included, held until it is complete.
    moof: Option<Vec<u8>>,
    /// Parsed from the init segment when the first `moof` arrives.
    tracks: Option<Tracks>,
}

impl Scanner {
    pub fn new() -> Self {
        Scanner {
            in_init: true,
            ..Default::default()
        }
    }

    /// The cached init segment, once the first `moof` has been reached.
    pub fn init_segment(&self) -> Option<Bytes> {
        if self.in_init || self.init.is_empty() {
            None
        } else {
            Some(Bytes::copy_from_slice(&self.init))
        }
    }

    /// True if the byte stream did not parse as fragmented MP4. Late joiners
    /// cannot be served safely once this is set.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Split one chunk of ffmpeg output into structure-aligned pieces.
    ///
    /// The concatenation of the returned pieces always equals `chunk`, minus
    /// at most a box header held back until it is complete enough to identify
    /// and a `moof` held back until its sample flags can be read. Nothing else
    /// is ever buffered across calls, and a `moof` is small and immediately
    /// followed by its `mdat`, so neither costs measurable latency.
    pub fn push(&mut self, chunk: Bytes) -> Vec<Piece> {
        if self.failed {
            return vec![Piece::Media {
                data: chunk,
                fragment_start: false,
                keyframe: false,
            }];
        }

        let mut out: Vec<Piece> = Vec::new();
        let mut i = 0usize;

        while i < chunk.len() {
            // Inside a box body: pass bytes straight through, or hold a moof.
            if self.body_left > 0 {
                let take = self.body_left.min((chunk.len() - i) as u64) as usize;
                let slice = chunk.slice(i..i + take);
                match self.moof.as_mut() {
                    Some(m) => m.extend_from_slice(&slice),
                    None => self.emit(&mut out, slice),
                }
                self.body_left -= take as u64;
                i += take;
                if self.body_left == 0 && self.moof.is_some() {
                    self.finish_moof();
                }
                continue;
            }

            // At a box boundary: accumulate a header.
            while self.header.len() < SHORT_HEADER && i < chunk.len() {
                self.header.push(chunk[i]);
                i += 1;
            }
            if self.header.len() < SHORT_HEADER {
                break; // need more bytes; header stays held back
            }

            let size32 = u32::from_be_bytes(self.header[0..4].try_into().unwrap());
            let (total, header_len) = if size32 == 1 {
                while self.header.len() < LONG_HEADER && i < chunk.len() {
                    self.header.push(chunk[i]);
                    i += 1;
                }
                if self.header.len() < LONG_HEADER {
                    break;
                }
                let large = u64::from_be_bytes(self.header[8..16].try_into().unwrap());
                (large, LONG_HEADER)
            } else if size32 == 0 {
                // "Extends to end of file" — never valid in a live fragmented
                // stream, and it would blind the scanner to every later box.
                return self.give_up(out, chunk, i);
            } else {
                (size32 as u64, SHORT_HEADER)
            };

            if total < header_len as u64 {
                return self.give_up(out, chunk, i);
            }

            let kind: [u8; 4] = self.header[4..8].try_into().unwrap();
            if !self.started {
                self.started = true;
                // A well-formed fMP4 stream opens with ftyp (or styp/moof if we
                // somehow attached mid-stream).
                if &kind != b"ftyp" && &kind != b"moof" && &kind != b"styp" {
                    return self.give_up(out, chunk, i);
                }
            }
            self.body_left = total - header_len as u64;

            if &kind == b"moof" {
                if total > MAX_MOOF {
                    return self.give_up(out, chunk, i);
                }
                self.in_init = false;
                if self.tracks.is_none() {
                    self.tracks = Some(Tracks::parse(&self.init));
                }
                // Close any run in progress so the fragment starts its own piece.
                if let Some(p) = self.pending.take() {
                    out.push(p);
                }
                self.moof = Some(std::mem::take(&mut self.header));
                if self.body_left == 0 {
                    self.finish_moof();
                }
                continue;
            }

            let header = Bytes::copy_from_slice(&self.header);
            self.header.clear();
            self.emit(&mut out, header);
        }

        if let Some(p) = self.pending.take() {
            out.push(p);
        }
        out
    }

    /// The held `moof` is complete: read its flags and start the fragment's run.
    fn finish_moof(&mut self) {
        let Some(moof) = self.moof.take() else { return };
        let keyframe = self
            .tracks
            .as_ref()
            .is_none_or(|t| t.keyframe_fragment(&moof));
        self.pending.starts = true;
        self.pending.keyframe = keyframe;
        self.pending.parts.push(Bytes::from(moof));
    }

    fn emit(&mut self, out: &mut Vec<Piece>, data: Bytes) {
        if data.is_empty() {
            return;
        }
        if self.in_init {
            self.init.extend_from_slice(&data);
            out.push(Piece::Init(data));
            return;
        }
        self.pending.parts.push(data);
    }

    /// After a structural failure, hand back everything still unconsumed —
    /// including held-back header or moof bytes — so the stream itself stays
    /// intact.
    fn give_up(&mut self, mut out: Vec<Piece>, chunk: Bytes, i: usize) -> Vec<Piece> {
        self.failed = true;
        self.in_init = false;
        // A partial init segment is worse than none: serving it to a late joiner
        // would produce a stream the client cannot decode.
        self.init.clear();

        if let Some(p) = self.pending.take() {
            out.push(p);
        }
        for held in [self.moof.take(), Some(std::mem::take(&mut self.header))]
            .into_iter()
            .flatten()
            .filter(|h| !h.is_empty())
        {
            out.push(Piece::Media {
                data: Bytes::from(held),
                fragment_start: false,
                keyframe: false,
            });
        }
        if i < chunk.len() {
            out.push(Piece::Media {
                data: chunk.slice(i..),
                fragment_start: false,
                keyframe: false,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn box_of(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let total = (SHORT_HEADER + body.len()) as u32;
        let mut v = total.to_be_bytes().to_vec();
        v.extend_from_slice(kind);
        v.extend_from_slice(body);
        v
    }

    fn large_box_of(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let total = (LONG_HEADER + body.len()) as u64;
        let mut v = 1u32.to_be_bytes().to_vec();
        v.extend_from_slice(kind);
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// A minimal but structurally valid fMP4 byte stream.
    /// Layout: ftyp(24) moov(48) | moof(28) mdat(108) | moof(28) mdat(88)
    fn stream() -> Vec<u8> {
        let mut v = box_of(b"ftyp", b"isom-brand-bytes");
        v.extend(box_of(b"moov", &[0xAA; 40]));
        v.extend(box_of(b"moof", &[0xBB; 20]));
        v.extend(box_of(b"mdat", &[0xCC; 100]));
        v.extend(box_of(b"moof", &[0xDD; 20]));
        v.extend(box_of(b"mdat", &[0xEE; 80]));
        v
    }

    const INIT_LEN: usize = 24 + 48;

    fn collect(pieces: &[Piece]) -> Vec<u8> {
        pieces.iter().flat_map(|p| p.data().to_vec()).collect()
    }

    /// Feed the stream in fixed-size slices to exercise header straddling.
    fn scan_in_chunks(data: &[u8], chunk: usize) -> (Scanner, Vec<Piece>) {
        let mut s = Scanner::new();
        let mut all = Vec::new();
        for c in data.chunks(chunk) {
            all.extend(s.push(Bytes::copy_from_slice(c)));
        }
        (s, all)
    }

    fn fragment_offsets(pieces: &[Piece]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut at = 0usize;
        for p in pieces {
            if p.fragment_start() {
                offsets.push(at);
            }
            at += p.data().len();
        }
        offsets
    }

    // -- Real init segments and fragments, as the mp4 muxer writes them ------

    fn full_box(kind: &[u8; 4], version: u8, flags: u32, body: &[u8]) -> Vec<u8> {
        let mut b = vec![version];
        b.extend_from_slice(&flags.to_be_bytes()[1..]);
        b.extend_from_slice(body);
        box_of(kind, &b)
    }

    fn trak(id: u32, handler: &[u8; 4]) -> Vec<u8> {
        let mut tkhd = vec![0u8; 8]; // creation, modification
        tkhd.extend(id.to_be_bytes());
        tkhd.extend([0u8; 60]);
        let mut hdlr = vec![0u8; 4]; // pre_defined
        hdlr.extend(handler);
        hdlr.extend([0u8; 13]);
        let mdia = box_of(b"mdia", &full_box(b"hdlr", 0, 0, &hdlr));
        box_of(b"trak", &[full_box(b"tkhd", 0, 0, &tkhd), mdia].concat())
    }

    fn trex(id: u32, default_flags: u32) -> Vec<u8> {
        let mut b = id.to_be_bytes().to_vec();
        b.extend(1u32.to_be_bytes());
        b.extend(0u32.to_be_bytes());
        b.extend(0u32.to_be_bytes());
        b.extend(default_flags.to_be_bytes());
        full_box(b"trex", 0, 0, &b)
    }

    /// ftyp + moov with a video track 1 and an audio track 2.
    fn init(trex_video_flags: u32) -> Vec<u8> {
        let mvex = box_of(
            b"mvex",
            &[trex(1, trex_video_flags), trex(2, 0x0200_0000)].concat(),
        );
        let moov = box_of(
            b"moov",
            &[trak(1, b"vide"), trak(2, b"soun"), mvex].concat(),
        );
        [box_of(b"ftyp", b"isom"), moov].concat()
    }

    const SYNC: u32 = 0x0200_0000;
    const NONSYNC: u32 = 0x0101_0000;

    /// A traf whose flags land where `Where` says.
    #[derive(Clone, Copy)]
    enum Where {
        FirstSampleFlags,
        PerSample,
        TfhdDefault,
        Nowhere,
    }

    fn traf(id: u32, flags: u32, at: Where) -> Vec<u8> {
        let (tfhd_flags, mut tfhd) = match at {
            Where::TfhdDefault => (0x20u32, [id.to_be_bytes(), flags.to_be_bytes()].concat()),
            _ => (0, id.to_be_bytes().to_vec()),
        };
        // default_sample_duration too, to prove optional fields are skipped.
        tfhd.splice(4..4, 40u32.to_be_bytes());
        let tfhd = full_box(b"tfhd", 0, tfhd_flags | 0x08, &tfhd);
        let trun = match at {
            Where::FirstSampleFlags => {
                let body = [2u32.to_be_bytes(), 0u32.to_be_bytes(), flags.to_be_bytes()].concat();
                full_box(b"trun", 0, 0x01 | 0x04, &body)
            }
            Where::PerSample => {
                let mut body = [2u32.to_be_bytes(), 0u32.to_be_bytes()].concat();
                for f in [flags, NONSYNC] {
                    body.extend(40u32.to_be_bytes()); // duration
                    body.extend(900u32.to_be_bytes()); // size
                    body.extend(f.to_be_bytes());
                }
                full_box(b"trun", 0, 0x01 | 0x100 | 0x200 | 0x400, &body)
            }
            _ => full_box(
                b"trun",
                0,
                0x01,
                &[2u32.to_be_bytes(), 0u32.to_be_bytes()].concat(),
            ),
        };
        box_of(b"traf", &[tfhd, trun].concat())
    }

    fn moof(trafs: &[Vec<u8>]) -> Vec<u8> {
        let mfhd = full_box(b"mfhd", 0, 0, &1u32.to_be_bytes());
        box_of(b"moof", &[mfhd, trafs.concat()].concat())
    }

    fn keyframe_flags_of(data: &[u8], chunk: usize) -> Vec<bool> {
        let (_, pieces) = scan_in_chunks(data, chunk);
        pieces
            .iter()
            .filter(|p| p.fragment_start())
            .map(|p| p.keyframe())
            .collect()
    }

    #[test]
    fn is_lossless_at_every_chunk_size() {
        let data = stream();
        for size in 1..=data.len() {
            let (_, pieces) = scan_in_chunks(&data, size);
            assert_eq!(collect(&pieces), data, "chunk size {size} lost bytes");
        }
    }

    #[test]
    fn init_segment_is_everything_before_the_first_moof() {
        let data = stream();
        let want = &data[..INIT_LEN];
        for size in [1, 3, 7, 8, 9, 16, 64, 4096] {
            let (s, _) = scan_in_chunks(&data, size);
            assert_eq!(s.init_segment().as_deref(), Some(want), "chunk size {size}");
        }
    }

    #[test]
    fn init_segment_is_unavailable_until_the_first_moof_arrives() {
        let mut s = Scanner::new();
        s.push(Bytes::from(box_of(b"ftyp", b"isom")));
        assert_eq!(s.init_segment(), None);
        s.push(Bytes::from(box_of(b"moov", &[0; 8])));
        assert_eq!(s.init_segment(), None, "moov alone must not complete init");
        s.push(Bytes::from(box_of(b"moof", &[0; 8])));
        assert!(s.init_segment().is_some());
    }

    #[test]
    fn fragment_starts_land_exactly_on_moof_headers() {
        let data = stream();
        for size in [1, 5, 8, 13, 64, 4096] {
            let (_, pieces) = scan_in_chunks(&data, size);
            assert_eq!(
                fragment_offsets(&pieces),
                vec![INIT_LEN, INIT_LEN + 28 + 108],
                "chunk {size}"
            );
        }
    }

    #[test]
    fn tolerates_free_boxes_inside_the_init_segment() {
        let mut data = box_of(b"ftyp", b"isom");
        data.extend(box_of(b"free", &[0; 16]));
        data.extend(box_of(b"moov", &[0xAA; 32]));
        data.extend(box_of(b"moof", &[0xBB; 8]));
        data.extend(box_of(b"mdat", &[0xCC; 8]));

        let (s, pieces) = scan_in_chunks(&data, 7);
        assert_eq!(collect(&pieces), data);
        assert_eq!(s.init_segment().map(|b| b.len()), Some(12 + 24 + 40));
        assert!(!s.failed());
    }

    #[test]
    fn handles_64_bit_largesize_boxes() {
        let mut data = box_of(b"ftyp", b"isom");
        data.extend(box_of(b"moov", &[0xAA; 16]));
        data.extend(box_of(b"moof", &[0xBB; 8]));
        // A large mdat is exactly where the 64-bit form shows up in practice.
        data.extend(large_box_of(b"mdat", &[0xCC; 200]));
        data.extend(box_of(b"moof", &[0xDD; 8]));

        for size in [1, 9, 15, 16, 17, 128] {
            let (s, pieces) = scan_in_chunks(&data, size);
            assert_eq!(collect(&pieces), data, "chunk {size}");
            assert!(!s.failed(), "chunk {size}");
            assert_eq!(
                fragment_offsets(&pieces).len(),
                2,
                "chunk {size}: largesize must not hide the second moof"
            );
        }
    }

    #[test]
    fn degrades_to_passthrough_on_garbage_without_losing_bytes() {
        // size == 0 means "to end of file" and is not valid in a live stream.
        let mut data = box_of(b"ftyp", b"isom");
        data.extend(0u32.to_be_bytes());
        data.extend(b"mdat");
        data.extend([0xCC; 32]);

        for size in [1, 6, 13, 256] {
            let (s, pieces) = scan_in_chunks(&data, size);
            assert!(s.failed(), "chunk {size}");
            assert_eq!(collect(&pieces), data, "chunk {size}: must stay lossless");
            // A partial init segment would decode to nothing for a late joiner.
            assert_eq!(s.init_segment(), None, "chunk {size}");
        }
    }

    #[test]
    fn rejects_a_stream_that_does_not_start_with_ftyp() {
        let data = box_of(b"junk", &[0; 16]);
        let (s, pieces) = scan_in_chunks(&data, 4);
        assert!(s.failed());
        assert_eq!(collect(&pieces), data);
    }

    #[test]
    fn rejects_a_box_smaller_than_its_own_header() {
        let mut data = box_of(b"ftyp", b"isom");
        data.extend(3u32.to_be_bytes()); // size 3 < 8-byte header
        data.extend(b"moov");
        data.extend([0; 8]);

        let (s, pieces) = scan_in_chunks(&data, 5);
        assert!(s.failed());
        assert_eq!(collect(&pieces), data);
    }

    #[test]
    fn rejects_an_absurdly_large_moof_without_losing_bytes() {
        let mut data = box_of(b"ftyp", b"isom");
        data.extend((MAX_MOOF as u32 + 1).to_be_bytes());
        data.extend(b"moof");
        data.extend([0xCC; 32]);
        for size in [1, 9, 64] {
            let (s, pieces) = scan_in_chunks(&data, size);
            assert!(s.failed(), "chunk {size}");
            assert_eq!(collect(&pieces), data, "chunk {size}");
        }
    }

    #[test]
    fn media_runs_are_coalesced_within_a_chunk() {
        let data = stream();
        let mut s = Scanner::new();
        let pieces = s.push(Bytes::from(data));
        let media: Vec<_> = pieces
            .iter()
            .filter(|p| !matches!(p, Piece::Init(_)))
            .collect();
        // One piece per fragment, not one per box header and body.
        assert_eq!(media.len(), 2);
        assert!(media.iter().all(|p| p.fragment_start()));
        assert_eq!(media[0].data().len(), 28 + 108);
        assert_eq!(media[1].data().len(), 28 + 88);
    }

    #[test]
    fn nothing_but_a_moof_is_buffered_across_pushes() {
        // Latency guard: a chunk that completes no box must still come straight
        // back out, minus only the held-back header.
        let mut s = Scanner::new();
        s.push(Bytes::from(box_of(b"ftyp", b"isom")));
        s.push(Bytes::from(box_of(b"moof", &[0; 64])));
        let out = s.push(Bytes::from(vec![0xCC; 32]));
        assert_eq!(collect(&out).len(), 32, "media must not be held back");
    }

    #[test]
    fn a_moof_split_across_pushes_is_held_then_emitted_whole() {
        let init = init(NONSYNC);
        let frag = moof(&[
            traf(1, SYNC, Where::FirstSampleFlags),
            traf(2, SYNC, Where::TfhdDefault),
        ]);
        let mdat = box_of(b"mdat", &[0xCC; 50]);
        let mut s = Scanner::new();
        s.push(Bytes::from(init));
        let first = s.push(Bytes::copy_from_slice(&frag[..20]));
        assert!(first.is_empty(), "an incomplete moof must be held back");
        let rest = s.push(Bytes::from([&frag[20..], &mdat[..]].concat()));
        assert_eq!(collect(&rest), [frag.clone(), mdat].concat());
        assert!(rest[0].fragment_start());
        assert!(rest[0].keyframe());
    }

    #[test]
    fn keyframe_fragments_are_recognised_wherever_the_flags_live() {
        for at in [
            Where::FirstSampleFlags,
            Where::PerSample,
            Where::TfhdDefault,
        ] {
            let mut data = init(NONSYNC);
            data.extend(moof(&[
                traf(1, SYNC, at),
                traf(2, SYNC, Where::TfhdDefault),
            ]));
            data.extend(box_of(b"mdat", &[0xCC; 20]));
            data.extend(moof(&[
                traf(1, NONSYNC, at),
                traf(2, SYNC, Where::TfhdDefault),
            ]));
            data.extend(box_of(b"mdat", &[0xCC; 20]));
            data.extend(moof(&[
                traf(1, SYNC, at),
                traf(2, SYNC, Where::TfhdDefault),
            ]));
            data.extend(box_of(b"mdat", &[0xCC; 20]));
            for chunk in [1, 13, 100, 4096] {
                assert_eq!(
                    keyframe_flags_of(&data, chunk),
                    vec![true, false, true],
                    "chunk {chunk}"
                );
            }
        }
    }

    #[test]
    fn trex_defaults_decide_when_a_fragment_carries_no_flags() {
        let mut data = init(SYNC);
        data.extend(moof(&[traf(1, 0, Where::Nowhere)]));
        data.extend(box_of(b"mdat", &[0xCC; 20]));
        assert_eq!(keyframe_flags_of(&data, 4096), vec![true]);

        let mut data = init(NONSYNC);
        data.extend(moof(&[traf(1, 0, Where::Nowhere)]));
        data.extend(box_of(b"mdat", &[0xCC; 20]));
        assert_eq!(keyframe_flags_of(&data, 4096), vec![false]);
    }

    #[test]
    fn an_audio_only_fragment_of_a_video_stream_is_not_a_join_point() {
        let mut data = init(NONSYNC);
        data.extend(moof(&[traf(2, SYNC, Where::TfhdDefault)]));
        data.extend(box_of(b"mdat", &[0xCC; 20]));
        assert_eq!(keyframe_flags_of(&data, 4096), vec![false]);
    }

    #[test]
    fn every_fragment_of_an_audio_only_stream_is_a_join_point() {
        let moov = box_of(
            b"moov",
            &[trak(1, b"soun"), box_of(b"mvex", &trex(1, SYNC))].concat(),
        );
        let mut data = [box_of(b"ftyp", b"isom"), moov].concat();
        data.extend(moof(&[traf(1, SYNC, Where::TfhdDefault)]));
        data.extend(box_of(b"mdat", &[0xCC; 20]));
        data.extend(moof(&[traf(1, NONSYNC, Where::TfhdDefault)]));
        data.extend(box_of(b"mdat", &[0xCC; 20]));
        assert_eq!(keyframe_flags_of(&data, 4096), vec![true, true]);
    }

    #[test]
    fn an_unparseable_init_segment_leaves_every_fragment_joinable() {
        // The garbage moov in `stream()` describes no tracks at all; with no
        // video track to check, keyframe alignment cannot apply.
        assert_eq!(keyframe_flags_of(&stream(), 4096), vec![true, true]);
    }
}
