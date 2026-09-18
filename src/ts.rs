//! MPEG-TS scanning: what the program carries, and which packets begin a
//! video keyframe.
//!
//! Every byte from the engine passes through this on its way into the replay
//! window. It reads only what two jobs need. The PAT and PMT name the
//! program's elementary streams, which is how the source's codecs are
//! identified without spawning ffprobe over a preroll (see [`Scanner::program`]);
//! and on the video PID, the first transport packet of each PES says whether
//! the access unit is a random-access point, which is what lets a new encoder
//! be primed from the most recent keyframe.
//!
//! Keyframe detection is by the codec's own syntax (an SPS or IDR NAL for
//! H.264, an IRAP or parameter set for HEVC, a sequence header for MPEG-2),
//! with the adaptation field's random_access_indicator only as a fallback
//! where the packet is inconclusive or the codec unknown. The flag alone is
//! not trusted: some muxers set it on every video PES, and aligning to a
//! non-keyframe is exactly the failure this scanner exists to prevent.

use Codec::{Hevc, Mpeg2, Other, H264};

const PACKET: usize = 188;
const SYNC: u8 = 0x47;
const PAT_PID: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    H264,
    Hevc,
    Mpeg2,
    /// A video stream type this scanner has no parser for; RAI decides.
    Other,
}

/// The program's first video and first audio stream, named as ffprobe would
/// name them (`h264`, `aac`, `ac3`, `mp2`, ...), so the copy-first table in
/// `format` needs no translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Program {
    pub video: Option<&'static str>,
    pub audio: Option<&'static str>,
}

/// A transport packet that begins a video keyframe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keyframe {
    /// Absolute offset of the packet, counted from the first byte ever fed.
    pub at: u64,
    /// The keyframe's presentation timestamp on the 90 kHz clock, if the PES
    /// carried one. Paired with [`Scanner::latest_video_pts`], this gives the
    /// content duration buffered after the keyframe.
    pub pts: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct Video {
    pid: u16,
    codec: Codec,
    name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Audio {
    Known(&'static str),
    /// MPEG-1/2 audio (stream types 0x03/0x04): the PMT does not say which
    /// layer, and `mp2` copies on one route while `mp3` copies on another,
    /// so the name waits for a frame header.
    MpegLayer,
    /// A private stream carrying no descriptor this scanner knows. It may be
    /// audio of any kind; ffprobe decides.
    Unknown,
}

enum Kind {
    Video(Codec, &'static str),
    Audio(Audio),
    Other,
}

/// PSI section reassembly for one PID. A PMT with many streams and
/// descriptors can outgrow one transport packet.
#[derive(Debug, Default)]
struct Section {
    buf: Vec<u8>,
    /// Total section bytes expected, once the length field has been read.
    want: Option<usize>,
}

impl Section {
    /// Feed one packet's payload; returns the section when it is complete.
    fn feed(&mut self, pusi: bool, payload: &[u8]) -> Option<Vec<u8>> {
        if pusi {
            // The pointer field skips the tail of any previous section.
            let pointer = usize::from(*payload.first()?);
            self.buf.clear();
            self.buf.extend_from_slice(payload.get(1 + pointer..)?);
            self.want = None;
        } else if self.buf.is_empty() {
            return None; // a continuation of a section we never saw start
        } else {
            self.buf.extend_from_slice(payload);
        }
        if self.want.is_none() && self.buf.len() >= 3 {
            let len = (usize::from(self.buf[1] & 0x0F) << 8) | usize::from(self.buf[2]);
            self.want = Some(3 + len);
        }
        let want = self.want?;
        if self.buf.len() < want {
            return None;
        }
        let section = self.buf[..want].to_vec();
        self.buf.clear();
        self.want = None;
        Some(section)
    }
}

#[derive(Debug, Default)]
pub struct Scanner {
    /// Bytes after the last complete packet, carried into the next `feed`.
    carry: Vec<u8>,
    /// Absolute offset of `carry[0]`, or of the next byte if `carry` is empty.
    pos: u64,
    pat: Section,
    pmt: Section,
    pmt_pid: Option<u16>,
    pmt_seen: bool,
    video: Option<Video>,
    audio: Option<(u16, Audio)>,
    /// The most recent presentation timestamp seen on the video PID, i.e. the
    /// content clock at the live edge.
    latest_video_pts: Option<u64>,
}

impl Scanner {
    pub fn new() -> Self {
        Scanner::default()
    }

    /// The program's video codec, once the PMT has been seen.
    #[cfg(test)]
    pub fn video_codec(&self) -> Option<Codec> {
        self.video.map(|v| v.codec)
    }

    /// Whether the PMT named a video stream. Known once the PMT is seen.
    pub fn has_video(&self) -> bool {
        self.video.is_some()
    }

    /// The content clock at the live edge: the newest video PTS seen.
    pub fn latest_video_pts(&self) -> Option<u64> {
        self.latest_video_pts
    }

    /// What the program carries, once that is settled: the PMT has been seen
    /// and the first audio stream, if any, has a name. `None` while it is
    /// not — including indefinitely for a first audio stream the scanner
    /// cannot name, which is the caller's cue to fall back to ffprobe.
    pub fn program(&self) -> Option<Program> {
        if !self.pmt_seen {
            return None;
        }
        let audio = match self.audio {
            None => None,
            Some((_, Audio::Known(name))) => Some(name),
            Some((_, Audio::MpegLayer | Audio::Unknown)) => return None,
        };
        Some(Program {
            video: self.video.map(|v| v.name),
            audio,
        })
    }

    /// Consume `data` and return a [`Keyframe`] for every transport packet
    /// that begins a video keyframe, with offsets counted from the first byte
    /// ever fed.
    ///
    /// Input need not be packet-aligned: the scanner resynchronises on a sync
    /// byte that is followed by another one packet later, as the mpegts demuxer
    /// does, and carries a trailing partial packet into the next call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<Keyframe> {
        let owned;
        let buf: &[u8] = if self.carry.is_empty() {
            data
        } else {
            owned = [self.carry.as_slice(), data].concat();
            &owned
        };
        let base = self.pos;
        let mut found = Vec::new();
        let mut i = 0;
        while i + PACKET <= buf.len() {
            let next = i + PACKET;
            if buf[i] != SYNC || (next < buf.len() && buf[next] != SYNC) {
                i += 1; // resync a byte at a time
                continue;
            }
            if let Some(pts) = self.packet(&buf[i..next]) {
                found.push(Keyframe {
                    at: base + i as u64,
                    pts,
                });
            }
            i = next;
        }
        self.carry = buf[i..].to_vec();
        self.pos = base + i as u64;
        found
    }

    /// Handle one 188-byte packet. `Some(pts)` if it starts a video keyframe,
    /// where `pts` is the keyframe's presentation timestamp if the PES carried
    /// one; `None` otherwise. Updates the live-edge video PTS as a side effect.
    fn packet(&mut self, p: &[u8]) -> Option<Option<u64>> {
        let pid = (u16::from(p[1] & 0x1F) << 8) | u16::from(p[2]);
        let pusi = p[1] & 0x40 != 0;
        let afc = (p[3] >> 4) & 0x3;
        let mut off = 4;
        let mut rai = false;
        if afc & 0x2 != 0 {
            let len = usize::from(p[4]);
            if len > 0 {
                rai = p[5] & 0x40 != 0;
            }
            off = 5 + len;
        }
        if afc & 0x1 == 0 || off >= PACKET {
            return None;
        }
        let payload = &p[off..];

        if pid == PAT_PID {
            if let Some(section) = self.pat.feed(pusi, payload) {
                self.parse_pat(&section);
            }
            return None;
        }
        if Some(pid) == self.pmt_pid {
            if let Some(section) = self.pmt.feed(pusi, payload) {
                self.parse_pmt(&section);
            }
            return None;
        }
        if !pusi {
            return None;
        }
        if let Some((apid, Audio::MpegLayer)) = self.audio {
            if apid == pid {
                if let Some(name) = mpeg_audio_layer(payload) {
                    self.audio = Some((pid, Audio::Known(name)));
                }
                return None;
            }
        }
        match self.video {
            Some(v) if v.pid == pid => {
                let pts = pes_pts(payload);
                if pts.is_some() {
                    self.latest_video_pts = pts;
                }
                keyframe(v.codec, payload).unwrap_or(rai).then_some(pts)
            }
            _ => None,
        }
    }

    fn parse_pat(&mut self, s: &[u8]) {
        if s.first() != Some(&0x00) || self.pmt_pid.is_some() {
            return;
        }
        // Program entries follow the 8-byte header; the last 4 bytes are the CRC.
        let mut i = 8;
        while i + 4 <= s.len().saturating_sub(4) {
            let program = (u16::from(s[i]) << 8) | u16::from(s[i + 1]);
            let pid = (u16::from(s[i + 2] & 0x1F) << 8) | u16::from(s[i + 3]);
            // Program 0 is the network PID, not a program.
            if program != 0 {
                self.pmt_pid = Some(pid);
                return;
            }
            i += 4;
        }
    }

    /// Take the first video and the first audio stream, in PMT order, which
    /// is the order ffprobe reports them in.
    fn parse_pmt(&mut self, s: &[u8]) {
        // A PMT repeats several times a second; the first one settles it.
        if s.first() != Some(&0x02) || s.len() < 12 || self.pmt_seen {
            return;
        }
        let program_info = (usize::from(s[10] & 0x0F) << 8) | usize::from(s[11]);
        let mut i = 12 + program_info;
        let end = s.len().saturating_sub(4);
        while i + 5 <= end {
            let stream_type = s[i];
            let pid = (u16::from(s[i + 1] & 0x1F) << 8) | u16::from(s[i + 2]);
            let es_info_len = (usize::from(s[i + 3] & 0x0F) << 8) | usize::from(s[i + 4]);
            let es_info = s.get(i + 5..(i + 5 + es_info_len).min(end)).unwrap_or(&[]);
            match classify(stream_type, es_info) {
                Kind::Video(codec, name) if self.video.is_none() => {
                    self.video = Some(Video { pid, codec, name });
                }
                Kind::Audio(audio) if self.audio.is_none() => {
                    self.audio = Some((pid, audio));
                }
                _ => {}
            }
            i += 5 + es_info_len;
        }
        self.pmt_seen = true;
    }
}

fn descriptors(es_info: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut i = 0;
    std::iter::from_fn(move || {
        let tag = *es_info.get(i)?;
        let len = usize::from(*es_info.get(i + 1)?);
        let data = es_info.get(i + 2..i + 2 + len)?;
        i += 2 + len;
        Some((tag, data))
    })
}

/// What a PMT entry is, from its stream type and, for private streams, its
/// descriptors. Names follow ffprobe's `codec_name`.
fn classify(stream_type: u8, es_info: &[u8]) -> Kind {
    match stream_type {
        0x01 => Kind::Video(Mpeg2, "mpeg1video"),
        0x02 => Kind::Video(Mpeg2, "mpeg2video"),
        0x10 => Kind::Video(Other, "mpeg4"),
        0x1B => Kind::Video(H264, "h264"),
        0x24 => Kind::Video(Hevc, "hevc"),
        0xEA => Kind::Video(Other, "vc1"),
        0x03 | 0x04 => Kind::Audio(Audio::MpegLayer),
        0x0F | 0x1C => Kind::Audio(Audio::Known("aac")),
        0x11 => Kind::Audio(Audio::Known("aac_latm")),
        0x81 => Kind::Audio(Audio::Known("ac3")),
        0x87 => Kind::Audio(Audio::Known("eac3")),
        0x82 | 0x85 | 0x8A => Kind::Audio(Audio::Known("dts")),
        // DVB carries AC-3, E-AC-3, DTS and subtitles as private data, told
        // apart by descriptor; ATSC and others use a registration descriptor.
        0x06 => {
            for (tag, data) in descriptors(es_info) {
                match (tag, data.get(..4)) {
                    (0x6A, _) => return Kind::Audio(Audio::Known("ac3")),
                    (0x7A, _) => return Kind::Audio(Audio::Known("eac3")),
                    (0x7B, _) => return Kind::Audio(Audio::Known("dts")),
                    (0x56 | 0x59, _) => return Kind::Other, // teletext, subtitles
                    (0x05, Some(b"AC-3")) => return Kind::Audio(Audio::Known("ac3")),
                    (0x05, Some(b"EAC3")) => return Kind::Audio(Audio::Known("eac3")),
                    (0x05, Some(b"DTS1" | b"DTS2" | b"DTS3")) => {
                        return Kind::Audio(Audio::Known("dts"))
                    }
                    (0x05, Some(b"Opus")) => return Kind::Audio(Audio::Known("opus")),
                    (0x05, Some(b"HEVC")) => return Kind::Video(Hevc, "hevc"),
                    _ => {}
                }
            }
            Kind::Audio(Audio::Unknown)
        }
        _ => Kind::Other,
    }
}

/// The 33-bit PTS of a PES-start packet on the 90 kHz clock, if it carries one.
fn pes_pts(payload: &[u8]) -> Option<u64> {
    if payload.len() < 14 || payload[..3] != [0, 0, 1] {
        return None;
    }
    // PTS_DTS_flags live in the high two bits of byte 7; either value (PTS
    // only, or PTS and DTS) puts the PTS in bytes 9..14.
    if payload[7] & 0x80 == 0 {
        return None;
    }
    let b = &payload[9..14];
    Some(
        (u64::from(b[0] >> 1 & 0x07) << 30)
            | (u64::from(b[1]) << 22)
            | (u64::from(b[2] >> 1 & 0x7F) << 15)
            | (u64::from(b[3]) << 7)
            | u64::from(b[4] >> 1 & 0x7F),
    )
}

/// The elementary stream bytes of a PES-start packet, past the PES header.
fn pes_payload(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 9 || payload[..3] != [0, 0, 1] {
        return None;
    }
    payload.get(9 + usize::from(payload[8])..)
}

/// The layer of the first MPEG audio frame header in a PES-start packet, as
/// ffprobe names it.
fn mpeg_audio_layer(payload: &[u8]) -> Option<&'static str> {
    let es = pes_payload(payload)?;
    es.windows(3).find_map(|w| {
        if w[0] != 0xFF || w[1] & 0xE0 != 0xE0 {
            return None;
        }
        let version = (w[1] >> 3) & 0x3; // 1 is reserved
        let bitrate = w[2] >> 4; // 15 is invalid
        let rate = (w[2] >> 2) & 0x3; // 3 is reserved
        if version == 1 || bitrate == 15 || rate == 3 {
            return None;
        }
        match (w[1] >> 1) & 0x3 {
            3 => Some("mp1"),
            2 => Some("mp2"),
            1 => Some("mp3"),
            _ => None,
        }
    })
}

/// Whether the PES starting in `payload` is a keyframe: `Some(verdict)` when
/// the first packet's NAL units settle it, `None` when they do not.
fn keyframe(codec: Codec, payload: &[u8]) -> Option<bool> {
    let es = pes_payload(payload)?;
    let mut i = 0;
    while i + 4 <= es.len() {
        if es[i..i + 3] != [0, 0, 1] {
            i += 1;
            continue;
        }
        let b = es[i + 3];
        let verdict = match codec {
            H264 => match b & 0x1F {
                5 | 7 => Some(true),  // IDR slice, or the SPS that precedes one
                1..=4 => Some(false), // a non-IDR slice
                _ => None,            // AUD, SEI, PPS: keep looking
            },
            Hevc => match (b >> 1) & 0x3F {
                16..=21 | 32 | 33 => Some(true), // BLA/IDR/CRA, or VPS/SPS
                0..=9 => Some(false),            // a non-IRAP slice
                _ => None,
            },
            Mpeg2 => match b {
                0xB3 | 0xB8 => Some(true), // sequence header, GOP header
                // Picture start: coding type 1 is an I-frame.
                0x00 => Some(es.get(i + 5).is_some_and(|t| (t >> 3) & 0x7 == 1)),
                _ => None,
            },
            Other => return None,
        };
        if verdict.is_some() {
            return verdict;
        }
        i += 4;
    }
    None
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// One transport packet. `rai` adds an adaptation field carrying that flag.
    pub fn packet(pid: u16, pusi: bool, rai: Option<bool>, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![SYNC, (pid >> 8) as u8 & 0x1F, pid as u8, 0x10];
        if pusi {
            p[1] |= 0x40;
        }
        let body = match rai {
            Some(flag) => {
                p[3] = 0x30;
                // Adaptation field padded so the payload exactly fills the packet.
                let af_len = PACKET - 4 - 1 - payload.len();
                let mut af = vec![af_len as u8, if flag { 0x40 } else { 0x00 }];
                af.resize(1 + af_len, 0xFF);
                [af, payload.to_vec()].concat()
            }
            None => {
                let mut v = payload.to_vec();
                v.resize(PACKET - 4, 0xFF);
                v
            }
        };
        p.extend(body);
        assert_eq!(p.len(), PACKET);
        p
    }

    pub fn pat(pmt_pid: u16) -> Vec<u8> {
        let mut s = vec![0x00, 0xB0, 13, 0x00, 0x01, 0xC1, 0x00, 0x00];
        s.extend([0x00, 0x01, 0xE0 | (pmt_pid >> 8) as u8, pmt_pid as u8]);
        s.extend([0, 0, 0, 0]); // crc, unchecked
        packet(0, true, None, &[&[0u8][..], &s].concat())
    }

    /// A PMT section (not yet packetised) listing `streams` as
    /// `(stream_type, pid, descriptors)`.
    pub fn pmt_section(streams: &[(u8, u16, &[u8])]) -> Vec<u8> {
        let mut s = vec![
            0x02, 0xB0, 0, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x00, 0xF0, 0x00,
        ];
        for &(stream_type, pid, desc) in streams {
            s.extend([stream_type, 0xE0 | (pid >> 8) as u8, pid as u8]);
            s.extend([0xF0 | (desc.len() >> 8) as u8, desc.len() as u8]);
            s.extend_from_slice(desc);
        }
        s.extend([0, 0, 0, 0]);
        let len = s.len() - 3;
        s[1] = 0xB0 | (len >> 8) as u8;
        s[2] = len as u8;
        s
    }

    /// A PMT in one packet.
    pub fn pmt_with(pmt_pid: u16, streams: &[(u8, u16, &[u8])]) -> Vec<u8> {
        let s = pmt_section(streams);
        assert!(s.len() <= PACKET - 5, "use pmt_packets for a long PMT");
        packet(pmt_pid, true, None, &[&[0u8][..], &s].concat())
    }

    /// A PMT spread over as many packets as it needs.
    pub fn pmt_packets(pmt_pid: u16, streams: &[(u8, u16, &[u8])]) -> Vec<u8> {
        let s = [&[0u8][..], &pmt_section(streams)].concat();
        let mut out = Vec::new();
        for (n, chunk) in s.chunks(PACKET - 4).enumerate() {
            out.extend(packet(pmt_pid, n == 0, None, chunk));
        }
        out
    }

    pub fn pmt(pmt_pid: u16, streams: &[(u8, u16)]) -> Vec<u8> {
        let with: Vec<(u8, u16, &[u8])> = streams.iter().map(|&(t, p)| (t, p, &[][..])).collect();
        pmt_with(pmt_pid, &with)
    }

    /// A PES-start packet whose elementary stream begins with `es`. Carries a
    /// PTS of 0.
    pub fn pes(pid: u16, rai: Option<bool>, es: &[u8]) -> Vec<u8> {
        pes_at(pid, 0, rai, es)
    }

    /// A PES-start packet carrying an explicit 90 kHz PTS.
    pub fn pes_at(pid: u16, pts: u64, rai: Option<bool>, es: &[u8]) -> Vec<u8> {
        let p = pts & ((1 << 33) - 1);
        let ts = [
            0x20 | ((p >> 29) & 0x0E) as u8 | 0x01,
            (p >> 22) as u8,
            (((p >> 14) & 0xFE) as u8) | 0x01,
            (p >> 7) as u8,
            (((p << 1) & 0xFE) as u8) | 0x01,
        ];
        let mut payload = vec![0, 0, 1, 0xE0, 0, 0, 0x80, 0x80, 5];
        payload.extend_from_slice(&ts);
        payload.extend_from_slice(es);
        packet(pid, true, rai, &payload)
    }

    pub const AUD: [u8; 6] = [0, 0, 0, 1, 0x09, 0xF0];
    pub const SPS: [u8; 8] = [0, 0, 0, 1, 0x67, 0x64, 0x00, 0x1F];
    pub const IDR: [u8; 6] = [0, 0, 0, 1, 0x65, 0x88];
    pub const SLICE: [u8; 6] = [0, 0, 0, 1, 0x41, 0x9A];
    pub const SEI: [u8; 7] = [0, 0, 0, 1, 0x06, 0x01, 0x80];

    /// PAT + PMT for an H.264 + AAC program: video on 0x101, audio on 0x102.
    pub fn h264_stream() -> (Scanner, Vec<u8>) {
        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x0F, 0x102), (0x1B, 0x101)]));
        (Scanner::new(), data)
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    /// The keyframe offsets, for the many tests that only care where they fell.
    fn ats(kfs: Vec<Keyframe>) -> Vec<u64> {
        kfs.iter().map(|k| k.at).collect()
    }

    fn program_of(data: &[u8]) -> Option<Program> {
        let mut s = Scanner::new();
        s.feed(data);
        s.program()
    }

    fn named(video: Option<&'static str>, audio: Option<&'static str>) -> Option<Program> {
        Some(Program { video, audio })
    }

    // -- keyframes ------------------------------------------------------------

    #[test]
    fn finds_h264_keyframes_by_sps_or_idr() {
        let (mut s, mut data) = h264_stream();
        let at_sps = data.len() as u64;
        data.extend(pes(
            0x101,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        ));
        data.extend(pes(
            0x101,
            None,
            &[AUD.as_slice(), SLICE.as_slice()].concat(),
        ));
        data.extend(packet(0x101, false, None, &[0xAA; 100]));
        let at_idr = data.len() as u64;
        data.extend(pes(
            0x101,
            None,
            &[AUD.as_slice(), SEI.as_slice(), IDR.as_slice()].concat(),
        ));
        assert_eq!(ats(s.feed(&data)), vec![at_sps, at_idr]);
        assert_eq!(s.video_codec(), Some(Codec::H264));
    }

    #[test]
    fn tracks_video_pts_and_tags_keyframes() {
        let (mut s, mut data) = h264_stream();
        assert_eq!(s.latest_video_pts(), None);
        let at = data.len() as u64;
        // A keyframe at 10 s, then a non-keyframe slice at 11 s.
        data.extend(pes_at(
            0x101,
            900_000,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        ));
        data.extend(pes_at(
            0x101,
            990_000,
            None,
            &[AUD.as_slice(), SLICE.as_slice()].concat(),
        ));
        assert_eq!(
            s.feed(&data),
            vec![Keyframe {
                at,
                pts: Some(900_000)
            }]
        );
        assert_eq!(
            s.latest_video_pts(),
            Some(990_000),
            "the clock advances past the keyframe"
        );
    }

    #[test]
    fn pts_survives_a_33_bit_value() {
        let (mut s, mut data) = h264_stream();
        let big = (1u64 << 33) - 1;
        data.extend(pes_at(
            0x101,
            big,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        ));
        assert_eq!(s.feed(&data).first().and_then(|k| k.pts), Some(big));
    }

    #[test]
    fn audio_pts_does_not_touch_the_video_clock() {
        let (mut s, mut data) = h264_stream();
        data.extend(pes_at(0x102, 5_000_000, None, &[0xFF; 8]));
        s.feed(&data);
        assert_eq!(s.latest_video_pts(), None, "only the video PID sets it");
    }

    #[test]
    fn a_video_pes_without_a_pts_flag_tags_the_keyframe_none() {
        let (mut s, mut data) = h264_stream();
        // PES-start with PTS_DTS_flags clear and no optional fields.
        let mut payload = vec![0, 0, 1, 0xE0, 0, 0, 0x80, 0x00, 0];
        payload.extend_from_slice(&[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat());
        let at = data.len() as u64;
        data.extend(packet(0x101, true, None, &payload));
        assert_eq!(s.feed(&data), vec![Keyframe { at, pts: None }]);
        assert_eq!(s.latest_video_pts(), None);
    }

    #[test]
    fn has_video_reflects_the_pmt() {
        let mut s = Scanner::new();
        assert!(!s.has_video());
        let (_, data) = h264_stream();
        s.feed(&data);
        assert!(s.has_video());

        let mut s = Scanner::new();
        s.feed(&pat(0x100));
        s.feed(&pmt(0x100, &[(0x0F, 0x102)]));
        assert!(!s.has_video(), "an audio-only program has no video");
    }

    #[test]
    fn rai_does_not_override_a_visible_non_idr_slice() {
        let (mut s, mut data) = h264_stream();
        // A muxer that flags every PES as random access must not fool us.
        data.extend(pes(
            0x101,
            Some(true),
            &[AUD.as_slice(), SLICE.as_slice()].concat(),
        ));
        assert!(s.feed(&data).is_empty());
    }

    #[test]
    fn rai_decides_when_the_packet_is_inconclusive() {
        let (mut s, mut data) = h264_stream();
        // Only an AUD and a SEI fit in the first packet: the slice comes later.
        let at = data.len() as u64;
        data.extend(pes(
            0x101,
            Some(true),
            &[AUD.as_slice(), SEI.as_slice()].concat(),
        ));
        data.extend(pes(
            0x101,
            Some(false),
            &[AUD.as_slice(), SEI.as_slice()].concat(),
        ));
        assert_eq!(ats(s.feed(&data)), vec![at]);
    }

    #[test]
    fn ignores_audio_and_unknown_pids() {
        let (mut s, mut data) = h264_stream();
        data.extend(pes(0x102, Some(true), &SPS));
        data.extend(pes(0x200, Some(true), &SPS));
        assert!(s.feed(&data).is_empty());
    }

    #[test]
    fn reports_nothing_before_the_pmt_is_known() {
        let mut s = Scanner::new();
        let pkt = pes(
            0x101,
            Some(true),
            &[SPS.as_slice(), IDR.as_slice()].concat(),
        );
        assert!(s.feed(&pkt).is_empty());
        let (_, tables) = h264_stream();
        s.feed(&tables);
        assert_eq!(ats(s.feed(&pkt)), vec![(tables.len() + PACKET) as u64]);
    }

    #[test]
    fn offsets_are_absolute_across_arbitrary_chunking() {
        let (_, mut data) = h264_stream();
        data.extend(pes(
            0x101,
            None,
            &[AUD.as_slice(), SLICE.as_slice()].concat(),
        ));
        let at = data.len() as u64;
        data.extend(pes(
            0x101,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        ));
        data.extend(packet(0x101, false, None, &[0xAA; 100]));

        for chunk in [1, 7, 100, 187, 188, 189, 1000] {
            let mut s = Scanner::new();
            let found: Vec<u64> = data
                .chunks(chunk)
                .flat_map(|c| s.feed(c))
                .map(|k| k.at)
                .collect();
            assert_eq!(found, vec![at], "chunk size {chunk}");
        }
    }

    #[test]
    fn resynchronises_after_junk_and_a_partial_packet() {
        let (_, tables) = h264_stream();
        let key = pes(
            0x101,
            None,
            &[AUD.as_slice(), SPS.as_slice(), IDR.as_slice()].concat(),
        );
        let mut s = Scanner::new();
        s.feed(&tables);
        // A torn packet, as an engine pull starts with, then a lone sync byte
        // that is not a packet, then a real one.
        let mut data = key[50..].to_vec();
        data.extend([0x47, 0x00, 0x11]);
        let at = data.len() as u64;
        data.extend(&key);
        assert_eq!(ats(s.feed(&data)), vec![tables.len() as u64 + at]);
    }

    #[test]
    fn detects_hevc_and_mpeg2_keyframes() {
        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x24, 0x101)]));
        let at = data.len() as u64;
        // HEVC: VPS (type 32) leads an IRAP access unit; type 1 is a TRAIL_R slice.
        data.extend(pes(0x101, None, &[0, 0, 0, 1, 0x40, 0x01]));
        data.extend(pes(0x101, None, &[0, 0, 0, 1, 0x02, 0x01]));
        let mut s = Scanner::new();
        assert_eq!(ats(s.feed(&data)), vec![at]);
        assert_eq!(s.video_codec(), Some(Codec::Hevc));

        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x02, 0x101)]));
        let at = data.len() as u64;
        data.extend(pes(0x101, None, &[0, 0, 1, 0xB3, 0x14, 0x00])); // sequence header
        data.extend(pes(0x101, None, &[0, 0, 1, 0x00, 0x00, 0x10])); // P picture
        let mut s = Scanner::new();
        assert_eq!(ats(s.feed(&data)), vec![at]);
    }

    #[test]
    fn unknown_video_codecs_fall_back_to_rai() {
        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x10, 0x101)]));
        let at = data.len() as u64;
        data.extend(pes(0x101, Some(true), &[0xAA; 8]));
        data.extend(pes(0x101, Some(false), &[0xAA; 8]));
        let mut s = Scanner::new();
        assert_eq!(ats(s.feed(&data)), vec![at]);
        assert_eq!(s.video_codec(), Some(Codec::Other));
    }

    #[test]
    fn survives_garbage() {
        let mut s = Scanner::new();
        assert!(s.feed(&[0x47; 1000]).is_empty());
        assert!(s.feed(&[0x00; 1000]).is_empty());
        let torn = pat(0x100);
        assert!(s.feed(&torn[..100]).is_empty());
        assert_eq!(s.program(), None);
    }

    // -- the program ----------------------------------------------------------

    #[test]
    fn names_the_program_from_the_pmt() {
        let (_, data) = h264_stream();
        assert_eq!(program_of(&data), named(Some("h264"), Some("aac")));
        assert_eq!(
            program_of(&data[..data.len() - PACKET]),
            None,
            "PAT alone settles nothing"
        );
    }

    #[test]
    fn takes_the_first_of_each_type_in_pmt_order() {
        let mut data = pat(0x100);
        data.extend(pmt(
            0x100,
            &[(0x81, 0x103), (0x0F, 0x102), (0x24, 0x104), (0x1B, 0x101)],
        ));
        assert_eq!(program_of(&data), named(Some("hevc"), Some("ac3")));
    }

    #[test]
    fn a_program_may_lack_audio_or_video() {
        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x1B, 0x101)]));
        assert_eq!(program_of(&data), named(Some("h264"), None));
        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x0F, 0x102)]));
        assert_eq!(program_of(&data), named(None, Some("aac")));
    }

    #[test]
    fn mpeg_audio_is_named_by_its_frame_header() {
        for (header, name) in [
            ([0xFF, 0xFD, 0x94, 0xC0], "mp2"), // MPEG-1 layer II, 192k, 48kHz
            ([0xFF, 0xFB, 0x90, 0x00], "mp3"), // MPEG-1 layer III, 128k, 44.1kHz
            ([0xFF, 0xF5, 0x60, 0x00], "mp2"), // MPEG-2 layer II
        ] {
            let mut data = pat(0x100);
            data.extend(pmt(0x100, &[(0x1B, 0x101), (0x03, 0x102)]));
            let mut s = Scanner::new();
            s.feed(&data);
            assert_eq!(s.program(), None, "the layer is not in the PMT");
            // Video and non-PES packets on the audio PID must not confuse it.
            s.feed(&pes(0x101, None, &SPS));
            s.feed(&packet(0x102, false, None, &[0xFF, 0xFB, 0x90, 0x00]));
            assert_eq!(s.program(), None);
            s.feed(&pes(0x102, None, &header));
            assert_eq!(s.program(), named(Some("h264"), Some(name)), "{name}");
        }
    }

    #[test]
    fn private_streams_are_named_by_descriptor() {
        for (desc, want) in [
            (&[0x6A, 0x01, 0x00][..], Some("ac3")),
            (
                &[0x0A, 0x04, b'e', b'n', b'g', 0, 0x7A, 0x01, 0x00][..],
                Some("eac3"),
            ),
            (&[0x7B, 0x01, 0x00][..], Some("dts")),
            (&[0x05, 0x04, b'A', b'C', b'-', b'3'][..], Some("ac3")),
            (&[0x05, 0x04, b'E', b'A', b'C', b'3'][..], Some("eac3")),
            (&[0x05, 0x04, b'D', b'T', b'S', b'2'][..], Some("dts")),
            (&[0x05, 0x04, b'O', b'p', b'u', b's'][..], Some("opus")),
        ] {
            let mut data = pat(0x100);
            data.extend(pmt_with(0x100, &[(0x1B, 0x101, &[]), (0x06, 0x102, desc)]));
            assert_eq!(program_of(&data), named(Some("h264"), want), "{desc:?}");
        }
    }

    #[test]
    fn subtitle_private_streams_are_not_audio() {
        let mut data = pat(0x100);
        let subtitling = [0x59, 0x08, b'e', b'n', b'g', 0x10, 0x00, 0x01, 0x00, 0x02];
        data.extend(pmt_with(
            0x100,
            &[
                (0x1B, 0x101, &[]),
                (0x06, 0x103, &subtitling),
                (0x0F, 0x102, &[]),
            ],
        ));
        assert_eq!(program_of(&data), named(Some("h264"), Some("aac")));
    }

    #[test]
    fn an_unnameable_private_stream_defers_to_ffprobe() {
        let mut data = pat(0x100);
        data.extend(pmt_with(
            0x100,
            &[
                (0x1B, 0x101, &[]),
                (0x06, 0x102, &[0x0A, 0x04, b'e', b'n', b'g', 0]),
            ],
        ));
        assert_eq!(program_of(&data), None);
        let mut data = pat(0x100);
        data.extend(pmt_with(0x100, &[(0x1B, 0x101, &[]), (0x06, 0x102, &[])]));
        assert_eq!(program_of(&data), None);
    }

    #[test]
    fn hevc_by_registration_descriptor_is_video() {
        let mut data = pat(0x100);
        data.extend(pmt_with(
            0x100,
            &[
                (0x06, 0x101, &[0x05, 0x04, b'H', b'E', b'V', b'C']),
                (0x0F, 0x102, &[]),
            ],
        ));
        assert_eq!(program_of(&data), named(Some("hevc"), Some("aac")));
        let mut s = Scanner::new();
        s.feed(&data);
        assert_eq!(s.video_codec(), Some(Codec::Hevc));
    }

    #[test]
    fn a_pmt_spanning_packets_is_reassembled() {
        // Thirty audio tracks with language descriptors push the PMT across
        // three packets; the video comes last so nothing is known until the end.
        let lang: &[u8] = &[0x0A, 0x04, b'e', b'n', b'g', 0x00, 0x6A, 0x01, 0x00];
        let mut streams: Vec<(u8, u16, &[u8])> = (0..30).map(|n| (0x06, 0x200 + n, lang)).collect();
        streams.push((0x1B, 0x101, &[]));
        let mut data = pat(0x100);
        data.extend(pmt_packets(0x100, &streams));
        assert_eq!(data.len(), 4 * PACKET, "PAT plus a three-packet PMT");
        for chunk in [1, 100, 188, 4096] {
            let mut s = Scanner::new();
            for c in data.chunks(chunk) {
                s.feed(c);
            }
            assert_eq!(
                s.program(),
                named(Some("h264"), Some("ac3")),
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn a_continuation_without_a_start_is_ignored() {
        let (_, tables) = h264_stream();
        let mut s = Scanner::new();
        s.feed(&packet(
            0x100,
            false,
            None,
            &[0x02, 0xB0, 0x10, 0, 0, 0, 0, 0],
        ));
        assert_eq!(s.program(), None);
        s.feed(&tables);
        assert_eq!(s.program(), named(Some("h264"), Some("aac")));
    }

    #[test]
    fn a_later_pmt_does_not_unsettle_a_named_program() {
        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x1B, 0x101), (0x03, 0x102)]));
        let mut s = Scanner::new();
        s.feed(&data);
        s.feed(&pes(0x102, None, &[0xFF, 0xFD, 0x94, 0xC0]));
        assert_eq!(s.program(), named(Some("h264"), Some("mp2")));
        s.feed(&data); // the tables repeat
        assert_eq!(s.program(), named(Some("h264"), Some("mp2")));
    }

    /// Against real ffmpeg output: the names must be the ones ffprobe gives,
    /// since `format::modes` keys off them. Skips codecs this ffmpeg lacks.
    #[test]
    fn names_agree_with_ffprobe_on_real_streams() {
        let mut checked = 0;
        for (encoder, want) in [
            ("aac", "aac"),
            ("ac3", "ac3"),
            ("mp2", "mp2"),
            ("libmp3lame", "mp3"),
            ("eac3", "eac3"),
        ] {
            let out = match std::process::Command::new("ffmpeg")
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
                    "1",
                    "-c:v",
                    "libx264",
                    "-preset",
                    "ultrafast",
                    "-c:a",
                    encoder,
                    "-f",
                    "mpegts",
                    "-",
                ])
                .output()
            {
                Ok(o) if o.status.success() && !o.stdout.is_empty() => o.stdout,
                _ => continue, // no ffmpeg, or not this encoder
            };
            let Ok(probe) = crate::probe::run(&out) else {
                continue;
            };
            let mut s = Scanner::new();
            for c in out.chunks(1000) {
                s.feed(c);
            }
            let program = s
                .program()
                .unwrap_or_else(|| panic!("{encoder}: program not settled"));
            assert_eq!(program.video, Some("h264"), "{encoder}");
            assert_eq!(program.audio, Some(want), "{encoder}");
            assert_eq!(
                program.video.map(str::to_owned),
                probe.video,
                "{encoder}: ffprobe disagrees"
            );
            assert_eq!(
                program.audio.map(str::to_owned),
                probe.audio,
                "{encoder}: ffprobe disagrees"
            );
            checked += 1;
        }
        eprintln!("cross-checked {checked} codecs against ffprobe");
    }

    /// Against real ffmpeg output: a 4s stream with a 1s GOP must yield four
    /// keyframes, each on a packet that starts a PES on the video PID.
    #[test]
    fn agrees_with_ffmpeg_on_keyframes_of_a_real_stream() {
        let out = match std::process::Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x240:rate=25",
                "-f",
                "lavfi",
                "-i",
                "sine",
                "-t",
                "4",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-g",
                "25",
                "-keyint_min",
                "25",
                "-sc_threshold",
                "0",
                "-c:a",
                "aac",
                "-f",
                "mpegts",
                "-",
            ])
            .output()
        {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => o.stdout,
            _ => return, // no usable ffmpeg here
        };
        let mut s = Scanner::new();
        let found: Vec<u64> = out
            .chunks(64 * 1024 + 13)
            .flat_map(|c| s.feed(c))
            .map(|k| k.at)
            .collect();
        assert_eq!(found.len(), 4, "keyframes at {found:?}");
        for at in found {
            let p = &out[at as usize..at as usize + PACKET];
            assert_eq!(p[0], SYNC);
            assert!(p[1] & 0x40 != 0, "keyframe packet must start a PES");
        }
    }
}
