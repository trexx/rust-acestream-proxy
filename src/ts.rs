//! MPEG-TS packet scanning: which packets begin a video keyframe.
//!
//! Every byte from the engine passes through this on its way into the replay
//! window, so a new encoder can be primed from the most recent keyframe instead
//! of from wherever the window happens to start. It reads only what that needs:
//! the PAT to find the program's PMT, the PMT to find the video PID and codec,
//! and on that PID the first transport packet of each PES, whose leading NAL
//! units say whether the access unit is a random-access point.
//!
//! Detection is by the codec's own syntax (an SPS or IDR NAL for H.264, an
//! IRAP or parameter set for HEVC, a sequence header for MPEG-2), with the
//! adaptation field's random_access_indicator only as a fallback where the
//! packet is inconclusive or the codec unknown. The flag alone is not trusted:
//! some muxers set it on every video PES, and aligning to a non-keyframe is
//! exactly the failure this scanner exists to prevent.

use Codec::{Hevc, Mpeg2, Other, H264};

const PACKET: usize = 188;
const SYNC: u8 = 0x47;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    H264,
    Hevc,
    Mpeg2,
    /// A video stream type this scanner has no parser for; RAI decides.
    Other,
}

#[derive(Debug, Clone, Copy)]
struct Video {
    pid: u16,
    codec: Codec,
}

#[derive(Debug, Default)]
pub struct Scanner {
    /// Bytes after the last complete packet, carried into the next `feed`.
    carry: Vec<u8>,
    /// Absolute offset of `carry[0]`, or of the next byte if `carry` is empty.
    pos: u64,
    pmt_pid: Option<u16>,
    video: Option<Video>,
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

    /// Consume `data` and return the absolute offsets (counted from the first
    /// byte ever fed) of every transport packet that begins a video keyframe.
    ///
    /// Input need not be packet-aligned: the scanner resynchronises on a sync
    /// byte that is followed by another one packet later, as the mpegts demuxer
    /// does, and carries a trailing partial packet into the next call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u64> {
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
            if self.packet(&buf[i..next]) {
                found.push(base + i as u64);
            }
            i = next;
        }
        self.carry = buf[i..].to_vec();
        self.pos = base + i as u64;
        found
    }

    /// Handle one 188-byte packet; true if it starts a video keyframe.
    fn packet(&mut self, p: &[u8]) -> bool {
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
        if afc & 0x1 == 0 || off >= PACKET || !pusi {
            return false;
        }
        let payload = &p[off..];

        if pid == 0 {
            self.parse_pat(payload);
            return false;
        }
        if Some(pid) == self.pmt_pid {
            self.parse_pmt(payload);
            return false;
        }
        match self.video {
            Some(v) if v.pid == pid => keyframe(v.codec, payload).unwrap_or(rai),
            _ => false,
        }
    }

    fn parse_pat(&mut self, payload: &[u8]) {
        let Some(s) = section(payload, 0x00) else {
            return;
        };
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

    fn parse_pmt(&mut self, payload: &[u8]) {
        let Some(s) = section(payload, 0x02) else {
            return;
        };
        if s.len() < 12 {
            return;
        }
        let program_info = usize::from(s[10] & 0x0F) << 8 | usize::from(s[11]);
        let mut i = 12 + program_info;
        let end = s.len().saturating_sub(4);
        while i + 5 <= end {
            let stream_type = s[i];
            let pid = (u16::from(s[i + 1] & 0x1F) << 8) | u16::from(s[i + 2]);
            let es_info = usize::from(s[i + 3] & 0x0F) << 8 | usize::from(s[i + 4]);
            let codec = match stream_type {
                0x01 | 0x02 => Some(Codec::Mpeg2),
                0x1B => Some(Codec::H264),
                0x24 => Some(Codec::Hevc),
                // MPEG-4 part 2 and VC-1: video, but nothing here parses them.
                0x10 | 0xEA => Some(Codec::Other),
                _ => None,
            };
            if let Some(codec) = codec {
                self.video = Some(Video { pid, codec });
                return;
            }
            i += 5 + es_info;
        }
    }
}

/// The PSI section in a payload-unit-start packet, if it carries `table_id`.
/// Returns the section from its table_id byte, bounded by section_length.
fn section(payload: &[u8], table_id: u8) -> Option<&[u8]> {
    let pointer = usize::from(*payload.first()?);
    let s = payload.get(1 + pointer..)?;
    if s.len() < 3 || s[0] != table_id {
        return None;
    }
    let len = (usize::from(s[1] & 0x0F) << 8) | usize::from(s[2]);
    Some(&s[..s.len().min(3 + len)])
}

/// Whether the PES starting in `payload` is a keyframe: `Some(verdict)` when
/// the first packet's NAL units settle it, `None` when they do not.
fn keyframe(codec: Codec, payload: &[u8]) -> Option<bool> {
    if payload.len() < 9 || payload[..3] != [0, 0, 1] {
        return None;
    }
    let es = payload.get(9 + usize::from(payload[8])..)?;
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

    pub fn pmt(pmt_pid: u16, streams: &[(u8, u16)]) -> Vec<u8> {
        let mut s = vec![
            0x02, 0xB0, 0, 0x00, 0x01, 0xC1, 0x00, 0x00, 0xE1, 0x00, 0xF0, 0x00,
        ];
        for &(stream_type, pid) in streams {
            s.extend([stream_type, 0xE0 | (pid >> 8) as u8, pid as u8, 0xF0, 0x00]);
        }
        s.extend([0, 0, 0, 0]);
        s[2] = (s.len() - 3) as u8;
        packet(pmt_pid, true, None, &[&[0u8][..], &s].concat())
    }

    /// A PES-start packet whose elementary stream begins with `nals`.
    pub fn pes(pid: u16, rai: Option<bool>, es: &[u8]) -> Vec<u8> {
        let mut payload = vec![0, 0, 1, 0xE0, 0, 0, 0x80, 0x80, 5, 0x21, 0, 1, 0, 1];
        payload.extend_from_slice(es);
        packet(pid, true, rai, &payload)
    }

    pub const AUD: [u8; 6] = [0, 0, 0, 1, 0x09, 0xF0];
    pub const SPS: [u8; 8] = [0, 0, 0, 1, 0x67, 0x64, 0x00, 0x1F];
    pub const IDR: [u8; 6] = [0, 0, 0, 1, 0x65, 0x88];
    pub const SLICE: [u8; 6] = [0, 0, 0, 1, 0x41, 0x9A];
    pub const SEI: [u8; 7] = [0, 0, 0, 1, 0x06, 0x01, 0x80];

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
        assert_eq!(s.feed(&data), vec![at_sps, at_idr]);
        assert_eq!(s.video_codec(), Some(Codec::H264));
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
        assert_eq!(s.feed(&data), vec![at]);
    }

    #[test]
    fn ignores_audio_and_unknown_pids() {
        let (mut s, mut data) = h264_stream();
        data.extend(pes(0x102, Some(true), &[SPS.as_slice()].concat()));
        data.extend(pes(0x200, Some(true), &[SPS.as_slice()].concat()));
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
        assert_eq!(s.feed(&pkt), vec![(tables.len() + PACKET) as u64]);
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
            let found: Vec<u64> = data.chunks(chunk).flat_map(|c| s.feed(c)).collect();
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
        assert_eq!(s.feed(&data), vec![tables.len() as u64 + at]);
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
        assert_eq!(s.feed(&data), vec![at]);
        assert_eq!(s.video_codec(), Some(Codec::Hevc));

        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x02, 0x101)]));
        let at = data.len() as u64;
        data.extend(pes(0x101, None, &[0, 0, 1, 0xB3, 0x14, 0x00])); // sequence header
        data.extend(pes(0x101, None, &[0, 0, 1, 0x00, 0x00, 0x10])); // P picture
        let mut s = Scanner::new();
        assert_eq!(s.feed(&data), vec![at]);
    }

    #[test]
    fn unknown_video_codecs_fall_back_to_rai() {
        let mut data = pat(0x100);
        data.extend(pmt(0x100, &[(0x10, 0x101)]));
        let at = data.len() as u64;
        data.extend(pes(0x101, Some(true), &[0xAA; 8]));
        data.extend(pes(0x101, Some(false), &[0xAA; 8]));
        let mut s = Scanner::new();
        assert_eq!(s.feed(&data), vec![at]);
        assert_eq!(s.video_codec(), Some(Codec::Other));
    }

    #[test]
    fn survives_garbage() {
        let mut s = Scanner::new();
        assert!(s.feed(&[0x47; 1000]).is_empty());
        assert!(s.feed(&[0x00; 1000]).is_empty());
        let torn = pat(0x100);
        assert!(s.feed(&torn[..100]).is_empty());
    }

    /// Against real ffmpeg output: a 4s stream with a 1s GOP must yield four
    /// keyframes, each on a packet that starts a PES on the video PID.
    #[test]
    fn agrees_with_ffmpeg_on_a_real_stream() {
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
        let found: Vec<u64> = out.chunks(64 * 1024 + 13).flat_map(|c| s.feed(c)).collect();
        assert_eq!(found.len(), 4, "keyframes at {found:?}");
        for at in found {
            let p = &out[at as usize..at as usize + PACKET];
            assert_eq!(p[0], SYNC);
            assert!(p[1] & 0x40 != 0, "keyframe packet must start a PES");
        }
    }
}
