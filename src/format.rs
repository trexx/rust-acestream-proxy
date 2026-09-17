//! Output formats and the copy-first decision table.
//!
//! ffmpeg reads raw MPEG-TS on stdin (fed by the shared engine puller) rather
//! than opening the engine URL itself, so there is exactly one engine pull per
//! content id no matter how many formats are being served from it.

use std::fmt;

/// What happens to a track on its way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackMode {
    /// Stream-copied untouched: no re-encode, no quality loss, near-zero CPU.
    Copy,
    Transcode,
    /// Track is dropped entirely (video on the audio-only endpoints).
    Dropped,
}

impl fmt::Display for TrackMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TrackMode::Copy => "copy",
            TrackMode::Transcode => "transcode",
            TrackMode::Dropped => "drop",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputFormat {
    Adts,
    Mp3,
    Fmp4,
}

impl OutputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            OutputFormat::Adts => "adts",
            OutputFormat::Mp3 => "mp3",
            OutputFormat::Fmp4 => "fmp4",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            OutputFormat::Adts => "audio/aac",
            OutputFormat::Mp3 => "audio/mpeg",
            OutputFormat::Fmp4 => "video/mp4",
        }
    }

    /// Only fMP4 has an init segment that late joiners need replayed; ADTS and
    /// MP3 are self-synchronising, so any byte offset is a valid join point.
    pub fn needs_init_segment(self) -> bool {
        matches!(self, OutputFormat::Fmp4)
    }

    /// Whether the output carries the video track. Decides how a new encoder
    /// is primed: video wants to start on a keyframe, audio does not care.
    pub fn has_video(self) -> bool {
        matches!(self, OutputFormat::Fmp4)
    }

    /// The `fmt=` values accepted on /audio.
    pub fn parse_audio(s: &str) -> Option<Self> {
        match s {
            "adts" => Some(OutputFormat::Adts),
            "mp3" => Some(OutputFormat::Mp3),
            _ => None,
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The chosen encoding for one (format, source codec) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub args: Vec<String>,
    pub video: TrackMode,
    pub audio: TrackMode,
}

/// Fragment duration for fMP4, in milliseconds. `None` fragments on keyframes
/// only.
///
/// A `moof` cannot be written until its fragment is complete, so the fragment
/// duration is a hard latency floor. Keyframe-only fragments make that floor
/// the source GOP: each fragment is emitted when the *next* keyframe arrives,
/// so its content is already one GOP old. A timed cut keeps fragments short;
/// `frag_keyframe` stays on as well, so every keyframe still opens a fragment
/// and late joiners can be aligned to one (see `mp4::Piece::keyframe`).
pub type FragDurationMs = Option<u32>;

fn s(v: &str) -> String {
    v.to_owned()
}

/// How much input ffmpeg may examine before it must have identified the
/// streams, as `(analyzeduration_us, probesize_bytes)`.
///
/// This is not a free cap that `find_stream_info` exits early from: MPEG-TS
/// has no header, so ffmpeg reads the whole window regardless — instantly when
/// the replay window supplies it, at stream rate otherwise.
///
/// Copying H.264 into MP4 requires SPS/PPS extradata to build the `avcC` box,
/// which arrive only with a keyframe. The window must therefore reach from
/// wherever ffmpeg starts reading to the first keyframe, or the muxer refuses
/// to write a header at all ("non-existing PPS 0 referenced", then "dimensions
/// not set"). Measured on a 3s-GOP stream: from a keyframe-aligned start every
/// window from 0.5s up succeeds; from a mid-GOP start 1s fails outright.
///
/// So a video encoder primed from a keyframe (the normal case, see
/// `replay::Policy::FromKeyframe`) gets 2s — comfortably over what it needs,
/// cheap because the replay window satisfies it at pipe speed — and one that
/// could not be gets 3s, the previous fixed value, which covers a mid-GOP
/// start on a GOP of up to 3s. Audio parameters come from any frame header, so
/// 1s is plenty there.
///
/// probesize was never the binding constraint; it also sizes the buffer the
/// demuxer keeps for seeking back after its header scan, so it is kept modest.
fn probe_window(fmt: OutputFormat, keyframe_start: bool) -> (&'static str, &'static str) {
    match fmt {
        OutputFormat::Fmp4 if keyframe_start => ("2000000", "5000000"),
        OutputFormat::Fmp4 => ("3000000", "5000000"),
        _ => ("1000000", "500000"),
    }
}

/// Input-side options. These must precede `-i`: `-fflags` is a demuxer option
/// and is silently inert if placed after it.
///
/// Deliberately *without* `-avioflags direct` here, although it is set on the
/// output. The mpegts demuxer scans the start of the input for its tables and
/// then seeks back through the AVIO buffer to re-read it; with direct I/O
/// there is no buffer, the seek fails ("Unable to seek back to the start",
/// logged only at info level) and everything the scan consumed is lost.
/// Measured at 1.5–2.6MB per encoder start, which is most of the replay window
/// and several seconds of a live stream, and it varied from run to run. The
/// buffer costs no latency: a pipe read returns whatever is there.
///
/// Also without `-fflags nobuffer`, despite its billing as a low-latency flag:
/// it slows stream analysis and so delays first output. Output-side latency is
/// handled by -flush_packets and -avioflags direct, which cost nothing.
fn input_args(fmt: OutputFormat, keyframe_start: bool) -> Vec<String> {
    let (analyzeduration, probesize) = probe_window(fmt, keyframe_start);
    [
        "-hide_banner",
        "-loglevel",
        "error",
        // discardcorrupt matters for a P2P source, where corrupt and partial
        // frames are routine rather than exceptional.
        "-fflags",
        "discardcorrupt",
        "-analyzeduration",
        analyzeduration,
        "-probesize",
        probesize,
        // The input is always raw TS from the engine puller; naming the demuxer
        // skips format detection entirely.
        "-f",
        "mpegts",
        "-i",
        "pipe:0",
    ]
    .iter()
    .map(|v| s(v))
    .collect()
}

/// Output-side options common to every format. `-flush_packets 1` is the single
/// biggest steady-state latency win: without it ffmpeg's output AVIO buffers
/// ~32KB before writing to the pipe, which at 128 kbps is ~2 seconds.
fn flush_args() -> Vec<String> {
    ["-avioflags", "direct", "-flush_packets", "1"]
        .iter()
        .map(|v| s(v))
        .collect()
}

fn aac_encode() -> Vec<String> {
    ["-c:a", "aac", "-b:a", "128k", "-ac", "2"]
        .iter()
        .map(|v| s(v))
        .collect()
}

/// The copy-first decision for one (format, source audio codec) pair.
///
/// `audio_codec` is the source's first audio stream codec name as reported by
/// ffprobe (e.g. "aac", "ac3"); `None` means no audio stream was found.
pub fn modes(fmt: OutputFormat, audio_codec: Option<&str>) -> (TrackMode, TrackMode) {
    match fmt {
        OutputFormat::Adts | OutputFormat::Mp3 => {
            let want = if fmt == OutputFormat::Adts {
                "aac"
            } else {
                "mp3"
            };
            let audio = if audio_codec == Some(want) {
                TrackMode::Copy
            } else {
                TrackMode::Transcode
            };
            (TrackMode::Dropped, audio)
        }
        OutputFormat::Fmp4 => {
            // AC-3, E-AC-3 and MP2 are legal in MP4 but browsers will not decode
            // them, so a blanket `-c copy` yields video with silence. Only AAC
            // survives the copy path.
            let audio = match audio_codec {
                Some("aac") => TrackMode::Copy,
                Some(_) => TrackMode::Transcode,
                None => TrackMode::Dropped,
            };
            (TrackMode::Copy, audio)
        }
    }
}

/// Build the full ffmpeg argv for one stream.
///
/// `keyframe_start` says the encoder will be primed from a video keyframe, so
/// stream analysis can be short; see [`probe_window`].
pub fn plan(
    fmt: OutputFormat,
    audio_codec: Option<&str>,
    frag_ms: FragDurationMs,
    keyframe_start: bool,
) -> Plan {
    let mut args = input_args(fmt, keyframe_start);
    let (video, audio) = modes(fmt, audio_codec);

    match fmt {
        OutputFormat::Adts | OutputFormat::Mp3 => {
            args.extend(["-vn", "-sn", "-dn"].iter().map(|v| s(v)));

            if audio == TrackMode::Copy {
                args.extend(["-c:a", "copy"].iter().map(|v| s(v)));
            } else if fmt == OutputFormat::Adts {
                args.extend(aac_encode());
            } else {
                args.extend(
                    ["-c:a", "libmp3lame", "-b:a", "128k", "-ac", "2"]
                        .iter()
                        .map(|v| s(v)),
                );
            }

            args.extend(flush_args());
            args.extend(["-f", fmt.as_str(), "pipe:1"].iter().map(|v| s(v)));
        }

        OutputFormat::Fmp4 => {
            // Video is always copied: that is where the CPU win is, and it is
            // what "zero copy" means here (no re-encode, not untouched bytes).
            args.extend(["-c:v", "copy"].iter().map(|v| s(v)));

            match audio {
                TrackMode::Copy => {
                    args.extend(["-c:a", "copy"].iter().map(|v| s(v)));
                    // MPEG-TS carries AAC in ADTS framing; MP4 wants raw AAC with
                    // an AudioSpecificConfig in the sample entry. The muxer does
                    // not convert on copy — without this it aborts the stream with
                    // "Malformed AAC bitstream detected". Not needed on the /audio
                    // routes, where ADTS is the native output framing, nor when
                    // transcoding, since the encoder emits raw AAC.
                    args.extend(["-bsf:a", "aac_adtstoasc"].iter().map(|v| s(v)));
                }
                TrackMode::Transcode => args.extend(aac_encode()),
                TrackMode::Dropped => args.push(s("-an")),
            }

            // Broadcast TS carries timestamp discontinuities that MP4 rejects.
            args.extend(["-avoid_negative_ts", "make_zero"].iter().map(|v| s(v)));
            args.extend(flush_args());

            if let Some(ms) = frag_ms {
                // frag_duration is in microseconds. The muxer ORs it with
                // frag_keyframe below, so a keyframe still always opens a fragment.
                args.extend(
                    ["-frag_duration", &(u64::from(ms) * 1000).to_string()]
                        .iter()
                        .map(|v| s(v)),
                );
            }
            args.extend(
                [
                    "-movflags",
                    "+frag_keyframe+empty_moov+default_base_moof+omit_tfhd_offset",
                    "-f",
                    "mp4",
                    "pipe:1",
                ]
                .iter()
                .map(|v| s(v)),
            );
        }
    }

    Plan { args, video, audio }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [OutputFormat; 3] = [OutputFormat::Adts, OutputFormat::Mp3, OutputFormat::Fmp4];

    fn args_of(fmt: OutputFormat, codec: Option<&str>) -> Vec<String> {
        plan(fmt, codec, None, false).args
    }

    /// Assert `needle` appears as a consecutive run in `hay`.
    fn contains_seq(hay: &[String], needle: &[&str]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn value_after(args: &[String], flag: &str) -> String {
        let i = args
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("no {flag}"));
        args[i + 1].clone()
    }

    #[test]
    fn adts_copies_aac() {
        let p = plan(OutputFormat::Adts, Some("aac"), None, false);
        assert_eq!(p.audio, TrackMode::Copy);
        assert_eq!(p.video, TrackMode::Dropped);
        assert!(contains_seq(&p.args, &["-c:a", "copy"]));
        assert!(contains_seq(&p.args, &["-f", "adts", "pipe:1"]));
    }

    #[test]
    fn adts_transcodes_everything_else() {
        for codec in ["ac3", "eac3", "mp2", "dts", "mp3"] {
            let p = plan(OutputFormat::Adts, Some(codec), None, false);
            assert_eq!(p.audio, TrackMode::Transcode, "codec {codec}");
            assert!(contains_seq(&p.args, &["-c:a", "aac"]), "codec {codec}");
        }
    }

    #[test]
    fn mp3_copies_mp3_only() {
        let p = plan(OutputFormat::Mp3, Some("mp3"), None, false);
        assert_eq!(p.audio, TrackMode::Copy);
        assert!(contains_seq(&p.args, &["-c:a", "copy"]));

        let p = plan(OutputFormat::Mp3, Some("aac"), None, false);
        assert_eq!(p.audio, TrackMode::Transcode);
        assert!(contains_seq(&p.args, &["-c:a", "libmp3lame"]));
    }

    #[test]
    fn fmp4_always_copies_video() {
        for codec in [Some("aac"), Some("ac3"), Some("mp2"), None] {
            let p = plan(OutputFormat::Fmp4, codec, None, false);
            assert_eq!(p.video, TrackMode::Copy, "codec {codec:?}");
            assert!(contains_seq(&p.args, &["-c:v", "copy"]), "codec {codec:?}");
        }
    }

    #[test]
    fn fmp4_transcodes_browser_hostile_audio() {
        // AC-3/E-AC-3/MP2 are legal in MP4 but browsers play them as silence.
        for codec in ["ac3", "eac3", "mp2"] {
            let p = plan(OutputFormat::Fmp4, Some(codec), None, false);
            assert_eq!(p.audio, TrackMode::Transcode, "codec {codec}");
            assert!(contains_seq(&p.args, &["-c:a", "aac"]), "codec {codec}");
        }
        let p = plan(OutputFormat::Fmp4, Some("aac"), None, false);
        assert_eq!(p.audio, TrackMode::Copy);
    }

    #[test]
    fn modes_match_the_plan() {
        for fmt in ALL {
            for codec in [Some("aac"), Some("ac3"), Some("mp3"), None] {
                let p = plan(fmt, codec, None, false);
                assert_eq!(modes(fmt, codec), (p.video, p.audio), "{fmt} {codec:?}");
            }
        }
    }

    #[test]
    fn fmp4_converts_adts_framing_when_copying_aac() {
        // Only on the copy path into MP4: the encoder already emits raw AAC,
        // and ADTS output wants ADTS framing.
        let p = plan(OutputFormat::Fmp4, Some("aac"), None, false);
        assert!(contains_seq(&p.args, &["-bsf:a", "aac_adtstoasc"]));

        let p = plan(OutputFormat::Fmp4, Some("ac3"), None, false);
        assert!(!p.args.iter().any(|a| a == "-bsf:a"));
        for fmt in [OutputFormat::Adts, OutputFormat::Mp3] {
            let p = plan(fmt, Some("aac"), None, false);
            assert!(!p.args.iter().any(|a| a == "-bsf:a"), "{fmt}");
        }
    }

    #[test]
    fn fmp4_without_audio_drops_the_track() {
        let p = plan(OutputFormat::Fmp4, None, None, false);
        assert_eq!(p.audio, TrackMode::Dropped);
        assert!(p.args.iter().any(|a| a == "-an"));
    }

    #[test]
    fn fmp4_movflags_are_mse_compatible() {
        let p = plan(OutputFormat::Fmp4, Some("aac"), None, false);
        let flags = value_after(&p.args, "-movflags");
        for want in [
            "frag_keyframe",
            "empty_moov",
            "default_base_moof",
            "omit_tfhd_offset",
        ] {
            assert!(flags.contains(want), "missing {want} in {flags}");
        }
    }

    /// Guards against inventing plausible-but-wrong option names. ffmpeg
    /// describes this flag as "default-base-is-moof" in prose while naming the
    /// option `default_base_moof`, and gets it wrong loudly but late — the
    /// muxer refuses to write a header at all.
    #[test]
    fn movflags_are_accepted_by_the_installed_ffmpeg() {
        let out = match std::process::Command::new("ffmpeg")
            .args(["-hide_banner", "-h", "muxer=mp4"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return, // no ffmpeg here; nothing to check against
        };
        let help = String::from_utf8_lossy(&out.stdout);
        // Option lines lead with the option name.
        let accepted: Vec<&str> = help
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .collect();

        for frag in [None, Some(200)] {
            let p = plan(OutputFormat::Fmp4, Some("aac"), frag, false);
            let flags = value_after(&p.args, "-movflags");
            for flag in flags.split('+').filter(|f| !f.is_empty()) {
                assert!(
                    accepted.contains(&flag),
                    "ffmpeg does not accept movflag {flag:?}"
                );
            }
        }
    }

    #[test]
    fn frag_duration_adds_to_keyframe_fragmentation() {
        let p = plan(OutputFormat::Fmp4, Some("aac"), Some(200), false);
        assert!(contains_seq(&p.args, &["-frag_duration", "200000"]));
        // Without frag_keyframe a timed cut lands late joiners mid-GOP; the two
        // combine, so every keyframe still opens a fragment.
        assert!(value_after(&p.args, "-movflags").contains("frag_keyframe"));

        let p = plan(OutputFormat::Fmp4, Some("aac"), None, false);
        assert!(!p.args.iter().any(|a| a == "-frag_duration"));
    }

    #[test]
    fn demuxer_options_precede_the_input() {
        // -fflags after -i is silently inert; guard against a reorder.
        for fmt in ALL {
            let args = args_of(fmt, Some("ac3"));
            let i = args.iter().position(|a| a == "-i").unwrap();
            for flag in ["-fflags", "-analyzeduration", "-probesize", "-f"] {
                let at = args.iter().position(|a| a == flag).unwrap();
                assert!(at < i, "{fmt}: {flag} must precede -i");
            }
        }
    }

    #[test]
    fn output_is_flushed_per_packet_but_input_is_buffered() {
        for fmt in ALL {
            let args = args_of(fmt, Some("aac"));
            assert!(contains_seq(&args, &["-flush_packets", "1"]), "{fmt}");
            // Direct I/O on the input side makes the mpegts demuxer lose its
            // table scan (see `input_args`); it belongs on the output only.
            let i = args.iter().position(|a| a == "-i").unwrap();
            let direct: Vec<usize> = args
                .iter()
                .enumerate()
                .filter(|(_, a)| *a == "-avioflags")
                .map(|(at, _)| at)
                .collect();
            assert_eq!(direct.len(), 1, "{fmt}");
            assert!(direct[0] > i, "{fmt}: -avioflags must follow -i");
        }
    }

    #[test]
    fn video_analysis_is_shorter_from_a_keyframe() {
        let cold = plan(OutputFormat::Fmp4, Some("aac"), None, false);
        let warm = plan(OutputFormat::Fmp4, Some("aac"), None, true);
        assert_eq!(value_after(&cold.args, "-analyzeduration"), "3000000");
        assert_eq!(value_after(&warm.args, "-analyzeduration"), "2000000");
        for fmt in [OutputFormat::Adts, OutputFormat::Mp3] {
            let p = plan(fmt, Some("aac"), None, true);
            assert_eq!(value_after(&p.args, "-analyzeduration"), "1000000", "{fmt}");
        }
    }

    #[test]
    fn input_is_always_the_shared_ts_pipe() {
        for fmt in ALL {
            let args = args_of(fmt, Some("aac"));
            assert!(
                contains_seq(&args, &["-f", "mpegts", "-i", "pipe:0"]),
                "{fmt}"
            );
        }
    }

    #[test]
    fn audio_formats_drop_non_audio_tracks() {
        for fmt in [OutputFormat::Adts, OutputFormat::Mp3] {
            let args = args_of(fmt, Some("aac"));
            for flag in ["-vn", "-sn", "-dn"] {
                assert!(args.iter().any(|a| a == flag), "{fmt} missing {flag}");
            }
        }
    }

    #[test]
    fn parse_audio_rejects_video_format() {
        assert_eq!(OutputFormat::parse_audio("adts"), Some(OutputFormat::Adts));
        assert_eq!(OutputFormat::parse_audio("mp3"), Some(OutputFormat::Mp3));
        assert_eq!(OutputFormat::parse_audio("fmp4"), None);
        assert_eq!(OutputFormat::parse_audio(""), None);
    }
}
