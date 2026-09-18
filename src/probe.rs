//! Source codec detection, the slow way.
//!
//! The usual way is the PMT: `ts::Scanner` names the program's streams from
//! the first packets of the pull, with no process spawned and nothing to wait
//! for. ffprobe is the fallback for a stream it cannot name — a private
//! stream with no descriptor it knows — and runs against a buffered preroll
//! of the shared pull rather than opening its own connection to the engine,
//! so even then it costs no extra engine session and happens once per content
//! id instead of once per listener.

use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    pub video: Option<String>,
    pub audio: Option<String>,
}

impl From<crate::ts::Program> for Probe {
    fn from(p: crate::ts::Program) -> Probe {
        Probe {
            video: p.video.map(str::to_owned),
            audio: p.audio.map(str::to_owned),
        }
    }
}

/// Parse `ffprobe -of json` output into the first codec of each type.
///
/// MPEG-TS lists streams both inside the program and at top level, so ffprobe
/// reports each one twice; the first of each `codec_type` wins.
pub fn parse(json: &str) -> Result<Probe, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("ffprobe output was not json: {e}"))?;
    let streams = v
        .get("streams")
        .and_then(|s| s.as_array())
        .ok_or_else(|| "ffprobe output had no streams array".to_string())?;

    let mut probe = Probe::default();
    for s in streams {
        let name = match s.get("codec_name").and_then(|n| n.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        match s.get("codec_type").and_then(|t| t.as_str()) {
            Some("video") if probe.video.is_none() => probe.video = Some(name.to_owned()),
            Some("audio") if probe.audio.is_none() => probe.audio = Some(name.to_owned()),
            _ => {}
        }
    }

    if probe.video.is_none() && probe.audio.is_none() {
        return Err("no audio or video stream found".into());
    }
    Ok(probe)
}

/// Run ffprobe over `preroll`, which must be raw MPEG-TS from the engine.
pub fn run(preroll: &[u8]) -> Result<Probe, String> {
    let mut child = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            // The preroll is always TS; naming the demuxer skips detection.
            "-f",
            "mpegts",
            "-analyzeduration",
            "500000",
            "-probesize",
            "200000",
            "-show_entries",
            "stream=codec_type,codec_name",
            "-of",
            "json",
            "-i",
            "pipe:0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start ffprobe: {e}"))?;

    // Feed stdin from its own thread: the preroll is larger than a pipe buffer,
    // so writing inline would deadlock against ffprobe filling stdout.
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let data = preroll.to_vec();
    let writer = thread::spawn(move || {
        // A broken pipe here is normal — ffprobe stops reading once it has seen
        // enough, and dropping stdin is what signals EOF.
        let _ = stdin.write_all(&data);
        let _: io::Result<()> = stdin.flush();
    });

    let out = child
        .wait_with_output()
        .map_err(|e| format!("ffprobe failed: {e}"))?;
    let _ = writer.join();

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() {
            format!("ffprobe exited with {}", out.status)
        } else {
            err
        });
    }

    parse(&String::from_utf8_lossy(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_video_and_audio_codecs() {
        let json = r#"{"streams":[
            {"codec_name":"h264","codec_type":"video"},
            {"codec_name":"ac3","codec_type":"audio"}
        ]}"#;
        let p = parse(json).unwrap();
        assert_eq!(p.video.as_deref(), Some("h264"));
        assert_eq!(p.audio.as_deref(), Some("ac3"));
    }

    #[test]
    fn takes_the_first_of_each_type_when_ts_duplicates_streams() {
        // MPEG-TS reports streams twice: inside the program and at top level.
        let json = r#"{"streams":[
            {"codec_name":"h264","codec_type":"video"},
            {"codec_name":"aac","codec_type":"audio"},
            {"codec_name":"h264","codec_type":"video"},
            {"codec_name":"aac","codec_type":"audio"}
        ]}"#;
        let p = parse(json).unwrap();
        assert_eq!(p.video.as_deref(), Some("h264"));
        assert_eq!(p.audio.as_deref(), Some("aac"));
    }

    #[test]
    fn keeps_the_first_audio_track_when_several_are_present() {
        let json = r#"{"streams":[
            {"codec_name":"eac3","codec_type":"audio"},
            {"codec_name":"aac","codec_type":"audio"}
        ]}"#;
        assert_eq!(parse(json).unwrap().audio.as_deref(), Some("eac3"));
    }

    #[test]
    fn handles_audio_only_and_video_only_sources() {
        let audio_only = r#"{"streams":[{"codec_name":"mp3","codec_type":"audio"}]}"#;
        let p = parse(audio_only).unwrap();
        assert_eq!(p.audio.as_deref(), Some("mp3"));
        assert_eq!(p.video, None);

        let video_only = r#"{"streams":[{"codec_name":"h264","codec_type":"video"}]}"#;
        let p = parse(video_only).unwrap();
        assert_eq!(p.video.as_deref(), Some("h264"));
        assert_eq!(p.audio, None);
    }

    #[test]
    fn ignores_subtitle_and_data_streams() {
        let json = r#"{"streams":[
            {"codec_name":"dvb_subtitle","codec_type":"subtitle"},
            {"codec_name":"bin_data","codec_type":"data"},
            {"codec_name":"aac","codec_type":"audio"}
        ]}"#;
        let p = parse(json).unwrap();
        assert_eq!(p.audio.as_deref(), Some("aac"));
        assert_eq!(p.video, None);
    }

    #[test]
    fn rejects_output_with_no_usable_streams() {
        assert!(parse(r#"{"streams":[]}"#).is_err());
        assert!(parse(r#"{"streams":[{"codec_type":"audio"}]}"#).is_err());
        assert!(parse("not json").is_err());
        assert!(parse("{}").is_err());
    }
}
