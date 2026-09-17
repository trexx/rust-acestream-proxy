//! The /status endpoint: what this service is pulling, what it is producing,
//! and what the AceStream engine reports about each swarm.

use std::sync::atomic::Ordering;
use std::time::Instant;

use serde_json::{json, Value};

use crate::registry::Registry;

pub fn snapshot(reg: &Registry, started: Instant) -> Value {
    let streams = reg.live_streams();

    let mut listeners_total = 0usize;
    let mut encoders_total = 0usize;

    let stream_json: Vec<Value> = streams
        .iter()
        .map(|s| {
            let encoders = s.live_encoders();
            encoders_total += encoders.len();

            let outputs: Vec<Value> = encoders
                .iter()
                .map(|e| {
                    let listeners = e.listener_info();
                    listeners_total += listeners.len();
                    json!({
                        "format": e.fmt.as_str(),
                        "video": e.video.to_string(),
                        "audio": e.audio.to_string(),
                        "uptime_s": e.started.elapsed().as_secs(),
                        "bytes_out": e.bytes_out.load(Ordering::Relaxed),
                        // No listener; ffmpeg is being kept for a reconnect.
                        "lingering": e.lingering(),
                        "listeners": listeners
                            .iter()
                            .map(|(peer, uptime_s, bytes)| json!({
                                "peer": peer,
                                "uptime_s": uptime_s,
                                "bytes_sent": bytes,
                            }))
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();

            let probe = s.probe();
            json!({
                "content_id": s.content_id,
                "uptime_s": s.started.elapsed().as_secs(),
                "bytes_from_engine": s.bytes_in.load(Ordering::Relaxed),
                // No encoder; the pull is being kept for a reconnect.
                "lingering": s.lingering(),
                "source": {
                    "video": probe.and_then(|p| p.video.clone()),
                    "audio": probe.and_then(|p| p.audio.clone()),
                },
                // Passed through verbatim: the shape varies between engine
                // versions, and null means the engine offered no stat_url.
                "engine": s.stats(),
                "outputs": outputs,
            })
        })
        .collect();

    json!({
        "uptime_s": started.elapsed().as_secs(),
        "summary": {
            // The point of the two-tier fan-out: engine_pulls stays at one per
            // content id however many formats and listeners hang off it.
            "engine_pulls": streams.len(),
            "encoders": encoders_total,
            "listeners": listeners_total,
        },
        "streams": stream_json,
    })
}
