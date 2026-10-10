//! Tiny stderr logger matching the Go service's line format.

use std::time::{SystemTime, UNIX_EPOCH};

fn stamp() -> String {
    // Container runtimes add their own timestamps; this is a coarse
    // seconds-since-epoch marker so lines remain orderable on their own.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

pub fn info(msg: &str) {
    eprintln!("{} {}", stamp(), msg);
}

pub fn warn(msg: &str) {
    eprintln!("{} warn: {}", stamp(), msg);
}

pub fn error(msg: &str) {
    eprintln!("{} error: {}", stamp(), msg);
}
