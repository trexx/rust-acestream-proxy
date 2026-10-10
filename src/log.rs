//! Tiny stderr logger matching the Go service's line format.
//!
//! `log::info!`, `log::warn!` and `log::error!` take `format!` arguments, so a
//! call site formats once, straight into stderr, rather than building a
//! `String` to pass by reference.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Write one line. Use the macros rather than calling this directly.
pub fn emit(prefix: &str, msg: fmt::Arguments) {
    // Container runtimes add their own timestamps; this is a coarse
    // seconds-since-epoch marker so lines remain orderable on their own.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("{secs} {prefix}{msg}");
}

macro_rules! log_info {
    ($($arg:tt)*) => { $crate::log::emit("", format_args!($($arg)*)) };
}

macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::log::emit("warn: ", format_args!($($arg)*)) };
}

macro_rules! log_error {
    ($($arg:tt)*) => { $crate::log::emit("error: ", format_args!($($arg)*)) };
}

// Defined under other names and re-exported, because a bare `warn` would
// collide with the built-in `#[warn]` attribute. Call sites always write the
// path, `log::warn!`, which is unambiguous.
pub(crate) use {log_error as error, log_info as info, log_warn as warn};
