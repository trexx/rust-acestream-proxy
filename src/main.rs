//! rust-acestream-proxy: pulls an AceStream engine stream once and serves it to many
//! listeners as audio (ADTS/MP3) or as fragmented MP4 with the video track
//! stream-copied.
//!
//!     GET /audio?id=<40-hex content id>[&fmt=adts|mp3]
//!     GET /video?id=<40-hex content id>
//!     GET /status
//!
//! Copy-first: audio already decodable by browsers is stream-copied untouched,
//! and video is *always* copied. One engine pull per content id feeds every
//! format, so a second listener — in any format — costs the engine nothing.

mod engine;
mod format;
mod http;
mod mp4;
mod probe;
mod registry;
mod replay;
mod status;
mod ts;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use engine::log;
use format::OutputFormat;
use http::{Request, Response};
use registry::{Config, Registry, Subscription};

fn main() {
    let engine_host = match std::env::var("ENGINE_HOST") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            log::error("ENGINE_HOST must be set");
            std::process::exit(1);
        }
    };
    let addr = normalise_addr(&env_or("LISTEN_ADDR", ":8080"));
    // Fragments are cut on a timer as well as on keyframes: the moof cannot
    // be written until its fragment is complete, so with keyframe-only
    // fragmentation a viewer sits a whole GOP behind. Late joiners are still
    // aligned to a keyframe fragment (see mp4::Piece::keyframe), so the timed
    // cut costs no artifacts. 0 restores keyframe-only fragmentation.
    let frag_duration_ms = match env_or("FRAG_DURATION_MS", "1000").parse::<u32>() {
        Ok(0) => None,
        Ok(ms) => Some(ms),
        Err(_) => {
            log::error("FRAG_DURATION_MS must be a non-negative integer");
            std::process::exit(1);
        }
    };
    let encoder_linger = env_seconds("ENCODER_LINGER_S", 15);
    let engine_linger = env_seconds("ENGINE_LINGER_S", 60);

    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            log::error(&format!("could not bind {addr}: {e}"));
            std::process::exit(1);
        }
    };

    let registry = Registry::new(Config {
        engine_host: engine_host.clone(),
        frag_duration_ms,
        encoder_linger,
        engine_linger,
    });
    let started = Instant::now();

    log::info(&format!(
        "listening on {addr} (engine host: {engine_host}, fragments: {}, linger: encoder {}s, engine {}s)",
        frag_duration_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "keyframe".into()),
        encoder_linger.as_secs(),
        engine_linger.as_secs(),
    ));

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                // One connection failing to arrive says nothing about the
                // listener, which is still perfectly good. tiny_http shut the
                // whole server down here, its open issue #283.
                log::warn(&format!("could not accept a connection: {e}"));
                continue;
            }
        };
        let registry = registry.clone();
        // A thread per request, deliberately not a pool: every stream is
        // long-lived, so a pool would be fully occupied by a handful of
        // listeners and new requests would never be served.
        if let Err(e) = thread::Builder::new()
            .name("request".into())
            .spawn(move || {
                // Reading the head here rather than in the accept loop means a
                // client that connects and then dawdles delays only itself.
                match Request::read(stream) {
                    Ok(request) => handle(&registry, request, started),
                    // The peer has already been answered; nothing else to do.
                    Err(e) => log::warn(&format!("rejected a request: {e}")),
                }
            })
        {
            log::error(&format!("could not spawn a request thread: {e}"));
        }
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_owned(),
    }
}

/// A whole number of seconds from the environment; 0 disables the feature.
fn env_seconds(key: &str, default_secs: u64) -> Duration {
    match env_or(key, &default_secs.to_string()).parse::<u64>() {
        Ok(secs) => Duration::from_secs(secs),
        Err(_) => {
            log::error(&format!("{key} must be a non-negative number of seconds"));
            std::process::exit(1);
        }
    }
}

/// Accept Go's `:8080` shorthand alongside a full `host:port`.
fn normalise_addr(addr: &str) -> String {
    match addr.strip_prefix(':') {
        Some(port) => format!("0.0.0.0:{port}"),
        None => addr.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

fn handle(registry: &Arc<Registry>, request: Request, started: Instant) {
    let url = request.url().to_owned();
    let path = url.split('?').next().unwrap_or("/").to_owned();
    let method = request.method().to_owned();

    if method == "OPTIONS" {
        // We advertise CORS, so answer the preflight even though a plain GET of
        // a media URL does not trigger one.
        request.respond(
            Response::empty(204)
                .with_header("Access-Control-Allow-Origin", "*")
                .with_header("Access-Control-Allow-Methods", "GET, OPTIONS")
                .with_header("Access-Control-Allow-Headers", "*"),
        );
        return;
    }
    if method != "GET" && method != "HEAD" {
        return reply(request, 405, "method not allowed");
    }

    match path.as_str() {
        "/audio" | "/video" => serve_stream(registry, request, &url, &path),
        "/healthz" => reply(request, 200, "ok"),
        "/status" => {
            let body = status::snapshot(registry, started).to_string();
            request.respond(
                Response::from_string(body)
                    .with_header("Content-Type", "application/json")
                    .with_header("Cache-Control", "no-store")
                    .with_header("Access-Control-Allow-Origin", "*"),
            );
        }
        "/" => reply(request, 200, USAGE),
        _ => reply(request, 404, USAGE),
    }
}

const USAGE: &str = "usage:\n  GET /audio?id=<40-hex content id>[&fmt=adts|mp3]\n  \
                     GET /video?id=<40-hex content id>\n  GET /status\n";

fn reply(request: Request, code: u16, body: &str) {
    request.respond(
        Response::from_string(body)
            .with_status_code(code)
            .with_header("Access-Control-Allow-Origin", "*"),
    );
}

/// Extract a query parameter. Values here are a hex id and a fixed word list,
/// neither of which can be percent-encoded, so no decoding is needed.
fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_owned())
    })
}

fn valid_content_id(id: &str) -> bool {
    id.len() == 40 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn serve_stream(registry: &Arc<Registry>, request: Request, url: &str, path: &str) {
    let peer = request.peer().to_owned();

    let id = query_param(url, "id").unwrap_or_default();
    if !valid_content_id(&id) {
        return reply(request, 400, "id must be a 40-char hex content id");
    }

    let fmt = if path == "/video" {
        OutputFormat::Fmp4
    } else {
        let raw = query_param(url, "fmt").unwrap_or_else(|| "adts".into());
        match OutputFormat::parse_audio(&raw) {
            Some(f) => f,
            None => return reply(request, 400, "fmt must be adts or mp3"),
        }
    };

    // Answered before anything is started. Players commonly probe with a HEAD
    // before the GET; subscribing here would start an engine pull and an
    // ffmpeg, wait for a first fragment, and tear the lot down again.
    if request.method() == "HEAD" {
        request.respond(
            Response::empty(200)
                .with_header("Content-Type", fmt.content_type())
                .with_header("Access-Control-Allow-Origin", "*"),
        );
        return;
    }

    // The fan-out gets its own handle on the socket so that evicting this
    // listener also unblocks a write it may be stuck in.
    let kick = request.socket_handle();
    let sub = match registry.subscribe(&id, fmt, &peer, kick) {
        Ok(s) => s,
        Err(e) => {
            log::error(&format!("{peer}: {id}/{fmt}: {e}"));
            return reply(request, 502, &format!("could not start stream: {e}"));
        }
    };

    log::info(&format!("{peer}: streaming {id} as {fmt}"));
    let counter = sub.counter();
    let start = Instant::now();

    stream_body(request, fmt, sub);

    log::info(&format!(
        "{peer}: {id}/{fmt} ended after {}s, {} bytes sent",
        start.elapsed().as_secs(),
        counter.load(Ordering::Relaxed)
    ));
}

/// Write the response head and body straight to the socket.
///
/// Deliberately bypasses `Request::respond`, which frames a response by its
/// known length; a stream has no length to know. Close-delimited framing
/// (RFC 9112 §6.3) is valid for both HTTP/1.0 and HTTP/1.1 and costs only
/// keep-alive, which is worthless when a connection carries exactly one
/// hours-long stream.
///
/// It also keeps the socket unbuffered, which is what makes the low-latency
/// ffmpeg flags meaningful end to end: every chunk the encoder emits is one
/// `write` straight to the kernel — see `http::Request::read`.
fn stream_body(request: Request, fmt: OutputFormat, mut sub: Subscription) {
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {}\r\n\
         Cache-Control: no-store\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\
         \r\n",
        fmt.content_type()
    );

    let mut w = request.into_writer();
    if w.write_all(head.as_bytes()).is_err() {
        return;
    }

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match sub.read(&mut buf) {
            Ok(0) => break,
            // A write error — the client gone, its write timeout expired, or
            // the fan-out having shut the socket on eviction — is how a
            // departed client is noticed; the Subscription drop that follows
            // deregisters it and starts the encoder's linger if it was last.
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_40_char_hex_ids() {
        assert!(valid_content_id(&"a".repeat(40)));
        assert!(valid_content_id("0123456789ABCDEFabcdef0123456789abcdef01"));
        assert!(!valid_content_id(&"a".repeat(39)));
        assert!(!valid_content_id(&"a".repeat(41)));
        assert!(!valid_content_id(""));
        assert!(!valid_content_id(&"g".repeat(40)));
        // Server-side url construction plus this check is what keeps a caller
        // from steering the engine request somewhere else.
        assert!(!valid_content_id("../../etc/passwd"));
        assert!(!valid_content_id("http://internal/admin"));
    }

    #[test]
    fn reads_query_parameters() {
        let url = "/audio?id=abc&fmt=mp3";
        assert_eq!(query_param(url, "id").as_deref(), Some("abc"));
        assert_eq!(query_param(url, "fmt").as_deref(), Some("mp3"));
        assert_eq!(query_param(url, "missing"), None);
        assert_eq!(query_param("/audio", "id"), None);
        assert_eq!(query_param("/audio?", "id"), None);
    }

    #[test]
    fn query_parameters_do_not_match_by_prefix() {
        let url = "/audio?xid=nope&id=yes";
        assert_eq!(query_param(url, "id").as_deref(), Some("yes"));
    }

    #[test]
    fn normalises_the_go_style_listen_address() {
        assert_eq!(normalise_addr(":8080"), "0.0.0.0:8080");
        assert_eq!(normalise_addr("127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(normalise_addr("0.0.0.0:8080"), "0.0.0.0:8080");
    }
}
