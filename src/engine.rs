//! Minimal blocking HTTP client and the AceStream engine session API.
//!
//! ffmpeg no longer opens the engine URL itself — one puller holds a single
//! engine connection per content id and feeds every format's ffmpeg over a
//! pipe. That means we own the network read, so we also own the stall timeout
//! that `-rw_timeout` used to provide.
//!
//! A dedicated client rather than an HTTP crate, because the semantics we need
//! are specific: a *per-read* timeout on an endless response body, with no
//! total-duration cap. Most clients only offer whole-body timeouts, which would
//! kill a stream that is working perfectly.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::log;

/// Matches the `-rw_timeout 30000000` the Go service passed to ffmpeg.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Short timeout for the small JSON control requests.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    pub target: String,
}

pub fn parse_url(s: &str) -> io::Result<Url> {
    let rest = s
        .strip_prefix("http://")
        .ok_or_else(|| bad(format!("only http:// urls are supported: {s}")))?;
    let (authority, target) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(bad(format!("url has no host: {s}")));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| bad(format!("invalid port in {s}")))?,
        ),
        None => (authority, 80),
    };
    Ok(Url {
        host: host.to_owned(),
        port,
        target: target.to_owned(),
    })
}

fn bad(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// How the response body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Chunked,
    Length(u64),
    /// No delimiter — the body runs until the peer closes. This is what the
    /// engine's stream endpoint does.
    ToClose,
}

pub struct Body<R: Read> {
    inner: BufReader<R>,
    kind: BodyKind,
    left: u64,
    done: bool,
}

impl<R: Read> Body<R> {
    #[cfg(test)]
    fn chunked(inner: BufReader<R>) -> Self {
        Body {
            inner,
            kind: BodyKind::Chunked,
            left: 0,
            done: false,
        }
    }

    /// Read one CRLF-terminated control line from a chunked body.
    fn read_line(&mut self) -> io::Result<String> {
        let mut line = String::new();
        let n = self.inner.read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "chunked body ended mid-stream",
            ));
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_owned())
    }
}

impl<R: Read> Read for Body<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        match self.kind {
            BodyKind::ToClose => self.inner.read(buf),
            BodyKind::Length(_) => {
                if self.left == 0 {
                    self.done = true;
                    return Ok(0);
                }
                let cap = buf.len().min(self.left as usize);
                let n = self.inner.read(&mut buf[..cap])?;
                if n == 0 {
                    self.done = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "body shorter than content-length",
                    ));
                }
                self.left -= n as u64;
                Ok(n)
            }
            BodyKind::Chunked => {
                if self.left == 0 {
                    // Every chunk after the first is preceded by a bare CRLF.
                    let mut line = self.read_line()?;
                    if line.is_empty() {
                        line = self.read_line()?;
                    }
                    // Chunk extensions follow a ';' and are ignored.
                    let size_hex = line.split(';').next().unwrap_or("").trim();
                    let size = u64::from_str_radix(size_hex, 16).map_err(|_| {
                        bad(format!("malformed chunk size {size_hex:?}"))
                    })?;
                    if size == 0 {
                        // Consume trailers up to the terminating blank line.
                        while !self.read_line().unwrap_or_default().is_empty() {}
                        self.done = true;
                        return Ok(0);
                    }
                    self.left = size;
                }
                let cap = buf.len().min(self.left as usize);
                let n = self.inner.read(&mut buf[..cap])?;
                if n == 0 {
                    self.done = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "chunk shorter than declared",
                    ));
                }
                self.left -= n as u64;
                Ok(n)
            }
        }
    }
}

pub struct Response {
    pub status: u16,
    pub body: Body<TcpStream>,
    /// A second handle on the same socket, so a reader blocked in `read` can be
    /// interrupted by `shutdown` from another thread instead of waiting out the
    /// stall timeout.
    pub socket: TcpStream,
}

fn read_head<R: Read>(inner: &mut BufReader<R>) -> io::Result<(u16, HashMap<String, String>)> {
    let mut line = String::new();
    let mut consumed = 0usize;
    consumed += inner.read_line(&mut line)?;
    if consumed == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no response from engine",
        ));
    }
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| bad(format!("malformed status line {line:?}")))?;

    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        let n = inner.read_line(&mut h)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "headers ended mid-stream",
            ));
        }
        consumed += n;
        if consumed > MAX_HEADER_BYTES {
            return Err(bad("response headers too large".into()));
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    Ok((status, headers))
}

fn body_kind(headers: &HashMap<String, String>) -> BodyKind {
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        return BodyKind::Chunked;
    }
    match headers.get("content-length").and_then(|v| v.parse().ok()) {
        Some(n) => BodyKind::Length(n),
        None => BodyKind::ToClose,
    }
}

/// Issue a GET, following at most one redirect.
///
/// `read_timeout` applies to each individual socket read, not to the response as
/// a whole — an endless stream is normal here, a stalled one is not.
pub fn get(url: &str, read_timeout: Duration) -> io::Result<Response> {
    let mut current = url.to_owned();
    for hop in 0..2 {
        let u = parse_url(&current)?;
        let addr = (u.host.as_str(), u.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| bad(format!("could not resolve {}", u.host)))?;

        let stream = TcpStream::connect_timeout(&addr, CONTROL_TIMEOUT)?;
        stream.set_read_timeout(Some(read_timeout))?;
        stream.set_write_timeout(Some(CONTROL_TIMEOUT))?;
        // Live streaming: never let Nagle sit on a partial frame.
        stream.set_nodelay(true)?;

        let mut w = &stream;
        write!(
            w,
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: rust-acestream-proxy\r\nConnection: close\r\nAccept: */*\r\n\r\n",
            u.target, u.host, u.port
        )?;
        w.flush()?;

        let socket = stream.try_clone()?;
        let mut inner = BufReader::with_capacity(64 * 1024, stream);
        let (status, headers) = read_head(&mut inner)?;

        if matches!(status, 301 | 302 | 303 | 307 | 308) && hop == 0 {
            if let Some(loc) = headers.get("location") {
                current = if loc.starts_with("http://") {
                    loc.clone()
                } else {
                    format!("http://{}:{}{}", u.host, u.port, loc)
                };
                continue;
            }
        }

        let kind = body_kind(&headers);
        return Ok(Response {
            status,
            socket,
            body: Body {
                inner,
                kind,
                left: match kind {
                    BodyKind::Length(n) => n,
                    _ => 0,
                },
                done: false,
            },
        });
    }
    Err(bad(format!("too many redirects from {url}")))
}

/// GET a small resource and return it as text.
fn get_text(url: &str, timeout: Duration) -> Result<String, String> {
    let mut r = get(url, timeout).map_err(|e| e.to_string())?;
    if r.status != 200 {
        return Err(format!("http {}", r.status));
    }
    let mut s = String::new();
    // Cap it: a control endpoint returning a stream would otherwise hang here.
    r.body
        .by_ref()
        .take(1 << 20)
        .read_to_string(&mut s)
        .map_err(|e| e.to_string())?;
    Ok(s)
}

/// An open engine session for one content id.
#[derive(Debug, Clone)]
pub struct Session {
    pub playback_url: String,
    /// Present only when the engine answered the JSON handshake. Without it
    /// there are no peer statistics and no clean stop.
    pub stat_url: Option<String>,
    pub command_url: Option<String>,
}

fn getstream_url(engine_host: &str, content_id: &str, pid: &str, json: bool) -> String {
    format!(
        "http://{engine_host}/ace/getstream?id={content_id}&pid={pid}{}",
        if json { "&format=json" } else { "" }
    )
}

/// Open a session against the engine.
///
/// Prefers the `format=json` handshake, which yields `stat_url` (peer and speed
/// statistics for /status) and `command_url` (a clean stop on teardown, so the
/// engine drops the P2P session rather than waiting for the TCP connection to
/// die). Falls back to a direct stream URL if the engine does not support it,
/// which costs statistics but keeps the service working.
pub fn open_session(engine_host: &str, content_id: &str, pid: &str) -> Result<Session, String> {
    let direct = getstream_url(engine_host, content_id, pid, false);
    let url = getstream_url(engine_host, content_id, pid, true);

    let text = match get_text(&url, CONTROL_TIMEOUT) {
        Ok(t) => t,
        Err(e) => {
            log::warn!(
                "engine json handshake failed ({e}); falling back to a direct pull without stats"
            );
            return Ok(Session {
                playback_url: direct,
                stat_url: None,
                command_url: None,
            });
        }
    };

    match parse_session(&text) {
        Ok(s) => Ok(s),
        Err(e) => {
            // A structured error from the engine (bad id, no such channel) is a
            // real failure and must surface, unlike an unsupported handshake.
            if let Some(msg) = engine_error(&text) {
                return Err(msg);
            }
            log::warn!(
                "engine json handshake unparsable ({e}); falling back to a direct pull without stats"
            );
            Ok(Session {
                playback_url: direct,
                stat_url: None,
                command_url: None,
            })
        }
    }
}

/// Extract the engine's own error message, if the response carries one.
pub fn engine_error(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    match v.get("error") {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(format!("engine error: {s}")),
        _ => None,
    }
}

pub fn parse_session(body: &str) -> Result<Session, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("not json: {e}"))?;
    let r = v
        .get("response")
        .filter(|r| !r.is_null())
        .ok_or_else(|| "no response object".to_string())?;
    let playback_url = r
        .get("playback_url")
        .and_then(|u| u.as_str())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "no playback_url".to_string())?
        .to_owned();
    let pick = |k: &str| {
        r.get(k)
            .and_then(|u| u.as_str())
            .filter(|u| !u.is_empty())
            .map(|u| u.to_owned())
    };
    Ok(Session {
        playback_url,
        stat_url: pick("stat_url"),
        command_url: pick("command_url"),
    })
}

/// Poll the engine's per-session statistics.
///
/// The shape varies between engine versions, so the whole `response` object is
/// passed through to /status rather than being coerced into a fixed struct.
pub fn fetch_stats(stat_url: &str) -> Result<serde_json::Value, String> {
    let text = get_text(stat_url, CONTROL_TIMEOUT)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("stat response not json: {e}"))?;
    match v.get("response") {
        Some(r) if !r.is_null() => Ok(r.clone()),
        _ => Err(engine_error(&text).unwrap_or_else(|| "stat response had no data".into())),
    }
}

/// Tell the engine to drop the session. Best effort: teardown must not block on
/// an unresponsive engine.
pub fn send_stop(command_url: &str) {
    let sep = if command_url.contains('?') { '&' } else { '?' };
    let url = format!("{command_url}{sep}method=stop");
    if let Err(e) = get_text(&url, CONTROL_TIMEOUT) {
        log::warn!("engine stop command failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_urls_with_and_without_ports() {
        let u = parse_url("http://engine:6878/ace/getstream?id=abc").unwrap();
        assert_eq!(u.host, "engine");
        assert_eq!(u.port, 6878);
        assert_eq!(u.target, "/ace/getstream?id=abc");

        let u = parse_url("http://127.0.0.1/x").unwrap();
        assert_eq!(u.port, 80);

        let u = parse_url("http://engine:6878").unwrap();
        assert_eq!(u.target, "/", "a bare authority must still request /");
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(parse_url("https://engine/x").is_err());
        assert!(parse_url("ftp://engine/x").is_err());
        assert!(parse_url("http:///x").is_err());
        assert!(parse_url("http://engine:notaport/x").is_err());
    }

    fn read_all_chunked(raw: &[u8]) -> io::Result<Vec<u8>> {
        let mut b = Body::chunked(BufReader::new(Cursor::new(raw.to_vec())));
        let mut out = Vec::new();
        b.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn decodes_chunked_bodies() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(read_all_chunked(raw).unwrap(), b"hello world");
    }

    #[test]
    fn ignores_chunk_extensions() {
        let raw = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        assert_eq!(read_all_chunked(raw).unwrap(), b"hello");
    }

    #[test]
    fn consumes_chunked_trailers() {
        let raw = b"3\r\nabc\r\n0\r\nX-Trailer: 1\r\n\r\n";
        assert_eq!(read_all_chunked(raw).unwrap(), b"abc");
    }

    #[test]
    fn rejects_malformed_chunk_sizes() {
        assert!(read_all_chunked(b"zz\r\nabc\r\n").is_err());
    }

    #[test]
    fn detects_body_framing_from_headers() {
        let mut h = HashMap::new();
        assert_eq!(body_kind(&h), BodyKind::ToClose);

        h.insert("content-length".into(), "42".into());
        assert_eq!(body_kind(&h), BodyKind::Length(42));

        h.insert("transfer-encoding".into(), "chunked".into());
        assert_eq!(body_kind(&h), BodyKind::Chunked, "chunked outranks length");
    }

    #[test]
    fn parses_status_line_and_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\nContent-Length: 5\r\n\r\nhello";
        let mut r = BufReader::new(Cursor::new(raw.to_vec()));
        let (status, headers) = read_head(&mut r).unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers.get("content-type").unwrap(), "video/mp2t");
        // Header names are matched case-insensitively.
        assert_eq!(headers.get("content-length").unwrap(), "5");
    }

    #[test]
    fn parses_the_acestream_handshake() {
        let body = r#"{"response":{
            "playback_url":"http://127.0.0.1:6878/content/abc/0.ts",
            "stat_url":"http://127.0.0.1:6878/ace/stat/abc",
            "command_url":"http://127.0.0.1:6878/ace/cmd/abc",
            "is_live":1},"error":null}"#;
        let s = parse_session(body).unwrap();
        assert_eq!(s.playback_url, "http://127.0.0.1:6878/content/abc/0.ts");
        assert_eq!(s.stat_url.as_deref(), Some("http://127.0.0.1:6878/ace/stat/abc"));
        assert_eq!(s.command_url.as_deref(), Some("http://127.0.0.1:6878/ace/cmd/abc"));
    }

    #[test]
    fn handshake_tolerates_a_missing_stat_url() {
        let body = r#"{"response":{"playback_url":"http://x/y.ts"},"error":null}"#;
        let s = parse_session(body).unwrap();
        assert_eq!(s.stat_url, None);
        assert_eq!(s.command_url, None);
    }

    #[test]
    fn handshake_rejects_responses_without_a_playback_url() {
        assert!(parse_session(r#"{"response":null,"error":"bad id"}"#).is_err());
        assert!(parse_session(r#"{"response":{},"error":null}"#).is_err());
        assert!(parse_session(r#"{"response":{"playback_url":""}}"#).is_err());
        assert!(parse_session("garbage").is_err());
    }

    #[test]
    fn surfaces_engine_error_messages() {
        let body = r#"{"response":null,"error":"unknown content id"}"#;
        assert_eq!(
            engine_error(body).as_deref(),
            Some("engine error: unknown content id")
        );
        assert_eq!(engine_error(r#"{"error":null}"#), None);
        assert_eq!(engine_error("not json"), None);
    }

    #[test]
    fn getstream_url_carries_a_distinct_player_id() {
        let u = getstream_url("engine:6878", "abc", "proxy-123", true);
        assert_eq!(
            u,
            "http://engine:6878/ace/getstream?id=abc&pid=proxy-123&format=json"
        );
        let u = getstream_url("engine:6878", "abc", "proxy-123", false);
        assert!(!u.contains("format=json"));
    }
}
