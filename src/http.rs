//! A small HTTP/1.1 server: accept a connection, read the request head, hand
//! the socket back.
//!
//! This replaces tiny_http, whose last release was 0.12.0 in October 2022 and
//! whose last commit was May 2023. Two advisories were published against it on
//! 2026-07-28 with no fixed version: CVE-2026-66752 (request smuggling — the
//! `Transfer-Encoding` header is tested for presence and its value never read,
//! so any coding triggers chunk decoding and discards `Content-Length`) and
//! CVE-2026-66753 (CR and LF accepted inside header values in both directions).
//! Neither is mapped to the crates.io ecosystem in OSV, so `cargo audit` and
//! the nightly Trivy scan do not see them.
//!
//! Replacing the crate is cheap because this service needs almost nothing from
//! HTTP: three routes, GET/HEAD/OPTIONS, and no request body anywhere. The hot
//! path never went through tiny_http to begin with — `stream_body` has always
//! written the response head by hand and streamed straight to the socket — so
//! only the accept-and-parse half is replaced here.
//!
//! Three properties fall out of the shape rather than out of careful coding:
//!
//! * One request per connection, always answered `Connection: close`. Smuggling
//!   is a disagreement between two parties about where one message ends and the
//!   next begins; a connection that never carries a second message has no such
//!   disagreement to exploit.
//! * Bodies are refused rather than parsed. There is no chunked decoder here to
//!   be confused about a coding it does not recognise.
//! * No request header value reaches the application. A CR or LF that somehow
//!   survived parsing would have nowhere to be reflected into.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::engine::log;

/// The whole head — request line, every header, and the blank line — must fit.
/// tiny_http had no equivalent cap, which is the root of its open "capacity
/// overflow in SequentialReader" crash report.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// A second bound, so a head of many tiny lines is rejected on count before it
/// reaches the byte cap.
const MAX_HEADER_LINES: usize = 64;

/// How long a connection may take to deliver its head. Without this a client
/// that connects and then says nothing parks a thread forever, which is what
/// tiny_http does today.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);

/// How long one write to a client may block. A phone that drops off the
/// network without closing leaves the socket's send buffer full and a blocking
/// write stuck until the kernel gives up on retransmission — a quarter of an
/// hour by default. Until then the request thread, its `Subscription`, and so
/// the encoder and engine pull behind it, all stay alive for nobody. Long
/// enough that a healthy client on a bad link is never cut off by this alone:
/// the fan-out evicts it on lag first.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    /// The head did not parse. Deliberately vague: the client does not need to
    /// know which of our checks it tripped.
    Malformed(&'static str),
    /// Head exceeded [`MAX_HEAD_BYTES`] or [`MAX_HEADER_LINES`].
    TooLarge,
    /// A body was declared. This service has no endpoint that reads one.
    BodyNotAllowed,
    /// Any `Transfer-Encoding` at all. Answered 501 rather than 400 because
    /// RFC 9112 §7 asks a server that does not support a coding to say so.
    TransferEncoding,
    Timeout,
    Io(std::io::Error),
}

impl Error {
    fn status(&self) -> u16 {
        match self {
            Error::Malformed(_) => 400,
            Error::TooLarge => 431,
            Error::BodyNotAllowed => 400,
            Error::TransferEncoding => 501,
            Error::Timeout => 408,
            Error::Io(_) => 400,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed request ({what})"),
            Error::TooLarge => write!(f, "request head too large"),
            Error::BodyNotAllowed => write!(f, "request body not allowed"),
            Error::TransferEncoding => write!(f, "transfer-encoding not supported"),
            Error::Timeout => write!(f, "timed out reading the request head"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

fn io_error(e: std::io::Error) -> Error {
    // A read timeout surfaces as WouldBlock or TimedOut depending on platform.
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Error::Timeout,
        _ => Error::Io(e),
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// The only two things this service takes from a request head.
#[derive(Debug, PartialEq)]
pub struct Head {
    pub method: String,
    pub target: String,
}

/// Read one line, requiring CRLF termination, and return it without that CRLF.
///
/// Strictness here is the request-side half of CVE-2026-66753. tiny_http's
/// `read_next_line` ends a line only on CRLF but pushes anything else into the
/// buffer, so a lone LF survives inside a value and reaches the application; a
/// backend that treats bare LF as a terminator — RFC 9112 §2.2 permits it, and
/// Go's net/http and Python's http.server both do — then reads one request as
/// two. Refusing bare CR and bare LF outright costs nothing and ends that.
fn read_line<R: BufRead>(reader: &mut R, budget: &mut usize) -> Result<Vec<u8>, Error> {
    if *budget == 0 {
        return Err(Error::TooLarge);
    }

    let mut buf = Vec::new();
    // Bounded by the remaining budget, so a client that never sends a newline
    // cannot make us allocate without limit.
    let n = reader
        .by_ref()
        .take(*budget as u64)
        .read_until(b'\n', &mut buf)
        .map_err(io_error)?;
    *budget -= n;

    if !buf.ends_with(b"\r\n") {
        // Either the budget ran out mid-line, or the peer closed, or the line
        // ended in a bare LF.
        return if *budget == 0 {
            Err(Error::TooLarge)
        } else {
            Err(Error::Malformed("line not CRLF-terminated"))
        };
    }
    buf.truncate(buf.len() - 2);

    // A CR surviving the truncation is a bare CR mid-line. A LF cannot appear:
    // read_until stopped at the first one.
    if buf.contains(&b'\r') || buf.contains(&0) {
        return Err(Error::Malformed("control byte in head"));
    }
    Ok(buf)
}

/// Parse `METHOD SP request-target SP HTTP-version`.
///
/// Origin-form targets only. Absolute-form (`GET http://host/path`) is what
/// lets a request be routed somewhere other than where the front end thought it
/// was going, and nothing here needs it.
fn parse_request_line(line: &[u8]) -> Result<Head, Error> {
    let mut parts = line.split(|b| *b == b' ');
    let method = parts
        .next()
        .ok_or(Error::Malformed("no method"))?
        .to_owned();
    let target = parts
        .next()
        .ok_or(Error::Malformed("no request target"))?
        .to_owned();
    let version = parts.next().ok_or(Error::Malformed("no version"))?;
    if parts.next().is_some() {
        return Err(Error::Malformed("extra field in request line"));
    }

    if method.is_empty() || method.len() > 16 || !method.iter().all(|b| b.is_ascii_alphabetic()) {
        return Err(Error::Malformed("bad method"));
    }
    if !version.starts_with(b"HTTP/1.") {
        return Err(Error::Malformed("unsupported version"));
    }
    // Visible ASCII only. The target reaches query parsing and the log, so
    // nothing invisible has any business being in it.
    if target.first() != Some(&b'/') || !target.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(Error::Malformed("bad request target"));
    }

    Ok(Head {
        // Both were just checked to be visible ASCII.
        method: String::from_utf8(method).map_err(|_| Error::Malformed("non-ascii method"))?,
        target: String::from_utf8(target).map_err(|_| Error::Malformed("non-ascii target"))?,
    })
}

/// Refuse any request that declares a body.
///
/// This is the whole of our framing logic, and the reason CVE-2026-66752 has no
/// analogue here: a request either has no body and is served, or declares one
/// and is rejected. There is no third path in which two parties could disagree
/// about a length.
fn check_no_body(line: &[u8]) -> Result<(), Error> {
    let colon = line
        .iter()
        .position(|b| *b == b':')
        .ok_or(Error::Malformed("header without a colon"))?;
    let name = &line[..colon];
    if name.is_empty() || name.iter().any(|b| b.is_ascii_whitespace()) {
        // A space before the colon is the classic way to get two parsers to
        // disagree about whether a header exists at all.
        return Err(Error::Malformed("bad header name"));
    }

    if name.eq_ignore_ascii_case(b"transfer-encoding") {
        return Err(Error::TransferEncoding);
    }
    if name.eq_ignore_ascii_case(b"content-length") {
        let value = std::str::from_utf8(&line[colon + 1..])
            .map_err(|_| Error::Malformed("non-ascii content-length"))?
            .trim();
        match value.parse::<u64>() {
            Ok(0) => {}
            Ok(_) => return Err(Error::BodyNotAllowed),
            Err(_) => return Err(Error::Malformed("bad content-length")),
        }
    }
    Ok(())
}

/// Read and validate a request head, discarding every header that is not a
/// framing header. Nothing else in this service reads request headers, so
/// keeping none of them is both simpler and one less thing to reflect.
pub fn read_head<R: BufRead>(reader: &mut R) -> Result<Head, Error> {
    let mut budget = MAX_HEAD_BYTES;
    let head = parse_request_line(&read_line(reader, &mut budget)?)?;

    let mut lines = 0;
    loop {
        let line = read_line(reader, &mut budget)?;
        if line.is_empty() {
            return Ok(head);
        }
        lines += 1;
        if lines > MAX_HEADER_LINES {
            return Err(Error::TooLarge);
        }
        check_no_body(&line)?;
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

pub struct Request {
    method: String,
    target: String,
    peer: String,
    stream: TcpStream,
}

impl Request {
    /// Take an accepted connection and read its request head.
    ///
    /// Call this on the thread that will serve the request, never on the accept
    /// loop: a client that dawdles holds this for up to [`HEAD_TIMEOUT`], and
    /// that wait belongs to one connection rather than to every pending one.
    ///
    /// On failure the peer has already been answered, and the socket closes as
    /// it drops.
    pub fn read(stream: TcpStream) -> Result<Request, Error> {
        // Set per socket, which the old libc setsockopt on the listener could
        // not do: tiny_http never exposed the accepted stream, so the code
        // relied on Linux copying the flag from listener to accepted socket.
        // Doing it here is explicit and drops the last use of the libc crate.
        if stream.set_nodelay(true).is_err() {
            log::warn("could not set TCP_NODELAY; expect added latency");
        }
        if let Err(e) = stream.set_read_timeout(Some(HEAD_TIMEOUT)) {
            log::warn(&format!("could not set a read timeout: {e}"));
        }
        if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
            log::warn(&format!("could not set a write timeout: {e}"));
        }
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".into());

        // The head is small and read a line at a time, so it wants buffering.
        // The write half deliberately gets none: stream_body flushes per chunk
        // and a buffer there would undo ffmpeg's -flush_packets.
        let mut reader = BufReader::with_capacity(2048, stream);
        let result = read_head(&mut reader);
        let mut stream = reader.into_inner();

        match result {
            Ok(head) => {
                // Nothing reads from this socket again; leaving a timeout armed
                // would only mislead whoever next touches this code.
                let _ = stream.set_read_timeout(None);
                Ok(Request {
                    method: head.method,
                    target: head.target,
                    peer,
                    stream,
                })
            }
            Err(e) => {
                let _ = respond_error(&mut stream, &e);
                Err(e)
            }
        }
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    /// The request target, path and query together.
    pub fn url(&self) -> &str {
        &self.target
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Answer with a framed response. A HEAD request gets the head alone,
    /// with the Content-Length the GET would have carried.
    pub fn respond(mut self, response: Response) {
        let head_only = self.method == "HEAD";
        let _ = response.write_to(&mut self.stream, head_only);
    }

    /// A second handle on the socket, for whoever needs to shut it down from
    /// another thread while a body is streaming.
    pub fn socket_handle(&self) -> Option<TcpStream> {
        self.stream.try_clone().ok()
    }

    /// Hand over the socket so the caller can write the head and stream a body
    /// itself. See `stream_body` for why this service does that.
    pub fn into_writer(self) -> TcpStream {
        self.stream
    }
}

fn respond_error(stream: &mut TcpStream, e: &Error) -> std::io::Result<()> {
    Response::from_string(format!("{e}\n"))
        .with_status_code(e.status())
        .write_to(stream, false)
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

pub struct Response {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

impl Response {
    pub fn empty(status: u16) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn from_string(body: impl Into<String>) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: body.into().into_bytes(),
        }
    }

    pub fn with_status_code(mut self, status: u16) -> Response {
        self.status = status;
        self
    }

    /// Add a header.
    ///
    /// The response-side half of CVE-2026-66753 was that tiny_http's
    /// `Header::from_bytes` checked only for ASCII and the writer emitted the
    /// value verbatim, so a CRLF in a value split the response. Every value
    /// this service sends is a literal or `OutputFormat::content_type`, so a
    /// failure here is a bug in our own source rather than anything a client
    /// can reach — which is exactly what an assertion is for.
    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Response {
        let value = value.into();
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b':' && b != b'\r' && b != b'\n'),
            "invalid header name {name:?}"
        );
        assert!(
            !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0),
            "header {name} carries a control byte, which would split the response"
        );
        self.headers.push((name, value));
        self
    }

    fn write_to(&self, w: &mut impl Write, head_only: bool) -> std::io::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (name, value) in &self.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        // 204 and 304 are defined to carry no body, and framing them as though
        // they might is how a client is led to wait for bytes never sent.
        if self.status != 204 && self.status != 304 {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        // Every connection carries exactly one request. Saying so is what makes
        // the smuggling class structurally unreachable rather than merely
        // unlikely.
        head.push_str("Connection: close\r\n\r\n");

        w.write_all(head.as_bytes())?;
        if !self.body.is_empty() && !head_only {
            w.write_all(&self.body)?;
        }
        w.flush()
    }
}

/// Reason phrases for the statuses this service actually emits. Clients ignore
/// these, but a human reading a curl trace does not.
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(raw: &[u8]) -> Result<Head, Error> {
        read_head(&mut Cursor::new(raw))
    }

    fn head(method: &str, target: &str) -> Head {
        Head {
            method: method.into(),
            target: target.into(),
        }
    }

    #[test]
    fn parses_a_minimal_request() {
        let raw = b"GET /audio?id=abc HTTP/1.1\r\nHost: x\r\nUser-Agent: mpv\r\n\r\n";
        assert_eq!(parse(raw).unwrap(), head("GET", "/audio?id=abc"));
    }

    #[test]
    fn parses_head_and_options() {
        assert_eq!(
            parse(b"HEAD /video?id=a HTTP/1.1\r\n\r\n").unwrap(),
            head("HEAD", "/video?id=a")
        );
        assert_eq!(
            parse(b"OPTIONS /audio HTTP/1.1\r\nOrigin: http://x\r\n\r\n").unwrap(),
            head("OPTIONS", "/audio")
        );
    }

    #[test]
    fn accepts_http_1_0() {
        // Close-delimited framing is valid for 1.0, and that is all we emit.
        assert_eq!(parse(b"GET / HTTP/1.0\r\n\r\n").unwrap(), head("GET", "/"));
    }

    // -- CVE-2026-66753, request side: CR and LF must not survive parsing ----

    #[test]
    fn rejects_bare_lf_line_endings() {
        // tiny_http keeps the lone LF inside the value and hands it to the app.
        let raw = b"GET / HTTP/1.1\nHost: x\n\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_a_bare_lf_inside_a_header_value() {
        let raw = b"GET / HTTP/1.1\r\nX-Thing: a\nb\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_a_bare_cr_inside_a_header_value() {
        let raw = b"GET / HTTP/1.1\r\nX-Thing: a\rb\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_a_nul_in_the_head() {
        let raw = b"GET / HTTP/1.1\r\nX-Thing: a\0b\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    // -- CVE-2026-66752: no body means no framing to disagree about ----------

    #[test]
    fn rejects_any_transfer_encoding() {
        for value in ["chunked", "identity", "gzip, chunked", "chunked, gzip"] {
            let raw = format!("POST / HTTP/1.1\r\nTransfer-Encoding: {value}\r\n\r\n");
            assert!(
                matches!(parse(raw.as_bytes()), Err(Error::TransferEncoding)),
                "accepted Transfer-Encoding: {value}"
            );
        }
    }

    #[test]
    fn rejects_transfer_encoding_whatever_its_case() {
        let raw = b"POST / HTTP/1.1\r\ntRaNsFeR-eNcOdInG: chunked\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::TransferEncoding)));
    }

    #[test]
    fn rejects_a_declared_body() {
        let raw = b"POST /audio HTTP/1.1\r\nContent-Length: 12\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::BodyNotAllowed)));
    }

    #[test]
    fn allows_an_explicit_zero_length_body() {
        // Some clients send this on a plain GET.
        let raw = b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(parse(raw).unwrap(), head("GET", "/"));
    }

    #[test]
    fn rejects_a_content_length_that_is_not_a_number() {
        let raw = b"GET / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_a_space_before_the_header_colon() {
        // The desync trick: one parser reads a header here, the other does not.
        let raw = b"GET / HTTP/1.1\r\nContent-Length : 12\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    // -- Bounds -------------------------------------------------------------

    #[test]
    fn rejects_a_head_over_the_byte_cap() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        raw.extend_from_slice(b"X-Pad: ");
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES));
        raw.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(parse(&raw), Err(Error::TooLarge)));
    }

    #[test]
    fn rejects_a_line_that_never_ends() {
        let mut raw = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD_BYTES * 4));
        // No CRLF, ever. Must be bounded rather than buffered whole.
        assert!(matches!(parse(&raw), Err(Error::TooLarge)));
    }

    #[test]
    fn rejects_too_many_header_lines() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..=MAX_HEADER_LINES {
            raw.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        assert!(matches!(parse(&raw), Err(Error::TooLarge)));
    }

    #[test]
    fn rejects_a_head_with_no_blank_line() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    // -- Request line -------------------------------------------------------

    #[test]
    fn rejects_an_absolute_form_target() {
        // Routing a request somewhere other than where the front end intended.
        let raw = b"GET http://elsewhere/admin HTTP/1.1\r\n\r\n";
        assert!(matches!(parse(raw), Err(Error::Malformed(_))));
    }

    #[test]
    fn rejects_a_malformed_request_line() {
        for raw in [
            &b"GET\r\n\r\n"[..],
            &b"GET /\r\n\r\n"[..],
            &b"GET / HTTP/1.1 extra\r\n\r\n"[..],
            &b"GET / RTSP/1.0\r\n\r\n"[..],
            &b"G3T / HTTP/1.1\r\n\r\n"[..],
            &b" / HTTP/1.1\r\n\r\n"[..],
        ] {
            assert!(
                matches!(parse(raw), Err(Error::Malformed(_))),
                "accepted {:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    // -- Responses ----------------------------------------------------------

    #[test]
    fn writes_a_response_with_framing_and_close() {
        let mut out = Vec::new();
        Response::from_string("ok")
            .with_header("Content-Type", "text/plain")
            .write_to(&mut out, false)
            .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
             Content-Length: 2\r\nConnection: close\r\n\r\nok"
        );
    }

    #[test]
    fn head_gets_the_framing_but_not_the_body() {
        let mut out = Vec::new();
        Response::from_string("ok").write_to(&mut out, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "no body after the head: {text:?}");
    }

    #[test]
    fn omits_content_length_on_204() {
        let mut out = Vec::new();
        Response::empty(204).write_to(&mut out, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(!text.contains("Content-Length"));
    }

    #[test]
    #[should_panic(expected = "control byte")]
    fn refuses_to_build_a_split_response() {
        Response::empty(200).with_header("X-Thing", "a\r\nInjected: yes");
    }
}
