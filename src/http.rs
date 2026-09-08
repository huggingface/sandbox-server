//! Minimal HTTP/1.1 server with explicit control over flushing (required for
//! live streaming of exec output through the HF Jobs proxy).
//!
//! Supported subset: request line + headers, Content-Length bodies (chunked
//! request bodies rejected with 411), keep-alive, fixed and chunked responses.

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Cap on the number of header lines, so a head can't be 64 KiB of one-byte headers.
const MAX_HEADERS: usize = 100;
/// A request head must arrive within this long, however slowly it trickles.
///
/// The socket read timeout alone is not enough: a client sending one byte every
/// few seconds never trips it, and each such connection holds an OS thread.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a body may take to arrive once the head has been read and authorized.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a write may block before we treat the peer as gone. Generous: a
/// legitimate client reading a large download slowly must not be cut off, but a
/// client that has read nothing for this long is not reading.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Beyond this, an unread body is not worth draining to keep the connection
/// reusable -- closing is cheaper than reading megabytes we already rejected.
const MAX_DRAIN_BYTES: u64 = 1024 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub params: HashMap<String, String>,
    /// Raw (un-decoded) query string, kept verbatim so the proxy can forward it as-is.
    pub raw_query: String,
    pub headers: HashMap<String, String>, // keys lowercased
    pub content_length: u64,
    body_consumed: u64,
    pub keep_alive: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }
}

/// Parse a truthy query parameter: "true"/"1" → true, "false"/"0" → false,
/// anything else (or absent) → `default`.
pub fn bool_param(params: &HashMap<String, String>, key: &str, default: bool) -> bool {
    match params.get(key).map(|v| v.as_str()) {
        Some("true" | "1") => true,
        Some("false" | "0") => false,
        _ => default,
    }
}

/// Reads the request head from `reader`. Returns Ok(None) on clean EOF (client
/// closed a keep-alive connection between requests).
pub fn read_request(reader: &mut BufReader<TcpStream>) -> io::Result<Option<Request>> {
    let deadline = Instant::now() + HEAD_TIMEOUT;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        // A per-read socket timeout does not bound a client that trickles one
        // byte just often enough; an absolute deadline does.
        if Instant::now() > deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out reading the request head"));
        }
        match reader.read(&mut byte) {
            Ok(0) => {
                if head.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in request head"));
            }
            Ok(_) => {
                head.push(byte[0]);
                if head.len() > MAX_HEADER_BYTES {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "request head too large"));
                }
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }
    parse_head(&head).map(Some)
}

/// Parse a complete request head, rejecting anything ambiguous.
///
/// The previous version was permissive in ways that matter once another proxy
/// sits in front: duplicate headers silently took the last value, an
/// unparseable `Content-Length` became zero (so the body was then read as the
/// next request on a keep-alive connection), and any spacing or version string
/// was accepted. Two parsers disagreeing about where a request ends is the
/// entire basis of request smuggling, so this one refuses rather than guesses.
fn parse_head(head: &[u8]) -> io::Result<Request> {
    fn bad(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message.to_string())
    }
    // A head is ASCII by definition. Refusing non-ASCII outright is simpler than
    // reasoning about what a lossy decode turned a byte into.
    if head.iter().any(|b| *b >= 0x80) {
        return Err(bad("non-ASCII byte in request head"));
    }
    let head = std::str::from_utf8(head).map_err(|_| bad("request head is not valid UTF-8"))?;
    let mut lines = head.trim_end_matches("\r\n\r\n").split("\r\n");

    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.split(' ').collect();
    let [method, url, version] = parts.as_slice() else {
        return Err(bad("request line must be exactly 'METHOD TARGET VERSION'"));
    };
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(bad("bad method"));
    }
    if !matches!(*version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(bad("unsupported HTTP version"));
    }
    let method = method.to_ascii_uppercase();

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut count = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(bad("too many headers"));
        }
        // Leading whitespace means an obsolete folded continuation line.
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(bad("obsolete line folding is not supported"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("header line without a colon"));
        };
        // A space before the colon is the classic name-smuggling trick.
        if name.is_empty() || name.ends_with(' ') || name.ends_with('\t') {
            return Err(bad("bad header name"));
        }
        if !name.bytes().all(is_token_byte) {
            return Err(bad("illegal character in header name"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_string();
        // Duplicates are only safe when they agree; when they don't, we and the
        // next parser in the chain may pick differently.
        if let Some(existing) = headers.get(&name) {
            if *existing != value {
                return Err(bad("conflicting duplicate header"));
            }
            continue;
        }
        headers.insert(name, value);
    }

    // Rejecting both together is the single most important framing rule: with
    // both present, two parsers can disagree about the body's length.
    if headers.contains_key("content-length") && headers.contains_key("transfer-encoding") {
        return Err(bad("Content-Length and Transfer-Encoding must not both be present"));
    }
    let content_length: u64 = match headers.get("content-length") {
        None => 0,
        Some(raw) => {
            // Only a plain decimal integer. Not "+1", not "0x10", not "1, 1",
            // and above all not "abc" silently meaning zero.
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad("malformed Content-Length"));
            }
            raw.parse().map_err(|_| bad("Content-Length out of range"))?
        }
    };

    let keep_alive = match headers.get("connection").map(|s| s.to_ascii_lowercase()) {
        Some(c) if c.contains("close") => false,
        Some(c) if c.contains("keep-alive") => true,
        _ => *version == "HTTP/1.1",
    };

    let (path, params, raw_query) = parse_url(url);
    Ok(Request {
        method,
        path,
        params,
        raw_query,
        headers,
        content_length,
        body_consumed: 0,
        keep_alive,
    })
}

/// RFC 9110 token characters, which is what a header name may contain.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Reads the full request body (for JSON endpoints).
pub fn read_body(request: &mut Request, reader: &mut BufReader<TcpStream>, max: u64) -> io::Result<Vec<u8>> {
    if request.content_length > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }
    // Grow as bytes arrive rather than allocating the advertised length up front:
    // otherwise a header claiming 16 MiB costs 16 MiB per connection before a
    // single byte of it shows up.
    let mut body = Vec::with_capacity(request.content_length.min(64 * 1024) as usize);
    let mut buf = [0u8; 64 * 1024];
    while (body.len() as u64) < request.content_length {
        let want = (request.content_length - body.len() as u64).min(buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in request body"));
        }
        body.extend_from_slice(&buf[..n]);
    }
    request.body_consumed = request.content_length;
    Ok(body)
}

/// Streams the request body in chunks to `f` (for file uploads).
pub fn stream_body(
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    mut f: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let mut remaining = request.content_length - request.body_consumed;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let max = buf.len().min(remaining as usize);
        let n = reader.read(&mut buf[..max])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in request body"));
        }
        f(&buf[..n])?;
        remaining -= n as u64;
        request.body_consumed += n as u64;
    }
    Ok(request.content_length)
}

/// Discards any unread request body (keeps the connection reusable).
pub fn drain_body(request: &mut Request, reader: &mut BufReader<TcpStream>) -> io::Result<()> {
    let remaining = request.content_length - request.body_consumed;
    if remaining == 0 {
        return Ok(());
    }
    // Draining exists to keep a keep-alive connection reusable. Past a point that
    // is no longer a bargain -- a rejected request should not buy the sender the
    // right to make us read megabytes -- so give up and let the caller close.
    if remaining > MAX_DRAIN_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "undrained body too large; closing"));
    }
    io::copy(&mut reader.take(remaining), &mut io::sink())?;
    request.body_consumed = request.content_length;
    Ok(())
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

pub struct ResponseWriter<'a> {
    writer: &'a mut BufWriter<TcpStream>,
    keep_alive: bool,
    pub started: bool,
    chunked: bool,
    /// Set when a handler has taken over the raw socket (e.g. the port proxy splices
    /// bytes directly). The connection loop must then stop driving this connection.
    pub hijacked: bool,
}

impl<'a> ResponseWriter<'a> {
    pub fn new(writer: &'a mut BufWriter<TcpStream>, keep_alive: bool) -> Self {
        Self { writer, keep_alive, started: false, chunked: false, hijacked: false }
    }

    /// Take over the raw connection: flush anything pending and hand back an owned
    /// clone of the underlying socket for direct (proxy) byte-splicing. After this
    /// the normal response/keep-alive machinery is bypassed (`hijacked` is set).
    pub fn hijack(&mut self) -> io::Result<TcpStream> {
        self.writer.flush()?;
        self.started = true;
        self.hijacked = true;
        self.writer.get_ref().try_clone()
    }

    fn write_head(&mut self, status: u16, content_type: &str, length: Option<u64>) -> io::Result<()> {
        self.started = true;
        let conn = if self.keep_alive { "keep-alive" } else { "close" };
        write!(
            self.writer,
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nConnection: {}\r\n",
            status,
            status_text(status),
            content_type,
            conn
        )?;
        match length {
            Some(n) => write!(self.writer, "Content-Length: {n}\r\n\r\n")?,
            None => {
                self.chunked = true;
                write!(self.writer, "Transfer-Encoding: chunked\r\nX-Accel-Buffering: no\r\n\r\n")?
            }
        }
        Ok(())
    }

    /// Fixed-size response, sent at once.
    pub fn fixed(&mut self, status: u16, content_type: &str, body: &[u8]) -> io::Result<()> {
        self.write_head(status, content_type, Some(body.len() as u64))?;
        self.writer.write_all(body)?;
        self.writer.flush()
    }

    pub fn json(&mut self, status: u16, body: &serde_json::Value) -> io::Result<()> {
        self.fixed(status, "application/json", &serde_json::to_vec(body).unwrap())
    }

    pub fn error(&mut self, status: u16, message: &str) -> io::Result<()> {
        self.json(status, &serde_json::json!({"error": message}))
    }

    /// Starts a chunked streaming response. Follow with `chunk()` calls and `finish()`.
    pub fn start_stream(&mut self, status: u16, content_type: &str) -> io::Result<()> {
        self.write_head(status, content_type, None)?;
        self.writer.flush()
    }

    /// Starts a fixed-length response to be written with `raw()` (file downloads).
    pub fn start_fixed(&mut self, status: u16, content_type: &str, length: u64) -> io::Result<()> {
        self.write_head(status, content_type, Some(length))
    }

    /// Writes raw bytes of a fixed-length body started with `start_fixed()`.
    pub fn raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Writes one chunk and flushes it immediately (this is the whole point).
    pub fn chunk(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        write!(self.writer, "{:x}\r\n", data.len())?;
        self.writer.write_all(data)?;
        self.writer.write_all(b"\r\n")?;
        self.writer.flush()
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.chunked {
            self.writer.write_all(b"0\r\n\r\n")?;
            self.writer.flush()?;
        }
        Ok(())
    }
}

/// Split "/v1/files/read?path=/x" into ("/v1/files/read", {"path": "/x"}, "path=/x").
fn parse_url(url: &str) -> (String, HashMap<String, String>, String) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        params.insert(urldecode(k), urldecode(v));
    }
    (path.to_string(), params, query.to_string())
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz");
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(head: &str) -> io::Result<Request> {
        parse_head(head.as_bytes())
    }

    fn head(extra: &str) -> String {
        format!("GET /v1/sandboxes HTTP/1.1\r\nHost: x\r\n{extra}\r\n\r\n")
    }

    #[test]
    fn a_well_formed_request_parses() {
        let request = parse(&head("X-Sandbox-Token: abc\r\nContent-Length: 3")).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/sandboxes");
        assert_eq!(request.content_length, 3);
        assert_eq!(request.header("x-sandbox-token"), Some("abc"));
        assert!(request.keep_alive);
    }

    /// Every one of these used to be accepted, most of them by guessing. Two
    /// parsers guessing differently about where a body ends is what request
    /// smuggling is, so the rule is refuse, never guess.
    #[test]
    fn ambiguous_framing_is_refused() {
        let cases = [
            ("Content-Length: abc", "non-numeric length"),
            ("Content-Length: ", "empty length"),
            ("Content-Length: -1", "negative length"),
            ("Content-Length: +1", "signed length"),
            ("Content-Length: 0x10", "hex length"),
            ("Content-Length: 1, 1", "list length"),
            ("Content-Length: 5\r\nContent-Length: 6", "conflicting duplicates"),
            ("Content-Length: 5\r\nTransfer-Encoding: chunked", "both framing headers"),
            ("Content-Length : 5", "space before the colon"),
            ("Content-Length\t: 5", "tab before the colon"),
            ("Content-Length", "no colon"),
            (" Content-Length: 5", "folded continuation"),
            ("Content-Le\u{0000}ngth: 5", "illegal name character"),
        ];
        for (extra, what) in cases {
            assert!(parse(&head(extra)).is_err(), "accepted {what}: {extra:?}");
        }
    }

    #[test]
    fn identical_duplicates_are_allowed() {
        // Harmless, and rejecting them would be stricter than any client expects.
        let request = parse(&head("Content-Length: 5\r\nContent-Length: 5")).unwrap();
        assert_eq!(request.content_length, 5);
    }

    #[test]
    fn a_malformed_request_line_is_refused() {
        for line in [
            "GET /x",                     // no version
            "GET  /x HTTP/1.1",           // double space
            "GET /x HTTP/1.1 extra",      // trailing junk
            "GET /x HTTP/2.0",            // unsupported version
            "GET /x ICY/1.0",             // not HTTP
            "G3T /x HTTP/1.1",            // non-alphabetic method
            " GET /x HTTP/1.1",           // leading space
            "/x HTTP/1.1",                // no method
        ] {
            assert!(parse(&format!("{line}\r\nHost: x\r\n\r\n")).is_err(), "accepted request line {line:?}");
        }
    }

    #[test]
    fn a_non_ascii_head_is_refused() {
        assert!(parse_head("GET /x HTTP/1.1\r\nX-Tag: caf\u{00e9}\r\n\r\n".as_bytes()).is_err());
    }

    #[test]
    fn too_many_headers_is_refused() {
        let many: String = (0..MAX_HEADERS + 1).map(|i| format!("X-H{i}: v\r\n")).collect();
        assert!(parse(&format!("GET /x HTTP/1.1\r\n{many}\r\n")).is_err());
    }

    #[test]
    fn keep_alive_follows_the_version_and_the_connection_header() {
        assert!(parse("GET /x HTTP/1.1\r\nHost: x\r\n\r\n").unwrap().keep_alive);
        assert!(!parse("GET /x HTTP/1.0\r\nHost: x\r\n\r\n").unwrap().keep_alive);
        assert!(!parse("GET /x HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap().keep_alive);
        assert!(parse("GET /x HTTP/1.0\r\nConnection: keep-alive\r\n\r\n").unwrap().keep_alive);
    }

    #[test]
    fn the_method_is_normalized_but_the_target_is_not() {
        let request = parse("get /V1/Files/Read?path=/A HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/V1/Files/Read");
        assert_eq!(request.params.get("path").map(String::as_str), Some("/A"));
    }
}
