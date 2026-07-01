//! Minimal HTTP/1.1 server with explicit control over flushing (required for
//! live streaming of exec output through the HF Jobs proxy).
//!
//! Supported subset: request line + headers, Content-Length bodies (chunked
//! request bodies rejected with 411), keep-alive, fixed and chunked responses.

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;

const MAX_HEADER_BYTES: usize = 64 * 1024;

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
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
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

    let head = String::from_utf8_lossy(&head);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_uppercase();
    let url = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1");
    if method.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request line"));
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_length: u64 = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let keep_alive = match headers.get("connection").map(|s| s.to_ascii_lowercase()) {
        Some(c) if c.contains("close") => false,
        Some(c) if c.contains("keep-alive") => true,
        _ => version == "HTTP/1.1",
    };

    let (path, params, raw_query) = parse_url(&url);
    Ok(Some(Request {
        method,
        path,
        params,
        raw_query,
        headers,
        content_length,
        body_consumed: 0,
        keep_alive,
    }))
}

/// Reads the full request body (for JSON endpoints).
pub fn read_body(request: &mut Request, reader: &mut BufReader<TcpStream>, max: u64) -> io::Result<Vec<u8>> {
    if request.content_length > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }
    let mut body = vec![0u8; request.content_length as usize];
    reader.read_exact(&mut body)?;
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
    if remaining > 0 {
        io::copy(&mut reader.take(remaining), &mut io::sink())?;
        request.body_consumed = request.content_length;
    }
    Ok(())
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        500 => "Internal Server Error",
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
