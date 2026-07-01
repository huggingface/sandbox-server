//! Port proxy: expose a server running *inside* a sandbox through the one port
//! the HF Jobs proxy (FRP) forwards to this job.
//!
//! Why this exists
//! ---------------
//! FRP routes `https://<job_id>--<port>.hf.jobs` to a single pre-registered port
//! in the job (the sandbox server, 49983). In **host mode** that one job hosts
//! many sandboxes, and FRP can't address them individually — so the demux has to
//! happen here. On top of that, host-mode sandboxes are Landlock-confined and
//! **cannot bind a TCP port** (see `landlock.rs`); they can only create files in
//! their own home. So a sandbox that wants to expose a server binds a **unix
//! socket** in its home and we reach it from here (we run as root, outside any
//! sandbox's Landlock domain).
//!
//! Routes:
//!   ANY /v1/proxy/<port>/<path...>                 → dedicated: TCP 127.0.0.1:<port>
//!   ANY /v1/sandboxes/<id>/proxy/<port>/<path...>  → host: unix socket in the home
//!
//! The proxy is deliberately protocol-agnostic: it replays the request head to the
//! backend and then splices raw bytes in both directions for the life of the
//! connection. That makes WebSocket upgrades, SSE and plain HTTP all "just work" —
//! the inner server performs the actual handshake; we only move bytes.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::http::{Request, ResponseWriter};
use crate::sandboxes::SandboxEntry;

/// Conventional location, inside a sandbox home, where the sandbox binds its
/// per-port unix sockets. Exposed to sandbox processes as `$SBX_PROXY_DIR`.
pub const PROXY_SUBDIR: &str = ".sbx/proxy";

/// A backend connection to the in-sandbox server: a TCP socket (dedicated mode)
/// or a unix socket in the sandbox home (host mode).
enum Backend {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Backend {
    fn try_clone(&self) -> io::Result<Backend> {
        match self {
            Backend::Tcp(s) => s.try_clone().map(Backend::Tcp),
            Backend::Unix(s) => s.try_clone().map(Backend::Unix),
        }
    }

    fn shutdown(&self, how: Shutdown) {
        let _ = match self {
            Backend::Tcp(s) => s.shutdown(how),
            Backend::Unix(s) => s.shutdown(how),
        };
    }
}

impl Read for Backend {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Backend::Tcp(s) => s.read(buf),
            Backend::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Backend {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Backend::Tcp(s) => s.write(buf),
            Backend::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Backend::Tcp(s) => s.flush(),
            Backend::Unix(s) => s.flush(),
        }
    }
}

/// Split "<port>/<rest...>" out of the path tail after the `proxy` segment.
/// Returns (port_or_name, "/rest"). A bare "<port>" maps to "/".
fn split_target(segments: &[&str]) -> Option<(String, String)> {
    let (port, rest) = segments.split_first()?;
    if port.is_empty() {
        return None;
    }
    let path = if rest.is_empty() { "/".to_string() } else { format!("/{}", rest.join("/")) };
    Some((port.to_string(), path))
}

/// Connect to the in-sandbox backend for `port`. Host mode (sandbox given) →
/// unix socket `<home>/.sbx/proxy/<port>.sock`; dedicated → TCP `127.0.0.1:<port>`.
fn connect_backend(sandbox: Option<&Arc<SandboxEntry>>, port: &str) -> io::Result<Backend> {
    match sandbox {
        Some(entry) => {
            let sock = format!("{}/{PROXY_SUBDIR}/{port}.sock", entry.home);
            UnixStream::connect(&sock).map(Backend::Unix)
        }
        None => TcpStream::connect(("127.0.0.1", port.parse::<u16>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "proxy port must be a number in dedicated mode")
        })?))
        .map(Backend::Tcp),
    }
}

/// Build the request head to send to the backend: the request line (with the
/// `/v1/.../proxy/<port>` prefix stripped) plus the forwarded headers.
fn build_head(request: &Request, forward_path: &str) -> Vec<u8> {
    let mut head = Vec::with_capacity(256);
    let target = if request.raw_query.is_empty() {
        forward_path.to_string()
    } else {
        format!("{forward_path}?{}", request.raw_query)
    };
    head.extend_from_slice(format!("{} {} HTTP/1.1\r\n", request.method, target).as_bytes());
    for (name, value) in &request.headers {
        // Drop our own auth header (it's for this hop, not the inner server) and the
        // hop-by-hop keep-alive hint; everything else (Host, Upgrade, Connection,
        // Sec-WebSocket-*, Content-Length, ...) is forwarded verbatim.
        if name == "x-sandbox-token" {
            continue;
        }
        head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// Handle a proxy request: connect to the backend, replay the head, then splice.
pub fn handle_proxy(
    sandbox: Option<&Arc<SandboxEntry>>,
    segments: &[&str],
    request: &Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
) -> io::Result<()> {
    let Some((port, forward_path)) = split_target(segments) else {
        return resp.error(404, "proxy target must be /proxy/<port>/<path>");
    };

    let backend = match connect_backend(sandbox, &port) {
        Ok(b) => b,
        Err(e) => return resp.error(502, &format!("cannot reach port {port} in sandbox: {e}")),
    };

    // From here on we own the raw socket: no more ResponseWriter framing.
    let head = build_head(request, &forward_path);
    let mut backend_wr = backend.try_clone()?;
    let mut backend_rd = backend;
    let mut outer_rd = reader.get_ref().try_clone()?;
    let mut outer_wr = resp.hijack()?;

    // Anything BufReader prefetched past the request head is the start of the body /
    // first client frames — forward it before we start copying from the raw socket.
    let leftover = reader.buffer().to_vec();
    let leftover_len = leftover.len();
    backend_wr.write_all(&head)?;
    backend_wr.write_all(&leftover)?;
    backend_wr.flush()?;
    reader.consume(leftover_len);

    // client → backend (request body, then WebSocket/streamed frames)
    let pump = std::thread::spawn(move || {
        let _ = io::copy(&mut outer_rd, &mut backend_wr);
        // Client hung up: stop the backend from waiting on more input.
        backend_wr.shutdown(Shutdown::Write);
        let _ = outer_rd.shutdown(Shutdown::Read);
    });

    // backend → client (response head, then the response/frame stream)
    let _ = io::copy(&mut backend_rd, &mut outer_wr);
    // Backend closed: tear down the other direction so the pump thread unblocks.
    backend_rd.shutdown(Shutdown::Both);
    let _ = outer_wr.shutdown(Shutdown::Both);
    let _ = pump.join();
    Ok(())
}
