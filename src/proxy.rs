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
//!
//! Because we connect as root to a path the sandbox controls, the host-mode
//! lookup is descriptor-relative and symlink-refusing, and the peer's uid is
//! checked — see `open_sandbox_socket`.

use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path};
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
/// Returns (port, "/rest"). A bare "<port>" maps to "/".
///
/// The port is parsed here, in both modes, so nothing downstream ever
/// interpolates a request-supplied string into a filesystem path.
fn split_target(segments: &[&str]) -> Option<(u16, String)> {
    let (port, rest) = segments.split_first()?;
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    let path = if rest.is_empty() { "/".to_string() } else { format!("/{}", rest.join("/")) };
    Some((port, path))
}

/// Open the sandbox's socket for `port` without following symlinks anywhere.
///
/// The sandbox owns `<home>/.sbx/proxy` — it has to, so its own code can bind
/// sockets there — so every component of that path is attacker-controlled from
/// the server's point of view. Resolving it by name would let a sandbox point
/// this root-privileged `connect` at a sibling's socket, or at any privileged
/// socket visible on the host. So: walk down from the home descriptor with
/// `O_NOFOLLOW`, pin the final inode with `O_PATH`, check it really is a socket
/// owned by this sandbox, and connect through the pinned descriptor rather than
/// the name (which closes the swap-it-after-the-check race).
fn open_sandbox_socket(entry: &SandboxEntry, port: u16) -> io::Result<std::fs::File> {
    let root = crate::fsutil::ScopedRoot::open(Path::new(&entry.home), entry.uid)?;
    let mut dir = None;
    for component in Path::new(PROXY_SUBDIR).components() {
        let Component::Normal(name) = component else { continue };
        let parent = dir.as_ref().map(|d: &std::fs::File| d.as_raw_fd()).unwrap_or_else(|| root.dir_fd());
        dir = Some(crate::fsutil::open_dir_at(parent, name)?);
    }
    let dir = dir.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty proxy subdir"))?;

    let socket = crate::fsutil::open_path_at(dir.as_raw_fd(), OsStr::new(&format!("{port}.sock")))?;
    let metadata = socket.metadata()?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path is a symlink"));
    }
    if metadata.mode() & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a unix socket"));
    }
    if metadata.uid() != entry.uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket is not owned by this sandbox",
        ));
    }
    Ok(socket)
}

/// Confirm the process on the other end really is this sandbox.
///
/// Belt to the braces of [`open_sandbox_socket`]: even if a future change let a
/// name slip back into the lookup, a connection to anything not running as the
/// sandbox's uid is refused here.
fn check_peer_uid(stream: &UnixStream, expected_uid: u32) -> io::Result<()> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer runs as uid {}, expected the sandbox's uid {expected_uid}", cred.uid),
        ));
    }
    Ok(())
}

/// Connect to the in-sandbox backend for `port`. Host mode (sandbox given) →
/// unix socket `<home>/.sbx/proxy/<port>.sock`; dedicated → TCP `127.0.0.1:<port>`.
fn connect_backend(sandbox: Option<&Arc<SandboxEntry>>, port: u16) -> io::Result<Backend> {
    match sandbox {
        Some(entry) => {
            let socket = open_sandbox_socket(entry, port)?;
            // Connecting through /proc/self/fd lands on the inode we just
            // vetted; it does not re-walk the path, so the socket cannot be
            // swapped for a symlink between the check and the connect.
            let stream = UnixStream::connect(crate::fsutil::proc_fd_path(&socket))?;
            check_peer_uid(&stream, entry.uid)?;
            Ok(Backend::Unix(stream))
        }
        // Dedicated mode: the job *is* the sandbox, so there is no second tenant
        // to be confused about — a plain loopback connect is what we want.
        None => TcpStream::connect(("127.0.0.1", port)).map(Backend::Tcp),
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
        // Drop auth headers for this hop; everything else (Host, Upgrade,
        // Connection, Sec-WebSocket-*, Content-Length, ...) is forwarded verbatim.
        if matches!(name.as_str(), "x-sandbox-token" | "authorization") {
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
        return resp.error(404, "proxy target must be /proxy/<port>/<path>, with port in 1-65535");
    };

    let backend = match connect_backend(sandbox, port) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

    /// A sandbox home laid out like a real one, plus an `outside` directory
    /// standing in for anything else on the host.
    fn layout() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "sbx-proxy-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let home = base.join("home");
        let outside = base.join("outside");
        std::fs::create_dir_all(home.join(PROXY_SUBDIR)).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        (base, home, outside)
    }

    fn entry(home: &Path) -> SandboxEntry {
        SandboxEntry {
            id: "test".to_string(),
            uid: unsafe { libc::geteuid() },
            home: home.to_string_lossy().into_owned(),
            created_at_ms: 0,
            env: HashMap::new(),
            max_procs: 16,
            max_mem_mb: 16,
            token: "sandbox-capability-token".to_string(),
            confinement: crate::sandboxes::Confinement::UidOnly,
            last_activity_ms: AtomicI64::new(0),
            idle_timeout_ms: 0,
        }
    }

    #[test]
    fn port_must_be_a_number_in_range() {
        assert_eq!(split_target(&["8000"]), Some((8000, "/".to_string())));
        assert_eq!(split_target(&["8000", "ws"]), Some((8000, "/ws".to_string())));
        for bad in ["", "0", "65536", "-1", "abc", "..", "8000.sock", "08000\n"] {
            assert!(split_target(&[bad]).is_none(), "{bad:?} was accepted as a port");
        }
    }

    #[test]
    fn a_real_socket_owned_by_the_sandbox_is_accepted() {
        let (base, home, _) = layout();
        let _listener = UnixListener::bind(home.join(PROXY_SUBDIR).join("8000.sock")).unwrap();

        assert!(open_sandbox_socket(&entry(&home), 8000).is_ok());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_symlinked_socket_is_refused() {
        let (base, home, outside) = layout();
        // The sandbox's own code can write here, so it can plant this link.
        let _victim = UnixListener::bind(outside.join("victim.sock")).unwrap();
        std::os::unix::fs::symlink(outside.join("victim.sock"), home.join(PROXY_SUBDIR).join("8000.sock")).unwrap();

        assert!(open_sandbox_socket(&entry(&home), 8000).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_symlinked_proxy_directory_is_refused() {
        let (base, home, outside) = layout();
        let _victim = UnixListener::bind(outside.join("8000.sock")).unwrap();
        // Replace <home>/.sbx/proxy itself with a link to somewhere else.
        std::fs::remove_dir_all(home.join(PROXY_SUBDIR)).unwrap();
        std::os::unix::fs::symlink(&outside, home.join(PROXY_SUBDIR)).unwrap();

        assert!(open_sandbox_socket(&entry(&home), 8000).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_non_socket_is_refused() {
        let (base, home, _) = layout();
        std::fs::write(home.join(PROXY_SUBDIR).join("8000.sock"), b"not a socket").unwrap();

        assert!(open_sandbox_socket(&entry(&home), 8000).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn a_socket_owned_by_another_uid_is_refused() {
        let (base, home, _) = layout();
        let _listener = UnixListener::bind(home.join(PROXY_SUBDIR).join("8000.sock")).unwrap();
        // Claim the sandbox runs as a different uid than the socket's owner.
        let mut foreign = entry(&home);
        foreign.uid = foreign.uid.wrapping_add(1);

        assert!(open_sandbox_socket(&foreign, 8000).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn connecting_through_the_pinned_descriptor_reaches_the_backend() {
        let (base, home, _) = layout();
        let listener = UnixListener::bind(home.join(PROXY_SUBDIR).join("8000.sock")).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            stream.write_all(b"pong").unwrap();
            buf
        });

        let backend = connect_backend(Some(&Arc::new(entry(&home))), 8000).unwrap();
        let Backend::Unix(mut stream) = backend else { panic!("expected a unix backend") };
        stream.write_all(b"ping!").unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).unwrap();

        assert_eq!(&reply, b"pong");
        assert_eq!(&server.join().unwrap(), b"ping!");
        std::fs::remove_dir_all(base).unwrap();
    }
}
