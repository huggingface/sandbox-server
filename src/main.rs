mod exec;
mod files;
mod fsutil;
mod http;
mod landlock;
mod proxy;
mod sandboxes;

use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{Request, ResponseWriter};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// Parse `value[key]` (a JSON object of string→string) into a map. Non-string
/// values become empty strings; a missing or non-object key yields an empty map.
pub fn json_string_map(value: &serde_json::Value, key: &str) -> HashMap<String, String> {
    value
        .get(key)
        .and_then(|v| v.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect())
        .unwrap_or_default()
}

/// Whether a token is required, and which one.
///
/// Deliberately an enum rather than an `Option<String>`: "no token configured"
/// used to mean "authorize everything", which is the kind of default that turns a
/// bootstrap slip into an unauthenticated root control plane. Every use site now
/// has to name the no-auth case.
pub enum Auth {
    /// A matching `X-Sandbox-Token` is required on every route except `/health`.
    Required(String),
    /// Local development only. Not reachable from a Job: it is enabled by an argv
    /// flag, and the client controls the argv (the job's env does not).
    DisabledForDevelopment,
}

impl Auth {
    /// Whether the credential a request presented is acceptable.
    fn accepts(&self, provided: Option<&str>) -> bool {
        match self {
            Auth::Required(expected) => provided.map(|token| ct_eq(token, expected)).unwrap_or(false),
            Auth::DisabledForDevelopment => true,
        }
    }
}

pub struct State {
    pub auth: Auth,
    pub started_at_ms: i64,
    pub last_activity_ms: AtomicI64,
    pub procs: exec::ProcRegistry,
    pub sandboxes: sandboxes::SandboxRegistry,
    /// Host mode (this job multiplexes many sandboxes) vs dedicated (the job IS the
    /// sandbox). Picks the idle policy: per-sandbox eviction + empty-host shutdown, vs
    /// the whole-job activity watchdog.
    pub host_mode: bool,
    /// Whether the host management token is still accepted on per-sandbox routes
    /// (see [`authorize`]). Transitional; `SBX_COMPAT_HOST_TOKEN=0` turns it off.
    pub compat_host_token: bool,
}

/// Constant-time string comparison.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether a request presents the server's own credential.
///
/// Used only by `/health`, which is not a scoped route: it decides how much
/// detail to include, not what may be addressed.
fn authorized(state: &State, request: &Request) -> bool {
    state.auth.accepts(request.header("x-sandbox-token"))
}

/// What a presented credential is allowed to address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The host management token (`SBX_TOKEN`), or the dedicated-mode token.
    Host,
    /// A capability token bound to exactly one pooled sandbox.
    Sandbox,
}

/// Authorize a request and decide what it may address.
///
/// Dedicated mode has one credential and one sandbox, so there is nothing to
/// scope. Host mode has two kinds:
///
/// - pool lifecycle (`/v1/sandboxes`, and token recovery) is management, so it
///   needs the host token;
/// - a scoped route accepts that sandbox's own capability token.
///
/// The host token is *also* accepted on scoped routes for now, so that clients
/// which predate per-sandbox tokens keep working when this binary is published
/// under them (every job fetches the binary fresh, so a hard break would break
/// every old client at once). That is a management credential legitimately
/// having authority over the sandboxes it created — not a sandbox credential
/// reaching a sibling, which is what this change closes. Set
/// `SBX_COMPAT_HOST_TOKEN=0` to refuse it and require scoped tokens today.
/// Which credential a host-mode route requires.
enum RouteAuth<'a> {
    /// Pool lifecycle and token recovery: the host management token.
    Management,
    /// Scoped to one sandbox: that sandbox's capability token.
    Sandbox(&'a str),
    /// Not a host-mode route.
    Unknown,
}

fn host_route_auth<'a>(segments: &[&'a str]) -> RouteAuth<'a> {
    match segments {
        ["v1", "sandboxes"] | ["v1", "sandboxes", _, "token"] => RouteAuth::Management,
        ["v1", "sandboxes", id, ..] => RouteAuth::Sandbox(id),
        _ => RouteAuth::Unknown,
    }
}

/// Decide what a credential presented on a scoped route may address.
fn classify_scoped_token(provided: &str, sandbox_token: &str, host: &Auth, compat: bool) -> Option<Scope> {
    if ct_eq(provided, sandbox_token) {
        return Some(Scope::Sandbox);
    }
    if compat && host.accepts(Some(provided)) {
        return Some(Scope::Host);
    }
    None
}

fn authorize(state: &State, provided: Option<&str>, segments: &[&str]) -> Option<Scope> {
    if !state.host_mode {
        return state.auth.accepts(provided).then_some(Scope::Host);
    }
    match host_route_auth(segments) {
        RouteAuth::Management => state.auth.accepts(provided).then_some(Scope::Host),
        RouteAuth::Sandbox(id) => {
            let entry = state.sandboxes.get(id)?;
            classify_scoped_token(provided?, &entry.token, &state.auth, state.compat_host_token)
        }
        // Not a host-mode route. Whether it *exists* is the route gate's
        // question, not authorization's: check the host credential so a valid
        // caller gets an accurate 404 while an invalid one still gets 403.
        RouteAuth::Unknown => state.auth.accepts(provided).then_some(Scope::Host),
    }
}

/// Whether a route exists in this server mode.
///
/// The two surfaces are mutually exclusive. The dedicated routes (`/v1/exec`,
/// `/v1/files/*`, `/v1/processes`, `/v1/proxy`) operate without a `SandboxEntry`,
/// so they run with the server's own privileges — as root, unconfined, in the
/// host's environment. In host mode that is a root shell for anyone holding the
/// host token, which is not the capability a pooled sandbox is supposed to
/// confer. Conversely `/v1/sandboxes*` has no meaning when the job *is* the
/// sandbox. `/health` is handled before this check and stays available in both.
fn route_mode_allowed(host_mode: bool, segments: &[&str]) -> bool {
    let host_scoped = matches!(segments, ["v1", "sandboxes", ..]);
    host_mode == host_scoped
}

fn route(
    state: &Arc<State>,
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
) -> std::io::Result<()> {
    let path = request.path.clone();
    let method = request.method.clone();

    if method == "GET" && path == "/health" {
        // Liveness has to stay reachable without a credential: the client polls
        // it while a job boots, before it is confident about anything. But the
        // *detail* used to come with it, so a read-only namespace member who
        // reached the proxy learned the exact server version -- i.e. which known
        // issues this host has not been patched for -- plus its uptime and how
        // many sandboxes it is packing.
        if !authorized(state, request) {
            return resp.json(200, &serde_json::json!({"status": "ok"}));
        }
        return resp.json(
            200,
            &serde_json::json!({
                "status": "ok",
                "version": VERSION,
                "uptime_ms": now_ms() - state.started_at_ms,
                "sandboxes": state.sandboxes.count(),
                "mode": if state.host_mode { "host" } else { "dedicated" },
                // Whether authentication is actually being enforced. A server
                // running with it disabled should be able to say so to a client
                // that cares, rather than looking identical to one that is not.
                "auth": if matches!(state.auth, Auth::Required(_)) { "required" } else { "disabled" },
                // So a client can refuse to run untrusted work on a host whose
                // confinement is weaker than it expects, instead of finding out
                // by not finding out.
                "landlock": {
                    "abi": landlock::abi(),
                    "features": landlock::features(landlock::abi()),
                },
            }),
        );
    }

    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    // Authentication first, so an unauthenticated caller learns nothing about
    // which routes this server serves.
    if authorize(state, request.header("x-sandbox-token"), &segments).is_none() {
        return resp.error(403, "invalid or missing X-Sandbox-Token");
    }
    if request.header("transfer-encoding").is_some() {
        return resp.error(411, "chunked request bodies not supported; send Content-Length");
    }
    state.last_activity_ms.store(now_ms(), Ordering::Relaxed);

    if !route_mode_allowed(state.host_mode, &segments) {
        return resp.error(404, &format!("no route in this server mode: {method} {path}"));
    }
    // Per-sandbox activity (host-mode idle eviction): any request scoped to a sandbox
    // resets its idle timer.
    if let ["v1", "sandboxes", id, ..] = segments.as_slice() {
        state.sandboxes.touch(id);
    }
    match (method.as_str(), segments.as_slice()) {
        // ---- dedicated mode: operate directly on the job (one job == one sandbox) ----
        ("POST", ["v1", "exec"]) => exec::handle_exec(state, request, reader, resp, None),
        ("POST", ["v1", "processes"]) => exec::handle_process_start(state, request, reader, resp, None),
        ("GET", ["v1", "processes"]) => resp.json(200, &state.procs.list_processes(None)),
        ("DELETE", ["v1", "processes", id]) => exec::handle_process_delete(state, id, None, resp),
        ("GET", ["v1", "files", "read"]) => files::handle_read(request, resp, None),
        ("PUT", ["v1", "files", "write"]) => files::handle_write(request, reader, resp, None),
        ("GET", ["v1", "files", "list"]) => files::handle_list(request, resp, None),
        ("GET", ["v1", "files", "stat"]) => files::handle_stat(request, resp, None),
        ("DELETE", ["v1", "files", "delete"]) => files::handle_delete(request, resp, None),
        ("POST", ["v1", "files", "mkdir"]) => files::handle_mkdir(request, resp, None),

        // ---- host mode: many lightweight sandboxes inside this job ----
        ("POST", ["v1", "sandboxes"]) => sandboxes::handle_create(state, request, reader, resp),
        ("GET", ["v1", "sandboxes"]) => resp.json(200, &state.sandboxes.list()),
        ("DELETE", ["v1", "sandboxes"]) => sandboxes::handle_delete_all(state, resp),
        // Recover a sandbox's capability token with the host token, so a client
        // that reconnects to an existing sandbox does not need local state.
        ("GET", ["v1", "sandboxes", id, "token"]) => match state.sandboxes.get(id) {
            Some(entry) => resp.json(200, &serde_json::json!({"id": entry.id, "token": entry.token})),
            None => resp.error(404, &format!("no such sandbox: {id}")),
        },
        ("DELETE", ["v1", "sandboxes", id]) => {
            let id = id.to_string();
            sandboxes::handle_delete(state, &id, resp)
        }
        // Per-sandbox operations mirror the dedicated routes, scoped to one sandbox
        // (its uid, its home, its processes). The client uses the same surface for
        // both modes, only the URL prefix differs.
        ("POST", ["v1", "sandboxes", id, "exec"]) => match state.sandboxes.get(id) {
            Some(entry) => exec::handle_exec(state, request, reader, resp, Some(entry)),
            None => resp.error(404, &format!("no such sandbox: {id}")),
        },
        ("POST", ["v1", "sandboxes", id, "processes"]) => match state.sandboxes.get(id) {
            Some(entry) => exec::handle_process_start(state, request, reader, resp, Some(entry)),
            None => resp.error(404, &format!("no such sandbox: {id}")),
        },
        ("GET", ["v1", "sandboxes", id, "processes"]) => resp.json(200, &state.procs.list_processes(Some(id))),
        ("DELETE", ["v1", "sandboxes", id, "processes", proc_id]) => {
            exec::handle_process_delete(state, proc_id, Some(id), resp)
        }
        ("GET", ["v1", "sandboxes", id, "files", "read"]) => with_sandbox(state, id, resp, |e, r| files::handle_read(request, r, Some(&e))),
        ("PUT", ["v1", "sandboxes", id, "files", "write"]) => with_sandbox(state, id, resp, |e, r| files::handle_write(request, reader, r, Some(&e))),
        ("GET", ["v1", "sandboxes", id, "files", "list"]) => with_sandbox(state, id, resp, |e, r| files::handle_list(request, r, Some(&e))),
        ("GET", ["v1", "sandboxes", id, "files", "stat"]) => with_sandbox(state, id, resp, |e, r| files::handle_stat(request, r, Some(&e))),
        ("DELETE", ["v1", "sandboxes", id, "files", "delete"]) => with_sandbox(state, id, resp, |e, r| files::handle_delete(request, r, Some(&e))),
        ("POST", ["v1", "sandboxes", id, "files", "mkdir"]) => with_sandbox(state, id, resp, |e, r| files::handle_mkdir(request, r, Some(&e))),

        // ---- port proxy: reach a server running inside the sandbox (any method, WS/SSE/HTTP) ----
        // Dedicated: forward to TCP 127.0.0.1:<port> in the job.
        (_, ["v1", "proxy", rest @ ..]) => proxy::handle_proxy(None, rest, request, reader, resp),
        // Host mode: forward to the sandbox's unix socket (it can't bind TCP under Landlock).
        (_, ["v1", "sandboxes", id, "proxy", rest @ ..]) => match state.sandboxes.get(id) {
            Some(entry) => proxy::handle_proxy(Some(&entry), rest, request, reader, resp),
            None => resp.error(404, &format!("no such sandbox: {id}")),
        },

        _ => resp.error(404, &format!("no route: {method} {path}")),
    }
}

/// Look up a sandbox and run `f` with its entry, or reply 404 if it doesn't exist.
fn with_sandbox(
    state: &Arc<State>,
    id: &str,
    resp: &mut ResponseWriter,
    f: impl FnOnce(Arc<sandboxes::SandboxEntry>, &mut ResponseWriter) -> std::io::Result<()>,
) -> std::io::Result<()> {
    match state.sandboxes.get(id) {
        Some(entry) => f(entry, resp),
        None => resp.error(404, &format!("no such sandbox: {id}")),
    }
}

/// Live connections, so a flood of them cannot exhaust the thread pool.
///
/// A worker is spawned per connection because a handler can block for the life
/// of a stream (an `/exec` may run for hours, a WebSocket tunnel for days), so a
/// fixed pool would deadlock rather than queue. Bounding the count is the part
/// that was missing: threads used to be spawned before a single byte was read or
/// authenticated, so a slow-request flood cost nothing to mount.
struct ConnectionSlot;

static LIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

impl ConnectionSlot {
    fn acquire(max: usize) -> Option<Self> {
        if LIVE_CONNECTIONS.fetch_add(1, Ordering::AcqRel) >= max {
            LIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(ConnectionSlot)
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        LIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_connection(state: Arc<State>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    // Deadlines are strict before the request is understood and generous after:
    // an unauthenticated caller must not be able to hold a thread indefinitely,
    // while a legitimate slow download must not be cut off.
    let _ = stream.set_read_timeout(Some(http::HEAD_TIMEOUT));
    let _ = stream.set_write_timeout(Some(http::WRITE_TIMEOUT));
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(stream);

    loop {
        // Back to the head deadline for each request on a keep-alive connection.
        let _ = writer.get_ref().set_read_timeout(Some(http::HEAD_TIMEOUT));
        let mut request = match http::read_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => {
                // Say why, then close. Silently dropping the connection leaves a
                // client unable to tell a rejected request from a crashed server.
                let status = match e.kind() {
                    std::io::ErrorKind::InvalidData => 400,
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => 408,
                    _ => 0, // EOF or a broken socket: nothing useful to send
                };
                if status != 0 {
                    let mut resp = ResponseWriter::new(&mut writer, false);
                    let _ = resp.error(status, &e.to_string());
                }
                break;
            }
        };
        let _ = writer.get_ref().set_read_timeout(Some(http::BODY_TIMEOUT));
        let keep_alive = request.keep_alive;
        let mut resp = ResponseWriter::new(&mut writer, keep_alive);
        let result = route(&state, &mut request, &mut reader, &mut resp);
        // A hijacked connection (port proxy) owns the socket now — its bytes have been
        // spliced directly and the request framing no longer applies, so stop here.
        if resp.hijacked {
            break;
        }
        let finished = result.and_then(|_| resp.finish());
        if finished.is_err() || http::drain_body(&mut request, &mut reader).is_err() || !keep_alive {
            break;
        }
    }
}

/// Read a numeric env var, refusing to start if it is set but unparseable.
///
/// These used to fall back to a default on a parse failure, which for
/// `SBX_CAPACITY` meant an unlimited host: a typo silently removed the packing
/// bound. A misconfigured server should not start, so the mistake is visible at
/// deploy time rather than as an over-packed host later.
fn env_number<T: std::str::FromStr>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Err(_) => default,
        Ok(raw) => match raw.parse() {
            Ok(value) => value,
            Err(_) => {
                eprintln!("sbx-server: {name}={raw:?} is not a valid number");
                std::process::exit(1);
            }
        },
    }
}

fn main() {
    let port: u16 = env_number("SBX_PORT", 8000);
    let token = std::env::var("SBX_TOKEN").ok().filter(|t| !t.is_empty());
    // Don't leak the token to child processes.
    std::env::remove_var("SBX_TOKEN");
    // Fail closed: without a token every route would be reachable by anyone who
    // can pass the Jobs proxy. The escape hatch is an argv flag rather than an
    // env var precisely so a Job's user-supplied `env` can never set it.
    let auth = match token {
        Some(token) => Auth::Required(token),
        None if std::env::args().skip(1).any(|arg| arg == "--allow-no-auth") => {
            eprintln!("sbx-server: WARNING running with authentication DISABLED (--allow-no-auth)");
            Auth::DisabledForDevelopment
        }
        None => {
            eprintln!(
                "sbx-server: SBX_TOKEN is required. Pass --allow-no-auth to run without \
                 authentication (local development only)."
            );
            std::process::exit(1);
        }
    };
    let idle_timeout_secs: Option<u64> = match std::env::var("SBX_IDLE_TIMEOUT") {
        Err(_) => None,
        Ok(_) => Some(env_number("SBX_IDLE_TIMEOUT", 0u64)),
    };
    // Host-mode packing density: max concurrent sandboxes on this host. Bounded
    // by default -- an unlimited host was only ever the *absence* of a setting,
    // not a considered choice, and the client always sets this explicitly.
    let capacity: usize = env_number("SBX_CAPACITY", 64);
    if capacity == 0 {
        eprintln!("sbx-server: SBX_CAPACITY must be at least 1");
        std::process::exit(1);
    }
    // Host mode multiplexes many sandboxes; dedicated mode is one sandbox == the job.
    let host_mode = std::env::var("SBX_HOST_MODE").map(|v| v == "1").unwrap_or(false);
    // Concurrent connections. Generous enough for the client's parallel file
    // transfers (16 workers) times many sandboxes, small enough that a flood
    // cannot exhaust the thread stack space.
    let max_connections: usize = env_number("SBX_MAX_CONNECTIONS", 512);
    if max_connections == 0 {
        eprintln!("sbx-server: SBX_MAX_CONNECTIONS must be at least 1");
        std::process::exit(1);
    }
    // Transitional: accept the host token on per-sandbox routes for clients that
    // predate per-sandbox tokens. Set to 0 to require scoped tokens.
    let compat_host_token = std::env::var("SBX_COMPAT_HOST_TOKEN").map(|v| v != "0").unwrap_or(true);
    // Like --allow-no-auth, an argv flag rather than an env var: a Job's
    // user-supplied env must not be able to turn off a sandbox's confinement.
    let allow_unconfined = std::env::args().skip(1).any(|arg| arg == "--allow-unconfined");
    // The isolation model documents two guarantees that need a recent ABI (no
    // TCP bind: 4; scoped abstract unix sockets: 6). Refuse to run host mode on
    // a kernel that cannot deliver them, rather than silently dropping them.
    let min_abi: i32 = env_number("SBX_MIN_LANDLOCK_ABI", landlock::FULL_ABI);

    // Orphaned grandchildren re-parent to us (we are typically PID 1 in the
    // container) and would otherwise pile up as zombies for the job's lifetime.
    exec::spawn_orphan_reaper();

    let state = Arc::new(State {
        auth,
        started_at_ms: now_ms(),
        last_activity_ms: AtomicI64::new(now_ms()),
        procs: exec::ProcRegistry::default(),
        sandboxes: sandboxes::SandboxRegistry::new(capacity, allow_unconfined),
        host_mode,
        compat_host_token,
    });

    // Idle watchdog: stop billing for an abandoned sandbox/host before the job timeout.
    if let Some(idle) = idle_timeout_secs {
        let state = Arc::clone(&state);
        let idle_ms = (idle * 1000) as i64;
        std::thread::spawn(move || {
            // Host mode: empty-host timer starts at boot, so a warmed-but-never-used pool
            // host is reclaimed too.
            let mut empty_since = now_ms();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let now = now_ms();
                if state.host_mode {
                    // 1. Evict sandboxes idle past their own timeout (unless still running work).
                    for id in state.sandboxes.idle_candidates(now) {
                        if state.procs.running_count_for(&id) == 0 && state.procs.active_ops() == 0 {
                            let outcome = state.sandboxes.delete(&id);
                            state.procs.remove_for_sandbox(&id);
                            match outcome {
                                Some(Err(message)) => eprintln!("sbx-server: evicting {id}: {message}"),
                                _ => eprintln!("sbx-server: evicted idle sandbox {id}"),
                            }
                        }
                    }
                    // 2. Shut the host down once it's been empty for the host idle timeout.
                    if state.sandboxes.count() != 0 {
                        empty_since = now;
                    } else if now - empty_since > idle_ms {
                        eprintln!("sbx-server: host empty for {}ms, shutting down", now - empty_since);
                        std::process::exit(0);
                    }
                } else {
                    // Dedicated: the whole job is the sandbox — stop when quiet and idle.
                    // `active_ops` covers foreground commands, which are not in the
                    // process registry and used to make a running job look idle.
                    let quiet_ms = now - state.last_activity_ms.load(Ordering::Relaxed);
                    let busy = state.procs.running_count() + state.procs.active_ops();
                    if quiet_ms > idle_ms && busy == 0 {
                        eprintln!("sbx-server: idle for {quiet_ms}ms, shutting down");
                        std::process::exit(0);
                    }
                }
            }
        });
    }

    let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("sbx-server: failed to bind port {port}: {e}");
        std::process::exit(1);
    });
    let landlock_ok = landlock::available();
    let abi = landlock::abi();
    // Host mode is the only mode that relies on Landlock as a boundary between
    // tenants; dedicated mode's boundary is the VM.
    if host_mode && abi < min_abi && !allow_unconfined {
        eprintln!(
            "sbx-server: landlock ABI {abi} on this kernel, but {min_abi} is required for the \
             documented isolation guarantees (have: {}). Lower SBX_MIN_LANDLOCK_ABI to accept \
             a reduced set, or pass --allow-unconfined to run without confinement.",
            landlock::features(abi).join(",")
        );
        std::process::exit(1);
    }
    // Mode and auth state on the first line: a server that silently serves the
    // wrong surface, or no authentication at all, is the hazard worth seeing.
    eprintln!(
        "sbx-server {VERSION} listening on 0.0.0.0:{port} (mode: {}, auth: {}, landlock: {}{})",
        if host_mode { "host" } else { "dedicated" },
        if matches!(state.auth, Auth::Required(_)) { "required" } else { "DISABLED" },
        if landlock_ok {
            format!("abi {abi} [{}]", landlock::features(abi).join(","))
        } else {
            "UNAVAILABLE".to_string()
        },
        if host_mode && compat_host_token { ", host-token compat: on" } else { "" }
    );
    // Host mode reuses one set of system-dir fds across every sandbox ruleset.
    // Open them now so the cost (and any missing-dir surface) lands at startup
    // rather than on the first sandbox create.
    if host_mode && landlock_ok {
        eprintln!("sbx-server: pinned {} system dirs for landlock", landlock::system_dir_rules().len());
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let Some(slot) = ConnectionSlot::acquire(max_connections) else {
            // Answer rather than dropping silently, so a client that hit the cap
            // can tell it apart from a crash — but do it inline, without a worker.
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
            let mut writer = BufWriter::new(stream);
            let _ = write!(
                writer,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = writer.flush();
            continue;
        };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _slot = slot; // released when this connection ends
            handle_connection(state, stream);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segments(path: &str) -> Vec<&str> {
        path.trim_matches('/').split('/').collect()
    }

    /// The whole point of the mode gate: a route that runs with the server's own
    /// root privileges must not exist in the mode that multiplexes tenants, and
    /// vice versa. Table-driven so a future refactor cannot quietly re-register
    /// one surface in the other mode.
    #[test]
    fn route_surfaces_are_mutually_exclusive() {
        let dedicated_only = [
            "/v1/exec",
            "/v1/processes",
            "/v1/processes/p-1",
            "/v1/files/read",
            "/v1/files/write",
            "/v1/files/list",
            "/v1/files/stat",
            "/v1/files/delete",
            "/v1/files/mkdir",
            "/v1/proxy/8000",
            "/v1/proxy/8000/ws",
        ];
        let host_only = [
            "/v1/sandboxes",
            "/v1/sandboxes/abc",
            "/v1/sandboxes/abc/exec",
            "/v1/sandboxes/abc/processes",
            "/v1/sandboxes/abc/processes/p-1",
            "/v1/sandboxes/abc/files/read",
            "/v1/sandboxes/abc/files/write",
            "/v1/sandboxes/abc/proxy/8000",
            "/v1/sandboxes/abc/proxy/8000/ws",
        ];

        for path in dedicated_only {
            assert!(route_mode_allowed(false, &segments(path)), "{path} should exist in dedicated mode");
            assert!(!route_mode_allowed(true, &segments(path)), "{path} must NOT exist in host mode");
        }
        for path in host_only {
            assert!(route_mode_allowed(true, &segments(path)), "{path} should exist in host mode");
            assert!(!route_mode_allowed(false, &segments(path)), "{path} must NOT exist in dedicated mode");
        }
    }

    #[test]
    fn a_required_token_must_match_exactly() {
        let auth = Auth::Required("s3cret".to_string());
        assert!(auth.accepts(Some("s3cret")));
        assert!(!auth.accepts(None), "a missing token must be refused");
        assert!(!auth.accepts(Some("")), "an empty token must be refused");
        assert!(!auth.accepts(Some("s3cre")), "a prefix must be refused");
        assert!(!auth.accepts(Some("s3crets")), "a superstring must be refused");
        assert!(!auth.accepts(Some("S3CRET")), "the compare must be case-sensitive");
    }

    /// The historical bug: no configured token meant "authorize everything".
    /// That state is now unrepresentable unless it is named explicitly.
    #[test]
    fn disabled_auth_has_to_be_asked_for_by_name() {
        assert!(Auth::DisabledForDevelopment.accepts(None));
        // An empty SBX_TOKEN is filtered out at startup, so it can never become
        // `Required("")` and accept an empty header.
        assert!(!Auth::Required(String::new()).accepts(None));
    }

    #[test]
    fn constant_time_compare_agrees_with_equality() {
        for (a, b) in [("", ""), ("a", "a"), ("a", "b"), ("ab", "a"), ("a", "ab"), ("token", "token")] {
            assert_eq!(ct_eq(a, b), a == b, "ct_eq({a:?}, {b:?})");
        }
    }

    /// Only the sandbox's own capability token addresses it. A sibling's token
    /// is refused even though it is a perfectly valid credential elsewhere --
    /// this is the property the change exists for.
    #[test]
    fn a_sandbox_token_addresses_only_its_own_sandbox() {
        let host = Auth::Required("host-management-token".to_string());
        let mine = "sandbox-a-token";
        let theirs = "sandbox-b-token";

        assert_eq!(classify_scoped_token(mine, mine, &host, false), Some(Scope::Sandbox));
        assert_eq!(classify_scoped_token(theirs, mine, &host, false), None, "a sibling's token must not work");
        assert_eq!(classify_scoped_token("", mine, &host, false), None);
        assert_eq!(classify_scoped_token("sandbox-a-toke", mine, &host, false), None, "a prefix must not work");
    }

    #[test]
    fn the_host_token_on_a_scoped_route_depends_on_the_compat_window() {
        let host = Auth::Required("host-management-token".to_string());
        let sandbox = "sandbox-a-token";

        // Transitional: a management credential may address its sandboxes.
        assert_eq!(
            classify_scoped_token("host-management-token", sandbox, &host, true),
            Some(Scope::Host)
        );
        // With the window closed, scoped routes require scoped tokens.
        assert_eq!(classify_scoped_token("host-management-token", sandbox, &host, false), None);
        // Either way it is still recognised as the host credential, never as the sandbox's.
        assert_ne!(
            classify_scoped_token("host-management-token", sandbox, &host, true),
            Some(Scope::Sandbox)
        );
    }

    #[test]
    fn pool_lifecycle_and_token_recovery_are_management_routes() {
        let management = ["/v1/sandboxes"];
        for path in management {
            assert!(
                matches!(host_route_auth(&segments(path)), RouteAuth::Management),
                "{path} must require the host token"
            );
        }
        assert!(matches!(host_route_auth(&segments("/v1/sandboxes/abc/token")), RouteAuth::Management));

        // Everything else scoped under a sandbox id belongs to that sandbox.
        for path in [
            "/v1/sandboxes/abc",
            "/v1/sandboxes/abc/exec",
            "/v1/sandboxes/abc/processes",
            "/v1/sandboxes/abc/files/read",
            "/v1/sandboxes/abc/proxy/8000/ws",
        ] {
            match host_route_auth(&segments(path)) {
                RouteAuth::Sandbox(id) => assert_eq!(id, "abc", "{path}"),
                _ => panic!("{path} should be scoped to a sandbox"),
            }
        }
    }

    /// Token recovery must be management-gated: if a sandbox's own token could
    /// read `/v1/sandboxes/<other>/token`, the whole scoping would be moot.
    #[test]
    fn token_recovery_is_not_reachable_with_a_sandbox_token() {
        assert!(matches!(host_route_auth(&segments("/v1/sandboxes/victim/token")), RouteAuth::Management));
    }
}
