mod exec;
mod files;
mod fsutil;
mod http;
mod landlock;
mod proxy;
mod sandboxes;

use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, Ordering};
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
}

/// Constant-time string comparison.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorized(state: &State, request: &Request) -> bool {
    state.auth.accepts(request.header("x-sandbox-token"))
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
        return resp.json(
            200,
            &serde_json::json!({
                "status": "ok",
                "version": VERSION,
                "uptime_ms": now_ms() - state.started_at_ms,
                "sandboxes": state.sandboxes.count(),
            }),
        );
    }

    // Authentication first, so an unauthenticated caller learns nothing about
    // which routes this server serves.
    if !authorized(state, request) {
        return resp.error(403, "invalid or missing X-Sandbox-Token");
    }
    if request.header("transfer-encoding").is_some() {
        return resp.error(411, "chunked request bodies not supported; send Content-Length");
    }
    state.last_activity_ms.store(now_ms(), Ordering::Relaxed);

    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
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

fn handle_connection(state: Arc<State>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let Ok(read_half) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(stream);

    loop {
        let mut request = match http::read_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) | Err(_) => break,
        };
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

fn main() {
    let port: u16 = std::env::var("SBX_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8000);
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
    let idle_timeout_secs: Option<u64> = std::env::var("SBX_IDLE_TIMEOUT").ok().and_then(|v| v.parse().ok());
    // Host-mode packing density: max concurrent sandboxes on this host (default: unlimited).
    let capacity = std::env::var("SBX_CAPACITY").ok().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    // Host mode multiplexes many sandboxes; dedicated mode is one sandbox == the job.
    let host_mode = std::env::var("SBX_HOST_MODE").map(|v| v == "1").unwrap_or(false);

    let state = Arc::new(State {
        auth,
        started_at_ms: now_ms(),
        last_activity_ms: AtomicI64::new(now_ms()),
        procs: exec::ProcRegistry::default(),
        sandboxes: sandboxes::SandboxRegistry::with_capacity(capacity),
        host_mode,
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
                        if state.procs.running_count_for(&id) == 0 {
                            state.sandboxes.delete(&id);
                            state.procs.remove_for_sandbox(&id);
                            eprintln!("sbx-server: evicted idle sandbox {id}");
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
                    let quiet_ms = now - state.last_activity_ms.load(Ordering::Relaxed);
                    if quiet_ms > idle_ms && state.procs.running_count() == 0 {
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
    // Mode and auth state on the first line: a server that silently serves the
    // wrong surface, or no authentication at all, is the hazard worth seeing.
    eprintln!(
        "sbx-server {VERSION} listening on 0.0.0.0:{port} (mode: {}, auth: {}, landlock: {})",
        if host_mode { "host" } else { "dedicated" },
        if matches!(state.auth, Auth::Required(_)) { "required" } else { "DISABLED" },
        if landlock_ok { "enabled" } else { "UNAVAILABLE — uid isolation only" }
    );
    // Host mode reuses one set of system-dir fds across every sandbox ruleset.
    // Open them now so the cost (and any missing-dir surface) lands at startup
    // rather than on the first sandbox create.
    if host_mode && landlock_ok {
        eprintln!("sbx-server: pinned {} system dirs for landlock", landlock::system_dir_rules().len());
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let state = Arc::clone(&state);
        std::thread::spawn(move || handle_connection(state, stream));
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
}
