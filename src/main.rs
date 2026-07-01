mod exec;
mod files;
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

pub struct State {
    pub token: Option<String>,
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
    let Some(expected) = &state.token else { return true };
    request.header("x-sandbox-token").map(|v| ct_eq(v, expected)).unwrap_or(false)
}

fn route(
    state: &Arc<State>,
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
) -> std::io::Result<()> {
    if request.header("transfer-encoding").is_some() {
        return resp.error(411, "chunked request bodies not supported; send Content-Length");
    }

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

    if !authorized(state, request) {
        return resp.error(403, "invalid or missing X-Sandbox-Token");
    }
    state.last_activity_ms.store(now_ms(), Ordering::Relaxed);

    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    // Per-sandbox activity (host-mode idle eviction): any request scoped to a sandbox
    // resets its idle timer.
    if let ["v1", "sandboxes", id, ..] = segments.as_slice() {
        state.sandboxes.touch(id);
    }
    match (method.as_str(), segments.as_slice()) {
        // ---- dedicated mode: operate directly on the job (one job == one sandbox) ----
        ("POST", ["v1", "exec"]) => exec::handle_exec(state, request, reader, resp, None),
        ("GET", ["v1", "procs"]) => resp.json(200, &state.procs.list(None)),
        ("GET", ["v1", "procs", pid, "logs"]) => exec::handle_logs(state, pid, &request.params, resp),
        ("GET", ["v1", "procs", pid, "wait"]) => exec::handle_wait(state, pid, resp),
        ("POST", ["v1", "procs", pid, "kill"]) => {
            let pid = pid.to_string();
            exec::handle_kill(state, request, reader, &pid, resp)
        }
        ("POST", ["v1", "procs", pid, "stdin"]) => {
            let pid = pid.to_string();
            exec::handle_stdin(state, request, reader, &pid, resp)
        }
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
        ("GET", ["v1", "sandboxes", id, "procs"]) => resp.json(200, &state.procs.list(Some(id))),
        ("GET", ["v1", "sandboxes", id, "procs", pid, "logs"]) => match parse_owned_pid(state, id, pid) {
            Ok(_) => exec::handle_logs(state, pid, &request.params, resp),
            Err(()) => resp.error(404, &format!("no such process: {pid}")),
        },
        ("GET", ["v1", "sandboxes", id, "procs", pid, "wait"]) => match parse_owned_pid(state, id, pid) {
            Ok(_) => exec::handle_wait(state, pid, resp),
            Err(()) => resp.error(404, &format!("no such process: {pid}")),
        },
        ("POST", ["v1", "sandboxes", id, "procs", pid, "kill"]) => match parse_owned_pid(state, id, pid) {
            Ok(pid) => exec::handle_kill(state, request, reader, &pid, resp),
            Err(()) => resp.error(404, &format!("no such process: {pid}")),
        },
        ("POST", ["v1", "sandboxes", id, "procs", pid, "stdin"]) => match parse_owned_pid(state, id, pid) {
            Ok(pid) => exec::handle_stdin(state, request, reader, &pid, resp),
            Err(()) => resp.error(404, &format!("no such process: {pid}")),
        },
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

/// Parse `pid` and confirm it belongs to sandbox `id` (host-mode process scoping).
fn parse_owned_pid(state: &Arc<State>, id: &str, pid: &str) -> Result<String, ()> {
    match pid.parse::<u32>() {
        Ok(p) if state.procs.belongs(p, id) => Ok(pid.to_string()),
        _ => Err(()),
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
    let idle_timeout_secs: Option<u64> = std::env::var("SBX_IDLE_TIMEOUT").ok().and_then(|v| v.parse().ok());
    // Host-mode packing density: max concurrent sandboxes on this host (default: unlimited).
    let capacity = std::env::var("SBX_CAPACITY").ok().and_then(|v| v.parse().ok()).unwrap_or(usize::MAX);
    // Host mode multiplexes many sandboxes; dedicated mode is one sandbox == the job.
    let host_mode = std::env::var("SBX_HOST_MODE").map(|v| v == "1").unwrap_or(false);

    let state = Arc::new(State {
        token,
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
    eprintln!(
        "sbx-server {VERSION} listening on 0.0.0.0:{port} (landlock: {})",
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
