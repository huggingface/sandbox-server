mod exec;
mod files;
mod http;

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

pub struct State {
    pub token: Option<String>,
    pub started_at_ms: i64,
    pub last_activity_ms: AtomicI64,
    pub procs: exec::ProcRegistry,
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
            }),
        );
    }

    if !authorized(state, request) {
        return resp.error(403, "invalid or missing X-Sandbox-Token");
    }
    state.last_activity_ms.store(now_ms(), Ordering::Relaxed);

    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method.as_str(), segments.as_slice()) {
        ("POST", ["v1", "exec"]) => exec::handle_exec(state, request, reader, resp),
        ("GET", ["v1", "procs"]) => resp.json(200, &state.procs.list()),
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
        ("GET", ["v1", "files", "read"]) => files::handle_read(request, resp),
        ("PUT", ["v1", "files", "write"]) => files::handle_write(request, reader, resp),
        ("GET", ["v1", "files", "list"]) => files::handle_list(request, resp),
        ("GET", ["v1", "files", "stat"]) => files::handle_stat(request, resp),
        ("DELETE", ["v1", "files", "delete"]) => files::handle_delete(request, resp),
        ("POST", ["v1", "files", "mkdir"]) => files::handle_mkdir(request, resp),
        _ => resp.error(404, &format!("no route: {method} {path}")),
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

    let state = Arc::new(State {
        token,
        started_at_ms: now_ms(),
        last_activity_ms: AtomicI64::new(now_ms()),
        procs: exec::ProcRegistry::default(),
    });

    // Idle watchdog: exit cleanly when no activity and no running processes,
    // so an abandoned sandbox stops billing before its job timeout.
    if let Some(idle) = idle_timeout_secs {
        let state = Arc::clone(&state);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let idle_ms = now_ms() - state.last_activity_ms.load(Ordering::Relaxed);
            if idle_ms > (idle * 1000) as i64 && state.procs.running_count() == 0 {
                eprintln!("sbx-server: idle for {idle_ms}ms, shutting down");
                std::process::exit(0);
            }
        });
    }

    let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("sbx-server: failed to bind port {port}: {e}");
        std::process::exit(1);
    });
    eprintln!("sbx-server {VERSION} listening on 0.0.0.0:{port}");

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let state = Arc::clone(&state);
        std::thread::spawn(move || handle_connection(state, stream));
    }
}
