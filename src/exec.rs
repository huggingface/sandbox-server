//! Command execution: foreground (streamed NDJSON events) and background
//! processes tracked in a registry.

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use crate::http::{read_body, Request, ResponseWriter};
use crate::{now_ms, State};

/// Heartbeat interval for long-silent streams, to keep the proxy connection alive.
const PING_INTERVAL: Duration = Duration::from_secs(15);
/// Keepalive frame written on stream timeout (kept identical across all streams).
const PING_CHUNK: &[u8] = b"{\"event\":\"ping\"}\n";

#[derive(Clone)]
pub enum Event {
    Stdout(String),
    Stderr(String),
    Exit(ExitInfo),
}

#[derive(Clone, Copy)]
pub struct ExitInfo {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: i64,
}

impl Event {
    fn to_line(&self) -> String {
        let mut line = match self {
            Event::Stdout(d) => serde_json::json!({"event": "stdout", "data": d}).to_string(),
            Event::Stderr(d) => serde_json::json!({"event": "stderr", "data": d}).to_string(),
            Event::Exit(info) => serde_json::json!({
                "event": "exit",
                "exit_code": info.exit_code,
                "signal": info.signal,
                "timed_out": info.timed_out,
                "duration_ms": info.duration_ms,
            })
            .to_string(),
        };
        line.push('\n');
        line
    }
}

pub struct ExecSpec {
    pub argv: Vec<String>,
    /// The original `cmd` value verbatim (string or argv array), preserved so the
    /// `/processes` API can round-trip it back to the client unchanged.
    pub cmd_json: serde_json::Value,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub timeout_secs: Option<f64>,
    pub stdin: Option<String>,
    pub background: bool,
    pub tag: Option<String>,
    /// When set, the command runs inside that sandbox: its uid, its home as cwd,
    /// a scrubbed environment and per-sandbox rlimits (see sandboxes module).
    pub sandbox: Option<Arc<crate::sandboxes::SandboxEntry>>,
}

impl ExecSpec {
    pub fn from_json(body: &serde_json::Value) -> Result<Self, String> {
        // `shell` makes the shell-vs-argv choice explicit; when omitted it is inferred
        // from the type of `cmd` (string → shell, array → argv) for backward compatibility.
        // When set, it is authoritative and the type of `cmd` must match it.
        let shell = body.get("shell").and_then(|v| v.as_bool());
        let argv: Vec<String> = match (shell, body.get("cmd")) {
            (Some(true) | None, Some(serde_json::Value::String(s))) => {
                vec!["/bin/sh".to_string(), "-c".to_string(), s.clone()]
            }
            (Some(false) | None, Some(serde_json::Value::Array(items))) => {
                let argv: Vec<String> = items
                    .iter()
                    .map(|v| v.as_str().map(String::from).ok_or("cmd array items must be strings"))
                    .collect::<Result<_, _>>()?;
                if argv.is_empty() {
                    return Err("cmd array must not be empty".into());
                }
                argv
            }
            (Some(true), _) => return Err("shell=true requires 'cmd' to be a string".into()),
            (Some(false), _) => return Err("shell=false requires 'cmd' to be an array of strings".into()),
            (None, _) => return Err("missing 'cmd' (string or array of strings)".into()),
        };
        Ok(ExecSpec {
            argv,
            cmd_json: body.get("cmd").cloned().unwrap_or(serde_json::Value::Null),
            env: crate::json_string_map(body, "env"),
            cwd: body.get("cwd").and_then(|v| v.as_str()).map(String::from),
            timeout_secs: body.get("timeout").and_then(|v| v.as_f64()),
            stdin: body.get("stdin").and_then(|v| v.as_str()).map(String::from),
            background: body.get("background").and_then(|v| v.as_bool()).unwrap_or(false),
            tag: body.get("tag").and_then(|v| v.as_str()).map(String::from),
            sandbox: None,
        })
    }
}

fn kill_group(pid: u32, signal: i32) {
    unsafe {
        // The child was spawned with process_group(0), so its pgid == its pid.
        libc::kill(-(pid as i32), signal);
    }
}

/// Spawns the process and wires up reader/waiter threads that push events to `tx`.
fn spawn(spec: &ExecSpec, tx: Sender<Event>) -> Result<Child, String> {
    let mut command = Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .stdin(if spec.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(sbx) = &spec.sandbox {
        // The host env may hold job secrets that must not leak into sandboxes.
        command.env_clear();
        for (k, v) in crate::sandboxes::base_env(sbx) {
            command.env(k, v);
        }
        command.uid(sbx.uid).gid(sbx.uid);
        unsafe { command.pre_exec(crate::sandboxes::pre_exec_isolation(sbx)) };
        command.current_dir(spec.cwd.as_deref().unwrap_or(&sbx.home));
    } else if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command.envs(&spec.env);
    let mut child = command.spawn().map_err(|e| format!("failed to spawn '{}': {e}", spec.argv[0]))?;

    // Optional one-shot stdin payload: write it then drop the pipe (-> EOF).
    if let Some(input) = &spec.stdin {
        if let Some(mut pipe) = child.stdin.take() {
            let data = input.clone().into_bytes();
            std::thread::spawn(move || {
                let _ = pipe.write_all(&data);
            });
        }
    }

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    spawn_reader(stdout, tx.clone(), Event::Stdout);
    spawn_reader(stderr, tx.clone(), Event::Stderr);

    Ok(child)
}

fn spawn_reader(mut pipe: impl Read + Send + 'static, tx: Sender<Event>, make: fn(String) -> Event) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                    if tx.send(make(data)).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// Waits for the child (with optional timeout) and emits the final Exit event.
/// Runs on its own thread; readers hold clones of `tx`, so the Exit event is
/// emitted only via this explicit send after wait() returns (which itself only
/// returns after stdout/stderr are closed... not strictly: wait() returns when
/// the process exits even if grandchildren keep the pipes open).
fn wait_and_report(mut child: Child, started_at: i64, timeout_secs: Option<f64>, tx: Sender<Event>) {
    let pid = child.id();
    let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Some(secs) = timeout_secs {
        let timed_out = Arc::clone(&timed_out);
        let deadline = started_at + (secs * 1000.0) as i64;
        std::thread::spawn(move || {
            // Sleep straight to the deadline instead of polling every 200ms.
            let remaining = (deadline - now_ms()).max(0) as u64;
            std::thread::sleep(Duration::from_millis(remaining));
            // kill(pid, 0) confirms the process is still alive before signalling.
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                timed_out.store(true, std::sync::atomic::Ordering::SeqCst);
                kill_group(pid, libc::SIGKILL);
            }
        });
    }

    let status = child.wait();
    let info = match status {
        Ok(status) => ExitInfo {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out: timed_out.load(std::sync::atomic::Ordering::SeqCst),
            duration_ms: now_ms() - started_at,
        },
        Err(_) => ExitInfo { exit_code: None, signal: None, timed_out: false, duration_ms: now_ms() - started_at },
    };
    let _ = tx.send(Event::Exit(info));
}

// ---------------------------------------------------------------------------
// Background process registry
// ---------------------------------------------------------------------------

pub struct ProcState {
    pub exit: Option<ExitInfo>,
}

pub struct Proc {
    /// Opaque, server-assigned handle (e.g. `p-3`) — the stable id the `/processes`
    /// API exposes, distinct from the OS `pid` (which the OS may later reuse).
    pub id: String,
    pub pid: u32,
    pub tag: Option<String>,
    /// Original `cmd` value (string or argv array), echoed back by `/processes`.
    pub cmd_json: serde_json::Value,
    pub started_at_ms: i64,
    /// Owning sandbox id in host mode (None for dedicated-mode processes).
    pub sandbox_id: Option<String>,
    pub state: Mutex<ProcState>,
}

#[derive(Default)]
pub struct ProcRegistry {
    procs: Mutex<Vec<Arc<Proc>>>,
    /// Monotonic source for opaque process ids.
    seq: std::sync::atomic::AtomicU64,
}

impl ProcRegistry {
    fn insert(&self, proc: Arc<Proc>) {
        self.procs.lock().unwrap().push(proc);
    }

    /// Allocate a fresh opaque process id (e.g. `p-7`).
    pub fn alloc_id(&self) -> String {
        let n = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("p-{n}")
    }

    /// Remove the process with opaque `id` (optionally scoped to `sandbox_id` in host
    /// mode) and return it so the caller can signal it. `None` if no such process is
    /// owned here — which lets `DELETE /processes/{id}` stay idempotent.
    pub fn remove_by_id(&self, id: &str, sandbox_id: Option<&str>) -> Option<Arc<Proc>> {
        let mut procs = self.procs.lock().unwrap();
        let pos = procs
            .iter()
            .position(|p| p.id == id && (sandbox_id.is_none() || p.sandbox_id.as_deref() == sandbox_id))?;
        Some(procs.remove(pos))
    }

    /// Forget all processes owned by a sandbox (called when it is deleted) so the
    /// registry doesn't grow without bound across short-lived sandboxes.
    pub fn remove_for_sandbox(&self, sandbox_id: &str) {
        self.procs.lock().unwrap().retain(|p| p.sandbox_id.as_deref() != Some(sandbox_id));
    }

    pub fn running_count(&self) -> usize {
        self.procs
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.state.lock().unwrap().exit.is_none())
            .count()
    }

    /// Number of still-running processes owned by `sandbox_id` (host-mode idle eviction
    /// must not evict a sandbox that still has work running).
    pub fn running_count_for(&self, sandbox_id: &str) -> usize {
        self.procs
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.sandbox_id.as_deref() == Some(sandbox_id) && p.state.lock().unwrap().exit.is_none())
            .count()
    }

    /// List background processes. In host mode pass `Some(sandbox_id)` to list only
    /// that sandbox's processes; pass `None` for the dedicated-mode global list.
    pub fn list_processes(&self, sandbox_id: Option<&str>) -> serde_json::Value {
        let procs = self.procs.lock().unwrap();
        serde_json::Value::Array(
            procs
                .iter()
                .filter(|p| sandbox_id.is_none() || p.sandbox_id.as_deref() == sandbox_id)
                .map(|p| {
                    let state = p.state.lock().unwrap();
                    serde_json::json!({
                        "id": p.id,
                        "pid": p.pid,
                        "cmd": p.cmd_json,
                        "tag": p.tag,
                        "started_at_ms": p.started_at_ms,
                        "running": state.exit.is_none(),
                        "exit_code": state.exit.and_then(|e| e.exit_code),
                    })
                })
                .collect(),
        )
    }
}

/// Drains the background process's output (not buffered — `/processes` doesn't expose
/// logs) and records the final exit status so the process list can report it.
fn pump_background(proc: Arc<Proc>, rx: Receiver<Event>) {
    std::thread::spawn(move || {
        for event in rx {
            if let Event::Exit(info) = event {
                proc.state.lock().unwrap().exit = Some(info);
                break;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/// Streams events from `rx` as NDJSON chunks until Exit, with keepalive pings.
fn stream_events(rx: &Receiver<Event>, resp: &mut ResponseWriter) -> std::io::Result<()> {
    loop {
        match rx.recv_timeout(PING_INTERVAL) {
            Ok(event) => {
                let is_exit = matches!(event, Event::Exit(_));
                resp.chunk(event.to_line().as_bytes())?;
                if is_exit {
                    return Ok(());
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                resp.chunk(PING_CHUNK)?;
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

pub fn handle_exec(
    state: &Arc<State>,
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
    sandbox: Option<Arc<crate::sandboxes::SandboxEntry>>,
) -> std::io::Result<()> {
    let body = read_body(request, reader, 16 * 1024 * 1024)?;
    let json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return resp.error(400, &format!("invalid JSON body: {e}")),
    };
    let mut spec = match ExecSpec::from_json(&json) {
        Ok(s) => s,
        Err(e) => return resp.error(400, &e),
    };
    spec.sandbox = sandbox;

    if spec.background {
        return match start_background(state, &spec) {
            Ok(proc) => resp.json(200, &serde_json::json!({"pid": proc.pid, "tag": proc.tag})),
            Err(e) => resp.error(400, &e),
        };
    }

    let (tx, rx) = mpsc::channel::<Event>();
    let started_at = now_ms();
    let child = match spawn(&spec, tx.clone()) {
        Ok(child) => child,
        Err(e) => return resp.error(400, &e),
    };
    let pid = child.id();
    wait_detached(child, started_at, spec.timeout_secs, tx);
    resp.start_stream(200, "application/x-ndjson")?;
    resp.chunk(format!("{}\n", serde_json::json!({"event": "start", "pid": pid})).as_bytes())?;
    stream_events(&rx, resp)
}

/// Spawn `spec` as a background process, register it, and return the registry entry.
/// Shared by `POST /exec {background:true}` and the `POST /processes` REST route.
fn start_background(state: &Arc<State>, spec: &ExecSpec) -> Result<Arc<Proc>, String> {
    let (tx, rx) = mpsc::channel::<Event>();
    let started_at = now_ms();
    let child = spawn(spec, tx.clone())?;
    let proc = Arc::new(Proc {
        id: state.procs.alloc_id(),
        pid: child.id(),
        tag: spec.tag.clone(),
        cmd_json: spec.cmd_json.clone(),
        started_at_ms: started_at,
        sandbox_id: spec.sandbox.as_ref().map(|s| s.id.clone()),
        state: Mutex::new(ProcState { exit: None }),
    });
    state.procs.insert(Arc::clone(&proc));
    pump_background(Arc::clone(&proc), rx);
    wait_detached(child, started_at, spec.timeout_secs, tx);
    Ok(proc)
}

/// `POST /processes` — start a background process and return its opaque `id`, `pid`
/// and `cmd`. Body is the same shape as `/exec` (`background` is implied).
pub fn handle_process_start(
    state: &Arc<State>,
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
    sandbox: Option<Arc<crate::sandboxes::SandboxEntry>>,
) -> std::io::Result<()> {
    let body = read_body(request, reader, 16 * 1024 * 1024)?;
    let json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return resp.error(400, &format!("invalid JSON body: {e}")),
    };
    let mut spec = match ExecSpec::from_json(&json) {
        Ok(s) => s,
        Err(e) => return resp.error(400, &e),
    };
    spec.background = true;
    spec.sandbox = sandbox;
    match start_background(state, &spec) {
        Ok(proc) => resp.json(
            200,
            &serde_json::json!({"id": proc.id, "pid": proc.pid, "cmd": proc.cmd_json, "tag": proc.tag}),
        ),
        Err(e) => resp.error(400, &e),
    }
}

/// `DELETE /processes/{id}` — terminate a background process by its opaque id and
/// forget it. Idempotent: an unknown id (or one owned by another sandbox) is a no-op.
pub fn handle_process_delete(
    state: &Arc<State>,
    id: &str,
    sandbox_id: Option<&str>,
    resp: &mut ResponseWriter,
) -> std::io::Result<()> {
    if let Some(proc) = state.procs.remove_by_id(id, sandbox_id) {
        kill_group(proc.pid, libc::SIGKILL);
    }
    resp.json(200, &serde_json::json!({"id": id, "ok": true}))
}

fn wait_detached(child: Child, started_at: i64, timeout_secs: Option<f64>, tx: Sender<Event>) {
    std::thread::spawn(move || wait_and_report(child, started_at, timeout_secs, tx));
}
