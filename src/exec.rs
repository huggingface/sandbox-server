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
use std::time::{Duration, Instant};

use crate::http::{read_body, Request, ResponseWriter};
use crate::{now_ms, State};

/// Heartbeat interval for long-silent streams, to keep the proxy connection alive.
const PING_INTERVAL: Duration = Duration::from_secs(15);
/// Maximum time to wait for stdout/stderr reader threads after the process exits.
///
/// In the normal case the pipes close immediately and all output is emitted before
/// Exit. A bounded timeout avoids hanging forever when grandchildren inherit pipes.
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
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

struct SpawnedCommand {
    child: Child,
    output_done: Receiver<()>,
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

// x86_64 syscall numbers (build target is x86_64-unknown-linux-musl).
const SYS_PIDFD_OPEN: libc::c_long = 434;
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

/// A handle on a spawned command that survives PID reuse.
///
/// A raw PID stops identifying a process the moment it exits, and the kernel may
/// then hand the number to something else. The timeout watcher used to sleep for
/// the full timeout and *then* signal a PID captured when the command started --
/// as root, in a container where we are PID 1, so a recycled PID could belong to
/// anything. A pidfd refers to the process itself, so the liveness check and the
/// signal to the leader cannot land on a stranger.
///
/// The PID is still kept, for the process-group sweep that catches the
/// command's children: `pgid == pid` because commands are spawned with
/// `process_group(0)`, and the sweep only runs after the pidfd says the leader
/// is alive, so the group cannot have been recycled underneath it.
struct ProcHandle {
    pid: u32,
    pidfd: Option<libc::c_int>,
}

impl ProcHandle {
    /// Must be called while the caller still holds the `Child`, so the PID
    /// cannot have been reaped and reused before the pidfd is opened.
    fn open(pid: u32) -> Self {
        let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as libc::pid_t, 0u32) };
        Self { pid, pidfd: (fd >= 0).then_some(fd as libc::c_int) }
    }

    fn signal_leader(&self, signal: i32) -> bool {
        match self.pidfd {
            Some(fd) => unsafe {
                libc::syscall(SYS_PIDFD_SEND_SIGNAL, fd, signal, std::ptr::null::<libc::c_void>(), 0u32) == 0
            },
            None => unsafe { libc::kill(self.pid as i32, signal) == 0 },
        }
    }

    fn alive(&self) -> bool {
        self.signal_leader(0)
    }

    /// Signal the leader, then its process group.
    fn kill_tree(&self, signal: i32) {
        self.signal_leader(signal);
        unsafe { libc::kill(-(self.pid as i32), signal) };
    }
}

impl Drop for ProcHandle {
    fn drop(&mut self) {
        if let Some(fd) = self.pidfd {
            unsafe { libc::close(fd) };
        }
    }
}

fn kill_group(pid: u32, signal: i32) {
    unsafe {
        // The child was spawned with process_group(0), so its pgid == its pid.
        libc::kill(-(pid as i32), signal);
    }
}

/// Spawns the process and wires up reader threads that push events to `tx`.
fn spawn(spec: &ExecSpec, tx: Sender<Event>) -> Result<SpawnedCommand, String> {
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

    let (output_done_tx, output_done) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    spawn_reader(stdout, tx.clone(), output_done_tx.clone(), Event::Stdout);
    spawn_reader(stderr, tx.clone(), output_done_tx, Event::Stderr);

    Ok(SpawnedCommand { child, output_done })
}

fn spawn_reader(
    mut pipe: impl Read + Send + 'static,
    tx: Sender<Event>,
    done_tx: Sender<()>,
    make: fn(String) -> Event,
) {
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
        let _ = done_tx.send(());
    });
}

fn drain_output_readers(output_done: &Receiver<()>) {
    let deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
    for _ in 0..2 {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return;
        };
        if output_done.recv_timeout(remaining).is_err() {
            return;
        }
    }
}

/// Waits for the child (with optional timeout) and emits the final Exit event.
/// Runs on its own thread. The Exit event is emitted only after wait() returns
/// and stdout/stderr readers have drained, so foreground streams do not lose the
/// final output chunk when the process writes and exits immediately.
fn wait_and_report(
    mut command: SpawnedCommand,
    started_at: i64,
    timeout_secs: Option<f64>,
    tx: Sender<Event>,
) {
    let child = &mut command.child;
    let pid = child.id();
    track_owned(pid);
    let handle = Arc::new(ProcHandle::open(pid));
    let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Cancels the timeout watcher the moment the child exits. Sending on this is
    // what stops a `timeout=3600` command from leaving a thread asleep for an
    // hour after it finished in a millisecond.
    let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
    if let Some(secs) = timeout_secs {
        let timed_out = Arc::clone(&timed_out);
        let handle = Arc::clone(&handle);
        let deadline = started_at + (secs * 1000.0) as i64;
        std::thread::spawn(move || {
            let remaining = Duration::from_millis((deadline - now_ms()).max(0) as u64);
            // Wait for the deadline *or* for the child to exit, whichever first.
            if cancel_rx.recv_timeout(remaining).is_ok() {
                return; // exited on its own; nothing to kill
            }
            if handle.alive() {
                timed_out.store(true, std::sync::atomic::Ordering::SeqCst);
                handle.kill_tree(libc::SIGKILL);
            }
        });
    }

    let status = child.wait();
    // Whatever happens next, the watcher has no more work: the child is reaped,
    // so its PID is now free for reuse and must not be signalled.
    drop(cancel_tx);
    untrack_owned(pid);
    let info = match status {
        Ok(status) => ExitInfo {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out: timed_out.load(std::sync::atomic::Ordering::SeqCst),
            duration_ms: now_ms() - started_at,
        },
        Err(_) => ExitInfo {
            exit_code: None,
            signal: None,
            timed_out: false,
            duration_ms: now_ms() - started_at,
        },
    };
    drain_output_readers(&command.output_done);
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

/// Guard marking an in-flight operation, so the idle watchdog does not shut the
/// job down underneath it.
///
/// A *foreground* command was invisible to the watchdog: it was never registered
/// in `ProcRegistry`, `running_count()` therefore returned 0, and
/// `last_activity_ms` was only stamped when a request *arrived* -- so a `run()`
/// lasting longer than the idle timeout, with no other traffic, killed its own
/// job mid-command. RAII rather than manual increments so no early return or
/// panic can leak the count.
pub struct ActiveOp<'a>(&'a ProcRegistry);

impl Drop for ActiveOp<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[derive(Default)]
pub struct ProcRegistry {
    procs: Mutex<Vec<Arc<Proc>>>,
    /// Monotonic source for opaque process ids.
    seq: std::sync::atomic::AtomicU64,
    /// Operations currently running that are not background processes.
    active: std::sync::atomic::AtomicUsize,
}

/// How many *finished* processes to keep per scope, so a long-lived sandbox that
/// starts thousands of short background commands does not grow the registry
/// without bound. Running processes are never dropped.
const MAX_FINISHED_PROCS: usize = 256;

impl ProcRegistry {
    fn insert(&self, proc: Arc<Proc>) {
        let mut procs = self.procs.lock().unwrap();
        procs.push(proc);
        // Oldest-first, so the newest exits stay visible to `/processes`.
        let finished: Vec<usize> = procs
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state.lock().unwrap().exit.is_some())
            .map(|(i, _)| i)
            .collect();
        if finished.len() > MAX_FINISHED_PROCS {
            let drop_count = finished.len() - MAX_FINISHED_PROCS;
            let doomed: std::collections::HashSet<usize> = finished.into_iter().take(drop_count).collect();
            let mut index = 0;
            procs.retain(|_| {
                let keep = !doomed.contains(&index);
                index += 1;
                keep
            });
        }
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

    /// Mark an operation in flight for as long as the returned guard lives.
    pub fn begin_op(&self) -> ActiveOp<'_> {
        self.active.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        ActiveOp(self)
    }

    /// Operations in flight right now (foreground commands, mostly).
    pub fn active_ops(&self) -> usize {
        self.active.load(std::sync::atomic::Ordering::Acquire)
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

/// PIDs of commands we spawned and will `wait()` on ourselves.
///
/// The reaper below must not steal their exit status, so it peeks with
/// `WNOWAIT` and only reaps PIDs that are not in here.
static OWNED_PIDS: Mutex<Option<std::collections::HashSet<u32>>> = Mutex::new(None);

fn track_owned(pid: u32) {
    OWNED_PIDS.lock().unwrap().get_or_insert_with(Default::default).insert(pid);
}

fn untrack_owned(pid: u32) {
    if let Some(set) = OWNED_PIDS.lock().unwrap().as_mut() {
        set.remove(&pid);
    }
}

fn is_owned(pid: u32) -> bool {
    OWNED_PIDS.lock().unwrap().as_ref().is_some_and(|set| set.contains(&pid))
}

/// Reap orphaned descendants, so they do not accumulate as zombies.
///
/// The server usually runs as PID 1 in its container, which makes it the
/// adoptive parent of every orphaned grandchild -- and it only ever waited on
/// its own `Child` handles, so anything re-parented to it stayed a zombie for
/// the life of the job. `PR_SET_CHILD_SUBREAPER` is belt and braces for the
/// case where we are not PID 1.
///
/// The delicate part is not stealing an exit status from `Child::wait()`, which
/// would turn a command's exit code into garbage. So this *peeks* first and only
/// reaps for real when the PID is not one we spawned.
///
/// The peek uses `waitid` with `WNOWAIT`, which leaves the child waitable.
/// `waitpid` cannot do this: `WNOWAIT` is a `waitid`-only flag, and passing it
/// to `waitpid` fails with `EINVAL` -- which silently turns the whole reaper
/// into a no-op, as the first version of this did.
///
/// `SIGCHLD` is not used: a handler that can be interrupted mid-`waitpid` is
/// harder to reason about than a thread polling a cheap syscall once a second.
pub fn spawn_orphan_reaper() {
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    std::thread::spawn(|| loop {
        // Bounded per tick so a burst cannot spin here forever.
        for _ in 0..256 {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
            };
            if rc != 0 {
                break; // no children, or nothing exited
            }
            let pid = unsafe { info.si_pid() };
            if pid == 0 {
                break; // WNOHANG: nothing ready
            }
            if is_owned(pid as u32) {
                // Its own `wait()` will collect it; taking the status here would
                // lose the exit code the caller is waiting to report. Leave it
                // and come back next tick.
                break;
            }
            let mut status: libc::c_int = 0;
            if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } <= 0 {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    });
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
fn stream_events(state: &Arc<State>, rx: &Receiver<Event>, resp: &mut ResponseWriter) -> std::io::Result<()> {
    loop {
        match rx.recv_timeout(PING_INTERVAL) {
            Ok(event) => {
                let is_exit = matches!(event, Event::Exit(_));
                resp.chunk(event.to_line().as_bytes())?;
                // Output is evidence of life. Stamping only on request arrival
                // meant a long, chatty command still looked idle.
                state.last_activity_ms.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
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
    let command = match spawn(&spec, tx.clone()) {
        Ok(command) => command,
        Err(e) => return resp.error(400, &e),
    };
    let pid = command.child.id();
    // Held until this handler returns, so the idle watchdog counts a running
    // foreground command as activity instead of shutting the job down under it.
    let _op = state.procs.begin_op();
    wait_detached(command, started_at, spec.timeout_secs, tx);
    resp.start_stream(200, "application/x-ndjson")?;
    resp.chunk(format!("{}\n", serde_json::json!({"event": "start", "pid": pid})).as_bytes())?;
    stream_events(state, &rx, resp)
}

/// Spawn `spec` as a background process, register it, and return the registry entry.
/// Shared by `POST /exec {background:true}` and the `POST /processes` REST route.
fn start_background(state: &Arc<State>, spec: &ExecSpec) -> Result<Arc<Proc>, String> {
    let (tx, rx) = mpsc::channel::<Event>();
    let started_at = now_ms();
    let command = spawn(spec, tx.clone())?;
    let proc = Arc::new(Proc {
        id: state.procs.alloc_id(),
        pid: command.child.id(),
        tag: spec.tag.clone(),
        cmd_json: spec.cmd_json.clone(),
        started_at_ms: started_at,
        sandbox_id: spec.sandbox.as_ref().map(|s| s.id.clone()),
        state: Mutex::new(ProcState { exit: None }),
    });
    state.procs.insert(Arc::clone(&proc));
    pump_background(Arc::clone(&proc), rx);
    wait_detached(command, started_at, spec.timeout_secs, tx);
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
        // Only signal while the process is still ours to signal: once it has
        // exited, its PID (and therefore its pgid) may belong to something else.
        let exited = proc.state.lock().unwrap().exit.is_some();
        if !exited {
            kill_group(proc.pid, libc::SIGKILL);
        }
    }
    resp.json(200, &serde_json::json!({"id": id, "ok": true}))
}

fn wait_detached(
    command: SpawnedCommand,
    started_at: i64,
    timeout_secs: Option<f64>,
    tx: Sender<Event>,
) {
    std::thread::spawn(move || wait_and_report(command, started_at, timeout_secs, tx));
}
