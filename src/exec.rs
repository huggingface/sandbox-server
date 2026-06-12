//! Command execution: foreground (streamed NDJSON events) and background
//! processes tracked in a registry with buffered logs.

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use crate::http::{read_body, stream_body, Request, ResponseWriter};
use crate::{now_ms, State};

/// Heartbeat interval for long-silent streams, to keep the proxy connection alive.
const PING_INTERVAL: Duration = Duration::from_secs(15);
/// Per-process buffered log budget for background processes.
const LOG_BUFFER_BYTES: usize = 4 * 1024 * 1024;

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
        match self {
            Event::Stdout(d) => format!("{}\n", serde_json::json!({"event": "stdout", "data": d})),
            Event::Stderr(d) => format!("{}\n", serde_json::json!({"event": "stderr", "data": d})),
            Event::Exit(info) => format!(
                "{}\n",
                serde_json::json!({
                    "event": "exit",
                    "exit_code": info.exit_code,
                    "signal": info.signal,
                    "timed_out": info.timed_out,
                    "duration_ms": info.duration_ms,
                })
            ),
        }
    }

    fn byte_len(&self) -> usize {
        match self {
            Event::Stdout(d) | Event::Stderr(d) => d.len(),
            Event::Exit(_) => 0,
        }
    }
}

pub struct ExecSpec {
    pub argv: Vec<String>,
    pub display: String,
    pub env: HashMap<String, String>,
    pub cwd: Option<String>,
    pub timeout_secs: Option<f64>,
    pub stdin: Option<String>,
    pub background: bool,
    pub tag: Option<String>,
}

impl ExecSpec {
    pub fn from_json(body: &serde_json::Value) -> Result<Self, String> {
        let (argv, display) = match body.get("cmd") {
            Some(serde_json::Value::String(s)) => {
                (vec!["/bin/sh".to_string(), "-c".to_string(), s.clone()], s.clone())
            }
            Some(serde_json::Value::Array(items)) => {
                let argv: Vec<String> = items
                    .iter()
                    .map(|v| v.as_str().map(String::from).ok_or("cmd array items must be strings"))
                    .collect::<Result<_, _>>()?;
                if argv.is_empty() {
                    return Err("cmd array must not be empty".into());
                }
                let display = argv.join(" ");
                (argv, display)
            }
            _ => return Err("missing 'cmd' (string or array of strings)".into()),
        };
        let env = body
            .get("env")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(ExecSpec {
            argv,
            display,
            env,
            cwd: body.get("cwd").and_then(|v| v.as_str()).map(String::from),
            timeout_secs: body.get("timeout").and_then(|v| v.as_f64()),
            stdin: body.get("stdin").and_then(|v| v.as_str()).map(String::from),
            background: body.get("background").and_then(|v| v.as_bool()).unwrap_or(false),
            tag: body.get("tag").and_then(|v| v.as_str()).map(String::from),
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
fn spawn(spec: &ExecSpec, tx: Sender<Event>) -> Result<(Child, Option<ChildStdin>), String> {
    let mut command = Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .envs(&spec.env)
        .stdin(if spec.stdin.is_some() || spec.background { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().map_err(|e| format!("failed to spawn '{}': {e}", spec.argv[0]))?;

    let mut stdin = child.stdin.take();
    if let Some(input) = &spec.stdin {
        if let Some(mut pipe) = stdin.take() {
            let data = input.clone().into_bytes();
            std::thread::spawn(move || {
                let _ = pipe.write_all(&data);
                // pipe dropped here -> EOF
            });
        }
    }

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    spawn_reader(stdout, tx.clone(), Event::Stdout);
    spawn_reader(stderr, tx.clone(), Event::Stderr);

    Ok((child, stdin))
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
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(200));
            if now_ms() >= deadline {
                if unsafe { libc::kill(pid as i32, 0) } == 0 {
                    timed_out.store(true, std::sync::atomic::Ordering::SeqCst);
                    kill_group(pid, libc::SIGKILL);
                }
                break;
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
    pub events: std::collections::VecDeque<Event>,
    pub buffered_bytes: usize,
    pub dropped_bytes: u64,
    pub exit: Option<ExitInfo>,
    pub subscribers: Vec<Sender<Event>>,
}

pub struct Proc {
    pub pid: u32,
    pub tag: Option<String>,
    pub display: String,
    pub started_at_ms: i64,
    pub state: Mutex<ProcState>,
    pub exited: Condvar,
    pub stdin: Mutex<Option<ChildStdin>>,
}

#[derive(Default)]
pub struct ProcRegistry {
    procs: Mutex<Vec<Arc<Proc>>>,
}

impl ProcRegistry {
    fn insert(&self, proc: Arc<Proc>) {
        self.procs.lock().unwrap().push(proc);
    }

    pub fn get(&self, pid: u32) -> Option<Arc<Proc>> {
        self.procs.lock().unwrap().iter().find(|p| p.pid == pid).cloned()
    }

    pub fn running_count(&self) -> usize {
        self.procs
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.state.lock().unwrap().exit.is_none())
            .count()
    }

    pub fn list(&self) -> serde_json::Value {
        let procs = self.procs.lock().unwrap();
        serde_json::Value::Array(
            procs
                .iter()
                .map(|p| {
                    let state = p.state.lock().unwrap();
                    serde_json::json!({
                        "pid": p.pid,
                        "tag": p.tag,
                        "cmd": p.display,
                        "started_at_ms": p.started_at_ms,
                        "running": state.exit.is_none(),
                        "exit_code": state.exit.and_then(|e| e.exit_code),
                    })
                })
                .collect(),
        )
    }
}

/// Fans events from the process into the registry entry (ring buffer + live subscribers).
fn pump_background(proc: Arc<Proc>, rx: Receiver<Event>) {
    std::thread::spawn(move || {
        for event in rx {
            let is_exit = matches!(event, Event::Exit(_));
            let mut state = proc.state.lock().unwrap();
            if let Event::Exit(info) = &event {
                state.exit = Some(*info);
            }
            state.buffered_bytes += event.byte_len();
            state.events.push_back(event.clone());
            while state.buffered_bytes > LOG_BUFFER_BYTES {
                if let Some(old) = state.events.pop_front() {
                    state.buffered_bytes -= old.byte_len();
                    state.dropped_bytes += old.byte_len() as u64;
                } else {
                    break;
                }
            }
            state.subscribers.retain(|sub| sub.send(event.clone()).is_ok());
            if is_exit {
                state.subscribers.clear();
                drop(state);
                proc.exited.notify_all();
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
                resp.chunk(b"{\"event\":\"ping\"}\n")?;
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
) -> std::io::Result<()> {
    let body = read_body(request, reader, 16 * 1024 * 1024)?;
    let json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return resp.error(400, &format!("invalid JSON body: {e}")),
    };
    let spec = match ExecSpec::from_json(&json) {
        Ok(s) => s,
        Err(e) => return resp.error(400, &e),
    };

    let (tx, rx) = mpsc::channel::<Event>();
    let started_at = now_ms();
    let (child, stdin) = match spawn(&spec, tx.clone()) {
        Ok(pair) => pair,
        Err(e) => return resp.error(400, &e),
    };
    let pid = child.id();

    if spec.background {
        let proc = Arc::new(Proc {
            pid,
            tag: spec.tag.clone(),
            display: spec.display.clone(),
            started_at_ms: started_at,
            state: Mutex::new(ProcState {
                events: Default::default(),
                buffered_bytes: 0,
                dropped_bytes: 0,
                exit: None,
                subscribers: Vec::new(),
            }),
            exited: Condvar::new(),
            stdin: Mutex::new(stdin),
        });
        state.procs.insert(Arc::clone(&proc));
        pump_background(proc, rx);
        wait_detached(child, started_at, spec.timeout_secs, tx);
        resp.json(200, &serde_json::json!({"pid": pid, "tag": spec.tag}))
    } else {
        drop(stdin); // foreground without stdin payload: close the pipe immediately
        wait_detached(child, started_at, spec.timeout_secs, tx);
        resp.start_stream(200, "application/x-ndjson")?;
        resp.chunk(format!("{}\n", serde_json::json!({"event": "start", "pid": pid})).as_bytes())?;
        stream_events(&rx, resp)
    }
}

fn wait_detached(child: Child, started_at: i64, timeout_secs: Option<f64>, tx: Sender<Event>) {
    std::thread::spawn(move || wait_and_report(child, started_at, timeout_secs, tx));
}

pub fn handle_logs(
    state: &Arc<State>,
    pid: &str,
    params: &HashMap<String, String>,
    resp: &mut ResponseWriter,
) -> std::io::Result<()> {
    let Some(proc) = pid.parse().ok().and_then(|pid| state.procs.get(pid)) else {
        return resp.error(404, &format!("no such process: {pid}"));
    };
    let follow = params.get("follow").map(|v| v == "true" || v == "1").unwrap_or(false);

    resp.start_stream(200, "application/x-ndjson")?;

    // Snapshot buffered events and (if following) subscribe atomically, so no
    // event is missed or duplicated between replay and live streaming.
    let (snapshot, rx, exited) = {
        let mut proc_state = proc.state.lock().unwrap();
        let snapshot: Vec<Event> = proc_state.events.iter().cloned().collect();
        let exited = proc_state.exit.is_some();
        let rx = if follow && !exited {
            let (tx, rx) = mpsc::channel();
            proc_state.subscribers.push(tx);
            Some(rx)
        } else {
            None
        };
        (snapshot, rx, exited)
    };

    for event in &snapshot {
        resp.chunk(event.to_line().as_bytes())?;
    }
    if let Some(rx) = rx {
        stream_events(&rx, resp)?;
    } else if !exited && follow {
        // raced: proc exited between lookup and subscribe — snapshot already has Exit
    }
    Ok(())
}

pub fn handle_wait(state: &Arc<State>, pid: &str, resp: &mut ResponseWriter) -> std::io::Result<()> {
    let Some(proc) = pid.parse().ok().and_then(|pid| state.procs.get(pid)) else {
        return resp.error(404, &format!("no such process: {pid}"));
    };
    resp.start_stream(200, "application/x-ndjson")?;
    let mut guard = proc.state.lock().unwrap();
    loop {
        if let Some(info) = guard.exit {
            drop(guard);
            return resp.chunk(Event::Exit(info).to_line().as_bytes());
        }
        let (g, timeout) = proc.exited.wait_timeout(guard, PING_INTERVAL).unwrap();
        guard = g;
        if timeout.timed_out() {
            // keepalive ping; must temporarily release the lock to write
            drop(guard);
            resp.chunk(b"{\"event\":\"ping\"}\n")?;
            guard = proc.state.lock().unwrap();
        }
    }
}

pub fn handle_kill(
    state: &Arc<State>,
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    pid: &str,
    resp: &mut ResponseWriter,
) -> std::io::Result<()> {
    let body = read_body(request, reader, 1024 * 1024)?;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::json!({}));
    let Some(proc) = pid.parse().ok().and_then(|pid| state.procs.get(pid)) else {
        return resp.error(404, &format!("no such process: {pid}"));
    };
    let signal = match json.get("signal") {
        Some(serde_json::Value::String(s)) => match s.to_uppercase().as_str() {
            "TERM" | "SIGTERM" => libc::SIGTERM,
            "KILL" | "SIGKILL" => libc::SIGKILL,
            "INT" | "SIGINT" => libc::SIGINT,
            "HUP" | "SIGHUP" => libc::SIGHUP,
            other => return resp.error(400, &format!("unknown signal: {other}")),
        },
        Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(libc::SIGKILL as i64) as i32,
        _ => libc::SIGKILL,
    };
    kill_group(proc.pid, signal);
    resp.json(200, &serde_json::json!({"pid": proc.pid, "signal": signal}))
}

pub fn handle_stdin(
    state: &Arc<State>,
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    pid: &str,
    resp: &mut ResponseWriter,
) -> std::io::Result<()> {
    let Some(proc) = pid.parse().ok().and_then(|pid| state.procs.get(pid)) else {
        return resp.error(404, &format!("no such process: {pid}"));
    };
    let eof = request.params.get("eof").map(|v| v == "true" || v == "1").unwrap_or(false);
    let mut stdin_guard = proc.stdin.lock().unwrap();
    let Some(stdin) = stdin_guard.as_mut() else {
        return resp.error(409, "stdin not available for this process");
    };
    let mut write_error = None;
    let written = stream_body(request, reader, |chunk| {
        if write_error.is_none() {
            if let Err(e) = stdin.write_all(chunk) {
                write_error = Some(e.to_string());
            }
        }
        Ok(())
    })?;
    if let Some(e) = write_error {
        return resp.error(409, &format!("failed to write to stdin: {e}"));
    }
    let _ = stdin.flush();
    if eof {
        *stdin_guard = None; // drop -> close pipe
    }
    resp.json(200, &serde_json::json!({"written": written, "eof": eof}))
}
