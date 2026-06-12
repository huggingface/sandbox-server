//! Host mode: many lightweight sandboxes inside one job.
//!
//! A sandbox is a dedicated uid + a private 0700 home directory. Commands run
//! with that uid, a scrubbed environment, NO_NEW_PRIVS (setuid binaries cannot
//! elevate) and per-uid/per-process rlimits. This is the classic multi-user
//! Unix isolation model: sandboxes cannot signal, ptrace or read each other
//! (or the server), while creation costs ~1ms — no nested container or extra
//! job needed. Requires running as root with CAP_SETUID/CAP_SETGID/CAP_KILL
//! (the Docker default set on HF Jobs).

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use crate::http::{read_body, Request, ResponseWriter};
use crate::{now_ms, State};

/// First uid handed out; far above any uid shipped in common images.
const UID_BASE: u32 = 100_000;
const HOMES_DIR: &str = "/sbx/homes";

/// Default per-sandbox rlimits (overridable per sandbox at creation).
const DEFAULT_MAX_PROCS: u64 = 256; // RLIMIT_NPROC is per-uid == per-sandbox
const DEFAULT_MAX_MEM_MB: u64 = 2048; // RLIMIT_AS, per process

pub struct SandboxEntry {
    pub id: String,
    pub uid: u32,
    pub home: String,
    pub created_at_ms: i64,
    pub env: HashMap<String, String>,
    pub max_procs: u64,
    pub max_mem_mb: u64,
}

#[derive(Default)]
pub struct SandboxRegistry {
    map: Mutex<HashMap<String, Arc<SandboxEntry>>>,
    next_uid: AtomicU32,
}

fn random_id() -> String {
    let mut buf = [0u8; 8];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).is_err() {
        // /dev/urandom always exists on Linux; fallback just in case
        let t = now_ms() as u64;
        buf.copy_from_slice(&t.to_le_bytes());
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl SandboxRegistry {
    pub fn create(
        &self,
        env: HashMap<String, String>,
        max_procs: Option<u64>,
        max_mem_mb: Option<u64>,
    ) -> std::io::Result<Arc<SandboxEntry>> {
        let uid = UID_BASE + self.next_uid.fetch_add(1, Ordering::SeqCst);
        let id = random_id();
        let home = format!("{HOMES_DIR}/{id}");
        std::fs::create_dir_all(&home)?;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
        let tmp = format!("{home}/.tmp");
        std::fs::create_dir_all(&tmp)?;
        unsafe {
            let c_home = std::ffi::CString::new(home.as_str()).unwrap();
            let c_tmp = std::ffi::CString::new(tmp.as_str()).unwrap();
            libc::chown(c_home.as_ptr(), uid, uid);
            libc::chown(c_tmp.as_ptr(), uid, uid);
        }
        let entry = Arc::new(SandboxEntry {
            id: id.clone(),
            uid,
            home,
            created_at_ms: now_ms(),
            env,
            max_procs: max_procs.unwrap_or(DEFAULT_MAX_PROCS),
            max_mem_mb: max_mem_mb.unwrap_or(DEFAULT_MAX_MEM_MB),
        });
        self.map.lock().unwrap().insert(id, Arc::clone(&entry));
        Ok(entry)
    }

    pub fn get(&self, id: &str) -> Option<Arc<SandboxEntry>> {
        self.map.lock().unwrap().get(id).cloned()
    }

    pub fn ids(&self) -> Vec<String> {
        self.map.lock().unwrap().keys().cloned().collect()
    }

    /// Kill every process owned by the sandbox uid, then remove its home.
    pub fn delete(&self, id: &str) -> bool {
        let Some(entry) = self.map.lock().unwrap().remove(id) else { return false };
        kill_uid(entry.uid);
        let _ = std::fs::remove_dir_all(&entry.home);
        true
    }

    pub fn list(&self) -> serde_json::Value {
        let map = self.map.lock().unwrap();
        serde_json::Value::Array(
            map.values()
                .map(|s| {
                    serde_json::json!({
                        "id": s.id,
                        "uid": s.uid,
                        "home": s.home,
                        "created_at_ms": s.created_at_ms,
                    })
                })
                .collect(),
        )
    }

    pub fn count(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

/// SIGKILL every process whose real uid matches, repeating until none are left
/// (children may be forking; RLIMIT_NPROC bounds how long this can take).
fn kill_uid(uid: u32) {
    for _ in 0..50 {
        let pids = pids_of_uid(uid);
        if pids.is_empty() {
            return;
        }
        for pid in pids {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn pids_of_uid(uid: u32) -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut pids = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
        // "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
        let real_uid = status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u32>().ok());
        if real_uid == Some(uid) {
            pids.push(pid);
        }
    }
    pids
}

/// Applied to the child between fork and exec (see exec::spawn).
pub fn pre_exec_isolation(entry: &SandboxEntry) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    let max_procs = entry.max_procs;
    let max_mem = entry.max_mem_mb * 1024 * 1024;
    move || {
        unsafe {
            // setuid binaries (su, passwd, ...) must not elevate back to root.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let nproc = libc::rlimit { rlim_cur: max_procs, rlim_max: max_procs };
            let mem = libc::rlimit { rlim_cur: max_mem, rlim_max: max_mem };
            let core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_NPROC, &nproc) != 0 || libc::setrlimit(libc::RLIMIT_AS, &mem) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::setrlimit(libc::RLIMIT_CORE, &core);
        }
        Ok(())
    }
}

/// Base environment for sandboxed processes (the parent env is never inherited:
/// it may contain job secrets that belong to the host, not the sandboxes).
pub fn base_env(entry: &SandboxEntry) -> Vec<(String, String)> {
    let mut env = vec![
        ("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()),
        ("HOME".to_string(), entry.home.clone()),
        ("TMPDIR".to_string(), format!("{}/.tmp", entry.home)),
        ("USER".to_string(), format!("sbx-{}", entry.id)),
        ("LOGNAME".to_string(), format!("sbx-{}", entry.id)),
        ("SBX_SANDBOX_ID".to_string(), entry.id.clone()),
    ];
    env.extend(entry.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

pub fn handle_create(
    state: &Arc<State>,
    request: &mut Request,
    reader: &mut BufReader<TcpStream>,
    resp: &mut ResponseWriter,
) -> std::io::Result<()> {
    let body = read_body(request, reader, 1024 * 1024)?;
    let json: serde_json::Value =
        if body.is_empty() { serde_json::json!({}) } else { serde_json::from_slice(&body).unwrap_or(serde_json::json!({})) };
    let count = json.get("count").and_then(|v| v.as_u64()).unwrap_or(1).clamp(1, 4096) as usize;
    let env: HashMap<String, String> = json
        .get("env")
        .and_then(|v| v.as_object())
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect())
        .unwrap_or_default();
    let max_procs = json.get("max_procs").and_then(|v| v.as_u64());
    let max_mem_mb = json.get("max_mem_mb").and_then(|v| v.as_u64());

    let mut created = Vec::with_capacity(count);
    for _ in 0..count {
        match state.sandboxes.create(env.clone(), max_procs, max_mem_mb) {
            Ok(entry) => created.push(serde_json::json!({"id": entry.id, "uid": entry.uid, "home": entry.home})),
            Err(e) => return resp.error(500, &format!("failed to create sandbox: {e}")),
        }
    }
    resp.json(200, &serde_json::json!({"sandboxes": created}))
}

pub fn handle_delete(state: &Arc<State>, id: &str, resp: &mut ResponseWriter) -> std::io::Result<()> {
    if state.sandboxes.delete(id) {
        resp.json(200, &serde_json::json!({"id": id, "deleted": true}))
    } else {
        resp.error(404, &format!("no such sandbox: {id}"))
    }
}

/// DELETE /v1/sandboxes — delete all sandboxes (bulk cleanup).
pub fn handle_delete_all(state: &Arc<State>, resp: &mut ResponseWriter) -> std::io::Result<()> {
    let ids = state.sandboxes.ids();
    let n = ids.len();
    for id in ids {
        state.sandboxes.delete(&id);
    }
    resp.json(200, &serde_json::json!({"deleted": n}))
}
