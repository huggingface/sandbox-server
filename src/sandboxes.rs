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
use std::ffi::CString;
use std::io::{BufReader, Read};
use std::net::TcpStream;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::http::{read_body, Request, ResponseWriter};
use crate::{now_ms, State};

/// First uid handed out. On HF Jobs the container runs in a user namespace that
/// maps only uids 0..65535, so setuid() to anything above that fails with EINVAL.
/// We stay inside the mapped range and above the uids common images use for
/// their service accounts (which top out in the low thousands; `nobody`=65534).
const UID_BASE: u32 = 20_000;
const UID_MAX: u32 = 65_000;
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
    /// Landlock ruleset fd confining this sandbox (-1 if Landlock unavailable).
    pub landlock_fd: i32,
    /// Last time a request targeted this sandbox; drives idle eviction.
    pub last_activity_ms: AtomicI64,
    /// Evict the sandbox after this many ms with no activity (0 = never).
    pub idle_timeout_ms: i64,
}

/// Why a `create` was refused.
pub enum CreateError {
    /// The host is at `capacity` — the caller should pack onto (or boot) another host.
    Full,
    Io(std::io::Error),
}

pub struct SandboxRegistry {
    map: Mutex<HashMap<String, Arc<SandboxEntry>>>,
    next_uid: AtomicU32,
    /// Max concurrent sandboxes on this host (the pool's `sandboxes_per_host`).
    capacity: usize,
    /// Reserved slots (== live sandboxes once creation settles). Reserved up front so
    /// concurrent creates from different clients can't over-commit past `capacity`.
    reserved: AtomicUsize,
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
    pub fn with_capacity(capacity: usize) -> Self {
        Self { map: Mutex::new(HashMap::new()), next_uid: AtomicU32::new(0), capacity, reserved: AtomicUsize::new(0) }
    }

    /// Create a sandbox, atomically reserving a capacity slot first. Returns
    /// [`CreateError::Full`] (without side effects) when the host is at capacity.
    pub fn create(
        &self,
        env: HashMap<String, String>,
        max_procs: Option<u64>,
        max_mem_mb: Option<u64>,
        idle_timeout_ms: i64,
    ) -> Result<Arc<SandboxEntry>, CreateError> {
        // Reserve a slot before doing any work, so two concurrent creates can't both
        // squeeze past the last free slot.
        if self.reserved.fetch_add(1, Ordering::SeqCst) >= self.capacity {
            self.reserved.fetch_sub(1, Ordering::SeqCst);
            return Err(CreateError::Full);
        }
        match self.create_inner(env, max_procs, max_mem_mb, idle_timeout_ms) {
            Ok(entry) => Ok(entry),
            Err(e) => {
                self.reserved.fetch_sub(1, Ordering::SeqCst); // release the slot we couldn't fill
                Err(CreateError::Io(e))
            }
        }
    }

    fn create_inner(
        &self,
        env: HashMap<String, String>,
        max_procs: Option<u64>,
        max_mem_mb: Option<u64>,
        idle_timeout_ms: i64,
    ) -> std::io::Result<Arc<SandboxEntry>> {
        let offset = self.next_uid.fetch_add(1, Ordering::SeqCst);
        let uid = UID_BASE + offset;
        if uid >= UID_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("sandbox uid pool exhausted (max {} concurrent sandboxes per host)", UID_MAX - UID_BASE),
            ));
        }
        let id = random_id();
        let home = format!("{HOMES_DIR}/{id}");
        std::fs::create_dir_all(&home)?;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
        let tmp = format!("{home}/.tmp");
        std::fs::create_dir_all(&tmp)?;
        // Where the sandbox binds the unix sockets it wants exposed via the port proxy
        // (it can't bind TCP under Landlock). Surfaced as $SBX_PROXY_DIR; see proxy.rs.
        let proxy_dir = format!("{home}/{}", crate::proxy::PROXY_SUBDIR);
        std::fs::create_dir_all(&proxy_dir)?;
        unsafe {
            let c_home = std::ffi::CString::new(home.as_str()).unwrap();
            let c_tmp = std::ffi::CString::new(tmp.as_str()).unwrap();
            libc::chown(c_home.as_ptr(), uid, uid);
            libc::chown(c_tmp.as_ptr(), uid, uid);
        }
        // chown the .sbx/proxy chain so the sandbox uid can create sockets in it.
        chown_into_home(&home, Path::new(&proxy_dir), uid);
        let landlock_fd = crate::landlock::build_ruleset(&home).unwrap_or(-1);
        let entry = Arc::new(SandboxEntry {
            id: id.clone(),
            uid,
            home,
            created_at_ms: now_ms(),
            env,
            max_procs: max_procs.unwrap_or(DEFAULT_MAX_PROCS),
            max_mem_mb: max_mem_mb.unwrap_or(DEFAULT_MAX_MEM_MB),
            landlock_fd,
            last_activity_ms: AtomicI64::new(now_ms()),
            idle_timeout_ms,
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

    /// Record activity on a sandbox (resets its idle timer).
    pub fn touch(&self, id: &str) {
        if let Some(entry) = self.map.lock().unwrap().get(id) {
            entry.last_activity_ms.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// Ids of sandboxes idle longer than their `idle_timeout_ms` (0 == never). The
    /// watchdog still checks for running processes before evicting them.
    pub fn idle_candidates(&self, now: i64) -> Vec<String> {
        self.map
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.idle_timeout_ms > 0 && now - e.last_activity_ms.load(Ordering::Relaxed) > e.idle_timeout_ms)
            .map(|e| e.id.clone())
            .collect()
    }

    /// Kill every process owned by the sandbox uid, then remove its home.
    pub fn delete(&self, id: &str) -> bool {
        let Some(entry) = self.map.lock().unwrap().remove(id) else { return false };
        self.reserved.fetch_sub(1, Ordering::SeqCst); // free the capacity slot
        kill_uid(entry.uid);
        if entry.landlock_fd >= 0 {
            unsafe { libc::close(entry.landlock_fd) };
        }
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
    let landlock_fd = entry.landlock_fd;
    move || {
        unsafe {
            // setuid binaries (su, passwd, ...) must not elevate back to root.
            // Also a prerequisite for unprivileged Landlock enforcement.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Confine the filesystem/network view to this sandbox (see landlock module).
            if landlock_fd >= 0 {
                crate::landlock::restrict_self(landlock_fd)?;
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
        // Bind a unix socket at $SBX_PROXY_DIR/<port>.sock to expose it via the port proxy.
        ("SBX_PROXY_DIR".to_string(), format!("{}/{}", entry.home, crate::proxy::PROXY_SUBDIR)),
    ];
    env.extend(entry.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

// ---------------------------------------------------------------------------
// Per-sandbox filesystem helpers
// ---------------------------------------------------------------------------

/// Resolve a user-facing path to an absolute path confined to the sandbox home.
///
/// In host mode a sandbox's writable view is its home (Landlock confines the
/// running code to it), so the file API roots every path at the home: a path is
/// taken relative to the home (a leading `/` is ignored) and `..` components can
/// never climb above it. This gives the caller a clean "filesystem rooted at the
/// sandbox" model that matches what code running inside the sandbox can touch.
pub fn resolve_in_home(home: &str, path: &str) -> PathBuf {
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::Normal(c) => stack.push(c.to_os_string()),
            Component::ParentDir => {
                stack.pop();
            }
            // RootDir / CurDir / Prefix are dropped: everything is relative to home.
            _ => {}
        }
    }
    let mut result = PathBuf::from(home);
    for c in stack {
        result.push(c);
    }
    result
}

fn chown(path: &Path, uid: u32) {
    if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
        unsafe {
            libc::chown(c.as_ptr(), uid, uid);
        }
    }
}

/// Chown `target` and every ancestor up to (but excluding) `home` to `uid`, so
/// files placed through the API are owned by the sandbox and readable/writable
/// by its code (which runs as `uid`). Anything created as root would otherwise
/// be inaccessible to the sandbox.
pub fn chown_into_home(home: &str, target: &Path, uid: u32) {
    let home_path = Path::new(home);
    let mut cur = Some(target);
    while let Some(p) = cur {
        if p == home_path || !p.starts_with(home_path) {
            break;
        }
        chown(p, uid);
        cur = p.parent();
    }
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
    let env: HashMap<String, String> = crate::json_string_map(&json, "env");
    let max_procs = json.get("max_procs").and_then(|v| v.as_u64());
    let max_mem_mb = json.get("max_mem_mb").and_then(|v| v.as_u64());
    // Per-sandbox idle timeout (the host has its own, for when it's empty). 0 = never.
    let idle_timeout_ms = json.get("idle_timeout_secs").and_then(|v| v.as_i64()).unwrap_or(0) * 1000;

    let mut created = Vec::with_capacity(count);
    let mut rejected = 0usize;
    for _ in 0..count {
        match state.sandboxes.create(env.clone(), max_procs, max_mem_mb, idle_timeout_ms) {
            Ok(entry) => created.push(serde_json::json!({"id": entry.id, "uid": entry.uid, "home": entry.home})),
            // Host full: report how many we couldn't place so the client packs them
            // onto another host (or boots a duplicate). Not an error.
            Err(CreateError::Full) => {
                rejected = count - created.len();
                break;
            }
            Err(CreateError::Io(e)) => return resp.error(500, &format!("failed to create sandbox: {e}")),
        }
    }
    resp.json(200, &serde_json::json!({"sandboxes": created, "rejected": rejected}))
}

pub fn handle_delete(state: &Arc<State>, id: &str, resp: &mut ResponseWriter) -> std::io::Result<()> {
    if state.sandboxes.delete(id) {
        state.procs.remove_for_sandbox(id);
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
        state.procs.remove_for_sandbox(&id);
    }
    resp.json(200, &serde_json::json!({"deleted": n}))
}
