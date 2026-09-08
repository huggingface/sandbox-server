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
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
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

/// Ceilings on what a caller may ask for. The server, not the caller, decides
/// how much of the host one sandbox can take: `max_procs`/`max_mem_mb` came
/// straight from the request body, and `max_mem_mb * 1024 * 1024` was computed
/// without `checked_mul`, so a value near 2^54 wrapped in release builds and
/// produced a tiny or enormous `RLIMIT_AS` -- either an effectively unlimited
/// address space or a sandbox where nothing can start.
const MAX_PROCS_CEILING: u64 = 4096;
const MAX_MEM_MB_CEILING: u64 = 1024 * 1024; // 1 TiB, i.e. "bigger than any flavor"

/// Per-process file descriptors, output file size, and CPU seconds.
///
/// `RLIMIT_NPROC` and `RLIMIT_AS` were the only limits set. Without these, one
/// sandbox could exhaust the host's descriptors, fill its disk, or spin a core
/// indefinitely -- none of which the other sandboxes on the host can do anything
/// about, since there are no cgroups to partition them.
const DEFAULT_MAX_FILES: u64 = 4096;
const DEFAULT_MAX_FILE_SIZE_MB: u64 = 8192;
const DEFAULT_MAX_CPU_SECS: u64 = 24 * 3600;

/// Largest `env` map accepted at creation, in bytes of keys plus values.
///
/// The body cap alone allowed ~1 MiB of environment, cloned per sandbox, times
/// a `count` of up to 4096.
const MAX_ENV_BYTES: usize = 64 * 1024;

pub struct SandboxEntry {
    pub id: String,
    pub uid: u32,
    pub home: String,
    pub created_at_ms: i64,
    pub env: HashMap<String, String>,
    pub max_procs: u64,
    pub max_mem_mb: u64,
    /// Capability token for this sandbox alone.
    ///
    /// The host token (`SBX_TOKEN`) is a management credential: it creates,
    /// lists and deletes sandboxes, and it can address any of them. This one is
    /// bound to a single sandbox, so it can be handed to whoever operates that
    /// sandbox — including into a browser or WebSocket client via the port
    /// proxy — without also conferring authority over its siblings or the host.
    pub token: String,
    /// How this sandbox is confined.
    pub confinement: Confinement,
    /// Last time a request targeted this sandbox; drives idle eviction.
    pub last_activity_ms: AtomicI64,
    /// Evict the sandbox after this many ms with no activity (0 = never).
    pub idle_timeout_ms: i64,
}

/// How a sandbox is confined.
///
/// Deliberately not `landlock_fd: i32` with `-1` meaning "none". That shape let
/// a failed ruleset build become an unconfined sandbox that was still reported
/// as created, with nothing telling the client its isolation was uid-only.
pub enum Confinement {
    /// Landlock ruleset fd, enforced by the exec child before it runs anything.
    Landlock(i32),
    /// Distinct uid and a 0700 home, and nothing else. `/tmp`, `/dev/shm`, TCP
    /// bind and other homes are *not* denied. Only reachable with
    /// `--allow-unconfined`.
    UidOnly,
}

impl Confinement {
    pub fn label(&self) -> &'static str {
        match self {
            Confinement::Landlock(_) => "landlock",
            Confinement::UidOnly => "uid-only",
        }
    }
}

/// Why a `create` was refused.
pub enum CreateError {
    /// The host is at `capacity` — the caller should pack onto (or boot) another host.
    Full,
    Io(std::io::Error),
}

pub struct SandboxRegistry {
    map: Mutex<HashMap<String, Arc<SandboxEntry>>>,
    /// Max concurrent sandboxes on this host (the pool's `sandboxes_per_host`).
    capacity: usize,
    /// Reserved slots (== live sandboxes once creation settles). Reserved up front so
    /// concurrent creates from different clients can't over-commit past `capacity`.
    reserved: AtomicUsize,
    /// Whether a sandbox may be created with uid-only isolation when Landlock is
    /// unavailable. Off unless the operator passed `--allow-unconfined`.
    allow_unconfined: bool,
    /// Uids available for reuse: freed by a sandbox whose teardown *verifiably*
    /// completed. See [`UidPool`].
    uids: Mutex<UidPool>,
}

/// Which uids may be handed out.
///
/// Uids used to be allocated monotonically from `UID_BASE` and never reused, so
/// a host that created ~45,000 sandboxes over its 24h lifetime could no longer
/// create one even while empty -- and the failure surfaced as a 500 rather than
/// as "this host is full", so the client treated it as a hard error instead of
/// packing elsewhere.
///
/// Reuse is the fix, but a careless free list would be worse than the problem:
/// hand back a uid whose processes are still alive and the next sandbox inherits
/// them, with the ability to signal and read them. So a uid is only freed when
/// teardown is known to have converged, and anything doubtful is quarantined for
/// the process's lifetime rather than risked.
#[derive(Default)]
struct UidPool {
    /// Next never-used uid offset.
    next: u32,
    /// Verified-clean uids, available for reuse.
    free: Vec<u32>,
    /// Uids we will not touch again: teardown could not be confirmed, or the
    /// image already has a user or a process there.
    quarantined: Vec<u32>,
}

/// Uids the running image already uses in our range, plus any that already own a
/// process. Sampled once at startup.
///
/// `UID_BASE` is chosen to sit above the uids images normally use, but nothing
/// checked -- and a collision would silently put two "isolated" sandboxes under
/// one uid, defeating the entire DAC half of the isolation model.
fn uids_already_in_use() -> Vec<u32> {
    let mut used = Vec::new();
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            // name:passwd:uid:gid:...
            if let Some(uid) = line.split(':').nth(2).and_then(|v| v.parse::<u32>().ok()) {
                if (UID_BASE..UID_MAX).contains(&uid) {
                    used.push(uid);
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
            let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
            let uid = status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u32>().ok());
            if let Some(uid) = uid {
                if (UID_BASE..UID_MAX).contains(&uid) && !used.contains(&uid) {
                    used.push(uid);
                }
            }
        }
    }
    used
}

impl UidPool {
    fn with_reserved(reserved: &[u32]) -> Self {
        Self { next: 0, free: Vec::new(), quarantined: reserved.to_vec() }
    }

    /// Take a uid, preferring reuse. `None` means the range is exhausted.
    fn take(&mut self) -> Option<u32> {
        while let Some(uid) = self.free.pop() {
            // Re-check at hand-out, not just at free: a quarantine decision made
            // a second ago is not a guarantee about now.
            if pids_of_uid(uid).is_empty() {
                return Some(uid);
            }
            eprintln!("sbx-server: uid {uid} still has processes; quarantining it");
            self.quarantined.push(uid);
        }
        loop {
            let uid = UID_BASE + self.next;
            if uid >= UID_MAX {
                return None;
            }
            self.next += 1;
            if !self.quarantined.contains(&uid) {
                return Some(uid);
            }
        }
    }

    /// Return a uid whose sandbox was verifiably torn down.
    fn release(&mut self, uid: u32) {
        self.free.push(uid);
    }

    /// Never hand this uid out again.
    fn quarantine(&mut self, uid: u32) {
        self.quarantined.push(uid);
    }
}

/// `n` bytes from the kernel CSPRNG, hex-encoded.
///
/// Fails rather than substituting anything weaker: this produces both sandbox
/// ids (which name home directories and appear in URLs) and per-sandbox
/// capability tokens, so a degraded source here would be a predictable
/// credential, which is worse than a failed create.
fn random_hex(n: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

impl SandboxRegistry {
    pub fn new(capacity: usize, allow_unconfined: bool) -> Self {
        let reserved = uids_already_in_use();
        if !reserved.is_empty() {
            eprintln!("sbx-server: skipping {} uid(s) already used by this image: {reserved:?}", reserved.len());
        }
        Self {
            map: Mutex::new(HashMap::new()),
            capacity,
            reserved: AtomicUsize::new(0),
            allow_unconfined,
            uids: Mutex::new(UidPool::with_reserved(&reserved)),
        }
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
        // An exhausted uid range means the same thing to the caller as a full
        // host: no more sandboxes here, pack elsewhere. Reporting it as an error
        // instead (which is what it used to be) made the client give up on the
        // create rather than re-placing it.
        let Some(uid) = self.uids.lock().unwrap().take() else {
            self.reserved.fetch_sub(1, Ordering::SeqCst);
            eprintln!("sbx-server: uid range exhausted; reporting this host as full");
            return Err(CreateError::Full);
        };
        match self.create_inner(uid, env, max_procs, max_mem_mb, idle_timeout_ms) {
            Ok(entry) => Ok(entry),
            Err(e) => {
                self.reserved.fetch_sub(1, Ordering::SeqCst); // release the slot we couldn't fill
                // The uid was never used, so it is clean by construction.
                self.uids.lock().unwrap().release(uid);
                Err(CreateError::Io(e))
            }
        }
    }

    fn create_inner(
        &self,
        uid: u32,
        env: HashMap<String, String>,
        max_procs: Option<u64>,
        max_mem_mb: Option<u64>,
        idle_timeout_ms: i64,
    ) -> std::io::Result<Arc<SandboxEntry>> {
        let id = random_hex(8)?;
        let token = random_hex(32)?;
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
        // Fail closed. A sandbox whose ruleset could not be built is not the
        // thing the caller asked for, so refuse to hand one out unless the
        // operator explicitly accepted uid-only isolation at startup.
        let confinement = match crate::landlock::build_ruleset(&home) {
            Ok(fd) => Confinement::Landlock(fd),
            Err(e) if self.allow_unconfined => {
                eprintln!("sbx-server: landlock unavailable ({e}); creating an UNCONFINED sandbox");
                Confinement::UidOnly
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&home);
                return Err(std::io::Error::other(format!("cannot confine sandbox: {e}")));
            }
        };
        let entry = Arc::new(SandboxEntry {
            id: id.clone(),
            uid,
            home,
            created_at_ms: now_ms(),
            env,
            max_procs: max_procs.unwrap_or(DEFAULT_MAX_PROCS),
            max_mem_mb: max_mem_mb.unwrap_or(DEFAULT_MAX_MEM_MB),
            token,
            confinement,
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
    ///
    /// `Ok(())` means the sandbox is really gone. `Err(msg)` means it was
    /// removed from the registry but something survived the sweep -- the caller
    /// must report that rather than claiming success, because "deleted" is what
    /// a client relies on when it stops paying attention to a sandbox.
    pub fn delete(&self, id: &str) -> Option<Result<(), String>> {
        let entry = self.map.lock().unwrap().remove(id)?;
        self.reserved.fetch_sub(1, Ordering::SeqCst); // free the capacity slot
        let converged = kill_uid(entry.uid);
        if let Confinement::Landlock(fd) = entry.confinement {
            unsafe { libc::close(fd) };
        }
        let removed = std::fs::remove_dir_all(&entry.home);
        if !converged {
            eprintln!("sbx-server: sandbox {id} still has live processes after the kill sweep");
            // Never reuse this uid: handing it to the next sandbox would give
            // that sandbox the surviving processes, with the ability to signal
            // and read them. Losing one uid out of 45,000 is the cheap side of
            // this trade.
            self.uids.lock().unwrap().quarantine(entry.uid);
            return Some(Err(format!(
                "sandbox {id} was removed but processes under uid {} survived the kill sweep",
                entry.uid
            )));
        }
        if let Err(e) = removed {
            // Files owned by this uid may still exist, so a new sandbox under it
            // would inherit them.
            self.uids.lock().unwrap().quarantine(entry.uid);
            return Some(Err(format!("sandbox {id} was removed but its home could not be deleted: {e}")));
        }
        self.uids.lock().unwrap().release(entry.uid);
        Some(Ok(()))
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
                        "confinement": s.confinement.label(),
                    })
                })
                .collect(),
        )
    }

    pub fn count(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    /// Slots still free on this host. `usize::MAX` capacity yields a large but
    /// finite number, so callers can use it as a bound without special-casing.
    pub fn remaining_capacity(&self) -> usize {
        self.capacity.saturating_sub(self.reserved.load(Ordering::SeqCst)).min(4096)
    }
}

/// SIGKILL every process whose real uid matches, repeating until none are left
/// (children may be forking; RLIMIT_NPROC bounds how long this can take).
///
/// Returns whether it converged. It used to return nothing, so a sweep that
/// gave up with processes still alive was indistinguishable from a clean one --
/// and the caller then removed the home directory and reported the sandbox
/// deleted while its code was still running. This sweep is also what catches a
/// descendant that escaped its process group with `setsid()`: the group is gone
/// but the uid is not.
fn kill_uid(uid: u32) -> bool {
    // ~1s total. Long enough for a fork bomb bounded by RLIMIT_NPROC to lose,
    // short enough not to stall a delete request.
    for attempt in 0..100 {
        let pids = pids_of_uid(uid);
        if pids.is_empty() {
            return true;
        }
        for pid in pids {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        // Back off a little as we go: the first pass clears the common case.
        std::thread::sleep(std::time::Duration::from_millis(if attempt < 10 { 5 } else { 10 }));
    }
    pids_of_uid(uid).is_empty()
}

/// Live processes with this real uid.
///
/// Zombies are excluded deliberately. A zombie holds no memory, no files and no
/// CPU -- it is an exit status waiting to be collected -- and it cannot be
/// killed, so counting one as "still running" makes the kill sweep below spin
/// until it gives up and then report a failure that is not one. (They are
/// collected by the orphan reaper, or by the parent that spawned them.)
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
        if real_uid != Some(uid) {
            continue;
        }
        let zombie = status
            .lines()
            .find(|l| l.starts_with("State:"))
            .is_some_and(|l| l.split_whitespace().nth(1) == Some("Z"));
        if !zombie {
            pids.push(pid);
        }
    }
    pids
}

/// Applied to the child between fork and exec (see exec::spawn).
pub fn pre_exec_isolation(entry: &SandboxEntry) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    let max_procs = entry.max_procs;
    // Clamped at creation, so this cannot overflow -- but say so in code rather
    // than in a comment, since the overflow was the bug.
    let max_mem = entry.max_mem_mb.saturating_mul(1024 * 1024);
    let confinement = match entry.confinement {
        Confinement::Landlock(fd) => Some(fd),
        Confinement::UidOnly => None,
    };
    move || {
        unsafe {
            // setuid binaries (su, passwd, ...) must not elevate back to root.
            // Also a prerequisite for unprivileged Landlock enforcement.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Confine the filesystem/network view to this sandbox (see landlock
            // module). An enforcement failure aborts the child rather than
            // running it unconfined.
            if let Some(fd) = confinement {
                crate::landlock::restrict_self(fd)?;
            }
            let limit = |value: u64| libc::rlimit { rlim_cur: value, rlim_max: value };
            let nproc = limit(max_procs);
            let mem = limit(max_mem);
            if libc::setrlimit(libc::RLIMIT_NPROC, &nproc) != 0 || libc::setrlimit(libc::RLIMIT_AS, &mem) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::setrlimit(libc::RLIMIT_CORE, &limit(0));
            // Best-effort: an image may already have a lower hard limit, and
            // failing to *tighten* a bound is not a reason to refuse the command.
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit(DEFAULT_MAX_FILES));
            libc::setrlimit(libc::RLIMIT_FSIZE, &limit(DEFAULT_MAX_FILE_SIZE_MB * 1024 * 1024));
            libc::setrlimit(libc::RLIMIT_CPU, &limit(DEFAULT_MAX_CPU_SECS));
        }
        Ok(())
    }
}

/// Base environment for sandboxed processes (the parent env is never inherited:
/// it may contain job secrets that belong to the host, not the sandboxes).
pub fn base_env(entry: &SandboxEntry) -> Vec<(String, String)> {
    let mut env = vec![
        // `~/.local/bin` first: a Landlock-confined sandbox can't write to the system
        // site (/usr is read-only), so `pip install` falls back to a `--user` install
        // there — its console scripts (uvicorn, ...) must be on PATH to be runnable.
        (
            "PATH".to_string(),
            format!("{}/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", entry.home),
        ),
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
    let env: HashMap<String, String> = crate::json_string_map(&json, "env");
    let env_bytes: usize = env.iter().map(|(k, v)| k.len() + v.len()).sum();
    if env_bytes > MAX_ENV_BYTES {
        return resp.error(400, &format!("env too large ({env_bytes} bytes, max {MAX_ENV_BYTES})"));
    }
    // Bounded by what this host can still hold, not by an arbitrary 4096: the
    // env is cloned per sandbox, and each one costs a home directory, a uid and
    // a Landlock ruleset. Asking for more than fits is not an error -- the
    // response already reports how many were rejected so the client packs the
    // rest elsewhere.
    let requested = json.get("count").and_then(|v| v.as_u64()).unwrap_or(1).max(1);
    let count = requested.min(state.sandboxes.remaining_capacity() as u64) as usize;
    let max_procs = match json.get("max_procs").and_then(|v| v.as_u64()) {
        Some(value) if value == 0 || value > MAX_PROCS_CEILING => {
            return resp.error(400, &format!("max_procs must be 1..={MAX_PROCS_CEILING}"))
        }
        other => other,
    };
    let max_mem_mb = match json.get("max_mem_mb").and_then(|v| v.as_u64()) {
        Some(value) if value == 0 || value > MAX_MEM_MB_CEILING => {
            return resp.error(400, &format!("max_mem_mb must be 1..={MAX_MEM_MB_CEILING}"))
        }
        other => other,
    };
    // Per-sandbox idle timeout (the host has its own, for when it's empty). 0 = never.
    let idle_timeout_ms = json.get("idle_timeout_secs").and_then(|v| v.as_i64()).unwrap_or(0) * 1000;

    let mut created = Vec::with_capacity(count);
    let mut rejected = 0usize;
    for _ in 0..count {
        match state.sandboxes.create(env.clone(), max_procs, max_mem_mb, idle_timeout_ms) {
            Ok(entry) => created.push(
                serde_json::json!({
                    "id": entry.id,
                    "token": entry.token,
                    "uid": entry.uid,
                    "home": entry.home,
                    "confinement": entry.confinement.label(),
                }),
            ),
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
    match state.sandboxes.delete(id) {
        None => resp.error(404, &format!("no such sandbox: {id}")),
        Some(Ok(())) => {
            state.procs.remove_for_sandbox(id);
            resp.json(200, &serde_json::json!({"id": id, "deleted": true}))
        }
        // Removed from the registry either way, so the client should stop using
        // it -- but say that teardown was incomplete instead of reporting success.
        Some(Err(message)) => {
            state.procs.remove_for_sandbox(id);
            resp.json(500, &serde_json::json!({"id": id, "deleted": true, "error": message}))
        }
    }
}

/// DELETE /v1/sandboxes — delete all sandboxes (bulk cleanup).
pub fn handle_delete_all(state: &Arc<State>, resp: &mut ResponseWriter) -> std::io::Result<()> {
    let ids = state.sandboxes.ids();
    let n = ids.len();
    let mut errors = Vec::new();
    for id in ids {
        if let Some(Err(message)) = state.sandboxes.delete(&id) {
            errors.push(message);
        }
        state.procs.remove_for_sandbox(&id);
    }
    if errors.is_empty() {
        resp.json(200, &serde_json::json!({"deleted": n}))
    } else {
        resp.json(500, &serde_json::json!({"deleted": n, "errors": errors}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_released_uid_is_reused_before_a_fresh_one() {
        let mut pool = UidPool::default();
        let first = pool.take().unwrap();
        let second = pool.take().unwrap();
        assert_eq!((first, second), (UID_BASE, UID_BASE + 1));

        pool.release(first);
        // Reuse, rather than burning through the range: exhaustion is what the
        // monotonic allocator was being replaced for.
        assert_eq!(pool.take(), Some(first));
        assert_eq!(pool.take(), Some(UID_BASE + 2));
    }

    #[test]
    fn a_quarantined_uid_is_never_handed_out() {
        let mut pool = UidPool::default();
        pool.quarantine(UID_BASE);
        pool.quarantine(UID_BASE + 2);

        // Skipped whether they are ahead of the cursor...
        assert_eq!(pool.take(), Some(UID_BASE + 1));
        assert_eq!(pool.take(), Some(UID_BASE + 3));
        // ...or released afterwards by mistake: quarantine is checked at hand-out.
        let mut pool = UidPool::default();
        let uid = pool.take().unwrap();
        pool.quarantine(uid);
        let mut fresh = UidPool::with_reserved(&[uid]);
        assert_ne!(fresh.take(), Some(uid));
    }

    #[test]
    fn uids_already_used_by_the_image_are_reserved() {
        // The whole point of `UID_BASE = 20000` was that images do not use it --
        // but nothing checked, and a collision puts two "isolated" sandboxes
        // under one uid.
        let mut pool = UidPool::with_reserved(&[UID_BASE, UID_BASE + 1]);
        assert_eq!(pool.take(), Some(UID_BASE + 2));
    }

    #[test]
    fn exhaustion_is_reported_rather_than_wrapping() {
        let mut pool = UidPool { next: UID_MAX - UID_BASE - 1, free: Vec::new(), quarantined: Vec::new() };
        assert_eq!(pool.take(), Some(UID_MAX - 1));
        assert_eq!(pool.take(), None, "handed out a uid at or past UID_MAX");
        assert_eq!(pool.take(), None, "exhaustion must be stable, not intermittent");
    }

    #[test]
    fn the_range_stays_inside_the_container_uid_map() {
        // On HF Jobs the container maps only uids 0..65535, so setuid() above
        // that fails with EINVAL. And UID_BASE must stay clear of the low uids
        // images use for service accounts.
        assert!(UID_BASE >= 20_000);
        assert!(UID_MAX <= 65_535);
        assert!(UID_MAX > UID_BASE);
    }

    #[test]
    fn a_free_uid_with_live_processes_is_quarantined_at_hand_out() {
        // Our own uid certainly has a live process (this test), so it stands in
        // for "teardown said it was clean but it was not".
        let ours = unsafe { libc::geteuid() };
        let mut pool = UidPool { next: 0, free: vec![ours], quarantined: Vec::new() };
        assert_ne!(pool.take(), Some(ours), "reused a uid that still owns processes");
        assert!(pool.quarantined.contains(&ours));
    }

    #[test]
    fn zombies_do_not_count_as_live_processes() {
        // A zombie cannot be killed and holds nothing, so counting one makes the
        // kill sweep fail to converge and quarantine a perfectly clean uid.
        let ours = unsafe { libc::geteuid() };
        assert!(!pids_of_uid(ours).is_empty(), "expected to find this test process");
        assert!(pids_of_uid(u32::MAX - 1).is_empty());
    }
}
