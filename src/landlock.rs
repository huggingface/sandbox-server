//! Landlock LSM confinement (unprivileged, no namespaces/cgroups/mount needed).
//!
//! On HF Jobs the container can't create namespaces (seccomp blocks `unshare`)
//! or delegate cgroups, but the kernel (6.12) ships Landlock ABI 6, which any
//! process can use to restrict ITSELF and its `execve`'d children — exactly the
//! per-sandbox boundary we need. The server builds one ruleset per sandbox and
//! the exec child calls `restrict_self` before running the command, so the
//! sandboxed process can only:
//!   - read/execute system dirs (/usr, /bin, /lib, /etc, ...) read-only,
//!   - read+write strictly within its own home,
//!   - read /proc and /sys, read+write the standard /dev nodes,
//! and CANNOT:
//!   - touch /tmp, /dev/shm or any other sandbox's home (closes the shared-fs,
//!     symlink-squat and cross-home channels),
//!   - bind a TCP port (closes inter-sandbox localhost services — outbound
//!     connect stays allowed so the sandbox keeps internet access),
//!   - connect to abstract unix sockets outside its domain, or signal processes
//!     outside its domain (ABI 6 scoping; defense-in-depth over uid isolation).
//!
//! Implemented with raw syscalls to stay a zero-dependency static binary.

use std::ffi::CString;
use std::os::unix::io::RawFd;

// x86_64 syscall numbers (build target is x86_64-unknown-linux-musl).
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

// access_fs bits
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const FS_IOCTL_DEV: u64 = 1 << 15;
// All ABI-1 bits (execute..make_sym) controlled, so anything not granted is denied.
const FS_BASE: u64 = (1 << 13) - 1;

// access_net bits
const NET_BIND_TCP: u64 = 1 << 0;

// scoped bits (ABI 6)
const SCOPED_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPED_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

// NOTE: the kernel declares this struct __attribute__((packed)).
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

fn abi_version() -> i32 {
    unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<u8>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION) as i32 }
}

/// Whether Landlock is usable on this kernel (built-in and enabled at boot).
pub fn available() -> bool {
    abi_version() >= 1
}

fn add_path_rule(ruleset_fd: RawFd, path: &str, access: u64) {
    let Ok(c_path) = CString::new(path) else { return };
    // O_PATH|O_CLOEXEC: we only need the fd to identify the inode for the rule.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return; // path absent in this image — skip silently
    }
    let attr = PathBeneathAttr { allowed_access: access, parent_fd: fd };
    unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const _ as *const libc::c_void,
            0u32,
        );
        libc::close(fd);
    }
}

/// Build a ruleset confining a sandbox to its `home`. Returns the ruleset fd
/// (to be passed to `restrict_self` in the exec child), or None if Landlock is
/// unavailable. The fd is held for the sandbox's lifetime.
pub fn build_ruleset(home: &str) -> Option<RawFd> {
    let abi = abi_version();
    if abi < 1 {
        return None;
    }
    let mut handled_fs = FS_BASE;
    if abi >= 2 {
        handled_fs |= FS_REFER;
    }
    if abi >= 3 {
        handled_fs |= FS_TRUNCATE;
    }
    if abi >= 5 {
        handled_fs |= FS_IOCTL_DEV;
    }
    // Control TCP bind only (leave connect unrestricted → outbound internet works).
    let handled_net = if abi >= 4 { NET_BIND_TCP } else { 0 };
    let scoped = if abi >= 6 { SCOPED_ABSTRACT_UNIX_SOCKET | SCOPED_SIGNAL } else { 0 };

    let attr = RulesetAttr { handled_access_fs: handled_fs, handled_access_net: handled_net, scoped };
    let ruleset_fd = unsafe {
        libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr as *const _ as *const libc::c_void, std::mem::size_of::<RulesetAttr>(), 0u32)
    } as RawFd;
    if ruleset_fd < 0 {
        return None;
    }

    // Read-only + executable: system directories needed to run programs.
    let ro = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
    for dir in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32", "/etc", "/opt", "/run"] {
        add_path_rule(ruleset_fd, dir, ro & handled_fs);
    }
    // Read-only data dirs (no execute): /proc and /sys are needed by many runtimes.
    let rd = FS_READ_FILE | FS_READ_DIR;
    for dir in ["/proc", "/sys"] {
        add_path_rule(ruleset_fd, dir, rd & handled_fs);
    }
    // /dev: allow read/write of the standard nodes (no node creation — MAKE_* not granted).
    add_path_rule(ruleset_fd, "/dev", (FS_READ_FILE | FS_WRITE_FILE | FS_READ_DIR | FS_IOCTL_DEV) & handled_fs);
    // The sandbox's own home: full control within this subtree only.
    add_path_rule(ruleset_fd, home, handled_fs);

    Some(ruleset_fd)
}

/// Enforce the ruleset on the current thread and its future children/execve.
/// Must be called with NO_NEW_PRIVS already set (Landlock requires it for
/// unprivileged callers). Returns Ok only if the kernel confirms enforcement.
pub fn restrict_self(ruleset_fd: RawFd) -> std::io::Result<()> {
    let r = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
