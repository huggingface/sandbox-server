//! Per-sandbox network policy: no outbound access, or only an allowlist.
//!
//! Jobs give the container its network, and the container cannot drop it
//! (no `CAP_NET_ADMIN`, no namespaces). What the server *can* do is take the
//! network away from the commands it starts, and only from them: the server
//! keeps its own connection (it needs it to serve the API), mounted volumes are
//! provided by the platform outside the container, so they keep working.
//!
//! Two kernel mechanisms, both inherited by every descendant and impossible to
//! remove, even for root inside the sandbox:
//!
//! - A **seccomp filter** limits which sockets can exist. `AF_UNIX` and
//!   `AF_NETLINK` stay allowed (local IPC, interface queries). `AF_INET` and
//!   `AF_INET6` are allowed for TCP only, so UDP, ICMP, raw sockets, SCTP and
//!   every other family (packet, vsock, ...) are refused. It also refuses TCP
//!   Fast Open (a `sendto` that connects without calling `connect`), io_uring
//!   (it issues socket calls without going through seccomp), and the syscalls
//!   that let a process act through another one (`ptrace`,
//!   `process_vm_writev`, `pidfd_getfd`).
//! - A **Landlock** ruleset that handles `CONNECT_TCP` with no rule, so the
//!   sandbox cannot connect any TCP socket itself, loopback included. Binding
//!   and listening stay allowed, so the port proxy still reaches servers that
//!   run in a dedicated sandbox.
//!
//! With `"none"`, that is all. With an allowlist, the seccomp filter sends the
//! sandbox's IP `socket()`, `connect()` and `listen()` calls to a supervisor
//! (`SECCOMP_RET_USER_NOTIF`): the server binary run again as the command's
//! parent, inside the sandbox (see "Connect supervisor" below). The supervisor
//! creates every IP socket the sandbox asks for and keeps a handle on it. On
//! `connect()`, it reads the destination, checks it against the allowlist and
//! connects its handle, which is the sandbox's own socket, to the address it
//! read. Changing the sandbox's memory after the check has no effect. A
//! `connect()` to a non-IP address (unix) is let through unchanged: the kernel
//! re-reads the address, but if it was swapped for an IP one, Landlock refuses it.
//!
//! Hostnames in the allowlist are resolved once, by the server, and pinned in
//! `/etc/hosts`, so the sandbox resolves them without DNS (it cannot send UDP)
//! and reaches exactly the addresses that were allowed.
//!
//! Implemented with raw syscalls to stay a zero-dependency static binary.

use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Most rules in one policy: allowlist entries as sent, and again once every
/// hostname has expanded to all of its addresses. The resolved rules reach the
/// supervisor as one argument, which must stay under the kernel's 128 KiB
/// limit: a rule takes at most ~50 bytes, so 1024 of them fit with room to spare.
const MAX_RULES: usize = 1024;
/// Largest `sockaddr` the supervisor reads from a sandbox (`sockaddr_storage`).
const MAX_SOCKADDR: usize = 128;
const HOSTS_FILE: &str = "/etc/hosts";
const HOSTS_MARKER: &str = "# sbx-server network allowlist";

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// One allowed destination: an address range and an optional port.
#[derive(Debug, Clone, PartialEq)]
struct Rule {
    addr: IpAddr,
    prefix: u8,
    port: Option<u16>,
}

impl Rule {
    fn matches(&self, ip: IpAddr, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => prefix_match(&net.octets(), &ip.octets(), self.prefix),
            (IpAddr::V6(net), IpAddr::V6(ip)) => prefix_match(&net.octets(), &ip.octets(), self.prefix),
            _ => false,
        }
    }
}

fn prefix_match(net: &[u8], ip: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    let rest = prefix % 8;
    if net[..full] != ip[..full] {
        return false;
    }
    rest == 0 || (net[full] ^ ip[full]) & (0xff << (8 - rest)) == 0
}

/// A network policy, as applied to every command a sandbox runs.
#[derive(Debug)]
pub struct Policy {
    /// Allowed TCP destinations. Empty means no outbound access at all.
    rules: Vec<Rule>,
    /// Hostnames from the allowlist and the addresses they resolved to.
    hosts: Vec<(String, Vec<IpAddr>)>,
    /// The value the client sent, echoed back so it can check it was applied.
    pub spec: serde_json::Value,
}

impl Policy {
    /// Parse a policy: `"none"`, or `{"allow": ["10.0.0.0/8", "1.2.3.4:443", "huggingface.co", ...]}`.
    ///
    /// Hostnames are resolved here, so a name that does not resolve is an
    /// error now rather than a sandbox that cannot reach it later.
    pub fn parse(value: &serde_json::Value) -> Result<Policy, String> {
        Self::parse_with(value, resolve)
    }

    fn parse_with(
        value: &serde_json::Value,
        resolve: fn(&str) -> Result<Vec<IpAddr>, String>,
    ) -> Result<Policy, String> {
        let entries = match value {
            serde_json::Value::String(s) if s == "none" => Vec::new(),
            serde_json::Value::Object(map) if map.len() == 1 && map.contains_key("allow") => {
                let Some(items) = map["allow"].as_array() else {
                    return Err("network.allow must be an array of strings".into());
                };
                if items.len() > MAX_RULES {
                    return Err(format!("network.allow has {} entries, max {MAX_RULES}", items.len()));
                }
                items
                    .iter()
                    .map(|v| v.as_str().map(str::to_string).ok_or("network.allow must be an array of strings"))
                    .collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err("network must be \"none\" or {\"allow\": [...]}".into()),
        };
        let mut rules = Vec::new();
        let mut hosts = Vec::new();
        for entry in &entries {
            match parse_entry(entry)? {
                Target::Net(addr, prefix, port) => rules.push(Rule { addr, prefix, port }),
                Target::Host(name, port) => {
                    let ips = resolve(&name)?;
                    rules.extend(ips.iter().map(|&ip| Rule { addr: ip, prefix: full_prefix(ip), port }));
                    hosts.push((name, ips));
                }
            }
        }
        // Checked here, when the sandbox is created, rather than by the supervisor
        // of every command, so a hostname that resolves to many addresses is a
        // clear error now and not a sandbox whose commands all fail.
        if rules.len() > MAX_RULES {
            return Err(format!(
                "network.allow resolves to {} addresses, max {MAX_RULES}: use IP ranges, or fewer hostnames",
                rules.len()
            ));
        }
        Ok(Policy { rules, hosts, spec: value.clone() })
    }

    /// Whether a sandbox may connect to `ip:port`.
    pub fn allows(&self, ip: IpAddr, port: u16) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.rules.iter().any(|rule| rule.matches(ip, port))
    }

    /// Pin the allowlisted hostnames in `/etc/hosts`, so the sandbox resolves
    /// them without DNS to the same addresses the allowlist holds.
    ///
    /// Best effort: an image whose `/etc/hosts` is read-only still enforces
    /// the allowlist, its sandboxes just have to connect by address.
    pub fn pin_hostnames(&self) {
        static LOCK: Mutex<()> = Mutex::new(());
        if self.hosts.is_empty() {
            return;
        }
        let _guard = LOCK.lock().unwrap();
        let existing = std::fs::read_to_string(HOSTS_FILE).unwrap_or_default();
        let known: BTreeSet<&str> = existing.lines().map(str::trim).collect();
        let mut missing = String::new();
        for (name, ips) in &self.hosts {
            for ip in ips {
                let line = format!("{ip}\t{name}");
                if !known.contains(line.as_str()) {
                    missing.push_str(&line);
                    missing.push('\n');
                }
            }
        }
        if missing.is_empty() {
            return;
        }
        let header = if existing.contains(HOSTS_MARKER) { String::new() } else { format!("{HOSTS_MARKER}\n") };
        let separator = if existing.is_empty() || existing.ends_with('\n') { "" } else { "\n" };
        let result = std::fs::OpenOptions::new()
            .append(true)
            .open(HOSTS_FILE)
            .and_then(|mut f| f.write_all(format!("{separator}{header}{missing}").as_bytes()));
        if let Err(e) = result {
            eprintln!("sbx-server: cannot pin allowlisted hostnames in {HOSTS_FILE}: {e}");
        }
    }
}

enum Target {
    Net(IpAddr, u8, Option<u16>),
    Host(String, Option<u16>),
}

fn full_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// Parse one allowlist entry: `IP`, `IP/PREFIX`, `IP:PORT`, `[IPv6]:PORT`,
/// `HOST` or `HOST:PORT`. A bare IPv6 address takes no port (wrap it in brackets).
fn parse_entry(entry: &str) -> Result<Target, String> {
    let invalid = |why: &str| format!("invalid network.allow entry {entry:?}: {why}");
    let (host, port) = if let Some(rest) = entry.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or_else(|| invalid("missing ']'"))?;
        match after {
            "" => (inner, None),
            _ => (inner, Some(after.strip_prefix(':').ok_or_else(|| invalid("expected ':PORT' after ']'"))?)),
        }
    } else if entry.matches(':').count() > 1 {
        (entry, None) // bare IPv6
    } else {
        match entry.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (entry, None),
        }
    };
    let port = match port {
        None => None,
        Some(p) => match p.parse::<u16>() {
            Ok(p) if p > 0 => Some(p),
            _ => return Err(invalid("port must be 1-65535")),
        },
    };
    if let Some((ip, prefix)) = host.split_once('/') {
        let ip: IpAddr = ip.parse().map_err(|_| invalid("a range must be IP/PREFIX"))?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid("bad prefix length"))?;
        if prefix > full_prefix(ip) {
            return Err(invalid("prefix length too long"));
        }
        return Ok(Target::Net(ip, prefix, port));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Target::Net(ip, full_prefix(ip), port));
    }
    let valid_host = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
        });
    if !valid_host {
        return Err(invalid("not an IP, a range or a hostname"));
    }
    Ok(Target::Host(host.to_ascii_lowercase(), port))
}

fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    let ips: BTreeSet<IpAddr> = (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host:?}: {e}"))?
        .map(|addr| addr.ip())
        .collect();
    if ips.is_empty() {
        return Err(format!("{host:?} resolved to no address"));
    }
    Ok(ips.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Seccomp filter
// ---------------------------------------------------------------------------

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_USER_NOTIF: u32 = 0x7fc0_0000;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

/// Offsets into `struct seccomp_data`.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
fn data_arg(i: u32) -> u32 {
    16 + 8 * i // low 32 bits on little-endian; every argument we test is an int
}

const MSG_FASTOPEN: u32 = 0x2000_0000;

/// A jump target while assembling: the next instruction, or a named label.
#[derive(Clone, Copy)]
enum To {
    Next,
    L(&'static str),
}

/// A tiny BPF assembler with named labels, so the filter reads top to bottom.
#[derive(Default)]
struct Asm {
    code: Vec<(u16, u32, To, To)>,
    labels: Vec<(&'static str, usize)>,
}

impl Asm {
    fn stmt(&mut self, code: u16, k: u32) -> &mut Self {
        self.code.push((code, k, To::Next, To::Next));
        self
    }
    fn jump(&mut self, code: u16, k: u32, jt: To, jf: To) -> &mut Self {
        self.code.push((code, k, jt, jf));
        self
    }
    fn ret(&mut self, k: u32) -> &mut Self {
        self.stmt(BPF_RET_K, k)
    }
    fn label(&mut self, name: &'static str) -> &mut Self {
        self.labels.push((name, self.code.len()));
        self
    }
    fn assemble(&self) -> Vec<libc::sock_filter> {
        let offset = |at: usize, to: To| -> u8 {
            let target = match to {
                To::Next => at + 1,
                To::L(name) => self.labels.iter().find(|(n, _)| *n == name).expect("unknown label").1,
            };
            // BPF jumps are forward-only, relative and 8-bit.
            let distance = target.checked_sub(at + 1).expect("BPF cannot jump backwards");
            u8::try_from(distance).expect("BPF jump out of range")
        };
        self.code
            .iter()
            .enumerate()
            .map(|(i, &(code, k, jt, jf))| libc::sock_filter { code, jt: offset(i, jt), jf: offset(i, jf), k })
            .collect()
    }
}

fn errno(e: i32) -> u32 {
    RET_ERRNO | (e as u32 & 0xffff)
}

/// The filter installed in every command of a restricted sandbox.
///
/// With `supervised`, the IP sockets the sandbox creates, its `connect()` and
/// `listen()` calls go to the connect supervisor instead of the kernel.
fn build_filter(supervised: bool) -> Vec<libc::sock_filter> {
    use To::*;
    let nr = |n: libc::c_long| n as u32;
    let mut a = Asm::default();
    // Only native x86_64 syscalls: the i386 entry point has `socketcall`, which
    // multiplexes every socket call behind one number, and x32 has its own table.
    a.stmt(BPF_LD_W_ABS, DATA_ARCH)
        .jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, Next, L("deny"))
        .stmt(BPF_LD_W_ABS, DATA_NR)
        .jump(BPF_JGE_K, X32_SYSCALL_BIT, L("deny"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_socket), L("socket"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_socketpair), L("socketpair"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_connect), L("supervised"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_listen), L("supervised"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_sendto), L("arg3_flags"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_sendmmsg), L("arg3_flags"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_sendmsg), L("arg2_flags"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_io_uring_setup), L("enosys"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_ptrace), L("deny"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_process_vm_writev), L("deny"), Next)
        .jump(BPF_JEQ_K, nr(libc::SYS_pidfd_getfd), L("deny"), L("allow"));

    // socket(domain, type, protocol): local families, or TCP over IPv4/IPv6.
    a.label("socket")
        .stmt(BPF_LD_W_ABS, data_arg(0))
        .jump(BPF_JEQ_K, libc::AF_UNIX as u32, L("allow"), Next)
        .jump(BPF_JEQ_K, libc::AF_NETLINK as u32, L("allow"), Next)
        .jump(BPF_JEQ_K, libc::AF_INET as u32, L("inet"), Next)
        .jump(BPF_JEQ_K, libc::AF_INET6 as u32, L("inet"), L("eacces"))
        .label("inet")
        .stmt(BPF_LD_W_ABS, data_arg(1))
        .stmt(BPF_ALU_AND_K, 0xf) // strip SOCK_NONBLOCK / SOCK_CLOEXEC
        .jump(BPF_JEQ_K, libc::SOCK_STREAM as u32, Next, L("eacces"))
        .stmt(BPF_LD_W_ABS, data_arg(2))
        .jump(BPF_JEQ_K, 0, L("supervised"), Next)
        .jump(BPF_JEQ_K, libc::IPPROTO_TCP as u32, L("supervised"), L("eacces"));

    a.label("socketpair").stmt(BPF_LD_W_ABS, data_arg(0)).jump(
        BPF_JEQ_K,
        libc::AF_UNIX as u32,
        L("allow"),
        L("eacces"),
    );

    // Without an allowlist, Landlock alone refuses every TCP connect.
    a.label("supervised").ret(if supervised { RET_USER_NOTIF } else { RET_ALLOW });

    // TCP Fast Open connects from sendto/sendmsg, without the connect() hook.
    a.label("arg3_flags").stmt(BPF_LD_W_ABS, data_arg(3)).jump(BPF_JSET_K, MSG_FASTOPEN, L("eacces"), L("allow"));
    a.label("arg2_flags").stmt(BPF_LD_W_ABS, data_arg(2)).jump(BPF_JSET_K, MSG_FASTOPEN, L("eacces"), L("allow"));

    // BPF only jumps forward, so every verdict sits at the end.
    a.label("allow").ret(RET_ALLOW);
    a.label("eacces").ret(errno(libc::EACCES));
    a.label("enosys").ret(errno(libc::ENOSYS));
    a.label("deny").ret(errno(libc::EPERM));
    a.assemble()
}

// ---------------------------------------------------------------------------
// Applying a policy to a spawned command
// ---------------------------------------------------------------------------

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

/// Everything the exec child needs, prepared before `fork` (the child must not allocate).
pub struct Prepared {
    filter: Vec<libc::sock_filter>,
    landlock_fd: RawFd,
    /// Socket pair used to hand the seccomp listener from the child to the
    /// server: (server end, child end). Only with an allowlist.
    channel: Option<(OwnedFd, OwnedFd)>,
}

impl Prepared {
    pub fn new(policy: &Policy) -> Result<Prepared, String> {
        let landlock_fd = crate::landlock::connect_ruleset().map_err(|e| format!("cannot restrict network: {e}"))?;
        let channel = if policy.needs_supervisor() {
            let mut fds = [0; 2];
            if unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr())
            } != 0
            {
                return Err(format!("socketpair: {}", std::io::Error::last_os_error()));
            }
            Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
        } else {
            None
        };
        Ok(Prepared { filter: build_filter(policy.needs_supervisor()), landlock_fd, channel })
    }

    /// The pre-exec hook: confine the child, then (with an allowlist) send the
    /// seccomp listener to the server. Runs between fork and exec, so it only
    /// makes syscalls on memory prepared beforehand.
    pub fn hook(&self) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
        let filter = self.filter.clone();
        let landlock_fd = self.landlock_fd;
        let child_end = self.channel.as_ref().map(|(_, child)| child.as_raw_fd());
        move || unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            crate::landlock::restrict_self(landlock_fd)?;
            let prog = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
            let flags = if child_end.is_some() { SECCOMP_FILTER_FLAG_NEW_LISTENER } else { 0 };
            let listener = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog);
            if listener < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some(sock) = child_end {
                let sent = send_fd(sock, listener as RawFd);
                libc::close(listener as RawFd);
                sent?;
            }
            Ok(())
        }
    }

    /// After a successful spawn: receive the listener and start answering
    /// the child's `connect()` calls (only with an allowlist).
    fn start(self, policy: Arc<Policy>) -> Result<(), String> {
        let Some((server_end, child_end)) = self.channel else {
            return Ok(());
        };
        drop(child_end);
        let listener = recv_fd(server_end.as_raw_fd()).map_err(|e| format!("no seccomp listener from child: {e}"))?;
        std::thread::spawn(move || supervise(Arc::new(listener), policy));
        Ok(())
    }
}

/// Send `fd` over a unix socket. Async-signal-safe: no allocation.
unsafe fn send_fd(sock: RawFd, fd: RawFd) -> std::io::Result<()> {
    #[repr(C, align(8))]
    struct Cmsg([u8; 32]);
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut buf = Cmsg([0; 32]);
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf.0.as_mut_ptr().cast();
    msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
    std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
    if libc::sendmsg(sock, &msg, 0) < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn recv_fd(sock: RawFd) -> std::io::Result<OwnedFd> {
    #[repr(C, align(8))]
    struct Cmsg([u8; 32]);
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut buf = Cmsg([0; 32]);
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf.0.as_mut_ptr().cast();
        msg.msg_controllen = buf.0.len() as _;
        // The child sent it before exec, and spawn only returns after exec.
        if libc::recvmsg(sock, &mut msg, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(std::io::Error::other("message carried no descriptor"));
        }
        Ok(OwnedFd::from_raw_fd(std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>())))
    }
}

// ---------------------------------------------------------------------------
// Connect supervisor
// ---------------------------------------------------------------------------
//
// With an allowlist, the server does not run the command directly. It runs
// itself again (`sbx-server --net-supervise RULES -- ARGV...`) with the
// sandbox's uid, home, rlimits and Landlock domain, and that process starts
// the command and answers its socket calls:
//
// - It creates the sandbox's IP sockets and installs them as the result of
//   `socket()` (`SECCOMP_ADDFD_FLAG_SEND`), so it holds the same open file as
//   the sandbox. Connecting that handle connects the sandbox's socket: epoll
//   registrations, duplicated descriptors, socket options and EISCONN behave
//   as they do without a policy. (`pidfd_getfd` would avoid holding handles,
//   but the Jobs seccomp profile refuses it without CAP_SYS_PTRACE.)
// - It lives in the command's process group and under the sandbox's limits:
//   a timeout or kill ends it together with the command, and its threads
//   count against the sandbox's RLIMIT_NPROC, not the server's.
// - It is a subreaper, so orphaned descendants stay under it while the
//   command runs. When the command exits, the supervisor exits too, and
//   leftover background processes lose their allowlisted access (ENOSYS).
// - It is not dumpable, so the sandbox (same uid) cannot ptrace it or write
//   to its memory. It can kill it; then connects fail (ENOSYS): closed.

/// Exit code of a supervisor whose setup failed (the server reports the error itself).
const SETUP_FAILED: i32 = 126;
/// How long the server waits for a supervisor to start its command.
const SETUP_TIMEOUT_MS: i32 = 30_000;

/// A pipe a supervisor reports its setup on: (read end, write end), both
/// close-on-exec. The server clears the flag on the write end in the
/// supervisor's child only (`inherit_fd`), so no other command inherits it.
pub fn status_pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Pre-exec hook that lets the exec'd program inherit `fd`.
pub fn inherit_fd(fd: RawFd) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    move || {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Wait until a supervisor has started its command (EOF on the status pipe),
/// or return the setup error it reported.
pub fn await_supervisor(status: OwnedFd) -> Result<(), String> {
    let mut pfd = libc::pollfd { fd: status.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let deadline = Instant::now() + Duration::from_millis(SETUP_TIMEOUT_MS as u64);
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as i32;
        match unsafe { libc::poll(&mut pfd, 1, left) } {
            0 => return Err("network supervisor did not start the command in time".into()),
            n if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => continue,
            _ => break,
        }
    }
    let mut message = String::new();
    let _ = std::io::Read::take(std::fs::File::from(status), 4096).read_to_string(&mut message);
    if message.is_empty() {
        Ok(())
    } else {
        Err(message)
    }
}

/// argv[1] that turns the binary into a connect supervisor.
pub const SUPERVISOR_FLAG: &str = "--net-supervise";

/// Stack size of the supervisor's worker threads (one per pending call).
const WORKER_STACK: usize = 256 * 1024;
/// Concurrent `connect()` calls one supervisor handles; past it they fail with EAGAIN.
const MAX_PENDING_CONNECTS: usize = 64;

impl Policy {
    /// The rules as allowlist entries with every hostname already resolved,
    /// to hand to a supervisor without resolving anything again.
    pub fn resolved_allowlist(&self) -> String {
        let entries: Vec<String> = self
            .rules
            .iter()
            .map(|rule| {
                let net = format!("{}/{}", rule.addr, rule.prefix);
                match (rule.port, rule.addr) {
                    (None, _) => net,
                    (Some(port), IpAddr::V4(_)) => format!("{net}:{port}"),
                    (Some(port), IpAddr::V6(_)) => format!("[{net}]:{port}"),
                }
            })
            .collect();
        serde_json::json!({ "allow": entries }).to_string()
    }

    /// Whether commands run through a connect supervisor (anything allowed at all).
    pub fn needs_supervisor(&self) -> bool {
        !self.rules.is_empty()
    }
}

/// What the server runs as a connect supervisor: its own image, through the
/// `/proc/self/exe` magic link rather than its path on disk. In dedicated mode
/// the sandbox runs as root and can replace the file at that path, and the
/// supervisor runs without the sandbox's restrictions: exec'ing the path would
/// hand the next allowlisted command an unrestricted parent of its choosing.
/// The link always resolves to the inode the server was started from.
pub const SUPERVISOR_EXE: &str = "/proc/self/exe";

/// The path of this binary on disk (Landlock lets host-mode sandboxes execute it,
/// as their supervisor; see `SUPERVISOR_EXE` for why it is not exec'd by path).
pub fn server_exe() -> Result<&'static std::path::Path, String> {
    static EXE: OnceLock<Result<std::path::PathBuf, String>> = OnceLock::new();
    EXE.get_or_init(|| std::env::current_exe().map_err(|e| format!("cannot locate the server binary: {e}")))
        .as_deref()
        .map_err(Clone::clone)
}

/// Entry point of `sbx-server --net-supervise ...`; None when not invoked that way.
pub fn supervisor_main() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some(SUPERVISOR_FLAG) {
        return None;
    }
    Some(run_supervisor(&args[2..]))
}

fn run_supervisor(args: &[String]) -> i32 {
    let (Some(rules), Some(status_fd), Some("--"), Some(program)) = (
        args.first(),
        args.get(1).and_then(|fd| fd.parse::<RawFd>().ok()),
        args.get(2).map(String::as_str),
        args.get(3),
    ) else {
        eprintln!("usage: sbx-server {SUPERVISOR_FLAG} RULES STATUS_FD -- PROGRAM [ARGS...]");
        return 2;
    };
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
        // The command must not inherit it: the server reads it until it closes.
        libc::fcntl(status_fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let status = unsafe { OwnedFd::from_raw_fd(status_fd) };
    // A setup error goes to the server, which reports it as the spawn error it
    // would have been without a supervisor, instead of as the command's output.
    let fail = |message: String| {
        // One write: the pipe holds far more than any message.
        unsafe { libc::write(status.as_raw_fd(), message.as_ptr().cast(), message.len()) };
        SETUP_FAILED
    };
    let policy = serde_json::from_str(rules)
        .map_err(|e| e.to_string())
        .and_then(|value| Policy::parse_with(&value, |host| Err(format!("unresolved hostname {host:?}"))));
    let policy = match policy {
        Ok(policy) if policy.needs_supervisor() => Arc::new(policy),
        Ok(_) => return fail("network supervisor: needs a non-empty allowlist".into()),
        Err(e) => return fail(format!("network supervisor: {e}")),
    };
    let prepared = match Prepared::new(&policy) {
        Ok(prepared) => prepared,
        Err(e) => return fail(format!("network supervisor: {e}")),
    };
    let mut command = std::process::Command::new(program);
    command.args(&args[4..]);
    unsafe { command.pre_exec(prepared.hook()) };
    let mut child = match command.spawn() {
        Ok(child) => child,
        // Worded like the server's own spawn error.
        Err(e) => return fail(format!("failed to spawn '{program}': {e}")),
    };
    let main_pid = child.id() as libc::pid_t;
    if let Err(e) = prepared.start(policy) {
        let _ = child.kill();
        let _ = child.wait();
        return fail(format!("network supervisor: {e}"));
    }
    // EOF on the status pipe: the command runs, supervised.
    drop(status);
    // Reap whatever ends up under us (we are a subreaper) until the command
    // exits, then exit the same way so the server reports its status.
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return 1;
        }
        if pid != main_pid {
            continue;
        }
        if libc::WIFSIGNALED(status) {
            let signal = libc::WTERMSIG(status);
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            return 128 + signal;
        }
        return libc::WEXITSTATUS(status);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Notif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
struct NotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
struct NotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

// _IOWR('!', 0, struct seccomp_notif), _IOWR('!', 1, struct seccomp_notif_resp),
// _IOW('!', 2, __u64), _IOW('!', 3, struct seccomp_notif_addfd)
const SECCOMP_IOCTL_NOTIF_RECV: u32 = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: u32 = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: u32 = 0x4008_2102;
const SECCOMP_IOCTL_NOTIF_ADDFD: u32 = 0x4018_2103;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

/// How often handles on sockets nobody uses any more are dropped.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// A socket younger than this is never swept: it may not be in the caller's
/// descriptor table yet.
const SWEEP_GRACE: Duration = Duration::from_secs(2);

/// The supervisor's handles on the IP sockets of the sandbox, by inode.
///
/// Every IP socket the sandbox has was created here and handed over with
/// `SECCOMP_ADDFD_FLAG_SEND`, so the handle and the sandbox's descriptor are
/// the same open file: connecting the handle connects the sandbox's socket,
/// with its epoll registrations, duplicates and options. A handle is dropped
/// once it is not needed (connected, listening, or closed by the sandbox), so
/// the supervisor never keeps a socket alive that the sandbox closed for longer
/// than one sweep.
#[derive(Default)]
struct Sockets {
    /// Not connected yet: (handle, created at).
    open: Mutex<HashMap<u64, (OwnedFd, Instant)>>,
    /// Connected and released; a new connect() on them is EISCONN.
    connected: Mutex<BTreeSet<u64>>,
}

impl Sockets {
    fn handle(&self, inode: u64) -> Option<OwnedFd> {
        self.open.lock().unwrap().get(&inode).and_then(|(fd, _)| fd.try_clone().ok())
    }

    fn release(&self, inode: u64, connected: bool) {
        self.open.lock().unwrap().remove(&inode);
        if connected {
            self.connected.lock().unwrap().insert(inode);
        }
    }

    /// Drop the handles that are no longer needed.
    fn sweep(&self) {
        let now = Instant::now();
        let candidates: Vec<(u64, RawFd)> = {
            let open = self.open.lock().unwrap();
            if open.is_empty() && self.connected.lock().unwrap().is_empty() {
                return;
            }
            open.iter()
                .filter(|(_, (_, at))| now - *at >= SWEEP_GRACE)
                .map(|(&ino, (fd, _))| (ino, fd.as_raw_fd()))
                .collect()
        };
        let in_use = sandbox_socket_inodes();
        let mut open = self.open.lock().unwrap();
        let mut connected = self.connected.lock().unwrap();
        for (inode, fd) in candidates {
            if is_connected(fd) {
                connected.insert(inode);
                open.remove(&inode);
            } else if !in_use.contains(&inode) {
                open.remove(&inode);
            }
        }
        connected.retain(|inode| in_use.contains(inode));
    }
}

fn is_connected(fd: RawFd) -> bool {
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    unsafe { libc::getpeername(fd, (&mut addr as *mut libc::sockaddr_storage).cast(), &mut len) == 0 }
}

/// Inodes of every socket in the descriptor table of a process we can see,
/// other than ourselves.
fn sandbox_socket_inodes() -> BTreeSet<u64> {
    let me = std::process::id().to_string();
    let mut inodes = BTreeSet::new();
    let Ok(procs) = std::fs::read_dir("/proc") else { return inodes };
    for proc in procs.flatten() {
        let name = proc.file_name();
        let Some(pid) = name.to_str().filter(|n| n.bytes().all(|b| b.is_ascii_digit()) && *n != me) else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            if let Some(inode) = std::fs::read_link(fd.path()).ok().and_then(|link| socket_inode_of(&link)) {
                inodes.insert(inode);
            }
        }
    }
    inodes
}

/// `socket:[12345]` -> 12345.
fn socket_inode_of(link: &std::path::Path) -> Option<u64> {
    link.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// Answer the calls of the command (and its descendants) until all of them
/// have exited.
fn supervise(listener: Arc<OwnedFd>, policy: Arc<Policy>) {
    static PENDING: AtomicUsize = AtomicUsize::new(0);
    let sockets = Arc::new(Sockets::default());
    {
        let sockets = Arc::clone(&sockets);
        std::thread::spawn(move || loop {
            std::thread::sleep(SWEEP_INTERVAL);
            sockets.sweep();
        });
    }
    let fd = listener.as_raw_fd();
    loop {
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut pfd, 1, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if pfd.revents & libc::POLLIN == 0 {
            return; // POLLHUP: no process uses this filter any more
        }
        let mut req: Notif = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as libc::Ioctl, &mut req) } != 0 {
            continue; // the caller died or was interrupted in the meantime
        }
        // One thread per call, so a slow connect does not hold up the others,
        // but a bounded number of them.
        if PENDING.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_CONNECTS {
            PENDING.fetch_sub(1, Ordering::SeqCst);
            respond(&listener, req.id, Verdict::Return(-libc::EAGAIN));
            continue;
        }
        let (worker_listener, policy, sockets) = (Arc::clone(&listener), Arc::clone(&policy), Arc::clone(&sockets));
        // A small stack: the supervisor runs under the sandbox's memory limit
        // (RLIMIT_AS), and the default 2 MiB per thread adds up to 128 MiB at
        // MAX_PENDING_CONNECTS. A call only needs a few small buffers.
        let spawned = std::thread::Builder::new().stack_size(WORKER_STACK).spawn(move || {
            let verdict = match req.data.nr as libc::c_long {
                libc::SYS_socket => on_socket(&worker_listener, &req, &sockets),
                libc::SYS_listen => on_listen(&req, &sockets),
                _ => on_connect(&worker_listener, &req, &policy, &sockets),
            };
            respond(&worker_listener, req.id, verdict);
            PENDING.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            PENDING.fetch_sub(1, Ordering::SeqCst);
            respond(&listener, req.id, Verdict::Return(-libc::EAGAIN));
        }
    }
}

/// What to tell the kernel about one intercepted call.
enum Verdict {
    /// Run the syscall as the sandbox asked.
    Continue,
    /// Return this from the syscall: 0, or a negative errno.
    Return(i32),
    /// Already answered (by `SECCOMP_ADDFD_FLAG_SEND`).
    Answered,
}

fn respond(listener: &OwnedFd, id: u64, verdict: Verdict) {
    let (error, flags) = match verdict {
        Verdict::Continue => (0, SECCOMP_USER_NOTIF_FLAG_CONTINUE),
        Verdict::Return(rc) => (rc.min(0), 0),
        Verdict::Answered => return,
    };
    let mut resp = NotifResp { id, val: 0, error, flags };
    unsafe { libc::ioctl(listener.as_raw_fd(), SECCOMP_IOCTL_NOTIF_SEND as libc::Ioctl, &mut resp) };
}

/// Whether the intercepted call is still waiting for an answer. Also proves
/// that what was read through the notification's pid came from the caller.
fn still_pending(listener: &OwnedFd, id: u64) -> bool {
    let mut id = id;
    unsafe { libc::ioctl(listener.as_raw_fd(), SECCOMP_IOCTL_NOTIF_ID_VALID as libc::Ioctl, &mut id) == 0 }
}

fn last_errno() -> i32 {
    -std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// `socket()` for TCP over IP (the filter refused everything else): create it
/// here, keep a handle, and install it as the call's result.
fn on_socket(listener: &OwnedFd, req: &Notif, sockets: &Sockets) -> Verdict {
    let [domain, kind, protocol, ..] = req.data.args.map(|arg| arg as libc::c_int);
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Verdict::Return(last_errno());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Verdict::Return(last_errno());
    }
    let inode = stat.st_ino as u64;
    let mut addfd = NotifAddfd {
        id: req.id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: if kind & libc::SOCK_CLOEXEC != 0 { libc::O_CLOEXEC as u32 } else { 0 },
    };
    // Registered before the caller can see it, so its connect() finds it.
    sockets.connected.lock().unwrap().remove(&inode);
    sockets.open.lock().unwrap().insert(inode, (sock, Instant::now()));
    if unsafe { libc::ioctl(listener.as_raw_fd(), SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl, &mut addfd) } < 0 {
        let err = last_errno();
        sockets.release(inode, false);
        return Verdict::Return(err);
    }
    Verdict::Answered
}

/// The inode of the socket at `fd` in process `pid`.
fn caller_socket(pid: u32, fd: u64) -> Result<u64, i32> {
    match std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
        Ok(link) => socket_inode_of(&link).ok_or(-libc::ENOTSOCK),
        Err(_) => Err(-libc::EBADF),
    }
}

/// `listen()`: a listening socket will not connect, so stop holding it (a
/// held listener would stay bound after the sandbox closed it).
fn on_listen(req: &Notif, sockets: &Sockets) -> Verdict {
    if let Ok(inode) = caller_socket(req.pid, req.data.args[0]) {
        sockets.release(inode, false);
    }
    Verdict::Continue
}

fn on_connect(listener: &OwnedFd, req: &Notif, policy: &Policy, sockets: &Sockets) -> Verdict {
    let [fd, addr_ptr, addr_len, ..] = req.data.args;
    let len = addr_len as usize;
    if !(2..=MAX_SOCKADDR).contains(&len) {
        return Verdict::Return(-libc::EINVAL);
    }
    let mut addr = [0u8; MAX_SOCKADDR];
    let read = std::fs::File::open(format!("/proc/{}/mem", req.pid))
        .and_then(|mem| mem.read_exact_at(&mut addr[..len], addr_ptr));
    let inode = caller_socket(req.pid, fd);
    // The pid may have been reused since the notification was queued; only
    // trust what we read through it if the notification is still alive.
    if !still_pending(listener, req.id) {
        return Verdict::Return(-libc::EINTR);
    }
    if let Err(e) = read {
        // Usually a process that changed user or made itself non-dumpable (see the README).
        eprintln!(
            "sbx-server: network: connect() refused, cannot check its address (pid {}: {e}). A process that \
             runs as another user or is not dumpable cannot connect under a network allowlist.",
            req.pid
        );
        return Verdict::Return(-libc::EACCES);
    }
    let Some(dest) = parse_sockaddr(&addr[..len]) else {
        // Not an IP destination. If the address is swapped for an IP one before
        // the kernel re-reads it, Landlock refuses the connect.
        return Verdict::Continue;
    };
    if !policy.allows(dest.ip(), dest.port()) {
        return Verdict::Return(-libc::EACCES);
    }
    let inode = match inode {
        Ok(inode) => inode,
        Err(err) => return Verdict::Return(err),
    };
    let Some(sock) = sockets.handle(inode) else {
        // Already connected, or a socket this supervisor did not create.
        let connected = sockets.connected.lock().unwrap().contains(&inode);
        return Verdict::Return(if connected { -libc::EISCONN } else { -libc::EACCES });
    };
    // Connect the caller's own socket to the address we checked, from our
    // copy of it: changing the sandbox's memory now has no effect. If fd now
    // names another socket, we still connect one of the sandbox's sockets to
    // an allowed address.
    let rc = connect_like_caller(listener, req.id, &sock, &addr[..len]);
    if rc == 0 {
        sockets.release(inode, true);
    }
    Verdict::Return(rc)
}

/// `connect()` the caller's socket, with the semantics the caller expects.
///
/// A non-blocking socket is connected as is: the result (EINPROGRESS,
/// EALREADY, EISCONN, ...) is exactly what the caller would have got. A
/// blocking one is connected without blocking, then waited for here, so the
/// wait ends as soon as the caller goes away (killed, timed out, interrupted)
/// and honors the socket's SO_SNDTIMEO like a kernel blocking connect.
fn connect_like_caller(listener: &OwnedFd, id: u64, sock: &OwnedFd, addr: &[u8]) -> i32 {
    let fd = sock.as_raw_fd();
    let connect = || {
        let rc = unsafe { libc::connect(fd, addr.as_ptr().cast(), addr.len() as libc::socklen_t) };
        if rc == 0 {
            0
        } else {
            last_errno()
        }
    };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return last_errno();
    }
    if flags & libc::O_NONBLOCK != 0 {
        return connect();
    }
    // The flag is on the shared open file description; restore it once done.
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    let result = (|| {
        let rc = connect();
        if rc != -libc::EINPROGRESS {
            return rc;
        }
        let deadline = send_timeout(fd).map(|timeout| Instant::now() + timeout);
        loop {
            let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
            if unsafe { libc::poll(&mut pfd, 1, 100) } > 0 {
                break;
            }
            if !still_pending(listener, id) {
                return -libc::EINTR;
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return -libc::EINPROGRESS; // what a timed-out blocking connect returns
            }
        }
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&mut err as *mut libc::c_int).cast(), &mut len)
        };
        -err
    })();
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    result
}

/// The socket's SO_SNDTIMEO, which bounds a blocking connect; None if unset.
fn send_timeout(fd: RawFd) -> Option<Duration> {
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, (&mut tv as *mut libc::timeval).cast(), &mut len)
    };
    let timeout = Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000);
    (rc == 0 && !timeout.is_zero()).then_some(timeout)
}

/// The IP destination of a `sockaddr`, or None for any other family.
fn parse_sockaddr(raw: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as i32;
    match family {
        libc::AF_INET if raw.len() >= 8 => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            Some(SocketAddr::from((Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]), port)))
        }
        libc::AF_INET6 if raw.len() >= 24 => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let octets: [u8; 16] = raw[8..24].try_into().unwrap();
            Some(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        // A short IP sockaddr: let the kernel reject it (EINVAL).
        libc::AF_INET | libc::AF_INET6 => Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fake_resolve(host: &str) -> Result<Vec<IpAddr>, String> {
        match host {
            "vllm.internal" => Ok(vec!["10.0.3.7".parse().unwrap()]),
            // A CDN name: many addresses for one entry.
            "cdn.example" => Ok((0..=255).map(|i| IpAddr::from([198, 51, 100, i])).collect()),
            _ => Err(format!("cannot resolve {host:?}")),
        }
    }

    fn policy(entries: &[&str]) -> Policy {
        Policy::parse_with(&json!({"allow": entries}), fake_resolve).unwrap()
    }

    fn allows(p: &Policy, dest: &str) -> bool {
        let dest: SocketAddr = dest.parse().unwrap();
        p.allows(dest.ip(), dest.port())
    }

    #[test]
    fn resolved_rules_are_limited_at_creation() {
        // Each `cdn.example` entry expands to 256 rules: 4 of them fit, 5 do not.
        let fits = vec!["cdn.example"; 4];
        let p = policy(&fits);
        // What the supervisor of every command parses must parse too.
        let resolved: serde_json::Value = serde_json::from_str(&p.resolved_allowlist()).unwrap();
        assert!(Policy::parse_with(&resolved, |h| Err(h.to_string())).is_ok());
        assert!(p.resolved_allowlist().len() < 128 * 1024);
        let err = Policy::parse_with(&json!({"allow": vec!["cdn.example"; 5]}), fake_resolve).unwrap_err();
        assert!(err.contains("resolves to 1280 addresses"), "{err}");
        // The longest rules still fit in one argument at the limit.
        let v6 = vec!["[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128]:65535"; MAX_RULES];
        let p = Policy::parse_with(&json!({"allow": v6}), fake_resolve).unwrap();
        assert!(p.resolved_allowlist().len() < 128 * 1024);
    }

    #[test]
    fn none_allows_nothing() {
        let p = Policy::parse(&json!("none")).unwrap();
        assert!(!p.needs_supervisor());
        assert!(!allows(&p, "127.0.0.1:80"));
        assert!(!allows(&p, "[::1]:80"));
    }

    #[test]
    fn ranges_addresses_ports_and_hostnames() {
        let p =
            policy(&["10.0.0.0/8", "203.0.113.10:443", "[2001:db8::1]:8000", "2001:db8:1::/48", "vllm.internal:8000"]);
        assert!(p.needs_supervisor());
        assert!(allows(&p, "10.1.2.3:22"));
        assert!(!allows(&p, "11.0.0.1:22"));
        assert!(allows(&p, "203.0.113.10:443"));
        assert!(!allows(&p, "203.0.113.10:80"));
        assert!(allows(&p, "[2001:db8::1]:8000"));
        assert!(!allows(&p, "[2001:db8::1]:8001"));
        assert!(allows(&p, "[2001:db8:1:ffff::5]:1"));
        // An IPv4-mapped IPv6 destination is checked as the IPv4 address it is.
        assert!(allows(&p, "[::ffff:10.0.0.1]:80"));
        assert!(!allows(&p, "[::ffff:11.0.0.1]:80"));
        // A hostname allows the addresses it resolved to, on its port only.
        assert!(allows(&p, "10.0.3.7:8000"));
        assert_eq!(p.hosts, vec![("vllm.internal".to_string(), vec!["10.0.3.7".parse().unwrap()])]);
    }

    #[test]
    fn prefixes_that_are_not_byte_aligned() {
        let p = policy(&["192.168.4.0/22"]);
        assert!(allows(&p, "192.168.7.255:1"));
        assert!(!allows(&p, "192.168.8.0:1"));
        assert!(allows(&policy(&["0.0.0.0/0"]), "8.8.8.8:53"));
    }

    #[test]
    fn invalid_policies_are_rejected() {
        for bad in [
            json!("all"),
            json!({"allow": "10.0.0.0/8"}),
            json!({"allow": [1]}),
            json!({"allow": [], "deny": []}),
            json!({"allow": ["10.0.0.0/33"]}),
            json!({"allow": ["10.0.0.1:0"]}),
            json!({"allow": ["10.0.0.1:http"]}),
            json!({"allow": ["[::1"]}),
            json!({"allow": ["bad host"]}),
            json!({"allow": ["unknown.internal"]}),
        ] {
            assert!(Policy::parse_with(&bad, fake_resolve).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn the_filter_assembles() {
        // Every jump must land inside the program, which `assemble` asserts.
        for notify in [false, true] {
            let prog = build_filter(notify);
            assert!(prog.len() < 64);
            assert_eq!(prog.last().unwrap().code, BPF_RET_K);
        }
    }

    #[test]
    fn sockaddrs_are_decoded() {
        let mut v4 = [0u8; 16];
        v4[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        v4[2..4].copy_from_slice(&443u16.to_be_bytes());
        v4[4..8].copy_from_slice(&[10, 0, 3, 7]);
        assert_eq!(parse_sockaddr(&v4), Some("10.0.3.7:443".parse().unwrap()));
        let mut unix = [0u8; 16];
        unix[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        assert_eq!(parse_sockaddr(&unix), None);
    }
}
