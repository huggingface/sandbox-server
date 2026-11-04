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
//! With `"none"`, that is all. With an allowlist, the seccomp filter also
//! sends every `connect()` to the server (`SECCOMP_RET_USER_NOTIF`). The
//! server reads the destination, checks it against the allowlist and, if it
//! matches, creates a socket of its own, connects it and installs it in place
//! of the sandbox's socket (`SECCOMP_IOCTL_NOTIF_ADDFD`). The server connects
//! the address it read, not whatever the sandbox's memory holds by the time the
//! kernel would re-read it, so there is no time-of-check/time-of-use gap. A
//! `connect()` on a non-IP socket (unix) is let through unchanged: the kernel
//! re-reads the address, but if it was swapped for an IP one the Landlock rule
//! refuses it.
//!
//! Hostnames in the allowlist are resolved once, by the server, and pinned in
//! `/etc/hosts`, so the sandbox resolves them without DNS (it cannot send UDP)
//! and reaches exactly the addresses that were allowed.
//!
//! Implemented with raw syscalls to stay a zero-dependency static binary.

use std::collections::BTreeSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

/// Most allowlist entries accepted in one policy.
const MAX_RULES: usize = 256;
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

    /// Whether `connect()` has to go through the server (anything allowed at all).
    fn needs_supervisor(&self) -> bool {
        !self.rules.is_empty()
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
fn build_filter(notify_connect: bool) -> Vec<libc::sock_filter> {
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
        .jump(BPF_JEQ_K, nr(libc::SYS_connect), L("connect"), Next)
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
        .jump(BPF_JEQ_K, 0, L("allow"), Next)
        .jump(BPF_JEQ_K, libc::IPPROTO_TCP as u32, L("allow"), L("eacces"));

    a.label("socketpair").stmt(BPF_LD_W_ABS, data_arg(0)).jump(
        BPF_JEQ_K,
        libc::AF_UNIX as u32,
        L("allow"),
        L("eacces"),
    );

    // Without an allowlist, Landlock alone refuses every TCP connect.
    a.label("connect").ret(if notify_connect { RET_USER_NOTIF } else { RET_ALLOW });

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
    /// the child's `connect()` calls. `uid` is the sandbox uid in host mode.
    pub fn start(self, policy: Arc<Policy>, uid: Option<u32>) -> Result<(), String> {
        let Some((server_end, child_end)) = self.channel else {
            return Ok(());
        };
        drop(child_end);
        let listener = recv_fd(server_end.as_raw_fd()).map_err(|e| format!("no seccomp listener from child: {e}"))?;
        std::thread::spawn(move || supervise(Arc::new(listener), policy, uid));
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
const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;

/// Answer the `connect()` calls of one spawned command (and its descendants)
/// until all of them have exited.
fn supervise(listener: Arc<OwnedFd>, policy: Arc<Policy>, uid: Option<u32>) {
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
        // One thread per call: a blocking connect must not hold up the others.
        let (listener, policy) = (Arc::clone(&listener), Arc::clone(&policy));
        std::thread::spawn(move || answer(&listener, &req, &policy, uid));
    }
}

/// What to tell the kernel about one intercepted `connect()`.
enum Verdict {
    /// Run the syscall as the sandbox asked (a non-IP socket).
    Continue,
    /// Return this from the syscall: 0, or a negative errno.
    Return(i32),
}

fn answer(listener: &OwnedFd, req: &Notif, policy: &Policy, uid: Option<u32>) {
    let verdict = decide(listener, req, policy, uid);
    let (val, error, flags) = match verdict {
        Verdict::Continue => (0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE),
        Verdict::Return(rc) => (0, rc.min(0), 0),
    };
    let mut resp = NotifResp { id: req.id, val, error, flags };
    unsafe { libc::ioctl(listener.as_raw_fd(), SECCOMP_IOCTL_NOTIF_SEND as libc::Ioctl, &mut resp) };
}

fn last_errno() -> i32 {
    -std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn decide(listener: &OwnedFd, req: &Notif, policy: &Policy, uid: Option<u32>) -> Verdict {
    // Read the sandbox's memory as the sandbox's uid, so the kernel's ptrace
    // access check passes in host mode. Only the filesystem ids change: the
    // thread keeps its real uid, so a sandbox cannot signal it.
    if let Some(uid) = uid {
        unsafe {
            libc::syscall(libc::SYS_setfsgid, uid);
            libc::syscall(libc::SYS_setfsuid, uid);
        }
    }
    let [fd, addr_ptr, addr_len, ..] = req.data.args;
    let len = addr_len as usize;
    if !(2..=MAX_SOCKADDR).contains(&len) {
        return Verdict::Return(-libc::EINVAL);
    }
    let mut addr = [0u8; MAX_SOCKADDR];
    let read = std::fs::File::open(format!("/proc/{}/mem", req.pid))
        .and_then(|mem| mem.read_exact_at(&mut addr[..len], addr_ptr));
    // The pid may have been reused since the notification was queued; only
    // trust what we read if the notification is still alive.
    let mut id = req.id;
    if unsafe { libc::ioctl(listener.as_raw_fd(), SECCOMP_IOCTL_NOTIF_ID_VALID as libc::Ioctl, &mut id) } != 0 {
        return Verdict::Return(-libc::EINTR);
    }
    if let Err(e) = read {
        eprintln!("sbx-server: network: cannot read connect() address of pid {}: {e}", req.pid);
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
    // Keep the sandbox's O_NONBLOCK and O_CLOEXEC on the replacement socket.
    let fdinfo = std::fs::read_to_string(format!("/proc/{}/fdinfo/{fd}", req.pid)).unwrap_or_default();
    let fd_flags = fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("flags:"))
        .and_then(|v| i32::from_str_radix(v.trim(), 8).ok())
        .unwrap_or(0);
    let family = if dest.is_ipv4() && addr[..2] == (libc::AF_INET as u16).to_ne_bytes() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let sock = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Verdict::Return(last_errno());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };
    if fd_flags & libc::O_NONBLOCK != 0 {
        unsafe { libc::fcntl(sock.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
    }
    // Connect the address we checked, from our own copy of it.
    let rc = unsafe { libc::connect(sock.as_raw_fd(), addr.as_ptr().cast(), len as libc::socklen_t) };
    let result = if rc == 0 { 0 } else { last_errno() };
    if result != 0 && result != -libc::EINPROGRESS {
        return Verdict::Return(result);
    }
    let mut addfd = NotifAddfd {
        id: req.id,
        flags: SECCOMP_ADDFD_FLAG_SETFD,
        srcfd: sock.as_raw_fd() as u32,
        newfd: fd as u32,
        newfd_flags: (fd_flags & libc::O_CLOEXEC) as u32,
    };
    if unsafe { libc::ioctl(listener.as_raw_fd(), SECCOMP_IOCTL_NOTIF_ADDFD as libc::Ioctl, &mut addfd) } < 0 {
        return Verdict::Return(last_errno());
    }
    Verdict::Return(result)
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
