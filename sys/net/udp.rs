//! UDP: header parse/build, a table of bound sockets, and the kernel-exported `oxidebsd_sys_*`
//! functions `sys/modules/net/src/lib.rs`'s thin syscall shims call through to
//! (`SYS_SOCKET`/`SYS_BIND`/`SYS_SENDTO`/`SYS_RECVFROM`/`SYS_SETSOCKOPT` = 140-144). `socket()`/
//! `bind()`/`setsockopt()` are shared with `super::tcp` (the same three syscall numbers cover
//! both `SOCK_DGRAM` and `SOCK_STREAM`) -- `socket()` dispatches by type at creation time,
//! `bind()`/`setsockopt()` fall back to `tcp`'s own table (`Option`-wrapped: `None` means "not
//! mine, keep looking") when a `real_fd` isn't a UDP socket. `sendto`/`recvfrom` stay UDP-only --
//! TCP reuses the plain `SYS_READ`/`SYS_WRITE` fd-ops path instead once a connection is
//! established (see `tcp.rs`'s own doc comment for why the two need different shapes).
//!
//! Sockets go through the same `crate::fd` registry every other fd-bearing resource in this
//! kernel does (`oxidebsd_alloc_fd`/`oxidebsd_register_fd_ops`), so `close`/`dup2`/`fork` all
//! work on a socket fd for free -- but `sendto`/`recvfrom` are registered as their own syscalls,
//! not through the fd-ops `read`/`write` callbacks, since both carry a `sockaddr` the plain
//! `(fd, ptr, len)` read/write shape has no room for (see `bits/syscall.h.in`'s own comment on
//! this, in the vendored musl tree, for the wire-format reduction that makes them fit this ABI's
//! 4-argument width at all).

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use spin::Mutex;

use super::ipv4::{self, Ipv4Addr};
use crate::syscall::{EBADF, EINVAL};

pub const PROTO_UDP: u8 = 17;

const AF_INET: i64 = 2;
const SOCK_STREAM: i64 = 1;
const SOCK_DGRAM: i64 = 2;
const SOCK_RAW: i64 = 3;
/// Real Linux/musl OR these bits directly into `socket()`'s `type` argument
/// (`external/mit/musl/arch/generic/bits/socket.h`) rather than passing them separately -- musl's
/// own DNS stub resolver does exactly this (`src/network/res_msend.c`'s
/// `SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK`). Masked off in `oxidebsd_sys_socket` before dispatch:
/// every socket this stack hands out already behaves non-blocking (the established self-poll
/// convention `oxidebsd_sys_recvfrom` set), and fd-level close-on-exec isn't modeled at all, so
/// both flags are accepted and silently ignored rather than making the type match fail outright.
const SOCK_CLOEXEC: i64 = 0o2000000;
const SOCK_NONBLOCK: i64 = 0o4000;

/// errno values are musl's (`bits/errno.h`): they become userland's `errno` unchanged. These four
/// used to be FreeBSD's, so e.g. `ENOTSOCK` read as `ENOSYS`.
const ENOTSOCK: i64 = 88;
const EDESTADDRREQ: i64 = 89;
/// `93`, matching musl's actual compiled-in value -- see `sys/syscall.rs`'s own copy of this
/// constant for the full story (this one used to be the same wrong `43` before that fix).
const EPROTONOSUPPORT: i64 = 93;
const EADDRINUSE: i64 = 98;
const EHOSTUNREACH: i64 = 113;
/// `97`, matching musl's actual compiled-in value (`external/mit/musl/arch/generic/bits/errno.h`) --
/// real Linux's own distinction between "this address family isn't supported at all" (this) and
/// "this type/protocol combination isn't supported within an otherwise-known family"
/// (`EPROTONOSUPPORT`, still used below for a bad `SOCK_*`/protocol pairing under `AF_INET`).
/// **A real, previously-live bug**, not just a naming nicety: musl's own `getgrouplist()`/
/// `initgroups()` (`external/mit/musl/src/passwd/getgrouplist.c` -> `src/passwd/nscd_query.c`)
/// always probes a real `AF_UNIX` socket to a local `nscd` daemon first, and *only* falls back to
/// parsing `/etc/group` for real when that `socket()` call itself fails with exactly
/// `EAFNOSUPPORT` -- any other errno (this handler's old `EPROTONOSUPPORT` for any non-`AF_INET`
/// domain included) is treated as a hard failure, never reaching the real fallback. Found live via
/// `sched_setparam/26-1.c`'s own privilege-drop path (`su user -c ...`, see
/// `sys/modules/oxfs/src/posix_conformance.sh`): `su`'s real `change_identity()` calls `initgroups()`,
/// which hit exactly this, and died with a real "can't set groups: Function not implemented"
/// before the test's own assertion ever ran.
const EAFNOSUPPORT: i64 = 97;

const HEADER_LEN: usize = 8;
const SOCKADDR_LEN: usize = 16;
const EPHEMERAL_PORT_START: u16 = 49152;
/// Bounded so a socket nobody's reading from can't grow without limit -- same backpressure
/// reasoning as `src/pipe.rs`'s own bounded buffer, except nothing here blocks an outrunning
/// sender (UDP is unreliable by nature; a full queue just drops the newest datagram instead of
/// backpressuring the network stack itself).
const MAX_QUEUED_DATAGRAMS: usize = 32;

struct UdpSocket {
    local_port: Option<u16>,
    recv_queue: VecDeque<(Ipv4Addr, u16, Vec<u8>)>,
}

impl UdpSocket {
    const fn new() -> Self {
        UdpSocket {
            local_port: None,
            recv_queue: VecDeque::new(),
        }
    }
}

struct UdpState {
    sockets: BTreeMap<u64, UdpSocket>,
    /// local port -> owning socket's `real_fd`, so `handle_packet` can route an inbound datagram
    /// to the right socket's queue.
    ports: BTreeMap<u16, u64>,
    next_ephemeral: u16,
}

impl UdpState {
    const fn new() -> Self {
        UdpState {
            sockets: BTreeMap::new(),
            ports: BTreeMap::new(),
            next_ephemeral: EPHEMERAL_PORT_START,
        }
    }

    fn alloc_ephemeral_port(&mut self) -> Option<u16> {
        let start = self.next_ephemeral;
        loop {
            let port = self.next_ephemeral;
            self.next_ephemeral = if self.next_ephemeral == u16::MAX {
                EPHEMERAL_PORT_START
            } else {
                self.next_ephemeral + 1
            };
            if !self.ports.contains_key(&port) {
                return Some(port);
            }
            if self.next_ephemeral == start {
                return None; // wrapped all the way around -- the ephemeral range is exhausted
            }
        }
    }

    /// Returns the socket's bound local port, auto-assigning an ephemeral one on first use if it
    /// was never explicitly `bind`-ed (standard implicit-bind-on-first-send behavior).
    fn ensure_bound(&mut self, real_fd: u64) -> Option<u16> {
        if let Some(port) = self.sockets.get(&real_fd).and_then(|s| s.local_port) {
            return Some(port);
        }
        let port = self.alloc_ephemeral_port()?;
        self.ports.insert(port, real_fd);
        self.sockets.get_mut(&real_fd).unwrap().local_port = Some(port);
        Some(port)
    }
}

static STATE: Mutex<UdpState> = Mutex::new(UdpState::new());

fn resolve(fd: u64) -> Option<u64> {
    crate::fs::fd::real_fd_of(fd)
}

/// Reads a `struct sockaddr_in` at `ptr` (2 bytes family, ignored -- AF_INET is the only family
/// this is ever called with; 2 bytes port, network/big-endian order; 4 bytes address; 8 bytes
/// padding, ignored). No pointer validation, matching this kernel's existing `sys_read`/
/// `sys_write` trust boundary -- a bad pointer page-faults, not a soundness hole.
pub(super) fn read_sockaddr(ptr: u64) -> Option<(Ipv4Addr, u16)> {
    if ptr == 0 {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, SOCKADDR_LEN) };
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let addr: Ipv4Addr = bytes[4..8].try_into().unwrap();
    Some((addr, port))
}

/// Writes a `struct sockaddr_in` at `ptr`. A no-op if `ptr` is null -- real `recvfrom(..., NULL)`
/// is a legal way to say "I don't care about the source address."
pub(super) fn write_sockaddr(ptr: u64, addr: Ipv4Addr, port: u16) {
    if ptr == 0 {
        return;
    }
    let mut bytes = [0u8; SOCKADDR_LEN];
    bytes[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes()); // sa_family_t is host-order
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&addr);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, SOCKADDR_LEN);
    }
}

/// Parses one UDP datagram (already IP-payload-only, see `ipv4::handle_packet`) and, if a socket
/// is bound to its destination port, queues it there. No listener means the datagram is silently
/// dropped -- a real stack would send back an ICMP port-unreachable; not implemented.
pub fn handle_packet(payload: &[u8], src_ip: Ipv4Addr) {
    if payload.len() < HEADER_LEN {
        return;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if length < HEADER_LEN || length > payload.len() {
        return;
    }
    let data = &payload[HEADER_LEN..length];

    let mut state = STATE.lock();
    let Some(&real_fd) = state.ports.get(&dst_port) else {
        return;
    };
    let Some(socket) = state.sockets.get_mut(&real_fd) else {
        return;
    };
    if socket.recv_queue.len() >= MAX_QUEUED_DATAGRAMS {
        socket.recv_queue.pop_front(); // drop oldest -- simple backpressure, no flow control
    }
    socket
        .recv_queue
        .push_back((src_ip, src_port, data.to_vec()));
}

/// `None` if `real_fd` isn't a UDP socket (caller, `net::oxidebsd_sys_poll`, keeps looking in the
/// other protocols' tables).
pub fn has_data_ready(real_fd: u64) -> Option<bool> {
    STATE
        .lock()
        .sockets
        .get(&real_fd)
        .map(|socket| !socket.recv_queue.is_empty())
}

extern "C" fn udp_read(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    // A UDP socket has no default peer without `connect()` (a later phase) -- real programs must
    // use `recvfrom`, matching real Linux/BSD behavior for plain `read()` on an unconnected UDP
    // socket.
    -ENOTSOCK
}

extern "C" fn udp_write(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -EDESTADDRREQ
}

extern "C" fn udp_close(real_fd: u64) -> i64 {
    let mut state = STATE.lock();
    if let Some(socket) = state.sockets.remove(&real_fd)
        && let Some(port) = socket.local_port
    {
        state.ports.remove(&port);
    }
    0
}

pub extern "C" fn oxidebsd_sys_socket(domain: u64, ty: u64, protocol: u64) -> i64 {
    if domain as i64 != AF_INET {
        return -EAFNOSUPPORT;
    }
    let base_ty = (ty as i64) & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    match base_ty {
        SOCK_DGRAM => {
            let fd = crate::fs::fd::oxidebsd_alloc_fd();
            STATE.lock().sockets.insert(fd, UdpSocket::new());
            crate::fs::fd::oxidebsd_register_fd_ops(fd, udp_read, udp_write, udp_close) as i64
        }
        SOCK_STREAM => super::tcp::create_socket() as i64,
        // socket(AF_INET, SOCK_RAW, 1) is exactly what a real `ping` asks for (see
        // external/gpl2/busybox's own ping.c) -- no other raw protocol is supported.
        SOCK_RAW if protocol as i64 == super::ipv4::PROTO_ICMP as i64 => {
            super::icmp::create_socket() as i64
        }
        _ => -EPROTONOSUPPORT,
    }
}

pub extern "C" fn oxidebsd_sys_bind(fd: u64, addr_ptr: u64, len: u64) -> i64 {
    let _ = len;
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };

    let mut state = STATE.lock();
    if !state.sockets.contains_key(&real_fd) {
        drop(state);
        if let Some(result) = super::tcp::bind(real_fd, addr_ptr) {
            return result;
        }
        return match super::icmp::bind(real_fd, addr_ptr) {
            Some(result) => result,
            None => -ENOTSOCK,
        };
    }

    let Some((_local_addr, port)) = read_sockaddr(addr_ptr) else {
        return -(EINVAL as i64);
    };
    let port = if port == 0 {
        match state.alloc_ephemeral_port() {
            Some(p) => p,
            None => return -EADDRINUSE,
        }
    } else {
        if state.ports.contains_key(&port) {
            return -EADDRINUSE;
        }
        port
    };
    state.ports.insert(port, real_fd);
    state.sockets.get_mut(&real_fd).unwrap().local_port = Some(port);
    0
}

/// Real `getsockname(2)` -- same not-mine-vs-mine fallback chain `oxidebsd_sys_bind` above uses.
/// Not wired for raw ICMP sockets (`super::icmp`) -- no real consumer needs it yet; `ENOTSOCK`
/// there is a known, narrow gap, not a correctness claim about raw sockets in general.
pub extern "C" fn oxidebsd_sys_getsockname(fd: u64, addr_out_ptr: u64, addrlen_ptr: u64) -> i64 {
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };

    let local_port = {
        let state = STATE.lock();
        state.sockets.get(&real_fd).map(|s| s.local_port)
    };
    if let Some(port) = local_port {
        write_sockaddr(addr_out_ptr, ipv4::GUEST_IP, port.unwrap_or(0));
        if addrlen_ptr != 0 {
            unsafe {
                *(addrlen_ptr as *mut u32) = 16;
            }
        }
        return 0;
    }

    match super::tcp::getsockname(real_fd, addr_out_ptr, addrlen_ptr) {
        Some(result) => result,
        None => -ENOTSOCK,
    }
}

pub extern "C" fn oxidebsd_sys_sendto(fd: u64, buf_ptr: u64, buf_len: u64, addr_ptr: u64) -> i64 {
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };
    let Some((dest_ip, dest_port)) = read_sockaddr(addr_ptr) else {
        return -EDESTADDRREQ;
    };
    if buf_ptr == 0 && buf_len > 0 {
        return -(EINVAL as i64);
    }

    let local_port = {
        let mut state = STATE.lock();
        if !state.sockets.contains_key(&real_fd) {
            drop(state);
            return match super::icmp::sendto(real_fd, buf_ptr, buf_len, dest_ip) {
                Some(result) => result,
                None => -ENOTSOCK,
            };
        }
        match state.ensure_bound(real_fd) {
            Some(p) => p,
            None => return -EADDRINUSE,
        }
    };

    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, buf_len as usize) };
    let mut packet = Vec::with_capacity(HEADER_LEN + data.len());
    packet.extend_from_slice(&local_port.to_be_bytes());
    packet.extend_from_slice(&dest_port.to_be_bytes());
    packet.extend_from_slice(&((HEADER_LEN + data.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]); // checksum: 0 is a legal "not computed" value over IPv4
    packet.extend_from_slice(data);

    match ipv4::send_packet(dest_ip, PROTO_UDP, &packet) {
        Some(()) => data.len() as i64,
        None => -EHOSTUNREACH,
    }
}

pub extern "C" fn oxidebsd_sys_recvfrom(
    fd: u64,
    buf_ptr: u64,
    buf_len: u64,
    addr_out_ptr: u64,
) -> i64 {
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };

    // Non-blocking, matching this kernel's own established `sys_read`-on-stdin convention (see
    // src/stdin.rs): drives the RX pipeline itself (same self-driving pattern
    // `ipv4::send_packet`'s own ARP wait already uses) rather than relying on anything else to
    // have polled first, then reports "nothing yet" as a plain empty read rather than actually
    // blocking -- no `BlockReason` exists for socket data yet, see this repo's networking plan.
    super::poll();

    let mut state = STATE.lock();
    if !state.sockets.contains_key(&real_fd) {
        drop(state);
        return match super::icmp::recvfrom(real_fd, buf_ptr, buf_len, addr_out_ptr) {
            Some(result) => result,
            None => -ENOTSOCK,
        };
    }
    let Some(socket) = state.sockets.get_mut(&real_fd) else {
        return -ENOTSOCK;
    };
    let Some((src_ip, src_port, data)) = socket.recv_queue.pop_front() else {
        return 0;
    };
    drop(state);

    let n = data.len().min(buf_len as usize);
    if buf_ptr != 0 && n > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr as *mut u8, n);
        }
    }
    write_sockaddr(addr_out_ptr, src_ip, src_port);
    n as i64
}

pub extern "C" fn oxidebsd_sys_setsockopt(fd: u64, level: u64, optname: u64) -> i64 {
    let _ = (level, optname);
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };
    if STATE.lock().sockets.contains_key(&real_fd) {
        return 0;
    }
    if let Some(result) = super::tcp::setsockopt(real_fd) {
        return result;
    }
    match super::icmp::setsockopt(real_fd) {
        Some(result) => result,
        None => -ENOTSOCK,
    }
}
