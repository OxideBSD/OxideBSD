//! The socket layer (OxideBSD-doc `UNIX.md` §3): every socket, whatever its family, is one entry
//! in `SOCKETS`, keyed by the `real_fd` of its open file description, naming the protocol that
//! implements it. The socket system calls resolve the caller's descriptor, look the socket up,
//! and call the protocol through the `Protocol` trait -- the BSDs' protocol switch (`protosw`).
//! Nothing here knows about a particular family; each protocol keeps its own per-socket state
//! (its control block) keyed by the same `real_fd`.
//!
//! Addresses cross this boundary as the bytes of the caller's `struct sockaddr`: the layer copies
//! them in and out, the protocol parses and builds them.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use spin::Mutex;

use crate::fs::Readiness;
use crate::fs::fd::{self, FdKind};
use crate::syscall::{EBADF, EINVAL, ENOTSOCK, EPROTONOSUPPORT};

pub(crate) const AF_UNIX: i64 = 1;
pub(crate) const AF_INET: i64 = 2;
pub(crate) const SOCK_STREAM: i64 = 1;
pub(crate) const SOCK_DGRAM: i64 = 2;
pub(crate) const SOCK_RAW: i64 = 3;
/// OR'd into `socket(2)`'s `type`, as in Linux and musl.
const SOCK_CLOEXEC: i64 = 0o2000000;
const SOCK_NONBLOCK: i64 = 0o4000;

/// musl's values (`bits/errno.h`).
pub(crate) const EPROTOTYPE: i64 = 91;
pub(crate) const EOPNOTSUPP: i64 = 95;
/// Not `EPROTONOSUPPORT` for an unknown domain: musl's `initgroups()` tries an `AF_UNIX` socket to
/// `nscd` first and falls back to reading `/etc/group` only on exactly this error (found through
/// `su`, which calls it).
pub(crate) const EAFNOSUPPORT: i64 = 97;

/// A socket address as user space lays it out (`struct sockaddr_*`).
pub(crate) type SockAddr = Vec<u8>;

/// What a protocol implements. Errors are positive errno values. `so` is the socket's `real_fd`.
pub(crate) trait Protocol: Sync {
    /// Sets up the protocol's state for a new socket.
    fn attach(&self, so: u64) -> Result<(), i64>;
    /// Tears it down; the last descriptor for the socket has been closed.
    fn detach(&self, so: u64);
    fn bind(&self, so: u64, addr: &[u8]) -> Result<(), i64>;
    fn connect(&self, _so: u64, _addr: &[u8]) -> Result<(), i64> {
        Err(EOPNOTSUPP)
    }
    fn listen(&self, _so: u64, _backlog: i64) -> Result<(), i64> {
        Err(EOPNOTSUPP)
    }
    /// Takes a completed connection: its `real_fd` (already known to the protocol, not yet to
    /// the socket layer) and the peer's address.
    fn accept(&self, _so: u64) -> Result<(u64, SockAddr), i64> {
        Err(EOPNOTSUPP)
    }
    /// Sends `data`, to `to` or the socket's peer. Returns the bytes accepted.
    fn send(&self, so: u64, data: &[u8], to: Option<&[u8]>) -> Result<usize, i64>;
    /// Receives into `buf`. Returns the bytes received and, if the protocol has one, the sender.
    fn recv(&self, so: u64, buf: &mut [u8]) -> Result<(usize, Option<SockAddr>), i64>;
    fn shutdown(&self, _so: u64, _how: i64) -> Result<(), i64> {
        Err(EOPNOTSUPP)
    }
    fn sockname(&self, so: u64) -> Result<SockAddr, i64>;
    fn setsockopt(&self, _so: u64, _level: i64, _name: i64) -> Result<(), i64> {
        Ok(())
    }
    fn readiness(&self, so: u64) -> Readiness;
    /// The length of this family's address, for calls whose caller doesn't pass one.
    fn addr_len(&self) -> usize;
    /// Whether the socket's state changes only when a waiter drives the network interface
    /// (`crate::net::poll`), rather than when another process runs (`UNIX.md` §3.4).
    fn pulled(&self) -> bool;
}

struct Socket {
    domain: i64,
    ty: i64,
    protocol: i64,
    proto: &'static dyn Protocol,
}

static SOCKETS: Mutex<BTreeMap<u64, Socket>> = Mutex::new(BTreeMap::new());

/// The protocol for `(domain, type, protocol)`, or the errno `socket(2)` reports.
fn find_protocol(domain: i64, ty: i64, protocol: i64) -> Result<&'static dyn Protocol, i64> {
    use crate::netinet::{icmp, tcp, udp};
    match domain {
        AF_INET => match (ty, protocol) {
            (SOCK_DGRAM, 0) | (SOCK_DGRAM, 17) => Ok(&udp::UDP),
            (SOCK_STREAM, 0) | (SOCK_STREAM, 6) => Ok(&tcp::TCP),
            (SOCK_RAW, 1) => Ok(&icmp::RAW_ICMP),
            (SOCK_DGRAM, 6) | (SOCK_STREAM, 17) => Err(EPROTOTYPE),
            _ => Err(EPROTONOSUPPORT as i64),
        },
        _ => Err(EAFNOSUPPORT),
    }
}

/// The protocol of the calling process's descriptor `fd`, with the socket's `real_fd`.
fn lookup(fd: u64) -> Result<(u64, &'static dyn Protocol), i64> {
    let so = fd::real_fd_of(fd).ok_or(EBADF as i64)?;
    let proto = SOCKETS.lock().get(&so).map(|s| s.proto).ok_or(ENOTSOCK as i64)?;
    Ok((so, proto))
}

fn proto_of(so: u64) -> Option<&'static dyn Protocol> {
    SOCKETS.lock().get(&so).map(|s| s.proto)
}

fn ffi(result: Result<u64, i64>) -> i64 {
    match result {
        Ok(v) => v as i64,
        Err(e) => -e,
    }
}

/// A user buffer as a slice. No validation, as for `read(2)`/`write(2)` (a bad pointer faults).
fn user_slice<'a>(ptr: u64, len: u64) -> Result<&'a [u8], i64> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr == 0 {
        return Err(EINVAL as i64);
    }
    // SAFETY: a user pointer in the current address space; see above.
    Ok(unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) })
}

fn user_slice_mut<'a>(ptr: u64, len: u64) -> Result<&'a mut [u8], i64> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr == 0 {
        return Err(EINVAL as i64);
    }
    // SAFETY: as `user_slice`.
    Ok(unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) })
}

/// Copies an address out. With `len_ptr`, copies at most `*len_ptr` bytes and stores the
/// address's real length there; without one (calls whose caller passes no length), copies it
/// all. A null `ptr` means the caller doesn't want it.
fn copy_addr_out(ptr: u64, len_ptr: u64, addr: &[u8]) {
    if ptr == 0 {
        return;
    }
    let n = if len_ptr == 0 {
        addr.len()
    } else {
        // SAFETY: a user `socklen_t *`; see `user_slice`.
        let room = unsafe { *(len_ptr as *const u32) } as usize;
        unsafe { *(len_ptr as *mut u32) = addr.len() as u32 };
        room.min(addr.len())
    };
    // SAFETY: as `user_slice`.
    unsafe { core::ptr::copy_nonoverlapping(addr.as_ptr(), ptr as *mut u8, n) };
}

/// Gives the calling process a descriptor for the socket `so`, served by `proto`.
fn install(so: u64, domain: i64, ty: i64, protocol: i64, proto: &'static dyn Protocol) -> u64 {
    SOCKETS.lock().insert(so, Socket { domain, ty, protocol, proto });
    let user_fd = fd::oxidebsd_register_fd_ops(so, so_read, so_write, so_close);
    fd::set_kind(so, FdKind::Socket(so));
    user_fd
}

extern "C" fn so_read(so: u64, ptr: u64, len: u64) -> i64 {
    let Some(proto) = proto_of(so) else { return -(EBADF as i64) };
    let result = user_slice_mut(ptr, len).and_then(|buf| proto.recv(so, buf));
    ffi(result.map(|(n, _)| n as u64))
}

extern "C" fn so_write(so: u64, ptr: u64, len: u64) -> i64 {
    let Some(proto) = proto_of(so) else { return -(EBADF as i64) };
    ffi(user_slice(ptr, len).and_then(|data| proto.send(so, data, None)).map(|n| n as u64))
}

extern "C" fn so_close(so: u64) -> i64 {
    // Out of the lock first: a protocol's detach may come back into the socket layer.
    let socket = SOCKETS.lock().remove(&so);
    if let Some(socket) = socket {
        socket.proto.detach(so);
    }
    0
}

/// `poll(2)`/`select(2)` state of `real_fd`, and whether its protocol is pulled (§3.4); `None` if
/// it isn't a socket.
pub(crate) fn readiness(so: u64) -> Option<(Readiness, bool)> {
    let proto = proto_of(so)?;
    Some((proto.readiness(so), proto.pulled()))
}

/// `(domain, type, protocol)` of the socket `real_fd`.
pub(crate) fn identity(so: u64) -> Option<(i64, i64, i64)> {
    SOCKETS.lock().get(&so).map(|s| (s.domain, s.ty, s.protocol))
}

pub extern "C" fn oxidebsd_sys_socket(domain: u64, ty: u64, protocol: u64) -> i64 {
    let (domain, protocol) = (domain as i64, protocol as i64);
    let base_ty = ty as i64 & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    let proto = match find_protocol(domain, base_ty, protocol) {
        Ok(p) => p,
        Err(e) => return -e,
    };
    let so = fd::oxidebsd_alloc_fd();
    if let Err(e) = proto.attach(so) {
        return -e;
    }
    install(so, domain, base_ty, protocol, proto) as i64
}

pub extern "C" fn oxidebsd_sys_bind(fd: u64, addr_ptr: u64, len: u64) -> i64 {
    let result = lookup(fd).and_then(|(so, proto)| {
        let len = if len == 0 { proto.addr_len() as u64 } else { len };
        proto.bind(so, user_slice(addr_ptr, len)?)
    });
    ffi(result.map(|()| 0))
}

pub extern "C" fn oxidebsd_sys_connect(fd: u64, addr_ptr: u64, len: u64) -> i64 {
    let result = lookup(fd).and_then(|(so, proto)| {
        let len = if len == 0 { proto.addr_len() as u64 } else { len };
        proto.connect(so, user_slice(addr_ptr, len)?)
    });
    ffi(result.map(|()| 0))
}

pub extern "C" fn oxidebsd_sys_listen(fd: u64, backlog: u64) -> i64 {
    ffi(lookup(fd).and_then(|(so, proto)| proto.listen(so, backlog as i64)).map(|()| 0))
}

pub extern "C" fn oxidebsd_sys_accept(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|(so, proto)| {
        let (conn, peer) = proto.accept(so)?;
        let (domain, ty, protocol) = identity(so).ok_or(EBADF as i64)?;
        let user_fd = install(conn, domain, ty, protocol, proto);
        copy_addr_out(addr_ptr, len_ptr, &peer);
        Ok(user_fd)
    });
    ffi(result)
}

pub extern "C" fn oxidebsd_sys_getsockname(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|(so, proto)| {
        copy_addr_out(addr_ptr, len_ptr, &proto.sockname(so)?);
        Ok(0)
    });
    ffi(result)
}

/// `sendto(fd, buf, len, addr)`: the reduced form in use until `sendmsg(2)` replaces it; the
/// address's length comes from the family.
pub extern "C" fn oxidebsd_sys_sendto(fd: u64, buf_ptr: u64, buf_len: u64, addr_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|(so, proto)| {
        let to = if addr_ptr == 0 { None } else { Some(user_slice(addr_ptr, proto.addr_len() as u64)?) };
        proto.send(so, user_slice(buf_ptr, buf_len)?, to)
    });
    ffi(result.map(|n| n as u64))
}

/// `recvfrom(fd, buf, len, addr)`: as `oxidebsd_sys_sendto`, the reduced form; the whole address
/// is written.
pub extern "C" fn oxidebsd_sys_recvfrom(fd: u64, buf_ptr: u64, buf_len: u64, addr_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|(so, proto)| {
        let (n, from) = proto.recv(so, user_slice_mut(buf_ptr, buf_len)?)?;
        if let Some(from) = from {
            copy_addr_out(addr_ptr, 0, &from);
        }
        Ok(n as u64)
    });
    ffi(result)
}

pub extern "C" fn oxidebsd_sys_setsockopt(fd: u64, level: u64, name: u64) -> i64 {
    ffi(lookup(fd).and_then(|(so, proto)| proto.setsockopt(so, level as i64, name as i64)).map(|()| 0))
}

/// `shutdown(2)`. A pipe-backed local socket pair (`crate::fs::pipe`) isn't in the socket table
/// yet, and keeps its own implementation until local sockets replace it (`UNIX.md` §10).
pub extern "C" fn oxidebsd_sys_shutdown(fd: u64, how: u64) -> i64 {
    let Some(so) = fd::real_fd_of(fd) else { return -(EBADF as i64) };
    match proto_of(so) {
        Some(proto) => ffi(proto.shutdown(so, how as i64).map(|()| 0)),
        None => match crate::fs::pipe::do_shutdown(so, how) {
            Ok(v) => v as i64,
            Err(e) => -(e as i64),
        },
    }
}

/// `socketpair(2)`: `AF_UNIX`/`SOCK_STREAM` only, over pipes (`crate::fs::pipe`), until local
/// sockets exist (`UNIX.md` §10).
pub extern "C" fn oxidebsd_sys_socketpair(domain: u64, ty: u64, _protocol: u64, fds_ptr: u64) -> i64 {
    let base_ty = ty as i64 & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    if domain as i64 != AF_UNIX || base_ty != SOCK_STREAM {
        return -(EPROTONOSUPPORT as i64);
    }
    match crate::fs::pipe::do_socketpair(fds_ptr) {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    }
}
