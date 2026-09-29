//! The socket layer (OxideBSD-doc `UNIX.md` §§3-4): every socket, whatever its family, is one
//! entry in `SOCKETS`, keyed by the `real_fd` of its open file description, naming the protocol
//! that implements it. The socket system calls resolve the caller's descriptor, look the socket
//! up, and call the protocol through the `Protocol` trait -- the BSDs' protocol switch
//! (`protosw`). Each protocol keeps its own per-socket state (its control block) keyed by the
//! same `real_fd`.
//!
//! What every family shares lives here: `socket(2)`'s `SOCK_CLOEXEC`/`SOCK_NONBLOCK`, blocking
//! and `O_NONBLOCK`/`MSG_DONTWAIT`/`SO_RCVTIMEO`/`SO_SNDTIMEO`, interruption by signals, the
//! `MSG_*` flags, the `SOL_SOCKET` options, `SIGPIPE`, and copying `struct msghdr`, iovecs and
//! addresses in and out. A protocol never blocks: it answers `EAGAIN` and the layer waits
//! (`wait`). Addresses cross as the bytes of the caller's `struct sockaddr`; the protocol parses
//! and builds them.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use spin::Mutex;

use crate::fs::Readiness;
use crate::fs::fd::{self, FdKind};
use crate::process::SIGPIPE;
use crate::syscall::{EAGAIN, EBADF, EINTR, EINVAL, EMSGSIZE, ENOTSOCK, EPIPE, EPROTONOSUPPORT};
use crate::tty::ERESTART;

pub(crate) const AF_UNSPEC: i64 = 0;
pub(crate) const AF_UNIX: i64 = 1;
pub(crate) const AF_INET: i64 = 2;
pub(crate) const SOCK_STREAM: i64 = 1;
pub(crate) const SOCK_DGRAM: i64 = 2;
pub(crate) const SOCK_RAW: i64 = 3;
pub(crate) const SOCK_SEQPACKET: i64 = 5;
/// OR'd into `socket(2)`'s `type`, and `accept4(2)`'s flags, as in Linux and musl.
const SOCK_CLOEXEC: i64 = 0o2000000;
const SOCK_NONBLOCK: i64 = 0o4000;

/// musl's values (`bits/errno.h`).
pub(crate) const EPROTOTYPE: i64 = 91;
pub(crate) const ENOPROTOOPT: i64 = 92;
pub(crate) const EOPNOTSUPP: i64 = 95;
/// Not `EPROTONOSUPPORT` for an unknown domain: musl's `initgroups()` tries an `AF_UNIX` socket to
/// `nscd` first and falls back to reading `/etc/group` only on exactly this error (found through
/// `su`, which calls it).
pub(crate) const EAFNOSUPPORT: i64 = 97;
pub(crate) const ENOTCONN: i64 = 107;
pub(crate) const EINPROGRESS: i64 = 115;

/// `MSG_*` (musl's `<sys/socket.h>`).
const MSG_OOB: i64 = 0x1;
const MSG_PEEK: i64 = 0x2;
const MSG_CTRUNC: i64 = 0x8;
const MSG_TRUNC: i64 = 0x20;
const MSG_DONTWAIT: i64 = 0x40;
pub(crate) const MSG_EOR: i64 = 0x80;
const MSG_WAITALL: i64 = 0x100;
const MSG_NOSIGNAL: i64 = 0x4000;
const MSG_CMSG_CLOEXEC: i64 = 0x40000000;
/// The flags a send or a receive may carry (`UNIX.md` §3.3.4); anything else is `EOPNOTSUPP`.
const SEND_FLAGS: i64 = MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL | MSG_OOB;
const RECV_FLAGS: i64 = MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_TRUNC | MSG_CMSG_CLOEXEC | MSG_OOB;

/// `SOL_SOCKET` and its options (musl's `<sys/socket.h>`, x86_64). `SO_NOSIGPIPE` is FreeBSD's
/// option at FreeBSD's value, added to OxideBSD's musl.
const SOL_SOCKET: i64 = 1;
const SO_REUSEADDR: i64 = 2;
const SO_TYPE: i64 = 3;
const SO_ERROR: i64 = 4;
const SO_BROADCAST: i64 = 6;
const SO_SNDBUF: i64 = 7;
const SO_RCVBUF: i64 = 8;
const SO_KEEPALIVE: i64 = 9;
const SO_LINGER: i64 = 13;
const SO_RCVLOWAT: i64 = 18;
const SO_RCVTIMEO: i64 = 20;
const SO_SNDTIMEO: i64 = 21;
const SO_ACCEPTCONN: i64 = 30;
const SO_PROTOCOL: i64 = 38;
const SO_DOMAIN: i64 = 39;
const SO_NOSIGPIPE: i64 = 0x0800;

/// Socket buffer sizes (`UNIX.md` §6.3): the default, and the range `SO_RCVBUF`/`SO_SNDBUF` accept.
pub(crate) const DEFAULT_BUF: usize = 64 * 1024;
const MIN_BUF: usize = 512;
const MAX_BUF: usize = 1024 * 1024;
/// `IOV_MAX`, and the most control data one message may carry (`UNIX.md` §4.5).
const IOV_MAX: usize = 1024;
const MAX_CONTROL: usize = 4096;

/// A socket address as user space lays it out (`struct sockaddr_*`).
pub(crate) type SockAddr = Vec<u8>;

/// What a protocol's receive produced.
pub(crate) struct Received {
    /// Bytes stored in the buffer.
    pub n: usize,
    /// The whole record's length: more than `n` if a datagram or record was truncated.
    pub full: usize,
    /// The sender, for protocols that have one per message.
    pub from: Option<SockAddr>,
    /// The end of a record was reached (sequenced-packet sockets).
    pub eor: bool,
}

impl Received {
    pub(crate) fn bytes(n: usize) -> Self {
        Received { n, full: n, from: None, eor: false }
    }
}

/// What a protocol implements. Errors are positive errno values; `EAGAIN` means "not now", and
/// the socket layer decides whether to wait. `so` is the socket's `real_fd`.
pub(crate) trait Protocol: Sync {
    /// Sets up the protocol's state for a new socket.
    fn attach(&self, so: u64) -> Result<(), i64>;
    /// Tears it down; the last descriptor for the socket has been closed.
    fn detach(&self, so: u64);
    fn bind(&self, so: u64, addr: &[u8]) -> Result<(), i64>;
    /// Connects, or starts to: `EINPROGRESS` if completion comes later (`connect_result`).
    fn connect(&self, _so: u64, _addr: &[u8]) -> Result<(), i64> {
        Err(EOPNOTSUPP)
    }
    /// How a pending connect ended, or `None` while it hasn't.
    fn connect_result(&self, _so: u64) -> Option<Result<(), i64>> {
        Some(Ok(()))
    }
    fn listen(&self, _so: u64, _backlog: i64) -> Result<(), i64> {
        Err(EOPNOTSUPP)
    }
    /// Takes a completed connection: its `real_fd` (already known to the protocol, not yet to
    /// the socket layer) and the peer's address. `EAGAIN` with none waiting.
    fn accept(&self, _so: u64) -> Result<(u64, SockAddr), i64> {
        Err(EOPNOTSUPP)
    }
    /// Sends `data`, to `to` or the socket's peer. Returns the bytes accepted.
    fn send(&self, so: u64, data: &[u8], to: Option<&[u8]>, flags: i64) -> Result<usize, i64>;
    /// Receives into `buf`; with `peek`, leaves the data queued. `Ok` with `n == 0` on a
    /// connection is end-of-file.
    fn recv(&self, so: u64, buf: &mut [u8], peek: bool) -> Result<Received, i64>;
    fn shutdown(&self, _so: u64, _how: i64) -> Result<(), i64> {
        Err(EOPNOTSUPP)
    }
    fn sockname(&self, so: u64) -> Result<SockAddr, i64>;
    fn peername(&self, _so: u64) -> Result<SockAddr, i64> {
        Err(ENOTCONN)
    }
    /// An option at a level other than `SOL_SOCKET`.
    fn setopt(&self, _so: u64, _level: i64, _name: i64, _val: &[u8]) -> Result<(), i64> {
        Err(ENOPROTOOPT)
    }
    fn getopt(&self, _so: u64, _level: i64, _name: i64) -> Result<Vec<u8>, i64> {
        Err(ENOPROTOOPT)
    }
    /// Takes the socket's pending error (`SO_ERROR`), 0 if none.
    fn take_error(&self, _so: u64) -> i64 {
        0
    }
    fn readiness(&self, so: u64) -> Readiness;
    /// Whether the socket's state changes only when a waiter drives the network interface
    /// (`crate::net::poll`), rather than when another process runs (`UNIX.md` §3.4).
    fn pulled(&self) -> bool;
}

/// The `SOL_SOCKET` options kept by the layer. Those the protocols don't act on yet
/// (`SO_KEEPALIVE`, `SO_LINGER`, `SO_BROADCAST`, the buffer sizes for Internet sockets) are
/// recorded and reported back.
#[derive(Clone, Copy)]
pub(crate) struct Options {
    pub rcvbuf: usize,
    pub sndbuf: usize,
    rcvlowat: usize,
    rcvtimeo_ms: u64,
    sndtimeo_ms: u64,
    reuseaddr: bool,
    keepalive: bool,
    broadcast: bool,
    linger: Option<i32>,
    nosigpipe: bool,
}

impl Options {
    const fn new() -> Self {
        Options {
            rcvbuf: DEFAULT_BUF,
            sndbuf: DEFAULT_BUF,
            rcvlowat: 1,
            rcvtimeo_ms: 0,
            sndtimeo_ms: 0,
            reuseaddr: false,
            keepalive: false,
            broadcast: false,
            linger: None,
            nosigpipe: false,
        }
    }
}

struct Socket {
    domain: i64,
    ty: i64,
    protocol: i64,
    proto: &'static dyn Protocol,
    opts: Options,
    listening: bool,
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

/// What the socket calls need of a socket: its `real_fd`, protocol, type and options.
#[derive(Clone, Copy)]
struct Handle {
    so: u64,
    proto: &'static dyn Protocol,
    ty: i64,
    opts: Options,
}

fn handle_of(so: u64) -> Option<Handle> {
    SOCKETS.lock().get(&so).map(|s| Handle { so, proto: s.proto, ty: s.ty, opts: s.opts })
}

/// The calling process's descriptor `fd`, as a socket.
fn lookup(fd: u64) -> Result<Handle, i64> {
    let so = fd::real_fd_of(fd).ok_or(EBADF as i64)?;
    handle_of(so).ok_or(ENOTSOCK as i64)
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

fn read_u32(ptr: u64) -> u32 {
    // SAFETY: as `user_slice`.
    unsafe { core::ptr::read_unaligned(ptr as *const u32) }
}

fn write_u32(ptr: u64, value: u32) {
    // SAFETY: as `user_slice`.
    unsafe { core::ptr::write_unaligned(ptr as *mut u32, value) }
}

fn read_u64(ptr: u64) -> u64 {
    // SAFETY: as `user_slice`.
    unsafe { core::ptr::read_unaligned(ptr as *const u64) }
}

/// Copies an address out: at most `*len_ptr` bytes, storing the address's real length there. A
/// null `ptr` means the caller doesn't want it.
fn copy_addr_out(ptr: u64, len_ptr: u64, addr: &[u8]) {
    if ptr == 0 || len_ptr == 0 {
        return;
    }
    let room = read_u32(len_ptr) as usize;
    write_u32(len_ptr, addr.len() as u32);
    let n = room.min(addr.len());
    // SAFETY: as `user_slice`.
    unsafe { core::ptr::copy_nonoverlapping(addr.as_ptr(), ptr as *mut u8, n) };
}

/// Gives the calling process a descriptor for the socket `so`, served by `proto`, with
/// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` from `flags`.
fn install(so: u64, domain: i64, ty: i64, protocol: i64, proto: &'static dyn Protocol, flags: i64) -> u64 {
    let socket = Socket { domain, ty, protocol, proto, opts: Options::new(), listening: false };
    SOCKETS.lock().insert(so, socket);
    let user_fd = fd::oxidebsd_register_fd_ops(so, so_read, so_write, so_close);
    fd::set_kind(so, FdKind::Socket(so));
    if flags & SOCK_NONBLOCK != 0 {
        fd::set_nonblocking(so, true);
    }
    if flags & SOCK_CLOEXEC != 0 {
        fd::set_cloexec(crate::process::scheduler::current_tgid(), user_fd, true);
    }
    user_fd
}

/// A deadline on the TSC for a timeout of `ms` (0 = none).
fn deadline_for(ms: u64) -> Option<u64> {
    (ms > 0).then(|| crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(ms))
}

/// Waits for the socket's state to change. `EAGAIN` once `deadline` passes; for a signal,
/// `EINTR` if a timeout is set, else `ERESTART` (`UNIX.md` §3.3.3: `SA_RESTART` restarts it).
fn wait(h: &Handle, deadline: Option<u64>) -> Result<(), i64> {
    let deadline_tick = match deadline {
        Some(d) => {
            let now = crate::cpu::tsc::now();
            if now >= d {
                return Err(EAGAIN as i64);
            }
            crate::net::deadline_tick_for(crate::cpu::tsc::cycles_to_ms(d - now) as i64)
        }
        None => u64::MAX,
    };
    match crate::net::wait_for_change(h.proto.pulled(), deadline_tick) {
        Ok(()) => Ok(()),
        Err(_) if deadline.is_some() => Err(EINTR as i64),
        Err(_) => Err(ERESTART as i64),
    }
}

fn nonblocking(h: &Handle, flags: i64) -> bool {
    flags & MSG_DONTWAIT != 0 || fd::is_nonblocking(h.so)
}

/// Sends one message: all of `data` as one datagram or record, or as much of a stream as goes
/// before the socket would block. `SIGPIPE` for `EPIPE` unless suppressed (§3.3.6).
fn send(h: &Handle, data: &[u8], to: Option<&[u8]>, flags: i64) -> Result<usize, i64> {
    if flags & !SEND_FLAGS != 0 || flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    if flags & MSG_EOR != 0 && h.ty != SOCK_SEQPACKET {
        return Err(EOPNOTSUPP);
    }
    let deadline = deadline_for(h.opts.sndtimeo_ms);
    let mut sent = 0;
    loop {
        match h.proto.send(h.so, &data[sent..], to, flags) {
            Ok(n) => {
                sent += n;
                if sent == data.len() || h.ty != SOCK_STREAM {
                    return Ok(sent);
                }
            }
            Err(e) if e == EAGAIN as i64 => {}
            Err(e) if e == EPIPE as i64 => {
                if flags & MSG_NOSIGNAL == 0 && !h.opts.nosigpipe {
                    raise_sigpipe();
                }
                return if sent > 0 { Ok(sent) } else { Err(e) };
            }
            Err(e) => return if sent > 0 { Ok(sent) } else { Err(e) },
        }
        if nonblocking(h, flags) {
            return if sent > 0 { Ok(sent) } else { Err(EAGAIN as i64) };
        }
        if let Err(e) = wait(h, deadline) {
            return if sent > 0 { Ok(sent) } else { Err(e) };
        }
    }
}

fn raise_sigpipe() {
    let pid = crate::process::scheduler::current_pid();
    if pid != 0 {
        let _ = crate::process::signals::do_kill(pid, pid as i64, SIGPIPE as i64);
    }
}

/// Receives one message into `buf`. With `MSG_WAITALL` on a stream, keeps receiving until `buf`
/// is full, end-of-file, an error or a signal. Returns the length to report (the whole record's
/// with `MSG_TRUNC`), the sender, and the `msg_flags` to report.
fn recv(h: &Handle, buf: &mut [u8], flags: i64) -> Result<(usize, Option<SockAddr>, i64), i64> {
    if flags & !RECV_FLAGS != 0 || flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    let peek = flags & MSG_PEEK != 0;
    let waitall = flags & MSG_WAITALL != 0 && h.ty == SOCK_STREAM && !peek;
    let deadline = deadline_for(h.opts.rcvtimeo_ms);
    let mut got = 0;
    loop {
        match h.proto.recv(h.so, &mut buf[got..], peek) {
            Ok(r) => {
                if h.ty != SOCK_STREAM {
                    let mut out_flags = 0;
                    if r.full > r.n {
                        out_flags |= MSG_TRUNC;
                    }
                    if r.eor {
                        out_flags |= MSG_EOR;
                    }
                    let len = if flags & MSG_TRUNC != 0 { r.full } else { r.n };
                    return Ok((len, r.from, out_flags));
                }
                got += r.n;
                if r.n == 0 || !waitall || got == buf.len() {
                    return Ok((got, r.from, 0));
                }
            }
            Err(e) if e == EAGAIN as i64 => {}
            Err(e) => return if got > 0 { Ok((got, None, 0)) } else { Err(e) },
        }
        if nonblocking(h, flags) {
            return if got > 0 { Ok((got, None, 0)) } else { Err(EAGAIN as i64) };
        }
        if let Err(e) = wait(h, deadline) {
            return if got > 0 { Ok((got, None, 0)) } else { Err(e) };
        }
    }
}

extern "C" fn so_read(so: u64, ptr: u64, len: u64) -> i64 {
    let Some(h) = handle_of(so) else { return -(EBADF as i64) };
    let result = user_slice_mut(ptr, len).and_then(|buf| recv(&h, buf, 0));
    ffi(result.map(|(n, _, _)| n as u64))
}

/// `write(2)` on a socket. `sys_write` raises `SIGPIPE` for `EPIPE` itself, unless
/// `suppresses_sigpipe`, so it isn't raised here too.
extern "C" fn so_write(so: u64, ptr: u64, len: u64) -> i64 {
    let Some(h) = handle_of(so) else { return -(EBADF as i64) };
    let result = user_slice(ptr, len).and_then(|data| send(&h, data, None, MSG_NOSIGNAL));
    ffi(result.map(|n| n as u64))
}

extern "C" fn so_close(so: u64) -> i64 {
    // Out of the lock first: a protocol's detach may come back into the socket layer.
    let socket = SOCKETS.lock().remove(&so);
    if let Some(socket) = socket {
        socket.proto.detach(so);
    }
    0
}

/// Whether `write(2)` on `real_fd` must not raise `SIGPIPE` (`SO_NOSIGPIPE`).
pub(crate) fn suppresses_sigpipe(real_fd: u64) -> bool {
    SOCKETS.lock().get(&real_fd).is_some_and(|s| s.opts.nosigpipe)
}

/// `poll(2)`/`select(2)` state of `real_fd`, and whether its protocol is pulled (§3.4); `None` if
/// it isn't a socket.
pub(crate) fn readiness(so: u64) -> Option<(Readiness, bool)> {
    let h = handle_of(so)?;
    Some((h.proto.readiness(so), h.proto.pulled()))
}

/// `(domain, type, protocol)` of the socket `real_fd`.
pub(crate) fn identity(so: u64) -> Option<(i64, i64, i64)> {
    SOCKETS.lock().get(&so).map(|s| (s.domain, s.ty, s.protocol))
}

pub extern "C" fn oxidebsd_sys_socket(domain: u64, ty: u64, protocol: u64) -> i64 {
    let (domain, protocol) = (domain as i64, protocol as i64);
    let flags = ty as i64 & (SOCK_CLOEXEC | SOCK_NONBLOCK);
    let base_ty = ty as i64 & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    let proto = match find_protocol(domain, base_ty, protocol) {
        Ok(p) => p,
        Err(e) => return -e,
    };
    let so = fd::oxidebsd_alloc_fd();
    if let Err(e) = proto.attach(so) {
        return -e;
    }
    install(so, domain, base_ty, protocol, proto, flags) as i64
}

pub extern "C" fn oxidebsd_sys_bind(fd: u64, addr_ptr: u64, len: u64) -> i64 {
    let result = lookup(fd).and_then(|h| h.proto.bind(h.so, user_slice(addr_ptr, len)?));
    ffi(result.map(|()| 0))
}

pub extern "C" fn oxidebsd_sys_connect(fd: u64, addr_ptr: u64, len: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        match h.proto.connect(h.so, user_slice(addr_ptr, len)?) {
            Err(e) if e == EINPROGRESS => {}
            other => return other,
        }
        if fd::is_nonblocking(h.so) {
            return Err(EINPROGRESS);
        }
        loop {
            if let Some(result) = h.proto.connect_result(h.so) {
                return result;
            }
            // A connection being set up isn't interrupted by `SA_RESTART`-restarting: the
            // restarted call would find it already in progress. `EINTR`, as in the BSDs.
            if let Err(e) = wait(&h, None) {
                return Err(if e == ERESTART as i64 { EINTR as i64 } else { e });
            }
        }
    });
    ffi(result.map(|()| 0))
}

pub extern "C" fn oxidebsd_sys_listen(fd: u64, backlog: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        h.proto.listen(h.so, backlog as i32 as i64)?;
        if let Some(s) = SOCKETS.lock().get_mut(&h.so) {
            s.listening = true;
        }
        Ok(())
    });
    ffi(result.map(|()| 0))
}

fn accept(fd: u64, addr_ptr: u64, len_ptr: u64, flags: i64) -> Result<u64, i64> {
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(EINVAL as i64);
    }
    let h = lookup(fd)?;
    let deadline = deadline_for(h.opts.rcvtimeo_ms);
    loop {
        match h.proto.accept(h.so) {
            Ok((conn, peer)) => {
                let (domain, ty, protocol) = identity(h.so).ok_or(EBADF as i64)?;
                let user_fd = install(conn, domain, ty, protocol, h.proto, flags);
                copy_addr_out(addr_ptr, len_ptr, &peer);
                return Ok(user_fd);
            }
            Err(e) if e == EAGAIN as i64 => {}
            Err(e) => return Err(e),
        }
        if fd::is_nonblocking(h.so) {
            return Err(EAGAIN as i64);
        }
        wait(&h, deadline)?;
    }
}

pub extern "C" fn oxidebsd_sys_accept(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64 {
    ffi(accept(fd, addr_ptr, len_ptr, 0))
}

pub extern "C" fn oxidebsd_sys_accept4(fd: u64, addr_ptr: u64, len_ptr: u64, flags: u64) -> i64 {
    ffi(accept(fd, addr_ptr, len_ptr, flags as i64))
}

pub extern "C" fn oxidebsd_sys_getsockname(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        copy_addr_out(addr_ptr, len_ptr, &h.proto.sockname(h.so)?);
        Ok(0)
    });
    ffi(result)
}

pub extern "C" fn oxidebsd_sys_getpeername(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        copy_addr_out(addr_ptr, len_ptr, &h.proto.peername(h.so)?);
        Ok(0)
    });
    ffi(result)
}

/// musl's `struct msghdr` on x86_64: `msg_name` at 0, `msg_namelen` at 8, `msg_iov` at 16,
/// `msg_iovlen` at 24, `msg_control` at 32, `msg_controllen` at 40, `msg_flags` at 48.
struct MsgHdr {
    ptr: u64,
    name: u64,
    namelen: u32,
    iovs: Vec<(u64, u64)>,
    control: u64,
    controllen: u32,
}

impl MsgHdr {
    fn read(ptr: u64) -> Result<MsgHdr, i64> {
        if ptr == 0 {
            return Err(EINVAL as i64);
        }
        let iov = read_u64(ptr + 16);
        let iovlen = read_u32(ptr + 24) as usize;
        if iovlen > IOV_MAX {
            return Err(EMSGSIZE as i64);
        }
        let mut iovs = Vec::with_capacity(iovlen);
        for i in 0..iovlen as u64 {
            let base = read_u64(iov + i * 16);
            let len = read_u64(iov + i * 16 + 8);
            if len > isize::MAX as u64 {
                return Err(EINVAL as i64);
            }
            iovs.push((base, len));
        }
        let controllen = read_u32(ptr + 40);
        if controllen as usize > MAX_CONTROL {
            return Err(EINVAL as i64);
        }
        Ok(MsgHdr {
            ptr,
            name: read_u64(ptr),
            namelen: read_u32(ptr + 8),
            iovs,
            control: read_u64(ptr + 32),
            controllen,
        })
    }

    fn total(&self) -> usize {
        self.iovs.iter().map(|&(_, len)| len as usize).sum()
    }
}

/// `sendmsg(fd, msghdr, flags)`, system call 577: every other send is built on it.
pub extern "C" fn oxidebsd_sys_sendmsg(fd: u64, msg_ptr: u64, flags: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        let msg = MsgHdr::read(msg_ptr)?;
        if msg.controllen != 0 {
            // No protocol takes control data yet (descriptor and credential passing: UNIX.md
            // §§8-9).
            return Err(EOPNOTSUPP);
        }
        let mut data = Vec::with_capacity(msg.total());
        for &(base, len) in &msg.iovs {
            data.extend_from_slice(user_slice(base, len)?);
        }
        let to = if msg.name == 0 { None } else { Some(user_slice(msg.name, msg.namelen as u64)?) };
        send(&h, &data, to, flags as i64).map(|n| n as u64)
    });
    ffi(result)
}

/// `recvmsg(fd, msghdr, flags)`, system call 578: every other receive is built on it.
pub extern "C" fn oxidebsd_sys_recvmsg(fd: u64, msg_ptr: u64, flags: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        let msg = MsgHdr::read(msg_ptr)?;
        // Capped: a datagram is never bigger, and a stream receive may be short.
        let mut buf = vec![0u8; msg.total().min(MAX_BUF)];
        let (len, from, mut out_flags) = recv(&h, &mut buf, flags as i64)?;
        let mut left = &buf[..len.min(buf.len())];
        for &(base, iov_len) in &msg.iovs {
            if left.is_empty() {
                break;
            }
            let n = left.len().min(iov_len as usize);
            user_slice_mut(base, n as u64)?.copy_from_slice(&left[..n]);
            left = &left[n..];
        }
        match from {
            Some(from) if msg.name != 0 => {
                let n = (msg.namelen as usize).min(from.len());
                user_slice_mut(msg.name, n as u64)?.copy_from_slice(&from[..n]);
                write_u32(msg.ptr + 8, from.len() as u32);
            }
            _ => write_u32(msg.ptr + 8, 0),
        }
        if msg.controllen != 0 && msg.control == 0 {
            out_flags |= MSG_CTRUNC;
        }
        write_u32(msg.ptr + 40, 0); // no control data yet
        write_u32(msg.ptr + 48, out_flags as u32);
        Ok(len as u64)
    });
    ffi(result)
}

/// `get/setsockopt`'s arguments past the descriptor: `{ level, name, optval, optlen }`, where
/// `optlen` is the option's length for `setsockopt` and a `socklen_t *` for `getsockopt`.
struct SockoptArgs {
    level: i64,
    name: i64,
    val: u64,
    len: u64,
}

impl SockoptArgs {
    fn read(ptr: u64) -> Result<SockoptArgs, i64> {
        if ptr == 0 {
            return Err(EINVAL as i64);
        }
        Ok(SockoptArgs {
            level: read_u64(ptr) as i32 as i64,
            name: read_u64(ptr + 8) as i32 as i64,
            val: read_u64(ptr + 16),
            len: read_u64(ptr + 24),
        })
    }
}

fn opt_int(val: &[u8]) -> Result<i32, i64> {
    val.get(..4).map(|b| i32::from_ne_bytes(b.try_into().unwrap())).ok_or(EINVAL as i64)
}

fn opt_timeval_ms(val: &[u8]) -> Result<u64, i64> {
    if val.len() < 16 {
        return Err(EINVAL as i64);
    }
    let sec = i64::from_ne_bytes(val[0..8].try_into().unwrap());
    let usec = i64::from_ne_bytes(val[8..16].try_into().unwrap());
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(EINVAL as i64);
    }
    Ok(sec as u64 * 1000 + (usec as u64).div_ceil(1000))
}

fn timeval_bytes(ms: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&((ms / 1000) as i64).to_ne_bytes());
    v.extend_from_slice(&(((ms % 1000) * 1000) as i64).to_ne_bytes());
    v
}

fn int_bytes(v: i64) -> Vec<u8> {
    (v as i32).to_ne_bytes().to_vec()
}

/// `setsockopt(fd, sockopt)`, system call 580.
pub extern "C" fn oxidebsd_sys_setsockopt(fd: u64, args_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        let a = SockoptArgs::read(args_ptr)?;
        let val = user_slice(a.val, a.len)?;
        if a.level != SOL_SOCKET {
            return h.proto.setopt(h.so, a.level, a.name, val);
        }
        let mut sockets = SOCKETS.lock();
        let opts = &mut sockets.get_mut(&h.so).ok_or(EBADF as i64)?.opts;
        let clamp = |v: i32| (v.max(0) as usize).clamp(MIN_BUF, MAX_BUF);
        match a.name {
            SO_REUSEADDR => opts.reuseaddr = opt_int(val)? != 0,
            SO_KEEPALIVE => opts.keepalive = opt_int(val)? != 0,
            SO_BROADCAST => opts.broadcast = opt_int(val)? != 0,
            SO_NOSIGPIPE => opts.nosigpipe = opt_int(val)? != 0,
            SO_RCVBUF => opts.rcvbuf = clamp(opt_int(val)?),
            SO_SNDBUF => opts.sndbuf = clamp(opt_int(val)?),
            SO_RCVLOWAT => opts.rcvlowat = opt_int(val)?.max(1) as usize,
            SO_RCVTIMEO => opts.rcvtimeo_ms = opt_timeval_ms(val)?,
            SO_SNDTIMEO => opts.sndtimeo_ms = opt_timeval_ms(val)?,
            SO_LINGER => {
                if val.len() < 8 {
                    return Err(EINVAL as i64);
                }
                let on = opt_int(&val[0..4])?;
                let secs = opt_int(&val[4..8])?;
                opts.linger = (on != 0).then_some(secs.max(0));
            }
            _ => return Err(ENOPROTOOPT),
        }
        Ok(())
    });
    ffi(result.map(|()| 0))
}

/// `getsockopt(fd, sockopt)`, system call 579.
pub extern "C" fn oxidebsd_sys_getsockopt(fd: u64, args_ptr: u64) -> i64 {
    let result = lookup(fd).and_then(|h| {
        let a = SockoptArgs::read(args_ptr)?;
        if a.len == 0 {
            return Err(EINVAL as i64);
        }
        let value = if a.level != SOL_SOCKET {
            h.proto.getopt(h.so, a.level, a.name)?
        } else {
            let sockets = SOCKETS.lock();
            let s = sockets.get(&h.so).ok_or(EBADF as i64)?;
            let o = &s.opts;
            match a.name {
                SO_TYPE => int_bytes(s.ty),
                SO_DOMAIN => int_bytes(s.domain),
                SO_PROTOCOL => int_bytes(s.protocol),
                SO_ACCEPTCONN => int_bytes(s.listening as i64),
                SO_ERROR => {
                    drop(sockets);
                    int_bytes(h.proto.take_error(h.so))
                }
                SO_REUSEADDR => int_bytes(o.reuseaddr as i64),
                SO_KEEPALIVE => int_bytes(o.keepalive as i64),
                SO_BROADCAST => int_bytes(o.broadcast as i64),
                SO_NOSIGPIPE => int_bytes(o.nosigpipe as i64),
                SO_RCVBUF => int_bytes(o.rcvbuf as i64),
                SO_SNDBUF => int_bytes(o.sndbuf as i64),
                SO_RCVLOWAT => int_bytes(o.rcvlowat as i64),
                SO_RCVTIMEO => timeval_bytes(o.rcvtimeo_ms),
                SO_SNDTIMEO => timeval_bytes(o.sndtimeo_ms),
                SO_LINGER => {
                    let mut v = int_bytes(o.linger.is_some() as i64);
                    v.extend_from_slice(&int_bytes(o.linger.unwrap_or(0) as i64));
                    v
                }
                _ => return Err(ENOPROTOOPT),
            }
        };
        let room = read_u32(a.len) as usize;
        let n = room.min(value.len());
        user_slice_mut(a.val, n as u64)?.copy_from_slice(&value[..n]);
        write_u32(a.len, n as u32);
        Ok(())
    });
    ffi(result.map(|()| 0))
}

/// `shutdown(2)`. A pipe-backed local socket pair (`crate::fs::pipe`) isn't in the socket table
/// yet, and keeps its own implementation until local sockets replace it (`UNIX.md` §10).
pub extern "C" fn oxidebsd_sys_shutdown(fd: u64, how: u64) -> i64 {
    let Some(so) = fd::real_fd_of(fd) else { return -(EBADF as i64) };
    if how > 2 {
        return -(EINVAL as i64);
    }
    match handle_of(so) {
        Some(h) => ffi(h.proto.shutdown(so, how as i64).map(|()| 0)),
        None => match crate::fs::pipe::do_shutdown(so, how) {
            Ok(v) => v as i64,
            Err(e) => -(e as i64),
        },
    }
}

/// `socketpair(2)`: `AF_UNIX`/`SOCK_STREAM` only, over pipes (`crate::fs::pipe`), until local
/// sockets exist (`UNIX.md` §10).
pub extern "C" fn oxidebsd_sys_socketpair(domain: u64, ty: u64, _protocol: u64, fds_ptr: u64) -> i64 {
    let flags = ty as i64 & (SOCK_CLOEXEC | SOCK_NONBLOCK);
    let base_ty = ty as i64 & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    if domain as i64 != AF_UNIX {
        return -EOPNOTSUPP;
    }
    if base_ty != SOCK_STREAM {
        return -(EPROTONOSUPPORT as i64);
    }
    if let Err(e) = crate::fs::pipe::do_socketpair(fds_ptr) {
        return -(e as i64);
    }
    // SAFETY: `do_socketpair` just wrote both descriptors there.
    let fds = unsafe { core::slice::from_raw_parts(fds_ptr as *const i32, 2) };
    for &user_fd in fds {
        let user_fd = user_fd as u64;
        if flags & SOCK_NONBLOCK != 0
            && let Some(real_fd) = fd::real_fd_of(user_fd)
        {
            fd::set_nonblocking(real_fd, true);
        }
        if flags & SOCK_CLOEXEC != 0 {
            fd::set_cloexec(crate::process::scheduler::current_tgid(), user_fd, true);
        }
    }
    0
}

/// `AF_UNSPEC` names no address: for `connect(2)`, "disconnect".
pub(crate) fn is_unspec(addr: &[u8]) -> bool {
    addr.len() >= 2 && u16::from_ne_bytes([addr[0], addr[1]]) as i64 == AF_UNSPEC
}
