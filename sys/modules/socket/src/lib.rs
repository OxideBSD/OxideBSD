//! `SYS_SOCKET = 140`, `SYS_BIND = 141`, `SYS_SENDTO = 142`, `SYS_RECVFROM = 143`,
//! `SYS_SETSOCKOPT = 144`, `SYS_CONNECT = 145`, `SYS_LISTEN = 146`, `SYS_ACCEPT = 147`,
//! `SYS_POLL = 148`, `SYS_SOCKETPAIR = 149`, `SYS_SHUTDOWN = 152`, `SYS_GETSOCKNAME = 559`,
//! `SYS_PPOLL = 575`, `SYS_SELECT`: the socket system calls, for every family, and the `poll`
//! family. This module only registers them; the socket layer (`sys/kern/uipc_socket.rs`) and
//! `sys/net/mod.rs` implement them, since a module can't use `alloc` (see CLAUDE.md's
//! module-loading section).
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_socket(domain: u64, ty: u64, protocol: u64) -> i64;
    fn oxidebsd_sys_bind(fd: u64, addr_ptr: u64, len: u64) -> i64;
    fn oxidebsd_sys_sendto(fd: u64, buf_ptr: u64, buf_len: u64, addr_ptr: u64) -> i64;
    fn oxidebsd_sys_recvfrom(fd: u64, buf_ptr: u64, buf_len: u64, addr_out_ptr: u64) -> i64;
    fn oxidebsd_sys_setsockopt(fd: u64, level: u64, optname: u64) -> i64;
    fn oxidebsd_sys_connect(fd: u64, addr_ptr: u64, len: u64) -> i64;
    fn oxidebsd_sys_listen(fd: u64, backlog: u64) -> i64;
    fn oxidebsd_sys_accept(fd: u64, addr_out_ptr: u64, addrlen_ptr: u64) -> i64;
    fn oxidebsd_sys_getsockname(fd: u64, addr_out_ptr: u64, addrlen_ptr: u64) -> i64;
    fn oxidebsd_sys_socketpair(domain: u64, ty: u64, protocol: u64, fds_ptr: u64) -> i64;
    fn oxidebsd_sys_shutdown(fd: u64, how: u64) -> i64;
    fn oxidebsd_sys_poll(fds_ptr: u64, nfds: u64, timeout_ms: u64) -> i64;
    fn oxidebsd_sys_ppoll(fds_ptr: u64, nfds: u64, timeout_ptr: u64, mask_ptr: u64) -> i64;
    fn oxidebsd_sys_select(req_ptr: u64) -> i64;
}

fn log(message: &str) {
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
}

const SYS_SOCKET: u64 = 140;
const SYS_BIND: u64 = 141;
const SYS_SENDTO: u64 = 142;
const SYS_RECVFROM: u64 = 143;
const SYS_SETSOCKOPT: u64 = 144;
const SYS_CONNECT: u64 = 145;
const SYS_LISTEN: u64 = 146;
const SYS_ACCEPT: u64 = 147;
const SYS_POLL: u64 = 148;
const SYS_SOCKETPAIR: u64 = 149;
const SYS_SHUTDOWN: u64 = 152;
/// Real Linux's own unclaimed legacy `select(2)` number -- see `crate::net::oxidebsd_sys_select`'s
/// own doc comment for the real logic.
const SYS_SELECT: u64 = 23;
/// OxideBSD's own invention (`559`, continuing right past `SYS_GET_KEYEVENT=558`, the current
/// highest assigned number as of this addition). Real `getsockname(2)` -- needed the moment any
/// real `std::net` consumer calls `local_addr()` (see `sys/netinet/udp.rs`'s
/// `oxidebsd_sys_getsockname`/`sys/netinet/tcp.rs`'s `getsockname`).
const SYS_GETSOCKNAME: u64 = 559;
/// Real `ppoll(2)` -- see `crate::net::oxidebsd_sys_ppoll`. Continues past the `*at()` family's
/// `560`-`574`, the highest numbers assigned before it.
const SYS_PPOLL: u64 = 575;

extern "C" fn handle_socket(domain: u64, ty: u64, protocol: u64, _r10: u64) -> i64 {
    unsafe { oxidebsd_sys_socket(domain, ty, protocol) }
}

extern "C" fn handle_bind(fd: u64, addr_ptr: u64, len: u64, _r10: u64) -> i64 {
    unsafe { oxidebsd_sys_bind(fd, addr_ptr, len) }
}

extern "C" fn handle_sendto(fd: u64, buf_ptr: u64, buf_len: u64, addr_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_sendto(fd, buf_ptr, buf_len, addr_ptr) }
}

extern "C" fn handle_recvfrom(fd: u64, buf_ptr: u64, buf_len: u64, addr_out_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_recvfrom(fd, buf_ptr, buf_len, addr_out_ptr) }
}

extern "C" fn handle_setsockopt(fd: u64, level: u64, optname: u64, _r10: u64) -> i64 {
    unsafe { oxidebsd_sys_setsockopt(fd, level, optname) }
}

extern "C" fn handle_connect(fd: u64, addr_ptr: u64, len: u64, _r10: u64) -> i64 {
    unsafe { oxidebsd_sys_connect(fd, addr_ptr, len) }
}

extern "C" fn handle_listen(fd: u64, backlog: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_listen(fd, backlog) }
}

extern "C" fn handle_accept(fd: u64, addr_out_ptr: u64, addrlen_ptr: u64, _r10: u64) -> i64 {
    unsafe { oxidebsd_sys_accept(fd, addr_out_ptr, addrlen_ptr) }
}

extern "C" fn handle_getsockname(fd: u64, addr_out_ptr: u64, addrlen_ptr: u64, _r10: u64) -> i64 {
    unsafe { oxidebsd_sys_getsockname(fd, addr_out_ptr, addrlen_ptr) }
}

extern "C" fn handle_socketpair(domain: u64, ty: u64, protocol: u64, fds_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_socketpair(domain, ty, protocol, fds_ptr) }
}

extern "C" fn handle_shutdown(fd: u64, how: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_shutdown(fd, how) }
}

extern "C" fn handle_poll(fds_ptr: u64, nfds: u64, timeout_ms: u64, _r10: u64) -> i64 {
    unsafe { oxidebsd_sys_poll(fds_ptr, nfds, timeout_ms) }
}

extern "C" fn handle_ppoll(fds_ptr: u64, nfds: u64, timeout_ptr: u64, mask_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_ppoll(fds_ptr, nfds, timeout_ptr, mask_ptr) }
}

extern "C" fn handle_select(req_ptr: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_select(req_ptr) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_SOCKET, handle_socket);
        oxidebsd_register_syscall(SYS_BIND, handle_bind);
        oxidebsd_register_syscall(SYS_SENDTO, handle_sendto);
        oxidebsd_register_syscall(SYS_RECVFROM, handle_recvfrom);
        oxidebsd_register_syscall(SYS_SETSOCKOPT, handle_setsockopt);
        oxidebsd_register_syscall(SYS_CONNECT, handle_connect);
        oxidebsd_register_syscall(SYS_LISTEN, handle_listen);
        oxidebsd_register_syscall(SYS_ACCEPT, handle_accept);
        oxidebsd_register_syscall(SYS_GETSOCKNAME, handle_getsockname);
        oxidebsd_register_syscall(SYS_SOCKETPAIR, handle_socketpair);
        oxidebsd_register_syscall(SYS_SHUTDOWN, handle_shutdown);
        oxidebsd_register_syscall(SYS_POLL, handle_poll);
        oxidebsd_register_syscall(SYS_PPOLL, handle_ppoll);
        oxidebsd_register_syscall(SYS_SELECT, handle_select);
    }
    log(
        "[module] socket: module_init running (registered SYS_SOCKET/SYS_BIND/SYS_SENDTO/\
         SYS_RECVFROM/SYS_SETSOCKOPT/SYS_CONNECT/SYS_LISTEN/SYS_ACCEPT/SYS_GETSOCKNAME/\
         SYS_SOCKETPAIR/SYS_SHUTDOWN/SYS_POLL/SYS_SELECT)\n",
    );
    0
}
