//! The socket system calls, for every family, and the `poll` family (OxideBSD-doc `UNIX.md` §4).
//! This module only registers them; the socket layer (`sys/kern/uipc_socket.rs`) and
//! `sys/net/mod.rs` implement them, since a module can't use `alloc` (see CLAUDE.md's
//! module-loading section).
//!
//! `sendmsg`/`recvmsg` carry every send and receive (the C library builds `sendto`/`recvfrom`/
//! `send`/`recv` on them), and `getsockopt`/`setsockopt` take their four trailing arguments as
//! one structure, since the native ABI passes at most four. The earlier reduced `sendto` (142),
//! `recvfrom` (143) and three-argument `setsockopt` (144) are retired: never registered again,
//! so they fail with `ENOSYS`.
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_socket(domain: u64, ty: u64, protocol: u64) -> i64;
    fn oxidebsd_sys_bind(fd: u64, addr_ptr: u64, len: u64) -> i64;
    fn oxidebsd_sys_connect(fd: u64, addr_ptr: u64, len: u64) -> i64;
    fn oxidebsd_sys_listen(fd: u64, backlog: u64) -> i64;
    fn oxidebsd_sys_accept(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64;
    fn oxidebsd_sys_accept4(fd: u64, addr_ptr: u64, len_ptr: u64, flags: u64) -> i64;
    fn oxidebsd_sys_getsockname(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64;
    fn oxidebsd_sys_getpeername(fd: u64, addr_ptr: u64, len_ptr: u64) -> i64;
    fn oxidebsd_sys_sendmsg(fd: u64, msg_ptr: u64, flags: u64) -> i64;
    fn oxidebsd_sys_recvmsg(fd: u64, msg_ptr: u64, flags: u64) -> i64;
    fn oxidebsd_sys_getsockopt(fd: u64, args_ptr: u64) -> i64;
    fn oxidebsd_sys_setsockopt(fd: u64, args_ptr: u64) -> i64;
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
const SYS_CONNECT: u64 = 145;
const SYS_LISTEN: u64 = 146;
const SYS_ACCEPT: u64 = 147;
const SYS_POLL: u64 = 148;
const SYS_SOCKETPAIR: u64 = 149;
const SYS_SHUTDOWN: u64 = 152;
/// Real Linux's own unclaimed legacy `select(2)` number -- see `crate::net::oxidebsd_sys_select`.
const SYS_SELECT: u64 = 23;
const SYS_GETSOCKNAME: u64 = 559;
const SYS_PPOLL: u64 = 575;
const SYS_SENDMSG: u64 = 577;
const SYS_RECVMSG: u64 = 578;
const SYS_GETSOCKOPT: u64 = 579;
const SYS_SETSOCKOPT: u64 = 580;
const SYS_GETPEERNAME: u64 = 581;
const SYS_ACCEPT4: u64 = 582;

extern "C" fn handle_socket(domain: u64, ty: u64, protocol: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_socket(domain, ty, protocol) }
}

extern "C" fn handle_bind(fd: u64, addr_ptr: u64, len: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_bind(fd, addr_ptr, len) }
}

extern "C" fn handle_connect(fd: u64, addr_ptr: u64, len: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_connect(fd, addr_ptr, len) }
}

extern "C" fn handle_listen(fd: u64, backlog: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_listen(fd, backlog) }
}

extern "C" fn handle_accept(fd: u64, addr_ptr: u64, len_ptr: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_accept(fd, addr_ptr, len_ptr) }
}

extern "C" fn handle_accept4(fd: u64, addr_ptr: u64, len_ptr: u64, flags: u64) -> i64 {
    unsafe { oxidebsd_sys_accept4(fd, addr_ptr, len_ptr, flags) }
}

extern "C" fn handle_getsockname(fd: u64, addr_ptr: u64, len_ptr: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getsockname(fd, addr_ptr, len_ptr) }
}

extern "C" fn handle_getpeername(fd: u64, addr_ptr: u64, len_ptr: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getpeername(fd, addr_ptr, len_ptr) }
}

extern "C" fn handle_sendmsg(fd: u64, msg_ptr: u64, flags: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sendmsg(fd, msg_ptr, flags) }
}

extern "C" fn handle_recvmsg(fd: u64, msg_ptr: u64, flags: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_recvmsg(fd, msg_ptr, flags) }
}

extern "C" fn handle_getsockopt(fd: u64, args_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getsockopt(fd, args_ptr) }
}

extern "C" fn handle_setsockopt(fd: u64, args_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_setsockopt(fd, args_ptr) }
}

extern "C" fn handle_socketpair(domain: u64, ty: u64, protocol: u64, fds_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_socketpair(domain, ty, protocol, fds_ptr) }
}

extern "C" fn handle_shutdown(fd: u64, how: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_shutdown(fd, how) }
}

extern "C" fn handle_poll(fds_ptr: u64, nfds: u64, timeout_ms: u64, _a3: u64) -> i64 {
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
        oxidebsd_register_syscall(SYS_CONNECT, handle_connect);
        oxidebsd_register_syscall(SYS_LISTEN, handle_listen);
        oxidebsd_register_syscall(SYS_ACCEPT, handle_accept);
        oxidebsd_register_syscall(SYS_ACCEPT4, handle_accept4);
        oxidebsd_register_syscall(SYS_GETSOCKNAME, handle_getsockname);
        oxidebsd_register_syscall(SYS_GETPEERNAME, handle_getpeername);
        oxidebsd_register_syscall(SYS_SENDMSG, handle_sendmsg);
        oxidebsd_register_syscall(SYS_RECVMSG, handle_recvmsg);
        oxidebsd_register_syscall(SYS_GETSOCKOPT, handle_getsockopt);
        oxidebsd_register_syscall(SYS_SETSOCKOPT, handle_setsockopt);
        oxidebsd_register_syscall(SYS_SOCKETPAIR, handle_socketpair);
        oxidebsd_register_syscall(SYS_SHUTDOWN, handle_shutdown);
        oxidebsd_register_syscall(SYS_POLL, handle_poll);
        oxidebsd_register_syscall(SYS_PPOLL, handle_ppoll);
        oxidebsd_register_syscall(SYS_SELECT, handle_select);
    }
    log("[module] socket: module_init running (registered the socket system calls and poll/ppoll/select)\n");
    0
}
