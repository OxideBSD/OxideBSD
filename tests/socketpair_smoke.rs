//! Smoke test for `SYS_SOCKETPAIR = 149` (local sockets, `sys/kern/uipc_usrreq.rs`), `SYS_FCNTL = 151`, and
//! `SYS_SHUTDOWN = 152` -- all added to unblock BusyBox's `wget` HTTPS path (`spawn_ssl_client` in
//! `networking/wget.c` uses a socketpair; `libbb/xfuncs.c`'s `ndelay_on`/`ndelay_off` need real
//! `fcntl`; `wget.c` itself calls `shutdown(fd, SHUT_WR)` on the same kind of endpoint -- see
//! CLAUDE.md's "Real networking" known-gaps entry). Calls the kernel's own FFI-level
//! `oxidebsd_sys_*` entry points directly, same technique `tests/tcp_smoke.rs` already uses -- no
//! module loading or real process needed, since this test never blocks: every read here happens
//! once data, a close, or a real `O_NONBLOCK` flag has already made the outcome immediate.
//!
//! Covers: both directions of a full-duplex pair actually reach the peer; closing one end
//! produces real EOF (on the peer's read) and EPIPE (on the peer's write); `fcntl(F_SETFL,
//! O_NONBLOCK)` makes an empty read return real `EAGAIN` instead of blocking (which would hang
//! this whole test, given this kernel is single-core and cooperatively scheduled -- see
//! `src/pipe.rs`'s own doc comment); `shutdown(SHUT_WR)` half-closes just one direction, leaving
//! the other direction of the same pair fully functional.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::fs::fd::oxidebsd_close_fd;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::kern::uipc_socket::{oxidebsd_sys_shutdown, oxidebsd_sys_socketpair};
use oxidebsd::syscall::{
    oxidebsd_sys_fcntl, oxidebsd_sys_read, oxidebsd_sys_set_tid_address, oxidebsd_sys_write,
};

limine_entry_point!(main);

const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const O_NONBLOCK: u64 = 0o4000;
const SHUT_WR: u64 = 1;

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);

    let mut fds: [i32; 2] = [-1, -1];
    let rc = oxidebsd_sys_socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr() as u64);
    assert_eq!(rc, 0, "socketpair() failed: {rc}");
    let fd0 = fds[0] as u64;
    let fd1 = fds[1] as u64;
    assert_ne!(fd0, fd1, "socketpair() must return two distinct fds");
    serial_println!(
        "socketpair_smoke: socketpair() returned fd0={} fd1={}",
        fd0,
        fd1
    );

    // fd0 -> fd1
    let msg = b"hello-over-socketpair";
    let n = oxidebsd_sys_write(fd0, msg.as_ptr() as u64, msg.len() as u64);
    assert_eq!(n, msg.len() as i64, "write(fd0) failed: {n}");
    let mut buf = [0u8; 64];
    let n = oxidebsd_sys_read(fd1, buf.as_mut_ptr() as u64, buf.len() as u64);
    assert_eq!(n, msg.len() as i64, "read(fd1) failed: {n}");
    assert_eq!(&buf[..n as usize], msg, "fd1 didn't see fd0's bytes");
    serial_println!("socketpair_smoke: fd0 -> fd1 direction verified");

    // fd1 -> fd0, the other direction -- proves this is a genuine full-duplex pair, not a plain
    // one-directional pipe wearing a socketpair-shaped API.
    let reply = b"and-back-again";
    let n = oxidebsd_sys_write(fd1, reply.as_ptr() as u64, reply.len() as u64);
    assert_eq!(n, reply.len() as i64, "write(fd1) failed: {n}");
    let mut buf2 = [0u8; 64];
    let n = oxidebsd_sys_read(fd0, buf2.as_mut_ptr() as u64, buf2.len() as u64);
    assert_eq!(n, reply.len() as i64, "read(fd0) failed: {n}");
    assert_eq!(&buf2[..n as usize], reply, "fd0 didn't see fd1's bytes");
    serial_println!("socketpair_smoke: fd1 -> fd0 direction verified -- full duplex confirmed");

    // Closing one end: the peer's next read sees real EOF, its next write real EPIPE.
    let rc = oxidebsd_close_fd(fd0);
    assert_eq!(rc, 0, "close(fd0) failed: {rc}");
    let n = oxidebsd_sys_read(fd1, buf.as_mut_ptr() as u64, buf.len() as u64);
    assert_eq!(
        n, 0,
        "read(fd1) after peer close should return EOF (0): {n}"
    );
    let n = oxidebsd_sys_write(fd1, reply.as_ptr() as u64, reply.len() as u64);
    assert!(
        n < 0,
        "write(fd1) after peer close should fail with EPIPE: {n}"
    );
    serial_println!(
        "socketpair_smoke: EOF/EPIPE after close verified -- SYS_SOCKETPAIR verified end to end"
    );

    // --- SYS_FCNTL: real O_NONBLOCK, on a fresh pair ---
    let mut fds2: [i32; 2] = [-1, -1];
    let rc = oxidebsd_sys_socketpair(AF_UNIX, SOCK_STREAM, 0, fds2.as_mut_ptr() as u64);
    assert_eq!(rc, 0, "socketpair() (2) failed: {rc}");
    let (fd2_0, fd2_1) = (fds2[0] as u64, fds2[1] as u64);

    let flags = oxidebsd_sys_fcntl(fd2_1, F_GETFL, 0);
    assert_eq!(flags, 0, "F_GETFL before any F_SETFL should be 0: {flags}");
    let rc = oxidebsd_sys_fcntl(fd2_1, F_SETFL, O_NONBLOCK);
    assert_eq!(rc, 0, "F_SETFL(O_NONBLOCK) failed: {rc}");
    let flags = oxidebsd_sys_fcntl(fd2_1, F_GETFL, 0);
    assert_eq!(
        flags, O_NONBLOCK as i64,
        "F_GETFL after F_SETFL(O_NONBLOCK) should report it: {flags}"
    );
    // The buffer is empty and the peer is still open -- without O_NONBLOCK this would block
    // forever (nothing else can run to ever fill it). Must return EAGAIN immediately instead.
    let n = oxidebsd_sys_read(fd2_1, buf.as_mut_ptr() as u64, buf.len() as u64);
    assert!(n < 0, "read() on an empty O_NONBLOCK fd should fail: {n}");
    serial_println!("socketpair_smoke: fcntl(F_SETFL, O_NONBLOCK) -> real EAGAIN verified");

    // --- SYS_SHUTDOWN: a real partial close ---
    let rc = oxidebsd_sys_shutdown(fd2_0, SHUT_WR);
    assert_eq!(rc, 0, "shutdown(fd2_0, SHUT_WR) failed: {rc}");
    // fd2_0's own write side is now closed -- further writes on it must fail.
    let n = oxidebsd_sys_write(fd2_0, msg.as_ptr() as u64, msg.len() as u64);
    assert!(
        n < 0,
        "write() after this end's own SHUT_WR should fail: {n}"
    );
    // fd2_1 (still O_NONBLOCK) reading from that now-shut-down direction sees a real EOF, not
    // EAGAIN -- shutdown must win over "no data yet".
    let n = oxidebsd_sys_read(fd2_1, buf.as_mut_ptr() as u64, buf.len() as u64);
    assert_eq!(
        n, 0,
        "read() on the shut-down direction should be EOF (0), not EAGAIN: {n}"
    );
    // The *other* direction of the same pair is untouched -- fd2_1 can still write, fd2_0 can
    // still read, proving this was a real half-close, not a full close in disguise.
    let n = oxidebsd_sys_write(fd2_1, reply.as_ptr() as u64, reply.len() as u64);
    assert_eq!(
        n,
        reply.len() as i64,
        "write(fd2_1) after peer's SHUT_WR should still work: {n}"
    );
    let n = oxidebsd_sys_read(fd2_0, buf2.as_mut_ptr() as u64, buf2.len() as u64);
    assert_eq!(
        n,
        reply.len() as i64,
        "read(fd2_0) on the still-open direction failed: {n}"
    );
    assert_eq!(&buf2[..n as usize], reply);
    serial_println!(
        "socketpair_smoke: shutdown(SHUT_WR) verified as a real half-close -- SYS_SHUTDOWN verified end to end"
    );
    let _ = oxidebsd_close_fd(fd2_0);
    let _ = oxidebsd_close_fd(fd2_1);

    // --- SYS_SET_TID_ADDRESS: no real threading, so tid == this process's own pid ---
    let tid = oxidebsd_sys_set_tid_address(0);
    assert_eq!(
        tid,
        oxidebsd::process::scheduler::current_pid() as i64,
        "set_tid_address() should report the caller's own pid as tid: {tid}"
    );
    serial_println!(
        "socketpair_smoke: set_tid_address() -> SYS_SET_TID_ADDRESS verified end to end"
    );

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
