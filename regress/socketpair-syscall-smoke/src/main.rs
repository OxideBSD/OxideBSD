//! Real-`SYSCALL` counterpart to `tests/socketpair_smoke.rs`.
//!
//! That test calls `oxidebsd_sys_socketpair`/`_fcntl`/`_shutdown`/`_read`/`_write` as plain Rust
//! functions from its own `main()`, never through a genuine `SYSCALL` instruction with interrupts
//! actually masked the way a real syscall runs -- see CLAUDE.md's own "Real networking" section
//! for the class of bug (three separate `hlt()`-in-syscall freezes) that blind spot let ship.
//! This binary drives the identical script -- both directions of the pair, EOF/EPIPE after close,
//! `fcntl(F_SETFL, O_NONBLOCK)` -> real `EAGAIN`, `shutdown(SHUT_WR)` as a real half-close,
//! `set_tid_address` -- but every step is a real `SYSCALL`, spawned as pid 1 by
//! `tests/socketpair_syscall_smoke.rs` the same way `regress/fork-exec-smoke` is spawned by
//! `tests/fork_wait.rs`.
//!
//! Both ends of the pair are owned by this single process, so unlike the UDP/TCP/poll
//! conversions, no test-only "advance a synthetic peer" syscall is needed at all -- everything
//! here is a real syscall number from the real ABI.
//!
//! **`SYS_CLOSE = 6`'s real handler is filesystem-owned** (`sys/modules/oxfs`/`modules/fat32` both
//! just delegate to the kernel's own `oxidebsd_close_fd`, no filesystem-specific logic at all --
//! see `src/fd.rs`'s own doc comment). Loading the full `oxfs` module (which embeds every BusyBox
//! applet's ELF bytes via `include_bytes!`) purely to get that one generic delegation registered
//! would bloat this test's build/boot cost for no socketpair-relevant reason, so
//! `tests/socketpair_syscall_smoke.rs` registers `SYS_CLOSE` itself against the exact same
//! delegation target instead -- same underlying fd-close path, none of the unrelated bulk.
//!
//! The syscall numbers/register convention here must match `sys/syscall.rs` in the kernel
//! exactly -- there's no shared crate between the two, this is the ABI boundary itself, same as
//! every other `regress/*` crate.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_CLOSE: u64 = 6;
const SYS_GETPID: u64 = 20;
const SYS_SOCKETPAIR: u64 = 149;
const SYS_SET_TID_ADDRESS: u64 = 150;
const SYS_FCNTL: u64 = 151;
const SYS_SHUTDOWN: u64 = 152;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// socketpair_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention `tests/fork_wait.rs` established.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const O_NONBLOCK: u64 = 0o4000;
const SHUT_WR: u64 = 1;

/// Issues a syscall via `SYSCALL`; see `regress/stsh/src/main.rs`'s identical helper for the full
/// doc comment (carry-flag convention, `rcx`/`r11` clobbered by `SYSCALL` itself). Delegates to
/// `syscall4` with a zeroed 4th argument.
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `socketpair`'s own
/// `sv_ptr` (its 4th real parameter).
#[inline(always)]
unsafe fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Result<u64, u64> {
    let ret: u64;
    let failed: u8;
    unsafe {
        asm!(
            "syscall",
            "setc {failed}",
            inlateout("rax") number => ret,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            failed = out(reg_byte) failed,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    if failed != 0 { Err(ret) } else { Ok(ret) }
}

fn write_bytes(s: &[u8]) {
    unsafe {
        let _ = syscall(SYS_WRITE, STDOUT, s.as_ptr() as u64, s.len() as u64);
    }
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut fds: [i32; 2] = [-1, -1];
    let rc = unsafe {
        syscall4(
            SYS_SOCKETPAIR,
            AF_UNIX,
            SOCK_STREAM,
            0,
            fds.as_mut_ptr() as u64,
        )
    };
    if rc.is_err() {
        write_bytes(b"socketpair-syscall-smoke: socketpair() failed\n");
        test_exit(false);
    }
    let (fd0, fd1) = (fds[0] as u64, fds[1] as u64);
    if fd0 == fd1 {
        write_bytes(b"socketpair-syscall-smoke: socketpair() returned two identical fds\n");
        test_exit(false);
    }
    write_bytes(b"socketpair-syscall-smoke: socketpair() ok\n");

    // fd0 -> fd1
    let msg = b"hello-over-socketpair";
    let n = unsafe { syscall(SYS_WRITE, fd0, msg.as_ptr() as u64, msg.len() as u64) };
    let mut buf = [0u8; 64];
    let read_ok = matches!(n, Ok(n) if n as usize == msg.len())
        && matches!(
            unsafe { syscall(SYS_READ, fd1, buf.as_mut_ptr() as u64, buf.len() as u64) },
            Ok(n) if n as usize == msg.len() && &buf[..n as usize] == msg
        );
    if !read_ok {
        write_bytes(b"socketpair-syscall-smoke: fd0 -> fd1 direction failed\n");
        test_exit(false);
    }
    write_bytes(b"socketpair-syscall-smoke: fd0 -> fd1 direction verified\n");

    // fd1 -> fd0, the other direction -- proves this is a genuine full-duplex pair.
    let reply = b"and-back-again";
    let n = unsafe { syscall(SYS_WRITE, fd1, reply.as_ptr() as u64, reply.len() as u64) };
    let mut buf2 = [0u8; 64];
    let read_ok = matches!(n, Ok(n) if n as usize == reply.len())
        && matches!(
            unsafe { syscall(SYS_READ, fd0, buf2.as_mut_ptr() as u64, buf2.len() as u64) },
            Ok(n) if n as usize == reply.len() && &buf2[..n as usize] == reply
        );
    if !read_ok {
        write_bytes(b"socketpair-syscall-smoke: fd1 -> fd0 direction failed\n");
        test_exit(false);
    }
    write_bytes(b"socketpair-syscall-smoke: fd1 -> fd0 direction verified -- full duplex\n");

    // Closing one end: the peer's next read sees real EOF, its next write real EPIPE.
    if unsafe { syscall(SYS_CLOSE, fd0, 0, 0) }.is_err() {
        write_bytes(b"socketpair-syscall-smoke: close(fd0) failed\n");
        test_exit(false);
    }
    let eof_ok = matches!(
        unsafe { syscall(SYS_READ, fd1, buf.as_mut_ptr() as u64, buf.len() as u64) },
        Ok(0)
    );
    let epipe_ok =
        unsafe { syscall(SYS_WRITE, fd1, reply.as_ptr() as u64, reply.len() as u64) }.is_err();
    if !eof_ok || !epipe_ok {
        write_bytes(b"socketpair-syscall-smoke: EOF/EPIPE after close not observed\n");
        test_exit(false);
    }
    write_bytes(b"socketpair-syscall-smoke: EOF/EPIPE after close verified\n");

    // --- SYS_FCNTL: real O_NONBLOCK, on a fresh pair ---
    let mut fds2: [i32; 2] = [-1, -1];
    let rc = unsafe {
        syscall4(
            SYS_SOCKETPAIR,
            AF_UNIX,
            SOCK_STREAM,
            0,
            fds2.as_mut_ptr() as u64,
        )
    };
    if rc.is_err() {
        write_bytes(b"socketpair-syscall-smoke: socketpair() (2) failed\n");
        test_exit(false);
    }
    let (fd2_0, fd2_1) = (fds2[0] as u64, fds2[1] as u64);

    let flags = unsafe { syscall(SYS_FCNTL, fd2_1, F_GETFL, 0) };
    if flags != Ok(0) {
        write_bytes(b"socketpair-syscall-smoke: F_GETFL before F_SETFL should be 0\n");
        test_exit(false);
    }
    if unsafe { syscall(SYS_FCNTL, fd2_1, F_SETFL, O_NONBLOCK) }.is_err() {
        write_bytes(b"socketpair-syscall-smoke: F_SETFL(O_NONBLOCK) failed\n");
        test_exit(false);
    }
    let flags = unsafe { syscall(SYS_FCNTL, fd2_1, F_GETFL, 0) };
    if flags != Ok(O_NONBLOCK) {
        write_bytes(b"socketpair-syscall-smoke: F_GETFL after F_SETFL didn't report O_NONBLOCK\n");
        test_exit(false);
    }
    // The buffer is empty and the peer is still open -- must return EAGAIN immediately, not
    // block forever (nothing else can run to ever fill it in a single-process test).
    let eagain_ok =
        unsafe { syscall(SYS_READ, fd2_1, buf.as_mut_ptr() as u64, buf.len() as u64) }.is_err();
    if !eagain_ok {
        write_bytes(b"socketpair-syscall-smoke: O_NONBLOCK read() on empty fd should fail\n");
        test_exit(false);
    }
    write_bytes(b"socketpair-syscall-smoke: fcntl(F_SETFL, O_NONBLOCK) -> real EAGAIN verified\n");

    // --- SYS_SHUTDOWN: a real partial close ---
    if unsafe { syscall(SYS_SHUTDOWN, fd2_0, SHUT_WR, 0) }.is_err() {
        write_bytes(b"socketpair-syscall-smoke: shutdown(fd2_0, SHUT_WR) failed\n");
        test_exit(false);
    }
    let write_after_shutdown_fails =
        unsafe { syscall(SYS_WRITE, fd2_0, msg.as_ptr() as u64, msg.len() as u64) }.is_err();
    let eof_after_shutdown = matches!(
        unsafe { syscall(SYS_READ, fd2_1, buf.as_mut_ptr() as u64, buf.len() as u64) },
        Ok(0)
    );
    if !write_after_shutdown_fails || !eof_after_shutdown {
        write_bytes(b"socketpair-syscall-smoke: SHUT_WR didn't behave as a real half-close\n");
        test_exit(false);
    }
    // The *other* direction of the same pair is untouched.
    let n = unsafe { syscall(SYS_WRITE, fd2_1, reply.as_ptr() as u64, reply.len() as u64) };
    let other_direction_ok = matches!(n, Ok(n) if n as usize == reply.len())
        && matches!(
            unsafe { syscall(SYS_READ, fd2_0, buf2.as_mut_ptr() as u64, buf2.len() as u64) },
            Ok(n) if n as usize == reply.len() && &buf2[..n as usize] == reply
        );
    if !other_direction_ok {
        write_bytes(b"socketpair-syscall-smoke: the still-open direction stopped working\n");
        test_exit(false);
    }
    write_bytes(b"socketpair-syscall-smoke: shutdown(SHUT_WR) verified as a real half-close\n");
    let _ = unsafe { syscall(SYS_CLOSE, fd2_0, 0, 0) };
    let _ = unsafe { syscall(SYS_CLOSE, fd2_1, 0, 0) };

    // --- SYS_SET_TID_ADDRESS: no real threading, so tid == this process's own real pid ---
    let pid = unsafe { syscall(SYS_GETPID, 0, 0, 0) };
    let tid = unsafe { syscall(SYS_SET_TID_ADDRESS, 0, 0, 0) };
    if pid.is_err() || tid != pid {
        write_bytes(b"socketpair-syscall-smoke: set_tid_address() should echo our own pid\n");
        test_exit(false);
    }
    write_bytes(b"socketpair-syscall-smoke: set_tid_address() verified -- PASS\n");

    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
