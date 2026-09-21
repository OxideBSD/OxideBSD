//! Real-`SYSCALL` smoke test for the session/controlling-tty additions (`SYS_SETSID = 112`,
//! `SYS_GETSID = 177`, and `SYS_IOCTL`'s new `TIOCSCTTY`/`TIOCNOTTY`/`TIOCGPGRP`/`TIOCSPGRP`
//! requests) -- added specifically to get `sulogin`/`getty` past their own `setsid()`/
//! `ioctl(TIOCSCTTY)` startup calls, which this kernel had no session/foreground-process-group
//! concept to answer at all before. See CLAUDE.md's session/controlling-tty notes.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning every other `*-syscall-smoke` crate
//! in this codebase already documents (this exercises `scheduler::current_pid()`-keyed per-process
//! state, exactly the class of thing a plain-Rust-function test can't exercise the same way).
//!
//! Runs as a forked child of pid 1, not pid 1 itself -- `process::spawn` already makes pid 1 its
//! own process-group leader (`pgid == pid`), so `setsid()` on pid 1 directly would always fail
//! `EPERM` (real POSIX rule) before ever reaching the interesting cases. A forked child inherits
//! its parent's `pgid` unchanged (real `fork()` semantics), so it starts out *not* its own group
//! leader -- exactly the shape `setsid()` requires to succeed, and the same shape a real shell's
//! job-control-spawned child (like a real `getty`) is in.
//!
//! Real Ctrl+C -> `SIGINT` delivery (`interrupts::keyboard_interrupt_handler`'s own new
//! interception, `process::signal_foreground_group`) is **not** covered here: it's driven by a
//! real PS/2 keyboard IRQ, not a syscall, and this kernel has no way to script keystrokes into a
//! test the way `tests/fork_wait.rs` scripts syscalls -- same "hand off anything needing a live
//! interactive QEMU session" precedent CLAUDE.md's own disk-persistence section already
//! documents. Only the syscall-reachable surface (session/pgid/controlling-tty state itself) is
//! covered by this test.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_GETPID: u64 = 20;
const SYS_IOCTL: u64 = 124;
/// Real x86_64 Linux's own `__NR_setsid` -- see `sys/syscall.rs`'s `sys_setsid` doc comment.
const SYS_SETSID: u64 = 112;
/// Invented -- real `__NR_getsid` (`124`) collides with `SYS_IOCTL` in this ABI. See
/// `sys/syscall.rs`'s `sys_getsid` doc comment.
const SYS_GETSID: u64 = 177;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// session_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const STDIN: u64 = 0;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCNOTTY: u64 = 0x5422;

/// The distinguishing exit code the child reports on full success -- checked by the parent via
/// `wait4`'s real `WEXITSTATUS`-shaped status (`oxidebsd_sys_exit` shifts a normal exit code into
/// bits 8-15, see `process::terminate_process`'s own doc comment).
const CHILD_PASS_CODE: i64 = 42;

/// Issues a syscall via `SYSCALL`; see `regress/ring3-smoke/src/main.rs`'s identical helper for
/// the full doc comment (carry-flag convention, `rcx`/`r11` clobbered by `SYSCALL` itself).
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
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
            // Explicitly zeroed, not left as whatever garbage the compiler happened to leave in
            // r10 -- SYSCALL doesn't clear it, and SYS_WAIT4's own optional rusage_ptr 4th
            // argument now reads it for real. Every 3-argument syscall's own handler still just
            // ignores this (an unused `_arg3` parameter), so zeroing it here is safe for all of
            // them, not just wait4.
            in("r10") 0u64,
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

fn getpid() -> u64 {
    unsafe { syscall(SYS_GETPID, 0, 0, 0).unwrap_or(0) }
}

fn getsid(pid: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_GETSID, pid, 0, 0) }
}

fn setsid() -> Result<u64, u64> {
    unsafe { syscall(SYS_SETSID, 0, 0, 0) }
}

fn ioctl(fd: u64, request: u64, argp: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_IOCTL, fd, request, argp) }
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

fn child_main(parent_sid: u64) -> ! {
    let own_pid = getpid();

    // Freshly forked -- sid is still inherited from the parent (pid 1's own sid), not this
    // child's own pid.
    match getsid(0) {
        Ok(sid) if sid == parent_sid => {}
        other => {
            write_bytes(b"session-syscall-smoke: child's initial getsid(0) unexpected\n");
            let _ = other;
            unsafe {
                let _ = syscall(SYS_EXIT, 1, 0, 0);
            };
            loop {
                spin_loop()
            }
        }
    }

    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if !$cond {
                write_bytes($msg);
                unsafe {
                    let _ = syscall(SYS_EXIT, 1, 0, 0);
                };
                loop {
                    spin_loop()
                }
            }
        };
    }

    // Not yet a session leader (sid == parent's sid, != own pid) -- TIOCSCTTY without force must
    // fail EPERM, the same real POSIX check `setsid()` itself enforces.
    check!(
        ioctl(STDIN, TIOCSCTTY, 0) == Err(1),
        b"session-syscall-smoke: TIOCSCTTY before setsid() should EPERM\n"
    );

    // setsid() itself: succeeds (fork gave this child a pgid it doesn't lead), returns own pid,
    // and a second call now fails EPERM (already its own group/session leader).
    check!(
        setsid() == Ok(own_pid),
        b"session-syscall-smoke: setsid() didn't return own pid\n"
    );
    check!(
        setsid() == Err(1),
        b"session-syscall-smoke: second setsid() should EPERM\n"
    );
    check!(
        getsid(0) == Ok(own_pid),
        b"session-syscall-smoke: getsid(0) after setsid() should be own pid\n"
    );

    // No controlling tty claimed yet.
    let mut pgrp: i32 = -1;
    check!(
        ioctl(STDIN, TIOCGPGRP, &mut pgrp as *mut i32 as u64) == Err(25), // ENOTTY
        b"session-syscall-smoke: TIOCGPGRP before TIOCSCTTY should ENOTTY\n"
    );

    // Now a session leader -- TIOCSCTTY (no force needed) succeeds.
    check!(
        ioctl(STDIN, TIOCSCTTY, 0) == Ok(0),
        b"session-syscall-smoke: TIOCSCTTY as session leader should succeed\n"
    );

    // TIOCGPGRP now reports the session's own default foreground group (falls back to the sid
    // itself until something explicitly calls TIOCSPGRP).
    check!(
        ioctl(STDIN, TIOCGPGRP, &mut pgrp as *mut i32 as u64) == Ok(0) && pgrp as u64 == own_pid,
        b"session-syscall-smoke: TIOCGPGRP after TIOCSCTTY didn't report own pid\n"
    );

    // Explicit TIOCSPGRP round-trip.
    let new_pgrp: i32 = own_pid as i32;
    check!(
        ioctl(STDIN, TIOCSPGRP, &new_pgrp as *const i32 as u64) == Ok(0),
        b"session-syscall-smoke: TIOCSPGRP should succeed\n"
    );
    pgrp = -1;
    check!(
        ioctl(STDIN, TIOCGPGRP, &mut pgrp as *mut i32 as u64) == Ok(0) && pgrp as u64 == own_pid,
        b"session-syscall-smoke: TIOCGPGRP after TIOCSPGRP round-trip mismatch\n"
    );

    // TIOCNOTTY releases the claim -- TIOCGPGRP goes back to ENOTTY.
    check!(
        ioctl(STDIN, TIOCNOTTY, 0) == Ok(0),
        b"session-syscall-smoke: TIOCNOTTY should succeed\n"
    );
    check!(
        ioctl(STDIN, TIOCGPGRP, &mut pgrp as *mut i32 as u64) == Err(25),
        b"session-syscall-smoke: TIOCGPGRP after TIOCNOTTY should ENOTTY again\n"
    );

    write_bytes(b"session-syscall-smoke: child checks all passed\n");
    unsafe {
        let _ = syscall(SYS_EXIT, CHILD_PASS_CODE as u64, 0, 0);
    };
    loop {
        spin_loop()
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"session-syscall-smoke: starting\n");

    let parent_sid = match getsid(0) {
        Ok(sid) => sid,
        Err(_) => {
            write_bytes(b"session-syscall-smoke: parent's own getsid(0) failed\n");
            test_exit(false);
        }
    };

    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => child_main(parent_sid),
        Ok(child_pid) => {
            let mut status: i32 = -1;
            let wait_result =
                unsafe { syscall(SYS_WAIT4, child_pid, &mut status as *mut i32 as u64, 0) };
            let ok = wait_result == Ok(child_pid) && (status >> 8) & 0xff == CHILD_PASS_CODE as i32;
            if ok {
                write_bytes(b"session-syscall-smoke: PASS\n");
            } else {
                write_bytes(b"session-syscall-smoke: FAIL\n");
            }
            test_exit(ok);
        }
        Err(_) => {
            write_bytes(b"session-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
