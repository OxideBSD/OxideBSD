//! Real-`SYSCALL` driver isolating the Open POSIX Test Suite's own `pthread_cancel/5-1.c`
//! crash-then-wedge investigation (see `regress/pthread-cancel-crash/main.c`'s own doc comment
//! for the exact scenario that file reproduces). A full ~1700-file pilot run found that this one
//! file's own real, expected `SIGSEGV` (a write through memory `pthread_join`'s own real `munmap`
//! already freed) seemed to leave the whole kernel unable to run any further pilot file for the
//! rest of that boot -- see CLAUDE.md's own write-up.
//!
//! This driver isolates exactly that shape in a controlled, two-part scenario:
//!  1. `fork`+`execve` `/pthread-cancel-crash.elf`, `wait4` for it, and confirm it was genuinely
//!     killed by `SIGSEGV` (the *expected* part -- not itself the bug under investigation).
//!  2. Immediately afterward, `fork`+`execve` `/bin/musl` (a real, already-proven-working musl
//!     binary, `regress/musl-smoke/main.c`) and `wait4` for *that* to confirm the system is still
//!     genuinely healthy. If the real bug reproduces here, this second `wait4` call itself hangs
//!     forever -- this test's own real `cargo test` timeout is what would actually surface that,
//!     not a clean FAIL report.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning every other real-`SYSCALL` smoke
//! test in this codebase documents.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_EXECVE: u64 = 59;
const SIGSEGV: i32 = 11;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// pthread_cancel_crash_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

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

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            write_bytes(b"pthread-cancel-crash-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
}

/// Wire format for `SYS_EXECVE`'s optional third argument -- matches `sys/process/mod.rs`'s
/// `RawArgvEntry` (the kernel-side counterpart this must match exactly: two `u64`s, `ptr` then
/// `len`). A sequence of these describes the *complete* argv[] array, starting at argv[0],
/// terminated by a `ptr == 0` entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

const MAX_ARGV: usize = 4;

fn execve(path: &[u8], argv: &[&[u8]]) -> Result<u64, u64> {
    let mut entries = [RawArgvEntry { ptr: 0, len: 0 }; MAX_ARGV + 1];
    for (i, arg) in argv.iter().enumerate() {
        entries[i] = RawArgvEntry {
            ptr: arg.as_ptr() as u64,
            len: arg.len() as u64,
        };
    }
    let argv_ptr = entries.as_ptr() as u64;
    const ENVP: &[u8] = b"PATH=";
    let envp_entries = [
        RawArgvEntry {
            ptr: ENVP.as_ptr() as u64,
            len: ENVP.len() as u64,
        },
        RawArgvEntry { ptr: 0, len: 0 },
    ];
    unsafe {
        syscall4(
            SYS_EXECVE,
            path.as_ptr() as u64,
            path.len() as u64,
            argv_ptr,
            envp_entries.as_ptr() as u64,
        )
    }
}

fn fork() -> Result<u64, u64> {
    unsafe { syscall(SYS_FORK, 0, 0, 0) }
}

fn wait4(pid: u64, status: &mut i32) -> Result<u64, u64> {
    unsafe { syscall(SYS_WAIT4, pid, status as *mut i32 as u64, 0) }
}

/// Real, unshifted `128 + signum` wire encoding for a signal-terminated child -- see
/// `do_wait4`'s own doc comment in `sys/process/lifecycle.rs`. Same helper
/// `regress/mmap-syscall-smoke/src/main.rs` already establishes.
fn wtermsig(status: i32) -> Option<i32> {
    if status & 0x7f != 0 {
        Some(status - 128)
    } else {
        None
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"pthread-cancel-crash-smoke: starting\n");

    // Part 1: run the real crash scenario, expect a genuine SIGSEGV.
    let child = match fork() {
        Ok(0) => {
            let _ = execve(
                b"/pthread-cancel-crash.elf",
                &[b"pthread-cancel-crash.elf"],
            );
            unsafe {
                let _ = syscall(SYS_EXIT, 127, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"pthread-cancel-crash-smoke: fork (part 1) failed\n");
            test_exit(false);
        }
    };
    let mut status: i32 = -1;
    let waited = wait4(child, &mut status);
    check!(
        waited == Ok(child),
        b"wait4 for pthread-cancel-crash.elf didn't return the right pid"
    );
    check!(
        wtermsig(status) == Some(SIGSEGV),
        b"pthread-cancel-crash.elf wasn't killed by a real SIGSEGV as expected"
    );
    write_bytes(b"pthread-cancel-crash-smoke: part 1 (real SIGSEGV as expected) OK\n");

    // Part 2: the real question -- is the system still healthy right after that crash? If the
    // real bug under investigation reproduces, this wait4 call itself never returns.
    let child2 = match fork() {
        Ok(0) => {
            let _ = execve(b"/usr/tests/musl", &[b"musl"]);
            unsafe {
                let _ = syscall(SYS_EXIT, 127, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"pthread-cancel-crash-smoke: fork (part 2) failed\n");
            test_exit(false);
        }
    };
    write_bytes(b"pthread-cancel-crash-smoke: part 2: waiting for /bin/musl after the crash\n");
    let mut status2: i32 = -1;
    let waited2 = wait4(child2, &mut status2);
    check!(
        waited2 == Ok(child2),
        b"wait4 for /bin/musl (after the crash) didn't return the right pid"
    );
    check!(
        status2 == 0,
        b"/usr/tests/musl didn't exit cleanly after the crash -- system health regression"
    );
    write_bytes(b"pthread-cancel-crash-smoke: part 2 (system still healthy after the crash) OK\n");

    write_bytes(b"pthread-cancel-crash-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
