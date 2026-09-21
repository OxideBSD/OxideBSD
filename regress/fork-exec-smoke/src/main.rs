//! A minimal freestanding fork/wait smoke test, purpose-built for `tests/fork_wait.rs`.
//!
//! Not part of the kernel — this is a standalone ELF binary, built by the kernel's `build.rs` and
//! embedded via `include_bytes!`, that the test spawns as pid 1 in place of `stsh`. Deliberately
//! narrower than driving the real interactive shell (`regress/stsh/`) through a fork+execve+wait
//! round trip: this binary only exercises `fork`/`wait4`/`exit` — no `execve`, no filesystem — so
//! a failure here isolates the process/scheduler/context-switch machinery itself
//! (`sys/process.rs`, `src/scheduler.rs`, `src/context_switch.rs`,
//! `src/address_space.rs`'s `fork`) from FAT32/ELF-loading concerns.
//!
//! Child forks, writes a marker, and exits with a distinctive code (`77`); the parent waits for
//! it and verifies both the reaped pid and the exit code came back correctly, then reports
//! pass/fail through a syscall number no real syscall ABI uses (`9999`) — registered directly by
//! `tests/fork_wait.rs` against a handler that calls `qemu::exit_qemu`, sidestepping the fact that
//! `scheduler::start`/`process::do_exit` never return control to the kernel's own boot code the
//! way a normal test's `main` does.
//!
//! The syscall numbers/register convention here must match `sys/syscall.rs` in the kernel
//! exactly — there's no shared crate between the two, this is the ABI boundary itself, same as
//! every other `regress/*` crate.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
/// Not a real syscall number anything else in this codebase registers -- `tests/fork_wait.rs`
/// registers this one directly against a test-only handler. See this file's module doc comment.
const SYS_TEST_EXIT: u64 = 9999;
const STDOUT: u64 = 1;
const CHILD_EXIT_CODE: u64 = 77;

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
    write_bytes(b"fork-exec-smoke: forking\n");
    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            write_bytes(b"fork-exec-smoke: child alive\n");
            unsafe {
                let _ = syscall(SYS_EXIT, CHILD_EXIT_CODE, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            write_bytes(b"fork-exec-smoke: parent waiting\n");
            let mut status: i32 = -1;
            let wait_result =
                unsafe { syscall(SYS_WAIT4, child_pid, &mut status as *mut i32 as u64, 0) };
            // Real WEXITSTATUS encoding -- see `sys/syscall.rs`'s `oxidebsd_sys_exit` doc comment
            // for why the reported status is the raw exit code shifted into bits 8-15, not the
            // raw code itself.
            let ok = wait_result == Ok(child_pid) && status == (CHILD_EXIT_CODE as i32) << 8;
            if ok {
                write_bytes(b"fork-exec-smoke: PASS\n");
            } else {
                write_bytes(b"fork-exec-smoke: FAIL\n");
            }
            test_exit(ok);
        }
        Err(_) => {
            write_bytes(b"fork-exec-smoke: fork failed\n");
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
