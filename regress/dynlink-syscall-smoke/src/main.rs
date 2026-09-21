//! Real-`SYSCALL` smoke test for PT_INTERP / dynamic-linking milestone 1 (see the plan this was
//! built from, and once it exists, CLAUDE.md's own "Dynamic linking" section): confirms
//! `/dynlink-smoke.elf`, a real dynamically-linked musl binary seeded by `sys/modules/oxfs`'s
//! `format_fresh_filesystem` (see `build.rs`'s `build_musl_sysroot_shared`/`build_dynlink_smoke`),
//! actually runs to completion through a real `PT_INTERP` load -- not just that the kernel accepts
//! the file.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning every other real-`SYSCALL` smoke
//! test in this codebase documents (see `tests/fork_wait.rs`'s own module doc comment):
//! this is the first time this kernel has ever loaded two ELF images (the main binary and its
//! interpreter) into one address space and jumped into the interpreter's own entry instead of the
//! main binary's, exactly the class of thing worth exercising through the genuine ring-3 path.
//!
//! One part, via `tests/dynlink_syscall_smoke.rs` spawning this binary as pid 1: `fork` + `execve`
//! `/dynlink-smoke.elf` (no argv/envp needed -- it just calls `write()` once and returns), `wait4`
//! for a clean exit.
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
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// dynlink_syscall_smoke.rs` registers this one directly against a test-only handler, same
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
            write_bytes(b"dynlink-syscall-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
}

/// Wire format for `SYS_EXECVE`'s optional third argument -- see `sys/process.rs`'s
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

/// Forks, `execve`s `path`/`argv` in the child (exiting `127` on failure, matching the real shell
/// convention -- `stsh`/`hush` both use it too), `wait4`s in the parent. Returns whether the child
/// exited cleanly with status `0`.
fn run_and_wait(path: &[u8], argv: &[&[u8]]) -> bool {
    match fork() {
        Ok(0) => {
            let _ = execve(path, argv);
            unsafe {
                let _ = syscall(SYS_EXIT, 127, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            let mut status: i32 = -1;
            wait4(child_pid, &mut status) == Ok(child_pid) && status == 0
        }
        Err(_) => {
            write_bytes(b"dynlink-syscall-smoke: fork failed\n");
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"dynlink-syscall-smoke: starting\n");

    let ok = run_and_wait(b"/dynlink-smoke.elf", &[b"dynlink-smoke.elf"]);
    check!(ok, b"running /dynlink-smoke.elf via a real PT_INTERP exec failed");

    write_bytes(b"dynlink-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
