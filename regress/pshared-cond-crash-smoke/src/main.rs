//! Real-`SYSCALL` driver isolating the Open POSIX Test Suite's own `pthread_cond_broadcast/1-2.c`
//! real-cross-process-stall investigation (see `regress/pshared-cond-crash/main.c`'s own doc
//! comment for the exact narrower scenario this reproduces: one forked child using a real
//! `PTHREAD_PROCESS_SHARED` mutex/cond in a real file-backed `MAP_SHARED` region, not up to
//! `MAX_PROCESS_CHILDREN = 200`).
//!
//! `fork`+`execve`s `/pshared-cond-crash.elf` and `wait4`s for it. If the real bug reproduces at
//! this narrower scale, that `wait4` call itself never returns -- this test's own real `cargo
//! test` timeout is what would actually surface that, not a clean FAIL report.
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
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// pshared_cond_crash_smoke.rs` registers this one directly against a test-only handler, same
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
            write_bytes(b"pshared-cond-crash-smoke: FAIL: ");
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"pshared-cond-crash-smoke: starting\n");

    let child = match fork() {
        Ok(0) => {
            let _ = execve(b"/pshared-cond-crash.elf", &[b"pshared-cond-crash.elf"]);
            unsafe {
                let _ = syscall(SYS_EXIT, 127, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"pshared-cond-crash-smoke: fork failed\n");
            test_exit(false);
        }
    };
    write_bytes(b"pshared-cond-crash-smoke: waiting for /pshared-cond-crash.elf\n");
    let mut status: i32 = -1;
    let waited = wait4(child, &mut status);
    check!(
        waited == Ok(child),
        b"wait4 for pshared-cond-crash.elf didn't return the right pid"
    );
    check!(
        status == 0,
        b"pshared-cond-crash.elf didn't exit cleanly"
    );

    write_bytes(b"pshared-cond-crash-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
