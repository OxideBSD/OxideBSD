//! Orchestrates `regress/pie-aslr-smoke/`'s own real per-`execve()` PIE/ASLR self-checks (see that
//! crate's own module doc comment for the full scenario) -- spawned as pid 1 by
//! `tests/pie_aslr_smoke.rs`. A plain, fixed-`ET_EXEC` binary: this process itself never needs a
//! kernel-assigned bias (`process::spawn`, which loads pid 1, always uses bias `0` -- only
//! `do_execve` ever calls `process::aslr::pick_bias()`), it only issues real `fork`/`execve`/
//! `wait4` syscalls to run the actual PIE binary twice.
#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_EXECVE: u64 = 59;
const STDOUT: u64 = 1;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// pie_aslr_smoke.rs` registers this one directly against a test-only handler, same convention
/// every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const PROBE_PATH: &[u8] = b"/pie-aslr-probe.elf";

#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
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

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

fn fork() -> Result<u64, u64> {
    unsafe { syscall(SYS_FORK, 0, 0, 0) }
}

fn wait4(pid: u64, status: &mut i32) -> Result<u64, u64> {
    unsafe { syscall(SYS_WAIT4, pid, status as *mut i32 as u64, 0) }
}

fn execve_probe() -> ! {
    let argv_entries = [
        RawArgvEntry {
            ptr: PROBE_PATH.as_ptr() as u64,
            len: PROBE_PATH.len() as u64,
        },
        RawArgvEntry { ptr: 0, len: 0 },
    ];
    const ENVP: &[u8] = b"PATH=";
    let envp_entries = [
        RawArgvEntry {
            ptr: ENVP.as_ptr() as u64,
            len: ENVP.len() as u64,
        },
        RawArgvEntry { ptr: 0, len: 0 },
    ];
    unsafe {
        let result = syscall4(
            SYS_EXECVE,
            PROBE_PATH.as_ptr() as u64,
            PROBE_PATH.len() as u64,
            argv_entries.as_ptr() as u64,
            envp_entries.as_ptr() as u64,
        );
        // Only reached if execve itself failed.
        let msg = b"pie-aslr-driver: execve failed, errno=";
        let _ = syscall(SYS_WRITE, STDOUT, msg.as_ptr() as u64, msg.len() as u64);
        if let Err(errno) = result {
            let mut buf = [0u8; 20];
            let mut n = errno;
            let mut i = buf.len();
            loop {
                i -= 1;
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
                if n == 0 {
                    break;
                }
            }
            let _ = syscall(
                SYS_WRITE,
                STDOUT,
                buf.as_ptr().add(i) as u64,
                (buf.len() - i) as u64,
            );
        }
        let nl = b"\n";
        let _ = syscall(SYS_WRITE, STDOUT, nl.as_ptr() as u64, nl.len() as u64);
        let _ = syscall(SYS_EXIT, 127, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Forks, `execve`s the probe binary in the child, `wait4`s in the parent. Returns whether the
/// child exited cleanly with status `0`.
fn run_probe_once() -> bool {
    match fork() {
        Ok(0) => execve_probe(),
        Ok(child_pid) => {
            let mut status: i32 = -1;
            wait4(child_pid, &mut status) == Ok(child_pid) && status == 0
        }
        Err(_) => false,
    }
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let first_ok = run_probe_once();
    let second_ok = run_probe_once();
    test_exit(first_ok && second_ok);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
