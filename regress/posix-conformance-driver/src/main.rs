//! Real-`SYSCALL` driver for the POSIX conformance pilot (see
//! `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`'s own "Verification" section and
//! `sys/modules/oxfs/src/posix_conformance.sh`'s own doc comment for the full design).
//!
//! `sh` (BusyBox hush) is normally pid 1 and interactive -- fine for a human at a real keyboard,
//! but this project's own established rule (see CLAUDE.md's Test architecture section) is that
//! anything needing live interactive keyboard input can't be scripted. Running the conformance
//! script non-interactively needs a real driver in front of it instead: this crate `fork`s,
//! `execve`s `/bin/sh /posix_conformance.sh` in the child (a real non-interactive script
//! invocation -- BusyBox hush skips its own interactive job-control startup whenever it's given a
//! script argument, so this needs no controlling-tty setup this test's module list doesn't already
//! provide), and `wait4`s in the parent.
//!
//! Deliberately does **not** fail the harness over the script's own aggregate PASS/FAIL/UNSUPPORTED
//! tally -- that tally *is* the actual, expected output of this pilot (real, documented POSIX gaps
//! showing up as real failures, not a bug in this test). Only a genuine infrastructure failure
//! (the shell itself couldn't be spawned/exec'd, or exited some way `wait4` can't even observe)
//! fails this test -- the tally itself is read from this test's own serial output by whoever ran
//! it, same as `test_busybox.sh`'s established "hand-read the PASS/FAIL summary" pattern.
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
/// posix_conformance_smoke.rs` registers this one directly against a test-only handler, same
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

/// Hand-rolled decimal formatting, no `core::fmt` -- this crate is `#![no_std]` with no `alloc`,
/// same discipline every other minimal userland smoke crate in this codebase already follows.
fn write_i32(n: i32) {
    let mut buf = [0u8; 11]; // "-2147483648" worst case
    let mut i = buf.len();
    let neg = n < 0;
    // i32::MIN can't be negated directly (would overflow) -- work in i64 for the magnitude.
    let mut mag = if neg { -(n as i64) } else { n as i64 };
    if mag == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while mag > 0 {
        i -= 1;
        buf[i] = b'0' + (mag % 10) as u8;
        mag /= 10;
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    write_bytes(&buf[i..]);
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

const MAX_ARGV: usize = 8;

fn execve(path: &[u8], argv: &[&[u8]]) -> Result<u64, u64> {
    let mut entries = [RawArgvEntry { ptr: 0, len: 0 }; MAX_ARGV + 1];
    for (i, arg) in argv.iter().enumerate() {
        entries[i] = RawArgvEntry {
            ptr: arg.as_ptr() as u64,
            len: arg.len() as u64,
        };
    }
    let argv_ptr = entries.as_ptr() as u64;
    const ENVP: &[u8] = b"PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";
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
    write_bytes(b"posix-conformance-driver: spawning sh /posix_conformance.sh\n");

    match fork() {
        Ok(0) => {
            let _ = execve(b"/bin/sh", &[b"sh", b"/posix_conformance.sh"]);
            write_bytes(b"posix-conformance-driver: execve(/bin/sh) failed\n");
            unsafe {
                let _ = syscall(SYS_EXIT, 127, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            let mut status: i32 = -1;
            match wait4(child_pid, &mut status) {
                // Real wait(2) encoding: `status == 0` is the only shape meaning "exited
                // normally, via exit(0)". Anything else -- a nonzero exit code, or the
                // low-7-bits-nonzero signal-terminated shape (`terminate_process`'s own
                // `128 + sig`/pre-shifted encoding, see CLAUDE.md's process/scheduler section) --
                // means `sh` didn't run its own `posix_conformance.sh` loop to completion,
                // whatever the reason. Found live: this check didn't exist before, so a shell
                // that silently died partway through the corpus (not a hang -- `wait4` still
                // returned promptly -- and not a kernel panic either) was reported as a clean
                // "PASS" regardless, hiding a real, separate infrastructure failure from every
                // caller that (reasonably) trusted this line to mean "the whole corpus ran."
                // Still deliberately doesn't touch the *tally* itself (see this module's own doc
                // comment) -- only whether `sh` actually finished its own loop and reached
                // `echo === summary ===`, a strictly narrower, purely infrastructural check.
                Ok(reaped) if reaped == child_pid && status == 0 => {
                    write_bytes(b"posix-conformance-driver: sh finished, harness done\n");
                    test_exit(true);
                }
                Ok(reaped) if reaped == child_pid => {
                    write_bytes(b"posix-conformance-driver: sh exited abnormally, status=");
                    write_i32(status);
                    write_bytes(b"\n");
                    test_exit(false);
                }
                _ => {
                    write_bytes(b"posix-conformance-driver: wait4 for sh failed\n");
                    test_exit(false);
                }
            }
        }
        Err(_) => {
            write_bytes(b"posix-conformance-driver: fork failed\n");
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
