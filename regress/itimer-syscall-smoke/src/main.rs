//! Real-`SYSCALL` smoke test for `SYS_SETITIMER`/`SYS_GETITIMER` (`156`/`157`) -- the syscall
//! that backs both real `setitimer(2)` and real `alarm(2)` (musl's own `alarm()` is a thin
//! wrapper around `setitimer(ITIMER_REAL, ...)`, see `external/mit/musl/src/unistd/alarm.c`), and
//! the concrete BusyBox gap this exists to close (`ping`'s own reliance on a real `SIGALRM` to
//! bound its receive loop -- see CLAUDE.md's "BusyBox gap analysis").
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- this exact feature depends on the timer IRQ firing
//! correctly across a syscall boundary (`SFMASK` masks `RFLAGS::INTERRUPT_FLAG` for a syscall's
//! entire duration, not just its entry), which is precisely the class of bug CLAUDE.md's "Real
//! networking" section documents finding *only* once tests were converted to this real-`SYSCALL`
//! style (the `hlt()`-in-syscall freeze, and separately the `ticks()`-frozen-during-syscall
//! deadline bug fixed by `src/tsc.rs`). A plain-Rust-function test would have missed both.
//!
//! Two parts, both through `tests/itimer_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. A `setitimer`/`getitimer` round trip in this process itself -- arm a one-shot timer, read
//!    back the remaining time, disarm it, confirm it reads back as fully disarmed.
//! 2. `fork()`, then in the child: arm a short one-shot timer with **no signal handler
//!    installed** (default `SIGALRM` disposition is `Terminate`), and spin in a tight loop of
//!    individually non-blocking `SYS_GETPID` calls -- exactly `ping`'s own real usage pattern (a
//!    tight loop of individually non-blocking `recvfrom` calls, each its own syscall, see
//!    `process::do_setitimer`'s own doc comment). The parent `wait4()`s for the child and checks
//!    the real BSD/Linux wait-status convention (`status & 0x7f == SIGALRM`, matching
//!    `process::terminate_process`'s own `128 + sig` exit-code convention -- see that call site's
//!    doc comment) to confirm the kernel actually killed it, not that the child gave up on its own
//!    time-bounded fallback (which would report as a plain non-signaled exit instead).
//!
//! The syscall numbers/register convention here must match `sys/syscall.rs` in the kernel
//! exactly -- there's no shared crate between the two, this is the ABI boundary itself, same as
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
const SYS_GETPID: u64 = 20;
const SYS_CLOCK_GETTIME: u64 = 138;
const SYS_SETITIMER: u64 = 156;
const SYS_GETITIMER: u64 = 157;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// itimer_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const ITIMER_REAL: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
/// Real signal number, matches `process::SIGALRM` -- see `sys/process.rs`'s own doc comment on
/// why this ABI didn't invent its own value here (unlike most of this ABI's syscall numbers).
const SIGALRM: i32 = 14;
/// Bound on the child's own time-bounded fallback loop (see this file's module doc comment) --
/// generous relative to the ~50ms timer it arms, but still far under `Cargo.toml`'s own
/// `test-timeout = 300` (seconds) ceiling, so a genuine regression fails fast with a clear,
/// distinguishable status rather than only being caught by the global QEMU timeout.
const FALLBACK_BOUND_MS: i64 = 3000;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawItimerval {
    it_interval_sec: i64,
    it_interval_usec: i64,
    it_value_sec: i64,
    it_value_usec: i64,
}

const ZERO_ITIMERVAL: RawItimerval = RawItimerval {
    it_interval_sec: 0,
    it_interval_usec: 0,
    it_value_sec: 0,
    it_value_usec: 0,
};

#[repr(C)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

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

fn monotonic_ms() -> i64 {
    let mut ts = RawTimespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        let _ = syscall(
            SYS_CLOCK_GETTIME,
            CLOCK_MONOTONIC,
            &mut ts as *mut RawTimespec as u64,
            0,
        );
    }
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Part 1 -- see this file's own module doc comment. Returns `false` (without exiting) on any
/// failed check, so the caller can report a clean `FAIL` through the usual path.
fn setitimer_round_trip() -> bool {
    // Arm a one-shot ~200ms timer (well above TIMER_HZ's own 10ms tick granularity, so rounding
    // never makes this ambiguous), and confirm the "previous state" it hands back is the correct
    // "nothing was armed before" zero value.
    let arm = RawItimerval {
        it_interval_sec: 0,
        it_interval_usec: 0,
        it_value_sec: 0,
        it_value_usec: 200_000,
    };
    let mut old = ZERO_ITIMERVAL;
    if unsafe {
        syscall(
            SYS_SETITIMER,
            ITIMER_REAL,
            &arm as *const RawItimerval as u64,
            &mut old as *mut RawItimerval as u64,
        )
    }
    .is_err()
    {
        write_bytes(b"itimer-syscall-smoke: initial setitimer failed\n");
        return false;
    }
    if old.it_value_sec != 0 || old.it_value_usec != 0 {
        write_bytes(b"itimer-syscall-smoke: fresh process already had a timer armed?\n");
        return false;
    }

    // Read it back immediately -- should still report just under 200ms remaining (a real timer
    // now genuinely armed), one-shot (it_interval all zero).
    let mut readback = ZERO_ITIMERVAL;
    if unsafe {
        syscall(
            SYS_GETITIMER,
            ITIMER_REAL,
            &mut readback as *mut RawItimerval as u64,
            0,
        )
    }
    .is_err()
    {
        write_bytes(b"itimer-syscall-smoke: getitimer failed\n");
        return false;
    }
    let remaining_ok = readback.it_value_sec == 0
        && readback.it_value_usec > 0
        && readback.it_value_usec <= 200_000;
    let interval_ok = readback.it_interval_sec == 0 && readback.it_interval_usec == 0;
    if !remaining_ok || !interval_ok {
        write_bytes(b"itimer-syscall-smoke: getitimer readback out of range\n");
        return false;
    }

    // Disarm (a zero it_value), confirm the "previous state" now correctly reflects the timer
    // that really was still pending, then confirm a follow-up getitimer reports fully disarmed.
    let mut old2 = ZERO_ITIMERVAL;
    if unsafe {
        syscall(
            SYS_SETITIMER,
            ITIMER_REAL,
            &ZERO_ITIMERVAL as *const RawItimerval as u64,
            &mut old2 as *mut RawItimerval as u64,
        )
    }
    .is_err()
    {
        write_bytes(b"itimer-syscall-smoke: disarming setitimer failed\n");
        return false;
    }
    if old2.it_value_sec != 0 || old2.it_value_usec == 0 {
        write_bytes(b"itimer-syscall-smoke: disarm's own previous-state readback looked wrong\n");
        return false;
    }

    let mut readback2 = RawItimerval {
        it_interval_sec: -1,
        it_interval_usec: -1,
        it_value_sec: -1,
        it_value_usec: -1,
    };
    if unsafe {
        syscall(
            SYS_GETITIMER,
            ITIMER_REAL,
            &mut readback2 as *mut RawItimerval as u64,
            0,
        )
    }
    .is_err()
    {
        write_bytes(b"itimer-syscall-smoke: post-disarm getitimer failed\n");
        return false;
    }
    if readback2.it_value_sec != 0
        || readback2.it_value_usec != 0
        || readback2.it_interval_sec != 0
        || readback2.it_interval_usec != 0
    {
        write_bytes(b"itimer-syscall-smoke: timer didn't read back fully disarmed\n");
        return false;
    }

    write_bytes(b"itimer-syscall-smoke: setitimer/getitimer round-trip OK\n");
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"itimer-syscall-smoke: starting\n");

    if !setitimer_round_trip() {
        test_exit(false);
    }

    write_bytes(b"itimer-syscall-smoke: forking for the real SIGALRM-termination check\n");
    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            // Child: arm a short one-shot timer with no handler installed, then spin through a
            // tight loop of individually non-blocking syscalls -- exactly ping's own real usage
            // pattern. If SIGALRM delivery genuinely works, the kernel terminates this process
            // partway through (default disposition), and this code never runs again. The
            // FALLBACK_BOUND_MS exit below only exists so a real regression fails fast and
            // distinctly instead of only ever being caught by the global QEMU test timeout.
            let arm = RawItimerval {
                it_interval_sec: 0,
                it_interval_usec: 0,
                it_value_sec: 0,
                it_value_usec: 50_000,
            };
            unsafe {
                let _ = syscall(
                    SYS_SETITIMER,
                    ITIMER_REAL,
                    &arm as *const RawItimerval as u64,
                    0,
                );
            }
            let start = monotonic_ms();
            loop {
                unsafe {
                    let _ = syscall(SYS_GETPID, 0, 0, 0);
                }
                if monotonic_ms() - start > FALLBACK_BOUND_MS {
                    break;
                }
            }
            write_bytes(
                b"itimer-syscall-smoke: child fallback bound reached -- SIGALRM never fired\n",
            );
            unsafe {
                let _ = syscall(SYS_EXIT, 99, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            write_bytes(b"itimer-syscall-smoke: parent waiting for real SIGALRM termination\n");
            let mut status: i32 = -1;
            let wait_result =
                unsafe { syscall(SYS_WAIT4, child_pid, &mut status as *mut i32 as u64, 0) };
            let ok = wait_result == Ok(child_pid) && (status & 0x7f) == SIGALRM;
            if ok {
                write_bytes(b"itimer-syscall-smoke: PASS\n");
            } else {
                write_bytes(b"itimer-syscall-smoke: FAIL\n");
            }
            test_exit(ok);
        }
        Err(_) => {
            write_bytes(b"itimer-syscall-smoke: fork failed\n");
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
