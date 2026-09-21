//! Real-`SYSCALL` smoke test for `SYS_SCHED_SETSCHEDULER = 481`/`SYS_SCHED_GETSCHEDULER = 482`/
//! `SYS_SCHED_GETPARAM = 483`/`SYS_SCHED_GET_PRIORITY_MAX = 484`/`SYS_SCHED_GET_PRIORITY_MIN =
//! 485`/`SYS_SCHED_RR_GET_INTERVAL = 508`/`SYS_SCHED_YIELD = 24` (`sys/modules/posix_compat`'s
//! `handle_sched_*` -> `sys/syscall/ffi.rs`'s `oxidebsd_sys_sched_*` ->
//! `sys/process/limits.rs`'s `do_sched_*`).
//!
//! Closes a real gap the Open POSIX Test Suite pilot found: musl's own `sched_getparam()`/
//! `sched_setscheduler()`/`sched_getscheduler()` library wrappers are permanently stubbed to
//! `ENOSYS` client-side (`external/mit/musl/src/sched/sched_{getparam,getscheduler,
//! setscheduler}.c`, patched on the `oxidebsd` branch to actually issue the real syscall) --
//! every pilot file calling the real libc function, not a raw `syscall()`, never reached the
//! kernel at all before that patch. Plus real permission checking
//! (`process::limits::has_sched_permission`) and real priority-range validation
//! (`sched_priority_range`), neither of which existed before.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- same reasoning every other real-`SYSCALL` smoke test in this codebase gives.
//! **No musl involved** -- a bare `#![no_std]` binary with its own hand-rolled `syscall()` helper.
//!
//! Nine parts:
//! 1. `sched_getparam(getpid(), ...)` succeeds with a real, non-`-1` `sched_priority`;
//!    `sched_getparam(0, ...)` reports the identical value (`pid == 0` means self).
//! 2. `sched_getparam` on an already-reaped pid is `ESRCH`.
//! 3. `sched_getscheduler(0)` and `sched_getscheduler(getpid())` report the identical policy.
//! 4. `sched_get_priority_max(-1)`/`sched_get_priority_min(-1)` (an unrecognized policy) are
//!    `EINVAL`; `sched_get_priority_max(SCHED_FIFO)`/`_min(SCHED_FIFO)` are the real `99`/`1`.
//! 5. `sched_setscheduler(0, SCHED_FIFO, priority = max + 1)` (out of range) is `EINVAL`.
//! 6. `sched_setscheduler` on an already-reaped pid is `ESRCH`.
//! 7. A forked, `setuid(1)`-dropped child sees real `EPERM` from both `sched_getscheduler(1, ...)`
//!    and `sched_setscheduler(1, ...)` -- pid 1 (this very process, still root) is a different
//!    uid than the child's own dropped one.
//! 8. `sched_rr_get_interval(0, ...)`/`_( getpid(), ...)` report the identical, real non-negative
//!    interval; `ESRCH` on an already-reaped pid.
//! 9. `sched_yield()` returns `0`.
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
const SYS_SCHED_YIELD: u64 = 24;
const SYS_SETUID: u64 = 162;
const SYS_SCHED_SETSCHEDULER: u64 = 481;
const SYS_SCHED_GETSCHEDULER: u64 = 482;
const SYS_SCHED_GETPARAM: u64 = 483;
const SYS_SCHED_GET_PRIORITY_MAX: u64 = 484;
const SYS_SCHED_GET_PRIORITY_MIN: u64 = 485;
const SYS_SCHED_RR_GET_INTERVAL: u64 = 508;

const STDOUT: u64 = 1;

const SCHED_FIFO: i32 = 1;

/// Real value, matches `sys/syscall/mod.rs`'s own `EINVAL`; identical on Linux/BSD/musl.
const EINVAL: u64 = 22;
/// Real value, matches `sys/syscall/mod.rs`'s own `ESRCH`; identical on Linux/BSD/musl.
const ESRCH: u64 = 3;
/// Real value, matches `sys/syscall/mod.rs`'s own `EPERM`; identical on Linux/BSD/musl.
const EPERM: u64 = 1;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10`. Explicitly zeroing `r10` on every 3-arg
/// call above (rather than leaving it unspecified) is the exact audit CLAUDE.md's own "any future
/// syscall that upgrades from 3 to 4 real arguments" note calls out -- `SYSCALL` doesn't clear
/// `r10` itself.
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

const SYS_TEST_EXIT: u64 = 9999;

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

fn getpid() -> u64 {
    unsafe { syscall(SYS_GETPID, 0, 0, 0) }.unwrap_or(0)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSchedParam {
    sched_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

const ZERO_TS: RawTimespec = RawTimespec {
    tv_sec: -1,
    tv_nsec: -1,
};

fn sched_getparam(pid: u64) -> Result<i32, u64> {
    let mut param = RawSchedParam { sched_priority: -1 };
    unsafe {
        syscall(
            SYS_SCHED_GETPARAM,
            pid,
            &mut param as *mut RawSchedParam as u64,
            0,
        )?;
    }
    Ok(param.sched_priority)
}

fn sched_getscheduler(pid: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_SCHED_GETSCHEDULER, pid, 0, 0) }
}

fn sched_setscheduler(pid: u64, policy: i32, priority: i32) -> Result<u64, u64> {
    let param = RawSchedParam {
        sched_priority: priority,
    };
    unsafe {
        syscall(
            SYS_SCHED_SETSCHEDULER,
            pid,
            policy as u64,
            &param as *const RawSchedParam as u64,
        )
    }
}

fn sched_get_priority_max(policy: i32) -> Result<u64, u64> {
    unsafe { syscall(SYS_SCHED_GET_PRIORITY_MAX, policy as u64, 0, 0) }
}

fn sched_get_priority_min(policy: i32) -> Result<u64, u64> {
    unsafe { syscall(SYS_SCHED_GET_PRIORITY_MIN, policy as u64, 0, 0) }
}

fn sched_rr_get_interval(pid: u64) -> Result<RawTimespec, u64> {
    let mut ts = ZERO_TS;
    unsafe {
        syscall(
            SYS_SCHED_RR_GET_INTERVAL,
            pid,
            &mut ts as *mut RawTimespec as u64,
            0,
        )?;
    }
    Ok(ts)
}

fn sched_yield() -> Result<u64, u64> {
    unsafe { syscall(SYS_SCHED_YIELD, 0, 0, 0) }
}

fn fork() -> Result<u64, u64> {
    unsafe { syscall(SYS_FORK, 0, 0, 0) }
}

fn wait4(pid: u64) -> Result<(u64, i32), u64> {
    let mut status: i32 = -1;
    let ret = unsafe { syscall4(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0, 0) }?;
    Ok((ret, status))
}

fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sched-syscall-smoke: starting\n");

    // Part 1: sched_getparam(getpid()) succeeds; sched_getparam(0) reports the same value.
    let self_pid = getpid();
    let prio_self = match sched_getparam(self_pid) {
        Ok(p) if p != -1 => p,
        _ => {
            write_bytes(b"sched-syscall-smoke: sched_getparam(getpid()) failed\n");
            test_exit(false);
        }
    };
    match sched_getparam(0) {
        Ok(p) if p == prio_self => {}
        _ => {
            write_bytes(b"sched-syscall-smoke: sched_getparam(0) != sched_getparam(getpid())\n");
            test_exit(false);
        }
    }
    write_bytes(b"sched-syscall-smoke: part 1 (sched_getparam self/pid-0) OK\n");

    // Part 2: sched_getparam on an already-reaped pid is ESRCH. Also sets up the reaped pid used
    // by parts 6 and 8 below.
    let reaped_pid = match fork() {
        Ok(0) => unsafe {
            let _ = syscall(SYS_EXIT, 0, 0, 0);
            loop {
                spin_loop();
            }
        },
        Ok(child_pid) => {
            match wait4(child_pid) {
                Ok((reaped, _)) if reaped == child_pid => child_pid,
                _ => {
                    write_bytes(b"sched-syscall-smoke: reaping the throwaway child failed\n");
                    test_exit(false);
                }
            }
        }
        Err(_) => {
            write_bytes(b"sched-syscall-smoke: fork for the throwaway child failed\n");
            test_exit(false);
        }
    };
    if sched_getparam(reaped_pid).err() != Some(ESRCH) {
        write_bytes(b"sched-syscall-smoke: sched_getparam on a reaped pid didn't fail ESRCH\n");
        test_exit(false);
    }
    write_bytes(b"sched-syscall-smoke: part 2 (sched_getparam ESRCH on reaped pid) OK\n");

    // Part 3: sched_getscheduler(0) and sched_getscheduler(getpid()) agree.
    let policy0 = match sched_getscheduler(0) {
        Ok(p) => p,
        Err(_) => {
            write_bytes(b"sched-syscall-smoke: sched_getscheduler(0) failed\n");
            test_exit(false);
        }
    };
    if sched_getscheduler(self_pid) != Ok(policy0) {
        write_bytes(b"sched-syscall-smoke: sched_getscheduler(0) != sched_getscheduler(getpid())\n");
        test_exit(false);
    }
    write_bytes(b"sched-syscall-smoke: part 3 (sched_getscheduler self/pid-0) OK\n");

    // Part 4: an unrecognized policy is EINVAL; SCHED_FIFO's real range is 1..=99.
    if sched_get_priority_max(-1).err() != Some(EINVAL)
        || sched_get_priority_min(-1).err() != Some(EINVAL)
    {
        write_bytes(b"sched-syscall-smoke: sched_get_priority_max/min(-1) didn't fail EINVAL\n");
        test_exit(false);
    }
    let fifo_max = match sched_get_priority_max(SCHED_FIFO) {
        Ok(99) => 99,
        _ => {
            write_bytes(b"sched-syscall-smoke: sched_get_priority_max(SCHED_FIFO) != 99\n");
            test_exit(false);
        }
    };
    if sched_get_priority_min(SCHED_FIFO) != Ok(1) {
        write_bytes(b"sched-syscall-smoke: sched_get_priority_min(SCHED_FIFO) != 1\n");
        test_exit(false);
    }
    write_bytes(b"sched-syscall-smoke: part 4 (get_priority_max/min validation + range) OK\n");

    // Part 5: an out-of-range priority is EINVAL.
    if sched_setscheduler(0, SCHED_FIFO, fifo_max as i32 + 1).err() != Some(EINVAL) {
        write_bytes(b"sched-syscall-smoke: out-of-range sched_setscheduler didn't fail EINVAL\n");
        test_exit(false);
    }
    write_bytes(b"sched-syscall-smoke: part 5 (sched_setscheduler EINVAL out-of-range) OK\n");

    // Part 6: sched_setscheduler on an already-reaped pid is ESRCH.
    if sched_setscheduler(reaped_pid, SCHED_FIFO, 1).err() != Some(ESRCH) {
        write_bytes(b"sched-syscall-smoke: sched_setscheduler on a reaped pid didn't fail ESRCH\n");
        test_exit(false);
    }
    write_bytes(b"sched-syscall-smoke: part 6 (sched_setscheduler ESRCH on reaped pid) OK\n");

    // Part 7: a forked, setuid(1)-dropped child sees real EPERM targeting pid 1 (this very
    // process, still root).
    match fork() {
        Ok(0) => {
            if unsafe { syscall(SYS_SETUID, 1, 0, 0) } != Ok(0) {
                unsafe {
                    let _ = syscall(SYS_EXIT, 2, 0, 0);
                }
                loop {
                    spin_loop();
                }
            }
            let ok = sched_getscheduler(1).err() == Some(EPERM)
                && sched_setscheduler(1, SCHED_FIFO, 1).err() == Some(EPERM);
            unsafe {
                let _ = syscall(SYS_EXIT, if ok { 0 } else { 1 }, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => match wait4(child_pid) {
            Ok((reaped, status)) if reaped == child_pid && wexitstatus(status) == 0 => {
                write_bytes(b"sched-syscall-smoke: part 7 (real EPERM for a non-root target) OK\n");
            }
            _ => {
                write_bytes(b"sched-syscall-smoke: part 7's non-root child didn't see real EPERM\n");
                test_exit(false);
            }
        },
        Err(_) => {
            write_bytes(b"sched-syscall-smoke: part 7 fork failed\n");
            test_exit(false);
        }
    }

    // Part 8: sched_rr_get_interval(0) and sched_rr_get_interval(getpid()) agree, real and
    // non-negative; ESRCH on the already-reaped pid.
    let interval0 = match sched_rr_get_interval(0) {
        Ok(ts) if ts.tv_sec >= 0 && ts.tv_nsec >= 0 => ts,
        _ => {
            write_bytes(b"sched-syscall-smoke: sched_rr_get_interval(0) failed or wasn't updated\n");
            test_exit(false);
        }
    };
    match sched_rr_get_interval(self_pid) {
        Ok(ts) if ts.tv_sec == interval0.tv_sec && ts.tv_nsec == interval0.tv_nsec => {}
        _ => {
            write_bytes(
                b"sched-syscall-smoke: sched_rr_get_interval(0) != sched_rr_get_interval(getpid())\n",
            );
            test_exit(false);
        }
    }
    if sched_rr_get_interval(reaped_pid).err() != Some(ESRCH) {
        write_bytes(b"sched-syscall-smoke: sched_rr_get_interval on a reaped pid didn't fail ESRCH\n");
        test_exit(false);
    }
    write_bytes(b"sched-syscall-smoke: part 8 (sched_rr_get_interval self/pid-0/ESRCH) OK\n");

    // Part 9: sched_yield() returns 0.
    if sched_yield() != Ok(0) {
        write_bytes(b"sched-syscall-smoke: sched_yield() didn't return 0\n");
        test_exit(false);
    }
    write_bytes(b"sched-syscall-smoke: part 9 (sched_yield) OK\n");

    write_bytes(b"sched-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let _ = syscall(SYS_EXIT, 1, 0, 0);
    }
    loop {
        spin_loop();
    }
}
