//! Real-`SYSCALL` smoke test for `SYS_CLOCK_GETRES = 229`/`SYS_CLOCK_SETTIME = 227`/
//! `SYS_CLOCK_NANOSLEEP = 230` (`sys/modules/clock`'s `handle_clock_getres`/`handle_clock_settime`/
//! `handle_clock_nanosleep` -> `sys/syscall/ffi.rs`'s `oxidebsd_sys_clock_getres`/
//! `oxidebsd_sys_clock_settime`/`oxidebsd_sys_clock_nanosleep` -> `sys_clock_getres`/
//! `sys_clock_settime`/`process::timers::do_clock_nanosleep`) plus the real dynamic per-process
//! `clockid_t` decode `sys_clock_gettime`/`sys_clock_getres`/`sys_clock_settime` all share
//! (`decode_dynamic_cpu_clock_pid`) -- what backs real `clock_getcpuclockid(2)` entirely
//! client-side on the musl side, no separate syscall needed.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call or a re-run of the vendored Open POSIX Test Suite `.c` files themselves -- see
//! CLAUDE.md's Test architecture section for why every syscall-shaped addition here gets this
//! treatment. The actual pilot files (`clock_getcpuclockid/*.c`, `clock_getres/*.c`,
//! `clock_nanosleep/*.c`, `clock_settime/*.c`) are the real scoring target and get re-verified by
//! re-running the full pilot (`sh /posix_conformance.sh`) separately -- this crate's job is
//! narrower: proving the syscall plumbing, argument convention, and (part 8 below) the one
//! genuinely new piece of real-time-tracking machinery this batch of fixes needed, independent of
//! musl/the pilot's own C harness.
//!
//! **No musl involved** -- a bare `#![no_std]` binary with its own hand-rolled `syscall()` helper,
//! same convention every other real-`SYSCALL` smoke test in this codebase uses.
//!
//! Eight parts:
//! 1. `clock_getres` on every standard clockid (`CLOCK_REALTIME`/`CLOCK_MONOTONIC`/
//!    `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID`) succeeds with a real, nonzero
//!    resolution; an unrecognized positive clockid is `EINVAL`.
//! 2. `clock_settime(CLOCK_MONOTONIC, ...)` is always `EINVAL` (not settable); an out-of-range
//!    `tv_nsec` is `EINVAL` regardless of clockid.
//! 3. `clock_settime(CLOCK_REALTIME, ...)` really recalibrates the clock -- an immediate
//!    `clock_gettime(CLOCK_REALTIME, ...)` reads back the same value.
//! 4. A real dynamic per-process CPU-time `clockid_t`, hand-encoded the same way musl's own
//!    `clock_getcpuclockid()` does (`(-pid-1)*8 + 2`) -- `clock_getres` succeeds for a pid that
//!    exists (self) and fails `EINVAL` for one that doesn't; `clock_settime` on the self-encoded
//!    id followed by `clock_gettime` on a *separately* pid-`0`-encoded id (real
//!    `clock_getcpuclockid(0, ...)`'s own "the calling process" convention) reads back the same
//!    value -- both target the same process's `Process::cpu_ticks`.
//! 5. `clock_nanosleep(CLOCK_REALTIME, 0, ...)` (relative) really sleeps at least the requested
//!    duration, measured against `CLOCK_MONOTONIC`.
//! 6. `clock_nanosleep` with an unrecognized clockid is `EINVAL`.
//! 7. `clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, ...)` really sleeps until roughly the
//!    requested wall-clock target.
//! 8. **The real proof this batch of fixes needed**: a forked child blocks in
//!    `clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, target)`; the parent then rewinds the wall
//!    clock via `clock_settime` while the child is still asleep. A stale, tick-domain-only
//!    deadline (the bug this fixes) would let the child wake far too early, well before the real
//!    (post-rewind) wall clock ever reaches `target`; the fix (re-deriving the deadline fresh on
//!    every wake, see `process::timers::do_clock_nanosleep`'s own doc comment) makes it correctly
//!    wait out the full, rewound duration instead.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_CLOCK_GETTIME: u64 = 138;
const SYS_CLOCK_SETTIME: u64 = 227;
const SYS_CLOCK_GETRES: u64 = 229;
const SYS_CLOCK_NANOSLEEP: u64 = 230;

const STDOUT: u64 = 1;

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const TIMER_ABSTIME: u64 = 1;

/// Real value, matches `sys/syscall/mod.rs`'s own `EINVAL`; identical on Linux/BSD/musl.
const EINVAL: u64 = 22;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `clock_nanosleep`'s own
/// `flags`/`req_ptr` pair to both fit alongside `clockid`. Explicitly zeroing `r10` on every 3-arg
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

#[repr(C)]
#[derive(Clone, Copy)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

const ZERO_TS: RawTimespec = RawTimespec {
    tv_sec: 0,
    tv_nsec: 0,
};

fn clock_gettime(clockid: u64) -> Result<RawTimespec, u64> {
    let mut ts = ZERO_TS;
    unsafe {
        syscall(
            SYS_CLOCK_GETTIME,
            clockid,
            &mut ts as *mut RawTimespec as u64,
            0,
        )?;
    }
    Ok(ts)
}

fn clock_getres(clockid: u64) -> Result<RawTimespec, u64> {
    let mut ts = ZERO_TS;
    unsafe {
        syscall(
            SYS_CLOCK_GETRES,
            clockid,
            &mut ts as *mut RawTimespec as u64,
            0,
        )?;
    }
    Ok(ts)
}

fn clock_settime(clockid: u64, ts: RawTimespec) -> Result<u64, u64> {
    unsafe { syscall(SYS_CLOCK_SETTIME, clockid, &ts as *const RawTimespec as u64, 0) }
}

fn clock_nanosleep(clockid: u64, flags: u64, req: RawTimespec) -> Result<u64, u64> {
    unsafe {
        syscall4(
            SYS_CLOCK_NANOSLEEP,
            clockid,
            flags,
            &req as *const RawTimespec as u64,
            0,
        )
    }
}

fn monotonic_ms() -> i64 {
    let ts = clock_gettime(CLOCK_MONOTONIC).unwrap_or(ZERO_TS);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

/// The real, dynamic per-process `clockid_t` encoding `clock_getcpuclockid(2)`'s own musl
/// implementation produces -- see `decode_dynamic_cpu_clock_pid`'s own doc comment in the OxideBSD
/// tree for the full derivation. Hand-rolled here (rather than calling a real `clock_getcpuclockid`
/// wrapper, which doesn't exist -- there's no musl in this crate at all) since it's a pure,
/// client-side computation with no syscall of its own.
fn encode_process_cpuclock(pid: u64) -> u64 {
    (0u64.wrapping_sub(pid).wrapping_sub(1)).wrapping_mul(8).wrapping_add(2)
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
    write_bytes(b"clock-syscall-smoke: starting\n");

    // Part 1: clock_getres on every standard clockid, plus an invalid one.
    for &clockid in &[
        CLOCK_REALTIME,
        CLOCK_MONOTONIC,
        CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID,
    ] {
        match clock_getres(clockid) {
            Ok(res) if res.tv_sec == 0 && res.tv_nsec > 0 => {}
            _ => {
                write_bytes(b"clock-syscall-smoke: clock_getres on a standard clockid failed\n");
                test_exit(false);
            }
        }
    }
    if clock_getres(9999).err() != Some(EINVAL) {
        write_bytes(b"clock-syscall-smoke: clock_getres on a bogus clockid didn't fail EINVAL\n");
        test_exit(false);
    }
    write_bytes(b"clock-syscall-smoke: part 1 (clock_getres) OK\n");

    // Part 2: CLOCK_MONOTONIC is never settable; an out-of-range tv_nsec is always EINVAL.
    if clock_settime(
        CLOCK_MONOTONIC,
        RawTimespec {
            tv_sec: 1_000_000,
            tv_nsec: 0,
        },
    ) != Err(EINVAL)
    {
        write_bytes(b"clock-syscall-smoke: clock_settime(CLOCK_MONOTONIC) didn't fail EINVAL\n");
        test_exit(false);
    }
    if clock_settime(
        CLOCK_REALTIME,
        RawTimespec {
            tv_sec: 1_000_000,
            tv_nsec: 1_000_000_000,
        },
    ) != Err(EINVAL)
    {
        write_bytes(b"clock-syscall-smoke: clock_settime with bad tv_nsec didn't fail EINVAL\n");
        test_exit(false);
    }
    write_bytes(b"clock-syscall-smoke: part 2 (clock_settime validation) OK\n");

    // Part 3: clock_settime(CLOCK_REALTIME, ...) really recalibrates the clock.
    const TESTTIME: i64 = 1_037_128_358; // Nov 12, 2002 -- same fixture the real pilot files use.
    if clock_settime(
        CLOCK_REALTIME,
        RawTimespec {
            tv_sec: TESTTIME,
            tv_nsec: 0,
        },
    ) != Ok(0)
    {
        write_bytes(b"clock-syscall-smoke: clock_settime(CLOCK_REALTIME) failed\n");
        test_exit(false);
    }
    let after = match clock_gettime(CLOCK_REALTIME) {
        Ok(ts) => ts,
        Err(_) => {
            write_bytes(b"clock-syscall-smoke: clock_gettime after settime failed\n");
            test_exit(false);
        }
    };
    if !(TESTTIME..=TESTTIME + 1).contains(&after.tv_sec) {
        write_bytes(b"clock-syscall-smoke: clock didn't read back the value just set\n");
        test_exit(false);
    }
    write_bytes(b"clock-syscall-smoke: part 3 (clock_settime really recalibrates) OK\n");

    // Part 4: a real dynamic per-process CPU-time clockid_t, hand-encoded the same way musl's own
    // clock_getcpuclockid() does.
    let self_pid_clock = encode_process_cpuclock(1); // pid 1 -- this crate's own pid when spawned.
    if clock_getres(self_pid_clock).is_err() {
        write_bytes(b"clock-syscall-smoke: clock_getres on self's dynamic clockid failed\n");
        test_exit(false);
    }
    let bogus_pid_clock = encode_process_cpuclock(999);
    if clock_getres(bogus_pid_clock).err() != Some(EINVAL) {
        write_bytes(
            b"clock-syscall-smoke: clock_getres on a nonexistent pid's dynamic clockid didn't fail EINVAL\n",
        );
        test_exit(false);
    }
    if clock_settime(
        self_pid_clock,
        RawTimespec {
            tv_sec: 7,
            tv_nsec: 0,
        },
    ) != Ok(0)
    {
        write_bytes(b"clock-syscall-smoke: clock_settime on self's dynamic clockid failed\n");
        test_exit(false);
    }
    // pid 0 -- real clock_getcpuclockid(0, ...)'s own "the calling process" convention.
    let caller_clock = encode_process_cpuclock(0);
    let readback = match clock_gettime(caller_clock) {
        Ok(ts) => ts,
        Err(_) => {
            write_bytes(b"clock-syscall-smoke: clock_gettime on the pid-0 dynamic clockid failed\n");
            test_exit(false);
        }
    };
    if readback.tv_sec != 7 {
        write_bytes(
            b"clock-syscall-smoke: pid-0 dynamic clockid didn't read back what self's clockid set\n",
        );
        test_exit(false);
    }
    write_bytes(b"clock-syscall-smoke: part 4 (dynamic per-process CPU clockid) OK\n");

    // Part 5: clock_nanosleep(CLOCK_REALTIME, 0, ...) (relative) really sleeps.
    let before_ms = monotonic_ms();
    if clock_nanosleep(
        CLOCK_REALTIME,
        0,
        RawTimespec {
            tv_sec: 0,
            tv_nsec: 150_000_000,
        },
    ) != Ok(0)
    {
        write_bytes(b"clock-syscall-smoke: relative clock_nanosleep failed\n");
        test_exit(false);
    }
    if monotonic_ms() - before_ms < 150 {
        write_bytes(b"clock-syscall-smoke: relative clock_nanosleep didn't sleep long enough\n");
        test_exit(false);
    }
    write_bytes(b"clock-syscall-smoke: part 5 (relative clock_nanosleep) OK\n");

    // Part 6: an unrecognized clockid is EINVAL.
    if clock_nanosleep(9999, 0, ZERO_TS) != Err(EINVAL) {
        write_bytes(b"clock-syscall-smoke: clock_nanosleep on a bogus clockid didn't fail EINVAL\n");
        test_exit(false);
    }
    write_bytes(b"clock-syscall-smoke: part 6 (clock_nanosleep bogus clockid EINVAL) OK\n");

    // Part 7: clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, ...) sleeps until roughly the target.
    let now_real = clock_gettime(CLOCK_REALTIME).unwrap_or(ZERO_TS);
    let target = RawTimespec {
        tv_sec: now_real.tv_sec + 1,
        tv_nsec: now_real.tv_nsec,
    };
    let before_abs_ms = monotonic_ms();
    if clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, target) != Ok(0) {
        write_bytes(b"clock-syscall-smoke: absolute clock_nanosleep failed\n");
        test_exit(false);
    }
    let elapsed_abs_ms = monotonic_ms() - before_abs_ms;
    if !(700..2500).contains(&elapsed_abs_ms) {
        write_bytes(b"clock-syscall-smoke: absolute clock_nanosleep slept the wrong duration\n");
        test_exit(false);
    }
    write_bytes(b"clock-syscall-smoke: part 7 (absolute CLOCK_REALTIME clock_nanosleep) OK\n");

    // Part 8: real dynamic re-targeting -- a forked child blocks in an absolute CLOCK_REALTIME
    // sleep; the parent rewinds the wall clock while the child is still asleep, and the child must
    // wait out the full, rewound duration rather than waking too early against a stale deadline.
    let base = clock_gettime(CLOCK_REALTIME).unwrap_or(ZERO_TS);
    let child_target = RawTimespec {
        tv_sec: base.tv_sec + 3,
        tv_nsec: base.tv_nsec,
    };
    match fork() {
        Ok(0) => {
            let start_ms = monotonic_ms();
            let _ = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, child_target);
            let elapsed_ms = monotonic_ms() - start_ms;
            // A correct implementation waits out the full, rewound ~4s (1s already elapsed before
            // the parent's rewind, plus the full 3s target-offset again after it) -- a stale,
            // tick-domain-only deadline (the bug this closes) would instead fire at the original,
            // un-rewound ~3s mark. 3500ms is comfortably above that buggy value and comfortably
            // below the correct one, with real scheduler/tick slack either side.
            unsafe {
                let _ = syscall(SYS_EXIT, if elapsed_ms >= 3500 { 0 } else { 1 }, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            if clock_nanosleep(
                CLOCK_REALTIME,
                0,
                RawTimespec {
                    tv_sec: 1,
                    tv_nsec: 0,
                },
            ) != Ok(0)
            {
                write_bytes(b"clock-syscall-smoke: part 8 parent's own relative sleep failed\n");
                test_exit(false);
            }
            // Rewind the wall clock back to `base` -- the same real ~1s clock_settime rewind
            // clock_settime/7-1.c's own parent performs.
            if clock_settime(CLOCK_REALTIME, base) != Ok(0) {
                write_bytes(b"clock-syscall-smoke: part 8 parent's clock_settime rewind failed\n");
                test_exit(false);
            }
            match wait4(child_pid) {
                Ok((reaped, status)) if reaped == child_pid && wexitstatus(status) == 0 => {
                    write_bytes(
                        b"clock-syscall-smoke: part 8 (real dynamic CLOCK_REALTIME re-target across a settime rewind) OK\n",
                    );
                }
                Ok((_, status)) => {
                    write_bytes(b"clock-syscall-smoke: part 8 child woke too early after the rewind\n");
                    let _ = status;
                    test_exit(false);
                }
                Err(_) => {
                    write_bytes(b"clock-syscall-smoke: part 8 wait4 for the child failed\n");
                    test_exit(false);
                }
            }
        }
        Err(_) => {
            write_bytes(b"clock-syscall-smoke: part 8 fork failed\n");
            test_exit(false);
        }
    }

    write_bytes(b"clock-syscall-smoke: PASS\n");
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
