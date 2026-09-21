//! Real-`SYSCALL` smoke test for `SYS_TIMER_CREATE = 531`/`SYS_TIMER_SETTIME = 532`/
//! `SYS_TIMER_GETTIME = 533`/`SYS_TIMER_GETOVERRUN = 534`/`SYS_TIMER_DELETE = 535`
//! (`sys/modules/clock`'s `handle_timer_*` -> `sys/syscall/ffi.rs`'s `oxidebsd_sys_timer_*` ->
//! `sys/process/timers.rs`'s `do_timer_*`/`process::PosixTimer`) -- items 6-10 of `docs/
//! MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch, the real POSIX per-process
//! timer sub-batch.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- this feature depends on the timer IRQ firing correctly across a syscall
//! boundary and on real signal delivery, the same class of bug CLAUDE.md's "Real networking" and
//! musl-port sections document catching only through a real syscall instruction.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper and its own minimal `sigreturn_trampoline` (same convention
//! `regress/pause-syscall-smoke/` already established).
//!
//! Nine parts, all through `tests/posix_timer_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `timer_create` with an invalid `clockid` is a real `EINVAL`.
//! 2. `evp_ptr == 0` defaults to `SIGEV_SIGNAL`/`SIGALRM` (real POSIX default) -- a relative
//!    one-shot timer fires exactly once, and reads back fully disarmed afterward.
//! 3. An explicit `SIGEV_SIGNAL`/`SIGUSR1` *periodic* timer fires more than once, and
//!    `timer_delete` genuinely stops further firings.
//! 4. `TIMER_ABSTIME` against `CLOCK_MONOTONIC`.
//! 5. `TIMER_ABSTIME` against `CLOCK_REALTIME` (exercises the CMOS-RTC-anchored
//!    `abstime_to_ticks` branch specifically).
//! 6. `timer_getoverrun` accounting: block the target signal, let a periodic timer expire several
//!    times while undelivered, confirm a nonzero overrun count, then unblock and confirm the
//!    handler still runs (once -- this kernel delivers via a plain bitmask, not a real per-expiry
//!    queue).
//! 7. `EAGAIN` once all `MAX_POSIX_TIMERS` slots are in use, and slot reuse after `timer_delete`.
//! 8. `EINVAL` for an out-of-range or already-deleted `timerid` across every one of
//!    `timer_settime`/`timer_gettime`/`timer_getoverrun`/`timer_delete`.
//! 9. A periodic timer with `sigev_signo = SIGRTMIN` fires repeatedly through the real-time
//!    signal path (`Process::rt_queue`), not just standard signals -- previously rejected
//!    `EINVAL` unconditionally.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

const SYS_EXIT: u64 = 1;
const SYS_WRITE: u64 = 4;
const SYS_GETPID: u64 = 20;
const SYS_SIGACTION: u64 = 117;
const SYS_SIGPROCMASK: u64 = 118;
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `external/mit/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly
/// rather than going through a shared macro.
const SYS_SIGRETURN: u64 = 119;
const SYS_CLOCK_GETTIME: u64 = 138;
const SYS_TIMER_CREATE: u64 = 531;
const SYS_TIMER_SETTIME: u64 = 532;
const SYS_TIMER_GETTIME: u64 = 533;
const SYS_TIMER_GETOVERRUN: u64 = 534;
const SYS_TIMER_DELETE: u64 = 535;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// posix_timer_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

const SIGALRM: u64 = 14;
const SIGUSR1: u64 = 10;
/// Matches `sys/process/mod.rs`'s own `SIGRTMIN` -- no shared crate across this ABI boundary.
const SIGRTMIN: u64 = 35;

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const TIMER_ABSTIME: u64 = 1;

const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;

/// Real value, matches `sys/syscall/mod.rs`'s own `EINVAL`; identical on Linux/BSD/musl.
const EINVAL: u64 = 22;
/// Real value, matches `sys/syscall/mod.rs`'s own `EAGAIN`; identical on Linux/BSD/musl.
const EAGAIN: u64 = 11;

/// Must match `sys/process/mod.rs`'s own `MAX_POSIX_TIMERS` -- no shared crate across this ABI
/// boundary, same convention every other regress/kernel pair here uses.
const MAX_POSIX_TIMERS: usize = 8;

const SIGEV_SIGNAL: i32 = 0;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`/`sigprocmask`'s
/// own `sigsetsize` and `timer_settime`'s own `old_ptr`. Explicitly zeroing `r10` on every 3-arg
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

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[repr(C)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Matches the kernel's own `RawKSigevent` (`sys/process/timers.rs`) exactly -- `union sigval` is
/// 8 bytes on this LP64 target, trailing padding to 24 bytes is automatic under `repr(C)`.
#[repr(C)]
struct RawKSigevent {
    sigev_value: u64,
    sigev_signo: i32,
    sigev_notify: i32,
    sigev_tid: i32,
}

const _: () = assert!(core::mem::size_of::<RawKSigevent>() == 24);

/// Matches the kernel's own `RawItimerspec` (`sys/process/timers.rs`) exactly.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawItimerspec {
    it_interval_sec: i64,
    it_interval_nsec: i64,
    it_value_sec: i64,
    it_value_nsec: i64,
}

const ZERO_ITIMERSPEC: RawItimerspec = RawItimerspec {
    it_interval_sec: 0,
    it_interval_nsec: 0,
    it_value_sec: 0,
    it_value_nsec: 0,
};

/// Matches `sys/process/signals.rs`'s `do_sigaction`'s own `RawSigAction` wire format exactly.
#[repr(C)]
struct RawSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// This crate's own minimal `__restore_rt` equivalent -- see `regress/pause-syscall-smoke/src/
/// main.rs`'s own module doc comment for why a hand-rolled one is needed here (no musl to provide
/// the real one). Never called directly from Rust; its address is installed as `sigaction`'s own
/// `restorer` field.
global_asm!(
    ".global sigreturn_trampoline",
    "sigreturn_trampoline:",
    "mov rax, {sigreturn}",
    "syscall",
    sigreturn = const SYS_SIGRETURN,
);

unsafe extern "C" {
    fn sigreturn_trampoline();
}

static SIGALRM_COUNT: AtomicU32 = AtomicU32::new(0);
static SIGUSR1_COUNT: AtomicU32 = AtomicU32::new(0);
static SIGRTMIN_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" fn sigalrm_handler(_signum: i64) {
    SIGALRM_COUNT.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn sigusr1_handler(_signum: i64) {
    SIGUSR1_COUNT.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn sigrtmin_handler(_signum: i64) {
    SIGRTMIN_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn install_handler(sig: u64, handler: extern "C" fn(i64)) -> bool {
    let act = RawSigAction {
        handler: handler as u64,
        flags: 0,
        restorer: sigreturn_trampoline as u64,
        mask: 0,
    };
    unsafe {
        syscall4(SYS_SIGACTION, sig, &act as *const RawSigAction as u64, 0, 8).is_ok()
    }
}

fn sigprocmask_one(how: u64, sig: u64) -> Result<u64, u64> {
    let set = 1u64 << (sig - 1);
    unsafe { syscall4(SYS_SIGPROCMASK, how, &set as *const u64 as u64, 0, 8) }
}

fn clock_gettime_ts(clockid: u64) -> RawTimespec {
    let mut ts = RawTimespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        let _ = syscall(
            SYS_CLOCK_GETTIME,
            clockid,
            &mut ts as *mut RawTimespec as u64,
            0,
        );
    }
    ts
}

fn monotonic_ms() -> i64 {
    let ts = clock_gettime_ts(CLOCK_MONOTONIC);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

fn add_ms(ts: RawTimespec, ms: i64) -> RawTimespec {
    let mut sec = ts.tv_sec + ms / 1000;
    let mut nsec = ts.tv_nsec + (ms % 1000) * 1_000_000;
    if nsec >= 1_000_000_000 {
        nsec -= 1_000_000_000;
        sec += 1;
    }
    RawTimespec {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

fn relative_ms(interval_ms: i64, value_ms: i64) -> RawItimerspec {
    RawItimerspec {
        it_interval_sec: interval_ms / 1000,
        it_interval_nsec: (interval_ms % 1000) * 1_000_000,
        it_value_sec: value_ms / 1000,
        it_value_nsec: (value_ms % 1000) * 1_000_000,
    }
}

/// Busy-spins on cheap, individually non-blocking `SYS_GETPID` calls (letting the timer IRQ keep
/// advancing the real tick count and firing expiries in the background) until `cond` is true or
/// `bound_ms` elapses -- same idiom `regress/itimer-syscall-smoke/src/main.rs` already
/// established for waiting on a real `SIGALRM`.
fn wait_until(bound_ms: i64, mut cond: impl FnMut() -> bool) -> bool {
    let start = monotonic_ms();
    loop {
        if cond() {
            return true;
        }
        unsafe {
            let _ = syscall(SYS_GETPID, 0, 0, 0);
        }
        if monotonic_ms() - start > bound_ms {
            return false;
        }
    }
}

fn timer_create(clockid: u64, evp: Option<&RawKSigevent>) -> Result<i32, u64> {
    let evp_ptr = evp.map(|e| e as *const RawKSigevent as u64).unwrap_or(0);
    let mut id: i32 = -1;
    unsafe {
        syscall(
            SYS_TIMER_CREATE,
            clockid,
            evp_ptr,
            &mut id as *mut i32 as u64,
        )?;
    }
    Ok(id)
}

fn timer_settime(
    id: i32,
    flags: u64,
    new: &RawItimerspec,
    old: Option<&mut RawItimerspec>,
) -> Result<u64, u64> {
    let old_ptr = old
        .map(|o| o as *mut RawItimerspec as u64)
        .unwrap_or(0);
    unsafe {
        syscall4(
            SYS_TIMER_SETTIME,
            id as u64,
            flags,
            new as *const RawItimerspec as u64,
            old_ptr,
        )
    }
}

fn timer_gettime(id: i32, val: &mut RawItimerspec) -> Result<u64, u64> {
    unsafe { syscall(SYS_TIMER_GETTIME, id as u64, val as *mut RawItimerspec as u64, 0) }
}

fn timer_getoverrun(id: i32) -> Result<u64, u64> {
    unsafe { syscall(SYS_TIMER_GETOVERRUN, id as u64, 0, 0) }
}

fn timer_delete(id: i32) -> Result<u64, u64> {
    unsafe { syscall(SYS_TIMER_DELETE, id as u64, 0, 0) }
}

fn is_zero_itimerspec(spec: &RawItimerspec) -> bool {
    spec.it_interval_sec == 0
        && spec.it_interval_nsec == 0
        && spec.it_value_sec == 0
        && spec.it_value_nsec == 0
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"posix-timer-syscall-smoke: starting\n");

    if !install_handler(SIGALRM, sigalrm_handler)
        || !install_handler(SIGUSR1, sigusr1_handler)
        || !install_handler(SIGRTMIN, sigrtmin_handler)
    {
        write_bytes(b"posix-timer-syscall-smoke: installing handlers failed\n");
        test_exit(false);
    }

    // Part 1: an invalid clockid is a real EINVAL.
    if timer_create(99, None) != Err(EINVAL) {
        write_bytes(b"posix-timer-syscall-smoke: bad clockid didn't fail EINVAL\n");
        test_exit(false);
    }
    write_bytes(b"posix-timer-syscall-smoke: part 1 (bad clockid EINVAL) OK\n");

    // Part 2: evp_ptr == 0 defaults to SIGEV_SIGNAL/SIGALRM -- a relative one-shot timer.
    let id_default = match timer_create(CLOCK_MONOTONIC, None) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: default-evp timer_create failed\n");
            test_exit(false);
        }
    };
    let arm_oneshot = relative_ms(0, 100);
    if timer_settime(id_default, 0, &arm_oneshot, None) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: one-shot timer_settime failed\n");
        test_exit(false);
    }
    if !wait_until(3000, || SIGALRM_COUNT.load(Ordering::SeqCst) >= 1) {
        write_bytes(b"posix-timer-syscall-smoke: default-evp SIGALRM never fired\n");
        test_exit(false);
    }
    if SIGALRM_COUNT.load(Ordering::SeqCst) != 1 {
        write_bytes(b"posix-timer-syscall-smoke: one-shot timer fired more than once\n");
        test_exit(false);
    }
    let mut readback = ZERO_ITIMERSPEC;
    if timer_gettime(id_default, &mut readback) != Ok(0) || !is_zero_itimerspec(&readback) {
        write_bytes(b"posix-timer-syscall-smoke: one-shot timer didn't read back disarmed\n");
        test_exit(false);
    }
    write_bytes(b"posix-timer-syscall-smoke: part 2 (default-evp one-shot SIGALRM) OK\n");

    // Part 3: an explicit SIGEV_SIGNAL/SIGUSR1 periodic timer, then timer_delete stops it.
    let evp_usr1 = RawKSigevent {
        sigev_value: 0,
        sigev_signo: SIGUSR1 as i32,
        sigev_notify: SIGEV_SIGNAL,
        sigev_tid: 0,
    };
    let id_periodic = match timer_create(CLOCK_MONOTONIC, Some(&evp_usr1)) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: periodic timer_create failed\n");
            test_exit(false);
        }
    };
    let arm_periodic = relative_ms(60, 60);
    if timer_settime(id_periodic, 0, &arm_periodic, None) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: periodic timer_settime failed\n");
        test_exit(false);
    }
    if !wait_until(5000, || SIGUSR1_COUNT.load(Ordering::SeqCst) >= 3) {
        write_bytes(b"posix-timer-syscall-smoke: periodic SIGUSR1 didn't fire 3+ times\n");
        test_exit(false);
    }
    if timer_delete(id_periodic) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: deleting the periodic timer failed\n");
        test_exit(false);
    }
    let snapshot = SIGUSR1_COUNT.load(Ordering::SeqCst);
    // Spin a while longer -- a real regression (delete not actually disarming) would show up as
    // the count continuing to climb.
    let _ = wait_until(300, || false);
    if SIGUSR1_COUNT.load(Ordering::SeqCst) != snapshot {
        write_bytes(b"posix-timer-syscall-smoke: timer_delete didn't really stop the timer\n");
        test_exit(false);
    }
    write_bytes(b"posix-timer-syscall-smoke: part 3 (periodic SIGUSR1 + delete stops it) OK\n");

    // Part 4: TIMER_ABSTIME against CLOCK_MONOTONIC.
    let id_abs_mono = match timer_create(CLOCK_MONOTONIC, Some(&evp_usr1)) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: abstime-monotonic timer_create failed\n");
            test_exit(false);
        }
    };
    let target = add_ms(clock_gettime_ts(CLOCK_MONOTONIC), 80);
    let arm_abs_mono = RawItimerspec {
        it_interval_sec: 0,
        it_interval_nsec: 0,
        it_value_sec: target.tv_sec,
        it_value_nsec: target.tv_nsec,
    };
    let before = SIGUSR1_COUNT.load(Ordering::SeqCst);
    if timer_settime(id_abs_mono, TIMER_ABSTIME, &arm_abs_mono, None) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: abstime-monotonic timer_settime failed\n");
        test_exit(false);
    }
    if !wait_until(3000, || SIGUSR1_COUNT.load(Ordering::SeqCst) > before) {
        write_bytes(b"posix-timer-syscall-smoke: abstime-monotonic timer never fired\n");
        test_exit(false);
    }
    let _ = timer_delete(id_abs_mono);
    write_bytes(b"posix-timer-syscall-smoke: part 4 (TIMER_ABSTIME/CLOCK_MONOTONIC) OK\n");

    // Part 5: TIMER_ABSTIME against CLOCK_REALTIME -- exercises the CMOS-RTC-anchored branch.
    let id_abs_real = match timer_create(CLOCK_REALTIME, Some(&evp_usr1)) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: abstime-realtime timer_create failed\n");
            test_exit(false);
        }
    };
    let target_real = add_ms(clock_gettime_ts(CLOCK_REALTIME), 1000);
    let arm_abs_real = RawItimerspec {
        it_interval_sec: 0,
        it_interval_nsec: 0,
        it_value_sec: target_real.tv_sec,
        it_value_nsec: target_real.tv_nsec,
    };
    let before_real = SIGUSR1_COUNT.load(Ordering::SeqCst);
    if timer_settime(id_abs_real, TIMER_ABSTIME, &arm_abs_real, None) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: abstime-realtime timer_settime failed\n");
        test_exit(false);
    }
    if !wait_until(4000, || SIGUSR1_COUNT.load(Ordering::SeqCst) > before_real) {
        write_bytes(b"posix-timer-syscall-smoke: abstime-realtime timer never fired\n");
        test_exit(false);
    }
    let _ = timer_delete(id_abs_real);
    write_bytes(b"posix-timer-syscall-smoke: part 5 (TIMER_ABSTIME/CLOCK_REALTIME) OK\n");

    // Part 6: overrun accounting -- block SIGUSR1, let a periodic timer expire several times
    // undelivered, confirm a nonzero overrun, then unblock and confirm exactly one delivery.
    if sigprocmask_one(SIG_BLOCK, SIGUSR1) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: blocking SIGUSR1 failed\n");
        test_exit(false);
    }
    let id_overrun = match timer_create(CLOCK_MONOTONIC, Some(&evp_usr1)) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: overrun timer_create failed\n");
            test_exit(false);
        }
    };
    let arm_overrun = relative_ms(30, 30);
    if timer_settime(id_overrun, 0, &arm_overrun, None) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: overrun timer_settime failed\n");
        test_exit(false);
    }
    // Real time, not signal-driven -- SIGUSR1 is blocked, so nothing here waits on it. ~200ms
    // against a 30ms period is comfortably several expiries.
    let _ = wait_until(200, || false);
    let overrun = match timer_getoverrun(id_overrun) {
        Ok(n) => n,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: timer_getoverrun failed\n");
            test_exit(false);
        }
    };
    if overrun < 2 {
        write_bytes(b"posix-timer-syscall-smoke: overrun count too low\n");
        test_exit(false);
    }
    let before_unblock = SIGUSR1_COUNT.load(Ordering::SeqCst);
    if sigprocmask_one(SIG_UNBLOCK, SIGUSR1) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: unblocking SIGUSR1 failed\n");
        test_exit(false);
    }
    // The very next completed syscall's own dispatch tail delivers the pending signal.
    unsafe {
        let _ = syscall(SYS_GETPID, 0, 0, 0);
    }
    if SIGUSR1_COUNT.load(Ordering::SeqCst) != before_unblock + 1 {
        write_bytes(b"posix-timer-syscall-smoke: unblock didn't deliver exactly once\n");
        test_exit(false);
    }
    let _ = timer_delete(id_overrun);
    write_bytes(b"posix-timer-syscall-smoke: part 6 (overrun accounting) OK\n");

    // Part 7: EAGAIN once every MAX_POSIX_TIMERS slot is in use, and slot reuse after delete.
    // id_default is still allocated (part 2 disarmed it, never deleted it) -- clean it up first so
    // every slot is genuinely free before filling them all.
    let _ = timer_delete(id_default);
    let mut ids = [0i32; MAX_POSIX_TIMERS];
    for slot in ids.iter_mut() {
        match timer_create(CLOCK_MONOTONIC, None) {
            Ok(id) => *slot = id,
            Err(_) => {
                write_bytes(b"posix-timer-syscall-smoke: filling every timer slot failed early\n");
                test_exit(false);
            }
        }
    }
    if timer_create(CLOCK_MONOTONIC, None) != Err(EAGAIN) {
        write_bytes(b"posix-timer-syscall-smoke: exceeding MAX_POSIX_TIMERS didn't fail EAGAIN\n");
        test_exit(false);
    }
    if timer_delete(ids[0]) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: deleting a slot to free it failed\n");
        test_exit(false);
    }
    let reused = match timer_create(CLOCK_MONOTONIC, None) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: slot reuse after delete failed\n");
            test_exit(false);
        }
    };
    if reused != ids[0] {
        write_bytes(b"posix-timer-syscall-smoke: reused slot didn't reuse the freed index\n");
        test_exit(false);
    }
    write_bytes(b"posix-timer-syscall-smoke: part 7 (EAGAIN + slot reuse) OK\n");

    // Part 8: EINVAL for an out-of-range or already-deleted timerid.
    let bogus: i32 = 999;
    let mut spec = ZERO_ITIMERSPEC;
    if timer_settime(bogus, 0, &ZERO_ITIMERSPEC, None) != Err(EINVAL)
        || timer_gettime(bogus, &mut spec) != Err(EINVAL)
        || timer_getoverrun(bogus) != Err(EINVAL)
        || timer_delete(bogus) != Err(EINVAL)
    {
        write_bytes(b"posix-timer-syscall-smoke: an out-of-range timerid didn't fail EINVAL\n");
        test_exit(false);
    }
    // ids[1] is still allocated (only ids[0] was deleted+reused above) -- delete it for real, then
    // confirm every op on it now fails EINVAL too.
    if timer_delete(ids[1]) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: deleting ids[1] failed\n");
        test_exit(false);
    }
    if timer_settime(ids[1], 0, &ZERO_ITIMERSPEC, None) != Err(EINVAL)
        || timer_gettime(ids[1], &mut spec) != Err(EINVAL)
        || timer_getoverrun(ids[1]) != Err(EINVAL)
        || timer_delete(ids[1]) != Err(EINVAL)
    {
        write_bytes(b"posix-timer-syscall-smoke: an already-deleted timerid didn't fail EINVAL\n");
        test_exit(false);
    }
    write_bytes(b"posix-timer-syscall-smoke: part 8 (EINVAL for bad/deleted timerid) OK\n");

    // Clean up the rest of the slots filled in part 7 -- not load-bearing for the test result, but
    // keeps this run's own footprint tidy.
    for &id in ids.iter().skip(2) {
        let _ = timer_delete(id);
    }

    // Part 9: `sigev_signo` may be a real-time signal (`SIGRTMIN`) -- real POSIX explicitly
    // allows this, and it used to be rejected `EINVAL` unconditionally (see `do_timer_create`'s
    // own doc comment). Exercises the fix directly: a periodic RT-signaled timer must actually
    // deliver more than once through the kernel's `rt_queue`-backed path, not just avoid a panic
    // on the first firing.
    let evp_rtmin = RawKSigevent {
        sigev_value: 0,
        sigev_signo: SIGRTMIN as i32,
        sigev_notify: SIGEV_SIGNAL,
        sigev_tid: 0,
    };
    let id_rt = match timer_create(CLOCK_MONOTONIC, Some(&evp_rtmin)) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"posix-timer-syscall-smoke: RT-signal timer_create failed\n");
            test_exit(false);
        }
    };
    let arm_rt = relative_ms(60, 60);
    if timer_settime(id_rt, 0, &arm_rt, None) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: RT-signal timer_settime failed\n");
        test_exit(false);
    }
    if !wait_until(5000, || SIGRTMIN_COUNT.load(Ordering::SeqCst) >= 3) {
        write_bytes(b"posix-timer-syscall-smoke: RT-signal timer didn't fire 3+ times\n");
        test_exit(false);
    }
    if timer_delete(id_rt) != Ok(0) {
        write_bytes(b"posix-timer-syscall-smoke: deleting the RT-signal timer failed\n");
        test_exit(false);
    }
    write_bytes(b"posix-timer-syscall-smoke: part 9 (periodic SIGRTMIN timer) OK\n");

    write_bytes(b"posix-timer-syscall-smoke: PASS\n");
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
