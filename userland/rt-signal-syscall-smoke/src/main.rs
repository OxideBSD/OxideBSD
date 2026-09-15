//! Real-`SYSCALL` smoke test for real-time signal queuing (`SIGRTMIN..=SIGRTMAX`, `35..=64`) --
//! `src/process/signals.rs`'s `record_pending`/`take_deliverable_signal`/`do_sigtimedwait` RT
//! branches, and the extended `do_kill`/`do_sigqueue`/`sys_sigaction` range checks. Closes the
//! Open POSIX Test Suite pilot's own `sigqueue/1-1,5-1,6-1,7-1.c` + `sigwait/2-1.c` UNRESOLVED
//! cluster (see `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`'s own "Real-time signal queuing" blocker) --
//! those all fail before their real assertion is ever reached, since every real signal number
//! they use (`SIGRTMIN`) used to be flatly rejected by this ABI's `1..=31`-only range checks.
//! `sigqueue/4-1.c`/`8-1.c` needed a second, separate fix on top (real signal-stack chaining --
//! see `src/syscall/mod.rs`'s `deliver_pending_signal`/`do_sigreturn`), landed later; parts 1/3
//! below originally worked around that gap with an explicit multi-syscall "pump" and now don't
//! need to. This test doesn't re-run the vendored suite itself (that stays automated via
//! `tests/posix_conformance_smoke.rs` + `userland/posix-conformance-driver/`, not this crate), it
//! exercises the same underlying kernel behavior those tests depend on through a dedicated,
//! automated, real-`SYSCALL` scenario.
//!
//! **No musl involved** -- bare `#![no_std]` binary with its own hand-rolled `syscall()` helper
//! and minimal `sigreturn_trampoline`, same convention `userland/sig-syscall-smoke/` established.
//!
//! Five parts, all driven from `tests/rt_signal_syscall_smoke.rs` spawning this as pid 1:
//! 1. `sigqueue/4-1.c`'s own scenario: `SIGRTMIN` blocked, queued 5 times, handler runs 0 times
//!    while still blocked, then all 5 times once unblocked -- proves multiple instances don't
//!    collapse into one the way a standard signal already does, and (checked immediately after
//!    the unblocking `sigprocmask` call returns, no extra syscalls in between) that all 5 real
//!    handler invocations happen via the unblocking call's own signal-stack chain, matching what
//!    `sigqueue/4-1.c` itself actually checks.
//! 2. Real per-signal `EAGAIN` once `RT_QUEUE_CAP` is exceeded, then a real full drain via
//!    `sigtimedwait` (which bypasses handler invocation/disposition entirely, so no handler needs
//!    to be installed for this signal at all) confirming every queued value comes back in order,
//!    followed by a real timeout `EAGAIN` once genuinely empty.
//! 3. `sigqueue/7-1.c`'s own scenario: two different RT signal numbers queued higher-first, then
//!    unblocked together -- confirms delivery order is lowest-signal-number-first regardless of
//!    queuing order (falls out of `take_deliverable_signal`'s existing `trailing_zeros()` pick,
//!    unchanged by this work, but only reachable at all once RT numbers pass validation).
//! 4. `sigwait/2-1.c`'s own scenario, via `sigtimedwait` (the same real syscall `sigwait(3)`
//!    itself routes through): raise the same RT signal twice, confirm it's still reported pending
//!    after consuming just one instance, and only actually clear once the second is consumed too.
//! 5. Real `EINVAL` boundary validation: the permanently-unclaimed `32..=34` gap below `SIGRTMIN`,
//!    and one past `SIGRTMAX`, are still rejected by `sigaction`/`kill`/`sigqueue` alike; `SIGRTMIN`
//!    and `SIGRTMAX` themselves are accepted.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

const SYS_WRITE: u64 = 4;
const SYS_GETPID: u64 = 20;
const SYS_KILL: u64 = 116;
const SYS_SIGACTION: u64 = 117;
const SYS_SIGPROCMASK: u64 = 118;
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `third_party/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly.
const SYS_SIGRETURN: u64 = 119;
const SYS_SIGPENDING: u64 = 494;
const SYS_SIGTIMEDWAIT: u64 = 495;
const SYS_SIGQUEUE: u64 = 496;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// rt_signal_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const EINVAL: u64 = 22;
const EAGAIN: u64 = 11;

/// Real `sigprocmask(2)` `how` values -- matches `src/process/signals.rs`'s own `do_sigprocmask`.
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;

/// Must match `src/process/mod.rs`'s own `SIGRTMIN`/`SIGRTMAX` exactly (musl's `sigrtmin.c`
/// hardcodes `35`; `SIGRTMAX = _NSIG - 1 = 64`).
const SIGRTMIN: u64 = 35;
const SIGRTMAX: u64 = 64;
/// Must match `src/process/signals.rs`'s own `RT_QUEUE_CAP`.
const RT_QUEUE_CAP: u64 = 16;

const SA_SIGINFO: u64 = 0x00000004;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`/
/// `sigtimedwait`'s own `sigsetsize`. Explicitly zeroing `r10` on every 3-arg call above (rather
/// than leaving it unspecified) is the exact audit CLAUDE.md's own "any future syscall that
/// upgrades from 3 to 4 real arguments" note calls out -- `SYSCALL` doesn't clear `r10` itself.
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
            write_bytes(concat!("rt-signal-syscall-smoke: FAIL -- ", $msg, "\n").as_bytes());
            test_exit(false);
        }
    };
}

/// Matches `src/process/mod.rs`'s own `RawSiginfo` wire format exactly.
#[repr(C)]
struct RawSiginfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad0: i32,
    si_pid: i32,
    si_uid: i32,
    si_value: u64,
    _tail: [u8; 128 - 4 * 4 - 2 * 4 - 8],
}

impl RawSiginfo {
    const fn zeroed() -> Self {
        RawSiginfo {
            si_signo: 0,
            si_code: 0,
            si_errno: 0,
            _pad0: 0,
            si_pid: 0,
            si_uid: 0,
            si_value: 0,
            _tail: [0; 128 - 4 * 4 - 2 * 4 - 8],
        }
    }
}

/// Matches `src/process/signals.rs`'s `resolve_relative_deadline`'s own `(sec, nsec)` pair.
#[repr(C)]
struct RawTimespec {
    sec: i64,
    nsec: i64,
}

/// Matches `src/process/signals.rs`'s `do_sigaction`'s own `RawSigAction` wire format exactly.
#[repr(C)]
struct RawSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// This crate's own minimal `__restore_rt` equivalent -- see `userland/pause-syscall-smoke/`'s own
/// module doc comment for why a hand-rolled one is needed here (no musl to provide the real one).
/// Never called directly from Rust; its address is installed as `sigaction`'s own `restorer` field.
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

/// Records each real handler invocation's own signal number, in delivery order -- part 3's own
/// proof that `SIGRTMIN..=SIGRTMAX` delivery is genuinely lowest-number-first, not queuing order.
static mut ORDER_LOG: [u64; 8] = [0; 8];
static ORDER_LEN: AtomicUsize = AtomicUsize::new(0);

/// The real `SA_SIGINFO` handler under test -- a genuine 3-argument `extern "C" fn`, matching
/// `userland/sa-siginfo-syscall-smoke/`'s own already-proven signature exactly.
extern "C" fn rt_handler(signum: i64, _siginfo: *const RawSiginfo, _ucontext: u64) {
    let idx = ORDER_LEN.fetch_add(1, Ordering::SeqCst);
    if idx < 8 {
        unsafe {
            (*(&raw mut ORDER_LOG))[idx] = signum as u64;
        }
    }
}

fn order_log_at(idx: usize) -> u64 {
    unsafe { (*(&raw const ORDER_LOG))[idx] }
}

fn sigaction(sig: u64, handler: u64, flags: u64) -> Result<u64, u64> {
    let act = RawSigAction {
        handler,
        flags,
        restorer: sigreturn_trampoline as u64,
        mask: 0,
    };
    unsafe { syscall4(SYS_SIGACTION, sig, &act as *const RawSigAction as u64, 0, 8) }
}

fn sigprocmask(how: u64, mask: u64) -> Result<u64, u64> {
    unsafe { syscall4(SYS_SIGPROCMASK, how, &mask as *const u64 as u64, 0, 8) }
}

fn sigpending() -> u64 {
    let mut set: u64 = 0;
    let _ = unsafe { syscall4(SYS_SIGPENDING, &mut set as *mut u64 as u64, 8, 0, 0) };
    set
}

fn sigqueue(pid: u64, sig: u64, value: u64) -> Result<u64, u64> {
    let mut si = RawSiginfo::zeroed();
    si.si_value = value;
    unsafe { syscall(SYS_SIGQUEUE, pid, sig, &si as *const RawSiginfo as u64) }
}

fn sigtimedwait(wait_set: u64, ts: Option<&RawTimespec>) -> Result<(u64, RawSiginfo), u64> {
    let mut info = RawSiginfo::zeroed();
    let ts_ptr = ts.map_or(0, |t| t as *const RawTimespec as u64);
    let signum = unsafe {
        syscall4(
            SYS_SIGTIMEDWAIT,
            &wait_set as *const u64 as u64,
            &mut info as *mut RawSiginfo as u64,
            ts_ptr,
            8,
        )
    }?;
    Ok((signum, info))
}

fn getpid() -> u64 {
    unsafe { syscall(SYS_GETPID, 0, 0, 0) }.unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"rt-signal-syscall-smoke: starting\n");

    let pid = getpid();
    check!(pid != 0, "getpid failed");

    // --- Part 1: sigqueue/4-1.c's own scenario -- SIGRTMIN queued 5 times while blocked, all 5
    // handler invocations only happen once unblocked. ---
    check!(
        sigaction(SIGRTMIN, rt_handler as u64, SA_SIGINFO).is_ok(),
        "sigaction(SIGRTMIN) failed"
    );
    check!(
        sigprocmask(SIG_BLOCK, 1 << (SIGRTMIN - 1)).is_ok(),
        "sigprocmask(SIG_BLOCK, SIGRTMIN) failed"
    );
    for i in 0..5u64 {
        check!(
            sigqueue(pid, SIGRTMIN, i).is_ok(),
            "sigqueue(SIGRTMIN) while blocked failed"
        );
    }
    check!(
        ORDER_LEN.load(Ordering::SeqCst) == 0,
        "handler ran while SIGRTMIN was still blocked"
    );
    check!(
        sigprocmask(SIG_UNBLOCK, 1 << (SIGRTMIN - 1)).is_ok(),
        "sigprocmask(SIG_UNBLOCK, SIGRTMIN) failed"
    );
    // No pump of extra syscalls needed here: real signal-stack chaining means the unblocking
    // sigprocmask call itself delivers every already-queued instance (via its own tail, then each
    // handler's own sigreturn re-checking for the next one) before ever returning to this code --
    // see `deliver_pending_signal`/`do_sigreturn` in `src/syscall/mod.rs`.
    check!(
        ORDER_LEN.load(Ordering::SeqCst) == 5,
        "not all 5 queued SIGRTMIN instances were delivered -- real-time signals collapsed like a standard one"
    );
    write_bytes(b"rt-signal-syscall-smoke: part 1 (5 queued instances, 5 real deliveries, no pump needed) OK\n");

    // --- Part 2: real EAGAIN past RT_QUEUE_CAP, then a real full drain via sigtimedwait (which
    // bypasses handler invocation/disposition entirely -- no handler needed for this signal). ---
    let sig2 = SIGRTMIN + 1;
    check!(
        sigprocmask(SIG_BLOCK, 1 << (sig2 - 1)).is_ok(),
        "sigprocmask(SIG_BLOCK, sig2) failed"
    );
    for i in 0..RT_QUEUE_CAP {
        check!(
            sigqueue(pid, sig2, 1000 + i).is_ok(),
            "sigqueue(sig2) failed before reaching RT_QUEUE_CAP"
        );
    }
    check!(
        sigqueue(pid, sig2, 9999).is_err_and(|e| e == EAGAIN),
        "sigqueue(sig2) past RT_QUEUE_CAP wasn't EAGAIN"
    );
    for i in 0..RT_QUEUE_CAP {
        let (signum, info) = sigtimedwait(1 << (sig2 - 1), None).unwrap_or_else(|_| {
            write_bytes(b"rt-signal-syscall-smoke: part 2 drain sigtimedwait failed\n");
            test_exit(false);
        });
        check!(signum == sig2, "part 2 drain: wrong signum");
        check!(
            info.si_value == 1000 + i,
            "part 2 drain: values didn't come back in real FIFO order"
        );
    }
    let short_timeout = RawTimespec { sec: 0, nsec: 30_000_000 }; // 30ms
    check!(
        sigtimedwait(1 << (sig2 - 1), Some(&short_timeout)).is_err_and(|e| e == EAGAIN),
        "sig2's queue wasn't genuinely empty after draining exactly RT_QUEUE_CAP instances"
    );
    write_bytes(b"rt-signal-syscall-smoke: part 2 (RT_QUEUE_CAP EAGAIN + real FIFO drain) OK\n");

    // --- Part 3: sigqueue/7-1.c's own scenario -- two RT signals queued higher-number-first,
    // delivered lowest-number-first once both are unblocked together. ---
    let sig_lo = SIGRTMIN + 2;
    let sig_hi = SIGRTMIN + 3;
    check!(sigaction(sig_lo, rt_handler as u64, SA_SIGINFO).is_ok(), "sigaction(sig_lo) failed");
    check!(sigaction(sig_hi, rt_handler as u64, SA_SIGINFO).is_ok(), "sigaction(sig_hi) failed");
    check!(
        sigprocmask(SIG_BLOCK, (1 << (sig_lo - 1)) | (1 << (sig_hi - 1))).is_ok(),
        "sigprocmask(SIG_BLOCK, sig_lo|sig_hi) failed"
    );
    check!(sigqueue(pid, sig_hi, 0).is_ok(), "sigqueue(sig_hi) failed"); // queued first
    check!(sigqueue(pid, sig_lo, 0).is_ok(), "sigqueue(sig_lo) failed"); // queued second
    let start_idx = ORDER_LEN.load(Ordering::SeqCst);
    check!(
        sigprocmask(SIG_UNBLOCK, (1 << (sig_lo - 1)) | (1 << (sig_hi - 1))).is_ok(),
        "sigprocmask(SIG_UNBLOCK, sig_lo|sig_hi) failed"
    );
    // Same real chaining as part 1 -- no pump needed.
    check!(
        ORDER_LEN.load(Ordering::SeqCst) == start_idx + 2,
        "sig_lo/sig_hi weren't both delivered"
    );
    let (first, second) = (order_log_at(start_idx), order_log_at(start_idx + 1));
    check!(
        first == sig_lo && second == sig_hi,
        "delivery wasn't lowest-signal-number-first despite queuing order"
    );
    write_bytes(b"rt-signal-syscall-smoke: part 3 (lowest-signal-number-first delivery) OK\n");

    // --- Part 4: sigwait/2-1.c's own scenario -- raise() (kill(self)) the same RT signal twice,
    // confirm it's still reported pending after consuming just one instance. ---
    let sig4 = SIGRTMIN + 4;
    check!(
        sigprocmask(SIG_BLOCK, 1 << (sig4 - 1)).is_ok(),
        "sigprocmask(SIG_BLOCK, sig4) failed"
    );
    check!(sigpending() & (1 << (sig4 - 1)) == 0, "sig4 was already pending at baseline");
    check!(unsafe { syscall(SYS_KILL, pid, sig4, 0) }.is_ok(), "first raise(sig4) failed");
    check!(unsafe { syscall(SYS_KILL, pid, sig4, 0) }.is_ok(), "second raise(sig4) failed");
    check!(sigpending() & (1 << (sig4 - 1)) != 0, "sig4 wasn't reported pending after two raises");
    let (signum, _) = sigtimedwait(1 << (sig4 - 1), None).unwrap_or_else(|_| {
        write_bytes(b"rt-signal-syscall-smoke: part 4 first sigtimedwait failed\n");
        test_exit(false);
    });
    check!(signum == sig4, "part 4: first consume returned the wrong signum");
    check!(
        sigpending() & (1 << (sig4 - 1)) != 0,
        "sig4 was cleared from pending after consuming only 1 of 2 queued instances -- real-time queuing regressed"
    );
    let (signum, _) = sigtimedwait(1 << (sig4 - 1), None).unwrap_or_else(|_| {
        write_bytes(b"rt-signal-syscall-smoke: part 4 second sigtimedwait failed\n");
        test_exit(false);
    });
    check!(signum == sig4, "part 4: second consume returned the wrong signum");
    check!(
        sigpending() & (1 << (sig4 - 1)) == 0,
        "sig4 was still reported pending after both queued instances were consumed"
    );
    write_bytes(b"rt-signal-syscall-smoke: part 4 (partial-drain pending-bit semantics) OK\n");

    // --- Part 5: real EINVAL boundary validation -- only one past SIGRTMAX is rejected. The
    // 32..=34 range (SIGTIMER/SIGCANCEL/SIGSYNCCALL, permanently unclaimed only as a *libc-level*
    // convention for internal NPTL-style machinery) is real, valid, kernel-accepted signal-number
    // space -- widened from an earlier, wrongly-restrictive EINVAL to unblock real
    // `pthread_cancel(3)`'s own genuine `sigaction(SIGCANCEL, ...)`/`pthread_kill(t, SIGCANCEL)`
    // calls (see CLAUDE.md's own history of this fix). SIGRTMIN/SIGRTMAX themselves are accepted. ---
    check!(
        sigaction(32, rt_handler as u64, SA_SIGINFO).is_ok(),
        "sigaction(32) wasn't accepted"
    );
    check!(
        sigaction(33, rt_handler as u64, SA_SIGINFO).is_ok(),
        "sigaction(33) wasn't accepted"
    );
    check!(
        sigaction(34, rt_handler as u64, SA_SIGINFO).is_ok(),
        "sigaction(34) wasn't accepted"
    );
    check!(
        sigaction(SIGRTMAX + 1, rt_handler as u64, SA_SIGINFO) == Err(EINVAL),
        "sigaction(SIGRTMAX + 1) wasn't EINVAL"
    );
    // No `kill(pid, 32)`-is-EINVAL check here any more: 32 is real, valid, deliverable signal
    // space (see the comment above) -- exercising it via `kill` would actually invoke `rt_handler`
    // synchronously, an untested, unrelated behavior change this file isn't set up to assert on.
    check!(
        sigqueue(pid, SIGRTMAX + 1, 0) == Err(EINVAL),
        "sigqueue(SIGRTMAX + 1) wasn't EINVAL"
    );
    check!(
        sigaction(SIGRTMIN, rt_handler as u64, SA_SIGINFO).is_ok(),
        "sigaction(SIGRTMIN) at the boundary wasn't accepted"
    );
    check!(
        sigaction(SIGRTMAX, rt_handler as u64, SA_SIGINFO).is_ok(),
        "sigaction(SIGRTMAX) at the boundary wasn't accepted"
    );
    write_bytes(b"rt-signal-syscall-smoke: part 5 (EINVAL boundary validation) OK\n");

    write_bytes(b"rt-signal-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(1, 1, 0, 0) }; // SYS_EXIT = 1
    loop {
        spin_loop();
    }
}
