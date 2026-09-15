//! Real-`SYSCALL` smoke test for `SYS_SIGTIMEDWAIT = 495`/`SYS_SIGQUEUE = 496`
//! (`modules/signal`'s `handle_sigtimedwait`/`handle_sigqueue` -> `src/syscall/ffi.rs`'s
//! `sys_sigtimedwait`/`sys_sigqueue` -> `src/process/signals.rs`'s `do_sigtimedwait`/
//! `do_sigqueue`) -- the two real, confirmed-live-caller gaps `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s
//! own "Missing, live caller confirmed" table tracked, closing both out.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- this exercises real per-process `ProcState`/scheduling behavior (a genuine new
//! block/wake primitive, `BlockReason::WaitingForSpecificSignal`) and real cross-process signal
//! delivery, the same class of bug this codebase's Test architecture section documents catching
//! only through a real syscall instruction.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper and its own minimal `sigreturn_trampoline` (same convention
//! `userland/pause-syscall-smoke/` already established).
//!
//! Scenario, driven entirely by `tests/sig_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. Installs a plain (non-`SA_SIGINFO`) handler for **both** `SIGUSR1`/`SIGUSR2`, then blocks
//!    both via `sigprocmask`. **Both steps are real POSIX requirements, not incidental setup**:
//!    a signal used with `sigwait`/`sigtimedwait` must be blocked first (POSIX explicitly leaves
//!    behavior "unspecified" otherwise -- an unblocked signal races the normal delivery path,
//!    which runs at the tail of the very syscall that made it pending, before `sigtimedwait` ever
//!    gets a chance to consume it); a handler must be installed for `do_kill`/`do_sigqueue`'s own
//!    cross-process delivery to defer as `SetPending` rather than resolving `SIGUSR1`/`SIGUSR2`'s
//!    real default disposition (`Terminate`) immediately (`do_kill`'s own documented cross-process
//!    simplification: that immediate-terminate path doesn't consult `blocked_signals` at all).
//! 2. A real self `sigqueue`/`sigtimedwait` round trip: confirms `si_code == SI_QUEUE`, real
//!    `si_pid`/`si_value`, and that the installed handler never ran.
//! 3. A real relative-timeout `sigtimedwait` on a signal that never arrives -- genuine `EAGAIN`.
//! 4. A real `fork()`-driven cross-process wake via plain `kill()`: the parent genuinely blocks in
//!    `sigtimedwait`, the child's `kill()` wakes it -- confirms `si_code == SI_USER`, real
//!    `si_pid` (the child's), `si_value == 0`.
//! 5. The same shape via `sigqueue` instead, with a real nonzero value -- confirms
//!    `si_code == SI_QUEUE` and the real value survived the round trip.
//! 6. Confirms `sigtimedwait` genuinely bypasses handler invocation one more time (a self-
//!    `sigqueue`d `SIGUSR1` consumed via `sigtimedwait` never runs the installed handler), then
//!    unblocks `SIGUSR1` and confirms a plain self-`kill(SIGUSR1)` *does* still run it immediately
//!    (real POSIX ordering, same "handler already ran before the interrupted call returns"
//!    property `pause-syscall-smoke` already proved).
//! 7. Real `EINVAL` validation: `sigqueue` against pid `0`/negative, against signal `65` (past
//!    `SIGRTMAX`), and
//!    confirms `sig == 0` (the real POSIX null-signal existence-check convention) now *succeeds*
//!    against self rather than `EINVAL`ing.
//! 8. Real `ESRCH`/`EPERM` enforcement for `kill`/`sigqueue`'s `sig == 0` path: a nonexistent pid
//!    is `ESRCH` regardless of caller privilege; a second forked child drops to uid `1`
//!    (`setuid`) and confirms both `kill(parent, 0)`/`sigqueue(parent, 0, ...)` genuinely fail
//!    `EPERM` against the still-root parent -- mirrors the Open POSIX Test Suite pilot's own
//!    `kill/2-2,3-1.c` + `sigqueue/2-1,2-2,3-1,11-1,12-1.c`.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_GETPID: u64 = 20;
const SYS_KILL: u64 = 116;
const SYS_SIGACTION: u64 = 117;
const SYS_SIGPROCMASK: u64 = 118;
/// Needed for part 8's real cross-uid kill/sigqueue `EPERM` check.
const SYS_SETUID: u64 = 162;
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `third_party/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly
/// rather than going through a shared macro.
const SYS_SIGRETURN: u64 = 119;
const SYS_SIGTIMEDWAIT: u64 = 495;
const SYS_SIGQUEUE: u64 = 496;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sig_syscall_smoke.rs` registers this one directly against a test-only handler, same convention
/// every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;

const EINVAL: u64 = 22;
const EAGAIN: u64 = 11;
/// Real value, matches `src/syscall/mod.rs`'s own `EPERM` -- identical on Linux/BSD/musl.
const EPERM: u64 = 1;
const ESRCH: u64 = 3;

/// Real `sigprocmask(2)` `how` values -- matches `src/process/signals.rs`'s own `do_sigprocmask`.
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;

/// Real Linux `si_code` values (`third_party/musl/include/bits/siginfo.h`) -- matches
/// `src/process/mod.rs`'s own `SI_USER`/`SI_QUEUE` exactly.
const SI_USER: i32 = 0;
const SI_QUEUE: i32 = -1;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`/
/// `sigtimedwait`'s own `sigsetsize` and `wait4`'s own `rusage_ptr`. Explicitly zeroing `r10` on
/// every 3-arg call above (rather than leaving it unspecified) is the exact audit CLAUDE.md's own
/// "any future syscall that upgrades from 3 to 4 real arguments" note calls out -- `SYSCALL`
/// doesn't clear `r10` itself.
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
            write_bytes(concat!("sig-syscall-smoke: FAIL -- ", $msg, "\n").as_bytes());
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

/// Matches `src/process/signals.rs`'s own `RawTimespec`-shaped `(sec, nsec)` pair every
/// timespec-taking syscall in this codebase uses.
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

static HANDLER_RAN: AtomicBool = AtomicBool::new(false);

/// The plain (non-`SA_SIGINFO`) 1-argument handler under test -- part 6 confirms `sigtimedwait`
/// never invokes this, while a plain `kill()` still does.
extern "C" fn signal_handler(_signum: i64) {
    HANDLER_RAN.store(true, Ordering::SeqCst);
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

fn sigprocmask(how: u64, mask: u64) -> Result<u64, u64> {
    unsafe { syscall4(SYS_SIGPROCMASK, how, &mask as *const u64 as u64, 0, 8) }
}

fn wait4(pid: u64) -> Result<(u64, i32), u64> {
    let mut status: i32 = -1;
    let ret = unsafe { syscall4(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0, 0) }?;
    Ok((ret, status))
}

/// Runs entirely inside the forked child for parts 4/5 -- see those parts' own inline comments in
/// `_start` for exactly what each sends and why.
fn child_process(parent_pid: u64) -> ! {
    write_bytes(b"sig-syscall-smoke: child sending SIGUSR1 via kill\n");
    check!(
        unsafe { syscall(SYS_KILL, parent_pid, SIGUSR1, 0) }.is_ok(),
        "child's plain kill(SIGUSR1) failed"
    );

    write_bytes(b"sig-syscall-smoke: child sending SIGUSR2 via sigqueue\n");
    check!(
        sigqueue(parent_pid, SIGUSR2, 0xdead_beef_1234).is_ok(),
        "child's sigqueue(SIGUSR2) failed"
    );

    unsafe {
        let _ = syscall(SYS_EXIT, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Runs entirely inside a second forked child, for part 8's own real cross-uid `EPERM` scenario --
/// drops from root to uid 1 (`setuid`), then confirms both `kill(parent, 0)` and
/// `sigqueue(parent, 0, ...)` genuinely fail `EPERM` against the still-root parent (mirrors the
/// Open POSIX Test Suite pilot's own `kill/2-2,3-1.c`/`sigqueue/3-1,12-1.c` scenario). Reports
/// pass/fail via its own real exit status, checked by `wait4` back in `_start`.
fn permission_child(parent_pid: u64) -> ! {
    write_bytes(b"sig-syscall-smoke: permission child dropping to uid 1\n");
    let ok = unsafe { syscall(SYS_SETUID, 1, 0, 0) }.is_ok()
        && unsafe { syscall(SYS_KILL, parent_pid, 0, 0) } == Err(EPERM)
        && sigqueue(parent_pid, 0, 0) == Err(EPERM);
    if !ok {
        write_bytes(b"sig-syscall-smoke: permission child's cross-uid EPERM checks failed\n");
    }
    unsafe {
        let _ = syscall(SYS_EXIT, if ok { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sig-syscall-smoke: starting\n");

    let pid = match unsafe { syscall(SYS_GETPID, 0, 0, 0) } {
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"sig-syscall-smoke: getpid failed\n");
            test_exit(false);
        }
    };

    // --- Part 1: install a plain handler for both SIGUSR1/SIGUSR2, then block both ---
    // See this file's own module doc comment for why both steps are real POSIX requirements, not
    // incidental setup -- an unblocked and/or handler-less signal races (or short-circuits) the
    // normal delivery path before sigtimedwait ever gets a chance to consume it.
    let act = RawSigAction {
        handler: signal_handler as u64,
        flags: 0,
        restorer: sigreturn_trampoline as u64,
        mask: 0,
    };
    check!(
        unsafe { syscall4(SYS_SIGACTION, SIGUSR1, &act as *const RawSigAction as u64, 0, 8) }
            .is_ok(),
        "sigaction(SIGUSR1) failed"
    );
    check!(
        unsafe { syscall4(SYS_SIGACTION, SIGUSR2, &act as *const RawSigAction as u64, 0, 8) }
            .is_ok(),
        "sigaction(SIGUSR2) failed"
    );
    check!(
        sigprocmask(SIG_BLOCK, (1 << (SIGUSR1 - 1)) | (1 << (SIGUSR2 - 1))).is_ok(),
        "sigprocmask(SIG_BLOCK) failed"
    );
    write_bytes(b"sig-syscall-smoke: part 1 (sigaction x2, sigprocmask block) OK\n");

    // --- Part 2: real self sigqueue/sigtimedwait round trip ---
    let value = 0x5a5a_1234_5678u64;
    check!(sigqueue(pid, SIGUSR2, value).is_ok(), "self sigqueue(SIGUSR2) failed");
    let (signum, info) = sigtimedwait(1 << (SIGUSR2 - 1), None).unwrap_or_else(|_| {
        write_bytes(b"sig-syscall-smoke: self sigtimedwait failed\n");
        test_exit(false);
    });
    check!(signum == SIGUSR2, "self round trip: wrong signum returned");
    check!(info.si_signo as u64 == SIGUSR2, "self round trip: wrong si_signo");
    check!(info.si_code == SI_QUEUE, "self round trip: si_code wasn't SI_QUEUE");
    check!(info.si_pid as u64 == pid, "self round trip: si_pid wasn't our own pid");
    check!(info.si_value == value, "self round trip: si_value didn't survive");
    check!(!HANDLER_RAN.load(Ordering::SeqCst), "self round trip ran the installed handler");
    write_bytes(b"sig-syscall-smoke: part 2 (self sigqueue/sigtimedwait) OK\n");

    // --- Part 3: real relative-timeout EAGAIN ---
    let short_timeout = RawTimespec { sec: 0, nsec: 30_000_000 }; // 30ms, well under a second
    check!(
        sigtimedwait(1 << (SIGUSR1 - 1), Some(&short_timeout)).is_err_and(|e| e == EAGAIN),
        "a real sigtimedwait timeout didn't expire with EAGAIN"
    );
    write_bytes(b"sig-syscall-smoke: part 3 (sigtimedwait EAGAIN) OK\n");

    // --- Parts 4 & 5: real fork()-driven cross-process wakes (SI_USER via kill, SI_QUEUE via
    // sigqueue with a real value) ---
    let fork_result = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid = match fork_result {
        Ok(0) => child_process(pid),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"sig-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    };

    // Genuinely blocks (nothing pending yet) -- hands the CPU to the freshly forked child, which
    // sends both signals before exiting.
    write_bytes(b"sig-syscall-smoke: parent blocking in sigtimedwait for SIGUSR1\n");
    let (signum, info) = sigtimedwait(1 << (SIGUSR1 - 1), None).unwrap_or_else(|_| {
        write_bytes(b"sig-syscall-smoke: parent's blocking sigtimedwait(SIGUSR1) failed\n");
        test_exit(false);
    });
    check!(signum == SIGUSR1, "cross-process kill: wrong signum returned");
    check!(info.si_code == SI_USER, "cross-process kill: si_code wasn't SI_USER");
    check!(info.si_pid == child_pid as i32, "cross-process kill: si_pid wasn't the child's");
    check!(info.si_value == 0, "cross-process kill: si_value wasn't 0");
    write_bytes(b"sig-syscall-smoke: part 4 (cross-process kill via sigtimedwait) OK\n");

    // The child already sent this one too (before exiting) -- may already be pending, may still
    // need a second real block/wake if scheduling landed differently; either way this exercises
    // the real condition, not a timing assumption.
    let (signum, info) = sigtimedwait(1 << (SIGUSR2 - 1), None).unwrap_or_else(|_| {
        write_bytes(b"sig-syscall-smoke: parent's sigtimedwait(SIGUSR2) failed\n");
        test_exit(false);
    });
    check!(signum == SIGUSR2, "cross-process sigqueue: wrong signum returned");
    check!(info.si_code == SI_QUEUE, "cross-process sigqueue: si_code wasn't SI_QUEUE");
    check!(info.si_pid == child_pid as i32, "cross-process sigqueue: si_pid wasn't the child's");
    check!(
        info.si_value == 0xdead_beef_1234,
        "cross-process sigqueue: si_value didn't survive the round trip"
    );
    check!(
        !HANDLER_RAN.load(Ordering::SeqCst),
        "a cross-process signal ran the installed handler instead of being consumed by sigtimedwait"
    );
    write_bytes(b"sig-syscall-smoke: part 5 (cross-process sigqueue, real value) OK\n");

    let (reaped_pid, status) = wait4(child_pid).unwrap_or_else(|_| {
        write_bytes(b"sig-syscall-smoke: wait4 failed\n");
        test_exit(false);
    });
    check!(reaped_pid == child_pid && status == 0, "wait4 didn't report a clean child exit");

    // --- Part 6: sigtimedwait bypasses the installed handler entirely; a plain kill() doesn't ---
    check!(!HANDLER_RAN.load(Ordering::SeqCst), "handler ran before it should have at all");
    check!(sigqueue(pid, SIGUSR1, 0).is_ok(), "self sigqueue(SIGUSR1) for part 6 failed");
    let (signum, _) = sigtimedwait(1 << (SIGUSR1 - 1), None).unwrap_or_else(|_| {
        write_bytes(b"sig-syscall-smoke: part 6 sigtimedwait failed\n");
        test_exit(false);
    });
    check!(signum == SIGUSR1, "part 6: wrong signum consumed");
    check!(
        !HANDLER_RAN.load(Ordering::SeqCst),
        "sigtimedwait invoked the installed handler -- real POSIX semantics never do this"
    );
    // Unblocked now, specifically so the plain kill() below actually invokes the handler
    // immediately (real delivery, not sigtimedwait's own bypass) instead of just sitting pending.
    check!(
        sigprocmask(SIG_UNBLOCK, 1 << (SIGUSR1 - 1)).is_ok(),
        "sigprocmask(SIG_UNBLOCK) failed"
    );
    check!(
        unsafe { syscall(SYS_KILL, pid, SIGUSR1, 0) }.is_ok(),
        "self plain kill(SIGUSR1) for part 6 failed"
    );
    check!(
        HANDLER_RAN.load(Ordering::SeqCst),
        "a plain kill() no longer invokes the installed handler"
    );
    write_bytes(b"sig-syscall-smoke: part 6 (sigtimedwait bypasses handler, kill doesn't) OK\n");

    // --- Part 7: real EINVAL validation ---
    check!(sigqueue(0, SIGUSR1, 0) == Err(EINVAL), "sigqueue against pid 0 wasn't EINVAL");
    check!(
        unsafe { syscall(SYS_SIGQUEUE, u64::MAX, SIGUSR1, 0) } == Err(EINVAL),
        "sigqueue against a negative pid wasn't EINVAL"
    );
    // sig=0 is the real POSIX null-signal existence(+permission)-only check (same convention
    // kill(pid, 0) already has) -- a self-targeted one always succeeds, matches sigqueue/2-1.c's
    // own assertion in the Open POSIX Test Suite pilot.
    check!(sigqueue(pid, 0, 0) == Ok(0), "self sigqueue with sig=0 didn't succeed");
    // sig=32 used to be the boundary case here, but a later session's real fix for real
    // pthread_cancel(3)/SIGCANCEL=33 support deliberately widened the valid range to 1..=34 (see
    // CLAUDE.md's "times/SIGCANCEL/shared sigactions fixed" section) -- 32 is genuinely valid now,
    // and self-sigqueue'ing it here (never blocked, no handler installed) resolved its real
    // default disposition (Terminate) immediately, silently killing this pid-1 test process mid
    // part 7 with no PASS/FAIL ever reported. The real invalid boundary is now one past
    // SIGRTMAX (64), not 32.
    check!(sigqueue(pid, 65, 0) == Err(EINVAL), "sigqueue with sig=65 (past SIGRTMAX) wasn't EINVAL");
    write_bytes(b"sig-syscall-smoke: part 7 (EINVAL validation) OK\n");

    // --- Part 8: real ESRCH/EPERM enforcement (kill/sigqueue's sig=0 existence+permission path)
    // --- mirrors kill/2-2,3-1.c and sigqueue/2-1,2-2,3-1,11-1,12-1.c in the Open POSIX Test Suite
    // pilot. A nonexistent pid is ESRCH regardless of caller privilege; a real permission mismatch
    // (checked from inside a forked, uid-dropped child so this process's own root identity stays
    // intact for a hypothetical later part) is EPERM.
    check!(
        unsafe { syscall(SYS_KILL, 999999, 0, 0) } == Err(ESRCH),
        "kill against a nonexistent pid wasn't ESRCH"
    );
    check!(
        sigqueue(999999, 0, 0) == Err(ESRCH),
        "sigqueue against a nonexistent pid wasn't ESRCH"
    );
    let fork_result2 = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child2_pid = match fork_result2 {
        Ok(0) => permission_child(pid),
        Ok(child2_pid) => child2_pid,
        Err(_) => {
            write_bytes(b"sig-syscall-smoke: second fork failed\n");
            test_exit(false);
        }
    };
    let (reaped_pid2, status2) = wait4(child2_pid).unwrap_or_else(|_| {
        write_bytes(b"sig-syscall-smoke: part 8 wait4 failed\n");
        test_exit(false);
    });
    check!(
        reaped_pid2 == child2_pid && status2 == 0,
        "permission child's cross-uid EPERM checks didn't all pass"
    );
    write_bytes(b"sig-syscall-smoke: part 8 (ESRCH/EPERM enforcement) OK\n");

    write_bytes(b"sig-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
