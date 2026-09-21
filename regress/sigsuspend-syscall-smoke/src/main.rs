//! Real-`SYSCALL` smoke test for `SYS_SIGSUSPEND = 530` (`sys/modules/signal`'s `handle_sigsuspend` ->
//! `sys/syscall/ffi.rs`'s `sys_sigsuspend` -> `sys/process/signals.rs`'s `do_sigsuspend`) -- item 5
//! of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch, and the second item in
//! that batch (after `pause`) to exercise the `BlockReason::WaitingForSignal` primitive, this time
//! with a real temporary mask swap around it.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- same reasoning `pause-syscall-smoke` already documents.
//!
//! **No musl involved** -- bare `#![no_std]` binary, hand-rolled `syscall()` helper and its own
//! minimal `sigreturn_trampoline`, same convention `pause-syscall-smoke`/`sa-siginfo-syscall-smoke`
//! already established.
//!
//! Scenario, driven entirely by `tests/sigsuspend_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. Installs a plain (non-`SA_SIGINFO`) `SIGUSR1` handler, then blocks `SIGUSR1` via
//!    `sigprocmask(SIG_BLOCK, ...)` -- the canonical `sigsuspend` setup: a signal that's normally
//!    blocked, temporarily unblocked just for the wait.
//! 2. `fork()`s. The **parent** immediately calls `sigsuspend(&empty_mask)` -- an empty mask
//!    temporarily unblocks *everything*, including `SIGUSR1`; with nothing pending yet, this
//!    genuinely blocks, letting the **child** run next.
//! 3. The child calls `kill(parent_pid, SIGUSR1)` (blocked under the parent's *original* mask, but
//!    not under `sigsuspend`'s temporary one) then exits `0`.
//! 4. The scheduler resumes the parent; `do_sigsuspend`'s loop finds the now-deliverable signal and
//!    returns `EINTR`. Real POSIX ordering (same mechanism `pause-syscall-smoke` already proved):
//!    the caught handler runs *before* the parent ever observes `sigsuspend()`'s own call site
//!    "returning" -- verified by checking the handler's own counter is already `1` by the time
//!    control resumes there.
//! 5. Confirms the mask was restored to the *original* (still-blocking-`SIGUSR1`) mask, not left at
//!    the temporary (empty) one `sigsuspend` swapped in -- via a `sigprocmask(SIG_BLOCK, NULL, ...)`
//!    readback. This is the specific correctness property `do_sigsuspend`'s own doc comment exists
//!    to get right (the mask restore has to be deferred to `sigreturn`, not done eagerly).
//! 6. Proves the restored block is *actually enforced*, not just reported: a self-`kill(pid,
//!    SIGUSR1)` while blocked again sets `SIGUSR1` pending (confirmed via `sigpending()`) without
//!    invoking the handler a second time; unblocking it and issuing one more syscall then does
//!    deliver it (handler count becomes `2`) via the normal `deliver_pending_signal` tail.
//! 7. Reaps the child via a real `wait4` and confirms a clean `exit(0)`.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_GETPID: u64 = 20;
const SYS_KILL: u64 = 116;
const SYS_SIGACTION: u64 = 117;
const SYS_SIGPROCMASK: u64 = 118;
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `external/mit/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly
/// rather than going through a shared macro.
const SYS_SIGRETURN: u64 = 119;
/// Real, unremapped Linux value redirected here off its previous accidental collision with
/// `SYS_STAT = 127` -- see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own collision table.
const SYS_SIGPENDING: u64 = 494;
const SYS_SIGSUSPEND: u64 = 530;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sigsuspend_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGUSR1: u64 = 10;
const SIGUSR1_BIT: u64 = 1 << (SIGUSR1 - 1);
/// Real value, matches `sys/syscall/mod.rs`'s own `EINTR`; identical on Linux/BSD/musl.
const EINTR: u64 = 4;
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`/`sigprocmask`/
/// `sigpending`'s own `sigsetsize` and `wait4`'s own `rusage_ptr`. Explicitly zeroing `r10` on
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

/// Matches `sys/process/signals.rs`'s `do_sigaction`'s own `RawSigAction` wire format exactly.
#[repr(C)]
struct RawSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// This crate's own minimal `__restore_rt` equivalent -- see this file's own module doc comment
/// for why a hand-rolled one is needed here (no musl to provide the real one). Never called
/// directly from Rust; its address is installed as `sigaction`'s own `restorer` field.
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

static HANDLER_RAN_COUNT: AtomicU32 = AtomicU32::new(0);

/// The plain (non-`SA_SIGINFO`) 1-argument handler under test.
extern "C" fn signal_handler(_signum: i64) {
    HANDLER_RAN_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn child_process(parent_pid: u64) -> ! {
    write_bytes(b"sigsuspend-syscall-smoke: child sending SIGUSR1 to parent\n");
    let _ = unsafe { syscall(SYS_KILL, parent_pid, SIGUSR1, 0) };
    unsafe {
        let _ = syscall(SYS_EXIT, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sigsuspend-syscall-smoke: starting\n");

    let pid = match unsafe { syscall(SYS_GETPID, 0, 0, 0) } {
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"sigsuspend-syscall-smoke: getpid failed\n");
            test_exit(false);
        }
    };

    let act = RawSigAction {
        handler: signal_handler as u64,
        flags: 0,
        restorer: sigreturn_trampoline as u64,
        mask: 0,
    };
    if unsafe {
        syscall4(
            SYS_SIGACTION,
            SIGUSR1,
            &act as *const RawSigAction as u64,
            0,
            8,
        )
    }
    .is_err()
    {
        write_bytes(b"sigsuspend-syscall-smoke: sigaction failed\n");
        test_exit(false);
    }

    // The canonical sigsuspend setup: SIGUSR1 is normally blocked, only temporarily unblocked for
    // the wait itself.
    let block_set: u64 = SIGUSR1_BIT;
    if unsafe {
        syscall4(
            SYS_SIGPROCMASK,
            SIG_BLOCK,
            &block_set as *const u64 as u64,
            0,
            8,
        )
    }
    .is_err()
    {
        write_bytes(b"sigsuspend-syscall-smoke: sigprocmask(SIG_BLOCK) failed\n");
        test_exit(false);
    }

    let fork_result = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid = match fork_result {
        Ok(0) => child_process(pid),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"sigsuspend-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    };

    // Genuinely blocks (nothing pending yet, and the empty temporary mask below unblocks
    // everything) -- forces the scheduler to run the freshly forked child next, same sequencing
    // story `pause-syscall-smoke` already documents.
    write_bytes(b"sigsuspend-syscall-smoke: parent calling sigsuspend(empty mask)\n");
    let empty_mask: u64 = 0;
    let sigsuspend_result =
        unsafe { syscall4(SYS_SIGSUSPEND, &empty_mask as *const u64 as u64, 8, 0, 0) };
    if sigsuspend_result != Err(EINTR) {
        write_bytes(b"sigsuspend-syscall-smoke: sigsuspend() didn't return EINTR\n");
        test_exit(false);
    }
    write_bytes(b"sigsuspend-syscall-smoke: sigsuspend() returned EINTR\n");

    // Real POSIX ordering: the caught handler already ran (hijacking sigsuspend()'s own return
    // path) by the time control resumes here.
    if HANDLER_RAN_COUNT.load(Ordering::SeqCst) != 1 {
        write_bytes(b"sigsuspend-syscall-smoke: handler hadn't run exactly once by return\n");
        test_exit(false);
    }
    write_bytes(b"sigsuspend-syscall-smoke: handler already ran before sigsuspend() returned -- OK\n");

    // The specific correctness property under test: the mask must be back to the *original*
    // (still-blocking-SIGUSR1) mask, not left at sigsuspend's own temporary (empty) one.
    let mut restored_mask: u64 = 0;
    if unsafe {
        syscall4(
            SYS_SIGPROCMASK,
            SIG_BLOCK,
            0,
            &mut restored_mask as *mut u64 as u64,
            8,
        )
    }
    .is_err()
    {
        write_bytes(b"sigsuspend-syscall-smoke: sigprocmask readback failed\n");
        test_exit(false);
    }
    if restored_mask & SIGUSR1_BIT == 0 {
        write_bytes(b"sigsuspend-syscall-smoke: mask wasn't restored -- SIGUSR1 not blocked again\n");
        test_exit(false);
    }
    write_bytes(b"sigsuspend-syscall-smoke: original mask correctly restored -- OK\n");

    // Prove the restored block is actually enforced, not just reported: a self-signal while
    // blocked again must not invoke the handler a second time yet.
    if unsafe { syscall(SYS_KILL, pid, SIGUSR1, 0) }.is_err() {
        write_bytes(b"sigsuspend-syscall-smoke: self kill(SIGUSR1) failed\n");
        test_exit(false);
    }
    let mut pending: u64 = 0;
    if unsafe {
        syscall4(
            SYS_SIGPENDING,
            &mut pending as *mut u64 as u64,
            8,
            0,
            0,
        )
    }
    .is_err()
    {
        write_bytes(b"sigsuspend-syscall-smoke: sigpending failed\n");
        test_exit(false);
    }
    if pending & SIGUSR1_BIT == 0 || HANDLER_RAN_COUNT.load(Ordering::SeqCst) != 1 {
        write_bytes(b"sigsuspend-syscall-smoke: blocked self-signal wasn't held pending\n");
        test_exit(false);
    }
    write_bytes(b"sigsuspend-syscall-smoke: blocked self-signal correctly held pending -- OK\n");

    // Unblocking now must let the very next syscall's own tail deliver it for real.
    if unsafe {
        syscall4(
            SYS_SIGPROCMASK,
            SIG_UNBLOCK,
            &block_set as *const u64 as u64,
            0,
            8,
        )
    }
    .is_err()
    {
        write_bytes(b"sigsuspend-syscall-smoke: sigprocmask(SIG_UNBLOCK) failed\n");
        test_exit(false);
    }
    let _ = unsafe { syscall(SYS_GETPID, 0, 0, 0) }; // any ordinary syscall's own tail delivers it
    if HANDLER_RAN_COUNT.load(Ordering::SeqCst) != 2 {
        write_bytes(b"sigsuspend-syscall-smoke: unblocked signal wasn't delivered\n");
        test_exit(false);
    }
    write_bytes(b"sigsuspend-syscall-smoke: unblocked signal correctly delivered -- OK\n");

    let mut status: i32 = -1;
    if unsafe {
        syscall4(
            SYS_WAIT4,
            child_pid,
            &mut status as *mut i32 as u64,
            0,
            0,
        )
    } != Ok(child_pid)
    {
        write_bytes(b"sigsuspend-syscall-smoke: wait4 didn't report the child\n");
        test_exit(false);
    }
    if status != 0 {
        write_bytes(b"sigsuspend-syscall-smoke: child's exit status wasn't a clean 0\n");
        test_exit(false);
    }
    write_bytes(b"sigsuspend-syscall-smoke: child reaped cleanly\n");

    write_bytes(b"sigsuspend-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
