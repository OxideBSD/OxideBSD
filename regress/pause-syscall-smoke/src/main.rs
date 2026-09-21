//! Real-`SYSCALL` smoke test for `SYS_PAUSE = 529` (`sys/modules/signal`'s `handle_pause` ->
//! `sys/syscall/ffi.rs`'s `sys_pause` -> `sys/process/signals.rs`'s `do_pause`) -- item 4 of
//! `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch, and the first item in
//! that batch to need a genuine new block/wake-on-signal primitive
//! (`BlockReason::WaitingForSignal`), not just a state field.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- real per-process `ProcState`/scheduling behavior (the exact thing under test
//! here) doesn't exist outside a real syscall/scheduler round trip.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper and its own minimal `sigreturn_trampoline` (same convention
//! `regress/sa-siginfo-syscall-smoke/` already established, see that crate's own module doc
//! comment for why a hand-rolled restorer is needed with no musl to provide the real one).
//!
//! Scenario, driven entirely by `tests/pause_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. Installs a plain (non-`SA_SIGINFO`) `SIGUSR1` handler.
//! 2. `fork()`s. The **parent** immediately calls `pause()` -- with nothing pending yet, this
//!    genuinely blocks (`ProcState::Blocked(BlockReason::WaitingForSignal)`), which is what lets
//!    the **child** (freshly enqueued but not yet run) actually get scheduled next.
//! 3. The child calls `kill(parent_pid, SIGUSR1)` -- `do_kill`'s `Action::SetPending` path finds
//!    the parent genuinely `Blocked(WaitingForSignal)` and wakes it (`wake_if_paused`) -- then
//!    exits `0`.
//! 4. The scheduler resumes the parent; `do_pause`'s loop finds the now-deliverable signal and
//!    returns `EINTR`. Real POSIX ordering: the caught handler runs (hijacking the return path,
//!    same mechanism `sa-siginfo-syscall-smoke` already proved for `tkill`) *before* the parent
//!    ever observes `pause()`'s own call site "returning" -- verified by checking the handler's
//!    own flag is already set by the time control resumes there.
//! 5. The parent reaps the child via a real `wait4` and confirms a clean exit(0).
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
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `external/mit/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly
/// rather than going through a shared macro.
const SYS_SIGRETURN: u64 = 119;
const SYS_PAUSE: u64 = 529;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// pause_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGUSR1: u64 = 10;
/// Real value, matches `sys/syscall/mod.rs`'s own `EINTR`; identical on Linux/BSD/musl.
const EINTR: u64 = 4;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`'s own
/// `sigsetsize` and `wait4`'s own `rusage_ptr`. Explicitly zeroing `r10` on every 3-arg call above
/// (rather than leaving it unspecified) is the exact audit CLAUDE.md's own "any future syscall
/// that upgrades from 3 to 4 real arguments" note calls out -- `SYSCALL` doesn't clear `r10`
/// itself.
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

static HANDLER_RAN: AtomicBool = AtomicBool::new(false);

/// The plain (non-`SA_SIGINFO`) 1-argument handler under test.
extern "C" fn signal_handler(_signum: i64) {
    HANDLER_RAN.store(true, Ordering::SeqCst);
}

fn child_process(parent_pid: u64) -> ! {
    write_bytes(b"pause-syscall-smoke: child sending SIGUSR1 to parent\n");
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
    write_bytes(b"pause-syscall-smoke: starting\n");

    let pid = match unsafe { syscall(SYS_GETPID, 0, 0, 0) } {
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"pause-syscall-smoke: getpid failed\n");
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
        write_bytes(b"pause-syscall-smoke: sigaction failed\n");
        test_exit(false);
    }

    let fork_result = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid = match fork_result {
        Ok(0) => child_process(pid),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"pause-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    };

    // Genuinely blocks (nothing pending yet) -- forces the scheduler to run the freshly forked
    // child next, which is what lets it actually reach its own kill() call before this call
    // returns. See this file's own module doc comment for the full sequencing story.
    write_bytes(b"pause-syscall-smoke: parent calling pause()\n");
    let pause_result = unsafe { syscall(SYS_PAUSE, 0, 0, 0) };
    if pause_result != Err(EINTR) {
        write_bytes(b"pause-syscall-smoke: pause() didn't return EINTR\n");
        test_exit(false);
    }
    write_bytes(b"pause-syscall-smoke: pause() returned EINTR\n");

    // Real POSIX ordering: the caught handler already ran (hijacking pause()'s own return path)
    // by the time control resumes here -- see this file's own module doc comment, part 4.
    if !HANDLER_RAN.load(Ordering::SeqCst) {
        write_bytes(b"pause-syscall-smoke: handler hadn't run by the time pause() returned\n");
        test_exit(false);
    }
    write_bytes(b"pause-syscall-smoke: handler already ran before pause() returned -- OK\n");

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
        write_bytes(b"pause-syscall-smoke: wait4 didn't report the child\n");
        test_exit(false);
    }
    if status != 0 {
        write_bytes(b"pause-syscall-smoke: child's exit status wasn't a clean 0\n");
        test_exit(false);
    }
    write_bytes(b"pause-syscall-smoke: child reaped cleanly\n");

    write_bytes(b"pause-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
