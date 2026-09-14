//! Real-`SYSCALL` smoke test for `SA_SIGINFO` handler invocation (`src/syscall/mod.rs`'s
//! `deliver_pending_signal`, `RawSiginfo`/`RawUcontext`/`RawMcontext`) and for `SYS_TKILL = 200`/
//! `SYS_SIGPENDING = 494` (both landed the same pass, see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own
//! "Implemented this session" section).
//!
//! No existing test exercised a real handler-invocation round trip at all before this one --
//! `Process::signal_stack`'s own doc comment used to note only `kill.elf $$`-style
//! default-terminate delivery had ever been boot-verified. This one installs a real `SA_SIGINFO`
//! handler for `SIGUSR1`, `tkill`s itself, and checks (from inside the handler, into global
//! statics -- safe on this single-threaded, non-preemptive kernel) that `signum`/`siginfo_t`/
//! `ucontext_t` all arrived correctly shaped and populated, then checks (after the `tkill` syscall
//! itself returns, i.e. after a real `sigreturn` round trip actually resumed the interrupted
//! instruction stream correctly) that `sigpending()` reports the signal as no longer pending.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- see `userland/itimer-syscall-smoke/src/main.rs`'s
//! own module doc comment for why this codebase specifically distrusts plain-Rust-function tests
//! for anything depending on real per-process state (`Process::sigactions`/`pending_signals`/
//! `blocked_signals` here, all resolved via `scheduler::current_pid()`).
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper (same convention every other `*-syscall-smoke` crate uses), so the real
//! `restorer` trampoline musl-linked binaries get for free (`__restore_rt`,
//! `third_party/musl/src/signal/x86_64/restore.s`) doesn't exist here -- `sigreturn_trampoline`
//! below is this crate's own minimal equivalent, the same two real instructions
//! (`mov rax, 119; syscall`) that file hardcodes.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, Ordering};

const SYS_EXIT: u64 = 1;
const SYS_WRITE: u64 = 4;
const SYS_GETPID: u64 = 20;
const SYS_SIGACTION: u64 = 117;
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `third_party/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly
/// rather than going through a shared macro.
const SYS_SIGRETURN: u64 = 119;
/// Real `rt_sigpending`'s own wire slot, redirected here off its earlier accidental `SYS_STAT`
/// collision -- see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own collision-sweep table.
const SYS_SIGPENDING: u64 = 494;
/// Real, unclaimed Linux `__NR_tkill` -- see `src/syscall/ffi.rs`'s `sys_tkill` doc comment.
const SYS_TKILL: u64 = 200;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sa_siginfo_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGUSR1: u64 = 10;
/// Real Linux/x86_64 value -- matches `src/process/mod.rs`'s own `SA_SIGINFO`.
const SA_SIGINFO: u64 = 0x00000004;
/// Real Linux `SI_USER` -- matches `src/syscall/mod.rs`'s own `SI_USER`.
const SI_USER: i32 = 0;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`'s own
/// `sigsetsize`.
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

/// Matches `src/process/signals.rs`'s `do_sigaction`'s own `RawSigAction` wire format exactly.
#[repr(C)]
struct RawSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// Matches `src/syscall/mod.rs`'s own `RawSiginfo` byte-for-byte -- see that struct's own doc
/// comment for the real field layout this mirrors.
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

const _: () = assert!(core::mem::size_of::<RawSiginfo>() == 128);

/// Matches `src/syscall/mod.rs`'s own `RawUcontext`/`RawMcontext` byte-for-byte.
#[repr(C)]
struct RawMcontext {
    gregs: [i64; 23],
    fpregs: u64,
    reserved1: [u64; 8],
}

#[repr(C)]
struct RawStackT {
    ss_sp: u64,
    ss_flags: i32,
    _pad: u32,
    ss_size: u64,
}

#[repr(C)]
struct RawUcontext {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: RawStackT,
    uc_mcontext: RawMcontext,
    uc_sigmask: [u64; 16],
    fpregs_mem: [u64; 64],
}

const _: () = assert!(core::mem::size_of::<RawUcontext>() == 936);

/// This crate's own minimal `__restore_rt` equivalent -- see this file's own module doc comment
/// for why a hand-rolled one is needed here (no musl to provide the real one). Never called
/// directly from Rust; its address is installed as `sigaction`'s own `restorer` field, and the
/// kernel places that address where the handler's own `ret` naturally lands (see
/// `deliver_pending_signal`'s own doc comment in `src/syscall/mod.rs`).
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
static HANDLER_SIGNUM: AtomicI64 = AtomicI64::new(-1);
static HANDLER_SI_SIGNO: AtomicI32 = AtomicI32::new(-1);
static HANDLER_SI_CODE: AtomicI32 = AtomicI32::new(-1);
static HANDLER_UCONTEXT_NONNULL: AtomicBool = AtomicBool::new(false);
static HANDLER_UC_SIGMASK0: AtomicU64 = AtomicU64::new(u64::MAX);

/// The real `SA_SIGINFO` handler under test -- a genuine 3-argument `extern "C" fn`, invoked
/// exactly the way a real musl-linked program's own signal handler would be. Records everything
/// into global statics rather than returning a value, since this is invoked by the kernel jumping
/// straight into it (via the constructed stack frame), not called from this crate's own Rust code.
extern "C" fn signal_handler(signum: i64, siginfo: *const RawSiginfo, ucontext: *const RawUcontext) {
    HANDLER_SIGNUM.store(signum, Ordering::SeqCst);
    if !siginfo.is_null() {
        // SAFETY: the kernel promises this points at a real, fully-initialized RawSiginfo for the
        // duration of the handler call.
        let si = unsafe { &*siginfo };
        HANDLER_SI_SIGNO.store(si.si_signo, Ordering::SeqCst);
        HANDLER_SI_CODE.store(si.si_code, Ordering::SeqCst);
    }
    HANDLER_UCONTEXT_NONNULL.store(!ucontext.is_null(), Ordering::SeqCst);
    if !ucontext.is_null() {
        // SAFETY: same promise as siginfo above.
        let uc = unsafe { &*ucontext };
        HANDLER_UC_SIGMASK0.store(uc.uc_sigmask[0], Ordering::SeqCst);
    }
    HANDLER_RAN.store(true, Ordering::SeqCst);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sa-siginfo-syscall-smoke: starting\n");

    let pid = match unsafe { syscall(SYS_GETPID, 0, 0, 0) } {
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"sa-siginfo-syscall-smoke: getpid failed\n");
            test_exit(false);
        }
    };

    let act = RawSigAction {
        handler: signal_handler as u64,
        flags: SA_SIGINFO,
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
        write_bytes(b"sa-siginfo-syscall-smoke: sigaction failed\n");
        test_exit(false);
    }

    // If sigreturn ever restores the wrong frame (a real risk this exercises directly, not just
    // the handler's own argument shape), this syscall either never returns here at all or returns
    // something other than Ok(0) -- both are real failures, not just "the handler looked wrong".
    if unsafe { syscall(SYS_TKILL, pid, SIGUSR1, 0) } != Ok(0) {
        write_bytes(b"sa-siginfo-syscall-smoke: tkill didn't return cleanly\n");
        test_exit(false);
    }

    if !HANDLER_RAN.load(Ordering::SeqCst) {
        write_bytes(b"sa-siginfo-syscall-smoke: handler never ran\n");
        test_exit(false);
    }
    if HANDLER_SIGNUM.load(Ordering::SeqCst) != SIGUSR1 as i64 {
        write_bytes(b"sa-siginfo-syscall-smoke: wrong signum in rdi\n");
        test_exit(false);
    }
    if HANDLER_SI_SIGNO.load(Ordering::SeqCst) != SIGUSR1 as i32 {
        write_bytes(b"sa-siginfo-syscall-smoke: siginfo->si_signo wrong\n");
        test_exit(false);
    }
    if HANDLER_SI_CODE.load(Ordering::SeqCst) != SI_USER {
        write_bytes(b"sa-siginfo-syscall-smoke: siginfo->si_code != SI_USER\n");
        test_exit(false);
    }
    if !HANDLER_UCONTEXT_NONNULL.load(Ordering::SeqCst) {
        write_bytes(b"sa-siginfo-syscall-smoke: ucontext arg was NULL\n");
        test_exit(false);
    }
    if HANDLER_UC_SIGMASK0.load(Ordering::SeqCst) != 0 {
        write_bytes(b"sa-siginfo-syscall-smoke: uc_sigmask wasn't empty pre-handler\n");
        test_exit(false);
    }

    // Real sigreturn already resumed execution correctly (proven above by tkill returning Ok(0)
    // at all) -- this additionally confirms the signal was actually drained from pending_signals,
    // exercising SYS_SIGPENDING for real too.
    let mut pending: u64 = u64::MAX;
    if unsafe { syscall(SYS_SIGPENDING, &mut pending as *mut u64 as u64, 8, 0) }.is_err() {
        write_bytes(b"sa-siginfo-syscall-smoke: sigpending failed\n");
        test_exit(false);
    }
    if pending & (1 << (SIGUSR1 - 1)) != 0 {
        write_bytes(b"sa-siginfo-syscall-smoke: SIGUSR1 still pending after delivery\n");
        test_exit(false);
    }

    write_bytes(b"sa-siginfo-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
