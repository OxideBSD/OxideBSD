//! Real-`SYSCALL` smoke test for `SYS_CLONE = 555` (`process::lifecycle::do_clone`) -- "Real
//! threading" phases 4+5's own finish-line-adjacent verification (before the real
//! `pthread_create`/`pthread_join` crate, `regress/pthread-syscall-smoke/`, which drives the same
//! underlying kernel primitive through genuine, unmodified musl thread-library code instead).
//!
//! A raw `syscall(SYS_CLONE, flags, newsp, ptid, tls)` call, deliberately bypassing musl's own
//! `__clone` asm/`pthread_create` entirely -- same "prove the kernel primitive first" spirit every
//! other `SYS_TEST_*`-scripted smoke test in this codebase already uses. **No musl involved** --
//! this crate is a bare `#![no_std]` binary with its own hand-rolled `syscall()` helpers, the same
//! convention `regress/pause-syscall-smoke/` and friends already establish.
//!
//! **Why the child needs a real asm trampoline, not just "keep running the same compiled code
//! after the syscall returns"**: unlike `fork()`, whose child resumes on a byte-for-byte copy of
//! the parent's own stack (same addresses, same values -- `AddressSpace::fork`'s real eager copy),
//! `clone()`'s child resumes with `RSP` set to the real, separate `newsp` argument
//! (`do_clone`/`context_switch::seed_clone_frame`). Any code compiled to reference a stack slot
//! relative to `_start()`'s own prologue (established against the *parent's* original stack) would
//! read garbage the instant the child's `RSP` pointed somewhere else. `clone_thread` below fixes
//! this exactly the way real `clone.s` does: the syscall's own inline asm branches the child path
//! directly into a real `call` instruction (`call r9`, `r9` = the address of `child_main`,
//! preserved across the syscall the same way musl's own asm preserves its function-pointer
//! argument) -- a genuine call boundary establishes a fresh, well-defined frame on the new stack,
//! so everything `child_main` does afterward is perfectly ordinary compiled code with no hazard.
//!
//! Scenario, driven entirely by `tests/clone_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. Records the caller's own pid (`PARENT_PID`) and clones with the exact flag combination real
//!    `pthread_create` issues, a real caller-provided stack (`CHILD_STACK`), and a real `ptid`
//!    pointer (`PTID`).
//! 2. The child (`child_main`, entered via the real call-boundary trampoline above) checks that
//!    its own `getpid()` reports the *parent's* pid -- real `CLONE_THREAD` tgid-sharing proof --
//!    writes a known sentinel into `SHARED_VALUE` -- real `CLONE_VM` proof, since both "threads"
//!    share one address space -- then signals completion via a real futex word (`JOIN_FUTEX`,
//!    the exact primitive real `pthread_join` itself is built on) and exits.
//! 3. The parent `FUTEX_WAIT`s on `JOIN_FUTEX` (the same real join mechanism `pthread_join` uses,
//!    proven directly rather than through musl), then checks `PTID` was written with the real
//!    child pid (`CLONE_PARENT_SETTID` proof), `SHARED_VALUE` holds the child's sentinel (`CLONE_VM`
//!    proof), and the child's own `getpid()` check passed (`CLONE_THREAD` proof).
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const SYS_EXIT: u64 = 1;
const SYS_WRITE: u64 = 4;
const SYS_GETPID: u64 = 20;
const SYS_FUTEX: u64 = 202;
const SYS_CLONE: u64 = 555;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// clone_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

/// Real `clone(2)` flag bit values (`external/mit/musl/include/sched.h`) -- must match
/// `process::lifecycle::do_clone`'s own `PTHREAD_CLONE_FLAGS` exactly, since that function only
/// ever accepts this precise combination.
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_DETACHED: u64 = 0x0040_0000;
const PTHREAD_CLONE_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED;

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;

const SHARED_SENTINEL: u64 = 0xC10E_5EED_0000_0001;

const CHILD_STACK_SIZE: usize = 65536;

#[repr(align(16))]
struct AlignedStack([u8; CHILD_STACK_SIZE]);

/// `static mut`, not `static` -- this memory is used as a real, writable stack by the cloned
/// thread (every `push`/`call` on it is a hardware write no Rust-level reference ever performs),
/// same "written only by hardware-adjacent code, never through a Rust-visible write" reasoning
/// `sys/cpu/gdt.rs`'s own RSP0/IST stacks and `sys/process/scheduler.rs`'s `BOOT_SCRATCH_RSP`
/// already document -- a plain immutable `static` with an all-zero initializer gets placed in
/// read-only memory (confirmed live: the very first `push` onto it, `call r9`'s own return
/// address, faulted `PROTECTION_VIOLATION | CAUSED_BY_WRITE`). Only ever accessed via `&raw
/// const`/`&raw mut` (its address, never a Rust reference), so this is sound.
static mut CHILD_STACK: AlignedStack = AlignedStack([0; CHILD_STACK_SIZE]);
static PARENT_PID: AtomicU64 = AtomicU64::new(0);
static PTID: AtomicU64 = AtomicU64::new(0);
static SHARED_VALUE: AtomicU64 = AtomicU64::new(0);
static JOIN_FUTEX: AtomicU32 = AtomicU32::new(0);
static CHILD_GETPID_OK: AtomicBool = AtomicBool::new(false);

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- explicitly zeroing it on every 3-arg
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

/// Real `clone(2)`, driven by hand -- see this file's own module doc comment for why the child
/// path has to branch straight into a real `call` instruction (`r9`, preserved across the syscall
/// exactly like real `clone.s` preserves its own function-pointer argument) rather than just
/// falling through into whatever Rust code happens to follow this call site.
///
/// `tls` goes into `r8` directly -- one register past what this ABI's normal 4-argument syscall
/// convention (`rdi`/`rsi`/`rdx`/`r10`) carries, matching real `clone.s`'s own register shuffle
/// (see `process::lifecycle::do_clone`'s own doc comment for the kernel side of this). `r10`
/// (`ctid`) is set to `0` and never used by the kernel -- `CLONE_CHILD_CLEARTID` needs no
/// kernel-side handling (real `pthread_join` is pure userspace futex logic).
///
/// Only ever returns for the **parent** (`Ok(child_pid)`/`Err(errno)`) -- the child never reaches
/// this function's own return point at all; it's called into fresh via `call r9` and is expected
/// to exit on its own.
#[inline(always)]
unsafe fn clone_thread(
    flags: u64,
    newsp: u64,
    ptid: u64,
    tls: u64,
    child_entry: unsafe extern "C" fn() -> !,
) -> Result<u64, u64> {
    let ret: u64;
    let failed: u8;
    unsafe {
        asm!(
            "syscall",
            // Must capture CF here, immediately after `syscall` -- `test` below unconditionally
            // clears it (real x86 `TEST` semantics), same "setc right after syscall" ordering
            // `syscall4` above already follows. The child's own resumption starts directly at
            // `test rax, rax` (its saved RCX return address is identical to the parent's, both
            // captured once at this same syscall entry) and never reaches this instruction at
            // all, so this reordering only matters for -- and only affects -- the parent's path.
            "setc {failed}",
            "test rax, rax",
            "jnz 2f",
            // Child path: rax == 0, rsp == newsp (a real, separate stack -- see this file's own
            // module doc comment for why a genuine call boundary is required here). r9 still
            // holds child_entry's address, preserved across the syscall (the kernel doesn't
            // touch r9 at all).
            "call r9",
            // child_entry is `-> !` -- never actually reached.
            "ud2",
            "2:",
            inlateout("rax") SYS_CLONE => ret,
            in("rdi") flags,
            in("rsi") newsp,
            in("rdx") ptid,
            in("r10") 0u64,
            in("r8") tls,
            in("r9") child_entry as u64,
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

fn write_decimal(value: u64) {
    let mut buf = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    if v == 0 {
        buf[0] = b'0';
        n = 1;
    }
    while v > 0 {
        buf[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    buf[..n].reverse();
    write_bytes(&buf[..n]);
    write_bytes(b"\n");
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// The cloned "thread"'s real entry point -- reached only via `clone_thread`'s own `call r9`,
/// never falls through from `_start`'s own code (see this file's own module doc comment). Runs on
/// `CHILD_STACK`, shares `_start`'s exact address space (real `CLONE_VM`) and tgid (real
/// `CLONE_THREAD`).
unsafe extern "C" fn child_main() -> ! {
    write_bytes(b"clone-syscall-smoke: child running\n");

    // Real CLONE_THREAD proof: getpid() reports the thread-group id, the parent's own pid, not a
    // fresh one -- see Process::tgid's own doc comment.
    let child_getpid = unsafe { syscall(SYS_GETPID, 0, 0, 0) };
    if child_getpid == Ok(PARENT_PID.load(Ordering::SeqCst)) {
        CHILD_GETPID_OK.store(true, Ordering::SeqCst);
    } else {
        write_bytes(b"clone-syscall-smoke: child's getpid() didn't report the parent's tgid\n");
    }

    // Real CLONE_VM proof: a plain static write, visible to the parent's own continuation only if
    // the address space is genuinely shared (not a copy) -- checked by the parent below.
    SHARED_VALUE.store(SHARED_SENTINEL, Ordering::SeqCst);

    // Real futex-based join -- the exact primitive real pthread_join is built on (see this file's
    // own module doc comment), proven directly here rather than through musl.
    JOIN_FUTEX.store(1, Ordering::SeqCst);
    unsafe {
        let _ = syscall4(
            SYS_FUTEX,
            (&JOIN_FUTEX as *const AtomicU32) as u64,
            FUTEX_WAKE,
            1,
            0,
        );
        let _ = syscall(SYS_EXIT, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"clone-syscall-smoke: starting\n");

    let parent_pid = match unsafe { syscall(SYS_GETPID, 0, 0, 0) } {
        Ok(pid) => pid,
        Err(_) => {
            write_bytes(b"clone-syscall-smoke: getpid failed\n");
            test_exit(false);
        }
    };
    PARENT_PID.store(parent_pid, Ordering::SeqCst);

    // SAFETY: only the address is read here (CHILD_STACK_SIZE is a plain constant, not a read
    // through the static), never a Rust reference to the mutable static itself -- see
    // CHILD_STACK's own doc comment.
    let stack_top = unsafe { (&raw const CHILD_STACK.0) as u64 + CHILD_STACK_SIZE as u64 };
    let newsp = stack_top & !0xf;
    let ptid_addr = (&PTID as *const AtomicU64) as u64;

    write_bytes(b"clone-syscall-smoke: cloning\n");
    let child_pid = match unsafe { clone_thread(PTHREAD_CLONE_FLAGS, newsp, ptid_addr, 0, child_main) }
    {
        Ok(pid) => pid,
        Err(errno) => {
            write_bytes(b"clone-syscall-smoke: clone() failed, errno=");
            write_decimal(errno);
            test_exit(false);
        }
    };
    write_bytes(b"clone-syscall-smoke: clone() returned child pid=");
    write_decimal(child_pid);

    // Real futex-based join, mirroring what real pthread_join does under the hood -- loop and
    // recheck the real word after every wake, same discipline every futex consumer in this
    // codebase already follows (a spurious/racing wake is real, documented FUTEX_WAIT behavior,
    // not a bug).
    while JOIN_FUTEX.load(Ordering::SeqCst) == 0 {
        let _ = unsafe {
            syscall4(
                SYS_FUTEX,
                (&JOIN_FUTEX as *const AtomicU32) as u64,
                FUTEX_WAIT,
                0,
                0,
            )
        };
    }
    write_bytes(b"clone-syscall-smoke: joined via futex\n");

    if PTID.load(Ordering::SeqCst) != child_pid {
        write_bytes(b"clone-syscall-smoke: CLONE_PARENT_SETTID didn't write the real child pid\n");
        test_exit(false);
    }
    write_bytes(b"clone-syscall-smoke: CLONE_PARENT_SETTID OK\n");

    if SHARED_VALUE.load(Ordering::SeqCst) != SHARED_SENTINEL {
        write_bytes(b"clone-syscall-smoke: shared write not visible -- CLONE_VM broken\n");
        test_exit(false);
    }
    write_bytes(b"clone-syscall-smoke: CLONE_VM (shared write visibility) OK\n");

    if !CHILD_GETPID_OK.load(Ordering::SeqCst) {
        write_bytes(b"clone-syscall-smoke: CLONE_THREAD (tgid sharing) check failed\n");
        test_exit(false);
    }
    write_bytes(b"clone-syscall-smoke: CLONE_THREAD (tgid sharing) OK\n");

    write_bytes(b"clone-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
