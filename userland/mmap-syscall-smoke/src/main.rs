//! Real-`SYSCALL` smoke test for two mmap-related fixes made while chasing the Open POSIX Test
//! Suite pilot's own `mmap/11-2.c`/`11-3.c`/`12-1.c` FAILs (see `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`
//! and `src/process/mm.rs`/`src/cpu/interrupts.rs`/`src/process/fault_trampoline.rs` for the real
//! implementation this exercises):
//!
//! 1. **`mmap/12-1.c`'s own bug, independent of mmap itself**: `open(O_CREAT)` on a brand-new path
//!    defers allocating a real inode/directory entry until the fd's first commit
//!    (`ftruncate`/`fsync`/`close`) -- `unlink()`ing the path *before* that first commit used to
//!    find nothing to remove (no entry exists yet) and silently do nothing, after which the
//!    deferred commit went ahead and inserted the entry anyway, resurrecting a name real POSIX
//!    says must stay gone. Part 1 below reproduces `open -> unlink -> ftruncate -> mmap -> close`
//!    and confirms the path is genuinely unreachable afterward, while the still-open mapping keeps
//!    working.
//! 2. **`mmap/11-2.c`/`11-3.c`'s own real gap**: a reference to a whole page mapped past a
//!    file-backed object's own real, page-rounded extent (but still within the caller's original
//!    `len`) must raise a real `SIGBUS` -- this kernel used to map every requested page
//!    unconditionally (zero-filled), so such a reference just silently succeeded. Fixing it needed
//!    a genuinely new capability this test also exercises: **real signal delivery from a ring-3
//!    page fault at all** (this kernel used to reboot on any such fault, ring-3 or not) -- part 2
//!    proves a real installed handler actually runs with the correct signal number; parts 3/4 prove
//!    the *default*-disposition case (no handler) now cleanly terminates just the one offending
//!    process (`SIGBUS` for the reserved-but-unbacked mmap tail specifically, `SIGSEGV` for an
//!    ordinary wild pointer) instead of rebooting the whole kernel.
//!
//! Parts 2-4 each run inside their own forked child -- a real fault-driven signal is fundamentally
//! disruptive to whichever process it hits (it either terminates the process or hands control to a
//! handler that can't safely "return" to the faulting instruction, see
//! `process::fault_trampoline`'s own module doc comment for why), so each gets an isolated child
//! whose own real exit status (checked via `wait4` back in the parent) is the pass/fail signal,
//! the same fork-and-check-wait4-status shape `userland/sig-syscall-smoke`'s own permission-check
//! parts already establish.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper and its own minimal `sigreturn_trampoline` (same convention
//! `userland/pause-syscall-smoke/` already established) -- part 2's handler never actually
//! `sigreturn`s (it calls `SYS_EXIT` directly, matching the real pilot test's own `sigbus_handler`,
//! which calls `exit()` and never returns), but `sigaction`'s own wire format still needs a real,
//! valid `restorer` field.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_WAIT4: u64 = 7;
const SYS_MMAP: u64 = 100;
const SYS_MUNMAP: u64 = 101;
const SYS_UNLINK: u64 = 109;
const SYS_SIGACTION: u64 = 117;
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `third_party/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly
/// rather than going through a shared macro.
const SYS_SIGRETURN: u64 = 119;
const SYS_FTRUNCATE: u64 = 473;
const SYS_PRLIMIT64: u64 = 478;
const SYS_MLOCKALL: u64 = 511;
const SYS_MUNLOCKALL: u64 = 512;
const SYS_FSTAT: u64 = 126;
const SYS_MSYNC: u64 = 26;
const SYS_NANOSLEEP: u64 = 139;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// mmap_syscall_smoke.rs` registers this one directly against a test-only handler, same convention
/// every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_CREAT: u64 = 0o100;
/// Real POSIX `open(2)` access-mode bit -- every part here `ftruncate`s and/or writes through the
/// real mapping, so `open_create` always requests real write access explicitly now that
/// `modules/oxfs`'s own `oxfs_open` enforces the caller's real requested access mode even on a
/// brand-new `O_CREAT` file (`OpenFile::Write::readonly`, see that field's own doc comment)
/// rather than always granting write access regardless of what was actually asked for.
const O_RDWR: u64 = 0o2;
const PROT_READ_WRITE: u64 = 0x1 | 0x2;
const SIGBUS: u64 = 7;
const SIGSEGV: u64 = 11;

/// Real `mmap(2)` flag bits, matching `third_party/musl/include/sys/mman.h` -- now real on the
/// wire (`process::mm::do_mmap`'s own doc comment), packed into the unused high bits of the `prot`
/// register (`mmap_call` below), not a spare argument this ABI doesn't have room for.
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const EBADF: u64 = 9;
const EINVAL: u64 = 22;
const EAGAIN: u64 = 11;
const ENXIO: u64 = 6;
const EOVERFLOW: u64 = 75;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`'s own
/// `sigsetsize` and `mmap`'s own packed `(fd, off)` register. Explicitly zeroing `r10` on every
/// 3-arg call above (rather than leaving it unspecified) is the exact audit CLAUDE.md's own "any
/// future syscall that upgrades from 3 to 4 real arguments" note calls out -- `SYSCALL` doesn't
/// clear `r10` itself.
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
            write_bytes(concat!("mmap-syscall-smoke: FAIL -- ", $msg, "\n").as_bytes());
            test_exit(false);
        }
    };
}

/// Matches `src/process/signals.rs`'s `do_sigaction`'s own `RawSigAction` wire format exactly.
#[repr(C)]
struct RawSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// Matches `src/process/limits.rs`'s own `RawRlimit` wire format exactly (`(rlim_cur, rlim_max)`).
#[repr(C)]
struct RawRlimit {
    rlim_cur: u64,
    rlim_max: u64,
}

/// Matches `modules/oxfs`'s own `MuslStat` wire format exactly (`third_party/musl`'s real x86_64
/// `struct stat`) -- only the fields part 11 actually reads are commented, the rest exist purely to
/// keep every later field at the right byte offset.
#[repr(C)]
struct RawStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime_sec: i64,
    st_atime_nsec: i64,
    st_mtime_sec: i64,
    st_mtime_nsec: i64,
    st_ctime_sec: i64,
    st_ctime_nsec: i64,
    __unused: [i64; 3],
}

const _: () = assert!(core::mem::size_of::<RawStat>() == 144);

/// Matches `src/process/timers.rs`'s own `RawTimespec`/real `struct timespec` wire format exactly.
#[repr(C)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// This crate's own minimal `__restore_rt` equivalent -- installed as `sigaction`'s own
/// `restorer` field (a real, valid function pointer sigaction itself doesn't reject), even though
/// part 2's own handler never actually reaches it (see this file's own module doc comment).
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

fn open_create(path: &[u8]) -> Result<u64, u64> {
    unsafe {
        syscall(
            SYS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            O_CREAT | O_RDWR,
        )
    }
}

/// `packed_prot` = real `prot` (low 8 bits) | real `flags` (shifted left 8) -- see
/// `src/syscall/ffi.rs`'s own `oxidebsd_sys_mmap` doc comment for this exact wire format. `packed`
/// = `(off << 32) | (fd as u32)`.
fn mmap_call_off(addr_hint: u64, fd: u64, len: u64, flags: u64, off: u32) -> Result<u64, u64> {
    let packed_prot = PROT_READ_WRITE | (flags << 8);
    let packed = (fd & 0xffff_ffff) | ((off as u64) << 32);
    unsafe { syscall4(SYS_MMAP, addr_hint, len, packed_prot, packed) }
}

fn mmap_call(addr_hint: u64, fd: u64, len: u64, flags: u64) -> Result<u64, u64> {
    mmap_call_off(addr_hint, fd, len, flags, 0)
}

fn mmap_shared(fd: u64, len: u64) -> Result<u64, u64> {
    mmap_call(0, fd, len, MAP_SHARED)
}

fn fstat(fd: u64) -> Result<RawStat, u64> {
    // SAFETY: RawStat is a plain-integer #[repr(C)] struct -- an all-zero bit pattern is valid for
    // every field, and oxfs_fstat immediately overwrites the whole thing via write_unaligned.
    let mut stat: RawStat = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
    unsafe { syscall(SYS_FSTAT, fd, &mut stat as *mut RawStat as u64, 0) }?;
    Ok(stat)
}

fn sleep_1s() {
    let ts = RawTimespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    unsafe {
        let _ = syscall(SYS_NANOSLEEP, &ts as *const RawTimespec as u64, 0, 0);
    }
}

fn wait4(pid: u64) -> Result<(u64, i32), u64> {
    let mut status: i32 = -1;
    let ret = unsafe { syscall4(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0, 0) }?;
    Ok((ret, status))
}

/// A normal (non-signal) child exit's own status encoding -- `(code & 0xff) << 8`, see
/// `process::lifecycle`'s own `do_wait4` doc comment.
fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

/// A signal-terminated child's own status encoding -- the *unshifted* `128 + signum` value,
/// distinguishable from a normal exit's status (whose own low byte is always `0`) by a nonzero low
/// byte -- see the same doc comment `wexitstatus` above references.
fn wtermsig(status: i32) -> Option<i32> {
    if status & 0x7f != 0 {
        Some(status - 128)
    } else {
        None
    }
}

/// Part 2's own handler -- proves real, argument-correct invocation the same way the actual pilot
/// test's own `sigbus_handler` does: exits directly with a distinctive marker code (`77`) rather
/// than trying to `sigreturn` back into a faulting instruction that can never safely re-execute
/// (see this file's own module doc comment).
extern "C" fn part2_handler(signum: i64) {
    write_bytes(b"mmap-syscall-smoke: part 2 handler ran\n");
    let marker = if signum == SIGBUS as i64 { 77 } else { 66 };
    unsafe {
        let _ = syscall(SYS_EXIT, marker, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Part 2: a real fd-backed `MAP_SHARED` mapping whose requested length (2 real pages) exceeds the
/// underlying object's own real, page-rounded extent (half a page) -- installs a real `SIGBUS`
/// handler, then writes into the second, entirely-unbacked page. A real handler invocation exits
/// `77`; anything else (the fault never happening at all -- the pre-fix behavior -- or an
/// incorrect signal number) exits `1`.
fn part2_child() -> ! {
    let path = b"/tmp/mmap-smoke-b\0";
    let fd = match open_create(path) {
        Ok(fd) => fd,
        Err(_) => unsafe {
            let _ = syscall(SYS_EXIT, 2, 0, 0);
            loop {
                spin_loop();
            }
        },
    };
    let _ = unsafe { syscall(SYS_FTRUNCATE, fd, 2048, 0) };

    let act = RawSigAction {
        handler: part2_handler as u64,
        flags: 0,
        restorer: sigreturn_trampoline as u64,
        mask: 0,
    };
    let _ = unsafe { syscall4(SYS_SIGACTION, SIGBUS, &act as *const RawSigAction as u64, 0, 8) };

    let pa = match mmap_shared(fd, 8192) {
        Ok(pa) => pa,
        Err(_) => unsafe {
            let _ = syscall(SYS_EXIT, 3, 0, 0);
            loop {
                spin_loop();
            }
        },
    };

    // The second page, entirely beyond the object's own real (2048-byte, rounded up to one page)
    // extent -- a real reference here must raise SIGBUS, never silently succeed.
    unsafe {
        core::ptr::write_volatile((pa + 4096 + 1) as *mut u8, 0xAB);
    }

    // Only reached if the fault never happened at all -- a real regression, not a pass.
    unsafe {
        let _ = syscall(SYS_EXIT, 1, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Part 3: the same reserved-but-unbacked mmap tail as part 2, but with *no* handler installed --
/// real default disposition for `SIGBUS` is `Terminate`, so this process should cleanly exit via
/// signal `7` (checked by the parent's own `wait4`), not silently succeed and not reboot the whole
/// kernel (the pre-fix behavior for *any* ring-3 fault, not just this one).
fn part3_child() -> ! {
    let path = b"/tmp/mmap-smoke-c\0";
    let fd = match open_create(path) {
        Ok(fd) => fd,
        Err(_) => unsafe {
            let _ = syscall(SYS_EXIT, 2, 0, 0);
            loop {
                spin_loop();
            }
        },
    };
    let _ = unsafe { syscall(SYS_FTRUNCATE, fd, 2048, 0) };
    let pa = match mmap_shared(fd, 8192) {
        Ok(pa) => pa,
        Err(_) => unsafe {
            let _ = syscall(SYS_EXIT, 3, 0, 0);
            loop {
                spin_loop();
            }
        },
    };
    unsafe {
        core::ptr::write_volatile((pa + 4096 + 1) as *mut u8, 0xCD);
    }
    // Only reached if the fault never happened at all.
    unsafe {
        let _ = syscall(SYS_EXIT, 1, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Part 4: an ordinary wild-pointer write, nowhere near any real mapping (not mmap'd, not the ELF
/// image/BRK/user stack) -- real default disposition for `SIGSEGV` is also `Terminate`. Proves the
/// fault-to-signal machinery's own `SIGSEGV` fallback (`process::mm::signal_for_user_fault`'s
/// `else` branch), independent of the mmap-specific `SIGBUS` case parts 2/3 exercise.
fn part4_child() -> ! {
    unsafe {
        core::ptr::write_volatile(0x0000_0000_0800_0000u64 as *mut u8, 0xEF);
    }
    unsafe {
        let _ = syscall(SYS_EXIT, 1, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Part 5: a real, live-found regression -- `mmap()`ing a freshly `open(O_CREAT)`'d file with *no*
/// `write()`/`ftruncate()` at all (real content length `0`, so `covered_pages == 0`: the whole
/// mapping is beyond the object's own real extent). The very first such mmap of a given file used
/// to panic (`mm::do_mmap_file_backed`'s own frame-cache lookup unconditionally `.expect()`ed an
/// entry the cache-growth block never actually inserts when `existing_len < covered_pages` is
/// `0 < 0` -- false). Not caught by parts 2/3 above, which both `ftruncate` first. No handler
/// installed -- default disposition `SIGBUS` should cleanly terminate this child (signal `7`),
/// proving both the panic is gone and the resulting mapping still behaves correctly (real POSIX:
/// *every* byte of it is beyond the object's own extent).
fn part5_child() -> ! {
    let path = b"/tmp/mmap-smoke-e\0";
    let fd = match open_create(path) {
        Ok(fd) => fd,
        Err(_) => unsafe {
            let _ = syscall(SYS_EXIT, 2, 0, 0);
            loop {
                spin_loop();
            }
        },
    };
    let pa = match mmap_shared(fd, 4096) {
        Ok(pa) => pa,
        Err(_) => unsafe {
            let _ = syscall(SYS_EXIT, 3, 0, 0);
            loop {
                spin_loop();
            }
        },
    };
    unsafe {
        core::ptr::write_volatile(pa as *mut u8, 0x99);
    }
    // Only reached if the fault never happened at all.
    unsafe {
        let _ = syscall(SYS_EXIT, 1, 0, 0);
    }
    loop {
        spin_loop();
    }
}

fn run_child_and_check(spawn: fn() -> !, part_name: &str, check: impl FnOnce(i32) -> bool) {
    let pid = unsafe { syscall(SYS_FORK, 0, 0, 0) }.expect("fork failed");
    if pid == 0 {
        spawn();
    }
    let (_, status) = wait4(pid).expect("wait4 failed");
    if !check(status) {
        write_bytes(b"mmap-syscall-smoke: FAIL -- ");
        write_bytes(part_name.as_bytes());
        write_bytes(b" (unexpected child status)\n");
        test_exit(false);
    }
    write_bytes(part_name.as_bytes());
    write_bytes(b" OK\n");
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"mmap-syscall-smoke: starting\n");

    // --- Part 1: mmap/12-1.c's own unlink-before-first-commit bug ---
    let path = b"/tmp/mmap-smoke-a\0";
    let fd = open_create(path).expect("part 1: open(O_CREAT) failed");
    check!(
        unsafe { syscall(SYS_UNLINK, path.as_ptr() as u64, path.len() as u64, 0) }.is_ok(),
        "part 1: unlink() before first commit failed"
    );
    check!(
        unsafe { syscall(SYS_FTRUNCATE, fd, 1024, 0) }.is_ok(),
        "part 1: ftruncate (forces the first commit) failed"
    );
    let pa = mmap_shared(fd, 4096).expect("part 1: mmap failed");
    check!(
        unsafe { syscall(SYS_CLOSE, fd, 0, 0) }.is_ok(),
        "part 1: close failed"
    );
    // The core regression check: the unlink() above must have stayed real, not been silently
    // undone by ftruncate's own forced early commit.
    check!(
        unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0) } == Err(2),
        "part 1: path still openable after close() -- unlink was silently undone"
    );
    // The still-live mapping (real POSIX: unlink doesn't invalidate an existing mapping/fd) keeps
    // working regardless.
    unsafe {
        core::ptr::write_volatile(pa as *mut u8, 0x42);
        check!(
            core::ptr::read_volatile(pa as *const u8) == 0x42,
            "part 1: mapping stopped working after unlink"
        );
    }
    check!(
        unsafe { syscall(SYS_MUNMAP, pa, 4096, 0) }.is_ok(),
        "part 1: munmap failed"
    );
    check!(
        unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0) } == Err(2),
        "part 1: path openable again after munmap"
    );
    write_bytes(b"mmap-syscall-smoke: part 1 (unlink before first commit) OK\n");

    // --- Part 2: real SIGBUS handler invocation on a reserved-but-unbacked mmap tail ---
    run_child_and_check(part2_child, "mmap-syscall-smoke: part 2 (SIGBUS handler)", |status| {
        wexitstatus(status) == 77
    });

    // --- Part 3: default-disposition SIGBUS (no handler) on the same reserved tail ---
    run_child_and_check(
        part3_child,
        "mmap-syscall-smoke: part 3 (SIGBUS default-terminate)",
        |status| wtermsig(status) == Some(SIGBUS as i32),
    );

    // --- Part 4: default-disposition SIGSEGV (no handler) on an ordinary wild pointer ---
    run_child_and_check(
        part4_child,
        "mmap-syscall-smoke: part 4 (SIGSEGV default-terminate)",
        |status| wtermsig(status) == Some(SIGSEGV as i32),
    );

    // --- Part 5: mmap of a file with zero real content (covered_pages == 0) -- a real panic
    // found live, see part5_child's own doc comment.
    run_child_and_check(
        part5_child,
        "mmap-syscall-smoke: part 5 (mmap of zero-content file)",
        |status| wtermsig(status) == Some(SIGBUS as i32),
    );

    // --- Part 6: real EBADF for a non-anonymous request against an invalid fd (`mmap/19-1.c`) ---
    // `fd == -1` (the real, recognizable `0xffff_ffff` wire pattern) with `MAP_SHARED` and no
    // `MAP_ANON` -- previously silently treated as an anonymous mapping (flags never reached the
    // kernel at all); now a real `EBADF`, matching real POSIX.
    check!(
        mmap_call(0, 0xffff_ffff, 4096, MAP_SHARED) == Err(EBADF),
        "part 6: expected EBADF for MAP_SHARED against an invalid fd"
    );
    write_bytes(b"mmap-syscall-smoke: part 6 (EBADF on invalid fd) OK\n");

    // --- Part 7: real EINVAL when neither MAP_SHARED nor MAP_PRIVATE is set (`mmap/9-1.c`/
    // `mmap/21-1.c`) -- checked before the fd validity check above, so this fires even against the
    // same invalid fd part 6 used.
    check!(
        mmap_call(0, 0xffff_ffff, 4096, 0) == Err(EINVAL),
        "part 7: expected EINVAL when neither MAP_SHARED nor MAP_PRIVATE is set"
    );
    check!(
        mmap_call(0, 0xffff_ffff, 4096, MAP_SHARED | MAP_PRIVATE) == Err(EINVAL),
        "part 7: expected EINVAL when both MAP_SHARED and MAP_PRIVATE are set"
    );
    write_bytes(b"mmap-syscall-smoke: part 7 (EINVAL on invalid flags) OK\n");

    // --- Part 8: real MAP_FIXED "replace" semantics (`mmap/3-1.c`) -- mmap file A, then mmap file
    // B MAP_FIXED at exactly the address the first mmap returned; the second call must return that
    // same address, and a read through it must see file B's content, not file A's.
    let path_fixed_a = b"/tmp/mmap-smoke-fixed-a\0";
    let fd_fixed_a = open_create(path_fixed_a).expect("part 8: open(A) failed");
    let buf_a = [b'a'; 4096];
    unsafe {
        syscall(SYS_WRITE, fd_fixed_a, buf_a.as_ptr() as u64, buf_a.len() as u64)
            .expect("part 8: write(A) failed");
    }
    let pa = mmap_shared(fd_fixed_a, 4096).expect("part 8: mmap(A) failed");

    let path_fixed_b = b"/tmp/mmap-smoke-fixed-b\0";
    let fd_fixed_b = open_create(path_fixed_b).expect("part 8: open(B) failed");
    let buf_b = [b'b'; 4096];
    unsafe {
        syscall(SYS_WRITE, fd_fixed_b, buf_b.as_ptr() as u64, buf_b.len() as u64)
            .expect("part 8: write(B) failed");
    }
    let pa2 = mmap_call(pa, fd_fixed_b, 4096, MAP_SHARED | MAP_FIXED)
        .expect("part 8: MAP_FIXED mmap(B) failed");
    check!(pa2 == pa, "part 8: MAP_FIXED did not return the requested address");
    unsafe {
        check!(
            core::ptr::read_volatile(pa2 as *const u8) == b'b',
            "part 8: MAP_FIXED did not replace the previous mapping's content"
        );
    }
    check!(
        unsafe { syscall(SYS_MUNMAP, pa2, 4096, 0) }.is_ok(),
        "part 8: munmap failed"
    );
    write_bytes(b"mmap-syscall-smoke: part 8 (MAP_FIXED replace) OK\n");

    // --- Part 9: real MAP_PRIVATE discard-on-unmap (`munmap/4-1.c`) -- a write through a
    // MAP_PRIVATE mapping must never reach the underlying file, unlike MAP_SHARED.
    let path_private = b"/tmp/mmap-smoke-private\0";
    let fd_private = open_create(path_private).expect("part 9: open failed");
    let buf_orig = [b'a'; 1024];
    unsafe {
        syscall(
            SYS_WRITE,
            fd_private,
            buf_orig.as_ptr() as u64,
            buf_orig.len() as u64,
        )
        .expect("part 9: write failed");
    }
    let pa3 = mmap_call(0, fd_private, 1024, MAP_PRIVATE).expect("part 9: mmap failed");
    unsafe {
        core::ptr::write_volatile(pa3 as *mut u8, b'b');
    }
    check!(
        unsafe { syscall(SYS_MUNMAP, pa3, 1024, 0) }.is_ok(),
        "part 9: munmap failed"
    );
    let pa4 = mmap_call(0, fd_private, 1024, MAP_PRIVATE).expect("part 9: second mmap failed");
    unsafe {
        check!(
            core::ptr::read_volatile(pa4 as *const u8) == b'a',
            "part 9: MAP_PRIVATE write leaked back into the file"
        );
    }
    check!(
        unsafe { syscall(SYS_MUNMAP, pa4, 1024, 0) }.is_ok(),
        "part 9: second munmap failed"
    );
    write_bytes(b"mmap-syscall-smoke: part 9 (MAP_PRIVATE discard) OK\n");

    // --- Part 10: real mlockall(MCL_FUTURE) + RLIMIT_MEMLOCK enforcement (`mmap/18-1.c`) -- a
    // mapping larger than the process's own remaining locked-byte budget must fail EAGAIN rather
    // than silently mapping (and silently *not* actually locking).
    const MCL_FUTURE: u64 = 2;
    const RLIMIT_MEMLOCK: u64 = 8;
    check!(
        unsafe { syscall(SYS_MLOCKALL, MCL_FUTURE, 0, 0) }.is_ok(),
        "part 10: mlockall(MCL_FUTURE) failed"
    );
    let rlim = RawRlimit {
        rlim_cur: 512 * 1024,
        rlim_max: u64::MAX,
    };
    check!(
        unsafe {
            syscall4(
                SYS_PRLIMIT64,
                0,
                RLIMIT_MEMLOCK,
                &rlim as *const RawRlimit as u64,
                0,
            )
        }
        .is_ok(),
        "part 10: setrlimit(RLIMIT_MEMLOCK) failed"
    );
    let path_lock = b"/tmp/mmap-smoke-lock\0";
    let fd_lock = open_create(path_lock).expect("part 10: open failed");
    check!(
        unsafe { syscall(SYS_FTRUNCATE, fd_lock, 1024, 0) }.is_ok(),
        "part 10: ftruncate failed"
    );
    check!(
        mmap_call(0, fd_lock, 1024 * 1024, MAP_SHARED) == Err(EAGAIN),
        "part 10: expected EAGAIN mapping past RLIMIT_MEMLOCK under mlockall(MCL_FUTURE)"
    );
    // Real POSIX munlockall() semantics: cancels the MCL_FUTURE setting -- undoes part 10's own
    // process-wide state so later parts aren't affected by it (this whole crate runs sequentially
    // in one process, not one-scenario-per-process).
    check!(
        unsafe { syscall(SYS_MUNLOCKALL, 0, 0, 0) }.is_ok(),
        "part 10: munlockall failed"
    );
    write_bytes(b"mmap-syscall-smoke: part 10 (mlockall(MCL_FUTURE) EAGAIN) OK\n");

    // --- Part 11: real st_mtime/st_ctime updates through a write via mmap + msync (`mmap/14-1.c`)
    // -- previously always-0 placeholders (no clock/RTC source existed when oxfs's stat path was
    // first written).
    let path_time = b"/tmp/mmap-smoke-time\0";
    let fd_time = open_create(path_time).expect("part 11: open failed");
    let content = [b'a'; 64];
    unsafe {
        syscall(SYS_WRITE, fd_time, content.as_ptr() as u64, content.len() as u64)
            .expect("part 11: write failed");
    }
    let stat1 = fstat(fd_time).expect("part 11: fstat 1 failed");
    // Whole-second RTC precision -- without a real elapsed second, mtime2 could legitimately equal
    // mtime1 even with the fix correctly in place.
    sleep_1s();
    let pa5 = mmap_shared(fd_time, 64).expect("part 11: mmap failed");
    unsafe {
        core::ptr::write_volatile(pa5 as *mut u8, b'b');
    }
    const MS_SYNC: u64 = 4;
    check!(
        unsafe { syscall(SYS_MSYNC, pa5, 64, MS_SYNC) }.is_ok(),
        "part 11: msync failed"
    );
    let stat2 = fstat(fd_time).expect("part 11: fstat 2 failed");
    check!(
        stat2.st_mtime_sec != stat1.st_mtime_sec,
        "part 11: st_mtime was not updated after a write through mmap"
    );
    check!(
        stat2.st_ctime_sec != stat1.st_ctime_sec,
        "part 11: st_ctime was not updated after a write through mmap"
    );
    check!(
        unsafe { syscall(SYS_MUNMAP, pa5, 64, 0) }.is_ok(),
        "part 11: munmap failed"
    );
    write_bytes(b"mmap-syscall-smoke: part 11 (real mtime/ctime via mmap) OK\n");

    // --- Part 12: real ENXIO for a nonzero-offset request whose range doesn't fit the object
    // (`mmap/28-1.c`) -- deliberately distinct from parts 2/3/5 above, which all use off == 0 and
    // must keep succeeding (real POSIX MPR, not ENXIO) even when their own `len` extends past the
    // object's real content.
    let path_nxio = b"/tmp/mmap-smoke-nxio\0";
    let fd_nxio = open_create(path_nxio).expect("part 12: open failed");
    let shm_size: u64 = 8192; // two pages
    check!(
        unsafe { syscall(SYS_FTRUNCATE, fd_nxio, shm_size, 0) }.is_ok(),
        "part 12: ftruncate failed"
    );
    check!(
        mmap_call_off(0, fd_nxio, 2 * shm_size, MAP_SHARED, 4096) == Err(ENXIO),
        "part 12: expected ENXIO for an out-of-bounds nonzero-offset request"
    );
    write_bytes(b"mmap-syscall-smoke: part 12 (ENXIO on out-of-bounds offset) OK\n");

    // --- Part 13: real EOVERFLOW when off + len exceeds this ABI's real off_t range (`mmap/31-1.c`)
    // -- mirrors the real pilot test's own ULONG_MAX-rounded-to-a-page len/off (this crate issues
    // the raw syscall directly, bypassing musl's own client-side length guard entirely, so the
    // request genuinely reaches the kernel).
    let path_of = b"/tmp/mmap-smoke-of\0";
    let fd_of = open_create(path_of).expect("part 13: open failed");
    let huge: u64 = 0xffff_ffff_ffff_f000; // ULONG_MAX rounded down to a page boundary
    check!(
        mmap_call_off(0, fd_of, huge, MAP_SHARED, huge as u32) == Err(EOVERFLOW),
        "part 13: expected EOVERFLOW for an off/len combination exceeding the real off_t range"
    );
    write_bytes(b"mmap-syscall-smoke: part 13 (EOVERFLOW on off/len overflow) OK\n");

    write_bytes(b"mmap-syscall-smoke: all parts passed\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_bytes(b"mmap-syscall-smoke: PANIC\n");
    test_exit(false);
}
