//! Real-`SYSCALL` smoke test for the NEEDS_SYSCALL gap-table pass's "cheap, no new data model"
//! batch: `SYS_FSYNC`/`SYS_SYNC`/`SYS_FTRUNCATE`/`SYS_FALLOCATE`/`SYS_FLOCK`/`SYS_STATFS`/
//! `SYS_FSTATFS` (`sys/modules/oxfs`, `471`-`477`) and `SYS_PRLIMIT64`/`SYS_SETPRIORITY`/
//! `SYS_GETPRIORITY`/`SYS_SCHED_SETSCHEDULER`/`SYS_SCHED_GETSCHEDULER`/`SYS_SCHED_GETPARAM`/
//! `SYS_SCHED_GET_PRIORITY_MAX`/`SYS_SCHED_GET_PRIORITY_MIN` (`sys/modules/posix_compat`,
//! `478`-`485`). `SYS_REBOOT` (`486`) is deliberately **not** covered here -- every success path
//! diverges (halts/resets/powers off the whole VM), which would end the test session in a way
//! `isa-debug-exit` can't distinguish from a hang; same "hand off anything that can't be scripted
//! this way" precedent this codebase already follows for real interactive-keyboard-input cases.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning every other real-`SYSCALL` smoke
//! test in this codebase documents (per-process state like `Process::rlimits`/`nice`/
//! `sched_policy` is keyed by `scheduler::current_pid()`, exactly the class of thing a
//! plain-Rust-function test can't exercise the same way).
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_READ: u64 = 3;
const SYS_FSYNC: u64 = 471;
const SYS_SYNC: u64 = 472;
const SYS_FTRUNCATE: u64 = 473;
const SYS_FALLOCATE: u64 = 474;
const SYS_FLOCK: u64 = 475;
const SYS_STATFS: u64 = 476;
const SYS_FSTATFS: u64 = 477;
const SYS_PRLIMIT64: u64 = 478;
const SYS_SETPRIORITY: u64 = 479;
const SYS_GETPRIORITY: u64 = 480;
const SYS_SCHED_SETSCHEDULER: u64 = 481;
const SYS_SCHED_GETSCHEDULER: u64 = 482;
const SYS_SCHED_GETPARAM: u64 = 483;
const SYS_SCHED_GET_PRIORITY_MAX: u64 = 484;
const SYS_SCHED_GET_PRIORITY_MIN: u64 = 485;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// needs_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_CREAT: u64 = 0o100;
/// Real POSIX `open(2)` access-mode bit -- needed explicitly now that `sys/modules/oxfs`'s own
/// `oxfs_open` enforces the caller's real requested access mode even on a brand-new `O_CREAT`
/// file (`OpenFile::Write::readonly`, see that field's own doc comment) rather than always
/// granting write access regardless of what was actually asked for.
const O_WRONLY: u64 = 0o1;
const EAGAIN: u64 = 11;

const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;

const PRIO_PROCESS: u64 = 0;
const SCHED_OTHER: u64 = 0;
const SCHED_FIFO: u64 = 1;

/// Real Linux's own `RLIMIT_NOFILE` index -- any of the 16 slots would exercise the same code
/// path (nothing here is resource-specific), this one's just recognizable.
const RLIMIT_NOFILE: u64 = 7;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `prlimit64`'s own
/// `(pid, resource, new_ptr, old_ptr)` and `fallocate`'s own `(fd, mode, offset, len)`.
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
            write_bytes(b"needs-syscall-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
}

#[repr(C)]
struct RawRlimit {
    rlim_cur: u64,
    rlim_max: u64,
}

#[repr(C)]
struct RawSchedParam {
    sched_priority: i32,
}

#[repr(C)]
struct MuslStatfs {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [u64; 4],
}

fn open_ro(path: &[u8]) -> Result<u64, u64> {
    unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0) }
}

fn close(fd: u64) {
    unsafe {
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"needs-syscall-smoke: starting\n");

    // --- fsync: a still-open write fd's content is force-committed, visible to an independent
    // concurrent reader before the writer ever closes. ---
    let f1 = b"/nsfsync";
    let wfd = unsafe {
        syscall(
            SYS_OPEN,
            f1.as_ptr() as u64,
            f1.len() as u64,
            O_CREAT | O_WRONLY,
        )
    };
    check!(wfd.is_ok(), b"create /nsfsync failed");
    let wfd = wfd.unwrap();
    unsafe {
        let _ = syscall(SYS_WRITE, wfd, b"AB".as_ptr() as u64, 2);
    }
    check!(
        unsafe { syscall(SYS_FSYNC, wfd, 0, 0) }.is_ok(),
        b"fsync failed"
    );
    let rfd = open_ro(f1);
    check!(
        rfd.is_ok(),
        b"reopen /nsfsync while still open for write failed"
    );
    let rfd = rfd.unwrap();
    let mut buf = [0u8; 8];
    let n = unsafe { syscall(SYS_READ, rfd, buf.as_mut_ptr() as u64, 8) };
    check!(
        n == Ok(2) && &buf[..2] == b"AB",
        b"fsync'd content not visible to a concurrent reader"
    );
    close(rfd);
    close(wfd);
    write_bytes(b"needs-syscall-smoke: fsync OK\n");

    // --- sync: a real no-op-success sweep of every open write fd. ---
    check!(
        unsafe { syscall(SYS_SYNC, 0, 0, 0) }.is_ok(),
        b"sync failed"
    );

    // --- flock: real LOCK_EX exclusion between two independent opens of the same path, and
    // release on close. ---
    let lfd1 = open_ro(f1).expect("open for flock 1");
    let lfd2 = open_ro(f1).expect("open for flock 2");
    check!(
        unsafe { syscall(SYS_FLOCK, lfd1, LOCK_EX, 0) }.is_ok(),
        b"flock LOCK_EX on fd1 failed"
    );
    check!(
        unsafe { syscall(SYS_FLOCK, lfd2, LOCK_EX | LOCK_NB, 0) } == Err(EAGAIN),
        b"flock LOCK_EX|LOCK_NB on fd2 didn't fail EAGAIN while fd1 holds the lock"
    );
    close(lfd1);
    check!(
        unsafe { syscall(SYS_FLOCK, lfd2, LOCK_EX | LOCK_NB, 0) }.is_ok(),
        b"flock LOCK_EX on fd2 didn't succeed after fd1's lock was released by close()"
    );
    close(lfd2);
    write_bytes(b"needs-syscall-smoke: flock OK\n");

    // --- ftruncate/fallocate: real shrink then real zero-extend, on a plain read-mode fd (no
    // write-buffer-commit-on-close interaction to worry about). ---
    let tfd = open_ro(f1).expect("open for ftruncate");
    check!(
        unsafe { syscall(SYS_FTRUNCATE, tfd, 1, 0) }.is_ok(),
        b"ftruncate shrink failed"
    );
    close(tfd);
    let tfd2 = open_ro(f1).expect("reopen after ftruncate");
    let mut tb = [0xffu8; 8];
    let tn = unsafe { syscall(SYS_READ, tfd2, tb.as_mut_ptr() as u64, 8) };
    check!(
        tn == Ok(1) && tb[0] == b'A',
        b"file content didn't reflect the ftruncate shrink"
    );
    check!(
        unsafe { syscall4(SYS_FALLOCATE, tfd2, 0, 0, 4) }.is_ok(),
        b"fallocate grow failed"
    );
    close(tfd2);
    let tfd3 = open_ro(f1).expect("reopen after fallocate");
    let mut tb2 = [0xffu8; 8];
    let tn2 = unsafe { syscall(SYS_READ, tfd3, tb2.as_mut_ptr() as u64, 8) };
    check!(
        tn2 == Ok(4) && tb2[0] == b'A' && tb2[1..4] == [0, 0, 0],
        b"file content didn't reflect the fallocate zero-extend"
    );
    close(tfd3);
    write_bytes(b"needs-syscall-smoke: ftruncate/fallocate OK\n");

    // --- statfs/fstatfs: plausible real values from the same live filesystem, both ways. ---
    let mut sbuf: MuslStatfs = MuslStatfs {
        f_type: 0,
        f_bsize: 0,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: 0,
        f_ffree: 0,
        f_fsid: [0, 0],
        f_namelen: 0,
        f_frsize: 0,
        f_flags: 0,
        f_spare: [0; 4],
    };
    let root = b"/";
    check!(
        unsafe {
            syscall(
                SYS_STATFS,
                root.as_ptr() as u64,
                root.len() as u64,
                &mut sbuf as *mut MuslStatfs as u64,
            )
        }
        .is_ok(),
        b"statfs(\"/\") failed"
    );
    check!(
        sbuf.f_bsize == 4096 && sbuf.f_blocks > 0 && sbuf.f_files > 0,
        b"statfs(\"/\") reported implausible values"
    );
    let sfd = open_ro(f1).expect("open for fstatfs");
    let mut sbuf2 = MuslStatfs {
        f_type: 0,
        f_bsize: 0,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: 0,
        f_ffree: 0,
        f_fsid: [0, 0],
        f_namelen: 0,
        f_frsize: 0,
        f_flags: 0,
        f_spare: [0; 4],
    };
    check!(
        unsafe { syscall(SYS_FSTATFS, sfd, &mut sbuf2 as *mut MuslStatfs as u64, 0) }.is_ok(),
        b"fstatfs failed"
    );
    close(sfd);
    check!(
        sbuf2.f_bsize == sbuf.f_bsize && sbuf2.f_blocks == sbuf.f_blocks,
        b"fstatfs disagreed with statfs on the same live filesystem"
    );
    write_bytes(b"needs-syscall-smoke: statfs/fstatfs OK\n");

    // --- prlimit64: real read-old/write-new round trip, RLIM_INFINITY default. ---
    let mut old = RawRlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    check!(
        unsafe {
            syscall4(
                SYS_PRLIMIT64,
                0,
                RLIMIT_NOFILE,
                0,
                &mut old as *mut RawRlimit as u64,
            )
        }
        .is_ok(),
        b"prlimit64 initial read failed"
    );
    check!(
        old.rlim_cur == u64::MAX && old.rlim_max == u64::MAX,
        b"prlimit64 default wasn't RLIM_INFINITY"
    );
    let new = RawRlimit {
        rlim_cur: 100,
        rlim_max: 200,
    };
    check!(
        unsafe {
            syscall4(
                SYS_PRLIMIT64,
                0,
                RLIMIT_NOFILE,
                &new as *const RawRlimit as u64,
                0,
            )
        }
        .is_ok(),
        b"prlimit64 set failed"
    );
    let mut confirm = RawRlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    check!(
        unsafe {
            syscall4(
                SYS_PRLIMIT64,
                0,
                RLIMIT_NOFILE,
                0,
                &mut confirm as *mut RawRlimit as u64,
            )
        }
        .is_ok(),
        b"prlimit64 read-back failed"
    );
    check!(
        confirm.rlim_cur == 100 && confirm.rlim_max == 200,
        b"prlimit64 didn't round-trip the new value"
    );
    write_bytes(b"needs-syscall-smoke: prlimit64 OK\n");

    // --- setpriority/getpriority: real 20-nice return-value convention. ---
    check!(
        unsafe { syscall(SYS_SETPRIORITY, PRIO_PROCESS, 0, 5) }.is_ok(),
        b"setpriority failed"
    );
    check!(
        unsafe { syscall(SYS_GETPRIORITY, PRIO_PROCESS, 0, 0) } == Ok(15),
        b"getpriority didn't report 20 - nice"
    );
    write_bytes(b"needs-syscall-smoke: setpriority/getpriority OK\n");

    // --- sched_setscheduler/sched_getscheduler/sched_getparam round trip. ---
    let sp = RawSchedParam { sched_priority: 42 };
    check!(
        unsafe {
            syscall(
                SYS_SCHED_SETSCHEDULER,
                0,
                SCHED_FIFO,
                &sp as *const RawSchedParam as u64,
            )
        }
        .is_ok(),
        b"sched_setscheduler failed"
    );
    check!(
        unsafe { syscall(SYS_SCHED_GETSCHEDULER, 0, 0, 0) } == Ok(SCHED_FIFO),
        b"sched_getscheduler didn't report the policy just set"
    );
    let mut gp = RawSchedParam { sched_priority: 0 };
    check!(
        unsafe {
            syscall(
                SYS_SCHED_GETPARAM,
                0,
                &mut gp as *mut RawSchedParam as u64,
                0,
            )
        }
        .is_ok(),
        b"sched_getparam failed"
    );
    check!(
        gp.sched_priority == 42,
        b"sched_getparam didn't report the priority just set"
    );
    write_bytes(b"needs-syscall-smoke: sched_setscheduler/getscheduler/getparam OK\n");

    // --- sched_get_priority_max/min: fixed, policy-dependent ranges. ---
    check!(
        unsafe { syscall(SYS_SCHED_GET_PRIORITY_MAX, SCHED_FIFO, 0, 0) } == Ok(99),
        b"sched_get_priority_max(SCHED_FIFO) wasn't 99"
    );
    check!(
        unsafe { syscall(SYS_SCHED_GET_PRIORITY_MIN, SCHED_FIFO, 0, 0) } == Ok(1),
        b"sched_get_priority_min(SCHED_FIFO) wasn't 1"
    );
    check!(
        unsafe { syscall(SYS_SCHED_GET_PRIORITY_MAX, SCHED_OTHER, 0, 0) } == Ok(0),
        b"sched_get_priority_max(SCHED_OTHER) wasn't 0"
    );
    write_bytes(b"needs-syscall-smoke: sched_get_priority_max/min OK\n");

    write_bytes(b"needs-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
