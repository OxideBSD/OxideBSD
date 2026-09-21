//! Real-`SYSCALL` smoke test for `SYS_ACCESS = 21` (`sys/modules/oxfs`'s `oxfs_access`) -- real
//! `access(2)`, kept at musl's own inert `__NR_access` value rather than one of this ABI's own
//! invented numbers (see `oxfs_access`'s own doc comment in the OxideBSD tree).
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same "distrust anything that depends on real
//! per-process state" reasoning `regress/uid-syscall-smoke/src/main.rs`'s own module doc comment
//! already gives (`oxidebsd_current_uid`/`_gid` here, resolved via `scheduler::current_pid()` on
//! every call).
//!
//! Three parts, all through `tests/access_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. As root: `F_OK`/`R_OK` (singly and combined with `W_OK`/`X_OK`) against `/hello.txt` (a
//!    real seeded file, mode `0o755`) all succeed -- root bypasses every bit. `F_OK` against a
//!    nonexistent path fails real `ENOENT`.
//! 2. Still as root: create `/accesstest`, `chmod` it to `0o600`, `chown` it to uid `99`.
//! 3. `fork()`, then in the child: `setuid(1)` (a real non-root uid), then `access(/accesstest,
//!    F_OK)` still succeeds (real POSIX semantics -- `F_OK` never consults permission bits, only
//!    existence), but `access(/accesstest, R_OK)` fails real `EACCES` -- the one check in this
//!    whole test that exercises `check_access` denying something for real, not just the
//!    always-true root-bypass path every earlier step ran through. The parent `wait4()`s the
//!    child and checks its real exit code.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_WAIT4: u64 = 7;
const SYS_ACCESS: u64 = 21;
const SYS_SETUID: u64 = 162;
const SYS_CHMOD: u64 = 165;
const SYS_CHOWN: u64 = 166;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// access_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_CREAT: u64 = 0o100;
/// Real POSIX `open(2)` access-mode bit -- needed explicitly now that `sys/modules/oxfs`'s own
/// `oxfs_open` enforces the caller's real requested access mode even on a brand-new `O_CREAT`
/// file (`OpenFile::Write::readonly`, see that field's own doc comment) rather than always
/// granting write access regardless of what was actually asked for.
const O_WRONLY: u64 = 0o1;
/// Real POSIX `access(2)` `amode` bits -- see `sys/modules/oxfs/src/lib.rs`'s own `check_access` doc
/// comment for why these need no translation at the kernel boundary.
const F_OK: u64 = 0;
const X_OK: u64 = 1;
const W_OK: u64 = 2;
const R_OK: u64 = 4;
/// Real value, matches `sys/syscall.rs`'s own `ENOENT`; identical on Linux/BSD/musl.
const ENOENT: u64 = 2;
/// Real value, matches `sys/syscall.rs`'s own `EACCES` copy in `sys/modules/oxfs`; identical on
/// Linux/BSD/musl.
const EACCES: u64 = 13;
/// Real POSIX `(uid_t)-1`/`(gid_t)-1` "leave this field unchanged" sentinel, as it arrives
/// truncated through this ABI's `u64` register.
const LEAVE_UNCHANGED: u64 = u32::MAX as u64;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `chown`'s own `gid`.
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

fn access(path: &[u8], amode: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_ACCESS, path.as_ptr() as u64, path.len() as u64, amode) }
}

/// Part 1 -- see this file's own module doc comment. Returns `false` (without exiting) on any
/// failed check.
fn check_root_access() -> bool {
    let hello = b"/hello.txt";
    if access(hello, F_OK) != Ok(0) {
        write_bytes(b"access-syscall-smoke: F_OK against /hello.txt failed\n");
        return false;
    }
    if access(hello, R_OK) != Ok(0) {
        write_bytes(b"access-syscall-smoke: R_OK against /hello.txt failed\n");
        return false;
    }
    if access(hello, R_OK | W_OK | X_OK) != Ok(0) {
        write_bytes(b"access-syscall-smoke: R_OK|W_OK|X_OK against /hello.txt failed\n");
        return false;
    }
    if access(b"/does-not-exist-xyz", F_OK) != Err(ENOENT) {
        write_bytes(b"access-syscall-smoke: F_OK against a missing path didn't fail ENOENT\n");
        return false;
    }

    write_bytes(b"access-syscall-smoke: root F_OK/R_OK checks OK\n");
    true
}

/// Part 2 -- see this file's own module doc comment.
fn setup_accesstest() -> bool {
    let path = b"/accesstest";
    let fd = unsafe {
        syscall(
            SYS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            O_CREAT | O_WRONLY,
        )
    };
    let Ok(fd) = fd else {
        write_bytes(b"access-syscall-smoke: creating /accesstest failed\n");
        return false;
    };
    unsafe {
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }

    if unsafe { syscall(SYS_CHMOD, path.as_ptr() as u64, path.len() as u64, 0o600) }.is_err() {
        write_bytes(b"access-syscall-smoke: chmod /accesstest failed\n");
        return false;
    }
    if unsafe { syscall4(SYS_CHOWN, path.as_ptr() as u64, path.len() as u64, 99, LEAVE_UNCHANGED) }
        .is_err()
    {
        write_bytes(b"access-syscall-smoke: chown /accesstest failed\n");
        return false;
    }

    write_bytes(b"access-syscall-smoke: /accesstest set up as 0600, owned by uid 99\n");
    true
}

/// Part 3's child-side logic -- see this file's own module doc comment. Returns the real exit
/// code the child should report (`0` pass, `1` fail).
fn child_check_enforcement() -> i32 {
    if unsafe { syscall(SYS_SETUID, 1, 0, 0) } != Ok(0) {
        write_bytes(b"access-syscall-smoke: child setuid(1) as root failed\n");
        return 1;
    }

    let path = b"/accesstest";
    if access(path, F_OK) != Ok(0) {
        write_bytes(
            b"access-syscall-smoke: child F_OK against a 0600-root-unowned file should still succeed\n",
        );
        return 1;
    }
    if access(path, R_OK) != Err(EACCES) {
        write_bytes(b"access-syscall-smoke: child R_OK against /accesstest didn't fail EACCES\n");
        return 1;
    }

    write_bytes(b"access-syscall-smoke: child F_OK-still-succeeds + R_OK-EACCES enforcement OK\n");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"access-syscall-smoke: starting\n");

    if !check_root_access() {
        test_exit(false);
    }
    if !setup_accesstest() {
        test_exit(false);
    }

    write_bytes(b"access-syscall-smoke: forking for the enforcement check\n");
    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            let code = child_check_enforcement();
            unsafe {
                let _ = syscall(SYS_EXIT, code as u64, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            let mut status: i32 = -1;
            let wait_result =
                unsafe { syscall(SYS_WAIT4, child_pid, &mut status as *mut i32 as u64, 0) };
            let ok = wait_result == Ok(child_pid) && status == 0;
            if ok {
                write_bytes(b"access-syscall-smoke: PASS\n");
            } else {
                write_bytes(b"access-syscall-smoke: FAIL\n");
            }
            test_exit(ok);
        }
        Err(_) => {
            write_bytes(b"access-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
