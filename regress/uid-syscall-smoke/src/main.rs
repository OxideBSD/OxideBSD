//! Real-`SYSCALL` smoke test for the permission model added this pass: `SYS_GETUID`/
//! `SYS_GETEUID`/`SYS_GETGID`/`SYS_GETEGID`/`SYS_SETUID`/`SYS_SETGID`/`SYS_GETGROUPS` (`158`-
//! `164`, `sys/modules/posix_compat`) and `SYS_CHMOD`/`SYS_CHOWN` (`165`/`166`, `sys/modules/oxfs`), plus
//! the real per-inode `mode`/`uid`/`gid` enforcement `oxfs_open` now performs.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- see `regress/itimer-syscall-smoke/src/main.rs`'s
//! own module doc comment for why this codebase specifically distrusts plain-Rust-function tests
//! for anything that depends on real per-process state (`Process::uid`/`gid` here, resolved via
//! `scheduler::current_pid()` on every call).
//!
//! Three parts, all through `tests/uid_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. As root (this kernel's only uid, since no login mechanism exists -- see `Process::uid`'s own
//!    doc comment): confirm `getuid`/`geteuid`/`getgid`/`getegid` all report `0`, and `getgroups`
//!    reports the single-element `[0]` list both the count-query (`size == 0`) and real-write
//!    (`size >= 1`) shapes expect.
//! 2. Still as root: create `/uidtest`, `chmod` it to `0o600`, `chown` it to uid `99` (leaving
//!    gid unchanged via the real `(gid_t)-1` sentinel), then `stat` it back and confirm both stuck.
//! 2b. Create `/uidtest_mode` via `open(O_CREAT, 0o600)` directly (no follow-up `chmod()`) and
//!    `stat` it back before ever calling `chmod` -- unlike part 2 above, which always `chmod()`s
//!    immediately after creating its file and so would pass even if `open(2)`'s own `mode`
//!    argument were silently discarded, this is the one check that actually proves a brand-new
//!    file's real requested creation mode lands on the inode by itself.
//! 3. `fork()`, then in the child: `setuid(1)` (root becoming a real non-root uid must succeed),
//!    confirm `getuid() == 1`, confirm `setuid(0)` now fails `EPERM` (no longer root), confirm
//!    `setuid(1)` (becoming itself) still succeeds as a real POSIX no-op, then attempt to `open`
//!    `/uidtest` for read -- the file is `0o600` and owned by uid `99`, neither the child's own
//!    uid (`1`) nor its unchanged gid (`0`, which doesn't match either, but the group bits are `0`
//!    regardless) grant it anything, so this must fail `EACCES`: the one check in this whole test
//!    that exercises `check_access` denying something for real, not just the always-true root-
//!    bypass path every earlier step ran through. The parent `wait4()`s the child and checks its
//!    real exit code (via the real `WEXITSTATUS` encoding -- see `sys/syscall.rs`'s
//!    `oxidebsd_sys_exit` doc comment -- for `0`, which is shift-invariant so this check needed no
//!    change when that encoding was fixed).
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
const SYS_STAT: u64 = 127;
const SYS_GETUID: u64 = 158;
const SYS_GETEUID: u64 = 159;
const SYS_GETGID: u64 = 160;
const SYS_GETEGID: u64 = 161;
const SYS_SETUID: u64 = 162;
const SYS_SETGID: u64 = 163;
const SYS_GETGROUPS: u64 = 164;
const SYS_CHMOD: u64 = 165;
const SYS_CHOWN: u64 = 166;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// uid_syscall_smoke.rs` registers this one directly against a test-only handler, same convention
/// every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_CREAT: u64 = 0o100;
/// Real POSIX `open(2)` access-mode bit -- needed explicitly now that `sys/modules/oxfs`'s own
/// `oxfs_open` enforces the caller's real requested access mode even on a brand-new `O_CREAT`
/// file (`OpenFile::Write::readonly`, see that field's own doc comment) rather than always
/// granting write access regardless of what was actually asked for.
const O_WRONLY: u64 = 0o1;
/// Real value, matches `sys/syscall.rs`'s own `EPERM` -- identical on Linux/BSD/musl.
const EPERM: u64 = 1;
/// Real value, matches `sys/syscall.rs`'s own `EACCES` copy in `sys/modules/oxfs` -- identical on
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

#[repr(C)]
struct MuslStat {
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

/// Part 1 -- see this file's own module doc comment. Returns `false` (without exiting) on any
/// failed check.
fn check_root_identity() -> bool {
    let uid = unsafe { syscall(SYS_GETUID, 0, 0, 0) };
    let euid = unsafe { syscall(SYS_GETEUID, 0, 0, 0) };
    let gid = unsafe { syscall(SYS_GETGID, 0, 0, 0) };
    let egid = unsafe { syscall(SYS_GETEGID, 0, 0, 0) };
    if uid != Ok(0) || euid != Ok(0) || gid != Ok(0) || egid != Ok(0) {
        write_bytes(b"uid-syscall-smoke: fresh process wasn't root\n");
        return false;
    }

    let count = unsafe { syscall(SYS_GETGROUPS, 0, 0, 0) };
    if count != Ok(1) {
        write_bytes(b"uid-syscall-smoke: getgroups(0, NULL) didn't report 1\n");
        return false;
    }
    let mut list: [u32; 1] = [0xffff_ffff];
    let n = unsafe { syscall(SYS_GETGROUPS, 1, list.as_mut_ptr() as u64, 0) };
    if n != Ok(1) || list[0] != 0 {
        write_bytes(b"uid-syscall-smoke: getgroups(1, &list) didn't report [0]\n");
        return false;
    }

    write_bytes(b"uid-syscall-smoke: root identity + getgroups OK\n");
    true
}

/// Part 2 -- see this file's own module doc comment.
fn check_chmod_chown() -> bool {
    let path = b"/uidtest";
    let fd = unsafe {
        syscall(
            SYS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            O_CREAT | O_WRONLY,
        )
    };
    let Ok(fd) = fd else {
        write_bytes(b"uid-syscall-smoke: creating /uidtest failed\n");
        return false;
    };
    unsafe {
        let _ = syscall(SYS_WRITE, fd, b"hi".as_ptr() as u64, 2);
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }

    if unsafe { syscall(SYS_CHMOD, path.as_ptr() as u64, path.len() as u64, 0o600) }.is_err() {
        write_bytes(b"uid-syscall-smoke: chmod /uidtest failed\n");
        return false;
    }
    if unsafe { syscall4(SYS_CHOWN, path.as_ptr() as u64, path.len() as u64, 99, LEAVE_UNCHANGED) }
        .is_err()
    {
        write_bytes(b"uid-syscall-smoke: chown /uidtest failed\n");
        return false;
    }

    let mut stat_buf: [u8; 144] = [0; 144];
    if unsafe {
        syscall(
            SYS_STAT,
            path.as_ptr() as u64,
            path.len() as u64,
            stat_buf.as_mut_ptr() as u64,
        )
    }
    .is_err()
    {
        write_bytes(b"uid-syscall-smoke: stat /uidtest failed\n");
        return false;
    }
    let st = unsafe { (stat_buf.as_ptr() as *const MuslStat).read_unaligned() };
    if st.st_mode & 0o777 != 0o600 || st.st_uid != 99 || st.st_gid != 0 {
        write_bytes(b"uid-syscall-smoke: /uidtest didn't reflect chmod/chown\n");
        return false;
    }

    write_bytes(b"uid-syscall-smoke: chmod/chown round-trip OK\n");
    true
}

/// Part 2b -- see this file's own module doc comment. Verifies `open(2)`'s own real `mode`
/// argument (threaded through as a real 4th syscall arg, `R10`) actually lands on a brand-new
/// inode by itself, with no `chmod()` involved.
fn check_open_creat_mode() -> bool {
    let path = b"/uidtest_mode";
    let fd = unsafe {
        syscall4(
            SYS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            O_CREAT | O_WRONLY,
            0o600,
        )
    };
    let Ok(fd) = fd else {
        write_bytes(b"uid-syscall-smoke: creating /uidtest_mode failed\n");
        return false;
    };
    // Committing (via close()) is what actually allocates the real inode `oxfs_open`'s deferred-
    // create design defers to -- the requested mode must have already been carried all the way
    // from the syscall's own 4th argument into `OpenFile::Write::mode` by this point.
    unsafe {
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }

    let mut stat_buf: [u8; 144] = [0; 144];
    if unsafe {
        syscall(
            SYS_STAT,
            path.as_ptr() as u64,
            path.len() as u64,
            stat_buf.as_mut_ptr() as u64,
        )
    }
    .is_err()
    {
        write_bytes(b"uid-syscall-smoke: stat /uidtest_mode failed\n");
        return false;
    }
    let st = unsafe { (stat_buf.as_ptr() as *const MuslStat).read_unaligned() };
    if st.st_mode & 0o777 != 0o600 {
        write_bytes(b"uid-syscall-smoke: /uidtest_mode's real mode wasn't honored at create time\n");
        return false;
    }

    write_bytes(b"uid-syscall-smoke: open(O_CREAT, mode) real mode honored OK\n");
    true
}

/// Part 3's child-side logic -- see this file's own module doc comment. Returns the real exit
/// code the child should report (`0` pass, `1` fail).
fn child_drop_privilege_and_check_enforcement() -> i32 {
    if unsafe { syscall(SYS_SETUID, 1, 0, 0) } != Ok(0) {
        write_bytes(b"uid-syscall-smoke: child setuid(1) as root failed\n");
        return 1;
    }
    if unsafe { syscall(SYS_GETUID, 0, 0, 0) } != Ok(1) {
        write_bytes(b"uid-syscall-smoke: child getuid() != 1 after setuid(1)\n");
        return 1;
    }
    if unsafe { syscall(SYS_SETUID, 0, 0, 0) } != Err(EPERM) {
        write_bytes(b"uid-syscall-smoke: child setuid(0) as non-root didn't fail EPERM\n");
        return 1;
    }
    if unsafe { syscall(SYS_SETUID, 1, 0, 0) } != Ok(0) {
        write_bytes(b"uid-syscall-smoke: child setuid(1) (self, no-op) failed\n");
        return 1;
    }

    let path = b"/uidtest";
    let open_result = unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0) };
    if open_result != Err(EACCES) {
        write_bytes(
            b"uid-syscall-smoke: child open of a 0600-root-owned file didn't fail EACCES\n",
        );
        return 1;
    }

    write_bytes(b"uid-syscall-smoke: child privilege-drop + EACCES enforcement OK\n");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"uid-syscall-smoke: starting\n");

    if !check_root_identity() {
        test_exit(false);
    }
    if !check_chmod_chown() {
        test_exit(false);
    }
    if !check_open_creat_mode() {
        test_exit(false);
    }

    write_bytes(b"uid-syscall-smoke: forking for the privilege-drop + enforcement check\n");
    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            let code = child_drop_privilege_and_check_enforcement();
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
                write_bytes(b"uid-syscall-smoke: PASS\n");
            } else {
                write_bytes(b"uid-syscall-smoke: FAIL\n");
            }
            test_exit(ok);
        }
        Err(_) => {
            write_bytes(b"uid-syscall-smoke: fork failed\n");
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
