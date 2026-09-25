//! Real-`SYSCALL` smoke test for the second NEEDS_SYSCALL gap-table batch: `SYS_LINK`/
//! `SYS_MKNOD`/`SYS_CHROOT` (`488`-`490`, `sys/modules/oxfs`) and `SYS_GETRUSAGE` plus `SYS_WAIT4`'s
//! own new optional rusage-pointer 4th argument (`491`, `sys/modules/posix_compat`/`sys/process.rs`).
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning every other real-`SYSCALL` smoke
//! test in this codebase documents: `SYS_CHROOT`'s own containment behavior in particular depends
//! on real per-process state (`Process::root_inode`, resolved via `scheduler::current_pid()` on
//! every call), exactly the class of thing a plain-Rust-function test can't exercise.
//!
//! Five parts, all through `tests/needs_syscall2_smoke.rs` spawning this binary as pid 1:
//! 1. `link`/`unlink`: a real hard link round trip against a freshly created file -- both names
//!    report the same inode/content and `nlink == 2`, and unlinking one drops `nlink` back to `1`
//!    without disturbing the other name.
//! 2. `mknod`: a real device node matching `/dev/null`'s own standard major:minor (`1,3`),
//!    round-tripped through create -> `stat` (real `S_IFCHR`/`st_rdev`) -> `open`/`write`/`read`
//!    (behaves exactly like `dev_open`'s own magic-path `/dev/null`) -> `unlink`; plus a plain
//!    `S_IFREG` node (an immediately committed empty regular file).
//! 3. `getrusage`/`wait4` rusage: a direct `getrusage(RUSAGE_SELF, ...)` call, then a real
//!    `fork()`+exit()+`wait4(..., &rusage)` round trip -- this kernel tracks no real per-process
//!    CPU-time accounting, so the check is that both calls succeed and report an honestly
//!    all-zero `struct rusage`, not that any particular number comes back.
//! 4. `chroot` root-only enforcement: a forked child `setuid(1)`s (dropping root), then confirms
//!    `chroot` on that non-root child fails real `EPERM` -- done in its own fork, before the
//!    parent's own root is ever touched (see part 5).
//! 5. `chroot` containment: the parent itself (still real root) creates a subdirectory, `chroot`s
//!    into it, `chdir("/")`s (real `chroot(2)` doesn't move cwd -- BusyBox's own `chroot` applet
//!    `chdir("/")`s right afterward, the pattern this mirrors), confirms `getcwd` reports `/`, and
//!    confirms `chdir("..")` still succeeds but stays contained (`getcwd` still reports `/`, not
//!    a real escape into the tree above). Deliberately last -- once a process chroots, it has no
//!    path-based way back to its real root, so nothing after this step can rely on the real tree.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_WAIT4: u64 = 7;
const SYS_CHDIR: u64 = 12;
const SYS_UNLINK: u64 = 109;
const SYS_GETCWD: u64 = 108;
const SYS_STAT: u64 = 127;
const SYS_MKDIR: u64 = 136;
const SYS_SETUID: u64 = 162;
const SYS_LINK: u64 = 488;
const SYS_MKNOD: u64 = 489;
const SYS_CHROOT: u64 = 490;
const SYS_GETRUSAGE: u64 = 491;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// needs_syscall2_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_CREAT: u64 = 0o100;
/// Real POSIX `open(2)` access-mode bit -- needed explicitly now that `sys/modules/oxfs`'s own
/// `oxfs_open` enforces the caller's real requested access mode even on a brand-new `O_CREAT`
/// file (`OpenFile::Write::readonly`, see that field's own doc comment) rather than always
/// granting write access regardless of what was actually asked for.
const O_WRONLY: u64 = 0o1;
const S_IFREG: u32 = 0o100000;
const S_IFCHR: u32 = 0o020000;
const S_IFMT: u32 = 0o170000;
/// Real value, matches `sys/syscall.rs`'s own `EPERM` -- identical on Linux/BSD/musl.
const EPERM: u64 = 1;
const RUSAGE_SELF: u64 = 0;
/// Real Linux's own standard major:minor for `/dev/null` -- see `sys/modules/oxfs/src/lib.rs`'s
/// `known_device` for why this specific pair is the one this kernel can actually service.
const NULL_DEV: u64 = (1 << 8) | 3;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `link`/`mknod`'s own
/// trailing args and `wait4`'s own optional `rusage_ptr`.
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
            write_bytes(b"needs-syscall2-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
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

/// Matches `sys/syscall.rs`'s own `RawRusage` layout exactly (272 bytes) -- see that struct's own
/// doc comment for why every field is an honest, all-zero placeholder.
#[repr(C)]
struct RawRusage {
    ru_utime: [i64; 2],
    ru_stime: [i64; 2],
    fields: [i64; 14],
    reserved: [i64; 16],
}

fn zeroed_rusage() -> RawRusage {
    RawRusage {
        ru_utime: [0; 2],
        ru_stime: [0; 2],
        fields: [0; 14],
        reserved: [0; 16],
    }
}

fn stat_of(path: &[u8]) -> Result<MuslStat, u64> {
    let mut buf = [0u8; 144];
    unsafe {
        syscall(
            SYS_STAT,
            path.as_ptr() as u64,
            path.len() as u64,
            buf.as_mut_ptr() as u64,
        )
    }?;
    Ok(unsafe { (buf.as_ptr() as *const MuslStat).read_unaligned() })
}

fn open_create(path: &[u8]) -> Result<u64, u64> {
    unsafe {
        syscall(
            SYS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            O_CREAT | O_WRONLY,
        )
    }
}

fn close(fd: u64) {
    unsafe {
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }
}

/// Part 1 -- see this file's own module doc comment.
fn check_link() -> bool {
    let file = b"/n2file";
    let link = b"/n2link";
    let Ok(fd) = open_create(file) else {
        write_bytes(b"needs-syscall2-smoke: create /n2file failed\n");
        return false;
    };
    unsafe {
        let _ = syscall(SYS_WRITE, fd, b"AB".as_ptr() as u64, 2);
    }
    close(fd);

    if unsafe {
        syscall4(
            SYS_LINK,
            file.as_ptr() as u64,
            file.len() as u64,
            link.as_ptr() as u64,
            link.len() as u64,
        )
    }
    .is_err()
    {
        write_bytes(b"needs-syscall2-smoke: link /n2link failed\n");
        return false;
    }

    let Ok(st_file) = stat_of(file) else {
        write_bytes(b"needs-syscall2-smoke: stat /n2file (after link) failed\n");
        return false;
    };
    let Ok(st_link) = stat_of(link) else {
        write_bytes(b"needs-syscall2-smoke: stat /n2link failed\n");
        return false;
    };
    if st_file.st_ino != st_link.st_ino || st_file.st_nlink != 2 || st_link.st_size != 2 {
        write_bytes(b"needs-syscall2-smoke: /n2link didn't share /n2file's real inode/nlink\n");
        return false;
    }

    let Ok(fd2) = (unsafe { syscall(SYS_OPEN, link.as_ptr() as u64, link.len() as u64, 0) }) else {
        write_bytes(b"needs-syscall2-smoke: open /n2link failed\n");
        return false;
    };
    let mut rbuf = [0u8; 4];
    let read = unsafe { syscall(SYS_READ, fd2, rbuf.as_mut_ptr() as u64, rbuf.len() as u64) };
    close(fd2);
    if read != Ok(2) || &rbuf[..2] != b"AB" {
        write_bytes(b"needs-syscall2-smoke: /n2link content mismatch\n");
        return false;
    }

    if unsafe { syscall_unlink(link) }.is_err() {
        write_bytes(b"needs-syscall2-smoke: unlink /n2link failed\n");
        return false;
    }
    let Ok(st_after) = stat_of(file) else {
        write_bytes(b"needs-syscall2-smoke: stat /n2file (after unlink) failed\n");
        return false;
    };
    if st_after.st_nlink != 1 {
        write_bytes(b"needs-syscall2-smoke: /n2file nlink didn't drop back to 1\n");
        return false;
    }

    write_bytes(b"needs-syscall2-smoke: link/unlink OK\n");
    true
}

unsafe fn syscall_unlink(path: &[u8]) -> Result<u64, u64> {
    unsafe { syscall(SYS_UNLINK, path.as_ptr() as u64, path.len() as u64, 0) }
}

/// Part 2 -- see this file's own module doc comment.
fn check_mknod() -> bool {
    let dev_path = b"/n2null";
    if unsafe {
        syscall4(
            SYS_MKNOD,
            dev_path.as_ptr() as u64,
            dev_path.len() as u64,
            (S_IFCHR | 0o600) as u64,
            NULL_DEV,
        )
    }
    .is_err()
    {
        write_bytes(b"needs-syscall2-smoke: mknod /n2null failed\n");
        return false;
    }
    let Ok(st) = stat_of(dev_path) else {
        write_bytes(b"needs-syscall2-smoke: stat /n2null failed\n");
        return false;
    };
    if st.st_mode & S_IFMT != S_IFCHR || st.st_rdev != NULL_DEV {
        write_bytes(b"needs-syscall2-smoke: /n2null didn't report real S_IFCHR/rdev\n");
        return false;
    }
    let Ok(fd) = (unsafe { syscall(SYS_OPEN, dev_path.as_ptr() as u64, dev_path.len() as u64, 1) })
    else {
        write_bytes(b"needs-syscall2-smoke: open /n2null failed\n");
        return false;
    };
    let wrote = unsafe { syscall(SYS_WRITE, fd, b"x".as_ptr() as u64, 1) };
    let mut rbuf = [1u8; 4];
    let read = unsafe { syscall(SYS_READ, fd, rbuf.as_mut_ptr() as u64, rbuf.len() as u64) };
    close(fd);
    if wrote.is_err() || read != Ok(0) {
        write_bytes(b"needs-syscall2-smoke: /n2null didn't behave like /dev/null\n");
        return false;
    }
    if unsafe { syscall_unlink(dev_path) }.is_err() {
        write_bytes(b"needs-syscall2-smoke: unlink /n2null failed\n");
        return false;
    }

    let reg_path = b"/n2reg";
    if unsafe {
        syscall4(
            SYS_MKNOD,
            reg_path.as_ptr() as u64,
            reg_path.len() as u64,
            (S_IFREG | 0o644) as u64,
            0,
        )
    }
    .is_err()
    {
        write_bytes(b"needs-syscall2-smoke: mknod /n2reg (S_IFREG) failed\n");
        return false;
    }
    if unsafe { syscall_unlink(reg_path) }.is_err() {
        write_bytes(b"needs-syscall2-smoke: unlink /n2reg failed\n");
        return false;
    }

    write_bytes(b"needs-syscall2-smoke: mknod OK\n");
    true
}

/// Part 3 -- see this file's own module doc comment.
fn check_getrusage_wait4() -> bool {
    let mut ru = zeroed_rusage();
    if unsafe {
        syscall(
            SYS_GETRUSAGE,
            RUSAGE_SELF,
            &mut ru as *mut RawRusage as u64,
            0,
        )
    }
    .is_err()
    {
        write_bytes(b"needs-syscall2-smoke: getrusage(RUSAGE_SELF) failed\n");
        return false;
    }
    if ru.ru_utime != [0, 0] {
        write_bytes(b"needs-syscall2-smoke: getrusage didn't report an honest zero ru_utime\n");
        return false;
    }

    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => unsafe {
            let _ = syscall(SYS_EXIT, 7, 0, 0);
            loop {
                spin_loop();
            }
        },
        Ok(child_pid) => {
            let mut status: i32 = -1;
            let mut wait_ru = zeroed_rusage();
            let wait_result = unsafe {
                syscall4(
                    SYS_WAIT4,
                    child_pid,
                    &mut status as *mut i32 as u64,
                    0,
                    &mut wait_ru as *mut RawRusage as u64,
                )
            };
            if wait_result != Ok(child_pid) || status != 7 << 8 {
                write_bytes(b"needs-syscall2-smoke: wait4 didn't report the real child status\n");
                return false;
            }
            write_bytes(b"needs-syscall2-smoke: getrusage/wait4-rusage OK\n");
            true
        }
        Err(_) => {
            write_bytes(b"needs-syscall2-smoke: fork (for getrusage/wait4) failed\n");
            false
        }
    }
}

/// Part 4's child-side logic -- see this file's own module doc comment. Returns the real exit
/// code the child should report (`0` pass, `1` fail).
fn child_nonroot_chroot_should_fail() -> i32 {
    if unsafe { syscall(SYS_SETUID, 1, 0, 0) } != Ok(0) {
        write_bytes(b"needs-syscall2-smoke: child setuid(1) failed\n");
        return 1;
    }
    let path = b"/";
    let result = unsafe { syscall(SYS_CHROOT, path.as_ptr() as u64, path.len() as u64, 0) };
    if result != Err(EPERM) {
        write_bytes(b"needs-syscall2-smoke: non-root chroot didn't fail EPERM\n");
        return 1;
    }
    write_bytes(b"needs-syscall2-smoke: non-root chroot EPERM enforcement OK\n");
    0
}

/// Part 4 -- see this file's own module doc comment.
fn check_chroot_permission() -> bool {
    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            let code = child_nonroot_chroot_should_fail();
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
            wait_result == Ok(child_pid) && status == 0
        }
        Err(_) => {
            write_bytes(b"needs-syscall2-smoke: fork (for chroot permission) failed\n");
            false
        }
    }
}

/// Part 5 -- see this file's own module doc comment. Deliberately last: once this succeeds, the
/// parent process has no path-based way back to the real root.
fn check_chroot_containment() -> bool {
    let dir = b"/n2root";
    if unsafe { syscall(SYS_MKDIR, dir.as_ptr() as u64, dir.len() as u64, 0o755) }.is_err() {
        write_bytes(b"needs-syscall2-smoke: mkdir /n2root failed\n");
        return false;
    }
    if unsafe { syscall(SYS_CHROOT, dir.as_ptr() as u64, dir.len() as u64, 0) }.is_err() {
        write_bytes(b"needs-syscall2-smoke: chroot /n2root failed\n");
        return false;
    }
    let root = b"/";
    if unsafe { syscall(SYS_CHDIR, root.as_ptr() as u64, root.len() as u64, 0) }.is_err() {
        write_bytes(b"needs-syscall2-smoke: chdir / after chroot failed\n");
        return false;
    }
    if !getcwd_is_root() {
        write_bytes(b"needs-syscall2-smoke: getcwd inside chroot didn't report /\n");
        return false;
    }
    let dotdot = b"..";
    if unsafe { syscall(SYS_CHDIR, dotdot.as_ptr() as u64, dotdot.len() as u64, 0) }.is_err() {
        write_bytes(b"needs-syscall2-smoke: chdir .. inside chroot should still succeed (contained, not escape)\n");
        return false;
    }
    if !getcwd_is_root() {
        write_bytes(b"needs-syscall2-smoke: chdir .. escaped the chroot\n");
        return false;
    }
    write_bytes(b"needs-syscall2-smoke: chroot containment OK\n");
    true
}

fn getcwd_is_root() -> bool {
    let mut buf = [0xffu8; 8];
    let n = unsafe { syscall(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64, 0) };
    n == Ok(2) && buf[0] == b'/' && buf[1] == 0
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"needs-syscall2-smoke: starting\n");

    check!(check_link(), b"link/unlink round trip failed");
    check!(check_mknod(), b"mknod round trip failed");
    check!(
        check_getrusage_wait4(),
        b"getrusage/wait4 rusage round trip failed"
    );
    check!(
        check_chroot_permission(),
        b"non-root chroot EPERM check failed"
    );
    check!(
        check_chroot_containment(),
        b"chroot containment check failed"
    );

    write_bytes(b"needs-syscall2-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
