//! Real-`SYSCALL` smoke test for the mount table added this pass: `SYS_MOUNT_BIND`/
//! `SYS_MOUNT_TMPFS`/`SYS_UMOUNT2` (`174`-`176`, `sys/modules/oxfs`) plus the `resolve_path_impl`
//! redirect, the tmpfs pool, `/proc/mounts`, and the `st_dev` split those rest on -- see
//! `sys/modules/oxfs/src/lib.rs`'s own "Mount table" section for the full design.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning every other real-`SYSCALL` smoke
//! test in this codebase documents (this feature's correctness depends on real per-process cwd/fd
//! state and the live `MOUNTS` table, not something a plain-Rust-function call exercises the same
//! way).
//!
//! Scenario, all through `tests/mount_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `mkdir /mnttest` and `mkdir /bindtest`, then `mount -t tmpfs` onto the first and
//!    `mount --bind /bin` onto the second.
//! 2. Read `/proc/mounts` and confirm both entries appear (`tmpfs`/`bind` substrings).
//! 3. Create+write+read a file inside the tmpfs mount, confirm its `stat` reports `st_dev == 2`
//!    (the tmpfs-pool marker), confirm `getdents` lists it.
//! 4. Confirm a known BusyBox applet (`ls`) is visible through the bind mount.
//! 5. `umount` both. A second `umount` of the same path now fails `EINVAL` (no longer a
//!    mountpoint). `stat`ing the tmpfs mountpoint again reports `st_dev == 1` (the real
//!    filesystem, unmodified underneath), `getdents` no longer shows the tmpfs file, and the
//!    applet is no longer reachable through the (now-empty, real) former bind-mount directory.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_READ: u64 = 3;
const SYS_STAT: u64 = 127;
const SYS_GETDENTS: u64 = 129;
const SYS_MKDIR: u64 = 136;
const SYS_MOUNT_BIND: u64 = 174;
const SYS_MOUNT_TMPFS: u64 = 175;
const SYS_UMOUNT2: u64 = 176;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// mount_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_CREAT: u64 = 0o100;
/// Real POSIX `open(2)` access-mode bit -- needed explicitly now that `sys/modules/oxfs`'s own
/// `oxfs_open` enforces the caller's real requested access mode even on a brand-new `O_CREAT`
/// file (`OpenFile::Write::readonly`, see that field's own doc comment) rather than always
/// granting write access regardless of what was actually asked for.
const O_WRONLY: u64 = 0o1;
/// Real value, matches `sys/modules/oxfs/src/lib.rs`'s own `EINVAL` -- identical on Linux/BSD/musl.
const EINVAL: u64 = 22;
/// Real value, matches `sys/modules/oxfs/src/lib.rs`'s own `ENOENT`.
const ENOENT: u64 = 2;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `mount --bind`'s own
/// `(source_ptr, source_len, target_ptr, target_len)`.
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

fn stat_dev(path: &[u8]) -> Option<u64> {
    let mut buf: [u8; 144] = [0; 144];
    unsafe { syscall(SYS_STAT, path.as_ptr() as u64, path.len() as u64, buf.as_mut_ptr() as u64) }
        .ok()?;
    Some(unsafe { (buf.as_ptr() as *const MuslStat).read_unaligned() }.st_dev)
}

/// Same wire format `regress/proc-smoke/src/main.rs`'s own `getdents_has_name` parses -- see that
/// file's doc comment for the exact record shape (`d_ino: u64, d_off: i64, d_reclen: u16,
/// d_type: u8, d_name: [u8; N]`).
fn getdents_has_name(buf: &[u8], name: &[u8]) -> bool {
    let mut off = 0usize;
    while off + 19 <= buf.len() {
        let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
        if reclen == 0 || off + reclen > buf.len() {
            break;
        }
        let name_start = off + 19;
        let mut name_end = name_start;
        while name_end < off + reclen && buf[name_end] != 0 {
            name_end += 1;
        }
        if &buf[name_start..name_end] == name {
            return true;
        }
        off += reclen;
    }
    false
}

fn list_dir(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    let fd = unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0) }.ok()?;
    let n =
        unsafe { syscall(SYS_GETDENTS, fd, buf.as_mut_ptr() as u64, buf.len() as u64) }.ok()?;
    let _ = unsafe { syscall(SYS_CLOSE, fd, 0, 0) };
    Some(n as usize)
}

/// Contains `needle` as a plain byte substring -- used to check `/proc/mounts` content without a
/// real string-search crate available in `no_std`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"mount-syscall-smoke: starting\n");

    let mnttest = b"/mnttest";
    let bindtest = b"/bindtest";
    let bin = b"/bin";

    if unsafe { syscall(SYS_MKDIR, mnttest.as_ptr() as u64, mnttest.len() as u64, 0o755) }.is_err()
        || unsafe { syscall(SYS_MKDIR, bindtest.as_ptr() as u64, bindtest.len() as u64, 0o755) }
            .is_err()
    {
        write_bytes(b"mount-syscall-smoke: mkdir failed\n");
        test_exit(false);
    }

    if unsafe {
        syscall(
            SYS_MOUNT_TMPFS,
            mnttest.as_ptr() as u64,
            mnttest.len() as u64,
            0,
        )
    }
    .is_err()
    {
        write_bytes(b"mount-syscall-smoke: mount -t tmpfs /mnttest failed\n");
        test_exit(false);
    }
    if unsafe {
        syscall4(
            SYS_MOUNT_BIND,
            bin.as_ptr() as u64,
            bin.len() as u64,
            bindtest.as_ptr() as u64,
            bindtest.len() as u64,
        )
    }
    .is_err()
    {
        write_bytes(b"mount-syscall-smoke: mount --bind /bin /bindtest failed\n");
        test_exit(false);
    }
    write_bytes(b"mount-syscall-smoke: both mounts established\n");

    // /proc/mounts should report both while they're active.
    let mounts_path = b"/proc/mounts";
    let Ok(mounts_fd) = (unsafe {
        syscall(
            SYS_OPEN,
            mounts_path.as_ptr() as u64,
            mounts_path.len() as u64,
            0,
        )
    }) else {
        write_bytes(b"mount-syscall-smoke: open /proc/mounts failed\n");
        test_exit(false);
    };
    let mut mounts_buf = [0u8; 512];
    let Ok(mounts_n) =
        (unsafe { syscall(SYS_READ, mounts_fd, mounts_buf.as_mut_ptr() as u64, 512) })
    else {
        write_bytes(b"mount-syscall-smoke: read /proc/mounts failed\n");
        test_exit(false);
    };
    let _ = unsafe { syscall(SYS_CLOSE, mounts_fd, 0, 0) };
    let mounts_content = &mounts_buf[..mounts_n as usize];
    if !contains(mounts_content, b"tmpfs") || !contains(mounts_content, b"bind") {
        write_bytes(b"mount-syscall-smoke: /proc/mounts missing an active entry\n");
        test_exit(false);
    }
    write_bytes(b"mount-syscall-smoke: /proc/mounts OK\n");

    // A file created inside the tmpfs mount is real, round-trips, and reports the tmpfs st_dev.
    let f = b"/mnttest/f";
    let Ok(fd) = (unsafe { syscall(SYS_OPEN, f.as_ptr() as u64, f.len() as u64, O_CREAT | O_WRONLY) })
    else {
        write_bytes(b"mount-syscall-smoke: create /mnttest/f failed\n");
        test_exit(false);
    };
    unsafe {
        let _ = syscall(SYS_WRITE, fd, b"hi".as_ptr() as u64, 2);
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }
    if stat_dev(f) != Some(2) {
        write_bytes(b"mount-syscall-smoke: /mnttest/f didn't report the tmpfs st_dev\n");
        test_exit(false);
    }
    let Ok(rfd) = (unsafe { syscall(SYS_OPEN, f.as_ptr() as u64, f.len() as u64, 0) }) else {
        write_bytes(b"mount-syscall-smoke: reopen /mnttest/f failed\n");
        test_exit(false);
    };
    let mut content = [0u8; 2];
    let read_ok = unsafe { syscall(SYS_READ, rfd, content.as_mut_ptr() as u64, 2) } == Ok(2)
        && &content == b"hi";
    let _ = unsafe { syscall(SYS_CLOSE, rfd, 0, 0) };
    if !read_ok {
        write_bytes(b"mount-syscall-smoke: /mnttest/f content didn't round-trip\n");
        test_exit(false);
    }
    let mut dbuf = [0u8; 512];
    let Some(dn) = list_dir(mnttest, &mut dbuf) else {
        write_bytes(b"mount-syscall-smoke: getdents /mnttest failed\n");
        test_exit(false);
    };
    if !getdents_has_name(&dbuf[..dn], b"f") {
        write_bytes(b"mount-syscall-smoke: /mnttest listing missing 'f'\n");
        test_exit(false);
    }
    write_bytes(b"mount-syscall-smoke: tmpfs mount read/write/getdents/st_dev OK\n");

    // A known applet is visible through the bind mount.
    let bind_ls = b"/bindtest/ls";
    let Ok(lsfd) =
        (unsafe { syscall(SYS_OPEN, bind_ls.as_ptr() as u64, bind_ls.len() as u64, 0) })
    else {
        write_bytes(b"mount-syscall-smoke: /bindtest/ls not visible through the bind mount\n");
        test_exit(false);
    };
    let _ = unsafe { syscall(SYS_CLOSE, lsfd, 0, 0) };
    write_bytes(b"mount-syscall-smoke: bind mount OK\n");

    // Unmount both. A repeat unmount of the same path now fails EINVAL.
    if unsafe { syscall(SYS_UMOUNT2, mnttest.as_ptr() as u64, mnttest.len() as u64, 0) }.is_err()
        || unsafe {
            syscall(
                SYS_UMOUNT2,
                bindtest.as_ptr() as u64,
                bindtest.len() as u64,
                0,
            )
        }
        .is_err()
    {
        write_bytes(b"mount-syscall-smoke: umount failed\n");
        test_exit(false);
    }
    if unsafe { syscall(SYS_UMOUNT2, mnttest.as_ptr() as u64, mnttest.len() as u64, 0) }
        != Err(EINVAL)
    {
        write_bytes(b"mount-syscall-smoke: repeat umount of /mnttest didn't fail EINVAL\n");
        test_exit(false);
    }

    // The real, empty directories underneath are what's exposed again -- not leftover tmpfs
    // content, and the bind-mounted applet is no longer reachable.
    if stat_dev(mnttest) != Some(1) {
        write_bytes(b"mount-syscall-smoke: /mnttest didn't revert to the real st_dev\n");
        test_exit(false);
    }
    let mut dbuf2 = [0u8; 512];
    let Some(dn2) = list_dir(mnttest, &mut dbuf2) else {
        write_bytes(b"mount-syscall-smoke: getdents /mnttest after umount failed\n");
        test_exit(false);
    };
    if getdents_has_name(&dbuf2[..dn2], b"f") {
        write_bytes(b"mount-syscall-smoke: /mnttest still shows tmpfs content after umount\n");
        test_exit(false);
    }
    if unsafe { syscall(SYS_OPEN, bind_ls.as_ptr() as u64, bind_ls.len() as u64, 0) }
        != Err(ENOENT)
    {
        write_bytes(b"mount-syscall-smoke: /bindtest/ls still reachable after umount\n");
        test_exit(false);
    }

    write_bytes(b"mount-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
