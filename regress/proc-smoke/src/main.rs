//! Real-`SYSCALL` counterpart to this session's `/proc` completion pass (system-wide files,
//! per-fd enumeration, chdir into `/proc`, and real symlinks) -- exercised directly at boot by
//! `sys/modules/oxfs`'s own self-check for everything that doesn't need a real live process, but that
//! self-check runs as pid 0 (`BOOT_CWD`, no real process table entry) before any process exists,
//! so it can't cover `/proc/<pid>/...` navigation at all. This binary is spawned as a real pid 1
//! by `tests/proc_smoke.rs`, exactly like `regress/fork-exec-smoke` is spawned by
//! `tests/fork_wait.rs`, so every step below drives `open`/`chdir`/`getcwd`/`getdents`/`mkdir`
//! through a genuine `SYSCALL`/`SYSRETQ`, not a plain Rust function call -- the same class of
//! blind spot CLAUDE.md's "Real networking" section already found and closed for the network
//! smoke tests.
//!
//! The syscall numbers/register convention here must match `sys/syscall.rs`/`sys/modules/oxfs/src/
//! lib.rs` in the kernel exactly -- there's no shared crate between the two, this is the ABI
//! boundary itself, same as every other `regress/*` crate.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_CHDIR: u64 = 12;
const SYS_GETPID: u64 = 20;
const SYS_GETCWD: u64 = 108;
const SYS_MKDIR: u64 = 136;
const SYS_GETDENTS: u64 = 129;
/// Not a real syscall number anything else in this codebase registers -- `tests/proc_smoke.rs`
/// registers this one directly against a test-only handler, same convention `tests/fork_wait.rs`
/// established.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
/// musl's own real compiled value (see `sys/modules/oxfs/src/lib.rs`'s own `EROFS` constant and its
/// doc comment on why this must match musl's header, not a real-BSD nod).
const EROFS: u64 = 30;

/// Issues a syscall via `SYSCALL`; see `regress/stsh/src/main.rs`'s identical helper for the full
/// doc comment (carry-flag convention, `rcx`/`r11` clobbered by `SYSCALL` itself). Delegates to
/// `syscall4` with a zeroed 4th argument.
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

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

/// Appends `value`'s decimal digits (no leading zeros; a real pid is never `0`) into `buf` at
/// `pos`, returning the new position -- this crate's own equivalent of `sys/modules/oxfs`'s
/// `decimal_into`, duplicated rather than shared since there's no crate boundary between userland
/// and the kernel to share it across.
fn push_decimal(buf: &mut [u8], pos: usize, value: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[pos + i] = digits[n - 1 - i];
    }
    pos + n
}

/// Walks a real `getdents(2)` record buffer looking for `name` -- parses the exact wire format
/// `sys/modules/oxfs`'s own `write_dirent_record` produces (`d_ino: u64, d_off: i64, d_reclen: u16,
/// d_type: u8, d_name: [u8; N]`, NUL-padded to `d_reclen`), independently of that implementation
/// (this test builds its own understanding of the wire format, not by calling into the code it's
/// verifying).
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let Ok(pid) = (unsafe { syscall(SYS_GETPID, 0, 0, 0) }) else {
        write_bytes(b"proc-smoke: getpid() failed\n");
        test_exit(false);
    };

    // "/proc/<pid>", built once and reused as both an absolute path and a comparison target.
    let mut pid_path = [0u8; 32];
    pid_path[..6].copy_from_slice(b"/proc/");
    let pid_path_len = push_decimal(&mut pid_path, 6, pid);

    // --- Absolute /proc/<pid>/fd listing -- fds 0/1/2 (stdin/stdout/stderr, inherited from the
    // --- boot process) must be present. The per-fd enumeration gap, closed. ---
    let mut fd_path = [0u8; 40];
    fd_path[..pid_path_len].copy_from_slice(&pid_path[..pid_path_len]);
    fd_path[pid_path_len..pid_path_len + 3].copy_from_slice(b"/fd");
    let fd_path_len = pid_path_len + 3;

    let Ok(dfd) = (unsafe { syscall(SYS_OPEN, fd_path.as_ptr() as u64, fd_path_len as u64, 0) })
    else {
        write_bytes(b"proc-smoke: open /proc/<pid>/fd failed\n");
        test_exit(false);
    };
    let mut dbuf = [0u8; 512];
    let Ok(n) =
        (unsafe { syscall(SYS_GETDENTS, dfd, dbuf.as_mut_ptr() as u64, dbuf.len() as u64) })
    else {
        write_bytes(b"proc-smoke: getdents /proc/<pid>/fd failed\n");
        test_exit(false);
    };
    let listing = &dbuf[..n as usize];
    if !getdents_has_name(listing, b"0")
        || !getdents_has_name(listing, b"1")
        || !getdents_has_name(listing, b"2")
    {
        write_bytes(b"proc-smoke: /proc/<pid>/fd missing 0/1/2\n");
        test_exit(false);
    }
    let _ = unsafe { syscall(SYS_CLOSE, dfd, 0, 0) };
    write_bytes(b"proc-smoke: /proc/<pid>/fd enumeration verified\n");

    // --- Absolute chdir into /proc/<pid>, getcwd matches. The chdir gap, closed. ---
    if unsafe { syscall(SYS_CHDIR, pid_path.as_ptr() as u64, pid_path_len as u64, 0) }.is_err() {
        write_bytes(b"proc-smoke: chdir /proc/<pid> failed\n");
        test_exit(false);
    }
    let mut cwd_buf = [0u8; 64];
    let Ok(n) =
        (unsafe { syscall(SYS_GETCWD, cwd_buf.as_mut_ptr() as u64, cwd_buf.len() as u64, 0) })
    else {
        write_bytes(b"proc-smoke: getcwd inside /proc/<pid> failed\n");
        test_exit(false);
    };
    if cwd_buf[..(n as usize - 1)] != pid_path[..pid_path_len] {
        write_bytes(b"proc-smoke: getcwd inside /proc/<pid> mismatch\n");
        test_exit(false);
    }
    write_bytes(b"proc-smoke: chdir /proc/<pid> + getcwd verified\n");

    // --- Relative open("stat")/open("cmdline") must match the equivalent absolute reads. ---
    for leaf in [b"stat".as_slice(), b"cmdline".as_slice()] {
        let Ok(rfd) = (unsafe { syscall(SYS_OPEN, leaf.as_ptr() as u64, leaf.len() as u64, 0) })
        else {
            write_bytes(b"proc-smoke: relative open(stat/cmdline) failed\n");
            test_exit(false);
        };
        let mut abs_leaf_path = [0u8; 48];
        abs_leaf_path[..pid_path_len].copy_from_slice(&pid_path[..pid_path_len]);
        abs_leaf_path[pid_path_len] = b'/';
        abs_leaf_path[pid_path_len + 1..pid_path_len + 1 + leaf.len()].copy_from_slice(leaf);
        let abs_len = pid_path_len + 1 + leaf.len();
        let Ok(afd) =
            (unsafe { syscall(SYS_OPEN, abs_leaf_path.as_ptr() as u64, abs_len as u64, 0) })
        else {
            write_bytes(b"proc-smoke: absolute open(stat/cmdline) failed\n");
            test_exit(false);
        };
        let mut rbuf = [0u8; 512];
        let mut abuf = [0u8; 512];
        let rn = unsafe { syscall(SYS_READ, rfd, rbuf.as_mut_ptr() as u64, rbuf.len() as u64) };
        let an = unsafe { syscall(SYS_READ, afd, abuf.as_mut_ptr() as u64, abuf.len() as u64) };
        let _ = unsafe { syscall(SYS_CLOSE, rfd, 0, 0) };
        let _ = unsafe { syscall(SYS_CLOSE, afd, 0, 0) };
        if rn.is_err() || rn != an || rbuf != abuf {
            write_bytes(b"proc-smoke: relative/absolute stat|cmdline content mismatch\n");
            test_exit(false);
        }
    }
    write_bytes(b"proc-smoke: relative stat/cmdline reads verified\n");

    // --- Relative chdir("fd"), relative listing matches the earlier absolute one. ---
    let fd_rel = b"fd";
    if unsafe { syscall(SYS_CHDIR, fd_rel.as_ptr() as u64, fd_rel.len() as u64, 0) }.is_err() {
        write_bytes(b"proc-smoke: relative chdir(fd) failed\n");
        test_exit(false);
    }
    let empty = b"";
    let Ok(dfd2) = (unsafe { syscall(SYS_OPEN, empty.as_ptr() as u64, 0, 0) }) else {
        write_bytes(b"proc-smoke: relative open(\"\") inside fd dir failed\n");
        test_exit(false);
    };
    let mut dbuf2 = [0u8; 512];
    let n2_result =
        unsafe { syscall(SYS_GETDENTS, dfd2, dbuf2.as_mut_ptr() as u64, dbuf2.len() as u64) };
    let _ = unsafe { syscall(SYS_CLOSE, dfd2, 0, 0) };
    let Ok(n2) = n2_result else {
        write_bytes(b"proc-smoke: relative getdents inside fd dir failed\n");
        test_exit(false);
    };
    let listing2 = &dbuf2[..n2 as usize];
    if !getdents_has_name(listing2, b"0")
        || !getdents_has_name(listing2, b"1")
        || !getdents_has_name(listing2, b"2")
    {
        write_bytes(b"proc-smoke: relative fd listing missing 0/1/2\n");
        test_exit(false);
    }
    write_bytes(b"proc-smoke: relative chdir(fd) + listing verified\n");

    // --- chdir("..") twice -> back at /proc's own root -> relative open(meminfo). ---
    let dotdot = b"..";
    let up1 = unsafe { syscall(SYS_CHDIR, dotdot.as_ptr() as u64, dotdot.len() as u64, 0) };
    let up2 = unsafe { syscall(SYS_CHDIR, dotdot.as_ptr() as u64, dotdot.len() as u64, 0) };
    if up1.is_err() || up2.is_err() {
        write_bytes(b"proc-smoke: chdir .. (x2) back to /proc root failed\n");
        test_exit(false);
    }
    let meminfo = b"meminfo";
    let Ok(mfd) = (unsafe { syscall(SYS_OPEN, meminfo.as_ptr() as u64, meminfo.len() as u64, 0) })
    else {
        write_bytes(b"proc-smoke: relative open(meminfo) at /proc root failed\n");
        test_exit(false);
    };
    let mut mbuf = [0u8; 256];
    let mn_result = unsafe { syscall(SYS_READ, mfd, mbuf.as_mut_ptr() as u64, mbuf.len() as u64) };
    let _ = unsafe { syscall(SYS_CLOSE, mfd, 0, 0) };
    let Ok(mn) = mn_result else {
        write_bytes(b"proc-smoke: read relative meminfo failed\n");
        test_exit(false);
    };
    let needle = b"MemTotal";
    if !mbuf[..mn as usize].windows(needle.len()).any(|w| w == needle) {
        write_bytes(b"proc-smoke: relative /proc/meminfo missing MemTotal\n");
        test_exit(false);
    }
    write_bytes(b"proc-smoke: chdir .. (x2) + relative meminfo verified\n");

    // --- mkdir relative while cwd is still inside /proc must fail with EROFS. ---
    let x = b"x";
    let mkdir_result = unsafe { syscall(SYS_MKDIR, x.as_ptr() as u64, x.len() as u64, 0o755) };
    if mkdir_result != Err(EROFS) {
        write_bytes(b"proc-smoke: mkdir inside /proc should have failed with EROFS\n");
        test_exit(false);
    }
    write_bytes(b"proc-smoke: EROFS guard verified\n");

    // --- chdir back to the real root -- a real filesystem op must still work cleanly. ---
    let root = b"/";
    if unsafe { syscall(SYS_CHDIR, root.as_ptr() as u64, root.len() as u64, 0) }.is_err() {
        write_bytes(b"proc-smoke: chdir / failed\n");
        test_exit(false);
    }
    let real_path = b"/hello.txt";
    let Ok(real_fd) =
        (unsafe { syscall(SYS_OPEN, real_path.as_ptr() as u64, real_path.len() as u64, 0) })
    else {
        write_bytes(b"proc-smoke: real open /hello.txt after leaving /proc failed\n");
        test_exit(false);
    };
    let _ = unsafe { syscall(SYS_CLOSE, real_fd, 0, 0) };
    write_bytes(b"proc-smoke: real filesystem access after leaving /proc verified -- PASS\n");

    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
