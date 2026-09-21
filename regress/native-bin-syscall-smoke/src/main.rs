//! Real-`SYSCALL` smoke test for the 12 native `/bin` utilities (`bin/echo`, `bin/cat`, `bin/ls`,
//! ... -- see `lib/oxlibc`): spawned as pid 1 by `tests/native_bin_syscall_smoke.rs`, it runs each
//! one through a genuine `fork`+`execve`+`wait4` (so each is loaded as the real PIE it is, at a
//! kernel-chosen randomized bias) and checks exit status and, where it matters, the exact bytes
//! written to stdout (redirected to a file via `dup2`, the same thing a shell does).
//!
//! Covers the flag surface each utility actually promises, plus its main error paths.
#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_WAIT4: u64 = 7;
const SYS_CHDIR: u64 = 12;
const SYS_EXECVE: u64 = 59;
const SYS_DUP2: u64 = 106;
/// Not a real syscall number anything else registers -- `tests/native_bin_syscall_smoke.rs`
/// registers it against a handler that calls `exit_qemu`.
const SYS_TEST_EXIT: u64 = 9999;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;

const OUT: &[u8] = b"/out.txt";

#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

#[inline(always)]
unsafe fn syscall4(number: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> Result<u64, u64> {
    let ret: u64;
    let failed: u8;
    unsafe {
        asm!(
            "syscall",
            "setc {failed}",
            inlateout("rax") number => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            failed = out(reg_byte) failed,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    if failed != 0 { Err(ret) } else { Ok(ret) }
}

#[inline(always)]
unsafe fn syscall(number: u64, a0: u64, a1: u64, a2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, a0, a1, a2, 0) }
}

fn say(s: &[u8]) {
    unsafe {
        let _ = syscall(SYS_WRITE, 1, s.as_ptr() as u64, s.len() as u64);
    }
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

macro_rules! check {
    ($cond:expr, $label:expr) => {
        if !$cond {
            say(b"native-bin-syscall-smoke: FAIL: ");
            say($label);
            say(b"\n");
            test_exit(false);
        }
    };
}

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall(SYS_EXIT, code, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Runs `path` with `args` (`args[0]` is `argv[0]`), optionally with stdout redirected into the
/// file `out` (created/truncated, `dup2`'d onto fd 1 -- what a shell's `>` does). Returns the exit
/// code, or `-1` if the child was killed by a signal / anything else went wrong.
fn run(path: &[u8], args: &[&[u8]], out: Option<&[u8]>) -> i64 {
    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            if let Some(file) = out {
                let Ok(fd) = (unsafe {
                    syscall4(
                        SYS_OPEN,
                        file.as_ptr() as u64,
                        file.len() as u64,
                        O_WRONLY | O_CREAT | O_TRUNC,
                        0o644,
                    )
                }) else {
                    exit(126);
                };
                if unsafe { syscall(SYS_DUP2, fd, 1, 0) }.is_err() {
                    exit(126);
                }
            }
            let mut argv = [RawArgvEntry { ptr: 0, len: 0 }; 8];
            for (i, a) in args.iter().enumerate().take(7) {
                argv[i] = RawArgvEntry {
                    ptr: a.as_ptr() as u64,
                    len: a.len() as u64,
                };
            }
            const ENVP: &[u8] = b"PATH=/bin";
            let envp = [
                RawArgvEntry {
                    ptr: ENVP.as_ptr() as u64,
                    len: ENVP.len() as u64,
                },
                RawArgvEntry { ptr: 0, len: 0 },
            ];
            unsafe {
                let _ = syscall4(
                    SYS_EXECVE,
                    path.as_ptr() as u64,
                    path.len() as u64,
                    argv.as_ptr() as u64,
                    envp.as_ptr() as u64,
                );
            }
            exit(127);
        }
        Ok(pid) => {
            let mut status: i32 = -1;
            match unsafe { syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0) } {
                Ok(p) if p == pid && status & 0x7f == 0 => ((status >> 8) & 0xff) as i64,
                _ => -1,
            }
        }
        Err(_) => -1,
    }
}

/// Reads all of `path` into `buf`, returning the length (`None` if it can't be opened).
fn read_file(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    let fd =
        unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, O_RDONLY) }.ok()?;
    let mut len = 0;
    while len < buf.len() {
        match unsafe {
            syscall(
                SYS_READ,
                fd,
                buf[len..].as_mut_ptr() as u64,
                (buf.len() - len) as u64,
            )
        } {
            Ok(0) | Err(_) => break,
            Ok(n) => len += n as usize,
        }
    }
    unsafe {
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }
    Some(len)
}

/// Runs a utility with stdout redirected to `OUT`, requiring exit `0` and exactly `expected` bytes.
fn expect_out(path: &[u8], args: &[&[u8]], expected: &[u8], label: &[u8]) {
    let code = run(path, args, Some(OUT));
    check!(code == 0, label);
    let mut buf = [0u8; 512];
    let n = read_file(OUT, &mut buf);
    check!(n.is_some() && &buf[..n.unwrap()] == expected, label);
}

fn expect_ok(path: &[u8], args: &[&[u8]], label: &[u8]) {
    check!(run(path, args, None) == 0, label);
}

fn expect_fail(path: &[u8], args: &[&[u8]], label: &[u8]) {
    let code = run(path, args, None);
    check!(code > 0 && code != 127, label);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    say(b"native-bin-syscall-smoke: starting\n");

    // echo: words joined by spaces, -n suppresses the newline, only an exact leading -n is a flag.
    expect_out(
        b"/bin/echo",
        &[b"echo", b"hello", b"world"],
        b"hello world\n",
        b"echo words",
    );
    expect_out(
        b"/bin/echo",
        &[b"echo", b"-n", b"a", b"b"],
        b"a b",
        b"echo -n",
    );
    expect_out(
        b"/bin/echo",
        &[b"echo", b"-x"],
        b"-x\n",
        b"echo prints an unknown dash arg",
    );
    expect_out(b"/bin/echo", &[b"echo"], b"\n", b"echo with no args");

    // true / false
    check!(run(b"/bin/true", &[b"true"], None) == 0, b"true exits 0");
    check!(run(b"/bin/false", &[b"false"], None) == 1, b"false exits 1");

    // mkdir / mkdir -p
    expect_ok(b"/bin/mkdir", &[b"mkdir", b"/t"], b"mkdir");
    expect_fail(
        b"/bin/mkdir",
        &[b"mkdir", b"/t"],
        b"mkdir on an existing dir fails",
    );
    expect_ok(
        b"/bin/mkdir",
        &[b"mkdir", b"-p", b"/t/a/b/c"],
        b"mkdir -p nested",
    );
    expect_ok(
        b"/bin/mkdir",
        &[b"mkdir", b"-p", b"/t"],
        b"mkdir -p on an existing dir",
    );
    expect_ok(
        b"/bin/mkdir",
        &[b"mkdir", b"-p", b"/t/a/b/c"],
        b"mkdir -p is idempotent",
    );

    // touch / touch -c
    expect_ok(b"/bin/touch", &[b"touch", b"/t/f1"], b"touch creates");
    expect_ok(
        b"/bin/touch",
        &[b"touch", b"/t/f1"],
        b"touch on an existing file",
    );
    expect_ok(
        b"/bin/touch",
        &[b"touch", b"-c", b"/t/nope"],
        b"touch -c on a missing file",
    );
    expect_fail(
        b"/bin/cat",
        &[b"cat", b"/t/nope"],
        b"touch -c must not have created it",
    );

    // cat (and the file that everything below copies around)
    check!(
        run(b"/bin/echo", &[b"echo", b"content"], Some(b"/t/src.txt")) == 0,
        b"redirect echo into /t/src.txt"
    );
    expect_out(
        b"/bin/cat",
        &[b"cat", b"/t/src.txt"],
        b"content\n",
        b"cat a file",
    );
    expect_fail(
        b"/bin/cat",
        &[b"cat", b"/t/nope"],
        b"cat a missing file fails",
    );

    // cp / cp -r
    expect_ok(b"/bin/cp", &[b"cp", b"/t/src.txt", b"/t/dst.txt"], b"cp");
    expect_out(
        b"/bin/cat",
        &[b"cat", b"/t/dst.txt"],
        b"content\n",
        b"cp copied the content",
    );
    expect_ok(b"/bin/cp", &[b"cp", b"-r", b"/t/a", b"/t/a2"], b"cp -r");
    expect_out(
        b"/bin/ls",
        &[b"ls", b"/t/a2"],
        b"b\n",
        b"cp -r copied the tree",
    );
    expect_fail(
        b"/bin/cp",
        &[b"cp", b"/t/a", b"/t/a3"],
        b"cp of a dir without -r fails",
    );

    // mv, including into a directory
    expect_ok(b"/bin/mv", &[b"mv", b"/t/dst.txt", b"/t/moved.txt"], b"mv");
    expect_out(
        b"/bin/cat",
        &[b"cat", b"/t/moved.txt"],
        b"content\n",
        b"mv kept the content",
    );
    expect_fail(
        b"/bin/cat",
        &[b"cat", b"/t/dst.txt"],
        b"mv removed the old name",
    );
    expect_ok(
        b"/bin/mv",
        &[b"mv", b"/t/moved.txt", b"/t/a"],
        b"mv into a directory",
    );
    expect_out(
        b"/bin/cat",
        &[b"cat", b"/t/a/moved.txt"],
        b"content\n",
        b"mv landed in the dir",
    );

    // ln / ln -s
    expect_ok(b"/bin/ln", &[b"ln", b"/t/src.txt", b"/t/hard"], b"ln");
    expect_out(
        b"/bin/cat",
        &[b"cat", b"/t/hard"],
        b"content\n",
        b"hard link shares content",
    );
    expect_ok(
        b"/bin/ln",
        &[b"ln", b"-s", b"/t/src.txt", b"/t/soft"],
        b"ln -s",
    );
    expect_out(
        b"/bin/cat",
        &[b"cat", b"/t/soft"],
        b"content\n",
        b"symlink resolves",
    );

    // ls: sorted, -l, -a
    expect_out(
        b"/bin/ls",
        &[b"ls", b"/t"],
        b"a\na2\nf1\nhard\nsoft\nsrc.txt\n",
        b"ls lists sorted entries",
    );
    let code = run(b"/bin/ls", &[b"ls", b"-l", b"/t"], Some(OUT));
    let mut buf = [0u8; 1024];
    let n = read_file(OUT, &mut buf);
    check!(
        code == 0 && n.is_some() && buf.starts_with(b"d"),
        b"ls -l marks a directory with d"
    );
    let code = run(b"/bin/ls", &[b"ls", b"-a", b"/t"], Some(OUT));
    let all_len = read_file(OUT, &mut buf);
    check!(
        code == 0 && all_len.is_some_and(|n| n >= 26),
        b"ls -a lists at least everything ls does"
    );

    // pwd
    unsafe {
        let _ = syscall(SYS_CHDIR, b"/t".as_ptr() as u64, 2, 0);
    }
    expect_out(b"/bin/pwd", &[b"pwd"], b"/t\n", b"pwd reports the cwd");
    unsafe {
        let _ = syscall(SYS_CHDIR, b"/".as_ptr() as u64, 1, 0);
    }

    // rm: files, -f, refusing a dir without -r, -r, and never removing /
    expect_ok(b"/bin/rm", &[b"rm", b"/t/hard"], b"rm a file");
    expect_fail(b"/bin/cat", &[b"cat", b"/t/hard"], b"rm removed it");
    expect_fail(
        b"/bin/rm",
        &[b"rm", b"/t/nope"],
        b"rm of a missing file fails",
    );
    expect_ok(
        b"/bin/rm",
        &[b"rm", b"-f", b"/t/nope"],
        b"rm -f of a missing file",
    );
    expect_fail(
        b"/bin/rm",
        &[b"rm", b"/t/a2"],
        b"rm of a dir without -r fails",
    );
    expect_ok(b"/bin/rm", &[b"rm", b"-r", b"/t/a2"], b"rm -r");
    expect_out(
        b"/bin/ls",
        &[b"ls", b"/t"],
        b"a\nf1\nsoft\nsrc.txt\n",
        b"rm -r removed the whole tree",
    );
    expect_fail(b"/bin/rm", &[b"rm", b"-rf", b"/"], b"rm refuses /");
    expect_ok(
        b"/bin/rm",
        &[b"rm", b"-rf", b"/t"],
        b"rm -rf a populated tree",
    );
    expect_fail(b"/bin/ls", &[b"ls", b"/t"], b"the tree is gone");

    say(b"native-bin-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
