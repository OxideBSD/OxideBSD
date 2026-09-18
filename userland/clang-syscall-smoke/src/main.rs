//! Real-`SYSCALL` smoke test for OxideBSD's second real on-target compiler, Clang/LLVM
//! (`third_party/llvm-project`, see CLAUDE.md's Clang/LLVM port section): confirms `/bin/clang`,
//! seeded by `modules/oxfs`'s `format_fresh_filesystem` alongside `tcc`, can actually compile and
//! link a real C file on target -- not just launch. This is the real proof of the "cc1/as/ld as
//! separate binaries" subprocess-pipeline milestone CLAUDE.md names as the reason GCC/Clang were
//! historically unstarted: `clang`'s own driver internally forks `clang -cc1` (compile) then
//! `ld.lld` (link) as real, separate child processes -- not something this test wires up itself,
//! just something it has to survive.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning `tcc-syscall-smoke` documents.
//!
//! Two parts, both through `tests/clang_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `fork` + `execve` `/bin/clang -static -o /hello.elf /hello.c` (`/hello.c` seeded by oxfs's
//!    own `format_fresh_filesystem`, a real `printf`, not a bare `return` -- the same fixture
//!    `tcc-syscall-smoke` uses), `wait4` for a clean exit. Internally: `clang` forks `clang -cc1`
//!    to produce an object file, then forks `ld.lld` to link it against the compiler-rt builtins
//!    archive and musl's `libc.a` -- both real, separate `fork`+`execve`d children of the `clang`
//!    process this test's own child became, invisible to this file except in that they must all
//!    genuinely succeed for `wait4` to report a clean exit here.
//! 2. `fork` + `execve` the just-produced `/hello.elf`, `wait4` and check its exit status -- proves
//!    the *output* of a real on-target Clang compile+link is itself a real, runnable ELF.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_EXECVE: u64 = 59;
const SYS_ACCESS: u64 = 21;
const X_OK: u64 = 1;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// clang_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

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

/// Debug helper -- prints a signed decimal, no libc involved.
fn write_decimal(mut n: i32) {
    let mut buf = [0u8; 12];
    let mut i = buf.len();
    let neg = n < 0;
    if neg {
        n = -n;
    }
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    write_bytes(&buf[i..]);
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
            write_bytes(b"clang-syscall-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
}

/// Wire format for `SYS_EXECVE`'s optional third argument -- see `src/process.rs`'s
/// `RawArgvEntry` (the kernel-side counterpart this must match exactly: two `u64`s, `ptr` then
/// `len`). A sequence of these describes the *complete* argv[] array, starting at argv[0],
/// terminated by a `ptr == 0` entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

const MAX_ARGV: usize = 8;

/// `path` is the real fs path `execve` loads (`/bin/clang`, `/hello.elf`); `argv` is the complete
/// argv[] including argv[0]. Envp is a fixed, minimal `PATH=` (empty value, present) -- matches
/// `tcc-syscall-smoke`'s own precedent; harmless here since neither `clang` nor `hello.elf` call
/// `execvp`/care about `$PATH` at all.
fn execve(path: &[u8], argv: &[&[u8]]) -> Result<u64, u64> {
    let mut entries = [RawArgvEntry { ptr: 0, len: 0 }; MAX_ARGV + 1];
    for (i, arg) in argv.iter().enumerate() {
        entries[i] = RawArgvEntry {
            ptr: arg.as_ptr() as u64,
            len: arg.len() as u64,
        };
    }
    let argv_ptr = entries.as_ptr() as u64;
    const ENVP: &[u8] = b"PATH=";
    let envp_entries = [
        RawArgvEntry {
            ptr: ENVP.as_ptr() as u64,
            len: ENVP.len() as u64,
        },
        RawArgvEntry { ptr: 0, len: 0 },
    ];
    unsafe {
        syscall4(
            SYS_EXECVE,
            path.as_ptr() as u64,
            path.len() as u64,
            argv_ptr,
            envp_entries.as_ptr() as u64,
        )
    }
}

fn fork() -> Result<u64, u64> {
    unsafe { syscall(SYS_FORK, 0, 0, 0) }
}

fn wait4(pid: u64, status: &mut i32) -> Result<u64, u64> {
    unsafe { syscall(SYS_WAIT4, pid, status as *mut i32 as u64, 0) }
}

/// Forks, `execve`s `path`/`argv` in the child (exiting `127` on failure, matching the real shell
/// convention), `wait4`s in the parent. Returns whether the child exited cleanly with status `0`.
fn run_and_wait(path: &[u8], argv: &[&[u8]]) -> bool {
    match fork() {
        Ok(0) => {
            let _ = execve(path, argv);
            unsafe {
                let _ = syscall(SYS_EXIT, 127, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            let mut status: i32 = -1;
            let waited = wait4(child_pid, &mut status);
            if waited != Ok(child_pid) || status != 0 {
                write_bytes(b"clang-syscall-smoke: wait4 returned ");
                match waited {
                    Ok(p) => write_decimal(p as i32),
                    Err(e) => {
                        write_bytes(b"Err(");
                        write_decimal(e as i32);
                        write_bytes(b")");
                    }
                }
                write_bytes(b", status=");
                write_decimal(status);
                write_bytes(b"\n");
            }
            waited == Ok(child_pid) && status == 0
        }
        Err(_) => {
            write_bytes(b"clang-syscall-smoke: fork failed\n");
            false
        }
    }
}

/// Debug-only: isolates whether clang can even start up and print something trivial, before
/// blaming the real compile+link path.
fn check_version() -> bool {
    let ok = run_and_wait(b"/bin/clang", &[b"clang", b"--version"]);
    write_bytes(if ok {
        b"clang-syscall-smoke: --version OK\n"
    } else {
        b"clang-syscall-smoke: --version failed\n"
    });
    ok
}

/// Debug-only: isolates cc1 (compile) from ld.lld (link) -- does `-c` alone (no link) succeed?
fn check_compile_object_only() -> bool {
    let ok = run_and_wait(
        b"/bin/clang",
        &[b"clang", b"-v", b"-c", b"-o", b"/hello.o", b"/hello.c"],
    );
    write_bytes(if ok {
        b"clang-syscall-smoke: -c (object only) OK\n"
    } else {
        b"clang-syscall-smoke: -c (object only) failed\n"
    });
    ok
}

/// Debug-only: isolates ld.lld specifically -- links the already-compiled `/hello.o` (from
/// `check_compile_object_only`) directly, skipping the driver's own compile+link orchestration.
fn check_link_only() -> bool {
    let ok = run_and_wait(
        b"/bin/clang",
        &[b"clang", b"-v", b"-static", b"-o", b"/hello3.elf", b"/hello.o"],
    );
    write_bytes(if ok {
        b"clang-syscall-smoke: link-only OK\n"
    } else {
        b"clang-syscall-smoke: link-only failed\n"
    });
    ok
}

/// Debug-only: a deliberately-broken link (nonexistent input) should print a clear, guaranteed
/// error if diagnostic output reaches the console at all -- isolates "the link genuinely fails for
/// a real reason" from "diagnostic output never reaches this console for any clang/lld invocation".
fn check_deliberately_broken_link() -> bool {
    let ok = run_and_wait(
        b"/bin/clang",
        &[
            b"clang",
            b"-v",
            b"-static",
            b"-o",
            b"/broken.elf",
            b"/does-not-exist.o",
        ],
    );
    write_bytes(if ok {
        b"clang-syscall-smoke: BUG: broken link unexpectedly succeeded\n"
    } else {
        b"clang-syscall-smoke: broken link failed as expected (see above for any error text)\n"
    });
    ok
}

/// Debug-only: tests whether the output path matters -- lld's `FileOutputBuffer` typically
/// `mmap()`s its *output* file PROT_WRITE (unlike cc1's plain buffered writes for .o output), and
/// this kernel's real MAP_SHARED fd-backed mmap support may be scoped to /tmp,/dev/shm rather than
/// arbitrary oxfs files (see CLAUDE.md's "Real /tmp, /dev/shm, fd-backed mmap" section).
fn check_link_to_tmp() -> bool {
    let ok = run_and_wait(
        b"/bin/clang",
        &[
            b"clang",
            b"-v",
            b"-static",
            b"-o",
            b"/tmp/hello4.elf",
            b"/hello.o",
        ],
    );
    write_bytes(if ok {
        b"clang-syscall-smoke: link-to-/tmp OK\n"
    } else {
        b"clang-syscall-smoke: link-to-/tmp failed\n"
    });
    ok
}

/// Debug-only: raw `open()` on a path, bypassing clang/musl entirely -- confirms a file genuinely
/// exists (and is openable) rather than trusting clang's own (silent) diagnostics for this.
fn check_file_openable(path: &[u8]) {
    let result = unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0) };
    write_bytes(b"clang-syscall-smoke: open(");
    write_bytes(path);
    write_bytes(b") = ");
    match result {
        Ok(fd) => {
            write_decimal(fd as i32);
            write_bytes(b"\n");
            unsafe {
                let _ = syscall(SYS_CLOSE, fd, 0, 0);
            }
        }
        Err(e) => {
            write_bytes(b"Err(");
            write_decimal(e as i32);
            write_bytes(b")\n");
        }
    }
}

/// Debug-only: raw `access(path, X_OK)` -- clang's own `ld.lld` lookup
/// (`llvm::sys::fs::can_execute`) uses exactly this syscall, distinct from a plain `open()`.
fn check_access_x_ok(path: &[u8]) {
    let result = unsafe { syscall(SYS_ACCESS, path.as_ptr() as u64, path.len() as u64, X_OK) };
    write_bytes(b"clang-syscall-smoke: access(");
    write_bytes(path);
    write_bytes(b", X_OK) = ");
    match result {
        Ok(v) => write_decimal(v as i32),
        Err(e) => {
            write_bytes(b"Err(");
            write_decimal(e as i32);
            write_bytes(b")");
        }
    }
    write_bytes(b"\n");
}

/// Part 1 -- see this file's own module doc comment.
fn check_compile() -> bool {
    let ok = run_and_wait(
        b"/bin/clang",
        &[
            b"clang",
            b"-v",
            b"-static",
            b"-o",
            b"/hello.elf",
            b"/hello.c",
        ],
    );
    if ok {
        write_bytes(b"clang-syscall-smoke: compile OK\n");
    } else {
        write_bytes(b"clang-syscall-smoke: clang -static -o /hello.elf /hello.c failed\n");
    }
    ok
}

/// Part 2 -- see this file's own module doc comment.
fn check_run_compiled_output() -> bool {
    let ok = run_and_wait(b"/hello.elf", &[b"hello.elf"]);
    if ok {
        write_bytes(b"clang-syscall-smoke: compiled hello.elf ran and exited 0\n");
    } else {
        write_bytes(b"clang-syscall-smoke: running /hello.elf failed\n");
    }
    ok
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"clang-syscall-smoke: starting\n");

    check_file_openable(b"/bin/ld.lld");
    check_file_openable(b"/lib/clang/23/lib/x86_64-unknown-oxidebsd-musl/libclang_rt.builtins.a");
    check_file_openable(b"/usr/lib/libc.a");
    check_file_openable(b"/usr/lib/crt1.o");
    check_file_openable(b"/usr/lib/crti.o");
    check_file_openable(b"/usr/lib/crtn.o");
    check_file_openable(b"/bin/x86_64-unknown-oxidebsd-musl-ld.lld");
    check_access_x_ok(b"/bin/ld.lld");
    check_access_x_ok(b"/bin/clang");
    {
        let ok = run_and_wait(b"/bin/ld.lld", &[b"ld.lld", b"--version"]);
        write_bytes(if ok {
            b"clang-syscall-smoke: ld.lld --version OK\n"
        } else {
            b"clang-syscall-smoke: ld.lld --version failed\n"
        });
    }

    check_version();
    check_compile_object_only();
    check_file_openable(b"/hello.o");
    check_link_only();
    check_link_to_tmp();
    check_deliberately_broken_link();

    check!(check_compile(), b"clang compile+link round trip failed");
    check!(
        check_run_compiled_output(),
        b"running clang's own compiled output failed"
    );

    write_bytes(b"clang-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
