//! Real-`SYSCALL` smoke test for the on-target C++ toolchain: `/bin/clang++` (a symlink to
//! `/bin/clang` -- the driver picks C++ mode off argv[0]) compiling and linking `/hello.cpp`
//! (`sys/modules/oxfs/src/hello.cpp`) against the seeded libc++ (`/usr/include/c++/v1`,
//! `/usr/lib/libc++.a`), then running the result.
//!
//! Deliberately passes **no** `--target=` and **no** `-I`/`-L`: the point is that a bare
//! `clang++ -static -o out in.cpp` works on-target, which needs the baked-in default triple
//! (`LLVM_DEFAULT_TARGET_TRIPLE`) and the LLVM fork's `OxideBSD::addLibCxxIncludePaths` both
//! doing their jobs.
//!
//! `/hello.cpp` self-checks STL, exceptions/RTTI, `std::thread`/`std::mutex`, and
//! `std::filesystem`, exiting non-zero if any check fails -- so part 2 only has to look at the
//! exit status.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_EXECVE: u64 = 59;
/// Registered by `tests/clangxx_syscall_smoke.rs` against a test-only handler.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

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
        let _ = syscall4(SYS_WRITE, STDOUT, s.as_ptr() as u64, s.len() as u64, 0);
    }
}

fn write_decimal(mut n: i64) {
    let mut buf = [0u8; 21];
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
        let _ = syscall4(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Kernel-side `RawArgvEntry` wire format: `(ptr, len)` pairs, terminated by `ptr == 0`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

const MAX_ARGV: usize = 8;

fn execve(path: &[u8], argv: &[&[u8]]) -> Result<u64, u64> {
    let mut entries = [RawArgvEntry { ptr: 0, len: 0 }; MAX_ARGV + 1];
    for (i, arg) in argv.iter().enumerate() {
        entries[i] = RawArgvEntry {
            ptr: arg.as_ptr() as u64,
            len: arg.len() as u64,
        };
    }
    const ENVP: &[u8] = b"PATH=/bin:/usr/bin";
    let envp = [
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
            entries.as_ptr() as u64,
            envp.as_ptr() as u64,
        )
    }
}

/// Fork + execve + wait4. Returns whether the child exited 0; logs the raw status otherwise.
fn run_and_wait(path: &[u8], argv: &[&[u8]]) -> bool {
    match unsafe { syscall4(SYS_FORK, 0, 0, 0, 0) } {
        Ok(0) => {
            let _ = execve(path, argv);
            unsafe {
                let _ = syscall4(SYS_EXIT, 127, 0, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child) => {
            let mut status: i32 = -1;
            let waited =
                unsafe { syscall4(SYS_WAIT4, child, &mut status as *mut i32 as u64, 0, 0) };
            let ok = waited == Ok(child) && status == 0;
            if !ok {
                write_bytes(b"clangxx-syscall-smoke: wait4 -> ");
                match waited {
                    Ok(p) => write_decimal(p as i64),
                    Err(e) => {
                        write_bytes(b"Err(");
                        write_decimal(e as i64);
                        write_bytes(b")");
                    }
                }
                write_bytes(b", raw status=");
                write_decimal(status as i64);
                write_bytes(b"\n");
            }
            ok
        }
        Err(_) => {
            write_bytes(b"clangxx-syscall-smoke: fork failed\n");
            false
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"clangxx-syscall-smoke: starting\n");

    // Part 1: bare compile+link. `-v` puts the resolved triple and #include search list in the
    // serial log, which is the first thing to read if this fails.
    let compiled = run_and_wait(
        b"/bin/clang++",
        &[
            b"/bin/clang++",
            b"-v",
            b"-static",
            b"-o",
            b"/hello-cpp.elf",
            b"/hello.cpp",
        ],
    );
    if !compiled {
        write_bytes(b"clangxx-syscall-smoke: FAIL: clang++ -static -o /hello-cpp.elf /hello.cpp\n");
        test_exit(false);
    }
    write_bytes(b"clangxx-syscall-smoke: compile+link OK\n");

    // Part 2: run it; its own exit status covers every C++ feature check.
    if !run_and_wait(b"/hello-cpp.elf", &[b"hello-cpp.elf"]) {
        write_bytes(b"clangxx-syscall-smoke: FAIL: /hello-cpp.elf reported failures\n");
        test_exit(false);
    }

    write_bytes(b"clangxx-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
