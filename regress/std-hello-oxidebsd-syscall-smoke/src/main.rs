//! Real-`SYSCALL` smoke test for OxideBSD's own real `x86_64-unknown-oxidebsd` Rust target (see
//! `x86_64-unknown-oxidebsd.json`, `external/mit/rust`'s `oxidebsd` branch, and `build.rs`'s
//! `build_std_oxidebsd_userland_crate`): confirms `/bin/std-hello-oxidebsd` -- `std` genuinely
//! compiled with `target_os = "oxidebsd"`, not borrowed Linux identity the way `std-hello`
//! (the earlier `x86_64-unknown-linux-musl` spike) is -- actually runs against OxideBSD's native
//! syscall ABI: real `write`/`writev` for its `println!`, a real observed exit code via
//! `wait4`, not just "the binary boots."
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- same reasoning `clang-syscall-smoke`/
//! `std-hello-syscall-smoke` document. `fork` + `execve` `/bin/std-hello-oxidebsd`, `wait4` for
//! it, and check the real `wait(2)`-encoded exit status decodes to `42`
//! (`std::process::exit(42)` in `std-hello-oxidebsd`'s own `main()`) via `WEXITSTATUS`
//! (`(status >> 8) & 0xff` -- see `sys/process/lifecycle.rs`'s own doc comment on this encoding).
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
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// std_hello_oxidebsd_syscall_smoke.rs` registers this one directly against a test-only handler,
/// same convention every other real-`SYSCALL` smoke test in this codebase uses.
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
            write_bytes(b"std-hello-oxidebsd-syscall-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
}

/// Wire format for `SYS_EXECVE`'s optional third argument -- see `sys/process.rs`'s
/// `RawArgvEntry` (the kernel-side counterpart this must match exactly: two `u64`s, `ptr` then
/// `len`).
#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

const MAX_ARGV: usize = 4;

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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"std-hello-oxidebsd-syscall-smoke: starting\n");

    match fork() {
        Ok(0) => {
            let _ = execve(b"/usr/tests/std-hello-oxidebsd", &[b"std-hello-oxidebsd"]);
            // execve only returns on failure.
            unsafe {
                let _ = syscall(SYS_EXIT, 127, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            let mut status: i32 = -1;
            let waited = wait4(child_pid, &mut status) == Ok(child_pid);
            check!(waited, b"wait4 did not return the expected child pid");

            let exit_code = (status >> 8) & 0xff;
            if exit_code != 42 {
                write_bytes(
                    b"std-hello-oxidebsd-syscall-smoke: FAIL: unexpected exit code (wanted 42)\n",
                );
                test_exit(false);
            }
            write_bytes(
                b"std-hello-oxidebsd-syscall-smoke: /bin/std-hello-oxidebsd ran and exited 42 as expected\n",
            );
            test_exit(true);
        }
        Err(_) => {
            write_bytes(b"std-hello-oxidebsd-syscall-smoke: fork failed\n");
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
