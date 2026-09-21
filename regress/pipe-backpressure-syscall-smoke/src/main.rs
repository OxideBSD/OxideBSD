//! Real-`SYSCALL` regression test for the `yes | head` OOM panic (see CLAUDE.md's BusyBox
//! section and `src/pipe.rs`'s module doc comment): a pipe write end used to be an unboundedly
//! growable `VecDeque<u8>`, so a producer that outpaced its consumer -- or, as here, has no
//! consumer draining fast enough -- could grow the kernel heap without limit until the allocator
//! itself panicked. `src/pipe.rs` now bounds the buffer and blocks a full writer for real.
//!
//! Forks: the child writes a single, real `write()` call far larger than the pipe's own capacity
//! (`PIPE_CAPACITY_HINT` below, matching `src/pipe.rs`'s `PIPE_CAPACITY`) into the write end, which
//! only completes once the parent has drained enough space across several read() calls --
//! exercising both new `BlockReason::WaitingForPipeSpace` (the writer blocking) and the existing
//! `WaitingForPipeData`/wake-on-read path together. The parent verifies every byte arrives, in
//! order, unmodified (a repeating `i % 251` pattern), and that the child's own `write()` reports
//! the full length back -- proving the kernel-side partial-write-then-block loop in
//! `src/pipe.rs::write_into` hands the *whole* buffer back to a blocking caller, matching a real
//! blocking pipe write's contract.
//!
//! The syscall numbers/register convention here must match `sys/syscall.rs` in the kernel
//! exactly -- there's no shared crate between the two, this is the ABI boundary itself, same as
//! every other `regress/*` crate.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_CLOSE: u64 = 6;
const SYS_WAIT4: u64 = 7;
const SYS_PIPE: u64 = 105;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// pipe_backpressure_syscall_smoke.rs` registers this one directly against a test-only handler,
/// same convention `tests/fork_wait.rs` established.
const SYS_TEST_EXIT: u64 = 9999;
const STDOUT: u64 = 1;

/// Mirrors `src/pipe.rs`'s own `PIPE_CAPACITY` (64 KiB) -- not imported (no shared crate across
/// the ABI boundary), just needs to be large enough that a single write forces several full-
/// buffer block/drain cycles rather than fitting in one shot.
const PIPE_CAPACITY_HINT: usize = 65536;
const N: usize = PIPE_CAPACITY_HINT * 3 + 12345;

const fn make_pattern() -> [u8; N] {
    let mut buf = [0u8; N];
    let mut i = 0;
    while i < N {
        buf[i] = (i % 251) as u8;
        i += 1;
    }
    buf
}
static WRITE_BUF: [u8; N] = make_pattern();

/// Issues a syscall via `SYSCALL`; see `regress/ring3-smoke/src/main.rs`'s identical helper for
/// the full doc comment (carry-flag convention, `rcx`/`r11` clobbered by `SYSCALL` itself).
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
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
            in("r10") 0u64,
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut fds: [i32; 2] = [-1, -1];
    if unsafe { syscall(SYS_PIPE, fds.as_mut_ptr() as u64, 0, 0) }.is_err() {
        write_bytes(b"pipe-backpressure-syscall-smoke: pipe() failed\n");
        test_exit(false);
    }
    let (read_fd, write_fd) = (fds[0] as u64, fds[1] as u64);

    write_bytes(b"pipe-backpressure-syscall-smoke: forking\n");
    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            // Child: producer. Doesn't need the read end.
            let _ = unsafe { syscall(SYS_CLOSE, read_fd, 0, 0) };
            let n = unsafe { syscall(SYS_WRITE, write_fd, WRITE_BUF.as_ptr() as u64, N as u64) };
            let _ = unsafe { syscall(SYS_CLOSE, write_fd, 0, 0) };
            let ok = n == Ok(N as u64);
            if !ok {
                write_bytes(b"pipe-backpressure-syscall-smoke: child write() didn't return the full length\n");
            }
            unsafe {
                let _ = syscall(SYS_EXIT, if ok { 0 } else { 1 }, 0, 0);
            }
            loop {
                spin_loop();
            }
        }
        Ok(child_pid) => {
            // Parent: consumer. Doesn't need the write end.
            let _ = unsafe { syscall(SYS_CLOSE, write_fd, 0, 0) };
            let mut total = 0usize;
            let mut ok = true;
            let mut buf = [0u8; 4096];
            loop {
                let n = unsafe {
                    syscall(SYS_READ, read_fd, buf.as_mut_ptr() as u64, buf.len() as u64)
                };
                match n {
                    Ok(0) => break, // real EOF: peer closed after writing everything
                    Ok(n) => {
                        let n = n as usize;
                        for (i, &b) in buf[..n].iter().enumerate() {
                            if b != ((total + i) % 251) as u8 {
                                ok = false;
                            }
                        }
                        total += n;
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            let _ = unsafe { syscall(SYS_CLOSE, read_fd, 0, 0) };
            if total != N {
                write_bytes(
                    b"pipe-backpressure-syscall-smoke: read total didn't match write length\n",
                );
                ok = false;
            } else if ok {
                write_bytes(
                    b"pipe-backpressure-syscall-smoke: all bytes received in order, unmodified\n",
                );
            } else {
                write_bytes(b"pipe-backpressure-syscall-smoke: received data didn't match the expected pattern\n");
            }

            let mut status: i32 = -1;
            let wait_result =
                unsafe { syscall(SYS_WAIT4, child_pid, &mut status as *mut i32 as u64, 0) };
            let child_ok = wait_result == Ok(child_pid) && status == 0;
            if !child_ok {
                write_bytes(b"pipe-backpressure-syscall-smoke: child didn't exit cleanly\n");
            }

            let pass = ok && child_ok;
            if pass {
                write_bytes(b"pipe-backpressure-syscall-smoke: PASS\n");
            } else {
                write_bytes(b"pipe-backpressure-syscall-smoke: FAIL\n");
            }
            test_exit(pass);
        }
        Err(_) => {
            write_bytes(b"pipe-backpressure-syscall-smoke: fork failed\n");
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
