//! Real-`SYSCALL` counterpart to `tests/poll_smoke.rs`.
//!
//! That test calls `oxidebsd_sys_socket`/`_bind`/`oxidebsd_sys_poll` as plain Rust functions from
//! its own `main()`, never through a genuine `SYSCALL` instruction. This binary drives the
//! identical two-socket scenario -- one pre-loaded with a synthetic datagram (must report
//! `POLLIN` immediately), one left empty (must report nothing and a bare `poll()` on it alone
//! must time out cleanly) -- entirely through real `SYSCALL`/`SYSRETQ`, spawned as pid 1 by
//! `tests/poll_syscall_smoke.rs`.
//!
//! Same test-only-syscall seam as `regress/udp-syscall-smoke/` (see its own module doc comment
//! for why this doesn't reintroduce the blind spot being closed): `SYS_TEST_INJECT_UDP_FRAME =
//! 9998` triggers the synthetic inbound datagram from kernel context, since this test's own
//! `main()` can't run again once `scheduler::start` hands control to this process. The function
//! actually under test, `poll()` itself, only ever runs via this process's own real `SYSCALL`.
//!
//! The syscall numbers/register convention here must match `sys/syscall.rs` in the kernel
//! exactly -- there's no shared crate between the two, this is the ABI boundary itself.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_SOCKET: u64 = 140;
const SYS_BIND: u64 = 141;
const SYS_POLL: u64 = 148;
/// Test-only -- see this file's own module doc comment.
const SYS_TEST_INJECT_UDP_FRAME: u64 = 9998;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// poll_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention `tests/fork_wait.rs` established.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_DGRAM: u64 = 2;
const POLLIN: i16 = 0x0001;

/// Must match `tests/poll_syscall_smoke.rs`'s own constant -- the test-only injection handler
/// builds a reply frame addressed to exactly this local port.
const LOCAL_PORT: u16 = 34567;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// Issues a syscall via `SYSCALL`; see `regress/stsh/src/main.rs`'s identical helper for the full
/// doc comment. Delegates to `syscall4` with a zeroed 4th argument.
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed by `bind`'s own address-pointer
/// argument (`poll` itself only needs 3 real arguments, so it goes through `syscall` directly).
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

fn build_sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip);
    buf
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Socket A: gets a synthetic datagram injected before poll() ever runs -- must report ready
    // immediately, not just eventually.
    let fd_a = match unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) } {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"poll-syscall-smoke: socket() (A) failed\n");
            test_exit(false);
        }
    };
    let bind_addr = build_sockaddr([0, 0, 0, 0], LOCAL_PORT);
    if unsafe { syscall4(SYS_BIND, fd_a, bind_addr.as_ptr() as u64, 16, 0) }.is_err() {
        write_bytes(b"poll-syscall-smoke: bind() (A) failed\n");
        test_exit(false);
    }

    if unsafe { syscall(SYS_TEST_INJECT_UDP_FRAME, 0, 0, 0) }.is_err() {
        write_bytes(b"poll-syscall-smoke: SYS_TEST_INJECT_UDP_FRAME failed\n");
        test_exit(false);
    }

    // Socket B: never gets anything -- must time out cleanly.
    let fd_b = match unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) } {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"poll-syscall-smoke: socket() (B) failed\n");
            test_exit(false);
        }
    };

    let mut fds = [
        PollFd {
            fd: fd_a as i32,
            events: POLLIN,
            revents: 0,
        },
        PollFd {
            fd: fd_b as i32,
            events: POLLIN,
            revents: 0,
        },
    ];
    let rc = unsafe { syscall(SYS_POLL, fds.as_mut_ptr() as u64, 2, 500) };
    if rc != Ok(1) || fds[0].revents & POLLIN != POLLIN || fds[1].revents != 0 {
        write_bytes(b"poll-syscall-smoke: poll() didn't report exactly the ready fd\n");
        test_exit(false);
    }
    write_bytes(b"poll-syscall-smoke: poll() correctly reported the ready fd\n");

    // Socket B alone must time out cleanly, not hang or false-positive.
    let mut fds_empty = [PollFd {
        fd: fd_b as i32,
        events: POLLIN,
        revents: 0,
    }];
    let rc = unsafe { syscall(SYS_POLL, fds_empty.as_mut_ptr() as u64, 1, 200) };
    if rc != Ok(0) || fds_empty[0].revents != 0 {
        write_bytes(b"poll-syscall-smoke: poll() on an empty socket didn't time out cleanly\n");
        test_exit(false);
    }
    write_bytes(b"poll-syscall-smoke: poll() correctly timed out on an empty socket -- PASS\n");

    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
