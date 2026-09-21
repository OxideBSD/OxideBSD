//! Real-`SYSCALL` counterpart to `tests/tcp_smoke.rs`.
//!
//! That test calls `oxidebsd_sys_socket`/`_bind`/`_listen`/`_accept`/`oxidebsd_sys_read`/`_write`/
//! `_fcntl` as plain Rust functions from its own `main()`, never through a genuine `SYSCALL`
//! instruction. This binary drives the identical state-machine script -- three-way handshake,
//! in-order data delivery, `accept()`'s promotion, a real `O_NONBLOCK`/`EAGAIN` check, and the
//! `tcp_read` EOF-vs-empty distinction on a real peer FIN -- entirely through real
//! `SYSCALL`/`SYSRETQ`, spawned as pid 1 by `tests/tcp_syscall_smoke.rs`.
//!
//! Unlike UDP/poll, the synthetic peer's own script depends on reading this connection's
//! internally-generated sequence number (`tcp::debug_send_next`/`debug_connection_for`, kept
//! `pub` for exactly this) to build a valid final ACK/data segment/FIN -- state this binary has
//! no way to observe itself. So every "advance the synthetic peer" moment goes through one
//! **test-only**, step-dispatched syscall, `SYS_TEST_TCP_STEP = 9997` (not part of any real ABI --
//! registered directly by the test file). The functions actually under test (`socket`/`bind`/
//! `listen`/`accept`/`read`/`write`/`fcntl`) are still only ever invoked by this process via real
//! `SYSCALL` -- see `regress/udp-syscall-smoke/src/main.rs`'s own module doc comment for why this
//! kind of test-only seam doesn't reintroduce the blind spot being closed here.
//!
//! Constants below (`LISTEN_PORT`/`PEER_IP`/`PEER_PORT`/`CLIENT_DATA`/`SERVER_DATA`) must match
//! `tests/tcp_syscall_smoke.rs`'s own copies exactly -- there's no shared crate across this
//! boundary, same as every other `regress/*` crate.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_SOCKET: u64 = 140;
const SYS_BIND: u64 = 141;
const SYS_LISTEN: u64 = 146;
const SYS_ACCEPT: u64 = 147;
const SYS_FCNTL: u64 = 151;
/// Test-only -- see this file's own module doc comment.
const SYS_TEST_TCP_STEP: u64 = 9997;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// tcp_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention `tests/fork_wait.rs` established.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const F_SETFL: u64 = 4;
const O_NONBLOCK: u64 = 0o4000;

/// Must match `tests/tcp_syscall_smoke.rs`'s own constants exactly.
const LISTEN_PORT: u16 = 7001;
const PEER_IP: [u8; 4] = [10, 0, 2, 66];
const PEER_PORT: u16 = 55556;
const CLIENT_DATA: &[u8] = b"hello-tcp-syscall";
const SERVER_DATA: &[u8] = b"echo-back-syscall";

/// Issues a syscall via `SYSCALL`; see `regress/stsh/src/main.rs`'s identical helper for the full
/// doc comment. Delegates to `syscall4` with a zeroed 4th argument.
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed by `bind`'s own address
/// pointer.
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

/// Runs one step of the synthetic peer's script -- see this file's own module doc comment.
fn tcp_step(step: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_TEST_TCP_STEP, step, 0, 0) }
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
    let listen_fd = match unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0) } {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"tcp-syscall-smoke: socket() failed\n");
            test_exit(false);
        }
    };

    let bind_addr = build_sockaddr([0, 0, 0, 0], LISTEN_PORT);
    if unsafe { syscall4(SYS_BIND, listen_fd, bind_addr.as_ptr() as u64, 16, 0) }.is_err() {
        write_bytes(b"tcp-syscall-smoke: bind() failed\n");
        test_exit(false);
    }
    if unsafe { syscall(SYS_LISTEN, listen_fd, 4, 0) }.is_err() {
        write_bytes(b"tcp-syscall-smoke: listen() failed\n");
        test_exit(false);
    }
    write_bytes(b"tcp-syscall-smoke: listening\n");

    // Step 0: synthetic peer completes the full three-way handshake.
    if tcp_step(0).is_err() {
        write_bytes(b"tcp-syscall-smoke: tcp_step(0) [handshake] failed\n");
        test_exit(false);
    }

    let mut addr_out = [0u8; 16];
    let mut addrlen: u32 = 16;
    let mut accepted: i64 = -1;
    for _ in 0..1000u32 {
        match unsafe {
            syscall4(
                SYS_ACCEPT,
                listen_fd,
                addr_out.as_mut_ptr() as u64,
                (&raw mut addrlen) as u64,
                0,
            )
        } {
            Ok(fd) => {
                accepted = fd as i64;
                break;
            }
            Err(_) => spin_loop(),
        }
    }
    if accepted < 0 {
        write_bytes(b"tcp-syscall-smoke: accept() never returned the promoted connection\n");
        test_exit(false);
    }
    let accepted = accepted as u64;
    let accepted_port = u16::from_be_bytes([addr_out[2], addr_out[3]]);
    let accepted_ip: [u8; 4] = [addr_out[4], addr_out[5], addr_out[6], addr_out[7]];
    if accepted_ip != PEER_IP || accepted_port != PEER_PORT {
        write_bytes(b"tcp-syscall-smoke: accept() peer address mismatch\n");
        test_exit(false);
    }
    write_bytes(b"tcp-syscall-smoke: accept() -- three-way handshake verified\n");

    // Step 3: synthetic peer sends data.
    if tcp_step(3).is_err() {
        write_bytes(b"tcp-syscall-smoke: tcp_step(3) [client data] failed\n");
        test_exit(false);
    }

    let mut recv_buf = [0u8; 64];
    let n = unsafe {
        syscall(
            SYS_READ,
            accepted,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
        )
    };
    if n != Ok(CLIENT_DATA.len() as u64) || &recv_buf[..CLIENT_DATA.len()] != CLIENT_DATA {
        write_bytes(b"tcp-syscall-smoke: read() didn't return the injected client data\n");
        test_exit(false);
    }
    write_bytes(b"tcp-syscall-smoke: real read() -- in-order data delivery verified\n");

    // Step 1: snapshot our own send sequence before we write.
    if tcp_step(1).is_err() {
        write_bytes(b"tcp-syscall-smoke: tcp_step(1) [seq snapshot] failed\n");
        test_exit(false);
    }
    let n = unsafe {
        syscall(
            SYS_WRITE,
            accepted,
            SERVER_DATA.as_ptr() as u64,
            SERVER_DATA.len() as u64,
        )
    };
    if n != Ok(SERVER_DATA.len() as u64) {
        write_bytes(b"tcp-syscall-smoke: write() didn't accept the full payload\n");
        test_exit(false);
    }
    // Step 2: prove the sequence number actually advanced -- not just a fake success return.
    if tcp_step(2) != Ok(1) {
        write_bytes(b"tcp-syscall-smoke: write() didn't actually transmit a segment\n");
        test_exit(false);
    }
    write_bytes(b"tcp-syscall-smoke: real write() -- sequence advance verified\n");

    // O_NONBLOCK read() on an empty-but-still-open connection must return EAGAIN immediately.
    if unsafe { syscall(SYS_FCNTL, accepted, F_SETFL, O_NONBLOCK) }.is_err() {
        write_bytes(b"tcp-syscall-smoke: fcntl(F_SETFL, O_NONBLOCK) failed\n");
        test_exit(false);
    }
    let eagain_ok = unsafe {
        syscall(
            SYS_READ,
            accepted,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
        )
    }
    .is_err();
    if !eagain_ok {
        write_bytes(b"tcp-syscall-smoke: O_NONBLOCK read() on an empty connection should fail\n");
        test_exit(false);
    }
    write_bytes(b"tcp-syscall-smoke: O_NONBLOCK read() -- real EAGAIN verified\n");

    // Step 4: synthetic peer sends a FIN -- only now should read() report real EOF.
    if tcp_step(4).is_err() {
        write_bytes(b"tcp-syscall-smoke: tcp_step(4) [FIN] failed\n");
        test_exit(false);
    }
    let n = unsafe {
        syscall(
            SYS_READ,
            accepted,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
        )
    };
    if n != Ok(0) {
        write_bytes(b"tcp-syscall-smoke: read() after a real peer FIN should report EOF\n");
        test_exit(false);
    }
    write_bytes(b"tcp-syscall-smoke: read() after a real peer FIN -- real EOF verified -- PASS\n");

    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
