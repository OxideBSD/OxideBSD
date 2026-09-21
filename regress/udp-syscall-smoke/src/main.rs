//! Real-`SYSCALL` counterpart to `tests/udp_smoke.rs`.
//!
//! That test calls `oxidebsd_sys_socket`/`_bind`/`_sendto`/`_recvfrom` as plain Rust functions
//! from its own `main()`, never through a genuine `SYSCALL` instruction. This binary drives the
//! identical two-half scenario -- a real `sendto()` out over the wire to SLIRP's gateway (proving
//! the real TX path: ARP resolution, IPv4 checksum, UDP header build, NIC send), then a synthetic
//! inbound frame consumed via a real `recvfrom()` -- entirely through real `SYSCALL`/`SYSRETQ`,
//! spawned as pid 1 by `tests/udp_syscall_smoke.rs`.
//!
//! `tests/udp_syscall_smoke.rs`'s own `main()` can't run again once `scheduler::start` hands
//! control to this process, so the old trick of injecting a synthetic frame directly from the
//! test's own linear code (`ethernet::handle_frame`) doesn't apply here. Instead this binary
//! calls a **test-only** syscall (`SYS_TEST_INJECT_UDP_FRAME = 9998`, not part of any real ABI --
//! registered directly by the test file) right after `bind()`, whose handler builds and injects
//! the exact same synthetic reply frame the old test built, from kernel context. The functions
//! actually under test (`socket`/`bind`/`sendto`/`recvfrom`) are still only ever invoked by this
//! process, via real `SYSCALL` -- the test-only syscall is just relocating *when* the synthetic
//! "a packet arrived" trigger fires, not changing what's being verified.
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
const SYS_SENDTO: u64 = 142;
const SYS_RECVFROM: u64 = 143;
/// Test-only -- see this file's own module doc comment.
const SYS_TEST_INJECT_UDP_FRAME: u64 = 9998;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// udp_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention `tests/fork_wait.rs` established.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_DGRAM: u64 = 2;

/// Must match `tests/udp_syscall_smoke.rs`'s own constants -- the test-only injection handler
/// builds a reply frame addressed to exactly this local port, from exactly this peer port, with
/// exactly this payload.
const LOCAL_PORT: u16 = 23456;
const PEER_PORT: u16 = 54321;
/// Arbitrary, unused port on the real gateway -- this send only needs to prove the real TX path
/// works (ARP + checksum + NIC send), not get a reply back the same way.
const GATEWAY_SEND_PORT: u16 = 9;
const PING_PAYLOAD: &[u8] = b"udp-syscall-smoke-ping";
const PONG_PAYLOAD: &[u8] = b"udp-syscall-smoke-pong";
/// SLIRP's fixed default-gateway address -- matches `sys/net/ipv4.rs`'s own `GATEWAY_IP`.
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
const MAX_RECV_ATTEMPTS: u32 = 2_000_000;

/// Issues a syscall via `SYSCALL`; see `regress/stsh/src/main.rs`'s identical helper for the full
/// doc comment. Delegates to `syscall4` with a zeroed 4th argument.
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed by `bind`/`sendto`/`recvfrom`'s
/// own address-pointer argument.
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
    let fd = match unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0) } {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"udp-syscall-smoke: socket() failed\n");
            test_exit(false);
        }
    };

    let bind_addr = build_sockaddr([0, 0, 0, 0], LOCAL_PORT);
    if unsafe { syscall4(SYS_BIND, fd, bind_addr.as_ptr() as u64, 16, 0) }.is_err() {
        write_bytes(b"udp-syscall-smoke: bind() failed\n");
        test_exit(false);
    }
    write_bytes(b"udp-syscall-smoke: socket()+bind() ok\n");

    let dest_addr = build_sockaddr(GATEWAY_IP, GATEWAY_SEND_PORT);
    let rc = unsafe {
        syscall4(
            SYS_SENDTO,
            fd,
            PING_PAYLOAD.as_ptr() as u64,
            PING_PAYLOAD.len() as u64,
            dest_addr.as_ptr() as u64,
        )
    };
    if rc != Ok(PING_PAYLOAD.len() as u64) {
        write_bytes(b"udp-syscall-smoke: sendto() didn't report the full packet sent\n");
        test_exit(false);
    }
    write_bytes(b"udp-syscall-smoke: real sendto() over the wire ok\n");

    if unsafe { syscall(SYS_TEST_INJECT_UDP_FRAME, 0, 0, 0) }.is_err() {
        write_bytes(b"udp-syscall-smoke: SYS_TEST_INJECT_UDP_FRAME failed\n");
        test_exit(false);
    }

    let mut recv_buf = [0u8; 128];
    let mut src_addr = [0u8; 16];
    for _ in 0..MAX_RECV_ATTEMPTS {
        let rc = unsafe {
            syscall4(
                SYS_RECVFROM,
                fd,
                recv_buf.as_mut_ptr() as u64,
                recv_buf.len() as u64,
                src_addr.as_mut_ptr() as u64,
            )
        };
        if let Ok(n) = rc
            && n > 0
        {
            let n = n as usize;
            let src_ip: [u8; 4] = [src_addr[4], src_addr[5], src_addr[6], src_addr[7]];
            let src_port = u16::from_be_bytes([src_addr[2], src_addr[3]]);
            if &recv_buf[..n] == PONG_PAYLOAD && src_ip == GATEWAY_IP && src_port == PEER_PORT {
                write_bytes(
                    b"udp-syscall-smoke: real recvfrom() -> synthetic reply matched -- PASS\n",
                );
                test_exit(true);
            }
            write_bytes(b"udp-syscall-smoke: recvfrom() payload/address mismatch\n");
            test_exit(false);
        }
        spin_loop();
    }

    write_bytes(b"udp-syscall-smoke: timed out waiting for the injected reply\n");
    test_exit(false);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
