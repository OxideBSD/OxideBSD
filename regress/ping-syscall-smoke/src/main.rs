//! Real-`SYSCALL` counterpart to `tests/ping_smoke.rs`.
//!
//! That test calls `oxidebsd_sys_socket`/`_sendto`/`_recvfrom` as plain Rust functions from its
//! own `main()`, never through a genuine `SYSCALL` instruction. This binary drives the identical
//! scenario -- a real `SOCK_RAW`+`IPPROTO_ICMP` socket, a hand-built ICMP echo request sent to
//! QEMU SLIRP's self-answering gateway, a real reply read back with its real IP header prepended
//! -- entirely through real `SYSCALL`/`SYSRETQ`, spawned as pid 1 by
//! `tests/ping_syscall_smoke.rs`.
//!
//! No test-only "advance a synthetic peer" syscall is needed: SLIRP genuinely answers a real echo
//! request over the real (virtual) wire, so simply looping on real `recvfrom()` until the reply
//! arrives (or a bounded retry count elapses) is enough -- the same reason
//! `tests/icmp_smoke.rs`/`tests/ping_smoke.rs` never needed synthetic RX injection either.
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
const SYS_SENDTO: u64 = 142;
const SYS_RECVFROM: u64 = 143;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// ping_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention `tests/fork_wait.rs` established.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_RAW: u64 = 3;
const IPPROTO_ICMP: u64 = 1;

const ECHO_ID: u16 = 0x5678;
const ECHO_SEQ: u16 = 1;
const ECHO_PAYLOAD: &[u8] = b"oxidebsd-ping-syscall-smoke";
/// SLIRP's fixed default-gateway address -- matches `sys/net/ipv4.rs`'s own `GATEWAY_IP` (a
/// freestanding binary has no way to import that constant, so it's duplicated here the same way
/// every other regress/* crate duplicates the syscall ABI shape itself).
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
/// Bounds the receive-retry loop -- not tick-based (no clock access from userland here), just a
/// generous fixed retry count with a `spin_loop` hint between attempts.
const MAX_RECV_ATTEMPTS: u32 = 2_000_000;

/// Issues a syscall via `SYSCALL`; see `regress/stsh/src/main.rs`'s identical helper for the full
/// doc comment (carry-flag convention, `rcx`/`r11` clobbered by `SYSCALL` itself). Delegates to
/// `syscall4` with a zeroed 4th argument.
#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed by `sendto`/`recvfrom`'s own
/// address-pointer argument.
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

/// Standard 16-bit-ones-complement Internet checksum -- matches `sys/net/ipv4.rs`'s own
/// `checksum` algorithm, duplicated here since a freestanding binary can't import it.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip);
    buf
}

/// Builds a raw ICMP echo request exactly the way a real `ping` does: the caller computes the
/// checksum itself and hands the kernel a complete message, since a raw socket's `sendto` wraps
/// it in IP verbatim rather than building a protocol header the way UDP's does.
fn build_echo_request(buf: &mut [u8; 64], identifier: u16, sequence: u16, data: &[u8]) -> usize {
    let len = 8 + data.len();
    buf[0] = 8; // ICMP_ECHO
    buf[1] = 0; // code
    buf[2] = 0;
    buf[3] = 0; // checksum placeholder
    buf[4..6].copy_from_slice(&identifier.to_be_bytes());
    buf[6..8].copy_from_slice(&sequence.to_be_bytes());
    buf[8..len].copy_from_slice(data);
    let sum = checksum(&buf[..len]);
    buf[2..4].copy_from_slice(&sum.to_be_bytes());
    len
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let fd = match unsafe { syscall(SYS_SOCKET, AF_INET, SOCK_RAW, IPPROTO_ICMP) } {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"ping-syscall-smoke: socket() failed\n");
            test_exit(false);
        }
    };
    write_bytes(b"ping-syscall-smoke: socket() ok\n");

    let mut packet_buf = [0u8; 64];
    let packet_len = build_echo_request(&mut packet_buf, ECHO_ID, ECHO_SEQ, ECHO_PAYLOAD);
    let dest_addr = build_sockaddr(GATEWAY_IP, 0); // ICMP has no port

    let rc = unsafe {
        syscall4(
            SYS_SENDTO,
            fd,
            packet_buf.as_ptr() as u64,
            packet_len as u64,
            dest_addr.as_ptr() as u64,
        )
    };
    if rc != Ok(packet_len as u64) {
        write_bytes(b"ping-syscall-smoke: sendto() didn't report the full packet sent\n");
        test_exit(false);
    }
    write_bytes(b"ping-syscall-smoke: sendto() -> sent to real gateway\n");

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
            let ihl = (recv_buf[0] & 0x0F) as usize * 4;
            if n >= ihl + 8 {
                let icmp = &recv_buf[ihl..n];
                let icmp_type = icmp[0];
                let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
                let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
                let src_ip: [u8; 4] = [src_addr[4], src_addr[5], src_addr[6], src_addr[7]];
                if icmp_type == 0 /* ICMP_ECHOREPLY */
                    && identifier == ECHO_ID
                    && sequence == ECHO_SEQ
                    && src_ip == GATEWAY_IP
                {
                    write_bytes(
                        b"ping-syscall-smoke: real ICMP echo reply received via a real \
                          SYS_SOCKET/SYS_SENDTO/SYS_RECVFROM syscall path -- PASS\n",
                    );
                    test_exit(true);
                }
                // Not our reply -- keep waiting.
            }
        }
        spin_loop();
    }

    write_bytes(b"ping-syscall-smoke: timed out waiting for an echo reply\n");
    test_exit(false);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
