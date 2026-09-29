//! Smoke test for real userland `ping` support (a `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`
//! socket, see `sys/netinet/icmp.rs`'s own doc comment) -- the syscall-level counterpart to
//! `tests/icmp_smoke.rs`, which only exercises `icmp::send_echo_request`/`take_echo_reply`
//! directly, a kernel-internal hook no real userland program ever touches.
//!
//! This test instead calls `oxidebsd_sys_socket`/`_sendto`/`_recvfrom` (the same handlers
//! `sys/modules/socket`'s syscall shims and, ultimately, a real BusyBox `ping` process reach), building
//! the ICMP echo request by hand the same way `external/gpl2/busybox`'s vendored `ping.c` does
//! (type/code/checksum/id/seq filled in by the caller, not the kernel -- a raw socket's whole
//! point). A real round trip against SLIRP's self-answering gateway (same target
//! `tests/icmp_smoke.rs` uses, for the same host-privilege reasons -- see that file's own doc
//! comment) proves: `SOCK_RAW`/`IPPROTO_ICMP` socket creation, a caller-built ICMP packet sent
//! as-is over the wire, and -- unlike every other socket type in this stack -- a reply delivered
//! back with the *real IP header* prepended, exactly as `ping.c`'s own `unpack4` expects.
#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::kern::uipc_socket::{oxidebsd_sys_recvmsg, oxidebsd_sys_sendmsg, oxidebsd_sys_socket};
use oxidebsd::netinet::ipv4;
use oxidebsd::drivers::rtl8139;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::cpu::interrupts;
use oxidebsd::serial_println;

/// `sendto`/`recvfrom` as musl builds them, over the kernel's `sendmsg`/`recvmsg` (the layout of
/// musl's x86_64 `struct msghdr` and `struct iovec`, duplicated from `sys/kern/uipc_socket.rs`).
#[repr(C)]
struct IoVec {
    base: u64,
    len: u64,
}

#[repr(C)]
struct MsgHdr {
    name: u64,
    namelen: u32,
    _pad0: u32,
    iov: u64,
    iovlen: i32,
    _pad1: i32,
    control: u64,
    controllen: u32,
    _pad2: u32,
    flags: i32,
    _pad3: i32,
}

fn msghdr(name: u64, iov: &IoVec) -> MsgHdr {
    MsgHdr {
        name,
        namelen: 16,
        _pad0: 0,
        iov: iov as *const IoVec as u64,
        iovlen: 1,
        _pad1: 0,
        control: 0,
        controllen: 0,
        _pad2: 0,
        flags: 0,
        _pad3: 0,
    }
}

fn sendto(fd: u64, buf: &[u8], addr: &[u8; 16]) -> i64 {
    let iov = IoVec { base: buf.as_ptr() as u64, len: buf.len() as u64 };
    let msg = msghdr(addr.as_ptr() as u64, &iov);
    oxidebsd_sys_sendmsg(fd, &msg as *const MsgHdr as u64, 0)
}

/// Doesn't wait (`MSG_DONTWAIT`): `-EAGAIN` with nothing queued.
fn recvfrom(fd: u64, buf: &mut [u8], addr: &mut [u8; 16]) -> i64 {
    const MSG_DONTWAIT: u64 = 0x40;
    let iov = IoVec { base: buf.as_mut_ptr() as u64, len: buf.len() as u64 };
    let mut msg = msghdr(addr.as_mut_ptr() as u64, &iov);
    oxidebsd_sys_recvmsg(fd, &mut msg as *mut MsgHdr as u64, MSG_DONTWAIT)
}

limine_entry_point!(main);

const AF_INET: u64 = 2;
const SOCK_RAW: u64 = 3;
const IPPROTO_ICMP: u64 = 1;

const ECHO_ID: u16 = 0x5678;
const ECHO_SEQ: u16 = 1;
const ECHO_PAYLOAD: &[u8] = b"oxidebsd-ping-smoke";

fn build_sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip);
    buf
}

/// Builds a raw ICMP echo request exactly the way `ping.c`'s `ping4()` does: the caller computes
/// the checksum itself and hands the kernel a complete message, since a raw socket's `sendto`
/// wraps it in IP verbatim rather than building a protocol header the way UDP's does.
fn build_echo_request(identifier: u16, sequence: u16, data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut packet = alloc::vec::Vec::with_capacity(8 + data.len());
    packet.push(8); // ICMP_ECHO
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum placeholder
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(data);
    let sum = ipv4::checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (_mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    rtl8139::init(&mut frame_allocator, physical_memory_offset);
    if oxidebsd::net::nic::NIC.lock().is_none() {
        serial_println!("ping_smoke: no NIC installed -- is -device rtl8139 passed to QEMU?");
        exit_qemu(QemuExitCode::Failed);
        oxidebsd::hlt_loop();
    }

    let fd = oxidebsd_sys_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    assert!(
        fd >= 0,
        "socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) failed: {fd}"
    );
    let fd = fd as u64;
    serial_println!("ping_smoke: socket() -> fd {}", fd);

    let packet = build_echo_request(ECHO_ID, ECHO_SEQ, ECHO_PAYLOAD);
    let dest_addr = build_sockaddr(ipv4::GATEWAY_IP, 0); // ICMP has no port
    let rc = sendto(fd, &packet, &dest_addr);
    assert_eq!(
        rc,
        packet.len() as i64,
        "sendto() didn't report the full packet sent: {rc}"
    );
    serial_println!(
        "ping_smoke: sendto() -> {} bytes sent to real gateway {:?}",
        rc,
        ipv4::GATEWAY_IP
    );

    // Bounded by PIT ticks, not an arbitrary spin count -- see icmp_smoke's own precedent.
    let deadline = interrupts::ticks() + 500; // ~5s at 100 Hz
    let mut recv_buf = [0u8; 128];
    let mut src_addr = [0u8; 16];
    loop {
        let rc = recvfrom(fd, &mut recv_buf, &mut src_addr);
        if rc > 0 {
            let n = rc as usize;
            let ihl = (recv_buf[0] & 0x0F) as usize * 4;
            assert!(n >= ihl + 8, "reply shorter than an IP+ICMP header: {n}");
            let icmp = &recv_buf[ihl..n];
            let icmp_type = icmp[0];
            let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
            let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
            let src_ip: [u8; 4] = src_addr[4..8].try_into().unwrap();
            if icmp_type == 0 /* ICMP_ECHOREPLY */ && identifier == ECHO_ID && sequence == ECHO_SEQ
            {
                assert_eq!(src_ip, ipv4::GATEWAY_IP, "reply source address mismatch");
                serial_println!(
                    "ping_smoke: real ICMP echo reply received via a real socket (IP header \
                     included, {} byte packet from {:?}) -- SOCK_RAW/IPPROTO_ICMP verified end \
                     to end",
                    n,
                    src_ip
                );
                exit_qemu(QemuExitCode::Success);
                oxidebsd::hlt_loop();
            }
            // Not our reply (e.g. our own echo *request*, which SLIRP doesn't loop back but a
            // real raw socket implementation still ought to survive seeing) -- keep waiting.
        }
        if interrupts::ticks() >= deadline {
            serial_println!("ping_smoke: timed out waiting for an echo reply");
            exit_qemu(QemuExitCode::Failed);
            oxidebsd::hlt_loop();
        }
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
