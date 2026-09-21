//! Networking Phase 3's smoke test (see this repo's networking plan): exercises every syscall
//! `sys/modules/net` registers (`SYS_SOCKET`/`SYS_BIND`/`SYS_SENDTO`/`SYS_RECVFROM`/
//! `SYS_SETSOCKOPT`) by calling `sys/net/udp.rs`'s kernel-exported handlers directly (same
//! "no real process needed" style `tests/rtl8139_smoke.rs`/`tests/icmp_smoke.rs` already use --
//! `scheduler::current_pid()` defaults to `0` before any process is spawned, the same pid
//! `crate::fd::init()` bootstraps fd 0/1/2 under, so fd allocation/registration works fine called
//! straight from this test's own `main`).
//!
//! Two halves, each proving something the other can't:
//! - A real `sendto()` out over the wire to the SLIRP gateway proves the actual TX path (ARP
//!   resolution, IPv4 checksum, UDP header build, NIC send) still works with the new UDP code on
//!   top of it -- same real-hardware-round-trip style Phases 1/2 already established.
//! - A synthetic inbound frame, fed directly through `ethernet::handle_frame` (bypassing the NIC
//!   entirely), proves RX dispatch -> port-bound-socket lookup -> `recvfrom` deterministically,
//!   without depending on any external responder existing on the guest's behalf (unlike ARP-for-
//!   itself/ICMP-echo-for-itself, QEMU's SLIRP has no built-in UDP echo service to target, and
//!   anything that *would* answer a real UDP datagram -- e.g. SLIRP's DNS forwarder -- needs real
//!   host network egress this test shouldn't depend on).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::net::udp::{
    oxidebsd_sys_bind, oxidebsd_sys_recvfrom, oxidebsd_sys_sendto, oxidebsd_sys_setsockopt,
    oxidebsd_sys_socket,
};
use oxidebsd::net::{ethernet, ipv4, rtl8139};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

const AF_INET: u64 = 2;
const SOCK_DGRAM: u64 = 2;

const LOCAL_PORT: u16 = 12345;
const PEER_PORT: u16 = 54321;
const SEND_DEST_PORT: u16 = 9; // discard -- doesn't matter, no reply is expected or needed
const PING_PAYLOAD: &[u8] = b"ping";
const PONG_PAYLOAD: &[u8] = b"pong!";

fn build_sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes()); // sa_family_t, host byte order
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip);
    buf
}

/// Builds one synthetic Ethernet+IPv4+UDP frame (a real, checksummed IPv4 header) as if it had
/// just arrived over the wire from `(src_ip, src_port)` addressed to `(dst_ip, dst_port)`.
fn build_udp_frame(
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    data: &[u8],
) -> ([u8; 64], usize) {
    let mut frame = [0u8; 64];
    let udp_len = 8 + data.len();
    let ip_len = 20 + udp_len;
    let total = 14 + ip_len;
    assert!(total <= frame.len(), "test frame buffer too small");

    frame[0..6].copy_from_slice(&dest_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = &mut frame[14..14 + ip_len];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17; // UDP
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let cksum = ipv4::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());

    let udp = &mut ip[20..20 + udp_len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(data);

    (frame, total)
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (_mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    rtl8139::init(&mut frame_allocator, physical_memory_offset);
    let Some(our_mac) = ethernet::our_mac() else {
        serial_println!("udp_smoke: no NIC installed -- is -device rtl8139 passed to QEMU?");
        exit_qemu(QemuExitCode::Failed);
        oxidebsd::hlt_loop();
    };

    let fd = oxidebsd_sys_socket(AF_INET, SOCK_DGRAM, 0);
    assert!(fd >= 0, "socket() failed: {fd}");
    let fd = fd as u64;
    serial_println!("udp_smoke: socket() -> fd {}", fd);

    let bind_addr = build_sockaddr([0, 0, 0, 0], LOCAL_PORT);
    let rc = oxidebsd_sys_bind(fd, bind_addr.as_ptr() as u64, 16);
    assert_eq!(rc, 0, "bind() failed: {rc}");
    serial_println!("udp_smoke: bind() -> port {}", LOCAL_PORT);

    let rc = oxidebsd_sys_setsockopt(fd, 1, 2);
    assert_eq!(rc, 0, "setsockopt() failed: {rc}");

    // Real send, over the actual wire -- proves the TX path (ARP resolve, IPv4 checksum, UDP
    // header, NIC send) still works with the new socket code on top of it.
    let dest_addr = build_sockaddr(ipv4::GATEWAY_IP, SEND_DEST_PORT);
    let rc = oxidebsd_sys_sendto(
        fd,
        PING_PAYLOAD.as_ptr() as u64,
        PING_PAYLOAD.len() as u64,
        dest_addr.as_ptr() as u64,
    );
    assert_eq!(
        rc,
        PING_PAYLOAD.len() as i64,
        "sendto() didn't report the full payload sent: {rc}"
    );
    serial_println!(
        "udp_smoke: sendto() -> {} bytes sent to real gateway {:?}",
        rc,
        ipv4::GATEWAY_IP
    );

    // Synthetic receive -- bypasses the NIC entirely, proving RX dispatch/port lookup/recvfrom
    // deterministically (see this file's own doc comment for why this half doesn't use real
    // hardware the way the send half above does).
    let peer_mac = [0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC];
    let (frame, len) = build_udp_frame(
        our_mac,
        peer_mac,
        ipv4::GATEWAY_IP,
        ipv4::GUEST_IP,
        PEER_PORT,
        LOCAL_PORT,
        PONG_PAYLOAD,
    );
    ethernet::handle_frame(&frame[..len]);

    let mut recv_buf = [0u8; 64];
    let mut src_addr = [0u8; 16];
    let rc = oxidebsd_sys_recvfrom(
        fd,
        recv_buf.as_mut_ptr() as u64,
        recv_buf.len() as u64,
        src_addr.as_mut_ptr() as u64,
    );
    assert_eq!(
        rc,
        PONG_PAYLOAD.len() as i64,
        "recvfrom() didn't return the injected payload's length: {rc}"
    );
    assert_eq!(
        &recv_buf[..rc as usize],
        PONG_PAYLOAD,
        "recvfrom() payload mismatch"
    );
    let src_port = u16::from_be_bytes([src_addr[2], src_addr[3]]);
    let src_ip: [u8; 4] = src_addr[4..8].try_into().unwrap();
    assert_eq!(src_port, PEER_PORT, "recvfrom() source port mismatch");
    assert_eq!(
        src_ip,
        ipv4::GATEWAY_IP,
        "recvfrom() source address mismatch"
    );

    serial_println!(
        "udp_smoke: recvfrom() -> {} bytes from {:?}:{} -- UDP stack verified end to end (real \
         TX + synthetic RX)",
        rc,
        src_ip,
        src_port
    );
    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
