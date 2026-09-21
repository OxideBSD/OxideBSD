//! Smoke test for `SYS_POLL = 148` (`sys/net/mod.rs`'s `oxidebsd_sys_poll`) -- added to unblock a
//! real DNS resolver (musl's own stub resolver multiplexes nameserver retries with a real
//! `poll()`; see that function's own doc comment for why `__NR_poll`'s real, unremapped value
//! couldn't be used as-is). Two halves:
//! - A UDP socket with a synthetic datagram injected via `ethernet::handle_frame` (same technique
//!   `tests/udp_smoke.rs` uses) must be reported `POLLIN`-ready immediately.
//! - A second, empty UDP socket must correctly time out (return `0`, no `revents` set) rather
//!   than hang or false-positive.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::net::oxidebsd_sys_poll;
use oxidebsd::net::udp::{oxidebsd_sys_bind, oxidebsd_sys_socket};
use oxidebsd::net::{ethernet, ipv4, rtl8139};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

const AF_INET: u64 = 2;
const SOCK_DGRAM: u64 = 2;
const POLLIN: i16 = 0x0001;

const LOCAL_PORT: u16 = 23456;
const PEER_PORT: u16 = 65432;
const PAYLOAD: &[u8] = b"poll-me";

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

fn build_sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip);
    buf
}

/// Same synthetic-frame technique `tests/udp_smoke.rs` already established.
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
        serial_println!("poll_smoke: no NIC installed -- is -device rtl8139 passed to QEMU?");
        exit_qemu(QemuExitCode::Failed);
        oxidebsd::hlt_loop();
    };

    // Socket A: gets a synthetic datagram injected before poll() ever runs -- must report ready
    // immediately, not just eventually.
    let fd_a = oxidebsd_sys_socket(AF_INET, SOCK_DGRAM, 0);
    assert!(fd_a >= 0, "socket() (A) failed: {fd_a}");
    let fd_a = fd_a as u64;
    let bind_addr = build_sockaddr([0, 0, 0, 0], LOCAL_PORT);
    let rc = oxidebsd_sys_bind(fd_a, bind_addr.as_ptr() as u64, 16);
    assert_eq!(rc, 0, "bind() (A) failed: {rc}");

    let peer_mac = [0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC];
    let (frame, len) = build_udp_frame(
        our_mac,
        peer_mac,
        ipv4::GATEWAY_IP,
        ipv4::GUEST_IP,
        PEER_PORT,
        LOCAL_PORT,
        PAYLOAD,
    );
    ethernet::handle_frame(&frame[..len]);

    // Socket B: never gets anything -- must time out cleanly.
    let fd_b = oxidebsd_sys_socket(AF_INET, SOCK_DGRAM, 0);
    assert!(fd_b >= 0, "socket() (B) failed: {fd_b}");
    let fd_b = fd_b as u64;

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
    let rc = oxidebsd_sys_poll(fds.as_mut_ptr() as u64, 2, 500);
    assert_eq!(rc, 1, "poll() should report exactly one ready fd: {rc}");
    assert_eq!(
        fds[0].revents & POLLIN,
        POLLIN,
        "socket A should be POLLIN-ready"
    );
    assert_eq!(fds[1].revents, 0, "socket B should have no revents set");
    serial_println!("poll_smoke: poll() correctly reported the ready fd, ignored the empty one");

    // Socket B never received anything -- polling it alone must time out cleanly, not hang or
    // false-positive.
    let mut fds_empty = [PollFd {
        fd: fd_b as i32,
        events: POLLIN,
        revents: 0,
    }];
    let rc = oxidebsd_sys_poll(fds_empty.as_mut_ptr() as u64, 1, 200);
    assert_eq!(rc, 0, "poll() on an empty socket should time out: {rc}");
    assert_eq!(
        fds_empty[0].revents, 0,
        "timed-out poll() shouldn't set revents"
    );
    serial_println!(
        "poll_smoke: poll() correctly timed out on an empty socket -- SYS_POLL verified end to end"
    );

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
