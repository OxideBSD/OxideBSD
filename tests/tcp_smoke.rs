//! Networking Phase 4's smoke test (see this repo's networking plan): a synthetic peer opens a
//! TCP connection to a real listening socket, exchanges data, entirely scripted from this test's
//! own `main` -- no real remote TCP endpoint involved.
//!
//! Unlike Phases 1-3 (which validated against SLIRP's own real, if virtual, gateway), this test
//! can't do the same for TCP, for two independent reasons:
//! - `oxidebsd_sys_connect`'s self-poll loop blocks internally until the handshake completes or
//!   times out, so there's no way for a single-threaded test to observe an in-progress
//!   connection's own internally-generated sequence numbers and script a believable reply
//!   mid-call. The *passive*-open (`listen`/`accept`) side has no such problem -- `listen()`
//!   returns immediately.
//! - More fundamentally: **QEMU SLIRP proxies every guest-originated TCP SYN as a real outbound
//!   connection attempt, regardless of destination** (confirmed live -- addressing this test's
//!   own synthetic-peer replies to an RFC 5737 documentation address, and separately to an
//!   address inside SLIRP's own 10.0.2.0/24 subnet, both produced real synthesized RSTs racing
//!   and tearing down this test's own connection state once SLIRP's relay attempt failed).
//!   There's no destination address that makes SLIRP just silently ignore an unsolicited SYN-ACK
//!   the way it does for ARP/ICMP. So this test doesn't use the real NIC at all -- it installs a
//!   trivial no-op `NicDriver` (`nic::NIC` is a `pub static` precisely so a second driver can be
//!   swapped in; see `sys/net/nic.rs`'s own doc comment on why the trait exists) whose `send`
//!   always succeeds without touching real hardware, so nothing this test's stack transmits can
//!   ever reach SLIRP to be misinterpreted as a real connection attempt.
//!
//! This test injects a synthetic SYN via `ethernet::handle_frame` (bypassing the NIC entirely,
//! same technique `tests/udp_smoke.rs`'s RX half already used), reads back the connection's own
//! generated sequence number via two `tcp` module functions kept `pub` specifically for this (see
//! their own doc comments), and uses that to script a valid final ACK and a data segment. This
//! exercises the full state machine (`SynReceived` -> `Established`, in-order data delivery,
//! `accept()`'s promotion) deterministically. The reply `write()` still proves the send path
//! (checksum, header build, `try_send`'s bookkeeping) runs correctly end to end -- just through
//! the no-op driver interface rather than real hardware, which Phases 1-3 (and `tcp_write`'s own
//! use of the exact same `ipv4::send_packet` those already exercise) already prove independently.
#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use alloc::boxed::Box;
use alloc::vec::Vec;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::net::nic::{NIC, NicDriver, NicError};
use oxidebsd::net::tcp::{self, oxidebsd_sys_accept, oxidebsd_sys_listen};
use oxidebsd::net::udp::{oxidebsd_sys_bind, oxidebsd_sys_socket};
use oxidebsd::net::{ethernet, ipv4};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::{oxidebsd_sys_fcntl, oxidebsd_sys_read, oxidebsd_sys_write};

limine_entry_point!(main);

const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const F_SETFL: u64 = 4;
const O_NONBLOCK: u64 = 0o4000;

const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];

const LISTEN_PORT: u16 = 7000;
const PEER_PORT: u16 = 55555;
const PEER_ISN: u32 = 1000;
/// Not a real, reachable address of any kind -- doesn't need to be, since the no-op driver (see
/// this file's own doc comment) means nothing this test's stack sends ever actually reaches a
/// wire for any real host to answer or reject.
const PEER_IP: [u8; 4] = [10, 0, 2, 66];
const PEER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xBE, 0xEF, 0x01];

const CLIENT_DATA: &[u8] = b"hello-tcp";
const SERVER_DATA: &[u8] = b"echo-back";

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

fn build_sockaddr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip);
    buf
}

fn build_arp_reply(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
) -> [u8; 42] {
    let mut frame = [0u8; 42];
    frame[0..6].copy_from_slice(&target_mac);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());

    let arp = &mut frame[14..42];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // HTYPE ethernet
    arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // PTYPE IPv4
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&2u16.to_be_bytes()); // OPER reply
    arp[8..14].copy_from_slice(&sender_mac);
    arp[14..18].copy_from_slice(&sender_ip);
    arp[18..24].copy_from_slice(&target_mac);
    arp[24..28].copy_from_slice(&target_ip);
    frame
}

/// Ten parameters, one per real field this test needs to vary across the SYN/ACK/data segments
/// it builds -- see `sys/net/tcp.rs`'s own `send_segment` for the same shape, for the same reason.
#[allow(clippy::too_many_arguments)]
fn build_tcp_frame(
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    data: &[u8],
) -> ([u8; 128], usize) {
    let mut frame = [0u8; 128];
    let tcp_len = 20 + data.len();
    let ip_len = 20 + tcp_len;
    let total = 14 + ip_len;
    assert!(total <= frame.len(), "test frame buffer too small");

    frame[0..6].copy_from_slice(&dest_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = &mut frame[14..14 + ip_len];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 6; // TCP
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let ip_cksum = ipv4::checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    {
        let tcp = &mut ip[20..20 + tcp_len];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4; // data offset = 5 (20 bytes, no options)
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&8192u16.to_be_bytes()); // window
        tcp[20..].copy_from_slice(data);
    }

    // TCP checksum: a 12-byte pseudo-header (src/dst IP, zero, protocol, TCP length) prepended to
    // the segment itself, checksum field zeroed while summing -- matches sys/net/tcp.rs's own
    // `tcp_checksum` exactly, duplicated here on purpose (this test builds wire bytes
    // independently, not by calling into the implementation it's verifying).
    let mut pseudo = [0u8; 12 + 128];
    pseudo[0..4].copy_from_slice(&src_ip);
    pseudo[4..8].copy_from_slice(&dst_ip);
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo[12..12 + tcp_len].copy_from_slice(&ip[20..20 + tcp_len]);
    let tcp_cksum = ipv4::checksum(&pseudo[..12 + tcp_len]);
    ip[36..38].copy_from_slice(&tcp_cksum.to_be_bytes());

    (frame, total)
}

/// See this file's own doc comment for why real hardware isn't used at all here. `send` always
/// succeeds without touching anything real; `poll_recv` never has anything to report, since
/// nothing external can ever reach a driver that was never plugged into a wire.
struct NoopNic;

impl NicDriver for NoopNic {
    fn send(&mut self, _frame: &[u8]) -> Result<(), NicError> {
        Ok(())
    }

    fn poll_recv(&mut self) -> Option<Vec<u8>> {
        None
    }

    fn mac_address(&self) -> [u8; 6] {
        OUR_MAC
    }
}

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);
    *NIC.lock() = Some(Box::new(NoopNic));
    let our_mac = OUR_MAC;

    let arp_reply = build_arp_reply(PEER_MAC, PEER_IP, our_mac, ipv4::GUEST_IP);
    ethernet::handle_frame(&arp_reply);

    let listen_fd = oxidebsd_sys_socket(AF_INET, SOCK_STREAM, 0);
    assert!(listen_fd >= 0, "socket() failed: {listen_fd}");
    let listen_fd = listen_fd as u64;

    let bind_addr = build_sockaddr([0, 0, 0, 0], LISTEN_PORT);
    let rc = oxidebsd_sys_bind(listen_fd, bind_addr.as_ptr() as u64, 16);
    assert_eq!(rc, 0, "bind() failed: {rc}");

    let rc = oxidebsd_sys_listen(listen_fd, 4);
    assert_eq!(rc, 0, "listen() failed: {rc}");
    serial_println!("tcp_smoke: listening on port {}", LISTEN_PORT);

    // --- Synthetic peer opens a connection: SYN ---
    let (syn, syn_len) = build_tcp_frame(
        our_mac,
        PEER_MAC,
        PEER_IP,
        ipv4::GUEST_IP,
        PEER_PORT,
        LISTEN_PORT,
        PEER_ISN,
        0,
        FLAG_SYN,
        &[],
    );
    ethernet::handle_frame(&syn[..syn_len]);

    let conn_fd = tcp::debug_connection_for(LISTEN_PORT, PEER_IP, PEER_PORT)
        .expect("no connection created after injecting a SYN");
    let our_seq = tcp::debug_send_next(conn_fd).expect("connection vanished after SYN");
    serial_println!(
        "tcp_smoke: SYN accepted, connection pending as fd {} (our SYN-ACK's own seq+1 = {})",
        conn_fd,
        our_seq
    );

    // --- Synthetic peer completes the handshake: ACK ---
    let (final_ack, final_ack_len) = build_tcp_frame(
        our_mac,
        PEER_MAC,
        PEER_IP,
        ipv4::GUEST_IP,
        PEER_PORT,
        LISTEN_PORT,
        PEER_ISN.wrapping_add(1),
        our_seq,
        FLAG_ACK,
        &[],
    );
    ethernet::handle_frame(&final_ack[..final_ack_len]);

    let mut addr_out = [0u8; 16];
    let mut addrlen: u32 = 16;
    let accepted = oxidebsd_sys_accept(
        listen_fd,
        addr_out.as_mut_ptr() as u64,
        (&raw mut addrlen) as u64,
    );
    assert_eq!(
        accepted, conn_fd as i64,
        "accept() didn't return the promoted connection's fd"
    );
    let accepted_port = u16::from_be_bytes([addr_out[2], addr_out[3]]);
    let accepted_ip: [u8; 4] = addr_out[4..8].try_into().unwrap();
    assert_eq!(accepted_ip, PEER_IP, "accept() peer address mismatch");
    assert_eq!(accepted_port, PEER_PORT, "accept() peer port mismatch");
    serial_println!(
        "tcp_smoke: accept() -> fd {} from {:?}:{} -- three-way handshake verified",
        accepted,
        accepted_ip,
        accepted_port
    );

    // --- Synthetic peer sends data ---
    let (data_seg, data_len) = build_tcp_frame(
        our_mac,
        PEER_MAC,
        PEER_IP,
        ipv4::GUEST_IP,
        PEER_PORT,
        LISTEN_PORT,
        PEER_ISN.wrapping_add(1),
        our_seq,
        FLAG_ACK | FLAG_PSH,
        CLIENT_DATA,
    );
    ethernet::handle_frame(&data_seg[..data_len]);

    let mut recv_buf = [0u8; 64];
    let n = oxidebsd_sys_read(
        accepted as u64,
        recv_buf.as_mut_ptr() as u64,
        recv_buf.len() as u64,
    );
    assert_eq!(
        n,
        CLIENT_DATA.len() as i64,
        "read() didn't return the injected payload's length: {n}"
    );
    assert_eq!(
        &recv_buf[..n as usize],
        CLIENT_DATA,
        "read() payload mismatch"
    );
    serial_println!("tcp_smoke: read() -> {} bytes of real in-order data", n);

    // --- We reply -- through the driver interface, not real hardware (see this file's own doc
    // comment), but exercising the exact same send/checksum/bookkeeping path either way ---
    let seq_before = tcp::debug_send_next(accepted as u64).unwrap();
    let n = oxidebsd_sys_write(
        accepted as u64,
        SERVER_DATA.as_ptr() as u64,
        SERVER_DATA.len() as u64,
    );
    assert_eq!(
        n,
        SERVER_DATA.len() as i64,
        "write() didn't accept the full payload: {n}"
    );
    let seq_after = tcp::debug_send_next(accepted as u64).unwrap();
    assert_eq!(
        seq_after,
        seq_before.wrapping_add(SERVER_DATA.len() as u32),
        "write() didn't actually transmit a segment"
    );
    serial_println!(
        "tcp_smoke: write() -> {} bytes sent, sequence number advanced for real -- TCP stack \
         verified end to end",
        n
    );

    // --- read() on an empty-but-still-open connection: with O_NONBLOCK set, must return EAGAIN
    // immediately, not spin forever (see sys/net/tcp.rs's own tcp_read doc comment -- there's
    // nothing else in this single-process test that would ever call poll() again on our behalf,
    // so a real hang here would mean the fix regressed, not just a slow test). ---
    let rc = oxidebsd_sys_fcntl(accepted as u64, F_SETFL, O_NONBLOCK);
    assert_eq!(rc, 0, "fcntl(F_SETFL, O_NONBLOCK) failed: {rc}");
    let n = oxidebsd_sys_read(
        accepted as u64,
        recv_buf.as_mut_ptr() as u64,
        recv_buf.len() as u64,
    );
    assert!(
        n < 0,
        "read() on an empty, still-open, O_NONBLOCK connection should fail (EAGAIN), not block \
         or return 0: {n}"
    );
    serial_println!("tcp_smoke: O_NONBLOCK read() on an empty connection -> real EAGAIN verified");

    // --- Synthetic peer sends a FIN: only *now* should read() report real EOF ---
    let (fin_seg, fin_len) = build_tcp_frame(
        our_mac,
        PEER_MAC,
        PEER_IP,
        ipv4::GUEST_IP,
        PEER_PORT,
        LISTEN_PORT,
        PEER_ISN
            .wrapping_add(1)
            .wrapping_add(CLIENT_DATA.len() as u32),
        seq_after,
        FLAG_FIN | FLAG_ACK,
        &[],
    );
    ethernet::handle_frame(&fin_seg[..fin_len]);

    let n = oxidebsd_sys_read(
        accepted as u64,
        recv_buf.as_mut_ptr() as u64,
        recv_buf.len() as u64,
    );
    assert_eq!(
        n, 0,
        "read() after a real peer FIN should report EOF (0): {n}"
    );
    serial_println!(
        "tcp_smoke: read() after a real peer FIN -> real EOF verified -- tcp_read's EOF-vs-empty \
         distinction verified end to end"
    );

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
