//! Real-`SYSCALL` counterpart to `tests/tcp_smoke.rs` -- see CLAUDE.md's "Real networking"
//! section for the blind spot this closes: every existing network smoke test calls kernel
//! handlers as plain Rust functions from its own `main()`, never through a genuine `SYSCALL` with
//! interrupts actually masked the way a real syscall runs. This test instead spawns
//! `regress/tcp-syscall-smoke/` as pid 1 and lets it drive `socket`/`bind`/`listen`/`accept`/
//! `read`/`write`/`fcntl` entirely through real `SYSCALL`/`SYSRETQ`.
//!
//! The synthetic peer's own script (ARP reply, SYN, final ACK, data segment, FIN) needs this
//! connection's internally-generated sequence number (`tcp::debug_send_next`/
//! `debug_connection_for`) to build valid segments -- state the spawned child has no way to
//! observe itself, and this file's own `main()` can't run again once `scheduler::start` hands
//! control to the child anyway. So the whole script is driven by one **test-only**,
//! step-dispatched syscall the child calls at each scripted moment: `SYS_TEST_TCP_STEP = 9997`.
//! See `regress/tcp-syscall-smoke/src/main.rs`'s own module doc comment for why this doesn't
//! reintroduce the blind spot being closed here -- `socket`/`bind`/`listen`/`accept`/`read`/
//! `write`/`fcntl` still only ever run when the child calls them via real `SYSCALL`.
//!
//! Installs the same no-op `NicDriver` `tests/tcp_smoke.rs` uses (QEMU SLIRP proxies every
//! guest-originated SYN as a real outbound connection attempt regardless of destination -- see
//! that test's own doc comment for the full story of why no real NIC is used here at all).
#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use alloc::boxed::Box;
use alloc::vec::Vec;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::net::nic::{NIC, NicDriver, NicError};
use oxidebsd::net::tcp;
use oxidebsd::net::{ethernet, ipv4};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/tcp-syscall-smoke/src/main.rs`'s own constants.
const SYS_TEST_EXIT: u64 = 9999;
const SYS_TEST_TCP_STEP: u64 = 9997;
const LISTEN_PORT: u16 = 7001;
const PEER_IP: [u8; 4] = [10, 0, 2, 66];
const PEER_PORT: u16 = 55556;
const PEER_ISN: u32 = 1000;
const PEER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xBE, 0xEF, 0x02];
const CLIENT_DATA: &[u8] = b"hello-tcp-syscall";
const SERVER_DATA: &[u8] = b"echo-back-syscall";

const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x11, 0x22, 0x44];

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

/// Set by step 0 once the synthetic peer's SYN has created a pending connection -- every later
/// step refers back to this same connection, since `debug_send_next`/`tcp_read`/`tcp_write` all
/// key off this "real_fd", which (see `oxidebsd_sys_accept`'s own implementation) is also exactly
/// the fd number the child process itself sees returned from `accept()`.
static mut CONN_FD: u64 = 0;
/// Set by step 1, read by step 2 -- proves `write()` actually advanced the connection's send
/// sequence, not just returned a fake success.
static mut SEQ_SNAPSHOT: u32 = 0;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "tcp_syscall_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
    oxidebsd::hlt_loop();
}

/// See this file's own doc comment for why real hardware isn't used at all here.
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

    // TCP checksum: a 12-byte pseudo-header prepended to the segment, checksum field zeroed while
    // summing -- matches sys/net/tcp.rs's own tcp_checksum exactly, duplicated here on purpose
    // (this test builds wire bytes independently, not by calling into the implementation it's
    // verifying).
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

/// Step-dispatched test-only syscall driving the synthetic peer's script -- see this file's own
/// module doc comment.
extern "C" fn test_tcp_step_handler(step: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    match step {
        0 => {
            // Synthetic peer opens a connection: ARP reply, then SYN, then read the connection's
            // own generated seq to build a valid final ACK -- completes the handshake in one call.
            let arp_reply = build_arp_reply(PEER_MAC, PEER_IP, OUR_MAC, ipv4::GUEST_IP);
            ethernet::handle_frame(&arp_reply);

            let (syn, syn_len) = build_tcp_frame(
                OUR_MAC,
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

            let Some(conn_fd) = tcp::debug_connection_for(LISTEN_PORT, PEER_IP, PEER_PORT) else {
                serial_println!("tcp_syscall_smoke: no connection created after injecting a SYN");
                return -1;
            };
            let Some(our_seq) = tcp::debug_send_next(conn_fd) else {
                serial_println!("tcp_syscall_smoke: connection vanished after SYN");
                return -1;
            };
            unsafe {
                CONN_FD = conn_fd;
            }

            let (final_ack, final_ack_len) = build_tcp_frame(
                OUR_MAC,
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
            0
        }
        1 => {
            let conn_fd = unsafe { CONN_FD };
            let Some(seq) = tcp::debug_send_next(conn_fd) else {
                return -1;
            };
            unsafe {
                SEQ_SNAPSHOT = seq;
            }
            0
        }
        2 => {
            let conn_fd = unsafe { CONN_FD };
            let Some(seq) = tcp::debug_send_next(conn_fd) else {
                return -1;
            };
            let advanced = seq == unsafe { SEQ_SNAPSHOT }.wrapping_add(SERVER_DATA.len() as u32);
            if advanced { 1 } else { 0 }
        }
        3 => {
            let conn_fd = unsafe { CONN_FD };
            let Some(our_seq) = tcp::debug_send_next(conn_fd) else {
                return -1;
            };
            let (data_seg, data_len) = build_tcp_frame(
                OUR_MAC,
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
            0
        }
        4 => {
            let conn_fd = unsafe { CONN_FD };
            let Some(seq_after) = tcp::debug_send_next(conn_fd) else {
                return -1;
            };
            let (fin_seg, fin_len) = build_tcp_frame(
                OUR_MAC,
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
            0
        }
        _ => -1,
    }
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);
    *NIC.lock() = Some(Box::new(NoopNic));

    const NATIVE_ABI_MOD: &[u8] = include_bytes!(env!("NATIVE_ABI_MOD_PATH"));
    const NATIVE_ABI_PANIC_SYMBOL: &str = env!("NATIVE_ABI_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "native_abi",
        NATIVE_ABI_MOD,
        NATIVE_ABI_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the native_abi module: {e:?}"));

    const POSIX_COMPAT_MOD: &[u8] = include_bytes!(env!("POSIX_COMPAT_MOD_PATH"));
    const POSIX_COMPAT_PANIC_SYMBOL: &str = env!("POSIX_COMPAT_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "posix_compat",
        POSIX_COMPAT_MOD,
        POSIX_COMPAT_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the posix_compat module: {e:?}"));

    const NET_MOD: &[u8] = include_bytes!(env!("NET_MOD_PATH"));
    const NET_PANIC_SYMBOL: &str = env!("NET_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "net",
        NET_MOD,
        NET_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the net module: {e:?}"));

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );
    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_TCP_STEP, test_tcp_step_handler),
        0,
        "SYS_TEST_TCP_STEP registration failed -- number collided with a real syscall?"
    );

    const TCP_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("TCP_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "tcp_syscall_smoke: spawning tcp-syscall-smoke as pid 1 ({} byte ELF)",
        TCP_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(TCP_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn tcp-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
