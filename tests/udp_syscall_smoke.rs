//! Real-`SYSCALL` counterpart to `tests/udp_smoke.rs` -- see CLAUDE.md's "Real networking"
//! section for the blind spot this closes: every existing network smoke test calls kernel
//! handlers as plain Rust functions from its own `main()`, never through a genuine `SYSCALL` with
//! interrupts actually masked the way a real syscall runs. This test instead spawns
//! `regress/udp-syscall-smoke/` as pid 1 and lets it drive `socket`/`bind`/`sendto`/`recvfrom`
//! entirely through real `SYSCALL`/`SYSRETQ`.
//!
//! Since `main()` can't run again once `scheduler::start` hands control to the child, the
//! synthetic-inbound-frame half of the original test (previously injected directly from this
//! file's own linear code) is instead triggered by a **test-only** syscall
//! (`SYS_TEST_INJECT_UDP_FRAME = 9998`) the child calls right after `bind()` -- see
//! `regress/udp-syscall-smoke/src/main.rs`'s own module doc comment for why this doesn't
//! reintroduce the blind spot being closed here.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::net::{ethernet, ipv4, rtl8139};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/udp-syscall-smoke/src/main.rs`'s own constants.
const SYS_TEST_EXIT: u64 = 9999;
const SYS_TEST_INJECT_UDP_FRAME: u64 = 9998;
const LOCAL_PORT: u16 = 23456;
const PEER_PORT: u16 = 54321;
const PONG_PAYLOAD: &[u8] = b"udp-syscall-smoke-pong";

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "udp_syscall_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
    oxidebsd::hlt_loop();
}

/// Same synthetic-frame technique `tests/udp_smoke.rs`/`tests/poll_smoke.rs` already established
/// -- just built from inside a test-only syscall handler instead of `main()`'s own linear code,
/// since `main()` never gets control back after `scheduler::start`.
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

extern "C" fn test_inject_udp_frame_handler(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    let our_mac = ethernet::our_mac().expect("NIC must be installed for this test to run at all");
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
    0
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    rtl8139::init(&mut frame_allocator, physical_memory_offset);
    if ethernet::our_mac().is_none() {
        serial_println!(
            "udp_syscall_smoke: no NIC installed -- is -device rtl8139 passed to QEMU?"
        );
        exit_qemu(QemuExitCode::Failed);
        oxidebsd::hlt_loop();
    }

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
        oxidebsd_register_syscall(SYS_TEST_INJECT_UDP_FRAME, test_inject_udp_frame_handler),
        0,
        "SYS_TEST_INJECT_UDP_FRAME registration failed -- number collided with a real syscall?"
    );

    const UDP_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("UDP_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "udp_syscall_smoke: spawning udp-syscall-smoke as pid 1 ({} byte ELF)",
        UDP_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(UDP_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn udp-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
