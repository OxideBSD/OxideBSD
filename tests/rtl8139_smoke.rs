//! Networking Phase 1's smoke test (see this repo's networking plan): boots the kernel, brings
//! up the rtl8139 driver, and sends a broadcast ARP request for QEMU SLIRP's default gateway.
//! SLIRP answers ARP requests for itself unprompted -- a real, externally-triggered RX event
//! that exercises PCI discovery, TX, IRQ delivery, and RX ring parsing end to end, without
//! needing any host-side tooling beyond QEMU's own `-nic user` backend (see Cargo.toml's
//! `test-args`).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::cpu::interrupts;
use oxidebsd::limine_entry_point;
use oxidebsd::net::{nic, rtl8139};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

/// SLIRP's default guest IP under QEMU's `-nic user` backend.
const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
/// SLIRP's default gateway -- answers ARP requests for itself unprompted.
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ARP_HTYPE_ETHERNET: [u8; 2] = [0x00, 0x01];
const ARP_PTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ARP_OPER_REQUEST: [u8; 2] = [0x00, 0x01];

fn build_arp_request(src_mac: [u8; 6]) -> [u8; 42] {
    let mut frame = [0u8; 42];
    frame[0..6].copy_from_slice(&[0xFF; 6]); // dest: broadcast
    frame[6..12].copy_from_slice(&src_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP);

    let arp = &mut frame[14..42];
    arp[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET);
    arp[2..4].copy_from_slice(&ARP_PTYPE_IPV4);
    arp[4] = 6; // HLEN
    arp[5] = 4; // PLEN
    arp[6..8].copy_from_slice(&ARP_OPER_REQUEST);
    arp[8..14].copy_from_slice(&src_mac);
    arp[14..18].copy_from_slice(&GUEST_IP);
    arp[18..24].copy_from_slice(&[0u8; 6]); // target MAC: unknown, that's what we're asking
    arp[24..28].copy_from_slice(&GATEWAY_IP);

    frame
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (_mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    rtl8139::init(&mut frame_allocator, physical_memory_offset);

    let mac = {
        let mut guard = nic::NIC.lock();
        let Some(driver) = guard.as_mut() else {
            serial_println!(
                "rtl8139_smoke: no NIC installed -- is -device rtl8139 passed to QEMU?"
            );
            exit_qemu(QemuExitCode::Failed);
            oxidebsd::hlt_loop();
        };
        driver.mac_address()
    };
    serial_println!(
        "rtl8139_smoke: sending broadcast ARP request from {:02x?} for {:?}",
        mac,
        GATEWAY_IP
    );

    let request = build_arp_request(mac);
    nic::NIC
        .lock()
        .as_mut()
        .expect("NIC vanished between checks")
        .send(&request)
        .expect("failed to send ARP request");

    // Bounded by PIT ticks (100 Hz, src/pit.rs), not an arbitrary spin count -- SLIRP typically
    // answers within a few milliseconds, so a few seconds of budget is generous headroom, not a
    // tight timing assumption.
    let deadline = interrupts::ticks() + 500; // ~5s at 100 Hz
    loop {
        if rtl8139::irq_fired()
            && let Some(reply) = nic::NIC.lock().as_mut().unwrap().poll_recv()
        {
            serial_println!("rtl8139_smoke: received a {}-byte frame", reply.len());
            if reply.get(12..14) == Some(ETHERTYPE_ARP.as_slice()) {
                serial_println!(
                    "rtl8139_smoke: ARP reply received -- IRQ path verified end to end"
                );
                exit_qemu(QemuExitCode::Success);
                oxidebsd::hlt_loop();
            }
        }
        if interrupts::ticks() >= deadline {
            serial_println!("rtl8139_smoke: timed out waiting for an ARP reply");
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
