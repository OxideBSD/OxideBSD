//! Networking Phase 2's smoke test (see this repo's networking plan): boots the kernel, brings
//! up the rtl8139 driver, and pings QEMU SLIRP's default gateway (10.0.2.2) -- SLIRP answers
//! ICMP echo requests directed at itself, so a real reply exercises ARP resolution, IPv4 header
//! build/parse (with a real checksum), and ICMP echo request/reply construction end to end.
//!
//! Deliberately pings *from* the guest rather than trying to have the host ping *into* it: an
//! inbound host-to-guest ping through QEMU's SLIRP backend needs raw-socket privileges on the
//! host side that aren't guaranteed to be available (or desirable to require) in a test
//! environment, where `tests/rtl8139_smoke.rs`'s own trick (targeting SLIRP's self-answering
//! gateway) has no such dependency and still validates real network behavior, not a loopback.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::cpu::interrupts;
use oxidebsd::limine_entry_point;
use oxidebsd::net::{icmp, ipv4, nic, rtl8139};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

const ECHO_ID: u16 = 0x1234;
const ECHO_SEQ: u16 = 1;

fn main(boot_info: &'static BootInfo) -> ! {
    let (_mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    rtl8139::init(&mut frame_allocator, physical_memory_offset);
    if nic::NIC.lock().is_none() {
        serial_println!("icmp_smoke: no NIC installed -- is -device rtl8139 passed to QEMU?");
        exit_qemu(QemuExitCode::Failed);
        oxidebsd::hlt_loop();
    }

    serial_println!(
        "icmp_smoke: pinging SLIRP gateway {:?} (id {:#06x}, seq {})",
        ipv4::GATEWAY_IP,
        ECHO_ID,
        ECHO_SEQ
    );
    if icmp::send_echo_request(ipv4::GATEWAY_IP, ECHO_ID, ECHO_SEQ, b"oxidebsd-icmp-smoke")
        .is_none()
    {
        serial_println!("icmp_smoke: failed to send echo request (ARP resolution failed?)");
        exit_qemu(QemuExitCode::Failed);
        oxidebsd::hlt_loop();
    }

    // Bounded by PIT ticks, not an arbitrary spin count -- see rtl8139_smoke's own precedent.
    let deadline = interrupts::ticks() + 500; // ~5s at 100 Hz
    loop {
        oxidebsd::net::poll();
        if let Some((src_ip, id, seq)) = icmp::take_echo_reply()
            && src_ip == ipv4::GATEWAY_IP
            && id == ECHO_ID
            && seq == ECHO_SEQ
        {
            serial_println!(
                "icmp_smoke: real ICMP echo reply received -- IPv4/ICMP stack verified end to \
                 end"
            );
            exit_qemu(QemuExitCode::Success);
            oxidebsd::hlt_loop();
        }
        if interrupts::ticks() >= deadline {
            serial_println!("icmp_smoke: timed out waiting for an echo reply");
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
