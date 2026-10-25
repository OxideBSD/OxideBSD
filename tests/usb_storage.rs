//! Smoke test for USB mass storage (`sys/drivers/usb/storage.rs`): the Bulk-Only Transport over
//! xHCI, SCSI commands, and the read path, against QEMU's `usb-storage` stick (attached by
//! `scripts/qemu_runner.sh`'s own `usb_storage` case, its sector 0 carrying a known marker).
//!
//! In-kernel, like `ata_smoke` -- USB mass storage is a block driver below the system-call
//! surface, not a syscall handler, so it's exercised directly rather than through a spawned ELF.
//! Covers: the controller comes up and the stick enumerates and configures (`usb::init`), and a
//! real Bulk-Only `READ(10)` of sector 0 returns exactly the bytes the backing image holds --
//! proving CBW/data/CSW framing, the SCSI read, and the interrupt-driven completion path all work.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::drivers::usb;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

/// The marker `scripts/qemu_runner.sh` writes to sector 0 of the stick's backing image.
const MARKER: &[u8] = b"OXIDEBSD_USB_TEST_SECTOR";

fn main(boot_info: &'static BootInfo) -> ! {
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    usb::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    let mut buf = [0u8; 512];
    assert!(
        usb::read_first_storage_sectors(0, &mut buf),
        "usb_storage's runner should attach a usb-storage stick that reads over Bulk-Only Transport"
    );
    assert_eq!(
        &buf[..MARKER.len()],
        MARKER,
        "sector 0 of the USB stick should read back the marker the runner wrote"
    );
    serial_println!("usb_storage: READ(10) of sector 0 returned the marker over BOT");

    // A second sector, to catch an address-computation bug a sector-0-only read would miss: the
    // runner also writes the marker (plus a suffix) at sector 1.
    let mut buf1 = [0u8; 512];
    assert!(
        usb::read_first_storage_sectors(1, &mut buf1),
        "reading sector 1 over Bulk-Only Transport"
    );
    assert_eq!(
        &buf1[..MARKER.len()],
        MARKER,
        "sector 1 should read back its own marker, not sector 0's"
    );
    assert_eq!(&buf1[MARKER.len()..MARKER.len() + 2], b"_1", "sector 1's suffix");
    serial_println!("usb_storage: READ(10) of sector 1 verified distinct from sector 0");

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("usb_storage: PANIC: {}", info);
    exit_qemu(QemuExitCode::Failed);
    oxidebsd::hlt_loop();
}
