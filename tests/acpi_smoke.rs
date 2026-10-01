//! `sys/acpi.rs`: the `\_S5` scan over hand-assembled AML, then `acpi::init` over the firmware's
//! real tables, which must yield a PM1a control port and a 3-bit sleep type. (Powering off itself
//! ends the VM without an `isa-debug-exit` code, so it is checked by hand: `poweroff` under UEFI
//! and `OXIDEBSD_FIRMWARE=bios`.)
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::acpi;
use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);

    // Name (_S5, Package (0x04) { 0x05, 0x05, Zero, Zero }), with BytePrefix.
    let byte_prefix = [
        0x08, b'_', b'S', b'5', b'_', 0x12, 0x0A, 0x04, 0x0A, 0x05, 0x0A, 0x05, 0x00, 0x00,
    ];
    assert_eq!(acpi::find_s5(&byte_prefix), Some((5, 5)));
    // A root-qualified name, ZeroOp/OneOp elements, and a two-byte PkgLength (lead 0x40).
    let root_two_byte = [
        0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x40, 0x00, 0x02, 0x01, 0x00,
    ];
    assert_eq!(acpi::find_s5(&root_two_byte), Some((1, 0)));
    // Bare bytes, as some firmware writes them, after an unrelated _S5_ that isn't a Name.
    let bare = [
        0x70, b'_', b'S', b'5', b'_', 0x60, 0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x07,
        0x07,
    ];
    assert_eq!(acpi::find_s5(&bare), Some((7, 7)));
    assert_eq!(acpi::find_s5(b"no sleep states here"), None);
    serial_println!("acpi_smoke: _S5 scan ok");

    acpi::init(boot_info.physical_memory_offset);
    let off = acpi::soft_off().expect("no S5 information from the firmware's tables");
    assert_ne!(off.pm1a_cnt, 0, "no PM1a control port");
    assert!(
        off.slp_typa <= 7 && off.slp_typb <= 7,
        "sleep types aren't 3-bit: {:?}",
        off
    );
    serial_println!("acpi_smoke: firmware tables ok: {:?}", off);

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
