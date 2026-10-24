//! UEFI runtime services (OxideBSD-doc `EFIRT.md` step 1), under OVMF: the EFI page table is
//! built from the firmware's memory map, `GetTime` answers with a plausible date, and a call that
//! faults inside the firmware (`efirt::fault_for_test`) is caught -- the kernel goes on, with
//! runtime services off from then on.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::{efirt, serial_println};

limine_entry_point!(main);

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);
    efirt::init_and_log();
    assert!(efirt::available(), "no UEFI runtime services under OVMF");
    let (vendor, _, uefi) = efirt::firmware().expect("no firmware");
    assert!(!vendor.is_empty() && uefi >> 16 >= 2, "firmware {vendor:?}, UEFI {uefi:#x}");
    let t = efirt::get_time().expect("GetTime failed");
    assert!(t.year >= 2024 && (1..=12).contains(&t.month) && (1..=31).contains(&t.day), "a bad date: {t:?}");
    serial_println!("efirt_smoke: GetTime {:04}-{:02}-{:02}", t.year, t.month, t.day);

    assert!(efirt::fault_for_test(), "the faulting call wasn't caught");
    assert!(!efirt::available(), "runtime services still on after a fault");
    assert!(efirt::get_time().is_none(), "a call went through after a fault");
    serial_println!("efirt_smoke: a fault in the firmware is caught, and the firmware switched off");

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
