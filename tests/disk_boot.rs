//! The bootable disk image (OxideBSD-doc `RAM_FLOOR.md` §4.4.4) under UEFI (OVMF), with no ISO:
//! the firmware finds Limine on the ESP, Limine loads the kernel from it, and the real system must
//! reach a login prompt from the disk's root file system. The QEMU runner builds the image with
//! `scripts/mkbootimg.sh` (`TEST_NAME` `disk_boot`).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;

limine_entry_point!(main);

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::kernel_main::run_real_system(boot_info)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
