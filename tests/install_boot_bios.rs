//! `install_boot` under BIOS (OxideBSD-doc `INSTALLER.md` step 6): the same medium, booted from
//! its El Torito BIOS image, the same checks.

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
