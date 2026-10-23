//! The install medium (OxideBSD-doc `INSTALLER.md` step 6), under UEFI: `scripts/mkinstalliso.sh`
//! makes it from this kernel, which the QEMU runner boots at 64 MB with no system disk, only a
//! blank one. Once the installer's first screen is up, `tests/install_boot.serial` chooses Shell
//! and checks the mfsroot from it: one crunched program behind the tools, a writable root and
//! `/tmp`, the blank disk registered.

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
