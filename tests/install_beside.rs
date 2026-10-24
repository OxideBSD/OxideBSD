//! Installing beside another system (OxideBSD-doc `INSTALLER.md` step 9c), in three boots, each at
//! 64 MB (`scripts/qemu_runner.sh`): the install medium, where `tests/install_beside.serial` runs
//! `installer -f` with the guided layout onto a disk that holds a "Windows" EFI system partition
//! and another partition, then checks the boot menu lists Windows and the firmware has an
//! `OxideBSD` entry; then the installed disk alone, on UEFI (through that entry: the disk's
//! removable fallback isn't a loader) and on BIOS, each to the login prompt. The other partition
//! is checked byte for byte on the host.

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
