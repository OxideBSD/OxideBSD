//! The installer's engine (OxideBSD-doc `INSTALLER.md` step 9a), in three boots, each at 64 MB
//! (`scripts/qemu_runner.sh`): the install medium, where `tests/install_disk.serial` runs
//! `installer -f` with the guided layout onto a blank disk; then the installed disk alone, on UEFI
//! and on BIOS, each to the login prompt of the host name the answer file gave.

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
