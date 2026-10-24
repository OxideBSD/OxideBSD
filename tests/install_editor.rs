//! The partition editor (OxideBSD-doc `INSTALLER.md` step 9b2), in three boots, each at 64 MB
//! (`scripts/qemu_runner.sh`): the install medium, where `tests/install_editor.serial` lays out two
//! disks by hand -- on the first, beside a "Windows" EFI system partition (kept) and another
//! partition, a BIOS boot partition and `/` in the free space; on the second, an existing oxfs
//! grown into the free space after it and kept as `/home` -- installs, and checks the result from
//! the last screen's shell; then both disks, booted on UEFI and on BIOS, each to the login
//! prompt, `/home` mounted from the second. The other partition is checked byte for byte on the
//! host.

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
