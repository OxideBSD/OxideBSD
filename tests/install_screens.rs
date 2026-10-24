//! The installer's screens (OxideBSD-doc `INSTALLER.md` step 9b), in three boots, each at 64 MB
//! (`scripts/qemu_runner.sh`): the install medium, where `tests/install_screens.serial` answers
//! every screen with keys on the serial line -- keyboard, host name, the whole blank disk, the
//! base set, DHCP (tried there and then), Europe/Berlin, root's password and a user in wheel --
//! installs, and from the last screen's shell checks the new system's files; then the installed
//! disk alone, on UEFI and on BIOS, each to the login prompt of its host name.

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
