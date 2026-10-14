//! The 128 MB floor (OxideBSD-doc `RAM_FLOOR.md` §4.9): the real system -- kernel, modules, the
//! system image's `/sbin/init`, `/etc/rc` and getty -- must reach a login prompt in 128 MB of RAM.
//! This kernel is the real one; the QEMU runner gives it 128 MB, passes when `login:` reaches the
//! serial console, and fails on a panic or anything running out of memory
//! (`scripts/qemu_runner.sh`, `TEST_NAME` `ram_floor_boot`).
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
