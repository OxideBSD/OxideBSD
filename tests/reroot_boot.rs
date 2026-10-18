//! The root switch (`reboot -r`, OxideBSD-doc `RAM_FLOOR.md` §5.1): the real system boots from a
//! disk with two roots (`scripts/mkreroottestimg.sh`); the first's `/etc/rc` switches to the
//! second, whose `/etc/rc` checks the switch and prints `reroot-smoke: PASS`, which the QEMU runner
//! waits for.
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
