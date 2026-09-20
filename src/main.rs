#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(oxidebsd::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::serial_println;

oxidebsd::limine_entry_point!(kernel_main);

#[cfg(test)]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    serial_println!("OxideBSD kernel booting...");

    oxidebsd::init(boot_info);
    test_main();

    serial_println!("OxideBSD kernel is up, entering idle loop");

    oxidebsd::hlt_loop();
}

/// Real regular boot -- delegates entirely to `oxidebsd::kernel_main::run_real_system`, shared
/// verbatim with the Multiboot2 boot path's own dedicated entry crate
/// (`smoke/multiboot2-kernel/`, see CLAUDE.md's Multiboot2 section) so both loaders reach the
/// exact same module-loading/hush-spawn/scheduler-handoff sequence, not two copies that could
/// drift apart.
#[cfg(not(test))]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::kernel_main::run_real_system(boot_info)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    oxidebsd::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
