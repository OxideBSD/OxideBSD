//! Multiboot2 boot-path smoke test (see CLAUDE.md's Multiboot2 section). Lives here so it's
//! visually grouped with every other `tests/*.rs` smoke test, but its actual compilation unit is
//! the separate `smoke/multiboot2-boot-smoke` workspace member (needed so it can get its own
//! linker script -- see that crate's `build.rs`) -- it is deliberately not one of this package's
//! own `[[test]]` entries and is not touched by a plain `cargo test`.
//!
//! Deliberately as close to `tests/basic_boot.rs` as possible: same `oxidebsd::init(boot_info)`
//! call, same shape -- the only difference is the macro that gets `boot_info` in the first place.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::multiboot2_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::{serial_print, serial_println};

multiboot2_entry_point!(main);

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);

    serial_print!("multiboot2_boot_smoke::kernel_boots...\t");
    assert_eq!(1, 1);
    serial_println!("[ok]");

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
