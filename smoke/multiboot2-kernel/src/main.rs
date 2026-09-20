//! The real kernel, entered via the Multiboot2 boot path (see CLAUDE.md's Multiboot2 section and
//! `oxidebsd::kernel_main`'s own doc comment for why this crate exists as a separate binary rather
//! than reusing `src/main.rs` directly the way `smoke/multiboot2-boot-smoke` reuses
//! `tests/multiboot2_boot_smoke.rs`). `run_real_system` is the exact function the ordinary Limine
//! boot path (`src/main.rs`'s `kernel_main`) also calls -- same module loading, same `hush` spawn,
//! same scheduler handoff, byte-for-byte.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

oxidebsd::multiboot2_entry_point!(oxidebsd::kernel_main::run_real_system);

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::serial_println!("{}", info);
    oxidebsd::hlt_loop();
}
