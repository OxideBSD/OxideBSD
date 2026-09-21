#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![feature(abi_x86_interrupt)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

pub mod boot;
pub mod console;
pub mod cpu;
pub mod drivers;
pub mod fs;
pub mod kernel_main;
pub mod memory;
pub mod module;
pub mod net;
pub mod process;
pub mod qemu;
pub mod random;
pub mod reboot;
pub mod syscall;

use core::panic::PanicInfo;

use boot::BootInfo;
use qemu::{QemuExitCode, exit_qemu};

/// Brings up the kernel: GDT/TSS, IDT, PIC + hardware interrupts, paging, and the heap.
///
/// Returns the kernel's own page-table mapper and physical frame allocator so callers can keep
/// using the *same* frame allocator afterward (e.g. to build further address spaces) — a second,
/// separately-`init`'d `BootInfoFrameAllocator` would restart handing out frames from the start of
/// the usable memory map, re-allocating ones the heap has already claimed.
pub fn init(
    boot_info: &'static BootInfo,
) -> (
    x86_64::structures::paging::OffsetPageTable<'static>,
    memory::BootInfoFrameAllocator,
) {
    serial_println!("[boot] kernel initialization starting");

    cpu::gdt::init();
    cpu::fpu::init();
    cpu::interrupts::init_idt();
    cpu::interrupts::init_pics();
    unsafe {
        cpu::pit::init();
    }
    syscall::init();

    serial_println!("[boot] enabling interrupts");
    x86_64::instructions::interrupts::enable();

    cpu::tsc::init();

    let phys_mem_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = unsafe { memory::init(phys_mem_offset) };
    let mut frame_allocator = unsafe { memory::BootInfoFrameAllocator::init(boot_info.memory_map) };

    let heap_size = memory::allocator::compute_heap_size(memory::usable_ram_bytes());
    memory::allocator::init_heap(&mut mapper, &mut frame_allocator, heap_size)
        .expect("heap initialization failed");

    serial_println!("[boot] kernel initialization complete");

    (mapper, frame_allocator)
}

pub trait Testable {
    fn run(&self);
}

impl<T: Fn()> Testable for T {
    fn run(&self) {
        serial_print!("{}...\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

pub fn test_panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    hlt_loop();
}

/// Spins forever and never returns.
///
/// This deliberately does not use `hlt`: `hlt` only resumes on the next interrupt, so if it's
/// ever reached with interrupts disabled (e.g. a panic during a `without_interrupts` critical
/// section) the CPU parks on that single instruction forever — indistinguishable from a genuine
/// halt/crash from outside the VM. A plain spin loop keeps the CPU visibly executing regardless
/// of interrupt state, at the cost of burning a full core doing nothing.
pub fn hlt_loop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
crate::limine_entry_point!(test_kernel_main);

#[cfg(test)]
fn test_kernel_main(boot_info: &'static BootInfo) -> ! {
    init(boot_info);
    test_main();
    hlt_loop();
}

#[test_case]
fn test_breakpoint_exception() {
    x86_64::instructions::interrupts::int3();
}

#[test_case]
fn test_timer_interrupt_fires() {
    let ticks_before = cpu::interrupts::ticks();
    while cpu::interrupts::ticks() == ticks_before {
        x86_64::instructions::hlt();
    }
    assert!(cpu::interrupts::ticks() > ticks_before);
}

#[test_case]
fn test_syscall_dispatch_rejects_unknown_number() {
    // Nothing registers a number anywhere near this one -- `dispatch`'s table starts empty in
    // this test binary regardless, since module loading only happens in sys/main.rs's non-test
    // kernel_main, never in this crate's own #[cfg(test)] entry point.
    assert_eq!(syscall::dispatch(0xFFFF, 0, 0, 0, 0), Err(syscall::ENOSYS));
}

#[test_case]
fn test_syscall_dispatch_routes_registered_handlers() {
    extern "C" fn ok_handler(a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
        (a0 + a1 + a2 + a3) as i64
    }
    extern "C" fn err_handler(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
        -5
    }

    const TEST_OK_NUMBER: u64 = 0xF001;
    const TEST_ERR_NUMBER: u64 = 0xF002;
    assert_eq!(
        syscall::oxidebsd_register_syscall(TEST_OK_NUMBER, ok_handler),
        0
    );
    assert_eq!(
        syscall::oxidebsd_register_syscall(TEST_ERR_NUMBER, err_handler),
        0
    );
    // Re-registering an already-claimed number is rejected, not silently overwritten.
    assert_eq!(
        syscall::oxidebsd_register_syscall(TEST_OK_NUMBER, ok_handler),
        -1
    );

    assert_eq!(syscall::dispatch(TEST_OK_NUMBER, 1, 2, 3, 4), Ok(10));
    assert_eq!(syscall::dispatch(TEST_ERR_NUMBER, 0, 0, 0, 0), Err(5));
}

#[test_case]
fn test_ipv4_next_hop_routes_off_subnet_to_gateway() {
    use net::ipv4::{self, GATEWAY_IP, GUEST_IP};

    // On-link (same /24 as GUEST_IP, e.g. SLIRP's own DNS relay): ARP the destination directly.
    assert_eq!(ipv4::next_hop(ipv4::DNS_SERVER_IP), ipv4::DNS_SERVER_IP);
    assert_eq!(ipv4::next_hop(GUEST_IP), GUEST_IP);
    // Off-link (any real internet destination, e.g. 1.1.1.1): route via the default gateway --
    // SLIRP never answers ARP for an address it doesn't itself own, so without this, nothing off
    // the local subnet could ever be reached at all (see ipv4.rs's own module doc comment).
    assert_eq!(ipv4::next_hop([1, 1, 1, 1]), GATEWAY_IP);
    assert_eq!(ipv4::next_hop([8, 8, 8, 8]), GATEWAY_IP);
}

#[test_case]
fn test_heap_allocation() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    let heap_value = Box::new(41);
    assert_eq!(*heap_value, 41);

    let mut vec = Vec::new();
    for i in 0..500 {
        vec.push(i);
    }
    assert_eq!(vec.iter().sum::<u64>(), (0..500).sum());
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}
