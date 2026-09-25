//! Kernel stacks (`memory::kstack`) are mapped, zeroed, and have unmapped guard space right below
//! them; a freed stack's slot is reused. Actually overflowing one double-faults and reboots, so
//! this checks the layout instead.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::memory::kstack::{GuardedStack, is_guard};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

const SIZE: usize = 128 * 1024;

fn main(boot_info: &'static BootInfo) -> ! {
    let (_mapper, frame_allocator) = oxidebsd::init(boot_info);
    let offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);
    oxidebsd::memory::install_global_memory_state(frame_allocator, offset);

    let a = GuardedStack::new(SIZE).expect("stack allocation failed");
    let top = a.top().as_u64();
    let bottom = top - SIZE as u64;
    // SAFETY: [bottom, top) is the stack just mapped.
    let (first, last) = unsafe {
        let first = (bottom as *const u8).read_volatile();
        let last = ((top - 1) as *const u8).read_volatile();
        ((bottom as *mut u8).write_volatile(0xaa), ((top - 1) as *mut u8).write_volatile(0x55));
        (first, last)
    };
    assert_eq!((first, last), (0, 0), "stack not zeroed");
    assert!(!is_guard(bottom) && !is_guard(top - 1), "stack itself reported as guard");
    assert!(is_guard(bottom - 1), "no guard page below the stack");
    assert!(is_guard(bottom - 4096 * 16), "guard region is less than 16 pages");

    let b = GuardedStack::new(SIZE).expect("second stack allocation failed");
    assert_ne!(a.top(), b.top(), "two live stacks share a slot");
    drop(a);
    assert!(is_guard(top - 1), "freed stack is still mapped");
    let c = GuardedStack::new(SIZE).expect("third stack allocation failed");
    assert_eq!(c.top().as_u64(), top, "freed slot wasn't reused");
    // SAFETY: c's stack is mapped; it must be fresh zeroed memory, not a's old contents.
    assert_eq!(unsafe { ((top - 1) as *const u8).read_volatile() }, 0, "reused stack not zeroed");

    serial_println!("kstack_guard: [ok]");
    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
