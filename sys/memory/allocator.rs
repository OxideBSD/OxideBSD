use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;

use linked_list_allocator::Heap;
use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB, mapper::MapToError,
};

use crate::serial_println;

pub const HEAP_START: usize = 0x_4444_4444_0000;

/// Floor: the original fixed heap size this kernel always used, raised from 100 KiB once
/// `sys/process.rs`'s `KernelStack` started allocating each process's own kernel stack from this
/// same heap (several are live at once under `fork`), on top of the process table itself and
/// whatever `execve`'s internal `Vec<u8>` needs to hold a loaded ELF's bytes. Proven sufficient for
/// today's workload -- never shrink below this just because a boot reports little RAM.
const HEAP_SIZE_FLOOR: usize = 4 * 1024 * 1024; // 4 MiB
/// Ceiling: bounds one-time boot cost (mapping + zeroing heap pages) on a RAM-rich machine.
/// Raised 128 -> 1024 MiB (alongside `Cargo.toml`'s own `-m` bump, same pairing precedent
/// `sys/modules/oxfs`'s `NUM_BLOCKS`/`-m` bumps already established) once the expanded POSIX
/// conformance pilot (see CLAUDE.md's "POSIX conformance pilot" sections) needed real headroom
/// this kernel's own "no frame deallocation, no address-space reclaim after `execve`/exit anywhere"
/// design (see this file's own module doc comment and the process-table section of CLAUDE.md)
/// makes genuinely necessary at this corpus size: a single continuous boot now runs several hundred
/// real `fork`+`execve`+`wait4` cycles (`sh` per test line, `t0` per test, the test binary itself),
/// each leaking real heap-resident bookkeeping (page-table wrapper allocations, `execve`'s own
/// `Vec<u8>` ELF-image buffer, ...) that's never reclaimed by design -- found live: the original
/// 128 MiB ceiling (which `-m 1024`'s own 1/8 scaling already maxed out) was only enough for
/// roughly the first ~140 of 492 pilot files before `alloc::alloc::handle_alloc_error` fired on an
/// 80 MiB request, the linked-list allocator unable to satisfy it out of an increasingly
/// fragmented heap. Not a fix for the underlying "never reclaim" design (out of scope -- a real
/// fix needs actual frame/address-space reclaim work, a much larger undertaking than this pilot
/// expansion), just enough headroom to run the current corpus with real margin, not just barely
/// enough.
const HEAP_SIZE_CEILING: usize = 1024 * 1024 * 1024; // 1024 MiB
/// What fraction of total usable RAM the heap gets, before clamping to the floor/ceiling above.
const HEAP_SIZE_DIVISOR: u64 = 8; // 1/8th of usable RAM

/// Picks a heap size scaled to `usable_ram_bytes` (as reported by
/// `memory::usable_ram_bytes`, itself populated by `memory::BootInfoFrameAllocator::init`),
/// clamped to `[HEAP_SIZE_FLOOR, HEAP_SIZE_CEILING]`. Called once, at boot, before `init_heap`.
pub fn compute_heap_size(usable_ram_bytes: u64) -> usize {
    let scaled = (usable_ram_bytes / HEAP_SIZE_DIVISOR) as usize;
    scaled.clamp(HEAP_SIZE_FLOOR, HEAP_SIZE_CEILING)
}

/// Wraps a type behind a `spin::Mutex`, reusing the project's existing spinlock rather than
/// pulling in `linked_list_allocator`'s own `spinning_top` dependency just for `LockedHeap`.
struct Locked<A> {
    inner: Mutex<A>,
}

impl<A> Locked<A> {
    const fn new(inner: A) -> Self {
        Locked {
            inner: Mutex::new(inner),
        }
    }
}

#[global_allocator]
static ALLOCATOR: Locked<Heap> = Locked::new(Heap::empty());

unsafe impl GlobalAlloc for Locked<Heap> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.inner
            .lock()
            .allocate_first_fit(layout)
            .map_or(core::ptr::null_mut(), NonNull::as_ptr)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            self.inner
                .lock()
                .deallocate(NonNull::new_unchecked(ptr), layout);
        }
    }
}

/// Maps the kernel heap's virtual page range to physical frames and hands the resulting region
/// to the global allocator.
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    heap_size: usize,
) -> Result<(), MapToError<Size4KiB>> {
    serial_println!(
        "[boot] mapping heap: {:#x}..{:#x} ({} KiB)",
        HEAP_START,
        HEAP_START + heap_size,
        heap_size / 1024
    );

    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + (heap_size - 1) as u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            // `.ignore()`, not `.flush()`: every page in this range is being mapped for the very
            // first time (HEAP_START's own VA range is never touched by anything earlier in boot),
            // so no stale TLB entry for it can exist to invalidate. `.flush()` here used to cost a
            // real `invlpg` per page regardless -- fine when the heap was a few thousand pages, but
            // a genuine, measured multi-minute stall once `Cargo.toml`'s QEMU `-m` grew enough to
            // push the heap toward its 128 MiB ceiling (tens of thousands of pages, each trapped
            // and emulated individually under QEMU's software TCG) -- see CLAUDE.md's oxfs section
            // for the BusyBox-roster growth that first forced a bigger heap and surfaced this.
            mapper.map_to(page, frame, flags, frame_allocator)?.ignore();
        }
    }

    unsafe {
        ALLOCATOR
            .inner
            .lock()
            .init(HEAP_START as *mut u8, heap_size);
    }
    serial_println!("[boot] heap ready");

    Ok(())
}
