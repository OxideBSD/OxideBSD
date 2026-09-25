//! Per-process kernel stacks with guard pages.
//!
//! Kernel stacks used to come from the heap, so overflowing one silently scribbled over whatever
//! heap object sat below it. Each stack now lives in its own `SLOT_SIZE` slot of a dedicated
//! kernel VA window, mapped at the top of the slot; everything below it in the slot stays
//! unmapped. Running off the bottom faults (a double fault, once the CPU can't push the `#PF`
//! frame either), and both fault handlers name it as a kernel stack overflow via `is_guard`.
//!
//! The window is one level-4 slot whose level-3 table is allocated at boot (`reserve_window`),
//! before any address space exists: `AddressSpace` copies the kernel's level-4 entries once, at
//! creation, so every address space then shares that level-3 table and sees stacks mapped later.

use alloc::vec::Vec;

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    Size4KiB,
};

/// Level-4 slot 385, the one right after `module::MODULE_DATA_BASE`'s slot 384.
const WINDOW_BASE: u64 = 0xffff_c080_0000_0000;
const WINDOW_SIZE: u64 = 512 << 30;
/// Room for the largest stack `process::kernel_stack_size` hands out (512 KiB) plus at least as
/// much unmapped guard space below it.
const SLOT_SIZE: u64 = 1 << 20;
const PAGE: u64 = 4096;

/// Slots freed by exited processes, reused before `NEXT_SLOT` grows.
static FREE_SLOTS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static NEXT_SLOT: Mutex<u64> = Mutex::new(0);

/// Allocates the window's level-3 table in the active (boot) page tables. Must run before the
/// first `AddressSpace` is built -- see this module's doc comment.
pub fn reserve_window(
    mapper: &mut OffsetPageTable<'static>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) {
    let index = VirtAddr::new(WINDOW_BASE).p4_index();
    let offset = mapper.phys_offset();
    let entry = &mut mapper.level_4_table_mut()[index];
    if !entry.is_unused() {
        panic!("kernel stack window's level-4 slot is already in use");
    }
    let frame = frame_allocator
        .allocate_frame()
        .expect("no frame for the kernel stack window's level-3 table");
    // SAFETY: a freshly allocated frame, reachable through the physical-memory window.
    unsafe { (offset + frame.start_address().as_u64()).as_mut_ptr::<PageTable>().write(PageTable::new()) };
    entry.set_frame(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
}

/// Is `addr` in the kernel stack window but not mapped -- i.e. did something run off a stack?
pub fn is_guard(addr: u64) -> bool {
    (WINDOW_BASE..WINDOW_BASE + WINDOW_SIZE).contains(&addr)
        && active_mapper()
            .translate_page(Page::<Size4KiB>::containing_address(VirtAddr::new(addr)))
            .is_err()
}

fn active_mapper() -> OffsetPageTable<'static> {
    let offset = super::phys_mem_offset();
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    // SAFETY: CR3's level-4 table is live and reachable through the physical-memory window. Only
    // kernel-window entries are touched through this view, and callers run on one core.
    unsafe { OffsetPageTable::new(super::frame_to_page_table(l4_frame, offset), offset) }
}

/// One kernel stack: `size` bytes mapped at the top of its slot.
pub struct GuardedStack {
    slot: u64,
    size: u64,
}

impl GuardedStack {
    /// `Err(())` when the frame allocator runs dry (the caller reports `ENOMEM`).
    pub fn new(size: usize) -> Result<Self, ()> {
        let size = (size as u64).next_multiple_of(PAGE);
        assert!(size <= SLOT_SIZE / 2, "kernel stack larger than its guarded slot");
        let slot = FREE_SLOTS.lock().pop().unwrap_or_else(|| {
            let mut next = NEXT_SLOT.lock();
            *next += 1;
            *next - 1
        });
        let stack = GuardedStack { slot, size };
        if slot >= WINDOW_SIZE / SLOT_SIZE {
            // Dropping `stack` would unmap pages it never mapped.
            core::mem::forget(stack);
            return Err(());
        }
        let mut mapper = active_mapper();
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let mapped = super::with_frame_allocator(|fa| {
            for page in stack.pages() {
                let Some(frame) = fa.allocate_frame() else {
                    return false;
                };
                // SAFETY: `page` is in this slot, which nothing else maps.
                match unsafe { mapper.map_to(page, frame, flags, fa) } {
                    Ok(flush) => flush.ignore(), // never mapped before, so nothing stale in the TLB
                    Err(_) => {
                        // SAFETY: `frame` was never mapped anywhere.
                        unsafe { fa.deallocate_frame(frame) };
                        return false;
                    }
                }
            }
            true
        });
        if !mapped {
            return Err(()); // `Drop` unmaps whatever did get mapped
        }
        // SAFETY: the whole range was just mapped writable; stacks start zeroed.
        unsafe { core::ptr::write_bytes(stack.bottom().as_mut_ptr::<u8>(), 0, size as usize) };
        Ok(stack)
    }

    pub fn top(&self) -> VirtAddr {
        VirtAddr::new(WINDOW_BASE + (self.slot + 1) * SLOT_SIZE)
    }

    fn bottom(&self) -> VirtAddr {
        self.top() - self.size
    }

    fn pages(&self) -> impl Iterator<Item = Page<Size4KiB>> {
        let first = Page::containing_address(self.bottom());
        let end = Page::containing_address(self.top());
        Page::range(first, end)
    }
}

impl Drop for GuardedStack {
    fn drop(&mut self) {
        let mut mapper = active_mapper();
        super::with_frame_allocator(|fa| {
            for page in self.pages() {
                if let Ok((frame, flush)) = mapper.unmap(page) {
                    flush.flush();
                    // SAFETY: the stack is dead (its process was reaped by someone else), and
                    // this was its only mapping.
                    unsafe { fa.deallocate_frame(frame) };
                }
            }
        });
        FREE_SLOTS.lock().push(self.slot);
    }
}
