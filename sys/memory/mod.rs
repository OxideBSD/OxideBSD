//! Physical/virtual memory management: this file is the frame allocator and phys-mem mapping
//! init (formerly `memory.rs`, top-level); `allocator` is the kernel heap allocator, `address_space`
//! is per-process page-table management (`AddressSpace::new`/`fork`/`new_excluding_user`).

pub mod address_space;
pub mod allocator;

use core::sync::atomic::{AtomicU64, Ordering};

use limine::memmap::{Entry, MEMMAP_USABLE};
use spin::Mutex;
use x86_64::PhysAddr;
use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
};

use crate::serial_println;

/// Builds a mapper over Limine's existing page tables.
///
/// # Safety
///
/// The complete physical memory must be mapped at `physical_memory_offset` (Limine's HHDM --
/// Higher-Half Direct Map -- is already established by the time `kmain` runs, unconditionally, no
/// feature flag needed), and this function must be called at most once to avoid aliasing `&mut`
/// references to the level 4 table.
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    serial_println!(
        "[boot] mapping page tables (physical memory offset {:?})",
        physical_memory_offset
    );
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    let mapper = unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) };
    serial_println!("[boot] page table mapper ready");
    mapper
}

/// # Safety
///
/// Same requirements as `init`.
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    let (level_4_table_frame, _flags) = Cr3::read();
    unsafe { frame_to_page_table(level_4_table_frame, physical_memory_offset) }
}

/// Views an arbitrary physical frame as a page table, through the physical-memory-offset window.
/// Used both for the currently-active level 4 table (`active_level_4_table`) and, by
/// `src/address_space.rs`, for a not-yet-active one.
///
/// # Safety
///
/// `physical_memory_offset` must be where Limine's HHDM mapped all of physical memory (same
/// requirement as `init`), `frame` must actually contain a valid, live page table, and the
/// caller must ensure no other `&mut` view of the same frame exists concurrently.
pub unsafe fn frame_to_page_table(
    frame: PhysFrame,
    physical_memory_offset: VirtAddr,
) -> &'static mut PageTable {
    let virt = physical_memory_offset + frame.start_address().as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    unsafe { &mut *page_table_ptr }
}

/// A `FrameAllocator` that hands out frames from Limine's reported usable regions of the
/// physical memory map, in order, never reusing a frame.
///
/// **Plain index/cursor state, not a rebuild-and-skip iterator.** This used to be `next: usize`
/// with `allocate_frame` calling `self.usable_frames().nth(self.next)` -- rebuilding the entire
/// `filter`/`map`/`flat_map`/`step_by` chain from region zero and re-walking `self.next` items
/// *every single call*, an O(n) cost per allocation and O(n²) total across n allocations. Utterly
/// invisible at boot's original scale (a few thousand frames total), but a real, measured
/// multi-minute-plus stall once a single caller needs tens of thousands (`allocator::init_heap`
/// mapping a heap anywhere near its 128 MiB ceiling, or `module::map_region` mapping
/// `sys/modules/oxfs`'s own object once its embedded BusyBox roster grew to ~300 applets -- see
/// CLAUDE.md's BusyBox section): at 32,000 frames, n² is roughly a billion iterator steps, each
/// one slow under QEMU's software TCG on top of being pure waste. A first fix tried storing a live
/// `Box<dyn Iterator<...>>` instead (O(1) amortized `next()` per call) -- wrong, not just
/// suboptimal: `BootInfoFrameAllocator::init` runs *before* `allocator::init_heap`, which needs a
/// working frame allocator to map the heap's own pages in the first place, so any heap allocation
/// this constructor makes (`Box::new` included) reliably panics ("memory allocation ... failed")
/// with no heap to satisfy it -- a real chicken-and-egg dependency, not a hypothetical one, hit and
/// diagnosed live. `region_index`/`frame_number` below is plain `Copy` state: `region_index` only
/// ever increases, bounded by Limine's own memory map's small, fixed region count, so total extra
/// work *across the allocator's entire lifetime* is O(regions), not O(frames) -- no heap, no
/// boxing, no dynamic dispatch needed at all.
pub struct BootInfoFrameAllocator {
    memory_map: &'static [&'static Entry],
    region_index: usize,
    frame_number: u64,
    /// Head of a real, reusable free list -- see `FrameDeallocator`'s own impl below for the
    /// mechanism and why it's safe to add on top of the bump-only design above without
    /// resurrecting the exact `Box`/heap-during-construction trap that design's own doc comment
    /// warns about.
    free_list: Option<PhysFrame>,
}

impl BootInfoFrameAllocator {
    /// # Safety
    ///
    /// The passed memory map must be valid; in particular, all frames it marks `MEMMAP_USABLE`
    /// must actually be unused.
    pub unsafe fn init(memory_map: &'static [&'static Entry]) -> Self {
        let usable_regions = memory_map
            .iter()
            .filter(|region| region.type_ == MEMMAP_USABLE)
            .count();
        let usable_bytes = usable_ram_bytes_in(memory_map);
        // Published globally (see `usable_ram_bytes` below) *before* anything downstream sizes
        // itself off of it -- `allocator::compute_heap_size` reads it immediately after this
        // call returns, and `process::kernel_stack_size`/`user_stack_pages` read it lazily, the
        // first time a process is ever created (always after this point).
        USABLE_RAM_BYTES.store(usable_bytes, Ordering::Relaxed);
        serial_println!(
            "[boot] frame allocator ready: {} usable region(s), {} KiB total",
            usable_regions,
            usable_bytes / 1024
        );

        BootInfoFrameAllocator {
            memory_map,
            region_index: 0,
            frame_number: 0,
            free_list: None,
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        // Real reuse first: `free_list` only ever becomes `Some` via `deallocate_frame` below,
        // which never runs before `install_global_memory_state` has already populated
        // `PHYS_MEM_OFFSET` (real process teardown, the only caller, happens well after boot) --
        // so `phys_mem_offset()` below is always safe to call once this branch is actually taken,
        // even though this exact function is also called during early boot (heap/module mapping)
        // while that global is still unset; those early calls never see a populated free list and
        // fall straight through to the bump path, never touching `phys_mem_offset()` at all.
        if let Some(frame) = self.free_list.take() {
            let offset = phys_mem_offset();
            let next_ptr = (offset + frame.start_address().as_u64()).as_ptr::<u64>();
            // SAFETY: frame was previously handed to deallocate_frame, which wrote a real next-
            // pointer (or the NONE sentinel) into its first 8 bytes through this same window.
            let next = unsafe { next_ptr.read() };
            self.free_list = if next == u64::MAX {
                None
            } else {
                Some(PhysFrame::containing_address(PhysAddr::new(next)))
            };
            return Some(frame);
        }
        loop {
            let region = self.memory_map.get(self.region_index).copied()?;
            if region.type_ != MEMMAP_USABLE {
                self.region_index += 1;
                continue;
            }
            // Real Limine memory-map entries for USABLE regions are always 4096-byte aligned
            // (protocol guarantee), so a plain byte-to-frame-number division is exact here --
            // no rounding needed the way an arbitrary region's `base`/`length` might.
            let start_frame_number = region.base / 4096;
            let end_frame_number = (region.base + region.length) / 4096;
            if self.frame_number < start_frame_number {
                self.frame_number = start_frame_number;
            }
            if self.frame_number >= end_frame_number {
                self.region_index += 1;
                continue;
            }
            let frame_number = self.frame_number;
            self.frame_number += 1;
            return Some(PhysFrame::containing_address(x86_64::PhysAddr::new(
                frame_number * 4096,
            )));
        }
    }
}

/// Real frame reuse, closing the "no frame deallocation anywhere" gap CLAUDE.md long documented as
/// a permanent limitation -- added once the expanded POSIX conformance pilot's own several-hundred
/// real `fork`+`execve`+`exit` cycles per boot made the cost of never reclaiming concrete (see
/// `memory::address_space::AddressSpace::teardown`'s own doc comment for the actual reclaim logic
/// and why it's safe; this impl is purely the storage mechanism).
///
/// **An intrusive singly-linked free list stored in the freed frames themselves**, not a
/// `Vec<PhysFrame>` -- deliberately: this allocator is constructed *before* `allocator::init_heap`
/// (see `init`'s own doc comment above), so anything requiring the heap to exist yet would
/// resurrect the exact chicken-and-egg trap that same comment already documents hitting once for a
/// boxed-iterator attempt. A `Vec`-based free list would only ever be *populated* well after the
/// heap exists (real teardown happens during process exit, long past boot) — but a data structure
/// whose safety depends on "well, nothing calls this early in practice" is worse than one that's
/// unconditionally heap-free by construction. Each freed frame's own first 8 bytes (viewed through
/// the phys-mem-offset window, the same technique every other cross-address-space frame access in
/// this codebase already uses) store the *previous* free-list head's physical address, or
/// `u64::MAX` as a real "list ends here" sentinel (never a valid frame-aligned address — every real
/// frame address is 4 KiB-aligned, so its low 12 bits are always zero, `u64::MAX`'s never are).
impl FrameDeallocator<Size4KiB> for BootInfoFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let offset = phys_mem_offset();
        let next_ptr = (offset + frame.start_address().as_u64()).as_mut_ptr::<u64>();
        let prev_head = self
            .free_list
            .map(|f| f.start_address().as_u64())
            .unwrap_or(u64::MAX);
        // SAFETY: frame was just handed back by a caller asserting it's no longer referenced by
        // any live mapping (see AddressSpace::teardown's own doc comment for why that's true for
        // every frame it passes here) -- safe to overwrite its content with free-list bookkeeping.
        unsafe { next_ptr.write(prev_head) };
        self.free_list = Some(frame);
    }
}

fn usable_ram_bytes_in(memory_map: &[&Entry]) -> u64 {
    memory_map
        .iter()
        .filter(|region| region.type_ == MEMMAP_USABLE)
        .map(|region| region.length)
        .sum()
}

/// Total usable physical RAM this boot's memory map reported, in bytes -- set once by
/// `BootInfoFrameAllocator::init`. Lets sizing decisions elsewhere (`allocator::compute_heap_size`,
/// `process::kernel_stack_size`/`user_stack_pages`) scale to whatever RAM this particular boot
/// actually has instead of assuming a fixed target machine. `0` until `init` has run.
static USABLE_RAM_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn usable_ram_bytes() -> u64 {
    USABLE_RAM_BYTES.load(Ordering::Relaxed)
}

/// Global home for the frame allocator and the bootloader's physical-memory offset, promoted out
/// of `main.rs`'s local variables once process creation (`sys/process.rs`'s `spawn`/`fork`/
/// `execve` paths) needs both from arbitrary syscall contexts, not just at boot. Populated exactly
/// once, via `install_global_memory_state`, right after `oxidebsd::init` returns.
static FRAME_ALLOCATOR: Mutex<Option<BootInfoFrameAllocator>> = Mutex::new(None);
static PHYS_MEM_OFFSET: Mutex<Option<VirtAddr>> = Mutex::new(None);

/// Must be called exactly once, after `oxidebsd::init`, before any code calls
/// `with_frame_allocator`/`phys_mem_offset`.
pub fn install_global_memory_state(frame_allocator: BootInfoFrameAllocator, offset: VirtAddr) {
    *FRAME_ALLOCATOR.lock() = Some(frame_allocator);
    *PHYS_MEM_OFFSET.lock() = Some(offset);
}

/// Runs `f` with exclusive access to the global frame allocator. Panics if
/// `install_global_memory_state` hasn't run yet.
pub fn with_frame_allocator<R>(f: impl FnOnce(&mut BootInfoFrameAllocator) -> R) -> R {
    let mut guard = FRAME_ALLOCATOR.lock();
    f(guard.as_mut().expect("frame allocator not yet installed"))
}

/// The bootloader's physical-memory offset (see `init`'s own doc comment). Panics if
/// `install_global_memory_state` hasn't run yet.
pub fn phys_mem_offset() -> VirtAddr {
    PHYS_MEM_OFFSET
        .lock()
        .expect("phys mem offset not yet installed")
}
