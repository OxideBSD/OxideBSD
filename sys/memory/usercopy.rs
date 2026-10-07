//! Access to user memory from the kernel (`OxideBSD-doc/USERMEM.md`).
//!
//! The user range is `[VM_MINUSER, VM_MAXUSER)`. Nothing kernel-only may be mapped inside it, so
//! a bounds check plus fault recovery is enough to validate a user pointer (USERMEM.md §3.2,
//! §5.1). `check_user_range_layout` enforces that at boot.

use x86_64::VirtAddr;
use x86_64::structures::paging::{OffsetPageTable, PageTable, PageTableFlags};

/// Lowest user address. Below it lies the Multiboot2 trampoline's kernel-only identity map of
/// physical `[0, 64 MiB)` (`boot::multiboot2`), present in every address space because the boot
/// stack lives in it. Every user load address is above it (fixed-address binaries start at
/// `0x800_0000`).
pub const VM_MINUSER: u64 = 0x400_0000;

/// End of the user range: the end of the canonical lower half.
pub const VM_MAXUSER: u64 = 0x8000_0000_0000;

/// Walks the lower half of the active page tables and panics if any kernel-only page lies in
/// `[VM_MINUSER, VM_MAXUSER)`. Run once at the end of `crate::init`, after the last boot-time
/// mapping and before any process exists.
pub fn check_user_range_layout(mapper: &OffsetPageTable) {
    let offset = mapper.phys_offset();
    // Only the lower half (L4 entries 0..256) can hold user addresses.
    walk(mapper.level_4_table(), 4, 0, offset, 256);
}

fn walk(table: &PageTable, level: u8, base: u64, offset: VirtAddr, entries: usize) {
    let span = 1u64 << (12 + 9 * (level as u32 - 1));
    for (i, entry) in table.iter().enumerate().take(entries) {
        let flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }
        let start = base + i as u64 * span;
        let leaf = level == 1 || flags.contains(PageTableFlags::HUGE_PAGE);
        if leaf {
            let end = start + span;
            if !flags.contains(PageTableFlags::USER_ACCESSIBLE)
                && start < VM_MAXUSER
                && end > VM_MINUSER
            {
                panic!(
                    "kernel-only mapping {:#x}..{:#x} lies in the user range {:#x}..{:#x} \
                     (USERMEM.md section 5.1)",
                    start, end, VM_MINUSER, VM_MAXUSER
                );
            }
            continue;
        }
        // SAFETY: a present, non-leaf entry points at a live page table, and the whole of
        // physical memory is mapped at `offset`. Read-only, at boot, before any other CPU or
        // process could change the tables.
        let child = unsafe { &*(offset + entry.addr().as_u64()).as_ptr::<PageTable>() };
        walk(child, level - 1, start, offset, 512);
    }
}

