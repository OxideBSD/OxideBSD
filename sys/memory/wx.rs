//! W^X audit of the kernel's own mappings, the counterpart of Linux's `CONFIG_DEBUG_WX`: walks
//! the upper half of the active page tables and reports every range that is both writable and
//! executable (THREAT_MODEL.md §3.3). A page's effective permissions are the intersection over
//! its table levels: writable only if every level is, executable only if no level is `NO_EXECUTE`.

use x86_64::VirtAddr;
use x86_64::structures::paging::{OffsetPageTable, PageTable, PageTableFlags};

use crate::serial_println;

/// The writable and executable ranges found by the last walk, coalesced.
struct Report {
    pages: u64,
    ranges: u64,
    open: Option<(u64, u64)>,
}

impl Report {
    fn add(&mut self, start: u64, len: u64) {
        self.pages += len / 4096;
        match &mut self.open {
            Some((_, end)) if *end == start => *end += len,
            _ => {
                self.flush();
                self.open = Some((start, start + len));
            }
        }
    }

    fn flush(&mut self) {
        if let Some((start, end)) = self.open.take() {
            self.ranges += 1;
            if self.ranges <= 16 {
                serial_println!("[wx]   {:#x}..{:#x} ({} KiB)", start, end, (end - start) / 1024);
            }
        }
    }
}

/// Logs every writable and executable kernel range and returns how many pages there are. A no-op
/// returning 0 where NX is off (every page is executable there; there is nothing to audit).
pub fn check_kernel(mapper: &OffsetPageTable, when: &str) -> u64 {
    if !crate::cpu::nx::enabled() {
        return 0;
    }
    let mut report = Report { pages: 0, ranges: 0, open: None };
    let all = PageTableFlags::WRITABLE;
    walk(mapper.level_4_table(), 4, 0xffff_8000_0000_0000, mapper.phys_offset(), all, false, &mut report);
    report.flush();
    if report.pages == 0 {
        serial_println!("[wx] {}: no writable and executable kernel pages", when);
    } else {
        serial_println!(
            "[wx] WARNING: {}: {} writable and executable kernel pages in {} ranges",
            when,
            report.pages,
            report.ranges
        );
    }
    report.pages
}

fn walk(
    table: &PageTable,
    level: u8,
    base: u64,
    offset: VirtAddr,
    writable: PageTableFlags,
    nx: bool,
    report: &mut Report,
) {
    let span = 1u64 << (12 + 9 * (level as u32 - 1));
    let (first, count) = if level == 4 { (256, 256) } else { (0, 512) };
    for (i, entry) in table.iter().enumerate().skip(first).take(count) {
        let flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }
        let start = base + (i - first) as u64 * span;
        let writable = writable & flags;
        let nx = nx || flags.contains(PageTableFlags::NO_EXECUTE);
        if level == 1 || flags.contains(PageTableFlags::HUGE_PAGE) {
            if !writable.is_empty() && !nx {
                report.add(start, span);
            }
            continue;
        }
        // SAFETY: a present, non-leaf entry points at a live page table, and the whole of
        // physical memory is mapped at `offset`. Read-only.
        let child = unsafe { &*(offset + entry.addr().as_u64()).as_ptr::<PageTable>() };
        walk(child, level - 1, start, offset, writable, nx, report);
    }
}
