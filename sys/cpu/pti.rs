//! Kernel page-table isolation: the Meltdown mitigation (`OxideBSD-doc/THREAT_MODEL.md` §3.4).
//!
//! Meltdown (CVE-2017-5754) lets ring 3 read any byte the page tables map, kernel memory included,
//! by timing a speculative access past a faulting one. The fix is to run ring 3 on page tables
//! that map almost none of the kernel: only the entry area (`cpu::entry`), the few pages that have
//! to be mapped for a trap or `syscall` to reach the switch to the kernel's own tables. This
//! module only decides *whether* to do that and reports the decision; the table split itself lands
//! in a later commit.
//!
//! **Who needs it.** Only Intel is affected, and newer Intel parts advertise `RDCL_NO` ("rogue
//! data cache load no") to say they aren't. So the default is on for a `GenuineIntel` CPU that
//! doesn't set `RDCL_NO`, off otherwise. A boot flag (`pti=`/`kpti=`/`meltdown=`, `on` or `off`)
//! overrides the detection either way, and tests force it on.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use x86_64::{PhysAddr, VirtAddr};
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    Translate,
};

use crate::memory::frame_to_page_table;

/// The decision, as one of these. `UNSET` until `decide` runs; a `request` from the command line
/// is remembered here too (as `FORCE_ON`/`FORCE_OFF`) until then.
static STATE: AtomicU8 = AtomicU8::new(UNSET);
const UNSET: u8 = 0;
const OFF: u8 = 1;
const ON: u8 = 2;
const FORCE_OFF: u8 = 3;
const FORCE_ON: u8 = 4;

/// Records a `pti=`/`kpti=`/`meltdown=` override (`Some(true)` on, `Some(false)` off), or leaves
/// the decision to `decide` (`None`). Called from `boot::apply_cmdline`, before `decide`.
pub fn request(force: Option<bool>) {
    let state = match force {
        Some(true) => FORCE_ON,
        Some(false) => FORCE_OFF,
        None => return,
    };
    STATE.store(state, Ordering::Relaxed);
}

/// Forces KPTI on regardless of the CPU, for a test kernel that wants to exercise it on hardware
/// that doesn't need it (the dev machine reports `RDCL_NO`). Call before `decide`.
pub fn force_on_for_test() {
    STATE.store(FORCE_ON, Ordering::Relaxed);
}

/// Makes the final on/off decision and logs it. Called once, early in `init`. An override (from
/// the command line or a test) wins; otherwise KPTI is on exactly when the CPU is affected by
/// Meltdown (`cpu_is_affected`).
pub fn decide() {
    let forced = match STATE.load(Ordering::Relaxed) {
        FORCE_ON => Some(true),
        FORCE_OFF => Some(false),
        _ => None,
    };
    let on = forced.unwrap_or_else(cpu_is_affected);
    STATE.store(if on { ON } else { OFF }, Ordering::Relaxed);

    let why = match forced {
        Some(_) => "forced by boot flag",
        None if on => "Intel without RDCL_NO",
        None => "CPU reports it isn't affected by Meltdown",
    };
    crate::serial_println!(
        "[pti] kernel page-table isolation {} ({})",
        if on { "ON" } else { "off" },
        why
    );
}

/// Whether KPTI is on. Only meaningful after `decide`.
pub fn enabled() -> bool {
    STATE.load(Ordering::Relaxed) == ON
}

/// Whether this CPU is affected by Meltdown: `GenuineIntel` that doesn't advertise `RDCL_NO`.
fn cpu_is_affected() -> bool {
    if !is_genuine_intel() {
        return false;
    }
    // RDCL_NO lives in IA32_ARCH_CAPABILITIES (MSR 0x10A) bit 0, which only exists when
    // CPUID.(EAX=7,ECX=0).EDX bit 29 (IA32_ARCH_CAPABILITIES present) is set. No bit 29 means an
    // older Intel part that predates the enumeration: affected.
    // SAFETY: CPUID leaf 7 is always available on any CPU this kernel runs on (checked for SMAP).
    let arch_caps_present = unsafe { core::arch::x86_64::__cpuid_count(7, 0).edx } & (1 << 29) != 0;
    if !arch_caps_present {
        return true;
    }
    // SAFETY: the MSR exists, per the CPUID bit just checked.
    let arch_caps = unsafe { x86_64::registers::model_specific::Msr::new(0x10A).read() };
    arch_caps & 1 == 0
}

/// Whether CPUID's vendor string is `GenuineIntel`.
fn is_genuine_intel() -> bool {
    // SAFETY: CPUID leaf 0 is always available.
    let vendor = unsafe { core::arch::x86_64::__cpuid(0) };
    // "Genu" "ineI" "ntel" in EBX, EDX, ECX.
    vendor.ebx == 0x756e_6547 && vendor.edx == 0x4965_6e69 && vendor.ecx == 0x6c65_746e
}

/// The one L4 entry (slot 511) that maps the entry area, shared by every process's user table
/// (decision A: one boot-time template, aliased everywhere). `0` until `build_entry_template`
/// runs; a raw `PageTableEntry` value (a present entry pointing at the shared PDPT).
static ENTRY_TEMPLATE_L4E: AtomicU64 = AtomicU64::new(0);

/// The L4 slot the entry area lives in: the top of the address space, where the kernel image is.
pub const ENTRY_L4_SLOT: usize = 511;

/// Builds the shared slot-511 subtree that maps exactly the entry area (`cpu::entry`) and nothing
/// else of the kernel, and records its L4 entry for `AddressSpace` to alias into every user table.
/// A user table has this one kernel-half entry and no other, so ring 3 running on it can reach a
/// trap or `syscall` stub and the CR3 switch, but can't see — or speculatively read — any other
/// kernel page.
///
/// Called once in `init`, after the GDT/TSS/IDT are in place (so the entry symbols resolve) and
/// only when KPTI is on. `active` is the kernel's own mapper, used to find each entry page's frame.
pub fn build_entry_template(
    active: &OffsetPageTable<'static>,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), ()> {
    let l4_frame = frame_allocator.allocate_frame().ok_or(())?;
    // SAFETY: a freshly allocated frame, viewed through the phys-mem window; nothing else holds it.
    let l4 = unsafe { frame_to_page_table(l4_frame, physical_memory_offset) };
    l4.zero();
    // SAFETY: this template L4 is not the active table; building mappings into it is local.
    let mut template = unsafe { OffsetPageTable::new(l4, physical_memory_offset) };

    let text = crate::cpu::entry::text();
    let data = crate::cpu::entry::data();
    // Entry text is supervisor R+X; entry data is supervisor R+W, never executable. Neither is
    // USER_ACCESSIBLE, so ring 3 can't read it even though it's mapped (the point is only that the
    // CPU can run the stubs and read the IDT/GDT/TSS during a transition). W^X holds here too.
    let text_flags = PageTableFlags::PRESENT;
    let data_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let parent_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    for (range, flags) in [(text, text_flags), (data, data_flags)] {
        let mut va = range.start;
        while va < range.end {
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
            let phys = active
                .translate_addr(VirtAddr::new(va))
                .expect("entry page is unmapped in the kernel's own tables");
            let frame = PhysFrame::<Size4KiB>::containing_address(phys);
            // SAFETY: mapping an entry page into a non-active template table; the frame is the
            // kernel's own already-present entry page, aliased read/execute or read/write.
            unsafe {
                match template.map_to_with_table_flags(page, frame, flags, parent_flags, frame_allocator) {
                    Ok(flush) => flush.ignore(),
                    Err(MapToError::PageAlreadyMapped(_)) => {}
                    Err(_) => return Err(()),
                }
            }
            va += 4096;
        }
    }

    ENTRY_TEMPLATE_L4E.store(l4[ENTRY_L4_SLOT].flags().bits() | l4[ENTRY_L4_SLOT].addr().as_u64(), Ordering::Relaxed);
    Ok(())
}

/// The raw L4 entry value every user table puts in slot 511 to map the entry area. `0` before
/// `build_entry_template`.
pub fn entry_template_l4e() -> u64 {
    ENTRY_TEMPLATE_L4E.load(Ordering::Relaxed)
}

/// Lazy user-half mirror (decision B1): on a ring-3 fault, if the kernel table maps the faulting
/// address's 512 GiB L4 slot but the user table doesn't, copy the L4 entry across and report a
/// retry. The two tables then share that whole subtree, so every later map/unmap beneath it shows
/// in both with no further work. Safe because a user L4 subtree, once present, is only freed at
/// teardown, so the copied pointer never goes stale mid-life. Reads the current process's two CR3
/// values (`entry::active_cr3`), no lock -- callable straight from the page-fault handler.
pub fn mirror_user_l4(fault_addr: u64) -> bool {
    if !enabled() {
        return false;
    }
    let (kernel_cr3, user_cr3) = crate::cpu::entry::active_cr3();
    if user_cr3 == 0 || user_cr3 == kernel_cr3 {
        return false;
    }
    let slot = ((fault_addr >> 39) & 0x1ff) as usize;
    if slot >= 256 {
        // Kernel half: never mirrored (that is the whole point of the user table).
        return false;
    }
    const FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;
    let pmo = VirtAddr::new(crate::boot::hhdm_offset());
    let kframe = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(kernel_cr3 & FRAME_MASK));
    let uframe = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(user_cr3 & FRAME_MASK));
    // SAFETY: both are the current process's live L4 frames, viewed through the phys-mem window;
    // single core, interrupts off in the fault handler, so no concurrent view.
    let kl4 = unsafe { frame_to_page_table(kframe, pmo) };
    let ul4 = unsafe { frame_to_page_table(uframe, pmo) };
    if kl4[slot].flags().contains(PageTableFlags::PRESENT)
        && !ul4[slot].flags().contains(PageTableFlags::PRESENT)
    {
        ul4[slot] = kl4[slot].clone();
        // The iretq/sysretq back to ring 3 reloads the user CR3, flushing stale TLB, so no
        // explicit invalidation is needed here.
        return true;
    }
    false
}

/// Reconstructs the canonical virtual address for a 4 KiB page from its four page-table indices.
fn page_va(l4: usize, pdpt: usize, pd: usize, pt: usize) -> u64 {
    let mut va = ((l4 as u64) << 39) | ((pdpt as u64) << 30) | ((pd as u64) << 21) | ((pt as u64) << 12);
    if va & (1 << 47) != 0 {
        va |= 0xffff_0000_0000_0000;
    }
    va
}

/// The `[kpti]` boot audit, the Meltdown counterpart of `[wx]`: walks the shared entry template
/// (the one kernel-half subtree a user table maps) and asserts every page it maps lies inside the
/// entry area. If anything else of the kernel slipped in, a process could read it -- so this
/// panics rather than boot isolated-in-name-only. The user half can't leak the kernel either: the
/// lazy mirror only ever copies user-half L4 slots (`mirror_user_l4`).
pub fn audit_entry_template(physical_memory_offset: VirtAddr) {
    if !enabled() {
        return;
    }
    let text = crate::cpu::entry::text();
    let data = crate::cpu::entry::data();
    let l4e = entry_template_l4e();
    assert!(l4e != 0, "[kpti] audit before the entry template was built");
    const MASK: u64 = 0x000f_ffff_ffff_f000;
    // SAFETY: the template's live subtree, read only, through the phys-mem window.
    let pdpt = unsafe {
        frame_to_page_table(
            PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(l4e & MASK)),
            physical_memory_offset,
        )
    };
    let mut pages = 0u64;
    for (pi, pde) in pdpt.iter().enumerate() {
        if !pde.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        assert!(!pde.flags().contains(PageTableFlags::HUGE_PAGE), "[kpti] huge page in the entry template");
        let pd = unsafe { frame_to_page_table(PhysFrame::<Size4KiB>::containing_address(pde.addr()), physical_memory_offset) };
        for (di, pdee) in pd.iter().enumerate() {
            if !pdee.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            assert!(!pdee.flags().contains(PageTableFlags::HUGE_PAGE), "[kpti] huge page in the entry template");
            let pt = unsafe { frame_to_page_table(PhysFrame::<Size4KiB>::containing_address(pdee.addr()), physical_memory_offset) };
            for (ti, pte) in pt.iter().enumerate() {
                if !pte.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }
                let va = page_va(ENTRY_L4_SLOT, pi, di, ti);
                assert!(
                    text.contains(&va) || data.contains(&va),
                    "[kpti] the entry template maps {va:#x}, outside the entry area"
                );
                // The user table must never expose kernel memory to ring 3: no entry-area page is
                // USER_ACCESSIBLE.
                assert!(
                    !pte.flags().contains(PageTableFlags::USER_ACCESSIBLE),
                    "[kpti] entry page {va:#x} is user-accessible"
                );
                pages += 1;
            }
        }
    }
    crate::serial_println!("[kpti] entry template maps {} pages, all in the entry area", pages);
}
