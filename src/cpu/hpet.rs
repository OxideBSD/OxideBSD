//! Real ACPI HPET (High Precision Event Timer) support -- **a free-running counter only, never an
//! interrupt source**. See `CLAUDE.md`'s own HPET section for the full design rationale; the short
//! version: this kernel's scheduler tick stays the 100Hz PIT (`cpu::pit`) exactly as it always
//! has -- HPET is a second, independent high-resolution *duration* clock layered on top, used only
//! by `sys_clock_getres` (real sub-tick resolution reporting) and `process::timers`' real POSIX
//! interval-timer overrun accounting (`PosixTimer::deadline_ns`/`interval_ns`). This kernel has no
//! IOAPIC/MSI support at all (see `drivers::usb`'s own module doc comment) and no interrupt-driven
//! HPET comparator is ever configured here -- `GENERAL_CONFIG` is written with only `ENABLE_CNF`
//! set, `LEG_RT_CNF` (legacy-replacement IRQ0/IRQ8 rerouting) deliberately left clear. A POSIX
//! timer's real overrun count doesn't actually need one real interrupt per interval -- it's a pure
//! counting problem, solved by exact `elapsed_ns / interval_ns` arithmetic at whatever cadence
//! something already polls (`interrupts::timer_interrupt_handler`'s existing 100Hz tick), the same
//! "catch-up" technique real Linux's own `hrtimer_forward()` uses. See `process::timers`' own
//! `deadline_ns` doc comment for that half.
//!
//! **Discovery**: Limine hands back a real ACPI RSDP address directly (`boot::rsdp_address`, a
//! genuine hardware/firmware value, not guessed or hardcoded) -- no manual BIOS/EBDA scanning
//! needed. From there this is a plain, real ACPI table walk: RSDP -> XSDT (or RSDT on an ACPI
//! 1.0 firmware with no XSDT) -> the `"HPET"` signature table -> its Generic Address Structure's
//! real MMIO base. Every pointer *inside* those tables is a genuine ACPI physical address (unlike
//! the RSDP pointer itself -- see `boot::rsdp_address`'s own doc comment), dereferenced via
//! `boot::hhdm_offset()` like every other raw physical access in this codebase. Real per-table
//! checksum validation before trusting anything, matching `drivers::usb::xhci`'s own defensive
//! posture toward hardware/firmware this kernel doesn't fully control.
//!
//! **Absence is never fatal** -- missing RSDP, missing `"HPET"` table, a bad checksum, or a
//! non-memory-space Generic Address Structure all just leave `HPET` at `None` for the rest of the
//! boot (logged), and every public accessor returns `None` -- `sys_clock_getres`/
//! `process::timers` both already have an honest tick-based fallback for exactly this case. Same
//! "logged, boot continues regardless" precedent `net::rtl8139::init`/`drivers::usb::init` already
//! establish for optional hardware.

use spin::Mutex;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::serial_println;

/// Real ACPI "System Description Table Header" -- the common 36-byte prefix of every ACPI table
/// this walk touches (RSDT/XSDT/HPET), per the ACPI spec's own fixed layout.
#[repr(C, packed)]
struct AcpiSdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// Real ACPI RSDP, revision-0/1 (ACPI 1.0) shape -- the first 20 bytes are common to every RSDP
/// revision; a revision `>= 2` RSDP has more fields immediately following (`length`/
/// `xsdt_address`/`extended_checksum`/reserved), read separately below rather than folded into
/// one struct, since a real ACPI-1.0-only firmware's RSDP genuinely is only these 20 bytes long.
#[repr(C, packed)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// Real ACPI HPET table body, immediately following the common `AcpiSdtHeader` -- fixed layout
/// per the ACPI/HPET spec. `event_timer_block_id` packs hardware revision/comparator count/counter
/// size/legacy-replacement-capable/PCI vendor ID into one `u32` -- none of those bitfields matter
/// for this driver's own counter-only use, so it's kept raw rather than decoded. The 12 bytes from
/// `address_space_id` through `reserved0`+`address` are a real ACPI Generic Address Structure.
#[repr(C, packed)]
struct HpetTable {
    header: AcpiSdtHeader,
    event_timer_block_id: u32,
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    reserved0: u8,
    address: u64,
    hpet_number: u8,
    minimum_tick: u16,
    page_protection: u8,
}

/// Real ACPI Generic Address Structure's `address_space_id` value for "System Memory" -- the only
/// space this driver ever trusts an HPET's own MMIO base to live in (always true in practice, but
/// checked defensively rather than assumed, matching `xhci.rs`'s own `HCCPARAMS1.CSZ` check).
const ACPI_ADDRESS_SPACE_MEMORY: u8 = 0;

const REG_CAPABILITIES: u64 = 0x000;
const REG_GENERAL_CONFIG: u64 = 0x010;
const REG_MAIN_COUNTER: u64 = 0x0F0;

/// `GENERAL_CONFIG`'s `ENABLE_CNF` bit -- the *only* bit this driver ever sets. `LEG_RT_CNF` (bit
/// 1, legacy-replacement IRQ0/IRQ8 rerouting) is deliberately never touched -- see this module's
/// own doc comment for why. Writing this single bit (rather than a read-modify-write) also
/// guarantees a clean, fully-known configuration regardless of whatever firmware left behind.
const GENERAL_CONFIG_ENABLE_CNF: u64 = 1 << 0;

struct HpetState {
    /// Kernel-virtual base of the one, explicitly `NO_CACHE`-mapped MMIO page holding every
    /// register this driver touches -- see `map_registers`' own doc comment for why an ordinary
    /// HHDM read isn't trusted for this, the identical reasoning `xhci.rs`'s `map_bar_pages`
    /// already established for a controller's own BAR.
    virt_base: VirtAddr,
    /// Real counter tick period, in femtoseconds (`10^-15` s) -- `CAP_ID_REG`'s own
    /// `COUNTER_CLK_PERIOD` field, the ground truth every `now_ns`/`resolution_ns` reading derives
    /// from.
    period_fs: u32,
}

static HPET: Mutex<Option<HpetState>> = Mutex::new(None);

#[inline]
fn read32(addr: VirtAddr) -> u32 {
    unsafe { core::ptr::read_volatile(addr.as_ptr::<u32>()) }
}

#[inline]
fn write32(addr: VirtAddr, val: u32) {
    unsafe { core::ptr::write_volatile(addr.as_mut_ptr::<u32>(), val) }
}

fn read_reg64(virt_base: VirtAddr, offset: u64) -> u64 {
    let addr = virt_base + offset;
    (read32(addr) as u64) | ((read32(addr + 4u64) as u64) << 32)
}

/// Real hi/lo/hi-retry read of the live, free-running 64-bit Main Counter -- a plain two-word
/// `read_reg64` could otherwise observe a torn value if the low 32 bits roll over between the two
/// 32-bit reads (standard guidance for reading a live-incrementing hardware counter wider than one
/// bus access; `CAPABILITIES`/`GENERAL_CONFIG` above never change after `init`, so they don't need
/// this).
fn read_counter64(virt_base: VirtAddr) -> u64 {
    let addr = virt_base + REG_MAIN_COUNTER;
    loop {
        let hi1 = read32(addr + 4u64);
        let lo = read32(addr);
        let hi2 = read32(addr + 4u64);
        if hi1 == hi2 {
            return (lo as u64) | ((hi1 as u64) << 32);
        }
    }
}

/// Reads `len` bytes starting at kernel-virtual `virt` and sums them as a plain `u8` wrapping
/// checksum -- real ACPI table validation (every table, including the RSDP itself, must sum to
/// `0` over its own declared length). Used for both the RSDP's own fixed 20/36-byte extent and
/// every subsequent `AcpiSdtHeader`-prefixed table's `length` field.
fn checksum_ok(virt: VirtAddr, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *(virt + i as u64).as_ptr::<u8>() });
    }
    sum == 0
}

/// Maps one real MMIO page at `phys_base` (rounded down to its containing page -- an HPET base is
/// always page-aligned in practice, but this doesn't assume it), `NO_CACHE` -- adapted directly
/// from `drivers::usb::xhci`'s own `map_bar_pages`: this is genuine, live hardware register space,
/// not RAM, so it must never be reached through a cached HHDM mapping (this module never trusts
/// that window for it regardless -- see this module's own doc comment). Returns the virtual
/// address of `phys_base` itself (not necessarily page-aligned), or `None` if the mapping failed.
fn map_registers(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    phys_mem_offset: VirtAddr,
    phys_base: PhysAddr,
) -> Option<VirtAddr> {
    let page_phys = PhysFrame::<Size4KiB>::containing_address(phys_base);
    let page_virt = phys_mem_offset + page_phys.start_address().as_u64();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
    let page = Page::<Size4KiB>::containing_address(page_virt);
    // SAFETY: `page_phys` is the real HPET's own MMIO page (never RAM this kernel hands out for
    // anything else), and `page` is that same range's own dedicated HHDM-offset virtual address --
    // mapping it there can't alias any other live mapping. Same reasoning `xhci.rs`'s own
    // `map_bar_pages` already establishes for an xHCI controller's BAR.
    match unsafe { mapper.map_to(page, page_phys, flags, frame_allocator) } {
        Ok(flush) => flush.ignore(), // never-before-mapped MMIO page -- no stale TLB entry.
        Err(MapToError::PageAlreadyMapped(_)) => {}
        Err(e) => {
            serial_println!("[hpet] failed to map MMIO page: {:?}", e);
            return None;
        }
    }
    Some(page_virt + (phys_base.as_u64() - page_phys.start_address().as_u64()))
}

/// Reads a real `AcpiSdtHeader`-prefixed table at physical `phys` and, if its signature matches
/// `want_sig` and its own checksum validates, returns its real kernel-virtual address. `phys == 0`
/// (an RSDP with no real XSDT, ACPI 1.0 firmware) is handled by the caller, not here.
fn find_table(hhdm_offset: u64, table_phys_addrs: &[u64], want_sig: &[u8; 4]) -> Option<VirtAddr> {
    for &phys in table_phys_addrs {
        if phys == 0 {
            continue;
        }
        let virt = VirtAddr::new(hhdm_offset + phys);
        // SAFETY: `phys` is a real ACPI table pointer taken directly from a validated RSDT/XSDT
        // entry; real ACPI tables always live well under the "at least 4 GiB" HHDM guarantee
        // every other low-physical-address read in this codebase already relies on (see
        // `boot::hhdm_offset`'s own doc comment).
        let header = unsafe { core::ptr::read_unaligned(virt.as_ptr::<AcpiSdtHeader>()) };
        if &header.signature != want_sig {
            continue;
        }
        let length = header.length;
        if checksum_ok(virt, length as usize) {
            return Some(virt);
        }
        serial_println!("[hpet] table at phys {:#x} failed checksum, skipping", phys);
    }
    None
}

/// Real ACPI RSDP -> RSDT/XSDT -> `"HPET"` table walk. Returns the HPET table's own real MMIO
/// base (`Generic Address Structure`'s `address` field) once every checksum/signature/address-
/// space check has passed, or `None` (logged) at the first real failure.
fn discover_hpet_mmio_base(hhdm_offset: u64) -> Option<u64> {
    let rsdp_virt = VirtAddr::new(crate::boot::rsdp_address()?);
    // SAFETY: `rsdp_virt` is Limine's own real RSDP response pointer -- see
    // `boot::rsdp_address`'s own doc comment for why this is already a valid virtual address at
    // this project's base revision.
    let rsdp = unsafe { core::ptr::read_unaligned(rsdp_virt.as_ptr::<RsdpV1>()) };
    if &rsdp.signature != b"RSD PTR " {
        serial_println!("[hpet] RSDP signature mismatch -- no ACPI tables, skipping");
        return None;
    }
    if !checksum_ok(rsdp_virt, core::mem::size_of::<RsdpV1>()) {
        serial_println!("[hpet] RSDP (v1) checksum mismatch, skipping");
        return None;
    }

    // ACPI 2.0+: a real XSDT (64-bit entries), preferred over the 1.0-only RSDT whenever present.
    // The extended fields sit immediately after the 20-byte v1 struct above.
    let xsdt_phys = if rsdp.revision >= 2 {
        let ext_virt = rsdp_virt + core::mem::size_of::<RsdpV1>() as u64;
        let ext_len = unsafe { core::ptr::read_unaligned((ext_virt).as_ptr::<u32>()) };
        if checksum_ok(rsdp_virt, ext_len as usize) {
            let xsdt_addr = unsafe { core::ptr::read_unaligned((ext_virt + 4u64).as_ptr::<u64>()) };
            (xsdt_addr != 0).then_some(xsdt_addr)
        } else {
            serial_println!("[hpet] RSDP (v2 extended) checksum mismatch -- falling back to RSDT");
            None
        }
    } else {
        None
    };

    let (root_phys, entry_size): (u64, u64) = match xsdt_phys {
        Some(xsdt) => (xsdt, 8),
        None => (rsdp.rsdt_address as u64, 4),
    };
    if root_phys == 0 {
        serial_println!("[hpet] no real RSDT/XSDT address in the RSDP, skipping");
        return None;
    }

    let root_virt = VirtAddr::new(hhdm_offset + root_phys);
    let root_header = unsafe { core::ptr::read_unaligned(root_virt.as_ptr::<AcpiSdtHeader>()) };
    let root_len = root_header.length;
    if !checksum_ok(root_virt, root_len as usize) {
        serial_println!("[hpet] RSDT/XSDT checksum mismatch, skipping");
        return None;
    }
    let sdt_header_size = core::mem::size_of::<AcpiSdtHeader>() as u32;
    let entry_count = ((root_len.saturating_sub(sdt_header_size)) as u64) / entry_size;

    // Real table-pointer array immediately following the RSDT/XSDT's own header -- collected into
    // a small on-stack buffer (a real system has a handful of ACPI tables, never remotely close to
    // this cap) rather than needing `alloc` this early/this low-level.
    const MAX_TABLES: usize = 64;
    let mut table_phys = [0u64; MAX_TABLES];
    let n = (entry_count as usize).min(MAX_TABLES);
    for i in 0..n {
        let entry_addr = root_virt + sdt_header_size as u64 + (i as u64) * entry_size;
        table_phys[i] = if entry_size == 8 {
            unsafe { core::ptr::read_unaligned(entry_addr.as_ptr::<u64>()) }
        } else {
            unsafe { core::ptr::read_unaligned(entry_addr.as_ptr::<u32>()) as u64 }
        };
    }

    let hpet_virt = find_table(hhdm_offset, &table_phys[..n], b"HPET")?;
    // SAFETY: `find_table` already validated this table's own signature and checksum.
    let hpet = unsafe { core::ptr::read_unaligned(hpet_virt.as_ptr::<HpetTable>()) };
    if hpet.address_space_id != ACPI_ADDRESS_SPACE_MEMORY {
        serial_println!(
            "[hpet] HPET table's own address space isn't system memory ({}), skipping",
            hpet.address_space_id
        );
        return None;
    }
    let address = hpet.address;
    if address == 0 {
        serial_println!("[hpet] HPET table reports a null MMIO base, skipping");
        return None;
    }
    Some(address)
}

/// Finds a real ACPI HPET, maps its MMIO registers, and enables its main counter -- **counter
/// only, no comparator/interrupt is ever configured**, see this module's own doc comment. Not
/// fatal either way (matches `net::rtl8139::init`/`drivers::usb::init`'s own precedent) -- every
/// caller of `now_ns`/`resolution_ns` already has an honest tick-based fallback for "no HPET
/// found this boot." Call once, at boot, after paging/the frame allocator are ready (same
/// prerequisite `drivers::usb::init` has) -- nothing downstream needs this any earlier.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) {
    let hhdm_offset = phys_mem_offset.as_u64();
    let Some(mmio_phys) = discover_hpet_mmio_base(hhdm_offset) else {
        serial_println!(
            "[hpet] no real HPET found this boot -- high-resolution timers unavailable"
        );
        return;
    };
    let Some(virt_base) = map_registers(
        mapper,
        frame_allocator,
        phys_mem_offset,
        PhysAddr::new(mmio_phys),
    ) else {
        return;
    };

    let capabilities = read_reg64(virt_base, REG_CAPABILITIES);
    let period_fs = (capabilities >> 32) as u32;
    if period_fs == 0 {
        serial_println!("[hpet] real HPET reports a zero counter period, treating as absent");
        return;
    }

    write32(
        virt_base + REG_GENERAL_CONFIG,
        GENERAL_CONFIG_ENABLE_CNF as u32,
    );
    write32(virt_base + REG_GENERAL_CONFIG + 4u64, 0);

    *HPET.lock() = Some(HpetState {
        virt_base,
        period_fs,
    });
    serial_println!(
        "[hpet] real HPET enabled: MMIO base {:#x}, counter period {} fs ({} ns resolution)",
        mmio_phys,
        period_fs,
        (period_fs as u64 / 1_000_000).max(1)
    );
}

/// Real elapsed nanoseconds since the HPET's own main counter was enabled (`init`) -- a pure
/// monotonic *duration* clock, never wall-clock-adjusted (no `clock_settime`-style retargeting
/// concept applies to it at all, unlike `cpu::rtc`'s own calibrated `CLOCK_REALTIME` reading).
/// `None` whenever no real HPET was found this boot. `u128` intermediate arithmetic avoids
/// overflowing a 64-bit counter times a up-to-`u32` femtosecond period before the final divide
/// (same precedent `process::mm`'s own `EOVERFLOW` check already established for this class of
/// wide multiply).
pub fn now_ns() -> Option<u64> {
    let guard = HPET.lock();
    let state = guard.as_ref()?;
    let counter = read_counter64(state.virt_base);
    Some(((counter as u128 * state.period_fs as u128) / 1_000_000) as u64)
}

/// Real HPET counter resolution in nanoseconds, rounded down but never `0` (a period finer than a
/// whole nanosecond, real on modern hardware, still honestly reported as "at least this fine" via
/// the `max(1)` floor) -- `sys_clock_getres`'s own real `CLOCK_REALTIME`/`CLOCK_MONOTONIC` source
/// once a real HPET is present. `None` whenever no real HPET was found this boot (the caller's own
/// existing `1_000_000_000 / TIMER_HZ` fallback applies instead).
pub fn resolution_ns() -> Option<u64> {
    let guard = HPET.lock();
    let state = guard.as_ref()?;
    Some(((state.period_fs as u64) / 1_000_000).max(1))
}
