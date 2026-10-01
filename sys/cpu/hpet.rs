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
//! **Discovery**: the `"HPET"` table, found by `acpi::find_table` (the RSDP -> XSDT/RSDT walk, with
//! every table's checksum validated), gives the counter's MMIO base in its Generic Address
//! Structure.
//!
//! **Absence is never fatal** -- missing RSDP, missing `"HPET"` table, a bad checksum, or a
//! non-memory-space Generic Address Structure all just leave `HPET` at `None` for the rest of the
//! boot (logged), and every public accessor returns `None` -- `sys_clock_getres`/
//! `process::timers` both already have an honest tick-based fallback for exactly this case. Same
//! "logged, boot continues regardless" precedent `drivers::rtl8139::init`/`drivers::usb::init` already
//! establish for optional hardware.

use spin::Mutex;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::serial_println;

/// Real ACPI HPET table body, immediately following the common `AcpiSdtHeader` -- fixed layout
/// per the ACPI/HPET spec. `event_timer_block_id` packs hardware revision/comparator count/counter
/// size/legacy-replacement-capable/PCI vendor ID into one `u32` -- none of those bitfields matter
/// for this driver's own counter-only use, so it's kept raw rather than decoded. The 12 bytes from
/// `address_space_id` through `reserved0`+`address` are a real ACPI Generic Address Structure.
#[repr(C, packed)]
struct HpetTable {
    header: crate::acpi::SdtHeader,
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

/// The HPET table's MMIO base (its Generic Address Structure's `address`), once `acpi::find_table`
/// has found and checksum-validated it and the address is in system memory; `None` (logged)
/// otherwise.
fn discover_hpet_mmio_base(hhdm_offset: u64) -> Option<u64> {
    let hpet_virt = crate::acpi::find_table(hhdm_offset, b"HPET")?;
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
/// fatal either way (matches `drivers::rtl8139::init`/`drivers::usb::init`'s own precedent) -- every
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
