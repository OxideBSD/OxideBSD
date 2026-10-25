//! The Local APIC, brought up late in boot for one reason: so a PCI device can deliver an
//! interrupt by MSI/MSI-X. Everything else -- the PIT timer, the keyboard, and the legacy-PCI
//! `INTx` devices (`drivers::rtl8139`, the IDE/AHCI/virtio disks) -- keeps arriving through the
//! 8259 pair exactly as before (`cpu::pic`). This module only adds a second, parallel delivery
//! path, for the device that needs it: USB mass storage (`drivers::usb`), where polling a bulk
//! endpoint at the 100 Hz tick would make disk I/O crawl, and whose real-hardware target (a
//! UEFI-only PCIe chipset) has no dependable `INTx` routing to fall back on.
//!
//! **Why this runs after `memory::init`, not alongside `cpu::pic::init`.** The xAPIC's registers
//! are MMIO (physical `0xFEE00000`), and mapping them uncached needs the page mapper, which
//! doesn't exist as early as `init_pics`. Early boot therefore stays on the proven pure-8259 path
//! (`pic::init` even clears `IA32_APIC_BASE`'s global-enable bit outright); this module re-enables
//! the LAPIC once the mapper is up.
//!
//! **Virtual wire mode (Intel MultiProcessor spec §3.6.2, mode B).** Enabling the LAPIC makes the
//! CPU stop listening to its raw `INTR` pin and take interrupts only from the LAPIC -- so the
//! 8259's output has to be routed *through* the LAPIC's LINT0 pin instead, in ExtINT delivery
//! mode, or every legacy IRQ (the timer included) would stop dead the instant the LAPIC comes on.
//! The enable + LINT0/LINT1 + IMCR transition is done with interrupts off so a timer IRQ can't be
//! lost across it. EOI for a legacy IRQ still goes to the 8259 (an ExtINT-delivered interrupt
//! never sets the LAPIC's own ISR); only an interrupt the LAPIC itself delivers -- an MSI -- is
//! acknowledged with a LAPIC EOI (`eoi`).
//!
//! **xAPIC (MMIO), not x2APIC.** Every LAPIC supports the xAPIC MMIO interface; x2APIC is a newer
//! feature this kernel's ISA baseline (x86-64-v1) doesn't include, so per the project's "probe,
//! don't require" rule it's left for later. One BSP, single core: no IPIs, no per-CPU state.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::{Mutex, Once};
use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::{ApicBase, ApicBaseFlags};
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};
use x86_64::VirtAddr;

use crate::serial_println;

// xAPIC register offsets, from the LAPIC MMIO base (Intel SDM vol. 3 Table 10-1).
const REG_ID: u64 = 0x20;
const REG_EOI: u64 = 0xB0;
const REG_SVR: u64 = 0xF0;
const REG_LVT_LINT0: u64 = 0x350;
const REG_LVT_LINT1: u64 = 0x360;

/// Spurious-Vector Register: bit 8 software-enables the LAPIC; the low 8 bits are the vector a
/// spurious interrupt reports as. 255 matches `trap::SPURIOUS_VECTOR`, whose stub already sends no
/// EOI -- exactly right, since a LAPIC spurious interrupt must not be acknowledged.
const SVR_APIC_ENABLE: u32 = 1 << 8;
const SPURIOUS_VECTOR: u32 = 255;

/// LVT delivery modes (bits 10:8) for the two local interrupt pins in virtual-wire mode.
const LVT_DELIVERY_EXTINT: u32 = 0b111 << 8;
const LVT_DELIVERY_NMI: u32 = 0b100 << 8;

/// The fixed MSI message-address window: a write here is delivered by the LAPIC. The destination
/// APIC id goes in bits 19:12; physical destination mode, fixed delivery, no redirection hint
/// (bits 3:2 clear) is all this single-core kernel ever needs.
const MSI_ADDRESS_BASE: u32 = 0xFEE0_0000;

/// The first IDT vector MSI interrupts use. `cpu::trap` emits real stubs for the whole
/// `[MSI_VECTOR_BASE, MSI_VECTOR_BASE + MSI_VECTORS)` range (everything above still shares the
/// spurious stub), and `cpu::interrupts::dispatch` routes them here.
pub const MSI_VECTOR_BASE: u8 = 48;
/// How many distinct MSI vectors are available. USB funnels every event through one interrupter,
/// so one vector covers the whole USB stack; the rest are headroom for a future MSI device.
pub const MSI_VECTORS: usize = 8;

/// The LAPIC MMIO base (an HHDM address, uncached), set once by `init`. `None` until then, and if
/// `init` never ran (no LAPIC) MSI is simply never offered -- drivers fall back to polling.
static LAPIC_BASE: Once<VirtAddr> = Once::new();
/// The BSP's LAPIC id, the destination every MSI message targets.
static LAPIC_ID: Once<u32> = Once::new();

/// One handler per MSI vector, indexed by `vector - MSI_VECTOR_BASE`. Copied out under the lock in
/// `dispatch_msi` (never called while holding it), the same shape `interrupts::IRQ_HANDLERS` uses.
static MSI_HANDLERS: [Mutex<Option<fn()>>; MSI_VECTORS] = [const { Mutex::new(None) }; MSI_VECTORS];
/// The next free MSI vector `register_msi` hands out.
static NEXT_MSI_VECTOR: Mutex<u8> = Mutex::new(MSI_VECTOR_BASE);

/// MSI interrupts delivered since boot, and whether the first one has been logged -- a bring-up
/// signal (zero after a device is used means MSI delivery is broken and only a polling fallback is
/// keeping it alive, which would bite on hardware with no such fallback).
static MSI_COUNT: AtomicU64 = AtomicU64::new(0);
static FIRST_MSI_LOGGED: AtomicBool = AtomicBool::new(false);

/// MSI interrupts delivered since boot.
pub fn msi_count() -> u64 {
    MSI_COUNT.load(Ordering::Relaxed)
}

fn read(off: u64) -> u32 {
    // SAFETY: `LAPIC_BASE` is a mapped, uncached LAPIC register page; `off` names a real register.
    unsafe { core::ptr::read_volatile((*LAPIC_BASE.get().unwrap() + off).as_ptr::<u32>()) }
}

fn write(off: u64, val: u32) {
    // SAFETY: as `read`.
    unsafe { core::ptr::write_volatile((*LAPIC_BASE.get().unwrap() + off).as_mut_ptr::<u32>(), val) }
}

/// Maps the LAPIC's registers and switches the CPU from pure-8259 delivery (what `pic::init` left)
/// to virtual-wire mode, so legacy IRQs keep flowing while MSI becomes possible. Call once, after
/// `memory::init`; never fatal.
pub fn init(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    phys_mem_offset: VirtAddr,
) {
    let (frame, _) = ApicBase::read();
    let phys_base = frame.start_address();
    // Uncached HHDM mapping, the same primitive every MMIO BAR goes through.
    let virt = crate::drivers::pci::map_mmio(mapper, frame_allocator, phys_mem_offset, phys_base, 1);
    LAPIC_BASE.call_once(|| virt);

    x86_64::instructions::interrupts::without_interrupts(|| {
        // Re-enable the LAPIC's global-enable bit (`pic::init` cleared it). Only now are its MMIO
        // registers live, so every write below has to follow this.
        let (frame, flags) = ApicBase::read();
        // SAFETY: re-enabling the LAPIC we're about to configure for virtual-wire delivery.
        unsafe { ApicBase::write(frame, flags | ApicBaseFlags::LAPIC_ENABLE) };

        write(REG_SVR, SVR_APIC_ENABLE | SPURIOUS_VECTOR);
        // The 8259 pair feeds LINT0 as an external interrupt controller; LINT1 is the NMI line.
        write(REG_LVT_LINT0, LVT_DELIVERY_EXTINT);
        write(REG_LVT_LINT1, LVT_DELIVERY_NMI);

        // IMCR (PIIX-family chipsets, I/O ports 0x22/0x23 register 0x70): 1 connects the 8259 and
        // NMI lines to the APIC instead of straight to the CPU -- the counterpart of the 0 that
        // `pic::init` wrote for pure-8259 mode. A no-op on chipsets (and QEMU setups) with no IMCR,
        // where the 8259 is wired to LINT0 unconditionally.
        // SAFETY: a documented chipset register; this is the one place that drives the transition.
        unsafe {
            let mut select: Port<u8> = Port::new(0x22);
            let mut data: Port<u8> = Port::new(0x23);
            select.write(0x70);
            data.write(0x01);
        }

        LAPIC_ID.call_once(|| read(REG_ID) >> 24);
    });

    serial_println!(
        "[boot] local APIC enabled (xAPIC at {:#x}, id {}); 8259 IRQs now virtual-wire via LINT0",
        phys_base.as_u64(),
        LAPIC_ID.get().copied().unwrap_or(0),
    );
}

/// Whether MSI is available (the LAPIC was brought up). Drivers check this to decide between MSI
/// and a polling fallback.
pub fn is_enabled() -> bool {
    LAPIC_BASE.get().is_some()
}

/// Reserves an MSI vector and registers `handler` for it; `None` if MSI is unavailable or every
/// vector is taken. The returned vector feeds `msi_message`, whose `(address, data)` a device's
/// MSI/MSI-X capability is then programmed with.
pub fn register_msi(handler: fn()) -> Option<u8> {
    if !is_enabled() {
        return None;
    }
    let mut next = NEXT_MSI_VECTOR.lock();
    if (*next as usize) >= MSI_VECTOR_BASE as usize + MSI_VECTORS {
        return None;
    }
    let vector = *next;
    *next += 1;
    *MSI_HANDLERS[(vector - MSI_VECTOR_BASE) as usize].lock() = Some(handler);
    Some(vector)
}

/// The `(message address, message data)` a device programs into its MSI/MSI-X capability to
/// deliver `vector` to this CPU. The address is 32-bit (the high dword of an MSI-X entry is 0).
pub fn msi_message(vector: u8) -> (u32, u32) {
    let dest = LAPIC_ID.get().copied().unwrap_or(0);
    let address = MSI_ADDRESS_BASE | (dest << 12);
    // Data: vector in the low 8 bits, fixed delivery mode, edge-triggered (the MSI default).
    (address, vector as u32)
}

/// Signals end-of-interrupt to the LAPIC. Only for an interrupt the LAPIC itself delivered (an
/// MSI) -- a legacy IRQ arriving via LINT0/ExtINT is acknowledged at the 8259 instead.
pub fn eoi() {
    write(REG_EOI, 0);
}

/// Runs the handler for an MSI vector and signals EOI. Called from `interrupts::dispatch` for
/// vectors in `[MSI_VECTOR_BASE, MSI_VECTOR_BASE + MSI_VECTORS)`.
pub(crate) fn dispatch_msi(vector: u64) {
    MSI_COUNT.fetch_add(1, Ordering::Relaxed);
    if !FIRST_MSI_LOGGED.swap(true, Ordering::Relaxed) {
        serial_println!("[apic] first MSI delivered (vector {})", vector);
    }
    let idx = vector as usize - MSI_VECTOR_BASE as usize;
    let handler = *MSI_HANDLERS[idx].lock();
    if let Some(handler) = handler {
        handler();
    }
    eoi();
}
