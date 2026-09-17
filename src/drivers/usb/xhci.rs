//! A minimal xHCI (Extensible Host Controller Interface) driver -- the real USB 2/3 host
//! controller every USB-3-era platform exposes, QEMU's `qemu-xhci` included. See
//! <https://www.intel.com/content/www/us/en/products/docs/io/universal-serial-bus/extensible-host-controler-interface-usb-xhci.html>
//! for the spec this follows (xHCI 1.1/1.2 register and data-structure layout).
//!
//! **Polling, not IRQ-driven, deliberately** -- see `super`'s own module doc comment for the full
//! rationale (this kernel's first real-hardware boot target has no known-good legacy PCI `INTx`
//! routing story, and this kernel has no IOAPIC/MSI support at all). Interrupter 0's Interrupt
//! Enable bit and `USBCMD.INTE` are deliberately left clear -- the Event Ring mechanism itself
//! (`ERSTBA`/`ERSTSZ`/`ERDP`) works identically either way; only actual CPU interrupt *signaling*
//! is gated by those bits, and this driver never asks for one.
//!
//! **32-byte device contexts only** (`HCCPARAMS1.CSZ == 0`) -- what QEMU's `qemu-xhci` and the
//! overwhelming majority of real platforms use. A controller reporting `CSZ == 1` (64-byte
//! contexts) is logged and treated as unsupported hardware, matching this codebase's existing
//! "known, deliberate gap" style rather than doubling every context struct's size/layout for a
//! case that's very unlikely to matter for this project's actual target hardware.
//!
//! **One command ring, one single-segment event ring, both exactly one page.** A page holds 256
//! 16-byte TRBs -- the last slot is a real Link TRB closing the ring (see `TrbRing`'s own doc
//! comment), so 255 real entries per lap. Nothing this driver does (bringing up one keyboard)
//! comes remotely close to needing more than one segment or a bigger ring.
//!
//! **No page-table mapping needed for this driver's own DMA structures** (rings, contexts, the
//! DCBAA, scratchpad buffers) -- every one of those is a frame this driver allocates itself via
//! the ordinary frame allocator, always real RAM, always within Limine's HHDM guarantee, addressed
//! the same way `memory::BootInfoFrameAllocator`'s own free-list already does: a plain
//! `phys_mem_offset + physical_address` pointer.
//!
//! **The controller's own MMIO BAR is a real, separate case, explicitly mapped by `map_bar_pages`
//! -- found live, not assumed.** An early version of this driver trusted the same HHDM window for
//! the BAR too, reasoning it would sit "within the first few GiB" like `console::framebuffer`'s
//! own doc comment establishes for Limine's linear framebuffer. **That's wrong for a 64-bit BAR**:
//! a real boot under OVMF (UEFI) placed `qemu-xhci`'s BAR0 at physical `0x800000000` (32 GiB) --
//! real firmware deliberately parks large/64-bit BARs in a high MMIO window specifically so they
//! never compete with the low 32-bit PCI hole, and Limine's HHDM only guarantees covering "at
//! least 4 GiB, plus whatever the memory map itself reports" -- a firmware-placed MMIO hole that
//! far up isn't in the memory map at all. The very first capability-register read through the
//! unmapped HHDM address page-faulted immediately, confirming this empirically rather than by
//! spec-reading alone. Fixed with a real, explicit two-phase mapping: `Xhci::init` first maps
//! exactly one page at the BAR's own physical address (enough to safely read the Capability
//! registers, always under 32 bytes), then -- once `HCSPARAMS1`/`DBOFF`/`RTSOFF` are known --
//! computes the real byte extent this driver actually touches (Operational registers through the
//! last root port's `PORTSC`, the Doorbell array through the highest enabled slot, Runtime
//! registers through Interrupter 0's own register block) and maps however many pages that needs.
//! Mapped `NO_CACHE` (true MMIO, unlike the DMA buffers above) via the same `Mapper::map_to`
//! primitive `module::map_region` already uses for module code pages -- this is genuinely the
//! second real use of that primitive in this codebase, not a new pattern.

use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::cpu::tsc;
use crate::serial_println;

/// One 4 KiB page's worth of 16-byte TRBs.
const TRBS_PER_PAGE: usize = 4096 / 16;
/// The last slot in a `TrbRing`'s page is always a real Link TRB, not usable for real content --
/// see `TrbRing`'s own doc comment for the producer/consumer cycle-bit mechanics this exists for.
const LINK_SLOT: usize = TRBS_PER_PAGE - 1;

const COMPLETION_SUCCESS: u8 = 1;
const COMPLETION_SHORT_PACKET: u8 = 13;

mod trb_type {
    pub const NORMAL: u8 = 1;
    pub const SETUP_STAGE: u8 = 2;
    pub const DATA_STAGE: u8 = 3;
    pub const STATUS_STAGE: u8 = 4;
    pub const LINK: u8 = 6;
    pub const ENABLE_SLOT_CMD: u8 = 9;
    pub const ADDRESS_DEVICE_CMD: u8 = 11;
    pub const CONFIGURE_ENDPOINT_CMD: u8 = 12;
    pub const EVALUATE_CONTEXT_CMD: u8 = 13;
    pub const TRANSFER_EVENT: u8 = 32;
    pub const COMMAND_COMPLETION_EVENT: u8 = 33;
}

#[inline]
fn read32(addr: VirtAddr) -> u32 {
    unsafe { core::ptr::read_volatile(addr.as_ptr::<u32>()) }
}

#[inline]
fn write32(addr: VirtAddr, val: u32) {
    unsafe { core::ptr::write_volatile(addr.as_mut_ptr::<u32>(), val) }
}

#[inline]
fn write64(addr: VirtAddr, val: u64) {
    unsafe {
        core::ptr::write_volatile(addr.as_mut_ptr::<u32>(), val as u32);
        core::ptr::write_volatile(addr.as_mut_ptr::<u32>().add(1), (val >> 32) as u32);
    }
}

/// Allocates one fresh, zeroed physical frame and returns both its kernel-virtual (via the HHDM
/// offset) and physical address -- the one allocation primitive every DMA-visible structure this
/// driver and `hid_keyboard` use goes through.
pub(crate) fn alloc_zeroed_page(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Option<(VirtAddr, PhysAddr)> {
    let phys = frame_allocator.allocate_frame()?.start_address();
    let virt = phys_mem_offset + phys.as_u64();
    unsafe { core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0u8, 4096) };
    Some((virt, phys))
}

/// Maps `page_count` pages of real, existing MMIO, `virt_base`/`phys_base` (both already page-
/// aligned) onward -- the explicit BAR-mapping primitive `Xhci::init` needs; see this module's own
/// doc comment for why the HHDM alone can't be trusted for this. `NO_CACHE` since this is genuine
/// device-register space, not RAM. Tolerates a page that's already mapped (harmless -- this
/// function is called twice during `init`, with the second call's range overlapping the first
/// call's single page); any other mapping failure is logged and left unmapped, so a subsequent
/// real access to it page-faults visibly rather than silently reading garbage.
fn map_bar_pages(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    virt_base: VirtAddr,
    phys_base: PhysAddr,
    page_count: u64,
) {
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
    for i in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(virt_base + i * 4096);
        let frame = PhysFrame::<Size4KiB>::containing_address(phys_base + i * 4096);
        // SAFETY: `frame` is the controller's own real MMIO BAR range (never RAM this kernel
        // hands out for anything else), and `page` is that same range's own dedicated HHDM-offset
        // virtual address -- mapping it there can't alias any other live mapping.
        match unsafe { mapper.map_to(page, frame, flags, frame_allocator) } {
            Ok(flush) => flush.ignore(), // never-before-mapped MMIO page -- no stale TLB entry.
            Err(MapToError::PageAlreadyMapped(_)) => {}
            Err(e) => {
                serial_println!("[usb] failed to map MMIO page {}: {:?}", i, e);
            }
        }
    }
}

/// One raw 16-byte TRB (Transfer Request Block), the one data unit every xHCI ring (command,
/// event, and per-endpoint transfer rings) is built from. See xHCI spec section 4.11 for the
/// field layout this decodes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RawTrb(pub [u32; 4]);

impl RawTrb {
    pub(crate) fn trb_type(&self) -> u8 {
        ((self.0[3] >> 10) & 0x3F) as u8
    }
    pub(crate) fn completion_code(&self) -> u8 {
        ((self.0[2] >> 24) & 0xFF) as u8
    }
    pub(crate) fn slot_id(&self) -> u8 {
        ((self.0[3] >> 24) & 0xFF) as u8
    }
    pub(crate) fn endpoint_id(&self) -> u8 {
        ((self.0[3] >> 16) & 0x1F) as u8
    }
    pub(crate) fn parameter(&self) -> u64 {
        (self.0[0] as u64) | ((self.0[1] as u64) << 32)
    }
    pub(crate) fn is_transfer_event(&self) -> bool {
        self.trb_type() == trb_type::TRANSFER_EVENT
    }
    pub(crate) fn is_success(&self) -> bool {
        matches!(
            self.completion_code(),
            COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET
        )
    }
}

/// A real producer ring (Command Ring, or any endpoint's Transfer Ring) -- one page, 255 usable
/// slots plus a real Link TRB closing the loop back to slot 0.
///
/// **Cycle-bit mechanics** (xHCI spec 4.9.2/4.11.5.1): the ring starts fully zeroed (every slot's
/// Cycle bit is 0). Software's Producer Cycle State (PCS) starts at `true`; hardware's Consumer
/// Cycle State is initialized to match (via `CRCR`'s own RCS bit for the command ring, or an
/// endpoint context's own DCS bit for a transfer ring) -- so a slot only becomes "owned by
/// hardware" once its Cycle bit is written to equal the *current* PCS. `enqueue` writes every
/// field of a real slot, Cycle bit last (so hardware only ever sees a fully-formed TRB become
/// valid, never a partial one). When the enqueue pointer would land on the Link slot, `enqueue`
/// "produces" the Link TRB for this lap instead (its Cycle bit set to the current PCS, its
/// Toggle-Cycle bit already fixed at ring-init time telling hardware to flip its own Consumer
/// Cycle State once it gets there), flips PCS, and wraps the enqueue index back to 0 -- so the
/// *next* real TRB written lands at slot 0 with the new (flipped) PCS, matching hardware's own
/// now-flipped state.
pub(crate) struct TrbRing {
    virt: VirtAddr,
    phys: PhysAddr,
    enqueue_index: usize,
    cycle: bool,
}

impl TrbRing {
    pub(crate) fn new(virt: VirtAddr, phys: PhysAddr) -> Self {
        // Pre-populate the Link TRB's static fields (the page itself was already zeroed by
        // `alloc_zeroed_page`, so nothing else here needs an explicit zero-write). Its Cycle bit
        // (bit 0 of the control word) stays 0 -- not yet "produced" -- until the first lap
        // actually reaches it, at which point `enqueue` sets it.
        let link = virt + (LINK_SLOT * 16) as u64;
        write32(link, phys.as_u64() as u32);
        write32(link + 4, (phys.as_u64() >> 32) as u32);
        write32(link + 8, 0);
        write32(link + 12, ((trb_type::LINK as u32) << 10) | (1 << 1)); // Toggle Cycle bit
        TrbRing {
            virt,
            phys,
            enqueue_index: 0,
            cycle: true,
        }
    }

    /// Writes one real TRB. `control`'s own bit 0 (Cycle) is overwritten with the ring's current
    /// Producer Cycle State -- callers pass every other control bit already set. Returns the
    /// physical address the TRB landed at, for later matching against a completion event's own
    /// TRB pointer.
    pub(crate) fn enqueue(&mut self, dw0: u32, dw1: u32, dw2: u32, control: u32) -> PhysAddr {
        let index = self.enqueue_index;
        let slot = self.virt + (index * 16) as u64;
        let slot_phys = self.phys + (index * 16) as u64;
        write32(slot, dw0);
        write32(slot + 4, dw1);
        write32(slot + 8, dw2);
        write32(slot + 12, (control & !1) | (self.cycle as u32));

        self.enqueue_index += 1;
        if self.enqueue_index == LINK_SLOT {
            let link = self.virt + (LINK_SLOT * 16) as u64;
            let link_control = ((trb_type::LINK as u32) << 10) | (1 << 1) | (self.cycle as u32);
            write32(link + 12, link_control);
            self.cycle = !self.cycle;
            self.enqueue_index = 0;
        }
        slot_phys
    }

    /// The value to place in a Device/Input Context's "TR Dequeue Pointer" field for a ring that
    /// hasn't been given to hardware yet: this ring's own base physical address with the initial
    /// Dequeue Cycle State bit (bit 0) folded in, matching `cycle`'s own starting value (`true`).
    pub(crate) fn initial_dequeue_pointer(&self) -> u64 {
        self.phys.as_u64() | 1
    }
}

/// The single-segment Event Ring hardware reports command/transfer/port-change completions on.
/// Unlike a `TrbRing`, wraparound is implicit at the segment boundary (no Link TRB) -- the
/// Consumer Cycle State just flips every time `dequeue_index` wraps back to 0.
struct EventRing {
    virt: VirtAddr,
    phys: PhysAddr,
    dequeue_index: usize,
    ccs: bool,
    erdp_reg: VirtAddr,
}

impl EventRing {
    fn next(&mut self) -> Option<RawTrb> {
        let slot = self.virt + (self.dequeue_index * 16) as u64;
        let dw3 = read32(slot + 12);
        if (dw3 & 1 != 0) != self.ccs {
            return None; // hardware hasn't produced anything new here yet
        }
        let dw0 = read32(slot);
        let dw1 = read32(slot + 4);
        let dw2 = read32(slot + 8);

        self.dequeue_index += 1;
        if self.dequeue_index == TRBS_PER_PAGE {
            self.dequeue_index = 0;
            self.ccs = !self.ccs;
        }

        // Write back ERDP: pointer to the new dequeue position, plus the Event Handler Busy bit
        // (bit 3, write-1-to-clear) -- harmless to always set since this driver never enables
        // real interrupt signaling (see this module's own doc comment) and so never needs EHB's
        // actual gating behavior, but it's the spec-correct value regardless.
        let new_ptr = (self.phys.as_u64() + (self.dequeue_index * 16) as u64) & !0xF;
        write64(self.erdp_reg, new_ptr | (1 << 3));

        Some(RawTrb([dw0, dw1, dw2, dw3]))
    }
}

/// A real xHCI host controller, brought up and ready to enable/address device slots. Owns the one
/// Command Ring and one Event Ring every operation (regardless of which device slot it targets)
/// shares.
pub struct Xhci {
    op_base: VirtAddr,
    db_base: VirtAddr,
    dcbaa_virt: VirtAddr,
    max_ports: u8,
    cmd_ring: TrbRing,
    event_ring: EventRing,
    /// Kept alive for the controller's lifetime (the scratchpad array itself is read only by
    /// hardware, never by this driver again after setup) -- `None` when `HCSPARAMS2` reported
    /// zero required scratchpad buffers.
    _scratchpad_virt: Option<VirtAddr>,
}

// Operational register offsets (from `op_base`).
const OP_USBCMD: u64 = 0x00;
const OP_USBSTS: u64 = 0x04;
const OP_CRCR: u64 = 0x18;
const OP_DCBAAP: u64 = 0x30;
const OP_CONFIG: u64 = 0x38;
const OP_PORTSC_BASE: u64 = 0x400;
const OP_PORTSC_STRIDE: u64 = 0x10;

const USBCMD_RS: u32 = 1 << 0;
const USBCMD_HCRST: u32 = 1 << 1;
const USBSTS_HCH: u32 = 1 << 0;
const USBSTS_CNR: u32 = 1 << 11;

const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_PED: u32 = 1 << 1;
const PORTSC_PR: u32 = 1 << 4;
const PORTSC_PP: u32 = 1 << 9;
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_SPEED_MASK: u32 = 0xF;
/// Every Read/Write-1-to-Clear status bit in `PORTSC` -- a write to this register must clear all
/// of these to 0 (leaving whichever ones it actually means to acknowledge set to 1) or it'll
/// spuriously ack change bits the caller never looked at.
const PORTSC_RW1C_MASK: u32 =
    (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);

fn portsc_preserve(current: u32, set: u32) -> u32 {
    (current & !PORTSC_RW1C_MASK) | set
}

impl Xhci {
    /// Finds the first xHCI controller via PCI (class `0x0C`, subclass `0x03`, prog-if `0x30`),
    /// resets and brings it up (including the real BIOS-to-OS ownership handoff -- see
    /// `handoff_from_bios`), and returns a ready-to-use handle. `None` on any failure or absence,
    /// always logged -- never fatal to boot, same precedent `net::rtl8139::init` already
    /// established for "no supported hardware found."
    pub(crate) fn init(
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
        mapper: &mut impl Mapper<Size4KiB>,
        phys_mem_offset: VirtAddr,
    ) -> Option<Self> {
        let candidate = crate::drivers::pci::find_by_class(0x0C, 0x03)?;
        if candidate.prog_if != 0x30 {
            serial_println!(
                "[usb] found a USB controller ({:02x}:{:02x}.{}) that isn't xHCI (prog-if {:#04x}) -- skipping",
                candidate.bus,
                candidate.device,
                candidate.function,
                candidate.prog_if
            );
            return None;
        }
        let bar0 = candidate.mem_bar(0)?;
        candidate.enable_bus_mastering();
        let cap_base = phys_mem_offset + bar0;
        let bar0_phys = PhysAddr::new(bar0);

        // Phase 1: map just enough to safely read the Capability registers themselves (always
        // under 32 bytes) -- see this module's own doc comment for why the HHDM can't be trusted
        // here at all, real BAR placement included.
        map_bar_pages(mapper, frame_allocator, cap_base, bar0_phys, 1);

        let caplength = unsafe { core::ptr::read_volatile(cap_base.as_ptr::<u8>()) };
        let hcsparams1 = read32(cap_base + 0x04);
        let hcsparams2 = read32(cap_base + 0x08);
        let hccparams1 = read32(cap_base + 0x10);
        let dboff = read32(cap_base + 0x14);
        let rtsoff = read32(cap_base + 0x18);

        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        let context_size_64 = hccparams1 & (1 << 2) != 0;
        if context_size_64 {
            serial_println!(
                "[usb] xHCI controller reports 64-byte device contexts (CSZ=1) -- unsupported by \
                 this driver, skipping USB entirely this boot"
            );
            return None;
        }

        let op_base = cap_base + caplength as u64;
        let db_base = cap_base + (dboff & !0x3) as u64;
        let rt_base = cap_base + (rtsoff & !0x1F) as u64;

        // Phase 2: now that HCSPARAMS1/DBOFF/RTSOFF are known, map every page this driver could
        // actually touch -- Operational registers through the last root port's own PORTSC,
        // the Doorbell array through the highest slot CONFIG enables below, Runtime registers
        // through Interrupter 0's own 32-byte block (the only interrupter this driver ever uses).
        let op_extent = caplength as u64 + OP_PORTSC_BASE + (max_ports as u64) * OP_PORTSC_STRIDE;
        let db_extent = (dboff & !0x3) as u64 + (max_slots as u64 + 1) * 4;
        let rt_extent = (rtsoff & !0x1F) as u64 + 0x20 + 0x20;
        let needed_pages = op_extent
            .max(db_extent)
            .max(rt_extent)
            .div_ceil(4096)
            .max(1);
        map_bar_pages(mapper, frame_allocator, cap_base, bar0_phys, needed_pages);

        serial_println!(
            "[usb] xHCI controller found at {:02x}:{:02x}.{} (BAR0 {:#x}, {} slots, {} ports)",
            candidate.bus,
            candidate.device,
            candidate.function,
            bar0,
            max_slots,
            max_ports
        );

        handoff_from_bios(cap_base, hccparams1);
        halt_controller(op_base);
        reset_controller(op_base)?;

        // Enable every slot the controller offers -- this driver only ever addresses one, but
        // there's no real cost to enabling more, and it avoids a second magic constant to keep in
        // sync with `max_slots`.
        write32(op_base + OP_CONFIG, max_slots as u32);

        // Real controllers commonly require at least one scratchpad buffer even with zero devices
        // attached (xHCI spec 4.20) -- HCSPARAMS2's Max Scratchpad Buffers field, a 10-bit value
        // split across two non-contiguous ranges.
        let max_scratchpad = (((hcsparams2 >> 21) & 0x1F) << 5) | ((hcsparams2 >> 27) & 0x1F);

        let (dcbaa_virt, dcbaa_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;

        let scratchpad_virt = if max_scratchpad > 0 {
            let (array_virt, array_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
            for i in 0..max_scratchpad {
                let (_, buf_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
                write64(array_virt + (i as u64) * 8, buf_phys.as_u64());
            }
            // DCBAA entry 0 is reserved specifically for the scratchpad buffer array pointer --
            // slot IDs themselves start at 1.
            write64(dcbaa_virt, array_phys.as_u64());
            Some(array_virt)
        } else {
            None
        };

        write64(op_base + OP_DCBAAP, dcbaa_phys.as_u64());

        let (cmd_virt, cmd_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
        let cmd_ring = TrbRing::new(cmd_virt, cmd_phys);
        write64(op_base + OP_CRCR, cmd_ring.initial_dequeue_pointer());

        let (evt_virt, evt_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
        let (erst_virt, erst_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
        write64(erst_virt, evt_phys.as_u64());
        write32(erst_virt + 8, TRBS_PER_PAGE as u32);

        let intr0 = rt_base + 0x20;
        write32(intr0 + 0x08, 1); // ERSTSZ: one segment
        let erdp_reg = intr0 + 0x18;
        write64(erdp_reg, evt_phys.as_u64());
        write64(intr0 + 0x10, erst_phys.as_u64()); // ERSTBA

        let event_ring = EventRing {
            virt: evt_virt,
            phys: evt_phys,
            dequeue_index: 0,
            ccs: true,
            erdp_reg,
        };

        // Run/Stop -- interrupt signaling (IMAN.IE / USBCMD.INTE) deliberately left disabled; see
        // this module's own doc comment.
        write32(op_base + OP_USBCMD, USBCMD_RS);
        let deadline = tsc::now() + tsc::ms_to_cycles(50);
        while read32(op_base + OP_USBSTS) & USBSTS_HCH != 0 {
            if tsc::now() > deadline {
                serial_println!(
                    "[usb] xHCI controller never left HCHalted after Run/Stop -- giving up"
                );
                return None;
            }
            core::hint::spin_loop();
        }

        serial_println!("[usb] xHCI controller running");

        Some(Xhci {
            op_base,
            db_base,
            dcbaa_virt,
            max_ports,
            cmd_ring,
            event_ring,
            _scratchpad_virt: scratchpad_virt,
        })
    }

    pub(crate) fn max_ports(&self) -> u8 {
        self.max_ports
    }

    fn portsc_addr(&self, port: u8) -> VirtAddr {
        self.op_base + OP_PORTSC_BASE + (port as u64 - 1) * OP_PORTSC_STRIDE
    }

    /// Powers on and resets root port `port` (1-based) if a device is connected. Returns the raw
    /// Port Speed ID (xHCI spec Table 5-12: 1=Full, 2=Low, 3=High, 4=SuperSpeed, ...) on success.
    pub(crate) fn reset_port(&self, port: u8) -> Option<u8> {
        let addr = self.portsc_addr(port);

        let current = read32(addr);
        if current & PORTSC_PP == 0 {
            write32(addr, portsc_preserve(current, PORTSC_PP));
            // Spec-mandated settle time after powering a port on before a device will assert
            // connect status.
            let deadline = tsc::now() + tsc::ms_to_cycles(20);
            while tsc::now() < deadline {
                core::hint::spin_loop();
            }
        }

        let current = read32(addr);
        if current & PORTSC_CCS == 0 {
            return None; // nothing plugged in here
        }

        // Ack any stale connect-status-change bit from power-up, then issue a real port reset.
        write32(addr, portsc_preserve(current, 1 << 17));
        let current = read32(addr);
        write32(addr, portsc_preserve(current, PORTSC_PR));

        let deadline = tsc::now() + tsc::ms_to_cycles(500);
        loop {
            let status = read32(addr);
            if status & (1 << 21) != 0 {
                // Port Reset Change -- reset completed (successfully or not).
                write32(addr, portsc_preserve(status, (1 << 21) | (1 << 17)));
                break;
            }
            if tsc::now() > deadline {
                serial_println!("[usb] port {}: reset never completed -- giving up", port);
                return None;
            }
            core::hint::spin_loop();
        }

        let status = read32(addr);
        if status & PORTSC_PED == 0 {
            serial_println!(
                "[usb] port {}: reset completed but port never enabled",
                port
            );
            return None;
        }

        let speed = ((status >> PORTSC_SPEED_SHIFT) & PORTSC_SPEED_MASK) as u8;
        Some(speed)
    }

    fn ring_doorbell(&self, slot_id: u8, target: u8) {
        let addr = self.db_base + (slot_id as u64) * 4;
        write32(addr, target as u32);
    }

    pub(crate) fn set_dcbaa_entry(&mut self, slot_id: u8, output_ctx_phys: PhysAddr) {
        write64(
            self.dcbaa_virt + (slot_id as u64) * 8,
            output_ctx_phys.as_u64(),
        );
    }

    fn wait_for_command_completion(&mut self, cmd_trb_phys: PhysAddr) -> Option<RawTrb> {
        let deadline = tsc::now() + tsc::ms_to_cycles(500);
        loop {
            if let Some(evt) = self.event_ring.next()
                && evt.trb_type() == trb_type::COMMAND_COMPLETION_EVENT
                && evt.parameter() & !0xF == cmd_trb_phys.as_u64() & !0xF
            {
                return Some(evt);
            }
            if tsc::now() > deadline {
                return None;
            }
            core::hint::spin_loop();
        }
    }

    fn wait_for_transfer_event(&mut self, slot_id: u8, ep_dci: u8) -> Option<RawTrb> {
        let deadline = tsc::now() + tsc::ms_to_cycles(500);
        loop {
            if let Some(evt) = self.event_ring.next()
                && evt.is_transfer_event()
                && evt.slot_id() == slot_id
                && evt.endpoint_id() == ep_dci
            {
                return Some(evt);
            }
            if tsc::now() > deadline {
                return None;
            }
            core::hint::spin_loop();
        }
    }

    pub(crate) fn enable_slot(&mut self) -> Option<u8> {
        let control = (trb_type::ENABLE_SLOT_CMD as u32) << 10;
        let trb_phys = self.cmd_ring.enqueue(0, 0, 0, control);
        self.ring_doorbell(0, 0);
        let evt = self.wait_for_command_completion(trb_phys)?;
        (evt.completion_code() == COMPLETION_SUCCESS).then(|| evt.slot_id())
    }

    pub(crate) fn address_device(&mut self, slot_id: u8, input_ctx_phys: PhysAddr) -> bool {
        let control = ((trb_type::ADDRESS_DEVICE_CMD as u32) << 10) | ((slot_id as u32) << 24);
        let param = input_ctx_phys.as_u64();
        let trb_phys = self
            .cmd_ring
            .enqueue(param as u32, (param >> 32) as u32, 0, control);
        self.ring_doorbell(0, 0);
        self.wait_for_command_completion(trb_phys)
            .is_some_and(|e| e.completion_code() == COMPLETION_SUCCESS)
    }

    pub(crate) fn evaluate_context(&mut self, slot_id: u8, input_ctx_phys: PhysAddr) -> bool {
        let control = ((trb_type::EVALUATE_CONTEXT_CMD as u32) << 10) | ((slot_id as u32) << 24);
        let param = input_ctx_phys.as_u64();
        let trb_phys = self
            .cmd_ring
            .enqueue(param as u32, (param >> 32) as u32, 0, control);
        self.ring_doorbell(0, 0);
        self.wait_for_command_completion(trb_phys)
            .is_some_and(|e| e.completion_code() == COMPLETION_SUCCESS)
    }

    pub(crate) fn configure_endpoint(&mut self, slot_id: u8, input_ctx_phys: PhysAddr) -> bool {
        let control = ((trb_type::CONFIGURE_ENDPOINT_CMD as u32) << 10) | ((slot_id as u32) << 24);
        let param = input_ctx_phys.as_u64();
        let trb_phys = self
            .cmd_ring
            .enqueue(param as u32, (param >> 32) as u32, 0, control);
        self.ring_doorbell(0, 0);
        self.wait_for_command_completion(trb_phys)
            .is_some_and(|e| e.completion_code() == COMPLETION_SUCCESS)
    }

    /// Rings the doorbell for endpoint `ep_dci` on `slot_id` (Device Context Index -- `1` for the
    /// default control endpoint, `epnum*2 + dir` for any other, `dir`: 0=OUT/1=IN).
    pub(crate) fn ring_endpoint_doorbell(&self, slot_id: u8, ep_dci: u8) {
        self.ring_doorbell(slot_id, ep_dci);
    }

    /// A synchronous control transfer over `ep0_ring`: Setup stage, an optional IN data stage,
    /// and a Status stage in the opposite direction -- the standard 3-stage USB control-transfer
    /// shape (USB 2.0 spec 9.4). Returns `Some(bytes actually available)` on success -- this
    /// driver never issues an OUT-with-data control transfer (every real request it makes is
    /// either a `GET_DESCRIPTOR`-style IN or a zero-length class/standard request), so that
    /// direction isn't implemented.
    #[allow(clippy::too_many_arguments)] // real xHCI control-transfer shape, not arbitrary
    pub(crate) fn control_transfer_in(
        &mut self,
        ep0_ring: &mut TrbRing,
        slot_id: u8,
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        data: Option<(PhysAddr, u16)>,
    ) -> Option<usize> {
        let w_length = data.map(|(_, len)| len).unwrap_or(0);
        let setup_param = (bm_request_type as u64)
            | ((b_request as u64) << 8)
            | ((w_value as u64) << 16)
            | ((w_index as u64) << 32)
            | ((w_length as u64) << 48);
        let trt: u32 = if data.is_some() { 3 } else { 0 }; // 3 = IN data stage, 0 = no data
        let setup_control =
            ((trb_type::SETUP_STAGE as u32) << 10) | (1 << 6/* IDT */) | (trt << 16);
        ep0_ring.enqueue(
            setup_param as u32,
            (setup_param >> 32) as u32,
            8,
            setup_control,
        );

        if let Some((buf_phys, len)) = data {
            let data_control =
                ((trb_type::DATA_STAGE as u32) << 10) | (1 << 16/* DIR=IN */) | (1 << 5/* IOC */);
            ep0_ring.enqueue(
                buf_phys.as_u64() as u32,
                (buf_phys.as_u64() >> 32) as u32,
                len as u32,
                data_control,
            );
        }

        // Status stage direction is the opposite of the data stage's; a no-data request's status
        // stage is always IN, by USB convention.
        let status_dir_in = data.is_none();
        let status_control = ((trb_type::STATUS_STAGE as u32) << 10)
            | if status_dir_in { 1 << 16 } else { 0 }
            | (1 << 5/* IOC */);
        ep0_ring.enqueue(0, 0, 0, status_control);

        self.ring_endpoint_doorbell(slot_id, 1);

        let evt = self.wait_for_transfer_event(slot_id, 1)?;
        evt.is_success().then_some(w_length as usize)
    }

    /// Drains one event, if any, from the shared Event Ring -- the primitive `usb::hid_keyboard`'s
    /// steady-state `poll()` builds on to notice completed interrupt-IN transfers. Also used
    /// internally by every synchronous `wait_for_*` helper above (a stray event unrelated to
    /// whatever a synchronous call is waiting for is simply dropped -- safe because this driver
    /// never has more than one logical operation in flight at once).
    pub(crate) fn poll_event(&mut self) -> Option<RawTrb> {
        self.event_ring.next()
    }
}

/// Stops the controller if it's currently running (`USBSTS.HCH == 0`), bounded -- a controller
/// left running by firmware (or a prior boot's own bring-up, on a warm reset) can't have `CRCR`/
/// `DCBAAP` written until it's genuinely halted.
fn halt_controller(op_base: VirtAddr) {
    if read32(op_base + OP_USBSTS) & USBSTS_HCH != 0 {
        return; // already halted
    }
    write32(
        op_base + OP_USBCMD,
        read32(op_base + OP_USBCMD) & !USBCMD_RS,
    );
    let deadline = tsc::now() + tsc::ms_to_cycles(50);
    while read32(op_base + OP_USBSTS) & USBSTS_HCH == 0 {
        if tsc::now() > deadline {
            serial_println!("[usb] xHCI controller never halted -- proceeding to reset anyway");
            break;
        }
        core::hint::spin_loop();
    }
}

/// A real controller reset (`USBCMD.HCRST`), bounded, then waits for `USBSTS.CNR` (Controller Not
/// Ready) to clear -- real hardware can take a real, if short, amount of time here.
fn reset_controller(op_base: VirtAddr) -> Option<()> {
    write32(op_base + OP_USBCMD, USBCMD_HCRST);
    let deadline = tsc::now() + tsc::ms_to_cycles(1000);
    while read32(op_base + OP_USBCMD) & USBCMD_HCRST != 0 {
        if tsc::now() > deadline {
            serial_println!("[usb] xHCI controller reset never completed -- giving up");
            return None;
        }
        core::hint::spin_loop();
    }
    let deadline = tsc::now() + tsc::ms_to_cycles(1000);
    while read32(op_base + OP_USBSTS) & USBSTS_CNR != 0 {
        if tsc::now() > deadline {
            serial_println!("[usb] xHCI controller stayed Controller-Not-Ready -- giving up");
            return None;
        }
        core::hint::spin_loop();
    }
    Some(())
}

/// Real BIOS/SMM-to-OS ownership handoff via the USB Legacy Support Capability (xHCI spec 7.2.1)
/// -- an *xHCI extended capability*, walked via `HCCPARAMS1.xECP` inside MMIO space, entirely
/// separate from the PCI config-space capability list. Real Intel platforms (this project's
/// actual real-hardware target's own chipset included) can leave the controller owned by
/// firmware/SMM by default; skipping this would silently eat every event on real hardware while
/// looking fine under QEMU, which doesn't implement this capability at all (so this call is
/// expected to log "no capability found" and return immediately under every QEMU boot).
fn handoff_from_bios(cap_base: VirtAddr, hccparams1: u32) {
    let xecp_dwords = (hccparams1 >> 16) & 0xFFFF;
    if xecp_dwords == 0 {
        serial_println!("[usb] no xHCI extended capabilities list -- nothing to hand off");
        return;
    }

    let mut offset = (xecp_dwords as u64) * 4;
    loop {
        let addr = cap_base + offset;
        let header = read32(addr);
        let cap_id = header & 0xFF;
        let next = (header >> 8) & 0xFF;

        const USB_LEGACY_SUPPORT_CAP_ID: u32 = 1;
        if cap_id == USB_LEGACY_SUPPORT_CAP_ID {
            const BIOS_OWNED: u32 = 1 << 16;
            const OS_OWNED: u32 = 1 << 24;
            if header & BIOS_OWNED == 0 {
                serial_println!("[usb] USB Legacy Support capability found -- already OS-owned");
            } else {
                serial_println!(
                    "[usb] USB Legacy Support capability found -- requesting OS ownership"
                );
                write32(addr, header | OS_OWNED);
                let deadline = tsc::now() + tsc::ms_to_cycles(1000);
                loop {
                    let current = read32(addr);
                    if current & BIOS_OWNED == 0 {
                        serial_println!("[usb] BIOS/SMM ownership released");
                        break;
                    }
                    if tsc::now() > deadline {
                        serial_println!(
                            "[usb] BIOS/SMM never released ownership within budget -- \
                             proceeding anyway"
                        );
                        break;
                    }
                    core::hint::spin_loop();
                }
            }
            // Disable every USBLEGCTLSTS SMI-generation enable bit (leaving it a plain 0) so a
            // later real event can't trigger an SMI the OS never expects a response to.
            write32(addr + 4, 0);
            return;
        }

        if next == 0 {
            serial_println!("[usb] no USB Legacy Support capability in the xECP list");
            return;
        }
        offset += (next as u64) * 4;
    }
}

/// 32-byte-context Slot Context fields this driver actually needs to set (xHCI spec 6.2.2). No
/// hub support -- `route_string` is always 0 (every device this driver handles sits directly on a
/// root port).
pub(crate) fn write_slot_context(base: VirtAddr, speed: u8, root_port: u8, context_entries: u8) {
    let dw0 = ((context_entries as u32) << 27) | ((speed as u32) << 20);
    let dw1 = (root_port as u32) << 16;
    write32(base, dw0);
    write32(base + 4, dw1);
    write32(base + 8, 0);
    write32(base + 12, 0);
}

#[derive(Clone, Copy)]
pub(crate) enum EndpointType {
    Control = 4,
    InterruptIn = 7,
}

/// 32-byte-context Endpoint Context fields this driver actually needs to set (xHCI spec 6.2.3).
/// `tr_dequeue` must already have the initial Dequeue Cycle State bit folded into bit 0 (see
/// `TrbRing::initial_dequeue_pointer`).
pub(crate) fn write_endpoint_context(
    base: VirtAddr,
    ep_type: EndpointType,
    max_packet_size: u16,
    interval: u8,
    tr_dequeue: u64,
) {
    let dw1 = ((ep_type as u32) << 3)
        | (3 << 1/* CErr = 3, max retries */)
        | ((max_packet_size as u32) << 16);
    write32(base, (interval as u32) << 16);
    write32(base + 4, dw1);
    write32(base + 8, tr_dequeue as u32);
    write32(base + 12, (tr_dequeue >> 32) as u32);
    write32(base + 16, 8); // Average TRB Length -- advisory; every transfer this driver issues is small.
}

/// Input Control Context (xHCI spec 6.2.5.1) -- `add`/`drop_flags` are bitmasks where bit 0 means
/// the Slot Context (A0/D0) and bit `n` (n=1..=31) means Endpoint Context DCI `n`.
pub(crate) fn write_input_control_context(base: VirtAddr, add: u32, drop_flags: u32) {
    write32(base, drop_flags);
    write32(base + 4, add);
}

/// Device Context Index for endpoint `ep_num` in direction `dir_in` -- `1` for the default
/// control endpoint (always, both directions), `2*ep_num + dir` for anything else.
pub(crate) fn endpoint_dci(ep_num: u8, dir_in: bool) -> u8 {
    2 * ep_num + (dir_in as u8)
}

/// Enqueues one real Normal TRB (a single IN transfer request) onto `ring`, with Interrupt On
/// Completion set -- the shape `hid_keyboard`'s interrupt-IN endpoint polling loop needs, one TRB
/// per report buffer.
pub(crate) fn enqueue_normal_in(ring: &mut TrbRing, buf_phys: PhysAddr, len: u16) -> PhysAddr {
    let control = ((trb_type::NORMAL as u32) << 10) | (1 << 5/* IOC */);
    ring.enqueue(
        buf_phys.as_u64() as u32,
        (buf_phys.as_u64() >> 32) as u32,
        len as u32,
        control,
    )
}
