//! Realtek RTL8139 NIC driver -- the first real network driver in this kernel. I/O-space only
//! (BAR0), classic fixed RX-ring-buffer design (no descriptor rings, unlike e1000/virtio-net).
//! See <https://wiki.osdev.org/RTL8139> for the register map this follows.

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;

use x86_64::instructions::port::Port;
use x86_64::structures::paging::{FrameAllocator, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::nic::{NicDriver, NicError};
use crate::serial_println;

const RTL8139_VENDOR: u16 = 0x10EC;
const RTL8139_DEVICE: u16 = 0x8139;

const REG_MAC: u16 = 0x00; // 6 bytes, IDR0-5
const REG_TSAD: [u16; 4] = [0x20, 0x24, 0x28, 0x2C];
const REG_TSD: [u16; 4] = [0x10, 0x14, 0x18, 0x1C];
const REG_RBSTART: u16 = 0x30;
const REG_CR: u16 = 0x37;
const REG_CAPR: u16 = 0x38;
const REG_IMR: u16 = 0x3C;
const REG_ISR: u16 = 0x3E;
const REG_RCR: u16 = 0x44;
const REG_CONFIG1: u16 = 0x52;

const CR_BUFFER_EMPTY: u8 = 1 << 0;
const CR_TX_ENABLE: u8 = 1 << 2;
const CR_RX_ENABLE: u8 = 1 << 3;
const CR_RESET: u8 = 1 << 4;

const ISR_ROK: u16 = 1 << 0;
const ISR_TOK: u16 = 1 << 2;

const RCR_ACCEPT_ALL: u32 = 1 << 0;
const RCR_ACCEPT_PHYS_MATCH: u32 = 1 << 1;
const RCR_ACCEPT_MULTICAST: u32 = 1 << 2;
const RCR_ACCEPT_BROADCAST: u32 = 1 << 3;
const RCR_WRAP: u32 = 1 << 7;

/// Wrap point for the RX read cursor -- the ring "proper", per the datasheet. Distinct from
/// `RX_RING_FRAMES`'s larger allocation, which exists only to satisfy `RCR_WRAP`'s padding
/// requirement (see its own doc comment below); offsets are never allowed to reach this value.
const RX_RING_SIZE: u32 = 8192;
/// `RX_RING_SIZE` (8192) + the recommended 16-byte pad + up to ~1500 bytes `RCR_WRAP` may write
/// past the nominal end for a packet straddling the boundary, rounded up to whole 4 KiB frames.
const RX_RING_FRAMES: usize = 3;

const NUM_TX_SLOTS: usize = 4;
const TX_SLOT_LEN: usize = 4096;
const ETHERNET_MIN_FRAME: usize = 60;
/// Real upper bound on any legitimate RX frame this hardware can report: standard Ethernet MTU
/// (1500) + 14-byte header + a 4-byte 802.1Q tag, rounded up. `poll_recv`'s `length` header field
/// comes straight from the NIC and is otherwise trusted as-is to size an allocation and a
/// `copy_nonoverlapping` read out of the RX ring -- since the HHDM maps all of physical memory, an
/// oversized value doesn't page-fault, it silently reads unrelated physical memory (a real
/// memory-disclosure/corruption bug, triggerable by a corrupted or adversarial inbound frame).
const ETHERNET_MAX_FRAME: usize = 1522;

/// Set by `probe_and_init` once the driver's I/O base is known, read by `rtl8139_irq_handler` --
/// a plain global rather than routing the IRQ handler through the `nic::NIC` mutex, since a
/// registered `fn()` handler can't capture driver state and locking the shared NIC mutex from
/// interrupt context would risk deadlocking against a longer-held lock elsewhere.
static IO_BASE: AtomicU16 = AtomicU16::new(0);
/// Set by the IRQ handler, cleared by `irq_fired`. Callers use this to avoid polling the ring on
/// every loop iteration; it carries no data itself -- `Rtl8139::poll_recv` still does the real
/// work of draining the ring, out of interrupt context.
static RX_IRQ_FIRED: AtomicBool = AtomicBool::new(false);

/// True if an RX or TX-complete interrupt has fired since the last call. Clears the flag.
pub fn irq_fired() -> bool {
    RX_IRQ_FIRED.swap(false, Ordering::Relaxed)
}

/// Registered via `interrupts::register_irq_handler`. Deliberately does no heap allocation and
/// doesn't lock `nic::NIC` -- just acks the hardware cause and sets a flag; the real ring-reading
/// work happens later, out of interrupt context, in `Rtl8139::poll_recv`.
fn rtl8139_irq_handler() {
    let io_base = IO_BASE.load(Ordering::Relaxed);
    if io_base == 0 {
        return;
    }
    let isr: u16;
    unsafe {
        isr = Port::<u16>::new(io_base + REG_ISR).read();
        // Write-1-to-clear, and must happen before this handler returns: EOI to the PIC only
        // tells the *controller* the CPU is ready for another interrupt, it doesn't touch the
        // NIC's own cause bits -- leaving them set means the NIC re-fires the same cause
        // immediately once EOI reopens the line, an interrupt storm.
        Port::<u16>::new(io_base + REG_ISR).write(isr);
    }
    // Real, externally-triggered timing jitter (a network frame's arrival, at whatever exact
    // cycle count it happened to land) -- feeds `src/random.rs`'s persistent entropy pool. No
    // heap allocation, matching this handler's own existing constraint.
    crate::random::mix_entropy(isr as u64);
    RX_IRQ_FIRED.store(true, Ordering::Relaxed);
}

pub struct Rtl8139 {
    io_base: u16,
    mac: [u8; 6],
    rx_ring_virt: VirtAddr,
    rx_read_offset: u16,
    tx_slots: [(VirtAddr, PhysAddr); NUM_TX_SLOTS],
    next_tx_slot: usize,
}

/// Allocates `count` frames and returns their base physical address, if they turned out to be
/// physically contiguous. `BootInfoFrameAllocator` is a bump allocator with no contiguity
/// guarantee across separate calls (see its own doc comment in `src/memory.rs`) -- in practice,
/// under QEMU's single large usable region, a short run like this is contiguous, but this checks
/// rather than assumes.
fn allocate_contiguous_frames(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    count: usize,
) -> Option<PhysAddr> {
    let first = frame_allocator.allocate_frame()?;
    let mut expected = first.start_address().as_u64() + 4096;
    for _ in 1..count {
        let frame = frame_allocator.allocate_frame()?;
        if frame.start_address().as_u64() != expected {
            serial_println!(
                "[net] rtl8139: RX ring allocation wasn't physically contiguous -- giving up"
            );
            return None;
        }
        expected += 4096;
    }
    Some(first.start_address())
}

/// Probes for an rtl8139 via PCI and, if found, brings it up: bus mastering, soft reset, RX ring
/// + TX buffers, and IRQ registration.
///
/// Returns `None` (logged, not fatal) if no such device is present or bring-up fails at any
/// step -- a boot without a NIC, or without one this driver supports, must still succeed.
fn probe_and_init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Option<Rtl8139> {
    let candidate = crate::drivers::pci::find_by_class(0x02, 0x00)?;
    if candidate.vendor_id != RTL8139_VENDOR || candidate.device_id != RTL8139_DEVICE {
        serial_println!(
            "[net] found a class-0x02 device ({:#06x}:{:#06x}) that isn't an rtl8139 -- skipping",
            candidate.vendor_id,
            candidate.device_id
        );
        return None;
    }
    let io_base = candidate.io_bar(0)?;
    candidate.enable_bus_mastering();

    serial_println!(
        "[net] rtl8139 found at {:02x}:{:02x}.{} (I/O base {:#06x}, IRQ line {})",
        candidate.bus,
        candidate.device,
        candidate.function,
        io_base,
        candidate.interrupt_line
    );

    unsafe {
        // Wake the device (some emulated/real parts power down unused registers otherwise).
        Port::<u8>::new(io_base + REG_CONFIG1).write(0x00);

        let mut cr: Port<u8> = Port::new(io_base + REG_CR);
        cr.write(CR_RESET);
        // Bounded poll, not a real timing budget -- real/emulated hardware clears RST in
        // microseconds; this bound only guards against a misbehaving or absent device.
        let mut attempts = 0u32;
        while cr.read() & CR_RESET != 0 {
            attempts += 1;
            if attempts > 1_000_000 {
                serial_println!("[net] rtl8139: soft reset never completed -- giving up");
                return None;
            }
        }
    }

    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = unsafe { Port::<u8>::new(io_base + REG_MAC + i as u16).read() };
    }
    serial_println!(
        "[net] rtl8139 MAC address {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    let rx_ring_phys = allocate_contiguous_frames(frame_allocator, RX_RING_FRAMES)?;
    let rx_ring_virt = phys_mem_offset + rx_ring_phys.as_u64();

    let mut tx_slots = [(VirtAddr::zero(), PhysAddr::zero()); NUM_TX_SLOTS];
    for slot in tx_slots.iter_mut() {
        let phys = frame_allocator.allocate_frame()?.start_address();
        *slot = (phys_mem_offset + phys.as_u64(), phys);
    }

    unsafe {
        Port::<u32>::new(io_base + REG_RBSTART).write(rx_ring_phys.as_u64() as u32);

        // WRAP (bit 7): lets the card write a packet that logically wraps past the ring's
        // nominal end in one contiguous write, so `poll_recv` never has to reassemble a frame
        // split across the buffer boundary -- at the cost of needing up to ~1500 extra bytes of
        // padding past the nominal 8192+16 ring, which is why RX_RING_FRAMES allocates 12 KiB,
        // not 8 KiB.
        Port::<u32>::new(io_base + REG_RCR).write(
            RCR_ACCEPT_ALL
                | RCR_ACCEPT_PHYS_MATCH
                | RCR_ACCEPT_MULTICAST
                | RCR_ACCEPT_BROADCAST
                | RCR_WRAP,
        );

        Port::<u16>::new(io_base + REG_IMR).write(ISR_ROK | ISR_TOK);
        Port::<u8>::new(io_base + REG_CR).write(CR_RX_ENABLE | CR_TX_ENABLE);
    }

    IO_BASE.store(io_base, Ordering::Relaxed);
    RX_IRQ_FIRED.store(false, Ordering::Relaxed);

    x86_64::instructions::interrupts::without_interrupts(|| {
        crate::cpu::interrupts::register_irq_handler(candidate.interrupt_line, rtl8139_irq_handler);
        unsafe {
            crate::cpu::pic::unmask_irq(candidate.interrupt_line);
        }
    });

    Some(Rtl8139 {
        io_base,
        mac,
        rx_ring_virt,
        rx_read_offset: 0,
        tx_slots,
        next_tx_slot: 0,
    })
}

/// Probes for and initializes the first rtl8139 found via PCI, installing it as the kernel's
/// active NIC (`net::nic::NIC`) if successful. Not fatal either way -- a boot with no such
/// device, or one whose bring-up fails, just continues without networking; logged either way.
pub fn init(frame_allocator: &mut impl FrameAllocator<Size4KiB>, phys_mem_offset: VirtAddr) {
    match probe_and_init(frame_allocator, phys_mem_offset) {
        Some(driver) => {
            *super::nic::NIC.lock() = Some(Box::new(driver));
            serial_println!("[net] rtl8139 driver installed");
        }
        None => {
            serial_println!("[net] no supported NIC found -- networking unavailable this boot");
        }
    }
}

impl NicDriver for Rtl8139 {
    fn send(&mut self, frame: &[u8]) -> Result<(), NicError> {
        if frame.len() > TX_SLOT_LEN {
            return Err(NicError::NoTxSlotAvailable);
        }

        let slot = self.next_tx_slot;
        self.next_tx_slot = (self.next_tx_slot + 1) % NUM_TX_SLOTS;
        let (virt, phys) = self.tx_slots[slot];
        let len = frame.len().max(ETHERNET_MIN_FRAME);

        unsafe {
            let dst = virt.as_mut_ptr::<u8>();
            core::ptr::write_bytes(dst, 0, len);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), dst, frame.len());

            Port::<u32>::new(self.io_base + REG_TSAD[slot]).write(phys.as_u64() as u32);
            // Writing TSD both sets the descriptor's length (bits 0-12) and triggers
            // transmission -- must be the last register write for this slot.
            Port::<u32>::new(self.io_base + REG_TSD[slot]).write(len as u32);
        }
        Ok(())
    }

    fn poll_recv(&mut self) -> Option<Vec<u8>> {
        // Loops past a dropped bad frame rather than returning `None` for it -- `None` here means
        // specifically "ring empty," which `net::poll()`'s own drain loop relies on to know
        // whether more frames are still queued behind the one it just got back.
        loop {
            unsafe {
                if Port::<u8>::new(self.io_base + REG_CR).read() & CR_BUFFER_EMPTY != 0 {
                    return None;
                }
            }

            // Each queued packet starts with a 4-byte header: 2 bytes status, 2 bytes length (the
            // received frame's length *including* its trailing 4-byte CRC, but not counting this
            // header itself).
            let header_ptr = (self.rx_ring_virt + self.rx_read_offset as u64).as_ptr::<u16>();
            let status = unsafe { header_ptr.read_volatile() };
            let length = unsafe { header_ptr.add(1).read_volatile() };

            let data_len = (length as usize).saturating_sub(4); // drop the trailing CRC
            let bad_length = length < 4 || data_len > ETHERNET_MAX_FRAME;
            // Reject a bad `status` or an out-of-range `length` before either drives an OOB
            // read/allocation -- previously the ISR_ROK check was decorative (logged, but still
            // read and returned the untrusted payload) and `length` was trusted up to the full
            // u16 range.
            let frame = if status & ISR_ROK == 0 {
                serial_println!(
                    "[net] rtl8139: dropping RX error frame, status {:#06x}",
                    status
                );
                None
            } else if bad_length {
                serial_println!(
                    "[net] rtl8139: dropping RX frame with bad length {}",
                    length
                );
                None
            } else {
                let data_offset = self.rx_read_offset as u64 + 4;
                let mut frame = alloc::vec![0u8; data_len];
                let data_ptr = (self.rx_ring_virt + data_offset).as_ptr::<u8>();
                unsafe {
                    core::ptr::copy_nonoverlapping(data_ptr, frame.as_mut_ptr(), data_len);
                }
                Some(frame)
            };

            // Advance past this packet's header + payload + CRC, rounded up to the 4-byte
            // boundary the card always starts the next packet on, then wrap within the
            // 8192-byte ring proper (the extra WRAP padding past that is never a valid
            // packet-start offset). A `length` too large to be a real frame is equally
            // untrustworthy here -- clamp the step to one frame's worth so a single corrupted
            // header can't push `rx_read_offset`/CAPR arbitrarily far out of sync with the
            // card's own write pointer.
            let advance_len = if bad_length {
                ETHERNET_MAX_FRAME as u32 + 4
            } else {
                length as u32
            };
            let next = (self.rx_read_offset as u32 + advance_len + 4 + 3) & !3;
            self.rx_read_offset = if next >= RX_RING_SIZE {
                (next - RX_RING_SIZE) as u16
            } else {
                next as u16
            };

            unsafe {
                // Hardware quirk: CAPR must be programmed 16 bytes *before* the actual next-read
                // offset, not the offset itself -- see the RTL8139 datasheet / OSDev wiki. Relies
                // on u16 wraparound when `rx_read_offset < 16`, matching what real drivers get
                // from the equivalent unsigned-underflow-then-truncate in C.
                Port::<u16>::new(self.io_base + REG_CAPR)
                    .write(self.rx_read_offset.wrapping_sub(16));
            }

            if frame.is_some() {
                return frame;
            }
        }
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }
}
