//! virtio-blk: a virtio block device (virtio 1.2 specification §5.2) as the data disk
//! (`drivers::disk`). The default under QEMU (`scripts/qemu_common.sh`), because unlike IDE PIO no
//! data passes through I/O ports: the device reads and writes a DMA buffer directly.
//!
//! One request at a time through queue 0: a chain of the request header (device-readable), the
//! data (through a bounce buffer, `BUFFER_BLOCKS` at a time), and the status byte
//! (device-writable). Completion is interrupt-driven with a polling fallback
//! (`dma::wait_until`): the PCI interrupt line's handler acknowledges the ISR, waking a `hlt`; the
//! wait itself watches the used ring. With `F_FLUSH` negotiated, every write batch ends with a
//! flush request, so it's durable when `write_blocks` returns, as the ATA path's `CACHE FLUSH`
//! makes it.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use super::dma::DmaBuffer;
use super::virtio::{F_VERSION_1, Segment, VENDOR, VirtioPci, Virtqueue};
use crate::serial_println;

/// PCI device ids: modern-only (`0x1040 + 2`) and transitional.
const DEVICE_MODERN: u16 = 0x1042;
const DEVICE_TRANSITIONAL: u16 = 0x1001;

/// The device supports flush requests (§5.2.3).
const F_FLUSH: u64 = 1 << 9;

const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const S_OK: u8 = 0;

/// Blocks per request, the bounce buffer's size (256 KiB).
const BUFFER_BLOCKS: usize = 64;
const TIMEOUT_MS: u64 = 5000;

struct Disk {
    dev: VirtioPci,
    queue: Virtqueue,
    /// The request header (16 bytes) at offset 0, the status byte at 16.
    request: DmaBuffer,
    buffer: DmaBuffer,
    flush: bool,
    /// In 512-byte sectors.
    capacity: u64,
}

static DISK: Mutex<Option<Disk>> = Mutex::new(None);
/// The ISR status register, for the interrupt handler, which can't take `DISK` (it may have
/// interrupted a holder). `0` until `init` succeeds.
static ISR_ADDR: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static IRQS: AtomicU64 = AtomicU64::new(0);

/// `(requests, completion interrupts)` so far.
pub fn stats() -> (u64, u64) {
    (REQUESTS.load(Ordering::Relaxed), IRQS.load(Ordering::Relaxed))
}

/// The PCI interrupt line (possibly shared): reading the ISR acknowledges the device, so the line
/// drops before EOI. The waiter re-checks the used ring itself; this only wakes it.
fn irq_handler() {
    let isr = ISR_ADDR.load(Ordering::Relaxed);
    if isr == 0 {
        return;
    }
    // SAFETY: the mapped ISR register.
    if unsafe { (isr as *const u8).read_volatile() } & 1 != 0 {
        IRQS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Finds and starts a virtio-blk device. `false` (logged) if there's none or it fails to start.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> bool {
    let Some(pci) = super::pci::find_by_id(VENDOR, DEVICE_MODERN)
        .or_else(|| super::pci::find_by_id(VENDOR, DEVICE_TRANSITIONAL))
    else {
        return false;
    };
    let fail = |why: &str| {
        serial_println!("[boot] virtio-blk: {} -- not used", why);
        false
    };
    let Some(dev) = VirtioPci::new(pci, frame_allocator, mapper, phys_mem_offset) else {
        return fail("no modern (virtio 1.x) interface");
    };
    let Some(features) = dev.negotiate(F_VERSION_1 | F_FLUSH) else {
        return fail("feature negotiation failed");
    };
    let Some(queue) = dev.setup_queue(0, 16, frame_allocator, phys_mem_offset) else {
        return fail("no request queue");
    };
    let request = DmaBuffer::alloc(frame_allocator, phys_mem_offset, 1, false);
    let buffer = DmaBuffer::alloc(frame_allocator, phys_mem_offset, BUFFER_BLOCKS, false);
    let (Some(request), Some(buffer)) = (request, buffer) else {
        return fail("no DMA buffer");
    };
    let capacity = dev.device_read32(0) as u64 | (dev.device_read32(4) as u64) << 32;
    dev.driver_ok();

    // Interrupt-line values 0-2 and >= 16 (0xFF: none assigned) can't be a usable PIC line here.
    let irq = pci.interrupt_line;
    let irq_ok = (3..16).contains(&irq);
    ISR_ADDR.store(dev.isr_addr().as_u64(), Ordering::Release);
    let _ = dev.read_isr(); // clear anything pending from setup
    if irq_ok {
        x86_64::instructions::interrupts::without_interrupts(|| {
            crate::cpu::interrupts::register_irq_handler(irq, irq_handler);
            // SAFETY: the handler is registered just above.
            unsafe { crate::cpu::pic::unmask_irq(irq) };
        });
    }
    serial_println!(
        "[boot] virtio-blk at {:02x}:{:02x}.{}: {} MiB, flush {}, {}",
        pci.bus,
        pci.device,
        pci.function,
        capacity / 2048,
        if features & F_FLUSH != 0 { "yes" } else { "no" },
        if irq_ok { alloc::format!("IRQ {irq}") } else { alloc::string::String::from("no IRQ, polling") }
    );
    *DISK.lock() = Some(Disk { dev, queue, request, buffer, flush: features & F_FLUSH != 0, capacity });
    true
}

impl Disk {
    /// One request: `kind` at `sector`, moving `len` bytes of the bounce buffer. `true` on success.
    fn request(&mut self, kind: u32, sector: u64, len: usize) -> bool {
        if kind != T_FLUSH && sector + (len / 512) as u64 > self.capacity {
            return false;
        }
        let header = self.request.as_mut_ptr::<u8>();
        // SAFETY: this driver's own request page, idle between requests.
        unsafe {
            (header as *mut u32).write_volatile(kind);
            (header.add(4) as *mut u32).write_volatile(0);
            (header.add(8) as *mut u64).write_volatile(sector);
            header.add(16).write_volatile(0xFF);
        }
        let base = self.request.phys.as_u64();
        let head = Segment { phys: base, len: 16, device_writes: false };
        let status = Segment { phys: base + 16, len: 1, device_writes: true };
        if kind == T_FLUSH {
            self.queue.submit(&[head, status]);
        } else {
            let data = Segment { phys: self.buffer.phys.as_u64(), len: len as u32, device_writes: kind == T_IN };
            self.queue.submit(&[head, data, status]);
        }
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let queue = &mut self.queue;
        if !super::dma::wait_until(TIMEOUT_MS, || queue.take_used()) {
            serial_println!("[virtio-blk] request {} at sector {} timed out", kind, sector);
            return false;
        }
        let _ = self.dev.read_isr(); // acknowledge, in case the interrupt was masked
        // SAFETY: the device has returned the request.
        unsafe { header.add(16).read_volatile() == S_OK }
    }
}

/// Reads blocks from `start_block` into `buf` (a whole number of 4 KiB blocks).
pub fn read_blocks(start_block: u64, buf: &mut [u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    for (i, chunk) in buf.chunks_mut(BUFFER_BLOCKS * 4096).enumerate() {
        let sector = (start_block + (i * BUFFER_BLOCKS) as u64) * 8;
        if !disk.request(T_IN, sector, chunk.len()) {
            return false;
        }
        // SAFETY: the request is complete; the device is done with the buffer.
        chunk.copy_from_slice(unsafe { disk.buffer.slice_mut(0, chunk.len()) });
    }
    true
}

/// Writes blocks from `buf` at `start_block`, then flushes, so they're durable on return.
pub fn write_blocks(start_block: u64, buf: &[u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    for (i, chunk) in buf.chunks(BUFFER_BLOCKS * 4096).enumerate() {
        let sector = (start_block + (i * BUFFER_BLOCKS) as u64) * 8;
        // SAFETY: no request is in flight.
        unsafe { disk.buffer.slice_mut(0, chunk.len()) }.copy_from_slice(chunk);
        if !disk.request(T_OUT, sector, chunk.len()) {
            return false;
        }
    }
    !disk.flush || disk.request(T_FLUSH, 0, 0)
}
