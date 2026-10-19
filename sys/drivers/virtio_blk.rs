//! virtio-blk: virtio block devices (virtio 1.2 specification §5.2), each a disk in the registry
//! (`drivers::disk`: `virt0`, `virt1`, ... in PCI order). The default under QEMU
//! (`scripts/qemu_common.sh`), because unlike IDE PIO no data passes through I/O ports: the device
//! reads and writes a DMA buffer directly.
//!
//! Each unit takes one request at a time through its queue 0: a chain of the request header
//! (device-readable), the data (through a bounce buffer, `BUFFER_BLOCKS` at a time), and the status
//! byte (device-writable). Completion is interrupt-driven with a polling fallback
//! (`dma::wait_for_disk`): the PCI interrupt lines' handler acknowledges every unit's ISR, waking
//! the waiters; each wait watches its own used ring. With `F_FLUSH` negotiated, every write batch
//! ends with a flush request, so it's durable when `write_sectors` returns, as the ATA path's
//! `CACHE FLUSH` makes it.

use alloc::vec::Vec;
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

/// The units, in PCI order: set once by `init`.
static UNITS: spin::Once<Vec<Mutex<Disk>>> = spin::Once::new();
/// Each unit's ISR status register, for the interrupt handler, which can't take a unit's lock (it
/// may have interrupted a holder). `0` past the units `init` started.
static ISR_ADDRS: [AtomicU64; MAX_UNITS] = [const { AtomicU64::new(0) }; MAX_UNITS];
/// Units driven at most (more are logged and left alone).
const MAX_UNITS: usize = 16;
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static IRQS: AtomicU64 = AtomicU64::new(0);

/// `(requests, completion interrupts)` so far.
pub fn stats() -> (u64, u64) {
    (REQUESTS.load(Ordering::Relaxed), IRQS.load(Ordering::Relaxed))
}

/// A unit's PCI interrupt line (possibly shared, with each other or other devices): reading each
/// unit's ISR acknowledges it, so the line drops before EOI. Each waiter re-checks its used ring
/// itself; this only wakes them.
fn irq_handler() {
    let mut any = false;
    for isr in &ISR_ADDRS {
        let isr = isr.load(Ordering::Relaxed);
        // SAFETY: a mapped ISR register.
        if isr != 0 && unsafe { (isr as *const u8).read_volatile() } & 1 != 0 {
            any = true;
        }
    }
    if any {
        IRQS.fetch_add(1, Ordering::Relaxed);
        super::dma::wake_disk_waiters(&mut crate::process::table().lock());
    }
}

/// Finds and starts every virtio-blk device; the capacity (in 512-byte sectors) of each started,
/// its unit number its index. Ones that fail to start are logged and left out.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Vec<u64> {
    let mut pcis = super::pci::find_all_by_id(VENDOR, DEVICE_MODERN);
    pcis.extend(super::pci::find_all_by_id(VENDOR, DEVICE_TRANSITIONAL));
    pcis.sort_by_key(|p| (p.bus, p.device, p.function));
    let mut units = Vec::new();
    for pci in pcis {
        if units.len() == MAX_UNITS {
            serial_println!("[boot] virtio-blk: more than {} devices -- the rest not used", MAX_UNITS);
            break;
        }
        if let Some(disk) = start(pci, units.len(), frame_allocator, mapper, phys_mem_offset) {
            units.push(Mutex::new(disk));
        }
    }
    let capacities = units.iter().map(|u| u.lock().capacity).collect();
    UNITS.call_once(|| units);
    capacities
}

/// Starts the device at `pci` as unit `unit`. `None` (logged) if it fails to.
fn start(
    pci: super::pci::PciDevice,
    unit: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Option<Disk> {
    let fail = |why: &str| {
        serial_println!(
            "[boot] virtio-blk at {:02x}:{:02x}.{}: {} -- not used",
            pci.bus,
            pci.device,
            pci.function,
            why
        );
        None
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
    ISR_ADDRS[unit].store(dev.isr_addr().as_u64(), Ordering::Release);
    let _ = dev.read_isr(); // clear anything pending from setup
    if irq_ok {
        x86_64::instructions::interrupts::without_interrupts(|| {
            crate::cpu::interrupts::register_irq_handler(irq, irq_handler);
            // SAFETY: the handler is registered just above.
            unsafe { crate::cpu::pic::unmask_irq(irq) };
        });
    }
    serial_println!(
        "[boot] virtio-blk: virt{} at {:02x}:{:02x}.{}: {} MiB, flush {}, {}",
        unit,
        pci.bus,
        pci.device,
        pci.function,
        capacity / 2048,
        if features & F_FLUSH != 0 { "yes" } else { "no" },
        if irq_ok { alloc::format!("IRQ {irq}") } else { alloc::string::String::from("no IRQ, polling") }
    );
    Some(Disk { dev, queue, request, buffer, flush: features & F_FLUSH != 0, capacity })
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
        if !super::dma::wait_for_disk(TIMEOUT_MS, || queue.take_used()) {
            serial_println!("[virtio-blk] request {} at sector {} timed out", kind, sector);
            return false;
        }
        let _ = self.dev.read_isr(); // acknowledge, in case the interrupt was masked
        // SAFETY: the device has returned the request.
        unsafe { header.add(16).read_volatile() == S_OK }
    }
}

/// Unit `unit`'s lock, if there is such a unit.
fn unit(unit: usize) -> Option<&'static Mutex<Disk>> {
    UNITS.get()?.get(unit)
}

/// Reads unit `n`'s sectors from `lba` into `buf` (a whole number of 512-byte sectors).
pub fn read_sectors(n: usize, lba: u64, buf: &mut [u8]) -> bool {
    let Some(unit) = unit(n) else { return false };
    let mut guard = unit.lock();
    let disk = &mut *guard;
    for (i, chunk) in buf.chunks_mut(BUFFER_BLOCKS * 4096).enumerate() {
        let sector = lba + (i * BUFFER_BLOCKS * 8) as u64;
        if !disk.request(T_IN, sector, chunk.len()) {
            return false;
        }
        // SAFETY: the request is complete; the device is done with the buffer.
        chunk.copy_from_slice(unsafe { disk.buffer.slice_mut(0, chunk.len()) });
    }
    true
}

/// Writes unit `n`'s sectors at `lba` from `buf` (whole sectors), then flushes, so they're durable
/// on return.
pub fn write_sectors(n: usize, lba: u64, buf: &[u8]) -> bool {
    let Some(unit) = unit(n) else { return false };
    let mut guard = unit.lock();
    let disk = &mut *guard;
    for (i, chunk) in buf.chunks(BUFFER_BLOCKS * 4096).enumerate() {
        let sector = lba + (i * BUFFER_BLOCKS * 8) as u64;
        // SAFETY: no request is in flight.
        unsafe { disk.buffer.slice_mut(0, chunk.len()) }.copy_from_slice(chunk);
        if !disk.request(T_OUT, sector, chunk.len()) {
            return false;
        }
    }
    !disk.flush || disk.request(T_FLUSH, 0, 0)
}
