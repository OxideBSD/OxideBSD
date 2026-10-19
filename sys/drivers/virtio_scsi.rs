//! virtio-scsi: SCSI host adapters (virtio 1.2 specification §5.6), each logical unit on them a
//! disk in the registry (`drivers::disk`: `scsi0`, `scsi1`, ... in controller, target order),
//! disks and CD drives alike (`OxideBSD-doc/INSTALLER.md` §5.3). QEMU's default CD controller
//! (`scripts/qemu_common.sh`) is one: through it the kernel reads the medium it booted from.
//!
//! The commands are `drivers::scsi`'s; this file carries them. Each controller takes one request
//! at a time through its first request queue (queue 2): a chain of the request header and any
//! data out (device-readable), then the response and any data in (device-writable), the data
//! through a bounce buffer. Completion is interrupt-driven with a polling fallback, as
//! `virtio_blk`'s: the interrupt handler acknowledges every controller's ISR and wakes the
//! waiters (`dma::wait_for_disk`). Sense data comes back with a failed command (autosense).
//!
//! At boot each target is asked `INQUIRY` on LUN 0 (a target with more LUNs shows only its
//! first).

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use super::dma::DmaBuffer;
use super::scsi::{Data, ScsiError, Transport};
use super::virtio::{F_VERSION_1, Segment, VENDOR, VirtioPci, Virtqueue};
use crate::serial_println;

/// PCI device ids: modern-only (`0x1040 + 8`) and transitional.
const DEVICE_MODERN: u16 = 0x1048;
const DEVICE_TRANSITIONAL: u16 = 0x1004;

/// The first request queue (0 is control, 1 events).
const REQUEST_QUEUE: u16 = 2;

// Device configuration (§5.6.4).
const CFG_SENSE_SIZE: u64 = 20;
const CFG_CDB_SIZE: u64 = 24;
/// `max_channel` (u16) and `max_target` (u16).
const CFG_MAX_CHANNEL_TARGET: u64 = 28;

/// The request header's fixed part: LUN (8), tag (8), task attribute, priority, CRN; then the
/// CDB.
const REQ_FIXED: usize = 19;
/// The response's fixed part: sense length, residual (u32 each), status qualifier (u16), status,
/// response; then the sense data.
const RESP_FIXED: usize = 12;
/// Where the response goes in the request page.
const RESP_AT: usize = 512;
/// `response`: the request was carried (whatever its SCSI status).
const S_OK: u8 = 0;
/// SCSI status: good, and check condition (the sense says why).
const STATUS_GOOD: u8 = 0x00;
const STATUS_CHECK_CONDITION: u8 = 0x02;

/// The bounce buffer, in pages (256 KiB).
const BUFFER_PAGES: usize = 64;
const TIMEOUT_MS: u64 = 10_000;
/// Controllers driven at most.
const MAX_CONTROLLERS: usize = 8;
/// Targets asked at most per controller.
const MAX_TARGETS: u16 = 256;

struct Controller {
    dev: VirtioPci,
    queue: Virtqueue,
    /// The request header at offset 0, the response at `RESP_AT`.
    request: DmaBuffer,
    buffer: DmaBuffer,
    cdb_size: usize,
    sense_size: usize,
    next_tag: u64,
}

/// The controllers, set once by `init`.
static CONTROLLERS: spin::Once<Vec<Mutex<Controller>>> = spin::Once::new();
/// Each controller's ISR status register, for the interrupt handler (`0` past those started).
static ISR_ADDRS: [AtomicU64; MAX_CONTROLLERS] = [const { AtomicU64::new(0) }; MAX_CONTROLLERS];
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static IRQS: AtomicU64 = AtomicU64::new(0);

/// `(requests, completion interrupts)` so far.
pub fn stats() -> (u64, u64) {
    (REQUESTS.load(Ordering::Relaxed), IRQS.load(Ordering::Relaxed))
}

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

/// One logical unit: a SCSI transport (`drivers::scsi`).
#[derive(Clone, Copy)]
pub struct Unit {
    controller: usize,
    target: u16,
    lun: u16,
}

/// A unit found at boot: its peripheral device type (`scsi::TYPE_*`), whether its medium is
/// removable, its vendor and product.
pub struct Found {
    pub unit: Unit,
    pub device_type: u8,
    pub removable: bool,
    pub model: String,
}

impl Unit {
    /// Blocks of `block_size` bytes one command moves at most: the bounce buffer's worth.
    pub fn max_blocks(&self, block_size: usize) -> usize {
        (BUFFER_PAGES * 4096 / block_size).max(1)
    }
}

impl Transport for Unit {
    fn command(&self, cdb: &[u8], data: Data) -> Result<usize, ScsiError> {
        let Some(c) = CONTROLLERS.get().and_then(|c| c.get(self.controller)) else {
            return Err(ScsiError::Transport);
        };
        c.lock().command(self, cdb, data)
    }
}

impl Controller {
    fn command(&mut self, unit: &Unit, cdb: &[u8], data: Data) -> Result<usize, ScsiError> {
        if cdb.len() > self.cdb_size {
            return Err(ScsiError::Transport);
        }
        let (len, data_out, data_in) = match &data {
            Data::None => (0, false, false),
            Data::In(b) => (b.len(), false, true),
            Data::Out(b) => (b.len(), true, false),
        };
        if len > self.buffer.len {
            return Err(ScsiError::Transport);
        }
        let req_len = REQ_FIXED + self.cdb_size;
        let resp_len = RESP_FIXED + self.sense_size;
        // SAFETY: this controller's own request page, idle between requests (its lock is held).
        let page = unsafe { self.request.slice_mut(0, 4096) };
        page[..req_len].fill(0);
        // The single-level LUN format (§5.6.6.1): 1, target, then 0x4000 | LUN, big-endian.
        page[0] = 1;
        page[1] = unit.target as u8;
        page[2..4].copy_from_slice(&(0x4000 | unit.lun).to_be_bytes());
        self.next_tag += 1;
        page[8..16].copy_from_slice(&self.next_tag.to_le_bytes());
        page[REQ_FIXED..REQ_FIXED + cdb.len()].copy_from_slice(cdb);
        page[RESP_AT..RESP_AT + resp_len].fill(0);
        page[RESP_AT + 11] = 0xFF;
        if let Data::Out(b) = &data {
            // SAFETY: as above.
            unsafe { self.buffer.slice_mut(0, len) }.copy_from_slice(b);
        }
        let base = self.request.phys.as_u64();
        let data_seg = |device_writes| Segment { phys: self.buffer.phys.as_u64(), len: len as u32, device_writes };
        let mut chain = alloc::vec![Segment { phys: base, len: req_len as u32, device_writes: false }];
        if data_out && len > 0 {
            chain.push(data_seg(false));
        }
        chain.push(Segment { phys: base + RESP_AT as u64, len: resp_len as u32, device_writes: true });
        if data_in && len > 0 {
            chain.push(data_seg(true));
        }
        self.queue.submit(&chain);
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let queue = &mut self.queue;
        if !super::dma::wait_for_disk(TIMEOUT_MS, || queue.take_used()) {
            serial_println!("[virtio-scsi] command {:#04x} to target {} timed out", cdb[0], unit.target);
            return Err(ScsiError::Transport);
        }
        let _ = self.dev.read_isr(); // acknowledge, in case the interrupt was masked
        // SAFETY: the device has returned the request.
        let resp = unsafe { self.request.slice_mut(RESP_AT, resp_len) };
        let sense_len = (u32::from_le_bytes(resp[0..4].try_into().unwrap()) as usize).min(self.sense_size);
        let resid = (u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize).min(len);
        let (status, response) = (resp[10], resp[11]);
        if response != S_OK {
            return Err(ScsiError::Transport); // no such target, a reset, ...
        }
        match status {
            STATUS_GOOD => {}
            STATUS_CHECK_CONDITION if sense_len >= 14 => {
                let s = &resp[RESP_FIXED..RESP_FIXED + sense_len];
                return Err(ScsiError::Sense(s[2] & 0x0F, s[12], s[13]));
            }
            _ => return Err(ScsiError::Transport),
        }
        let moved = len - resid;
        if let Data::In(b) = data {
            // SAFETY: the request is complete; the device is done with the buffer.
            b[..moved].copy_from_slice(unsafe { self.buffer.slice_mut(0, moved) });
        }
        Ok(moved)
    }
}

/// Finds and starts every virtio-scsi controller, and asks each of its targets what's there;
/// the units found, in controller and target order.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Vec<Found> {
    let mut pcis = super::pci::find_all_by_id(VENDOR, DEVICE_MODERN);
    pcis.extend(super::pci::find_all_by_id(VENDOR, DEVICE_TRANSITIONAL));
    pcis.sort_by_key(|p| (p.bus, p.device, p.function));
    let mut controllers = Vec::new();
    let mut targets = Vec::new();
    for pci in pcis {
        if controllers.len() == MAX_CONTROLLERS {
            serial_println!("[boot] virtio-scsi: more than {} controllers -- the rest not used", MAX_CONTROLLERS);
            break;
        }
        if let Some((c, max_target)) = start(pci, controllers.len(), frame_allocator, mapper, phys_mem_offset) {
            targets.push(max_target);
            controllers.push(Mutex::new(c));
        }
    }
    CONTROLLERS.call_once(|| controllers);
    let mut found = Vec::new();
    for (controller, &max_target) in targets.iter().enumerate() {
        for target in 0..=max_target.min(MAX_TARGETS - 1) {
            let unit = Unit { controller, target, lun: 0 };
            if let Some((device_type, removable, model)) = super::scsi::inquiry(&unit) {
                serial_println!(
                    "[boot] virtio-scsi: controller {} target {}: type {:#04x}{}, \"{}\"",
                    controller,
                    target,
                    device_type,
                    if removable { ", removable" } else { "" },
                    model
                );
                found.push(Found { unit, device_type, removable, model });
            }
        }
    }
    found
}

/// Starts the controller at `pci` as number `n`; it and its highest target number. `None`
/// (logged) if it fails to.
fn start(
    pci: super::pci::PciDevice,
    n: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Option<(Controller, u16)> {
    let fail = |why: &str| {
        serial_println!("[boot] virtio-scsi at {:02x}:{:02x}.{}: {} -- not used", pci.bus, pci.device, pci.function, why);
        None
    };
    let Some(dev) = VirtioPci::new(pci, frame_allocator, mapper, phys_mem_offset) else {
        return fail("no modern (virtio 1.x) interface");
    };
    if dev.negotiate(F_VERSION_1).is_none() {
        return fail("feature negotiation failed");
    }
    let Some(queue) = dev.setup_queue(REQUEST_QUEUE, 16, frame_allocator, phys_mem_offset) else {
        return fail("no request queue");
    };
    let request = DmaBuffer::alloc(frame_allocator, phys_mem_offset, 1, false);
    let buffer = DmaBuffer::alloc(frame_allocator, phys_mem_offset, BUFFER_PAGES, false);
    let (Some(request), Some(buffer)) = (request, buffer) else {
        return fail("no DMA buffer");
    };
    let sense_size = dev.device_read32(CFG_SENSE_SIZE) as usize;
    let cdb_size = dev.device_read32(CFG_CDB_SIZE) as usize;
    let max_target = (dev.device_read32(CFG_MAX_CHANNEL_TARGET) >> 16) as u16;
    // Both fit the request page: header at 0, response at `RESP_AT`.
    if cdb_size < 16 || REQ_FIXED + cdb_size > RESP_AT || RESP_AT + RESP_FIXED + sense_size > 4096 {
        return fail("unexpected CDB or sense size");
    }
    dev.driver_ok();

    let irq = pci.interrupt_line;
    let irq_ok = (3..16).contains(&irq);
    ISR_ADDRS[n].store(dev.isr_addr().as_u64(), Ordering::Release);
    let _ = dev.read_isr();
    if irq_ok {
        x86_64::instructions::interrupts::without_interrupts(|| {
            crate::cpu::interrupts::register_irq_handler(irq, irq_handler);
            // SAFETY: the handler is registered just above.
            unsafe { crate::cpu::pic::unmask_irq(irq) };
        });
    }
    serial_println!(
        "[boot] virtio-scsi: controller {} at {:02x}:{:02x}.{}: targets 0-{}, {}",
        n,
        pci.bus,
        pci.device,
        pci.function,
        max_target,
        if irq_ok { alloc::format!("IRQ {irq}") } else { String::from("no IRQ, polling") }
    );
    Some((Controller { dev, queue, request, buffer, cdb_size, sense_size, next_tag: 0 }, max_target))
}
