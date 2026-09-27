//! The modern (virtio 1.x) PCI transport and a split virtqueue -- what every virtio device driver
//! shares (`virtio_blk` today). See the virtio 1.2 specification, sections 2 ("Basic
//! Facilities"), 2.7 ("Split Virtqueues") and 4.1 ("Virtio Over PCI Bus").
//!
//! Modern only: the legacy (0.9.5) I/O-port register block is deprecated, and a device QEMU
//! creates with `disable-legacy=on` (id `0x1040 + type`) has only this interface. The transport's
//! register blocks are found through vendor-specific PCI capabilities, each naming a BAR and an
//! offset, and are mapped uncached through `pci::map_mmio`.
//!
//! One request in flight at a time: the virtqueue always uses its first descriptors for the
//! chain it submits, and the caller waits for it to complete before submitting the next.

use core::sync::atomic::{Ordering, fence};

use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::dma::DmaBuffer;
use super::pci::PciDevice;

pub const VENDOR: u16 = 0x1AF4;

/// Device status bits (§2.1).
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

/// The one feature every modern driver must accept (§6).
pub const F_VERSION_1: u64 = 1 << 32;

/// Capability types (§4.1.4).
const CAP_VENDOR: u8 = 0x09;
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_ISR: u8 = 3;
const CFG_DEVICE: u8 = 4;

// Common configuration registers (§4.1.4.3).
const DEVICE_FEATURE_SELECT: u64 = 0;
const DEVICE_FEATURE: u64 = 4;
const DRIVER_FEATURE_SELECT: u64 = 8;
const DRIVER_FEATURE: u64 = 12;
const DEVICE_STATUS: u64 = 20;
const QUEUE_SELECT: u64 = 22;
const QUEUE_SIZE: u64 = 24;
const QUEUE_ENABLE: u64 = 28;
const QUEUE_NOTIFY_OFF: u64 = 30;
const QUEUE_DESC: u64 = 32;
const QUEUE_DRIVER: u64 = 40;
const QUEUE_DEVICE: u64 = 48;

/// A virtio device's register blocks.
pub struct VirtioPci {
    pub pci: PciDevice,
    common: VirtAddr,
    notify: VirtAddr,
    notify_multiplier: u32,
    isr: VirtAddr,
    device: VirtAddr,
}

fn read8(a: VirtAddr) -> u8 {
    unsafe { a.as_ptr::<u8>().read_volatile() }
}
fn read16(a: VirtAddr) -> u16 {
    unsafe { a.as_ptr::<u16>().read_volatile() }
}
fn read32(a: VirtAddr) -> u32 {
    unsafe { a.as_ptr::<u32>().read_volatile() }
}
fn write8(a: VirtAddr, v: u8) {
    unsafe { a.as_mut_ptr::<u8>().write_volatile(v) }
}
fn write16(a: VirtAddr, v: u16) {
    unsafe { a.as_mut_ptr::<u16>().write_volatile(v) }
}
fn write32(a: VirtAddr, v: u32) {
    unsafe { a.as_mut_ptr::<u32>().write_volatile(v) }
}
/// 64-bit registers written as two 32-bit halves, low first, which §4.1.3.1 permits.
fn write64(a: VirtAddr, v: u64) {
    write32(a, v as u32);
    write32(a + 4u64, (v >> 32) as u32);
}

impl VirtioPci {
    /// Finds `pci`'s modern register blocks and maps them. `None` if it has no modern interface.
    pub fn new(
        pci: PciDevice,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
        mapper: &mut impl Mapper<Size4KiB>,
        phys_mem_offset: VirtAddr,
    ) -> Option<VirtioPci> {
        let (mut common, mut notify, mut isr, mut device) = (None, None, None, None);
        let mut notify_multiplier = 0;
        for cap in pci.capabilities(CAP_VENDOR) {
            let cfg_type = pci.config_read_u8(cap + 3);
            let bar = pci.config_read_u8(cap + 4) as usize;
            let offset = pci.config_read_u32(cap + 8) as u64;
            let length = pci.config_read_u32(cap + 12) as u64;
            // The first capability of each type is the one to use (§4.1.4).
            let slot = match cfg_type {
                CFG_COMMON => &mut common,
                CFG_NOTIFY => &mut notify,
                CFG_ISR => &mut isr,
                CFG_DEVICE => &mut device,
                _ => continue,
            };
            if slot.is_some() || bar > 5 {
                continue;
            }
            let Some(bar_phys) = pci.mem_bar(bar) else { continue };
            let start = PhysAddr::new(bar_phys + offset);
            let first_page = start.align_down(4096u64);
            let pages = (start.as_u64() + length.max(1) - first_page.as_u64()).div_ceil(4096);
            super::pci::map_mmio(mapper, frame_allocator, phys_mem_offset, first_page, pages);
            *slot = Some(phys_mem_offset + start.as_u64());
            if cfg_type == CFG_NOTIFY {
                notify_multiplier = pci.config_read_u32(cap + 16);
            }
        }
        pci.enable_memory_and_bus_mastering();
        Some(VirtioPci {
            pci,
            common: common?,
            notify: notify?,
            notify_multiplier,
            isr: isr?,
            device: device?,
        })
    }

    fn status(&self) -> u8 {
        read8(self.common + DEVICE_STATUS)
    }

    fn add_status(&self, bits: u8) {
        write8(self.common + DEVICE_STATUS, self.status() | bits);
    }

    /// Resets the device and negotiates features (§3.1.1 steps 1-6): accepts `wanted` (which must
    /// include `F_VERSION_1`) intersected with what the device offers. Returns the accepted set,
    /// or `None` if the device rejects it or lacks `F_VERSION_1`.
    pub fn negotiate(&self, wanted: u64) -> Option<u64> {
        write8(self.common + DEVICE_STATUS, 0);
        let deadline = crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(1000);
        while self.status() != 0 {
            if crate::cpu::tsc::now() >= deadline {
                return None;
            }
            core::hint::spin_loop();
        }
        self.add_status(STATUS_ACKNOWLEDGE);
        self.add_status(STATUS_DRIVER);
        let mut offered = 0u64;
        for half in 0..2u32 {
            write32(self.common + DEVICE_FEATURE_SELECT, half);
            offered |= (read32(self.common + DEVICE_FEATURE) as u64) << (32 * half);
        }
        let accepted = offered & wanted;
        if accepted & F_VERSION_1 == 0 {
            self.add_status(STATUS_FAILED);
            return None;
        }
        for half in 0..2u32 {
            write32(self.common + DRIVER_FEATURE_SELECT, half);
            write32(self.common + DRIVER_FEATURE, (accepted >> (32 * half)) as u32);
        }
        self.add_status(STATUS_FEATURES_OK);
        if self.status() & STATUS_FEATURES_OK == 0 {
            self.add_status(STATUS_FAILED);
            return None;
        }
        Some(accepted)
    }

    /// Sets up queue `index` with at most `max_size` entries (§4.1.5.1.3).
    pub fn setup_queue(
        &self,
        index: u16,
        max_size: u16,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
        phys_mem_offset: VirtAddr,
    ) -> Option<Virtqueue> {
        write16(self.common + QUEUE_SELECT, index);
        let device_max = read16(self.common + QUEUE_SIZE);
        if device_max == 0 {
            return None;
        }
        // A power of two no larger than either limit, and small enough for one page.
        let mut size = 1u16;
        while size * 2 <= device_max.min(max_size).min(Virtqueue::MAX_SIZE) {
            size *= 2;
        }
        write16(self.common + QUEUE_SIZE, size);
        let mem = DmaBuffer::alloc(frame_allocator, phys_mem_offset, 1, false)?;
        let base = mem.phys.as_u64();
        write64(self.common + QUEUE_DESC, base + Virtqueue::DESC);
        write64(self.common + QUEUE_DRIVER, base + Virtqueue::AVAIL);
        write64(self.common + QUEUE_DEVICE, base + Virtqueue::USED);
        let notify_off = read16(self.common + QUEUE_NOTIFY_OFF) as u64;
        write16(self.common + QUEUE_ENABLE, 1);
        Some(Virtqueue {
            index,
            size,
            mem,
            notify: self.notify + notify_off * self.notify_multiplier as u64,
            avail_idx: 0,
            used_seen: 0,
        })
    }

    /// Tells the device the driver is ready (§3.1.1 step 8).
    pub fn driver_ok(&self) {
        self.add_status(STATUS_DRIVER_OK);
    }

    /// Reads, and so acknowledges, the ISR status (§4.1.4.5): bit 0 is a queue interrupt.
    pub fn read_isr(&self) -> u8 {
        read8(self.isr)
    }

    /// The ISR register's address, for an interrupt handler that can't reach `self`.
    pub fn isr_addr(&self) -> VirtAddr {
        self.isr
    }

    pub fn device_read32(&self, offset: u64) -> u32 {
        read32(self.device + offset)
    }
}

/// One buffer in a descriptor chain: physical address, length, and whether the device writes it.
pub struct Segment {
    pub phys: u64,
    pub len: u32,
    pub device_writes: bool,
}

/// A split virtqueue in one page: descriptor table, then the available ring, then the used ring.
pub struct Virtqueue {
    index: u16,
    size: u16,
    mem: DmaBuffer,
    notify: VirtAddr,
    avail_idx: u16,
    used_seen: u16,
}

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

impl Virtqueue {
    /// Largest queue that fits the page layout below.
    const MAX_SIZE: u16 = 64;
    const DESC: u64 = 0; // 16 bytes per descriptor: 1 KiB for 64
    const AVAIL: u64 = 1024; // flags, idx, ring[size], used_event
    const USED: u64 = 2048; // flags, idx, ring[size] of (id, len), avail_event

    fn at<T>(&self, offset: u64) -> *mut T {
        (self.mem.virt + offset).as_mut_ptr()
    }

    /// Posts `chain` as one request and notifies the device.
    pub fn submit(&mut self, chain: &[Segment]) {
        assert!(!chain.is_empty() && chain.len() <= self.size as usize);
        for (i, seg) in chain.iter().enumerate() {
            let mut flags = if seg.device_writes { DESC_F_WRITE } else { 0 };
            if i + 1 < chain.len() {
                flags |= DESC_F_NEXT;
            }
            let desc = Self::DESC + i as u64 * 16;
            // SAFETY: descriptors this queue owns, idle between requests.
            unsafe {
                self.at::<u64>(desc).write_volatile(seg.phys);
                self.at::<u32>(desc + 8).write_volatile(seg.len);
                self.at::<u16>(desc + 12).write_volatile(flags);
                self.at::<u16>(desc + 14).write_volatile(i as u16 + 1);
            }
        }
        let slot = (self.avail_idx % self.size) as u64;
        // SAFETY: the available ring this queue owns.
        unsafe { self.at::<u16>(Self::AVAIL + 4 + slot * 2).write_volatile(0) };
        // The ring entry and descriptors must be visible before the index that publishes them,
        // and the index before the notification (§2.7.13).
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        unsafe { self.at::<u16>(Self::AVAIL + 2).write_volatile(self.avail_idx) };
        fence(Ordering::SeqCst);
        write16(self.notify, self.index);
    }

    /// Whether the device has returned a request not yet taken; takes it if so.
    pub fn take_used(&mut self) -> bool {
        // SAFETY: the used ring's index, written by the device.
        let used = unsafe { self.at::<u16>(Self::USED + 2).read_volatile() };
        if used == self.used_seen {
            return false;
        }
        fence(Ordering::SeqCst);
        self.used_seen = self.used_seen.wrapping_add(1);
        true
    }
}
