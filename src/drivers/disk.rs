//! The data disk: the one block device backing oxfs's persistence, behind the `oxidebsd_block_*`
//! exports oxfs calls. `init` picks it at boot -- a virtio-blk disk if there is one (the fastest
//! under QEMU), else the legacy IDE disk at secondary master (by bus-master DMA when the
//! controller can, else PIO) -- and oxfs never knows which. Not a general block layer: exactly one
//! disk, found once.
//!
//! Every export takes oxfs's 4 KiB blocks and returns `0` or `-1`, the plain-integer convention
//! modules need (no `alloc`, no rich types across the boundary). Callers are oxfs's
//! `module_init` (interrupts enabled) and its syscall handlers (interrupts masked); the drivers
//! handle both (`dma::wait_until`).

use core::sync::atomic::{AtomicU8, Ordering};

use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use crate::serial_println;

const NONE: u8 = 0;
const ATA: u8 = 1;
const VIRTIO: u8 = 2;

static BACKEND: AtomicU8 = AtomicU8::new(NONE);

/// Finds the data disk: virtio-blk first, then the IDE disk (setting up its DMA). With neither,
/// oxfs runs in memory only this boot.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) {
    if super::virtio_blk::init(frame_allocator, mapper, phys_mem_offset) {
        BACKEND.store(VIRTIO, Ordering::Relaxed);
        serial_println!("[boot] disk: data disk is virtio-blk");
        return;
    }
    super::ata::init();
    if super::ata::present() {
        super::ata::init_dma(frame_allocator, phys_mem_offset);
        BACKEND.store(ATA, Ordering::Relaxed);
        serial_println!("[boot] disk: data disk is the IDE secondary master");
    } else {
        serial_println!("[boot] disk: no data disk -- oxfs runs in memory only this boot");
    }
}

/// `(transfers, completion interrupts)` on the data disk so far, for the boot log.
pub fn stats() -> (u64, u64) {
    match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::dma_stats(),
        VIRTIO => super::virtio_blk::stats(),
        _ => (0, 0),
    }
}

fn read(start_block: u64, buf: &mut [u8]) -> i64 {
    let ok = match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::read_blocks(start_block, buf).is_ok(),
        VIRTIO => super::virtio_blk::read_blocks(start_block, buf),
        _ => false,
    };
    if ok { 0 } else { -1 }
}

fn write(start_block: u64, buf: &[u8]) -> i64 {
    let ok = match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::write_blocks(start_block, buf).is_ok(),
        VIRTIO => super::virtio_blk::write_blocks(start_block, buf),
        _ => false,
    };
    if ok { 0 } else { -1 }
}

/// Whether a data disk is attached this boot: `1` or `0`.
pub extern "C" fn oxidebsd_block_device_present() -> i64 {
    (BACKEND.load(Ordering::Relaxed) != NONE) as i64
}

/// Reads block `block_no` into the 4096 bytes at `buf_ptr`.
pub extern "C" fn oxidebsd_block_read(block_no: u64, buf_ptr: u64) -> i64 {
    oxidebsd_block_read_batch(block_no, 1, buf_ptr)
}

/// Writes the 4096 bytes at `buf_ptr` to block `block_no`, durably.
pub extern "C" fn oxidebsd_block_write(block_no: u64, buf_ptr: u64) -> i64 {
    oxidebsd_block_write_batch(block_no, 1, buf_ptr)
}

/// Reads `count` consecutive blocks from `start_block` into `buf_ptr` (`count * 4096` bytes).
pub extern "C" fn oxidebsd_block_read_batch(start_block: u64, count: u64, buf_ptr: u64) -> i64 {
    // SAFETY: the caller (oxfs) passes `count * 4096` live, writable bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, (count * 4096) as usize) };
    read(start_block, buf)
}

/// Writes `count` consecutive blocks from `buf_ptr` to `start_block`, durably: one flush for the
/// whole batch, not one per block.
pub extern "C" fn oxidebsd_block_write_batch(start_block: u64, count: u64, buf_ptr: u64) -> i64 {
    // SAFETY: the caller (oxfs) passes `count * 4096` live, readable bytes.
    let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, (count * 4096) as usize) };
    write(start_block, buf)
}
