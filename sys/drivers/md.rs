//! md: a memory disk, the data disk when there is no real one (`OxideBSD-doc/RAM_FLOOR.md`
//! §3.1.3.1). oxfs formats and uses it exactly as it would a disk, through the same cache, so a
//! diskless boot needs no second storage path.
//!
//! Its capacity is a quarter of RAM, but its RAM cost is only what has been written: a block
//! gets a frame on its first write, and a never-written block reads as zeros. Frames are never
//! given back (oxfs doesn't tell a disk which blocks it freed), so a busy diskless system grows
//! toward the capacity, never past it.

use alloc::vec;
use alloc::vec::Vec;

use spin::Mutex;
use x86_64::VirtAddr;

const BLOCK: usize = 4096;

struct MemoryDisk {
    /// Physical address of each block's frame; `0` until the block is first written.
    frames: Vec<u64>,
    phys_mem_offset: VirtAddr,
}

static DISK: Mutex<Option<MemoryDisk>> = Mutex::new(None);

/// Creates the memory disk, `capacity_blocks` 4 KiB blocks, none of them backed yet.
pub fn init(capacity_blocks: u64, phys_mem_offset: VirtAddr) {
    *DISK.lock() = Some(MemoryDisk { frames: vec![0; capacity_blocks as usize], phys_mem_offset });
}

/// The disk's size in 4 KiB blocks.
pub fn capacity_blocks() -> u64 {
    DISK.lock().as_ref().map_or(0, |disk| disk.frames.len() as u64)
}

/// Reads blocks from `start_block` into `buf` (a whole number of blocks).
pub fn read_blocks(start_block: u64, buf: &mut [u8]) -> bool {
    let guard = DISK.lock();
    let Some(disk) = guard.as_ref() else { return false };
    for (i, chunk) in buf.chunks_mut(BLOCK).enumerate() {
        let Some(&frame) = disk.frames.get(start_block as usize + i) else { return false };
        if frame == 0 {
            chunk.fill(0);
        } else {
            // SAFETY: `frame` is a frame this disk owns, mapped through the HHDM.
            let src = unsafe { &*((disk.phys_mem_offset + frame).as_ptr::<[u8; BLOCK]>()) };
            chunk.copy_from_slice(src);
        }
    }
    true
}

/// Reads sectors from `lba` into `buf` (whole 512-byte sectors): the block layer's way in, for a
/// file system with smaller blocks than the disk's 4 KiB frames.
pub fn read_sectors(lba: u64, buf: &mut [u8]) -> bool {
    let guard = DISK.lock();
    let Some(disk) = guard.as_ref() else { return false };
    for (i, sector) in buf.chunks_mut(512).enumerate() {
        let at = lba + i as u64;
        let Some(&frame) = disk.frames.get((at / 8) as usize) else { return false };
        if frame == 0 {
            sector.fill(0);
        } else {
            let off = (at % 8) as usize * 512;
            // SAFETY: as in `read_blocks`.
            let src = unsafe { &*((disk.phys_mem_offset + frame).as_ptr::<[u8; BLOCK]>()) };
            sector.copy_from_slice(&src[off..off + 512]);
        }
    }
    true
}

/// Writes sectors at `lba` from `buf` (whole sectors). A block's frame, taken on its first write,
/// starts zeroed: the rest of the block reads as zeros, as it did before.
pub fn write_sectors(lba: u64, buf: &[u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    let offset = disk.phys_mem_offset;
    for (i, sector) in buf.chunks(512).enumerate() {
        let at = lba + i as u64;
        let Some(slot) = disk.frames.get_mut((at / 8) as usize) else { return false };
        if *slot == 0 {
            let Some(frame) = crate::module::allocate_frame() else { return false };
            *slot = frame.start_address().as_u64();
            // SAFETY: a frame just allocated, reached through the HHDM.
            unsafe { core::ptr::write_bytes((offset + *slot).as_mut_ptr::<u8>(), 0, BLOCK) };
        }
        let off = (at % 8) as usize * 512;
        // SAFETY: as in `write_blocks`.
        let dst = unsafe { &mut *((offset + *slot).as_mut_ptr::<[u8; BLOCK]>()) };
        dst[off..off + 512].copy_from_slice(sector);
    }
    true
}

/// Writes blocks from `buf` at `start_block`, backing each with a frame on its first write.
pub fn write_blocks(start_block: u64, buf: &[u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    let offset = disk.phys_mem_offset;
    for (i, chunk) in buf.chunks(BLOCK).enumerate() {
        let Some(slot) = disk.frames.get_mut(start_block as usize + i) else { return false };
        if *slot == 0 {
            let Some(frame) = crate::module::allocate_frame() else { return false };
            *slot = frame.start_address().as_u64();
        }
        // SAFETY: as in `read_blocks`; nothing else maps this frame.
        let dst = unsafe { &mut *((offset + *slot).as_mut_ptr::<[u8; BLOCK]>()) };
        dst.copy_from_slice(chunk);
    }
    true
}
