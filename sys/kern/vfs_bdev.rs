//! Block devices for file systems (OxideBSD-doc `VFS.md` §8.2): every disk, partition and memory
//! disk the kernel found, each a handle bounded to its own sectors. A file system reads and writes
//! its device through the handle in 512-byte sectors (`oxidebsd_bdev_read`/`_write`), whatever
//! the disk's own sector size (`drivers::disk` translates), normally
//! through the buffer cache (`vfs_bio`); the raw `/dev` nodes (`drivers::disk`) read and write the
//! same extents directly, uncached, as FreeBSD's do.
//!
//! A file system says when it has its device mounted read-write (`oxidebsd_bdev_set_mounted`):
//! raw writes to any device overlapping it are refused then (`EPERM`), since they would go around
//! its cache (RAM_FLOOR.md §3.4.3, first for the root only).
//!
//! Handles are indices into `BDEVS`, which only grows: devices are found at boot, and when a CD's
//! disc changes (`retire` the old partitions').

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};

use spin::Mutex;

use crate::syscall::EIO;

/// One block device: a whole disk, a partition of it, or the memory disk.
pub(crate) struct Bdev {
    pub major: u32,
    pub minor: u32,
    /// The extent on the disk underneath, in 512-byte sectors.
    pub first: u64,
    pub sectors: u64,
    /// The disk underneath: its index in the disk registry (`drivers::disk`).
    pub disk: u32,
    /// A file system has it mounted read-write.
    pub mounted_rw: bool,
    /// Gone (`retire`): kept only so handles stay indices.
    pub retired: bool,
}

static BDEVS: Mutex<Vec<Bdev>> = Mutex::new(Vec::new());

/// The root file system's device, `-1` until the disk layer chooses it.
static ROOT: AtomicI64 = AtomicI64::new(-1);

pub(crate) const SECTOR: u64 = 512;

/// Adds a device, sectors `[first, first + sectors)` of registered disk `disk`; its handle.
pub(crate) fn register(name: &str, major: u32, minor: u32, first: u64, sectors: u64, disk: u32) -> u32 {
    let mut bdevs = BDEVS.lock();
    let _ = name; // `/dev`'s name for it, registered with devfs by the disk layer
    bdevs.push(Bdev { major, minor, first, sectors, disk, mounted_rw: false, retired: false });
    (bdevs.len() - 1) as u32
}

/// The device numbered `major`/`minor` (a `/dev` node's), if any.
pub(crate) fn find(major: u32, minor: u32) -> Option<u32> {
    BDEVS.lock().iter().position(|b| !b.retired && b.major == major && b.minor == minor).map(|i| i as u32)
}

/// Device `handle` is gone (a partition of a CD whose disc changed): nothing finds it, and it has
/// no sectors left to read.
pub(crate) fn retire(handle: u32) {
    if let Some(b) = BDEVS.lock().get_mut(handle as usize) {
        b.retired = true;
        b.sectors = 0;
    }
}

/// Device `handle` (a CD drive's whole disc) now has `sectors` sectors.
pub(crate) fn set_sectors(handle: u32, sectors: u64) {
    if let Some(b) = BDEVS.lock().get_mut(handle as usize) {
        b.sectors = sectors;
    }
}

/// `(first sector, sectors, disk)` of device `handle`.
pub(crate) fn extent(handle: u32) -> Option<(u64, u64, u32)> {
    BDEVS.lock().get(handle as usize).map(|b| (b.first, b.sectors, b.disk))
}

/// Makes `handle` the root file system's device.
pub(crate) fn set_root(handle: u32) {
    ROOT.store(handle as i64, Ordering::Relaxed);
}

/// The root file system's device: the one the disk layer chose, else (no disk probed at all: a
/// kernel that loads a file system without `drivers::disk::init`) a memory disk made now.
pub(crate) fn root() -> Option<u32> {
    let root = ROOT.load(Ordering::Relaxed);
    if root >= 0 {
        return Some(root as u32);
    }
    let offset = crate::memory::try_phys_mem_offset()?;
    crate::drivers::disk::init_memory(offset);
    let root = ROOT.load(Ordering::Relaxed);
    (root >= 0).then_some(root as u32)
}

/// Whether sectors `[first, first + sectors)` of disk `disk` overlap a device a file system has
/// mounted read-write.
pub(crate) fn overlaps_mounted_rw(first: u64, sectors: u64, disk: u32) -> bool {
    BDEVS.lock().iter().any(|b| {
        b.mounted_rw && b.disk == disk && first < b.first + b.sectors && b.first < first + sectors
    })
}

/// Checks that `len` bytes at device sector `sector` lie inside `handle`'s extent; the disk's
/// sector they start at.
fn locate(handle: u32, sector: u64, len: usize) -> Result<(u64, u32), u64> {
    let (first, sectors, disk) = extent(handle).ok_or(EIO)?;
    if len as u64 % SECTOR != 0 {
        return Err(EIO);
    }
    let count = len as u64 / SECTOR;
    if sector.checked_add(count).is_none_or(|end| end > sectors) {
        return Err(EIO);
    }
    Ok((first + sector, disk))
}

/// Reads `buf.len()` bytes (whole sectors) from device `handle` at its sector `sector`.
pub(crate) fn read(handle: u32, sector: u64, buf: &mut [u8]) -> Result<(), u64> {
    let (lba, disk) = locate(handle, sector, buf.len())?;
    if crate::drivers::disk::read_sectors(disk, lba, buf) { Ok(()) } else { Err(EIO) }
}

/// Writes `buf` (whole sectors) to device `handle` at its sector `sector`, durably: on the disk
/// when this returns.
pub(crate) fn write(handle: u32, sector: u64, buf: &[u8]) -> Result<(), u64> {
    let (lba, disk) = locate(handle, sector, buf.len())?;
    if crate::drivers::disk::write_sectors(disk, lba, buf) { Ok(()) } else { Err(EIO) }
}

/// Kernel API for file systems: the root file system's device handle, `-1` if there is none.
pub(crate) extern "C" fn oxidebsd_bdev_root() -> i64 {
    root().map_or(-1, |h| h as i64)
}

/// Kernel API: device `handle`'s size in sectors (`0` for no such device).
pub(crate) extern "C" fn oxidebsd_bdev_sectors(handle: u64) -> u64 {
    extent(handle as u32).map_or(0, |(_, sectors, _)| sectors)
}

/// Kernel API: reads `count` sectors of device `handle` at `sector` into `buf`; `0` or `-EIO`.
pub(crate) extern "C" fn oxidebsd_bdev_read(handle: u64, sector: u64, count: u64, buf: *mut u8) -> i64 {
    // SAFETY: the file system's own buffer of `count` sectors.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, (count * SECTOR) as usize) };
    match read(handle as u32, sector, buf) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// Kernel API: writes `count` sectors from `buf` to device `handle` at `sector`; `0` or `-EIO`.
pub(crate) extern "C" fn oxidebsd_bdev_write(handle: u64, sector: u64, count: u64, buf: *const u8) -> i64 {
    // SAFETY: as `oxidebsd_bdev_read`.
    let buf = unsafe { core::slice::from_raw_parts(buf, (count * SECTOR) as usize) };
    match write(handle as u32, sector, buf) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// Kernel API: a file system has device `handle` mounted read-write (`rw != 0`) or no longer.
pub(crate) extern "C" fn oxidebsd_bdev_set_mounted(handle: u64, rw: u64) {
    if let Some(b) = BDEVS.lock().get_mut(handle as usize) {
        b.mounted_rw = rw != 0;
    }
}
