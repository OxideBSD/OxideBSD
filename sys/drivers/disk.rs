//! The data disk: `init` finds it at boot -- a virtio-blk disk if there is one (the
//! fastest under QEMU), else the legacy IDE disk at secondary master (by bus-master DMA when the
//! controller can, else PIO) -- and then oxfs's partition on it (`OxideBSD-doc/RAM_FLOOR.md`
//! §3.4.5): the first GPT or MBR partition of oxfs's type (`part`). The kernel never partitions
//! or formats a disk (RAM_FLOOR.md §4.2.1): one without an oxfs partition, like no disk at all,
//! leaves oxfs the memory disk (`md`), empty until the mfsroot fills it. oxfs never knows which.
//! The disk, each partition and the memory disk become block devices (`kern::vfs_bdev`), the
//! root's chosen here; file systems read them through their handles. One disk, found once.
//!
//! Disks are named by bus (`virt0`, `ide0`; `nvme0`, `sata0`, `sda0`, `mmc0` when those drivers
//! exist), partitions `<disk>p<N>` (GPT) or `<disk>s<N>` (MBR). Each gets a raw device in `/dev`,
//! readable and writable by root, except that the root file system's can't be written while it's
//! mounted read-write (RAM_FLOOR.md §3.4.3: the writes would go around its cache).
//!
//! File systems reach their devices through `kern::vfs_bdev` and the buffer cache
//! (`kern::vfs_bio`); this file finds the disk and serves the raw `/dev` nodes.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use spin::Mutex;

use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use crate::serial_println;

const NONE: u8 = 0;
const ATA: u8 = 1;
const VIRTIO: u8 = 2;

/// The physical data disk's driver, `NONE` without one.
static BACKEND: AtomicU8 = AtomicU8::new(NONE);
/// Whether oxfs should mount the root read-only at boot (`set_root_readonly_at_boot`).
static ROOT_READONLY_AT_BOOT: AtomicBool = AtomicBool::new(false);

/// The disk's device numbers (Linux's, `OxideBSD-doc/DEVFS.md` §3.5): whole disk minor 0,
/// partition N minor N.
const IDE_MAJOR: u32 = 3;
const VIRTIO_MAJOR: u32 = 252;
/// `/dev/gpt/<label>`: another name for a labelled GPT partition (FreeBSD's `glabel`), minor N
/// for partition N of the one data disk.
const GPT_LABEL_MAJOR: u32 = 253;

/// Open raw devices: `real_fd -> block device handle` (`kern::vfs_bdev`). The offset is the
/// file's (`fs::fd`).
static RAW_OPEN: Mutex<alloc::collections::BTreeMap<u64, u32>> = Mutex::new(alloc::collections::BTreeMap::new());

/// Finds the data disk: virtio-blk first, then the IDE disk (setting up its DMA), else a memory
/// disk.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) {
    if super::virtio_blk::init(frame_allocator, mapper, phys_mem_offset) {
        BACKEND.store(VIRTIO, Ordering::Relaxed);
        attach("virt0", VIRTIO_MAJOR, phys_mem_offset);
        return;
    }
    super::ata::init();
    if super::ata::present() {
        super::ata::init_dma(frame_allocator, phys_mem_offset);
        BACKEND.store(ATA, Ordering::Relaxed);
        attach("ide0", IDE_MAJOR, phys_mem_offset);
    } else {
        init_memory(phys_mem_offset);
    }
}

/// The physical disk's size in 512-byte sectors.
fn disk_sectors() -> u64 {
    match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::capacity_sectors(),
        VIRTIO => super::virtio_blk::capacity_sectors(),
        _ => 0,
    }
}

/// Reads the partition table of the physical disk `name`, gives oxfs its partition, and
/// registers the raw devices.
fn attach(name: &str, major: u32, phys_mem_offset: VirtAddr) {
    use crate::kern::vfs_bdev;
    let sectors = disk_sectors();
    let parts = read_partitions();
    vfs_bdev::register(name, major, 0, 0, sectors, false);
    let _ = crate::fs::devfs::make_dev(name, major, 0, 0, 0, 0o600, raw_open);
    for p in &parts {
        let dev = alloc::format!("{name}{}", p.suffix());
        vfs_bdev::register(&dev, major, p.index, p.first_lba, p.sectors, false);
        let _ = crate::fs::devfs::make_dev(&dev, major, p.index, 0, 0, 0o600, raw_open);
        if let Some(label) = &p.label {
            let dev = alloc::format!("gpt/{label}");
            vfs_bdev::register(&dev, GPT_LABEL_MAJOR, p.index, p.first_lba, p.sectors, false);
            let _ = crate::fs::devfs::make_dev(&dev, GPT_LABEL_MAJOR, p.index, 0, 0, 0o600, raw_open);
        }
    }
    // oxfs's 4 KiB blocks: its partition must start on one (`Partition::blocks`).
    match choose_root(name, &parts).and_then(|p| Some((p, p.blocks()?))) {
        Some((p, (_, blocks))) => {
            if let Some(handle) = vfs_bdev::find(major, p.index) {
                vfs_bdev::set_root(handle);
            }
            serial_println!("[boot] disk: oxfs on {}{} ({} MiB)", name, p.suffix(), blocks / 256);
        }
        None => {
            serial_println!(
                "[boot] disk: no oxfs partition on {} (partition and newfs_oxfs it, or install a system image)",
                name
            );
            init_memory(phys_mem_offset);
        }
    }
}

/// oxfs's partition on disk `name`: the root device `/boot/fsconf` names (`/dev/virt0p1`, or
/// `/dev/gpt/<label>`), if it's on this disk; else the first oxfs partition.
fn choose_root<'a>(name: &str, parts: &'a [super::part::Partition]) -> Option<&'a super::part::Partition> {
    if let Some(device) = crate::kern::fsconf::root_device() {
        let spec = device.strip_prefix("/dev/").unwrap_or(&device);
        let named = parts.iter().find(|p| {
            alloc::format!("{name}{}", p.suffix()) == spec
                || p.label.as_deref().is_some_and(|l| spec.strip_prefix("gpt/") == Some(l))
        });
        match named {
            Some(p) => {
                serial_println!("[boot] disk: root {} (from /boot/fsconf)", device);
                return Some(p);
            }
            None => {
                serial_println!(
                    "[boot] disk: root {} (from /boot/fsconf) isn't on {} -- using its first oxfs partition",
                    device,
                    name
                );
            }
        }
    }
    parts.iter().find(|p| p.oxfs)
}

/// The physical disk's partitions, from its first 34 sectors.
fn read_partitions() -> Vec<super::part::Partition> {
    let mut head = alloc::vec![0u8; 5 * 4096];
    if !read_sectors(false, 0, &mut head) {
        return Vec::new();
    }
    super::part::read(&head)
}

/// Makes a memory disk of a quarter of RAM the data disk (`md`): with no real disk, or with
/// `no-ata`, where real disks aren't probed at all.
pub fn init_memory(phys_mem_offset: VirtAddr) {
    let blocks = crate::memory::usable_ram_bytes() / 4 / 4096;
    super::md::init(blocks, phys_mem_offset);
    let handle = crate::kern::vfs_bdev::register("md0", 0, 0, 0, blocks * 8, true);
    crate::kern::vfs_bdev::set_root(handle);
    serial_println!(
        "[boot] disk: no data disk -- a {} MiB memory disk this boot, nothing persists",
        blocks / 256
    );
}

/// `(transfers, completion interrupts)` on the data disk so far, for the boot log.
pub fn stats() -> (u64, u64) {
    match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::dma_stats(),
        VIRTIO => super::virtio_blk::stats(),
        _ => (0, 0),
    }
}

/// Reads whole sectors from `lba` of the physical disk (or of the memory disk, `memory`) into
/// `buf`: the block layer's way down (`kern::vfs_bdev`), unbounded -- the handle bounds it.
pub(crate) fn read_sectors(memory: bool, lba: u64, buf: &mut [u8]) -> bool {
    if memory {
        return super::md::read_sectors(lba, buf);
    }
    match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::read_disk_sectors(lba, buf).is_ok(),
        VIRTIO => super::virtio_blk::read_sectors(lba, buf),
        _ => false,
    }
}

/// Writes whole sectors at `lba`, durably.
pub(crate) fn write_sectors(memory: bool, lba: u64, buf: &[u8]) -> bool {
    if memory {
        return super::md::write_sectors(lba, buf);
    }
    match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::write_disk_sectors(lba, buf).is_ok(),
        VIRTIO => super::virtio_blk::write_sectors(lba, buf),
        _ => false,
    }
}

/// Asks oxfs to mount the root read-only (the real boot path, `kernel_main`).
pub fn set_root_readonly_at_boot() {
    ROOT_READONLY_AT_BOOT.store(true, Ordering::Relaxed);
}

/// For oxfs: `1` when it should mount the root read-only at boot. Never for the memory disk:
/// formatted moments ago, it has nothing to check, and no raw device to check it through.
pub extern "C" fn oxidebsd_root_readonly_at_boot() -> u64 {
    let on_memory = crate::kern::vfs_bdev::root()
        .and_then(crate::kern::vfs_bdev::extent)
        .is_some_and(|(_, _, memory)| memory);
    (ROOT_READONLY_AT_BOOT.load(Ordering::Relaxed) && !on_memory) as u64
}

/// For oxfs: it has its partition mounted read-write (`rw != 0`) or read-only.
pub extern "C" fn oxidebsd_root_mounted_rw(rw: u64) {
    if let Some(h) = crate::kern::vfs_bdev::root() {
        crate::kern::vfs_bdev::oxidebsd_bdev_set_mounted(h as u64, rw);
    }
}

/// Whether raw device `handle` overlaps a device a file system has mounted read-write.
fn overlaps_mounted(handle: u32) -> bool {
    crate::kern::vfs_bdev::extent(handle)
        .is_some_and(|(first, sectors, memory)| crate::kern::vfs_bdev::overlaps_mounted_rw(first, sectors, memory))
}

/// Opens raw device `major:minor`. Writing is refused (`EPERM`) for a device overlapping one a
/// file system has mounted read-write: the writes would go around its cache (RAM_FLOOR.md
/// §3.4.3). `fsck_oxfs` writes the root while it's read-only.
extern "C" fn raw_open(major: u64, minor: u64, flags: u64) -> i64 {
    const O_ACCMODE: u64 = 3;
    let Some(handle) = crate::kern::vfs_bdev::find(major as u32, minor as u32) else {
        return -(crate::syscall::ENXIO as i64);
    };
    if flags & O_ACCMODE != 0 && overlaps_mounted(handle) {
        return -(crate::syscall::EPERM as i64);
    }
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -(e as i64);
    }
    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    RAW_OPEN.lock().insert(real_fd, handle);
    crate::fs::fd::finstall(real_fd, &RAW_OPS, 0, crate::fs::fd::open_flag(flags), crate::fs::fd::FdKind::Module)
}

/// A raw disk or partition device's file operations: seekable, the kernel keeping the offset.
static RAW_OPS: crate::fs::fd::FileOps = crate::fs::fd::FileOps {
    flags: crate::fs::fd::DFLAG_SEEKABLE,
    read: Some(raw_read),
    write: Some(raw_write),
    close: Some(raw_close),
    ioctl: Some(raw_ioctl),
    sync: Some(raw_sync),
    ..crate::fs::fd::FileOps::NONE
};

/// `FileOps::ioctl`: the disk requests (`ioctl` below); `ENOTTY` for any other.
extern "C" fn raw_ioctl(real_fd: u64, request: u64, argp: u64) -> i64 {
    match ioctl(real_fd, request, argp) {
        Some(Ok(v)) => v as i64,
        Some(Err(e)) => -(e as i64),
        None => -(crate::syscall::ENOTTY as i64),
    }
}

/// `FileOps::sync`: nothing to do, every raw write goes straight to the disk.
extern "C" fn raw_sync(_real_fd: u64, _data_only: u64) -> i64 {
    0
}

/// Reads from the device at the descriptor's position (or `pread`'s offset), the whole sectors it
/// covers, stopping at the device's end. Uncached, as FreeBSD's raw devices are.
extern "C" fn raw_read(real_fd: u64, uio: *mut crate::kern::subr_uio::Uio, _flags: u64) -> i64 {
    use crate::kern::vfs_bdev;
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let Some(handle) = RAW_OPEN.lock().get(&real_fd).copied() else {
        return -(crate::syscall::EBADF as i64);
    };
    let Some((_, sectors, _)) = vfs_bdev::extent(handle) else {
        return -(crate::syscall::EBADF as i64);
    };
    // Seekable: the uio is always at an offset (FOF_OFFSET or FOF_NEXTOFF).
    let offset = uio.offset();
    let len = uio.resid().min((sectors * vfs_bdev::SECTOR).saturating_sub(offset));
    if len == 0 {
        return 0;
    }
    let (first, count) = covering_sectors(offset, len);
    let mut buf = alloc::vec![0u8; (count * vfs_bdev::SECTOR) as usize];
    if vfs_bdev::read(handle, first, &mut buf).is_err() {
        return -(crate::syscall::EIO as i64);
    }
    let at = (offset - first * vfs_bdev::SECTOR) as usize;
    match uio.uiomove_out(&buf[at..at + len as usize]) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

/// The sectors `[first, first + count)` covering `len` bytes at byte `offset`.
fn covering_sectors(offset: u64, len: u64) -> (u64, u64) {
    let sector = crate::kern::vfs_bdev::SECTOR;
    let first = offset / sector;
    (first, (offset + len).div_ceil(sector) - first)
}

/// Writes at the descriptor's position (or `pwrite`'s offset), the sectors it covers read,
/// patched and written back, stopping at the device's end. Refused again if a file system
/// mounted the device (or one overlapping it) read-write since the open.
extern "C" fn raw_write(real_fd: u64, uio: *mut crate::kern::subr_uio::Uio, _flags: u64) -> i64 {
    use crate::kern::vfs_bdev;
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let Some(handle) = RAW_OPEN.lock().get(&real_fd).copied() else {
        return -(crate::syscall::EBADF as i64);
    };
    if overlaps_mounted(handle) {
        return -(crate::syscall::EPERM as i64);
    }
    let Some((_, sectors, _)) = vfs_bdev::extent(handle) else {
        return -(crate::syscall::EBADF as i64);
    };
    let offset = uio.offset();
    let len = uio.resid().min((sectors * vfs_bdev::SECTOR).saturating_sub(offset));
    if len == 0 {
        return if uio.resid() == 0 { 0 } else { -(crate::syscall::ENOSPC as i64) };
    }
    let (first, count) = covering_sectors(offset, len);
    let mut buf = alloc::vec![0u8; (count * vfs_bdev::SECTOR) as usize];
    if vfs_bdev::read(handle, first, &mut buf).is_err() {
        return -(crate::syscall::EIO as i64);
    }
    let at = (offset - first * vfs_bdev::SECTOR) as usize;
    let n = match uio.uiomove_in(&mut buf[at..at + len as usize]) {
        Ok(n) => n,
        Err(e) => return -(e as i64),
    };
    if vfs_bdev::write(handle, first, &buf).is_err() {
        return -(crate::syscall::EIO as i64);
    }
    n as i64
}

/// `DIOCGSECTORSIZE`: a raw device's sector size (`u32`, always 512). FreeBSD's name in
/// `<sys/disk.h>`; the number is OxideBSD's own, `_IOR('d', 128, u32)` in musl's encoding.
pub const DIOCGSECTORSIZE: u64 = 0x8004_6480;
/// `DIOCGMEDIASIZE`: a raw device's size in bytes (`i64`, FreeBSD's `off_t`), so `newfs_oxfs`
/// can lay a filesystem out over it. `_IOR('d', 129, i64)`.
pub const DIOCGMEDIASIZE: u64 = 0x8008_6481;

/// The disk requests `ioctl(2)` answers on a raw device descriptor; `None` when `real_fd` isn't
/// one or `request` isn't a disk request, so `sys_ioctl` goes on to the others.
pub fn ioctl(real_fd: u64, request: u64, argp: u64) -> Option<Result<u64, u64>> {
    use crate::memory::usercopy::{UserPtr, copyout_val};
    if request != DIOCGSECTORSIZE && request != DIOCGMEDIASIZE {
        return None;
    }
    let handle = RAW_OPEN.lock().get(&real_fd).copied()?;
    let (_, sectors, _) = crate::kern::vfs_bdev::extent(handle)?;
    Some(if request == DIOCGSECTORSIZE {
        copyout_val(&512u32, UserPtr::new(argp)).map(|()| 0)
    } else {
        copyout_val(&((sectors * 512) as i64), UserPtr::new(argp)).map(|()| 0)
    })
}

extern "C" fn raw_close(real_fd: u64) -> i64 {
    RAW_OPEN.lock().remove(&real_fd);
    0
}

/// The data disk's name for the boot log and `/etc/fstab`: `virt0`, `ide0`, or empty.
#[allow(dead_code)]
pub fn disk_name() -> String {
    String::from(match BACKEND.load(Ordering::Relaxed) {
        VIRTIO => "virt0",
        ATA => "ide0",
        _ => "",
    })
}
