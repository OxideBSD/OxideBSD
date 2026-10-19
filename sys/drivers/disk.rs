//! The disk registry (`OxideBSD-doc/INSTALLER.md` §5): `init` registers every disk the kernel
//! drives at boot -- each virtio-blk device (`virt0`, `virt1`, ... in PCI order), then each IDE
//! disk (`ide0`, ... in the order primary master, primary slave, secondary master, secondary
//! slave; ATA by bus-master DMA when the controller can, else PIO) -- with the partitions of each
//! (`part`: GPT, else MBR). Disks are named by bus, one counter per bus, optical drives counted
//! with disks (their kind is in `kern.disk.<name>.kind`); partitions are `<disk>p<N>` (GPT) or
//! `<disk>s<N>` (MBR), and labelled GPT partitions are also `gpt/<label>` (FreeBSD's `glabel`;
//! the first of a label wins). Each becomes a block device (`kern::vfs_bdev`) and a raw device in
//! `/dev`, readable and writable by root, except that a device overlapping one a file system has
//! mounted read-write can't be written (RAM_FLOOR.md §3.4.3: the writes would go around its
//! cache).
//!
//! The root is oxfs's partition `/boot/fsconf` names, on any disk, else the first oxfs partition
//! in registration order (RAM_FLOOR.md §3.4.5). The kernel never partitions or formats a disk
//! (RAM_FLOOR.md §4.2.1): with no oxfs partition anywhere, like no disk at all, oxfs gets the
//! memory disk (`md0`), empty until the mfsroot fills it. oxfs never knows which.
//!
//! The block layer addresses every disk in 512-byte sectors; a disk with larger ones (a CD's
//! 2048, INSTALLER.md §5.4) is translated here, partial sectors read whole (and written back
//! whole).
//!
//! File systems reach their devices through `kern::vfs_bdev` and the buffer cache
//! (`kern::vfs_bio`); this file finds the disks and serves the raw `/dev` nodes.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use super::ata::{Channel, Drive};
use super::part::Partition;
use crate::serial_println;

/// Which driver serves a disk, and which of its devices it is.
#[derive(Clone, Copy)]
enum Backend {
    Ata(Channel, Drive),
    Virtio(usize),
    Memory,
}

/// What a disk is (`kern.disk.<name>.kind`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Disk,
    Cd,
    Memory,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Disk => "disk",
            Kind::Cd => "cd",
            Kind::Memory => "memory",
        }
    }
}

/// One registered disk.
struct Disk {
    name: String,
    backend: Backend,
    kind: Kind,
    /// Its size in 512-byte sectors (the block layer's unit).
    sectors: u64,
    /// Its own sector size in bytes, a multiple of 512.
    sector_size: u32,
    model: String,
}

/// Every disk, in registration order: a disk's index here is its number for `kern::vfs_bdev`.
/// Grow-only.
static DISKS: Mutex<Vec<Disk>> = Mutex::new(Vec::new());
/// Whether oxfs should mount the root read-only at boot (`set_root_readonly_at_boot`).
static ROOT_READONLY_AT_BOOT: AtomicBool = AtomicBool::new(false);

/// Device numbers (Linux's majors, `OxideBSD-doc/DEVFS.md` §3.5), one major per driver: minor
/// `unit << 8` for a whole disk, `unit << 8 | N` for its partition N.
const IDE_MAJOR: u32 = 3;
const VIRTIO_MAJOR: u32 = 252;
/// `/dev/gpt/<label>`: another name for a labelled GPT partition, minors in the order found.
const GPT_LABEL_MAJOR: u32 = 253;
static NEXT_LABEL_MINOR: AtomicU32 = AtomicU32::new(0);

/// Open raw devices: `real_fd -> block device handle` (`kern::vfs_bdev`). The offset is the
/// file's (`fs::fd`).
static RAW_OPEN: Mutex<alloc::collections::BTreeMap<u64, u32>> = Mutex::new(alloc::collections::BTreeMap::new());

/// Adds a disk to the registry; its index.
fn register(name: String, backend: Backend, kind: Kind, sectors: u64, sector_size: u32, model: String) -> u32 {
    let mut disks = DISKS.lock();
    disks.push(Disk { name: name.clone(), backend, kind, sectors, sector_size, model });
    let index = (disks.len() - 1) as u32;
    drop(disks);
    crate::kern::kern_sysctl::disk_registered(name, index);
    index
}

/// Registers every disk: virtio-blk first, then the IDE disks (setting up their DMA); then their
/// partitions and `/dev` nodes, and the root (else a memory disk).
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) {
    let mut found = Vec::new();
    for (unit, sectors) in super::virtio_blk::init(frame_allocator, mapper, phys_mem_offset).into_iter().enumerate() {
        let name = alloc::format!("virt{unit}");
        let disk = register(name.clone(), Backend::Virtio(unit), Kind::Disk, sectors, 512, String::from("virtio-blk"));
        found.push((disk, name, VIRTIO_MAJOR, unit as u32));
    }
    super::ata::init();
    super::ata::init_dma(frame_allocator, phys_mem_offset);
    let mut unit = 0;
    for (channel, drive) in super::ata::POSITIONS {
        if !super::ata::present(channel, drive) {
            continue;
        }
        let name = alloc::format!("ide{unit}");
        let sectors = super::ata::capacity_sectors(channel, drive);
        let model = super::ata::model(channel, drive);
        let disk = register(name.clone(), Backend::Ata(channel, drive), Kind::Disk, sectors, 512, model);
        found.push((disk, name, IDE_MAJOR, unit));
        unit += 1;
    }

    let mut parts = Vec::new();
    for (disk, name, major, unit) in found {
        attach(disk, &name, major, unit, &mut parts);
    }
    // oxfs's 4 KiB blocks: its partition must start on one (`Partition::blocks`).
    match choose_root(&parts).and_then(|r| Some((r, r.part.blocks()?))) {
        Some((r, (_, blocks))) => {
            crate::kern::vfs_bdev::set_root(r.handle);
            serial_println!("[boot] disk: oxfs on {} ({} MiB)", r.name, blocks / 256);
        }
        None => {
            serial_println!(
                "[boot] disk: no usable oxfs partition on any disk (partition and newfs_oxfs one, or install a system image)"
            );
            init_memory(phys_mem_offset);
        }
    }
}

/// A partition found at boot: its `/dev` name, its block device, and where it is.
struct Found {
    name: String,
    handle: u32,
    part: Partition,
}

/// Reads disk `disk`'s partition table and registers the disk's block devices and raw `/dev`
/// nodes; adds its partitions to `parts`.
fn attach(disk: u32, name: &str, major: u32, unit: u32, parts: &mut Vec<Found>) {
    use crate::kern::vfs_bdev;
    let sectors = DISKS.lock()[disk as usize].sectors;
    let minor = unit << 8;
    vfs_bdev::register(name, major, minor, 0, sectors, disk);
    let _ = crate::fs::devfs::make_dev(name, major, minor, 0, 0, 0o600, raw_open);
    let mut head = alloc::vec![0u8; 5 * 4096];
    let table = if read_sectors(disk, 0, &mut head) { super::part::read(&head) } else { Vec::new() };
    for p in table {
        if p.index > 0xff || p.first_lba.checked_add(p.sectors).is_none_or(|end| end > sectors) {
            serial_println!("[boot] disk: {}: partition {} lies outside the disk -- ignored", name, p.index);
            continue;
        }
        let dev = alloc::format!("{name}{}", p.suffix());
        let handle = vfs_bdev::register(&dev, major, minor | p.index, p.first_lba, p.sectors, disk);
        let _ = crate::fs::devfs::make_dev(&dev, major, minor | p.index, 0, 0, 0o600, raw_open);
        if let Some(label) = &p.label {
            let label_dev = alloc::format!("gpt/{label}");
            let label_minor = NEXT_LABEL_MINOR.fetch_add(1, Ordering::Relaxed);
            if crate::fs::devfs::make_dev(&label_dev, GPT_LABEL_MAJOR, label_minor, 0, 0, 0o600, raw_open).is_ok() {
                vfs_bdev::register(&label_dev, GPT_LABEL_MAJOR, label_minor, p.first_lba, p.sectors, disk);
            } else {
                serial_println!("[boot] disk: {}: label {} is taken -- only {} names it", name, label_dev, dev);
            }
        }
        parts.push(Found { name: dev, handle, part: p });
    }
}

/// The root's partition: the device `/boot/fsconf` names (`/dev/virt0p1`, or `/dev/gpt/<label>`),
/// on whichever disk; else the first oxfs partition, with a word when there are several to choose
/// from (an `/etc/fstab` root entry settles it).
fn choose_root(parts: &[Found]) -> Option<&Found> {
    if let Some(device) = crate::kern::fsconf::root_device() {
        let spec = device.strip_prefix("/dev/").unwrap_or(&device);
        let named = parts.iter().find(|f| {
            f.name == spec || f.part.label.as_deref().is_some_and(|l| spec.strip_prefix("gpt/") == Some(l))
        });
        match named {
            Some(f) => {
                serial_println!("[boot] disk: root {} (from /boot/fsconf)", device);
                return Some(f);
            }
            None => {
                serial_println!(
                    "[boot] disk: root {} (from /boot/fsconf) isn't on any disk -- using the first oxfs partition",
                    device
                );
            }
        }
    }
    let mut oxfs = parts.iter().filter(|f| f.part.oxfs);
    let first = oxfs.next()?;
    if oxfs.next().is_some() {
        serial_println!(
            "[boot] disk: several oxfs partitions and no root entry in /boot/fsconf -- using {}; add a root entry to /etc/fstab",
            first.name
        );
    }
    Some(first)
}

/// Makes a memory disk of a quarter of RAM the root (`md0`): with no oxfs partition on any disk, or
/// with `no-ata`, where real disks aren't probed at all.
pub fn init_memory(phys_mem_offset: VirtAddr) {
    let blocks = crate::memory::usable_ram_bytes() / 4 / 4096;
    super::md::init(blocks, phys_mem_offset);
    let disk = register(String::from("md0"), Backend::Memory, Kind::Memory, blocks * 8, 512, String::from("memory disk"));
    let handle = crate::kern::vfs_bdev::register("md0", 0, 0, 0, blocks * 8, disk);
    crate::kern::vfs_bdev::set_root(handle);
    serial_println!(
        "[boot] disk: no data disk -- a {} MiB memory disk this boot, nothing persists",
        blocks / 256
    );
}

/// `(transfers, completion interrupts)` on the disks so far, for the boot log.
pub fn stats() -> (u64, u64) {
    let (ata_transfers, ata_irqs) = super::ata::dma_stats();
    let (virtio_transfers, virtio_irqs) = super::virtio_blk::stats();
    (ata_transfers + virtio_transfers, ata_irqs + virtio_irqs)
}

/// The space-separated names of the registered disks (`kern.disks`).
pub fn names() -> String {
    let disks = DISKS.lock();
    let names: Vec<&str> = disks.iter().map(|d| d.name.as_str()).collect();
    names.join(" ")
}

/// Disk `disk`'s `(kind, size in bytes, sector size, model)` (`kern.disk.<name>`).
pub fn describe(disk: u32) -> Option<(&'static str, u64, u32, String)> {
    let disks = DISKS.lock();
    let d = disks.get(disk as usize)?;
    Some((d.kind.name(), d.sectors * 512, d.sector_size, d.model.clone()))
}

/// Whether disk `disk` is the memory disk.
fn is_memory(disk: u32) -> bool {
    DISKS.lock().get(disk as usize).is_some_and(|d| d.kind == Kind::Memory)
}

/// Disk `disk`'s driver and sector size. The registry's lock is dropped before any I/O: a
/// transfer may sleep.
fn backend(disk: u32) -> Option<(Backend, u64)> {
    DISKS.lock().get(disk as usize).map(|d| (d.backend, d.sector_size as u64))
}

/// Reads whole device sectors from device sector `lba`.
fn device_read(backend: Backend, lba: u64, buf: &mut [u8]) -> bool {
    match backend {
        Backend::Ata(channel, drive) => super::ata::read_disk_sectors(channel, drive, lba, buf).is_ok(),
        Backend::Virtio(unit) => super::virtio_blk::read_sectors(unit, lba, buf),
        Backend::Memory => super::md::read_sectors(lba, buf),
    }
}

/// Writes whole device sectors at device sector `lba`, durably.
fn device_write(backend: Backend, lba: u64, buf: &[u8]) -> bool {
    match backend {
        Backend::Ata(channel, drive) => super::ata::write_disk_sectors(channel, drive, lba, buf).is_ok(),
        Backend::Virtio(unit) => super::virtio_blk::write_sectors(unit, lba, buf),
        Backend::Memory => super::md::write_sectors(lba, buf),
    }
}

/// The device sectors `[first, first + count)` (of `sector_size` bytes) covering 512-byte
/// sectors `[lba, lba + n)`, and the byte offset of `lba` in the first.
fn covering(sector_size: u64, lba: u64, n: u64) -> (u64, u64, usize) {
    let per = sector_size / 512;
    let first = lba / per;
    (first, (lba + n).div_ceil(per) - first, ((lba % per) * 512) as usize)
}

/// Reads whole 512-byte sectors from `lba` of disk `disk` into `buf`: the block layer's way down
/// (`kern::vfs_bdev`), unbounded -- the handle bounds it.
pub(crate) fn read_sectors(disk: u32, lba: u64, buf: &mut [u8]) -> bool {
    let Some((backend, sector_size)) = backend(disk) else { return false };
    let (first, count, at) = covering(sector_size, lba, buf.len() as u64 / 512);
    if at == 0 && buf.len() as u64 == count * sector_size {
        return device_read(backend, first, buf);
    }
    let mut whole = alloc::vec![0u8; (count * sector_size) as usize];
    if !device_read(backend, first, &mut whole) {
        return false;
    }
    buf.copy_from_slice(&whole[at..at + buf.len()]);
    true
}

/// Writes whole 512-byte sectors at `lba` of disk `disk`, durably; a partial device sector is
/// read, patched and written back.
pub(crate) fn write_sectors(disk: u32, lba: u64, buf: &[u8]) -> bool {
    let Some((backend, sector_size)) = backend(disk) else { return false };
    let (first, count, at) = covering(sector_size, lba, buf.len() as u64 / 512);
    if at == 0 && buf.len() as u64 == count * sector_size {
        return device_write(backend, first, buf);
    }
    let mut whole = alloc::vec![0u8; (count * sector_size) as usize];
    if !device_read(backend, first, &mut whole) {
        return false;
    }
    whole[at..at + buf.len()].copy_from_slice(buf);
    device_write(backend, first, &whole)
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
        .is_some_and(|(_, _, disk)| is_memory(disk));
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
        .is_some_and(|(first, sectors, disk)| crate::kern::vfs_bdev::overlaps_mounted_rw(first, sectors, disk))
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

/// `DIOCGSECTORSIZE`: a raw device's sector size (`u32`: its disk's, 512 or a CD's 2048).
/// FreeBSD's name in `<sys/disk.h>`; the number is OxideBSD's own, `_IOR('d', 128, u32)` in musl's
/// encoding.
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
    let (_, sectors, disk) = crate::kern::vfs_bdev::extent(handle)?;
    Some(if request == DIOCGSECTORSIZE {
        let sector_size = backend(disk).map_or(512, |(_, size)| size as u32);
        copyout_val(&sector_size, UserPtr::new(argp)).map(|()| 0)
    } else {
        copyout_val(&((sectors * 512) as i64), UserPtr::new(argp)).map(|()| 0)
    })
}

extern "C" fn raw_close(real_fd: u64) -> i64 {
    RAW_OPEN.lock().remove(&real_fd);
    0
}
