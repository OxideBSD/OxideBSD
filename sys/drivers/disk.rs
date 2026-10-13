//! The data disk: the one block device backing oxfs's persistence, behind the `oxidebsd_block_*`
//! exports oxfs calls. `init` picks the disk at boot -- a virtio-blk disk if there is one (the
//! fastest under QEMU), else the legacy IDE disk at secondary master (by bus-master DMA when the
//! controller can, else PIO) -- and then oxfs's partition on it (`OxideBSD-doc/RAM_FLOOR.md`
//! §3.4.5): the first GPT or MBR partition of oxfs's type (`part`). A disk without one is only
//! partitioned when the kernel was booted with `format-blank`; otherwise, as with no disk at all,
//! oxfs runs on a memory disk (`md`) this boot. oxfs never knows which. Not a general block
//! layer: one disk, found once.
//!
//! Disks are named by bus (`virt0`, `ide0`; `nvme0`, `sata0`, `sda0`, `mmc0` when those drivers
//! exist), partitions `<disk>p<N>` (GPT) or `<disk>s<N>` (MBR). Each gets a raw device in `/dev`,
//! readable by root (writing one waits for read-only mounts, RAM_FLOOR.md §3.4.3: under a
//! mounted file system it would go around its cache).
//!
//! Every export takes oxfs's 4 KiB blocks, numbered from the start of its partition, and returns
//! `0` or `-1`, the plain-integer convention modules need (no `alloc`, no rich types across the
//! boundary).

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use spin::Mutex;

use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use crate::serial_println;

const NONE: u8 = 0;
const ATA: u8 = 1;
const VIRTIO: u8 = 2;
const MEMORY: u8 = 3;

/// The physical data disk's driver, `NONE` without one.
static BACKEND: AtomicU8 = AtomicU8::new(NONE);
/// Whether oxfs is on the memory disk (no disk, no oxfs partition, or no probe at all) rather than
/// on a partition of `BACKEND`'s disk.
static ON_MEMORY: AtomicBool = AtomicBool::new(false);
/// oxfs's partition on the physical disk, in 4 KiB blocks.
static ROOT_START: AtomicU64 = AtomicU64::new(0);
static ROOT_BLOCKS: AtomicU64 = AtomicU64::new(0);

/// The disk's device numbers (Linux's, `OxideBSD-doc/DEVFS.md` §3.5): whole disk minor 0,
/// partition N minor N.
const IDE_MAJOR: u32 = 3;
const VIRTIO_MAJOR: u32 = 252;

/// A raw device: its number and the sectors it covers on the physical disk.
struct RawDev {
    major: u32,
    minor: u32,
    first_sector: u64,
    sectors: u64,
}

static RAW_DEVS: Mutex<Vec<RawDev>> = Mutex::new(Vec::new());
/// Open raw devices: `real_fd -> (first sector, sectors, read position in bytes)`.
static RAW_OPEN: Mutex<alloc::collections::BTreeMap<u64, (u64, u64, u64)>> =
    Mutex::new(alloc::collections::BTreeMap::new());

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

/// Reads the partition table of the physical disk `name`, gives oxfs its partition (writing a
/// fresh GPT first under `format-blank`, if it has none), and registers the raw devices.
fn attach(name: &str, major: u32, phys_mem_offset: VirtAddr) {
    let sectors = disk_sectors();
    let mut parts = read_partitions();
    if !parts.iter().any(|p| p.oxfs && p.blocks().is_some()) && crate::boot::format_blank() {
        serial_println!("[boot] disk: {} has no oxfs partition -- format-blank: writing a GPT", name);
        write_fresh_gpt(sectors);
        parts = read_partitions();
    }
    let mut devs = RAW_DEVS.lock();
    devs.push(RawDev { major, minor: 0, first_sector: 0, sectors });
    for p in &parts {
        devs.push(RawDev { major, minor: p.index, first_sector: p.first_lba, sectors: p.sectors });
    }
    drop(devs);
    let _ = crate::fs::devfs::make_dev(name, major, 0, 0, 0, 0o600, raw_open);
    for p in &parts {
        let dev = alloc::format!("{name}{}", p.suffix());
        let _ = crate::fs::devfs::make_dev(&dev, major, p.index, 0, 0, 0o600, raw_open);
    }
    match parts.iter().find(|p| p.oxfs).and_then(|p| Some((p, p.blocks()?))) {
        Some((p, (start, blocks))) => {
            ROOT_START.store(start, Ordering::Relaxed);
            ROOT_BLOCKS.store(blocks, Ordering::Relaxed);
            serial_println!("[boot] disk: oxfs on {}{} ({} MiB)", name, p.suffix(), blocks / 256);
        }
        None => {
            serial_println!(
                "[boot] disk: no oxfs partition on {} (boot with format-blank to make one)",
                name
            );
            init_memory(phys_mem_offset);
        }
    }
}

/// The physical disk's partitions, from its first 34 sectors.
fn read_partitions() -> Vec<super::part::Partition> {
    let mut head = alloc::vec![0u8; 5 * 4096];
    if read_physical(0, &mut head) != 0 {
        return Vec::new();
    }
    super::part::read(&head)
}

/// Writes a fresh GPT with one oxfs partition over the whole physical disk.
fn write_fresh_gpt(sectors: u64) {
    let (head, tail) = super::part::fresh_gpt(sectors, random_guid(), random_guid());
    // Both ends patched a whole block at a time: the tables needn't be block-aligned.
    patch_sectors(0, &head);
    patch_sectors(sectors - tail.len() as u64 / 512, &tail);
}

/// A random (version 4) GUID, in GPT's byte order.
fn random_guid() -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..8].copy_from_slice(&crate::random::kernel_random_u64().to_le_bytes());
    g[8..].copy_from_slice(&crate::random::kernel_random_u64().to_le_bytes());
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    g
}

/// Writes `bytes` at sector `first` of the physical disk, through the blocks covering them.
fn patch_sectors(first: u64, bytes: &[u8]) {
    let start_byte = first * 512;
    let end_byte = start_byte + bytes.len() as u64;
    let first_block = start_byte / 4096;
    let blocks = end_byte.div_ceil(4096) - first_block;
    let mut buf = alloc::vec![0u8; (blocks * 4096) as usize];
    let _ = read_physical(first_block, &mut buf);
    let at = (start_byte - first_block * 4096) as usize;
    buf[at..at + bytes.len()].copy_from_slice(bytes);
    let _ = write_physical(first_block, &buf);
}

/// Makes a memory disk of a quarter of RAM the data disk (`md`): with no real disk, or with
/// `no-ata`, where real disks aren't probed at all.
pub fn init_memory(phys_mem_offset: VirtAddr) {
    let blocks = crate::memory::usable_ram_bytes() / 4 / 4096;
    super::md::init(blocks, phys_mem_offset);
    ON_MEMORY.store(true, Ordering::Relaxed);
    serial_println!(
        "[boot] disk: no data disk -- a {} MiB memory disk this boot, nothing persists",
        blocks / 256
    );
}

/// Where oxfs's blocks live: `MEMORY`, or the physical disk's backend (at `ROOT_START`). When
/// nothing chose (no probe ran: a test kernel that loads oxfs without `init`), a memory disk, as
/// for a boot with no disk.
fn backend() -> u8 {
    if ON_MEMORY.load(Ordering::Relaxed) {
        return MEMORY;
    }
    let backend = BACKEND.load(Ordering::Relaxed);
    if backend != NONE {
        return backend;
    }
    match crate::module::phys_mem_offset() {
        Some(offset) => {
            init_memory(offset);
            MEMORY
        }
        None => NONE,
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

/// Blocks of the physical disk, from its start.
fn read_physical(start_block: u64, buf: &mut [u8]) -> i64 {
    let ok = match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::read_blocks(start_block, buf).is_ok(),
        VIRTIO => super::virtio_blk::read_blocks(start_block, buf),
        _ => false,
    };
    if ok { 0 } else { -1 }
}

fn write_physical(start_block: u64, buf: &[u8]) -> i64 {
    let ok = match BACKEND.load(Ordering::Relaxed) {
        ATA => super::ata::write_blocks(start_block, buf).is_ok(),
        VIRTIO => super::virtio_blk::write_blocks(start_block, buf),
        _ => false,
    };
    if ok { 0 } else { -1 }
}

/// Whether oxfs's blocks `[start, start + count)` lie inside its partition.
fn in_root(start: u64, count: u64) -> bool {
    start.checked_add(count).is_some_and(|end| end <= ROOT_BLOCKS.load(Ordering::Relaxed))
}

/// oxfs's blocks, numbered from the start of its partition (or of the memory disk).
fn read(start_block: u64, buf: &mut [u8]) -> i64 {
    match backend() {
        MEMORY => if super::md::read_blocks(start_block, buf) { 0 } else { -1 },
        NONE => -1,
        _ if !in_root(start_block, buf.len() as u64 / 4096) => -1,
        _ => read_physical(ROOT_START.load(Ordering::Relaxed) + start_block, buf),
    }
}

fn write(start_block: u64, buf: &[u8]) -> i64 {
    match backend() {
        MEMORY => if super::md::write_blocks(start_block, buf) { 0 } else { -1 },
        NONE => -1,
        _ if !in_root(start_block, buf.len() as u64 / 4096) => -1,
        _ => write_physical(ROOT_START.load(Ordering::Relaxed) + start_block, buf),
    }
}

/// Whether a data disk is attached this boot: `1` or `0`.
pub extern "C" fn oxidebsd_block_device_present() -> i64 {
    (backend() != NONE) as i64
}

/// The size of oxfs's partition (or the memory disk) in 4 KiB blocks, `0` without one.
pub extern "C" fn oxidebsd_block_device_blocks() -> u64 {
    match backend() {
        MEMORY => super::md::capacity_blocks(),
        NONE => 0,
        _ => ROOT_BLOCKS.load(Ordering::Relaxed),
    }
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

/// Opens raw device `major:minor`, read-only: `EPERM` for writing (RAM_FLOOR.md §3.4.3).
extern "C" fn raw_open(major: u64, minor: u64, flags: u64) -> i64 {
    const O_ACCMODE: u64 = 3;
    if flags & O_ACCMODE != 0 {
        return -(crate::syscall::EPERM as i64);
    }
    let extent = RAW_DEVS
        .lock()
        .iter()
        .find(|d| (d.major as u64, d.minor as u64) == (major, minor))
        .map(|d| (d.first_sector, d.sectors));
    let Some((first, sectors)) = extent else {
        return -(crate::syscall::ENXIO as i64);
    };
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -(e as i64);
    }
    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    RAW_OPEN.lock().insert(real_fd, (first, sectors, 0));
    let fd = crate::fs::fd::oxidebsd_register_fd_ops(real_fd, raw_read, raw_write, raw_close);
    crate::fs::fd::oxidebsd_set_fd_positioned(real_fd);
    fd
}

/// Reads from the device at the descriptor's position (or `pread`'s offset), in whole blocks of
/// the physical disk underneath, stopping at the device's end.
extern "C" fn raw_read(real_fd: u64, uio: *mut crate::kern::subr_uio::Uio, flags: u64) -> i64 {
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let Some((first, sectors, pos)) = RAW_OPEN.lock().get(&real_fd).copied() else {
        return -(crate::syscall::EBADF as i64);
    };
    let positioned = flags & crate::kern::subr_uio::FOF_OFFSET != 0;
    let offset = if positioned { crate::kern::subr_uio::oxidebsd_uio_offset(uio) } else { pos };
    let size = sectors * 512;
    let len = uio.resid().min(size.saturating_sub(offset));
    if len == 0 {
        return 0;
    }
    let start = first * 512 + offset;
    let first_block = start / 4096;
    let blocks = (start + len).div_ceil(4096) - first_block;
    let mut buf = alloc::vec![0u8; (blocks * 4096) as usize];
    if read_physical(first_block, &mut buf) != 0 {
        return -(crate::syscall::EIO as i64);
    }
    let at = (start - first_block * 4096) as usize;
    let n = match uio.uiomove_out(&buf[at..at + len as usize]) {
        Ok(n) => n,
        Err(e) => return -(e as i64),
    };
    if !positioned && let Some(entry) = RAW_OPEN.lock().get_mut(&real_fd) {
        entry.2 = offset + n as u64;
    }
    n as i64
}

extern "C" fn raw_write(_real_fd: u64, _uio: *mut crate::kern::subr_uio::Uio, _flags: u64) -> i64 {
    -(crate::syscall::EBADF as i64)
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
