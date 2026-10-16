//! oxfs's blocks through the kernel's buffer cache (kernel tree: `kern::vfs_bio`, OxideBSD-doc
//! `VFS.md` §7.4), on the root's block device. Every disk block oxfs touches -- superblock aside,
//! read and written straight through the device -- goes through here by its *device* block number,
//! 4 KiB each: data blocks, the inode file, directories, index blocks and the block-used bitmap.
//!
//! `write` puts a block on the disk before returning (structural metadata, RAM_FLOOR.md §3.3.1);
//! `store` leaves it dirty, tagged with what it is (`Kind`), for a later flush (a regular file's
//! data, index blocks and inode record, §3.3.2). While the filesystem is being formatted
//! (`write_through` false) even `write` only stores, and `flush_all` writes everything at the end.
//!
//! **Ordering (§3.3.3): a pointer never reaches the disk before what it points at.** The cache asks
//! oxfs before it writes any dirty block (`pre_write`, oxfs's hook): before an inode-file block,
//! the dirty data and index blocks of the inodes in it go; before an index block, its file's dirty
//! data blocks. So after a crash an inode on disk points only at blocks holding its own data (an
//! older size at worst), never at another file's freed contents. Index and inode-file blocks go
//! to the disk alone; data and plain metadata blocks may share a command with their neighbours.
//!
//! Everything is single-core and syscall-serialized, like the rest of oxfs; nothing may use the
//! cache from inside a `with` closure (the buffer is held only for the closure).

use crate::{BLOCK_SIZE, log};

unsafe extern "C" {
    fn oxidebsd_bdev_root() -> i64;
    fn oxidebsd_bdev_sectors(dev: u64) -> u64;
    fn oxidebsd_bdev_read(dev: u64, sector: u64, count: u64, buf: *mut u8) -> i64;
    fn oxidebsd_bdev_write(dev: u64, sector: u64, count: u64, buf: *const u8) -> i64;
    fn oxidebsd_bread(dev: u64, blkno: u64, size: u64, ahead: u64) -> i64;
    fn oxidebsd_getblk(dev: u64, blkno: u64, size: u64) -> i64;
    fn oxidebsd_bdata(b: u64) -> u64;
    fn oxidebsd_brelse(b: u64);
    fn oxidebsd_bdwrite(b: u64, tag: u64);
    fn oxidebsd_bwrite(b: u64, tag: u64) -> i64;
    fn oxidebsd_bflush(dev: u64, mask: u64, value: u64);
    fn oxidebsd_bdiscard(dev: u64, mask: u64, value: u64);
    fn oxidebsd_binval(dev: u64, blkno: u64);
    fn oxidebsd_binvalall(dev: u64);
    fn oxidebsd_bmostly_dirty() -> i64;
    fn oxidebsd_bio_set_hook(dev: u64, hook: extern "C" fn(u64, u64, u64) -> i64);
}

/// Blocks read on a miss after the missed one, stopping at one already cached. Programs and files
/// are mostly laid out contiguously (`alloc_block` is a forward cursor), so the next blocks are
/// usually wanted next.
const READ_AHEAD: u64 = 15;
/// Sectors per oxfs block.
const SECTORS: u64 = BLOCK_SIZE as u64 / 512;
/// Inodes per inode-file block (`INODES_PER_BLOCK` in the crate root).
const INODES_PER_BLOCK: u32 = 32;
/// The cache's answer bit for "may share a disk command" (kernel tree: `vfs_bio::HOOK_CLUSTER`).
const HOOK_CLUSTER: i64 = 1;

/// What a dirty block holds, for the write ordering: the buffer's tag is `kind << 32 | owner`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Anything written synchronously, or during a format: no ordering. Tag 0.
    Meta,
    /// A data block of regular file `owner`.
    Data(u32),
    /// An index (indirect) block of regular file `owner`.
    Index(u32),
    /// An inode-file block holding inodes `first .. first + INODES_PER_BLOCK`.
    Inodes(u32),
}

const META: u64 = 0;
const DATA: u64 = 1 << 32;
const INDEX: u64 = 2 << 32;
const INODES: u64 = 3 << 32;
const KIND: u64 = 0xffff_ffff << 32;
const ALL: u64 = u64::MAX;
/// An owner's inode-file block group: its inode number less the low bits.
const GROUP: u64 = KIND | (0xffff_ffff & !(INODES_PER_BLOCK as u64 - 1));

fn tag(kind: Kind) -> u64 {
    match kind {
        Kind::Meta => META,
        Kind::Data(o) => DATA | o as u64,
        Kind::Index(o) => INDEX | o as u64,
        Kind::Inodes(first) => INODES | first as u64,
    }
}

/// The root's block device, and whether `write` reaches the disk (false while formatting).
static mut DEV: u64 = 0;
static mut WRITE_THROUGH: bool = false;

fn dev() -> u64 {
    // SAFETY: set once in `init`, inside `module_init`; read-only after.
    unsafe { DEV }
}

/// The cache's pre-write hook for oxfs's device: writes what the block tagged `tag` points at.
extern "C" fn pre_write(dev: u64, _blkno: u64, tag: u64) -> i64 {
    let owner = tag & 0xffff_ffff;
    match tag & KIND {
        META | DATA => HOOK_CLUSTER,
        INDEX => {
            // SAFETY: FFI call to a kernel-exported function.
            unsafe { oxidebsd_bflush(dev, ALL, DATA | owner) };
            0
        }
        _ => {
            // An inode-file block's inodes are `owner .. owner + 32`, `owner` a multiple of 32.
            // SAFETY: as above.
            unsafe {
                oxidebsd_bflush(dev, GROUP, DATA | owner);
                oxidebsd_bflush(dev, GROUP, INDEX | owner);
            }
            0
        }
    }
}

/// Finds the root's device and gives the cache oxfs's ordering. Must run inside `module_init`.
pub fn init() -> bool {
    // SAFETY: FFI call to a kernel-exported function.
    let root = unsafe { oxidebsd_bdev_root() };
    if root < 0 {
        return false;
    }
    // SAFETY: inside `module_init`, before any syscall.
    unsafe {
        DEV = root as u64;
        oxidebsd_bio_set_hook(root as u64, pre_write);
    }
    true
}

/// Whether the root has a device this boot.
pub fn present() -> bool {
    // SAFETY: FFI call to a kernel-exported function.
    unsafe { oxidebsd_bdev_root() >= 0 }
}

/// The device's size in oxfs blocks.
pub fn device_blocks() -> u64 {
    // SAFETY: FFI calls to kernel-exported functions.
    unsafe {
        let root = oxidebsd_bdev_root();
        if root < 0 { 0 } else { oxidebsd_bdev_sectors(root as u64) / SECTORS }
    }
}

/// Reads device block `block` straight from the disk, around the cache (the superblock).
pub fn read_direct(block: u32, out: &mut [u8; BLOCK_SIZE]) -> bool {
    // SAFETY: FFI call; `out` holds one block.
    unsafe { oxidebsd_bdev_read(dev(), block as u64 * SECTORS, SECTORS, out.as_mut_ptr()) == 0 }
}

/// Writes device block `block` straight to the disk, durably, around the cache (the superblock).
pub fn write_direct(block: u32, data: &[u8; BLOCK_SIZE]) -> bool {
    // SAFETY: FFI call; `data` holds one block.
    unsafe { oxidebsd_bdev_write(dev(), block as u64 * SECTORS, SECTORS, data.as_ptr()) == 0 }
}

/// Whether the cache is mostly dirty: the writer should flush (back-pressure, §3.2.5).
pub fn mostly_dirty() -> bool {
    // SAFETY: FFI call to a kernel-exported function.
    unsafe { oxidebsd_bmostly_dirty() != 0 }
}

/// From now on, `write` reaches the disk before returning (until now, during a format, it only
/// stores).
pub fn set_write_through(on: bool) {
    // SAFETY: single-core, syscall-serialized.
    unsafe { WRITE_THROUGH = on };
}

fn block_bytes(b: u64) -> &'static mut [u8; BLOCK_SIZE] {
    // SAFETY: the kernel maps a held 4 KiB buffer's whole block at this address.
    unsafe { &mut *(oxidebsd_bdata(b) as *mut [u8; BLOCK_SIZE]) }
}

/// Runs `f` on device block `block`'s contents. `f` must not use the cache.
pub fn with<R>(block: u32, f: impl FnOnce(&[u8; BLOCK_SIZE]) -> R) -> R {
    // SAFETY: FFI call to a kernel-exported function.
    let b = unsafe { oxidebsd_bread(dev(), block as u64 * SECTORS, BLOCK_SIZE as u64, READ_AHEAD) };
    if b < 0 {
        log("[oxfs] cache: read failed\n");
        return f(&[0; BLOCK_SIZE]);
    }
    let r = f(block_bytes(b as u64));
    // SAFETY: as above; `b` is held.
    unsafe { oxidebsd_brelse(b as u64) };
    r
}

/// A copy of device block `block`.
pub fn read(block: u32) -> [u8; BLOCK_SIZE] {
    with(block, |b| *b)
}

/// The cache's buffer for `block`, held, filled with `data`.
fn put(block: u32, data: &[u8; BLOCK_SIZE]) -> Option<u64> {
    // SAFETY: FFI call to a kernel-exported function.
    let b = unsafe { oxidebsd_getblk(dev(), block as u64 * SECTORS, BLOCK_SIZE as u64) };
    if b < 0 {
        log("[oxfs] cache: no buffer\n");
        return None;
    }
    *block_bytes(b as u64) = *data;
    Some(b as u64)
}

/// Writes device block `block` (`kind` says what it is) to the disk before returning, after
/// anything it points at. While formatting, only stores it.
pub fn write(block: u32, data: &[u8; BLOCK_SIZE], kind: Kind) {
    let Some(b) = put(block, data) else { return };
    // SAFETY: FFI calls; `b` is held and handed back.
    unsafe {
        if WRITE_THROUGH {
            if oxidebsd_bwrite(b, tag(kind)) != 0 {
                log("[oxfs] cache: write failed\n");
            }
        } else {
            oxidebsd_bdwrite(b, tag(kind));
        }
    }
}

/// Stores `data` as device block `block`, dirty, for a later flush (§3.3.2).
pub fn store(block: u32, data: &[u8; BLOCK_SIZE], kind: Kind) {
    let Some(b) = put(block, data) else { return };
    // SAFETY: FFI call; `b` is held and handed back.
    unsafe { oxidebsd_bdwrite(b, tag(kind)) };
}

/// Drops device block `block` from the cache without writing it: the block was freed.
pub fn discard(block: u32) {
    // SAFETY: FFI call to a kernel-exported function.
    unsafe { oxidebsd_binval(dev(), block as u64 * SECTORS) };
}

/// Drops the dirty data and index blocks of file `owner` without writing them: it's being freed.
pub fn discard_owned(owner: u32) {
    // SAFETY: FFI calls to kernel-exported functions.
    unsafe {
        oxidebsd_bdiscard(dev(), ALL, DATA | owner as u64);
        oxidebsd_bdiscard(dev(), ALL, INDEX | owner as u64);
    }
}

/// `fsync(2)` of file `owner`: its data, its index blocks, then its inode-file block.
pub fn flush_file(owner: u32) {
    let first = owner - owner % INODES_PER_BLOCK;
    // SAFETY: FFI calls to kernel-exported functions.
    unsafe {
        oxidebsd_bflush(dev(), ALL, DATA | owner as u64);
        oxidebsd_bflush(dev(), ALL, INDEX | owner as u64);
        oxidebsd_bflush(dev(), ALL, INODES | first as u64);
    }
}

/// Writes every dirty block: data first, then index blocks, then inode-file blocks, then the rest.
pub fn flush_all() {
    // SAFETY: FFI calls to kernel-exported functions.
    unsafe {
        oxidebsd_bflush(dev(), KIND, DATA);
        oxidebsd_bflush(dev(), KIND, INDEX);
        oxidebsd_bflush(dev(), KIND, INODES);
        oxidebsd_bflush(dev(), 0, 0);
    }
}

/// Forgets every cached block (dirty ones included): the disk changed underneath the cache.
pub fn invalidate_all() {
    // SAFETY: FFI call to a kernel-exported function.
    unsafe { oxidebsd_binvalall(dev()) };
}
