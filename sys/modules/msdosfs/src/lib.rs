//! msdosfs (OxideBSD-doc `VFS.md` §9, `msdosfs(5)`): the FAT file system, FAT12, FAT16 and FAT32
//! with long names, FreeBSD's `mount_msdosfs(8)` in its semantics. The on-disk format is
//! `lib/libmsdosfs`'s, shared with makefs(8), newfs_msdos(8) and fsck_msdosfs(8).
//!
//! Every block goes through the kernel's buffer cache (`kern::vfs_bio`) on the mount's device, on
//! a grid that never overlaps: each copy of the FAT in 4 KiB pieces (the last one shorter), the
//! FAT12/16 root directory's fixed area likewise, and the data area in clusters. The boot sector
//! and FAT32's FSInfo are read and written around the cache.
//!
//! FAT keeps no owners, modes or links. Every file is owned by the mount's `uid` and `gid` (by
//! default the mount point's), with permission `mask` (`dirmask` for directories; by default the
//! mount point's mode); the read-only attribute takes the write bits away. Names are
//! case-insensitive and case-preserving: a lookup matches a long name or the short alias, either
//! in any case (`libmsdosfs::same_name`). `shortnames` shows and makes only 8.3 names. Short names
//! are in a code page: CP437 unless `cs_dos` gave a compiled table (mount_msdosfs(8)'s `-D`).
//!
//! A file's ID is where its directory entry is (byte offset on the device / 32), as FreeBSD's;
//! a directory's is where its first cluster is, so `..` from below and its entry from above name
//! the same vnode, and renaming a directory keeps it. The root's is 1. FAT stores local time
//! (`kern.utc_offset`, `adjkerntz(8)`).
//!
//! A FAT16 or FAT32 volume not marked clean (the clean bit in FAT entry 1) is mounted read-only
//! unless the mount is forced (`mount -f`), as there may be damage only fsck_msdosfs(8) should
//! repair. Mounted read-write, the bit is cleared until unmount.
//!
//! **Ordering: a crash leaves only what `fsck_msdosfs -p` repairs** (lost clusters, a chain longer
//! or shorter than its file, FAT copies that differ). Dirty buffers are tagged data, FAT or
//! directory, and the cache's pre-write hook writes every dirty FAT buffer before a directory one
//! and every dirty data buffer before a FAT one: an entry never reaches the disk naming clusters
//! the FAT doesn't give it. What frees clusters writes the directory entry first, synchronously,
//! and frees them after: an entry never names a free cluster. A rename removes the old entry
//! before writing the new one (a crash between loses the name: fsck saves the chain as
//! `LOST.DIR/FILEnnnn.CHK`), never leaving two entries sharing a chain. A new directory's cluster
//! is on the disk before the entry naming it.
#![no_std]

extern crate alloc;
use kern_mod as _;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

use msdosfs_format::codepage::Codepage;
use msdosfs_format::fat::{self, Entry};
use msdosfs_format::*;
use vfs_if::*;

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_uiomove(kbuf: *mut u8, len: u64, uio: u64) -> i64;
    fn oxidebsd_uio_resid(uio: u64) -> u64;
    fn oxidebsd_uio_offset(uio: u64) -> u64;
    fn oxidebsd_uio_set_offset(uio: u64, offset: u64);
    fn oxidebsd_module_serialize();
    fn oxidebsd_vop_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32;
    fn oxidebsd_utc_offset() -> i32;
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
    fn oxidebsd_binval(dev: u64, blkno: u64);
    fn oxidebsd_binvalall(dev: u64);
    fn oxidebsd_bio_set_hook(dev: u64, hook: extern "C" fn(u64, u64, u64) -> i64);
    fn oxidebsd_unix_time() -> i64;
}

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const ENXIO: i32 = 6;
const ENOMEM: i32 = 12;
const EFAULT: i32 = 14;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const EFBIG: i32 = 27;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;
const ENAMETOOLONG: i32 = 36;
const ENOTEMPTY: i32 = 39;
const EOPNOTSUPP: i32 = 95;

/// The device's sector, which bio and bdev count in.
const SECTOR: u64 = 512;
/// The FAT and the fixed root are cached in pieces of this many bytes.
const PIECE: u64 = 4096;
/// The root directory's file ID: no directory entry can be at byte 32.
const ROOT_ID: u64 = 1;
/// Linux's `MSDOS_SUPER_MAGIC`, `statfs(2)`'s `f_type`.
const MSDOS_MAGIC: u64 = 0x4d44;
/// Clusters read ahead of a file's cluster on a miss.
const READ_AHEAD: u64 = 15;
/// File IDs given to removed files still open (`Node::unlinked`): their entry's slot may be taken
/// by a new file, which must get a vnode of its own.
const ORPHAN_ID: u64 = 1 << 62;

/// Buffer tags, for the write ordering (`pre_write`): `kind << 32`.
const TAG_DATA: u64 = 1 << 32;
const TAG_FAT: u64 = 2 << 32;
const TAG_DIR: u64 = 3 << 32;
const TAG_KIND: u64 = 0xffff_ffff << 32;
/// The cache's answer bit for "may share a disk command" (kernel tree: `vfs_bio::HOOK_CLUSTER`).
const HOOK_CLUSTER: i64 = 1;

/// The cache's pre-write hook: a directory buffer goes after every dirty FAT buffer, a FAT buffer
/// after every dirty data buffer.
extern "C" fn pre_write(dev: u64, _blkno: u64, tag: u64) -> i64 {
    // SAFETY: kernel export.
    match tag & TAG_KIND {
        TAG_DIR => unsafe {
            oxidebsd_bflush(dev, TAG_KIND, TAG_DATA);
            oxidebsd_bflush(dev, TAG_KIND, TAG_FAT);
            0
        },
        TAG_FAT => unsafe {
            oxidebsd_bflush(dev, TAG_KIND, TAG_DATA);
            0
        },
        _ => HOOK_CLUSTER,
    }
}

static ORPHANS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn log(s: &str) {
    // SAFETY: kernel export.
    unsafe { oxidebsd_log(s.as_ptr(), s.len() as u64) };
}

// --- The mount -------------------------------------------------------------------------------

struct Fs {
    dev: u64,
    bpb: Bpb,
    kind: FatType,
    /// Bytes per FAT sector and per cluster; the last cluster's number.
    bps: u64,
    cb: u64,
    max: u32,
    /// Byte offsets on the device: the first FAT, the fixed root (FAT12/16), the data area.
    fat_at: u64,
    fat_bytes: u64,
    root_at: u64,
    root_bytes: u64,
    data_at: u64,
    /// The root directory's first cluster: FAT32's, or 0 for the fixed area.
    root_first: u32,
    uid: u32,
    gid: u32,
    mask: u32,
    dirmask: u32,
    shortnames: bool,
    /// A compiled code page table (`cs_dos`), or empty for CP437.
    codepage: Vec<u8>,
    /// Free clusters, once known, and where to look for the next one.
    free: Option<u32>,
    next_free: u32,
    /// Mounted read-write (the clean bit is cleared).
    rw: bool,
}

impl Fs {
    fn codepage(&self) -> Codepage<'_> {
        if self.codepage.is_empty() { Codepage::Cp437 } else { Codepage::parse(&self.codepage).unwrap_or(Codepage::Cp437) }
    }

    fn cluster_at(&self, c: u32) -> u64 {
        self.data_at + (c - FIRST_CLUSTER) as u64 * self.cb
    }

    fn dir_id(&self, c: u32) -> u64 {
        if c == 0 || c == self.root_first { ROOT_ID } else { self.cluster_at(c) / 32 }
    }

    fn valid_cluster(&self, c: u32) -> bool {
        (FIRST_CLUSTER..=self.max).contains(&c)
    }

    /// FAT entry `c` (copy 0).
    fn fat_get(&self, c: u32) -> Result<u32, i32> {
        let off = fat::entry_offset(self.kind, c) as u64;
        let mut w = [0u8; 4];
        let n = self.kind.window() as u64;
        // The window may straddle two pieces (FAT12).
        let mut done = 0u64;
        while done < n {
            let at = off + done;
            let piece = at / PIECE;
            let len = PIECE.min(self.fat_bytes - piece * PIECE);
            let within = at % PIECE;
            let take = (n - done).min(len - within);
            with_block(self.dev, self.fat_at + piece * PIECE, len, 0, |b| {
                w[done as usize..(done + take) as usize].copy_from_slice(&b[within as usize..(within + take) as usize]);
            })?;
            done += take;
        }
        Ok(fat::get(self.kind, c, &w))
    }

    fn entry(&self, c: u32) -> Result<Entry, i32> {
        Ok(self.kind.classify(self.fat_get(c)?, self.max))
    }

    /// The cluster after `c` in its chain, or `None` at the end (or at anything that can't
    /// continue a chain, which fsck_msdosfs reports).
    fn next(&self, c: u32) -> Result<Option<u32>, i32> {
        Ok(match self.entry(c)? {
            Entry::Next(n) => Some(n),
            _ => None,
        })
    }

    /// Clusters in the chain from `first` (at most `max`, so a loop ends).
    fn chain_len(&self, first: u32) -> Result<u32, i32> {
        let mut n = 0;
        let mut c = first;
        while self.valid_cluster(c) && n < self.max {
            n += 1;
            match self.next(c)? {
                Some(x) => c = x,
                None => break,
            }
        }
        Ok(n)
    }

    fn count_free(&mut self) -> Result<u32, i32> {
        if let Some(f) = self.free {
            return Ok(f);
        }
        let mut free = 0;
        for c in FIRST_CLUSTER..=self.max {
            if self.fat_get(c)? == 0 {
                free += 1;
            }
        }
        self.free = Some(free);
        Ok(free)
    }

    /// Sets FAT entry `c` to `v` in every copy, delayed (`sync`: on the disk at once).
    fn fat_set(&mut self, c: u32, v: u32, sync: bool) -> Result<(), i32> {
        let off = fat::entry_offset(self.kind, c) as u64;
        let n = self.kind.window() as u64;
        for copy in 0..self.bpb.fats as u64 {
            let base = self.fat_at + copy * self.fat_bytes;
            // The window, gathered from its (one or two) pieces, changed, and put back.
            let mut w = [0u8; 4];
            let mut done = 0u64;
            while done < n {
                let at = off + done;
                let piece = at / PIECE;
                let len = PIECE.min(self.fat_bytes - piece * PIECE);
                let within = at % PIECE;
                let take = (n - done).min(len - within);
                with_block(self.dev, base + piece * PIECE, len, 0, |b| {
                    w[done as usize..(done + take) as usize].copy_from_slice(&b[within as usize..(within + take) as usize]);
                })?;
                done += take;
            }
            fat::set(self.kind, c, &mut w, v);
            let mut done = 0u64;
            while done < n {
                let at = off + done;
                let piece = at / PIECE;
                let len = PIECE.min(self.fat_bytes - piece * PIECE);
                let within = at % PIECE;
                let take = (n - done).min(len - within);
                with_block_mut(self.dev, base + piece * PIECE, len, false, TAG_FAT, sync, |b| {
                    b[within as usize..(within + take) as usize].copy_from_slice(&w[done as usize..(done + take) as usize]);
                })?;
                done += take;
            }
        }
        Ok(())
    }

    /// `n` new clusters chained, the first linked after `after` if given; the first. Each is
    /// zeroed (a file reads zeros where it was never written). `ENOSPC` takes nothing.
    fn alloc(&mut self, n: u32, after: Option<u32>) -> Result<u32, i32> {
        if n == 0 {
            return Err(EINVAL);
        }
        if self.count_free()? < n {
            return Err(ENOSPC);
        }
        let mut got: Vec<u32> = Vec::new();
        got.try_reserve(n as usize).map_err(|_| ENOMEM)?;
        let total = self.max - 1;
        let mut c = if self.valid_cluster(self.next_free) { self.next_free } else { FIRST_CLUSTER };
        let mut looked = 0;
        while (got.len() as u32) < n && looked < total {
            if self.fat_get(c)? == 0 {
                got.push(c);
            }
            c = if c >= self.max { FIRST_CLUSTER } else { c + 1 };
            looked += 1;
        }
        if (got.len() as u32) < n {
            self.free = Some(0);
            return Err(ENOSPC);
        }
        // The chain ends first, so a crash part way leaves lost clusters, not a broken chain.
        for i in (0..got.len()).rev() {
            let v = if i + 1 == got.len() { self.kind.eoc() } else { got[i + 1] };
            self.fat_set(got[i], v, false)?;
            self.zero_cluster(got[i])?;
        }
        if let Some(prev) = after {
            self.fat_set(prev, got[0], false)?;
        }
        self.next_free = c;
        self.free = self.free.map(|f| f - n);
        Ok(got[0])
    }

    /// Frees the chain from `first` (bounded by `max`, so a loop ends).
    fn free_chain(&mut self, first: u32) -> Result<(), i32> {
        let mut c = first;
        let mut steps = 0;
        while self.valid_cluster(c) && steps < self.max {
            let next = self.fat_get(c)?;
            self.fat_set(c, 0, false)?;
            // SAFETY: kernel export: the cluster's cached contents needn't reach the disk.
            unsafe { oxidebsd_binval(self.dev, self.cluster_at(c) / SECTOR) };
            self.free = self.free.map(|f| f + 1);
            steps += 1;
            match self.kind.classify(next, self.max) {
                Entry::Next(n) => c = n,
                _ => break,
            }
        }
        Ok(())
    }

    fn zero_cluster(&self, c: u32) -> Result<(), i32> {
        with_block_new(self.dev, self.cluster_at(c), self.cb, TAG_DATA, false, |b| b.fill(0))
    }

    /// The block of the grid holding device byte `at` of a directory: `(start, size)`.
    fn dir_block_of(&self, at: u64) -> (u64, u64) {
        if at < self.data_at {
            let piece = (at - self.root_at) / PIECE * PIECE;
            (self.root_at + piece, PIECE.min(self.root_bytes - piece))
        } else {
            (self.data_at + (at - self.data_at) / self.cb * self.cb, self.cb)
        }
    }

    /// Rewrites the directory entry at device byte `at` with `f` (delayed, or `sync`).
    fn put_entry(&self, at: u64, sync: bool, f: impl FnOnce(&mut [u8])) -> Result<(), i32> {
        let (start, size) = self.dir_block_of(at);
        let within = (at - start) as usize;
        with_block_mut(self.dev, start, size, false, TAG_DIR, sync, |b| f(&mut b[within..within + DIR_ENTRY_SIZE]))
    }

    /// FAT entry 1's clean bit set (`clean`) or cleared, on the disk at once.
    fn set_clean(&mut self, clean: bool) -> Result<(), i32> {
        let Some(bit) = self.kind.clean_bit() else { return Ok(()) };
        let e1 = self.fat_get(1)?;
        let want = if clean { e1 | bit } else { e1 & !bit };
        if want != e1 {
            self.fat_set(1, want, true)?;
        }
        Ok(())
    }

    /// FAT32's FSInfo: the free count and next free cluster, written around the cache.
    fn write_fsinfo(&mut self) -> Result<(), i32> {
        if self.kind != FatType::Fat32 || self.bpb.fsinfo_sector == 0 || self.bpb.fsinfo_sector == 0xFFFF {
            return Ok(());
        }
        let free = self.count_free()?;
        let mut s = [0u8; 4096];
        let n = self.bps as usize;
        write_fsinfo(&mut s[..n], free, self.next_free);
        let sector = self.bpb.fsinfo_sector as u64 * self.bps / SECTOR;
        // SAFETY: kernel export, with this module's buffer of `n` bytes.
        if unsafe { oxidebsd_bdev_write(self.dev, sector, n as u64 / SECTOR, s.as_ptr()) } != 0 {
            return Err(EIO);
        }
        Ok(())
    }
}

fn fs(mp: *mut Mount) -> &'static mut Fs {
    // SAFETY: `mnt_data` holds the pointer `msdosfs_mount` stored, live until unmount.
    unsafe { &mut **((*mp).mnt_data as *mut *mut Fs) }
}

/// Runs `f` on `size` bytes of the device at byte `at` (a block of the grid), through the cache.
fn with_block<R>(dev: u64, at: u64, size: u64, ahead: u64, f: impl FnOnce(&[u8]) -> R) -> Result<R, i32> {
    // SAFETY: kernel export.
    let b = unsafe { oxidebsd_bread(dev, at / SECTOR, size, ahead) };
    if b < 0 {
        return Err(EIO);
    }
    // SAFETY: the kernel maps a held buffer's whole block at its data address.
    let bytes = unsafe { core::slice::from_raw_parts(oxidebsd_bdata(b as u64) as *const u8, size as usize) };
    let r = f(bytes);
    // SAFETY: `b` is held.
    unsafe { oxidebsd_brelse(b as u64) };
    Ok(r)
}

/// Runs `f` on a block to change it (read first unless `fresh`), then gives it back dirty with
/// `tag`, or (`sync`) writes it at once, after what the hook says it depends on.
fn with_block_mut<R>(dev: u64, at: u64, size: u64, fresh: bool, tag: u64, sync: bool, f: impl FnOnce(&mut [u8]) -> R) -> Result<R, i32> {
    // SAFETY: kernel exports.
    let b = unsafe { if fresh { oxidebsd_getblk(dev, at / SECTOR, size) } else { oxidebsd_bread(dev, at / SECTOR, size, 0) } };
    if b < 0 {
        return Err(EIO);
    }
    // SAFETY: as `with_block`.
    let bytes = unsafe { core::slice::from_raw_parts_mut(oxidebsd_bdata(b as u64) as *mut u8, size as usize) };
    let r = f(bytes);
    // SAFETY: `b` is held and handed back.
    unsafe {
        if sync {
            if oxidebsd_bwrite(b as u64, tag) != 0 {
                return Err(EIO);
            }
        } else {
            oxidebsd_bdwrite(b as u64, tag);
        }
    }
    Ok(r)
}

/// As `with_block_mut` for a block `f` overwrites whole: not read first.
fn with_block_new(dev: u64, at: u64, size: u64, tag: u64, sync: bool, f: impl FnOnce(&mut [u8])) -> Result<(), i32> {
    with_block_mut(dev, at, size, true, tag, sync, f)
}

// --- Nodes -------------------------------------------------------------------------------------

/// What a vnode's `v_data` points at: the file's directory entry as last read.
struct Node {
    is_dir: bool,
    is_root: bool,
    first: u32,
    size: u32,
    attr: u8,
    created: DosTime,
    modified: DosTime,
    accessed: u16,
    /// Where the short entry is: its directory's first cluster (0: the fixed root), its slot, how
    /// many long-name slots come before it, and its device byte offset. `None` for the root.
    entry: Option<(u32, u32, u32, u64)>,
    /// The last position a read reached in the chain: (cluster index, cluster).
    cursor: (u32, u32),
    /// Its name was removed while it was in use: its clusters go when it's inactive.
    unlinked: bool,
}

impl Node {
    fn from_entry(e: &DirEntry, dir_first: u32, slot: u32, lfn: u32, at: u64) -> Node {
        Node {
            is_dir: e.attr & ATTR_DIRECTORY != 0,
            is_root: false,
            first: e.cluster,
            size: if e.attr & ATTR_DIRECTORY != 0 { 0 } else { e.size },
            attr: e.attr,
            created: e.created,
            modified: e.modified,
            accessed: e.accessed_date,
            entry: Some((dir_first, slot, lfn, at)),
            cursor: (0, e.cluster),
            unlinked: false,
        }
    }

    /// Its directory entry from what it holds now.
    fn to_entry(&self, name: [u8; 11], nt_case: u8) -> DirEntry {
        DirEntry {
            name,
            attr: self.attr,
            nt_case,
            created: self.created,
            accessed_date: self.accessed,
            modified: self.modified,
            cluster: self.first,
            size: if self.is_dir { 0 } else { self.size },
        }
    }
}

fn node_of(vp: *mut Vnode) -> Option<&'static mut Node> {
    // SAFETY: `v_data` holds a pointer this module stored (or null), live until reclaim.
    unsafe {
        let p = *((*vp).v_data as *mut *mut Node);
        if p.is_null() { None } else { Some(&mut *p) }
    }
}

/// `Box::new` that fails instead of ending the call.
fn try_box<T>(v: T) -> Option<Box<T>> {
    let layout = core::alloc::Layout::new::<T>();
    // SAFETY: `T` is never zero-sized here (nodes and mounts); a non-null result is fresh memory
    // for one `T`, which the `Box` then owns, as `Box::new` would.
    unsafe {
        let p = alloc::alloc::alloc(layout) as *mut T;
        if p.is_null() {
            return None;
        }
        p.write(v);
        Some(Box::from_raw(p))
    }
}

fn mount_of(vp: *mut Vnode) -> *mut Mount {
    // SAFETY: a live vnode.
    unsafe { (*vp).v_mount }
}

/// The vnode of file `id`, from the hash or made with `make`'s node.
fn vget(mp: *mut Mount, id: u64, make: impl FnOnce() -> Result<Node, i32>, vpp: *mut *mut Vnode) -> i32 {
    // SAFETY: kernel exports, called as declared.
    unsafe {
        let vp = oxidebsd_vfs_hash_get(mp, id);
        if !vp.is_null() {
            *vpp = vp;
            return 0;
        }
        let node = match make() {
            Ok(n) => n,
            Err(e) => return e,
        };
        let Some(b) = try_box(node) else { return ENOMEM };
        let node = Box::into_raw(b);
        let mut vp = ptr::null_mut();
        let e = oxidebsd_getnewvnode(mp, if (*node).is_dir { VDIR } else { VREG }, id, &mut vp);
        if e != 0 {
            drop(Box::from_raw(node));
            return e;
        }
        *((*vp).v_data as *mut *mut Node) = node;
        if (*node).is_root {
            (*vp).v_flag |= VV_ROOT;
        }
        oxidebsd_vfs_hash_insert(vp);
        *vpp = vp;
    }
    0
}

fn root_node(m: &Fs) -> Node {
    Node {
        is_dir: true,
        is_root: true,
        first: m.root_first,
        size: 0,
        attr: ATTR_DIRECTORY,
        created: DosTime::default(),
        modified: DosTime::default(),
        accessed: 0,
        entry: None,
        cursor: (0, m.root_first),
        unlinked: false,
    }
}

// --- Directories -------------------------------------------------------------------------------

/// One short entry a scan found: its slot, device byte offset, contents, long name (if a valid
/// one leads it) and how many long-name slots it has.
struct Found<'a> {
    slot: u32,
    at: u64,
    entry: DirEntry,
    long: Option<&'a [u16]>,
    lfn: u32,
}

/// The blocks of directory `first` (0: the fixed root): `(device byte offset, bytes)`.
fn dir_blocks(m: &Fs, first: u32) -> Result<Vec<(u64, u64)>, i32> {
    let mut out = Vec::new();
    if first == 0 {
        let mut off = 0;
        while off < m.root_bytes {
            let len = PIECE.min(m.root_bytes - off);
            out.push((m.root_at + off, len));
            off += len;
        }
        return Ok(out);
    }
    let mut c = first;
    while m.valid_cluster(c) && out.len() < m.max as usize {
        out.push((m.cluster_at(c), m.cb));
        match m.next(c)? {
            Some(n) => c = n,
            None => break,
        }
    }
    Ok(out)
}

/// Calls `f` for each short entry of directory `first` (volume labels skipped) until it returns
/// `true`; long names are assembled and checked (sequence, checksum) on the way.
fn scan(m: &Fs, first: u32, mut f: impl FnMut(&Found) -> bool) -> Result<(), i32> {
    let mut name = [0u16; LFN_MAX + LFN_CHARS];
    let (mut expect, mut sum, mut count, mut len) = (0u8, 0u8, 0u32, 0usize);
    let mut slot = 0u32;
    for (at, size) in dir_blocks(m, first)? {
        let stop = with_block(m.dev, at, size, 0, |b| {
            for (i, raw) in b.chunks_exact(DIR_ENTRY_SIZE).enumerate() {
                let this = slot + i as u32;
                if raw[0] == ENTRY_END {
                    return true;
                }
                if raw[0] == ENTRY_FREE {
                    expect = 0;
                    count = 0;
                    continue;
                }
                if DirEntry::is_long_name(raw) {
                    let mut units = [0u16; LFN_CHARS];
                    let (seq, last, s) = read_lfn_entry(raw, &mut units);
                    if last {
                        expect = seq;
                        sum = s;
                        count = 0;
                        len = 0;
                    }
                    if seq == 0 || seq != expect || s != sum || seq as usize * LFN_CHARS > name.len() {
                        expect = 0;
                        count = 0;
                        continue;
                    }
                    let base = (seq as usize - 1) * LFN_CHARS;
                    name[base..base + LFN_CHARS].copy_from_slice(&units);
                    if last {
                        len = base + units.iter().position(|&u| u == 0 || u == 0xFFFF).unwrap_or(LFN_CHARS);
                    }
                    expect -= 1;
                    count += 1;
                    continue;
                }
                let entry = DirEntry::read(raw);
                let long = (count > 0 && expect == 0 && sum == short_name_checksum(&entry.name)).then(|| &name[..len]);
                let lfn = if long.is_some() { count } else { 0 };
                expect = 0;
                count = 0;
                if entry.attr & ATTR_VOLUME_ID != 0 {
                    continue;
                }
                if f(&Found { slot: this, at: at + i as u64 * DIR_ENTRY_SIZE as u64, entry, long, lfn }) {
                    return true;
                }
            }
            false
        })?;
        if stop {
            return Ok(());
        }
        slot += (size / DIR_ENTRY_SIZE as u64) as u32;
    }
    Ok(())
}

/// An entry's name as shown: its long name (unless `shortnames`), else its short one.
fn display_name(m: &Fs, f: &Found, out: &mut String) {
    out.clear();
    if let (Some(long), false) = (f.long, m.shortnames) {
        for c in char::decode_utf16(long.iter().copied()) {
            out.push(c.unwrap_or('\u{FFFD}'));
        }
        return;
    }
    let mut text = [0u8; 48];
    let n = short_name_text(&f.entry.name, f.entry.nt_case, &m.codepage(), &mut text);
    out.push_str(core::str::from_utf8(&text[..n]).unwrap_or("?"));
}

/// Whether `f` is the entry named `name` (in any case, by its long or its short name).
fn matches(m: &Fs, f: &Found, name: &str, buf: &mut String) -> bool {
    let mut text = [0u8; 48];
    let n = short_name_text(&f.entry.name, f.entry.nt_case, &m.codepage(), &mut text);
    if core::str::from_utf8(&text[..n]).is_ok_and(|s| same_name(s, name)) {
        return true;
    }
    if m.shortnames {
        return false;
    }
    if let Some(long) = f.long {
        buf.clear();
        for c in char::decode_utf16(long.iter().copied()) {
            buf.push(c.unwrap_or('\u{FFFD}'));
        }
        return same_name(buf, name);
    }
    false
}

/// The file ID and node of found entry `f` in directory `dir_first`.
fn found_id(m: &Fs, f: &Found) -> u64 {
    if f.entry.attr & ATTR_DIRECTORY != 0 && m.valid_cluster(f.entry.cluster) { m.dir_id(f.entry.cluster) } else { f.at / 32 }
}

/// The parent of directory `first` (not the root): its `..` entry's cluster.
fn parent_of(m: &Fs, first: u32) -> Result<u32, i32> {
    let mut parent = None;
    scan(m, first, |f| {
        if &f.entry.name == b"..         " {
            parent = Some(f.entry.cluster);
            return true;
        }
        false
    })?;
    // FAT32 lets `..` name the root by its cluster as well as by 0.
    Ok(match parent.ok_or(EIO)? {
        c if c == m.root_first => 0,
        c => c,
    })
}

/// The node of directory `first` (not the root), found through its parent's entry for it.
fn dir_node(m: &Fs, first: u32) -> Result<Node, i32> {
    let parent = parent_of(m, first)?;
    let dir = if parent == 0 { if m.kind == FatType::Fat32 { m.root_first } else { 0 } } else { parent };
    let mut node = None;
    scan(m, dir, |f| {
        if f.entry.attr & ATTR_DIRECTORY != 0 && f.entry.cluster == first && f.entry.name[0] != b'.' {
            node = Some(Node::from_entry(&f.entry, dir, f.slot, f.lfn, f.at));
            return true;
        }
        false
    })?;
    node.ok_or(EIO)
}

// --- Time --------------------------------------------------------------------------------------

/// A FAT time (local, `kern.utc_offset`) as a timestamp.
fn ts(t: DosTime) -> Timespec {
    if t.date == 0 {
        return Timespec { tv_sec: 315_532_800, tv_nsec: 0 };
    }
    // SAFETY: kernel export.
    let offset = unsafe { oxidebsd_utc_offset() } as i64 * 60;
    Timespec { tv_sec: t.to_unix() - offset, tv_nsec: 0 }
}

/// Now, as a FAT time (local).
fn now() -> DosTime {
    // SAFETY: kernel exports.
    let t = unsafe { oxidebsd_unix_time() + oxidebsd_utc_offset() as i64 * 60 };
    DosTime::from_unix(t)
}

/// A timestamp as a FAT time (local).
fn dos(t: Timespec) -> DosTime {
    // SAFETY: kernel export.
    DosTime::from_unix(t.tv_sec + unsafe { oxidebsd_utc_offset() } as i64 * 60)
}

// --- Mount options -----------------------------------------------------------------------------

struct Options {
    uid: Option<u32>,
    gid: Option<u32>,
    mask: Option<u32>,
    dirmask: Option<u32>,
    shortnames: bool,
    codepage: Vec<u8>,
}

fn parse_num(v: &[u8], radix: u32) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in v {
        n = n.checked_mul(radix as u64)?.checked_add((c as char).to_digit(radix)? as u64)?;
    }
    Some(n)
}

/// The options the kernel passed (`name\0value\0` pairs), FreeBSD's names: `uid`, `gid`, `mask`,
/// `dirmask` (octal), `shortnames`, `longnames`, and `cs_dos`, a compiled code page table in hex
/// (mount_msdosfs(8) makes it from `/usr/share/msdosfs`). `EINVAL` for anything else.
fn parse_options(args: &MountArgs) -> Result<Options, i32> {
    let mut o = Options { uid: None, gid: None, mask: None, dirmask: None, shortnames: false, codepage: Vec::new() };
    if args.opts.is_null() || args.opts_len == 0 {
        return Ok(o);
    }
    // SAFETY: the kernel's buffer, live for the call.
    let buf = unsafe { core::slice::from_raw_parts(args.opts, args.opts_len) };
    let mut fields = buf.split(|&b| b == 0);
    while let Some(name) = fields.next() {
        if name.is_empty() {
            continue;
        }
        let value = fields.next().unwrap_or(b"");
        let id = |v: &[u8]| parse_num(v, 10).filter(|&n| n <= u32::MAX as u64).map(|n| n as u32).ok_or(EINVAL);
        let mode = |v: &[u8]| parse_num(v, 8).filter(|&n| n <= 0o777).map(|n| n as u32).ok_or(EINVAL);
        match name {
            b"uid" => o.uid = Some(id(value)?),
            b"gid" => o.gid = Some(id(value)?),
            b"mask" => o.mask = Some(mode(value)?),
            b"dirmask" => o.dirmask = Some(mode(value)?),
            b"shortnames" => o.shortnames = true,
            b"longnames" => o.shortnames = false,
            b"cs_dos" => {
                if value.len() % 2 != 0 {
                    return Err(EINVAL);
                }
                let mut table = Vec::new();
                table.try_reserve_exact(value.len() / 2).map_err(|_| ENOMEM)?;
                for pair in value.chunks_exact(2) {
                    let hi = (pair[0] as char).to_digit(16).ok_or(EINVAL)?;
                    let lo = (pair[1] as char).to_digit(16).ok_or(EINVAL)?;
                    table.push((hi << 4 | lo) as u8);
                }
                if Codepage::parse(&table).is_none() {
                    return Err(EINVAL);
                }
                o.codepage = table;
            }
            _ => return Err(EINVAL),
        }
    }
    Ok(o)
}

// --- vfsops ------------------------------------------------------------------------------------

static MSDOSFS_VFSOPS: VfsOps = VfsOps {
    mount: Some(msdosfs_mount),
    unmount: Some(msdosfs_unmount),
    root: Some(msdosfs_root),
    statfs: Some(msdosfs_statfs),
    sync: Some(msdosfs_sync),
    vget: None,
};

static MSDOSFS_VFSCONF: VfsConf = VfsConf {
    name: b"msdosfs".as_ptr(),
    name_len: 7,
    ops: &MSDOSFS_VFSOPS,
    vops: &MSDOSFS_VOPS,
    mnt_data_size: 8,
    v_data_size: 8,
    // Not the name cache: a name is found in any case, and the cache would give getcwd(3) the
    // case a lookup used, not the one on the volume.
    flags: VFCF_NOCACHE,
};

extern "C" fn msdosfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel's argument record and mount, live for the call.
    let (args, flags) = unsafe { (&*args, (*mp).mnt_flag) };
    let opts = match parse_options(args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if flags & MNT_UPDATE != 0 {
        let m = fs(mp);
        let want_rw = flags & MNT_RDONLY == 0;
        if want_rw == m.rw {
            return 0;
        }
        if want_rw {
            return go_rw(mp, m, flags & MNT_FORCE != 0);
        }
        // Read-write to read-only: everything delayed goes out, then the volume is clean.
        // SAFETY: kernel export.
        unsafe { oxidebsd_bflush(m.dev, 0, 0) };
        let r = m.write_fsinfo().and_then(|()| m.set_clean(true));
        // SAFETY: as above.
        unsafe { oxidebsd_bflush(m.dev, 0, 0) };
        m.rw = false;
        return r.err().unwrap_or(0);
    }
    if args.dev == NODEV {
        return ENXIO;
    }
    // The boot sector: up to 4 KiB (FAT's largest sector).
    let mut boot = [0u8; 4096];
    // SAFETY: kernel exports; `boot` holds 8 sectors.
    let sectors = unsafe { oxidebsd_bdev_sectors(args.dev) };
    if sectors < 8 || unsafe { oxidebsd_bdev_read(args.dev, 0, 8, boot.as_mut_ptr()) } != 0 {
        return EIO;
    }
    let Ok(bpb) = Bpb::read_boot_sector(&boot) else {
        log("[msdosfs] no FAT file system there (no valid boot sector)\n");
        return EINVAL;
    };
    let (Ok(kind), Ok(clusters)) = (bpb.fat_type(), bpb.clusters()) else { return EINVAL };
    let bps = bpb.bytes_per_sector as u64;
    if bpb.total_sectors as u64 * bps > sectors * SECTOR {
        log("[msdosfs] the file system is larger than its device\n");
        return EINVAL;
    }
    if kind == FatType::Fat32 && !(FIRST_CLUSTER..=clusters + 1).contains(&bpb.root_cluster) {
        return EINVAL;
    }
    // Owner, group and modes: the mount point's unless the options say (FreeBSD's defaults).
    let mut covered = Vattr::NULL;
    // SAFETY: the kernel sets the covered vnode before calling `mount`, referenced.
    let cvp = unsafe { (*mp).mnt_vnodecovered };
    let have = !cvp.is_null() && unsafe { oxidebsd_vop_getattr(cvp, &mut covered) } == 0;
    let mask = opts.mask.unwrap_or(if have { covered.va_mode & 0o777 } else { 0o755 });
    let m = Fs {
        dev: args.dev,
        bpb,
        kind,
        bps,
        cb: bpb.cluster_bytes() as u64,
        max: clusters + 1,
        fat_at: bpb.fat_start() as u64 * bps,
        fat_bytes: bpb.fat_sectors as u64 * bps,
        root_at: (bpb.fat_start() + bpb.fats as u32 * bpb.fat_sectors) as u64 * bps,
        root_bytes: bpb.root_dir_sectors() as u64 * bps,
        data_at: bpb.data_start() as u64 * bps,
        root_first: if kind == FatType::Fat32 { bpb.root_cluster } else { 0 },
        uid: opts.uid.unwrap_or(if have { covered.va_uid } else { 0 }),
        gid: opts.gid.unwrap_or(if have { covered.va_gid } else { 0 }),
        mask,
        dirmask: opts.dirmask.unwrap_or(mask),
        shortnames: opts.shortnames,
        codepage: opts.codepage,
        free: None,
        next_free: FIRST_CLUSTER,
        rw: false,
    };
    let Some(b) = try_box(m) else { return ENOMEM };
    // SAFETY: `mnt_data` is 8 bytes for the pointer.
    unsafe { *((*mp).mnt_data as *mut *mut Fs) = Box::into_raw(b) };
    let m = fs(mp);
    // FAT32's FSInfo: a hint where the free clusters are (its count isn't trusted: it's counted).
    if kind == FatType::Fat32 && bpb.fsinfo_sector != 0 && bpb.fsinfo_sector != 0xFFFF {
        let at = bpb.fsinfo_sector as u64 * bps;
        if at + 512 <= 4096 {
            let next = u32::from_le_bytes(boot[at as usize + 492..at as usize + 496].try_into().unwrap());
            if m.valid_cluster(next) {
                m.next_free = next;
            }
        }
    }
    if flags & MNT_RDONLY == 0 {
        let e = go_rw(mp, m, flags & MNT_FORCE != 0);
        if e != 0 {
            // SAFETY: made above, never shared.
            unsafe {
                drop(Box::from_raw(*((*mp).mnt_data as *mut *mut Fs)));
                *((*mp).mnt_data as *mut *mut Fs) = ptr::null_mut();
            }
            return e;
        }
    }
    0
}

/// Makes mount `mp` read-write: a volume not marked clean stays read-only (`MNT_RDONLY` set,
/// with a warning) unless `force`; otherwise its clean bit is cleared until unmount.
fn go_rw(mp: *mut Mount, m: &mut Fs, force: bool) -> i32 {
    let clean = match m.kind.clean_bit() {
        Some(bit) => match m.fat_get(1) {
            Ok(e1) => e1 & bit != 0,
            Err(e) => return e,
        },
        None => true,
    };
    if !clean && !force {
        log("[msdosfs] the volume is not marked clean: mounted read-only (check it with fsck_msdosfs, or mount -f)\n");
        // SAFETY: the kernel's mount, which reads the flag back.
        unsafe { (*mp).mnt_flag |= MNT_RDONLY };
        return 0;
    }
    // SAFETY: kernel export: the write ordering for this device.
    unsafe { oxidebsd_bio_set_hook(m.dev, pre_write) };
    if let Err(e) = m.set_clean(false) {
        return e;
    }
    m.rw = true;
    0
}

extern "C" fn msdosfs_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    let m = fs(mp);
    if m.rw {
        // SAFETY: kernel export.
        unsafe { oxidebsd_bflush(m.dev, 0, 0) };
        if m.write_fsinfo().and_then(|()| m.set_clean(true)).is_err() {
            log("[msdosfs] couldn't mark the volume clean\n");
        }
    }
    // SAFETY: kernel exports. The cache forgets the device's blocks: fsck_msdosfs or another
    // system may change them before the next mount.
    unsafe {
        oxidebsd_bflush(m.dev, 0, 0);
        oxidebsd_binvalall(m.dev);
        let p = *((*mp).mnt_data as *mut *mut Fs);
        drop(Box::from_raw(p));
        *((*mp).mnt_data as *mut *mut Fs) = ptr::null_mut();
    }
    0
}

extern "C" fn msdosfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    let m = fs(mp);
    let node = root_node(m);
    vget(mp, ROOT_ID, || Ok(node), vpp)
}

extern "C" fn msdosfs_statfs(mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    let m = fs(mp);
    let free = match m.count_free() {
        Ok(f) => f,
        Err(e) => return e,
    };
    // SAFETY: the kernel's record.
    let sb = unsafe { &mut *sbp };
    sb.f_bsize = m.cb;
    sb.f_iosize = m.cb;
    sb.f_blocks = (m.max - 1) as u64;
    sb.f_bfree = free as u64;
    sb.f_bavail = free as u64;
    sb.f_files = 0;
    sb.f_ffree = 0;
    sb.f_namemax = if m.shortnames { 12 } else { LFN_MAX as u32 };
    sb.f_magic = MSDOS_MAGIC;
    0
}

extern "C" fn msdosfs_sync(mp: *mut Mount, _waitfor: i32) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_bflush(fs(mp).dev, 0, 0) };
    0
}

// --- Vnode operations --------------------------------------------------------------------------

static MSDOSFS_VOPS: VopVector = VopVector {
    lookup: Some(msdosfs_lookup),
    create: Some(msdosfs_create),
    getattr: Some(msdosfs_getattr),
    setattr: Some(msdosfs_setattr),
    read: Some(msdosfs_read),
    write: Some(msdosfs_write),
    fsync: Some(msdosfs_fsync),
    remove: Some(msdosfs_remove),
    rename: Some(msdosfs_rename),
    mkdir: Some(msdosfs_mkdir),
    rmdir: Some(msdosfs_rmdir),
    readdir: Some(msdosfs_readdir),
    inactive: Some(msdosfs_inactive),
    reclaim: Some(msdosfs_reclaim),
    pathconf: Some(msdosfs_pathconf),
    ..VopVector::DEFAULT
};

extern "C" fn msdosfs_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32 {
    let mp = mount_of(dvp);
    let m = fs(mp);
    let Some(dn) = node_of(dvp) else { return ENOENT };
    if !dn.is_dir {
        return ENOTDIR;
    }
    // SAFETY: the kernel's component.
    let (flags, nameiop, raw) = unsafe { ((*cnp).cn_flags, (*cnp).cn_nameiop, (*cnp).name()) };
    let dir = if dn.is_root { m.root_first } else { dn.first };
    if raw == b"." {
        // SAFETY: a referenced vnode of ours.
        unsafe { oxidebsd_vref(dvp) };
        // SAFETY: the kernel's out-parameter.
        unsafe { *vpp = dvp };
        return 0;
    }
    if flags & ISDOTDOT != 0 || raw == b".." {
        if dn.is_root {
            // SAFETY: as above.
            unsafe {
                oxidebsd_vref(dvp);
                *vpp = dvp;
            }
            return 0;
        }
        let parent = match parent_of(m, dir) {
            Ok(p) => p,
            Err(e) => return e,
        };
        if parent == 0 {
            return msdosfs_root(mp, vpp);
        }
        return vget(mp, m.dir_id(parent), || dir_node(m, parent), vpp);
    }
    let Ok(name) = core::str::from_utf8(raw) else { return ENOENT };
    let mut found: Option<(u64, Node)> = None;
    let mut buf = String::new();
    let r = scan(m, dir, |f| {
        if f.entry.name[0] == b'.' && (&f.entry.name == b".          " || &f.entry.name == b"..         ") {
            return false;
        }
        if matches(m, f, name, &mut buf) {
            found = Some((found_id(m, f), Node::from_entry(&f.entry, dir, f.slot, f.lfn, f.at)));
            return true;
        }
        false
    });
    if let Err(e) = r {
        return e;
    }
    match found {
        Some((id, node)) => vget(mp, id, || Ok(node), vpp),
        None if flags & ISLASTCN != 0 && (nameiop == CREATE || nameiop == RENAME) => EJUSTRETURN,
        None => ENOENT,
    }
}

extern "C" fn msdosfs_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    let m = fs(mount_of(vp));
    let Some(n) = node_of(vp) else { return EIO };
    // SAFETY: a live vnode.
    let id = unsafe { (*vp).v_fileid };
    let mut mode = if n.is_dir { m.dirmask } else { m.mask };
    if !n.is_dir && n.attr & ATTR_READ_ONLY != 0 {
        mode &= !0o222;
    }
    let first = if n.is_root { m.root_first } else { n.first };
    let clusters = if n.is_root && first == 0 {
        0
    } else if m.valid_cluster(first) {
        m.chain_len(first).unwrap_or(0) as u64
    } else {
        0
    };
    let size = if n.is_dir { if first == 0 { m.root_bytes } else { clusters * m.cb } } else { n.size as u64 };
    let mtime = ts(n.modified);
    // SAFETY: the kernel's record.
    let va = unsafe { &mut *vap };
    *va = Vattr {
        va_type: if n.is_dir { VDIR } else { VREG },
        va_mode: mode,
        va_nlink: 1,
        va_uid: m.uid,
        va_gid: m.gid,
        va_fsid: 0,
        va_fileid: id,
        va_size: size,
        va_blocksize: m.cb,
        va_atime: ts(DosTime { date: n.accessed, time: 0 }),
        va_mtime: mtime,
        // FAT has no change time: the modification time stands in, as on FreeBSD.
        va_ctime: mtime,
        va_birthtime: ts(n.created),
        va_gen: 0,
        va_flags: 0,
        va_rdev: 0,
        va_bytes: clusters * m.cb,
        va_vaflags: 0,
    };
    0
}

/// The cluster holding byte `off` of node `n`'s file, using and moving its cursor.
fn cluster_for(m: &Fs, n: &mut Node, off: u64) -> Result<Option<u32>, i32> {
    let want = (off / m.cb) as u32;
    let (mut idx, mut c) = n.cursor;
    if want < idx || !m.valid_cluster(c) {
        idx = 0;
        c = n.first;
    }
    while idx < want {
        if !m.valid_cluster(c) {
            return Ok(None);
        }
        match m.next(c)? {
            Some(x) => c = x,
            None => return Ok(None),
        }
        idx += 1;
    }
    if !m.valid_cluster(c) {
        return Ok(None);
    }
    n.cursor = (idx, c);
    Ok(Some(c))
}

extern "C" fn msdosfs_read(vp: *mut Vnode, uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    let m = fs(mount_of(vp));
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    if n.is_dir {
        return -(EISDIR as i64);
    }
    // SAFETY: kernel export.
    let mut off = unsafe { oxidebsd_uio_offset(uio) };
    let mut moved = 0i64;
    let mut chunk = Vec::new();
    loop {
        // SAFETY: kernel export.
        let resid = unsafe { oxidebsd_uio_resid(uio) };
        if resid == 0 || off >= n.size as u64 {
            break;
        }
        let c = match cluster_for(m, n, off) {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => return if moved > 0 { moved } else { -(e as i64) },
        };
        let within = off % m.cb;
        let len = resid.min(m.cb - within).min(n.size as u64 - off);
        let left = (n.size as u64 - off).div_ceil(m.cb).saturating_sub(1);
        // Copied out of the buffer before moving it to the caller: the copy may fault on a page
        // of a mapped file of this very file system.
        chunk.clear();
        if chunk.try_reserve(len as usize).is_err() {
            return if moved > 0 { moved } else { -(ENOMEM as i64) };
        }
        let r = with_block(m.dev, m.cluster_at(c), m.cb, left.min(READ_AHEAD), |b| {
            chunk.extend_from_slice(&b[within as usize..(within + len) as usize]);
        });
        if let Err(e) = r {
            return if moved > 0 { moved } else { -(e as i64) };
        }
        // SAFETY: kernel export; a read transfer only reads the buffer.
        let r = unsafe { oxidebsd_uiomove(chunk.as_mut_ptr(), len, uio) };
        if r <= 0 {
            if moved == 0 && r < 0 {
                return r;
            }
            break;
        }
        moved += r;
        off += r as u64;
    }
    moved
}

/// `readdir`: positions are slots (the root, which has no `.` and `..` entries of its own, shows
/// them as positions 0 and 1 and its slots from 2).
extern "C" fn msdosfs_readdir(vp: *mut Vnode, uio: u64, _cred: *const Ucred, eofflag: *mut i32) -> i64 {
    let m = fs(mount_of(vp));
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    if !n.is_dir {
        return -(ENOTDIR as i64);
    }
    // SAFETY: a live vnode.
    let self_id = unsafe { (*vp).v_fileid };
    let dir = if n.is_root { m.root_first } else { n.first };
    let base: u64 = if n.is_root { 2 } else { 0 };
    // SAFETY: kernel export.
    let start = unsafe { oxidebsd_uio_offset(uio) };
    // The records, gathered first (`scan` holds a buffer while it calls back).
    let mut records: Vec<(u64, u64, u8, String)> = Vec::new();
    if n.is_root {
        for (pos, name) in [(0u64, "."), (1, "..")] {
            if pos >= start {
                records.push((pos, ROOT_ID, vtype_to_dt(VDIR), String::from(name)));
            }
        }
    }
    let parent_id = if n.is_root { ROOT_ID } else { parent_of(m, dir).map(|p| m.dir_id(p)).unwrap_or(ROOT_ID) };
    let mut name = String::new();
    let r = scan(m, dir, |f| {
        let pos = base + f.slot as u64;
        if pos < start {
            return false;
        }
        let (id, shown) = match &f.entry.name {
            b".          " => (self_id, String::from(".")),
            b"..         " => (parent_id, String::from("..")),
            _ => {
                display_name(m, f, &mut name);
                (found_id(m, f), name.clone())
            }
        };
        let dt = vtype_to_dt(if f.entry.attr & ATTR_DIRECTORY != 0 { VDIR } else { VREG });
        records.push((pos, id, dt, shown));
        // A screenful at a time: the caller's buffer bounds what's sent anyway.
        records.len() >= 256
    });
    if let Err(e) = r {
        return -(e as i64);
    }
    let complete = records.len() < 256;
    let mut record = [0u8; dirent_reclen(LFN_MAX * 3)];
    let mut written = 0i64;
    let mut cursor = start;
    let mut eof = complete;
    for (pos, id, dt, shown) in &records {
        let reclen = dirent_reclen(shown.len());
        // SAFETY: kernel export.
        if (unsafe { oxidebsd_uio_resid(uio) } as usize) < reclen {
            eof = false;
            break;
        }
        dirent_encode(&mut record, *id, (*pos + 1) as i64, *dt, shown.as_bytes());
        // SAFETY: kernel export, with this module's buffer.
        let r = unsafe { oxidebsd_uiomove(record.as_mut_ptr(), reclen as u64, uio) };
        if r < 0 {
            if written == 0 {
                return -(EFAULT as i64);
            }
            eof = false;
            break;
        }
        written += reclen as i64;
        cursor = pos + 1;
    }
    if !complete && eof {
        eof = false;
    }
    // SAFETY: as above.
    unsafe {
        oxidebsd_uio_set_offset(uio, cursor);
        *eofflag = eof as i32;
    }
    written
}

extern "C" fn msdosfs_reclaim(vp: *mut Vnode) -> i32 {
    // SAFETY: `v_data` holds this module's pointer or null; nothing uses it after reclaim.
    unsafe {
        let slot = (*vp).v_data as *mut *mut Node;
        if !(*slot).is_null() {
            drop(Box::from_raw(*slot));
            *slot = ptr::null_mut();
        }
    }
    0
}

/// `_PC_LINK_MAX` 1 (no hard links), `_PC_NAME_MAX` 255 (12 with `shortnames`).
extern "C" fn msdosfs_pathconf(vp: *mut Vnode, name: i32, retval: *mut i64) -> i32 {
    const PC_LINK_MAX: i32 = 0;
    const PC_NAME_MAX: i32 = 3;
    let m = fs(mount_of(vp));
    let v = match name {
        PC_LINK_MAX => 1,
        PC_NAME_MAX => if m.shortnames { 12 } else { LFN_MAX as i64 },
        _ => return EINVAL,
    };
    // SAFETY: the kernel's out-parameter.
    unsafe { *retval = v };
    0
}

// --- Writing -----------------------------------------------------------------------------------

fn dir_of_node(m: &Fs, n: &Node) -> u32 {
    if n.is_root { m.root_first } else { n.first }
}

/// Device byte offset of slot `slot` of directory `first` (0: the fixed root).
fn slot_at(m: &Fs, first: u32, slot: u32) -> Result<u64, i32> {
    let byte = slot as u64 * DIR_ENTRY_SIZE as u64;
    if first == 0 {
        return Ok(m.root_at + byte);
    }
    let mut c = first;
    for _ in 0..byte / m.cb {
        c = m.next(c)?.ok_or(EIO)?;
    }
    Ok(m.cluster_at(c) + byte % m.cb)
}

/// Every slot of directory `first`: `(device byte offset, its 32 bytes)`. A directory is at most
/// 65536 slots (2 MiB), as FAT allows.
fn slots_of(m: &Fs, first: u32) -> Result<Vec<(u64, [u8; 32])>, i32> {
    let mut out: Vec<(u64, [u8; 32])> = Vec::new();
    for (at, size) in dir_blocks(m, first)? {
        out.try_reserve((size / 32) as usize).map_err(|_| ENOMEM)?;
        with_block(m.dev, at, size, 0, |b| {
            for (i, raw) in b.chunks_exact(DIR_ENTRY_SIZE).enumerate() {
                out.push((at + i as u64 * 32, raw.try_into().unwrap()));
            }
        })?;
    }
    Ok(out)
}

/// `need` consecutive free slots in directory `first`, growing it by a cluster (zeroed on the
/// disk before it joins the chain) if it has none: `(first slot's index, their offsets)`.
fn find_free(m: &mut Fs, first: u32, need: usize) -> Result<(u32, Vec<u64>), i32> {
    loop {
        let slots = slots_of(m, first)?;
        let mut run = 0;
        let mut end = false;
        for (i, (_, raw)) in slots.iter().enumerate() {
            end |= raw[0] == ENTRY_END;
            if end || raw[0] == ENTRY_FREE {
                run += 1;
                if run == need {
                    let start = i + 1 - need;
                    return Ok((start as u32, slots[start..=i].iter().map(|s| s.0).collect()));
                }
            } else {
                run = 0;
            }
        }
        if first == 0 || slots.len() + (m.cb as usize / 32) > 65536 {
            return Err(ENOSPC);
        }
        let mut last = first;
        while let Some(n) = m.next(last)? {
            last = n;
        }
        let c = m.alloc(1, None)?;
        with_block_new(m.dev, m.cluster_at(c), m.cb, TAG_DATA, true, |b| b.fill(0))?;
        m.fat_set(last, c, false)?;
    }
}

/// The names a new entry `name` takes in directory `first`: its short name (unique there), NT
/// case flags, and its long name if it needs one. `EINVAL` for a name FAT can't hold.
fn make_name(m: &Fs, first: u32, name: &[u8]) -> Result<([u8; 11], u8, Option<Vec<u16>>), i32> {
    let name = core::str::from_utf8(name).map_err(|_| EINVAL)?;
    if name.is_empty() || name.ends_with(['.', ' ']) || !name.chars().all(long_name_char) {
        return Err(EINVAL);
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.len() > LFN_MAX {
        return Err(ENAMETOOLONG);
    }
    let cp = m.codepage();
    let shorts: Vec<[u8; 11]> = slots_of(m, first)?
        .iter()
        .filter(|(_, r)| r[0] != ENTRY_END && r[0] != ENTRY_FREE && !DirEntry::is_long_name(r))
        .map(|(_, r)| r[0..11].try_into().unwrap())
        .collect();
    match short_name_in(name, &cp) {
        ShortName::Exact { name: short, nt_case } if !shorts.contains(&short) => Ok((short, nt_case, None)),
        _ if m.shortnames => Err(EINVAL),
        ShortName::Exact { name: basis, .. } | ShortName::Basis { name: basis, .. } => {
            let lossless = matches!(short_name_in(name, &cp), ShortName::Basis { lossy: false, .. });
            let short = if lossless && !shorts.contains(&basis) {
                basis
            } else {
                (1..1_000_000).map(|n| with_numeric_tail(&basis, n)).find(|s| !shorts.contains(s)).ok_or(EEXIST)?
            };
            Ok((short, 0, Some(units)))
        }
    }
}

/// Writes entry `e` with long name `long` into `slots` (long-name entries first, last index
/// first, then the short entry); delayed, or `sync`.
fn write_entries(m: &Fs, slots: &[u64], e: &DirEntry, long: Option<&[u16]>, sync: bool) -> Result<(), i32> {
    let sum = short_name_checksum(&e.name);
    if let Some(long) = long {
        let k = lfn_entries(long.len());
        for (j, &at) in slots[..k].iter().enumerate() {
            m.put_entry(at, sync, |b| write_lfn_entry(b, long, k - 1 - j, sum))?;
        }
    }
    m.put_entry(*slots.last().unwrap(), sync, |b| e.write(b))
}

/// Frees the slots of node `n`'s entry (its long-name entries and its short one), on the disk at
/// once: what frees its clusters comes after.
fn clear_entry(m: &Fs, n: &Node) -> Result<(), i32> {
    let Some((dir, slot, lfn, _)) = n.entry else { return Err(EINVAL) };
    for s in slot - lfn..=slot {
        let at = slot_at(m, dir, s)?;
        m.put_entry(at, true, |b| b[0] = ENTRY_FREE)?;
    }
    Ok(())
}

/// Node `n`'s entry rewritten from what it holds (name kept); delayed, or `sync`.
fn update_entry(m: &Fs, n: &Node, sync: bool) -> Result<(), i32> {
    let Some((_, _, _, at)) = n.entry else { return Ok(()) };
    m.put_entry(at, sync, |b| {
        let mut e = DirEntry::read(b);
        let (name, nt) = (e.name, e.nt_case);
        e = n.to_entry(name, nt);
        e.write(b);
    })
}

/// The vnode's file ID moves out of the way: its entry is gone (or moved), and the slot may be
/// taken by another file.
fn orphan(vp: *mut Vnode) {
    let id = ORPHAN_ID | ORPHANS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: kernel export, a referenced vnode of ours.
    unsafe { oxidebsd_vfs_hash_rehash(vp, id) };
}

fn writable(m: &Fs) -> Result<(), i32> {
    if m.rw { Ok(()) } else { Err(EROFS) }
}

/// A new file or directory `cnp` in directory `dvp`; `*vpp` gets it.
fn new_entry(dvp: *mut Vnode, cnp: *const ComponentName, is_dir: bool, read_only: bool, vpp: *mut *mut Vnode) -> i32 {
    let mp = mount_of(dvp);
    let m = fs(mp);
    let r = (|| -> Result<(u64, Node), i32> {
        writable(m)?;
        let dn = node_of(dvp).ok_or(ENOENT)?;
        let dir = dir_of_node(m, dn);
        let parent_cluster = if dn.is_root { 0 } else { dn.first };
        // SAFETY: the kernel's component.
        let (short, nt_case, long) = make_name(m, dir, unsafe { (*cnp).name() })?;
        let need = 1 + long.as_ref().map_or(0, |l| lfn_entries(l.len()));
        let (start, slots) = find_free(m, dir, need)?;
        let t = now();
        let first = if is_dir {
            // The new directory's cluster, with `.` and `..`, is on the disk before its entry.
            let c = m.alloc(1, None)?;
            let dot = |name: &[u8; 11], cluster: u32| DirEntry { name: *name, attr: ATTR_DIRECTORY, created: t, modified: t, accessed_date: t.date, cluster, ..DirEntry::default() };
            with_block_new(m.dev, m.cluster_at(c), m.cb, TAG_DIR, true, |b| {
                b.fill(0);
                dot(b".          ", c).write(&mut b[0..]);
                dot(b"..         ", parent_cluster).write(&mut b[32..]);
            })?;
            c
        } else {
            0
        };
        let e = DirEntry {
            name: short,
            attr: if is_dir { ATTR_DIRECTORY } else { ATTR_ARCHIVE | if read_only { ATTR_READ_ONLY } else { 0 } },
            nt_case,
            created: t,
            accessed_date: t.date,
            modified: t,
            cluster: first,
            size: 0,
        };
        write_entries(m, &slots, &e, long.as_deref(), false)?;
        let at = *slots.last().unwrap();
        let node = Node::from_entry(&e, dir, start + need as u32 - 1, need as u32 - 1, at);
        Ok((if is_dir { m.dir_id(first) } else { at / 32 }, node))
    })();
    match r {
        Ok((id, node)) => vget(mp, id, || Ok(node), vpp),
        Err(e) => e,
    }
}

/// A file made without its owner's write bit gets FAT's read-only attribute, as on FreeBSD.
extern "C" fn msdosfs_create(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    // SAFETY: the kernel's record.
    let read_only = !vap.is_null() && unsafe { (*vap).va_mode } & 0o200 == 0;
    new_entry(dvp, cnp, false, read_only, vpp)
}

extern "C" fn msdosfs_mkdir(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, _vap: *const Vattr) -> i32 {
    new_entry(dvp, cnp, true, false, vpp)
}

/// Whether directory `first` holds nothing but `.` and `..`.
fn dir_empty(m: &Fs, first: u32) -> Result<bool, i32> {
    let mut empty = true;
    scan(m, first, |f| {
        if &f.entry.name != b".          " && &f.entry.name != b"..         " {
            empty = false;
            return true;
        }
        false
    })?;
    Ok(empty)
}

/// Removes node `vp`'s name; its clusters go when it's no longer in use (`msdosfs_inactive`).
fn unlink(m: &Fs, vp: *mut Vnode) -> Result<(), i32> {
    let n = node_of(vp).ok_or(ENOENT)?;
    clear_entry(m, n)?;
    n.entry = None;
    n.unlinked = true;
    orphan(vp);
    Ok(())
}

extern "C" fn msdosfs_remove(_dvp: *mut Vnode, vp: *mut Vnode, _cnp: *const ComponentName) -> i32 {
    let m = fs(mount_of(vp));
    match writable(m).and_then(|()| unlink(m, vp)) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

extern "C" fn msdosfs_rmdir(_dvp: *mut Vnode, vp: *mut Vnode, _cnp: *const ComponentName) -> i32 {
    let m = fs(mount_of(vp));
    let r = (|| {
        writable(m)?;
        let n = node_of(vp).ok_or(ENOENT)?;
        if n.is_root {
            return Err(EINVAL);
        }
        if !dir_empty(m, n.first)? {
            return Err(ENOTEMPTY);
        }
        unlink(m, vp)
    })();
    r.err().unwrap_or(0)
}

extern "C" fn msdosfs_rename(
    _fdvp: *mut Vnode,
    fvp: *mut Vnode,
    _fcnp: *const ComponentName,
    tdvp: *mut Vnode,
    tvp: *mut Vnode,
    tcnp: *const ComponentName,
) -> i32 {
    let m = fs(mount_of(fvp));
    let r = (|| {
        writable(m)?;
        let fnode = node_of(fvp).ok_or(ENOENT)?;
        let tdn = node_of(tdvp).ok_or(ENOENT)?;
        let tdir = dir_of_node(m, tdn);
        let new_parent = if tdn.is_root { 0 } else { tdn.first };
        if !tvp.is_null() {
            let tn = node_of(tvp).ok_or(ENOENT)?;
            if tn.is_dir && !dir_empty(m, tn.first)? {
                return Err(ENOTEMPTY);
            }
            unlink(m, tvp)?;
        }
        // The old entry goes first: a crash between loses the name, never shares a chain.
        let old_parent = match fnode.entry {
            Some((d, ..)) => if d == m.root_first { 0 } else { d },
            None => return Err(ENOENT),
        };
        let old_entry = fnode.to_entry([b' '; 11], 0);
        clear_entry(m, fnode)?;
        fnode.entry = None;
        // SAFETY: the kernel's component.
        let (short, nt_case, long) = make_name(m, tdir, unsafe { (*tcnp).name() })?;
        let need = 1 + long.as_ref().map_or(0, |l| lfn_entries(l.len()));
        let (start, slots) = find_free(m, tdir, need)?;
        let e = DirEntry { name: short, nt_case, ..old_entry };
        write_entries(m, &slots, &e, long.as_deref(), true)?;
        let at = *slots.last().unwrap();
        fnode.entry = Some((tdir, start + need as u32 - 1, need as u32 - 1, at));
        if fnode.is_dir && old_parent != new_parent {
            // Its `..` names the new parent (0 for the root, as FAT wants).
            let dotdot = slot_at(m, fnode.first, 1)?;
            m.put_entry(dotdot, true, |b| {
                b[20..22].copy_from_slice(&((new_parent >> 16) as u16).to_le_bytes());
                b[26..28].copy_from_slice(&(new_parent as u16).to_le_bytes());
            })?;
        }
        if !fnode.is_dir {
            // A file's ID is where its entry is.
            // SAFETY: kernel export, a referenced vnode of ours.
            unsafe { oxidebsd_vfs_hash_rehash(fvp, at / 32) };
        }
        Ok(())
    })();
    r.err().unwrap_or(0)
}

/// Changes node `n`'s size: clusters past the new end go (its entry on the disk first), or new
/// ones, zeroed, are added.
fn resize(m: &mut Fs, n: &mut Node, size: u64) -> Result<(), i32> {
    if size > u32::MAX as u64 {
        return Err(EFBIG);
    }
    let have = if m.valid_cluster(n.first) { m.chain_len(n.first)? } else { 0 };
    let need = size.div_ceil(m.cb) as u32;
    let old = n.size as u64;
    if need > have {
        let last = if have == 0 { None } else { Some(chain_cluster(m, n.first, have - 1)?) };
        let first = m.alloc(need - have, last)?;
        if have == 0 {
            n.first = first;
        }
    }
    if size > old && have > 0 {
        // Zeros past the old end in its last cluster (newly added ones are zeroed already).
        let end = (have as u64 * m.cb).min(size);
        if end > old {
            let c = chain_cluster(m, n.first, (old / m.cb) as u32)?;
            let within = (old % m.cb) as usize;
            let upto = within + (end - old).min(m.cb - old % m.cb) as usize;
            with_block_mut(m.dev, m.cluster_at(c), m.cb, false, TAG_DATA, false, |b| b[within..upto].fill(0))?;
        }
    }
    n.size = size as u32;
    n.cursor = (0, n.first);
    if need < have {
        // The entry with its new size (and first cluster) on the disk, then the clusters freed.
        let freed = if need == 0 {
            let f = n.first;
            n.first = 0;
            update_entry(m, n, true)?;
            f
        } else {
            let last = chain_cluster(m, n.first, need - 1)?;
            update_entry(m, n, true)?;
            let rest = m.next(last)?.ok_or(EIO)?;
            m.fat_set(last, m.kind.eoc(), false)?;
            rest
        };
        n.cursor = (0, n.first);
        m.free_chain(freed)?;
    }
    Ok(())
}

/// The `index`th cluster of the chain from `first`.
fn chain_cluster(m: &Fs, first: u32, index: u32) -> Result<u32, i32> {
    let mut c = first;
    for _ in 0..index {
        c = m.next(c)?.ok_or(EIO)?;
    }
    Ok(c)
}

extern "C" fn msdosfs_setattr(vp: *mut Vnode, vap: *const Vattr, _cred: *const Ucred) -> i32 {
    let m = fs(mount_of(vp));
    let r = (|| {
        writable(m)?;
        let n = node_of(vp).ok_or(ENOENT)?;
        // SAFETY: the kernel's record.
        let va = unsafe { &*vap };
        // FAT keeps no owner: only the mount's own may be "set".
        if (va.va_uid != VNOVAL as u32 && va.va_uid != m.uid) || (va.va_gid != VNOVAL as u32 && va.va_gid != m.gid) {
            return Err(EPERM);
        }
        if va.va_flags != VNOVAL && va.va_flags != 0 {
            return Err(EOPNOTSUPP);
        }
        if n.is_root {
            return Ok(());
        }
        if va.va_size != VNOVAL {
            if n.is_dir {
                return Err(EISDIR);
            }
            resize(m, n, va.va_size)?;
            n.modified = now();
            n.attr |= ATTR_ARCHIVE;
        }
        if va.va_mode != VNOVAL as u32 && !n.is_dir {
            // The owner's write bit is FAT's read-only attribute.
            if va.va_mode & 0o200 == 0 {
                n.attr |= ATTR_READ_ONLY;
            } else {
                n.attr &= !ATTR_READ_ONLY;
            }
        }
        if va.va_mtime != VNOVAL_TIME {
            n.modified = dos(va.va_mtime);
            n.attr |= ATTR_ARCHIVE;
        }
        if va.va_atime != VNOVAL_TIME {
            n.accessed = dos(va.va_atime).date;
        }
        if va.va_birthtime != VNOVAL_TIME {
            n.created = dos(va.va_birthtime);
        }
        update_entry(m, n, false)
    })();
    r.err().unwrap_or(0)
}

extern "C" fn msdosfs_write(vp: *mut Vnode, uio: u64, ioflag: u32, _cred: *const Ucred) -> i64 {
    let m = fs(mount_of(vp));
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    if n.is_dir {
        return -(EISDIR as i64);
    }
    if !m.rw {
        return -(EROFS as i64);
    }
    // SAFETY: kernel exports.
    let (mut off, resid) = unsafe { (oxidebsd_uio_offset(uio), oxidebsd_uio_resid(uio)) };
    if ioflag & IO_APPEND != 0 {
        off = n.size as u64;
        // SAFETY: as above.
        unsafe { oxidebsd_uio_set_offset(uio, off) };
    }
    if resid == 0 {
        return 0;
    }
    let end = match off.checked_add(resid) {
        Some(e) if e <= u32::MAX as u64 => e,
        _ => return -(EFBIG as i64),
    };
    // Room first, so a full volume fails before anything is written.
    if end > n.size as u64 {
        let size = n.size as u64;
        if let Err(e) = resize(m, n, end) {
            return -(e as i64);
        }
        // `resize` set the size to the end; until the data's there, only what was.
        n.size = size as u32;
        if off > size {
            n.size = off as u32;
        }
    }
    let mut moved = 0i64;
    let mut chunk: Vec<u8> = Vec::new();
    while (moved as u64) < resid {
        let c = match cluster_for(m, n, off) {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => return if moved > 0 { moved } else { -(e as i64) },
        };
        let within = off % m.cb;
        let len = (resid - moved as u64).min(m.cb - within);
        // From the caller first, outside the buffer: the copy may fault on a mapped file.
        chunk.clear();
        if chunk.try_reserve(len as usize).is_err() {
            return if moved > 0 { moved } else { -(ENOMEM as i64) };
        }
        chunk.resize(len as usize, 0);
        // SAFETY: kernel export; a write transfer fills the buffer.
        let r = unsafe { oxidebsd_uiomove(chunk.as_mut_ptr(), len, uio) };
        if r <= 0 {
            if moved == 0 && r < 0 {
                return r;
            }
            break;
        }
        let r = r as u64;
        let whole = within == 0 && r == m.cb;
        let put = with_block_mut(m.dev, m.cluster_at(c), m.cb, whole, TAG_DATA, false, |b| {
            b[within as usize..(within + r) as usize].copy_from_slice(&chunk[..r as usize]);
        });
        if let Err(e) = put {
            return if moved > 0 { moved } else { -(e as i64) };
        }
        moved += r as i64;
        off += r;
        if off > n.size as u64 {
            n.size = off as u32;
        }
    }
    n.modified = now();
    n.attr |= ATTR_ARCHIVE;
    if update_entry(m, n, false).is_err() && moved == 0 {
        return -(EIO as i64);
    }
    if ioflag & IO_SYNC != 0 {
        // SAFETY: kernel export.
        unsafe { oxidebsd_bflush(m.dev, 0, 0) };
    }
    moved
}

extern "C" fn msdosfs_fsync(vp: *mut Vnode, _waitfor: i32, _data_only: u32) -> i32 {
    // SAFETY: kernel export: data, then the FAT, then directories (the hook's order).
    unsafe { oxidebsd_bflush(fs(mount_of(vp)).dev, 0, 0) };
    0
}

/// A removed file's clusters go with its last use.
extern "C" fn msdosfs_inactive(vp: *mut Vnode) -> i32 {
    let mp = mount_of(vp);
    if let Some(n) = node_of(vp)
        && n.unlinked
    {
        let m = fs(mp);
        if m.valid_cluster(n.first) && m.free_chain(n.first).is_err() {
            log("[msdosfs] couldn't free a removed file's clusters\n");
        }
        n.first = 0;
        // SAFETY: kernel exports.
        unsafe { oxidebsd_vfs_recycle(mp, (*vp).v_fileid) };
    }
    0
}

// --- Loading -----------------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // SAFETY: kernel exports, with a static table.
    unsafe {
        oxidebsd_module_serialize();
        if oxidebsd_vfs_register(&MSDOSFS_VFSCONF) != 0 {
            log("[msdosfs] registering the type failed\n");
            return -1;
        }
    }
    0
}
