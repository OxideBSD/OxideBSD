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
//! repair.
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
    fn oxidebsd_bread(dev: u64, blkno: u64, size: u64, ahead: u64) -> i64;
    fn oxidebsd_bdata(b: u64) -> u64;
    fn oxidebsd_brelse(b: u64);
    fn oxidebsd_bflush(dev: u64, mask: u64, value: u64);
    fn oxidebsd_binvalall(dev: u64);
}

const ENOENT: i32 = 2;
const EIO: i32 = 5;
const ENXIO: i32 = 6;
const ENOMEM: i32 = 12;
const EFAULT: i32 = 14;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const EROFS: i32 = 30;

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
    /// Free clusters, once known.
    free: Option<u32>,
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
    /// Where the short entry is: its directory's first cluster (0: the fixed root), its slot, and
    /// how many long-name slots come before it. `None` for the root.
    entry: Option<(u32, u32, u32)>,
    /// The last position a read reached in the chain: (cluster index, cluster).
    cursor: (u32, u32),
}

impl Node {
    fn from_entry(e: &DirEntry, dir_first: u32, slot: u32, lfn: u32) -> Node {
        Node {
            is_dir: e.attr & ATTR_DIRECTORY != 0,
            is_root: false,
            first: e.cluster,
            size: if e.attr & ATTR_DIRECTORY != 0 { 0 } else { e.size },
            attr: e.attr,
            created: e.created,
            modified: e.modified,
            accessed: e.accessed_date,
            entry: Some((dir_first, slot, lfn)),
            cursor: (0, e.cluster),
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
            node = Some(Node::from_entry(&f.entry, dir, f.slot, f.lfn));
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
    flags: 0,
};

extern "C" fn msdosfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel's argument record and mount, live for the call.
    let (args, flags) = unsafe { (&*args, (*mp).mnt_flag) };
    let opts = match parse_options(args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if flags & MNT_UPDATE != 0 {
        // Only read-only stays read-only until writing is supported.
        return if flags & MNT_RDONLY == 0 { EROFS } else { 0 };
    }
    if flags & MNT_RDONLY == 0 {
        return EROFS;
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
    };
    let Some(b) = try_box(m) else { return ENOMEM };
    // SAFETY: `mnt_data` is 8 bytes for the pointer.
    unsafe { *((*mp).mnt_data as *mut *mut Fs) = Box::into_raw(b) };
    0
}

extern "C" fn msdosfs_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    let m = fs(mp);
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
    getattr: Some(msdosfs_getattr),
    read: Some(msdosfs_read),
    readdir: Some(msdosfs_readdir),
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
            found = Some((found_id(m, f), Node::from_entry(&f.entry, dir, f.slot, f.lfn)));
            return true;
        }
        false
    });
    if let Err(e) = r {
        return e;
    }
    match found {
        Some((id, node)) => vget(mp, id, || Ok(node), vpp),
        None if flags & ISLASTCN != 0 && (nameiop == CREATE || nameiop == RENAME) => EROFS,
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
