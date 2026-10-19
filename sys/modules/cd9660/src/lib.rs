//! cd9660 (`OxideBSD-doc/INSTALLER.md` §6, `cd9660(5)`): ISO 9660 read-only, FreeBSD's name and
//! mount options. The on-disk format is `lib/libcd9660`'s.
//!
//! Names come from Rock Ridge where the disc has it (POSIX names, modes, owners, times, symbolic
//! links, relocated deep directories), else from Joliet (UCS-2 names), else the plain ISO 9660
//! names, their version dropped and in lower case. `norrip` and `nojoliet` (mount_cd9660(8)'s
//! `-r` and `-j`) skip the first two. Only the first session is read. Without Rock Ridge every
//! file is owned by root and mode 0555, as on FreeBSD.
//!
//! Every block goes through the kernel's buffer cache in 2048-byte logical blocks (a CD's own
//! sector). A file's ID is the disc byte offset of its directory record; a directory's is its
//! first block's offset, so its entry above, its `.` and `..` from below name the same vnode.
//!
//! Everything on the disc is untrusted: lengths are checked by `libcd9660`, continuation areas are
//! followed at most `MAX_CONTINUATIONS` deep, and a directory or file is read only within its own
//! recorded size.
//!
//! The mount is always read-only: a read-write mount is made read-only, and `mount -u -w` is
//! refused (`EROFS`).
#![no_std]

extern crate alloc;
use kern_mod as _;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;

use cd9660_format::{self as iso, BLOCK, Descriptor, Record, RockRidge};
use vfs_if::*;

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_uiomove(kbuf: *mut u8, len: u64, uio: u64) -> i64;
    fn oxidebsd_uio_resid(uio: u64) -> u64;
    fn oxidebsd_uio_offset(uio: u64) -> u64;
    fn oxidebsd_uio_set_offset(uio: u64, offset: u64);
    fn oxidebsd_module_serialize();
    fn oxidebsd_bdev_sectors(dev: u64) -> u64;
    fn oxidebsd_bread(dev: u64, blkno: u64, size: u64, ahead: u64) -> i64;
    fn oxidebsd_bdata(b: u64) -> u64;
    fn oxidebsd_brelse(b: u64);
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
/// Linux's `ISOFS_SUPER_MAGIC`, `statfs(2)`'s `f_type`.
const ISOFS_MAGIC: u64 = 0x9660;
/// Volume descriptors looked at, at most, before giving up on a terminator.
const MAX_DESCRIPTORS: u32 = 64;
/// Rock Ridge continuation areas followed for one file, at most (a loop of them is a bad disc).
const MAX_CONTINUATIONS: u32 = 16;
/// Blocks read ahead of a file's block on a miss (with it, 64 KiB: one CD command).
const READ_AHEAD: u64 = 31;
/// Directory entries a `readdir` call gathers at most.
const READDIR_BATCH: usize = 256;

fn log(s: &str) {
    // SAFETY: kernel export.
    unsafe { oxidebsd_log(s.as_ptr(), s.len() as u64) };
}

// --- The mount -------------------------------------------------------------------------------

/// Where names and attributes come from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Names {
    /// Rock Ridge, its System Use areas skipping this many bytes (`SP`'s `LEN_SKP`).
    RockRidge(u8),
    Joliet,
    Plain,
}

struct Fs {
    dev: u64,
    names: Names,
    /// The volume's size in blocks.
    blocks: u32,
    root_extent: u32,
}

fn fs(mp: *mut Mount) -> &'static Fs {
    // SAFETY: `mnt_data` holds the pointer `cd9660_mount` stored, live until unmount.
    unsafe { &**((*mp).mnt_data as *mut *mut Fs) }
}

/// Logical block `lba` of the disc, copied out of the cache (the caller may read others while it
/// uses it). `ahead`: blocks after it worth reading in the same command.
fn read_block(dev: u64, lba: u32, ahead: u64) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    out.try_reserve_exact(BLOCK).map_err(|_| ENOMEM)?;
    with_block(dev, lba, ahead, |b| out.extend_from_slice(b))?;
    Ok(out)
}

/// Runs `f` on logical block `lba`, through the cache.
fn with_block<R>(dev: u64, lba: u32, ahead: u64, f: impl FnOnce(&[u8]) -> R) -> Result<R, i32> {
    // SAFETY: kernel export.
    let b = unsafe { oxidebsd_bread(dev, lba as u64 * (BLOCK as u64 / SECTOR), BLOCK as u64, ahead) };
    if b < 0 {
        return Err(EIO);
    }
    // SAFETY: the kernel maps a held buffer's whole block at its data address.
    let bytes = unsafe { core::slice::from_raw_parts(oxidebsd_bdata(b as u64) as *const u8, BLOCK) };
    let r = f(bytes);
    // SAFETY: `b` is held.
    unsafe { oxidebsd_brelse(b as u64) };
    Ok(r)
}

/// A file's Rock Ridge entries: its System Use area (past `skip` bytes) and the continuation
/// areas it chains to.
fn rock_ridge(dev: u64, system_use: &[u8], skip: u8) -> RockRidge {
    let mut rr = RockRidge::default();
    rr.parse(system_use.get(skip as usize..).unwrap_or(&[]));
    let mut hops = 0;
    while let Some((block, offset, len)) = rr.continuation.take() {
        hops += 1;
        let (offset, len) = (offset as usize, len as usize);
        if hops > MAX_CONTINUATIONS || offset.checked_add(len).is_none_or(|end| end > BLOCK) {
            break;
        }
        let Ok(area) = read_block(dev, block, 0) else { break };
        rr.parse(&area[offset..offset + len]);
    }
    rr
}

/// The options the kernel passed (`name\0value\0` pairs): `norrip`, `nojoliet` (FreeBSD's
/// names). `EINVAL` for anything else.
fn parse_options(args: &MountArgs) -> Result<(bool, bool), i32> {
    let (mut norrip, mut nojoliet) = (false, false);
    if args.opts.is_null() || args.opts_len == 0 {
        return Ok((norrip, nojoliet));
    }
    // SAFETY: the kernel's buffer, live for the call.
    let buf = unsafe { core::slice::from_raw_parts(args.opts, args.opts_len) };
    let mut fields = buf.split(|&b| b == 0);
    while let Some(name) = fields.next() {
        if name.is_empty() {
            continue;
        }
        let _value = fields.next();
        match name {
            b"norrip" => norrip = true,
            b"nojoliet" => nojoliet = true,
            _ => return Err(EINVAL),
        }
    }
    Ok((norrip, nojoliet))
}

// --- Nodes -------------------------------------------------------------------------------------

/// What a vnode's `v_data` points at.
struct Node {
    vtype: VType,
    is_root: bool,
    /// The data: `(first block, bytes)` per extent (more than one for a multi-extent file).
    extents: Vec<(u32, u32)>,
    size: u64,
    /// A directory's parent's first block (the root's is its own).
    parent: u32,
    mode: u32,
    nlink: u64,
    uid: u32,
    gid: u32,
    mtime: i64,
    atime: i64,
    ctime: i64,
    birthtime: i64,
    /// A symbolic link's target (Rock Ridge `SL`).
    link: Option<String>,
}

impl Node {
    /// A node from a directory record's attributes and its Rock Ridge entries, if any.
    fn new(vtype: VType, extents: Vec<(u32, u32)>, recorded: i64, rr: Option<&RockRidge>) -> Node {
        let size = extents.iter().map(|&(_, len)| len as u64).sum();
        let mut n = Node {
            vtype,
            is_root: false,
            extents,
            size,
            parent: 0,
            mode: 0o555,
            nlink: if vtype == VDIR { 2 } else { 1 },
            uid: 0,
            gid: 0,
            mtime: recorded,
            atime: recorded,
            ctime: recorded,
            birthtime: recorded,
            link: None,
        };
        if let Some(rr) = rr {
            if let Some(mode) = rr.mode {
                n.mode = mode & 0o7777;
                if rr.nlink > 0 {
                    n.nlink = rr.nlink as u64;
                }
                n.uid = rr.uid;
                n.gid = rr.gid;
            }
            n.mtime = rr.mtime.unwrap_or(recorded);
            n.atime = rr.atime.unwrap_or(n.mtime);
            n.ctime = rr.ctime.unwrap_or(n.mtime);
            n.birthtime = rr.birthtime.unwrap_or(n.mtime);
            if vtype == VLNK {
                n.link = rr.link.clone();
            }
        }
        n
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
    // SAFETY: `T` is never zero-sized here; a non-null result is fresh memory for one `T`, which
    // the `Box` then owns, as `Box::new` would.
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

/// A directory's ID: its first block's disc byte offset.
fn dir_id(extent: u32) -> u64 {
    extent as u64 * BLOCK as u64
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
        let e = oxidebsd_getnewvnode(mp, (*node).vtype, id, &mut vp);
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

/// The directory whose first block is `extent`, from its own `.` record (its size, and under Rock
/// Ridge its attributes) and its `..` record (its parent, or Rock Ridge's `PL` for a relocated
/// one).
fn dir_node(m: &Fs, extent: u32) -> Result<Node, i32> {
    let block = read_block(m.dev, extent, 0)?;
    let mut it = iso::records(&block);
    let (Some((_, dot)), Some((_, dotdot))) = (it.next(), it.next()) else { return Err(EIO) };
    if !dot.is_self() || !dotdot.is_parent() {
        return Err(EIO);
    }
    let (rr, parent) = match m.names {
        Names::RockRidge(skip) => {
            let rr = rock_ridge(m.dev, dot.system_use, skip);
            let up = rock_ridge(m.dev, dotdot.system_use, skip);
            (Some(rr), up.parent.unwrap_or(dotdot.extent))
        }
        _ => (None, dotdot.extent),
    };
    let mut n = Node::new(VDIR, alloc::vec![(extent, dot.size)], dot.recorded, rr.as_ref());
    n.is_root = extent == m.root_extent;
    n.parent = if n.is_root { extent } else { parent };
    Ok(n)
}

/// One file in a directory, as `scan` gives it: the records of a multi-extent file joined.
struct Entry {
    /// Its first record's byte offset in the directory, and the offset after its last.
    pos: u64,
    next: u64,
    id: u64,
    name: String,
    vtype: VType,
    extents: Vec<(u32, u32)>,
    recorded: i64,
    rr: Option<RockRidge>,
    is_self: bool,
    is_parent: bool,
}

/// The name a record shows under `names`.
fn shown_name(names: Names, r: &Record, rr: Option<&RockRidge>) -> String {
    match (names, rr.and_then(|rr| rr.name.clone())) {
        (Names::RockRidge(_), Some(name)) => name,
        (Names::Joliet, _) => iso::joliet_name(r.name),
        _ => iso::plain_name(r.name),
    }
}

/// Calls `f` on each file of directory `dir` (a directory node) from byte offset `start`, in
/// order, until it returns `true`. Hidden: associated files, Rock Ridge relocated directories'
/// own entries (`RE`: they show at their `CL` entry), records with no name.
fn scan(m: &Fs, dir: &Node, start: u64, mut f: impl FnMut(Entry) -> bool) -> Result<(), i32> {
    let Some(&(extent, size)) = dir.extents.first() else { return Ok(()) };
    let blocks = (size as u64).div_ceil(BLOCK as u64);
    let mut pending: Option<Entry> = None;
    let mut b = start / BLOCK as u64;
    while b < blocks {
        let lba = extent.checked_add(b as u32).ok_or(EIO)?;
        if lba >= m.blocks {
            return Err(EIO);
        }
        let block = read_block(m.dev, lba, (blocks - b - 1).min(READ_AHEAD))?;
        for (off, r) in iso::records(&block) {
            let pos = b * BLOCK as u64 + off as u64;
            if pos < start && pending.is_none() {
                continue;
            }
            let next = pos + r.len as u64;
            // A later extent of the file `pending` holds.
            if let Some(p) = pending.as_mut() {
                p.extents.push((r.extent, r.size));
                p.next = next;
                if r.flags & iso::FLAG_MULTI_EXTENT == 0 {
                    let done = pending.take().unwrap();
                    if f(done) {
                        return Ok(());
                    }
                }
                continue;
            }
            if r.flags & iso::FLAG_ASSOCIATED != 0 || r.name.is_empty() {
                continue;
            }
            let rr = match m.names {
                Names::RockRidge(skip) => Some(rock_ridge(m.dev, r.system_use, skip)),
                _ => None,
            };
            if rr.as_ref().is_some_and(|rr| rr.relocated) {
                continue;
            }
            let disc_offset = lba as u64 * BLOCK as u64 + off as u64;
            let (vtype, id, extents) = match rr.as_ref().and_then(|rr| rr.child) {
                // A relocated directory, standing here.
                Some(child) => (VDIR, dir_id(child), alloc::vec![(child, 0)]),
                None if r.is_dir() => (VDIR, dir_id(r.extent), alloc::vec![(r.extent, r.size)]),
                None => {
                    let link = rr.as_ref().and_then(|rr| rr.mode).is_some_and(|m| m & iso::S_IFMT == iso::S_IFLNK);
                    (if link { VLNK } else { VREG }, disc_offset, alloc::vec![(r.extent, r.size)])
                }
            };
            let e = Entry {
                pos,
                next,
                id,
                name: shown_name(m.names, &r, rr.as_ref()),
                vtype,
                extents,
                recorded: r.recorded,
                is_self: r.is_self(),
                is_parent: r.is_parent(),
                rr,
            };
            if r.flags & iso::FLAG_MULTI_EXTENT != 0 && !e.is_self && !e.is_parent {
                pending = Some(e);
                continue;
            }
            if f(e) {
                return Ok(());
            }
        }
        b += 1;
    }
    Ok(())
}

// --- vfsops ------------------------------------------------------------------------------------

static CD9660_VFSOPS: VfsOps = VfsOps {
    mount: Some(cd9660_mount),
    unmount: Some(cd9660_unmount),
    root: Some(cd9660_root),
    statfs: Some(cd9660_statfs),
    sync: None,
    vget: None,
};

static CD9660_VFSCONF: VfsConf = VfsConf {
    name: b"cd9660".as_ptr(),
    name_len: 6,
    ops: &CD9660_VFSOPS,
    vops: &CD9660_VOPS,
    mnt_data_size: 8,
    v_data_size: 8,
    flags: 0,
};

extern "C" fn cd9660_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel's argument record and mount, live for the call.
    let (args, flags) = unsafe { (&*args, (*mp).mnt_flag) };
    if flags & MNT_UPDATE != 0 {
        return if flags & MNT_RDONLY == 0 { EROFS } else { 0 };
    }
    let (norrip, nojoliet) = match parse_options(args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if args.dev == NODEV {
        return ENXIO;
    }
    // SAFETY: kernel export.
    let sectors = unsafe { oxidebsd_bdev_sectors(args.dev) };
    if sectors == 0 {
        return ENXIO; // an empty drive
    }
    // The volume descriptors, from block 16 to the terminator.
    let mut primary: Option<(u32, u32, u32)> = None; // (blocks, root extent, root size)
    let mut joliet: Option<(u32, u32)> = None;
    for lba in iso::FIRST_DESCRIPTOR..iso::FIRST_DESCRIPTOR + MAX_DESCRIPTORS {
        if lba as u64 * (BLOCK as u64 / SECTOR) >= sectors {
            break;
        }
        let Ok(block) = read_block(args.dev, lba, 0) else { return EIO };
        match iso::descriptor(&block) {
            Some(Descriptor::Primary(v)) if primary.is_none() => {
                if v.block_size as usize != BLOCK {
                    log("[cd9660] logical blocks other than 2048 bytes aren't supported\n");
                    return EINVAL;
                }
                primary = Some((v.blocks, v.root.extent, v.root.size));
            }
            Some(Descriptor::Joliet(v)) if joliet.is_none() && v.block_size as usize == BLOCK => {
                joliet = Some((v.root.extent, v.root.size));
            }
            Some(Descriptor::Terminator) | None => break,
            _ => {}
        }
    }
    let Some((blocks, root_extent, _)) = primary else {
        log("[cd9660] no ISO 9660 file system there (no primary volume descriptor)\n");
        return EINVAL;
    };
    let mut m = Fs { dev: args.dev, names: Names::Plain, blocks, root_extent };
    // Rock Ridge: SUSP's `SP` opens the root's `.` record's System Use area.
    if !norrip
        && let Ok(block) = read_block(args.dev, root_extent, 0)
        && let Some((_, dot)) = iso::records(&block).next()
    {
        let mut rr = RockRidge::default();
        rr.parse(dot.system_use);
        if let Some(skip) = rr.sp_skip {
            let rr = rock_ridge(args.dev, dot.system_use, skip);
            if rr.extension || rr.any {
                m.names = Names::RockRidge(skip);
            }
        }
    }
    if m.names == Names::Plain
        && !nojoliet
        && let Some((extent, _)) = joliet
    {
        m.names = Names::Joliet;
        m.root_extent = extent;
    }
    let Some(b) = try_box(m) else { return ENOMEM };
    // SAFETY: `mnt_data` is 8 bytes for the pointer; the mount is always read-only, which the
    // kernel reads back.
    unsafe {
        *((*mp).mnt_data as *mut *mut Fs) = Box::into_raw(b);
        (*mp).mnt_flag |= MNT_RDONLY;
    }
    // The root must be readable now, not at the first lookup.
    let m = fs(mp);
    if let Err(e) = dir_node(m, m.root_extent) {
        // SAFETY: made above, never shared.
        unsafe {
            drop(Box::from_raw(*((*mp).mnt_data as *mut *mut Fs)));
            *((*mp).mnt_data as *mut *mut Fs) = ptr::null_mut();
        }
        return e;
    }
    0
}

extern "C" fn cd9660_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    // SAFETY: kernel export. The cache forgets the device's blocks: the next disc in the drive
    // has other ones.
    unsafe {
        let p = *((*mp).mnt_data as *mut *mut Fs);
        oxidebsd_binvalall((*p).dev);
        drop(Box::from_raw(p));
        *((*mp).mnt_data as *mut *mut Fs) = ptr::null_mut();
    }
    0
}

extern "C" fn cd9660_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    let m = fs(mp);
    vget(mp, dir_id(m.root_extent), || dir_node(m, m.root_extent), vpp)
}

extern "C" fn cd9660_statfs(mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    let m = fs(mp);
    // SAFETY: the kernel's record.
    let sb = unsafe { &mut *sbp };
    sb.f_bsize = BLOCK as u64;
    sb.f_iosize = BLOCK as u64;
    sb.f_blocks = m.blocks as u64;
    sb.f_bfree = 0;
    sb.f_bavail = 0;
    sb.f_files = 0;
    sb.f_ffree = 0;
    sb.f_namemax = 255;
    sb.f_magic = ISOFS_MAGIC;
    0
}

// --- Vnode operations --------------------------------------------------------------------------

static CD9660_VOPS: VopVector = VopVector {
    lookup: Some(cd9660_lookup),
    getattr: Some(cd9660_getattr),
    read: Some(cd9660_read),
    readdir: Some(cd9660_readdir),
    readlink: Some(cd9660_readlink),
    reclaim: Some(cd9660_reclaim),
    pathconf: Some(cd9660_pathconf),
    ..VopVector::DEFAULT
};

extern "C" fn cd9660_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32 {
    let mp = mount_of(dvp);
    let m = fs(mp);
    let Some(dn) = node_of(dvp) else { return ENOENT };
    if dn.vtype != VDIR {
        return ENOTDIR;
    }
    // SAFETY: the kernel's component.
    let (flags, nameiop, raw) = unsafe { ((*cnp).cn_flags, (*cnp).cn_nameiop, (*cnp).name()) };
    if raw == b"." {
        // SAFETY: a referenced vnode of ours, and the kernel's out-parameter.
        unsafe {
            oxidebsd_vref(dvp);
            *vpp = dvp;
        }
        return 0;
    }
    if flags & ISDOTDOT != 0 || raw == b".." {
        let parent = dn.parent;
        return vget(mp, dir_id(parent), || dir_node(m, parent), vpp);
    }
    let mut found: Option<Entry> = None;
    let r = scan(m, dn, 0, |e| {
        if !e.is_self && !e.is_parent && e.name.as_bytes() == raw {
            found = Some(e);
            return true;
        }
        false
    });
    if let Err(e) = r {
        return e;
    }
    match found {
        Some(e) if e.vtype == VDIR => {
            let extent = e.extents[0].0;
            vget(mp, e.id, || dir_node(m, extent), vpp)
        }
        Some(e) => vget(mp, e.id, || Ok(Node::new(e.vtype, e.extents, e.recorded, e.rr.as_ref())), vpp),
        // A read-only file system: nothing is made here.
        None if flags & ISLASTCN != 0 && (nameiop == CREATE || nameiop == RENAME) => EROFS,
        None => ENOENT,
    }
}

extern "C" fn cd9660_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    let Some(n) = node_of(vp) else { return EIO };
    // SAFETY: a live vnode.
    let id = unsafe { (*vp).v_fileid };
    let ts = |t: i64| Timespec { tv_sec: t, tv_nsec: 0 };
    let bytes: u64 = n.extents.iter().map(|&(_, len)| (len as u64).div_ceil(BLOCK as u64) * BLOCK as u64).sum();
    let size = match &n.link {
        Some(target) => target.len() as u64,
        None => n.size,
    };
    // SAFETY: the kernel's record.
    let va = unsafe { &mut *vap };
    *va = Vattr {
        va_type: n.vtype,
        va_mode: n.mode,
        va_nlink: n.nlink,
        va_uid: n.uid,
        va_gid: n.gid,
        va_fsid: 0,
        va_fileid: id,
        va_size: size,
        va_blocksize: BLOCK as u64,
        va_atime: ts(n.atime),
        va_mtime: ts(n.mtime),
        va_ctime: ts(n.ctime),
        va_birthtime: ts(n.birthtime),
        va_gen: 0,
        va_flags: 0,
        va_rdev: 0,
        va_bytes: bytes,
        va_vaflags: 0,
    };
    0
}

extern "C" fn cd9660_read(vp: *mut Vnode, uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    let m = fs(mount_of(vp));
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    if n.vtype == VDIR {
        return -(EISDIR as i64);
    }
    // SAFETY: kernel export.
    let mut off = unsafe { oxidebsd_uio_offset(uio) };
    let mut moved = 0i64;
    let mut chunk = Vec::new();
    loop {
        // SAFETY: kernel export.
        let resid = unsafe { oxidebsd_uio_resid(uio) };
        if resid == 0 || off >= n.size {
            break;
        }
        // The extent holding byte `off`, and where in it.
        let mut base = 0u64;
        let Some(&(extent, len)) = n.extents.iter().find(|&&(_, len)| {
            let hit = off < base + len as u64;
            if !hit {
                base += len as u64;
            }
            hit
        }) else {
            break;
        };
        let within = off - base;
        let block = within / BLOCK as u64;
        let in_block = within % BLOCK as u64;
        let take = resid.min(BLOCK as u64 - in_block).min(len as u64 - within);
        let Some(lba) = extent.checked_add(block as u32).filter(|&l| l < m.blocks) else {
            return if moved > 0 { moved } else { -(EIO as i64) };
        };
        let left = (len as u64).div_ceil(BLOCK as u64) - block - 1;
        // Copied out of the buffer before moving it to the caller: the copy may fault on a page
        // of a mapped file of this very file system.
        chunk.clear();
        if chunk.try_reserve(take as usize).is_err() {
            return if moved > 0 { moved } else { -(ENOMEM as i64) };
        }
        let r = with_block(m.dev, lba, left.min(READ_AHEAD), |b| {
            chunk.extend_from_slice(&b[in_block as usize..(in_block + take) as usize]);
        });
        if let Err(e) = r {
            return if moved > 0 { moved } else { -(e as i64) };
        }
        // SAFETY: kernel export; a read transfer only reads the buffer.
        let r = unsafe { oxidebsd_uiomove(chunk.as_mut_ptr(), take, uio) };
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

/// `readdir`: positions are byte offsets in the directory, `.` and `..` its first two records.
extern "C" fn cd9660_readdir(vp: *mut Vnode, uio: u64, _cred: *const Ucred, eofflag: *mut i32) -> i64 {
    let m = fs(mount_of(vp));
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    if n.vtype != VDIR {
        return -(ENOTDIR as i64);
    }
    // SAFETY: a live vnode, and kernel export.
    let (self_id, start) = unsafe { ((*vp).v_fileid, oxidebsd_uio_offset(uio)) };
    let parent_id = dir_id(n.parent);
    // The records, gathered first (each block is read whole before its entries go out).
    let mut records: Vec<(u64, u64, u64, u8, String)> = Vec::new();
    let r = scan(m, n, start, |e| {
        let (id, name) = if e.is_self {
            (self_id, String::from("."))
        } else if e.is_parent {
            (parent_id, String::from(".."))
        } else {
            (e.id, e.name)
        };
        records.push((e.pos, e.next, id, vtype_to_dt(e.vtype), name));
        records.len() >= READDIR_BATCH
    });
    if let Err(e) = r {
        return -(e as i64);
    }
    let complete = records.len() < READDIR_BATCH;
    let mut record = [0u8; dirent_reclen(1024)];
    let mut written = 0i64;
    let mut cursor = start;
    let mut eof = complete;
    for (_pos, next, id, dt, name) in &records {
        let name = &name.as_bytes()[..name.len().min(1024)];
        let reclen = dirent_reclen(name.len());
        // SAFETY: kernel export.
        if (unsafe { oxidebsd_uio_resid(uio) } as usize) < reclen {
            eof = false;
            break;
        }
        dirent_encode(&mut record, *id, *next as i64, *dt, name);
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
        cursor = *next;
    }
    // SAFETY: as above.
    unsafe {
        oxidebsd_uio_set_offset(uio, cursor);
        *eofflag = eof as i32;
    }
    written
}

extern "C" fn cd9660_readlink(vp: *mut Vnode, uio: u64, _cred: *const Ucred) -> i64 {
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    let Some(target) = n.link.as_ref() else { return -(EINVAL as i64) };
    let mut bytes = target.clone().into_bytes();
    // SAFETY: kernel export; a read transfer only reads the buffer.
    unsafe { oxidebsd_uiomove(bytes.as_mut_ptr(), bytes.len() as u64, uio) }
}

extern "C" fn cd9660_reclaim(vp: *mut Vnode) -> i32 {
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

/// `_PC_LINK_MAX` (Rock Ridge keeps link counts; plain ISO 9660 has none), `_PC_NAME_MAX` 255.
extern "C" fn cd9660_pathconf(vp: *mut Vnode, name: i32, retval: *mut i64) -> i32 {
    const PC_LINK_MAX: i32 = 0;
    const PC_NAME_MAX: i32 = 3;
    let m = fs(mount_of(vp));
    let v = match name {
        PC_LINK_MAX => if matches!(m.names, Names::RockRidge(_)) { 65535 } else { 1 },
        PC_NAME_MAX => 255,
        _ => return EINVAL,
    };
    // SAFETY: the kernel's out-parameter.
    unsafe { *retval = v };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // SAFETY: kernel exports; the configuration is static.
    unsafe {
        oxidebsd_module_serialize();
        if oxidebsd_vfs_register(&CD9660_VFSCONF) != 0 {
            log("[cd9660] couldn't register the file system type\n");
            return -1;
        }
    }
    0
}
