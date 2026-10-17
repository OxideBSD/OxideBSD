//! tmpfs (OxideBSD-doc `VFS.md` §8.1, `tmpfs(5)`): a file system in memory, FreeBSD's in shape.
//! Each mount has its own nodes, its own file IDs and its own limits; nothing is kept on a disk,
//! and everything goes at unmount.
//!
//! A node (`Node`, FreeBSD's `tmpfs_node`) lives on the kernel heap and is named by the directory
//! entries pointing at it; its vnode's `v_data` holds a pointer to it. A regular file's data is
//! pages from the frame allocator, never the heap (an eighth of RAM, 8 MiB on a 64 MB machine):
//! the first `NDIRECT` pages directly in the node, the rest through index pages of 512 page
//! addresses each, also from the frame allocator. A page never written is a hole and reads as
//! zeros.
//!
//! Limits, per mount (`mount_tmpfs` options, as FreeBSD's): `size` (default RAM/16, at least 8
//! MiB and at most 64 MiB), `nodes` (default 3 + size/1 KiB), `maxfilesize` (default none but `size`); and
//! for every mount at once, no page is taken when the free memory would drop below
//! `vfs.tmpfs.memory_reserved` (the kernel's). `mount -u -o size=` changes the size.
#![no_std]

extern crate alloc;
use kern_mod as _;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;

use vfs_if::*;

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_uiomove(kbuf: *mut u8, len: u64, uio: u64) -> i64;
    fn oxidebsd_uio_resid(uio: u64) -> u64;
    fn oxidebsd_uio_offset(uio: u64) -> u64;
    fn oxidebsd_uio_set_offset(uio: u64, offset: u64);
    fn oxidebsd_unix_time() -> i64;
    fn oxidebsd_physmem_bytes() -> u64;
    /// A zeroed page (its kernel address), or `0` when there is none to spare above
    /// `vfs.tmpfs.memory_reserved`; given back with `oxidebsd_page_free`.
    fn oxidebsd_tmpfs_page_alloc() -> u64;
    fn oxidebsd_page_free(page: u64);
    fn oxidebsd_module_serialize();
    /// The attributes of any vnode (the kernel's `vop_getattr`): the directory a mount covers.
    fn oxidebsd_vop_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32;
}

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const ENOMEM: i32 = 12;
const EFAULT: i32 = 14;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const EXDEV: i32 = 18;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const EFBIG: i32 = 27;
const ENOSPC: i32 = 28;
const EMLINK: i32 = 31;
const ENAMETOOLONG: i32 = 36;
const ENOTEMPTY: i32 = 39;

const PAGE: u64 = 4096;
const NAME_MAX: usize = 255;
/// Linux's `TMPFS_MAGIC`, what `statfs(2)`'s `f_type` says.
const TMPFS_MAGIC: u64 = 0x0102_1994;
/// The root's file ID, as on FreeBSD (and every BSD's UFS).
const ROOT_ID: u64 = 2;
const LINK_MAX: u64 = 32767;

/// Pages a file holds in its node before it needs index pages.
const NDIRECT: usize = 8;
/// Page addresses in one index page.
const PER_INDEX: usize = (PAGE as usize) / 8;

const MIB: u64 = 1 << 20;
const MIN_DEFAULT_SIZE: u64 = 8 * MIB;
const MAX_DEFAULT_SIZE: u64 = 64 * MIB;

/// `S_ISUID | S_ISGID`.
const SETID_BITS: u32 = 0o6000;

// --- Nodes ---------------------------------------------------------------------------------------

struct Node {
    id: u64,
    vtype: VType,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    birthtime: Timespec,
    rdev: u64,
    /// `chflags(2)`'s.
    flags: u64,
    data: Data,
}

enum Data {
    Dir(Dir),
    Reg(Pages),
    Lnk(Box<[u8]>),
    /// Devices, FIFOs and sockets: only attributes.
    Special,
}

struct Dir {
    /// `..`: the directory this one is in (the root's own: `namei` leaves at the mount root).
    parent: *mut Node,
    /// In cookie order, the order they were made: `readdir`'s position is a cookie, so a name
    /// added or removed meanwhile doesn't make a listing skip or repeat one.
    entries: Vec<Entry>,
    /// The next entry's; `0` and `1` are `.` and `..`.
    next_cookie: u64,
}

struct Entry {
    cookie: u64,
    name: Box<[u8]>,
    node: *mut Node,
}

/// A regular file's pages: kernel addresses of frames, `0` for a hole.
struct Pages {
    direct: [u64; NDIRECT],
    /// Index pages for pages `NDIRECT..`, `0` where none was needed yet.
    index: Vec<u64>,
    /// Data pages held (not index pages).
    held: u64,
}

impl Dir {
    fn find(&self, name: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| &*e.name == name)
    }
}

/// One mount's state; `mnt_data` holds a pointer to it.
struct TmpMount {
    root: *mut Node,
    next_id: u64,
    /// Pages held (data and index), and the most it may hold (`size`).
    pages: u64,
    max_pages: u64,
    nodes: u64,
    max_nodes: u64,
    maxfilesize: u64,
    /// Regular files here are POSIX shared memory objects (`VF_SHM`): mounted on `/dev/shm`,
    /// where musl's `shm_open` makes them.
    shm: bool,
}

fn now() -> Timespec {
    // SAFETY: kernel export.
    Timespec { tv_sec: unsafe { oxidebsd_unix_time() }, tv_nsec: 0 }
}

fn tm(mp: *mut Mount) -> &'static mut TmpMount {
    // SAFETY: `mnt_data` (8 bytes, `TFS_VFSCONF`) holds the pointer `tmpfs_mount` stored, and
    // every call runs under the VFS's giant lock.
    unsafe { &mut **((*mp).mnt_data as *mut *mut TmpMount) }
}

fn node_of(vp: *mut Vnode) -> Option<&'static mut Node> {
    // SAFETY: `v_data` (8 bytes) holds the node's pointer, or null once it's freed.
    unsafe {
        let p = *((*vp).v_data as *mut *mut Node);
        p.as_mut()
    }
}

fn set_node_of(vp: *mut Vnode, n: *mut Node) {
    // SAFETY: as `node_of`.
    unsafe { *((*vp).v_data as *mut *mut Node) = n };
}

fn mount_of(vp: *mut Vnode) -> *mut Mount {
    // SAFETY: the kernel's live vnode.
    unsafe { (*vp).v_mount }
}

fn name_of(cnp: *const ComponentName) -> &'static [u8] {
    // SAFETY: the kernel's component, live for the call.
    unsafe { (*cnp).name() }
}

fn cred_of(cnp: *const ComponentName) -> &'static Ucred {
    // SAFETY: as above.
    unsafe { &*(*cnp).cn_cred }
}

fn vattr<'a>(vap: *const Vattr) -> &'a Vattr {
    // SAFETY: the kernel's record, live for the call.
    unsafe { &*vap }
}

fn log(s: &str) {
    // SAFETY: kernel export.
    unsafe { oxidebsd_log(s.as_ptr(), s.len() as u64) };
}

/// A page for the mount, counted; `None` past its size or the memory reserve.
fn take_page(m: &mut TmpMount) -> Option<u64> {
    if m.pages >= m.max_pages {
        return None;
    }
    // SAFETY: kernel export.
    let p = unsafe { oxidebsd_tmpfs_page_alloc() };
    if p == 0 {
        return None;
    }
    m.pages += 1;
    Some(p)
}

fn give_page(m: &mut TmpMount, p: u64) {
    // SAFETY: a page `take_page` returned, no longer used.
    unsafe { oxidebsd_page_free(p) };
    m.pages -= 1;
}

fn page_bytes(p: u64) -> &'static mut [u8] {
    // SAFETY: a whole page from the frame allocator, reached through the kernel's window onto
    // physical memory, owned by one file.
    unsafe { core::slice::from_raw_parts_mut(p as *mut u8, PAGE as usize) }
}

impl Pages {
    const EMPTY: Pages = Pages { direct: [0; NDIRECT], index: Vec::new(), held: 0 };

    /// Page `i`'s address, `0` for a hole.
    fn get(&self, i: u64) -> u64 {
        let i = i as usize;
        if i < NDIRECT {
            return self.direct[i];
        }
        let (slot, at) = ((i - NDIRECT) / PER_INDEX, (i - NDIRECT) % PER_INDEX);
        match self.index.get(slot) {
            // SAFETY: an index page of `PER_INDEX` addresses.
            Some(&ix) if ix != 0 => unsafe { *(ix as *const u64).add(at) },
            _ => 0,
        }
    }

    /// Page `i`, made (zeroed) if it's a hole. `None` when the mount or memory can't spare it.
    fn get_or_make(&mut self, m: &mut TmpMount, i: u64) -> Option<u64> {
        let have = self.get(i);
        if have != 0 {
            return Some(have);
        }
        let i = i as usize;
        let slot_ptr: *mut u64 = if i < NDIRECT {
            &mut self.direct[i]
        } else {
            let (slot, at) = ((i - NDIRECT) / PER_INDEX, (i - NDIRECT) % PER_INDEX);
            if self.index.len() <= slot {
                self.index.try_reserve(slot + 1 - self.index.len()).ok()?;
                self.index.resize(slot + 1, 0);
            }
            if self.index[slot] == 0 {
                self.index[slot] = take_page(m)?;
            }
            // SAFETY: an index page of `PER_INDEX` addresses.
            unsafe { (self.index[slot] as *mut u64).add(at) }
        };
        let page = take_page(m)?;
        // SAFETY: a slot of the direct array or of an index page, as computed above.
        unsafe { *slot_ptr = page };
        self.held += 1;
        Some(page)
    }

    /// Frees every page from page `first` on (and index pages left empty).
    fn truncate(&mut self, m: &mut TmpMount, first: u64) {
        for i in (first as usize)..NDIRECT {
            if self.direct[i] != 0 {
                give_page(m, self.direct[i]);
                self.direct[i] = 0;
                self.held -= 1;
            }
        }
        let first_indexed = (first as usize).saturating_sub(NDIRECT);
        for slot in 0..self.index.len() {
            let ix = self.index[slot];
            if ix == 0 {
                continue;
            }
            let base = slot * PER_INDEX;
            let from = first_indexed.saturating_sub(base).min(PER_INDEX);
            // SAFETY: an index page of `PER_INDEX` addresses.
            let entries = unsafe { core::slice::from_raw_parts_mut(ix as *mut u64, PER_INDEX) };
            for e in &mut entries[from..] {
                if *e != 0 {
                    give_page(m, *e);
                    *e = 0;
                    self.held -= 1;
                }
            }
            if from == 0 {
                give_page(m, ix);
                self.index[slot] = 0;
            }
        }
        while self.index.last() == Some(&0) {
            self.index.pop();
        }
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

/// A copy of `name` on the heap.
fn boxed_bytes(name: &[u8]) -> Option<Box<[u8]>> {
    let mut v = Vec::new();
    v.try_reserve_exact(name.len()).ok()?;
    v.extend_from_slice(name);
    Some(v.into_boxed_slice())
}

/// A new node of `vtype`, counted against the mount's `nodes`.
fn new_node(m: &mut TmpMount, vtype: VType, mode: u32, uid: u32, gid: u32, data: Data) -> Result<*mut Node, i32> {
    if m.nodes >= m.max_nodes {
        return Err(ENOSPC);
    }
    let t = now();
    let node = Node {
        id: m.next_id,
        vtype,
        mode: mode & 0o7777,
        uid,
        gid,
        nlink: if vtype == VDIR { 2 } else { 1 },
        size: 0,
        atime: t,
        mtime: t,
        ctime: t,
        birthtime: t,
        rdev: VNOVAL,
        flags: 0,
        data,
    };
    let b = try_box(node).ok_or(ENOMEM)?;
    m.next_id += 1;
    m.nodes += 1;
    Ok(Box::into_raw(b))
}

/// Frees a node no name and no vnode refers to any more: its pages, its names.
fn free_node(m: &mut TmpMount, n: *mut Node) {
    // SAFETY: a node `new_node` made, unreachable from now on.
    let mut b = unsafe { Box::from_raw(n) };
    if let Data::Reg(pages) = &mut b.data {
        pages.truncate(m, 0);
    }
    m.nodes -= 1;
    drop(b);
}

// --- Vnodes -----------------------------------------------------------------------------------------

/// Node `n`'s vnode, referenced: the hash's, or a new one.
fn vget(mp: *mut Mount, n: *mut Node, vpp: *mut *mut Vnode) -> i32 {
    // SAFETY: a live node of this mount; kernel exports, called as declared.
    unsafe {
        let node = &*n;
        let vp = oxidebsd_vfs_hash_get(mp, node.id);
        if !vp.is_null() {
            *vpp = vp;
            return 0;
        }
        let mut vp = ptr::null_mut();
        let e = oxidebsd_getnewvnode(mp, node.vtype, node.id, &mut vp);
        if e != 0 {
            return e;
        }
        set_node_of(vp, n);
        if node.vtype == VCHR || node.vtype == VBLK {
            (*vp).v_rdev = node.rdev;
        }
        if node.id == ROOT_ID {
            (*vp).v_flag |= VV_ROOT;
        }
        oxidebsd_vfs_hash_insert(vp);
        *vpp = vp;
    }
    0
}

// --- Mount options ---------------------------------------------------------------------------------

/// `size=`, `maxfilesize=`: a byte count with an optional `k`, `m`, `g` or `t` (FreeBSD's
/// `expand_number`).
fn parse_size(v: &[u8]) -> Option<u64> {
    let (digits, shift) = match v.last()? {
        b'k' | b'K' => (&v[..v.len() - 1], 10),
        b'm' | b'M' => (&v[..v.len() - 1], 20),
        b'g' | b'G' => (&v[..v.len() - 1], 30),
        b't' | b'T' => (&v[..v.len() - 1], 40),
        _ => (v, 0),
    };
    let n = parse_num(digits, 10)?;
    n.checked_mul(1u64 << shift)
}

fn parse_num(v: &[u8], radix: u64) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in v {
        let d = (c as char).to_digit(radix as u32)? as u64;
        n = n.checked_mul(radix)?.checked_add(d)?;
    }
    Some(n)
}

struct Options {
    size: Option<u64>,
    nodes: Option<u64>,
    maxfilesize: Option<u64>,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

/// The options the kernel passed through (`name\0value\0` pairs). `EINVAL` for one tmpfs doesn't
/// know or a value it can't read, as FreeBSD's `vfs_filteropt`.
fn parse_options(args: &MountArgs) -> Result<Options, i32> {
    let mut o = Options { size: None, nodes: None, maxfilesize: None, mode: None, uid: None, gid: None };
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
        match name {
            b"size" => o.size = Some(parse_size(value).ok_or(EINVAL)?),
            b"nodes" | b"inodes" => o.nodes = Some(parse_num(value, 10).ok_or(EINVAL)?),
            b"maxfilesize" => o.maxfilesize = Some(parse_size(value).ok_or(EINVAL)?),
            b"mode" => o.mode = Some(parse_num(value, 8).filter(|&m| m <= 0o7777).ok_or(EINVAL)? as u32),
            b"uid" => o.uid = Some(parse_num(value, 10).filter(|&u| u <= u32::MAX as u64).ok_or(EINVAL)? as u32),
            b"gid" => o.gid = Some(parse_num(value, 10).filter(|&g| g <= u32::MAX as u64).ok_or(EINVAL)? as u32),
            _ => return Err(EINVAL),
        }
    }
    Ok(o)
}

fn default_size() -> u64 {
    // SAFETY: kernel export.
    (unsafe { oxidebsd_physmem_bytes() } / 16).clamp(MIN_DEFAULT_SIZE, MAX_DEFAULT_SIZE)
}

// --- vfsops --------------------------------------------------------------------------------------------

static TFS_VFSOPS: VfsOps = VfsOps {
    mount: Some(tmpfs_mount),
    unmount: Some(tmpfs_unmount),
    root: Some(tmpfs_root),
    statfs: Some(tmpfs_statfs),
    sync: None,
    vget: None,
};

static TFS_VFSCONF: VfsConf = VfsConf {
    name: b"tmpfs".as_ptr(),
    name_len: 5,
    ops: &TFS_VFSOPS,
    vops: &TFS_VOPS,
    mnt_data_size: 8,
    v_data_size: 8,
    flags: VFCF_SYNTHETIC,
};

extern "C" fn tmpfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel's argument record, live for the call.
    let args = unsafe { &*args };
    let opts = match parse_options(args) {
        Ok(o) => o,
        Err(e) => return e,
    };
    // SAFETY: the kernel filled the flags.
    let flags = unsafe { (*mp).mnt_flag };
    if flags & MNT_UPDATE != 0 {
        // FreeBSD's: the size and node limits may change, never below what's in use.
        let m = tm(mp);
        if let Some(size) = opts.size {
            let pages = size.div_ceil(PAGE).max(1);
            if pages < m.pages {
                return EBUSY;
            }
            m.max_pages = pages;
        }
        if let Some(nodes) = opts.nodes {
            if nodes < m.nodes {
                return EBUSY;
            }
            m.max_nodes = nodes.max(3);
        }
        return 0;
    }
    let size = match opts.size {
        Some(0) | None => default_size(),
        Some(s) => s,
    };
    let max_pages = size.div_ceil(PAGE).max(1);
    let max_nodes = match opts.nodes {
        Some(n) if n >= 3 => n,
        _ => 3 + max_pages * PAGE / 1024,
    };
    let maxfilesize = match opts.maxfilesize {
        Some(0) | None => u64::MAX,
        Some(s) => s,
    };
    // The root takes the directory it covers' mode, owner and group unless the options say (as
    // FreeBSD's).
    let mut covered = Vattr::NULL;
    // SAFETY: the kernel sets the covered vnode before calling `mount`, referenced.
    let cvp = unsafe { (*mp).mnt_vnodecovered };
    let have_covered = !cvp.is_null() && unsafe { oxidebsd_vop_getattr(cvp, &mut covered) } == 0;
    let mode = opts.mode.unwrap_or(if have_covered { covered.va_mode & 0o7777 } else { 0o1777 });
    let uid = opts.uid.unwrap_or(if have_covered { covered.va_uid } else { 0 });
    let gid = opts.gid.unwrap_or(if have_covered { covered.va_gid } else { 0 });

    let onname = unsafe { &(*mp).mnt_onname };
    let on_len = onname.iter().position(|&b| b == 0).unwrap_or(onname.len());
    let shm = &onname[..on_len] == b"/dev/shm";

    let Some(m) = try_box(TmpMount {
        root: ptr::null_mut(),
        next_id: ROOT_ID,
        pages: 0,
        max_pages,
        nodes: 0,
        max_nodes,
        maxfilesize,
        shm,
    }) else {
        return ENOMEM;
    };
    let m = Box::into_raw(m);
    // SAFETY: `m` was just made; `mnt_data` is 8 bytes for its pointer.
    unsafe { *((*mp).mnt_data as *mut *mut TmpMount) = m };
    let mm = tm(mp);
    let dir = Data::Dir(Dir { parent: ptr::null_mut(), entries: Vec::new(), next_cookie: 2 });
    match new_node(mm, VDIR, mode, uid, gid, dir) {
        Ok(root) => {
            // SAFETY: just made.
            if let Data::Dir(d) = unsafe { &mut (*root).data } {
                d.parent = root;
            }
            mm.root = root;
            0
        }
        Err(e) => {
            // SAFETY: made above, never shared.
            drop(unsafe { Box::from_raw(m) });
            e
        }
    }
}

/// Frees every node: the kernel reclaimed every vnode of the mount first, which freed the
/// unlinked ones still open (`tmpfs_reclaim`), so what's left is the tree.
extern "C" fn tmpfs_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    let m = tm(mp);
    let mut stack: Vec<*mut Node> = Vec::new();
    stack.push(m.root);
    while let Some(n) = stack.pop() {
        // SAFETY: a node of the tree; each is reached once (hard links are only to non-dirs, and
        // a non-dir is freed when its last name goes).
        let node = unsafe { &mut *n };
        if let Data::Dir(d) = &mut node.data {
            for e in d.entries.drain(..) {
                // SAFETY: a live node named by the entry.
                let child = unsafe { &mut *e.node };
                if child.vtype == VDIR {
                    stack.push(e.node);
                } else {
                    child.nlink -= 1;
                    if child.nlink == 0 {
                        free_node(m, e.node);
                    }
                }
            }
        }
        free_node(m, n);
    }
    // SAFETY: the pointer `tmpfs_mount` stored; nothing refers to it now.
    unsafe {
        let p = *((*mp).mnt_data as *mut *mut TmpMount);
        drop(Box::from_raw(p));
        *((*mp).mnt_data as *mut *mut TmpMount) = ptr::null_mut();
    }
    0
}

extern "C" fn tmpfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    vget(mp, tm(mp).root, vpp)
}

extern "C" fn tmpfs_statfs(mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    let m = tm(mp);
    // SAFETY: the kernel's record.
    let sb = unsafe { &mut *sbp };
    let free = m.max_pages.saturating_sub(m.pages);
    sb.f_bsize = PAGE;
    sb.f_iosize = PAGE;
    sb.f_blocks = m.max_pages;
    sb.f_bfree = free;
    sb.f_bavail = free;
    sb.f_files = m.max_nodes;
    sb.f_ffree = m.max_nodes.saturating_sub(m.nodes);
    sb.f_namemax = NAME_MAX as u32;
    sb.f_magic = TMPFS_MAGIC;
    0
}

// --- Vnode operations -------------------------------------------------------------------------------

static TFS_VOPS: VopVector = VopVector {
    lookup: Some(tmpfs_lookup),
    create: Some(tmpfs_create),
    mknod: Some(tmpfs_mknod),
    getattr: Some(tmpfs_getattr),
    setattr: Some(tmpfs_setattr),
    read: Some(tmpfs_read),
    write: Some(tmpfs_write),
    fsync: Some(tmpfs_fsync),
    remove: Some(tmpfs_remove),
    link: Some(tmpfs_link),
    rename: Some(tmpfs_rename),
    mkdir: Some(tmpfs_mkdir),
    rmdir: Some(tmpfs_rmdir),
    symlink: Some(tmpfs_symlink),
    readdir: Some(tmpfs_readdir),
    readlink: Some(tmpfs_readlink),
    inactive: Some(tmpfs_inactive),
    reclaim: Some(tmpfs_reclaim),
    allocate: Some(tmpfs_allocate),
    ..VopVector::DEFAULT
};

fn dir_of(n: &mut Node) -> Result<&mut Dir, i32> {
    match &mut n.data {
        Data::Dir(d) => Ok(d),
        _ => Err(ENOTDIR),
    }
}

extern "C" fn tmpfs_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32 {
    let Some(dn) = node_of(dvp) else { return ENOENT };
    let Ok(d) = dir_of(dn) else { return ENOTDIR };
    // SAFETY: the kernel's component.
    let dotdot = unsafe { (*cnp).cn_flags } & ISDOTDOT != 0;
    let name = name_of(cnp);
    let target = if dotdot || name == b".." {
        d.parent
    } else if name == b"." {
        dn as *mut Node
    } else {
        match d.find(name) {
            Some(i) => d.entries[i].node,
            None => return ENOENT,
        }
    };
    vget(mount_of(dvp), target, vpp)
}

/// A new node named `cnp` in directory `dvp`, owned by the caller and the directory's group (as
/// on the BSDs); `*vpp` gets its vnode.
fn new_entry(dvp: *mut Vnode, cnp: *const ComponentName, vtype: VType, mode: u32, data: Data, vpp: *mut *mut Vnode) -> i32 {
    let mp = mount_of(dvp);
    let m = tm(mp);
    let Some(dn) = node_of(dvp) else { return ENOENT };
    let dgid = dn.gid;
    let dir_ptr = dn as *mut Node;
    let name = name_of(cnp);
    if name.len() > NAME_MAX {
        return ENAMETOOLONG;
    }
    let d = match dir_of(dn) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if d.find(name).is_some() {
        return EEXIST;
    }
    let Some(boxed) = boxed_bytes(name) else { return ENOMEM };
    if d.entries.try_reserve(1).is_err() {
        return ENOMEM;
    }
    let n = match new_node(m, vtype, mode, cred_of(cnp).cr_uid, dgid, data) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Data::Dir(child) = unsafe { &mut (*n).data } {
        child.parent = dir_ptr;
    }
    let cookie = d.next_cookie;
    d.next_cookie += 1;
    d.entries.push(Entry { cookie, name: boxed, node: n });
    // SAFETY: the directory's node, live.
    let dn = unsafe { &mut *dir_ptr };
    if vtype == VDIR {
        dn.nlink += 1;
    }
    let t = now();
    dn.mtime = t;
    dn.ctime = t;
    vget(mp, n, vpp)
}

extern "C" fn tmpfs_create(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    new_entry(dvp, cnp, VREG, vattr(vap).va_mode & 0o777, Data::Reg(Pages::EMPTY), vpp)
}

extern "C" fn tmpfs_mknod(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    let va = vattr(vap);
    let data = match va.va_type {
        VREG => Data::Reg(Pages::EMPTY),
        VCHR | VBLK | VFIFO | VSOCK => Data::Special,
        _ => return EINVAL,
    };
    let e = new_entry(dvp, cnp, va.va_type, va.va_mode & 0o777, data, vpp);
    if e == 0 && (va.va_type == VCHR || va.va_type == VBLK) {
        // SAFETY: the vnode `new_entry` returned, referenced.
        unsafe {
            if let Some(n) = node_of(*vpp) {
                n.rdev = va.va_rdev;
            }
            (**vpp).v_rdev = va.va_rdev;
        }
    }
    e
}

extern "C" fn tmpfs_mkdir(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    let dir = Data::Dir(Dir { parent: ptr::null_mut(), entries: Vec::new(), next_cookie: 2 });
    new_entry(dvp, cnp, VDIR, vattr(vap).va_mode & 0o7777, dir, vpp)
}

extern "C" fn tmpfs_symlink(
    dvp: *mut Vnode,
    vpp: *mut *mut Vnode,
    cnp: *const ComponentName,
    vap: *const Vattr,
    target: *const u8,
    target_len: usize,
) -> i32 {
    // SAFETY: the kernel's buffer, live for the call.
    let target = unsafe { core::slice::from_raw_parts(target, target_len) };
    let Some(t) = boxed_bytes(target) else { return ENOMEM };
    let mode = match vattr(vap).va_mode {
        m if m == VNOVAL as u32 => 0o777,
        m => m & 0o7777,
    };
    let e = new_entry(dvp, cnp, VLNK, mode, Data::Lnk(t), vpp);
    if e == 0 {
        // SAFETY: as in `tmpfs_mknod`.
        if let Some(n) = node_of(unsafe { *vpp }) {
            n.size = target_len as u64;
        }
    }
    e
}

/// Removes the entry `name` from directory `dn`, giving its name's memory back.
fn unlink_entry(dn: &mut Node, name: &[u8]) -> Option<*mut Node> {
    let d = dir_of(dn).ok()?;
    let i = d.find(name)?;
    let e = d.entries.remove(i);
    let t = now();
    dn.mtime = t;
    dn.ctime = t;
    Some(e.node)
}

extern "C" fn tmpfs_remove(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let (Some(dn), Some(n)) = (node_of(dvp), node_of(vp)) else { return ENOENT };
    if n.vtype == VDIR {
        return EISDIR;
    }
    if unlink_entry(dn, name_of(cnp)).is_none() {
        return ENOENT;
    }
    // The node goes when its vnode's last use does (`tmpfs_inactive`): the kernel holds one now.
    n.nlink -= 1;
    n.ctime = now();
    0
}

extern "C" fn tmpfs_rmdir(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let (Some(dn), Some(n)) = (node_of(dvp), node_of(vp)) else { return ENOENT };
    match &n.data {
        Data::Dir(d) if !d.entries.is_empty() => return ENOTEMPTY,
        Data::Dir(_) => {}
        _ => return ENOTDIR,
    }
    if unlink_entry(dn, name_of(cnp)).is_none() {
        return ENOENT;
    }
    dn.nlink -= 1;
    n.nlink = 0;
    n.ctime = now();
    0
}

extern "C" fn tmpfs_link(tdvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    if mount_of(tdvp) != mount_of(vp) {
        return EXDEV;
    }
    let (Some(dn), Some(n)) = (node_of(tdvp), node_of(vp)) else { return ENOENT };
    if n.vtype == VDIR {
        return EPERM;
    }
    if n.nlink >= LINK_MAX {
        return EMLINK;
    }
    let name = name_of(cnp);
    if name.len() > NAME_MAX {
        return ENAMETOOLONG;
    }
    let target = n as *mut Node;
    let d = match dir_of(dn) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if d.find(name).is_some() {
        return EEXIST;
    }
    let Some(boxed) = boxed_bytes(name) else { return ENOMEM };
    if d.entries.try_reserve(1).is_err() {
        return ENOMEM;
    }
    let cookie = d.next_cookie;
    d.next_cookie += 1;
    d.entries.push(Entry { cookie, name: boxed, node: target });
    let t = now();
    dn.mtime = t;
    dn.ctime = t;
    n.nlink += 1;
    n.ctime = t;
    0
}

extern "C" fn tmpfs_rename(
    fdvp: *mut Vnode,
    fvp: *mut Vnode,
    fcnp: *const ComponentName,
    tdvp: *mut Vnode,
    tvp: *mut Vnode,
    tcnp: *const ComponentName,
) -> i32 {
    if mount_of(fdvp) != mount_of(tdvp) || mount_of(fvp) != mount_of(tdvp) {
        return EXDEV;
    }
    let (Some(fdn), Some(fnode), Some(tdn)) = (node_of(fdvp), node_of(fvp), node_of(tdvp)) else { return ENOENT };
    let (fdp, fp, tdp) = (fdn as *mut Node, fnode as *mut Node, tdn as *mut Node);
    let tp = if tvp.is_null() { ptr::null_mut() } else { node_of(tvp).map_or(ptr::null_mut(), |n| n as *mut Node) };
    if tp == fp {
        // Two names of one file: POSIX says nothing happens.
        return 0;
    }
    let tname = name_of(tcnp);
    if tname.len() > NAME_MAX {
        return ENAMETOOLONG;
    }
    // SAFETY: live nodes of this mount, distinct where they're mutated together below.
    unsafe {
        let is_dir = (*fp).vtype == VDIR;
        if !tp.is_null() {
            match (&(*tp).data, is_dir) {
                (Data::Dir(d), true) if !d.entries.is_empty() => return ENOTEMPTY,
                (Data::Dir(_), false) => return EISDIR,
                (_, true) if (*tp).vtype != VDIR => return ENOTDIR,
                _ => {}
            }
        }
        let Some(newname) = boxed_bytes(tname) else { return ENOMEM };
        // Find the source entry before changing anything.
        let Ok(fd) = dir_of(&mut *fdp) else { return ENOTDIR };
        let Some(fi) = fd.find(name_of(fcnp)) else { return ENOENT };
        if tp.is_null() && dir_of(&mut *tdp).map(|d| d.entries.try_reserve(1).is_err()).unwrap_or(true) {
            return ENOMEM;
        }
        let entry = dir_of(&mut *fdp).unwrap().entries.remove(fi);
        let t = now();
        if !tp.is_null() {
            // Replaced: its name now names the source. A directory goes with its last link.
            let td = dir_of(&mut *tdp).unwrap();
            let ti = td.find(tname).unwrap();
            td.entries[ti].node = fp;
            if (*tp).vtype == VDIR {
                (*tp).nlink = 0;
                (*tdp).nlink -= 1;
            } else {
                (*tp).nlink -= 1;
            }
            (*tp).ctime = t;
            drop(newname);
        } else {
            let td = dir_of(&mut *tdp).unwrap();
            let cookie = td.next_cookie;
            td.next_cookie += 1;
            td.entries.push(Entry { cookie, name: newname, node: fp });
        }
        drop(entry);
        if is_dir && fdp != tdp {
            if let Data::Dir(d) = &mut (*fp).data {
                d.parent = tdp;
            }
            (*fdp).nlink -= 1;
            (*tdp).nlink += 1;
        }
        (*fdp).mtime = t;
        (*fdp).ctime = t;
        (*tdp).mtime = t;
        (*tdp).ctime = t;
        (*fp).ctime = t;
    }
    0
}

extern "C" fn tmpfs_readdir(vp: *mut Vnode, uio: u64, _cred: *const Ucred, eofflag: *mut i32) -> i64 {
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    let self_id = n.id;
    let Ok(d) = dir_of(n) else { return -(ENOTDIR as i64) };
    // SAFETY: the parent is a live directory (the root's is itself).
    let parent_id = unsafe { (*d.parent).id };
    // SAFETY: kernel export.
    let mut cursor = unsafe { oxidebsd_uio_offset(uio) };
    let mut record = [0u8; dirent_reclen(NAME_MAX)];
    let mut written = 0i64;
    let mut eof = true;
    // `.` and `..` first (cookies 0 and 1), then the entries from the cursor's cookie on.
    let fixed: [(u64, &[u8], u64); 2] = [(0, b".", self_id), (1, b"..", parent_id)];
    let start = d.entries.partition_point(|e| e.cookie < cursor);
    let rest = d.entries[start..].iter().map(|e| {
        // SAFETY: a live node named by the entry.
        let c = unsafe { &*e.node };
        (e.cookie, &*e.name, c.id, c.vtype)
    });
    let from = cursor;
    let dots = fixed.into_iter().filter(move |f| f.0 >= from).map(|(c, name, id)| (c, name, id, VDIR));
    for (cookie, name, id, vtype) in dots.chain(rest) {
        let reclen = dirent_reclen(name.len());
        // SAFETY: kernel export.
        if (unsafe { oxidebsd_uio_resid(uio) } as usize) < reclen {
            eof = false;
            break;
        }
        dirent_encode(&mut record, id, (cookie + 1) as i64, vtype_to_dt(vtype), name);
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
        cursor = cookie + 1;
    }
    // SAFETY: as above.
    unsafe {
        oxidebsd_uio_set_offset(uio, cursor);
        *eofflag = eof as i32;
    }
    n_touch_atime(vp);
    written
}

fn n_touch_atime(vp: *mut Vnode) {
    if let Some(n) = node_of(vp) {
        n.atime = now();
    }
}

extern "C" fn tmpfs_readlink(vp: *mut Vnode, uio: u64, _cred: *const Ucred) -> i64 {
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    let Data::Lnk(target) = &n.data else { return -(EINVAL as i64) };
    // SAFETY: kernel export.
    let cap = (unsafe { oxidebsd_uio_resid(uio) } as usize).min(target.len());
    // SAFETY: kernel export; a read transfer only reads the buffer.
    unsafe { oxidebsd_uiomove(target.as_ptr() as *mut u8, cap as u64, uio) }
}

extern "C" fn tmpfs_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    let Some(n) = node_of(vp) else { return EIO };
    let shm = tm(mount_of(vp)).shm;
    let bytes = match &n.data {
        Data::Reg(p) => p.held * PAGE,
        Data::Dir(d) => (d.entries.len() as u64 + 2) * 32,
        Data::Lnk(t) => t.len() as u64,
        Data::Special => 0,
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
        va_fileid: n.id,
        va_size: match &n.data {
            Data::Dir(d) => (d.entries.len() as u64 + 2) * 32,
            _ => n.size,
        },
        va_blocksize: PAGE,
        va_atime: n.atime,
        va_mtime: n.mtime,
        va_ctime: n.ctime,
        va_birthtime: n.birthtime,
        va_gen: 0,
        va_flags: n.flags | if shm && n.vtype == VREG { VF_SHM } else { 0 },
        va_rdev: if n.rdev == VNOVAL { 0 } else { n.rdev },
        va_bytes: bytes,
        va_vaflags: 0,
    };
    0
}

/// Changes a regular file's size: pages past the end go, and the end's page is zeroed past it, so
/// growing again reads zeros.
fn resize(m: &mut TmpMount, n: &mut Node, size: u64) -> i32 {
    let Data::Reg(pages) = &mut n.data else {
        return if n.vtype == VDIR { EISDIR } else { EINVAL };
    };
    if size > m.maxfilesize {
        return EFBIG;
    }
    if size < n.size {
        pages.truncate(m, size.div_ceil(PAGE));
        let tail = (size % PAGE) as usize;
        if tail != 0 {
            let p = pages.get(size / PAGE);
            if p != 0 {
                page_bytes(p)[tail..].fill(0);
            }
        }
    }
    n.size = size;
    0
}

extern "C" fn tmpfs_setattr(vp: *mut Vnode, vap: *const Vattr, _cred: *const Ucred) -> i32 {
    let m = tm(mount_of(vp));
    let Some(n) = node_of(vp) else { return EIO };
    let va = vattr(vap);
    let t = now();
    if va.va_size != VNOVAL {
        let e = resize(m, n, va.va_size);
        if e != 0 {
            return e;
        }
        n.mtime = t;
        n.ctime = t;
    }
    let mut changed = false;
    if va.va_mode != VNOVAL as u32 {
        n.mode = va.va_mode & 0o7777;
        changed = true;
    }
    if va.va_uid != VNOVAL as u32 {
        n.uid = va.va_uid;
        changed = true;
    }
    if va.va_gid != VNOVAL as u32 {
        n.gid = va.va_gid;
        changed = true;
    }
    if va.va_flags != VNOVAL {
        n.flags = va.va_flags & !VF_SHM;
        changed = true;
    }
    if va.va_atime != VNOVAL_TIME {
        n.atime = va.va_atime;
        changed = true;
    }
    if va.va_mtime != VNOVAL_TIME {
        n.mtime = va.va_mtime;
        changed = true;
    }
    if va.va_birthtime != VNOVAL_TIME {
        n.birthtime = va.va_birthtime;
        changed = true;
    }
    if changed {
        n.ctime = t;
    }
    0
}

extern "C" fn tmpfs_read(vp: *mut Vnode, uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    let Data::Reg(pages) = &n.data else {
        return -(if n.vtype == VDIR { EISDIR } else { EINVAL } as i64);
    };
    // SAFETY: kernel exports.
    let mut off = unsafe { oxidebsd_uio_offset(uio) };
    let mut moved = 0i64;
    let zeros = [0u8; 512];
    loop {
        // SAFETY: kernel export.
        let resid = unsafe { oxidebsd_uio_resid(uio) };
        if resid == 0 || off >= n.size {
            break;
        }
        let in_page = off % PAGE;
        let len = resid.min(PAGE - in_page).min(n.size - off);
        let p = pages.get(off / PAGE);
        let r = if p != 0 {
            let bytes = &page_bytes(p)[in_page as usize..(in_page + len) as usize];
            // SAFETY: kernel export; a read transfer only reads the buffer.
            unsafe { oxidebsd_uiomove(bytes.as_ptr() as *mut u8, len, uio) }
        } else {
            let len = len.min(zeros.len() as u64);
            // SAFETY: as above.
            unsafe { oxidebsd_uiomove(zeros.as_ptr() as *mut u8, len, uio) }
        };
        if r < 0 {
            if moved == 0 {
                return r;
            }
            break;
        }
        if r == 0 {
            break;
        }
        moved += r;
        off += r as u64;
    }
    if moved > 0 {
        n.atime = now();
    }
    moved
}

extern "C" fn tmpfs_write(vp: *mut Vnode, uio: u64, ioflag: u32, cred: *const Ucred) -> i64 {
    let m = tm(mount_of(vp));
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    if !matches!(n.data, Data::Reg(_)) {
        return -(if n.vtype == VDIR { EISDIR } else { EINVAL } as i64);
    }
    if ioflag & IO_APPEND != 0 {
        // SAFETY: kernel export.
        unsafe { oxidebsd_uio_set_offset(uio, n.size) };
    }
    // SAFETY: kernel exports.
    let (mut off, resid) = unsafe { (oxidebsd_uio_offset(uio), oxidebsd_uio_resid(uio)) };
    if resid == 0 {
        return 0;
    }
    if off >= m.maxfilesize {
        return -(EFBIG as i64);
    }
    let limit = m.maxfilesize.min(off.saturating_add(resid));
    // A write by anyone but root clears the set-user-ID and set-group-ID bits, as on the BSDs.
    // SAFETY: the kernel's credentials.
    if unsafe { (*cred).cr_uid } != 0 {
        n.mode &= !SETID_BITS;
    }
    let mut moved = 0i64;
    let mut error = 0i32;
    while off < limit {
        let in_page = off % PAGE;
        let len = (PAGE - in_page).min(limit - off);
        let Data::Reg(pages) = &mut n.data else { unreachable!() };
        let Some(p) = pages.get_or_make(m, off / PAGE) else {
            error = ENOSPC;
            break;
        };
        let bytes = &mut page_bytes(p)[in_page as usize..(in_page + len) as usize];
        // SAFETY: kernel export, into this file's page.
        let r = unsafe { oxidebsd_uiomove(bytes.as_mut_ptr(), len, uio) };
        if r <= 0 {
            if r < 0 {
                error = (-r) as i32;
            }
            break;
        }
        moved += r;
        off += r as u64;
        if off > n.size {
            n.size = off;
        }
    }
    if moved > 0 {
        let t = now();
        n.mtime = t;
        n.ctime = t;
        return moved;
    }
    -(error as i64)
}

extern "C" fn tmpfs_allocate(vp: *mut Vnode, offset: u64, len: u64) -> i32 {
    let m = tm(mount_of(vp));
    let Some(n) = node_of(vp) else { return EIO };
    if !matches!(n.data, Data::Reg(_)) {
        return if n.vtype == VDIR { EISDIR } else { EINVAL };
    }
    let end = offset.saturating_add(len);
    if end > m.maxfilesize {
        return EFBIG;
    }
    let Data::Reg(pages) = &mut n.data else { unreachable!() };
    for i in offset / PAGE..end.div_ceil(PAGE) {
        if pages.get_or_make(m, i).is_none() {
            return ENOSPC;
        }
    }
    if end > n.size {
        n.size = end;
        let t = now();
        n.mtime = t;
        n.ctime = t;
    }
    0
}

extern "C" fn tmpfs_fsync(_vp: *mut Vnode, _waitfor: i32, _data_only: u32) -> i32 {
    0
}

/// The last use went: a file with no name left goes now (its vnode is recycled, which frees it).
extern "C" fn tmpfs_inactive(vp: *mut Vnode) -> i32 {
    if let Some(n) = node_of(vp)
        && n.nlink == 0
    {
        // SAFETY: kernel export.
        unsafe { oxidebsd_vfs_recycle(mount_of(vp), n.id) };
    }
    0
}

/// The vnode is going: a node with no name goes with it; one still named stays in the tree.
extern "C" fn tmpfs_reclaim(vp: *mut Vnode) -> i32 {
    if let Some(n) = node_of(vp) {
        let np = n as *mut Node;
        if n.nlink == 0 {
            let mp = mount_of(vp);
            // SAFETY: the mount's data outlives its vnodes (unmount runs after every reclaim).
            let has_mount = unsafe { !(*((*mp).mnt_data as *mut *mut TmpMount)).is_null() };
            if has_mount {
                free_node(tm(mp), np);
            }
        }
        set_node_of(vp, ptr::null_mut());
    }
    0
}

// --- Loading -----------------------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // SAFETY: kernel exports, with a static table.
    unsafe {
        oxidebsd_module_serialize();
        if oxidebsd_vfs_register(&TFS_VFSCONF) != 0 {
            log("[tmpfs] registering the type failed\n");
            return -1;
        }
    }
    0
}
