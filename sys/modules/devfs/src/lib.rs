//! devfs (OxideBSD-doc `DEVFS.md`, `devfs(5)`): the file system on `/dev`, a node for every
//! device in the kernel's registry (`sys/fs/devfs.rs`), FreeBSD's devfs in what it lets a user do.
//!
//! Each mount is its own view, kept in step with the registry whenever a name in it is looked up
//! or listed and the registry changed since (`sync`): a device registered gets a node (with the
//! registry's owner, group and mode, and the directories its name has: `pts/0`), and one that
//! goes loses its node. In a view, until it's unmounted (for `/dev`, until reboot):
//!
//! - `chmod`, `chown` and times set on a node stay;
//! - removing a device's node hides it from this view (the registry still has it);
//! - directories (`mkdir`, `rmdir`) and symbolic links (`ln -s`) can be made and removed;
//! - so can sockets (`bind`): musl's `syslog(3)` talks to `/dev/log`, as OpenBSD's does;
//! - nothing else: no regular files (`EOPNOTSUPP`), no device nodes or FIFOs by hand (`EPERM`),
//!   no links or renames.
//!
//! Every view has an empty `shm` directory at its root, where `/etc/fstab` mounts the tmpfs that
//! holds POSIX shared memory (`shm_open`), as FreeBSD's devfs has `fd` for fdescfs.
//!
//! A device node's vnode is `VCHR` with the device's number; the kernel opens it through the
//! registry. Nodes live on the kernel heap; `v_data` holds a node's pointer.
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
    fn oxidebsd_module_serialize();
    /// The registry's generation: changes on every registration and removal.
    fn oxidebsd_dev_generation() -> u64;
    /// Registry entry `index`, or nonzero past the last.
    fn oxidebsd_dev_entry(index: u64, out: *mut RawDevEntry) -> i64;
}

/// One registry entry, as `oxidebsd_dev_entry` writes it (`sys/fs/devfs.rs`'s `RawDevEntry`).
#[repr(C)]
struct RawDevEntry {
    name: [u8; 64],
    name_len: u32,
    major: u32,
    minor: u32,
    uid: u32,
    gid: u32,
    mode: u32,
}

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const ENOMEM: i32 = 12;
const EFAULT: i32 = 14;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const ENAMETOOLONG: i32 = 36;
const ENOTEMPTY: i32 = 39;
const EOPNOTSUPP: i32 = 95;

const NAME_MAX: usize = 255;
const ROOT_ID: u64 = 2;
/// FreeBSD's `DEVFS_MAGIC`, `statfs(2)`'s `f_type`.
const DEVFS_MAGIC: u64 = 0xdb0a_087a;

struct Node {
    id: u64,
    vtype: VType,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    data: Data,
}

enum Data {
    Dir(Dir),
    /// A device's node: its number.
    Dev(u32, u32),
    Lnk(Box<[u8]>),
    /// A socket's node (`bind`): the kernel keeps the socket by the vnode.
    Sock,
}

struct Dir {
    parent: *mut Node,
    /// In cookie order (`readdir`'s position is a cookie, as tmpfs's).
    entries: Vec<Entry>,
    next_cookie: u64,
}

struct Entry {
    cookie: u64,
    name: Box<[u8]>,
    node: *mut Node,
}

impl Dir {
    fn find(&self, name: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| &*e.name == name)
    }
}

/// One view.
struct DevMount {
    root: *mut Node,
    next_id: u64,
    /// The registry generation this view was last brought up to.
    generation: u64,
    /// Devices whose nodes were removed from this view.
    hidden: Vec<(u32, u32)>,
}

fn now() -> Timespec {
    // SAFETY: kernel export.
    Timespec { tv_sec: unsafe { oxidebsd_unix_time() }, tv_nsec: 0 }
}

fn dm(mp: *mut Mount) -> &'static mut DevMount {
    // SAFETY: `mnt_data` (8 bytes) holds the pointer `devfs_mount` stored; every call runs under
    // the VFS's giant lock.
    unsafe { &mut **((*mp).mnt_data as *mut *mut DevMount) }
}

fn node_of(vp: *mut Vnode) -> Option<&'static mut Node> {
    // SAFETY: `v_data` (8 bytes) holds the node's pointer, or null once it's freed.
    unsafe { (*((*vp).v_data as *mut *mut Node)).as_mut() }
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

fn log(s: &str) {
    // SAFETY: kernel export.
    unsafe { oxidebsd_log(s.as_ptr(), s.len() as u64) };
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

fn boxed_bytes(b: &[u8]) -> Option<Box<[u8]>> {
    let mut v = Vec::new();
    v.try_reserve_exact(b.len()).ok()?;
    v.extend_from_slice(b);
    Some(v.into_boxed_slice())
}

fn new_node(m: &mut DevMount, vtype: VType, mode: u32, uid: u32, gid: u32, data: Data) -> Option<*mut Node> {
    let t = now();
    let b = try_box(Node {
        id: m.next_id,
        vtype,
        mode: mode & 0o7777,
        uid,
        gid,
        nlink: if vtype == VDIR { 2 } else { 1 },
        atime: t,
        mtime: t,
        ctime: t,
        data,
    })?;
    m.next_id += 1;
    Some(Box::into_raw(b))
}

fn free_node(n: *mut Node) {
    // SAFETY: a node `new_node` made, unreachable from now on.
    drop(unsafe { Box::from_raw(n) });
}

fn dir_of(n: &mut Node) -> Result<&mut Dir, i32> {
    match &mut n.data {
        Data::Dir(d) => Ok(d),
        _ => Err(ENOTDIR),
    }
}

/// Names `child` `name` in directory `dir`.
fn insert(dir: *mut Node, name: &[u8], child: *mut Node) -> Result<(), i32> {
    let boxed = boxed_bytes(name).ok_or(ENOMEM)?;
    // SAFETY: a live directory node of this mount.
    let dn = unsafe { &mut *dir };
    let d = dir_of(dn)?;
    d.entries.try_reserve(1).map_err(|_| ENOMEM)?;
    let cookie = d.next_cookie;
    d.next_cookie += 1;
    d.entries.push(Entry { cookie, name: boxed, node: child });
    // SAFETY: a live node.
    if unsafe { (*child).vtype } == VDIR {
        dn.nlink += 1;
    }
    let t = now();
    dn.mtime = t;
    dn.ctime = t;
    Ok(())
}

/// Takes the name `name` out of directory `dn`; the node it named, whose link count drops (and
/// which goes now if no vnode has it: `free_if_unused`).
fn unlink(dn: &mut Node, name: &[u8]) -> Option<*mut Node> {
    let d = dir_of(dn).ok()?;
    let i = d.find(name)?;
    let e = d.entries.remove(i);
    // SAFETY: the live node the entry named.
    let child = unsafe { &mut *e.node };
    if child.vtype == VDIR {
        dn.nlink -= 1;
        child.nlink = 0;
    } else {
        child.nlink -= 1;
    }
    let t = now();
    dn.mtime = t;
    dn.ctime = t;
    child.ctime = t;
    Some(e.node)
}

// --- Keeping a view in step with the registry ----------------------------------------------------

/// The directory `name` in `dir`, made (as the registry's, mode 0755) if missing.
fn subdir(m: &mut DevMount, dir: *mut Node, name: &[u8]) -> Option<*mut Node> {
    // SAFETY: a live directory node.
    let d = dir_of(unsafe { &mut *dir }).ok()?;
    if let Some(i) = d.find(name) {
        let n = d.entries[i].node;
        // SAFETY: a live node.
        return (unsafe { (*n).vtype } == VDIR).then_some(n);
    }
    let n = new_node(m, VDIR, 0o755, 0, 0, Data::Dir(Dir { parent: dir, entries: Vec::new(), next_cookie: 2 }))?;
    if insert(dir, name, n).is_err() {
        free_node(n);
        return None;
    }
    Some(n)
}

/// Brings the view up to date with the registry (`DEVFS.md` §4.3): a node for each registered
/// device that has none (unless hidden here), and none for a device no longer registered.
fn sync(mp: *mut Mount) {
    let m = dm(mp);
    // SAFETY: kernel export.
    let generation = unsafe { oxidebsd_dev_generation() };
    if m.generation == generation {
        return;
    }
    m.generation = generation;
    // Every registered device first, then the stale nodes pruned, then the missing ones added: a
    // device gone and another registered under its name (a disk's GPT label, plugged in again)
    // would otherwise find the old node still there, and lose its name when it's pruned.
    let mut entries: Vec<RawDevEntry> = Vec::new();
    let mut index = 0;
    loop {
        let mut e = RawDevEntry { name: [0; 64], name_len: 0, major: 0, minor: 0, uid: 0, gid: 0, mode: 0 };
        // SAFETY: a buffer for one entry.
        if unsafe { oxidebsd_dev_entry(index, &mut e) } != 0 {
            break;
        }
        index += 1;
        if entries.try_reserve(1).is_err() {
            // Without the whole list, pruning could take nodes still registered: wait for the next.
            m.generation = 0;
            return;
        }
        entries.push(e);
    }
    let mut registered: Vec<(u32, u32)> = Vec::new();
    if registered.try_reserve(entries.len()).is_err() {
        m.generation = 0;
        return;
    }
    registered.extend(entries.iter().map(|e| (e.major, e.minor)));
    prune(mp, m.root, &registered, 0);
    for e in &entries {
        if m.hidden.contains(&(e.major, e.minor)) {
            continue;
        }
        let name = &e.name[..(e.name_len as usize).min(64)];
        let (path, leaf) = match name.iter().rposition(|&b| b == b'/') {
            Some(i) => (&name[..i], &name[i + 1..]),
            None => (&name[..0], name),
        };
        let mut dir = m.root;
        let mut ok = true;
        for c in path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            match subdir(m, dir, c) {
                Some(d) => dir = d,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        // SAFETY: a live directory node.
        if !ok || dir_of(unsafe { &mut *dir }).map_or(true, |d| d.find(leaf).is_some()) {
            continue;
        }
        let Some(n) = new_node(m, VCHR, e.mode, e.uid, e.gid, Data::Dev(e.major, e.minor)) else { break };
        if insert(dir, leaf, n).is_err() {
            free_node(n);
        }
    }
}

/// Removes the nodes under `dir` of devices no longer registered.
fn prune(mp: *mut Mount, dir: *mut Node, registered: &[(u32, u32)], depth: u32) {
    if depth > 16 {
        return;
    }
    // SAFETY: a live directory node.
    let Ok(d) = dir_of(unsafe { &mut *dir }) else { return };
    let mut gone: Vec<Box<[u8]>> = Vec::new();
    let mut subdirs: Vec<*mut Node> = Vec::new();
    for e in &d.entries {
        // SAFETY: a live node.
        match unsafe { &(*e.node).data } {
            Data::Dev(ma, mi) if !registered.contains(&(*ma, *mi)) => {
                if let Some(b) = boxed_bytes(&e.name) {
                    gone.push(b);
                }
            }
            Data::Dir(_) => subdirs.push(e.node),
            _ => {}
        }
    }
    for name in gone {
        // SAFETY: as above.
        if let Some(n) = unlink(unsafe { &mut *dir }, &name) {
            free_if_unused(mp, n);
        }
    }
    for s in subdirs {
        prune(mp, s, registered, depth + 1);
    }
}

/// A node with no name left goes now if no vnode has it, else when its vnode goes
/// (`devfs_reclaim`).
fn free_if_unused(mp: *mut Mount, n: *mut Node) {
    // SAFETY: a live node with no name.
    let id = unsafe { (*n).id };
    // SAFETY: kernel exports.
    let vp = unsafe { oxidebsd_vfs_hash_get(mp, id) };
    if vp.is_null() {
        free_node(n);
    } else {
        // Referenced by the lookup above; recycled once its users let go (`devfs_inactive`).
        unsafe { oxidebsd_vrele(vp) };
    }
}

// --- vnodes and vfsops -------------------------------------------------------------------------------

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
        if let Data::Dev(ma, mi) = node.data {
            (*vp).v_rdev = makedev(ma, mi);
        }
        if node.id == ROOT_ID {
            (*vp).v_flag |= VV_ROOT;
        }
        oxidebsd_vfs_hash_insert(vp);
        *vpp = vp;
    }
    0
}

static DEVFS_VFSOPS: VfsOps = VfsOps {
    mount: Some(devfs_mount),
    unmount: Some(devfs_unmount),
    root: Some(devfs_root),
    statfs: Some(devfs_statfs),
    sync: None,
    vget: None,
};

static DEVFS_VFSCONF: VfsConf = VfsConf {
    name: b"devfs".as_ptr(),
    name_len: 5,
    ops: &DEVFS_VFSOPS,
    vops: &DEVFS_VOPS,
    mnt_data_size: 8,
    v_data_size: 8,
    flags: VFCF_SYNTHETIC | VFCF_NOCACHE,
};

extern "C" fn devfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel's mount and arguments, live for the call.
    let (update, has_opts) = unsafe { ((*mp).mnt_flag & MNT_UPDATE != 0, (*args).opts_len != 0) };
    if has_opts {
        return EINVAL;
    }
    if update {
        return 0;
    }
    let Some(m) = try_box(DevMount { root: ptr::null_mut(), next_id: ROOT_ID, generation: 0, hidden: Vec::new() })
    else {
        return ENOMEM;
    };
    let m = Box::into_raw(m);
    // SAFETY: `mnt_data` is 8 bytes for its pointer.
    unsafe { *((*mp).mnt_data as *mut *mut DevMount) = m };
    let mm = dm(mp);
    let Some(root) = new_node(mm, VDIR, 0o755, 0, 0, Data::Dir(Dir { parent: ptr::null_mut(), entries: Vec::new(), next_cookie: 2 }))
    else {
        // SAFETY: made above, never shared.
        drop(unsafe { Box::from_raw(m) });
        return ENOMEM;
    };
    // SAFETY: just made.
    if let Data::Dir(d) = unsafe { &mut (*root).data } {
        d.parent = root;
    }
    mm.root = root;
    // The mount point for `/etc/fstab`'s tmpfs of POSIX shared memory objects.
    if let Some(shm) = subdir(mm, root, b"shm") {
        // SAFETY: just made.
        unsafe { (*shm).mode = 0o1777 };
    }
    sync(mp);
    0
}

/// Frees the view: the kernel reclaimed every vnode of it first (freeing the nameless nodes they
/// had), so what's left is the tree.
extern "C" fn devfs_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    let mut stack: Vec<*mut Node> = Vec::new();
    stack.push(dm(mp).root);
    while let Some(n) = stack.pop() {
        // SAFETY: a node of the tree, each reached once (no hard links in devfs).
        if let Data::Dir(d) = unsafe { &mut (*n).data } {
            for e in d.entries.drain(..) {
                stack.push(e.node);
            }
        }
        free_node(n);
    }
    // SAFETY: the pointer `devfs_mount` stored; nothing refers to it now.
    unsafe {
        let p = *((*mp).mnt_data as *mut *mut DevMount);
        drop(Box::from_raw(p));
        *((*mp).mnt_data as *mut *mut DevMount) = ptr::null_mut();
    }
    0
}

extern "C" fn devfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    vget(mp, dm(mp).root, vpp)
}

extern "C" fn devfs_statfs(_mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    // SAFETY: the kernel's record.
    let sb = unsafe { &mut *sbp };
    sb.f_bsize = 512;
    sb.f_iosize = 4096;
    sb.f_namemax = NAME_MAX as u32;
    sb.f_magic = DEVFS_MAGIC;
    0
}

// --- Vnode operations ---------------------------------------------------------------------------------

static DEVFS_VOPS: VopVector = VopVector {
    lookup: Some(devfs_lookup),
    create: Some(devfs_create),
    mknod: Some(devfs_mknod),
    getattr: Some(devfs_getattr),
    setattr: Some(devfs_setattr),
    read: Some(devfs_read),
    write: Some(devfs_write),
    remove: Some(devfs_remove),
    link: Some(devfs_link),
    rename: Some(devfs_rename),
    mkdir: Some(devfs_mkdir),
    rmdir: Some(devfs_rmdir),
    symlink: Some(devfs_symlink),
    readdir: Some(devfs_readdir),
    readlink: Some(devfs_readlink),
    inactive: Some(devfs_inactive),
    reclaim: Some(devfs_reclaim),
    ..VopVector::DEFAULT
};

extern "C" fn devfs_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32 {
    let mp = mount_of(dvp);
    sync(mp);
    let Some(dn) = node_of(dvp) else { return ENOENT };
    let self_ptr = dn as *mut Node;
    let Ok(d) = dir_of(dn) else { return ENOTDIR };
    // SAFETY: the kernel's component.
    let dotdot = unsafe { (*cnp).cn_flags } & ISDOTDOT != 0;
    let name = name_of(cnp);
    let target = if dotdot || name == b".." {
        d.parent
    } else if name == b"." {
        self_ptr
    } else {
        match d.find(name) {
            Some(i) => d.entries[i].node,
            None => return ENOENT,
        }
    };
    vget(mp, target, vpp)
}

/// No regular files in devfs, as FreeBSD's.
extern "C" fn devfs_create(_dvp: *mut Vnode, _vpp: *mut *mut Vnode, _cnp: *const ComponentName, _vap: *const Vattr) -> i32 {
    EOPNOTSUPP
}

/// The registry's nodes are its own: nobody makes a device node (or a FIFO) by hand. A socket's is
/// made by `bind`.
extern "C" fn devfs_mknod(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    // SAFETY: the kernel's record.
    let va = unsafe { &*vap };
    if va.va_type != VSOCK {
        return EPERM;
    }
    make_named(dvp, cnp, VSOCK, va.va_mode & 0o7777, Data::Sock, vpp)
}

extern "C" fn devfs_link(_tdvp: *mut Vnode, _vp: *mut Vnode, _cnp: *const ComponentName) -> i32 {
    EOPNOTSUPP
}

extern "C" fn devfs_rename(
    _fdvp: *mut Vnode,
    _fvp: *mut Vnode,
    _fcnp: *const ComponentName,
    _tdvp: *mut Vnode,
    _tvp: *mut Vnode,
    _tcnp: *const ComponentName,
) -> i32 {
    EOPNOTSUPP
}

/// A user's directory or link, named `cnp` in `dvp`.
fn make_named(dvp: *mut Vnode, cnp: *const ComponentName, vtype: VType, mode: u32, data: Data, vpp: *mut *mut Vnode) -> i32 {
    let mp = mount_of(dvp);
    let m = dm(mp);
    let Some(dn) = node_of(dvp) else { return ENOENT };
    let dir = dn as *mut Node;
    let name = name_of(cnp);
    if name.len() > NAME_MAX {
        return ENAMETOOLONG;
    }
    match dir_of(dn) {
        Ok(d) if d.find(name).is_some() => return EEXIST,
        Ok(_) => {}
        Err(e) => return e,
    }
    let gid = dn.gid;
    let Some(n) = new_node(m, vtype, mode, cred_of(cnp).cr_uid, gid, data) else { return ENOMEM };
    // SAFETY: just made.
    if let Data::Dir(d) = unsafe { &mut (*n).data } {
        d.parent = dir;
    }
    if let Err(e) = insert(dir, name, n) {
        free_node(n);
        return e;
    }
    vget(mp, n, vpp)
}

extern "C" fn devfs_mkdir(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    // SAFETY: the kernel's record.
    let mode = unsafe { (*vap).va_mode } & 0o7777;
    make_named(dvp, cnp, VDIR, mode, Data::Dir(Dir { parent: ptr::null_mut(), entries: Vec::new(), next_cookie: 2 }), vpp)
}

extern "C" fn devfs_symlink(
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
    // SAFETY: the kernel's record.
    let mode = match unsafe { (*vap).va_mode } {
        m if m == VNOVAL as u32 => 0o755,
        m => m & 0o7777,
    };
    make_named(dvp, cnp, VLNK, mode, Data::Lnk(t), vpp)
}

/// Removing a device's node hides the device in this view; a link just goes.
extern "C" fn devfs_remove(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let mp = mount_of(dvp);
    let (Some(dn), Some(n)) = (node_of(dvp), node_of(vp)) else { return ENOENT };
    if n.vtype == VDIR {
        return EISDIR;
    }
    if let Data::Dev(ma, mi) = n.data {
        let m = dm(mp);
        if m.hidden.try_reserve(1).is_err() {
            return ENOMEM;
        }
        if !m.hidden.contains(&(ma, mi)) {
            m.hidden.push((ma, mi));
        }
    }
    if unlink(dn, name_of(cnp)).is_none() {
        return ENOENT;
    }
    // The kernel holds `vp`: the node goes when it does (`devfs_inactive`).
    0
}

extern "C" fn devfs_rmdir(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let (Some(dn), Some(n)) = (node_of(dvp), node_of(vp)) else { return ENOENT };
    match &n.data {
        Data::Dir(d) if !d.entries.is_empty() => return ENOTEMPTY,
        Data::Dir(_) => {}
        _ => return ENOTDIR,
    }
    if unlink(dn, name_of(cnp)).is_none() {
        return ENOENT;
    }
    0
}

extern "C" fn devfs_readdir(vp: *mut Vnode, uio: u64, _cred: *const Ucred, eofflag: *mut i32) -> i64 {
    sync(mount_of(vp));
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
    let from = cursor;
    let fixed: [(u64, &[u8], u64, VType); 2] = [(0, b".", self_id, VDIR), (1, b"..", parent_id, VDIR)];
    let start = d.entries.partition_point(|e| e.cookie < cursor);
    let rest = d.entries[start..].iter().map(|e| {
        // SAFETY: a live node named by the entry.
        let c = unsafe { &*e.node };
        (e.cookie, &*e.name, c.id, c.vtype)
    });
    for (cookie, name, id, vtype) in fixed.into_iter().filter(move |f| f.0 >= from).chain(rest) {
        let reclen = dirent_reclen(name.len());
        // SAFETY: kernel export.
        if (unsafe { oxidebsd_uio_resid(uio) } as usize) < reclen {
            eof = false;
            break;
        }
        dirent_encode(&mut record, id, (cookie + 1) as i64, vtype_to_dt(vtype), name);
        // SAFETY: kernel export, with this module's buffer.
        if unsafe { oxidebsd_uiomove(record.as_mut_ptr(), reclen as u64, uio) } < 0 {
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
    written
}

extern "C" fn devfs_readlink(vp: *mut Vnode, uio: u64, _cred: *const Ucred) -> i64 {
    let Some(n) = node_of(vp) else { return -(EIO as i64) };
    let Data::Lnk(t) = &n.data else { return -(EINVAL as i64) };
    // SAFETY: kernel export.
    let cap = (unsafe { oxidebsd_uio_resid(uio) } as usize).min(t.len());
    // SAFETY: kernel export; a read transfer only reads the buffer.
    unsafe { oxidebsd_uiomove(t.as_ptr() as *mut u8, cap as u64, uio) }
}

/// A device node's reads and writes are the device's (the kernel opens it through the registry);
/// a directory's is `EISDIR`.
extern "C" fn devfs_read(vp: *mut Vnode, _uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    match node_of(vp).map(|n| n.vtype) {
        Some(VDIR) => -(EISDIR as i64),
        _ => -(EOPNOTSUPP as i64),
    }
}

extern "C" fn devfs_write(vp: *mut Vnode, _uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    devfs_read(vp, 0, 0, ptr::null())
}

extern "C" fn devfs_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    let Some(n) = node_of(vp) else { return EIO };
    let (size, rdev) = match &n.data {
        Data::Dir(d) => ((d.entries.len() as u64 + 2) * 32, 0),
        Data::Dev(ma, mi) => (0, makedev(*ma, *mi)),
        Data::Lnk(t) => (t.len() as u64, 0),
        Data::Sock => (0, 0),
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
        va_size: size,
        va_blocksize: 4096,
        va_atime: n.atime,
        va_mtime: n.mtime,
        va_ctime: n.ctime,
        va_birthtime: n.ctime,
        va_gen: 0,
        va_flags: 0,
        va_rdev: rdev,
        va_bytes: 0,
        va_vaflags: 0,
    };
    0
}

/// `chmod`, `chown` and times, kept in this view; a size is the device's business (`EINVAL`,
/// except a truncation to 0, which opening `/dev/null` with `O_TRUNC` asks for and is a no-op).
extern "C" fn devfs_setattr(vp: *mut Vnode, vap: *const Vattr, _cred: *const Ucred) -> i32 {
    let Some(n) = node_of(vp) else { return EIO };
    // SAFETY: the kernel's record.
    let va = unsafe { &*vap };
    if va.va_size != VNOVAL {
        match n.data {
            Data::Dir(_) => return EISDIR,
            Data::Dev(..) if va.va_size == 0 => {}
            _ => return EINVAL,
        }
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
    if va.va_atime != VNOVAL_TIME {
        n.atime = va.va_atime;
        changed = true;
    }
    if va.va_mtime != VNOVAL_TIME {
        n.mtime = va.va_mtime;
        changed = true;
    }
    if changed {
        n.ctime = now();
    }
    0
}

/// The last use went: a node with no name left goes (its vnode is recycled, which frees it).
extern "C" fn devfs_inactive(vp: *mut Vnode) -> i32 {
    if let Some(n) = node_of(vp)
        && n.nlink == 0
    {
        // SAFETY: kernel export.
        unsafe { oxidebsd_vfs_recycle(mount_of(vp), n.id) };
    }
    0
}

extern "C" fn devfs_reclaim(vp: *mut Vnode) -> i32 {
    if let Some(n) = node_of(vp) {
        if n.nlink == 0 {
            free_node(n as *mut Node);
        }
        set_node_of(vp, ptr::null_mut());
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // SAFETY: kernel exports, with a static table. Registering mounts devfs on `/dev` once the
    // root is up (`vfs_mount::automount`).
    unsafe {
        oxidebsd_module_serialize();
        if oxidebsd_vfs_register(&DEVFS_VFSCONF) != 0 {
            log("[devfs] registering the type failed\n");
            return -1;
        }
    }
    0
}
