//! oxfs's VFS types (OxideBSD-doc `VFS.md` §4-§5): `oxfs` (the disk), and `nullfs` over its inode
//! space until step 3d makes nullfs a module of its own (tmpfs and devfs went in 3b and 3c). A
//! vnode's file ID is the inode number; the kernel does path lookup and the system calls, and these
//! are the operations it asks for.
//!
//! A nullfs mount shows another mount's directory under a mount of its own (so `..` at its root
//! leaves through the directory it covers, which the kernel's `namei` handles).

use alloc::vec::Vec;
use core::ptr;

use oxfs_format::*;
use vfs_if::*;

use super::*;

const VFS_ENOENT: i32 = 2;
const VFS_EIO: i32 = 5;
const VFS_ENXIO: i32 = 6;
const VFS_EFAULT: i32 = 14;
const VFS_EXDEV: i32 = 18;
const VFS_ENOTDIR: i32 = 20;
const VFS_EISDIR: i32 = 21;
const VFS_EINVAL: i32 = 22;
const VFS_ENOSPC: i32 = 28;
const VFS_EMLINK: i32 = 31;
const VFS_ENOTEMPTY: i32 = 39;

/// What a mount of one of these types is. The kernel allocates it zeroed with the mount.
#[repr(C)]
struct OxMount {
    /// The inode the mount's root is.
    root: u32,
    kind: u32,
    /// A nullfs mount's: the mount it shows a directory of, whose vnodes hold the contents.
    lower: *mut Mount,
    /// A nullfs mount's: that directory, in use for as long as it's mounted, so the lower mount
    /// can't be unmounted from under it (`EBUSY`).
    lower_root: *mut Vnode,
}

const KIND_DISK: u32 = 0;
const KIND_NULLFS: u32 = 3;

macro_rules! vfsconf {
    ($name:ident, $str:literal, $ops:ident, $flags:expr) => {
        pub(crate) static $name: VfsConf = VfsConf {
            name: $str.as_ptr(),
            name_len: $str.len(),
            ops: &$ops,
            vops: &OXFS_VOPS,
            mnt_data_size: core::mem::size_of::<OxMount>(),
            v_data_size: 0,
            flags: $flags,
        };
    };
}

vfsconf!(OXFS_VFSCONF, b"oxfs", OXFS_VFSOPS, 0);
vfsconf!(NULLFS_VFSCONF, b"nullfs", NULLFS_VFSOPS, VFCF_FROM_VNODE);

macro_rules! vfsops {
    ($name:ident, $mount:ident) => {
        static $name: VfsOps = VfsOps {
            mount: Some($mount),
            unmount: Some(oxfs_vfs_unmount),
            root: Some(oxfs_vfs_root),
            statfs: Some(oxfs_vfs_statfs),
            sync: Some(oxfs_vfs_sync),
            vget: Some(oxfs_vfs_vget),
        };
    };
}

vfsops!(OXFS_VFSOPS, oxfs_vfs_mount);
vfsops!(NULLFS_VFSOPS, nullfs_vfs_mount);

static OXFS_VOPS: VopVector = VopVector {
    lookup: Some(oxfs_vop_lookup),
    create: Some(oxfs_vop_create),
    mknod: Some(oxfs_vop_mknod),
    getattr: Some(oxfs_vop_getattr),
    setattr: Some(oxfs_vop_setattr),
    read: Some(oxfs_vop_read),
    write: Some(oxfs_vop_write),
    fsync: Some(oxfs_vop_fsync),
    remove: Some(oxfs_vop_remove),
    link: Some(oxfs_vop_link),
    rename: Some(oxfs_vop_rename),
    mkdir: Some(oxfs_vop_mkdir),
    rmdir: Some(oxfs_vop_rmdir),
    symlink: Some(oxfs_vop_symlink),
    readdir: Some(oxfs_vop_readdir),
    readlink: Some(oxfs_vop_readlink),
    inactive: Some(oxfs_vop_inactive),
    reclaim: Some(oxfs_vop_reclaim),
    bmap: Some(oxfs_vop_bmap),
    allocate: Some(oxfs_vop_allocate),
    ..VopVector::DEFAULT
};

/// Every mount of these types, for `inode_busy`.
static mut MOUNTS: Vec<*mut Mount> = Vec::new();

fn our_mounts() -> &'static mut Vec<*mut Mount> {
    // SAFETY: under the VFS's giant lock, as every call into this module.
    unsafe { &mut *ptr::addr_of_mut!(MOUNTS) }
}

/// The root mount (the disk's), once mounted.
static mut ROOT_MOUNT: *mut Mount = ptr::null_mut();

pub(crate) fn root_mount() -> *mut Mount {
    // SAFETY: written once, at mount, before any process runs.
    unsafe { *ptr::addr_of!(ROOT_MOUNT) }
}

/// Whether a vnode of inode `n`, on any mount, is in use: a file's storage stays until none is.
pub(crate) fn inode_busy(n: u32) -> bool {
    // SAFETY: kernel export, called as declared.
    our_mounts().iter().any(|&mp| unsafe { oxidebsd_vfs_fileid_busy(mp, n as u64) } != 0)
}

/// Inode `n`'s storage is gone and its number free: no mount may keep a vnode of it.
pub(crate) fn inode_freed(n: u32) {
    for &mp in our_mounts().iter() {
        // SAFETY: kernel export.
        unsafe { oxidebsd_vfs_recycle(mp, n as u64) };
    }
}

fn oxmount(mp: *mut Mount) -> &'static mut OxMount {
    // SAFETY: the kernel allocated `mnt_data` with `size_of::<OxMount>()` bytes for this type.
    unsafe { &mut *((*mp).mnt_data as *mut OxMount) }
}

fn inode_of(vp: *mut Vnode) -> u32 {
    // SAFETY: the kernel passes a live vnode of ours.
    unsafe { (*vp).v_fileid as u32 }
}

fn mount_of(vp: *mut Vnode) -> *mut Mount {
    // SAFETY: as above.
    unsafe { (*vp).v_mount }
}

fn cred_of(cnp: *const ComponentName) -> &'static Ucred {
    // SAFETY: the kernel passes its own component and credentials, live for the call.
    unsafe { &*(*cnp).cn_cred }
}

fn name_of(cnp: *const ComponentName) -> &'static [u8] {
    // SAFETY: as above.
    unsafe { (*cnp).name() }
}

/// `errno_for`'s negative errno as an operation's positive one.
fn err(e: OxfsError) -> i32 {
    (-errno_for(e)) as i32
}

fn registered(mp: *mut Mount) {
    our_mounts().push(mp);
}

// --- vfsops ----------------------------------------------------------------------------------

/// Mounts the disk's oxfs: the superblock, the layout, the free counts. Only the root for now
/// (oxfs has one partition's worth of global state). With `MNT_UPDATE`, changes the root between
/// read-only and read-write (`remount_root`).
extern "C" fn oxfs_vfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel filled the mount's flags.
    let flags = unsafe { (*mp).mnt_flag };
    // SAFETY: the kernel's arguments.
    if unsafe { (*args).opts_len } != 0 {
        return VFS_EINVAL;
    }
    if flags & MNT_UPDATE != 0 {
        return match remount_root(flags & MNT_RDONLY != 0) {
            0 => 0,
            e => (-e) as i32,
        };
    }
    if !root_mount().is_null() {
        return VFS_EINVAL;
    }
    // The root file system is the disk's oxfs partition, made by newfs_oxfs(8) or installed from
    // a system image; the kernel never formats one (`OxideBSD-doc/RAM_FLOOR.md` §4.2.1).
    if !block_device_present() {
        log("[oxfs] no root file system: no disk (and the memory disk is empty)\n");
        return VFS_ENXIO;
    }
    if !mount_from_disk() {
        log("[oxfs] no root file system: the root partition holds no oxfs of this version (make one with newfs_oxfs(8), or install a system image)\n");
        return VFS_EINVAL;
    }
    // SAFETY: before any process runs; nothing else reads it yet.
    unsafe { *ptr::addr_of_mut!(ROOT_MOUNT) = mp };
    *oxmount(mp) = OxMount { root: ROOT_INODE, kind: KIND_DISK, lower: ptr::null_mut(), lower_root: ptr::null_mut() };
    registered(mp);
    // Mounting leaves PERSISTENCE_READY false through its own reads (see that flag's own doc
    // comment) -- flipped here, once, right before real syscalls become reachable, so every write
    // a running process makes from this point on is persisted immediately.
    set_persistence_ready(true);
    buf::set_write_through(true);
    let rdonly = flags & MNT_RDONLY != 0;
    set_root_rdonly(rdonly);
    if rdonly {
        log("[oxfs] root mounted read-only\n");
    } else {
        // Mounted: not clean on the disk until an orderly shutdown says so (§3.4.1).
        set_clean(false);
        write_superblock();
        sweep_unnamed_inodes();
    }
    // `/dev` is devfs's mount point; the kernel mounts devfs there.
    ensure_dir(ROOT_INODE, b"dev");
    0
}

/// For a mount that takes no options of its own: `Some(result)` to return at once for a remount
/// (`MNT_UPDATE`: only the kernel's flags change) or for options it doesn't know (`EINVAL`).
fn no_options(mp: *mut Mount, args: *const MountArgs) -> Option<i32> {
    // SAFETY: the kernel's mount and arguments, live for the call.
    let (update, has_opts) = unsafe { ((*mp).mnt_flag & MNT_UPDATE != 0, (*args).opts_len != 0) };
    if has_opts {
        return Some(VFS_EINVAL);
    }
    update.then_some(0)
}

/// A directory of one of these types shown at another place (`mount -t nullfs`).
extern "C" fn nullfs_vfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    if let Some(e) = no_options(mp, args) {
        return e;
    }
    // SAFETY: the kernel passes its arguments.
    let from = unsafe { (*args).from_vp };
    if from.is_null() {
        return VFS_EINVAL;
    }
    // SAFETY: referenced by the kernel for the call.
    let from_vfc = unsafe { (*(*from).v_mount).mnt_vfc };
    let ours = [&OXFS_VFSCONF, &NULLFS_VFSCONF];
    if !ours.iter().any(|&c| ptr::eq(c, from_vfc)) {
        return VFS_EXDEV;
    }
    // SAFETY: referenced by the kernel for the call; kept in use until this mount goes.
    unsafe { oxidebsd_vref(from) };
    let lower = unsafe { (*from).v_mount };
    *oxmount(mp) = OxMount { root: inode_of(from), kind: KIND_NULLFS, lower, lower_root: from };
    registered(mp);
    0
}

/// The disk's at shutdown (`vfs_unmountall`): everything delayed is written, and the file system
/// marked clean (§3.4.1). Not called on a panic or a fault. A nullfs mount lets go of its
/// directory.
extern "C" fn oxfs_vfs_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    our_mounts().retain(|&m| m != mp);
    let lower_root = oxmount(mp).lower_root;
    if !lower_root.is_null() {
        // SAFETY: kernel export; the reference `nullfs_vfs_mount` took.
        unsafe { oxidebsd_vrele(lower_root) };
    }
    if oxmount(mp).kind != KIND_DISK || root_rdonly() {
        return 0;
    }
    buf::flush_all();
    set_clean(true);
    write_superblock();
    log("[oxfs] filesystem synced and marked clean\n");
    0
}

extern "C" fn oxfs_vfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    oxfs_vfs_vget(mp, oxmount(mp).root as u64, vpp)
}

/// The disk's counts.
extern "C" fn oxfs_vfs_statfs(_mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    let (blocks_lo, blocks_hi) = (0, disk_blocks());
    let free_blocks: u64 = (0..bitmap_blocks()).map(|i| *free_count(i) as u64).sum();
    // The table grows into free blocks, so each free block is `INODES_PER_BLOCK` inodes to come
    // (as ZFS reports it): the count is an estimate that shrinks as data fills the pool.
    let table = inode_table();
    let free_inodes = table.free as u64 + free_blocks * INODES_PER_BLOCK as u64;
    let used_inodes = (table.count - table.free) as u64;
    // SAFETY: the kernel passes its own record.
    let sb = unsafe { &mut *sbp };
    sb.f_bsize = BLOCK_SIZE as u64;
    sb.f_iosize = BLOCK_SIZE as u64;
    sb.f_blocks = (blocks_hi - blocks_lo) as u64;
    sb.f_bfree = free_blocks;
    sb.f_bavail = free_blocks;
    sb.f_files = used_inodes + free_inodes;
    sb.f_ffree = free_inodes;
    sb.f_namemax = NAME_MAX as u32;
    sb.f_magic = OXFS_STATFS_MAGIC;
    0
}

extern "C" fn oxfs_vfs_sync(mp: *mut Mount, _waitfor: i32) -> i32 {
    if oxmount(mp).kind == KIND_DISK {
        buf::flush_all();
    }
    0
}

fn vtype_of(kind: InodeKind, device_char: bool) -> VType {
    match kind {
        InodeKind::Dir => VDIR,
        InodeKind::Symlink => VLNK,
        InodeKind::Device if device_char => VCHR,
        InodeKind::Device => VBLK,
        InodeKind::Fifo => VFIFO,
        InodeKind::Socket => VSOCK,
        InodeKind::Free => VNON,
        _ => VREG,
    }
}

extern "C" fn oxfs_vfs_vget(mp: *mut Mount, fileid: u64, vpp: *mut *mut Vnode) -> i32 {
    // A nullfs mount whose lower mount was forcibly unmounted: its directory (still held) is
    // doomed and the mount gone, so nothing below can be reached.
    let lower_root = oxmount(mp).lower_root;
    // SAFETY: held by this mount until it's unmounted.
    if !lower_root.is_null() && unsafe { (*lower_root).v_flag } & VI_DOOMED != 0 {
        return VFS_EIO;
    }
    // SAFETY: kernel exports, called as declared.
    unsafe {
        let vp = oxidebsd_vfs_hash_get(mp, fileid);
        if !vp.is_null() {
            *vpp = vp;
            return 0;
        }
        let inode = read_inode(fileid as u32);
        if inode.kind == InodeKind::Free {
            return VFS_EIO;
        }
        let mut vp = ptr::null_mut();
        let e = oxidebsd_getnewvnode(mp, vtype_of(inode.kind, inode.device_char), fileid, &mut vp);
        if e != 0 {
            return e;
        }
        if inode.kind == InodeKind::Device {
            (*vp).v_rdev = inode.rdev as u64;
        }
        if fileid == oxmount(mp).root as u64 {
            (*vp).v_flag |= VV_ROOT;
        }
        // A nullfs vnode's contents are the lower mount's vnode's (VFS.md §13): it holds that one,
        // or the one that one holds, so the page cache, mappings, FIFOs and sockets see one file.
        let lower_mp = oxmount(mp).lower;
        if !lower_mp.is_null() {
            let mut lower = ptr::null_mut();
            if oxfs_vfs_vget(lower_mp, fileid, &mut lower) == 0 {
                let object = if (*lower).v_lower.is_null() { lower } else { (*lower).v_lower };
                oxidebsd_vhold(object);
                (*vp).v_lower = object;
                oxidebsd_vrele(lower);
            }
        }
        oxidebsd_vfs_hash_insert(vp);
        *vpp = vp;
    }
    0
}

fn vget(mp: *mut Mount, n: u32, vpp: *mut *mut Vnode) -> i32 {
    oxfs_vfs_vget(mp, n as u64, vpp)
}

// --- Names ---------------------------------------------------------------------------------------

extern "C" fn oxfs_vop_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32 {
    let dir = inode_of(dvp);
    if read_inode(dir).kind != InodeKind::Dir {
        return VFS_ENOTDIR;
    }
    // SAFETY: the kernel's component.
    let dotdot = unsafe { (*cnp).cn_flags } & ISDOTDOT != 0;
    let name: &[u8] = if dotdot { b".." } else { name_of(cnp) };
    match dir_lookup(dir, name) {
        Some(n) => vget(mount_of(dvp), n, vpp),
        None => VFS_ENOENT,
    }
}

/// A new inode of `kind` in directory `parent`, owned by `cred`'s user and the directory's group,
/// named `name`: `create`, `mknod`, `mkdir` and `symlink`'s common part.
fn new_node(
    dvp: *mut Vnode,
    cnp: *const ComponentName,
    kind: InodeKind,
    mode: u32,
    fill: impl FnOnce(u32, &mut Inode) -> Result<(), i32>,
    vpp: *mut *mut Vnode,
) -> i32 {
    let parent = inode_of(dvp);
    let cred = cred_of(cnp);
    let Some(n) = alloc_inode_in(parent) else { return VFS_ENOSPC };
    let mut inode = fresh_inode(kind);
    inode.uid = cred.cr_uid;
    inode.gid = new_entry_gid(parent);
    inode.mode = mode as u16;
    if let Err(e) = fill(n, &mut inode) {
        return e;
    }
    write_inode(n, inode);
    if kind == InodeKind::Dir
        && (dir_insert(n, b".", n).is_err() || dir_insert(n, b"..", parent).is_err())
    {
        return VFS_ENOSPC;
    }
    if let Err(e) = dir_insert(parent, name_of(cnp), n) {
        return err(e);
    }
    vget(mount_of(dvp), n, vpp)
}

fn vattr(vap: *const Vattr) -> &'static Vattr {
    // SAFETY: the kernel's record, live for the call.
    unsafe { &*vap }
}

extern "C" fn oxfs_vop_create(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    new_node(dvp, cnp, InodeKind::File, vattr(vap).va_mode & 0o777, |_, _| Ok(()), vpp)
}

extern "C" fn oxfs_vop_mknod(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    let va = vattr(vap);
    let (kind, device_char) = match va.va_type {
        VREG => (InodeKind::File, false),
        VCHR => (InodeKind::Device, true),
        VBLK => (InodeKind::Device, false),
        VFIFO => (InodeKind::Fifo, false),
        VSOCK => (InodeKind::Socket, false),
        _ => return VFS_EINVAL,
    };
    new_node(dvp, cnp, kind, va.va_mode & 0o777, |_, inode| {
        if kind == InodeKind::Device {
            inode.rdev = va.va_rdev as u32;
            inode.device_char = device_char;
        }
        Ok(())
    }, vpp)
}

extern "C" fn oxfs_vop_mkdir(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
    new_node(dvp, cnp, InodeKind::Dir, vattr(vap).va_mode & 0o7777, |_, _| Ok(()), vpp)
}

extern "C" fn oxfs_vop_symlink(
    dvp: *mut Vnode,
    vpp: *mut *mut Vnode,
    cnp: *const ComponentName,
    _vap: *const Vattr,
    target: *const u8,
    target_len: usize,
) -> i32 {
    // SAFETY: the kernel's buffer, live for the call.
    let target = unsafe { core::slice::from_raw_parts(target, target_len) };
    let parent = inode_of(dvp);
    let cred = cred_of(cnp);
    let Some(n) = alloc_inode_in(parent) else { return VFS_ENOSPC };
    let mut inode = fresh_inode(InodeKind::Symlink);
    inode.uid = cred.cr_uid;
    inode.gid = new_entry_gid(parent);
    write_inode(n, inode);
    if !write_inode_data(n, target) {
        return VFS_EIO;
    }
    if let Err(e) = dir_insert(parent, name_of(cnp), n) {
        return err(e);
    }
    vget(mount_of(dvp), n, vpp)
}

extern "C" fn oxfs_vop_remove(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let (parent, target) = (inode_of(dvp), inode_of(vp));
    if let Err(e) = dir_remove(parent, name_of(cnp)) {
        return err(e);
    }
    let mut inode = read_inode(target);
    inode.nlink = inode.nlink.saturating_sub(1);
    write_inode(target, inode);
    maybe_release(target);
    0
}

extern "C" fn oxfs_vop_rmdir(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let (parent, target) = (inode_of(dvp), inode_of(vp));
    if dir_entry_count(target) > 2 {
        return VFS_ENOTEMPTY;
    }
    if let Err(e) = dir_remove(parent, name_of(cnp)) {
        return err(e);
    }
    let mut dir = read_inode(target);
    dir.nlink = 0;
    write_inode(target, dir);
    maybe_release(target);
    0
}

extern "C" fn oxfs_vop_link(tdvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let (parent, n) = (inode_of(tdvp), inode_of(vp));
    let mut inode = read_inode(n);
    if inode.nlink == u16::MAX {
        return VFS_EMLINK;
    }
    if let Err(e) = dir_insert(parent, name_of(cnp), n) {
        return err(e);
    }
    inode.nlink += 1;
    write_inode(n, inode);
    0
}

extern "C" fn oxfs_vop_rename(
    fdvp: *mut Vnode,
    fvp: *mut Vnode,
    fcnp: *const ComponentName,
    tdvp: *mut Vnode,
    tvp: *mut Vnode,
    tcnp: *const ComponentName,
) -> i32 {
    let (old_parent, target, new_parent) = (inode_of(fdvp), inode_of(fvp), inode_of(tdvp));
    let (old_leaf, new_leaf) = (name_of(fcnp), name_of(tcnp));
    let is_dir = read_inode(target).kind == InodeKind::Dir;
    let existing = if tvp.is_null() { None } else { Some(inode_of(tvp)) };
    if let Some(existing) = existing {
        let existing_is_dir = read_inode(existing).kind == InodeKind::Dir;
        if existing_is_dir && dir_entry_count(existing) > 2 {
            return VFS_ENOTEMPTY;
        }
        let _ = dir_remove(new_parent, new_leaf);
        let mut replaced = read_inode(existing);
        replaced.nlink = if existing_is_dir { 0 } else { replaced.nlink.saturating_sub(1) };
        write_inode(existing, replaced);
    }
    if dir_remove(old_parent, old_leaf).is_err() {
        return VFS_EIO;
    }
    if let Err(e) = dir_insert(new_parent, new_leaf, target) {
        let _ = dir_insert(old_parent, old_leaf, target);
        return err(e);
    }
    if is_dir && new_parent != old_parent {
        let _ = dir_remove(target, b"..");
        if let Err(e) = dir_insert(target, b"..", new_parent) {
            return err(e);
        }
    }
    if let Some(existing) = existing {
        maybe_release(existing);
    }
    0
}

extern "C" fn oxfs_vop_readdir(vp: *mut Vnode, uio: u64, _cred: *const Ucred, eofflag: *mut i32) -> i64 {
    let dir = inode_of(vp);
    // SAFETY: kernel exports, called as declared.
    let mut cursor = unsafe { oxidebsd_uio_offset(uio) } as usize;
    let mut record = [0u8; dirent_reclen(NAME_MAX)];
    let mut written = 0i64;
    let mut eof = true;
    while let Some((child, name, name_len)) = dir_nth_used_record(dir, cursor) {
        let name = &name[..name_len as usize];
        let reclen = dirent_reclen(name.len());
        if uio_resid(uio) < reclen {
            eof = false;
            break;
        }
        let c = read_inode(child);
        let dtype = vtype_to_dt(vtype_of(c.kind, c.device_char));
        dirent_encode(&mut record, child as u64, (cursor + 1) as i64, dtype, name);
        match uio_out(uio, &record[..reclen]) {
            Ok(_) => {}
            Err(_) if written == 0 => return -(VFS_EFAULT as i64),
            Err(_) => {
                eof = false;
                break;
            }
        }
        written += reclen as i64;
        cursor += 1;
    }
    // SAFETY: as above.
    unsafe {
        oxidebsd_uio_set_offset(uio, cursor as u64);
        *eofflag = eof as i32;
    }
    written
}

extern "C" fn oxfs_vop_readlink(vp: *mut Vnode, uio: u64, _cred: *const Ucred) -> i64 {
    let mut target = [0u8; OXFS_PATH_MAX];
    let cap = uio_resid(uio).min(target.len());
    let n = read_inode_at(inode_of(vp), 0, &mut target[..cap]);
    match uio_out(uio, &target[..n]) {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

// --- Attributes and contents --------------------------------------------------------------------

extern "C" fn oxfs_vop_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    let n = inode_of(vp);
    let st = inode_stat(n);
    let inode = read_inode(n);
    let t = |sec: i64| Timespec { tv_sec: sec, tv_nsec: 0 };
    // SAFETY: the kernel's record.
    let va = unsafe { &mut *vap };
    *va = Vattr {
        va_type: vtype_of(inode.kind, inode.device_char),
        va_mode: inode.mode as u32,
        // The real count, 0 for an unlinked file still open (`stat` reported it floored at 1).
        va_nlink: if inode.kind == InodeKind::Dir { st.st_nlink } else { inode.nlink as u64 },
        va_uid: inode.uid,
        va_gid: inode.gid,
        va_fsid: 0,
        va_fileid: n as u64,
        va_size: inode.size,
        va_blocksize: BLOCK_SIZE as u64,
        va_atime: t(inode.atime),
        va_mtime: t(inode.mtime),
        va_ctime: t(inode.ctime),
        va_birthtime: t(inode.ctime),
        va_gen: 0,
        va_flags: 0,
        va_rdev: st.st_rdev,
        va_bytes: st.st_blocks as u64 * 512,
        va_vaflags: 0,
    };
    0
}

/// Applies the fields of `vap` that aren't `VNOVAL`; the kernel checked permission.
extern "C" fn oxfs_vop_setattr(vp: *mut Vnode, vap: *const Vattr, _cred: *const Ucred) -> i32 {
    let n = inode_of(vp);
    let va = vattr(vap);
    // SAFETY: kernel export.
    let now = unsafe { oxidebsd_unix_time() };
    if va.va_size != VNOVAL {
        if read_inode(n).kind == InodeKind::Dir {
            return VFS_EISDIR;
        }
        if !resize_inode_data(n, va.va_size as usize) {
            return VFS_ENOSPC;
        }
    }
    let mut inode = read_inode(n);
    let mut changed = false;
    if va.va_mode != VNOVAL as u32 {
        inode.mode = (va.va_mode & 0o7777) as u16;
        changed = true;
    }
    if va.va_uid != VNOVAL as u32 {
        inode.uid = va.va_uid;
        changed = true;
    }
    if va.va_gid != VNOVAL as u32 {
        inode.gid = va.va_gid;
        changed = true;
    }
    if va.va_atime != VNOVAL_TIME {
        inode.atime = va.va_atime.tv_sec;
        changed = true;
    }
    if va.va_mtime != VNOVAL_TIME {
        inode.mtime = va.va_mtime.tv_sec;
        changed = true;
    }
    if changed {
        inode.ctime = now;
        write_inode(n, inode);
    }
    0
}

extern "C" fn oxfs_vop_read(vp: *mut Vnode, uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    let n = inode_of(vp);
    // SAFETY: kernel export.
    let offset = unsafe { oxidebsd_uio_offset(uio) } as usize;
    match read_inode_uio(n, offset, uio) {
        Ok(moved) => {
            if moved > 0 {
                touch_atime(n);
            }
            moved as i64
        }
        Err(e) => e,
    }
}

extern "C" fn oxfs_vop_write(vp: *mut Vnode, uio: u64, ioflag: u32, cred: *const Ucred) -> i64 {
    let n = inode_of(vp);
    if ioflag & IO_APPEND != 0 {
        // SAFETY: kernel export.
        unsafe { oxidebsd_uio_set_offset(uio, read_inode(n).size) };
    }
    if uio_resid(uio) == 0 {
        return 0;
    }
    // A write by anyone but root clears the set-user-ID and set-group-ID bits (POSIX allows it,
    // the BSDs do it), so a writable set-ID program can't be swapped for another.
    // SAFETY: the kernel's credentials.
    if unsafe { (*cred).cr_uid } != 0 {
        let mut inode = read_inode(n);
        if inode.mode & SETID_BITS != 0 {
            inode.mode &= !SETID_BITS;
            write_inode(n, inode);
        }
    }
    // SAFETY: kernel export.
    let offset = unsafe { oxidebsd_uio_offset(uio) } as usize;
    uio_ret(write_inode_uio(n, offset, uio))
}

extern "C" fn oxfs_vop_fsync(vp: *mut Vnode, _waitfor: i32, _data_only: u32) -> i32 {
    sync_file(inode_of(vp));
    0
}

/// The last use of the file went: an unlinked file's storage goes now.
extern "C" fn oxfs_vop_inactive(vp: *mut Vnode) -> i32 {
    maybe_release(inode_of(vp));
    0
}

extern "C" fn oxfs_vop_allocate(vp: *mut Vnode, offset: u64, len: u64) -> i32 {
    let n = inode_of(vp);
    let target = offset.saturating_add(len) as usize;
    if read_inode(n).size as usize >= target {
        return 0;
    }
    if resize_inode_data(n, target) { 0 } else { VFS_ENOSPC }
}

/// File block `lblkno` to its sector on the disk, and how many blocks after it follow contiguously
/// (`DEMANDPAGE.md` §5.1): the page cache fills mapped pages from the device with it. A block past
/// the end has none (a hole).
extern "C" fn oxfs_vop_bmap(vp: *mut Vnode, lblkno: u64, bnp: *mut u64, runp: *mut u64) -> i32 {
    let n = inode_of(vp);
    let record = read_inode(n);
    let device = |index: usize| -> Option<u64> {
        let block = inode_block_at(&record, index)?;
        Some(data_block_offset() as u64 + block as u64)
    };
    let (bn, run) = match device(lblkno as usize) {
        Some(first) => {
            let pages = (record.size as usize).div_ceil(BLOCK_SIZE);
            let mut run = 0u64;
            while (lblkno + run + 1) < pages as u64 && device((lblkno + run + 1) as usize) == Some(first + run + 1) {
                run += 1;
            }
            (first * (BLOCK_SIZE as u64 / 512), run)
        }
        None => (u64::MAX, 0),
    };
    // SAFETY: the kernel's out-parameters.
    unsafe {
        *bnp = bn;
        *runp = run;
    }
    0
}

/// The vnode is going: a nullfs vnode lets go of the lower one it holds (`v_lower`).
extern "C" fn oxfs_vop_reclaim(vp: *mut Vnode) -> i32 {
    // SAFETY: the kernel's vnode, being reclaimed.
    unsafe {
        let lower = (*vp).v_lower;
        if !lower.is_null() {
            (*vp).v_lower = ptr::null_mut();
            oxidebsd_vdrop(lower);
        }
    }
    0
}
