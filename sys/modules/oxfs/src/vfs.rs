//! oxfs as a VFS type (OxideBSD-doc `VFS.md` §4-§5). A vnode's file ID is the inode number; the
//! kernel does path lookup and the system calls, and these are the operations it asks for.

use alloc::boxed::Box;
use core::ptr;

use oxfs_format::*;
use vfs_if::*;

use super::*;

const VFS_ENOENT: i32 = 2;
const VFS_EIO: i32 = 5;
const VFS_ENXIO: i32 = 6;
const VFS_EFAULT: i32 = 14;
const VFS_ENOTDIR: i32 = 20;
const VFS_EISDIR: i32 = 21;
const VFS_EINVAL: i32 = 22;
const VFS_ENOMEM: i32 = 12;
const VFS_ENOSPC: i32 = 28;
const VFS_EMLINK: i32 = 31;
const VFS_ENOTEMPTY: i32 = 39;

macro_rules! vfsconf {
    ($name:ident, $str:literal, $ops:ident, $flags:expr) => {
        pub(crate) static $name: VfsConf = VfsConf {
            name: $str.as_ptr(),
            name_len: $str.len(),
            ops: &$ops,
            vops: &OXFS_VOPS,
            mnt_data_size: core::mem::size_of::<*mut Fs>(),
            v_data_size: 0,
            flags: $flags,
        };
    };
}

vfsconf!(OXFS_VFSCONF, b"oxfs", OXFS_VFSOPS, 0);

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
    bmap: Some(oxfs_vop_bmap),
    allocate: Some(oxfs_vop_allocate),
    ..VopVector::DEFAULT
};

/// The root mount (the disk's), once mounted.
static mut ROOT_MOUNT: *mut Mount = ptr::null_mut();

pub(crate) fn root_mount() -> *mut Mount {
    // SAFETY: written at the root's mount and unmount, under the giant lock.
    unsafe { *ptr::addr_of!(ROOT_MOUNT) }
}

fn set_root_mount(mp: *mut Mount) {
    // SAFETY: as `root_mount`.
    unsafe { *ptr::addr_of_mut!(ROOT_MOUNT) = mp };
}

/// Whether a vnode of inode `n` on mount `mp` is in use: a file's storage stays until none is.
pub(crate) fn inode_busy(mp: *mut Mount, n: u32) -> bool {
    // SAFETY: kernel export, called as declared.
    unsafe { oxidebsd_vfs_fileid_busy(mp, n as u64) != 0 }
}

/// Inode `n`'s storage on mount `mp` is gone and its number free: no vnode of it may stay.
pub(crate) fn inode_freed(mp: *mut Mount, n: u32) {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vfs_recycle(mp, n as u64) };
}

/// Mount `mp`'s file system.
pub(crate) fn fs(mp: *mut Mount) -> &'static mut Fs {
    // SAFETY: `mnt_data` holds the pointer `oxfs_vfs_mount` stored, live until unmount; every call
    // into this module holds the giant lock.
    unsafe { &mut **((*mp).mnt_data as *mut *mut Fs) }
}

/// The file system vnode `vp` is on.
fn fs_of(vp: *mut Vnode) -> &'static mut Fs {
    fs(mount_of(vp))
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

// --- vfsops ----------------------------------------------------------------------------------

/// Mounts the oxfs on the device the kernel hands it (`MountArgs::dev`): the superblock, the
/// layout, the free counts, into a new `Fs` of its own. With `MNT_UPDATE`, changes a mount between
/// read-only and read-write (`Fs::remount`).
extern "C" fn oxfs_vfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel filled the mount's flags.
    let flags = unsafe { (*mp).mnt_flag };
    // SAFETY: the kernel's arguments.
    if unsafe { (*args).opts_len } != 0 {
        return VFS_EINVAL;
    }
    if flags & MNT_UPDATE != 0 {
        return match fs(mp).remount(flags & MNT_RDONLY != 0) {
            0 => 0,
            e => (-e) as i32,
        };
    }
    let root = flags & MNT_ROOTFS != 0;
    // A file system is made by newfs_oxfs(8) or installed from a system image; the kernel never
    // formats one (`OxideBSD-doc/RAM_FLOOR.md` §4.2.1).
    // SAFETY: the kernel's arguments.
    let dev = unsafe { (*args).dev };
    if dev == vfs_if::NODEV {
        log(if root {
            "[oxfs] no root file system: no disk (and the memory disk is empty)\n"
        } else {
            "[oxfs] mount: no device\n"
        });
        return VFS_ENXIO;
    }
    let Some(b) = try_box(Fs::new(dev, mp, root)) else { return VFS_ENOMEM };
    let p = Box::into_raw(b);
    // SAFETY: `mnt_data` is the size of the pointer (`OXFS_VFSCONF`).
    unsafe { *((*mp).mnt_data as *mut *mut Fs) = p };
    let fs = fs(mp);
    buf::attach(dev);
    if !fs.mount_from_disk() {
        log(if root {
            "[oxfs] no root file system: the root partition holds no oxfs of this version (make one with newfs_oxfs(8), or install a system image)\n"
        } else {
            "[oxfs] mount: the device holds no oxfs of this version\n"
        });
        buf::detach(dev);
        // SAFETY: made above, never shared.
        unsafe {
            drop(Box::from_raw(p));
            *((*mp).mnt_data as *mut *mut Fs) = ptr::null_mut();
        }
        return VFS_EINVAL;
    }
    let rdonly = flags & MNT_RDONLY != 0;
    fs.set_rdonly(rdonly);
    if rdonly {
        log(if root { "[oxfs] root mounted read-only\n" } else { "[oxfs] mounted read-only\n" });
    } else {
        // Mounted: not clean on the disk until an unmount says so (§3.4.1).
        fs.clean = false;
        fs.write_superblock();
        fs.sweep_unnamed_inodes();
    }
    if root {
        set_root_mount(mp);
        // `/dev` is devfs's mount point; the kernel mounts devfs there.
        fs.ensure_dir(ROOT_INODE, b"dev");
    }
    0
}

/// An unmount, or the root's at shutdown (`vfs_unmountall`): everything delayed is written, and
/// the file system marked clean (§3.4.1). Not called on a panic or a fault.
extern "C" fn oxfs_vfs_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    let fs = fs(mp);
    if !fs.rdonly {
        buf::flush_all(fs.dev);
        fs.clean = true;
        fs.write_superblock();
        log("[oxfs] filesystem synced and marked clean\n");
    }
    buf::detach(fs.dev);
    if root_mount() == mp {
        set_root_mount(ptr::null_mut());
    }
    // SAFETY: the kernel has reclaimed every vnode of `mp`; nothing refers to its `Fs` now.
    unsafe {
        drop(Box::from_raw(*((*mp).mnt_data as *mut *mut Fs)));
        *((*mp).mnt_data as *mut *mut Fs) = ptr::null_mut();
    }
    0
}

extern "C" fn oxfs_vfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    oxfs_vfs_vget(mp, ROOT_INODE as u64, vpp)
}

/// The file system's counts.
extern "C" fn oxfs_vfs_statfs(mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    let fs = fs(mp);
    let free_blocks: u64 = fs.free_counts.iter().map(|&c| c as u64).sum();
    // The table grows into free blocks, so each free block is `INODES_PER_BLOCK` inodes to come
    // (as ZFS reports it): the count is an estimate that shrinks as data fills the pool.
    let table = fs.inodes;
    let free_inodes = table.free as u64 + free_blocks * INODES_PER_BLOCK as u64;
    let used_inodes = (table.count - table.free) as u64;
    // SAFETY: the kernel passes its own record.
    let sb = unsafe { &mut *sbp };
    sb.f_bsize = BLOCK_SIZE as u64;
    sb.f_iosize = BLOCK_SIZE as u64;
    sb.f_blocks = fs.data_blocks as u64;
    sb.f_bfree = free_blocks;
    sb.f_bavail = free_blocks;
    sb.f_files = used_inodes + free_inodes;
    sb.f_ffree = free_inodes;
    sb.f_namemax = NAME_MAX as u32;
    sb.f_magic = OXFS_STATFS_MAGIC;
    0
}

extern "C" fn oxfs_vfs_sync(mp: *mut Mount, _waitfor: i32) -> i32 {
    buf::flush_all(fs(mp).dev);
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
    // SAFETY: kernel exports, called as declared.
    unsafe {
        let vp = oxidebsd_vfs_hash_get(mp, fileid);
        if !vp.is_null() {
            *vpp = vp;
            return 0;
        }
        let inode = fs(mp).read_inode(fileid as u32);
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
        if fileid == ROOT_INODE as u64 {
            (*vp).v_flag |= VV_ROOT;
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
    let fs = fs_of(dvp);
    let dir = inode_of(dvp);
    if fs.read_inode(dir).kind != InodeKind::Dir {
        return VFS_ENOTDIR;
    }
    // SAFETY: the kernel's component.
    let dotdot = unsafe { (*cnp).cn_flags } & ISDOTDOT != 0;
    let name: &[u8] = if dotdot { b".." } else { name_of(cnp) };
    match fs.dir_lookup(dir, name) {
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
    let fs = fs_of(dvp);
    let parent = inode_of(dvp);
    let cred = cred_of(cnp);
    let Some(n) = fs.alloc_inode() else { return VFS_ENOSPC };
    let mut inode = fresh_inode(kind);
    inode.uid = cred.cr_uid;
    inode.gid = fs.new_entry_gid(parent);
    inode.mode = mode as u16;
    if let Err(e) = fill(n, &mut inode) {
        return e;
    }
    fs.write_inode(n, inode);
    if kind == InodeKind::Dir
        && (fs.dir_insert(n, b".", n).is_err() || fs.dir_insert(n, b"..", parent).is_err())
    {
        return VFS_ENOSPC;
    }
    if let Err(e) = fs.dir_insert(parent, name_of(cnp), n) {
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
    let fs = fs_of(dvp);
    // SAFETY: the kernel's buffer, live for the call.
    let target = unsafe { core::slice::from_raw_parts(target, target_len) };
    let parent = inode_of(dvp);
    let cred = cred_of(cnp);
    let Some(n) = fs.alloc_inode() else { return VFS_ENOSPC };
    let mut inode = fresh_inode(InodeKind::Symlink);
    inode.uid = cred.cr_uid;
    inode.gid = fs.new_entry_gid(parent);
    fs.write_inode(n, inode);
    if !fs.write_inode_data(n, target) {
        return VFS_EIO;
    }
    if let Err(e) = fs.dir_insert(parent, name_of(cnp), n) {
        return err(e);
    }
    vget(mount_of(dvp), n, vpp)
}

extern "C" fn oxfs_vop_remove(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let fs = fs_of(dvp);
    let (parent, target) = (inode_of(dvp), inode_of(vp));
    if let Err(e) = fs.dir_remove(parent, name_of(cnp)) {
        return err(e);
    }
    let mut inode = fs.read_inode(target);
    inode.nlink = inode.nlink.saturating_sub(1);
    fs.write_inode(target, inode);
    fs.maybe_release(target);
    0
}

extern "C" fn oxfs_vop_rmdir(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let fs = fs_of(dvp);
    let (parent, target) = (inode_of(dvp), inode_of(vp));
    if fs.dir_entry_count(target) > 2 {
        return VFS_ENOTEMPTY;
    }
    if let Err(e) = fs.dir_remove(parent, name_of(cnp)) {
        return err(e);
    }
    let mut dir = fs.read_inode(target);
    dir.nlink = 0;
    fs.write_inode(target, dir);
    fs.maybe_release(target);
    0
}

extern "C" fn oxfs_vop_link(tdvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    let fs = fs_of(tdvp);
    let (parent, n) = (inode_of(tdvp), inode_of(vp));
    let mut inode = fs.read_inode(n);
    if inode.nlink == u16::MAX {
        return VFS_EMLINK;
    }
    if let Err(e) = fs.dir_insert(parent, name_of(cnp), n) {
        return err(e);
    }
    inode.nlink += 1;
    fs.write_inode(n, inode);
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
    let fs = fs_of(fdvp);
    let (old_parent, target, new_parent) = (inode_of(fdvp), inode_of(fvp), inode_of(tdvp));
    let (old_leaf, new_leaf) = (name_of(fcnp), name_of(tcnp));
    let is_dir = fs.read_inode(target).kind == InodeKind::Dir;
    let existing = if tvp.is_null() { None } else { Some(inode_of(tvp)) };
    if let Some(existing) = existing {
        let existing_is_dir = fs.read_inode(existing).kind == InodeKind::Dir;
        if existing_is_dir && fs.dir_entry_count(existing) > 2 {
            return VFS_ENOTEMPTY;
        }
        let _ = fs.dir_remove(new_parent, new_leaf);
        let mut replaced = fs.read_inode(existing);
        replaced.nlink = if existing_is_dir { 0 } else { replaced.nlink.saturating_sub(1) };
        fs.write_inode(existing, replaced);
    }
    if fs.dir_remove(old_parent, old_leaf).is_err() {
        return VFS_EIO;
    }
    if let Err(e) = fs.dir_insert(new_parent, new_leaf, target) {
        let _ = fs.dir_insert(old_parent, old_leaf, target);
        return err(e);
    }
    if is_dir && new_parent != old_parent {
        let _ = fs.dir_remove(target, b"..");
        if let Err(e) = fs.dir_insert(target, b"..", new_parent) {
            return err(e);
        }
    }
    if let Some(existing) = existing {
        fs.maybe_release(existing);
    }
    0
}

extern "C" fn oxfs_vop_readdir(vp: *mut Vnode, uio: u64, _cred: *const Ucred, eofflag: *mut i32) -> i64 {
    let fs = fs_of(vp);
    let dir = inode_of(vp);
    // SAFETY: kernel exports, called as declared.
    let mut cursor = unsafe { oxidebsd_uio_offset(uio) } as usize;
    let mut record = [0u8; dirent_reclen(NAME_MAX)];
    let mut written = 0i64;
    let mut eof = true;
    while let Some((child, name, name_len)) = fs.dir_nth_used_record(dir, cursor) {
        let name = &name[..name_len as usize];
        let reclen = dirent_reclen(name.len());
        if uio_resid(uio) < reclen {
            eof = false;
            break;
        }
        let c = fs.read_inode(child);
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
    let fs = fs_of(vp);
    let mut target = [0u8; OXFS_PATH_MAX];
    let cap = uio_resid(uio).min(target.len());
    let n = fs.read_inode_at(inode_of(vp), 0, &mut target[..cap]);
    match uio_out(uio, &target[..n]) {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

// --- Attributes and contents --------------------------------------------------------------------

extern "C" fn oxfs_vop_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    let fs = fs_of(vp);
    let n = inode_of(vp);
    let st = fs.inode_stat(n);
    let inode = fs.read_inode(n);
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
    let fs = fs_of(vp);
    let n = inode_of(vp);
    let va = vattr(vap);
    // SAFETY: kernel export.
    let now = unsafe { oxidebsd_unix_time() };
    if va.va_size != VNOVAL {
        if fs.read_inode(n).kind == InodeKind::Dir {
            return VFS_EISDIR;
        }
        if !fs.resize_inode_data(n, va.va_size as usize) {
            return VFS_ENOSPC;
        }
    }
    let mut inode = fs.read_inode(n);
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
        fs.write_inode(n, inode);
    }
    0
}

extern "C" fn oxfs_vop_read(vp: *mut Vnode, uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    let fs = fs_of(vp);
    let n = inode_of(vp);
    // SAFETY: kernel export.
    let offset = unsafe { oxidebsd_uio_offset(uio) } as usize;
    match fs.read_inode_uio(n, offset, uio) {
        Ok(moved) => {
            if moved > 0 {
                fs.touch_atime(n);
            }
            moved as i64
        }
        Err(e) => e,
    }
}

extern "C" fn oxfs_vop_write(vp: *mut Vnode, uio: u64, ioflag: u32, cred: *const Ucred) -> i64 {
    let fs = fs_of(vp);
    let n = inode_of(vp);
    if ioflag & IO_APPEND != 0 {
        // SAFETY: kernel export.
        unsafe { oxidebsd_uio_set_offset(uio, fs.read_inode(n).size) };
    }
    if uio_resid(uio) == 0 {
        return 0;
    }
    // A write by anyone but root clears the set-user-ID and set-group-ID bits (POSIX allows it,
    // the BSDs do it), so a writable set-ID program can't be swapped for another.
    // SAFETY: the kernel's credentials.
    if unsafe { (*cred).cr_uid } != 0 {
        let mut inode = fs.read_inode(n);
        if inode.mode & SETID_BITS != 0 {
            inode.mode &= !SETID_BITS;
            fs.write_inode(n, inode);
        }
    }
    // SAFETY: kernel export.
    let offset = unsafe { oxidebsd_uio_offset(uio) } as usize;
    uio_ret(fs.write_inode_uio(n, offset, uio))
}

extern "C" fn oxfs_vop_fsync(vp: *mut Vnode, _waitfor: i32, _data_only: u32) -> i32 {
    let fs = fs_of(vp);
    fs.sync_file(inode_of(vp));
    0
}

/// The last use of the file went: an unlinked file's storage goes now.
extern "C" fn oxfs_vop_inactive(vp: *mut Vnode) -> i32 {
    let fs = fs_of(vp);
    fs.maybe_release(inode_of(vp));
    0
}

extern "C" fn oxfs_vop_allocate(vp: *mut Vnode, offset: u64, len: u64) -> i32 {
    let fs = fs_of(vp);
    let n = inode_of(vp);
    let target = offset.saturating_add(len) as usize;
    if fs.read_inode(n).size as usize >= target {
        return 0;
    }
    if fs.resize_inode_data(n, target) { 0 } else { VFS_ENOSPC }
}

/// File block `lblkno` to its sector on the disk, and how many blocks after it follow contiguously
/// (`DEMANDPAGE.md` §5.1): the page cache fills mapped pages from the device with it. A block past
/// the end has none (a hole).
extern "C" fn oxfs_vop_bmap(vp: *mut Vnode, lblkno: u64, bnp: *mut u64, runp: *mut u64) -> i32 {
    let fs = fs_of(vp);
    let n = inode_of(vp);
    let record = fs.read_inode(n);
    let device = |index: usize| -> Option<u64> {
        let block = fs.inode_block_at(&record, index)?;
        Some(fs.data_block_offset as u64 + block as u64)
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

