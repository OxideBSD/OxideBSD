//! nullfs (OxideBSD-doc `VFS.md` §8.1, `nullfs(5)`): a directory of any mounted file system seen
//! again at another place, FreeBSD's nullfs.
//!
//! Each vnode of a nullfs mount stands for one vnode of the lower file system (`NullNode`, in
//! `v_data`): it keeps that one referenced, and every operation goes on to it through the kernel's
//! vnode operation calls (`oxidebsd_vop_*`), never to another module directly. One lower vnode has
//! one upper vnode per mount: the kernel's vnode hash, keyed by the lower vnode's address, which is
//! stable while it's referenced. The file's contents are the lower vnode's (`v_lower`, VFS.md §13):
//! the page cache, mappings, FIFOs and sockets name it by that one.
//!
//! A nullfs mount has flags of its own (`ro`, `nosuid`, `noexec`), which the kernel applies to it,
//! whatever the lower mount's. Lookups aren't kept in the name cache (`VFCF_NOCACHE`): a name may
//! change through the lower path behind this mount's back.
#![no_std]

extern crate alloc;
use kern_mod as _;

use core::ptr;

use vfs_if::*;

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_module_serialize();
    fn oxidebsd_vfs_statfs(mp: *mut Mount, sbp: *mut Statfs) -> i32;
    fn oxidebsd_vop_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32;
    fn oxidebsd_vop_create(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32;
    fn oxidebsd_vop_mknod(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32;
    fn oxidebsd_vop_mkdir(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32;
    fn oxidebsd_vop_symlink(
        dvp: *mut Vnode,
        vpp: *mut *mut Vnode,
        cnp: *const ComponentName,
        vap: *const Vattr,
        target: *const u8,
        target_len: usize,
    ) -> i32;
    fn oxidebsd_vop_open(vp: *mut Vnode, fflag: u32, cred: *const Ucred) -> i32;
    fn oxidebsd_vop_close(vp: *mut Vnode, fflag: u32, cred: *const Ucred) -> i32;
    fn oxidebsd_vop_access(vp: *mut Vnode, accmode: u32, cred: *const Ucred) -> i32;
    fn oxidebsd_vop_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32;
    fn oxidebsd_vop_setattr(vp: *mut Vnode, vap: *const Vattr, cred: *const Ucred) -> i32;
    fn oxidebsd_vop_read(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: *const Ucred) -> i64;
    fn oxidebsd_vop_write(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: *const Ucred) -> i64;
    fn oxidebsd_vop_ioctl(vp: *mut Vnode, cmd: u64, data: u64, fflag: u32, cred: *const Ucred) -> i32;
    fn oxidebsd_vop_fsync(vp: *mut Vnode, waitfor: i32, data_only: u32) -> i32;
    fn oxidebsd_vop_remove(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32;
    fn oxidebsd_vop_link(tdvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32;
    fn oxidebsd_vop_rename(
        fdvp: *mut Vnode,
        fvp: *mut Vnode,
        fcnp: *const ComponentName,
        tdvp: *mut Vnode,
        tvp: *mut Vnode,
        tcnp: *const ComponentName,
    ) -> i32;
    fn oxidebsd_vop_rmdir(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32;
    fn oxidebsd_vop_readdir(vp: *mut Vnode, uio: Uio, cred: *const Ucred, eofflag: *mut i32) -> i64;
    fn oxidebsd_vop_readlink(vp: *mut Vnode, uio: Uio, cred: *const Ucred) -> i64;
    fn oxidebsd_vop_bmap(vp: *mut Vnode, lblkno: u64, bnp: *mut u64, runp: *mut u64) -> i32;
    fn oxidebsd_vop_allocate(vp: *mut Vnode, offset: u64, len: u64) -> i32;
}

const EIO: i32 = 5;
const EINVAL: i32 = 22;
const EXDEV: i32 = 18;

/// A nullfs mount's: the lower directory it shows, referenced while mounted (so the lower file
/// system can't be unmounted from under it: `EBUSY`).
#[repr(C)]
struct NullMount {
    lower_root: *mut Vnode,
}

/// An upper vnode's `v_data`: the lower vnode, referenced while the upper one lives.
#[repr(C)]
struct NullNode {
    lower: *mut Vnode,
}

fn nm(mp: *mut Mount) -> &'static mut NullMount {
    // SAFETY: `mnt_data` is a `NullMount` (`NULLFS_VFSCONF`); calls run under the giant lock.
    unsafe { &mut *((*mp).mnt_data as *mut NullMount) }
}

/// The lower vnode of upper vnode `vp`; null once reclaimed.
fn lower(vp: *mut Vnode) -> *mut Vnode {
    if vp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: an upper vnode's `v_data` is a `NullNode`.
    unsafe { (*((*vp).v_data as *mut NullNode)).lower }
}

fn mount_of(vp: *mut Vnode) -> *mut Mount {
    // SAFETY: the kernel's live vnode.
    unsafe { (*vp).v_mount }
}

fn log(s: &str) {
    // SAFETY: kernel export.
    unsafe { oxidebsd_log(s.as_ptr(), s.len() as u64) };
}

/// The upper vnode for lower vnode `lvp` (referenced by the caller, a reference this takes over),
/// referenced: the hash's if there is one (`lvp`'s reference then goes), else a new one keeping
/// it (FreeBSD's `null_nodeget`).
fn nodeget(mp: *mut Mount, lvp: *mut Vnode, vpp: *mut *mut Vnode) -> i32 {
    let key = lvp as u64;
    // SAFETY: kernel exports, called as declared; `lvp` is referenced.
    unsafe {
        let vp = oxidebsd_vfs_hash_get(mp, key);
        if !vp.is_null() {
            oxidebsd_vrele(lvp);
            *vpp = vp;
            return 0;
        }
        let mut vp = ptr::null_mut();
        let e = oxidebsd_getnewvnode(mp, (*lvp).v_type, key, &mut vp);
        if e != 0 {
            oxidebsd_vrele(lvp);
            return e;
        }
        (*((*vp).v_data as *mut NullNode)).lower = lvp;
        (*vp).v_rdev = (*lvp).v_rdev;
        if lvp == nm(mp).lower_root {
            (*vp).v_flag |= VV_ROOT;
        }
        // The contents are the lower file's (or the one it shows, for a nullfs over a nullfs).
        let object = if (*lvp).v_lower.is_null() { lvp } else { (*lvp).v_lower };
        oxidebsd_vhold(object);
        (*vp).v_lower = object;
        oxidebsd_vfs_hash_insert(vp);
        *vpp = vp;
    }
    0
}

/// Wraps an operation's new lower vnode (`lvp`, when `e == 0`) as an upper one in `*vpp`.
fn wrap(mp: *mut Mount, e: i32, lvp: *mut Vnode, vpp: *mut *mut Vnode) -> i32 {
    if e != 0 {
        return e;
    }
    nodeget(mp, lvp, vpp)
}

// --- vfsops -------------------------------------------------------------------------------------

static NULLFS_VFSOPS: VfsOps = VfsOps {
    mount: Some(nullfs_mount),
    unmount: Some(nullfs_unmount),
    root: Some(nullfs_root),
    statfs: Some(nullfs_statfs),
    sync: None,
    vget: None,
};

static NULLFS_VFSCONF: VfsConf = VfsConf {
    name: b"nullfs".as_ptr(),
    name_len: 6,
    ops: &NULLFS_VFSOPS,
    vops: &NULLFS_VOPS,
    mnt_data_size: core::mem::size_of::<NullMount>(),
    v_data_size: core::mem::size_of::<NullNode>(),
    flags: VFCF_FROM_VNODE | VFCF_NOCACHE,
};

extern "C" fn nullfs_mount(mp: *mut Mount, args: *const MountArgs) -> i32 {
    // SAFETY: the kernel's mount and arguments, live for the call.
    let (update, has_opts, from) = unsafe { ((*mp).mnt_flag & MNT_UPDATE != 0, (*args).opts_len != 0, (*args).from_vp) };
    if has_opts {
        return EINVAL;
    }
    if update {
        return 0;
    }
    if from.is_null() {
        return EINVAL;
    }
    // SAFETY: referenced by the kernel for the call; kept until unmount.
    unsafe { oxidebsd_vref(from) };
    nm(mp).lower_root = from;
    0
}

extern "C" fn nullfs_unmount(mp: *mut Mount, _flags: u64) -> i32 {
    let root = nm(mp).lower_root;
    if !root.is_null() {
        // SAFETY: the reference `nullfs_mount` took.
        unsafe { oxidebsd_vrele(root) };
        nm(mp).lower_root = ptr::null_mut();
    }
    0
}

extern "C" fn nullfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    let root = nm(mp).lower_root;
    // A lower file system forcibly unmounted: its directory (still held) is doomed.
    // SAFETY: held while mounted.
    if root.is_null() || unsafe { (*root).v_flag } & VI_DOOMED != 0 {
        return EIO;
    }
    // SAFETY: kernel export; `nodeget` takes this reference over.
    unsafe { oxidebsd_vref(root) };
    nodeget(mp, root, vpp)
}

/// The lower file system's counts.
extern "C" fn nullfs_statfs(mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    let root = nm(mp).lower_root;
    if root.is_null() {
        return EIO;
    }
    // SAFETY: held while mounted; kernel export with the kernel's record.
    unsafe { oxidebsd_vfs_statfs((*root).v_mount, sbp) }
}

// --- Vnode operations: each the lower vnode's ------------------------------------------------------

static NULLFS_VOPS: VopVector = VopVector {
    lookup: Some(null_lookup),
    create: Some(null_create),
    mknod: Some(null_mknod),
    open: Some(null_open),
    close: Some(null_close),
    access: Some(null_access),
    getattr: Some(null_getattr),
    setattr: Some(null_setattr),
    read: Some(null_read),
    write: Some(null_write),
    ioctl: Some(null_ioctl),
    fsync: Some(null_fsync),
    remove: Some(null_remove),
    link: Some(null_link),
    rename: Some(null_rename),
    mkdir: Some(null_mkdir),
    rmdir: Some(null_rmdir),
    symlink: Some(null_symlink),
    readdir: Some(null_readdir),
    readlink: Some(null_readlink),
    inactive: Some(null_inactive),
    reclaim: Some(null_reclaim),
    bmap: Some(null_bmap),
    allocate: Some(null_allocate),
    ..VopVector::DEFAULT
};

extern "C" fn null_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32 {
    let mut lvp = ptr::null_mut();
    // SAFETY: kernel export; `dvp`'s lower vnode is referenced by it.
    let e = unsafe { oxidebsd_vop_lookup(lower(dvp), cnp, &mut lvp) };
    wrap(mount_of(dvp), e, lvp, vpp)
}

macro_rules! forward_new {
    ($name:ident, $call:ident) => {
        extern "C" fn $name(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32 {
            let mut lvp = ptr::null_mut();
            // SAFETY: kernel export, with the lower directory.
            let e = unsafe { $call(lower(dvp), &mut lvp, cnp, vap) };
            wrap(mount_of(dvp), e, lvp, vpp)
        }
    };
}

forward_new!(null_create, oxidebsd_vop_create);
forward_new!(null_mknod, oxidebsd_vop_mknod);
forward_new!(null_mkdir, oxidebsd_vop_mkdir);

extern "C" fn null_symlink(
    dvp: *mut Vnode,
    vpp: *mut *mut Vnode,
    cnp: *const ComponentName,
    vap: *const Vattr,
    target: *const u8,
    target_len: usize,
) -> i32 {
    let mut lvp = ptr::null_mut();
    // SAFETY: kernel export, with the lower directory.
    let e = unsafe { oxidebsd_vop_symlink(lower(dvp), &mut lvp, cnp, vap, target, target_len) };
    wrap(mount_of(dvp), e, lvp, vpp)
}

extern "C" fn null_open(vp: *mut Vnode, fflag: u32, cred: *const Ucred) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_open(lower(vp), fflag, cred) }
}

extern "C" fn null_close(vp: *mut Vnode, fflag: u32, cred: *const Ucred) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_close(lower(vp), fflag, cred) }
}

extern "C" fn null_access(vp: *mut Vnode, accmode: u32, cred: *const Ucred) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_access(lower(vp), accmode, cred) }
}

extern "C" fn null_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    // SAFETY: kernel export. The kernel puts this mount's `st_dev` in it.
    unsafe { oxidebsd_vop_getattr(lower(vp), vap) }
}

extern "C" fn null_setattr(vp: *mut Vnode, vap: *const Vattr, cred: *const Ucred) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_setattr(lower(vp), vap, cred) }
}

extern "C" fn null_read(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: *const Ucred) -> i64 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_read(lower(vp), uio, ioflag, cred) }
}

extern "C" fn null_write(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: *const Ucred) -> i64 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_write(lower(vp), uio, ioflag, cred) }
}

extern "C" fn null_ioctl(vp: *mut Vnode, cmd: u64, data: u64, fflag: u32, cred: *const Ucred) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_ioctl(lower(vp), cmd, data, fflag, cred) }
}

extern "C" fn null_fsync(vp: *mut Vnode, waitfor: i32, data_only: u32) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_fsync(lower(vp), waitfor, data_only) }
}

/// Every vnode a two-vnode operation is given is this mount's (the kernel refuses `EXDEV`
/// across mounts first); their lower vnodes are then all of the lower mount.
fn ours(mp: *mut Mount, vp: *mut Vnode) -> bool {
    vp.is_null() || mount_of(vp) == mp
}

extern "C" fn null_remove(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_remove(lower(dvp), lower(vp), cnp) }
}

extern "C" fn null_rmdir(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_rmdir(lower(dvp), lower(vp), cnp) }
}

extern "C" fn null_link(tdvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32 {
    if !ours(mount_of(tdvp), vp) {
        return EXDEV;
    }
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_link(lower(tdvp), lower(vp), cnp) }
}

extern "C" fn null_rename(
    fdvp: *mut Vnode,
    fvp: *mut Vnode,
    fcnp: *const ComponentName,
    tdvp: *mut Vnode,
    tvp: *mut Vnode,
    tcnp: *const ComponentName,
) -> i32 {
    let mp = mount_of(fdvp);
    if !(ours(mp, fvp) && ours(mp, tdvp) && ours(mp, tvp)) {
        return EXDEV;
    }
    // SAFETY: kernel export, with the lower vnodes (a null `tvp` stays null).
    unsafe { oxidebsd_vop_rename(lower(fdvp), lower(fvp), fcnp, lower(tdvp), lower(tvp), tcnp) }
}

extern "C" fn null_readdir(vp: *mut Vnode, uio: Uio, cred: *const Ucred, eofflag: *mut i32) -> i64 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_readdir(lower(vp), uio, cred, eofflag) }
}

extern "C" fn null_readlink(vp: *mut Vnode, uio: Uio, cred: *const Ucred) -> i64 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_readlink(lower(vp), uio, cred) }
}

extern "C" fn null_bmap(vp: *mut Vnode, lblkno: u64, bnp: *mut u64, runp: *mut u64) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_bmap(lower(vp), lblkno, bnp, runp) }
}

extern "C" fn null_allocate(vp: *mut Vnode, offset: u64, len: u64) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vop_allocate(lower(vp), offset, len) }
}

/// The last use of the upper vnode went: it's recycled at once, so it lets go of the lower one
/// (whose file may then go, if it was unlinked), as FreeBSD's `null_inactive`.
extern "C" fn null_inactive(vp: *mut Vnode) -> i32 {
    // SAFETY: kernel export.
    unsafe { oxidebsd_vfs_recycle(mount_of(vp), (*vp).v_fileid) };
    0
}

extern "C" fn null_reclaim(vp: *mut Vnode) -> i32 {
    // SAFETY: the kernel's vnode, being reclaimed; the references `nodeget` took.
    unsafe {
        let node = &mut *((*vp).v_data as *mut NullNode);
        if !node.lower.is_null() {
            oxidebsd_vrele(node.lower);
            node.lower = ptr::null_mut();
        }
        let object = (*vp).v_lower;
        if !object.is_null() {
            (*vp).v_lower = ptr::null_mut();
            oxidebsd_vdrop(object);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // SAFETY: kernel exports, with a static table.
    unsafe {
        oxidebsd_module_serialize();
        if oxidebsd_vfs_register(&NULLFS_VFSCONF) != 0 {
            log("[nullfs] registering the type failed\n");
            return -1;
        }
    }
    0
}
