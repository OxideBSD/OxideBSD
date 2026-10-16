//! File system types and mounts (OxideBSD-doc `VFS.md` §4): the registry of types modules
//! register (FreeBSD's `vfs_init.c`), `struct mount`s in mount order, mounting the root when its
//! type arrives (`vfs_mountroot`), `sync(2)` over every mount and the unmount at shutdown
//! (`vfs_unmountall`). FreeBSD's `vfs_mount.c` in miniature.
//!
//! A mount is kernel memory (`Box<Mount>`) with the type's private data beside it (`mnt_data`).
//! The list holds them in mount order: the root first.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use spin::Mutex;
use vfs_if::*;

use crate::fs::fslock;

const EEXIST: i32 = 17;
const ENOMEM: i32 = 12;
const EOPNOTSUPP: i32 = 95;

/// Registered types, in registration order (FreeBSD's `vfsconf` list; `f_type` is the index + 1).
static TYPES: Mutex<Vec<usize>> = Mutex::new(Vec::new());
/// Every mount, in mount order.
static MOUNTS: Mutex<Vec<usize>> = Mutex::new(Vec::new());
/// The root file system's root directory (FreeBSD's `rootvnode`), referenced for good.
static ROOTVNODE: AtomicPtr<Vnode> = AtomicPtr::new(ptr::null_mut());
/// The next file system ID to hand out: `st_dev` of every file of a mount. The root's is 1, as
/// oxfs's disk files reported before the VFS (`2` was tmpfs's and devfs's shared one).
static NEXT_FSID: AtomicU64 = AtomicU64::new(1);

fn name_of(vfc: &VfsConf) -> &[u8] {
    // SAFETY: a registered type's name is a static string.
    unsafe { core::slice::from_raw_parts(vfc.name, vfc.name_len) }
}

/// The registered type named `name`.
pub(crate) fn find_type(name: &[u8]) -> Option<&'static VfsConf> {
    // SAFETY: registered types are statics.
    TYPES.lock().iter().map(|&v| unsafe { &*(v as *const VfsConf) }).find(|v| name_of(v) == name)
}

/// `f_type` of a type: its registration order, from 1.
fn type_number(vfc: *const VfsConf) -> u32 {
    TYPES.lock().iter().position(|&v| v == vfc as usize).map_or(0, |i| i as u32 + 1)
}

/// The root file system's type as `/boot/fsconf` names it; `oxfs` without one.
fn root_fstype() -> alloc::string::String {
    crate::kern::fsconf::root_entry().map_or_else(|| alloc::string::String::from("oxfs"), |e| e.fs_type)
}

/// `vfs_register`: adds `vfc`, and mounts the root through it if it's the root's type and no root
/// is mounted yet.
pub(crate) fn register(vfc: &'static VfsConf) -> i32 {
    if find_type(name_of(vfc)).is_some() {
        return EEXIST;
    }
    TYPES.lock().push(vfc as *const VfsConf as usize);
    if ROOTVNODE.load(Ordering::Acquire).is_null() && name_of(vfc) == root_fstype().as_bytes() {
        return mountroot(vfc);
    }
    0
}

fn data_layout(size: usize) -> Layout {
    Layout::from_size_align(size.max(1), 16).expect("mnt_data layout")
}

fn copy_name(dst: &mut [u8; MNAMELEN], src: &[u8]) {
    let n = src.len().min(MNAMELEN - 1);
    dst[..n].copy_from_slice(&src[..n]);
}

/// A new mount of `vfc` (FreeBSD's `vfs_mount_alloc`), not yet on the list.
fn mount_alloc(vfc: &'static VfsConf, flags: u64, dev: u64, onname: &[u8], fromname: &[u8]) -> Result<*mut Mount, i32> {
    // SAFETY: a nonzero-size layout.
    let data = unsafe { alloc_zeroed(data_layout(vfc.mnt_data_size)) };
    if data.is_null() {
        return Err(ENOMEM);
    }
    let mut mp = Box::new(Mount {
        mnt_vfc: vfc,
        mnt_flag: flags,
        mnt_data: data as *mut c_void,
        mnt_vnodecovered: ptr::null_mut(),
        mnt_dev: dev,
        mnt_fsid: NEXT_FSID.fetch_add(1, Ordering::Relaxed),
        mnt_nvnodes: 0,
        mnt_onname: [0; MNAMELEN],
        mnt_fromname: [0; MNAMELEN],
    });
    copy_name(&mut mp.mnt_onname, onname);
    copy_name(&mut mp.mnt_fromname, fromname);
    Ok(Box::into_raw(mp))
}

fn mount_free(mp: *mut Mount) {
    // SAFETY: `mp` came from `mount_alloc` and nothing references it any more.
    unsafe {
        let size = (*(*mp).mnt_vfc).mnt_data_size;
        dealloc((*mp).mnt_data as *mut u8, data_layout(size));
        drop(Box::from_raw(mp));
    }
}

fn ops(mp: *mut Mount) -> &'static VfsOps {
    // SAFETY: a live mount's type and its ops are registered statics.
    unsafe { &*(*(*mp).mnt_vfc).ops }
}

/// `VFS_ROOT`.
pub(crate) fn vfs_root(mp: *mut Mount) -> Result<*mut Vnode, i32> {
    let Some(root) = ops(mp).root else { return Err(EOPNOTSUPP) };
    let mut vp = ptr::null_mut();
    let e = {
        let _lock = fslock::Guard::for_call(root as usize as u64);
        root(mp, &mut vp)
    };
    if e != 0 { Err(e) } else { Ok(vp) }
}

/// `VFS_SYNC`.
pub(crate) fn vfs_sync(mp: *mut Mount, waitfor: i32) -> i32 {
    let Some(sync) = ops(mp).sync else { return 0 };
    let _lock = fslock::Guard::for_call_sleepable(sync as usize as u64);
    sync(mp, waitfor)
}

/// `VFS_STATFS`, with the kernel's fields filled.
pub(crate) fn vfs_statfs(mp: *mut Mount) -> Result<Statfs, i32> {
    let mut sb = Statfs::ZERO;
    if let Some(statfs) = ops(mp).statfs {
        let e = {
            let _lock = fslock::Guard::for_call(statfs as usize as u64);
            statfs(mp, &mut sb)
        };
        if e != 0 {
            return Err(e);
        }
    }
    // SAFETY: `mp` is live.
    unsafe {
        sb.f_type = type_number((*mp).mnt_vfc);
        sb.f_flags = (*mp).mnt_flag;
        sb.f_fsid = (*mp).mnt_fsid;
    }
    Ok(sb)
}

/// Mounts the root through `vfc` (FreeBSD's `vfs_mountroot`): the boot device, read-only unless
/// the kernel was told otherwise (`/etc/rc` remounts it read-write).
fn mountroot(vfc: &'static VfsConf) -> i32 {
    let Some(mount) = (unsafe { (*vfc.ops).mount }) else { return EOPNOTSUPP };
    let dev = crate::kern::vfs_bdev::root().map_or(NODEV, |h| h as u64);
    let rdonly = crate::drivers::disk::oxidebsd_root_readonly_at_boot() != 0;
    let from = crate::kern::fsconf::root_entry().map(|e| e.device).unwrap_or_default();
    let flags = MNT_ROOTFS | if rdonly { MNT_RDONLY } else { 0 };
    let mp = match mount_alloc(vfc, flags, dev, b"/", from.as_bytes()) {
        Ok(mp) => mp,
        Err(e) => return e,
    };
    let args = MountArgs {
        from: from.as_ptr(),
        from_len: from.len(),
        dev,
        opts: ptr::null(),
        opts_len: 0,
    };
    let e = {
        let _lock = fslock::Guard::for_call(mount as usize as u64);
        mount(mp, &args)
    };
    if e != 0 {
        mount_free(mp);
        return e;
    }
    let root = match vfs_root(mp) {
        Ok(vp) => vp,
        Err(e) => {
            mount_free(mp);
            return e;
        }
    };
    // SAFETY: a referenced vnode.
    unsafe { (*root).v_flag |= VV_ROOT };
    MOUNTS.lock().push(mp as usize);
    ROOTVNODE.store(root, Ordering::Release);
    0
}

/// The root directory of the whole system, if the root is mounted.
pub(crate) fn rootvnode() -> *mut Vnode {
    ROOTVNODE.load(Ordering::Acquire)
}

/// Every mount, in mount order.
pub(crate) fn mounts() -> Vec<*mut Mount> {
    MOUNTS.lock().iter().map(|&m| m as *mut Mount).collect()
}

/// `sync(2)`: every mount's delayed writes go to its device before this returns (POSIX lets
/// `sync` return early; OxideBSD doesn't, since `update(8)` and shutdown rely on it).
pub(crate) fn sync_all() {
    for mp in mounts() {
        vfs_sync(mp, MNT_WAIT);
    }
}

/// Unmounts everything at shutdown, the last mounted first (FreeBSD's `vfs_unmountall`): each
/// file system writes what's delayed and marks itself clean. Processes still hold vnodes, which
/// stay; nothing runs after this but the reset.
pub(crate) fn unmount_all() {
    for mp in mounts().into_iter().rev() {
        vfs_sync(mp, MNT_WAIT);
        if let Some(unmount) = ops(mp).unmount {
            let _lock = fslock::Guard::for_call(unmount as usize as u64);
            unmount(mp, MNT_FORCE);
        }
    }
}

// --- Exports -------------------------------------------------------------------------------------

pub(crate) extern "C" fn oxidebsd_vfs_register(vfc: *const VfsConf) -> i32 {
    // SAFETY: a module passes its static `VfsConf`.
    register(unsafe { &*vfc })
}

/// `sync(2)`, registered by the `vfs` module.
pub(crate) extern "C" fn oxidebsd_sys_sync(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    sync_all();
    0
}
