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
    if ROOTVNODE.load(Ordering::Acquire).is_null() {
        if name_of(vfc) == root_fstype().as_bytes() {
            return mountroot(vfc);
        }
    } else {
        automount_type(vfc);
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
        from_vp: ptr::null_mut(),
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
    automount();
    0
}

/// Mounts registered synthetic types on their directories once the root is up (FreeBSD mounts
/// devfs in `vfs_mountroot`): devfs on `/dev`, procfs on `/proc`, whichever are registered now;
/// one that registers later is mounted then (`register`).
fn automount() {
    for name in [&b"devfs"[..], b"procfs"] {
        if let Some(vfc) = find_type(name) {
            automount_type(vfc);
        }
    }
}

fn automount_type(vfc: &'static VfsConf) {
    // procfs is read-only: nothing in it can be made, removed or renamed (`EROFS`).
    let (path, from, flags): (&[u8], &[u8], u64) = match name_of(vfc) {
        b"devfs" => (b"/dev", b"devfs", 0),
        b"procfs" => (b"/proc", b"procfs", MNT_RDONLY),
        _ => return,
    };
    let cred = crate::kern::vfs_subr::current_ucred();
    let nd = crate::kern::vfs_lookup::NameiData {
        path,
        nameiop: LOOKUP,
        follow: true,
        startdir: ptr::null_mut(),
        cred: &cred,
    };
    let covered = match crate::kern::vfs_lookup::namei(&nd) {
        Ok(ni) => ni.into_vp(),
        Err(_) => {
            crate::serial_println!("[vfs] no {} to mount {} on", core::str::from_utf8(path).unwrap_or("?"), core::str::from_utf8(from).unwrap_or("?"));
            return;
        }
    };
    // Already mounted (the root's /dev crossed to it): nothing to do.
    // SAFETY: referenced.
    if unsafe { (*covered).v_flag } & VV_ROOT != 0 && unsafe { (*covered).v_mount } != unsafe { (*rootvnode()).v_mount } {
        crate::kern::vfs_subr::vrele(covered);
        return;
    }
    if let Err(e) = domount(vfc, covered, flags, path, from, ptr::null_mut()) {
        crate::serial_println!("[vfs] mounting {} failed: {}", core::str::from_utf8(from).unwrap_or("?"), e);
    }
}

/// Mounts `vfc` on directory `covered` (referenced; the mount keeps the reference): `nmount(2)`'s
/// work once its options are parsed. `onname` is the path as given, `fromname` what it's from.
pub(crate) fn domount(
    vfc: &'static VfsConf,
    covered: *mut Vnode,
    flags: u64,
    onname: &[u8],
    fromname: &[u8],
    from_vp: *mut Vnode,
) -> Result<(), i32> {
    let Some(mount) = (unsafe { (*vfc.ops).mount }) else {
        crate::kern::vfs_subr::vrele(covered);
        return Err(EOPNOTSUPP);
    };
    let mp = match mount_alloc(vfc, flags, NODEV, onname, fromname) {
        Ok(mp) => mp,
        Err(e) => {
            crate::kern::vfs_subr::vrele(covered);
            return Err(e);
        }
    };
    let args = MountArgs {
        from: fromname.as_ptr(),
        from_len: fromname.len(),
        dev: NODEV,
        opts: ptr::null(),
        opts_len: 0,
        from_vp,
    };
    let e = {
        let _giant = fslock::Giant::enter();
        mount(mp, &args)
    };
    if e != 0 {
        mount_free(mp);
        crate::kern::vfs_subr::vrele(covered);
        return Err(e);
    }
    let root = match vfs_root(mp) {
        Ok(vp) => vp,
        Err(e) => {
            mount_free(mp);
            crate::kern::vfs_subr::vrele(covered);
            return Err(e);
        }
    };
    // SAFETY: referenced vnodes; `mp` is ours until it's on the list.
    unsafe {
        (*root).v_flag |= VV_ROOT;
        (*mp).mnt_vnodecovered = covered;
        (*covered).v_mountedhere = mp;
    }
    crate::kern::vfs_subr::vrele(root);
    MOUNTS.lock().push(mp as usize);
    Ok(())
}

/// Unmounts `mp` (`dounmount`): `EBUSY` while a vnode of it is in use or a mount sits on it, `EINVAL`
/// for the root.
pub(crate) fn dounmount(mp: *mut Mount, flags: u64) -> Result<(), i32> {
    const EBUSY: i32 = 16;
    const EINVAL: i32 = 22;
    // SAFETY: a mounted mount.
    let covered = unsafe { (*mp).mnt_vnodecovered };
    if covered.is_null() {
        return Err(EINVAL);
    }
    let stacked = mounts().into_iter().any(|m| {
        // SAFETY: mounted mounts.
        let c = unsafe { (*m).mnt_vnodecovered };
        !c.is_null() && unsafe { (*c).v_mount } == mp
    });
    if stacked || crate::kern::vfs_subr::vflush(mp) != 0 {
        return Err(EBUSY);
    }
    vfs_sync(mp, MNT_WAIT);
    if let Some(unmount) = ops(mp).unmount {
        let _giant = fslock::Giant::enter();
        let e = unmount(mp, flags);
        if e != 0 {
            return Err(e);
        }
    }
    // SAFETY: as above; nothing else refers to `mp` now.
    unsafe { (*covered).v_mountedhere = ptr::null_mut() };
    crate::kern::vfs_subr::vrele(covered);
    MOUNTS.lock().retain(|&m| m != mp as usize);
    mount_free(mp);
    Ok(())
}

/// `mount -u /`: the root's read-only state, through its type's `mount` with `MNT_UPDATE`.
pub(crate) fn update_root(rdonly: bool) -> Result<(), i32> {
    let root = rootvnode();
    if root.is_null() {
        return Err(EOPNOTSUPP);
    }
    // SAFETY: the root vnode and its mount live for good.
    let mp = unsafe { (*root).v_mount };
    let Some(mount) = ops(mp).mount else { return Err(EOPNOTSUPP) };
    let old = unsafe { (*mp).mnt_flag };
    if rdonly && old & MNT_RDONLY == 0 && crate::fs::fd::writers_on(mp) {
        return Err(16); // EBUSY
    }
    let new = (old & !MNT_RDONLY) | MNT_UPDATE | if rdonly { MNT_RDONLY } else { 0 };
    // SAFETY: as above.
    unsafe { (*mp).mnt_flag = new };
    let args = MountArgs {
        from: ptr::null(),
        from_len: 0,
        dev: unsafe { (*mp).mnt_dev },
        opts: ptr::null(),
        opts_len: 0,
        from_vp: ptr::null_mut(),
    };
    let e = {
        let _giant = fslock::Giant::enter();
        mount(mp, &args)
    };
    // SAFETY: as above.
    unsafe { (*mp).mnt_flag = if e == 0 { new & !MNT_UPDATE } else { old } };
    if e != 0 { Err(e) } else { Ok(()) }
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

fn name_bytes(field: &[u8; MNAMELEN]) -> &[u8] {
    let n = field.iter().position(|&b| b == 0).unwrap_or(MNAMELEN);
    &field[..n]
}

/// `/proc/mounts` (Linux's `fstab`-like shape, which `mount(8)` without arguments and scripts
/// read): `from on type options 0 0` per mount, in mount order. Exported to procfs; the length
/// written, cut at `cap`.
pub(crate) extern "C" fn oxidebsd_mounts_render(buf: *mut u8, cap: u64) -> i64 {
    let mut out = Vec::new();
    for mp in mounts() {
        // SAFETY: mounted mounts and their registered types.
        let (vfc, flags, from, on) = unsafe { (&*(*mp).mnt_vfc, (*mp).mnt_flag, &(*mp).mnt_fromname, &(*mp).mnt_onname) };
        let from = name_bytes(from);
        out.extend_from_slice(if from.is_empty() { name_of(vfc) } else { from });
        out.push(b' ');
        out.extend_from_slice(name_bytes(on));
        out.push(b' ');
        out.extend_from_slice(name_of(vfc));
        out.extend_from_slice(if flags & MNT_RDONLY != 0 { b" ro" } else { b" rw" });
        if flags & MNT_NOSUID != 0 {
            out.extend_from_slice(b",nosuid");
        }
        if flags & MNT_WXALLOWED != 0 {
            out.extend_from_slice(b",wxallowed");
        }
        out.extend_from_slice(b" 0 0\n");
    }
    let n = out.len().min(cap as usize);
    // SAFETY: procfs passes a buffer of `cap` bytes.
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), buf, n) };
    n as i64
}
