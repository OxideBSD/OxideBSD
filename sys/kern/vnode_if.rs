//! Calling vnode operations (FreeBSD's generated `vnode_if.c`): one `VOP_*` function per entry of
//! `vfs_if::VopVector`, each taking the VFS's giant lock for the call (`fs::fslock::Giant`,
//! `VFS.md` §5.4) and supplying the kernel's default where the type left the entry null.
//!
//! Whether a call may sleep for the disk is the caller's context, not the operation's: system
//! calls may, and code that holds a spin lock or runs from a copy routine wraps itself in
//! `fslock::NoSleep` first.
//!
//! A doomed vnode (`VI_DOOMED`, revoked or reclaimed) never reaches its file system: every
//! operation on it is deadfs's (`EBADF`, reads at end of file).

use core::ptr;

use vfs_if::*;

use crate::fs::fslock;

pub(crate) const ENOENT: i32 = 2;
pub(crate) const EBADF: i32 = 9;
pub(crate) const EINVAL: i32 = 22;
pub(crate) const ENOTDIR: i32 = 20;
pub(crate) const EOPNOTSUPP: i32 = 95;
pub(crate) const ENOTTY: i32 = 25;

fn ops(vp: *mut Vnode) -> Option<&'static VopVector> {
    // SAFETY: the caller holds a reference to `vp`.
    let v = unsafe { &*vp };
    if v.v_flag & VI_DOOMED != 0 {
        return None;
    }
    // SAFETY: a live vnode's vector is a registered static.
    Some(unsafe { &*v.v_op })
}

/// Calls `$field` of `$vp`'s vector with the giant lock held, or evaluates `$default` (`$dead` for
/// a doomed vnode).
macro_rules! vop {
    ($vp:expr, $field:ident, $dead:expr, $default:expr, |$f:ident| $call:expr) => {{
        match ops($vp) {
            None => $dead,
            Some(v) => match v.$field {
                Some($f) => {
                    let _giant = fslock::Giant::enter();
                    $call
                }
                None => $default,
            },
        }
    }};
}

pub(crate) fn vop_lookup(dvp: *mut Vnode, cnp: &ComponentName) -> Result<*mut Vnode, i32> {
    let mut vp = ptr::null_mut();
    // A revoked directory (a cwd on a forcibly unmounted file system) has nothing in it.
    let e = vop!(dvp, lookup, ENOENT, ENOTDIR, |f| f(dvp, cnp, &mut vp));
    if e != 0 { Err(e) } else { Ok(vp) }
}

pub(crate) fn vop_create(dvp: *mut Vnode, cnp: &ComponentName, vap: &Vattr) -> Result<*mut Vnode, i32> {
    let mut vp = ptr::null_mut();
    let e = vop!(dvp, create, EBADF, EOPNOTSUPP, |f| f(dvp, &mut vp, cnp, vap));
    if e != 0 { Err(e) } else { Ok(vp) }
}

pub(crate) fn vop_mknod(dvp: *mut Vnode, cnp: &ComponentName, vap: &Vattr) -> Result<*mut Vnode, i32> {
    let mut vp = ptr::null_mut();
    let e = vop!(dvp, mknod, EBADF, EOPNOTSUPP, |f| f(dvp, &mut vp, cnp, vap));
    if e != 0 { Err(e) } else { Ok(vp) }
}

pub(crate) fn vop_mkdir(dvp: *mut Vnode, cnp: &ComponentName, vap: &Vattr) -> Result<*mut Vnode, i32> {
    let mut vp = ptr::null_mut();
    let e = vop!(dvp, mkdir, EBADF, EOPNOTSUPP, |f| f(dvp, &mut vp, cnp, vap));
    if e != 0 { Err(e) } else { Ok(vp) }
}

pub(crate) fn vop_symlink(dvp: *mut Vnode, cnp: &ComponentName, vap: &Vattr, target: &[u8]) -> Result<*mut Vnode, i32> {
    let mut vp = ptr::null_mut();
    let e = vop!(dvp, symlink, EBADF, EOPNOTSUPP, |f| f(dvp, &mut vp, cnp, vap, target.as_ptr(), target.len()));
    if e != 0 { Err(e) } else { Ok(vp) }
}

pub(crate) fn vop_open(vp: *mut Vnode, fflag: u32, cred: &Ucred) -> i32 {
    vop!(vp, open, EBADF, 0, |f| f(vp, fflag, cred))
}

pub(crate) fn vop_close(vp: *mut Vnode, fflag: u32, cred: &Ucred) -> i32 {
    vop!(vp, close, 0, 0, |f| f(vp, fflag, cred))
}

pub(crate) fn vop_getattr(vp: *mut Vnode) -> Result<Vattr, i32> {
    let mut va = Vattr::NULL;
    let e = vop!(vp, getattr, EBADF, EOPNOTSUPP, |f| f(vp, &mut va));
    if e != 0 {
        return Err(e);
    }
    // SAFETY: the caller holds `vp`; its mount lives while it does.
    va.va_fsid = unsafe { (*(*vp).v_mount).mnt_fsid };
    Ok(va)
}

/// `getattr` for modules: a file system reading another vnode's attributes (tmpfs, the directory
/// it covers). `0` or the errno.
pub(crate) extern "C" fn oxidebsd_vop_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    match vop_getattr(vp) {
        Ok(va) => {
            // SAFETY: the calling module's record.
            unsafe { *vap = va };
            0
        }
        Err(e) => e,
    }
}

/// `access`: the type's, else `vaccess` over `getattr` (FreeBSD's `vop_stdaccess`).
pub(crate) fn vop_access(vp: *mut Vnode, accmode: u32, cred: &Ucred) -> i32 {
    vop!(vp, access, 0, {
        match vop_getattr(vp) {
            Ok(va) => crate::kern::vfs_subr::vaccess(va.va_type, va.va_mode, va.va_uid, va.va_gid, accmode, cred),
            Err(e) => e,
        }
    }, |f| f(vp, accmode, cred))
}

pub(crate) fn vop_setattr(vp: *mut Vnode, vap: &Vattr, cred: &Ucred) -> i32 {
    if vap.va_size != VNOVAL {
        contents_changing(vp);
    }
    vop!(vp, setattr, EBADF, EOPNOTSUPP, |f| f(vp, vap, cred))
}

/// The page cache forgets the file's pages before its blocks change (`VFS.md` §7.3; FreeBSD's
/// `vnode_pager_setsize` and friends): processes already mapping the old pages keep them, and
/// those not yet filled are filled from the old blocks first (`DEMANDPAGE.md` §5.3).
fn contents_changing(vp: *mut Vnode) {
    if ops(vp).is_some() {
        crate::memory::pagecache::changed(crate::kern::vfs_vnops::object_vp(vp) as u64);
    }
}

/// Returns the bytes moved.
pub(crate) fn vop_read(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: &Ucred) -> Result<usize, i32> {
    let r = vop!(vp, read, 0i64, -(EOPNOTSUPP as i64), |f| f(vp, uio, ioflag, cred));
    if r < 0 { Err((-r) as i32) } else { Ok(r as usize) }
}

pub(crate) fn vop_write(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: &Ucred) -> Result<usize, i32> {
    contents_changing(vp);
    let r = vop!(vp, write, -(EBADF as i64), -(EOPNOTSUPP as i64), |f| f(vp, uio, ioflag, cred));
    if r < 0 { Err((-r) as i32) } else { Ok(r as usize) }
}

pub(crate) fn vop_ioctl(vp: *mut Vnode, cmd: u64, data: u64, fflag: u32, cred: &Ucred) -> i32 {
    vop!(vp, ioctl, EBADF, ENOTTY, |f| f(vp, cmd, data, fflag, cred))
}

pub(crate) fn vop_fsync(vp: *mut Vnode, waitfor: i32, data_only: bool) -> i32 {
    vop!(vp, fsync, EBADF, 0, |f| f(vp, waitfor, data_only as u32))
}

pub(crate) fn vop_remove(dvp: *mut Vnode, vp: *mut Vnode, cnp: &ComponentName) -> i32 {
    vop!(dvp, remove, EBADF, EOPNOTSUPP, |f| f(dvp, vp, cnp))
}

pub(crate) fn vop_link(tdvp: *mut Vnode, vp: *mut Vnode, cnp: &ComponentName) -> i32 {
    vop!(tdvp, link, EBADF, EOPNOTSUPP, |f| f(tdvp, vp, cnp))
}

pub(crate) fn vop_rename(
    fdvp: *mut Vnode,
    fvp: *mut Vnode,
    fcnp: &ComponentName,
    tdvp: *mut Vnode,
    tvp: *mut Vnode,
    tcnp: &ComponentName,
) -> i32 {
    vop!(fdvp, rename, EBADF, EOPNOTSUPP, |f| f(fdvp, fvp, fcnp, tdvp, tvp, tcnp))
}

pub(crate) fn vop_rmdir(dvp: *mut Vnode, vp: *mut Vnode, cnp: &ComponentName) -> i32 {
    vop!(dvp, rmdir, EBADF, EOPNOTSUPP, |f| f(dvp, vp, cnp))
}

pub(crate) fn vop_readdir(vp: *mut Vnode, uio: Uio, cred: &Ucred) -> Result<(usize, bool), i32> {
    let mut eof = 0i32;
    let r = vop!(vp, readdir, -(EBADF as i64), -(ENOTDIR as i64), |f| f(vp, uio, cred, &mut eof));
    if r < 0 { Err((-r) as i32) } else { Ok((r as usize, eof != 0)) }
}

pub(crate) fn vop_readlink(vp: *mut Vnode, uio: Uio, cred: &Ucred) -> Result<usize, i32> {
    let r = vop!(vp, readlink, -(EBADF as i64), -(EINVAL as i64), |f| f(vp, uio, cred));
    if r < 0 { Err((-r) as i32) } else { Ok(r as usize) }
}

pub(crate) fn vop_bmap(vp: *mut Vnode, lblkno: u64) -> Result<(u64, u64), i32> {
    let (mut bn, mut run) = (0u64, 0u64);
    let e = vop!(vp, bmap, EBADF, EOPNOTSUPP, |f| f(vp, lblkno, &mut bn, &mut run));
    if e != 0 { Err(e) } else { Ok((bn, run)) }
}

pub(crate) fn vop_allocate(vp: *mut Vnode, offset: u64, len: u64) -> i32 {
    contents_changing(vp);
    vop!(vp, allocate, EBADF, EOPNOTSUPP, |f| f(vp, offset, len))
}
