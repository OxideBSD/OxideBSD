//! The path system calls (FreeBSD's `vfs_syscalls.c`, OxideBSD-doc `VFS.md` §6): every call that
//! names a file by path, or works on a directory or a vnode file's attributes, done by the kernel
//! through `namei` and the vnode operations. The `vfs` module registers them (`sys/modules/vfs`).
//!
//! Each runs under the VFS's giant lock (`fs::fslock::Giant`) for its whole length, and releases
//! the vnode references queued while a file system couldn't be entered first
//! (`vfs_subr::drain_deferred`).
//!
//! Paths cross the ABI length-prefixed (`ptr, len`); the `*at()` calls pass a `RawAtPath`
//! (`dirfd`, `ptr`, `len`). Where POSIX leaves the order of checks open, they follow what oxfs
//! did before the VFS, so the errors a program sees didn't change with it.

use alloc::vec::Vec;
use core::ptr;

use vfs_if::*;

use crate::fs::fd::{self, FWRITE};
use crate::fs::fslock::Giant;
use crate::kern::vfs_lookup::{self, Namei, NameiData, PATH_MAX};
use crate::kern::vfs_mount;
use crate::kern::vfs_subr::{self, current_ucred, vref, vrele};
use crate::kern::vfs_vnops::{self, VN_OPS, rdonly, vn_stat};
use crate::kern::vnode_if::*;
use crate::memory::usercopy::{UserPtr, copyin, copyout};

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const ENXIO: i32 = 6;
const EBADF: i32 = 9;
const EACCES: i32 = 13;
const EFAULT: i32 = 14;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const EXDEV: i32 = 18;
const ENODEV: i32 = 19;
const EISDIR: i32 = 21;
const ERANGE: i32 = 34;
const ENAMETOOLONG: i32 = 36;
const EROFS: i32 = 30;

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EACCESS: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const RENAME_NOREPLACE: u64 = 1;
const RENAME_EXCHANGE: u64 = 2;
const RENAME_WHITEOUT: u64 = 4;
const O_CLOEXEC: u64 = 0o2000000;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;

const SETID_BITS: u32 = 0o6000;

type R = Result<i64, i32>;

fn ret(r: R) -> i64 {
    match r {
        Ok(v) => v,
        Err(e) => -(e as i64),
    }
}

/// The giant lock for a system call, after releasing what was queued.
fn enter() -> Giant {
    let giant = Giant::enter();
    vfs_subr::drain_deferred();
    giant
}

// --- Arguments -------------------------------------------------------------------------------------

/// Copies a length-prefixed path in. `ENAMETOOLONG` past `PATH_MAX`, as oxfs had it.
fn copyin_path(ptr: u64, len: u64) -> Result<Vec<u8>, i32> {
    if len > PATH_MAX as u64 {
        return Err(ENAMETOOLONG);
    }
    let mut buf = alloc::vec![0u8; len as usize];
    copyin(UserPtr::new(ptr), &mut buf).map_err(|_| EFAULT)?;
    Ok(buf)
}

fn copyout_bytes(data: &[u8], dst: u64) -> Result<(), i32> {
    copyout(data, UserPtr::new(dst)).map_err(|_| EFAULT)
}

fn copyout_val<T: Copy>(v: &T, dst: u64) -> Result<(), i32> {
    // SAFETY: a plain-data value read as its bytes.
    let bytes = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) };
    copyout_bytes(bytes, dst)
}

fn copyin_val<T: Copy + Default>(src: u64) -> Result<T, i32> {
    let mut v = T::default();
    // SAFETY: filling a plain-data value from its bytes.
    let bytes = unsafe { core::slice::from_raw_parts_mut(&mut v as *mut T as *mut u8, core::mem::size_of::<T>()) };
    copyin(UserPtr::new(src), bytes).map_err(|_| EFAULT)?;
    Ok(v)
}

/// An `*at()` call's path: `{dirfd, ptr, len}` in user memory.
struct AtPath {
    dirfd: i64,
    /// A NULL path (`utimensat(fd, NULL, ...)`).
    null: bool,
    path: Vec<u8>,
}

fn read_at(at_ptr: u64) -> Result<AtPath, i32> {
    let raw: [u64; 3] = copyin_val(at_ptr)?;
    let (dirfd, ptr, len) = (raw[0] as i64, raw[1], raw[2]);
    let path = if ptr == 0 { Vec::new() } else { copyin_path(ptr, len)? };
    Ok(AtPath { dirfd, null: ptr == 0, path })
}

/// The vnode a vnode file `fd` is open on, referenced: `EBADF` for a closed fd or one that isn't a
/// vnode's (a pipe, a socket, a terminal).
fn fd_vnode(fd: u64) -> Result<*mut Vnode, i32> {
    let real_fd = fd::real_fd_of(fd).ok_or(EBADF)?;
    let (ops, _, _, data) = fd::file_of(real_fd).ok_or(EBADF)?;
    if !ptr::eq(ops, &VN_OPS) {
        return Err(EBADF);
    }
    let vp = data as *mut Vnode;
    vref(vp);
    Ok(vp)
}

/// Where an `*at()` path starts: null for the cwd (`AT_FDCWD`, or an absolute path), else the
/// directory `dirfd` is open on, referenced (`EBADF`, or `ENOTDIR` for an fd that isn't a
/// directory's).
fn at_start(at: &AtPath) -> Result<*mut Vnode, i32> {
    if at.dirfd == AT_FDCWD || at.path.first() == Some(&b'/') {
        return Ok(ptr::null_mut());
    }
    if at.dirfd < 0 {
        return Err(EBADF);
    }
    let real_fd = fd::real_fd_of(at.dirfd as u64).ok_or(EBADF)?;
    let (ops, _, _, data) = fd::file_of(real_fd).ok_or(EBADF)?;
    if !ptr::eq(ops, &VN_OPS) {
        return Err(ENOTDIR);
    }
    let vp = data as *mut Vnode;
    // SAFETY: the open file holds `vp`.
    if unsafe { (*vp).v_type } != VDIR {
        return Err(ENOTDIR);
    }
    vref(vp);
    Ok(vp)
}

/// Runs `f` with `at`'s start directory, released afterwards. An empty path is `ENOENT`.
fn with_at(at: &AtPath, f: impl FnOnce(*mut Vnode) -> R) -> R {
    if at.path.is_empty() {
        return Err(ENOENT);
    }
    let start = at_start(at)?;
    let r = f(start);
    if !start.is_null() {
        vrele(start);
    }
    r
}

/// The vnode an `AT_EMPTY_PATH` call names: the cwd for `AT_FDCWD`, else `dirfd`'s, referenced.
/// `EPERM` for an fd that isn't a vnode's: nothing to change, as oxfs had it.
fn at_empty_vnode(dirfd: i64) -> Result<*mut Vnode, i32> {
    if dirfd == AT_FDCWD {
        return Ok(cwd_referenced());
    }
    if dirfd < 0 {
        return Err(EBADF);
    }
    fd_vnode(dirfd as u64).map_err(|e| if e == EBADF && fd::real_fd_of(dirfd as u64).is_some() { EPERM } else { e })
}

fn cwd_referenced() -> *mut Vnode {
    let vp = crate::process::current_dir_vnode(true);
    let vp = if vp.is_null() { vfs_mount::rootvnode() } else { vp };
    vref(vp);
    vp
}

fn lookup(path: &[u8], start: *mut Vnode, follow: bool, cred: &Ucred) -> Result<*mut Vnode, i32> {
    let nd = NameiData { path, nameiop: LOOKUP, follow, startdir: start, cred };
    Ok(vfs_lookup::namei(&nd)?.into_vp())
}

/// Runs `f` on a referenced vnode and releases it.
fn with_vnode(vp: *mut Vnode, f: impl FnOnce(*mut Vnode) -> R) -> R {
    let r = f(vp);
    vrele(vp);
    r
}

fn vattr(vp: *mut Vnode) -> Result<Vattr, i32> {
    vop_getattr(vp)
}

fn vtype(vp: *mut Vnode) -> VType {
    // SAFETY: the callers hold `vp`.
    unsafe { (*vp).v_type }
}

fn same_mount(a: *mut Vnode, b: *mut Vnode) -> bool {
    // SAFETY: the callers hold both.
    unsafe { (*a).v_mount == (*b).v_mount }
}

/// The sticky-directory rule (`S_ISVTX`): in a sticky directory only the directory's owner, the
/// file's owner or root may remove or rename a file. Plus write permission on the directory.
fn may_delete(dvp: *mut Vnode, vp: *mut Vnode, cred: &Ucred) -> Result<(), i32> {
    let e = vop_access(dvp, VWRITE, cred);
    if e != 0 {
        return Err(e);
    }
    let dva = vattr(dvp)?;
    if dva.va_mode & 0o1000 != 0 && cred.cr_uid != 0 && cred.cr_uid != dva.va_uid && cred.cr_uid != vattr(vp)?.va_uid {
        return Err(EACCES);
    }
    Ok(())
}

/// Gives the description of fd (or kernel handle) `r` the reference to the vnode it was opened
/// through (`fd::set_vnode`).
fn attach_vnode(r: i64, vp: *mut Vnode) {
    let real_fd = if fd::is_kernel_opening() { Some(r as u64) } else { fd::real_fd_of(r as u64) };
    match real_fd {
        Some(real_fd) => fd::set_vnode(real_fd, vp),
        None => vrele(vp),
    }
}

// --- open --------------------------------------------------------------------------------------------

fn open_common(path: &[u8], start: *mut Vnode, flags: u64, mode: u64) -> R {
    fd::check_room(1).map_err(|e| e as i32)?;
    let vp = vfs_vnops::vn_open(path, start, flags, mode as u32)?;
    let fd = match vtype(vp) {
        // Every device, in devfs or made by mknod elsewhere, opens through the kernel's registry
        // by number (`DEVFS.md` §3.4).
        VCHR => {
            let rdev = unsafe { (*vp).v_rdev } as u32;
            let r = crate::fs::devfs::oxidebsd_dev_open(((rdev >> 8) & 0xfff) as u64, (rdev & 0xff) as u64, flags);
            if r < 0 {
                vrele(vp);
                return Err((-r) as i32);
            }
            attach_vnode(r, vp);
            r
        }
        VBLK => {
            vrele(vp);
            return Err(ENXIO);
        }
        VFIFO => {
            // Keyed by the vnode holding the file (a nullfs vnode's lower one), which the FIFO's
            // descriptor holds: the key can't be reused while it's open.
            let key = vfs_vnops::object_vp(vp) as u64;
            let r = crate::fs::pipe::oxidebsd_fifo_open(key, flags);
            if r < 0 {
                vrele(vp);
                return Err((-r) as i32);
            }
            attach_vnode(r, vp);
            r
        }
        _ => {
            let real_fd = fd::oxidebsd_alloc_fd();
            let r = fd::finstall(real_fd, &VN_OPS, vp as u64, fd::open_flag(flags), fd::FdKind::Vnode);
            if r < 0 {
                let cred = current_ucred();
                let fflag = fd::open_flag(flags);
                if fflag & FWRITE != 0 && vtype(vp) == VREG {
                    // SAFETY: held; `vn_open` counted it.
                    unsafe { (*vfs_vnops::object_vp(vp)).v_writecount -= 1 };
                }
                vop_close(vp, fflag, &cred);
                vrele(vp);
                return Err((-r) as i32);
            }
            r
        }
    };
    if flags & O_CLOEXEC != 0 {
        fd::oxidebsd_set_fd_cloexec(fd as u64, 1);
    }
    Ok(fd)
}

/// `open(2)`, system call 5.
pub(crate) extern "C" fn oxidebsd_sys_open(path_ptr: u64, path_len: u64, flags: u64, mode: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let path = copyin_path(path_ptr, path_len)?;
        open_common(&path, ptr::null_mut(), flags, mode)
    })())
}

/// `openat(2)`, system call 560.
pub(crate) extern "C" fn oxidebsd_sys_openat(at_ptr: u64, flags: u64, mode: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let at = read_at(at_ptr)?;
        with_at(&at, |start| open_common(&at.path, start, flags, mode))
    })())
}

/// Opens `path` (a kernel buffer) for the kernel itself (exec's program): inside
/// `fd::kernel_open`, so the vnode file it makes is held, not given an fd. Its handle.
pub(crate) fn kern_open(path: &[u8]) -> Result<u64, i32> {
    let _g = enter();
    let r = fd::kernel_open(|| ret(open_common(path, ptr::null_mut(), 0, 0)));
    if r < 0 { Err((-r) as i32) } else { Ok(r as u64) }
}

// --- Directories ----------------------------------------------------------------------------------

fn mkdir_common(path: &[u8], start: *mut Vnode, mode: u64) -> R {
    let cred = current_ucred();
    let nd = NameiData { path, nameiop: CREATE, follow: false, startdir: start, cred: &cred };
    let ni = match vfs_lookup::namei(&nd) {
        Ok(ni) => ni,
        // `/`, `a/.`, `a/..`: no name of its own, but it exists.
        Err(e @ (EISDIR | EINVAL)) => {
            return match lookup(path, start, true, &cred) {
                Ok(vp) => {
                    vrele(vp);
                    Err(EEXIST)
                }
                Err(_) => Err(e),
            };
        }
        Err(e) => return Err(e),
    };
    let r = (|| {
        if rdonly(ni.dvp) {
            return Err(EROFS);
        }
        if !ni.vp.is_null() {
            return Err(EEXIST);
        }
        let e = vop_access(ni.dvp, VWRITE, &cred);
        if e != 0 {
            return Err(e);
        }
        let mut va = Vattr::NULL;
        va.va_type = VDIR;
        va.va_mode = (mode as u32 & 0o1777) & !(crate::process::oxidebsd_current_umask() as u32);
        let vp = vop_mkdir(ni.dvp, &ni.cn(CREATE, &cred), &va)?;
        crate::kern::vfs_cache::purge_negative(ni.dvp);
        vrele(vp);
        Ok(0)
    })();
    ni.release();
    r
}

pub(crate) extern "C" fn oxidebsd_sys_mkdir(path_ptr: u64, path_len: u64, mode: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| mkdir_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), mode))())
}

pub(crate) extern "C" fn oxidebsd_sys_mkdirat(at_ptr: u64, mode: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let at = read_at(at_ptr)?;
        with_at(&at, |start| mkdir_common(&at.path, start, mode))
    })())
}

fn mknod_common(path: &[u8], start: *mut Vnode, mode: u64, dev: u64) -> R {
    let vtype = match mode as u32 & S_IFMT {
        S_IFREG => VREG,
        S_IFCHR => VCHR,
        S_IFBLK => VBLK,
        S_IFIFO => VFIFO,
        _ => return Err(EINVAL),
    };
    let cred = current_ucred();
    make_node(path, start, vtype, mode as u32 & 0o777, dev, &cred).map(|vp| {
        vrele(vp);
        0
    })
}

/// Makes a node of `vtype` at `path` (`mknod`, `bind` of a local socket). Returns it, referenced.
pub(crate) fn make_node(path: &[u8], start: *mut Vnode, vtype: VType, perm: u32, dev: u64, cred: &Ucred) -> Result<*mut Vnode, i32> {
    let nd = NameiData { path, nameiop: CREATE, follow: false, startdir: start, cred };
    let ni = vfs_lookup::namei(&nd)?;
    let r = (|| {
        if rdonly(ni.dvp) {
            return Err(EROFS);
        }
        if !ni.vp.is_null() {
            return Err(EEXIST);
        }
        if matches!(vtype, VCHR | VBLK) && cred.cr_uid != 0 {
            return Err(EPERM);
        }
        let e = vop_access(ni.dvp, VWRITE, cred);
        if e != 0 {
            return Err(e);
        }
        let mut va = Vattr::NULL;
        va.va_type = vtype;
        va.va_mode = perm & !(crate::process::oxidebsd_current_umask() as u32);
        va.va_rdev = dev;
        let vp = vop_mknod(ni.dvp, &ni.cn(CREATE, cred), &va)?;
        crate::kern::vfs_cache::purge_negative(ni.dvp);
        Ok(vp)
    })();
    ni.release();
    r
}

pub(crate) extern "C" fn oxidebsd_sys_mknod(path_ptr: u64, path_len: u64, mode: u64, dev: u64) -> i64 {
    let _g = enter();
    ret((|| mknod_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), mode, dev))())
}

pub(crate) extern "C" fn oxidebsd_sys_mknodat(at_ptr: u64, mode: u64, dev: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let at = read_at(at_ptr)?;
        with_at(&at, |start| mknod_common(&at.path, start, mode, dev))
    })())
}

fn delete_lookup(path: &[u8], start: *mut Vnode, cred: &Ucred) -> Result<Namei, i32> {
    let nd = NameiData { path, nameiop: DELETE, follow: false, startdir: start, cred };
    vfs_lookup::namei(&nd)
}

fn unlink_common(path: &[u8], start: *mut Vnode) -> R {
    let cred = current_ucred();
    let ni = delete_lookup(path, start, &cred)?;
    let r = (|| {
        let e = vop_access(ni.dvp, VWRITE, &cred);
        if e != 0 {
            return Err(e);
        }
        if rdonly(ni.dvp) {
            return Err(EROFS);
        }
        if ni.vp.is_null() {
            return Err(ENOENT);
        }
        if vtype(ni.vp) == VDIR {
            return Err(EISDIR);
        }
        may_delete(ni.dvp, ni.vp, &cred)?;
        let e = vop_remove(ni.dvp, ni.vp, &ni.cn(DELETE, &cred));
        crate::kern::vfs_cache::purge_name(ni.dvp, &ni.last);
        if e != 0 { Err(e) } else { Ok(0) }
    })();
    ni.release();
    r
}

fn rmdir_common(path: &[u8], start: *mut Vnode) -> R {
    let cred = current_ucred();
    let ni = delete_lookup(path, start, &cred)?;
    let r = (|| {
        if rdonly(ni.dvp) {
            return Err(EROFS);
        }
        if ni.vp.is_null() {
            return Err(ENOENT);
        }
        if vtype(ni.vp) != VDIR {
            return Err(ENOTDIR);
        }
        may_delete(ni.dvp, ni.vp, &cred)?;
        // SAFETY: held.
        if unsafe { !(*ni.vp).v_mountedhere.is_null() || (*ni.vp).v_flag & VV_ROOT != 0 } {
            return Err(EBUSY);
        }
        let e = vop_rmdir(ni.dvp, ni.vp, &ni.cn(DELETE, &cred));
        crate::kern::vfs_cache::purge(ni.vp);
        crate::kern::vfs_cache::purge_name(ni.dvp, &ni.last);
        if e != 0 { Err(e) } else { Ok(0) }
    })();
    ni.release();
    r
}

pub(crate) extern "C" fn oxidebsd_sys_unlink(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| unlink_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut()))())
}

pub(crate) extern "C" fn oxidebsd_sys_rmdir(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| rmdir_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut()))())
}

pub(crate) extern "C" fn oxidebsd_sys_unlinkat(at_ptr: u64, flags: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        if flags & !AT_REMOVEDIR != 0 {
            return Err(EINVAL);
        }
        let at = read_at(at_ptr)?;
        if flags & AT_REMOVEDIR != 0 {
            with_at(&at, |start| rmdir_common(&at.path, start))
        } else {
            with_at(&at, |start| unlink_common(&at.path, start))
        }
    })())
}

/// Whether directory `ancestor` is `dir` or above it in `dir`'s mount (rename's "into itself").
fn is_same_or_descendant(dir: *mut Vnode, ancestor: *mut Vnode, cred: &Ucred) -> Result<bool, i32> {
    let mut dp = dir;
    vref(dp);
    let dotdot = ComponentName { cn_nameiop: LOOKUP, cn_flags: ISDOTDOT, cn_cred: cred, cn_nameptr: b"..".as_ptr(), cn_namelen: 2 };
    for _ in 0..(1u32 << 16) {
        if dp == ancestor {
            vrele(dp);
            return Ok(true);
        }
        // SAFETY: held.
        if unsafe { (*dp).v_flag } & VV_ROOT != 0 {
            break;
        }
        let parent = match vop_lookup(dp, &dotdot) {
            Ok(p) => p,
            Err(e) => {
                vrele(dp);
                return Err(e);
            }
        };
        vrele(dp);
        if parent == dp {
            vrele(parent);
            return Ok(false);
        }
        dp = parent;
    }
    vrele(dp);
    Ok(false)
}

fn rename_common(old: &AtPath, new: &AtPath, noreplace: bool) -> R {
    if old.path.is_empty() || new.path.is_empty() {
        return Err(ENOENT);
    }
    let cred = current_ucred();
    let ostart = at_start(old)?;
    let from = delete_lookup(&old.path, ostart, &cred);
    if !ostart.is_null() {
        vrele(ostart);
    }
    let from = from?;
    if from.vp.is_null() {
        from.release();
        return Err(ENOENT);
    }
    let nstart = match at_start(new) {
        Ok(s) => s,
        Err(e) => {
            from.release();
            return Err(e);
        }
    };
    let nd = NameiData { path: &new.path, nameiop: RENAME, follow: false, startdir: nstart, cred: &cred };
    let to = vfs_lookup::namei(&nd);
    if !nstart.is_null() {
        vrele(nstart);
    }
    let to = match to {
        Ok(t) => t,
        Err(e) => {
            from.release();
            return Err(e);
        }
    };
    let r = (|| {
        let (fdvp, fvp, tdvp, tvp) = (from.dvp, from.vp, to.dvp, to.vp);
        let is_dir = vtype(fvp) == VDIR;
        if rdonly(fdvp) || rdonly(tdvp) {
            return Err(EROFS);
        }
        if tvp == fvp {
            return if noreplace { Err(EEXIST) } else { Ok(0) };
        }
        if !same_mount(fvp, tdvp) || (!tvp.is_null() && !same_mount(fvp, tvp)) {
            return Err(EXDEV);
        }
        if is_dir && is_same_or_descendant(tdvp, fvp, &cred)? {
            return Err(EINVAL);
        }
        may_delete(fdvp, fvp, &cred)?;
        let e = vop_access(tdvp, VWRITE, &cred);
        if e != 0 {
            return Err(e);
        }
        if is_dir && fdvp != tdvp {
            let e = vop_access(fvp, VWRITE, &cred);
            if e != 0 {
                return Err(e);
            }
        }
        if !tvp.is_null() {
            if noreplace {
                return Err(EEXIST);
            }
            may_delete(tdvp, tvp, &cred)?;
            match (is_dir, vtype(tvp) == VDIR) {
                (false, true) => return Err(EISDIR),
                (true, false) => return Err(ENOTDIR),
                _ => {}
            }
            // SAFETY: held.
            if unsafe { !(*tvp).v_mountedhere.is_null() } {
                return Err(EBUSY);
            }
        }
        let e = vop_rename(fdvp, fvp, &from.cn(RENAME, &cred), tdvp, tvp, &to.cn(RENAME, &cred));
        crate::kern::vfs_cache::purge_name(fdvp, &from.last);
        crate::kern::vfs_cache::purge_name(tdvp, &to.last);
        if is_dir {
            crate::kern::vfs_cache::purge(fvp);
        } else if e == 0 {
            crate::kern::vfs_cache::note_opened(tdvp, &to.last, fvp);
        }
        if !tvp.is_null() {
            crate::kern::vfs_cache::purge(tvp);
        }
        if e != 0 { Err(e) } else { Ok(0) }
    })();
    from.release();
    to.release();
    r
}

pub(crate) extern "C" fn oxidebsd_sys_rename(old_ptr: u64, old_len: u64, new_ptr: u64, new_len: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let old = AtPath { dirfd: AT_FDCWD, null: false, path: copyin_path(old_ptr, old_len)? };
        let new = AtPath { dirfd: AT_FDCWD, null: false, path: copyin_path(new_ptr, new_len)? };
        rename_common(&old, &new, false)
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_renameat2(old_at: u64, new_at: u64, flags: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
            || flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        {
            return Err(EINVAL);
        }
        let old = read_at(old_at)?;
        let new = read_at(new_at)?;
        rename_common(&old, &new, flags & RENAME_NOREPLACE != 0)
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_renameat(old_at: u64, new_at: u64, _a2: u64, _a3: u64) -> i64 {
    oxidebsd_sys_renameat2(old_at, new_at, 0, 0)
}

fn link_common(old: &AtPath, new: &AtPath, follow: bool) -> R {
    if old.path.is_empty() || new.path.is_empty() {
        return Err(ENOENT);
    }
    let cred = current_ucred();
    let ostart = at_start(old)?;
    let vp = lookup(&old.path, ostart, follow, &cred);
    if !ostart.is_null() {
        vrele(ostart);
    }
    let vp = vp?;
    with_vnode(vp, |vp| {
        if vtype(vp) == VDIR || (vtype(vp) == VLNK && follow) {
            return Err(EPERM);
        }
        let nstart = at_start(new)?;
        let nd = NameiData { path: &new.path, nameiop: CREATE, follow: false, startdir: nstart, cred: &cred };
        let ni = vfs_lookup::namei(&nd);
        if !nstart.is_null() {
            vrele(nstart);
        }
        let ni = ni?;
        let r = (|| {
            if rdonly(ni.dvp) {
                return Err(EROFS);
            }
            if !ni.vp.is_null() {
                return Err(EEXIST);
            }
            if !same_mount(vp, ni.dvp) {
                return Err(EXDEV);
            }
            let e = vop_access(ni.dvp, VWRITE, &cred);
            if e != 0 {
                return Err(e);
            }
            let e = vop_link(ni.dvp, vp, &ni.cn(CREATE, &cred));
            crate::kern::vfs_cache::purge_negative(ni.dvp);
            if e != 0 { Err(e) } else { Ok(0) }
        })();
        ni.release();
        r
    })
}

/// `link(2)`: a final symbolic link is linked itself, not followed (POSIX leaves it open; the
/// BSDs and Linux agree).
pub(crate) extern "C" fn oxidebsd_sys_link(old_ptr: u64, old_len: u64, new_ptr: u64, new_len: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let old = AtPath { dirfd: AT_FDCWD, null: false, path: copyin_path(old_ptr, old_len)? };
        let new = AtPath { dirfd: AT_FDCWD, null: false, path: copyin_path(new_ptr, new_len)? };
        link_common(&old, &new, false)
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_linkat(old_at: u64, new_at: u64, flags: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(EINVAL);
        }
        let old = read_at(old_at)?;
        let new = read_at(new_at)?;
        link_common(&old, &new, flags & AT_SYMLINK_FOLLOW != 0)
    })())
}

fn symlink_common(target: &[u8], path: &[u8], start: *mut Vnode) -> R {
    let cred = current_ucred();
    let nd = NameiData { path, nameiop: CREATE, follow: false, startdir: start, cred: &cred };
    let ni = vfs_lookup::namei(&nd)?;
    let r = (|| {
        if rdonly(ni.dvp) {
            return Err(EROFS);
        }
        if !ni.vp.is_null() {
            return Err(EEXIST);
        }
        let e = vop_access(ni.dvp, VWRITE, &cred);
        if e != 0 {
            return Err(e);
        }
        let mut va = Vattr::NULL;
        va.va_type = VLNK;
        va.va_mode = 0o777;
        let vp = vop_symlink(ni.dvp, &ni.cn(CREATE, &cred), &va, target)?;
        crate::kern::vfs_cache::purge_negative(ni.dvp);
        vrele(vp);
        Ok(0)
    })();
    ni.release();
    r
}

pub(crate) extern "C" fn oxidebsd_sys_symlink(target_ptr: u64, target_len: u64, path_ptr: u64, path_len: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let target = copyin_path(target_ptr, target_len)?;
        symlink_common(&target, &copyin_path(path_ptr, path_len)?, ptr::null_mut())
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_symlinkat(target_ptr: u64, target_len: u64, at_ptr: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let target = copyin_path(target_ptr, target_len)?;
        let at = read_at(at_ptr)?;
        with_at(&at, |start| symlink_common(&target, &at.path, start))
    })())
}

fn readlink_common(path: &[u8], start: *mut Vnode, buf_ptr: u64, buf_cap: u64) -> R {
    let cred = current_ucred();
    with_vnode(lookup(path, start, false, &cred)?, |vp| {
        if vtype(vp) != VLNK {
            return Err(EINVAL);
        }
        let mut target = vfs_lookup::readlink_kernel(vp, &cred)?;
        target.truncate(buf_cap as usize);
        copyout_bytes(&target, buf_ptr)?;
        Ok(target.len() as i64)
    })
}

pub(crate) extern "C" fn oxidebsd_sys_readlink(path_ptr: u64, path_len: u64, buf_ptr: u64, buf_cap: u64) -> i64 {
    let _g = enter();
    ret((|| readlink_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), buf_ptr, buf_cap))())
}

pub(crate) extern "C" fn oxidebsd_sys_readlinkat(at_ptr: u64, buf_ptr: u64, buf_cap: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let at = read_at(at_ptr)?;
        with_at(&at, |start| readlink_common(&at.path, start, buf_ptr, buf_cap))
    })())
}

// --- Attributes ---------------------------------------------------------------------------------

fn stat_common(path: &[u8], start: *mut Vnode, follow: bool, buf_ptr: u64) -> R {
    let cred = current_ucred();
    with_vnode(lookup(path, start, follow, &cred)?, |vp| {
        copyout_val(&vn_stat(vp)?, buf_ptr)?;
        Ok(0)
    })
}

pub(crate) extern "C" fn oxidebsd_sys_stat(path_ptr: u64, path_len: u64, buf_ptr: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| stat_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), true, buf_ptr))())
}

pub(crate) extern "C" fn oxidebsd_sys_lstat(path_ptr: u64, path_len: u64, buf_ptr: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| stat_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), false, buf_ptr))())
}

pub(crate) extern "C" fn oxidebsd_sys_fstatat(at_ptr: u64, buf_ptr: u64, flags: u64, _a3: u64) -> i64 {
    let g = enter();
    ret((|| {
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT) != 0 {
            return Err(EINVAL);
        }
        let at = read_at(at_ptr)?;
        if at.path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            if at.dirfd == AT_FDCWD {
                return stat_common(b".", ptr::null_mut(), true, buf_ptr);
            }
            if at.dirfd < 0 {
                return Err(EBADF);
            }
            drop(g);
            let r = crate::kern::kern_descrip::oxidebsd_sys_fstat(at.dirfd as u64, buf_ptr, 0, 0);
            return if r < 0 { Err((-r) as i32) } else { Ok(r) };
        }
        with_at(&at, |start| stat_common(&at.path, start, flags & AT_SYMLINK_NOFOLLOW == 0, buf_ptr))
    })())
}

const X_OK: u64 = 1;
const W_OK: u64 = 2;
const R_OK: u64 = 4;

fn access_vnode(vp: *mut Vnode, amode: u64, effective: bool, cred: &Ucred) -> R {
    if amode == 0 {
        return Ok(0);
    }
    let mut want = 0;
    if amode & R_OK != 0 {
        want |= VREAD;
    }
    if amode & W_OK != 0 {
        want |= VWRITE;
    }
    if amode & X_OK != 0 {
        want |= VEXEC;
    }
    if !effective {
        want |= VACCESS_REAL;
    }
    match vop_access(vp, want, cred) {
        0 => Ok(0),
        _ => Err(EACCES),
    }
}

fn access_common(path: &[u8], start: *mut Vnode, amode: u64, effective: bool) -> R {
    let cred = current_ucred();
    with_vnode(lookup(path, start, true, &cred)?, |vp| access_vnode(vp, amode, effective, &cred))
}

pub(crate) extern "C" fn oxidebsd_sys_access(path_ptr: u64, path_len: u64, amode: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| access_common(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), amode, false))())
}

pub(crate) extern "C" fn oxidebsd_sys_faccessat(at_ptr: u64, amode: u64, flags: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(EINVAL);
        }
        let at = read_at(at_ptr)?;
        let cred = current_ucred();
        let effective = flags & AT_EACCESS != 0;
        if at.path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            return with_vnode(at_empty_vnode(at.dirfd)?, |vp| access_vnode(vp, amode, effective, &cred));
        }
        if flags & AT_SYMLINK_NOFOLLOW != 0 {
            let start = at_start(&at)?;
            let vp = lookup(&at.path, start, false, &cred);
            if !start.is_null() {
                vrele(start);
            }
            if let Ok(vp) = vp {
                let link = vtype(vp) == VLNK;
                vrele(vp);
                if link {
                    return Ok(0);
                }
            }
        }
        with_at(&at, |start| access_common(&at.path, start, amode, effective))
    })())
}

/// `chmod`: the owner or root; the set-group-ID bit is cleared unless the caller is in the file's
/// group (POSIX).
fn chmod_vnode(vp: *mut Vnode, mode: u64, cred: &Ucred) -> R {
    if rdonly(vp) {
        return Err(EROFS);
    }
    let va = vattr(vp)?;
    if cred.cr_uid != 0 && cred.cr_uid != va.va_uid {
        return Err(EPERM);
    }
    let mut mode = mode as u32 & 0o7777;
    if cred.cr_uid != 0 && !cred.groupmember(va.va_gid) {
        mode &= !0o2000;
    }
    let mut set = Vattr::NULL;
    set.va_mode = mode;
    match vop_setattr(vp, &set, cred) {
        0 => Ok(0),
        e => Err(e),
    }
}

pub(crate) extern "C" fn oxidebsd_sys_chmod(path_ptr: u64, path_len: u64, mode: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let cred = current_ucred();
        with_vnode(lookup(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), true, &cred)?, |vp| {
            chmod_vnode(vp, mode, &cred)
        })
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_fchmod(fd: u64, mode: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let cred = current_ucred();
        with_vnode(fd_vnode(fd)?, |vp| chmod_vnode(vp, mode, &cred))
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_fchmodat(at_ptr: u64, mode: u64, flags: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(EINVAL);
        }
        let at = read_at(at_ptr)?;
        let cred = current_ucred();
        if at.path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            if at.dirfd == AT_FDCWD {
                return with_vnode(cwd_referenced(), |vp| chmod_vnode(vp, mode, &cred));
            }
            if at.dirfd < 0 {
                return Err(EBADF);
            }
            return with_vnode(fd_vnode(at.dirfd as u64)?, |vp| chmod_vnode(vp, mode, &cred));
        }
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        with_at(&at, |start| {
            with_vnode(lookup(&at.path, start, follow, &cred)?, |vp| {
                if vtype(vp) == VLNK {
                    return Err(EOPNOTSUPP);
                }
                chmod_vnode(vp, mode, &cred)
            })
        })
    })())
}

/// `chown`: root, or the owner giving the file to a group it's in without changing the owner. A
/// change by anyone but root clears the set-ID bits. `-1` leaves an ID alone.
fn chown_vnode(vp: *mut Vnode, uid: u64, gid: u64, cred: &Ucred) -> R {
    if rdonly(vp) {
        return Err(EROFS);
    }
    let va = vattr(vp)?;
    let new_uid = if uid as u32 == u32::MAX { va.va_uid } else { uid as u32 };
    let new_gid = if gid as u32 == u32::MAX { va.va_gid } else { gid as u32 };
    let mut set = Vattr::NULL;
    if cred.cr_uid != 0 {
        let owner = cred.cr_uid == va.va_uid && new_uid == va.va_uid;
        let group_ok = new_gid == va.va_gid || cred.groupmember(new_gid);
        if !owner || !group_ok {
            return Err(EPERM);
        }
        if va.va_mode & SETID_BITS != 0 {
            set.va_mode = va.va_mode & !SETID_BITS;
        }
    }
    set.va_uid = new_uid;
    set.va_gid = new_gid;
    match vop_setattr(vp, &set, cred) {
        0 => Ok(0),
        e => Err(e),
    }
}

pub(crate) extern "C" fn oxidebsd_sys_chown(path_ptr: u64, path_len: u64, uid: u64, gid: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let cred = current_ucred();
        with_vnode(lookup(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), true, &cred)?, |vp| {
            chown_vnode(vp, uid, gid, &cred)
        })
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_fchownat(at_ptr: u64, uid: u64, gid: u64, flags: u64) -> i64 {
    let _g = enter();
    ret((|| {
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(EINVAL);
        }
        let at = read_at(at_ptr)?;
        let cred = current_ucred();
        if at.path.is_empty() && flags & AT_EMPTY_PATH != 0 {
            return with_vnode(at_empty_vnode(at.dirfd)?, |vp| chown_vnode(vp, uid, gid, &cred));
        }
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        with_at(&at, |start| with_vnode(lookup(&at.path, start, follow, &cred)?, |vp| chown_vnode(vp, uid, gid, &cred)))
    })())
}

const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `utimensat`'s times: `UTIME_NOW`, `UTIME_OMIT`, or explicit (which only the owner or root may
/// set; "now" also anyone who may write the file).
fn utimens_vnode(vp: *mut Vnode, times_ptr: u64, cred: &Ucred) -> R {
    if rdonly(vp) {
        return Err(EROFS);
    }
    let now = Timespec { tv_sec: crate::cpu::rtc::oxidebsd_unix_time(), tv_nsec: 0 };
    let (mut atime, mut mtime) = (Some(now), Some(now));
    let mut explicit = false;
    if times_ptr != 0 {
        let t: [i64; 4] = copyin_val(times_ptr)?;
        let mut resolve = |sec: i64, nsec: i64| -> Result<Option<Timespec>, i32> {
            if nsec == UTIME_NOW {
                Ok(Some(now))
            } else if nsec == UTIME_OMIT {
                Ok(None)
            } else if !(0..1_000_000_000).contains(&nsec) {
                Err(EINVAL)
            } else {
                explicit = true;
                Ok(Some(Timespec { tv_sec: sec, tv_nsec: 0 }))
            }
        };
        atime = resolve(t[0], t[1])?;
        mtime = resolve(t[2], t[3])?;
    }
    if atime.is_none() && mtime.is_none() {
        return Ok(0);
    }
    let va = vattr(vp)?;
    if cred.cr_uid != 0 && cred.cr_uid != va.va_uid {
        if explicit {
            return Err(EPERM);
        }
        if vop_access(vp, VWRITE, cred) != 0 {
            return Err(EACCES);
        }
    }
    let mut set = Vattr::NULL;
    if let Some(a) = atime {
        set.va_atime = a;
    }
    if let Some(m) = mtime {
        set.va_mtime = m;
    }
    if !explicit {
        set.va_vaflags |= VA_UTIMES_NULL;
    }
    match vop_setattr(vp, &set, cred) {
        0 => Ok(0),
        e => Err(e),
    }
}

pub(crate) extern "C" fn oxidebsd_sys_utimensat(path_ptr: u64, path_len: u64, times_ptr: u64, flags: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let cred = current_ucred();
        let path = copyin_path(path_ptr, path_len)?;
        with_vnode(lookup(&path, ptr::null_mut(), flags & AT_SYMLINK_NOFOLLOW == 0, &cred)?, |vp| {
            utimens_vnode(vp, times_ptr, &cred)
        })
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_utimensat_at(at_ptr: u64, times_ptr: u64, flags: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(EINVAL);
        }
        let at = read_at(at_ptr)?;
        let cred = current_ucred();
        if at.null || (at.path.is_empty() && flags & AT_EMPTY_PATH != 0) {
            return with_vnode(at_empty_vnode(at.dirfd)?, |vp| utimens_vnode(vp, times_ptr, &cred));
        }
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        with_at(&at, |start| with_vnode(lookup(&at.path, start, follow, &cred)?, |vp| utimens_vnode(vp, times_ptr, &cred)))
    })())
}

// --- Working and root directories ---------------------------------------------------------------

pub(crate) extern "C" fn oxidebsd_sys_chdir(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let cred = current_ucred();
        let vp = lookup(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), true, &cred)?;
        if vtype(vp) != VDIR {
            vrele(vp);
            return Err(ENOTDIR);
        }
        let e = vop_access(vp, VEXEC, &cred);
        if e != 0 {
            vrele(vp);
            return Err(e);
        }
        crate::process::set_current_dir_vnode(true, vp);
        Ok(0)
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_fchdir(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let vp = fd_vnode(fd)?;
        if vtype(vp) != VDIR {
            vrele(vp);
            return Err(ENOTDIR);
        }
        crate::process::set_current_dir_vnode(true, vp);
        Ok(0)
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_chroot(path_ptr: u64, path_len: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let path = copyin_path(path_ptr, path_len)?;
        let cred = current_ucred();
        if cred.cr_uid != 0 {
            return Err(EPERM);
        }
        let vp = lookup(&path, ptr::null_mut(), true, &cred)?;
        if vtype(vp) != VDIR {
            vrele(vp);
            return Err(ENOTDIR);
        }
        crate::process::set_current_dir_vnode(false, vp);
        Ok(0)
    })())
}

/// The path of directory `vp` from the process's root (FreeBSD's `vn_fullpath`): each directory's
/// name from the name cache, else by looking itself up in `..`. A directory outside the process's
/// root (a cwd left behind by `chroot`) is given from the system's root.
pub(crate) fn fullpath(vp: *mut Vnode, cred: &Ucred) -> Result<Vec<u8>, i32> {
    let root = {
        let r = crate::process::current_dir_vnode(false);
        if r.is_null() { vfs_mount::rootvnode() } else { r }
    };
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut dp = vp;
    vref(dp);
    let dotdot = ComponentName { cn_nameiop: LOOKUP, cn_flags: ISDOTDOT, cn_cred: cred, cn_nameptr: b"..".as_ptr(), cn_namelen: 2 };
    let result = loop {
        if dp == root || dp == vfs_mount::rootvnode() {
            break Ok(());
        }
        // A mount's root: its name is the covered directory's.
        // SAFETY: held.
        let (flag, covered) = unsafe { ((*dp).v_flag, (*(*dp).v_mount).mnt_vnodecovered) };
        if flag & VV_ROOT != 0 {
            if covered.is_null() {
                break Ok(());
            }
            vref(covered);
            vrele(dp);
            dp = covered;
            continue;
        }
        if names.len() > PATH_MAX / 2 {
            break Err(ENAMETOOLONG);
        }
        // Not a directory: no `..` to climb, only the name it was found or opened by.
        if vtype(dp) != VDIR {
            let Some((parent, name)) = crate::kern::vfs_cache::name_of(dp) else { break Err(ENOENT) };
            vref(parent);
            vrele(dp);
            dp = parent;
            names.push(name);
            continue;
        }
        let parent = match vop_lookup(dp, &dotdot) {
            Ok(p) => p,
            Err(e) => break Err(e),
        };
        let name = match crate::kern::vfs_cache::name_of(dp) {
            Some((d, name)) if d == parent => Ok(name),
            _ => name_in(parent, dp, cred),
        };
        vrele(dp);
        dp = parent;
        match name {
            Ok(n) => names.push(n),
            Err(e) => break Err(e),
        }
    };
    vrele(dp);
    result?;
    let mut path = Vec::new();
    for name in names.iter().rev() {
        path.push(b'/');
        path.extend_from_slice(name);
    }
    if path.is_empty() {
        path.push(b'/');
    }
    Ok(path)
}

/// `vp`'s name in directory `dvp`, by reading `dvp` for its file ID.
fn name_in(dvp: *mut Vnode, vp: *mut Vnode, cred: &Ucred) -> Result<Vec<u8>, i32> {
    use crate::kern::subr_uio::{IoSeg, Uio, UioRw, UioSeg};
    // SAFETY: held.
    let fileid = unsafe { (*vp).v_fileid };
    let mut buf = alloc::vec![0u8; 4096];
    let mut cookie = 0u64;
    loop {
        let seg = IoSeg { base: buf.as_mut_ptr() as u64, len: buf.len() as u64 };
        let mut uio = Uio::new(alloc::vec![seg], UioRw::Read, UioSeg::Kernel, cookie).map_err(|e| e as i32)?;
        let (n, eof) = vop_readdir(dvp, &mut uio as *mut Uio as u64, cred)?;
        cookie = uio.offset();
        let mut at = 0;
        while at + DIRENT_NAME_OFFSET < n {
            let ino = u64::from_le_bytes(buf[at..at + 8].try_into().unwrap());
            let reclen = u16::from_le_bytes(buf[at + 16..at + 18].try_into().unwrap()) as usize;
            let name_end = buf[at + DIRENT_NAME_OFFSET..at + reclen].iter().position(|&b| b == 0).unwrap_or(reclen - DIRENT_NAME_OFFSET);
            let name = &buf[at + DIRENT_NAME_OFFSET..at + DIRENT_NAME_OFFSET + name_end];
            if ino == fileid && name != b"." && name != b".." {
                return Ok(name.to_vec());
            }
            if reclen == 0 {
                break;
            }
            at += reclen;
        }
        if eof || n == 0 {
            return Err(ENOENT);
        }
    }
}

pub(crate) extern "C" fn oxidebsd_sys_getcwd(buf_ptr: u64, buf_len: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let cred = current_ucred();
        let cwd = cwd_referenced();
        let path = fullpath(cwd, &cred);
        vrele(cwd);
        let path = path?;
        if buf_len == 0 || path.len() as u64 + 1 > buf_len {
            return Err(ERANGE);
        }
        copyout_bytes(&path, buf_ptr)?;
        copyout_bytes(&[0], buf_ptr.wrapping_add(path.len() as u64))?;
        Ok(path.len() as i64 + 1)
    })())
}

// --- Directory reading, file systems, locks ------------------------------------------------------------

/// `getdents(2)`: the directory's records from the file's offset, a cookie its file system chose,
/// stored back after.
pub(crate) extern "C" fn oxidebsd_sys_getdents(fd: u64, buf_ptr: u64, buf_len: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let real_fd = fd::real_fd_of(fd).ok_or(EBADF)?;
        let (ops, _, offset, data) = fd::file_of(real_fd).ok_or(EBADF)?;
        if !ptr::eq(ops, &VN_OPS) {
            return Err(EBADF);
        }
        let vp = data as *mut Vnode;
        if vtype(vp) != VDIR {
            return Err(ENOTDIR);
        }
        let mut uio = crate::kern::subr_uio::Uio::user(buf_ptr, buf_len, crate::kern::subr_uio::UioRw::Read, offset)
            .map_err(|e| e as i32)?;
        let (n, _) = vop_readdir(vp, &mut uio as *mut crate::kern::subr_uio::Uio as u64, &current_ucred())?;
        fd::set_offset(real_fd, uio.offset());
        Ok(n as i64)
    })())
}

/// musl's `struct statfs` (`arch/generic/bits/statfs.h`), 120 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MuslStatfs {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [u32; 2],
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<MuslStatfs>() == 120);

/// `ST_RDONLY`, `ST_NOSUID` (`statvfs(3)`'s `f_flag`).
const ST_RDONLY: u64 = 1;
const ST_NOSUID: u64 = 2;

fn statfs_vnode(vp: *mut Vnode, buf_ptr: u64) -> R {
    // SAFETY: held; its mount lives while it does.
    let sb = vfs_mount::vfs_statfs(unsafe { (*vp).v_mount })?;
    let out = MuslStatfs {
        f_type: sb.f_magic,
        f_bsize: sb.f_bsize,
        f_blocks: sb.f_blocks,
        f_bfree: sb.f_bfree,
        f_bavail: sb.f_bavail,
        f_files: sb.f_files,
        f_ffree: sb.f_ffree,
        f_fsid: [sb.f_fsid as u32, (sb.f_fsid >> 32) as u32],
        f_namelen: sb.f_namemax as u64,
        f_frsize: sb.f_bsize,
        f_flags: (if sb.f_flags & MNT_RDONLY != 0 { ST_RDONLY } else { 0 })
            | (if sb.f_flags & MNT_NOSUID != 0 { ST_NOSUID } else { 0 }),
        f_spare: [0; 4],
    };
    copyout_val(&out, buf_ptr)?;
    Ok(0)
}

pub(crate) extern "C" fn oxidebsd_sys_statfs(path_ptr: u64, path_len: u64, buf_ptr: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let cred = current_ucred();
        with_vnode(lookup(&copyin_path(path_ptr, path_len)?, ptr::null_mut(), true, &cred)?, |vp| {
            statfs_vnode(vp, buf_ptr)
        })
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_fstatfs(fd: u64, buf_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| with_vnode(fd_vnode(fd)?, |vp| statfs_vnode(vp, buf_ptr)))())
}

/// `posix_fallocate(3)`'s system call: `EINVAL` for a descriptor not open for writing, as oxfs had
/// it.
pub(crate) extern "C" fn oxidebsd_sys_fallocate(fd: u64, _mode: u64, offset: u64, len: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let real_fd = fd::real_fd_of(fd).ok_or(EBADF)?;
        let (_, flag, _, _) = fd::file_of(real_fd).ok_or(EBADF)?;
        let vp = fd_vnode(fd)?;
        with_vnode(vp, |vp| {
            if flag & FWRITE == 0 {
                return Err(EINVAL);
            }
            if vtype(vp) == VDIR {
                return Err(EISDIR);
            }
            match vop_allocate(vp, offset, len) {
                0 => Ok(0),
                e => Err(e),
            }
        })
    })())
}

pub(crate) extern "C" fn oxidebsd_sys_flock(fd: u64, op: u64, _a2: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let real_fd = fd::real_fd_of(fd).ok_or(EBADF)?;
        with_vnode(fd_vnode(fd)?, |vp| match crate::kern::vfs_advlock::flock(vp, real_fd, op as u32) {
            0 => Ok(0),
            e => Err(e),
        })
    })())
}

// --- Mounting -----------------------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct IoVec {
    base: u64,
    len: u64,
}

const NMOUNT_MAX_IOV: usize = 64;

fn iov_str(v: IoVec) -> Result<Vec<u8>, i32> {
    if v.base == 0 {
        return Ok(Vec::new());
    }
    let mut s = copyin_path(v.base, v.len)?;
    if let Some(n) = s.iter().position(|&b| b == 0) {
        s.truncate(n);
    }
    Ok(s)
}

/// `nmount(2)`, system call 584 (FreeBSD's shape): `fstype`, `fspath` and `from` options, plus
/// `nosuid`, `wxallowed`, `ro`, `rw`; `errmsg` gets a message on failure. `MNT_UPDATE` changes a
/// mounted file system's read-only state (`/` only for now).
pub(crate) extern "C" fn oxidebsd_sys_nmount(iov_ptr: u64, niov: u64, flags: u64, _a3: u64) -> i64 {
    let _g = enter();
    if niov % 2 != 0 || niov > NMOUNT_MAX_IOV as u64 {
        return -(EINVAL as i64);
    }
    let mut iov = Vec::new();
    for i in 0..niov {
        match copyin_val::<IoVec>(iov_ptr.wrapping_add(i * 16)) {
            Ok(v) => iov.push(v),
            Err(e) => return -(e as i64),
        }
    }
    let mut errmsg: Option<IoVec> = None;
    let (mut fstype, mut fspath, mut from) = (Vec::new(), Vec::new(), Vec::new());
    let mut unknown = false;
    let mut bad_option: Option<i32> = None;
    let mut nosuid = flags & MNT_NOSUID != 0;
    let mut wxallowed = false;
    let mut rd = flags & MNT_RDONLY != 0;
    for pair in iov.chunks_exact(2) {
        let name = match iov_str(pair[0]) {
            Ok(name) => name,
            Err(e) => {
                bad_option.get_or_insert(e);
                continue;
            }
        };
        let slot = match name.as_slice() {
            b"nosuid" => {
                nosuid = true;
                continue;
            }
            b"wxallowed" => {
                wxallowed = true;
                continue;
            }
            b"ro" => {
                rd = true;
                continue;
            }
            b"rw" => {
                rd = false;
                continue;
            }
            b"errmsg" => {
                errmsg = Some(pair[1]);
                continue;
            }
            b"fstype" => &mut fstype,
            b"fspath" => &mut fspath,
            b"from" | b"target" => &mut from,
            _ => {
                unknown = true;
                continue;
            }
        };
        match iov_str(pair[1]) {
            Ok(v) => *slot = v,
            Err(e) => {
                bad_option.get_or_insert(e);
            }
        }
    }
    let fail = |errno: i32, msg: &[u8]| -> i64 {
        if let Some(buf) = errmsg
            && buf.base != 0
            && buf.len > 0
        {
            let n = msg.len().min(buf.len as usize - 1);
            let _ = copyout_bytes(&msg[..n], buf.base);
            let _ = copyout_bytes(&[0], buf.base.wrapping_add(n as u64));
        }
        -(errno as i64)
    };
    let cred = current_ucred();
    if cred.cr_uid != 0 {
        return fail(EPERM, b"only root may mount file systems");
    }
    if let Some(e) = bad_option {
        return fail(e, b"an option's name or value can't be read, or is too long");
    }
    if unknown || flags & !(MNT_NOSUID | MNT_RDONLY | MNT_UPDATE) != 0 {
        return fail(EOPNOTSUPP, b"the only mount options are nosuid, wxallowed, ro and rw");
    }
    if fspath.is_empty() {
        return fail(EINVAL, b"no fspath: the directory to mount on");
    }
    if flags & MNT_UPDATE != 0 {
        if fspath != b"/" {
            return fail(EOPNOTSUPP, b"only / can be updated (mount -u) for now");
        }
        return match vfs_mount::update_root(rd) {
            Ok(()) => 0,
            Err(EBUSY) => fail(EBUSY, b"files are open for writing on /"),
            Err(e) => fail(e, b"can't reread the root file system's superblock"),
        };
    }
    if rd {
        return fail(EOPNOTSUPP, b"read-only mounts are for / only, with mount -u, for now");
    }
    if fstype.is_empty() {
        return fail(EINVAL, b"no fstype");
    }
    let Some(vfc) = vfs_mount::find_type(&fstype) else {
        return fail(ENODEV, b"unknown file system type");
    };
    if vfc.flags & VFCF_FROM_VNODE != 0 && from.is_empty() {
        return fail(EINVAL, b"nullfs needs a target: the directory to mount");
    }
    let mflags = (if nosuid { MNT_NOSUID } else { 0 }) | (if wxallowed { MNT_WXALLOWED } else { 0 });
    let r = (|| -> Result<(), i32> {
        let from_vp = if vfc.flags & VFCF_FROM_VNODE != 0 {
            let vp = lookup(&from, ptr::null_mut(), true, &cred)?;
            if vtype(vp) != VDIR {
                vrele(vp);
                return Err(ENOTDIR);
            }
            vp
        } else {
            ptr::null_mut()
        };
        let covered = match lookup(&fspath, ptr::null_mut(), true, &cred) {
            Ok(vp) => vp,
            Err(e) => {
                if !from_vp.is_null() {
                    vrele(from_vp);
                }
                return Err(e);
            }
        };
        if vtype(covered) != VDIR {
            vrele(covered);
            if !from_vp.is_null() {
                vrele(from_vp);
            }
            return Err(ENOTDIR);
        }
        let fromname: &[u8] = if from.is_empty() { &fstype } else { &from };
        let r = vfs_mount::domount(vfc, covered, mflags, &fspath, fromname, from_vp);
        if !from_vp.is_null() {
            vrele(from_vp);
        }
        r
    })();
    match r {
        Ok(()) => 0,
        Err(e) => fail(e, b""),
    }
}

/// `unmount(2)` (musl's `umount2`, system call 176): `EBUSY` while anything on it is in use.
pub(crate) extern "C" fn oxidebsd_sys_unmount(path_ptr: u64, path_len: u64, flags: u64, _a3: u64) -> i64 {
    let _g = enter();
    ret((|| {
        let path = copyin_path(path_ptr, path_len)?;
        let cred = current_ucred();
        if cred.cr_uid != 0 {
            return Err(EPERM);
        }
        let vp = lookup(&path, ptr::null_mut(), true, &cred)?;
        // SAFETY: held.
        let (flag, mp) = unsafe { ((*vp).v_flag, (*vp).v_mount) };
        vrele(vp);
        if flag & VV_ROOT == 0 {
            return Err(EINVAL);
        }
        vfs_mount::dounmount(mp, flags).map(|()| 0)
    })())
}

// --- Registration -------------------------------------------------------------------------------------

type Handler = extern "C" fn(u64, u64, u64, u64) -> i64;

/// The calls above with their numbers, for the `vfs` module to register.
static SYSCALLS: [(u64, Handler); 41] = [
    (5, oxidebsd_sys_open),
    (12, oxidebsd_sys_chdir),
    (21, oxidebsd_sys_access),
    (81, oxidebsd_sys_fchdir),
    (91, oxidebsd_sys_fchmod),
    (108, oxidebsd_sys_getcwd),
    (109, oxidebsd_sys_unlink),
    (110, oxidebsd_sys_rmdir),
    (111, oxidebsd_sys_rename),
    (127, oxidebsd_sys_stat),
    (128, oxidebsd_sys_lstat),
    (129, oxidebsd_sys_getdents),
    (136, oxidebsd_sys_mkdir),
    (154, oxidebsd_sys_readlink),
    (155, oxidebsd_sys_symlink),
    (165, oxidebsd_sys_chmod),
    (166, oxidebsd_sys_chown),
    (167, oxidebsd_sys_utimensat),
    (176, oxidebsd_sys_unmount),
    (474, oxidebsd_sys_fallocate),
    (475, oxidebsd_sys_flock),
    (476, oxidebsd_sys_statfs),
    (477, oxidebsd_sys_fstatfs),
    (488, oxidebsd_sys_link),
    (489, oxidebsd_sys_mknod),
    (490, oxidebsd_sys_chroot),
    (560, oxidebsd_sys_openat),
    (561, oxidebsd_sys_mkdirat),
    (562, oxidebsd_sys_mknodat),
    (563, oxidebsd_sys_fchownat),
    (564, oxidebsd_sys_fstatat),
    (565, oxidebsd_sys_unlinkat),
    (566, oxidebsd_sys_renameat),
    (567, oxidebsd_sys_linkat),
    (568, oxidebsd_sys_symlinkat),
    (569, oxidebsd_sys_readlinkat),
    (570, oxidebsd_sys_fchmodat),
    (571, oxidebsd_sys_faccessat),
    (572, oxidebsd_sys_utimensat_at),
    (573, oxidebsd_sys_renameat2),
    (584, oxidebsd_sys_nmount),
];

/// Entry `i` of the path calls: its handler, with its number in `*number`; null past the end.
pub(crate) extern "C" fn oxidebsd_vfs_syscall(i: u64, number: *mut u64) -> u64 {
    match SYSCALLS.get(i as usize) {
        Some(&(n, h)) => {
            // SAFETY: the module passes a place for the number.
            unsafe { *number = n };
            h as usize as u64
        }
        None => 0,
    }
}
