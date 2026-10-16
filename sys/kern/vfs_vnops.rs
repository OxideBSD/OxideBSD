//! Files that are vnodes (FreeBSD's `vfs_vnops.c`): `vn_open`, the descriptor operations of an
//! open regular file, directory or symbolic link (`VN_OPS`, `fs::fd::FileOps`), and `stat(2)`'s
//! record built from a vnode's attributes (`vn_stat`).
//!
//! A vnode file's `data` is its vnode, referenced for as long as the file is open; the kernel
//! keeps the offset (`DFLAG_SEEKABLE`) and checks the access mode, so each operation is one
//! `VOP_*` call. Device and FIFO nodes open into their own kinds of file (the device's driver,
//! `fs::pipe`'s FIFO), which still remember the vnode they came through (`Description::vnode`).

use vfs_if::*;

use crate::fs::fd::{self, DFLAG_SEEKABLE, FAPPEND, FNONBLOCK, FREAD, FWRITE, FileOps};
use crate::kern::subr_uio::Uio as KUio;
use crate::kern::vfs_lookup::{self, Namei, NameiData};
use crate::kern::vfs_subr::{current_ucred, vrele};
use crate::kern::vnode_if::*;

pub(crate) const EACCES: i32 = 13;
pub(crate) const EEXIST: i32 = 17;
pub(crate) const EISDIR: i32 = 21;
pub(crate) const ELOOP: i32 = 40;
pub(crate) const EROFS: i32 = 30;
pub(crate) const ENXIO: i32 = 6;

pub(crate) const O_ACCMODE: u64 = 0o3;
pub(crate) const O_CREAT: u64 = 0o100;
pub(crate) const O_EXCL: u64 = 0o200;
pub(crate) const O_TRUNC: u64 = 0o1000;
pub(crate) const O_DIRECTORY: u64 = 0o200000;
pub(crate) const O_NOFOLLOW: u64 = 0o400000;

/// musl's `struct stat` for x86_64 (`arch/x86_64/bits/stat.h`), 144 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime_sec: i64,
    pub st_atime_nsec: i64,
    pub st_mtime_sec: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime_sec: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

const _: () = assert!(core::mem::size_of::<Stat>() == 144);

/// `S_IF*` for a vnode type.
pub(crate) fn vtype_to_ifmt(t: VType) -> u32 {
    match t {
        VREG => 0o100000,
        VDIR => 0o040000,
        VBLK => 0o060000,
        VCHR => 0o020000,
        VLNK => 0o120000,
        VSOCK => 0o140000,
        VFIFO => 0o010000,
        _ => 0,
    }
}

/// `stat(2)`'s record for `vp` (FreeBSD's `vn_stat`).
pub(crate) fn vn_stat(vp: *mut Vnode) -> Result<Stat, i32> {
    let va = vop_getattr(vp)?;
    Ok(Stat {
        st_dev: va.va_fsid,
        st_ino: va.va_fileid,
        st_nlink: va.va_nlink,
        st_mode: vtype_to_ifmt(va.va_type) | (va.va_mode & 0o7777),
        st_uid: va.va_uid,
        st_gid: va.va_gid,
        __pad0: 0,
        st_rdev: if matches!(va.va_type, VCHR | VBLK) { va.va_rdev } else { 0 },
        st_size: va.va_size as i64,
        st_blksize: va.va_blocksize as i64,
        st_blocks: (va.va_bytes / 512) as i64,
        st_atime_sec: va.va_atime.tv_sec,
        st_atime_nsec: va.va_atime.tv_nsec,
        st_mtime_sec: va.va_mtime.tv_sec,
        st_mtime_nsec: va.va_mtime.tv_nsec,
        st_ctime_sec: va.va_ctime.tv_sec,
        st_ctime_nsec: va.va_ctime.tv_nsec,
        __unused: [0; 3],
    })
}

/// Whether `vp`'s mount is read-only.
pub(crate) fn rdonly(vp: *mut Vnode) -> bool {
    // SAFETY: the caller holds `vp`; its mount lives while it does.
    unsafe { (*(*vp).v_mount).mnt_flag & MNT_RDONLY != 0 }
}

fn vtype(vp: *mut Vnode) -> VType {
    // SAFETY: the caller holds `vp`.
    unsafe { (*vp).v_type }
}

/// `vn_open`: looks `path` up for an open with `open(2)` flags `oflags`, creating a regular file
/// (mode `cmode` less the umask) for `O_CREAT`, checks permission and truncates for `O_TRUNC`.
/// Returns the vnode, referenced and opened (`VOP_OPEN`).
pub(crate) fn vn_open(path: &[u8], startdir: *mut Vnode, oflags: u64, cmode: u32) -> Result<*mut Vnode, i32> {
    let cred = current_ucred();
    let fflag = fd::open_flag(oflags);
    let mut created = false;
    let vp = if oflags & O_CREAT != 0 {
        // `O_EXCL` means the name itself: a symbolic link there exists, wherever it points.
        let nd = NameiData {
            path,
            nameiop: CREATE,
            follow: oflags & (O_EXCL | O_NOFOLLOW) == 0,
            startdir,
            cred: &cred,
        };
        let ni = vfs_lookup::namei(&nd)?;
        if !ni.vp.is_null() && vtype(ni.vp) != VDIR {
            crate::kern::vfs_cache::note_opened(ni.dvp, &ni.last, ni.vp);
        }
        if ni.vp.is_null() {
            let r = create_file(&ni, cmode, &cred);
            if let Ok(vp) = r {
                crate::kern::vfs_cache::note_opened(ni.dvp, &ni.last, vp);
            }
            let dvp = ni.dvp;
            core::mem::forget(ni);
            vrele(dvp);
            created = true;
            r?
        } else if oflags & O_EXCL != 0 {
            ni.release();
            return Err(EEXIST);
        } else {
            let mut vp = ni.into_vp();
            if let Err(e) = vfs_lookup::cross_mounts(&mut vp) {
                vrele(vp);
                return Err(e);
            }
            vp
        }
    } else {
        let nd = NameiData { path, nameiop: LOOKUP, follow: oflags & O_NOFOLLOW == 0, startdir, cred: &cred };
        let ni = vfs_lookup::namei(&nd)?;
        if !ni.dvp.is_null() && vtype(ni.vp) != VDIR {
            crate::kern::vfs_cache::note_opened(ni.dvp, &ni.last, ni.vp);
        }
        ni.into_vp()
    };
    match open_checks(vp, oflags, fflag, created, &cred) {
        Ok(()) => Ok(vp),
        Err(e) => {
            vrele(vp);
            Err(e)
        }
    }
}

/// Makes the missing last component of `ni` a regular file.
fn create_file(ni: &Namei, cmode: u32, cred: &Ucred) -> Result<*mut Vnode, i32> {
    if ni.trailing_slash {
        return Err(EISDIR);
    }
    if rdonly(ni.dvp) {
        return Err(EROFS);
    }
    let e = vop_access(ni.dvp, VWRITE, cred);
    if e != 0 {
        return Err(e);
    }
    let umask = crate::process::oxidebsd_current_umask() as u32;
    let mut va = Vattr::NULL;
    va.va_type = VREG;
    va.va_mode = cmode & !umask & 0o7777;
    let cn = ni.cn(CREATE, cred);
    let vp = vop_create(ni.dvp, &cn, &va)?;
    crate::kern::vfs_cache::purge_negative(ni.dvp);
    Ok(vp)
}

fn open_checks(vp: *mut Vnode, oflags: u64, fflag: u32, created: bool, cred: &Ucred) -> Result<(), i32> {
    let t = vtype(vp);
    if t == VLNK {
        return Err(ELOOP); // only reached with O_NOFOLLOW
    }
    if t == VSOCK {
        return Err(EOPNOTSUPP); // UNIX.md §5.2, as in the BSDs
    }
    if oflags & O_DIRECTORY != 0 && t != VDIR {
        return Err(ENOTDIR);
    }
    let writing = fflag & FWRITE != 0;
    if t == VDIR && (writing || oflags & O_TRUNC != 0) {
        return Err(EISDIR);
    }
    if !created {
        let mut want = 0;
        if fflag & FREAD != 0 {
            want |= VREAD;
        }
        if writing || oflags & O_TRUNC != 0 {
            want |= VWRITE;
        }
        if want != 0 {
            let e = vop_access(vp, want, cred);
            if e != 0 {
                return Err(e);
            }
        }
    }
    if (writing || oflags & O_TRUNC != 0) && matches!(t, VREG | VDIR) && rdonly(vp) {
        return Err(EROFS);
    }
    if oflags & O_TRUNC != 0 && t == VREG && !created {
        let mut va = Vattr::NULL;
        va.va_size = 0;
        let e = vop_setattr(vp, &va, cred);
        if e != 0 {
            return Err(e);
        }
    }
    let e = vop_open(vp, fflag, cred);
    if e != 0 { Err(e) } else { Ok(()) }
}

// --- The descriptor operations of a vnode file ---------------------------------------------------

fn vnode_of(handle: u64) -> *mut Vnode {
    fd::oxidebsd_file_data(handle) as *mut Vnode
}

fn ioflag_of(handle: u64) -> u32 {
    let flag = fd::file_of(handle).map_or(0, |(_, f, _, _)| f);
    (if flag & FAPPEND != 0 { IO_APPEND } else { 0 }) | (if flag & FNONBLOCK != 0 { IO_NDELAY } else { 0 })
}

extern "C" fn vn_read(handle: u64, uio: *mut KUio, _flags: u64) -> i64 {
    let vp = vnode_of(handle);
    if vtype(vp) == VDIR {
        return -(EISDIR as i64);
    }
    match vop_read(vp, uio as u64, ioflag_of(handle), &current_ucred()) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

extern "C" fn vn_write(handle: u64, uio: *mut KUio, flags: u64) -> i64 {
    let vp = vnode_of(handle);
    // `O_APPEND` moves a `write` to the end, not a `pwrite` (`FOF_OFFSET`), as oxfs had it.
    let mut ioflag = ioflag_of(handle);
    if flags & crate::kern::subr_uio::FOF_NEXTOFF == 0 {
        ioflag &= !IO_APPEND;
    }
    match vop_write(vp, uio as u64, ioflag, &current_ucred()) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

extern "C" fn vn_close(handle: u64) -> i64 {
    let vp = vnode_of(handle);
    let flag = fd::file_of(handle).map_or(0, |(_, f, _, _)| f);
    crate::kern::vfs_advlock::release_all(vp, handle);
    vop_close(vp, flag, &current_ucred());
    vrele(vp);
    0
}

extern "C" fn vn_stat_op(handle: u64, out: u64) -> i64 {
    match vn_stat(vnode_of(handle)) {
        Ok(st) => {
            // SAFETY: `out` is the kernel's own `Stat` buffer (`FileOps::stat`).
            unsafe { *(out as *mut Stat) = st };
            0
        }
        Err(e) => -(e as i64),
    }
}

extern "C" fn vn_truncate(handle: u64, len: u64) -> i64 {
    let vp = vnode_of(handle);
    if vtype(vp) != VREG {
        return -(EINVAL as i64);
    }
    if rdonly(vp) {
        return -(EROFS as i64);
    }
    let mut va = Vattr::NULL;
    va.va_size = len;
    -(vop_setattr(vp, &va, &current_ucred()) as i64)
}

extern "C" fn vn_sync(handle: u64, data_only: u64) -> i64 {
    -(vop_fsync(vnode_of(handle), MNT_WAIT, data_only != 0) as i64)
}

extern "C" fn vn_ioctl(handle: u64, request: u64, arg: u64) -> i64 {
    let flag = fd::file_of(handle).map_or(0, |(_, f, _, _)| f);
    -(vop_ioctl(vnode_of(handle), request, arg, flag, &current_ucred()) as i64)
}

pub(crate) static VN_OPS: FileOps = FileOps {
    flags: DFLAG_SEEKABLE,
    read: Some(vn_read),
    write: Some(vn_write),
    close: Some(vn_close),
    ioctl: Some(vn_ioctl),
    poll: None,
    stat: Some(vn_stat_op),
    truncate: Some(vn_truncate),
    sync: Some(vn_sync),
    content_id: Some(vn_content_id),
    fb_geometry: None,
};

/// `mmap`'s identity for the file: its file ID, for a type whose file IDs are content IDs
/// (`VFCF_INODE_CONTENT`, until step 2c keys the page cache by vnode); else not mappable.
extern "C" fn vn_content_id(handle: u64) -> i64 {
    let vp = vnode_of(handle);
    // SAFETY: the open file holds `vp`; its mount and type are live.
    unsafe {
        let flags = (*(*(*vp).v_mount).mnt_vfc).flags;
        if (*vp).v_type == VREG && flags & VFCF_INODE_CONTENT != 0 { (*vp).v_fileid as i64 } else { -1 }
    }
}

/// `execve`'s view of the program open on `vp`: mode, owner and group (the set-ID bits cleared on
/// a `nosuid` mount), and whether its mount is `wxallowed`.
pub(crate) fn exec_setid(vp: *mut Vnode) -> Option<((u32, u32, u32), bool)> {
    let va = vop_getattr(vp).ok()?;
    // SAFETY: the caller's open file holds `vp`.
    let mflag = unsafe { (*(*vp).v_mount).mnt_flag };
    let mut mode = va.va_mode;
    if mflag & MNT_NOSUID != 0 {
        mode &= !0o6000;
    }
    Some(((mode, va.va_uid, va.va_gid), mflag & MNT_WXALLOWED != 0))
}
