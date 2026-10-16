//! oxfs as a VFS type (OxideBSD-doc `VFS.md` §4-§5): its `vfsops` and vnode operations. A vnode's
//! file ID is the inode number. Path lookup and the system calls are still oxfs's own until §11
//! step 2b; through here the kernel mounts the root, syncs, unmounts at shutdown and asks
//! attributes.

use core::ptr;

use oxfs_format::*;
use vfs_if::*;

use super::*;

const VFS_EINVAL: i32 = 22;
const VFS_EIO: i32 = 5;
const VFS_ENXIO: i32 = 6;

static OXFS_NAME: &[u8] = b"oxfs";

pub(crate) static OXFS_VFSCONF: VfsConf = VfsConf {
    name: OXFS_NAME.as_ptr(),
    name_len: 4,
    ops: &OXFS_VFSOPS,
    vops: &OXFS_VOPS,
    mnt_data_size: 0,
    v_data_size: 0,
    flags: 0,
};

static OXFS_VFSOPS: VfsOps = VfsOps {
    mount: Some(oxfs_vfs_mount),
    unmount: Some(oxfs_vfs_unmount),
    root: Some(oxfs_vfs_root),
    statfs: Some(oxfs_vfs_statfs),
    sync: Some(oxfs_vfs_sync),
    vget: Some(oxfs_vfs_vget),
};

static OXFS_VOPS: VopVector = VopVector { getattr: Some(oxfs_vop_getattr), ..VopVector::DEFAULT };

/// The root mount (the disk's), once mounted.
static mut ROOT_MOUNT: *mut Mount = ptr::null_mut();

pub(crate) fn root_mount() -> *mut Mount {
    // SAFETY: written once, at mount, before any process runs.
    unsafe { *ptr::addr_of!(ROOT_MOUNT) }
}

/// Keeps the root mount's `MNT_RDONLY` in step with a remount (`remount_root`), until `nmount`
/// moves into the kernel (step 2b).
pub(crate) fn set_mount_rdonly(rdonly: bool) {
    let mp = root_mount();
    if mp.is_null() {
        return;
    }
    // SAFETY: the root mount lives for good; the kernel reads its flags only between calls.
    unsafe {
        if rdonly {
            (*mp).mnt_flag |= MNT_RDONLY;
        } else {
            (*mp).mnt_flag &= !MNT_RDONLY;
        }
    }
}

/// Mounts the disk's oxfs: the superblock, the layout, the free counts; then devfs on `/dev`.
/// Only the root for now (oxfs has one partition's worth of global state until step 2b).
extern "C" fn oxfs_vfs_mount(mp: *mut Mount, _args: *const MountArgs) -> i32 {
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
    // Mounting leaves PERSISTENCE_READY false through its own reads (see that flag's own doc
    // comment) -- flipped here, once, right before real syscalls become reachable, so every write
    // a running process makes from this point on is persisted immediately.
    set_persistence_ready(true);
    buf::set_write_through(true);
    // SAFETY: the kernel filled the mount's flags.
    let rdonly = unsafe { (*mp).mnt_flag } & MNT_RDONLY != 0;
    set_root_rdonly(rdonly);
    if rdonly {
        log("[oxfs] root mounted read-only\n");
    } else {
        // Mounted: not clean on the disk until an orderly shutdown says so (§3.4.1).
        set_clean(false);
        write_superblock();
        sweep_unnamed_inodes();
    }
    // /dev (`DEVFS.md` §4.1): devfs over the disk's /dev, before any process runs.
    if !mount_devfs() {
        log("[oxfs] failed to mount devfs on /dev\n");
    }
    0
}

/// At shutdown (`vfs_unmountall`): everything delayed is written, and the file system marked
/// clean (§3.4.1). Not called on a panic or a fault.
extern "C" fn oxfs_vfs_unmount(_mp: *mut Mount, _flags: u64) -> i32 {
    if root_rdonly() {
        return 0; // nothing delayed, and the disk can't be written
    }
    buf::flush_all();
    set_clean(true);
    write_superblock();
    log("[oxfs] filesystem synced and marked clean\n");
    0
}

extern "C" fn oxfs_vfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    oxfs_vfs_vget(mp, ROOT_INODE as u64, vpp)
}

/// The disk pool's counts (`write_statfs` reports the same for `statfs(2)` until step 2b).
extern "C" fn oxfs_vfs_statfs(_mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    let free_blocks: u64 = (0..bitmap_blocks()).map(|i| *free_count(i) as u64).sum();
    let table = inode_table(false);
    let free_inodes = table.free as u64 + free_blocks * INODES_PER_BLOCK as u64;
    let used_inodes = (table.count - table.free) as u64;
    // SAFETY: the kernel passes its own record.
    let sb = unsafe { &mut *sbp };
    sb.f_bsize = BLOCK_SIZE as u64;
    sb.f_iosize = BLOCK_SIZE as u64;
    sb.f_blocks = disk_blocks() as u64;
    sb.f_bfree = free_blocks;
    sb.f_bavail = free_blocks;
    sb.f_files = used_inodes + free_inodes;
    sb.f_ffree = free_inodes;
    sb.f_namemax = NAME_MAX as u32;
    sb.f_magic = OXFS_STATFS_MAGIC;
    0
}

extern "C" fn oxfs_vfs_sync(_mp: *mut Mount, _waitfor: i32) -> i32 {
    buf::flush_all();
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
        if fileid == ROOT_INODE as u64 {
            (*vp).v_flag |= VV_ROOT;
        }
        oxidebsd_vfs_hash_insert(vp);
        *vpp = vp;
    }
    0
}

fn timespec(sec: i64) -> Timespec {
    Timespec { tv_sec: sec, tv_nsec: 0 }
}

extern "C" fn oxfs_vop_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    // SAFETY: the kernel passes a live vnode and its own record.
    let (n, fsid) = unsafe { ((*vp).v_fileid as u32, (*(*vp).v_mount).mnt_fsid) };
    let st = inode_stat(n);
    let inode = read_inode(n);
    // SAFETY: as above.
    let va = unsafe { &mut *vap };
    *va = Vattr {
        va_type: vtype_of(inode.kind, inode.device_char),
        va_mode: inode.mode as u32,
        va_nlink: st.st_nlink,
        va_uid: inode.uid,
        va_gid: inode.gid,
        va_fsid: fsid,
        va_fileid: n as u64,
        va_size: inode.size as u64,
        va_blocksize: BLOCK_SIZE as u64,
        va_atime: timespec(inode.atime),
        va_mtime: timespec(inode.mtime),
        va_ctime: timespec(inode.ctime),
        va_birthtime: timespec(inode.ctime),
        va_gen: 0,
        va_flags: 0,
        va_rdev: st.st_rdev,
        va_bytes: st.st_blocks as u64 * 512,
        va_vaflags: 0,
    };
    0
}
