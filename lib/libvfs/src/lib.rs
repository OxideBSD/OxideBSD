//! The VFS's interface between the kernel and file system modules (OxideBSD-doc `VFS.md` §3-§6),
//! in FreeBSD's shape and vocabulary: `struct mount` and its `vfsops`, `struct vnode` and its
//! operations vector, `struct vattr`, `struct componentname`.
//!
//! Everything here is C ABI (`#[repr(C)]`, `extern "C"`), since a module is a separately linked
//! object. The kernel owns and allocates every `Mount` and `Vnode`; a file system reads their public
//! fields and keeps its own state in the private data the kernel allocates beside them
//! (`mnt_data`, `v_data`, of the sizes its `VfsConf` declares).
//!
//! Errors: every operation returns `0` or a positive errno (musl's values), as FreeBSD's do. The
//! kernel turns them into the system call ABI's negative returns. The exceptions move data and
//! return a count: `read`, `write`, `readdir` and `readlink` return the bytes moved, or a negative
//! errno.
#![no_std]

use core::ffi::c_void;

// --- File system types ------------------------------------------------------------------------

/// What a module registers with `oxidebsd_vfs_register` (FreeBSD's `struct vfsconf`). Static: the
/// kernel keeps the pointer.
#[repr(C)]
pub struct VfsConf {
    /// The type's name as `mount -t` and `/etc/fstab` spell it (`oxfs`, `tmpfs`, `procfs`).
    pub name: *const u8,
    pub name_len: usize,
    pub ops: *const VfsOps,
    /// The operations every vnode of this type starts with.
    pub vops: *const VopVector,
    /// Bytes of zeroed private data the kernel allocates with each mount (`Mount::mnt_data`).
    pub mnt_data_size: usize,
    /// Bytes of zeroed private data the kernel allocates with each vnode (`Vnode::v_data`).
    pub v_data_size: usize,
    /// `VFCF_*`.
    pub flags: u32,
}

// SAFETY: a `VfsConf` is an immutable static table of pointers to other statics.
unsafe impl Sync for VfsConf {}

/// No backing device: synthetic (procfs, devfs) or memory (tmpfs).
pub const VFCF_SYNTHETIC: u32 = 1;
/// The name cache keeps nothing for this type: its names come and go behind the VFS's back
/// (procfs's processes, devfs's devices).
pub const VFCF_NOCACHE: u32 = 2;
/// `from` names a directory the kernel looks up for the mount (`MountArgs::from_vp`): nullfs.
pub const VFCF_FROM_VNODE: u32 = 4;
/// Names compare without case (msdosfs): the name cache keys them folded, and never answers
/// `getcwd` from a folded key (the directory is asked for the name as stored).
pub const VFCF_CASEFOLD: u32 = 8;

/// Per-type mount operations (FreeBSD's `struct vfsops`). A null entry takes the kernel's
/// default: `EOPNOTSUPP` for `mount`/`root`/`vget`, success for `unmount`/`sync`, zeros for
/// `statfs`.
#[repr(C)]
pub struct VfsOps {
    /// Sets up `mp` (whose `mnt_data`, flags, names and device the kernel has filled) from `args`.
    /// `MNT_UPDATE` in `mp.mnt_flag` means a remount: only flags change.
    pub mount: Option<extern "C" fn(mp: *mut Mount, args: *const MountArgs) -> i32>,
    /// Tears `mp` down: no vnode of it is referenced any more (or `MNT_FORCE` revoked them all) and
    /// the kernel has reclaimed every vnode of it. Writes what's delayed and marks the file system
    /// clean.
    pub unmount: Option<extern "C" fn(mp: *mut Mount, flags: u64) -> i32>,
    /// The mount's root directory, referenced.
    pub root: Option<extern "C" fn(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32>,
    /// Fills the counts of `sbp` (`f_bsize` through `f_namemax`); the kernel fills the rest.
    pub statfs: Option<extern "C" fn(mp: *mut Mount, sbp: *mut Statfs) -> i32>,
    /// Puts everything delayed on the device. `waitfor` is `MNT_WAIT` or `MNT_NOWAIT`.
    pub sync: Option<extern "C" fn(mp: *mut Mount, waitfor: i32) -> i32>,
    /// The vnode of file `fileid`, referenced: the hash's if it has one (`oxidebsd_vfs_hash_get`),
    /// otherwise a new one (`oxidebsd_getnewvnode` + `oxidebsd_vfs_hash_insert`).
    pub vget: Option<extern "C" fn(mp: *mut Mount, fileid: u64, vpp: *mut *mut Vnode) -> i32>,
}

// SAFETY: as `VfsConf`.
unsafe impl Sync for VfsOps {}

/// What `mount` receives: `nmount(2)`'s options, parsed once by the kernel.
#[repr(C)]
pub struct MountArgs {
    /// `from=`: the device path (`/dev/gpt/rootfs`), a bind source, or empty.
    pub from: *const u8,
    pub from_len: usize,
    /// The block device the kernel opened for `from` (`oxidebsd_bdev_*` handle), or `NODEV`.
    pub dev: u64,
    /// Options the kernel didn't consume, as `name\0value\0` pairs (`size=16m\0`).
    pub opts: *const u8,
    pub opts_len: usize,
    /// `from` looked up, for a `VFCF_FROM_VNODE` type: referenced for the call only (`vref` it to
    /// keep it); null otherwise.
    pub from_vp: *mut Vnode,
}

/// `MountArgs::dev` for a file system with no device.
pub const NODEV: u64 = u64::MAX;

/// A device number in musl's `makedev` encoding (`<sys/sysmacros.h>`), as `stat(2)`'s `st_rdev`
/// and `v_rdev` carry it: `major << 8 | minor` while both are small (`minor < 256`, `major <
/// 4096`), the rest of each in the high bits.
pub const fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (major as u64, minor as u64);
    (ma & 0xffff_f000) << 32 | (ma & 0xfff) << 8 | (mi & 0xffff_ff00) << 12 | mi & 0xff
}

/// `makedev`'s major number.
pub const fn major(dev: u64) -> u32 {
    ((dev >> 32 & 0xffff_f000) | (dev >> 8 & 0xfff)) as u32
}

/// `makedev`'s minor number.
pub const fn minor(dev: u64) -> u32 {
    ((dev >> 12 & 0xffff_ff00) | (dev & 0xff)) as u32
}

// --- Mounts -------------------------------------------------------------------------------------

/// One mounted instance of a type (FreeBSD's `struct mount`). Kernel-owned.
#[repr(C)]
pub struct Mount {
    pub mnt_vfc: *const VfsConf,
    /// `MNT_*`.
    pub mnt_flag: u64,
    /// The type's private data (`VfsConf::mnt_data_size` bytes, zeroed at mount).
    pub mnt_data: *mut c_void,
    /// The directory this mount covers; null for the root.
    pub mnt_vnodecovered: *mut Vnode,
    /// The block device handle (`MountArgs::dev`), or `NODEV`.
    pub mnt_dev: u64,
    /// The file system ID the kernel assigned: `st_dev` of every file on it, `f_fsid`.
    pub mnt_fsid: u64,
    /// Referenced vnodes of this mount (use count above 0), kept by the kernel.
    pub mnt_nvnodes: u64,
    /// Where it's mounted (`/`, `/tmp`), NUL-padded, as `mount(8)` and `/proc/mounts` show it.
    pub mnt_onname: [u8; MNAMELEN],
    /// What it's mounted from (`/dev/gpt/rootfs`, `tmpfs`), NUL-padded.
    pub mnt_fromname: [u8; MNAMELEN],
}

pub const MNAMELEN: usize = 1024;

pub const MNT_RDONLY: u64 = 0x0000_0001;
pub const MNT_SYNCHRONOUS: u64 = 0x0000_0002;
pub const MNT_NOEXEC: u64 = 0x0000_0004;
pub const MNT_NOSUID: u64 = 0x0000_0008;
/// A `wxneeded` program on this mount may map pages writable and executable (OpenBSD's
/// `wxallowed`; THREAT_MODEL.md §3.3).
pub const MNT_WXALLOWED: u64 = 0x0000_0800;
pub const MNT_ROOTFS: u64 = 0x0000_4000;
pub const MNT_UPDATE: u64 = 0x0001_0000;
pub const MNT_FORCE: u64 = 0x0008_0000;

pub const MNT_WAIT: i32 = 1;
pub const MNT_NOWAIT: i32 = 2;

/// What `vfsops.statfs` fills and `getfsstat(2)`/`statfs(2)` report (FreeBSD's `struct statfs`,
/// without its version and spare fields). The kernel fills `f_type`, `f_flags`, `f_fsid` and the
/// names; the file system the counts.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Statfs {
    pub f_type: u32,
    pub f_flags: u64,
    /// Fundamental block size.
    pub f_bsize: u64,
    /// Optimal transfer size.
    pub f_iosize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    /// Free blocks an unprivileged user may use.
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_namemax: u32,
    pub f_fsid: u64,
    /// The type's own magic, reported as musl's `f_type` (`OXFS` for oxfs).
    pub f_magic: u64,
}

impl Statfs {
    pub const ZERO: Statfs = Statfs {
        f_type: 0,
        f_flags: 0,
        f_bsize: 0,
        f_iosize: 0,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: 0,
        f_ffree: 0,
        f_namemax: 0,
        f_fsid: 0,
        f_magic: 0,
    };
}

// --- Vnodes -------------------------------------------------------------------------------------

/// Vnode types (FreeBSD's `enum vtype`).
pub type VType = u32;
pub const VNON: VType = 0;
pub const VREG: VType = 1;
pub const VDIR: VType = 2;
pub const VBLK: VType = 3;
pub const VCHR: VType = 4;
pub const VLNK: VType = 5;
pub const VSOCK: VType = 6;
pub const VFIFO: VType = 7;
/// A revoked vnode (deadfs).
pub const VBAD: VType = 8;

/// The kernel's object for one file of one mount (FreeBSD's `struct vnode`). Kernel-owned;
/// reference counted with `oxidebsd_vref`/`oxidebsd_vrele`. A file system may read every field
/// and write `v_type`, `v_flag`'s `VV_*` bits and `v_rdev` while it sets the vnode up.
#[repr(C)]
pub struct Vnode {
    pub v_type: VType,
    /// `VV_*` (the file system's) and `VI_*` (the kernel's).
    pub v_flag: u32,
    /// References from descriptors, cwds, roots, mappings, the name cache's callers.
    pub v_usecount: u32,
    /// References that keep the memory but not the file active (the name cache's entries).
    pub v_holdcnt: u32,
    pub v_mount: *mut Mount,
    pub v_op: *const VopVector,
    /// The type's private data (`VfsConf::v_data_size` bytes, zeroed at allocation).
    pub v_data: *mut c_void,
    /// The file's ID within its mount (oxfs's inode number): the hash key with `v_mount`.
    pub v_fileid: u64,
    /// A mount covering this directory, or null.
    pub v_mountedhere: *mut Mount,
    /// The device of a `VCHR`/`VBLK` vnode, in musl's `makedev` encoding (`makedev`).
    pub v_rdev: u64,
    /// Kernel-private: the page cache object, the FIFO or socket rendezvous.
    pub v_object: u64,
    pub v_un: u64,
    /// The vnode below this one holding the same file's contents (a nullfs vnode's lower vnode),
    /// held (`oxidebsd_vhold`) by the file system that set it; null for a vnode that is its own.
    /// The page cache, mappings, FIFOs and sockets name a file by this one (`VFS.md` §13).
    pub v_lower: *mut Vnode,
    /// Kernel-private: descriptors open for writing, and address spaces running it as a program
    /// (`ETXTBSY` either way).
    pub v_writecount: u32,
    pub v_textcount: u32,
}

/// The root directory of its mount.
pub const VV_ROOT: u32 = 0x0001;
/// Kernel: being reclaimed or reclaimed; no file system operation reaches it any more.
pub const VI_DOOMED: u32 = 0x0001_0000;
/// Kernel: inactive (use count 0, `vop_inactive` called).
pub const VI_INACTIVE: u32 = 0x0002_0000;
/// Kernel: inside `vop_inactive`; whatever happens meanwhile leaves freeing it to `vrele`.
pub const VI_ININACT: u32 = 0x0004_0000;

/// A timestamp (`struct timespec`).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// A file's attributes (FreeBSD's `struct vattr`). `getattr` fills every field; `setattr` changes
/// the fields that aren't `VNOVAL` (`VNOVAL_TIME` for times).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vattr {
    pub va_type: VType,
    /// Permission and set-id bits (`0o7777`); the file type is `va_type`.
    pub va_mode: u32,
    pub va_nlink: u64,
    pub va_uid: u32,
    pub va_gid: u32,
    /// `st_dev`: the kernel fills it from the mount.
    pub va_fsid: u64,
    pub va_fileid: u64,
    pub va_size: u64,
    pub va_blocksize: u64,
    pub va_atime: Timespec,
    pub va_mtime: Timespec,
    pub va_ctime: Timespec,
    pub va_birthtime: Timespec,
    pub va_gen: u64,
    /// `chflags(2)` flags.
    pub va_flags: u64,
    pub va_rdev: u64,
    /// Bytes of storage the file holds.
    pub va_bytes: u64,
    /// `VA_*`.
    pub va_vaflags: u32,
}

pub const VNOVAL: u64 = u64::MAX;
/// `va_flags`: a POSIX shared memory object (`shm_open`), whose mappings `mmap` bounds by its size.
pub const VF_SHM: u64 = 1 << 32;
pub const VNOVAL_TIME: Timespec = Timespec { tv_sec: -1, tv_nsec: -1 };
/// `setattr`: the times are the caller's own "now" (`utimensat` with null times), which a non-owner
/// with write permission may set.
pub const VA_UTIMES_NULL: u32 = 1;

impl Vattr {
    /// Every field `VNOVAL`: what `setattr` callers start from (FreeBSD's `VATTR_NULL`).
    pub const NULL: Vattr = Vattr {
        va_type: VNON,
        va_mode: VNOVAL as u32,
        va_nlink: VNOVAL,
        va_uid: VNOVAL as u32,
        va_gid: VNOVAL as u32,
        va_fsid: VNOVAL,
        va_fileid: VNOVAL,
        va_size: VNOVAL,
        va_blocksize: VNOVAL,
        va_atime: VNOVAL_TIME,
        va_mtime: VNOVAL_TIME,
        va_ctime: VNOVAL_TIME,
        va_birthtime: VNOVAL_TIME,
        va_gen: VNOVAL,
        va_flags: VNOVAL,
        va_rdev: VNOVAL,
        va_bytes: VNOVAL,
        va_vaflags: 0,
    };
}

/// The credentials an operation runs with (FreeBSD's `struct ucred`, the part file systems use).
#[repr(C)]
pub struct Ucred {
    /// Effective ids: what permission checks use.
    pub cr_uid: u32,
    pub cr_gid: u32,
    /// Real ids: `access(2)` checks with these.
    pub cr_ruid: u32,
    pub cr_rgid: u32,
    pub cr_ngroups: u32,
    pub cr_groups: [u32; NGROUPS],
}

pub const NGROUPS: usize = 32;

impl Ucred {
    pub fn groupmember(&self, gid: u32) -> bool {
        self.cr_gid == gid || self.cr_groups[..(self.cr_ngroups as usize).min(NGROUPS)].contains(&gid)
    }
}

/// One path component handed to `lookup`, `create`, `remove`, ... (FreeBSD's
/// `struct componentname`). The name isn't NUL-terminated.
#[repr(C)]
pub struct ComponentName {
    /// `LOOKUP`, `CREATE`, `DELETE`, `RENAME`.
    pub cn_nameiop: u32,
    /// `ISLASTCN`, `ISDOTDOT`, `MAKEENTRY`, ...
    pub cn_flags: u32,
    pub cn_cred: *const Ucred,
    pub cn_nameptr: *const u8,
    pub cn_namelen: usize,
}

impl ComponentName {
    /// # Safety
    /// `cn_nameptr` must point at `cn_namelen` readable bytes, as the kernel's always do.
    pub unsafe fn name(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.cn_nameptr, self.cn_namelen) }
    }
}

pub const LOOKUP: u32 = 0;
pub const CREATE: u32 = 1;
pub const DELETE: u32 = 2;
pub const RENAME: u32 = 3;

/// The last component of the path.
pub const ISLASTCN: u32 = 0x0001;
/// The component is `..`.
pub const ISDOTDOT: u32 = 0x0002;
/// The name cache may keep the result.
pub const MAKEENTRY: u32 = 0x0004;

/// `lookup`'s answer for a missing last component of a `CREATE` or `RENAME` lookup the caller may
/// create: not an error, but no vnode (FreeBSD's `EJUSTRETURN`).
pub const EJUSTRETURN: i32 = -2;

/// `access` modes (FreeBSD's `accmode_t` bits).
pub const VEXEC: u32 = 0o100;
pub const VWRITE: u32 = 0o200;
pub const VREAD: u32 = 0o400;
/// Modifiers: check the real ids (`access(2)`), may append only.
pub const VACCESS_REAL: u32 = 0x1000;
pub const VAPPEND: u32 = 0x2000;
/// Owner-only operations: change attributes, delete through a sticky directory.
pub const VADMIN: u32 = 0x4000;

/// `read`/`write` `ioflag` bits.
pub const IO_APPEND: u32 = 0x0002;
pub const IO_SYNC: u32 = 0x0004;
pub const IO_NDELAY: u32 = 0x0010;

/// An opaque kernel `uio` handle: moved with `oxidebsd_uiomove`.
pub type Uio = u64;

/// The vnode operations of one type (FreeBSD's `struct vop_vector`, as a positional table:
/// `VFS.md` §5.2). A null entry takes the kernel's default (`vop_std*`, or `EOPNOTSUPP`).
#[repr(C)]
pub struct VopVector {
    /// Looks `cnp`'s name up in directory `dvp`; `*vpp` gets the file, referenced. For `..`
    /// (`ISDOTDOT`) the parent within the same mount: the kernel handles mount roots. Missing:
    /// `ENOENT`, or `EJUSTRETURN` if it's the last component of a `CREATE`/`RENAME` lookup.
    pub lookup: Option<extern "C" fn(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32>,
    /// Makes a regular file `cnp` in `dvp` with `vap`'s type and mode (umask applied, owner the
    /// caller's); `*vpp` gets it, referenced.
    pub create: Option<
        extern "C" fn(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32,
    >,
    /// As `create`, for a device, FIFO or socket node (`vap.va_type`, `va_rdev`).
    pub mknod: Option<
        extern "C" fn(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32,
    >,
    /// `fflag` is the descriptor's `FREAD`/`FWRITE`/`O_*` flags.
    pub open: Option<extern "C" fn(vp: *mut Vnode, fflag: u32, cred: *const Ucred) -> i32>,
    pub close: Option<extern "C" fn(vp: *mut Vnode, fflag: u32, cred: *const Ucred) -> i32>,
    /// `accmode` is `VREAD`/`VWRITE`/`VEXEC`/`VADMIN`, possibly `VACCESS_REAL`. Most types call the
    /// kernel's `oxidebsd_vaccess` with the file's attributes.
    pub access: Option<extern "C" fn(vp: *mut Vnode, accmode: u32, cred: *const Ucred) -> i32>,
    pub getattr: Option<extern "C" fn(vp: *mut Vnode, vap: *mut Vattr) -> i32>,
    /// The kernel checked permissions for the fields set (`VADMIN`, or `VWRITE` for a size or
    /// `VA_UTIMES_NULL`); the file system applies them.
    pub setattr: Option<extern "C" fn(vp: *mut Vnode, vap: *const Vattr, cred: *const Ucred) -> i32>,
    /// Reads from the uio's offset; returns the bytes moved through the uio, or `-errno`.
    pub read: Option<extern "C" fn(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: *const Ucred) -> i64>,
    pub write: Option<extern "C" fn(vp: *mut Vnode, uio: Uio, ioflag: u32, cred: *const Ucred) -> i64>,
    pub ioctl: Option<extern "C" fn(vp: *mut Vnode, cmd: u64, data: u64, fflag: u32, cred: *const Ucred) -> i32>,
    /// Returns the `POLL*` events of `events` that are ready (not an errno).
    pub poll: Option<extern "C" fn(vp: *mut Vnode, events: u32) -> i32>,
    /// `waitfor` `MNT_WAIT`; `data_only` for `fdatasync`.
    pub fsync: Option<extern "C" fn(vp: *mut Vnode, waitfor: i32, data_only: u32) -> i32>,
    /// Removes name `cnp` (naming `vp`, not a directory) from `dvp`.
    pub remove: Option<extern "C" fn(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32>,
    /// Adds name `cnp` in `tdvp` for `vp` (same mount, not a directory).
    pub link: Option<extern "C" fn(tdvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32>,
    /// Moves `fvp` (named `fcnp` in `fdvp`) to `tcnp` in `tdvp`, replacing `tvp` if not null. Same
    /// mount; the kernel checked the directory cases (`EINVAL` into a descendant, `EISDIR`,
    /// `ENOTDIR`, `ENOTEMPTY` is the file system's).
    pub rename: Option<
        extern "C" fn(
            fdvp: *mut Vnode,
            fvp: *mut Vnode,
            fcnp: *const ComponentName,
            tdvp: *mut Vnode,
            tvp: *mut Vnode,
            tcnp: *const ComponentName,
        ) -> i32,
    >,
    pub mkdir: Option<
        extern "C" fn(dvp: *mut Vnode, vpp: *mut *mut Vnode, cnp: *const ComponentName, vap: *const Vattr) -> i32,
    >,
    pub rmdir: Option<extern "C" fn(dvp: *mut Vnode, vp: *mut Vnode, cnp: *const ComponentName) -> i32>,
    pub symlink: Option<
        extern "C" fn(
            dvp: *mut Vnode,
            vpp: *mut *mut Vnode,
            cnp: *const ComponentName,
            vap: *const Vattr,
            target: *const u8,
            target_len: usize,
        ) -> i32,
    >,
    /// Writes `Dirent` records from the directory position in the uio's offset (a cookie the file
    /// system chose), stores the next position back, and sets `*eofflag` at the end. Returns the
    /// bytes written, or `-errno`; a record that doesn't fit whole isn't written.
    pub readdir: Option<extern "C" fn(vp: *mut Vnode, uio: Uio, cred: *const Ucred, eofflag: *mut i32) -> i64>,
    /// The link's target into the uio; returns its length, or `-errno`.
    pub readlink: Option<extern "C" fn(vp: *mut Vnode, uio: Uio, cred: *const Ucred) -> i64>,
    /// The last use reference went: free an unlinked file's storage.
    pub inactive: Option<extern "C" fn(vp: *mut Vnode) -> i32>,
    /// The kernel recycles the vnode: drop everything `v_data` holds. Never fails.
    pub reclaim: Option<extern "C" fn(vp: *mut Vnode) -> i32>,
    /// File block `lblkno` (of `f_iosize` bytes) to its device sector on the mount's device
    /// (`*bnp`, `u64::MAX` for a hole), and how many following blocks are contiguous after it
    /// (`*runp`). The page cache fills mapped pages from the device with it, never through
    /// `read`; delayed writes of the file are on the device first (the kernel `fsync`s it).
    /// `EOPNOTSUPP` for a file with no device blocks (tmpfs).
    pub bmap: Option<extern "C" fn(vp: *mut Vnode, lblkno: u64, bnp: *mut u64, runp: *mut u64) -> i32>,
    pub pathconf: Option<extern "C" fn(vp: *mut Vnode, name: i32, retval: *mut i64) -> i32>,
    /// `flock(2)`-style locks: `op` is `LOCK_SH`/`LOCK_EX`/`LOCK_UN` with `LOCK_NB`; `id` names the
    /// open file description. The kernel default keeps them per vnode.
    pub advlock: Option<extern "C" fn(vp: *mut Vnode, id: u64, op: u32) -> i32>,
    /// Space for `[offset, offset + len)` (`posix_fallocate`).
    pub allocate: Option<extern "C" fn(vp: *mut Vnode, offset: u64, len: u64) -> i32>,
    /// `revoke(2)`: the kernel default revokes every descriptor of the vnode (deadfs).
    pub revoke: Option<extern "C" fn(vp: *mut Vnode, flags: u32) -> i32>,
}

// SAFETY: as `VfsConf`.
unsafe impl Sync for VopVector {}

impl VopVector {
    /// Every operation the kernel's default: what a type's table starts from with `..`.
    pub const DEFAULT: VopVector = VopVector {
        lookup: None,
        create: None,
        mknod: None,
        open: None,
        close: None,
        access: None,
        getattr: None,
        setattr: None,
        read: None,
        write: None,
        ioctl: None,
        poll: None,
        fsync: None,
        remove: None,
        link: None,
        rename: None,
        mkdir: None,
        rmdir: None,
        symlink: None,
        readdir: None,
        readlink: None,
        inactive: None,
        reclaim: None,
        bmap: None,
        pathconf: None,
        advlock: None,
        allocate: None,
        revoke: None,
    };
}

/// A directory record as `readdir` writes it and `getdents(2)` returns it (musl's `struct
/// dirent`): `d_reclen` bytes, the name NUL-terminated and the record padded to 8.
#[repr(C)]
pub struct Dirent {
    pub d_ino: u64,
    /// The position of the next record (the cookie `readdir` resumes from).
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    // d_name follows.
}

pub const DIRENT_NAME_OFFSET: usize = 19;

/// The size of a record for a name of `name_len` bytes.
pub const fn dirent_reclen(name_len: usize) -> usize {
    (DIRENT_NAME_OFFSET + name_len + 1 + 7) & !7
}

/// Writes one record into `out` (at least `dirent_reclen(name.len())` bytes).
pub fn dirent_encode(out: &mut [u8], ino: u64, next: i64, d_type: u8, name: &[u8]) -> usize {
    let len = dirent_reclen(name.len());
    out[..len].fill(0);
    out[0..8].copy_from_slice(&ino.to_le_bytes());
    out[8..16].copy_from_slice(&next.to_le_bytes());
    out[16..18].copy_from_slice(&(len as u16).to_le_bytes());
    out[18] = d_type;
    out[DIRENT_NAME_OFFSET..DIRENT_NAME_OFFSET + name.len()].copy_from_slice(name);
    len
}

/// `d_type` for a vnode type.
pub const fn vtype_to_dt(t: VType) -> u8 {
    match t {
        VREG => 8,
        VDIR => 4,
        VBLK => 6,
        VCHR => 2,
        VLNK => 10,
        VSOCK => 12,
        VFIFO => 1,
        _ => 0,
    }
}

// --- What the kernel exports to file systems ------------------------------------------------------

unsafe extern "C" {
    /// Registers a type. If it's the root file system's type and no root is mounted yet, the root
    /// is mounted through it now and the result returned (FreeBSD's `vfs_mountroot`, run when the
    /// type arrives).
    pub fn oxidebsd_vfs_register(vfc: *const VfsConf) -> i32;
    /// A new vnode of `mp` with type `vtype`, file ID `fileid` and `vops` (null: the type's),
    /// use count 1, `v_data` zeroed. Not yet in the hash.
    pub fn oxidebsd_getnewvnode(mp: *mut Mount, vtype: VType, fileid: u64, vpp: *mut *mut Vnode) -> i32;
    /// The hash's vnode for `(mp, fileid)`, referenced, or null.
    pub fn oxidebsd_vfs_hash_get(mp: *mut Mount, fileid: u64) -> *mut Vnode;
    /// Enters a vnode from `getnewvnode` into the hash.
    pub fn oxidebsd_vfs_hash_insert(vp: *mut Vnode);
    /// Changes a hashed vnode's file ID (msdosfs's rename).
    pub fn oxidebsd_vfs_hash_rehash(vp: *mut Vnode, fileid: u64);
    /// Whether file `fileid` of `mp` has a vnode in use (a descriptor, a cwd, a mapping): a file
    /// system keeps an unlinked file's storage until it hasn't.
    pub fn oxidebsd_vfs_fileid_busy(mp: *mut Mount, fileid: u64) -> i32;
    /// File `fileid` of `mp` is gone (its storage freed, the ID free for reuse): any vnode of it
    /// is reclaimed (FreeBSD's `vrecycle`).
    pub fn oxidebsd_vfs_recycle(mp: *mut Mount, fileid: u64);
    /// Keeps `vp`'s memory without keeping its file in use (`vhold`/`vdrop`): `v_lower`.
    pub fn oxidebsd_vhold(vp: *mut Vnode);
    pub fn oxidebsd_vdrop(vp: *mut Vnode);
    pub fn oxidebsd_vref(vp: *mut Vnode);
    pub fn oxidebsd_vrele(vp: *mut Vnode);
    /// FreeBSD's `vaccess`: whether `cred` may `accmode` a file of type `vtype`, mode `mode`,
    /// owned by `uid:gid`. `0`, `EACCES` or `EPERM`.
    pub fn oxidebsd_vaccess(vtype: VType, mode: u32, uid: u32, gid: u32, accmode: u32, cred: *const Ucred) -> i32;
}
