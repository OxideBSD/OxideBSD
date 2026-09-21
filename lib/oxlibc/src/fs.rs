//! Filesystem syscall wrappers for OxideBSD's native ABI. Every path argument is
//! `(path_ptr, path_len)` -- length-prefixed, never NUL-terminated (see `sys/modules/oxfs`'s own
//! `oxfs_*` handlers); wire formats here were read directly off those handlers, not assumed.

use crate::syscall::{syscall3, syscall4};

const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_GETCWD: u64 = 108;
const SYS_UNLINK: u64 = 109;
const SYS_RMDIR: u64 = 110;
const SYS_RENAME: u64 = 111;
const SYS_LSTAT: u64 = 128;
const SYS_STAT: u64 = 127;
const SYS_GETDENTS: u64 = 129;
const SYS_MKDIR: u64 = 136;
const SYS_SYMLINK: u64 = 155;
const SYS_UTIMENSAT: u64 = 167;
const SYS_LINK: u64 = 488;

pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 0o1;
pub const O_CREAT: u64 = 0o100;
pub const O_TRUNC: u64 = 0o1000;

pub const ENOENT: u64 = 2;
pub const EEXIST: u64 = 17;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

pub const DT_DIR: u8 = 4;

pub fn open(path: &[u8], flags: u64, mode: u64) -> Result<u64, u64> {
    unsafe {
        syscall4(
            SYS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            flags,
            mode,
        )
    }
}

pub fn close(fd: u64) {
    unsafe {
        let _ = syscall3(SYS_CLOSE, fd, 0, 0);
    }
}

pub fn read(fd: u64, buf: &mut [u8]) -> Result<usize, u64> {
    unsafe { syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) }.map(|n| n as usize)
}

pub fn write(fd: u64, buf: &[u8]) -> Result<usize, u64> {
    unsafe { syscall3(SYS_WRITE, fd, buf.as_ptr() as u64, buf.len() as u64) }.map(|n| n as usize)
}

/// The 144-byte musl-layout `struct stat` this kernel writes (`sys/modules/oxfs`'s `MuslStat`).
#[repr(C)]
struct RawStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    _pad0: i32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    _unused: [i64; 3],
}

pub struct Stat {
    pub mode: u32,
    pub size: u64,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
}

impl Stat {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    /// The permission bits only (`0o7777`), as `open(O_CREAT)`'s mode argument wants.
    pub fn perm(&self) -> u64 {
        (self.mode & 0o7777) as u64
    }
}

fn stat_via(number: u64, path: &[u8]) -> Result<Stat, u64> {
    let mut raw = core::mem::MaybeUninit::<RawStat>::zeroed();
    unsafe {
        syscall3(
            number,
            path.as_ptr() as u64,
            path.len() as u64,
            raw.as_mut_ptr() as u64,
        )?;
        let raw = raw.assume_init();
        Ok(Stat {
            mode: raw.st_mode,
            size: raw.st_size as u64,
            nlink: raw.st_nlink,
            uid: raw.st_uid,
            gid: raw.st_gid,
            mtime: raw.st_mtime,
        })
    }
}

/// `stat(2)`: follows a final symlink.
pub fn stat(path: &[u8]) -> Result<Stat, u64> {
    stat_via(SYS_STAT, path)
}

/// `lstat(2)`: doesn't follow a final symlink.
pub fn lstat(path: &[u8]) -> Result<Stat, u64> {
    stat_via(SYS_LSTAT, path)
}

pub fn mkdir(path: &[u8]) -> Result<(), u64> {
    unsafe { syscall3(SYS_MKDIR, path.as_ptr() as u64, path.len() as u64, 0) }.map(|_| ())
}

pub fn unlink(path: &[u8]) -> Result<(), u64> {
    unsafe { syscall3(SYS_UNLINK, path.as_ptr() as u64, path.len() as u64, 0) }.map(|_| ())
}

pub fn rmdir(path: &[u8]) -> Result<(), u64> {
    unsafe { syscall3(SYS_RMDIR, path.as_ptr() as u64, path.len() as u64, 0) }.map(|_| ())
}

pub fn rename(old: &[u8], new: &[u8]) -> Result<(), u64> {
    unsafe {
        syscall4(
            SYS_RENAME,
            old.as_ptr() as u64,
            old.len() as u64,
            new.as_ptr() as u64,
            new.len() as u64,
        )
    }
    .map(|_| ())
}

/// Hard link: `new` becomes another name for `existing`.
pub fn link(existing: &[u8], new: &[u8]) -> Result<(), u64> {
    unsafe {
        syscall4(
            SYS_LINK,
            existing.as_ptr() as u64,
            existing.len() as u64,
            new.as_ptr() as u64,
            new.len() as u64,
        )
    }
    .map(|_| ())
}

/// Symbolic link at `linkpath` pointing at `target` (stored verbatim, never resolved here).
pub fn symlink(target: &[u8], linkpath: &[u8]) -> Result<(), u64> {
    unsafe {
        syscall4(
            SYS_SYMLINK,
            target.as_ptr() as u64,
            target.len() as u64,
            linkpath.as_ptr() as u64,
            linkpath.len() as u64,
        )
    }
    .map(|_| ())
}

/// `utimensat(AT_FDCWD, path, NULL, 0)`'s shape on this ABI (the `fd` argument is dropped -- see
/// `sys/modules/oxfs`'s `oxfs_utimensat`). Today that handler is a real existence check (`ENOENT`
/// for a missing path) and a no-op otherwise, which is exactly what `touch` needs to decide
/// whether to create the file.
pub fn utimensat(path: &[u8]) -> Result<(), u64> {
    unsafe { syscall4(SYS_UTIMENSAT, path.as_ptr() as u64, path.len() as u64, 0, 0) }.map(|_| ())
}

/// Writes the current directory (no trailing NUL) into `buf`, returning its length.
pub fn getcwd(buf: &mut [u8]) -> Result<usize, u64> {
    let n = unsafe { syscall3(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64, 0) }? as usize;
    Ok(n.saturating_sub(1)) // the kernel's count includes the trailing NUL
}

/// One `getdents` call: fills `buf` with as many whole `dirent64` records as fit, returning the
/// byte count (`0` once the directory is exhausted).
pub fn getdents(fd: u64, buf: &mut [u8]) -> Result<usize, u64> {
    unsafe { syscall3(SYS_GETDENTS, fd, buf.as_mut_ptr() as u64, buf.len() as u64) }
        .map(|n| n as usize)
}

/// Iterates the `dirent64` records (`d_ino: u64, d_off: i64, d_reclen: u16, d_type: u8,
/// d_name: NUL-terminated`) in a buffer `getdents` filled, yielding `(name, d_type)`.
pub struct Dirents<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dirents<'a> {
    pub fn new(buf: &'a [u8]) -> Dirents<'a> {
        Dirents { buf, pos: 0 }
    }
}

impl<'a> Iterator for Dirents<'a> {
    type Item = (&'a [u8], u8);

    fn next(&mut self) -> Option<(&'a [u8], u8)> {
        let rec = self.buf.get(self.pos..)?;
        if rec.len() < 19 {
            return None;
        }
        let reclen = u16::from_le_bytes([rec[16], rec[17]]) as usize;
        if reclen < 19 || reclen > rec.len() {
            return None;
        }
        let dtype = rec[18];
        let name_field = &rec[19..reclen];
        let name_len = name_field
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_field.len());
        self.pos += reclen;
        Some((&name_field[..name_len], dtype))
    }
}

/// `true` for the `.`/`..` entries every directory listing carries.
pub fn is_dot_or_dotdot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}
