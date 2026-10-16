//! The system calls every descriptor answers, whatever file it is (FreeBSD's `kern_descrip.c`,
//! OxideBSD-doc `VFS.md` §6.4): `close`, `lseek`, `fstat`, `ftruncate`, `fsync` and `fdatasync`,
//! through the file's operations (`fs::fd::FileOps`). `ioctl` is `syscall::ffi::sys_ioctl`. The
//! `vfs` module registers them (`sys/modules/vfs`).
//!
//! A file whose table lacks an operation gets the POSIX answer for "not a file this works on":
//! `ESPIPE` for `lseek` without `DFLAG_SEEKABLE` (pipes, sockets, terminals), `EINVAL` for
//! `ftruncate`, `fsync` and `fdatasync`.

use crate::fs::fd::{self, DFLAG_SEEKABLE, FWRITE};
use crate::memory::usercopy::{UserPtr, copyout};
use crate::syscall::{EBADF, EINVAL, EOVERFLOW, ESPIPE};

/// musl's x86_64 `struct stat`: 144 bytes, `st_mode` at byte 24, `st_size` at byte 48.
const STAT_SIZE: usize = 144;
const ST_MODE: usize = 24;
const ST_SIZE: usize = 48;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_END: u64 = 2;

fn ret(r: Result<u64, u64>) -> i64 {
    match r {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    }
}

/// Calls one of a file's operations under the filesystem lock its module may need, as the fd
/// layer's read and write do; it may wait on the disk.
fn call<R>(op: usize, f: impl FnOnce() -> R) -> R {
    let _lock = crate::fs::fslock::Guard::for_call_sleepable(op as u64);
    f()
}

/// `close(2)`, system call 6.
pub(crate) extern "C" fn oxidebsd_sys_close(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    if fd::oxidebsd_close_fd(fd) == 0 { 0 } else { -(EBADF as i64) }
}

/// A file's `struct stat`, from its `stat` operation (or the fallback), into a kernel buffer.
fn stat_of(real_fd: u64, ops: &fd::FileOps) -> Result<[u64; STAT_SIZE / 8], u64> {
    let stat = fd::stat_op(ops).ok_or(EBADF)?;
    let mut buf = [0u64; STAT_SIZE / 8];
    let r = call(stat as usize, || stat(real_fd, buf.as_mut_ptr() as u64));
    if r < 0 { Err(r.unsigned_abs()) } else { Ok(buf) }
}

fn stat_field<T: Copy>(buf: &[u64; STAT_SIZE / 8], at: usize) -> T {
    // SAFETY: `at` is a field offset inside the 144-byte buffer.
    unsafe { core::ptr::read_unaligned((buf.as_ptr() as *const u8).add(at) as *const T) }
}

/// `fstat(2)`, system call 126: the file's `stat` operation fills a kernel `struct stat`, copied
/// out whole.
pub(crate) extern "C" fn oxidebsd_sys_fstat(fd: u64, buf_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    ret((|| {
        let (real_fd, ops, _, _) = fd::file(fd).ok_or(EBADF)?;
        let buf = stat_of(real_fd, ops)?;
        // SAFETY: plain integers.
        let bytes = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, STAT_SIZE) };
        copyout(bytes, UserPtr::new(buf_ptr))?;
        Ok(0)
    })())
}

/// `lseek(2)`, system call 8, on the offset the kernel keeps for a seekable file: `ESPIPE` for one
/// that isn't. `SEEK_END` counts from `st_size`; a directory's offset is its record cursor, which
/// has no end to count from (`EINVAL`). A result before the start is `EINVAL`, one past `off_t`
/// `EOVERFLOW`.
pub(crate) extern "C" fn oxidebsd_sys_lseek(fd: u64, offset: u64, whence: u64, _a3: u64) -> i64 {
    ret((|| {
        let (real_fd, ops, _, current) = fd::file(fd).ok_or(EBADF)?;
        if ops.flags & DFLAG_SEEKABLE == 0 {
            return Err(ESPIPE);
        }
        let offset = offset as i64;
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => current as i64,
            SEEK_END => {
                let buf = stat_of(real_fd, ops).map_err(|_| EINVAL)?;
                if stat_field::<u32>(&buf, ST_MODE) & S_IFMT == S_IFDIR {
                    return Err(EINVAL);
                }
                stat_field::<i64>(&buf, ST_SIZE)
            }
            _ => return Err(EINVAL),
        };
        let new = base.checked_add(offset).ok_or(EOVERFLOW)?;
        if new < 0 {
            return Err(EINVAL);
        }
        fd::set_offset(real_fd, new as u64);
        Ok(new as u64)
    })())
}

/// `ftruncate(2)`, system call 473: `EINVAL` when the file isn't open for writing (POSIX) or can't
/// be truncated (a pipe, a socket: no `truncate` operation).
pub(crate) extern "C" fn oxidebsd_sys_ftruncate(fd: u64, length: u64, _a2: u64, _a3: u64) -> i64 {
    ret((|| {
        let (real_fd, ops, flag, _) = fd::file(fd).ok_or(EBADF)?;
        if (length as i64) < 0 || flag & FWRITE == 0 {
            return Err(EINVAL);
        }
        let truncate = ops.truncate.ok_or(EINVAL)?;
        let r = call(truncate as usize, || truncate(real_fd, length));
        if r < 0 { Err(r.unsigned_abs()) } else { Ok(0) }
    })())
}

fn sync(fd: u64, data_only: u64) -> i64 {
    ret((|| {
        let (real_fd, ops, _, _) = fd::file(fd).ok_or(EBADF)?;
        let sync = ops.sync.ok_or(EINVAL)?;
        let r = call(sync as usize, || sync(real_fd, data_only));
        if r < 0 { Err(r.unsigned_abs()) } else { Ok(0) }
    })())
}

/// `fsync(2)`, system call 471: `EINVAL` for a file that can't be synchronized (POSIX: a pipe, a
/// socket).
pub(crate) extern "C" fn oxidebsd_sys_fsync(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    sync(fd, 0)
}

/// `fdatasync(2)`, system call 75: as `fsync`, data only.
pub(crate) extern "C" fn oxidebsd_sys_fdatasync(fd: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    sync(fd, 1)
}
