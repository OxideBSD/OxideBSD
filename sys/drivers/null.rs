//! The memory devices (OxideBSD-doc `DEVFS.md` §3.4): `/dev/null`, `/dev/zero`, and
//! `/dev/random` with `/dev/urandom`, FreeBSD's `null(4)`, `zero(4)` and `random(4)`. Registered at
//! boot (`init`), so they exist with no file system module loaded. Open to all, as on the BSDs.

use crate::fs::fd::{self, FileOps};
use crate::kern::subr_uio::Uio;

/// What a descriptor of `MEM_OPS` is, its file data.
const NULL: u64 = 0;
const ZERO: u64 = 1;
const RANDOM: u64 = 2;

/// Linux's numbers, as BusyBox's `makedevs` and `mknod` users expect.
const DEVICES: [(&str, u32, u32, u64); 4] = [("null", 1, 3, NULL), ("zero", 1, 5, ZERO), ("random", 1, 8, RANDOM), ("urandom", 1, 9, RANDOM)];

/// Registers the devices.
pub fn init() {
    for (name, major, minor, _) in DEVICES {
        let _ = crate::fs::devfs::make_dev(name, major, minor, 0, 0, 0o666, mem_open);
    }
}

extern "C" fn mem_open(major: u64, minor: u64, flags: u64) -> i64 {
    let Some(&(_, _, _, which)) = DEVICES.iter().find(|d| (d.1 as u64, d.2 as u64) == (major, minor)) else {
        return -(crate::syscall::ENXIO as i64);
    };
    if let Err(e) = fd::check_room(1) {
        return -(e as i64);
    }
    let real_fd = fd::oxidebsd_alloc_fd();
    fd::finstall(real_fd, &MEM_OPS, which, fd::open_flag(flags), fd::FdKind::Module)
}

/// Seekable (an `lseek` succeeds and means nothing, as on the BSDs).
static MEM_OPS: FileOps = FileOps {
    flags: fd::DFLAG_SEEKABLE,
    read: Some(mem_read),
    write: Some(mem_write),
    ..FileOps::NONE
};

/// `null` is at end of file; `zero` fills with zeros; `random` with the generator's bytes.
extern "C" fn mem_read(real_fd: u64, uio: *mut Uio, _flags: u64) -> i64 {
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let which = fd::oxidebsd_file_data(real_fd);
    if which == NULL {
        return 0;
    }
    let mut chunk = [0u8; 512];
    let mut total = 0i64;
    while uio.resid() > 0 {
        let n = (uio.resid() as usize).min(chunk.len());
        if which == RANDOM {
            crate::random::oxidebsd_random_bytes(chunk.as_mut_ptr() as u64, n as u64);
        }
        match uio.uiomove_out(&chunk[..n]) {
            Ok(moved) => total += moved as i64,
            Err(e) if total == 0 => return -(e as i64),
            Err(_) => break,
        }
    }
    total
}

/// Every write is taken and thrown away (this kernel has no entropy pool to mix one into).
extern "C" fn mem_write(_real_fd: u64, uio: *mut Uio, _flags: u64) -> i64 {
    // SAFETY: as `mem_read`.
    let uio = unsafe { &mut *uio };
    let n = uio.resid();
    uio.skip(n);
    n as i64
}
