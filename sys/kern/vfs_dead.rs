//! deadfs (FreeBSD's `fs/deadfs`): what a revoked descriptor is. `revoke(2)` and a forced
//! unmount (`MNT_FORCE`) close a descriptor's file under it and give it these operations, so the
//! process keeps the number but the file is gone: reads are at end of file, writes and the rest
//! fail, `poll` says hung up. The vnodes themselves are doomed (`vfs_subr::vgone`), and their
//! operations the defaults `kern::vnode_if` gives a doomed vnode.

use crate::fs::fd::{self, FileOps, POLL_HANGUP, POLL_READABLE};
use crate::kern::subr_uio::Uio;

const EIO: i64 = 5;
const EBADF: i64 = 9;

extern "C" fn dead_read(_handle: u64, _uio: *mut Uio, _flags: u64) -> i64 {
    0
}

extern "C" fn dead_write(_handle: u64, _uio: *mut Uio, _flags: u64) -> i64 {
    -EIO
}

extern "C" fn dead_ioctl(_handle: u64, _request: u64, _arg: u64) -> i64 {
    -EBADF
}

extern "C" fn dead_poll(_handle: u64, _events: u64) -> i64 {
    POLL_READABLE | POLL_HANGUP
}

extern "C" fn dead_stat(_handle: u64, _out: u64) -> i64 {
    -EBADF
}

extern "C" fn dead_truncate(_handle: u64, _len: u64) -> i64 {
    -EBADF
}

extern "C" fn dead_sync(_handle: u64, _data_only: u64) -> i64 {
    -EBADF
}

pub(crate) static DEAD_OPS: FileOps = FileOps {
    flags: fd::DFLAG_SEEKABLE,
    read: Some(dead_read),
    write: Some(dead_write),
    close: None,
    ioctl: Some(dead_ioctl),
    poll: Some(dead_poll),
    stat: Some(dead_stat),
    truncate: Some(dead_truncate),
    sync: Some(dead_sync),
    fb_geometry: None,
};
