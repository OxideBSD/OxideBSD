//! Filesystem-adjacent primitives shared across independently-loaded kernel modules: the
//! per-process `(Pid, fd)` table (`fd`, the only coordination point between e.g. `oxfs` and
//! `native_abi` -- modules can't call each other directly), real blocking pipes (`pipe`), real
//! POSIX message queues (`mqueue`), and real SysV IPC (`sysv_msg`/`sysv_sem`/`sysv_shm` -- a
//! distinct subsystem with a distinct lifecycle from `mqueue`, see `sysv_msg`'s own doc comment
//! for the contrast; `sysv_ipc` factors out the `RawIpcPerm`/permission-check plumbing all three
//! share). Real filesystems themselves (`oxfs`, `fat32`) live in `modules/`, not here -- see
//! CLAUDE.md's filesystem section.

pub mod fd;
pub mod mqueue;
pub mod pipe;
pub mod sysv_ipc;
pub mod sysv_msg;
pub mod sysv_sem;
pub mod sysv_shm;

/// What `poll`/`select` can report for one fd right now (`fs::pipe`, `net::tcp`, ...).
#[derive(Clone, Copy, Default)]
pub(crate) struct Readiness {
    /// Data to read, or end-of-file (a read won't block).
    pub readable: bool,
    /// A small write won't block.
    pub writable: bool,
    /// The other side is gone for good.
    pub hangup: bool,
    /// A write would fail (e.g. `EPIPE`).
    pub error: bool,
}
