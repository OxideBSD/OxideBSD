//! `flock(2)` locks, the VFS's default `advlock` (FreeBSD's `vop_stdadvlock`, whole-file locks
//! only): per vnode, held by an open file description (its handle), shared or exclusive. A
//! description's locks go when it's closed or unlocks.
//!
//! A conflicting request fails with `EAGAIN` at once, `LOCK_NB` or not (OxideBSD-doc `CLEANUP.md`:
//! blocking `flock` is still to come).

use alloc::vec::Vec;

use spin::Mutex;
use vfs_if::Vnode;

const EAGAIN: i32 = 11;
const EINVAL: i32 = 22;

pub(crate) const LOCK_SH: u32 = 1;
pub(crate) const LOCK_EX: u32 = 2;
pub(crate) const LOCK_UN: u32 = 8;

/// `(vnode, holder handle, exclusive)`.
static LOCKS: Mutex<Vec<(usize, u64, bool)>> = Mutex::new(Vec::new());

/// `flock(2)` on `vp` for the description `handle` (`LOCK_NB` changes nothing: a conflict never
/// waits yet).
pub(crate) fn flock(vp: *mut Vnode, handle: u64, op: u32) -> i32 {
    let vp = vp as usize;
    let mut locks = LOCKS.lock();
    if op & LOCK_UN != 0 {
        locks.retain(|&(v, h, _)| !(v == vp && h == handle));
        return 0;
    }
    let exclusive = op & LOCK_EX != 0;
    if !exclusive && op & LOCK_SH == 0 {
        return EINVAL;
    }
    if locks.iter().any(|&(v, h, ex)| v == vp && h != handle && (exclusive || ex)) {
        return EAGAIN;
    }
    match locks.iter_mut().find(|(v, h, _)| *v == vp && *h == handle) {
        Some(lock) => lock.2 = exclusive,
        None => locks.push((vp, handle, exclusive)),
    }
    0
}

/// Drops every lock `handle` holds on `vp` (its last close).
pub(crate) fn release_all(vp: *mut Vnode, handle: u64) {
    LOCKS.lock().retain(|&(v, h, _)| !(v == vp as usize && h == handle));
}
