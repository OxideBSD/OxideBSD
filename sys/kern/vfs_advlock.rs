//! `flock(2)` locks, the VFS's default `advlock` (FreeBSD's `vop_stdadvlock`, whole-file locks
//! only): per vnode, held by an open file description (its handle), shared or exclusive. A
//! description's locks go when it's closed or unlocks.
//!
//! A conflicting request waits until the lock is free (`LOCK_NB`: fails with `EWOULDBLOCK` at
//! once), interrupted by a caught signal (`EINTR`). Converting a held lock to a conflicting kind
//! gives up the old one first, as on the BSDs: the conversion isn't atomic.

use alloc::vec::Vec;

use spin::Mutex;
use vfs_if::Vnode;

use crate::process::{BlockReason, ProcState};

const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EINVAL: i32 = 22;

pub(crate) const LOCK_SH: u32 = 1;
pub(crate) const LOCK_EX: u32 = 2;
pub(crate) const LOCK_NB: u32 = 4;
pub(crate) const LOCK_UN: u32 = 8;

/// `(vnode, holder handle, exclusive)`.
static LOCKS: Mutex<Vec<(usize, u64, bool)>> = Mutex::new(Vec::new());

/// `flock(2)` on `vp` for the description `handle`. Called inside the file system's lock, which a
/// wait gives up while asleep (`fslock::release_for_sleep`): the holder unlocks through it.
pub(crate) fn flock(vp: *mut Vnode, handle: u64, op: u32) -> i32 {
    let vp = vp as usize;
    let exclusive = op & LOCK_EX != 0;
    if op & LOCK_UN == 0 && !exclusive && op & LOCK_SH == 0 {
        return EINVAL;
    }
    let pid = crate::process::scheduler::current_pid();
    loop {
        let mut gave_up = false;
        {
            let mut locks = LOCKS.lock();
            if op & LOCK_UN != 0 {
                locks.retain(|&(v, h, _)| !(v == vp && h == handle));
                drop(locks);
                wake_waiters(vp);
                return 0;
            }
            if !locks.iter().any(|&(v, h, ex)| v == vp && h != handle && (exclusive || ex)) {
                match locks.iter_mut().find(|(v, h, _)| *v == vp && *h == handle) {
                    Some(lock) => {
                        gave_up = lock.2 && !exclusive; // a downgrade lets shared waiters in
                        lock.2 = exclusive;
                    }
                    None => locks.push((vp, handle, exclusive)),
                }
                drop(locks);
                if gave_up {
                    wake_waiters(vp);
                }
                return 0;
            }
            // A conversion that has to wait gives up the lock it holds first.
            let before = locks.len();
            locks.retain(|&(v, h, _)| !(v == vp && h == handle));
            gave_up = locks.len() != before;
            if op & LOCK_NB != 0 {
                drop(locks);
                if gave_up {
                    wake_waiters(vp);
                }
                return EAGAIN;
            }
            if let Some(p) = crate::process::table().lock().get_mut(&pid) {
                p.state = ProcState::Blocked(BlockReason::WaitingForFlock(vp as u64));
            }
        }
        if gave_up {
            wake_waiters(vp);
        }
        let held = crate::fs::fslock::release_for_sleep();
        crate::process::scheduler::schedule();
        crate::fs::fslock::reacquire(held);
        if crate::process::signals::has_interrupting_signal_now(pid) {
            return EINTR;
        }
    }
}

/// Wakes every process waiting for a lock on `vp`; each looks again.
fn wake_waiters(vp: usize) {
    let mut table = crate::process::table().lock();
    for (&pid, p) in table.iter_mut() {
        if p.state == ProcState::Blocked(BlockReason::WaitingForFlock(vp as u64)) {
            p.state = ProcState::Ready;
            crate::process::scheduler::enqueue_ready(pid);
        }
    }
}

/// Drops every lock `handle` holds on `vp` (its last close).
pub(crate) fn release_all(vp: *mut Vnode, handle: u64) {
    let vp = vp as usize;
    let mut locks = LOCKS.lock();
    let before = locks.len();
    locks.retain(|&(v, h, _)| !(v == vp && h == handle));
    let released = locks.len() != before;
    drop(locks);
    if released {
        wake_waiters(vp);
    }
}
