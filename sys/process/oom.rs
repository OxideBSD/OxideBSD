//! The out-of-memory killer (OxideBSD-doc `COW.md` §6).
//!
//! Fork overcommits, so a page a process may write can find no frame when it's needed: a
//! copy-on-write copy, or a stack page. The frame allocator has already taken back what the page
//! cache could give (`pagecache::reclaim`), so the kernel picks the process using the most memory
//! and kills it (`SIGKILL`) to free some.
//!
//! The faulting process may be in ring 3 or in a copy routine in ring 0 (a system call writing a
//! copy-on-write buffer). From ring 3 nothing in the kernel is held -- the fault is as good a place
//! as a system call -- so the victim is terminated on the spot, as `kill(2)` does it, and the
//! faulting instruction runs again. From ring 0 the handler doesn't know what the interrupted
//! system call holds, and terminating a process closes its files, which could need one of those
//! locks: the victim is only sent `SIGKILL` (acted on when it next runs) and the copy fails with
//! `EFAULT`.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{INIT_PID, Pid, Process, ProcState, SIGKILL};
use crate::kern::kern_procctl::OOM_ADJ_MIN;
use crate::serial_println;

/// What the fault handler does next.
pub enum Outcome {
    /// Retry: another process was killed to free memory. The faulting instruction runs again.
    Retry,
    /// The faulter itself is the victim (or nothing else could be): it dies of `SIGKILL`.
    KillFaulter,
    /// The usual fault path: `EFAULT` from a copy routine (a victim was sent `SIGKILL`, if there
    /// was one), or nothing could be done (the process table was busy, or the faulter is pid 1).
    Fail,
}

/// The faulting process found no free frame. `from_user`: the fault interrupted ring 3, so it may
/// sleep here.
pub fn out_of_memory(from_user: bool) -> Outcome {
    let me = super::scheduler::current_pid();
    // Who to kill, chosen under the process table -- unless the interrupted code holds it, when
    // nothing can be chosen safely.
    let (my_tgid, victim, partners) = {
        let Some(table) = super::table().try_lock() else {
            return Outcome::Fail;
        };
        let Some(my_tgid) = table.get(&me).map(|p| p.tgid) else {
            return Outcome::Fail;
        };
        let phys = crate::memory::phys_mem_offset();
        // (pid, score, pages, already sent SIGKILL)
        let mut best: Option<(super::Pid, u64, u64, bool)> = None;
        // One entry per thread group: its leader holds the address space (threads share it).
        for (&pid, proc) in table.iter() {
            if pid != proc.tgid || pid == INIT_PID || matches!(proc.state, ProcState::Zombie(_)) {
                continue;
            }
            let Some(space) = proc.address_space.as_ref() else { continue };
            // The interrupted code may hold this lock: then the process counts as unadjusted.
            let adj = proc.shared.try_lock().map_or(0, |s| s.oom_adj);
            if adj <= OOM_ADJ_MIN {
                continue;
            }
            let pages = space.private_pages(phys);
            let score = pages * (1000 + adj as i64) as u64 / 1000;
            if best.is_none_or(|(_, most, _, _)| score > most) {
                let dying = proc.pending_signals & (1 << (SIGKILL - 1)) != 0;
                best = Some((pid, score, pages, dying));
            }
        }
        let victim = best.map(|(pid, _, pages, dying)| {
            if !dying {
                let name = table.get(&pid).map(|p| p.comm.as_slice()).unwrap_or(b"?");
                serial_println!(
                    "pid {} ({}), {} pages: killed, out of memory",
                    pid,
                    core::str::from_utf8(name).unwrap_or("?"),
                    pages
                );
            }
            (pid, dying)
        });
        let partners = victim.map(|(pid, _)| vfork_partners(&table, pid)).unwrap_or_default();
        (my_tgid, victim, partners)
    };
    // A vfork child and its parent are one address space: the memory goes only if both do.
    for &other in partners.iter().filter(|&&other| other != my_tgid) {
        if from_user {
            super::terminate_thread_group(other, 128 + SIGKILL as i32);
        } else {
            super::signals::post_signal(other, SIGKILL);
        }
    }
    let victim = if partners.contains(&my_tgid) { Some((my_tgid, false)) } else { victim };
    let Some((pid, dying)) = victim.filter(|&(pid, _)| pid != my_tgid) else {
        // The faulter is the biggest, or the only candidate left. Pid 1 is never killed for it.
        if my_tgid == INIT_PID {
            return Outcome::Fail;
        }
        if !from_user {
            // Dies at the end of this system call, after its copy fails.
            super::signals::post_signal(me, SIGKILL);
            return Outcome::Fail;
        }
        return Outcome::KillFaulter;
    };
    if !from_user {
        if !dying {
            super::signals::post_signal(pid, SIGKILL);
        }
        return Outcome::Fail;
    }
    // Even one already sent SIGKILL: it may be blocked somewhere a signal doesn't wake.
    super::terminate_thread_group(pid, 128 + SIGKILL as i32);
    // Its memory is free now -- unless the termination waits for the filesystem lock
    // (`fs::fslock`), when this lets the holder finish first.
    if crate::fs::fslock::busy() {
        super::scheduler::schedule();
    }
    Outcome::Retry
}

/// The thread groups a vfork borrow ties to `tgid`: a vfork child running in its address space,
/// or the parent whose space it runs in (`Process::vfork_parent`). Never pid 1, nor a zombie.
fn vfork_partners(table: &BTreeMap<Pid, Box<Process>>, tgid: Pid) -> Vec<Pid> {
    let mut partners = Vec::new();
    for child in table.values() {
        let Some(parent_tgid) = child.vfork_parent.and_then(|p| table.get(&p)).map(|p| p.tgid) else {
            continue;
        };
        let other = if child.tgid == tgid {
            parent_tgid
        } else if parent_tgid == tgid {
            child.tgid
        } else {
            continue;
        };
        let alive = table.get(&other).is_some_and(|p| !matches!(p.state, ProcState::Zombie(_)));
        if other != INIT_PID && alive && !partners.contains(&other) {
            partners.push(other);
        }
    }
    partners
}
