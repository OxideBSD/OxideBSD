//! The filesystem lock (`OxideBSD-doc/RAM_FLOOR.md` §3.5.2): one sleepable, recursive lock that
//! every call from the kernel into a serialized module (oxfs) takes, so only one process at a time
//! is inside the filesystem.
//!
//! oxfs was written for a kernel where a system call never gives up the CPU partway through: its
//! state lives in plain `static mut`s, and nothing guards one operation from another. That held
//! while disk I/O spun with interrupts masked. Once a process sleeps waiting for the disk (§3.5.1),
//! another can run and call into oxfs while the first is midway through changing it; this lock
//! makes the second wait. It's recursive because oxfs calls back into the kernel, and the kernel
//! back into oxfs, on the same process's behalf (closing a descriptor oxfs opened, for one).
//!
//! The holder is a process (a thread: a `Pid`); waiters block through the scheduler and re-check
//! after every wake (`CLAUDE.md`: every blocking `schedule()` loops). Before any process exists
//! (`module_init` at boot, pid 0) there's nothing to serialize against and the lock isn't taken.
//!
//! Terminating another process closes its files, which enters the filesystem; that can't wait for
//! the lock when it runs in an interrupt handler (the keyboard's `^C`), and mustn't when the
//! process being terminated is the one holding it (it would never run to release it). So
//! `terminate_thread_group` asks `busy` first and, if so, hands the termination to
//! `defer_termination`, carried out when the lock is next released. Finer-grained locking is SMP
//! work (v0.5.0).
//!
//! Which calls take the lock: those into a module that asked for it with
//! `oxidebsd_module_serialize` (oxfs), recognised by the address of the function called
//! (`module::is_serialized`). `Guard` takes it for the length of the call.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Mutex;

use crate::process::{self, BlockReason, Pid, ProcState, scheduler};

/// The holder's pid, `0` when free.
static OWNER: AtomicU64 = AtomicU64::new(0);
/// Whether the holder is asleep inside the filesystem (waiting for the disk), so an interrupt
/// arriving now runs on its behalf without it being mid-operation-safe.
static OWNER_ASLEEP: AtomicBool = AtomicBool::new(false);
/// How many times the holder has taken it.
static DEPTH: AtomicU64 = AtomicU64::new(0);
/// Processes blocked in `enter`.
static WAITERS: AtomicU64 = AtomicU64::new(0);
/// Terminations an interrupt handler couldn't carry out while the lock was held:
/// `(thread group to terminate, wait status)`.
static DEFERRED: Mutex<Vec<(Pid, i32)>> = Mutex::new(Vec::new());

/// Takes the lock, sleeping until it's free if another process holds it.
pub fn enter() {
    let me = scheduler::current_pid();
    if me == 0 {
        return;
    }
    loop {
        let owner = OWNER.load(Ordering::Acquire);
        if owner == 0 || owner == me as u64 {
            OWNER.store(me as u64, Ordering::Release);
            DEPTH.fetch_add(1, Ordering::AcqRel);
            return;
        }
        WAITERS.fetch_add(1, Ordering::AcqRel);
        {
            let mut table = process::table().lock();
            if let Some(p) = table.get_mut(&me) {
                p.state = ProcState::Blocked(BlockReason::WaitingForFsLock);
            }
        }
        scheduler::schedule();
        WAITERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Releases one level of the lock; at the last, wakes every waiter and carries out deferred
/// terminations.
pub fn exit() {
    if scheduler::current_pid() == 0 {
        return;
    }
    if DEPTH.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    OWNER.store(0, Ordering::Release);
    // Only with someone waiting: a caller may hold the process table's lock around its call into
    // the filesystem (which must not then sleep), and taking it again here would deadlock.
    if WAITERS.load(Ordering::Acquire) > 0 {
        let mut table = process::table().lock();
        let waiters: Vec<Pid> = table
            .iter()
            .filter(|(_, p)| p.state == ProcState::Blocked(BlockReason::WaitingForFsLock))
            .map(|(&pid, _)| pid)
            .collect();
        for pid in waiters {
            if let Some(p) = table.get_mut(&pid) {
                p.state = ProcState::Ready;
            }
            scheduler::enqueue_ready(pid);
        }
    }
    run_deferred();
}

/// Holds the lock for its lifetime, if `function` (a module function about to be called) belongs
/// to a serialized module; does nothing otherwise.
pub struct Guard(bool);

impl Guard {
    pub fn for_call(function: u64) -> Self {
        let locked = crate::module::is_serialized(function);
        if locked {
            enter();
        }
        Guard(locked)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0 {
            exit();
        }
    }
}

/// Whether entering the filesystem now would have to wait, or would run inside an operation
/// that's asleep partway through: another process holds the lock, or the holder is asleep.
pub fn busy() -> bool {
    let owner = OWNER.load(Ordering::Acquire);
    owner != 0 && (owner != scheduler::current_pid() as u64 || OWNER_ASLEEP.load(Ordering::Acquire))
}

/// Brackets a sleep inside the filesystem that keeps the lock (the disk wait): see `busy`.
pub fn set_owner_asleep(asleep: bool) {
    OWNER_ASLEEP.store(asleep, Ordering::Release);
}

/// Releases the lock entirely for a sleep that waits on another process (a FIFO open waiting for
/// its other end): holding it would deadlock that process's own open. Returns what to pass to
/// `reacquire` afterwards; `0` when the caller didn't hold it.
pub fn release_for_sleep() -> u64 {
    let me = scheduler::current_pid();
    if me == 0 || OWNER.load(Ordering::Acquire) != me as u64 {
        return 0;
    }
    let depth = DEPTH.load(Ordering::Acquire);
    DEPTH.store(1, Ordering::Release);
    exit();
    depth
}

/// Takes the lock back after `release_for_sleep`, at the depth it was held.
pub fn reacquire(depth: u64) {
    if depth == 0 {
        return;
    }
    enter();
    DEPTH.store(depth, Ordering::Release);
}

/// Whether the current process holds the lock (`scheduler::schedule` checks this to report a
/// sleep inside the filesystem that would block every other process's file access).
pub fn held_by_current() -> bool {
    let me = scheduler::current_pid();
    me != 0 && OWNER.load(Ordering::Acquire) == me as u64
}

/// Queues terminating thread group `pid` with wait status `status` until the lock is released.
pub fn defer_termination(pid: Pid, status: i32) {
    DEFERRED.lock().push((pid, status));
}

fn run_deferred() {
    loop {
        let Some((pid, status)) = DEFERRED.lock().pop() else { return };
        let tgid = process::table().lock().get(&pid).map(|p| p.tgid);
        if tgid == Some(scheduler::current_tgid()) && status > 128 {
            // The process releasing the lock is the one to terminate: not from inside its own
            // system call; the signal is left pending, and delivered as it returns.
            process::signals::post_signal(pid, (status - 128) as u64);
        } else {
            process::terminate_thread_group(pid, status);
        }
    }
}
