//! Taskqueues (`OxideBSD-doc/KTHREAD.md` §6), FreeBSD's `taskqueue(9)`: a task is a function and
//! its argument, queued (`enqueue`, which interrupt handlers may call: it neither sleeps nor
//! allocates) to be called once by the queue's kernel threads. A task enqueued again before it runs
//! runs once, told how many enqueues it absorbed; one enqueued again while it runs runs again.
//!
//! `TASKQUEUE_THREAD` is the system's queue, run by one kernel thread, `taskq`, started once pid 1
//! exists (`start_system`, from `scheduler::start`): tasks queued before then wait for it.

use core::sync::atomic::Ordering;

use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

use super::kern_kthread::kthread_add;
use super::kern_synch::{tsleep, wakeup};

/// The task structure, shared with modules (§7): `kthread_if::Task`.
pub use kthread_if::{Task, TaskFn};

/// A queue's tasks, first to run first, and the one running.
struct Queued {
    head: *const Task,
    tail: *const Task,
    running: *const Task,
}

// SAFETY: the pointers are to `'static` tasks, and only touched under the queue's lock.
unsafe impl Send for Queued {}

pub struct Taskqueue {
    name: &'static str,
    queued: Mutex<Queued>,
}

impl Taskqueue {
    pub const fn new(name: &'static str) -> Taskqueue {
        Taskqueue {
            name,
            queued: Mutex::new(Queued { head: core::ptr::null(), tail: core::ptr::null(), running: core::ptr::null() }),
        }
    }

    /// The channel the queue's threads sleep on for work.
    fn work_chan(&self) -> usize {
        self as *const Taskqueue as usize
    }

    /// The channel `drain` sleeps on for a task to finish.
    fn done_chan(&self) -> usize {
        &self.queued as *const Mutex<Queued> as usize
    }
}

/// The system's queue (§6.4).
pub static TASKQUEUE_THREAD: Taskqueue = Taskqueue::new("taskq");

/// Queues `task` on `queue`, or, if it's queued already, counts one more enqueue for it; wakes the
/// queue's threads. Never sleeps or allocates.
/// Interrupts are masked throughout: at boot, before the scheduler, they're enabled, and an
/// interrupt handler enqueueing on top of a holder of the queue's lock would deadlock.
pub fn enqueue(queue: &'static Taskqueue, task: &'static Task) {
    without_interrupts(|| {
        {
            let mut q = queue.queued.lock();
            let n = task.pending.load(Ordering::Relaxed);
            if n > 0 {
                task.pending.store(n.saturating_add(1), Ordering::Relaxed);
                return;
            }
            task.pending.store(1, Ordering::Relaxed);
            task.next.store(core::ptr::null_mut(), Ordering::Relaxed);
            if q.tail.is_null() {
                q.head = task;
            } else {
                // SAFETY: a queued task, alive as long as it's queued.
                unsafe { (*q.tail).next.store(task as *const Task as *mut Task, Ordering::Relaxed) };
            }
            q.tail = task;
        }
        wakeup(queue.work_chan());
    })
}

/// Returns once `task` is neither queued on `queue` nor running there. Sleeps.
pub fn drain(queue: &'static Taskqueue, task: &'static Task) {
    loop {
        {
            let q = queue.queued.lock();
            if task.pending.load(Ordering::Relaxed) == 0 && !core::ptr::eq(q.running, task) {
                return;
            }
        }
        tsleep(queue.done_chan(), Some(1));
    }
}

/// A queue's thread: runs its tasks in order, sleeping while there are none.
extern "C" fn run(queue: usize) {
    // SAFETY: `start_threads` passes a `&'static Taskqueue`.
    let queue: &'static Taskqueue = unsafe { &*(queue as *const Taskqueue) };
    loop {
        let next = {
            let mut q = queue.queued.lock();
            let task = q.head;
            if !task.is_null() {
                // SAFETY: a queued task, alive as long as it's queued.
                let t = unsafe { &*task };
                q.head = t.next.load(Ordering::Relaxed);
                if q.head.is_null() {
                    q.tail = core::ptr::null();
                }
                q.running = task;
                Some((t, t.pending.swap(0, Ordering::Relaxed)))
            } else {
                None
            }
        };
        match next {
            Some((task, pending)) => {
                (task.func)(task.arg, pending);
                queue.queued.lock().running = core::ptr::null();
                wakeup(queue.done_chan());
            }
            // Interrupts are masked: an enqueue can't fall between the check and the sleep.
            None => {
                tsleep(queue.work_chan(), None);
            }
        }
    }
}

/// Starts `n` kernel threads named after `queue` to run its tasks.
pub fn start_threads(queue: &'static Taskqueue, n: usize) -> Result<(), u64> {
    for _ in 0..n {
        kthread_add(run, queue as *const Taskqueue as usize, queue.name)?;
    }
    Ok(())
}

/// A queue of a subsystem's own (§6.4), threads started with `start_threads`.
pub fn create(name: &'static str) -> &'static Taskqueue {
    alloc::boxed::Box::leak(alloc::boxed::Box::new(Taskqueue::new(name)))
}

/// Starts `TASKQUEUE_THREAD`'s thread, `taskq`: once, after pid 1 is made (kernel threads'
/// ids would otherwise take its number in a kernel that numbers pid 1 itself).
pub fn start_system() {
    static STARTED: spin::Once<()> = spin::Once::new();
    STARTED.call_once(|| {
        start_threads(&TASKQUEUE_THREAD, 1).expect("taskqueue: no memory for the taskq thread");
    });
}

/// `oxidebsd_taskqueue_enqueue` (§7.1): `enqueue` on the system's queue, for modules.
pub(crate) extern "C" fn oxidebsd_taskqueue_enqueue(task: *const Task) {
    // SAFETY: a module's task lives as long as the module, which is never unloaded (§7.2).
    enqueue(&TASKQUEUE_THREAD, unsafe { &*task });
}

/// `oxidebsd_taskqueue_drain` (§7.1): `drain` on the system's queue, for modules.
pub(crate) extern "C" fn oxidebsd_taskqueue_drain(task: *const Task) {
    // SAFETY: as `oxidebsd_taskqueue_enqueue`.
    drain(&TASKQUEUE_THREAD, unsafe { &*task });
}
