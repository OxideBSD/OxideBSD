//! Kernel threads' and taskqueues' interface between the kernel and modules (OxideBSD-doc
//! `KTHREAD.md` §7): `struct task` (FreeBSD's), and the kernel's exports a module calls to make
//! kernel threads, sleep and wake on wait channels, and queue tasks on the system's taskqueue
//! (`taskqueue_thread`, run by the kernel thread `taskq`).
//!
//! Everything here is C ABI, since a module is a separately linked object: a kernel thread's
//! function and a task's are `extern "C"`. A module's threads and tasks run the module's code,
//! which is safe only because modules are never unloaded (§7.2).
#![no_std]

use core::sync::atomic::{AtomicPtr, AtomicU32};

/// A kernel thread's function: called with the thread's argument; returning ends the thread.
pub type KthreadFn = extern "C" fn(arg: usize);

/// A task's function: called with the task's argument and how many enqueues the run absorbed.
pub type TaskFn = extern "C" fn(arg: usize, pending: u32);

/// A task (§6.1): `func(arg, pending)`, and its place in a queue. Its owner keeps it alive for as
/// long as it may be queued (a `static`, usually) and enqueues it by reference; queueing allocates
/// nothing.
#[repr(C)]
pub struct Task {
    pub func: TaskFn,
    pub arg: usize,
    /// The kernel's: enqueues not yet run, 0 while the task isn't queued.
    pub pending: AtomicU32,
    /// The kernel's: the next task in its queue.
    pub next: AtomicPtr<Task>,
}

impl Task {
    pub const fn new(func: TaskFn, arg: usize) -> Task {
        Task { func, arg, pending: AtomicU32::new(0), next: AtomicPtr::new(core::ptr::null_mut()) }
    }
}

/// What `oxidebsd_tsleep` returns when its timeout passed (FreeBSD's `EWOULDBLOCK`, musl's
/// `EAGAIN`).
pub const EWOULDBLOCK: i32 = 11;

unsafe extern "C" {
    /// Makes a kernel thread named `name` (at most 19 bytes kept) calling `func(arg)`: its thread
    /// id, or `-ENOMEM`.
    pub fn oxidebsd_kthread_add(func: KthreadFn, arg: usize, name: *const u8, name_len: usize) -> i64;
    /// Ends the calling kernel thread.
    pub fn oxidebsd_kthread_exit() -> !;
    /// Gives the CPU to any ready thread; returns when the caller runs again.
    pub fn oxidebsd_kthread_yield();
    /// Sleeps on wait channel `chan` until woken or, if `timo` isn't 0, `timo` timer ticks: 0, or
    /// `EWOULDBLOCK` if the timeout passed. The caller checks its condition again either way.
    pub fn oxidebsd_tsleep(chan: usize, timo: u64) -> i32;
    /// Wakes every thread asleep on `chan`. Never sleeps.
    pub fn oxidebsd_wakeup(chan: usize);
    /// Wakes the thread that has slept longest on `chan`.
    pub fn oxidebsd_wakeup_one(chan: usize);
    /// Queues `task` on the system's taskqueue, or counts one more enqueue if it's queued. Never
    /// sleeps or allocates.
    pub fn oxidebsd_taskqueue_enqueue(task: *const Task);
    /// Returns once `task` is neither queued on the system's taskqueue nor running. Sleeps.
    pub fn oxidebsd_taskqueue_drain(task: *const Task);
}
