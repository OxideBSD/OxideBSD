//! Test-only module for `tests/kern_syscall_smoke.rs` (OxideBSD-doc `KTHREAD.md` §10 step 4): its
//! `module_init` starts a kernel thread of its own, which uses the kernel's exports (§7.1) through
//! `lib/libkthread`: it times out, wakes a second thread of the module's, queues a task on the
//! system's taskqueue three times and drains it, and is woken by another task. Never loaded at
//! boot.
//!
//! One test system call, `SYS_KTHREAD_MOD` (9993): the verdict (0 while the checks run, 1 when all
//! passed, else 2 | the failed checks << 8).
#![no_std]

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};

use kthread_if::{
    EWOULDBLOCK, Task, oxidebsd_kthread_add, oxidebsd_kthread_exit, oxidebsd_kthread_yield, oxidebsd_taskqueue_drain,
    oxidebsd_taskqueue_enqueue, oxidebsd_tsleep, oxidebsd_wakeup, oxidebsd_wakeup_one,
};

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(number: u64, handler: extern "C" fn(u64, u64, u64, u64) -> i64) -> i32;
}

const SYS_KTHREAD_MOD: u64 = 9993;
/// One bit per check in `main`.
const CHECKS: u32 = 5;

static VERDICT: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

static NEVER_CHAN: u8 = 0;
static FLAG: AtomicBool = AtomicBool::new(false);
static WOKE: AtomicBool = AtomicBool::new(false);
static TOLD: AtomicBool = AtomicBool::new(false);
static SLEEPER: AtomicI64 = AtomicI64::new(0);

static COUNTED: Task = Task::new(counted, 0);
static COUNTED_RUNS: AtomicU32 = AtomicU32::new(0);
static COUNTED_PENDING: AtomicU32 = AtomicU32::new(0);
static TELLER: Task = Task::new(teller, 0);

fn chan<T>(x: &'static T) -> usize {
    x as *const T as usize
}

fn log(message: &str) {
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
}

fn result(check: u32, ok: bool) {
    log(if ok { "kthread_smoke: ok\n" } else { "kthread_smoke: FAIL\n" });
    if !ok {
        FAILED.fetch_or(1 << check, Ordering::Relaxed);
    }
}

extern "C" fn counted(_: usize, pending: u32) {
    COUNTED_RUNS.fetch_add(1, Ordering::Relaxed);
    COUNTED_PENDING.store(pending, Ordering::Relaxed);
}

extern "C" fn teller(_: usize, _: u32) {
    TOLD.store(true, Ordering::Relaxed);
    unsafe { oxidebsd_wakeup_one(chan(&TOLD)) };
}

/// Sleeps until `main` sets the flag and wakes it, then exits explicitly.
extern "C" fn sleeper(_: usize) {
    while !FLAG.load(Ordering::Relaxed) {
        unsafe { oxidebsd_tsleep(chan(&FLAG), 0) };
    }
    WOKE.store(true, Ordering::Relaxed);
    unsafe { oxidebsd_kthread_exit() }
}

/// Sleeps on `chan` in ticks of one until `done`, at most `ticks` ticks; whether `done` came.
fn wait(done: impl Fn() -> bool, ticks: u32) -> bool {
    for _ in 0..ticks {
        if done() {
            return true;
        }
        unsafe { oxidebsd_tsleep(chan(&NEVER_CHAN), 1) };
    }
    done()
}

extern "C" fn main(_: usize) {
    // 0: a thread of the module's own.
    result(0, SLEEPER.load(Ordering::Relaxed) > 1);

    // 1: a timeout with no one to wake it.
    result(1, unsafe { oxidebsd_tsleep(chan(&NEVER_CHAN), 2) } == EWOULDBLOCK);

    // 2: wakes the sleeper, which then exits.
    FLAG.store(true, Ordering::Relaxed);
    unsafe { oxidebsd_wakeup(chan(&FLAG)) };
    result(2, wait(|| WOKE.load(Ordering::Relaxed), 100));

    // 3: three enqueues before taskq runs (this thread doesn't give the CPU up between them) are
    // one run told 3; drain returns once it ran.
    for _ in 0..3 {
        unsafe { oxidebsd_taskqueue_enqueue(&COUNTED) };
    }
    unsafe { oxidebsd_taskqueue_drain(&COUNTED) };
    result(3, COUNTED_RUNS.load(Ordering::Relaxed) == 1 && COUNTED_PENDING.load(Ordering::Relaxed) == 3);

    // 4: a task wakes this thread (woken, not timed out).
    unsafe { oxidebsd_taskqueue_enqueue(&TELLER) };
    let mut woken = false;
    for _ in 0..10 {
        if TOLD.load(Ordering::Relaxed) {
            break;
        }
        woken = unsafe { oxidebsd_tsleep(chan(&TOLD), 500) } == 0;
    }
    result(4, woken && TOLD.load(Ordering::Relaxed));

    unsafe { oxidebsd_kthread_yield() };
    let failed = FAILED.load(Ordering::Relaxed) as u64 & ((1 << CHECKS) - 1);
    VERDICT.store(if failed == 0 { 1 } else { 2 | failed << 8 }, Ordering::Relaxed);
}

extern "C" fn handle(_: u64, _: u64, _: u64, _: u64) -> i64 {
    VERDICT.load(Ordering::Relaxed) as i64
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe { oxidebsd_register_syscall(SYS_KTHREAD_MOD, handle) };
    let name = b"kmod-sleeper";
    SLEEPER.store(unsafe { oxidebsd_kthread_add(sleeper, 0, name.as_ptr(), name.len()) }, Ordering::Relaxed);
    let name = b"kmod-main";
    if unsafe { oxidebsd_kthread_add(main, 0, name.as_ptr(), name.len()) } < 0 {
        log("[module] kthread_smoke: no kernel thread\n");
        return 1;
    }
    log("[module] kthread_smoke: module_init running\n");
    0
}
