//! Kernel threads (`OxideBSD-doc/KTHREAD.md`), FreeBSD's `kthread(9)`: threads of the kernel
//! process (pid 0, `process::KERNEL_TGID`) that run only kernel code. A kernel thread is an entry
//! of the process table like any thread, sharing the kernel process's address space (no user half)
//! and state (root's credentials); it runs in ring 0 with interrupts masked, as a system call does,
//! and keeps the CPU until it sleeps (`kern_synch::tsleep`), yields or exits (§4). The scheduler
//! runs a ready one before any time-sharing thread (`sched_4bsd::key`), and logs one that ran too
//! long without giving the CPU up (`ran`).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::process::{self, Pid, ProcState, scheduler};
use crate::serial_println;

pub use kthread_if::KthreadFn;

/// How long a kernel thread may run before giving the CPU up without being logged (§4.2).
const HOG_MS: u64 = 100;
/// How many such runs are logged.
const HOG_REPORTS: u32 = 8;
static HOG_REPORTED: AtomicU32 = AtomicU32::new(0);

/// Creates a kernel thread named `name` (at most 19 characters kept) that calls `func(arg)`, and
/// ends when that returns; its thread id, or `ENOMEM`. Created before the scheduler starts, it
/// first runs once the scheduler does.
pub fn kthread_add(func: KthreadFn, arg: usize, name: &str) -> Result<Pid, u64> {
    process::lifecycle::spawn_kernel_thread(func as usize, arg, name.as_bytes())
}

/// Where a new kernel thread starts (`context_switch::seed_kthread_frame`), interrupts masked as
/// the scheduler left them: there's no system call frame, and `func` is a `KthreadFn`.
#[unsafe(no_mangle)]
extern "C" fn kthread_start(func: usize, arg: usize) -> ! {
    crate::syscall::set_current_frame(core::ptr::null_mut());
    // SAFETY: `kthread_add` passed a `KthreadFn` as its address.
    let func: KthreadFn = unsafe { core::mem::transmute(func) };
    func(arg);
    kthread_exit()
}

/// Ends the calling kernel thread. Its entry and kernel stack go once the scheduler has switched
/// off it (`scheduler::queue_thread_reap`).
pub fn kthread_exit() -> ! {
    let pid = scheduler::current_pid();
    {
        let mut table = process::table().lock();
        let thread = table.get_mut(&pid).expect("kthread_exit: current thread missing from table");
        assert!(process::is_kernel_thread(thread), "kthread_exit called by a user thread");
        thread.state = ProcState::Zombie(0);
    }
    scheduler::queue_thread_reap(pid, scheduler::ReapKind::RemoveEntry);
    scheduler::schedule();
    unreachable!("kthread_exit: an exited kernel thread ran again");
}

/// Gives the CPU to any ready thread; returns when the caller runs again.
pub fn kthread_yield() {
    scheduler::schedule();
}

/// Whether `tid` is a kernel thread that hasn't exited.
pub fn alive(tid: Pid) -> bool {
    process::table()
        .lock()
        .get(&tid)
        .is_some_and(|p| process::is_kernel_thread(p) && !matches!(p.state, ProcState::Zombie(_)))
}

/// The scheduler switching off kernel thread `p` after it ran `cycles` TSC cycles: logged, the
/// first few times, past `HOG_MS` (§4.2).
pub(crate) fn ran(p: &process::Process, cycles: u64) {
    let ms = cycles / crate::cpu::tsc::ms_to_cycles(1).max(1);
    if ms > HOG_MS && HOG_REPORTED.fetch_add(1, Ordering::Relaxed) < HOG_REPORTS {
        serial_println!(
            "[kthread] {} ran {} ms without sleeping",
            core::str::from_utf8(&p.comm).unwrap_or("?"),
            ms
        );
    }
}

// --- Module exports (§7.1) ---------------------------------------------------------------------

/// `oxidebsd_kthread_add`: `kthread_add`, its thread id or `-ENOMEM`.
pub(crate) extern "C" fn oxidebsd_kthread_add(func: KthreadFn, arg: usize, name: *const u8, name_len: usize) -> i64 {
    // SAFETY: the module passes its own name bytes.
    let name = unsafe { core::slice::from_raw_parts(name, name_len.min(process::lifecycle::MAXCOMLEN)) };
    match process::lifecycle::spawn_kernel_thread(func as usize, arg, name) {
        Ok(tid) => tid as i64,
        Err(e) => -(e as i64),
    }
}

pub(crate) extern "C" fn oxidebsd_kthread_exit() -> ! {
    kthread_exit()
}

pub(crate) extern "C" fn oxidebsd_kthread_yield() {
    kthread_yield()
}

/// `oxidebsd_tsleep`: `tsleep`, a `timo` of 0 meaning none (FreeBSD's); 0 when woken,
/// `EWOULDBLOCK` when the timeout passed.
pub(crate) extern "C" fn oxidebsd_tsleep(chan: usize, timo: u64) -> i32 {
    match super::kern_synch::tsleep(chan, (timo != 0).then_some(timo)) {
        super::kern_synch::Slept::Woken => 0,
        super::kern_synch::Slept::TimedOut => kthread_if::EWOULDBLOCK,
    }
}

pub(crate) extern "C" fn oxidebsd_wakeup(chan: usize) {
    super::kern_synch::wakeup(chan)
}

pub(crate) extern "C" fn oxidebsd_wakeup_one(chan: usize) {
    super::kern_synch::wakeup_one(chan)
}
