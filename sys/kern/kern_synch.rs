//! Sleep and wakeup on wait channels (`OxideBSD-doc/KTHREAD.md` §5.3, FreeBSD's `tsleep(9)`), and
//! the load average (OxideBSD-doc `SYSCTL.md` §9), as the BSDs compute it (`kern_synch.c`'s
//! `loadav`): every 5 seconds, the number of runnable threads decays into three averages with time
//! constants of 1, 5 and 15 minutes, in fixed point with `FSCALE` 2048.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::process::{BlockReason, Pid, ProcState, Process};

pub(crate) const FSHIFT: u32 = 11;
pub(crate) const FSCALE: u32 = 1 << FSHIFT;

/// `exp(-5/60)`, `exp(-5/300)`, `exp(-5/900)` in fixed point: FreeBSD's `cexp`.
const CEXP: [u64; 3] = [1884, 2014, 2037];

/// How often a sample is taken, in timer ticks: 5 seconds.
const SAMPLE_TICKS: u64 = 5 * crate::cpu::pit::TIMER_HZ as u64;

/// `vm.loadavg`'s `ldavg`: the 1-, 5- and 15-minute averages.
static AVENRUN: [AtomicU32; 3] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
static NEXT_SAMPLE: AtomicU64 = AtomicU64::new(SAMPLE_TICKS);

/// Threads ready to run or running: what the load average counts (`vm.vmtotal`'s `t_rq`).
pub(crate) fn runnable(table: &BTreeMap<Pid, Box<Process>>) -> u64 {
    table.values().filter(|p| matches!(p.state, ProcState::Ready | ProcState::Running)).count() as u64
}

/// Called by the timer interrupt, with the process table it already holds. A tick that couldn't
/// get the table is made up by the next that can.
pub(crate) fn tick(table: &BTreeMap<Pid, Box<Process>>, now: u64) {
    if now < NEXT_SAMPLE.load(Ordering::Relaxed) {
        return;
    }
    NEXT_SAMPLE.store(now + SAMPLE_TICKS, Ordering::Relaxed);
    let n = runnable(table);
    for (avg, cexp) in AVENRUN.iter().zip(CEXP) {
        let old = avg.load(Ordering::Relaxed) as u64;
        let new = (cexp * old + n * FSCALE as u64 * (FSCALE as u64 - cexp)) >> FSHIFT;
        avg.store(new as u32, Ordering::Relaxed);
    }
}

/// The three averages, scaled by `FSCALE`.
pub(crate) fn averages() -> [u32; 3] {
    [0, 1, 2].map(|i| AVENRUN[i].load(Ordering::Relaxed))
}

/// How a `tsleep` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slept {
    /// Woken (by `wakeup`, or early by anything that makes a thread ready): the caller checks its
    /// condition again.
    Woken,
    /// The timeout passed.
    TimedOut,
}

/// Orders the sleepers on a channel for `wakeup_one`.
static SLEEP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Sleeps on wait channel `chan` until `wakeup(chan)` or, with `timeout`, that many timer ticks
/// (at least one). Not interrupted by signals. The caller checks its condition again when this
/// returns, and sleeps again if it doesn't hold: kernel code runs with interrupts masked, so a
/// wakeup can't fall between its check and this sleep. Not for interrupt handlers.
pub fn tsleep(chan: usize, timeout: Option<u64>) -> Slept {
    let pid = crate::process::scheduler::current_pid();
    assert!(pid != 0, "tsleep with no current thread");
    let deadline = timeout.map_or(u64::MAX, |t| crate::cpu::interrupts::ticks() + t.max(1));
    let seq = SLEEP_SEQ.fetch_add(1, Ordering::Relaxed);
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Some(p) = crate::process::table().lock().get_mut(&pid) {
            p.state = ProcState::Blocked(BlockReason::KernelSleep(chan, deadline, seq));
        }
    });
    crate::process::scheduler::schedule();
    if deadline != u64::MAX && crate::cpu::interrupts::ticks() >= deadline { Slept::TimedOut } else { Slept::Woken }
}

/// Sleeps for `ticks` timer ticks, on a channel no one wakes.
pub fn pause(ticks: u64) {
    let deadline = crate::cpu::interrupts::ticks() + ticks.max(1);
    while crate::cpu::interrupts::ticks() < deadline {
        let left = deadline - crate::cpu::interrupts::ticks();
        tsleep(&SLEEP_SEQ as *const AtomicU64 as usize, Some(left));
    }
}

/// Wakes every thread asleep on `chan`. Never sleeps: interrupt handlers may call it.
pub fn wakeup(chan: usize) {
    let mut table = crate::process::table().lock();
    wake(&mut table, |c, _| c == chan);
}

/// Wakes the thread that has slept longest on `chan`, if any.
pub fn wakeup_one(chan: usize) {
    let mut table = crate::process::table().lock();
    let first = table
        .values()
        .filter_map(|p| match p.state {
            ProcState::Blocked(BlockReason::KernelSleep(c, _, seq)) if c == chan => Some(seq),
            _ => None,
        })
        .min();
    if let Some(first) = first {
        wake(&mut table, |c, seq| c == chan && seq == first);
    }
}

/// The timer's tick: wakes the sleepers whose timeout passed.
pub(crate) fn expire_sleeps(table: &mut BTreeMap<Pid, Box<Process>>, now: u64) {
    for (&pid, p) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::KernelSleep(_, deadline, _)) = p.state
            && now >= deadline
        {
            p.state = ProcState::Ready;
            crate::process::scheduler::enqueue_ready(pid);
        }
    }
}

/// Makes ready every thread asleep on a channel `which(chan, seq)` picks.
fn wake(table: &mut BTreeMap<Pid, Box<Process>>, which: impl Fn(usize, u64) -> bool) {
    for (&pid, p) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::KernelSleep(c, _, seq)) = p.state
            && which(c, seq)
        {
            p.state = ProcState::Ready;
            crate::process::scheduler::enqueue_ready(pid);
        }
    }
}
