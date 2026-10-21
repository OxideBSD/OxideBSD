//! The time-sharing scheduler's priorities, as 4.4BSD computes them (FreeBSD's `sched_4bsd.c`,
//! NetBSD's `sched_4bsd.c`): every thread accumulates `estcpu` for each clock tick it runs, which
//! decays once a second by a factor depending on the load average; its user priority is
//!
//! ```text
//! usrpri = PRI_MIN_TIMESHARE + estcpu / INVERSE_ESTCPU_WEIGHT + NICE_WEIGHT * (nice - PRIO_MIN)
//! ```
//!
//! and the scheduler runs the ready thread with the best (lowest) one. A CPU-bound thread's
//! priority worsens as it runs and recovers as it waits, so interactive ones stay responsive and
//! `nice` shifts the balance between CPU-bound ones. Real-time threads (`SCHED_FIFO`,
//! `SCHED_RR`, `sched_priority` 1..=99) come before every time-sharing one, highest first.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use super::limits::{SCHED_FIFO, SCHED_RR};
use super::{Pid, Process};

/// The time-sharing priority range, FreeBSD's.
pub(crate) const PRI_MIN_TIMESHARE: u32 = 120;
pub(crate) const PRI_MAX_TIMESHARE: u32 = 223;
/// `nice` runs `PRIO_MIN..=PRIO_MAX`.
pub(crate) const PRIO_MIN: i32 = -20;
pub(crate) const PRIO_MAX: i32 = 20;
const NICE_WEIGHT: u32 = 1;
const INVERSE_ESTCPU_WEIGHT: u32 = 8;
/// Run queues are four priorities wide on the BSDs; `estcpu` stops where more of it couldn't
/// move a thread to a worse queue (FreeBSD's `ESTCPULIM`).
const RQ_PPQ: u32 = 4;
const ESTCPU_LIMIT: u32 =
    INVERSE_ESTCPU_WEIGHT * (NICE_WEIGHT * (PRIO_MAX - PRIO_MIN) as u32 - RQ_PPQ) + INVERSE_ESTCPU_WEIGHT - 1;

/// A clock tick spent running: one more unit of `estcpu`.
pub(crate) fn charge_tick(p: &mut Process) {
    p.estcpu = (p.estcpu + 1).min(ESTCPU_LIMIT);
}

/// Once a second (`schedcpu`): decays every thread's `estcpu` by `2 * load / (2 * load + 1)`, the
/// load being the one-minute load average, so that about 90% of it is forgotten in `5 * load`
/// seconds (4.4BSD's derivation). With no load it halves.
pub(crate) fn schedcpu(table: &mut BTreeMap<Pid, Box<Process>>) {
    use crate::kern::kern_synch::FSCALE;
    let load = crate::kern::kern_synch::averages()[0] as u64;
    let loadfac = 2 * load;
    let (num, den) = if loadfac == 0 { (1, 2) } else { (loadfac, loadfac + FSCALE as u64) };
    for p in table.values_mut() {
        p.estcpu = (p.estcpu as u64 * num / den) as u32;
    }
}

/// A thread's time-sharing priority (lower is better).
pub(crate) fn usrpri(p: &Process) -> u32 {
    let nice = (p.nice - PRIO_MIN) as u32;
    (PRI_MIN_TIMESHARE + p.estcpu / INVERSE_ESTCPU_WEIGHT + NICE_WEIGHT * nice).min(PRI_MAX_TIMESHARE)
}

/// What the scheduler orders ready threads by, lower first: a real-time thread's place (`100 -
/// sched_priority`, so 1..=99), else a kernel thread's band (`PRI_KERN`, between them as on
/// FreeBSD: `OxideBSD-doc/KTHREAD.md` §4.3), else its time-sharing priority (120..=223). Equal
/// keys run in the order they became ready.
pub(crate) fn key(p: &Process) -> u32 {
    if super::is_kernel_thread(p) {
        PRI_KERN
    } else if matches!(p.sched_policy, SCHED_FIFO | SCHED_RR) && p.sched_priority > 0 {
        REALTIME_KEYS - p.sched_priority.clamp(1, 99) as u32
    } else {
        usrpri(p)
    }
}

/// Keys below this are real-time (`key`).
pub(crate) const REALTIME_KEYS: u32 = 100;
/// Every kernel thread's key: after the real-time ones, before any time-sharing one.
pub(crate) const PRI_KERN: u32 = REALTIME_KEYS;

/// The run queue a key falls in: one per real-time rank, one per `RQ_PPQ` time-sharing
/// priorities, as the BSDs' run queues are. A thread is preempted only by one in a better queue,
/// so neighbouring time-sharing priorities don't switch on every tick.
pub(crate) fn queue_of(key: u32) -> u32 {
    if key < REALTIME_KEYS { key } else { REALTIME_KEYS + (key - REALTIME_KEYS) / RQ_PPQ }
}
