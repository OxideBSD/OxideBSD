//! The load average (OxideBSD-doc `SYSCTL.md` §9), as the BSDs compute it (`kern_synch.c`'s
//! `loadav`): every 5 seconds, the number of runnable threads decays into three averages with time
//! constants of 1, 5 and 15 minutes, in fixed point with `FSCALE` 2048.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::process::{Pid, ProcState, Process};

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
