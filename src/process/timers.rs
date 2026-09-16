//! nanosleep/itimer syscalls -- split out of the original process.rs.



use crate::syscall::{EAGAIN, EINTR, EINVAL};
use super::*;

/// musl's own `struct timespec` on x86_64 -- see `src/syscall.rs`'s `RawTimespec` (duplicated
/// here rather than shared, same "no shared crate across this internal ABI boundary" convention
/// this file's own `SYS_OPEN`/`SYS_READ`/`SYS_CLOSE` constants above already follow).
#[derive(Clone, Copy)]
#[repr(C)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// `SYS_NANOSLEEP` — matches real `nanosleep(2)`'s exact `(req_ptr, rem_ptr)` wire format (musl's
/// own `nanosleep()`, calling through `__clock_nanosleep(CLOCK_REALTIME, 0, req, rem)`, reduces to
/// exactly this shape whenever `flags == 0`, the common case), so only the number needed
/// remapping.
///
/// Converts the requested duration into an absolute wake-up tick deadline (`src/pit.rs`'s
/// `TIMER_HZ` ground truth, the same one `src/syscall.rs`'s `sys_clock_gettime` already uses for
/// `CLOCK_MONOTONIC`), blocks the caller (`BlockReason::Sleeping`), and lets
/// `interrupts::timer_interrupt_handler` do the actual waking once that many ticks have passed —
/// the same block-then-`scheduler::schedule()` shape `WaitingForPipeData`/`WaitingForStdin`
/// already established, just woken by a timer IRQ instead of another process's syscall. Rounds the
/// requested duration *up* to a whole tick (never sleeps for less than asked, consistent with real
/// `nanosleep`'s own "at least this long" contract) — a `{0, 0}` request returns immediately
/// without ever blocking at all.
///
/// **Real signal-interrupts-sleep support**: a signal that will invoke a caught handler (real
/// POSIX `nanosleep(2)`'s own interruption contract) now wakes this loop early via
/// `process::signals::wake_if_sleeping` (called from the same `Action::SetPending` sites
/// `do_pause`'s own `wake_if_paused` already is) rather than leaving the caller genuinely
/// `Blocked` until its own deadline naturally passes — found live chasing the Open POSIX Test
/// Suite pilot's `nanosleep/1-3.c`, which forks a child that `nanosleep()`s for 30 real seconds and
/// expects a `SIGABRT` sent 1 second in to cut that short. `rem_ptr` (if non-null) reports the real
/// remaining time (`deadline - ticks()`, converted back to a timespec) on this `EINTR` path — a
/// zeroed `rem_ptr` only for the ordinary "slept the full requested duration" success path. A
/// `SIGKILL`-style immediate, no-handler termination still doesn't go through this path at all
/// (`do_kill`'s own `Action::Terminate` calls `terminate_process` directly, unaffected by this
/// process's `ProcState`).
///
/// **Real HPET top-off, when a real HPET is present** (found live chasing `timer_getoverrun/
/// 2-3.c`): the tick-deadline loop above and `PosixTimer::deadline_ns`'s own real HPET-based
/// overrun accounting are two genuinely independent clocks -- `ticks()` (PIT-interrupt-driven) can
/// measurably lag a directly-read HPET counter by a handful of milliseconds over a long sleep
/// (real PIT interrupt-delivery latency under this project's own `-accel kvm` setup, not a TCG
/// software-emulation artifact), enough for a `nanosleep()`-then-`timer_getoverrun()` sequence to
/// undercount real elapsed HPET time. Once the tick deadline is reached, this loop keeps
/// re-blocking on that same (now-past) deadline -- the timer IRQ handler's own `now >= deadline`
/// wake check (`interrupts.rs`) fires again on the very next tick regardless, so this is still a
/// real, cheap, yielding `schedule()` wait, not a busy-spin -- until `cpu::hpet::now_ns()` also
/// reaches the equivalent real-nanosecond target, capped at `HPET_TOPOFF_TICK_CAP` extra ticks as
/// a defensive bound against a pathological/stuck HPET reading (never observed, but this is a
/// syscall-reachable loop, so it gets the same "never trust it unconditionally" treatment as every
/// other one in this codebase). A complete no-op whenever no real HPET was found this boot.
pub fn do_nanosleep(pid: Pid, req_ptr: u64, rem_ptr: u64) -> Result<u64, u64> {
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has -- req_ptr isn't checked against the caller's actual mappings first.
    let req = unsafe { *(req_ptr as *const RawTimespec) };
    if req.tv_sec < 0 || !(0..1_000_000_000).contains(&req.tv_nsec) {
        return Err(EINVAL);
    }

    // Real HPET-precision target, computed up front (before any blocking) whenever a real HPET
    // is present -- see the real top-off spin-wait at the end of this function for why. `None`
    // whenever no real HPET was found this boot; the existing tick-only behavior is completely
    // unaffected in that case.
    let hpet_target_ns = timespec_to_ns(req.tv_sec, req.tv_nsec)
        .and_then(|req_ns| crate::cpu::hpet::now_ns().map(|now_ns| now_ns + req_ns));

    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let whole_second_ticks = req.tv_sec as u64 * hz;
    let sub_second_ticks = (req.tv_nsec as u64 * hz).div_ceil(1_000_000_000);
    let requested_ticks = whole_second_ticks + sub_second_ticks;

    if requested_ticks > 0 {
        let deadline = crate::cpu::interrupts::ticks() + requested_ticks;
        // Loops and re-checks the real deadline, the same self-correcting pattern
        // `crate::fs::pipe`/`crate::console::stdin::read` already use -- normally the timer IRQ
        // handler is the only thing that ever sets this process back to `Ready` (only once the
        // real deadline has actually passed), so a single `schedule()` call used to be enough.
        // Real `SIGCONT` resuming a `Stopped` process (see `ProcState::Stopped`'s own doc comment)
        // broke that assumption: it unconditionally flips `state` back to `Ready` regardless of
        // what `BlockReason` it's interrupting -- found live (Ctrl+Z-ing a `sleep`, then `bg`,
        // resumed it far short of its real deadline). Re-blocking on the same deadline if it
        // hasn't actually passed yet also gets real semantics for free: `ticks()` keeps advancing
        // while `Stopped` (it's a global counter, not paused per-process), so time spent stopped
        // still counts toward the sleep, matching real Linux's own wall-clock-deadline behavior.
        //
        // Real HPET top-off headroom, capped at this many *extra* ticks past `deadline` -- see
        // this function's own doc comment for why this exists. Generous versus the handful of
        // milliseconds of real PIT-vs-HPET drift actually observed (well under one tick), purely
        // a defensive bound against a pathological/stuck HPET reading, never expected to bind in
        // practice.
        const HPET_TOPOFF_TICK_CAP: u64 = 50;
        while crate::cpu::interrupts::ticks() < deadline
            || hpet_target_ns.is_some_and(|target| {
                crate::cpu::interrupts::ticks() < deadline + HPET_TOPOFF_TICK_CAP
                    && crate::cpu::hpet::now_ns().is_some_and(|now_ns| now_ns < target)
            })
        {
            {
                let mut table = PROCESS_TABLE.lock();
                let proc = table.get_mut(&pid).unwrap();
                // Real POSIX: a signal that will invoke a caught handler interrupts the sleep
                // early -- checked before (re-)blocking, same "avoid a lost wakeup" reasoning
                // `do_pause`'s own identical check already establishes. Once a signal is actually
                // pending here, `deliver_pending_signal` (this syscall's own tail, back in
                // `syscall_dispatch`) resolves what really happens next (handler invocation, or a
                // self-signaled default-Terminate) -- this function's only job is to stop waiting
                // and hand control back.
                if crate::process::signals::has_interrupting_signal(proc) {
                    let now = crate::cpu::interrupts::ticks();
                    let remaining = deadline.saturating_sub(now);
                    drop(table);
                    if rem_ptr != 0 {
                        // SAFETY: same known pointer-validation gap as every other user-memory
                        // write in this codebase.
                        unsafe {
                            *(rem_ptr as *mut RawTimespec) = RawTimespec {
                                tv_sec: (remaining / hz) as i64,
                                tv_nsec: ((remaining % hz) * 1_000_000_000 / hz) as i64,
                            }
                        };
                    }
                    return Err(EINTR);
                }
                proc.state = ProcState::Blocked(BlockReason::Sleeping(deadline));
            } // lock dropped before schedule() -- see process::table()'s own doc comment
            crate::process::scheduler::schedule();
        }
    }

    if rem_ptr != 0 {
        // SAFETY: same known pointer-validation gap as above, for a write this time.
        unsafe {
            *(rem_ptr as *mut RawTimespec) = RawTimespec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        };
    }
    Ok(0)
}

/// Real `struct itimerval` layout (`{ struct timeval it_interval; struct timeval it_value; }`,
/// each `timeval` a `{ i64 tv_sec; i64 tv_usec; }` pair on this LP64 target — no padding, matching
/// what musl's own `setitimer()`/`getitimer()` (`third_party/musl/src/signal/{set,get}itimer.c`)
/// read/write directly, since `sizeof(time_t) > sizeof(long)` is false here and both fall straight
/// through to a plain 3-register syscall with no repacking).
#[derive(Clone, Copy)]
#[repr(C)]
struct RawItimerval {
    it_interval_sec: i64,
    it_interval_usec: i64,
    it_value_sec: i64,
    it_value_usec: i64,
}

const ITIMER_REAL: u64 = 0;

/// `sec`/`usec` -> ticks, rounded up (never fires *earlier* than requested) — same rounding
/// discipline `do_nanosleep` already established for its own `TIMER_HZ` conversion.
fn timeval_to_ticks(sec: i64, usec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return None;
    }
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let whole = sec as u64 * hz;
    let frac = (usec as u64 * hz).div_ceil(1_000_000);
    Some(whole + frac)
}

/// Inverse of `timeval_to_ticks` — floored, since this reports *remaining* time (rounding up here
/// would claim more time is left than actually is).
fn ticks_to_timeval(ticks: u64) -> (i64, i64) {
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    ((ticks / hz) as i64, ((ticks % hz) * 1_000_000 / hz) as i64)
}

/// `SYS_SETITIMER`'s real logic — real `setitimer(2)`'s exact `(which, new_ptr, old_ptr)` wire
/// format (musl's own `setitimer()` passes this straight through unmodified on a 64-bit `time_t`
/// target, and `alarm()` is itself just a thin wrapper around `setitimer(ITIMER_REAL, ...)` — see
/// `third_party/musl/src/unistd/alarm.c` — so this one syscall backs both real libc entry points).
///
/// Only `ITIMER_REAL` is supported (`EINVAL` otherwise) — `ITIMER_VIRTUAL`/`ITIMER_PROF` are
/// defined in terms of a process's own CPU time, which this kernel doesn't track at all (see
/// CLAUDE.md's real-time-clock section: "no per-process/per-thread CPU time is tracked").
///
/// A zero `it_value` (both fields `0`) disarms any pending timer, matching real `setitimer`'s own
/// "cancel" convention. `it_interval` (if the resulting deadline is ever reached and is nonzero)
/// reloads the deadline instead of leaving it disarmed — real periodic-timer semantics, checked by
/// `interrupts::timer_interrupt_handler` alongside its `BlockReason::Sleeping` scan, which raises
/// `SIGALRM` the same simple way `do_kill`'s self-targeting case already does (just sets the
/// pending bit — see that function's own doc comment for why that's sufficient here: unlike an
/// arbitrary cross-process `kill`, delivery only needs the *next* syscall this exact process makes
/// to complete, and `ping`'s own real usage pattern — a tight loop of individually non-blocking
/// `recvfrom` calls — guarantees that happens promptly).
pub fn do_setitimer(pid: Pid, which: u64, new_ptr: u64, old_ptr: u64) -> Result<u64, u64> {
    if which != ITIMER_REAL {
        return Err(EINVAL);
    }
    if new_ptr == 0 {
        return Err(EINVAL);
    }
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let new = unsafe { *(new_ptr as *const RawItimerval) };
    let value_ticks = timeval_to_ticks(new.it_value_sec, new.it_value_usec).ok_or(EINVAL)?;
    let interval_ticks =
        timeval_to_ticks(new.it_interval_sec, new.it_interval_usec).ok_or(EINVAL)?;

    let mut table = PROCESS_TABLE.lock();
    let proc = table
        .get_mut(&pid)
        .expect("setitimer: current process missing from table");

    if old_ptr != 0 {
        let (value_sec, value_usec) = match proc.real_timer_deadline {
            Some(deadline) => ticks_to_timeval(deadline.saturating_sub(crate::cpu::interrupts::ticks())),
            None => (0, 0),
        };
        let (interval_sec, interval_usec) = ticks_to_timeval(proc.real_timer_interval_ticks);
        // SAFETY: same known pointer-validation gap as above, for a write this time.
        unsafe {
            (old_ptr as *mut RawItimerval).write_unaligned(RawItimerval {
                it_interval_sec: interval_sec,
                it_interval_usec: interval_usec,
                it_value_sec: value_sec,
                it_value_usec: value_usec,
            })
        };
    }

    if value_ticks == 0 {
        proc.real_timer_deadline = None;
        proc.real_timer_interval_ticks = 0;
    } else {
        proc.real_timer_deadline = Some(crate::cpu::interrupts::ticks() + value_ticks);
        proc.real_timer_interval_ticks = interval_ticks;
    }
    Ok(0)
}

/// `SYS_GETITIMER`'s real logic — real `getitimer(2)`'s exact `(which, old_ptr)` wire format. Same
/// `ITIMER_REAL`-only restriction as `do_setitimer`.
pub fn do_getitimer(pid: Pid, which: u64, old_ptr: u64) -> Result<u64, u64> {
    if which != ITIMER_REAL {
        return Err(EINVAL);
    }
    if old_ptr == 0 {
        return Err(EINVAL);
    }
    let table = PROCESS_TABLE.lock();
    let proc = table
        .get(&pid)
        .expect("getitimer: current process missing from table");

    let (value_sec, value_usec) = match proc.real_timer_deadline {
        Some(deadline) => ticks_to_timeval(deadline.saturating_sub(crate::cpu::interrupts::ticks())),
        None => (0, 0),
    };
    let (interval_sec, interval_usec) = ticks_to_timeval(proc.real_timer_interval_ticks);
    // SAFETY: same known pointer-validation gap every other user-memory write in this codebase
    // already has.
    unsafe {
        (old_ptr as *mut RawItimerval).write_unaligned(RawItimerval {
            it_interval_sec: interval_sec,
            it_interval_usec: interval_usec,
            it_value_sec: value_sec,
            it_value_usec: value_usec,
        })
    };
    Ok(0)
}

/// Real, architecture-generic `clockid_t` values -- duplicated from `src/syscall/ffi.rs`'s own
/// copy rather than shared across this internal module boundary, same "no shared crate across this
/// internal ABI boundary" convention this file's own `RawTimespec`/`RawItimerval` already follow.
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
/// Real Linux clockid values -- same duplication-across-the-internal-module-boundary convention as
/// `CLOCK_REALTIME`/`CLOCK_MONOTONIC` above. Both share this kernel's one real per-process CPU-time
/// counter (`Process::cpu_ticks`, see `sys_clock_gettime`'s own doc comment) -- no per-thread
/// distinction exists to make `_THREAD_` mean anything different from `_PROCESS_` here.
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;

/// `pub(crate)`, not private -- `interrupts::timer_interrupt_handler`'s own `posix_timers` expiry
/// scan needs this too, to know whether a given slot's `deadline` compares against `ticks()` or
/// `Process::cpu_ticks`. A plain `u64 -> bool` function, not one taking `&Process`, deliberately --
/// that scan already holds a live `&mut` sub-borrow of `proc.posix_timers` via its own `slot`
/// local by the time it needs this, and a function borrowing all of `&Process` wouldn't compile
/// alongside it (see `timer_now`'s own doc comment for the general version of this constraint).
pub(crate) fn is_cputime_clock(clockid: u64) -> bool {
    clockid == CLOCK_PROCESS_CPUTIME_ID || clockid == CLOCK_THREAD_CPUTIME_ID
}

/// The "now" a `PosixTimer`'s own `deadline` is measured against, per its `clockid` -- real
/// `interrupts::ticks()` for `CLOCK_REALTIME`/`CLOCK_MONOTONIC`, or `Process::cpu_ticks` for
/// `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID` (the same real per-process CPU-time
/// counter `sys_clock_gettime` already reads for those two clockids). Shared by `do_timer_settime`
/// (both the relative-arm case and the `old_ptr` remaining-time readback) and `do_timer_gettime`,
/// plus `interrupts::timer_interrupt_handler`'s own expiry scan -- one definition, so all four
/// call sites agree on which counter a given timer's own domain compares against.
fn timer_now(proc: &Process, clockid: u64) -> u64 {
    if is_cputime_clock(clockid) {
        proc.cpu_ticks
    } else {
        crate::cpu::interrupts::ticks()
    }
}

/// Real Linux `TIMER_ABSTIME` (`third_party/musl/include/time.h`) -- the one `timer_settime(2)`
/// `flags` bit this ABI understands; any other bit is `EINVAL`.
const TIMER_ABSTIME: u64 = 1;

/// musl's own `struct ksigevent` (`third_party/musl/src/time/timer_create.c`) -- the real,
/// kernel-facing shape `timer_create(2)`'s `evp` argument actually points at (musl's userspace
/// `struct sigevent` is translated into this smaller struct before the syscall for every
/// notification kind reachable here -- see `do_timer_create`'s own doc comment for why
/// `SIGEV_THREAD`/`SIGEV_THREAD_ID` never really reach this kernel in practice). `union sigval` is
/// 8 bytes on this LP64 target (its largest member is a pointer); `sigev_value`/`sigev_tid` are
/// never read (only `sigev_notify`/`sigev_signo` matter here) but stay in the struct for correct
/// field-offset layout matching the real one musl builds.
#[derive(Clone, Copy)]
#[repr(C)]
struct RawKSigevent {
    #[allow(dead_code)]
    sigev_value: u64,
    sigev_signo: i32,
    sigev_notify: i32,
    #[allow(dead_code)]
    sigev_tid: i32,
}

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;

/// Real `struct itimerspec` layout (`{ struct timespec it_interval; struct timespec it_value; }`,
/// nanosecond precision) -- distinct from `RawItimerval` above (`setitimer`'s own microsecond-
/// precision `timeval` pair). What `timer_settime(2)`/`timer_gettime(2)` actually read/write.
#[derive(Clone, Copy)]
#[repr(C)]
struct RawItimerspec {
    it_interval_sec: i64,
    it_interval_nsec: i64,
    it_value_sec: i64,
    it_value_nsec: i64,
}

/// `sec`/`nsec` -> ticks, rounded up (never fires *earlier* than requested) -- same rounding
/// discipline `timeval_to_ticks` above already established, just nanosecond- instead of
/// microsecond-precision.
fn timespec_to_ticks(sec: i64, nsec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let whole = sec as u64 * hz;
    let frac = (nsec as u64 * hz).div_ceil(1_000_000_000);
    Some(whole + frac)
}

/// Inverse of `timespec_to_ticks` -- floored, same "never claim more time is left than actually
/// is" reasoning `ticks_to_timeval` above already established.
fn ticks_to_timespec(ticks: u64) -> (i64, i64) {
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    ((ticks / hz) as i64, ((ticks % hz) * 1_000_000_000 / hz) as i64)
}

/// `sec`/`nsec` -> real nanoseconds, verbatim -- no tick rounding at all, unlike
/// `timespec_to_ticks` above. Backs `PosixTimer::deadline_ns`/`interval_ns` (see that field's own
/// doc comment).
fn timespec_to_ns(sec: i64, nsec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    Some(sec as u64 * 1_000_000_000 + nsec as u64)
}

/// Converts a `TIMER_ABSTIME` `timer_settime` target (a point in `clockid`'s own domain, not a
/// duration) into an absolute deadline in the tick-shaped units `interrupts::
/// timer_interrupt_handler`'s own `PosixTimer::deadline` comparison expects. `CLOCK_MONOTONIC`'s
/// domain already *is* "seconds since boot at `TIMER_HZ` resolution" -- exactly what `ticks()`
/// counts -- so a requested absolute timestamp converts the same way a relative one would
/// (`timespec_to_ticks`), just used directly as the deadline instead of added to `ticks()`.
/// **`CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID` take the identical direct-conversion
/// path** -- `Process::cpu_ticks` accumulates at the same `TIMER_HZ` cadence as `ticks()` (see its
/// own doc comment), just gated on "this process was the one actually running," so an absolute
/// cpu-time target is a raw tick count in exactly the same sense a `CLOCK_MONOTONIC` one is; the
/// only caller ever passing one of these two clockids here (`do_timer_settime`) compares the
/// result against `Process::cpu_ticks`, never `interrupts::ticks()`, so reusing this branch is
/// correct rather than coincidental. `CLOCK_REALTIME`'s domain is wall-clock time -- converted via
/// the delta between the requested wall-clock second and *now*, then applied against the current
/// tick count. A target already in the past (delta `<= 0`) collapses to "fire on the very next
/// timer IRQ" (`now_ticks`) rather than underflowing, matching real semantics for an
/// already-elapsed absolute deadline.
///
/// **`rtc::unix_epoch_now_precise()`, not `rtc::unix_epoch_seconds()`** -- found live via this
/// function's own smoke test (`userland/clock-syscall-smoke`'s part 7): the latter reads the real
/// CMOS chip directly, entirely unaffected by `rtc::set_unix_epoch`'s recalibration, so a target
/// computed against a `clock_settime`-adjusted `CLOCK_REALTIME` reading (e.g. `clock_settime/1-1.c`'s
/// own Nov-2002 fixture) would diff against the *real*, un-adjusted current date instead -- a
/// wildly wrong (here, deeply negative) `delta_secs` that collapsed to "fire immediately" instead
/// of sleeping the real requested duration. `unix_epoch_now_precise()` is the same live,
/// settable-via-`clock_settime` clock `sys_clock_gettime`'s own `CLOCK_REALTIME` arm already reads,
/// so this keeps every `CLOCK_REALTIME`-domain absolute deadline (`timer_settime`,
/// `do_clock_nanosleep`) consistent with whatever `clock_gettime(CLOCK_REALTIME, ...)` itself would
/// report at arm time.
pub(crate) fn abstime_to_ticks(clockid: u64, sec: i64, nsec: i64) -> u64 {
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let frac_ticks = (nsec as u64 * hz).div_ceil(1_000_000_000);
    let now_ticks = crate::cpu::interrupts::ticks();
    if clockid == CLOCK_MONOTONIC || is_cputime_clock(clockid) {
        sec.max(0) as u64 * hz + frac_ticks
    } else {
        let (now_wall_sec, now_wall_nsec) = crate::cpu::rtc::unix_epoch_now_precise();
        let delta_ticks = (sec - now_wall_sec) * hz as i64
            + (nsec - now_wall_nsec) * hz as i64 / 1_000_000_000;
        if delta_ticks <= 0 {
            now_ticks
        } else {
            now_ticks + delta_ticks as u64
        }
    }
}

/// `SYS_TIMER_CREATE` (`531`, item 6 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
/// pre-reserved batch) -- matches real `timer_create(2)`'s exact `(clockid, evp_ptr, timerid_ptr)`
/// wire format (musl's own `timer_create()` translates its `struct sigevent` argument into the
/// smaller `struct ksigevent` -- `RawKSigevent` above -- before issuing the raw syscall for every
/// `SIGEV_SIGNAL`/`SIGEV_NONE`/`SIGEV_THREAD_ID` notification kind; `SIGEV_THREAD` is handled
/// entirely in userspace via a real `pthread_create()` first, which always fails on this kernel
/// -- no `clone(2)` -- before ever reaching this syscall, so only `SIGEV_SIGNAL`/`SIGEV_NONE` are
/// real, reachable cases here; a caller bypassing musl's own wrapper to request `SIGEV_THREAD_ID`
/// directly gets a real `EINVAL`, this kernel having no notion of a specific thread to target).
///
/// `evp_ptr == 0` matches real POSIX's own default: `SIGEV_SIGNAL` with `sigev_signo = SIGALRM`.
/// Finds the first free `Process::posix_timers` slot (`EAGAIN` if all `MAX_POSIX_TIMERS` are
/// already in use, matching real Linux's own resource-exhaustion errno for this call) and writes
/// its index back as the real, opaque `timer_t` value.
///
/// **`clockid`**: `CLOCK_REALTIME`/`CLOCK_MONOTONIC`, plus `CLOCK_PROCESS_CPUTIME_ID`/
/// `CLOCK_THREAD_CPUTIME_ID` (added later -- see `is_cputime_clock`'s own doc comment; any other
/// value is still a real `EINVAL`). Found live via `timer_create/10-1.c`/`11-1.c` (Open POSIX Test
/// Suite pilot): both unconditionally `EINVAL`'d here before, since only the first two clockids
/// were ever accepted -- `sysconf(_SC_CPUTIME)`/`_SC_THREAD_CPUTIME` both unconditionally claim
/// support (musl's own compile-time answer, see `sys_clock_gettime`'s own doc comment), so both
/// tests proceeded straight to a real `timer_create()` call expecting it to succeed.
pub fn do_timer_create(pid: Pid, clockid: u64, evp_ptr: u64, timerid_ptr: u64) -> Result<u64, u64> {
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC && !is_cputime_clock(clockid) {
        return Err(EINVAL);
    }

    let signo = if evp_ptr == 0 {
        SIGALRM
    } else {
        // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
        // already has.
        let evp = unsafe { *(evp_ptr as *const RawKSigevent) };
        match evp.sigev_notify {
            SIGEV_NONE => 0,
            SIGEV_SIGNAL => {
                let sig = evp.sigev_signo as u64;
                if !(1..=31).contains(&sig) {
                    return Err(EINVAL);
                }
                sig
            }
            _ => return Err(EINVAL),
        }
    };

    let mut table = PROCESS_TABLE.lock();
    let proc = table
        .get_mut(&pid)
        .expect("timer_create: current process missing from table");

    let Some(slot) = proc.posix_timers.iter().position(Option::is_none) else {
        return Err(EAGAIN);
    };
    proc.posix_timers[slot] = Some(PosixTimer {
        clockid,
        signo,
        deadline: None,
        interval_ticks: 0,
        interval_requested: (0, 0),
        realtime_target: None,
        overrun: 0,
        deadline_ns: None,
        interval_ns: 0,
    });
    drop(table);

    // SAFETY: same known pointer-validation gap as above, for a write this time.
    unsafe { (timerid_ptr as *mut i32).write(slot as i32) };
    Ok(0)
}

/// `SYS_TIMER_SETTIME` (`532`, item 7 of the same batch) -- matches real `timer_settime(2)`'s
/// exact `(timerid, flags, new_ptr, old_ptr)` wire format (musl's own `timer_settime()` reduces to
/// a bare 4-argument `syscall` on this LP64 target -- no `*64`-suffixed sibling exists for
/// `time_t` this size, see `third_party/musl/arch/x86_64/bits/syscall.h.in`'s own comment on the
/// batch). `timerid` doubles as `Process::posix_timers`'s own index; an out-of-range or currently-
/// unallocated one is `EINVAL`, matching real Linux.
///
/// Setting `it_value` to all-zero disarms the timer regardless of `TIMER_ABSTIME` -- real
/// `timer_settime(2)` semantics, checked before either the relative or absolute interpretation
/// below. Otherwise: relative mode (`flags == 0`) arms `ticks() + value_ticks`, same shape
/// `do_setitimer` already uses; `TIMER_ABSTIME` mode resolves the absolute target via
/// `abstime_to_ticks`, using the `clockid` this timer was created against. Rearming always clears
/// `overrun` -- a stale overrun count from before this call has no real meaning against a freshly
/// (re)armed timer.
pub fn do_timer_settime(
    pid: Pid,
    timerid: u64,
    flags: u64,
    new_ptr: u64,
    old_ptr: u64,
) -> Result<u64, u64> {
    if flags & !TIMER_ABSTIME != 0 {
        return Err(EINVAL);
    }
    if new_ptr == 0 {
        return Err(EINVAL);
    }
    let timerid = timerid as usize;

    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let new = unsafe { *(new_ptr as *const RawItimerspec) };
    let value_ticks = timespec_to_ticks(new.it_value_sec, new.it_value_nsec).ok_or(EINVAL)?;
    let interval_ticks =
        timespec_to_ticks(new.it_interval_sec, new.it_interval_nsec).ok_or(EINVAL)?;
    // Real, non-tick-quantized counterparts -- see `PosixTimer::deadline_ns`'s own doc comment
    // for exactly when these actually get used below (relative-mode, non-cputime, real HPET
    // present) versus just computed and discarded.
    let value_ns = timespec_to_ns(new.it_value_sec, new.it_value_nsec).ok_or(EINVAL)?;
    let interval_ns_val = timespec_to_ns(new.it_interval_sec, new.it_interval_nsec).ok_or(EINVAL)?;

    let mut table = PROCESS_TABLE.lock();
    let proc = table
        .get_mut(&pid)
        .expect("timer_settime: current process missing from table");
    let clockid = proc
        .posix_timers
        .get(timerid)
        .and_then(|s| s.as_ref())
        .ok_or(EINVAL)?
        .clockid;

    if old_ptr != 0 {
        let slot = proc.posix_timers[timerid].as_ref().unwrap();
        let (value_sec, value_nsec) = match slot.deadline {
            Some(deadline) => ticks_to_timespec(deadline.saturating_sub(timer_now(proc, clockid))),
            None => (0, 0),
        };
        let (interval_sec, interval_nsec) = slot.interval_requested;
        // SAFETY: same known pointer-validation gap as above, for a write this time.
        unsafe {
            (old_ptr as *mut RawItimerspec).write_unaligned(RawItimerspec {
                it_interval_sec: interval_sec,
                it_interval_nsec: interval_nsec,
                it_value_sec: value_sec,
                it_value_nsec: value_nsec,
            })
        };
    }

    // Computed before `slot` below takes its own mutable borrow of `proc.posix_timers` -- `proc`
    // (the whole struct, for `proc.cpu_ticks`) can't be reborrowed immutably while a field of it
    // is already borrowed mutably through `slot`, even though the two touch disjoint fields (same
    // borrow-splitting limitation `interrupts.rs`'s own `newly_signaled` local already works
    // around for the identical reason).
    let now = timer_now(proc, clockid);
    let slot = proc.posix_timers[timerid].as_mut().unwrap();
    if new.it_value_sec == 0 && new.it_value_nsec == 0 {
        slot.deadline = None;
        slot.interval_ticks = 0;
        slot.interval_requested = (0, 0);
        slot.realtime_target = None;
        slot.deadline_ns = None;
        slot.interval_ns = 0;
    } else if flags & TIMER_ABSTIME != 0 {
        slot.deadline = Some(abstime_to_ticks(clockid, new.it_value_sec, new.it_value_nsec));
        slot.interval_ticks = interval_ticks;
        slot.interval_requested = (new.it_interval_sec, new.it_interval_nsec);
        slot.realtime_target = if clockid == CLOCK_REALTIME {
            Some((new.it_value_sec, new.it_value_nsec))
        } else {
            None
        };
        // The real HPET-precision path is relative-mode only -- an abstime arm already has its
        // own correct wall-clock-retargeting story via `realtime_target` above, untouched here.
        slot.deadline_ns = None;
        slot.interval_ns = 0;
    } else {
        slot.deadline = Some(now + value_ticks);
        slot.interval_ticks = interval_ticks;
        slot.interval_requested = (new.it_interval_sec, new.it_interval_nsec);
        slot.realtime_target = None;
        slot.deadline_ns = if is_cputime_clock(clockid) {
            None
        } else {
            crate::cpu::hpet::now_ns().map(|now_ns| now_ns + value_ns)
        };
        slot.interval_ns = interval_ns_val;
    }
    slot.overrun = 0;
    Ok(0)
}

/// `SYS_TIMER_GETTIME` (`533`, item 8) -- matches real `timer_gettime(2)`'s exact
/// `(timerid, val_ptr)` wire format. Same `ok_or(EINVAL)` invalid-id handling as
/// `do_timer_settime`.
pub fn do_timer_gettime(pid: Pid, timerid: u64, val_ptr: u64) -> Result<u64, u64> {
    if val_ptr == 0 {
        return Err(EINVAL);
    }
    let timerid = timerid as usize;
    let table = PROCESS_TABLE.lock();
    let proc = table
        .get(&pid)
        .expect("timer_gettime: current process missing from table");
    let slot = proc
        .posix_timers
        .get(timerid)
        .and_then(|s| s.as_ref())
        .ok_or(EINVAL)?;

    let (value_sec, value_nsec) = match slot.deadline {
        Some(deadline) => ticks_to_timespec(deadline.saturating_sub(timer_now(proc, slot.clockid))),
        None => (0, 0),
    };
    let (interval_sec, interval_nsec) = slot.interval_requested;
    // SAFETY: same known pointer-validation gap every other user-memory write in this codebase
    // already has.
    unsafe {
        (val_ptr as *mut RawItimerspec).write_unaligned(RawItimerspec {
            it_interval_sec: interval_sec,
            it_interval_nsec: interval_nsec,
            it_value_sec: value_sec,
            it_value_nsec: value_nsec,
        })
    };
    Ok(0)
}

/// `SYS_TIMER_GETOVERRUN` (`534`, item 9) -- matches real `timer_getoverrun(2)`'s exact
/// single-argument `(timerid)` wire format; unlike every other timer call here, the overrun count
/// itself *is* the real return value (no output pointer) -- see `PosixTimer::overrun`'s own doc
/// comment for what this counts and its one known, accepted simplification.
pub fn do_timer_getoverrun(pid: Pid, timerid: u64) -> Result<u64, u64> {
    let timerid = timerid as usize;
    let table = PROCESS_TABLE.lock();
    let proc = table
        .get(&pid)
        .expect("timer_getoverrun: current process missing from table");
    let slot = proc
        .posix_timers
        .get(timerid)
        .and_then(|s| s.as_ref())
        .ok_or(EINVAL)?;
    Ok(slot.overrun as u64)
}

/// `SYS_TIMER_DELETE` (`535`, item 10, the last of the POSIX-timer sub-batch) -- matches real
/// `timer_delete(2)`'s exact single-argument `(timerid)` wire format. Just frees the slot (`None`)
/// -- no dealloc beyond that to do, consistent with the rest of this kernel's "no deallocation
/// anywhere" stance for every other resource.
pub fn do_timer_delete(pid: Pid, timerid: u64) -> Result<u64, u64> {
    let timerid = timerid as usize;
    let mut table = PROCESS_TABLE.lock();
    let proc = table
        .get_mut(&pid)
        .expect("timer_delete: current process missing from table");
    let slot = proc.posix_timers.get_mut(timerid).ok_or(EINVAL)?;
    if slot.is_none() {
        return Err(EINVAL);
    }
    *slot = None;
    Ok(0)
}

/// `SYS_CLOCK_NANOSLEEP` -- real Linux's own unclaimed `230` (confirmed against every `SYS_*`
/// constant already registered in this ABI, same collision-avoidance discipline the syscall-ABI
/// section of `CLAUDE.md` requires; musl's own `bits/syscall.h.in` already carries this value
/// unremapped, so no musl-side patch was needed either, just a kernel-side handler). musl's own
/// `__clock_nanosleep` (`third_party/musl/src/time/clock_nanosleep.c`) only ever issues this
/// syscall when `clk != CLOCK_REALTIME || flags != 0` -- the one case that instead short-circuits
/// to plain `SYS_nanosleep`/`do_nanosleep` above is a relative `CLOCK_REALTIME` sleep, already
/// handled. `clk == CLOCK_THREAD_CPUTIME_ID` never reaches here either -- that same C source
/// returns `EINVAL` for it client-side before ever issuing a syscall.
///
/// `CLOCK_MONOTONIC` (relative or `TIMER_ABSTIME`) and a relative `CLOCK_REALTIME` request (only
/// reachable by a caller bypassing musl's own wrapper) all resolve to a single, fixed
/// `interrupts::ticks()` deadline computed once, exactly like `do_nanosleep`'s own shape --
/// `ticks()` already *is* `CLOCK_MONOTONIC`'s domain, immune to any later `clock_settime`.
///
/// **`CLOCK_REALTIME` + `TIMER_ABSTIME` is the one case needing real, live wall-clock tracking,**
/// closing `clock_nanosleep/2-1.c`/`3-1.c` (previously `ENOSYS`, since this syscall didn't exist at
/// all) and `clock_settime/7-1.c` (a concurrent `clock_settime(CLOCK_REALTIME, ...)` from another
/// process must retarget an in-progress wait like this one). Rather than storing a fixed tick
/// deadline once and needing some separate mechanism to shift it later (what `PosixTimer::
/// realtime_target` needs, since nothing re-enters that code path once armed), this function
/// re-derives its own deadline via `abstime_to_ticks` fresh on **every** loop pass -- cheap, and
/// self-correcting for free when a concurrent `clock_settime` moves the real target *further
/// out*: the timer IRQ still wakes this process at its own already-correct, unaffected tick
/// deadline (an ordinary, harmless spurious wake, using the same plain `BlockReason::Sleeping`
/// every other tick-deadline wait already uses -- no new variant needed), this loop's next pass
/// recomputes a fresh deadline from the *current* wall clock, and re-blocks (closes
/// `clock_settime/7-1.c`). Moving the target *into the past* needs an active nudge instead --
/// nothing here changes `ticks()`, so a process blocked on a now-stale, too-far-out deadline would
/// otherwise never wake early on its own at all. `sys_clock_settime`'s `CLOCK_REALTIME` arm
/// supplies that nudge via `wake_realtime_sleepers_after_clock_change` below, right after
/// `rtc::set_unix_epoch` (closes `clock_settime/7-2.c`).
pub fn do_clock_nanosleep(
    pid: Pid,
    clockid: u64,
    flags: u64,
    req_ptr: u64,
    rem_ptr: u64,
) -> Result<u64, u64> {
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return Err(EINVAL);
    }
    if flags & !TIMER_ABSTIME != 0 {
        return Err(EINVAL);
    }
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let req = unsafe { *(req_ptr as *const RawTimespec) };
    if !(0..1_000_000_000).contains(&req.tv_nsec) {
        return Err(EINVAL);
    }
    let absolute = flags & TIMER_ABSTIME != 0;
    if !absolute && req.tv_sec < 0 {
        return Err(EINVAL);
    }

    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let wall_clock_realtime = absolute && clockid == CLOCK_REALTIME;

    let mut deadline = if absolute {
        abstime_to_ticks(clockid, req.tv_sec, req.tv_nsec)
    } else {
        let whole = req.tv_sec as u64 * hz;
        let frac = (req.tv_nsec as u64 * hz).div_ceil(1_000_000_000);
        crate::cpu::interrupts::ticks() + whole + frac
    };

    while crate::cpu::interrupts::ticks() < deadline {
        {
            let mut table = PROCESS_TABLE.lock();
            let proc = table.get_mut(&pid).unwrap();
            // Real POSIX: a signal that will invoke a caught handler interrupts the sleep early --
            // same "avoid a lost wakeup" reasoning `do_nanosleep`'s own identical check already
            // establishes.
            if crate::process::signals::has_interrupting_signal(proc) {
                let now = crate::cpu::interrupts::ticks();
                let remaining = deadline.saturating_sub(now);
                drop(table);
                // Real POSIX: `rem` is only ever meaningful for a *relative* request -- an
                // absolute-mode `clock_nanosleep` never writes it back on `EINTR` either.
                if rem_ptr != 0 && !absolute {
                    // SAFETY: same known pointer-validation gap as above, for a write this time.
                    unsafe {
                        *(rem_ptr as *mut RawTimespec) = RawTimespec {
                            tv_sec: (remaining / hz) as i64,
                            tv_nsec: ((remaining % hz) * 1_000_000_000 / hz) as i64,
                        }
                    };
                }
                return Err(EINTR);
            }
            proc.state = ProcState::Blocked(BlockReason::Sleeping(deadline));
        } // lock dropped before schedule() -- see process::table()'s own doc comment
        crate::process::scheduler::schedule();
        if wall_clock_realtime {
            deadline = abstime_to_ticks(CLOCK_REALTIME, req.tv_sec, req.tv_nsec);
        }
    }

    if rem_ptr != 0 && !absolute {
        // SAFETY: same known pointer-validation gap as above, for a write this time.
        unsafe {
            *(rem_ptr as *mut RawTimespec) = RawTimespec {
                tv_sec: 0,
                tv_nsec: 0,
            }
        };
    }
    Ok(0)
}

/// Real, active nudge for `clock_settime(CLOCK_REALTIME, ...)` moving the wall clock *forward*
/// past a process's own absolute `CLOCK_REALTIME` `clock_nanosleep()` target -- closes
/// `clock_settime/7-2.c`. `do_clock_nanosleep`'s own self-correcting recompute (see its doc
/// comment above) only ever runs *after* a blocked process actually wakes -- fine when a
/// concurrent `clock_settime` moves the target *further out* (the process's already-correct,
/// `ticks()`-based deadline is entirely unaffected by any wall-clock change, so it naturally
/// fires once real elapsed time catches up, closing `clock_settime/7-1.c` for free) -- but wrong
/// when it moves the target *into the past*: nothing here ever changes `ticks()` itself, so a
/// process blocked on a now-stale, too-far-in-the-future tick deadline would otherwise never wake
/// early at all. Real POSIX requires immediate expiry in exactly this case.
///
/// Force-wakes *every* `Sleeping`-blocked process unconditionally, not just ones known to be on a
/// `CLOCK_REALTIME` absolute wait (this kernel's `BlockReason::Sleeping` carries no clock-id to
/// distinguish them) -- safe because both `do_nanosleep` and `do_clock_nanosleep` already re-check
/// their own real deadline before ever re-blocking, so a spurious wake here is a harmless no-op
/// for anything not actually expired -- the same discipline real `SIGCONT` resuming a `Stopped`
/// sleeper already established (see `do_nanosleep`'s own doc comment). Only `sys_clock_settime`'s
/// `CLOCK_REALTIME` arm calls this -- `CLOCK_MONOTONIC`/CPU-time clocks can never retarget an
/// already-armed wall-clock deadline.
pub(crate) fn wake_realtime_sleepers_after_clock_change() {
    let mut table = PROCESS_TABLE.lock();
    for (&pid, proc) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::Sleeping(_)) = proc.state {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}
