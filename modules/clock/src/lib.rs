//! `SYS_CLOCK_GETTIME = 138` and `SYS_NANOSLEEP = 139` (see CLAUDE.md's "BusyBox gap analysis" —
//! the "clock + nanosleep" gap), continuing the sequence past `modules/posix_compat`'s
//! `SYS_UNAME = 137`. Same "module registers, kernel implements" split every other syscall module
//! in this codebase uses: real logic is kernel-resident, since this module can't use `alloc` (see
//! CLAUDE.md's module-loading section) —
//! `src/syscall.rs`'s `sys_clock_gettime` (backed by `src/pit.rs`'s reprogrammed timer tick rate
//! for `CLOCK_MONOTONIC` and `src/rtc.rs`'s CMOS read for `CLOCK_REALTIME`) for the former,
//! `src/process.rs`'s `do_nanosleep` (a real block-then-`scheduler::schedule()`, woken by
//! `interrupts::timer_interrupt_handler` once the requested tick deadline passes — genuinely
//! scheduler-resident work, not something this module could implement by itself) for the latter.
//!
//! `SYS_SETITIMER = 156`/`SYS_GETITIMER = 157`, continuing on from `SYS_SYMLINK = 155`: real
//! `setitimer(2)`/`getitimer(2)`, also backing real `alarm(2)` (a thin musl-side wrapper around
//! `setitimer`, see `third_party/musl/src/unistd/alarm.c`) — the same class of timer-machinery
//! addition this module already owns, backed by `process::do_setitimer`/`do_getitimer` and
//! `interrupts::timer_interrupt_handler`'s own `ITIMER_REAL` expiry check.
//!
//! `SYS_TIMER_CREATE = 531`/`SYS_TIMER_SETTIME = 532`/`SYS_TIMER_GETTIME = 533`/
//! `SYS_TIMER_GETOVERRUN = 534`/`SYS_TIMER_DELETE = 535` (`OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own
//! 28-syscall pre-reserved batch, items 6-10): real POSIX per-process timers, a natural extension
//! of the `setitimer`/`getitimer` machinery just above now that per-timer-id tracking exists
//! (`process::PosixTimer`/`Process::posix_timers`) — see `process::do_timer_create`'s own doc
//! comment for the real wire format/semantics of the whole sub-batch.
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_clock_gettime(clockid: u64, ts_ptr: u64) -> i64;
    fn oxidebsd_sys_clock_getres(clockid: u64, res_ptr: u64) -> i64;
    fn oxidebsd_sys_clock_settime(clockid: u64, ts_ptr: u64) -> i64;
    fn oxidebsd_sys_clock_nanosleep(clockid: u64, flags: u64, req_ptr: u64, rem_ptr: u64) -> i64;
    fn oxidebsd_sys_nanosleep(req_ptr: u64, rem_ptr: u64) -> i64;
    fn oxidebsd_sys_setitimer(which: u64, new_ptr: u64, old_ptr: u64) -> i64;
    fn oxidebsd_sys_getitimer(which: u64, old_ptr: u64) -> i64;
    fn oxidebsd_sys_timer_create(clockid: u64, evp_ptr: u64, timerid_ptr: u64) -> i64;
    fn oxidebsd_sys_timer_settime(timerid: u64, flags: u64, new_ptr: u64, old_ptr: u64) -> i64;
    fn oxidebsd_sys_timer_gettime(timerid: u64, val_ptr: u64) -> i64;
    fn oxidebsd_sys_timer_getoverrun(timerid: u64) -> i64;
    fn oxidebsd_sys_timer_delete(timerid: u64) -> i64;
}

fn log(message: &str) {
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
}

const SYS_CLOCK_GETTIME: u64 = 138;
/// Real Linux's own unclaimed `227`/`229`/`230` -- see `sys_clock_settime`/`sys_clock_getres`/
/// `do_clock_nanosleep`'s own doc comments in the OxideBSD tree for why these land at their real,
/// already-unremapped `bits/syscall.h.in` values instead of a freshly invented OxideBSD-space
/// number: musl already calls through to exactly these numbers, so only a kernel-side handler was
/// missing.
const SYS_CLOCK_SETTIME: u64 = 227;
const SYS_CLOCK_GETRES: u64 = 229;
const SYS_CLOCK_NANOSLEEP: u64 = 230;
const SYS_NANOSLEEP: u64 = 139;
const SYS_SETITIMER: u64 = 156;
const SYS_GETITIMER: u64 = 157;
const SYS_TIMER_CREATE: u64 = 531;
const SYS_TIMER_SETTIME: u64 = 532;
const SYS_TIMER_GETTIME: u64 = 533;
const SYS_TIMER_GETOVERRUN: u64 = 534;
const SYS_TIMER_DELETE: u64 = 535;

extern "C" fn handle_clock_gettime(clockid: u64, ts_ptr: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_clock_gettime(clockid, ts_ptr) }
}

extern "C" fn handle_clock_getres(clockid: u64, res_ptr: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_clock_getres(clockid, res_ptr) }
}

extern "C" fn handle_clock_settime(clockid: u64, ts_ptr: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_clock_settime(clockid, ts_ptr) }
}

extern "C" fn handle_clock_nanosleep(clockid: u64, flags: u64, req_ptr: u64, rem_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_clock_nanosleep(clockid, flags, req_ptr, rem_ptr) }
}

extern "C" fn handle_nanosleep(req_ptr: u64, rem_ptr: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_nanosleep(req_ptr, rem_ptr) }
}

extern "C" fn handle_setitimer(which: u64, new_ptr: u64, old_ptr: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_setitimer(which, new_ptr, old_ptr) }
}

extern "C" fn handle_getitimer(which: u64, old_ptr: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_getitimer(which, old_ptr) }
}

extern "C" fn handle_timer_create(clockid: u64, evp_ptr: u64, timerid_ptr: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_timer_create(clockid, evp_ptr, timerid_ptr) }
}

extern "C" fn handle_timer_settime(timerid: u64, flags: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_timer_settime(timerid, flags, new_ptr, old_ptr) }
}

extern "C" fn handle_timer_gettime(timerid: u64, val_ptr: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_timer_gettime(timerid, val_ptr) }
}

extern "C" fn handle_timer_getoverrun(timerid: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_timer_getoverrun(timerid) }
}

extern "C" fn handle_timer_delete(timerid: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_timer_delete(timerid) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_CLOCK_GETTIME, handle_clock_gettime);
        oxidebsd_register_syscall(SYS_CLOCK_GETRES, handle_clock_getres);
        oxidebsd_register_syscall(SYS_CLOCK_SETTIME, handle_clock_settime);
        oxidebsd_register_syscall(SYS_CLOCK_NANOSLEEP, handle_clock_nanosleep);
        oxidebsd_register_syscall(SYS_NANOSLEEP, handle_nanosleep);
        oxidebsd_register_syscall(SYS_SETITIMER, handle_setitimer);
        oxidebsd_register_syscall(SYS_GETITIMER, handle_getitimer);
        oxidebsd_register_syscall(SYS_TIMER_CREATE, handle_timer_create);
        oxidebsd_register_syscall(SYS_TIMER_SETTIME, handle_timer_settime);
        oxidebsd_register_syscall(SYS_TIMER_GETTIME, handle_timer_gettime);
        oxidebsd_register_syscall(SYS_TIMER_GETOVERRUN, handle_timer_getoverrun);
        oxidebsd_register_syscall(SYS_TIMER_DELETE, handle_timer_delete);
    }
    log(
        "[module] clock: module_init running (registered SYS_CLOCK_GETTIME/SYS_CLOCK_GETRES/SYS_CLOCK_SETTIME/SYS_CLOCK_NANOSLEEP/SYS_NANOSLEEP/SYS_SETITIMER/SYS_GETITIMER/SYS_TIMER_CREATE/SYS_TIMER_SETTIME/SYS_TIMER_GETTIME/SYS_TIMER_GETOVERRUN/SYS_TIMER_DELETE)\n",
    );
    0
}
