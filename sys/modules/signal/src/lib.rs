//! Registers `SYS_KILL`/`SYS_SIGACTION`/`SYS_SIGPROCMASK` against `sys/syscall.rs`'s dispatch
//! table — a dedicated module rather than folded into `native_abi`/`posix_compat` further, since
//! real signals are a big enough new subsystem of their own to deserve their own home (see
//! CLAUDE.md's BusyBox gap-analysis section: "kill/sigaction/sigprocmask ... either native_abi or
//! a dedicated new sys/modules/signal, whichever the user prefers"). Same "module registers, kernel
//! implements" split every other syscall module in this codebase already uses: the real logic
//! (`do_kill`/`do_sigaction`/`do_sigprocmask` in `sys/process.rs`, plus the pending-signal
//! delivery/`sigreturn` machinery in `sys/syscall.rs`) all stays kernel-resident, since this
//! module can't use `alloc` and the process table needs `BTreeMap` freely — this crate only ever
//! gains thin `extern "C" fn handle_x` wrappers over kernel-resident `oxidebsd_sys_x` functions.
//!
//! `SYS_KILL = 116`/`SYS_SIGACTION = 117`/`SYS_SIGPROCMASK = 118` continue the existing
//! OxideBSD-own-invented-number sequence right past `SYS_RENAME = 111`/`SYS_GETPPID = 107`, per
//! this project's established convention that syscalls added after the musl/BusyBox port invent
//! their own numbers rather than copying FreeBSD/Linux — but all three happen to match real
//! `kill(2)`/`rt_sigaction(2)`/`rt_sigprocmask(2)`'s own wire formats exactly, the same
//! "no argument-convention patch needed" story `SYS_PIPE`/`SYS_DUP2` already had — see
//! `sys/process.rs`'s `do_kill`/`do_sigaction`/`do_sigprocmask` and `bits/syscall.h.in`'s own
//! comment on the musl fork.
//!
//! `SYS_SIGRETURN = 119` (real `rt_sigreturn`'s own wire slot) is deliberately **not** registered
//! here at all — see `sys/syscall.rs`'s `syscall_dispatch`, which intercepts that number directly,
//! before ever reaching this module's table.
//!
//! `SYS_SIGALTSTACK = 528` is item 3 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
//! "pre-reserved ahead of implementation" batch. Real logic (`sys/process/signals.rs`'s
//! `do_sigaltstack`/`AltStack`) is kernel-resident, same pattern as everything else this module
//! only ever calls through to — bookkeeping only, no signal is ever actually delivered on the alt
//! stack (see that type's own doc comment).
//!
//! `SYS_PAUSE = 529` is item 4 of the same batch. Real logic (`sys/process/signals.rs`'s
//! `do_pause`) is kernel-resident and introduces a genuine new block/wake-on-signal primitive
//! (`BlockReason::WaitingForSignal`) — this module's own `handle_pause` is, same as everything
//! else here, a thin zero-argument wrapper.
//!
//! `SYS_SIGSUSPEND = 530` is item 5 of the same batch. Real logic (`sys/process/signals.rs`'s
//! `do_sigsuspend`) is kernel-resident and reuses `do_pause`'s own `BlockReason::WaitingForSignal`
//! primitive, adding a temporary, atomic swap of `blocked_signals` around the same wait — this
//! module's own `handle_sigsuspend` is, same as everything else here, a thin wrapper.
//!
//! `SYS_SIGTIMEDWAIT = 495`/`SYS_SIGQUEUE = 496` (real, unclaimed `__NR_rt_sigtimedwait`/
//! `__NR_rt_sigqueueinfo`, confirmed collision-free by `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own full
//! header sweep) back real `sigtimedwait(2)`/`sigwaitinfo(2)`/`sigwait(3)` and `sigqueue(2)` — the
//! two real, confirmed-live-caller gaps that doc's own "Missing, live caller confirmed" table
//! tracked. Real logic (`sys/process/signals.rs`'s `do_sigtimedwait`/`do_sigqueue`) is
//! kernel-resident, same thin-wrapper pattern as everything else in this module — see those
//! functions' own doc comments for the genuinely new signal-consuming (not handler-invoking)
//! primitive `do_sigtimedwait` needed, and the real sender-identity/payload tracking
//! (`Process::pending_siginfo`) both now share with the `SA_SIGINFO` handler-invocation path.
#![no_std]

unsafe extern "C" {
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_kill(pid: u64, sig: u64) -> i64;
    fn oxidebsd_sys_sigaction(sig: u64, act_ptr: u64, oldact_ptr: u64, sigsetsize: u64) -> i64;
    fn oxidebsd_sys_sigprocmask(how: u64, set_ptr: u64, oldset_ptr: u64, sigsetsize: u64) -> i64;
    fn oxidebsd_sys_sigpending(set_ptr: u64, sigsetsize: u64) -> i64;
    fn oxidebsd_sys_tkill(tid: u64, sig: u64) -> i64;
    fn oxidebsd_sys_sigaltstack(ss_ptr: u64, old_ptr: u64) -> i64;
    fn oxidebsd_sys_pause() -> i64;
    fn oxidebsd_sys_sigsuspend(mask_ptr: u64, sigsetsize: u64) -> i64;
    fn oxidebsd_sys_sigtimedwait(mask_ptr: u64, info_ptr: u64, ts_ptr: u64, sigsetsize: u64) -> i64;
    fn oxidebsd_sys_sigqueue(pid: u64, sig: u64, siginfo_ptr: u64, arg3: u64) -> i64;
}

const SYS_KILL: u64 = 116;
const SYS_SIGACTION: u64 = 117;
const SYS_SIGPROCMASK: u64 = 118;
/// Real, unremapped Linux value -- redirected here off its previous accidental collision with
/// `SYS_STAT = 127` by the full header sweep in `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`. See that doc's
/// own collision table for why 127 was unsafe and 494 isn't.
const SYS_SIGPENDING: u64 = 494;
/// Real, unclaimed Linux `__NR_tkill` value -- used directly, no musl-side remap needed. See
/// `sys/syscall/ffi.rs`'s `sys_tkill` doc comment for why this is just `kill` under another name
/// on a single-threaded kernel.
const SYS_TKILL: u64 = 200;
/// Item 3 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of
/// implementation" batch -- a permanent OxideBSD-invented number claimed before this handler
/// existed, same reasoning `sys/modules/posix_compat`'s `SYS_GETRANDOM`/`SYS_SYSINFO` already have.
const SYS_SIGALTSTACK: u64 = 528;
/// Item 4 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of
/// implementation" batch -- same reasoning `SYS_SIGALTSTACK` just above already has.
const SYS_PAUSE: u64 = 529;
/// Item 5 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of
/// implementation" batch -- same reasoning `SYS_PAUSE` just above already has.
const SYS_SIGSUSPEND: u64 = 530;
/// Real, unclaimed Linux `__NR_rt_sigtimedwait` value -- used directly, no invented number or
/// musl-side remap needed (already confirmed collision-free by `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s
/// own full header sweep). Backs `sigtimedwait(2)`/`sigwaitinfo(2)`/`sigwait(3)`.
const SYS_SIGTIMEDWAIT: u64 = 495;
/// Real, unclaimed Linux `__NR_rt_sigqueueinfo` value -- same story as `SYS_SIGTIMEDWAIT` above.
/// Backs `sigqueue(2)`.
const SYS_SIGQUEUE: u64 = 496;

extern "C" fn handle_kill(pid: u64, sig: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_kill(pid, sig) }
}

extern "C" fn handle_sigaction(sig: u64, act_ptr: u64, oldact_ptr: u64, sigsetsize: u64) -> i64 {
    unsafe { oxidebsd_sys_sigaction(sig, act_ptr, oldact_ptr, sigsetsize) }
}

extern "C" fn handle_sigprocmask(how: u64, set_ptr: u64, oldset_ptr: u64, sigsetsize: u64) -> i64 {
    unsafe { oxidebsd_sys_sigprocmask(how, set_ptr, oldset_ptr, sigsetsize) }
}

extern "C" fn handle_sigpending(set_ptr: u64, sigsetsize: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_sigpending(set_ptr, sigsetsize) }
}

extern "C" fn handle_tkill(tid: u64, sig: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_tkill(tid, sig) }
}

extern "C" fn handle_sigaltstack(ss_ptr: u64, old_ptr: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_sigaltstack(ss_ptr, old_ptr) }
}

extern "C" fn handle_pause(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_pause() }
}

extern "C" fn handle_sigsuspend(mask_ptr: u64, sigsetsize: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_sigsuspend(mask_ptr, sigsetsize) }
}

extern "C" fn handle_sigtimedwait(mask_ptr: u64, info_ptr: u64, ts_ptr: u64, sigsetsize: u64) -> i64 {
    unsafe { oxidebsd_sys_sigtimedwait(mask_ptr, info_ptr, ts_ptr, sigsetsize) }
}

extern "C" fn handle_sigqueue(pid: u64, sig: u64, siginfo_ptr: u64, arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_sigqueue(pid, sig, siginfo_ptr, arg3) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_KILL, handle_kill);
        oxidebsd_register_syscall(SYS_SIGACTION, handle_sigaction);
        oxidebsd_register_syscall(SYS_SIGPROCMASK, handle_sigprocmask);
        oxidebsd_register_syscall(SYS_SIGPENDING, handle_sigpending);
        oxidebsd_register_syscall(SYS_TKILL, handle_tkill);
        oxidebsd_register_syscall(SYS_SIGALTSTACK, handle_sigaltstack);
        oxidebsd_register_syscall(SYS_PAUSE, handle_pause);
        oxidebsd_register_syscall(SYS_SIGSUSPEND, handle_sigsuspend);
        oxidebsd_register_syscall(SYS_SIGTIMEDWAIT, handle_sigtimedwait);
        oxidebsd_register_syscall(SYS_SIGQUEUE, handle_sigqueue);
    }
    0
}
