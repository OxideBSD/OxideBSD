//! The low-level mechanics of moving execution from one process's kernel stack to another's:
//! `switch_context` (the generic save/restore primitive) plus the two trampolines that give a
//! process that has never run before somewhere to "return" into.
//!
//! `switch_context` only saves/restores System V's callee-saved registers (`rbp`, `rbx`,
//! `r12`-`r15`) plus `RSP` itself, via the ordinary `call`/`ret` mechanism — **not** a full GPR
//! save like `sys/syscall.rs`'s `syscall_entry`. Everything else is either caller-saved (already
//! safe on the Rust call stack of whichever function called `scheduler::schedule()`) or, for a
//! process's ring-3 register state, already saved by `syscall_entry`'s own pushes on *that
//! process's own* kernel stack. This is the classic kernel-thread "swtch" pattern (see e.g. xv6),
//! not an interrupt-style save.
//!
//! The restore side of `switch_context` is exactly symmetric with the save side — that symmetry
//! is what lets one primitive handle both "resume a process that previously yielded mid-syscall"
//! (the final `ret` lands back inside `scheduler::schedule()`'s own call site, and execution
//! unwinds normally back up through whatever Rust code was running, e.g. `process::do_wait4`'s
//! loop) and "start a process that has never run at all" (a hand-seeded fake stack frame with the
//! same shape makes the final `ret` land in a trampoline instead). `switch_context` itself has no
//! "first run" special case — only how each process's *initial* stack contents are constructed
//! differs, in `seed_spawn_frame`/`seed_fork_frame` below.
//!
//! Two trampolines, deliberately asymmetric:
//! - `spawn_trampoline_asm` (a process that's never run at all — `pid` 1, or any future non-forked
//!   `spawn`): defensively `and rsp, -16` before `call`ing into real Rust code
//!   (`spawn_trampoline_inner`, `sys/process.rs`) — sidesteps hand-deriving the exact stack offset
//!   that would satisfy System V's call-entry alignment convention, which is easy to get subtly
//!   wrong (silent SSE-adjacent misalignment faults) and painful to debug.
//! - `fork_trampoline_asm` (forked children only): jumps straight into
//!   `syscall_return_tail` (`sys/syscall.rs`'s `syscall_entry` GPR-pop-and-`iretq` tail) with
//!   **no** realignment at all — `seed_fork_frame` places the copied `SyscallFrame` immediately
//!   below the fake register-save frame, so after `switch_context`'s pops and `ret`, `RSP` already
//!   points exactly at the copied frame's first field, exactly what `syscall_return_tail` expects.
//!   Counter-intuitively the fork path needs *less* defensive code than the spawn path — worth
//!   remembering, since intuition suggests the opposite.

use core::arch::global_asm;
use core::mem::size_of;

use x86_64::VirtAddr;

use crate::syscall::SyscallFrame;

unsafe extern "C" {
    /// `switch_context(old_rsp_slot: *mut u64, new_rsp: u64)`: saves the six callee-saved GPRs and
    /// the current `RSP` into `*old_rsp_slot`, then loads `RSP` from `new_rsp` and restores its
    /// own six callee-saved GPRs before `ret`urning — to whatever call site owns `new_rsp`'s
    /// stack, which may be a completely different logical flow (or, for a process's first run, a
    /// trampoline) than the one that called `switch_context` in the first place.
    ///
    /// # Safety
    ///
    /// `old_rsp_slot` must be a valid, writable `*mut u64` (a scratch slot is fine if there's no
    /// real "previous process" to resume later — see `scheduler::start`). `new_rsp` must point at
    /// a stack region shaped exactly like what this function itself saves: six callee-saved GPRs
    /// then a `call`-style return address, low-to-high — true by construction both for a
    /// previously-switched-away-from process's own saved `rsp` and for this file's
    /// `seed_spawn_frame`/`seed_fork_frame`.
    pub fn switch_context(old_rsp_slot: *mut u64, new_rsp: u64);

    fn spawn_trampoline_asm();
    fn fork_trampoline_asm();
}

/// Mirrors exactly what `switch_context`'s asm pushes, low address to high: the six callee-saved
/// GPRs (in push order — last pushed is lowest address, hence first field here) followed by the
/// `call`-pushed return address. `seed_spawn_frame`/`seed_fork_frame` hand-build one of these at
/// the top of a fresh kernel stack so a never-run process's first switch-in lands in the right
/// trampoline instead of resuming nonexistent prior execution.
#[repr(C)]
struct SwitchFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rbp: u64,
    return_address: u64,
}

/// Seeds a fresh kernel stack (for a process created by `process::spawn`, never run before) so its
/// first switch-in lands in `spawn_trampoline_asm`. Returns the RSP value to store in the new
/// process's `rsp` field.
pub(crate) fn seed_spawn_frame(kernel_stack_top: VirtAddr) -> u64 {
    let frame_addr = kernel_stack_top.as_u64() - size_of::<SwitchFrame>() as u64;
    let frame = SwitchFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbx: 0,
        rbp: 0,
        return_address: spawn_trampoline_asm as *const () as u64,
    };
    // SAFETY: frame_addr falls within this process's own freshly allocated, otherwise-untouched
    // kernel stack (KernelStack::new zeroes it and nothing has run on it yet), with room for a
    // full SwitchFrame below kernel_stack_top.
    unsafe { core::ptr::write(frame_addr as *mut SwitchFrame, frame) };
    frame_addr
}

/// Seeds a freshly forked child's kernel stack so its first switch-in lands in
/// `fork_trampoline_asm`, which resumes it as if it were returning from the very same `fork()`
/// syscall its parent made — but with return value `0`. Copies `*parent_frame` (the parent's own
/// live `SyscallFrame`, mid-`sys_fork`) onto the child's stack via
/// `syscall::copy_frame_for_fork` (which also forces the copy's `rax` to `0`), placing it
/// immediately below a `SwitchFrame` pointing at `fork_trampoline_asm` — the two frames'
/// adjacency is exactly what lets `fork_trampoline_asm` jump straight into `syscall_return_tail`
/// with no stack adjustment at all. Returns the RSP value to store in the child's `rsp` field.
///
/// # Safety
///
/// `parent_frame` must point at a valid, fully-initialized `SyscallFrame` (i.e. the caller's own
/// `syscall::current_frame()`, called from within `sys_fork`'s own handling).
pub(crate) unsafe fn seed_fork_frame(
    kernel_stack_top: VirtAddr,
    parent_frame: *const SyscallFrame,
) -> u64 {
    let syscall_frame_addr = kernel_stack_top.as_u64() - size_of::<SyscallFrame>() as u64;
    // SAFETY: syscall_frame_addr points at size_of::<SyscallFrame>() freshly allocated, unused
    // bytes at the top of this (otherwise-untouched) kernel stack; parent_frame is valid per this
    // function's own safety contract.
    unsafe {
        crate::syscall::copy_frame_for_fork(syscall_frame_addr as *mut SyscallFrame, parent_frame);
    }

    let switch_frame_addr = syscall_frame_addr - size_of::<SwitchFrame>() as u64;
    let frame = SwitchFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbx: 0,
        rbp: 0,
        return_address: fork_trampoline_asm as *const () as u64,
    };
    // SAFETY: switch_frame_addr sits directly below the just-written SyscallFrame, still within
    // this fresh kernel stack.
    unsafe { core::ptr::write(switch_frame_addr as *mut SwitchFrame, frame) };
    switch_frame_addr
}

/// `seed_fork_frame`'s sibling for real `clone(2)`/`CLONE_THREAD` (`process::lifecycle::
/// do_clone`) — identical shape (the child's first switch-in also lands in
/// `fork_trampoline_asm`, resuming as if returning from the same syscall the parent made, with
/// `rax = 0`), except the copied frame's `user_rsp` is overridden to the real `newsp` argument
/// (`syscall::copy_frame_for_clone`, not `copy_frame_for_fork`) — a cloned thread starts running on
/// its own caller-supplied stack, not a copy of the parent's.
///
/// # Safety
///
/// `parent_frame` must point at a valid, fully-initialized `SyscallFrame` (i.e. the caller's own
/// `syscall::current_frame()`, called from within `do_clone`'s own handling).
pub(crate) unsafe fn seed_clone_frame(
    kernel_stack_top: VirtAddr,
    parent_frame: *const SyscallFrame,
    new_user_rsp: u64,
) -> u64 {
    let syscall_frame_addr = kernel_stack_top.as_u64() - size_of::<SyscallFrame>() as u64;
    // SAFETY: syscall_frame_addr points at size_of::<SyscallFrame>() freshly allocated, unused
    // bytes at the top of this (otherwise-untouched) kernel stack; parent_frame is valid per this
    // function's own safety contract.
    unsafe {
        crate::syscall::copy_frame_for_clone(
            syscall_frame_addr as *mut SyscallFrame,
            parent_frame,
            new_user_rsp,
        );
    }

    let switch_frame_addr = syscall_frame_addr - size_of::<SwitchFrame>() as u64;
    let frame = SwitchFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbx: 0,
        rbp: 0,
        return_address: fork_trampoline_asm as *const () as u64,
    };
    // SAFETY: switch_frame_addr sits directly below the just-written SyscallFrame, still within
    // this fresh kernel stack.
    unsafe { core::ptr::write(switch_frame_addr as *mut SwitchFrame, frame) };
    switch_frame_addr
}

global_asm!(
    ".global switch_context",
    "switch_context:",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rdi], rsp",
    "mov rsp, rsi",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "ret",
    ".global spawn_trampoline_asm",
    "spawn_trampoline_asm:",
    // Defensive realignment, not a derived offset -- see this file's module doc comment.
    "and rsp, -16",
    "call spawn_trampoline_inner", // -> !, never returns
    ".global fork_trampoline_asm",
    "fork_trampoline_asm:",
    // RSP already points exactly at the copied SyscallFrame's first field -- see seed_fork_frame.
    "jmp syscall_return_tail",
);
