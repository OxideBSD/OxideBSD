//! Picks which `Ready` process runs next and performs the actual switch: repointing `CR3`
//! (address space) and `TSS.RSP0` (via `gdt::set_kernel_stack` — the stack the CPU auto-switches
//! to on the next ring-3→ring-0 transition) before handing off to
//! `context_switch::switch_context`.
//!
//! **Real preemption**: a process leaves `Running` either voluntarily (calling `schedule()` itself
//! via `process::do_exit`/`do_wait4`/every other blocking primitive — unchanged) *or* because
//! `interrupts::timer_interrupt_handler` caught it executing ring-3 (user-mode) code and called
//! this exact same `schedule()` directly, once a time quantum elapsed. No raw-asm timer-entry
//! conversion needed (an earlier version of this comment predicted one would be) — `schedule()`
//! itself is just a stack-pointer-swap primitive (`switch_context`) agnostic to *why* the caller
//! is yielding, so calling it from inside the existing `extern "x86-interrupt" fn` works
//! unmodified: the preempted process's own compiler-generated interrupt-return sequence sits
//! dormant on its own kernel stack (below wherever `switch_context`'s `ret` suspended it) until
//! this exact same pid is picked again, at which point unwinding back up through `schedule()` and
//! this file's own call site reaches that dormant `iretq` naturally. **Deliberately scoped to
//! ring-3 only** — kernel/syscall/module code is never preempted (`IA32_SFMASK` already clears
//! `IF` for a `SYSCALL`'s whole duration, and nothing else here runs with `IF` set for long), so no
//! kernel `spin::Mutex`/module-static-data critical section anywhere in this codebase needed
//! auditing for preemption-safety — user-mode code never holds one. See
//! `interrupts::timer_interrupt_handler`'s own doc comment for the ring check/quantum/EOI-ordering
//! details, and `cpu::fpu`'s module doc comment for the one real correctness gap preemption opened
//! up (unsaved SSE/x87 state) and how it's closed (`Process::fpu_state`).
//!
//! **"Nothing runnable" no longer means "spin forever with interrupts masked."** `schedule()`'s
//! own fallback used to be `crate::hlt_loop()` — a deliberate, permanent dead end, safe only
//! because until `sh` (BusyBox's `hush`) needed a real blocking stdin read (`crate::stdin`'s own
//! module doc comment, `process::BlockReason::WaitingForStdin`), *every* blocked process was woken
//! by another *schedulable* process's own syscall (`do_exit` waking a `wait4`er, `pipe_write`
//! waking a pipe reader) — something always eventually ran to do the waking, so an empty ready
//! queue genuinely meant "stuck forever" and burning a core spinning was an acceptable (if wasteful)
//! way to make that visible. A blocked stdin read breaks that assumption: the *only* thing that can
//! ever wake it is a hardware keyboard IRQ, which can't fire at all while `IA32_SFMASK`-cleared
//! `IF` (or a permanently spinning `hlt_loop` that never bothered to `sti` first) keeps interrupts
//! masked. `wait_for_ready` below replaces that fallback with a real idle wait: enable interrupts
//! just long enough to let a hardware interrupt land (the standard `sti; hlt` atomic idiom, so a
//! wakeup racing the check is never lost), then re-disable and re-check. Safe to do here
//! specifically because, by construction, nothing in `schedule()`'s own call path still holds
//! `process::table()`/`READY_QUEUE` at this point (every caller that blocks — `do_wait4`,
//! `pipe_read`, `stdin::read` — drops its locks before ever calling `schedule()`) — the keyboard
//! IRQ handler's own locking of those same structures (to wake a blocked reader) can't deadlock
//! against a lock this code is still holding, because it isn't holding any.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use x86_64::instructions::interrupts::without_interrupts;

use crate::cpu::gdt;
use crate::process::context_switch::switch_context;
use crate::process::{self, Pid, ProcState};
use crate::serial_println;

/// `0` is never a valid `Pid` (`process::alloc_pid` starts at 1) — used as "no current process,"
/// true only before the very first `scheduler::start`.
static CURRENT_PID: AtomicU64 = AtomicU64::new(0);
static READY_QUEUE: Mutex<VecDeque<Pid>> = Mutex::new(VecDeque::new());

/// Discard slot for `switch_context`'s `old_rsp_slot` on the very first switch (`start`), which
/// has no real "previous process" to save an `rsp` into. `static mut`, not `static`, for the same
/// reason `gdt.rs`'s RSP0/IST stacks are: it's written only by hardware-adjacent asm (the `mov
/// [rdi], rsp` inside `switch_context`), never through a Rust-visible write, so a plain `static`
/// risks being interned into `.rodata` by the optimizer.
static mut BOOT_SCRATCH_RSP: u64 = 0;

pub fn current_pid() -> Pid {
    CURRENT_PID.load(Ordering::Relaxed)
}

/// The calling process's real POSIX thread-group id (`Process::tgid`) — what `fs::fd` (`CLONE_FILES`
/// sharing) and `process::identity::do_getpid` both actually want, distinct from `current_pid()`'s
/// raw schedulable pid once real `clone(2)`-created threads exist. Factors out the same
/// `table().get(&pid).map(|p| p.tgid)` lookup `identity::do_getpid` and `limits::do_futex` each
/// already duplicated on their own. Falls back to `current_pid()` itself if the table lookup ever
/// fails (mirrors `do_getpid`'s own fallback) — should only happen transiently, e.g. mid-construction
/// before a fresh `Process` is inserted.
pub fn current_tgid() -> Pid {
    let pid = current_pid();
    process::table()
        .lock()
        .get(&pid)
        .map(|p| p.tgid)
        .unwrap_or(pid)
}

pub fn enqueue_ready(pid: Pid) {
    READY_QUEUE.lock().push_back(pid);
}

/// Real `SCHED_FIFO`/`SCHED_RR` priority-based preemption: pops the *highest-`sched_priority`*
/// pid currently sitting in `READY_QUEUE`, not simply the front (plain FIFO order is preserved as
/// the tie-break among equal priorities, which is what real `SCHED_RR` round-robin — and this
/// codebase's original, still-unchanged `SCHED_OTHER` fairness, since every such process shares
/// the one valid priority for that policy, `0` — both already want). Deliberately reads
/// `Process::sched_priority` here rather than having every one of `enqueue_ready`'s ~15 call
/// sites pass it in: several of those already hold `process::table()`'s lock at the point they
/// enqueue (`spin::Mutex` isn't reentrant, so `enqueue_ready` itself must never try to lock the
/// table) — but nothing calls *this* function while still holding that lock (only ever reached via
/// `wait_for_ready`, itself only ever reached from `schedule()` after any table guard it took has
/// already been dropped), so it's the one safe place to actually consult priority.
///
/// O(n) per dequeue instead of the old `pop_front`'s O(1) — fine at this kernel's process-table
/// scale (never more than a handful of ready processes at once).
fn dequeue_highest_priority() -> Option<Pid> {
    let mut queue = READY_QUEUE.lock();
    if queue.is_empty() {
        return None;
    }
    let table = process::table().lock();
    let priority_of = |pid: Pid| table.get(&pid).map(|p| p.sched_priority).unwrap_or(0);
    let mut best_idx = 0;
    let mut best_priority = priority_of(queue[0]);
    for (i, &pid) in queue.iter().enumerate().skip(1) {
        let priority = priority_of(pid);
        if priority > best_priority {
            best_priority = priority;
            best_idx = i;
        }
    }
    drop(table);
    queue.remove(best_idx)
}

/// Whether some pid in `READY_QUEUE` outranks `current_priority` — the real-time half of
/// preemption: `interrupts::timer_interrupt_handler` calls this on *every* tick (not just once a
/// quantum expires) so a newly-readied higher-priority `SCHED_FIFO`/`SCHED_RR` process preempts
/// within one tick (~10ms at `TIMER_HZ`), not up to a full `PREEMPT_QUANTUM_TICKS` quantum later —
/// real POSIX/Linux would preempt essentially instantly (an IPI on a real multi-core kernel); this
/// kernel has no such mechanism and is single-core regardless, so the next timer tick is the
/// tightest bound achievable without one. Every `SCHED_OTHER` process shares priority `0`, so this
/// is always `false` for the pre-existing plain-round-robin case — zero behavioral change there.
pub fn ready_queue_has_higher_priority_than(current_priority: i32) -> bool {
    let queue = READY_QUEUE.lock();
    if queue.is_empty() {
        return false;
    }
    let table = process::table().lock();
    queue
        .iter()
        .any(|&pid| table.get(&pid).map(|p| p.sched_priority).unwrap_or(0) > current_priority)
}

/// Removes `pid` from `READY_QUEUE` if it's sitting in it -- needed only for a cross-process
/// `SIGSTOP`/`SIGTSTP` (see `process::signals`'s `Action::Stop` handling) landing on a target
/// that's `Ready` but hasn't actually run yet. Without this, the scheduler would still pop and run
/// it on its next turn regardless of `state` having been flipped to `Stopped` — nothing else in
/// this cooperative scheduler ever needs to retract a pid it already enqueued, so this has no
/// other caller.
pub fn remove_ready(pid: Pid) {
    READY_QUEUE.lock().retain(|&p| p != pid);
}

/// What `reap_pending_threads` should do once it's safe (`current_pid()` has genuinely moved off
/// the queued pid's own stack) -- see `PENDING_THREAD_REAPS`'s own doc comment for why this can't
/// happen inline at the moment a process decides to exit itself.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReapKind {
    /// Remove the whole `Process` table entry -- a non-leader `CLONE_THREAD` sibling (never an
    /// independent `wait4` target, see `do_clone`'s own doc comment) or a self-exiting process
    /// whose parent's `SIGCHLD` action has `SA_NOCLDWAIT` set (never left as a wait4-reapable
    /// zombie at all, see `terminate_process`'s own doc comment on that flag).
    RemoveEntry,
    /// Tear down just the address space's own physical frames (`me.address_space.take()`), but
    /// leave the table entry itself alive in `ProcState::Zombie` for a real future `wait4` to
    /// find and reap -- the default self-exit case. Real POSIX zombie semantics: only a small
    /// exit-status stub needs to survive until reaped, not the process's entire memory image.
    /// Splits "free the big stuff" (must happen promptly, or a long-running sequence of
    /// exit-without-being-reaped children permanently pins physical memory -- found live via a
    /// real kernel OOM panic under the POSIX conformance pilot's own full corpus, see
    /// `terminate_process`'s own doc comment) from "keep the small stuff for reap" (still fully
    /// gated on a parent's own `wait4` call, unchanged).
    TeardownOnly,
}

/// Pids queued for real cleanup by `process::lifecycle::terminate_process` once it's safe -- see
/// that function's own doc comment for why it can't just act on its own `Process` entry directly
/// when exiting itself (it's still running on that exact entry's own `KernelStack` at the point it
/// decides to exit). Drained by `reap_pending_threads` below, called at the top of every
/// `schedule()` -- by the time *any* call to `schedule()` other than the one a queued pid made to
/// exit itself runs, `CURRENT_PID` has necessarily moved on, so that pid's own stack (and, for
/// `ReapKind::TeardownOnly`, its own address space) is guaranteed no longer live/active.
static PENDING_THREAD_REAPS: Mutex<Vec<(Pid, ReapKind)>> = Mutex::new(Vec::new());

pub(crate) fn queue_thread_reap(pid: Pid, kind: ReapKind) {
    PENDING_THREAD_REAPS.lock().push((pid, kind));
}

/// Acts on every queued pid -- except one that still equals `current_pid()`, which means this is
/// the exact same `schedule()` call that pid's own `do_exit` made to switch away from itself
/// (still running on its own about-to-be-freed `KernelStack`/active `CR3`, mid-switch) -- left
/// queued for a later call, once some other process's own turn confirms `current_pid()` has
/// genuinely moved on. See `PENDING_THREAD_REAPS`'s own doc comment.
fn reap_pending_threads() {
    let mut pending = PENDING_THREAD_REAPS.lock();
    if pending.is_empty() {
        return;
    }
    let cur = current_pid();
    pending.retain(|&(pid, kind)| {
        if pid == cur {
            return true;
        }
        let address_space = match kind {
            ReapKind::RemoveEntry => process::table()
                .lock()
                .remove(&pid)
                .and_then(|p| p.address_space),
            ReapKind::TeardownOnly => process::table()
                .lock()
                .get_mut(&pid)
                .and_then(|p| p.address_space.take()),
        };
        // Real frame reclaim, not just a table-entry drop: `AddressSpace` has no `Drop` impl
        // (`teardown` is the only thing that ever frees its frames -- see that method's own doc
        // comment), and its own `Arc::strong_count` gate already correctly no-ops for a
        // `CLONE_THREAD` sibling whose address space is still shared with the rest of its thread
        // group, so this is safe to call unconditionally here regardless of which `ReapKind` this
        // was queued as.
        if let Some(address_space) = address_space {
            let phys_offset = crate::memory::phys_mem_offset();
            crate::memory::with_frame_allocator(|fa| unsafe {
                address_space.teardown(phys_offset, fa)
            });
        }
        false
    });
}

/// Voluntarily gives up the CPU. If the caller is still `Ready` or `Running` (i.e. it didn't just
/// block or exit), it's re-enqueued so it gets another turn later — a caller that transitioned to
/// `Blocked`/`Zombie` just before calling this is deliberately *not* re-enqueued, which is how
/// `process::do_wait4`/`do_exit` actually suspend/terminate. Picks the next `Ready` process and
/// switches to it; falls back to `wait_for_ready`'s real idle wait only if nothing is runnable at
/// all. Returns once this exact call site is switched back into — for a caller that just blocked,
/// that means "a later event woke it back to `Ready` and the scheduler picked it again."
pub fn schedule() {
    without_interrupts(|| {
        reap_pending_threads();

        let prev_pid = current_pid();
        let has_prev = prev_pid != 0;

        if has_prev {
            let mut table = process::table().lock();
            let prev = table
                .get_mut(&prev_pid)
                .expect("schedule: current process missing from table");
            if matches!(prev.state, ProcState::Ready | ProcState::Running) {
                // Real invariant this codebase's own cross-process `Action::Stop` handling
                // (`process::signals`) depends on: "every pid sitting in `READY_QUEUE` has
                // `state == Ready`". Before real ring-3 preemption existed, `schedule()` only
                // ever reached this branch via a still-`Running` caller voluntarily yielding
                // (`sched_yield`); a genuinely `Ready` (never-yet-run, or already-preempted-once)
                // pid re-entering here was never a real case. Real preemption broke that
                // assumption silently: the timer interrupt now calls this same function directly
                // on a still-`Running`, merely-interrupted process, and this branch used to leave
                // `state` at its stale `Running` value while still pushing it onto `READY_QUEUE`.
                // A cross-process `SIGSTOP` landing on exactly that pid then saw `state ==
                // Running` (not `Ready`), skipped its own `remove_ready` dequeue, and left a
                // `Stopped` process's own stale entry sitting in the queue -- which the scheduler
                // then genuinely popped and resumed later via `activate_and_prepare` (which sets
                // `Running` unconditionally), silently un-stopping it and stomping the `Stopped`
                // state a subsequent `SIGCONT`'s own `matches!(state, Stopped(_))` check depended
                // on. Found live: a flaky (preemption-timing-dependent) hang in
                // `sigaction/11-1.c`'s own `SIGSTOP`/`SIGCONT`/`CLD_CONTINUED` round trip. Fixed
                // at the actual source of the drift, not by loosening `Action::Stop`'s own check.
                prev.state = ProcState::Ready;
                drop(table);
                enqueue_ready(prev_pid);
            }
        }

        // If the caller itself were still Ready/Running it would have just been popped back out
        // above, so an empty queue here means the system is genuinely idle right now -- wait_for_ready
        // blocks (with interrupts real-enabled, not spinning) until a hardware event makes that no
        // longer true.
        let next_pid = wait_for_ready();

        if has_prev && next_pid == prev_pid {
            let mut table = process::table().lock();
            let prev = table.get_mut(&prev_pid).unwrap();
            prev.state = ProcState::Running;
            // Same fresh-quantum reasoning as `activate_and_prepare` -- this fast path (nothing
            // else was ready, so the same process just keeps running) skips that function
            // entirely, so it needs its own reset here.
            prev.quantum_ticks_left = crate::cpu::interrupts::PREEMPT_QUANTUM_TICKS;
            return;
        }

        let prev_rsp_slot: *mut u64 = if has_prev {
            let mut table = process::table().lock();
            let prev = table.get_mut(&prev_pid).unwrap();
            // SAFETY: prev is the outgoing process, about to be switched away from on the very
            // next line below — its live hardware FPU/SSE state genuinely belongs to it (see
            // cpu::fpu's own module doc comment for why this capture is required now that
            // preemption exists) and fpu_state is a valid, 16-byte-aligned FxSaveArea field.
            unsafe { crate::cpu::fpu::save(&mut prev.fpu_state as *mut _) };
            &mut prev.rsp as *mut u64
        } else {
            &raw mut BOOT_SCRATCH_RSP
        };

        let next_rsp = activate_and_prepare(next_pid);
        CURRENT_PID.store(next_pid, Ordering::Relaxed);

        // SAFETY: prev_rsp_slot is either a live Process's own `rsp` field or the dedicated boot
        // scratch slot; next_rsp was seeded by process::spawn/do_fork_from_current (a never-run
        // process) or saved by this exact process's own previous call to schedule() (a resumed
        // one) — both satisfy switch_context's stack-shape requirement. The whole function runs
        // under without_interrupts, so no timer IRQ can land between repointing RSP0 in
        // activate_and_prepare and switch_context actually moving execution onto the new stack.
        unsafe { switch_context(prev_rsp_slot, next_rsp) };
    });
}

/// Blocks (genuinely — not spinning) until `READY_QUEUE` has something in it, and returns that
/// pid. See this module's own doc comment for why this exists at all (`hlt_loop()`'s old
/// permanent-dead-end fallback can't work once a process can be blocked waiting on nothing but a
/// hardware interrupt) and why it's safe to enable interrupts here specifically (every caller that
/// blocks drops its own locks before ever reaching `schedule()`, so nothing this code's caller
/// might be holding can be re-entered by the keyboard IRQ handler this is specifically waiting to
/// let fire).
///
/// Only ever called from inside `schedule()`'s own `without_interrupts` critical section, but
/// explicitly `disable()`s at the top of every loop iteration anyway (not just relying on that
/// outer wrapper) — cheap, and makes this function's own precondition self-contained rather than
/// relying on every future call site to remember it.
fn wait_for_ready() -> Pid {
    loop {
        x86_64::instructions::interrupts::disable();
        // Scoped so the READY_QUEUE guard (and the process-table guard `dequeue_highest_priority`
        // briefly takes internally) are dropped before enable_and_hlt() below -- holding either
        // across that would let the keyboard IRQ handler's own wake-up (which needs the same
        // locks, see crate::console::stdin::push_byte) deadlock against itself on this single core.
        let popped = dequeue_highest_priority();
        if let Some(pid) = popped {
            return pid;
        }
        // Nothing runnable anywhere. The only thing that can still change that is a hardware
        // interrupt (concretely: the keyboard IRQ waking a process blocked on stdin) -- enable
        // interrupts and halt right up to the point one arrives, rather than either burning a full
        // core spinning forever or leaving interrupts masked forever (which would make that
        // wakeup impossible in the first place). `sti; hlt` back to back is the standard atomic
        // idiom for exactly this: x86 guarantees the very next instruction after `sti` (here,
        // `hlt`) executes before any interrupt just unmasked is actually taken, so a wakeup that
        // raced right up against the check above is never lost.
        x86_64::instructions::interrupts::enable_and_hlt();
        // Woken by *some* interrupt (timer or keyboard) -- loop back and re-check; only a keyboard
        // IRQ that actually queued a reader will make the next pop_front() succeed.
    }
}

/// The very first switch: boots the scheduler by "switching away" from the current boot stack
/// into `first_pid`, which must already be `Ready` in the process table (i.e. already
/// `process::spawn`'d). Never returns — same one-way shape `usermode::jump_to_usermode` always
/// had (and which this function reaches indirectly, via `spawn_trampoline_inner`).
pub fn start(first_pid: Pid) -> ! {
    serial_println!("[boot] scheduler starting: switching to pid {}", first_pid);
    without_interrupts(|| {
        let next_rsp = activate_and_prepare(first_pid);
        CURRENT_PID.store(first_pid, Ordering::Relaxed);
        // SAFETY: see schedule()'s own safety comment; the boot stack this runs on is abandoned
        // for good, exactly like usermode::jump_to_usermode's own one-way transition.
        unsafe { switch_context(&raw mut BOOT_SCRATCH_RSP, next_rsp) };
    });
    unreachable!("scheduler::start's switch_context should never return to the boot stack");
}

/// Marks `pid` `Running`, activates its address space (`CR3`), repoints `TSS.RSP0` at its own
/// kernel stack, restores its own `IA32_FS_BASE`, and returns its saved `rsp` — the common tail
/// shared by `schedule()` and `start()` just before the actual `switch_context` call.
fn activate_and_prepare(pid: Pid) -> u64 {
    let mut table = process::table().lock();
    let next = table
        .get_mut(&pid)
        .expect("activate_and_prepare: pid missing from table");
    next.state = ProcState::Running;
    // A fresh quantum every time a process is (re)activated -- see `Process::quantum_ticks_left`'s
    // own doc comment for why this replaced a purely global-clock-phase preemption check.
    next.quantum_ticks_left = crate::cpu::interrupts::PREEMPT_QUANTUM_TICKS;
    // SAFETY: next's AddressSpace carries the kernel's own mappings (shared by every process, per
    // AddressSpace::new's shallow copy) plus its own user segments/stack, so activating it here —
    // still running on the outgoing stack, about to switch away — is safe, mirroring
    // AddressSpace::activate's own safety contract.
    // `.expect()`: only `ProcState::Zombie` ever has `address_space == None` (see that field's own
    // doc comment), and a Zombie is never picked to run -- `schedule()` only ever activates a
    // `Ready` pid.
    unsafe {
        next.address_space
            .as_ref()
            .expect("activate_and_prepare: picked a process with no address space")
            .activate()
    };
    gdt::set_kernel_stack(next.kernel_stack_top);
    // IA32_FS_BASE is a single global MSR, not something switch_context itself saves/restores (it
    // only touches RSP/callee-saved GPRs) -- without this, one process's own %fs-relative TLS
    // (every musl-linked binary's stack-protector check among it) would silently see whichever
    // *other* process last called SYS_SET_FS_BASE. See Process::fs_base's own doc comment for the
    // real crash this fixed.
    x86_64::registers::model_specific::FsBase::write(x86_64::VirtAddr::new(next.fs_base));
    // Same "restore before the switch actually lands" reasoning as schedule()'s own fpu::save
    // call on the outgoing side — by the time switch_context's `ret` hands control to next, the
    // hardware FPU/SSE registers must already hold *its* state, not whichever process ran last.
    // SAFETY: next.fpu_state is a valid, 16-byte-aligned FxSaveArea — either a real prior
    // fpu::save() (a process that's run before) or cpu::fpu::clean_state()'s own output (a
    // never-run process, see process::lifecycle::spawn/do_fork_from_current).
    unsafe { crate::cpu::fpu::restore(&next.fpu_state as *const _) };
    next.rsp
}
