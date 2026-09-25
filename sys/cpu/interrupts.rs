use core::sync::atomic::{AtomicU64, Ordering};

use pc_keyboard::layouts::Us104Key;
use pc_keyboard::{DecodedKey, HandleControl, KeyCode, PS2Keyboard, ScancodeSet1};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;
use x86_64::instructions::port::Port;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::cpu::gdt::DOUBLE_FAULT_IST_INDEX;
use crate::cpu::pic::{self, PIC_1_OFFSET, PIC_2_OFFSET};
use crate::reboot::reboot;
use crate::{serial_print, serial_println};

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

static TICKS: AtomicU64 = AtomicU64::new(0);

/// Number of timer interrupts handled since boot.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

type IrqHandlerSlot = Mutex<Option<fn()>>;

/// One slot per possible IRQ line (0-15); only 2-15 are ever populated -- 0/1 are permanently
/// owned by the timer/keyboard's own dedicated handlers below, never routed through this table.
/// Lets a driver whose IRQ line isn't known until runtime (e.g. read from a PCI device's
/// interrupt-line register during `net::rtl8139::probe_and_init`) claim a vector without the
/// static `IDT` needing to change shape.
static IRQ_HANDLERS: [IrqHandlerSlot; 16] = [const { Mutex::new(None) }; 16];

/// Registers `handler` to be called whenever `irq` fires. Must be paired with a subsequent
/// `pic::unmask_irq(irq)` -- until that call, the line stays masked at the controller and
/// `handler` is simply never invoked. Both calls should happen inside
/// `x86_64::instructions::interrupts::without_interrupts` to close the race where the line fires
/// between registration and unmasking.
pub fn register_irq_handler(irq: u8, handler: fn()) {
    assert!(
        (2..16).contains(&irq),
        "IRQ 0/1 are reserved for the timer/keyboard"
    );
    *IRQ_HANDLERS[irq as usize].lock() = Some(handler);
}

/// Defines one `extern "x86-interrupt"` trampoline per listed IRQ line (each must be a distinct
/// function item -- a handler installed into the IDT can't be parameterized by IRQ number at
/// runtime) plus `install_irq_trampolines`, which wires all of them into a `Lazy<IDT>` under
/// construction. Each trampoline dispatches through `IRQ_HANDLERS`, doing nothing but the EOI if
/// that line has no registered handler (a spurious or not-yet-claimed IRQ) -- and always sends
/// the EOI regardless, since skipping it leaves the line masked at the controller forever, not
/// just for this one interrupt.
macro_rules! define_irq_trampolines {
    ($( $name:ident => $irq:literal ),+ $(,)?) => {
        $(
            extern "x86-interrupt" fn $name(_stack_frame: InterruptStackFrame) {
                let handler = *IRQ_HANDLERS[$irq].lock();
                if let Some(handler) = handler {
                    handler();
                }
                unsafe {
                    pic::notify_end_of_interrupt(PIC_1_OFFSET + $irq);
                }
            }
        )+

        fn install_irq_trampolines(idt: &mut InterruptDescriptorTable) {
            $(
                idt[PIC_1_OFFSET + $irq].set_handler_fn($name);
            )+
        }
    };
}

define_irq_trampolines! {
    irq2_trampoline => 2,
    irq3_trampoline => 3,
    irq4_trampoline => 4,
    irq5_trampoline => 5,
    irq6_trampoline => 6,
    irq7_trampoline => 7,
    irq8_trampoline => 8,
    irq9_trampoline => 9,
    irq10_trampoline => 10,
    irq11_trampoline => 11,
    irq12_trampoline => 12,
    irq13_trampoline => 13,
    irq14_trampoline => 14,
    irq15_trampoline => 15,
}

// MapLettersToUnicode (not Ignore) so Ctrl+<letter> decodes to the corresponding C0 control code
// (Ctrl+C => 0x03, Ctrl+D => 0x04, etc.) instead of being silently dropped to the plain letter --
// stsh's read_line (see `regress/stsh/`) relies on those bytes reaching stdin to implement
// abort-line/EOF handling.
static KEYBOARD: Mutex<PS2Keyboard<Us104Key, ScancodeSet1>> = Mutex::new(PS2Keyboard::new(
    ScancodeSet1::new(),
    Us104Key,
    HandleControl::MapLettersToUnicode,
));

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    // DPL 3 so ring-3 code can hit this via `int3` directly: interrupt gates default to DPL 0,
    // and a *software*-invoked interrupt (unlike a hardware exception) additionally requires
    // CPL <= gate DPL, so leaving this at the default causes int3-from-ring-3 to fault with a
    // #GP on the gate itself instead of ever reaching this handler.
    idt.breakpoint
        .set_handler_fn(breakpoint_handler)
        .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
    idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
    idt.general_protection_fault
        .set_handler_fn(general_protection_fault_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt_handler);
    idt[InterruptIndex::Keyboard.as_u8()].set_handler_fn(keyboard_interrupt_handler);
    install_irq_trampolines(&mut idt);

    idt
});

pub fn init_idt() {
    serial_println!(
        "[boot] loading IDT: breakpoint, invalid_opcode, general_protection_fault, page_fault, \
         double_fault, timer (vector {:#x}), keyboard (vector {:#x}), IRQ2-15 trampolines \
         (vectors {:#x}-{:#x}, unclaimed until a driver calls register_irq_handler)",
        InterruptIndex::Timer.as_u8(),
        InterruptIndex::Keyboard.as_u8(),
        PIC_1_OFFSET + 2,
        PIC_1_OFFSET + 15,
    );
    IDT.load();
    serial_println!("[boot] IDT loaded");
}

/// Remaps the PIC pair's interrupt vectors and unmasks the timer/keyboard lines. Must run after
/// `init_idt` and before interrupts are enabled, so every unmasked IRQ already has a handler
/// installed.
pub fn init_pics() {
    serial_println!(
        "[boot] remapping PIC1/PIC2 to vectors {:#x}/{:#x}",
        PIC_1_OFFSET,
        PIC_2_OFFSET
    );
    unsafe {
        pic::init();
        // Explicit, not inherited from `pic::init()`'s own mask save/restore -- that preserves
        // whatever mask was already in place, which under real BIOS + the old `bootloader` crate
        // happened to leave IRQ0 (PIT timer)/IRQ1 (keyboard) unmasked by default, so this was
        // never needed before. Limine masks *both* the legacy PIC and the IOAPIC unconditionally
        // before handing off to the kernel (a real, documented protocol guarantee, not a bug) --
        // found live: with no explicit unmask here, `cpu::tsc::init()`'s own PIT-tick calibration
        // busy-wait (see that module's doc comment) spun forever, since the timer IRQ genuinely
        // never fired. Every other IRQ line (e.g. `net::rtl8139`'s own) already unmasks itself
        // explicitly once its own handler is registered -- timer/keyboard get the same treatment
        // here instead of relying on inherited firmware state, which is the more robust design
        // regardless of boot protocol.
        pic::unmask_irq(0);
        pic::unmask_irq(1);
    }
    serial_println!("[boot] PICs initialized and unmasked");
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

/// Ring-3 `#UD`s get the same fault-to-signal treatment `general_protection_fault_handler` below
/// already documents in full -- found auditing this file for the same gap after `page_fault_handler`/
/// `general_protection_fault_handler` had already been fixed: this handler still rebooted the whole
/// VM unconditionally on *any* invalid-opcode fault, ring-3 included (a real `ud2`, or a genuinely
/// corrupted jump into non-code memory, in any userland program). Real Linux maps every userland
/// `#UD` to `SIGILL`.
extern "x86-interrupt" fn invalid_opcode_handler(mut stack_frame: InterruptStackFrame) {
    let interrupted_ring3 = stack_frame.code_segment.0 & 0x3 == 3;
    if interrupted_ring3 {
        let pid = crate::process::scheduler::current_pid();
        if pid != 0 {
            // Real, force-delivered self-signal -- see `signals::force_fault_signal`'s own doc
            // comment for why a plain `do_kill` self-signal isn't safe here.
            crate::process::signals::force_fault_signal(pid, crate::process::SIGILL);
            // SAFETY: see page_fault_handler's own identical redirect.
            unsafe {
                stack_frame.as_mut().update(|f| {
                    f.instruction_pointer =
                        VirtAddr::new(crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA);
                });
            }
            return;
        }
    }
    serial_println!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
    reboot();
}

/// Ring-3 `#GP`s get the same fault-to-signal treatment `page_fault_handler` below already
/// documents in full (see that function's own doc comment for the trampoline mechanism and why a
/// direct handler call isn't possible from an `extern "x86-interrupt" fn`) -- found live, not
/// preemptively: the expanded POSIX conformance pilot's own `strftime/2-1.c` has a real stack-
/// buffer overflow (an upstream test bug -- it declares `char text[20]` but passes `256` as
/// `strftime`'s own max-length argument), correctly caught by musl's stack-protector, whose
/// `__stack_chk_fail` on this target is a bare `hlt; ret` (`hlt` is a privileged, ring-0-only
/// instruction) -- executing it from ring 3 raises exactly this fault. Before this fix, *any*
/// ring-3 `#GP` (a real stack-smashing catch, a bad segment reference, any other privileged-
/// instruction misuse) rebooted the whole VM instead of just terminating the one offending
/// process, a real robustness gap independent of this one test file. No fault-specific signal
/// distinction is needed the way `page_fault_handler`'s `SIGBUS`-vs-`SIGSEGV` split is: real Linux
/// maps every userland `#GP` to `SIGSEGV` uniformly, so this does too.
extern "x86-interrupt" fn general_protection_fault_handler(
    mut stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    let interrupted_ring3 = stack_frame.code_segment.0 & 0x3 == 3;
    if interrupted_ring3 {
        let pid = crate::process::scheduler::current_pid();
        if pid != 0 {
            // Real, force-delivered self-signal -- see `signals::force_fault_signal`'s own doc
            // comment for why a plain `do_kill` self-signal (which respects the target's own
            // blocked-signal mask, correct for an ordinary async `kill()`) isn't safe here: this
            // signal is synchronously generated by a real fault, which can't simply be "left
            // pending" if it happens to be blocked.
            serial_println!(
                "[fault] pid {} ring-3 #GP (error {:#x}) ip {:#x} -> SIGSEGV",
                pid,
                error_code,
                stack_frame.instruction_pointer.as_u64()
            );
            crate::process::signals::force_fault_signal(pid, crate::process::SIGSEGV);
            // SAFETY: see page_fault_handler's own identical redirect.
            unsafe {
                stack_frame.as_mut().update(|f| {
                    f.instruction_pointer =
                        VirtAddr::new(crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA);
                });
            }
            return;
        }
    }
    serial_println!(
        "EXCEPTION: GENERAL PROTECTION FAULT (error code: {:#x})\n{:#?}",
        error_code,
        stack_frame
    );
    reboot();
}

/// Ring-3 faults no longer reboot the whole kernel — they terminate (or, if a real handler is
/// installed, signal) just the one offending process. A kernel-mode fault (a real bug in this
/// kernel itself) is unchanged: still an unconditional reboot, the same safety net as before.
///
/// **Why this can't just invoke the process's own handler directly, right here**: unlike
/// `syscall::SyscallFrame` (built by hand, every GPR an explicit mutable field),
/// `extern "x86-interrupt"`'s compiler-generated entry/exit leaves the interrupted GPRs
/// (`RDI`/`RSI`/`RDX`/...) completely inaccessible to this function — only
/// `InterruptStackFrame`'s handful of fields (`instruction_pointer`, `stack_pointer`, `cpu_flags`,
/// the segment selectors) can be read or changed via its own `as_mut()`. A real, argument-correct
/// handler call needs to set `RDI = signum` (and `RSI`/`RDX` for `SA_SIGINFO`) directly, which this
/// function has no way to do. See `process::fault_trampoline`'s own module doc comment for the real
/// fix: record the signal as pending, then redirect `instruction_pointer` to a tiny kernel-authored
/// trampoline page that forces the process straight back through a real `SYSCALL` instruction,
/// landing in the already-correct, GPR-complete `syscall::deliver_pending_signal` machinery
/// instead.
///
/// `signal_for_user_fault` decides `SIGBUS` (a reference into a real fd-backed mapping's own
/// reserved-but-unbacked tail — `mmap/11-2.c`/`11-3.c` in the conformance pilot) vs. `SIGSEGV`
/// (every other unmapped/invalid ring-3 reference) — either way, `do_kill`'s own self-signal path
/// (just sets the pending bit, doesn't act on it) is reused rather than hand-rolling a second
/// "record this signal" path; `deliver_pending_signal`, reached via the trampoline, resolves the
/// real disposition (terminate, by default — a real fix in its own right, replacing a full reboot
/// — or a genuine handler invocation).
extern "x86-interrupt" fn page_fault_handler(
    mut stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    // Stack growth first, for either ring -- see `mm::try_grow_user_stack`. A not-present fault
    // inside the stack reserve just gets its page and retries the instruction.
    if !error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION)
        && let Ok(fault_addr) = Cr2::read()
        && crate::process::mm::try_grow_user_stack(fault_addr.as_u64())
    {
        return;
    }
    let interrupted_ring3 = stack_frame.code_segment.0 & 0x3 == 3;
    if interrupted_ring3 && let Ok(fault_addr) = Cr2::read() {
        let pid = crate::process::scheduler::current_pid();
        if pid != 0 {
            let sig = crate::process::signal_for_user_fault(pid, fault_addr.as_u64());
            // Real Linux logs "segfault at ADDR ip IP" for the same reason: without it a ring-3
            // crash is just an exit status. Added chasing ninja's first on-target SIGSEGV.
            serial_println!(
                "[fault] pid {} ring-3 page fault at {:#x} ip {:#x} ({:?}) -> signal {}",
                pid,
                fault_addr.as_u64(),
                stack_frame.instruction_pointer.as_u64(),
                error_code,
                sig
            );
            // Real, force-delivered self-signal -- see `signals::force_fault_signal`'s own doc
            // comment for why a plain `do_kill` self-signal (which respects the target's own
            // blocked-signal mask, correct for an ordinary async `kill()`) isn't safe here: this
            // signal is synchronously generated by a real fault, which can't simply be "left
            // pending" if it happens to be blocked. Safe to call from here for the identical
            // reason `timer_interrupt_handler`'s own calls into `process::table()`/`scheduler`
            // already are (this interrupt gate runs with IF cleared, same single-core
            // non-reentrancy this whole file already relies on).
            crate::process::signals::force_fault_signal(pid, sig);
            // SAFETY: only the resume RIP is changed -- redirecting straight into a real,
            // kernel-mapped, user-executable trampoline page (see its own module doc comment).
            // RSP/RFLAGS/the segment selectors are left exactly as they were; this process has
            // exactly one ring-3 code/data selector pair, already correct.
            unsafe {
                stack_frame.as_mut().update(|f| {
                    f.instruction_pointer =
                        VirtAddr::new(crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA);
                });
            }
            return;
        }
    }
    serial_println!(
        "EXCEPTION: PAGE FAULT\naccessed address: {:?}\nerror code: {:?}\n{:#?}",
        Cr2::read(),
        error_code,
        stack_frame
    );
    reboot();
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    serial_println!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
    reboot();
}

/// How many timer ticks (`TIMER_HZ = 100`, see `cpu::pit.rs`) a process gets before it's
/// preempted — `4` ticks = 40ms, a fairly conventional interactive quantum (in the same ballpark
/// as classic Linux's old `HZ=100` default). Only ever consulted for a process actually caught
/// running ring-3 (user-mode) code — see `timer_interrupt_handler`'s own doc comment.
pub(crate) const PREEMPT_QUANTUM_TICKS: u64 = 4;

/// Real preemption lives here: on top of the tick/sleeper-wake bookkeeping this handler has always
/// done, it now also decides whether to force a reschedule.
///
/// **Deliberately scoped to ring-3 only** — checked via `stack_frame.code_segment`'s RPL bits (the
/// CPU's own record of what was interrupted, not anything this handler has to track itself): a
/// hardware interrupt gate automatically switches onto `TSS.RSP0` (this process's own kernel
/// stack, kept in sync by `gdt::set_kernel_stack` on every context switch) whenever it catches
/// ring-3 code, so by the time this function runs, we're already on the right stack to suspend
/// this exact process via an ordinary `scheduler::schedule()` call. Ring-0 code (a syscall handler,
/// another IRQ handler, this very function's own housekeeping) is never preempted — deliberately,
/// not just "not implemented yet": user-mode code never holds a kernel `spin::Mutex` or touches
/// module static state, so scoping preemption to ring-3 sidesteps auditing every critical section
/// in this codebase for preemption-safety. See `scheduler.rs`'s own module doc comment for why
/// calling `schedule()` directly from this `extern "x86-interrupt" fn` is sound even though it may
/// not return for an arbitrary stretch of wall-clock time.
///
/// **EOI is sent before the possible `schedule()` call, not after** — load-bearing, not stylistic.
/// `schedule()` can switch away to a completely different process for an arbitrary amount of time
/// before this exact call returns (i.e. before this exact process is picked again); until the EOI
/// is sent, the PIC still considers IRQ0 "in service" and won't deliver *any* further timer
/// interrupt to anyone — which would freeze not just future preemption but every other
/// `ticks()`-gated wakeup in this file (sleepers, POSIX timers, `SIGALRM`, ...) for good.
extern "x86-interrupt" fn timer_interrupt_handler(mut stack_frame: InterruptStackFrame) {
    let now = TICKS.fetch_add(1, Ordering::Relaxed) + 1;

    // Wake any process blocked in `process::do_nanosleep` (`BlockReason::Sleeping`) whose deadline
    // has now passed -- same "IRQ handler reaches directly into `process::table()`" shape
    // `crate::console::stdin::push_byte`'s own `wake_blocked_readers` already established for
    // `WaitingForStdin`, just driven by this timer IRQ instead of the keyboard one. Safe for the
    // same reason that one is: every other place `process::table()` is locked either runs inside a
    // `SYSCALL` (where `SFMASK` clears `IF` for the syscall's entire duration) or inside
    // `scheduler::schedule()`'s own `without_interrupts` section -- this lock can never be held by
    // code this interrupt could actually preempt.
    {
        let mut table = crate::process::table().lock();
        // Real per-process CPU-time accounting (`Process::cpu_ticks`, see its own doc comment) --
        // the process this tick actually interrupted is the one that was consuming the CPU for it.
        // `current_pid() == 0` only at boot, before any real process exists.
        let current = crate::process::scheduler::current_pid();
        if current != 0
            && let Some(proc) = table.get_mut(&current)
        {
            proc.cpu_ticks += 1;
        }
        for (&pid, proc) in table.iter_mut() {
            if let crate::process::ProcState::Blocked(
                crate::process::BlockReason::Sleeping(deadline)
                | crate::process::BlockReason::Polling(deadline),
            ) = proc.state
                && now >= deadline
            {
                proc.state = crate::process::ProcState::Ready;
                crate::process::scheduler::enqueue_ready(pid);
            }

            // Real `mq_timedsend`/`mq_timedreceive` deadline expiry (`crate::fs::mqueue`) -- same
            // "IRQ handler reaches directly into `process::table()`" shape `Sleeping` just above
            // already established; `u64::MAX` (the plain `mq_send`/`mq_receive` wrapper's "no
            // timeout" case) never realistically matches `now` within this kernel's lifetime, so
            // no separate `Option`-typed deadline is needed. `do_mq_timedsend`/`do_mq_timedreceive`
            // re-check the real condition after waking, same discipline `Sleeping` establishes.
            if let crate::process::ProcState::Blocked(
                crate::process::BlockReason::WaitingForMqData(_, deadline)
                | crate::process::BlockReason::WaitingForMqSpace(_, deadline),
            ) = proc.state
                && now >= deadline
            {
                proc.state = crate::process::ProcState::Ready;
                crate::process::scheduler::enqueue_ready(pid);
            }

            // Real `semtimedop` deadline expiry (`crate::fs::sysv_sem`) -- same dual-wake shape
            // `WaitingForMqData`/`WaitingForMqSpace` just above already establish; `u64::MAX` (the
            // plain, non-timed `semop` wrapper's case) never realistically matches `now`.
            // `do_semop`/`do_semtimedop` re-check the whole op array from scratch after waking,
            // same discipline `Sleeping` establishes.
            if let crate::process::ProcState::Blocked(crate::process::BlockReason::WaitingForSemOp(
                _,
                _,
                _,
                deadline,
            )) = proc.state
                && now >= deadline
            {
                proc.state = crate::process::ProcState::Ready;
                crate::process::scheduler::enqueue_ready(pid);
            }

            // Real `sigtimedwait` deadline expiry (`process::signals::do_sigtimedwait`) -- same
            // dual-wake shape `WaitingForSemOp`/`WaitingForMqData` just above already establish;
            // `u64::MAX` (the plain `sigwaitinfo`/`sigwait` case) never realistically matches
            // `now`. `do_sigtimedwait`'s own loop re-checks `pending_signals & wait_set` fresh
            // after waking, same discipline `Sleeping` establishes.
            if let crate::process::ProcState::Blocked(
                crate::process::BlockReason::WaitingForSpecificSignal(_, deadline),
            ) = proc.state
                && now >= deadline
            {
                proc.state = crate::process::ProcState::Ready;
                crate::process::scheduler::enqueue_ready(pid);
            }

            // Real `FUTEX_WAIT` deadline expiry (`process::do_futex`) -- same dual-wake shape
            // `WaitingForSpecificSignal`/`WaitingForSemOp` just above already establish; `u64::MAX`
            // (a null `to`, the plain "wait forever" case) never realistically matches `now`.
            // `do_futex`'s own post-wake check re-verifies the real deadline fresh, same
            // discipline `Sleeping` establishes -- this scan only needs to flip `state` back to
            // `Ready` so that check gets a chance to run at all.
            if let crate::process::ProcState::Blocked(crate::process::BlockReason::WaitingForFutex(
                _,
                _,
                deadline,
            )) = proc.state
                && now >= deadline
            {
                proc.state = crate::process::ProcState::Ready;
                crate::process::scheduler::enqueue_ready(pid);
            }

            // `SYS_SETITIMER`'s `ITIMER_REAL` expiry (also backs real `alarm()`, a thin musl-side
            // wrapper around it -- see `process::do_setitimer`'s own doc comment). Just sets the
            // pending bit, the same simple, already-established pattern `process::do_kill`'s own
            // self-targeting case uses (`me.pending_signals |= ...`) -- real delivery/default
            // termination happens naturally at this exact process's own next syscall-dispatch tail
            // (`sys/syscall.rs`'s `deliver_pending_signal`), not from here. Deliberately *not* the
            // stronger immediate-termination path `do_kill`'s cross-process branch uses for a
            // no-handler target: doing that here would mean re-locking `process::table()` (or
            // calling `terminate_process`, which does its own locking) while this exact lock is
            // still held for the surrounding scan -- a real deadlock against `spin::Mutex`'s
            // non-reentrant guarantee. Sufficient for this kernel's actual use case (`ping`'s own
            // real usage pattern: a tight loop of individually non-blocking `recvfrom` calls, each
            // its own syscall) -- a process genuinely blocked elsewhere (`BlockReason::Sleeping`/
            // `WaitingForPipeData`/...) won't see this promptly, the same documented, accepted gap
            // `do_kill`'s own doc comment already calls out for a handler-installed cross-process
            // signal.
            if let Some(deadline) = proc.real_timer_deadline
                && now >= deadline
            {
                proc.pending_signals |= 1 << (crate::process::SIGALRM - 1);
                proc.real_timer_deadline = if proc.real_timer_interval_ticks > 0 {
                    Some(now + proc.real_timer_interval_ticks)
                } else {
                    None
                };
                // A process genuinely `Blocked` (`pause`/`nanosleep`/`sigwait`/a plain `mq_receive`)
                // waiting specifically on this signal must be woken here, or it hangs forever --
                // this expiry only sets the pending bit, unlike `do_kill`'s own `Action::SetPending`
                // arm, whose callers already wire these same four hooks in. Safe to call
                // unconditionally: each hook only fires if `proc`'s own state actually matches its
                // one relevant `BlockReason`, a no-op otherwise. Found live via
                // `clock_settime/4-1.c` (a real `alarm()`-shaped `SIGALRM` expiry while the target
                // sits in `sigwait()`) permanently hanging the POSIX conformance pilot.
                crate::process::signals::wake_if_paused(pid, proc, crate::process::SIGALRM);
                crate::process::signals::wake_if_sigwaiting(pid, proc, crate::process::SIGALRM);
                crate::process::signals::wake_if_sleeping(pid, proc, crate::process::SIGALRM);
                crate::process::signals::wake_if_mq_waiting(pid, proc, crate::process::SIGALRM);
                crate::process::signals::wake_if_futex_waiting(pid, proc, crate::process::SIGALRM);
            }

            // `SYS_TIMER_CREATE`'s own per-timer expiry (`Process::posix_timers`, batch items
            // 6-10 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`) -- same simple pending-bit-only delivery
            // as `real_timer_deadline` just above (no forced cross-process wake here either, same
            // reasoning), plus a real `timer_getoverrun` count: an expiry whose signal is *still*
            // pending from a previous, undelivered expiry increments `overrun` instead of getting
            // lost silently.
            for i in 0..proc.posix_timers.len() {
                // `newly_signaled` carries a just-set signal number past the end of `slot`'s own
                // borrow (of `proc.posix_timers[i]`, not all of `proc`) -- calling the wake hooks
                // below needs `&mut Process` (the whole struct), which can't coexist with a live
                // sub-borrow from array indexing, even though the two touch disjoint fields.
                let mut newly_signaled = None;
                let Some(slot) = proc.posix_timers[i].as_mut() else {
                    continue;
                };
                // A live wall-clock comparison, not the (possibly stale) tick-domain `deadline`,
                // for a timer armed via `TIMER_ABSTIME` against `CLOCK_REALTIME` -- see
                // `PosixTimer::realtime_target`'s own doc comment for why this is what lets a
                // later `clock_settime(CLOCK_REALTIME, ...)` correctly retarget an already-armed
                // timer with zero extra bookkeeping on the `clock_settime` side.
                // `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID` timers compare against
                // `proc.cpu_ticks` (real per-process CPU time), not wall-clock `now` -- a direct
                // field read, not a call to `timers::timer_now(proc, ...)`, since that takes
                // `&Process` and can't coexist with `slot`'s own live sub-borrow of
                // `proc.posix_timers` (same disjoint-field-access pattern this loop's own
                // `proc.pending_signals` accesses below already rely on).
                let timer_now = if crate::process::timers::is_cputime_clock(slot.clockid) {
                    proc.cpu_ticks
                } else {
                    now
                };
                // Real, non-tick-quantized expiry+overrun path -- see `PosixTimer::deadline_ns`'s
                // own doc comment for exactly when `do_timer_settime` populates this (a relative-
                // mode `CLOCK_REALTIME`/`CLOCK_MONOTONIC` timer, real HPET present). Checked
                // first: mutually exclusive with `realtime_target`/tick `deadline` below by
                // construction (`deadline_ns` is only ever `Some` when both of those are meant to
                // be ignored). `elapsed`/`ns_overrun_extra` fold in however many whole intervals
                // have really elapsed since `deadline_ns` in one shot -- real, exact
                // `elapsed_ns / interval_ns` arithmetic, the same "catch-up" technique real
                // Linux's own `hrtimer_forward()` uses, since this kernel checks at the existing
                // 100Hz tick cadence rather than firing one real interrupt per interval (`cpu::
                // hpet`'s own module doc comment has the full story on why that's deliberate).
                let mut ns_overrun_extra: u32 = 0;
                let fired = if let Some(deadline_ns) = slot.deadline_ns {
                    match crate::cpu::hpet::now_ns() {
                        Some(now_ns) if now_ns >= deadline_ns => {
                            if let Some(periods) =
                                (now_ns - deadline_ns).checked_div(slot.interval_ns)
                            {
                                let elapsed = periods + 1;
                                slot.deadline_ns = Some(deadline_ns + elapsed * slot.interval_ns);
                                ns_overrun_extra = (elapsed - 1) as u32;
                            } else {
                                slot.deadline_ns = None;
                            }
                            true
                        }
                        _ => false,
                    }
                } else if let Some(target) = slot.realtime_target {
                    crate::cpu::rtc::unix_epoch_now_precise() >= target
                } else if let Some(deadline) = slot.deadline {
                    timer_now >= deadline
                } else {
                    false
                };
                if fired {
                    if slot.signo != 0 {
                        let sig = slot.signo;
                        // A real-time signal's "already pending" state is its own `rt_queue`
                        // entry, not the flat `pending_signals` bit -- `take_deliverable_signal`
                        // unconditionally pops from `rt_queue` for any `sig >= SIGRTMIN` found
                        // set in `pending_signals`, so setting the bit here without also pushing
                        // a real queue entry would panic the kernel on an empty-Vec pop the next
                        // time this signal is delivered (found via audit, not live -- currently
                        // unreachable only because `do_timer_create` rejects RT `sigev_signo`;
                        // this fix removes that dependency so either side can change safely).
                        let already_pending = if sig >= crate::process::SIGRTMIN {
                            !proc.rt_queue[(sig - crate::process::SIGRTMIN) as usize].is_empty()
                        } else {
                            proc.pending_signals & (1 << (sig - 1)) != 0
                        };
                        if already_pending {
                            slot.overrun = slot.overrun.saturating_add(1 + ns_overrun_extra);
                        } else {
                            slot.overrun = ns_overrun_extra;
                            let info = crate::process::QueuedSigInfo {
                                code: crate::process::SI_TIMER,
                                pid: 0,
                                uid: 0,
                                value: 0,
                            };
                            if sig >= crate::process::SIGRTMIN {
                                proc.rt_queue[(sig - crate::process::SIGRTMIN) as usize].push(info);
                            } else {
                                proc.pending_siginfo[sig as usize] = info;
                            }
                            proc.pending_signals |= 1 << (sig - 1);
                            newly_signaled = Some(sig);
                        }
                    }
                    // Only the *first* expiry of an abstime-armed `CLOCK_REALTIME` timer needs
                    // real wall-clock precision -- a periodic reload falls back to plain
                    // tick-domain `interval_ticks`, same simplification `PosixTimer::
                    // realtime_target`'s own doc comment already flags.
                    slot.realtime_target = None;
                    slot.deadline = if slot.interval_ticks > 0 {
                        Some(timer_now + slot.interval_ticks)
                    } else {
                        None
                    };
                }
                // `slot`'s own borrow of `proc.posix_timers[i]` ends here -- only now can `proc`
                // be reborrowed whole for the wake hooks below. Same hang this section's own
                // `real_timer_deadline` sibling above just got fixed for, via a real POSIX timer
                // instead of `alarm()`/`setitimer()` -- a process sitting in `pause`/`nanosleep`/
                // `sigwait`/a plain `mq_receive` waiting on a `timer_create`-armed signal (e.g.
                // `clock_settime/4-1.c`'s own `sigwait()` for a `TIMER_ABSTIME` timer) would
                // otherwise never wake once this loop merely set the pending bit.
                if let Some(signo) = newly_signaled {
                    crate::process::signals::wake_if_paused(pid, proc, signo);
                    crate::process::signals::wake_if_sigwaiting(pid, proc, signo);
                    crate::process::signals::wake_if_sleeping(pid, proc, signo);
                    crate::process::signals::wake_if_mq_waiting(pid, proc, signo);
                    crate::process::signals::wake_if_futex_waiting(pid, proc, signo);
                }
            }
        }
    }

    // Must happen before the preemption check below can call scheduler::schedule() -- see this
    // function's own doc comment.
    unsafe {
        pic::notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }

    // Polled, not IRQ-driven -- see `drivers::usb`'s own module doc comment for why. Once per
    // tick (100 Hz) is plenty for human typing speed; cost when no USB keyboard was ever found is
    // a single relaxed atomic load. A no-op until `drivers::usb::init` has actually found and
    // brought up a controller + HID boot-keyboard device.
    crate::drivers::usb::poll();

    // Ring check via the CPU's own saved CS RPL bits (`& 0x3`), not e.g. `scheduler::current_pid()`
    // state -- see this function's own doc comment for why ring-3-only is the deliberate scope.
    let interrupted_ring3 = stack_frame.code_segment.0 & 0x3 == 3;
    // A thread caught mid-`fault_trampoline` (its own store into the *shared-per-address-space*
    // `RAX_SCRATCH_OFFSET` cell, immediately followed by the `syscall` that reads it back) must
    // never be preempted -- doing so lets a sibling `CLONE_THREAD` thread interleave its own pass
    // through the same physical page before this one resumes, clobbering the stashed `rax` with
    // the sibling's own value. See `fault_trampoline::RAX_SCRATCH_OFFSET`'s own doc comment for the
    // real bug this closes (`pthread_mutex_trylock/4-3.c`, a genuine `CRASH(139)` this caused).
    // Deferring for one tick is enough: by the next tick the thread has long since finished this
    // few-cycle sequence and is safe to preempt/redirect normally again. Also covers the restore
    // stub at `STUB_OFFSET` -- it reads/consumes the same shared scratch cells (now also
    // `RCX_SCRATCH_OFFSET`/`R11_SCRATCH_OFFSET`/`TRUE_RFLAGS_OFFSET`/`TRUE_RESUME_RIP_OFFSET`, not
    // just `RAX_SCRATCH_OFFSET`) and is exposed to the identical interleaving risk.
    let ip = stack_frame.instruction_pointer.as_u64();
    let mid_fault_trampoline = interrupted_ring3
        && ((crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
            ..crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
                + crate::process::fault_trampoline::CODE_LEN)
            .contains(&ip)
            || (crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
                + crate::process::fault_trampoline::STUB_OFFSET
                ..crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
                    + crate::process::fault_trampoline::STUB_OFFSET
                    + crate::process::fault_trampoline::STUB_LEN)
                .contains(&ip));
    if interrupted_ring3 && !mid_fault_trampoline {
        // Real `SCHED_FIFO`/`SCHED_RR` priority preemption: checked on *every* tick, not gated on
        // the quantum below -- a higher-`sched_priority` process becoming Ready must preempt within
        // about one tick, not wait up to a full `PREEMPT_QUANTUM_TICKS` quantum. Every `SCHED_OTHER`
        // process (this kernel's spawn-time default, see `Process::sched_policy`'s own doc comment)
        // shares the one priority valid for that policy (`0`), so `higher_priority_ready` is always
        // `false` for the pre-existing plain-round-robin case -- this whole branch is inert unless
        // something has actually called `sched_setscheduler`/`sched_setparam` into a real-time
        // policy. See `scheduler::ready_queue_has_higher_priority_than`'s own doc comment for why a
        // process-table lookup here is safe (no lock this handler already holds could conflict).
        //
        // Real per-process quantum (`Process::quantum_ticks_left`'s own doc comment) replacing a
        // purely global-clock-phase check -- decremented here, once per tick this exact process is
        // found actually running, rather than checking whether the *global* tick counter's phase
        // happens to line up. One combined table lookup for both this and the priority check above.
        let (current_priority, quantum_expired) = {
            let mut table = crate::process::table().lock();
            match table.get_mut(&crate::process::scheduler::current_pid()) {
                Some(p) => {
                    let priority = p.sched_priority;
                    p.quantum_ticks_left = p.quantum_ticks_left.saturating_sub(1);
                    (priority, p.quantum_ticks_left == 0)
                }
                None => (0, false),
            }
        };
        let higher_priority_ready =
            crate::process::scheduler::ready_queue_has_higher_priority_than(current_priority);
        if higher_priority_ready || quantum_expired {
            crate::process::scheduler::schedule();
        }

        // Real signal delivery for a ring-3 process making no syscalls of its own -- a tight,
        // purely userspace-computational loop (e.g. `pthread_atfork/3-3.c`'s own worker thread,
        // whose `while(do_it) pthread_atfork(...)` loop never traps into the kernel at all).
        // `syscall::deliver_pending_signal` only ever runs from a real syscall's own dispatch tail
        // or `sigreturn` -- a signal set pending via `do_kill`/an itimer/POSIX-timer expiry on a
        // process that never makes another syscall would otherwise sit pending forever, hanging
        // any caller (or `sigwait`-ing sibling thread) that depends on it. Checked on every tick,
        // independent of the preemption decision above (real signal delivery isn't gated by
        // scheduling quantum) -- by the time execution reaches here, whether or not `schedule()`
        // was just called, `current_pid()` always names the exact process `stack_frame` belongs to
        // (a preempted process's own call into `schedule()` above only "returns" once *that same*
        // process is re-selected -- see `scheduler.rs`'s own module doc comment).
        //
        // `pending & !blocked != 0` is a safe, sufficient proxy for "something is really
        // deliverable": `record_pending`/`do_kill`'s own `Action::Discard` arm never sets the
        // pending bit at all for a `SIG_IGN` disposition, so a set-and-unblocked bit here always
        // means a real handler invocation or a real default-disposition resolution (including
        // `Terminate`) is waiting. Reuses the exact same real, kernel-authored trampoline page
        // `page_fault_handler`'s own fault-to-signal redirect already established (see
        // `fault_trampoline`'s own module doc comment for why a raw `extern "x86-interrupt" fn`
        // can't build a real handler-invocation frame itself) -- but stashes the real, true
        // interrupted `(rip, rsp, rflags)` first (`Process::preempted_resume`), unlike the
        // page-fault case: a page fault's own "resume" point is the faulting instruction itself
        // (real POSIX doesn't define resuming past an unhandled fault as portable anyway), but
        // this is *ordinary*, otherwise-uninterrupted ring-3 code -- resuming it after a handler
        // returns (or immediately, if no handler fires) must land back on the real original
        // instruction, not the trampoline's own internal `syscall`.
        let pid = crate::process::scheduler::current_pid();
        // Only redirect `instruction_pointer` the *first* tick a deliverable signal is found --
        // NOT unconditionally on every tick this remains true. Found live, the hard way: an
        // unconditional per-tick redirect actively prevents forward progress rather than being
        // the harmless idempotent no-op it looks like -- once redirected, the process needs a few
        // real cycles to run the trampoline's own `mov`+`syscall` and reach `syscall_dispatch`
        // (which is what actually clears the pending bit); slamming `instruction_pointer` back to
        // the trampoline's *start* on every subsequent tick, before that ever completes, resets
        // that progress every ~10ms forever -- a real, self-inflicted livelock, not a race. Once
        // `preempted_resume` is `Some`, the process is trusted to already be correctly on its way
        // through the trampoline on its own; this only fires again for a *genuinely new* signal
        // becoming deliverable after the previous one was actually consumed (`preempted_resume`
        // cleared by `syscall_dispatch`'s own `SYS_FAULT_PUMP` handling).
        // Real, live-found correctness gap: skip entirely while a signal handler is already
        // running (`!signal_stack.is_empty()`) -- this kernel's own `deliver_pending_signal`
        // chaining (`do_sigreturn` re-checking for a further deliverable signal, see that
        // function's own doc comment) already guarantees strict lowest-signal-number-first
        // delivery order across a chain of several deliverable signals, entirely via real
        // syscalls (the handler's own eventual `sigreturn`) -- no timer help is ever needed
        // there, and a currently-running handler is *always* going to make that real syscall
        // shortly (when it returns through its restorer), so this mechanism's own reason for
        // existing (a thread making *no* syscalls of its own at all) doesn't apply mid-handler.
        // Found live: a real RT-signal ordering regression (`rt_signal_syscall_smoke`'s own part
        // 3, `sigqueue/7-1.c`'s scenario) -- a timer tick landing at the *exact* instant a lower-
        // numbered signal's handler was about to execute its first instruction (a real, valid,
        // narrow window: `mask_to_add` only blocks the signal *being delivered*, not siblings)
        // found the higher-numbered sibling already pending+unblocked too and redirected *that*
        // one in first, delivering strictly out of the kernel's own documented order -- a real
        // regression this mechanism must never cause, since the ordinary chaining path already
        // had this covered without it.
        let should_redirect = {
            let mut table = crate::process::table().lock();
            table.get_mut(&pid).is_some_and(|p| {
                let deliverable =
                    p.pending_signals & !p.blocked_signals != 0 && p.signal_stack.is_empty();
                if deliverable && p.preempted_resume.is_none() {
                    p.preempted_resume = Some((
                        stack_frame.instruction_pointer.as_u64(),
                        stack_frame.stack_pointer.as_u64(),
                        stack_frame.cpu_flags.bits(),
                    ));
                    true
                } else {
                    false
                }
            })
        };
        if should_redirect {
            // SAFETY: only the resume RIP is changed -- redirecting straight into a real,
            // kernel-mapped, user-executable trampoline page. RSP/RFLAGS/the segment selectors are
            // left exactly as they were; this process has exactly one ring-3 code/data selector
            // pair, already correct. Same technique `page_fault_handler` already uses.
            unsafe {
                stack_frame.as_mut().update(|f| {
                    f.instruction_pointer =
                        VirtAddr::new(crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA);
                });
            }
        }
    }
}

/// Runs one already-decoded key through the same echo/Ctrl+C/Ctrl+Z/`push_byte` handling
/// `keyboard_interrupt_handler` always has -- factored out so `drivers::usb::hid_keyboard`'s
/// synthetic PS/2-shaped byte feed (see `feed_synthetic_scancode` below) gets identical shift-
/// state, caps-lock, signal-interception, and echo behavior for free, with zero duplicated logic.
/// A USB keyboard only ever has to produce Scan Code Set 1 bytes; everything past decode is
/// shared. Deliberately never touches the PIC -- `keyboard_interrupt_handler` (the only caller
/// actually inside a real hardware IRQ) sends its own EOI unconditionally after calling this,
/// whether or not this returns early.
///
/// **Return value, found live via a real crash**: `true` means the process this interrupt
/// actually landed on (`scheduler::current_pid()`) is no longer `Running` -- the caller must call
/// `scheduler::schedule()` itself, right after its own EOI, exactly like `timer_interrupt_handler`
/// already does for ring-3 preemption (same "EOI before schedule()" ordering — see that function's
/// own doc comment). Without this, a Ctrl+C/Ctrl+Z that terminates or stops the *currently
/// running* process only updates its `Process` table entry (`Zombie`/`Stopped`) -- nothing stops
/// the plain `iretq` this interrupt would otherwise take back into that exact process's own,
/// still-live ring-3 instruction stream. That "zombie/stopped but still actually executing" window
/// (up to a full preemption quantum) is real, not theoretical: found live running the fbdoom port
/// (a real, tight, never-blocking `for(;;) doomgeneric_Tick();` loop, so extremely likely to make
/// another syscall inside that exact window) -- `Ctrl+C` mid-game reliably panicked the whole
/// kernel (`activate_and_prepare: picked a process with no address space`). Root cause: the
/// process's very next `usleep()` (`process::timers::do_nanosleep`) unconditionally overwrote its
/// already-`Zombie` state with `Blocked(Sleeping(deadline))` and blocked normally -- once that
/// deadline passed, `timer_interrupt_handler`'s own sleeper-wake loop dutifully re-`Ready`'d and
/// re-enqueued what was, by every real invariant this codebase depends on, supposed to be a dead
/// process -- and by the time the scheduler actually popped it, its address space had already been
/// torn down by the deferred zombie-reap path that assumed nothing could ever touch that entry
/// again. Every other blocking primitive in this codebase (`pause`, pipe/mqueue/futex waits, ...)
/// has the identical latent hazard for the same reason; forcing an immediate, synchronous
/// reschedule here closes all of them at the actual source, rather than auditing every blocking
/// syscall to check `state == Zombie`/`Stopped` before overwriting it.
/// Normalizes `pc-keyboard`'s own `Return`/`NumpadEnter` decode (`DecodedKey::Unicode('\n')`, LF)
/// to the real terminal convention for the Enter key (`\r`, CR, `0x0D`) -- a real, genuine bug
/// found live via nano's own save dialog silently never confirming (see CLAUDE.md's
/// ncurses/nano/nvi section for the full writeup). Every real terminal and every curses/readline
/// program's own shortcut table (nano's own `^M`/`\r` -> `do_enter` binding, `usr.bin/nano/src/
/// global.c`) is built around a physical Enter key sending CR raw -- ICRNL-style translation to
/// LF is a later, optional *tty-driver* step (real canonical mode only), never what the key
/// itself produces. `pc-keyboard`'s own `Us104Key` layout collapses `Return` straight to Unicode
/// LF instead, which broke exactly the code paths relying on the real `\r` convention (nano's own
/// prompt-confirmation logic, `acquire_an_answer` in `usr.bin/nano/src/prompt.c`, checks only the
/// shortcut table) -- masked in the main editor by its own separate, more permissive fallback
/// (`nano.c`'s own `input == '\r' || input == '\n'` check for newline insertion specifically).
///
/// **Deliberately scoped to the `Return`/`NumpadEnter` key itself, not a blanket `\n` -> `\r`
/// rewrite**: Ctrl+J legitimately decodes to the same Unicode LF via `pc-keyboard`'s own
/// `HandleControl` mapping, and is a real, distinct keystroke (nano's own `^J` -> `do_justify`
/// binding) that must stay LF -- a blanket rewrite would make the two indistinguishable.
fn normalize_enter_key(code: KeyCode, key: DecodedKey) -> DecodedKey {
    if matches!(code, KeyCode::Return | KeyCode::NumpadEnter)
        && let DecodedKey::Unicode('\n') = key
    {
        DecodedKey::Unicode('\r')
    } else {
        key
    }
}

/// One decoded key, from either keyboard path: a navigation/editing key becomes the escape
/// sequence a Linux console sends (what `TERM=linux`'s terminfo, which pid 1 advertises, tells
/// programs to expect), everything else goes through `handle_decoded_key`.
fn dispatch_key(code: KeyCode, key: DecodedKey) -> bool {
    if let Some(seq) = console_key_sequence(code, &key) {
        if !crate::console::stdin::raw_keyboard_owned() {
            for &b in seq {
                crate::console::stdin::push_byte(b);
            }
        }
        return false;
    }
    handle_decoded_key(normalize_enter_key(code, key))
}

/// Linux console key sequences (`kcuu1`/`khome`/`kdch1`/... in the `linux` terminfo entry).
/// pc-keyboard reports these keys as `RawKey` -- they used to be dropped entirely, so no program
/// ever saw an arrow key -- except Delete, which it decodes as DEL (0x7f), and Backspace, as BS
/// (0x08). A Linux console sends DEL for Backspace (matching `VERASE`, see
/// `console::stdin::DEFAULT_TERMIOS`) and `ESC [ 3 ~` for Delete, so both are rewritten too.
/// Ctrl+H still produces BS: only the Backspace key itself is matched.
fn console_key_sequence(code: KeyCode, key: &DecodedKey) -> Option<&'static [u8]> {
    let seq: &'static [u8] = match (code, key) {
        (KeyCode::ArrowUp | KeyCode::Numpad8, DecodedKey::RawKey(_)) => b"\x1b[A",
        (KeyCode::ArrowDown | KeyCode::Numpad2, DecodedKey::RawKey(_)) => b"\x1b[B",
        (KeyCode::ArrowRight | KeyCode::Numpad6, DecodedKey::RawKey(_)) => b"\x1b[C",
        (KeyCode::ArrowLeft | KeyCode::Numpad4, DecodedKey::RawKey(_)) => b"\x1b[D",
        (KeyCode::Home | KeyCode::Numpad7, DecodedKey::RawKey(_)) => b"\x1b[1~",
        (KeyCode::Insert | KeyCode::Numpad0, DecodedKey::RawKey(_)) => b"\x1b[2~",
        (KeyCode::End | KeyCode::Numpad1, DecodedKey::RawKey(_)) => b"\x1b[4~",
        (KeyCode::PageUp | KeyCode::Numpad9, DecodedKey::RawKey(_)) => b"\x1b[5~",
        (KeyCode::PageDown | KeyCode::Numpad3, DecodedKey::RawKey(_)) => b"\x1b[6~",
        (KeyCode::Delete | KeyCode::NumpadPeriod, DecodedKey::Unicode('\u{7f}')) => b"\x1b[3~",
        (KeyCode::Backspace, DecodedKey::Unicode('\u{8}')) => b"\x7f",
        _ => return None,
    };
    Some(seq)
}

fn handle_decoded_key(key: DecodedKey) -> bool {
    match key {
        DecodedKey::Unicode(character) => {
            // Non-ASCII is silently dropped here -- a US keyboard layout won't produce it,
            // and it keeps sys_read's contract (raw bytes, not full UTF-8) simple.
            if character.is_ascii() {
                let byte = character as u8;
                // Only echo printable characters and newline directly here. Control bytes
                // (backspace, delete, Ctrl+C, Ctrl+D, ...) are still pushed to stdin below,
                // but *how* they should look on screen (erasing a character, printing "^C",
                // etc.) is a userland concern -- see `regress/stsh/`'s `read_line` -- and
                // echoing them raw here just produces VGA's placeholder glyph for anything
                // outside 0x20..=0x7e, which isn't useful for any of them.
                //
                // Gated on the console's own current termios ECHO bit (see `src/stdin.rs`) --
                // a program that's switched to raw mode with ECHO cleared (e.g. a real
                // line-editing shell) does its own echoing; echoing here on top of that would
                // double every keystroke. Defaults to on, matching this kernel's original,
                // always-echo behavior before real termios existed.
                // Real tty-driver INTR behavior: once a real session has actually claimed the
                // controlling terminal and set a foreground process group (`TIOCSCTTY`/
                // `TIOCSPGRP` -- see CLAUDE.md's session/controlling-tty notes), Ctrl+C (ASCII
                // ETX, `0x03`) is intercepted here and turned into a real `SIGINT` delivered to
                // that whole group, exactly like a real terminal driver consuming INTR before
                // it ever reaches a reading process's buffer -- it is deliberately *not* also
                // pushed to stdin in this case. Gated on the console's own `ISIG` bit (real
                // convention: a program that's cleared it, same as `ECHO` above, wants raw
                // bytes instead, e.g. a line editor that means to handle Ctrl+C itself). Until
                // some session actually does this (the common case today -- nothing calls
                // `setsid`/`TIOCSCTTY` yet outside `sulogin`/`getty`), `foreground_pgid()` stays
                // `None` and this falls through to the original behavior below: the raw byte is
                // pushed to stdin and a userland reader (`stsh`'s own `read_line`, BusyBox
                // `hush`'s line editor) handles it itself, unchanged from before this existed.
                if byte == 0x03
                    && crate::console::stdin::get_termios().c_lflag & crate::console::stdin::ISIG
                        != 0
                    && let Some(pgid) = crate::console::stdin::foreground_pgid()
                {
                    serial_print!("^C\n");
                    let cur = crate::process::scheduler::current_pid();
                    crate::process::signal_foreground_group(pgid, crate::process::SIGINT);
                    return !matches!(
                        crate::process::table().lock().get(&cur).map(|p| p.state),
                        Some(crate::process::ProcState::Running)
                    );
                }
                // Real tty-driver SUSP behavior, same shape as the Ctrl+C/SIGINT interception
                // directly above (ASCII SUB, `0x1a`, is Ctrl+Z's real terminal-driver INTR-
                // family byte) -- delivers a real SIGTSTP to the foreground group instead of
                // SIGINT (see `ProcState::Stopped`/`process::signals`'s `Action::Stop` for what
                // happens next: the target genuinely stops, observable via `wait4(WUNTRACED)`,
                // resumable via a later `SIGCONT` -- `hush`'s own `fg`/`bg`/`jobs` builtins
                // already send/observe that real machinery unmodified). Same `ISIG`/
                // `foreground_pgid()` gating and not-also-pushed-to-stdin behavior.
                if byte == 0x1a
                    && crate::console::stdin::get_termios().c_lflag & crate::console::stdin::ISIG
                        != 0
                    && let Some(pgid) = crate::console::stdin::foreground_pgid()
                {
                    serial_print!("^Z\n");
                    let cur = crate::process::scheduler::current_pid();
                    crate::process::signal_foreground_group(pgid, crate::process::SIGTSTP);
                    return !matches!(
                        crate::process::table().lock().get(&cur).map(|p| p.state),
                        Some(crate::process::ProcState::Running)
                    );
                }
                // Suppressed while a process owns real raw keyboard input (`SYS_GET_KEYEVENT`,
                // e.g. the fbdoom/doomgeneric port) -- see `console::stdin::RAW_KEYBOARD_OWNED`'s
                // own doc comment for the real bug this closes (every ASCII-producing keystroke
                // visibly "leaking" into the console while a program reads it correctly through
                // the raw keyevent path instead).
                if !crate::console::stdin::raw_keyboard_owned() {
                    if crate::console::stdin::echo_enabled()
                        && (byte == b'\n' || byte == b'\r' || (0x20..=0x7e).contains(&byte))
                    {
                        serial_print!("{character}");
                    }
                    crate::console::stdin::push_byte(byte);
                }
            }
        }
        // Modifier/lock keys (Shift, Ctrl, CapsLock, ...) and any other non-Unicode key --
        // nothing to echo or push to stdin. These used to be logged via `{key:?}` for
        // debugging during early keyboard-decode bring-up, but that printed raw debug names
        // like "LControl" inline with real typed text (e.g. right before a Ctrl+C's "^C"),
        // which is exactly the kind of noise a real shell shouldn't produce.
        DecodedKey::RawKey(_) => {}
    }
    false
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    let mut port: Port<u8> = Port::new(0x60);
    // SAFETY: 0x60 is the PS/2 controller's data port; reading it is how a keyboard IRQ is
    // acknowledged at the hardware level, and it's only ever read here.
    let scancode: u8 = unsafe { port.read() };

    // Real, externally-triggered timing jitter (a human keystroke, at whatever exact cycle count
    // it happened to land) -- feeds `sys/random.rs`'s persistent entropy pool. Unconditional, not
    // gated on how the scancode later decodes, so every keyboard IRQ contributes.
    crate::random::mix_entropy(scancode as u64);

    // Scoped so KEYBOARD's own lock is dropped before the possible `schedule()` call below --
    // holding it across a real context switch (which can run arbitrary other code, including a
    // *different* keyboard IRQ once this one's own EOI has gone out) would deadlock this
    // single-locked-at-all resource against itself.
    let must_reschedule = {
        let mut keyboard = KEYBOARD.lock();
        if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
            // Captured here, before `process_keyevent` below discards release information for
            // nearly every key -- see `console::keyevents`'s own doc comment.
            crate::console::keyevents::record_raw_key_event(&key_event);
            let code = key_event.code;
            match keyboard.process_keyevent(key_event) {
                Some(key) => dispatch_key(code, key),
                None => false,
            }
        } else {
            false
        }
    };

    unsafe {
        pic::notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }

    // See `handle_decoded_key`'s own doc comment for why this can't just be an ordinary `iretq`
    // back into a process a Ctrl+C/Ctrl+Z just terminated/stopped. Same "EOI before schedule()"
    // ordering `timer_interrupt_handler`'s own ring-3 preemption already establishes.
    if must_reschedule {
        crate::process::scheduler::schedule();
    }
}

/// Feeds one synthesized PS/2 Scan Code Set 1 byte through the exact same decode pipeline a real
/// PS/2 IRQ uses (`KEYBOARD`'s `add_byte`/`process_keyevent`, then `handle_decoded_key`) -- the
/// integration point `drivers::usb::hid_keyboard` calls once per synthesized make/break byte
/// after diffing a HID boot-keyboard report against its previous one. Not itself inside a real
/// hardware IRQ (called from `drivers::usb::poll()`, in turn called once per timer tick), so
/// unlike `keyboard_interrupt_handler` it never touches the PIC.
pub(crate) fn feed_synthetic_scancode(byte: u8) {
    // Scoped so KEYBOARD's own lock is dropped before the possible `schedule()` call below -- see
    // `keyboard_interrupt_handler`'s own identical comment.
    let must_reschedule = {
        let mut keyboard = KEYBOARD.lock();
        if let Ok(Some(key_event)) = keyboard.add_byte(byte) {
            crate::console::keyevents::record_raw_key_event(&key_event);
            let code = key_event.code;
            match keyboard.process_keyevent(key_event) {
                Some(key) => dispatch_key(code, key),
                None => false,
            }
        } else {
            false
        }
    };
    // Safe here too: called from `drivers::usb::poll()`, itself called from
    // `timer_interrupt_handler` *after* that handler's own EOI (see this function's own doc
    // comment) -- same "EOI before schedule()" ordering as `keyboard_interrupt_handler`. See
    // `handle_decoded_key`'s own doc comment for why this can't just fall through to a plain
    // return.
    if must_reschedule {
        crate::process::scheduler::schedule();
    }
}
