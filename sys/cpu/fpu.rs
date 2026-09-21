//! Enables SSE for the whole system: `CR0`/`CR4` bits that were never touched before this, since
//! nothing needed them.
//!
//! Discovered as a real, previously-latent gap while bringing up `musl-smoke` (see `CLAUDE.md`'s
//! musl section) — this kernel's own build target (`x86_64-oxidebsd.json`) disables SSE/MMX in
//! its own codegen (`disable-redzone: true`, `+soft-float`), and every userland crate written
//! *for* that target (`ring3-smoke`, `stsh`, `fork-exec-smoke`) inherits the same restriction, so
//! none of them ever emit an SSE instruction. A real musl static binary, built with an ordinary
//! host `gcc` targeting plain x86_64 (SSE2 baseline, per the standard ABI), is the first userland
//! binary this kernel has ever run that isn't built against `x86_64-oxidebsd.json` — and it
//! `#UD`'d on its very first `pxor` (inside musl's own stdio buffer init). Per the SDM: executing
//! an SSE instruction while `CR4.OSFXSR` is clear raises `#UD`, not a more suggestive fault — this
//! kernel never sets that bit (or `CR0.EM`/`CR0.MP`) anywhere, so it was purely accidental that
//! nothing surfaced this until now.
//!
//! Deliberately not "lazy" FPU state switching (`CR0.TS` + `#NM`-triggered save/restore, the
//! classic optimization real kernels use to skip saving FPU/SSE state for threads that never touch
//! it) — every context switch unconditionally `fxsave`/`fxrstor`s (see `save`/`restore` below),
//! simpler and correct regardless of which processes actually touch SSE.
//!
//! **This used to be a real, flagged gap**: `context_switch::switch_context` only ever saved/
//! restored `RSP` + System V's callee-saved GPRs, never `XMM`/`x87` state, which was fine only as
//! long as at most one process was ever actually *using* SSE at a time without yielding
//! mid-computation — true under the old cooperative-only scheduler (a process only ever gave up
//! the CPU at a real function-call boundary, where the SysV ABI already forces the compiler to
//! spill any XMM state it cares about to its own stack before the call/syscall — nothing needed
//! saving on the kernel side). **Real preemption breaks that assumption**: the timer IRQ can now
//! interrupt a process at literally any instruction, including mid-computation with live XMM
//! register content the compiler never spilled (no call boundary to require it). Fixed by adding
//! `Process::fpu_state` (`scheduler::schedule`/`start` `fxsave` the outgoing process and `fxrstor`
//! the incoming one on every switch, not just preemptive ones — simpler to make it unconditional
//! than to special-case cooperative vs. preemptive switches).
pub fn init() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

    // SAFETY: clearing EMULATE_COPROCESSOR and setting MONITOR_COPROCESSOR/OSFXSR/
    // OSXMMEXCPT_ENABLE is exactly the documented "enable SSE" sequence (see the OSDev wiki's SSE
    // page, or the SDM's discussion of CR0.EM/CR4.OSFXSR) -- safe unconditionally this early in
    // boot, before anything (kernel or user) has executed an SSE instruction that could be
    // affected by the transition.
    unsafe {
        Cr0::write((Cr0::read() & !Cr0Flags::EMULATE_COPROCESSOR) | Cr0Flags::MONITOR_COPROCESSOR);
        Cr4::write(Cr4::read() | Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
    }
    capture_clean_state();
}

/// A 512-byte `FXSAVE`/`FXRSTOR` state area. `#[repr(align(16))]` is load-bearing, not cosmetic —
/// both instructions `#GP` on a misaligned memory operand, and this type is embedded directly in
/// `Process` (itself heap-allocated via `Box`), so the alignment has to be real, not assumed.
#[repr(align(16))]
#[derive(Clone, Copy)]
pub struct FxSaveArea(pub [u8; 512]);

/// A real CPU-reset FPU/SSE state, captured once here (via a genuine `fninit` + `fxsave`, not a
/// hand-guessed all-zero buffer — an all-zero image isn't actually a legal reset state, the x87
/// control word and `MXCSR` both have real nonzero hardware defaults) and copied into every freshly
/// spawned/forked process's own `Process::fpu_state` as its starting point. `static mut`, not
/// `static`, for the same reason as `gdt.rs`'s `CURRENT_RSP0`: written here through ordinary Rust
/// code (visible to the optimizer) but read only via `clean_state()`, called from a different
/// module (`process::lifecycle`) — distinct enough from this write site that a defensive
/// `static mut` is worth it.
///
/// Safe to derive by actually executing `fninit` (which clobbers the *real* hardware FPU state)
/// at this specific point in boot, and would remain safe even if called again later: kernel code
/// itself never emits an SSE/x87 instruction on this soft-float target (see `x86_64-oxidebsd.json`
/// in CLAUDE.md's target-spec section), so there is no live "kernel-side" FPU state this could ever
/// stomp on — only a real process's state matters, and that's saved/restored per-switch by
/// `save`/`restore` below, never left implicitly resident in the hardware registers across a call
/// into kernel code.
static mut CLEAN_FPU_STATE: FxSaveArea = FxSaveArea([0; 512]);

fn capture_clean_state() {
    let mut area = FxSaveArea([0; 512]);
    // SAFETY: fninit takes no operands; fxsave writes exactly size_of::<FxSaveArea>() bytes to a
    // pointer that's 16-byte aligned (guaranteed by FxSaveArea's own repr(align(16))) and valid for
    // that whole write (a live local on this function's own stack).
    unsafe {
        core::arch::asm!("fninit");
        core::arch::asm!("fxsave [{0}]", in(reg) &raw mut area.0 as *mut u8, options(nostack));
        CLEAN_FPU_STATE = area;
    }
}

/// A copy of the real CPU-reset FPU/SSE state — what a freshly spawned/forked process's own
/// `Process::fpu_state` starts as.
pub fn clean_state() -> FxSaveArea {
    // SAFETY: only ever written once, by capture_clean_state() during this module's own init()
    // (which runs long before any process — and therefore any call to this function — exists).
    unsafe { CLEAN_FPU_STATE }
}

/// Saves the live hardware FPU/SSE state into `*area`. Called by `scheduler::schedule`/`start` for
/// the outgoing process, right before switching away — see this module's own doc comment for why
/// this is needed at all now that the scheduler is preemptive.
///
/// # Safety
///
/// `area` must point at a valid, writable, 16-byte-aligned `FxSaveArea`.
pub unsafe fn save(area: *mut FxSaveArea) {
    // SAFETY: caller's contract.
    unsafe {
        core::arch::asm!("fxsave [{0}]", in(reg) area, options(nostack));
    }
}

/// Restores the live hardware FPU/SSE state from `*area`. Called by `scheduler::schedule`/`start`
/// for the incoming process, right before actually switching onto its stack.
///
/// # Safety
///
/// `area` must point at a valid, 16-byte-aligned `FxSaveArea` (either a real prior `save()` or
/// `clean_state()`'s own output).
pub unsafe fn restore(area: *const FxSaveArea) {
    // SAFETY: caller's contract.
    unsafe {
        core::arch::asm!("fxrstor [{0}]", in(reg) area, options(nostack));
    }
}
