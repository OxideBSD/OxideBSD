//! A hardware time source immune to `sys/syscall.rs`'s own SFMASK clearing
//! `RFLAGS::INTERRUPT_FLAG` for a syscall's *entire* duration (see that file's own module doc
//! comment). `crate::cpu::interrupts::ticks()` is driven entirely by the timer IRQ, which cannot fire
//! while a real ring-3 `SYSCALL` has interrupts masked -- so any tick-based deadline check spun
//! *inside* a syscall handler (`net::oxidebsd_sys_poll`'s timeout, `ipv4::resolve_with_retry`'s
//! ARP wait, `tcp::oxidebsd_sys_connect`'s handshake wait) can never actually elapse when reached
//! via a genuine `SYSCALL` -- `ticks()` is frozen at whatever value it had when the syscall began
//! for the syscall's *entire* remaining duration.
//!
//! **Confirmed live, not theoretical**: converting `tests/poll_smoke.rs` (calls
//! `oxidebsd_sys_poll` as a plain Rust function, interrupts enabled throughout) into
//! `tests/poll_syscall_smoke.rs` (spawns a real ELF, drives the identical scenario through a
//! genuine `SYSCALL`) made the second, empty-socket `poll()` call -- which should time out after
//! 200ms -- hang solid instead, never returning. Exactly the class of blind spot the whole
//! direct-call-to-real-`SYSCALL` test conversion pass exists to catch (see CLAUDE.md's own "Real
//! networking" section on the `hlt()`-in-syscall freeze two of these same three call sites were
//! already fixed for, once, without catching this).
//!
//! `RDTSC` is a plain CPU cycle counter, not interrupt-driven -- it keeps advancing regardless of
//! `RFLAGS::INTERRUPT_FLAG`. Calibrated once at boot, in `crate::init`, while running ordinary
//! interrupt-enabled kernel code (never inside a syscall), against `crate::cpu::interrupts::ticks()`'s
//! own known `TIMER_HZ` rate -- the same "plain hardware register, no CPUID gate needed" RDTSC
//! use `sys/random.rs` already established.

use core::arch::x86_64::_rdtsc;
use core::sync::atomic::{AtomicU64, Ordering};

/// Cycles per millisecond, set once by `init()`. `0` means "not yet calibrated" -- every caller
/// here runs after `crate::init`, same ordering requirement `crate::cpu::interrupts::ticks()` already
/// has on the PIT being programmed first.
static CYCLES_PER_MS: AtomicU64 = AtomicU64::new(0);

/// The current cycle count. Monotonic, immune to interrupt masking -- see this module's own doc
/// comment.
pub fn now() -> u64 {
    unsafe { _rdtsc() }
}

/// Calibrates `CYCLES_PER_MS` by busy-waiting across a fixed number of real PIT ticks. Must run
/// while interrupts are genuinely enabled (ordinary boot-time kernel code) -- see this module's
/// own doc comment for why a tick-based wait is safe here but not inside a syscall handler.
pub fn init() {
    // 100ms at TIMER_HZ=100 -- enough headroom for a stable estimate without meaningfully
    // slowing every test's boot.
    const CALIBRATION_TICKS: u64 = 10;
    const MS_PER_TICK: u64 = 10;

    let start_tick = crate::cpu::interrupts::ticks();
    let start_tsc = now();
    while crate::cpu::interrupts::ticks() < start_tick + CALIBRATION_TICKS {
        core::hint::spin_loop();
    }
    let elapsed_cycles = now() - start_tsc;
    let elapsed_ms = CALIBRATION_TICKS * MS_PER_TICK;
    CYCLES_PER_MS.store(elapsed_cycles / elapsed_ms, Ordering::Relaxed);
}

/// Converts a millisecond duration into an equivalent delta on `now()`'s own scale -- e.g.
/// `now() + ms_to_cycles(200)` is a deadline 200ms out, checkable with a plain `now() >= deadline`
/// comparison that keeps advancing even inside a syscall with interrupts masked.
pub fn ms_to_cycles(ms: u64) -> u64 {
    CYCLES_PER_MS.load(Ordering::Relaxed).saturating_mul(ms)
}
