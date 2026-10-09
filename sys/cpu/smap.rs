//! SMEP and SMAP (`OxideBSD-doc/USERMEM.md` §5.3): with them on, the kernel faults if it executes
//! a user page (SMEP), or reads or writes one outside the copy routines (SMAP), instead of silently
//! working. Enabled at boot where the CPU has them; a CPU without them boots unprotected.
//!
//! SMAP lets the kernel touch user pages only while `RFLAGS.AC` is set: the copy routines
//! (`memory::usercopy`) set it with `stac` around the copy and clear it with `clac`. Ring 3 may set
//! AC too, and an interrupt or exception doesn't clear it (only `SYSCALL`'s `SFMASK` does), so
//! every interrupt and exception entry calls `clac` first, as Linux does; otherwise a handler, and
//! whatever kernel code the scheduler switches to from it, would run with SMAP off.

use core::arch::x86_64::__cpuid_count;
use core::sync::atomic::{AtomicU8, Ordering};

use x86_64::registers::control::{Cr4, Cr4Flags};

use crate::serial_println;

/// Nonzero once SMAP is on: `stac`/`clac` are invalid instructions on a CPU without it, so the copy
/// routines (assembly, which reads this byte) and `clac` below run them only then.
#[unsafe(no_mangle)]
pub static USERCOPY_SMAP: AtomicU8 = AtomicU8::new(0);

/// Turns on SMEP and SMAP where the CPU has them (CPUID leaf 7: EBX bit 7, bit 20). Called once,
/// early in `crate::init`, before any process exists.
pub fn init() {
    let ebx = __cpuid_count(7, 0).ebx;
    let smep = ebx & (1 << 7) != 0;
    let smap = ebx & (1 << 20) != 0;
    // SAFETY: the kernel executes no user page, and touches user pages only inside the copy
    // routines, which set AC (USERMEM.md).
    unsafe {
        Cr4::update(|f| {
            if smep {
                f.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
            }
            if smap {
                f.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
            }
        });
    }
    if smap {
        USERCOPY_SMAP.store(1, Ordering::Relaxed);
    }
    let state = |on: bool| if on { "on" } else { "not supported by this CPU" };
    serial_println!("[boot] SMEP: {}, SMAP: {}", state(smep), state(smap));
}

/// Whether SMAP is on.
pub fn enabled() -> bool {
    USERCOPY_SMAP.load(Ordering::Relaxed) != 0
}

/// Clears `RFLAGS.AC` where SMAP is on: first thing at every interrupt and exception entry.
#[inline(always)]
pub fn clac() {
    if enabled() {
        // SAFETY: only clears AC; valid because the CPU has SMAP.
        unsafe { core::arch::asm!("clac", options(nomem, nostack)) };
    }
}
