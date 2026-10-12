//! No-execute (`OxideBSD-doc/THREAT_MODEL.md` §3.3): with `EFER.NXE` set, a page whose entry (at
//! any level) has `NO_EXECUTE` faults on an instruction fetch, so data can't be run as code. Every
//! x86_64 CPU has NX, but firmware can hide it ("XD disable"); such a CPU boots without the defence,
//! and `NO_EXECUTE` must then never be set, since on it the bit is reserved and faults every access.

use core::arch::x86_64::__cpuid;
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::registers::model_specific::{Efer, EferFlags};
use x86_64::structures::paging::PageTableFlags;

use crate::serial_println;

static NX: AtomicBool = AtomicBool::new(false);

/// Turns on `EFER.NXE` where the CPU has NX (CPUID 0x8000_0001: EDX bit 20). Called once, early in
/// `crate::init`, before anything maps a page with `no_execute()`.
pub fn init() {
    let has_nx = __cpuid(0x8000_0000).eax >= 0x8000_0001 && __cpuid(0x8000_0001).edx & (1 << 20) != 0;
    if has_nx {
        // SAFETY: only adds NXE; no mapping has NO_EXECUTE on code it runs.
        unsafe { Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE)) };
        NX.store(true, Ordering::Relaxed);
        serial_println!("[boot] NX: on");
    } else {
        serial_println!(
            "[boot] WARNING: NX: not supported by this CPU (or disabled in firmware): \
             data pages are executable, W^X is not enforced"
        );
    }
}

/// Whether NX is on.
pub fn enabled() -> bool {
    NX.load(Ordering::Relaxed)
}

/// `NO_EXECUTE` where NX is on, nothing otherwise: OR it into the flags of any mapping that
/// mustn't run code.
pub fn no_execute() -> PageTableFlags {
    if enabled() { PageTableFlags::NO_EXECUTE } else { PageTableFlags::empty() }
}
