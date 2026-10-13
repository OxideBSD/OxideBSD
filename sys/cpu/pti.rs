//! Kernel page-table isolation: the Meltdown mitigation (`OxideBSD-doc/THREAT_MODEL.md` §3.4).
//!
//! Meltdown (CVE-2017-5754) lets ring 3 read any byte the page tables map, kernel memory included,
//! by timing a speculative access past a faulting one. The fix is to run ring 3 on page tables
//! that map almost none of the kernel: only the entry area (`cpu::entry`), the few pages that have
//! to be mapped for a trap or `syscall` to reach the switch to the kernel's own tables. This
//! module only decides *whether* to do that and reports the decision; the table split itself lands
//! in a later commit.
//!
//! **Who needs it.** Only Intel is affected, and newer Intel parts advertise `RDCL_NO` ("rogue
//! data cache load no") to say they aren't. So the default is on for a `GenuineIntel` CPU that
//! doesn't set `RDCL_NO`, off otherwise. A boot flag (`pti=`/`kpti=`/`meltdown=`, `on` or `off`)
//! overrides the detection either way, and tests force it on.

use core::sync::atomic::{AtomicU8, Ordering};

/// The decision, as one of these. `UNSET` until `decide` runs; a `request` from the command line
/// is remembered here too (as `FORCE_ON`/`FORCE_OFF`) until then.
static STATE: AtomicU8 = AtomicU8::new(UNSET);
const UNSET: u8 = 0;
const OFF: u8 = 1;
const ON: u8 = 2;
const FORCE_OFF: u8 = 3;
const FORCE_ON: u8 = 4;

/// Records a `pti=`/`kpti=`/`meltdown=` override (`Some(true)` on, `Some(false)` off), or leaves
/// the decision to `decide` (`None`). Called from `boot::apply_cmdline`, before `decide`.
pub fn request(force: Option<bool>) {
    let state = match force {
        Some(true) => FORCE_ON,
        Some(false) => FORCE_OFF,
        None => return,
    };
    STATE.store(state, Ordering::Relaxed);
}

/// Forces KPTI on regardless of the CPU, for a test kernel that wants to exercise it on hardware
/// that doesn't need it (the dev machine reports `RDCL_NO`). Call before `decide`.
pub fn force_on_for_test() {
    STATE.store(FORCE_ON, Ordering::Relaxed);
}

/// Makes the final on/off decision and logs it. Called once, early in `init`. An override (from
/// the command line or a test) wins; otherwise KPTI is on exactly when the CPU is affected by
/// Meltdown (`cpu_is_affected`).
pub fn decide() {
    let forced = match STATE.load(Ordering::Relaxed) {
        FORCE_ON => Some(true),
        FORCE_OFF => Some(false),
        _ => None,
    };
    let on = forced.unwrap_or_else(cpu_is_affected);
    STATE.store(if on { ON } else { OFF }, Ordering::Relaxed);

    let why = match forced {
        Some(_) => "forced by boot flag",
        None if on => "Intel without RDCL_NO",
        None => "CPU reports it isn't affected by Meltdown",
    };
    crate::serial_println!(
        "[pti] kernel page-table isolation {} ({})",
        if on { "ON" } else { "off" },
        why
    );
}

/// Whether KPTI is on. Only meaningful after `decide`.
pub fn enabled() -> bool {
    STATE.load(Ordering::Relaxed) == ON
}

/// Whether this CPU is affected by Meltdown: `GenuineIntel` that doesn't advertise `RDCL_NO`.
fn cpu_is_affected() -> bool {
    if !is_genuine_intel() {
        return false;
    }
    // RDCL_NO lives in IA32_ARCH_CAPABILITIES (MSR 0x10A) bit 0, which only exists when
    // CPUID.(EAX=7,ECX=0).EDX bit 29 (IA32_ARCH_CAPABILITIES present) is set. No bit 29 means an
    // older Intel part that predates the enumeration: affected.
    // SAFETY: CPUID leaf 7 is always available on any CPU this kernel runs on (checked for SMAP).
    let arch_caps_present = unsafe { core::arch::x86_64::__cpuid_count(7, 0).edx } & (1 << 29) != 0;
    if !arch_caps_present {
        return true;
    }
    // SAFETY: the MSR exists, per the CPUID bit just checked.
    let arch_caps = unsafe { x86_64::registers::model_specific::Msr::new(0x10A).read() };
    arch_caps & 1 == 0
}

/// Whether CPUID's vendor string is `GenuineIntel`.
fn is_genuine_intel() -> bool {
    // SAFETY: CPUID leaf 0 is always available.
    let vendor = unsafe { core::arch::x86_64::__cpuid(0) };
    // "Genu" "ineI" "ntel" in EBX, EDX, ECX.
    vendor.ebx == 0x756e_6547 && vendor.edx == 0x4965_6e69 && vendor.ecx == 0x6c65_746e
}
