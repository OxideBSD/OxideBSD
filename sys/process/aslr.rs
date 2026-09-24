//! Real per-`execve()` load-bias randomization for a no-`PT_INTERP` PIE main executable — genuine
//! ASLR, extending `elf::load`'s already-generic `bias` mechanism (previously used only for a
//! `PT_INTERP` interpreter's own fixed `INTERP_LOAD_BASE`) to a second, distinct case. See
//! `do_execve` for where this gets called, and `elf.rs`'s own module doc comment for why zero
//! in-kernel relocation processing is needed for this to be correct (a disciplined, build-time-
//! verified "never store an address as data" coding style — `build.rs`'s
//! `assert_zero_relocations`).
//!
//! **Fork never re-randomizes.** A forked child inherits its parent's exact, already-mapped,
//! already-biased address space unchanged — `do_fork_from_current` contains no `elf::load` call
//! anywhere in its body (confirmed by inspection, not just convention), so this invariant holds by
//! construction. A process's PIE bias is fixed for its entire lifetime once `execve()` picks it;
//! only a *later* `execve()` (a fresh image entirely) ever picks a new one.
//!
//! # The randomization window
//!
//! Every existing fixed VA reservation in this kernel, sorted (grep-verified against the current
//! tree, not assumed):
//!
//! ```text
//! 0x0000000010000000  INTERP_LOAD_BASE       (process/lifecycle.rs)
//! 0x0000000020000000  BRK_REGION_CEILING     (process/mm.rs)
//! 0x00001ffffffff000  FAULT_TRAMPOLINE_VA    (process/fault_trampoline.rs)
//! 0x0000200000000000  MMAP_REGION_BASE       (process/mm.rs)
//! 0x0000300000000000  MMAP_REGION_CEILING    (process/mm.rs)   <- this window starts here
//! 0x0000400000000000  SHM_REGION_BASE        (fs/sysv_shm.rs)
//! 0x0000444444440000  HEAP_START             (memory/allocator.rs)
//! 0x0000500000000000  USER_STACK_TOP         (process/mod.rs)
//! 0xffffc00000000000  MODULE_DATA_BASE       (module.rs)
//! 0xffffffffa0000000  MODULE_VA_BASE         (module.rs)
//! 0xffffffffff000000  MODULE_REGION_CEILING  (module.rs)
//! ```
//!
//! A genuinely empty 16 TiB gap sits between `MMAP_REGION_CEILING` and `SHM_REGION_BASE` — nothing
//! else in the tree falls inside it. `PIE_ASLR_CEILING` leaves 256 MiB of headroom below
//! `SHM_REGION_BASE` (these are small, freestanding `#![no_std]` binaries — a few hundred KiB at
//! most — so this margin is generous, not tight), and every bias is chosen page-aligned (the
//! natural unit `elf::load`'s own segment mapping already works in). That yields
//! `(PIE_ASLR_CEILING - PIE_ASLR_BASE) / 4096` ≈ 4.29 billion distinct page-aligned slots, i.e.
//! ~32 bits of real entropy — on par with typical amd64 Linux ASLR.

/// Base of the real PIE ASLR window — coincides with `process::mm::MMAP_REGION_CEILING`, the
/// first unclaimed address above every existing mmap allocation.
pub const PIE_ASLR_BASE: u64 = 0x_3000_0000_0000;

/// Safety margin kept clear below `SHM_REGION_BASE`, so even a much-larger-than-today PIE image's
/// highest mapped address (`bias + highest p_vaddr + memsz`) can never reach it.
const PIE_ASLR_HEADROOM: u64 = 0x_1000_0000;

/// Exclusive upper bound of the real PIE ASLR window.
pub const PIE_ASLR_CEILING: u64 = 0x_4000_0000_0000 - PIE_ASLR_HEADROOM;

const PAGE_SIZE: u64 = 4096;

/// Picks a real, page-aligned, randomized load bias for a no-`PT_INTERP` PIE main binary,
/// somewhere in `[PIE_ASLR_BASE, PIE_ASLR_CEILING)`. Called once per `execve()` of such a binary
/// — never on `fork()` (see this module's own doc comment).
pub fn pick_bias() -> u64 {
    let raw = crate::random::kernel_random_u64();
    let range_pages = (PIE_ASLR_CEILING - PIE_ASLR_BASE) / PAGE_SIZE;
    PIE_ASLR_BASE + (raw % range_pages) * PAGE_SIZE
}
