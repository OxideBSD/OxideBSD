//! Low-level CPU bring-up and interrupt/timer plumbing: GDT/TSS (`gdt`), the IDT and trap entry
//! (`trap`), the entry area KPTI maps for ring 3 (`entry`), the handlers (`interrupts`), the legacy 8259 PIC (`pic`), SSE/MMX enablement
//! (`fpu`), KPTI / Meltdown (`pti`), and the four hardware time sources this kernel reads from directly (`tsc`, `pit`,
//! `rtc`, `hpet`) -- see each submodule's own doc comment for the real story; this file is purely
//! a grouping point, same shape as `net/mod.rs`.

pub mod entry;
pub mod fpu;
pub mod gdt;
pub mod hpet;
pub mod interrupts;
pub mod nx;
pub mod pic;
pub mod pti;
pub mod pit;
pub mod rtc;
pub mod smap;
pub mod trap;
pub mod tsc;
