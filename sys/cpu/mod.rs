//! Low-level CPU bring-up and interrupt/timer plumbing: GDT/TSS (`gdt`), the IDT and its handlers
//! (`interrupts`), the legacy 8259 PIC (`pic`), SSE/MMX enablement (`fpu`), and the four hardware
//! time sources this kernel reads from directly (`tsc`, `pit`, `rtc`, `hpet`) -- see each
//! submodule's own doc comment for the real story; this file is purely a grouping point, same
//! shape as `net/mod.rs`.

pub mod fpu;
pub mod gdt;
pub mod hpet;
pub mod interrupts;
pub mod pic;
pub mod pit;
pub mod rtc;
pub mod tsc;
