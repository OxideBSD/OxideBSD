//! A minimal driver for channel 0 of the 8253/8254 Programmable Interval Timer -- the same chip
//! `src/interrupts.rs`'s `TICKS` counter already counts IRQs from, just never reprogrammed away
//! from whatever rate the BIOS happened to leave it at. See <https://wiki.osdev.org/Programmable_Interval_Timer>.
//!
//! Reprogrammed here to a known, fixed rate instead, so `ticks()` means something precise: real
//! PC BIOSes (including QEMU's SeaBIOS) do leave channel 0 free-running at its power-on default
//! (~18.2065 Hz, divisor 0 meaning 65536) well before this kernel ever runs, which is *why*
//! `TICKS` already worked at all -- but that default was never something this kernel configured,
//! and relying on an unconfirmed implicit rate for real clock arithmetic (`sys/syscall.rs`'s
//! `sys_clock_gettime`) would make every `CLOCK_MONOTONIC` reading only as trustworthy as that
//! assumption. `TIMER_HZ = 100` (the traditional old-Linux `HZ` value) is deliberately modest, not
//! the finer 1000 Hz some modern kernels use: this kernel's IRQ handling runs under QEMU's
//! software TCG emulation, where every extra interrupt has real, measured overhead (see
//! `sys/memory.rs`'s own doc comment on `invlpg` cost at scale for the same class of concern) --
//! 100 Hz is plenty of resolution for a clock nothing here yet needs sub-10ms precision from.

use x86_64::instructions::port::Port;

use crate::serial_println;

const CHANNEL0_DATA: u16 = 0x40;
const COMMAND: u16 = 0x43;

/// Channel 0's own input clock frequency -- fixed by the chip, not configurable.
const BASE_FREQUENCY: u32 = 1_193_182;

/// Channel 0, access mode lobyte/hibyte, mode 3 (square wave generator), binary (not BCD) counting.
const CMD_CHANNEL0_SQUARE_WAVE: u8 = 0x36;

/// The rate `src/interrupts.rs`'s timer IRQ now fires at, and the ground truth
/// `sys/syscall.rs`'s `sys_clock_gettime` converts `ticks()` against for `CLOCK_MONOTONIC`.
pub const TIMER_HZ: u32 = 100;

/// Reprograms channel 0 to fire at `TIMER_HZ`.
///
/// # Safety
///
/// Must run after the IDT has a handler installed for the timer vector and before interrupts are
/// enabled, same ordering constraint as `pic::init`.
pub unsafe fn init() {
    serial_println!("[boot] reprogramming PIT channel 0 to {} Hz", TIMER_HZ);
    let divisor = (BASE_FREQUENCY / TIMER_HZ) as u16;
    let mut command: Port<u8> = Port::new(COMMAND);
    let mut channel0: Port<u8> = Port::new(CHANNEL0_DATA);

    unsafe {
        command.write(CMD_CHANNEL0_SQUARE_WAVE);
        channel0.write((divisor & 0xff) as u8);
        channel0.write((divisor >> 8) as u8);
    }
    serial_println!("[boot] PIT ready");
}
