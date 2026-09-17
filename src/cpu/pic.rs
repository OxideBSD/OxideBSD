//! A minimal driver for the 8259 (and 8259A) Programmable Interrupt Controller pair. See
//! <https://wiki.osdev.org/8259_PIC>.
//!
//! By default PIC1 maps IRQ0-7 onto interrupt vectors 0x8-0xF and PIC2 maps IRQ8-15 onto
//! 0x70-0x77 (or a chipset-specific alternative) — both overlap CPU exception vectors, so both
//! controllers are reprogrammed here to a contiguous, exception-free range instead.

use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::{ApicBase, ApicBaseFlags};

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

/// Unused I/O port used purely as a delay: writing to it takes long enough for the PIC to
/// process the previous command, which is otherwise not guaranteed on older hardware.
const WAIT_PORT: u16 = 0x80;

const CMD_INIT: u8 = 0x11;
const CMD_END_OF_INTERRUPT: u8 = 0x20;
const MODE_8086: u8 = 0x01;

/// Vector offset both PICs are remapped to. PIC1 owns `[PIC_1_OFFSET, PIC_2_OFFSET)`
/// (IRQ0-7) and PIC2 owns `[PIC_2_OFFSET, PIC_2_OFFSET + 8)` (IRQ8-15).
pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

/// Remaps both PICs to `PIC_1_OFFSET`/`PIC_2_OFFSET` and restores whatever interrupt mask was
/// already in place (so this only changes *which vectors* IRQs map to, not which are masked).
///
/// # Safety
///
/// Must run after the IDT has handlers installed for every vector in
/// `[PIC_1_OFFSET, PIC_2_OFFSET + 8)`, and before interrupts are enabled.
pub unsafe fn init() {
    let mut pic1_command: Port<u8> = Port::new(PIC1_COMMAND);
    let mut pic1_data: Port<u8> = Port::new(PIC1_DATA);
    let mut pic2_command: Port<u8> = Port::new(PIC2_COMMAND);
    let mut pic2_data: Port<u8> = Port::new(PIC2_DATA);
    let mut wait_port: Port<u8> = Port::new(WAIT_PORT);
    let mut wait = || unsafe { wait_port.write(0) };

    unsafe {
        // Real root cause, confirmed live via QEMU's own `info lapic`/`info pic` monitor
        // commands, chasing why no PIC-delivered IRQ (timer *or* keyboard) ever reached this
        // kernel under Limine, even after unmasking both lines (see `interrupts::init_pics`'s
        // own doc comment) and forcing the IMCR below: the platform boots with the Local APIC
        // genuinely *enabled* (`SPIV` showed "APIC enabled") but its `LVT0` entry -- the one that
        // receives the legacy 8259's `INTR` output in "virtual wire" compatibility mode --
        // *masked*. The 8259 itself was working correctly the whole time (`info pic` showed
        // `irr=01`, a real pending IRQ0 request) but nothing ever delivered it to the CPU core,
        // since the LAPIC (not the 8259) is what the CPU actually listens to whenever the LAPIC
        // is enabled at all. Real BIOS/SeaBIOS + the old `bootloader` crate apparently never
        // enabled the LAPIC in the first place, so the CPU fell back to the legacy direct-INTR
        // 8259 path by construction; Limine (or OVMF/SeaBIOS's own more modern, ACPI-aware
        // platform init once Limine hands off through them) leaves it enabled but not configured
        // for virtual-wire passthrough. Fixed at the actual source, not by chasing the LAPIC's
        // own MMIO-mapped LVT0 register (real APIC programming this kernel has no other use for
        // and no driver for at all -- `cpu::interrupts` is purely 8259-based): disabling the
        // LAPIC outright via `IA32_APIC_BASE`'s global-enable bit makes the CPU treat its `INTR`
        // pin exactly like a pre-APIC system again, restoring direct 8259-to-CPU delivery
        // unconditionally. The IMCR write below (a real PIIX-family chipset detail, ports
        // 0x22/0x23 -- `1` would disconnect the 8259 pair in favor of IOAPIC routing) is kept as
        // a defensive belt-and-suspenders measure alongside it, though the LAPIC disable alone
        // was confirmed sufficient.
        let (frame, flags) = ApicBase::read();
        ApicBase::write(frame, flags & !ApicBaseFlags::LAPIC_ENABLE);

        let mut imcr_select: Port<u8> = Port::new(0x22);
        let mut imcr_data: Port<u8> = Port::new(0x23);
        imcr_select.write(0x70);
        imcr_data.write(0x00);

        let saved_mask1 = pic1_data.read();
        let saved_mask2 = pic2_data.read();

        // Byte 1: start the 3-byte initialization sequence on both controllers.
        pic1_command.write(CMD_INIT);
        wait();
        pic2_command.write(CMD_INIT);
        wait();

        // Byte 2: vector offsets.
        pic1_data.write(PIC_1_OFFSET);
        wait();
        pic2_data.write(PIC_2_OFFSET);
        wait();

        // Byte 3: tell PIC1 it has a secondary PIC cascaded on IRQ2 (bit 2 set), and tell PIC2
        // its own cascade identity (binary, i.e. "I am IRQ2 on the primary").
        pic1_data.write(4);
        wait();
        pic2_data.write(2);
        wait();

        pic1_data.write(MODE_8086);
        wait();
        pic2_data.write(MODE_8086);
        wait();

        pic1_data.write(saved_mask1);
        pic2_data.write(saved_mask2);
    }
}

/// Signals end-of-interrupt for `vector`, which must be a vector this PIC pair owns (i.e. in
/// `[PIC_1_OFFSET, PIC_2_OFFSET + 8)`) — otherwise the wrong controller(s) get acknowledged and
/// further interrupts on that line stay stuck.
///
/// # Safety
///
/// Must only be called from within the interrupt handler for `vector`.
/// Clears the mask bit for `irq` (0-15), letting it start delivering interrupts. Must only be
/// called after a handler for that line is already installed (`interrupts::register_irq_handler`
/// for anything beyond the timer/keyboard) -- unmasking first risks a line firing before anything
/// is listening for it.
///
/// # Safety
///
/// Caller must ensure a handler for `irq`'s vector is already installed in the IDT.
pub unsafe fn unmask_irq(irq: u8) {
    debug_assert!(irq < 16, "PIC pair only owns IRQ0-15");
    let (mut port, bit): (Port<u8>, u8) = if irq < 8 {
        (Port::new(PIC1_DATA), irq)
    } else {
        (Port::new(PIC2_DATA), irq - 8)
    };
    unsafe {
        let mask = port.read();
        port.write(mask & !(1 << bit));
        // Any IRQ8-15 line physically cascades into the CPU through PIC1's own IRQ2 input --
        // PIC2's INTR output pin *is* PIC1's IRQ2 line. `init_pics` only ever unmasks IRQ0/IRQ1
        // (the timer/keyboard), so IRQ2 stays masked at PIC1 unless something explicitly clears
        // it -- meaning no PIC2 line, unmasked here or not, could ever actually reach the CPU.
        // Found live chasing why `net::rtl8139`'s own IRQ (line 11, PIC2) never fired despite
        // `register_irq_handler`/`unmask_irq(11)` both running correctly: PIC2's own mask bit
        // was clear, but PIC1's IRQ2 bit was still set from boot, silently swallowing the signal
        // one hop earlier. Any future PIC2-line driver would hit the exact same silent failure
        // without this.
        if irq >= 8 {
            let mut pic1_data: Port<u8> = Port::new(PIC1_DATA);
            let mask1 = pic1_data.read();
            pic1_data.write(mask1 & !(1 << 2));
        }
    }
}

/// # Safety
/// Must be called from within a real interrupt handler for the vector being acknowledged --
/// sending a spurious EOI confuses the PIC's own interrupt-priority state for every IRQ after it.
pub unsafe fn notify_end_of_interrupt(vector: u8) {
    let mut pic1_command: Port<u8> = Port::new(PIC1_COMMAND);
    let mut pic2_command: Port<u8> = Port::new(PIC2_COMMAND);

    unsafe {
        // IRQ8-15 (PIC2) must be acknowledged on both controllers, since PIC2 is cascaded
        // through PIC1's IRQ2 line.
        if vector >= PIC_2_OFFSET {
            pic2_command.write(CMD_END_OF_INTERRUPT);
        }
        pic1_command.write(CMD_END_OF_INTERRUPT);
    }
}
