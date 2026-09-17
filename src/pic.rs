//! A minimal driver for the 8259 (and 8259A) Programmable Interrupt Controller pair. See
//! <https://wiki.osdev.org/8259_PIC>.
//!
//! By default PIC1 maps IRQ0-7 onto interrupt vectors 0x8-0xF and PIC2 maps IRQ8-15 onto
//! 0x70-0x77 (or a chipset-specific alternative) — both overlap CPU exception vectors, so both
//! controllers are reprogrammed here to a contiguous, exception-free range instead.

use x86_64::instructions::port::Port;

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
        // PIC2's INTR output pin *is* PIC1's IRQ2 line. Real BIOS/legacy boot typically leaves
        // IRQ2 unmasked already (this driver's own `init()` preserves whatever mask was inherited,
        // never touching it explicitly), so this defensive fix is likely inert on this boot path
        // in practice -- ported from the Limine-era master branch fix, where it *was* live: there,
        // Limine masks everything at boot and nothing ever unmasked IRQ2, so no PIC2-line
        // interrupt (rtl8139's included) could ever reach the CPU regardless of that line's own
        // mask state. Fixed here too so this function is correct on its own, not merely "correct
        // by accident of inherited firmware state."
        if irq >= 8 {
            let mut pic1_data: Port<u8> = Port::new(PIC1_DATA);
            let mask1 = pic1_data.read();
            pic1_data.write(mask1 & !(1 << 2));
        }
    }
}

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
