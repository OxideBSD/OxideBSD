use x86_64::instructions::port::Port;

use crate::hlt_loop;

/// Resets the CPU by pulsing the 8042 keyboard controller's reset line.
///
/// Fatal exception handlers call this instead of halting: kernel state after a double fault (or
/// similar) can't be trusted, so restarting clean is safer than continuing to run.
pub fn reboot() -> ! {
    let mut status_port: Port<u8> = Port::new(0x64);
    let mut command_port: Port<u8> = Port::new(0x64);

    unsafe {
        // Wait until the controller's input buffer is empty before writing to it.
        while status_port.read() & 0x02 != 0 {}
        command_port.write(0xFEu8);
    }

    // The reset should fire almost immediately; this is only a fallback if it doesn't.
    hlt_loop();
}

/// Powers off: ACPI S5 through the ports and sleep type the firmware's tables give
/// (`acpi::enter_s5`). If that is unavailable or doesn't take, the old QEMU-only write (`0x2000`
/// to port `0x604`, PM1a control under SeaBIOS) is tried, and then the CPU halts.
pub fn poweroff() -> ! {
    crate::acpi::enter_s5();
    let mut port: Port<u16> = Port::new(0x604);
    unsafe { port.write(0x2000u16) };
    hlt_loop();
}

/// Halts the CPU with no reset and no power-off -- real `RB_HALT_SYSTEM` semantics on a kernel
/// with no other hardware-specific halt mechanism to invoke.
pub fn halt() -> ! {
    hlt_loop();
}
