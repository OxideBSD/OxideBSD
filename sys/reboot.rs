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

/// Powers off via QEMU's own ACPI PM shutdown port (`0x604`, value `0x2000`) -- the standard
/// "system_powerdown" trick for QEMU's default `i440fx`/PIIX4 machine (see CLAUDE.md's own "Real
/// disk persistence" section for this same machine's other fixed-port assumptions). Real hardware
/// wouldn't have this port at all, and an older QEMU machine type might not act on the write --
/// either way, falling through to a plain halt is the correct fallback, not a spin-forever wait.
pub fn poweroff() -> ! {
    let mut port: Port<u16> = Port::new(0x604);
    unsafe { port.write(0x2000u16) };
    hlt_loop();
}

/// Halts the CPU with no reset and no power-off -- real `RB_HALT_SYSTEM` semantics on a kernel
/// with no other hardware-specific halt mechanism to invoke.
pub fn halt() -> ! {
    hlt_loop();
}
