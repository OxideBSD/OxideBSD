use x86_64::instructions::port::Port;

use crate::hlt_loop;

/// The TSC `ms` milliseconds from now; forever before the TSC is calibrated.
fn after_ms(ms: u64) -> u64 {
    match crate::cpu::tsc::ms_to_cycles(ms) {
        0 => u64::MAX,
        c => crate::cpu::tsc::now().saturating_add(c),
    }
}

/// Resets the CPU by pulsing the 8042 keyboard controller's reset line.
///
/// Fatal exception handlers call this instead of halting: kernel state after a double fault (or
/// similar) can't be trusted, so restarting clean is safer than continuing to run.
pub fn reboot() -> ! {
    let mut status_port: Port<u8> = Port::new(0x64);
    let mut command_port: Port<u8> = Port::new(0x64);

    unsafe {
        // Wait until the controller's input buffer is empty before writing to it: for 100 ms
        // once the TSC is calibrated (a machine without one reads back 0xff forever).
        let deadline = after_ms(100);
        while status_port.read() & 0x02 != 0 && crate::cpu::tsc::now() < deadline {}
        command_port.write(0xFEu8);
    }

    // The reset should fire almost immediately. If it hasn't after half a second, the firmware's
    // own reset (UEFI's `ResetSystem`, EFIRT.md §9), then a halt.
    let deadline = after_ms(500);
    while crate::cpu::tsc::now() < deadline {
        core::hint::spin_loop();
    }
    crate::efirt::reset(crate::efirt::ResetKind::Cold);
    hlt_loop();
}

/// Powers off: ACPI S5 through the ports and sleep type the firmware's tables give
/// (`acpi::enter_s5`). If that is unavailable or doesn't take, the firmware's own power-off
/// (UEFI's `ResetSystem`, EFIRT.md §9), then the old QEMU-only write (`0x2000` to port `0x604`,
/// PM1a control under SeaBIOS) is tried, and then the CPU halts.
pub fn poweroff() -> ! {
    crate::acpi::enter_s5();
    crate::efirt::reset(crate::efirt::ResetKind::Shutdown);
    let mut port: Port<u16> = Port::new(0x604);
    unsafe { port.write(0x2000u16) };
    hlt_loop();
}

/// Halts the CPU with no reset and no power-off -- real `RB_HALT_SYSTEM` semantics on a kernel
/// with no other hardware-specific halt mechanism to invoke.
pub fn halt() -> ! {
    hlt_loop();
}
