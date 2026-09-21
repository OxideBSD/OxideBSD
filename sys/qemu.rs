use x86_64::instructions::port::Port;

/// Exit codes written to the `isa-debug-exit` device.
///
/// QEMU maps a written value `v` to process exit code `(v << 1) | 1`, so these
/// must stay in sync with `test-success-exit-code` in `Cargo.toml`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) {
    let mut port = Port::new(0xf4);
    unsafe {
        port.write(exit_code as u32);
    }
}
