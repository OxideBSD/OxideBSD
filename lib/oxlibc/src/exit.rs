//! `exit()` and the crate graph's one `#[panic_handler]` -- Rust requires exactly one, not
//! necessarily in the final binary crate, so no `bin/<name>` utility needs its own (a real
//! simplification over `usr.bin/lsoxmod`'s own hand-rolled copy, which predates this crate).

use crate::syscall::syscall3;

const SYS_EXIT: u64 = 1;

/// Terminates the calling process with `code` -- never returns (`SYS_EXIT` itself never returns
/// on success; the trailing spin loop is only ever reached if the syscall somehow failed).
pub fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall3(SYS_EXIT, code, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit(1)
}
