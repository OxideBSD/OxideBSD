//! Real-`SYSCALL` regression test for the `yes | head` OOM panic -- see CLAUDE.md's BusyBox
//! section and `src/pipe.rs`'s module doc comment for the original bug (an unboundedly-growable
//! pipe buffer letting a producer with no blocking syscall in its own write loop starve a
//! consumer and grow the kernel heap until the allocator panicked) and its fix (a bounded buffer
//! with a real blocking writer, `BlockReason::WaitingForPipeSpace`).
//!
//! Spawns `userland/pipe-backpressure-syscall-smoke/` as pid 1 (same shape `tests/fork_wait.rs`
//! and `tests/socketpair_syscall_smoke.rs` already established) and lets it drive `pipe`/`fork`/
//! `write`/`read`/`close`/`wait4` entirely through real `SYSCALL`/`SYSRETQ` -- proving the fix
//! from inside an actual syscall context, not by calling `crate::pipe`'s functions directly as
//! plain Rust (see CLAUDE.md's Test architecture section for why that distinction matters here).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::fs::fd::oxidebsd_close_fd;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `userland/pipe-backpressure-syscall-smoke/src/main.rs`'s own constant.
const SYS_TEST_EXIT: u64 = 9999;
/// The real ABI number -- see `tests/socketpair_syscall_smoke.rs`'s own module doc comment for
/// why this is registered directly here instead of by loading the full `oxfs` module (a pipe fd's
/// own close callback, registered by `crate::pipe::do_pipe`, needs no filesystem at all).
const SYS_CLOSE: u64 = 6;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "pipe_backpressure_syscall_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
    oxidebsd::hlt_loop();
}

/// `SYS_CLOSE`'s real handler (registered by `modules/oxfs` at real boot) is pure
/// filesystem-agnostic delegation to this same function.
extern "C" fn test_close_handler(fd: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    oxidebsd_close_fd(fd) as i64
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4 -- this test's own core scenario.
    const NATIVE_ABI_MOD: &[u8] = include_bytes!(env!("NATIVE_ABI_MOD_PATH"));
    const NATIVE_ABI_PANIC_SYMBOL: &str = env!("NATIVE_ABI_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "native_abi",
        NATIVE_ABI_MOD,
        NATIVE_ABI_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the native_abi module: {e:?}"));

    // Populates SYS_PIPE -- the syscall this test actually exercises.
    const POSIX_COMPAT_MOD: &[u8] = include_bytes!(env!("POSIX_COMPAT_MOD_PATH"));
    const POSIX_COMPAT_PANIC_SYMBOL: &str = env!("POSIX_COMPAT_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "posix_compat",
        POSIX_COMPAT_MOD,
        POSIX_COMPAT_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the posix_compat module: {e:?}"));

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );
    assert_eq!(
        oxidebsd_register_syscall(SYS_CLOSE, test_close_handler),
        0,
        "SYS_CLOSE registration failed -- number collided with a real syscall?"
    );

    const PIPE_BACKPRESSURE_SYSCALL_SMOKE_ELF: &[u8] =
        include_bytes!(env!("PIPE_BACKPRESSURE_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "pipe_backpressure_syscall_smoke: spawning pipe-backpressure-syscall-smoke as pid 1 ({} byte ELF)",
        PIPE_BACKPRESSURE_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(PIPE_BACKPRESSURE_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn pipe-backpressure-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
