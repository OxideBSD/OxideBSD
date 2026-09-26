//! Real-`SYSCALL` counterpart to `tests/socketpair_smoke.rs` -- see CLAUDE.md's "Real networking"
//! section for the blind spot this closes: every existing network smoke test calls kernel
//! handlers as plain Rust functions from its own `main()`, never through a genuine `SYSCALL` with
//! interrupts actually masked the way a real syscall runs. This test instead spawns
//! `regress/socketpair-syscall-smoke/` as pid 1 (same shape `tests/fork_wait.rs` already
//! established for `fork`/`wait4`/`exit`) and lets it drive `socketpair`/`fcntl`/`shutdown`/
//! `read`/`write`/`close`/`set_tid_address` entirely through real `SYSCALL`/`SYSRETQ`.
//!
//! No test-only "advance a synthetic peer" syscall is needed here (unlike the UDP/TCP/poll
//! conversions) -- both ends of the pair are owned by the same process, so every step is already
//! a real ABI syscall the child can issue directly.
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

/// Must match `regress/socketpair-syscall-smoke/src/main.rs`'s own constant.
const SYS_TEST_EXIT: u64 = 9999;
/// The real ABI number -- see this test's own module doc comment for why it's registered
/// directly here instead of by loading the full `oxfs` module.
const SYS_CLOSE: u64 = 6;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "socketpair_syscall_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
    oxidebsd::hlt_loop();
}

/// `SYS_CLOSE`'s real handler (registered by `sys/modules/oxfs` at real boot) is pure
/// filesystem-agnostic delegation to this same function -- see this test's own module doc comment
/// for why loading all of `oxfs` isn't worth it just for this one generic close path.
extern "C" fn test_close_handler(fd: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    oxidebsd_close_fd(fd) as i64
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

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

    // Registers SYS_SIGACTION -- the fixture ignores SIGPIPE before its EPIPE check.
    const SIGNAL_MOD: &[u8] = include_bytes!(env!("SIGNAL_MOD_PATH"));
    const SIGNAL_PANIC_SYMBOL: &str = env!("SIGNAL_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "signal",
        SIGNAL_MOD,
        SIGNAL_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the signal module: {e:?}"));

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

    const SOCKETPAIR_SYSCALL_SMOKE_ELF: &[u8] =
        include_bytes!(env!("SOCKETPAIR_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "socketpair_syscall_smoke: spawning socketpair-syscall-smoke as pid 1 ({} byte ELF)",
        SOCKETPAIR_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(SOCKETPAIR_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn socketpair-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
