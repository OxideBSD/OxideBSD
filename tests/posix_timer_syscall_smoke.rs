//! Boots the full kernel, loads `native_abi` (exit/write/getpid's own syscall registration path),
//! `signal` (`SYS_SIGACTION`/`SYS_SIGPROCMASK`), and `clock` (`SYS_CLOCK_GETTIME`/
//! `SYS_TIMER_CREATE`/`SYS_TIMER_SETTIME`/`SYS_TIMER_GETTIME`/`SYS_TIMER_GETOVERRUN`/
//! `SYS_TIMER_DELETE`), then spawns `regress/posix-timer-syscall-smoke/` as pid 1 -- see that
//! crate's own module doc comment for the full eight-part POSIX-per-process-timer scenario.
//!
//! Same `SYS_TEST_EXIT` convention `tests/fork_wait.rs` established: `scheduler::start`/
//! `process::do_exit` never return control to this file's own `main`, so the child reports
//! pass/fail through a syscall number no real ABI uses, registered directly against a handler
//! that calls `exit_qemu`.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/posix-timer-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant --
/// no shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "posix_timer_syscall_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
    oxidebsd::hlt_loop();
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID -- must load
    // before posix-timer-syscall-smoke, below, is spawned.
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

    // Populates SYS_KILL/SYS_SIGACTION/SYS_SIGPROCMASK/... -- this test needs SYS_SIGACTION (to
    // install the SIGALRM/SIGUSR1 handlers under test) and SYS_SIGPROCMASK (the overrun-accounting
    // part).
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

    // Populates SYS_CLOCK_GETTIME/SYS_NANOSLEEP/SYS_SETITIMER/SYS_GETITIMER/SYS_TIMER_CREATE/
    // SYS_TIMER_SETTIME/SYS_TIMER_GETTIME/SYS_TIMER_GETOVERRUN/SYS_TIMER_DELETE -- this test's
    // entire subject.
    const CLOCK_MOD: &[u8] = include_bytes!(env!("CLOCK_MOD_PATH"));
    const CLOCK_PANIC_SYMBOL: &str = env!("CLOCK_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "clock",
        CLOCK_MOD,
        CLOCK_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the clock module: {e:?}"));

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const POSIX_TIMER_SYSCALL_SMOKE_ELF: &[u8] =
        include_bytes!(env!("POSIX_TIMER_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "posix_timer_syscall_smoke: spawning posix-timer-syscall-smoke as pid 1 ({} byte ELF)",
        POSIX_TIMER_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(POSIX_TIMER_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn posix-timer-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
