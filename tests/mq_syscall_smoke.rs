//! Boots the full kernel, loads `native_abi` (exit/write/fork/wait4/getpid's own syscall
//! registration path), `signal` (`SYS_KILL`/`SYS_SIGACTION` -- `mq_notify`'s `SIGEV_SIGNAL`
//! delivery reuses `process::do_kill` directly, and the test installs a real `SIGUSR1` handler),
//! `clock` (`SYS_CLOCK_GETTIME`, for the real-deadline part), and `posix_compat`
//! (`SYS_MQ_OPEN`...`SYS_MQ_GETSETATTR`), then spawns `regress/mq-syscall-smoke/` as pid 1 -- see
//! that crate's own module doc comment for the full eight-part POSIX-message-queue scenario.
//!
//! Same `SYS_TEST_EXIT` convention `tests/fork_wait.rs` established: `scheduler::start`/
//! `process::do_exit` never return control to this file's own `main`, so the child reports
//! pass/fail through a syscall number no real ABI uses, registered directly against a handler
//! that calls `exit_qemu`.
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

/// Must match `regress/mq-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no shared
/// crate across this ABI boundary, same convention every other regress/kernel pair here uses.
const SYS_TEST_EXIT: u64 = 9999;
/// The real ABI number -- see `tests/socketpair_syscall_smoke.rs`'s own precedent for why this is
/// registered directly here (delegating straight to `oxidebsd_close_fd`, the same real logic
/// `sys/modules/oxfs` registers it against at real boot) instead of loading all of
/// `oxfs` just to exercise the one generic close path this test's final part needs (`mq_close`
/// isn't its own syscall -- see `sys/fs/mqueue.rs`'s own doc comment).
const SYS_CLOSE: u64 = 6;

extern "C" fn test_close_handler(fd: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    oxidebsd_close_fd(fd) as i64
}

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "mq_syscall_smoke: child reported {}",
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
    // before mq-syscall-smoke, below, is spawned.
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

    // Populates SYS_KILL/SYS_SIGACTION/... -- SYS_SIGACTION installs the SIGUSR1 handler under
    // test; SYS_KILL is what mq_notify's SIGEV_SIGNAL delivery calls through to (process::do_kill)
    // once a real handler exists to invoke.
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

    // Populates SYS_CLOCK_GETTIME -- the real-deadline part reads CLOCK_REALTIME to build a real
    // near-future mq_timedreceive/mq_timedsend `at` timestamp.
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

    // Populates SYS_MQ_OPEN/SYS_MQ_UNLINK/SYS_MQ_TIMEDSEND/SYS_MQ_TIMEDRECEIVE/SYS_MQ_NOTIFY/
    // SYS_MQ_GETSETATTR -- this test's entire subject.
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

    const MQ_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("MQ_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "mq_syscall_smoke: spawning mq-syscall-smoke as pid 1 ({} byte ELF)",
        MQ_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(MQ_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn mq-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
