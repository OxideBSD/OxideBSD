//! Boots the full kernel, loads `native_abi` (fork/exit/wait4/execve/read/write/clone/mmap/
//! set_tid_address -- everything the test harness itself plus musl's own thread-creation path
//! needs), `signal` (`SYS_SIGACTION` -- real `pthread_cancel()`'s own one-time
//! `init_cancellation()` installs a real `SIGCANCEL` handler the first time it's ever called),
//! `posix_compat` (`SYS_FUTEX` -- what real `pthread_join` is actually built on), and `oxfs`
//! (serving `/pthread-cancel-crash.elf` and `/bin/musl`), then spawns
//! `regress/pthread-cancel-crash-smoke/` as pid 1 -- see that crate's own module doc comment for
//! the full two-part scenario this isolates: a real, expected `SIGSEGV` inside the Open POSIX Test
//! Suite's own `pthread_cancel/5-1.c` (`regress/pthread-cancel-crash/main.c`'s own doc comment
//! has the exact mechanism), immediately followed by a real `fork`+`execve`+`wait4` of an
//! already-proven-working musl binary to check whether the system is still healthy afterward.
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

/// Must match `regress/pthread-cancel-crash-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant --
/// no shared crate across this ABI boundary, same convention every other regress/kernel pair
/// here uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "pthread_cancel_crash_smoke: child reported {}",
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

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID/SYS_CLONE/
    // SYS_MMAP/SYS_MUNMAP/SYS_BRK/SYS_SET_FS_BASE/SYS_SET_TID_ADDRESS -- must load before
    // pthread-cancel-crash-smoke, below, is spawned.
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

    // Populates SYS_SIGACTION -- real pthread_cancel()'s own one-time init_cancellation()
    // installs a real SIGCANCEL handler the first time it's ever called.
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

    // Populates SYS_FUTEX -- the real primitive musl's own pthread_join is built on.
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

    // Serves /pthread-cancel-crash.elf and /bin/musl for the real fork+execve below.
    const OXFS_MOD: &[u8] = include_bytes!(env!("OXFS_MOD_PATH"));
    const OXFS_PANIC_SYMBOL: &str = env!("OXFS_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "oxfs",
        OXFS_MOD,
        OXFS_PANIC_SYMBOL,
        true,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the oxfs module: {e:?}"));

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const PTHREAD_CANCEL_CRASH_SMOKE_ELF: &[u8] =
        include_bytes!(env!("PTHREAD_CANCEL_CRASH_SMOKE_ELF_PATH"));
    serial_println!(
        "pthread_cancel_crash_smoke: spawning pthread-cancel-crash-smoke as pid 1 ({} byte ELF)",
        PTHREAD_CANCEL_CRASH_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(PTHREAD_CANCEL_CRASH_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn pthread-cancel-crash-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
