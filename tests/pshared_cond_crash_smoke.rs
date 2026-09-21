//! Boots the full kernel, loads `native_abi` (fork/exit/wait4/execve/read/write/open/mmap/munmap
//! -- everything the test harness itself plus this fixture's own real `mkstemp`+`mmap` needs),
//! `clock` (`SYS_CLOCK_GETTIME` -- real `mkstemp()` seeds its own temp-file name via
//! `clock_gettime`, same as `sem_open()` does), `signal` (`SYS_SIGPROCMASK` -- real `fork()`
//! unconditionally blocks/restores signals around the fork transition), `posix_compat`
//! (`SYS_FUTEX` -- what real `pthread_mutex`/`pthread_cond` are actually built on), and `oxfs`
//! (serving `/pshared-cond-crash.elf` and real `/tmp`), then spawns
//! `regress/pshared-cond-crash-smoke/` as pid 1 -- see that crate's own module doc comment for
//! the fork+execve+wait4 scenario, and `regress/pshared-cond-crash/main.c`'s own doc comment for
//! what the executed fixture itself isolates: a real cross-process `PTHREAD_PROCESS_SHARED`
//! mutex/cond, one forked child, distilled from the Open POSIX Test Suite's own
//! `pthread_cond_broadcast/1-2.c`, which appears to genuinely stall during a full pilot run.
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

/// Must match `regress/pshared-cond-crash-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant --
/// no shared crate across this ABI boundary, same convention every other regress/kernel pair
/// here uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "pshared_cond_crash_smoke: child reported {}",
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

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID/SYS_MMAP/
    // SYS_MUNMAP/SYS_BRK -- must load before pshared-cond-crash-smoke, below, is spawned.
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

    // Populates SYS_CLOCK_GETTIME -- real mkstemp() calls clock_gettime(CLOCK_REALTIME, ...) to
    // seed its own temp-file name.
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

    // Populates SYS_SIGPROCMASK -- real fork() unconditionally blocks/restores signals around the
    // fork transition (__block_app_sigs/__restore_sigs in external/mit/musl/src/process/fork.c).
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

    // Populates SYS_FUTEX -- the real primitive musl's own pthread_mutex/pthread_cond are built
    // on.
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

    // Serves /pshared-cond-crash.elf and real /tmp for the real fork+execve below.
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

    const PSHARED_COND_CRASH_SMOKE_ELF: &[u8] =
        include_bytes!(env!("PSHARED_COND_CRASH_SMOKE_ELF_PATH"));
    serial_println!(
        "pshared_cond_crash_smoke: spawning pshared-cond-crash-smoke as pid 1 ({} byte ELF)",
        PSHARED_COND_CRASH_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(PSHARED_COND_CRASH_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn pshared-cond-crash-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
