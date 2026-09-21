//! Boots the full kernel, loads `native_abi` (fork/wait4/exit/open/close/write/mmap/munmap/msync's
//! own syscall registration path), `posix_compat` (`SYS_MLOCKALL`/`SYS_PRLIMIT64`, part 10's
//! `mlockall(MCL_FUTURE)`/`RLIMIT_MEMLOCK` scenario), `clock` (`SYS_NANOSLEEP`, part 11's real
//! mtime/ctime scenario), `signal` (`SYS_SIGACTION`/`SYS_SIGRETURN`, plus the real
//! ring-3-page-fault-to-signal delivery parts 2-4 exercise), and `oxfs`
//! (`SYS_OPEN`/`SYS_CLOSE`/`SYS_UNLINK`/`SYS_FTRUNCATE`/`SYS_FSTAT`, real `/tmp`), then spawns
//! `regress/mmap-syscall-smoke/` as pid 1 -- see that crate's own module doc comment for the full
//! scenario list (the `mmap/12-1.c` unlink-before-first-commit fix, three real
//! fault-to-signal-delivery scenarios closing `mmap/11-2.c`/`11-3.c`, and the real `MAP_FIXED`/
//! `MAP_PRIVATE`/`EBADF`/`EINVAL`/`mlockall`/mtime-ctime scenarios closing `mmap/3-1.c`, `9-1.c`,
//! `14-1.c`, `18-1.c`, `19-1.c`, `21-1.c`, `munmap/3-1.c`, `munmap/4-1.c`).
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

/// Must match `regress/mmap-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "mmap_syscall_smoke: child reported {}",
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
    // SYS_MUNMAP -- must load before mmap-syscall-smoke, below, is spawned.
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

    // Populates SYS_MLOCKALL/SYS_PRLIMIT64 -- part 10's real mlockall(MCL_FUTURE)/RLIMIT_MEMLOCK
    // scenario.
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

    // Populates SYS_NANOSLEEP -- part 11's own real mtime/ctime scenario needs a real elapsed
    // second between the two fstat() calls.
    const CLOCK_MOD: &[u8] = include_bytes!(env!("CLOCK_MOD_PATH"));
    const CLOCK_MOD_PANIC_SYMBOL: &str = env!("CLOCK_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "clock",
        CLOCK_MOD,
        CLOCK_MOD_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the clock module: {e:?}"));

    // Populates SYS_SIGACTION/SYS_SIGRETURN -- part 2's own real handler-invocation scenario.
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

    // Populates SYS_OPEN/SYS_CLOSE/SYS_UNLINK/SYS_FTRUNCATE, real /tmp -- this test's whole
    // filesystem-side scenario.
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

    const MMAP_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("MMAP_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "mmap_syscall_smoke: spawning mmap-syscall-smoke as pid 1 ({} byte ELF)",
        MMAP_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(MMAP_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn mmap-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
