//! Boots the full kernel, loads `native_abi` (fork/wait4/exit/write/open/close's own syscall
//! registration path), `posix_compat` (`SYS_SETUID`), and `oxfs` (`SYS_ACCESS`/`SYS_CHMOD`/
//! `SYS_CHOWN`), then spawns `regress/access-syscall-smoke/` as pid 1 -- see that crate's own
//! module doc comment for the full three-part scenario (root `F_OK`/`R_OK` checks against a real
//! seeded file plus `ENOENT` on a missing one, a chmod/chown setup, then a real `setuid`-driven
//! privilege drop followed by a real `EACCES` denial on `R_OK` while `F_OK` still succeeds).
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

/// Must match `regress/access-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "access_syscall_smoke: child reported {}",
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
    // before access-syscall-smoke, below, is spawned.
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

    // Populates SYS_SETUID -- this test's own part 3 privilege drop.
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

    // Populates SYS_OPEN/SYS_CLOSE/SYS_ACCESS/SYS_CHMOD/SYS_CHOWN, plus the real per-inode
    // permission enforcement this test's own part 1/3 exercise.
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

    const ACCESS_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("ACCESS_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "access_syscall_smoke: spawning access-syscall-smoke as pid 1 ({} byte ELF)",
        ACCESS_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(ACCESS_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn access-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
