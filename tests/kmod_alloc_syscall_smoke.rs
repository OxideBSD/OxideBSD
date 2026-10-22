//! The module allocator (OxideBSD-doc `VFS.md` §3.1): loads the test-only `alloc_smoke` module
//! (`sys/modules/alloc_smoke`, `alloc` through `lib/libkern-mod`) and spawns
//! `regress/kmod-alloc-syscall-smoke/` as pid 1, which allocates and frees through the module's
//! system call and reads what the module is charged through `SYS_ALLOC_STATS` below. Same
//! `SYS_TEST_EXIT` convention as `tests/fork_wait.rs`.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/kmod-alloc-syscall-smoke/src/main.rs`.
const SYS_TEST_EXIT: u64 = 9999;
/// Must match `regress/kmod-alloc-syscall-smoke/src/main.rs`: what `alloc_smoke` holds from the
/// kernel heap, bytes (`which` 0) or allocations (1), as `kern.module.alloc_smoke.alloc{,s}`.
const SYS_ALLOC_STATS: u64 = 9994;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "kmod_alloc_syscall_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
    oxidebsd::hlt_loop();
}

extern "C" fn alloc_stats_handler(which: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    match oxidebsd::module::alloc_stats("alloc_smoke") {
        Some((bytes, _)) if which == 0 => bytes as i64,
        Some((_, count)) if which == 1 => count as i64,
        _ => -22,
    }
}

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);

    // SYS_WRITE and the rest of the native ABI.
    const NATIVE_ABI_MOD: &[u8] = include_bytes!(env!("NATIVE_ABI_MOD_PATH"));
    const NATIVE_ABI_PANIC_SYMBOL: &str = env!("NATIVE_ABI_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "native_abi",
        NATIVE_ABI_MOD,
        NATIVE_ABI_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the native_abi module: {e:?}"));
    // close, lseek, fstat, ioctl, ftruncate, fsync, fdatasync (VFS.md §6.4).
    const VFS_MOD: &[u8] = include_bytes!(env!("VFS_MOD_PATH"));
    const VFS_PANIC_SYMBOL: &str = env!("VFS_MOD_PANIC_SYMBOL");
    oxidebsd::module::load("vfs", VFS_MOD, VFS_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the vfs module: {e:?}"));

    // The module under test; it allocates in module_init too.
    const ALLOC_SMOKE_MOD: &[u8] = include_bytes!(env!("ALLOC_SMOKE_MOD_PATH"));
    const ALLOC_SMOKE_PANIC_SYMBOL: &str = env!("ALLOC_SMOKE_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "alloc_smoke",
        ALLOC_SMOKE_MOD,
        ALLOC_SMOKE_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the alloc_smoke module: {e:?}"));

    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );
    assert_eq!(
        oxidebsd_register_syscall(SYS_ALLOC_STATS, alloc_stats_handler),
        0,
        "SYS_ALLOC_STATS registration failed -- number collided with a real syscall?"
    );

    const KMOD_ALLOC_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("KMOD_ALLOC_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "kmod_alloc_syscall_smoke: spawning kmod-alloc-syscall-smoke as pid 1 ({} byte ELF)",
        KMOD_ALLOC_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(KMOD_ALLOC_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn kmod-alloc-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
