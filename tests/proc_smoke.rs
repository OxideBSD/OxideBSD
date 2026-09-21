//! Real-`SYSCALL` counterpart to this session's `/proc` completion pass (system-wide files,
//! per-fd enumeration, chdir into `/proc`) -- see `regress/proc-smoke/src/main.rs`'s own module
//! doc comment for why a real spawned process is needed at all (`sys/modules/oxfs`'s own boot-time
//! self-check runs as pid 0, before any real process exists, so it can't exercise
//! `/proc/<pid>/...` navigation). Spawns `regress/proc-smoke/` as pid 1, same shape
//! `tests/fork_wait.rs` already established for `fork`/`wait4`/`exit`.
//!
//! Loads `native_abi` (for `read`/`write`/`getpid`) and `oxfs` (for `open`/`chdir`/`getcwd`/
//! `mkdir`/`getdents`/`close`, plus the `/proc`/symlink work this test verifies) -- unlike
//! `tests/socketpair_syscall_smoke.rs`, `oxfs` itself is exactly what's under test here, so
//! there's no reason to avoid loading the full module the way that test avoids it for `SYS_CLOSE`
//! alone.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/proc-smoke/src/main.rs`'s own constant.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "proc_smoke: child reported {}",
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

    const PROC_SMOKE_ELF: &[u8] = include_bytes!(env!("PROC_SMOKE_ELF_PATH"));
    serial_println!(
        "proc_smoke: spawning proc-smoke as pid 1 ({} byte ELF)",
        PROC_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(PROC_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn proc-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
