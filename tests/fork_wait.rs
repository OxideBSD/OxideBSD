//! Boots the full kernel (modules included) and spawns `regress/fork-exec-smoke/` as pid 1 in
//! place of the real interactive shell, exercising a real ring-3 `fork`/`wait4`/`exit` round trip
//! end to end without needing interactive keyboard input the way driving the real shell would.
//!
//! `scheduler::start`/`process::do_exit` never return control to this file's own `main` (see
//! CLAUDE.md's process/scheduler section) -- there's no way to `exit_qemu` after `start` the way
//! `tests/basic_boot.rs` does after its own assertions. Instead, `main` registers a test-only
//! syscall number (`SYS_TEST_EXIT`, not used by any real ABI) directly against
//! `oxidebsd::syscall::oxidebsd_register_syscall` before spawning pid 1; `fork-exec-smoke` calls
//! it once it's verified its own fork+wait result, and the handler here calls `exit_qemu`
//! directly from that syscall-handling context -- still kernel code, reachable regardless of
//! whether the original boot stack itself will ever run again.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/fork-exec-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no shared
/// crate across this ABI boundary, same convention every other regress/kernel pair here uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "fork_wait: fork-exec-smoke reported {}",
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

    const HELLO_MOD: &[u8] = include_bytes!(env!("HELLO_MOD_PATH"));
    const HELLO_PANIC_SYMBOL: &str = env!("HELLO_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "hello",
        HELLO_MOD,
        HELLO_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the hello module: {e:?}"));

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID -- must load
    // before fork-exec-smoke, below, is spawned.
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

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const FORK_EXEC_SMOKE_ELF: &[u8] = include_bytes!(env!("FORK_EXEC_SMOKE_ELF_PATH"));
    serial_println!(
        "fork_wait: spawning fork-exec-smoke as pid 1 ({} byte ELF)",
        FORK_EXEC_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(FORK_EXEC_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn fork-exec-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
