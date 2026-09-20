//! Boots the full kernel, loads `native_abi` (fork/exit/wait4/execve/read/write), `posix_compat`
//! (ioctl/fcntl/futex), `signal`/`clock` (real `std`'s runtime init touches both), `oxfs`
//! (open/close/stat -- `/bin/std-thread-net-signal-oxidebsd` and its own `/bin/true`/`/bin/sleep`
//! dependencies, all seeded by `modules/oxfs`'s `module_init`), and `net` (real socket/bind/
//! listen/accept), then spawns `userland/std-thread-net-signal-oxidebsd-syscall-smoke/` as pid 1
//! -- see that crate's own module doc comment for the full scenario (v0.3.0's real `std` consumer
//! proof, extended past fs/`process::Command` into `std::thread`, signals, and `std::net`).
//!
//! Same `SYS_TEST_EXIT` convention `tests/fork_wait.rs` established.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `userland/std-thread-net-signal-oxidebsd-syscall-smoke/src/main.rs`'s own
/// `SYS_TEST_EXIT` constant.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "std_thread_net_signal_oxidebsd_syscall_smoke: child reported {}",
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

    const NET_MOD: &[u8] = include_bytes!(env!("NET_MOD_PATH"));
    const NET_PANIC_SYMBOL: &str = env!("NET_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "net",
        NET_MOD,
        NET_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the net module: {e:?}"));

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const STD_THREAD_NET_SIGNAL_OXIDEBSD_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!(
        "STD_THREAD_NET_SIGNAL_OXIDEBSD_SYSCALL_SMOKE_ELF_PATH"
    ));
    serial_println!(
        "std_thread_net_signal_oxidebsd_syscall_smoke: spawning std-thread-net-signal-oxidebsd-syscall-smoke as pid 1 ({} byte ELF)",
        STD_THREAD_NET_SIGNAL_OXIDEBSD_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(STD_THREAD_NET_SIGNAL_OXIDEBSD_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| {
            panic!("failed to spawn std-thread-net-signal-oxidebsd-syscall-smoke: {e:?}")
        });

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
