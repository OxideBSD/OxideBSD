//! Boots the full kernel, loads `native_abi` (fork/wait4/exit/write/getpid/clock_gettime's own
//! syscall registration path) and `clock` (`SYS_SETITIMER`/`SYS_GETITIMER`), and spawns
//! `regress/itimer-syscall-smoke/` as pid 1 -- see that crate's own module doc comment for the
//! full two-part scenario (a `setitimer`/`getitimer` round trip, then a real default-disposition
//! `SIGALRM` termination check across a genuine `SYSCALL` boundary).
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

/// Must match `regress/itimer-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "itimer_syscall_smoke: child reported {}",
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
    // before itimer-syscall-smoke, below, is spawned.
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

    // Populates SYS_CLOCK_GETTIME/SYS_NANOSLEEP/SYS_SETITIMER/SYS_GETITIMER -- the syscalls this
    // test actually exercises.
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

    const ITIMER_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("ITIMER_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "itimer_syscall_smoke: spawning itimer-syscall-smoke as pid 1 ({} byte ELF)",
        ITIMER_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(ITIMER_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn itimer-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
