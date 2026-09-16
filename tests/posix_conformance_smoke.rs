//! Boots the full kernel, loads `native_abi` (fork/exit/wait4/execve/read/write -- everything
//! `sh`/`tcc`/the pilot's own compiled test binaries need to actually run), `signal`
//! (`SYS_KILL`/`SYS_SIGACTION`/`SYS_SIGTIMEDWAIT`/`SYS_SIGQUEUE` -- the `kill`/`sigqueue`/`sigwait`
//! pilot interfaces), `clock` (`SYS_CLOCK_GETTIME`/`SYS_NANOSLEEP` -- the other two pilot
//! interfaces), `posix_compat` (`SYS_MQ_OPEN`...`SYS_MQ_GETSETATTR`, plus `ioctl`/`fcntl` for
//! musl's own `isatty()`-style startup probes), `net` (just so `SYS_SOCKET` is a real registered
//! syscall -- see that module's own loading comment below for why: musl's `initgroups()` needs a
//! real `EAFNOSUPPORT`, not a generic `ENOSYS`, to fall back to parsing `/etc/group`), and `oxfs`
//! (the filesystem -- `/bin/sh`, `/bin/tcc`, and the whole `/posix-tests` tree this pilot runs
//! against), then spawns
//! `userland/posix-conformance-driver/` as pid 1 -- see that crate's own module doc comment for
//! why a dedicated driver exists instead of just spawning `sh` directly (this project's own
//! established rule against scripting live interactive keyboard input -- see CLAUDE.md's Test
//! architecture section -- and hush is normally pid 1 and interactive).
//!
//! Deliberately not a strict pass/fail assertion over the pilot's own tally (see that crate's own
//! doc comment) -- read `/posix_conformance.sh`'s own `=== summary ===` block from this test's
//! serial output for the actual, real baseline numbers.
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

/// Must match `userland/posix-conformance-driver/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other userland/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "posix_conformance_smoke: driver reported {}",
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

    // Real ACPI HPET, if QEMU exposes one -- exercises the real sub-tick `clock_getres`/POSIX
    // interval-timer overrun path (`timer_getoverrun/2-2,2-3.c`), not just its tick-based
    // fallback. Not fatal either way, same precedent `main.rs`'s own boot sequence establishes.
    oxidebsd::cpu::hpet::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

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

    // Real `AF_INET` networking itself is out of this pilot's own scope (no socket-shaped
    // interface is in `POSIX_TEST_PILOT_FILES`) -- loaded purely so `SYS_SOCKET` is a genuinely
    // *registered* syscall rather than falling through to the generic "unrecognized syscall
    // number" ENOSYS path. Found live: `sched_setparam/26-1.c`'s own privilege-drop
    // (`su user -c ...`, see `modules/oxfs/src/posix_conformance.sh`) calls real `initgroups()`,
    // which probes a real `AF_UNIX` socket to a local `nscd` daemon first (`third_party/musl/src/
    // passwd/nscd_query.c`) and only falls back to parsing `/etc/group` for real when that
    // `socket()` call fails with exactly `EAFNOSUPPORT` -- an unregistered syscall's generic
    // `ENOSYS` doesn't qualify, so `su` died with a real "can't set groups: Function not
    // implemented" before ever reaching `initgroups()`'s own real fallback, let alone the test's
    // own assertion. No NIC/hardware dependency to worry about -- `module_init` here just
    // registers syscall handlers; it doesn't touch `rtl8139`/`ethernet` at all (unlike e.g.
    // `tests/udp_syscall_smoke.rs`, which genuinely needs a working NIC and checks for one).
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

    const DRIVER_ELF: &[u8] = include_bytes!(env!("POSIX_CONFORMANCE_DRIVER_ELF_PATH"));
    serial_println!(
        "posix_conformance_smoke: spawning posix-conformance-driver as pid 1 ({} byte ELF)",
        DRIVER_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(DRIVER_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn posix-conformance-driver: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
