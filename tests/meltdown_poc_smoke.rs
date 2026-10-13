//! Boots the kernel and spawns `regress/meltdown-poc/` as pid 1: ring-3 reads of kernel addresses
//! fault, and the kernel confirms those addresses are absent from the process's user table (KPTI).
//! Reports SKIP when KPTI is off. Same `SYS_TEST_EXIT` convention as `tests/trap_syscall_smoke.rs`.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/meltdown-poc/src/main.rs`.
const SYS_KPTI_PROBE: u64 = 9996;
const SYS_TEST_EXIT: u64 = 9999;

/// Runs the structural KPTI probe and exits the test with its verdict. SKIP when KPTI is off.
extern "C" fn kpti_probe_handler(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    if !oxidebsd::cpu::pti::enabled() {
        serial_println!("meltdown_poc_smoke: SKIP (KPTI off: CPU not vulnerable, or pti=off)");
        exit_qemu(QemuExitCode::Success);
        oxidebsd::hlt_loop();
    }
    match oxidebsd::cpu::pti::poc_probe() {
        Ok(hidden) => {
            serial_println!(
                "meltdown_poc_smoke: PASS ({} kernel addresses present in the kernel table are \
                 absent from the user table)",
                hidden
            );
            exit_qemu(QemuExitCode::Success);
        }
        Err(what) => {
            serial_println!("meltdown_poc_smoke: FAIL: {} is reachable from the user table", what);
            exit_qemu(QemuExitCode::Failed);
        }
    }
    oxidebsd::hlt_loop();
}

/// Only reached if the probe handler didn't exit first (the child reporting a behavioural failure).
extern "C" fn test_exit_handler(code: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    serial_println!(
        "meltdown_poc_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 { QemuExitCode::Success } else { QemuExitCode::Failed });
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

    // Signal delivery for the forked children that fault.
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

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_KPTI_PROBE, kpti_probe_handler),
        0,
        "SYS_KPTI_PROBE registration failed"
    );
    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed"
    );

    const MELTDOWN_POC_ELF: &[u8] = include_bytes!(env!("MELTDOWN_POC_ELF_PATH"));
    serial_println!(
        "meltdown_poc_smoke: spawning meltdown-poc as pid 1 ({} byte ELF)",
        MELTDOWN_POC_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(MELTDOWN_POC_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn meltdown-poc: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
