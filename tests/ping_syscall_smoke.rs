//! Real-`SYSCALL` counterpart to `tests/ping_smoke.rs` -- see CLAUDE.md's "Real networking"
//! section for the blind spot this closes: every existing network smoke test calls kernel
//! handlers as plain Rust functions from its own `main()`, never through a genuine `SYSCALL` with
//! interrupts actually masked the way a real syscall runs. This test instead spawns
//! `regress/ping-syscall-smoke/` as pid 1 and lets it drive `socket`/`sendto`/`recvfrom` entirely
//! through real `SYSCALL`/`SYSRETQ` against QEMU SLIRP's real self-answering gateway.
//!
//! No test-only "advance a synthetic peer" syscall is needed here (unlike the UDP/TCP/poll
//! conversions) -- SLIRP genuinely replies over the real (virtual) wire.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::net::rtl8139;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/ping-syscall-smoke/src/main.rs`'s own constant.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "ping_syscall_smoke: child reported {}",
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

    rtl8139::init(&mut frame_allocator, physical_memory_offset);
    if oxidebsd::net::nic::NIC.lock().is_none() {
        serial_println!(
            "ping_syscall_smoke: no NIC installed -- is -device rtl8139 passed to QEMU?"
        );
        exit_qemu(QemuExitCode::Failed);
        oxidebsd::hlt_loop();
    }

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

    const PING_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("PING_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "ping_syscall_smoke: spawning ping-syscall-smoke as pid 1 ({} byte ELF)",
        PING_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(PING_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn ping-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
