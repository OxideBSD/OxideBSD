//! Boots the full kernel, loads `native_abi` (fork/exit/wait4/execve/read/write) and `oxfs`
//! (open/close/stat/getdents -- serving `/pie-aslr-probe.elf`), then spawns
//! `regress/pie-aslr-driver/` as pid 1 -- see that crate's own module doc comment, and
//! `regress/pie-aslr-smoke/src/main.rs`'s, for the full scenario: two real `fork`+`execve` runs of
//! a genuine no-`PT_INTERP` PIE main binary, proving `process::aslr::pick_bias()`'s real per-exec
//! randomization and the `AT_PHDR`/`AT_ENTRY` bias-correctness fix this milestone made.
//!
//! Same `SYS_TEST_EXIT` convention every other real-`SYSCALL` smoke test in this codebase
//! establishes, plus one more test-only syscall this scenario specifically needs:
//! `SYS_TEST_REPORT_U64`, called by the probe binary to report its own computed address back to
//! this file's own accumulator (`REPORTS`/`REPORT_COUNT`, `static mut` -- safe here because every
//! report is strictly sequential: each `execve`d process's own `wait4` in its parent completes
//! before the next report can possibly arrive, so there is never real concurrent access). The
//! final `SYS_TEST_EXIT` call (from the driver, once both runs have fully completed) is what
//! actually evaluates the three accumulated reports and calls `exit_qemu`.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::process::aslr::{PIE_ASLR_BASE, PIE_ASLR_CEILING};
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/pie-aslr-driver/src/main.rs`'s own `SYS_TEST_EXIT` constant.
const SYS_TEST_EXIT: u64 = 9999;
/// Must match `regress/pie-aslr-smoke/src/main.rs`'s own `SYS_TEST_REPORT_U64` constant.
const SYS_TEST_REPORT_U64: u64 = 9996;

const PAGE_SIZE: u64 = 4096;

/// Expected report order: each `execve` of the probe reports its own address once, then
/// unconditionally `fork()`s itself and the child reports the identical value again -- so two
/// full driver-orchestrated runs produce exactly four reports: `[0]` first `execve`'s own address,
/// `[1]` that same run's forked child (must equal `[0]`), `[2]` second `execve`'s own address
/// (must differ from `[0]` -- real randomization), `[3]` that run's forked child (must equal
/// `[2]`).
static mut REPORTS: [u64; 4] = [0; 4];
static mut REPORT_COUNT: usize = 0;

extern "C" fn test_report_handler(value: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    // SAFETY: see this file's own module doc comment -- reports arrive strictly sequentially.
    // Pure raw-pointer read/write throughout -- edition 2024 hard-errors on forming any `&`/`&mut`
    // to a `static mut` (even implicitly, e.g. via indexing or `.len()`), matching this codebase's
    // own `&raw const`/`&raw mut` idiom (see `sys/random.rs`'s `gather_seed`).
    unsafe {
        let count_ptr = &raw mut REPORT_COUNT;
        let idx = *count_ptr;
        if idx < 4 {
            (&raw mut REPORTS as *mut u64).add(idx).write(value);
        }
        *count_ptr = idx + 1;
    }
    serial_println!("pie_aslr_smoke: reported {:#x}", value);
    0
}

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    // SAFETY: see this file's own module doc comment and test_report_handler's.
    let (count, reports) = unsafe {
        let reports_ptr = &raw const REPORTS as *const u64;
        (
            *(&raw const REPORT_COUNT),
            [
                reports_ptr.read(),
                reports_ptr.add(1).read(),
                reports_ptr.add(2).read(),
                reports_ptr.add(3).read(),
            ],
        )
    };

    let driver_ok = code == 0;
    let count_ok = count == 4;
    let first = reports[0];
    let first_child = reports[1];
    let second = reports[2];
    let second_child = reports[3];
    let in_bounds = |a: u64| a >= PIE_ASLR_BASE && a < PIE_ASLR_CEILING;
    let bounds_ok = in_bounds(first) && in_bounds(second);
    // Each reported value is `bias + <_start's fixed, non-page-aligned file offset>` -- only the
    // *bias* itself is page-aligned, not the derived address. Checking the two runs' *difference*
    // is what actually confirms both biases were independently page-aligned, without needing to
    // know that fixed offset here.
    let aligned_ok = second.wrapping_sub(first) % PAGE_SIZE == 0;
    let randomized_ok = first != second;
    let fork_inherits_ok = first == first_child && second == second_child;

    serial_println!(
        "pie_aslr_smoke: driver_ok={} count={} first={:#x} first_child={:#x} second={:#x} second_child={:#x} bounds_ok={} aligned_ok={} randomized_ok={} fork_inherits_ok={}",
        driver_ok,
        count,
        first,
        first_child,
        second,
        second_child,
        bounds_ok,
        aligned_ok,
        randomized_ok,
        fork_inherits_ok
    );

    let pass =
        driver_ok && count_ok && bounds_ok && aligned_ok && randomized_ok && fork_inherits_ok;
    serial_println!(
        "pie_aslr_smoke: {}",
        if pass { "PASS" } else { "FAIL" }
    );
    exit_qemu(if pass {
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
        oxidebsd_register_syscall(SYS_TEST_REPORT_U64, test_report_handler),
        0,
        "SYS_TEST_REPORT_U64 registration failed -- number collided with a real syscall?"
    );
    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const PIE_ASLR_DRIVER_ELF: &[u8] = include_bytes!(env!("PIE_ASLR_DRIVER_ELF_PATH"));
    serial_println!(
        "pie_aslr_smoke: spawning pie-aslr-driver as pid 1 ({} byte ELF)",
        PIE_ASLR_DRIVER_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(PIE_ASLR_DRIVER_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn pie-aslr-driver: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
