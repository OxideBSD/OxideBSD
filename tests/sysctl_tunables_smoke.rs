//! Boot tunables (OxideBSD-doc `SYSCTL.md` §6, §11.3): the same kernel and fixture as
//! `tests/sysctl_syscall_smoke.rs`, booted with `TUNABLES` added to the command line before
//! `init`. The fixture sees `kern.msgbufsize` at 131072 and checks the tunables instead: the
//! buffer's size, `fork` refused past `kern.maxproc`, `ENFILE` past `kern.maxfiles`, and the
//! unknown and out-of-range tokens logged.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/sysctl-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

/// What `regress/sysctl-smoke/main.c`'s `tunables` expects: the last `kern.maxfiles` is out of
/// range, so the first stays. `-D` keeps the console on COM1 as `qemu_runner.sh` asked, since this
/// replaces the flags the real command line set.
const TUNABLES: &str = "-D kern.msgbufsize=131072 kern.maxproc=40 kern.maxfiles=100 kern.bogus=1 kern.maxfiles=5";

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "sysctl_tunables_smoke: child reported {}",
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
    oxidebsd::boot::apply_cmdline(TUNABLES);
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID/SYS_CLONE/
    // SYS_MMAP/SYS_MUNMAP/SYS_BRK/SYS_MPROTECT/SYS_SET_FS_BASE/SYS_SET_TID_ADDRESS -- must load
    // before sysctl-syscall-smoke, below, is spawned.
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

    // Populates SYS_KILL/SYS_SIGACTION/SYS_SIGPROCMASK/SYS_SIGRETURN -- musl's own fork() path
    // blocks and restores signals around the real SYS_FORK.
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

    // Populates fcntl/ioctl/dup and friends -- stdio's isatty() probe and the fixture's fds.
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

    // Populates SYS_CLOCK_GETTIME -- tmpnam()/tmpfile()'s random names are seeded from it.
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

    // poll(2), for /dev/klog's readiness.
    const SOCKET_MOD: &[u8] = include_bytes!(env!("SOCKET_MOD_PATH"));
    const SOCKET_PANIC_SYMBOL: &str = env!("SOCKET_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "socket",
        SOCKET_MOD,
        SOCKET_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the socket module: {e:?}"));

    // sysctl(2) itself.
    const SYSCTL_MOD: &[u8] = include_bytes!(env!("SYSCTL_MOD_PATH"));
    const SYSCTL_PANIC_SYMBOL: &str = env!("SYSCTL_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "sysctl",
        SYSCTL_MOD,
        SYSCTL_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the sysctl module: {e:?}"));

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const SYSCTL_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("SYSCTL_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "sysctl_tunables_smoke: spawning sysctl-syscall-smoke as pid 1 ({} byte ELF)",
        SYSCTL_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(SYSCTL_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn sysctl-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
