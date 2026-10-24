//! Boots the kernel under OVMF, with UEFI's runtime services set up as at boot (`efirt`), and
//! spawns `regress/efirt-syscall-smoke/` as pid 1, which runs `/usr/tests/efirt/run.sh`:
//! `/dev/efi`, `efivar(8)` and the write allow-list (EFIRT.md §8.2).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/efirt-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "efirt_syscall_smoke: child reported {}",
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
    // UEFI's runtime services and /dev/efi, as kernel_main sets them up.
    oxidebsd::efirt::init_and_log();
    assert!(oxidebsd::efirt::available(), "no UEFI runtime services");
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID/SYS_CLONE/
    // SYS_MMAP/SYS_MUNMAP/SYS_BRK/SYS_MPROTECT/SYS_SET_FS_BASE/SYS_SET_TID_ADDRESS -- must load
    // before efirt-syscall-smoke, below, is spawned.
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

    // vfork(2) (COW.md §7), as at boot: BusyBox's spawn() and musl's vfork() call it.
    const VFORK_MOD: &[u8] = include_bytes!(env!("VFORK_MOD_PATH"));
    const VFORK_PANIC_SYMBOL: &str = env!("VFORK_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "vfork",
        VFORK_MOD,
        VFORK_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the vfork module: {e:?}"));

    // Populates SYS_KILL/SYS_SIGACTION/SYS_SIGPROCMASK/SYS_SIGRETURN -- musl's own fork() path
    // blocks and restores signals around the real SYS_FORK.
    const SIGNAL_MOD: &[u8] = include_bytes!(env!("SIGNAL_MOD_PATH"));
    const SIGNAL_PANIC_SYMBOL: &str = env!("SIGNAL_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "signal",
        SIGNAL_MOD,
        SIGNAL_PANIC_SYMBOL,
        false,
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
    )
    .unwrap_or_else(|e| panic!("failed to load the clock module: {e:?}"));

    // The data disk first, as kernel_main does: oxfs mounts the system image on it.
    oxidebsd::drivers::disk::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    // The file system modules, as at boot: oxfs mounts the system image, then procfs and tmpfs.
    oxidebsd::kernel_main::load_file_systems();
    // /dev/shm, which /etc/fstab mounts on a real system (shm_open, sem_open).
    oxidebsd::kernel_main::mount_shm_for_tests();

    // Local sockets (/dev/log) and poll(2), syslogd's loop.
    const SOCKET_MOD: &[u8] = include_bytes!(env!("SOCKET_MOD_PATH"));
    const SOCKET_PANIC_SYMBOL: &str = env!("SOCKET_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "socket",
        SOCKET_MOD,
        SOCKET_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the socket module: {e:?}"));

    // sysctl(2), which the tools the script runs may ask for.
    const SYSCTL_MOD: &[u8] = include_bytes!(env!("SYSCTL_MOD_PATH"));
    const SYSCTL_PANIC_SYMBOL: &str = env!("SYSCTL_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "sysctl",
        SYSCTL_MOD,
        SYSCTL_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the sysctl module: {e:?}"));

    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const EFIRT_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("EFIRT_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "efirt_syscall_smoke: spawning efirt-syscall-smoke as pid 1 ({} byte ELF)",
        EFIRT_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(EFIRT_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn efirt-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
