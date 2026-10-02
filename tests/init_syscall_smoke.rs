//! `/sbin/init`'s states, ttys sessions and signals (INIT.md §§3, 5, 6): starts
//! `regress/std/init-smoke/` as pid 1, which sets up a test `/etc/ttys` and `/etc/rc` and execs
//! the real `/sbin/init`; see that program's doc comment for the sequence. Takes about a minute:
//! one step waits out init's 30-second restart pause. The last step kills init, so pid 1 is
//! supervised as on a real boot.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Must match `regress/std/init-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "init_syscall_smoke: child reported {}",
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

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID/SYS_CLONE/
    // SYS_MMAP/SYS_MUNMAP/SYS_BRK/SYS_MPROTECT/SYS_SET_FS_BASE/SYS_SET_TID_ADDRESS -- must load
    // before init-smoke, below, is spawned.
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

    // Registers SYS_POLL/SYS_SELECT, which a shell's children (BusyBox tools) may probe.
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

    // Registers SYS_SYSCTL: the last step kills init through debug.kill_init.
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

    // The kernel's supervision of pid 1 (INIT.md §9), as the real boot arms it: the last step
    // kills init through debug.kill_init, and the kernel restarts the real /sbin/init with -R.
    const INIT_ELF: &[u8] = include_bytes!(env!("OXFS_INIT_ELF_PATH"));
    const EMERGENCY_ELF: &[u8] = include_bytes!(env!("OXFS_EMERGENCY_ELF_PATH"));
    oxidebsd::process::init::register(
        oxidebsd::process::init::InitProgram {
            elf: INIT_ELF,
            argv: &[b"/sbin/init"],
            restart_argv: &[b"/sbin/init", b"-R"],
            envp: &[],
            console: false,
        },
        oxidebsd::process::init::InitProgram {
            elf: EMERGENCY_ELF,
            argv: &[b"/sbin/emergency"],
            restart_argv: &[b"/sbin/emergency"],
            envp: &[],
            console: true,
        },
    );
    const SMOKE_ELF: &[u8] = include_bytes!(env!("OXFS_INIT_SMOKE_ELF_PATH"));
    serial_println!("init_syscall_smoke: spawning init-smoke as pid 1 ({} byte ELF)", SMOKE_ELF.len());
    // Without a controlling terminal, as the real boot starts /sbin/init (kernel_main): a session
    // leader can't drop one, and init's children have to be able to take the console.
    let pid1 = oxidebsd::process::lifecycle::spawn_boot(SMOKE_ELF, None, &[b"init-smoke", b"pid1"], &[], false)
        .unwrap_or_else(|e| panic!("failed to spawn init-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
