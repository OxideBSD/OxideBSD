//! `init=` and `init_path=` (INIT.md §4.1): with them on the command line, the kernel runs its
//! embedded `start_init` as pid 1, which must skip `init=`'s missing program and exec
//! `init_path=`'s, `regress/std/init-smoke/` (`started_by_start_init`), keeping pid 1. That kills
//! itself through `debug.kill_init`, and the kernel's restart must take the same way, without
//! `-R`.
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
        "init_path_smoke: child reported {}",
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
    // init= and init_path= name pid 1's program (INIT.md §4.1): the first doesn't exist.
    oxidebsd::boot::apply_cmdline("-D init=/nonexistent/init init_path=/usr/tests/init/init-smoke");
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

    const INIT_ELF: &[u8] = include_bytes!(env!("OXFS_INIT_ELF_PATH"));
    const START_INIT_ELF: &[u8] = include_bytes!(env!("START_INIT_ELF_PATH"));
    const EMERGENCY_ELF: &[u8] = include_bytes!(env!("OXFS_EMERGENCY_ELF_PATH"));
    let init = oxidebsd::process::init::pid1_program(INIT_ELF, START_INIT_ELF);
    assert!(init.elf.as_ptr() == START_INIT_ELF.as_ptr(), "init_path= didn't select start_init");
    oxidebsd::process::init::register(
        init,
        oxidebsd::process::init::InitProgram {
            elf: EMERGENCY_ELF,
            argv: &[b"/sbin/emergency"],
            restart_argv: &[b"/sbin/emergency"],
            envp: &[],
            console: true,
        },
    );
    serial_println!("init_path_smoke: spawning start_init as pid 1");
    let pid1 = oxidebsd::process::lifecycle::spawn_boot(init.elf, None, init.argv, init.envp, false)
        .unwrap_or_else(|e| panic!("failed to spawn start_init: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
