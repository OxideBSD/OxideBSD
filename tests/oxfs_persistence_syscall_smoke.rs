//! Boots the full kernel with `src/ata.rs`'s data disk attached (`Cargo.toml`'s `test-args` point
//! this test at `target/oxfs_test_disk.img`, always freshly zeroed by `build.rs` -- so `oxfs`'s
//! `module_init` takes the format-then-flush path, not mount), loads `native_abi` + `oxfs`, then
//! spawns `regress/oxfs-persistence-syscall-smoke/` as pid 1 -- see that crate's own module doc
//! comment for the full scenario (create+write+close through the real write-through persistence
//! path, then a read-back).
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

/// Must match `regress/oxfs-persistence-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT`
/// constant -- no shared crate across this ABI boundary, same convention every other userland/
/// kernel pair here uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "oxfs_persistence_syscall_smoke: child reported {}",
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

    // Must run before oxfs loads, below: its module_init mounts the system image on the data disk
    // this probe finds (`drivers::disk`: virtio-blk, or the IDE disk).
    oxidebsd::drivers::disk::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID -- must load
    // before oxfs-persistence-syscall-smoke, below, is spawned.
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
    // close, lseek, fstat, ioctl, ftruncate, fsync, fdatasync (VFS.md §6.4).
    const VFS_MOD: &[u8] = include_bytes!(env!("VFS_MOD_PATH"));
    const VFS_PANIC_SYMBOL: &str = env!("VFS_MOD_PANIC_SYMBOL");
    oxidebsd::module::load("vfs", VFS_MOD, VFS_PANIC_SYMBOL, false, &mut mapper, &mut frame_allocator)
        .unwrap_or_else(|e| panic!("failed to load the vfs module: {e:?}"));

    // vfork(2) (COW.md §7), as at boot: BusyBox's spawn() and musl's vfork() call it.
    const VFORK_MOD: &[u8] = include_bytes!(env!("VFORK_MOD_PATH"));
    const VFORK_PANIC_SYMBOL: &str = env!("VFORK_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "vfork",
        VFORK_MOD,
        VFORK_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the vfork module: {e:?}"));

    // The file system modules, as at boot: oxfs mounts the system image, then procfs and tmpfs.
    oxidebsd::kernel_main::load_file_systems(&mut mapper, &mut frame_allocator);

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const OXFS_PERSISTENCE_SYSCALL_SMOKE_ELF: &[u8] =
        include_bytes!(env!("OXFS_PERSISTENCE_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "oxfs_persistence_syscall_smoke: spawning oxfs-persistence-syscall-smoke as pid 1 ({} byte ELF)",
        OXFS_PERSISTENCE_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(OXFS_PERSISTENCE_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn oxfs-persistence-syscall-smoke: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
