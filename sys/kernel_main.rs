//! The real system boot sequence -- loads every kernel module that populates the native syscall
//! ABI's dispatch table and filesystem support, spawns the first real process (BusyBox's `hush`,
//! pid 1), and hands off to the scheduler. Lives in the library (not `sys/main.rs`) so **every**
//! boot-path entry point can call the exact same code, not just the Limine one: `sys/main.rs`'s
//! `kernel_main` (Limine) and the Multiboot2 path's own dedicated entry crate
//! (`regress/multiboot2-kernel/`, see CLAUDE.md's Multiboot2 section) both just call
//! [`run_real_system`] directly with whatever `&'static BootInfo` their own entry macro produced.
//!
//! **Why this can't just live in `sys/main.rs` and be reused via a second `[[bin]]`-style crate
//! pointed at that same source file** (the same trick `regress/multiboot2-boot-smoke` uses for its
//! own, much smaller, trampoline-only smoke test): every module/`hush` ELF embedded below via
//! `include_bytes!(env!("..._PATH"))` needs an `OXIDEBSD_MANIFEST_DIR`-package-scoped
//! `cargo:rustc-env` variable this crate's own `build.rs` sets -- and `rustc-env` variables are
//! visible only while compiling the *package that set them*, never propagated to a downstream
//! dependent's own compilation (confirmed directly: a separate crate's `env!()` call for a
//! variable emitted by a path-dependency's `build.rs` fails to compile at all, "environment
//! variable not defined at compile time"). Putting this function inside the `oxidebsd` library
//! itself means any crate that depends on `oxidebsd` and calls [`run_real_system`] gets a fully
//! resolved function, since the `env!()` calls were already resolved *when this library itself was
//! compiled* -- not when some downstream caller was.

use x86_64::VirtAddr;

use crate::boot::BootInfo;
use crate::serial_println;

/// Non-test builds boot, load the kernel modules that populate the native syscall ABI's dispatch
/// table and filesystem support, spawn the first real process (BusyBox's `hush`, pid 1), and hand
/// off to the scheduler — see `process::spawn` and `process::scheduler::start` for why this never
/// returns (the same one-way shape `usermode::jump_to_usermode` always had, just reached through
/// the scheduler's own first-run trampoline now instead of a direct call).
///
/// `hush` runs over OxideBSD's own native, BSD-style `SYSCALL`/`SYSRETQ` ABI (`sys/syscall/`),
/// with real `fork`/`execve`/`wait4` to run BusyBox's other applets and any other ELF on the real
/// filesystem (`oxfs`, see `CLAUDE.md`'s oxfs/BusyBox sections) — not just shell built-ins.
///
/// Before that, loads the `hello` kernel module (`sys/modules/hello/`) via `module::load` — see
/// `CLAUDE.md`'s module-loading section. This is the first, deliberately minimal proof that
/// dynamic module loading works end to end; later modules (the native syscall ABI, oxfs, ...) load
/// the same way.
pub fn run_real_system(boot_info: &'static BootInfo) -> ! {
    serial_println!("OxideBSD kernel booting...");

    // Small, harmless easter eggs -- real CMOS RTC read (`cpu::rtc::current_month`), safe this
    // early (raw port I/O only, no heap/paging/interrupt dependency yet, same reasoning
    // `unix_epoch_seconds` already establishes). Zero effect on anything real POSIX conformance
    // cares about.
    match crate::cpu::rtc::current_month() {
        6 => {
            serial_println!("Happy Pride Month!");
        }
        10 => {
            serial_println!("It is the spooky month!");
        }
        _ => {}
    }

    let (mut mapper, mut frame_allocator) = crate::init(boot_info);
    let physical_memory_offset = VirtAddr::new(boot_info.physical_memory_offset);

    // Phase 1 of networking (see this repo's networking plan): probes for and brings up a real
    // NIC, if one is present, before any module loads. Not fatal either way -- logged, boot
    // continues regardless of whether a supported device was found. No protocol stack, no
    // syscalls, no `sys/modules/socket` yet -- just raw Ethernet frame TX/RX, IRQ-driven.
    crate::drivers::rtl8139::init(&mut frame_allocator, physical_memory_offset);
    // A real system's rl0 has no address until `rc.d/netif` gives it one (`ifconfig_rl0` in
    // rc.conf, or DHCP); only a test kernel starts with QEMU's.
    crate::net::ifnet::unconfigure();

    // A real xHCI USB host controller + HID boot-protocol keyboard, if either is present -- this
    // kernel's only input path on hardware with no PS/2 controller (a Surface Pro; see
    // `drivers::usb`'s own module doc comment). Not fatal either way, same "logged, boot continues
    // regardless" precedent as `rtl8139::init` just above. Before module loading so a USB keyboard
    // is live before `hush` is spawned.
    crate::drivers::usb::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    // A real ACPI HPET, if present -- a second, high-resolution *duration* clock layered on top
    // of the 100Hz PIT scheduler tick (unchanged), used only for real sub-tick `clock_getres`
    // resolution reporting and real POSIX interval-timer overrun accounting. See `cpu::hpet`'s own
    // module doc comment for the full design (deliberately never an interrupt source). Not fatal
    // either way, same precedent as `usb::init` just above.
    crate::cpu::hpet::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    // What powering off needs (the FADT's PM1 control ports, the DSDT's \_S5 sleep type), found
    // once now and used by `reboot::poweroff`. Not fatal either way, like the probes above.
    crate::acpi::init(physical_memory_offset.as_u64());

    // Populates sys/syscall.rs's dispatch table (SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/
    // SYS_EXECVE/SYS_GETPID) -- must load before pid 1, below, is spawned, since its syscalls
    // resolve through that table.
    const NATIVE_ABI_MOD: &[u8] = include_bytes!(env!("NATIVE_ABI_MOD_PATH"));
    const NATIVE_ABI_PANIC_SYMBOL: &str = env!("NATIVE_ABI_MOD_PANIC_SYMBOL");
    crate::module::load(
        "native_abi",
        NATIVE_ABI_MOD,
        NATIVE_ABI_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the native_abi module: {e:?}"));
    // close, lseek, fstat, ioctl, ftruncate, fsync, fdatasync (VFS.md §6.4).
    const VFS_MOD: &[u8] = include_bytes!(env!("VFS_MOD_PATH"));
    const VFS_PANIC_SYMBOL: &str = env!("VFS_MOD_PANIC_SYMBOL");
    crate::module::load("vfs", VFS_MOD, VFS_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the vfs module: {e:?}"));

    // The home for whatever POSIX/libc-surface syscalls BusyBox's applets need beyond what
    // native_abi already provides -- see CLAUDE.md's BusyBox section and
    // sys/modules/posix_compat/src/lib.rs's own doc comment. Must load before pid 1 is spawned, same
    // as native_abi, since anything it registers needs to be in place before a program calling it
    // can run.
    const POSIX_COMPAT_MOD: &[u8] = include_bytes!(env!("POSIX_COMPAT_MOD_PATH"));
    const POSIX_COMPAT_PANIC_SYMBOL: &str = env!("POSIX_COMPAT_MOD_PANIC_SYMBOL");
    crate::module::load(
        "posix_compat",
        POSIX_COMPAT_MOD,
        POSIX_COMPAT_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the posix_compat module: {e:?}"));

    // Registers SYS_KILL/SYS_SIGACTION/SYS_SIGPROCMASK -- real process signaling. See
    // sys/modules/signal/src/lib.rs's own doc comment; must load before hush, below, is spawned, same
    // as every other syscall-registering module.
    const SIGNAL_MOD: &[u8] = include_bytes!(env!("SIGNAL_MOD_PATH"));
    const SIGNAL_PANIC_SYMBOL: &str = env!("SIGNAL_MOD_PANIC_SYMBOL");
    crate::module::load(
        "signal",
        SIGNAL_MOD,
        SIGNAL_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the signal module: {e:?}"));

    // Registers SYS_CLOCK_GETTIME -- CLOCK_REALTIME/CLOCK_MONOTONIC reads. See
    // sys/modules/clock/src/lib.rs's own doc comment; must load before hush, below, is spawned, same
    // as every other syscall-registering module.
    const CLOCK_MOD: &[u8] = include_bytes!(env!("CLOCK_MOD_PATH"));
    const CLOCK_PANIC_SYMBOL: &str = env!("CLOCK_MOD_PANIC_SYMBOL");
    crate::module::load(
        "clock",
        CLOCK_MOD,
        CLOCK_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the clock module: {e:?}"));

    // Registers every disk (`drivers::disk`: virtio-blk, then IDE by DMA or PIO) and picks the
    // root before oxfs loads, below -- its module_init mounts it, or, with none, the memory disk.
    //
    // Skipped entirely with `no-ata`/`no-disk` on the kernel command line: a safety gate for
    // real hardware, where oxfs would format whatever disk it found (`boot::ata_disabled`).
    if crate::boot::ata_disabled() {
        serial_println!("[boot] no-ata on kernel command line: skipping the data disk probe");
        if !(crate::boot::mfsroot() && crate::drivers::disk::init_mfsroot(physical_memory_offset)) {
            crate::drivers::disk::init_memory(physical_memory_offset);
        }
    } else {
        crate::drivers::disk::init(&mut frame_allocator, &mut mapper, physical_memory_offset);
    }
    // The root file system is mounted read-only; /etc/rc checks it and remounts it read-write
    // (rc.d/root), as on the BSDs (OxideBSD-doc RAM_FLOOR.md §3.4.3). Test kernels, which start
    // their own pid 1, keep it read-write.
    crate::drivers::disk::set_root_readonly_at_boot();

    load_file_systems();
    let (transfers, irqs) = crate::drivers::disk::stats();
    serial_println!("[boot] disk: {} transfers so far, {} completion interrupts", transfers, irqs);

    // Registers SYS_SOCKET/SYS_BIND/SYS_SENDTO/SYS_RECVFROM/SYS_SETSOCKOPT -- UDP sockets (see
    // CLAUDE.md's networking plan; sys/netinet/udp.rs holds the real logic, this module is just the
    // usual thin syscall-registration shim). Must load before hush, below, is spawned, same as
    // every other syscall-registering module.
    const SOCKET_MOD: &[u8] = include_bytes!(env!("SOCKET_MOD_PATH"));
    const SOCKET_PANIC_SYMBOL: &str = env!("SOCKET_MOD_PANIC_SYMBOL");
    crate::module::load(
        "socket",
        SOCKET_MOD,
        SOCKET_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the socket module: {e:?}"));

    // Registers sysctl(2) (SYSCTL.md); the tree is kern::kern_sysctl.
    const SYSCTL_MOD: &[u8] = include_bytes!(env!("SYSCTL_MOD_PATH"));
    const SYSCTL_PANIC_SYMBOL: &str = env!("SYSCTL_MOD_PANIC_SYMBOL");
    crate::module::load(
        "sysctl",
        SYSCTL_MOD,
        SYSCTL_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the sysctl module: {e:?}"));

    // Registers procctl(2) (COW.md §6.3); the commands are kern::kern_procctl.
    const PROCCTL_MOD: &[u8] = include_bytes!(env!("PROCCTL_MOD_PATH"));
    const PROCCTL_PANIC_SYMBOL: &str = env!("PROCCTL_MOD_PANIC_SYMBOL");
    crate::module::load(
        "procctl",
        PROCCTL_MOD,
        PROCCTL_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the procctl module: {e:?}"));

    // Registers vfork(2) (COW.md §7); the work is process::do_vfork.
    const VFORK_MOD: &[u8] = include_bytes!(env!("VFORK_MOD_PATH"));
    const VFORK_PANIC_SYMBOL: &str = env!("VFORK_MOD_PANIC_SYMBOL");
    crate::module::load(
        "vfork",
        VFORK_MOD,
        VFORK_PANIC_SYMBOL,
        false,
    )
    .unwrap_or_else(|e| panic!("failed to load the vfork module: {e:?}"));

    crate::memory::wx::check_kernel(&mapper, "modules loaded");


    // Registers fd 0/1/2 as real crate::fd entries (see that module's own doc comment for why
    // stdin/stdout/stderr moved out of being special-cased directly in sys_read/sys_write) --
    // must happen before any process (starting with pid 1 below) can issue its first read/write.
    crate::fs::fd::init();

    // The loader's memory (UEFI boot services, Limine's own data): 40 MB of a 64 MB UEFI
    // machine. Every boot response the kernel keeps is copied first; Limine's page tables, which
    // the kernel runs on, and this stack stay.
    crate::boot::snapshot();
    crate::memory::reclaim_bootloader_memory();

    // pid 1 is `/sbin/init` (INIT.md), read from the root file system as FreeBSD's start_init
    // does -- nothing userland is embedded in the kernel (RAM_FLOOR.md §4.6.3) -- started with the
    // boot flags (§4.1) and an empty environment (§4.2), and without a controlling terminal: its
    // children take the console. `init=`/`init_path=` name other programs, tried in order. A
    // restart after a death gets `-R` (§9.3); repeated deaths start `/sbin/emergency` (§9.4). If
    // nothing can be started, `/bin/sh` runs on the console instead; failing that, there is no
    // system to run.
    crate::process::init::arm(crate::process::init::boot_init(), crate::process::init::boot_emergency());
    let pid1 = crate::process::init::start_pid1()
        .unwrap_or_else(|| panic!("no init found: nothing in init_path, nor /bin/sh, could be started"));

    crate::process::scheduler::start(pid1)
}

/// Loads the file system modules (OxideBSD-doc `VFS.md`), in the order they must come: oxfs, whose
/// type mounts the root as it registers, then the types the kernel mounts on the root's
/// directories (devfs on `/dev`, procfs on `/proc`) and the ones `/etc/fstab` and `mount(8)` name
/// (tmpfs, nullfs). The data
/// disk must be attached first (`drivers::disk::init`). Test kernels call it too, so each loads
/// the same set.
pub fn load_file_systems() {
    // The live filesystem (see CLAUDE.md's oxfs section) -- replaced the earlier FAT32 module,
    // since removed (superseded, no longer buildable or loaded).
    //
    // `fatal_on_panic = true`: unlike every other module here, a filesystem module's state *is*
    // the entire in-memory filesystem (plus, now, whatever's mid-flight to its real backing disk
    // when a data disk is attached -- see src/ata.rs and this module's own on-disk persistence
    // logic). There's no way to safely resume past a panic in either case: with no disk, "restart
    // the module and keep going" would silently revert every file to empty; with one attached, a
    // panic mid-mount or mid-format risks leaving a torn superblock/inode-table write behind,
    // which is worse to resume past than a purely in-memory panic ever was. So a panic anywhere in
    // oxfs reboots the whole system instead (see `module_panic_trampoline` in `sys/module.rs`).
    // The same reasoning will apply to ext4/xfs/... should any real disk filesystem load at boot.
    const OXFS_MOD: &[u8] = include_bytes!(env!("OXFS_MOD_PATH"));
    const OXFS_PANIC_SYMBOL: &str = env!("OXFS_MOD_PANIC_SYMBOL");
    crate::module::load(
        "oxfs",
        OXFS_MOD,
        OXFS_PANIC_SYMBOL,
        true,
    )
    .unwrap_or_else(|e| panic!("failed to load the oxfs module: {e:?}"));

    // /proc (OxideBSD-doc VFS.md §8.3): mounted on /proc as soon as it registers.
    const PROCFS_MOD: &[u8] = include_bytes!(env!("PROCFS_MOD_PATH"));
    const PROCFS_PANIC_SYMBOL: &str = env!("PROCFS_MOD_PANIC_SYMBOL");
    crate::module::load("procfs", PROCFS_MOD, PROCFS_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the procfs module: {e:?}"));

    // devfs (OxideBSD-doc DEVFS.md): mounted on /dev as soon as it registers.
    const DEVFS_MOD: &[u8] = include_bytes!(env!("DEVFS_MOD_PATH"));
    const DEVFS_PANIC_SYMBOL: &str = env!("DEVFS_MOD_PANIC_SYMBOL");
    crate::module::load("devfs", DEVFS_MOD, DEVFS_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the devfs module: {e:?}"));

    const TMPFS_MOD: &[u8] = include_bytes!(env!("TMPFS_MOD_PATH"));
    const TMPFS_PANIC_SYMBOL: &str = env!("TMPFS_MOD_PANIC_SYMBOL");
    crate::module::load("tmpfs", TMPFS_MOD, TMPFS_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the tmpfs module: {e:?}"));

    const NULLFS_MOD: &[u8] = include_bytes!(env!("NULLFS_MOD_PATH"));
    const NULLFS_PANIC_SYMBOL: &str = env!("NULLFS_MOD_PANIC_SYMBOL");
    crate::module::load("nullfs", NULLFS_MOD, NULLFS_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the nullfs module: {e:?}"));

    // FAT (VFS.md §9): the EFI system partition, memory cards. Not fatal on panic: a volume
    // other than the root, which the system runs without.
    const MSDOSFS_MOD: &[u8] = include_bytes!(env!("MSDOSFS_MOD_PATH"));
    const MSDOSFS_PANIC_SYMBOL: &str = env!("MSDOSFS_MOD_PANIC_SYMBOL");
    crate::module::load("msdosfs", MSDOSFS_MOD, MSDOSFS_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the msdosfs module: {e:?}"));

    // ISO 9660 (INSTALLER.md §6): CDs, the install medium. Not fatal on panic either.
    const CD9660_MOD: &[u8] = include_bytes!(env!("CD9660_MOD_PATH"));
    const CD9660_PANIC_SYMBOL: &str = env!("CD9660_MOD_PANIC_SYMBOL");
    crate::module::load("cd9660", CD9660_MOD, CD9660_PANIC_SYMBOL, false)
        .unwrap_or_else(|e| panic!("failed to load the cd9660 module: {e:?}"));
}

/// For test kernels, which run no `/etc/rc`: mounts the tmpfs on `/dev/shm` that `/etc/fstab`
/// mounts on a real system, so `shm_open` and `sem_open` work (`tmpfs(5)`). After
/// `load_file_systems`.
pub fn mount_shm_for_tests() {
    crate::kern::vfs_mount::mount_type_at(b"tmpfs", b"/dev/shm", b"tmpfs", b"mode\x001777\x00")
        .unwrap_or_else(|e| panic!("mounting a tmpfs on /dev/shm failed: {e}"));
}
