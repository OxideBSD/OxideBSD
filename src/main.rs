#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(oxidebsd::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::serial_println;

oxidebsd::limine_entry_point!(kernel_main);

#[cfg(test)]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    serial_println!("OxideBSD kernel booting...");

    oxidebsd::init(boot_info);
    test_main();

    serial_println!("OxideBSD kernel is up, entering idle loop");

    oxidebsd::hlt_loop();
}

/// Non-test builds boot, load the kernel modules that populate the native syscall ABI's dispatch
/// table and filesystem support, spawn the first real process (`stsh`, pid 1), and hand off to the
/// scheduler — see `oxidebsd::process::spawn` and `oxidebsd::scheduler::start` for why this never
/// returns here (the same one-way shape `usermode::jump_to_usermode` always had, just reached
/// through the scheduler's own first-run trampoline now instead of a direct call).
///
/// `stsh` (see `userland/stsh/`) is a genuinely interactive shell over OxideBSD's own native,
/// BSD-style `SYSCALL`/`SYSRETQ` ABI (`src/syscall.rs`), and — now that `fork`/`execve`/`wait4` are
/// real — can `fork`+`execve`+`wait` other programs instead of only running shell built-ins.
/// `ring3-smoke` (`userland/ring3-smoke/`) isn't spawned directly at boot; it's instead embedded
/// into the FAT32 image (see `build.rs`) so `stsh` can `execve` it as a real file.
///
/// Before that, loads the `hello` kernel module (`modules/hello/`) via `oxidebsd::module::load`
/// — see `CLAUDE.md`'s module-loading section. This is the first, deliberately minimal proof that
/// dynamic module loading works end to end; later modules (the native syscall ABI, FAT32) load
/// the same way.
#[cfg(not(test))]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    serial_println!("OxideBSD kernel booting...");

    // A small, harmless easter egg -- real CMOS RTC read (`cpu::rtc::current_month`), safe this
    // early (raw port I/O only, no heap/paging/interrupt dependency yet, same reasoning
    // `unix_epoch_seconds` already establishes). Zero effect on anything real POSIX conformance
    // cares about.
    if oxidebsd::cpu::rtc::current_month() == 6 {
        serial_println!("Happy Pride Month!");
    }

    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    // Phase 1 of networking (see this repo's networking plan): probes for and brings up a real
    // NIC, if one is present, before any module loads. Not fatal either way -- logged, boot
    // continues regardless of whether a supported device was found. No protocol stack, no
    // syscalls, no `modules/net` yet -- just raw Ethernet frame TX/RX, IRQ-driven.
    oxidebsd::net::rtl8139::init(&mut frame_allocator, physical_memory_offset);

    // A real xHCI USB host controller + HID boot-protocol keyboard, if either is present -- this
    // kernel's only input path on hardware with no PS/2 controller (a Surface Pro; see
    // `oxidebsd::drivers::usb`'s own module doc comment). Not fatal either way, same "logged,
    // boot continues regardless" precedent as `rtl8139::init` just above. Before module loading so
    // a USB keyboard is live before `hush` is spawned.
    oxidebsd::drivers::usb::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    // A real ACPI HPET, if present -- a second, high-resolution *duration* clock layered on top
    // of the 100Hz PIT scheduler tick (unchanged), used only for real sub-tick `clock_getres`
    // resolution reporting and real POSIX interval-timer overrun accounting. See
    // `oxidebsd::cpu::hpet`'s own module doc comment for the full design (deliberately never an
    // interrupt source). Not fatal either way, same precedent as `usb::init` just above.
    oxidebsd::cpu::hpet::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    const HELLO_MOD: &[u8] = include_bytes!(env!("HELLO_MOD_PATH"));
    const HELLO_PANIC_SYMBOL: &str = env!("HELLO_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "hello",
        HELLO_MOD,
        HELLO_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the hello module: {e:?}"));

    // Populates src/syscall.rs's dispatch table (SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/
    // SYS_EXECVE/SYS_GETPID) -- must load before stsh, below, is spawned, since stsh's syscalls
    // resolve through that table.
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

    // The home for whatever POSIX/libc-surface syscalls BusyBox's applets need beyond what
    // native_abi/fat32 already provide -- see CLAUDE.md's BusyBox section and
    // modules/posix_compat/src/lib.rs's own doc comment. Empty (registers nothing) at this point;
    // must still load before stsh is spawned, same as native_abi, since anything it later
    // registers needs to be in place before a program calling it can run.
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

    // Registers SYS_KILL/SYS_SIGACTION/SYS_SIGPROCMASK -- real process signaling. See
    // modules/signal/src/lib.rs's own doc comment; must load before hush, below, is spawned, same
    // as every other syscall-registering module.
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

    // Registers SYS_CLOCK_GETTIME -- CLOCK_REALTIME/CLOCK_MONOTONIC reads. See
    // modules/clock/src/lib.rs's own doc comment; must load before hush, below, is spawned, same
    // as every other syscall-registering module.
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

    // Probes for a real ATA disk (see src/ata.rs's own doc comment) before oxfs loads, below --
    // oxfs's module_init needs to know whether a data disk is attached to decide between its
    // mount-existing-disk and format-fresh-disk/pure-in-memory paths. Never fatal: absence just
    // means oxfs falls back to its original 100%-in-memory behavior for this boot.
    //
    // Skipped entirely when booted with `no-ata` on the Limine command line -- see
    // `oxidebsd::boot::ata_disabled`'s own doc comment for why this exists (a real safety gate
    // for a first real-hardware boot attempt, not something this project's own QEMU workflow
    // needs). Skipping the probe forces oxfs into its always-safe in-memory fallback below.
    if oxidebsd::boot::ata_disabled() {
        serial_println!("[boot] no-ata on kernel command line: skipping ATA disk probe");
    } else {
        oxidebsd::drivers::ata::init();
    }

    // The live filesystem (see CLAUDE.md's oxfs section) -- modules/fat32 is kept in the workspace
    // (still built and self-checked by build.rs on every `cargo build`) but deliberately not
    // loaded here anymore.
    //
    // `fatal_on_panic = true`: unlike every other module here, a filesystem module's state *is*
    // the entire in-memory filesystem (plus, now, whatever's mid-flight to its real backing disk
    // when a data disk is attached -- see src/ata.rs and this module's own on-disk persistence
    // logic). There's no way to safely resume past a panic in either case: with no disk, "restart
    // the module and keep going" would silently revert every file to empty; with one attached, a
    // panic mid-mount or mid-format risks leaving a torn superblock/inode-table write behind,
    // which is worse to resume past than a purely in-memory panic ever was. So a panic anywhere in
    // oxfs reboots the whole system instead (see `module_panic_trampoline` in `src/module.rs`).
    // The same reasoning will apply to fat32/ext4/xfs/... once any of them load at boot again.
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

    // Registers SYS_SOCKET/SYS_BIND/SYS_SENDTO/SYS_RECVFROM/SYS_SETSOCKOPT -- UDP sockets (see
    // CLAUDE.md's networking plan; src/net/udp.rs holds the real logic, this module is just the
    // usual thin syscall-registration shim). Must load before hush, below, is spawned, same as
    // every other syscall-registering module.
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

    // Modules are loaded; nothing else needs `frame_allocator`/`physical_memory_offset` as local
    // values from here on -- hand them over to memory's global state (moving frame_allocator by
    // value, not cloning it: BootInfoFrameAllocator's own bump-allocation state must stay singular,
    // never tracked in two places at once) so process::spawn/do_fork_from_current/do_execve can
    // reach them from arbitrary syscall contexts via memory::with_frame_allocator/phys_mem_offset.
    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);

    // Registers fd 0/1/2 as real crate::fd entries (see that module's own doc comment for why
    // stdin/stdout/stderr moved out of being special-cased directly in sys_read/sys_write) --
    // must happen before any process (starting with pid 1 below) can issue its first read/write.
    oxidebsd::fs::fd::init();

    // BusyBox's `hush` (see CLAUDE.md's BusyBox/oxfs sections) replaces `stsh` as pid 1 -- a real
    // shell over a real filesystem, not a purpose-built demo. `stsh` (`userland/stsh/`) stays in
    // the workspace, still built by build.rs, but is no longer spawned here; unlike
    // `modules/fat32`, it isn't even embedded into oxfs's filesystem (nothing execve's it, so
    // there's no reason to). `hush` prints no prompt of its own (`CONFIG_HUSH_INTERACTIVE` is off
    // -- see CLAUDE.md's BusyBox section) -- it silently blocks reading the first line, which is
    // correct, not stuck (confirmed via QEMU + injected keystrokes: ordinary commands, `cd`/`pwd`,
    // and piping all work).
    const HUSH_ELF: &[u8] = include_bytes!(env!("HUSH_ELF_PATH"));
    serial_println!(
        "[boot] spawning hush (BusyBox sh) as pid 1 ({} byte ELF)",
        HUSH_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(HUSH_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn hush: {e:?}"));

    oxidebsd::process::scheduler::start(pid1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    oxidebsd::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
