//! Kernel command-line parsing (`boot::parse_cmdline`) and the argv pid 1 gets (`boot::init_argv`).
//! The last check follows whatever this boot's own command line was, so running this binary with
//! `OXIDEBSD_KERNEL_CMDLINE=-s` exercises the real Limine path end to end.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::{BootFlags, BootInfo, init_argv, parse_cmdline, single_user};
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;

limine_entry_point!(main);

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);

    let none = BootFlags::default();
    let single = BootFlags { single_user: true, ..none };
    assert_eq!(parse_cmdline(""), none);
    assert_eq!(parse_cmdline("-s"), single);
    assert_eq!(parse_cmdline("  no-ata   -s "), BootFlags { no_ata: true, single_user: true });
    assert_eq!(parse_cmdline("-vs"), single, "combined flags");
    assert_eq!(parse_cmdline("-v"), none, "unknown flag is ignored");
    assert_eq!(parse_cmdline("s single no-atax"), none, "non-flags aren't flags");

    let argv = init_argv();
    if single_user() {
        assert_eq!(argv, &[&b"/sbin/init"[..], &b"-s"[..]]);
    } else {
        assert_eq!(argv, &[&b"/sbin/init"[..]]);
    }
    serial_println!("boot_flags: [ok] (single_user = {})", single_user());

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
