//! Kernel command-line parsing (`boot::parse_cmdline`) and what pid 1 is started as
//! (`process::init::boot_init`).
//! The last check follows whatever this boot's own command line was, so running this binary with
//! `OXIDEBSD_KERNEL_CMDLINE=-s` exercises the real Limine path end to end.
#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use oxidebsd::boot::{BootFlags, BootInfo, parse_cmdline, single_user};
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
    assert_eq!(parse_cmdline("  no-ata   -s "), BootFlags { no_ata: true, single_user: true, ..none });
    assert_eq!(parse_cmdline("-vs"), single, "combined flags");
    assert_eq!(parse_cmdline("-v"), none, "unknown flag is ignored");
    assert_eq!(parse_cmdline("s single no-atax"), none, "non-flags aren't flags");
    assert_eq!(parse_cmdline("console.underline=color"), BootFlags { underline_color: true, ..none });
    assert_eq!(parse_cmdline("console.underline=line"), none);
    assert_eq!(parse_cmdline("-D"), BootFlags { dual_console: true, ..none });
    assert_eq!(parse_cmdline("-sD"), BootFlags { single_user: true, dual_console: true, ..none });
    assert_eq!(parse_cmdline("-h"), BootFlags { serial_console: true, ..none });

    let init = oxidebsd::process::init::boot_init();
    assert!(init.paths == [b"/sbin/init".to_vec()], "pid 1's path");
    if single_user() {
        assert!(init.args == [b"-s".to_vec()], "single-user boot without -s");
    } else {
        assert!(init.args.is_empty(), "boot without -s passed arguments");
    }
    serial_println!("boot_flags: [ok] (single_user = {})", single_user());

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
