//! `rescue`: the install medium's tools crunched into one program (OxideBSD-doc `INSTALLER.md`
//! §4.3), as FreeBSD's `crunchgen(1)` makes its `/rescue` and install media. Each tool is its own
//! source, included as a module (`#[path]`), and the program runs the one its `argv[0]` names
//! (`/bin/ls` is a hard link to it), or, as `rescue TOOL ARGS...`, the one named first. One copy
//! of std, libc and the shared libraries instead of one per tool: the mfsroot lives in RAM.
//!
//! A tool to add: its directory here, and its dependencies in `Cargo.toml`. The tools themselves
//! build alone as ever; their `main` is `pub(crate)` for this, and their own modules refer to
//! each other through `super::`, never `crate::`.

use std::process::{ExitCode, Termination};


#[path = "../../bin/cat/src/main.rs"]
mod bin_cat;
#[path = "../../bin/chmod/src/main.rs"]
mod bin_chmod;
#[path = "../../bin/cp/src/main.rs"]
mod bin_cp;
#[path = "../../bin/date/src/main.rs"]
mod bin_date;
#[path = "../../bin/dd/src/main.rs"]
mod bin_dd;
#[path = "../../bin/df/src/main.rs"]
mod bin_df;
#[path = "../../bin/echo/src/main.rs"]
mod bin_echo;
#[path = "../../bin/expr/src/main.rs"]
mod bin_expr;
#[path = "../../bin/false/src/main.rs"]
mod bin_false;
#[path = "../../bin/grep/src/main.rs"]
mod bin_grep;
#[path = "../../bin/hostname/src/main.rs"]
mod bin_hostname;
#[path = "../../bin/kill/src/main.rs"]
mod bin_kill;
#[path = "../../bin/ln/src/main.rs"]
mod bin_ln;
#[path = "../../bin/ls/src/main.rs"]
mod bin_ls;
#[path = "../../bin/mkdir/src/main.rs"]
mod bin_mkdir;
#[path = "../../bin/mv/src/main.rs"]
mod bin_mv;
#[path = "../../bin/ps/src/main.rs"]
mod bin_ps;
#[path = "../../bin/pwd/src/main.rs"]
mod bin_pwd;
#[path = "../../bin/rm/src/main.rs"]
mod bin_rm;
#[path = "../../bin/rmdir/src/main.rs"]
mod bin_rmdir;
#[path = "../../bin/sed/src/main.rs"]
mod bin_sed;
#[path = "../../bin/sh/src/main.rs"]
mod bin_sh;
#[path = "../../bin/sleep/src/main.rs"]
mod bin_sleep;
#[path = "../../bin/stty/src/main.rs"]
mod bin_stty;
#[path = "../../bin/sync/src/main.rs"]
mod bin_sync;
#[path = "../../bin/tar/src/main.rs"]
mod bin_tar;
#[path = "../../bin/test/src/main.rs"]
mod bin_test;
#[path = "../../bin/touch/src/main.rs"]
mod bin_touch;
#[path = "../../bin/true/src/main.rs"]
mod bin_true;
#[path = "../../sbin/dhclient/src/main.rs"]
mod sbin_dhclient;
#[path = "../../sbin/dmesg/src/main.rs"]
mod sbin_dmesg;
#[path = "../../sbin/fsck/src/main.rs"]
mod sbin_fsck;
#[path = "../../sbin/fsck_msdosfs/src/main.rs"]
mod sbin_fsck_msdosfs;
#[path = "../../sbin/fsck_oxfs/src/main.rs"]
mod sbin_fsck_oxfs;
#[path = "../../sbin/ifconfig/src/main.rs"]
mod sbin_ifconfig;
#[path = "../../sbin/init/src/main.rs"]
mod sbin_init;
#[path = "../../sbin/init_sh/src/main.rs"]
mod sbin_init_sh;
#[path = "../../sbin/mount/src/main.rs"]
mod sbin_mount;
#[path = "../../sbin/newfs_msdos/src/main.rs"]
mod sbin_newfs_msdos;
#[path = "../../sbin/newfs_oxfs/src/main.rs"]
mod sbin_newfs_oxfs;
#[path = "../../sbin/reboot/src/main.rs"]
mod sbin_reboot;
#[path = "../../sbin/route/src/main.rs"]
mod sbin_route;
#[path = "../../sbin/sysctl/src/main.rs"]
mod sbin_sysctl;
#[path = "../../sbin/umount/src/main.rs"]
mod sbin_umount;
#[path = "../../sbin/gpart/src/main.rs"]
mod sbin_gpart;
#[path = "../../sbin/wsconsctl/src/main.rs"]
mod sbin_wsconsctl;
#[path = "../../usr.sbin/efibootmgr/src/main.rs"]
mod usr_sbin_efibootmgr;

/// The tools, by name, and their `main`s.
const TOOLS: &[(&str, fn() -> ExitCode)] = &[
    ("cat", || bin_cat::main().report()),
    ("chmod", || bin_chmod::main().report()),
    ("cp", || bin_cp::main().report()),
    ("date", || bin_date::main().report()),
    ("dd", || bin_dd::main().report()),
    ("df", || bin_df::main().report()),
    ("echo", || bin_echo::main().report()),
    ("expr", || bin_expr::main().report()),
    ("false", || bin_false::main().report()),
    ("grep", || bin_grep::main().report()),
    ("hostname", || bin_hostname::main().report()),
    ("kill", || bin_kill::main().report()),
    ("ln", || bin_ln::main().report()),
    ("ls", || bin_ls::main().report()),
    ("mkdir", || bin_mkdir::main().report()),
    ("mv", || bin_mv::main().report()),
    ("ps", || bin_ps::main().report()),
    ("pwd", || bin_pwd::main().report()),
    ("rm", || bin_rm::main().report()),
    ("rmdir", || bin_rmdir::main().report()),
    ("sed", || bin_sed::main().report()),
    ("sh", || bin_sh::main().report()),
    ("sleep", || bin_sleep::main().report()),
    ("stty", || bin_stty::main().report()),
    ("sync", || bin_sync::main().report()),
    ("tar", || bin_tar::main().report()),
    ("test", || bin_test::main().report()),
    ("touch", || bin_touch::main().report()),
    ("true", || bin_true::main().report()),
    ("dhclient", || sbin_dhclient::main().report()),
    ("dmesg", || sbin_dmesg::main().report()),
    ("fsck", || sbin_fsck::main().report()),
    ("fsck_msdosfs", || sbin_fsck_msdosfs::main().report()),
    ("fsck_oxfs", || sbin_fsck_oxfs::main().report()),
    ("ifconfig", || sbin_ifconfig::main().report()),
    ("init", || sbin_init::main().report()),
    ("init_sh", || sbin_init_sh::main().report()),
    ("mount", || sbin_mount::main().report()),
    // Its other names (install.mtree's hard links), which it reads from argv[0].
    ("mount_msdosfs", || sbin_mount::main().report()),
    ("mount_tmpfs", || sbin_mount::main().report()),
    ("newfs_msdos", || sbin_newfs_msdos::main().report()),
    ("newfs_oxfs", || sbin_newfs_oxfs::main().report()),
    ("reboot", || sbin_reboot::main().report()),
    ("route", || sbin_route::main().report()),
    ("sysctl", || sbin_sysctl::main().report()),
    ("umount", || sbin_umount::main().report()),
    ("gpart", || sbin_gpart::main().report()),
    ("wsconsctl", || sbin_wsconsctl::main().report()),
    ("efibootmgr", || usr_sbin_efibootmgr::main().report()),
];

fn main() -> ExitCode {
    let arg0 = std::env::args().next().unwrap_or_default();
    let name = arg0.rsplit('/').next().unwrap_or("").trim_start_matches('-');
    if let Some((_, run)) = TOOLS.iter().find(|(n, _)| *n == name) {
        return run();
    }
    // `rescue TOOL ARGS...`: std's argument list can't drop a word, so the tool is run again
    // under its own name.
    let mut args = std::env::args_os().skip(1);
    if let Some(tool) = args.next() {
        if TOOLS.iter().any(|(n, _)| std::ffi::OsStr::new(n) == tool) {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new("/proc/self/exe").arg0(&tool).args(args).exec();
            eprintln!("rescue: {err}");
            return ExitCode::from(1);
        }
    }
    let names: Vec<&str> = TOOLS.iter().map(|(n, _)| *n).collect();
    eprintln!("usage: rescue tool [argument ...]\ntools: {}", names.join(" "));
    ExitCode::from(1)
}
