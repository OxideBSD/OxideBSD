//! `reboot(8)`, `halt(8)`, `poweroff(8)`: one program, installed under all three names, that
//! picks its action from `argv[0]`.
//!
//! By default it asks init to do the work, by signaling process 1 (INIT.md §6): `SIGINT` to
//! reboot, `SIGUSR1` to halt, `SIGUSR2` to power off. Init then runs `/etc/rc.shutdown`,
//! terminates every process, synchronizes storage and calls `reboot(2)`.
//!
//! `-q` skips init: storage is synchronized (unless `-n`) and `reboot(2)` is called at once,
//! with no services stopped and no processes warned.
//!
//! `-r [type:]special` switches the root file system instead (OxideBSD-doc `RAM_FLOOR.md` §5.1,
//! FreeBSD's reroot): init shuts everything down as for a reboot, then the kernel unmounts every
//! file system, mounts `special` as the root and starts init on it. Without `special`, the root
//! `/etc/fstab` names; without `type:`, fstab's type for that device, else `oxfs`. The kernel
//! takes the spec (`reboot(RB_REROOT, spec)`, checking the device at once) and asks init with
//! `SIGPWR` (this ABI has no `SIGEMT`, FreeBSD's signal for it).

use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq)]
enum Action {
    Reboot,
    Halt,
    PowerOff,
}

fn main() -> ExitCode {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_default();
    let name = argv0.rsplit('/').next().unwrap_or("reboot").to_string();
    let mut action = match name.as_str() {
        "halt" => Action::Halt,
        "poweroff" => Action::PowerOff,
        _ => Action::Reboot,
    };
    let usage = format!("usage: {name} [-lnpq]\n       {name} -r [[type:]special]");
    let (mut quick, mut nosync, mut reroot) = (false, false, false);
    let mut special: Option<String> = None;
    for arg in args {
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            if reroot && special.is_none() {
                special = Some(arg);
                continue;
            }
            eprintln!("{usage}");
            return ExitCode::FAILURE;
        };
        for c in flags.chars() {
            match c {
                // No system log exists yet, so there is nothing to not log to.
                'l' => {}
                'n' => nosync = true,
                'p' => action = Action::PowerOff,
                'q' => quick = true,
                'r' => reroot = true,
                _ => {
                    eprintln!("{name}: illegal option -- {c}\n{usage}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }
    if reroot {
        if quick || nosync || action != Action::Reboot {
            eprintln!("{usage}");
            return ExitCode::FAILURE;
        }
        return match ask_reroot(special.as_deref()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{name}: {e}");
                ExitCode::FAILURE
            }
        };
    }
    if nosync && !quick {
        eprintln!("{name}: -n only applies with -q; init always synchronizes storage");
        return ExitCode::FAILURE;
    }

    if quick {
        if !nosync {
            unsafe { libc::sync() };
        }
        let how = match action {
            Action::Reboot => libc::RB_AUTOBOOT,
            Action::Halt => libc::RB_HALT_SYSTEM,
            Action::PowerOff => libc::RB_POWER_OFF,
        };
        // -n: the kernel mustn't synchronize either (`RB_NOSYNC`, which musl's reboot(3) has no
        // argument for).
        let flags = if nosync { RB_NOSYNC } else { 0 };
        // SAFETY: syscall with plain integer arguments.
        unsafe { libc::syscall(SYS_REBOOT, 0xfee1deadu32 as libc::c_long, 672274793 as libc::c_long, how as libc::c_long, flags) };
        // reboot(2) only returns on failure.
    } else {
        let sig = match action {
            Action::Reboot => libc::SIGINT,
            Action::Halt => libc::SIGUSR1,
            Action::PowerOff => libc::SIGUSR2,
        };
        if unsafe { libc::kill(1, sig) } == 0 {
            return ExitCode::SUCCESS;
        }
    }
    eprintln!("{name}: {}", std::io::Error::last_os_error());
    ExitCode::FAILURE
}

/// `reboot(2)`'s number on this ABI (the libc crate's `SYS_reboot` is Linux's), and its root
/// switch (FreeBSD's `RB_REROOT` value).
const SYS_REBOOT: libc::c_long = 486;
const RB_REROOT: libc::c_long = 0x0020_0000;
/// FreeBSD's `RB_NOSYNC` value, as this ABI takes it: in the fourth argument.
const RB_NOSYNC: libc::c_long = 0x4;

/// `-r`: the new root's `type:special`, from `special` or fstab, handed to the kernel, which asks
/// init to shut down and switch.
fn ask_reroot(special: Option<&str>) -> Result<(), String> {
    let entries = fstab::read().map(|r| r.0).unwrap_or_default();
    let spec = match special {
        Some(s) if s.contains(':') => s.to_string(),
        Some(s) => {
            let t = entries.iter().find(|e| e.spec == s).map_or("oxfs", |e| e.vfstype.as_str());
            format!("{t}:{s}")
        }
        None => {
            let root = entries.iter().find(|e| e.file == "/").ok_or(format!("{}: no root line", fstab::PATH))?;
            format!("{}:{}", root.vfstype, root.spec)
        }
    };
    let spec_c = std::ffi::CString::new(spec.clone()).map_err(|_| format!("{spec}: a NUL in it"))?;
    // musl's reboot(2) passes Linux's two magic numbers first; the spec is the fourth argument.
    // SAFETY: syscall with a NUL-terminated string that outlives it.
    let r = unsafe { libc::syscall(SYS_REBOOT, 0xfee1deadu32 as libc::c_long, 672274793 as libc::c_long, RB_REROOT, spec_c.as_ptr()) };
    if r != 0 {
        return Err(format!("{spec}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}
