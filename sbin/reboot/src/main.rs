//! `reboot(8)`, `halt(8)`, `poweroff(8)`: one program, installed under all three names, that
//! picks its action from `argv[0]`.
//!
//! By default it asks init to do the work, by signaling process 1 (INIT.md §6): `SIGINT` to
//! reboot, `SIGUSR1` to halt, `SIGUSR2` to power off. Init then runs `/etc/rc.shutdown`,
//! terminates every process, synchronizes storage and calls `reboot(2)`.
//!
//! `-q` skips init: storage is synchronized (unless `-n`) and `reboot(2)` is called at once,
//! with no services stopped and no processes warned.

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
    let usage = format!("usage: {name} [-lnpq]");
    let (mut quick, mut nosync) = (false, false);
    for arg in args {
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
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
                _ => {
                    eprintln!("{name}: illegal option -- {c}\n{usage}");
                    return ExitCode::FAILURE;
                }
            }
        }
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
        unsafe { libc::reboot(how) };
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
