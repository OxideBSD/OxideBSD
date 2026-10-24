//! `installer(8)`: installs OxideBSD from the install medium (OxideBSD-doc `INSTALLER.md` §9).
//!
//! The install medium's `/etc/ttys` starts it on the console as `installer -t ttyv0`, in place of
//! getty: it takes the terminal as a session of its own, then shows its first screen, from which
//! the user installs (`screens`, drawn by `ui`), gets a shell on the mfsroot (recovery, §4.4) or
//! reboots. init starts it again whenever it exits.
//!
//! `installer -f file` installs with no screens, every answer read from `file`, an
//! `installerconfig` (§9.4, `config`), and exits 0 once the new system is in place (`engine`).

mod config;
mod curses;
mod editor;
mod engine;
mod loaders;
mod screens;
mod ui;

use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::process::ExitCode;

use curses::Screen;
use ui::{Dialog, Ui};

fn usage() -> ExitCode {
    eprintln!("usage: installer [-t tty]\n       installer -f installerconfig");
    ExitCode::from(1)
}

/// Opens `/dev/<tty>` as a new session's controlling terminal, and as descriptors 0, 1 and 2, as
/// getty does.
fn take_terminal(tty: &str) -> std::io::Result<()> {
    let path = CString::new(format!("/dev/{tty}")).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    // SAFETY: plain system calls.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::setsid();
        if libc::ioctl(fd, libc::TIOCSCTTY, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for target in 0..3 {
            libc::dup2(fd, target);
        }
        if fd > 2 {
            libc::close(fd);
        }
    }
    Ok(())
}

/// The kernel's release (`uname -r`), for the title.
fn release() -> String {
    // SAFETY: uname fills a local struct.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = u.release.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

const HELP_WELCOME: &str = "Install puts OxideBSD on a disk of this machine, asking first about \
    the keyboard, the disks, the network, the time zone and the users; nothing is written before the \
    last question. Shell is a shell on the install medium, to repair a system. In every dialog the \
    arrows move, Tab goes to the buttons, Enter goes on, Esc goes back, F1 shows help and F10 a shell.";

/// The first screen: install, a shell, or reboot.
fn welcome(ui: &Ui, at: &mut usize) -> Option<usize> {
    let items = [
        ("Install", "Install OxideBSD on a disk of this machine"),
        ("Shell", "A shell on the install medium, for recovery"),
        ("Reboot", "Restart the machine"),
    ]
    .map(|(n, w)| (n.to_string(), w.to_string()));
    let d = Dialog::new("Welcome", "Welcome. This program installs OxideBSD, or gives you a shell to repair one.", HELP_WELCOME);
    // The tests wait for this line before typing.
    let i = ui.menu_keys(&d, &items, *at, "Up and down choose, Enter goes.   F1 help   F10 shell")?;
    *at = i;
    Some(i)
}

/// `-f`: installs as `file` says, telling each step on the standard output.
fn scripted(file: &str) -> ExitCode {
    let result = config::read(file).and_then(|cfg| engine::install(&cfg, &mut |step| println!("installer: {step}")));
    match result {
        Ok(()) => {
            println!("installer: OxideBSD is installed");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("installer: {e}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {}
        [t, tty] if t == "-t" => {
            if let Err(e) = take_terminal(tty) {
                eprintln!("installer: /dev/{tty}: {e}");
                return ExitCode::from(1);
            }
        }
        [f, file] if f == "-f" => return scripted(file),
        _ => return usage(),
    }
    let title = format!("OxideBSD {} installer", release());
    let mut ui = Ui::new(Screen::start(), title);
    let mut at = 0;
    loop {
        ui.step = String::new();
        let reboot = match welcome(&ui, &mut at) {
            None => continue,
            Some(0) => matches!(screens::run(&mut ui), screens::After::Reboot),
            Some(1) => {
                ui.shell();
                false
            }
            Some(_) => true,
        };
        if reboot {
            drop(ui);
            let err = std::process::Command::new("/sbin/reboot").exec();
            eprintln!("installer: /sbin/reboot: {err}");
            return ExitCode::from(1);
        }
    }
}
