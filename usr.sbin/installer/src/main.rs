//! `installer(8)`: installs OxideBSD from the install medium (OxideBSD-doc `INSTALLER.md` §9).
//!
//! The install medium's `/etc/ttys` starts it on the console as `installer -t ttyv0`, in place of
//! getty: it takes the terminal as a session of its own, then shows its first screen, from which
//! the user installs, gets a shell on the mfsroot (recovery, §4.4) or reboots. init starts it again
//! whenever it exits. The install steps' screens (§9.2) come with `INSTALLER.md` step 9b.
//!
//! `installer -f file` installs with no screens, every answer read from `file`, an
//! `installerconfig` (§9.4, `config`), and exits 0 once the new system is in place (`engine`).

mod config;
mod curses;
mod engine;

use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::process::ExitCode;

use curses::{A_BOLD, A_REVERSE, KEY_DOWN, KEY_ENTER, KEY_UP, Screen};

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

#[derive(Clone, Copy, PartialEq)]
enum Choice {
    Install,
    Shell,
    Reboot,
}

const CHOICES: [(Choice, &str, &str); 3] = [
    (Choice::Install, "Install", "Install OxideBSD on a disk of this machine"),
    (Choice::Shell, "Shell", "A shell on the install medium, for recovery"),
    (Choice::Reboot, "Reboot", "Restart the machine"),
];

/// Shows `lines` under the title, then waits for a key.
fn message(screen: &Screen, title: &str, lines: &[&str]) {
    screen.clear();
    screen.put(1, 2, title, A_BOLD);
    for (i, l) in lines.iter().enumerate() {
        screen.put(3 + i as i32, 2, l, 0);
    }
    screen.put(4 + lines.len() as i32, 2, "Press any key.", 0);
    screen.show();
    screen.key();
}

/// The first screen: the choices, the arrow keys to move, Enter to choose.
fn welcome(screen: &Screen, title: &str, at: &mut usize) -> Option<Choice> {
    loop {
        screen.clear();
        let (rows, _) = screen.size();
        screen.put(1, 2, title, A_BOLD);
        screen.put(3, 2, "Welcome. This program installs OxideBSD, or gives you a shell to repair one.", 0);
        for (i, (_, name, what)) in CHOICES.iter().enumerate() {
            let y = 5 + i as i32;
            screen.put(y, 4, &format!(" {name:<8} "), if i == *at { A_REVERSE } else { 0 });
            screen.put(y, 15, what, 0);
        }
        screen.put(rows - 2, 2, "Up and down choose, Enter goes.", 0);
        screen.show();
        match screen.key()? {
            KEY_UP | 0x6b => *at = at.checked_sub(1).unwrap_or(CHOICES.len() - 1),
            KEY_DOWN | 0x6a => *at = (*at + 1) % CHOICES.len(),
            KEY_ENTER | 0x0a | 0x0d => return Some(CHOICES[*at].0),
            _ => {}
        }
    }
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
    let screen = Screen::start();
    let mut at = 0;
    loop {
        match welcome(&screen, &title, &mut at) {
            None => return ExitCode::SUCCESS,
            Some(Choice::Install) => message(
                &screen,
                &title,
                &["Installing isn't here yet: it comes with the partition editor and the install steps.", "Choose Shell to work by hand."],
            ),
            Some(Choice::Shell) => {
                screen.suspend(|| {
                    println!("\nThe install medium's shell; `exit` returns to the installer.\n");
                    let _ = std::process::Command::new("/bin/sh").arg0("-sh").status();
                });
            }
            Some(Choice::Reboot) => {
                drop(screen);
                let err = std::process::Command::new("/sbin/reboot").exec();
                eprintln!("installer: /sbin/reboot: {err}");
                return ExitCode::from(1);
            }
        }
    }
}
