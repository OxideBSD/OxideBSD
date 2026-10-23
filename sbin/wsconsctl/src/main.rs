//! `wsconsctl(8)`: the console's settings (OxideBSD-doc `INSTALLER.md` §7), with NetBSD's and
//! OpenBSD's names.
//!
//! ```text
//! wsconsctl [-n] [-a | name ...]
//! wsconsctl [-n] name=value ...
//! ```
//!
//! One setting so far, `keyboard.encoding`: the keyboard's layout (`us`, `uk`, `de`, `fr`,
//! `us.dvorak`, `us.colemak`, `jp`, `no`, `fi`, `sv`), for PS/2 and USB keyboards alike, set
//! through the console terminal's `KBDIOC_*` requests (setting it is root's). `name` prints
//! `name=value` (`-n`: the value alone), `-a` (or nothing) every setting, and `name=value`
//! sets it and prints `name -> value`, as OpenBSD's does.

use std::os::fd::AsRawFd;
use std::process::ExitCode;

/// The console terminal, whose requests these are.
const CONSOLE: &str = "/dev/ttyv0";
const KBDIOC_GETENCODING: u64 = 0x6f78_4b01;
const KBDIOC_SETENCODING: u64 = 0x6f78_4b02;
const KBD_NAME: usize = 32;

/// The settings, in `-a`'s order.
const NAMES: [&str; 1] = ["keyboard.encoding"];

fn console() -> Result<std::fs::File, String> {
    std::fs::File::open(CONSOLE).map_err(|e| format!("{CONSOLE}: {e}"))
}

fn ioctl(request: u64, name: &mut [u8; KBD_NAME]) -> Result<(), String> {
    let f = console()?;
    // SAFETY: the request reads or writes `KBD_NAME` bytes at the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), request as _, name.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn get(name: &str) -> Result<String, String> {
    match name {
        "keyboard.encoding" => {
            let mut buf = [0u8; KBD_NAME];
            ioctl(KBDIOC_GETENCODING, &mut buf).map_err(|e| format!("{name}: {e}"))?;
            let len = buf.iter().position(|&b| b == 0).unwrap_or(KBD_NAME);
            Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
        }
        _ => Err(format!("{name}: no such setting")),
    }
}

fn set(name: &str, value: &str) -> Result<(), String> {
    match name {
        "keyboard.encoding" => {
            let mut buf = [0u8; KBD_NAME];
            if value.is_empty() || value.len() >= KBD_NAME || value.contains('\0') {
                return Err(format!("{name}: {value}: no such encoding"));
            }
            buf[..value.len()].copy_from_slice(value.as_bytes());
            ioctl(KBDIOC_SETENCODING, &mut buf).map_err(|e| {
                if e.contains("Invalid argument") { format!("{name}: {value}: no such encoding") } else { format!("{name}: {e}") }
            })
        }
        _ => Err(format!("{name}: no such setting")),
    }
}

pub(crate) fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut values_only = false;
    let mut all = false;
    while let Some(a) = args.first().filter(|a| a.starts_with('-') && a.len() > 1) {
        for c in a[1..].chars() {
            match c {
                'n' => values_only = true,
                'a' => all = true,
                _ => {
                    eprintln!("usage: wsconsctl [-n] [-a | name ...]\n       wsconsctl [-n] name=value ...");
                    return ExitCode::from(1);
                }
            }
        }
        args.remove(0);
    }
    if args.is_empty() || all {
        args = NAMES.iter().map(|n| n.to_string()).collect();
    }
    let mut status = 0;
    for arg in &args {
        let r = match arg.split_once('=') {
            Some((name, value)) => {
                set(name, value).map(|()| if values_only { value.to_string() } else { format!("{name} -> {value}") })
            }
            None => get(arg).map(|v| if values_only { v } else { format!("{arg}={v}") }),
        };
        match r {
            Ok(line) => println!("{line}"),
            Err(e) => {
                eprintln!("wsconsctl: {e}");
                status = 1;
            }
        }
    }
    ExitCode::from(status)
}
