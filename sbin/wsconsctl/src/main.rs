//! `wsconsctl(8)`: the console's settings (OxideBSD-doc `INSTALLER.md` §7), with NetBSD's and
//! OpenBSD's names.
//!
//! ```text
//! wsconsctl [-n] [-a | name ...]
//! wsconsctl [-n] name=value ...
//! ```
//!
//! The settings, each through the console terminal's requests (setting one is root's):
//!
//! - `keyboard.encoding`: the keyboard's layout (`us`, `uk`, `de`, `fr`, `us.dvorak`,
//!   `us.colemak`, `jp`, `no`, `fi`, `sv`), for PS/2 and USB keyboards alike (`KBDIOC_*`);
//! - `display.palette`: the console's 16 colours, `vga` (the standard ones) or `rust`
//!   (OxideBSD's own, each hue in oxidised metal) (`DISPIOC_*`).
//!
//! `name` prints `name=value` (`-n`: the value alone), `-a` (or nothing) every setting, and
//! `name=value` sets it and prints `name -> value`, as OpenBSD's does.

use std::os::fd::AsRawFd;
use std::process::ExitCode;

/// The console terminal, whose requests these are.
const CONSOLE: &str = "/dev/ttyv0";
const KBDIOC_GETENCODING: u64 = 0x6f78_4b01;
const KBDIOC_SETENCODING: u64 = 0x6f78_4b02;
const DISPIOC_GETPALETTE: u64 = 0x6f78_4401;
const DISPIOC_SETPALETTE: u64 = 0x6f78_4402;
const KBD_NAME: usize = 32;

/// The settings, in `-a`'s order: each one's get and set requests, and what its values are.
const SETTINGS: [(&str, u64, u64, &str); 2] = [
    ("keyboard.encoding", KBDIOC_GETENCODING, KBDIOC_SETENCODING, "encoding"),
    ("display.palette", DISPIOC_GETPALETTE, DISPIOC_SETPALETTE, "palette"),
];

fn setting(name: &str) -> Result<(u64, u64, &'static str), String> {
    SETTINGS.iter().find(|s| s.0 == name).map(|s| (s.1, s.2, s.3)).ok_or(format!("{name}: no such setting"))
}

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
    let (request, _, _) = setting(name)?;
    let mut buf = [0u8; KBD_NAME];
    ioctl(request, &mut buf).map_err(|e| format!("{name}: {e}"))?;
    let len = buf.iter().position(|&b| b == 0).unwrap_or(KBD_NAME);
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}

fn set(name: &str, value: &str) -> Result<(), String> {
    let (_, request, what) = setting(name)?;
    let mut buf = [0u8; KBD_NAME];
    if value.is_empty() || value.len() >= KBD_NAME || value.contains('\0') {
        return Err(format!("{name}: {value}: no such {what}"));
    }
    buf[..value.len()].copy_from_slice(value.as_bytes());
    ioctl(request, &mut buf).map_err(|e| {
        if e.contains("Invalid argument") { format!("{name}: {value}: no such {what}") } else { format!("{name}: {e}") }
    })
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
        args = SETTINGS.iter().map(|s| s.0.to_string()).collect();
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
