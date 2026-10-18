//! `hostname(1)`: writes, or (as the superuser) sets, the name of the host.
//!
//! ```text
//! hostname [-f] [-s | -d] [name-of-host]
//! ```
//!
//! `-s` writes the name up to its first dot, `-d` what follows that dot (the domain; the whole
//! name if there is none). `-f` asks for the fully qualified name, which the name already is on
//! a BSD: it is accepted and does nothing, as on FreeBSD.

use std::ffi::{CStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: hostname [-f] [-s | -d] [name-of-host]");
    ExitCode::FAILURE
}

fn strerror(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }
            .to_string_lossy()
            .into_owned(),
        None => e.to_string(),
    }
}

fn main() -> ExitCode {
    // SAFETY: the BSDs' default: a closed pipe ends us quietly.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (mut short, mut domain) = (false, false);
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_bytes();
        if a == b"--" {
            i += 1;
            break;
        }
        if a.len() < 2 || a[0] != b'-' {
            break;
        }
        for &c in &a[1..] {
            match c {
                b'f' => {}
                b's' => short = true,
                b'd' => domain = true,
                _ => {
                    eprintln!("hostname: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
        i += 1;
    }
    let rest = &args[i..];
    if rest.len() > 1 || (short && domain) {
        return usage();
    }
    if let Some(name) = rest.first() {
        let b = name.as_bytes();
        // SAFETY: a buffer and its length; sethostname(2) needs no NUL.
        if unsafe { libc::sethostname(b.as_ptr().cast(), b.len() as _) } != 0 {
            eprintln!(
                "hostname: sethostname: {}",
                strerror(&std::io::Error::last_os_error())
            );
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }
    let mut buf = [0u8; 256];
    // SAFETY: a buffer and its length.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        eprintln!(
            "hostname: gethostname: {}",
            strerror(&std::io::Error::last_os_error())
        );
        return ExitCode::FAILURE;
    }
    // A name filling the buffer may lack its NUL: the last byte is always kept as one.
    buf[buf.len() - 1] = 0;
    let mut name = CStr::from_bytes_until_nul(&buf)
        .map(|c| c.to_bytes())
        .unwrap_or(b"");
    if let Some(dot) = name.iter().position(|&c| c == b'.') {
        if short {
            name = &name[..dot];
        } else if domain {
            name = &name[dot + 1..];
        }
    }
    let mut line = name.to_vec();
    line.push(b'\n');
    if let Err(e) = std::io::stdout().lock().write_all(&line) {
        eprintln!("hostname: stdout: {}", strerror(&e));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
