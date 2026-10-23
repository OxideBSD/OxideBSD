//! `pwd(1)`: writes the absolute pathname of the working directory.
//!
//! ```text
//! pwd [-L | -P]
//! ```
//!
//! `-L` (the default) writes `$PWD` when it is an absolute pathname of the working directory
//! with no `.` or `..` component, as POSIX asks, and otherwise falls back to `-P`. `-P` writes
//! the physical pathname, with no symbolic links (`getcwd(3)`). The last of the two counts.

use std::ffi::{CStr, OsString};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: pwd [-L | -P]");
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

/// `$PWD`, if it is absolute, has no `.` or `..` component and names the working directory.
fn logical() -> Option<OsString> {
    let pwd = std::env::var_os("PWD")?;
    let b = pwd.as_bytes();
    if b.first() != Some(&b'/') || b.split(|&c| c == b'/').any(|c| c == b"." || c == b"..") {
        return None;
    }
    let (l, p) = (std::fs::metadata(&pwd).ok()?, std::fs::metadata(".").ok()?);
    (l.dev() == p.dev() && l.ino() == p.ino()).then_some(pwd)
}

pub(crate) fn main() -> ExitCode {
    // SAFETY: the BSDs' default: a closed pipe ends us quietly.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let mut physical = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            break;
        };
        for c in flags.chars() {
            match c {
                'L' => physical = false,
                'P' => physical = true,
                _ => {
                    eprintln!("pwd: illegal option -- {c}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    if i != args.len() {
        return usage();
    }
    let dir = match (!physical).then(logical).flatten() {
        Some(d) => d,
        None => match std::env::current_dir() {
            Ok(d) => d.into_os_string(),
            Err(e) => {
                eprintln!("pwd: .: {}", strerror(&e));
                return ExitCode::FAILURE;
            }
        },
    };
    let mut line = dir.into_vec();
    line.push(b'\n');
    if let Err(e) = std::io::stdout().lock().write_all(&line) {
        eprintln!("pwd: stdout: {}", strerror(&e));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
