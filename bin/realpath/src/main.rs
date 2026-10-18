//! `realpath(1)`: writes the absolute pathname of each path, with no symbolic links and no `.`
//! or `..` components (`realpath(3)`).
//!
//! ```text
//! realpath [-q] [path ...]
//! ```
//!
//! With no path, the working directory's. `-q` keeps quiet about paths that can't be resolved
//! (the exit status still says so).

use std::ffi::{CStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: realpath [-q] [path ...]");
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
    let mut quiet = false;
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
                b'q' => quiet = true,
                _ => {
                    eprintln!("realpath: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
        i += 1;
    }
    let mut paths: Vec<OsString> = args[i..].to_vec();
    if paths.is_empty() {
        paths.push(".".into());
    }
    let mut status = ExitCode::SUCCESS;
    let mut out = std::io::stdout().lock();
    for p in &paths {
        // std's canonicalize is realpath(3).
        match std::fs::canonicalize(p) {
            Ok(r) => {
                let _ = out
                    .write_all(r.as_os_str().as_bytes())
                    .and_then(|_| out.write_all(b"\n"));
            }
            Err(e) => {
                if !quiet {
                    let _ = out.flush();
                    eprintln!("realpath: {}: {}", p.to_string_lossy(), strerror(&e));
                }
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}
