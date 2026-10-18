//! `echo(1)`: writes its arguments, separated by spaces, and a newline.
//!
//! ```text
//! echo [-n] [string ...]
//! ```
//!
//! As on the BSDs, the only option is a first argument of exactly `-n`, which leaves the newline
//! off; there is no other option parsing (`echo -x` prints `-x`, `echo -n -n` prints `-n`). A
//! last argument ending in `\c` loses those two characters and the newline (FreeBSD's, and
//! System V's, way of doing the same). No other backslash is special.

use std::ffi::{CStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

fn main() -> ExitCode {
    // SAFETY: back to the default, so `echo | head -0` ends quietly like the BSDs' echo.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut newline = true;
    if args.first().is_some_and(|a| a == "-n") {
        args.remove(0);
        newline = false;
    }
    let mut out = Vec::new();
    let last = args.len().saturating_sub(1);
    for (i, a) in args.iter().enumerate() {
        let mut b = a.as_bytes();
        if i == last && b.ends_with(b"\\c") {
            b = &b[..b.len() - 2];
            newline = false;
        }
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(b);
    }
    if newline {
        out.push(b'\n');
    }
    // One write for the whole line, as FreeBSD's writev does.
    if let Err(e) = std::io::stdout().lock().write_all(&out) {
        let msg = match e.raw_os_error() {
            // SAFETY: strerror returns a NUL-terminated string.
            Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }
                .to_string_lossy()
                .into_owned(),
            None => e.to_string(),
        };
        eprintln!("echo: write: {msg}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
