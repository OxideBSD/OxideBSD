//! `mkdir(1)`: makes directories.
//!
//! ```text
//! mkdir [-pv] [-m mode] directory_name ...
//! ```
//!
//! Each directory gets mode `0777` less the umask, or, with `-m`, exactly `mode` (octal or
//! symbolic, `lib/libmode`; a symbolic mode starts from `a=rwx`). `-p` makes any missing parent
//! first, each with the umask's mode plus `u+wx` (POSIX), and is quiet about a directory that is
//! already there. `-v` names each directory made.

use std::ffi::{CStr, CString, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: mkdir [-pv] [-m mode] directory_name ...");
    ExitCode::FAILURE
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a NUL-terminated string.
    unsafe { CStr::from_ptr(libc::strerror(n)) }
        .to_string_lossy()
        .into_owned()
}

fn warn(path: &[u8], err: i32) {
    eprintln!(
        "mkdir: {}: {}",
        String::from_utf8_lossy(path),
        strerror(err)
    );
}

fn mkdir(path: &[u8], mode: u32) -> Result<(), i32> {
    let c = CString::new(path).map_err(|_| libc::EINVAL)?;
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::mkdir(c.as_ptr(), mode as libc::mode_t) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

fn is_dir(path: &[u8]) -> Result<bool, i32> {
    match std::fs::metadata(std::ffi::OsStr::from_bytes(path)) {
        Ok(m) => Ok(m.is_dir()),
        Err(e) => Err(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

fn say(verbose: bool, path: &[u8]) {
    if verbose {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(path).and_then(|_| out.write_all(b"\n"));
    }
}

/// How `-p` went for one operand.
#[derive(PartialEq)]
enum Built {
    Made,
    Existed,
    Failed,
}

/// `-p`: makes each missing component of `path` in turn, the parents as `mkdir -p -m
/// $(umask -S),u+wx` would and the last with `mode`.
fn build(path: &[u8], mode: u32, verbose: bool) -> Built {
    // SAFETY: umask(2) can't fail.
    let old = unsafe { libc::umask(0) };
    // Every end of a component: each '/' that follows a non-'/' byte, and the end.
    let mut ends: Vec<usize> = (1..path.len())
        .filter(|&i| path[i] == b'/' && path[i - 1] != b'/')
        .collect();
    let trailing = path.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    ends.retain(|&e| e < trailing);
    ends.push(trailing.max(1).min(path.len()));
    let mut result = Built::Made;
    for (n, &end) in ends.iter().enumerate() {
        let last = n + 1 == ends.len();
        let part = if last { path } else { &path[..end] };
        // SAFETY: as above.
        unsafe { libc::umask(if last { old } else { old & !0o300 }) };
        match mkdir(part, if last { mode } else { 0o777 }) {
            Ok(()) => say(verbose, part),
            Err(e) if e == libc::EEXIST || e == libc::EISDIR => match is_dir(part) {
                Ok(true) => {
                    if last {
                        result = Built::Existed;
                    }
                }
                Ok(false) => {
                    warn(part, if last { libc::EEXIST } else { libc::ENOTDIR });
                    result = Built::Failed;
                    break;
                }
                Err(e) => {
                    warn(part, e);
                    result = Built::Failed;
                    break;
                }
            },
            Err(e) => {
                warn(part, e);
                result = Built::Failed;
                break;
            }
        }
    }
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    result
}

pub(crate) fn main() -> ExitCode {
    // SAFETY: the BSDs' default: a closed pipe (under -v) ends us quietly.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (mut parents, mut verbose, mut mode_text) = (false, false, None::<String>);
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
        let mut j = 1;
        while j < a.len() {
            match a[j] {
                b'p' => parents = true,
                b'v' => verbose = true,
                b'm' => {
                    let v = if j + 1 < a.len() {
                        a[j + 1..].to_vec()
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.as_bytes().to_vec(),
                            None => {
                                eprintln!("mkdir: option requires an argument -- m");
                                return usage();
                            }
                        }
                    };
                    mode_text = Some(String::from_utf8_lossy(&v).into_owned());
                    break;
                }
                c => {
                    eprintln!("mkdir: illegal option -- {}", c as char);
                    return usage();
                }
            }
            j += 1;
        }
        i += 1;
    }
    let dirs = &args[i..];
    if dirs.is_empty() {
        return usage();
    }
    let mode = match &mode_text {
        None => 0o777,
        Some(t) => match mode::parse(t) {
            // SAFETY: umask(2) can't fail; set it back at once.
            Ok(m) => m.apply(0o777, true, unsafe {
                let u = libc::umask(0);
                libc::umask(u);
                u as u32
            }),
            Err(e) => {
                eprintln!("mkdir: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let mut status = ExitCode::SUCCESS;
    for d in dirs {
        let path = d.as_bytes();
        let made = if parents {
            build(path, mode, verbose)
        } else {
            match mkdir(path, mode) {
                Ok(()) => {
                    say(verbose, path);
                    Built::Made
                }
                Err(e) => {
                    warn(path, e);
                    Built::Failed
                }
            }
        };
        if made == Built::Failed {
            status = ExitCode::FAILURE;
        }
        // mkdir(2) drops the set-ID and sticky bits and honours the umask: give a mode asked
        // for with -m exactly, but only to a directory made just now.
        if made == Built::Made && mode_text.is_some() {
            let c = CString::new(path).unwrap_or_default();
            // SAFETY: a NUL-terminated path.
            if unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) } != 0 {
                warn(path, errno());
                status = ExitCode::FAILURE;
            }
        }
    }
    status
}
