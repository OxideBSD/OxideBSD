//! `ln(1)`: makes links.
//!
//! ```text
//! ln [-s [-F] | -L | -P] [-f | -i] [-hnvw] source_file [target_file]
//! ln [-s [-F] | -L | -P] [-f | -i] [-hnvw] source_file ... target_dir
//! ```
//!
//! A hard link by default, a symbolic link with `-s`. With one operand the link goes in the
//! working directory; with a target that is a directory (or more than two operands, when it
//! must be), each link goes in it under its source's last component. `-f` first removes a
//! target that exists; `-i` asks (on the standard error) before doing so; the last of the two
//! counts. `-h` (or `-n`) doesn't follow a target that is a symbolic link to a directory, so
//! that `-f` replaces the link itself. `-F`, with `-s`, removes a target that is a directory
//! (an empty one) to put the link in its place. `-L` (the default) hard links what a symbolic
//! link source points to; `-P` the symbolic link itself. `-v` names each link made; `-w`
//! warns when a symbolic link's source doesn't exist.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{BufRead, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: ln [-s [-F] | -L | -P] [-f | -i] [-hnvw] source_file [target_file]");
    eprintln!("       ln [-s [-F] | -L | -P] [-f | -i] [-hnvw] source_file ... target_dir");
    ExitCode::FAILURE
}

fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a NUL-terminated string.
    unsafe { CStr::from_ptr(libc::strerror(n)) }
        .to_string_lossy()
        .into_owned()
}

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn show(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}

fn warn(path: &[u8], err: i32) {
    eprintln!("ln: {}: {}", show(path), strerror(err));
}

fn os(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(b)
}

/// The last component of `path`, trailing slashes ignored (`basename(3)`).
fn basename(path: &[u8]) -> &[u8] {
    let end = path.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    if end == 0 {
        return if path.is_empty() { b"." } else { b"/" };
    }
    let start = path[..end]
        .iter()
        .rposition(|&c| c == b'/')
        .map_or(0, |i| i + 1);
    &path[start..end]
}

/// The directory part of `path` (`dirname(3)`).
fn dirname(path: &[u8]) -> &[u8] {
    let end = path.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    match path[..end].iter().rposition(|&c| c == b'/') {
        None => {
            if end == 0 && !path.is_empty() {
                b"/"
            } else {
                b"."
            }
        }
        Some(slash) => {
            let d = &path[..slash];
            let d_end = d.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
            if d_end == 0 { b"/" } else { &d[..d_end] }
        }
    }
}

fn is_dir(path: &[u8], follow: bool) -> bool {
    let m = if follow {
        std::fs::metadata(os(path))
    } else {
        std::fs::symlink_metadata(os(path))
    };
    m.is_ok_and(|m| m.is_dir())
}

/// Whether `a` and `b` name the same entry of the same directory.
fn same_dirent(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    let split = |p: &[u8]| match p.iter().rposition(|&c| c == b'/') {
        Some(i) => (p[..i + 1].to_vec(), p[i + 1..].to_vec()),
        None => (b".".to_vec(), p.to_vec()),
    };
    let ((da, fa), (db, fb)) = (split(a), split(b));
    if fa != fb {
        return false;
    }
    match (std::fs::metadata(os(&da)), std::fs::metadata(os(&db))) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

struct Opts {
    symbolic: bool,
    force: bool,
    interactive: bool,
    remove_dir: bool,
    no_follow_target: bool,
    physical: bool,
    verbose: bool,
    warn_missing: bool,
}

/// Links `source` as `target`, or into it, `into_dir` saying it must be a directory. `true`
/// on success.
fn link_it(o: &Opts, source: &[u8], target: &[u8], into_dir: bool) -> bool {
    if !o.symbolic {
        // A hard link needs a source, and not a directory.
        let m = if o.physical {
            std::fs::symlink_metadata(os(source))
        } else {
            std::fs::metadata(os(source))
        };
        match m {
            Err(e) => {
                warn(source, errno_of(&e));
                return false;
            }
            Ok(m) if m.is_dir() => {
                warn(source, libc::EISDIR);
                return false;
            }
            Ok(_) => {}
        }
    }
    let mut target = target.to_vec();
    if !o.remove_dir
        && (into_dir || is_dir(&target, false) || (!o.no_follow_target && is_dir(&target, true)))
    {
        target.push(b'/');
        target.extend_from_slice(basename(source));
    }
    if o.symbolic && o.warn_missing {
        if source.first() == Some(&b'/') {
            if let Err(e) = std::fs::metadata(os(source)) {
                eprintln!(
                    "ln: warning: {} inaccessible: {}",
                    show(source),
                    strerror(errno_of(&e))
                );
            }
        } else {
            // A relative source is relative to the link's directory.
            let mut full = dirname(&target).to_vec();
            full.push(b'/');
            full.extend_from_slice(source);
            if let Err(e) = std::fs::metadata(os(&full)) {
                eprintln!("ln: warning: {}: {}", show(source), strerror(errno_of(&e)));
            }
        }
    }
    let existing = std::fs::symlink_metadata(os(&target)).ok();
    if let Some(m) = &existing {
        if !o.symbolic && same_dirent(source, &target) {
            eprintln!(
                "ln: {} and {} are the same directory entry",
                show(source),
                show(&target)
            );
            return false;
        }
        let remove = if o.force {
            true
        } else if o.interactive {
            let _ = std::io::stdout().flush();
            eprint!("replace {}? ", show(&target));
            let _ = std::io::stderr().flush();
            let mut line = Vec::new();
            let _ = std::io::stdin().lock().read_until(b'\n', &mut line);
            if !matches!(line.first(), Some(b'y' | b'Y')) {
                eprintln!("not replaced");
                return false;
            }
            true
        } else {
            false
        };
        if remove {
            let r = if o.remove_dir && m.is_dir() {
                std::fs::remove_dir(os(&target))
            } else {
                std::fs::remove_file(os(&target))
            };
            if let Err(e) = r {
                warn(&target, errno_of(&e));
                return false;
            }
        }
    }
    let r = if o.symbolic {
        std::os::unix::fs::symlink(os(source), os(&target))
    } else {
        let (s, t) = (
            CString::new(source).unwrap_or_default(),
            CString::new(target.clone()).unwrap_or_default(),
        );
        let flags = if o.physical {
            0
        } else {
            libc::AT_SYMLINK_FOLLOW
        };
        // SAFETY: two NUL-terminated paths.
        if unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                s.as_ptr(),
                libc::AT_FDCWD,
                t.as_ptr(),
                flags,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    if let Err(e) = r {
        warn(&target, errno_of(&e));
        return false;
    }
    if o.verbose {
        let mut line = target;
        line.extend_from_slice(if o.symbolic { b" -> " } else { b" => " });
        line.extend_from_slice(source);
        line.push(b'\n');
        let _ = std::io::stdout().lock().write_all(&line);
    }
    true
}

fn main() -> ExitCode {
    // SAFETY: the BSDs' default: a closed pipe (under -v) ends us quietly.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut o = Opts {
        symbolic: false,
        force: false,
        interactive: false,
        remove_dir: false,
        no_follow_target: false,
        physical: false,
        verbose: false,
        warn_missing: false,
    };
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
                b'F' => o.remove_dir = true,
                b'L' => o.physical = false,
                b'P' => o.physical = true,
                b'f' => (o.force, o.interactive, o.warn_missing) = (true, false, false),
                b'h' | b'n' => o.no_follow_target = true,
                b'i' => (o.interactive, o.force) = (true, false),
                b's' => o.symbolic = true,
                b'v' => o.verbose = true,
                b'w' => o.warn_missing = true,
                _ => {
                    eprintln!("ln: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
        i += 1;
    }
    if !o.symbolic {
        o.remove_dir = false;
    }
    if o.remove_dir && !o.interactive {
        (o.force, o.warn_missing) = (true, false);
    }
    let ops: Vec<Vec<u8>> = args[i..].iter().map(|a| a.clone().into_vec()).collect();
    let ok = match ops.len() {
        0 => return usage(),
        1 => link_it(&o, &ops[0], b".", true),
        2 => link_it(&o, &ops[0], &ops[1], false),
        n => {
            let dir = &ops[n - 1];
            if o.no_follow_target
                && std::fs::symlink_metadata(os(dir)).is_ok_and(|m| m.file_type().is_symlink())
            {
                warn(dir, libc::ENOTDIR);
                return ExitCode::FAILURE;
            }
            match std::fs::metadata(os(dir)) {
                Err(e) => {
                    warn(dir, errno_of(&e));
                    return ExitCode::FAILURE;
                }
                Ok(m) if !m.is_dir() => return usage(),
                Ok(_) => {}
            }
            let mut ok = true;
            for s in &ops[..n - 1] {
                ok &= link_it(&o, s, dir, true);
            }
            ok
        }
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
