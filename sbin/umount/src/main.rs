//! `umount(8)`: unmounts file systems.
//!
//! ```text
//! umount [-fv] special | node ...
//! umount -a [-fv] [-t type[,type...]]      fstab's entries that are mounted, last first, not /
//! ```
//!
//! `-f` forces the unmount even while files on it are in use.

use std::ffi::CString;
use std::process::ExitCode;

fn unmount(node: &str, force: bool) -> Result<(), String> {
    let c = CString::new(node).map_err(|_| "a NUL in the name".to_string())?;
    let flags = if force { libc::MNT_FORCE } else { 0 };
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::umount2(c.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

fn type_selected(list: Option<&str>, vfstype: &str) -> bool {
    let Some(list) = list else { return true };
    match list.strip_prefix("no") {
        Some(excluded) => !excluded.split(',').any(|t| t == vfstype),
        None => list.split(',').any(|t| t == vfstype),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: umount [-fv] special | node ...");
    eprintln!("       umount -a [-fv] [-t type]");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let mut all = false;
    let mut force = false;
    let mut verbose = false;
    let mut types: Option<String> = None;
    let mut names: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--" {
            names.extend(args.by_ref());
            break;
        }
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            names.push(a);
            continue;
        };
        let mut chars = flags.chars();
        while let Some(c) = chars.next() {
            match c {
                'a' => all = true,
                'f' => force = true,
                'v' => verbose = true,
                't' => {
                    let tail: String = chars.by_ref().collect();
                    types = if tail.is_empty() {
                        args.next()
                    } else {
                        Some(tail)
                    };
                    if types.is_none() {
                        return usage();
                    }
                }
                _ => return usage(),
            }
        }
    }

    let mounted = fstab::mounted();
    let mut targets: Vec<String> = Vec::new();
    if all {
        if !names.is_empty() {
            return usage();
        }
        let entries = fstab::read().map(|r| r.0).unwrap_or_default();
        for e in entries.iter().rev() {
            if e.file != "/"
                && type_selected(types.as_deref(), &e.vfstype)
                && mounted.iter().any(|m| m.file == e.file)
            {
                targets.push(e.file.clone());
            }
        }
    } else {
        if names.is_empty() {
            return usage();
        }
        for n in names {
            // A special (tmpfs, a nullfs target) names its mount point; the last mount wins.
            let node = mounted
                .iter()
                .rev()
                .find(|m| m.file == n)
                .or_else(|| mounted.iter().rev().find(|m| m.spec == n))
                .map(|m| m.file.clone())
                .unwrap_or(n);
            targets.push(node);
        }
    }
    let mut failed = false;
    for node in targets {
        match unmount(&node, force) {
            Ok(()) if verbose => println!("{node}: unmounted"),
            Ok(()) => {}
            Err(e) => {
                eprintln!("umount: {node}: {e}");
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
