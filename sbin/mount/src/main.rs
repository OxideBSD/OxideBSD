//! `mount(8)`: mounts file systems with `nmount(2)`, lists them, or mounts `/etc/fstab`'s.
//!
//! ```text
//! mount                                     list what is mounted
//! mount -a [-v] [-t type[,type...]]         mount fstab's entries (not noauto, not /)
//! mount [-v] [-t type] [-o options] special node
//! mount [-v] node | special                 as fstab says
//! mount --bind directory node               the same as -t nullfs
//! mount_nullfs [-o options] target node     the same as -t nullfs
//! mount_tmpfs [-o options] tmpfs node        the same as -t tmpfs
//! mount -u [-rw] [-o options] node          change a mounted file system
//! ```
//!
//! The types are `tmpfs` (`tmpfs(5)`) and `nullfs` (a directory seen again at another place,
//! Linux's bind mount). Options are passed to the kernel, which takes `ro`, `rw`, `nosuid`,
//! `noexec` and `wxallowed` itself and gives the rest to the type (`size=` for tmpfs). `-u` changes
//! a mounted file system: between read-only and read-write (`-r`/`-o ro`, `-w`/`-o rw`, as in
//! FreeBSD; `/etc/rc` mounts the root read-write after checking it), and its type's options
//! (`mount -u -o size=64m /tmp`). Without `-r` or `-w` it stays as it is.

use std::ffi::CString;
use std::process::ExitCode;

/// `nmount(2)` (`sys/modules/oxfs`).
const SYS_NMOUNT: libc::c_long = 584;
/// FreeBSD's `MNT_RDONLY` and `MNT_UPDATE`.
const MNT_RDONLY: libc::c_int = 0x1;
const MNT_UPDATE: libc::c_int = 0x0001_0000;

/// Mounts with `nmount(2)`: `pairs` are the name/value options. On failure, the kernel's own
/// explanation when it gave one, else the errno's.
fn nmount(pairs: &[(&str, &str)]) -> Result<(), String> {
    nmount_flags(pairs, 0)
}

fn nmount_flags(pairs: &[(&str, &str)], flags: libc::c_int) -> Result<(), String> {
    let mut strings: Vec<CString> = Vec::new();
    for (n, v) in pairs {
        strings.push(CString::new(*n).map_err(|_| "a NUL in an option".to_string())?);
        strings.push(CString::new(*v).map_err(|_| "a NUL in an option".to_string())?);
    }
    let mut errmsg = [0u8; 256];
    let errname = c"errmsg";
    let mut iov: Vec<libc::iovec> = strings
        .iter()
        .map(|s| libc::iovec {
            iov_base: s.as_ptr() as *mut _,
            iov_len: s.as_bytes_with_nul().len(),
        })
        .collect();
    iov.push(libc::iovec {
        iov_base: errname.as_ptr() as *mut _,
        iov_len: errname.to_bytes_with_nul().len(),
    });
    iov.push(libc::iovec {
        iov_base: errmsg.as_mut_ptr().cast(),
        iov_len: errmsg.len(),
    });
    // SAFETY: an array of iovecs over live strings and buffers.
    let r = unsafe { libc::syscall(SYS_NMOUNT, iov.as_ptr(), iov.len() as libc::c_uint, flags) };
    if r == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    let end = errmsg.iter().position(|&b| b == 0).unwrap_or(0);
    Err(if end > 0 {
        String::from_utf8_lossy(&errmsg[..end]).into_owned()
    } else {
        e.to_string()
    })
}

fn mount_one(
    vfstype: &str,
    spec: &str,
    node: &str,
    options: &[String],
    verbose: bool,
) -> Result<(), String> {
    let mut pairs: Vec<(&str, &str)> = vec![("fstype", vfstype), ("fspath", node)];
    if vfstype == "nullfs" {
        pairs.push(("target", spec));
    }
    // fstab options that are for mount itself, not the kernel.
    const FOR_MOUNT: [&str; 4] = ["noauto", "late", "failok", "sw"];
    for o in options
        .iter()
        .filter(|o| !o.is_empty() && !FOR_MOUNT.contains(&o.as_str()))
    {
        match o.split_once('=') {
            Some((n, v)) => pairs.push((n, v)),
            None => pairs.push((o.as_str(), "")),
        }
    }
    nmount(&pairs)?;
    if verbose {
        println!("{spec} on {node} ({vfstype}, local)");
    }
    Ok(())
}

fn list() {
    for m in fstab::mounted() {
        let ro = if m.rdonly { ", read-only" } else { "" };
        println!("{} on {} ({}, local{ro})", m.spec, m.file, m.vfstype);
    }
}

/// Whether `vfstype` is selected by a `-t` list (`tmpfs,nullfs`, or `notmpfs` to exclude).
fn type_selected(list: Option<&str>, vfstype: &str) -> bool {
    let Some(list) = list else { return true };
    match list.strip_prefix("no") {
        Some(excluded) => !excluded.split(',').any(|t| t == vfstype),
        None => list.split(',').any(|t| t == vfstype),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: mount [-av] [-t type] [-o options] [special | node] ...");
    eprintln!("       mount --bind directory node");
    eprintln!("       mount -u [-rw] [-o options] node");
    ExitCode::from(1)
}

/// `mount -u`: changes the file system mounted on `node` (or on the node fstab gives `node` as a
/// device for): read-only or read-write (`rdonly`; `None` keeps what it is), and `options`.
fn update(node: &str, rdonly: Option<bool>, options: &[String], verbose: bool) -> Result<(), String> {
    let entries = fstab::read().map(|r| r.0).unwrap_or_default();
    let node = entries
        .iter()
        .find(|e| e.spec == node)
        .map_or(node.to_string(), |e| e.file.clone());
    let rdonly = rdonly.unwrap_or_else(|| fstab::mounted().iter().any(|m| m.file == node && m.rdonly));
    let flags = MNT_UPDATE | if rdonly { MNT_RDONLY } else { 0 };
    let mut pairs: Vec<(&str, &str)> = vec![("fspath", &node)];
    for o in options.iter().filter(|o| !o.is_empty()) {
        match o.split_once('=') {
            Some((n, v)) => pairs.push((n, v)),
            None => pairs.push((o.as_str(), "")),
        }
    }
    nmount_flags(&pairs, flags).map_err(|why| format!("{node}: {why}"))?;
    if verbose {
        println!("{node}: now {}", if rdonly { "read-only" } else { "read-write" });
    }
    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let name = argv
        .first()
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_string())
        .unwrap_or_default();
    let mut all = false;
    let mut verbose = false;
    let mut updating = false;
    let mut rdonly = false;
    let mut vfstype: Option<String> = match name.as_str() {
        "mount_nullfs" => Some("nullfs".to_string()),
        "mount_tmpfs" => Some("tmpfs".to_string()),
        _ => None,
    };
    // `-r`/`-w` given, for `-u` (which otherwise keeps the current mode).
    let mut mode_given = false;
    let mut options: Vec<String> = Vec::new();
    let mut rest: Vec<String> = Vec::new();
    let mut args = argv.into_iter().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--bind" => vfstype = Some("nullfs".into()),
            "--" => {
                rest.extend(args.by_ref());
                break;
            }
            s if s.starts_with('-') && s.len() > 1 => {
                let mut flags = s[1..].chars();
                while let Some(c) = flags.next() {
                    let mut value = || {
                        let tail: String = flags.by_ref().collect();
                        if tail.is_empty() {
                            args.next()
                        } else {
                            Some(tail)
                        }
                    };
                    match c {
                        'a' => all = true,
                        'v' => verbose = true,
                        'u' => updating = true,
                        'r' => {
                            rdonly = true;
                            mode_given = true;
                        }
                        'w' => {
                            rdonly = false;
                            mode_given = true;
                        }
                        't' => match value() {
                            Some(t) => vfstype = Some(t),
                            None => return usage(),
                        },
                        'o' => match value() {
                            Some(o) => options.extend(o.split(',').map(String::from)),
                            None => return usage(),
                        },
                        _ => return usage(),
                    }
                }
            }
            _ => rest.push(a),
        }
    }

    if updating {
        let mut rest_options = Vec::new();
        for o in &options {
            match o.as_str() {
                "ro" | "rdonly" => {
                    rdonly = true;
                    mode_given = true;
                }
                "rw" => {
                    rdonly = false;
                    mode_given = true;
                }
                _ => rest_options.push(o.clone()),
            }
        }
        let [node] = rest.as_slice() else { return usage() };
        return match update(node, mode_given.then_some(rdonly), &rest_options, verbose) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mount: {e}");
                ExitCode::from(1)
            }
        };
    }

    if all {
        let (entries, errors) = match fstab::read() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("mount: {}: {e}", fstab::PATH);
                return ExitCode::from(1);
            }
        };
        for (line, e) in errors {
            eprintln!("mount: {} line {line}: {e}", fstab::PATH);
        }
        let mounted = fstab::mounted();
        let mut failed = false;
        for e in entries {
            let skip = e.file == "/"
                || e.has_option("noauto")
                || e.has_option("sw")
                || e.vfstype == "swap"
                || !type_selected(vfstype.as_deref(), &e.vfstype)
                || mounted.iter().any(|m| m.file == e.file);
            if skip {
                continue;
            }
            if let Err(why) = mount_one(&e.vfstype, &e.spec, &e.file, &e.options, verbose) {
                eprintln!("mount: {}: {why}", e.file);
                failed = true;
            }
        }
        return if failed {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }

    let result = match rest.as_slice() {
        [] if vfstype.is_none() && options.is_empty() => {
            list();
            return ExitCode::SUCCESS;
        }
        [one] => {
            let entries = fstab::read().map(|r| r.0).unwrap_or_default();
            match entries.iter().find(|e| &e.file == one || &e.spec == one) {
                Some(e) => {
                    let mut opts = e.options.clone();
                    opts.extend(options.iter().cloned());
                    mount_one(
                        vfstype.as_deref().unwrap_or(&e.vfstype),
                        &e.spec,
                        &e.file,
                        &opts,
                        verbose,
                    )
                    .map_err(|why| format!("{}: {why}", e.file))
                }
                None => Err(format!("{one}: not in {}", fstab::PATH)),
            }
        }
        [special, node] => {
            let t = vfstype
                .clone()
                .or_else(|| (special == "tmpfs").then(|| "tmpfs".to_string()));
            match t {
                Some(t) => mount_one(&t, special, node, &options, verbose)
                    .map_err(|why| format!("{node}: {why}")),
                None => Err(format!("{special}: no file system type; give one with -t")),
            }
        }
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mount: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_lists() {
        assert!(type_selected(None, "tmpfs"));
        assert!(type_selected(Some("tmpfs,nullfs"), "nullfs"));
        assert!(!type_selected(Some("tmpfs"), "nullfs"));
        assert!(!type_selected(Some("notmpfs"), "tmpfs"));
        assert!(type_selected(Some("notmpfs,devfs"), "nullfs"));
    }
}
