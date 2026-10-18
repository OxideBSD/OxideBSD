//! `mknod(8)`: makes device special files.
//!
//! ```text
//! mknod name
//! mknod name [b | c] major minor [owner:group]
//! ```
//!
//! The second form makes a block (`b`) or character (`c`) special file, mode `0666` less the
//! umask, for the device `major`, `minor` (numbers as `strtoul(3)` reads them: `0x` hex, `0`
//! octal), and with `owner:group` (names or numbers, both needed) gives it to them. The first
//! form, as on FreeBSD, asks for a character special file of device 0, which recreates a node
//! deleted from `devfs(4)` where the file system allows it. FIFOs are `mkfifo(1)`'s.

use std::ffi::{CStr, CString};
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: mknod name");
    eprintln!("       mknod name [b | c] major minor [owner:group]");
    ExitCode::FAILURE
}

fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a NUL-terminated string.
    unsafe { CStr::from_ptr(libc::strerror(n)) }
        .to_string_lossy()
        .into_owned()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn fail(msg: String) -> ExitCode {
    eprintln!("mknod: {msg}");
    ExitCode::FAILURE
}

/// A whole number as `strtoul(3)` reads it, all of `s`: hexadecimal after `0x`, octal after
/// `0` (with `base` 0), else decimal. `Err(true)` when it is too large, `Err(false)` when it
/// isn't a number.
fn number(s: &str, base: u32) -> Result<u64, bool> {
    let t = s.trim_start().strip_prefix('+').unwrap_or(s.trim_start());
    let (digits, radix) = if base != 0 {
        (t, base)
    } else if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        (h, 16)
    } else if t.len() > 1 && t.starts_with('0') {
        (&t[1..], 8)
    } else {
        (t, 10)
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(false);
    }
    u64::from_str_radix(digits, radix).map_err(|_| true)
}

/// A user or group: a name, else a number.
fn id(s: &str, kind: &str) -> Result<u32, String> {
    let c = CString::new(s).map_err(|_| format!("{s}: illegal {kind} name"))?;
    // SAFETY: getpwnam/getgrnam's results are read at once.
    let found = unsafe {
        if kind == "user" {
            let pw = libc::getpwnam(c.as_ptr());
            (!pw.is_null()).then(|| (*pw).pw_uid)
        } else {
            let gr = libc::getgrnam(c.as_ptr());
            (!gr.is_null()).then(|| (*gr).gr_gid)
        }
    };
    if let Some(n) = found {
        return Ok(n);
    }
    match number(s, 10) {
        Ok(n) if n <= u32::MAX as u64 => Ok(n as u32),
        Err(false) => Err(format!("{s}: illegal {kind} name")),
        _ => Err(format!("{s}: {}", strerror(libc::ERANGE))),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if ![1, 4, 5].contains(&args.len()) {
        return usage();
    }
    let (mode, dev) = if args.len() >= 4 {
        let kind = match args[1].as_bytes().first() {
            Some(b'c') => libc::S_IFCHR,
            Some(b'b') => libc::S_IFBLK,
            _ => return fail("node must be type 'b' or 'c'".into()),
        };
        let major = match number(&args[2], 0) {
            Err(false) => return fail(format!("{}: non-numeric major number", args[2])),
            r => r,
        };
        let minor = match number(&args[3], 0) {
            Err(false) => return fail(format!("{}: non-numeric minor number", args[3])),
            r => r,
        };
        let (Ok(major), Ok(minor)) = (major, minor) else {
            return fail("major or minor number too large".into());
        };
        let (Ok(ma), Ok(mi)) = (u32::try_from(major), u32::try_from(minor)) else {
            return fail("major or minor number too large".into());
        };
        let dev = libc::makedev(ma, mi);
        if libc::major(dev) != ma || libc::minor(dev) != mi {
            return fail("major or minor number too large".into());
        }
        (0o666 | kind, dev)
    } else {
        (0o666 | libc::S_IFCHR, 0)
    };
    let mut owner = None;
    if args.len() == 5 {
        let Some((user, group)) = args[4].split_once(':') else {
            return usage();
        };
        if group.is_empty() {
            return fail("group must be specified when the owner is".into());
        }
        if user.is_empty() {
            return fail("owner must be specified when the group is".into());
        }
        let gid = match id(group, "group") {
            Ok(g) => g,
            Err(e) => return fail(e),
        };
        let uid = match id(user, "user") {
            Ok(u) => u,
            Err(e) => return fail(e),
        };
        owner = Some((uid, gid));
    }
    let name = &args[0];
    let c = CString::new(name.as_str()).unwrap_or_default();
    // SAFETY: a NUL-terminated path.
    if unsafe { libc::mknod(c.as_ptr(), mode as libc::mode_t, dev) } != 0 {
        return fail(format!("{name}: {}", strerror(errno())));
    }
    if let Some((uid, gid)) = owner {
        // SAFETY: as above.
        if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
            return fail(format!(
                "setting ownership on {name}: {}",
                strerror(errno())
            ));
        }
    }
    ExitCode::SUCCESS
}
