//! `rm(1)`: removes directory entries.
//!
//! ```text
//! rm [-f | -i] [-dIPRrvx] file ...
//! ```
//!
//! A directory is refused unless `-d` (an empty one, with `rmdir(2)`) or `-R`/`-r` (it and
//! everything in it, depth first, never following a symbolic link) is given. `-f` never asks and
//! is quiet about files that don't exist; `-i` asks before each removal (the last of the two
//! counts). Without either, a file that isn't writable is asked about when the standard input is
//! a terminal (POSIX). `-I` asks once, before starting, when more than three files or a
//! directory tree (`-R`) are to go. `-v` names each file removed; `-x` doesn't cross into
//! another file system under `-R`. `-P` is accepted and does nothing, as on FreeBSD.
//!
//! Questions go to the standard error; an answer beginning `y` or `Y` is yes. `.`, `..` (as an
//! operand's last component) and the root directory are never removed.

use std::ffi::{CStr, CString, OsString};
use std::io::{BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: rm [-f | -i] [-dIPRrvx] file ...");
    ExitCode::FAILURE
}

fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a NUL-terminated string.
    unsafe { CStr::from_ptr(libc::strerror(n)) }
        .to_string_lossy()
        .into_owned()
}

fn os_errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn cpath(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap_or_default()
}

/// Reads a line of the standard input: yes if it begins with `y` or `Y`. `None` at end of file.
fn answer() -> Option<bool> {
    let mut line = Vec::new();
    match std::io::stdin().lock().read_until(b'\n', &mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(matches!(line.first(), Some(b'y' | b'Y'))),
    }
}

/// `strmode(3)`'s permission part: `rwxr-xr-x`, with `s`/`S` and `t`/`T`.
fn perms(mode: u32) -> String {
    let mut s = String::new();
    for (shift, special, c) in [(6, 0o4000, 's'), (3, 0o2000, 's'), (0, 0o1000, 't')] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(match (bits & 1 != 0, mode & special != 0) {
            (true, true) => c,
            (false, true) => c.to_ascii_uppercase(),
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    s
}

fn user_name(uid: u32) -> String {
    // SAFETY: getpwuid's result is read before any other call can reuse it.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            uid.to_string()
        } else {
            CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
        }
    }
}

fn group_name(gid: u32) -> String {
    // SAFETY: as for getpwuid.
    unsafe {
        let gr = libc::getgrgid(gid);
        if gr.is_null() {
            gid.to_string()
        } else {
            CStr::from_ptr((*gr).gr_name).to_string_lossy().into_owned()
        }
    }
}

struct Rm {
    force: bool,
    interactive: bool,
    dirs: bool,
    recurse: bool,
    verbose: bool,
    xdev: bool,
    stdin_ok: bool,
    failed: bool,
}

impl Rm {
    fn warn(&mut self, path: &Path, err: i32) {
        eprintln!("rm: {}: {}", path.display(), strerror(err));
        self.failed = true;
    }

    /// Reports a failure, unless it is `-f` and the file was already gone.
    fn complain(&mut self, path: &Path, err: i32) {
        if !(self.force && err == libc::ENOENT) {
            self.warn(path, err);
        }
    }

    fn removed(&self, path: &Path) {
        if self.verbose {
            let mut out = std::io::stdout().lock();
            let _ = out
                .write_all(path.as_os_str().as_bytes())
                .and_then(|_| out.write_all(b"\n"));
        }
    }

    /// Whether to go ahead with `path`: with `-i`, if the user says so; otherwise, unless it is
    /// an unwritable file (not a symbolic link) and the user, asked at a terminal, says no.
    fn check(&self, path: &Path, md: &std::fs::Metadata) -> bool {
        if self.interactive {
            eprint!("remove {}? ", path.display());
        } else {
            // SAFETY: a NUL-terminated path.
            if !self.stdin_ok
                || md.file_type().is_symlink()
                || unsafe { libc::access(cpath(path).as_ptr(), libc::W_OK) } == 0
            {
                return true;
            }
            eprint!(
                "override {} {}/{} for {}? ",
                perms(md.mode()),
                user_name(md.uid()),
                group_name(md.gid()),
                path.display()
            );
        }
        let _ = std::io::stderr().flush();
        answer().unwrap_or(false)
    }

    fn unlink(&mut self, path: &Path, dir: bool) -> bool {
        let r = if dir {
            std::fs::remove_dir(path)
        } else {
            std::fs::remove_file(path)
        };
        match r {
            Ok(()) => {
                self.removed(path);
                true
            }
            Err(e) => {
                self.complain(path, os_errno(&e));
                false
            }
        }
    }

    /// Without `-R`: one file, or with `-d` an empty directory.
    fn file(&mut self, path: &Path) {
        let md = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => return self.complain(path, os_errno(&e)),
        };
        if md.is_dir() && !self.dirs {
            eprintln!("rm: {}: is a directory", path.display());
            self.failed = true;
            return;
        }
        if !self.force && !self.check(path, &md) {
            return;
        }
        self.unlink(path, md.is_dir());
    }

    /// `-R`: `path` and, depth first, everything under it. `dev` is the file system of the
    /// operand, for `-x`.
    fn tree(&mut self, path: &Path, dev: Option<u64>) {
        let md = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => return self.complain(path, os_errno(&e)),
        };
        if !md.is_dir() {
            if self.force || self.check(path, &md) {
                self.unlink(path, false);
            }
            return;
        }
        if !self.force && !self.check(path, &md) {
            return;
        }
        let dev = dev.unwrap_or(md.dev());
        // -x: a directory of another file system is not entered; removing it fails below.
        if !(self.xdev && md.dev() != dev) {
            // Read the whole directory before removing from it.
            let names: Result<Vec<_>, _> = std::fs::read_dir(path)
                .and_then(|rd| rd.map(|e| e.map(|e| e.file_name())).collect());
            match names {
                Ok(mut names) => {
                    names.sort();
                    for n in names {
                        self.tree(&path.join(n), Some(dev));
                    }
                }
                Err(e) => {
                    // It can't be read, but an empty one may still be removed.
                    if std::fs::remove_dir(path).is_ok() {
                        return self.removed(path);
                    }
                    return self.complain(path, os_errno(&e));
                }
            }
        }
        self.unlink(path, true);
    }
}

/// `-I`: one question before anything is removed, if more than three files or a directory tree
/// are to go. False if the answer is no.
fn check_once(files: &[OsString], recurse: bool) -> bool {
    let (mut nfiles, mut ndirs, mut dir_name) = (0, 0, None);
    for f in files {
        if let Ok(md) = std::fs::symlink_metadata(f) {
            if md.is_dir() {
                ndirs += 1;
                dir_name = Some(f);
            } else {
                nfiles += 1;
            }
        }
    }
    let question = if ndirs > 0 && recurse {
        let mut q = String::from("recursively remove");
        match (ndirs, dir_name) {
            (1, Some(d)) => q += &format!(" {}", Path::new(d).display()),
            _ => q += &format!(" {ndirs} dirs"),
        }
        match nfiles {
            0 => {}
            1 => q += " and 1 file",
            n => q += &format!(" and {n} files"),
        }
        q
    } else if ndirs + nfiles > 3 {
        format!("remove {} files", ndirs + nfiles)
    } else {
        return true;
    };
    loop {
        eprint!("{question}? ");
        let _ = std::io::stderr().flush();
        let mut line = Vec::new();
        match std::io::stdin().lock().read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return false,
            Ok(_) => match line.first() {
                Some(b'y' | b'Y') => return true,
                Some(b'n' | b'N') => return false,
                _ => {}
            },
        }
    }
}

fn main() -> ExitCode {
    // SAFETY: the BSDs' default: a closed pipe (under -v) ends us quietly.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut rm = Rm {
        force: false,
        interactive: false,
        dirs: false,
        recurse: false,
        verbose: false,
        xdev: false,
        // SAFETY: isatty(3) on a descriptor number.
        stdin_ok: unsafe { libc::isatty(0) } == 1,
        failed: false,
    };
    let mut ask_once = false;
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
                b'd' => rm.dirs = true,
                b'f' => (rm.force, rm.interactive) = (true, false),
                b'i' => (rm.force, rm.interactive) = (false, true),
                b'I' => ask_once = true,
                b'P' => {} // overwriting before removal: a no-op, as on FreeBSD
                b'R' | b'r' => rm.recurse = true,
                b'v' => rm.verbose = true,
                b'x' => rm.xdev = true,
                _ => {
                    eprintln!("rm: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
        i += 1;
    }
    let operands = &args[i..];
    if operands.is_empty() {
        return if rm.force { ExitCode::SUCCESS } else { usage() };
    }
    // POSIX: an operand whose last component is . or .., or that is the root directory, gets
    // a diagnostic and is left alone.
    let root = std::fs::metadata("/").ok().map(|m| (m.dev(), m.ino()));
    let (mut said_dot, mut said_root) = (false, false);
    let mut files = Vec::new();
    for f in operands {
        let b = f.as_bytes();
        let trimmed = &b[..b.iter().rposition(|&c| c != b'/').map_or(0, |p| p + 1)];
        let last = trimmed.rsplit(|&c| c == b'/').next().unwrap_or(b"");
        if !trimmed.is_empty() && (last == b"." || last == b"..") {
            if !said_dot {
                eprintln!("rm: \".\" and \"..\" may not be removed");
                said_dot = true;
            }
            rm.failed = true;
            continue;
        }
        let is_root = std::fs::symlink_metadata(f)
            .ok()
            .map(|m| (m.dev(), m.ino()));
        if is_root.is_some() && is_root == root {
            if !said_root {
                eprintln!("rm: \"/\" may not be removed");
                said_root = true;
            }
            rm.failed = true;
            continue;
        }
        files.push(f.clone());
    }
    if ask_once && !files.is_empty() && !check_once(&files, rm.recurse) {
        return ExitCode::FAILURE;
    }
    for f in &files {
        if rm.recurse {
            rm.tree(Path::new(f), None);
        } else {
            rm.file(Path::new(f));
        }
    }
    if rm.failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
