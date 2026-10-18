//! `mv(1)`: moves (renames) files.
//!
//! ```text
//! mv [-f | -i | -n] [-hv] source target
//! mv [-f | -i | -n] [-v] source ... directory
//! ```
//!
//! POSIX's mv with the BSDs' options. With a directory as the last operand each source is moved
//! into it under its own name.
//!
//! An existing target is replaced, asking first (on stderr, the answer from stdin) with `-i`, or
//! when the target can't be written and stdin is a terminal; `-f` never asks, `-n` never replaces.
//! The last of the three counts. `-h`: a target that is a symbolic link to a directory is replaced
//! rather than moved into. `-v` names each file moved.
//!
//! A move is `rename(2)`. Between file systems (`EXDEV`) it is a copy and a removal, as FreeBSD's
//! mv does: a regular file is copied with its mode, owner, group and times; anything else is
//! copied as `cp -PRp` would (links as links, devices and FIFOs made anew), any target removed
//! first; the source goes only once all of it was copied. A mount point is never moved.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Clobber {
    Default,
    Force,
    Ask,
    Never,
}

struct Run {
    clobber: Clobber,
    verbose: bool,
    out: io::BufWriter<io::Stdout>,
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn cpath(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).unwrap_or_default()
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: mv [-f | -i | -n] [-hv] source target\n       mv [-f | -i | -n] [-v] source ... directory"
    );
    ExitCode::from(1)
}

/// strmode(3)'s nine permission characters.
fn perm_string(mode: u32) -> String {
    let mut s = String::new();
    for (i, c) in "rwxrwxrwx".chars().enumerate() {
        let bit = 0o400 >> i;
        let special = match i {
            2 => Some((0o4000, 's', 'S')),
            5 => Some((0o2000, 's', 'S')),
            8 => Some((0o1000, 't', 'T')),
            _ => None,
        };
        s.push(match special {
            Some((m, on, off)) if mode & m != 0 => {
                if mode & bit != 0 {
                    on
                } else {
                    off
                }
            }
            _ if mode & bit != 0 => c,
            _ => '-',
        });
    }
    s
}

fn user_name(uid: u32) -> String {
    // SAFETY: the record is read at once.
    let p = unsafe { libc::getpwuid(uid) };
    if p.is_null() { uid.to_string() } else { unsafe { CStr::from_ptr((*p).pw_name) }.to_string_lossy().into_owned() }
}

fn group_name(gid: u32) -> String {
    // SAFETY: the record is read at once.
    let g = unsafe { libc::getgrgid(gid) };
    if g.is_null() { gid.to_string() } else { unsafe { CStr::from_ptr((*g).gr_name) }.to_string_lossy().into_owned() }
}

fn set_times(path: &Path, md: &Metadata, link: bool) -> io::Result<()> {
    let ts = [
        libc::timespec { tv_sec: md.atime() as _, tv_nsec: md.atime_nsec() as _ },
        libc::timespec { tv_sec: md.mtime() as _, tv_nsec: md.mtime_nsec() as _ },
    ];
    let flags = if link { libc::AT_SYMLINK_NOFOLLOW } else { 0 };
    // SAFETY: a NUL-terminated path and two timespecs.
    if unsafe { libc::utimensat(libc::AT_FDCWD, cpath(path).as_ptr(), ts.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Gives `to` `md`'s owner, group, mode and times (as `cp -p`). Errors are warned about; the
/// copy still counts.
fn preserve(to: &Path, md: &Metadata, link: bool) {
    let c = cpath(to);
    let mut mode = md.mode() & 0o7777;
    // SAFETY: a NUL-terminated path.
    let r = unsafe {
        if link { libc::lchown(c.as_ptr(), md.uid(), md.gid()) } else { libc::chown(c.as_ptr(), md.uid(), md.gid()) }
    };
    if r != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EPERM) {
            eprintln!("mv: {}: set owner/group: {}", to.display(), strerror(&e));
        }
        mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
    }
    if !link && let Err(e) = fs::set_permissions(to, fs::Permissions::from_mode(mode)) {
        eprintln!("mv: {}: set mode: {}", to.display(), strerror(&e));
    }
    if let Err(e) = set_times(to, md, link)
        && !(link && e.raw_os_error() == Some(libc::EOPNOTSUPP))
    {
        eprintln!("mv: {}: set times: {}", to.display(), strerror(&e));
    }
}

/// Copies the tree at `from` to `to` (which doesn't exist), as `cp -PRp`. False if anything
/// failed (it was said why).
fn copy_tree(from: &Path, to: &Path) -> bool {
    let md = match fs::symlink_metadata(from) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mv: {}: {}", from.display(), strerror(&e));
            return false;
        }
    };
    let ft = md.file_type();
    let fail = |p: &Path, e: io::Error| {
        eprintln!("mv: {}: {}", p.display(), strerror(&e));
        false
    };
    if ft.is_dir() {
        if let Err(e) = fs::create_dir(to) {
            return fail(to, e);
        }
        let mut ok = true;
        match fs::read_dir(from) {
            Ok(rd) => {
                for de in rd {
                    match de {
                        Ok(de) => ok &= copy_tree(&de.path(), &to.join(de.file_name())),
                        Err(e) => ok = fail(from, e),
                    }
                }
            }
            Err(e) => ok = fail(from, e),
        }
        preserve(to, &md, false);
        ok
    } else if ft.is_symlink() {
        match fs::read_link(from).and_then(|t| std::os::unix::fs::symlink(t, to)) {
            Ok(()) => {
                preserve(to, &md, true);
                true
            }
            Err(e) => fail(to, e),
        }
    } else if ft.is_file() {
        copy_file(from, to, &md)
    } else {
        let c = cpath(to);
        // SAFETY: a NUL-terminated path.
        let r = if ft.is_fifo() {
            unsafe { libc::mkfifo(c.as_ptr(), (md.mode() & 0o7777) as libc::mode_t) }
        } else if ft.is_char_device() || ft.is_block_device() || ft.is_socket() {
            unsafe { libc::mknod(c.as_ptr(), md.mode() as libc::mode_t, md.rdev() as libc::dev_t) }
        } else {
            0
        };
        if r != 0 {
            return fail(to, io::Error::last_os_error());
        }
        preserve(to, &md, false);
        true
    }
}

/// FreeBSD's `fastcopy`: a regular file, its contents, owner, mode and times.
fn copy_file(from: &Path, to: &Path, md: &Metadata) -> bool {
    let fail = |p: &Path, e: io::Error| {
        eprintln!("mv: {}: {}", p.display(), strerror(&e));
        false
    };
    let mut src = match File::open(from) {
        Ok(f) => f,
        Err(e) => return fail(from, e),
    };
    let mut dst = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(to) {
        Ok(f) => f,
        Err(e) => return fail(to, e),
    };
    if let Err(e) = io::copy(&mut src, &mut dst).and_then(|_| dst.sync_all()) {
        drop(dst);
        let _ = fs::remove_file(to);
        return fail(to, e);
    }
    drop(dst);
    preserve(to, md, false);
    true
}

/// Removes the tree at `p`.
fn remove_tree(p: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(p)?;
    if md.is_dir() { fs::remove_dir_all(p) } else { fs::remove_file(p) }
}

impl Run {
    /// Asks on stderr, the answer read from stdin: yes if it begins with `y`.
    fn ask(&mut self, question: &str) -> bool {
        let _ = self.out.flush();
        eprint!("{question}(y/n [n]) ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        let _ = io::stdin().lock().read_line(&mut line);
        matches!(line.as_bytes().first(), Some(b'y' | b'Y'))
    }

    /// Moves `from` to `to`. True on success.
    fn do_move(&mut self, from: &Path, to: &Path) -> bool {
        let src_md = match fs::symlink_metadata(from) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("mv: {}: {}", from.display(), strerror(&e));
                return false;
            }
        };
        if self.clobber != Clobber::Force && fs::symlink_metadata(to).is_ok() {
            let question = match self.clobber {
                Clobber::Never => {
                    if self.verbose {
                        let _ = writeln!(self.out, "{} not overwritten", to.display());
                    }
                    return true;
                }
                Clobber::Ask => Some(format!("overwrite {}? ", to.display())),
                _ => {
                    // SAFETY: NUL-terminated path; isatty only looks.
                    let writable = unsafe { libc::access(cpath(to).as_ptr(), libc::W_OK) } == 0;
                    match fs::metadata(to) {
                        Ok(t) if !writable && unsafe { libc::isatty(0) } == 1 => Some(format!(
                            "override {} {}/{} for {}? ",
                            perm_string(t.mode()),
                            user_name(t.uid()),
                            group_name(t.gid()),
                            to.display()
                        )),
                        _ => None,
                    }
                }
            };
            if let Some(q) = question
                && !self.ask(&q)
            {
                eprintln!("not overwritten");
                return true;
            }
        }
        match fs::rename(from, to) {
            Ok(()) => {
                if self.verbose {
                    let _ = writeln!(self.out, "{} -> {}", from.display(), to.display());
                }
                return true;
            }
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {}
            Err(e) => {
                eprintln!("mv: rename {} to {}: {}", from.display(), to.display(), strerror(&e));
                return false;
            }
        }
        // Another file system: copy, then remove. Never a mount point.
        if !src_md.file_type().is_symlink() {
            let parent = from.join("..");
            if let Ok(p) = fs::metadata(&parent)
                && src_md.is_dir()
                && (p.dev() != src_md.dev() || p.ino() == src_md.ino())
            {
                eprintln!("mv: cannot rename a mount point");
                return false;
            }
        }
        if let Ok(t) = fs::symlink_metadata(to) {
            let r = if t.is_dir() { fs::remove_dir(to) } else { fs::remove_file(to) };
            if let Err(e) = r {
                let what = if t.is_dir() { "rmdir" } else { "unlink" };
                eprintln!("mv: {what} {}: {}", to.display(), strerror(&e));
                return false;
            }
        }
        let ok = if src_md.file_type().is_file() { copy_file(from, to, &src_md) } else { copy_tree(from, to) };
        if !ok {
            eprintln!("mv: {}: not removed: the copy failed", from.display());
            return false;
        }
        if let Err(e) = remove_tree(from) {
            eprintln!("mv: {}: remove: {}", from.display(), strerror(&e));
            return false;
        }
        if self.verbose {
            let _ = writeln!(self.out, "{} -> {}", from.display(), to.display());
        }
        true
    }
}

/// The last path component of `p`, trailing slashes ignored.
fn base_name(p: &OsStr) -> &OsStr {
    let b = p.as_bytes();
    let end = b.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    let b = &b[..end];
    let start = b.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1);
    OsStr::from_bytes(&b[start..])
}

fn main() -> ExitCode {
    let mut clobber = Clobber::Default;
    let (mut no_deref, mut verbose) = (false, false);
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
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
                b'f' => clobber = Clobber::Force,
                b'i' => clobber = Clobber::Ask,
                b'n' => clobber = Clobber::Never,
                b'h' => no_deref = true,
                b'v' => verbose = true,
                _ => {
                    eprintln!("mv: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
        i += 1;
    }
    let ops = &args[i..];
    if ops.len() < 2 {
        return usage();
    }
    let mut run = Run { clobber, verbose, out: io::BufWriter::new(io::stdout()) };
    let (sources, target) = ops.split_at(ops.len() - 1);
    let target = PathBuf::from(&target[0]);
    let target_is_dir = fs::metadata(&target).map(|m| m.is_dir()).unwrap_or(false);
    let ok = if !target_is_dir {
        if sources.len() > 1 {
            eprintln!("mv: {} is not a directory", target.display());
            return ExitCode::from(1);
        }
        run.do_move(Path::new(&sources[0]), &target)
    } else if no_deref
        && sources.len() == 1
        && fs::symlink_metadata(&target).map(|m| m.file_type().is_symlink()).unwrap_or(false)
    {
        // -h: replace the link to the directory, not move into it.
        run.do_move(Path::new(&sources[0]), &target)
    } else {
        if no_deref && sources.len() > 1 {
            return usage();
        }
        let mut ok = true;
        for s in sources {
            let to = target.join(base_name(s));
            ok &= run.do_move(Path::new(s), &to);
        }
        ok
    };
    let _ = run.out.flush();
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
