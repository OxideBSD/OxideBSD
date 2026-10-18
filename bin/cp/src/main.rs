//! `cp(1)`: copies files.
//!
//! ```text
//! cp [-R [-H | -L | -P]] [-f | -i | -n] [-alpsvx] source_file target_file
//! cp [-R [-H | -L | -P]] [-f | -i | -n] [-alpsvx] source_file ... target_directory
//! ```
//!
//! POSIX's cp with the BSDs' options. With a directory as the last operand each source is copied
//! into it under its own name.
//!
//! - `-R` copies directories and what is in them, and recreates symbolic links, FIFOs and devices
//!   rather than copying what they hold; following no symbolic links (`-P`, the default with
//!   `-R`), only those on the command line (`-H`), or all (`-L`). Without `-R` links are
//!   followed. `-r` is taken as `-R`.
//! - An existing target is overwritten in place; `-f` removes it and tries again if it can't be
//!   opened, `-i` asks first, `-n` leaves it alone. The last of the three counts.
//! - `-p` keeps each file's times, owner and group, and mode (set-user-ID and set-group-ID only
//!   when the owner could be kept). Otherwise a new file gets the source's mode less the umask and
//!   those two bits; an existing one keeps its own.
//! - `-a` is `-RpP`. `-l` makes hard links instead of copies, `-s` symbolic links. `-v` names each
//!   file as it is copied, `-x` stays on the file system each operand is on.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufRead, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Follow {
    Never,
    CommandLine,
    All,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Clobber {
    Overwrite,
    Force,
    Ask,
    Never,
}

struct Opts {
    recursive: bool,
    follow: Follow,
    clobber: Clobber,
    preserve: bool,
    hard_link: bool,
    sym_link: bool,
    verbose: bool,
    one_fs: bool,
}

struct Run {
    o: Opts,
    umask: u32,
    failed: bool,
    /// Directories this run made, so a copy into itself stops.
    made: Vec<(u64, u64)>,
    /// `-v`'s output, in one buffer (console writes are slow), flushed before a prompt.
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

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: cp [-R [-H | -L | -P]] [-f | -i | -n] [-alpsvx] source_file target_file\n       \
         cp [-R [-H | -L | -P]] [-f | -i | -n] [-alpsvx] source_file ... target_directory"
    );
    ExitCode::from(1)
}

/// Asks on stderr and reads the answer from stdin: yes if it begins with `y`.
fn ask(question: &str) -> bool {
    eprint!("{question}");
    let _ = io::stderr().flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    matches!(line.trim_start().as_bytes().first(), Some(b'y' | b'Y'))
}

/// Sets `path`'s times to `md`'s, without following a link at it if `link`.
fn set_times(path: &Path, md: &Metadata, link: bool) -> io::Result<()> {
    let ts = [
        libc::timespec { tv_sec: md.atime() as _, tv_nsec: md.atime_nsec() as _ },
        libc::timespec { tv_sec: md.mtime() as _, tv_nsec: md.mtime_nsec() as _ },
    ];
    let flags = if link { libc::AT_SYMLINK_NOFOLLOW } else { 0 };
    // SAFETY: a NUL-terminated path and two timespecs.
    if unsafe { libc::utimensat(libc::AT_FDCWD, cpath(path).as_ptr(), ts.as_ptr(), flags) } != 0 {
        return Err(last_err());
    }
    Ok(())
}

impl Run {
    fn complain(&mut self, what: &Path, e: &io::Error) {
        eprintln!("cp: {}: {}", what.display(), strerror(e));
        self.failed = true;
    }

    /// `-p`'s owner, mode and times for `to`, copied from `md`. `link`: `to` is a symbolic link.
    fn preserve(&mut self, to: &Path, md: &Metadata, link: bool) {
        let c = cpath(to);
        let mut mode = md.mode() & 0o7777;
        // SAFETY: a NUL-terminated path.
        let chowned = unsafe {
            if link {
                libc::lchown(c.as_ptr(), md.uid(), md.gid())
            } else {
                libc::chown(c.as_ptr(), md.uid(), md.gid())
            }
        } == 0;
        if !chowned {
            let e = last_err();
            if e.raw_os_error() != Some(libc::EPERM) {
                self.complain(to, &e);
            }
            // Not ours to give away: no set-user-ID or set-group-ID for someone else's file.
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
        if !link && let Err(e) = fs::set_permissions(to, fs::Permissions::from_mode(mode)) {
            self.complain(to, &e);
        }
        if let Err(e) = set_times(to, md, link)
            && !(link && e.raw_os_error() == Some(libc::EOPNOTSUPP))
        {
            self.complain(to, &e);
        }
    }

    /// Whether an existing `to` may be replaced, asking if -i. Prints what -n and -i say.
    fn may_replace(&mut self, to: &Path) -> bool {
        match self.o.clobber {
            Clobber::Never => {
                if self.o.verbose {
                    let _ = writeln!(self.out, "{} not overwritten", to.display());
                }
                false
            }
            Clobber::Ask => {
                let _ = self.out.flush();
                if ask(&format!("overwrite {}? (y/n [n]) ", to.display())) {
                    true
                } else {
                    eprintln!("not overwritten");
                    false
                }
            }
            _ => true,
        }
    }

    fn verbose(&mut self, from: &Path, to: &Path) {
        if self.o.verbose {
            let _ = writeln!(self.out, "{} -> {}", from.display(), to.display());
        }
    }

    /// Copies `from` (whose metadata is `md`) to `to`. `root_dev`: the operand's device, for -x.
    fn copy(&mut self, from: &Path, to: &Path, md: &Metadata, root_dev: u64) {
        let ft = md.file_type();
        if ft.is_dir() {
            if !self.o.recursive {
                eprintln!("cp: {} is a directory (not copied).", from.display());
                self.failed = true;
                return;
            }
            return self.copy_dir(from, to, md, root_dev);
        }
        let existing = fs::symlink_metadata(to).ok();
        if let Some(ex) = &existing {
            let same = fs::metadata(to).map(|t| t.dev() == md.dev() && t.ino() == md.ino()).unwrap_or(false);
            if same && !ft.is_symlink() {
                eprintln!("cp: {} and {} are identical (not copied).", from.display(), to.display());
                self.failed = true;
                return;
            }
            if ex.is_dir() {
                eprintln!("cp: cannot overwrite directory {} with non-directory {}", to.display(), from.display());
                self.failed = true;
                return;
            }
            if !self.may_replace(to) {
                return;
            }
        }
        if self.o.hard_link || self.o.sym_link {
            if existing.is_some()
                && let Err(e) = fs::remove_file(to)
            {
                return self.complain(to, &e);
            }
            let r = if self.o.hard_link {
                fs::hard_link(from, to)
            } else {
                std::os::unix::fs::symlink(from, to)
            };
            match r {
                Ok(()) => self.verbose(from, to),
                Err(e) => self.complain(to, &e),
            }
            return;
        }
        if self.o.recursive && ft.is_symlink() {
            return self.copy_link(from, to, md, existing.is_some());
        }
        if self.o.recursive && (ft.is_fifo() || ft.is_char_device() || ft.is_block_device() || ft.is_socket()) {
            return self.copy_special(from, to, md, existing.is_some());
        }
        self.copy_file(from, to, md, existing.is_some());
    }

    fn copy_file(&mut self, from: &Path, to: &Path, md: &Metadata, exists: bool) {
        let mut src = match File::open(from) {
            Ok(f) => f,
            Err(e) => return self.complain(from, &e),
        };
        let mode = md.mode() & 0o777 | (md.mode() & 0o1000);
        let create = |path: &Path| {
            OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path)
        };
        let dst = match create(to) {
            Ok(f) => f,
            Err(e) if exists && self.o.clobber == Clobber::Force => {
                // -f: remove what can't be opened and make it anew.
                match fs::remove_file(to).and_then(|_| create(to)) {
                    Ok(f) => f,
                    Err(_) => return self.complain(to, &e),
                }
            }
            Err(e) => return self.complain(to, &e),
        };
        let mut dst = dst;
        if let Err(e) = io::copy(&mut src, &mut dst) {
            return self.complain(to, &e);
        }
        drop(dst);
        if self.o.preserve {
            self.preserve(to, md, false);
        }
        self.verbose(from, to);
    }

    fn copy_link(&mut self, from: &Path, to: &Path, md: &Metadata, exists: bool) {
        let target = match fs::read_link(from) {
            Ok(t) => t,
            Err(e) => return self.complain(from, &e),
        };
        if exists && let Err(e) = fs::remove_file(to) {
            return self.complain(to, &e);
        }
        if let Err(e) = std::os::unix::fs::symlink(&target, to) {
            return self.complain(to, &e);
        }
        if self.o.preserve {
            self.preserve(to, md, true);
        }
        self.verbose(from, to);
    }

    fn copy_special(&mut self, from: &Path, to: &Path, md: &Metadata, exists: bool) {
        if exists && let Err(e) = fs::remove_file(to) {
            return self.complain(to, &e);
        }
        let c = cpath(to);
        let mode = (md.mode() & 0o7777) as libc::mode_t;
        // SAFETY: a NUL-terminated path.
        let r = if md.file_type().is_fifo() {
            unsafe { libc::mkfifo(c.as_ptr(), mode) }
        } else {
            unsafe { libc::mknod(c.as_ptr(), md.mode() as libc::mode_t, md.rdev() as libc::dev_t) }
        };
        if r != 0 {
            return self.complain(to, &last_err());
        }
        if self.o.preserve {
            self.preserve(to, md, false);
        }
        self.verbose(from, to);
    }

    fn copy_dir(&mut self, from: &Path, to: &Path, md: &Metadata, root_dev: u64) {
        if self.made.contains(&(md.dev(), md.ino())) {
            eprintln!("cp: {} is the copy being made, not copied.", from.display());
            self.failed = true;
            return;
        }
        let made_now = match fs::symlink_metadata(to) {
            Ok(ex) if ex.is_dir() => false,
            Ok(_) => {
                eprintln!("cp: cannot overwrite non-directory {} with directory {}", to.display(), from.display());
                self.failed = true;
                return;
            }
            Err(_) => {
                // Writable by us while it is filled; the real mode is set after.
                let c = cpath(to);
                // SAFETY: a NUL-terminated path.
                if unsafe { libc::mkdir(c.as_ptr(), ((md.mode() & 0o777) | 0o700) as libc::mode_t) } != 0 {
                    return self.complain(to, &last_err());
                }
                if let Ok(m) = fs::metadata(to) {
                    self.made.push((m.dev(), m.ino()));
                }
                true
            }
        };
        self.verbose(from, to);
        let entries = match fs::read_dir(from) {
            Ok(r) => r,
            Err(e) => {
                self.complain(from, &e);
                return;
            }
        };
        let mut names: Vec<OsString> = entries.flatten().map(|e| e.file_name()).collect();
        names.sort();
        for name in names {
            let f = from.join(&name);
            let t = to.join(&name);
            let md = if self.o.follow == Follow::All {
                fs::metadata(&f).or_else(|_| fs::symlink_metadata(&f))
            } else {
                fs::symlink_metadata(&f)
            };
            match md {
                Ok(m) => {
                    if self.o.one_fs && m.is_dir() && m.dev() != root_dev {
                        continue;
                    }
                    self.copy(&f, &t, &m, root_dev);
                }
                Err(e) => self.complain(&f, &e),
            }
        }
        if self.o.preserve {
            self.preserve(to, md, false);
        } else if made_now {
            let mode = md.mode() & 0o7777 & !self.umask;
            if let Err(e) = fs::set_permissions(to, fs::Permissions::from_mode(mode)) {
                self.complain(to, &e);
            }
        }
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
    let mut o = Opts {
        recursive: false,
        follow: Follow::Never,
        clobber: Clobber::Overwrite,
        preserve: false,
        hard_link: false,
        sym_link: false,
        verbose: false,
        one_fs: false,
    };
    let mut follow: Option<Follow> = None;
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
                b'R' | b'r' => o.recursive = true,
                b'H' => follow = Some(Follow::CommandLine),
                b'L' => follow = Some(Follow::All),
                b'P' => follow = Some(Follow::Never),
                b'f' => o.clobber = Clobber::Force,
                b'i' => o.clobber = Clobber::Ask,
                b'n' => o.clobber = Clobber::Never,
                b'a' => {
                    o.recursive = true;
                    o.preserve = true;
                    follow = Some(Follow::Never);
                }
                b'l' => {
                    o.hard_link = true;
                    o.sym_link = false;
                }
                b's' => {
                    o.sym_link = true;
                    o.hard_link = false;
                }
                b'p' => o.preserve = true,
                b'v' => o.verbose = true,
                b'x' => o.one_fs = true,
                _ => {
                    eprintln!("cp: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
        i += 1;
    }
    // Without -R, links are followed (what they point to is copied).
    o.follow = if o.recursive { follow.unwrap_or(Follow::Never) } else { Follow::All };
    let ops = &args[i..];
    if ops.len() < 2 {
        return usage();
    }
    let (sources, target) = ops.split_at(ops.len() - 1);
    let target = PathBuf::from(&target[0]);
    let target_is_dir = fs::metadata(&target).map(|m| m.is_dir()).unwrap_or(false);
    if sources.len() > 1 && !target_is_dir {
        eprintln!("cp: {}: {}", target.display(), strerror(&io::Error::from_raw_os_error(libc::ENOTDIR)));
        return ExitCode::from(1);
    }
    // SAFETY: umask can't fail; it is put back at once.
    let umask = unsafe {
        let m = libc::umask(0);
        libc::umask(m);
        m as u32
    };
    let mut run = Run { o, umask, failed: false, made: Vec::new(), out: io::BufWriter::new(io::stdout()) };
    for src in sources {
        let from = Path::new(src);
        let md = if run.o.follow == Follow::Never {
            fs::symlink_metadata(from)
        } else {
            fs::metadata(from)
        };
        let md = match md {
            Ok(m) => m,
            Err(e) => {
                run.complain(from, &e);
                continue;
            }
        };
        let to = if target_is_dir { target.join(base_name(src)) } else { target.clone() };
        run.copy(from, &to, &md, md.dev());
    }
    let _ = run.out.flush();
    if run.failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
}
