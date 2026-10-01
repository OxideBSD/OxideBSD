//! `chmod(1)`: changes file modes, octal or symbolic (`lib/libmode`).
//!
//! ```text
//! chmod [-fhv] [-R [-H | -L | -P]] mode file ...
//! ```
//!
//! `-R` descends into directories; while doing so it follows no symbolic links (`-P`, the
//! default), only those named on the command line (`-H`), or all (`-L`). `-h` changes a symbolic
//! link itself rather than what it points to, where the system allows it. `-f` keeps quiet about
//! files it can't change; `-v` names each file changed (twice, `-vv`, with the old and new mode).

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Follow {
    None,
    CommandLine,
    All,
}

struct Opts {
    force: bool,
    no_deref: bool,
    verbose: u8,
    recurse: bool,
    follow: Follow,
}

fn usage() -> ExitCode {
    eprintln!("usage: chmod [-fhv] [-R [-H | -L | -P]] mode file ...");
    ExitCode::from(1)
}

/// The process's umask, which symbolic modes without a `who` respect.
fn umask() -> u32 {
    // SAFETY: umask(2) can't fail; set it back at once.
    unsafe {
        let m = libc::umask(0);
        libc::umask(m);
        m as u32
    }
}

struct Run<'a> {
    opts: &'a Opts,
    mode: &'a mode::Mode,
    umask: u32,
    failed: bool,
}

impl Run<'_> {
    fn complain(&mut self, path: &Path, e: std::io::Error) {
        self.failed = true;
        if !self.opts.force {
            eprintln!("chmod: {}: {e}", path.display());
        }
    }

    /// Changes `path`, then, with `-R`, what is in it. `top` is whether it was named on the
    /// command line.
    fn change(&mut self, path: &Path, top: bool) {
        let follow = match self.opts.follow {
            Follow::All => true,
            Follow::CommandLine => top,
            Follow::None => top && !self.opts.recurse,
        } && !self.opts.no_deref;
        let md = if follow {
            std::fs::metadata(path)
        } else {
            std::fs::symlink_metadata(path)
        };
        let md = match md {
            Ok(m) => m,
            Err(e) => return self.complain(path, e),
        };
        let is_link = md.file_type().is_symlink();
        if !is_link || self.opts.no_deref {
            let old = md.mode() & 0o7777;
            let new = self.mode.apply(old, md.is_dir(), self.umask);
            if new != old {
                let flags = if is_link {
                    libc::AT_SYMLINK_NOFOLLOW
                } else {
                    0
                };
                let c = CString::new(path.as_os_str().as_bytes()).unwrap_or_default();
                // SAFETY: a NUL-terminated path.
                if unsafe { libc::fchmodat(libc::AT_FDCWD, c.as_ptr(), new as libc::mode_t, flags) }
                    != 0
                {
                    // A symbolic link's own mode can't be changed here; with -h that is no error.
                    let e = std::io::Error::last_os_error();
                    if !(is_link && e.raw_os_error() == Some(libc::EOPNOTSUPP)) {
                        return self.complain(path, e);
                    }
                } else if self.opts.verbose >= 2 {
                    println!("{}: 0{:o} -> 0{:o}", path.display(), old, new);
                } else if self.opts.verbose == 1 {
                    println!("{}", path.display());
                }
            }
        }
        if self.opts.recurse && md.is_dir() {
            let entries = match std::fs::read_dir(path) {
                Ok(r) => r,
                Err(e) => return self.complain(path, e),
            };
            let mut names: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            names.sort();
            for p in names {
                self.change(&p, false);
            }
        }
    }
}

fn main() -> ExitCode {
    let mut opts = Opts {
        force: false,
        no_deref: false,
        verbose: 0,
        recurse: false,
        follow: Follow::None,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        // A symbolic mode may begin with '-' ("-w"): stop at anything that isn't all known flags.
        let Some(flags) = a
            .strip_prefix('-')
            .filter(|f| !f.is_empty() && f.chars().all(|c| "fhvRHLP".contains(c)))
        else {
            break;
        };
        for c in flags.chars() {
            match c {
                'f' => opts.force = true,
                'h' => opts.no_deref = true,
                'v' => opts.verbose = opts.verbose.saturating_add(1),
                'R' => opts.recurse = true,
                'H' => opts.follow = Follow::CommandLine,
                'L' => opts.follow = Follow::All,
                'P' => opts.follow = Follow::None,
                _ => unreachable!(),
            }
        }
        i += 1;
    }
    if !opts.recurse {
        opts.follow = Follow::None;
    }
    let Some(mode_text) = args.get(i) else {
        return usage();
    };
    let files = &args[i + 1..];
    if files.is_empty() {
        return usage();
    }
    let mode = match mode::parse(mode_text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("chmod: {e}");
            return ExitCode::from(1);
        }
    };
    let mut run = Run {
        opts: &opts,
        mode: &mode,
        umask: umask(),
        failed: false,
    };
    for f in files {
        run.change(Path::new(f), true);
    }
    if run.failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
