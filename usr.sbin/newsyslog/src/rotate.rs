//! Rotating a log (`SYSLOG.md` §9.2): shifting its archives, starting a new empty file,
//! telling the daemon writing it, and compressing the newest archive.
//!
//! Archives are `file.0` (newest) to `file.N-1`, each maybe `.gz`/`.bz2`/`.xz`/`.zst`, or with
//! `-t`, `file.<time stamp>`. Rotation sets the newest archive's modification time to the time
//! of rotation: that is the "last rotated" time the next run's decision reads.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::conf::{Compress, Entry, Reason};

/// The run's settings and what it has to say.
pub struct Ctx {
    pub now: i64,
    pub host: String,
    pub pid: u32,
    /// `-n`: only say what would be done.
    pub dry_run: bool,
    /// `-v`: say what is done.
    pub verbose: bool,
    /// `-t`: time-stamped archive names in this `strftime(3)` format.
    pub timefmt: Option<String>,
    /// `-a`: where archives go (relative to the log's directory).
    pub archive_dir: Option<PathBuf>,
    /// `-S`: the pid file of entries that name none.
    pub default_pidfile: String,
    /// Lines for standard output (`-n`, `-v`).
    pub out: Vec<String>,
    /// Lines for standard error.
    pub warnings: Vec<String>,
}

/// `-t`'s format when given as `""` or `DEFAULT`: FreeBSD's.
pub const DEFAULT_TIMEFMT: &str = "%Y%m%dT%H%M%S";

/// An archive waiting to be compressed once the daemon has been told.
pub struct Pending {
    pub archive: PathBuf,
    pub compress: Compress,
}

/// Daemons to tell, by pid file (or command, with `R`): the signal, and whether it's a group.
#[derive(Default)]
pub struct Notices {
    pub signals: BTreeMap<String, (i32, bool)>,
    pub commands: Vec<String>,
}

impl Ctx {
    /// Does `f`, or with `-n` only says `what`. With `-v` says it too.
    fn act(&mut self, what: String, f: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if self.dry_run {
            self.out.push(what);
            return Ok(());
        }
        if self.verbose {
            self.out.push(what);
        }
        f()
    }

    fn archives_dir(&self, log: &Path) -> PathBuf {
        let parent = log.parent().unwrap_or(Path::new("/"));
        match &self.archive_dir {
            Some(d) => parent.join(d),
            None => parent.to_path_buf(),
        }
    }
}

fn base_name(log: &Path) -> String {
    log.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn mtime(p: &Path) -> Option<i64> {
    std::fs::metadata(p).ok().map(|m| m.mtime())
}

/// `dir/base.N` with whichever compression suffix exists.
fn numbered(dir: &Path, base: &str, n: u32) -> Option<PathBuf> {
    Compress::SUFFIXES
        .iter()
        .map(|s| dir.join(format!("{base}.{n}{s}")))
        .find(|p| std::fs::symlink_metadata(p).is_ok())
}

/// Time-stamped archives of `base` in `dir` under `fmt`, oldest first.
fn stamped(dir: &Path, base: &str, fmt: &str) -> Vec<PathBuf> {
    let prefix = format!("{base}.");
    let mut v: Vec<(i64, String, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let rest = name.strip_prefix(&prefix)?;
            let stamp = Compress::SUFFIXES[1..].iter().find_map(|s| rest.strip_suffix(s)).unwrap_or(rest);
            if !crate::clock::parses(fmt, stamp) {
                return None;
            }
            let p = e.path();
            Some((mtime(&p).unwrap_or(0), name, p))
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, _, p)| p).collect()
}

/// When `log` was last rotated: its newest archive's modification time.
pub fn last_rotation(ctx: &Ctx, log: &Path) -> Option<i64> {
    let dir = ctx.archives_dir(log);
    let base = base_name(log);
    match &ctx.timefmt {
        Some(fmt) => stamped(&dir, &base, fmt).iter().filter_map(|p| mtime(p)).max(),
        None => numbered(&dir, &base, 0).and_then(|p| mtime(&p)),
    }
}

fn cpath(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).unwrap_or_default()
}

/// Sets a file's access and modification times.
pub fn set_mtime(p: &Path, t: i64) {
    let ts = libc::timespec { tv_sec: t, tv_nsec: 0 };
    let times = [ts, ts];
    // SAFETY: a NUL-terminated path and two timespecs.
    unsafe { libc::utimensat(libc::AT_FDCWD, cpath(p).as_ptr(), times.as_ptr(), 0) };
}

fn lookup_user(name: &str) -> Option<(u32, u32)> {
    if let Ok(n) = name.parse() {
        return Some((n, u32::MAX));
    }
    let c = CString::new(name).ok()?;
    // SAFETY: getpwnam's result is read before any other passwd call.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    (!pw.is_null()).then(|| unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
}

fn lookup_group(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse() {
        return Some(n);
    }
    let c = CString::new(name).ok()?;
    // SAFETY: as lookup_user.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    (!gr.is_null()).then(|| unsafe { (*gr).gr_gid })
}

/// The owner and group a new log gets: the entry's, else those of the file it replaces.
fn ids(e: &Entry, old: Option<(u32, u32)>) -> Result<Option<(u32, u32)>, String> {
    let (mut uid, mut gid) = match old {
        Some(o) => (Some(o.0), Some(o.1)),
        None => (None, None),
    };
    if let Some(o) = &e.owner {
        uid = Some(lookup_user(o).ok_or_else(|| format!("unknown user {o}"))?.0);
    }
    if let Some(g) = &e.group {
        gid = Some(lookup_group(g).ok_or_else(|| format!("unknown group {g}"))?);
    }
    Ok(match (uid, gid) {
        (None, None) => None,
        (u, g) => Some((u.unwrap_or(u32::MAX), g.unwrap_or(u32::MAX))),
    })
}

fn ids_text(e: &Entry, owner: (u32, u32)) -> String {
    let u = e.owner.clone().unwrap_or_else(|| owner.0.to_string());
    let g = e.group.clone().unwrap_or_else(|| owner.1.to_string());
    format!("{u}:{g}")
}

/// Creates `log` empty with the entry's mode and owner (for `-C`, and after a rotation).
pub fn create(ctx: &mut Ctx, e: &Entry, log: &Path, old: Option<(u32, u32)>) -> io::Result<()> {
    let owner = ids(e, old).map_err(io::Error::other)?;
    let mode = e.mode;
    ctx.act(format!("install -m {mode:o} /dev/null {}", log.display()), || {
        let f = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_CLOEXEC).open(log)?;
        // The mode exactly, whatever the umask.
        f.set_permissions(std::fs::Permissions::from_mode(mode))
    })?;
    if let Some(owner) = owner {
        let text = ids_text(e, owner);
        ctx.act(format!("chown {text} {}", log.display()), || {
            let m = std::fs::metadata(log)?;
            // Changing nothing needs no privilege; skip it so a non-root run (-r) works.
            if (owner.0 == u32::MAX || owner.0 == m.uid()) && (owner.1 == u32::MAX || owner.1 == m.gid()) {
                return Ok(());
            }
            // SAFETY: a NUL-terminated path; u32::MAX is (uid_t)-1, "unchanged".
            if unsafe { libc::chown(cpath(log).as_ptr(), owner.0, owner.1) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn remove(ctx: &mut Ctx, p: &Path) -> io::Result<()> {
    ctx.act(format!("rm -f {}", p.display()), || std::fs::remove_file(p))
}

fn rename(ctx: &mut Ctx, from: &Path, to: &Path) -> io::Result<()> {
    ctx.act(format!("mv {} {}", from.display(), to.display()), || std::fs::rename(from, to))
}

/// Rotates `log`. Returns the new archive, if any is kept.
pub fn rotate(ctx: &mut Ctx, e: &Entry, log: &Path, reason: Reason) -> io::Result<Option<PathBuf>> {
    let meta = std::fs::metadata(log)?;
    let old = (meta.uid(), meta.gid());
    let dir = ctx.archives_dir(log);
    let base = base_name(log);
    if ctx.archive_dir.is_some() && !dir.is_dir() {
        return Err(io::Error::other(format!("archive directory {} does not exist", dir.display())));
    }
    let mut archive = None;
    match ctx.timefmt.clone() {
        Some(fmt) => {
            let mut existing = stamped(&dir, &base, &fmt);
            // Room for the one about to be made.
            while !existing.is_empty() && existing.len() >= e.count.max(1) as usize {
                let p = existing.remove(0);
                remove(ctx, &p)?;
            }
            if e.count == 0 {
                for p in existing {
                    remove(ctx, &p)?;
                }
            } else {
                archive = Some(dir.join(format!("{base}.{}", crate::clock::format(&fmt, ctx.now))));
            }
        }
        None => {
            if e.count > 0 {
                // Everything from the last kept number on goes (a count lowered since).
                let mut n = e.count - 1;
                while let Some(p) = numbered(&dir, &base, n) {
                    remove(ctx, &p)?;
                    n += 1;
                }
                for n in (0..e.count - 1).rev() {
                    if let Some(p) = numbered(&dir, &base, n) {
                        let suffix = p.to_string_lossy()[dir.join(format!("{base}.{n}")).to_string_lossy().len()..].to_string();
                        rename(ctx, &p, &dir.join(format!("{base}.{}{suffix}", n + 1)))?;
                    }
                }
                archive = Some(dir.join(format!("{base}.0")));
            }
        }
    }
    match &archive {
        Some(a) => {
            rename(ctx, log, a)?;
            let (a, now) = (a.clone(), ctx.now);
            ctx.act(format!("touch -d @{now} {}", a.display()), || {
                set_mtime(&a, now);
                Ok(())
            })?;
        }
        None => remove(ctx, log)?,
    }
    create(ctx, e, log, Some(old))?;
    if !e.flags.binary {
        let why = match reason {
            Reason::Size(k) => format!(" due to size>{k}K"),
            Reason::Force => " due to -F request".into(),
            Reason::Time => String::new(),
        };
        let line = format!(
            "{} {} newsyslog[{}]: logfile turned over{why}\n",
            syslog::time::local(ctx.now).rfc3164(),
            ctx.host,
            ctx.pid
        );
        ctx.act(format!("echo 'logfile turned over{why}' >> {}", log.display()), || {
            OpenOptions::new().append(true).open(log)?.write_all(line.as_bytes())
        })?;
    }
    Ok(archive)
}

/// Where a compressor is: BusyBox installs `gzip` in `/bin` and `bzip2` in `/usr/bin`; failing
/// those, `PATH`.
pub fn compressor(c: Compress) -> Option<PathBuf> {
    let (name, places): (&str, &[&str]) = match c {
        Compress::None => return None,
        Compress::Gzip => ("gzip", &["/bin/gzip", "/usr/bin/gzip"]),
        Compress::Bzip2 => ("bzip2", &["/usr/bin/bzip2", "/bin/bzip2"]),
        Compress::Xz => ("xz", &["/usr/bin/xz"]),
        Compress::Zstd => ("zstd", &["/usr/bin/zstd", "/usr/local/bin/zstd"]),
    };
    if let Some(p) = places.iter().map(PathBuf::from).find(|p| p.is_file()) {
        return Some(p);
    }
    std::env::var_os("PATH")?.to_string_lossy().split(':').map(|d| Path::new(d).join(name)).find(|p| p.is_file())
}

/// Compresses an archive, keeping its time; a missing compressor leaves it as it is.
pub fn compress(ctx: &mut Ctx, p: &Pending) {
    let Some(prog) = compressor(p.compress) else {
        ctx.warnings.push(format!(
            "{}: {} is not installed; left uncompressed",
            p.archive.display(),
            p.compress.suffix().trim_start_matches('.')
        ));
        return;
    };
    let done = PathBuf::from(format!("{}{}", p.archive.display(), p.compress.suffix()));
    let (archive, now) = (p.archive.clone(), ctx.now);
    let r = ctx.act(format!("{} -f {}", prog.display(), archive.display()), || {
        let status = Command::new(&prog).arg("-f").arg(&archive).status()?;
        if !status.success() {
            return Err(io::Error::other(format!("{} exited with {status}", prog.display())));
        }
        set_mtime(&done, now);
        Ok(())
    });
    if let Err(e) = r {
        ctx.warnings.push(format!("{}: {e}", archive.display()));
    }
}

/// Signals each daemon once, and runs `R` commands. Returns whether anything was told.
pub fn notify(ctx: &mut Ctx, n: &Notices) -> bool {
    let mut told = false;
    for (pidfile, &(sig, group)) in &n.signals {
        let pid = std::fs::read_to_string(pidfile)
            .ok()
            .and_then(|s| s.split_ascii_whitespace().next().and_then(|w| w.parse::<i32>().ok()))
            .filter(|&p| p > 0);
        let Some(pid) = pid else {
            ctx.warnings.push(format!("{pidfile}: no process to signal"));
            continue;
        };
        let target = if group { -pid } else { pid };
        let r = ctx.act(format!("kill -{sig} {target}"), || {
            // SAFETY: kill(2) with a pid read from the pid file.
            if unsafe { libc::kill(target, sig) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
        match r {
            Ok(()) => told = true,
            Err(e) => ctx.warnings.push(format!("can't notify daemon, pid {pid}: {e}")),
        }
    }
    for cmd in &n.commands {
        let r = ctx.act(cmd.clone(), || {
            let status = Command::new(cmd).status()?;
            if !status.success() {
                return Err(io::Error::other(format!("exited with {status}")));
            }
            Ok(())
        });
        match r {
            Ok(()) => told = true,
            Err(e) => ctx.warnings.push(format!("{cmd}: {e}")),
        }
    }
    told
}
