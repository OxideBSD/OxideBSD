//! `-t` and `-x`: listing and extracting members.
//!
//! Extraction treats every archive as hostile:
//!
//! - Without `-P`, a leading `/` is removed (once noted), and a name with a `..` component is
//!   refused, as is a hard link naming one.
//! - Each member is reached from the extraction directory one component at a time with
//!   `openat(O_DIRECTORY | O_NOFOLLOW)`, creating missing directories: a symbolic link on the
//!   way, whether the archive made it earlier or it was there before, is refused ("Cannot
//!   extract through symlink"), not followed. So `ln -s /etc x` followed by `x/passwd` in an
//!   archive writes nothing in `/etc`. `-P` follows links and allows `..` and absolute names.
//! - The member's own name is removed if something is there (a directory only if empty; an
//!   existing directory stays for a directory member), and a file is then created with
//!   `O_CREAT | O_EXCL | O_NOFOLLOW`: never written through a link. `-k` keeps what exists.
//! - A hard link's target is looked up the same way and linked without following a link.
//! - Owners are restored only by root (unless `-o`), by name unless `--numeric-owner`. The
//!   mode is kept whole by root or with `-p`; otherwise the umask applies and the set-user-ID,
//!   set-group-ID and sticky bits are cleared. Set-ID bits also go when the owner was not set.
//! - Directories are created owner-writable and given their own mode and time at the end,
//!   deepest first, so a read-only directory can be filled and its time is not disturbed.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use super::archive::{ReadError, Reader};
use super::create::makedev;
use super::header::{Entry, Kind};
use super::pattern::{self, Target};
use super::{Mode, Operand, Opts, shown, strerror};

fn errno() -> io::Error {
    io::Error::last_os_error()
}

fn cstr(b: &[u8]) -> Result<CString, String> {
    CString::new(b).map_err(|_| "Invalid pathname (contains NUL)".to_string())
}

fn openat_dir(fd: RawFd, name: &CString, nofollow: bool) -> io::Result<OwnedFd> {
    let mut flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    // SAFETY: a valid directory descriptor and NUL-terminated name.
    let r = unsafe { libc::openat(fd, name.as_ptr(), flags) };
    if r < 0 {
        return Err(errno());
    }
    // SAFETY: openat returned a new descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

fn lstat_at(fd: RawFd, name: &CString) -> io::Result<libc::stat> {
    // SAFETY: fstatat fills the stat buffer it is given.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstatat(fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) != 0 {
            return Err(errno());
        }
        Ok(st)
    }
}

fn is(st: &libc::stat, t: libc::mode_t) -> bool {
    st.st_mode & libc::S_IFMT == t
}

/// A name split into components, and whether it starts at `/` (only with `-P`).
struct Clean {
    abs: bool,
    comps: Vec<Vec<u8>>,
}

struct Fixup {
    clean: Clean,
    e: Entry,
}

struct Extract<'a> {
    o: &'a Opts,
    root: OwnedFd,
    umask: u32,
    euid: u32,
    egid: u32,
    fixups: Vec<Fixup>,
    warned_slash: bool,
    ok: bool,
    out: Option<BufWriter<io::Stdout>>,
}

/// --strip-components: the name without its first `n` components, or None if it has no more.
fn strip(name: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut p = name;
    for _ in 0..n {
        while let Some(r) = p.strip_prefix(b"/") {
            p = r;
        }
        let i = p.iter().position(|&b| b == b'/')?;
        p = &p[i + 1..];
    }
    while let Some(r) = p.strip_prefix(b"/") {
        p = r;
    }
    if p.is_empty() { None } else { Some(p.to_vec()) }
}

impl Extract<'_> {
    fn fail(&mut self, name: &[u8], msg: impl std::fmt::Display) {
        if let Some(o) = self.out.as_mut() {
            let _ = o.flush();
        }
        eprintln!("tar: {}: {msg}", shown(name));
        self.ok = false;
    }

    fn clean(&mut self, name: &[u8]) -> Result<Clean, String> {
        let abs = name.starts_with(b"/");
        if abs && !self.o.absolute && !self.warned_slash {
            eprintln!("tar: Removing leading '/' from member names");
            self.warned_slash = true;
        }
        let comps: Vec<Vec<u8>> =
            name.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".").map(<[u8]>::to_vec).collect();
        if !self.o.absolute && comps.iter().any(|c| c == b"..") {
            return Err("Path contains '..'".into());
        }
        Ok(Clean { abs: abs && self.o.absolute, comps })
    }

    /// Opens the directory holding `c`'s last component, making the missing ones if `make`.
    fn walk(&self, c: &Clean, make: bool) -> Result<OwnedFd, String> {
        let nofollow = !self.o.absolute;
        let mut fd = if c.abs { openat_dir(libc::AT_FDCWD, &cstr(b"/")?, false) } else { self.root.try_clone() }
            .map_err(|e| strerror(&e))?;
        let n = c.comps.len().saturating_sub(1);
        for (i, comp) in c.comps[..n].iter().enumerate() {
            let name = cstr(comp)?;
            let prefix = || shown(&c.comps[..=i].join(&b'/'));
            let next = match openat_dir(fd.as_raw_fd(), &name, nofollow) {
                Ok(f) => f,
                Err(e) => {
                    let code = e.raw_os_error();
                    let st = lstat_at(fd.as_raw_fd(), &name);
                    match (code, st) {
                        (_, Ok(st)) if is(&st, libc::S_IFLNK) && nofollow => {
                            return Err(format!("Cannot extract through symlink {}", prefix()));
                        }
                        (Some(libc::ENOENT), Err(_)) if make => {}
                        (Some(libc::ENOTDIR | libc::ELOOP), Ok(_)) if make && !self.o.keep_old => {
                            // A file (or, with -P, a link to one) where a directory goes.
                            // SAFETY: unlinkat on a descriptor and name.
                            if unsafe { libc::unlinkat(fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                                return Err(format!("Can't remove {}: {}", prefix(), strerror(&errno())));
                            }
                        }
                        _ => return Err(format!("Can't open {}: {}", prefix(), strerror(&e))),
                    }
                    // SAFETY: mkdirat on a descriptor and name.
                    if unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
                        let e = errno();
                        if e.raw_os_error() != Some(libc::EEXIST) {
                            return Err(format!("Can't create directory {}: {}", prefix(), strerror(&e)));
                        }
                    }
                    openat_dir(fd.as_raw_fd(), &name, nofollow).map_err(|e| match e.raw_os_error() {
                        Some(libc::ELOOP | libc::ENOTDIR) => format!("Cannot extract through symlink {}", prefix()),
                        _ => format!("Can't open {}: {}", prefix(), strerror(&e)),
                    })?
                }
            };
            fd = next;
        }
        Ok(fd)
    }

    /// Makes room for a new `name` in `dfd`: Ok(false) to leave the member out (-k).
    fn clear(&self, dfd: RawFd, name: &CString, dir: bool) -> Result<bool, String> {
        let st = match lstat_at(dfd, name) {
            Ok(st) => st,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(true),
            Err(e) => return Err(strerror(&e)),
        };
        if dir && is(&st, libc::S_IFDIR) {
            return Ok(true);
        }
        if self.o.keep_old {
            return Ok(false);
        }
        let flag = if is(&st, libc::S_IFDIR) { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: unlinkat on a descriptor and name.
        if unsafe { libc::unlinkat(dfd, name.as_ptr(), flag) } != 0 {
            return Err(format!(
                "Can't remove existing {}: {}",
                if flag != 0 { "directory" } else { "file" },
                strerror(&errno())
            ));
        }
        Ok(true)
    }

    fn owner(&self, e: &Entry) -> Option<(u32, u32)> {
        if !self.o.same_owner {
            return None;
        }
        let mut uid = u32::try_from(e.uid).unwrap_or(u32::MAX - 1);
        let mut gid = u32::try_from(e.gid).unwrap_or(u32::MAX - 1);
        if !self.o.numeric_owner {
            if !e.uname.is_empty()
                && let Ok(n) = CString::new(e.uname.clone())
            {
                // SAFETY: getpwnam's result is read at once.
                unsafe {
                    let p = libc::getpwnam(n.as_ptr());
                    if !p.is_null() {
                        uid = (*p).pw_uid;
                    }
                }
            }
            if !e.gname.is_empty()
                && let Ok(n) = CString::new(e.gname.clone())
            {
                // SAFETY: as for getpwnam.
                unsafe {
                    let g = libc::getgrnam(n.as_ptr());
                    if !g.is_null() {
                        gid = (*g).gr_gid;
                    }
                }
            }
        }
        Some((uid, gid))
    }

    fn perm(&self, e: &Entry, owned: Option<(u32, u32)>) -> u32 {
        let mut m = e.mode & 0o7777;
        if !self.o.preserve_perms {
            m &= 0o777 & !self.umask;
        }
        // Set-ID bits only on a file that belongs to the archive's owner.
        let (u, g) = owned.unwrap_or((self.euid, self.egid));
        if u64::from(u) != e.uid {
            m &= !(libc::S_ISUID as u32);
        }
        if u64::from(g) != e.gid {
            m &= !(libc::S_ISGID as u32);
        }
        m
    }

    fn times(&self, e: &Entry) -> [libc::timespec; 2] {
        [
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW },
            libc::timespec { tv_sec: e.mtime as _, tv_nsec: e.mtime_nsec as _ },
        ]
    }

    /// Owner, mode and time for an open file or directory.
    fn set_fd(&mut self, fd: RawFd, e: &Entry, name: &[u8]) {
        let mut owned = None;
        if let Some((u, g)) = self.owner(e) {
            // SAFETY: fchown on an open descriptor.
            if unsafe { libc::fchown(fd, u, g) } == 0 {
                owned = Some((u, g));
            } else {
                let err = errno();
                self.fail(name, format_args!("Can't set user={u}/group={g}: {}", strerror(&err)));
            }
        }
        let m = self.perm(e, owned);
        // SAFETY: fchmod and futimens on an open descriptor.
        unsafe {
            if libc::fchmod(fd, m as libc::mode_t) != 0 {
                let err = errno();
                self.fail(name, format_args!("Can't set permissions: {}", strerror(&err)));
            }
            if !self.o.no_mtime && libc::futimens(fd, self.times(e).as_ptr()) != 0 {
                let err = errno();
                self.fail(name, format_args!("Can't restore time: {}", strerror(&err)));
            }
        }
    }

    /// The same for a link, FIFO or device, by name in `dfd` (never following a link).
    fn set_at(&mut self, dfd: RawFd, last: &CString, e: &Entry, name: &[u8]) {
        let link = e.kind == Kind::Symlink;
        let mut owned = None;
        if let Some((u, g)) = self.owner(e) {
            // SAFETY: fchownat on a descriptor and name.
            if unsafe { libc::fchownat(dfd, last.as_ptr(), u, g, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
                owned = Some((u, g));
            } else if !link {
                let err = errno();
                self.fail(name, format_args!("Can't set user={u}/group={g}: {}", strerror(&err)));
            }
        }
        // SAFETY: as above.
        unsafe {
            if !link && libc::fchmodat(dfd, last.as_ptr(), self.perm(e, owned) as libc::mode_t, 0) != 0 {
                let err = errno();
                self.fail(name, format_args!("Can't set permissions: {}", strerror(&err)));
            }
            // A link's own time is not always settable; that is not worth an error.
            if !self.o.no_mtime
                && libc::utimensat(dfd, last.as_ptr(), self.times(e).as_ptr(), libc::AT_SYMLINK_NOFOLLOW) != 0
                && !link
            {
                let err = errno();
                self.fail(name, format_args!("Can't restore time: {}", strerror(&err)));
            }
        }
    }

    fn extract(&mut self, r: &mut Reader, e: &Entry, name: &[u8], link: &[u8]) -> Result<(), String> {
        let c = self.clean(name)?;
        let Some(last) = c.comps.last() else {
            // "." or "/": the extraction directory itself is left as it is.
            return Ok(());
        };
        let last = cstr(last)?;
        let kind = match e.kind {
            Kind::Other(b'D') => Kind::Dir,
            Kind::Other(b'S') => return Err("Sparse files are not supported; skipped".into()),
            Kind::Other(b'V') => return Ok(()),
            Kind::Other(t) => return Err(format!("Unknown file type '{}'; skipped", t.escape_ascii())),
            k => k,
        };
        let dfd = self.walk(&c, true)?;
        let dfd_raw = dfd.as_raw_fd();
        if !self.clear(dfd_raw, &last, kind == Kind::Dir)? {
            return Ok(());
        }
        match kind {
            Kind::Dir => {
                // SAFETY: mkdirat on a descriptor and name.
                if unsafe { libc::mkdirat(dfd_raw, last.as_ptr(), 0o700) } != 0 {
                    let err = errno();
                    if err.raw_os_error() != Some(libc::EEXIST) {
                        return Err(format!("Can't create directory: {}", strerror(&err)));
                    }
                }
                self.fixups.push(Fixup { clean: c, e: e.clone() });
            }
            Kind::File => {
                let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                // SAFETY: openat on a descriptor and name.
                let fd = unsafe { libc::openat(dfd_raw, last.as_ptr(), flags, 0o600 as libc::c_uint) };
                if fd < 0 {
                    return Err(format!("Can't create: {}", strerror(&errno())));
                }
                // SAFETY: a new descriptor we own.
                let mut f = unsafe { File::from_raw_fd(fd) };
                let mut buf = vec![0u8; 64 * 1024];
                let mut werr = None;
                loop {
                    let n = match r.read_data(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(err) => return Err(format!("Read error: {err}")),
                    };
                    if werr.is_none()
                        && let Err(err) = f.write_all(&buf[..n])
                    {
                        werr = Some(err);
                    }
                }
                if let Some(err) = werr {
                    return Err(format!("Write error: {}", strerror(&err)));
                }
                self.set_fd(f.as_raw_fd(), e, name);
            }
            Kind::HardLink => {
                let tc = self.clean(link).map_err(|m| format!("Hard link target {}: {m}", shown(link)))?;
                let Some(tlast) = tc.comps.last() else {
                    return Err("Hard link to a directory".into());
                };
                let tlast = cstr(tlast)?;
                let tfd =
                    self.walk(&tc, false).map_err(|m| format!("Can't create hardlink to {}: {m}", shown(link)))?;
                // SAFETY: linkat without AT_SYMLINK_FOLLOW links a symbolic link itself.
                if unsafe { libc::linkat(tfd.as_raw_fd(), tlast.as_ptr(), dfd_raw, last.as_ptr(), 0) } != 0 {
                    return Err(format!("Can't create hardlink to {}: {}", shown(link), strerror(&errno())));
                }
            }
            Kind::Symlink => {
                let target = cstr(link)?;
                // SAFETY: symlinkat on a descriptor and names.
                if unsafe { libc::symlinkat(target.as_ptr(), dfd_raw, last.as_ptr()) } != 0 {
                    return Err(format!("Can't create symlink: {}", strerror(&errno())));
                }
                self.set_at(dfd_raw, &last, e, name);
            }
            Kind::Fifo | Kind::Char | Kind::Block => {
                // SAFETY: mkfifoat/mknodat on a descriptor and name.
                let rc = unsafe {
                    match kind {
                        Kind::Fifo => libc::mkfifoat(dfd_raw, last.as_ptr(), 0o600),
                        Kind::Char => libc::mknodat(
                            dfd_raw,
                            last.as_ptr(),
                            libc::S_IFCHR | 0o600,
                            makedev(e.devmajor, e.devminor) as libc::dev_t,
                        ),
                        _ => libc::mknodat(
                            dfd_raw,
                            last.as_ptr(),
                            libc::S_IFBLK | 0o600,
                            makedev(e.devmajor, e.devminor) as libc::dev_t,
                        ),
                    }
                };
                if rc != 0 {
                    return Err(format!(
                        "Can't create {}: {}",
                        if kind == Kind::Fifo { "fifo" } else { "device node" },
                        strerror(&errno())
                    ));
                }
                self.set_at(dfd_raw, &last, e, name);
            }
            Kind::Other(_) => unreachable!(),
        }
        Ok(())
    }

    /// Directories' modes and times, deepest first.
    fn fixups(&mut self) {
        let mut f = std::mem::take(&mut self.fixups);
        f.sort_by(|a, b| b.clean.comps.len().cmp(&a.clean.comps.len()).then_with(|| b.clean.comps.cmp(&a.clean.comps)));
        for x in f {
            let name = x.e.path.clone();
            let r = self.walk(&x.clean, false).and_then(|dfd| {
                let last = cstr(x.clean.comps.last().unwrap())?;
                openat_dir(dfd.as_raw_fd(), &last, !self.o.absolute).map_err(|e| strerror(&e))
            });
            match r {
                Ok(fd) => self.set_fd(fd.as_raw_fd(), &x.e, &name),
                Err(m) => self.fail(&name, m),
            }
        }
    }
}

/// Widths of the `-tv` columns, which grow as wider values are seen (as in bsdtar).
struct Widths {
    user: usize,
    group_size: usize,
}

fn mode_string(e: &Entry) -> String {
    let t = match e.kind {
        Kind::Dir | Kind::Other(b'D') => 'd',
        Kind::Symlink => 'l',
        Kind::HardLink => 'h',
        Kind::Char => 'c',
        Kind::Block => 'b',
        Kind::Fifo => 'p',
        _ => '-',
    };
    let m = e.mode;
    let mut s = String::with_capacity(10);
    s.push(t);
    let bit = |b: u32, c: char| if m & b != 0 { c } else { '-' };
    let special = |x: bool, sp: u32, lo: char, hi: char| match (m & sp != 0, x) {
        (true, true) => lo,
        (true, false) => hi,
        (false, true) => 'x',
        (false, false) => '-',
    };
    s.push(bit(0o400, 'r'));
    s.push(bit(0o200, 'w'));
    s.push(special(m & 0o100 != 0, 0o4000, 's', 'S'));
    s.push(bit(0o040, 'r'));
    s.push(bit(0o020, 'w'));
    s.push(special(m & 0o010 != 0, 0o2000, 's', 'S'));
    s.push(bit(0o004, 'r'));
    s.push(bit(0o002, 'w'));
    s.push(special(m & 0o001 != 0, 0o1000, 't', 'T'));
    s
}

/// `ls -l`'s date: "Mon dd hh:mm" within half a year of now, else "Mon dd  yyyy".
fn date(t: i64) -> String {
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    // SAFETY: localtime_r fills the tm it is given.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let tt = t as _;
        libc::localtime_r(&tt, &mut tm);
        tm
    };
    let mon = MON[tm.tm_mon.clamp(0, 11) as usize];
    const HALF_YEAR: i64 = 365 * 86400 / 2;
    if t < now - HALF_YEAR || t > now + HALF_YEAR {
        format!("{mon} {:2}  {}", tm.tm_mday, tm.tm_year + 1900)
    } else {
        format!("{mon} {:2} {:02}:{:02}", tm.tm_mday, tm.tm_hour, tm.tm_min)
    }
}

fn list_line(w: &mut Widths, e: &Entry, name: &[u8], link: &[u8]) -> String {
    let user = if e.uname.is_empty() { e.uid.to_string() } else { String::from_utf8_lossy(&e.uname).into_owned() };
    let group = if e.gname.is_empty() { e.gid.to_string() } else { String::from_utf8_lossy(&e.gname).into_owned() };
    w.user = w.user.max(user.len());
    let size = if matches!(e.kind, Kind::Char | Kind::Block) {
        format!("{},{}", e.devmajor, e.devminor)
    } else {
        e.size.to_string()
    };
    if group.len() + size.len() >= w.group_size {
        w.group_size = group.len() + size.len() + 1;
    }
    let mut s = format!(
        "{}  0 {:<uw$} {}{:>gw$} {} {}",
        mode_string(e),
        shown(user.as_bytes()),
        shown(group.as_bytes()),
        size,
        date(e.mtime),
        shown(name),
        uw = w.user,
        gw = w.group_size - group.len()
    );
    match e.kind {
        Kind::HardLink => s.push_str(&format!(" link to {}", shown(link))),
        Kind::Symlink => s.push_str(&format!(" -> {}", shown(link))),
        _ => {}
    }
    s
}

pub fn run(o: &Opts) -> bool {
    let mut patterns: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut dirs: Vec<&[u8]> = o.chdir.iter().map(Vec::as_slice).collect();
    for op in &o.operands {
        match op {
            Operand::Name(n) => patterns.push((n.clone(), false)),
            Operand::Chdir(d) => dirs.push(d),
        }
    }
    let mut r = match Reader::open(&o.file) {
        Ok(r) => r,
        Err(m) => {
            let f = if o.file == "-" { "stdin".to_string() } else { shown(o.file.as_bytes()) };
            eprintln!("tar: {f}: {m}");
            return false;
        }
    };
    for d in dirs {
        if let Err(e) = std::env::set_current_dir(OsStr::from_bytes(d)) {
            eprintln!("tar: could not chdir to '{}': {}", shown(d), strerror(&e));
            return false;
        }
    }
    let extracting = o.mode == Mode::Extract && !o.to_stdout;
    let root = match openat_dir(libc::AT_FDCWD, &CString::new(".").unwrap(), false) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tar: .: {}", strerror(&e));
            return false;
        }
    };
    // SAFETY: umask is read by setting it and putting it back.
    let umask = unsafe {
        let m = libc::umask(0);
        libc::umask(m);
        m as u32
    };
    let mut x = Extract {
        o,
        root,
        umask,
        // SAFETY: plain getters.
        euid: unsafe { libc::geteuid() },
        egid: unsafe { libc::getegid() },
        fixups: Vec::new(),
        warned_slash: false,
        ok: true,
        out: if o.mode == Mode::List || o.to_stdout {
            Some(BufWriter::with_capacity(64 * 1024, io::stdout()))
        } else {
            None
        },
    };
    let mut widths = Widths { user: 6, group_size: 13 };
    let mut remaining = patterns.len();
    loop {
        let e = match r.next() {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                if let Some(out) = x.out.as_mut() {
                    let _ = out.flush();
                }
                match err {
                    ReadError::NotTar => {
                        eprintln!("tar: {err}");
                    }
                    _ => eprintln!("tar: {err}"),
                }
                x.ok = false;
                break;
            }
        };
        if !patterns.is_empty() {
            let mut hit = false;
            for (p, seen) in patterns.iter_mut() {
                if pattern::includes(p, &e.path) {
                    hit = true;
                    if !*seen {
                        *seen = true;
                        remaining -= 1;
                    }
                }
            }
            if !hit {
                continue;
            }
        }
        if o.excludes.iter().any(|p| pattern::excludes(p, &e.path)) {
            continue;
        }
        // --strip-components and -s, to the name and to a hard link's target.
        let mut name = e.path.clone();
        let mut link = e.link.clone();
        if o.strip > 0 {
            match strip(&name, o.strip) {
                Some(n) => name = n,
                None => continue,
            }
            if e.kind == Kind::HardLink {
                match strip(&link, o.strip) {
                    Some(l) => link = l,
                    None => continue,
                }
            }
        }
        if !o.subst.is_empty() {
            let (n, p) = pattern::substitute(&o.subst, &name, Target::Name);
            if p {
                eprintln!("{} >> {}", shown(&name), shown(&n));
            }
            name = n;
            if name.is_empty() {
                continue;
            }
            let t = if e.kind == Kind::HardLink { Target::HardLink } else { Target::Symlink };
            if matches!(e.kind, Kind::HardLink | Kind::Symlink) {
                link = pattern::substitute(&o.subst, &link, t).0;
            }
        }
        if o.mode == Mode::List {
            let line = if o.verbose > 0 { list_line(&mut widths, &e, &name, &link) } else { shown(&name) };
            let out = x.out.as_mut().unwrap();
            if let Err(err) = writeln!(out, "{line}") {
                eprintln!("tar: stdout: {}", strerror(&err));
                return false;
            }
        } else if o.to_stdout {
            if o.verbose > 0 {
                eprintln!("x {}", shown(&name));
            }
            if e.kind == Kind::File {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match r.read_data(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(err) = x.out.as_mut().unwrap().write_all(&buf[..n]) {
                                eprintln!("tar: stdout: {}", strerror(&err));
                                return false;
                            }
                        }
                        Err(err) => {
                            x.fail(&name, err);
                            break;
                        }
                    }
                }
            }
        } else if extracting {
            if o.verbose > 0 {
                eprintln!("x {}", shown(&name));
            }
            if let Err(m) = x.extract(&mut r, &e, &name, &link) {
                x.fail(&name, m);
            }
        }
        if o.fast_read && !patterns.is_empty() && remaining == 0 {
            break;
        }
    }
    r.close();
    if extracting {
        x.fixups();
    }
    if let Some(mut out) = x.out.take()
        && let Err(err) = out.flush()
    {
        eprintln!("tar: stdout: {}", strerror(&err));
        return false;
    }
    for (p, seen) in &patterns {
        if !seen {
            eprintln!("tar: {}: Not found in archive", shown(p));
            x.ok = false;
        }
    }
    if !x.ok {
        eprintln!("tar: Error exit delayed from previous errors.");
    }
    x.ok
}
