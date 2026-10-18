//! `-c`, `-r`, `-u`: writing members.
//!
//! Directories are walked in name order, so the same tree makes the same archive. A file with
//! other links is stored once; its later names are hard-link members naming the first. A name
//! is stored as given, without a leading `/` or `../` unless `-P`, with `-s` applied; a
//! directory's name ends in `/`. Sockets are left out, as is the archive itself.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Stdio;

use crate::archive::{Comp, Reader, Writer};
use crate::header::{self, Entry, Kind};
use crate::pattern::{self, Target};
use crate::{Mode, Operand, Opts, shown, strerror};

/// musl's (and glibc's) `dev_t` encoding, which OxideBSD's devfs uses.
pub fn major(d: u64) -> u32 {
    (((d >> 32) & 0xffff_f000) | ((d >> 8) & 0xfff)) as u32
}
pub fn minor(d: u64) -> u32 {
    (((d >> 12) & 0xffff_ff00) | (d & 0xff)) as u32
}
pub fn makedev(ma: u32, mi: u32) -> u64 {
    let (ma, mi) = (u64::from(ma), u64::from(mi));
    ((ma & 0xffff_f000) << 32) | ((ma & 0xfff) << 8) | ((mi & 0xffff_ff00) << 12) | (mi & 0xff)
}

struct Create<'a> {
    o: &'a Opts,
    w: Writer,
    /// (dev, ino) of a file with other links -> its member name.
    links: HashMap<(u64, u64), Vec<u8>>,
    users: HashMap<u32, Vec<u8>>,
    groups: HashMap<u32, Vec<u8>>,
    /// The archive file, so it is not added to itself.
    me: Option<(u64, u64)>,
    /// -u: member name -> its newest time in the archive.
    have: Option<HashMap<Vec<u8>, i64>>,
    warned_slash: bool,
    warned_dotdot: bool,
    ok: bool,
}

fn user_name(cache: &mut HashMap<u32, Vec<u8>>, uid: u32) -> Vec<u8> {
    cache
        .entry(uid)
        .or_insert_with(|| {
            // SAFETY: getpwuid's result is copied before any other call can reuse it.
            unsafe {
                let p = libc::getpwuid(uid);
                if p.is_null() { Vec::new() } else { std::ffi::CStr::from_ptr((*p).pw_name).to_bytes().to_vec() }
            }
        })
        .clone()
}

fn group_name(cache: &mut HashMap<u32, Vec<u8>>, gid: u32) -> Vec<u8> {
    cache
        .entry(gid)
        .or_insert_with(|| {
            // SAFETY: as for getpwuid.
            unsafe {
                let g = libc::getgrgid(gid);
                if g.is_null() { Vec::new() } else { std::ffi::CStr::from_ptr((*g).gr_name).to_bytes().to_vec() }
            }
        })
        .clone()
}

fn chdir(d: &[u8]) -> Result<(), String> {
    std::env::set_current_dir(OsStr::from_bytes(d))
        .map_err(|e| format!("could not chdir to '{}': {}", shown(d), strerror(&e)))
}

impl Create<'_> {
    fn fail(&mut self, what: &[u8], msg: impl std::fmt::Display) {
        eprintln!("tar: {}: {msg}", shown(what));
        self.ok = false;
    }

    /// The member name for `name`, or None to store nothing under it.
    fn member_name(&mut self, name: &[u8], dir: bool) -> Option<Vec<u8>> {
        let mut n = name;
        if !self.o.absolute {
            if n.starts_with(b"/") {
                if !self.warned_slash {
                    eprintln!("tar: Removing leading '/' from member names");
                    self.warned_slash = true;
                }
                while let Some(r) = n.strip_prefix(b"/") {
                    n = r;
                }
            }
            loop {
                let r = if n == b".." { Some(&b""[..]) } else { n.strip_prefix(b"../") };
                let Some(r) = r else { break };
                if !self.warned_dotdot {
                    eprintln!("tar: Removing leading '../' from member names");
                    self.warned_dotdot = true;
                }
                n = r;
                while let Some(r) = n.strip_prefix(b"/") {
                    n = r;
                }
            }
        }
        let (mut n, print) = pattern::substitute(&self.o.subst, n, Target::Name);
        if print {
            eprintln!("{} >> {}", shown(name), shown(&n));
        }
        if n.is_empty() {
            return None;
        }
        if dir && !n.ends_with(b"/") {
            n.push(b'/');
        }
        Some(n)
    }

    fn excluded(&self, name: &[u8]) -> bool {
        self.o.excludes.iter().any(|p| pattern::excludes(p, name))
    }

    /// Adds `name` (as given on the command line or found in a directory) and, for a
    /// directory, what is in it.
    fn add(&mut self, name: &[u8], top: bool) {
        if self.excluded(name) {
            return;
        }
        let path = Path::new(OsStr::from_bytes(name));
        let follow = self.o.follow || (top && self.o.follow_cmdline);
        let md = if follow { fs::metadata(path) } else { fs::symlink_metadata(path) };
        let md = match md {
            Ok(m) => m,
            Err(e) => return self.fail(name, format_args!("Cannot stat: {}", strerror(&e))),
        };
        if self.me == Some((md.dev(), md.ino())) {
            return self.fail(name, "Can't add archive to itself");
        }
        let ft = md.file_type();
        if ft.is_socket() {
            return self.fail(name, "socket ignored");
        }
        if let Some(mem) = self.member_name(name, ft.is_dir()) {
            let newer = match &self.have {
                Some(h) => h.get(&mem).is_none_or(|&t| md.mtime() > t),
                None => true,
            };
            if newer && let Err(e) = self.store(path, name, mem, &md) {
                // The archive can't be written: nothing more can be done.
                eprintln!("tar: Write error: {}", strerror(&e));
                std::process::exit(1);
            }
        }
        if ft.is_dir() && !self.o.no_recurse {
            let mut kids: Vec<Vec<u8>> = match fs::read_dir(path) {
                Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.file_name().as_bytes().to_vec()).collect(),
                Err(e) => return self.fail(name, format_args!("Couldn't visit directory: {}", strerror(&e))),
            };
            kids.sort();
            for k in kids {
                let mut child = name.to_vec();
                if !child.ends_with(b"/") {
                    child.push(b'/');
                }
                child.extend_from_slice(&k);
                self.add(&child, false);
            }
        }
    }

    /// Writes one member. An `Err` is an archive write error, which ends the run.
    fn store(&mut self, path: &Path, name: &[u8], mem: Vec<u8>, md: &Metadata) -> io::Result<()> {
        let ft = md.file_type();
        let kind = if ft.is_dir() {
            Kind::Dir
        } else if ft.is_symlink() {
            Kind::Symlink
        } else if ft.is_char_device() {
            Kind::Char
        } else if ft.is_block_device() {
            Kind::Block
        } else if ft.is_fifo() {
            Kind::Fifo
        } else {
            Kind::File
        };
        let mut e = Entry::new(mem, kind);
        e.mode = md.mode() & 0o7777;
        e.uid = u64::from(md.uid());
        e.gid = u64::from(md.gid());
        e.uname = user_name(&mut self.users, md.uid());
        e.gname = group_name(&mut self.groups, md.gid());
        e.mtime = md.mtime();
        e.mtime_nsec = md.mtime_nsec().clamp(0, 999_999_999) as u32;
        if matches!(kind, Kind::Char | Kind::Block) {
            e.devmajor = major(md.rdev());
            e.devminor = minor(md.rdev());
        }
        let mut file = None;
        match kind {
            Kind::Symlink => match fs::read_link(path) {
                Ok(t) => {
                    let (t, _) = pattern::substitute(&self.o.subst, t.as_os_str().as_bytes(), Target::Symlink);
                    e.link = t;
                }
                Err(err) => {
                    self.fail(name, format_args!("Couldn't read symbolic link: {}", strerror(&err)));
                    return Ok(());
                }
            },
            Kind::File => {
                let key = (md.dev(), md.ino());
                if md.nlink() > 1
                    && let Some(first) = self.links.get(&key)
                {
                    e.kind = Kind::HardLink;
                    e.link = first.clone();
                } else {
                    match File::open(path) {
                        Ok(f) => file = Some(f),
                        Err(err) => {
                            self.fail(name, format_args!("Couldn't open: {}", strerror(&err)));
                            return Ok(());
                        }
                    }
                    e.size = md.len();
                    if md.nlink() > 1 {
                        self.links.insert(key, e.path.clone());
                    }
                }
            }
            _ => {}
        }
        let h = match header::encode(&e, self.o.format) {
            Ok(h) => h,
            Err(err) => {
                self.fail(name, err);
                return Ok(());
            }
        };
        if self.o.verbose > 0 {
            eprintln!("a {}", shown(&e.path));
        }
        self.w.entry(&h)?;
        if let Some(mut f) = file {
            let mut left = e.size;
            let mut buf = vec![0u8; 64 * 1024];
            while left > 0 {
                let want = (buf.len() as u64).min(left) as usize;
                let n = match f.read(&mut buf[..want]) {
                    Ok(n) => n,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        self.fail(name, format_args!("Read error: {}", strerror(&err)));
                        0
                    }
                };
                if n == 0 {
                    // The file shrank: keep the archive whole.
                    self.fail(name, format_args!("File shrank by {left} bytes; padding with zeros"));
                    let z = vec![0u8; buf.len()];
                    while left > 0 {
                        let k = (z.len() as u64).min(left) as usize;
                        self.w.write_all(&z[..k])?;
                        left -= k as u64;
                    }
                    break;
                }
                self.w.write_all(&buf[..n])?;
                left -= n as u64;
            }
            self.w.pad()?;
        }
        Ok(())
    }
}

/// Scans an archive for -r and -u: where its end blocks start, and (for -u) each member's
/// newest time.
fn scan(f: File, times: bool) -> Result<(u64, HashMap<Vec<u8>, i64>), String> {
    let mut r = Reader::open_file(f)?;
    let mut have = HashMap::new();
    loop {
        match r.next() {
            Ok(Some(e)) => {
                if times {
                    let t = have.entry(e.path.clone()).or_insert(e.mtime);
                    *t = (*t).max(e.mtime);
                }
            }
            Ok(None) => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok((r.end, have))
}

pub fn run(o: &Opts) -> bool {
    let names: Vec<&Operand> = o.operands.iter().collect();
    if o.mode == Mode::Create && !names.iter().any(|n| matches!(n, Operand::Name(_))) {
        eprintln!("tar: no files or directories specified");
        return false;
    }
    let to_stdout = o.file == "-";
    let mut me = None;
    let mut start = 0;
    let mut have = None;
    let (out, out_stdio, file): (Box<dyn Write>, Option<Stdio>, Option<File>) = if to_stdout {
        if o.mode != Mode::Create {
            eprintln!("tar: Cannot append to standard output");
            return false;
        }
        (Box::new(io::BufWriter::with_capacity(64 * 1024, io::stdout())), None, None)
    } else if o.mode == Mode::Create {
        match File::create(&o.file) {
            Ok(f) => {
                if let Ok(m) = f.metadata()
                    && m.is_file()
                {
                    me = Some((m.dev(), m.ino()));
                }
                let stdio = match o.comp {
                    Comp::Zstd => match f.try_clone() {
                        Ok(c) => Some(Stdio::from(c)),
                        Err(e) => {
                            eprintln!("tar: {}: {}", shown(o.file.as_bytes()), strerror(&e));
                            return false;
                        }
                    },
                    _ => None,
                };
                let w = f.try_clone().map(|c| Box::new(io::BufWriter::with_capacity(64 * 1024, c)) as Box<dyn Write>);
                match w {
                    Ok(w) => (w, stdio, Some(f)),
                    Err(e) => {
                        eprintln!("tar: {}: {}", shown(o.file.as_bytes()), strerror(&e));
                        return false;
                    }
                }
            }
            Err(e) => {
                eprintln!("tar: Failed to open '{}': {}", shown(o.file.as_bytes()), strerror(&e));
                return false;
            }
        }
    } else {
        if o.comp != Comp::None {
            eprintln!("tar: Cannot append to a compressed archive");
            return false;
        }
        let f = match OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&o.file) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("tar: {}: {}", shown(o.file.as_bytes()), strerror(&e));
                return false;
            }
        };
        let m = f.metadata().ok();
        if let Some(m) = &m {
            me = Some((m.dev(), m.ino()));
        }
        if m.is_some_and(|m| m.len() > 0) {
            let scanned = f.try_clone().map_err(|e| strerror(&e)).and_then(|c| scan(c, o.mode == Mode::Update));
            match scanned {
                Ok((end, h)) => {
                    start = end;
                    if o.mode == Mode::Update {
                        have = Some(h);
                    }
                }
                Err(m) => {
                    eprintln!("tar: {}: {m}", shown(o.file.as_bytes()));
                    return false;
                }
            }
        }
        use std::io::Seek;
        let mut f = f;
        if let Err(e) = f.seek(io::SeekFrom::Start(start)) {
            eprintln!("tar: {}: {}", shown(o.file.as_bytes()), strerror(&e));
            return false;
        }
        match f.try_clone() {
            Ok(c) => (Box::new(io::BufWriter::with_capacity(64 * 1024, c)), None, Some(f)),
            Err(e) => {
                eprintln!("tar: {}: {}", shown(o.file.as_bytes()), strerror(&e));
                return false;
            }
        }
    };
    let comp = if o.mode == Mode::Create { o.comp } else { Comp::None };
    let w = match Writer::new(out, out_stdio, comp, o.record, start) {
        Ok(w) => w,
        Err(m) => {
            eprintln!("tar: {m}");
            return false;
        }
    };
    let mut c = Create {
        o,
        w,
        links: HashMap::new(),
        users: HashMap::new(),
        groups: HashMap::new(),
        me,
        have,
        warned_slash: false,
        warned_dotdot: false,
        ok: true,
    };
    let mut fatal = false;
    for d in &o.chdir {
        if let Err(m) = chdir(d) {
            eprintln!("tar: {m}");
            fatal = true;
        }
    }
    if !fatal {
        for n in names {
            match n {
                Operand::Chdir(d) => {
                    if let Err(m) = chdir(d) {
                        eprintln!("tar: {m}");
                        fatal = true;
                        break;
                    }
                }
                Operand::Name(n) => c.add(n, true),
            }
        }
    }
    let ok = c.ok && !fatal;
    match c.w.finish() {
        Ok(end) => {
            if o.mode != Mode::Create
                && let Some(f) = file
                && let Err(e) = f.set_len(end)
            {
                eprintln!("tar: {}: {}", shown(o.file.as_bytes()), strerror(&e));
                return false;
            }
        }
        Err(e) => {
            eprintln!("tar: {}: {}", if to_stdout { "stdout".into() } else { shown(o.file.as_bytes()) }, strerror(&e));
            return false;
        }
    }
    if !ok {
        eprintln!("tar: Error exit delayed from previous errors.");
    }
    ok
}
