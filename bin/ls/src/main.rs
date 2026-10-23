//! `ls(1)`: lists directory contents.
//!
//! ```text
//! ls [-1AaCcdFfGgHhikLlmnopqRrSsTtUuwx] [--color=when] [file ...]
//! ```
//!
//! POSIX's ls with the options the BSDs share. Each operand that is a directory has its contents
//! listed; anything else is listed itself, before the directories. With no operand, `.`.
//!
//! - Formats: `-1` one per line, `-C` columns down, `-x` columns across, `-m` a comma-separated
//!   stream, `-l` long. The last one given wins; with none, `-C` on a terminal and `-1` off it.
//!   `-g` (no owner), `-o` (no group) and `-n` (numbers for owner and group) imply `-l`, as POSIX
//!   has them.
//! - Which: `-a` everything, `-A` everything but `.` and `..` (always on for the super-user),
//!   `-d` directories as themselves, `-R` into subdirectories.
//! - Order: by name; `-t` by time, `-S` by size (largest first), `-f` not at all (and `-a`),
//!   `-r` reversed.
//! - Times: the modification time; `-c` the status change, `-u` the access, `-U` the creation
//!   time (status change where the system doesn't keep it), both to show and to sort by. `-T`
//!   shows them in full.
//! - Extras: `-i` inode numbers, `-s` sizes in blocks (512 bytes, `BLOCKSIZE`, or 1024 with
//!   `-k`), `-h` sizes in K, M, G..., `-F` a `/ @ * = |` after names by type, `-p` a `/` after
//!   directories, `-q` `?` for non-printing characters (the default on a terminal), `-w` raw.
//! - Symbolic links named on the command line are followed unless `-d`, `-F` or `-l` is given
//!   (`-H` follows them anyway, `-P` never); `-L` follows all of them.
//! - Colour: `-G`, or `CLICOLOR` set in the environment, on a terminal (or with `CLICOLOR_FORCE`);
//!   `--color=always|auto|never`. The colours are FreeBSD's `LSCOLORS`.
//!
//! Output goes through one buffer, flushed at exit: each console write costs about a millisecond.

use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::Metadata;
use std::io::{self, BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    One,
    Columns,
    Across,
    Stream,
    Long,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Name,
    Time,
    Size,
    None,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TimeField {
    Modify,
    Change,
    Access,
    Birth,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Follow {
    /// The default: command-line links unless -d, -F or -l.
    Default,
    CommandLine,
    Never,
    All,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Color {
    Auto,
    Always,
    Never,
}

struct Opts {
    format: Format,
    sort: Sort,
    reverse: bool,
    time: TimeField,
    all: bool,
    almost_all: bool,
    directory: bool,
    recursive: bool,
    inode: bool,
    size: bool,
    kilo: bool,
    human: bool,
    classify: bool,
    slash: bool,
    numeric: bool,
    no_owner: bool,
    no_group: bool,
    full_time: bool,
    /// Some(true): `?` for non-printing; Some(false): raw; None: by whether stdout is a terminal.
    quote: Option<bool>,
    follow: Follow,
    color: Color,
    color_flag: bool,
}

/// One name to list.
struct Entry {
    /// What is printed: the operand as given, or the name in its directory.
    name: OsString,
    path: PathBuf,
    md: Metadata,
    /// The metadata is the link's own (not followed).
    is_link: bool,
}

/// Everything decided once per run.
struct Ctx {
    o: Opts,
    width: usize,
    quote: bool,
    colors: Option<[Option<String>; 11]>,
    block_size: u64,
    now: i64,
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
    status: u8,
    /// Something has been printed (so a directory header needs a blank line first).
    printed: bool,
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: ls [-1AaCcdFfGgHhikLlmnopqRrSsTtUuwx] [--color=when] [file ...]");
    ExitCode::from(1)
}

fn isatty(fd: i32) -> bool {
    // SAFETY: isatty only looks at the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// The terminal width: `COLUMNS`, else the terminal's, else 80.
fn term_width() -> usize {
    if let Some(n) = std::env::var("COLUMNS").ok().and_then(|c| c.trim().parse::<usize>().ok())
        && n > 0
    {
        return n;
    }
    if isatty(1) {
        // SAFETY: a zeroed winsize for TIOCGWINSZ to fill.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }
    80
}

/// `getbsize(3)`: the block size `BLOCKSIZE` asks for (512 by default), between 512 and 1 GiB.
fn getbsize() -> u64 {
    let Ok(v) = std::env::var("BLOCKSIZE") else {
        return 512;
    };
    let v = v.trim();
    let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let n: u64 = if split == 0 { 1 } else { v[..split].parse().unwrap_or(512) };
    let mult = match &v[split..] {
        "" => 1,
        "k" | "K" => 1024,
        "m" | "M" => 1024 * 1024,
        "g" | "G" => 1024 * 1024 * 1024,
        _ => {
            eprintln!("ls: {v}: unknown blocksize");
            return 512;
        }
    };
    (n * mult).clamp(512, 1024 * 1024 * 1024)
}

/// FreeBSD's `humanize_number(3)` with `HN_AUTOSCALE | HN_B | HN_NOSPACE | HN_DECIMAL`, for a
/// buffer of `len` bytes (so `len - 1` characters).
pub fn humanize(bytes: u64, len: usize, si: bool) -> String {
    let (divisor, deccut): (u64, u64) = if si { (1000, 950) } else { (1024, 973) };
    let prefixes = ["B", "K", "M", "G", "T", "P", "E"];
    let baselen = 2; // a digit and the prefix
    let mut max: u64 = 1;
    for _ in 0..len.saturating_sub(baselen) {
        max *= 10;
    }
    let (mut quotient, mut remainder) = (bytes, 0u64);
    let mut i = 0;
    while (quotient >= max || (quotient == max - 1 && (remainder >= deccut || remainder >= divisor / 2)))
        && i < prefixes.len() - 1
    {
        remainder = quotient % divisor;
        quotient /= divisor;
        i += 1;
    }
    if (quotient < 9 || (quotient == 9 && remainder < deccut)) && i > 0 {
        let s1 = quotient + ((remainder * 10 + divisor / 2) / divisor / 10);
        let s2 = ((remainder * 10 + divisor / 2) / divisor) % 10;
        format!("{s1}.{s2}{}", prefixes[i])
    } else {
        format!("{}{}", quotient + (remainder + divisor / 2) / divisor, prefixes[i])
    }
}

/// `strftime(3)` in local time.
fn ftime(t: i64, fmt: &str) -> String {
    // SAFETY: a zeroed tm for localtime_r to fill.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // time_t is 64 bits on both musl and glibc.
    unsafe { libc::localtime_r(&t, &mut tm) };
    let cfmt = CString::new(fmt).unwrap();
    let mut buf = [0u8; 128];
    // SAFETY: a buffer of the length given and a NUL-terminated format.
    let n = unsafe { libc::strftime(buf.as_mut_ptr().cast(), buf.len(), cfmt.as_ptr(), &tm) };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// strmode(3): the type letter and the nine permission characters.
fn strmode(mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(match mode & libc::S_IFMT {
        libc::S_IFDIR => 'd',
        libc::S_IFLNK => 'l',
        libc::S_IFCHR => 'c',
        libc::S_IFBLK => 'b',
        libc::S_IFIFO => 'p',
        libc::S_IFSOCK => 's',
        _ => '-',
    });
    let bit = |m: u32, c: char| if mode & m != 0 { c } else { '-' };
    s.push(bit(0o400, 'r'));
    s.push(bit(0o200, 'w'));
    s.push(match (mode & 0o100 != 0, mode & 0o4000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        _ => '-',
    });
    s.push(bit(0o040, 'r'));
    s.push(bit(0o020, 'w'));
    s.push(match (mode & 0o010 != 0, mode & 0o2000 != 0) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        _ => '-',
    });
    s.push(bit(0o004, 'r'));
    s.push(bit(0o002, 'w'));
    s.push(match (mode & 0o001 != 0, mode & 0o1000 != 0) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        _ => '-',
    });
    s
}

/// `LSCOLORS` as escape sequences, for: directory, link, socket, FIFO, executable, block device,
/// character device, set-user-ID executable, set-group-ID executable, writable-by-others
/// directory with and without the sticky bit.
fn parse_lscolors(spec: &str) -> [Option<String>; 11] {
    const DEFAULT: &str = "exfxcxdxbxegedabagacad";
    let mut out: [Option<String>; 11] = Default::default();
    let spec: Vec<u8> = spec.bytes().chain(DEFAULT.bytes().skip(spec.len())).collect();
    for (i, slot) in out.iter_mut().enumerate() {
        let (fg, bg) = (spec[2 * i], spec[2 * i + 1]);
        let mut codes = Vec::new();
        let colour = |c: u8| match c {
            b'a'..=b'h' => Some((c - b'a', false)),
            b'A'..=b'H' => Some((c - b'A', true)),
            _ => None,
        };
        if let Some((n, bold)) = colour(fg) {
            if bold {
                codes.push("1".to_string());
            }
            codes.push(format!("3{n}"));
        }
        if let Some((n, _)) = colour(bg) {
            codes.push(format!("4{n}"));
        }
        if !codes.is_empty() {
            *slot = Some(format!("\x1b[{}m", codes.join(";")));
        }
    }
    out
}

impl Ctx {
    fn err(&mut self, what: &OsStr, e: &io::Error) {
        // Errors interleave with the listing in order.
        let _ = io::stdout().flush();
        eprintln!("ls: {}: {}", what.to_string_lossy(), strerror(e));
        self.status = 1;
    }

    fn user(&mut self, uid: u32) -> String {
        if self.o.numeric {
            return uid.to_string();
        }
        self.users
            .entry(uid)
            .or_insert_with(|| {
                // SAFETY: getpwuid's result is read at once.
                let p = unsafe { libc::getpwuid(uid) };
                if p.is_null() {
                    uid.to_string()
                } else {
                    unsafe { CStr::from_ptr((*p).pw_name) }.to_string_lossy().into_owned()
                }
            })
            .clone()
    }

    fn group(&mut self, gid: u32) -> String {
        if self.o.numeric {
            return gid.to_string();
        }
        self.groups
            .entry(gid)
            .or_insert_with(|| {
                // SAFETY: getgrgid's result is read at once.
                let g = unsafe { libc::getgrgid(gid) };
                if g.is_null() {
                    gid.to_string()
                } else {
                    unsafe { CStr::from_ptr((*g).gr_name) }.to_string_lossy().into_owned()
                }
            })
            .clone()
    }

    fn time_of(&self, md: &Metadata) -> (i64, i64) {
        match self.o.time {
            TimeField::Modify => (md.mtime(), md.mtime_nsec()),
            TimeField::Access => (md.atime(), md.atime_nsec()),
            TimeField::Change => (md.ctime(), md.ctime_nsec()),
            TimeField::Birth => match md.created() {
                Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
                    Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
                    Err(e) => (-(e.duration().as_secs() as i64), 0),
                },
                Err(_) => (md.ctime(), md.ctime_nsec()),
            },
        }
    }

    fn sort(&self, v: &mut [Entry]) {
        let by_name = |a: &Entry, b: &Entry| a.name.as_bytes().cmp(b.name.as_bytes());
        match self.o.sort {
            Sort::None => return,
            Sort::Name => v.sort_by(by_name),
            Sort::Time => v.sort_by(|a, b| self.time_of(&b.md).cmp(&self.time_of(&a.md)).then_with(|| by_name(a, b))),
            Sort::Size => v.sort_by(|a, b| b.md.size().cmp(&a.md.size()).then_with(|| by_name(a, b))),
        }
        if self.o.reverse {
            v.reverse();
        }
    }

    fn blocks(&self, md: &Metadata) -> u64 {
        let bytes = md.blocks() * 512;
        bytes.div_ceil(self.block_size)
    }

    fn blocks_text(&self, md: &Metadata) -> String {
        if self.o.human {
            humanize(md.blocks() * 512, 5, false)
        } else {
            self.blocks(md).to_string()
        }
    }

    /// The name as it is shown, without colour or type suffix.
    fn shown_name(&self, name: &OsStr) -> String {
        let bytes = name.as_bytes();
        if !self.quote {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let s = String::from_utf8_lossy(bytes);
        s.chars().map(|c| if c.is_control() || c == '\u{fffd}' { '?' } else { c }).collect()
    }

    fn type_char(&self, e: &Entry) -> Option<char> {
        let mode = e.md.mode();
        if self.o.classify {
            match mode & libc::S_IFMT {
                libc::S_IFDIR => Some('/'),
                libc::S_IFLNK => Some('@'),
                libc::S_IFSOCK => Some('='),
                libc::S_IFIFO => Some('|'),
                libc::S_IFREG if mode & 0o111 != 0 => Some('*'),
                _ => None,
            }
        } else if self.o.slash && mode & libc::S_IFMT == libc::S_IFDIR {
            Some('/')
        } else {
            None
        }
    }

    fn color_of(&self, e: &Entry) -> Option<&str> {
        let colors = self.colors.as_ref()?;
        let mode = e.md.mode();
        let idx = match mode & libc::S_IFMT {
            libc::S_IFDIR if mode & 0o002 != 0 => {
                if mode & 0o1000 != 0 {
                    9
                } else {
                    10
                }
            }
            libc::S_IFDIR => 0,
            libc::S_IFLNK => 1,
            libc::S_IFSOCK => 2,
            libc::S_IFIFO => 3,
            libc::S_IFBLK => 5,
            libc::S_IFCHR => 6,
            libc::S_IFREG if mode & 0o111 != 0 => {
                if mode & 0o4000 != 0 {
                    7
                } else if mode & 0o2000 != 0 {
                    8
                } else {
                    4
                }
            }
            _ => return None,
        };
        colors[idx].as_deref()
    }

    /// Writes the name, coloured, and its type character; the number of columns it took.
    fn put_name(&self, out: &mut dyn Write, e: &Entry) -> usize {
        let shown = self.shown_name(&e.name);
        let mut n = shown.chars().count();
        match self.color_of(e) {
            Some(c) => {
                let _ = write!(out, "{c}{shown}\x1b[0m");
            }
            None => {
                if self.quote {
                    let _ = out.write_all(shown.as_bytes());
                } else {
                    let _ = out.write_all(e.name.as_bytes());
                }
            }
        }
        if let Some(t) = self.type_char(e) {
            let _ = write!(out, "{t}");
            n += 1;
        }
        n
    }

    fn name_width(&self, e: &Entry) -> usize {
        self.shown_name(&e.name).chars().count() + usize::from(self.type_char(e).is_some())
    }

    /// Lists `entries` in the chosen format. `total` is whether a `total` line belongs (a
    /// directory's contents, with -l or -s).
    fn display(&mut self, out: &mut dyn Write, entries: &[Entry], total: bool) {
        if entries.is_empty() && !total {
            return;
        }
        self.printed = true;
        let inode_w = if self.o.inode { entries.iter().map(|e| e.md.ino().to_string().len()).max().unwrap_or(1) } else { 0 };
        let block_w = if self.o.size { entries.iter().map(|e| self.blocks_text(&e.md).len()).max().unwrap_or(1) } else { 0 };
        if total && (self.o.format == Format::Long || self.o.size) {
            let sum: u64 = entries.iter().map(|e| self.blocks(&e.md)).sum();
            if self.o.human {
                let bytes: u64 = entries.iter().map(|e| e.md.blocks() * 512).sum();
                let _ = writeln!(out, "total {}", humanize(bytes, 5, false));
            } else {
                let _ = writeln!(out, "total {sum}");
            }
        }
        match self.o.format {
            Format::Long => self.print_long(out, entries, inode_w, block_w),
            Format::One => {
                for e in entries {
                    self.prefix(out, e, inode_w, block_w);
                    self.put_name(out, e);
                    let _ = writeln!(out);
                }
            }
            Format::Stream => self.print_stream(out, entries, inode_w, block_w),
            Format::Columns | Format::Across => self.print_columns(out, entries, inode_w, block_w),
        }
    }

    fn prefix(&self, out: &mut dyn Write, e: &Entry, inode_w: usize, block_w: usize) -> usize {
        let mut n = 0;
        if self.o.inode {
            let _ = write!(out, "{:>inode_w$} ", e.md.ino());
            n += inode_w + 1;
        }
        if self.o.size {
            let _ = write!(out, "{:>block_w$} ", self.blocks_text(&e.md));
            n += block_w + 1;
        }
        n
    }

    fn print_stream(&self, out: &mut dyn Write, entries: &[Entry], inode_w: usize, block_w: usize) {
        let mut col = 0;
        for (i, e) in entries.iter().enumerate() {
            let last = i + 1 == entries.len();
            let w = self.name_width(e)
                + if self.o.inode { inode_w + 1 } else { 0 }
                + if self.o.size { block_w + 1 } else { 0 };
            if col > 0 && col + w + if last { 0 } else { 2 } >= self.width {
                let _ = writeln!(out);
                col = 0;
            }
            col += self.prefix(out, e, inode_w, block_w);
            col += self.put_name(out, e);
            if !last {
                let _ = write!(out, ", ");
                col += 2;
            }
        }
        if col > 0 {
            let _ = writeln!(out);
        }
    }

    /// FreeBSD's `printcol`: columns padded to tab stops (with spaces when colouring).
    fn print_columns(&self, out: &mut dyn Write, entries: &[Entry], inode_w: usize, block_w: usize) {
        let n = entries.len();
        if n == 0 {
            return;
        }
        let tabs = self.colors.is_none();
        let tab = if tabs { 8 } else { 1 };
        let mut colwidth = entries.iter().map(|e| self.name_width(e)).max().unwrap_or(0);
        if self.o.inode {
            colwidth += inode_w + 1;
        }
        if self.o.size {
            colwidth += block_w + 1;
        }
        colwidth = (colwidth + tab) & !(tab - 1);
        if self.width < 2 * colwidth {
            for e in entries {
                self.prefix(out, e, inode_w, block_w);
                self.put_name(out, e);
                let _ = writeln!(out);
            }
            return;
        }
        let mut numcols = self.width / colwidth;
        let numrows = n.div_ceil(numcols);
        if self.o.format == Format::Columns {
            // Columns down: as many as the rows need.
            numcols = n.div_ceil(numrows);
        }
        for row in 0..numrows {
            let mut endcol = colwidth;
            let mut chcnt = 0;
            for col in 0..numcols {
                let idx = if self.o.format == Format::Across { row * numcols + col } else { col * numrows + row };
                if idx >= n {
                    break;
                }
                chcnt += self.prefix(out, &entries[idx], inode_w, block_w);
                chcnt += self.put_name(out, &entries[idx]);
                let next = if self.o.format == Format::Across { idx + 1 } else { idx + numrows };
                if col + 1 >= numcols || next >= n {
                    break;
                }
                loop {
                    let cnt = (chcnt + tab) & !(tab - 1);
                    if cnt > endcol {
                        break;
                    }
                    let _ = out.write_all(if tabs { b"\t" } else { b" " });
                    chcnt = cnt;
                }
                endcol += colwidth;
            }
            let _ = writeln!(out);
        }
    }

    fn print_long(&mut self, out: &mut dyn Write, entries: &[Entry], inode_w: usize, block_w: usize) {
        struct Row {
            mode: String,
            nlink: String,
            owner: String,
            group: String,
            size: String,
            date: String,
        }
        let six_months = (365 / 2) * 86400;
        let mut rows = Vec::with_capacity(entries.len());
        for e in entries {
            let md = &e.md;
            let ft = md.file_type();
            let size = if ft.is_block_device() || ft.is_char_device() {
                let r = md.rdev();
                format!("{:>3}, {:>3}", libc::major(r as libc::dev_t), libc::minor(r as libc::dev_t))
            } else if self.o.human {
                humanize(md.size(), 5, false)
            } else {
                md.size().to_string()
            };
            let (t, _) = self.time_of(md);
            let fmt = if self.o.full_time {
                "%b %e %H:%M:%S %Y"
            } else if t + six_months > self.now && t < self.now + six_months {
                "%b %e %H:%M"
            } else {
                "%b %e  %Y"
            };
            rows.push(Row {
                mode: strmode(md.mode()),
                nlink: md.nlink().to_string(),
                owner: if self.o.no_owner { String::new() } else { self.user(md.uid()) },
                group: if self.o.no_group { String::new() } else { self.group(md.gid()) },
                size,
                date: ftime(t, fmt),
            });
        }
        let w = |f: &dyn Fn(&Row) -> usize| rows.iter().map(f).max().unwrap_or(0);
        let (nl_w, own_w, grp_w, size_w) = (
            w(&|r| r.nlink.len()),
            w(&|r| r.owner.chars().count()),
            w(&|r| r.group.chars().count()),
            w(&|r| r.size.len()),
        );
        for (e, r) in entries.iter().zip(&rows) {
            self.prefix(out, e, inode_w, block_w);
            let _ = write!(out, "{}  {:>nl_w$} ", r.mode, r.nlink);
            if !self.o.no_owner {
                let _ = write!(out, "{:<own_w$}  ", r.owner);
            }
            if !self.o.no_group {
                let _ = write!(out, "{:<grp_w$}  ", r.group);
            }
            let _ = write!(out, "{:>size_w$} {} ", r.size, r.date);
            self.put_name(out, e);
            if e.md.file_type().is_symlink() {
                match std::fs::read_link(&e.path) {
                    Ok(t) => {
                        let _ = write!(out, " -> {}", self.shown_name(t.as_os_str()));
                    }
                    Err(err) => {
                        let _ = out.flush();
                        eprintln!("ls: {}: {}", e.path.display(), strerror(&err));
                        self.status = 1;
                    }
                }
            }
            let _ = writeln!(out);
        }
    }

    /// The entries of the directory `path`, not yet sorted.
    fn read_dir(&mut self, path: &Path) -> Result<Vec<Entry>, io::Error> {
        let mut v = Vec::new();
        if self.o.all {
            for dot in [".", ".."] {
                let p = path.join(dot);
                if let Ok(md) = std::fs::symlink_metadata(&p) {
                    v.push(Entry { name: dot.into(), path: p, md, is_link: false });
                }
            }
        }
        for de in std::fs::read_dir(path)? {
            let de = match de {
                Ok(d) => d,
                Err(e) => {
                    self.err(path.as_os_str(), &e);
                    break;
                }
            };
            let name = de.file_name();
            if name.as_bytes().first() == Some(&b'.') && !self.o.all && !self.o.almost_all {
                continue;
            }
            let p = de.path();
            let md = if self.o.follow == Follow::All {
                std::fs::metadata(&p).or_else(|_| std::fs::symlink_metadata(&p))
            } else {
                std::fs::symlink_metadata(&p)
            };
            match md {
                Ok(md) => {
                    let is_link = md.file_type().is_symlink();
                    v.push(Entry { name, path: p, md, is_link });
                }
                Err(e) => self.err(&name, &e),
            }
        }
        Ok(v)
    }

    /// Lists a directory's contents, then (with -R) its subdirectories'.
    fn list_dir(&mut self, out: &mut dyn Write, path: &Path, header: bool) {
        if header {
            if self.printed {
                let _ = writeln!(out);
            }
            let _ = writeln!(out, "{}:", path.display());
            self.printed = true;
        }
        let mut entries = match self.read_dir(path) {
            Ok(v) => v,
            Err(e) => {
                let _ = out.flush();
                self.err(path.as_os_str(), &e);
                return;
            }
        };
        self.sort(&mut entries);
        self.display(out, &entries, true);
        if self.o.recursive {
            for e in &entries {
                if e.md.is_dir() && e.name != "." && e.name != ".." && !(e.is_link && self.o.follow != Follow::All) {
                    self.list_dir(out, &e.path, true);
                }
            }
        }
    }
}

pub(crate) fn main() -> ExitCode {
    let mut o = Opts {
        format: if isatty(1) { Format::Columns } else { Format::One },
        sort: Sort::Name,
        reverse: false,
        time: TimeField::Modify,
        all: false,
        // SAFETY: getuid can't fail.
        almost_all: unsafe { libc::getuid() } == 0,
        directory: false,
        recursive: false,
        inode: false,
        size: false,
        kilo: false,
        human: false,
        classify: false,
        slash: false,
        numeric: false,
        no_owner: false,
        no_group: false,
        full_time: false,
        quote: None,
        follow: Follow::Default,
        color: Color::Auto,
        color_flag: false,
    };
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut i = 0;
    let mut by_time = false;
    let mut by_size = false;
    let mut unsorted = false;
    while i < args.len() {
        let a = args[i].as_bytes();
        if a == b"--" {
            i += 1;
            break;
        }
        if let Some(when) = a.strip_prefix(b"--color") {
            o.color = match when {
                b"" | b"=always" | b"=yes" | b"=force" => Color::Always,
                b"=auto" | b"=tty" | b"=if-tty" => Color::Auto,
                b"=never" | b"=no" | b"=none" => Color::Never,
                _ => {
                    eprintln!("ls: unsupported --color value '{}'", String::from_utf8_lossy(&when[1..]));
                    return usage();
                }
            };
            o.color_flag = true;
            i += 1;
            continue;
        }
        if a.len() < 2 || a[0] != b'-' {
            break;
        }
        for &c in &a[1..] {
            match c {
                b'1' => o.format = Format::One,
                b'C' => o.format = Format::Columns,
                b'x' => o.format = Format::Across,
                b'm' => o.format = Format::Stream,
                b'l' => o.format = Format::Long,
                b'n' => {
                    o.format = Format::Long;
                    o.numeric = true;
                }
                b'g' => {
                    o.format = Format::Long;
                    o.no_owner = true;
                }
                b'o' => {
                    o.format = Format::Long;
                    o.no_group = true;
                }
                b'a' => o.all = true,
                b'A' => o.almost_all = true,
                b'd' => o.directory = true,
                b'R' => o.recursive = true,
                b'r' => o.reverse = true,
                b't' => by_time = true,
                b'S' => by_size = true,
                b'f' => {
                    unsorted = true;
                    o.all = true;
                }
                b'c' => o.time = TimeField::Change,
                b'u' => o.time = TimeField::Access,
                b'U' => o.time = TimeField::Birth,
                b'T' => o.full_time = true,
                b'i' => o.inode = true,
                b's' => o.size = true,
                b'k' => {
                    o.kilo = true;
                    o.human = false;
                }
                b'h' => {
                    o.human = true;
                    o.kilo = false;
                }
                b'F' => {
                    o.classify = true;
                    o.slash = false;
                }
                b'p' => {
                    o.slash = true;
                    o.classify = false;
                }
                b'q' => o.quote = Some(true),
                b'w' => o.quote = Some(false),
                b'H' => o.follow = Follow::CommandLine,
                b'L' => o.follow = Follow::All,
                b'P' => o.follow = Follow::Never,
                b'G' => o.color_flag = true,
                _ => {
                    eprintln!("ls: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
        i += 1;
    }
    // -S over -t, as FreeBSD; -f over both.
    o.sort = if unsorted {
        Sort::None
    } else if by_size {
        Sort::Size
    } else if by_time {
        Sort::Time
    } else {
        Sort::Name
    };
    if unsorted {
        o.reverse = false;
    }

    let tty = isatty(1);
    let want_color = match o.color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => {
            (o.color_flag || std::env::var_os("CLICOLOR").is_some())
                && (tty || std::env::var_os("CLICOLOR_FORCE").is_some())
        }
    };
    let colors = want_color.then(|| parse_lscolors(&std::env::var("LSCOLORS").unwrap_or_default()));
    let block_size = if o.kilo { 1024 } else { getbsize() };
    let quote = o.quote.unwrap_or(tty);
    let follow_cmdline = match o.follow {
        Follow::All | Follow::CommandLine => true,
        Follow::Never => false,
        Follow::Default => !(o.directory || o.classify || o.format == Format::Long),
    };
    let mut ctx = Ctx {
        width: term_width(),
        quote,
        colors,
        block_size,
        // SAFETY: time(NULL) can't fail.
        now: unsafe { libc::time(std::ptr::null_mut()) } as i64,
        users: HashMap::new(),
        groups: HashMap::new(),
        status: 0,
        printed: false,
        o,
    };

    let mut operands: Vec<OsString> = args[i..].to_vec();
    if operands.is_empty() {
        operands.push(".".into());
    }
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for op in &operands {
        let p = PathBuf::from(op);
        let md = if follow_cmdline {
            std::fs::metadata(&p).or_else(|_| std::fs::symlink_metadata(&p))
        } else {
            std::fs::symlink_metadata(&p)
        };
        match md {
            Ok(md) => {
                let is_link = md.file_type().is_symlink();
                let e = Entry { name: op.clone(), path: p, md, is_link };
                if e.md.is_dir() && !ctx.o.directory {
                    dirs.push(e);
                } else {
                    files.push(e);
                }
            }
            Err(e) => {
                eprintln!("ls: {}: {}", op.to_string_lossy(), strerror(&e));
                ctx.status = 1;
            }
        }
    }
    let stdout = io::stdout();
    let mut out = BufWriter::with_capacity(64 * 1024, stdout.lock());
    ctx.sort(&mut files);
    ctx.sort(&mut dirs);
    ctx.display(&mut out, &files, false);
    // A directory gets a heading when there are several operands, or after other output.
    let headers = operands.len() > 1;
    for d in &dirs {
        let header = headers || ctx.printed;
        ctx.list_dir(&mut out, &d.path, header);
    }
    if let Err(e) = out.flush() {
        eprintln!("ls: stdout: {}", strerror(&e));
        return ExitCode::from(1);
    }
    ExitCode::from(ctx.status)
}
