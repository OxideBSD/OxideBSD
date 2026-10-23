//! `df(1)`: shows free disk space.
//!
//! ```text
//! df [-b | -g | -H | -h | -k | -m | -P] [-acilnT] [-t type] [file | filesystem ...]
//! ```
//!
//! For every mounted file system, or those holding each `file` (or mounted from each device
//! `filesystem`): its size, used and available space, how full it is, and where it is mounted.
//!
//! - Units: 512-byte blocks, or `BLOCKSIZE`; `-b` 512 bytes, `-k` KiB, `-m` MiB, `-g` GiB; `-h`
//!   sizes with a unit suffix in powers of 1024, `-H` of 1000. `-P` is POSIX's output (its
//!   header, 512-byte blocks unless `-k`, capacity rounded up). The last of these counts, but `-k`
//!   with `-P` makes 1024-byte blocks in either order.
//! - `-i` adds inodes used and free; `-T` the file system type; `-c` a total line.
//! - `-t type[,type...]` only those types (`-t nofoo,bar` all but them); `-l` only local file
//!   systems. `-a` shows all (OxideBSD hides none). `-n` uses the counts the kernel has to hand,
//!   asking no file system (`getvfsstat(2)` with `ST_NOWAIT`).
//!
//! On OxideBSD the mounted file systems come from `getvfsstat(2)`, whose records (NetBSD's
//! `struct statvfs`) name each one's type, mount point and source. Elsewhere (a host test) they
//! come from `/proc/mounts` and `statvfs(3)`.

use std::ffi::CStr;
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::process::ExitCode;

/// One mounted file system.
#[derive(Clone, Default)]
struct Fs {
    from: String,
    on: String,
    fstype: String,
    frsize: u64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Units {
    Blocks(u64),
    Human { si: bool },
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: df [-b | -g | -H | -h | -k | -m | -P] [-acilnT] [-t type] [file | filesystem ...]");
    ExitCode::from(1)
}

#[cfg(target_os = "oxidebsd")]
mod sys {
    use super::Fs;

    unsafe extern "C" {
        fn getvfsstat(buf: *mut libc::statvfs, bufsize: usize, flags: libc::c_int) -> libc::c_int;
    }
    const ST_WAIT: libc::c_int = 1;
    const ST_NOWAIT: libc::c_int = 2;

    fn text(b: &[libc::c_char]) -> String {
        let bytes: Vec<u8> = b.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn from_statvfs(s: &libc::statvfs) -> Fs {
        Fs {
            from: text(&s.f_mntfromname),
            on: text(&s.f_mntonname),
            fstype: text(&s.f_fstypename),
            frsize: if s.f_frsize != 0 { s.f_frsize as u64 } else { s.f_bsize as u64 },
            blocks: s.f_blocks as u64,
            bfree: s.f_bfree as u64,
            bavail: s.f_bavail as u64,
            files: s.f_files as u64,
            ffree: s.f_ffree as u64,
        }
    }

    pub fn mounted(nowait: bool) -> std::io::Result<Vec<Fs>> {
        let flags = if nowait { ST_NOWAIT } else { ST_WAIT };
        // SAFETY: a null buffer only counts.
        let n = unsafe { getvfsstat(core::ptr::null_mut(), 0, flags) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let room = n as usize + 4;
        let mut buf: Vec<libc::statvfs> = Vec::with_capacity(room);
        // SAFETY: room records of space; the call fills at most that many.
        let got = unsafe { getvfsstat(buf.as_mut_ptr(), room * size_of::<libc::statvfs>(), flags) };
        if got < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the call filled `got` records.
        unsafe { buf.set_len(got as usize) };
        Ok(buf.iter().map(from_statvfs).collect())
    }

    /// The file system holding `path`.
    pub fn of_path(path: &str, _all: &[Fs]) -> std::io::Result<Fs> {
        let c = std::ffi::CString::new(path).unwrap_or_default();
        // SAFETY: a zeroed statvfs for the call to fill.
        let mut s: libc::statvfs = unsafe { core::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(from_statvfs(&s))
    }
}

#[cfg(not(target_os = "oxidebsd"))]
mod sys {
    use super::Fs;
    use std::os::unix::fs::MetadataExt;

    fn unescape(s: &str) -> String {
        // /proc/mounts writes a space as \040 and so on.
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 3 < b.len() + 0 && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push(((b[i + 1] - b'0') << 6) | ((b[i + 2] - b'0') << 3) | (b[i + 3] - b'0'));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn fill(fs: &mut Fs) -> bool {
        let c = std::ffi::CString::new(fs.on.as_str()).unwrap_or_default();
        // SAFETY: a zeroed statvfs for the call to fill.
        let mut s: libc::statvfs = unsafe { core::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
            return false;
        }
        fs.frsize = if s.f_frsize != 0 { s.f_frsize as u64 } else { s.f_bsize as u64 };
        fs.blocks = s.f_blocks as u64;
        fs.bfree = s.f_bfree as u64;
        fs.bavail = s.f_bavail as u64;
        fs.files = s.f_files as u64;
        fs.ffree = s.f_ffree as u64;
        true
    }

    pub fn mounted(_nowait: bool) -> std::io::Result<Vec<Fs>> {
        let text = std::fs::read_to_string("/proc/mounts")?;
        let mut v = Vec::new();
        for l in text.lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 {
                continue;
            }
            let mut fs = Fs { from: unescape(f[0]), on: unescape(f[1]), fstype: f[2].to_string(), ..Default::default() };
            if fill(&mut fs) {
                v.push(fs);
            }
        }
        Ok(v)
    }

    /// The file system holding `path`: the last mount on the same device.
    pub fn of_path(path: &str, all: &[Fs]) -> std::io::Result<Fs> {
        let dev = std::fs::metadata(path)?.dev();
        all.iter()
            .rev()
            .find(|f| std::fs::metadata(&f.on).map(|m| m.dev() == dev).unwrap_or(false))
            .cloned()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))
    }
}

/// FreeBSD's `getbsize(3)`: the block size and its header.
fn getbsize() -> (u64, String) {
    let n = match std::env::var("BLOCKSIZE") {
        Ok(v) => {
            let v = v.trim().to_string();
            let split = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
            let n: u64 = if split == 0 { 1 } else { v[..split].parse().unwrap_or(512) };
            let mult = match &v[split..] {
                "" => 1,
                "k" | "K" => 1 << 10,
                "m" | "M" => 1 << 20,
                "g" | "G" => 1 << 30,
                _ => {
                    eprintln!("df: {v}: unknown blocksize");
                    0
                }
            };
            if mult == 0 { 512 } else { (n * mult).clamp(512, 1 << 30) }
        }
        Err(_) => 512,
    };
    (n, block_header(n))
}

fn block_header(n: u64) -> String {
    for (shift, unit) in [(30, 'G'), (20, 'M'), (10, 'K')] {
        if n >= 1 << shift && n % (1 << shift) == 0 {
            return format!("{}{unit}-blocks", n >> shift);
        }
    }
    format!("{n}-blocks")
}

/// FreeBSD's `humanize_number(3)` as df calls it (`HN_B | HN_NOSPACE | HN_DECIMAL`, four
/// characters).
fn humanize(bytes: u64, si: bool) -> String {
    let (divisor, deccut): (u64, u64) = if si { (1000, 950) } else { (1024, 973) };
    let prefixes = ["B", "K", "M", "G", "T", "P", "E"];
    let max: u64 = 1000; // three digits and the prefix
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

/// File system types that are not local, for -l.
const REMOTE: &[&str] = &["nfs", "nfs4", "smbfs", "cifs", "fusefs", "afs", "9p", "sshfs"];

struct TypeFilter {
    negate: bool,
    types: Vec<String>,
}

impl TypeFilter {
    fn allows(&self, t: &str) -> bool {
        self.types.iter().any(|x| x == t) != self.negate
    }
}

pub(crate) fn main() -> ExitCode {
    let (mut bsize, mut header) = getbsize();
    let mut units = Units::Blocks(bsize);
    let (mut posix, mut kflag) = (false, false);
    let (mut inodes, mut fstype, mut total, mut local, mut nowait) = (false, false, false, false, false);
    let mut filter: Option<TypeFilter> = None;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if a.len() < 2 || !a.starts_with('-') {
            break;
        }
        let mut chars = a[1..].chars();
        while let Some(c) = chars.next() {
            match c {
                'a' => {}
                'b' => {
                    (bsize, header, units) = (512, block_header(512), Units::Blocks(512));
                    posix = false;
                }
                'k' => {
                    (bsize, header, units) = (1024, block_header(1024), Units::Blocks(1024));
                    kflag = true;
                }
                'm' => {
                    (bsize, header, units) = (1 << 20, block_header(1 << 20), Units::Blocks(1 << 20));
                    posix = false;
                }
                'g' => {
                    (bsize, header, units) = (1 << 30, block_header(1 << 30), Units::Blocks(1 << 30));
                    posix = false;
                }
                'h' => {
                    units = Units::Human { si: false };
                    posix = false;
                }
                'H' => {
                    units = Units::Human { si: true };
                    posix = false;
                }
                'P' => posix = true,
                'c' => total = true,
                'i' => inodes = true,
                'l' => local = true,
                'n' => nowait = true,
                'T' => fstype = true,
                't' => {
                    let rest: String = chars.by_ref().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => return usage(),
                        }
                    };
                    if filter.is_some() {
                        eprintln!("df: only one -t option may be specified");
                        return ExitCode::from(1);
                    }
                    let (negate, list) = match v.strip_prefix("no") {
                        Some(r) => (true, r),
                        None => (false, v.as_str()),
                    };
                    filter = Some(TypeFilter {
                        negate,
                        types: list.split(',').map(|t| t.strip_prefix("no").unwrap_or(t).to_string()).collect(),
                    });
                }
                _ => {
                    eprintln!("df: illegal option -- {c}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    if posix {
        // POSIX: 512-byte units, or 1024 with -k.
        bsize = if kflag { 1024 } else { 512 };
        header = format!("{bsize}-blocks");
        units = Units::Blocks(bsize);
    }
    let _ = bsize;

    let all = match sys::mounted(nowait) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("df: getvfsstat: {}", strerror(&e));
            return ExitCode::from(1);
        }
    };
    let mut status = 0u8;
    let mut list: Vec<Fs> = Vec::new();
    let operands = &args[i..];
    if operands.is_empty() {
        list = all.clone();
    } else {
        for op in operands {
            let md = match std::fs::metadata(op) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("df: {op}: {}", strerror(&e));
                    status = 1;
                    continue;
                }
            };
            // A device: the file system mounted from it.
            if md.file_type().is_block_device() || md.file_type().is_char_device() {
                let found = all.iter().rev().find(|f| {
                    f.from == *op || std::fs::metadata(&f.from).map(|m| m.rdev() == md.rdev() && m.rdev() != 0).unwrap_or(false)
                });
                match found {
                    Some(f) => list.push(f.clone()),
                    None => {
                        eprintln!("df: {op}: not mounted");
                        status = 1;
                    }
                }
                continue;
            }
            match sys::of_path(op, &all) {
                Ok(f) => list.push(f),
                Err(e) => {
                    eprintln!("df: {op}: {}", strerror(&e));
                    status = 1;
                }
            }
        }
    }
    list.retain(|f| {
        filter.as_ref().is_none_or(|t| t.allows(&f.fstype)) && !(local && REMOTE.contains(&f.fstype.as_str()))
    });
    if list.is_empty() {
        return ExitCode::from(status);
    }
    if total {
        let mut t = Fs { from: "total".into(), frsize: 512, ..Default::default() };
        for f in &list {
            t.blocks += f.blocks * f.frsize / 512;
            t.bfree += f.bfree * f.frsize / 512;
            t.bavail += f.bavail * f.frsize / 512;
            t.files += f.files;
            t.ffree += f.ffree;
        }
        list.push(t);
    }

    // Rows as text, then widths.
    struct Row {
        from: String,
        fstype: String,
        size: String,
        used: String,
        avail: String,
        cap: String,
        iused: String,
        ifree: String,
        ipct: String,
        on: String,
    }
    let show = |count: u64, frsize: u64| -> String {
        let bytes = count as u128 * frsize as u128;
        match units {
            Units::Blocks(b) => (bytes / b as u128).to_string(),
            Units::Human { si } => humanize(bytes.min(u64::MAX as u128) as u64, si),
        }
    };
    let rows: Vec<Row> = list
        .iter()
        .map(|f| {
            let used = f.blocks.saturating_sub(f.bfree);
            let availblks = f.bavail + used;
            let pct = if availblks == 0 { 100.0 } else { used as f64 / availblks as f64 * 100.0 };
            let pct = if posix { pct.ceil() } else { pct.round() };
            let iused = f.files.saturating_sub(f.ffree);
            let ipct = if f.files == 0 { 100.0 } else { iused as f64 / f.files as f64 * 100.0 };
            Row {
                from: f.from.clone(),
                fstype: f.fstype.clone(),
                size: show(f.blocks, f.frsize),
                used: show(used, f.frsize),
                avail: show(f.bavail, f.frsize),
                cap: format!("{pct:.0}%"),
                iused: iused.to_string(),
                ifree: f.ffree.to_string(),
                ipct: format!("{:.0}%", ipct.round()),
                on: f.on.clone(),
            }
        })
        .collect();
    let size_header = if matches!(units, Units::Human { .. }) { "Size".to_string() } else { header };
    let avail_header = if posix { "Available" } else { "Avail" };
    let w = |h: &str, f: &dyn Fn(&Row) -> usize| rows.iter().map(f).max().unwrap_or(0).max(h.len());
    let from_w = w("Filesystem", &|r| r.from.chars().count());
    let type_w = w("Type", &|r| r.fstype.len());
    let size_w = w(&size_header, &|r| r.size.len());
    let used_w = w("Used", &|r| r.used.len());
    let avail_w = w(avail_header, &|r| r.avail.len());
    let iused_w = w("iused", &|r| r.iused.len());
    let ifree_w = w("ifree", &|r| r.ifree.len());

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let _ = write!(out, "{:<from_w$}", "Filesystem");
    if fstype {
        let _ = write!(out, "  {:<type_w$}", "Type");
    }
    let _ = write!(out, " {size_header:>size_w$} {:>used_w$} {avail_header:>avail_w$} Capacity", "Used");
    if inodes {
        let _ = write!(out, " {:>iused_w$} {:>ifree_w$} %iused", "iused", "ifree");
    }
    let _ = writeln!(out, "  Mounted on");
    for r in &rows {
        let _ = write!(out, "{:<from_w$}", r.from);
        if fstype {
            let _ = write!(out, "  {:<type_w$}", r.fstype);
        }
        let _ = write!(out, " {:>size_w$} {:>used_w$} {:>avail_w$} {:>6}", r.size, r.used, r.avail, r.cap);
        if inodes {
            let _ = write!(out, " {:>iused_w$} {:>ifree_w$} {:>5} ", r.iused, r.ifree, r.ipct);
        } else {
            let _ = write!(out, "  ");
        }
        let _ = writeln!(out, "  {}", r.on);
    }
    if let Err(e) = out.flush() {
        eprintln!("df: stdout: {}", strerror(&e));
        return ExitCode::from(1);
    }
    ExitCode::from(status)
}
