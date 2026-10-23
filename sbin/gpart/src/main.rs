//! `gpart(8)`: shows and changes disks' partition tables (OxideBSD-doc `INSTALLER.md` §8), with
//! FreeBSD's verbs, over `lib/libpart`.
//!
//! ```text
//! gpart show [-l] [geom ...]
//! gpart create -s gpt|mbr geom
//! gpart destroy [-F] geom
//! gpart add -t type [-b start] [-s size] [-l label] geom
//! gpart delete -i index geom
//! gpart resize -i index [-s size] geom
//! gpart modify -i index [-l label] [-t type] geom
//! gpart set|unset -a active -i index geom
//! ```
//!
//! A geom is a disk's name (`ide0`, `/dev/ide0`), or an image file. Starts and sizes are sectors,
//! or bytes with a `k`, `m`, `g` or `t` suffix; a new partition starts on a 1 MiB boundary unless
//! `-b` says where, and runs to the end of its free space unless `-s` says how far. Each change is
//! written at once, then the kernel told to read the table again (`DIOCRESCAN`): a disk with a
//! partition mounted or open keeps its old partitions until they're let go, and gpart says so.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

use part::{Kind, Scheme, Table};

const DIOCGSECTORSIZE: u64 = 0x8004_6480;
const DIOCGMEDIASIZE: u64 = 0x8008_6481;
const DIOCRESCAN: u64 = 0x6482;

fn usage() -> ExitCode {
    eprintln!(
        "usage: gpart show [-l] [geom ...]
       gpart create -s gpt|mbr geom
       gpart destroy [-F] geom
       gpart add -t type [-b start] [-s size] [-l label] geom
       gpart delete -i index geom
       gpart resize -i index [-s size] geom
       gpart modify -i index [-l label] [-t type] geom
       gpart set|unset -a active -i index geom"
    );
    ExitCode::from(1)
}

/// An open disk or image.
struct Geom {
    name: String,
    file: File,
    sector_size: u32,
    sectors: u64,
    /// A disk device, not an image file: the kernel is told when its table changes.
    device: bool,
}

impl part::Disk for Geom {
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.file.read_exact_at(buf, lba * self.sector_size as u64).is_ok()
    }
}

impl Geom {
    fn open(arg: &str, write: bool) -> Result<Geom, String> {
        let (path, name) = match arg.strip_prefix("/dev/") {
            Some(n) => (arg.to_string(), n.to_string()),
            None if !arg.contains('/') && std::path::Path::new(&format!("/dev/{arg}")).exists() => (format!("/dev/{arg}"), arg.to_string()),
            None => (arg.to_string(), arg.rsplit('/').next().unwrap_or(arg).to_string()),
        };
        let file = OpenOptions::new().read(true).write(write).open(&path).map_err(|e| format!("{path}: {e}"))?;
        let mut ss: u32 = 0;
        let mut bytes: i64 = 0;
        // SAFETY: each request writes one value of the type passed.
        let device = unsafe {
            libc::ioctl(file.as_raw_fd(), DIOCGSECTORSIZE as _, &mut ss) == 0
                && libc::ioctl(file.as_raw_fd(), DIOCGMEDIASIZE as _, &mut bytes) == 0
        };
        let (sector_size, size) = if device {
            (ss, bytes as u64)
        } else {
            (512, file.metadata().map_err(|e| format!("{path}: {e}"))?.len())
        };
        if !sector_size.is_power_of_two() || sector_size < 512 {
            return Err(format!("{name}: a sector size of {sector_size}"));
        }
        Ok(Geom { name, file, sector_size, sectors: size / sector_size as u64, device })
    }

    fn table(&mut self) -> Result<Option<Table>, String> {
        part::read(self).map_err(|()| format!("{}: can't read the disk", self.name))
    }

    /// Writes `sectors` (`Table::write`'s), then has the kernel read the table again.
    fn write(&mut self, sectors: &[(u64, Vec<u8>)]) -> Result<(), String> {
        for (lba, bytes) in sectors {
            self.file.write_all_at(bytes, lba * self.sector_size as u64).map_err(|e| format!("{}: {e}", self.name))?;
        }
        self.file.sync_all().map_err(|e| format!("{}: {e}", self.name))?;
        if self.device {
            // SAFETY: a request with no argument.
            if unsafe { libc::ioctl(self.file.as_raw_fd(), DIOCRESCAN as _, 0) } < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EBUSY) {
                    eprintln!("gpart: {}: a partition is in use: the system sees the new table once it's let go", self.name);
                } else {
                    eprintln!("gpart: {}: the system didn't reread the table: {e}", self.name);
                }
            }
        }
        Ok(())
    }

    /// A partition's name: `ide0p2` (GPT) or `ide0s2` (MBR).
    fn part_name(&self, scheme: Scheme, index: u32) -> String {
        format!("{}{}{index}", self.name, if scheme == Scheme::Gpt { 'p' } else { 's' })
    }
}

/// A size or start: sectors, or bytes with a suffix, in `ss`-byte sectors (bytes rounded down).
fn parse_amount(s: &str, ss: u32) -> Result<u64, String> {
    let bad = || format!("{s}: not a number of sectors, or bytes with k, m, g or t");
    let (num, mult): (&str, Option<u64>) = match s.as_bytes().last().map(u8::to_ascii_lowercase) {
        Some(b'b') => (&s[..s.len() - 1], Some(1)),
        Some(b'k') => (&s[..s.len() - 1], Some(1 << 10)),
        Some(b'm') => (&s[..s.len() - 1], Some(1 << 20)),
        Some(b'g') => (&s[..s.len() - 1], Some(1 << 30)),
        Some(b't') => (&s[..s.len() - 1], Some(1 << 40)),
        _ => (s, None),
    };
    let n: u64 = num.parse().map_err(|_| bad())?;
    match mult {
        None => Ok(n),
        Some(m) => n.checked_mul(m).map(|b| b / ss as u64).ok_or_else(bad),
    }
}

/// FreeBSD's humanize_number: `512K`, `1.5G`, `20G`.
fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u > 0 && v < 10.0 && (v * 10.0).round() % 10.0 != 0.0 { format!("{v:.1}{}", UNITS[u]) } else { format!("{}{}", v.round(), UNITS[u]) }
}

/// A new partition's unique GUID, from the system's randomness.
fn random_guid() -> Result<[u8; 16], String> {
    let mut g = [0u8; 16];
    File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut g)).map_err(|e| format!("/dev/urandom: {e}"))?;
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    Ok(g)
}

/// The disks the kernel has (`kern.disks`), for `gpart show` with none named.
fn all_disks() -> Vec<String> {
    let out = std::process::Command::new("/sbin/sysctl").args(["-n", "kern.disks"]).output();
    out.map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().map(String::from).collect()).unwrap_or_default()
}

fn show(geoms: &[String], labels: bool) -> Result<(), String> {
    let named = !geoms.is_empty();
    let list = if named { geoms.to_vec() } else { all_disks() };
    let mut out = String::new();
    for g in &list {
        let mut geom = match Geom::open(g, false) {
            Ok(geom) => geom,
            Err(e) if named => return Err(e),
            Err(_) => continue,
        };
        let Some(t) = geom.table()? else {
            if named {
                return Err(format!("{}: no partition table", geom.name));
            }
            continue;
        };
        let ss = t.sector_size as u64;
        let usable = t.last_usable + 1 - t.first_usable;
        let corrupt = if t.from_backup { " [CORRUPT]" } else { "" };
        out += &format!(
            "=>{:>10}{:>11}  {}  {}  ({}){corrupt}\n",
            t.first_usable,
            usable,
            geom.name,
            t.scheme.name(),
            human(t.disk_sectors * ss)
        );
        let mut rows: Vec<(u64, u64, Option<&part::Entry>)> = t.entries.iter().map(|e| (e.first, e.sectors, Some(e))).collect();
        rows.extend(t.free().into_iter().map(|(at, n)| (at, n, None)));
        rows.sort_by_key(|r| r.0);
        for (first, sectors, e) in rows {
            let what = match e {
                Some(e) if labels => format!("{:>6}  {}", e.index, if e.label.is_empty() { "(null)" } else { &e.label }),
                Some(e) => format!("{:>6}  {}{}", e.index, e.kind().name(), if e.active { "  [active]" } else { "" }),
                None => "        - free -".to_string(),
            };
            out += &format!("{first:>12}{sectors:>11}{what}  ({})\n", human(sectors * ss));
        }
        out += "\n";
    }
    print!("{out}");
    Ok(())
}

/// The options a verb took, and its one operand.
struct Opts {
    flags: Vec<(char, Option<String>)>,
    geom: String,
}

impl Opts {
    fn get(&self, c: char) -> Option<&str> {
        self.flags.iter().find(|(f, _)| *f == c).and_then(|(_, v)| v.as_deref())
    }
    fn has(&self, c: char) -> bool {
        self.flags.iter().any(|(f, _)| *f == c)
    }
    fn index(&self) -> Result<u32, String> {
        self.get('i').ok_or("-i index is needed")?.parse().map_err(|_| "-i: a partition's number".to_string())
    }
}

/// `args` as options (those in `with_value` take one) and one geom.
fn parse_opts(args: &[String], with_value: &str, flags: &str) -> Option<Opts> {
    let mut out = Vec::new();
    let mut it = args.iter();
    let mut geom = None;
    while let Some(a) = it.next() {
        if let Some(f) = a.strip_prefix('-').and_then(|f| f.chars().next()).filter(|_| a.len() == 2) {
            if with_value.contains(f) {
                out.push((f, Some(it.next()?.clone())));
            } else if flags.contains(f) {
                out.push((f, None));
            } else {
                return None;
            }
        } else if geom.is_none() {
            geom = Some(a.clone());
        } else {
            return None;
        }
    }
    Some(Opts { flags: out, geom: geom? })
}

fn kind_of(name: &str, scheme: Scheme) -> Result<part::TypeCode, String> {
    let names: Vec<&str> = Kind::NAMED.iter().map(|(n, _)| *n).collect();
    let kind = Kind::parse(name).ok_or_else(|| format!("{name}: no such type ({}, or !<type>)", names.join(", ")))?;
    kind.code(scheme).ok_or_else(|| format!("{name}: not a type a{} {} table has", if scheme == Scheme::Mbr { "n" } else { "" }, scheme.name()))
}

fn run(verb: &str, args: &[String]) -> Result<(), String> {
    let lib = |e: part::Error| e.to_string();
    match verb {
        "show" => {
            let labels = args.iter().any(|a| a == "-l");
            let geoms: Vec<String> = args.iter().filter(|a| *a != "-l").cloned().collect();
            if geoms.iter().any(|g| g.starts_with('-')) {
                return Err(String::new());
            }
            show(&geoms, labels)
        }
        "create" => {
            let o = parse_opts(args, "s", "").ok_or_else(String::new)?;
            let scheme = match o.get('s').map(str::to_ascii_lowercase).as_deref() {
                Some("gpt") => Scheme::Gpt,
                Some("mbr") => Scheme::Mbr,
                _ => return Err("-s gpt or -s mbr is needed".into()),
            };
            let mut g = Geom::open(&o.geom, true)?;
            if g.table()?.is_some_and(|t| !(t.scheme == Scheme::Mbr && t.entries.is_empty())) {
                return Err(format!("{}: has a partition table already (gpart destroy it first)", g.name));
            }
            let t = Table::new(scheme, g.sector_size, g.sectors, random_guid()?).map_err(lib)?;
            g.write(&t.write())?;
            println!("{} created", g.name);
            Ok(())
        }
        "destroy" => {
            let o = parse_opts(args, "", "F").ok_or_else(String::new)?;
            let mut g = Geom::open(&o.geom, true)?;
            let t = g.table()?.ok_or(format!("{}: no partition table", g.name))?;
            if !t.entries.is_empty() && !o.has('F') {
                return Err(format!("{}: has partitions (delete them, or destroy -F)", g.name));
            }
            g.write(&t.destroy())?;
            println!("{} destroyed", g.name);
            Ok(())
        }
        "add" => {
            let o = parse_opts(args, "tbsl", "").ok_or_else(String::new)?;
            let mut g = Geom::open(&o.geom, true)?;
            let mut t = g.table()?.ok_or(format!("{}: no partition table (gpart create it first)", g.name))?;
            let code = kind_of(o.get('t').ok_or("-t type is needed")?, t.scheme)?;
            let first = o.get('b').map(|v| parse_amount(v, t.sector_size)).transpose()?;
            let sectors = o.get('s').map(|v| parse_amount(v, t.sector_size)).transpose()?;
            let guid = if t.scheme == Scheme::Gpt { random_guid()? } else { [0; 16] };
            let i = t.add(code, o.get('l').unwrap_or(""), first, sectors, guid).map_err(lib)?;
            g.write(&t.write())?;
            println!("{} added", g.part_name(t.scheme, i));
            Ok(())
        }
        "delete" => {
            let o = parse_opts(args, "i", "").ok_or_else(String::new)?;
            let mut g = Geom::open(&o.geom, true)?;
            let mut t = g.table()?.ok_or(format!("{}: no partition table", g.name))?;
            let i = o.index()?;
            t.delete(i).map_err(lib)?;
            g.write(&t.write())?;
            println!("{} deleted", g.part_name(t.scheme, i));
            Ok(())
        }
        "resize" => {
            let o = parse_opts(args, "is", "").ok_or_else(String::new)?;
            let mut g = Geom::open(&o.geom, true)?;
            let mut t = g.table()?.ok_or(format!("{}: no partition table", g.name))?;
            let i = o.index()?;
            let sectors = o.get('s').map(|v| parse_amount(v, t.sector_size)).transpose()?;
            t.resize(i, sectors).map_err(lib)?;
            g.write(&t.write())?;
            println!("{} resized", g.part_name(t.scheme, i));
            Ok(())
        }
        "modify" => {
            let o = parse_opts(args, "ilt", "").ok_or_else(String::new)?;
            let mut g = Geom::open(&o.geom, true)?;
            let mut t = g.table()?.ok_or(format!("{}: no partition table", g.name))?;
            let i = o.index()?;
            let code = o.get('t').map(|n| kind_of(n, t.scheme)).transpose()?;
            if code.is_none() && o.get('l').is_none() {
                return Err("-l label or -t type is needed".into());
            }
            t.modify(i, code, o.get('l')).map_err(lib)?;
            g.write(&t.write())?;
            println!("{} modified", g.part_name(t.scheme, i));
            Ok(())
        }
        "set" | "unset" => {
            let o = parse_opts(args, "ai", "").ok_or_else(String::new)?;
            if o.get('a') != Some("active") {
                return Err("-a active is the only attribute".into());
            }
            let mut g = Geom::open(&o.geom, true)?;
            let mut t = g.table()?.ok_or(format!("{}: no partition table", g.name))?;
            let i = o.index()?;
            t.set_active(i, verb == "set").map_err(lib)?;
            g.write(&t.write())?;
            println!("active {} on {}", if verb == "set" { "set" } else { "cleared" }, g.part_name(t.scheme, i));
            Ok(())
        }
        _ => Err(String::new()),
    }
}

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((verb, rest)) = args.split_first() else { return usage() };
    match run(verb, rest) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.is_empty() => usage(),
        Err(e) => {
            eprintln!("gpart: {e}");
            ExitCode::from(1)
        }
    }
}
