//! What `/proc` says about a process: OxideBSD's procfs (`sys/modules/procfs`, the lines are
//! formatted by the kernel's `sys/process/procfs.rs`), whose `stat` is Linux proc(5)'s format,
//! so the same reader serves a Linux host too (where these programs are tested).
//!
//! Per process this reads `stat` (states, ids, terminal, times, priority, sizes, signal masks),
//! `status` (the real/effective/saved user and group IDs, and OxideBSD's `PPWait`, ps's `V`) and
//! `cmdline` (NUL-separated arguments). Sources that only some systems have are read when they
//! exist and asked for: OxideBSD's `stat` reports no resident size, so it comes from summing the
//! resident column of FreeBSD-format `/proc/<pid>/map` (OxideBSD only); `environ` and `wchan`
//! are Linux's.
//!
//! This file is shared, by copy, between ps(1) and pgrep(1).

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::MetadataExt;

/// The clock tick of `stat`'s times: 100 Hz on OxideBSD (the PIT), and `sysconf(_SC_CLK_TCK)`
/// elsewhere.
pub fn hz() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if n > 0 { n as u64 } else { 100 }
}

pub fn page_size() -> u64 {
    // SAFETY: as above.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as u64 } else { 4096 }
}

#[derive(Clone, Default)]
pub struct Proc {
    pub pid: i32,
    /// The command name (`p_comm`): the file name exec'd, as `stat` has it.
    pub comm: String,
    /// proc(5)'s state letter: `R`, `S`, `D`, `T`, `Z` (and Linux's `I`, `t`, `X`, ...).
    pub state: u8,
    pub ppid: i32,
    pub pgid: i32,
    pub sid: i32,
    /// The controlling terminal, musl's `makedev` encoding (`major << 8 | minor`); 0 for none.
    pub tty: u64,
    /// The terminal's foreground process group; -1 for none.
    pub tpgid: i32,
    pub flags: u64,
    pub minflt: u64,
    pub majflt: u64,
    /// CPU times in clock ticks.
    pub utime: u64,
    pub stime: u64,
    pub cutime: u64,
    pub cstime: u64,
    /// proc(5)'s priority: 20 + nice when time-sharing, -1 - rank when real-time.
    pub priority: i64,
    pub nice: i64,
    pub nlwp: i64,
    /// Start time, in clock ticks since boot.
    pub start: u64,
    /// Virtual size in bytes.
    pub vsize: u64,
    /// Resident pages, as `stat` gives them (0 on OxideBSD: see `rss_pages`).
    pub rss: u64,
    pub sigpend: u64,
    pub sigmask: u64,
    pub sigignore: u64,
    pub sigcatch: u64,
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    /// A vfork child still borrowing its parent's memory (FreeBSD's `P_PPWAIT`).
    pub ppwait: bool,
    pub args: Vec<String>,
}

/// The pids in `/proc`, ascending.
pub fn pids() -> std::io::Result<Vec<i32>> {
    let mut v = Vec::new();
    for e in fs::read_dir("/proc")? {
        let Ok(e) = e else { continue };
        let name = e.file_name();
        let Some(s) = name.to_str() else { continue };
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(p) = s.parse() {
                v.push(p);
            }
        }
    }
    v.sort_unstable();
    Ok(v)
}

fn num<T: std::str::FromStr + Default>(f: &[&str], i: usize) -> T {
    f.get(i).and_then(|s| s.parse().ok()).unwrap_or_default()
}

/// Parses a `stat` line: `pid (comm) state ppid ...`. The command name may itself hold
/// parentheses and spaces, so it runs to the last `)`.
pub fn parse_stat(line: &str) -> Option<Proc> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }
    let mut p = Proc { pid: line[..open].trim().parse().ok()?, ..Default::default() };
    p.comm = line[open + 1..close].to_string();
    let f: Vec<&str> = line[close + 1..].split_ascii_whitespace().collect();
    // f[n - 3] is proc(5)'s field n.
    p.state = f.first()?.bytes().next()?;
    p.ppid = num(&f, 1);
    p.pgid = num(&f, 2);
    p.sid = num(&f, 3);
    p.tty = num::<i64>(&f, 4) as u64 & 0xffff_ffff;
    p.tpgid = num(&f, 5);
    p.flags = num(&f, 6);
    p.minflt = num(&f, 7);
    p.majflt = num(&f, 9);
    p.utime = num(&f, 11);
    p.stime = num(&f, 12);
    p.cutime = num(&f, 13);
    p.cstime = num(&f, 14);
    p.priority = num(&f, 15);
    p.nice = num(&f, 16);
    p.nlwp = num(&f, 17);
    p.start = num(&f, 19);
    p.vsize = num(&f, 20);
    p.rss = num(&f, 21);
    p.sigpend = num(&f, 28);
    p.sigmask = num(&f, 29);
    p.sigignore = num(&f, 30);
    p.sigcatch = num(&f, 31);
    Some(p)
}

fn ids(v: &str) -> [u32; 3] {
    let f: Vec<u32> = v.split_ascii_whitespace().filter_map(|s| s.parse().ok()).collect();
    [f.first().copied().unwrap_or(0), f.get(1).copied().unwrap_or(0), f.get(2).copied().unwrap_or(0)]
}

/// Reads process `pid`, or `None` if it is gone (or hidden from the caller).
pub fn read(pid: i32) -> Option<Proc> {
    let dir = format!("/proc/{pid}");
    let stat = fs::read(format!("{dir}/stat")).ok()?;
    let mut p = parse_stat(&String::from_utf8_lossy(&stat))?;
    let mut have_ids = false;
    if let Ok(st) = fs::read(format!("{dir}/status")) {
        for line in String::from_utf8_lossy(&st).lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            match k {
                "Uid" => {
                    [p.ruid, p.euid, p.suid] = ids(v);
                    have_ids = true;
                }
                "Gid" => [p.rgid, p.egid, p.sgid] = ids(v),
                "PPWait" => p.ppwait = v.trim() == "1",
                _ => {}
            }
        }
    }
    if !have_ids {
        // The owner of the directory is the process's effective user.
        if let Ok(m) = fs::metadata(&dir) {
            (p.ruid, p.euid, p.suid) = (m.uid(), m.uid(), m.uid());
            (p.rgid, p.egid, p.sgid) = (m.gid(), m.gid(), m.gid());
        }
    }
    if let Ok(c) = fs::read(format!("{dir}/cmdline")) {
        let c = c.strip_suffix(b"\0").unwrap_or(&c);
        if !c.is_empty() {
            p.args = c.split(|&b| b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        }
    }
    Some(p)
}

/// All the processes `/proc` shows, by pid.
pub fn all() -> std::io::Result<Vec<Proc>> {
    Ok(pids()?.into_iter().filter_map(read).collect())
}

/// Resident pages: `stat`'s count where the system fills it in, else (OxideBSD) the sum of the
/// resident column of `/proc/<pid>/map` (FreeBSD's format: start end resident ...).
pub fn rss_pages(p: &Proc) -> u64 {
    if p.rss != 0 {
        return p.rss;
    }
    let Ok(map) = fs::read(format!("/proc/{}/map", p.pid)) else { return 0 };
    String::from_utf8_lossy(&map)
        .lines()
        .filter_map(|l| l.split_ascii_whitespace().nth(2)?.parse::<u64>().ok())
        .sum()
}

/// The environment, where the system shows it (`/proc/<pid>/environ`; OxideBSD has none).
pub fn environ(pid: i32) -> Vec<String> {
    match fs::read(format!("/proc/{pid}/environ")) {
        Ok(e) => e
            .split(|&b| b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The wait channel, where the system names it (`/proc/<pid>/wchan`; OxideBSD has none).
pub fn wchan(pid: i32) -> Option<String> {
    let w = fs::read_to_string(format!("/proc/{pid}/wchan")).ok()?;
    let w = w.trim();
    if w.is_empty() || w == "0" { None } else { Some(w.to_string()) }
}

/// Seconds since boot, from `/proc/uptime`.
pub fn uptime() -> f64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_ascii_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
}

/// `MemTotal` of `/proc/meminfo`, in KiB.
pub fn mem_total_kb() -> u64 {
    let Ok(m) = fs::read_to_string("/proc/meminfo") else { return 0 };
    m.lines()
        .find_map(|l| l.strip_prefix("MemTotal:")?.split_ascii_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// The terminals in `/dev` (and `/dev/pts`), by device number, as devfs names them: the number
/// is the same `major << 8 | minor` encoding `stat`'s `tty_nr` uses.
pub struct Ttys(Vec<(u64, String)>);

impl Ttys {
    pub fn scan() -> Ttys {
        let mut v: Vec<(u64, String)> = Vec::new();
        for (dir, prefix) in [("/dev/pts", "pts/"), ("/dev", "")] {
            let Ok(rd) = fs::read_dir(dir) else { continue };
            let mut names: Vec<(u64, String)> = Vec::new();
            for e in rd.flatten() {
                let Ok(m) = e.metadata() else { continue };
                use std::os::unix::fs::FileTypeExt;
                if !m.file_type().is_char_device() {
                    continue;
                }
                let Some(n) = e.file_name().to_str().map(str::to_string) else { continue };
                names.push((m.rdev(), format!("{prefix}{n}")));
            }
            names.sort();
            v.extend(names);
        }
        Ttys(v)
    }

    /// The best name for device `dev`: a real terminal's (`tty*`, `pts/*`) over an alias like
    /// `console`.
    pub fn name(&self, dev: u64) -> Option<&str> {
        let mut best: Option<&str> = None;
        for (d, n) in &self.0 {
            if *d == dev {
                let good = n.starts_with("tty") || n.starts_with("pts/");
                if good {
                    return Some(n);
                }
                if best.is_none() && n != "tty" {
                    best = Some(n);
                }
            }
        }
        best
    }

    /// The device a user's terminal name means: `ttyv0`, `/dev/ttyv0`, `v0` (ps's abbreviation),
    /// `pts/1`, `1`, `co`/`console`; `None` if there's none such.
    pub fn lookup(&self, arg: &str) -> Option<u64> {
        let a = arg.strip_prefix("/dev/").unwrap_or(arg);
        let tries = [a.to_string(), format!("tty{a}"), format!("pts/{a}"), if a == "co" || a == "con" { "console".into() } else { String::new() }];
        for t in tries.iter().filter(|t| !t.is_empty()) {
            if let Some((d, _)) = self.0.iter().find(|(_, n)| n == t) {
                return Some(*d);
            }
        }
        None
    }
}

/// ps's `TT` abbreviation of a terminal's name: `ttyv0` is `v0`, `pts/3` is `3`, `console` is
/// `con`.
pub fn abbrev(name: &str) -> &str {
    if let Some(r) = name.strip_prefix("tty") {
        if !r.is_empty() {
            return r;
        }
    }
    if let Some(r) = name.strip_prefix("pts/") {
        return r;
    }
    if name == "console" {
        return "con";
    }
    name
}

pub fn user_name(uid: u32) -> Option<String> {
    // SAFETY: getpwuid returns a static entry or null; the name is copied out at once.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

pub fn group_name(gid: u32) -> Option<String> {
    // SAFETY: as above.
    unsafe {
        let gr = libc::getgrgid(gid);
        if gr.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr((*gr).gr_name).to_string_lossy().into_owned())
    }
}

/// A user name or number.
pub fn user_id(s: &str) -> Option<u32> {
    let c = std::ffi::CString::new(s).ok()?;
    // SAFETY: getpwnam takes a NUL-terminated name and returns a static entry or null.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if !pw.is_null() {
        // SAFETY: non-null.
        return Some(unsafe { (*pw).pw_uid });
    }
    s.parse().ok()
}

/// A group name or number.
pub fn group_id(s: &str) -> Option<u32> {
    let c = std::ffi::CString::new(s).ok()?;
    // SAFETY: as above.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if !gr.is_null() {
        // SAFETY: non-null.
        return Some(unsafe { (*gr).gr_gid });
    }
    s.parse().ok()
}

pub fn strerror(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}
