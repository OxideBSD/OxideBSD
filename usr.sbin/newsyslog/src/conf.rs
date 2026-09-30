//! `newsyslog.conf(5)`, FreeBSD's format (`SYSLOG.md` §9.1): one line per log file,
//!
//! ```text
//! # logfile            [owner:group]  mode count size when  flags [/pid_file|/cmd] [sig]
//! /var/log/messages                   644  5     100  @T00  JC
//! /var/log/auth.log    root:wheel     600  7     *    $D0   C
//! ```
//!
//! and `include path` (or FreeBSD's `<include>`), which reads a file, or a directory's `*.conf`
//! files in name order, as `syslog.conf(5)` does. A `<default>` line applies to files named on
//! the command line that no other line mentions.

use std::path::{Path, PathBuf};

use crate::clock;

/// How an archive is compressed (`J`, `Z`, `X`, `Y`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compress {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

impl Compress {
    /// The suffix the compressor adds.
    pub fn suffix(self) -> &'static str {
        match self {
            Compress::None => "",
            Compress::Gzip => ".gz",
            Compress::Bzip2 => ".bz2",
            Compress::Xz => ".xz",
            Compress::Zstd => ".zst",
        }
    }

    /// Every suffix an archive may carry, the uncompressed one first.
    pub const SUFFIXES: [&'static str; 5] = ["", ".gz", ".bz2", ".xz", ".zst"];
}

/// The flags field (`SYSLOG.md` §9.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// `B`: binary, no rotation message.
    pub binary: bool,
    /// `C`: create if missing (with `-C`).
    pub create: bool,
    /// `D`: no dump. Accepted; OxideBSD has no file flags yet.
    pub nodump: bool,
    /// `G`: the log file name is a shell pattern.
    pub glob: bool,
    /// `N`: signal no process.
    pub nosignal: bool,
    /// `U`: the pid file names a process group.
    pub group: bool,
    /// `R`: run the command at the pid-file position instead of signalling.
    pub run: bool,
    pub compress: Option<Compress>,
}

/// A day-of-the-month in a `$M` spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MonthDay {
    Day(i32),
    Last,
}

/// A rotation time: `@` ISO 8601 or `$` day, week or month.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// `@[[[[cc]yy]mm]dd][T[hh[mm[ss]]]]`: fields left of the first one given are "every", those
    /// right of the last one given are 0.
    Iso { year: Option<i32>, month: Option<i32>, day: Option<i32>, hour: i32, minute: i32, second: i32 },
    /// `$D` hour, every day.
    Daily { hour: i32 },
    /// `$W` weekday (0 is Sunday).
    Weekly { wday: i32, hour: i32 },
    /// `$M` day of the month, or `L` for the last.
    Monthly { day: MonthDay, hour: i32 },
}

/// The `when` field: an interval in hours, a rotation time, both, or neither (`*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct When {
    pub hours: Option<u32>,
    pub at: Option<At>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The log file (a pattern with `G`), or `<default>`.
    pub path: String,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub mode: u32,
    pub count: u32,
    /// In KiB; `None` for `*`.
    pub size: Option<u64>,
    pub when: When,
    pub flags: Flags,
    /// The pid file, or with `R` the command.
    pub pidfile: Option<String>,
    pub signal: i32,
    pub origin: String,
}

impl Entry {
    pub fn is_default(&self) -> bool {
        self.path == "<default>"
    }
}

/// A parsed configuration; problems in `errors` (the rest still applies).
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub entries: Vec<Entry>,
    pub errors: Vec<String>,
}

pub fn load(path: &Path) -> Config {
    let mut config = Config::default();
    match std::fs::read_to_string(path) {
        Ok(text) => parse_str(&mut config, &text, &path.display().to_string(), 0),
        Err(e) => config.errors.push(format!("{}: {e}", path.display())),
    }
    config
}

#[cfg(test)]
pub fn parse(text: &str) -> Config {
    let mut config = Config::default();
    parse_str(&mut config, text, "-", 0);
    config
}

fn parse_str(config: &mut Config, text: &str, name: &str, depth: u32) {
    for (i, raw) in text.lines().enumerate() {
        let origin = format!("{name}:{}", i + 1);
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let words: Vec<&str> = line.split_ascii_whitespace().collect();
        if words[0] == "include" || words[0] == "<include>" {
            if words.len() != 2 {
                config.errors.push(format!("{origin}: include takes one path"));
            } else if depth >= 8 {
                config.errors.push(format!("{origin}: includes nested too deeply"));
            } else {
                include(config, words[1], depth + 1);
            }
            continue;
        }
        match parse_entry(&words, &origin) {
            Ok(e) => config.entries.push(e),
            Err(e) => config.errors.push(format!("{origin}: {e}")),
        }
    }
}

/// A file, a directory's `*.conf` files, or (FreeBSD's `<include> dir/*`) a shell pattern. A
/// path that doesn't exist is ignored: the default configuration includes directories that may
/// not.
fn include(config: &mut Config, spec: &str, depth: u32) {
    let files: Vec<PathBuf> = if spec.contains(['*', '?', '[']) {
        glob(spec).into_iter().map(PathBuf::from).collect()
    } else {
        let path = Path::new(spec);
        match std::fs::metadata(path) {
            Ok(m) if m.is_dir() => {
                let mut v: Vec<PathBuf> = std::fs::read_dir(path)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "conf") && p.is_file())
                    .collect();
                v.sort();
                v
            }
            Ok(_) => vec![path.to_path_buf()],
            Err(_) => Vec::new(),
        }
    };
    for file in files {
        match std::fs::read_to_string(&file) {
            Ok(text) => parse_str(config, &text, &file.display().to_string(), depth),
            Err(e) => config.errors.push(format!("{}: {e}", file.display())),
        }
    }
}

/// Expands a shell pattern (`glob(3)`), sorted; nothing if nothing matches.
pub fn glob(pattern: &str) -> Vec<String> {
    let Ok(c) = std::ffi::CString::new(pattern) else { return Vec::new() };
    let mut out = Vec::new();
    // SAFETY: glob fills the zeroed glob_t, which globfree releases.
    unsafe {
        let mut g: libc::glob_t = std::mem::zeroed();
        if libc::glob(c.as_ptr(), 0, None, &mut g) == 0 {
            for i in 0..g.gl_pathc {
                let p = *g.gl_pathv.add(i);
                out.push(std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned());
            }
        }
        libc::globfree(&mut g);
    }
    out
}

fn parse_entry(words: &[&str], origin: &str) -> Result<Entry, String> {
    let mut w = words.iter().copied();
    let path = w.next().unwrap().to_string();
    if !path.starts_with('/') && path != "<default>" {
        return Err(format!("{path}: log file must be an absolute path"));
    }
    let mut next = w.next().ok_or("missing mode")?;
    let (mut owner, mut group) = (None, None);
    // `owner:group`, `owner:`, `:group` (or FreeBSD's older `.` separator).
    if let Some((o, g)) = next.split_once(':').or_else(|| next.split_once('.')) {
        owner = (!o.is_empty()).then(|| o.to_string());
        group = (!g.is_empty()).then(|| g.to_string());
        next = w.next().ok_or("missing mode")?;
    }
    let mode = u32::from_str_radix(next, 8).ok().filter(|&m| m <= 0o7777).ok_or_else(|| format!("bad mode {next}"))?;
    let count_s = w.next().ok_or("missing count")?;
    let count: u32 = count_s.parse().map_err(|_| format!("bad count {count_s}"))?;
    let size_s = w.next().ok_or("missing size")?;
    let size = if size_s == "*" {
        None
    } else {
        Some(size_s.trim_end_matches(['k', 'K']).parse::<u64>().map_err(|_| format!("bad size {size_s}"))?)
    };
    let when_s = w.next().ok_or("missing when")?;
    let when = parse_when(when_s)?;
    let mut flags = Flags::default();
    let mut pidfile = None;
    let mut signal = libc::SIGHUP;
    let mut rest: Vec<&str> = w.collect();
    // The flags field is optional: a word starting with `/` is already the pid file.
    if rest.first().is_some_and(|f| !f.starts_with('/')) {
        flags = parse_flags(rest.remove(0))?;
    }
    if !rest.is_empty() {
        pidfile = Some(rest.remove(0).to_string());
        if !pidfile.as_ref().unwrap().starts_with('/') {
            return Err(format!("{}: pid file must be an absolute path", pidfile.unwrap()));
        }
    }
    if !rest.is_empty() {
        let s = rest.remove(0);
        signal = parse_signal(s).ok_or_else(|| format!("unknown signal {s}"))?;
    }
    if !rest.is_empty() {
        return Err(format!("unexpected {}", rest[0]));
    }
    if flags.run && pidfile.is_none() {
        return Err("flag R needs a command".into());
    }
    Ok(Entry { path, owner, group, mode, count, size, when, flags, pidfile, signal, origin: origin.to_string() })
}

fn parse_flags(s: &str) -> Result<Flags, String> {
    let mut f = Flags::default();
    for c in s.chars() {
        let compress = |f: &mut Flags, c: Compress| -> Result<(), String> {
            if f.compress.is_some() {
                return Err(format!("more than one compression flag in {s}"));
            }
            f.compress = Some(c);
            Ok(())
        };
        match c.to_ascii_uppercase() {
            '-' => {}
            'B' => f.binary = true,
            'C' => f.create = true,
            'D' => f.nodump = true,
            'G' => f.glob = true,
            'N' => f.nosignal = true,
            'U' => f.group = true,
            'R' => f.run = true,
            'J' => compress(&mut f, Compress::Bzip2)?,
            'Z' => compress(&mut f, Compress::Gzip)?,
            'X' => compress(&mut f, Compress::Xz)?,
            'Y' => compress(&mut f, Compress::Zstd)?,
            _ => return Err(format!("unknown flag {c}")),
        }
    }
    Ok(f)
}

pub fn parse_signal(s: &str) -> Option<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return (1..=64).contains(&n).then_some(n);
    }
    let name = s.to_ascii_uppercase();
    let name = name.strip_prefix("SIG").unwrap_or(&name);
    Some(match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "CONT" => libc::SIGCONT,
        "WINCH" => libc::SIGWINCH,
        "INFO" | "PWR" => libc::SIGPWR,
        _ => return None,
    })
}

/// `*`, hours, `@spec`, `$spec`, or hours followed by either spec.
pub fn parse_when(s: &str) -> Result<When, String> {
    if s == "*" {
        return Ok(When::default());
    }
    let split = s.find(['@', '$']).unwrap_or(s.len());
    let (hours_s, spec) = s.split_at(split);
    let hours = if hours_s.is_empty() || hours_s == "*" {
        None
    } else {
        Some(hours_s.parse::<u32>().map_err(|_| format!("bad interval in {s}"))?)
    };
    let at = match spec.chars().next() {
        None => None,
        Some('@') => Some(parse_iso(&spec[1..]).ok_or_else(|| format!("bad @ time {s}"))?),
        Some(_) => Some(parse_periodic(&spec[1..]).ok_or_else(|| format!("bad $ time {s}"))?),
    };
    if hours.is_none() && at.is_none() {
        return Err(format!("bad when {s}"));
    }
    Ok(When { hours, at })
}

fn digits(s: &str) -> Option<i32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok())?
}

fn parse_iso(s: &str) -> Option<At> {
    let (date, time) = match s.split_once(['T', 't']) {
        Some((d, t)) => (d, t),
        None => (s, ""),
    };
    let (mut year, mut month, mut day) = (None, None, None);
    match date.len() {
        0 => {}
        2 => day = Some(digits(date)?),
        4 => (month, day) = (Some(digits(&date[..2])?), Some(digits(&date[2..])?)),
        6 => {
            let century = clock::broken(syslog::time::epoch()).year / 100 * 100;
            year = Some(century + digits(&date[..2])?);
            month = Some(digits(&date[2..4])?);
            day = Some(digits(&date[4..])?);
        }
        8 => {
            year = Some(digits(&date[..4])?);
            month = Some(digits(&date[4..6])?);
            day = Some(digits(&date[6..])?);
        }
        _ => return None,
    }
    let (mut hour, mut minute, mut second) = (0, 0, 0);
    match time.len() {
        0 => {}
        2 => hour = digits(time)?,
        4 => (hour, minute) = (digits(&time[..2])?, digits(&time[2..])?),
        6 => (hour, minute, second) = (digits(&time[..2])?, digits(&time[2..4])?, digits(&time[4..])?),
        _ => return None,
    }
    if month.is_some_and(|m| !(1..=12).contains(&m))
        || day.is_some_and(|d| !(1..=31).contains(&d))
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(At::Iso { year, month, day, hour, minute, second })
}

/// `[W<0-6>|M<1-31|L>][D<0-23>]`, at least one part.
fn parse_periodic(s: &str) -> Option<At> {
    let mut rest = s;
    let mut kind = None;
    if let Some(r) = rest.strip_prefix(['W', 'w']) {
        let n = r.bytes().take_while(u8::is_ascii_digit).count();
        let wday = digits(&r[..n]).filter(|w| (0..=6).contains(w))?;
        kind = Some((Some(wday), None));
        rest = &r[n..];
    } else if let Some(r) = rest.strip_prefix(['M', 'm']) {
        if let Some(r2) = r.strip_prefix(['L', 'l']) {
            kind = Some((None, Some(MonthDay::Last)));
            rest = r2;
        } else {
            let n = r.bytes().take_while(u8::is_ascii_digit).count();
            let day = digits(&r[..n]).filter(|d| (1..=31).contains(d))?;
            kind = Some((None, Some(MonthDay::Day(day))));
            rest = &r[n..];
        }
    }
    let mut hour = None;
    if let Some(r) = rest.strip_prefix(['D', 'd']) {
        hour = Some(digits(r).filter(|h| (0..=23).contains(h))?);
        rest = "";
    }
    if !rest.is_empty() || (kind.is_none() && hour.is_none()) {
        return None;
    }
    let hour = hour.unwrap_or(0);
    Some(match kind {
        None => At::Daily { hour },
        Some((Some(wday), _)) => At::Weekly { wday, hour },
        Some((_, Some(day))) => At::Monthly { day, hour },
        _ => unreachable!(),
    })
}

/// Days searched back for a time a spec names: enough for a 29 February.
const SEARCH_DAYS: i32 = 4 * 366 + 1;

/// The most recent time at or before `now` that `at` names; `None` if it names none yet.
pub fn last_due(at: &At, now: i64) -> Option<i64> {
    let (hour, minute, second) = match *at {
        At::Iso { hour, minute, second, .. } => (hour, minute, second),
        At::Daily { hour } | At::Weekly { hour, .. } | At::Monthly { hour, .. } => (hour, 0, 0),
    };
    if let At::Iso { year: Some(y), month: Some(m), day: Some(d), .. } = *at {
        let t = clock::mk(y, m, d, hour, minute, second);
        return (t <= now).then_some(t);
    }
    let today = clock::broken(now);
    for back in 0..SEARCH_DAYS {
        // Noon, so a daylight-saving change can't move the day.
        let day = clock::broken(clock::mk(today.year, today.month, today.day - back, 12, 0, 0));
        let hit = match *at {
            At::Iso { year, month, day: d, .. } => {
                year.is_none_or(|y| y == day.year) && month.is_none_or(|m| m == day.month) && d.is_none_or(|d| d == day.day)
            }
            At::Daily { .. } => true,
            At::Weekly { wday, .. } => day.wday == wday,
            At::Monthly { day: MonthDay::Day(d), .. } => day.day == d,
            At::Monthly { day: MonthDay::Last, .. } => {
                clock::broken(clock::mk(day.year, day.month, day.day + 1, 12, 0, 0)).month != day.month
            }
        };
        if !hit {
            continue;
        }
        let t = clock::mk(day.year, day.month, day.day, hour, minute, second);
        if t <= now {
            return Some(t);
        }
    }
    None
}

/// Why a log is rotated; the rotation message says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Size(u64),
    Time,
    Force,
}

/// Whether `e`'s log is due (`SYSLOG.md` §9.1-9.2): over its size, or its time has come since
/// the last rotation. `last` is when it was last rotated (the newest archive's modification
/// time, which rotation sets); without one, a time spec is due only within the hour it names,
/// and an interval only once the log has something in it.
pub fn due(e: &Entry, size_bytes: u64, last: Option<i64>, now: i64) -> Option<Reason> {
    if let Some(kib) = e.size {
        if size_bytes >= kib * 1024 {
            return Some(Reason::Size(kib));
        }
    }
    if let Some(at) = &e.when.at {
        if let Some(t) = last_due(at, now) {
            let hit = match last {
                Some(l) => l < t,
                None => now - t < 3600,
            };
            if hit {
                return Some(Reason::Time);
            }
        }
    }
    if let Some(hours) = e.when.hours {
        let hit = match last {
            Some(l) => now - l >= hours as i64 * 3600,
            None => size_bytes > 0,
        };
        if hit {
            return Some(Reason::Time);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(y: i32, mo: i32, d: i32, h: i32, mi: i32) -> i64 {
        clock::mk(y, mo, d, h, mi, 0)
    }

    #[test]
    fn default_config() {
        let c = parse(include_str!("../../../etc/newsyslog.conf"));
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert!(c.entries.len() >= 5);
        assert!(c.entries.iter().all(|e| e.flags.create));
        let m = c.entries.iter().find(|e| e.path == "/var/log/messages").unwrap();
        assert_eq!(m.mode, 0o644);
    }

    #[test]
    fn entries() {
        let c = parse(
            "/var/log/a   root:wheel 640 7 100 * JC\n\
             /var/log/b   600 3 * 24\n\
             /var/log/c   :staff 644 0 5k @T00 BN\n\
             /var/log/d   644 5 * $W0D23 - /var/run/d.pid USR1\n\
             /var/log/e   644 5 * * UR /usr/sbin/rotated\n\
             /var/log/*.x 644 1 * 168 GZ /var/run/x.pid 30 # comment\n\
             <default>    644 2 10 *\n",
        );
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        let e = &c.entries;
        assert_eq!((e[0].owner.as_deref(), e[0].group.as_deref(), e[0].mode, e[0].count), (Some("root"), Some("wheel"), 0o640, 7));
        assert_eq!(e[0].size, Some(100));
        assert_eq!(e[0].flags.compress, Some(Compress::Bzip2));
        assert!(e[0].flags.create && !e[0].flags.binary);
        assert_eq!(e[1].when, When { hours: Some(24), at: None });
        assert_eq!(e[1].flags, Flags::default());
        assert_eq!((e[2].owner.as_deref(), e[2].group.as_deref(), e[2].size), (None, Some("staff"), Some(5)));
        assert!(e[2].flags.binary && e[2].flags.nosignal);
        assert_eq!(e[3].pidfile.as_deref(), Some("/var/run/d.pid"));
        assert_eq!(e[3].signal, libc::SIGUSR1);
        assert!(e[4].flags.run && e[4].flags.group);
        assert_eq!(e[4].pidfile.as_deref(), Some("/usr/sbin/rotated"));
        assert!(e[5].flags.glob);
        assert_eq!(e[5].signal, 30);
        assert!(e[6].is_default());
    }

    #[test]
    fn errors() {
        let c = parse(
            "var/log/a 644 1 * *\n/a 999 1 * *\n/a 644 x * *\n/a 644 1 big *\n/a 644 1 * soon\n\
             /a 644 1 * * Q\n/a 644 1 * * JZ\n/a 644 1 * * R\n/a 644 1 * * - /p NOSIG\n/a 644\n/a 644 1 * * - rel\n",
        );
        assert_eq!(c.entries.len(), 0);
        assert_eq!(c.errors.len(), 11, "{:?}", c.errors);
    }

    #[test]
    fn when_forms() {
        assert_eq!(parse_when("*").unwrap(), When::default());
        assert_eq!(parse_when("12").unwrap().hours, Some(12));
        let iso = |s| parse_when(s).unwrap().at.unwrap();
        assert_eq!(iso("@T00"), At::Iso { year: None, month: None, day: None, hour: 0, minute: 0, second: 0 });
        assert_eq!(iso("@T"), At::Iso { year: None, month: None, day: None, hour: 0, minute: 0, second: 0 });
        assert_eq!(iso("@0101T"), At::Iso { year: None, month: Some(1), day: Some(1), hour: 0, minute: 0, second: 0 });
        assert_eq!(iso("@01T05"), At::Iso { year: None, month: None, day: Some(1), hour: 5, minute: 0, second: 0 });
        assert_eq!(iso("@20260929T2359"), At::Iso { year: Some(2026), month: Some(9), day: Some(29), hour: 23, minute: 59, second: 0 });
        assert_eq!(iso("@T123045"), At::Iso { year: None, month: None, day: None, hour: 12, minute: 30, second: 45 });
        let yy = iso("@261231T");
        assert!(matches!(yy, At::Iso { year: Some(y), month: Some(12), day: Some(31), .. } if y % 100 == 26));
        assert_eq!(iso("$D0"), At::Daily { hour: 0 });
        assert_eq!(iso("$D23"), At::Daily { hour: 23 });
        assert_eq!(iso("$W0D23"), At::Weekly { wday: 0, hour: 23 });
        assert_eq!(iso("$W6"), At::Weekly { wday: 6, hour: 0 });
        assert_eq!(iso("$M1D0"), At::Monthly { day: MonthDay::Day(1), hour: 0 });
        assert_eq!(iso("$ML"), At::Monthly { day: MonthDay::Last, hour: 0 });
        assert_eq!(iso("$MLD6"), At::Monthly { day: MonthDay::Last, hour: 6 });
        let both = parse_when("168@T02").unwrap();
        assert_eq!(both.hours, Some(168));
        assert!(both.at.is_some());
        for bad in ["", "@T24", "@1301T", "@123T", "$", "$W7", "$M32", "$D24", "$X1", "soon", "12x"] {
            assert!(parse_when(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn last_due_times() {
        // 2026-09-29 is a Tuesday.
        let now = t(2026, 9, 29, 14, 30);
        let at = |s| parse_when(s).unwrap().at.unwrap();
        assert_eq!(last_due(&at("@T00"), now), Some(t(2026, 9, 29, 0, 0)));
        assert_eq!(last_due(&at("@T15"), now), Some(t(2026, 9, 28, 15, 0)));
        assert_eq!(last_due(&at("@0101T"), now), Some(t(2026, 1, 1, 0, 0)));
        assert_eq!(last_due(&at("@01T05"), now), Some(t(2026, 9, 1, 5, 0)));
        assert_eq!(last_due(&at("@30T"), now), Some(t(2026, 8, 30, 0, 0)));
        assert_eq!(last_due(&at("@20260929T1400"), now), Some(t(2026, 9, 29, 14, 0)));
        assert_eq!(last_due(&at("@20260929T1500"), now), None);
        assert_eq!(last_due(&at("$D0"), now), Some(t(2026, 9, 29, 0, 0)));
        assert_eq!(last_due(&at("$W0D23"), now), Some(t(2026, 9, 27, 23, 0)));
        assert_eq!(last_due(&at("$W2D14"), now), Some(t(2026, 9, 29, 14, 0)));
        assert_eq!(last_due(&at("$W2D15"), now), Some(t(2026, 9, 22, 15, 0)));
        assert_eq!(last_due(&at("$M1D0"), now), Some(t(2026, 9, 1, 0, 0)));
        assert_eq!(last_due(&at("$ML"), now), Some(t(2026, 8, 31, 0, 0)));
        assert_eq!(last_due(&at("$ML"), t(2026, 9, 30, 1, 0)), Some(t(2026, 9, 30, 0, 0)));
        assert_eq!(last_due(&at("$M31"), now), Some(t(2026, 8, 31, 0, 0)));
        assert_eq!(last_due(&at("@0229T"), now), Some(t(2024, 2, 29, 0, 0)));
    }

    #[test]
    fn due_decisions() {
        let c = parse("/a 644 5 100 * -\n/b 644 5 * @T00 -\n/c 644 5 * 24 -\n/d 644 5 * * -\n/e 644 5 10 $D0 -\n");
        let [a, b, cc, d, e] = &c.entries[..] else { panic!() };
        let now = t(2026, 9, 29, 0, 30);
        assert_eq!(due(a, 102_400, None, now), Some(Reason::Size(100)));
        assert_eq!(due(a, 102_399, None, now), None);
        // A time spec: within its hour with no archive; otherwise when not rotated since.
        assert_eq!(due(b, 0, None, now), Some(Reason::Time));
        assert_eq!(due(b, 0, None, t(2026, 9, 29, 1, 30)), None);
        assert_eq!(due(b, 0, Some(t(2026, 9, 28, 0, 5)), t(2026, 9, 29, 5, 0)), Some(Reason::Time));
        assert_eq!(due(b, 0, Some(t(2026, 9, 29, 0, 5)), t(2026, 9, 29, 5, 0)), None);
        // An interval.
        assert_eq!(due(cc, 0, None, now), None);
        assert_eq!(due(cc, 1, None, now), Some(Reason::Time));
        assert_eq!(due(cc, 1, Some(now - 23 * 3600), now), None);
        assert_eq!(due(cc, 1, Some(now - 24 * 3600), now), Some(Reason::Time));
        assert_eq!(due(d, u64::MAX, None, now), None);
        // Size or time, whichever comes first.
        assert_eq!(due(e, 20 * 1024, Some(now - 60), now), Some(Reason::Size(10)));
        assert_eq!(due(e, 0, Some(now - 3600), now), Some(Reason::Time));
    }

    #[test]
    fn includes() {
        let dir = std::env::temp_dir().join(format!("newsyslog-conf-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("d/b.conf"), "/b 644 1 * *\n").unwrap();
        std::fs::write(dir.join("d/a.conf"), "/a 644 1 * *\n").unwrap();
        std::fs::write(dir.join("d/skip"), "/skip 644 1 * *\n").unwrap();
        std::fs::write(
            dir.join("main"),
            format!("include {0}/d\n<include> {0}/d/a.*\ninclude /nonexistent\n/z 644 1 * *\n", dir.display()),
        )
        .unwrap();
        let c = load(&dir.join("main"));
        let paths: Vec<_> = c.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["/a", "/b", "/a", "/z"]);
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
