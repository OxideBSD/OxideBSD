//! `touch(1)` (POSIX): sets the access and modification times of each file, creating a missing
//! one empty.
//!
//! ```text
//! touch [-acm] [-r ref_file | -t time | -d date_time] file...
//! ```
//!
//! `-a` and `-m` change only the access or only the modification time (both, given neither);
//! `-c` doesn't create a missing file. The time is now, or `ref_file`'s times (`-r`), or
//! `-t [[CC]YY]MMDDhhmm[.SS]` in local time, or `-d YYYY-MM-DDThh:mm:SS[.frac][Z]` (a space for
//! the `T`, a comma for the `.`; local time unless `Z`).

use std::ffi::CString;
use std::process::ExitCode;

const USAGE: &str = "usage: touch [-acm] [-r ref_file | -t time | -d date_time] file ...";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut atime, mut mtime, mut create) = (false, false, true);
    let mut when: Option<[libc::timespec; 2]> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        let mut flags = a[1..].chars();
        while let Some(f) = flags.next() {
            match f {
                'a' => atime = true,
                'm' => mtime = true,
                'c' => create = false,
                'r' | 't' | 'd' => {
                    // The value is the rest of this word, or the next one.
                    let rest: String = flags.by_ref().collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => return usage(),
                        }
                    };
                    if when.is_some() {
                        return usage(); // only one of -r, -t, -d
                    }
                    let t = match f {
                        'r' => reference_times(&value),
                        't' => parse_t(&value).map(|t| [t, t]),
                        _ => parse_d(&value).map(|t| [t, t]),
                    };
                    match t {
                        Ok(t) => when = Some(t),
                        Err(e) => {
                            eprintln!("touch: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
                _ => {
                    eprintln!("touch: illegal option -- {f}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    let files = &args[i..];
    if files.is_empty() {
        return usage();
    }
    if !atime && !mtime {
        atime = true;
        mtime = true;
    }
    let now = libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_NOW };
    let omit = libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT };
    let [a, m] = when.unwrap_or([now, now]);
    let times = [if atime { a } else { omit }, if mtime { m } else { omit }];
    let mut status = ExitCode::SUCCESS;
    for f in files {
        if let Err(e) = touch(f, &times, create) {
            eprintln!("touch: {f}: {e}");
            status = ExitCode::FAILURE;
        }
    }
    status
}

fn touch(path: &str, times: &[libc::timespec; 2], create: bool) -> std::io::Result<()> {
    let c = CString::new(path).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: a valid path and two timespecs.
    if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::ENOENT) {
        return Err(err);
    }
    if !create {
        return Ok(()); // POSIX: -c with a missing file is no error
    }
    std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(path)?;
    // SAFETY: as above.
    if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// `-r`: the reference file's access and modification times.
fn reference_times(path: &str) -> Result<[libc::timespec; 2], String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    Ok([
        libc::timespec { tv_sec: m.atime(), tv_nsec: m.atime_nsec() },
        libc::timespec { tv_sec: m.mtime(), tv_nsec: m.mtime_nsec() },
    ])
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn digits(s: &str) -> Option<i32> {
    if all_digits(s) { s.parse().ok() } else { None }
}

/// Local (or, with `utc`, UTC) broken-down time to seconds since the epoch.
fn to_epoch(year: i32, mon: i32, mday: i32, hour: i32, min: i32, sec: i32, utc: bool) -> Result<i64, String> {
    let bad = || "out of range or illegal time specification".to_string();
    if !(1..=12).contains(&mon) || !(1..=31).contains(&mday) || hour > 23 || min > 59 || sec > 60 {
        return Err(bad());
    }
    // SAFETY: a zeroed tm is a valid starting point.
    let mut tm: libc::tm = unsafe { core::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = mday;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;
    tm.tm_isdst = -1;
    // SAFETY: tm is filled in.
    let t = if utc { unsafe { libc::timegm(&mut tm) } } else { unsafe { libc::mktime(&mut tm) } };
    // mktime normalizes an impossible date (February 30) instead of refusing it.
    if t == -1 || tm.tm_mday != mday || tm.tm_mon != mon - 1 {
        return Err(bad());
    }
    Ok(t)
}

/// `-t [[CC]YY]MMDDhhmm[.SS]`. A two-digit year 69-99 is 19YY, 00-68 is 20YY (POSIX).
fn parse_t(s: &str) -> Result<libc::timespec, String> {
    let bad = || "out of range or illegal time specification: [[CC]YY]MMDDhhmm[.SS]".to_string();
    let (main, sec) = match s.split_once('.') {
        Some((m, ss)) if ss.len() == 2 => (m, digits(ss).ok_or_else(bad)?),
        Some(_) => return Err(bad()),
        None => (s, 0),
    };
    if !all_digits(main) || ![8, 10, 12].contains(&main.len()) {
        return Err(bad());
    }
    let n = |r: core::ops::Range<usize>| main[r].parse::<i32>().unwrap();
    let k = main.len() - 8;
    let year = match k {
        0 => {
            let mut tm: libc::tm = unsafe { core::mem::zeroed() };
            let now = unsafe { libc::time(core::ptr::null_mut()) };
            unsafe { libc::localtime_r(&now, &mut tm) };
            tm.tm_year + 1900
        }
        2 => {
            let yy = n(0..2);
            if yy >= 69 { 1900 + yy } else { 2000 + yy }
        }
        _ => n(0..4),
    };
    let t = to_epoch(year, n(k..k + 2), n(k + 2..k + 4), n(k + 4..k + 6), n(k + 6..k + 8), sec, false)
        .map_err(|_| bad())?;
    Ok(libc::timespec { tv_sec: t, tv_nsec: 0 })
}

/// `-d YYYY-MM-DDThh:mm:SS[.frac][Z]`.
fn parse_d(s: &str) -> Result<libc::timespec, String> {
    let bad = || "out of range or illegal time specification: YYYY-MM-DDThh:mm:SS[.frac][tz]".to_string();
    let (s, utc) = match s.strip_suffix('Z') {
        Some(rest) => (rest, true),
        None => (s, false),
    };
    let (date, time) = s.split_once(['T', ' ']).ok_or_else(bad)?;
    let d: Vec<&str> = date.split('-').collect();
    if d.len() != 3 || d[1].len() != 2 || d[2].len() != 2 {
        return Err(bad());
    }
    let (clock, frac) = match time.split_once(['.', ',']) {
        Some((c, f)) => (c, Some(f)),
        None => (time, None),
    };
    let t: Vec<&str> = clock.split(':').collect();
    if t.len() != 3 || t.iter().any(|x| x.len() != 2) {
        return Err(bad());
    }
    let num = |x: &str| digits(x).ok_or_else(bad);
    let nsec = match frac {
        None => 0,
        Some(f) if all_digits(f) => {
            let mut padded: String = f.chars().take(9).collect();
            while padded.len() < 9 {
                padded.push('0');
            }
            padded.parse::<i64>().unwrap()
        }
        Some(_) => return Err(bad()),
    };
    let secs = to_epoch(num(d[0])?, num(d[1])?, num(d[2])?, num(t[0])?, num(t[1])?, num(t[2])?, utc)
        .map_err(|_| bad())?;
    Ok(libc::timespec { tv_sec: secs, tv_nsec: nsec })
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::FAILURE
}
