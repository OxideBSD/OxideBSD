//! `date(1)`: shows or sets the date and time.
//!
//! ```text
//! date [-jnRu] [-I[date|hours|minutes|seconds]] [-r seconds | -r file]
//!      [-v [+|-]val[y|m|w|d|H|M|S]] ... [+output_fmt]
//! date [-jnu] [[[[[cc]yy]mm]dd]HH]MM[.SS] [+output_fmt]
//! date [-jnRu] -f input_fmt new_date [+output_fmt]
//! ```
//!
//! The BSDs' date. With no operand it writes the time (now, or `-r`'s) in the `+output_fmt`
//! given (`strftime(3)`), or as `%a %b %e %H:%M:%S %Z %Y`; `-R` writes RFC 2822's form and `-I`
//! ISO 8601's, to the day, hour, minute or second. `-u` works in UTC.
//!
//! `-r seconds` is a time since the epoch, `-r file` that file's modification time. `-v` adjusts
//! the time before it is written: a field set to `val`, or moved `+` or `-` by it, in years,
//! months, weeks, days, hours, minutes or seconds; a month or weekday may be named
//! (`-v+fri`: the next Friday). Several apply in turn.
//!
//! An operand of digits sets the clock: `[[[[[cc]yy]mm]dd]HH]MM[.SS]`, the fields left out
//! staying as they are (seconds as 0); with `-f input_fmt` the operand is read with
//! `strptime(3)` instead. `-j` only shows the time the operand names, setting nothing (with `-f`,
//! a way to convert dates). `-n` is accepted (there is no time daemon to keep out of it).

use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;

const DEFAULT_FORMAT: &str = "%a %b %e %H:%M:%S %Z %Y";
const RFC2822: &str = "%a, %d %b %Y %T %z";

fn usage() -> ExitCode {
    eprintln!(
        "usage: date [-jnRu] [-I[date|hours|minutes|seconds]] [-r seconds | -r file]\n            \
         [-v[+|-]val[y|m|w|d|H|M|S]] [+output_fmt]\n       \
         date [-jnu] [[[[[cc]yy]mm]dd]HH]MM[.SS] [+output_fmt]\n       \
         date [-jnRu] -f input_fmt new_date [+output_fmt]"
    );
    ExitCode::from(1)
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn zero_tm() -> libc::tm {
    // SAFETY: an all-zero tm is valid (tm_zone a null pointer).
    unsafe { std::mem::zeroed() }
}

fn localtime(t: i64) -> libc::tm {
    let mut tm = zero_tm();
    // SAFETY: tm is ours to fill; time_t is 64 bits.
    unsafe { libc::localtime_r(&t, &mut tm) };
    tm
}

/// mktime(3), daylight saving time worked out afresh.
fn mktime(tm: &mut libc::tm) -> Option<i64> {
    tm.tm_isdst = -1;
    // SAFETY: a filled-in tm.
    let t = unsafe { libc::mktime(tm) };
    if t == -1 && !(tm.tm_year == 69 && tm.tm_mon == 11 && tm.tm_mday == 31) { None } else { Some(t) }
}

fn strftime(fmt: &str, tm: &libc::tm) -> String {
    if fmt.is_empty() {
        return String::new();
    }
    let Ok(cfmt) = CString::new(fmt) else {
        return String::new();
    };
    let mut size = 256;
    while size <= 1 << 20 {
        let mut buf = vec![0u8; size];
        // SAFETY: a buffer of `size` bytes and a NUL-terminated format.
        let n = unsafe { libc::strftime(buf.as_mut_ptr().cast(), size, cfmt.as_ptr(), tm) };
        if n > 0 {
            buf.truncate(n);
            return String::from_utf8_lossy(&buf).into_owned();
        }
        size *= 4;
    }
    String::new()
}

fn days_in_month(year: i32, mon: i32) -> i32 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    match mon {
        1 => {
            if leap {
                29
            } else {
                28
            }
        }
        3 | 5 | 8 | 10 => 30,
        _ => 31,
    }
}

const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// A month or weekday name (three letters at least, or the full name), as an index.
fn name_index(s: &str, names: &[&str]) -> Option<usize> {
    let l = s.to_ascii_lowercase();
    if l.len() < 3 {
        return None;
    }
    let full = [
        "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november",
        "december", "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
    ];
    names.iter().position(|n| l.starts_with(n) && full.iter().any(|f| f.starts_with(&l)))
}

/// Moves `tm` by `days` days, wall-clock time kept.
fn add_days(tm: &mut libc::tm, days: i64) -> Option<()> {
    tm.tm_mday = (tm.tm_mday as i64 + days) as i32;
    mktime(tm).map(|_| ())
}

/// One `-v` adjustment, FreeBSD's vary(3).
fn vary(tm: &mut libc::tm, spec: &str) -> Option<()> {
    let (sign, rest) = match spec.as_bytes().first()? {
        b'+' => (1i64, &spec[1..]),
        b'-' => (-1i64, &spec[1..]),
        _ => (0, spec),
    };
    // A name: a month or a weekday.
    if rest.chars().next()?.is_ascii_alphabetic() {
        if let Some(m) = name_index(rest, &MONTHS) {
            let m = m as i32;
            match sign {
                0 => {
                    tm.tm_mon = m;
                }
                1 => {
                    if m != tm.tm_mon {
                        tm.tm_mon = if m > tm.tm_mon { m } else { m + 12 };
                    }
                }
                _ => {
                    if m != tm.tm_mon {
                        tm.tm_mon = if m < tm.tm_mon { m } else { m - 12 };
                    }
                }
            }
            let y = 1900 + tm.tm_year + tm.tm_mon.div_euclid(12);
            tm.tm_mday = tm.tm_mday.min(days_in_month(y, tm.tm_mon.rem_euclid(12)));
            return mktime(tm).map(|_| ());
        }
        let w = name_index(rest, &WEEKDAYS)? as i32;
        return weekday(tm, sign, w);
    }
    let unit = rest.chars().last()?;
    let digits = &rest[..rest.len() - unit.len_utf8()];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let val: i64 = digits.parse().ok()?;
    let delta = sign * val;
    match unit {
        'y' => {
            if sign == 0 {
                let y = if val < 69 {
                    val + 2000
                } else if val < 100 {
                    val + 1900
                } else {
                    val
                };
                tm.tm_year = (y - 1900) as i32;
            } else {
                tm.tm_year += delta as i32;
            }
            let y = 1900 + tm.tm_year;
            tm.tm_mday = tm.tm_mday.min(days_in_month(y, tm.tm_mon));
            mktime(tm).map(|_| ())
        }
        'm' => {
            if sign == 0 {
                if !(1..=12).contains(&val) {
                    return None;
                }
                tm.tm_mon = val as i32 - 1;
            } else {
                tm.tm_mon += delta as i32;
            }
            let y = 1900 + tm.tm_year + tm.tm_mon.div_euclid(12);
            tm.tm_mday = tm.tm_mday.min(days_in_month(y, tm.tm_mon.rem_euclid(12)));
            mktime(tm).map(|_| ())
        }
        'w' => {
            if sign == 0 {
                if val > 6 {
                    return None;
                }
                weekday(tm, 0, val as i32)
            } else {
                add_days(tm, 7 * delta)
            }
        }
        'd' => {
            if sign == 0 {
                if val < 1 || val > days_in_month(1900 + tm.tm_year, tm.tm_mon) as i64 {
                    return None;
                }
                tm.tm_mday = val as i32;
                mktime(tm).map(|_| ())
            } else {
                add_days(tm, delta)
            }
        }
        'H' | 'M' | 'S' => {
            let (limit, secs) = match unit {
                'H' => (23, 3600),
                'M' => (59, 60),
                _ => (60, 1),
            };
            if sign == 0 {
                if val > limit {
                    return None;
                }
                match unit {
                    'H' => tm.tm_hour = val as i32,
                    'M' => tm.tm_min = val as i32,
                    _ => tm.tm_sec = val as i32,
                }
                mktime(tm).map(|_| ())
            } else {
                // Hours and less are real elapsed time, across a DST change too.
                let mut copy = *tm;
                let t = mktime(&mut copy)?;
                *tm = localtime(t + delta * secs);
                Some(())
            }
        }
        _ => None,
    }
}

/// `-v` with a weekday: forward (`+`), back (`-`), or within this week.
fn weekday(tm: &mut libc::tm, sign: i64, w: i32) -> Option<()> {
    let cur = tm.tm_wday;
    let days = match sign {
        1 => (w - cur).rem_euclid(7),
        -1 => -((cur - w).rem_euclid(7)),
        _ => w - cur,
    };
    add_days(tm, days as i64)
}

/// `[[[[[cc]yy]mm]dd]HH]MM[.SS]` over `now`.
fn parse_set(s: &str, now: i64) -> Option<i64> {
    let (main, secs) = match s.split_once('.') {
        Some((m, ss)) => {
            if ss.len() != 2 || !ss.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (m, ss.parse::<i32>().ok()?)
        }
        None => (s, 0),
    };
    if !main.bytes().all(|b| b.is_ascii_digit()) || main.len() % 2 == 1 || main.len() < 2 || main.len() > 12 {
        return None;
    }
    let mut tm = localtime(now);
    let pairs: Vec<i32> = main.as_bytes().chunks(2).map(|c| ((c[0] - b'0') * 10 + (c[1] - b'0')) as i32).collect();
    let mut p = pairs.into_iter().rev();
    // Right to left: minutes, hours, day, month, year, century.
    tm.tm_min = p.next()?;
    if let Some(h) = p.next() {
        tm.tm_hour = h;
    }
    if let Some(d) = p.next() {
        tm.tm_mday = d;
    }
    if let Some(m) = p.next() {
        tm.tm_mon = m - 1;
    }
    if let Some(yy) = p.next() {
        let year = match p.next() {
            Some(cc) => cc * 100 + yy,
            None if yy < 69 => 2000 + yy,
            None => 1900 + yy,
        };
        tm.tm_year = year - 1900;
    }
    tm.tm_sec = secs;
    if tm.tm_min > 59 || tm.tm_hour > 23 || tm.tm_sec > 60 || !(0..12).contains(&tm.tm_mon) || tm.tm_mday < 1 {
        return None;
    }
    if tm.tm_mday > days_in_month(1900 + tm.tm_year, tm.tm_mon) {
        return None;
    }
    mktime(&mut tm)
}

/// `-f`: `s` read with `strptime(3)` over `now`.
fn parse_with(fmt: &str, s: &str, now: i64) -> Option<i64> {
    let mut tm = localtime(now);
    let (cf, cs) = (CString::new(fmt).ok()?, CString::new(s).ok()?);
    // SAFETY: NUL-terminated strings and a tm to fill.
    let end = unsafe { libc::strptime(cs.as_ptr(), cf.as_ptr(), &mut tm) };
    if end.is_null() {
        return None;
    }
    // SAFETY: strptime returns a pointer into cs.
    if unsafe { *end } != 0 {
        let rest = unsafe { CStr::from_ptr(end) }.to_string_lossy().into_owned();
        eprintln!("date: Ignoring {} extraneous characters in date string ({rest})", rest.len());
    }
    mktime(&mut tm)
}

/// ISO 8601 for `-I`: the time to `level`, with the UTC offset as `+hh:mm`.
fn iso(tm: &libc::tm, level: &str) -> Option<String> {
    let fmt = match level {
        "date" => return Some(strftime("%Y-%m-%d", tm)),
        "hours" => "%Y-%m-%dT%H",
        "minutes" => "%Y-%m-%dT%H:%M",
        "seconds" => "%Y-%m-%dT%H:%M:%S",
        _ => return None,
    };
    let z = strftime("%z", tm);
    let z = if z.len() == 5 { format!("{}:{}", &z[..3], &z[3..]) } else { z };
    Some(strftime(fmt, tm) + &z)
}

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut no_set, mut rfc, mut utc) = (false, false, false);
    let mut iso_level: Option<String> = None;
    let mut reference: Option<String> = None;
    let mut input_fmt: Option<String> = None;
    let mut adjustments: Vec<String> = Vec::new();
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
        let mut chars = a[1..].char_indices();
        while let Some((pos, c)) = chars.next() {
            let rest = &a[1 + pos + c.len_utf8()..];
            match c {
                'j' => no_set = true,
                'n' => {}
                'R' => rfc = true,
                'u' => utc = true,
                'I' => {
                    iso_level = Some(if rest.is_empty() { "date".into() } else { rest.to_string() });
                    break;
                }
                'r' | 'f' | 'v' => {
                    let value = if !rest.is_empty() {
                        rest.to_string()
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => return usage(),
                        }
                    };
                    match c {
                        'r' => reference = Some(value),
                        'f' => input_fmt = Some(value),
                        _ => adjustments.push(value),
                    }
                    break;
                }
                _ => {
                    eprintln!("date: illegal option -- {c}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    if utc {
        // SAFETY: single-threaded; set before any time conversion.
        unsafe { std::env::set_var("TZ", "UTC0") };
    }
    unsafe extern "C" {
        fn tzset();
    }
    // SAFETY: reads TZ.
    unsafe { tzset() };

    let mut tval: i64 = match &reference {
        None => {
            // SAFETY: time(NULL) can't fail here.
            unsafe { libc::time(std::ptr::null_mut()) }
        }
        Some(r) => {
            let num = r.strip_prefix('-').unwrap_or(r);
            if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
                match r.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("date: {r}: value out of range");
                        return ExitCode::from(1);
                    }
                }
            } else {
                match std::fs::metadata(r) {
                    Ok(m) => m.mtime(),
                    Err(e) => {
                        eprintln!("date: {r}: {}", strerror(&e));
                        return ExitCode::from(1);
                    }
                }
            }
        }
    };

    let mut format = if rfc { RFC2822.to_string() } else { DEFAULT_FORMAT.to_string() };
    let mut ops = args[i..].iter();
    let mut next = ops.next();
    if let Some(f) = next.and_then(|o| o.strip_prefix('+')) {
        format = f.to_string();
        next = ops.next();
    }
    if let Some(when) = next {
        let parsed = match &input_fmt {
            Some(f) => parse_with(f, when, tval),
            None => parse_set(when, tval),
        };
        let Some(t) = parsed else {
            match &input_fmt {
                Some(_) => eprintln!("date: Cannot parse \"{when}\" using the given format"),
                None => {
                    eprintln!("date: illegal time format");
                    return usage();
                }
            }
            return ExitCode::from(1);
        };
        tval = t;
        if !no_set {
            let ts = libc::timespec { tv_sec: t as _, tv_nsec: 0 };
            // SAFETY: a valid timespec.
            if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } != 0 {
                eprintln!("date: clock_settime: {}", strerror(&io::Error::last_os_error()));
                return ExitCode::from(1);
            }
        }
        next = ops.next();
    } else if input_fmt.is_some() {
        return usage();
    }
    if let Some(n) = next {
        match n.strip_prefix('+') {
            Some(f) => format = f.to_string(),
            None => return usage(),
        }
        if ops.next().is_some() {
            return usage();
        }
    }

    let mut tm = localtime(tval);
    for v in &adjustments {
        if vary(&mut tm, v).is_none() {
            eprintln!("date: -v{v}: Cannot apply date adjustment");
            return usage();
        }
    }
    let text = match &iso_level {
        Some(l) => match iso(&tm, l) {
            Some(s) => s,
            None => {
                eprintln!("date: invalid argument '{l}' for -I");
                return usage();
            }
        },
        None => strftime(&format, &tm),
    };
    let mut out = io::stdout().lock();
    if out.write_all(format!("{text}\n").as_bytes()).and_then(|_| out.flush()).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
