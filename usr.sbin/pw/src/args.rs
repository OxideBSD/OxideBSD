//! Command-line parsing shared by both interfaces: a `getopt(3)` and the option values' formats.

use crate::{EX_USAGE, Result, err};

/// Parsed options, in order, and the operands.
pub struct Opts {
    pub opts: Vec<(char, Option<String>)>,
    pub operands: Vec<String>,
}

/// `getopt(3)` over `spec` (`"c:d:m"`: a letter, `:` if it takes a value). Options may follow
/// operands, as pw's `pw useradd name -m` needs; `--` ends them. A bad option is a usage error
/// with `usage` as its message.
pub fn getopt(args: &[String], spec: &str, usage: &str) -> Result<Opts> {
    let takes = |c: char| -> Option<bool> {
        let i = spec.find(c).filter(|_| c != ':')?;
        Some(spec[i + c.len_utf8()..].starts_with(':'))
    };
    let (mut opts, mut operands) = (Vec::new(), Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            operands.extend(it.cloned());
            break;
        }
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            operands.push(a.clone());
            continue;
        };
        for (i, c) in flags.char_indices() {
            match takes(c) {
                None => {
                    crate::warn(&format!("illegal option -- {c}"));
                    return err(EX_USAGE, usage);
                }
                Some(false) => opts.push((c, None)),
                Some(true) => {
                    let rest = &flags[i + c.len_utf8()..];
                    let v = if !rest.is_empty() {
                        rest.to_string()
                    } else {
                        match it.next() {
                            Some(v) => v.clone(),
                            None => {
                                crate::warn(&format!("option requires an argument -- {c}"));
                                return err(EX_USAGE, usage);
                            }
                        }
                    };
                    opts.push((c, Some(v)));
                    break;
                }
            }
        }
    }
    Ok(Opts { opts, operands })
}

/// A user or group ID.
pub fn id(what: &str, s: &str) -> Result<u32> {
    match s.parse::<u32>() {
        Ok(n) if s.bytes().all(|b| b.is_ascii_digit()) => Ok(n),
        _ => err(EX_USAGE, format!("bad {what} `{s}'")),
    }
}

/// An ID range, `low..high` (usermgmt.conf's `range`, useradd's `-r`).
pub fn range(s: &str) -> Result<(u32, u32)> {
    let Some((lo, hi)) = s.split_once("..") else { return err(EX_USAGE, format!("bad range `{s}': want low..high")) };
    let (lo, hi) = (id("range", lo)?, id("range", hi)?);
    if lo > hi {
        return err(EX_USAGE, format!("bad range `{s}': low above high"));
    }
    Ok((lo, hi))
}

/// A mode in octal (`-M 0750`).
pub fn mode(s: &str) -> Result<u32> {
    match u32::from_str_radix(s, 8) {
        Ok(m) if m <= 0o7777 => Ok(m),
        _ => err(EX_USAGE, format!("bad mode `{s}'")),
    }
}

/// A comma- or space-separated list (`-G wheel,staff`, `-M a,b`); repeated options add to it.
pub fn list(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split([',', ' ']).filter(|x| !x.is_empty()).map(String::from)
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// An account or password expiry time, in the forms the BSDs accept: `0` or empty (never),
/// seconds since the Epoch, `+N[hdwmy]` from now (days without a suffix; pw's form), or a date
/// (UTC midnight) as `YYYY-MM-DD`, `dd-mmm-yy[yy]` (pw's) or `dd mmm yyyy` / `mmm dd yyyy`
/// (useradd's).
pub fn time(s: &str, now: i64) -> Result<i64> {
    let s = s.trim();
    let bad = || err(EX_USAGE, format!("bad date `{s}'"));
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().or_else(|_| bad());
    }
    if let Some(rel) = s.strip_prefix('+') {
        let (n, unit) = match rel.find(|c: char| !c.is_ascii_digit()) {
            Some(i) => (&rel[..i], &rel[i..]),
            None => (rel, "d"),
        };
        let secs: i64 = match unit {
            "h" => 3600,
            "d" => 86400,
            "w" => 7 * 86400,
            "m" => 30 * 86400,
            "y" => 365 * 86400,
            _ => return bad(),
        };
        let Ok(n) = n.parse::<i64>() else { return bad() };
        return n.checked_mul(secs).and_then(|d| d.checked_add(now)).map_or_else(bad, Ok);
    }
    let parts: Vec<&str> = s.split(['-', ' ', '/']).filter(|p| !p.is_empty()).collect();
    let [a, b, c] = parts[..] else { return bad() };
    let (y, m, d) = if a.len() == 4 && a.bytes().all(|x| x.is_ascii_digit()) {
        (a, b.parse::<u32>().ok(), c)
    } else if let Some(m) = month(b) {
        (c, Some(m), a)
    } else if let Some(m) = month(a) {
        (c, Some(m), b)
    } else {
        return bad();
    };
    let (Ok(mut y), Some(m), Ok(d)) = (y.parse::<i64>(), m, d.parse::<u32>()) else { return bad() };
    if y < 100 {
        y += if y < 70 { 2000 } else { 1900 };
    }
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return bad();
    }
    Ok(days_from_civil(y, m, d) * 86400)
}

fn month(s: &str) -> Option<u32> {
    const M: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let s = s.to_ascii_lowercase();
    let p = s.get(..3)?;
    M.iter().position(|m| *m == p).map(|i| i as u32 + 1)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m as usize - 1]
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The date of a day since 1970-01-01: the inverse of `days_from_civil`.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn getopt_permutes_and_bundles() {
        let o = getopt(&s(&["name", "-mo", "-ufoo", "-s", "/bin/sh", "--", "-x"]), "mou:s:", "usage").unwrap();
        assert_eq!(o.operands, ["name", "-x"]);
        let flat: Vec<(char, Option<&str>)> = o.opts.iter().map(|(c, v)| (*c, v.as_deref())).collect();
        assert_eq!(flat, [('m', None), ('o', None), ('u', Some("foo")), ('s', Some("/bin/sh"))]);
        assert!(getopt(&s(&["-z"]), "m", "usage").is_err());
        assert!(getopt(&s(&["-s"]), "s:", "usage").is_err());
    }

    #[test]
    fn times() {
        assert_eq!(time("0", 5).unwrap(), 0);
        assert_eq!(time("1700000000", 5).unwrap(), 1700000000);
        assert_eq!(time("+2", 100).unwrap(), 100 + 2 * 86400);
        assert_eq!(time("+1w", 0).unwrap(), 7 * 86400);
        assert_eq!(time("1970-01-02", 0).unwrap(), 86400);
        assert_eq!(time("2000-03-01", 0).unwrap(), 951868800);
        assert_eq!(time("01-Mar-2000", 0).unwrap(), 951868800);
        assert_eq!(time("1 march 00", 0).unwrap(), 951868800);
        assert_eq!(time("Mar 1 2000", 0).unwrap(), 951868800);
        assert!(time("2001-02-29", 0).is_err());
        assert!(time("+3q", 0).is_err());
        assert!(time("tomorrow", 0).is_err());
        for days in [-1, 0, 59, 10957, 11016, 20000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(11017), (2000, 3, 1));
    }

    #[test]
    fn values() {
        assert_eq!(range("1000..60000").unwrap(), (1000, 60000));
        assert!(range("5..1").is_err() && range("5").is_err());
        assert_eq!(mode("0750").unwrap(), 0o750);
        assert!(mode("9").is_err());
        assert!(id("uid", "+1").is_err() && id("uid", "-1").is_err());
        assert_eq!(list("a,b c,,").collect::<Vec<_>>(), ["a", "b", "c"]);
    }
}
