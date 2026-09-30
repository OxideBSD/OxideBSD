//! The `crontab(5)` format (CRON.md §3): blank lines and `#` comments, environment settings
//! `name = value`, and job lines.
//!
//! ```text
//! MAILTO=""
//! # minute hour mday month wday [user] command
//! */15     9-17 *    *     mon-fri       backup -q
//! @reboot                                echo up%hello%world
//! ```
//!
//! The rules follow Vixie cron's `entry.c`, which the BSDs share: a field that begins with `*`
//! counts as unrestricted (so `*/2` in the day of the month still means "and", not "or", with
//! the day of the week); names work anywhere a number does; `7` is Sunday as well as `0`.

use crate::Tm;

/// A parsed table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    /// Environment settings, in order; a job sees those above it and below it alike, as in
    /// Vixie cron.
    pub env: Vec<(String, String)>,
    pub jobs: Vec<Job>,
}

/// One job line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub when: When,
    /// The user to run as: the sixth field of a system table, `None` in a user's own.
    pub user: Option<String>,
    /// The command, for `$SHELL -c`: up to the first unescaped `%`, with `\%` turned into `%`.
    pub command: String,
    /// The job's standard input, from the text after the first unescaped `%` (§3.5); `None`
    /// when there is none.
    pub input: Option<String>,
    /// The line the job is on, from 1.
    pub line: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum When {
    /// `@reboot`: once, when cron starts after boot.
    Reboot,
    /// `@every_second`.
    EverySecond,
    /// Five time fields, or a nickname standing for them.
    At(Schedule),
}

/// The five time fields, as bit sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// Bits 0-59.
    pub minute: u64,
    /// Bits 0-23.
    pub hour: u32,
    /// Bits 1-31.
    pub mday: u32,
    /// Bits 1-12.
    pub month: u16,
    /// Bits 0-6, Sunday 0 (a `7` in the table sets bit 0).
    pub wday: u8,
    /// Which fields began with `*`.
    pub minute_star: bool,
    pub hour_star: bool,
    pub mday_star: bool,
    pub wday_star: bool,
}

impl Schedule {
    /// Whether the job is due in minute `t`. When both day fields are restricted, either may
    /// match (§3.2); when either is `*`, both must.
    pub fn matches(&self, t: &Tm) -> bool {
        let bit = |set: u64, n: u32| set & (1u64 << n) != 0;
        let mday = bit(self.mday.into(), t.mday);
        let wday = bit(self.wday.into(), t.wday);
        let day = if self.mday_star || self.wday_star {
            mday && wday
        } else {
            mday || wday
        };
        bit(self.minute, t.min)
            && bit(self.hour.into(), t.hour)
            && bit(self.month.into(), t.mon)
            && day
    }

    /// A job whose minute or hour is `*` runs at many times of day; after a clock change such
    /// jobs are only run for the current time, while the others catch up (§4.5).
    pub fn is_wild(&self) -> bool {
        self.minute_star || self.hour_star
    }
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const DAYS: [&str; 8] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// A time field's name, bounds and value names (the first name is the value `lo`).
struct Field {
    what: &'static str,
    lo: u32,
    hi: u32,
    names: &'static [&'static str],
}

const MINUTE: Field = Field {
    what: "minute",
    lo: 0,
    hi: 59,
    names: &[],
};
const HOUR: Field = Field {
    what: "hour",
    lo: 0,
    hi: 23,
    names: &[],
};
const MDAY: Field = Field {
    what: "day of the month",
    lo: 1,
    hi: 31,
    names: &[],
};
const MONTH: Field = Field {
    what: "month",
    lo: 1,
    hi: 12,
    names: &MONTHS,
};
const WDAY: Field = Field {
    what: "day of the week",
    lo: 0,
    hi: 7,
    names: &DAYS,
};

impl Field {
    fn number(&self, s: &str) -> Result<u32, String> {
        let n = if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
            s.parse::<u32>().ok()
        } else {
            self.names
                .iter()
                .position(|n| n.eq_ignore_ascii_case(s))
                .map(|i| i as u32 + self.lo)
        };
        match n {
            Some(n) if (self.lo..=self.hi).contains(&n) => Ok(n),
            Some(n) => Err(format!(
                "{} {n} is out of range {}-{}",
                self.what, self.lo, self.hi
            )),
            None => Err(format!("bad {} \"{s}\"", self.what)),
        }
    }

    /// One field: a comma-separated list of `*`, `n` or `a-b`, each with an optional `/step`.
    /// Returns the set and whether the field began with `*`.
    fn parse(&self, s: &str) -> Result<(u64, bool), String> {
        let mut set = 0u64;
        for elem in s.split(',') {
            let (range, step) = match elem.split_once('/') {
                Some((r, st)) => {
                    let step = st
                        .parse::<u32>()
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or_else(|| format!("bad step \"{st}\" in the {}", self.what))?;
                    (r, Some(step))
                }
                None => (elem, None),
            };
            let (a, b) = if range == "*" {
                (self.lo, self.hi)
            } else if let Some((a, b)) = range.split_once('-') {
                let (a, b) = (self.number(a)?, self.number(b)?);
                if a > b {
                    return Err(format!("backwards range {range} in the {}", self.what));
                }
                (a, b)
            } else {
                let a = self.number(range)?;
                // `n/step` means from n to the end, stepping (as cronie and the BSDs' newer crons).
                (a, if step.is_some() { self.hi } else { a })
            };
            let step = step.unwrap_or(1);
            let mut n = a;
            while n <= b {
                set |= 1 << n;
                n += step;
            }
        }
        Ok((set, s.starts_with('*')))
    }
}

/// The `@` nicknames (§3.4), as the five fields they stand for.
fn nickname(word: &str) -> Option<When> {
    let fields = match word {
        "@reboot" => return Some(When::Reboot),
        "@every_second" => return Some(When::EverySecond),
        "@yearly" | "@annually" => "0 0 1 1 *",
        "@monthly" => "0 0 1 * *",
        "@weekly" => "0 0 * * 0",
        "@daily" | "@midnight" => "0 0 * * *",
        "@hourly" => "0 * * * *",
        "@every_minute" => "* * * * *",
        _ => return None,
    };
    let f: Vec<&str> = fields.split(' ').collect();
    Some(When::At(schedule(&f).expect("nicknames are valid")))
}

fn schedule(f: &[&str]) -> Result<Schedule, String> {
    let (minute, minute_star) = MINUTE.parse(f[0])?;
    let (hour, hour_star) = HOUR.parse(f[1])?;
    let (mday, mday_star) = MDAY.parse(f[2])?;
    let (month, _) = MONTH.parse(f[3])?;
    let (mut wday, wday_star) = WDAY.parse(f[4])?;
    if wday & (1 << 7) != 0 {
        wday = (wday & !(1 << 7)) | 1;
    }
    Ok(Schedule {
        minute,
        hour: hour as u32,
        mday: mday as u32,
        month: month as u16,
        wday: wday as u8,
        minute_star,
        hour_star,
        mday_star,
        wday_star,
    })
}

/// Splits off the first whitespace-separated word of `s`.
fn word(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start_matches([' ', '\t']);
    if s.is_empty() {
        return None;
    }
    let end = s.find([' ', '\t']).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

/// An environment setting, `name = value`: a name (no blanks or `=`), optional blanks, `=`,
/// and a value, trimmed, which may be quoted with `'` or `"`.
fn env_line(line: &str) -> Option<(String, String)> {
    let line = line.trim_start_matches([' ', '\t']);
    let end = line.find([' ', '\t', '='])?;
    let name = &line[..end];
    let rest = line[end..]
        .trim_start_matches([' ', '\t'])
        .strip_prefix('=')?;
    if name.is_empty() {
        return None;
    }
    let mut value = rest.trim_matches([' ', '\t']);
    for q in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(q) && value.ends_with(q) {
            value = &value[1..value.len() - 1];
            break;
        }
    }
    Some((name.to_string(), value.to_string()))
}

/// Splits a command at its first unescaped `%` (§3.5). In both parts `\%` is a `%`; in the
/// input, each further `%` is a newline, and a final newline is added if missing.
pub fn split_percent(text: &str) -> (String, Option<String>) {
    let mut command = String::new();
    let mut input: Option<String> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' && input.is_none() {
            input = Some(String::new());
            continue;
        }
        let out = input.as_mut().unwrap_or(&mut command);
        match c {
            '\\' if chars.peek() == Some(&'%') => {
                out.push('%');
                chars.next();
            }
            '%' => out.push('\n'),
            c => out.push(c),
        }
    }
    if let Some(input) = input.as_mut()
        && !input.is_empty()
        && !input.ends_with('\n')
    {
        input.push('\n');
    }
    (command.trim_end_matches([' ', '\t']).to_string(), input)
}

fn job_line(line: &str, number: usize, system: bool) -> Result<Job, String> {
    let (first, mut rest) = word(line).ok_or("empty line")?;
    let when = if first.starts_with('@') {
        nickname(first).ok_or_else(|| format!("unknown time \"{first}\""))?
    } else {
        let mut f = vec![first];
        for what in ["hour", "day of the month", "month", "day of the week"] {
            let (w, r) = word(rest).ok_or_else(|| format!("no {what}"))?;
            f.push(w);
            rest = r;
        }
        When::At(schedule(&f)?)
    };
    let user = if system {
        let (u, r) = word(rest).ok_or("no user")?;
        rest = r;
        Some(u.to_string())
    } else {
        None
    };
    let (command, input) = split_percent(rest.trim_start_matches([' ', '\t']));
    if command.is_empty() {
        return Err("no command".into());
    }
    Ok(Job {
        when,
        user,
        command,
        input,
        line: number,
    })
}

/// Parses a table. `system` is true for `/etc/crontab` and the `cron.d` directories, whose job
/// lines name a user (§3.3). Returns what parsed and, for each line that didn't, its number
/// (from 1) and the reason; `cron` runs the rest, `crontab` refuses the table.
pub fn parse(text: &str, system: bool) -> (Table, Vec<(usize, String)>) {
    let mut table = Table::default();
    let mut errors = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(setting) = env_line(line) {
            table.env.push(setting);
            continue;
        }
        match job_line(line, i + 1, system) {
            Ok(job) => table.jobs.push(job),
            Err(e) => errors.push((i + 1, e)),
        }
    }
    (table, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(fields: &str) -> Schedule {
        let (t, errs) = parse(&format!("{fields} true"), false);
        assert!(errs.is_empty(), "{fields}: {errs:?}");
        match t.jobs[0].when {
            When::At(s) => s,
            ref w => panic!("{w:?}"),
        }
    }

    fn bits(set: u64) -> Vec<u32> {
        (0..64).filter(|n| set & (1 << n) != 0).collect()
    }

    #[test]
    fn field_forms() {
        let s = at("*/15 9-17/4 1,15,31 */3 *");
        assert_eq!(bits(s.minute), [0, 15, 30, 45]);
        assert_eq!(bits(s.hour.into()), [9, 13, 17]);
        assert_eq!(bits(s.mday.into()), [1, 15, 31]);
        assert_eq!(bits(s.month.into()), [1, 4, 7, 10]);
        assert_eq!(s.wday, 0x7f);
        assert!(s.minute_star && !s.hour_star && !s.mday_star && s.wday_star);
        assert_eq!(bits(at("50/5 * * * *").minute), [50, 55]);
        assert_eq!(
            bits(at("1-3,7,40-42 * * * *").minute),
            [1, 2, 3, 7, 40, 41, 42]
        );
    }

    #[test]
    fn names_and_sunday() {
        let s = at("0 0 * JAN-mar,Dec mon-FRI");
        assert_eq!(bits(s.month.into()), [1, 2, 3, 12]);
        assert_eq!(bits(s.wday.into()), [1, 2, 3, 4, 5]);
        assert_eq!(at("0 0 * * 7").wday, 1);
        assert_eq!(at("0 0 * * 5-7").wday, 0b110_0001);
        assert_eq!(at("0 0 * * sun").wday, 1);
    }

    #[test]
    fn nicknames() {
        assert_eq!(at("@daily"), at("0 0 * * *"));
        assert_eq!(at("@midnight"), at("0 0 * * *"));
        assert_eq!(at("@yearly"), at("0 0 1 1 *"));
        assert_eq!(at("@annually"), at("0 0 1 1 *"));
        assert_eq!(at("@monthly"), at("0 0 1 * *"));
        assert_eq!(at("@weekly"), at("0 0 * * 0"));
        assert_eq!(at("@hourly"), at("0 * * * *"));
        assert_eq!(at("@every_minute"), at("* * * * *"));
        let (t, _) = parse("@reboot a\n@every_second b\n", false);
        assert_eq!(t.jobs[0].when, When::Reboot);
        assert_eq!(t.jobs[1].when, When::EverySecond);
    }

    #[test]
    fn day_rule() {
        // The 13th, or any Friday.
        let either = at("0 0 13 * 5");
        let fri_12th = Tm {
            min: 0,
            hour: 0,
            mday: 12,
            mon: 6,
            wday: 5,
        };
        let thu_13th = Tm {
            min: 0,
            hour: 0,
            mday: 13,
            mon: 6,
            wday: 4,
        };
        let thu_12th = Tm {
            min: 0,
            hour: 0,
            mday: 12,
            mon: 6,
            wday: 4,
        };
        assert!(
            either.matches(&fri_12th) && either.matches(&thu_13th) && !either.matches(&thu_12th)
        );
        // Fridays only: the day of the month is `*`.
        let fridays = at("0 0 * * 5");
        assert!(fridays.matches(&fri_12th) && !fridays.matches(&thu_13th));
        // A field beginning with `*` counts as unrestricted: odd days that are also Fridays.
        let both = at("0 0 */2 * 5");
        let fri_13th = Tm {
            wday: 5,
            ..thu_13th
        };
        assert!(both.matches(&fri_13th) && !both.matches(&fri_12th) && !both.matches(&thu_13th));
        assert!(!at("5 0 * * *").matches(&fri_12th));
        assert!(!at("0 0 * 7 *").matches(&fri_12th));
    }

    #[test]
    fn system_tables_and_environment() {
        let text = "SHELL=/bin/sh\n\
                    PATH = /etc:/bin \n\
                    MAILTO=\"\"\n\
                    GREETING = 'hi there'\n\
                    # a comment\n\
                    \n\
                    \t0\t*\t*\t*\t*\troot\tnewsyslog -v\n\
                    @reboot operator  echo  up \n";
        let (t, errs) = parse(text, true);
        assert!(errs.is_empty(), "{errs:?}");
        let env: Vec<(&str, &str)> = t
            .env
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        assert_eq!(
            env,
            [
                ("SHELL", "/bin/sh"),
                ("PATH", "/etc:/bin"),
                ("MAILTO", ""),
                ("GREETING", "hi there")
            ]
        );
        assert_eq!(t.jobs.len(), 2);
        assert_eq!(t.jobs[0].user.as_deref(), Some("root"));
        assert_eq!(t.jobs[0].command, "newsyslog -v");
        assert_eq!(t.jobs[0].line, 7);
        assert_eq!(t.jobs[1].user.as_deref(), Some("operator"));
        assert_eq!(t.jobs[1].command, "echo  up");
        // A user's own table has no user field.
        let (t, _) = parse("0 * * * * root newsyslog\n", false);
        assert_eq!(t.jobs[0].user, None);
        assert_eq!(t.jobs[0].command, "root newsyslog");
    }

    #[test]
    fn percent() {
        assert_eq!(split_percent("date"), ("date".into(), None));
        assert_eq!(
            split_percent("mail -s hi root%line one%line two"),
            (
                "mail -s hi root".into(),
                Some("line one\nline two\n".into())
            )
        );
        assert_eq!(
            split_percent(r"date +\%Y-\%m%in\%put%"),
            ("date +%Y-%m".into(), Some("in%put\n".into()))
        );
        assert_eq!(split_percent("cat %"), ("cat".into(), Some(String::new())));
        assert_eq!(split_percent(r"echo \n"), (r"echo \n".into(), None));
        let (t, _) = parse("* * * * * cat%a%b\n", false);
        assert_eq!(t.jobs[0].input.as_deref(), Some("a\nb\n"));
    }

    #[test]
    fn errors_name_the_line() {
        let text = "ok=1\n\
                    60 * * * * a\n\
                    * 24 * * * a\n\
                    * * 0 * * a\n\
                    * * * 13 * a\n\
                    * * * * 8 a\n\
                    * * * foo * a\n\
                    5-1 * * * * a\n\
                    */0 * * * * a\n\
                    * * * *\n\
                    * * * * *\n\
                    @sometimes a\n\
                    1,,2 * * * * a\n\
                    * * * * * fine\n";
        let (t, errs) = parse(text, false);
        let lines: Vec<usize> = errs.iter().map(|e| e.0).collect();
        assert_eq!(lines, (2..=13).collect::<Vec<_>>(), "{errs:#?}");
        assert_eq!(t.jobs.len(), 1);
        assert_eq!(errs[0].1, "minute 60 is out of range 0-59");
        assert_eq!(errs[5].1, "bad month \"foo\"");
        assert_eq!(errs[6].1, "backwards range 5-1 in the minute");
        assert_eq!(errs[8].1, "no day of the week");
        assert_eq!(errs[9].1, "no command");
        assert_eq!(errs[10].1, "unknown time \"@sometimes\"");
        // In a system table the last word is the user, and the command is missing.
        let (_, errs) = parse("0 0 * * * root\n", true);
        assert_eq!(errs, [(1, "no command".to_string())]);
    }
}
