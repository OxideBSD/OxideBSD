//! Which minutes to run jobs for, as the clock moves (CRON.md §§4.1, 4.5, 4.6). Vixie cron 4's
//! main loop, which the BSDs' crons share, as a pure state machine:
//!
//! - The clock advanced one minute: run every job due in it.
//! - It jumped forward by up to three hours: for each skipped minute, run the jobs with a fixed
//!   time that were due in it, once; then every job due in the current minute.
//! - It jumped back by up to three hours: until it is past where it was, run only the jobs
//!   whose minute or hour is `*`; the fixed ones already ran.
//! - A larger jump in either direction starts again from the new time.
//!
//! What counts as a jump depends on how minutes are counted ([`Mode`]). Counted in UTC (`-o`,
//! the default, as in FreeBSD), only a change of the clock itself is one, and a daylight-saving
//! change skips or repeats local times like any other. Counted in local time (`-s`), a
//! daylight-saving change is a jump too: a fixed-time job in a skipped hour runs once after it,
//! and one in a repeated hour doesn't run again.

use crate::Tm;
use crate::table::Schedule;

/// How cron counts minutes; `-o` and `-s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    /// Minutes since the epoch, UTC.
    #[default]
    Utc,
    /// Minutes since the epoch plus the local offset from UTC.
    Local,
}

impl Mode {
    /// The minute `secs` (seconds since the epoch) falls in; `gmtoff` is the local offset from
    /// UTC at that moment, in seconds.
    pub fn minute(self, secs: i64, gmtoff: i64) -> i64 {
        match self {
            Mode::Utc => secs.div_euclid(60),
            Mode::Local => (secs + gmtoff).div_euclid(60),
        }
    }

    /// The local time of a minute counted this way. `localtime` breaks seconds since the epoch
    /// down to local time (`localtime(3)`); only [`Mode::Utc`] needs it.
    pub fn tm(self, minute: i64, localtime: impl Fn(i64) -> Tm) -> Tm {
        match self {
            Mode::Utc => localtime(minute * 60),
            Mode::Local => Tm::from_minutes(minute),
        }
    }
}

/// How far the clock may jump, in minutes, and still be caught up with rather than started over.
pub const MAX_JUMP: i64 = 3 * 60;

/// A minute to run jobs for, and which of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Due {
    pub minute: i64,
    /// Jobs whose minute or hour is `*`.
    pub wild: bool,
    /// The others.
    pub fixed: bool,
}

impl Due {
    /// Whether a job with this schedule runs in this minute.
    pub fn runs(&self, s: &Schedule, tm: &Tm) -> bool {
        (if s.is_wild() { self.wild } else { self.fixed }) && s.matches(tm)
    }
}

/// The scheduler's state.
#[derive(Clone, Debug)]
pub struct Clock {
    /// The latest minute every job has been run for.
    running: i64,
    /// The minute of the last call.
    last: i64,
}

impl Clock {
    /// Starts at `now`, a minute counted per the [`Mode`]; jobs run from the next one, as cron
    /// starts partway through a minute.
    pub fn new(now: i64) -> Clock {
        Clock {
            running: now,
            last: now,
        }
    }

    /// Called whenever cron wakes, with the current minute; returns the minutes to run jobs
    /// for, in order. Nothing when it's still the minute of the last call.
    pub fn advance(&mut self, now: i64) -> Vec<Due> {
        if now == self.last {
            return Vec::new();
        }
        self.last = now;
        let all = Due {
            minute: now,
            wild: true,
            fixed: true,
        };
        if now > self.running && now - self.running <= MAX_JUMP {
            let mut due: Vec<Due> = (self.running + 1..now)
                .map(|minute| Due {
                    minute,
                    wild: false,
                    fixed: true,
                })
                .collect();
            due.push(all);
            self.running = now;
            due
        } else if now <= self.running && self.running - now <= MAX_JUMP {
            vec![Due {
                minute: now,
                wild: true,
                fixed: false,
            }]
        } else {
            self.running = now;
            vec![all]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::{When, parse};

    fn all(minute: i64) -> Due {
        Due {
            minute,
            wild: true,
            fixed: true,
        }
    }

    #[test]
    fn steady() {
        let mut c = Clock::new(100);
        assert_eq!(c.advance(100), []);
        assert_eq!(c.advance(101), [all(101)]);
        assert_eq!(c.advance(101), []);
        assert_eq!(c.advance(102), [all(102)]);
    }

    #[test]
    fn forward_catches_up_fixed_jobs() {
        let mut c = Clock::new(100);
        let due = c.advance(104);
        let fixed = |minute| Due {
            minute,
            wild: false,
            fixed: true,
        };
        assert_eq!(due, [fixed(101), fixed(102), fixed(103), all(104)]);
        assert_eq!(c.advance(105), [all(105)]);
        // Exactly three hours is still caught up with; more starts over.
        assert_eq!(c.advance(105 + MAX_JUMP).len(), MAX_JUMP as usize);
        let mut c = Clock::new(100);
        assert_eq!(c.advance(101 + MAX_JUMP), [all(101 + MAX_JUMP)]);
        assert_eq!(c.advance(102 + MAX_JUMP), [all(102 + MAX_JUMP)]);
    }

    #[test]
    fn backward_runs_only_wild_jobs_until_past() {
        let mut c = Clock::new(100);
        let wild = |minute| Due {
            minute,
            wild: true,
            fixed: false,
        };
        assert_eq!(c.advance(40), [wild(40)]);
        for m in 41..=100 {
            assert_eq!(c.advance(m), [wild(m)]);
        }
        assert_eq!(c.advance(101), [all(101)]);
        // Further back than three hours starts over.
        let mut c = Clock::new(1000);
        assert_eq!(c.advance(1000 - MAX_JUMP - 1), [all(1000 - MAX_JUMP - 1)]);
        assert_eq!(c.advance(1000 - MAX_JUMP), [all(1000 - MAX_JUMP)]);
    }

    /// A zone one hour ahead of UTC that moves to two hours ahead at `spring` and back at `fall`
    /// (seconds since the epoch).
    struct Zone {
        spring: i64,
        fall: i64,
    }

    impl Zone {
        fn gmtoff(&self, secs: i64) -> i64 {
            if (self.spring..self.fall).contains(&secs) {
                7200
            } else {
                3600
            }
        }
        fn localtime(&self, secs: i64) -> Tm {
            Tm::from_minutes((secs + self.gmtoff(secs)).div_euclid(60))
        }
    }

    /// Runs cron's loop over `[from, to)` (UTC seconds) a minute at a time, and returns, for
    /// each job of `table`, the local times (`hh:mm`) it ran at.
    fn simulate(table: &str, zone: &Zone, mode: Mode, from: i64, to: i64) -> Vec<Vec<String>> {
        let (t, errs) = parse(table, false);
        assert!(errs.is_empty());
        let mut runs = vec![Vec::new(); t.jobs.len()];
        let mut clock = Clock::new(mode.minute(from, zone.gmtoff(from)));
        let mut secs = from + 60;
        while secs < to {
            for due in clock.advance(mode.minute(secs, zone.gmtoff(secs))) {
                let tm = mode.tm(due.minute, |s| zone.localtime(s));
                for (i, job) in t.jobs.iter().enumerate() {
                    if let When::At(s) = &job.when
                        && due.runs(s, &tm)
                    {
                        runs[i].push(format!("{:02}:{:02}", tm.hour, tm.min));
                    }
                }
            }
            secs += 60;
        }
        runs
    }

    // 2026-03-29 00:00 UTC (a Sunday); the zone springs forward at 01:00 UTC, 02:00 local
    // becoming 03:00, and falls back at 2026-10-25 01:00 UTC, 03:00 local becoming 02:00.
    const MAR29: i64 = 1_774_742_400;
    const OCT25: i64 = 1_792_886_400;
    const TABLE: &str = "30 2 * * * fixed\n0 * * * * hourly\n*/20 2 * * * wild-in-2\n";

    #[test]
    fn spring_forward() {
        let zone = Zone {
            spring: MAR29 + 3600,
            fall: OCT25 + 3600,
        };
        let (from, to) = (MAR29, MAR29 + 4 * 3600);
        // Minutes counted in UTC: 02:30 local never happens.
        let r = simulate(TABLE, &zone, Mode::Utc, from, to);
        assert_eq!(r[0], Vec::<String>::new());
        assert_eq!(r[1], ["03:00", "04:00", "05:00"]);
        assert_eq!(r[2], Vec::<String>::new());
        // Counted in local time the skipped hour is a jump: the fixed job runs once, at the
        // time it was skipped for; the wild ones don't catch up.
        let r = simulate(TABLE, &zone, Mode::Local, from, to);
        assert_eq!(r[0], ["02:30"]);
        assert_eq!(r[1], ["03:00", "04:00", "05:00"]);
        assert_eq!(r[2], Vec::<String>::new());
    }

    #[test]
    fn fall_back() {
        let zone = Zone {
            spring: MAR29 + 3600,
            fall: OCT25 + 3600,
        };
        let (from, to) = (OCT25 - 60, OCT25 + 3 * 3600);
        // UTC: 02:00-02:59 local happens twice, and so does everything in it.
        let r = simulate(TABLE, &zone, Mode::Utc, from, to);
        assert_eq!(r[0], ["02:30", "02:30"]);
        assert_eq!(r[1], ["02:00", "02:00", "03:00"]);
        assert_eq!(r[2], ["02:00", "02:20", "02:40", "02:00", "02:20", "02:40"]);
        // Local: the fixed job runs once; jobs with a `*` hour or minute keep running by the
        // clock on the wall.
        let r = simulate(TABLE, &zone, Mode::Local, from, to);
        assert_eq!(r[0], ["02:30"]);
        assert_eq!(r[1], ["02:00", "02:00", "03:00"]);
        assert_eq!(r[2], ["02:00", "02:20", "02:40", "02:00", "02:20", "02:40"]);
    }
}
