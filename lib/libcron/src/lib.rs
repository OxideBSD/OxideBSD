//! cron's tables and schedule (CRON.md in OxideBSD-doc), shared by `cron(8)` and `crontab(1)`.
//!
//! - [`table`]: the `crontab(5)` format: environment settings, job lines, their time fields and
//!   the `%` convention for a job's standard input.
//! - [`sched`]: which jobs are due at a minute, and what to run when the clock jumps (§4.5).
//!
//! Nothing here touches the system: times come in as broken-down [`Tm`]s, which `cron` makes
//! from the real clock and the tests make up.

pub mod sched;
pub mod table;

pub use sched::{Clock, Due, Mode};
pub use table::{Job, Schedule, Table, When, parse};

/// A minute of local time, broken down: all a job's time fields look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tm {
    /// 0-59.
    pub min: u32,
    /// 0-23.
    pub hour: u32,
    /// Day of the month, 1-31.
    pub mday: u32,
    /// 1-12.
    pub mon: u32,
    /// Day of the week, 0-6, Sunday 0.
    pub wday: u32,
}

impl Tm {
    /// The broken-down time of `minute` minutes since 1970-01-01 00:00, read as UTC (the
    /// proleptic Gregorian calendar, as `gmtime(3)`). With [`Mode::Local`], `cron` counts in
    /// local minutes, and this gives the local time.
    pub fn from_minutes(minute: i64) -> Tm {
        let days = minute.div_euclid(1440);
        let rem = minute.rem_euclid(1440) as u32;
        // 1970-01-01 was a Thursday.
        let wday = (days + 4).rem_euclid(7) as u32;
        let (_, mon, mday) = civil_from_days(days);
        Tm {
            min: rem % 60,
            hour: rem / 60,
            mday,
            mon,
            wday,
        }
    }
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (year, month 1-12, day 1-31).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_leap_days() {
        assert_eq!(
            Tm::from_minutes(0),
            Tm {
                min: 0,
                hour: 0,
                mday: 1,
                mon: 1,
                wday: 4
            }
        );
        // 2024-02-29 13:37 UTC, a Thursday.
        let t = 1_709_213_820 / 60;
        assert_eq!(
            Tm::from_minutes(t),
            Tm {
                min: 37,
                hour: 13,
                mday: 29,
                mon: 2,
                wday: 4
            }
        );
        // 2026-09-30 00:00, a Wednesday; the minute before is September 29th.
        let t = 1_790_726_400 / 60;
        assert_eq!(
            Tm::from_minutes(t),
            Tm {
                min: 0,
                hour: 0,
                mday: 30,
                mon: 9,
                wday: 3
            }
        );
        assert_eq!(
            Tm::from_minutes(t - 1),
            Tm {
                min: 59,
                hour: 23,
                mday: 29,
                mon: 9,
                wday: 2
            }
        );
        // Before 1970.
        assert_eq!(
            Tm::from_minutes(-1),
            Tm {
                min: 59,
                hour: 23,
                mday: 31,
                mon: 12,
                wday: 3
            }
        );
    }
}
