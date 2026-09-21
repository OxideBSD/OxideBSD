//! Wall-clock time and calendar formatting -- UTC only (this system has no timezone database).

use crate::syscall::syscall3;

const SYS_CLOCK_GETTIME: u64 = 138;
const CLOCK_REALTIME: u64 = 0;

/// Seconds since the Unix epoch, from `clock_gettime(CLOCK_REALTIME)`.
pub fn now() -> Result<i64, u64> {
    let mut ts = [0i64; 2]; // struct timespec { tv_sec, tv_nsec }
    unsafe {
        syscall3(SYS_CLOCK_GETTIME, CLOCK_REALTIME, ts.as_mut_ptr() as u64, 0)?;
    }
    Ok(ts[0])
}

/// A broken-down UTC time. `month` is `1..=12`.
pub struct Civil {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
}

/// Converts Unix epoch seconds to a UTC calendar time -- Howard Hinnant's `civil_from_days`, which
/// is exact for the whole proleptic Gregorian calendar (no leap-year table needed).
pub fn civil(epoch_secs: i64) -> Civil {
    let days = epoch_secs.div_euclid(86_400);
    let secs_of_day = epoch_secs.rem_euclid(86_400) as u32;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era, 0..=146096
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + (month <= 2) as i64;

    Civil {
        year,
        month,
        day,
        hour: secs_of_day / 3600,
        minute: secs_of_day % 3600 / 60,
    }
}

/// Three-letter English month abbreviation, `month` in `1..=12`. One flat byte string sliced by
/// index -- not a table of slices, which would be a static full of stored addresses (see
/// `build.rs`'s zero-relocation gate).
fn month_abbrev(month: u32) -> &'static [u8] {
    let i = (month.clamp(1, 12) - 1) as usize * 3;
    &b"JanFebMarAprMayJunJulAugSepOctNovDec"[i..i + 3]
}

/// Six months, in seconds -- `ls -l`'s own cutoff between showing a time of day and a year.
const SIX_MONTHS: i64 = 15_778_476;

/// Formats `mtime` the way `ls -l` does: `"Sep 20 19:23"` for a recent file, `"Sep  9  2001"` for
/// one more than ~six months old (or in the future). Always exactly 12 bytes.
pub fn format_ls_time(mtime: i64, now: i64, out: &mut [u8; 12]) {
    let c = civil(mtime);
    out[..3].copy_from_slice(month_abbrev(c.month));
    out[3] = b' ';
    out[4] = if c.day >= 10 {
        b'0' + (c.day / 10) as u8
    } else {
        b' '
    };
    out[5] = b'0' + (c.day % 10) as u8;
    out[6] = b' ';
    if mtime > now || now - mtime > SIX_MONTHS {
        // The year is right-aligned in the 5 columns a "HH:MM" would occupy (one leading space).
        let y = c.year.clamp(0, 9999) as u32;
        out[7] = b' ';
        out[8] = if y >= 1000 {
            b'0' + (y / 1000) as u8
        } else {
            b' '
        };
        out[9] = b'0' + (y / 100 % 10) as u8;
        out[10] = b'0' + (y / 10 % 10) as u8;
        out[11] = b'0' + (y % 10) as u8;
    } else {
        out[7] = b'0' + (c.hour / 10) as u8;
        out[8] = b'0' + (c.hour % 10) as u8;
        out[9] = b':';
        out[10] = b'0' + (c.minute / 10) as u8;
        out[11] = b'0' + (c.minute % 10) as u8;
    }
}
