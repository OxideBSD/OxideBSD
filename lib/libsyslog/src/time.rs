//! Local time. Only this module calls the C library: `localtime_r(3)` knows the time zone (UTC
//! until `/etc/localtime` exists, `TIMEZONE.md`), so nothing here changes when zones arrive.

use crate::msg::Stamp;

/// The current local time, to the microsecond, with its UTC offset.
pub fn now() -> Stamp {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let mut stamp = local(ts.tv_sec as i64);
    stamp.usec = Some((ts.tv_nsec / 1000) as u32);
    stamp
}

/// Seconds since the epoch, as local time (whole seconds).
pub fn local(secs: i64) -> Stamp {
    // time_t: 64 bits in musl (libc's alias for it is deprecated).
    let t: i64 = secs;
    // SAFETY: an all-zero `tm` is valid; localtime_r fills it in.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call.
    unsafe { libc::localtime_r(&t, &mut tm) };
    Stamp {
        year: Some(tm.tm_year + 1900),
        month: (tm.tm_mon + 1) as u8,
        day: tm.tm_mday as u8,
        hour: tm.tm_hour as u8,
        minute: tm.tm_min as u8,
        second: tm.tm_sec as u8,
        usec: None,
        offset: Some(tm.tm_gmtoff as i32),
    }
}

unsafe extern "C" {
    fn tzset();
}

/// Makes the next conversion read the local zone afresh (`TIMEZONE.md` §5.4: syslogd re-reads it
/// on `SIGHUP`). musl only reloads when the `TZ` string changes, so a new `/etc/localtime` link
/// goes unnoticed otherwise: `TZ` is set to something else for one `tzset(3)`, then restored.
/// Call only while the process is single-threaded (it sets environment variables).
pub fn reload_zone() {
    let saved = std::env::var_os("TZ");
    // SAFETY: the caller guarantees no other thread reads the environment.
    unsafe {
        std::env::set_var("TZ", "UTC0");
        tzset();
        match saved {
            Some(tz) => std::env::set_var("TZ", tz),
            None => std::env::remove_var("TZ"),
        }
        tzset();
    }
}

/// Seconds since the epoch.
pub fn epoch() -> i64 {
    // SAFETY: time(NULL) has no preconditions.
    unsafe { libc::time(std::ptr::null_mut()) as i64 }
}
