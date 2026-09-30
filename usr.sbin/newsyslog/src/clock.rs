//! Local-time arithmetic for rotation times: broken-down time with the weekday, `mktime(3)`
//! that normalizes out-of-range fields (day 0 is the last day of the month before), and
//! `strftime(3)`/`strptime(3)` for time-stamped archive names. `syslog::time` has the fixed-range
//! forms; these need the C library's normalization.

use std::ffi::CString;

/// A local time, broken down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tm {
    pub year: i32,
    /// 1-12.
    pub month: i32,
    pub day: i32,
    pub hour: i32,
    pub minute: i32,
    pub second: i32,
    /// 0 is Sunday.
    pub wday: i32,
}

fn to_tm(t: i64) -> libc::tm {
    // SAFETY: an all-zero `tm` is valid; localtime_r fills it in.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    tm
}

pub fn broken(t: i64) -> Tm {
    let tm = to_tm(t);
    Tm {
        year: tm.tm_year + 1900,
        month: tm.tm_mon + 1,
        day: tm.tm_mday,
        hour: tm.tm_hour,
        minute: tm.tm_min,
        second: tm.tm_sec,
        wday: tm.tm_wday,
    }
}

/// Seconds since the epoch of a local time; fields out of range carry into the next ones.
pub fn mk(year: i32, month: i32, day: i32, hour: i32, minute: i32, second: i32) -> i64 {
    // SAFETY: an all-zero `tm` is valid.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = -1;
    // SAFETY: `tm` is valid.
    unsafe { libc::mktime(&mut tm) as i64 }
}

/// `strftime(3)` of `t` in local time.
pub fn format(fmt: &str, t: i64) -> String {
    let Ok(cfmt) = CString::new(fmt) else { return String::new() };
    let tm = to_tm(t);
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is as long as passed.
    let n = unsafe { libc::strftime(buf.as_mut_ptr().cast(), buf.len(), cfmt.as_ptr(), &tm) };
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Whether all of `s` parses with `strptime(3)` under `fmt`.
pub fn parses(fmt: &str, s: &str) -> bool {
    let (Ok(cfmt), Ok(cs)) = (CString::new(fmt), CString::new(s)) else { return false };
    // SAFETY: an all-zero `tm` is valid; strptime returns a pointer into `cs` or NULL.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(cs.as_ptr(), cfmt.as_ptr(), &mut tm) };
    // SAFETY: a non-null result points into `cs`, at or before its NUL.
    !end.is_null() && unsafe { *end } == 0
}
