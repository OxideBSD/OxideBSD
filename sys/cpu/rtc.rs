//! A minimal driver for the CMOS/MC146818 real-time clock -- the standard PC wall-clock chip,
//! battery-backed and running independently of anything this kernel does. See
//! <https://wiki.osdev.org/CMOS>. Read fresh on every `CLOCK_REALTIME` request
//! (`sys/syscall.rs`'s `sys_clock_gettime`) rather than cached at boot: the chip is always there
//! and reading it is cheap, so there's no drift/staleness tradeoff to make the way there would be
//! deriving wall-clock time from `src/pit.rs`'s tick count instead.
//!
//! Known simplifications: doesn't wait out an in-progress RTC update before reading (a real read
//! landing mid-tick can be off by up to a second, extremely rare and self-correcting on the next
//! call -- not worth the standard double-read-until-stable dance for a clock nothing here needs
//! sub-second wall-clock accuracy from) and assumes the 21st century (`year` is `2000 + CMOS
//! year`, no century register read). Sub-second resolution isn't offered at all --
//! `sys_clock_gettime`'s `CLOCK_REALTIME` always reports `tv_nsec = 0`.

use x86_64::instructions::port::Port;

const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
/// Status Register B: bit 2 set means binary (not BCD) values; bit 1 set means 24-hour (not
/// 12-hour) mode.
const REG_STATUS_B: u8 = 0x0B;

fn cmos_read(register: u8) -> u8 {
    let mut index: Port<u8> = Port::new(CMOS_INDEX);
    let mut data: Port<u8> = Port::new(CMOS_DATA);
    unsafe {
        index.write(register);
        data.read()
    }
}

fn bcd_to_binary(value: u8) -> u8 {
    (value & 0x0F) + (value >> 4) * 10
}

/// The chip's current date/time as `(year, month, day, hour, minute, second)`, all in binary
/// (never raw BCD) regardless of which mode Status Register B reports.
fn read_datetime() -> (u32, u8, u8, u8, u8, u8) {
    let mut second = cmos_read(REG_SECONDS);
    let mut minute = cmos_read(REG_MINUTES);
    let mut hour = cmos_read(REG_HOURS);
    let mut day = cmos_read(REG_DAY);
    let mut month = cmos_read(REG_MONTH);
    let mut year = cmos_read(REG_YEAR);

    let status_b = cmos_read(REG_STATUS_B);
    let is_binary = status_b & 0x04 != 0;
    let is_24_hour = status_b & 0x02 != 0;

    if !is_binary {
        second = bcd_to_binary(second);
        minute = bcd_to_binary(minute);
        // The PM bit (0x80) sits alongside the BCD hour value even in 12-hour mode -- masked off
        // before converting, then folded back in below.
        hour = bcd_to_binary(hour & 0x7F) | (hour & 0x80);
        day = bcd_to_binary(day);
        month = bcd_to_binary(month);
        year = bcd_to_binary(year);
    }
    if !is_24_hour && hour & 0x80 != 0 {
        hour = ((hour & 0x7F) + 12) % 24;
    } else {
        hour &= 0x7F;
    }

    (2000 + year as u32, month, day, hour, minute, second)
}

/// Days since the Unix epoch (1970-01-01) for a given proleptic Gregorian civil date. Howard
/// Hinnant's well-known `days_from_civil` algorithm -- correct for any year representable in
/// `i64`, no leap-year branching needed.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let year_of_era = (y - era * 400) as u64;
    let month_index = (month + 10) % 12;
    let day_of_year = (153 * month_index as u64 + 2) / 5 + day as u64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era as i64 - 719_468
}

/// The RTC's current reading as a Unix epoch timestamp (seconds).
pub fn unix_epoch_seconds() -> i64 {
    let (year, month, day, hour, minute, second) = read_datetime();
    let days = days_from_civil(year as i64, month as u32, day as u32);
    days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64
}

/// Just the chip's current month (`1..=12`) -- cheap enough to read standalone (raw port I/O,
/// same as every other function here) without needing a full `unix_epoch_seconds`-style
/// timestamp. Safe to call before `crate::init` has run anything else: no heap/paging/interrupt
/// dependency, identical to `unix_epoch_seconds`'s own reasoning. The one real caller today is
/// `main.rs`'s own boot-time Pride Month greeting.
pub fn current_month() -> u8 {
    read_datetime().1
}

/// Exposed to `sys/modules/oxfs` (see `sys/module.rs`'s `resolve_external_symbol`) for real
/// `st_mtime`/`st_ctime` tracking (`write_inode_data`/`resize_inode_data`) -- a relocated module
/// can't call kernel functions directly, only through this hand-curated symbol table, the same
/// shape `oxidebsd_current_uid`/`_gid` already established for identity. Whole-second precision,
/// same tier `crate::fs::sysv_msg`'s own real `stime`/`rtime`/`ctime` already uses.
pub(crate) extern "C" fn oxidebsd_unix_time() -> i64 {
    unix_epoch_seconds()
}

/// Real, calibrated mapping between `interrupts::ticks()` and this chip's own wall-clock reading --
/// see `unix_epoch_now_precise`'s own doc comment for why a single calibration point beats reading
/// the RTC fresh on every call once real sub-second precision is needed. `spin::Mutex<Option<i64>>`,
/// not `spin::Once` -- lazily calibrated on first read same as before, but now also **re**-
/// calibrated by `set_unix_epoch` (real `clock_settime(CLOCK_REALTIME, ...)` support, see that
/// function's own doc comment), which a one-shot `Once` can't express.
static REALTIME_BASE_TICKS: spin::Mutex<Option<i64>> = spin::Mutex::new(None);

fn realtime_base_ticks() -> i64 {
    let mut guard = REALTIME_BASE_TICKS.lock();
    match *guard {
        Some(base) => base,
        None => {
            let hz = crate::cpu::pit::TIMER_HZ as i64;
            let base = unix_epoch_seconds() * hz - crate::cpu::interrupts::ticks() as i64;
            *guard = Some(base);
            base
        }
    }
}

/// Real, sub-second-precision wall-clock time, as `(tv_sec, tv_nsec)` -- unlike
/// `unix_epoch_seconds` above (kept as-is, still used by SysV IPC's own `stime`/`rtime`/`ctime`,
/// which only ever need whole seconds), this backs `CLOCK_REALTIME` in `sys_clock_gettime`, which
/// real POSIX `nanosleep(2)` conformance tests genuinely check to sub-second precision. Found
/// live: `nanosleep/1-1.c`/`2-1.c` sleep for as little as a handful of nanoseconds and then expect
/// `clock_gettime` to observe *some* elapsed time -- a fixed `tv_nsec = 0` can never show that
/// unless the RTC's own 1 Hz second boundary happens to land inside the sleep by pure luck (it
/// almost never does), so both tests failed regardless of how correct `nanosleep`'s own real sleep
/// duration was.
///
/// Calibrates a fixed `ticks() -> real seconds` offset exactly once, lazily, on first call
/// (`base = unix_epoch_seconds() * TIMER_HZ - ticks()`), then derives every later reading purely
/// from `interrupts::ticks()` against that fixed base -- the same real, `TIMER_HZ`-cadence
/// technique `CLOCK_MONOTONIC` already uses, just shifted by a real wall-clock epoch instead of
/// starting at `0`. Deliberately *not* re-reading the RTC on every call the way `unix_epoch_seconds`
/// does: mixing a fresh RTC second-boundary read with a `ticks()`-derived sub-second offset that
/// isn't phase-locked to that same boundary would make `tv_sec`/`tv_nsec` disagree with each other
/// (a real, if usually brief, backward jump every time the two disagree) -- a single calibration
/// point avoids that by construction, at the honest cost of the RTC's own already-documented
/// "doesn't wait out an in-progress update" off-by-one-second risk applying once, at calibration
/// time, rather than on every read (a real improvement, not just a wash).
pub fn unix_epoch_now_precise() -> (i64, i64) {
    let hz = crate::cpu::pit::TIMER_HZ as i64;
    let base = realtime_base_ticks();
    let total_ticks = crate::cpu::interrupts::ticks() as i64 + base;
    (total_ticks / hz, (total_ticks % hz) * 1_000_000_000 / hz)
}

/// Real `clock_settime(CLOCK_REALTIME, ...)` support -- recalibrates the base so a later
/// `unix_epoch_now_precise()` reads back `(sec, nsec)` immediately (real `clock_gettime`
/// round-trips). Closes the Open POSIX Test Suite pilot's `clock_settime/1-1.c` et al.
///
/// `PosixTimer::realtime_target` makes `interrupts::timer_interrupt_handler`'s own per-tick scan
/// compare against a live wall-clock reading instead of a tick count baked in at arm time -- a
/// real, live re-derivation rather than a cached value this function would otherwise have to hunt
/// down and shift. `process::timers::do_clock_nanosleep` is *not* similarly self-sufficient,
/// though it looks like it should be: its own recompute only runs after a blocked process already
/// wakes, which never happens on its own if this call moves the target *into the past* (nothing
/// here touches `ticks()`). The caller (`sys_clock_settime`) is responsible for the active nudge
/// that case needs -- see `process::timers::wake_realtime_sleepers_after_clock_change`'s own doc
/// comment.
pub fn set_unix_epoch(sec: i64, nsec: i64) {
    let hz = crate::cpu::pit::TIMER_HZ as i64;
    let now_ticks = crate::cpu::interrupts::ticks() as i64;
    let target_total_ticks = sec * hz + (nsec * hz) / 1_000_000_000;
    *REALTIME_BASE_TICKS.lock() = Some(target_total_ticks - now_ticks);
}
