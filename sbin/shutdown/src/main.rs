//! `shutdown(8)`: takes the system down at a given time, warning its users beforehand.
//!
//! ```text
//! shutdown [-] [-h | -p | -r | -k] [-o [-n]] time [warning-message ...]
//! shutdown -C
//! ```
//!
//! `time` is `now`, `+minutes`, `hh:mm`, or `[[[[[cc]yy]mm]dd]hh]mm`. Until then, shutdown waits
//! in the background (its pid recorded in `/var/run/shutdown.pid`), printing warnings to the
//! console on FreeBSD's schedule and creating `/etc/nologin` five minutes beforehand. At the
//! time, it signals init (INIT.md §6): `-r` reboot, `-h` halt, `-p` power off, and with none of
//! them, single-user mode. `-o` runs `reboot -q` itself instead of asking init, `-n` (with `-o`)
//! skips synchronizing storage, and `-k` only warns and blocks logins. `-C` cancels a pending
//! shutdown -- `-c` stays free for FreeBSD's power cycle, which OxideBSD can't do yet.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

const PIDFILE: &str = "/var/run/shutdown.pid";
const NOLOGIN: &str = "/etc/nologin";
/// How long before the deadline logins are refused.
const NOLOGIN_LEAD: i64 = 5 * 60;
/// Seconds before the deadline at which the console is warned (FreeBSD's schedule).
const WARNINGS: &[i64] = &[10 * 3600, 5 * 3600, 2 * 3600, 3600, 45 * 60, 30 * 60, 20 * 60, 15 * 60, 10 * 60, 5 * 60, 3 * 60, 2 * 60, 60, 30];
const USAGE: &str = "usage: shutdown [-] [-h | -p | -r | -k] [-o [-n]] time [warning-message ...]\n       shutdown -C";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Action {
    SingleUser,
    Reboot,
    Halt,
    PowerOff,
    /// `-k`: warn and refuse logins, but don't actually shut down.
    Kick,
}

#[derive(Debug, PartialEq)]
enum Request {
    Cancel,
    Shutdown { action: Action, run_reboot: bool, nosync: bool, time: String, message: String, message_from_stdin: bool },
}

static CANCELED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_cancel(_: libc::c_int) {
    CANCELED.store(true, Ordering::SeqCst);
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("shutdown: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn parse_args(args: &[String]) -> Result<Request, String> {
    let mut action = None;
    let (mut run_reboot, mut nosync, mut message_from_stdin, mut cancel) = (false, false, false, false);
    let mut rest = args;
    while let Some(arg) = rest.first().filter(|a| a.starts_with('-')) {
        rest = &rest[1..];
        if arg == "-" {
            message_from_stdin = true;
            continue;
        }
        if arg == "--" {
            break;
        }
        for c in arg[1..].chars() {
            let chosen = match c {
                'h' => Action::Halt,
                'p' => Action::PowerOff,
                'r' => Action::Reboot,
                'k' => Action::Kick,
                'o' => {
                    run_reboot = true;
                    continue;
                }
                'n' => {
                    nosync = true;
                    continue;
                }
                'C' => {
                    cancel = true;
                    continue;
                }
                'c' => return Err("power cycling is not supported".into()),
                _ => return Err(format!("illegal option -- {c}\n{USAGE}")),
            };
            if action.is_some_and(|a| a != chosen) {
                return Err(format!("only one of -h, -p, -r and -k may be given\n{USAGE}"));
            }
            action = Some(chosen);
        }
    }
    if cancel {
        return if action.is_none() && !run_reboot && !nosync && !message_from_stdin && rest.is_empty() {
            Ok(Request::Cancel)
        } else {
            Err(format!("-C takes no other arguments\n{USAGE}"))
        };
    }
    let action = action.unwrap_or(Action::SingleUser);
    if nosync && !run_reboot {
        return Err("-n requires -o".into());
    }
    if run_reboot && !matches!(action, Action::Reboot | Action::Halt | Action::PowerOff) {
        return Err("-o requires -h, -p or -r".into());
    }
    let Some((time, words)) = rest.split_first() else {
        return Err(USAGE.into());
    };
    Ok(Request::Shutdown { action, run_reboot, nosync, time: time.clone(), message: words.join(" "), message_from_stdin })
}

fn local_tm(t: i64) -> libc::tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    tm
}

/// The deadline `arg` names, in seconds since the epoch, given the current time.
fn parse_time(arg: &str, now: i64) -> Result<i64, String> {
    let bad = || format!("bad time format: {arg}");
    if arg == "now" {
        return Ok(now);
    }
    if let Some(minutes) = arg.strip_prefix('+') {
        let m: i64 = minutes.parse().ok().filter(|m| *m >= 0).ok_or_else(bad)?;
        return Ok(now + m * 60);
    }
    let digits: String = match arg.split_once(':') {
        Some((h, m)) if h.len() <= 2 && m.len() == 2 => format!("{h:0>2}{m}"),
        Some(_) => return Err(bad()),
        None => arg.into(),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) || !matches!(digits.len(), 4 | 6 | 8 | 10 | 12) {
        return Err(bad());
    }
    // Fields from the right: mm, hh, then optionally dd, mm, yy, cc.
    let mut fields: Vec<i32> = digits.as_bytes().rchunks(2).map(|p| ((p[0] - b'0') * 10 + p[1] - b'0') as i32).collect();
    fields.resize(6, -1);
    let [min, hour, day, month, yy, cc] = fields[..] else { unreachable!() };
    let mut tm = local_tm(now);
    tm.tm_sec = 0;
    tm.tm_min = min;
    tm.tm_hour = hour;
    if day >= 0 {
        tm.tm_mday = day;
    }
    if month >= 0 {
        tm.tm_mon = month - 1;
    }
    if yy >= 0 {
        let century = if cc >= 0 { cc } else if yy < 69 { 20 } else { 19 };
        tm.tm_year = century * 100 + yy - 1900;
    }
    if min > 59 || hour > 23 || !(1..=31).contains(&tm.tm_mday) || !(0..=11).contains(&tm.tm_mon) {
        return Err(bad());
    }
    tm.tm_isdst = -1;
    let t = unsafe { libc::mktime(&mut tm) };
    if t < now {
        return Err("that time is already past".into());
    }
    Ok(t)
}

fn now() -> i64 {
    unsafe { libc::time(std::ptr::null_mut()) }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn hhmm(t: i64) -> String {
    let tm = local_tm(t);
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

/// Writes to the console, or to standard error if it can't be opened.
fn console(text: &str) {
    match std::fs::OpenOptions::new().write(true).open("/dev/console") {
        Ok(mut c) => _ = c.write_all(text.as_bytes()),
        Err(_) => _ = std::io::stderr().write_all(text.as_bytes()),
    }
}

fn warn(host: &str, deadline: i64, message: &str) {
    let left = deadline - now();
    let when = match left {
        ..=0 => "IMMEDIATELY".to_string(),
        1..60 => format!("in {left} seconds"),
        60..3600 => {
            let m = (left + 30) / 60;
            format!("in {m} minute{}", if m == 1 { "" } else { "s" })
        }
        _ => format!("at {}", hhmm(deadline)),
    };
    let last = if left <= 30 { "FINAL " } else { "" };
    let body = if message.is_empty() { String::new() } else { format!("\n{message}\n") };
    console(&format!("\n*** {last}System shutdown message from root@{host} ***\nSystem going down {when}\n{body}\n"));
}

fn nologin(deadline: i64, message: &str) {
    let _ = std::fs::write(NOLOGIN, format!("\n\nNO LOGINS: System going down at {}\n\n{message}\n", hhmm(deadline)));
}

/// Sleeps until `t`; false if the shutdown was canceled first.
fn sleep_until(t: i64) -> bool {
    loop {
        if CANCELED.load(Ordering::SeqCst) {
            return false;
        }
        let left = t - now();
        if left <= 0 {
            return true;
        }
        // Short naps, so a changed clock or a signal is noticed; nanosleep returns early on a
        // signal, where std::thread::sleep would carry on.
        let ts = libc::timespec { tv_sec: left.min(10), tv_nsec: 0 };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    }
}

/// The pid in the pidfile, if that process still exists.
fn pending() -> Option<libc::pid_t> {
    let pid: libc::pid_t = std::fs::read_to_string(PIDFILE).ok()?.trim().parse().ok()?;
    let alive = unsafe { libc::kill(pid, 0) } == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    alive.then_some(pid)
}

fn cancel() -> Result<(), String> {
    let Some(pid) = pending() else {
        let _ = std::fs::remove_file(PIDFILE);
        return Err("no shutdown is pending".into());
    };
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(format!("{pid}: {}", std::io::Error::last_os_error()));
    }
    println!("shutdown: pending shutdown (pid {pid}) canceled");
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (action, run_reboot, nosync, time, mut message, message_from_stdin) = match parse_args(&args)? {
        Request::Cancel => return cancel(),
        Request::Shutdown { action, run_reboot, nosync, time, message, message_from_stdin } => {
            (action, run_reboot, nosync, time, message, message_from_stdin)
        }
    };
    if unsafe { libc::geteuid() } != 0 {
        return Err("NOT super-user".into());
    }
    if let Some(pid) = pending() {
        return Err(format!("a shutdown is already pending (pid {pid}); cancel it with shutdown -C"));
    }
    let deadline = parse_time(&time, now())?;
    if message_from_stdin {
        let mut more = String::new();
        let _ = std::io::stdin().read_to_string(&mut more);
        message = [message, more.trim_end().to_string()].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join("\n");
    }
    let host = hostname();

    if deadline > now() {
        // Wait in the background, in a session of its own so a closing terminal doesn't end it.
        match unsafe { libc::fork() } {
            -1 => return Err(format!("fork: {}", std::io::Error::last_os_error())),
            0 => {
                unsafe { libc::setsid() };
            }
            pid => {
                println!("shutdown: [pid {pid}]");
                return Ok(());
            }
        }
        let _ = std::fs::create_dir_all("/var/run");
        let _ = std::fs::write(PIDFILE, format!("{}\n", std::process::id()));
    }
    unsafe {
        libc::signal(libc::SIGINT, on_cancel as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_cancel as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let start_left = deadline - now();
    warn(&host, deadline, &message);
    let mut blocked_logins = false;
    for &w in WARNINGS.iter().filter(|&&w| w < start_left) {
        if w <= NOLOGIN_LEAD && !blocked_logins {
            if !sleep_until(deadline - NOLOGIN_LEAD.max(w)) {
                return canceled(blocked_logins);
            }
            nologin(deadline, &message);
            blocked_logins = true;
        }
        if !sleep_until(deadline - w) {
            return canceled(blocked_logins);
        }
        warn(&host, deadline, &message);
    }
    if !blocked_logins {
        nologin(deadline, &message);
        blocked_logins = true;
    }
    if !sleep_until(deadline) {
        return canceled(blocked_logins);
    }
    let _ = std::fs::remove_file(PIDFILE);

    if action == Action::Kick {
        console("\nSystem shutdown time has arrived; logins stay disabled, but the system is not going down (-k).\n");
        return Ok(());
    }
    console("\nSystem shutdown time has arrived\n");
    if run_reboot {
        let name = match action {
            Action::Halt => "halt",
            Action::PowerOff => "poweroff",
            _ => "reboot",
        };
        let err = std::process::Command::new("/sbin/reboot").arg0(name).arg(if nosync { "-qn" } else { "-q" }).exec();
        return Err(format!("/sbin/reboot: {err}"));
    }
    let sig = match action {
        Action::Reboot => libc::SIGINT,
        Action::Halt => libc::SIGUSR1,
        Action::PowerOff => libc::SIGUSR2,
        _ => libc::SIGTERM,
    };
    if unsafe { libc::kill(1, sig) } != 0 {
        return Err(format!("can't signal init: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn canceled(blocked_logins: bool) -> Result<(), String> {
    if blocked_logins {
        let _ = std::fs::remove_file(NOLOGIN);
    }
    let _ = std::fs::remove_file(PIDFILE);
    console("\n*** System shutdown canceled ***\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    fn at(year: i32, mon: i32, day: i32, hour: i32, min: i32) -> i64 {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        (tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_isdst) = (year - 1900, mon - 1, day, hour, min, -1);
        unsafe { libc::mktime(&mut tm) }
    }

    #[test]
    fn arguments() {
        let r = parse_args(&args("-r +5 back soon")).unwrap();
        assert_eq!(
            r,
            Request::Shutdown { action: Action::Reboot, run_reboot: false, nosync: false, time: "+5".into(), message: "back soon".into(), message_from_stdin: false }
        );
        assert!(matches!(parse_args(&args("now")).unwrap(), Request::Shutdown { action: Action::SingleUser, .. }));
        assert!(matches!(parse_args(&args("-po -n now")).unwrap(), Request::Shutdown { action: Action::PowerOff, run_reboot: true, nosync: true, .. }));
        assert!(matches!(parse_args(&args("- -k now")).unwrap(), Request::Shutdown { action: Action::Kick, message_from_stdin: true, .. }));
        assert_eq!(parse_args(&args("-C")).unwrap(), Request::Cancel);
        assert!(parse_args(&args("-C now")).is_err());
        assert!(parse_args(&args("-rh now")).unwrap_err().contains("only one"));
        assert!(parse_args(&args("-c now")).unwrap_err().contains("power cycling"));
        assert!(parse_args(&args("-n -r now")).unwrap_err().contains("requires -o"));
        assert!(parse_args(&args("-o now")).unwrap_err().contains("-o requires"));
        assert!(parse_args(&args("-r")).is_err());
    }

    #[test]
    fn times() {
        let now = at(2026, 9, 25, 12, 0);
        assert_eq!(parse_time("now", now), Ok(now));
        assert_eq!(parse_time("+15", now), Ok(now + 900));
        assert_eq!(parse_time("1330", now), Ok(at(2026, 9, 25, 13, 30)));
        assert_eq!(parse_time("13:30", now), Ok(at(2026, 9, 25, 13, 30)));
        assert_eq!(parse_time("260930", now), Ok(at(2026, 9, 26, 9, 30)));
        assert_eq!(parse_time("10260930", now), Ok(at(2026, 10, 26, 9, 30)));
        assert_eq!(parse_time("2701010000", now), Ok(at(2027, 1, 1, 0, 0)));
        assert_eq!(parse_time("202701010000", now), Ok(at(2027, 1, 1, 0, 0)));
        assert_eq!(parse_time("1130", now), Err("that time is already past".into()));
        for bad in ["+x", "+-1", "13:3", "133", "1360", "2500", "ab:cd", "261399", "1500000000"] {
            assert!(parse_time(bad, now).unwrap_err().starts_with("bad time format"), "{bad}");
        }
    }
}
