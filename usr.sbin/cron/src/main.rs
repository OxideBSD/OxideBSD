//! `cron(8)`: runs scheduled commands (OxideBSD-doc `CRON.md` §4), with FreeBSD's options.
//!
//! One loop: sleep to the next minute (the next second while an `@every_second` job exists),
//! reread any table that changed, and start what's due. Which minutes are due, after the clock
//! moves or jumps, is `libcron`'s [`Clock`]; each job runs in a runner process of its own
//! ([`job`]).

mod db;
mod job;

use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libcron::{Clock, Mode, Tm, When};

const PIDFILE: &str = "/var/run/cron.pid";
/// Present once `@reboot` jobs have run this boot (§4.4); `rc.d/cleanvar` empties `/var/run`.
const REBOOT_FILE: &str = "/var/run/cron.reboot";

struct Opts {
    settings: job::Settings,
    foreground: bool,
    mode: Mode,
}

fn usage() -> ExitCode {
    eprintln!("usage: cron [-j jitter] [-J rootjitter] [-m mailto] [-n] [-s] [-o]");
    ExitCode::from(1)
}

fn parse_args() -> Result<Opts, ExitCode> {
    let mut o = Opts {
        settings: job::Settings {
            jitter: 0,
            root_jitter: 0,
            mailto: None,
        },
        foreground: false,
        mode: Mode::Utc,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            return Err(usage());
        };
        let mut chars = flags.chars();
        while let Some(c) = chars.next() {
            // An option's value is the rest of the word, or the next word.
            let mut value = || {
                let rest: String = chars.by_ref().collect();
                if rest.is_empty() {
                    args.next()
                } else {
                    Some(rest)
                }
            };
            match c {
                'j' | 'J' => {
                    // FreeBSD's limit: at most a minute of delay.
                    let Some(n) = value()
                        .and_then(|v| v.parse::<u32>().ok())
                        .filter(|&n| n <= 60)
                    else {
                        eprintln!("cron: -{c}: a number of seconds from 0 to 60");
                        return Err(usage());
                    };
                    if c == 'j' {
                        o.settings.jitter = n;
                    } else {
                        o.settings.root_jitter = n;
                    }
                    break;
                }
                'm' => {
                    let Some(v) = value() else {
                        return Err(usage());
                    };
                    o.settings.mailto = Some(v);
                    break;
                }
                'n' => o.foreground = true,
                's' => o.mode = Mode::Local,
                'o' => o.mode = Mode::Utc,
                _ => return Err(usage()),
            }
        }
    }
    Ok(o)
}

/// Opens and locks the pid file, as FreeBSD's `pidfile_open(3)`: a second cron finds it locked
/// and exits.
fn lock_pidfile() -> Result<File, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .custom_flags(libc::O_CLOEXEC)
        .open(PIDFILE)
        .map_err(|e| format!("{PIDFILE}: {e}"))?;
    // SAFETY: a valid descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            let pid = std::fs::read_to_string(PIDFILE).unwrap_or_default();
            return Err(format!("already running, pid {}", pid.trim()));
        }
        return Err(format!("{PIDFILE}: {e}"));
    }
    Ok(file)
}

/// Into the background: a session of its own, `/` as its directory, standard descriptors on
/// `/dev/null`.
fn daemonize() {
    // SAFETY: single-threaded here, so fork is safe; the parent only exits.
    unsafe {
        match libc::fork() {
            -1 => {
                eprintln!("cron: fork: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            0 => {}
            _ => libc::_exit(0),
        }
        libc::setsid();
        libc::chdir(c"/".as_ptr());
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..3 {
                libc::dup2(null, fd);
            }
            if null > 2 {
                libc::close(null);
            }
        }
    }
}

fn now() -> (i64, Duration) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64, d)
}

/// `localtime(3)` of `secs`: the broken-down time and the offset from UTC.
fn localtime(secs: i64) -> (Tm, i64) {
    // SAFETY: localtime_r fills a local struct.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = secs as libc::time_t;
    unsafe { libc::localtime_r(&t, &mut tm) };
    let broken = Tm {
        min: tm.tm_min as u32,
        hour: tm.tm_hour as u32,
        mday: tm.tm_mday as u32,
        mon: tm.tm_mon as u32 + 1,
        wday: tm.tm_wday as u32,
    };
    (broken, tm.tm_gmtoff as i64)
}

/// Collects finished runners.
fn reap() {
    // SAFETY: waitpid without a status pointer.
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
}

fn load() -> db::Db {
    db::Db::load(&mut |msg| job::log(libc::LOG_ERR, msg))
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(code) => return code,
    };
    // SAFETY: umask(2) can't fail.
    unsafe { libc::umask(0o022) };
    pam::link();

    // Checked before going into the background, so that a second cron says why it exits; taken
    // again by the daemon (a lock doesn't survive the parent's exit on every system).
    match lock_pidfile() {
        Ok(f) => drop(f),
        Err(e) => {
            eprintln!("cron: {e}");
            return ExitCode::from(1);
        }
    }
    if !opts.foreground {
        daemonize();
    }
    let mut pidfile = match lock_pidfile() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cron: {e}");
            return ExitCode::from(1);
        }
    };
    let _ = pidfile.set_len(0);
    let _ = writeln!(pidfile, "{}", std::process::id());
    // SAFETY: a static identity string.
    unsafe { libc::openlog(c"cron".as_ptr(), libc::LOG_PID, libc::LOG_CRON) };
    job::log(libc::LOG_INFO, "(CRON) STARTUP");

    let mut db = load();
    if !Path::new(REBOOT_FILE).exists() {
        let _ = File::create(REBOOT_FILE);
        for e in db.entries.iter().filter(|e| e.job.when == When::Reboot) {
            job::start(e, &opts.settings);
        }
    }

    let (secs, _) = now();
    let mut clock = Clock::new(opts.mode.minute(secs, localtime(secs).1));
    let mut last_second = secs;
    loop {
        // To the start of the next second or minute.
        let (secs, exact) = now();
        let step = if db.every_second() {
            1
        } else {
            60 - secs.rem_euclid(60) as u64
        };
        let next = Duration::from_secs((secs as u64) + step);
        std::thread::sleep(next.saturating_sub(exact));

        reap();
        if db.changed() {
            db = load();
        }
        let (secs, _) = now();
        if secs != last_second {
            last_second = secs;
            for e in db
                .entries
                .iter()
                .filter(|e| e.job.when == When::EverySecond)
            {
                job::start(e, &opts.settings);
            }
        }
        let minute = opts.mode.minute(secs, localtime(secs).1);
        for due in clock.advance(minute) {
            let tm = opts.mode.tm(due.minute, |s| localtime(s).0);
            for e in &db.entries {
                if let When::At(s) = &e.job.when
                    && due.runs(s, &tm)
                {
                    job::start(e, &opts.settings);
                }
            }
        }
    }
}
