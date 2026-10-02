//! `/sbin/init`'s states (INIT.md §§3, 5, 6), checked end to end by `tests/init_syscall_smoke.rs`.
//! One program in several roles, chosen by its first argument. The kernel starts it as pid 1
//! (`pid1`). It writes a test `/etc/ttys` and `/etc/rc` that run this program again (seeded as
//! `/usr/tests/init/init-smoke`), then execs the real `/sbin/init`, which keeps pid 1. Every role
//! appends to `LOG`, and the last one reads it back and reports to the kernel.
//!
//! 1. `rc autoboot` fails, so init goes to single-user. A `killer` it leaves behind ends that
//!    shell; init runs `/etc/rc` again, this time without `autoboot`, and it succeeds.
//! 2. multi-user starts `session ttyv0`, which adds a `ttyx0` entry and sends `SIGHUP`.
//! 3. `second ttyx0` exits at once three times; init must pause it about 30 seconds before the
//!    fourth start. That one sends `SIGTERM`, leaving a killer behind again.
//! 4. clean-ttys hangs up both sessions, and the killer ends the single-user shell. Init goes back
//!    to multi-user without running `/etc/rc`, and the new `session` checks the log.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SYS_TEST_EXIT: libc::c_long = 9999;
const SELF: &str = "/usr/tests/init/init-smoke";
const LOG: &str = "/var/run/init-smoke.log";
/// init's `PATH` for its children (INIT.md §4.2).
const INIT_PATH: &str = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";

fn finish(pass: bool, why: &str) -> ! {
    println!("init-smoke: {} {why}", if pass { "PASS" } else { "FAIL" });
    if let Ok(log) = std::fs::read_to_string(LOG) {
        for line in log.lines() {
            println!("init-smoke: log: {line}");
        }
    }
    unsafe { libc::syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }) };
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn check(ok: bool, why: &str) {
    if !ok {
        finish(false, why);
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

fn log(line: &str) {
    println!("init-smoke: {line}");
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(LOG).unwrap_or_else(|e| finish(false, &format!("{LOG}: {e}")));
    let _ = writeln!(f, "{line}");
}

fn lines() -> Vec<String> {
    std::fs::read_to_string(LOG).unwrap_or_default().lines().map(String::from).collect()
}

fn count(word: &str) -> usize {
    lines().iter().filter(|l| l.split_whitespace().next() == Some(word)).count()
}

fn write(path: &str, text: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, text).unwrap_or_else(|e| finish(false, &format!("{path}: {e}")));
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

fn ttys(second: bool) -> String {
    let mut t = String::from("console\tnone\tunknown\toff\tsecure\n");
    t += &format!("ttyv0\t\"{SELF} session\"\tlinux\ton\tsecure\n");
    if second {
        t += &format!("ttyx0\t\"{SELF} second\"\tvt100\ton\tsecure\n");
    }
    t
}

/// Leaves behind a process of its own session that ends the next single-user shell.
fn spawn_killer(tag: &str) {
    let mut cmd = Command::new(SELF);
    cmd.args(["killer", tag, &std::process::id().to_string(), &unsafe { libc::getppid() }.to_string()]);
    // SAFETY: setsid between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        })
    };
    cmd.spawn().unwrap_or_else(|e| finish(false, &format!("killer: {e}")));
}

static HUNG_UP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hup(_: libc::c_int) {
    HUNG_UP.store(true, Ordering::Relaxed);
}

/// Waits for init to hang the session up, then logs it and exits.
fn wait_for_hangup(who: &str) -> ! {
    // SAFETY: a handler that only stores to an atomic.
    unsafe { libc::signal(libc::SIGHUP, on_hup as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    loop {
        if HUNG_UP.load(Ordering::Relaxed) {
            log(&format!("hup {who}"));
            std::process::exit(0);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `/proc/<pid>/stat`'s fields after the command name: state, ppid, pgrp, session, tty_nr.
fn stat(pid: i32) -> Option<(String, Vec<i64>)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (open, close) = (s.find('(')?, s.rfind(')')?);
    let comm = s[open + 1..close].to_string();
    let f = s[close + 1..].split_whitespace().skip(1).take(4).filter_map(|v| v.parse().ok()).collect();
    Some((comm, f))
}

/// The single-user shell: a session leader, child of pid 1, holding the console. Not the rc
/// process (`exclude`), which held the console before it.
fn find_single_user_shell(console_rdev: i64, exclude: &[i32]) -> Option<i32> {
    for e in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
        if exclude.contains(&pid) {
            continue;
        }
        if let Some((comm, f)) = stat(pid)
            && f.len() == 4
            && f[0] == 1
            && f[2] == pid as i64
            && f[3] == console_rdev
            && comm.ends_with("sh")
        {
            return Some(pid);
        }
    }
    None
}

fn killer(tag: &str, exclude: &[i32]) -> ! {
    use std::os::unix::fs::MetadataExt;
    let rdev = std::fs::metadata("/dev/ttyv0").map(|m| m.rdev() as i64).unwrap_or_else(|e| finish(false, &format!("/dev/ttyv0: {e}")));
    let until = Instant::now() + Duration::from_secs(30);
    while Instant::now() < until {
        if let Some(pid) = find_single_user_shell(rdev, exclude) {
            std::thread::sleep(Duration::from_millis(500));
            log(&format!("killed {tag} {pid}"));
            unsafe { libc::kill(pid, libc::SIGKILL) };
            std::process::exit(0);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    finish(false, &format!("killer {tag}: no single-user shell on the console"));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str).unwrap_or("");
    let arg = args.get(2).cloned();
    let pid = std::process::id() as i32;
    let ppid = unsafe { libc::getppid() };
    match role {
        "pid1" => {
            check(pid == 1, "not started as pid 1");
            let _ = std::fs::create_dir_all("/var/run");
            let _ = std::fs::remove_file(LOG);
            write("/etc/ttys", &ttys(false), 0o644);
            write("/etc/rc", &format!("#!/sbin/init_sh\n{SELF} rc \"$@\"\n"), 0o644);
            log("pid1");
            let err = Command::new("/sbin/init").exec();
            finish(false, &format!("exec /sbin/init: {err}"));
        }
        "rc" => {
            let n = count("rc");
            log(&format!("rc {}", arg.as_deref().unwrap_or("-")));
            match n {
                0 => {
                    check(arg.as_deref() == Some("autoboot"), "the first /etc/rc didn't get `autoboot'");
                    spawn_killer("rc-failed");
                    std::process::exit(1);
                }
                1 => {
                    check(arg.is_none(), "/etc/rc after single-user got an argument");
                    check(count("killed") == 1, "a failed /etc/rc didn't lead to a single-user shell");
                    std::process::exit(0);
                }
                _ => finish(false, "/etc/rc ran a third time: single-user after clean-ttys must go back to multi-user"),
            }
        }
        "killer" => {
            let exclude: Vec<i32> = args[3..].iter().filter_map(|a| a.parse().ok()).collect();
            killer(arg.as_deref().unwrap_or("?"), &exclude);
        }
        "session" => {
            let n = count("session");
            log(&format!("session {pid}"));
            check(arg.as_deref() == Some("ttyv0"), "getty wasn't given its terminal's name");
            check(std::env::var("TERM").as_deref() == Ok("linux"), "TERM isn't the ttys(5) type");
            check(std::env::var("PATH").as_deref() == Ok(INIT_PATH), "PATH isn't init's");
            check(ppid == 1 && pid != 1, "the session isn't a child of pid 1");
            if n == 0 {
                check(count("rc") == 2, "multi-user before /etc/rc succeeded");
                write("/etc/ttys", &ttys(true), 0o644);
                unsafe { libc::kill(1, libc::SIGHUP) };
                wait_for_hangup("session");
            }
            // Back in multi-user after clean-ttys and single-user.
            check(count("killed") == 2, "multi-user again without the second single-user shell");
            check(count("rc") == 2, "/etc/rc ran again");
            check(lines().iter().any(|l| l == "hup session"), "clean-ttys didn't hang up the ttyv0 session");
            check(lines().iter().any(|l| l == "hup second"), "clean-ttys didn't hang up the ttyx0 session");
            check(lines().iter().any(|l| l == "paused ok"), "no pause before the fourth start");
            finish(true, "init's states, ttys, restart limit and signals");
        }
        "second" => {
            let starts: Vec<u128> = lines()
                .iter()
                .filter_map(|l| l.strip_prefix("second ").and_then(|t| t.parse().ok()))
                .collect();
            let t = now_ms();
            log(&format!("second {t}"));
            check(arg.as_deref() == Some("ttyx0"), "the new entry wasn't given its name");
            check(std::env::var("TERM").as_deref() == Ok("vt100"), "TERM isn't the new entry's type");
            match starts.len() {
                0..=2 => std::process::exit(0),
                3 => {
                    let gap = t - starts[2];
                    check(gap >= 25_000, &format!("restarted {gap} ms after three quick exits"));
                    log("paused ok");
                    spawn_killer("clean-ttys");
                    unsafe { libc::kill(1, libc::SIGTERM) };
                    wait_for_hangup("second");
                }
                _ => wait_for_hangup("second-again"),
            }
        }
        _ => finish(false, &format!("unknown role `{role}'")),
    }
}
