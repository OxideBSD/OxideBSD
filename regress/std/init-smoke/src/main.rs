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
//!    to multi-user without running `/etc/rc`, and the new `session` checks the log, and the
//!    utmpx records: one `BOOT_TIME`, and the login record the first session left open (as a
//!    killed login(1) would) closed by init.
//! 5. That session takes `ttyv0` as its controlling terminal, as getty does, adds an enabled
//!    `rc.d` service with `KEYWORD: shutdown` that isn't running (`smoked`, this program as a
//!    `daemon`), and kills init with `debug.kill_init`. The kernel restarts init with `-R`, which
//!    must start `smoked` and keep the session rather than start another on `ttyv0`.

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

/// A login record for `line`, as login(1) writes one, which this session never closes.
#[allow(deprecated)]
fn record_login(line: &str) {
    let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
    ut.ut_type = libc::USER_PROCESS;
    ut.ut_pid = std::process::id() as libc::pid_t;
    for (d, b) in ut.ut_line.iter_mut().zip(line.bytes()) {
        *d = b as libc::c_char;
    }
    for (d, b) in ut.ut_id.iter_mut().zip(line.trim_start_matches("tty").bytes()) {
        *d = b as libc::c_char;
    }
    for (d, b) in ut.ut_user.iter_mut().zip("smoke".bytes()) {
        *d = b as libc::c_char;
    }
    unsafe {
        libc::setutxent();
        check(!libc::pututxline(&ut).is_null(), "pututxline failed");
        libc::endutxent();
    }
}

/// Every record in `/var/run/utmpx`: (type, line).
#[allow(deprecated)]
fn utmpx_records() -> Vec<(libc::c_short, String)> {
    let mut out = Vec::new();
    unsafe {
        libc::setutxent();
        loop {
            let e = libc::getutxent();
            if e.is_null() {
                break;
            }
            let line: String = (*e).ut_line.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
            out.push(((*e).ut_type, line));
        }
        libc::endutxent();
    }
    out
}

unsafe extern "C" {
    fn sysctlbyname(
        name: *const libc::c_char,
        oldp: *mut libc::c_void,
        oldlenp: *mut libc::size_t,
        newp: *const libc::c_void,
        newlen: libc::size_t,
    ) -> libc::c_int;
}

/// Makes `/dev/<tty>` this process's controlling terminal, in a session of its own, as getty does.
fn take_terminal(tty: &str) {
    let path = std::ffi::CString::new(format!("/dev/{tty}")).unwrap();
    unsafe {
        check(libc::setsid() > 0, "setsid failed");
        let fd = libc::open(path.as_ptr(), libc::O_RDWR);
        check(fd >= 0, &format!("/dev/{tty}: {}", std::io::Error::last_os_error()));
        check(libc::ioctl(fd, libc::TIOCSCTTY, 0) == 0, &format!("TIOCSCTTY on {tty}: {}", std::io::Error::last_os_error()));
    }
}

const SMOKED: &str = "#!/sbin/init_sh
#
# PROVIDE: smoked
# REQUIRE: FILESYSTEMS
# KEYWORD: shutdown
#
# init-smoke's daemon, for init's recovery mode (INIT.md section 9.3).

. /etc/rc.subr

name=\"smoked\"
rcvar=\"smoked_enable\"
command=\"/usr/tests/init/init-smoke\"
command_args=\"daemon\"
pidfile=\"/var/run/smoked.pid\"

load_rc_config $name
run_rc_command \"$1\"
";

/// Step 5: sets up a stopped service and kills init; the restarted init must start the service
/// and keep this session.
fn recovery() -> ! {
    take_terminal("ttyv0");
    // Only smoked is checked: the real daemons with `KEYWORD: shutdown` are turned off.
    write("/etc/rc.conf", "cron_enable=\"NO\"\nsyslogd_enable=\"NO\"\nsmoked_enable=\"YES\"\n", 0o644);
    write("/etc/rc.d/smoked", SMOKED, 0o755);
    log("killing init");
    let sig: libc::c_int = libc::SIGKILL;
    let r = unsafe {
        sysctlbyname(
            c"debug.kill_init".as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            (&sig as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>(),
        )
    };
    check(r == 0, &format!("debug.kill_init: {}", std::io::Error::last_os_error()));
    let until = Instant::now() + Duration::from_secs(30);
    while count("daemon") == 0 {
        check(Instant::now() < until, "the restarted init didn't start smoked");
        std::thread::sleep(Duration::from_millis(200));
    }
    // Long enough for a restarted init that didn't keep this session to have started another.
    std::thread::sleep(Duration::from_secs(3));
    check(count("session") == 2, "the restarted init started a second session on ttyv0");
    check(unsafe { libc::getppid() } == 1, "the session wasn't reparented to the new init");
    let deaths = std::fs::read_to_string("/proc/initdeaths").unwrap_or_default();
    check(deaths.lines().count() == 1 && deaths.contains(" signal 9"), &format!("/proc/initdeaths: {deaths:?}"));
    finish(true, "init's states, ttys, restart limit, signals, utmpx and recovery");
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

/// `tests/init_path_smoke.rs`: the kernel was told `init=/nonexistent/init
/// init_path=/usr/tests/init/init-smoke`, so its `start_init` must have skipped the first and
/// exec'd this as pid 1, with no arguments. The first run kills itself through `debug.kill_init`;
/// the restart must come the same way, still without `-R` (only `/sbin/init` gets it).
fn started_by_start_init(args: &[String]) -> ! {
    check(std::process::id() == 1, "not pid 1");
    check(args.len() == 1, &format!("arguments {args:?}: -R is only for /sbin/init"));
    check(std::env::var("PATH").is_ok(), "the kernel's environment wasn't passed on");
    let _ = std::fs::create_dir_all("/var/run");
    let deaths = std::fs::read_to_string("/proc/initdeaths").unwrap_or_default();
    if count("start_init") == 0 {
        check(deaths.is_empty(), &format!("/proc/initdeaths: {deaths:?}"));
        log("start_init 1");
        let sig: libc::c_int = libc::SIGKILL;
        let r = unsafe {
            sysctlbyname(
                c"debug.kill_init".as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                (&sig as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>(),
            )
        };
        finish(false, &format!("debug.kill_init returned {r}: {}", std::io::Error::last_os_error()));
    }
    check(deaths.lines().count() == 1 && deaths.contains(" signal 9"), &format!("/proc/initdeaths: {deaths:?}"));
    finish(true, "start_init ran init_path's program, and again after a death, without -R");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 && args[0] == SELF {
        started_by_start_init(&args);
    }
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
                record_login("ttyv0");
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
            let records = utmpx_records();
            check(records.iter().any(|r| r.0 == libc::BOOT_TIME), "no BOOT_TIME record in /var/run/utmpx");
            // wtmpx is history: whole records, appended. /etc/rc succeeded once, so one boot.
            let wtmpx = std::fs::read("/var/log/wtmpx").unwrap_or_default();
            let size = std::mem::size_of::<libc::utmpx>();
            check(wtmpx.len() % size == 0, "/var/log/wtmpx holds a partial record");
            let boots = wtmpx.chunks(size).filter(|r| i16::from_ne_bytes([r[0], r[1]]) == libc::BOOT_TIME).count();
            check(boots == 1, &format!("{boots} BOOT_TIME records in /var/log/wtmpx, not 1"));
            check(
                records.iter().any(|r| r.0 == libc::DEAD_PROCESS && r.1 == "ttyv0"),
                "the hung-up ttyv0 login wasn't closed with DEAD_PROCESS",
            );
            check(
                !records.iter().any(|r| r.0 == libc::USER_PROCESS && r.1 == "ttyv0"),
                "a USER_PROCESS record is left for ttyv0",
            );

            recovery();
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
        "daemon" => {
            // rc.subr's start waits for the command, so a daemon detaches.
            match unsafe { libc::fork() } {
                0 => {
                    unsafe { libc::setsid() };
                    let me = std::process::id();
                    write("/var/run/smoked.pid", &format!("{me}\n"), 0o644);
                    log(&format!("daemon {me}"));
                    loop {
                        std::thread::sleep(Duration::from_secs(60));
                    }
                }
                -1 => finish(false, "fork failed"),
                _ => std::process::exit(0),
            }
        }
        _ => finish(false, &format!("unknown role `{role}'")),
    }
}
