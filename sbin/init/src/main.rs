//! `/sbin/init`, process 1 (INIT.md in OxideBSD-doc): the state machine of §3.
//!
//! - `single-user` runs a root shell on the console (asking for root's password first when
//!   `/etc/ttys` marks the console `insecure`, §5.4).
//! - `runcom` runs `/etc/rc`; a failure drops to `single-user`.
//! - `multi-user` runs and supervises the sessions `/etc/ttys` lists (normally getty), restarting
//!   each when it exits, with FreeBSD's limit on one that keeps dying (§5).
//! - `clean-ttys` (`SIGTERM`) ends every session and goes to `single-user`. Services keep
//!   running, so when that shell exits init goes back to `multi-user` without running `/etc/rc`.
//! - A restart by the kernel after a death (`-R`, §9.3) is recovery: it says why init died,
//!   starts the services `/etc/rc.shutdown` would stop that aren't running, keeps the sessions the
//!   old init left running and starts the missing ones.
//!
//! `SIGINT`, `SIGUSR1` and `SIGUSR2` (reboot, halt, power off, §6) shut the system down from any
//! state as §10 says: `/etc/rc.shutdown`, then `SIGTERM` and `SIGKILL` to everything, `sync`, and
//! `reboot(2)`. `SIGHUP` re-reads `/etc/ttys`; `SIGTSTP` stops new sessions from starting.
//!
//! Like the BSDs' init it has no controlling terminal (the kernel starts it without one): each
//! session is its own, so the keyboard's signals reach the session and never init.

use std::collections::VecDeque;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

const CONSOLE: &CStr = c"/dev/console";
/// The terminal `/dev/console` is, for ttys(5)'s `onifconsole`.
const CONSOLE_TTY: &str = "ttyv0";
/// INIT.md §4.2.
const PATH: &str = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";
/// The single-user shell's prompt (login shells get theirs from `/etc/profile`).
const PS1: &str = "\\[\\e[1;32m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ ";
/// §10.2's default for `rcshutdown_timeout`.
const RCSHUTDOWN_TIMEOUT: Duration = Duration::from_secs(90);
/// §10.3.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// How long a hung-up session gets to exit before it is killed.
const HANGUP_GRACE: Duration = Duration::from_secs(2);
/// FreeBSD's restart limit for a terminal session (§5.3): this many exits within
/// `RESPAWN_WINDOW` of starting pause the entry for `RESPAWN_PAUSE`.
const RESPAWN_LIMIT: usize = 3;
const RESPAWN_WINDOW: Duration = Duration::from_secs(5);
const RESPAWN_PAUSE: Duration = Duration::from_secs(30);

/// A shutdown request: the signal that asked for it, or 0.
static REQUEST: AtomicI32 = AtomicI32::new(0);
static GOT_HUP: AtomicBool = AtomicBool::new(false);
static GOT_TERM: AtomicBool = AtomicBool::new(false);
static GOT_TSTP: AtomicBool = AtomicBool::new(false);
/// Leaders of the sessions init started and is responsible for: hung up at shutdown.
static LEADERS: Mutex<Vec<libc::pid_t>> = Mutex::new(Vec::new());

extern "C" fn on_signal(sig: libc::c_int) {
    match sig {
        libc::SIGHUP => GOT_HUP.store(true, Ordering::Relaxed),
        libc::SIGTERM => GOT_TERM.store(true, Ordering::Relaxed),
        libc::SIGTSTP => GOT_TSTP.store(true, Ordering::Relaxed),
        libc::SIGCHLD => {}
        _ => REQUEST.store(sig, Ordering::Relaxed),
    }
}

/// Opens init's log as FreeBSD's init does (`LOG_AUTH`), with `LOG_CONS`: until syslogd is
/// running, its messages go to the console (SYSLOG.md §5.2).
fn open_log() {
    // SAFETY: openlog keeps the pointer to a static string.
    unsafe { libc::openlog(c"init".as_ptr(), libc::LOG_CONS, libc::LOG_AUTH) };
}

fn log(priority: libc::c_int, msg: &str) {
    let Ok(msg) = CString::new(msg) else { return };
    // SAFETY: a constant format and a NUL-terminated argument.
    unsafe { libc::syslog(priority, c"%s".as_ptr(), msg.as_ptr()) };
}

/// A state change or other news, which `syslog.conf`'s `auth.notice` puts on the console.
fn say(msg: &str) {
    log(libc::LOG_NOTICE, msg);
}

/// Something that went wrong.
fn complain(msg: &str) {
    log(libc::LOG_ERR, msg);
}

fn signal_set(sigs: &[libc::c_int]) -> libc::sigset_t {
    // SAFETY: sigemptyset/sigaddset initialize and fill a local set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &s in sigs {
            libc::sigaddset(&mut set, s);
        }
        set
    }
}

const HANDLED: [libc::c_int; 7] =
    [libc::SIGINT, libc::SIGUSR1, libc::SIGUSR2, libc::SIGHUP, libc::SIGTERM, libc::SIGTSTP, libc::SIGCHLD];

/// Installs the handlers and keeps their signals blocked except while waiting, so that one
/// arriving between a check and the wait can't be missed.
fn install_handlers() {
    let blocked = signal_set(&HANDLED);
    // SAFETY: plain sigaction/sigprocmask calls with local structs; the handler only stores to
    // atomics.
    unsafe {
        libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut());
        for sig in HANDLED {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Sleeps until a handled signal arrives, or `limit` passes.
fn wait_for_signal(limit: Option<Duration>) {
    let none = signal_set(&[]);
    match limit {
        // SAFETY: sigsuspend with a local, initialized set.
        None => unsafe {
            libc::sigsuspend(&none);
        },
        Some(d) => {
            let ts = libc::timespec { tv_sec: d.as_secs() as _, tv_nsec: d.subsec_nanos() as _ };
            // SAFETY: ppoll on no descriptors with a local timeout and mask: a sleep that a
            // handled signal ends.
            unsafe { libc::ppoll(std::ptr::null_mut(), 0, &ts, &none) };
        }
    }
}

/// Collects every exited child: `(pid, status)` for each.
fn reap_all() -> Vec<(libc::pid_t, libc::c_int)> {
    let mut out = Vec::new();
    loop {
        let mut status = 0;
        // SAFETY: waitpid with a local status word.
        let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if r <= 0 {
            return out;
        }
        out.push((r, status));
    }
}

/// Collects every exited child; `pid`'s status if it was one of them.
fn reap(pid: libc::pid_t) -> Option<libc::c_int> {
    reap_all().into_iter().find(|&(p, _)| p == pid).map(|(_, s)| s)
}

fn describe(status: libc::c_int) -> String {
    if libc::WIFEXITED(status) {
        format!("exit status {}", libc::WEXITSTATUS(status))
    } else {
        format!("signal {}", libc::WTERMSIG(status))
    }
}

fn unblock_all() {
    let none = signal_set(&[]);
    // SAFETY: sigprocmask with a local, initialized set.
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut()) };
}

/// Makes the child a session of its own, with the console as its controlling terminal (when no
/// other session has it) and standard input, output and error, and with no signals blocked.
fn take_console() -> io::Result<()> {
    // SAFETY: runs in the child between fork and exec; only async-signal-safe calls.
    unsafe {
        unblock_all();
        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::open(CONSOLE.as_ptr(), libc::O_RDWR);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Best effort: a session still holding the console (one that ignored its hangup) keeps
        // it, and the child then just writes to it.
        libc::ioctl(fd, libc::TIOCSCTTY, 0);
        for target in 0..3 {
            libc::dup2(fd, target);
        }
        if fd > 2 {
            libc::close(fd);
        }
    }
    Ok(())
}

/// For a child whose standard descriptors are already set up: no signals blocked.
fn signals_only() -> io::Result<()> {
    unblock_all();
    Ok(())
}

/// For a session's command, which takes its terminal itself (getty opens `/dev/<tty>`): no
/// signals blocked, and the console (not as controlling terminal) for anything it says before.
fn console_output() -> io::Result<()> {
    // SAFETY: runs in the child between fork and exec; only async-signal-safe calls.
    unsafe {
        unblock_all();
        let fd = libc::open(CONSOLE.as_ptr(), libc::O_RDWR);
        if fd >= 0 {
            for target in 0..3 {
                libc::dup2(fd, target);
            }
            if fd > 2 {
                libc::close(fd);
            }
        }
    }
    Ok(())
}

/// A command with init's environment for its children (§4.2).
fn command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .envs([("PATH", PATH), ("HOME", "/"), ("SHELL", "/bin/sh"), ("TERM", "linux")])
        .current_dir("/");
    cmd
}

/// `command`, run as a session on the console.
fn console_command(program: &str) -> Command {
    let mut cmd = command(program);
    // SAFETY: take_console is async-signal-safe.
    unsafe { cmd.pre_exec(take_console) };
    cmd
}

/// Runs `cmd` to completion as a session init answers for, reaping orphans and honoring
/// shutdown requests meanwhile. `None` if it couldn't be started.
fn run(mut cmd: Command, what: &str) -> Option<libc::c_int> {
    let child = match cmd.spawn() {
        Ok(c) => c.id() as libc::pid_t,
        Err(e) => {
            complain(&format!("{what}: {e}"));
            return None;
        }
    };
    set_leaders(&[child]);
    loop {
        if let Some(status) = reap(child) {
            set_leaders(&[]);
            return Some(status);
        }
        check_request();
        wait_for_signal(None);
    }
}

fn set_leaders(pids: &[libc::pid_t]) {
    *LEADERS.lock().unwrap() = pids.to_vec();
}

fn check_request() {
    let sig = REQUEST.swap(0, Ordering::Relaxed);
    if sig != 0 {
        shutdown(sig);
    }
}

/// Waits up to `limit` for `pid` to exit (any child, for -1: until none is left), reaping.
/// Returns whether it did.
fn wait_up_to(pid: libc::pid_t, limit: Duration) -> bool {
    let until = Instant::now() + limit;
    loop {
        if pid > 0 && reap(pid).is_some() {
            return true;
        }
        if pid < 0 {
            reap_all();
            // SAFETY: waitpid only probing for remaining children.
            let r = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
            if r < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                return true;
            }
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: kill with signal 0 only probes.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Hangs up the sessions led by `leaders`, as the BSDs' init does by revoking the terminals,
/// and kills any leader still there after `HANGUP_GRACE`. Reaps as it waits.
fn hang_up(leaders: &[libc::pid_t]) {
    for &p in leaders {
        // SAFETY: kill with the pid and process group of a session init started. The group is
        // the leader's own once it has called setsid; until then only the pid reaches it.
        unsafe {
            libc::kill(-p, libc::SIGHUP);
            libc::kill(p, libc::SIGHUP);
            libc::kill(-p, libc::SIGCONT);
            libc::kill(p, libc::SIGCONT);
        }
    }
    let until = Instant::now() + HANGUP_GRACE;
    loop {
        reap_all();
        if !leaders.iter().any(|&p| alive(p)) {
            return;
        }
        if Instant::now() >= until {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for &p in leaders.iter().filter(|&&p| alive(p)) {
        complain(&format!("session {p} would not hang up; killing it"));
        // SAFETY: as above.
        unsafe {
            libc::kill(-p, libc::SIGKILL);
            libc::kill(p, libc::SIGKILL);
        }
    }
    let until = Instant::now() + Duration::from_millis(500);
    while leaders.iter().any(|&p| alive(p)) && Instant::now() < until {
        reap_all();
        std::thread::sleep(Duration::from_millis(50));
    }
    reap_all();
}

/// §10: `/etc/rc.shutdown`, then every process is terminated, storage synchronized, and
/// `reboot(2)` called with the action `sig` asked for.
fn shutdown(sig: libc::c_int) -> ! {
    let (how, what) = match sig {
        libc::SIGUSR1 => (libc::RB_HALT_SYSTEM, "halt"),
        libc::SIGUSR2 => (libc::RB_POWER_OFF, "power off"),
        _ => (libc::RB_AUTOBOOT, "reboot"),
    };
    say(&format!("shutting down ({what})"));
    record_time(SHUTDOWN_TIME, "shutdown");
    // The sessions let go of their terminals, so that rc.shutdown can have the console.
    let leaders = std::mem::take(&mut *LEADERS.lock().unwrap());
    hang_up(&leaders);
    let mut rc = console_command("/sbin/init_sh");
    rc.arg("/etc/rc.shutdown");
    match rc.spawn() {
        Ok(c) => {
            let pid = c.id() as libc::pid_t;
            if !wait_up_to(pid, RCSHUTDOWN_TIMEOUT) {
                complain("/etc/rc.shutdown timed out; terminating it");
                // SAFETY: kill with a pid init started.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        Err(e) => complain(&format!("/etc/rc.shutdown: {e}")),
    }
    // SAFETY: kill(-1) signals every process but init.
    unsafe { libc::kill(-1, libc::SIGTERM) };
    if !wait_up_to(-1, KILL_GRACE) {
        complain("some processes would not die; killing them");
        unsafe { libc::kill(-1, libc::SIGKILL) };
        wait_up_to(-1, Duration::from_secs(1));
    }
    // SAFETY: sync and reboot take no pointers.
    unsafe {
        libc::sync();
        libc::reboot(how);
    }
    complain(&format!("reboot: {}", io::Error::last_os_error()));
    loop {
        // SAFETY: pause takes no arguments.
        unsafe { libc::pause() };
    }
}

unsafe extern "C" {
    /// Appends a record to a wtmpx file (musl, `_BSD_SOURCE`); the libc crate doesn't bind it.
    fn updwtmpx(file: *const libc::c_char, ut: *const libc::utmpx);
}

const WTMPX: &CStr = c"/var/log/wtmpx";
/// `<utmpx.h>`'s `SHUTDOWN_TIME` (OxideBSD's musl; NetBSD's `DOWN_TIME`), which the libc crate
/// doesn't have.
const SHUTDOWN_TIME: libc::c_short = 11;

fn now_tv() -> libc::timeval {
    // SAFETY: gettimeofday into a local.
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    tv
}

fn copy_into(dst: &mut [libc::c_char], s: &str) {
    let room = dst.len() - 1;
    for (d, b) in dst.iter_mut().zip(s.bytes().take(room)) {
        *d = b as libc::c_char;
    }
}

/// Writes `rec` to `/var/run/utmpx` and appends it to `/var/log/wtmpx` (LOGIN.md §8).
// The libc crate marks musl's utmpx functions deprecated because stock musl stubs them;
// OxideBSD's musl implements them.
#[allow(deprecated)]
fn put_record(rec: &libc::utmpx) {
    // SAFETY: utmpx calls with a whole, initialized record.
    unsafe {
        libc::setutxent();
        libc::pututxline(rec);
        libc::endutxent();
        updwtmpx(WTMPX.as_ptr(), rec);
    }
}

/// A `BOOT_TIME` or `SHUTDOWN_TIME` record, named as the BSDs' wtmp names them for `last`.
fn record_time(kind: libc::c_short, name: &str) {
    // SAFETY: a zeroed utmpx is a valid empty record.
    let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
    ut.ut_type = kind;
    copy_into(&mut ut.ut_line, "~");
    copy_into(&mut ut.ut_user, name);
    let tv = now_tv();
    ut.ut_tv.tv_sec = tv.tv_sec as _;
    ut.ut_tv.tv_usec = tv.tv_usec as _;
    put_record(&ut);
}

/// A session on `line` ended. If its login record still says someone is logged in there (login
/// was killed before it could write its own logout), it is closed, as FreeBSD's init does.
#[allow(deprecated)]
fn record_logout(line: &str) {
    // SAFETY: a zeroed key with ut_line set; getutxline returns a static record or NULL.
    let found = unsafe {
        let mut key: libc::utmpx = std::mem::zeroed();
        copy_into(&mut key.ut_line, line);
        libc::setutxent();
        let e = libc::getutxline(&key);
        let found = (!e.is_null()).then(|| *e);
        libc::endutxent();
        found
    };
    let Some(old) = found else { return };
    // SAFETY: as in record_time.
    let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
    ut.ut_type = libc::DEAD_PROCESS;
    ut.ut_pid = old.ut_pid;
    ut.ut_line = old.ut_line;
    ut.ut_id = old.ut_id;
    let tv = now_tv();
    ut.ut_tv.tv_sec = tv.tv_sec as _;
    ut.ut_tv.tv_usec = tv.tv_usec as _;
    put_record(&ut);
}

// musl has crypt(3) in libc; a glibc host (for `cargo test`) keeps it in libcrypt.
#[cfg_attr(target_os = "linux", link(name = "crypt"))]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Root's password hash; `None` if root has none, or it can't be read (FreeBSD's init doesn't
/// ask then either).
fn root_hash() -> Option<CString> {
    // SAFETY: getspnam returns a static record or NULL.
    let sp = unsafe { libc::getspnam(c"root".as_ptr()) };
    if sp.is_null() {
        return None;
    }
    let hash = unsafe { CStr::from_ptr((*sp).sp_pwdp) };
    (!hash.is_empty()).then(|| hash.to_owned())
}

/// Reads a line from standard input with echo off. `None` at end of input (`^D`).
fn read_secret() -> Option<String> {
    // SAFETY: tcgetattr/tcsetattr on descriptor 0 with local termios structs.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have_tty = unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    if have_tty {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &quiet) };
    }
    let mut line = Vec::new();
    let mut b = [0u8];
    let eof = loop {
        match io::stdin().read(&mut b) {
            Ok(0) | Err(_) => break true,
            Ok(_) if b[0] == b'\n' || b[0] == b'\r' => break false,
            Ok(_) if b[0] == 0x04 && line.is_empty() => break true,
            Ok(_) => line.push(b[0]),
        }
    };
    if have_tty {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
    }
    println!();
    (!eof).then(|| String::from_utf8_lossy(&line).into_owned())
}

/// Asks for root's password until it is given; false if the operator typed `^D` instead.
fn single_user_password(hash: &CStr) -> bool {
    loop {
        print!("Enter root password, or ^D to go multi-user\nPassword: ");
        let _ = io::stdout().flush();
        let Some(input) = read_secret() else { return false };
        let Ok(key) = CString::new(input) else { continue };
        // SAFETY: crypt returns a static buffer or NULL.
        let out = unsafe { crypt(key.as_ptr(), hash.as_ptr()) };
        if !out.is_null() && unsafe { CStr::from_ptr(out) } == hash {
            return true;
        }
        println!("Login incorrect");
    }
}

/// The child half of `single-user`: takes the console, asks for root's password if it is
/// insecure, and becomes the shell. Exits 0 without a shell when the operator types `^D` at the
/// password prompt.
fn single_user_child(insecure: bool) -> ! {
    if let Err(e) = take_console() {
        complain(&format!("/dev/console: {e}"));
    }
    if insecure
        && let Some(hash) = root_hash()
        && !single_user_password(&hash)
    {
        // SAFETY: _exit in a forked child.
        unsafe { libc::_exit(0) };
    }
    let err = command("/bin/sh").arg0("-sh").env("PS1", PS1).exec();
    complain(&format!("/bin/sh: {err}"));
    // SAFETY: as above.
    unsafe { libc::_exit(1) };
}

/// §3 `single-user`: a root shell on the console, until it exits.
fn single_user() {
    say("single-user mode");
    let insecure = !ttyent::is_secure("console");
    // init is single-threaded, so the child may allocate before it execs.
    // SAFETY: fork; the child never returns from single_user_child.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        complain(&format!("fork: {}", io::Error::last_os_error()));
        std::thread::sleep(RESPAWN_PAUSE);
        return;
    }
    if pid == 0 {
        single_user_child(insecure);
    }
    set_leaders(&[pid]);
    loop {
        if reap(pid).is_some() {
            set_leaders(&[]);
            return;
        }
        check_request();
        wait_for_signal(None);
    }
}

/// §3 `runcom`: whether `/etc/rc` succeeded.
fn runcom(autoboot: bool) -> bool {
    let mut rc = console_command("/sbin/init_sh");
    rc.arg("/etc/rc");
    if autoboot {
        rc.arg("autoboot");
    }
    match run(rc, "/etc/rc") {
        Some(0) => true,
        Some(status) => {
            complain(&format!("/etc/rc failed ({})", describe(status)));
            false
        }
        None => false,
    }
}

/// §9.3 step 3: why the kernel restarted init, from the last line of `/proc/initdeaths`
/// (`<time> exit <status>` or `<time> signal <n> [ip <ip> [addr <addr>]]`).
fn death_reason() -> String {
    let text = std::fs::read_to_string("/proc/initdeaths").unwrap_or_default();
    let Some(line) = text.lines().last() else { return "no death recorded".into() };
    let w: Vec<&str> = line.split_whitespace().collect();
    match &w[1.min(w.len())..] {
        ["exit", status] => format!("it exited with status {status}"),
        ["signal", sig, rest @ ..] => {
            let mut why = format!("it was killed by signal {sig}");
            if let ["ip", ip, tail @ ..] = rest {
                why += &format!(" at ip {ip}");
                if let ["addr", addr] = tail {
                    why += &format!(", address {addr}");
                }
            }
            why
        }
        _ => line.to_string(),
    }
}

/// §9.3 step 2: starts the services that should be running and aren't. Only those
/// `/etc/rc.shutdown` would stop (`KEYWORD: shutdown`) are checked: they are the ones with a
/// process to look for, and one-shot scripts such as cleanvar must not run twice.
fn restore_services() {
    let mut scripts: Vec<String> = match std::fs::read_dir("/etc/rc.d") {
        Ok(dir) => dir.flatten().map(|e| e.path().display().to_string()).collect(),
        Err(e) => {
            complain(&format!("/etc/rc.d: {e}"));
            return;
        }
    };
    scripts.sort();
    let mut rcorder = command("/sbin/rcorder");
    rcorder.args(["-k", "shutdown"]).args(&scripts).stdin(std::process::Stdio::null());
    // SAFETY: signals_only is async-signal-safe.
    unsafe { rcorder.pre_exec(signals_only) };
    let order = match rcorder.output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => {
            complain(&format!("/sbin/rcorder: {e}"));
            return;
        }
    };
    for script in order.lines() {
        // `quiet`: a disabled service answers 0 without a word.
        let mut status = command("/sbin/init_sh");
        status.args([script, "quietstatus"]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null());
        // SAFETY: signals_only is async-signal-safe.
        unsafe { status.pre_exec(signals_only) };
        if status.status().is_ok_and(|s| s.success()) {
            continue;
        }
        let name = script.rsplit('/').next().unwrap_or(script);
        say(&format!("{name} is not running; starting it"));
        let mut start = command("/sbin/init_sh");
        start.args([script, "start"]);
        // SAFETY: console_output is async-signal-safe.
        unsafe { start.pre_exec(console_output) };
        match run(start, script) {
            Some(0) | None => {}
            Some(st) => complain(&format!("{name} start failed ({})", describe(st))),
        }
    }
}

/// One `/etc/ttys` entry init runs a session on.
struct Session {
    ent: ttyent::TtyEnt,
    /// The session's leader, or 0 when none is running.
    pid: libc::pid_t,
    started: Instant,
    /// Recent exits that came within `RESPAWN_WINDOW` of starting.
    quick_exits: VecDeque<Instant>,
    /// No new session before this.
    paused_until: Option<Instant>,
}

impl Session {
    fn new(ent: ttyent::TtyEnt) -> Self {
        Session { ent, pid: 0, started: Instant::now(), quick_exits: VecDeque::new(), paused_until: None }
    }

    /// FreeBSD's argv: the getty field split into words, then the terminal's name.
    fn argv(&self) -> Vec<String> {
        let mut v: Vec<String> = self.ent.getty.as_deref().unwrap_or("").split_whitespace().map(String::from).collect();
        v.push(self.ent.name.clone());
        v
    }

    fn start(&mut self) {
        let argv = self.argv();
        let mut cmd = command(&argv[0]);
        cmd.args(&argv[1..]).env("TERM", &self.ent.term);
        // SAFETY: console_output is async-signal-safe.
        unsafe { cmd.pre_exec(console_output) };
        self.started = Instant::now();
        match cmd.spawn() {
            Ok(c) => self.pid = c.id() as libc::pid_t,
            Err(e) => {
                complain(&format!("{}: {}: {e}", self.ent.name, argv[0]));
                self.ended();
            }
        }
    }

    /// The session's leader exited (or couldn't be started): §5.3's limit.
    fn ended(&mut self) {
        self.pid = 0;
        let now = Instant::now();
        if now.duration_since(self.started) < RESPAWN_WINDOW {
            self.quick_exits.push_back(now);
        }
        self.quick_exits.retain(|t| now.duration_since(*t) < RESPAWN_WINDOW);
        if self.quick_exits.len() >= RESPAWN_LIMIT {
            complain(&format!(
                "{}: getty repeating too quickly; waiting {} seconds",
                self.ent.name,
                RESPAWN_PAUSE.as_secs()
            ));
            self.quick_exits.clear();
            self.paused_until = Some(now + RESPAWN_PAUSE);
        }
    }

    /// When the session the old init started on this terminal still holds it (recovery, §9.3),
    /// adopts its leader: the kernel made it our child. Found in `/proc`: a session leader whose
    /// parent is pid 1 and whose controlling terminal (`tty_nr`) is this one.
    fn adopt(&mut self) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Ok(rdev) = std::fs::metadata(format!("/dev/{}", self.ent.name)).map(|m| m.rdev()) else { return false };
        let Ok(dir) = std::fs::read_dir("/proc") else { return false };
        for entry in dir.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<libc::pid_t>().ok()) else { continue };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
            // proc(5): `pid (comm) state ppid pgrp session tty_nr ...`; comm may hold spaces.
            let Some(rest) = stat.rfind(')').map(|i| &stat[i + 1..]) else { continue };
            let f: Vec<&str> = rest.split_whitespace().collect();
            let field = |i: usize| f.get(i).and_then(|v| v.parse::<i64>().ok());
            if field(1) == Some(1) && field(3) == Some(pid as i64) && field(4) == Some(rdev as i64) {
                self.pid = pid;
                say(&format!("{}: keeping session {pid}", self.ent.name));
                return true;
            }
        }
        false
    }
}

/// The `/etc/ttys` entries init runs sessions on (ttys(5)'s status, and a command to run).
fn wanted_ttys() -> Vec<ttyent::TtyEnt> {
    let entries = match ttyent::read() {
        Ok(e) => e,
        Err(e) => {
            complain(&format!("{}: {e}", ttyent::PATH));
            return Vec::new();
        }
    };
    entries
        .into_iter()
        .filter(|e| e.getty.is_some())
        .filter(|e| match e.status {
            ttyent::Status::On => true,
            ttyent::Status::Off => false,
            ttyent::Status::OnIfExists => std::path::Path::new(&format!("/dev/{}", e.name)).exists(),
            ttyent::Status::OnIfConsole => e.name == CONSOLE_TTY,
        })
        .collect()
}

/// §5.5: brings `sessions` in line with `/etc/ttys`. An entry that is gone, turned off, or now
/// runs a different command has its session hung up; a new one gets a session.
fn reread_ttys(sessions: &mut Vec<Session>) {
    let wanted = wanted_ttys();
    let mut dropped = Vec::new();
    sessions.retain_mut(|s| match wanted.iter().find(|w| w.name == s.ent.name) {
        Some(w) if w.getty == s.ent.getty && w.term == s.ent.term => {
            s.ent = w.clone();
            true
        }
        _ => {
            if s.pid > 0 {
                dropped.push((s.pid, s.ent.name.clone()));
            }
            false
        }
    });
    hang_up(&dropped.iter().map(|d| d.0).collect::<Vec<_>>());
    for (_, line) in &dropped {
        record_logout(line);
    }
    for w in wanted {
        if !sessions.iter().any(|s| s.ent.name == w.name) {
            sessions.push(Session::new(w));
        }
    }
}

/// How `multi-user` ended.
enum Leave {
    /// `SIGTERM`: sessions ended, on to `single-user`.
    CleanTtys,
}

/// §3 `multi-user` (and `recovery`, which first adopts the sessions still running).
fn multi_user(recovering: bool) -> Leave {
    GOT_HUP.store(false, Ordering::Relaxed);
    GOT_TSTP.store(false, Ordering::Relaxed);
    let mut sessions: Vec<Session> = wanted_ttys().into_iter().map(Session::new).collect();
    if sessions.is_empty() {
        complain("no terminals in /etc/ttys are on");
    }
    if recovering {
        for s in &mut sessions {
            s.adopt();
        }
    }
    let mut stopped = false;
    loop {
        check_request();
        if GOT_TERM.swap(false, Ordering::Relaxed) {
            // §3 clean-ttys.
            say("ending terminal sessions");
            let leaders: Vec<_> = sessions.iter().map(|s| s.pid).filter(|&p| p > 0).collect();
            set_leaders(&[]);
            hang_up(&leaders);
            for s in &sessions {
                record_logout(&s.ent.name);
            }
            return Leave::CleanTtys;
        }
        if GOT_HUP.swap(false, Ordering::Relaxed) {
            if stopped {
                say("starting sessions again");
            }
            stopped = false;
            reread_ttys(&mut sessions);
        }
        if GOT_TSTP.swap(false, Ordering::Relaxed) && !stopped {
            say("not starting new sessions (SIGHUP resumes)");
            stopped = true;
        }

        for (pid, _) in reap_all() {
            if let Some(s) = sessions.iter_mut().find(|s| s.pid == pid) {
                record_logout(&s.ent.name);
                s.ended();
            }
        }

        let now = Instant::now();
        let mut next_wake: Option<Instant> = None;
        for s in &mut sessions {
            if s.pid != 0 || stopped {
                continue;
            }
            match s.paused_until {
                Some(t) if t > now => {
                    next_wake = Some(next_wake.map_or(t, |n| n.min(t)));
                }
                _ => {
                    s.paused_until = None;
                    s.start();
                }
            }
        }
        set_leaders(&sessions.iter().map(|s| s.pid).filter(|&p| p > 0).collect::<Vec<_>>());

        // A session whose start failed may want another try right away (or after its pause);
        // anything else waits for a signal.
        let retry = sessions.iter().any(|s| s.pid == 0 && s.paused_until.is_none());
        if retry && !stopped {
            continue;
        }
        wait_for_signal(next_wake.map(|t| t.saturating_duration_since(Instant::now())));
    }
}

#[derive(Clone, Copy)]
enum State {
    SingleUser,
    Runcom,
    MultiUser,
    Recovery,
}

fn main() {
    // Only the kernel starts init, as process 1; run from a shell it would run /etc/rc and fight
    // the console for a single-user shell. Refused as on OpenBSD and NetBSD.
    // SAFETY: getuid and getpid take no arguments.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("init: Operation not permitted");
        std::process::exit(1);
    }
    // SAFETY: as above.
    if unsafe { libc::getpid() } != 1 {
        eprintln!("init: already running");
        std::process::exit(1);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    open_log();
    install_handlers();
    // SAFETY: umask takes no pointers.
    unsafe { libc::umask(0o022) };
    let _ = std::env::set_current_dir("/");

    let mut state = if args.iter().any(|a| a == "-R") {
        State::Recovery
    } else if args.iter().any(|a| a == "-s") {
        State::SingleUser
    } else {
        State::Runcom
    };
    // `/etc/rc` gets `autoboot` only at boot, not after single-user (FreeBSD).
    let mut autoboot = true;
    // Whether the services `/etc/rc` started are still running: single-user reached through
    // clean-ttys goes back to multi-user without running it again.
    let mut services_up = false;
    // The boot's `BOOT_TIME` record is written once, by the first successful /etc/rc.
    let mut boot_recorded = false;

    loop {
        state = match state {
            State::SingleUser => {
                single_user();
                GOT_TERM.store(false, Ordering::Relaxed);
                if services_up { State::MultiUser } else { State::Runcom }
            }
            State::Runcom => {
                let ok = runcom(autoboot);
                autoboot = false;
                services_up = ok;
                // After /etc/rc, whose cleanvar empties /var/run (LOGIN.md §8.3).
                if ok && !boot_recorded {
                    record_time(libc::BOOT_TIME, "reboot");
                    boot_recorded = true;
                }
                if ok { State::MultiUser } else { State::SingleUser }
            }
            State::MultiUser => match multi_user(false) {
                Leave::CleanTtys => State::SingleUser,
            },
            State::Recovery => {
                log(libc::LOG_ALERT, &format!("restarted by the kernel: {}", death_reason()));
                restore_services();
                services_up = true;
                match multi_user(true) {
                    Leave::CleanTtys => State::SingleUser,
                }
            }
        };
    }
}
