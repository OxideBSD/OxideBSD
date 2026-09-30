//! `/sbin/init`, process 1 (INIT.md in OxideBSD-doc). A first cut: it runs `/etc/rc`, then a
//! root shell on the console, starting a new one whenever it exits, and reaps every orphan.
//!
//! - `-s` (single-user, from the kernel's boot flags) skips `/etc/rc`.
//! - `-R` (the kernel restarting init after a death, §9.3) skips it too: the services are
//!   already running.
//! - `SIGINT`, `SIGUSR1` and `SIGUSR2` (reboot, halt, power off, §6) shut the system down as
//!   §10 says: `/etc/rc.shutdown`, then `SIGTERM` and `SIGKILL` to everything, `sync`, and
//!   `reboot(2)`.
//!
//! Not yet (INIT_WORKPLAN step 10): `/etc/ttys` sessions and getty, `SIGTERM` to single-user,
//! `SIGHUP`, the password on an insecure console, recovery mode's service checks, `utmpx`.
//!
//! Like the BSDs' init it has no controlling terminal (the kernel starts it without one). Each
//! child it starts is a session of its own with the console as controlling terminal, so the
//! keyboard's signals reach that child and never init.

use std::collections::VecDeque;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

const CONSOLE: &std::ffi::CStr = c"/dev/console";
/// INIT.md §4.2.
const PATH: &str = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin";
/// The console shell's prompt: `user@host:dir$`, colored.
const PS1: &str = "\\[\\e[1;32m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ ";
/// §10.2's default for `rcshutdown_timeout`.
const RCSHUTDOWN_TIMEOUT: Duration = Duration::from_secs(90);
/// §10.3.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// The shell's restart limit, FreeBSD's for a terminal session: this many exits within
/// `RESPAWN_WINDOW` of starting pause restarts for `RESPAWN_PAUSE`.
const RESPAWN_LIMIT: usize = 3;
const RESPAWN_WINDOW: Duration = Duration::from_secs(5);
const RESPAWN_PAUSE: Duration = Duration::from_secs(30);

/// A shutdown request: the signal that asked for it, or 0.
static REQUEST: AtomicI32 = AtomicI32::new(0);
/// The session running on the console (`/etc/rc` or the shell; its leader's pid), or 0.
static SESSION: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_request(sig: libc::c_int) {
    REQUEST.store(sig, Ordering::Relaxed);
}

extern "C" fn on_child(_: libc::c_int) {}

fn say(msg: &str) {
    eprintln!("init: {msg}");
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

const HANDLED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGUSR1, libc::SIGUSR2, libc::SIGCHLD];

/// Installs the handlers and keeps their signals blocked except inside `sigsuspend`, so that
/// one arriving between a check and the wait can't be missed.
fn install_handlers() {
    let blocked = signal_set(&HANDLED);
    // SAFETY: plain sigaction/sigprocmask calls with local structs; the handlers only store to
    // an atomic.
    unsafe {
        libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut());
        for sig in HANDLED {
            let mut sa: libc::sigaction = std::mem::zeroed();
            let handler: extern "C" fn(libc::c_int) = if sig == libc::SIGCHLD { on_child } else { on_request };
            sa.sa_sigaction = handler as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// Sleeps until a handled signal arrives.
fn wait_for_signal() {
    let none = signal_set(&[]);
    // SAFETY: sigsuspend with a local, initialized set.
    unsafe { libc::sigsuspend(&none) };
}

/// Collects every exited child; returns whether `pid` was one of them, with its status.
fn reap(pid: libc::pid_t) -> Option<libc::c_int> {
    let mut found = None;
    loop {
        let mut status = 0;
        // SAFETY: waitpid with a local status word.
        let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if r <= 0 {
            return found;
        }
        if r == pid {
            found = Some(status);
        }
    }
}

fn describe(status: libc::c_int) -> String {
    if libc::WIFEXITED(status) {
        format!("exit status {}", libc::WEXITSTATUS(status))
    } else {
        format!("signal {}", libc::WTERMSIG(status))
    }
}

/// Makes the child a session of its own, with the console as its controlling terminal (when no
/// other session has it) and standard input, output and error, and with no signals blocked.
fn take_console() -> io::Result<()> {
    // SAFETY: runs in the child between fork and exec; only async-signal-safe calls.
    unsafe {
        let none = signal_set(&[]);
        libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
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

/// A command with init's environment for its children (§4.2), run on the console.
fn command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .envs([("PATH", PATH), ("HOME", "/"), ("SHELL", "/bin/sh"), ("TERM", "linux")])
        .current_dir("/");
    // SAFETY: take_console is async-signal-safe.
    unsafe { cmd.pre_exec(take_console) };
    cmd
}

/// Runs `cmd` to completion, reaping orphans and honoring shutdown requests meanwhile. `None`
/// if it couldn't be started.
fn run(mut cmd: Command, what: &str) -> Option<libc::c_int> {
    let child = match cmd.spawn() {
        Ok(c) => c.id() as libc::pid_t,
        Err(e) => {
            say(&format!("{what}: {e}"));
            return None;
        }
    };
    SESSION.store(child, Ordering::Relaxed);
    loop {
        if let Some(status) = reap(child) {
            SESSION.store(0, Ordering::Relaxed);
            return Some(status);
        }
        check_request();
        wait_for_signal();
    }
}

/// Sleeps for `d`, reaping orphans and honoring shutdown requests meanwhile.
fn pause_for(d: Duration) {
    let handled = signal_set(&HANDLED);
    let until = Instant::now() + d;
    while Instant::now() < until {
        reap(-1);
        check_request();
        // The handlers may run during the sleep; the check above sees what they stored.
        // SAFETY: sigprocmask with a local, initialized set.
        unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &handled, std::ptr::null_mut()) };
        std::thread::sleep(Duration::from_millis(250).min(until.saturating_duration_since(Instant::now())));
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &handled, std::ptr::null_mut()) };
    }
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
            reap(-1);
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

/// §10: `/etc/rc.shutdown`, then every process is terminated, storage synchronized, and
/// `reboot(2)` called with the action `sig` asked for.
fn shutdown(sig: libc::c_int) -> ! {
    let (how, what) = match sig {
        libc::SIGUSR1 => (libc::RB_HALT_SYSTEM, "halt"),
        libc::SIGUSR2 => (libc::RB_POWER_OFF, "power off"),
        _ => (libc::RB_AUTOBOOT, "reboot"),
    };
    say(&format!("shutting down ({what})"));
    // Hang up the console's session, as the BSDs' init does by revoking the terminals, so that
    // it lets go of the console and rc.shutdown can have it.
    let session = SESSION.swap(0, Ordering::Relaxed);
    if session > 0 {
        // SAFETY: kill with the process group of a session init started.
        unsafe {
            libc::kill(-session, libc::SIGHUP);
            libc::kill(-session, libc::SIGCONT);
        }
        wait_up_to(session, Duration::from_secs(2));
    }
    let mut rc = command("/sbin/init_sh");
    rc.arg("/etc/rc.shutdown");
    match rc.spawn() {
        Ok(c) => {
            let pid = c.id() as libc::pid_t;
            if !wait_up_to(pid, RCSHUTDOWN_TIMEOUT) {
                say("/etc/rc.shutdown timed out; terminating it");
                // SAFETY: kill with a pid init started.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
        Err(e) => say(&format!("/etc/rc.shutdown: {e}")),
    }
    // SAFETY: kill(-1) signals every process but init.
    unsafe { libc::kill(-1, libc::SIGTERM) };
    if !wait_up_to(-1, KILL_GRACE) {
        say("some processes would not die; killing them");
        unsafe { libc::kill(-1, libc::SIGKILL) };
        wait_up_to(-1, Duration::from_secs(1));
    }
    // SAFETY: sync and reboot take no pointers.
    unsafe {
        libc::sync();
        libc::reboot(how);
    }
    say(&format!("reboot: {}", io::Error::last_os_error()));
    loop {
        // SAFETY: pause takes no arguments.
        unsafe { libc::pause() };
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let single = args.iter().any(|a| a == "-s");
    let restarted = args.iter().any(|a| a == "-R");
    install_handlers();
    // SAFETY: umask takes no pointers.
    unsafe { libc::umask(0o022) };
    let _ = std::env::set_current_dir("/");

    if restarted {
        say("restarted by the kernel after a death; see /proc/initdeaths");
    } else if single {
        say("single-user mode");
    } else {
        let mut rc = command("/sbin/init_sh");
        rc.args(["/etc/rc", "autoboot"]);
        match run(rc, "/etc/rc") {
            Some(0) => {}
            Some(status) => say(&format!("/etc/rc failed ({})", describe(status))),
            None => {}
        }
    }

    let mut exits: VecDeque<Instant> = VecDeque::new();
    loop {
        let started = Instant::now();
        let mut sh = command("/bin/sh");
        // The prompt the kernel gave its own pid-1 shell before init existed; it belongs in a
        // profile once the console gets real login sessions.
        sh.arg0("-sh").env("PS1", PS1);
        if run(sh, "/bin/sh").is_none() {
            pause_for(RESPAWN_PAUSE);
            continue;
        }
        if started.elapsed() < RESPAWN_WINDOW {
            exits.push_back(Instant::now());
        }
        exits.retain(|t| t.elapsed() < RESPAWN_WINDOW);
        if exits.len() >= RESPAWN_LIMIT {
            say("/bin/sh keeps exiting; waiting 30 seconds");
            exits.clear();
            pause_for(RESPAWN_PAUSE);
        }
    }
}
