//! `devd(8)`: runs the configuration's handlers for device events (OxideBSD-doc `DEVD.md` §5).
//!
//! One loop over `poll`: event lines from `/dev/devctl` ([`event`]) go to every `devd.pipe` client
//! ([`pipe`]), then to the rules ([`rules`]); when any match, a child process runs their handlers
//! with the event's fields as variables, and devd waits for it (up to `-t` seconds, then kills its
//! process group) before reading the next event. Signals reach the loop through a pipe written by
//! their handlers: `SIGHUP` reloads the configuration, `SIGTERM` and `SIGINT` end devd.

mod event;
mod pipe;
mod rules;

use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use libsh::{Flow, Shell};

use event::Event;
use pipe::Pipe;
use rules::{Config, Rule};

const DEVCTL: &str = "/dev/devctl";
const PIDFILE: &str = "/var/run/devd.pid";

struct Opts {
    /// `-d`: in the foreground, each event and rule logged to stderr.
    debug: bool,
    /// `-f`: this file instead of §5.3's list.
    file: Option<PathBuf>,
    /// `-n`: check the configuration and exit.
    check: bool,
    /// `-t`: a handler's time, 0 for no limit.
    timeout: u64,
}

fn usage() -> ExitCode {
    eprintln!("usage: devd [-dn] [-f file] [-t timeout]");
    ExitCode::from(1)
}

fn parse_args() -> Result<Opts, ExitCode> {
    let mut o = Opts { debug: false, file: None, check: false, timeout: 30 };
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
                if rest.is_empty() { args.next() } else { Some(rest) }
            };
            match c {
                'd' => o.debug = true,
                'n' => o.check = true,
                'f' => {
                    o.file = Some(value().ok_or_else(usage)?.into());
                    break;
                }
                't' => {
                    let Some(n) = value().and_then(|v| v.parse().ok()) else {
                        eprintln!("devd: -t: a number of seconds");
                        return Err(usage());
                    };
                    o.timeout = n;
                    break;
                }
                _ => return Err(usage()),
            }
        }
    }
    Ok(o)
}

// ---- logging ----

/// Messages go to stderr too: under `-d`, and before devd goes into the background.
static STDERR: AtomicBool = AtomicBool::new(true);
static DEBUG: AtomicBool = AtomicBool::new(false);

/// To syslog (`daemon`), and stderr while it's ours.
fn log(level: libc::c_int, msg: &str) {
    if STDERR.load(Ordering::Relaxed) {
        eprintln!("devd: {msg}");
    }
    let msg = CString::new(msg.replace('\0', "?")).unwrap_or_default();
    // SAFETY: a "%s" format with one C string.
    unsafe { libc::syslog(level, c"%s".as_ptr(), msg.as_ptr()) };
}

/// Under `-d` only.
fn debug(msg: &str) {
    if DEBUG.load(Ordering::Relaxed) {
        eprintln!("devd: {msg}");
    }
}

// ---- signals ----

/// The signals caught since the loop last looked, a bit each.
static CAUGHT: AtomicU64 = AtomicU64::new(0);
/// The write end of the pipe that wakes the loop's `poll`.
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(sig: libc::c_int) {
    CAUGHT.fetch_or(1 << sig, Ordering::Relaxed);
    let fd = WAKE_FD.load(Ordering::Relaxed);
    // SAFETY: write(2) is async-signal-safe; a full pipe already wakes the loop.
    unsafe { libc::write(fd, [0u8].as_ptr().cast(), 1) };
}

/// Whether `sig` was caught since the last look, forgetting it.
fn caught(sig: libc::c_int) -> bool {
    CAUGHT.fetch_and(!(1 << sig), Ordering::Relaxed) & (1 << sig) != 0
}

const CAUGHT_SIGNALS: [libc::c_int; 4] = [libc::SIGHUP, libc::SIGTERM, libc::SIGINT, libc::SIGCHLD];

/// The wake pipe's read end, and the handlers installed.
fn catch_signals() -> std::io::Result<libc::c_int> {
    let mut fds = [0; 2];
    // SAFETY: pipe(2) fills two descriptors.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: descriptors just made.
        unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
    }
    WAKE_FD.store(fds[1], Ordering::Relaxed);
    // SAFETY: plain sigaction(2) calls with a handler that only touches atomics and write(2).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        for sig in CAUGHT_SIGNALS {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
    Ok(fds[0])
}

fn drain(fd: libc::c_int) {
    let mut junk = [0u8; 64];
    // SAFETY: reading into a local buffer.
    while unsafe { libc::read(fd, junk.as_mut_ptr().cast(), junk.len()) } > 0 {}
}

// ---- the pid file and the background ----

/// Opens and locks the pid file, as FreeBSD's `pidfile_open(3)`: a second devd finds it locked.
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
    // SAFETY: single-threaded, so fork is safe; the parent only exits.
    unsafe {
        match libc::fork() {
            -1 => {
                eprintln!("devd: fork: {}", std::io::Error::last_os_error());
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
    STDERR.store(DEBUG.load(Ordering::Relaxed), Ordering::Relaxed);
}

// ---- running handlers ----

struct Devd {
    opts: Opts,
    files: Vec<PathBuf>,
    config: Config,
    devctl: libc::c_int,
    wake: libc::c_int,
    pipe: Pipe,
    /// What `/dev/devctl` gave past its last newline.
    partial: Vec<u8>,
}

fn load(files: &[PathBuf]) -> Config {
    let (mut config, _) = rules::load(files, &mut |msg| log(libc::LOG_ERR, msg));
    // SAFETY: getpid(2) can't fail.
    config.shell.shell_pid = unsafe { libc::getpid() };
    config.shell.shell_pgid = config.shell.shell_pid;
    config
}

/// In a handler's process: sets the event's variables, runs each rule's handler in turn, and
/// exits (§5.4).
fn run_handlers(sh: &mut Shell, e: &Event, line: &str, matched: &[&Rule]) -> ! {
    let vars = [("verb", e.verb.as_str()), ("class", e.class.as_str())]
        .into_iter()
        .chain(e.fields.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    for (name, value) in vars {
        match sh.set(name, value) {
            Ok(()) => {
                if let Some(v) = sh.vars.get_mut(name) {
                    v.exported = true;
                }
            }
            Err(msg) => log(libc::LOG_WARNING, &format!("{msg}: not set for `{line}`")),
        }
    }
    let mut status = 0;
    for rule in matched {
        status = match sh.source(&rule.handler) {
            Ok(Ok(s) | Err(Flow::Return(s))) => s,
            Ok(Err(Flow::Exit(s) | Flow::Fatal(s))) => {
                if s != 0 {
                    log(libc::LOG_WARNING, &format!("`{}` exited {s} for `{line}`", rule.text));
                }
                std::process::exit(sh.finish(s));
            }
            Ok(Err(Flow::Break(_) | Flow::Continue(_))) => 0,
            Err(err) => {
                log(libc::LOG_ERR, &format!("`{}`: its handler doesn't parse: {err}", rule.text));
                2
            }
        };
        if status != 0 {
            log(libc::LOG_WARNING, &format!("`{}` exited {status} for `{line}`", rule.text));
        }
    }
    std::process::exit(sh.finish(status));
}

impl Devd {
    /// Polls the wake pipe, the pipe's listener and its clients (and, with `devctl`, the event
    /// device) for up to `timeout` ms (-1: no limit); serves what's ready; whether the device is.
    fn poll(&mut self, devctl: bool, timeout: libc::c_int) -> bool {
        let pollfd = |fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let mut fds = vec![pollfd(self.wake), pollfd(self.pipe.listener_fd())];
        if devctl {
            fds.push(pollfd(self.devctl));
        }
        let first_client = fds.len();
        fds.extend(self.pipe.client_fds().map(pollfd));
        // SAFETY: `fds` is a valid array of its length.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if n <= 0 {
            return false;
        }
        if fds[0].revents != 0 {
            drain(self.wake);
        }
        if fds[1].revents != 0 {
            self.pipe.accept();
        }
        for p in &fds[first_client..] {
            if p.revents != 0 {
                self.pipe.service(p.fd);
            }
        }
        devctl && fds[2].revents != 0
    }

    /// Reads what `/dev/devctl` has and handles each whole line.
    fn read_events(&mut self) {
        let mut buf = [0u8; 4096];
        // SAFETY: reading into a local buffer.
        let n = unsafe { libc::read(self.devctl, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return;
        }
        self.partial.extend_from_slice(&buf[..n as usize]);
        while let Some(end) = self.partial.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=end).collect();
            self.pipe.broadcast(&line);
            let line = String::from_utf8_lossy(&line[..end]).into_owned();
            self.handle(&line);
        }
    }

    fn handle(&mut self, line: &str) {
        debug(&format!("event: {line}"));
        let Some(e) = event::parse(line) else {
            log(libc::LOG_WARNING, &format!("not an event: `{line}`"));
            return;
        };
        if e.verb == "lost" && e.class == "devctl" {
            log(libc::LOG_WARNING, &format!("the kernel dropped {} events", e.get("count").unwrap_or("some")));
        }
        let matched: Vec<&Rule> = self.config.rules.iter().filter(|r| r.matches(&e)).collect();
        if matched.is_empty() {
            return;
        }
        for r in &matched {
            debug(&format!("rule: on {}", r.text));
        }
        // SAFETY: single-threaded; the child only runs the shell and exits.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: the child's own copies: signals back to their defaults for what it runs,
            // devd's descriptors closed.
            unsafe {
                for sig in CAUGHT_SIGNALS.into_iter().chain([libc::SIGPIPE]) {
                    libc::signal(sig, libc::SIG_DFL);
                }
                libc::close(self.devctl);
                libc::close(self.wake);
                libc::close(WAKE_FD.load(Ordering::Relaxed));
                libc::close(self.pipe.listener_fd());
                for fd in self.pipe.client_fds() {
                    libc::close(fd);
                }
                libc::setpgid(0, 0);
            }
            run_handlers(&mut self.config.shell, &e, line, &matched);
        }
        if pid < 0 {
            log(libc::LOG_ERR, &format!("fork: {}", std::io::Error::last_os_error()));
            return;
        }
        // Set on both sides, so a kill at the timeout finds the group whichever ran first.
        // SAFETY: plain system calls on our own child.
        unsafe { libc::setpgid(pid, pid) };
        self.wait_child(pid, line);
    }

    /// Waits for handler process `pid`, serving the pipe meanwhile; kills its group at the timeout.
    fn wait_child(&mut self, pid: libc::pid_t, line: &str) {
        let deadline = (self.opts.timeout > 0).then(|| Instant::now() + Duration::from_secs(self.opts.timeout));
        loop {
            let mut status = 0;
            // SAFETY: waitpid on our own child.
            if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
                if libc::WIFSIGNALED(status) {
                    log(libc::LOG_WARNING, &format!("handler for `{line}` killed by signal {}", libc::WTERMSIG(status)));
                }
                return;
            }
            let left = match deadline {
                Some(d) => d.saturating_duration_since(Instant::now()),
                None => Duration::from_secs(1),
            };
            if left.is_zero() {
                log(libc::LOG_WARNING, &format!("handler for `{line}` still running after {} s: killed", self.opts.timeout));
                // SAFETY: our child's process group, then the child.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                return;
            }
            // SIGCHLD wakes the poll; a second at most between looks without it.
            self.poll(false, left.as_millis().clamp(1, 1000) as libc::c_int);
            if CAUGHT.load(Ordering::Relaxed) & (1 << libc::SIGTERM | 1 << libc::SIGINT) != 0 {
                return;
            }
        }
    }

    fn reload(&mut self) {
        log(libc::LOG_INFO, "reloading the configuration");
        self.config = load(&self.files);
    }

    fn run(&mut self) -> ! {
        loop {
            let readable = self.poll(true, -1);
            if caught(libc::SIGTERM) || caught(libc::SIGINT) {
                let _ = std::fs::remove_file(pipe::PATH);
                let _ = std::fs::remove_file(PIDFILE);
                log(libc::LOG_INFO, "exiting");
                std::process::exit(0);
            }
            if caught(libc::SIGHUP) {
                self.reload();
            }
            if caught(libc::SIGCHLD) {
                // What a reloaded configuration's commands left, or a handler's after a kill.
                // SAFETY: waitpid without a status pointer.
                while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
            }
            if readable {
                self.read_events();
            }
        }
    }
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(code) => return code,
    };
    DEBUG.store(opts.debug, Ordering::Relaxed);
    let files = opts.file.clone().map_or_else(rules::default_files, |f| vec![f]);
    if opts.check {
        let (_, clean) = rules::load(&files, &mut |msg| eprintln!("devd: {msg}"));
        return ExitCode::from(if clean { 0 } else { 1 });
    }
    // SAFETY: umask(2) can't fail; a static identity string.
    unsafe {
        libc::umask(0o022);
        libc::openlog(c"devd".as_ptr(), libc::LOG_PID, libc::LOG_DAEMON);
    }

    // Checked before going into the background, so that a second devd says why it exits; taken
    // again by the daemon (a lock doesn't survive the parent's exit on every system).
    if let Err(e) = lock_pidfile() {
        eprintln!("devd: {e}");
        return ExitCode::from(1);
    }
    let path = CString::new(DEVCTL).unwrap();
    // SAFETY: a valid path.
    let devctl = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if devctl < 0 {
        let e = std::io::Error::last_os_error();
        let why = if e.raw_os_error() == Some(libc::EBUSY) { "open already (another devd?)".into() } else { e.to_string() };
        eprintln!("devd: {DEVCTL}: {why}");
        return ExitCode::from(1);
    }
    let pipe = match Pipe::bind(Path::new(pipe::PATH)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("devd: {}: {e}", pipe::PATH);
            return ExitCode::from(1);
        }
    };
    let wake = match catch_signals() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("devd: pipe: {e}");
            return ExitCode::from(1);
        }
    };
    if !opts.debug {
        daemonize();
    }
    let mut pidfile = match lock_pidfile() {
        Ok(f) => f,
        Err(e) => {
            log(libc::LOG_ERR, &e);
            return ExitCode::from(1);
        }
    };
    let _ = pidfile.set_len(0);
    let _ = writeln!(pidfile, "{}", std::process::id());
    // Loaded by the daemon itself: the configuration's commands are its children, `$$` its pid.
    let config = load(&files);
    log(libc::LOG_INFO, &format!("started, {} rules", config.rules.len()));
    let mut devd = Devd { opts, files, config, devctl, wake, pipe, partial: Vec::new() };
    devd.run()
}
