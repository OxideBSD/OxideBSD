//! `timeout(1)`: runs a command with a time limit.
//!
//! ```text
//! timeout [-f] [-k time] [-p] [-s signal] [-v] duration command [arg ...]
//! ```
//!
//! After `duration` the command gets `signal` (`-s`, default `TERM`), and, with `-k`, `KILL`
//! when it is still running `time` later; a stopped command also gets a `CONT`. Durations are
//! numbers, fractions allowed, of seconds or, with a suffix, `s`, `m`, `h` or `d`; 0 means no
//! limit. Terminating signals sent to timeout itself are passed on (and treated as the time
//! running out early), other signals just passed on.
//!
//! Unless `-f` (`--foreground`), the command runs in a process group of its own, and the
//! signals go to the whole group, the command's own children too (FreeBSD makes timeout a
//! reaper for this, `procctl(2)` `PROC_REAP_KILL`, which OxideBSD doesn't have). With `-f` only
//! the command is signalled, and it stays in timeout's process group, so it may read the
//! terminal. `-v` reports each signal sent on the standard error.
//!
//! Exit status: 124 if the time ran out (unless `-p`, `--preserve-status`, which always gives
//! the command's), 125 if timeout itself failed, 126 if the command couldn't be run, 127 if it
//! wasn't found, else the command's. A command killed by a signal kills timeout with the same
//! signal (core dumps off), so the shell sees what happened (POSIX.1-2024).
//! Long options: `--foreground`, `--kill-after`, `--preserve-status`, `--signal`, `--verbose`.

use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};

const EXIT_TIMEOUT: u8 = 124;
const EXIT_INVALID: u8 = 125;
const EXIT_CMD_ERROR: i32 = 126;
const EXIT_CMD_NOENT: i32 = 127;

const SIGNALS: [(&str, libc::c_int); 31] = [
    ("HUP", libc::SIGHUP),
    ("INT", libc::SIGINT),
    ("QUIT", libc::SIGQUIT),
    ("ILL", libc::SIGILL),
    ("TRAP", libc::SIGTRAP),
    ("ABRT", libc::SIGABRT),
    ("BUS", libc::SIGBUS),
    ("FPE", libc::SIGFPE),
    ("KILL", libc::SIGKILL),
    ("USR1", libc::SIGUSR1),
    ("SEGV", libc::SIGSEGV),
    ("USR2", libc::SIGUSR2),
    ("PIPE", libc::SIGPIPE),
    ("ALRM", libc::SIGALRM),
    ("TERM", libc::SIGTERM),
    ("STKFLT", libc::SIGSTKFLT),
    ("CHLD", libc::SIGCHLD),
    ("CONT", libc::SIGCONT),
    ("STOP", libc::SIGSTOP),
    ("TSTP", libc::SIGTSTP),
    ("TTIN", libc::SIGTTIN),
    ("TTOU", libc::SIGTTOU),
    ("URG", libc::SIGURG),
    ("XCPU", libc::SIGXCPU),
    ("XFSZ", libc::SIGXFSZ),
    ("VTALRM", libc::SIGVTALRM),
    ("PROF", libc::SIGPROF),
    ("WINCH", libc::SIGWINCH),
    ("IO", libc::SIGIO),
    ("PWR", libc::SIGPWR),
    ("SYS", libc::SIGSYS),
];

/// What the signal handler saw, for the loop around `sigsuspend(2)`.
static GOT_CHLD: AtomicI32 = AtomicI32::new(0);
static GOT_ALRM: AtomicI32 = AtomicI32::new(0);
/// A terminating signal to pass on (or the kill signal itself).
static GOT_TERM: AtomicI32 = AtomicI32::new(0);
/// Any other signal to pass on.
static GOT_OTHER: AtomicI32 = AtomicI32::new(0);
static KILL_SIG: AtomicI32 = AtomicI32::new(libc::SIGTERM);

extern "C" fn on_signal(sig: libc::c_int) {
    if sig == KILL_SIG.load(Ordering::Relaxed) {
        GOT_TERM.store(sig, Ordering::Relaxed);
        return;
    }
    match sig {
        libc::SIGCHLD => GOT_CHLD.store(1, Ordering::Relaxed),
        libc::SIGALRM => GOT_ALRM.store(1, Ordering::Relaxed),
        // The signals whose default action ends a process.
        libc::SIGHUP
        | libc::SIGINT
        | libc::SIGQUIT
        | libc::SIGILL
        | libc::SIGTRAP
        | libc::SIGABRT
        | libc::SIGFPE
        | libc::SIGBUS
        | libc::SIGSEGV
        | libc::SIGSYS
        | libc::SIGPIPE
        | libc::SIGTERM
        | libc::SIGXCPU
        | libc::SIGXFSZ
        | libc::SIGVTALRM
        | libc::SIGPROF
        | libc::SIGUSR1
        | libc::SIGUSR2
        | libc::SIGSTKFLT
        | libc::SIGIO
        | libc::SIGPWR => GOT_TERM.store(sig, Ordering::Relaxed),
        _ => GOT_OTHER.store(sig, Ordering::Relaxed),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: timeout [-f] [-k time] [-p] [-s signal] [-v] duration command [arg ...]");
    ExitCode::from(EXIT_INVALID)
}

fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a NUL-terminated string.
    unsafe { CStr::from_ptr(libc::strerror(n)) }
        .to_string_lossy()
        .into_owned()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn sig_name(sig: libc::c_int) -> String {
    SIGNALS
        .iter()
        .find(|&&(_, v)| v == sig)
        .map_or_else(|| sig.to_string(), |&(n, _)| n.to_string())
}

/// A signal by name (with or without `SIG`, in any case) or number.
fn parse_signal(s: &str) -> Option<libc::c_int> {
    if let Ok(n) = s.parse::<libc::c_int>() {
        return SIGNALS.iter().any(|&(_, v)| v == n).then_some(n);
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    SIGNALS.iter().find(|&&(n, _)| n == name).map(|&(_, v)| v)
}

/// A duration in seconds: a number (`strtod(3)`'s) with an optional `s`, `m`, `h` or `d`.
fn parse_duration(s: &str) -> Result<f64, &'static str> {
    let c = CString::new(s).map_err(|_| "duration is not a number")?;
    let mut end: *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: a NUL-terminated string; strtod sets end inside it.
    let mut v = unsafe { libc::strtod(c.as_ptr(), &mut end) };
    // SAFETY: end points into c.
    let consumed = unsafe { end.offset_from(c.as_ptr()) } as usize;
    if consumed == 0 {
        return Err("duration is not a number");
    }
    match &s.as_bytes()[consumed..] {
        b"" | b"s" => {}
        b"m" => v *= 60.0,
        b"h" => v *= 3600.0,
        b"d" => v *= 86400.0,
        [_] => return Err("duration unit suffix invalid"),
        _ => return Err("duration unit suffix too long"),
    }
    if v.is_nan() || v < 0.0 || v >= 100_000_000.0 {
        return Err("duration out of range");
    }
    Ok(v)
}

/// Arms (or, for 0, disarms) the one real-time timer.
fn set_interval(secs: f64) {
    let whole = secs.trunc();
    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: whole as libc::time_t,
            tv_usec: ((secs - whole) * 1e6) as libc::suseconds_t,
        },
    };
    // SAFETY: a valid itimerval; the old value isn't wanted.
    if unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) } != 0 {
        eprintln!("timeout: setitimer: {}", strerror(errno()));
        std::process::exit(EXIT_INVALID.into());
    }
}

struct Run {
    pid: libc::pid_t,
    foreground: bool,
    verbose: bool,
    command: String,
}

impl Run {
    fn log(&self, msg: std::fmt::Arguments) {
        if self.verbose {
            eprintln!("timeout: {msg}");
        }
    }

    /// Signals the command (and, without -f, its process group), then CONTs it, in case it
    /// was stopped.
    fn send(&self, sig: libc::c_int) {
        let target = if self.foreground { self.pid } else { -self.pid };
        for s in [sig, libc::SIGCONT] {
            if s == libc::SIGCONT && matches!(sig, libc::SIGKILL | libc::SIGSTOP | libc::SIGCONT) {
                break;
            }
            self.log(format_args!(
                "sending signal {}({}) to command '{}'",
                sig_name(s),
                s,
                self.command
            ));
            // SAFETY: kill(2) with a pid and a signal number.
            if unsafe { libc::kill(target, s) } != 0 && errno() != libc::ESRCH && s == sig {
                eprintln!(
                    "timeout: kill({}, {}): {}",
                    target,
                    sig_name(s),
                    strerror(errno())
                );
            }
        }
    }
}

/// Dies of `sig`, as the command did, without leaving a core.
fn kill_self(sig: libc::c_int) -> ! {
    // SAFETY: plain system calls on our own process.
    unsafe {
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
        libc::signal(sig, libc::SIG_DFL);
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut mask);
        libc::sigdelset(&mut mask, sig);
        libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
        libc::raise(sig);
    }
    std::process::exit(128 + sig)
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (mut foreground, mut preserve, mut verbose) = (false, false, false);
    let mut second_kill: Option<f64> = None;
    let mut i = 0;
    // The value of an option: the rest of this word, or the next word.
    macro_rules! value {
        ($rest:expr, $name:expr) => {{
            if !$rest.is_empty() {
                $rest.to_string()
            } else {
                i += 1;
                match args.get(i) {
                    Some(v) => v.to_string_lossy().into_owned(),
                    None => {
                        eprintln!("timeout: option requires an argument -- {}", $name);
                        return usage();
                    }
                }
            }
        }};
    }
    while i < args.len() {
        let a = args[i].to_string_lossy().into_owned();
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            match (name, inline) {
                ("foreground", None) => foreground = true,
                ("preserve-status", None) => preserve = true,
                ("verbose", None) => verbose = true,
                ("kill-after" | "signal", _) => {
                    let v = value!(inline.unwrap_or(""), name);
                    if name == "signal" {
                        match parse_signal(&v) {
                            Some(s) => KILL_SIG.store(s, Ordering::Relaxed),
                            None => {
                                eprintln!("timeout: invalid signal");
                                return ExitCode::from(EXIT_INVALID);
                            }
                        }
                    } else {
                        match parse_duration(&v) {
                            Ok(d) => second_kill = Some(d),
                            Err(e) => {
                                eprintln!("timeout: {e}");
                                return ExitCode::from(EXIT_INVALID);
                            }
                        }
                    }
                }
                _ => {
                    eprintln!("timeout: unrecognized option '{a}'");
                    return usage();
                }
            }
            i += 1;
            continue;
        }
        if a.len() < 2 || !a.starts_with('-') {
            break;
        }
        let mut chars = a[1..].char_indices();
        while let Some((at, c)) = chars.next() {
            match c {
                'f' => foreground = true,
                'p' => preserve = true,
                'v' => verbose = true,
                'k' | 's' => {
                    let v = value!(&a[at + 2..], c);
                    if c == 's' {
                        match parse_signal(&v) {
                            Some(s) => KILL_SIG.store(s, Ordering::Relaxed),
                            None => {
                                eprintln!("timeout: invalid signal");
                                return ExitCode::from(EXIT_INVALID);
                            }
                        }
                    } else {
                        match parse_duration(&v) {
                            Ok(d) => second_kill = Some(d),
                            Err(e) => {
                                eprintln!("timeout: {e}");
                                return ExitCode::from(EXIT_INVALID);
                            }
                        }
                    }
                    break;
                }
                _ => {
                    eprintln!("timeout: illegal option -- {c}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    let rest = &args[i..];
    if rest.len() < 2 {
        return usage();
    }
    let first_kill = match parse_duration(&rest[0].to_string_lossy()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("timeout: {e}");
            return ExitCode::from(EXIT_INVALID);
        }
    };
    let argv: Vec<CString> = rest[1..]
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_default())
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let command = rest[1].to_string_lossy().into_owned();
    let exec_failed = format!("timeout: exec({command})");

    // SAFETY: from here on, plain POSIX calls on valid arguments; the child of fork(2) only
    // makes system calls (this program has one thread) before it execs or exits.
    unsafe {
        // Block everything until the handlers are in place, so nothing is lost or acted on early.
        let (mut all, mut old): (libc::sigset_t, libc::sigset_t) =
            (std::mem::zeroed(), std::mem::zeroed());
        libc::sigfillset(&mut all);
        libc::sigprocmask(libc::SIG_BLOCK, &all, &mut old);
        let mut pp = [0 as libc::c_int; 2];
        if libc::pipe(pp.as_mut_ptr()) != 0 {
            eprintln!("timeout: pipe: {}", strerror(errno()));
            return ExitCode::from(EXIT_INVALID);
        }
        for fd in pp {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("timeout: fork: {}", strerror(errno()));
            return ExitCode::from(EXIT_INVALID);
        }
        if pid == 0 {
            if !foreground {
                libc::setpgid(0, 0);
            }
            // The command gets the dispositions timeout was given, but for the kill signal, and
            // a default SIGPIPE (std's runtime ignores it).
            libc::signal(KILL_SIG.load(Ordering::Relaxed), libc::SIG_DFL);
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
            libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
            libc::close(pp[1]);
            let mut c = 0u8;
            // Wait until the parent is ready (or gone).
            if libc::read(pp[0], (&raw mut c).cast(), 1) != 1 {
                libc::_exit(EXIT_INVALID.into());
            }
            libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
            let e = errno();
            eprintln!("{exec_failed}: {}", strerror(e));
            libc::_exit(if e == libc::ENOENT {
                EXIT_CMD_NOENT
            } else {
                EXIT_CMD_ERROR
            });
        }
        if !foreground {
            libc::setpgid(pid, pid); // as the child does, whichever runs first
        }
        libc::close(pp[0]);

        // Catch every signal to pass it on; a background command's tty reads mustn't stop us.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::sigfillset(&mut sa.sa_mask);
        sa.sa_flags = libc::SA_RESTART;
        for sig in 1..32 {
            match sig {
                libc::SIGTTIN | libc::SIGTTOU => {
                    libc::signal(sig, libc::SIG_IGN);
                }
                libc::SIGKILL | libc::SIGSTOP | libc::SIGCONT => {}
                _ => {
                    libc::sigaction(sig, &sa, std::ptr::null_mut());
                }
            }
        }
        set_interval(first_kill);
        if libc::write(pp[1], b"a".as_ptr().cast(), 1) != 1 {
            eprintln!("timeout: write to control pipe: {}", strerror(errno()));
            return ExitCode::from(EXIT_INVALID);
        }
        libc::close(pp[1]);

        let run = Run {
            pid,
            foreground,
            verbose,
            command,
        };
        let mut timed_out = false;
        let status;
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        'wait: loop {
            libc::sigsuspend(&none);
            if GOT_CHLD.swap(0, Ordering::Relaxed) != 0 {
                let mut st = 0;
                loop {
                    let r = libc::waitpid(-1, &mut st, libc::WNOHANG);
                    if r == pid {
                        status = st;
                        if libc::WIFEXITED(st) {
                            run.log(format_args!(
                                "child terminated: pid={pid}, exit={}",
                                libc::WEXITSTATUS(st)
                            ));
                        } else if libc::WIFSIGNALED(st) {
                            run.log(format_args!(
                                "child terminated: pid={pid}, sig={}",
                                libc::WTERMSIG(st)
                            ));
                        }
                        break 'wait;
                    }
                    if r <= 0 {
                        break;
                    }
                }
            } else if GOT_ALRM.load(Ordering::Relaxed) != 0 || GOT_TERM.load(Ordering::Relaxed) != 0
            {
                let sig = if GOT_ALRM.swap(0, Ordering::Relaxed) != 0 {
                    timed_out = true;
                    run.log(format_args!("time limit reached or received SIGALRM"));
                    KILL_SIG.load(Ordering::Relaxed)
                } else {
                    let s = GOT_TERM.swap(0, Ordering::Relaxed);
                    run.log(format_args!(
                        "received terminating signal {}({s})",
                        sig_name(s)
                    ));
                    s
                };
                run.send(sig);
                if let Some(d) = second_kill.take() {
                    set_interval(d);
                    KILL_SIG.store(libc::SIGKILL, Ordering::Relaxed);
                }
            } else if GOT_OTHER.load(Ordering::Relaxed) != 0 {
                let s = GOT_OTHER.swap(0, Ordering::Relaxed);
                run.log(format_args!("received signal {}({s})", sig_name(s)));
                run.send(s);
            }
        }
        if timed_out && !preserve {
            ExitCode::from(EXIT_TIMEOUT)
        } else if libc::WIFSIGNALED(status) {
            run.log(format_args!(
                "killing self with signal {}({})",
                sig_name(libc::WTERMSIG(status)),
                libc::WTERMSIG(status)
            ));
            kill_self(libc::WTERMSIG(status))
        } else if libc::WIFEXITED(status) {
            ExitCode::from(libc::WEXITSTATUS(status) as u8)
        } else {
            ExitCode::FAILURE
        }
    }
}
