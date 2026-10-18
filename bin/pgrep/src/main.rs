//! `pgrep(1)` and `pkill(1)`: find or signal processes by name and other attributes. One
//! program; run as `pkill` it signals what it finds.
//!
//! ```text
//! pgrep [-aLSfilnoqvx] [-d delim] [-F pidfile] [-G gid] [-P ppid] [-U uid] [-g pgrp]
//!       [-s sid] [-t tty] [-u euid] pattern ...
//! pkill [-signal] [-aILSfilnovx] [-F pidfile] [-G gid] [-P ppid] [-U uid] [-g pgrp]
//!       [-s sid] [-t tty] [-u euid] pattern ...
//! ```
//!
//! FreeBSD's (which NetBSD's and OpenBSD's agree with on everything here). A process is picked
//! when its name (`-f`: its whole argument list) matches any `pattern`, an extended regular
//! expression (`-x`: the whole of it, `-i`: ignoring case), and when it is in every list given
//! (`-G` real group, `-P` parent, `-U` real user, `-u` effective user, `-g` process group, `-s`
//! session, `-t` terminal, `-F` the pid in a file); `-v` turns the choice around, `-n`/`-o` keep
//! only the newest/oldest. The program itself is never picked, nor (without `-a`) any of its
//! ancestors, nor (without `-S`) a system process (a kernel thread: Linux has them, OxideBSD
//! doesn't).
//!
//! pgrep prints the pids, one per line (`-d` sets the separator, `-l` adds the name or with `-f`
//! the arguments, `-q` prints nothing). pkill sends `-signal` (a name with or without `SIG`, in
//! any case, or a number; `TERM` by default); `-I` asks first, `-l` shows each kill.
//!
//! Exit status: 0 if something was picked (pkill: and signalled), 1 if nothing, 2 for a bad
//! command line, 3 for anything else.

mod kinfo;

use kinfo::Proc;
use std::ffi::{CStr, CString};
use std::io::{self, BufRead, BufWriter, Write};
use std::os::unix::io::AsRawFd;
use std::process::ExitCode;

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

/// The highest signal number the kernel takes (OxideBSD: `1..=64`).
const MAX_SIGNAL: i32 = 64;

const STATUS_MATCH: u8 = 0;
const STATUS_NOMATCH: u8 = 1;
const STATUS_BADUSAGE: u8 = 2;
const STATUS_ERROR: u8 = 3;

/// Linux's `PF_KTHREAD`: a kernel thread, FreeBSD's `P_SYSTEM`. OxideBSD's `stat` flags are 0.
const PF_KTHREAD: u64 = 0x0020_0000;

fn signal(s: &str) -> Option<libc::c_int> {
    if let Ok(n) = s.parse::<i32>() {
        return (0..=MAX_SIGNAL).contains(&n).then_some(n);
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    SIGNALS.iter().find(|&&(n, _)| n == name).map(|&(_, v)| v)
}

struct Prog {
    kill: bool,
    name: &'static str,
}

impl Prog {
    fn usage(&self) -> ExitCode {
        if self.kill {
            eprintln!(
                "usage: pkill [-signal] [-aILSfilnovx] [-F pidfile] [-G gid] [-P ppid] [-U uid]\n             \
                 [-g pgrp] [-s sid] [-t tty] [-u euid] pattern ..."
            );
        } else {
            eprintln!(
                "usage: pgrep [-aLSfilnoqvx] [-d delim] [-F pidfile] [-G gid] [-P ppid] [-U uid]\n             \
                 [-g pgrp] [-s sid] [-t tty] [-u euid] pattern ..."
            );
        }
        ExitCode::from(STATUS_BADUSAGE)
    }

    fn fatal(&self, msg: &str) -> ExitCode {
        eprintln!("{}: {msg}", self.name);
        ExitCode::from(STATUS_ERROR)
    }
}

/// A compiled `regcomp(3)` extended regular expression.
struct Regex(Box<libc::regex_t>);

impl Regex {
    fn new(pat: &str, icase: bool) -> Result<Regex, String> {
        let c = CString::new(pat).map_err(|_| "embedded NUL".to_string())?;
        // SAFETY: regcomp initialises the regex_t it's given; on failure regerror describes it.
        unsafe {
            let mut re: Box<libc::regex_t> = Box::new(std::mem::zeroed());
            let flags = libc::REG_EXTENDED | if icase { libc::REG_ICASE } else { 0 };
            let rc = libc::regcomp(&mut *re, c.as_ptr(), flags);
            if rc != 0 {
                let mut buf = [0u8; 256];
                libc::regerror(rc, &*re, buf.as_mut_ptr().cast(), buf.len());
                return Err(CStr::from_ptr(buf.as_ptr().cast()).to_string_lossy().into_owned());
            }
            Ok(Regex(re))
        }
    }

    /// Whether `s` matches; with `whole`, the match must be all of it.
    fn matches(&self, s: &str, whole: bool) -> bool {
        let Ok(c) = CString::new(s) else { return false };
        // SAFETY: the regex is compiled; one regmatch_t is room for the whole match.
        unsafe {
            let mut m: [libc::regmatch_t; 1] = std::mem::zeroed();
            if libc::regexec(&*self.0, c.as_ptr(), 1, m.as_mut_ptr(), 0) != 0 {
                return false;
            }
            !whole || (m[0].rm_so == 0 && m[0].rm_eo as usize == s.len())
        }
    }
}

impl Drop for Regex {
    fn drop(&mut self) {
        // SAFETY: compiled by regcomp.
        unsafe { libc::regfree(&mut *self.0) };
    }
}

#[derive(Default)]
struct Lists {
    euids: Option<Vec<u32>>,
    ruids: Option<Vec<u32>>,
    rgids: Option<Vec<u32>>,
    ppids: Option<Vec<i32>>,
    pgrps: Option<Vec<i32>>,
    sids: Option<Vec<i32>>,
    ttys: Option<Vec<u64>>,
    pidfile: Option<i32>,
}

fn has<T: PartialEq>(l: &Option<Vec<T>>, v: T) -> bool {
    l.as_ref().is_none_or(|l| l.contains(&v))
}

/// The pid in a pid file; with `-L`, the file must be locked (its daemon running).
fn read_pidfile(prog: &Prog, path: &str, must_lock: bool) -> Result<i32, ExitCode> {
    let f = std::fs::File::open(path).map_err(|e| prog.fatal(&format!("Cannot open pidfile `{path}': {}", kinfo::strerror(&e))))?;
    if must_lock {
        // SAFETY: flock on an open descriptor.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if rc == 0 {
            return Err(prog.fatal(&format!("File '{path}' can be locked")));
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(prog.fatal(&format!("Error while locking file '{path}': {}", kinfo::strerror(&e))));
        }
    }
    let mut line = String::new();
    io::BufReader::new(&f).read_line(&mut line).map_err(|e| prog.fatal(&format!("Cannot read from pid file `{path}': {}", kinfo::strerror(&e))))?;
    match line.trim().parse::<i32>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(prog.fatal(&format!("Invalid pid in file `{path}'"))),
    }
}

fn items(arg: &str) -> impl Iterator<Item = &str> {
    arg.split([',', ' ', '\t']).filter(|s| !s.is_empty())
}

fn main() -> ExitCode {
    // SAFETY: restoring a signal's default action.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let argv0 = std::env::args().next().unwrap_or_default();
    let base = argv0.rsplit('/').next().unwrap_or("");
    let prog = if base == "pkill" { Prog { kill: true, name: "pkill" } } else { Prog { kill: false, name: "pgrep" } };
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    let mut sig = libc::SIGTERM;
    if prog.kill {
        if let Some(a) = args.first() {
            if let Some(s) = a.strip_prefix('-').filter(|s| !s.is_empty()).and_then(signal) {
                sig = s;
                args.remove(0);
            }
        }
    }

    let (mut ancestors, mut must_lock, mut kthreads, mut full, mut confirm, mut icase) = (false, false, false, false, false, false);
    let (mut long, mut newest, mut oldest, mut quiet, mut invert, mut exact) = (false, false, false, false, false, false);
    let mut delim = "\n".to_string();
    let mut pidfile: Option<String> = None;
    let mut l = Lists::default();
    let ttys = kinfo::Ttys::scan();
    // SAFETY: none of these have preconditions.
    let (mypid, mypgrp, mysid) = unsafe { (libc::getpid(), libc::getpgrp(), libc::getsid(0)) };
    let mut criteria = false;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        i += 1;
        let b = a.as_bytes();
        let mut j = 1;
        while j < b.len() {
            let c = b[j] as char;
            j += 1;
            let takes = "dFGPUgstu".contains(c);
            let val = if !takes {
                String::new()
            } else if j < b.len() {
                let v = a[j..].to_string();
                j = b.len();
                v
            } else if i < args.len() {
                i += 1;
                args[i - 1].clone()
            } else {
                eprintln!("{}: option requires an argument -- {c}", prog.name);
                return prog.usage();
            };
            macro_rules! list {
                ($field:expr, $parse:expr, $what:expr) => {{
                    criteria = true;
                    let v = $field.get_or_insert_with(Vec::new);
                    for it in items(&val) {
                        match $parse(it) {
                            Some(x) => v.push(x),
                            None => {
                                eprintln!("{}: Unknown {} `{it}'", prog.name, $what);
                                return ExitCode::from(STATUS_BADUSAGE);
                            }
                        }
                    }
                }};
            }
            let num = |s: &str| s.parse::<i32>().ok().filter(|&n| n >= 0);
            match c {
                'a' => ancestors = true,
                'd' if !prog.kill => delim = val,
                'F' => {
                    pidfile = Some(val);
                    criteria = true;
                }
                'f' => full = true,
                'G' => list!(l.rgids, kinfo::group_id, "group"),
                'g' => list!(l.pgrps, |s: &str| num(s).map(|n| if n == 0 { mypgrp } else { n }), "process group"),
                'I' if prog.kill => confirm = true,
                'i' => icase = true,
                'L' => must_lock = true,
                'l' => long = true,
                'n' => newest = true,
                'o' => oldest = true,
                'P' => list!(l.ppids, num, "process ID"),
                'q' if !prog.kill => quiet = true,
                'S' => kthreads = true,
                's' => list!(l.sids, |s: &str| num(s).map(|n| if n == 0 { mysid } else { n }), "session ID"),
                't' => list!(l.ttys, |s: &str| if s == "-" { Some(0) } else { ttys.lookup(s) }, "terminal"),
                'U' => list!(l.ruids, kinfo::user_id, "user"),
                'u' => list!(l.euids, kinfo::user_id, "user"),
                'v' => invert = true,
                'x' => exact = true,
                _ => {
                    eprintln!("{}: illegal option -- {c}", prog.name);
                    return prog.usage();
                }
            }
        }
    }
    let patterns = &args[i..];
    if newest && oldest {
        eprintln!("{}: -n and -o are mutually exclusive", prog.name);
        return prog.usage();
    }
    if must_lock && pidfile.is_none() {
        eprintln!("{}: -L requires -F", prog.name);
        return prog.usage();
    }
    if patterns.is_empty() && !criteria {
        return prog.usage();
    }
    if let Some(f) = &pidfile {
        match read_pidfile(&prog, f, must_lock) {
            Ok(p) => l.pidfile = Some(p),
            Err(code) => return code,
        }
    }
    let mut res = Vec::new();
    for p in patterns {
        match Regex::new(p, icase) {
            Ok(r) => res.push(r),
            Err(e) => {
                eprintln!("{}: Cannot compile regular expression `{p}' ({e})", prog.name);
                return ExitCode::from(STATUS_BADUSAGE);
            }
        }
    }

    let procs = match kinfo::all() {
        Ok(p) => p,
        Err(e) => return prog.fatal(&format!("Cannot get process list: /proc: {}", kinfo::strerror(&e))),
    };
    let target = |p: &Proc| -> String {
        if full && !p.args.is_empty() { p.args.join(" ") } else { p.comm.clone() }
    };
    let skip = |p: &Proc| p.pid == mypid || (!kthreads && p.flags & PF_KTHREAD != 0);
    let mut picked: Vec<&Proc> = procs
        .iter()
        .filter(|p| !skip(p))
        .filter(|p| {
            let m = (res.is_empty() || res.iter().any(|r| r.matches(&target(p), exact)))
                && l.pidfile.is_none_or(|f| f == p.pid)
                && has(&l.euids, p.euid)
                && has(&l.ruids, p.ruid)
                && has(&l.rgids, p.rgid)
                && has(&l.ppids, p.ppid)
                && has(&l.pgrps, p.pgid)
                && has(&l.sids, p.sid)
                && has(&l.ttys, p.tty);
            m != invert
        })
        .collect();
    if !ancestors {
        let mut chain = Vec::new();
        let mut pid = mypid;
        while pid > 0 && !chain.contains(&pid) {
            chain.push(pid);
            pid = procs.iter().find(|p| p.pid == pid).map_or(0, |p| p.ppid);
        }
        picked.retain(|p| !chain.contains(&p.pid));
    }
    if newest || oldest {
        let key = |p: &&Proc| (p.start, p.pid);
        let one = if newest { picked.iter().copied().max_by_key(key) } else { picked.iter().copied().min_by_key(key) };
        picked = one.into_iter().collect();
    }

    let mut out = BufWriter::new(io::stdout().lock());
    let mut matched = 0usize;
    if prog.kill {
        let stdin = io::stdin();
        for p in &picked {
            if confirm {
                let _ = write!(out, "kill {} {}? ", p.pid, target(p));
                let _ = out.flush();
                let mut ans = String::new();
                if stdin.lock().read_line(&mut ans).unwrap_or(0) == 0 {
                    break;
                }
                if !ans.trim_start().starts_with(['y', 'Y']) {
                    continue;
                }
            }
            // SAFETY: kill has no memory preconditions.
            if unsafe { libc::kill(p.pid, sig) } == -1 {
                let e = io::Error::last_os_error();
                // Gone between being read and being signalled: not a match.
                if e.raw_os_error() != Some(libc::ESRCH) {
                    let _ = out.flush();
                    eprintln!("{}: signalling pid {}: {}", prog.name, p.pid, kinfo::strerror(&e));
                }
                continue;
            }
            matched += 1;
            if long {
                let _ = writeln!(out, "kill -{sig} {}", p.pid);
            }
        }
    } else {
        matched = picked.len();
        if !quiet {
            let mut first = true;
            for p in &picked {
                if !first {
                    let _ = write!(out, "{delim}");
                }
                first = false;
                if long {
                    let _ = write!(out, "{} {}", p.pid, target(p));
                } else {
                    let _ = write!(out, "{}", p.pid);
                }
            }
            if !first {
                let _ = writeln!(out);
            }
        }
    }
    if let Err(e) = out.flush() {
        return prog.fatal(&format!("stdout: {}", kinfo::strerror(&e)));
    }
    ExitCode::from(if matched > 0 { STATUS_MATCH } else { STATUS_NOMATCH })
}
