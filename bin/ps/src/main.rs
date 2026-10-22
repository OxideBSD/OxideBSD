//! `ps(1)`: process status, the BSD way.
//!
//! ```text
//! ps [-AaCcefHjlmrSTuvwXx] [-O fmt | -o fmt] [-G gid[,gid...]] [-p pid[,pid...]]
//!    [-t tty[,tty...]] [-U user[,user...]]
//! ps -L
//! ```
//!
//! FreeBSD's ps, with what the three BSDs agree on: by default your own processes that have a
//! controlling terminal, in the columns `PID TT STAT TIME COMMAND`, sorted by terminal and then
//! pid. `-a` adds other users' processes, `-x` those without a terminal (`-A` is both); `-G`,
//! `-p`, `-t`, `-T` and `-U` select instead (any of them matching keeps a process), and all but
//! `-t`/`-T` imply `-x`. `-j`, `-l`, `-u` and `-v` are FreeBSD's canned formats (`-u` sorts by
//! CPU, `-v` by memory), `-o` gives the columns (`keyword[=header]`), `-O` adds columns after the
//! pid. The leading `-` may be left out (`ps ax`), and a trailing pid works as `-p`.
//!
//! The kernel process, pid 0, is `[kernel]`; `-H` shows each of its threads instead, as
//! `[kernel/<name>]` (`/proc/0/task`, OxideBSD-doc `KTHREAD.md` §8.2). A user thread has a `/proc`
//! entry, so a line, of its own already.
//!
//! Everything comes from `/proc` (see `kinfo.rs`). What OxideBSD's `/proc` doesn't tell (wait
//! channels, job-control counts, page-ins, ...) prints as `-`. `%cpu` is the CPU time over the
//! time since the process started (the kernel keeps no decaying average); `STAT`'s `I` (idle for
//! over 20 seconds) can't be told from `S`, since no sleep time is kept.

mod kinfo;

use kinfo::{Proc, Ttys};
use std::collections::HashMap;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum K {
    Pcpu,
    Pmem,
    Args,
    Comm,
    Ucomm,
    Time,
    Etime,
    Etimes,
    Uid,
    Ruid,
    Svuid,
    Gid,
    Rgid,
    Svgid,
    User,
    Ruser,
    Group,
    Rgroup,
    Flags,
    Lstart,
    Start,
    Nice,
    Nlwp,
    Pgid,
    Pid,
    Ppid,
    Pri,
    Rss,
    Vsz,
    Sid,
    Tsid,
    Stat,
    Systime,
    Usertime,
    Tdev,
    Tt,
    Tty,
    Tpgid,
    Wchan,
    Sigmask,
    Pending,
    Sigignore,
    Sigcatch,
    Minflt,
    Majflt,
    Tid,
    Rtprio,
    Jid,
    /// Something `/proc` doesn't say.
    Dash,
}

/// Every keyword FreeBSD's ps knows: name, header, meaning, whether it's right-aligned.
const KEYWORDS: &[(&str, &str, K, bool)] = &[
    ("%cpu", "%CPU", K::Pcpu, true),
    ("%mem", "%MEM", K::Pmem, true),
    ("acflag", "ACFLG", K::Dash, true),
    ("acflg", "ACFLG", K::Dash, true),
    ("args", "COMMAND", K::Args, false),
    ("class", "CLASS", K::Dash, false),
    ("comm", "COMMAND", K::Comm, false),
    ("command", "COMMAND", K::Args, false),
    ("cow", "COW", K::Dash, true),
    ("cpu", "C", K::Dash, true),
    ("cputime", "TIME", K::Time, true),
    ("dsiz", "DSIZ", K::Dash, true),
    ("emul", "EMUL", K::Dash, false),
    ("etime", "ELAPSED", K::Etime, true),
    ("etimes", "ELAPSED", K::Etimes, true),
    ("euid", "UID", K::Uid, true),
    ("f", "F", K::Flags, true),
    ("flags", "F", K::Flags, true),
    ("gid", "GID", K::Gid, true),
    ("group", "GROUP", K::Group, false),
    ("inblk", "INBLK", K::Dash, true),
    ("jid", "JID", K::Jid, true),
    ("jobc", "JOBC", K::Dash, true),
    ("ktrace", "KTRACE", K::Dash, true),
    ("label", "LABEL", K::Dash, false),
    ("lim", "LIM", K::Dash, true),
    ("lockname", "LOCK", K::Dash, false),
    ("login", "LOGIN", K::Dash, false),
    ("logname", "LOGIN", K::Dash, false),
    ("lstart", "STARTED", K::Lstart, false),
    ("lwp", "LWP", K::Tid, true),
    ("majflt", "MAJFLT", K::Majflt, true),
    ("minflt", "MINFLT", K::Minflt, true),
    ("msgrcv", "MSGRCV", K::Dash, true),
    ("msgsnd", "MSGSND", K::Dash, true),
    ("mwchan", "MWCHAN", K::Wchan, false),
    ("ni", "NI", K::Nice, true),
    ("nice", "NI", K::Nice, true),
    ("nivcsw", "NIVCSW", K::Dash, true),
    ("nlwp", "NLWP", K::Nlwp, true),
    ("nsigs", "NSIGS", K::Dash, true),
    ("nswap", "NSWAP", K::Dash, true),
    ("nvcsw", "NVCSW", K::Dash, true),
    ("nwchan", "NWCHAN", K::Dash, false),
    ("oublk", "OUBLK", K::Dash, true),
    ("oublock", "OUBLK", K::Dash, true),
    ("paddr", "PADDR", K::Dash, true),
    ("pagein", "PAGEIN", K::Majflt, true),
    ("pcpu", "%CPU", K::Pcpu, true),
    ("pending", "PENDING", K::Pending, true),
    ("pgid", "PGID", K::Pgid, true),
    ("pid", "PID", K::Pid, true),
    ("pmem", "%MEM", K::Pmem, true),
    ("ppid", "PPID", K::Ppid, true),
    ("pri", "PRI", K::Pri, true),
    ("re", "RE", K::Dash, true),
    ("rgid", "RGID", K::Rgid, true),
    ("rgroup", "RGROUP", K::Rgroup, false),
    ("rss", "RSS", K::Rss, true),
    ("rssize", "RSS", K::Rss, true),
    ("rsz", "RSZ", K::Rss, true),
    ("rtprio", "RTPRIO", K::Rtprio, false),
    ("ruid", "RUID", K::Ruid, true),
    ("ruser", "RUSER", K::Ruser, false),
    ("sid", "SID", K::Sid, true),
    ("sig", "PENDING", K::Pending, true),
    ("sigcatch", "CAUGHT", K::Sigcatch, true),
    ("sigignore", "IGNORED", K::Sigignore, true),
    ("sigmask", "BLOCKED", K::Sigmask, true),
    ("sl", "SL", K::Dash, true),
    ("ssiz", "SSIZ", K::Dash, true),
    ("start", "STARTED", K::Start, false),
    ("stat", "STAT", K::Stat, false),
    ("state", "STAT", K::Stat, false),
    ("svgid", "SVGID", K::Svgid, true),
    ("svuid", "SVUID", K::Svuid, true),
    ("systime", "SYSTIME", K::Systime, true),
    ("tdaddr", "TDADDR", K::Dash, true),
    ("tdev", "TDEV", K::Tdev, true),
    ("tdnam", "TDNAM", K::Dash, false),
    ("tid", "TID", K::Tid, true),
    ("time", "TIME", K::Time, true),
    ("tpgid", "TPGID", K::Tpgid, true),
    ("tracer", "TRACER", K::Dash, true),
    ("tsid", "TSID", K::Tsid, true),
    ("tsiz", "TSIZ", K::Dash, true),
    ("tt", "TT", K::Tt, false),
    ("tty", "TTY", K::Tty, false),
    ("ucomm", "UCOMM", K::Ucomm, false),
    ("uid", "UID", K::Uid, true),
    ("upr", "UPR", K::Dash, true),
    ("uprocp", "UPROCP", K::Dash, true),
    ("user", "USER", K::User, false),
    ("usertime", "USERTIME", K::Usertime, true),
    ("vsize", "VSZ", K::Vsz, true),
    ("vsz", "VSZ", K::Vsz, true),
    ("wchan", "WCHAN", K::Wchan, false),
    ("xstat", "XSTAT", K::Dash, true),
];

const DFMT: &str = "pid,tt,state,time,command";
const JFMT: &str = "user,pid,ppid,pgid,sid,jobc,state,tt,time,command";
const LFMT: &str = "uid,pid,ppid,cpu,pri,nice,vsz,rss,mwchan,state,tt,time,command";
const UFMT: &str = "user,pid,%cpu,%mem,vsz,rss,tt,state,start,time,command";
const VFMT: &str = "pid,state,time,sl,re,pagein,vsz,rss,lim,tsiz,%cpu,%mem,command";

#[derive(Clone)]
struct Col {
    k: K,
    header: String,
    right: bool,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: ps [-AaCcefHjlmrSTuvwXx] [-O fmt | -o fmt] [-G gid[,gid...]]\n          \
         [-p pid[,pid...]] [-t tty[,tty...]] [-U user[,user...]]\n       ps -L"
    );
    ExitCode::from(1)
}

/// Parses a format list into columns. The header after a keyword's `=` runs to the end of the
/// argument (POSIX's rule, which FreeBSD follows), so it may hold commas and blanks.
fn parse_fmt(fmt: &str, cols: &mut Vec<Col>) -> Result<(), String> {
    let mut rest = fmt;
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',', '\n']);
        if rest.is_empty() {
            return Ok(());
        }
        let end = rest.find([' ', '\t', ',', '\n', '=']).unwrap_or(rest.len());
        let name = &rest[..end];
        let (header, next) = if rest[end..].starts_with('=') {
            (Some(rest[end + 1..].to_string()), "")
        } else {
            (None, &rest[end..])
        };
        let Some(&(_, h, k, right)) = KEYWORDS.iter().find(|kw| kw.0 == name) else {
            return Err(format!("{name}: keyword not found"));
        };
        cols.push(Col { k, header: header.unwrap_or_else(|| h.to_string()), right });
        rest = next;
    }
}

fn list_keywords() -> ExitCode {
    let mut out = BufWriter::new(io::stdout().lock());
    let mut col = 0;
    for (name, ..) in KEYWORDS {
        if col + name.len() + 1 > 79 {
            let _ = writeln!(out);
            col = 0;
        }
        if col > 0 {
            let _ = write!(out, " ");
            col += 1;
        }
        let _ = write!(out, "{name}");
        col += name.len();
    }
    let _ = writeln!(out);
    match out.flush() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

/// The terminal width output is cut to: none when it isn't a terminal, else `COLUMNS` or the
/// window size, less one (FreeBSD's); `-w` makes it at least 131, `-ww` unlimited.
fn term_width(wflag: u32) -> usize {
    if wflag >= 2 || !io::stdout().is_terminal() {
        return usize::MAX;
    }
    let mut w = std::env::var("COLUMNS").ok().and_then(|c| c.parse::<usize>().ok()).filter(|&c| c > 0);
    if w.is_none() {
        // SAFETY: TIOCGWINSZ fills a winsize.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
            w = Some(ws.ws_col as usize);
        }
    }
    let w = w.map_or(79, |c| c.saturating_sub(1).max(1));
    if wflag == 1 { w.max(131) } else { w }
}

/// The time of day as `strftime` formats it, local time.
fn strftime(t: i64, fmt: &str) -> String {
    let fmt = std::ffi::CString::new(fmt).unwrap();
    // time_t is 64 bits on every target here.
    let tt: i64 = t;
    // SAFETY: localtime_r fills tm from tt; strftime writes at most buf.len() bytes.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r((&tt as *const i64).cast(), &mut tm).is_null() {
            return "-".into();
        }
        let mut buf = [0u8; 64];
        let n = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), &tm);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

fn now() -> i64 {
    // SAFETY: clock_gettime fills ts.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    ts.tv_sec as i64
}

/// FreeBSD's CPU time format: minutes, seconds and hundredths.
fn cputime(ticks: u64, hz: u64) -> String {
    let secs = ticks / hz;
    let centis = (ticks % hz) * 100 / hz;
    format!("{}:{:02}.{:02}", secs / 60, secs % 60, centis)
}

/// `[[dd-]hh:]mm:ss`.
fn elapsed(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}-{h:02}:{m:02}:{s:02}")
    } else if h > 0 {
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

/// Printable: control characters become `?`.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

struct Ctx {
    hz: u64,
    page_kb: u64,
    mem_kb: u64,
    uptime_ticks: u64,
    boot: i64,
    now: i64,
    ttys: Ttys,
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
    comm_only: bool,
    env: bool,
    child_times: bool,
}

impl Ctx {
    fn user(&mut self, uid: u32) -> String {
        self.users.entry(uid).or_insert_with(|| kinfo::user_name(uid).unwrap_or_else(|| uid.to_string())).clone()
    }

    fn group(&mut self, gid: u32) -> String {
        self.groups.entry(gid).or_insert_with(|| kinfo::group_name(gid).unwrap_or_else(|| gid.to_string())).clone()
    }

    fn ticks(&self, p: &Proc) -> u64 {
        let mut t = p.utime + p.stime;
        if self.child_times {
            t += p.cutime + p.cstime;
        }
        t
    }

    fn pcpu(&self, p: &Proc) -> f64 {
        let life = self.uptime_ticks.saturating_sub(p.start);
        if life == 0 || p.state == b'Z' {
            return 0.0;
        }
        (p.utime + p.stime) as f64 * 100.0 / life as f64
    }

    fn rss_kb(&self, p: &Proc, rss: &mut Option<u64>) -> u64 {
        *rss.get_or_insert_with(|| kinfo::rss_pages(p)) * self.page_kb
    }
}

/// BSD's `STAT`: the state, then `<` (raised priority) or `N` (lowered), `V` (a vfork child
/// borrowing its parent's memory), `s` (session leader), `+` (in its terminal's foreground
/// process group).
fn stat_string(p: &Proc) -> String {
    let mut s = String::new();
    s.push(match p.state {
        b'R' => 'R',
        b'S' => 'S',
        b'I' => 'I',
        b'D' => 'D',
        b'T' | b't' => 'T',
        b'Z' | b'X' | b'x' => 'Z',
        b'W' => 'W',
        _ => '?',
    });
    if p.nice < 0 || p.priority < 0 {
        s.push('<');
    } else if p.nice > 0 {
        s.push('N');
    }
    if p.ppwait {
        s.push('V');
    }
    if p.pid == p.sid && p.sid > 0 {
        s.push('s');
    }
    if p.tty != 0 && p.tpgid >= 0 && p.pgid == p.tpgid {
        s.push('+');
    }
    s
}

fn field(c: &Col, p: &Proc, cx: &mut Ctx, rss: &mut Option<u64>) -> String {
    match c.k {
        K::Pcpu => format!("{:.1}", cx.pcpu(p)),
        K::Pmem => {
            let r = cx.rss_kb(p, rss);
            if cx.mem_kb == 0 { "0.0".into() } else { format!("{:.1}", r as f64 * 100.0 / cx.mem_kb as f64) }
        }
        K::Args | K::Comm | K::Ucomm => {
            if p.state == b'Z' && c.k != K::Ucomm {
                return "<defunct>".into();
            }
            let mut s = if c.k != K::Args || cx.comm_only {
                clean(&p.comm)
            } else if p.args.is_empty() {
                format!("[{}]", clean(&p.comm))
            } else {
                clean(&p.args.join(" "))
            };
            if cx.env && c.k == K::Args {
                for e in kinfo::environ(p.pid) {
                    s.push(' ');
                    s.push_str(&clean(&e));
                }
            }
            s
        }
        K::Time => cputime(cx.ticks(p), cx.hz),
        K::Systime => cputime(p.stime + if cx.child_times { p.cstime } else { 0 }, cx.hz),
        K::Usertime => cputime(p.utime + if cx.child_times { p.cutime } else { 0 }, cx.hz),
        K::Etime => elapsed(cx.uptime_ticks.saturating_sub(p.start) / cx.hz),
        K::Etimes => (cx.uptime_ticks.saturating_sub(p.start) / cx.hz).to_string(),
        K::Uid => p.euid.to_string(),
        K::Ruid => p.ruid.to_string(),
        K::Svuid => p.suid.to_string(),
        K::Gid => p.egid.to_string(),
        K::Rgid => p.rgid.to_string(),
        K::Svgid => p.sgid.to_string(),
        K::User => cx.user(p.euid),
        K::Ruser => cx.user(p.ruid),
        K::Group => cx.group(p.egid),
        K::Rgroup => cx.group(p.rgid),
        K::Flags => format!("{:x}", p.flags),
        K::Start | K::Lstart => {
            let t = cx.boot + (p.start / cx.hz) as i64;
            if c.k == K::Lstart {
                strftime(t, "%a %b %e %T %Y")
            } else if cx.now - t < 24 * 3600 {
                strftime(t, "%H:%M")
            } else if cx.now - t < 7 * 86400 {
                strftime(t, "%a%H")
            } else {
                strftime(t, "%e%b%y")
            }
        }
        K::Nice => p.nice.to_string(),
        K::Nlwp => p.nlwp.max(1).to_string(),
        K::Pgid => p.pgid.to_string(),
        K::Pid | K::Tid => p.pid.to_string(),
        K::Ppid => p.ppid.to_string(),
        K::Pri => p.priority.to_string(),
        K::Rss => cx.rss_kb(p, rss).to_string(),
        K::Vsz => (p.vsize / 1024).to_string(),
        K::Sid => p.sid.to_string(),
        K::Tsid => if p.tty != 0 { p.sid.to_string() } else { "-".into() },
        K::Tpgid => if p.tty != 0 && p.tpgid >= 0 { p.tpgid.to_string() } else { "-".into() },
        K::Stat => stat_string(p),
        K::Tdev => if p.tty != 0 { format!("{:#x}", p.tty) } else { "-".into() },
        K::Tt | K::Tty => {
            if p.tty == 0 {
                return "-".into();
            }
            match cx.ttys.name(p.tty) {
                Some(n) if c.k == K::Tt => kinfo::abbrev(n).to_string(),
                Some(n) => n.to_string(),
                None => "??".into(),
            }
        }
        K::Wchan => {
            if p.state == b'S' || p.state == b'D' || p.state == b'I' {
                kinfo::wchan(p.pid).unwrap_or_else(|| "-".into())
            } else {
                "-".into()
            }
        }
        K::Sigmask => format!("{:x}", p.sigmask),
        K::Pending => format!("{:x}", p.sigpend),
        K::Sigignore => format!("{:x}", p.sigignore),
        K::Sigcatch => format!("{:x}", p.sigcatch),
        K::Minflt => p.minflt.to_string(),
        K::Majflt => p.majflt.to_string(),
        K::Rtprio => if p.priority < 0 { format!("real:{}", -1 - p.priority) } else { "normal".into() },
        K::Jid => "0".into(),
        K::Dash => "-".into(),
    }
}

/// `-H`'s lines for the kernel process: one per kernel thread (`/proc/0/task/<tid>`), as FreeBSD
/// shows them, pid 0 and `kernel/<name>`; the one line if there's no such directory (a Linux host).
fn kernel_threads(kernel: &Proc) -> Vec<Proc> {
    let Ok(dir) = std::fs::read_dir("/proc/0/task") else { return vec![kernel.clone()] };
    let mut tids: Vec<u32> = dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect();
    tids.sort_unstable();
    tids.into_iter()
        .filter_map(|tid| {
            let stat = std::fs::read(format!("/proc/0/task/{tid}/stat")).ok()?;
            let t = kinfo::parse_stat(&String::from_utf8_lossy(&stat))?;
            Some(Proc {
                comm: format!("kernel/{}", t.comm),
                state: t.state,
                flags: t.flags,
                utime: t.utime,
                stime: t.stime,
                priority: t.priority,
                nice: t.nice,
                nlwp: t.nlwp,
                start: t.start,
                ..kernel.clone()
            })
        })
        .collect()
}

/// A comma- or blank-separated list (several `-p` and friends add up).
fn items(arg: &str) -> impl Iterator<Item = &str> {
    arg.split([',', ' ', '\t']).filter(|s| !s.is_empty())
}

#[derive(Default)]
struct Sel {
    pids: Vec<i32>,
    ttys: Vec<u64>,
    ruids: Vec<u32>,
    rgids: Vec<u32>,
}

impl Sel {
    fn count(&self) -> usize {
        self.pids.len() + self.ttys.len() + self.ruids.len() + self.rgids.len()
    }
}

fn main() -> ExitCode {
    // Die quietly on a closed pipe (`ps | head`), as a C program does.
    // SAFETY: restoring a signal's default action.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // BSD's old style: `ps aux` is `ps -aux`.
    if let Some(a) = args.first_mut() {
        if !a.starts_with('-') && !a.bytes().all(|b| b.is_ascii_digit()) {
            a.insert(0, '-');
        }
    }

    let mut cols: Vec<Col> = Vec::new();
    let mut extra: Vec<Col> = Vec::new(); // -O
    let mut all = false;
    let mut xkeep: Option<bool> = None;
    let mut xkeep_implied = false;
    let mut sel = Sel::default();
    let mut tty_args: Vec<String> = Vec::new();
    let mut this_tty = false;
    let mut sort_cpu = false;
    let mut sort_mem = false;
    let mut wflag = 0;
    let mut comm_only = false;
    let mut env = false;
    let mut child_times = false;
    let mut threads = false;
    let mut status = ExitCode::SUCCESS;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        i += 1;
        if a == "--" {
            break;
        }
        if !a.starts_with('-') || a == "-" {
            i -= 1;
            break;
        }
        let b = a.as_bytes();
        let mut j = 1;
        while j < b.len() {
            let c = b[j] as char;
            j += 1;
            if "GOopUt".contains(c) {
                let val = if j < b.len() {
                    let v = a[j..].to_string();
                    j = b.len();
                    v
                } else if i < args.len() {
                    i += 1;
                    args[i - 1].clone()
                } else {
                    eprintln!("ps: option requires an argument -- {c}");
                    return usage();
                };
                match c {
                    'G' => {
                        xkeep_implied = true;
                        for g in items(&val) {
                            match kinfo::group_id(g) {
                                Some(id) => sel.rgids.push(id),
                                None => {
                                    eprintln!("ps: No group named '{g}'");
                                    status = ExitCode::from(1);
                                }
                            }
                        }
                    }
                    'U' => {
                        xkeep_implied = true;
                        for u in items(&val) {
                            match kinfo::user_id(u) {
                                Some(id) => sel.ruids.push(id),
                                None => {
                                    eprintln!("ps: No user named '{u}'");
                                    status = ExitCode::from(1);
                                }
                            }
                        }
                    }
                    'p' => {
                        xkeep_implied = true;
                        for p in items(&val) {
                            match p.parse::<i32>() {
                                Ok(n) if n >= 0 => sel.pids.push(n),
                                _ => {
                                    eprintln!("ps: Invalid process ID: {p}");
                                    return ExitCode::from(1);
                                }
                            }
                        }
                    }
                    't' => tty_args.extend(items(&val).map(str::to_string)),
                    'o' => {
                        if let Err(e) = parse_fmt(&val, &mut cols) {
                            eprintln!("ps: {e}");
                            return ExitCode::from(1);
                        }
                    }
                    'O' => {
                        if let Err(e) = parse_fmt(&val, &mut extra) {
                            eprintln!("ps: {e}");
                            return ExitCode::from(1);
                        }
                    }
                    _ => unreachable!(),
                }
                continue;
            }
            let canned = match c {
                'A' => {
                    all = true;
                    xkeep = Some(true);
                    None
                }
                'a' => {
                    all = true;
                    None
                }
                'C' => None, // FreeBSD's "raw" CPU figure: there's only the one here.
                'c' => {
                    comm_only = true;
                    None
                }
                'e' => {
                    env = true;
                    None
                }
                'f' => None, // swapped-out processes: there's no swap.
                'H' => {
                    threads = true;
                    None
                }
                'j' => Some(JFMT),
                'L' => return list_keywords(),
                'l' => Some(LFMT),
                'm' => {
                    sort_mem = true;
                    sort_cpu = false;
                    None
                }
                'r' => {
                    sort_cpu = true;
                    sort_mem = false;
                    None
                }
                'S' => {
                    child_times = true;
                    None
                }
                'T' => {
                    this_tty = true;
                    None
                }
                'u' => {
                    sort_cpu = true;
                    sort_mem = false;
                    Some(UFMT)
                }
                'v' => {
                    sort_mem = true;
                    sort_cpu = false;
                    Some(VFMT)
                }
                'w' => {
                    wflag += 1;
                    None
                }
                'X' => {
                    xkeep = Some(false);
                    None
                }
                'x' => {
                    xkeep = Some(true);
                    None
                }
                _ => {
                    eprintln!("ps: illegal option -- {c}");
                    return usage();
                }
            };
            if let Some(f) = canned {
                parse_fmt(f, &mut cols).unwrap();
            }
        }
    }
    // Old style: trailing pids.
    for a in &args[i..] {
        match a.parse::<i32>() {
            Ok(n) if n >= 0 => {
                sel.pids.push(n);
                xkeep_implied = true;
            }
            _ => return usage(),
        }
    }

    let ttys = Ttys::scan();
    for t in &tty_args {
        if t == "-" {
            sel.ttys.push(0);
            continue;
        }
        match ttys.lookup(t) {
            Some(d) => sel.ttys.push(d),
            None => {
                eprintln!("ps: {t}: No such file or directory");
                status = ExitCode::from(1);
            }
        }
    }
    if this_tty {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: ttyname returns a static string or null.
        let name = unsafe { libc::ttyname(0) };
        let dev = if name.is_null() {
            None
        } else {
            let n = unsafe { std::ffi::CStr::from_ptr(name) }.to_string_lossy().into_owned();
            std::fs::metadata(n).ok().map(|m| m.rdev())
        };
        match dev {
            Some(d) => sel.ttys.push(d),
            None => {
                eprintln!("ps: stdin: not a terminal");
                return ExitCode::from(1);
            }
        }
    }
    if !tty_args.is_empty() && sel.ttys.is_empty() {
        return ExitCode::from(1);
    }
    // A selection that named nothing that exists selects nothing (not the default set).
    if status != ExitCode::SUCCESS && sel.count() == 0 {
        return status;
    }

    if cols.is_empty() {
        parse_fmt(DFMT, &mut cols).unwrap();
    }
    if !extra.is_empty() {
        let at = cols.iter().position(|c| c.k == K::Pid).map_or(0, |p| p + 1);
        cols.splice(at..at, extra);
    }
    let xkeep = xkeep.unwrap_or(xkeep_implied);

    let mut procs = match kinfo::all() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ps: /proc: {}", kinfo::strerror(&e));
            return ExitCode::from(1);
        }
    };
    if threads {
        procs = procs.into_iter().flat_map(|p| if p.pid == 0 { kernel_threads(&p) } else { vec![p] }).collect();
    }
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let nsel = sel.count();
    let kept: Vec<Proc> = procs
        .into_iter()
        .filter(|p| {
            if !xkeep && p.tty == 0 && !sel.ttys.contains(&0) {
                return false;
            }
            if nsel > 0 {
                return sel.pids.contains(&p.pid)
                    || sel.ttys.contains(&p.tty)
                    || sel.ruids.contains(&p.ruid)
                    || sel.rgids.contains(&p.rgid);
            }
            all || p.euid == me
        })
        .collect();

    let hz = kinfo::hz();
    let up = kinfo::uptime();
    let now = now();
    let mut cx = Ctx {
        hz,
        page_kb: kinfo::page_size() / 1024,
        mem_kb: kinfo::mem_total_kb(),
        uptime_ticks: (up * hz as f64) as u64,
        boot: now - up as i64,
        now,
        ttys,
        users: HashMap::new(),
        groups: HashMap::new(),
        comm_only,
        env,
        child_times,
    };

    // Sort: by CPU or memory if asked, then by terminal and pid (FreeBSD's order).
    let mut rows: Vec<(Proc, Option<u64>)> = kept.into_iter().map(|p| (p, None)).collect();
    if sort_mem {
        for (p, r) in rows.iter_mut() {
            cx.rss_kb(p, r);
        }
    }
    rows.sort_by(|(a, ra), (b, rb)| {
        let primary = if sort_cpu {
            cx.pcpu(b).partial_cmp(&cx.pcpu(a)).unwrap_or(std::cmp::Ordering::Equal)
        } else if sort_mem {
            rb.cmp(ra)
        } else {
            std::cmp::Ordering::Equal
        };
        primary.then(a.tty.cmp(&b.tty)).then(a.pid.cmp(&b.pid))
    });

    let mut table: Vec<Vec<String>> = Vec::with_capacity(rows.len());
    for (p, mut r) in rows {
        let line: Vec<String> = cols.iter().map(|c| field(c, &p, &mut cx, &mut r)).collect();
        table.push(line);
    }
    let headers = cols.iter().any(|c| !c.header.is_empty());
    let mut width: Vec<usize> = cols.iter().map(|c| c.header.chars().count()).collect();
    for line in &table {
        for (w, f) in width.iter_mut().zip(line) {
            *w = (*w).max(f.chars().count());
        }
    }

    let tw = term_width(wflag);
    let mut out = BufWriter::with_capacity(64 * 1024, io::stdout().lock());
    let mut emit = |fields: Vec<&str>| -> io::Result<()> {
        let mut s = String::new();
        let last = fields.len().saturating_sub(1);
        for (n, f) in fields.iter().enumerate() {
            if n > 0 {
                s.push(' ');
            }
            let pad = width[n].saturating_sub(f.chars().count());
            if cols[n].right {
                s.extend(std::iter::repeat_n(' ', pad));
                s.push_str(f);
            } else {
                s.push_str(f);
                if n != last {
                    s.extend(std::iter::repeat_n(' ', pad));
                }
            }
        }
        s.truncate(s.trim_end().len());
        if s.chars().count() > tw {
            s = s.chars().take(tw).collect();
        }
        writeln!(out, "{s}")
    };
    let mut r = Ok(());
    if headers {
        r = emit(cols.iter().map(|c| c.header.as_str()).collect());
    }
    let n = table.len();
    for line in &table {
        if r.is_err() {
            break;
        }
        r = emit(line.iter().map(String::as_str).collect());
    }
    drop(emit);
    if let Err(e) = r.and_then(|()| out.flush()) {
        eprintln!("ps: stdout: {}", kinfo::strerror(&e));
        return ExitCode::from(1);
    }
    if n == 0 {
        return ExitCode::from(1);
    }
    status
}
