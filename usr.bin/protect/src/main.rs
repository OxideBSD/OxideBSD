//! `protect(1)`: protects processes from the OOM killer (OxideBSD-doc `COW.md` §6.3), FreeBSD's
//! options plus `-a`.
//!
//! ```text
//! protect [-i] [-a adj] command [argument ...]
//! protect [-cdi] [-a adj] -g pgrp | -p pid
//! ```
//!
//! Sets the processes' OOM adjustment through `procctl(2)` (`PROC_OOM_ADJ_CTL`): `-1000`, never
//! chosen, unless `-a` gives another value (`-1000` to `1000`); `-c` sets it back to `0`. The
//! first form sets it for itself and executes `command`, which keeps it. `-d` also sets it for
//! every descendant of the processes (found through `/proc`). `-i` is accepted for FreeBSD's
//! sake: the adjustment is always inherited by children.

use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

const P_PID: libc::c_int = 1;
const P_PGID: libc::c_int = 2;
const PROC_OOM_ADJ_CTL: libc::c_int = 1;

unsafe extern "C" {
    fn procctl(idtype: libc::c_int, id: libc::id_t, cmd: libc::c_int, data: *mut libc::c_void) -> libc::c_int;
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: protect [-i] [-a adj] command [argument ...]\n\
         \x20      protect [-cdi] [-a adj] -g pgrp | -p pid"
    );
    ExitCode::from(1)
}

enum Target {
    Command(Vec<String>),
    Pid(libc::pid_t),
    Pgrp(libc::pid_t),
}

struct Opts {
    adj: i32,
    descendants: bool,
    target: Target,
}

fn parse_args() -> Result<Opts, ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut adj = None;
    let mut clear = false;
    let mut descendants = false;
    let mut target = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            i += 1;
            break;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else { break };
        i += 1;
        for (j, c) in flags.char_indices() {
            if "agp".contains(c) {
                let value = if j + 1 < flags.len() {
                    flags[j + 1..].to_string()
                } else if i < args.len() {
                    i += 1;
                    args[i - 1].clone()
                } else {
                    return Err(usage());
                };
                let Ok(n) = value.parse::<i32>() else {
                    eprintln!("protect: {value}: not a number");
                    return Err(usage());
                };
                match c {
                    'a' if (-1000..=1000).contains(&n) => adj = Some(n),
                    'a' => {
                        eprintln!("protect: {n}: out of range (-1000 to 1000)");
                        return Err(ExitCode::from(1));
                    }
                    'g' if n > 0 && target.is_none() => target = Some(Target::Pgrp(n)),
                    'p' if n > 0 && target.is_none() => target = Some(Target::Pid(n)),
                    _ => return Err(usage()),
                }
                break;
            }
            match c {
                'c' => clear = true,
                'd' => descendants = true,
                'i' => {}
                _ => return Err(usage()),
            }
        }
    }
    let target = match target {
        Some(t) if i == args.len() => t,
        None if i < args.len() && !clear && !descendants => Target::Command(args[i..].to_vec()),
        _ => return Err(usage()),
    };
    let adj = match (clear, adj) {
        (true, Some(_)) => return Err(usage()),
        (true, None) => 0,
        (false, a) => a.unwrap_or(-1000),
    };
    Ok(Opts { adj, descendants, target })
}

fn set(idtype: libc::c_int, id: libc::pid_t, adj: i32) -> std::io::Result<()> {
    let mut value: libc::c_int = adj;
    // SAFETY: `value` is a live int the call reads.
    let r = unsafe { procctl(idtype, id as libc::id_t, PROC_OOM_ADJ_CTL, (&raw mut value).cast()) };
    if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

/// Every process whose parent is in `roots`, transitively, from `/proc/<pid>/stat`.
fn descendants_of(roots: &[libc::pid_t]) -> Vec<libc::pid_t> {
    let mut parents: Vec<(libc::pid_t, libc::pid_t)> = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<libc::pid_t>() else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        // "pid (comm) state ppid ...": comm may hold spaces and parentheses, so after the last ')'.
        let Some(rest) = stat.rfind(')').map(|at| &stat[at + 1..]) else { continue };
        if let Some(ppid) = rest.split_whitespace().nth(1).and_then(|p| p.parse().ok()) {
            parents.push((pid, ppid));
        }
    }
    let mut found: Vec<libc::pid_t> = Vec::new();
    let mut frontier = roots.to_vec();
    while let Some(parent) = frontier.pop() {
        for &(pid, ppid) in &parents {
            if ppid == parent && !found.contains(&pid) && !roots.contains(&pid) {
                found.push(pid);
                frontier.push(pid);
            }
        }
    }
    found
}

/// The pids in process group `pgrp`, from `/proc/<pid>/stat`.
fn members_of(pgrp: libc::pid_t) -> Vec<libc::pid_t> {
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<libc::pid_t>() else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let Some(rest) = stat.rfind(')').map(|at| &stat[at + 1..]) else { continue };
        if rest.split_whitespace().nth(2).and_then(|g| g.parse().ok()) == Some(pgrp) {
            members.push(pid);
        }
    }
    members
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(code) => return code,
    };
    let (idtype, id, what) = match &opts.target {
        Target::Command(argv) => {
            if let Err(e) = set(P_PID, 0, opts.adj) {
                eprintln!("protect: procctl: {e}");
                return ExitCode::from(1);
            }
            let e = Command::new(&argv[0]).args(&argv[1..]).exec();
            eprintln!("protect: {}: {e}", argv[0]);
            return ExitCode::from(if e.kind() == std::io::ErrorKind::NotFound { 127 } else { 126 });
        }
        Target::Pid(pid) => (P_PID, *pid, format!("pid {pid}")),
        Target::Pgrp(pgrp) => (P_PGID, *pgrp, format!("process group {pgrp}")),
    };
    let mut status = ExitCode::SUCCESS;
    if let Err(e) = set(idtype, id, opts.adj) {
        eprintln!("protect: {what}: {e}");
        status = ExitCode::from(1);
    }
    if opts.descendants {
        let roots = match opts.target {
            Target::Pgrp(pgrp) => members_of(pgrp),
            _ => vec![id],
        };
        for pid in descendants_of(&roots) {
            // A descendant may have exited since the scan: not an error.
            match set(P_PID, pid, opts.adj) {
                Err(e) if e.raw_os_error() != Some(libc::ESRCH) => {
                    eprintln!("protect: pid {pid}: {e}");
                    status = ExitCode::from(1);
                }
                _ => {}
            }
        }
    }
    status
}
