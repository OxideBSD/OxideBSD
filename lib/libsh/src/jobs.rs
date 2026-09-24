//! Job control (XCU 2.11, `set -m`): each pipeline gets its own process group, the foreground
//! one owns the terminal, and a stopped or backgrounded one becomes a job `jobs`/`fg`/`bg`/`wait`
//! and `kill %n` can name.

use crate::shell::{Exec, Shell};
use crate::sys::{self, ChildState, Fd};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcState {
    Running,
    Stopped(i32),
    Done(i32),
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: usize,
    pub pgid: libc::pid_t,
    pub procs: Vec<(libc::pid_t, ProcState)>,
    pub text: String,
    /// The user has been told about its current state (Done/Stopped notices are printed once).
    pub notified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Running,
    Stopped(i32),
    Done(i32),
}

impl Job {
    pub fn state(&self) -> JobState {
        if let Some(&(_, ProcState::Stopped(sig))) = self.procs.iter().find(|(_, s)| matches!(s, ProcState::Stopped(_))) {
            return JobState::Stopped(sig);
        }
        if self.procs.iter().all(|(_, s)| matches!(s, ProcState::Done(_))) {
            // A pipeline's status is its last command's.
            let last = self.procs.last().map(|&(_, s)| s);
            return JobState::Done(match last {
                Some(ProcState::Done(s)) => s,
                _ => 0,
            });
        }
        JobState::Running
    }

    fn update(&mut self, pid: libc::pid_t, st: ChildState) -> bool {
        let Some(p) = self.procs.iter_mut().find(|(p, _)| *p == pid) else { return false };
        p.1 = match st {
            ChildState::Done(s) => ProcState::Done(s),
            ChildState::Stopped(sig) => ProcState::Stopped(sig),
            ChildState::Continued => ProcState::Running,
        };
        self.notified = false;
        true
    }
}

fn signal_description(sig: i32) -> String {
    match sig {
        libc::SIGTSTP => "Stopped".into(),
        libc::SIGSTOP => "Stopped (signal)".into(),
        libc::SIGTTIN => "Stopped (tty input)".into(),
        libc::SIGTTOU => "Stopped (tty output)".into(),
        s => format!("Stopped (SIG{})", sys::signal_name(s).unwrap_or("?")),
    }
}

impl Shell {
    /// Job control is on: `set -m`, in the top-level shell only (a subshell's children stay in
    /// its process group, as in every POSIX shell).
    pub fn job_control(&self) -> bool {
        self.opts.monitor && !self.is_subshell && self.tty_fd.is_some()
    }

    /// In a freshly forked child of a job-controlled shell: join `pgid` (0: start a new group led
    /// by this process), take the terminal if it's a foreground job, and restore the signals the
    /// shell itself ignores.
    pub(crate) fn job_child_setup(&self, pgid: libc::pid_t, foreground: bool) {
        let _ = sys::setpgid(0, pgid);
        if foreground && let Some(tty) = self.tty_fd {
            let _ = sys::tcsetpgrp(tty, sys::getpgrp());
        }
        for sig in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU, libc::SIGINT, libc::SIGQUIT] {
            sys::set_signal(sig, libc::SIG_DFL);
        }
    }

    /// The parent's half of `job_child_setup` (both sides call `setpgid`, so whichever runs first
    /// wins the race against the child exec'ing).
    pub(crate) fn job_parent_setup(&self, pid: libc::pid_t, pgid: libc::pid_t) {
        let _ = sys::setpgid(pid, if pgid == 0 { pid } else { pgid });
    }

    fn give_terminal(&self, pgid: libc::pid_t) {
        if let Some(tty) = self.tty_fd {
            let _ = sys::tcsetpgrp(tty, pgid);
        }
    }

    /// Takes the terminal back, and restores its modes (a program that was stopped or died may
    /// have left it raw).
    fn reclaim_terminal(&self) {
        if let Some(tty) = self.tty_fd {
            let _ = sys::tcsetpgrp(tty, self.shell_pgid);
            if let Some(t) = &self.tty_modes {
                let _ = sys::tcsetattr(tty, t);
            }
        }
    }

    /// Runs a foreground job to completion or until it stops. `pids` are its processes, in
    /// pipeline order. Returns the shell status: the last process's, or 128 + the stop signal.
    pub(crate) fn wait_foreground(&mut self, pgid: libc::pid_t, pids: &[libc::pid_t], text: &str) -> i32 {
        let mut job = Job { id: 0, pgid, procs: pids.iter().map(|&p| (p, ProcState::Running)).collect(), text: text.to_string(), notified: true };
        self.give_terminal(pgid);
        self.wait_job(&mut job);
        self.reclaim_terminal();
        self.finish_foreground(job)
    }

    /// Waits until every process of `job` has finished, or one has stopped.
    fn wait_job(&mut self, job: &mut Job) {
        loop {
            let Some(&(pid, _)) = job.procs.iter().find(|(_, s)| *s == ProcState::Running) else { return };
            match sys::wait_any(pid, false) {
                Ok(Some((p, st))) => {
                    job.update(p, st);
                    if let ChildState::Stopped(_) = st {
                        // The whole group got the stop signal: collect the others' stops too.
                        for (p, s) in job.procs.iter_mut() {
                            if *s == ProcState::Running
                                && let Ok(Some((_, ChildState::Stopped(sig)))) = sys::wait_any(*p, true)
                            {
                                *s = ProcState::Stopped(sig);
                            }
                        }
                        return;
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    // Not our child any more (already reaped elsewhere): treat as done.
                    job.update(pid, ChildState::Done(127));
                }
            }
        }
    }

    /// Records a foreground job that stopped, or returns the status of one that finished.
    fn finish_foreground(&mut self, mut job: Job) -> i32 {
        match job.state() {
            JobState::Done(s) => {
                if job.id != 0 {
                    self.jobs.retain(|j| j.id != job.id);
                    self.job_order.retain(|&i| i != job.id);
                }
                // A job killed by SIGINT (Ctrl+C) leaves the cursor mid-line.
                if job.procs.iter().any(|&(_, st)| st == ProcState::Done(128 + libc::SIGINT)) {
                    let _ = sys::write_all(2, b"\n");
                }
                s
            }
            JobState::Stopped(sig) => {
                if job.id == 0 {
                    job.id = self.next_job_id();
                }
                let id = job.id;
                job.notified = true;
                let line = format!("\n[{id}]+  {}  {}\n", signal_description(sig), job.text);
                self.jobs.retain(|j| j.id != id);
                self.jobs.push(job);
                self.touch_job(id);
                let _ = sys::write_all(2, line.as_bytes());
                128 + sig
            }
            JobState::Running => 0,
        }
    }

    fn next_job_id(&self) -> usize {
        (1..).find(|n| !self.jobs.iter().any(|j| j.id == *n)).unwrap()
    }

    /// Makes `id` the current job (`%+`).
    fn touch_job(&mut self, id: usize) {
        self.job_order.retain(|&i| i != id);
        self.job_order.push(id);
    }

    /// Records a job started in the background; prints `[n] pid` if interactive.
    pub(crate) fn add_background_job(&mut self, pgid: libc::pid_t, pids: Vec<libc::pid_t>, text: String) {
        let id = self.next_job_id();
        let last = *pids.last().unwrap_or(&pgid);
        self.jobs.push(Job { id, pgid, procs: pids.into_iter().map(|p| (p, ProcState::Running)).collect(), text, notified: true });
        self.touch_job(id);
        if self.interactive {
            let _ = sys::write_all(2, format!("[{id}] {last}\n").as_bytes());
        }
    }

    /// Collects state changes of every job without blocking.
    pub fn poll_jobs(&mut self) {
        for job in &mut self.jobs {
            let pids: Vec<libc::pid_t> = job.procs.iter().filter(|(_, s)| !matches!(s, ProcState::Done(_))).map(|&(p, _)| p).collect();
            for pid in pids {
                if let Ok(Some((p, st))) = sys::wait_any(pid, true) {
                    job.update(p, st);
                }
            }
        }
    }

    /// Before a prompt: reports jobs that finished or stopped since the last one, and forgets
    /// finished ones.
    pub fn notify_jobs(&mut self) {
        self.poll_jobs();
        let current = self.job_order.last().copied();
        let mut out = String::new();
        for job in &mut self.jobs {
            if job.notified {
                continue;
            }
            job.notified = true;
            let mark = if Some(job.id) == current { '+' } else { ' ' };
            let what = match job.state() {
                JobState::Done(0) => "Done".to_string(),
                JobState::Done(s) if s > 128 => sys::signal_name(s - 128).map(|n| format!("Killed (SIG{n})")).unwrap_or_else(|| format!("Done({s})")),
                JobState::Done(s) => format!("Done({s})"),
                JobState::Stopped(sig) => signal_description(sig),
                JobState::Running => continue,
            };
            out.push_str(&format!("[{}]{mark}  {what}  {}\n", job.id, job.text));
        }
        let done: Vec<usize> = self.jobs.iter().filter(|j| matches!(j.state(), JobState::Done(_))).map(|j| j.id).collect();
        self.jobs.retain(|j| !done.contains(&j.id));
        self.job_order.retain(|i| !done.contains(i));
        if !out.is_empty() {
            let _ = sys::write_all(2, out.as_bytes());
        }
    }

    /// Resolves a job specification (`%n`, `%+`, `%%`, `%-`, `%prefix`, `%?text`), or with `None`
    /// the current job.
    pub fn find_job(&self, spec: Option<&str>) -> Result<usize, String> {
        let pick = |id: Option<&usize>| id.copied().ok_or_else(|| "no current job".to_string());
        let Some(spec) = spec else { return pick(self.job_order.last()) };
        let Some(s) = spec.strip_prefix('%') else { return Err(format!("{spec}: no such job")) };
        match s {
            "" | "+" | "%" => pick(self.job_order.last()),
            "-" => pick(self.job_order.iter().rev().nth(1)),
            _ => {
                if let Ok(n) = s.parse::<usize>() {
                    return self.jobs.iter().find(|j| j.id == n).map(|j| j.id).ok_or_else(|| format!("{spec}: no such job"));
                }
                let matches: Vec<usize> = match s.strip_prefix('?') {
                    Some(t) => self.jobs.iter().filter(|j| j.text.contains(t)).map(|j| j.id).collect(),
                    None => self.jobs.iter().filter(|j| j.text.starts_with(s)).map(|j| j.id).collect(),
                };
                match matches.as_slice() {
                    [id] => Ok(*id),
                    [] => Err(format!("{spec}: no such job")),
                    _ => Err(format!("{spec}: ambiguous job specification")),
                }
            }
        }
    }

    pub fn job_pgid(&self, id: usize) -> Option<libc::pid_t> {
        self.jobs.iter().find(|j| j.id == id).map(|j| j.pgid)
    }

    pub fn has_stopped_jobs(&self) -> bool {
        self.jobs.iter().any(|j| matches!(j.state(), JobState::Stopped(_)))
    }

    /// Waits for job `id` to finish (the `wait` built-in; not in the foreground).
    pub(crate) fn wait_for_job(&mut self, id: usize) -> i32 {
        let Some(pos) = self.jobs.iter().position(|j| j.id == id) else { return 127 };
        let mut job = self.jobs.remove(pos);
        loop {
            self.wait_job(&mut job);
            match job.state() {
                JobState::Done(s) => {
                    self.job_order.retain(|&i| i != id);
                    return s;
                }
                // `wait` on a stopped job returns rather than hanging forever.
                JobState::Stopped(sig) => {
                    self.jobs.push(job);
                    return 128 + sig;
                }
                JobState::Running => {}
            }
        }
    }

    /// On exit from an interactive shell: stopped jobs would otherwise stay stopped forever.
    pub fn hangup_jobs(&mut self) {
        for job in &self.jobs {
            if matches!(job.state(), JobState::Stopped(_)) {
                let _ = sys::kill(-job.pgid, libc::SIGHUP);
                let _ = sys::kill(-job.pgid, libc::SIGCONT);
            }
        }
    }
}

fn no_job_control(sh: &Shell, name: &str) -> Option<Exec> {
    if sh.job_control() {
        None
    } else {
        sh.error(&format!("{name}: no job control"));
        Some(Ok(1))
    }
}

pub fn jobs(sh: &mut Shell, args: &[String]) -> Exec {
    sh.poll_jobs();
    let mut long = false;
    let mut pids_only = false;
    let mut specs = Vec::new();
    for a in &args[1..] {
        match a.as_str() {
            "-l" => long = true,
            "-p" => pids_only = true,
            _ => specs.push(a.as_str()),
        }
    }
    let ids: Vec<usize> = if specs.is_empty() {
        sh.jobs.iter().map(|j| j.id).collect()
    } else {
        let mut v = Vec::new();
        for s in specs {
            match sh.find_job(Some(s)) {
                Ok(id) => v.push(id),
                Err(e) => {
                    sh.error(&format!("jobs: {e}"));
                    return Ok(1);
                }
            }
        }
        v
    };
    let current = sh.job_order.last().copied();
    let previous = sh.job_order.iter().rev().nth(1).copied();
    let mut out = String::new();
    for id in ids {
        let Some(job) = sh.jobs.iter_mut().find(|j| j.id == id) else { continue };
        if pids_only {
            out.push_str(&format!("{}\n", job.pgid));
            continue;
        }
        let mark = if Some(id) == current {
            '+'
        } else if Some(id) == previous {
            '-'
        } else {
            ' '
        };
        let state = match job.state() {
            JobState::Running => "Running".to_string(),
            JobState::Stopped(sig) => signal_description(sig),
            JobState::Done(0) => "Done".to_string(),
            JobState::Done(s) => format!("Done({s})"),
        };
        if long {
            out.push_str(&format!("[{id}]{mark} {:>6} {state}  {}\n", job.pgid, job.text));
        } else {
            out.push_str(&format!("[{id}]{mark}  {state}  {}\n", job.text));
        }
        job.notified = true;
    }
    let _ = sys::write_all(1, out.as_bytes());
    Ok(0)
}

pub fn fg(sh: &mut Shell, args: &[String]) -> Exec {
    if let Some(r) = no_job_control(sh, "fg") {
        return r;
    }
    let id = match sh.find_job(args.get(1).map(String::as_str)) {
        Ok(id) => id,
        Err(e) => {
            sh.error(&format!("fg: {e}"));
            return Ok(1);
        }
    };
    let pos = sh.jobs.iter().position(|j| j.id == id).unwrap();
    let mut job = sh.jobs.remove(pos);
    let _ = sys::write_all(1, format!("{}\n", job.text).as_bytes());
    sh.give_terminal(job.pgid);
    let _ = sys::kill(-job.pgid, libc::SIGCONT);
    for p in job.procs.iter_mut() {
        if let ProcState::Stopped(_) = p.1 {
            p.1 = ProcState::Running;
        }
    }
    sh.wait_job(&mut job);
    sh.reclaim_terminal();
    Ok(sh.finish_foreground(job))
}

pub fn bg(sh: &mut Shell, args: &[String]) -> Exec {
    if let Some(r) = no_job_control(sh, "bg") {
        return r;
    }
    let specs: Vec<Option<&str>> = if args.len() > 1 { args[1..].iter().map(|a| Some(a.as_str())).collect() } else { vec![None] };
    let mut status = 0;
    for spec in specs {
        let id = match sh.find_job(spec) {
            Ok(id) => id,
            Err(e) => {
                sh.error(&format!("bg: {e}"));
                status = 1;
                continue;
            }
        };
        let current = sh.job_order.last().copied();
        let Some(job) = sh.jobs.iter_mut().find(|j| j.id == id) else { continue };
        let _ = sys::kill(-job.pgid, libc::SIGCONT);
        for p in job.procs.iter_mut() {
            if let ProcState::Stopped(_) = p.1 {
                p.1 = ProcState::Running;
            }
        }
        let mark = if Some(id) == current { '+' } else { ' ' };
        let _ = sys::write_all(1, format!("[{id}]{mark} {} &\n", job.text).as_bytes());
    }
    Ok(status)
}

/// The terminal descriptors an interactive shell keeps for itself (`>= 10`, close-on-exec):
/// one to read keys from and to set modes and the foreground group on (standard input), one to
/// write prompts and echo to (standard error). Two, not one: OxideBSD's console descriptors are
/// one-way (fd 0 can't be written, fds 1 and 2 can't be read), unlike a Unix tty opened
/// read-write.
pub fn claim_terminal() -> Option<(Fd, Fd)> {
    if !sys::isatty(0) {
        return None;
    }
    let out = [2, 1].into_iter().find(|&fd| sys::isatty(fd))?;
    Some((sys::dup_high(0).ok()?, sys::dup_high(out).ok()?))
}
