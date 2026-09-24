//! Command execution (XCU 2.9): lists, pipelines, simple and compound commands, functions,
//! redirections, and command search.

use std::rc::Rc;

use crate::ast::*;
use crate::builtins::{self, Builtin};
use crate::shell::{Exec, Flow, Shell, Var};
use crate::sys::{self, Fd};

/// Here-documents up to this size are written into a pipe directly; larger ones get a writer
/// child, so a body bigger than the pipe's capacity can't deadlock the shell against itself.
const HEREDOC_INLINE_MAX: usize = 4096;

/// A descriptor a redirection replaced, to put back afterwards. `None`: it was closed before.
pub(crate) type Saved = Vec<(Fd, Option<Fd>)>;

impl Shell {
    pub fn run_list(&mut self, list: &List) -> Exec {
        let mut status = self.status;
        for item in list {
            self.reap_background();
            status = if item.background { self.run_background(&item.and_or)? } else { self.run_and_or(&item.and_or)? };
            self.status = status;
            self.run_pending_traps()?;
        }
        Ok(status)
    }

    fn run_background(&mut self, and_or: &AndOr) -> Exec {
        let jc = self.job_control();
        match sys::fork() {
            Ok(0) => {
                if jc {
                    self.job_child_setup(0, false);
                }
                self.enter_subshell();
                // XCU 2.9.3.1: without job control, an asynchronous list ignores SIGINT and
                // SIGQUIT and reads from /dev/null unless it redirects its own input. With it,
                // the job is in its own process group, which the terminal's signals don't reach,
                // and reading the terminal stops it (SIGTTIN) instead.
                if !jc {
                    unsafe {
                        libc::signal(libc::SIGINT, libc::SIG_IGN);
                        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
                    }
                    if let Ok(fd) = sys::open("/dev/null", libc::O_RDONLY, 0) {
                        let _ = sys::dup2(fd, 0);
                        if fd != 0 {
                            sys::close(fd);
                        }
                    }
                }
                self.tail = and_or.rest.is_empty() && !and_or.first.bang;
                let status = self.run_and_or(and_or).unwrap_or_else(|f| self.flow_status(f));
                let status = self.finish(status);
                sys::exit_child(status);
            }
            Ok(pid) => {
                self.last_bg = Some(pid);
                if jc {
                    self.job_parent_setup(pid, 0);
                    self.add_background_job(pid, vec![pid], crate::unparse::and_or(and_or));
                } else {
                    self.bg_pids.push(pid);
                }
                Ok(0)
            }
            Err(e) => {
                self.error(&format!("cannot fork: {e}"));
                Ok(2)
            }
        }
    }

    /// Collects finished asynchronous lists without blocking, so they don't linger as zombies.
    fn reap_background(&mut self) {
        let mut i = 0;
        while i < self.bg_pids.len() {
            let pid = self.bg_pids[i];
            let mut st = 0;
            if unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) } == pid {
                self.bg_done.insert(pid, sys::decode_status(st));
                self.bg_pids.remove(i);
            } else {
                i += 1;
            }
        }
    }

    pub(crate) fn flow_status(&self, f: Flow) -> i32 {
        match f {
            Flow::Exit(s) | Flow::Fatal(s) | Flow::Return(s) => s,
            Flow::Break(_) | Flow::Continue(_) => self.status,
        }
    }

    fn run_and_or(&mut self, and_or: &AndOr) -> Exec {
        let n = and_or.rest.len();
        let mut status = self.run_pipeline(&and_or.first, n > 0)?;
        let mut last_bang = and_or.first.bang;
        for (i, (op, p)) in and_or.rest.iter().enumerate() {
            self.status = status;
            let run = match op {
                AndOrOp::And => status == 0,
                AndOrOp::Or => status != 0,
            };
            if run {
                status = self.run_pipeline(p, i + 1 < n)?;
                last_bang = p.bang;
            } else {
                // A skipped pipeline can't trigger -e: the status came from a condition.
                last_bang = true;
            }
        }
        if status != 0 && self.opts.errexit && self.cond_depth == 0 && !last_bang {
            return Err(Flow::Exit(status));
        }
        Ok(status)
    }

    /// `cond`: this pipeline is the left side of `&&`/`||`, where `-e` does not apply.
    fn run_pipeline(&mut self, p: &Pipeline, cond: bool) -> Exec {
        let cond = cond || p.bang;
        if cond {
            self.cond_depth += 1;
        }
        let r = if p.commands.len() == 1 { self.run_command(&p.commands[0]) } else { self.run_multi(&p.commands) };
        if cond {
            self.cond_depth -= 1;
        }
        let status = r?;
        Ok(if p.bang { (status == 0) as i32 } else { status })
    }

    fn run_multi(&mut self, commands: &[Command]) -> Exec {
        let jc = self.job_control();
        // With job control, the pipeline is one process group, led by its first process.
        let mut pgid: libc::pid_t = 0;
        let mut pids = Vec::new();
        let mut prev_read: Option<Fd> = None;
        let mut spawn_error = None;
        for (i, cmd) in commands.iter().enumerate() {
            let last = i + 1 == commands.len();
            let (r, w) = if last {
                (None, None)
            } else {
                match sys::pipe() {
                    Ok((r, w)) => (Some(r), Some(w)),
                    Err(e) => {
                        spawn_error = Some(format!("cannot create pipe: {e}"));
                        break;
                    }
                }
            };
            match sys::fork() {
                Ok(0) => {
                    if jc {
                        self.job_child_setup(pgid, true);
                    }
                    if let Some(pr) = prev_read {
                        let _ = sys::dup2(pr, 0);
                        sys::close(pr);
                    }
                    if let (Some(r), Some(w)) = (r, w) {
                        sys::close(r);
                        let _ = sys::dup2(w, 1);
                        if w != 1 {
                            sys::close(w);
                        }
                    }
                    self.enter_subshell();
                    self.tail = true;
                    let status = self.run_command(cmd).unwrap_or_else(|f| self.flow_status(f));
                    let status = self.finish(status);
                    sys::exit_child(status);
                }
                Ok(pid) => {
                    if jc {
                        self.job_parent_setup(pid, pgid);
                        if pgid == 0 {
                            pgid = pid;
                        }
                    }
                    pids.push(pid)
                }
                Err(e) => spawn_error = Some(format!("cannot fork: {e}")),
            }
            if let Some(pr) = prev_read.take() {
                sys::close(pr);
            }
            if let Some(w) = w {
                sys::close(w);
            }
            prev_read = r;
            if spawn_error.is_some() {
                break;
            }
        }
        if let Some(pr) = prev_read {
            sys::close(pr);
        }
        let mut status = 0;
        if jc && !pids.is_empty() {
            let text = commands.iter().map(crate::unparse::command).collect::<Vec<_>>().join(" | ");
            status = self.wait_foreground(pgid, &pids, &text);
            self.interrupted_by_child(status)?;
        } else {
            for pid in pids {
                status = sys::wait_pid(pid).unwrap_or(1);
            }
        }
        if let Some(e) = spawn_error {
            self.error(&e);
            return Ok(2);
        }
        Ok(status)
    }

    pub fn run_command(&mut self, cmd: &Command) -> Exec {
        match cmd {
            Command::Simple(sc) => self.run_simple(sc),
            Command::Compound(cc, redirs) => {
                self.tail = false;
                if let CompoundCommand::Subshell(list) = cc {
                    return self.run_subshell(list, redirs);
                }
                let saved = match self.redirect(redirs, true) {
                    Ok(s) => s,
                    Err(e) => {
                        self.error(&e);
                        return Ok(1);
                    }
                };
                let r = self.run_compound(cc);
                self.restore(saved);
                r
            }
            Command::FunctionDef { name, body } => {
                self.tail = false;
                self.functions.insert(name.clone(), Rc::clone(body));
                Ok(0)
            }
        }
    }

    fn run_subshell(&mut self, list: &List, redirs: &[Redirect]) -> Exec {
        let jc = self.job_control();
        match sys::fork() {
            Ok(0) => {
                if jc {
                    self.job_child_setup(0, true);
                }
                self.enter_subshell();
                let status = match self.redirect(redirs, false) {
                    Ok(_) => self.run_list(list).unwrap_or_else(|f| self.flow_status(f)),
                    Err(e) => {
                        self.error(&e);
                        1
                    }
                };
                let status = self.finish(status);
                sys::exit_child(status);
            }
            Ok(pid) if jc => {
                self.job_parent_setup(pid, 0);
                let status = self.wait_foreground(pid, &[pid], &format!("({})", crate::unparse::list(list)));
                self.interrupted_by_child(status)?;
                Ok(status)
            }
            Ok(pid) => Ok(sys::wait_pid(pid).unwrap_or(1)),
            Err(e) => {
                self.error(&format!("cannot fork: {e}"));
                Ok(2)
            }
        }
    }

    /// A foreground job killed by Ctrl+C ends the whole command line in an interactive shell, as
    /// if the shell had been interrupted itself (`sleep 10; echo done` doesn't print `done`).
    fn interrupted_by_child(&self, status: i32) -> Result<(), Flow> {
        if self.interactive && status == 128 + libc::SIGINT { Err(Flow::Fatal(status)) } else { Ok(()) }
    }

    /// State changes on entering any forked subshell.
    pub(crate) fn enter_subshell(&mut self) {
        if self.interactive {
            // The interactive shell's own signal handling isn't inherited: a subshell or command
            // gets the default dispositions back (the ones it ignored for its own sake).
            for sig in [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
                sys::set_signal(sig, libc::SIG_DFL);
            }
            self.interactive = false;
            self.jobs.clear();
            self.job_order.clear();
        }
        self.is_subshell = true;
        self.reset_traps_for_child();
        self.bg_pids.clear();
        self.bg_done.clear();
    }

    fn run_compound(&mut self, cc: &CompoundCommand) -> Exec {
        match cc {
            CompoundCommand::Brace(list) => self.run_list(list),
            CompoundCommand::Subshell(_) => unreachable!("handled by run_command"),
            CompoundCommand::If { branches, else_body } => {
                for (cond, body) in branches {
                    if self.run_condition(cond)? == 0 {
                        return self.run_list(body);
                    }
                }
                match else_body {
                    Some(body) => self.run_list(body),
                    None => Ok(0),
                }
            }
            CompoundCommand::While { cond, body } => self.run_loop(cond, body, false),
            CompoundCommand::Until { cond, body } => self.run_loop(cond, body, true),
            CompoundCommand::For { var, words, body } => {
                let items = match words {
                    Some(w) => self.expand_words(w)?,
                    None => self.positional.clone(),
                };
                let mut status = 0;
                self.loop_depth += 1;
                let r = (|| {
                    for item in items {
                        if let Err(e) = self.set(var, &item) {
                            self.error(&e);
                            return Err(Flow::Fatal(2));
                        }
                        match self.run_list(body) {
                            Ok(s) => status = s,
                            Err(Flow::Break(n)) => return if n > 1 { Err(Flow::Break(n - 1)) } else { Ok(()) },
                            Err(Flow::Continue(n)) if n > 1 => return Err(Flow::Continue(n - 1)),
                            Err(Flow::Continue(_)) => status = self.status,
                            Err(f) => return Err(f),
                        }
                    }
                    Ok(())
                })();
                self.loop_depth -= 1;
                r.map(|()| status)
            }
            CompoundCommand::Case { word, arms } => {
                let subject = self.expand_string(word)?;
                for arm in arms {
                    for p in &arm.patterns {
                        let pat = self.expand_pattern(p)?;
                        if crate::pattern::matches(&pat, &subject) {
                            return self.run_list(&arm.body);
                        }
                    }
                }
                Ok(0)
            }
        }
    }

    fn run_condition(&mut self, cond: &List) -> Exec {
        self.cond_depth += 1;
        let r = self.run_list(cond);
        self.cond_depth -= 1;
        r
    }

    fn run_loop(&mut self, cond: &List, body: &List, until: bool) -> Exec {
        let mut status = 0;
        self.loop_depth += 1;
        let r = (|| {
            loop {
                let c = match self.run_condition(cond) {
                    Ok(c) => c,
                    Err(Flow::Break(n)) => return if n > 1 { Err(Flow::Break(n - 1)) } else { Ok(()) },
                    Err(Flow::Continue(n)) if n > 1 => return Err(Flow::Continue(n - 1)),
                    Err(Flow::Continue(_)) => continue,
                    Err(f) => return Err(f),
                };
                if (c == 0) == until {
                    return Ok(());
                }
                match self.run_list(body) {
                    Ok(s) => status = s,
                    Err(Flow::Break(n)) => return if n > 1 { Err(Flow::Break(n - 1)) } else { Ok(()) },
                    Err(Flow::Continue(n)) if n > 1 => return Err(Flow::Continue(n - 1)),
                    Err(Flow::Continue(_)) => status = self.status,
                    Err(f) => return Err(f),
                }
            }
        })();
        self.loop_depth -= 1;
        r.map(|()| status)
    }

    fn run_simple(&mut self, sc: &SimpleCommand) -> Exec {
        // Set by a forked child about to exit anyway: an external command can replace the
        // process instead of forking again.
        let tail = std::mem::take(&mut self.tail);
        self.subst_status = None;
        let fields = self.expand_words(&sc.words)?;
        let mut assigns = Vec::with_capacity(sc.assignments.len());
        for a in &sc.assignments {
            assigns.push((a.name.clone(), self.expand_string(&a.value)?));
        }

        if fields.is_empty() {
            // Assignments alone persist in the shell; redirections are done and undone.
            let status = self.subst_status.unwrap_or(0);
            self.xtrace(&assigns, &[]);
            match self.redirect(&sc.redirects, true) {
                Ok(saved) => self.restore(saved),
                Err(e) => {
                    self.error(&e);
                    return Ok(1);
                }
            }
            for (n, v) in &assigns {
                if let Err(e) = self.set(n, v) {
                    self.error(&e);
                    return Err(Flow::Fatal(1));
                }
            }
            return Ok(status);
        }

        self.xtrace(&assigns, &fields);
        let name = fields[0].as_str();

        if let Some(b) = builtins::lookup_special(name) {
            // XCU 2.14: assignments before a special built-in persist, and its errors end a
            // non-interactive shell.
            for (n, v) in &assigns {
                if let Err(e) = self.set(n, v) {
                    self.error(&e);
                    return Err(Flow::Fatal(1));
                }
            }
            if name == "exec" && fields.len() == 1 {
                // `exec` with only redirections: they apply to the shell itself, permanently.
                return match self.redirect(&sc.redirects, false) {
                    Ok(_) => Ok(0),
                    Err(e) => {
                        self.error(&e);
                        Err(Flow::Fatal(1))
                    }
                };
            }
            let saved = match self.redirect(&sc.redirects, true) {
                Ok(s) => s,
                Err(e) => {
                    self.error(&e);
                    return Err(Flow::Fatal(1));
                }
            };
            let r = b(self, &fields);
            self.restore(saved);
            return r;
        }

        if let Some(body) = self.functions.get(name).cloned() {
            return self.with_temp_assigns(&assigns, &sc.redirects, |sh| sh.call_function(&body, &fields));
        }

        if let Some(b) = builtins::lookup_regular(name) {
            return self.with_temp_assigns(&assigns, &sc.redirects, |sh| b(sh, &fields));
        }

        self.run_external(&fields, &assigns, &sc.redirects, tail)
    }

    fn xtrace(&self, assigns: &[(String, String)], fields: &[String]) {
        if !self.opts.xtrace {
            return;
        }
        let mut line = self.get("PS4").unwrap_or_else(|| "+ ".into());
        let mut words: Vec<String> = assigns.iter().map(|(n, v)| format!("{n}={}", quote(v))).collect();
        words.extend(fields.iter().map(|f| quote(f)));
        line.push_str(&words.join(" "));
        line.push('\n');
        let _ = sys::write_all(2, line.as_bytes());
    }

    /// Runs `f` with `assigns` in effect (exported) and `redirs` applied, then undoes both.
    fn with_temp_assigns(&mut self, assigns: &[(String, String)], redirs: &[Redirect], f: impl FnOnce(&mut Self) -> Exec) -> Exec {
        let saved = match self.redirect(redirs, true) {
            Ok(s) => s,
            Err(e) => {
                self.error(&e);
                return Ok(1);
            }
        };
        let mut old_vars = Vec::new();
        for (n, v) in assigns {
            if self.vars.get(n).is_some_and(|v| v.readonly) {
                self.error(&format!("{n}: is read only"));
                self.restore_vars(old_vars);
                self.restore(saved);
                return Ok(1);
            }
            old_vars.push((n.clone(), self.vars.get(n).cloned()));
            self.vars.insert(n.clone(), Var { value: Some(v.clone()), exported: true, readonly: false });
        }
        let r = f(self);
        self.restore_vars(old_vars);
        self.restore(saved);
        r
    }

    pub(crate) fn restore_vars(&mut self, old: Vec<(String, Option<Var>)>) {
        for (n, v) in old.into_iter().rev() {
            match v {
                Some(v) => {
                    self.vars.insert(n, v);
                }
                None => {
                    self.vars.remove(&n);
                }
            }
        }
    }

    pub fn call_function(&mut self, body: &Command, fields: &[String]) -> Exec {
        let saved_pos = std::mem::replace(&mut self.positional, fields[1..].to_vec());
        let saved_loop = std::mem::take(&mut self.loop_depth);
        self.return_depth += 1;
        self.local_frames.push(Vec::new());
        let r = self.run_command(body);
        let frame = self.local_frames.pop().unwrap_or_default();
        self.restore_vars(frame);
        self.return_depth -= 1;
        self.loop_depth = saved_loop;
        self.positional = saved_pos;
        match r {
            Err(Flow::Return(s)) => Ok(s),
            other => other,
        }
    }

    fn run_external(&mut self, fields: &[String], assigns: &[(String, String)], redirs: &[Redirect], tail: bool) -> Exec {
        let path = match self.find_command(&fields[0]) {
            Some(p) => p,
            None => {
                // Redirections are still performed (and can fail) for a command not found.
                if let Ok(saved) = self.redirect(redirs, true) {
                    self.restore(saved);
                }
                self.error(&format!("{}: not found", fields[0]));
                return Ok(127);
            }
        };
        let env = self.environment(assigns);
        if tail {
            self.exec_in_child(&path, fields, &env, redirs);
        }
        let jc = self.job_control();
        match sys::fork() {
            Ok(0) => {
                if jc {
                    self.job_child_setup(0, true);
                }
                if self.interactive {
                    self.enter_subshell();
                }
                self.exec_in_child(&path, fields, &env, redirs)
            }
            Ok(pid) if jc => {
                self.job_parent_setup(pid, 0);
                let status = self.wait_foreground(pid, &[pid], &fields.join(" "));
                self.interrupted_by_child(status)?;
                Ok(status)
            }
            Ok(pid) => {
                let status = sys::wait_pid(pid).unwrap_or(1);
                self.interrupted_by_child(status)?;
                Ok(status)
            }
            Err(e) => {
                self.error(&format!("cannot fork: {e}"));
                Ok(2)
            }
        }
    }

    /// Applies `redirs` and execs; only returns by exiting the process.
    fn exec_in_child(&mut self, path: &str, fields: &[String], env: &[String], redirs: &[Redirect]) -> ! {
        if let Err(e) = self.redirect(redirs, false) {
            self.error(&e);
            sys::exit_child(1);
        }
        let err = sys::execve(path, fields, env);
        if err.raw_os_error() == Some(libc::ENOEXEC) {
            // XCU 2.9.1.1: a file that isn't an executable format is a shell script.
            self.run_script_in_place(path, fields);
        }
        self.error(&format!("{}: {}", fields[0], sys::strerror(&err)));
        sys::exit_child(if err.raw_os_error() == Some(libc::ENOENT) { 127 } else { 126 });
    }

    /// Runs `path` as a script in this (already forked) process, as a fresh shell would.
    fn run_script_in_place(&mut self, path: &str, fields: &[String]) -> ! {
        let source = match std::fs::read(path) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                self.error(&format!("{path}: {e}"));
                sys::exit_child(126);
            }
        };
        self.vars.retain(|_, v| v.exported);
        self.functions.clear();
        self.traps.clear();
        self.local_frames.clear();
        self.return_depth = 0;
        self.loop_depth = 0;
        self.cond_depth = 0;
        self.arg0 = path.to_string();
        self.positional = fields[1..].to_vec();
        let status = self.run_source(&source);
        sys::exit_child(status);
    }

    /// XCU 2.9.1.1 command search: a name with a `/` is used as is, otherwise `$PATH`.
    pub fn find_command(&self, name: &str) -> Option<String> {
        if name.contains('/') {
            return Some(name.to_string());
        }
        let path = self.get("PATH").unwrap_or_else(|| "/bin:/usr/bin".into());
        for dir in path.split(':') {
            let dir = if dir.is_empty() { "." } else { dir };
            let candidate = format!("{dir}/{name}");
            if sys::is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Performs redirections (XCU 2.7). With `save`, returns what's needed to undo them.
    pub(crate) fn redirect(&mut self, redirs: &[Redirect], save: bool) -> Result<Saved, String> {
        let mut saved: Saved = Vec::new();
        for r in redirs {
            if let Err(e) = self.redirect_one(r, save, &mut saved) {
                self.restore(saved);
                return Err(e);
            }
        }
        Ok(saved)
    }

    fn redirect_one(&mut self, r: &Redirect, save: bool, saved: &mut Saved) -> Result<(), String> {
        let default_fd = match r.op {
            RedirOp::Input | RedirOp::ReadWrite | RedirOp::DupInput | RedirOp::HereDoc => 0,
            RedirOp::Output | RedirOp::Clobber | RedirOp::Append | RedirOp::DupOutput => 1,
        };
        let fd = r.fd.map(|f| f as Fd).unwrap_or(default_fd);

        // Produce the new descriptor first: a failed open must leave `fd` untouched.
        let new_fd: Option<Fd> = match &r.target {
            RedirTarget::HereDoc(h) => {
                let body = h.body.borrow().clone();
                let text = if h.quoted {
                    body.iter()
                        .map(|p| match p {
                            WordPart::Quoted(s) | WordPart::Literal(s) => s.as_str(),
                            _ => "",
                        })
                        .collect()
                } else {
                    self.expand_string(&body).map_err(|_| "here-document expansion failed".to_string())?
                };
                Some(self.heredoc_fd(&text)?)
            }
            RedirTarget::Word(w) => {
                let target = self.expand_string(w).map_err(|_| "redirection expansion failed".to_string())?;
                match r.op {
                    RedirOp::DupInput | RedirOp::DupOutput => {
                        if target == "-" {
                            None
                        } else {
                            let src: Fd = target.parse().map_err(|_| format!("{target}: bad file descriptor"))?;
                            if !sys::is_open(src) {
                                return Err(format!("{src}: bad file descriptor"));
                            }
                            if src == fd {
                                return Ok(());
                            }
                            // dup, not dup2, so the source stays valid if it's saved below.
                            let d = unsafe { libc::fcntl(src, libc::F_DUPFD_CLOEXEC, 0) };
                            if d < 0 {
                                return Err(format!("{src}: bad file descriptor"));
                            }
                            Some(d)
                        }
                    }
                    _ => {
                        let flags = match r.op {
                            RedirOp::Input => libc::O_RDONLY,
                            RedirOp::ReadWrite => libc::O_RDWR | libc::O_CREAT,
                            RedirOp::Append => libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                            RedirOp::Clobber => libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                            RedirOp::Output if self.opts.noclobber => {
                                if std::fs::metadata(&target).is_ok_and(|m| m.is_file()) {
                                    return Err(format!("{target}: file exists"));
                                }
                                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC
                            }
                            _ => libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        };
                        let opened = sys::open(&target, flags | libc::O_CLOEXEC, 0o666).map_err(|e| {
                            let what = if r.op == RedirOp::Input { "cannot open" } else { "cannot create" };
                            format!("{target}: {what}: {}", sys::strerror(&e))
                        })?;
                        Some(opened)
                    }
                }
            }
        };

        if save && !saved.iter().any(|&(f, _)| f == fd) {
            let backup = if sys::is_open(fd) { Some(sys::dup_high(fd).map_err(|e| format!("{fd}: {e}"))?) } else { None };
            saved.push((fd, backup));
        }
        match new_fd {
            None => sys::close(fd),
            Some(n) => {
                // dup2 clears close-on-exec on the target, which is what we want.
                if n == fd {
                    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
                } else {
                    let res = sys::dup2(n, fd);
                    sys::close(n);
                    res.map_err(|e| format!("{fd}: {e}"))?;
                }
            }
        }
        Ok(())
    }

    fn heredoc_fd(&mut self, text: &str) -> Result<Fd, String> {
        let (r, w) = sys::pipe().map_err(|e| format!("cannot create pipe: {e}"))?;
        if text.len() <= HEREDOC_INLINE_MAX {
            let _ = sys::write_all(w, text.as_bytes());
            sys::close(w);
            return Ok(r);
        }
        match sys::fork() {
            Ok(0) => {
                sys::close(r);
                let _ = sys::write_all(w, text.as_bytes());
                sys::exit_child(0);
            }
            Ok(pid) => {
                sys::close(w);
                // The writer exits on its own once the reader drains or closes the pipe; reap it
                // later with the background jobs so it doesn't block this command.
                self.bg_pids.push(pid);
                Ok(r)
            }
            Err(e) => {
                sys::close(r);
                sys::close(w);
                Err(format!("cannot fork: {e}"))
            }
        }
    }

    pub(crate) fn restore(&mut self, saved: Saved) {
        for (fd, backup) in saved.into_iter().rev() {
            match backup {
                Some(b) => {
                    let _ = sys::dup2(b, fd);
                    sys::close(b);
                }
                None => sys::close(fd),
            }
        }
    }

    /// `${…}` lookups for built-ins that take a function or builtin by name.
    pub(crate) fn builtin_kind(&self, name: &str) -> Option<&'static str> {
        if builtins::lookup_special(name).is_some() {
            Some("special shell builtin")
        } else if self.functions.contains_key(name) {
            Some("function")
        } else if builtins::lookup_regular(name).is_some() {
            Some("shell builtin")
        } else {
            None
        }
    }

    /// Runs a built-in or external command by fields, bypassing functions (`command`).
    pub(crate) fn run_fields_no_functions(&mut self, fields: &[String]) -> Exec {
        let name = fields[0].as_str();
        let b: Option<Builtin> = builtins::lookup_special(name).or_else(|| builtins::lookup_regular(name));
        if let Some(b) = b {
            // Under `command`, a special built-in's errors don't end the shell.
            return match b(self, fields) {
                Err(Flow::Fatal(s)) => Ok(s),
                other => other,
            };
        }
        self.run_external(fields, &[], &[], false)
    }
}

/// Quotes a string for `set -x` / `set` / `export -p` output, if it needs it.
pub fn quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "_-./:=@%+,".contains(c)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}
