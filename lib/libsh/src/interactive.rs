//! The interactive shell (XCU 2.1, `sh -i`): prompts, the line editor, startup files, job
//! control, and surviving errors that would end a script.

use crate::lineedit::{Editor, ReadResult};
use crate::parse;
use crate::shell::{Flow, PENDING_SIGNALS, Shell, trap_handler};
use crate::sys;
use std::sync::atomic::Ordering;

impl Shell {
    /// Reads and runs commands from the terminal until end of input or `exit`. Returns the exit
    /// status.
    pub fn run_interactive(&mut self) -> i32 {
        self.interactive = true;
        let Some((tty, tty_out)) = crate::jobs::claim_terminal() else {
            self.error("interactive mode needs a terminal");
            return 2;
        };
        self.tty_fd = Some(tty);
        self.tty_modes = sys::tcgetattr(tty).ok();

        // SIGINT interrupts the command line being run, not the shell; SIGTERM and SIGQUIT are
        // ignored (XCU 2.11).
        sys::set_signal(libc::SIGINT, trap_handler as *const () as libc::sighandler_t);
        sys::set_signal(libc::SIGQUIT, libc::SIG_IGN);
        sys::set_signal(libc::SIGTERM, libc::SIG_IGN);
        if self.opts.monitor {
            self.start_job_control(tty);
        }

        self.run_startup_files();

        let hist_file = self.get("HISTFILE").or_else(|| self.get("HOME").map(|h| format!("{}/.sh_history", h.trim_end_matches('/'))));
        let hist_max = self.get("HISTSIZE").and_then(|s| s.parse().ok()).unwrap_or(500);
        let mut editor = Editor::new(tty, tty_out, hist_file, hist_max);
        let mut warned_stopped = false;

        let status = loop {
            if self.job_control() {
                self.notify_jobs();
            }
            let Some(source) = self.read_command(&mut editor) else {
                // End of input.
                if self.has_stopped_jobs() && !warned_stopped {
                    warned_stopped = true;
                    self.error("there are stopped jobs");
                    continue;
                }
                break self.status;
            };
            let list = match parse::parse(&source) {
                Ok(list) => list,
                Err(e) => {
                    editor.add_history(&source);
                    self.error(&format!("syntax error: {e}"));
                    self.status = 2;
                    continue;
                }
            };
            editor.add_history(&source);
            if self.opts.noexec {
                continue;
            }
            self.current_text = source.trim_end().to_string();
            match self.run_list(&list) {
                Ok(s) => self.status = s,
                Err(Flow::Exit(s)) => {
                    if self.has_stopped_jobs() && !warned_stopped {
                        warned_stopped = true;
                        self.status = s;
                        self.error("there are stopped jobs");
                        continue;
                    }
                    break s;
                }
                Err(Flow::Fatal(s) | Flow::Return(s)) => self.status = s,
                Err(Flow::Break(_) | Flow::Continue(_)) => {}
            }
            warned_stopped = false;
        };
        editor.save_history();
        self.hangup_jobs();
        if let (Some(tty), Some(t)) = (self.tty_fd, &self.tty_modes) {
            let _ = sys::tcsetattr(tty, t);
        }
        self.finish(status)
    }

    /// Puts the shell in its own process group in the foreground (waiting while some other group
    /// has the terminal, as a job-control shell started in the background must), and ignores the
    /// stop signals only its jobs should get.
    fn start_job_control(&mut self, tty: sys::Fd) {
        loop {
            let fg = sys::tcgetpgrp(tty);
            if fg < 0 || fg == sys::getpgrp() {
                break;
            }
            let _ = sys::kill(0, libc::SIGTTIN);
        }
        for sig in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
            sys::set_signal(sig, libc::SIG_IGN);
        }
        let pid = sys::getpid();
        if sys::getpgrp() != pid {
            // A session leader (pid 1, a login shell) already leads its own group.
            let _ = sys::setpgid(0, pid);
        }
        self.shell_pgid = sys::getpgrp();
        if sys::tcsetpgrp(tty, self.shell_pgid).is_err() {
            self.error("can't access the terminal: job control turned off");
            self.opts.monitor = false;
        }
    }

    /// A login shell (`argv[0]` starting with `-`) reads `/etc/profile` and `~/.profile`; every
    /// interactive shell then reads the file named by `$ENV` (XCU `sh`, ENVIRONMENT VARIABLES).
    fn run_startup_files(&mut self) {
        if self.arg0.starts_with('-') {
            self.source_if_exists("/etc/profile");
            if let Some(home) = self.get("HOME") {
                self.source_if_exists(&format!("{}/.profile", home.trim_end_matches('/')));
            }
        }
        if let Some(env) = self.get("ENV") {
            let path = match parse::parse_heredoc_body(&env) {
                Ok(w) => self.expand_string(&w).unwrap_or(env),
                Err(_) => env,
            };
            self.source_if_exists(&path);
        }
    }

    fn source_if_exists(&mut self, path: &str) {
        let Ok(bytes) = std::fs::read(path) else { return };
        match parse::parse(&String::from_utf8_lossy(&bytes)) {
            Ok(list) => {
                if let Err(Flow::Exit(s)) = self.run_list(&list) {
                    self.status = s;
                }
            }
            Err(e) => self.error(&format!("{path}: syntax error: {e}")),
        }
    }

    /// Reads one complete command: `PS1`, then `PS2` lines while the input so far is unfinished
    /// (an open quote, `if` without `fi`, a trailing `|` or backslash...). `None` at end of input.
    fn read_command(&mut self, editor: &mut Editor) -> Option<String> {
        let mut source = String::new();
        let mut first = true;
        loop {
            let ps = if first { self.expand_prompt("PS1", if sys::geteuid() == 0 { "# " } else { "$ " }) } else { self.expand_prompt("PS2", "> ") };
            // A Ctrl+C that arrived while the previous command ran has done its job already.
            PENDING_SIGNALS.fetch_and(!(1 << libc::SIGINT), Ordering::SeqCst);
            match editor.read_line(self, &ps) {
                ReadResult::Line(l) => {
                    source.push_str(&l);
                    source.push('\n');
                }
                ReadResult::Interrupted => {
                    self.status = 130;
                    source.clear();
                    first = true;
                    continue;
                }
                ReadResult::Eof => {
                    return if first { None } else { Some(source) };
                }
            }
            first = false;
            if ends_with_continuation(&source) {
                continue;
            }
            match parse::parse(&source) {
                Err(e) if e.incomplete => continue,
                _ => return Some(source),
            }
        }
    }
}

/// A line ending in an unescaped backslash continues on the next one.
fn ends_with_continuation(s: &str) -> bool {
    let body = s.strip_suffix('\n').unwrap_or(s);
    body.chars().rev().take_while(|&c| c == '\\').count() % 2 == 1
}
