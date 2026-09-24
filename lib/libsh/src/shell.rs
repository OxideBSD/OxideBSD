//! Shell state and the entry point.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ast::Command;
use crate::sys;

#[derive(Clone, Debug, Default)]
pub struct Var {
    pub value: Option<String>,
    pub exported: bool,
    pub readonly: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// `-a`
    pub allexport: bool,
    /// `-C`
    pub noclobber: bool,
    /// `-e`
    pub errexit: bool,
    /// `-f`
    pub noglob: bool,
    /// `-m`: job control. On by default in an interactive shell.
    pub monitor: bool,
    /// `-n`
    pub noexec: bool,
    /// `-u`
    pub nounset: bool,
    /// `-v`
    pub verbose: bool,
    /// `-x`
    pub xtrace: bool,
}

impl Options {
    pub const LETTERS: &'static [(char, &'static str)] = &[
        ('a', "allexport"),
        ('C', "noclobber"),
        ('e', "errexit"),
        ('f', "noglob"),
        ('m', "monitor"),
        ('n', "noexec"),
        ('u', "nounset"),
        ('v', "verbose"),
        ('x', "xtrace"),
    ];

    pub fn flag_mut(&mut self, letter: char) -> Option<&mut bool> {
        Some(match letter {
            'a' => &mut self.allexport,
            'C' => &mut self.noclobber,
            'e' => &mut self.errexit,
            'f' => &mut self.noglob,
            'm' => &mut self.monitor,
            'n' => &mut self.noexec,
            'u' => &mut self.nounset,
            'v' => &mut self.verbose,
            'x' => &mut self.xtrace,
            _ => return None,
        })
    }

    pub fn letter_for(name: &str) -> Option<char> {
        Self::LETTERS.iter().find(|(_, n)| *n == name).map(|&(c, _)| c)
    }
}

/// Non-local control flow, carried up the call stack as the `Err` side of `Exec`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Break(usize),
    Continue(usize),
    Return(i32),
    /// `exit`, or `set -e` tripping: always ends the shell.
    Exit(i32),
    /// A shell error (XCU 2.8.1): ends a non-interactive shell, but an interactive one only
    /// abandons the current command line.
    Fatal(i32),
}

pub type Exec = Result<i32, Flow>;

/// Signals caught by a `trap` action, not yet run.
pub(crate) static PENDING_SIGNALS: AtomicU64 = AtomicU64::new(0);

pub(crate) extern "C" fn trap_handler(sig: libc::c_int) {
    PENDING_SIGNALS.fetch_or(1 << sig, Ordering::SeqCst);
}

pub struct Shell {
    pub vars: HashMap<String, Var>,
    pub positional: Vec<String>,
    pub arg0: String,
    /// `$?`
    pub status: i32,
    pub functions: HashMap<String, Rc<Command>>,
    pub opts: Options,
    /// `$!`
    pub last_bg: Option<i32>,
    pub bg_pids: Vec<i32>,
    /// `$$` -- the top-level shell's pid, unchanged in subshells.
    pub shell_pid: i32,
    pub loop_depth: usize,
    /// Nesting of function calls and `.` scripts, which `return` may leave.
    pub return_depth: usize,
    /// Saved variables to restore when the current function returns (`local`).
    pub local_frames: Vec<Vec<(String, Option<Var>)>>,
    /// Trap actions by signal number; 0 is `EXIT`.
    pub traps: HashMap<i32, String>,
    /// >0 while running a condition (`if`/`while` test, `&&`/`||` left side, `!`), where `-e`
    /// does not apply.
    pub cond_depth: usize,
    /// Running in a forked subshell (affects `exit` from traps and a few messages).
    pub is_subshell: bool,
    /// `getopts`' position inside the current argument.
    pub getopts_char: usize,
    /// Statuses of asynchronous lists already reaped, for a later `wait`.
    pub bg_done: HashMap<i32, i32>,
    /// The next simple command is the last thing a forked child does: it may exec in place.
    pub tail: bool,
    /// Status of the last command substitution in the current simple command.
    pub subst_status: Option<i32>,
    /// Reading commands from a terminal (`-i`, or no script with a terminal on stdin).
    pub interactive: bool,
    /// The terminal an interactive shell uses for prompts, editing and job control.
    pub tty_fd: Option<sys::Fd>,
    /// The terminal's modes when the shell started, restored after each foreground job.
    pub tty_modes: Option<libc::termios>,
    /// The shell's own process group, which gets the terminal back after a job.
    pub shell_pgid: i32,
    pub jobs: Vec<crate::jobs::Job>,
    /// Job ids, least recently used first: the last is `%+`, the one before `%-`.
    pub job_order: Vec<usize>,
    /// The command line being run, which names any job it starts.
    pub current_text: String,
}

impl Shell {
    pub fn new(arg0: String, positional: Vec<String>) -> Self {
        let mut sh = Shell {
            vars: HashMap::new(),
            positional,
            arg0,
            status: 0,
            functions: HashMap::new(),
            opts: Options::default(),
            last_bg: None,
            bg_pids: Vec::new(),
            shell_pid: sys::getpid(),
            loop_depth: 0,
            return_depth: 0,
            local_frames: Vec::new(),
            traps: HashMap::new(),
            cond_depth: 0,
            is_subshell: false,
            getopts_char: 0,
            bg_done: HashMap::new(),
            tail: false,
            subst_status: None,
            interactive: false,
            tty_fd: None,
            tty_modes: None,
            shell_pgid: sys::getpid(),
            jobs: Vec::new(),
            job_order: Vec::new(),
            current_text: String::new(),
        };
        for (k, v) in std::env::vars_os() {
            let (Some(k), Some(v)) = (k.to_str(), v.to_str()) else { continue };
            if crate::parse::is_name(k) {
                sh.vars.insert(k.to_string(), Var { value: Some(v.to_string()), exported: true, readonly: false });
            }
        }
        sh.set_default("IFS", " \t\n");
        sh.set_default("PS1", "$ ");
        sh.set_default("PS2", "> ");
        sh.set_default("PS4", "+ ");
        sh.set_default("OPTIND", "1");
        let ppid = sys::getppid().to_string();
        sh.vars.insert("PPID".into(), Var { value: Some(ppid), exported: false, readonly: false });
        if let Ok(cwd) = std::env::current_dir()
            && let Some(cwd) = cwd.to_str()
        {
            let keep = sh.get("PWD").is_some_and(|p| p.starts_with('/') && same_dir(&p, cwd));
            if !keep {
                let _ = sh.set("PWD", cwd);
            }
        }
        sh
    }

    fn set_default(&mut self, name: &str, value: &str) {
        self.vars.entry(name.to_string()).or_insert(Var { value: Some(value.into()), exported: false, readonly: false });
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.vars.get(name).and_then(|v| v.value.clone())
    }

    pub fn set(&mut self, name: &str, value: &str) -> Result<(), String> {
        let allexport = self.opts.allexport;
        let var = self.vars.entry(name.to_string()).or_default();
        if var.readonly {
            return Err(format!("{name}: is read only"));
        }
        var.value = Some(value.to_string());
        if allexport {
            var.exported = true;
        }
        if name == "OPTIND" {
            self.getopts_char = 0;
        }
        Ok(())
    }

    pub fn unset(&mut self, name: &str) -> Result<(), String> {
        if self.vars.get(name).is_some_and(|v| v.readonly) {
            return Err(format!("{name}: is read only"));
        }
        self.vars.remove(name);
        Ok(())
    }

    pub fn ifs(&self) -> String {
        self.get("IFS").unwrap_or_else(|| " \t\n".into())
    }

    /// `name=value` strings for every exported variable, plus `extra` (a command's own
    /// assignments, which override).
    pub fn environment(&self, extra: &[(String, String)]) -> Vec<String> {
        let mut env: Vec<String> = self
            .vars
            .iter()
            .filter(|(k, v)| v.exported && v.value.is_some() && !extra.iter().any(|(n, _)| n == *k))
            .map(|(k, v)| format!("{k}={}", v.value.as_deref().unwrap_or("")))
            .collect();
        env.extend(extra.iter().map(|(k, v)| format!("{k}={v}")));
        env
    }

    /// Prints `prog: message` to standard error.
    pub fn error(&self, message: &str) {
        let _ = sys::write_all(2, format!("{}: {message}\n", self.arg0).as_bytes());
    }

    /// Runs a complete script. Parse errors are status 2.
    pub fn run_source(&mut self, source: &str) -> i32 {
        let list = match crate::parse(source) {
            Ok(list) => list,
            Err(e) => {
                self.error(&format!("syntax error: {e}"));
                return self.finish(2);
            }
        };
        if self.opts.noexec {
            return self.finish(0);
        }
        let status = match self.run_list(&list) {
            Ok(s) => s,
            Err(Flow::Exit(s) | Flow::Fatal(s)) => s,
            Err(Flow::Return(s)) => s,
            Err(Flow::Break(_) | Flow::Continue(_)) => self.status,
        };
        self.finish(status)
    }

    /// Runs the `EXIT` trap (once) and returns the final status.
    pub fn finish(&mut self, status: i32) -> i32 {
        self.status = status;
        if let Some(action) = self.traps.remove(&0) {
            let saved = self.status;
            if let Ok(list) = crate::parse(&action) {
                match self.run_list(&list) {
                    Err(Flow::Exit(s) | Flow::Fatal(s)) => return s,
                    _ => self.status = saved,
                }
            }
        }
        self.status
    }

    /// Runs any trap actions for signals caught since the last check.
    pub fn run_pending_traps(&mut self) -> Result<(), Flow> {
        let pending = PENDING_SIGNALS.swap(0, Ordering::SeqCst);
        if pending == 0 {
            return Ok(());
        }
        if self.interactive && pending & (1 << libc::SIGINT) != 0 && !self.traps.contains_key(&libc::SIGINT) {
            let _ = sys::write_all(2, b"\n");
            return Err(Flow::Fatal(130));
        }
        for sig in 1..64 {
            if pending & (1 << sig) != 0
                && let Some(action) = self.traps.get(&sig).cloned()
                && let Ok(list) = crate::parse(&action)
            {
                let saved = self.status;
                self.run_list(&list)?;
                self.status = saved;
            }
        }
        Ok(())
    }

    /// Restores default signal dispositions for trapped signals, as a subshell or executed
    /// command must (ignored signals stay ignored).
    pub fn reset_traps_for_child(&mut self) {
        let caught: Vec<i32> = self.traps.iter().filter(|(s, a)| **s != 0 && !a.is_empty()).map(|(s, _)| *s).collect();
        for sig in caught {
            unsafe {
                libc::signal(sig, libc::SIG_DFL);
            }
            self.traps.remove(&sig);
        }
        self.traps.remove(&0);
    }
}

fn same_dir(a: &str, b: &str) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => {
            use std::os::unix::fs::MetadataExt;
            x.dev() == y.dev() && x.ino() == y.ino()
        }
        _ => false,
    }
}

/// Whether this binary offers an interactive shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interactive {
    /// Exit with an error (`/sbin/init_sh`, INIT_SH.md §3.2).
    Refuse,
    /// `/bin/sh`.
    Allow,
}

/// `sh [-abCefnuvx] [-o opt]... [-c command_string [command_name [arg...]] | script [arg...]]`
pub fn main(args: Vec<String>) -> i32 {
    main_with(args, Interactive::Refuse)
}

fn refuse_interactive(prog: &str) -> i32 {
    let _ = sys::write_all(2, format!("{prog}: interactive mode is not supported\n").as_bytes());
    2
}

pub fn main_with(args: Vec<String>, interactive: Interactive) -> i32 {
    // Rust ignores SIGPIPE at startup; a shell must not pass that on to what it runs.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let prog = args.first().cloned().unwrap_or_else(|| "sh".into());
    let mut i = 1;
    let mut opts = Options::default();
    let mut command_string = false;
    let mut force_interactive = false;
    // `-m`/`+m` given explicitly; otherwise an interactive shell turns job control on itself.
    let mut monitor_set = false;
    while i < args.len() {
        let a = &args[i];
        if a == "--" || a == "-" {
            i += 1;
            break;
        }
        let (on, flags) = match (a.strip_prefix('-'), a.strip_prefix('+')) {
            (Some(f), _) if !f.is_empty() => (true, f),
            (_, Some(f)) if !f.is_empty() => (false, f),
            _ => break,
        };
        for c in flags.chars() {
            if c == 'c' {
                command_string = true;
            } else if c == 'o' {
                i += 1;
                let Some(name) = args.get(i) else { break };
                if let Some(f) = Options::letter_for(name).and_then(|l| opts.flag_mut(l)) {
                    *f = on;
                }
            } else if c == 's' {
                // Read commands from standard input: the default without a script anyway.
            } else if c == 'i' {
                if interactive == Interactive::Refuse {
                    return refuse_interactive(&prog);
                }
                force_interactive = on;
            } else if let Some(f) = opts.flag_mut(c) {
                *f = on;
                monitor_set |= c == 'm';
            } else {
                let _ = sys::write_all(2, format!("{prog}: illegal option -{c}\n").as_bytes());
                return 2;
            }
        }
        i += 1;
    }
    let rest = &args[i.min(args.len())..];
    let (source, arg0, positional) = if command_string {
        let Some(cmd) = rest.first() else {
            let _ = sys::write_all(2, format!("{prog}: -c requires an argument\n").as_bytes());
            return 2;
        };
        let arg0 = rest.get(1).cloned().unwrap_or_else(|| prog.clone());
        (cmd.clone(), arg0, rest.iter().skip(2).cloned().collect())
    } else if let Some(script) = rest.first() {
        match std::fs::read(script) {
            Ok(bytes) => (String::from_utf8_lossy(&bytes).into_owned(), script.clone(), rest[1..].to_vec()),
            Err(e) => {
                let _ = sys::write_all(2, format!("{prog}: cannot open {script}: {e}\n").as_bytes());
                return 127;
            }
        }
    } else {
        if force_interactive || (sys::isatty(0) && sys::isatty(2)) {
            if interactive == Interactive::Refuse {
                return refuse_interactive(&prog);
            }
            let mut sh = Shell::new(prog.clone(), rest.to_vec());
            sh.opts = opts;
            if !monitor_set {
                sh.opts.monitor = true;
            }
            return sh.run_interactive();
        }
        match sys::read_to_end(0) {
            Ok(bytes) => (String::from_utf8_lossy(&bytes).into_owned(), prog.clone(), Vec::new()),
            Err(e) => {
                let _ = sys::write_all(2, format!("{prog}: reading standard input: {e}\n").as_bytes());
                return 2;
            }
        }
    };
    let mut sh = Shell::new(arg0, positional);
    sh.opts = opts;
    sh.run_source(&source)
}
