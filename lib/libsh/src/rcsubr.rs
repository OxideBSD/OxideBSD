//! FreeBSD's `rc.subr(8)` as native built-ins of the init dialect (INIT_SH.md §4.6-4.7), so
//! classic `rc.d` scripts -- `name=`, `rcvar=`, `command=`, `load_rc_config $name`,
//! `run_rc_command "$1"` -- run unchanged. `. /etc/rc.subr` finds these already defined.
//!
//! `rc.conf` is loaded natively rather than sourced: only assignments are accepted, and
//! `*_enable` / `*_restart` values must be YES/NO-like, both with warnings naming the file and line.

use crate::ast::{Command, ListItem, SimpleCommand};
use crate::builtins::Builtin;
use crate::shell::{Exec, Flow, Shell};
use crate::sys;

const BUILTINS: &[(&str, Builtin)] = &[
    ("check_pidfile", check_pidfile),
    ("check_process", check_process),
    ("checkyesno", checkyesno),
    ("debug", debug),
    ("err", err),
    ("force_depend", force_depend),
    ("info", info),
    ("load_rc_config", load_rc_config),
    ("run_rc_command", run_rc_command),
    ("wait_for_pids", wait_for_pids),
    ("warn", warn),
];

pub fn lookup(name: &str) -> Option<Builtin> {
    BUILTINS.iter().find(|(n, _)| *n == name).map(|&(_, b)| b)
}

pub fn names() -> impl Iterator<Item = &'static str> {
    BUILTINS.iter().map(|&(n, _)| n)
}

const DEFAULT_RC_CONF: &str = "/etc/defaults/rc.conf";
const DEFAULT_RC_CONF_FILES: &str = "/etc/rc.conf /etc/rc.conf.local";
const RC_CONF_D: &str = "/etc/rc.conf.d";

/// `YES`/`TRUE`/`ON`/`1` and their opposites, in any case (§4.6.2).
pub fn yesno(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Some(true),
        "no" | "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn out(s: &str) {
    let _ = sys::write_all(1, s.as_bytes());
}

fn report(sh: &Shell, level: &str, message: &str) {
    let _ = sys::write_all(2, format!("{}: {level}: {message}\n", sh.arg0).as_bytes());
}

fn is_yes(sh: &Shell, var: &str) -> bool {
    sh.get(var).and_then(|v| yesno(&v)).unwrap_or(false)
}

/// Runs shell source in the current shell, as `eval` does.
fn eval(sh: &mut Shell, source: &str) -> Exec {
    match crate::parse(source) {
        Ok(list) => sh.run_list(&list),
        Err(e) => {
            sh.error(&format!("{source}: {e}"));
            Ok(2)
        }
    }
}

// --- rc.conf ------------------------------------------------------------------------------------

/// An item made only of assignments: `a=1 b=2`, nothing else.
fn assignments_only(item: &ListItem) -> Option<&SimpleCommand> {
    let first = &item.and_or.first;
    if item.background || !item.and_or.rest.is_empty() || first.bang || first.commands.len() != 1 {
        return None;
    }
    match &first.commands[0] {
        Command::Simple(sc) if sc.words.is_empty() && sc.redirects.is_empty() && !sc.assignments.is_empty() => Some(sc),
        _ => None,
    }
}

/// Loads one `rc.conf`-format file into the shell's variables (§4.6).
pub fn load_conf_file(sh: &mut Shell, path: &str) {
    let text = match std::fs::read(path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => return report(sh, "WARNING", &format!("{path}: {}", sys::strerror(&e))),
    };
    let items = match crate::parse::parse_lines(&text) {
        Ok(items) => items,
        Err(e) => return report(sh, "WARNING", &format!("{path}:{e}; file ignored")),
    };
    for (line, item) in &items {
        let Some(sc) = assignments_only(item) else {
            report(sh, "WARNING", &format!("{path}:{line}: not an assignment; ignored"));
            continue;
        };
        for a in &sc.assignments {
            let Ok(mut value) = sh.expand_string(&a.value) else { continue };
            if (a.name.ends_with("_enable") || a.name.ends_with("_restart")) && yesno(&value).is_none() {
                report(sh, "WARNING", &format!("{path}:{line}: {}=\"{value}\" is not YES or NO; treated as NO", a.name));
                value = "NO".into();
            }
            if let Err(e) = sh.set(&a.name, &value) {
                report(sh, "WARNING", &format!("{path}:{line}: {e}"));
            }
        }
    }
}

/// `load_rc_config [name]`: `/etc/defaults/rc.conf`, then each of `$rc_conf_files`, once per
/// shell; then `/etc/rc.conf.d/<name>` if it exists.
fn load_rc_config(sh: &mut Shell, args: &[String]) -> Exec {
    if sh.get("_rc_conf_loaded").is_none() {
        load_conf_file(sh, DEFAULT_RC_CONF);
        let files = sh.get("rc_conf_files").unwrap_or_else(|| DEFAULT_RC_CONF_FILES.into());
        for f in files.split_whitespace() {
            if std::path::Path::new(f).is_file() {
                load_conf_file(sh, f);
            }
        }
        let _ = sh.set("_rc_conf_loaded", "YES");
    }
    if let Some(name) = args.get(1) {
        let path = format!("{RC_CONF_D}/{name}");
        if std::path::Path::new(&path).is_file() {
            load_conf_file(sh, &path);
        }
    }
    Ok(0)
}

fn checkyesno(sh: &mut Shell, args: &[String]) -> Exec {
    let Some(var) = args.get(1) else {
        report(sh, "ERROR", "usage: checkyesno var");
        return Ok(2);
    };
    match yesno(&sh.get(var).unwrap_or_default()) {
        Some(true) => Ok(0),
        Some(false) => Ok(1),
        None => {
            report(sh, "WARNING", &format!("${var} is not set properly - see rc.conf(5)."));
            Ok(1)
        }
    }
}

// --- messages -----------------------------------------------------------------------------------

fn info(sh: &mut Shell, args: &[String]) -> Exec {
    if is_yes(sh, "rc_info") {
        out(&format!("{}: INFO: {}\n", sh.arg0, args[1..].join(" ")));
    }
    Ok(0)
}

fn warn(sh: &mut Shell, args: &[String]) -> Exec {
    report(sh, "WARNING", &args[1..].join(" "));
    Ok(0)
}

fn debug(sh: &mut Shell, args: &[String]) -> Exec {
    if is_yes(sh, "rc_debug") {
        report(sh, "DEBUG", &args[1..].join(" "));
    }
    Ok(0)
}

/// `err exitval message...`: report and exit the script.
fn err(sh: &mut Shell, args: &[String]) -> Exec {
    let code = args.get(1).and_then(|c| c.parse::<i32>().ok()).unwrap_or(1);
    report(sh, "ERROR", &args.get(2..).unwrap_or_default().join(" "));
    Err(Flow::Exit(code & 0xff))
}

// --- processes ----------------------------------------------------------------------------------

fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 || *libc::__errno_location() == libc::EPERM }
}

/// `argv[0]` of a running process, from `/proc/<pid>/cmdline`.
fn argv0(pid: i32) -> Option<String> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let first = cmdline.split(|&b| b == 0).next()?;
    Some(String::from_utf8_lossy(first).into_owned())
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Whether process `pid` is running `procname`: the same path, or the same file name when either
/// side was started without a path.
fn runs(pid: i32, procname: &str) -> bool {
    argv0(pid).is_some_and(|a| a == procname || ((!a.contains('/') || !procname.contains('/')) && basename(&a) == basename(procname)))
}

/// The live pid in `pidfile`, if it is running `procname` (any program, if empty).
pub fn pidfile_pid(pidfile: &str, procname: &str) -> Option<i32> {
    let text = std::fs::read_to_string(pidfile).ok()?;
    let pid: i32 = text.split_whitespace().next()?.parse().ok()?;
    (pid > 0 && alive(pid) && (procname.is_empty() || runs(pid, procname))).then_some(pid)
}

/// Every process running `procname`, other than this shell.
pub fn find_processes(procname: &str) -> Vec<i32> {
    let me = std::process::id() as i32;
    let Ok(dir) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut pids: Vec<i32> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .filter(|&pid| pid != me && runs(pid, procname))
        .collect();
    pids.sort_unstable();
    pids
}

fn check_pidfile(sh: &mut Shell, args: &[String]) -> Exec {
    let (Some(pidfile), Some(procname)) = (args.get(1), args.get(2)) else {
        return err(sh, &["err".into(), "3".into(), "USAGE: check_pidfile pidfile procname [interpreter]".into()]);
    };
    if let Some(pid) = pidfile_pid(pidfile, procname) {
        out(&format!("{pid}\n"));
    }
    Ok(0)
}

fn check_process(sh: &mut Shell, args: &[String]) -> Exec {
    let Some(procname) = args.get(1) else {
        return err(sh, &["err".into(), "3".into(), "USAGE: check_process procname [interpreter]".into()]);
    };
    let pids = find_processes(procname);
    if !pids.is_empty() {
        out(&format!("{}\n", pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ")));
    }
    Ok(0)
}

fn wait_pids(pids: &[i32]) {
    let mut waiting: Vec<i32> = pids.iter().copied().filter(|&p| alive(p)).collect();
    if waiting.is_empty() {
        return;
    }
    out(&format!("Waiting for PIDS: {}", waiting.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ")));
    while !waiting.is_empty() {
        std::thread::sleep(std::time::Duration::from_millis(200));
        waiting.retain(|&p| alive(p));
    }
    out(".\n");
}

fn wait_for_pids(_: &mut Shell, args: &[String]) -> Exec {
    let pids: Vec<i32> = args[1..].iter().filter_map(|a| a.parse().ok()).collect();
    wait_pids(&pids);
    Ok(0)
}

/// `force_depend service [rcvar-prefix]`: start `service` if it isn't running, whether or not
/// it is enabled.
fn force_depend(sh: &mut Shell, args: &[String]) -> Exec {
    let Some(dep) = args.get(1) else {
        return err(sh, &["err".into(), "3".into(), "USAGE: force_depend script [var]".into()]);
    };
    let script = format!("/etc/rc.d/{dep}");
    if eval(sh, &format!("/sbin/init_sh {script} forcestatus >/dev/null 2>&1"))? == 0 {
        return Ok(0);
    }
    let name = sh.get("name").unwrap_or_default();
    info(sh, &["info".into(), format!("{name} depends on {dep}, which will be forced to start.")])?;
    if eval(sh, &format!("/sbin/init_sh {script} forcestart"))? != 0 {
        report(sh, "WARNING", &format!("Unable to force {dep}. It may already be running."));
        return Ok(1);
    }
    Ok(0)
}

// --- run_rc_command -----------------------------------------------------------------------------

/// A variable's value, if set and not empty.
fn var(sh: &Shell, name: &str) -> Option<String> {
    sh.get(name).filter(|v| !v.is_empty())
}

/// `rc_startmsgs`: "Starting foo." is printed unless quiet, or when quiet if this is YES (the
/// default).
fn start_messages(sh: &Shell, quiet: bool) -> bool {
    !quiet || sh.get("rc_startmsgs").is_none_or(|v| yesno(&v) != Some(false))
}

/// Runs `${action}_precmd`; its failure aborts the action unless forced.
fn precmd(sh: &mut Shell, action: &str, extra: &str, force: bool) -> Result<bool, Flow> {
    match var(sh, &format!("{action}_precmd")) {
        Some(c) => Ok(eval(sh, &format!("{c} {extra}"))? == 0 || force),
        None => Ok(true),
    }
}

fn postcmd(sh: &mut Shell, action: &str, extra: &str) -> Exec {
    match var(sh, &format!("{action}_postcmd")) {
        Some(c) => eval(sh, &format!("{c} {extra}")),
        None => Ok(0),
    }
}

/// `run_rc_command [fast|force|one|quiet]action [args...]`, driven by the script's variables:
/// `name`, `rcvar`, `command`, `command_args`, `pidfile`, `procname`, `extra_commands`,
/// `required_files`, `required_dirs`, `sig_stop`, `<action>_cmd`, `<action>_precmd`,
/// `<action>_postcmd`, and `rc.conf`'s `<name>_flags` / `<name>_program`.
fn run_rc_command(sh: &mut Shell, args: &[String]) -> Exec {
    let Some(name) = var(sh, "name") else {
        return err(sh, &["err".into(), "3".into(), "run_rc_command: name not set".into()]);
    };
    let full = args.get(1).cloned().unwrap_or_default();
    let extra = args.get(2..).unwrap_or_default().join(" ");
    let rcvar = sh.get("rcvar").unwrap_or_default();
    let (mut fast, mut force, mut quiet, mut prefix) = (false, false, false, "");
    let action = if let Some(a) = full.strip_prefix("fast") {
        (fast, quiet) = (true, true);
        a
    } else if let Some(a) = full.strip_prefix("force") {
        (force, prefix) = (true, "force");
        a
    } else if let Some(a) = full.strip_prefix("one") {
        prefix = "one";
        a
    } else if let Some(a) = full.strip_prefix("quiet") {
        (quiet, prefix) = (true, "quiet");
        a
    } else {
        full.as_str()
    };
    if matches!(prefix, "force" | "one") && !rcvar.is_empty() {
        let _ = sh.set(&rcvar, "YES");
    }

    let extra_commands = sh.get("extra_commands").unwrap_or_default();
    let mut keywords = vec!["start", "stop", "restart", "rcvar", "enabled", "status", "poll"];
    keywords.extend(extra_commands.split_whitespace());
    if !keywords.contains(&action) {
        if !action.is_empty() {
            report(sh, "ERROR", &format!("unknown directive '{action}'."));
        }
        let _ = sys::write_all(2, format!("Usage: {} [fast|force|one|quiet]({})\n", sh.arg0, keywords.join("|")).as_bytes());
        return Ok(1);
    }

    let enabled = rcvar.is_empty() || yesno(&sh.get(&rcvar).unwrap_or_default()) == Some(true);
    match action {
        "rcvar" => {
            if !rcvar.is_empty() {
                out(&format!("# {name}\n#\n{rcvar}=\"{}\"\n", sh.get(&rcvar).unwrap_or_default()));
            }
            return Ok(0);
        }
        "enabled" => return Ok(if enabled { 0 } else { 1 }),
        _ => {}
    }

    let command = var(sh, &format!("{name}_program")).or_else(|| var(sh, "command")).unwrap_or_default();
    let procname = var(sh, "procname").unwrap_or_else(|| command.clone());
    let pidfile = var(sh, "pidfile");
    let pids: Vec<i32> = match &pidfile {
        Some(pf) => pidfile_pid(pf, &procname).into_iter().collect(),
        None if !procname.is_empty() => find_processes(&procname),
        None => Vec::new(),
    };
    let pid_list = pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ");

    // Stopping a disabled service that is running is allowed; anything else needs it enabled.
    if !enabled && !(action == "stop" && !pids.is_empty()) {
        if !quiet {
            report(
                sh,
                "WARNING",
                &format!("Cannot '{action}' {name}. Set {rcvar} to YES in /etc/rc.conf or use 'one{action}' instead of '{action}'."),
            );
        }
        return Ok(0);
    }

    // A script-defined `<action>_cmd` replaces the built-in behavior.
    if let Some(cmd) = var(sh, &format!("{action}_cmd")) {
        if !precmd(sh, action, &extra, force)? {
            return Ok(1);
        }
        if eval(sh, &format!("{cmd} {extra}"))? != 0 {
            return Ok(1);
        }
        return postcmd(sh, action, &extra);
    }

    match action {
        "start" => {
            if !fast && !pids.is_empty() {
                if !quiet {
                    let _ = sys::write_all(2, format!("{name} already running? (pid={pid_list}).\n").as_bytes());
                }
                return Ok(1);
            }
            if command.is_empty() {
                report(sh, "WARNING", &format!("run_rc_command: {name}: no command to start"));
                return Ok(1);
            }
            if !force {
                for d in sh.get("required_dirs").unwrap_or_default().split_whitespace() {
                    if !std::path::Path::new(d).is_dir() {
                        report(sh, "WARNING", &format!("{d} is not a directory."));
                        return Ok(1);
                    }
                }
                for f in sh.get("required_files").unwrap_or_default().split_whitespace() {
                    if !std::path::Path::new(f).exists() {
                        report(sh, "WARNING", &format!("{f} is not readable."));
                        return Ok(1);
                    }
                }
            }
            if var(sh, &format!("{name}_user")).is_some() {
                report(sh, "WARNING", &format!("{name}_user is not supported yet"));
                return Ok(1);
            }
            if !precmd(sh, "start", &extra, force)? {
                return Ok(1);
            }
            if start_messages(sh, quiet) {
                out(&format!("Starting {name}.\n"));
            }
            let flags = var(sh, "flags").or_else(|| var(sh, &format!("{name}_flags"))).unwrap_or_default();
            let args = sh.get("command_args").unwrap_or_default();
            if eval(sh, &format!("{command} {flags} {args}"))? != 0 {
                return Ok(1);
            }
            postcmd(sh, "start", &extra)
        }
        "stop" => {
            if pids.is_empty() {
                if !quiet {
                    let hint = pidfile.as_ref().map(|p| format!(" (check {p})")).unwrap_or_default();
                    let _ = sys::write_all(2, format!("{name} not running?{hint}.\n").as_bytes());
                }
                return Ok(1);
            }
            if !precmd(sh, "stop", &extra, force)? {
                return Ok(1);
            }
            if start_messages(sh, quiet) {
                out(&format!("Stopping {name}.\n"));
            }
            let sig = var(sh, "sig_stop").unwrap_or_else(|| "TERM".into());
            eval(sh, &format!("kill -{sig} {pid_list}"))?;
            wait_pids(&pids);
            postcmd(sh, "stop", &extra)
        }
        "restart" => {
            if !precmd(sh, "restart", &extra, force)? {
                return Ok(1);
            }
            // As FreeBSD: a failed stop (not running) doesn't prevent the start.
            run_rc_command(sh, &[args[0].clone(), format!("{prefix}stop")])?;
            let status = run_rc_command(sh, &[args[0].clone(), format!("{prefix}start")])?;
            if status != 0 {
                return Ok(status);
            }
            postcmd(sh, "restart", &extra)
        }
        "status" => {
            if pids.is_empty() {
                out(&format!("{name} is not running.\n"));
                return Ok(1);
            }
            out(&format!("{name} is running as pid {pid_list}.\n"));
            Ok(0)
        }
        "poll" => {
            wait_pids(&pids);
            Ok(0)
        }
        _ => {
            report(sh, "WARNING", &format!("{action}: no {action}_cmd defined"));
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell() -> Shell {
        Shell::new("test".into(), Vec::new())
    }

    fn conf(text: &str) -> Shell {
        let dir = std::env::temp_dir().join(format!("libsh-rcconf-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::write(&dir, text).unwrap();
        let mut sh = shell();
        load_conf_file(&mut sh, dir.to_str().unwrap());
        std::fs::remove_file(&dir).unwrap();
        sh
    }

    #[test]
    fn yes_and_no() {
        for y in ["YES", "yes", "True", "ON", "1"] {
            assert_eq!(yesno(y), Some(true), "{y}");
        }
        for n in ["NO", "false", "Off", "0"] {
            assert_eq!(yesno(n), Some(false), "{n}");
        }
        assert_eq!(yesno("NONE"), None);
        assert_eq!(yesno(""), None);
    }

    #[test]
    fn rc_conf_takes_assignments_only() {
        let sh = conf("# comment\nhostname=\"box\"\nfoo_flags=\"-a ${hostname}\"\ncron_enable=YES a=1\necho hi\nbad_enable=\"maybe\"\n");
        assert_eq!(sh.get("hostname").as_deref(), Some("box"));
        assert_eq!(sh.get("foo_flags").as_deref(), Some("-a box"));
        assert_eq!(sh.get("cron_enable").as_deref(), Some("YES"));
        assert_eq!(sh.get("a").as_deref(), Some("1"));
        assert_eq!(sh.get("bad_enable").as_deref(), Some("NO"));
    }

    #[test]
    fn a_syntax_error_ignores_the_file() {
        let sh = conf("a=1\nb=\"unterminated\n");
        assert_eq!(sh.get("a"), None);
    }

    #[test]
    fn checkyesno_status() {
        let mut sh = shell();
        sh.set("x", "Yes").unwrap();
        sh.set("y", "no").unwrap();
        sh.set("z", "bogus").unwrap();
        let run = |sh: &mut Shell, v: &str| checkyesno(sh, &["checkyesno".into(), v.into()]).unwrap();
        assert_eq!(run(&mut sh, "x"), 0);
        assert_eq!(run(&mut sh, "y"), 1);
        assert_eq!(run(&mut sh, "z"), 1);
        assert_eq!(run(&mut sh, "unset"), 1);
    }
}
