//! `crontab(1)`: installs, lists, edits and removes users' tables for `cron(8)` (OxideBSD-doc
//! `CRON.md` §5).
//!
//! ```text
//! crontab [-u user] file        install a table from a file, or from standard input as "-"
//! crontab [-u user] -l          list it
//! crontab [-u user] -e          edit it with $VISUAL, $EDITOR or vi
//! crontab [-u user] -r [-f]     remove it, after asking unless -f
//! ```
//!
//! A table is checked with cron's own parser before it is installed. Tables are written to
//! `/var/cron/tabs/<user>`, owned by root, mode 0600; the directory's time is updated so that
//! cron rereads it. On the BSDs crontab is set-user-ID root; until OxideBSD runs set-user-ID
//! programs, only root may use it (§5.5).

use std::io::{BufRead, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const TABS: &str = "/var/cron/tabs";
const ALLOW: &str = "/var/cron/allow";
const DENY: &str = "/var/cron/deny";

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Install(String),
    List,
    Edit,
    Remove { force: bool },
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    user: Option<String>,
    action: Action,
}

fn parse_args(args: &[String]) -> Result<Args, ()> {
    let mut user = None;
    let mut action = None;
    let mut force = false;
    let mut file = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-u" => {
                i += 1;
                user = Some(args.get(i).ok_or(())?.clone());
            }
            "-l" | "-e" | "-r" if action.is_none() => {
                action = Some(a.clone());
            }
            "-f" => force = true,
            "-" => file = Some(a.clone()),
            s if s.starts_with('-') => return Err(()),
            _ if file.is_none() => file = Some(a.clone()),
            _ => return Err(()),
        }
        i += 1;
    }
    let action = match (action.as_deref(), file) {
        (Some("-l"), None) if !force => Action::List,
        (Some("-e"), None) if !force => Action::Edit,
        (Some("-r"), None) => Action::Remove { force },
        (None, Some(f)) if !force => Action::Install(f),
        _ => return Err(()),
    };
    Ok(Args { user, action })
}

fn usage() -> ExitCode {
    eprintln!("usage: crontab [-u user] file");
    eprintln!("       crontab [-u user] -l | -e | -r [-f]");
    ExitCode::from(1)
}

/// §5.4: whether `user` may have a table, from `allow` and `deny` (the texts of
/// `/var/cron/allow` and `/var/cron/deny`, if they exist). Root always may.
fn permitted(user: &str, allow: Option<&str>, deny: Option<&str>) -> bool {
    let listed = |text: &str| text.lines().map(str::trim).any(|l| l == user);
    if user == "root" {
        return true;
    }
    match (allow, deny) {
        (Some(a), _) => listed(a),
        (None, Some(d)) => !listed(d),
        (None, None) => true,
    }
}

fn table_path(user: &str) -> PathBuf {
    Path::new(TABS).join(user)
}

/// Checks a table (§5.2); the errors, each with its line number.
fn check(text: &str) -> Vec<(usize, String)> {
    libcron::parse(text, false).1
}

/// Writes `text` as `user`'s table: a new file, mode 0600, renamed into place, then the
/// directory's time updated so that cron notices.
fn install(user: &str, text: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(TABS)?;
    std::fs::set_permissions(TABS, std::fs::Permissions::from_mode(0o700))?;
    let tmp = Path::new(TABS).join(format!(".tmp.{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    if !text.is_empty() && !text.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    f.sync_all()?;
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, table_path(user)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    touch_tabs();
    Ok(())
}

fn touch_tabs() {
    let dir = std::ffi::CString::new(TABS).unwrap_or_default();
    // SAFETY: a NUL-terminated path; a null times pointer means now.
    unsafe { libc::utimensat(libc::AT_FDCWD, dir.as_ptr(), std::ptr::null(), 0) };
}

fn report(source: &str, errors: &[(usize, String)]) {
    for (line, e) in errors {
        eprintln!("crontab: {source}: line {line}: {e}");
    }
}

fn ask(question: &str) -> bool {
    eprint!("{question} ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().lock().read_line(&mut answer);
    matches!(answer.trim_start().chars().next(), Some('y' | 'Y'))
}

fn do_install(user: &str, file: &str) -> ExitCode {
    let text = if file == "-" {
        let mut s = String::new();
        if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut s) {
            eprintln!("crontab: standard input: {e}");
            return ExitCode::from(1);
        }
        s
    } else {
        match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("crontab: {file}: {e}");
                return ExitCode::from(1);
            }
        }
    };
    let errors = check(&text);
    if !errors.is_empty() {
        report(if file == "-" { "standard input" } else { file }, &errors);
        eprintln!("crontab: errors in crontab file, can't install");
        return ExitCode::from(1);
    }
    match install(user, &text) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("crontab: {}: {e}", table_path(user).display());
            ExitCode::from(1)
        }
    }
}

fn do_list(user: &str) -> ExitCode {
    match std::fs::read(table_path(user)) {
        Ok(text) => {
            let _ = std::io::stdout().write_all(&text);
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("crontab: no crontab for {user}");
            ExitCode::from(1)
        }
    }
}

fn do_remove(user: &str, force: bool) -> ExitCode {
    let path = table_path(user);
    if !path.exists() {
        eprintln!("crontab: no crontab for {user}");
        return ExitCode::from(1);
    }
    if !force && !ask(&format!("remove crontab for {user}?")) {
        return ExitCode::SUCCESS;
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {
            touch_tabs();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("crontab: {}: {e}", path.display());
            ExitCode::from(1)
        }
    }
}

fn do_edit(user: &str) -> ExitCode {
    let original = std::fs::read_to_string(table_path(user)).unwrap_or_default();
    let tmp = std::env::temp_dir().join(format!("crontab.{}", std::process::id()));
    let created = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(original.as_bytes()));
    if let Err(e) = created {
        eprintln!("crontab: {}: {e}", tmp.display());
        return ExitCode::from(1);
    }
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .ok()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| "vi".into());
    loop {
        match Command::new(&editor).arg(&tmp).status() {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!(
                    "crontab: {editor} exited with {s}; edits left in {}",
                    tmp.display()
                );
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("crontab: {editor}: {e}");
                let _ = std::fs::remove_file(&tmp);
                return ExitCode::from(1);
            }
        }
        let edited = std::fs::read_to_string(&tmp).unwrap_or_default();
        if edited == original {
            eprintln!("crontab: no changes made to crontab");
            let _ = std::fs::remove_file(&tmp);
            return ExitCode::SUCCESS;
        }
        let errors = check(&edited);
        if errors.is_empty() {
            let result = install(user, &edited);
            let _ = std::fs::remove_file(&tmp);
            return match result {
                Ok(()) => {
                    eprintln!("crontab: installing new crontab");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("crontab: {}: {e}", table_path(user).display());
                    ExitCode::from(1)
                }
            };
        }
        report("the edited table", &errors);
        if !ask("Do you want to retry the same edit? (y/n)") {
            eprintln!("crontab: edits left in {}", tmp.display());
            return ExitCode::from(1);
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Ok(args) = parse_args(&argv) else {
        return usage();
    };

    // SAFETY: getuid(2) can't fail.
    let uid = unsafe { libc::getuid() };
    let Some(me) = pwd::lookup_uid(uid) else {
        eprintln!("crontab: who are you? (uid {uid} has no account)");
        return ExitCode::from(1);
    };
    if uid != 0 {
        let read = |p: &str| std::fs::read_to_string(p).ok();
        if !permitted(&me.name, read(ALLOW).as_deref(), read(DENY).as_deref()) {
            eprintln!(
                "crontab: you ({}) are not allowed to use this program",
                me.name
            );
        } else {
            eprintln!("crontab: only root can use crontab until it can be installed set-user-ID");
        }
        return ExitCode::from(1);
    }
    let user = match args.user {
        Some(u) if pwd::lookup(&u).is_none() => {
            eprintln!("crontab: unknown user {u}");
            return ExitCode::from(1);
        }
        Some(u) => u,
        None => me.name,
    };
    match args.action {
        Action::Install(file) => do_install(&user, &file),
        Action::List => do_list(&user),
        Action::Edit => do_edit(&user),
        Action::Remove { force } => do_remove(&user, force),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Result<Args, ()> {
        parse_args(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn arguments() {
        assert_eq!(
            args("-l"),
            Ok(Args {
                user: None,
                action: Action::List
            })
        );
        assert_eq!(
            args("-u bob -e"),
            Ok(Args {
                user: Some("bob".into()),
                action: Action::Edit
            })
        );
        assert_eq!(
            args("-r -f"),
            Ok(Args {
                user: None,
                action: Action::Remove { force: true }
            })
        );
        assert_eq!(
            args("-f -u bob -r").unwrap().action,
            Action::Remove { force: true }
        );
        assert_eq!(
            args("mytab").unwrap().action,
            Action::Install("mytab".into())
        );
        assert_eq!(
            args("-u bob -").unwrap().action,
            Action::Install("-".into())
        );
        for bad in [
            "", "-l -e", "-l file", "a b", "-f", "-l -f", "-u", "-x", "-f file",
        ] {
            assert_eq!(args(bad), Err(()), "{bad:?}");
        }
    }

    #[test]
    fn allow_and_deny() {
        assert!(permitted("bob", None, None));
        assert!(permitted("bob", Some("alice\nbob\n"), Some("bob\n")));
        assert!(!permitted("bob", Some("alice\n"), None));
        assert!(!permitted("bob", None, Some("bob\n")));
        assert!(permitted("bob", None, Some("alice\n")));
        assert!(permitted("root", Some(""), Some("root\n")));
    }
}
