//! `pwd_mkdb(8)`: installs a new account database (LOGIN.md §7.4 in OxideBSD-doc).
//!
//! ```text
//! pwd_mkdb [-Cp] [-d directory] [-u user] file
//! ```
//!
//! Checks `file` (normally `/etc/ptmp`, written by `vipw`), installs it as `master.passwd` (mode
//! 0600) and, with `-p`, generates the public `passwd` from it. Unlike the BSDs' there are no
//! `.db` files: the C library reads the text files. `-C` only checks; `-d` installs into another
//! directory; `-u` (update one user) is accepted and rebuilds everything.

use std::process::ExitCode;

const USAGE: &str = "usage: pwd_mkdb [-Cp] [-d directory] [-u user] file";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (mut check, mut passwd, mut dir) = (false, false, "/etc".to_string());
    let mut file = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-C" => check = true,
            "-p" => passwd = true,
            "-d" => match args.next() {
                Some(d) => dir = d,
                None => return usage(),
            },
            "-u" => {
                if args.next().is_none() {
                    return usage();
                }
            }
            s if s.starts_with('-') => return usage(),
            s => {
                if file.replace(s.to_string()).is_some() {
                    return usage();
                }
            }
        }
    }
    let Some(file) = file else { return usage() };
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => return fail(&format!("{file}: {e}")),
    };
    let (entries, errors) = pwd::parse(&text);
    if let Some((line, e)) = errors.first() {
        return fail(&format!("{file}: line {line}: {e}"));
    }
    if let Err(e) = pwd::validate(&entries) {
        return fail(&format!("{file}: {e}"));
    }
    if check {
        return ExitCode::SUCCESS;
    }
    let master = format!("{dir}/master.passwd");
    if let Err(e) = pwd::write_atomic(&master, &pwd::master_text(&entries), 0o600) {
        return fail(&format!("{master}: {e}"));
    }
    if passwd {
        let public = format!("{dir}/passwd");
        if let Err(e) = pwd::write_atomic(&public, &pwd::passwd_text(&entries), 0o644) {
            return fail(&format!("{public}: {e}"));
        }
    }
    // Like the BSDs', the input file is consumed.
    if std::fs::canonicalize(&file).ok() != std::fs::canonicalize(&master).ok() {
        let _ = std::fs::remove_file(&file);
    }
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::FAILURE
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("pwd_mkdb: {msg}");
    ExitCode::FAILURE
}
