//! `kill(1)`: sends a signal to processes.
//!
//! ```text
//! kill [-s signal_name] pid ...
//! kill -signal_name pid ...
//! kill -signal_number pid ...
//! kill -l [exit_status]
//! ```
//!
//! The default signal is `TERM`. Names are accepted with or without `SIG`, in any case. A
//! negative pid names a process group (after `--`, or after the signal). `-l` lists the names,
//! or names the signal that ended a process whose exit status (`$?`, 128 and over) is given.

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

/// A signal by name (`TERM`, `sigterm`) or number (`15`, `0`).
fn signal(s: &str) -> Option<libc::c_int> {
    if let Ok(n) = s.parse::<libc::c_int>() {
        return (n == 0 || SIGNALS.iter().any(|&(_, v)| v == n)).then_some(n);
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    SIGNALS.iter().find(|&&(n, _)| n == name).map(|&(_, v)| v)
}

fn name_of(sig: libc::c_int) -> Option<&'static str> {
    SIGNALS.iter().find(|&&(_, v)| v == sig).map(|&(n, _)| n)
}

#[derive(Debug, PartialEq, Eq)]
enum Request {
    List(Option<String>),
    Send(libc::c_int, Vec<String>),
}

fn parse(args: &[String]) -> Result<Request, String> {
    let mut sig = libc::SIGTERM;
    let mut rest = args;
    match args.first().map(String::as_str) {
        Some("-l") => {
            return match args.len() {
                1 => Ok(Request::List(None)),
                2 => Ok(Request::List(Some(args[1].clone()))),
                _ => Err(String::new()),
            };
        }
        Some("-s") => {
            let name = args.get(1).ok_or_else(String::new)?;
            sig = signal(name).ok_or_else(|| format!("{name}: invalid signal"))?;
            rest = &args[2..];
        }
        Some("--") => rest = &args[1..],
        Some(a) if a.len() > 1 && a.starts_with('-') => {
            sig = signal(&a[1..]).ok_or_else(|| format!("{}: invalid signal", &a[1..]))?;
            rest = &args[1..];
        }
        _ => {}
    }
    if rest.first().map(String::as_str) == Some("--") {
        rest = &rest[1..];
    }
    if rest.is_empty() {
        return Err(String::new());
    }
    Ok(Request::Send(sig, rest.to_vec()))
}

fn usage() -> ExitCode {
    eprintln!("usage: kill [-s signal_name] pid ...");
    eprintln!("       kill -l [exit_status]");
    eprintln!("       kill -signal_name pid ...");
    eprintln!("       kill -signal_number pid ...");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Err(msg) if msg.is_empty() => usage(),
        Err(msg) => {
            eprintln!("kill: {msg}");
            ExitCode::from(2)
        }
        Ok(Request::List(None)) => {
            let names: Vec<&str> = SIGNALS.iter().map(|&(n, _)| n).collect();
            println!("{}", names.join(" "));
            ExitCode::SUCCESS
        }
        Ok(Request::List(Some(status))) => {
            let n: libc::c_int = match status.parse() {
                Ok(n) if n > 128 => n - 128,
                Ok(n) => n,
                Err(_) => {
                    eprintln!("kill: {status}: invalid status");
                    return ExitCode::from(2);
                }
            };
            match name_of(n) {
                Some(name) => {
                    println!("{name}");
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("kill: {status}: invalid status");
                    ExitCode::from(2)
                }
            }
        }
        Ok(Request::Send(sig, pids)) => {
            let mut failed = false;
            for p in &pids {
                let Ok(pid) = p.parse::<libc::pid_t>() else {
                    eprintln!("kill: {p}: illegal process id");
                    failed = true;
                    continue;
                };
                // SAFETY: kill(2) takes no pointers.
                if unsafe { libc::kill(pid, sig) } != 0 {
                    eprintln!("kill: {p}: {}", std::io::Error::last_os_error());
                    failed = true;
                }
            }
            if failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Request, String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn signals() {
        assert_eq!(signal("TERM"), Some(libc::SIGTERM));
        assert_eq!(signal("sigkill"), Some(libc::SIGKILL));
        assert_eq!(signal("9"), Some(9));
        assert_eq!(signal("0"), Some(0));
        assert_eq!(signal("NOPE"), None);
        assert_eq!(signal("999"), None);
    }

    #[test]
    fn requests() {
        let send = |sig, pids: &[&str]| {
            Ok(Request::Send(
                sig,
                pids.iter().map(|s| s.to_string()).collect(),
            ))
        };
        assert_eq!(p("123"), send(libc::SIGTERM, &["123"]));
        assert_eq!(p("-9 1 2"), send(9, &["1", "2"]));
        assert_eq!(p("-HUP 5"), send(libc::SIGHUP, &["5"]));
        assert_eq!(p("-s int 5"), send(libc::SIGINT, &["5"]));
        assert_eq!(p("-- -42"), send(libc::SIGTERM, &["-42"]));
        assert_eq!(p("-KILL -- -42"), send(libc::SIGKILL, &["-42"]));
        assert_eq!(p("-l"), Ok(Request::List(None)));
        assert_eq!(p("-l 143"), Ok(Request::List(Some("143".into()))));
        assert!(p("").is_err() && p("-9").is_err() && p("-s").is_err() && p("-l 1 2").is_err());
        assert_eq!(p("-BOGUS 1"), Err("BOGUS: invalid signal".into()));
    }
}
