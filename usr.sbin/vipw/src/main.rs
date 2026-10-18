//! `vipw(8)`: edits the account database by hand.
//!
//! ```text
//! vipw [-d directory]
//! ```
//!
//! Takes the database lock (`flock(2)` on `master.passwd`, the one pw(8) takes), copies
//! `master.passwd` to `ptmp` in the same directory, and runs `$EDITOR` (default `/bin/vi`, where
//! OxideBSD keeps it) on the copy. If it changed, the copy is checked and installed as
//! `pwd_mkdb -p -d directory ptmp` would; if it doesn't check out, the user may edit it again.

use std::fs::File;
use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::process::ExitCode;

const EDITOR: &str = "/bin/vi";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = match args.as_slice() {
        [] => "/etc".to_string(),
        [d, dir] if d == "-d" => dir.trim_end_matches('/').to_string(),
        [d] if d.len() > 2 && d.starts_with("-d") => d[2..].trim_end_matches('/').to_string(),
        _ => {
            eprintln!("usage: vipw [-d directory]");
            return ExitCode::from(64);
        }
    };
    match run(if dir.is_empty() { "/" } else { &dir }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vipw: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(dir: &str) -> Result<(), String> {
    let master = format!("{dir}/master.passwd");
    let ptmp = format!("{dir}/ptmp");
    let _lock = lock(&master)?;
    let original = std::fs::read_to_string(&master).map_err(|e| format!("{master}: {e}"))?;
    // Holding the lock, a ptmp left behind is a dead vipw's: replace it, never write through it
    // (it could be a link planted to have root overwrite something).
    let _ = std::fs::remove_file(&ptmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&ptmp)
        .and_then(|mut f| f.write_all(original.as_bytes()).and_then(|()| f.sync_all()))
        .map_err(|e| format!("{ptmp}: {e}"))?;
    let r = edit_loop(dir, &ptmp, &original);
    let _ = std::fs::remove_file(&ptmp);
    r
}

fn edit_loop(dir: &str, ptmp: &str, original: &str) -> Result<(), String> {
    loop {
        edit(ptmp)?;
        let text = std::fs::read_to_string(ptmp).map_err(|e| format!("{ptmp}: {e}"))?;
        if text == original {
            eprintln!("vipw: no changes made");
            return Ok(());
        }
        let (entries, errors) = pwd::parse(&text);
        let problem = match errors.first() {
            Some((line, e)) => Some(format!("{ptmp}: line {line}: {e}")),
            None => pwd::validate(&entries).err().map(|e| format!("{ptmp}: {e}")),
        };
        match problem {
            None => {
                return grp::install_users_in(dir, &entries).map_err(|e| format!("{dir}/master.passwd: {e}"));
            }
            Some(p) => {
                eprintln!("vipw: {p}");
                if !reedit() {
                    return Err(format!("{dir}/master.passwd: unchanged"));
                }
            }
        }
    }
}

/// Asks whether to edit again; yes unless the answer starts with `n` (or there is no answer).
fn reedit() -> bool {
    eprint!("re-edit the password file? [y]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => false,
        Ok(_) => !line.trim_start().starts_with(['n', 'N']),
    }
}

/// Runs the editor on `file`. vipw ignores the terminal's interrupt and quit while it waits, as
/// the BSDs' does; the editor gets them back.
fn edit(file: &str) -> Result<(), String> {
    let editor = std::env::var("EDITOR").ok().filter(|e| !e.trim().is_empty()).unwrap_or_else(|| EDITOR.into());
    let mut words = editor.split_whitespace();
    let prog = words.next().unwrap_or(EDITOR).to_string();
    let mut cmd = std::process::Command::new(&prog);
    cmd.args(words).arg(file);
    // SAFETY: signal(2) only, between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }
    let saved = unsafe { (libc::signal(libc::SIGINT, libc::SIG_IGN), libc::signal(libc::SIGQUIT, libc::SIG_IGN)) };
    let status = cmd.status();
    unsafe {
        libc::signal(libc::SIGINT, saved.0);
        libc::signal(libc::SIGQUIT, saved.1);
    }
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("{prog}: {s}")),
        Err(e) => Err(format!("{prog}: {e}")),
    }
}

/// The database lock, as pw(8) takes it: `flock(2)` on `master.passwd`, retried if the file was
/// replaced (an install renames over it) between opening and locking.
fn lock(path: &str) -> Result<File, String> {
    loop {
        let f = File::open(path).map_err(|e| format!("{path}: {e}"))?;
        // SAFETY: flock(2) on a descriptor we own.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err("the password file is busy".into());
            }
            return Err(format!("{path}: lock: {e}"));
        }
        if let (Ok(h), Ok(n)) = (f.metadata(), std::fs::metadata(path))
            && (h.dev(), h.ino()) == (n.dev(), n.ino())
        {
            return Ok(f);
        }
    }
}
