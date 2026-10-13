//! `fsck(8)`: checks file systems, by running each type's own checker (`fsck_oxfs(8)`), as on the
//! BSDs.
//!
//! ```text
//! fsck [-fnpy] [-t type] [special | node] ...
//! ```
//!
//! With no file systems named, checks every `/etc/fstab` entry with a nonzero pass number, in pass
//! order. A named one is found in fstab by device or mount point; one not there is checked as
//! `-t`'s type (oxfs by default). The flags are passed on. The exit status is the worst any
//! checker returned (`8`: a file system needs a manual check).

use std::process::{Command, ExitCode};

fn usage() -> ExitCode {
    eprintln!("usage: fsck [-fnpy] [-t type] [special | node] ...");
    ExitCode::from(16)
}

/// Runs `/sbin/fsck_<vfstype> <flags> <spec>`; its exit status, or 8 if it couldn't be run.
fn run(vfstype: &str, spec: &str, flags: &str) -> u8 {
    let checker = format!("/sbin/fsck_{vfstype}");
    let mut cmd = Command::new(&checker);
    if !flags.is_empty() {
        cmd.arg(format!("-{flags}"));
    }
    match cmd.arg(spec).status() {
        Ok(s) => s.code().unwrap_or(8).clamp(0, 255) as u8,
        Err(e) => {
            eprintln!("fsck: {checker}: {e}");
            8
        }
    }
}

fn main() -> ExitCode {
    let mut flags = String::new();
    let mut vfstype: Option<String> = None;
    let mut named: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.strip_prefix('-') {
            Some("t") => match args.next() {
                Some(t) => vfstype = Some(t),
                None => return usage(),
            },
            Some(f) if !f.is_empty() && f.chars().all(|c| "fnpy".contains(c)) => flags.push_str(f),
            Some(_) => return usage(),
            None => named.push(a),
        }
    }
    let entries = fstab::read().map(|r| r.0).unwrap_or_default();
    let mut worst = 0u8;
    if named.is_empty() {
        let mut todo: Vec<&fstab::Entry> = entries
            .iter()
            .filter(|e| e.passno > 0 && vfstype.as_deref().is_none_or(|t| t == e.vfstype))
            .collect();
        todo.sort_by_key(|e| e.passno);
        for e in todo {
            worst = worst.max(run(&e.vfstype, &e.spec, &flags));
        }
    } else {
        for n in &named {
            let (t, spec) = match entries.iter().find(|e| &e.spec == n || &e.file == n) {
                Some(e) => (e.vfstype.clone(), e.spec.clone()),
                None => (vfstype.clone().unwrap_or_else(|| "oxfs".into()), n.clone()),
            };
            worst = worst.max(run(&t, &spec, &flags));
        }
    }
    ExitCode::from(worst)
}
