//! Differential testing (INIT_SH.md §8.1): every script in `tests/diff/` runs through this crate's
//! shell and through `dash`; standard output and exit status must match exactly, and standard
//! error must be empty in both or non-empty in both (the message wording is the shell's own).
//!
//! Known, intended differences are listed in `KNOWN_DIFFERENCES` below.

use std::path::Path;
use std::process::{Command, Output};

/// Scripts whose output is expected to differ from dash's, with the reason.
const KNOWN_DIFFERENCES: &[(&str, &str)] = &[];

fn run(shell: &str, script: &Path) -> Output {
    Command::new(shell)
        .arg(script)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()
        .unwrap_or_else(|e| panic!("running {shell}: {e}"))
}

#[test]
fn matches_dash() {
    if Command::new("dash").arg("-c").arg(":").output().is_err() {
        eprintln!("dash not installed; skipping differential tests");
        return;
    }
    let ours = env!("CARGO_BIN_EXE_libsh");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/diff");
    let mut scripts: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "sh")).collect();
    scripts.sort();
    let mut failures = Vec::new();
    for script in &scripts {
        let name = script.file_name().unwrap().to_string_lossy().into_owned();
        if KNOWN_DIFFERENCES.iter().any(|(n, _)| *n == name) {
            continue;
        }
        let a = run(ours, script);
        let b = run("dash", script);
        let mut problems = Vec::new();
        if a.stdout != b.stdout {
            problems.push(format!(
                "stdout differs\n--- libsh\n{}--- dash\n{}",
                String::from_utf8_lossy(&a.stdout),
                String::from_utf8_lossy(&b.stdout)
            ));
        }
        if a.status.code() != b.status.code() {
            problems.push(format!("status: libsh {:?}, dash {:?}", a.status.code(), b.status.code()));
        }
        if a.stderr.is_empty() != b.stderr.is_empty() {
            problems.push(format!(
                "stderr presence differs\n--- libsh\n{}--- dash\n{}",
                String::from_utf8_lossy(&a.stderr),
                String::from_utf8_lossy(&b.stderr)
            ));
        }
        if !problems.is_empty() {
            failures.push(format!("== {name}\n{}", problems.join("\n")));
        }
    }
    assert!(failures.is_empty(), "{} of {} scripts differ from dash:\n{}", failures.len(), scripts.len(), failures.join("\n\n"));
}
