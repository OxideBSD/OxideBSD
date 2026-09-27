//! Differential testing against mandoc (MAN.md §9.2): every page in `tests/corpus/` and every
//! OxideBSD manual page in `share/man/` is formatted with `-T ascii` by this crate and by
//! `mandoc -T ascii -O overstrike`; the output must match byte for byte. Skipped when mandoc
//! isn't installed.
//!
//! Known, intended differences are listed in `KNOWN_DIFFERENCES`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Pages whose output is expected to differ from mandoc's, with the reason.
const KNOWN_DIFFERENCES: &[(&str, &str)] = &[(
    "man-basic.1",
    "uses .MR (groff 1.23), which mandoc 1.14.6 ignores and oxdoc implements (MAN.md §4.3)",
)];

fn pages() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    let mut dirs = vec![root.join("tests/corpus")];
    if let Ok(entries) = std::fs::read_dir(root.join("../../share/man")) {
        dirs.extend(entries.flatten().map(|e| e.path()));
    }
    for d in dirs {
        if let Ok(entries) = std::fs::read_dir(&d) {
            out.extend(entries.flatten().map(|e| e.path()).filter(|p| p.is_file()));
        }
    }
    out.sort();
    out
}

#[test]
fn matches_mandoc() {
    if Command::new("mandoc").arg("-V").output().is_err() {
        eprintln!("mandoc not installed; skipping differential tests");
        return;
    }
    let ours = env!("CARGO_BIN_EXE_oxdoc-host");
    let mut failures = Vec::new();
    let pages = pages();
    for page in &pages {
        let name = page.file_name().unwrap().to_string_lossy().into_owned();
        if KNOWN_DIFFERENCES.iter().any(|(n, _)| *n == name) {
            continue;
        }
        let a = Command::new(ours).args(["-T", "ascii"]).arg(page).output().unwrap();
        let b = Command::new("mandoc").args(["-T", "ascii"]).arg(page).output().unwrap();
        if a.stdout != b.stdout {
            let (a, b) = (String::from_utf8_lossy(&a.stdout), String::from_utf8_lossy(&b.stdout));
            let first = a.lines().zip(b.lines()).position(|(x, y)| x != y).unwrap_or(0);
            failures.push(format!(
                "== {}\nfirst difference at line {}:\n  oxdoc:  {:?}\n  mandoc: {:?}",
                page.display(),
                first + 1,
                a.lines().nth(first).unwrap_or(""),
                b.lines().nth(first).unwrap_or("")
            ));
        }
    }
    assert!(pages.len() > 10, "corpus not found");
    assert!(failures.is_empty(), "{} of {} pages differ from mandoc:\n{}", failures.len(), pages.len(), failures.join("\n"));
}
