//! certctl(8): manage the system's trusted TLS certificates. The operations are libcertstore's
//! `ctl` module, which build.rs also runs to build the seeded `/etc/ssl`; this is the command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use libcertstore::ctl::{self, Config, TrustError};

const EX_USAGE: u8 = 64;

fn usage() -> ExitCode {
    eprintln!(
        "usage: certctl [-v] list\n\
         \x20      certctl [-v] untrusted\n\
         \x20      certctl [-nv] [-D destdir] [-d distbase] rehash\n\
         \x20      certctl [-nv] untrust file ...\n\
         \x20      certctl [-nv] trust file | name ..."
    );
    ExitCode::from(EX_USAGE)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn split_path(v: &str) -> Vec<PathBuf> {
    v.split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut dry_run, mut verbose) = (false, false);
    let mut destdir = env("DESTDIR").unwrap_or_default();
    let mut distbase = env("DISTBASE").unwrap_or_default();
    let mut i = 0;
    // getopt("D:d:nv"): flags may be grouped, an option's argument attached or separate.
    while i < args.len() && args[i].starts_with('-') && args[i] != "-" {
        if args[i] == "--" {
            i += 1;
            break;
        }
        let flags = &args[i][1..];
        for (j, c) in flags.char_indices() {
            match c {
                'n' => dry_run = true,
                'v' => verbose = true,
                'D' | 'd' => {
                    let value = if j + 1 < flags.len() {
                        flags[j + 1..].to_string()
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => return usage(),
                        }
                    };
                    if c == 'D' {
                        destdir = value;
                    } else {
                        distbase = value;
                    }
                    break;
                }
                _ => return usage(),
            }
        }
        i += 1;
    }
    let Some(command) = args.get(i) else { return usage() };
    let operands = &args[i + 1..];

    let localbase = env("LOCALBASE").unwrap_or_else(|| "/usr/local".to_string());
    let mut cfg = Config::standard(&destdir, &distbase, &localbase);
    if let Some(v) = env("TRUSTPATH") {
        cfg.trust_path = split_path(&v);
    }
    if let Some(v) = env("UNTRUSTPATH") {
        cfg.untrust_path = split_path(&v);
    }
    if let Some(v) = env("CERTDESTDIR") {
        cfg.certs_dir = v.into();
    }
    if let Some(v) = env("UNTRUSTDESTDIR") {
        cfg.untrusted_dir = v.into();
    }
    if let Some(v) = env("BUNDLE") {
        cfg.bundle = v.into();
    }
    cfg.dry_run = dry_run;
    cfg.verbose = verbose;

    match (command.as_str(), operands.is_empty()) {
        ("list", true) => show(&cfg.certs_dir),
        ("untrusted", true) => show(&cfg.untrusted_dir),
        ("rehash", true) => rehash(&cfg),
        ("untrust", false) => {
            let mut failed = false;
            for file in operands {
                if let Err(e) = ctl::untrust(&cfg, Path::new(file)) {
                    eprintln!("certctl: {file}: {e}");
                    failed = true;
                }
            }
            finish(&cfg, failed)
        }
        ("trust", false) => {
            let mut failed = false;
            for what in operands {
                match ctl::trust(&cfg, what) {
                    Ok(_) => {}
                    Err(TrustError::NotFound) => {
                        eprintln!("certctl: {what}: not an untrusted certificate");
                        failed = true;
                    }
                    Err(TrustError::SystemList(file)) => {
                        eprintln!(
                            "certctl: {what}: untrusted by the system list, in {}",
                            file.display()
                        );
                        failed = true;
                    }
                    Err(TrustError::Io(e)) => {
                        eprintln!("certctl: {what}: {e}");
                        failed = true;
                    }
                }
            }
            finish(&cfg, failed)
        }
        _ => usage(),
    }
}

fn show(dir: &Path) -> ExitCode {
    for (name, subject) in ctl::list(dir) {
        println!("{name}\t{subject}");
    }
    ExitCode::SUCCESS
}

fn rehash(cfg: &Config) -> ExitCode {
    match ctl::rehash(cfg) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("certctl: rehash: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `trust` and `untrust` rehash afterwards, so the change takes effect at once.
fn finish(cfg: &Config, failed: bool) -> ExitCode {
    let rehashed = rehash(cfg);
    if failed { ExitCode::FAILURE } else { rehashed }
}
