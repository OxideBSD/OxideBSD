//! `rmdir(1)`: removes empty directories. `-p` also removes each directory's parents named in
//! its path, from the inside out, stopping at the first that can't be removed; `-v` names each
//! one removed.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut parents = false;
    let mut verbose = false;
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.peek() {
        if a == "--" {
            args.next();
            break;
        }
        let Some(flags) = a.strip_prefix('-').filter(|f| !f.is_empty()) else {
            break;
        };
        for c in flags.chars() {
            match c {
                'p' => parents = true,
                'v' => verbose = true,
                _ => {
                    eprintln!("usage: rmdir [-pv] directory ...");
                    return ExitCode::from(1);
                }
            }
        }
        args.next();
    }
    let dirs: Vec<String> = args.collect();
    if dirs.is_empty() {
        eprintln!("usage: rmdir [-pv] directory ...");
        return ExitCode::from(1);
    }
    let mut failed = false;
    for dir in &dirs {
        let mut path = Path::new(dir.trim_end_matches('/'));
        if path.as_os_str().is_empty() {
            path = Path::new("/");
        }
        loop {
            if let Err(e) = std::fs::remove_dir(path) {
                eprintln!("rmdir: {}: {e}", path.display());
                failed = true;
                break;
            }
            if verbose {
                println!("{}", path.display());
            }
            if !parents {
                break;
            }
            match path.parent() {
                Some(p) if !p.as_os_str().is_empty() && p != Path::new("/") => path = p,
                _ => break,
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
