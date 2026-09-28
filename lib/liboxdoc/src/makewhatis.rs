//! makewhatis(8) (MAN.md §7.1): builds `oxdoc.db` for manual trees.

use crate::db::{self, Db};
use crate::diag::Diagnostics;
use crate::keys::{self, Page};
use std::path::Path;

/// The index's name in each tree.
pub const DB_NAME: &str = "oxdoc.db";

fn usage() -> i32 {
    eprintln!("usage: makewhatis [-an] [-C file]");
    eprintln!("       makewhatis [-an] dir ...");
    eprintln!("       makewhatis [-n] -d dir [file ...]");
    eprintln!("       makewhatis [-n] -u dir [file ...]");
    eprintln!("       makewhatis -t file ...");
    1
}

/// Runs makewhatis with `args` (without the program name); returns the exit status.
pub fn main(args: &[String]) -> i32 {
    let mut conf = None;
    let mut dry = false;
    let mut mode = ' ';
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i].len() > 1 {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        let flags: Vec<char> = a[1..].chars().collect();
        for (k, &f) in flags.iter().enumerate() {
            match f {
                'C' => {
                    // The value follows, attached or as the next argument.
                    let rest: String = flags[k + 1..].iter().collect();
                    conf = Some(if rest.is_empty() {
                        i += 1;
                        match args.get(i) {
                            Some(v) => v.clone(),
                            None => return usage(),
                        }
                    } else {
                        rest
                    });
                    break;
                }
                'd' | 'u' | 't' => mode = f,
                'n' => dry = true,
                // Accepted for compatibility: all architectures, debug output, quick mode,
                // warnings, the output encoding.
                'a' | 'D' | 'p' | 'Q' => {}
                'T' => {
                    if flags.len() == k + 1 {
                        i += 1;
                    }
                    break;
                }
                _ => return usage(),
            }
        }
        i += 1;
    }
    let rest = &args[i..];
    match mode {
        't' => check(rest),
        'd' | 'u' => {
            let Some(dir) = rest.first() else { return usage() };
            update(dir, &rest[1..], mode == 'u', dry)
        }
        _ => {
            let dirs: Vec<String> = if rest.is_empty() {
                crate::manpath::resolve(conf.as_deref(), None, &[])
            } else {
                rest.to_vec()
            };
            let mut status = 0;
            for d in dirs {
                if !Path::new(&d).is_dir() {
                    // (A configured tree that doesn't exist is skipped quietly.)
                    if !rest.is_empty() {
                        eprintln!("makewhatis: {d}: not a directory");
                        status = 1;
                    }
                    continue;
                }
                let pages = index_tree(Path::new(&d));
                if !dry && let Err(e) = write_db(Path::new(&d), &pages) {
                    eprintln!("makewhatis: {d}/{DB_NAME}: {e}");
                    status = 1;
                }
            }
            status
        }
    }
}

/// The section a `man*` directory holds: `man3p` holds `3p`.
fn dir_section(name: &str) -> Option<&str> {
    name.strip_prefix("man").filter(|s| !s.is_empty())
}

/// A page's file, if it is one: `name.section...`, not compressed or an editor's backup.
fn is_page(name: &str) -> bool {
    !name.starts_with('.') && name.contains('.') && !name.ends_with('~') && ![".gz", ".bz2", ".xz", ".Z", ".orig", ".rej", ".db"].iter().any(|s| name.ends_with(s))
}

/// Every page of the tree at `root`, in file order. A file holding nothing but `.so other`
/// is a link: its name becomes one more name of the page it points to.
pub fn index_tree(root: &Path) -> Vec<Page> {
    let mut files: Vec<(String, String, String)> = Vec::new();
    let Ok(dirs) = std::fs::read_dir(root) else { return Vec::new() };
    let mut dirs: Vec<_> = dirs.flatten().filter(|e| e.path().is_dir()).collect();
    dirs.sort_by_key(|e| e.file_name());
    for d in dirs {
        let dname = d.file_name().to_string_lossy().into_owned();
        let Some(sec) = dir_section(&dname) else { continue };
        let Ok(entries) = std::fs::read_dir(d.path()) else { continue };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.path().is_dir() {
                // An architecture's own pages: `man4/amd64/`.
                let Ok(sub) = std::fs::read_dir(e.path()) else { continue };
                let mut sub: Vec<_> = sub.flatten().filter(|s| s.path().is_file()).collect();
                sub.sort_by_key(|s| s.file_name());
                for s in sub {
                    let f = s.file_name().to_string_lossy().into_owned();
                    if is_page(&f) {
                        files.push((format!("{dname}/{name}/{f}"), sec.to_string(), name.clone()));
                    }
                }
            } else if is_page(&name) {
                files.push((format!("{dname}/{name}"), sec.to_string(), String::new()));
            }
        }
    }
    let mut pages = Vec::new();
    let mut links = Vec::new();
    for (rel, sec, arch) in files {
        let Ok(bytes) = std::fs::read(root.join(&rel)) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        if let Some(target) = so_target(&text) {
            links.push((rel, target));
            continue;
        }
        let mut p = index_page(&text, &rel, &sec);
        if !arch.is_empty() && p.arch.is_empty() {
            p.arch = arch;
        }
        pages.push(p);
    }
    for (rel, target) in links {
        let stem = stem(&rel);
        if let Some(p) = pages.iter_mut().find(|p| p.file == target) {
            if !p.names.iter().any(|n| n == stem) {
                p.names.push(stem.to_string());
                p.keys.push((0, stem.to_string()));
                p.keys.sort();
            }
            if !p.links.iter().any(|n| n == stem) {
                p.links.push(stem.to_string());
            }
        }
    }
    pages
}

/// A file's name without its directory and its last suffix.
fn stem(rel: &str) -> &str {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base.rsplit_once('.').map_or(base, |(s, _)| s)
}

/// The page a link file points to: its only line (comments aside) is `.so path`.
fn so_target(text: &str) -> Option<String> {
    let mut target = None;
    for l in text.lines() {
        let t = l.trim_end();
        if t.is_empty() || t.starts_with(".\\\"") || t.starts_with("'\\\"") || t == "." {
            continue;
        }
        if target.is_some() {
            return None;
        }
        target = Some(t.strip_prefix(".so")?.trim().to_string());
    }
    target.filter(|t| !t.is_empty())
}

/// One page's index entry, from its text.
pub fn index_page(text: &str, rel: &str, section: &str) -> Page {
    let mut diag = Diagnostics::new(rel);
    let doc = crate::parse(text, &mut diag);
    keys::page(&doc, rel, section)
}

/// Writes the index of `pages` into the tree at `root`, replacing the old one only once the
/// new one is complete.
pub fn write_db(root: &Path, pages: &[Page]) -> std::io::Result<()> {
    let tmp = root.join(format!("{DB_NAME}.tmp"));
    std::fs::write(&tmp, db::write(pages))?;
    std::fs::rename(&tmp, root.join(DB_NAME))
}

/// The pages of an index, with their keys, as makewhatis built them.
pub fn read_pages(db: &Db) -> Vec<Page> {
    let mut pages: Vec<Page> = (0..db.page_count())
        .map(|i| {
            let p = db.page(i);
            Page {
                file: p.file.to_string(),
                section: p.section.to_string(),
                arch: p.arch.to_string(),
                names: p.names.iter().map(|s| s.to_string()).collect(),
                links: p.links.iter().map(|s| s.to_string()).collect(),
                desc: p.desc.to_string(),
                keys: Vec::new(),
            }
        })
        .collect();
    for k in 0..db.key_count() {
        let key = db.key(k);
        for p in key.pages {
            if let Some(page) = pages.get_mut(p as usize) {
                page.keys.push((key.class, key.value.to_string()));
            }
        }
    }
    pages
}

/// `-d` and `-u`: the tree's index with `files` indexed again, or removed.
fn update(dir: &str, files: &[String], remove: bool, dry: bool) -> i32 {
    let root = Path::new(dir);
    let mut pages = match std::fs::read(root.join(DB_NAME)).map_err(|e| e.to_string()).and_then(|b| Db::read(b).map_err(|e| e.to_string())) {
        Ok(db) => read_pages(&db),
        Err(e) => {
            eprintln!("makewhatis: {dir}/{DB_NAME}: {e}");
            return 1;
        }
    };
    let mut status = 0;
    for f in files {
        // A file named from the current directory or within the tree.
        let rel = Path::new(f).strip_prefix(root).map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| f.trim_start_matches("./").to_string());
        pages.retain(|p| p.file != rel);
        if remove {
            continue;
        }
        let Some(sec) = rel.split('/').next().and_then(dir_section) else {
            eprintln!("makewhatis: {f}: not in a man* directory of {dir}");
            status = 1;
            continue;
        };
        match std::fs::read(root.join(&rel)) {
            Ok(b) => pages.push(index_page(&String::from_utf8_lossy(&b), &rel, sec)),
            Err(e) => {
                eprintln!("makewhatis: {f}: {e}");
                status = 1;
            }
        }
    }
    pages.sort_by(|a, b| a.file.cmp(&b.file));
    if !dry && let Err(e) = write_db(root, &pages) {
        eprintln!("makewhatis: {dir}/{DB_NAME}: {e}");
        status = 1;
    }
    status
}

/// `-t`: reports what would keep each file from being indexed well.
fn check(files: &[String]) -> i32 {
    let mut status = 0;
    for f in files {
        let text = match std::fs::read(f) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                eprintln!("makewhatis: {f}: {e}");
                status = 1;
                continue;
            }
        };
        let sec = f.rsplit('.').next().unwrap_or("");
        let p = index_page(&text, f, sec);
        if p.desc.is_empty() {
            eprintln!("makewhatis: {f}: no one-line description");
            status = 1;
        }
    }
    status
}
