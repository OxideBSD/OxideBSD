//! The tables cron runs (CRON.md §§2-3, 4.1): the system table `/etc/crontab`, the system
//! tables in the `cron.d` directories, and the users' tables in `/var/cron/tabs`, each read
//! whole and read again when it, or the directory holding it, changes.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::SystemTime;

use libcron::{Job, When};

pub const SYSTEM_TABLE: &str = "/etc/crontab";
pub const SYSTEM_DIRS: [&str; 2] = ["/etc/cron.d", "/usr/local/etc/cron.d"];
pub const USER_TABS: &str = "/var/cron/tabs";

/// A job, with the user it runs as and its table's environment settings.
pub struct Entry {
    pub user: String,
    pub job: Job,
    pub env: Rc<Vec<(String, String)>>,
}

/// Whether a file in a `cron.d` directory is a table: not hidden, not an editor's or package
/// manager's leftover (as the BSDs' `not_a_crontab`).
pub fn is_table_name(name: &str) -> bool {
    const LEFTOVERS: [&str; 6] = ["~", ",", ".bak", ".orig", ".new", ".swp"];
    !name.is_empty()
        && !name.starts_with('.')
        && !name.starts_with('#')
        && !LEFTOVERS.iter().any(|s| name.ends_with(s))
}

/// Whether a table file may be trusted: a regular file owned by root and not writable by its
/// group or anyone else. A table anyone could write would run their commands as its user.
fn trusted(path: &Path) -> Result<(), String> {
    let md = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !md.is_file() {
        return Err("not a regular file".into());
    }
    if md.uid() != 0 {
        return Err("not owned by root".into());
    }
    if md.mode() & 0o022 != 0 {
        return Err("writable by group or others".into());
    }
    Ok(())
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The files and directories whose modification times decide a reload, as found at a load.
fn stamps(files: &[PathBuf]) -> Vec<(PathBuf, Option<SystemTime>)> {
    let mut watched: Vec<PathBuf> = vec![SYSTEM_TABLE.into(), USER_TABS.into()];
    watched.extend(SYSTEM_DIRS.iter().map(PathBuf::from));
    watched.extend(files.iter().cloned());
    watched
        .into_iter()
        .map(|p| {
            let t = mtime(&p);
            (p, t)
        })
        .collect()
}

fn sorted_dir(dir: &str) -> Vec<(String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<(String, PathBuf)> = rd
        .flatten()
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    names.sort();
    names
}

pub struct Db {
    pub entries: Vec<Entry>,
    stamps: Vec<(PathBuf, Option<SystemTime>)>,
}

impl Db {
    /// Reads every table; problems are passed to `log`, and a table with one is skipped whole
    /// (untrusted) or line by line (a bad line).
    pub fn load(log: &mut dyn FnMut(&str)) -> Db {
        let mut entries = Vec::new();
        let mut files = Vec::new();
        let mut tables: Vec<(PathBuf, Option<String>)> = vec![(SYSTEM_TABLE.into(), None)];
        for dir in SYSTEM_DIRS {
            tables.extend(
                sorted_dir(dir)
                    .into_iter()
                    .filter(|(n, _)| is_table_name(n))
                    .map(|(_, p)| (p, None)),
            );
        }
        tables.extend(sorted_dir(USER_TABS).into_iter().map(|(n, p)| (p, Some(n))));

        for (path, user) in tables {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            files.push(path.clone());
            let shown = path.display().to_string();
            let who = user.clone().unwrap_or_else(|| "CRON".into());
            if let Err(e) = trusted(&path) {
                log(&format!("({who}) WRONG FILE OWNER OR MODE ({shown}: {e})"));
                continue;
            }
            if let Some(u) = &user
                && pwd::lookup(u).is_none()
            {
                log(&format!("({u}) ORPHAN (no passwd entry)"));
                continue;
            }
            let (table, errors) = libcron::parse(&text, user.is_none());
            for (line, e) in errors {
                log(&format!("({who}) ERROR ({shown} line {line}: {e})"));
            }
            let env = Rc::new(table.env);
            for job in table.jobs {
                let user = job
                    .user
                    .clone()
                    .or_else(|| user.clone())
                    .unwrap_or_default();
                entries.push(Entry {
                    user,
                    job,
                    env: env.clone(),
                });
            }
        }
        Db {
            entries,
            stamps: stamps(&files),
        }
    }

    /// Whether any table, or a directory of tables, changed since the load.
    pub fn changed(&self) -> bool {
        // A directory's time changes when a table is added to it or removed; a table's when
        // it's rewritten.
        self.stamps.iter().any(|(p, t)| mtime(p) != *t)
    }

    pub fn every_second(&self) -> bool {
        self.entries.iter().any(|e| e.job.when == When::EverySecond)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_names() {
        for ok in ["0hourly", "sysstat", "local-backups", "a.b"] {
            assert!(is_table_name(ok), "{ok}");
        }
        for bad in [
            "",
            ".hidden",
            "#autosave#",
            "job~",
            "job,",
            "job.bak",
            "job.orig",
            "job.new",
            "job.swp",
        ] {
            assert!(!is_table_name(bad), "{bad}");
        }
    }
}
