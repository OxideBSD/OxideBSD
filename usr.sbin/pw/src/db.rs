//! The account database as one unit: `master.passwd`, `passwd` and `group` in an `/etc`
//! directory, read and written under its lock.
//!
//! The lock is FreeBSD's: `flock(2)` on `master.passwd`, held until the program exits. vipw(8)
//! takes the same one. Installing renames a new file over `master.passwd`, so a lock taken on the
//! file just replaced is no lock at all: after locking, the descriptor must still be the file at
//! the path, or it is tried again.

use crate::{EX_CANTCREAT, EX_NOPERM, EX_NOUSER, EX_OSFILE, EX_TEMPFAIL, Result, err};
use grp::Group;
use pwd::Entry;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

pub struct Db {
    pub dir: String,
    pub users: Vec<Entry>,
    pub groups: Vec<Group>,
    /// Write `group` / the account files on [`save`](Db::save).
    pub groups_changed: bool,
    pub users_changed: bool,
    _lock: Option<File>,
}

/// Takes the database lock on `path`, or says who has it.
pub fn lock(path: &str) -> Result<File> {
    loop {
        let f = File::open(path).or_else(|e| err(EX_OSFILE, format!("{path}: {e}")))?;
        // SAFETY: flock(2) on a descriptor we own.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return err(EX_TEMPFAIL, format!("{path}: the password database is busy (locked by another program)"));
            }
            return err(EX_OSFILE, format!("{path}: lock: {e}"));
        }
        let (held, now) = (f.metadata(), std::fs::metadata(path));
        if let (Ok(h), Ok(n)) = (&held, &now)
            && (h.dev(), h.ino()) == (n.dev(), n.ino())
        {
            return Ok(f);
        }
    }
}

/// Whether the program runs as the superuser, which every change needs.
pub fn require_root() -> Result<()> {
    // SAFETY: geteuid(2).
    if unsafe { libc::geteuid() } != 0 {
        return err(EX_NOPERM, "permission denied (must be the superuser)");
    }
    Ok(())
}

fn read<T>(path: &str, parse: fn(&str) -> (Vec<T>, Vec<(usize, String)>)) -> Result<Vec<T>> {
    let text = std::fs::read_to_string(path).or_else(|e| err(EX_OSFILE, format!("{path}: {e}")))?;
    let (items, errors) = parse(&text);
    // Rewriting the file would drop a line we can't read: refuse instead.
    if let Some((line, e)) = errors.first() {
        return err(EX_OSFILE, format!("{path}: line {line}: {e}"));
    }
    Ok(items)
}

impl Db {
    /// Reads the database in `dir`; `for_change` checks for root and takes the lock first.
    pub fn open(dir: &str, for_change: bool) -> Result<Db> {
        let master = format!("{dir}/master.passwd");
        let lock = if for_change {
            require_root()?;
            Some(lock(&master)?)
        } else {
            None
        };
        Ok(Db {
            dir: dir.into(),
            users: read(&master, pwd::parse)?,
            groups: read(&format!("{dir}/group"), grp::parse_groups)?,
            groups_changed: false,
            users_changed: false,
            _lock: lock,
        })
    }

    pub fn user(&self, name: &str) -> Option<usize> {
        self.users.iter().position(|e| e.name == name)
    }

    /// A user named on the command line: by name, else by uid if it is a number (as pw does).
    pub fn find_user(&self, name: &str) -> Result<usize> {
        self.user(name)
            .or_else(|| name.parse::<u32>().ok().and_then(|uid| self.users.iter().position(|e| e.uid == uid)))
            .map_or_else(|| err(EX_NOUSER, format!("user `{name}' does not exist")), Ok)
    }

    pub fn group(&self, name: &str) -> Option<usize> {
        self.groups.iter().position(|g| g.name == name)
    }

    /// A group by name, else by gid if it is a number.
    pub fn find_group(&self, name: &str) -> Result<usize> {
        self.group(name)
            .or_else(|| name.parse::<u32>().ok().and_then(|gid| self.groups.iter().position(|g| g.gid == gid)))
            .map_or_else(|| err(EX_NOUSER, format!("group `{name}' does not exist")), Ok)
    }

    /// Writes what changed: `group` first, then the account files, so that by the time a new
    /// user is visible its groups are.
    pub fn save(&mut self) -> Result<()> {
        if self.groups_changed {
            grp::install_groups_in(&self.dir, &self.groups).or_else(|e| err(EX_CANTCREAT, format!("{}/group: {e}", self.dir)))?;
            self.groups_changed = false;
        }
        if self.users_changed {
            grp::install_users_in(&self.dir, &self.users).or_else(|e| err(EX_CANTCREAT, format!("{}/master.passwd: {e}", self.dir)))?;
            self.users_changed = false;
        }
        Ok(())
    }
}
