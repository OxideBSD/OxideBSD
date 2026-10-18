//! User operations, shared by both interfaces: each front end fills in a [`UserSpec`] and calls
//! these.

use crate::conf::Defaults;
use crate::db::Db;
use crate::{EX_DATAERR, EX_IOERR, EX_OSFILE, EX_SOFTWARE, Result, err};
use grp::Group;
use pwd::Entry;
use std::ffi::{CStr, CString, c_char};

/// The primary group asked for (`-g`).
#[derive(Clone, Debug, PartialEq)]
pub enum GroupSpec {
    /// A group, by name or gid.
    Existing(String),
    /// A new group named like the user, with its uid as gid where free (`-g =uid`).
    Own,
}

impl GroupSpec {
    pub fn parse(s: &str) -> GroupSpec {
        if s == "=uid" { GroupSpec::Own } else { GroupSpec::Existing(s.into()) }
    }
}

/// What to do with the home directory.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum HomeAction {
    #[default]
    Leave,
    /// Create it from the skeleton if it doesn't exist (`useradd -m`, `pw usermod -m`).
    Create,
    /// Move the old one to the new `-d` (`usermod -m`).
    Move,
}

/// A user's options, as given; `None` is "not given" (a default for a new user, unchanged for
/// an existing one).
#[derive(Default)]
pub struct UserSpec {
    pub name: String,
    pub new_name: Option<String>,
    pub uid: Option<u32>,
    pub group: Option<GroupSpec>,
    /// Supplementary groups, by name or gid; replaces the user's list on a change.
    pub groups: Option<Vec<String>>,
    pub comment: Option<String>,
    pub home: Option<String>,
    pub base_dir: Option<String>,
    pub skel: Option<String>,
    pub home_mode: Option<u32>,
    pub class: Option<String>,
    pub shell: Option<String>,
    pub expire: Option<i64>,
    pub change: Option<i64>,
    /// A `crypt(3)` hash, `*` to lock, or empty for no password.
    pub password: Option<String>,
    pub home_action: HomeAction,
    /// Allow a uid (or gid) already in use (`-o`).
    pub dup_ok: bool,
    /// Range for a new uid, overriding the defaults' (`useradd -r`).
    pub range: Option<(u32, u32)>,
    /// Only print the new entry (`pw -N`).
    pub dry_run: bool,
    pub verbose: bool,
}

fn data<T>(r: std::result::Result<T, String>) -> Result<T> {
    r.or_else(|e| err(EX_DATAERR, e))
}

/// Checks the free-text fields given.
fn check_fields(s: &UserSpec) -> Result<()> {
    for (what, v) in [
        ("the comment", &s.comment),
        ("the home directory", &s.home),
        ("the shell", &s.shell),
        ("the class", &s.class),
        ("the password", &s.password),
    ] {
        if let Some(v) = v {
            data(grp::valid_field(what, v))?;
        }
    }
    if s.class.as_ref().is_some_and(|c| c.contains(char::is_whitespace)) {
        return err(EX_DATAERR, "the class may not contain spaces");
    }
    Ok(())
}

/// A shell named by path is taken as is (with a warning if it doesn't exist); a bare name
/// (`-s ksh`) is looked up in `/etc/shells`, then the usual directories, as pw does.
pub fn resolve_shell(shell: &str) -> Result<String> {
    if shell.is_empty() || shell.contains('/') {
        if !shell.is_empty() && !std::path::Path::new(shell).exists() {
            crate::warn(&format!("warning: shell `{shell}' does not exist"));
        }
        return Ok(shell.into());
    }
    let listed = std::fs::read_to_string("/etc/shells").unwrap_or_default();
    let found = listed
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('/'))
        .find(|l| l.rsplit('/').next() == Some(shell))
        .map(String::from)
        .or_else(|| ["/bin", "/usr/bin", "/usr/local/bin"].iter().map(|d| format!("{d}/{shell}")).find(|p| std::path::Path::new(p).exists()));
    found.map_or_else(|| err(EX_OSFILE, format!("shell `{shell}' does not exist")), Ok)
}

/// The gids of `names` (names or numbers), each an existing group.
fn resolve_groups(db: &Db, names: &[String]) -> Result<Vec<usize>> {
    let mut v = Vec::new();
    for n in names {
        let i = db.find_group(n)?;
        if !v.contains(&i) {
            v.push(i);
        }
    }
    Ok(v)
}

/// Makes `user` a member of exactly the groups at `want`.
fn set_memberships(groups: &mut [Group], user: &str, want: &[usize]) -> bool {
    let mut changed = false;
    for (i, g) in groups.iter_mut().enumerate() {
        let member = g.has_member(user);
        if want.contains(&i) && !member {
            g.members.push(user.into());
            changed = true;
        } else if !want.contains(&i) && member {
            g.members.retain(|m| m != user);
            changed = true;
        }
    }
    changed
}

pub fn add(db: &mut Db, s: UserSpec, d: &Defaults) -> Result<Entry> {
    data(grp::valid_name(&s.name))?;
    check_fields(&s)?;
    if db.user(&s.name).is_some() {
        return err(EX_DATAERR, format!("user `{}' already exists", s.name));
    }
    let (lo, hi) = s.range.unwrap_or(d.range);
    let group = s.group.clone().unwrap_or_else(|| GroupSpec::parse(&d.group));
    let uid = match s.uid {
        Some(uid) => {
            if !s.dup_ok && db.users.iter().any(|e| e.uid == uid) {
                return err(EX_DATAERR, format!("uid {uid} is already in use"));
            }
            Some(uid)
        }
        // A user with a group of its own gets an ID free for both, so the two match.
        None if group == GroupSpec::Own => grp::next_shared_id(&db.users, &db.groups, lo, hi),
        None => grp::next_uid(&db.users, lo, hi),
    }
    .map_or_else(|| err(EX_SOFTWARE, format!("no free uid in {lo}..{hi}")), Ok)?;
    let gid = match &group {
        GroupSpec::Existing(g) => db.groups[db.find_group(g)?].gid,
        GroupSpec::Own => {
            if db.group(&s.name).is_some() {
                return err(EX_DATAERR, format!("group `{}' already exists; name it with -g to use it", s.name));
            }
            let gid = if db.groups.iter().any(|g| g.gid == uid) { grp::next_gid(&db.groups, lo, hi) } else { Some(uid) };
            let gid = gid.map_or_else(|| err(EX_SOFTWARE, format!("no free gid in {lo}..{hi}")), Ok)?;
            db.groups.push(Group { name: s.name.clone(), password: "*".into(), gid, members: Vec::new() });
            db.groups_changed = true;
            gid
        }
    };
    if let Some(names) = &s.groups {
        let want = resolve_groups(db, names)?;
        db.groups_changed |= set_memberships(&mut db.groups, &s.name, &want);
    }
    let base = s.base_dir.clone().unwrap_or_else(|| d.base_dir.clone());
    let home = s.home.clone().unwrap_or_else(|| format!("{}/{}", base.trim_end_matches('/'), s.name));
    let shell = resolve_shell(s.shell.as_deref().unwrap_or(&d.shell))?;
    let expire = match s.expire {
        Some(t) => t,
        None => crate::args::time(&d.expire, crate::args::now())?,
    };
    let e = Entry {
        name: s.name.clone(),
        password: s.password.clone().unwrap_or_else(|| d.password.clone()),
        uid,
        gid,
        class: s.class.clone().unwrap_or_else(|| d.class.clone()),
        change: s.change.unwrap_or(0),
        expire,
        gecos: s.comment.clone().unwrap_or_default(),
        home,
        shell,
    };
    data(pwd::validate(&[e.clone()]))?;
    if s.dry_run {
        println!("{}", e.master_line());
        return Ok(e);
    }
    db.users.push(e.clone());
    db.users_changed = true;
    db.save()?;
    if s.verbose {
        println!("{}: added user `{}' (uid {uid}, gid {gid})", crate::prog(), e.name);
    }
    if s.home_action != HomeAction::Leave {
        let skel = s.skel.clone().unwrap_or_else(|| d.skel_dir.clone());
        crate::home::create(&e.home, &skel, uid, gid, s.home_mode.unwrap_or(d.homeperm))?;
        if s.verbose {
            println!("{}: created home directory {}", crate::prog(), e.home);
        }
    }
    Ok(e)
}

pub fn modify(db: &mut Db, s: UserSpec, d: &Defaults) -> Result<()> {
    check_fields(&s)?;
    let i = db.find_user(&s.name)?;
    let old = db.users[i].clone();
    let mut e = old.clone();
    if let Some(n) = &s.new_name {
        data(grp::valid_name(n))?;
        if *n != old.name && db.user(n).is_some() {
            return err(EX_DATAERR, format!("user `{n}' already exists"));
        }
        e.name = n.clone();
    }
    if let Some(uid) = s.uid {
        if !s.dup_ok && uid != old.uid && db.users.iter().any(|o| o.uid == uid) {
            return err(EX_DATAERR, format!("uid {uid} is already in use"));
        }
        e.uid = uid;
    }
    match &s.group {
        Some(GroupSpec::Existing(g)) => e.gid = db.groups[db.find_group(g)?].gid,
        Some(GroupSpec::Own) => return err(crate::EX_USAGE, "-g =uid is only for new users"),
        None => {}
    }
    if let Some(c) = &s.comment {
        e.gecos = c.clone();
    }
    if let Some(h) = &s.home {
        e.home = h.clone();
    }
    if let Some(sh) = &s.shell {
        e.shell = resolve_shell(sh)?;
    }
    if let Some(c) = &s.class {
        e.class = c.clone();
    }
    if let Some(t) = s.expire {
        e.expire = t;
    }
    if let Some(t) = s.change {
        e.change = t;
    }
    if let Some(p) = &s.password {
        e.password = p.clone();
    }
    // Memberships follow a rename; -G then replaces them.
    let mut groups = db.groups.clone();
    let mut groups_changed = false;
    if e.name != old.name {
        for g in &mut groups {
            for m in &mut g.members {
                if *m == old.name {
                    *m = e.name.clone();
                    groups_changed = true;
                }
            }
        }
    }
    if let Some(names) = &s.groups {
        let want = resolve_groups(db, names)?;
        groups_changed |= set_memberships(&mut groups, &e.name, &want);
    }
    data(pwd::validate(&[e.clone()]))?;
    if s.dry_run {
        println!("{}", e.master_line());
        return Ok(());
    }
    if s.home_action == HomeAction::Move && e.home != old.home && std::path::Path::new(&old.home).is_dir() {
        crate::home::relocate(&old.home, &e.home, e.uid, e.gid)?;
        if s.verbose {
            println!("{}: moved {} to {}", crate::prog(), old.home, e.home);
        }
    }
    db.groups = groups;
    db.groups_changed |= groups_changed;
    db.users[i] = e.clone();
    db.users_changed = true;
    db.save()?;
    if s.verbose {
        println!("{}: modified user `{}'", crate::prog(), e.name);
    }
    if s.home_action == HomeAction::Create && !std::path::Path::new(&e.home).is_dir() {
        let skel = s.skel.clone().unwrap_or_else(|| d.skel_dir.clone());
        crate::home::create(&e.home, &skel, e.uid, e.gid, s.home_mode.unwrap_or(d.homeperm))?;
    }
    Ok(())
}

/// Deletes a user, its memberships, and its own group if nothing else uses it. `remove_home`
/// also removes the home directory and mail; the crontab goes either way, as on FreeBSD (only
/// for the live system's database, not another `-V` directory's).
pub fn delete(db: &mut Db, name: &str, remove_home: bool, verbose: bool) -> Result<()> {
    let i = db.find_user(name)?;
    if db.users[i].name == "root" {
        return err(EX_DATAERR, format!("cannot remove user `{}'", db.users[i].name));
    }
    let e = db.users.remove(i);
    db.users_changed = true;
    for g in &mut db.groups {
        if g.has_member(&e.name) {
            g.members.retain(|m| *m != e.name);
            db.groups_changed = true;
        }
    }
    let own = db.groups.iter().position(|g| g.name == e.name && g.gid == e.gid && g.members.is_empty());
    if let Some(gi) = own
        && !db.users.iter().any(|o| o.gid == e.gid)
    {
        db.groups.remove(gi);
        db.groups_changed = true;
        if verbose {
            println!("{}: removed group `{}'", crate::prog(), e.name);
        }
    }
    db.save()?;
    if verbose {
        println!("{}: removed user `{}'", crate::prog(), e.name);
    }
    if db.dir == "/etc" {
        let _ = std::fs::remove_file(format!("/var/cron/tabs/{}", e.name));
        if remove_home {
            let _ = std::fs::remove_file(format!("/var/mail/{}", e.name));
        }
    }
    if remove_home {
        // Another account sharing the directory keeps it.
        if db.users.iter().any(|o| o.home == e.home) {
            crate::warn(&format!("{}: not removing: another account uses it", e.home));
        } else if let Some(why) = crate::home::remove(&e.home, e.uid)? {
            crate::warn(&why);
        } else if verbose {
            println!("{}: removed {}", crate::prog(), e.home);
        }
    }
    Ok(())
}

/// Locks (`*LOCKED*` before the hash, FreeBSD's marker) or unlocks a user's password logins.
pub fn set_locked(db: &mut Db, name: &str, lock: bool) -> Result<()> {
    const MARK: &str = "*LOCKED*";
    let i = db.find_user(name)?;
    let p = &mut db.users[i].password;
    match (lock, p.starts_with(MARK)) {
        (true, false) => *p = format!("{MARK}{p}"),
        (false, true) => *p = p[MARK.len()..].to_string(),
        (true, true) => return err(EX_DATAERR, format!("user `{name}' is already locked")),
        (false, false) => return err(EX_DATAERR, format!("user `{name}' is not locked")),
    }
    db.users_changed = true;
    db.save()
}

unsafe extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

/// A new SHA-512 (`$6$`) `crypt(3)` hash with a random salt, as `pam_unix` makes.
pub fn hash_password(password: &str) -> Result<String> {
    const SALT_CHARS: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let raw = random(16)?;
    let salt: String = raw.iter().map(|b| SALT_CHARS[*b as usize % SALT_CHARS.len()] as char).collect();
    let Ok(key) = CString::new(password) else { return err(EX_DATAERR, "the password may not contain a NUL") };
    let salt = CString::new(format!("$6${salt}$")).expect("salt has no NUL");
    // SAFETY: crypt(3) returns a static buffer or NULL.
    let out = unsafe { crypt(key.as_ptr(), salt.as_ptr()) };
    if out.is_null() {
        return err(EX_SOFTWARE, "crypt failed");
    }
    Ok(unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned())
}

fn random(n: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut raw = vec![0u8; n];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut raw)).or_else(|e| err(EX_IOERR, format!("/dev/urandom: {e}")))?;
    Ok(raw)
}

/// A random password for `pw -w random`: 12 characters from an alphabet without look-alikes.
pub fn random_password() -> Result<String> {
    const CHARS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    Ok(random(12)?.iter().map(|b| CHARS[*b as usize % CHARS.len()] as char).collect())
}

/// Reads one line, a password, from descriptor `fd` (`pw -h`/`-H`). On a terminal it prompts and
/// turns echo off.
pub fn read_password_fd(fd: i32, user: &str) -> Result<String> {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    // SAFETY: isatty(3)/tcgetattr(3) on a descriptor number; failure is reported, not UB.
    let tty = unsafe { libc::isatty(fd) } == 1;
    let mut saved: Option<libc::termios> = None;
    if tty {
        eprint!("password for user {user}: ");
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut t) } == 0 {
            saved = Some(t);
            t.c_lflag &= !libc::ECHO;
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) };
        }
    }
    // SAFETY: the descriptor is the caller's; ManuallyDrop keeps it open.
    let mut f = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    let r = loop {
        match f.read(&mut b) {
            Ok(0) => break Ok(()),
            Ok(_) if b[0] == b'\n' => break Ok(()),
            Ok(_) => line.push(b[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e),
        }
    };
    if let Some(t) = saved {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) };
        eprintln!();
    }
    r.or_else(|e| err(EX_IOERR, format!("reading the password from fd {fd}: {e}")))?;
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).or_else(|_| err(EX_DATAERR, "the password is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(name: &str, members: &[&str]) -> Group {
        Group { name: name.into(), password: "*".into(), gid: 1, members: members.iter().map(|m| m.to_string()).collect() }
    }

    #[test]
    fn memberships() {
        let mut gs = vec![g("a", &["u", "x"]), g("b", &[]), g("c", &["u"])];
        assert!(set_memberships(&mut gs, "u", &[1, 2]));
        assert_eq!(gs[0].members, ["x"]);
        assert_eq!(gs[1].members, ["u"]);
        assert_eq!(gs[2].members, ["u"]);
        assert!(!set_memberships(&mut gs, "u", &[1, 2]));
    }

    #[test]
    fn group_specs() {
        assert_eq!(GroupSpec::parse("=uid"), GroupSpec::Own);
        assert_eq!(GroupSpec::parse("wheel"), GroupSpec::Existing("wheel".into()));
    }
}
