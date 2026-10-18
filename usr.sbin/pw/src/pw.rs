//! FreeBSD's `pw(8)` interface: `pw [-V etcdir] command [name] [options]`, the name given as
//! the first operand or with `-n`, options anywhere after the command. Commands may be one word
//! (`useradd`) or two (`user add`).

use crate::args::{self, getopt};
use crate::conf::Defaults;
use crate::db::Db;
use crate::user::{GroupSpec, HomeAction, UserSpec};
use crate::{EX_DATAERR, EX_NOUSER, EX_USAGE, Result, err, group, user};

const USAGE: &str = "usage: pw [-V etcdir] useradd [name] [-Nmoq] [-C config] [-b base-dir] [-c comment]
              [-d home] [-e date] [-G grouplist] [-g group] [-H fd | -h fd] [-k skel]
              [-L class] [-M mode] [-p date] [-s shell] [-u uid] [-w method]
       pw [-V etcdir] usermod [name|uid] [-Nmoq] [-c comment] [-d home] [-e date]
              [-G grouplist] [-g group] [-H fd | -h fd] [-k skel] [-L class]
              [-l newname] [-M mode] [-p date] [-s shell] [-u uid] [-w method]
       pw [-V etcdir] userdel [name|uid] [-qr]
       pw [-V etcdir] usershow [name|uid] [-7Paq]
       pw [-V etcdir] usernext [-q] [-C config]
       pw [-V etcdir] lock|unlock [name|uid] [-q]
       pw [-V etcdir] groupadd [group] [-Noq] [-g gid] [-M members]
       pw [-V etcdir] groupmod [group|gid] [-Noq] [-d members] [-g gid] [-l newname]
              [-M members] [-m members]
       pw [-V etcdir] groupdel [group|gid] [-q]
       pw [-V etcdir] groupshow [group|gid] [-Paq]
       pw [-V etcdir] groupnext [-q] [-C config]";

/// Options common to every command: `-V etcdir`, `-q`, `-C config`, `-Y` (NIS; nothing to do).
struct Common {
    dir: String,
    conf: Option<String>,
    name: Option<String>,
}

pub fn main(a: &[String]) -> Result<()> {
    let mut a = a.to_vec();
    // `-V dir` and `-q` may come before the command too.
    let mut pre = Vec::new();
    while let Some(f) = a.first().filter(|f| f.starts_with('-')).cloned() {
        a.remove(0);
        if f == "-V" {
            if a.is_empty() {
                return err(EX_USAGE, USAGE);
            }
            pre.push(f);
            pre.push(a.remove(0));
        } else if f.starts_with("-V") || f == "-q" {
            pre.push(f);
        } else {
            return err(EX_USAGE, USAGE);
        }
    }
    if a.is_empty() {
        return err(EX_USAGE, USAGE);
    }
    let mut cmd = a.remove(0);
    if matches!(cmd.as_str(), "user" | "group")
        && let Some(verb) = a.first().filter(|v| matches!(v.as_str(), "add" | "del" | "mod" | "show" | "next")).cloned()
    {
        a.remove(0);
        cmd += &verb;
    }
    let rest: Vec<String> = pre.into_iter().chain(a).collect();
    match cmd.as_str() {
        "useradd" => useradd(&rest),
        "usermod" => usermod(&rest),
        "userdel" => userdel(&rest),
        "usershow" => usershow(&rest),
        "usernext" => usernext(&rest),
        "lock" => lock(&rest, true),
        "unlock" => lock(&rest, false),
        "groupadd" => groupadd(&rest),
        "groupmod" => groupmod(&rest),
        "groupdel" => groupdel(&rest),
        "groupshow" => groupshow(&rest),
        "groupnext" => groupnext(&rest),
        _ => err(EX_USAGE, USAGE),
    }
}

/// Parses `spec` plus the common options; returns the rest of the options and the common ones.
fn parse(a: &[String], spec: &str) -> Result<(Vec<(char, Option<String>)>, Common)> {
    let o = getopt(a, &format!("{spec}V:qYC:n:"), USAGE)?;
    let mut c = Common { dir: "/etc".into(), conf: None, name: None };
    let mut rest = Vec::new();
    for (f, v) in o.opts {
        match f {
            'V' => c.dir = v.unwrap_or_default().trim_end_matches('/').to_string(),
            'q' => crate::set_quiet(),
            'Y' => {}
            'C' => c.conf = v,
            'n' => c.name = v,
            _ => rest.push((f, v)),
        }
    }
    match <[String; 1]>::try_from(o.operands) {
        Ok([n]) if c.name.is_none() => c.name = Some(n),
        Ok(_) => return err(EX_USAGE, USAGE),
        Err(v) if v.is_empty() => {}
        Err(_) => return err(EX_USAGE, USAGE),
    }
    if c.dir.is_empty() {
        c.dir = "/".into();
    }
    Ok((rest, c))
}

fn defaults(c: &Common) -> Defaults {
    match &c.conf {
        Some(path) => {
            let (d, errors) = Defaults::parse(&std::fs::read_to_string(path).unwrap_or_default());
            for (line, e) in errors {
                crate::warn(&format!("{path}: line {line}: {e}"));
            }
            d
        }
        None => Defaults::load(&c.dir),
    }
}

/// `-h fd` (a password to hash, `-` for none: locked), `-H fd` (a hash) and `-w method`.
fn password(s: &mut UserSpec, f: char, v: &str) -> Result<()> {
    s.password = Some(match (f, v) {
        ('h', "-") => "*".into(),
        ('h', fd) => user::hash_password(&user::read_password_fd(args::id("descriptor", fd)? as i32, &s.name)?)?,
        ('H', fd) => user::read_password_fd(args::id("descriptor", fd)? as i32, &s.name)?,
        ('w', "no") => "*".into(),
        ('w', "none") => String::new(),
        ('w', "random") => {
            let p = user::random_password()?;
            println!("{p}");
            user::hash_password(&p)?
        }
        // FreeBSD's `yes`, the login name as the password, is not offered.
        ('w', m) => return err(EX_USAGE, format!("bad password method `{m}': use no, none or random")),
        _ => unreachable!(),
    });
    Ok(())
}

/// The options useradd and usermod share; `false` if `f` isn't one of them. The password
/// options are applied after the name is known (they may prompt with it).
fn common(s: &mut UserSpec, f: char, v: &str) -> Result<bool> {
    match f {
        'c' => s.comment = Some(v.into()),
        'd' => s.home = Some(v.into()),
        'e' => s.expire = Some(args::time(v, args::now())?),
        'p' => s.change = Some(args::time(v, args::now())?),
        'g' => s.group = Some(GroupSpec::parse(v)),
        'G' => s.groups.get_or_insert_with(Vec::new).extend(args::list(v)),
        'k' => s.skel = Some(v.into()),
        'L' => s.class = Some(v.into()),
        'M' => s.home_mode = Some(args::mode(v)?),
        'm' => s.home_action = HomeAction::Create,
        's' => s.shell = Some(v.into()),
        'o' => s.dup_ok = true,
        'N' => s.dry_run = true,
        _ => return Ok(false),
    }
    Ok(true)
}

fn finish_password(s: &mut UserSpec, pw: &[(char, String)]) -> Result<()> {
    if pw.len() > 1 {
        return err(EX_USAGE, "only one of -h, -H and -w may be given");
    }
    for (f, v) in pw {
        password(s, *f, v)?;
    }
    Ok(())
}

fn useradd(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "Nmob:c:d:e:p:g:G:k:L:M:s:u:h:H:w:")?;
    let mut s = UserSpec::default();
    let mut pw = Vec::new();
    for (f, v) in opts {
        let v = v.unwrap_or_default();
        if common(&mut s, f, &v)? {
            continue;
        }
        match f {
            'b' => s.base_dir = Some(v),
            'u' => s.uid = Some(args::id("uid", &v)?),
            'h' | 'H' | 'w' => pw.push((f, v)),
            _ => return err(EX_USAGE, USAGE),
        }
    }
    let Some(name) = c.name.clone() else { return err(EX_USAGE, USAGE) };
    s.name = name;
    let d = defaults(&c);
    let mut db = Db::open(&c.dir, !s.dry_run)?;
    // Checked before a password prompt, not after.
    if db.user(&s.name).is_some() {
        return err(EX_DATAERR, format!("user `{}' already exists", s.name));
    }
    finish_password(&mut s, &pw)?;
    user::add(&mut db, s, &d).map(drop)
}

fn usermod(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "Nmoc:d:e:p:g:G:k:l:L:M:s:u:h:H:w:")?;
    let mut s = UserSpec::default();
    let mut pw = Vec::new();
    let mut uid = None;
    for (f, v) in opts {
        let v = v.unwrap_or_default();
        if common(&mut s, f, &v)? {
            continue;
        }
        match f {
            'l' => s.new_name = Some(v),
            'u' => uid = Some(args::id("uid", &v)?),
            'h' | 'H' | 'w' => pw.push((f, v)),
            _ => return err(EX_USAGE, USAGE),
        }
    }
    let mut db = Db::open(&c.dir, !s.dry_run)?;
    // Without a name, -u says which user; with one, it is the new uid.
    match (&c.name, uid) {
        (Some(n), uid) => {
            s.name = db.users[db.find_user(n)?].name.clone();
            s.uid = uid;
        }
        (None, Some(uid)) => s.name = by_uid(&db, uid)?,
        (None, None) => return err(EX_USAGE, USAGE),
    }
    finish_password(&mut s, &pw)?;
    user::modify(&mut db, s, &defaults(&c))
}

fn by_uid(db: &Db, uid: u32) -> Result<String> {
    db.users.iter().find(|e| e.uid == uid).map_or_else(|| err(EX_NOUSER, format!("no user with uid {uid}")), |e| Ok(e.name.clone()))
}

/// The user a command names: `name`, or `-u uid`.
fn target(db: &Db, c: &Common, opts: &[(char, Option<String>)]) -> Result<String> {
    if let Some(n) = &c.name {
        return Ok(db.users[db.find_user(n)?].name.clone());
    }
    match opts.iter().find(|(f, _)| *f == 'u') {
        Some((_, v)) => by_uid(db, args::id("uid", v.as_deref().unwrap_or_default())?),
        None => err(EX_USAGE, USAGE),
    }
}

fn userdel(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "ru:")?;
    let mut db = Db::open(&c.dir, true)?;
    let name = target(&db, &c, &opts)?;
    user::delete(&mut db, &name, opts.iter().any(|(f, _)| *f == 'r'), false)
}

fn lock(a: &[String], on: bool) -> Result<()> {
    let (opts, c) = parse(a, "u:")?;
    let mut db = Db::open(&c.dir, true)?;
    let name = target(&db, &c, &opts)?;
    user::set_locked(&mut db, &name, on)
}

fn usershow(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "7Pau:")?;
    let has = |f: char| opts.iter().any(|(o, _)| *o == f);
    // Reading master.passwd needs root anyway; no lock is needed to read it.
    let db = Db::open(&c.dir, false)?;
    let users: Vec<&pwd::Entry> = if has('a') {
        db.users.iter().collect()
    } else {
        match target(&db, &c, &opts) {
            Ok(n) => vec![&db.users[db.user(&n).expect("target exists")]],
            Err(e) => return Err(e),
        }
    };
    for e in users {
        if has('P') {
            print!("{}", pretty_user(&db, e));
        } else if has('7') {
            println!("{}", e.passwd_line());
        } else {
            println!("{}", e.master_line());
        }
    }
    Ok(())
}

fn date(t: i64) -> String {
    if t == 0 {
        return "never".into();
    }
    let (y, m, d) = args::civil_from_days(t.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

fn pretty_user(db: &Db, e: &pwd::Entry) -> String {
    let group = db.groups.iter().find(|g| g.gid == e.gid).map_or("?", |g| g.name.as_str());
    let groups: Vec<&str> = db.groups.iter().filter(|g| g.gid == e.gid || g.has_member(&e.name)).map(|g| g.name.as_str()).collect();
    format!(
        "Login Name: {:<16} #{:<10} Group: {:<16} #{}\n Full Name: {}\n      Home: {}\n     Shell: {}\n     Class: {}\n    Groups: {}\n    Change: {}\n    Expire: {}\n\n",
        e.name,
        e.uid,
        group,
        e.gid,
        e.gecos,
        e.home,
        e.shell,
        e.class,
        groups.join(" "),
        date(e.change),
        date(e.expire)
    )
}

/// The uid and gid the next `pw useradd` would pick.
fn usernext(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "")?;
    if !opts.is_empty() || c.name.is_some() {
        return err(EX_USAGE, USAGE);
    }
    let d = defaults(&c);
    let db = Db::open(&c.dir, false)?;
    let (lo, hi) = d.range;
    let none = || err(crate::EX_SOFTWARE, format!("no free uid in {lo}..{hi}"));
    match GroupSpec::parse(&d.group) {
        GroupSpec::Own => {
            let id = grp::next_shared_id(&db.users, &db.groups, lo, hi).map_or_else(none, Ok)?;
            println!("{id}:{id}");
        }
        GroupSpec::Existing(g) => {
            let uid = grp::next_uid(&db.users, lo, hi).map_or_else(none, Ok)?;
            println!("{uid}:{}", db.groups[db.find_group(&g)?].gid);
        }
    }
    Ok(())
}

fn groupspec(opts: Vec<(char, Option<String>)>) -> Result<(group::GroupSpec, Option<u32>)> {
    let mut s = group::GroupSpec::default();
    let mut gid = None;
    for (f, v) in opts {
        let v = v.unwrap_or_default();
        match f {
            'g' => gid = Some(args::id("gid", &v)?),
            'l' => s.new_name = Some(v),
            'M' => s.members.get_or_insert_with(Vec::new).extend(args::list(&v)),
            'm' => s.add.extend(args::list(&v)),
            'd' => s.remove.extend(args::list(&v)),
            'o' => s.dup_ok = true,
            'N' => s.dry_run = true,
            _ => return err(EX_USAGE, USAGE),
        }
    }
    Ok((s, gid))
}

fn groupadd(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "NoM:g:")?;
    let (mut s, gid) = groupspec(opts)?;
    let Some(name) = c.name.clone() else { return err(EX_USAGE, USAGE) };
    (s.name, s.gid) = (name, gid);
    let mut db = Db::open(&c.dir, !s.dry_run)?;
    group::add(&mut db, s, &defaults(&c)).map(drop)
}

/// The group a command names: `name`, or `-g gid`.
fn group_target(db: &Db, c: &Common, gid: Option<u32>) -> Result<String> {
    match (&c.name, gid) {
        (Some(n), _) => Ok(db.groups[db.find_group(n)?].name.clone()),
        (None, Some(gid)) => db.groups.iter().find(|g| g.gid == gid).map_or_else(|| err(EX_NOUSER, format!("no group with gid {gid}")), |g| Ok(g.name.clone())),
        (None, None) => err(EX_USAGE, USAGE),
    }
}

fn groupmod(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "Nod:g:l:M:m:")?;
    let (mut s, gid) = groupspec(opts)?;
    let mut db = Db::open(&c.dir, !s.dry_run)?;
    // As usermod's -u: -g names the group only when no name does.
    s.name = group_target(&db, &c, gid)?;
    if c.name.is_some() {
        s.gid = gid;
    }
    group::modify(&mut db, s)
}

fn groupdel(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "g:")?;
    let (_, gid) = groupspec(opts)?;
    let mut db = Db::open(&c.dir, true)?;
    let name = group_target(&db, &c, gid)?;
    group::delete(&mut db, &name, false)
}

fn groupshow(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "Pag:")?;
    let has = |f: char| opts.iter().any(|(o, _)| *o == f);
    let gid = opts.iter().find(|(f, _)| *f == 'g').map(|(_, v)| args::id("gid", v.as_deref().unwrap_or_default())).transpose()?;
    let db = Db::open(&c.dir, false)?;
    let groups: Vec<&grp::Group> = if has('a') {
        db.groups.iter().collect()
    } else {
        match group_target(&db, &c, gid) {
            Ok(n) => vec![&db.groups[db.group(&n).expect("target exists")]],
            Err(e) => return Err(e),
        }
    };
    for g in groups {
        if has('P') {
            println!("Group Name: {:<16} #{}\n   Members: {}\n", g.name, g.gid, g.members.join(", "));
        } else {
            println!("{}", g.line());
        }
    }
    Ok(())
}

fn groupnext(a: &[String]) -> Result<()> {
    let (opts, c) = parse(a, "")?;
    if !opts.is_empty() || c.name.is_some() {
        return err(EX_USAGE, USAGE);
    }
    let (lo, hi) = defaults(&c).range;
    let db = Db::open(&c.dir, false)?;
    let gid = grp::next_gid(&db.groups, lo, hi).map_or_else(|| err(crate::EX_SOFTWARE, format!("no free gid in {lo}..{hi}")), Ok)?;
    println!("{gid}");
    Ok(())
}
