//! The NetBSD/OpenBSD interface: `useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`,
//! `groupmod`, each its own command with getopt options before the one operand.

use crate::args::{self, getopt};
use crate::conf::Defaults;
use crate::db::{self, Db};
use crate::user::{GroupSpec, HomeAction, UserSpec};
use crate::{EX_USAGE, Result, err, group, user};

const ETC: &str = "/etc";

const USERADD: &str = "usage: useradd -D [-b base-dir] [-e expiry] [-g gid|name|=uid] [-k skel-dir]
               [-L class] [-r low..high] [-s shell]
       useradd [-mov] [-b base-dir] [-c comment] [-d home-dir] [-e expiry]
               [-G group[,group]] [-g gid|name|=uid] [-k skel-dir] [-L class]
               [-M homeperm] [-p password] [-r low..high] [-s shell] [-u uid] user";
const USERDEL: &str = "usage: userdel [-prv] user";
const USERMOD: &str = "usage: usermod [-mov] [-c comment] [-d home-dir] [-e expiry]
               [-G group[,group]] [-g gid|name] [-L class] [-l new-login]
               [-p password] [-s shell] [-u uid] user";
const GROUPADD: &str = "usage: groupadd [-ov] [-g gid] group";
const GROUPDEL: &str = "usage: groupdel [-v] group";
const GROUPMOD: &str = "usage: groupmod [-ov] [-g gid] [-n newname] group";

fn one(operands: Vec<String>, usage: &str) -> Result<String> {
    match <[String; 1]>::try_from(operands) {
        Ok([name]) => Ok(name),
        Err(_) => err(EX_USAGE, usage),
    }
}

/// The options useradd and usermod share; `false` if `c` isn't one of them.
fn common(s: &mut UserSpec, c: char, v: Option<String>) -> Result<bool> {
    let v = v.unwrap_or_default();
    match c {
        'c' => s.comment = Some(v),
        'd' => s.home = Some(v),
        'e' => s.expire = Some(args::time(&v, args::now())?),
        'G' => s.groups.get_or_insert_with(Vec::new).extend(args::list(&v)),
        'g' => s.group = Some(GroupSpec::parse(&v)),
        'L' => s.class = Some(v),
        'p' => s.password = Some(v),
        's' => s.shell = Some(v),
        'u' => s.uid = Some(args::id("uid", &v)?),
        'o' => s.dup_ok = true,
        'v' => s.verbose = true,
        _ => return Ok(false),
    }
    Ok(true)
}

pub fn useradd(a: &[String]) -> Result<()> {
    let o = getopt(a, "Db:c:d:e:G:g:k:L:M:mop:r:s:u:v", USERADD)?;
    let mut d = Defaults::load(ETC);
    if o.opts.iter().any(|(c, _)| *c == 'D') {
        return set_defaults(o, d);
    }
    let mut s = UserSpec::default();
    for (c, v) in o.opts {
        if common(&mut s, c, v.clone())? {
            continue;
        }
        let v = v.unwrap_or_default();
        match c {
            'b' => s.base_dir = Some(v),
            'k' => s.skel = Some(v),
            'M' => s.home_mode = Some(args::mode(&v)?),
            'm' => s.home_action = HomeAction::Create,
            'r' => d.range = args::range(&v)?,
            _ => return err(EX_USAGE, USERADD),
        }
    }
    s.name = one(o.operands, USERADD)?;
    let mut db = Db::open(ETC, true)?;
    user::add(&mut db, s, &d).map(drop)
}

/// `useradd -D`: lists the defaults, or with options, changes them in `usermgmt.conf`.
fn set_defaults(o: args::Opts, mut d: Defaults) -> Result<()> {
    if !o.operands.is_empty() {
        return err(EX_USAGE, USERADD);
    }
    let mut changed = false;
    for (c, v) in o.opts {
        let key = match c {
            'D' => continue,
            'b' => "base_dir",
            'e' => "expire",
            'g' => "group",
            'k' => "skel_dir",
            'L' => "class",
            'M' => "homeperm",
            'r' => "range",
            's' => "shell",
            _ => return err(EX_USAGE, USERADD),
        };
        d.set(key, &v.unwrap_or_default())?;
        changed = true;
    }
    if changed {
        db::require_root()?;
        d.save(ETC)?;
    }
    print!("{}", d.text());
    Ok(())
}

pub fn usermod(a: &[String]) -> Result<()> {
    let o = getopt(a, "c:d:e:G:g:L:l:mop:s:u:v", USERMOD)?;
    let mut s = UserSpec::default();
    for (c, v) in o.opts {
        if common(&mut s, c, v.clone())? {
            continue;
        }
        match c {
            'l' => s.new_name = v,
            'm' => s.home_action = HomeAction::Move,
            _ => return err(EX_USAGE, USERMOD),
        }
    }
    s.name = one(o.operands, USERMOD)?;
    if s.home_action == HomeAction::Move && s.home.is_none() {
        return err(EX_USAGE, "-m needs -d: the directory to move the home to");
    }
    let mut db = Db::open(ETC, true)?;
    user::modify(&mut db, s, &Defaults::load(ETC))
}

/// `userdel -p` keeps the account but makes it unusable, as NetBSD's: password locked, shell
/// `/sbin/nologin`.
pub fn userdel(a: &[String]) -> Result<()> {
    let o = getopt(a, "prv", USERDEL)?;
    let has = |f: char| o.opts.iter().any(|(c, _)| *c == f);
    let (preserve, remove, verbose) = (has('p'), has('r'), has('v'));
    let name = one(o.operands, USERDEL)?;
    let mut db = Db::open(ETC, true)?;
    if preserve {
        let i = db.find_user(&name)?;
        let e = &mut db.users[i];
        if !e.password.starts_with("*LOCKED*") {
            e.password = format!("*LOCKED*{}", e.password);
        }
        e.shell = "/sbin/nologin".into();
        db.users_changed = true;
        return db.save();
    }
    user::delete(&mut db, &name, remove, verbose)
}

pub fn groupadd(a: &[String]) -> Result<()> {
    let o = getopt(a, "g:ov", GROUPADD)?;
    let mut s = group::GroupSpec::default();
    for (c, v) in o.opts {
        match c {
            'g' => s.gid = Some(args::id("gid", &v.unwrap_or_default())?),
            'o' => s.dup_ok = true,
            'v' => s.verbose = true,
            _ => return err(EX_USAGE, GROUPADD),
        }
    }
    s.name = one(o.operands, GROUPADD)?;
    let mut db = Db::open(ETC, true)?;
    group::add(&mut db, s, &Defaults::load(ETC)).map(drop)
}

pub fn groupdel(a: &[String]) -> Result<()> {
    let o = getopt(a, "v", GROUPDEL)?;
    let verbose = !o.opts.is_empty();
    let name = one(o.operands, GROUPDEL)?;
    let mut db = Db::open(ETC, true)?;
    group::delete(&mut db, &name, verbose)
}

pub fn groupmod(a: &[String]) -> Result<()> {
    let o = getopt(a, "g:n:ov", GROUPMOD)?;
    let mut s = group::GroupSpec::default();
    for (c, v) in o.opts {
        match c {
            'g' => s.gid = Some(args::id("gid", &v.unwrap_or_default())?),
            'n' => s.new_name = v,
            'o' => s.dup_ok = true,
            'v' => s.verbose = true,
            _ => return err(EX_USAGE, GROUPMOD),
        }
    }
    s.name = one(o.operands, GROUPMOD)?;
    let mut db = Db::open(ETC, true)?;
    group::modify(&mut db, s)
}
