//! Group operations, shared by both interfaces.

use crate::conf::Defaults;
use crate::db::Db;
use crate::{EX_DATAERR, EX_SOFTWARE, Result, err};
use grp::Group;

#[derive(Default)]
pub struct GroupSpec {
    pub name: String,
    pub new_name: Option<String>,
    pub gid: Option<u32>,
    /// Replaces the member list (`-M`).
    pub members: Option<Vec<String>>,
    /// Members to add (`pw groupmod -m`) and remove (`-d`).
    pub add: Vec<String>,
    pub remove: Vec<String>,
    pub dup_ok: bool,
    pub dry_run: bool,
    pub verbose: bool,
}

fn data<T>(r: std::result::Result<T, String>) -> Result<T> {
    r.or_else(|e| err(EX_DATAERR, e))
}

/// Members named on the command line must be users (by name or uid); they are stored by name.
fn users(db: &Db, names: &[String]) -> Result<Vec<String>> {
    let mut v: Vec<String> = Vec::new();
    for n in names {
        let name = db.users[db.find_user(n)?].name.clone();
        if !v.contains(&name) {
            v.push(name);
        }
    }
    Ok(v)
}

fn check_gid(db: &Db, gid: u32, dup_ok: bool, except: Option<usize>) -> Result<()> {
    if !dup_ok && db.groups.iter().enumerate().any(|(i, g)| g.gid == gid && Some(i) != except) {
        return err(EX_DATAERR, format!("gid {gid} is already in use"));
    }
    Ok(())
}

pub fn add(db: &mut Db, s: GroupSpec, d: &Defaults) -> Result<Group> {
    data(grp::valid_name(&s.name))?;
    if db.group(&s.name).is_some() {
        return err(EX_DATAERR, format!("group `{}' already exists", s.name));
    }
    let gid = match s.gid {
        Some(gid) => {
            check_gid(db, gid, s.dup_ok, None)?;
            gid
        }
        None => grp::next_gid(&db.groups, d.range.0, d.range.1)
            .map_or_else(|| err(EX_SOFTWARE, format!("no free gid in {}..{}", d.range.0, d.range.1)), Ok)?,
    };
    let members = users(db, s.members.as_deref().unwrap_or_default())?;
    let g = Group { name: s.name, password: "*".into(), gid, members };
    data(grp::validate_groups(std::slice::from_ref(&g)))?;
    if s.dry_run {
        println!("{}", g.line());
        return Ok(g);
    }
    db.groups.push(g.clone());
    db.groups_changed = true;
    db.save()?;
    if s.verbose {
        println!("{}: added group `{}' (gid {gid})", crate::prog(), g.name);
    }
    Ok(g)
}

pub fn modify(db: &mut Db, s: GroupSpec) -> Result<()> {
    let i = db.find_group(&s.name)?;
    let mut g = db.groups[i].clone();
    if let Some(n) = &s.new_name {
        data(grp::valid_name(n))?;
        if *n != g.name && db.group(n).is_some() {
            return err(EX_DATAERR, format!("group `{n}' already exists"));
        }
        g.name = n.clone();
    }
    if let Some(gid) = s.gid {
        check_gid(db, gid, s.dup_ok, Some(i))?;
        g.gid = gid;
    }
    if let Some(m) = &s.members {
        g.members = users(db, m)?;
    }
    for u in users(db, &s.add)? {
        if !g.has_member(&u) {
            g.members.push(u);
        }
    }
    // A member being removed needn't be a user any more: that is how stale names go.
    for u in &s.remove {
        let name = db.find_user(u).map_or(u.as_str(), |j| db.users[j].name.as_str()).to_string();
        g.members.retain(|m| *m != name);
    }
    data(grp::validate_groups(std::slice::from_ref(&g)))?;
    if s.dry_run {
        println!("{}", g.line());
        return Ok(());
    }
    db.groups[i] = g;
    db.groups_changed = true;
    db.save()?;
    if s.verbose {
        println!("{}: modified group `{}'", crate::prog(), db.groups[i].name);
    }
    Ok(())
}

/// Deletes a group, unless it is some user's primary group (as OpenBSD's groupdel refuses):
/// that user would be left with a gid that names nothing.
pub fn delete(db: &mut Db, name: &str, verbose: bool) -> Result<()> {
    let i = db.find_group(name)?;
    let g = &db.groups[i];
    if let Some(u) = db.users.iter().find(|u| u.gid == g.gid) {
        // Only if no other group has the gid (-o), which would still name it.
        if db.groups.iter().filter(|o| o.gid == g.gid).count() == 1 {
            return err(EX_DATAERR, format!("group `{}' is the primary group of user `{}'", g.name, u.name));
        }
    }
    let g = db.groups.remove(i);
    db.groups_changed = true;
    db.save()?;
    if verbose {
        println!("{}: removed group `{}'", crate::prog(), g.name);
    }
    Ok(())
}
