//! Groups (`group(5)`) and the rest of what changing the account database takes beyond
//! `libpwd`: checks for new names and fields, picking free IDs, and installing into a directory
//! other than `/etc`. `/etc/group` holds one group per line:
//!
//! ```text
//! name:password:gid:member,member,...
//! ```
//!
//! Locking the database is left to the programs that change it (`pw(8)`, `vipw(8)`): it needs
//! `flock(2)`, and this crate stays plain Rust so it can be tested on the host.

use pwd::Entry;
use std::io;

pub const GROUP: &str = "/etc/group";

/// The longest user or group name: `MAXLOGNAME` less the NUL, as on FreeBSD.
pub const NAME_MAX: usize = 32;

/// `pwd::install` into another directory (`vipw -d`, `pw -V`): `master.passwd` (0600), then the
/// generated `passwd` (0644).
pub fn install_users_in(dir: &str, entries: &[Entry]) -> io::Result<()> {
    pwd::validate(entries).map_err(io::Error::other)?;
    pwd::write_atomic(&format!("{dir}/master.passwd"), &pwd::master_text(entries), 0o600)?;
    pwd::write_atomic(&format!("{dir}/passwd"), &pwd::passwd_text(entries), 0o644)
}

/// Checks a new user or group name the way the BSDs' account tools do: 1 to [`NAME_MAX`]
/// characters of letters, digits, `.`, `_` and `-`, not starting with `-` (it would read as an
/// option), not all digits (it would read as an ID), with an optional trailing `$` (Samba's
/// machine accounts). Existing entries are not held to this; only new names are.
pub fn valid_name(name: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("bad name `{name}': {why}"));
    if name.is_empty() {
        return bad("empty");
    }
    if name.len() > NAME_MAX {
        return bad(&format!("longer than {NAME_MAX} characters"));
    }
    if name.starts_with('-') {
        return bad("starts with `-'");
    }
    if name.bytes().all(|b| b.is_ascii_digit()) {
        return bad("all digits");
    }
    let body = name.strip_suffix('$').unwrap_or(name);
    if let Some(c) = body.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))) {
        return bad(&format!("contains `{}'", c.escape_default()));
    }
    Ok(())
}

/// Checks a free-text field (password hash, GECOS, home, shell) can be stored: no `:`, which
/// separates fields, and no newline, which separates entries.
pub fn valid_field(what: &str, value: &str) -> Result<(), String> {
    match value.chars().find(|c| matches!(c, ':' | '\n' | '\r')) {
        Some(c) => Err(format!("{what} may not contain `{}'", c.escape_default())),
        None => Ok(()),
    }
}

/// The lowest ID in `min..=max` that `used` doesn't contain.
pub fn next_free_id(used: impl IntoIterator<Item = u32>, min: u32, max: u32) -> Option<u32> {
    let mut used: Vec<u32> = used.into_iter().filter(|id| (min..=max).contains(id)).collect();
    used.sort_unstable();
    used.dedup();
    let mut next = min;
    for id in used {
        if id != next {
            break;
        }
        next = next.checked_add(1)?;
    }
    (next <= max).then_some(next)
}

/// The next free user ID in `min..=max`.
pub fn next_uid(entries: &[Entry], min: u32, max: u32) -> Option<u32> {
    next_free_id(entries.iter().map(|e| e.uid), min, max)
}

/// The next free group ID in `min..=max`.
pub fn next_gid(groups: &[Group], min: u32, max: u32) -> Option<u32> {
    next_free_id(groups.iter().map(|g| g.gid), min, max)
}

/// The lowest ID in `min..=max` free both as a user and as a group ID: a new user's own group
/// can then share its number (`useradd -g =uid`).
pub fn next_shared_id(entries: &[Entry], groups: &[Group], min: u32, max: u32) -> Option<u32> {
    next_free_id(entries.iter().map(|e| e.uid).chain(groups.iter().map(|g| g.gid)), min, max)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    /// Almost always `*`: group passwords (`newgrp(1)`) are a relic.
    pub password: String,
    pub gid: u32,
    /// Users with this as a supplementary group. A user's primary group, from the `gid` of its
    /// `passwd(5)` entry, is usually not listed.
    pub members: Vec<String>,
}

impl Group {
    pub fn line(&self) -> String {
        format!("{}:{}:{}:{}", self.name, self.password, self.gid, self.members.join(","))
    }

    pub fn has_member(&self, user: &str) -> bool {
        self.members.iter().any(|m| m == user)
    }
}

/// Parses one `/etc/group` line.
pub fn parse_group_line(line: &str) -> Result<Group, String> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() != 4 {
        return Err(format!("expected 4 fields, found {}", f.len()));
    }
    if f[0].is_empty() {
        return Err("empty group name".into());
    }
    Ok(Group {
        name: f[0].into(),
        password: f[1].into(),
        gid: f[2].parse().map_err(|_| format!("bad gid `{}'", f[2]))?,
        members: f[3].split(',').filter(|m| !m.is_empty()).map(String::from).collect(),
    })
}

/// Parses a whole `/etc/group`, as [`parse`] does `master.passwd`.
pub fn parse_groups(text: &str) -> (Vec<Group>, Vec<(usize, String)>) {
    let (mut groups, mut errors) = (Vec::new(), Vec::new());
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_group_line(line) {
            Ok(g) => groups.push(g),
            Err(e) => errors.push((i + 1, e)),
        }
    }
    (groups, errors)
}

/// The `/etc/group` text for these groups.
pub fn group_text(groups: &[Group]) -> String {
    groups.iter().map(|g| g.line() + "\n").collect()
}

pub fn read_groups() -> io::Result<Vec<Group>> {
    Ok(parse_groups(&std::fs::read_to_string(GROUP)?).0)
}

pub fn lookup_group(name: &str) -> Option<Group> {
    read_groups().ok()?.into_iter().find(|g| g.name == name)
}

pub fn lookup_gid(gid: u32) -> Option<Group> {
    read_groups().ok()?.into_iter().find(|g| g.gid == gid)
}

/// Checks a new `/etc/group`: unique names, and names and members a line can hold. Like
/// [`validate`], duplicate IDs are allowed (`groupadd -o`).
pub fn validate_groups(groups: &[Group]) -> Result<(), String> {
    for (i, g) in groups.iter().enumerate() {
        if groups[..i].iter().any(|o| o.name == g.name) {
            return Err(format!("duplicate entry for group `{}'", g.name));
        }
        if g.name.contains(|c: char| c.is_whitespace() || matches!(c, ':' | ',')) || g.name.starts_with('-') {
            return Err(format!("bad group name `{}'", g.name));
        }
        valid_field("a group password", &g.password)?;
        if let Some(m) = g.members.iter().find(|m| m.is_empty() || m.contains(|c: char| c.is_whitespace() || matches!(c, ':' | ','))) {
            return Err(format!("group `{}': bad member name `{m}'", g.name));
        }
    }
    Ok(())
}

/// Installs `groups` as `/etc/group` (mode 0644).
pub fn install_groups(groups: &[Group]) -> io::Result<()> {
    install_groups_in("/etc", groups)
}

/// [`install_groups`] into another directory.
pub fn install_groups_in(dir: &str, groups: &[Group]) -> io::Result<()> {
    validate_groups(groups).map_err(io::Error::other)?;
    pwd::write_atomic(&format!("{dir}/group"), &group_text(groups), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUPS: &str = "# comment\nwheel:*:0:root,user\n\nuser:*:1000:\nstaff:*:20:a,,b\n";

    #[test]
    fn groups_parse_and_regenerate() {
        let (gs, errs) = parse_groups(GROUPS);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(gs.len(), 3);
        assert_eq!(gs[0].members, ["root", "user"]);
        assert!(gs[0].has_member("user") && !gs[1].has_member("user"));
        assert!(gs[1].members.is_empty());
        assert_eq!(gs[2].members, ["a", "b"]);
        assert_eq!(group_text(&gs), "wheel:*:0:root,user\nuser:*:1000:\nstaff:*:20:a,b\n");
        assert!(validate_groups(&gs).is_ok());
    }

    #[test]
    fn group_errors_name_the_line() {
        let (gs, errs) = parse_groups("ok:*:1:\nshort:*:2\nbad:*:x:\n:*:3:\n");
        assert_eq!(gs.len(), 1);
        assert_eq!(
            errs,
            [(2, "expected 4 fields, found 3".to_string()), (3, "bad gid `x'".to_string()), (4, "empty group name".to_string())]
        );
    }

    #[test]
    fn group_validation() {
        let g = |name: &str, members: &[&str]| Group { name: name.into(), password: "*".into(), gid: 5, members: members.iter().map(|m| m.to_string()).collect() };
        assert!(validate_groups(&[g("a", &[]), g("b", &[])]).is_ok(), "duplicate gids are allowed");
        assert!(validate_groups(&[g("a", &[]), g("a", &[])]).unwrap_err().contains("duplicate"));
        assert!(validate_groups(&[g("a b", &[])]).is_err());
        assert!(validate_groups(&[g("a", &["x,y"])]).is_err());
    }

    #[test]
    fn names() {
        for ok in ["user", "a", "_dhcp", "www-data", "j.doe", "host$", "x1"] {
            assert!(valid_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-r", "1000", "a b", "a:b", "a,b", "a$b", "é", &"x".repeat(NAME_MAX + 1)] {
            assert!(valid_name(bad).is_err(), "{bad}");
        }
        assert!(valid_field("GECOS", "Charlie &, Room 1").is_ok());
        assert!(valid_field("GECOS", "a:b").is_err());
        assert!(valid_field("shell", "/bin/sh\n").is_err());
    }

    #[test]
    fn id_allocation() {
        assert_eq!(next_free_id([], 1000, 60000), Some(1000));
        assert_eq!(next_free_id([0, 1000, 1001, 1003, 65534], 1000, 60000), Some(1002));
        assert_eq!(next_free_id([1001, 1000, 1001], 1000, 60000), Some(1002), "unsorted, duplicates");
        assert_eq!(next_free_id([5, 6], 5, 6), None);
        assert_eq!(next_free_id([u32::MAX], u32::MAX, u32::MAX), None);
        let (es, _) = pwd::parse("a:*:1000:1000::0:0:::\nb:*:1002:1002::0:0:::\n");
        let (gs, _) = parse_groups("a:*:1000:\nb:*:1002:\nc:*:1001:\n");
        assert_eq!(next_uid(&es, 1000, 60000), Some(1001));
        assert_eq!(next_gid(&gs, 1000, 60000), Some(1003));
        assert_eq!(next_shared_id(&es, &gs, 1000, 60000), Some(1003));
    }
}
