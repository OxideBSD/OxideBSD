//! Account records (`passwd(5)`) in the layout all three BSDs use (LOGIN.md §7.4):
//! `/etc/master.passwd`, readable only by root, holds every field,
//!
//! ```text
//! name:password:uid:gid:class:change:expire:gecos:home:shell
//! ```
//!
//! and `pwd_mkdb(8)` generates the public `/etc/passwd` from it, with the password shown as `*`
//! and the class, change and expire fields left out. `change` and `expire` are seconds since the
//! epoch; 0 means never.

use std::io;

pub const MASTER_PASSWD: &str = "/etc/master.passwd";
pub const PASSWD: &str = "/etc/passwd";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// A `crypt(3)` hash; empty for no password, or one that no password matches (`*`,
    /// `*LOCKED*...`) to disable password logins.
    pub password: String,
    pub uid: u32,
    pub gid: u32,
    /// The `login.conf(5)` class; empty means `default`.
    pub class: String,
    /// When the password must be changed, or 0.
    pub change: i64,
    /// When the account expires, or 0.
    pub expire: i64,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

impl Entry {
    pub fn master_line(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.name, self.password, self.uid, self.gid, self.class, self.change, self.expire, self.gecos, self.home, self.shell
        )
    }

    /// The `/etc/passwd` line: no password, class, change or expire.
    pub fn passwd_line(&self) -> String {
        format!("{}:*:{}:{}:{}:{}:{}", self.name, self.uid, self.gid, self.gecos, self.home, self.shell)
    }

    /// The login class to use (`default` when the field is empty).
    pub fn login_class(&self) -> &str {
        if self.class.is_empty() { "default" } else { &self.class }
    }

    /// Password logins are disabled (`*` or a `*LOCKED*` prefix, as on the BSDs).
    pub fn locked(&self) -> bool {
        self.password.starts_with('*')
    }
}

/// Parses one `master.passwd` line.
pub fn parse_line(line: &str) -> Result<Entry, String> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() != 10 {
        return Err(format!("expected 10 fields, found {}", f.len()));
    }
    if f[0].is_empty() {
        return Err("empty user name".into());
    }
    let num = |i: usize, what: &str| -> Result<i64, String> {
        if f[i].is_empty() { Ok(0) } else { f[i].parse().map_err(|_| format!("bad {what} `{}'", f[i])) }
    };
    let id = |i: usize, what: &str| -> Result<u32, String> { f[i].parse().map_err(|_| format!("bad {what} `{}'", f[i])) };
    Ok(Entry {
        name: f[0].into(),
        password: f[1].into(),
        uid: id(2, "uid")?,
        gid: id(3, "gid")?,
        class: f[4].into(),
        change: num(5, "change time")?,
        expire: num(6, "expire time")?,
        gecos: f[7].into(),
        home: f[8].into(),
        shell: f[9].into(),
    })
}

/// Parses a whole `master.passwd`: the entries, and each bad line's number and problem.
/// Blank lines and `#` comments are skipped.
pub fn parse(text: &str) -> (Vec<Entry>, Vec<(usize, String)>) {
    let (mut entries, mut errors) = (Vec::new(), Vec::new());
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Ok(e) => entries.push(e),
            Err(e) => errors.push((i + 1, e)),
        }
    }
    (entries, errors)
}

pub fn read_master() -> io::Result<Vec<Entry>> {
    Ok(parse(&std::fs::read_to_string(MASTER_PASSWD)?).0)
}

pub fn lookup(name: &str) -> Option<Entry> {
    read_master().ok()?.into_iter().find(|e| e.name == name)
}

pub fn lookup_uid(uid: u32) -> Option<Entry> {
    read_master().ok()?.into_iter().find(|e| e.uid == uid)
}

/// The generated `/etc/passwd` for these entries.
pub fn passwd_text(entries: &[Entry]) -> String {
    entries.iter().map(|e| e.passwd_line() + "\n").collect()
}

/// The `master.passwd` text for these entries.
pub fn master_text(entries: &[Entry]) -> String {
    entries.iter().map(|e| e.master_line() + "\n").collect()
}

/// Replaces `path` with `text` atomically (a temporary file renamed over it), with `mode`.
pub fn write_atomic(path: &str, text: &str, mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{path}.tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Installs `entries` as the account database: `master.passwd` (mode 0600), then the generated
/// `/etc/passwd` (0644) -- what `pwd_mkdb -p` does after an edit.
pub fn install(entries: &[Entry]) -> io::Result<()> {
    validate(entries).map_err(io::Error::other)?;
    write_atomic(MASTER_PASSWD, &master_text(entries), 0o600)?;
    write_atomic(PASSWD, &passwd_text(entries), 0o644)
}

/// Checks what `pwd_mkdb(8)` checks before installing a new `master.passwd`.
pub fn validate(entries: &[Entry]) -> Result<(), String> {
    for (i, e) in entries.iter().enumerate() {
        if entries[..i].iter().any(|o| o.name == e.name) {
            return Err(format!("duplicate entry for user `{}'", e.name));
        }
        if e.name.contains(char::is_whitespace) || e.name.starts_with('-') {
            return Err(format!("bad user name `{}'", e.name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "# comment\nroot:$6$salt$hash:0:0::0:0:Charlie &:/root:/bin/sh\n\nuser:*:1000:1000:staff:1700000000:0:User:/home/user:/bin/sh\n";

    #[test]
    fn parses_and_regenerates() {
        let (es, errs) = parse(MASTER);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].login_class(), "default");
        assert_eq!(es[1].login_class(), "staff");
        assert!(es[1].locked() && !es[0].locked());
        assert_eq!(es[1].change, 1700000000);
        assert_eq!(es[0].master_line(), "root:$6$salt$hash:0:0::0:0:Charlie &:/root:/bin/sh");
        assert_eq!(passwd_text(&es), "root:*:0:0:Charlie &:/root:/bin/sh\nuser:*:1000:1000:User:/home/user:/bin/sh\n");
    }

    #[test]
    fn errors_name_the_line() {
        let (es, errs) = parse("root:x:0:0:/:/bin/sh\nbad:x:zero:0::0:0:::\nok:x:1:1::::::/bin/sh\n");
        assert_eq!(es.len(), 1);
        assert_eq!(errs, [(1, "expected 10 fields, found 6".to_string()), (2, "bad uid `zero'".to_string())]);
    }

    #[test]
    fn validation() {
        let (es, _) = parse("a:x:1:1::0:0:::\na:x:2:2::0:0:::\n");
        assert!(validate(&es).unwrap_err().contains("duplicate"));
    }
}
