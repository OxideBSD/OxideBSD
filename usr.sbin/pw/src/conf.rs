//! New accounts' defaults, from `usermgmt.conf(5)` (NetBSD's and OpenBSD's file; pw reads it too,
//! in place of FreeBSD's `pw.conf`): `key value` lines, `#` comments.

use crate::{EX_CANTCREAT, Result, err};

pub const FILE: &str = "usermgmt.conf";

#[derive(Clone, Debug, PartialEq)]
pub struct Defaults {
    /// Where new homes go: `base_dir/name`.
    pub base_dir: String,
    pub class: String,
    /// The primary group: a name, a gid, or `=uid` for a new group of the user's own.
    pub group: String,
    /// An expiry time, in any form `args::time` takes; empty for none.
    pub expire: String,
    /// The `crypt(3)` hash new accounts get; `*` (locked) until a password is set.
    pub password: String,
    pub shell: String,
    pub skel_dir: String,
    /// Where new user and group IDs are taken from.
    pub range: (u32, u32),
    /// The mode of a new home directory.
    pub homeperm: u32,
    /// Accepted for NetBSD's and OpenBSD's files; OxideBSD's `master.passwd` has no inactive
    /// field, so nothing uses it.
    pub inactive: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            base_dir: "/home".into(),
            class: String::new(),
            group: "=uid".into(),
            expire: String::new(),
            password: "*".into(),
            shell: "/bin/sh".into(),
            skel_dir: "/etc/skel".into(),
            range: (1000, 60000),
            homeperm: 0o755,
            inactive: String::new(),
        }
    }
}

impl Defaults {
    /// Reads `dir/usermgmt.conf`, if there is one. A bad line is warned about and skipped.
    pub fn load(dir: &str) -> Defaults {
        let path = format!("{dir}/{FILE}");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let (d, errors) = Defaults::parse(&text);
        for (line, e) in errors {
            crate::warn(&format!("{path}: line {line}: {e}"));
        }
        d
    }

    pub fn parse(text: &str) -> (Defaults, Vec<(usize, String)>) {
        let (mut d, mut errors) = (Defaults::default(), Vec::new());
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once(char::is_whitespace).map_or((line, ""), |(k, v)| (k, v.trim()));
            if let Err(e) = d.set(key, value) {
                errors.push((i + 1, e.msg));
            }
        }
        (d, errors)
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let v = value.to_string();
        match key {
            "base_dir" => self.base_dir = v,
            "class" => self.class = v,
            "group" => self.group = v,
            "expire" => {
                crate::args::time(value, 0)?;
                self.expire = v
            }
            "password" => {
                grp::valid_field("a password", value).or_else(|e| err(crate::EX_DATAERR, e))?;
                self.password = v
            }
            "shell" => self.shell = v,
            "skel_dir" => self.skel_dir = v,
            "range" => self.range = crate::args::range(value)?,
            "homeperm" => self.homeperm = crate::args::mode(value)?,
            "inactive" => self.inactive = v,
            // NetBSD's: keep the home's files on usermod -m (we always move them).
            "preserve" => {}
            _ => return err(crate::EX_DATAERR, format!("unknown key `{key}'")),
        }
        Ok(())
    }

    /// The file's text (`useradd -D`'s listing).
    pub fn text(&self) -> String {
        let mut s = String::new();
        let mut kv = |k: &str, v: &str| s += &format!("{k:<12}{v}\n");
        kv("group", &self.group);
        kv("base_dir", &self.base_dir);
        kv("skel_dir", &self.skel_dir);
        kv("shell", &self.shell);
        kv("class", &self.class);
        kv("inactive", &self.inactive);
        kv("expire", &self.expire);
        kv("password", &self.password);
        kv("homeperm", &format!("0{:o}", self.homeperm));
        kv("range", &format!("{}..{}", self.range.0, self.range.1));
        s
    }

    /// Writes `dir/usermgmt.conf` (`useradd -D` with options).
    pub fn save(&self, dir: &str) -> Result<()> {
        let path = format!("{dir}/{FILE}");
        let text = format!("# Defaults for useradd(8) and pw(8); see usermgmt.conf(5).\n{}", self.text());
        pwd::write_atomic(&path, &text, 0o644).or_else(|e| err(EX_CANTCREAT, format!("{path}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let (d, errs) = Defaults::parse("# x\nbase_dir /u\nshell\t/bin/ksh # comment\nrange 2000..3000\nhomeperm 0700\nbogus 1\nrange 9\n");
        assert_eq!(d.base_dir, "/u");
        assert_eq!(d.shell, "/bin/ksh");
        assert_eq!(d.range, (2000, 3000));
        assert_eq!(d.homeperm, 0o700);
        assert_eq!(d.group, "=uid");
        assert_eq!(errs.iter().map(|e| e.0).collect::<Vec<_>>(), [6, 7]);
        assert_eq!(Defaults::parse(&d.text()).0, d, "text round-trips");
    }
}
