//! Login classes (`login.conf(5)`, LOGIN.md §7), the BSDs' `login_cap(3)`: the record for a
//! user's class, and the values `login(1)` applies. Numbers may be written either way the BSDs' files use, `name#n` or `name=n`,
//! with `unlimited`/`infinity`, size suffixes (`b`, `k`, `m`, `g`, `t`) and time suffixes (`s`,
//! `m`, `h`, `d`, `w`, `y`).

pub const LOGIN_CONF: &str = "/etc/login.conf";

pub struct Class {
    entry: Option<getcap::Entry>,
}

/// A value that may be unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Value(u64),
    Unlimited,
}

fn parse_scaled(s: &str, units: &[(char, u64)]) -> Option<Limit> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("unlimited") || s.eq_ignore_ascii_case("infinity") {
        return Some(Limit::Unlimited);
    }
    // A sum of terms, e.g. `1h30m`.
    let mut total: u64 = 0;
    let mut digits = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let n: u64 = digits.parse().ok()?;
        let unit = units.iter().find(|(u, _)| u.eq_ignore_ascii_case(&c))?.1;
        total = total.checked_add(n.checked_mul(unit)?)?;
        digits.clear();
    }
    if !digits.is_empty() {
        total = total.checked_add(digits.parse().ok()?)?;
    }
    Some(Limit::Value(total))
}

pub fn parse_size(s: &str) -> Option<Limit> {
    parse_scaled(s, &[('b', 512), ('k', 1 << 10), ('m', 1 << 20), ('g', 1 << 30), ('t', 1 << 40)])
}

pub fn parse_time(s: &str) -> Option<Limit> {
    parse_scaled(s, &[('s', 1), ('m', 60), ('h', 3600), ('d', 86400), ('w', 604800), ('y', 31536000)])
}

impl Class {
    /// The class record, or `default` if the class has none.
    pub fn load(name: &str) -> Class {
        let db = getcap::Db::read(LOGIN_CONF).unwrap_or_default();
        Class { entry: db.get(name).or_else(|| db.get("default")) }
    }

    pub fn from_text(text: &str, name: &str) -> Class {
        let db = getcap::Db::parse(text);
        Class { entry: db.get(name).or_else(|| db.get("default")) }
    }

    pub fn string(&self, cap: &str) -> Option<&str> {
        self.entry.as_ref()?.string(cap)
    }

    pub fn flag(&self, cap: &str) -> bool {
        self.entry.as_ref().is_some_and(|e| e.flag(cap))
    }

    fn raw_num(&self, cap: &str, parse: fn(&str) -> Option<Limit>) -> Option<Limit> {
        let e = self.entry.as_ref()?;
        match e.num(cap) {
            Some(n) => Some(Limit::Value(n.max(0) as u64)),
            None => parse(e.string(cap)?),
        }
    }

    pub fn number(&self, cap: &str, default: u64) -> u64 {
        match self.raw_num(cap, parse_size) {
            Some(Limit::Value(v)) => v,
            _ => default,
        }
    }

    pub fn size(&self, cap: &str) -> Option<Limit> {
        self.raw_num(cap, parse_size)
    }

    pub fn time(&self, cap: &str) -> Option<Limit> {
        self.raw_num(cap, parse_time)
    }

    /// `umask`: octal, `umask=022` or `umask#022`.
    pub fn umask(&self) -> Option<u32> {
        let e = self.entry.as_ref()?;
        match (e.string("umask"), e.num("umask")) {
            (Some(s), _) => u32::from_str_radix(s.trim_start_matches('0'), 8).ok().or(Some(0)),
            // `#022` already parsed as octal by getcap.
            (None, Some(n)) => Some(n as u32),
            _ => None,
        }
    }

    /// `setenv`: `NAME=value,NAME=value`, with `\,` for a literal comma.
    pub fn setenv(&self) -> Vec<(String, String)> {
        let Some(s) = self.string("setenv") else { return Vec::new() };
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut chars = s.chars().peekable();
        let mut items = Vec::new();
        while let Some(c) = chars.next() {
            match c {
                '\\' if chars.peek() == Some(&',') => cur.push(chars.next().unwrap()),
                ',' => items.push(std::mem::take(&mut cur)),
                c => cur.push(c),
            }
        }
        items.push(cur);
        for item in items {
            if let Some((k, v)) = item.trim().split_once('=') {
                out.push((k.to_string(), v.to_string()));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "default:\\\n\t:path=/sbin /bin /usr/sbin /usr/bin:\\\n\t:umask=022:\\\n\t:datasize=64M:cputime=1h30m:openfiles=unlimited:\\\n\t:setenv=MAIL=/var/mail/$,BLOCKSIZE=K,A=b\\\\,c:\\\n\t:login-retries#10:login-backoff=3:\n\nroot:\\\n\t:umask#077:tc=default:\n";

    #[test]
    fn values() {
        let c = Class::from_text(CONF, "default");
        assert_eq!(c.size("datasize"), Some(Limit::Value(64 << 20)));
        assert_eq!(c.time("cputime"), Some(Limit::Value(5400)));
        assert_eq!(c.size("openfiles"), Some(Limit::Unlimited));
        assert_eq!(c.umask(), Some(0o022));
        assert_eq!(c.number("login-retries", 1), 10);
        assert_eq!(c.number("login-backoff", 1), 3);
        assert_eq!(c.number("login-timeout", 300), 300);
        assert_eq!(c.string("path"), Some("/sbin /bin /usr/sbin /usr/bin"));
        let env = c.setenv();
        assert_eq!(env[0], ("MAIL".into(), "/var/mail/$".into()));
        assert_eq!(env[2], ("A".into(), "b,c".into()));
    }

    #[test]
    fn classes_inherit_and_fall_back() {
        assert_eq!(Class::from_text(CONF, "root").umask(), Some(0o077));
        assert_eq!(Class::from_text(CONF, "root").size("datasize"), Some(Limit::Value(64 << 20)));
        assert_eq!(Class::from_text(CONF, "nosuch").umask(), Some(0o022));
    }
}
