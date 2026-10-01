//! Login classes (`login.conf(5)`, LOGIN.md §7), the BSDs' `login_cap(3)`: the record for a
//! user's class, and [`setusercontext`], which applies it for `login(1)` and `cron(8)`. Numbers may be written either way the BSDs' files use, `name#n` or `name=n`,
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

impl Class {
    /// `path`, as a `PATH` value: the words joined with `:`, a leading `~` in each standing for
    /// the home directory, as in the BSDs' `login_cap`.
    pub fn path(&self, home: &str) -> Option<String> {
        let words = self.string("path")?.split_whitespace().map(|d| match d.strip_prefix('~') {
            Some(rest) => format!("{home}{rest}"),
            None => d.to_string(),
        });
        Some(words.collect::<Vec<_>>().join(":"))
    }

    /// The environment the class sets (the BSDs' `LOGIN_SETENV`): `lang`, `charset` and
    /// `timezone` as `LANG`, `MM_CHARSET` and `TZ`, then `setenv`, in whose values `~` and `$`
    /// stand for the home directory and the user name.
    ///
    /// Unlike the BSDs' `setusercontext`, which sets these in the calling process, this returns
    /// them, for a caller building a `Command`'s environment.
    pub fn environment(&self, user: &str, home: &str) -> Vec<(String, String)> {
        let mut env = Vec::new();
        for (cap, var) in [("lang", "LANG"), ("charset", "MM_CHARSET"), ("timezone", "TZ")] {
            if let Some(v) = self.string(cap) {
                env.push((var.to_string(), v.to_string()));
            }
        }
        for (k, v) in self.setenv() {
            env.push((k, v.replace('~', home).replace('$', user)));
        }
        env
    }
}

/// `setusercontext(3)`'s flags, with FreeBSD's values. `LOGIN_SETPATH` and `LOGIN_SETENV` are
/// accepted and ignored: see [`Class::path`] and [`Class::environment`].
pub const LOGIN_SETGROUP: u32 = 0x0001;
pub const LOGIN_SETLOGIN: u32 = 0x0002;
pub const LOGIN_SETPATH: u32 = 0x0004;
pub const LOGIN_SETPRIORITY: u32 = 0x0008;
pub const LOGIN_SETRESOURCES: u32 = 0x0010;
pub const LOGIN_SETUMASK: u32 = 0x0020;
pub const LOGIN_SETUSER: u32 = 0x0040;
pub const LOGIN_SETENV: u32 = 0x0080;
pub const LOGIN_SETALL: u32 = 0x7fff;

/// The resource limits a class sets, and the `rlimit` each is.
const RESOURCES: [(libc::c_int, &str, bool); 10] = [
    (libc::RLIMIT_CPU as libc::c_int, "cputime", true),
    (libc::RLIMIT_FSIZE as libc::c_int, "filesize", false),
    (libc::RLIMIT_DATA as libc::c_int, "datasize", false),
    (libc::RLIMIT_STACK as libc::c_int, "stacksize", false),
    (libc::RLIMIT_CORE as libc::c_int, "coredumpsize", false),
    (libc::RLIMIT_RSS as libc::c_int, "memoryuse", false),
    (libc::RLIMIT_MEMLOCK as libc::c_int, "memorylocked", false),
    (libc::RLIMIT_NPROC as libc::c_int, "maxproc", false),
    (libc::RLIMIT_NOFILE as libc::c_int, "openfiles", false),
    (libc::RLIMIT_AS as libc::c_int, "vmemoryuse", false),
];

/// Sets one limit from `cap` (both), `cap-cur` and `cap-max`, leaving what the class doesn't say.
fn set_limit(class: &Class, resource: libc::c_int, cap: &str, time: bool) {
    let get = |name: &str| if time { class.time(name) } else { class.size(name) };
    let value = |l: Limit| match l {
        Limit::Unlimited => libc::RLIM_INFINITY,
        Limit::Value(v) => v as libc::rlim_t,
    };
    let (both, cur, max) = (get(cap), get(&format!("{cap}-cur")), get(&format!("{cap}-max")));
    if both.is_none() && cur.is_none() && max.is_none() {
        return;
    }
    // SAFETY: getrlimit/setrlimit with a local struct.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(resource as _, &mut rl) };
    if let Some(v) = both {
        rl.rlim_cur = value(v);
        rl.rlim_max = value(v);
    }
    if let Some(v) = cur {
        rl.rlim_cur = value(v);
    }
    if let Some(v) = max {
        rl.rlim_max = value(v);
    }
    unsafe { libc::setrlimit(resource as _, &rl) };
}

/// The BSDs' `setusercontext(3)`: applies what `flags` asks for of `class` to this process, and
/// becomes user `name` (`uid`, `gid`), in the BSDs' order: resource limits, priority, umask,
/// groups, then the user ID, after which the rest can no longer be changed. Limits, priority and
/// umask are best effort, as in the BSDs; failing to change groups or user is an error.
pub fn setusercontext(class: &Class, name: &str, uid: u32, gid: u32, flags: u32) -> std::io::Result<()> {
    if flags & LOGIN_SETRESOURCES != 0 {
        for (resource, cap, time) in RESOURCES {
            set_limit(class, resource, cap, time);
        }
    }
    if flags & LOGIN_SETPRIORITY != 0
        && let Some(Limit::Value(p)) = class.size("priority")
    {
        // SAFETY: setpriority(2) for this process.
        unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, p as libc::c_int) };
    }
    if flags & LOGIN_SETUMASK != 0
        && let Some(mask) = class.umask()
    {
        // SAFETY: umask(2) can't fail.
        unsafe { libc::umask(mask as libc::mode_t) };
    }
    let err = std::io::Error::last_os_error;
    if flags & LOGIN_SETGROUP != 0 {
        let cname = std::ffi::CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // SAFETY: initgroups/setgid with a valid name and ids.
        if unsafe { libc::initgroups(cname.as_ptr(), gid as _) } != 0 || unsafe { libc::setgid(gid) } != 0 {
            return Err(err());
        }
    }
    if flags & LOGIN_SETUSER != 0 && unsafe { libc::setuid(uid) } != 0 {
        return Err(err());
    }
    Ok(())
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

    #[test]
    fn path_and_environment() {
        let conf = "default:\\\n\t:path=/bin ~/bin /usr/bin:\\\n\t:lang=en_US.UTF-8:timezone=UTC:\\\n\t:setenv=MAIL=/var/mail/$,DIR=~/x:\n";
        let c = Class::from_text(conf, "default");
        assert_eq!(c.path("/home/u").as_deref(), Some("/bin:/home/u/bin:/usr/bin"));
        let env = c.environment("u", "/home/u");
        let env: Vec<(&str, &str)> = env.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        assert_eq!(env, [("LANG", "en_US.UTF-8"), ("TZ", "UTC"), ("MAIL", "/var/mail/u"), ("DIR", "/home/u/x")]);
        assert_eq!(Class::from_text("", "default").path("/"), None);
    }
}
