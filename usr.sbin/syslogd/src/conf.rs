//! `syslog.conf(5)`, in FreeBSD's format (`SYSLOG.md` §7): rules of a selector and an action,
//! program and host blocks, property filters, `include`, and NetBSD's `name=value` options.
//!
//! ```text
//! *.err;kern.warning;auth.notice          /dev/console
//! !sshd
//! *.*                                     /var/log/sshd.log
//! !*
//! :msg, contains, "fail"
//! *.*                                     |/usr/local/bin/alert
//! ```

use std::path::{Path, PathBuf};

use syslog::pri::{Facility, Level};

/// Levels a rule takes, per facility, as a bit per level (bit `n` is level `n`).
pub type Masks = [u8; Facility::COUNT];

/// Where a rule sends what it selects (`SYSLOG.md` §7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// `/path` (synchronized after each line) or `-/path`. A terminal path, such as
    /// `/dev/console`, is written as a terminal; which it is is found when it's opened.
    File { path: PathBuf, sync: bool },
    /// `|command`.
    Pipe(String),
    /// `@host[:port]`, over UDP.
    Forward { host: String, port: u16 },
    /// `user1,user2`.
    Users(Vec<String>),
    /// `*`.
    Wall,
}

/// A `!prog` / `+host` block's condition: names, and whether a match excludes (`!-prog`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameFilter {
    pub names: Vec<String>,
    pub negate: bool,
}

impl NameFilter {
    /// Whether `name` passes. An empty filter passes everything.
    pub fn allows(&self, name: Option<&str>) -> bool {
        if self.names.is_empty() {
            return true;
        }
        let hit = name.is_some_and(|n| self.names.iter().any(|f| f == n));
        hit != self.negate
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Property {
    Msg,
    ProgramName,
    HostName,
    Source,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operator {
    Contains,
    IsEqual,
    StartsWith,
    /// POSIX basic (`regex`) or extended (`ereg`) regular expression.
    Regex { extended: bool },
}

/// `:property, [!][icase_]operator, "value"` (FreeBSD's property-based filter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropFilter {
    pub property: Property,
    pub operator: Operator,
    pub negate: bool,
    pub icase: bool,
    pub value: String,
}

/// One rule: the blocks in force where it appeared, its selector and its action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub program: NameFilter,
    pub host: NameFilter,
    pub prop: Option<PropFilter>,
    pub masks: Masks,
    pub target: Target,
    /// Where it came from, for diagnostics.
    pub origin: String,
}

/// A parsed configuration: the rules in order, the global options, and every problem found (the
/// rest of the file still applies, `SYSLOG.md` §6.7).
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub options: Vec<(String, String)>,
    pub errors: Vec<String>,
}

/// Options this syslogd knows. Those of TCP and TLS (`SYSLOG.md` §8.3-8.4) are accepted and
/// reported as not supported yet, not as unknown.
const LATER_OPTIONS: &[&str] = &[
    "tcp_server",
    "tcp_bindhost",
    "tcp_bindport",
    "tls_server",
    "tls_bindhost",
    "tls_bindport",
    "tls_keyfile",
    "tls_certfile",
    "tls_ca",
    "tls_cadir",
    "tls_verify",
    "tls_allow_fingerprints",
    "tls_allow_clientcerts",
    "tls_gen_cert",
];

/// The configuration used when the file can't be read (`SYSLOG.md` §6.7).
pub fn fallback() -> Config {
    let mut config = Config::default();
    parse_str(&mut config, "*.err\t/dev/console\n*.emerg\t*\n", "(built in)", &mut Blocks::default(), 0);
    config
}

/// Reads `path` and what it includes. A missing file is an error in `errors`.
pub fn load(path: &Path) -> Config {
    let mut config = Config::default();
    let mut blocks = Blocks::default();
    match std::fs::read_to_string(path) {
        Ok(text) => parse_str(&mut config, &text, &path.display().to_string(), &mut blocks, 0),
        Err(e) => config.errors.push(format!("{}: {e}", path.display())),
    }
    config
}

/// Parses configuration text.
#[cfg(test)]
pub fn parse(text: &str) -> Config {
    let mut config = Config::default();
    parse_str(&mut config, text, "-", &mut Blocks::default(), 0);
    config
}

#[derive(Clone, Default)]
struct Blocks {
    program: NameFilter,
    host: NameFilter,
    prop: Option<PropFilter>,
}

fn parse_str(config: &mut Config, text: &str, name: &str, blocks: &mut Blocks, depth: u32) {
    for (i, raw) in text.lines().enumerate() {
        let origin = format!("{name}:{}", i + 1);
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // `#!prog` and `#+host` are old spellings of the block lines; any other `#` is a comment.
        // (FreeBSD also takes `#-host`, which turns a `#-----` banner into a block: not here.)
        let line = match line.strip_prefix('#') {
            Some(rest) if rest.starts_with('!') || rest.starts_with('+') => rest,
            Some(_) => continue,
            None => line,
        };
        let err = |config: &mut Config, what: &str| config.errors.push(format!("{origin}: {what}"));
        match line.as_bytes()[0] {
            b'!' => {
                blocks.program = name_block(&line[1..]);
                continue;
            }
            b'+' | b'-' if !line.starts_with("-/") => {
                let mut f = name_block(&line[1..]);
                f.negate = line.starts_with('-');
                if f.names.is_empty() {
                    f.negate = false;
                }
                blocks.host = f;
                continue;
            }
            b':' => {
                match parse_prop(&line[1..]) {
                    Ok(p) => blocks.prop = p,
                    Err(e) => err(config, &e),
                }
                continue;
            }
            _ => {}
        }
        let (first, rest) = split_word(line);
        if first == "include" {
            if depth >= 8 {
                err(config, "includes nested too deeply");
                continue;
            }
            include(config, Path::new(rest.trim()), blocks, depth + 1);
            continue;
        }
        if let Some((key, value)) = option_line(line) {
            if !LATER_OPTIONS.contains(&key) {
                err(config, &format!("unknown option {key}"));
            } else {
                err(config, &format!("option {key} is not supported yet"));
            }
            config.options.push((key.to_string(), value.to_string()));
            continue;
        }
        let action = rest.trim();
        if action.is_empty() {
            err(config, "no action");
            continue;
        }
        let masks = match parse_selector(first) {
            Ok(m) => m,
            Err(e) => {
                err(config, &e);
                continue;
            }
        };
        let target = match parse_action(action) {
            Ok(t) => t,
            Err(e) => {
                err(config, &e);
                continue;
            }
        };
        config.rules.push(Rule {
            program: blocks.program.clone(),
            host: blocks.host.clone(),
            prop: blocks.prop.clone(),
            masks,
            target,
            origin,
        });
    }
}

/// `include path`: a file, or a directory's `*.conf` files in name order. A missing path is
/// ignored: the default configuration includes directories that may not exist.
fn include(config: &mut Config, path: &Path, blocks: &mut Blocks, depth: u32) {
    let Ok(meta) = std::fs::metadata(path) else { return };
    let files: Vec<PathBuf> = if meta.is_dir() {
        let mut v: Vec<PathBuf> = std::fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "conf") && p.is_file())
            .collect();
        v.sort();
        v
    } else {
        vec![path.to_path_buf()]
    };
    for file in files {
        match std::fs::read_to_string(&file) {
            Ok(text) => parse_str(config, &text, &file.display().to_string(), blocks, depth),
            Err(e) => config.errors.push(format!("{}: {e}", file.display())),
        }
    }
}

/// The first word, and what follows it.
fn split_word(line: &str) -> (&str, &str) {
    match line.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (&line[..i], &line[i..]),
        None => (line, ""),
    }
}

/// `name=value`, the name a plain identifier (so a selector like `*.=info` never matches).
fn option_line(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    if key.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((key, value.trim().trim_matches('"')))
}

/// The names of a `!prog` or `+host` line; `*` (or nothing) ends the block. `!-prog` excludes.
fn name_block(spec: &str) -> NameFilter {
    let spec = spec.trim();
    let (negate, spec) = match spec.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, spec),
    };
    if spec.is_empty() || spec == "*" {
        return NameFilter::default();
    }
    NameFilter { names: spec.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(), negate }
}

/// `property, [!][icase_]operator, "value"`; `*` ends the block.
fn parse_prop(spec: &str) -> Result<Option<PropFilter>, String> {
    let spec = spec.trim();
    if spec == "*" || spec.is_empty() {
        return Ok(None);
    }
    let mut parts = spec.splitn(3, ',');
    let prop = parts.next().unwrap_or("").trim();
    let op = parts.next().ok_or("property filter without an operator")?.trim();
    let value = parts.next().ok_or("property filter without a value")?.trim();
    let property = match prop {
        "msg" => Property::Msg,
        "programname" => Property::ProgramName,
        "hostname" => Property::HostName,
        "source" => Property::Source,
        _ => return Err(format!("unknown property {prop}")),
    };
    let (negate, op) = match op.strip_prefix('!') {
        Some(o) => (true, o),
        None => (false, op),
    };
    let (icase, op) = match op.strip_prefix("icase_") {
        Some(o) => (true, o),
        None => (false, op),
    };
    let operator = match op {
        "contains" => Operator::Contains,
        "isequal" => Operator::IsEqual,
        "startswith" => Operator::StartsWith,
        "regex" => Operator::Regex { extended: false },
        "ereg" => Operator::Regex { extended: true },
        _ => return Err(format!("unknown operator {op}")),
    };
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or("property filter value must be quoted")?;
    // `\"` and `\\` inside the quotes.
    let mut unescaped = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                unescaped.push(n);
            }
        } else {
            unescaped.push(c);
        }
    }
    Ok(Some(PropFilter { property, operator, negate, icase, value: unescaped }))
}

/// A selector: `facility[,facility...].level` terms joined by `;`. Terms apply in order, each
/// replacing what earlier ones said about the facilities it names. `*` names every facility but
/// `mark`, which must be named (as in the BSDs).
pub fn parse_selector(spec: &str) -> Result<Masks, String> {
    let mut masks = [0u8; Facility::COUNT];
    for term in spec.split(';') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        let (facs, level) = term.rsplit_once('.').ok_or_else(|| format!("selector {term} has no level"))?;
        let mask = level_mask(level)?;
        for fac in facs.split(',') {
            let fac = fac.trim();
            if fac == "*" {
                for (i, m) in masks.iter_mut().enumerate() {
                    if i != Facility::MARK.0 as usize {
                        *m = mask;
                    }
                }
            } else {
                let f = Facility::from_name(fac).ok_or_else(|| format!("unknown facility {fac}"))?;
                masks[f.0 as usize] = mask;
            }
        }
    }
    Ok(masks)
}

/// The levels a level field selects, as a bit mask. Severity rises as the number falls, so
/// `warning` (`>=warning`) is levels 0-4.
fn level_mask(spec: &str) -> Result<u8, String> {
    match spec {
        "*" => return Ok(0xff),
        "none" => return Ok(0),
        _ => {}
    }
    let (negate, rest) = match spec.strip_prefix('!') {
        Some(r) => (true, r),
        None => (false, spec),
    };
    let ops = rest.bytes().take_while(|b| b"<=>".contains(b)).count();
    let (op, name) = rest.split_at(ops);
    let lvl = if name == "*" {
        None
    } else {
        Some(Level::from_name(name).ok_or_else(|| format!("unknown level {name}"))?.0)
    };
    let mut mask = 0u8;
    for n in 0..8u8 {
        let take = match lvl {
            None => true,
            Some(l) => match op {
                "" | ">=" | "=>" => n <= l,
                ">" => n < l,
                "<" => n > l,
                "<=" | "=<" => n >= l,
                "=" => n == l,
                "<>" | "><" => n != l,
                _ => return Err(format!("bad comparison {op}")),
            },
        };
        if take {
            mask |= 1 << n;
        }
    }
    Ok(if negate { !mask } else { mask })
}

fn parse_action(action: &str) -> Result<Target, String> {
    if let Some(cmd) = action.strip_prefix('|') {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return Err("empty pipe command".into());
        }
        return Ok(Target::Pipe(cmd.to_string()));
    }
    if let Some(path) = action.strip_prefix("-/") {
        return Ok(Target::File { path: PathBuf::from(format!("/{path}")), sync: false });
    }
    if action.starts_with('/') {
        return Ok(Target::File { path: PathBuf::from(action), sync: true });
    }
    if action.starts_with("@@") || action.starts_with("@[") {
        return Err(format!("{action}: TCP and TLS forwarding are not supported yet"));
    }
    if let Some(dest) = action.strip_prefix('@') {
        let (host, port) = match dest.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| format!("bad port in {action}"))?),
            None => (dest, syslog::SYSLOG_PORT),
        };
        if host.is_empty() {
            return Err(format!("no host in {action}"));
        }
        return Ok(Target::Forward { host: host.to_string(), port });
    }
    if action == "*" {
        return Ok(Target::Wall);
    }
    let users: Vec<String> = action.split(',').map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
    if users.is_empty() || users.iter().any(|u| u.contains(char::is_whitespace)) {
        return Err(format!("bad action {action}"));
    }
    Ok(Target::Users(users))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fac(name: &str) -> usize {
        Facility::from_name(name).unwrap().0 as usize
    }

    #[test]
    fn default_config() {
        let text = include_str!("../../../etc/syslog.conf");
        let c = parse(text);
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        assert_eq!(c.rules.len(), 7);
        // *.err;kern.warning;auth.notice;mail.crit /dev/console
        let r = &c.rules[0];
        assert_eq!(r.target, Target::File { path: "/dev/console".into(), sync: true });
        assert_eq!(r.masks[fac("user")], 0b0000_1111);
        assert_eq!(r.masks[fac("kern")], 0b0001_1111);
        assert_eq!(r.masks[fac("auth")], 0b0011_1111);
        assert_eq!(r.masks[fac("mail")], 0b0000_0111);
        assert_eq!(r.masks[fac("mark")], 0);
        // authpriv.none
        assert_eq!(c.rules[1].masks[fac("authpriv")], 0);
        assert_eq!(c.rules[1].masks[fac("kern")], 0xff);
        assert_eq!(c.rules[6].target, Target::Wall);
        assert_eq!(c.rules[6].masks[fac("daemon")], 1);
    }

    #[test]
    fn comparisons() {
        assert_eq!(level_mask("=info").unwrap(), 1 << 6);
        assert_eq!(level_mask("!=info").unwrap(), !(1 << 6));
        assert_eq!(level_mask(">err").unwrap(), 0b0000_0111);
        assert_eq!(level_mask("<err").unwrap(), 0b1111_0000);
        assert_eq!(level_mask("<=err").unwrap(), 0b1111_1000);
        assert_eq!(level_mask("!err").unwrap(), 0b1111_0000);
        assert_eq!(level_mask("debug").unwrap(), 0xff);
        assert!(level_mask("loud").is_err());
        let m = parse_selector("mail,news.info;*.none").unwrap();
        assert!(m.iter().all(|&x| x == 0));
        let m = parse_selector("mark.info;kern.*").unwrap();
        assert_eq!(m[fac("mark")], 0b0111_1111);
        assert_eq!(m[fac("kern")], 0xff);
        assert!(parse_selector("bogus.info").is_err());
        assert!(parse_selector("kern").is_err());
    }

    #[test]
    fn actions() {
        assert_eq!(parse_action("-/var/log/x").unwrap(), Target::File { path: "/var/log/x".into(), sync: false });
        assert_eq!(parse_action("|exec cat >> /tmp/o").unwrap(), Target::Pipe("exec cat >> /tmp/o".into()));
        assert_eq!(parse_action("@loghost").unwrap(), Target::Forward { host: "loghost".into(), port: 514 });
        assert_eq!(parse_action("@10.0.2.2:5140").unwrap(), Target::Forward { host: "10.0.2.2".into(), port: 5140 });
        assert_eq!(parse_action("root,operator").unwrap(), Target::Users(vec!["root".into(), "operator".into()]));
        assert!(parse_action("@@loghost").is_err());
        assert!(parse_action("@[loghost]:6514").is_err());
    }

    #[test]
    fn blocks() {
        let c = parse(
            "!sshd,ftpd\n*.*\t/a\n#!-cron\n#-----\n*.*\t/b\n!*\n+alpha\n*.*\t/c\n-alpha\n*.*\t/d\n+*\n\
             :msg, !icase_contains, \"Fail \\\"x\\\"\"\n*.*\t/e\n:*\n*.*\t/f\n",
        );
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        let r = &c.rules;
        assert!(r[0].program.allows(Some("sshd")) && !r[0].program.allows(Some("cron")) && !r[0].program.allows(None));
        assert!(!r[1].program.allows(Some("cron")) && r[1].program.allows(Some("sshd")) && r[1].program.allows(None));
        assert!(r[2].program.allows(Some("cron")));
        assert!(r[2].host.allows(Some("alpha")) && !r[2].host.allows(Some("beta")));
        assert!(!r[3].host.allows(Some("alpha")) && r[3].host.allows(Some("beta")));
        let p = r[4].prop.as_ref().unwrap();
        assert_eq!((p.property, p.operator, p.negate, p.icase), (Property::Msg, Operator::Contains, true, true));
        assert_eq!(p.value, "Fail \"x\"");
        assert!(r[4].host.names.is_empty());
        assert!(r[5].prop.is_none());
    }

    #[test]
    fn options_and_errors() {
        let c = parse("tcp_server=on\nfoo=bar\n*.=info\t/x\nkern.bogus /y\n*.* \n*.*\t@@h\n");
        assert_eq!(c.options, vec![("tcp_server".into(), "on".into()), ("foo".into(), "bar".into())]);
        assert_eq!(c.rules.len(), 1);
        assert_eq!(c.rules[0].masks[fac("user")], 1 << 6);
        assert_eq!(c.errors.len(), 5, "{:?}", c.errors);
        assert!(c.errors[0].contains("not supported yet"));
        assert!(c.errors[1].contains("unknown option foo"));
    }

    #[test]
    fn includes() {
        let dir = std::env::temp_dir().join(format!("syslogd-conf-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("d/b.conf"), "*.*\t/b\n").unwrap();
        std::fs::write(dir.join("d/a.conf"), "*.*\t/a\n").unwrap();
        std::fs::write(dir.join("d/skip.txt"), "*.*\t/skip\n").unwrap();
        std::fs::write(dir.join("main"), format!("include {}\ninclude /nonexistent\n*.*\t/z\n", dir.join("d").display())).unwrap();
        let c = load(&dir.join("main"));
        let paths: Vec<_> = c
            .rules
            .iter()
            .map(|r| match &r.target {
                Target::File { path, .. } => path.display().to_string(),
                _ => String::new(),
            })
            .collect();
        assert_eq!(paths, ["/a", "/b", "/z"]);
        assert!(c.errors.is_empty(), "{:?}", c.errors);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
