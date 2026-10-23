//! The configuration (OxideBSD-doc `DEVD.md` §5.2-5.3): shell scripts sourced into one shell,
//! whose `on` built-in adds the rules events are matched against.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use libsh::pattern::{self, PatChar};
use libsh::Shell;

use crate::event::{Event, is_field_name};

/// `NAME=PATTERN`, or with `negate`, `NAME!=PATTERN`.
#[derive(Debug)]
struct Cond {
    name: String,
    pattern: Vec<PatChar>,
    negate: bool,
}

#[derive(Debug)]
pub struct Rule {
    verb: Vec<PatChar>,
    class: Vec<PatChar>,
    /// Shell text, run as `eval` runs it.
    pub handler: String,
    conds: Vec<Cond>,
    /// The `on` command's words, for messages.
    pub text: String,
}

/// A glob as `case` reads an expanded word: a backslash quotes the character after it.
fn glob(s: &str) -> Vec<PatChar> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(PatChar { c: chars.next().unwrap_or('\\'), quoted: true }),
            c => out.push(PatChar { c, quoted: false }),
        }
    }
    out
}

impl Rule {
    /// Makes the rule `on` adds, from its arguments after `on` itself.
    fn new(args: &[String]) -> Result<Rule, String> {
        let [verb, class, handler, conds @ ..] = args else {
            return Err("usage: on verb class handler [name=pattern | name!=pattern ...]".into());
        };
        let conds = conds
            .iter()
            .map(|c| {
                let (name, pattern) = c.split_once('=').ok_or_else(|| format!("{c}: not name=pattern"))?;
                let (name, negate) = match name.strip_suffix('!') {
                    Some(n) => (n, true),
                    None => (name, false),
                };
                if !is_field_name(name) {
                    return Err(format!("{c}: `{name}` isn't a field's name"));
                }
                Ok(Cond { name: name.to_string(), pattern: glob(pattern), negate })
            })
            .collect::<Result<_, String>>()?;
        Ok(Rule { verb: glob(verb), class: glob(class), handler: handler.clone(), conds, text: args.join(" ") })
    }

    pub fn matches(&self, e: &Event) -> bool {
        pattern::matches(&self.verb, &e.verb)
            && pattern::matches(&self.class, &e.class)
            && self.conds.iter().all(|c| {
                let hit = e.get(&c.name).is_some_and(|v| pattern::matches(&c.pattern, v));
                hit != c.negate
            })
    }
}

/// The loaded configuration: the shell its files ran in, which runs the handlers, and its rules.
pub struct Config {
    pub shell: Shell,
    pub rules: Vec<Rule>,
}

/// The files §5.3 lists, in order: `/etc/devd.conf`, then `*.conf` in each directory, sorted.
pub fn default_files() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/devd.conf")];
    for dir in ["/etc/devd", "/usr/local/etc/devd"] {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        let mut confs: Vec<PathBuf> =
            entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "conf")).collect();
        confs.sort();
        files.extend(confs);
    }
    files
}

/// Loads `files` into a fresh shell; each problem is passed to `report` (a file that doesn't
/// parse is skipped, the rest still load). `true` in the second place if there were none. A
/// missing `/etc/devd.conf` is no problem; any other missing file is.
pub fn load(files: &[PathBuf], report: &mut dyn FnMut(&str)) -> (Config, bool) {
    let mut shell = Shell::new("devd".into(), Vec::new());
    let rules = Rc::new(RefCell::new(Vec::new()));
    let errors = Rc::new(RefCell::new(Vec::new()));
    let (r, e) = (rules.clone(), errors.clone());
    shell
        .add_builtin("on", move |_: &mut Shell, args: &[String]| match Rule::new(&args[1..]) {
            Ok(rule) => {
                r.borrow_mut().push(rule);
                Ok(0)
            }
            Err(msg) => {
                e.borrow_mut().push(format!("on: {msg}"));
                Ok(2)
            }
        })
        .expect("on is a regular built-in's name");
    let mut clean = true;
    for file in files {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && file == Path::new("/etc/devd.conf") => continue,
            Err(err) => {
                report(&format!("{}: {err}", file.display()));
                clean = false;
                continue;
            }
        };
        match shell.source(&text) {
            Err(err) => {
                report(&format!("{}: line {}: {err} (file skipped)", file.display(), err.line));
                clean = false;
            }
            // A status, or `exit`, which ends the file, not devd.
            Ok(_) => {}
        }
        for msg in errors.borrow_mut().drain(..) {
            report(&format!("{}: {msg}", file.display()));
            clean = false;
        }
    }
    let rules = std::mem::take(&mut *rules.borrow_mut());
    (Config { shell, rules }, clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::parse;

    /// Writes each text to a file of its own and loads them; the config and what was reported.
    fn load_texts(texts: &[&str]) -> (Config, Vec<String>) {
        let dir = std::env::temp_dir().join(format!("devd-test-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let files: Vec<PathBuf> = texts
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let f = dir.join(format!("{i}.conf"));
                std::fs::write(&f, t).unwrap();
                f
            })
            .collect();
        let mut reports = Vec::new();
        let (config, clean) = load(&files, &mut |m| reports.push(m.to_string()));
        assert_eq!(clean, reports.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
        (config, reports)
    }

    fn matching<'a>(c: &'a Config, line: &str) -> Vec<&'a str> {
        let e = parse(line).unwrap();
        c.rules.iter().filter(|r| r.matches(&e)).map(|r| r.handler.as_str()).collect()
    }

    #[test]
    fn rules_match_in_order() {
        let (c, reports) = load_texts(&[
            "on attach disk one bus=ahci\non attach disk two 'name=sata*'\non '*' '*' every\non attach disk five bus!=ahci\n",
        ]);
        assert!(reports.is_empty(), "{reports:?}");
        assert_eq!(matching(&c, "attach disk name=sata0.1 bus=ahci"), ["one", "two", "every"]);
        assert_eq!(matching(&c, "attach disk name=virt0 bus=virtio_blk"), ["every", "five"]);
        assert_eq!(matching(&c, "detach disk name=sata0.1 bus=ahci"), ["every"]);
    }

    #[test]
    fn negation_matches_a_missing_field() {
        let (c, _) = load_texts(&["on media cd h state!=ejected\non media cd p port=*\n"]);
        assert_eq!(matching(&c, "media cd name=ide0"), ["h"]);
        assert_eq!(matching(&c, "media cd name=ide0 state=ejected"), Vec::<&str>::new());
        assert_eq!(matching(&c, "media cd name=ide0 state=inserted port=1"), ["h", "p"]);
    }

    #[test]
    fn a_backslash_quotes_in_a_pattern() {
        let (c, _) = load_texts(&["on a b h 'model=\\*'\n"]);
        assert_eq!(matching(&c, "a b model=*"), ["h"]);
        assert_eq!(matching(&c, "a b model=x"), Vec::<&str>::new());
    }

    #[test]
    fn files_share_one_shell() {
        let (c, reports) = load_texts(&["helper() { on \"$1\" disk \"log_$1\"; }\nkind=ahci\n", "helper attach\non x y \"echo $kind\"\n"]);
        assert!(reports.is_empty(), "{reports:?}");
        assert_eq!(matching(&c, "attach disk"), ["log_attach"]);
        assert_eq!(matching(&c, "x y"), ["echo ahci"]);
        assert!(c.shell.functions.contains_key("helper"));
    }

    #[test]
    fn a_bad_file_is_reported_and_skipped() {
        let (c, reports) = load_texts(&["on a b first\n", "on c d never\nif then; fi\n", "on e f\non g h ok BAD=x\nexit 3\non i j after_exit\n", "on k l last\n"]);
        assert_eq!(reports.len(), 3, "{reports:?}");
        assert!(reports[0].contains("1.conf: line 2:") && reports[0].contains("skipped"), "{}", reports[0]);
        assert!(reports[1].contains("2.conf: on: usage"), "{}", reports[1]);
        assert!(reports[2].contains("`BAD` isn't a field's name"), "{}", reports[2]);
        let handlers: Vec<&str> = c.rules.iter().map(|r| r.handler.as_str()).collect();
        assert_eq!(handlers, ["first", "last"]);
    }

    #[test]
    fn a_missing_main_file_is_fine() {
        let mut reports = Vec::new();
        let (c, clean) = load(&[PathBuf::from("/etc/devd.conf"), PathBuf::from("/nonexistent/x.conf")], &mut |m| reports.push(m.to_string()));
        assert!(!clean);
        assert!(c.rules.is_empty());
        assert_eq!(reports.len(), if Path::new("/etc/devd.conf").exists() { reports.len() } else { 1 });
        assert!(reports.last().unwrap().contains("/nonexistent/x.conf"));
    }
}
