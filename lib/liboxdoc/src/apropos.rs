//! apropos(1) and whatis(1) (MAN.md §7): searches the `oxdoc.db` index of each manual tree.
//!
//! An expression is terms joined by `-a` (and) and `-o` (or, also what two terms next to each
//! other mean), with `-a` binding tighter, and parentheses. A term is `[key[,key...]](=|~)value`:
//! `=` finds `value` as a substring (ignoring case), `~` matches it as an extended regular
//! expression (with `-i` before the term, ignoring case). A term with neither searches names
//! and descriptions with a regular expression, ignoring case. The keys are the macro classes
//! of [`crate::keys::CLASSES`], `any` for all of them but the full text, `sec` and `arch`.

use crate::db::Db;
use crate::keys::{self, CLASSES};
use crate::makewhatis::DB_NAME;
use crate::regex::Regex;

fn usage(prog: &str) -> i32 {
    eprintln!("usage: {prog} [-afk] [-C file] [-M path] [-m path] [-O outkey] [-S arch] [-s section] [-t] expression ...");
    1
}

/// What a term compares.
#[derive(Clone, Debug)]
enum Field {
    Class(u8),
    Section,
    Arch,
}

#[derive(Debug)]
enum Test {
    Substr(String),
    Regex(Regex),
}

impl Test {
    fn matches(&self, s: &str) -> bool {
        match self {
            Test::Substr(sub) => s.to_lowercase().contains(sub),
            Test::Regex(r) => r.is_match(s),
        }
    }
}

#[derive(Debug)]
struct Term {
    fields: Vec<Field>,
    test: Test,
}

#[derive(Debug)]
enum Expr {
    Term(usize),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl Expr {
    fn eval(&self, hits: &[Vec<bool>], page: usize) -> bool {
        match self {
            Expr::Term(t) => hits[*t][page],
            Expr::And(a, b) => a.eval(hits, page) && b.eval(hits, page),
            Expr::Or(a, b) => a.eval(hits, page) || b.eval(hits, page),
        }
    }
}

/// The name and description classes, a plain term's fields.
fn default_fields() -> Vec<Field> {
    vec![Field::Class(0), Field::Class(1)]
}

fn fields_named(list: &str) -> Option<Vec<Field>> {
    let mut out = Vec::new();
    for k in list.split(',') {
        match k {
            "any" => out.extend((0..CLASSES.len() as u8).filter(|c| CLASSES[*c as usize] != "Tx").map(Field::Class)),
            "sec" => out.push(Field::Section),
            "arch" => out.push(Field::Arch),
            k => out.push(Field::Class(keys::class(k)?)),
        }
    }
    Some(out)
}

/// A term as typed; `icase` from a `-i` before it.
fn term(s: &str, icase: bool) -> Result<Term, String> {
    let op = s.find(['=', '~']);
    if let Some(i) = op {
        let keys = &s[..i];
        let fields = if keys.is_empty() { Some(default_fields()) } else { fields_named(keys) };
        if let Some(fields) = fields {
            let value = &s[i + 1..];
            let test = if s.as_bytes()[i] == b'=' {
                Test::Substr(value.to_lowercase())
            } else {
                Test::Regex(Regex::new(value, icase).map_err(|e| format!("{value}: {e}"))?)
            };
            return Ok(Term { fields, test });
        }
    }
    // A plain word: names and descriptions, as a regular expression ignoring case.
    let r = Regex::new(s, true).map_err(|e| format!("{s}: {e}"))?;
    Ok(Term { fields: default_fields(), test: Test::Regex(r) })
}

struct QueryParser<'a> {
    args: &'a [String],
    i: usize,
    terms: Vec<Term>,
}

impl QueryParser<'_> {
    fn or(&mut self) -> Result<Expr, String> {
        let mut e = self.and()?;
        loop {
            match self.args.get(self.i).map(String::as_str) {
                None | Some(")") => return Ok(e),
                Some("-o") => {
                    self.i += 1;
                }
                _ => {}
            }
            let r = self.and()?;
            e = Expr::Or(Box::new(e), Box::new(r));
        }
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut e = self.unary()?;
        while self.args.get(self.i).map(String::as_str) == Some("-a") {
            self.i += 1;
            let r = self.unary()?;
            e = Expr::And(Box::new(e), Box::new(r));
        }
        Ok(e)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        let Some(a) = self.args.get(self.i) else { return Err("missing term".into()) };
        self.i += 1;
        match a.as_str() {
            "(" => {
                let e = self.or()?;
                if self.args.get(self.i).map(String::as_str) != Some(")") {
                    return Err("unbalanced parentheses".into());
                }
                self.i += 1;
                Ok(e)
            }
            ")" | "-a" | "-o" => Err(format!("unexpected {a}")),
            "-i" => {
                let Some(t) = self.args.get(self.i) else { return Err("missing term after -i".into()) };
                self.i += 1;
                self.push(term(t, true)?)
            }
            t => self.push(term(t, false)?),
        }
    }

    fn push(&mut self, t: Term) -> Result<Expr, String> {
        self.terms.push(t);
        Ok(Expr::Term(self.terms.len() - 1))
    }
}

/// A regular expression matching `s` literally.
fn escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "\\.[]()*+?{}|^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A found page: its tree, and its entry.
pub struct Hit {
    pub tree: String,
    pub file: String,
    pub section: String,
    pub arch: String,
    pub names: Vec<String>,
    /// The file this line is for: the page's own (empty) or a link's name.
    pub link: String,
    pub desc: String,
    /// The values of the `-O` key, if one was asked for.
    pub out: Option<String>,
}

/// The pages of the index `db` in tree `tree` satisfying `expr` and the section and
/// architecture limits.
fn search(db: &Db, tree: &str, terms: &[Term], expr: &Expr, sec: Option<&str>, arch: Option<&str>, outkey: Option<&str>) -> Vec<Hit> {
    let n = db.page_count();
    let pages: Vec<_> = (0..n).map(|i| db.page(i)).collect();
    let mut hits = vec![vec![false; n]; terms.len()];
    for (t, term) in terms.iter().enumerate() {
        for f in &term.fields {
            match f {
                Field::Class(c) => {
                    for k in db.class_range(*c) {
                        let key = db.key(k);
                        if term.test.matches(key.value) {
                            for p in key.pages {
                                if let Some(h) = hits[t].get_mut(p as usize) {
                                    *h = true;
                                }
                            }
                        }
                    }
                }
                Field::Section => {
                    for (i, p) in pages.iter().enumerate() {
                        hits[t][i] |= p.section.split(", ").any(|s| term.test.matches(s));
                    }
                }
                Field::Arch => {
                    for (i, p) in pages.iter().enumerate() {
                        hits[t][i] |= term.test.matches(if p.arch.is_empty() { "any" } else { p.arch });
                    }
                }
            }
        }
    }
    let out_class = outkey.and_then(keys::class);
    let mut found = Vec::new();
    for (i, p) in pages.iter().enumerate() {
        if !expr.eval(&hits, i) {
            continue;
        }
        if sec.is_some_and(|s| !p.section.split(", ").any(|x| x.eq_ignore_ascii_case(s))) {
            continue;
        }
        if let Some(a) = arch
            && !p.arch.is_empty()
            && !p.arch.eq_ignore_ascii_case(a)
            && !p.arch.eq_ignore_ascii_case("any")
        {
            continue;
        }
        let out = outkey.map(|k| match (k, out_class) {
            ("Nm", _) => p.names.join(" # "),
            ("Nd", _) => p.desc.to_string(),
            ("sec", _) => p.section.to_string(),
            ("arch", _) => p.arch.to_string(),
            (_, Some(c)) => {
                let mut vals: Vec<&str> = db.class_range(c).map(|k| db.key(k)).filter(|k| k.pages.contains(&(i as u32))).map(|k| k.value).collect();
                vals.sort();
                vals.dedup();
                vals.join(" # ")
            }
            _ => String::new(),
        });
        // One line for the page's file and one for each link to it, with the link's name first.
        for link in std::iter::once("").chain(p.links.iter().copied()) {
            let mut names: Vec<String> = p.names.iter().map(|s| s.to_string()).collect();
            if let Some(k) = names.iter().position(|n| n == link) {
                let l = names.remove(k);
                names.insert(0, l);
            }
            found.push(Hit {
                tree: tree.to_string(),
                file: p.file.to_string(),
                section: p.section.to_string(),
                arch: p.arch.to_string(),
                names,
                link: link.to_string(),
                desc: p.desc.to_string(),
                out: out.clone(),
            });
        }
    }
    found
}

/// Sorting: section by number, then name, ignoring case.
fn order(a: &Hit, b: &Hit) -> std::cmp::Ordering {
    let num = |s: &str| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u32>().unwrap_or(u32::MAX);
    num(&a.section)
        .cmp(&num(&b.section))
        .then_with(|| a.section.cmp(&b.section))
        .then_with(|| a.names.first().map(|n| n.to_lowercase()).cmp(&b.names.first().map(|n| n.to_lowercase())))
}

/// Text for the terminal: as it is in a UTF-8 locale, else in ASCII.
fn show(s: &str, utf8: bool) -> String {
    if utf8 {
        return s.to_string();
    }
    s.chars()
        .map(|c| {
            if c.is_ascii() {
                return c.to_string();
            }
            // A character without an ASCII form is a question mark for each of its bytes, as
            // in mandoc's apropos.
            let a = crate::term::ascii_for(c);
            if a == "<?>" { "?".repeat(c.len_utf8()) } else { a.replace('\u{8}', "") }
        })
        .collect()
}

/// Runs apropos (or whatis, if `prog` is `whatis`) with `args` (without the program name);
/// returns the exit status.
pub fn main(prog: &str, args: &[String]) -> i32 {
    let mut whatis = prog == "whatis";
    let mut all = false;
    let mut conf = None;
    let mut manpath = None;
    let mut extra = Vec::new();
    let mut outkey = None;
    let mut arch = None;
    let mut sec = None;
    let mut fulltext = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        // Options stop at the expression: a term, or `-a`/`-o`/`-i` once the expression began.
        if !a.starts_with('-') || a.len() < 2 || a == "-i" {
            break;
        }
        let flags: Vec<char> = a[1..].chars().collect();
        let mut k = 0;
        while k < flags.len() {
            let f = flags[k];
            let takes = matches!(f, 'C' | 'M' | 'm' | 'O' | 'S' | 's');
            let value = if takes {
                let rest: String = flags[k + 1..].iter().collect();
                if rest.is_empty() {
                    i += 1;
                    match args.get(i) {
                        Some(v) => Some(v.clone()),
                        None => return usage(prog),
                    }
                } else {
                    Some(rest)
                }
            } else {
                None
            };
            match f {
                'a' => all = true,
                'f' => whatis = true,
                'k' => whatis = false,
                't' => fulltext = true,
                'C' => conf = value,
                'M' => manpath = value,
                'm' => extra.push(value.unwrap()),
                'O' => outkey = value,
                'S' => arch = value,
                's' => sec = value,
                // man(1)'s options, accepted: -c no pager, -h synopsis, -l local, -w paths.
                'c' | 'h' | 'l' | 'w' => {}
                _ => return usage(prog),
            }
            if takes {
                break;
            }
            k += 1;
        }
        i += 1;
    }
    let words = &args[i..];
    if words.is_empty() {
        return usage(prog);
    }
    // The expression as terms and operators.
    let query: Vec<String> = if whatis {
        // Each word, whole, in the names only.
        let mut q = Vec::new();
        for (k, w) in words.iter().enumerate() {
            if k > 0 {
                q.push("-o".to_string());
            }
            q.push("-i".to_string());
            q.push(format!("Nm~[[:<:]]{}[[:>:]]", escape(w)));
        }
        q
    } else if fulltext {
        // `-t word ...`: the full text.
        words.iter().map(|w| if w.starts_with('-') || w == "(" || w == ")" || w.contains(['=', '~']) { w.clone() } else { format!("Tx={w}") }).collect()
    } else {
        words.to_vec()
    };
    let mut p = QueryParser { args: &query, i: 0, terms: Vec::new() };
    let expr = match p.or() {
        Ok(e) if p.i == query.len() => e,
        Ok(_) => {
            eprintln!("{prog}: unbalanced parentheses");
            return 1;
        }
        Err(e) => {
            eprintln!("{prog}: {e}");
            return 1;
        }
    };
    let terms = p.terms;
    let mut found = Vec::new();
    for tree in crate::manpath::resolve(conf.as_deref(), manpath.as_deref(), &extra) {
        let path = std::path::Path::new(&tree).join(DB_NAME);
        let Ok(bytes) = std::fs::read(&path) else { continue };
        match Db::read(bytes) {
            Ok(db) => found.extend(search(&db, &tree, &terms, &expr, sec.as_deref(), arch.as_deref(), outkey.as_deref())),
            Err(e) => eprintln!("{prog}: {}: {e}", path.display()),
        }
    }
    if found.is_empty() {
        eprintln!("{prog}: nothing appropriate");
        return 1;
    }
    found.sort_by(order);
    if all {
        // Every page in full, through man(1).
        let files: Vec<String> = found.iter().map(|h| format!("{}/{}", h.tree, h.file)).collect();
        return match std::process::Command::new("man").arg("-l").args(&files).status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("{prog}: man: {e}");
                1
            }
        };
    }
    let utf8 = crate::locale_is_utf8();
    let mut out = String::new();
    for h in &found {
        let sec = if h.arch.is_empty() { h.section.clone() } else { format!("{}/{}", h.section, h.arch) };
        let what = h.out.as_deref().unwrap_or(&h.desc);
        out.push_str(&show(&format!("{}({sec}) - {what}\n", h.names.join(", ")), utf8));
    }
    use std::io::Write;
    let _ = std::io::stdout().write_all(out.as_bytes());
    0
}
