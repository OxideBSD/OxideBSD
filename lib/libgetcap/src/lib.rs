//! Capability databases in the format of the BSDs' `getcap(3)`, used by `gettytab(5)` and
//! `login.conf(5)` (LOGIN.md §3). A record is a list of names and capabilities:
//!
//! ```text
//! default|std|the default entry:\
//!         :sp#9600:lm=login\72 :ht:tc=common:
//! ```
//!
//! A capability is a flag (`ht`), a number (`sp#9600`; octal with a leading 0, hex with 0x), a
//! string (`lm=...`, with the escapes `\E`, `\n`, `\r`, `\t`, `\b`, `\f`, `\^`, `\\`, `\:`,
//! `\` and three octal digits, and `^X` for a control character), or cancelled (`name@`).
//! `tc=name` includes another record at that point. The first definition of a capability wins,
//! so a record overrides what it includes. Lines ending in `\` continue; `#` starts a comment
//! line. Unlike the BSDs, the text file is read directly: there is no `cap_mkdb` database.

use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Flag,
    Num(i64),
    Str(String),
    /// `name@`: this capability is absent, whatever an included record says.
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub names: Vec<String>,
    /// Capabilities in order, `tc=` entries included as `("tc", Str(name))`.
    pub caps: Vec<(String, Value)>,
}

#[derive(Clone, Debug, Default)]
pub struct Db {
    records: Vec<Record>,
    by_name: HashMap<String, usize>,
}

fn parse_number(s: &str) -> Option<i64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        i64::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse().ok()
    }
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('E' | 'e') => out.push('\x1b'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\x08'),
                Some('f') => out.push('\x0c'),
                Some(d @ '0'..='7') => {
                    let mut v = d.to_digit(8).unwrap();
                    for _ in 0..2 {
                        match chars.peek().and_then(|c| c.to_digit(8)) {
                            Some(x) => {
                                v = v * 8 + x;
                                chars.next();
                            }
                            None => break,
                        }
                    }
                    out.push(char::from_u32(v & 0xff).unwrap_or('\0'));
                }
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            '^' => match chars.next() {
                Some('?') => out.push('\x7f'),
                Some(x) => out.push(char::from((x as u8) & 0x1f)),
                None => out.push('^'),
            },
            c => out.push(c),
        }
    }
    out
}

/// Splits record text on unescaped `:`.
fn fields(text: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            out.last_mut().unwrap().push('\\');
            out.last_mut().unwrap().push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ':' {
            out.push(String::new());
        } else {
            out.last_mut().unwrap().push(c);
        }
    }
    out
}

impl Db {
    pub fn parse(text: &str) -> Db {
        let mut db = Db::default();
        let mut logical = String::new();
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            if logical.is_empty() && (line.trim_start().starts_with('#') || line.trim().is_empty()) {
                continue;
            }
            // A continuation: drop the trailing backslash, and the next line's indentation.
            if let Some(body) = line.strip_suffix('\\') {
                logical.push_str(if logical.is_empty() { body } else { body.trim_start() });
                continue;
            }
            logical.push_str(if logical.is_empty() { line } else { line.trim_start() });
            db.add(&std::mem::take(&mut logical));
        }
        if !logical.is_empty() {
            db.add(&logical);
        }
        db
    }

    fn add(&mut self, text: &str) {
        let mut f = fields(text).into_iter();
        let names: Vec<String> = f.next().unwrap_or_default().split('|').map(|s| s.trim().to_string()).collect();
        let mut caps = Vec::new();
        for field in f {
            // Only leading blanks go: a string value keeps its trailing ones (`lm=login\: `).
            let field = field.trim_start();
            if field.trim_end().is_empty() {
                continue;
            }
            let split = field.find(['#', '=', '@']);
            let (name, value) = match split {
                None => (field.trim_end(), Value::Flag),
                Some(i) => {
                    let (name, rest) = field.split_at(i);
                    match rest.as_bytes()[0] {
                        b'#' => match parse_number(&rest[1..]) {
                            Some(n) => (name, Value::Num(n)),
                            None => continue,
                        },
                        b'=' => (name, Value::Str(unescape(&rest[1..]))),
                        _ => (name, Value::Cancelled),
                    }
                }
            };
            caps.push((name.to_string(), value));
        }
        let index = self.records.len();
        for n in &names {
            self.by_name.entry(n.clone()).or_insert(index);
        }
        self.records.push(Record { names, caps });
    }

    pub fn read(path: &str) -> std::io::Result<Db> {
        Ok(Db::parse(&std::fs::read_to_string(path)?))
    }

    /// The record named `name`, with its `tc=` inclusions expanded.
    pub fn get(&self, name: &str) -> Option<Entry> {
        let mut caps: Vec<(String, Value)> = Vec::new();
        self.expand(*self.by_name.get(name)?, &mut caps, 0);
        Some(Entry { name: name.to_string(), caps })
    }

    fn expand(&self, index: usize, out: &mut Vec<(String, Value)>, depth: usize) {
        for (name, value) in &self.records[index].caps {
            if name == "tc" {
                if depth < 32
                    && let Value::Str(other) = value
                    && let Some(&i) = self.by_name.get(other)
                {
                    self.expand(i, out, depth + 1);
                }
                continue;
            }
            out.push((name.clone(), value.clone()));
        }
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.records.iter().filter_map(|r| r.names.first().map(String::as_str))
    }
}

/// A record with its inclusions expanded. The first definition of each capability wins.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    caps: Vec<(String, Value)>,
}

impl Entry {
    fn find(&self, name: &str) -> Option<&Value> {
        self.caps.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn flag(&self, name: &str) -> bool {
        matches!(self.find(name), Some(Value::Flag))
    }

    pub fn num(&self, name: &str) -> Option<i64> {
        match self.find(name) {
            Some(Value::Num(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn string(&self, name: &str) -> Option<&str> {
        match self.find(name) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// Whether the capability is present in any form (not cancelled).
    pub fn has(&self, name: &str) -> bool {
        !matches!(self.find(name), None | Some(Value::Cancelled))
    }

    /// Every capability name defined, in order.
    pub fn cap_names(&self) -> impl Iterator<Item = &str> {
        self.caps.iter().map(|(n, _)| n.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: &str = "# comment\n\
default:\\\n\
\t:cb:ce:ck:lc:fd#1000:im=\\r\\n%s/%m (%h) (%t)\\r\\n\\r\\n:sp#1200:\\\n\
\t:if=/etc/issue:\n\
\n\
P|Pc|Pc console:\\\n\
\t:ht:np:sp#9600:tc=default:\n\
3wire|std three-wire:\\\n\
\t:np:nc:sp#0x2580:ce@:lm=\\Elogin\\: :er=^?:kl=^U:tc=default:\n";

    #[test]
    fn records_aliases_and_inheritance() {
        let db = Db::parse(DB);
        let pc = db.get("Pc").unwrap();
        assert!(pc.flag("ht") && pc.flag("cb"));
        assert_eq!(pc.num("sp"), Some(9600), "a record overrides what it includes");
        assert_eq!(pc.num("fd"), Some(1000));
        assert_eq!(pc.string("im"), Some("\r\n%s/%m (%h) (%t)\r\n\r\n"));
        assert_eq!(pc.string("if"), Some("/etc/issue"));
        assert!(db.get("Pc console").is_some());
        assert_eq!(db.names().collect::<Vec<_>>(), ["default", "P", "3wire"]);
    }

    #[test]
    fn values_and_cancellation() {
        let db = Db::parse(DB);
        let w = db.get("3wire").unwrap();
        assert_eq!(w.num("sp"), Some(9600));
        assert!(!w.has("ce") && !w.flag("ce"), "cancelled before tc=");
        assert_eq!(w.string("lm"), Some("\x1blogin: "));
        assert_eq!(w.string("er"), Some("\x7f"));
        assert_eq!(w.string("kl"), Some("\x15"));
        assert!(db.get("nope").is_none());
    }

    #[test]
    fn numbers_and_octal() {
        let db = Db::parse("x:a#010:b#0x10:c#10:s=\\101\\072\\\\:\n");
        let x = db.get("x").unwrap();
        assert_eq!((x.num("a"), x.num("b"), x.num("c")), (Some(8), Some(16), Some(10)));
        assert_eq!(x.string("s"), Some("A:\\"));
    }

    #[test]
    fn self_inclusion_terminates() {
        let db = Db::parse("a:x:tc=a:\n");
        assert!(db.get("a").unwrap().flag("x"));
    }
}
