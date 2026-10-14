//! mtree(5) specifications: a file hierarchy described one entry per line, with each entry's
//! type, mode, owner, size, digest and so on (OxideBSD-doc `RAM_FLOOR.md` §4.3). `build.rs`
//! writes one per dist set, `makefs(8)` builds images from them, and the installed copies in
//! `/etc/mtree` are what `oxupdate(8)` compares the disk against.
//!
//! Both of FreeBSD's forms are read: full-path entries (`./bin/sh type=file ...`, what
//! `mtree -C` prints and what `Spec::write` writes) and relative ones, where a `type=dir` entry
//! without a slash descends into that directory and `..` climbs back out. `/set` gives defaults
//! for the entries after it and `/unset` removes them; a line ending in `\` continues on the
//! next. Names are encoded as `strsvis(3)` does with `VIS_OCTAL`: `\` followed by three octal
//! digits for a space, a non-printing byte, `#`, `\`, or a glob character.

use std::collections::BTreeMap;
use std::fmt;

/// What an entry is (`type=`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Type {
    File,
    Dir,
    Link,
    Char,
    Block,
    Fifo,
    Socket,
}

impl Type {
    fn parse(s: &str) -> Option<Type> {
        Some(match s {
            "file" => Type::File,
            "dir" => Type::Dir,
            "link" => Type::Link,
            "char" => Type::Char,
            "block" => Type::Block,
            "fifo" => Type::Fifo,
            "socket" => Type::Socket,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Type::File => "file",
            Type::Dir => "dir",
            Type::Link => "link",
            Type::Char => "char",
            Type::Block => "block",
            Type::Fifo => "fifo",
            Type::Socket => "socket",
        }
    }
}

/// One entry: its path (relative to the hierarchy's root, components joined by `/`, the root
/// itself being empty) and its keywords, `/set` defaults applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: Vec<u8>,
    pub keywords: BTreeMap<String, String>,
}

impl Entry {
    pub fn new(path: &[u8]) -> Entry {
        Entry { path: path.to_vec(), keywords: BTreeMap::new() }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.keywords.get(canonical(key)).map(String::as_str)
    }

    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.keywords.insert(canonical(key).to_string(), value.into());
    }

    pub fn kind(&self) -> Option<Type> {
        self.get("type").and_then(Type::parse)
    }

    /// `mode=`, octal.
    pub fn mode(&self) -> Option<u32> {
        u32::from_str_radix(self.get("mode")?, 8).ok()
    }

    pub fn uid(&self) -> Option<u32> {
        self.get("uid")?.parse().ok()
    }

    pub fn gid(&self) -> Option<u32> {
        self.get("gid")?.parse().ok()
    }

    pub fn size(&self) -> Option<u64> {
        self.get("size")?.parse().ok()
    }

    /// `time=`, `seconds.nanoseconds`: the seconds.
    pub fn time(&self) -> Option<i64> {
        self.get("time")?.split('.').next()?.parse().ok()
    }

    /// A symlink's target (`link=`), decoded.
    pub fn link(&self) -> Option<Vec<u8>> {
        unvis(self.get("link")?)
    }

    /// Where a file's contents are (`contents=`, FreeBSD makefs's manifest keyword), decoded.
    pub fn contents(&self) -> Option<Vec<u8>> {
        unvis(self.get("contents")?)
    }
}

/// The spelling a keyword is stored under: FreeBSD accepts `sha256` for `sha256digest`, and
/// so on.
fn canonical(key: &str) -> &str {
    match key {
        "sha256" => "sha256digest",
        "sha512" => "sha512digest",
        "md5" => "md5digest",
        "rmd160" | "ripemd160digest" => "rmd160digest",
        k => k,
    }
}

/// A whole specification, in file order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Spec {
    pub entries: Vec<Entry>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub what: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.what)
    }
}

impl std::error::Error for ParseError {}

impl Spec {
    pub fn parse(text: &str) -> Result<Spec, ParseError> {
        let mut spec = Spec::default();
        let mut defaults: BTreeMap<String, String> = BTreeMap::new();
        // The current directory in relative form.
        let mut cwd: Vec<Vec<u8>> = Vec::new();
        let mut pending = String::new();
        let mut first_line = 0;
        for (n, raw) in text.lines().enumerate() {
            if pending.is_empty() {
                first_line = n + 1;
            }
            if let Some(head) = raw.strip_suffix('\\') {
                pending.push_str(head);
                pending.push(' ');
                continue;
            }
            pending.push_str(raw);
            let line = std::mem::take(&mut pending);
            let err = |what: String| ParseError { line: first_line, what };
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut words = line.split_whitespace();
            let name = words.next().unwrap();
            let keywords = || -> Result<Vec<(String, String)>, ParseError> {
                line.split_whitespace()
                    .skip(1)
                    .map(|w| match w.split_once('=') {
                        Some((k, v)) => Ok((canonical(k).to_string(), v.to_string())),
                        None => Err(err(format!("keyword without a value: {w}"))),
                    })
                    .collect()
            };
            match name {
                "/set" => {
                    for (k, v) in keywords()? {
                        defaults.insert(k, v);
                    }
                    continue;
                }
                "/unset" => {
                    for k in words {
                        if k == "all" {
                            defaults.clear();
                        } else {
                            defaults.remove(canonical(k));
                        }
                    }
                    continue;
                }
                ".." => {
                    if cwd.pop().is_none() {
                        return Err(err("`..` above the root".into()));
                    }
                    continue;
                }
                _ if name.starts_with('/') => return Err(err(format!("unknown command {name}"))),
                _ => {}
            }
            let decoded = unvis(name).ok_or_else(|| err(format!("bad escape in {name}")))?;
            let full = decoded.contains(&b'/');
            let path = if full {
                // `./a/b`, or `.` for the root.
                let p = decoded.strip_prefix(b"./").or_else(|| (decoded == b".").then_some(&b""[..]));
                p.ok_or_else(|| err(format!("full path not starting with ./: {name}")))?.to_vec()
            } else if decoded == b"." {
                Vec::new()
            } else {
                let mut p = cwd.join(&b'/');
                if !p.is_empty() {
                    p.push(b'/');
                }
                p.extend_from_slice(&decoded);
                p
            };
            let mut entry = Entry { path, keywords: defaults.clone() };
            for (k, v) in keywords()? {
                entry.keywords.insert(k, v);
            }
            if entry.get("type").is_some_and(|t| Type::parse(t).is_none()) {
                return Err(err(format!("unknown type {}", entry.get("type").unwrap())));
            }
            if !full && decoded != b"." && entry.kind() == Some(Type::Dir) {
                cwd.push(decoded);
            }
            spec.entries.push(entry);
        }
        Ok(spec)
    }

    /// The specification in full-path form (`mtree -C`'s), keywords in name order.
    pub fn write(&self) -> String {
        let mut out = String::from("#mtree v2.0\n");
        for e in &self.entries {
            if e.path.is_empty() {
                out.push('.');
            } else {
                out.push_str("./");
                out.push_str(&vis(&e.path));
            }
            for (k, v) in &e.keywords {
                out.push(' ');
                out.push_str(k);
                out.push('=');
                out.push_str(v);
            }
            out.push('\n');
        }
        out
    }
}

/// `strsvis(3)` with `VIS_OCTAL | VIS_WHITE | VIS_GLOB`, as mtree encodes names: every byte
/// outside printable ASCII, and space, `#`, `\`, `*`, `?`, `[` and `=`, as `\ooo`. `/` is kept:
/// it separates components.
pub fn vis(name: &[u8]) -> String {
    let mut out = String::new();
    for &b in name {
        if b.is_ascii_graphic() && !b"#\\*?[=".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\{b:03o}"));
        }
    }
    out
}

/// `vis`'s inverse; also C-style escapes (`\n`, `\t`, `\s` for a space, `\\`). `None` for a
/// malformed escape.
pub fn unvis(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let rest = &b[i + 1..];
        match rest.first()? {
            b'0'..=b'7' => {
                let digits = rest.iter().take(3).take_while(|c| (b'0'..=b'7').contains(c)).count();
                if digits != 3 {
                    return None;
                }
                let v = rest[..3].iter().fold(0u32, |acc, c| acc * 8 + (c - b'0') as u32);
                out.push(u8::try_from(v).ok()?);
                i += 4;
            }
            c => {
                out.push(match c {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    b's' => b' ',
                    b'\\' => b'\\',
                    b'#' => b'#',
                    _ => return None,
                });
                i += 2;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_path_round_trips() {
        let mut spec = Spec::default();
        let mut root = Entry::new(b"");
        root.set("type", "dir");
        root.set("mode", "0755");
        let mut f = Entry::new(b"usr/share/a b#c");
        f.set("type", "file");
        f.set("sha256", "ab");
        f.set("size", "12");
        let mut l = Entry::new(b"bin/lsmod");
        l.set("type", "link");
        l.set("link", vis(b"lsoxmod"));
        spec.entries = vec![root, f, l];
        let text = spec.write();
        assert!(text.contains("./usr/share/a\\040b\\043c "));
        assert!(text.contains("sha256digest=ab"));
        assert_eq!(Spec::parse(&text).unwrap(), spec);
    }

    #[test]
    fn relative_form_and_set() {
        let text = "\
#mtree
/set type=file uid=0 gid=0 mode=0644
. type=dir mode=0755
bin type=dir mode=0755
    sh mode=0555 \\
        size=10
..
etc type=dir
    passwd
/unset mode
    group
..
";
        let spec = Spec::parse(text).unwrap();
        let paths: Vec<&[u8]> = spec.entries.iter().map(|e| &e.path[..]).collect();
        assert_eq!(paths, [&b""[..], b"bin", b"bin/sh", b"etc", b"etc/passwd", b"etc/group"]);
        assert_eq!(spec.entries[2].mode(), Some(0o555));
        assert_eq!(spec.entries[2].size(), Some(10));
        assert_eq!(spec.entries[4].mode(), Some(0o644));
        assert_eq!(spec.entries[5].mode(), None);
        assert_eq!(spec.entries[5].kind(), Some(Type::File));
    }

    #[test]
    fn errors() {
        assert_eq!(Spec::parse("..\n").unwrap_err().line, 1);
        assert!(Spec::parse("\n./a type=wat\n").unwrap_err().line == 2);
        assert!(Spec::parse("./a mode\n").is_err());
        assert!(unvis("a\\12").is_none());
        assert_eq!(unvis("a\\012\\s").unwrap(), b"a\n ");
    }
}
