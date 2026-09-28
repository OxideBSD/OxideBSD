//! What `makewhatis` indexes from a page (MAN.md §7.2): its names, section, architecture and
//! one-line description, and search keys by macro class, as mandoc's makewhatis(8) records
//! them, so `apropos` queries give the same pages. Plus `Tx`, every word of the page's text,
//! for full-text search (§7.3).

use crate::roff::mark;
use crate::tree::{Document, Kind, Language, Node};

/// The macro classes a key can belong to, in the order `-O any` lists them.
pub const CLASSES: &[&str] = &[
    "Nm", "Nd", "Sh", "Ss", "Xr", "Rs", "Fl", "Cm", "Ar", "Ic", "Ev", "Pa", "Lb", "In", "Ft", "Fn", "Fa", "Vt", "Va", "Dv", "Er", "An", "Lk", "Mt", "Cd", "Ms",
    "Tn", "Em", "Sy", "Li", "St", "At", "Bx", "Bsx", "Nx", "Fx", "Ox", "Dx", "Tx",
];

/// A class's number in [`CLASSES`].
pub fn class(name: &str) -> Option<u8> {
    CLASSES.iter().position(|c| c.eq_ignore_ascii_case(name)).map(|i| i as u8)
}

/// One page's entry in the index.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Page {
    /// The file, relative to its manual tree (`man1/ls.1`).
    pub file: String,
    /// Its sections, comma-separated, usually one.
    pub section: String,
    pub arch: String,
    /// Its names: the file's, the one matching the title, the rest of its NAME section's,
    /// then its links'.
    pub names: Vec<String>,
    /// The names of the files that are links to it (`.so` it): each is listed on its own.
    pub links: Vec<String>,
    pub desc: String,
    /// `(class, value)`, sorted and without duplicates.
    pub keys: Vec<(u8, String)>,
}

/// The machine architectures a page can be for, as mandoc knows them.
const ARCHES: &[&str] = &[
    "alpha", "amd64", "amiga", "arc", "arm", "arm64", "armish", "armv7", "aviion", "hp300", "hppa", "hppa64", "i386", "landisk", "loongson", "luna88k", "mac68k", "macppc",
    "mips64", "mvme68k", "mvme88k", "mvmeppc", "octeon", "pmax", "powerpc64", "riscv64", "sgi", "socppc", "sparc", "sparc64", "sun3", "tahoe", "vax", "zaurus",
];

/// A node's text as mandoc reads it for the index: its words, and the arguments macros
/// keep aside (`.Fn name`, `.Xr page 1`), separated by spaces.
pub fn deroff(n: &Node) -> String {
    fn walk(n: &Node, out: &mut String) {
        let mut push = |s: &str, nospace: bool| {
            if s.is_empty() {
                return;
            }
            if !out.is_empty() && !nospace {
                out.push(' ');
            }
            out.push_str(s);
        };
        match n.kind {
            Kind::Text => push(&n.text, n.flags.nospace),
            Kind::Elem if n.tok == "Xr" => match n.args.as_slice() {
                [name, sec, ..] if !sec.is_empty() => push(&format!("{name}({sec})"), false),
                [name, ..] => push(name, false),
                [] => {}
            },
            Kind::Elem => {
                for a in &n.args {
                    push(a, false);
                }
            }
            _ => {}
        }
        for c in &n.children {
            walk(c, out);
        }
    }
    let mut out = String::new();
    walk(n, &mut out);
    out
}

/// A decoded text as plain characters: markers resolved to what they print, fonts dropped.
pub fn plain(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            mark::MINUS => Some('-'),
            mark::NBSP => Some(' '),
            mark::BACKSLASH => Some('\\'),
            c if ('\u{E000}'..='\u{E01F}').contains(&c) => None,
            c => Some(c),
        })
        .collect()
}

/// The sections every page may have: not worth indexing under `Sh`.
fn standard_section(title: &str) -> bool {
    crate::lint::SECTIONS.contains(&title)
}

/// The index entry for a parsed page found at `file` (relative to its tree) in `section`.
pub fn page(doc: &Document, file: &str, section: &str) -> Page {
    // `.Dt`'s third argument is an architecture only if it names one.
    let arch = doc.meta.arch.to_lowercase();
    let arch = if ARCHES.contains(&arch.as_str()) { arch } else { String::new() };
    let mut p = Page { file: file.to_string(), arch, ..Page::default() };
    // The file's own name; then those of the NAME section, the one matching the title first.
    let base = file.rsplit('/').next().unwrap_or(file);
    let stem = base.rsplit_once('.').map_or(base, |(s, _)| s);
    // Its sections: its directory's, its own and its file's suffix, where they differ
    // (`man3/curs_variables.3x`, `.TH ... 3X`: 3, 3X, 3x).
    let suffix = base.rsplit_once('.').map_or("", |(_, s)| s);
    let mut secs: Vec<&str> = [section, doc.meta.section.as_str(), suffix].into_iter().filter(|s| !s.is_empty()).collect();
    secs.sort();
    secs.dedup();
    p.section = secs.join(", ");
    add_name(&mut p.names, stem);
    let mut k = Collector { keys: Vec::new(), synopsis: false };
    let mut names = Vec::new();
    let mut found = false;
    match doc.language {
        Language::Mdoc => {
            for sh in &doc.root.children {
                mdoc_names(sh, &mut names, &mut p.desc, &mut found);
            }
            k.walk(&doc.root);
        }
        Language::Man => man_name(&doc.root, &mut names, &mut p.desc, &mut found),
    }
    if let Some(i) = names.iter().position(|n| n.eq_ignore_ascii_case(&doc.meta.title)) {
        let head = names.remove(i);
        names.insert(0, head);
    }
    for n in names {
        add_name(&mut p.names, &n);
    }
    // A page without a description in its NAME section is described by its name.
    if !found {
        p.desc = p.names.first().cloned().unwrap_or_default();
    }
    for n in p.names.clone() {
        k.keys.push((0, n));
    }
    if !p.desc.is_empty() {
        k.keys.push((1, p.desc.clone()));
    }
    // Every word of the text, lower-cased, once.
    let mut words = Vec::new();
    text_words(&doc.root, &mut words);
    for w in words {
        k.keys.push((class("Tx").unwrap(), w));
    }
    k.keys.sort();
    k.keys.dedup();
    p.keys = k.keys;
    p
}

fn add_name(names: &mut Vec<String>, n: &str) {
    let n = n.trim();
    if !n.is_empty() && !names.iter().any(|x| x == n) {
        names.push(n.to_string());
    }
}

/// An mdoc page's NAME section: its `.Nm` names (each word one) and its `.Nd` description.
fn mdoc_names(sh: &Node, names: &mut Vec<String>, desc: &mut String, desc_found: &mut bool) {
    if sh.tok != "Sh" || sh.part(Kind::Head).map(|h| plain(&h.plain_text())).as_deref() != Some("NAME") {
        return;
    }
    let Some(body) = sh.part(Kind::Body) else { return };
    // Names anywhere in the section, the description's included.
    fn nms(n: &Node, names: &mut Vec<String>) {
        if n.tok == "Nm" && n.kind == Kind::Elem {
            for w in n.children.iter().filter(|w| w.kind == Kind::Text && !w.flags.delim) {
                add_name(names, &plain(&w.text));
            }
        }
        for c in &n.children {
            nms(c, names);
        }
    }
    nms(body, names);
    for c in &body.children {
        if c.tok == "Nd" {
            *desc_found = true;
            *desc = plain(&deroff(c)).trim().to_string();
        }
    }
}

/// A man(7) page's NAME section, as mandoc reads it: names separated by commas up to the
/// first space, then the description after a dash, at most 150 bytes of it.
fn man_name(root: &Node, names: &mut Vec<String>, desc: &mut String, desc_found: &mut bool) {
    let mut found = None;
    for sh in &root.children {
        if sh.tok == "SH" && sh.part(Kind::Head).map(|h| plain(&h.plain_text())).as_deref() == Some("NAME") {
            found = sh.part(Kind::Body);
            break;
        }
    }
    let Some(body) = found else { return };
    // As mandoc reads it, with font changes still in the text: one right after the names
    // (`\fBname \fP- text`) keeps the dash in the description.
    let text: String = deroff(body).chars().map(|c| if c == mark::MINUS { '-' } else { c }).collect();
    let mut rest = text.trim_start();
    loop {
        let Some(end) = rest.find([' ', ',']) else {
            // Nothing but names: no description.
            if !rest.is_empty() && !rest.starts_with('-') {
                names.push(plain(rest));
            }
            return;
        };
        let name = &rest[..end];
        // A name starting with a dash is the description's: a stray comma before it.
        if name.starts_with('-') {
            break;
        }
        let name = plain(name);
        if !name.is_empty() {
            names.push(name);
        }
        let sep = rest.as_bytes()[end];
        rest = &rest[end + 1..];
        if sep == b' ' {
            break;
        }
        rest = rest.trim_start_matches(' ');
    }
    // (Names alone, with no dash and description, leave the page described by its name.)
    *desc_found = true;
    let mut d = rest.trim_start();
    for dash in ["--", "-", "\u{2013}", "\u{2014}"] {
        if let Some(r) = d.strip_prefix(dash) {
            d = r;
            break;
        }
    }
    let d = plain(d.trim_start_matches(' '));
    let mut cut = d.len().min(150);
    while !d.is_char_boundary(cut) {
        cut -= 1;
    }
    *desc = d[..cut].trim_end().to_string();
}

struct Collector {
    keys: Vec<(u8, String)>,
    /// Inside the SYNOPSIS section, where function types and arguments are also types (`Vt`).
    synopsis: bool,
}

impl Collector {
    fn put(&mut self, cls: &str, v: &str) {
        let v = plain(v);
        let v = v.trim();
        if !v.is_empty() {
            self.keys.push((class(cls).unwrap(), v.to_string()));
        }
    }

    /// An element's words, each on its own, delimiters left out.
    fn words(n: &Node) -> Vec<String> {
        n.children.iter().filter(|c| c.kind == Kind::Text && !c.flags.delim).map(|c| c.text.clone()).collect()
    }

    fn walk(&mut self, n: &Node) {
        if n.tok == "Sh" && n.kind == Kind::Block {
            let title = n.part(Kind::Head).map(|h| plain(&deroff(h))).unwrap_or_default();
            self.synopsis = title == "SYNOPSIS";
            if !standard_section(&title) {
                self.put("Sh", &title);
            }
        }
        if n.tok == "Ss" && n.kind == Kind::Block {
            let title = n.part(Kind::Head).map(deroff).unwrap_or_default();
            self.put("Ss", &title);
        }
        if n.kind == Kind::Elem {
            self.elem(n);
        }
        if n.tok == "Fo" && n.kind == Kind::Block {
            self.put("Fn", &n.text);
        }
        for c in &n.children {
            self.walk(c);
        }
    }

    fn elem(&mut self, n: &Node) {
        let tok = n.tok.as_str();
        let words = Collector::words(n);
        let joined = words.iter().map(|w| plain(w)).collect::<Vec<_>>().join(" ");
        match tok {
            // Each word its own key.
            "Fl" | "Cm" | "Ar" | "Ev" | "Pa" | "Dv" | "Er" | "Ms" | "Tn" | "Lb" => {
                for w in &words {
                    self.put(tok, w);
                }
                for a in &n.args {
                    self.put(tok, a);
                }
            }
            "Fa" => {
                for w in &words {
                    self.put("Fa", w);
                    if self.synopsis {
                        self.put("Vt", w);
                    }
                }
            }
            // Types: also types in general.
            "Ft" => {
                for w in &words {
                    self.put("Ft", w);
                    self.put("Vt", w);
                }
            }
            // A variable with more than a name (`.Va int count`) has a type too.
            "Va" => {
                self.put("Va", &joined);
                if words.len() > 1 {
                    self.put("Vt", &joined);
                }
            }
            // All the words as one key.
            "Ic" | "Vt" | "An" | "Cd" | "Em" | "Sy" | "Li" => self.put(tok, &joined),
            "Lk" | "Mt" => {
                for a in &n.args {
                    self.put(tok, a);
                }
            }
            "Xr" => match n.args.as_slice() {
                [name, sec, ..] if !sec.is_empty() => self.put("Xr", &format!("{name}({sec})")),
                [name, ..] => self.put("Xr", name),
                [] => {}
            },
            "In" => {
                if let Some(a) = n.args.first() {
                    self.put("In", a);
                }
            }
            // `.Fd #include <file>` names a header too.
            "Fd" => {
                if words.first().is_some_and(|w| w == "#include")
                    && let Some(f) = words.get(1)
                {
                    self.put("In", f.trim_matches(|c| c == '<' || c == '>' || c == '"'));
                }
            }
            "Fn" => {
                if let Some(name) = n.args.first() {
                    self.put("Fn", name);
                }
                for a in n.args.iter().skip(1) {
                    self.put("Fa", a);
                    if self.synopsis {
                        self.put("Vt", a);
                    }
                }
            }
            // The standard's name as typed and as printed.
            "St" | "At" => {
                if let Some(a) = n.args.first() {
                    self.put(tok, a);
                    self.put(tok, &crate::mdoc_term::os_name(tok, &n.args));
                }
            }
            "Bx" | "Bsx" | "Nx" | "Fx" | "Ox" | "Dx" => {
                if !n.args.is_empty() {
                    self.put(tok, &n.args.join(" "));
                }
            }
            _ => {}
        }
    }
}

/// Every word of a page's text for `Tx`: split at anything not alphanumeric, lower-cased.
fn text_words(n: &Node, out: &mut Vec<String>) {
    add_words(&n.text, out);
    for a in &n.args {
        add_words(a, out);
    }
    for c in &n.children {
        text_words(c, out);
    }
}

fn add_words(s: &str, out: &mut Vec<String>) {
    for w in plain(s).split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) {
        out.push(w.to_lowercase());
    }
}
