//! Renders an mdoc document tree on a terminal (MAN.md §5, `-T ascii`/`-T utf8`).

use crate::mdoc::{has_flag, list_type, option};
use crate::roff::mark;
use crate::term::{Style, Term};
use crate::tree::{Document, Kind, Meta, Node};

/// The body text's indentation, and a section heading's.
const INDENT: usize = 5;
const SS_INDENT: usize = 3;

/// The default widths of macros named in `-width` (mdoc(7)).
const MACRO_WIDTHS: &[(&str, usize)] = &[
    ("Ad", 12), ("Ao", 12), ("Aq", 12), ("Ar", 12), ("At", 22), ("Bc", 10), ("Bo", 12), ("Bq", 12), ("Bsx", 6), ("Bx", 6), ("Cd", 12), ("Cm", 10), ("Dc", 10), ("Do", 10), ("Dq", 12), ("Dv", 12), ("Dx", 10), ("Ec", 10), ("Em", 10), ("Er", 17), ("Es", 12), ("Ev", 12), ("Fa", 12), ("Fl", 10), ("Fn", 16), ("Ft", 8), ("Fx", 9), ("Ic", 10), ("Li", 16), ("Ms", 6), ("Nm", 10), ("No", 12), ("Nx", 9), ("Oo", 10), ("Op", 14), ("Ox", 10), ("Pa", 32), ("Pc", 10), ("Pf", 12), ("Po", 12), ("Pq", 12), ("Ql", 16), ("Qo", 12), ("Qq", 12), ("Sc", 10), ("So", 12), ("Sq", 12), ("Sx", 16), ("Sy", 6), ("Tn", 10), ("Ux", 10), ("Va", 12), ("Vt", 12), ("Xr", 10),
];

/// The volume a section belongs to, printed in the header.
pub fn volume(section: &str) -> &'static str {
    match section {
        "1" => "General Commands Manual",
        "2" => "System Calls Manual",
        "3" | "3p" => "Library Functions Manual",
        "4" => "Device Drivers Manual",
        "5" => "File Formats Manual",
        "6" => "Games Manual",
        "7" => "Miscellaneous Information Manual",
        "8" => "System Manager's Manual",
        "9" => "Kernel Developer's Manual",
        _ => "Unknown",
    }
}

/// A width or offset argument in columns: a scaled number (`6n`), `Ds` (6), or the width of the
/// string itself.
pub fn scaled(s: &str) -> usize {
    if s == "Ds" {
        return 6;
    }
    if let Some(&(_, w)) = MACRO_WIDTHS.iter().find(|(m, _)| *m == s) {
        return w;
    }
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    if !digits.is_empty() {
        let unit = &s[digits.len()..];
        let v: f64 = digits.parse().unwrap_or(0.0);
        let cols = match unit {
            "" | "n" | "m" | "M" | "u" => v,
            "i" => v * 10.0,
            "c" => v * 10.0 / 2.54,
            "p" => v / 7.2,
            "P" => v * 10.0 / 6.0,
            "v" => v,
            _ => return s.chars().count(),
        };
        return cols.round() as usize;
    }
    s.chars().filter(|c| !('\u{E000}'..='\u{E01F}').contains(c)).count()
}

fn offset_of(s: &str) -> usize {
    match s {
        "left" => 0,
        "indent" => 6,
        "indent-two" => 12,
        _ => scaled(s),
    }
}

struct R<'a> {
    t: Term,
    meta: &'a Meta,
    synopsis: bool,
}

pub fn render(doc: &Document, t: Term) -> String {
    let mut r = R { t, meta: &doc.meta, synopsis: false };
    r.header();
    for n in &doc.root.children {
        r.node(n, Style::None);
    }
    r.t.flush();
    r.footer();
    r.t.finish()
}

impl R<'_> {
    fn header(&mut self) {
        let mut title = format!("{}({})", self.meta.title, self.meta.section);
        if !self.meta.arch.is_empty() && self.meta.volume.is_empty() {
            title = format!("{}({})", self.meta.title, self.meta.section);
        }
        let vol = volume(&self.meta.section).to_string();
        let vol = if self.meta.arch.is_empty() { vol } else { format!("{vol} ({})", self.meta.arch) };
        self.t.three_part(&title, &vol, &title);
        self.t.raw_blank();
    }

    fn footer(&mut self) {
        let os = if self.meta.os.is_empty() { crate::default_os() } else { self.meta.os.clone() };
        let date = crate::format_date(&self.meta.date);
        self.t.raw_blank();
        self.t.three_part(&os, &date, &os);
    }

    fn children(&mut self, n: &Node, style: Style) {
        for c in &n.children {
            self.node(c, style);
        }
    }

    fn node(&mut self, n: &Node, style: Style) {
        if n.flags.nospace {
            self.t.nospace();
        }
        match n.kind {
            Kind::Text => self.text(n, style),
            Kind::Elem => self.elem(n, style),
            Kind::Block => self.block(n, style),
            _ => self.children(n, style),
        }
    }

    fn text(&mut self, n: &Node, style: Style) {
        if self.t.nofill {
            if n.flags.line_start {
                self.t.flush();
            }
            // Spaces are kept as they are.
            let s: String = n.text.chars().map(|c| if c == ' ' { mark::NBSP } else { c }).collect();
            self.t.word_ext(&s, style, false);
            return;
        }
        let text = &n.text;
        if n.flags.line_start && text.starts_with(' ') {
            self.t.flush();
        }
        let words: Vec<&str> = text.split(' ').filter(|w| !w.is_empty()).collect();
        let last = words.len().saturating_sub(1);
        for (i, w) in words.iter().enumerate() {
            self.t.word_ext(w, style, i == last && n.flags.eos);
        }
    }

    fn words_of(&mut self, n: &Node, style: Style) {
        for c in &n.children {
            self.node(c, style);
        }
    }

    fn elem(&mut self, n: &Node, style: Style) {
        // An element's font replaces the enclosing one, as in mandoc.
        let bold = Style::Bold;
        let under = Style::Under;
        match n.tok.as_str() {
            "Pp" => self.t.vspace(),
            "sp" => self.t.vspace(),
            "br" => self.t.flush(),
            "Fl" => {
                let mut first = true;
                for c in &n.children {
                    if c.kind == Kind::Text {
                        if !first && !c.flags.nospace {
                            // Each word is its own flag.
                        }
                        if c.flags.nospace {
                            self.t.nospace();
                        }
                        let w = format!("{}{}", mark::MINUS, c.text);
                        self.t.word_ext(&w, bold, c.flags.eos);
                        first = false;
                    } else {
                        self.node(c, bold);
                    }
                }
                if n.children.is_empty() {
                    self.t.word(&mark::MINUS.to_string(), bold);
                }
            }
            "Nm" => {
                if n.children.is_empty() {
                    let name = self.meta.name.clone();
                    self.t.word(&name, bold);
                } else {
                    self.words_of(n, bold);
                }
            }
            "Cm" | "Ic" | "Sy" | "Fd" | "Cd" | "Ms" => self.words_of(n, bold),
            "Ar" | "Pa" | "Va" | "Fa" | "Em" | "Ft" | "Ad" | "Vt" | "Mt" | "Lk" => self.words_of(n, under),
            "Xr" => {
                let name = n.args.first().cloned().unwrap_or_default();
                let w = match n.args.get(1) {
                    Some(sec) => format!("{name}({sec})"),
                    None => name,
                };
                self.t.word(&w, style);
            }
            "Ox" | "Nx" | "Fx" | "Dx" | "Bsx" | "Bx" | "Ux" | "At" | "St" => {
                let text = os_name(&n.tok, &n.args);
                for (i, w) in text.split(' ').enumerate() {
                    if i > 0 {
                        // Words of one expansion stay together on a line where they fit.
                    }
                    self.t.word(w, style);
                }
            }
            "Ex" => {
                let name = n.children.iter().filter(|c| c.kind == Kind::Text && c.text != "-std").map(|c| c.text.clone()).next().unwrap_or_else(|| self.meta.name.clone());
                self.t.word("The", style);
                self.t.word(&name, bold);
                for w in "utility exits 0 on success, and >0 if an error occurs.".split(' ') {
                    self.t.word_ext(w, style, w.ends_with("occurs."));
                }
            }
            _ => self.words_of(n, style),
        }
    }

    fn block(&mut self, n: &Node, style: Style) {
        match n.tok.as_str() {
            "Sh" => self.section(n, 0),
            "Ss" => self.section(n, SS_INDENT),
            "Nd" => {
                self.t.word("\u{2013}", style);
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, style);
                }
            }
            "Nm" => self.synopsis_nm(n),
            "Bl" => self.list(n),
            "Bd" => self.display(n),
            "D1" | "Dl" => {
                self.t.flush();
                let saved = self.t.offset;
                self.t.offset += 6;
                let nofill = self.t.nofill;
                if n.tok == "Dl" {
                    self.t.nofill = true;
                }
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, if n.tok == "Dl" { style } else { style });
                }
                self.t.flush();
                self.t.nofill = nofill;
                self.t.set_offset(saved);
            }
            "Bf" => {
                let s = if has_flag(&n.args, "-symbolic") || has_flag(&n.args, "Sy") {
                    Style::Bold
                } else if has_flag(&n.args, "-emphasis") || has_flag(&n.args, "Em") {
                    Style::Under
                } else {
                    Style::None
                };
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, style.with(s));
                }
            }
            "Fo" => {
                let name = n.text.clone();
                self.t.word(&name, style.with(Style::Bold));
                self.t.nospace();
                self.t.word("(", style);
                self.t.nospace();
                if let Some(b) = n.part(Kind::Body) {
                    let mut first = true;
                    for c in &b.children {
                        if !first {
                            self.t.nospace();
                            self.t.word(",", style);
                        }
                        self.node(c, style);
                        first = false;
                    }
                }
                self.t.nospace();
                self.t.word(")", style);
            }
            _ if n.args.len() == 2 && n.part(Kind::Body).is_some() => {
                // Enclosures: `.Op`, `.Dq`, `.Oo`...
                let (open, close) = (n.args[0].clone(), n.args[1].clone());
                // The enclosing text takes the surrounding style (bold in a SYNOPSIS head).
                if !open.is_empty() {
                    self.t.word(&open, style);
                    self.t.nospace();
                }
                self.children(n.part(Kind::Body).unwrap(), style);
                if !close.is_empty() {
                    self.t.nospace();
                    self.t.word(&close, style);
                }
            }
            _ => {
                for part in &n.children {
                    self.children(part, style);
                }
            }
        }
    }

    fn section(&mut self, n: &Node, indent: usize) {
        self.t.flush();
        self.t.no_vspace = false;
        self.t.vspace();
        self.t.set_offset(indent);
        if let Some(h) = n.part(Kind::Head) {
            self.synopsis = n.tok == "Sh" && h.plain_text() == "SYNOPSIS" || (n.tok == "Ss" && self.synopsis);
            self.children(h, Style::Bold);
        }
        self.t.flush();
        self.t.set_offset(INDENT);
        self.t.no_vspace = true;
        if let Some(b) = n.part(Kind::Body) {
            self.children(b, Style::None);
        }
        self.t.flush();
    }

    fn synopsis_nm(&mut self, n: &Node) {
        self.t.flush();
        let saved = self.t.offset;
        let name = n.part(Kind::Head).and_then(|h| h.children.first()).map(|e| e.plain_text()).filter(|s| !s.is_empty()).unwrap_or_else(|| self.meta.name.clone());
        if let Some(h) = n.part(Kind::Head) {
            self.children(h, Style::Bold);
        } else {
            self.t.word(&name, Style::Bold);
        }
        self.t.set_offset(saved + name.chars().count() + 1);
        if let Some(b) = n.part(Kind::Body) {
            self.children(b, Style::None);
        }
        self.t.flush();
        self.t.set_offset(saved);
    }

    fn list(&mut self, n: &Node) {
        let ltype = list_type(&n.args).to_string();
        let compact = has_flag(&n.args, "-compact");
        self.t.flush();
        if !compact {
            self.t.vspace();
        }
        let saved = (self.t.offset, self.t.rmargin);
        let base = self.t.offset + option(&n.args, "-offset").map(offset_of).unwrap_or(0);
        let width = match option(&n.args, "-width") {
            Some(w) => scaled(w) + 2,
            None => match ltype.as_str() {
                "-bullet" | "-dash" | "-hyphen" => 4,
                "-enum" => 5,
                _ => 8,
            },
        };
        let items: Vec<&Node> = n.part(Kind::Body).map(|b| b.children.iter().filter(|c| c.kind == Kind::Block && c.tok == "It").collect()).unwrap_or_default();
        let mut number = 0;
        for (i, it) in items.iter().enumerate() {
            if i > 0 && !compact && ltype != "-column" {
                self.t.vspace();
            }
            self.t.set_offset(base);
            let head = it.part(Kind::Head);
            let body = it.children.iter().find(|c| c.kind == Kind::Body);
            match ltype.as_str() {
                "-tag" | "-hang" => {
                    if let Some(h) = head {
                        self.children(h, Style::None);
                    }
                    let col = self.t.flush_open();
                    if col + 2 <= base + width {
                        self.t.pad_to(base + width);
                    } else if ltype == "-tag" {
                        self.t.flush();
                    }
                    self.t.set_offset(base + width);
                }
                "-bullet" | "-dash" | "-hyphen" | "-enum" => {
                    let mark = match ltype.as_str() {
                        "-bullet" => "\u{2022}".to_string(),
                        "-enum" => {
                            number += 1;
                            format!("{number}.")
                        }
                        _ => "-".to_string(),
                    };
                    // Bullets and dashes are bold; numbers are not.
                    let st = if ltype == "-enum" { Style::None } else { Style::Bold };
                    self.t.word(&mark, st);
                    self.t.flush_open();
                    self.t.pad_to(base + width);
                    self.t.set_offset(base + width);
                }
                "-ohang" => {
                    if let Some(h) = head {
                        self.children(h, Style::None);
                    }
                    self.t.flush();
                }
                "-inset" => {
                    if let Some(h) = head {
                        self.children(h, Style::None);
                    }
                }
                "-diag" => {
                    if let Some(h) = head {
                        self.children(h, Style::Bold);
                    }
                    let col = self.t.flush_open();
                    self.t.pad_to(col + 2);
                }
                "-column" => {
                    self.column_row(n, it, base);
                    continue;
                }
                _ => {}
            }
            if let Some(b) = body {
                self.children(b, Style::None);
            }
            self.t.flush();
        }
        self.t.flush();
        self.t.set_offset(saved.0);
        self.t.set_rmargin(saved.1);
    }

    fn column_row(&mut self, bl: &Node, it: &Node, base: usize) {
        // Column widths: the arguments after -column, each the width of its string.
        let mut widths: Vec<usize> = Vec::new();
        let mut after = false;
        for a in &bl.args {
            if a == "-column" {
                after = true;
                continue;
            }
            if after {
                if a.starts_with('-') && matches!(a.as_str(), "-compact" | "-offset") {
                    break;
                }
                widths.push(scaled(a));
            }
        }
        let cells: Vec<&Node> = it.children.iter().filter(|c| c.kind == Kind::Body).collect();
        let mut col = base;
        for (i, cell) in cells.iter().enumerate() {
            let w = widths.get(i).copied().unwrap_or(10);
            self.t.set_offset(col);
            if i > 0 {
                let cur = self.t.flush_open();
                if cur + 1 > col {
                    self.t.flush();
                    self.t.set_offset(col);
                }
                self.t.pad_to(col);
            }
            self.children(cell, Style::None);
            col += w + 4;
        }
        self.t.flush();
    }

    fn display(&mut self, n: &Node) {
        self.t.flush();
        if !has_flag(&n.args, "-compact") {
            self.t.vspace();
        }
        let saved = self.t.offset;
        self.t.offset += option(&n.args, "-offset").map(offset_of).unwrap_or(0);
        let nofill = self.t.nofill;
        self.t.nofill = has_flag(&n.args, "-literal") || has_flag(&n.args, "-unfilled");
        if let Some(b) = n.part(Kind::Body) {
            self.children(b, Style::None);
        }
        self.t.flush();
        self.t.nofill = nofill;
        self.t.set_offset(saved);
    }
}

/// The text of `.Ox`, `.Bx`, `.At`, `.St` and friends.
fn os_name(tok: &str, args: &[String]) -> String {
    let v = args.join(" ");
    match tok {
        "Ox" => if v.is_empty() { "OpenBSD".into() } else { format!("OpenBSD {v}") },
        "Nx" => if v.is_empty() { "NetBSD".into() } else { format!("NetBSD {v}") },
        "Fx" => if v.is_empty() { "FreeBSD".into() } else { format!("FreeBSD {v}") },
        "Dx" => if v.is_empty() { "DragonFly".into() } else { format!("DragonFly {v}") },
        "Bsx" => if v.is_empty() { "BSD/OS".into() } else { format!("BSD/OS {v}") },
        "Ux" => "UNIX".into(),
        "Bx" => match (args.first(), args.get(1)) {
            (None, _) => "BSD".into(),
            (Some(a), None) => format!("{a}BSD"),
            (Some(a), Some(b)) => format!("{a}BSD-{b}"),
        },
        "At" => match args.first().map(String::as_str) {
            Some("v1") => "Version 1 AT&T UNIX".into(),
            Some("v2") => "Version 2 AT&T UNIX".into(),
            Some("v3") => "Version 3 AT&T UNIX".into(),
            Some("v4") => "Version 4 AT&T UNIX".into(),
            Some("v5") => "Version 5 AT&T UNIX".into(),
            Some("v6") => "Version 6 AT&T UNIX".into(),
            Some("v7") => "Version 7 AT&T UNIX".into(),
            Some("32v") => "Version 32V AT&T UNIX".into(),
            Some("III") => "AT&T System III UNIX".into(),
            Some("V") => "AT&T System V UNIX".into(),
            Some(r) if r.starts_with("V.") => format!("AT&T System V Release {} UNIX", &r[2..]),
            _ => "AT&T UNIX".into(),
        },
        "St" => crate::standards::name(args.first().map(String::as_str).unwrap_or("")).to_string(),
        _ => v,
    }
}
