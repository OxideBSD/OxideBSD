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
        _ => "",
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
        // Basic units, 24 to a column; an exact half rounds down, as mandoc's does.
        let units = match unit {
            "" | "n" | "m" => v * 24.0,
            "u" => v,
            "M" => v * 0.24,
            "i" => v * 240.0,
            "c" => v * 240.0 / 2.54,
            "p" => v * 240.0 / 72.0,
            "P" => v * 40.0,
            "v" => v * 40.0,
            _ => return s.chars().count(),
        };
        return (units / 24.0 + 0.4995).floor() as usize;
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
    /// The previous sibling's macro: SYNOPSIS spacing depends on it.
    prev: String,
    /// In AUTHORS: each `.An` starts a new line unless `.An -nosplit` was given.
    authors: bool,
    see_also: bool,
    split: Option<bool>,
    seen_an: bool,
    /// The input line of the last node rendered.
    last_line: usize,
}

pub fn render(doc: &Document, t: Term, synopsis_only: bool) -> String {
    if synopsis_only {
        // `man -h`: the SYNOPSIS section's body at the left margin, and nothing else.
        let mut r = R { t, meta: &doc.meta, synopsis: true, prev: String::new(), authors: false, see_also: false, split: None, seen_an: false, last_line: 0 };
        for sh in doc.root.children.iter().filter(|n| n.tok == "Sh") {
            if sh.part(Kind::Head).is_some_and(|h| h.plain_text() == "SYNOPSIS")
                && let Some(b) = sh.part(Kind::Body)
            {
                r.t.no_vspace = true;
                r.children(b, Style::None);
            }
        }
        r.t.flush();
        return r.t.finish();
    }
    let mut r = R { t, meta: &doc.meta, synopsis: false, prev: String::new(), authors: false, see_also: false, split: None, seen_an: false, last_line: 0 };
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
        let title = format!("{}({})", plain(&self.meta.title), plain(&self.meta.section));
        // An unknown section is its own volume name.
        let vol = match volume(&self.meta.section) {
            "" => plain(&self.meta.section),
            v => v.to_string(),
        };
        // `.Dt`'s third argument, an architecture or volume, follows in lower case.
        let vol = if self.meta.arch.is_empty() { vol } else { format!("{vol} ({})", self.meta.arch.to_lowercase()) };
        self.t.three_part(&title, &vol, &title);
        self.t.raw_blank();
    }

    fn footer(&mut self) {
        let os = if !self.meta.os.is_empty() {
            plain(&self.meta.os)
        } else if self.meta.os_given {
            crate::default_os()
        } else {
            String::new()
        };
        let date = plain(&crate::format_date(&self.meta.date));
        self.t.no_vspace = false;
        self.t.vspace();
        self.t.three_part(&os, &date, &os);
    }

    fn children(&mut self, n: &Node, style: Style) {
        for c in &n.children {
            self.node(c, style);
            // A trailing delimiter belongs to the macro before it.
            if !(c.kind == Kind::Text && c.flags.delim) {
                self.prev = if c.kind == Kind::Text { String::new() } else { c.tok.clone() };
            }
        }
    }

    fn node(&mut self, n: &Node, style: Style) {
        // In mdoc a font escape lasts only to the end of its own macro argument or text line.
        self.t.reset_font();
        // In no-fill mode every input line, macro lines included, is an output line.
        if self.t.nofill && n.line != self.last_line && self.last_line != 0 && n.kind != Kind::Text {
            self.t.flush();
        }
        self.last_line = n.line;
        if n.flags.nospace {
            self.t.nospace();
        }
        if n.kind == Kind::Text {
            return self.text(n, style);
        }
        // The arguments of these macros break at hyphens like text; nested macros' don't.
        let saved = self.t.hyph_args;
        if matches!(n.kind, Kind::Elem | Kind::Block) {
            self.t.hyph_args = matches!(n.tok.as_str(), "Nd" | "D1" | "Sh" | "Ss");
        }
        match n.kind {
            Kind::Elem => self.elem(n, style),
            Kind::Block => self.block(n, style),
            _ => self.children(n, style),
        }
        self.t.hyph_args = saved;
    }

    fn text(&mut self, n: &Node, style: Style) {
        text_node(&mut self.t, n, style);
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
            "sp" => self.t.blank_line(),
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
            "Cm" | "Ic" | "Sy" | "Cd" | "Ms" => self.words_of(n, bold),
            "Ar" | "Pa" | "Va" | "Fa" | "Em" | "Ad" | "Sx" | "Fr" | "%T" | "%B" | "%J" | "%I" => self.words_of(n, under),
            "Xr" => {
                let name = n.args.first().cloned().unwrap_or_default();
                let w = match n.args.get(1) {
                    Some(sec) => format!("{name}({sec})"),
                    None => name,
                };
                self.t.word(&w, style);
            }
            "Ox" | "Nx" | "Fx" | "Dx" | "Bsx" | "Bx" | "Ux" => {
                // A system and its version (`OpenBSD 3.0`) never break apart.
                let text = os_name(&n.tok, &n.args).replace(' ', &mark::NBSP.to_string());
                self.t.word(&text, style);
            }
            "At" | "St" => {
                for w in os_name(&n.tok, &n.args).split(' ') {
                    self.t.word(w, style);
                }
            }
            "Ex" | "Rv" => self.std_text(n, style),
            "In" => {
                let file = n.args.first().cloned().unwrap_or_default();
                if self.synopsis {
                    self.synopsis_pre("In");
                    self.t.word("#include", bold);
                    self.t.word(&format!("<{file}>"), bold);
                } else {
                    self.t.word("<", style);
                    self.t.nospace();
                    self.t.word(&file, under);
                    self.t.nospace();
                    self.t.word(">", style);
                }
            }
            "Ft" => {
                if self.synopsis {
                    self.synopsis_pre("Ft");
                    self.words_of(n, under);
                } else {
                    self.words_of(n, under);
                }
            }
            "Fd" => {
                if self.synopsis {
                    self.synopsis_pre("Fd");
                    self.words_of(n, bold);
                    self.t.flush();
                } else {
                    self.words_of(n, bold);
                }
            }
            "Vt" => {
                if self.synopsis {
                    self.synopsis_pre("Vt");
                }
                self.words_of(n, under);
            }
            "Fn" => {
                let name = n.args.first().cloned().unwrap_or_default();
                let args: Vec<String> = n.args.iter().skip(1).cloned().collect();
                self.function(&name, &args, None, style);
            }
            "Lb" => {
                let text = crate::libraries::name(n.args.first().map(String::as_str).unwrap_or(""));
                for w in text.split(' ') {
                    self.t.word(w, style);
                }
            }
            "Mt" => {
                for a in &n.args {
                    self.t.word(a, under);
                }
            }
            "Lk" => {
                let url = n.args.first().cloned().unwrap_or_default();
                let words: Vec<String> = n.args.iter().skip(1).flat_map(|a| a.split(' ').filter(|w| !w.is_empty()).map(String::from).collect::<Vec<_>>()).collect();
                for (i, w) in words.iter().enumerate() {
                    self.t.word(w, under);
                    if i + 1 == words.len() {
                        self.t.nospace();
                        self.t.word(":", style);
                    }
                }
                self.t.word(&url, bold);
            }
            "An" => {
                if let Some(mode) = n.args.first() {
                    self.split = Some(mode == "-split");
                    return;
                }
                if self.authors && self.seen_an && self.split != Some(false) {
                    self.t.flush();
                }
                self.seen_an = true;
                self.words_of(n, style);
            }
            _ => self.words_of(n, style),
        }
    }

    /// `name(arg, arg)`: `.Fn` and `.Fo`/`.Fc`. In SYNOPSIS it is its own paragraph (sharing
    /// one with a `.Ft` just before it) and ends with `;`.
    fn function(&mut self, name: &str, args: &[String], nodes: Option<&Node>, style: Style) {
        if self.synopsis {
            self.synopsis_pre("Fn");
        }
        // A prototype that wraps continues four columns in.
        let saved = self.t.offset;
        if self.synopsis {
            self.t.set_offset(saved + 4);
            self.t.begin_line_at(saved);
        }
        self.t.word(name, Style::Bold);
        self.t.nospace();
        self.t.word("(", style);
        let mut first = true;
        let mut arg = |r: &mut Self, words: Vec<String>| {
            if !first {
                r.t.nospace();
                r.t.word(",", style);
            } else {
                r.t.nospace();
            }
            first = false;
            // In SYNOPSIS an argument doesn't break across lines where it can be helped, and
            // keeps its spacing; elsewhere its words fill like any others.
            if r.synopsis {
                let joined = words.join(" ").replace(' ', &mark::NBSP.to_string());
                r.t.word(&joined, Style::Under);
            } else {
                for w in words.join(" ").split(' ').filter(|w| !w.is_empty()) {
                    r.t.word(w, Style::Under);
                }
            }
        };
        for a in args {
            arg(self, vec![a.clone()]);
        }
        if let Some(body) = nodes {
            for c in &body.children {
                if c.kind == Kind::Elem && c.tok == "Fa" {
                    for t in &c.children {
                        arg(self, vec![t.text.clone()]);
                    }
                } else {
                    self.node(c, Style::None);
                }
            }
        }
        self.t.nospace();
        self.t.word(")", style);
        if self.synopsis {
            self.t.nospace();
            self.t.word(";", Style::None);
            self.t.flush();
            self.t.set_offset(saved);
        }
    }

    /// Spacing before a SYNOPSIS macro, as in mandoc: after a different declaration macro a
    /// blank line, after the same one (or `.Ft` before a function) a line break, after anything
    /// else a line break.
    fn synopsis_pre(&mut self, tok: &str) {
        let prev = self.prev.as_str();
        let decl = matches!(prev, "In" | "Fd" | "Fn" | "Fo" | "Ft" | "Vt" | "Cd");
        let same = prev == tok && tok != "Fn";
        let ft_fn = prev == "Ft" && tok == "Fn";
        if decl && !same && !ft_fn {
            self.t.vspace();
        } else {
            self.t.flush();
        }
    }

    /// `.Ex -std` and `.Rv -std`: the standard exit-status and return-value sentences.
    fn std_text(&mut self, n: &Node, style: Style) {
        let mut names: Vec<String> = n.args.iter().filter(|a| *a != "-std").cloned().collect();
        let fns = n.tok == "Rv";
        if fns && names.is_empty() {
            // `.Rv -std` naming no function.
            for w in "Upon successful completion, the value\u{E002}0 is returned; otherwise the value\u{E002}-1 is returned and the global variable errno is set to indicate the error.".split(' ') {
                let st = if w == "errno" { Style::Under } else { style };
                self.t.word_ext(w, st, w == "error.");
            }
            return;
        }
        if names.is_empty() {
            names.push(self.meta.name.clone());
        }
        self.t.word("The", style);
        let count = names.len();
        for (i, name) in names.iter().enumerate() {
            if fns {
                self.t.word(name, Style::Bold);
                self.t.nospace();
                self.t.word("()", style);
            } else {
                self.t.word(name, Style::Bold);
            }
            if count > 2 && i + 1 < count {
                self.t.nospace();
                self.t.word(",", style);
            }
            if count > 1 && i + 2 == count {
                self.t.word("and", style);
            }
        }
        let rest = match (fns, count > 1) {
            (false, false) => "utility exits 0 on success, and >0 if an error occurs.",
            (false, true) => "utilities exit 0 on success, and >0 if an error occurs.",
            (true, false) => "function returns the value\u{E002}0 if successful; otherwise the value\u{E002}-1 is returned and the global variable errno is set to indicate the error.",
            (true, true) => "functions return the value\u{E002}0 if successful; otherwise the value\u{E002}-1 is returned and the global variable errno is set to indicate the error.",
        };
        for w in rest.split(' ') {
            let st = if w == "errno" { Style::Under } else { style };
            self.t.word_ext(w, st, w.ends_with("occurs.") || w.ends_with("error."));
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
                // `.Dl` is one line of literal text, but its words come from macro arguments,
                // so they still fill and wrap.
                let nofill = self.t.nofill;
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, if n.tok == "Dl" { style } else { style });
                }
                self.t.flush();
                self.t.nofill = nofill;
                self.t.set_offset(saved);
            }
            "Bk" => {
                if let Some(b) = n.part(Kind::Body) {
                    if has_flag(&n.args, "-words") {
                        self.kept_lines(b, style);
                    } else {
                        self.children(b, style);
                    }
                }
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
            "Rs" => self.reference(n, style),
            "Fo" => {
                let name = n.text.clone();
                self.function(&name, &[], n.part(Kind::Body), style);
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

    /// A `.Rs` reference: its fields in a fixed order, separated by commas, ending with a period.
    /// In SEE ALSO each reference is its own paragraph.
    fn reference(&mut self, n: &Node, style: Style) {
        let Some(body) = n.part(Kind::Body) else { return };
        let field = |tok: &str| -> Vec<String> {
            body.children.iter().filter(|c| c.tok == tok).map(|c| c.plain_text()).collect()
        };
        if self.see_also {
            self.t.vspace();
        }
        let quoted_title = !field("%B").is_empty() || !field("%J").is_empty();
        let mut parts: Vec<(Vec<String>, Style, bool, bool)> = Vec::new();
        let authors = field("%A");
        if !authors.is_empty() {
            let mut text = Vec::new();
            for (i, a) in authors.iter().enumerate() {
                if i > 0 && authors.len() > 2 {
                    text.push(",".to_string());
                }
                if i > 0 && i + 1 == authors.len() {
                    text.push(" and".to_string());
                }
                text.push(format!(" {a}"));
            }
            parts.push((vec![text.concat().trim_start().to_string()], style, false, false));
        }
        for tok in ["%T", "%B", "%I", "%J", "%R", "%N", "%V", "%U", "%P", "%Q", "%C", "%D", "%O"] {
            for v in field(tok) {
                let (st, quote) = match tok {
                    "%T" if quoted_title => (style, true),
                    "%T" | "%B" | "%I" | "%J" => (Style::Under, false),
                    _ => (style, false),
                };
                // Titles, numbers and notes break at hyphens like text.
                parts.push((vec![v], st, quote, matches!(tok, "%T" | "%B" | "%R" | "%N" | "%O")));
            }
        }
        let count = parts.len();
        for (i, (texts, st, quote, hyph)) in parts.into_iter().enumerate() {
            let text = texts.concat();
            let words: Vec<&str> = text.split(' ').filter(|w| !w.is_empty()).collect();
            let last_part = i + 1 == count;
            for (k, w) in words.iter().enumerate() {
                let mut word = w.to_string();
                if quote && k == 0 {
                    word = format!("\u{201C}{word}");
                }
                if quote && k + 1 == words.len() {
                    word.push('\u{201D}');
                }
                // Punctuation after a styled word isn't styled.
                if hyph {
                    self.t.hyphenate_next();
                }
                self.t.word(&word, st);
                if k + 1 == words.len() {
                    self.t.nospace();
                    self.t.word_ext(if last_part { "." } else { "," }, style, last_part);
                }
            }
        }
    }

    fn section(&mut self, n: &Node, indent: usize) {
        self.t.flush();
        // A subsection first in its section follows the heading directly.
        if n.tok == "Sh" {
            self.t.no_vspace = false;
        }
        self.t.vspace();
        self.t.set_offset(indent);
        if let Some(h) = n.part(Kind::Head) {
            self.synopsis = n.tok == "Sh" && h.plain_text() == "SYNOPSIS" || (n.tok == "Ss" && self.synopsis);
            if n.tok == "Sh" {
                self.authors = h.plain_text() == "AUTHORS";
                self.see_also = h.plain_text() == "SEE ALSO";
                self.seen_an = false;
            }
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

    /// Children, keeping the words of each input line together (`.Bk -words`): the line may
    /// break between input lines but not within one.
    fn kept_lines(&mut self, n: &Node, style: Style) {
        let mut line = None;
        for c in &n.children {
            if c.kind == Kind::Block && spans_lines(c) {
                // A block over several input lines keeps its own lines.
                if line.take().is_some() {
                    self.t.keep_end();
                }
                if c.tok == "Bk" || c.tok == "Nm" {
                    self.node(c, style);
                } else {
                    for part in &c.children {
                        let _ = part;
                    }
                    self.node(c, style);
                }
                self.prev = c.tok.clone();
                continue;
            }
            if line != Some(c.line) {
                if line.is_some() {
                    self.t.keep_end();
                }
                self.t.keep_begin();
                line = Some(c.line);
            }
            self.node(c, style);
            if !(c.kind == Kind::Text && c.flags.delim) {
                self.prev = if c.kind == Kind::Text { String::new() } else { c.tok.clone() };
            }
        }
        if line.is_some() {
            self.t.keep_end();
        }
    }

    fn synopsis_nm(&mut self, n: &Node) {
        self.t.flush();
        let saved = self.t.offset;
        let name = n.part(Kind::Head).and_then(|h| h.children.first()).map(|e| e.plain_text()).filter(|s| !s.is_empty()).unwrap_or_else(|| self.meta.name.clone());
        // A SYNOPSIS name block keeps each input line's words together, as `.Bk -words` does.
        if let Some(h) = n.part(Kind::Head) {
            self.kept_lines(h, Style::Bold);
        } else {
            self.t.word(&name, Style::Bold);
        }
        self.t.set_offset(saved + name.chars().count() + 1);
        if let Some(b) = n.part(Kind::Body) {
            self.kept_lines(b, Style::None);
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
                    // A head too long for one line continues at the body's column.
                    self.t.set_offset(base + width);
                    self.t.begin_line_at(base);
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
        // A row is a line even when all its cells are empty.
        self.t.keep_line();
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
            Some("v1") => "Version\u{E002}1 AT&T UNIX".into(),
            Some("v2") => "Version\u{E002}2 AT&T UNIX".into(),
            Some("v3") => "Version\u{E002}3 AT&T UNIX".into(),
            Some("v4") => "Version\u{E002}4 AT&T UNIX".into(),
            Some("v5") => "Version\u{E002}5 AT&T UNIX".into(),
            Some("v6") => "Version\u{E002}6 AT&T UNIX".into(),
            Some("v7") => "Version\u{E002}7 AT&T UNIX".into(),
            Some("32v") => "Version\u{E002}32V AT&T UNIX".into(),
            Some("III") => "AT&T System\u{E002}III UNIX".into(),
            Some("V") => "AT&T System\u{E002}V UNIX".into(),
            Some(r) if r.starts_with("V.") => format!("AT&T System\u{E002}V Release\u{E002}{} UNIX", &r[2..]),
            _ => "AT&T UNIX".into(),
        },
        "St" => crate::standards::name(args.first().map(String::as_str).unwrap_or("")).to_string(),
        _ => v,
    }
}

/// A text node on the terminal: in fill mode its words, with the spacing typed between them,
/// breaking before a line that starts with spaces; in no-fill mode the line as typed. Shared by
/// the mdoc and man renderers.
pub fn text_node(t: &mut Term, n: &Node, style: Style) {
    if t.nofill {
        if n.flags.line_start && !n.flags.continues && !t.at_line_start() {
            t.flush();
        }
        // Spaces are kept as they are; an overlong line still wraps.
        let text = &n.text;
        let lead = text.len() - text.trim_start_matches(' ').len();
        if lead > 0 {
            let at = t.offset + lead;
            t.begin_line_at(at);
        }
        let mut spaces = 0;
        let mut first = true;
        for w in text.trim_start_matches(' ').split(' ') {
            if w.is_empty() {
                spaces += 1;
                continue;
            }
            if !first {
                t.set_space(spaces + 1);
            }
            t.word(w, style);
            spaces = 0;
            first = false;
        }
        if first {
            // An empty line.
            t.word("", style);
        }
        return;
    }
    if !n.flags.line_start && (n.text.starts_with(' ') || n.text.ends_with(' ')) && n.text.trim() != "" {
        // A macro argument with spaces at its edges (`.Dq "Password: "`) keeps them.
        let lead = n.text.len() - n.text.trim_start_matches(' ').len();
        let trail = n.text.len() - n.text.trim_end_matches(' ').len();
        let words: Vec<&str> = n.text.split(' ').filter(|w| !w.is_empty()).collect();
        let last = words.len().saturating_sub(1);
        for (i, w) in words.iter().enumerate() {
            let mut word = w.to_string();
            if i == 0 {
                word = format!("{}{word}", mark::NBSP.to_string().repeat(lead));
            }
            if i == last {
                word.push_str(&mark::NBSP.to_string().repeat(trail));
            }
            t.word_ext(&word, style, i == last && n.flags.eos);
        }
        return;
    }
    let text = n.text.trim_end_matches([' ', '\t']);
    if n.flags.line_start && text.starts_with(' ') {
        // A line starting with spaces breaks, and its first output line is indented by them.
        let lead = text.len() - text.trim_start_matches(' ').len();
        t.leading_space(lead);
    }
    let text = text.trim_start_matches(' ');
    // Spaces between words are kept as typed, as roff does in fill mode.
    let mut words: Vec<(&str, usize)> = Vec::new();
    let mut spaces = 0;
    for w in text.split(' ') {
        if w.is_empty() {
            spaces += 1;
            continue;
        }
        words.push((w, spaces + 1));
        spaces = 0;
    }
    let last = words.len().saturating_sub(1);
    for (i, (w, sp)) in words.iter().enumerate() {
        if i > 0 {
            t.set_space(*sp);
        }
        // Only a text line's hyphens are break points, not a macro argument's (with a few
        // exceptions, see `hyph_args`).
        if n.flags.line_start || t.hyph_args {
            t.hyphenate_next();
        }
        t.word_ext(w, style, i == last && n.flags.eos);
    }
}

/// Whether any node under `n` comes from a later input line than `n` itself.
fn spans_lines(n: &Node) -> bool {
    fn max_line(n: &Node) -> usize {
        n.children.iter().map(max_line).max().unwrap_or(0).max(n.line)
    }
    max_line(n) > n.line
}

/// Prologue text with roff's escape markers resolved, for the header and footer.
fn plain(s: &str) -> String {
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
