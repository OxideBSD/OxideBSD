//! Checks of input lines as typed (MAN.md §6), made where mandoc makes them so that the same
//! page lints the same way with either. Columns are 1-based byte positions.

use crate::diag::{Diagnostics, Level};

/// The checks on a text line, before its escapes are decoded. `literal` is no-fill mode;
/// `mdoc` enables the checks only mdoc(7) makes.
pub fn text_line(diag: &mut Diagnostics, line: usize, raw: &str, last: bool, literal: bool, mdoc: bool) {
    if literal {
        return;
    }
    // A line that could have been broken earlier: longer than 80 bytes, with a space in it
    // (and not starting with one, or with an escape).
    // (mandoc counts the input's last line one byte longer.)
    let len = raw.len() + last as usize;
    if len > 80 && raw.contains(' ') && !raw.starts_with([' ', '\\']) {
        let start: String = raw.chars().take(20).collect();
        diag.report(Level::Style, line, len, "input text line longer than 80 bytes", &format!("{start}..."));
    }
    for (p, _) in raw.match_indices('\t') {
        diag.report(Level::Warning, line, p + 1, "tab in filled text", "");
    }
    if mdoc {
        new_sentence(diag, line, raw);
    }
}

/// A sentence that doesn't start on a new line: a period after two letters or digits (but not
/// "Inc." or "vs."), then one to three spaces and a capital letter.
fn new_sentence(diag: &mut Diagnostics, line: usize, raw: &str) {
    let b = raw.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c != b'.' || i < 2 || !b[i - 2].is_ascii_alphanumeric() || !b[i - 1].is_ascii_alphanumeric() {
            continue;
        }
        if &b[i - 2..i] == b"nc" || &b[i - 2..i] == b"vs" {
            continue;
        }
        let mut j = i + 1;
        if b.get(j) != Some(&b' ') {
            continue;
        }
        j += 1;
        for _ in 0..2 {
            if b.get(j) == Some(&b' ') {
                j += 1;
            }
        }
        if b.get(j).is_some_and(|c| c.is_ascii_uppercase()) {
            diag.report(Level::Warning, line, j + 1, "new sentence, new line", "");
        }
    }
}

/// A child of a man(7) container, as far as the paragraph checks care.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Child {
    /// `.sp` or a blank line, at its line and column.
    Sp(usize, usize),
    /// `.br`, at its line and column.
    Br(usize, usize),
    /// A paragraph (`PP`) that turned out not to be empty.
    Para,
    Content,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    /// A section or subsection body: `SH` or `SS`.
    Section(&'static str),
    /// An `.RS` block.
    Rs,
    /// A paragraph, `PP` (for `LP`/`P` too) or `IP`, at the macro's line and column.
    Para(&'static str, usize, usize),
    /// A paragraph whose start isn't checked (`TP`, `HP`, `IP` with a tag).
    Other,
}

struct Container {
    kind: Kind,
    children: Vec<Child>,
}

/// mandoc's checks on man(7) paragraph macros and breaks that do nothing, fed the page's lines
/// in order. Some are made as a macro arrives (`.br` after `.br` or `.sp`, `.br` before `.sp`);
/// the rest when its paragraph or section ends, on what comes first or last in it.
pub struct ManFlow {
    stack: Vec<Container>,
}

impl Default for ManFlow {
    fn default() -> Self {
        // (Before the first `.SH`, as in a section without a name.)
        ManFlow { stack: vec![Container { kind: Kind::Other, children: Vec::new() }] }
    }
}

const SKIP: &str = "skipping paragraph macro";

impl ManFlow {
    /// A macro line: `name` at `line`:`col`, with or without arguments.
    pub fn macro_line(&mut self, diag: &mut Diagnostics, name: &str, line: usize, col: usize, has_args: bool) {
        match name {
            "SH" => {
                while !self.stack.is_empty() {
                    self.close(diag);
                }
                self.stack.push(Container { kind: Kind::Section("SH"), children: Vec::new() });
            }
            // A subsection is part of its section: it ends what is open inside the section.
            "SS" => {
                while self.stack.len() > 1 && self.stack.last().is_some_and(|c| c.kind != Kind::Section("SH")) {
                    self.close(diag);
                }
                self.top().children.push(Child::Content);
                self.stack.push(Container { kind: Kind::Section("SS"), children: Vec::new() });
            }
            "PP" | "LP" | "P" | "IP" | "TP" | "TQ" | "HP" => {
                self.close_para(diag);
                let kind = match name {
                    "IP" if has_args => Kind::Other,
                    "IP" => Kind::Para("IP", line, col),
                    "PP" | "LP" | "P" => Kind::Para("PP", line, col),
                    _ => Kind::Other,
                };
                if kind == Kind::Other {
                    self.top().children.push(Child::Content);
                }
                self.stack.push(Container { kind, children: Vec::new() });
            }
            "RS" => {
                self.top().children.push(Child::Content);
                self.stack.push(Container { kind: Kind::Rs, children: Vec::new() });
            }
            "RE" => {
                // Closes the innermost `.RS`; one with none open is a `.br`, after the paragraph.
                if let Some(pos) = self.stack.iter().rposition(|c| c.kind == Kind::Rs) {
                    while self.stack.len() > pos {
                        self.close(diag);
                    }
                } else {
                    self.close_para(diag);
                    self.br(diag, line, col);
                }
            }
            "sp" => self.sp(diag, line, col),
            "br" => self.br(diag, line, col),
            _ => self.top().children.push(Child::Content),
        }
    }

    /// A blank line: `.sp`, except first in a section, where it is ignored.
    pub fn blank(&mut self, diag: &mut Diagnostics, line: usize) {
        let top = self.stack.last().unwrap();
        if matches!(top.kind, Kind::Section(_)) && top.children.is_empty() {
            return;
        }
        self.sp(diag, line, 1);
    }

    pub fn text(&mut self, diag: &mut Diagnostics, raw: &str) {
        let top = self.top();
        if raw.starts_with(' ')
            && let Some(Child::Br(l, c)) = top.children.last().copied()
        {
            top.children.pop();
            diag.report(Level::Warning, l, c, SKIP, "br before text line with leading blank");
        }
        self.top().children.push(Child::Content);
    }

    /// The end of the input.
    pub fn end(&mut self, diag: &mut Diagnostics) {
        while !self.stack.is_empty() {
            self.close(diag);
        }
    }

    fn top(&mut self) -> &mut Container {
        self.stack.last_mut().unwrap()
    }

    fn sp(&mut self, diag: &mut Diagnostics, line: usize, col: usize) {
        let top = self.top();
        if let Some(Child::Br(l, c)) = top.children.last().copied() {
            top.children.pop();
            diag.report(Level::Warning, l, c, SKIP, "br before sp");
        }
        self.top().children.push(Child::Sp(line, col));
    }

    fn br(&mut self, diag: &mut Diagnostics, line: usize, col: usize) {
        match self.top().children.last() {
            Some(Child::Br(..)) => diag.report(Level::Warning, line, col, SKIP, "br after br"),
            Some(Child::Sp(..)) => diag.report(Level::Warning, line, col, SKIP, "br after sp"),
            _ => self.top().children.push(Child::Br(line, col)),
        }
    }

    /// Closes the open paragraph, if the innermost container is one.
    fn close_para(&mut self, diag: &mut Diagnostics) {
        if matches!(self.stack.last().map(|c| c.kind), Some(Kind::Para(..) | Kind::Other)) && self.stack.len() > 1 {
            self.close(diag);
        }
    }

    /// Ends the innermost container: a useless `.sp` or `.br` first in it, or `.br` last, and
    /// an empty paragraph, are reported and dropped.
    fn close(&mut self, diag: &mut Diagnostics) {
        let Some(mut c) = self.stack.pop() else { return };
        let name = match c.kind {
            Kind::Section(s) => s,
            Kind::Para(p, ..) => p,
            _ => "",
        };
        if !name.is_empty() {
            match c.children.first().copied() {
                Some(Child::Sp(l, col)) => {
                    diag.report(Level::Warning, l, col, SKIP, &format!("sp after {name}"));
                    c.children.remove(0);
                }
                Some(Child::Br(l, col)) => {
                    diag.report(Level::Warning, l, col, SKIP, &format!("br after {name}"));
                    c.children.remove(0);
                }
                Some(Child::Para) if matches!(c.kind, Kind::Section(_)) => {}
                _ => {}
            }
        }
        if let Kind::Section(s) = c.kind
            && let Some(Child::Br(l, col)) = c.children.last().copied()
        {
            diag.report(Level::Warning, l, col, SKIP, &format!("br at the end of {s}"));
        }
        let Some(parent) = self.stack.last_mut() else { return };
        if let Kind::Para(p, l, col) = c.kind {
            if c.children.is_empty() {
                diag.report(Level::Warning, l, col, SKIP, &format!("{p} empty"));
            } else {
                // A paragraph first in its section is useless (reported with the section).
                if p == "PP" && matches!(parent.kind, Kind::Section(_)) && parent.children.is_empty() {
                    diag.report(Level::Warning, l, col, SKIP, &format!("PP after {}", if let Kind::Section(s) = parent.kind { s } else { "" }));
                }
                parent.children.push(Child::Para);
            }
        }
    }
}

/// The 1-based columns of a macro line's arguments, from the line as typed (`raw`, starting
/// with the macro name at column `col`): where each argument, or its opening quote, starts.
pub fn arg_columns(raw: &str, col: usize) -> Vec<usize> {
    typed_args(raw, col).into_iter().map(|(c, _)| c).collect()
}

/// A macro line's arguments as typed, escapes and all, with their quotes removed (`""` inside
/// quotes is one quote), and the column each starts at (its opening quote, if quoted).
pub fn typed_args(raw: &str, col: usize) -> Vec<(usize, String)> {
    let b = raw.as_bytes();
    let mut i = b.iter().position(|c| *c == b' ' || *c == b'\t').unwrap_or(b.len());
    let mut args = Vec::new();
    loop {
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        let mut text = Vec::new();
        if b[i] == b'"' {
            i += 1;
            while i < b.len() {
                if b[i] == b'"' {
                    if b.get(i + 1) == Some(&b'"') {
                        text.push(b'"');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                let n = if b[i] == b'\\' { 2 } else { 1 }.min(b.len() - i);
                text.extend_from_slice(&b[i..i + n]);
                i += n;
            }
        } else {
            while i < b.len() && b[i] != b' ' && b[i] != b'\t' {
                let n = if b[i] == b'\\' { 2 } else { 1 }.min(b.len() - i);
                text.extend_from_slice(&b[i..i + n]);
                i += n;
            }
        }
        args.push((col + start, String::from_utf8_lossy(&text).into_owned()));
    }
    args
}

const MONTHS: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/// A man(7) date as mandoc reads it: `YYYY-MM-DD` as it is, or `Month D, YYYY` (any case, the
/// month in full or its first three letters) in canonical form, a day past the month's end
/// rolling over into the next. `None` if it is neither.
pub fn man_date(s: &str) -> Option<String> {
    if let Some(d) = iso_date(s) {
        return Some(d);
    }
    let (month, rest) = s.trim_start().split_once(|c: char| c == ' ' || c == '\t')?;
    let m = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(month) || (month.len() == 3 && m[..3].eq_ignore_ascii_case(month)))?;
    let (day, year) = rest.trim_start().split_once(',')?;
    let day: u32 = day.trim_end().parse().ok().filter(|d| (1..=31).contains(d))?;
    let year = year.trim_start();
    if year.is_empty() || !year.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let y: i64 = year.parse().ok()?;
    let (mut m, mut day) = (m, day);
    let mut y = y;
    let dim = |m: usize, y: i64| [31, if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m];
    while day > dim(m, y) {
        day -= dim(m, y);
        m += 1;
        if m == 12 {
            m = 0;
            y += 1;
        }
    }
    Some(format!("{} {day}, {y}", MONTHS[m]))
}

fn iso_date(s: &str) -> Option<String> {
    let mut it = s.split('-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    let digits = |p: &str, max: usize| !p.is_empty() && p.len() <= max && p.bytes().all(|c| c.is_ascii_digit());
    if it.next().is_some() || y.len() != 4 || !digits(y, 4) || !digits(m, 2) || !digits(d, 2) {
        return None;
    }
    let (m, d): (u32, u32) = (m.parse().ok()?, d.parse().ok()?);
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| s.to_string())
}

/// mandoc's checks of `.TH title section [date [source [volume]]]`, made on the arguments as
/// typed (a date written with `\-` doesn't parse).
pub fn man_th(diag: &mut Diagnostics, line: usize, col: usize, raw: &str) {
    let args = typed_args(raw, col);
    match args.first() {
        None => diag.report(Level::Warning, line, col, "missing manual title, using \"\"", "TH"),
        // (The column is where the argument starts, plus the letter's place in it unquoted.)
        Some((c, t)) => {
            if let Some(p) = t.find(|c: char| c.is_ascii_lowercase()) {
                diag.report(Level::Style, line, c + p, "lower case character in document title", &format!("TH {t}"));
            }
        }
    }
    if args.len() < 2 {
        let t = args.first().map(|(_, t)| t.as_str()).unwrap_or("");
        diag.report(Level::Warning, line, col, "missing manual section, using \"\"", &format!("TH {t}"));
    }
    match args.get(2) {
        None => diag.report(Level::Warning, line, col, "missing date, using \"\"", "TH"),
        Some((c, d)) if d.is_empty() => diag.report(Level::Warning, line, *c, "missing date, using \"\"", "TH"),
        Some((c, d)) => match man_date(d) {
            Some(n) if n != *d => diag.report(Level::Style, line, *c, "normalizing date format to", &format!("TH {n}")),
            Some(_) => {}
            None => diag.report(Level::Warning, line, *c, "cannot parse date, using it verbatim", &format!("TH {d}")),
        },
    }
    if let Some((c, extra)) = args.get(5) {
        diag.report(Level::Error, line, *c, "skipping excess arguments", &format!("TH ... {extra}"));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn arg_cols() {
        assert_eq!(super::arg_columns("TH \"Esys_ClearControl\" 3 \"Version 4.2.0\" \"tpm2-tss\"", 2), vec![5, 25, 27, 43]);
    }
}

/// mdoc macros whose last argument may not end with a closing delimiter joined to it
/// (`.Ar file.` instead of `.Ar file .`).
const DELIM_CHECKED: &[&str] = &[
    "Ad", "An", "Ar", "Cm", "Dv", "Er", "Ev", "Fa", "Fl", "Fn", "Ft", "Ic", "In", "Li", "Lk", "Mt", "Nm", "Pa", "Sy", "Va", "Vt", "Xr", "Ql", "Ms", "Em", "No", "Bx", "Dx", "Nx", "Ox", "Fx", "Lb", "Sq", "Pq", "Aq", "Qq", "Op", "Ot", "Bsx", "Brq",
];

/// mdoc macros whose arguments the delimiter message shows joined; the others show `...` and
/// the last one.
const JOINED: &[&str] = &["An", "Ic", "Li", "Sy", "Ql", "Em", "No", "Sq", "Pq", "Aq", "Qq", "Brq"];

/// Enclosures, whose argument is checked only at the end of the line.
const ENCLOSURES: &[&str] = &["Sq", "Pq", "Aq", "Qq", "Op", "Brq"];

/// mdoc macros taking a single argument; what follows is outside them.
const ONE_ARG: &[&str] = &["In", "Dx", "Nx", "Ox", "Fx", "Bsx"];

/// mandoc's checks of an mdoc macro line's arguments as typed: a closing delimiter joined to a
/// macro's last argument, and text ending in punctuation where it shouldn't. A description
/// (`.Nd`) ending so is returned rather than reported, since it may go on on the next line.
pub fn mdoc_args(diag: &mut Diagnostics, line: usize, col: usize, name: &str, raw: &str) -> Option<(usize, usize, String)> {
    let args = typed_args(raw, col);
    // Macros whose text shouldn't end with punctuation at all (unless it is a separate
    // argument).
    if matches!(name, "Nd" | "Sh" | "Ss" | "Sx" | "Rv" | "Ex" | "Fo") {
        // (A description may end in a closing bracket.)
        let delims: &[char] = if name == "Nd" { &['.', ',', ':', ';', '?', '!'] } else { &['.', ',', ':', ';', ')', ']', '?', '!'] };
        if let Some((c, last)) = args.last()
            && last.chars().count() > 1
            && last.ends_with(delims)
            && !(last.ends_with(')') && args.iter().any(|(_, a)| a.contains('(')))
        {
            let all: Vec<&str> = args.iter().map(|(_, a)| a.as_str()).collect();
            let found = (line, c + last.len() - 1, format!("{name} {}", all.join(" ")));
            if name == "Nd" {
                return Some(found);
            }
            diag.report(Level::Style, found.0, found.1, "trailing delimiter", &found.2);
        }
        return None;
    }
    // Each macro on the line, at its column, with its arguments, in order.
    let mut groups: Vec<(&str, Vec<(usize, &str)>)> = vec![(name, Vec::new())];
    let mut macro_cols = vec![col];
    for (c, a) in &args {
        if crate::mdoc::CALLABLE.contains(&a.as_str()) {
            groups.push((a.as_str(), Vec::new()));
            macro_cols.push(*c);
        } else {
            groups.last_mut().unwrap().1.push((*c, a.as_str()));
        }
    }
    for ((m, _), c) in groups.iter().zip(&macro_cols) {
        match *m {
            "Tn" | "Bt" | "Ud" => diag.report(Level::Style, line, *c, "useless macro", m),
            "Fr" | "Hf" | "Ot" | "Es" | "En" | "Db" => diag.report(Level::Warning, line, *c, "obsolete macro", m),
            _ => {}
        }
    }
    let n = groups.len();
    for (g, (m, margs)) in groups.iter().enumerate() {
        if !DELIM_CHECKED.contains(m) || (ENCLOSURES.contains(m) && g + 1 < n) {
            continue;
        }
        let shown = if *m == "Ot" { "Ft" } else { *m };
        // `.Fl` checks each argument, a one-argument macro its argument, the rest their last.
        let checked: Vec<(usize, (usize, &str))> = if *m == "Fl" {
            margs.iter().map(|a| (0, *a)).collect()
        } else if ONE_ARG.contains(m) {
            margs.first().map(|a| vec![(0, *a)]).unwrap_or_default()
        } else {
            margs.last().map(|a| vec![(margs.len() - 1, *a)]).unwrap_or_default()
        };
        for (i, (c, a)) in checked {
            let Some(d) = a.chars().last() else { continue };
            // (Not after `\&`, not an ellipsis `a..`, not a bracket closing one opened in the
            // same word.)
            let escaped = a.ends_with(&format!("\\&{d}"));
            let paired = (d == ')' && a.contains('(')) || (d == ']' && a.contains('['));
            // (And not after a character that is neither part of a word nor punctuation, as in
            // `*.`, or one escaped, as in `\e)`.)
            let before: Vec<char> = a.chars().rev().skip(1).take(2).collect();
            let odd = before.first().is_some_and(|c| !c.is_alphanumeric() && !".,:;)]?!|\\(".contains(*c));
            let after_escape = before.get(1) == Some(&'\\');
            if a.chars().count() < 2 || !".,:;)]?!|".contains(d) || escaped || a.ends_with("..") || paired || odd || after_escape {
                continue;
            }
            let what = if i == 0 {
                format!("{shown} {a}")
            } else if JOINED.contains(m) {
                let all: Vec<&str> = margs.iter().map(|(_, a)| *a).collect();
                format!("{shown} {}", all.join(" "))
            } else {
                format!("{shown} ... {a}")
            };
            diag.report(Level::Style, line, c + a.len() - 1, "no blank before trailing delimiter", &what);
        }
    }
    None
}

/// A cross-reference seen in SEE ALSO, for the order and punctuation checks: name, section,
/// column, and the punctuation after it with its column.
#[derive(Clone, Debug)]
struct Xref {
    line: usize,
    name: String,
    sec: String,
    punct: Option<(String, usize)>,
}

/// mdoc checks that need what came before: the page's own name and section, and the order and
/// punctuation of the cross-references in SEE ALSO.
#[derive(Default)]
pub struct MdocState {
    /// The current section's heading.
    section: String,
    /// The page's name (the first `.Nm`) and section (`.Dt`).
    name: Option<String>,
    dt_section: String,
    /// The last cross-reference in an unbroken run of them in SEE ALSO.
    last_xr: Option<Xref>,
    /// The prologue macros seen so far.
    seen_dt: bool,
    seen_os: bool,
}

impl MdocState {
    /// A macro line, with the macros it calls; `raw` is the line as typed from `name` on.
    pub fn macro_line(&mut self, diag: &mut Diagnostics, line: usize, col: usize, name: &str, raw: &str) {
        let args = typed_args(raw, col);
        match name {
            "Dd" => self.dd(diag, line, col, &args),
            "Dt" => self.dt(diag, line, col, &args),
            "Os" => self.seen_os = true,
            _ => {}
        }
        match name {
            "Sh" => {
                self.end_run(diag);
                self.section = args.iter().map(|(_, a)| a.as_str()).collect::<Vec<_>>().join(" ");
                return;
            }
            "Dt" => self.dt_section = args.get(1).map(|(_, a)| a.clone()).unwrap_or_default(),
            "Nm" if self.name.is_none() => self.name = args.first().map(|(_, a)| a.clone()),
            _ => {}
        }
        // Each macro on the line with its column and arguments.
        let mut groups: Vec<(&str, usize, Vec<(usize, &str)>)> = vec![(name, col, Vec::new())];
        for (c, a) in &args {
            if crate::mdoc::CALLABLE.contains(&a.as_str()) {
                groups.push((a.as_str(), *c, Vec::new()));
            } else {
                groups.last_mut().unwrap().2.push((*c, a.as_str()));
            }
        }
        for (m, mcol, margs) in groups {
            if m != "Xr" {
                // A block interrupting a run of cross-references ends it, as the section's end
                // does; a paragraph break or text just breaks it.
                if matches!(m, "Rs" | "Bl" | "Bd" | "Ss") {
                    self.end_run(diag);
                } else {
                    self.last_xr = None;
                }
                continue;
            }
            let (Some(&(nc, xname)), Some(&(_, sec))) = (margs.first(), margs.get(1)) else { continue };
            if self.name.as_deref() == Some(xname) && sec == self.dt_section {
                diag.report(Level::Warning, line, nc, "cross reference to self", &format!("Xr {xname} {sec}"));
            }
            if self.section != "SEE ALSO" {
                continue;
            }
            let punct = margs.get(2).map(|&(c, p)| (p.to_string(), c));
            if let Some(prev) = self.last_xr.take() {
                match &prev.punct {
                    None => diag.report(Level::Warning, line, mcol, "unusual Xr punctuation", &format!("none before {xname}({sec})")),
                    Some((p, _)) if p != "," => diag.report(Level::Warning, line, mcol, "unusual Xr punctuation", &format!("{p} before {xname}({sec})")),
                    _ => {}
                }
                if prev.sec == sec {
                    if xname.to_lowercase() < prev.name.to_lowercase() {
                        diag.report(Level::Warning, line, mcol, "unusual Xr order", &format!("{xname} after {}", prev.name));
                    }
                } else if sec < prev.sec.as_str() {
                    diag.report(Level::Warning, line, mcol, "unusual Xr order", &format!("{xname}({sec}) after {}({})", prev.name, prev.sec));
                }
            }
            self.last_xr = Some(Xref { line, name: xname.to_string(), sec: sec.to_string(), punct });
        }
    }

    /// A text line: it breaks a run of cross-references.
    pub fn text(&mut self) {
        self.last_xr = None;
    }

    /// The end of the input.
    pub fn end(&mut self, diag: &mut Diagnostics) {
        self.end_run(diag);
        if !self.seen_os {
            diag.report(Level::Warning, 0, 0, "missing Os macro, using \"\"", "");
        }
    }

    /// `.Dd date`: the date as `Month D, YYYY` or `$Mdocdate: Month D YYYY $`.
    fn dd(&mut self, diag: &mut Diagnostics, line: usize, col: usize, args: &[(usize, String)]) {
        if self.seen_dt || self.seen_os {
            let after = if self.seen_os { "Os" } else { "Dt" };
            diag.report(Level::Warning, line, col, "prologue macros out of order", &format!("Dd after {after}"));
        }
        let Some(&(c, _)) = args.first() else {
            diag.report(Level::Warning, line, col, "missing date, using \"\"", "Dd");
            return;
        };
        let date = args.iter().map(|(_, a)| a.as_str()).collect::<Vec<_>>().join(" ");
        if date.starts_with("$Mdocdate") {
            return;
        }
        if iso_date(&date).is_some() {
            diag.report(Level::Style, line, c, "legacy man(7) date format", &format!("Dd {date}"));
            return;
        }
        match man_date(&date) {
            Some(n) if n != date => diag.report(Level::Style, line, c, "normalizing date format to", &format!("Dd {n}")),
            Some(_) => {}
            None => diag.report(Level::Warning, line, c, "cannot parse date, using it verbatim", &format!("Dd {date}")),
        }
    }

    /// `.Dt TITLE section [arch]`.
    fn dt(&mut self, diag: &mut Diagnostics, line: usize, col: usize, args: &[(usize, String)]) {
        if self.seen_os {
            diag.report(Level::Warning, line, col, "prologue macros out of order", "Dt after Os");
        }
        self.seen_dt = true;
        let title = match args.first() {
            None => {
                diag.report(Level::Warning, line, col, "missing manual title, using UNTITLED", "Dt");
                "UNTITLED".to_string()
            }
            Some((c, t)) => {
                if let Some(p) = t.find(|c: char| c.is_ascii_lowercase()) {
                    diag.report(Level::Style, line, c + p, "lower case character in document title", &format!("Dt {t}"));
                }
                t.clone()
            }
        };
        match args.get(1) {
            None => diag.report(Level::Warning, line, col, "missing manual section, using \"\"", &format!("Dt {title}")),
            Some((c, sec)) if !matches!(sec.as_str(), "1" | "2" | "3" | "3p" | "4" | "5" | "6" | "7" | "8" | "9") => {
                diag.report(Level::Warning, line, *c, "unknown manual section", &format!("Dt ... {sec}"));
            }
            _ => {}
        }
    }

    /// The end of a run of cross-references: the last one takes no punctuation.
    fn end_run(&mut self, diag: &mut Diagnostics) {
        if let Some(Xref { line, name, sec, punct: Some((p, c)) }) = self.last_xr.take() {
            diag.report(Level::Warning, line, c, "unusual Xr punctuation", &format!("{p} after {name}({sec})"));
        }
    }
}
