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
    if raw.len() > 80 && raw.contains(' ') && !raw.starts_with([' ', '\\']) {
        let start: String = raw.chars().take(20).collect();
        // (mandoc reports the input's last line one column further.)
        diag.report(Level::Style, line, raw.len() + last as usize, "input text line longer than 80 bytes", &format!("{start}..."));
    }
    if let Some(p) = raw.find('\t') {
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

/// What came last in the flow of a man(7) page, for its paragraph checks. Deleting a skipped
/// macro doesn't change it, except that a `.br` before `.sp` is gone before the `.sp` is judged.
#[derive(Clone, Debug, PartialEq)]
enum Prev {
    /// The start of a section (`SH`) or subsection (`SS`).
    Section(&'static str),
    /// A paragraph macro (`PP` for `LP`/`P` too, or `IP`).
    Para(&'static str),
    Sp,
    /// A `.br` at its line and column, and what came before it. Whether it is skipped is
    /// decided by what comes next.
    Br { line: usize, col: usize, before: Box<Prev> },
    /// A `.br` already judged, and whether it was skipped.
    BrDone(bool),
    Other,
}

/// The open paragraph: its macro, position, the section it starts (if it is first in one),
/// and whether anything has been put in it.
struct Para {
    name: &'static str,
    line: usize,
    col: usize,
    at_start: Option<&'static str>,
    content: bool,
}

/// mandoc's checks on man(7) paragraph macros and breaks that do nothing: a break or paragraph
/// at the start of a section, one right after another, an empty paragraph. Fed the page's lines
/// in order.
pub struct ManFlow {
    prev: Prev,
    para: Option<Para>,
    /// The current section macro, for "at the end of" messages.
    section: &'static str,
}

impl Default for ManFlow {
    fn default() -> Self {
        ManFlow { prev: Prev::Other, para: None, section: "SH" }
    }
}

const SKIP: &str = "skipping paragraph macro";

impl ManFlow {
    /// A macro line: `name` at `line`:`col`, with or without arguments.
    pub fn macro_line(&mut self, diag: &mut Diagnostics, name: &str, line: usize, col: usize, has_args: bool) {
        if name != "sp" {
            self.resolve_br(diag, name == "SH" || name == "SS");
        }
        match name {
            "SH" | "SS" => {
                self.end_section(diag);
                let s = if name == "SH" { "SH" } else { "SS" };
                self.section = s;
                self.prev = Prev::Section(s);
            }
            "RE" => {
                self.close_para(diag);
                self.prev = Prev::Other;
            }
            "PP" | "LP" | "P" | "IP" => {
                self.close_para(diag);
                let name = if name == "IP" { "IP" } else { "PP" };
                let at_start = match self.prev {
                    Prev::Section(s) if name == "PP" => Some(s),
                    _ => None,
                };
                // An `.IP` with a tag isn't empty.
                self.para = Some(Para { name, line, col, at_start, content: false });
                if name == "IP" && has_args {
                    self.content(diag);
                }
                self.prev = Prev::Para(name);
            }
            "TP" | "TQ" | "HP" => {
                self.close_para(diag);
                self.prev = Prev::Other;
            }
            "sp" => self.sp(diag, line, col),
            "br" => {
                let before = Box::new(std::mem::replace(&mut self.prev, Prev::Other));
                self.prev = Prev::Br { line, col, before };
            }
            _ => {
                self.content(diag);
                self.prev = Prev::Other;
            }
        }
    }

    /// A blank line: `.sp`, except at the start of a section, where it is ignored.
    pub fn blank(&mut self, diag: &mut Diagnostics, line: usize) {
        if !matches!(self.prev, Prev::Section(_)) {
            // (A `.br` before it is judged by `sp`.)
            self.sp(diag, line, 1);
        }
    }

    pub fn text(&mut self, diag: &mut Diagnostics, raw: &str) {
        if let Prev::Br { line, col, .. } = self.prev
            && raw.starts_with(' ')
            && !self.br_skipped()
        {
            diag.report(Level::Warning, line, col, SKIP, "br before text line with leading blank");
            self.prev = Prev::BrDone(true);
        }
        self.resolve_br(diag, false);
        self.content(diag);
        self.prev = Prev::Other;
    }

    /// The end of the input.
    pub fn end(&mut self, diag: &mut Diagnostics) {
        self.resolve_br(diag, true);
        self.end_section(diag);
    }

    /// What a pending `.br` comes after, if that makes it useless.
    fn br_after(before: &Prev) -> Option<&'static str> {
        match before {
            Prev::Section(s) | Prev::Para(s) => Some(s),
            Prev::Br { .. } | Prev::BrDone(_) => Some("br"),
            Prev::Sp => Some("sp"),
            Prev::Other => None,
        }
    }

    fn br_skipped(&self) -> bool {
        matches!(&self.prev, Prev::Br { before, .. } if Self::br_after(before).is_some())
    }

    /// Judges a pending `.br` by what came before it, now that something other than `.sp`
    /// follows; at the end of a section, a `.br` not otherwise skipped is.
    fn resolve_br(&mut self, diag: &mut Diagnostics, section_end: bool) {
        let Prev::Br { line, col, before } = &self.prev else { return };
        let (line, col) = (*line, *col);
        let skipped = match Self::br_after(before) {
            Some(w) => {
                diag.report(Level::Warning, line, col, SKIP, &format!("br after {w}"));
                true
            }
            None if section_end => {
                diag.report(Level::Warning, line, col, SKIP, &format!("br at the end of {}", self.section));
                true
            }
            None => {
                self.content(diag);
                false
            }
        };
        self.prev = Prev::BrDone(skipped);
    }

    fn sp(&mut self, diag: &mut Diagnostics, line: usize, col: usize) {
        let mut prev = std::mem::replace(&mut self.prev, Prev::Sp);
        if let Prev::Br { line: l, col: c, before } = prev {
            diag.report(Level::Warning, l, c, SKIP, "br before sp");
            prev = *before;
        }
        match prev {
            Prev::Section(s) | Prev::Para(s) => diag.report(Level::Warning, line, col, SKIP, &format!("sp after {s}")),
            _ => self.content(diag),
        }
    }

    fn end_section(&mut self, diag: &mut Diagnostics) {
        self.close_para(diag);
    }

    /// Something in the open paragraph: it isn't empty, and one first in its section is
    /// reported as useless there.
    fn content(&mut self, diag: &mut Diagnostics) {
        if let Some(p) = self.para.as_mut()
            && !p.content
        {
            p.content = true;
            if let Some(s) = p.at_start {
                diag.report(Level::Warning, p.line, p.col, SKIP, &format!("PP after {s}"));
            }
        }
    }

    /// Ends the open paragraph; one with nothing in it is reported, and doesn't count as having
    /// started its section.
    fn close_para(&mut self, diag: &mut Diagnostics) {
        if let Some(p) = self.para.take()
            && !p.content
        {
            diag.report(Level::Warning, p.line, p.col, SKIP, &format!("{} empty", p.name));
            if let Some(s) = p.at_start {
                self.prev = Prev::Section(s);
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
