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
