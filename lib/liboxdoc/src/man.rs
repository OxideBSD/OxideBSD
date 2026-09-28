//! The man(7) parser (MAN.md §4.3): builds the document tree from roff lines.
//!
//! man(7) is line-oriented and presentational. Sections (`.SH`, `.SS`) hold paragraphs; a
//! paragraph macro (`.PP`, `.TP`, `.IP`, `.HP`) starts a new one, ending the last; `.RS`/`.RE`
//! nest a relative indent around paragraphs. Font macros (`.B`, `.I`, `.BR`...) format their
//! arguments, or the next input line when they have none.

use crate::diag::{Diagnostics, Level};
use crate::mdoc::ends_sentence;
use crate::roff::Line;
use crate::tree::{Document, Kind, Language, Meta, Node};

/// Font macros: one font for all arguments, or two alternating.
pub const FONT_MACROS: &[&str] = &["B", "I", "SB", "SM", "BI", "BR", "IB", "IR", "RB", "RI", "R"];

/// Paragraph macros: each ends the previous paragraph.
const PARAGRAPHS: &[&str] = &["PP", "LP", "P", "TP", "TQ", "IP", "HP"];

/// Macros with no text of their own that the renderer interprets.
const CONTROL: &[&str] = &["br", "sp", "nf", "fi", "EX", "EE", "in", "ti", "PD", "DT", "ne", "ce", "ad", "na", "hy", "nh", "ta", "ft", "UC", "AT", "ll", "bp", "Sp", "Vb", "Ve"];

struct Parser<'a> {
    stack: Vec<Node>,
    meta: Meta,
    diag: &'a mut Diagnostics,
    /// A font macro with no arguments, applying to the next line.
    pending_font: Option<String>,
    /// A `.SH`/`.SS`/`.TP` head waiting for the next line.
    pending_head: bool,
    /// The last text line ended in `\c`: the next node attaches without a space.
    nospace: bool,
    /// The last text line ended in `\c`.
    continued: bool,
    /// The next node continues the last input line, which ended in `\c`.
    joined: bool,
    line: usize,
    /// The column of the current macro's name, for diagnostics.
    col: usize,
    /// The current macro line as typed, from its name on.
    raw: String,
    /// Unknown macros already reported.
    unknown: Vec<String>,
    /// Inside a tbl or eqn block (`.TS`/`.TE`, `.EQ`/`.EN`), whose lines aren't text.
    in_preproc: bool,
    /// Whitespace at the end of the current macro line: where to report it, if the macro is
    /// known.
    trailing: Option<(usize, usize)>,
    /// In no-fill mode (`.nf`, `.EX`), where text lines aren't checked.
    nofill: bool,
    /// The paragraph checks.
    flow: crate::lint::ManFlow,
}

pub fn parse(lines: Vec<Line>, diag: &mut Diagnostics) -> Document {
    let mut p = Parser { stack: vec![Node::new(Kind::Root, "", 0)], meta: Meta::default(), diag, pending_font: None, pending_head: false, nospace: false, continued: false, joined: false, nofill: false, line: 0, col: 0, raw: String::new(), trailing: None, unknown: Vec::new(), in_preproc: false, flow: Default::default() };
    for l in lines {
        match l {
            Line::Macro { name, args, line, col, raw, trailing, .. } => {
                p.line = line;
                p.trailing = trailing;
                // tbl and eqn blocks: not formatted yet, and not checked.
                match name.as_str() {
                    "TS" | "EQ" => {
                        p.in_preproc = true;
                        continue;
                    }
                    "TE" | "EN" => {
                        p.in_preproc = false;
                        continue;
                    }
                    _ => {}
                }
                p.col = col;
                p.raw = raw;
                p.flow.macro_line(p.diag, &name, line, col, !args.is_empty());
                match name.as_str() {
                    "nf" | "EX" => p.nofill = true,
                    "fi" | "EE" => p.nofill = false,
                    _ => {}
                }
                p.macro_line(&name, &args);
                // (Requests such as `.sp` aren't the language's own: no report.)
                if let Some((l, c)) = p.trailing.take().filter(|_| crate::roff::MAN_MACROS.contains(&name.as_str()) || name == "MR") {
                    p.diag.report(Level::Style, l, c, "whitespace at end of input line", "");
                }
            }
            Line::Text { text, raw, line, last } => {
                p.line = line;
                p.col = 1;
                crate::lint::text_line(p.diag, line, &raw, last, p.nofill || p.in_preproc, false);
                if !p.in_preproc {
                    p.flow.text(p.diag, &raw);
                }
                p.text_line(&text);
            }
            Line::Blank { line } => {
                p.line = line;
                // Where a head line is expected (after `.TP` or an empty `.SS`), blank lines are
                // skipped.
                if p.pending_head {
                    continue;
                }
                p.flow.blank(p.diag, line);
                // A blank line is `.sp`, even before the first section (unlike in mdoc); marked,
                // since at the start of a section it is ignored where `.sp` isn't.
                let mut n = Node::new(Kind::Elem, "sp", line);
                n.text = "blank".to_string();
                p.push(n);
            }
        }
    }
    p.flow.end(p.diag);
    while p.stack.len() > 1 {
        p.close_top();
    }
    let root = p.stack.pop().unwrap();
    Document { language: Language::Man, meta: p.meta, root }
}

impl Parser<'_> {
    fn push(&mut self, mut n: Node) {
        if std::mem::take(&mut self.nospace) {
            n.flags.nospace = true;
        }
        if std::mem::take(&mut self.joined) {
            n.flags.continues = true;
        }
        self.stack.last_mut().unwrap().children.push(n);
        self.head_done();
    }

    fn open(&mut self, kind: Kind, tok: &str) {
        self.stack.push(Node::new(kind, tok, self.line));
    }

    fn close_top(&mut self) {
        let n = self.stack.pop().unwrap();
        self.stack.last_mut().unwrap().children.push(n);
    }

    /// After the line that completes a pending head: close the head, open the body.
    fn head_done(&mut self) {
        if self.pending_head && self.stack.last().is_some_and(|t| t.kind == Kind::Head) {
            self.pending_head = false;
            let tok = self.stack.last().unwrap().tok.clone();
            self.close_top();
            self.open(Kind::Body, &tok);
        }
    }

    /// Closes open paragraph blocks, up to (not including) the nearest `.RS` body or section.
    fn close_paragraph(&mut self) {
        while let Some(top) = self.stack.last() {
            let is_para = PARAGRAPHS.contains(&top.tok.as_str()) && matches!(top.kind, Kind::Block | Kind::Head | Kind::Body);
            if !is_para {
                break;
            }
            self.close_top();
        }
        self.pending_head = false;
    }

    /// Drops a `.PP` that ends the current node: an empty paragraph (before `.SH`, `.SS`, `.RE`
    /// or the end), which mandoc drops.
    fn drop_trailing_pp(&mut self) {
        if let Some(top) = self.stack.last_mut()
            && top.children.last().is_some_and(|c| c.kind == Kind::Elem && c.tok == "PP")
        {
            top.children.pop();
        }
    }

    /// Closes everything inside the current section (for `.SS`) or everything (for `.SH`).
    fn close_to_section(&mut self, sh: bool) {
        self.drop_trailing_pp();
        loop {
            let Some(top) = self.stack.last() else { break };
            if top.kind == Kind::Root {
                break;
            }
            if !sh && top.kind == Kind::Body && top.tok == "SH" {
                break;
            }
            self.close_top();
        }
        self.pending_head = false;
    }

    fn text_line(&mut self, text: &str) {
        use crate::roff::mark::{CONT, NBSP};
        let text = text.trim_end_matches([' ', '\t']);
        // `\c`: the next line continues this one without a space. Spaces before it are kept,
        // and the line may break at the last of them.
        let cont = text.ends_with(CONT);
        let mut text = text.trim_end_matches(CONT).to_string();
        let mut trail = 0;
        if cont {
            let body = text.trim_end_matches(' ').len();
            trail = text.len() - body;
            text.truncate(body);
            text.extend(std::iter::repeat_n(NBSP, trail.saturating_sub(1)));
        }
        // A line continuing one that ended in `\c` doesn't break at its leading spaces.
        if std::mem::take(&mut self.continued) && text.starts_with(' ') {
            let lead = text.len() - text.trim_start_matches(' ').len();
            text = std::iter::repeat_n(NBSP, lead).chain(text[lead..].chars()).collect();
        }
        let text = text.as_str();
        self.text_line_inner(text);
        if cont {
            self.nospace = trail == 0;
            self.continued = true;
            self.joined = true;
        }
    }

    fn text_line_inner(&mut self, text: &str) {
        let mut n = Node::text(text, self.line);
        n.flags.line_start = true;
        n.flags.eos = ends_sentence(text);
        if let Some(font) = self.pending_font.take() {
            let mut e = Node::new(Kind::Elem, &font, self.line);
            e.args = vec![text.to_string()];
            e.flags.line_start = true;
            e.flags.eos = n.flags.eos;
            self.push(e);
            return;
        }
        self.push(n);
    }

    fn macro_line(&mut self, name: &str, args: &[String]) {
        match name {
            "TH" => {
                crate::lint::man_th(self.diag, self.line, self.col, &self.raw);
                self.meta.title = args.first().cloned().unwrap_or_default();
                self.meta.section = args.get(1).cloned().unwrap_or_default();
                self.meta.date = args.get(2).cloned().unwrap_or_default();
                self.meta.os = args.get(3).cloned().unwrap_or_default();
                self.meta.os_given = args.len() > 3;
                self.meta.volume = args.get(4).cloned().unwrap_or_default();
                // An explicitly empty volume stays empty, rather than the section's default.
                self.meta.volume_given = args.len() > 4;
            }
            "SH" | "SS" => {
                self.close_to_section(name == "SH");
                self.open(Kind::Block, name);
                self.open(Kind::Head, name);
                if args.is_empty() {
                    // The heading is the next line.
                    self.pending_head = true;
                } else {
                    let mut t = Node::text(&args.join(" "), self.line);
                    t.flags.line_start = true;
                    self.stack.last_mut().unwrap().children.push(t);
                    self.close_top();
                    self.open(Kind::Body, name);
                }
                self.pending_font = None;
            }
            "PP" | "LP" | "P" => {
                self.close_paragraph();
                self.push(Node::new(Kind::Elem, "PP", self.line));
            }
            "TP" | "TQ" => {
                self.close_paragraph();
                self.open(Kind::Block, name);
                self.stack.last_mut().unwrap().args = args.to_vec();
                self.open(Kind::Head, name);
                self.pending_head = true;
            }
            "IP" | "HP" => {
                self.close_paragraph();
                self.open(Kind::Block, name);
                self.stack.last_mut().unwrap().args = args.to_vec();
                self.open(Kind::Body, name);
            }
            "RS" => {
                self.close_paragraph_if_head();
                self.open(Kind::Block, "RS");
                self.stack.last_mut().unwrap().args = args.to_vec();
                self.open(Kind::Body, "RS");
            }
            "RE" => {
                // Closes the innermost `.RS` (or the one numbered by the argument).
                let Some(pos) = self.stack.iter().rposition(|n| n.kind == Kind::Block && n.tok == "RS") else {
                    self.diag.report(Level::Error, self.line, self.col, "skipping end of block that is not open", "RE");
                    self.drop_trailing_pp();
                    self.close_paragraph();
                    self.push(Node::new(Kind::Elem, "RE", self.line));
                    return;
                };
                self.drop_trailing_pp();
                while self.stack.len() > pos {
                    self.close_top();
                }
            }
            "UR" | "MT" => {
                self.open(Kind::Block, name);
                // After `\c`, the link attaches to the text before it.
                let nospace = std::mem::take(&mut self.nospace);
                let top = self.stack.last_mut().unwrap();
                top.args = args.to_vec();
                top.flags.nospace = nospace;
                self.open(Kind::Body, name);
            }
            "UE" | "ME" => {
                let open = if name == "UE" { "UR" } else { "MT" };
                if let Some(pos) = self.stack.iter().rposition(|n| n.kind == Kind::Block && n.tok == open) {
                    while self.stack.len() > pos {
                        self.close_top();
                    }
                    // Text after `.UE` on the same line (punctuation) attaches to the link.
                    if let Some(rest) = args.first() {
                        let cont = rest.ends_with(crate::roff::mark::CONT);
                        let rest = rest.trim_end_matches(crate::roff::mark::CONT);
                        if !rest.is_empty() {
                            let mut t = Node::text(rest, self.line);
                            t.flags.nospace = true;
                            t.flags.eos = ends_sentence(rest);
                            self.push(t);
                        }
                        if cont {
                            self.nospace = true;
                            self.joined = true;
                        }
                    }
                }
            }
            "SY" => {
                self.close_paragraph();
                self.open(Kind::Block, "SY");
                self.stack.last_mut().unwrap().args = args.to_vec();
                self.open(Kind::Body, "SY");
            }
            "YS" => {
                if let Some(pos) = self.stack.iter().rposition(|n| n.kind == Kind::Block && n.tok == "SY") {
                    while self.stack.len() > pos {
                        self.close_top();
                    }
                }
            }
            "OP" | "MR" => {
                let mut e = Node::new(Kind::Elem, name, self.line);
                e.args = args.to_vec();
                self.push(e);
            }
            _ if FONT_MACROS.contains(&name) => {
                if args.is_empty() {
                    self.pending_font = Some(name.to_string());
                    return;
                }
                // `\c` ending the last argument joins the next line without a space.
                let mut args = args.to_vec();
                let cont = args.last().is_some_and(|a| a.ends_with(crate::roff::mark::CONT));
                if let Some(last) = args.last_mut() {
                    *last = last.trim_end_matches(crate::roff::mark::CONT).to_string();
                }
                let mut e = Node::new(Kind::Elem, name, self.line);
                e.flags.line_start = true;
                e.flags.eos = args.last().is_some_and(|a| ends_sentence(a));
                e.args = args;
                self.push(e);
                if cont {
                    self.nospace = true;
                    self.joined = true;
                }
            }
            "UC" | "AT" => {
                // The system the page belongs to, printed at the bottom left.
                let v = args.first().map(String::as_str).unwrap_or("");
                self.meta.os = match (name, v) {
                    ("UC", "3") => "3rd Berkeley Distribution",
                    ("UC", "4") => "4th Berkeley Distribution",
                    ("UC", "5") => "4.2 Berkeley Distribution",
                    ("UC", "6") => "4.3 Berkeley Distribution",
                    ("UC", "7") => "4.4 Berkeley Distribution",
                    ("UC", _) => "3rd Berkeley Distribution",
                    ("AT", "3") => "7th Edition",
                    ("AT", "4") => "System III",
                    ("AT", "5") if args.get(1).is_some_and(|r| r == "2") => "System V Release 2",
                    ("AT", "5") => "System V",
                    _ => "7th Edition",
                }
                .to_string();
                self.meta.os_given = true;
            }
            _ if CONTROL.contains(&name) => {
                let mut e = Node::new(Kind::Elem, name, self.line);
                e.args = args.to_vec();
                self.stack.last_mut().unwrap().children.push(e);
            }
            _ => {
                self.trailing = None;
                // Each unknown macro is reported once, as mandoc does.
                if !self.unknown.iter().any(|u| u == name) {
                    self.unknown.push(name.to_string());
                    self.diag.report(Level::Error, self.line, self.col, "skipping unknown macro", &format!(".{}", self.raw));
                }
            }
        }
    }

    /// `.RS` right after `.TP` (before its head line) doesn't start a head.
    fn close_paragraph_if_head(&mut self) {
        if self.pending_head && self.stack.last().is_some_and(|t| t.kind == Kind::Head && t.tok != "SH" && t.tok != "SS") {
            self.head_done();
        }
    }
}
