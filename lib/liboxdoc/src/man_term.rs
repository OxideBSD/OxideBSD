//! Renders a man(7) document tree on a terminal (MAN.md §5).

use crate::mdoc_term::{scaled, text_node, volume};
use crate::roff::mark;
use crate::term::{Style, Term};
use crate::tree::{Document, Kind, Meta, Node};

/// The body text's indentation, a subsection heading's, and the default paragraph width.
const INDENT: usize = 7;
const SS_INDENT: usize = 3;
const WIDTH: usize = 7;

struct R<'a> {
    t: Term,
    meta: &'a Meta,
    /// The left margin of the current `.RS` level.
    base: usize,
    /// The paragraph width in effect: set by `.TP`, `.IP`, `.HP`; reset by `.PP` and sections.
    width: usize,
    /// Margins and widths saved by `.RS`, restored by `.RE`.
    levels: Vec<(usize, usize)>,
    /// The indent `.in` sets, which lasts across sections until changed.
    indent: isize,
}

pub fn render(doc: &Document, t: Term, synopsis_only: bool) -> String {
    let mut t = t;
    // man(7) sets tab stops every half inch, five columns.
    t.tab_width = 5;
    let mut r = R { t, meta: &doc.meta, base: INDENT, width: WIDTH, levels: Vec::new(), indent: 0 };
    if synopsis_only {
        for sh in doc.root.children.iter().filter(|n| n.tok == "SH") {
            if sh.part(Kind::Head).is_some_and(|h| h.plain_text().trim() == "SYNOPSIS")
                && let Some(b) = sh.part(Kind::Body)
            {
                r.base = 0;
                r.t.set_offset(0);
                r.t.no_vspace = true;
                r.children(b, Style::None);
            }
        }
        r.t.flush();
        return r.t.finish();
    }
    r.header();
    for n in &doc.root.children {
        r.node(n, Style::None);
    }
    r.t.flush();
    r.footer();
    r.t.finish()
}

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

impl R<'_> {
    /// A margin shifted by the `.in` indent.
    fn at(&self, col: usize) -> usize {
        (col as isize + self.indent).max(0) as usize
    }

    fn title(&self) -> String {
        format!("{}({})", plain(&self.meta.title), plain(&self.meta.section))
    }

    fn header(&mut self) {
        let title = self.title();
        let vol = if self.meta.volume_given {
            plain(&self.meta.volume)
        } else {
            match volume(&self.meta.section) {
                "" => String::new(),
                v => v.to_string(),
            }
        };
        self.t.three_part(&title, &vol, &title);
        self.t.raw_blank();
    }

    fn footer(&mut self) {
        let title = self.title();
        let source = plain(&self.meta.os);
        let date = plain(&crate::format_date(&self.meta.date));
        self.t.no_vspace = false;
        self.t.vspace();
        self.t.footer_three_part(&source, &date, &title);
    }

    fn children(&mut self, n: &Node, style: Style) {
        for c in &n.children {
            self.node(c, style);
        }
    }

    fn node(&mut self, n: &Node, style: Style) {
        // In no-fill mode each input line, font macro lines included, is an output line.
        if self.t.nofill && n.kind == Kind::Elem && n.flags.line_start && !self.t.at_line_start() {
            self.t.flush();
        }
        if n.flags.nospace {
            self.t.nospace();
        }
        match n.kind {
            Kind::Text => text_node(&mut self.t, n, style),
            Kind::Elem => self.elem(n, style),
            Kind::Block => self.block(n, style),
            _ => self.children(n, style),
        }
    }

    /// Words of one macro argument, which may contain spaces.
    fn arg_words(&mut self, text: &str, style: Style, eos: bool) {
        let words: Vec<&str> = text.split(' ').filter(|w| !w.is_empty()).collect();
        let last = words.len().saturating_sub(1);
        for (i, w) in words.iter().enumerate() {
            self.t.word_ext(w, style, eos && i == last);
        }
    }

    fn elem(&mut self, n: &Node, style: Style) {
        let fonts = |tok: &str| -> (Style, Style) {
            match tok {
                "B" | "SB" => (Style::Bold, Style::Bold),
                "I" => (Style::Under, Style::Under),
                "BI" => (Style::Bold, Style::Under),
                "BR" => (Style::Bold, Style::None),
                "IB" => (Style::Under, Style::Bold),
                "IR" => (Style::Under, Style::None),
                "RB" => (Style::None, Style::Bold),
                "RI" => (Style::None, Style::Under),
                _ => (Style::None, Style::None),
            }
        };
        match n.tok.as_str() {
            "PP" => {
                self.t.reset_font();
                self.t.section_vspace();
                self.width = WIDTH;
                self.t.set_offset(self.base);
            }
            "br" => self.t.flush(),
            "sp" => {
                // Swallowed at the start of a section, like paragraph space.
                if self.t.no_vspace && !self.t.has_pending() {
                    return;
                }
                let count = n.args.first().and_then(|a| a.trim_end_matches(['v', 'n']).parse::<usize>().ok()).unwrap_or(1);
                self.t.flush();
                for _ in 0..count.max(1) {
                    self.t.sp_line();
                }
            }
            "nf" | "EX" | "Vb" => {
                self.t.flush();
                self.t.nofill = true;
            }
            "fi" | "EE" | "Ve" => {
                self.t.flush();
                self.t.nofill = false;
            }
            "in" => {
                self.t.flush();
                let arg = n.args.first().map(String::as_str).unwrap_or("");
                let old = self.indent;
                self.indent = if let Some(v) = arg.strip_prefix('+') {
                    self.indent + scaled(v) as isize
                } else if let Some(v) = arg.strip_prefix('-') {
                    self.indent - scaled(v) as isize
                } else if arg.is_empty() {
                    0
                } else {
                    scaled(arg) as isize
                };
                let off = (self.t.offset as isize + self.indent - old).max(0) as usize;
                self.t.set_offset(off);
            }
            "ti" => {
                let arg = n.args.first().map(String::as_str).unwrap_or("0");
                let at = if let Some(v) = arg.strip_prefix('+') {
                    self.t.offset + scaled(v)
                } else if let Some(v) = arg.strip_prefix('-') {
                    self.t.offset.saturating_sub(scaled(v))
                } else {
                    scaled(arg)
                };
                self.t.begin_line_at(at);
            }
            "OP" => {
                self.t.word("[", style);
                self.t.nospace();
                if let Some(o) = n.args.first() {
                    self.t.word(o, Style::Bold);
                }
                if let Some(a) = n.args.get(1) {
                    self.t.word(a, Style::Under);
                }
                self.t.nospace();
                self.t.word("]", style);
            }
            "MR" => {
                let name = n.args.first().cloned().unwrap_or_default();
                let sec = n.args.get(1).cloned().unwrap_or_default();
                self.t.word(&name, Style::Under);
                self.t.nospace();
                self.t.word(&format!("({sec})"), style);
                if let Some(p) = n.args.get(2) {
                    self.t.nospace();
                    self.t.word(p, style);
                }
            }
            "ft" => {
                // `.ft B`: a font for the text that follows, like `\fB`.
                let f = match n.args.first().map(String::as_str) {
                    Some("B") | Some("3") => mark::FONT_B,
                    Some("I") | Some("2") => mark::FONT_I,
                    Some("BI") | Some("4") => mark::FONT_BI,
                    Some("R") | Some("1") | Some("CW") | Some("CR") => mark::FONT_R,
                    _ => mark::FONT_P,
                };
                self.t.set_font_marker(f);
            }
            tok if crate::man::FONT_MACROS.contains(&tok) => {
                // A font macro sets its own fonts and leaves no escape font behind.
                self.t.reset_font();
                let (a, b) = fonts(tok);
                let alternating = tok.len() == 2 && tok != "SB" && tok != "SM";
                let last = n.args.len().saturating_sub(1);
                for (i, arg) in n.args.iter().enumerate() {
                    let st = if i % 2 == 0 { a } else { b };
                    if alternating {
                        // Alternating fonts join their arguments; spaces inside one are kept.
                        if i > 0 {
                            self.t.nospace();
                        }
                        let w = arg.replace(' ', &mark::NBSP.to_string());
                        self.t.word_ext(&w, st, n.flags.eos && i == last);
                    } else if self.t.nofill {
                        // In no-fill mode an argument's spaces, leading ones included, are kept.
                        if i > 0 {
                            self.t.set_space(1);
                        }
                        let w = arg.replace(' ', &mark::NBSP.to_string());
                        self.t.word_ext(&w, st, false);
                    } else {
                        self.arg_words(arg, st, n.flags.eos && i == last);
                    }
                }
                self.t.reset_font();
            }
            "RE" => {
                // An `.RE` with no `.RS` open still ends the line.
                self.t.flush();
                self.t.set_offset(self.base);
            }
            _ => {}
        }
    }

    fn block(&mut self, n: &Node, style: Style) {
        match n.tok.as_str() {
            "SH" | "SS" => {
                self.t.flush();
                self.t.reset_font();
                // A subsection first in its section follows the heading directly.
                if n.tok == "SH" {
                    self.t.no_vspace = false;
                }
                self.t.section_vspace();
                self.levels.clear();
                self.base = INDENT;
                self.width = WIDTH;
                self.t.nofill = false;
                let head = if n.tok == "SH" { 0 } else { SS_INDENT };
                self.t.set_offset(self.at(head));
                if let Some(h) = n.part(Kind::Head) {
                    self.children(h, Style::Bold);
                }
                self.t.flush();
                self.t.reset_font();
                self.base = self.at(INDENT);
                self.t.set_offset(self.base);
                self.t.no_vspace = true;
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, Style::None);
                }
                self.t.flush();
            }
            "TP" | "TQ" | "IP" => {
                if n.tok != "TQ" {
                    self.t.section_vspace();
                } else {
                    self.t.flush();
                }
                let (tag_arg, width_arg) = if n.tok == "IP" { (n.args.first(), n.args.get(1)) } else { (None, n.args.first()) };
                if let Some(w) = width_arg.filter(|w| !w.is_empty()) {
                    self.width = scaled(w);
                }
                let base = self.base;
                let body_at = base + self.width;
                self.t.set_offset(body_at);
                self.t.begin_line_at(base);
                if let Some(tag) = tag_arg {
                    self.arg_words(tag, style, false);
                } else if let Some(h) = n.part(Kind::Head) {
                    self.children(h, style);
                }
                let col = self.t.flush_open();
                if col < body_at {
                    self.t.pad_to(body_at);
                } else if col > base {
                    self.t.flush();
                }
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, style);
                }
                self.t.flush();
                self.t.set_offset(base);
            }
            "HP" => {
                self.t.section_vspace();
                if let Some(w) = n.args.first().filter(|w| !w.is_empty()) {
                    self.width = scaled(w);
                }
                let base = self.base;
                self.t.set_offset(base + self.width);
                self.t.begin_line_at(base);
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, style);
                }
                self.t.flush();
                self.t.set_offset(base);
            }
            "RS" => {
                self.t.flush();
                self.levels.push((self.base, self.width));
                // A negative width moves the margin left.
                match n.args.first().filter(|a| !a.is_empty()) {
                    Some(a) if a.starts_with('-') => self.base = self.base.saturating_sub(scaled(&a[1..])),
                    Some(a) => self.base += scaled(a.trim_start_matches('+')),
                    None => self.base += self.width,
                }
                self.width = WIDTH;
                self.t.set_offset(self.base);
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, style);
                }
                self.t.flush();
                if let Some((base, width)) = self.levels.pop() {
                    self.base = base;
                    self.width = width;
                }
                self.t.set_offset(self.base);
            }
            "UR" | "MT" => {
                // Link text, then the address in angle brackets.
                let url = n.args.first().cloned().unwrap_or_default();
                let body = n.part(Kind::Body);
                let has_text = body.is_some_and(|b| !b.children.is_empty());
                if let Some(b) = body {
                    self.children(b, style);
                }
                // The address in angle brackets, after the link text if there is any.
                let _ = has_text;
                self.t.word("\u{27E8}", style);
                self.t.nospace();
                self.t.word(&url, style);
                self.t.nospace();
                self.t.word("\u{27E9}", style);
            }
            "SY" => {
                self.t.vspace();
                let cmd = n.args.first().cloned().unwrap_or_default();
                let base = self.base;
                self.t.word(&cmd, Style::Bold);
                self.t.flush_open();
                self.t.set_offset(base + cmd.chars().count() + 1);
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, style);
                }
                self.t.flush();
                self.t.set_offset(base);
            }
            _ => {
                for part in &n.children {
                    self.children(part, style);
                }
            }
        }
    }
}
