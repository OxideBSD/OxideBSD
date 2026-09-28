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
    /// Blank lines before a paragraph or heading (`.PD`).
    pd: usize,
    /// `lines_out` just after the last `.SH` heading: if nothing has been output since, the next
    /// heading follows it without space.
    after_sh: Option<(usize, bool)>,
    /// The `.sp` at the start of this section has been swallowed.
    sp_swallowed: bool,
    /// A table comes next, after requests that print nothing (for a paragraph macro whose
    /// text follows it, not in a body of its own).
    table_next: bool,
}

/// Requests that print nothing, which don't stop a table from being first in a paragraph.
fn prints_nothing(c: &Node) -> bool {
    c.kind == Kind::Elem && matches!(c.tok.as_str(), "ne" | "ft" | "ta" | "ll" | "hy" | "nh" | "ad" | "na")
}

fn table_first(nodes: &[Node]) -> bool {
    nodes.iter().find(|c| !prints_nothing(c)).is_some_and(|c| c.kind == Kind::Table)
}

pub fn render(doc: &Document, t: Term, synopsis_only: bool) -> String {
    let mut t = t;
    // man(7) sets tab stops every half inch, five columns.
    t.tab_width = 5;
    t.nofill_zero_lines = true;
    let mut r = R { t, meta: &doc.meta, base: INDENT, width: WIDTH, levels: Vec::new(), pd: 1, after_sh: None, sp_swallowed: false, table_next: false };
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

/// Header and footer text with roff's markers resolved; `\ ` stays a no-break space, which
/// [`Term::columns`] doesn't break at.
fn plain(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            mark::MINUS => Some('-'),
            mark::NBSP => Some('\u{A0}'),
            mark::BACKSLASH => Some('\\'),
            c if ('\u{E000}'..='\u{E01F}').contains(&c) => None,
            c => Some(c),
        })
        .collect()
}

impl R<'_> {
    /// The space before a heading or paragraph: `.PD` blank lines, one by default.
    fn para_space(&mut self) {
        if self.pd == 0 {
            self.t.flush();
            return;
        }
        self.t.section_vspace();
        for _ in 1..self.pd {
            self.t.extra_blank();
        }
    }

    /// A paragraph's space, except when its body starts with a table, whose own blank line
    /// stands in for it.
    fn para_space_unless_table(&mut self, n: &Node) {
        let body = n.part(Kind::Body).map(|b| &b.children[..]);
        if body.map_or(self.table_next, |b| b.is_empty() && self.table_next || table_first(b)) {
            self.t.flush();
            return;
        }
        self.para_space();
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
        // The title at the left, the volume centered and the title again at the right, if they
        // fit; else the volume flush right, and the title only on the left.
        let w = self.t.width;
        let (tl, vl) = (title.chars().count(), vol.chars().count());
        let r1 = if 2 * (tl + 1) + vl < w {
            (w + 1 - vl) / 2
        } else {
            w.saturating_sub(vl)
        };
        let r2 = if r1 + vl + tl < w { w - tl } else { w };
        if r2 + tl <= w {
            self.t.columns(&[(&title, 0, r1), (&vol, r1, r2), (&title, r2, w)]);
        } else {
            self.t.columns(&[(&title, 0, r1), (&vol, r1, r2)]);
        }
        self.t.raw_blank();
    }

    fn footer(&mut self) {
        let title = self.title();
        let source = plain(&self.meta.os);
        let date = plain(&crate::format_date(&self.meta.date));
        self.t.no_vspace = false;
        self.t.section_vspace();
        // The source at the left, the date centered and the title at the right.
        let w = self.t.width;
        let (dl, tl) = (date.chars().count(), title.chars().count());
        let r1 = (w + 1).saturating_sub(dl) / 2;
        let r2 = w.saturating_sub(tl);
        self.t.columns(&[(&source, 0, r1), (&date, r1, r2), (&title, r2, w)]);
    }

    fn children(&mut self, n: &Node, style: Style) {
        for (i, c) in n.children.iter().enumerate() {
            self.table_next = table_first(&n.children[i + 1..]);
            self.node(c, style);
        }
    }

    fn node(&mut self, n: &Node, style: Style) {
        // In no-fill mode each input line, font macro lines included, is an output line.
        if self.t.nofill && n.kind == Kind::Elem && n.flags.line_start && !n.flags.continues && !self.t.at_line_start() {
            self.t.flush();
        }
        if n.flags.nospace {
            self.t.nospace();
        }
        match n.kind {
            Kind::Text => text_node(&mut self.t, n, style),
            Kind::Table => {
                if let Some(t) = &n.table {
                    crate::tbl_term::render(&mut self.t, t, true);
                }
            }
            Kind::Eqn => {
                if let Some(e) = &n.eqn {
                    crate::eqn_term::render(e, &mut self.t);
                }
            }
            Kind::Elem => self.elem(n, style),
            Kind::Block => self.block(n, style),
            _ => self.children(n, style),
        }
    }

    /// Words of one macro argument, which may contain spaces.
    /// A macro argument's words. Its spaces are all kept, as mandoc does, and the line may
    /// break at any of them; at the start of a line, leading ones are printed.
    fn arg_words(&mut self, text: &str, style: Style, eos: bool) {
        let body = text.trim_matches(' ');
        if body.is_empty() {
            // Only spaces: still that many spaces, printed even at the start of a line.
            if self.t.at_line_start() && !text.is_empty() {
                self.t.word(&mark::NBSP.to_string().repeat(text.len()), style);
            } else {
                self.t.add_space(text.len());
            }
            return;
        }
        let lead = text.len() - text.trim_start_matches(' ').len();
        let trail = text.len() - text.trim_end_matches(' ').len();
        let nbsp = |n: usize| mark::NBSP.to_string().repeat(n);
        let mut words: Vec<(String, usize)> = Vec::new();
        let mut spaces = 0;
        for w in body.split(' ') {
            if w.is_empty() {
                spaces += 1;
                continue;
            }
            words.push((w.to_string(), spaces + 1));
            spaces = 0;
        }
        let last = words.len() - 1;
        if self.t.at_line_start() {
            words[0].0.insert_str(0, &nbsp(lead));
        } else {
            self.t.add_space(lead);
        }
        for (i, (w, sp)) in words.iter().enumerate() {
            if i > 0 {
                self.t.set_space(*sp);
            }
            self.t.word_ext(w, style, eos && i == last);
        }
        self.t.add_space(trail);
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
        // Anything but a break in a paragraph makes it non-empty: its space then stays, rather
        // than being absorbed by the next paragraph's.
        if !matches!(n.tok.as_str(), "PP" | "br" | "sp") {
            self.t.keep_blank();
        }
        match n.tok.as_str() {
            "PP" => {
                self.t.reset_font();
                self.para_space_unless_table(n);
                self.width = WIDTH;
                self.t.set_offset(self.base);
            }
            "ta" => {
                // Tab stops: absolute, `+n` from the one before, and `T n` repeating n.
                let mut stops: Vec<usize> = Vec::new();
                let mut repeat = None;
                let mut args = n.args.iter();
                while let Some(a) = args.next() {
                    if a == "T" {
                        repeat = args.next().map(|r| width(r.trim_start_matches('+')));
                        break;
                    }
                    let prev = stops.last().copied().unwrap_or(0);
                    stops.push(match a.strip_prefix('+') {
                        Some(r) => prev + width(r),
                        None => width(a),
                    });
                }
                self.t.tab_stops = Some((stops, repeat));
            }
            "DT" => self.t.tab_stops = None,
            "PD" => {
                self.pd = n.args.first().filter(|a| !a.is_empty()).map(|a| vertical_lines(a)).unwrap_or(1);
            }
            "br" => {
                self.t.flush();
                self.t.break_after_header();
            }
            "sp" => {
                // At the start of a section a blank line is ignored, and the first `.sp` is
                // swallowed, like paragraph space.
                if self.t.no_vspace && !self.t.has_pending() {
                    if !self.sp_swallowed {
                        self.sp_swallowed |= n.text != "blank";
                        return;
                    }
                }
                let count = n.args.first().filter(|a| !a.is_empty()).map(|a| vertical_lines(a)).unwrap_or(1);
                self.t.flush();
                for _ in 0..count {
                    self.t.sp_line();
                }
            }
            "nf" | "EX" | "Vb" => {
                self.t.flush();
                self.t.break_after_header();
                self.t.nofill = true;
                // A paragraph after this is no longer the first thing in its section.
                self.t.no_vspace = false;
                self.after_sh = None;
            }
            "fi" | "EE" | "Ve" => {
                self.t.flush();
                self.t.break_after_header();
                self.t.nofill = false;
                self.t.no_vspace = false;
                self.after_sh = None;
            }
            "in" => {
                self.t.flush();
                self.t.break_after_header();
                // An absolute indent counts from the page's left edge; with no argument, the
                // paragraph's own margin. The next paragraph macro resets it.
                let arg = n.args.first().map(String::as_str).unwrap_or("");
                let off = if let Some(v) = arg.strip_prefix('+') {
                    self.t.offset + width(v)
                } else if let Some(v) = arg.strip_prefix('-') {
                    self.t.offset.saturating_sub(width(v))
                } else if arg.is_empty() {
                    self.base
                } else {
                    width(arg)
                };
                self.t.set_offset(off);
                self.t.no_vspace = false;
                self.after_sh = None;
            }
            "ti" => {
                let arg = n.args.first().map(String::as_str).unwrap_or("0");
                let at = if let Some(v) = arg.strip_prefix('+') {
                    self.t.offset + width(v)
                } else if let Some(v) = arg.strip_prefix('-') {
                    self.t.offset.saturating_sub(width(v))
                } else {
                    width(arg)
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
                // An unknown name is ignored.
                if let Some(f) = crate::roff::font_mark(n.args.first().map(String::as_str).unwrap_or("")) {
                    self.t.set_font_marker(f);
                }
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
                        // Each argument starts in its own font, whatever escapes came before.
                        self.t.reset_font();
                        if i > 0 {
                            self.t.nospace();
                        }
                        self.arg_words(arg, st, n.flags.eos && i == last);
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
                // An `.RE` with no `.RS` open still ends the line (but keeps the font).
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
                // A heading gets space before it unless nothing has been output since the last
                // `.SH` heading (an empty section, or a subsection first in its section).
                self.t.flush();
                // (After an empty `.SS`, a `.SH` still gets its space.)
                let skip = matches!(self.after_sh, Some((lines, was_sh)) if lines == self.t.lines_out && (was_sh || n.tok == "SS"));
                if !skip {
                    let saved = self.t.no_vspace;
                    self.t.no_vspace = false;
                    self.para_space();
                    self.t.no_vspace = saved;
                }
                self.sp_swallowed = false;
                self.levels.clear();
                self.base = INDENT;
                self.width = WIDTH;
                self.t.nofill = false;
                // A long subsection heading wraps to the body's indent.
                if n.tok == "SH" {
                    self.t.set_offset(0);
                } else {
                    self.t.set_offset(INDENT);
                    self.t.begin_line_at(SS_INDENT);
                }
                if let Some(h) = n.part(Kind::Head) {
                    self.children(h, Style::Bold);
                }
                self.t.flush();
                self.after_sh = Some((self.t.lines_out, n.tok == "SH"));
                self.t.reset_font();
                self.base = INDENT;
                self.t.set_offset(self.base);
                self.t.no_vspace = true;
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, Style::None);
                }
                self.t.flush();
            }
            "TP" | "TQ" | "IP" | "HP" if is_empty_paragraph(n) => {}
            "TP" | "TQ" | "IP" => {
                // Each paragraph, and its body after the tag, starts in the regular font.
                self.t.reset_font();
                if n.tok != "TQ" {
                    self.para_space_unless_table(n);
                } else {
                    self.t.flush();
                }
                let (tag_arg, width_arg) = if n.tok == "IP" { (n.args.first(), n.args.get(1)) } else { (None, n.args.first()) };
                if let Some(w) = width_arg.filter(|w| !w.is_empty()) {
                    self.width = width(w);
                }
                let base = self.base;
                let body_at = base + self.width;
                // A tag too long for one line wraps at the paragraph's own indent.
                self.t.set_offset(base);
                self.t.begin_line_at(base);
                if let Some(tag) = tag_arg {
                    self.arg_words(tag, style, false);
                } else if let Some(h) = n.part(Kind::Head) {
                    self.children(h, style);
                }
                let col = self.t.flush_open();
                self.t.reset_font();
                self.t.set_offset(body_at);
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
                self.t.reset_font();
                self.para_space_unless_table(n);
                if let Some(w) = n.args.first().filter(|w| !w.is_empty()) {
                    self.width = width(w);
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
                self.t.reset_font();
                // A paragraph's space before the `.RS` doesn't absorb the next one's.
                self.t.keep_blank();
                // What follows is no longer the start of the section.
                self.t.no_vspace = false;
                self.after_sh = None;
                self.levels.push((self.base, self.width));
                // A negative width moves the margin left.
                match n.args.first().filter(|a| !a.is_empty()) {
                    Some(a) if a.starts_with('-') => self.base = self.base.saturating_sub(width(&a[1..])),
                    Some(a) => self.base += width(a.trim_start_matches('+')),
                    None => self.base += self.width,
                }
                self.width = WIDTH;
                self.t.set_offset(self.base);
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b, style);
                }
                self.t.flush();
                self.t.reset_font();
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
                if n.flags.nospace {
                    self.t.nospace();
                }
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
                // Hung by the name's printed width: markers such as `\%` take no column.
                let printed = cmd.chars().filter(|c| !crate::roff::is_marker(*c) || matches!(*c, mark::NBSP | mark::MINUS | mark::BACKSLASH)).count();
                self.t.set_offset(base + printed + 1);
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

/// A paragraph macro with nothing in it, which mandoc drops (`.TP` right before `.SH`).
/// A horizontal distance in columns, as man(7) reads one: a number and a scaling unit, with
/// anything after them ignored (and an unknown unit taken as the default, ens).
fn width(s: &str) -> usize {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    if digits.is_empty() {
        return scaled(s);
    }
    let unit = s[digits.len()..].chars().next().filter(|c| "unmMicpPv".contains(*c));
    scaled(&format!("{digits}{}", unit.map(String::from).unwrap_or_default()))
}

/// A vertical distance in lines: `v` (a line) by default; an exact half rounds down, as
/// mandoc's does.
pub(crate) fn vertical_lines(a: &str) -> usize {
    let digits: String = a.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let v: f64 = digits.parse().unwrap_or(0.0);
    let units = match &a[digits.len()..] {
        "u" => v,
        "n" | "m" => v * 24.0,
        "i" => v * 240.0,
        "c" => v * 240.0 / 2.54,
        "p" => v * 240.0 / 72.0,
        "P" => v * 40.0,
        _ => v * 40.0,
    };
    (units / 40.0 + 0.4995).floor() as usize
}

fn is_empty_paragraph(n: &Node) -> bool {
    n.args.first().is_none_or(|a| n.tok != "IP" || a.is_empty()) && n.children.iter().all(|part| part.children.is_empty())
}
