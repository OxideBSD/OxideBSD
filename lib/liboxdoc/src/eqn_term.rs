//! eqn on the terminal (MAN.md §4.5): an equation set as linear text, `a/b` for `a over b`,
//! `x^2` for `x sup 2`, `√(x)` for `sqrt x`, with parentheses where the structure would
//! otherwise be lost, laid out as mandoc does.

use crate::eqn::{self, EBox, Eqn, Font, Kind};
use crate::term::{Style, Term};

/// Characters a word attaches to the word before.
const NOSPACE_BEFORE: &str = "!\"'),.:;?]}";
/// Characters a word ending in one attaches the next word to it.
const NOSPACE_AFTER: &str = "\"'([{";

pub fn render(e: &Eqn, t: &mut Term) {
    let mut r = Renderer { t };
    // An equation of nothing but statements still starts a line: what follows is spaced.
    if e.root.children.is_empty() && r.t.at_line_start() {
        r.t.word(&crate::roff::mark::ZERO.to_string(), Style::None);
    }
    r.children(&e.root, None);
    // Spacing after an equation is the text's own.
    r.t.clear_nospace();
}

struct Renderer<'a> {
    t: &'a mut Term,
}

fn style(f: Font) -> Style {
    match f {
        Font::Roman => Style::None,
        Font::Italic => Style::Under,
        Font::Bold => Style::Bold,
    }
}

/// The box a mark or font sits on, for looking at what precedes a list.
fn inner(b: &EBox) -> &EBox {
    if b.kind == Kind::Mark {
        return b.children.first().map_or(b, inner);
    }
    b
}

/// Whether box `b`, child of `parent` between `prev` and a next sibling (`next`), is set in
/// parentheses.
fn delimited(b: &EBox, parent: &EBox, prev: Option<&EBox>, next: bool) -> bool {
    match b.kind {
        Kind::List if b.braced || b.split || b.left.is_some() => return true,
        Kind::List if b.row => return b.children.len() != 1,
        Kind::Pile(_) if prev.is_some() || next => return true,
        _ => {}
    }
    if parent.kind == Kind::Sqrt {
        return true;
    }
    // A marked box that is the base of a sub- or superscript.
    if !b.marks.is_empty() && parent.is_pos() && parent.kind != Kind::Over && next {
        return true;
    }
    b.is_pos() && parent.is_pos()
}

impl Renderer<'_> {
    fn word(&mut self, s: &str, font: Font) {
        self.t.word(s, style(font));
    }

    /// A delimiter; an empty one still takes a word's place, spacing and all.
    fn delim_word(&mut self, s: &str, font: Font) {
        if s.is_empty() {
            self.t.word(&crate::roff::mark::ZERO.to_string(), Style::None);
        } else {
            self.word(s, font);
        }
    }

    /// A word's text: the line may break at spaces in it (a quoted word's), which are kept.
    fn text(&mut self, s: &str, font: Font) {
        let mut first = true;
        let mut rest = s;
        while !rest.is_empty() {
            let lead = rest.len() - rest.trim_start_matches(' ').len();
            if lead > 0 {
                if first {
                    self.t.word(&crate::roff::mark::ZERO.to_string(), Style::None);
                    self.t.nospace();
                }
                self.t.set_space(lead);
                rest = &rest[lead..];
                if rest.is_empty() {
                    self.t.word(&crate::roff::mark::ZERO.to_string(), Style::None);
                    break;
                }
            }
            let end = rest.find(' ').unwrap_or(rest.len());
            self.word(&rest[..end], font);
            rest = &rest[end..];
            first = false;
        }
    }

    /// A box's marks: the last in `font`, any before it in roman, as mandoc sets them.
    fn marks(&mut self, b: &EBox, font: Font) {
        for (i, m) in b.marks.iter().enumerate() {
            let name = eqn::MARKS.iter().find(|(k, _)| k == m).map_or("", |(_, v)| v);
            self.t.nospace();
            self.word(&eqn::char_text(name), if i + 1 == b.marks.len() { font } else { Font::Roman });
        }
    }

    fn children(&mut self, b: &EBox, font: Option<Font>) {
        for (i, c) in b.children.iter().enumerate() {
            let prev = if i > 0 { b.children.get(i - 1) } else { None };
            self.one(c, b, prev, i + 1 < b.children.len(), font);
        }
    }

    fn one(&mut self, b: &EBox, parent: &EBox, prev: Option<&EBox>, next: bool, ctx: Option<Font>) {
        // A word's font is its own; a container's covers its delimiters, operators and marks,
        // and what it holds. The box a mark box holds has its delimiters in roman.
        let delim = delimited(b, parent, prev, next);
        let font = if b.kind == Kind::Text { ctx } else { b.font.or(ctx) };
        let dfont = font.unwrap_or(Font::Roman);
        let delim_font = if parent.kind == Kind::Mark { Font::Roman } else { ctx.unwrap_or(Font::Roman) };
        if delim {
            let nospace = (parent.is_pos() && prev.is_some())
                || (b.kind == Kind::List
                    && b.children.first().is_some_and(|c| !matches!(c.kind, Kind::Pile(_) | Kind::Matrix))
                    && prev.is_some_and(|p| !p.marks.is_empty() || {
                        let p = inner(p);
                        p.kind == Kind::List || (p.kind == Kind::Text && p.raw.starts_with(|c: char| c.is_ascii_alphabetic() || c == '\\'))
                    }));
            if nospace {
                self.t.nospace();
            }
            let open = b.left.clone().unwrap_or_else(|| "(".into());
            self.delim_word(&open, delim_font);
            self.t.nospace();
        }
        match b.kind {
            Kind::Text => {
                if b.raw.starts_with(|c| NOSPACE_BEFORE.contains(c)) {
                    self.t.nospace();
                }
                if b.text.is_empty() {
                    // (An empty word takes the place of one, spacing and all.)
                    self.t.clear_nospace();
                } else {
                    let f = if b.func { Font::Roman } else { b.font.unwrap_or(b.auto_font) };
                    self.text(&b.text, f);
                }
                if b.raw.ends_with(|c| NOSPACE_AFTER.contains(c)) || (prev.is_none() && (b.raw.ends_with('-') || b.raw.ends_with("\\[mi]"))) {
                    self.t.nospace();
                }
                self.marks(b, b.font.or(ctx).unwrap_or(Font::Roman));
            }
            Kind::List | Kind::Pile(_) | Kind::Matrix => self.children(b, font),
            Kind::Sqrt => {
                self.word(&eqn::char_text("sr"), dfont);
                self.t.nospace();
                self.children(b, font);
            }
            Kind::Mark => {
                self.children(b, font);
                self.marks(b, dfont);
            }
            _ => {
                let ops: &[&str] = match b.kind {
                    Kind::Sub | Kind::From => &["_"],
                    Kind::Sup | Kind::To => &["^"],
                    Kind::SubSup | Kind::FromTo => &["_", "^"],
                    _ => &["/"],
                };
                for (i, c) in b.children.iter().enumerate() {
                    if i > 0 {
                        self.t.nospace();
                        self.word(ops[(i - 1).min(ops.len() - 1)], dfont);
                        self.t.nospace();
                    }
                    let prev = if i > 0 { b.children.get(i - 1) } else { None };
                    self.one(c, b, prev, i + 1 < b.children.len(), font);
                }
                if b.children.len() == 1 {
                    self.t.nospace();
                    self.word(ops[0], dfont);
                    self.t.nospace();
                }
            }
        }
        if delim {
            self.t.nospace();
            let close = b.right.clone().unwrap_or_else(|| ")".into());
            self.delim_word(&close, delim_font);
        }
    }
}
