//! The terminal layout engine (MAN.md §5): fills words into lines between a left offset and a
//! right margin, and emits them with bold and underline as SGR sequences or backspace
//! overstrike. The language renderers (`mdoc_term`, `man_term`) drive it.

use crate::chars;
use crate::roff::mark;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Style {
    #[default]
    None,
    Bold,
    Under,
    BoldUnder,
}

impl Style {
    pub fn with(self, other: Style) -> Style {
        match (self, other) {
            (Style::None, o) | (o, Style::None) => o,
            (Style::Bold, Style::Under) | (Style::Under, Style::Bold) => Style::BoldUnder,
            (a, _) => a,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Ascii,
    Utf8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Styling {
    /// No bold or underline at all.
    Plain,
    /// `c\bc` for bold, `_\bc` for underline.
    Overstrike,
    /// `ESC[1m`, `ESC[4m`.
    Sgr,
}

#[derive(Clone, Copy, Debug)]
struct Cell {
    ch: char,
    style: Style,
}

#[derive(Debug)]
struct Word {
    cells: Vec<Cell>,
    /// Spaces before this word when it isn't first on a line.
    space: usize,
    /// The line may not break before this word (inside a kept group).
    glue: bool,
    /// The word may break after a hyphen (text lines only, as in mandoc).
    hyph: bool,
}

pub struct Term {
    pub width: usize,
    pub encoding: Encoding,
    pub styling: Styling,
    /// The left margin of lines being filled.
    pub offset: usize,
    /// The column lines may not reach past.
    pub rmargin: usize,
    /// No-fill mode: every input line is an output line.
    pub nofill: bool,
    /// Columns between tab stops: 8 for mdoc, 5 for man(7).
    pub tab_width: usize,
    out: String,
    words: Vec<Word>,
    /// Cells already placed on the current, unfinished output line.
    line: Vec<Cell>,
    line_open: bool,
    /// No word has been placed on the open line yet: the next one gets no space before it.
    fresh: bool,
    /// Something (a word, or a tag's padding) has been placed on the open line, so ending it
    /// outputs a line.
    dirty: bool,
    /// The next word attaches to the previous one.
    nospace: bool,
    /// The previous word ended a sentence.
    eos: bool,
    /// The exact spacing before the next word, overriding the usual one or two.
    space: Option<usize>,
    /// The font a `\f` escape selected, overriding the style words are given, and the one before
    /// it (for `\fP`). It lasts until the next font escape or [`Term::reset_font`].
    esc_font: Option<Style>,
    esc_prev: Option<Style>,
    /// Inside a kept group (`.Bk -words`, a SYNOPSIS enclosure): no breaks between words.
    keep: usize,
    keep_started: bool,
    /// The next word may break at a hyphen.
    hyph_next: bool,
    /// The output so far ends with a blank line (or nothing has been output), so vertical space
    /// isn't doubled.
    at_blank: bool,
    /// The blank line the output ends with was an explicit one (`.sp`, a blank input line).
    blank_explicit: bool,
    /// The blank line the output ends with is the one after the header.
    blank_header: bool,
    /// Vertical space is suppressed until the next text (right after a section heading).
    pub no_vspace: bool,
}

impl Term {
    pub fn new(width: usize, encoding: Encoding, styling: Styling) -> Term {
        Term {
            width,
            encoding,
            styling,
            offset: 0,
            rmargin: width,
            nofill: false,
            tab_width: 8,
            out: String::new(),
            words: Vec::new(),
            line: Vec::new(),
            line_open: false,
            fresh: false,
            dirty: false,
            nospace: false,
            eos: false,
            space: None,
            esc_font: None,
            esc_prev: None,
            keep: 0,
            keep_started: false,
            hyph_next: false,
            at_blank: true,
            blank_explicit: false,
            blank_header: false,
            no_vspace: false,
        }
    }

    pub fn finish(mut self) -> String {
        self.flush();
        self.out
    }

    /// Changes the left margin. Pending words are laid out first, at the old margin, since
    /// they belong to the text before the change.
    pub fn set_offset(&mut self, offset: usize) {
        self.layout();
        self.offset = offset;
    }

    pub fn set_rmargin(&mut self, rmargin: usize) {
        self.layout();
        self.rmargin = rmargin;
    }

    /// Applies a font change as if `\f` had selected it (`.ft`).
    pub fn set_font_marker(&mut self, f: char) {
        self.font_change(f, Style::None);
    }

    /// Updates the escape font for marker `f` (see [`mark`]); `base` is the style in effect
    /// when no escape font is set. Returns the new current style, or `None` if `f` isn't a
    /// font marker.
    fn font_change(&mut self, f: char, base: Style) -> Option<Style> {
        let cur = self.esc_font.unwrap_or(base);
        let new = match f {
            mark::FONT_R | mark::FONT_CW => Style::None,
            mark::FONT_B => Style::Bold,
            mark::FONT_I => Style::Under,
            mark::FONT_BI => Style::BoldUnder,
            mark::FONT_P => self.esc_prev.unwrap_or(base),
            _ => return None,
        };
        self.esc_prev = Some(cur);
        self.esc_font = Some(new);
        Some(new)
    }

    /// Forgets the font `\f` escapes selected: words get the style they're given again.
    pub fn reset_font(&mut self) {
        self.esc_font = None;
        self.esc_prev = None;
    }

    /// Starts a group of words the line may not break inside.
    pub fn keep_begin(&mut self) {
        self.keep += 1;
        if self.keep == 1 {
            self.keep_started = false;
        }
    }

    pub fn keep_end(&mut self) {
        self.keep = self.keep.saturating_sub(1);
    }

    /// Marks the next word as breakable after a hyphen.
    pub fn hyphenate_next(&mut self) {
        self.hyph_next = true;
    }

    /// Sets the spacing before the next word (spaces typed between words on one input line).
    pub fn set_space(&mut self, n: usize) {
        self.space = Some(n);
    }

    /// Suppresses the space before the next word.
    pub fn nospace(&mut self) {
        self.nospace = true;
    }

    pub fn has_pending(&self) -> bool {
        !self.words.is_empty() || self.line_open
    }

    /// Adds one word (no breakable spaces inside; [`mark::NBSP`] is a non-breaking space).
    pub fn word(&mut self, text: &str, style: Style) {
        self.word_ext(text, style, false);
    }

    /// Adds a word that ends a sentence when `eos` is set.
    pub fn word_ext(&mut self, text: &str, style: Style, eos: bool) {
        let mut cells = Vec::new();
        let mut cur = self.esc_font.unwrap_or(style);
        for c in text.chars() {
            if let Some(f) = self.font_change(c, style) {
                cur = f;
                continue;
            }
            match c {
                mark::ZERO | mark::CONT => {}
                mark::NBSP => cells.push(Cell { ch: ' ', style: Style::None }),
                mark::MINUS => cells.push(Cell { ch: '-', style: cur }),
                mark::BACKSLASH => cells.push(Cell { ch: '\\', style: cur }),
                '\t' => cells.push(Cell { ch: '\t', style: Style::None }),
                c => {
                    let s = if c == ' ' { Style::None } else { cur };
                    self.push_char(&mut cells, c, s);
                }
            }
        }
        let space = if self.nospace {
            0
        } else if let Some(n) = self.space {
            n
        } else if self.eos {
            2
        } else {
            1
        };
        self.nospace = false;
        self.space = None;
        self.eos = eos;
        let glue = self.keep > 0 && self.keep_started;
        if self.keep > 0 {
            self.keep_started = true;
        }
        let hyph = std::mem::take(&mut self.hyph_next);
        self.words.push(Word { cells, space, glue, hyph });
    }

    fn push_char(&self, cells: &mut Vec<Cell>, c: char, style: Style) {
        if self.encoding == Encoding::Ascii && !c.is_ascii() {
            let fallback = ascii_for(c);
            // An overstruck fallback (`+\bo`) is one printed cell.
            if fallback.contains('\u{8}') {
                for f in fallback.chars() {
                    cells.push(Cell { ch: f, style: if f == '\u{8}' { Style::None } else { style } });
                }
                return;
            }
            for f in fallback.chars() {
                cells.push(Cell { ch: f, style });
            }
            return;
        }
        cells.push(Cell { ch: c, style });
    }

    /// Lays out the pending words and ends the line.
    pub fn flush(&mut self) {
        self.layout();
        if self.line_open {
            if self.dirty {
                self.emit_line();
            } else {
                // Opened but never written to: no output line.
                self.line_open = false;
                self.line.clear();
            }
        }
    }

    /// Lays out the pending words but leaves the last line open, returning its column; used
    /// for list tags, which the body may continue on the same line.
    pub fn flush_open(&mut self) -> usize {
        self.layout();
        if !self.line_open {
            self.open_line();
        }
        visible_len(&self.line)
    }

    /// Pads the open line with spaces up to `col`; the next word starts there.
    pub fn pad_to(&mut self, col: usize) {
        if !self.line_open {
            self.open_line();
        }
        while visible_len(&self.line) < col {
            self.line.push(Cell { ch: ' ', style: Style::None });
        }
        self.fresh = true;
        self.dirty = true;
    }

    /// Starts a line at column `col` rather than the left margin; lines it wraps onto start at
    /// the margin (a hanging indent when `col` is less than it).
    pub fn begin_line_at(&mut self, col: usize) {
        self.flush();
        self.line_open = true;
        self.fresh = true;
        self.dirty = false;
        self.line = vec![Cell { ch: ' ', style: Style::None }; col];
    }

    fn open_line(&mut self) {
        self.line_open = true;
        self.fresh = true;
        self.dirty = false;
        self.line = vec![Cell { ch: ' ', style: Style::None }; self.offset];
    }

    /// Ends the current line, if any text is on it or pending.
    pub fn newline(&mut self) {
        self.flush();
    }

    /// Ends the current line and outputs a blank line, unless the output already ends with one or
    /// vertical space is suppressed.
    pub fn vspace(&mut self) {
        self.flush();
        if self.no_vspace || self.at_blank {
            return;
        }
        self.out.push('\n');
        self.at_blank = true;
        self.blank_explicit = false;
        self.blank_header = false;
    }

    /// A blank line even at the start of a section.
    pub fn blank_line(&mut self) {
        self.flush();
        self.out.push('\n');
        self.at_blank = true;
        self.blank_explicit = true;
        self.blank_header = false;
    }

    /// A man(7) `.sp`: a blank line, unless paragraph space was just output, which absorbs it.
    pub fn sp_line(&mut self) {
        self.flush();
        if self.at_blank && !self.blank_explicit && !self.blank_header {
            self.blank_explicit = true;
            return;
        }
        self.out.push('\n');
        self.at_blank = true;
        self.blank_explicit = true;
        self.blank_header = false;
    }

    /// Whether the open line has nothing on it since it was started or padded: a new input
    /// line in no-fill mode continues there instead of breaking.
    pub fn at_line_start(&self) -> bool {
        self.words.is_empty() && (!self.line_open || self.fresh)
    }

    /// The space before a man(7) section heading: like [`Term::vspace`], but not absorbed by an
    /// explicit blank line before it.
    pub fn section_vspace(&mut self) {
        self.flush();
        if self.no_vspace || (self.at_blank && !self.blank_explicit) {
            return;
        }
        self.out.push('\n');
        self.at_blank = true;
        self.blank_explicit = false;
        self.blank_header = false;
    }

    fn layout(&mut self) {
        let words = std::mem::take(&mut self.words);
        let mut i = 0;
        while i < words.len() {
            // Words joined without a space are placed, and broken, as one.
            let mut j = i + 1;
            while j < words.len() && (words[j].space == 0 || words[j].glue) {
                j += 1;
            }
            let mut cells: Vec<Cell> = Vec::new();
            for (k, w) in words[i..j].iter().enumerate() {
                if k > 0 {
                    for _ in 0..w.space {
                        cells.push(Cell { ch: ' ', style: Style::None });
                    }
                }
                cells.extend(w.cells.iter().copied());
            }
            let hyph = j == i + 1 && words[i].hyph;
            self.place(cells, words[i].space, hyph);
            i = j;
        }
    }

    /// Places one unbreakable run of cells, wrapping first if it doesn't fit, and breaking it
    /// after a hyphen when even a fresh line is too short.
    fn place(&mut self, mut cells: Vec<Cell>, space: usize, hyph: bool) {
        loop {
            if !self.line_open {
                self.open_line();
            }
            let len = visible_len(&cells);
            let col = visible_len(&self.line);
            let gap = if self.fresh { 0 } else { space };
            if self.nofill || col + gap + len <= self.rmargin {
                self.pad(gap);
                self.push_cells(&cells);
                self.fresh = false;
                return;
            }
            if let Some(cut) = hyph.then(|| hyphen_break(&cells, self.rmargin.saturating_sub(col + gap))).flatten() {
                self.pad(gap);
                self.push_cells(&cells[..cut]);
                cells.drain(..cut);
                self.emit_line();
                self.open_line();
                continue;
            }
            if !self.fresh {
                self.emit_line();
                self.open_line();
                continue;
            }
            // Too long for an empty line: break it at its own spaces where it must.
            if let Some(cut) = space_break(&cells, self.rmargin.saturating_sub(col)) {
                self.push_cells(&cells[..cut]);
                let rest = cells[cut..].iter().skip_while(|c| c.ch == ' ').count();
                let skip = cells.len() - cut - rest;
                cells.drain(..cut + skip);
                self.emit_line();
                self.open_line();
                continue;
            }
            // Too long for any line: it overflows.
            self.push_cells(&cells);
            self.fresh = false;
            return;
        }
    }

    fn pad(&mut self, n: usize) {
        for _ in 0..n {
            self.line.push(Cell { ch: ' ', style: Style::None });
        }
    }

    fn push_cells(&mut self, cells: &[Cell]) {
        self.dirty = true;
        for c in cells {
            if c.ch == '\t' {
                // Tab stops every 8 columns from the left margin.
                let col = visible_len(&self.line);
                let tw = self.tab_width.max(1);
                let stop = self.offset + ((col.saturating_sub(self.offset)) / tw + 1) * tw;
                while visible_len(&self.line) < stop {
                    self.line.push(Cell { ch: ' ', style: Style::None });
                }
            } else {
                self.line.push(*c);
            }
        }
    }

    fn emit_line(&mut self) {
        let line = std::mem::take(&mut self.line);
        self.line_open = false;
        // Trailing spaces are dropped.
        let end = line.iter().rposition(|c| c.ch != ' ').map(|i| i + 1).unwrap_or(0);
        let mut s = String::new();
        let mut cur = Style::None;
        for c in &line[..end] {
            if c.ch == '\u{8}' {
                s.push('\u{8}');
                continue;
            }
            match self.styling {
                Styling::Plain => s.push(c.ch),
                Styling::Overstrike => match c.style {
                    Style::None => s.push(c.ch),
                    Style::Bold => {
                        s.push(c.ch);
                        s.push('\u{8}');
                        s.push(c.ch);
                    }
                    Style::Under => {
                        s.push('_');
                        s.push('\u{8}');
                        s.push(c.ch);
                    }
                    Style::BoldUnder => {
                        s.push('_');
                        s.push('\u{8}');
                        s.push(c.ch);
                        s.push('\u{8}');
                        s.push(c.ch);
                    }
                },
                Styling::Sgr => {
                    if c.style != cur {
                        s.push_str("\x1b[0m");
                        match c.style {
                            Style::None => {}
                            Style::Bold => s.push_str("\x1b[1m"),
                            Style::Under => s.push_str("\x1b[4m"),
                            Style::BoldUnder => s.push_str("\x1b[1;4m"),
                        }
                        cur = c.style;
                    }
                    s.push(c.ch);
                }
            }
        }
        if self.styling == Styling::Sgr && cur != Style::None {
            s.push_str("\x1b[0m");
        }
        self.out.push_str(&s);
        self.out.push('\n');
        self.at_blank = false;
        self.blank_explicit = false;
        self.blank_header = false;
        self.no_vspace = false;
    }

    /// A whole line laid out by the caller: `left`, `center` and `right` parts of a header or
    /// footer, spread across the width.
    pub fn three_part(&mut self, left: &str, center: &str, right: &str) {
        self.flush();
        let w = self.width;
        let (ll, cl, rl) = (left.chars().count(), center.chars().count(), right.chars().count());
        let mut s = String::from(left);
        let mut col = ll;
        let pad = |s: &mut String, col: &mut usize, to: usize| {
            while *col < to {
                s.push(' ');
                *col += 1;
            }
        };
        if ll + cl + rl + 2 < w {
            // All three fit: the center part centered, the right part flush right.
            let cstart = ((w + 1).saturating_sub(cl) / 2).max(col + 1);
            pad(&mut s, &mut col, cstart);
            s.push_str(center);
            col += cl;
            let rstart = w.saturating_sub(rl).max(col + 1);
            pad(&mut s, &mut col, rstart);
            s.push_str(right);
        } else if ll + cl + 1 <= w {
            // No room for the right part: the center part goes flush right.
            pad(&mut s, &mut col, w - cl);
            s.push_str(center);
        } else if !center.is_empty() {
            // Not even that: the center part goes flush right on a line of its own.
            s.push('\n');
            s.push_str(&" ".repeat(w.saturating_sub(cl)));
            s.push_str(center);
        }
        let s = s.trim_end().to_string();
        let s = if self.encoding == Encoding::Ascii { s.chars().map(|c| if c.is_ascii() { c.to_string() } else { ascii_for(c).to_string() }).collect() } else { s };
        self.out.push_str(&s);
        self.out.push('\n');
        self.at_blank = false;
        self.blank_explicit = false;
        self.blank_header = false;
    }

    /// A man(7) footer: like [`Term::three_part`], but when the parts don't fit, the right one
    /// goes flush right on a line of its own.
    pub fn footer_three_part(&mut self, left: &str, center: &str, right: &str) {
        let (ll, cl, rl) = (left.chars().count(), center.chars().count(), right.chars().count());
        // Where the center part ends up, centered but after the left part.
        let cend = ((self.width + 1).saturating_sub(cl) / 2).max(ll + 1) + cl;
        if cend + 1 <= self.width.saturating_sub(rl) || right.is_empty() {
            self.three_part(left, center, right);
            return;
        }
        self.three_part(left, center, "");
        let pad = self.width.saturating_sub(rl);
        self.out.push_str(&" ".repeat(pad));
        self.out.push_str(right);
        self.out.push('\n');
    }

    /// Indentation for a text line starting with `lead` spaces: on a line nothing has been
    /// written to yet, from where it starts; otherwise a break, then from the left margin.
    pub fn leading_space(&mut self, lead: usize) {
        self.layout();
        if self.line_open && self.fresh && !self.dirty {
            let col = visible_len(&self.line) + lead;
            self.pad_to(col);
        } else {
            let at = self.offset + lead;
            self.begin_line_at(at);
        }
    }

    pub fn raw_blank(&mut self) {
        self.out.push('\n');
        self.at_blank = true;
        self.blank_header = true;
    }
}

/// Where a word may break so that at most `room` columns stay on this line: just after the last
/// fitting `-` that has a letter on each side. Returns the number of cells before the break.
fn hyphen_break(cells: &[Cell], room: usize) -> Option<usize> {
    let mut best = None;
    for k in 1..cells.len().saturating_sub(1) {
        let plain = cells[k - 1].style == Style::None && cells[k].style == Style::None && cells[k + 1].style == Style::None;
        if plain && cells[k].ch == '-' && cells[k - 1].ch.is_alphabetic() && cells[k + 1].ch.is_alphabetic() && visible_len(&cells[..=k]) <= room {
            best = Some(k + 1);
        }
    }
    best
}

/// The last space in `cells` before which at most `room` columns are used. Returns the number of
/// cells before it.
fn space_break(cells: &[Cell], room: usize) -> Option<usize> {
    let mut best = None;
    for k in 1..cells.len() {
        if cells[k].ch == ' ' && cells[k - 1].ch != ' ' && visible_len(&cells[..k]) <= room {
            best = Some(k);
        }
    }
    best
}

/// Printed width of cells: an overstrike (`+\bo`) is one column.
fn visible_len(cells: &[Cell]) -> usize {
    let bs = cells.iter().filter(|c| c.ch == '\u{8}').count();
    cells.len() - 2 * bs
}

/// The ASCII rendering of a non-ASCII character, as `-T ascii` prints it.
pub fn ascii_for(c: char) -> String {
    // Characters mdoc generates itself, before the table.
    match c {
        '\u{27E8}' => return "<".into(),
        '\u{27E9}' => return ">".into(),
        '\u{201C}' | '\u{201D}' => return "\"".into(),
        '\u{2018}' => return "`".into(),
        '\u{2019}' => return "'".into(),
        '\u{2013}' => return "-".into(),
        '\u{2014}' => return "--".into(),
        '\u{00A0}' => return " ".into(),
        '\u{00B4}' => return "'".into(),
        _ => {}
    }
    let s = c.to_string();
    for (_, u, a) in chars::CHARS {
        if *u == s {
            return a.to_string();
        }
    }
    // A character with no ASCII form, as mandoc shows it.
    "<?>".into()
}
