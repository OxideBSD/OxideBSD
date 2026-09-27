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
    out: String,
    words: Vec<Word>,
    /// Cells already placed on the current, unfinished output line.
    line: Vec<Cell>,
    line_open: bool,
    /// No word has been placed on the open line yet: the next one gets no space before it.
    fresh: bool,
    /// The next word attaches to the previous one.
    nospace: bool,
    /// The previous word ended a sentence.
    eos: bool,
    /// The output so far ends with a blank line (or nothing has been output), so vertical space
    /// isn't doubled.
    at_blank: bool,
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
            out: String::new(),
            words: Vec::new(),
            line: Vec::new(),
            line_open: false,
            fresh: false,
            nospace: false,
            eos: false,
            at_blank: true,
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
        let mut cur = style;
        let mut prev = style;
        for c in text.chars() {
            match c {
                mark::FONT_R => {
                    prev = cur;
                    cur = Style::None;
                }
                mark::FONT_B => {
                    prev = cur;
                    cur = Style::Bold;
                }
                mark::FONT_I => {
                    prev = cur;
                    cur = Style::Under;
                }
                mark::FONT_BI => {
                    prev = cur;
                    cur = Style::BoldUnder;
                }
                mark::FONT_CW => {
                    prev = cur;
                    cur = Style::None;
                }
                mark::FONT_P => std::mem::swap(&mut cur, &mut prev),
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
        } else if self.eos {
            2
        } else {
            1
        };
        self.nospace = false;
        self.eos = eos;
        self.words.push(Word { cells, space });
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
            self.emit_line();
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
    }

    fn open_line(&mut self) {
        self.line_open = true;
        self.fresh = true;
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
    }

    /// A blank line even at the start of a section.
    pub fn blank_line(&mut self) {
        self.flush();
        self.out.push('\n');
        self.at_blank = true;
    }

    fn layout(&mut self) {
        let words = std::mem::take(&mut self.words);
        let mut i = 0;
        while i < words.len() {
            // Words joined without a space break together.
            let mut j = i + 1;
            while j < words.len() && words[j].space == 0 {
                j += 1;
            }
            if !self.line_open {
                self.open_line();
            }
            let group_len: usize = words[i..j].iter().map(|w| visible_len(&w.cells)).sum();
            let col = visible_len(&self.line);
            let gap = if self.fresh { 0 } else { words[i].space };
            if !self.nofill && col + gap + group_len > self.rmargin {
                // A single word may break after a hyphen between letters, as mandoc does.
                if j == i + 1
                    && let Some(cut) = hyphen_break(&words[i].cells, self.rmargin.saturating_sub(col + gap))
                {
                    for _ in 0..gap {
                        self.line.push(Cell { ch: ' ', style: Style::None });
                    }
                    self.push_cells(&words[i].cells[..cut]);
                    self.emit_line();
                    self.open_line();
                    self.push_cells(&words[i].cells[cut..]);
                    self.fresh = false;
                    i = j;
                    continue;
                }
            }
            if !self.nofill && !self.fresh && col + gap + group_len > self.rmargin {
                self.emit_line();
                self.open_line();
            } else {
                for _ in 0..gap {
                    self.line.push(Cell { ch: ' ', style: Style::None });
                }
            }
            for w in &words[i..j] {
                self.push_cells(&w.cells);
            }
            self.fresh = false;
            i = j;
        }
    }

    fn push_cells(&mut self, cells: &[Cell]) {
        for c in cells {
            if c.ch == '\t' {
                // Tab stops every 8 columns from the left margin.
                let col = visible_len(&self.line);
                let stop = self.offset + ((col.saturating_sub(self.offset)) / 8 + 1) * 8;
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
        let cstart = ((w + 1).saturating_sub(cl) / 2).max(col + 1);
        while col < cstart {
            s.push(' ');
            col += 1;
        }
        s.push_str(center);
        col += cl;
        let rstart = w.saturating_sub(rl).max(col + 1);
        while col < rstart {
            s.push(' ');
            col += 1;
        }
        s.push_str(right);
        let s = if self.encoding == Encoding::Ascii { s.chars().map(|c| if c.is_ascii() { c.to_string() } else { ascii_for(c).to_string() }).collect() } else { s };
        self.out.push_str(&s);
        self.out.push('\n');
        self.at_blank = false;
    }

    pub fn raw_blank(&mut self) {
        self.out.push('\n');
        self.at_blank = true;
    }
}

/// Where a word may break so that at most `room` columns stay on this line: just after the last
/// fitting `-` that has a letter on each side. Returns the number of cells before the break.
fn hyphen_break(cells: &[Cell], room: usize) -> Option<usize> {
    let mut best = None;
    for k in 1..cells.len().saturating_sub(1) {
        if cells[k].ch == '-' && cells[k - 1].ch.is_alphabetic() && cells[k + 1].ch.is_alphabetic() && visible_len(&cells[..=k]) <= room {
            best = Some(k + 1);
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
    "?".into()
}
