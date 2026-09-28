//! The tbl preprocessor's language (MAN.md §4.4): a table between `.TS` and `.TE`, parsed from
//! its lines as typed into options, layout rows and data rows. Cell text is decoded by the roff
//! layer, like any text line.

use crate::diag::{Diagnostics, Level};

/// Table-wide options, from the line ending in `;`.
#[derive(Clone, Debug, PartialEq)]
pub struct Opts {
    /// A frame around the table: 0 none, 1 `box`, 2 `doublebox`.
    pub frame: u8,
    /// `allbox`: a frame, and lines between all cells.
    pub allbox: bool,
    pub center: bool,
    pub expand: bool,
    /// The character separating cells in data lines.
    pub tab: char,
    pub decimal: char,
    pub nospaces: bool,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts { frame: 0, allbox: false, center: false, expand: false, tab: '\t', decimal: '.', nospaces: false }
    }
}

/// One column of a layout row.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    /// `l` `r` `c` `n` `a` `s` (span from the left) `^` (span from above) `_` `=` (lines).
    pub kind: char,
    pub bold: bool,
    pub italic: bool,
    /// A minimum width in columns (`w(n)`).
    pub width: Option<usize>,
    /// All `e` columns get the same width.
    pub equal: bool,
    /// Columns between this column and the next, instead of 3.
    pub spacing: Option<usize>,
    /// Vertical lines after this column: 0, 1 (`|`) or 2 (`||`).
    pub vline: u8,
    /// `x`: the column takes a share of the width left over.
    pub max: bool,
}

impl Spec {
    pub fn new(kind: char) -> Spec {
        Spec { kind, bold: false, italic: false, width: None, equal: false, spacing: None, vline: 0, max: false }
    }
}

/// A layout row: vertical lines before the first column, and the columns.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Layout {
    pub lead: u8,
    pub specs: Vec<Spec>,
}

/// One cell of a data row.
#[derive(Clone, Debug, PartialEq)]
pub enum Cell {
    /// Text, escapes decoded.
    Text(String),
    /// A `T{` ... `T}` text block, filled: its lines, decoded.
    Block(Vec<String>),
    /// `_` or `=`: a line across the cell (1 or 2 for double).
    Line(u8),
    /// `\_`: a line as long as the cell's contents would be.
    ShortLine,
    /// `\^`: continues the cell above.
    SpanDown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Row {
    /// Cells, and the layout row they follow.
    Data { cells: Vec<Cell>, layout: Layout, line: usize },
    /// `_` or `=` alone on a line: a line across the table.
    Line(u8),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Table {
    pub opts: Opts,
    pub rows: Vec<Row>,
    /// The number of columns: the most any layout row has.
    pub ncols: usize,
    pub line: usize,
}

/// Parses a table from its lines (with their line numbers), decoding cell text with `decode`.
pub fn parse(lines: &[(usize, String)], start: usize, decode: &mut dyn FnMut(&str, usize) -> String, diag: &mut Diagnostics) -> Table {
    let mut opts = Opts::default();
    let mut i = 0;
    // Options: a first line ending in `;`.
    if let Some((_, first)) = lines.first()
        && first.trim_end().ends_with(';')
    {
        opts = parse_opts(first);
        i = 1;
    }
    let mut layouts: Vec<Layout> = Vec::new();
    let mut ncols = 0;
    i = parse_layout(lines, i, &mut layouts);
    ncols = ncols.max(layouts.iter().map(|l| l.specs.len()).max().unwrap_or(0));
    let mut rows = Vec::new();
    let mut next = 0;
    while i < lines.len() {
        let (lineno, line) = &lines[i];
        // `.T&`: a new layout for the rows after it.
        if line.trim_end() == ".T&" {
            layouts.clear();
            i = parse_layout(lines, i + 1, &mut layouts);
            ncols = ncols.max(layouts.iter().map(|l| l.specs.len()).max().unwrap_or(0));
            next = 0;
            continue;
        }
        if line.starts_with('.') || line.starts_with('\'') {
            ignore_macro(line, *lineno, diag);
            i += 1;
            continue;
        }
        match line.as_str() {
            "_" => {
                rows.push(Row::Line(1));
                i += 1;
                continue;
            }
            "=" => {
                rows.push(Row::Line(2));
                i += 1;
                continue;
            }
            _ => {}
        }
        let layout = layouts.get(next.min(layouts.len().saturating_sub(1))).cloned().unwrap_or_default();
        next += 1;
        // The cells, text blocks spanning lines.
        let mut cells = Vec::new();
        let mut rest = line.clone();
        let row_line = *lineno;
        i += 1;
        loop {
            let (cell, tail) = match rest.find(opts.tab) {
                Some(p) => (rest[..p].to_string(), Some(rest[p + opts.tab.len_utf8()..].to_string())),
                None => (rest.clone(), None),
            };
            if cell == "T{" {
                // A text block: the following lines up to one starting `T}`.
                let mut text: Vec<String> = Vec::new();
                let mut after = None;
                while i < lines.len() {
                    let (_, l) = &lines[i];
                    i += 1;
                    if let Some(t) = l.strip_prefix("T}") {
                        after = Some(t.to_string());
                        break;
                    }
                    if l.starts_with('.') || l.starts_with('\'') {
                        // A macro inside a block: ignored, but its arguments stay as text.
                        if let Some(args) = ignore_macro(l, lines[i - 1].0, diag) {
                            text.push(decode(args, lines[i - 1].0));
                        }
                        continue;
                    }
                    text.push(decode(l, lines[i - 1].0));
                }
                cells.push(Cell::Block(text));
                match after {
                    // `T}` then the next cell, after a tab.
                    Some(a) if a.starts_with(opts.tab) => {
                        rest = a[opts.tab.len_utf8()..].to_string();
                        continue;
                    }
                    _ => break,
                }
            }
            cells.push(match cell.as_str() {
                "_" => Cell::Line(1),
                "=" => Cell::Line(2),
                "\\_" => Cell::ShortLine,
                "\\^" => Cell::SpanDown,
                c => Cell::Text(decode(c, row_line)),
            });
            match tail {
                Some(t) => rest = t,
                None => break,
            }
        }
        rows.push(Row::Data { cells, layout, line: row_line });
    }
    Table { opts, rows, ncols, line: start }
}

/// Reports a macro line in a table, which isn't formatted. The requests that break or place
/// text (`br`, `sp`, `ce`, `rj`) are reported at their arguments and leave nothing; any other
/// macro is reported at its name, and its arguments (returned) stay as text.
fn ignore_macro<'a>(line: &'a str, lineno: usize, diag: &mut Diagnostics) -> Option<&'a str> {
    let body = line[1..].trim_start_matches([' ', '\t']);
    if body.is_empty() || body.starts_with('\\') {
        return None;
    }
    let name_col = line.len() - body.len() + 1;
    let name_len = body.find([' ', '\t']).unwrap_or(body.len());
    let args = body[name_len..].trim_start_matches([' ', '\t']);
    if matches!(&body[..name_len], "br" | "sp" | "ce" | "rj") {
        diag.report(Level::Unsupported, lineno, line.len() - args.len() + 1, "ignoring macro in table", body);
        return None;
    }
    diag.report(Level::Unsupported, lineno, name_col, "ignoring macro in table", body);
    (!args.is_empty()).then_some(args)
}

fn parse_opts(line: &str) -> Opts {
    let mut o = Opts::default();
    let s = line.trim_end().trim_end_matches(';');
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_alphabetic() {
            i += 1;
        }
        let word: String = b[start..i].iter().collect::<String>().to_lowercase();
        // An argument in parentheses.
        let mut arg = String::new();
        if b.get(i) == Some(&'(') {
            i += 1;
            while i < b.len() && b[i] != ')' {
                arg.push(b[i]);
                i += 1;
            }
            i += 1;
        }
        match word.as_str() {
            "box" | "frame" => o.frame = o.frame.max(1),
            "doublebox" | "doubleframe" => o.frame = 2,
            "allbox" => {
                o.allbox = true;
                o.frame = o.frame.max(1);
            }
            "center" | "centre" => o.center = true,
            "expand" => o.expand = true,
            "tab" => o.tab = arg.chars().next().unwrap_or('\t'),
            "decimalpoint" => o.decimal = arg.chars().next().unwrap_or('.'),
            "nospaces" => o.nospaces = true,
            _ => {}
        }
    }
    o
}

/// Reads layout lines from `i` up to and including the one ending in `.`; returns the index
/// after it.
fn parse_layout(lines: &[(usize, String)], mut i: usize, out: &mut Vec<Layout>) -> usize {
    while i < lines.len() {
        let line = lines[i].1.trim_end();
        i += 1;
        let (body, last) = match line.strip_suffix('.') {
            Some(b) => (b, true),
            None => (line, false),
        };
        for row in body.split(',') {
            let l = parse_layout_row(row);
            if !l.specs.is_empty() {
                out.push(l);
            }
        }
        if last {
            break;
        }
    }
    i
}

fn parse_layout_row(s: &str) -> Layout {
    let mut l = Layout::default();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        match c {
            '|' => match l.specs.last_mut() {
                Some(sp) => sp.vline += 1,
                None => l.lead += 1,
            },
            'l' | 'L' | 'r' | 'R' | 'c' | 'C' | 'n' | 'N' | 'a' | 'A' | 's' | 'S' | '^' | '_' | '-' | '=' => {
                let kind = match c.to_ascii_lowercase() {
                    '-' => '_',
                    k => k,
                };
                l.specs.push(Spec::new(kind));
            }
            _ if l.specs.is_empty() => {}
            'b' | 'B' => l.specs.last_mut().unwrap().bold = true,
            'i' | 'I' => l.specs.last_mut().unwrap().italic = true,
            'e' | 'E' => l.specs.last_mut().unwrap().equal = true,
            'x' | 'X' => l.specs.last_mut().unwrap().max = true,
            'f' | 'F' => {
                // A font: `(xx`, one letter, or two starting with C (`CW`).
                let mut name = String::new();
                if b.get(i) == Some(&'(') {
                    name = b[(i + 1).min(b.len())..(i + 3).min(b.len())].iter().collect();
                    i += 3;
                } else if let Some(&f) = b.get(i) {
                    name.push(f);
                    i += 1;
                    if f == 'C' && b.get(i).is_some_and(|c| c.is_ascii_uppercase()) {
                        name.push(b[i]);
                        i += 1;
                    }
                }
                let sp = l.specs.last_mut().unwrap();
                match name.as_str() {
                    "B" | "3" => sp.bold = true,
                    "I" | "2" => sp.italic = true,
                    "BI" | "4" => {
                        sp.bold = true;
                        sp.italic = true;
                    }
                    _ => {}
                }
            }
            'w' | 'W' => {
                let mut arg = String::new();
                if b.get(i) == Some(&'(') {
                    i += 1;
                    while i < b.len() && b[i] != ')' {
                        arg.push(b[i]);
                        i += 1;
                    }
                    i += 1;
                } else {
                    while i < b.len() && (b[i].is_ascii_digit() || b[i] == '.') {
                        arg.push(b[i]);
                        i += 1;
                    }
                    if i < b.len() && b[i].is_ascii_alphabetic() && "icpPmnuv".contains(b[i]) {
                        arg.push(b[i]);
                        i += 1;
                    }
                }
                l.specs.last_mut().unwrap().width = Some(crate::mdoc_term::scaled(&arg));
            }
            'p' | 'P' | 'v' | 'V' => {
                // Point size and vertical spacing: skipped with their number.
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == '+' || b[i] == '-') {
                    i += 1;
                }
            }
            c if c.is_ascii_digit() => {
                let mut n = c.to_digit(10).unwrap() as usize;
                while i < b.len() && b[i].is_ascii_digit() {
                    n = n * 10 + b[i].to_digit(10).unwrap() as usize;
                    i += 1;
                }
                l.specs.last_mut().unwrap().spacing = Some(n);
            }
            _ => {}
        }
    }
    l
}
