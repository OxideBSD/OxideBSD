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
    /// Cells, and the layout row they follow. `raw` has each text cell as typed (empty for
    /// the others): mandoc aligns numbers by it.
    Data { cells: Vec<Cell>, raw: Vec<String>, layout: Layout, line: usize },
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
        opts = parse_opts(first, lines[0].0, diag);
        i = 1;
    }
    let mut layouts: Vec<Layout> = Vec::new();
    let mut ncols = 0;
    i = parse_layout(lines, i, &mut layouts, diag);
    ncols = ncols.max(layouts.iter().map(|l| l.specs.len()).max().unwrap_or(0));
    let mut rows = Vec::new();
    let mut next = 0;
    let mut any_data = false;
    while i < lines.len() {
        let (lineno, line) = &lines[i];
        // `.T&`: a new layout for the rows after it.
        if line.trim_end() == ".T&" {
            layouts.clear();
            i = parse_layout(lines, i + 1, &mut layouts, diag);
            ncols = ncols.max(layouts.iter().map(|l| l.specs.len()).max().unwrap_or(0));
            next = 0;
            continue;
        }
        // A blank line is an empty row, but not data.
        if !line.is_empty() {
            any_data = true;
        }
        // A macro isn't formatted; any but a break's arguments make a row of their own.
        let from_macro = line.starts_with('.') || line.starts_with('\'');
        let line = if from_macro {
            match ignore_macro(line, *lineno, diag) {
                Some(args) => args.to_string(),
                None => {
                    i += 1;
                    continue;
                }
            }
        } else {
            line.clone()
        };
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
        // A layout row of lines only is a line across the table, taking no data line.
        while next + 1 < layouts.len() && !layouts[next].specs.is_empty() && layouts[next].specs.iter().all(|s| matches!(s.kind, '_' | '=')) {
            let double = layouts[next].specs.iter().all(|s| s.kind == '=');
            rows.push(Row::Line(if double { 2 } else { 1 }));
            next += 1;
        }
        let layout = layouts.get(next.min(layouts.len().saturating_sub(1))).cloned().unwrap_or_default();
        next += 1;
        // The cells, text blocks spanning lines.
        let mut cells = Vec::new();
        let mut raw = Vec::new();
        let row_line = *lineno;
        // Where each cell was typed: its line, the line, and its column.
        let mut at: Vec<(usize, String, usize)> = Vec::new();
        let (mut cur_no, mut cur_text, mut offset) = (row_line, line.clone(), 0);
        let mut rest = line;
        i += 1;
        loop {
            let (cell, tail) = match rest.find(opts.tab) {
                Some(p) => (rest[..p].to_string(), Some(rest[p + opts.tab.len_utf8()..].to_string())),
                None => (rest.clone(), None),
            };
            at.push((cur_no, cur_text.clone(), offset + 1));
            if cell == "T{" {
                // A text block: the following lines up to one starting `T}`.
                let mut text: Vec<String> = Vec::new();
                let mut after = None;
                while i < lines.len() {
                    let (_, l) = &lines[i];
                    i += 1;
                    if let Some(t) = l.strip_prefix("T}") {
                        after = Some(t.to_string());
                        (cur_no, cur_text, offset) = (lines[i - 1].0, l.clone(), 2);
                        break;
                    }
                    if l.starts_with('.') || l.starts_with('\'') {
                        // A lone control character or a comment line leaves the dot as text.
                        let body = l[1..].trim_start_matches([' ', '\t']);
                        if body.is_empty() || body.starts_with("\\\"") || body.starts_with("\\#") {
                            text.push(".".into());
                            continue;
                        }
                        // A macro inside a block: ignored, but its arguments stay as text.
                        if let Some(args) = ignore_macro(l, lines[i - 1].0, diag) {
                            text.push(decode(args, lines[i - 1].0));
                        }
                        continue;
                    }
                    text.push(decode(l, lines[i - 1].0));
                }
                if after.is_none() {
                    diag.report(Level::Error, start, 2, "data block open at end of tbl", "TE");
                }
                cells.push(Cell::Block(text));
                raw.push(String::new());
                match after {
                    // `T}` then the next cell, after a tab.
                    Some(a) if a.starts_with(opts.tab) => {
                        rest = a[opts.tab.len_utf8()..].to_string();
                        offset += opts.tab.len_utf8();
                        continue;
                    }
                    _ => break,
                }
            }
            raw.push(cell.clone());
            cells.push(match cell.as_str() {
                "_" => Cell::Line(1),
                "=" => Cell::Line(2),
                "\\_" => Cell::ShortLine,
                "\\^" => Cell::SpanDown,
                c => Cell::Text(decode(c, row_line)),
            });
            match tail {
                Some(t) => {
                    offset += cell.len() + opts.tab.len_utf8();
                    rest = t;
                }
                None => break,
            }
        }
        if !from_macro {
            // Cells past the layout's columns, and data where a cell spans down, are dropped.
            let takes: Vec<&Spec> = layout.specs.iter().filter(|s| s.kind != 's').collect();
            for (k, cell) in cells.iter().enumerate() {
                let (no, text, col) = &at[k];
                if k >= takes.len() {
                    if !takes.is_empty() {
                        diag.report(Level::Error, *no, *col, "ignoring extra tbl data cells", &text[col - 1..]);
                    }
                    break;
                }
                if takes[k].kind == '^' && !raw[k].is_empty() && matches!(cell, Cell::Text(_)) {
                    diag.report(Level::Error, *no, *col, "ignoring data in spanned tbl cell", &raw[k]);
                }
            }
        }
        rows.push(Row::Data { cells, raw, layout, line: row_line });
    }
    if !any_data {
        diag.report(Level::Error, start, 2, "tbl without any data cells", "");
    }
    Table { opts, rows, ncols, line: start }
}

/// Reports a macro line in a table, which isn't formatted. The requests that break or place
/// text (`br`, `sp`, `ce`, `rj`) are reported at their arguments and leave nothing; any other
/// macro is reported at its name, and its arguments (returned, maybe empty) stay as text.
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
    Some(args)
}

fn parse_opts(line: &str, lineno: usize, diag: &mut Diagnostics) -> Opts {
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
        let typed: String = b[start..i].iter().collect();
        let word = typed.to_lowercase();
        // An argument in parentheses, maybe after spaces.
        let mut arg = String::new();
        let mut k = i;
        while b.get(k).is_some_and(|c| *c == ' ' || *c == '\t') {
            k += 1;
        }
        let arg_col = k + 2;
        if b.get(k) == Some(&'(') {
            i = k;
            i += 1;
            while i < b.len() && b[i] != ')' {
                arg.push(b[i]);
                i += 1;
            }
            i += 1;
        }
        // The options taking an argument, and how long it must be.
        let want = match word.as_str() {
            "tab" | "decimalpoint" => Some(1),
            "delim" => Some(2),
            "linesize" => Some(0),
            _ => None,
        };
        if let Some(want) = want {
            if arg.is_empty() {
                diag.report(Level::Error, lineno, arg_col, "missing tbl option argument", &typed);
                continue;
            }
            if want > 0 && arg.chars().count() != want {
                let msg = format!("{typed} want {want} have {}", arg.chars().count());
                diag.report(Level::Error, lineno, arg_col, "wrong tbl option argument size", &msg);
                continue;
            }
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
            "delim" | "linesize" | "nowarn" | "nokeep" => {}
            _ => diag.report(Level::Error, lineno, start + 1, "skipping unknown tbl option", &typed),
        }
    }
    o
}

/// Reads layout lines from `i` up to and including the one ending the layout with `.`;
/// returns the index after it. Rows end at `,` or a line's end; parentheses hold arguments.
fn parse_layout(lines: &[(usize, String)], mut i: usize, out: &mut Vec<Layout>, diag: &mut Diagnostics) -> usize {
    let first = out.len();
    while i < lines.len() {
        let (lineno, line) = (lines[i].0, &lines[i].1);
        i += 1;
        let b: Vec<char> = line.chars().collect();
        let mut row = String::new();
        let mut row_col = 1;
        let mut k = 0;
        let mut done = false;
        while k < b.len() {
            match b[k] {
                '(' => {
                    match b[k..].iter().position(|c| *c == ')') {
                        Some(p) => {
                            row.extend(&b[k..=k + p]);
                            k += p + 1;
                        }
                        None => {
                            diag.report(Level::Error, lineno, b.len() + 1, "unmatched parenthesis in tbl layout", "");
                            row.extend(&b[k..]);
                            k = b.len();
                        }
                    }
                    continue;
                }
                ',' => {
                    push_row(&row, lineno, row_col, out, diag);
                    row.clear();
                    row_col = k + 2;
                }
                '.' => {
                    push_row(&row, lineno, row_col, out, diag);
                    row.clear();
                    done = true;
                    if out.len() == first {
                        diag.report(Level::Error, lineno, k + 2, "empty tbl layout", "");
                    }
                    break;
                }
                c => row.push(c),
            }
            k += 1;
        }
        if done {
            break;
        }
        push_row(&row, lineno, row_col, out, diag);
    }
    i
}

fn push_row(row: &str, lineno: usize, col: usize, out: &mut Vec<Layout>, diag: &mut Diagnostics) {
    let l = parse_layout_row(row, lineno, col, diag);
    if !l.specs.is_empty() {
        out.push(l);
    }
}

fn set_font(sp: &mut Spec, name: &str) {
    (sp.bold, sp.italic) = match name {
        "B" | "3" | "CB" => (true, false),
        "I" | "2" | "CI" => (false, true),
        "BI" | "4" => (true, true),
        _ => (false, false),
    };
}

fn parse_layout_row(s: &str, lineno: usize, col: usize, diag: &mut Diagnostics) -> Layout {
    let mut l = Layout::default();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c == 's' || c == 'S' {
            if l.specs.is_empty() {
                diag.report(Level::Warning, lineno, col + i - 1, "tbl line starts with span", "");
            }
        }
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
            ' ' | '\t' => {}
            // A group in parentheses not after `f` or `w` (or the rest of an unmatched one,
            // already reported): skipped.
            '(' => {
                while i < b.len() && b[i] != ')' {
                    i += 1;
                }
                i += 1;
            }
            '.' => {}
            // Vertical placement and zero width: no effect on a terminal.
            'z' | 'Z' | 't' | 'T' | 'd' | 'D' | 'u' | 'U' if !l.specs.is_empty() => {}
            _ if l.specs.is_empty() && !"bBiIeExXfFwWpPvV0123456789".contains(c) => {
                diag.report(Level::Error, lineno, col + i - 1, "invalid character in tbl layout", &c.to_string());
            }
            _ if l.specs.is_empty() => {}
            // A font replaces the one before: `b`, `i`, or `f` and a name. mandoc takes a
            // one- or two-character name as typed; `f(xx` isn't a font it knows, so roman.
            'b' | 'B' => set_font(l.specs.last_mut().unwrap(), "B"),
            'i' | 'I' => set_font(l.specs.last_mut().unwrap(), "I"),
            'e' | 'E' => l.specs.last_mut().unwrap().equal = true,
            'x' | 'X' => l.specs.last_mut().unwrap().max = true,
            'f' | 'F' => {
                let mut name = String::new();
                if b.get(i) == Some(&'(') {
                    i += 1;
                    while i < b.len() && b[i] != ')' {
                        i += 1;
                    }
                    i += 1;
                } else {
                    while i < b.len() && name.len() < 2 && (b[i].is_ascii_uppercase() || b[i].is_ascii_digit()) {
                        name.push(b[i]);
                        i += 1;
                    }
                }
                set_font(l.specs.last_mut().unwrap(), &name);
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
                // Only a number counts; anything else (`w(\n(.lu)`) gives no width.
                if arg.starts_with(|c: char| c.is_ascii_digit() || c == '.') {
                    l.specs.last_mut().unwrap().width = Some(crate::mdoc_term::scaled(&arg));
                }
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
            _ => diag.report(Level::Error, lineno, col + i - 1, "invalid character in tbl layout", &c.to_string()),
        }
    }
    l
}
