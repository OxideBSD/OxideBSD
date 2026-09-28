//! Tables on a terminal: column widths, alignment, spans, lines and frames, laid out the way
//! mandoc lays them out. Each cell is formatted by a scratch [`Term`], so fonts, escapes and
//! special characters come out as they do in running text.

use crate::tbl::{Cell, Row, Spec, Table};
use crate::term::{Style, Term};

/// A cell formatted: its lines and their printed widths.
struct Formatted {
    lines: Vec<(String, usize)>,
    /// The width it claims even when its lines are shorter.
    min_width: usize,
}

impl Formatted {
    fn width(&self) -> usize {
        self.lines.iter().map(|(_, w)| *w).max().unwrap_or(0).max(self.min_width)
    }
}

/// Printed width of a formatted line: overstrike (`x\bx`) and SGR sequences take no columns.
fn visible(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{8}' => n -= 1,
            '\x1b' => {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            _ => n += 1,
        }
    }
    n
}

/// Formats text lines, filled, in a scratch terminal `width` columns wide (a text block's
/// width, or wide enough for any cell). Spaces between words are kept as typed; a sentence
/// ending a line gets no extra one, unlike running text.
fn format(t: &Term, text: &[String], style: Style, width: usize) -> Formatted {
    let mut s = Term::new(width, t.encoding, t.styling);
    s.tab_width = t.tab_width;
    let mut lines = Vec::new();
    for line in text {
        let line = line.trim_end_matches(' ');
        let mut words: Vec<(&str, usize)> = Vec::new();
        let mut spaces = 0;
        for w in line.split(' ') {
            if w.is_empty() {
                spaces += 1;
                continue;
            }
            words.push((w, spaces + 1));
            spaces = 0;
        }
        for (i, (w, sp)) in words.iter().enumerate() {
            if i > 0 {
                s.set_space(*sp);
            }
            s.word(w, style);
        }
    }
    s.flush();
    let out = s.finish();
    for l in out.lines() {
        lines.push((l.to_string(), visible(l)));
    }
    if lines.is_empty() {
        lines.push((String::new(), 0));
    }
    Formatted { lines, min_width: 0 }
}

fn style_of(spec: &Spec) -> Style {
    match (spec.bold, spec.italic) {
        (true, true) => Style::BoldUnder,
        (true, false) => Style::Bold,
        (false, true) => Style::Under,
        _ => Style::None,
    }
}

/// The integer and fraction widths of a number, split at the decimal point (or after the
/// last digit, or at the end).
fn numeric_split(s: &str, point: char) -> (usize, usize) {
    let w = visible(s);
    let p = s.rfind(point).or_else(|| s.rfind(|c: char| c.is_ascii_digit()).map(|p| p + 1)).unwrap_or(s.len());
    let int = visible(&s[..p]);
    (int, w - int)
}

/// A text block's width: its words, filled with single spaces between them (whatever was
/// typed) into lines at most `limit` wide, and the longest of those lines.
fn measure_block(t: &Term, text: &[String], style: Style, limit: usize) -> usize {
    let (mut longest, mut line) = (0, 0);
    for w in text.iter().flat_map(|l| l.split(' ')).filter(|w| !w.is_empty()) {
        let ww = format(t, &[w.to_string()], style, 10_000).width();
        line = if line > 0 && line + 1 + ww <= limit { line + 1 + ww } else { ww };
        longest = longest.max(line);
    }
    longest
}

/// One laid-out data row: for each column, the formatted cell (if it starts there), its
/// kind, and the number of columns it spans.
struct Laid {
    cells: Vec<Option<(Formatted, char, usize, Option<u8>)>>,
    /// The row's own vertical lines: before the first column, then after each.
    vl: Vec<u8>,
}

/// Lays out a table; man(7) puts a blank line before it, mdoc doesn't.
pub fn render(t: &mut Term, tbl: &Table, space_before: bool) {
    let n = tbl.ncols.max(1);
    let o = &tbl.opts;
    // A text block's width, unless the layout gives one: the line over the columns plus one.
    let block_width = (t.width / (n + 1)).max(1);
    let big = 10_000;
    let none: [String; 0] = [];

    // Format the cells and find the natural widths.
    let mut widths = vec![0usize; n];
    let mut ints = vec![0usize; n];
    let mut fracs = vec![0usize; n];
    let mut spans: Vec<(usize, usize, usize)> = Vec::new();
    let mut spacing = vec![3usize; n];
    let mut vlines = vec![0u8; n + 1];
    let mut equal = vec![false; n];
    // `x` belongs to the column, whichever layout row gives it.
    let mut max = vec![false; n];
    for row in &tbl.rows {
        if let Row::Data { layout, .. } = row {
            for (j, spec) in layout.specs.iter().enumerate().take(n) {
                max[j] |= spec.max;
            }
        }
    }
    let mut laid_rows: Vec<Option<Laid>> = Vec::new();
    // Text blocks, formatted once the widths are known: row, column, text.
    let mut later: Vec<(usize, usize, &[String], Style)> = Vec::new();
    for (ri, row) in tbl.rows.iter().enumerate() {
        let Row::Data { cells, layout, .. } = row else {
            laid_rows.push(None);
            continue;
        };
        vlines[0] = vlines[0].max(layout.lead);
        let mut vl = vec![0u8; n + 1];
        vl[0] = layout.lead;
        for (j, spec) in layout.specs.iter().enumerate().take(n) {
            vl[j + 1] = spec.vline;
        }
        if o.allbox {
            vl.fill(1);
        }
        let mut laid = Laid { cells: (0..n).map(|_| None).collect(), vl };
        for (j, spec) in layout.specs.iter().enumerate().take(n) {
            vlines[j + 1] = vlines[j + 1].max(spec.vline);
            if let Some(s) = spec.spacing {
                spacing[j] = s;
            }
            if let Some(w) = spec.width {
                widths[j] = widths[j].max(w);
            }
            equal[j] |= spec.equal;
        }
        // Map the cells to the layout's columns; a spanned (`s`) column takes none.
        let mut k = 0;
        for j in 0..n {
            let spec = layout.specs.get(j).cloned().unwrap_or_else(|| Spec::new('l'));
            if spec.kind == 's' {
                continue;
            }
            let span = 1 + layout.specs.iter().skip(j + 1).take_while(|s| s.kind == 's').count();
            let cell = cells.get(k);
            k += 1;
            let style = style_of(&spec);
            let (f, line) = match (cell, spec.kind) {
                (_, '_') => (format(t, &none, style, big), Some(1)),
                (_, '=') => (format(t, &none, style, big), Some(2)),
                (Some(Cell::Line(d)), _) => (format(t, &none, style, big), Some(*d)),
                (Some(Cell::Block(text)), _) => {
                    // A block claims the width of its words filled with single spaces up to its
                    // width, and is formatted once the column's width is known.
                    later.push((ri, j, text, style));
                    let mut f = format(t, &none, style, big);
                    f.min_width = measure_block(t, text, style, spec.width.unwrap_or(block_width));
                    (f, None)
                }
                (Some(Cell::Text(text)), _) => (format(t, std::slice::from_ref(text), style, big), None),
                (Some(Cell::ShortLine), _) => (format(t, &none, style, big), Some(0)),
                _ => (format(t, &none, style, big), None),
            };
            let w = f.width();
            if span > 1 {
                spans.push((j, span, w));
            } else if spec.kind == 'n' && line.is_none() {
                let text = &f.lines[0].0;
                let (i, fr) = numeric_split(text, o.decimal);
                ints[j] = ints[j].max(i);
                fracs[j] = fracs[j].max(fr);
            } else {
                widths[j] = widths[j].max(w);
            }
            laid.cells[j] = Some((f, spec.kind, span, line));
        }
        laid_rows.push(Some(laid));
    }
    for j in 0..n {
        widths[j] = widths[j].max(ints[j] + fracs[j]);
    }
    if o.allbox {
        for v in vlines.iter_mut() {
            *v = 1;
        }
    }
    // Equal columns: all as wide as the widest.
    let eq = (0..n).filter(|j| equal[*j]).map(|j| widths[j]).max().unwrap_or(0);
    for j in 0..n {
        if equal[j] {
            widths[j] = eq;
        }
    }
    // A spanning cell wider than its columns widens them evenly, the leftmost first by the
    // odd columns.
    for &(j, span, w) in &spans {
        let have: usize = (j..j + span).map(|c| widths[c]).sum::<usize>() + (j..j + span - 1).map(|c| spacing[c]).sum::<usize>();
        if w > have {
            let extra = w - have;
            for (i, c) in (j..j + span).enumerate() {
                widths[c] += extra / span + usize::from(i < extra % span);
            }
        }
    }
    // `x` columns share the width the others leave, less 3 columns between each two and the
    // outer lines, as evenly as whole columns allow. Like mandoc, this copies a GNU tbl quirk
    // with five of them.
    let nx = max.iter().filter(|m| **m).count();
    if nx > 0 {
        let outer = if o.frame > 0 { 2 } else { usize::from(vlines[0] > 0) + usize::from(vlines[n] > 0) };
        let fixed: usize = (0..n).filter(|j| !max[*j]).map(|j| widths[j]).sum::<usize>() + 3 * (n - 1) + outer;
        let avail = t.rmargin.saturating_sub(t.offset);
        if avail > fixed {
            let xw = avail - fixed;
            let quirk = if nx == 5 && matches!(xw % 5 + 2, 3 | 4) { xw % 5 + 2 } else { 0 };
            let (mut k, mut given) = (0, 0);
            for j in 0..n {
                if !max[j] {
                    continue;
                }
                k += 1;
                let mut w = ((xw * k) as f64 / nx as f64 - given as f64 + 0.4995) as usize;
                if k == quirk {
                    w -= 1;
                }
                given += w;
                widths[j] = w;
            }
        }
    }
    // Text blocks, at their column's width.
    for (ri, j, text, style) in later {
        if let Some(Some(laid)) = laid_rows.get_mut(ri)
            && let Some(cell) = laid.cells[j].as_mut()
        {
            let span = cell.2;
            let w = (j..j + span).map(|c| widths[c]).sum::<usize>() + (j..j + span - 1).map(|c| spacing[c]).sum::<usize>();
            cell.0 = format(t, text, style, w.max(1));
        }
    }

    // Column positions, from the left edge of the table's content (after a frame's line).
    let mut start = vec![0usize; n];
    for j in 1..n {
        start[j] = start[j - 1] + widths[j - 1] + spacing[j - 1];
    }
    let content = start[n - 1] + widths[n - 1] + 1;
    let frame = o.frame > 0;
    // Lines down the table's edges: a frame's, or the layout's first and last `|` (one line,
    // even for `||`).
    let left = frame || vlines[0] > 0;
    let right = frame || vlines[n] > 0;
    let total = content + usize::from(left) + usize::from(right);
    let avail = t.rmargin.saturating_sub(t.offset);
    let indent = t.offset + if o.center { (avail.saturating_sub(total) + 1) / 2 } else { 0 };
    let pad = " ".repeat(indent);

    // A horizontal line across the table, with `+` where vertical lines cross it.
    // Lines cross it where the rows above and below it have them (`vl`).
    let rule = |double: bool, vl: &[u8]| -> String {
        let fill = if double { '=' } else { '-' };
        let mut line: Vec<char> = vec![fill; content];
        for j in 0..n.saturating_sub(1) {
            let at = start[j] + widths[j] + 1;
            for v in 0..vl.get(j + 1).copied().unwrap_or(0) as usize {
                if at + v < content {
                    line[at + v] = '+';
                }
            }
        }
        let body: String = line.into_iter().collect();
        format!("{pad}{}{body}{}", if left { "+" } else { "" }, if right { "+" } else { "" })
    };

    if space_before {
        t.table_space();
    } else {
        t.flush();
    }
    // The vertical lines crossing a horizontal one after row `i`: those of the data rows on
    // either side.
    let data_vl = |i: usize| laid_rows.get(i).and_then(|l| l.as_ref()).map(|l| l.vl.clone());
    let crossing = |after: usize| -> Vec<u8> {
        let prev = (0..=after).rev().find_map(data_vl);
        let next = (after + 1..laid_rows.len()).find_map(data_vl);
        let mut v = vec![0u8; n + 1];
        for src in [prev, next].into_iter().flatten() {
            for (a, b) in v.iter_mut().zip(src) {
                *a = (*a).max(b);
            }
        }
        v
    };
    // A double frame's outer line doesn't show where the columns' lines cross it.
    if frame {
        let next_only = (0..laid_rows.len()).find_map(data_vl).unwrap_or_default();
        for i in 0..o.frame {
            t.raw_line(&rule(false, if i + 1 == o.frame { &next_only } else { &[] }));
        }
    }
    let nrows = laid_rows.len();
    for (ri, (row, laid)) in tbl.rows.iter().zip(&laid_rows).enumerate() {
        match (row, laid) {
            (Row::Line(d), _) => t.raw_line(&rule(*d == 2, &crossing(ri))),
            (_, Some(laid)) => {
                let height = laid.cells.iter().flatten().map(|(f, ..)| f.lines.len()).max().unwrap_or(1);
                for li in 0..height {
                    let mut s = String::new();
                    s.push_str(&pad);
                    if left {
                        s.push('|');
                    }
                    let mut col = 0;
                    for j in 0..n {
                        let Some((f, kind, span, line)) = &laid.cells[j] else { continue };
                        // Get to the column's start, drawing vertical lines on the way.
                        while col < start[j] {
                            let sep_start = start[j] - spacing[j - 1];
                            let bar = col >= sep_start + 1 && col < sep_start + 1 + laid.vl[j] as usize;
                            s.push(if bar { '|' } else { ' ' });
                            col += 1;
                        }
                        let w = (j..j + span).map(|c| widths[c]).sum::<usize>() + (j..j + span - 1).map(|c| spacing[c]).sum::<usize>();
                        let text = match line {
                            Some(d) if li == 0 => {
                                let c = if *d == 2 { '=' } else { '-' };
                                let len = if *d == 0 { f.width().max(1).min(w) } else { w };
                                (c.to_string().repeat(len), len)
                            }
                            _ => f.lines.get(li).cloned().unwrap_or_default(),
                        };
                        let lead = match kind {
                            'r' => w.saturating_sub(text.1),
                            'c' => w.saturating_sub(text.1) / 2,
                            'n' if line.is_none() && *span == 1 => ints[j].saturating_sub(numeric_split(&text.0, tbl.opts.decimal).0),
                            _ => 0,
                        };
                        s.push_str(&" ".repeat(lead));
                        s.push_str(&text.0);
                        col = start[j] + lead + text.1;
                    }
                    if right {
                        while col < content {
                            s.push(' ');
                            col += 1;
                        }
                        s.push('|');
                    }
                    t.raw_line(&s);
                }
                // allbox: a line after every row but the last.
                if o.allbox && ri + 1 < nrows {
                    t.raw_line(&rule(false, &crossing(ri)));
                }
            }
            _ => {}
        }
    }
    if frame {
        let last = (0..laid_rows.len()).rev().find_map(data_vl).unwrap_or_default();
        for i in 0..o.frame {
            t.raw_line(&rule(false, if i == 0 { &last } else { &[] }));
        }
        t.skip_vspace = true;
    }
}
