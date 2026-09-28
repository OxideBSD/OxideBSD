//! Tables on a terminal: column widths, alignment, spans, lines and frames, laid out the way
//! mandoc lays them out. Each cell is formatted by a scratch [`Term`], so fonts, escapes and
//! special characters come out as they do in running text.

use crate::tbl::{Cell, Row, Spec, Table};
use crate::term::{Style, Term};

/// A cell formatted: its lines and their printed widths.
struct Formatted {
    lines: Vec<(String, usize)>,
}

impl Formatted {
    fn width(&self) -> usize {
        self.lines.iter().map(|(_, w)| *w).max().unwrap_or(0)
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

/// Formats `text` in a scratch terminal `width` columns wide (a text block's width, or wide
/// enough for any cell).
fn format(t: &Term, text: &str, style: Style, width: usize) -> Formatted {
    let mut s = Term::new(width, t.encoding, t.styling);
    s.tab_width = t.tab_width;
    let mut lines = Vec::new();
    for para in text.split('\n') {
        for w in para.split(' ').filter(|w| !w.is_empty()) {
            s.word(w, style);
        }
        s.flush();
    }
    let out = s.finish();
    for l in out.lines() {
        lines.push((l.to_string(), visible(l)));
    }
    if lines.is_empty() {
        lines.push((String::new(), 0));
    }
    Formatted { lines }
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

/// One laid-out data row: for each column, the formatted cell (if it starts there), its
/// kind, and the number of columns it spans.
struct Laid {
    cells: Vec<Option<(Formatted, char, usize, Option<u8>)>>,
}

pub fn render(t: &mut Term, tbl: &Table) {
    let n = tbl.ncols.max(1);
    let o = &tbl.opts;
    // A text block's width, unless the layout gives one: the line over the columns plus one.
    let block_width = (t.width / (n + 1)).max(1);
    let big = 10_000;

    // Format the cells and find the natural widths.
    let mut widths = vec![0usize; n];
    let mut ints = vec![0usize; n];
    let mut fracs = vec![0usize; n];
    let mut spans: Vec<(usize, usize, usize)> = Vec::new();
    let mut spacing = vec![3usize; n];
    let mut vlines = vec![0u8; n + 1];
    let mut equal = vec![false; n];
    let mut laid_rows: Vec<Option<Laid>> = Vec::new();
    for row in &tbl.rows {
        let Row::Data { cells, layout, .. } = row else {
            laid_rows.push(None);
            continue;
        };
        vlines[0] = vlines[0].max(layout.lead);
        let mut laid = Laid { cells: (0..n).map(|_| None).collect() };
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
            let spec = layout.specs.get(j).cloned().unwrap_or_else(|| Spec { kind: 'l', bold: false, italic: false, width: None, equal: false, spacing: None, vline: 0 });
            if spec.kind == 's' {
                continue;
            }
            let span = 1 + layout.specs.iter().skip(j + 1).take_while(|s| s.kind == 's').count();
            let cell = cells.get(k);
            k += 1;
            let style = style_of(&spec);
            let (f, line) = match (cell, spec.kind) {
                (_, '_') => (format(t, "", style, big), Some(1)),
                (_, '=') => (format(t, "", style, big), Some(2)),
                (Some(Cell::Line(d)), _) => (format(t, "", style, big), Some(*d)),
                (Some(Cell::Block(text)), _) => (format(t, text, style, spec.width.unwrap_or(block_width)), None),
                (Some(Cell::Text(text)), _) => (format(t, text, style, big), None),
                (Some(Cell::ShortLine), _) => (format(t, "", style, big), Some(0)),
                _ => (format(t, "", style, big), None),
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
    // A spanning cell wider than its columns widens the last of them.
    for &(j, span, w) in &spans {
        let have: usize = (j..j + span).map(|c| widths[c]).sum::<usize>() + (j..j + span - 1).map(|c| spacing[c]).sum::<usize>();
        if w > have {
            widths[j + span - 1] += w - have;
        }
    }

    // Column positions, from the left edge of the table's content (after a frame's line).
    let mut start = vec![0usize; n];
    for j in 1..n {
        start[j] = start[j - 1] + widths[j - 1] + spacing[j - 1];
    }
    let content = start[n - 1] + widths[n - 1] + 1;
    let frame = o.frame > 0;
    let total = content + if frame { 2 } else { 0 };
    let avail = t.rmargin.saturating_sub(t.offset);
    let indent = t.offset + if o.center { (avail.saturating_sub(total) + 1) / 2 } else { 0 };
    let pad = " ".repeat(indent);

    // A horizontal line across the table, with `+` where vertical lines cross it.
    let rule = |double: bool| -> String {
        let fill = if double { '=' } else { '-' };
        let mut line: Vec<char> = vec![fill; content];
        for j in 0..n.saturating_sub(1) {
            let at = start[j] + widths[j] + 1;
            for v in 0..vlines[j + 1] as usize {
                if at + v < content {
                    line[at + v] = '+';
                }
            }
        }
        let body: String = line.into_iter().collect();
        if frame { format!("{pad}+{body}+") } else { format!("{pad}{body}") }
    };

    t.flush();
    t.vspace();
    if frame {
        for _ in 0..o.frame {
            t.raw_line(&rule(false));
        }
    }
    let nrows = laid_rows.len();
    for (ri, (row, laid)) in tbl.rows.iter().zip(&laid_rows).enumerate() {
        match (row, laid) {
            (Row::Line(d), _) => t.raw_line(&rule(*d == 2)),
            (_, Some(laid)) => {
                let height = laid.cells.iter().flatten().map(|(f, ..)| f.lines.len()).max().unwrap_or(1);
                for li in 0..height {
                    let mut s = String::new();
                    s.push_str(&pad);
                    if frame {
                        s.push('|');
                    }
                    let mut col = 0;
                    for j in 0..n {
                        let Some((f, kind, span, line)) = &laid.cells[j] else { continue };
                        // Get to the column's start, drawing vertical lines on the way.
                        while col < start[j] {
                            let sep_start = start[j] - spacing[j - 1];
                            let bar = col >= sep_start + 1 && col < sep_start + 1 + vlines[j] as usize;
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
                            'c' => (w.saturating_sub(text.1) + 1) / 2,
                            'n' if line.is_none() && *span == 1 => ints[j].saturating_sub(numeric_split(&text.0, tbl.opts.decimal).0),
                            _ => 0,
                        };
                        s.push_str(&" ".repeat(lead));
                        s.push_str(&text.0);
                        col = start[j] + lead + text.1;
                    }
                    if frame {
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
                    t.raw_line(&rule(false));
                }
            }
            _ => {}
        }
    }
    if frame {
        for _ in 0..o.frame {
            t.raw_line(&rule(false));
        }
    }
}
