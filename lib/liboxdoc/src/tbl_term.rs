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
    use crate::roff::mark::BACK;
    // Moving left overprints what follows; at the end of a line it prints nothing, and a cell
    // is as wide as its text without it, as in mandoc.
    if text.iter().any(|l| l.contains(BACK)) {
        let trimmed: Vec<String> = text.iter().map(|l| l.trim_end_matches(BACK).to_string()).collect();
        let mut f = format_filled(t, &trimmed, style, width);
        let plain: Vec<String> = text.iter().map(|l| l.replace(BACK, "")).collect();
        f.min_width = format_filled(t, &plain, style, width).width();
        return f;
    }
    format_filled(t, text, style, width)
}

fn format_filled(t: &Term, text: &[String], style: Style, width: usize) -> Formatted {
    let mut s = Term::new(width, t.encoding, t.styling);
    s.tab_width = t.tab_width;
    let mut lines = Vec::new();
    let nbsp = |n: usize| crate::roff::mark::NBSP.to_string().repeat(n);
    let last_line = text.len().saturating_sub(1);
    for (li, line) in text.iter().enumerate() {
        // Spaces at the cell's edges are kept, and count in its width.
        let lead = if li == 0 { line.len() - line.trim_start_matches(' ').len() } else { 0 };
        let trail = if li == last_line { line.len() - line.trim_end_matches(' ').len() } else { 0 };
        let body = line.trim_matches(' ');
        if body.is_empty() {
            if lead > 0 {
                s.word(&nbsp(lead), style);
            } else if li > 0 {
                // An empty line is joined like any other: one more space between the words.
                s.add_space(1);
            }
            continue;
        }
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
        words[0].0.insert_str(0, &nbsp(lead));
        words.last_mut().unwrap().0.push_str(&nbsp(trail));
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
    // The terminal drops spaces at the end of a line; a cell keeps its trailing ones.
    let trail = text.last().map_or(0, |l| l.len() - l.trim_end_matches(' ').len());
    if trail > 0 && text.last().is_some_and(|l| !l.trim().is_empty())
        && let Some(last) = lines.last_mut()
    {
        last.0.push_str(&" ".repeat(trail));
        last.1 += trail;
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

/// Where a number aligns, as a byte offset into its decoded text: the last `\&`, or else the
/// last decimal point next to a digit, or else just after the last digit. `None` when the text
/// has no digit: it isn't a number.
fn number_point(s: &str, point: char) -> Option<usize> {
    if let Some(p) = s.rfind(crate::roff::mark::ZERO) {
        return Some(p);
    }
    let last_digit = s.char_indices().filter(|(_, c)| c.is_ascii_digit()).last()?;
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let dot = (0..chars.len()).rev().find(|&k| {
        chars[k].1 == point
            && (k > 0 && chars[k - 1].1.is_ascii_digit() || chars.get(k + 1).is_some_and(|(_, c)| c.is_ascii_digit()))
    });
    Some(dot.map_or(last_digit.0 + last_digit.1.len_utf8(), |k| chars[k].0))
}

/// Characters drawn as an overstrike (`+\bo`) in `s`: mandoc measures each as three columns.
fn struck(t: &Term, s: &str) -> usize {
    if t.encoding != crate::term::Encoding::Ascii {
        return 0;
    }
    s.chars().filter(|c| !c.is_ascii() && crate::term::ascii_for(*c).contains('\u{8}')).count()
}

/// A text block's width: its words, filled with single spaces between them (whatever was
/// typed) into lines at most `limit` wide, and the longest of those lines.
fn measure_block(t: &Term, text: &[String], style: Style, limit: usize) -> usize {
    let (mut longest, mut line) = (0, 0);
    for w in text.iter().flat_map(|l| l.split(' ')).filter(|w| !w.is_empty()) {
        let ww = format(t, &[w.to_string()], style, 10_000).width() + 2 * struck(t, w);
        line = if line > 0 && line + 1 + ww <= limit { line + 1 + ww } else { ww };
        longest = longest.max(line);
    }
    longest
}

/// One laid-out data row: for each column, the formatted cell (if it starts there), its
/// kind, and the number of columns it spans.
struct Laid {
    cells: Vec<Option<(Formatted, char, usize, Option<u8>)>>,
    /// For a number in an `n` column, the width of its part before the alignment point.
    nums: Vec<Option<usize>>,
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
        let mut laid = Laid { cells: (0..n).map(|_| None).collect(), nums: vec![None; n], vl };
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
                (Some(Cell::Text(text)), _) => {
                    let mut f = format(t, std::slice::from_ref(text), style, big);
                    f.min_width = f.min_width.max(f.width() + 2 * struck(t, text));
                    (f, None)
                }
                (Some(Cell::ShortLine), _) => (format(t, &none, style, big), Some(0)),
                _ => (format(t, &none, style, big), None),
            };
            let w = f.width();
            if span > 1 {
                spans.push((j, span, w));
            } else if let (Some(Cell::Text(raw)), 'n', None) = (cell, spec.kind, line)
                && let Some(p) = number_point(raw, o.decimal)
            {
                let int = format(t, &[raw[..p].to_string()], style, big).width();
                ints[j] = ints[j].max(int);
                fracs[j] = fracs[j].max(w.saturating_sub(int));
                laid.nums[j] = Some(int);
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
    // A spanning cell wider than its columns widens them.
    for &(j, span, w) in &spans {
        let have: usize = (j..j + span).map(|c| widths[c]).sum::<usize>() + (j..j + span - 1).map(|c| spacing[c]).sum::<usize>();
        if w > have {
            // The missing width goes to the narrowest columns, raising them together to the
            // next narrowest; when it can't, each of them from the left takes an even share
            // rounded up, until it runs out.
            let mut extra = w - have;
            while extra > 0 {
                let cols = j..j + span;
                let min = cols.clone().map(|c| widths[c]).min().unwrap_or(0);
                let low: Vec<usize> = cols.clone().filter(|c| widths[*c] == min).collect();
                let next = cols.map(|c| widths[c]).filter(|w| *w > min).min();
                match next {
                    Some(next) if extra >= low.len() * (next - min) => {
                        for c in &low {
                            widths[*c] = next;
                        }
                        extra -= low.len() * (next - min);
                    }
                    _ => {
                        let share = extra.div_ceil(low.len());
                        for c in low {
                            let add = share.min(extra);
                            widths[c] += add;
                            extra -= add;
                        }
                    }
                }
            }
        }
    }
    // Numbers in a column wider than they need are centred as a block.
    let num_lead: Vec<usize> = (0..n).map(|j| (widths[j] - (ints[j] + fracs[j]).min(widths[j])) / 2).collect();
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
    // Centred in the space from the page's left edge plus the indent to the right margin, so
    // a table too wide for its indent moves left of it, as in mandoc (which counts one column
    // less for such a table).
    let indent = if o.center {
        let mut size = content - 1 + usize::from(left) + usize::from(right);
        if t.offset + size > t.rmargin {
            size -= 1;
        }
        (t.offset + t.rmargin).saturating_sub(size) / 2
    } else {
        t.offset
    };
    let pad = " ".repeat(indent);

    // A horizontal line across the table, with `+` where vertical lines cross it.
    // Where the first of `bars` vertical lines goes in the gap before column `j`: in its
    // middle.
    let bar_at = |j: usize, bars: usize| start[j] - spacing[j - 1] + (spacing[j - 1].saturating_sub(bars) + 1) / 2;
    // Lines cross it where the rows above and below it have them (`vl`).
    let rule = |double: bool, vl: &[u8]| -> String {
        let fill = if double { '=' } else { '-' };
        let mut line: Vec<char> = vec![fill; content];
        for j in 0..n.saturating_sub(1) {
            let bars = vl.get(j + 1).copied().unwrap_or(0) as usize;
            let at = bar_at(j + 1, bars);
            for v in 0..bars {
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
                        // A line across the cell (not `\_`) reaches the vertical lines on either
                        // side, crossing those on its left and the first on its right.
                        let full = matches!(line, Some(1 | 2)) && li == 0;
                        let fill = if *line == Some(2) { '=' } else { '-' };
                        // Get to the column's start, drawing vertical lines on the way.
                        if j > 0 {
                            let bars = laid.vl[j] as usize;
                            let b0 = bar_at(j, bars);
                            while col < start[j] {
                                let bar = col >= b0 && col < b0 + bars;
                                s.push(match (bar, full) {
                                    (true, true) => '+',
                                    (true, false) => '|',
                                    (false, true) if bars > 0 && col == b0 + bars => fill,
                                    _ => ' ',
                                });
                                col += 1;
                            }
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
                        // A one-line cell aligns by its measured width.
                        let tw = if f.lines.len() == 1 && line.is_none() { text.1.max(f.min_width) } else { text.1 };
                        let lead = match kind {
                            'r' => w.saturating_sub(tw),
                            'c' => w.saturating_sub(tw) / 2,
                            // Alphabetic: one column in, without widening the column.
                            'a' if line.is_none() => 1,
                            'n' if line.is_none() && *span == 1 => match laid.nums[j] {
                                Some(int) => num_lead[j] + ints[j] - int,
                                // Not a number: centred.
                                None => w.saturating_sub(tw) / 2,
                            },
                            _ => 0,
                        };
                        s.push_str(&" ".repeat(lead));
                        s.push_str(&text.0);
                        col = start[j] + lead + text.1;
                        let next = j + span;
                        if full && next < n && laid.vl[next] > 0 {
                            let b0 = bar_at(next, laid.vl[next] as usize);
                            while col < b0 {
                                s.push(fill);
                                col += 1;
                            }
                            s.push('+');
                            col += 1;
                        }
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
        // The bottom line stands in for the next blank line.
        t.skip_vspace = true;
    }
}
