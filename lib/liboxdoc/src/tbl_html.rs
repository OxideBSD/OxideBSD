//! tbl as HTML (MAN.md §4.4): a table as an HTML table, laid out as mandoc does. Frames and
//! lines become border styles on the table, its rows and cells; spans become `colspan` and
//! `rowspan`; a line in a cell becomes `hr`.

use crate::html::{self, Html};
use crate::roff::mark;
use crate::tbl::{Cell, Layout, Row, Spec, Table};

/// A line's border style: single or double.
fn line_style(d: u8) -> &'static str {
    if d >= 2 { "double" } else { "solid" }
}

pub fn render(h: &mut Html, t: &Table) {
    // (A table with no data makes nothing at all.)
    if !t.rows.iter().any(|r| matches!(r, Row::Data { .. })) {
        return;
    }
    let o = &t.opts;
    let mut attrs = String::from("class=\"tbl\"");
    if o.allbox {
        attrs.push_str(" border=\"1\"");
    }
    let mut style = String::new();
    if o.allbox || o.frame == 1 {
        style.push_str("border-style: solid;");
    } else if o.frame == 2 {
        style.push_str("border-style: double;");
    }
    // A line before the first row is the table's top border.
    if let Some(Row::Line(d)) = t.rows.first() {
        push_style(&mut style, &format!("border-top-style: {};", line_style(*d)));
    }
    if !style.is_empty() {
        attrs.push_str(&format!(" style=\"{style}\""));
    }
    h.open("table", &attrs);
    for (ri, row) in t.rows.iter().enumerate() {
        let Row::Data { cells, layout, .. } = row else { continue };
        let mut style = String::new();
        if layout.lead > 0 {
            style.push_str(&format!("border-left-style: {};", line_style(layout.lead)));
        }
        // A line after the row is its bottom border (the first, if several follow).
        if let Some(Row::Line(d)) = t.rows.get(ri + 1) {
            push_style(&mut style, &format!("border-bottom-style: {};", line_style(*d)));
        }
        h.open("tr", &if style.is_empty() { String::new() } else { format!("style=\"{style}\"") });
        row_cells(h, t, ri, cells, layout);
        h.close("tr");
    }
    h.close("table");
}

fn push_style(style: &mut String, s: &str) {
    if !style.is_empty() {
        style.push(' ');
    }
    style.push_str(s);
}

/// A data row's cells: one element for each cell that starts a column, up to the row's data.
fn row_cells(h: &mut Html, t: &Table, ri: usize, cells: &[Cell], layout: &Layout) {
    let n = layout.specs.len().min(t.ncols.max(1));
    // (A tab ending the line starts no cell.)
    let cells = match cells.split_last() {
        Some((Cell::Text(last), rest)) if last.is_empty() => rest,
        _ => cells,
    };
    let mut k = 0;
    for j in 0..n {
        let spec = &layout.specs[j];
        if spec.kind == 's' {
            continue;
        }
        // (A short row ends where its data does.)
        let Some(cell) = cells.get(k) else { break };
        k += 1;
        // Continued from above: the cell above spans it.
        if spec.kind == '^' || matches!(cell, Cell::SpanDown) {
            continue;
        }
        let span = 1 + layout.specs[j + 1..n].iter().take_while(|s| s.kind == 's').count();
        let down = 1 + rows_below(t, ri, j);
        let mut attrs = String::new();
        if span > 1 {
            attrs.push_str(&format!("colspan=\"{span}\""));
        }
        if down > 1 {
            push_style(&mut attrs, &format!("rowspan=\"{down}\""));
        }
        let mut style = String::new();
        match spec.kind {
            'r' | 'n' => style.push_str("text-align: right;"),
            'c' => style.push_str("text-align: center;"),
            _ => {}
        }
        // The vertical line after the cell's last column.
        let last = &layout.specs[j + span - 1];
        if last.vline > 0 {
            push_style(&mut style, &format!("border-right-style: {};", line_style(last.vline)));
        }
        if !style.is_empty() {
            push_style(&mut attrs, &format!("style=\"{style}\""));
        }
        h.open("td", &attrs);
        match (spec.kind, cell) {
            ('_' | '=', _) | (_, Cell::Line(_)) => h.raw("<hr/>"),
            (_, Cell::Text(text)) => cell_text(h, spec, text),
            (_, Cell::Block(lines)) => cell_text(h, spec, &lines.join(" ")),
            (_, Cell::ShortLine) => h.word("_"),
            (_, Cell::SpanDown) => {}
        }
        h.close("td");
    }
}

/// The number of data rows right below row `ri` continuing its cell in column `j`.
fn rows_below(t: &Table, ri: usize, j: usize) -> usize {
    let mut count = 0;
    for row in &t.rows[ri + 1..] {
        let Row::Data { cells, layout, .. } = row else { continue };
        let spec = layout.specs.get(j);
        // The data cell for column `j`: one for each column before it that isn't a span.
        let k = layout.specs.iter().take(j).filter(|s| s.kind != 's').count();
        if spec.is_some_and(|s| s.kind == '^') || matches!(cells.get(k), Some(Cell::SpanDown)) {
            count += 1;
        } else {
            break;
        }
    }
    count
}

/// Text in a cell, starting in the column's font, which its escapes change.
fn cell_text(h: &mut Html, spec: &Spec, text: &str) {
    let mut fonts = html::Fonts::default();
    fonts.esc = match (spec.bold, spec.italic) {
        (true, true) => Some(mark::FONT_BI),
        (true, false) => Some(mark::FONT_B),
        (false, true) => Some(mark::FONT_I),
        _ => None,
    };
    h.text(text, &mut fonts, false);
}
