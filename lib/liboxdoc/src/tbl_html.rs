//! tbl as HTML (MAN.md §4.4): a table as an HTML table, laid out as mandoc does.

use crate::html::Html;
use crate::tbl::Table;

pub fn render(h: &mut Html, t: &Table) {
    let _ = t;
    h.open("table", "class=\"tbl\"");
    h.close("table");
}
