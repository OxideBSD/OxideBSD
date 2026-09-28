//! Renders a man(7) document tree as HTML (MAN.md §5, `-T html`).

use crate::html::{self, Html, HtmlOptions};
use crate::tree::Document;

pub fn render(doc: &Document, opts: &HtmlOptions, comments: &[String]) -> String {
    let mut h = Html::new();
    html::begin_document(&mut h, opts, &format!("{}({})", doc.meta.title, doc.meta.section), comments);
    html::end_document(&mut h, opts);
    h.finish()
}
