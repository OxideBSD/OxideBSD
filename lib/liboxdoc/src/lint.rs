//! Checks of input lines as typed (MAN.md §6), made where mandoc makes them so that the same
//! page lints the same way with either. Columns are 1-based byte positions.

use crate::diag::{Diagnostics, Level};

/// The checks on a text line, before its escapes are decoded. `literal` is no-fill mode;
/// `mdoc` enables the checks only mdoc(7) makes.
pub fn text_line(diag: &mut Diagnostics, line: usize, raw: &str, literal: bool, mdoc: bool) {
    if literal {
        return;
    }
    // A line that could have been broken earlier: longer than 80 bytes, with a space in it.
    if raw.len() > 80 && raw.contains(' ') {
        let start: String = raw.chars().take(20).collect();
        diag.report(Level::Style, line, raw.len(), "input text line longer than 80 bytes", &format!("{start}..."));
    }
    if let Some(p) = raw.find('\t') {
        diag.report(Level::Warning, line, p + 1, "tab in filled text", "");
    }
    if mdoc {
        new_sentence(diag, line, raw);
    }
}

/// A sentence that doesn't start on a new line: a period after two letters or digits (but not
/// "Inc." or "vs."), then one to three spaces and a capital letter.
fn new_sentence(diag: &mut Diagnostics, line: usize, raw: &str) {
    let b = raw.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c != b'.' || i < 2 || !b[i - 2].is_ascii_alphanumeric() || !b[i - 1].is_ascii_alphanumeric() {
            continue;
        }
        if &b[i - 2..i] == b"nc" || &b[i - 2..i] == b"vs" {
            continue;
        }
        let mut j = i + 1;
        if b.get(j) != Some(&b' ') {
            continue;
        }
        j += 1;
        for _ in 0..2 {
            if b.get(j) == Some(&b' ') {
                j += 1;
            }
        }
        if b.get(j).is_some_and(|c| c.is_ascii_uppercase()) {
            diag.report(Level::Warning, line, j + 1, "new sentence, new line", "");
        }
    }
}
