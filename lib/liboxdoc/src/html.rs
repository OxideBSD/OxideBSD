//! The HTML output device (MAN.md §5, `-T html`): a writer that lays out HTML source as
//! mandoc does, so pages can be checked against it byte for byte, and the document frame
//! (head, header and footer tables) the language renderers (`mdoc_html`, `man_html`) fill.
//!
//! The source is filled like text: words and the phrasing elements around them run on, and a
//! line breaks at a space once the run after it, as it is being written, would pass column 80;
//! the new line is indented one step further than the elements open at that moment. Block
//! elements start their own lines, indented two columns for each enclosing element that
//! indents its contents.

use crate::roff::mark;

/// The column a filled line may not pass.
const WIDTH: usize = 80;

/// Options of the HTML device (`-O`).
#[derive(Clone, Debug, Default)]
pub struct HtmlOptions {
    /// A stylesheet to link instead of the built-in style (`-O style=`).
    pub style: Option<String>,
    /// A template for links to other pages, `%N` the name and `%S` the section (`-O man=`).
    pub man: Option<String>,
    /// Only the page's own content, without the document around it (`-O fragment`).
    pub fragment: bool,
}

/// OxideBSD's default style, embedded in a page that links no stylesheet. The full one is
/// `/usr/share/misc/oxdoc.css`.
const DEFAULT_STYLE: &[&str] = &[
    "table.head, table.foot { width: 100%; border-collapse: collapse; }",
    ".head-vol { text-align: center; }",
    ".head-rtitle, .foot-os { text-align: right; }",
    ".Nm, .Fl, .Cm, .Ic, .Fn, .Fd, .In, .Cd, .Ms { font-weight: bold; }",
    "code.Nm, .Fl, .Cm, .Ic, .Fn, .Fd, code.In, .Cd { font-family: inherit; }",
    ".Pa, .Ad { font-style: italic; }",
    ".Nd, .Op, .Bf { display: inline; }",
    ".Bl-diag > dt { font-weight: bold; }",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Part of the running text.
    Phrase,
    /// Starts its own line; its contents follow on that line.
    Block,
}

/// How an element is laid out: whether it is a block, and whether it indents what it holds.
fn layout(tag: &str) -> (Class, bool) {
    match tag {
        "html" | "body" | "section" | "div" | "h1" | "h2" | "dt" | "td" | "th" | "title" | "pre" | "math" => (Class::Block, false),
        "head" | "table" | "tr" | "dl" | "ul" | "ol" | "p" | "dd" | "li" | "style" | "mrow" | "mtable" | "mtr" => (Class::Block, true),
        _ => (Class::Phrase, false),
    }
}

struct Open {
    tag: String,
    class: Class,
    indents: bool,
    /// Something that ended a line was output inside it: its end tag goes on a line of its own.
    had_block: bool,
}

/// The HTML source writer.
pub struct Html {
    out: String,
    /// Columns on the current output line.
    col: usize,
    /// Enclosing elements that indent their contents.
    indent: usize,
    stack: Vec<Open>,
    /// The run of text and phrasing tags since the last break opportunity, not yet placed.
    unit: String,
    /// A space, where the line may break, goes before `unit`.
    unit_space: bool,
    /// The current line holds something beyond its indentation.
    started: bool,
    /// The next word attaches to what came before.
    nospace: bool,
    /// Inside `pre`: text goes out as it is.
    pub literal: bool,
    /// Nothing has been output since the last block element's start tag.
    fresh: bool,
}

impl Default for Html {
    fn default() -> Self {
        Self::new()
    }
}

impl Html {
    pub fn new() -> Html {
        Html { out: String::new(), col: 0, indent: 0, stack: Vec::new(), unit: String::new(), unit_space: false, started: false, nospace: false, literal: false, fresh: false }
    }

    pub fn finish(mut self) -> String {
        self.flush_unit();
        if self.started {
            self.newline();
        }
        self.out
    }

    fn newline(&mut self) {
        self.out.push('\n');
        self.col = 0;
        self.started = false;
        for o in self.stack.iter_mut() {
            o.had_block = true;
        }
    }

    fn write_indent(&mut self, levels: usize) {
        let s = "  ".repeat(levels);
        self.col += s.len();
        self.out.push_str(&s);
    }

    /// Places the pending run after a space on this line.
    fn flush_unit(&mut self) {
        if self.unit.is_empty() {
            self.unit_space = false;
            return;
        }
        let unit = std::mem::take(&mut self.unit);
        if !self.started {
            self.write_indent(self.indent);
        } else if self.unit_space {
            self.out.push(' ');
            self.col += 1;
        }
        self.col += unit.chars().count();
        self.out.push_str(&unit);
        self.started = true;
        self.unit_space = false;
    }

    /// Adds to the pending run. Once the run no longer fits after its space, the line breaks
    /// there, and the rest of the run follows on the new line.
    fn append(&mut self, s: &str) {
        if !s.is_empty() {
            self.fresh = false;
        }
        // A line's indentation goes out with its first character.
        if !self.started && self.unit.is_empty() && !s.is_empty() {
            self.write_indent(self.indent);
            self.started = true;
            self.unit_space = false;
        }
        self.unit.push_str(s);
        if self.unit_space && self.started && self.col + 1 + self.unit.chars().count() > WIDTH {
            self.newline();
            self.write_indent(self.indent + 1);
            self.started = true;
            self.unit_space = false;
            self.flush_unit();
        }
    }

    /// Ends the current line, if it has anything on it.
    fn end_line(&mut self) {
        self.flush_unit();
        if self.started {
            self.newline();
        }
    }

    /// Starts a new run, after a space unless the next word attaches.
    fn begin_run(&mut self) {
        if std::mem::take(&mut self.nospace) {
            return;
        }
        if !self.unit.is_empty() || self.started {
            self.flush_unit();
            self.unit_space = true;
        }
    }

    /// The next word or element attaches to what came before.
    pub fn nospace(&mut self) {
        self.nospace = true;
    }

    pub fn clear_nospace(&mut self) {
        self.nospace = false;
    }

    /// Opens element `tag` with attributes, as written (`class="Nm"`).
    pub fn open(&mut self, tag: &str, attrs: &str) {
        let (class, indents) = layout(tag);
        let text = if attrs.is_empty() { format!("<{tag}>") } else { format!("<{tag} {attrs}>") };
        match class {
            Class::Block => {
                self.end_line();
                self.nospace = false;
                self.write_indent(self.indent);
                self.out.push_str(&text);
                self.col += text.chars().count();
                self.started = true;
                self.fresh = true;
            }
            Class::Phrase => {
                self.begin_run();
                self.append(&text);
            }
        }
        if indents {
            self.indent += 1;
        }
        self.stack.push(Open { tag: tag.to_string(), class, indents, had_block: false });
        // What an element holds starts right after its tag.
        self.nospace = true;
    }

    /// Closes the innermost open element, which must be `tag`.
    pub fn close(&mut self, tag: &str) {
        let Some(pos) = self.stack.iter().rposition(|o| o.tag == tag) else { return };
        while self.stack.len() > pos + 1 {
            let t = self.stack.last().unwrap().tag.clone();
            self.close_top(&t);
        }
        self.close_top(tag);
    }

    fn close_top(&mut self, tag: &str) {
        let o = self.stack.pop().unwrap();
        if o.indents {
            self.indent -= 1;
        }
        let text = format!("</{tag}>");
        match o.class {
            Class::Phrase => {
                self.append(&text);
            }
            Class::Block => {
                // A section's end tag has a line of its own.
                if tag == "section" {
                    self.end_line();
                }
                // The end tag ends the pending run, and counts in whether it fits.
                if self.unit.is_empty() {
                    if !self.started {
                        self.write_indent(self.indent);
                    }
                    self.out.push_str(&text);
                    self.col += text.len();
                    self.started = true;
                } else {
                    self.append(&text);
                    self.flush_unit();
                }
                self.newline();
            }
        }
        self.nospace = false;
    }

    /// Whether nothing has been output since the innermost block element began.
    pub fn at_block_start(&self) -> bool {
        self.fresh
    }

    /// Whether element `tag` is open.
    pub fn is_open(&self, tag: &str) -> bool {
        self.stack.iter().any(|o| o.tag == tag)
    }

    /// The element around the innermost open one.
    pub fn parent_of_top(&self) -> Option<&str> {
        let n = self.stack.len();
        (n >= 2).then(|| self.stack[n - 2].tag.as_str())
    }

    /// The innermost open element.
    pub fn top(&self) -> Option<&str> {
        self.stack.last().map(|o| o.tag.as_str())
    }

    /// A void element on a line of its own (`<br/>`, `<meta .../>`).
    pub fn void_line(&mut self, tag: &str, attrs: &str) {
        self.end_line();
        self.fresh = false;
        self.nospace = false;
        let text = if attrs.is_empty() { format!("<{tag}/>") } else { format!("<{tag} {attrs}/>") };
        self.write_indent(self.indent);
        self.out.push_str(&text);
        self.col += text.len();
        self.started = true;
        self.newline();
    }

    /// A line break in the text: `<br/>` on a line of its own.
    pub fn br(&mut self) {
        self.void_line("br", "");
    }

    /// A word, escaped, after a space unless it attaches.
    pub fn word(&mut self, text: &str) {
        self.begin_run();
        self.append(&escape(text));
    }

    /// Markup appended to the current run, as it is.
    pub fn raw(&mut self, s: &str) {
        self.append(s);
    }

    /// Text going out as it is, lines and all, inside `pre`.
    pub fn literal_text(&mut self, s: &str) {
        self.flush_unit();
        let e = escape(s);
        self.out.push_str(&e);
        match e.rfind('\n') {
            Some(p) => self.col = e[p + 1..].chars().count(),
            None => self.col += e.chars().count(),
        }
        self.started = true;
    }

    /// A raw line of the document frame, at the current indentation.
    pub fn line(&mut self, s: &str) {
        self.end_line();
        self.write_indent(self.indent);
        self.out.push_str(s);
        self.newline();
    }

    /// Output appended as it is, with no layout.
    pub fn push_raw(&mut self, s: &str) {
        self.end_line();
        self.out.push_str(s);
    }
}

/// Text escaped for HTML: markup characters as entities, anything beyond ASCII as a numeric
/// reference, and roff's markers resolved.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            mark::MINUS => out.push('-'),
            mark::NBSP => out.push_str("&#x00A0;"),
            mark::BACKSLASH => out.push('\\'),
            c if ('\u{E000}'..='\u{E0FF}').contains(&c) => {}
            c if (c as u32) < 0x80 => out.push(c),
            c => out.push_str(&format!("&#x{:04X};", c as u32)),
        }
    }
    out
}

/// The comment lines a page starts with, as they are copied into the document.
pub fn leading_comments(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in input.lines() {
        let body = line.strip_prefix(".\\\"").or_else(|| line.strip_prefix("'\\\""));
        match body {
            Some(b) => out.push(b.to_string()),
            None => break,
        }
    }
    out
}

/// The head of a standalone document, up to and including `<body>`.
pub fn begin_document(h: &mut Html, opts: &HtmlOptions, title: &str, comments: &[String]) {
    if opts.fragment {
        return;
    }
    h.push_raw("<!DOCTYPE html>\n<html>\n");
    // (Blank comment lines before the first with text are left out; a blank last one runs into
    // the end of the comment.)
    let mut comments: Vec<&String> = comments.iter().skip_while(|l| l.trim().is_empty()).collect();
    // (Blank lines in a row are one.)
    comments.dedup_by(|a, b| a.trim().is_empty() && b.trim().is_empty());
    if !comments.is_empty() {
        let mut c = String::from("<!-- This is an automatically generated file.  Do not edit.");
        for l in &comments {
            c.push_str("\n  ");
            // (Characters beyond ASCII as roff escapes, as mandoc has read them.)
            for ch in l.chars() {
                if ch.is_ascii() {
                    c.push(ch);
                } else {
                    c.push_str(&format!("\\[u{:04X}]", ch as u32));
                }
            }
        }
        c.push_str(if comments.last().is_some_and(|l| l.is_empty()) { " -->\n" } else { "\n -->\n" });
        h.push_raw(&c);
    }
    h.push_raw("<head>\n");
    h.push_raw("  <meta charset=\"utf-8\"/>\n");
    h.push_raw("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>\n");
    match &opts.style {
        Some(s) => h.push_raw(&format!("  <link rel=\"stylesheet\" href=\"{}\" type=\"text/css\" media=\"all\"/>\n", escape(s))),
        None => {
            h.push_raw("  <style>\n");
            for l in DEFAULT_STYLE {
                h.push_raw(&format!("    {l}\n"));
            }
            h.push_raw("  </style>\n");
        }
    }
    h.push_raw(&format!("  <title>{}</title>\n", escape(title)));
    h.push_raw("</head>\n<body>\n");
}

pub fn end_document(h: &mut Html, opts: &HtmlOptions) {
    if !opts.fragment {
        h.push_raw("</body>\n</html>\n");
    }
}

/// The header table: title, volume, title.
pub fn header(h: &mut Html, left: &str, center: &str, right: &str) {
    h.push_raw(&format!(
        "<table class=\"head\">\n  <tr>\n    <td class=\"head-ltitle\">{}</td>\n    <td class=\"head-vol\">{}</td>\n    <td class=\"head-rtitle\">{}</td>\n  </tr>\n</table>\n",
        escape(left),
        escape(center),
        escape(right)
    ));
}

/// The footer table: date and operating system.
pub fn footer(h: &mut Html, date: &str, os: &str) {
    h.push_raw(&format!("<table class=\"foot\">\n  <tr>\n    <td class=\"foot-date\">{}</td>\n    <td class=\"foot-os\">{}</td>\n  </tr>\n</table>\n", escape(date), escape(os)));
}

/// An identifier made from text, as mandoc makes them: letters, digits and the punctuation
/// allowed in a URL fragment stay, anything else becomes an underscore.
pub fn make_id(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            mark::MINUS => out.push('-'),
            c if ('\u{E000}'..='\u{E0FF}').contains(&c) && c != mark::NBSP => {}
            c if c.is_ascii_alphanumeric() || "!$&'()*+,-./:;=?@_".contains(c) => out.push(c),
            _ => out.push('_'),
        }
    }
    out
}

/// A link to page `name(section)` from template `tmpl` (`%N`, `%S`).
pub fn man_link(tmpl: &str, name: &str, section: &str) -> String {
    tmpl.replace("%N", name).replace("%S", section)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filling() {
        let mut h = Html::new();
        h.open("p", "class=\"Pp\"");
        for w in "Every object can be thought of as having associated with it an ACL qualifier, and a set".split(' ') {
            h.word(w);
        }
        h.close("p");
        assert_eq!(h.finish(), "<p class=\"Pp\">Every object can be thought of as having associated with it an ACL\n    qualifier, and a set</p>\n");
    }
}
