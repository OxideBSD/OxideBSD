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
    /// Words are kept together (`.Bk -words`): no-break spaces between them.
    pub keep: bool,
    /// While words are kept together, the next space may break all the same.
    pub keep_break: bool,
}

impl Default for Html {
    fn default() -> Self {
        Self::new()
    }
}

impl Html {
    pub fn new() -> Html {
        Html { out: String::new(), col: 0, indent: 0, stack: Vec::new(), unit: String::new(), unit_space: false, started: false, nospace: false, literal: false, fresh: false, keep: false, keep_break: false }
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
    pub fn end_line(&mut self) {
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
        // (Words kept together are joined by no-break spaces, but for the one space allowed to
        // break.)
        if self.keep && !std::mem::take(&mut self.keep_break) && (!self.unit.is_empty() || self.started) {
            self.append("&#x00A0;");
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
        // The spaces between an element's classes are places the line may break, as between
        // words.
        let mut pieces = text.splitn(2, "class=\"");
        let head = pieces.next().unwrap();
        let (first, more) = match pieces.next() {
            Some(rest) => {
                let end = rest.find('"').unwrap_or(rest.len());
                let words: Vec<&str> = rest[..end].split(' ').collect();
                let tail = &rest[end..];
                let mut more: Vec<String> = words[1..].iter().map(|w| w.to_string()).collect();
                if let Some(l) = more.last_mut() {
                    l.push_str(tail);
                }
                let first = format!("{head}class=\"{}{}", words[0], if more.is_empty() { tail } else { "" });
                (first, more)
            }
            None => (text.clone(), Vec::new()),
        };
        match class {
            Class::Block => {
                self.end_line();
                self.nospace = false;
                self.write_indent(self.indent);
                self.out.push_str(&first);
                self.col += first.chars().count();
                self.started = true;
                self.fresh = true;
            }
            Class::Phrase => {
                self.begin_run();
                self.append(&first);
            }
        }
        for w in &more {
            self.flush_unit();
            self.unit_space = true;
            self.append(w);
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
                // A section's end tag has a line of its own, and so has a table's, a row's or a
                // list's, even with nothing in it.
                if matches!(tag, "section" | "table" | "tr" | "dl" | "ul" | "ol") {
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

    /// Markup going out as it is, inside `pre`.
    pub fn literal_raw(&mut self, s: &str) {
        self.flush_unit();
        self.out.push_str(s);
        match s.rfind('\n') {
            Some(p) => self.col = s[p + 1..].chars().count(),
            None => self.col += s.chars().count(),
        }
        // (After a newline, an end tag starts its own indented line.)
        self.started = !self.out.ends_with('\n');
        self.fresh = false;
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

/// Text without what `\l` draws, which HTML leaves out.
fn undrawn(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains([mark::LINE, mark::RULE]) {
        return s.into();
    }
    let mut out = String::new();
    let mut inside: Option<char> = None;
    for c in s.chars() {
        match inside {
            Some(m) if c == m => inside = None,
            Some(_) => {}
            None if c == mark::LINE || c == mark::RULE => inside = Some(c),
            None => out.push(c),
        }
    }
    out.into()
}

/// Text escaped for HTML: markup characters as entities, anything beyond ASCII as a numeric
/// reference, and roff's markers resolved.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in undrawn(s).chars() {
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
            Some(b) => out.push(b.trim_end().to_string()),
            None => {
                // (The first other line's own comment, at its end, is the last.)
                if let Some(p) = line.find("\\\"").filter(|p| !line[..*p].ends_with('\\')) {
                    out.push(line[p + 2..].trim_end().to_string());
                }
                break;
            }
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
    let any = !comments.is_empty();
    let mut comments: Vec<&String> = comments.iter().skip_while(|l| l.trim().is_empty()).collect();
    // (Blank lines in a row are one.)
    comments.dedup_by(|a, b| a.trim().is_empty() && b.trim().is_empty());
    if any && comments.is_empty() {
        h.push_raw("<!-- This is an automatically generated file.  Do not edit. -->\n");
    }
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
    h.open("head", "");
    h.line("<meta charset=\"utf-8\"/>");
    h.line("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>");
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
    // (The title is filled like text.)
    h.open("title", "");
    for w in title.split(' ').filter(|w| !w.is_empty()) {
        h.word(w);
    }
    h.close("title");
    h.close("head");
    h.push_raw("<body>\n");
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

/// The font roman escapes (`\fB`, `\fI`...) and `.ft` have selected: it lasts across text
/// lines, each line reopening it, until a macro resets it.
#[derive(Clone, Debug, Default)]
pub struct Fonts {
    /// The escape font's marker, `None` for roman.
    pub esc: Option<char>,
    /// The font before the last escape, for `\fP`.
    prev: Option<char>,
    /// The font a bare `.ft` goes back to: the last one not roman at a line's end or a macro.
    saved: Option<char>,
    /// Its elements, open now.
    open: Vec<&'static str>,
}

impl Fonts {
    /// Back to roman, at a macro: the font selected, if not roman, becomes the previous one.
    pub fn reset(&mut self) {
        if let Some(f) = self.esc.take() {
            self.prev = Some(f);
            self.saved = Some(f);
        }
    }

    /// The end of a filled text line: the font selected, if not roman, is saved for `.ft`.
    pub fn line_end(&mut self) {
        if self.esc.is_some() {
            self.saved = self.esc;
        }
    }

    /// `.ft`: a font named (with nothing previous), or the one saved.
    pub fn select(&mut self, f: Option<Option<char>>) {
        match f {
            Some(f) => {
                self.esc = f;
                self.prev = None;
                self.saved = None;
            }
            None => self.esc = self.saved,
        }
    }
}

/// The elements a font marker opens, with their attributes: constant width is a literal span.
pub fn font_elements(f: Option<char>) -> &'static [(&'static str, &'static str)] {
    match f {
        Some(mark::FONT_B) => &[("b", "")],
        Some(mark::FONT_I) => &[("i", "")],
        Some(mark::FONT_BI) => &[("b", ""), ("i", "")],
        Some(mark::FONT_CW) => &[("span", "class=\"Li\"")],
        Some(mark::FONT_CB) => &[("span", "class=\"Li\""), ("b", "")],
        Some(mark::FONT_CI) => &[("span", "class=\"Li\""), ("i", "")],
        _ => &[],
    }
}

impl Html {
    fn font_open(&mut self, fonts: &mut Fonts, literal: bool) {
        for &(t, attrs) in font_elements(fonts.esc) {
            if literal {
                self.literal_raw(&if attrs.is_empty() { format!("<{t}>") } else { format!("<{t} {attrs}>") });
            } else {
                self.open(t, attrs);
            }
            fonts.open.push(t);
        }
    }

    /// Closes the escape font's elements (it stays selected).
    pub fn font_close(&mut self, fonts: &mut Fonts, literal: bool) {
        while let Some(t) = fonts.open.pop() {
            if literal {
                self.literal_raw(&format!("</{t}>"));
            } else {
                self.close(t);
            }
        }
    }

    /// Text with roff's font escapes as elements: the escape font reopened at its start and
    /// closed at its end. In `literal` mode (inside `pre`) spaces are kept as they are; else
    /// they separate words, where the line may break.
    pub fn text(&mut self, text: &str, fonts: &mut Fonts, literal: bool) {
        let text = &*undrawn(text);
        let mut buf = String::new();
        // (Something before, in the same word: what follows attaches.)
        let mut glue = false;
        let flush = |h: &mut Html, buf: &mut String, glue: &mut bool| {
            if !buf.is_empty() {
                if literal {
                    h.literal_text(buf);
                } else {
                    if *glue {
                        h.nospace();
                    }
                    h.word(buf);
                }
                buf.clear();
                *glue = true;
            }
        };
        if !fonts.open.is_empty() {
            self.font_close(fonts, literal);
        }
        if fonts.esc.is_some() {
            self.font_open(fonts, literal);
            glue = true;
        }
        // (A font change with nothing after it in the text joins nothing.)
        let mut last_font = false;
        // A space not yet placed: before a font change it goes before the end tag.
        let mut space = false;
        for c in text.chars() {
            if !mark::is_font(c) {
                last_font = false;
                if c != ' ' {
                    space = false;
                }
            }
            if c == ' ' && !literal {
                flush(self, &mut buf, &mut glue);
                self.clear_nospace();
                glue = false;
                space = true;
                continue;
            }
            if mark::is_font(c) {
                flush(self, &mut buf, &mut glue);
                if std::mem::take(&mut space) && !fonts.open.is_empty() {
                    self.space();
                    glue = true;
                }
                let new = match c {
                    mark::FONT_P => fonts.prev,
                    mark::FONT_R => None,
                    c => Some(c),
                };
                self.font_close(fonts, literal);
                fonts.prev = fonts.esc;
                fonts.esc = new;
                if !literal && glue {
                    self.nospace();
                }
                self.font_open(fonts, literal);
                last_font = true;
                if !literal && !font_elements(new).is_empty() {
                    glue = true;
                }
                continue;
            }
            buf.push(c);
        }
        flush(self, &mut buf, &mut glue);
        if last_font && !literal {
            self.clear_nospace();
        }
        // (A space at the end comes before what closes.)
        if !literal && text.ends_with(' ') {
            self.space();
        }
        self.font_close(fonts, literal);
    }

    /// A space here, where the line may break, whatever attaches.
    pub fn space(&mut self) {
        self.flush_unit();
        self.unit_space = true;
        self.nospace = false;
    }
}
