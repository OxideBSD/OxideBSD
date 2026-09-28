//! Renders a man(7) document tree as HTML (MAN.md §5, `-T html`), in the markup mandoc
//! produces: fonts as `b`/`i`, paragraphs as `p`, tagged paragraphs as a tag list.

use std::collections::{HashMap, HashSet};

use crate::html::{self, Html, HtmlOptions};
use crate::mdoc_term::volume;
use crate::roff::mark;
use crate::tree::{Document, Kind, Node};

struct R {
    h: Html,
    /// Text directly in a section starts a paragraph until the section has had one.
    para: bool,
    in_ss: bool,
    /// Identifiers of headings and tagged paragraphs, by node address.
    ids: HashMap<usize, String>,
    /// The font escapes selected, lasting across text lines.
    fonts: html::Fonts,
    /// The font an escape selected inside a macro's arguments.
    font: Vec<&'static str>,
    /// No-fill mode (`.nf`, `.EX`), and whether `.EX` started it.
    nofill: bool,
    example: bool,
    /// In no-fill mode: nothing has been output in the block yet, and a break (`.br`) is due
    /// before the next line.
    pre_start: bool,
    pre_break: bool,
    /// In no-fill mode: the `.sp` requests since the last line, each a newline before the next,
    /// and whether a blank line came since (ending the block, it ends the last line).
    pre_sp: usize,
    pre_blank: bool,
    /// Bullet-tagged indented paragraphs in runs of two or more, by node address: those make
    /// bullet lists.
    bullets: HashSet<usize>,
    /// The tag list open, and the macro and indent its items were made with.
    list: Option<(String, Option<String>)>,
}

pub fn render(doc: &Document, opts: &HtmlOptions, comments: &[String]) -> String {
    let meta = &doc.meta;
    let mut r = R { h: Html::new(), para: false, in_ss: false, ids: tags(doc), fonts: Default::default(), font: Vec::new(), nofill: false, example: false, pre_start: false, pre_break: false, pre_sp: 0, pre_blank: false, bullets: bullet_runs(&doc.root), list: None };
    let title = format!("{}({})", plain(&meta.title), plain(&meta.section));
    html::begin_document(&mut r.h, opts, &title, comments);
    let vol = if meta.volume_given {
        plain(&meta.volume)
    } else {
        volume(&meta.section).to_string()
    };
    r.table("head", &[("head-ltitle", &title), ("head-vol", &vol), ("head-rtitle", &title)]);
    r.h.open("div", "class=\"manual-text\"");
    r.children(&doc.root);
    r.end_list();
    r.close_p();
    while r.h.is_open("section") {
        r.h.close("section");
    }
    r.h.close("div");
    // (A date left as written keeps its spaces.)
    let date = crate::format_date(&meta.date);
    let date = plain(if date == meta.date.trim() { &meta.date } else { &date });
    let source = plain(&meta.os);
    r.table("foot", &[("foot-date", &date), ("foot-os", &source)]);
    html::end_document(&mut r.h, opts);
    r.h.finish()
}

/// Headings and the heads of tagged paragraphs get identifiers, numbered when repeated. A
/// head's claim is weaker when more follows its word, and only the best claims on a text
/// stand.
fn tags(doc: &Document) -> HashMap<usize, String> {
    fn walk(n: &Node, out: &mut Vec<(usize, String, usize)>) {
        for c in &n.children {
            if c.kind == Kind::Block {
                let claim = match c.tok.as_str() {
                    "SH" | "SS" => c.part(Kind::Head).map(|h| (h.text.clone(), 0)),
                    "TP" | "TQ" => c.part(Kind::Head).and_then(|h| first_word(&head_text(h))),
                    "IP" => c.args.first().and_then(|a| first_word(a)),
                    _ => None,
                };
                if let Some((t, p)) = claim.filter(|(t, _)| !t.is_empty() && t.is_ascii()) {
                    out.push((c as *const Node as usize, t, p));
                }
            }
            walk(c, out);
        }
    }
    let mut claims = Vec::new();
    walk(&doc.root, &mut claims);
    let mut best: HashMap<String, usize> = HashMap::new();
    for (_, t, p) in &claims {
        let b = best.entry(t.clone()).or_insert(*p);
        *b = (*b).min(*p);
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out = HashMap::new();
    for (node, text, p) in claims {
        if p != best[&text] {
            continue;
        }
        let n = seen.entry(text.clone()).or_default();
        *n += 1;
        let id = html::make_id(&text);
        out.insert(node, if *n == 1 { id } else { format!("{id}~{n}") });
    }
    out
}

fn is_bullet(n: &Node) -> bool {
    n.kind == Kind::Block && n.tok == "IP" && n.args.first().is_some_and(|a| a == "\u{2022}" || a == "*")
}

/// The bullet items that have another right before or after them.
fn bullet_runs(root: &Node) -> HashSet<usize> {
    let mut out = HashSet::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        for (i, c) in n.children.iter().enumerate() {
            let near = |j: Option<usize>| j.and_then(|j| n.children.get(j)).is_some_and(is_bullet);
            if is_bullet(c) && (near(i.checked_sub(1)) || near(Some(i + 1))) {
                out.insert(c as *const Node as usize);
            }
            stack.push(c);
        }
    }
    out
}

/// The text of a node's words and its macros' arguments.
fn text_of(n: &Node) -> String {
    let mut out = String::new();
    for c in &n.children {
        let t = match c.kind {
            Kind::Text => hyphens(&c.text),
            Kind::Elem => c.args.join(" "),
            _ => text_of(c),
        };
        if !t.is_empty() {
            if !out.is_empty() && !c.flags.nospace {
                out.push(' ');
            }
            out.push_str(&t);
        }
    }
    out
}

/// The text a tagged paragraph's head claims with: its first line of text, or its first macro's
/// arguments (only the first of an alternating font macro's).
fn head_text(h: &Node) -> String {
    match h.children.first() {
        Some(c) if c.kind == Kind::Text => hyphens(&c.text),
        Some(c) if c.kind == Kind::Elem && matches!(c.tok.as_str(), "B" | "I" | "SM" | "SB") => c.args.join(" "),
        Some(c) if c.kind == Kind::Elem => c.args.first().cloned().unwrap_or_default(),
        _ => text_of(h),
    }
}

/// A text line's hyphenation points as an identifier sees them: roff marks a `-` between two
/// letters of the source line as one, and it turns into an underscore.
fn hyphens(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let alpha = |ch: char| ch.is_ascii_alphabetic();
    (0..c.len())
        .map(|i| {
            let hyph = c[i] == '-' && i > 0 && alpha(c[i - 1]) && c.get(i + 1).is_some_and(|&n| alpha(n));
            if hyph { '_' } else { c[i] }
        })
        .collect()
}

/// A tag's text: its first word, without leading dashes and fonts, up to a space or an escape;
/// it must start with a letter. With the strength of its claim: 0 when the word is all there
/// is, 1 when more follows (even a font escape).
fn first_word(s: &str) -> Option<(String, usize)> {
    let lead = s.trim_start_matches(|c: char| mark::is_font(c) || c == ' ');
    let s = lead.trim_start_matches(|c: char| c == '-' || c == mark::MINUS || c == mark::BACKSLASH || mark::is_font(c));
    let word: String = s.chars().take_while(|c| !('\u{E000}'..='\u{E0FF}').contains(c) && *c != ' ').collect();
    let more = s.len() > word.len();
    word.starts_with(|c: char| c.is_ascii_alphabetic()).then_some((word, more as usize))
}


impl R {
    fn table(&mut self, class: &str, cells: &[(&str, &str)]) {
        self.h.open("table", &format!("class=\"{class}\""));
        self.h.open("tr", "");
        for (c, text) in cells {
            self.h.open("td", &format!("class=\"{c}\""));
            // (Runs of spaces count as one, at the ends too.)
            if text.starts_with(' ') {
                self.h.raw(" ");
                self.h.nospace();
            }
            for w in text.split(' ').filter(|w| !w.is_empty()) {
                self.h.word(w);
            }
            if text.ends_with(' ') && text.trim() != "" {
                self.h.raw(" ");
            }
            self.h.close("td");
        }
        self.h.close("tr");
        self.h.close("table");
    }

    fn ensure_p(&mut self) {
        if self.h.top() == Some("section") && self.para {
            self.h.open("p", "class=\"Pp\"");
            self.para = false;
        }
    }

    fn close_p(&mut self) {
        self.close_font();
        if self.h.top() == Some("p") {
            self.h.close("p");
        }
    }

    /// Closes the tag list, if one is open.
    fn end_list(&mut self) {
        if let Some((k, _)) = self.list.take() {
            self.close_font();
            self.h.close(if k == "bullet" { "ul" } else { "dl" });
        }
    }

    fn close_font(&mut self) {
        while let Some(t) = self.font.pop() {
            self.h.close(t);
        }
    }

    fn children(&mut self, n: &Node) {
        for c in &n.children {
            self.node(c);
        }
    }

    fn node(&mut self, n: &Node) {
        if n.flags.nospace {
            self.h.nospace();
        }
        match n.kind {
            Kind::Text => self.text(n),
            Kind::Elem => self.elem(n),
            Kind::Block => self.block(n),
            Kind::Table => {
                self.close_p();
                if let Some(t) = &n.table {
                    crate::tbl_html::render(&mut self.h, t);
                }
                // Text after it starts a paragraph.
                self.para = true;
            }
            Kind::Eqn => {
                self.ensure_p();
                if let Some(e) = &n.eqn {
                    crate::eqn_html::render(e, &mut self.h);
                }
            }
            _ => self.children(n),
        }
    }

    /// Ends an open preformatted block, staying in no-fill mode.
    fn close_pre(&mut self) {
        if self.h.is_open("pre") {
            self.end_pre_lines();
            self.h.font_close(&mut self.fonts, true);
            self.h.close("pre");
        }
    }

    /// Newlines for the `.sp` requests last in a preformatted block, and the last line's own, if
    /// there was one: an example ends with it, other blocks only before such a `.sp` or a blank
    /// line.
    fn end_pre_lines(&mut self) {
        let sp = std::mem::take(&mut self.pre_sp);
        let blank = std::mem::take(&mut self.pre_blank);
        let end = !self.pre_start && (self.example || sp > 0 || blank);
        self.h.literal_raw(&"\n".repeat(sp + end as usize));
    }

    /// In no-fill mode, a preformatted block for what comes next, if one isn't open.
    fn ensure_pre(&mut self) {
        if self.nofill && !self.h.is_open("pre") {
            self.close_p();
            self.h.open("pre", "");
            self.pre_start = true;
        }
    }

    /// Text, with its font escapes as elements.
    fn text(&mut self, n: &Node) {
        if self.nofill && !self.h.is_open("pre") {
            if n.text.is_empty() {
                return;
            }
            self.ensure_pre();
        }
        if self.nofill {
            // (Blank lines vanish, and lines of only zero-width escapes.)
            if n.text.chars().all(|c| c == mark::ZERO || c == mark::BREAK) {
                return;
            }
            // (A line starting with a space breaks; with a tab, it doesn't.)
            if !n.flags.continues {
                self.pre_line(n.text.starts_with(' '));
            }
            self.h.text(&n.text, &mut self.fonts, true);
            return;
        }
        // A line starting with spaces breaks the line before it (before the paragraph a
        // section's text starts), and starts with one space.
        let lead = n.flags.line_start && !n.flags.continues && n.text.starts_with(' ');
        if lead {
            self.h.br();
        }
        self.ensure_p();
        let text = n.text.trim_end_matches(' ');
        // (Leading tabs stay.)
        let text = text.trim_start_matches(' ');
        if lead {
            self.h.raw(" ");
            self.h.nospace();
        }
        self.h.text(text, &mut self.fonts, false);
        self.fonts.line_end();
    }

    /// The start of a line in no-fill mode: after a newline, or a break where the line starts
    /// with spaces (or `.br` came before it).
    fn pre_line(&mut self, spaces: bool) {
        let brk = spaces || std::mem::take(&mut self.pre_break);
        let sp = std::mem::take(&mut self.pre_sp);
        // (First in the block, a break's newline stands for one of them.)
        let sp = if self.pre_start && brk { sp.saturating_sub(1) } else { sp };
        self.pre_blank = false;
        self.h.literal_raw(&"\n".repeat(sp));
        if brk {
            self.h.literal_raw("\n<br/>\n");
        } else if !self.pre_start {
            self.h.literal_raw("\n");
        }
        self.pre_start = false;
    }

    /// Text in no-fill mode, spaces kept, font escapes as elements.
    fn literal(&mut self, text: &str) {
        let mut buf = String::new();
        for c in text.chars() {
            if mark::is_font(c) {
                if !buf.is_empty() {
                    self.h.literal_text(&std::mem::take(&mut buf));
                }
                while let Some(t) = self.font.pop() {
                    self.h.literal_raw(&format!("</{t}>"));
                }
                for &(t, attrs) in html::font_elements(Some(c)) {
                    self.h.literal_raw(&if attrs.is_empty() { format!("<{t}>") } else { format!("<{t} {attrs}>") });
                    self.font.push(t);
                }
                continue;
            }
            buf.push(c);
        }
        if !buf.is_empty() {
            self.h.literal_text(&buf);
        }
    }

    /// A macro argument's words, its font escapes lasting to its end.
    fn words(&mut self, text: &str, _line: bool) {
        let mut f = html::Fonts::default();
        self.h.text(text, &mut f, false);
    }

    fn elem(&mut self, n: &Node) {
        let tok = n.tok.as_str();
        // Macros end the escape font, but for those mandoc ignores, or doesn't know.
        if !matches!(tok, "ft" | "ad" | "na" | "ne" | "hy" | "nh" | "MR" | "UE" | "ME" | "YS") {
            self.fonts.reset();
        }
        match tok {
            "PP" | "LP" | "P" if self.nofill => {
                // It ends the preformatted block, unless nothing is in it yet; the next text
                // starts another.
                if !(self.h.is_open("pre") && self.pre_start) {
                    self.close_pre();
                }
            }
            "PP" | "LP" | "P" => {
                self.end_list();
                self.close_p();
                self.h.open("p", "class=\"Pp\"");
                self.para = false;
            }
            "br" => {
                if self.nofill {
                    self.pre_break = true;
                } else {
                    self.h.br();
                }
            }
            "sp" => {
                // A paragraph within whatever holds it; in no-fill mode, a newline. Blank lines
                // there are one newline before the first line, or after the last; between lines,
                // nothing.
                if self.nofill {
                    self.ensure_pre();
                    if n.text != "blank" {
                        self.pre_sp += 1;
                    } else if self.pre_start {
                        self.pre_sp = self.pre_sp.max(1);
                    } else {
                        self.pre_blank = true;
                    }
                } else {
                    self.close_p();
                    self.h.open("p", "class=\"Pp\"");
                    self.para = false;
                }
            }
            // In no-fill mode, the next line starts on a line of its own, even first.
            "ti" if self.nofill => {
                self.ensure_pre();
                self.pre_start = false;
            }
            "in" => {
                if !self.nofill {
                    self.h.br();
                }
            }
            "nf" | "EX" => {
                if !self.nofill {
                    self.close_p();
                    self.h.open("pre", "");
                    self.nofill = true;
                    self.example = tok == "EX";
                    self.pre_start = true;
                    self.pre_break = false;
                    self.pre_sp = 0;
                    self.pre_blank = false;
                }
            }
            "fi" | "EE" => {
                if self.nofill {
                    // (Ending no-fill mode between blocks leaves an empty one.)
                    self.ensure_pre();
                    self.end_pre_lines();
                    while let Some(t) = self.font.pop() {
                        self.h.literal_raw(&format!("</{t}>"));
                    }
                    self.h.close("pre");
                    // Text after it starts a paragraph.
                    self.para = true;
                }
                self.nofill = false;
            }
            "SM" | "SB" => {
                self.ensure_p();
                self.h.open("small", "");
                if tok == "SB" {
                    self.h.open("b", "");
                }
                for (i, a) in n.args.iter().enumerate() {
                    if i > 0 {
                        self.h.clear_nospace();
                    }
                    self.words(a, false);
                }
                if tok == "SB" {
                    self.h.close("b");
                }
                self.h.close("small");
            }
            "B" | "I" | "BI" | "IB" | "BR" | "RB" | "IR" | "RI" if n.args.is_empty() => {}
            "B" | "I" | "BI" | "IB" | "BR" | "RB" | "IR" | "RI" if self.nofill => {
                self.ensure_pre();
                if !n.flags.continues {
                    self.pre_line(false);
                }
                let fonts: [&str; 2] = match tok {
                    "B" => ["b", "b"],
                    "I" => ["i", "i"],
                    "BI" => ["b", "i"],
                    "IB" => ["i", "b"],
                    "BR" => ["b", ""],
                    "RB" => ["", "b"],
                    "IR" => ["i", ""],
                    _ => ["", "i"],
                };
                let alternating = tok.len() == 2;
                // (A single font's arguments are one element, spaced.)
                let groups: Vec<(usize, String)> = if alternating {
                    n.args.iter().cloned().enumerate().collect()
                } else {
                    vec![(0, n.args.join(" "))]
                };
                for (i, a) in groups {
                    let f = fonts[i % 2];
                    if !f.is_empty() {
                        self.h.literal_raw(&format!("<{f}>"));
                    }
                    self.literal(&a);
                    while let Some(t) = self.font.pop() {
                        self.h.literal_raw(&format!("</{t}>"));
                    }
                    if !f.is_empty() {
                        self.h.literal_raw(&format!("</{f}>"));
                    }
                }
            }
            "B" | "I" | "BI" | "IB" | "BR" | "RB" | "IR" | "RI" => {
                self.ensure_p();
                self.close_font();
                let fonts: [&str; 2] = match tok {
                    "B" => ["b", "b"],
                    "I" => ["i", "i"],
                    "BI" => ["b", "i"],
                    "IB" => ["i", "b"],
                    "BR" => ["b", ""],
                    "RB" => ["", "b"],
                    "IR" => ["i", ""],
                    _ => ["", "i"],
                };
                let alternating = tok.len() == 2;
                if !alternating {
                    self.h.open(fonts[0], "");
                    for (i, a) in n.args.iter().enumerate() {
                        if i > 0 {
                            self.h.clear_nospace();
                        }
                        self.words(a, false);
                    }
                    self.close_font();
                    self.h.close(fonts[0]);
                } else {
                    for (i, a) in n.args.iter().enumerate() {
                        // (Arguments join, but for a space a roman one ends with; one in a font
                        // keeps its space inside.)
                        if i > 0 && !(n.args[i - 1].ends_with(' ') && fonts[(i - 1) % 2].is_empty()) {
                            self.h.nospace();
                        }
                        let f = fonts[i % 2];
                        if !f.is_empty() {
                            self.h.open(f, "");
                        }
                        self.words(a, false);
                        self.close_font();
                        if !f.is_empty() {
                            self.h.close(f);
                        }
                    }
                }
            }
            "OP" => {
                self.ensure_p();
                self.h.word("[");
                self.h.nospace();
                self.h.open("span", "class=\"Op\"");
                if let Some(a) = n.args.first() {
                    self.h.open("b", "");
                    self.words(a, false);
                    self.h.close("b");
                }
                if let Some(a) = n.args.get(1) {
                    self.h.open("i", "");
                    self.words(a, false);
                    self.h.close("i");
                }
                self.h.nospace();
                self.h.word("]");
                self.h.close("span");
            }
            "RE" => {}
            "ft" => {
                self.fonts.select(match n.args.first().map(String::as_str) {
                    None | Some("P") => None,
                    Some("B") | Some("3") => Some(Some(mark::FONT_B)),
                    Some("I") | Some("2") => Some(Some(mark::FONT_I)),
                    Some("BI") | Some("4") => Some(Some(mark::FONT_BI)),
                    Some("CW") | Some("CR") => Some(Some(mark::FONT_CW)),
                    Some("CB") => Some(Some(mark::FONT_CB)),
                    Some("CI") => Some(Some(mark::FONT_CI)),
                    _ => Some(None),
                });
            }
            "MR" => {
                self.ensure_p();
                self.h.open("a", "class=\"Xr\"");
                let name = n.args.first().cloned().unwrap_or_default();
                let sec = n.args.get(1).cloned().unwrap_or_default();
                self.h.word(&format!("{name}({sec})"));
                self.h.close("a");
                if let Some(p) = n.args.get(2) {
                    self.h.nospace();
                    self.h.word(p);
                }
            }
            // (Other requests print nothing.)
            _ => {}
        }
    }

    fn block(&mut self, n: &Node) {
        let tok = n.tok.as_str();
        self.fonts.reset();
        match tok {
            "SH" | "SS" => self.section(n),
            "IP" if self.bullets.contains(&(n as *const Node as usize)) => {
                // Indented paragraphs tagged with bullets, two or more, are a bullet list.
                self.close_p();
                let same = self.list.as_ref().is_some_and(|(k, _)| k == "bullet");
                if !same {
                    self.end_list();
                    self.h.open("ul", "class=\"Bl-bullet\"");
                }
                self.list = Some(("bullet".into(), None));
                self.h.open("li", "");
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.close_font();
                self.h.close("li");
            }
            "TP" | "TQ" | "IP" => {
                self.close_p();
                let width = if tok == "IP" { n.args.get(1).cloned() } else { n.args.first().cloned() };
                // (A bullet item on its own is a tag list of its own.)
                let kind = if is_bullet(n) { "bullet-item" } else if tok == "IP" { "IP" } else { "TP" };
                // (A list goes on through items of its kind; an indented paragraph with a new
                // indent starts another.)
                let same = kind != "bullet-item" && self.list.as_ref().is_some_and(|(k, w)| k == kind && (kind == "TP" || width.is_none() || *w == width));
                if !same {
                    self.end_list();
                    self.h.open("dl", "class=\"Bl-tag\"");
                }
                self.list = Some((kind.to_string(), if width.is_some() { width } else { self.list.as_ref().and_then(|l| l.1.clone()) }));
                match self.ids.get(&(n as *const Node as usize)).cloned() {
                    Some(id) => {
                        self.h.open("dt", &format!("id=\"{}\"", html::escape(&id)));
                        self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(&id)));
                        self.head(n);
                        self.close_font();
                        self.h.close("a");
                    }
                    None => {
                        self.h.open("dt", "");
                        self.head(n);
                        self.close_font();
                    }
                }
                self.h.close("dt");
                self.h.open("dd", "");
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.close_font();
                self.h.close("dd");
            }
            "HP" => {
                self.end_list();
                self.close_p();
                self.para = false;
                self.h.open("p", "class=\"Pp HP\"");
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.close_p();
            }
            "RS" => {
                self.end_list();
                self.close_p();
                self.h.open("div", "class=\"Bd-indent\"");
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.end_list();
                self.close_p();
                self.h.close("div");
            }
            "UR" | "MT" => {
                self.ensure_p();
                let url = n.args.first().cloned().unwrap_or_default();
                let (class, href) = if tok == "UR" { ("Lk", url.clone()) } else { ("Mt", format!("mailto:{url}")) };
                self.h.open("a", &format!("class=\"{class}\" href=\"{}\"", html::escape(&href)));
                // (With no text, the address is the text.)
                match n.part(Kind::Body).filter(|b| !b.children.is_empty()) {
                    Some(b) => self.children(b),
                    None => self.words(&url, false),
                }
                self.close_font();
                self.h.close("a");
            }
            "SY" => {
                self.end_list();
                self.close_p();
                self.h.open("table", "class=\"Nm\"");
                self.h.open("tr", "");
                self.h.open("td", "");
                self.h.open("code", "class=\"Nm\"");
                for a in &n.args {
                    self.words(a, false);
                }
                self.h.close("code");
                self.h.close("td");
                self.h.open("td", "");
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.close_font();
                self.h.close("td");
                self.h.close("tr");
                self.h.close("table");
            }
            _ => {
                for part in &n.children {
                    self.children(part);
                }
            }
        }
    }

    /// A tagged paragraph's head: `.IP`'s tag argument, or the head line.
    fn head(&mut self, n: &Node) {
        if n.tok == "IP" {
            if let Some(a) = n.args.first() {
                self.words(a, false);
            }
        } else if let Some(h) = n.part(Kind::Head) {
            self.children(h);
        }
    }

    fn section(&mut self, n: &Node) {
        self.end_list();
        if self.nofill {
            while let Some(t) = self.font.pop() {
                self.h.literal_raw(&format!("</{t}>"));
            }
            self.h.close("pre");
            self.nofill = false;
        }
        self.close_p();
        let (class, h) = if n.tok == "SH" { ("Sh", "h1") } else { ("Ss", "h2") };
        if n.tok == "SH" {
            while self.h.is_open("section") {
                self.h.close("section");
            }
            self.in_ss = false;
        } else if self.in_ss {
            self.h.close("section");
        }
        if n.tok == "SS" {
            self.in_ss = true;
        }
        self.h.open("section", &format!("class=\"{class}\""));
        let head = n.part(Kind::Head);
        match self.ids.get(&(n as *const Node as usize)).cloned() {
            Some(id) => {
                self.h.open(h, &format!("class=\"{class}\" id=\"{}\"", html::escape(&id)));
                self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(&id)));
                if let Some(hd) = head {
                    self.children(hd);
                }
                self.close_font();
                self.h.close("a");
            }
            None => {
                self.h.open(h, &format!("class=\"{class}\""));
                if let Some(hd) = head {
                    self.children(hd);
                }
                self.close_font();
            }
        }
        self.h.close(h);
        self.para = true;
        if let Some(b) = n.part(Kind::Body) {
            self.children(b);
        }
        self.end_list();
        self.close_p();
    }
}

/// Prologue text with roff's markers resolved (a no-break space stays one).
fn plain(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            mark::MINUS => Some('-'),
            mark::NBSP => Some(mark::NBSP),
            mark::BACKSLASH => Some('\\'),
            c if ('\u{E000}'..='\u{E01F}').contains(&c) => None,
            c => Some(c),
        })
        .collect()
}
