//! Renders an mdoc document tree as HTML (MAN.md §5, `-T html`), in the markup mandoc
//! produces: each macro becomes an element with the macro's name as its class.

use crate::html::{self, Html, HtmlOptions};
use crate::mdoc::{has_flag, list_type};
use crate::mdoc_term::{os_name, volume};
use crate::roff::mark;
use crate::tree::{Document, Kind, Meta, Node};
use std::collections::HashMap;

struct R<'a> {
    h: Html,
    meta: &'a Meta,
    opts: &'a HtmlOptions,
    synopsis: bool,
    authors: bool,
    split: Option<bool>,
    seen_an: bool,
    /// The identifier each tagged node gets, by the node's address (see [`tags`]).
    ids: HashMap<usize, String>,
    /// Nodes a permalink goes around, and the identifier it links to.
    links: HashMap<usize, String>,
    /// The previous sibling's macro, for SYNOPSIS spacing.
    prev: String,
    /// Empty `.Fl` macros joined to the next, whose dashes it prints.
    fl_prefix: usize,
    /// Text directly in a section starts a paragraph until the section has had one.
    para: bool,
    /// A subsection is open.
    in_ss: bool,
    /// Nothing has been rendered yet in the current section.
    first: bool,
}

pub fn render(doc: &Document, opts: &HtmlOptions, comments: &[String]) -> String {
    let meta = &doc.meta;
    let (ids, links) = tags(doc);
    let mut r = R { h: Html::new(), meta, opts, synopsis: false, authors: false, split: None, seen_an: false, ids, links, prev: String::new(), fl_prefix: 0, para: false, in_ss: false, first: false };
    let title = format!("{}({})", plain(&meta.title), plain(&meta.section));
    let doc_title = if meta.arch.is_empty() { title.clone() } else { format!("{title} ({})", meta.arch.to_lowercase()) };
    html::begin_document(&mut r.h, opts, &doc_title, comments);
    let vol = match volume(&meta.section) {
        "" => plain(&meta.section),
        v => v.to_string(),
    };
    let vol = if meta.arch.is_empty() { vol } else { format!("{vol} ({})", meta.arch.to_lowercase()) };
    r.header(&title, &vol);
    r.h.open("div", "class=\"manual-text\"");
    for n in &doc.root.children {
        r.node(n);
    }
    r.h.close("div");
    let os = if !meta.os.is_empty() {
        plain(&meta.os)
    } else if meta.os_given {
        crate::default_os()
    } else {
        String::new()
    };
    let date = plain(&crate::format_date(&meta.date));
    r.footer(&date, &os);
    html::end_document(&mut r.h, opts);
    r.h.finish()
}

/// The elements for phrasing macros: tag and class.
fn phrase(tok: &str) -> Option<(&'static str, &'static str)> {
    Some(match tok {
        "Ad" => ("span", "Ad"),
        "An" => ("span", "An"),
        "Ar" => ("var", "Ar"),
        "Cd" => ("code", "Cd"),
        "Cm" => ("code", "Cm"),
        "Dv" => ("code", "Dv"),
        "Em" => ("i", "Em"),
        "Er" => ("code", "Er"),
        "Ev" => ("code", "Ev"),
        "Fa" => ("var", "Fa"),
        "Fd" => ("code", "Fd"),
        "Fr" => ("i", "Em"),
        "Ft" => ("var", "Ft"),
        "Ic" => ("code", "Ic"),
        "Li" => ("code", "Li"),
        "Ms" => ("span", "Ms"),
        "Nm" => ("code", "Nm"),
        "No" => ("span", "No"),
        "Pa" => ("span", "Pa"),
        "Sy" => ("b", "Sy"),
        "Va" => ("var", "Va"),
        "Vt" => ("var", "Vt"),
        _ => return None,
    })
}

impl R<'_> {
    fn header(&mut self, title: &str, vol: &str) {
        self.h.open("table", "class=\"head\"");
        self.h.open("tr", "");
        for (class, text) in [("head-ltitle", title), ("head-vol", vol), ("head-rtitle", title)] {
            self.h.open("td", &format!("class=\"{class}\""));
            self.words(text);
            self.h.close("td");
        }
        self.h.close("tr");
        self.h.close("table");
    }

    fn footer(&mut self, date: &str, os: &str) {
        self.h.open("table", "class=\"foot\"");
        self.h.open("tr", "");
        for (class, text) in [("foot-date", date), ("foot-os", os)] {
            self.h.open("td", &format!("class=\"{class}\""));
            self.words(text);
            self.h.close("td");
        }
        self.h.close("tr");
        self.h.close("table");
    }

    /// Plain text as words.
    fn words(&mut self, text: &str) {
        for w in text.split(' ').filter(|w| !w.is_empty()) {
            self.h.word(w);
        }
    }

    /// The identifier node `n` gets, if it is tagged.
    fn id_of(&self, n: &Node) -> Option<String> {
        self.ids.get(&(n as *const Node as usize)).cloned()
    }

    /// Opens a paragraph for the first text in a section; once the section has had one, text
    /// after a block element sits directly in the section, as mandoc puts it.
    fn ensure_p(&mut self) {
        if self.h.top() == Some("section") && self.para {
            self.h.open("p", "class=\"Pp\"");
            self.para = false;
        }
    }

    /// Whether the open paragraph is directly in a section.
    fn p_at_section(&self) -> bool {
        self.h.top() == Some("p") && self.h.parent_of_top() == Some("section")
    }

    /// Ends the open paragraph, for a block element.
    fn close_p(&mut self) {
        if self.h.top() == Some("p") {
            self.h.close("p");
        }
    }

    fn children(&mut self, n: &Node) {
        for (i, c) in n.children.iter().enumerate() {
            let next = n.children.get(i + 1);
            // An empty macro right before the same macro with words joins it (`.Fl Fl help`).
            if c.kind == Kind::Elem
                && !c.children.iter().any(|t| !t.text.is_empty() || t.kind != Kind::Text)
                && c.args.is_empty()
                && next.is_some_and(|x| x.kind == Kind::Elem && x.tok == c.tok && x.flags.nospace && x.children.iter().any(|t| !t.text.is_empty()))
            {
                if c.tok == "Fl" {
                    self.fl_prefix += 1;
                }
                continue;
            }
            self.node(c);
            if !(c.kind == Kind::Text && c.flags.delim) {
                self.prev = if c.kind == Kind::Text { String::new() } else { c.tok.clone() };
            }
        }
    }

    fn node(&mut self, n: &Node) {
        // (An element attached to what came before carries that on its first word.)
        if n.flags.nospace || (n.kind == Kind::Elem && n.children.first().is_some_and(|c| c.kind == Kind::Text && c.flags.nospace)) {
            self.h.nospace();
        }
        if let Some(id) = self.links.get(&(n as *const Node as usize)).cloned().filter(|_| !matches!(n.tok.as_str(), "Fn" | "Fl" | "Fo")) {
            self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(&id)));
            self.h.nospace();
            self.node_inner(n);
            self.h.close("a");
            return;
        }
        self.node_inner(n);
        self.first = false;
    }

    fn node_inner(&mut self, n: &Node) {
        match n.kind {
            Kind::Text => {
                self.ensure_p();
                if n.flags.nospace {
                    self.h.nospace();
                }
                self.text(&n.text);
            }
            Kind::Table => {
                self.close_p();
                if let Some(t) = &n.table {
                    crate::tbl_html::render(&mut self.h, t);
                }
            }
            Kind::Eqn => {
                self.ensure_p();
                if let Some(e) = &n.eqn {
                    crate::eqn_html::render(e, &mut self.h);
                }
            }
            Kind::Elem => self.elem(n),
            Kind::Block => self.block(n),
            _ => self.children(n),
        }
    }

    /// Text: its words, with font escapes as elements.
    fn text(&mut self, s: &str) {
        let s = s.trim_matches([' ', '\t']);
        let mut first = true;
        for w in s.split(' ').filter(|w| !w.is_empty()) {
            if !first {
                self.h.clear_nospace();
            }
            self.h.word(w);
            first = false;
        }
    }

    fn elem(&mut self, n: &Node) {
        let tok = n.tok.as_str();
        match tok {
            "Pp" | "Lp" => {
                self.close_p();
                self.para = false;
                match self.id_of(n) {
                    Some(id) => self.h.open("p", &format!("class=\"Pp\" id=\"{}\"", html::escape(&id))),
                    None => self.h.open("p", "class=\"Pp\""),
                }
                return;
            }
            "br" | "sp" => {
                self.h.br();
                return;
            }
            _ => {}
        }
        if !(tok == "An" && !n.args.is_empty()) {
            self.ensure_p();
        }
        match tok {
            "Fl" => {
                // Each word is a flag of its own.
                let extra = "-".repeat(std::mem::take(&mut self.fl_prefix));
                // (A permalink goes around the first.)
                let link = self.links.get(&(n as *const Node as usize)).cloned();
                let words: Vec<&Node> = n.children.iter().filter(|c| c.kind == Kind::Text).collect();
                if words.is_empty() {
                    if let Some(l) = &link {
                        self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(l)));
                    }
                    self.h.open("code", "class=\"Fl\"");
                    self.h.word(&format!("{extra}-"));
                    self.h.close("code");
                    if link.is_some() {
                        self.h.close("a");
                    }
                }
                for (i, c) in n.children.iter().enumerate() {
                    if c.kind == Kind::Text {
                        if i > 0 && c.flags.nospace {
                            self.h.nospace();
                        }
                        let wrap = i == 0 && link.is_some();
                        if wrap {
                            self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(link.as_ref().unwrap())));
                        }
                        self.h.open("code", "class=\"Fl\"");
                        self.h.word(&format!("{}-{}", if i == 0 { extra.as_str() } else { "" }, c.text));
                        self.h.close("code");
                        if wrap {
                            self.h.close("a");
                        }
                    } else {
                        self.node(c);
                    }
                }
            }
            "Nm" if n.children.is_empty() => {
                self.h.open("code", "class=\"Nm\"");
                let name = self.meta.name.clone();
                self.words(&name);
                self.h.close("code");
            }
            "Xr" => {
                let name = n.args.first().cloned().unwrap_or_default();
                let sec = n.args.get(1).cloned();
                let attrs = match (&self.opts.man, &sec) {
                    (Some(t), Some(s)) => format!("class=\"Xr\" href=\"{}\"", html::escape(&html::man_link(t, &name, s))),
                    _ => "class=\"Xr\"".to_string(),
                };
                self.h.open("a", &attrs);
                let w = match sec {
                    Some(s) => format!("{name}({s})"),
                    None => name,
                };
                self.h.word(&w);
                self.h.close("a");
            }
            "Sx" => {
                let target = html::make_id(&n.plain_text());
                self.h.open("a", &format!("class=\"Sx\" href=\"#{}\"", html::escape(&target)));
                self.children(n);
                self.h.close("a");
            }
            "Tn" => self.children(n),
            "Ox" | "Nx" | "Fx" | "Dx" | "Bsx" | "Bx" | "Ux" | "At" => {
                self.h.open("span", "class=\"Ux\"");
                let text = os_name(tok, &n.args);
                self.words(&text);
                self.h.close("span");
            }
            "St" => {
                self.h.open("span", "class=\"St\"");
                self.words(&os_name(tok, &n.args));
                self.h.close("span");
            }
            "Lb" => {
                self.h.open("span", "class=\"Lb\"");
                self.words(&crate::libraries::name(n.args.first().map(String::as_str).unwrap_or("")));
                self.h.close("span");
            }
            "Lk" => {
                let url = n.args.first().cloned().unwrap_or_default();
                self.h.open("a", &format!("class=\"Lk\" href=\"{}\"", html::escape(&url)));
                let label: Vec<&String> = n.args.iter().skip(1).collect();
                if label.is_empty() {
                    self.h.word(&url);
                } else {
                    for a in label {
                        self.words(a);
                    }
                }
                self.h.close("a");
            }
            "Mt" => {
                for a in &n.args {
                    self.h.open("a", &format!("class=\"Mt\" href=\"mailto:{}\"", html::escape(a)));
                    self.h.word(a);
                    self.h.close("a");
                }
            }
            "In" => {
                let file = n.args.first().cloned().unwrap_or_default();
                if self.synopsis {
                    self.synopsis_pre("In");
                }
                self.h.open("code", "class=\"In\"");
                if self.synopsis {
                    self.h.word("#include");
                }
                self.h.word("<");
                self.h.nospace();
                self.h.open("a", "class=\"In\"");
                self.h.word(&file);
                self.h.close("a");
                self.h.nospace();
                self.h.word(">");
                self.h.close("code");
            }
            "Fn" => {
                let name = n.args.first().cloned().unwrap_or_default();
                let args: Vec<String> = n.args.iter().skip(1).cloned().collect();
                let id = self.id_of(n);
                let link = self.links.get(&(n as *const Node as usize)).cloned();
                self.function(&name, &args, None, id, link);
            }
            "Ex" | "Rv" => {
                // In the middle of a paragraph, the sentence starts a line.
                if !self.h.at_block_start() {
                    self.h.br();
                }
                self.std_text(n)
            }
            "An" => {
                if let Some(mode) = n.args.first() {
                    self.split = Some(mode == "-split");
                    if mode == "-split" {
                        self.h.br();
                    }
                    return;
                }
                if self.authors && self.seen_an && self.split != Some(false) {
                    self.h.br();
                }
                self.seen_an = true;
                self.h.open("span", "class=\"An\"");
                self.children(n);
                self.h.close("span");
            }
            "Fd" if n.children.first().is_some_and(|c| c.text == "#include") => {
                // `.Fd #include <file>` is set as an include.
                if self.synopsis {
                    self.synopsis_pre("Fd");
                }
                self.h.open("code", "class=\"In\"");
                self.h.word("#include");
                self.h.open("a", "class=\"In\"");
                for c in n.children.iter().skip(1) {
                    self.h.word(&c.text);
                }
                self.h.close("a");
                self.h.close("code");
            }
            _ => match phrase(tok) {
                Some((tag, class)) => {
                    if self.synopsis && matches!(tok, "Ft" | "Fd" | "Vt" | "Cd") {
                        self.synopsis_pre(tok);
                    }
                    match self.id_of(n) {
                        Some(id) => {
                            self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(&id)));
                            self.h.open(tag, &format!("class=\"{class}\" id=\"{}\"", html::escape(&id)));
                            self.children(n);
                            self.h.close(tag);
                            self.h.close("a");
                        }
                        None => {
                            self.h.open(tag, &format!("class=\"{class}\""));
                            self.children(n);
                            self.h.close(tag);
                        }
                    }
                }
                None => self.children(n),
            },
        }
    }

    fn function(&mut self, name: &str, args: &[String], body: Option<&Node>, id: Option<String>, link: Option<String>) {
        if self.synopsis && body.is_none() {
            self.synopsis_pre("Fn");
        }
        // The permalink goes around the name only.
        if let Some(l) = id.as_ref().or(link.as_ref()) {
            self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(l)));
        }
        match &id {
            Some(id) => self.h.open("code", &format!("class=\"Fn\" id=\"{}\"", html::escape(id))),
            None => self.h.open("code", "class=\"Fn\""),
        }
        self.h.word(name);
        self.h.close("code");
        if id.is_some() || link.is_some() {
            self.h.close("a");
        }
        self.h.nospace();
        self.h.word("(");
        let mut first = true;
        for a in args {
            if !first {
                self.h.nospace();
                self.h.word(",");
            } else {
                self.h.nospace();
            }
            first = false;
            if self.synopsis {
                self.h.open("var", "class=\"Fa\" style=\"white-space: nowrap;\"");
            } else {
                self.h.open("var", "class=\"Fa\"");
            }
            self.words(a);
            self.h.close("var");
        }
        if let Some(b) = body {
            for c in &b.children {
                if c.kind == Kind::Elem && c.tok == "Fa" {
                    for t in &c.children {
                        if !first {
                            self.h.nospace();
                            self.h.word(",");
                        } else {
                            self.h.nospace();
                        }
                        first = false;
                        self.h.open("var", "class=\"Fa\"");
                        self.words(&t.text);
                        self.h.close("var");
                    }
                } else {
                    self.node(c);
                }
            }
        }
        self.h.nospace();
        self.h.word(")");
        // (`.Fo` ends with a semicolon wherever it is.)
        if self.synopsis || body.is_some() {
            self.h.nospace();
            self.h.word(";");
        }
    }

    /// Before a SYNOPSIS declaration: a new paragraph after a different kind of declaration, a
    /// line break after the same kind (or a function after its type), as on the terminal.
    fn synopsis_pre(&mut self, tok: &str) {
        let prev = self.prev.as_str();
        let decl = matches!(prev, "In" | "Fd" | "Fn" | "Fo" | "Ft" | "Vt" | "Cd");
        let same = prev == tok && tok != "Fn";
        let ft_fn = prev == "Ft" && tok == "Fn";
        if decl && !same && !ft_fn {
            self.close_p();
            self.h.open("p", "class=\"Pp\"");
        } else if !self.h.at_block_start() {
            self.h.br();
        }
    }

    fn std_text(&mut self, n: &Node) {
        let mut names: Vec<String> = n.args.iter().filter(|a| *a != "-std").cloned().collect();
        let fns = n.tok == "Rv";
        if names.is_empty() && !fns {
            names.push(self.meta.name.clone());
        }
        self.h.word("The");
        let count = names.len();
        for (i, name) in names.iter().enumerate() {
            let class = if fns { "Fn" } else { "Nm" };
            self.h.open("code", &format!("class=\"{class}\""));
            self.h.word(name);
            self.h.close("code");
            if fns {
                self.h.nospace();
                self.h.word("()");
            }
            if count > 2 && i + 1 < count {
                self.h.nospace();
                self.h.word(",");
            }
            if count > 1 && i + 2 == count {
                self.h.word("and");
            }
        }
        let rest = match (fns, count > 1) {
            (false, false) => "utility exits\u{E002}0 on success, and\u{E002}>0 if an error occurs.",
            (false, true) => "utilities exit\u{E002}0 on success, and\u{E002}>0 if an error occurs.",
            (true, false) => "function returns the value\u{E002}0 if successful; otherwise the value\u{E002}-1 is returned and the global variable",
            (true, true) => "functions return the value\u{E002}0 if successful; otherwise the value\u{E002}-1 is returned and the global variable",
        };
        self.words(rest);
        if fns {
            self.h.open("var", "class=\"Va\"");
            self.h.word("errno");
            self.h.close("var");
            self.words("is set to indicate the error.");
        }
    }

    fn block(&mut self, n: &Node) {
        let tok = n.tok.as_str();
        match tok {
            "Sh" | "Ss" => self.section(n),
            "Nd" => {
                self.ensure_p();
                self.h.word("\u{2014}");
                self.h.open("span", "class=\"Nd\"");
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.h.close("span");
            }
            "Nm" => self.synopsis_nm(n),
            "Bl" => self.list(n),
            "Bd" => self.display(n),
            "D1" | "Dl" => {
                self.close_p();
                self.h.open("div", "class=\"Bd Bd-indent\"");
                if tok == "Dl" {
                    self.h.open("code", "class=\"Li\"");
                }
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                if tok == "Dl" {
                    self.h.close("code");
                }
                self.h.close("div");
            }
            "Bf" => {
                self.close_p();
                let class = if has_flag(&n.args, "-symbolic") || has_flag(&n.args, "Sy") {
                    "Bf Sy"
                } else if has_flag(&n.args, "-emphasis") || has_flag(&n.args, "Em") {
                    "Bf Em"
                } else {
                    "Bf Li"
                };
                self.h.open("div", &format!("class=\"{class}\""));
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.h.close("div");
            }
            "Rs" => self.reference(n),
            "Fo" => {
                self.ensure_p();
                if self.synopsis {
                    self.synopsis_pre("Fn");
                }
                let name = n.text.clone();
                let link = self.links.get(&(n as *const Node as usize)).cloned();
                let id = self.id_of(n);
                self.function(&name, &[], n.part(Kind::Body), id, link);
            }
            "Bk" => {
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
            }
            "Ql" => {
                self.ensure_p();
                self.h.word("\u{2018}");
                self.h.nospace();
                self.h.open("code", "class=\"Li\"");
                if let Some(b) = n.part(Kind::Body) {
                    self.children(b);
                }
                self.h.close("code");
                self.h.nospace();
                self.h.word("\u{2019}");
            }
            _ if n.args.len() == 2 && n.part(Kind::Body).is_some() => {
                self.ensure_p();
                let (open, close) = crate::mdoc::enclosure(n);
                if !open.is_empty() {
                    self.h.word(&open);
                    self.h.nospace();
                }
                self.children(n.part(Kind::Body).unwrap());
                if !close.is_empty() {
                    self.h.nospace();
                    self.h.word(&close);
                }
            }
            _ => {
                for part in &n.children {
                    self.children(part);
                }
            }
        }
    }

    fn section(&mut self, n: &Node) {
        let (sec, h) = if n.tok == "Sh" { ("Sh", "h1") } else { ("Ss", "h2") };
        self.close_p();
        if n.tok == "Sh" {
            while self.h.is_open("section") {
                self.h.close("section");
            }
            self.in_ss = false;
        } else if self.in_ss {
            self.h.close("section");
        }
        if n.tok == "Ss" {
            self.in_ss = true;
        }
        self.h.open("section", &format!("class=\"{sec}\""));
        let head = n.part(Kind::Head);
        let text = head.map(|h| h.plain_text()).unwrap_or_default();
        if n.tok == "Sh" {
            self.synopsis = text == "SYNOPSIS";
            self.authors = text == "AUTHORS";
            self.seen_an = false;
        }
        match self.id_of(n) {
            Some(id) => {
                self.h.open(h, &format!("class=\"{sec}\" id=\"{}\"", html::escape(&id)));
                self.h.open("a", &format!("class=\"permalink\" href=\"#{}\"", html::escape(&id)));
                if let Some(hd) = head {
                    self.children(hd);
                }
                self.h.close("a");
            }
            None => {
                self.h.open(h, &format!("class=\"{sec}\""));
                if let Some(hd) = head {
                    self.children(hd);
                }
            }
        }
        self.h.close(h);
        self.prev.clear();
        self.para = true;
        self.first = true;
        if let Some(b) = n.part(Kind::Body) {
            self.children(b);
        }
        self.close_p();
        if n.tok == "Sh" {
            while self.h.is_open("section") {
                self.h.close("section");
            }
        }
    }

    fn synopsis_nm(&mut self, n: &Node) {
        self.close_p();
        if !self.prev.is_empty() {
            self.h.br();
        }
        self.h.open("table", "class=\"Nm\"");
        self.h.open("tr", "");
        self.h.open("td", "");
        if let Some(hd) = n.part(Kind::Head) {
            self.children(hd);
        }
        self.h.close("td");
        self.h.open("td", "");
        if let Some(b) = n.part(Kind::Body) {
            self.children(b);
        }
        self.h.close("td");
        self.h.close("tr");
        self.h.close("table");
    }

    fn list(&mut self, n: &Node) {
        self.close_p();
        let ltype = list_type(&n.args).to_string();
        let compact = if has_flag(&n.args, "-compact") { " Bl-compact" } else { "" };
        let (tag, class) = match ltype.as_str() {
            "-bullet" => ("ul", "Bl-bullet"),
            "-dash" | "-hyphen" => ("ul", "Bl-dash"),
            "-item" => ("ul", "Bl-item"),
            "-enum" => ("ol", "Bl-enum"),
            "-column" => ("table", "Bl-column"),
            "-diag" => ("dl", "Bl-diag"),
            "-hang" => ("dl", "Bl-hang"),
            "-ohang" => ("dl", "Bl-ohang"),
            "-inset" => ("dl", "Bl-inset"),
            _ => ("dl", "Bl-tag"),
        };
        // An indented list: a class of its own for bullets and numbers, otherwise a division.
        let offset = crate::mdoc::option(&n.args, "-offset").is_some() && !matches!(tag, "ul" | "ol");
        let indent = if !offset && crate::mdoc::option(&n.args, "-offset").is_some() { " Bd-indent" } else { "" };
        if offset {
            self.h.open("div", "class=\"Bd-indent\"");
        }
        self.h.open(tag, &format!("class=\"{class}{indent}{compact}\""));
        let items: Vec<&Node> = n.part(Kind::Body).map(|b| b.children.iter().filter(|c| c.kind == Kind::Block && c.tok == "It").collect()).unwrap_or_default();
        for it in items {
            let head = it.part(Kind::Head);
            match tag {
                "ul" | "ol" => {
                    match self.id_of(it) {
                        Some(id) => self.h.open("li", &format!("id=\"{}\"", html::escape(&id))),
                        None => self.h.open("li", ""),
                    }
                    for b in it.children.iter().filter(|c| c.kind == Kind::Body) {
                        self.children(b);
                    }
                    self.h.close("li");
                }
                "table" => {
                    match self.id_of(it) {
                        Some(id) => self.h.open("tr", &format!("id=\"{}\"", html::escape(&id))),
                        None => self.h.open("tr", ""),
                    }
                    for b in it.children.iter().filter(|c| c.kind == Kind::Body) {
                        self.h.open("td", "");
                        self.children(b);
                        self.h.close("td");
                    }
                    self.h.close("tr");
                }
                _ => {
                    let empty = !it.children.iter().any(|c| c.kind == Kind::Body && !c.children.is_empty());
                    match self.id_of(it) {
                        Some(id) => {
                            self.h.open("dt", &format!("id=\"{}\"", html::escape(&id)));
                            if let Some(hd) = head {
                                self.children(hd);
                            }
                        }
                        None => {
                            self.h.open("dt", "");
                            if let Some(hd) = head {
                                self.children(hd);
                            }
                        }
                    }
                    self.h.close("dt");
                    // An empty body in a tag list is a no-break space, so the head keeps its line.
                    if empty && class == "Bl-tag" {
                        self.h.open("dd", "style=\"width: auto;\"");
                        self.h.word(&mark::NBSP.to_string());
                    } else {
                        self.h.open("dd", "");
                    }
                    for b in it.children.iter().filter(|c| c.kind == Kind::Body) {
                        self.children(b);
                    }
                    self.h.close("dd");
                }
            }
        }
        self.h.close(tag);
        if offset {
            self.h.close("div");
        }
    }

    fn display(&mut self, n: &Node) {
        let first = self.first;
        self.close_p();
        let mut class = String::from("Bd");
        // (Space before it, unless it is compact or starts its section.)
        if !has_flag(&n.args, "-compact") && !first {
            class.push_str(" Pp");
        }
        if crate::mdoc::option(&n.args, "-offset").is_some_and(|o| o != "left") {
            class.push_str(" Bd-indent");
        }
        let literal = has_flag(&n.args, "-literal") || has_flag(&n.args, "-unfilled");
        if literal {
            class.push_str(" Li");
        }
        self.h.open("div", &format!("class=\"{class}\""));
        if literal {
            self.h.open("pre", "");
            if let Some(b) = n.part(Kind::Body) {
                let mut first = true;
                for c in &b.children {
                    if c.kind == Kind::Text && c.flags.line_start && !first {
                        self.h.literal_text("\n");
                    }
                    first = false;
                    if c.kind == Kind::Text {
                        self.h.literal_text(&c.text);
                    } else {
                        self.node(c);
                    }
                }
            }
            self.h.close("pre");
        } else if let Some(b) = n.part(Kind::Body) {
            self.children(b);
        }
        self.h.close("div");
    }

    fn reference(&mut self, n: &Node) {
        let Some(body) = n.part(Kind::Body) else { return };
        // A reference is a paragraph of its own in a section.
        if matches!(self.h.top(), Some("section") | Some("p")) && (self.h.top() == Some("section") || self.h.is_open("section") && self.p_at_section()) {
            self.close_p();
            self.h.open("p", "class=\"Pp\"");
            self.para = false;
        }
        self.h.open("cite", "class=\"Rs\"");
        let field = |tok: &str| -> Vec<&Node> { body.children.iter().filter(|c| c.tok == tok).collect() };
        let mut parts: Vec<(&str, &Node)> = Vec::new();
        for tok in ["%A", "%T", "%B", "%I", "%J", "%R", "%N", "%V", "%U", "%P", "%Q", "%C", "%D", "%O"] {
            for f in field(tok) {
                parts.push((tok, f));
            }
        }
        let authors = field("%A").len();
        let count = parts.len();
        let mut ai = 0;
        for (i, (tok, f)) in parts.iter().enumerate() {
            let class = format!("Rs{}", &tok[1..]);
            let tag = match *tok {
                "%B" | "%I" | "%J" => "i",
                "%U" => "a",
                _ => "span",
            };
            if *tok == "%U" {
                self.h.open("a", &format!("class=\"{class}\" href=\"{}\"", html::escape(&f.plain_text())));
            } else {
                self.h.open(tag, &format!("class=\"{class}\""));
            }
            self.children(f);
            self.h.close(tag);
            let last = i + 1 == count;
            if *tok == "%A" {
                ai += 1;
                if ai < authors {
                    if authors > 2 {
                        self.h.nospace();
                        self.h.word(",");
                    }
                    if ai + 1 == authors {
                        self.h.word("and");
                    }
                    continue;
                }
            }
            self.h.nospace();
            self.h.word(if last { "." } else { "," });
        }
        self.h.close("cite");
    }
}

/// Prologue text with roff's markers resolved.
fn plain(s: &str) -> String {
    s.chars()
        .filter_map(|c| match c {
            mark::MINUS => Some('-'),
            mark::NBSP => Some(' '),
            mark::BACKSLASH => Some('\\'),
            c if ('\u{E000}'..='\u{E01F}').contains(&c) => None,
            c => Some(c),
        })
        .collect()
}

/// Macros that tag a list item they start, in a tag list.
const ITEM_TAGS: &[&str] = &["Cm", "Dv", "Em", "Ev", "Fl", "Fn", "Fo", "Ic", "Li", "Ms", "No", "Sy", "Va"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimKind {
    Heading,
    /// A tag-list item's head, by its first macro.
    Item,
    /// `.Fn`, `.Em` or `.Sy` in running text.
    Text,
}

/// A claim on an identifier: the node that would carry it, the one its permalink goes
/// around, and the text it is made from.
struct Claim {
    kind: ClaimKind,
    /// The macro the text comes from.
    tok: String,
    node: usize,
    link: usize,
    text: String,
    /// The paragraph the node is in, counted in the order of the text: a new one starts at
    /// every `.Pp`, wherever it is.
    para: usize,
    /// For text: the paragraph or list item it is in, which takes the identifier if it has
    /// none of its own.
    anchor: usize,
}

/// Works out which nodes carry identifiers, as mandoc does. Section headings, the heads of
/// tag-list items starting with certain macros, and `.Fn`, `.Em` and `.Sy` in running text
/// claim them, each with a priority: a heading or an item 1; a function 1 plus the number of
/// functions before it in its paragraph; an emphasis last of all. For each text only the best
/// claims stand (emphases only if there is one); a heading of several words used twice stands
/// for nothing. What stands is numbered in order (`name`, `name~2`...). An identifier from
/// running text goes on its paragraph or list item, if that has none, and the permalink stays
/// on the text.
fn tags(doc: &Document) -> (HashMap<usize, String>, HashMap<usize, String>) {
    const EMPHASIS: usize = usize::MAX;
    let mut claims = Vec::new();
    collect(&doc.root, "", "", &mut 0, 0, &mut claims);
    // A function's claim ranks by the functions before it in its paragraph, list item heads
    // included. A name claimed by a function twice in a paragraph is claimed by the first (the
    // second still counts).
    const GONE: usize = usize::MAX - 1;
    let mut in_para: HashMap<usize, usize> = HashMap::new();
    let mut named: Vec<(String, usize)> = Vec::new();
    let prio: Vec<usize> = claims
        .iter()
        .map(|c| {
            if c.tok == "Fn" {
                let n = in_para.entry(c.para).or_default();
                *n += 1;
                let key = (c.text.clone(), c.para);
                if named.contains(&key) {
                    return GONE;
                }
                named.push(key);
                *n
            } else if c.kind == ClaimKind::Text {
                EMPHASIS
            } else {
                1
            }
        })
        .collect();
    if std::env::var_os("OXDOC_TAGDEBUG").is_some() {
        for (c, p) in claims.iter().zip(&prio) {
            eprintln!("claim {:?} {} {:?} prio={} para={:x}", c.kind as u8, c.tok, c.text, p, c.para);
        }
    }
    let mut best: HashMap<&str, (usize, usize)> = HashMap::new();
    for (c, &p) in claims.iter().zip(&prio).filter(|(_, p)| **p != GONE) {
        let e = best.entry(&c.text).or_insert((p, 0));
        if p < e.0 {
            *e = (p, 0);
        }
        if p == e.0 {
            e.1 += 1;
        }
    }
    let mut headings: HashMap<&str, usize> = HashMap::new();
    for c in claims.iter().filter(|c| c.kind == ClaimKind::Heading) {
        *headings.entry(&c.text).or_default() += 1;
    }
    let mut out = HashMap::new();
    let mut links = HashMap::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (c, &p) in claims.iter().zip(&prio) {
        let (bp, count) = best[c.text.as_str()];
        if p == GONE || p != bp || (p == EMPHASIS && count > 1) {
            continue;
        }
        if c.kind == ClaimKind::Heading && c.text.contains(' ') && headings[c.text.as_str()] > 1 {
            continue;
        }
        let n = seen.entry(c.text.clone()).or_default();
        *n += 1;
        let base = html::make_id(&c.text);
        let id = if *n == 1 { base } else { format!("{base}~{n}") };
        match c.kind {
            ClaimKind::Text if c.anchor != 0 && !out.contains_key(&c.anchor) => {
                out.insert(c.anchor, id.clone());
                links.insert(c.node, id);
            }
            _ => {
                // (A variable's item has no permalink.)
                if c.link != c.node && c.tok != "Va" {
                    links.insert(c.link, id.clone());
                }
                out.insert(c.node, id);
            }
        }
    }
    (out, links)
}

/// The sections mdoc(7) names, where `.Fn` isn't tagged (except in DESCRIPTION).
const STANDARD_SECTIONS: &[&str] = &[
    "NAME", "LIBRARY", "SYNOPSIS", "DESCRIPTION", "CONTEXT", "IMPLEMENTATION NOTES", "RETURN VALUES", "ENVIRONMENT", "FILES", "EXIT STATUS", "EXAMPLES", "DIAGNOSTICS", "COMPATIBILITY", "ERRORS", "SEE ALSO", "STANDARDS", "HISTORY", "AUTHORS", "CAVEATS", "BUGS", "SECURITY CONSIDERATIONS",
];

/// The text a tag is made from: the first word of an element's words, if it is plain (a
/// flag's without its dashes).
fn tag_text(n: &Node) -> Option<String> {
    let text = match n.tok.as_str() {
        "Fn" | "Fo" => if n.tok == "Fo" { n.text.clone() } else { n.args.first().cloned().unwrap_or_default() },
        _ => n.plain_text(),
    };
    let text = text.trim_start_matches(['-', mark::MINUS]).to_string();
    // (An escape sequence ends it.)
    let text: String = text.chars().take_while(|c| !('\u{E000}'..='\u{E0FF}').contains(c)).collect();
    let word = text.split(' ').find(|w| !w.is_empty())?.to_string();
    (word.is_ascii() && !word.chars().any(|c| c.is_ascii_control())).then_some(word)
}

fn collect(n: &Node, section: &str, list: &str, para: &mut usize, anchor: usize, out: &mut Vec<Claim>) {
    let mut anchor = anchor;
    let addr = |c: &Node| c as *const Node as usize;
    for c in &n.children {
        if c.kind == Kind::Elem && matches!(c.tok.as_str(), "Pp" | "Lp") {
            *para += 1;
            anchor = addr(c);
            continue;
        }
        match (c.kind, c.tok.as_str()) {
            (Kind::Block, "Sh" | "Ss") => {
                let text = c.part(Kind::Head).map(|h| h.plain_text()).unwrap_or_default();
                if text.is_ascii() && !text.is_empty() {
                    out.push(Claim { kind: ClaimKind::Heading, tok: c.tok.clone(), node: addr(c), link: addr(c), text: text.clone(), para: *para, anchor: 0 });
                }
                // (A section goes on with the last paragraph before it: only `.Pp` starts one.)
                let sec = if c.tok == "Sh" { text.as_str() } else { section };
                for part in &c.children {
                    collect(part, sec, "", para, 0, out);
                }
            }
            (Kind::Block, "Bl") => {
                let lt = list_type(&c.args).to_string();
                for part in &c.children {
                    collect(part, section, &lt, para, anchor, out);
                }
            }
            (Kind::Block, "It") => {
                // The head, or for items without one (bullets, columns) the first body.
                let head = if matches!(list, "-tag" | "-hang" | "-ohang" | "-inset") { c.part(Kind::Head) } else if list == "-diag" { None } else { c.children.iter().find(|p| p.kind == Kind::Body) };
                // (An `.Xo` extension is part of the head.)
                let items: Vec<&Node> = head.map(|h| h.children.iter().flat_map(|x| if x.kind == Kind::Block && x.tok == "Xo" { x.part(Kind::Body).map(|b| b.children.iter().collect::<Vec<_>>()).unwrap_or_default() } else { vec![x] }).collect()).unwrap_or_default();
                if head.is_some()
                    && let Some(&first) = items.first()
                {
                    // (Inside an explicit enclosure, `.Oo Fl x Oc`, and `.Bq Er` in ERRORS, the
                    // macro inside counts.)
                    let enclosed = first.kind == Kind::Block && (matches!(first.tok.as_str(), "Oo" | "Ao" | "Bo" | "Bro" | "Do" | "Po" | "Qo" | "So") || (section == "ERRORS" && first.tok == "Bq"));
                    // A function anywhere in the head is what it is tagged by.
                    let func = items.iter().copied().find(|x| (x.kind == Kind::Elem && x.tok == "Fn") || (x.kind == Kind::Block && x.tok == "Fo"));
                    let target = if func.is_some() {
                        func
                    } else if enclosed {
                        first.part(Kind::Body).and_then(|b| b.children.first())
                    } else {
                        Some(first)
                    };
                    if let Some(t) = target
                        && (t.kind == Kind::Elem || t.tok == "Fo")
                        && (ITEM_TAGS.contains(&t.tok.as_str()) || (t.tok == "Er" && section == "ERRORS"))
                        && let Some(text) = tag_text(t)
                    {
                        let tok = if t.tok == "Fo" { "Fn".to_string() } else { t.tok.clone() };
                        // (A function only where a function in the text would be.)
                        if tok == "Fn" && section != "DESCRIPTION" && STANDARD_SECTIONS.contains(&section) {
                            for part in &c.children {
                                collect(part, section, "", para, addr(c), out);
                            }
                            continue;
                        }
                        out.push(Claim { kind: ClaimKind::Item, tok, node: addr(c), link: addr(t), text, para: *para, anchor: 0 });
                    }
                }
                // (What the head holds is the item's claim, not claims of its own.)
                for part in c.children.iter().filter(|p| p.kind != Kind::Head) {
                    collect(part, section, "", para, addr(c), out);
                }
            }
            (Kind::Block, "Fo") if section == "DESCRIPTION" || !STANDARD_SECTIONS.contains(&section) => {
                if let Some(text) = tag_text(c) {
                    out.push(Claim { kind: ClaimKind::Text, tok: "Fn".into(), node: addr(c), link: addr(c), text, para: *para, anchor });
                }
                collect(c, section, list, para, anchor, out);
            }
            (Kind::Elem, "Em" | "Sy") | (Kind::Elem, "Fn") if c.tok != "Fn" || section == "DESCRIPTION" || !STANDARD_SECTIONS.contains(&section) => {
                if let Some(text) = tag_text(c) {
                    out.push(Claim { kind: ClaimKind::Text, tok: c.tok.clone(), node: addr(c), link: addr(c), text, para: *para, anchor });
                }
                collect(c, section, list, para, anchor, out);
            }
            _ => collect(c, section, list, para, anchor, out),
        }
    }
}
