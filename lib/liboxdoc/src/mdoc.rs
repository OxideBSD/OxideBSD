//! The mdoc parser (MAN.md §4.2): builds the document tree from roff lines.
//!
//! mdoc macros fall into the classes mdoc(7) describes: section and block macros that enclose
//! later lines (`.Sh`, `.Bl`, `.It`, `.Bd`...), partial blocks that enclose the rest of their own
//! line (`.Op`, `.Dq`...) or everything up to a closing macro (`.Oo`/`.Oc`), and in-line macros that
//! format their arguments (`.Fl`, `.Ar`...). In-line and partial macros are "parsed": a later
//! argument that names a "callable" macro starts that macro. Delimiters (`.`, `,`, `)`, `(`, `|`...)
//! are split off an in-line macro's arguments and printed outside its style.

use crate::diag::{Diagnostics, Level};
use crate::roff::{Line, mark};
use crate::tree::{Document, Kind, Language, Meta, Node};

/// Macros that may be called from another macro's arguments.
pub const CALLABLE: &[&str] = &[
    "Ac", "Ad", "An", "Ao", "Ap", "Aq", "Ar", "At", "Bc", "Bo", "Bq", "Brc", "Bro", "Brq", "Bsx", "Bx", "Cd", "Cm", "Dc", "Do", "Dq", "Dv", "Dx", "Ec", "Em", "En", "Eo", "Er", "Es", "Ev", "Fa", "Fc", "Fl", "Fn", "Fr", "Ft", "Fx", "Ic", "Li", "Lk", "Ms", "Mt", "Nm", "No", "Ns", "Nx", "Oc", "Oo", "Op", "Ox", "Pa", "Pc", "Pf", "Po", "Pq", "Qc", "Ql", "Qo", "Qq", "Sc", "So", "Sq", "St", "Sx", "Sy", "Ta", "Tn", "Ux", "Va", "Vt", "Xc", "Xo", "Xr",
];

/// Partial blocks enclosing the rest of their line, with their opening and closing text (UTF-8;
/// the renderer maps these to ASCII).
const PARTIAL_IMPLICIT: &[(&str, &str, &str)] = &[
    ("Aq", "\u{27E8}", "\u{27E9}"),
    ("Bq", "[", "]"),
    ("Brq", "{", "}"),
    ("Dq", "\u{201C}", "\u{201D}"),
    ("Op", "[", "]"),
    ("Pq", "(", ")"),
    ("Ql", "\u{2018}", "\u{2019}"),
    ("Qq", "\"", "\""),
    ("Sq", "\u{2018}", "\u{2019}"),
];

/// Partial blocks up to a closing macro: (open, close, opening text, closing text).
const PARTIAL_EXPLICIT: &[(&str, &str, &str, &str)] = &[
    ("Ao", "Ac", "\u{27E8}", "\u{27E9}"),
    ("Bo", "Bc", "[", "]"),
    ("Bro", "Brc", "{", "}"),
    ("Do", "Dc", "\u{201C}", "\u{201D}"),
    ("Oo", "Oc", "[", "]"),
    ("Po", "Pc", "(", ")"),
    ("Qo", "Qc", "\"", "\""),
    ("So", "Sc", "\u{2018}", "\u{2019}"),
    ("Xo", "Xc", "", ""),
    ("Eo", "Ec", "", ""),
    ("Fo", "Fc", "", ""),
];

/// Block macros that enclose later lines until their closing macro.
const FULL_EXPLICIT: &[(&str, &str)] = &[("Bd", "Ed"), ("Bf", "Ef"), ("Bk", "Ek"), ("Bl", "El"), ("Rs", "Re")];

pub fn is_delim_open(s: &str) -> bool {
    matches!(s, "(" | "[")
}

pub fn is_delim_close(s: &str) -> bool {
    matches!(s, "." | "," | ":" | ";" | ")" | "]" | "?" | "!")
}

pub fn is_delim(s: &str) -> bool {
    is_delim_open(s) || is_delim_close(s) || s == "|"
}

fn is_callable(s: &str) -> bool {
    CALLABLE.contains(&s)
}

/// Whether text ends a sentence: a final `.`, `!` or `?`, possibly followed by closing
/// punctuation, and not escaped with `\&`.
pub fn ends_sentence(s: &str) -> bool {
    // A period, `!` or `?` among the trailing punctuation. Closing punctuation after it
    // (`x.)`) passes the end of sentence on only when the run follows a letter or digit: `.)`
    // alone doesn't end one.
    let (mut found, mut enclosed) = (false, false);
    for c in s.chars().rev() {
        match c {
            '"' | '\'' | ')' | ']' | '*' | '\u{2019}' | '\u{201D}' => enclosed |= !found,
            '.' | '!' | '?' => found = true,
            // (A font escape counts as the letter its raw form `\fR` ends with.)
            c => return found && (!enclosed || c.is_alphanumeric() || mark::is_font(c)),
        }
    }
    found && !enclosed
}

struct Parser<'a> {
    stack: Vec<Node>,
    meta: Meta,
    diag: &'a mut Diagnostics,
    /// The next node gets no space before it (`.Ns`, an opening delimiter...).
    nospace: bool,
    /// `.Sm off`: no spaces between macro arguments.
    spacing_off: bool,
    in_synopsis: bool,
    line: usize,
    /// The column of the current macro's name, for diagnostics.
    col: usize,
    /// The current macro line as typed, from its name on.
    raw: String,
    /// The checks that need what came before.
    lint: crate::lint::MdocState,
    /// A description ending in punctuation, reported unless a text line continues it.
    pending_nd: Option<(usize, usize, String)>,
    /// Unknown macros already reported.
    unknown: Vec<String>,
    /// Inside a tbl or eqn block (`.TS`/`.TE`, `.EQ`/`.EN`), whose lines aren't text.
    in_preproc: bool,
    /// Whitespace at the end of the current macro line: where to report it, if the macro is
    /// known.
    trailing: Option<(usize, usize)>,
}

pub fn parse(lines: Vec<Line>, diag: &mut Diagnostics) -> Document {
    let mut p = Parser { stack: vec![Node::new(Kind::Root, "", 0)], meta: Meta::default(), diag, nospace: false, spacing_off: false, in_synopsis: false, line: 0, col: 0, raw: String::new(), trailing: None, unknown: Vec::new(), in_preproc: false, pending_nd: None, lint: Default::default() };
    let mut first = true;
    for l in lines {
        match l {
            Line::Macro { name, args, line, col, raw, trailing, .. } => {
                p.line = line;
                p.trailing = trailing;
                // tbl and eqn blocks: not formatted yet, and not checked.
                match name.as_str() {
                    "TS" | "EQ" => {
                        p.in_preproc = true;
                        continue;
                    }
                    "TE" | "EN" => {
                        p.in_preproc = false;
                        continue;
                    }
                    _ => {}
                }
                p.col = col;
                p.raw = raw;
                // A description runs to the next section; anything else before then continues it.
                if let Some((l, c, d)) = p.pending_nd.take()
                    && matches!(name.as_str(), "Sh" | "Ss")
                {
                    p.diag.report(Level::Style, l, c, "trailing delimiter", &d);
                }
                p.pending_nd = crate::lint::mdoc_args(p.diag, line, p.col, &name, &p.raw);
                p.lint.macro_line(p.diag, line, p.col, &name, &p.raw);
                p.macro_line(&name, &args, first);
                if let Some((l, c)) = p.trailing.take().filter(|_| crate::roff::MDOC_MACROS.contains(&name.as_str())) {
                    p.diag.report(Level::Style, l, c, "whitespace at end of input line", "");
                }
                // An `.Xc` may have closed the last open part of an `.It` head.
                p.end_item_head();
                first = false;
            }
            Line::Text { text, raw, line, last } => {
                // A description continued on a text line doesn't end where its macro line does.
                p.pending_nd = None;
                p.lint.text();
                p.line = line;
                p.col = 1;
                let literal = p.in_literal() || p.in_preproc;
                crate::lint::text_line(p.diag, line, &raw, last, literal, true);
                p.text_line(&text);
            }
            Line::Blank { line } => {
                p.line = line;
                // Blank lines before the first section are ignored.
                if p.stack.len() == 1 && !p.stack[0].children.iter().any(|c| c.tok == "Sh") {
                    continue;
                }
                // A blank line is a paragraph break, except in literal displays.
                if p.in_literal() {
                    let mut n = Node::text("", line);
                    n.flags.line_start = true;
                    p.push(n);
                } else {
                    p.diag.report(Level::Warning, line, 0, "blank line in fill mode, using .sp", "");
                    p.push(Node::new(Kind::Elem, "sp", line));
                }
            }
        }
    }
    if let Some((l, c, d)) = p.pending_nd.take() {
        p.diag.report(Level::Style, l, c, "trailing delimiter", &d);
    }
    p.lint.end(p.diag);
    while p.stack.len() > 1 {
        let top = p.stack.last().unwrap();
        if top.kind == Kind::Block && FULL_EXPLICIT.iter().any(|(o, _)| *o == top.tok) {
            let tok = top.tok.clone();
            p.diag.report(Level::Error, p.line, 0, "missing end of block", &tok);
        }
        p.close_top();
    }
    let root = p.stack.pop().unwrap();
    Document { language: Language::Mdoc, meta: p.meta, root }
}

impl Parser<'_> {
    fn push(&mut self, mut n: Node) {
        if self.nospace {
            n.flags.nospace = true;
            self.nospace = false;
        }
        self.stack.last_mut().unwrap().children.push(n);
    }

    fn open(&mut self, kind: Kind, tok: &str) {
        let mut n = Node::new(kind, tok, self.line);
        if kind == Kind::Block && self.nospace {
            n.flags.nospace = true;
            self.nospace = false;
        }
        self.stack.push(n);
    }

    fn close_top(&mut self) {
        let n = self.stack.pop().unwrap();
        self.stack.last_mut().unwrap().children.push(n);
    }

    /// Closes open nodes up to and including the block `tok`. Returns false if none is open.
    fn close_block(&mut self, tok: &str) -> bool {
        let Some(pos) = self.stack.iter().rposition(|n| n.kind == Kind::Block && n.tok == tok) else { return false };
        while self.stack.len() > pos {
            self.close_top();
        }
        true
    }

    fn open_block_tok(&self, tok: &str) -> Option<usize> {
        self.stack.iter().rposition(|n| n.kind == Kind::Block && n.tok == tok)
    }

    fn in_literal(&self) -> bool {
        self.stack.iter().any(|n| n.kind == Kind::Block && n.tok == "Bd" && n.args.iter().any(|a| a == "-literal" || a == "-unfilled"))
    }

    fn text_line(&mut self, text: &str) {
        // Trailing whitespace is ignored (and doesn't hide a sentence end).
        let text = text.trim_end_matches([' ', '\t']);
        // `\c`: the next line continues this one without a space.
        let cont = text.ends_with(mark::CONT);
        let text = text.trim_end_matches(mark::CONT);
        if cont {
            let mut n = Node::text(text, self.line);
            n.flags.line_start = true;
            self.push(n);
            self.nospace = true;
            return;
        }
        let mut n = Node::text(text, self.line);
        n.flags.line_start = true;
        n.flags.eos = ends_sentence(text);
        // A text line inside an `.It` head of a tag list with no head yet is body text.
        self.push(n);
    }

    fn macro_line(&mut self, name: &str, args: &[String], _first: bool) {
        match name {
            "Dd" => {
                self.meta.date = args.join(" ");

            }
            "Dt" => {
                self.meta.title = args.first().cloned().unwrap_or_default();
                self.meta.section = args.get(1).cloned().unwrap_or_default();
                self.meta.arch = args.get(2).cloned().unwrap_or_default();
            }
            "Os" => {
                self.meta.os_given = true;
                self.meta.os = args.join(" ");
            }
            "Sh" | "Ss" => {
                if name == "Sh" {
                    while self.stack.len() > 1 {
                        self.close_top();
                    }
                    self.in_synopsis = args.join(" ") == "SYNOPSIS";
                } else if let Some(pos) = self.open_block_tok("Sh") {
                    while self.stack.len() > pos + 2 {
                        self.close_top();
                    }
                }
                self.open(Kind::Block, name);
                self.open(Kind::Head, name);
                self.words(args, None);
                self.close_top();
                self.open(Kind::Body, name);
                self.nospace = false;
            }
            "Pp" | "Lp" => {
                self.close_synopsis_nm();
                self.push(Node::new(Kind::Elem, "Pp", self.line));
            }
            "Nd" => {
                self.open(Kind::Block, "Nd");
                self.open(Kind::Body, "Nd");
                self.words(args, None);
            }
            "Nm" if self.in_synopsis && self.stack.last().is_some_and(|t| t.kind == Kind::Body && (t.tok == "Sh" || t.tok == "Ss" || t.tok == "Nm")) => {
                // In SYNOPSIS, .Nm starts a block: its body hangs after the name.
                self.close_synopsis_nm();
                if self.meta.name.is_empty() && !args.is_empty() {
                    self.meta.name = args[0].clone();
                }
                // The head holds the whole line, the body the lines after it.
                self.open(Kind::Block, "Nm");
                self.open(Kind::Head, "Nm");
                self.words(&prepend("Nm", args), None);
                self.close_top();
                self.open(Kind::Body, "Nm");
            }
            "Bl" | "Bd" | "Bf" | "Bk" | "Rs" => {
                self.close_synopsis_nm_if(name == "Bl" || name == "Bd");
                self.open(Kind::Block, name);
                self.stack.last_mut().unwrap().args = args.to_vec();
                self.open(Kind::Body, name);
            }
            "El" | "Ed" | "Ef" | "Ek" | "Re" => {
                let open = FULL_EXPLICIT.iter().find(|(_, c)| *c == name).unwrap().0;
                if !self.close_block(open) {
                    self.diag.report(Level::Error, self.line, 0, "skipping end of block that is not open", name);
                }
            }
            "It" => self.item(args),
            "D1" | "Dl" => {
                self.open(Kind::Block, name);
                self.open(Kind::Body, name);
                self.words(args, None);
                self.close_top();
                self.close_top();
            }
            "Sm" => {
                self.spacing_off = match args.first().map(String::as_str) {
                    Some("off") => true,
                    Some("on") => false,
                    _ => !self.spacing_off,
                };
            }
            "Db" => {}
            "An" if args.first().is_some_and(|a| a == "-split" || a == "-nosplit") => {
                let mut n = Node::new(Kind::Elem, "An", self.line);
                n.args = vec![args[0].clone()];
                self.push(n);
            }
            "In" | "Lb" | "Rv" | "Ex" => {
                self.special_elem(name, args);
            }
            "Hf" | "Ot" | "Fr" | "Bt" | "Ud" | "Fd" | "Cd" | "An" => {
                // The element takes its words; a callable macro after them runs as usual.
                let used = self.inline_elem(name, args);
                self.words(&args[used..], None);
            }
            "br" | "sp" => self.push(Node::new(Kind::Elem, name, self.line)),
            _ if name.starts_with('%') && !self.stack.iter().any(|n| n.kind == Kind::Block && n.tok == "Rs") => {
                // A reference field outside `.Rs`: an in-line macro like any other.
                let used = self.inline_elem(name, args);
                self.words(&args[used..], None);
            }
            _ if name.starts_with('%') => {
                self.open(Kind::Elem, name);
                for a in args {
                    self.push(Node::text(a, self.line));
                }
                self.close_top();
            }
            _ if is_callable(name) || PARTIAL_EXPLICIT.iter().any(|(o, ..)| *o == name) || matches!(name, "Fn" | "Fo" | "Fc" | "St" | "Lk") => {
                self.words(&prepend(name, args), None);
            }
            _ => {
                self.trailing = None;
                // Each unknown macro is reported once, as mandoc does.
                if !self.unknown.iter().any(|u| u == name) {
                    self.unknown.push(name.to_string());
                    self.diag.report(Level::Error, self.line, self.col, "skipping unknown macro", &format!(".{}", self.raw));
                }
            }
        }
    }

    /// Ends an open SYNOPSIS `.Nm` block (another `.Nm`, `.Pp` or a display follows).
    fn close_synopsis_nm(&mut self) {
        self.close_synopsis_nm_if(true);
    }

    fn close_synopsis_nm_if(&mut self, yes: bool) {
        if yes && self.stack.last().is_some_and(|t| t.kind == Kind::Body && t.tok == "Nm") {
            self.close_top();
            self.close_top();
        }
    }

    fn item(&mut self, args: &[String]) {
        let Some(bl) = self.open_block_tok("Bl") else {
            self.diag.report(Level::Error, self.line, 0, "It outside of list", "");
            return;
        };
        // Close the previous item.
        while self.stack.len() > bl + 2 {
            self.close_top();
        }
        let ltype = list_type(&self.stack[bl].args).to_string();
        let ltype = ltype.as_str();
        self.open(Kind::Block, "It");
        match ltype {
            "-column" => {
                // Cells are separated by `Ta` or tabs.
                let mut cells: Vec<Vec<String>> = vec![Vec::new()];
                for a in args {
                    if a == "Ta" {
                        cells.push(Vec::new());
                    } else {
                        let parts: Vec<&str> = a.split('\t').collect();
                        for (i, part) in parts.iter().enumerate() {
                            if i > 0 {
                                cells.push(Vec::new());
                            }
                            if !part.is_empty() {
                                cells.last_mut().unwrap().push(part.to_string());
                            }
                        }
                    }
                }
                let n = cells.len();
                for (i, c) in cells.into_iter().enumerate() {
                    self.open(Kind::Body, "Ta");
                    self.words(&c, None);
                    if i + 1 < n {
                        self.close_top();
                    }
                }
            }
            "-bullet" | "-dash" | "-hyphen" | "-enum" | "-item" => {
                self.open(Kind::Body, "It");
                if !args.is_empty() {
                    self.diag.report(Level::Warning, self.line, 0, "skipping It arguments", ltype);
                }
            }
            _ => {
                self.open(Kind::Head, "It");
                self.words(args, None);
                // A head extended with `.Xo` stays open until its `.Xc`.
                self.end_item_head();
            }
        }
        self.nospace = false;
    }

    /// Closes an `.It` head and opens its body, unless an `.Xo` in the head is still open.
    fn end_item_head(&mut self) {
        if self.stack.last().is_some_and(|t| t.kind == Kind::Head && t.tok == "It") {
            self.close_top();
            self.open(Kind::Body, "It");
        }
    }

    /// Parses a line's arguments as words and callable macros into the current node. `in_elem`
    /// is the in-line macro whose arguments these are, if any.
    fn words(&mut self, args: &[String], in_elem: Option<&str>) {
        let _ = in_elem;
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if is_callable(a) || PARTIAL_EXPLICIT.iter().any(|(o, c, ..)| o == a || c == a) || matches!(a.as_str(), "Fn" | "St" | "Lk" | "Fc") {
                i = self.call(a, &args[i + 1..]) + i + 1;
                continue;
            }
            self.plain_word(a, i + 1 == args.len());
            i += 1;
        }
    }

    /// A word outside any in-line macro; `last` if it ends the input line.
    fn plain_word(&mut self, a: &str, last: bool) {
        let mut n = Node::text(a, self.line);
        if is_delim(a) {
            n.flags.delim = true;
            if is_delim_close(a) {
                n.flags.nospace = true;
            }
        }
        // On a macro line, only a final closing delimiter (`.Ev PATH .`) ends a sentence.
        n.flags.eos = last && is_delim_close(a) && ends_sentence(a);
        if self.spacing_off {
            n.flags.nospace = true;
        }
        let open = is_delim_open(a);
        self.push(n);
        if open {
            self.nospace = true;
        }
    }

    /// Runs macro `name` with the words `rest` that follow it. Returns how many words it used.
    fn call(&mut self, name: &str, rest: &[String]) -> usize {
        if let Some(&(_, open, close)) = PARTIAL_IMPLICIT.iter().find(|(t, ..)| *t == name) {
            // Leading opening delimiters go before it; the rest of the line, less trailing
            // closing delimiters, goes inside.
            let mut start = 0;
            while start < rest.len() && is_delim_open(&rest[start]) {
                self.plain_word(&rest[start], false);
                start += 1;
            }
            let rest = &rest[start..];
            let mut end = rest.len();
            while end > 0 && is_delim_close(&rest[end - 1]) {
                end -= 1;
            }
            self.open(Kind::Block, name);
            let b = self.stack.last_mut().unwrap();
            b.args = vec![open.to_string(), close.to_string()];
            self.open(Kind::Body, name);
            self.words(&rest[..end], None);
            self.close_top();
            self.close_top();
            for (k, d) in rest[end..].iter().enumerate() {
                self.plain_word(d, end + k + 1 == rest.len());
            }
            return start + rest.len();
        }
        if let Some(&(open_tok, close_tok, open, close)) = PARTIAL_EXPLICIT.iter().find(|(o, c, ..)| *o == name || *c == name) {
            if name == open_tok {
                self.open(Kind::Block, name);
                let b = self.stack.last_mut().unwrap();
                b.args = vec![open.to_string(), close.to_string()];
                if name == "Fo" || name == "Eo" {
                    // `.Fo name`: the function name; `.Eo x`: the opening text.
                    let first = rest.first().cloned().unwrap_or_default();
                    b.text = first;
                    self.open(Kind::Body, name);
                    return rest.len().min(1) + self.words_count(&rest[rest.len().min(1)..]);
                }
                self.open(Kind::Body, name);
                self.nospace = true;
                return self.words_count(rest);
            }
            // The closing macro.
            if self.open_block_tok(open_tok).is_some() {
                let at = self.open_block_tok(open_tok).unwrap();
                if name == "Ec" {
                    self.stack[at].args[1] = rest.first().cloned().unwrap_or_default();
                }
                while self.stack.len() > at {
                    self.close_top();
                }
            } else {
                self.diag.report(Level::Error, self.line, 0, "skipping end of block that is not open", close_tok);
            }
            if name == "Ec" {
                return rest.len().min(1) + self.words_count(&rest[rest.len().min(1)..]);
            }
            return self.words_count(rest);
        }
        match name {
            "Ns" => {
                self.nospace = true;
                self.words_count(rest)
            }
            "Ap" => {
                let mut n = Node::text("'", self.line);
                n.flags.nospace = true;
                self.nospace = false;
                self.stack.last_mut().unwrap().children.push(n);
                self.nospace = true;
                self.words_count(rest)
            }
            "Pf" => {
                // `.Pf prefix Macro ...`: the prefix, then no space.
                if let Some(p) = rest.first() {
                    self.push(Node::text(p, self.line));
                    self.nospace = true;
                    1 + self.words_count(&rest[1..])
                } else {
                    0
                }
            }
            "Ta" => {
                // A column separator inside `.It` of a column list: start the next cell.
                if self.stack.last().is_some_and(|t| t.kind == Kind::Body && t.tok == "Ta") {
                    self.close_top();
                    self.open(Kind::Body, "Ta");
                }
                self.words_count(rest)
            }
            "Xr" | "Fn" | "Lk" | "Mt" | "St" | "At" | "Bx" | "Bsx" | "Dx" | "Fx" | "Nx" | "Ox" | "Ux" | "In" => self.special_elem(name, rest),
            _ => self.inline_elem(name, rest),
        }
    }

    fn words_count(&mut self, rest: &[String]) -> usize {
        self.words(rest, None);
        rest.len()
    }

    /// An in-line macro: its arguments up to the next callable macro, with delimiters split off.
    fn inline_elem(&mut self, name: &str, rest: &[String]) -> usize {
        if name == "Nm" && self.meta.name.is_empty()
            && let Some(first) = rest.first().filter(|a| !is_delim(a) && !is_callable(a))
        {
            self.meta.name = first.clone();
        }
        let mut i = 0;
        // Leading opening delimiters print before the element.
        while i < rest.len() && is_delim_open(&rest[i]) {
            self.plain_word(&rest[i], false);
            i += 1;
        }
        let mut open = false;
        let mut produced = false;
        let mut defaulted = false;
        let start_elem = |p: &mut Parser, open: &mut bool| {
            if !*open {
                p.open(Kind::Elem, name);
                *open = true;
            }
        };
        while i < rest.len() {
            let a = &rest[i];
            if is_callable(a) || PARTIAL_EXPLICIT.iter().any(|(o, c, ..)| o == a || c == a) || matches!(a.as_str(), "Fn" | "St" | "Lk" | "Fc") {
                break;
            }
            if is_delim(a) && !a.contains(mark::ZERO) {
                // A delimiter: close the element; a middle delimiter reopens it after, unless the
                // element printed its default (`.Nm , text`), when the rest is plain text.
                if !produced && !open {
                    self.default_content(name);
                    produced = true;
                    defaulted = true;
                }
                if open {
                    self.close_top();
                    open = false;
                }
                self.plain_word(a, i + 1 == rest.len());
                i += 1;
                // Only delimiters left (or a macro): they all stay outside.
                continue;
            }
            if defaulted {
                self.plain_word(a, i + 1 == rest.len());
                i += 1;
                continue;
            }
            start_elem(self, &mut open);
            let mut n = Node::text(a, self.line);
            if self.spacing_off {
                n.flags.nospace = true;
            }
            self.push(n);
            produced = true;
            i += 1;
        }
        if open {
            self.close_top();
        } else if !produced {
            self.default_content(name);
            // `.Fl Fl variables`: an empty flag attaches to what follows.
            if name == "Fl" && i < rest.len() {
                self.nospace = true;
            }
        }
        i
    }

    /// An element with no arguments: some macros print a default.
    fn default_content(&mut self, name: &str) {
        let text = match name {
            "Ar" => "file ...".to_string(),
            "Nm" => self.meta.name.clone(),
            "Pa" => "~".to_string(),
            "Fl" => String::new(),
            _ => {
                if !matches!(name, "Fl" | "Li" | "No") {
                    self.diag.report(Level::Warning, self.line, 0, "macro requires an argument", name);
                }
                return;
            }
        };
        self.open(Kind::Elem, name);
        self.push(Node::text(&text, self.line));
        self.close_top();
    }

    /// Macros whose arguments form one formatted unit.
    fn special_elem(&mut self, name: &str, rest: &[String]) -> usize {
        // Their own arguments end at the first delimiter or callable macro.
        // `.Fn`'s first argument is the function's name, whatever it looks like.
        let mut end = if name == "Fn" && !rest.is_empty() { 1 } else { 0 };
        while end < rest.len() && !is_delim(&rest[end]) && !is_callable(&rest[end]) {
            end += 1;
        }
        let take = match name {
            "Xr" => end.min(2),
            "In" | "Lb" => end.min(1),
            "Rv" | "Ex" => end,
            "Lk" | "Mt" | "Fn" | "St" | "At" | "Bx" | "Bsx" | "Dx" | "Fx" | "Nx" | "Ox" | "Ux" => end,
            _ => end,
        };
        let mut n = Node::new(Kind::Elem, name, self.line);
        n.args = rest[..take].to_vec();
        if self.nospace {
            n.flags.nospace = true;
            self.nospace = false;
        }
        self.stack.last_mut().unwrap().children.push(n);
        take + self.words_count(&rest[take..])
    }
}

fn prepend(name: &str, args: &[String]) -> Vec<String> {
    let mut v = vec![name.to_string()];
    v.extend_from_slice(args);
    v
}

/// A list's type option (`-tag`, `-bullet`...), `-item` by default.
pub fn list_type(args: &[String]) -> &str {
    args.iter()
        .map(String::as_str)
        .find(|a| matches!(*a, "-bullet" | "-dash" | "-hyphen" | "-enum" | "-item" | "-tag" | "-diag" | "-hang" | "-ohang" | "-inset" | "-column"))
        .unwrap_or("-item")
}

/// A block option's value (`-width Ds`, `-offset indent`).
pub fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
