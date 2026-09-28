//! The eqn preprocessor's language (MAN.md §4.5): an equation between `.EQ` and `.EN`, or
//! between the delimiters a `delim` statement set, parsed into a tree of boxes that renderers
//! set as linear text (`eqn_term`) or MathML (`eqn_html`).
//!
//! The grammar is the Second Edition eqn language as eqn(7) describes it. Where mandoc's
//! behavior differs from that page, it is followed, since it is what pages are checked against:
//! `sqrt` and the font keywords take one box; `sub` and `sup` bind tightest and group to the
//! right; `over` groups to the left and takes a `sub`/`sup` expression on its right;
//! `from`/`to` group to the right and take anything but `over` on their right; `sup` right after
//! a `sub` (and `to` after `from`) sets both on the same box.

use std::collections::HashMap;

use crate::diag::{Diagnostics, Level};

/// State that lasts from one equation to the next in a document: definitions and delimiters.
#[derive(Default)]
pub struct State {
    defs: HashMap<String, String>,
    /// The in-line delimiters `delim` set.
    pub delim: Option<(char, char)>,
    /// `delim off` suspends them.
    pub delim_off: bool,
}

impl State {
    /// The in-line delimiters in effect, if any.
    pub fn delims(&self) -> Option<(char, char)> {
        self.delim.filter(|_| !self.delim_off)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Font {
    Roman,
    Italic,
    Bold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A word, `text` set.
    Text,
    /// A sequence of boxes: braces, a split word, a pile's row, `left`/`right`.
    List,
    /// `pile` family (or a matrix column): rows one above the other.
    Pile(Align),
    /// `matrix`: its columns (piles) and anything else its braces held.
    Matrix,
    Sub,
    Sup,
    /// `x sub i sup 2`: base, subscript, superscript.
    SubSup,
    From,
    To,
    /// `sum from a to b`: base, lower limit, upper limit.
    FromTo,
    Over,
    Sqrt,
    /// Diacritical marks (`marks`) over a box other than a word; a word carries its own.
    Mark,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Center,
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EBox {
    pub kind: Kind,
    /// A word's text, escapes decoded.
    pub text: String,
    /// A word as typed, which decides its spacing (first and last characters).
    pub raw: String,
    /// The font a word gets unless an enclosing font keyword says otherwise.
    pub auto_font: Font,
    /// The font a font keyword set on this box, which its contents take.
    pub font: Option<Font>,
    pub children: Vec<EBox>,
    /// The list came from braces.
    pub braced: bool,
    /// The list is one word split at its character classes, as an operand.
    pub split: bool,
    /// `left`/`right` delimiters, decoded; `right` defaults to `)`.
    pub left: Option<String>,
    pub right: Option<String>,
    /// Mark keywords (`dot`, `bar`...), in order.
    pub marks: Vec<String>,
    /// A pile's row, or a `left` body: a list set without delimiters unless it has other than one
    /// box.
    pub row: bool,
    /// A word that is a special character (a glyph name or an escape): it isn't italic, and
    /// spacing treats it as an escape.
    pub glyph: bool,
    /// A function name (`sin`, `log`...), always set in roman.
    pub func: bool,
}

impl EBox {
    pub fn new(kind: Kind) -> EBox {
        EBox { kind, text: String::new(), raw: String::new(), auto_font: Font::Roman, font: None, children: Vec::new(), braced: false, split: false, left: None, right: None, marks: Vec::new(), row: false, glyph: false, func: false }
    }

    fn text(raw: &str, text: String, auto_font: Font) -> EBox {
        let mut b = EBox::new(Kind::Text);
        b.raw = raw.to_string();
        b.text = text;
        b.auto_font = auto_font;
        b
    }

    fn list(children: Vec<EBox>) -> EBox {
        let mut b = EBox::new(Kind::List);
        b.children = children;
        b
    }

    /// Whether this is a binary positioning operation (`sub`, `over`, `from`...).
    pub fn is_pos(&self) -> bool {
        matches!(self.kind, Kind::Sub | Kind::Sup | Kind::SubSup | Kind::From | Kind::To | Kind::FromTo | Kind::Over)
    }

    /// A tree dump for `-T tree`.
    pub fn dump(&self, depth: usize, out: &mut String) {
        let pad = "    ".repeat(depth);
        let mut attrs = String::new();
        if let Some(f) = self.font {
            attrs.push_str(&format!(" font={f:?}"));
        }
        if !self.marks.is_empty() {
            attrs.push_str(&format!(" marks={:?}", self.marks));
        }
        if let Some(l) = &self.left {
            attrs.push_str(&format!(" left={l:?}"));
        }
        if let Some(r) = &self.right {
            attrs.push_str(&format!(" right={r:?}"));
        }
        if self.braced {
            attrs.push_str(" braced");
        }
        match self.kind {
            Kind::Text => out.push_str(&format!("{pad}{:?} ({:?}){attrs}\n", self.text, self.auto_font)),
            k => out.push_str(&format!("{pad}{k:?}{attrs}\n")),
        }
        for c in &self.children {
            c.dump(depth + 1, out);
        }
    }
}

/// One equation.
#[derive(Clone, Debug, PartialEq)]
pub struct Eqn {
    pub root: EBox,
    pub line: usize,
}

/// Names set as special characters, and the roff character each stands for.
const GLYPHS: &[(&str, &str)] = &[
    ("alpha", "*a"), ("beta", "*b"), ("chi", "*x"), ("delta", "*d"), ("epsilon", "*e"), ("eta", "*y"), ("gamma", "*g"), ("iota", "*i"), ("kappa", "*k"), ("lambda", "*l"), ("mu", "*m"), ("nu", "*n"), ("omega", "*w"), ("omicron", "*o"), ("phi", "*f"), ("pi", "*p"), ("psi", "*q"), ("rho", "*r"), ("sigma", "*s"), ("tau", "*t"), ("theta", "*h"), ("upsilon", "*u"), ("xi", "*c"), ("zeta", "*z"),
    ("DELTA", "*D"), ("GAMMA", "*G"), ("LAMBDA", "*L"), ("OMEGA", "*W"), ("PHI", "*F"), ("PI", "*P"), ("PSI", "*Q"), ("SIGMA", "*S"), ("THETA", "*H"), ("UPSILON", "*U"), ("XI", "*C"),
    ("inter", "ca"), ("union", "cu"), ("prod", "product"), ("int", "integral"), ("sum", "sum"), ("grad", "gr"), ("del", "gr"), ("times", "mu"), ("cdot", "pc"), ("approx", "~~"), ("prime", "fm"), ("half", "12"), ("partial", "pd"), ("inf", "if"),
    (">>", ">>"), ("<<", "<<"), ("<-", "<-"), ("->", "->"), ("+-", "+-"), ("!=", "!="), ("==", "=="), ("<=", "<="), (">=", ">="),
];

/// Words set in roman rather than italic.
const FUNCTIONS: &[&str] = &["Im", "Re", "and", "arc", "atan", "cos", "cosh", "coth", "csc", "det", "exp", "for", "if", "lim", "ln", "log", "max", "min", "sec", "sin", "sinh", "tan", "tanh"];

/// Mark keywords and the roff character each draws.
pub const MARKS: &[(&str, &str)] = &[("dot", "a."), ("dotdot", "ad"), ("hat", "a^"), ("tilde", "a~"), ("vec", "->"), ("dyad", "<>"), ("bar", "rn"), ("under", "ul")];

/// A glyph name's special character, if `word` is one; `nothing` is zero-width.
fn glyph(word: &str) -> Option<String> {
    if word == "nothing" {
        return Some(crate::roff::mark::ZERO.to_string());
    }
    let name = GLYPHS.iter().find(|(n, _)| *n == word)?.1;
    crate::chars::lookup(name).map(|(u, _)| u.to_string())
}

/// The roff character `name`'s text.
pub fn char_text(name: &str) -> String {
    crate::chars::lookup(name).map(|(u, _)| u.to_string()).unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq)]
struct Token {
    text: String,
    quoted: bool,
}

/// Binary positioning keywords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pos {
    Sub,
    Sup,
    Over,
    From,
    To,
}

impl Pos {
    fn from(s: &str) -> Option<Pos> {
        Some(match s {
            "sub" => Pos::Sub,
            "sup" => Pos::Sup,
            "over" => Pos::Over,
            "from" => Pos::From,
            "to" => Pos::To,
            _ => return None,
        })
    }

    /// The operations that continue this one's right operand (the rest end it).
    fn continues(self, next: Pos) -> bool {
        match self {
            Pos::Sub => next == Pos::Sub,
            Pos::Sup | Pos::Over => matches!(next, Pos::Sub | Pos::Sup),
            Pos::From => matches!(next, Pos::Sub | Pos::Sup | Pos::From),
            Pos::To => next != Pos::Over,
        }
    }
}

/// What ended a list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Eof,
    Brace,
    Above,
    Right,
    /// A `from` or `to` climbing out to the nearest enclosing `sub`, `sup`, `over` or `sqrt`
    /// (`Parser::climb`).
    Climb,
}

/// What may end the list being read.
#[derive(Clone, Copy, Default)]
struct Ctx {
    brace: bool,
    above: bool,
    right: bool,
}

/// Input stack depth limit for definitions, so a self-referencing one can't hang.
const MAX_EXPANSIONS: usize = 1000;

struct Parser<'a> {
    /// Characters still to read, innermost expansion first.
    input: Vec<char>,
    pos: usize,
    peeked: Vec<Token>,
    state: &'a mut State,
    decode: &'a mut dyn FnMut(&str) -> String,
    diag: &'a mut Diagnostics,
    line: usize,
    expansions: usize,
    /// The input stack overflowed: the rest of the equation is dropped.
    dead: bool,
    /// Inside a font keyword's box: its words are set whole in this font.
    scope: Option<Font>,
    /// Operands of `sub`, `sup`, `over` and `sqrt` being read (reset inside `from` and `to`):
    /// a `from` or `to` met inside one of them, however deep in braces, applies to the
    /// innermost of those operations, the lists around it left unfinished, as mandoc does.
    op_depth: usize,
    /// The `from` or `to` climbing out, until the operation it applies to takes it.
    climb: Option<Pos>,
    /// Open braces (and `left` bodies, which a `}` also ends), and open piles: a `}` or an
    /// `above` outside them is skipped where it stands.
    braces: usize,
    piles: usize,
    lefts: usize,
}

/// Parses the text of one equation (its lines joined by newlines), starting on input line
/// `line`. `decode` expands roff escapes in a word.
pub fn parse(src: &str, line: usize, state: &mut State, decode: &mut dyn FnMut(&str) -> String, diag: &mut Diagnostics) -> Eqn {
    let mut p = Parser { input: src.chars().collect(), pos: 0, peeked: Vec::new(), state, decode, diag, line, expansions: 0, dead: false, scope: None, op_depth: 0, climb: None, braces: 0, piles: 0, lefts: 0 };
    let (children, _) = p.list(Ctx::default());
    Eqn { root: EBox::list(children), line }
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '^' | '~' | '\n')
}

impl Parser<'_> {
    fn report(&mut self, level: Level, message: &str, detail: &str) {
        self.diag.report(level, self.line, 2, message, detail);
    }

    /// Reads a raw token: a brace, a quoted string, or a run up to white space, a brace or a
    /// quote. Definitions are not expanded.
    fn raw_token(&mut self) -> Option<Token> {
        if let Some(t) = self.peeked.pop() {
            return Some(t);
        }
        if self.dead {
            return None;
        }
        while self.pos < self.input.len() && is_space(self.input[self.pos]) {
            self.pos += 1;
        }
        let c = *self.input.get(self.pos)?;
        if c == '{' || c == '}' {
            self.pos += 1;
            return Some(Token { text: c.to_string(), quoted: false });
        }
        if c == '"' {
            self.pos += 1;
            let mut s = String::new();
            loop {
                match self.input.get(self.pos) {
                    None => {
                        self.report(Level::Style, "unterminated quoted argument", "");
                        break;
                    }
                    Some('"') => {
                        self.pos += 1;
                        break;
                    }
                    Some('\\') if self.input.get(self.pos + 1) == Some(&'"') => {
                        s.push('"');
                        self.pos += 2;
                    }
                    Some(&c) => {
                        s.push(c);
                        self.pos += 1;
                    }
                }
            }
            return Some(Token { text: s, quoted: true });
        }
        let mut s = String::new();
        while let Some(&c) = self.input.get(self.pos) {
            if is_space(c) || c == '{' || c == '}' || c == '"' {
                break;
            }
            s.push(c);
            self.pos += 1;
            // An escape is one unit: `\(xx`, `\[...]`, and the like, whatever they hold.
            if c == '\\' {
                let rest: String = self.input[self.pos..].iter().take(64).collect();
                let n = escape_rest_len(&rest);
                for _ in 0..n {
                    if let Some(&c) = self.input.get(self.pos) {
                        s.push(c);
                        self.pos += 1;
                    }
                }
            }
        }
        Some(Token { text: s, quoted: false })
    }

    /// The next token, with definitions expanded.
    fn token(&mut self) -> Option<Token> {
        loop {
            let t = self.raw_token()?;
            if t.quoted {
                return Some(t);
            }
            let Some(value) = self.state.defs.get(&t.text).cloned() else { return Some(t) };
            self.expansions += 1;
            if self.expansions > MAX_EXPANSIONS {
                self.report(Level::Error, "input stack limit exceeded, infinite loop?", "");
                self.dead = true;
                self.peeked.clear();
                return None;
            }
            // The value replaces the key in the input.
            let mut v: Vec<char> = value.chars().collect();
            v.push(' ');
            self.input.splice(self.pos..self.pos, v);
        }
    }

    fn peek(&mut self) -> Option<Token> {
        let t = self.token()?;
        self.peeked.push(t.clone());
        Some(t)
    }

    fn push_back(&mut self, t: Token) {
        self.peeked.push(t);
    }

    /// Reads a list of boxes up to what ends it in `ctx`.
    fn list(&mut self, ctx: Ctx) -> (Vec<EBox>, End) {
        let mut items: Vec<EBox> = Vec::new();
        loop {
            let Some(t) = self.token() else { return (items, End::Eof) };
            if !t.quoted {
                match t.text.as_str() {
                    "}" => {
                        if ctx.brace || ctx.right {
                            return (items, End::Brace);
                        }
                        self.report(Level::Error, "skipping end of block that is not open", "}");
                        continue;
                    }
                    "above" => {
                        if ctx.above {
                            return (items, End::Above);
                        }
                        // It ends everything up to the pile it separates rows of.
                        if self.piles > 0 {
                            self.push_back(t);
                            return (items, End::Above);
                        }
                        self.report(Level::Error, "skipping item outside list", "above");
                        continue;
                    }
                    "right" => {
                        if ctx.right {
                            return (items, End::Right);
                        }
                        // It ends everything up to its `left`.
                        if self.lefts > 0 {
                            self.push_back(t);
                            return (items, End::Right);
                        }
                        self.report(Level::Error, "skipping end of block that is not open", "right");
                        continue;
                    }
                    w => {
                        if let Some(pos) = Pos::from(w) {
                            if matches!(pos, Pos::From | Pos::To) && self.op_depth > 0 && !items.last().is_some_and(is_op) {
                                self.climb = Some(pos);
                                return (items, End::Climb);
                            }
                            let left = match items.pop() {
                                Some(b) => b,
                                None => {
                                    self.report(Level::Warning, "missing eqn box, using \"\"", w);
                                    EBox::text("", String::new(), Font::Roman)
                                }
                            };
                            let b = self.operation(left, pos);
                            items.push(b);
                            continue;
                        }
                        if MARKS.iter().any(|(m, _)| *m == w) {
                            match items.pop() {
                                Some(b) => items.push(add_mark(b, w)),
                                None => self.report(Level::Warning, "missing eqn box, using \"\"", w),
                            }
                            continue;
                        }
                    }
                }
            }
            self.push_back(t);
            match self.primary(false) {
                Primary::Boxes(bs) => items.extend(bs),
                Primary::None => {}
                Primary::Stop => {
                    // A token that ends lists but not this one was left; drop it.
                    let _ = self.token();
                }
            }
            if self.climb.is_some() {
                return (items, End::Climb);
            }
        }
    }

    /// Skips tokens that end lists where no list they could end is open, reporting them.
    fn skip_stray(&mut self) {
        while let Some(t) = self.peek() {
            let stray = !t.quoted
                && match t.text.as_str() {
                    "}" => self.braces == 0 && self.lefts == 0,
                    "above" => self.piles == 0,
                    "right" => self.lefts == 0,
                    _ => false,
                };
            if !stray {
                break;
            }
            self.token();
            let msg = if t.text == "above" { "skipping item outside list" } else { "skipping end of block that is not open" };
            self.report(Level::Error, msg, &t.text);
        }
    }

    /// Completes `left pos ...`: reads the right operand and any operations that continue it.
    fn operation(&mut self, left: EBox, pos: Pos) -> EBox {
        let saved = self.op_depth;
        if !matches!(pos, Pos::From | Pos::To) {
            self.op_depth += 1;
        }
        let right = self.operand(pos);
        self.op_depth = saved;
        let b = combine(left, pos, right);
        self.resolve_climb(b)
    }

    /// Applies a climbing `from` or `to` to box `b`, the operation it climbed to.
    fn resolve_climb(&mut self, b: EBox) -> EBox {
        let Some(p) = self.climb.take() else { return b };
        let mut b = self.operation(b, p);
        // `to` after the `from` (or `sup` after a `sub`) pairs with it.
        while self.climb.is_none()
            && let Some(t) = self.peek()
        {
            match (b.kind, Pos::from(&t.text).filter(|_| !t.quoted)) {
                (Kind::From, Some(Pos::To)) | (Kind::Sub, Some(Pos::Sup)) if b.children.len() == 2 => {
                    self.token();
                    let pos = if b.kind == Kind::From { Pos::To } else { Pos::Sup };
                    b = self.operation(b, pos);
                }
                _ => break,
            }
        }
        b
    }

    /// Reads the right operand of `pos`.
    fn operand(&mut self, pos: Pos) -> Option<EBox> {
        let mut b = self.one_box()?;
        loop {
            if self.climb.is_some() {
                break;
            }
            self.skip_stray();
            let Some(t) = self.peek() else { break };
            let next = if t.quoted { None } else { Pos::from(&t.text) };
            match next {
                Some(n) if pos.continues(n) => {
                    self.token();
                    b = self.operation(b, n);
                }
                // `sup` after a `sub` just completed, however deep, pairs with it.
                Some(Pos::Sup) if b.kind == Kind::Sub && b.children.len() == 2 => {
                    self.token();
                    b = self.operation(b, Pos::Sup);
                }
                Some(Pos::To) if b.kind == Kind::From && b.children.len() == 2 => {
                    self.token();
                    b = self.operation(b, Pos::To);
                }
                // A `from` or `to` goes with the operation just completed, however deep.
                Some(n @ (Pos::From | Pos::To)) if is_op(&b) => {
                    self.token();
                    b = self.operation(b, n);
                }
                _ => break,
            }
        }
        Some(b)
    }

    /// Reads one box and the marks after it, a split word becoming one list.
    fn one_box(&mut self) -> Option<EBox> {
        let b = match self.primary(true) {
            Primary::Boxes(mut bs) => {
                if bs.len() == 1 {
                    bs.pop().unwrap()
                } else {
                    let mut l = EBox::list(bs);
                    l.split = true;
                    l
                }
            }
            _ => return None,
        };
        self.marks_on(b)
    }

    /// Puts the marks that follow on box `b`.
    fn marks_on(&mut self, mut b: EBox) -> Option<EBox> {
        while self.climb.is_none()
            && {
                self.skip_stray();
                true
            }
            && let Some(t) = self.peek()
        {
            if !t.quoted && MARKS.iter().any(|(m, _)| *m == t.text) {
                self.token();
                b = add_mark(b, &t.text);
            } else {
                break;
            }
        }
        Some(b)
    }

    /// Reads a primary box. `operand`: the box is an operand, so it is one box (a split word
    /// is returned as its pieces, for the caller to group).
    fn primary(&mut self, operand: bool) -> Primary {
        loop {
            let Some(t) = self.token() else { return Primary::Stop };
            if t.quoted {
                let text = (self.decode)(&t.text);
                if t.text.is_empty() {
                    return Primary::Boxes(vec![EBox::text("", String::new(), Font::Roman)]);
                }
                let mut b = EBox::text(&t.text, text, Font::Italic);
                b.font = self.scope;
                return Primary::Boxes(vec![b]);
            }
            match t.text.as_str() {
                "}" | "above" | "right" => {
                    self.push_back(t);
                    return Primary::Stop;
                }
                w if Pos::from(w).is_some() || MARKS.iter().any(|(m, _)| *m == w) => {
                    // An operation with no left operand where a box was expected: the caller's
                    // list takes it.
                    self.push_back(t);
                    return if operand { Primary::Stop } else { Primary::None };
                }
                "{" => {
                    self.braces += 1;
                    let (children, _) = self.list(Ctx { brace: true, ..Ctx::default() });
                    self.braces -= 1;
                    let mut b = EBox::list(children);
                    b.braced = true;
                    return Primary::Boxes(vec![b]);
                }
                "define" | "ndefine" | "tdefine" => {
                    self.define(&t.text);
                    continue;
                }
                "undef" => {
                    match self.raw_token() {
                        Some(k) => {
                            self.state.defs.remove(&k.text);
                        }
                        None => self.report(Level::Warning, "skipping empty request", "undef"),
                    }
                    continue;
                }
                "delim" => {
                    match self.raw_token() {
                        Some(d) if d.text == "off" => self.state.delim_off = true,
                        Some(d) if d.text == "on" => self.state.delim_off = false,
                        Some(d) if d.text.chars().count() >= 2 => {
                            let mut cs = d.text.chars();
                            self.state.delim = Some((cs.next().unwrap(), cs.next().unwrap()));
                            self.state.delim_off = false;
                        }
                        _ => self.report(Level::Warning, "skipping empty request", "delim"),
                    }
                    continue;
                }
                "gfont" | "gsize" | "back" | "fwd" | "up" | "down" => {
                    if self.token().is_none() {
                        self.report(Level::Warning, "skipping empty request", &t.text);
                    }
                    continue;
                }
                "mark" | "lineup" => continue,
                "sqrt" => {
                    let mut b = EBox::new(Kind::Sqrt);
                    self.op_depth += 1;
                    let c = self.one_box();
                    self.op_depth -= 1;
                    if let Some(c) = c {
                        b.children.push(c);
                    }
                    let b = self.resolve_climb(b);
                    return Primary::Boxes(vec![b]);
                }
                "roman" | "italic" | "bold" | "fat" => {
                    let font = match t.text.as_str() {
                        "roman" => Font::Roman,
                        "italic" => Font::Italic,
                        _ => Font::Bold,
                    };
                    // The box goes in a group of its own that carries the font; a word's marks go
                    // on the word, inside it, anything else's on the group.
                    let saved = self.scope.replace(font);
                    let b = match self.primary(true) {
                        Primary::Boxes(bs) => Some(if bs.len() == 1 { bs.into_iter().next().unwrap() } else { EBox::list(bs) }),
                        _ => None,
                    };
                    let b = match b {
                        Some(b) if b.kind == Kind::Text => self.marks_on(b),
                        b => b,
                    };
                    self.scope = saved;
                    return match b {
                        Some(b) => {
                            let mut g = EBox::list(vec![b]);
                            g.font = Some(font);
                            Primary::Boxes(vec![g])
                        }
                        None => Primary::None,
                    };
                }
                "size" => {
                    if self.token().is_none() {
                        self.report(Level::Warning, "skipping empty request", "size");
                        return Primary::None;
                    }
                    return match self.one_box() {
                        Some(b) => Primary::Boxes(vec![EBox::list(vec![b])]),
                        None => Primary::None,
                    };
                }
                "pile" | "lpile" | "cpile" | "rpile" | "lcol" | "ccol" | "rcol" => {
                    let align = match t.text.as_bytes()[0] {
                        b'l' => Align::Left,
                        b'r' => Align::Right,
                        _ => Align::Center,
                    };
                    match self.peek() {
                        Some(n) if !n.quoted && n.text == "{" => {
                            self.token();
                        }
                        _ => continue,
                    }
                    let mut b = EBox::new(Kind::Pile(align));
                    self.braces += 1;
                    self.piles += 1;
                    loop {
                        let (children, end) = self.list(Ctx { brace: true, above: true, ..Ctx::default() });
                        let mut row = EBox::list(children);
                        row.row = true;
                        b.children.push(row);
                        if end != End::Above {
                            break;
                        }
                    }
                    self.braces -= 1;
                    self.piles -= 1;
                    return Primary::Boxes(vec![b]);
                }
                "matrix" => {
                    match self.peek() {
                        Some(n) if !n.quoted && n.text == "{" => {
                            self.token();
                        }
                        _ => continue,
                    }
                    self.braces += 1;
                    let (children, _) = self.list(Ctx { brace: true, ..Ctx::default() });
                    self.braces -= 1;
                    let mut b = EBox::new(Kind::Matrix);
                    b.children = children;
                    return Primary::Boxes(vec![b]);
                }
                "left" => {
                    let Some(d) = self.token() else {
                        self.report(Level::Warning, "skipping empty request", "left");
                        return Primary::None;
                    };
                    let left = (self.decode)(&d.text);
                    self.lefts += 1;
                    let (children, end) = self.list(Ctx { right: true, ..Ctx::default() });
                    self.lefts -= 1;
                    let mut b = EBox::list(children);
                    b.left = Some(left);
                    if end == End::Right {
                        match self.token() {
                            Some(r) => b.right = Some((self.decode)(&r.text)),
                            None => self.report(Level::Warning, "skipping empty request", "right"),
                        }
                    }
                    return Primary::Boxes(vec![b]);
                }
                _ => return Primary::Boxes(self.word(&t.text)),
            }
        }
    }

    /// `define key cvalc`: the first character of the value delimits it.
    fn define(&mut self, which: &str) {
        let Some(key) = self.raw_token() else {
            self.report(Level::Warning, "skipping empty request", which);
            return;
        };
        while self.pos < self.input.len() && is_space(self.input[self.pos]) {
            self.pos += 1;
        }
        let Some(&delim) = self.input.get(self.pos) else {
            self.report(Level::Warning, "skipping empty request", &format!("{which} {}", key.text));
            return;
        };
        self.pos += 1;
        let mut value = String::new();
        loop {
            match self.input.get(self.pos) {
                None => {
                    self.report(Level::Style, "unterminated quoted argument", "");
                    break;
                }
                Some(&c) if c == delim => {
                    self.pos += 1;
                    break;
                }
                Some(&c) => {
                    value.push(c);
                    self.pos += 1;
                }
            }
        }
        if which != "tdefine" {
            self.state.defs.insert(key.text, value);
        }
    }

    /// A word outside a font keyword: a glyph name, a function name, or text split at its
    /// character classes (letters italic).
    fn word(&mut self, w: &str) -> Vec<EBox> {
        if let Some(g) = glyph(w) {
            let mut b = EBox::text(&format!("\\[{w}]"), g, Font::Roman);
            b.glyph = true;
            b.font = self.scope;
            return vec![b];
        }
        if FUNCTIONS.contains(&w) {
            let mut b = EBox::text(w, (self.decode)(w), Font::Roman);
            b.func = true;
            b.font = self.scope;
            return vec![b];
        }
        // A minus sign on its own is one.
        if w == "-" {
            let mut b = EBox::text("\\[mi]", char_text("mi"), Font::Roman);
            b.font = self.scope;
            return vec![b];
        }
        if let Some(f) = self.scope {
            let mut b = EBox::text(w, (self.decode)(w), f);
            b.font = Some(f);
            return vec![b];
        }
        split(w)
            .into_iter()
            .map(|(piece, letters)| {
                let text = (self.decode)(&piece);
                let mut b = EBox::text(&piece, text, if letters { Font::Italic } else { Font::Roman });
                b.glyph = piece.starts_with('\\');
                b
            })
            .collect()
    }
}

enum Primary {
    Boxes(Vec<EBox>),
    /// Nothing (a statement).
    None,
    /// A token that ends a list, pushed back.
    Stop,
}

/// A `sub`, `sup` or `over` box: what a `from` or `to` right after it applies to.
fn is_op(b: &EBox) -> bool {
    matches!(b.kind, Kind::Sub | Kind::Sup | Kind::SubSup | Kind::Over)
}

/// Puts a mark on a box: a word or a mark box takes it; anything else is wrapped in a mark box.
fn add_mark(mut b: EBox, mark: &str) -> EBox {
    if matches!(b.kind, Kind::Text | Kind::Mark) {
        b.marks.push(mark.to_string());
        return b;
    }
    let mut m = EBox::new(Kind::Mark);
    m.children.push(b);
    m.marks.push(mark.to_string());
    m
}

fn combine(left: EBox, pos: Pos, right: Option<EBox>) -> EBox {
    // `x sub i sup 2`, `sum from a to b`: both on the same box.
    let pair = match (left.kind, pos) {
        (Kind::Sub, Pos::Sup) if left.children.len() == 2 => Some(Kind::SubSup),
        (Kind::From, Pos::To) if left.children.len() == 2 => Some(Kind::FromTo),
        _ => None,
    };
    if let (Some(kind), Some(r)) = (pair, right.as_ref()) {
        let mut b = left;
        b.kind = kind;
        b.children.push(r.clone());
        return b;
    }
    let mut b = EBox::new(match pos {
        Pos::Sub => Kind::Sub,
        Pos::Sup => Kind::Sup,
        Pos::Over => Kind::Over,
        Pos::From => Kind::From,
        Pos::To => Kind::To,
    });
    b.children.push(left);
    if let Some(r) = right {
        b.children.push(r);
    }
    b
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Letter,
    Digit,
    Punct,
}

/// Splits a word where its character class changes (letters, digits and a decimal point,
/// anything else), after a comma, and before an escape that follows a letter or digit; the
/// character right after an escape stays with it. Returns the pieces, each flagged if it holds
/// letters.
fn split(w: &str) -> Vec<(String, bool)> {
    let cs: Vec<char> = w.chars().collect();
    let mut out: Vec<(String, bool)> = Vec::new();
    let mut cur = String::new();
    let mut class: Option<Class> = None;
    let mut after_comma = false;
    let mut i = 0;
    let flush = |cur: &mut String, class: Option<Class>, out: &mut Vec<(String, bool)>| {
        if !cur.is_empty() {
            out.push((std::mem::take(cur), class == Some(Class::Letter)));
        }
    };
    while i < cs.len() {
        let c = cs[i];
        if c == '\\' {
            if after_comma || class.is_some_and(|k| k != Class::Punct) {
                flush(&mut cur, class, &mut out);
            }
            let rest: String = cs[i + 1..].iter().collect();
            let n = 1 + escape_rest_len(&rest);
            cur.extend(&cs[i..(i + n).min(cs.len())]);
            i += n;
            class = Some(Class::Punct);
            after_comma = false;
            // The character after an escape goes with it.
            if i < cs.len() && cs[i] != '\\' {
                cur.push(cs[i]);
                after_comma = cs[i] == ',';
                i += 1;
            }
            continue;
        }
        let k = if c.is_ascii_alphabetic() {
            Class::Letter
        } else if c.is_ascii_digit() || c == '.' && (class == Some(Class::Digit) || cs.get(i + 1).is_some_and(|n| n.is_ascii_digit())) {
            Class::Digit
        } else {
            Class::Punct
        };
        if after_comma || class.is_some_and(|p| p != k) {
            flush(&mut cur, class, &mut out);
        }
        cur.push(c);
        class = Some(k);
        after_comma = c == ',';
        i += 1;
    }
    flush(&mut cur, class, &mut out);
    out
}

/// The length of an escape after its backslash, in characters.
pub fn escape_rest_len(rest: &str) -> usize {
    let cs: Vec<char> = rest.chars().collect();
    let Some(&c) = cs.first() else { return 0 };
    // `\X(xx`, `\X[...]`, `\Xx`.
    let arg = |from: usize| -> usize {
        match cs.get(from) {
            None => 0,
            Some('(') => 3.min(cs.len() - from),
            Some('[') => cs[from..].iter().position(|&c| c == ']').map_or(cs.len() - from, |p| p + 1),
            Some(_) => 1,
        }
    };
    match c {
        '(' => 3.min(cs.len()),
        '[' => cs.iter().position(|&c| c == ']').map_or(cs.len(), |p| p + 1),
        '*' | 'f' | 'n' | 'F' | 'g' | 'k' | 'M' | 'm' | 'Y' | 'V' => 1 + arg(1),
        's' => {
            let mut j = 1;
            if matches!(cs.get(j), Some('+') | Some('-')) {
                j += 1;
            }
            match cs.get(j) {
                Some('(') => j + 3,
                Some('[') | Some('\'') => {
                    let close = if cs[j] == '[' { ']' } else { '\'' };
                    j + 1 + cs[j + 1..].iter().position(|&c| c == close).map_or(cs.len() - j - 1, |p| p + 1)
                }
                Some(d) if d.is_ascii_digit() => j + 1,
                _ => j,
            }
            .min(cs.len())
        }
        'A' | 'b' | 'B' | 'C' | 'D' | 'h' | 'H' | 'l' | 'L' | 'N' | 'o' | 'R' | 'S' | 'v' | 'w' | 'x' | 'X' | 'Z' => {
            match cs.get(1) {
                Some(&q) => 2 + cs[2..].iter().position(|&c| c == q).map_or(cs.len() - 2, |p| p + 1),
                None => 1,
            }
            .min(cs.len())
        }
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting() {
        let s = |w: &str| split(w).into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        assert_eq!(s("ab12cd"), ["ab", "12", "cd"]);
        assert_eq!(s("a.b"), ["a", ".", "b"]);
        assert_eq!(s("a.1"), ["a", ".1"]);
        assert_eq!(s("1..2"), ["1..2"]);
        assert_eq!(s("x+(y)"), ["x", "+(", "y", ")"]);
        assert_eq!(s("a,(b"), ["a", ",", "(", "b"]);
        assert_eq!(s("a\\(mub+c"), ["a", "\\(mub+", "c"]);
        assert_eq!(s("-\\(mub"), ["-\\(mub"]);
    }
}
