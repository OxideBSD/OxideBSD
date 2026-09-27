//! The document tree (MAN.md §3.1, stage 2): one node type for every language.
//!
//! A macro that encloses others is a `Block` with up to three parts, `Head`, `Body` and `Tail`
//! (`.Sh` has a head, the section title, and a body; `.It` in a tag list has both; `.Op` has
//! only a body). A macro that formats its own arguments is an `Elem`. Words are `Text`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Root,
    Block,
    Head,
    Body,
    Tail,
    Elem,
    Text,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Flags {
    /// No space before this node (it follows `.Ns`, an opening delimiter, `\c`...).
    pub nospace: bool,
    /// This node ends a sentence: the next word on the same line gets two spaces.
    pub eos: bool,
    /// A delimiter word (`.`, `(`, `|`...), printed outside any enclosing style.
    pub delim: bool,
    /// The first node of an input line: the renderer may need to break (no-fill mode).
    pub line_start: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub kind: Kind,
    /// The macro name, or empty for text and structural parts.
    pub tok: String,
    /// A text node's text; for some elements, a value the parser worked out (`.Nm`'s name).
    pub text: String,
    /// A block's options (`-tag -width Ds`) or an element's arguments where the renderer needs
    /// them raw (`.Xr name section`).
    pub args: Vec<String>,
    pub children: Vec<Node>,
    pub line: usize,
    pub flags: Flags,
}

impl Node {
    pub fn new(kind: Kind, tok: &str, line: usize) -> Node {
        Node { kind, tok: tok.to_string(), text: String::new(), args: Vec::new(), children: Vec::new(), line, flags: Flags::default() }
    }

    pub fn text(text: &str, line: usize) -> Node {
        let mut n = Node::new(Kind::Text, "", line);
        n.text = text.to_string();
        n
    }

    pub fn part(&self, kind: Kind) -> Option<&Node> {
        self.children.iter().find(|c| c.kind == kind)
    }

    /// The concatenated text of this subtree, words separated by spaces.
    pub fn plain_text(&self) -> String {
        let mut out = String::new();
        self.collect_text(&mut out);
        out
    }

    fn collect_text(&self, out: &mut String) {
        if self.kind == Kind::Text {
            if !out.is_empty() && !self.flags.nospace {
                out.push(' ');
            }
            out.push_str(&self.text);
        }
        for c in &self.children {
            c.collect_text(out);
        }
    }

    /// A debugging dump (`-T tree`).
    pub fn dump(&self, depth: usize, out: &mut String) {
        let pad = "    ".repeat(depth);
        match self.kind {
            Kind::Text => out.push_str(&format!("{pad}{:?}{}{}\n", self.text, if self.flags.nospace { " (nospace)" } else { "" }, if self.flags.eos { " (eos)" } else { "" })),
            _ => out.push_str(&format!("{pad}{} ({:?}){} {}\n", self.tok, self.kind, if self.args.is_empty() { String::new() } else { format!(" {:?}", self.args) }, self.line)),
        }
        for c in &self.children {
            c.dump(depth + 1, out);
        }
    }
}

/// The prologue (`.Dd`, `.Dt`, `.Os` in mdoc; `.TH` in man).
#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub title: String,
    pub section: String,
    pub arch: String,
    /// The volume (`.Dt`'s third argument or `.TH`'s fifth); empty means the section's default.
    pub volume: String,
    pub date: String,
    pub os: String,
    /// Whether the page has an `.Os` line at all: an empty one means this system's name, a
    /// missing one means none.
    pub os_given: bool,
    /// `.Nm`'s first argument, the name later bare `.Nm` calls print.
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    Mdoc,
    Man,
}

pub struct Document {
    pub language: Language,
    pub meta: Meta,
    pub root: Node,
}
