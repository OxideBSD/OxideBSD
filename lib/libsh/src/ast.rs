//! The syntax tree for the POSIX Shell Command Language (XCU chapter 2).
//!
//! Words keep their quoting structure (`WordPart`) instead of being flattened to strings, because
//! expansion needs to know which characters were quoted: field splitting and pathname expansion
//! only ever apply to unquoted results.

use std::cell::RefCell;
use std::rc::Rc;

/// A whole script, or the body of a `$( … )` / `{ … }` / `( … )`.
pub type List = Vec<ListItem>;

/// One and-or list, terminated by `;`, a newline, or `&`.
#[derive(Clone, Debug, PartialEq)]
pub struct ListItem {
    pub and_or: AndOr,
    /// Terminated by `&`: run asynchronously.
    pub background: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AndOr {
    pub first: Pipeline,
    pub rest: Vec<(AndOrOp, Pipeline)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AndOrOp {
    And,
    Or,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pipeline {
    /// Leading `!`: the pipeline's status is logically negated.
    pub bang: bool,
    pub commands: Vec<Command>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    Simple(SimpleCommand),
    Compound(CompoundCommand, Vec<Redirect>),
    FunctionDef { name: String, body: Rc<Command> },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SimpleCommand {
    pub assignments: Vec<Assignment>,
    pub words: Vec<Word>,
    pub redirects: Vec<Redirect>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Assignment {
    pub name: String,
    pub value: Word,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CompoundCommand {
    Brace(List),
    Subshell(List),
    For { var: String, words: Option<Vec<Word>>, body: List },
    Case { word: Word, arms: Vec<CaseArm> },
    /// `if` / `elif` branches in order, then the optional `else` body.
    If { branches: Vec<(List, List)>, else_body: Option<List> },
    While { cond: List, body: List },
    Until { cond: List, body: List },
    /// `service NAME { … }` (INIT_SH.md §4.1).
    #[cfg(feature = "init-dialect")]
    Service(Rc<ServiceBlock>),
}

/// A service declaration: fields in source order, then hooks in source order.
#[cfg(feature = "init-dialect")]
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceBlock {
    pub name: String,
    pub fields: Vec<ServiceField>,
    pub hooks: Vec<ServiceHook>,
}

#[cfg(feature = "init-dialect")]
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceField {
    pub name: String,
    pub words: Vec<Word>,
    /// 1-based source line, for diagnostics.
    pub line: usize,
}

#[cfg(feature = "init-dialect")]
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceHook {
    /// `start_pre`, `status`, ... or `command` for an extra action.
    pub name: String,
    /// The action name of a `command <action> { … }` hook.
    pub action: Option<String>,
    pub body: List,
}

/// The fields `rcorder` reads without running the script; their words are literal (§4.2.1).
#[cfg(feature = "init-dialect")]
pub const ORDERING_FIELDS: &[&str] = &["provide", "require", "before", "keyword"];

#[cfg(feature = "init-dialect")]
pub const SERVICE_FIELDS: &[&str] = &[
    "desc", "provide", "require", "before", "keyword", "command", "args", "pidfile", "user", "group", "env",
    "chdir", "stop_signal", "stop_timeout", "foreground",
];

#[cfg(feature = "init-dialect")]
pub const SERVICE_HOOKS: &[&str] = &["start_pre", "start_post", "stop_pre", "stop_post", "status", "command"];

#[cfg(feature = "init-dialect")]
impl ServiceBlock {
    /// The literal values of an ordering field, across every occurrence of it. The parser has
    /// already checked they contain no expansions.
    pub fn literal_field(&self, name: &str) -> Vec<String> {
        self.fields
            .iter()
            .filter(|f| f.name == name)
            .flat_map(|f| f.words.iter().map(|w| literal_text(w).unwrap_or_default()))
            .collect()
    }

    /// What this service provides to `rcorder`: its `provide` field, or else its own name.
    pub fn provides(&self) -> Vec<String> {
        let p = self.literal_field("provide");
        if p.is_empty() { vec![self.name.clone()] } else { p }
    }
}

/// A word's text if it contains no expansions: literal and quoted parts only.
pub fn literal_text(word: &Word) -> Option<String> {
    let mut out = String::new();
    for part in word {
        match part {
            WordPart::Literal(s) | WordPart::Quoted(s) => out.push_str(s),
            WordPart::DoubleQuoted(inner) => out.push_str(&literal_text(inner)?),
            _ => return None,
        }
    }
    Some(out)
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseArm {
    pub patterns: Vec<Word>,
    pub body: List,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Redirect {
    /// Explicit descriptor (`2>`), or `None` for the operator's default.
    pub fd: Option<u32>,
    pub op: RedirOp,
    pub target: RedirTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirOp {
    /// `<`
    Input,
    /// `>`
    Output,
    /// `>|`
    Clobber,
    /// `>>`
    Append,
    /// `<>`
    ReadWrite,
    /// `<&`
    DupInput,
    /// `>&`
    DupOutput,
    /// `<<` and `<<-`
    HereDoc,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RedirTarget {
    Word(Word),
    HereDoc(HereDoc),
}

/// A here-document. The body is filled in by the parser when it reaches the end of the line the
/// `<<` appeared on, which can be after the redirection itself has been parsed.
#[derive(Clone, Debug, PartialEq)]
pub struct HereDoc {
    /// Any part of the delimiter was quoted: the body is used literally, with no expansion.
    pub quoted: bool,
    /// `<<-`: leading tabs are stripped from each line.
    pub strip_tabs: bool,
    pub body: Rc<RefCell<Word>>,
}

/// A word: a sequence of parts, concatenated after expansion.
pub type Word = Vec<WordPart>;

#[derive(Clone, Debug, PartialEq)]
pub enum WordPart {
    /// Unquoted literal text. Subject to field splitting (if produced by expansion) and pathname
    /// expansion.
    Literal(String),
    /// Literal text that was quoted (`'…'`, or a backslash-escaped character).
    Quoted(String),
    /// A `"…"` group.
    DoubleQuoted(Vec<WordPart>),
    Param(ParamExpansion),
    /// `$( … )` or `` ` … ` ``.
    CommandSubst(Rc<List>),
    /// `$(( … ))`: the expression's text, itself expanded before evaluation.
    Arith(Vec<WordPart>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParamExpansion {
    pub param: Param,
    pub op: ParamOp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Param {
    Named(String),
    /// `$1` … `$9`, `${10}` …
    Positional(usize),
    /// `@ * # ? - $ ! 0`
    Special(char),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParamOp {
    /// `$x`, `${x}`
    Plain,
    /// `${#x}`
    Length,
    /// `${x-w}` / `${x:-w}` (`colon`: also when set but empty)
    Default { colon: bool, word: Word },
    /// `${x=w}` / `${x:=w}`
    Assign { colon: bool, word: Word },
    /// `${x?w}` / `${x:?w}`
    Error { colon: bool, word: Word },
    /// `${x+w}` / `${x:+w}`
    Alternative { colon: bool, word: Word },
    /// `${x%w}` / `${x%%w}`
    RemoveSuffix { longest: bool, pattern: Word },
    /// `${x#w}` / `${x##w}`
    RemovePrefix { longest: bool, pattern: Word },
}
