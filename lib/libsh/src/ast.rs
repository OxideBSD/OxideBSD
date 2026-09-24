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
