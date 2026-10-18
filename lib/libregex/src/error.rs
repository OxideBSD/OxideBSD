//! `regcomp`/`regexec` error kinds and their `regerror(3)` texts.

use std::fmt;

/// The POSIX error codes. `code()` gives musl's `<regex.h>` numbering, so a C wrapper can return
/// them unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// `REG_NOMATCH`: never returned by this crate (no match is `Ok(None)`/`false`), but kept so
    /// `regerror` can describe every code.
    NoMatch,
    /// `REG_BADPAT`
    BadPat,
    /// `REG_ECOLLATE`: a collating element other than a single character.
    Collate,
    /// `REG_ECTYPE`: an unknown `[:class:]`.
    Ctype,
    /// `REG_EESCAPE`: a trailing backslash.
    Escape,
    /// `REG_ESUBREG`: a back-reference to a subexpression that does not exist or is not closed.
    Subreg,
    /// `REG_EBRACK`
    Brack,
    /// `REG_EPAREN`
    Paren,
    /// `REG_EBRACE`
    Brace,
    /// `REG_BADBR`: an interval that is not `m`, `m,` or `m,n` with `m <= n <= RE_DUP_MAX`.
    BadBr,
    /// `REG_ERANGE`
    Range,
    /// `REG_ESPACE`: the pattern is too large, or a back-reference match exceeded its work bound.
    Space,
    /// `REG_BADRPT`: a repetition operator with nothing to repeat.
    BadRpt,
}

impl ErrorKind {
    /// The `REG_*` value in musl's `<regex.h>`.
    pub fn code(self) -> i32 {
        self as i32 + 1
    }

    pub fn name(self) -> &'static str {
        use ErrorKind::*;
        match self {
            NoMatch => "REG_NOMATCH",
            BadPat => "REG_BADPAT",
            Collate => "REG_ECOLLATE",
            Ctype => "REG_ECTYPE",
            Escape => "REG_EESCAPE",
            Subreg => "REG_ESUBREG",
            Brack => "REG_EBRACK",
            Paren => "REG_EPAREN",
            Brace => "REG_EBRACE",
            BadBr => "REG_BADBR",
            Range => "REG_ERANGE",
            Space => "REG_ESPACE",
            BadRpt => "REG_BADRPT",
        }
    }

    /// The `regerror(3)` text, as the BSDs word it.
    pub fn message(self) -> &'static str {
        use ErrorKind::*;
        match self {
            NoMatch => "regexec() failed to match",
            BadPat => "invalid regular expression",
            Collate => "invalid collating element",
            Ctype => "invalid character class",
            Escape => "trailing backslash (\\)",
            Subreg => "invalid backreference number",
            Brack => "brackets ([ ]) not balanced",
            Paren => "parentheses not balanced",
            Brace => "braces not balanced",
            BadBr => "invalid repetition count(s)",
            Range => "invalid character range",
            Space => "out of memory",
            BadRpt => "repetition-operator operand invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    /// Byte offset in the pattern where compilation failed (0 for execution errors).
    pub offset: usize,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, offset: usize) -> Error {
        Error { kind, offset }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl std::error::Error for Error {}
