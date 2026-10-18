//! POSIX regular expressions (XBD chapter 9; `regcomp`/`regexec`), for OxideBSD's `grep`,
//! `sed`, `ed` and `expr`. Byte-oriented in the POSIX locale: a pattern and a text are byte
//! slices, `.` and bracket expressions match one byte, and UTF-8 passes through as bytes.
//!
//! # Design
//!
//! A pattern is parsed (`parse.rs`) to a tree, then compiled (`nfa.rs`) to a Thompson NFA in
//! which every tree node is a fragment with its own entry and exit state. Matching runs in up
//! to three passes, each only when the caller needs it:
//!
//! 1. A lazy DFA (`dfa.rs`) scans for the earliest match end. A miss stops there; this is all
//!    `is_match` does for a pattern without back-references, so `grep` runs at DFA speed.
//! 2. The leftmost-longest match: a reverse DFA over the text finds the leftmost start, an
//!    anchored forward DFA from there the longest end. Both read the whole rest of the text,
//!    so when that is much longer than the distance to the earliest match end (`sed`'s `g`
//!    flag over a large buffer), a Pike VM whose threads carry their start position
//!    (`sim.rs`) does it instead, reading only up to the end of the match.
//! 3. `exec.rs` assigns subexpressions by the XBD 9.1 rule (each subpattern, left to right,
//!    longest), deciding each choice with NFA simulations over windows of the match.
//!
//! None of this backtracks, so a pattern without back-references runs in time linear in the
//! text (times the NFA size; the submatch pass can go quadratic in the match length for
//! some repetitions of groups). Back-references can't be done by automata: for them the NFA
//! matches a superset (a back-reference as a copy of its group), used as a prefilter, and a
//! bounded backtracking search tries starts left to right, ends longest first, and submatch
//! choices in preference order. Past its bound it returns `REG_ESPACE`.
//!
//! # Conformance notes
//!
//! Where POSIX leaves behaviour undefined this follows the BSDs, or the XBD text where it says
//! enough:
//!
//! - Back-references `\1`-`\9` work in EREs too. A back-reference to a group that is not yet
//!   closed is `REG_ESUBREG`. One to a group that did not participate (including one in
//!   another alternative, which glibc refuses to compile) fails to match.
//! - In BREs, `^` is an anchor at the start of the pattern or of a subexpression, `$` at the
//!   end of either; elsewhere they are literal. `*` is literal at the start of either, or
//!   after the leading `^`. In EREs, `^` and `$` are anchors everywhere.
//! - A repetition operator with nothing to repeat (an ERE starting `*`, `(+`, `|?`, `^*`, a BRE
//!   `\{` at the start) is `REG_BADRPT`. Stacked operators (`a**`, `a+?`) nest.
//! - An unmatched `)` in an ERE is literal (XBD 9.4.3 makes it special only when matched).
//! - Intervals: `{m}`, `{m,}`, `{m,n}` with `m <= n <= RE_DUP_MAX` (255); `{,n}` is
//!   `REG_BADBR`.
//! - An escape of an ordinary character (`\n`, `\w`, `\<`) is that character, not a GNU
//!   operator.
//! - Collating symbols and equivalence classes are single characters (`[.-.]`, `[=a=]`); a
//!   name such as `[.hyphen.]` is `REG_ECOLLATE`. Ranges compare byte values.
//! - `REG_ICASE` folds ASCII letters only (the POSIX locale has no others).
//! - `.` and every non-matching bracket expression match any byte including NUL, except newline
//!   under `REG_NEWLINE`.
//!
//! Submatch reporting follows XBD 9.1 and the `regexec` description: each subpattern, left to
//! right, matches the longest string that still lets the whole match succeed; a group in a
//! repetition reports its last iteration; and a group inside another reports only within its
//! enclosing group's last match (so `(a(b)?)+` on `aba` leaves group 2 unset). A
//! back-reference sees exactly what would be reported at that point, so `((a)|b)*\2` does not
//! match `aba` (glibc lets it see group 2 from an earlier iteration).
//!
//! Choices POSIX leaves open: among alternatives matching the same span, the first is taken. A
//! repetition over an empty span takes one empty iteration if its body can match empty
//! (`(a*)*` on `b` gives group 1 = (0,0): a null match is longer than none), and otherwise
//! iterates on an empty string only as its minimum count demands (`a+(b*){0,2}` on `abb` gives
//! group 1 = (1,3), where glibc adds an empty iteration and gives (3,3)). The one exception
//! is a back-reference that can only match after a final empty iteration: `a(a|b*)*\1`
//! matches all of `aab`, with group 1 = (3,3).
//!
//! `tests/glibc.rs` compares all this against glibc and lists, case by case, where glibc
//! departs from the XBD text.
//!
//! Back-reference matching is exponential in the worst case. The search gives up with
//! `REG_ESPACE` after a few million steps, or when its continuations nest about a thousand
//! repetitions of a group that a back-reference depends on (`(a)(\1)*` on a 20,000-byte run
//! of `a`).

mod byteset;
mod dfa;
mod error;
mod exec;
mod nfa;
mod parse;
mod sim;

#[cfg(test)]
mod tests;

use std::ops::{BitOr, Range};
use std::sync::Mutex;

pub use error::{Error, ErrorKind};
pub use exec::Span;
pub use parse::DUP_MAX;

/// `regcomp` flags, with musl's values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompileFlags(pub u32);

impl CompileFlags {
    /// A basic regular expression (no flags).
    pub const BASIC: CompileFlags = CompileFlags(0);
    pub const EXTENDED: CompileFlags = CompileFlags(1);
    pub const ICASE: CompileFlags = CompileFlags(2);
    /// `.` and non-matching lists don't match newline; `^`/`$` also match after/before one.
    pub const NEWLINE: CompileFlags = CompileFlags(4);
    /// Only match or no match is wanted: `captures` returns no groups.
    pub const NOSUB: CompileFlags = CompileFlags(8);

    pub fn contains(self, o: CompileFlags) -> bool {
        self.0 & o.0 == o.0
    }
}

impl BitOr for CompileFlags {
    type Output = CompileFlags;
    fn bitor(self, o: CompileFlags) -> CompileFlags {
        CompileFlags(self.0 | o.0)
    }
}

/// `regexec` flags, with musl's values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecFlags(pub u32);

impl ExecFlags {
    pub const NONE: ExecFlags = ExecFlags(0);
    /// The start of the text is not the start of a line: `^` doesn't match there.
    pub const NOTBOL: ExecFlags = ExecFlags(1);
    /// The end of the text is not the end of a line: `$` doesn't match there.
    pub const NOTEOL: ExecFlags = ExecFlags(2);

    pub fn contains(self, o: ExecFlags) -> bool {
        self.0 & o.0 == o.0
    }
}

impl BitOr for ExecFlags {
    type Output = ExecFlags;
    fn bitor(self, o: ExecFlags) -> ExecFlags {
        ExecFlags(self.0 | o.0)
    }
}

/// A compiled regular expression. Shareable between threads; the DFA cache sits behind a
/// mutex taken once per search.
pub struct Regex {
    ast: parse::Ast,
    nfa: nfa::Nfa,
    flags: CompileFlags,
    dfa: Mutex<Dfas>,
}

/// The lazy DFAs; the last two are made on first use.
struct Dfas {
    fwd: dfa::Dfa,
    rev: Option<dfa::Dfa>,
    anchored: Option<dfa::Dfa>,
}

/// Use the DFAs for the match extent when the text past the earliest match end is at most
/// this many times longer than the text before it (plus `EXTENT_SLACK`), else the Pike VM.
const EXTENT_RATIO: usize = 32;
const EXTENT_SLACK: usize = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Test,
    Extent,
    Groups,
}

impl Regex {
    /// `regcomp`.
    pub fn new(pattern: &[u8], flags: CompileFlags) -> Result<Regex, Error> {
        let opts = parse::Opts {
            ere: flags.contains(CompileFlags::EXTENDED),
            icase: flags.contains(CompileFlags::ICASE),
            newline: flags.contains(CompileFlags::NEWLINE),
        };
        let mut ast = parse::parse(pattern, &opts)?;
        let nfa = nfa::compile(&mut ast)?;
        let dfa = Mutex::new(Dfas { fwd: dfa::Dfa::new(&nfa, opts.newline, dfa::Dir::Fwd, false), rev: None, anchored: None });
        Ok(Regex { ast, nfa, flags, dfa })
    }

    /// The number of parenthesized subexpressions (`re_nsub`).
    pub fn nsub(&self) -> usize {
        self.ast.nsub as usize
    }

    pub fn flags(&self) -> CompileFlags {
        self.flags
    }

    /// Whether the pattern has back-references (and so may backtrack, and may fail with
    /// `REG_ESPACE`).
    pub fn has_backrefs(&self) -> bool {
        self.ast.has_backref
    }

    /// Whether anything in `text` matches. A back-reference search that exceeds its work
    /// bound counts as no match; `try_is_match_at` reports it.
    pub fn is_match(&self, text: &[u8], flags: ExecFlags) -> bool {
        self.try_is_match_at(text, 0..text.len(), flags).unwrap_or(false)
    }

    /// The leftmost-longest match.
    pub fn find(&self, text: &[u8], flags: ExecFlags) -> Option<Span> {
        self.try_find_at(text, 0..text.len(), flags).unwrap_or(None)
    }

    /// The leftmost-longest match and its subexpressions: element 0 is the whole match,
    /// element `i` subexpression `i` (`None` if it took no part). Empty under `NOSUB`.
    pub fn captures(&self, text: &[u8], flags: ExecFlags) -> Option<Vec<Option<Span>>> {
        self.try_captures_at(text, 0..text.len(), flags).unwrap_or(None)
    }

    /// `is_match` within `text[range]`, as `REG_STARTEND`: the range's ends are the text's
    /// ends for `^`, `$`, `NOTBOL` and `NOTEOL`; nothing outside it is looked at.
    pub fn try_is_match_at(&self, text: &[u8], range: Range<usize>, flags: ExecFlags) -> Result<bool, Error> {
        Ok(self.run(text, range, flags, Want::Test)?.is_some())
    }

    /// `find` within `text[range]` (see `try_is_match_at`); offsets index `text`.
    pub fn try_find_at(&self, text: &[u8], range: Range<usize>, flags: ExecFlags) -> Result<Option<Span>, Error> {
        Ok(self.run(text, range, flags, Want::Extent)?.map(|v| v[0].unwrap()))
    }

    /// `captures` within `text[range]` (see `try_is_match_at`); offsets index `text`.
    pub fn try_captures_at(&self, text: &[u8], range: Range<usize>, flags: ExecFlags) -> Result<Option<Vec<Option<Span>>>, Error> {
        let nosub = self.flags.contains(CompileFlags::NOSUB);
        let r = self.run(text, range, flags, if nosub { Want::Test } else { Want::Groups })?;
        Ok(r.map(|v| if nosub { Vec::new() } else { v }))
    }

    /// `Some(groups)` on a match: for `Test` possibly empty, for `Extent` at least `[0]`.
    fn run(&self, text: &[u8], range: Range<usize>, flags: ExecFlags, want: Want) -> Result<Option<Vec<Option<Span>>>, Error> {
        let off = range.start;
        let tx = sim::Text {
            t: &text[range],
            notbol: flags.contains(ExecFlags::NOTBOL),
            noteol: flags.contains(ExecFlags::NOTEOL),
            nl: self.flags.contains(CompileFlags::NEWLINE),
        };
        let mut dfas = self.dfa.lock().unwrap_or_else(|e| e.into_inner());
        let Some(earliest) = dfas.fwd.earliest(&self.nfa, tx.t, tx.bol(0), tx.noteol) else { return Ok(None) };
        if want == Want::Test && !self.ast.has_backref {
            return Ok(Some(Vec::new()));
        }
        let extent = if !self.ast.has_backref && tx.t.len() <= EXTENT_RATIO * (earliest + 1) + EXTENT_SLACK {
            Some(self.dfa_extent(&mut dfas, &tx))
        } else {
            None
        };
        drop(dfas);
        let icase = self.flags.contains(CompileFlags::ICASE);
        let mut ex = exec::Exec::new(&self.ast, &self.nfa, tx, icase);
        if self.ast.has_backref {
            if ex.search(0)?.is_none() {
                return Ok(None);
            }
        } else {
            let Some((s, e)) = extent.unwrap_or_else(|| ex.sim.extent(&self.nfa, &tx, 0, earliest)) else {
                debug_assert!(false, "the DFA and the NFA disagree");
                return Ok(None);
            };
            ex.caps[0] = Some((s, e));
            if want == Want::Groups {
                ex.assign(self.ast.root, s, e);
            }
        }
        let mut caps = ex.caps;
        if want != Want::Groups {
            caps.truncate(1);
        }
        for c in caps.iter_mut().flatten() {
            c.0 += off;
            c.1 += off;
        }
        Ok(Some(caps))
    }
}

impl Regex {
    /// The leftmost-longest match by the reverse and anchored DFAs.
    fn dfa_extent(&self, dfas: &mut Dfas, tx: &sim::Text) -> Option<Span> {
        let nl = tx.nl;
        let rev = dfas.rev.get_or_insert_with(|| dfa::Dfa::new(&self.nfa, nl, dfa::Dir::Rev, false));
        let s = rev.leftmost_start(&self.nfa, tx.t, tx.notbol, tx.noteol)?;
        let anchored = dfas.anchored.get_or_insert_with(|| dfa::Dfa::new(&self.nfa, nl, dfa::Dir::Fwd, true));
        let e = anchored.longest(&self.nfa, tx.t, s, tx.bol(s), tx.noteol)?;
        Some((s, e))
    }

    /// Tests only: the extent both ways.
    #[cfg(test)]
    fn extents(&self, t: &[u8], flags: ExecFlags) -> (Option<Span>, Option<Span>) {
        let tx = sim::Text {
            t,
            notbol: flags.contains(ExecFlags::NOTBOL),
            noteol: flags.contains(ExecFlags::NOTEOL),
            nl: self.flags.contains(CompileFlags::NEWLINE),
        };
        let mut dfas = self.dfa.lock().unwrap();
        let d = self.dfa_extent(&mut dfas, &tx);
        let mut sim = sim::Sim::new(&self.nfa);
        (d, sim.extent(&self.nfa, &tx, 0, t.len()))
    }
}

/// `regerror`: the message for an error kind.
pub fn regerror(kind: ErrorKind) -> &'static str {
    kind.message()
}
