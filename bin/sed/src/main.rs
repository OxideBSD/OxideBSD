//! `sed(1)`: the stream editor.
//!
//! ```text
//! sed [-Ealnru] command [-I extension] [-i extension] [file ...]
//! sed [-Ealnru] [-e command] [-f command_file] [-I extension] [-i extension] [file ...]
//! ```
//!
//! POSIX's sed with FreeBSD's options. The script is every `-e` and `-f` joined by newlines in
//! the order given, or else the first operand. A line of input goes into the pattern space; each
//! command whose addresses select it runs; then the pattern space is written (unless `-n`, or
//! `#n` as the script's first line) and the next cycle starts. The input is every file in turn
//! as one stream (`-` or no file at all is the standard input).
//!
//! - Options: `-E` (and `-r`) extended regular expressions; `-n` no automatic output; `-i ext`
//!   edits each file in place, as a separate stream (its own line numbers, `$` and ranges),
//!   keeping the original as the file name plus `ext` unless `ext` is empty (`-i ''`); `-I ext`
//!   the same but as one stream across all the files; `-l` and `-u` flush the output after each
//!   line; `-a` is accepted (`w` files are always created before the input is read).
//! - Addresses: a line number, `$` (the last line), `/re/` or `\cREc` (`c` any character but
//!   backslash and newline; `\c` inside is a literal `c`, `\n` a newline), optionally followed by
//!   `I` to ignore case. `//` is the last regular expression used. Two addresses `a1,a2` select
//!   a range from a line `a1` matches through the next one `a2` does (a line number not past
//!   the first line ends it at once), or `a1,+N` through `N` lines more. `!` inverts.
//! - Commands: `{ ... }`, `a`, `b`, `c`, `d`, `D`, `g`, `G`, `h`, `H`, `i`, `l`, `n`, `N`, `p`,
//!   `P`, `q`, `r`, `s`, `t`, `w`, `x`, `y`, `:`, `=`, `#`, as POSIX describes them. `a`, `i` and
//!   `c` take `\`, a newline and the text, or (as the BSDs also allow) the text on the same
//!   line; leading blanks of each text line are dropped unless escaped. Labels for `:`, `b` and
//!   `t` run to the end of the line, semicolons included (POSIX).
//! - `s/re/replacement/flags`: in the replacement, `&` is the match, `\1`-`\9` its groups, `\n`
//!   and an escaped newline a newline, `\&` and `\\` themselves. Flags: `g` every match, a
//!   number `N` the Nth (with `g`, the Nth and on), `p` print, `w file`, and `i` or `I` ignore
//!   case (FreeBSD).
//! - `N` on the last line quits without printing (POSIX and the BSDs; GNU prints). A last line
//!   without a newline is written without one.
//!
//! Output goes through a buffer flushed at exit, before an error message and per line with
//! `-u`/`-l` (a console write costs about a millisecond). The exit status is 0, or 1 on any
//! error.

use std::collections::HashMap;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use posixre::{CompileFlags, ExecFlags, Regex};

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: sed [-Ealnru] command [-I extension] [-i extension] [file ...]\n\
         \tsed [-Ealnru] [-e command] [-f command_file] [-I extension]\n\
         \t    [-i extension] [file ...]"
    );
    ExitCode::from(1)
}

/// A fatal error: the message, already formatted after `sed: `.
struct Fatal(String);

// --- the compiled script ---------------------------------------------------------------------

#[derive(Clone)]
enum Addr {
    Line(u64),
    Last,
    /// `None`: the last regular expression used.
    Re(Option<Rc<Regex>>),
    /// `+N`, as a second address only.
    Rel(u64),
}

enum ReplPart {
    Lit(Vec<u8>),
    Group(usize),
}

struct Subst {
    re: Option<Rc<Regex>>,
    repl: Vec<ReplPart>,
    global: bool,
    nth: u64,
    print: bool,
    wfile: Option<usize>,
    /// The replacement uses `\1`-`\9`.
    groups: bool,
}

enum Kind {
    /// `{`: the index past the matching `}`.
    Block(usize),
    EndBlock,
    Append(Vec<u8>),
    Insert(Vec<u8>),
    Change(Vec<u8>),
    /// `b` and `t`: the target index (the script's length for its end); the label until
    /// resolved.
    Branch(usize, Vec<u8>),
    Test(usize, Vec<u8>),
    Label,
    Delete,
    DeleteFirst,
    Get,
    GetAppend,
    Hold,
    HoldAppend,
    List,
    Next,
    NextAppend,
    Print,
    PrintFirst,
    Quit,
    Read(Vec<u8>),
    Write(usize),
    Subst(Box<Subst>),
    Exchange,
    Translate(Box<[u8; 256]>),
    LineNumber,
}

struct Cmd {
    a1: Option<Addr>,
    a2: Option<Addr>,
    neg: bool,
    kind: Kind,
    /// The line a range started on, 0 when not in one.
    start: u64,
}

/// One piece of the script: its text and how errors name it.
struct Unit {
    text: Vec<u8>,
    name: String,
}

struct Parser<'a> {
    s: &'a [u8],
    p: usize,
    /// Byte offsets where each unit starts, with its name and its first line's number.
    units: &'a [(usize, String)],
    ere: bool,
    cmds: Vec<Cmd>,
    labels: HashMap<Vec<u8>, usize>,
    wfiles: &'a mut Vec<(Vec<u8>, Out)>,
}

fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

impl Parser<'_> {
    fn err(&self, msg: impl AsRef<str>) -> Fatal {
        let at = self.p.min(self.s.len());
        let line = 1 + self.s[..at].iter().filter(|&&c| c == b'\n').count();
        let name = self.units.iter().rev().find(|u| u.0 <= at).map_or("", |u| u.1.as_str());
        Fatal(format!("{line}: {name}: {}", msg.as_ref()))
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.p).copied()
    }

    fn skip_blanks(&mut self) {
        while self.peek().is_some_and(is_blank) {
            self.p += 1;
        }
    }

    fn number(&mut self) -> u64 {
        let mut n: u64 = 0;
        while let Some(c) = self.peek().filter(u8::is_ascii_digit) {
            n = n.saturating_mul(10).saturating_add((c - b'0') as u64);
            self.p += 1;
        }
        n
    }

    /// Reads a delimited regular expression or `y` string up to `delim`: `\delim` is a literal
    /// delimiter, `\n` a newline. For a regular expression, a bracket expression is copied
    /// whole (a delimiter inside doesn't end it) and an escaped delimiter that is special in
    /// the syntax stays escaped, so it means itself.
    fn delimited(&mut self, delim: u8, regex: bool, what: &str) -> Result<Vec<u8>, Fatal> {
        let mut out = Vec::new();
        loop {
            let Some(c) = self.peek() else { return Err(self.err(format!("unterminated {what}"))) };
            if c == delim {
                self.p += 1;
                return Ok(out);
            }
            if c == b'\n' && regex {
                return Err(self.err(format!("unterminated {what}")));
            }
            if c == b'\\' {
                let Some(n) = self.s.get(self.p + 1).copied() else { return Err(self.err(format!("unterminated {what}"))) };
                self.p += 2;
                if n == delim {
                    let special: &[u8] = if self.ere { b".[]\\()*+?{}|^$" } else { b".[]\\*^$" };
                    if regex && special.contains(&n) {
                        out.push(b'\\');
                    }
                    out.push(n);
                } else if n == b'n' || n == b'\n' {
                    out.push(b'\n');
                } else if !regex && n == b'\\' {
                    out.push(b'\\');
                } else {
                    if !regex {
                        // y: only \\, \n and \delim are escapes.
                        return Err(self.err("unknown option to `y'"));
                    }
                    out.push(b'\\');
                    out.push(n);
                }
                continue;
            }
            if c == b'[' && regex {
                self.bracket(&mut out)?;
                continue;
            }
            out.push(c);
            self.p += 1;
        }
    }

    /// Copies a bracket expression starting at `[`, `\n` inside it becoming a newline (as in
    /// FreeBSD).
    fn bracket(&mut self, out: &mut Vec<u8>) -> Result<(), Fatal> {
        let start = self.p;
        out.push(b'[');
        self.p += 1;
        if self.peek() == Some(b'^') {
            out.push(b'^');
            self.p += 1;
        }
        if self.peek() == Some(b']') {
            out.push(b']');
            self.p += 1;
        }
        loop {
            let Some(c) = self.peek() else {
                self.p = start;
                return Err(self.err("unbalanced brackets ([])"));
            };
            match c {
                b']' => {
                    out.push(b']');
                    self.p += 1;
                    return Ok(());
                }
                b'[' if matches!(self.s.get(self.p + 1), Some(b'.' | b':' | b'=')) => {
                    let kind = self.s[self.p + 1];
                    out.extend_from_slice(&self.s[self.p..self.p + 2]);
                    self.p += 2;
                    loop {
                        let Some(d) = self.peek() else {
                            self.p = start;
                            return Err(self.err("unbalanced brackets ([])"));
                        };
                        if d == kind && self.s.get(self.p + 1) == Some(&b']') {
                            out.extend_from_slice(&[kind, b']']);
                            self.p += 2;
                            break;
                        }
                        out.push(d);
                        self.p += 1;
                    }
                }
                b'\\' if self.s.get(self.p + 1) == Some(&b'n') => {
                    out.push(b'\n');
                    self.p += 2;
                }
                b'\n' => {
                    self.p = start;
                    return Err(self.err("unbalanced brackets ([])"));
                }
                _ => {
                    out.push(c);
                    self.p += 1;
                }
            }
        }
    }

    fn compile_re(&self, pat: &[u8], icase: bool) -> Result<Option<Rc<Regex>>, Fatal> {
        if pat.is_empty() {
            return Ok(None);
        }
        let mut fl = if self.ere { CompileFlags::EXTENDED } else { CompileFlags::BASIC };
        if icase {
            fl = fl | CompileFlags::ICASE;
        }
        Regex::new(pat, fl).map(|r| Some(Rc::new(r))).map_err(|e| self.err(format!("RE error: {}", e.kind.message())))
    }

    fn address(&mut self) -> Result<Option<Addr>, Fatal> {
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                let n = self.number();
                if n == 0 {
                    return Err(self.err("invalid usage of line address 0"));
                }
                Ok(Some(Addr::Line(n)))
            }
            Some(b'$') => {
                self.p += 1;
                Ok(Some(Addr::Last))
            }
            Some(b'/') | Some(b'\\') => {
                let delim = if self.peek() == Some(b'\\') {
                    self.p += 1;
                    match self.peek() {
                        None | Some(b'\n') | Some(b'\\') => return Err(self.err("unexpected EOF (pending }'s)")),
                        Some(d) => d,
                    }
                } else {
                    b'/'
                };
                self.p += 1;
                let pat = self.delimited(delim, true, "regular expression")?;
                let mut icase = false;
                while self.peek() == Some(b'I') {
                    icase = true;
                    self.p += 1;
                }
                Ok(Some(Addr::Re(self.compile_re(&pat, icase)?)))
            }
            _ => Ok(None),
        }
    }

    /// After a command: blanks, then `;`, a newline, `}`, `#` or the end.
    fn end_of_cmd(&mut self, c: u8) -> Result<(), Fatal> {
        self.skip_blanks();
        match self.peek() {
            None | Some(b'\n') | Some(b';') => {
                if self.peek().is_some() {
                    self.p += 1;
                }
                Ok(())
            }
            Some(b'}') | Some(b'#') => Ok(()),
            _ => Err(self.err(format!("extra characters at the end of {} command", c as char))),
        }
    }

    /// The rest of the line (for labels and file names), without leading blanks.
    fn to_eol(&mut self) -> Vec<u8> {
        self.skip_blanks();
        let st = self.p;
        while self.peek().is_some_and(|c| c != b'\n') {
            self.p += 1;
        }
        let v = self.s[st..self.p].to_vec();
        if self.peek() == Some(b'\n') {
            self.p += 1;
        }
        v
    }

    fn label(&mut self) -> Vec<u8> {
        let mut l = self.to_eol();
        while l.last().is_some_and(|&c| is_blank(c)) {
            l.pop();
        }
        l
    }

    /// The text of `a`, `i` and `c`.
    fn text(&mut self) -> Result<Vec<u8>, Fatal> {
        self.skip_blanks();
        if self.peek() == Some(b'\\') {
            self.p += 1;
            if self.peek() == Some(b'\n') {
                self.p += 1;
            }
        }
        let mut out = Vec::new();
        let mut at_line_start = true;
        loop {
            if at_line_start {
                self.skip_blanks();
                at_line_start = false;
            }
            match self.peek() {
                None => break,
                Some(b'\n') => {
                    self.p += 1;
                    break;
                }
                Some(b'\\') => {
                    self.p += 1;
                    match self.peek() {
                        None => break,
                        Some(b'\n') => {
                            out.push(b'\n');
                            self.p += 1;
                            at_line_start = true;
                        }
                        Some(c) => {
                            out.push(c);
                            self.p += 1;
                        }
                    }
                }
                Some(c) => {
                    out.push(c);
                    self.p += 1;
                }
            }
        }
        Ok(out)
    }

    fn wfile(&mut self, name: Vec<u8>) -> Result<usize, Fatal> {
        if name.is_empty() {
            return Err(self.err("filename expected"));
        }
        if let Some(i) = self.wfiles.iter().position(|w| w.0 == name) {
            return Ok(i);
        }
        let out = match &name[..] {
            b"/dev/stdout" => Out::stdout_alias(),
            b"/dev/stderr" => Out::new(Box::new(io::stderr()), false),
            _ => match File::create(OsStr::from_bytes(&name)) {
                Ok(f) => Out::new(Box::new(BufWriter::new(f)), false),
                Err(e) => return Err(Fatal(format!("{}: {}", String::from_utf8_lossy(&name), strerror(&e)))),
            },
        };
        self.wfiles.push((name, out));
        Ok(self.wfiles.len() - 1)
    }

    fn subst(&mut self) -> Result<Kind, Fatal> {
        let delim = match self.peek() {
            None | Some(b'\n') | Some(b'\\') => return Err(self.err("substitute pattern can not be delimited by newline or backslash")),
            Some(d) => d,
        };
        self.p += 1;
        let pat = self.delimited(delim, true, "substitute pattern")?;
        // The replacement.
        let mut repl: Vec<ReplPart> = Vec::new();
        let mut lit: Vec<u8> = Vec::new();
        let mut maxref = 0;
        loop {
            let Some(c) = self.peek() else { return Err(self.err("unterminated substitute in regular expression")) };
            self.p += 1;
            if c == delim {
                break;
            }
            match c {
                b'\\' => {
                    let Some(n) = self.peek() else { return Err(self.err("unterminated substitute in regular expression")) };
                    self.p += 1;
                    if n == delim && !n.is_ascii_digit() && n != b'&' {
                        lit.push(n);
                    } else if n.is_ascii_digit() {
                        if !lit.is_empty() {
                            repl.push(ReplPart::Lit(std::mem::take(&mut lit)));
                        }
                        let g = (n - b'0') as usize;
                        maxref = maxref.max(g);
                        repl.push(ReplPart::Group(g));
                    } else if n == b'n' || n == b'\n' {
                        lit.push(b'\n');
                    } else {
                        lit.push(n);
                    }
                }
                b'&' => {
                    if !lit.is_empty() {
                        repl.push(ReplPart::Lit(std::mem::take(&mut lit)));
                    }
                    repl.push(ReplPart::Group(0));
                }
                b'\n' => return Err(self.err("unterminated substitute in regular expression")),
                _ => lit.push(c),
            }
        }
        if !lit.is_empty() {
            repl.push(ReplPart::Lit(lit));
        }
        let (mut global, mut print, mut icase, mut nth, mut wfile) = (false, false, false, 0u64, None);
        loop {
            match self.peek() {
                Some(b'g') => {
                    if global {
                        return Err(self.err("more than one number or 'g' in substitute flags"));
                    }
                    global = true;
                    self.p += 1;
                }
                Some(b'p') => {
                    if print {
                        return Err(self.err("more than one 'p' in substitute flags"));
                    }
                    print = true;
                    self.p += 1;
                }
                Some(b'i') | Some(b'I') => {
                    icase = true;
                    self.p += 1;
                }
                Some(c) if c.is_ascii_digit() => {
                    if nth != 0 {
                        return Err(self.err("more than one number or 'g' in substitute flags"));
                    }
                    nth = self.number();
                    if nth == 0 {
                        return Err(self.err("zero substitution count"));
                    }
                }
                Some(b'w') => {
                    self.p += 1;
                    let name = self.to_eol();
                    wfile = Some(self.wfile(name)?);
                    // to_eol took the newline.
                    self.p -= usize::from(self.s.get(self.p.wrapping_sub(1)) == Some(&b'\n'));
                    break;
                }
                None | Some(b'\n') | Some(b';') | Some(b'}') | Some(b'#') | Some(b' ') | Some(b'\t') => break,
                Some(c) => return Err(self.err(format!("bad flag in substitute command: '{}'", c as char))),
            }
        }
        let re = self.compile_re(&pat, icase)?;
        if let Some(r) = &re {
            if maxref > r.nsub() {
                return Err(self.err(format!("\\{maxref} not defined in the RE")));
            }
        }
        Ok(Kind::Subst(Box::new(Subst { re, repl, global, nth: nth.max(1), print, wfile, groups: maxref > 0 })))
    }

    fn translate(&mut self) -> Result<Kind, Fatal> {
        let delim = match self.peek() {
            None | Some(b'\n') | Some(b'\\') => return Err(self.err("transform pattern can not be delimited by newline or backslash")),
            Some(d) => d,
        };
        self.p += 1;
        let a = self.delimited(delim, false, "transform pattern")?;
        let b = self.delimited(delim, false, "transform pattern")?;
        if a.len() != b.len() {
            return Err(self.err("transform strings are not the same length"));
        }
        let mut t = Box::new([0u8; 256]);
        for (i, v) in t.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut seen = [false; 256];
        for (&x, &y) in a.iter().zip(&b) {
            if seen[x as usize] && t[x as usize] != y {
                return Err(self.err("transform string has a character twice"));
            }
            seen[x as usize] = true;
            t[x as usize] = y;
        }
        Ok(Kind::Translate(t))
    }

    fn parse(mut self) -> Result<(Vec<Cmd>, HashMap<Vec<u8>, usize>), Fatal> {
        let mut blocks: Vec<usize> = Vec::new();
        loop {
            while self.peek().is_some_and(|c| is_blank(c) || c == b'\n' || c == b';') {
                self.p += 1;
            }
            let Some(_) = self.peek() else { break };
            if self.peek() == Some(b'#') {
                self.to_eol();
                continue;
            }
            let a1 = self.address()?;
            let mut a2 = None;
            if a1.is_some() {
                self.skip_blanks();
                if self.peek() == Some(b',') {
                    self.p += 1;
                    self.skip_blanks();
                    if self.peek() == Some(b'+') {
                        self.p += 1;
                        if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                            return Err(self.err("expected address"));
                        }
                        a2 = Some(Addr::Rel(self.number()));
                    } else {
                        a2 = self.address()?;
                        if a2.is_none() {
                            return Err(self.err("expected context address"));
                        }
                    }
                }
            }
            let naddr = a1.is_some() as usize + a2.is_some() as usize;
            self.skip_blanks();
            let mut neg = false;
            if self.peek() == Some(b'!') {
                neg = true;
                self.p += 1;
                self.skip_blanks();
                if self.peek() == Some(b'!') {
                    return Err(self.err("multiple !'s"));
                }
            }
            let Some(c) = self.peek() else { return Err(self.err("command expected")) };
            self.p += 1;
            let max_addr = match c {
                b':' | b'}' => 0,
                b'q' => 1,
                _ => 2,
            };
            if naddr > max_addr {
                return Err(self.err(format!("command {} expects up to {max_addr} address(es), found {naddr}", c as char)));
            }
            if neg && max_addr == 0 {
                return Err(self.err(format!("command {} expects up to 0 address(es), found {naddr}", c as char)));
            }
            let kind = match c {
                b'{' => {
                    blocks.push(self.cmds.len());
                    Kind::Block(0)
                }
                b'}' => {
                    let Some(open) = blocks.pop() else { return Err(self.err("unexpected }")) };
                    let here = self.cmds.len();
                    self.cmds[open].kind = Kind::Block(here + 1);
                    self.end_of_cmd(c)?;
                    Kind::EndBlock
                }
                b'a' => Kind::Append(self.text()?),
                b'i' => Kind::Insert(self.text()?),
                b'c' => Kind::Change(self.text()?),
                b':' => {
                    let l = self.label();
                    if l.is_empty() {
                        return Err(self.err("empty label"));
                    }
                    if self.labels.insert(l.clone(), self.cmds.len()).is_some() {
                        return Err(self.err(format!("duplicate label '{}'", String::from_utf8_lossy(&l))));
                    }
                    Kind::Label
                }
                b'b' => Kind::Branch(usize::MAX, self.label()),
                b't' => Kind::Test(usize::MAX, self.label()),
                b'r' => {
                    let name = self.to_eol();
                    if name.is_empty() {
                        return Err(self.err("filename expected"));
                    }
                    Kind::Read(name)
                }
                b'w' => {
                    let name = self.to_eol();
                    Kind::Write(self.wfile(name)?)
                }
                b's' => {
                    let k = self.subst()?;
                    self.end_of_cmd(c)?;
                    k
                }
                b'y' => {
                    let k = self.translate()?;
                    self.end_of_cmd(c)?;
                    k
                }
                b'd' | b'D' | b'g' | b'G' | b'h' | b'H' | b'l' | b'n' | b'N' | b'p' | b'P' | b'q' | b'x' | b'=' => {
                    self.end_of_cmd(c)?;
                    match c {
                        b'd' => Kind::Delete,
                        b'D' => Kind::DeleteFirst,
                        b'g' => Kind::Get,
                        b'G' => Kind::GetAppend,
                        b'h' => Kind::Hold,
                        b'H' => Kind::HoldAppend,
                        b'l' => Kind::List,
                        b'n' => Kind::Next,
                        b'N' => Kind::NextAppend,
                        b'p' => Kind::Print,
                        b'P' => Kind::PrintFirst,
                        b'q' => Kind::Quit,
                        b'x' => Kind::Exchange,
                        _ => Kind::LineNumber,
                    }
                }
                b'\n' | b';' => {
                    self.p -= 1;
                    return Err(self.err("command expected"));
                }
                _ => {
                    self.p -= 1;
                    return Err(self.err(format!("unknown command: `{}'", c as char)));
                }
            };
            self.cmds.push(Cmd { a1, a2, neg, kind, start: 0 });
        }
        if !blocks.is_empty() {
            return Err(self.err("unexpected EOF (pending }'s)"));
        }
        let n = self.cmds.len();
        for i in 0..n {
            let (Kind::Branch(t, l) | Kind::Test(t, l)) = &mut self.cmds[i].kind else { continue };
            if l.is_empty() {
                *t = n;
            } else {
                match self.labels.get(l) {
                    Some(&j) => *t = j,
                    None => {
                        let l = String::from_utf8_lossy(l).into_owned();
                        return Err(Fatal(format!("{}: undefined label '{l}'", self.units.last().map_or("", |u| u.1.as_str()))));
                    }
                }
            }
        }
        Ok((self.cmds, self.labels))
    }
}

// --- output ----------------------------------------------------------------------------------

struct Out {
    w: Box<dyn Write>,
    /// The last line written lacked its newline: write one before anything else.
    missing_nl: bool,
    /// Writes go to the main output (`w /dev/stdout`).
    alias_stdout: bool,
    flush_each: bool,
}

impl Out {
    fn new(w: Box<dyn Write>, flush_each: bool) -> Out {
        Out { w, missing_nl: false, alias_stdout: false, flush_each }
    }

    fn stdout_alias() -> Out {
        Out { w: Box::new(io::sink()), missing_nl: false, alias_stdout: true, flush_each: false }
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        if self.missing_nl {
            self.missing_nl = false;
            self.w.write_all(b"\n")?;
        }
        self.w.write_all(b)
    }

    /// A line: `b`, then a newline unless `nl` is false (the input's last line had none).
    fn line(&mut self, b: &[u8], nl: bool) -> io::Result<()> {
        self.put(b)?;
        if nl {
            self.w.write_all(b"\n")?;
        } else {
            self.missing_nl = true;
        }
        if self.flush_each {
            self.w.flush()?;
        }
        Ok(())
    }
}

// --- input -----------------------------------------------------------------------------------

struct Line {
    text: Vec<u8>,
    nl: bool,
    /// Index of the file it came from.
    file: usize,
}

struct Input {
    files: Vec<OsString>,
    next_file: usize,
    cur: Option<(Box<dyn BufRead>, usize)>,
    peeked: Option<Line>,
    /// `-i`: `$` is the last line of each file.
    separate: bool,
    errors: bool,
}

impl Input {
    fn open_next(&mut self) -> bool {
        while self.next_file < self.files.len() {
            let i = self.next_file;
            self.next_file += 1;
            let f = &self.files[i];
            if f.as_bytes() == b"-" {
                self.cur = Some((Box::new(BufReader::new(io::stdin())), i));
                return true;
            }
            match File::open(f) {
                Ok(h) => {
                    if h.metadata().is_ok_and(|m| m.is_dir()) {
                        eprintln!("sed: {}: {}", f.to_string_lossy(), strerror(&io::Error::from_raw_os_error(libc::EISDIR)));
                        self.errors = true;
                        continue;
                    }
                    self.cur = Some((Box::new(BufReader::with_capacity(64 * 1024, h)), i));
                    return true;
                }
                Err(e) => {
                    eprintln!("sed: {}: {}", f.to_string_lossy(), strerror(&e));
                    self.errors = true;
                }
            }
        }
        false
    }

    fn fill(&mut self) {
        if self.peeked.is_some() {
            return;
        }
        loop {
            if self.cur.is_none() && !self.open_next() {
                return;
            }
            let (r, idx) = self.cur.as_mut().unwrap();
            let mut text = Vec::new();
            match r.read_until(b'\n', &mut text) {
                Ok(0) => {
                    self.cur = None;
                }
                Ok(_) => {
                    let nl = text.last() == Some(&b'\n');
                    if nl {
                        text.pop();
                    }
                    self.peeked = Some(Line { text, nl, file: *idx });
                    return;
                }
                Err(e) => {
                    eprintln!("sed: {}: {}", self.files[*idx].to_string_lossy(), strerror(&e));
                    self.errors = true;
                    self.cur = None;
                }
            }
        }
    }

    /// Whether any input is left at all.
    fn has_more(&mut self) -> bool {
        self.fill();
        self.peeked.is_some()
    }

    fn next(&mut self) -> Option<Line> {
        self.fill();
        self.peeked.take()
    }

    /// Whether the line from file `file` just read is the last (of the input, or with `-i` of
    /// its file).
    fn is_last(&mut self, file: usize) -> bool {
        self.fill();
        match &self.peeked {
            None => true,
            Some(l) => self.separate && l.file != file,
        }
    }
}

// --- execution -------------------------------------------------------------------------------

enum Append {
    Text(Vec<u8>),
    File(Vec<u8>),
}

/// In-place editing of one file.
struct InPlace {
    ext: Vec<u8>,
    /// -i (each file its own stream) rather than -I.
    separate: bool,
    /// The file being written: its index, path and temporary.
    cur: Option<(usize, PathBuf, PathBuf)>,
}

struct Sed {
    cmds: Vec<Cmd>,
    out: Out,
    wfiles: Vec<(Vec<u8>, Out)>,
    nflag: bool,
    ps: Vec<u8>,
    ps_nl: bool,
    hold: Vec<u8>,
    appends: Vec<Append>,
    input: Input,
    lineno: u64,
    cur_file: usize,
    last_re: Option<Rc<Regex>>,
    tflag: bool,
    inplace: Option<InPlace>,
    flush_each: bool,
    list_width: usize,
    /// `N` on the last line: quit without the automatic output.
    quiet_quit: bool,
}

enum Flow {
    Continue,
    /// End of the cycle: autoprint unless `false`.
    End(bool),
    /// `D` with a newline: restart the script on what is left.
    Restart,
    Quit,
}

fn wr_err(e: io::Error) -> Fatal {
    Fatal(format!("stdout: {}", strerror(&e)))
}

impl Sed {
    fn out_for(&mut self, w: usize) -> &mut Out {
        if self.wfiles[w].1.alias_stdout { &mut self.out } else { &mut self.wfiles[w].1 }
    }

    fn regex(&mut self, r: &Option<Rc<Regex>>) -> Result<Rc<Regex>, Fatal> {
        match r {
            Some(r) => {
                self.last_re = Some(r.clone());
                Ok(r.clone())
            }
            None => self.last_re.clone().ok_or_else(|| Fatal("no previous regular expression".into())),
        }
    }

    fn addr_matches(&mut self, a: &Addr) -> Result<bool, Fatal> {
        Ok(match a {
            Addr::Line(n) => self.lineno == *n,
            Addr::Last => self.input.is_last(self.cur_file),
            Addr::Re(r) => {
                let re = self.regex(r)?;
                match re.try_is_match_at(&self.ps, 0..self.ps.len(), ExecFlags::NONE) {
                    Ok(m) => m,
                    Err(e) => return Err(Fatal(format!("RE error: {}", e.kind.message()))),
                }
            }
            Addr::Rel(_) => false,
        })
    }

    /// Whether command `i` applies to this line (FreeBSD's `applies`).
    fn applies(&mut self, i: usize) -> Result<bool, Fatal> {
        let (a1, a2) = (self.cmds[i].a1.clone(), self.cmds[i].a2.clone());
        let r = match (a1, a2) {
            (None, _) => true,
            (Some(a1), None) => self.addr_matches(&a1)?,
            (Some(a1), Some(a2)) => {
                if self.cmds[i].start > 0 {
                    match a2 {
                        Addr::Rel(n) => {
                            if self.lineno - self.cmds[i].start <= n {
                                if self.lineno - self.cmds[i].start == n {
                                    self.cmds[i].start = 0;
                                }
                                true
                            } else {
                                self.cmds[i].start = 0;
                                false
                            }
                        }
                        Addr::Line(n) if self.lineno > n => {
                            // A branch skipped the end line: close the range.
                            self.cmds[i].start = 0;
                            false
                        }
                        a2 => {
                            if self.addr_matches(&a2)? {
                                self.cmds[i].start = 0;
                            }
                            true
                        }
                    }
                } else if self.addr_matches(&a1)? {
                    let one = match a2 {
                        Addr::Line(n) => self.lineno >= n,
                        Addr::Rel(0) => true,
                        _ => false,
                    };
                    if !one {
                        self.cmds[i].start = self.lineno;
                    }
                    true
                } else {
                    false
                }
            }
        };
        Ok(r != self.cmds[i].neg)
    }

    fn flush_appends(&mut self) -> Result<(), Fatal> {
        for a in std::mem::take(&mut self.appends) {
            match a {
                Append::Text(t) => {
                    self.out.put(&t).map_err(wr_err)?;
                    self.out.put(b"\n").map_err(wr_err)?;
                }
                Append::File(f) => {
                    let mut data = Vec::new();
                    // A file that can't be read is silently ignored (POSIX).
                    if let Ok(mut h) = File::open(OsStr::from_bytes(&f)) {
                        let _ = h.read_to_end(&mut data);
                    }
                    if !data.is_empty() {
                        self.out.put(&data).map_err(wr_err)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Ends in-place output for the current file, renaming the temporary over it.
    fn finish_inplace(&mut self) -> Result<(), Fatal> {
        let Some(ip) = self.inplace.as_mut() else { return Ok(()) };
        let Some((_, path, tmp)) = ip.cur.take() else { return Ok(()) };
        let ext = ip.ext.clone();
        self.out.w.flush().map_err(|e| Fatal(format!("{}: {}", tmp.display(), strerror(&e))))?;
        self.out = Out::new(Box::new(io::sink()), false);
        if !ext.is_empty() {
            let mut b = path.clone().into_os_string().into_vec();
            b.extend_from_slice(&ext);
            let backup = PathBuf::from(OsString::from_vec(b));
            if let Err(e) = std::fs::rename(&path, &backup) {
                return Err(Fatal(format!("{}: {}", backup.display(), strerror(&e))));
            }
        }
        std::fs::rename(&tmp, &path).map_err(|e| Fatal(format!("{}: {}", path.display(), strerror(&e))))
    }

    /// Starts in-place output for file `idx`.
    fn start_inplace(&mut self, idx: usize) -> Result<(), Fatal> {
        let path = PathBuf::from(&self.input.files[idx]);
        let meta = std::fs::metadata(&path).map_err(|e| Fatal(format!("{}: {}", path.display(), strerror(&e))))?;
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let base = path.file_name().map(|b| b.as_bytes().to_vec()).unwrap_or_default();
        let mut tname = format!(".!{}!", std::process::id()).into_bytes();
        tname.extend_from_slice(&base);
        let tmp = dir.join(OsStr::from_bytes(&tname));
        let f = File::create(&tmp).map_err(|e| Fatal(format!("{}: {}", tmp.display(), strerror(&e))))?;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(meta.permissions().mode() & 0o7777));
        self.out = Out::new(Box::new(BufWriter::with_capacity(64 * 1024, f)), false);
        if let Some(ip) = self.inplace.as_mut() {
            ip.cur = Some((idx, path, tmp));
        }
        Ok(())
    }

    /// Reads the next line into a fresh pattern space (`append`: after a newline, for `N`).
    fn read_line(&mut self, append: bool) -> Result<bool, Fatal> {
        let Some(l) = self.input.next() else { return Ok(false) };
        if l.file != self.cur_file || self.lineno == 0 {
            let switching = l.file != self.cur_file || self.inplace.as_ref().is_some_and(|ip| ip.cur.is_none());
            self.cur_file = l.file;
            if switching && self.inplace.is_some() {
                self.finish_inplace()?;
                self.start_inplace(l.file)?;
                if self.inplace.as_ref().unwrap().separate {
                    self.lineno = 0;
                    for c in &mut self.cmds {
                        c.start = 0;
                    }
                }
            }
        }
        self.lineno += 1;
        if append {
            self.ps.push(b'\n');
            self.ps.extend_from_slice(&l.text);
        } else {
            self.ps = l.text;
        }
        self.ps_nl = l.nl;
        Ok(true)
    }

    fn list(&mut self) -> Result<(), Fatal> {
        let w = self.list_width.max(2);
        let mut o: Vec<u8> = Vec::new();
        let mut col = 0;
        for &c in &self.ps {
            let esc: Vec<u8> = match c {
                b'\\' => b"\\\\".to_vec(),
                0x07 => b"\\a".to_vec(),
                0x08 => b"\\b".to_vec(),
                0x0c => b"\\f".to_vec(),
                b'\n' => b"\\n".to_vec(),
                b'\r' => b"\\r".to_vec(),
                b'\t' => b"\\t".to_vec(),
                0x0b => b"\\v".to_vec(),
                c if (0x20..0x7f).contains(&c) => vec![c],
                c => format!("\\{c:03o}").into_bytes(),
            };
            if col + esc.len() > w - 1 {
                o.extend_from_slice(b"\\\n");
                col = 0;
            }
            col += esc.len();
            o.extend_from_slice(&esc);
        }
        o.extend_from_slice(b"$");
        self.out.line(&o, true).map_err(wr_err)
    }

    fn substitute(&mut self, i: usize) -> Result<(), Fatal> {
        let Kind::Subst(sub) = &self.cmds[i].kind else { unreachable!() };
        let re = match &sub.re {
            Some(r) => r.clone(),
            None => self.last_re.clone().ok_or_else(|| Fatal("no previous regular expression".into()))?,
        };
        self.last_re = Some(re.clone());
        let Kind::Subst(sub) = &self.cmds[i].kind else { unreachable!() };
        let ps = &self.ps;
        let len = ps.len();
        let mut out: Vec<u8> = Vec::new();
        let mut pos = 0;
        let mut count = 0u64;
        let mut made = false;
        let mut last_end: Option<usize> = None;
        while pos <= len {
            let fl = if pos > 0 { ExecFlags::NOTBOL } else { ExecFlags::NONE };
            // Only the extent is needed unless the replacement names a group.
            let r = if sub.groups { re.try_captures_at(ps, pos..len, fl) } else { re.try_find_at(ps, pos..len, fl).map(|m| m.map(|m| vec![Some(m)])) };
            let caps = match r {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => return Err(Fatal(format!("RE error: {}", e.kind.message()))),
            };
            let (s, e) = caps[0].unwrap();
            if s == e && last_end == Some(s) {
                // An empty match right after the last match doesn't count.
                if s >= len {
                    break;
                }
                out.push(ps[s]);
                pos = s + 1;
                continue;
            }
            count += 1;
            out.extend_from_slice(&ps[pos..s]);
            if count >= sub.nth {
                for part in &sub.repl {
                    match part {
                        ReplPart::Lit(l) => out.extend_from_slice(l),
                        ReplPart::Group(g) => {
                            if let Some(Some((a, b))) = caps.get(*g) {
                                out.extend_from_slice(&ps[*a..*b]);
                            }
                        }
                    }
                }
                made = true;
            } else {
                out.extend_from_slice(&ps[s..e]);
            }
            last_end = Some(e);
            pos = e;
            if made && !sub.global {
                break;
            }
            if s == e {
                if s >= len {
                    break;
                }
                out.push(ps[s]);
                pos = s + 1;
            }
        }
        if !made {
            return Ok(());
        }
        if pos < len {
            out.extend_from_slice(&ps[pos..]);
        }
        self.ps = out;
        self.tflag = true;
        let (print, wfile) = (sub.print, sub.wfile);
        if print {
            let nl = self.ps_nl;
            self.out.line(&self.ps.clone(), nl).map_err(wr_err)?;
        }
        if let Some(w) = wfile {
            let ps = self.ps.clone();
            self.out_for(w).line(&ps, true).map_err(wr_err)?;
        }
        Ok(())
    }

    fn exec(&mut self, i: usize, pc: &mut usize) -> Result<Flow, Fatal> {
        match &self.cmds[i].kind {
            Kind::Block(past) => {
                // Only reached when the block's addresses don't select the line.
                *pc = *past;
            }
            Kind::EndBlock | Kind::Label => {}
            Kind::Append(t) => self.appends.push(Append::Text(t.clone())),
            Kind::Insert(t) => {
                let t = t.clone();
                self.out.line(&t, true).map_err(wr_err)?;
            }
            Kind::Change(t) => {
                let c = &self.cmds[i];
                let t = t.clone();
                if c.a2.is_none() || c.neg || c.start == 0 || self.input.is_last(self.cur_file) {
                    self.out.line(&t, true).map_err(wr_err)?;
                }
                return Ok(Flow::End(false));
            }
            Kind::Branch(t, _) => *pc = *t,
            Kind::Test(t, _) => {
                if self.tflag {
                    self.tflag = false;
                    *pc = *t;
                }
            }
            Kind::Delete => return Ok(Flow::End(false)),
            Kind::DeleteFirst => match self.ps.iter().position(|&c| c == b'\n') {
                None => return Ok(Flow::End(false)),
                Some(n) => {
                    self.ps.drain(..=n);
                    return Ok(Flow::Restart);
                }
            },
            Kind::Get => self.ps = self.hold.clone(),
            Kind::GetAppend => {
                self.ps.push(b'\n');
                let h = self.hold.clone();
                self.ps.extend_from_slice(&h);
            }
            Kind::Hold => self.hold = self.ps.clone(),
            Kind::HoldAppend => {
                self.hold.push(b'\n');
                let p = self.ps.clone();
                self.hold.extend_from_slice(&p);
            }
            Kind::Exchange => std::mem::swap(&mut self.ps, &mut self.hold),
            Kind::List => self.list()?,
            Kind::Next => {
                if self.input.is_last(self.cur_file) {
                    // No next line: quit (the automatic output happens once, there); with -i,
                    // end this file's last cycle and go on to the next file.
                    return Ok(if self.input.has_more() { Flow::End(true) } else { Flow::Quit });
                }
                if !self.nflag {
                    let nl = self.ps_nl;
                    self.out.line(&self.ps.clone(), nl).map_err(wr_err)?;
                }
                self.flush_appends()?;
                if !self.read_line(false)? {
                    return Ok(Flow::End(false));
                }
            }
            Kind::NextAppend => {
                if self.input.is_last(self.cur_file) {
                    // POSIX and the BSDs: quit without writing the pattern space.
                    if self.input.has_more() {
                        return Ok(Flow::End(false));
                    }
                    self.quiet_quit = true;
                    return Ok(Flow::Quit);
                }
                self.flush_appends()?;
                if !self.read_line(true)? {
                    return Ok(Flow::End(false));
                }
            }
            Kind::Print => {
                let nl = self.ps_nl;
                self.out.line(&self.ps.clone(), nl).map_err(wr_err)?;
            }
            Kind::PrintFirst => {
                let n = self.ps.iter().position(|&c| c == b'\n').unwrap_or(self.ps.len());
                let first = self.ps[..n].to_vec();
                let nl = self.ps_nl || n < self.ps.len();
                self.out.line(&first, nl).map_err(wr_err)?;
            }
            Kind::Quit => return Ok(Flow::Quit),
            Kind::Read(f) => self.appends.push(Append::File(f.clone())),
            Kind::Write(w) => {
                let w = *w;
                let ps = self.ps.clone();
                self.out_for(w).line(&ps, true).map_err(wr_err)?;
            }
            Kind::Subst(_) => self.substitute(i)?,
            Kind::Translate(t) => {
                let t = t.clone();
                for c in &mut self.ps {
                    *c = t[*c as usize];
                }
            }
            Kind::LineNumber => {
                let s = format!("{}", self.lineno);
                self.out.line(s.as_bytes(), true).map_err(wr_err)?;
            }
        }
        Ok(Flow::Continue)
    }

    fn run(&mut self) -> Result<(), Fatal> {
        let mut restart = false;
        loop {
            if !restart {
                if !self.read_line(false)? {
                    break;
                }
                self.tflag = false;
            }
            restart = false;
            let mut pc = 0;
            let mut flow = Flow::End(true);
            while pc < self.cmds.len() {
                let i = pc;
                pc += 1;
                if !self.applies(i)? {
                    if let Kind::Block(past) = self.cmds[i].kind {
                        pc = past;
                    }
                    continue;
                }
                if let Kind::Block(_) = self.cmds[i].kind {
                    continue;
                }
                match self.exec(i, &mut pc)? {
                    Flow::Continue => {}
                    f => {
                        flow = f;
                        break;
                    }
                }
            }
            match flow {
                Flow::Continue | Flow::End(true) => {
                    if !self.nflag {
                        let nl = self.ps_nl;
                        self.out.line(&self.ps.clone(), nl).map_err(wr_err)?;
                    }
                    self.flush_appends()?;
                }
                Flow::End(false) => self.flush_appends()?,
                Flow::Restart => restart = true,
                Flow::Quit => {
                    if !self.nflag && !self.quiet_quit {
                        let nl = self.ps_nl;
                        self.out.line(&self.ps.clone(), nl).map_err(wr_err)?;
                    }
                    self.flush_appends()?;
                    break;
                }
            }
            if self.flush_each {
                self.out.w.flush().map_err(wr_err)?;
            }
        }
        self.finish_inplace()?;
        self.out.w.flush().map_err(wr_err)?;
        for (_, w) in &mut self.wfiles {
            let _ = w.w.flush();
        }
        Ok(())
    }
}

// --- main ------------------------------------------------------------------------------------

fn script_name(text: &[u8]) -> String {
    let t = String::from_utf8_lossy(text);
    let first: String = t.chars().take(30).collect();
    if first.len() < t.len() { format!("\"{first}...\"") } else { format!("\"{first}\"") }
}

pub(crate) fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut units: Vec<Unit> = Vec::new();
    let (mut ere, mut nflag, mut flush_each) = (false, false, false);
    let mut inplace: Option<InPlace> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_bytes();
        if a == b"--" {
            i += 1;
            break;
        }
        if a.len() < 2 || a[0] != b'-' {
            break;
        }
        i += 1;
        let mut j = 1;
        while j < a.len() {
            let c = a[j];
            j += 1;
            match c {
                b'E' | b'r' => ere = true,
                b'n' => nflag = true,
                b'a' => {}
                b'l' | b'u' => flush_each = true,
                b'e' | b'f' | b'i' | b'I' => {
                    let val: Vec<u8> = if j < a.len() {
                        let v = a[j..].to_vec();
                        j = a.len();
                        v
                    } else if i < args.len() {
                        i += 1;
                        args[i - 1].as_bytes().to_vec()
                    } else {
                        eprintln!("sed: option requires an argument -- {}", c as char);
                        return usage();
                    };
                    match c {
                        b'e' => {
                            let name = script_name(&val);
                            units.push(Unit { text: val, name });
                        }
                        b'f' => {
                            let mut data = Vec::new();
                            let r = if val == b"-" {
                                io::stdin().lock().read_to_end(&mut data)
                            } else {
                                File::open(OsStr::from_bytes(&val)).and_then(|mut f| f.read_to_end(&mut data))
                            };
                            if let Err(e) = r {
                                eprintln!("sed: {}: {}", String::from_utf8_lossy(&val), strerror(&e));
                                return ExitCode::from(1);
                            }
                            if data.last() == Some(&b'\n') {
                                data.pop();
                            }
                            units.push(Unit { text: data, name: String::from_utf8_lossy(&val).into_owned() });
                        }
                        _ => inplace = Some(InPlace { ext: val, separate: c == b'i', cur: None }),
                    }
                }
                _ => {
                    eprintln!("sed: illegal option -- {}", c as char);
                    return usage();
                }
            }
        }
    }
    if units.is_empty() {
        if i >= args.len() {
            return usage();
        }
        let t = args[i].as_bytes().to_vec();
        i += 1;
        let name = script_name(&t);
        units.push(Unit { text: t, name });
    }
    let mut files: Vec<OsString> = args[i..].to_vec();
    if files.is_empty() {
        if inplace.is_some() {
            eprintln!("sed: -I or -i may not be used with stdin");
            return ExitCode::from(1);
        }
        files.push("-".into());
    }
    let mut script: Vec<u8> = Vec::new();
    let mut starts: Vec<(usize, String)> = Vec::new();
    for (k, u) in units.iter().enumerate() {
        if k > 0 {
            script.push(b'\n');
        }
        starts.push((script.len(), u.name.clone()));
        script.extend_from_slice(&u.text);
    }
    if script.starts_with(b"#n") && (script.len() == 2 || script[2] == b'\n') {
        nflag = true;
    }
    let mut wfiles: Vec<(Vec<u8>, Out)> = Vec::new();
    let parser = Parser { s: &script, p: 0, units: &starts, ere, cmds: Vec::new(), labels: HashMap::new(), wfiles: &mut wfiles };
    let cmds = match parser.parse() {
        Ok((c, _)) => c,
        Err(Fatal(m)) => {
            eprintln!("sed: {m}");
            return ExitCode::from(1);
        }
    };
    let list_width = std::env::var("COLUMNS").ok().and_then(|c| c.parse::<usize>().ok()).filter(|&c| c > 0).unwrap_or(60);
    let separate = inplace.as_ref().is_some_and(|ip| ip.separate);
    if let Some(ip) = &inplace {
        // Only regular files can be edited in place; leave the others out.
        let _ = ip;
        files.retain(|f| match std::fs::metadata(f) {
            Ok(m) if !m.is_file() => {
                eprintln!("sed: {}: in-place editing only works for regular files", f.to_string_lossy());
                false
            }
            _ => true,
        });
    }
    let main_out: Box<dyn Write> = if inplace.is_some() {
        Box::new(io::sink())
    } else {
        Box::new(BufWriter::with_capacity(64 * 1024, io::stdout()))
    };
    let mut sed = Sed {
        cmds,
        out: Out::new(main_out, flush_each),
        wfiles,
        nflag,
        ps: Vec::new(),
        ps_nl: true,
        hold: Vec::new(),
        appends: Vec::new(),
        input: Input { files, next_file: 0, cur: None, peeked: None, separate, errors: false },
        lineno: 0,
        cur_file: 0,
        last_re: None,
        tflag: false,
        inplace,
        flush_each,
        list_width,
        quiet_quit: false,
    };
    // `w /dev/stdout` under -i still means the standard output.
    if sed.inplace.is_some() {
        for (_, w) in &mut sed.wfiles {
            if w.alias_stdout {
                *w = Out::new(Box::new(BufWriter::new(io::stdout())), flush_each);
            }
        }
    }
    let r = sed.run();
    for (_, w) in &mut sed.wfiles {
        let _ = w.w.flush();
    }
    match r {
        Ok(()) => ExitCode::from(sed.input.errors as u8),
        Err(Fatal(m)) => {
            let _ = sed.out.w.flush();
            eprintln!("sed: {m}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delim(s: &str, ere: bool) -> Result<Vec<u8>, String> {
        let units = vec![(0, "t".to_string())];
        let mut wf = Vec::new();
        let mut p = Parser { s: s.as_bytes(), p: 0, units: &units, ere, cmds: Vec::new(), labels: HashMap::new(), wfiles: &mut wf };
        p.delimited(b'/', true, "x").map_err(|f| f.0)
    }

    #[test]
    fn delimited_regex() {
        assert_eq!(delim("a\\/b/", false).unwrap(), b"a/b");
        assert_eq!(delim("a\\nb/", false).unwrap(), b"a\nb");
        assert_eq!(delim("[/]x/", false).unwrap(), b"[/]x");
        assert_eq!(delim("[]/]/", false).unwrap(), b"[]/]");
        assert_eq!(delim("[[:alpha:]/]/", false).unwrap(), b"[[:alpha:]/]");
        assert_eq!(delim("[\\n]/", false).unwrap(), b"[\n]");
        assert_eq!(delim("\\(a\\)/", false).unwrap(), b"\\(a\\)");
        assert!(delim("abc", false).is_err());
        assert!(delim("[abc/", false).is_err());
    }

    #[test]
    fn escaped_delimiter_is_literal() {
        let units = vec![(0, "t".to_string())];
        let mut wf = Vec::new();
        let mut p = Parser { s: b"a\\.b.", p: 0, units: &units, ere: false, cmds: Vec::new(), labels: HashMap::new(), wfiles: &mut wf };
        assert_eq!(p.delimited(b'.', true, "x").map_err(|f| f.0).unwrap(), b"a\\.b");
        let mut p = Parser { s: b"a\\|b|", p: 0, units: &units, ere: true, cmds: Vec::new(), labels: HashMap::new(), wfiles: &mut wf };
        assert_eq!(p.delimited(b'|', true, "x").map_err(|f| f.0).unwrap(), b"a\\|b");
        let mut p = Parser { s: b"a\\|b|", p: 0, units: &units, ere: false, cmds: Vec::new(), labels: HashMap::new(), wfiles: &mut wf };
        assert_eq!(p.delimited(b'|', true, "x").map_err(|f| f.0).unwrap(), b"a|b");
    }
}
