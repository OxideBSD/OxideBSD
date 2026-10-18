//! `grep(1)`, `egrep(1)`, `fgrep(1)`: print the lines that match patterns.
//!
//! ```text
//! grep [-abcEFGHhIiLlnOopqRrSsUvwxy] [-A num] [-B num] [-C num] [-d action] [-e pattern]
//!      [-f file] [-m num] [--color[=when]] [--exclude=glob] [--exclude-dir=glob]
//!      [--include=glob] [--line-buffered] [--null] [pattern] [file ...]
//! ```
//!
//! One program; run as `egrep` it starts with `-E`, as `fgrep` with `-F` (FreeBSD's way). It is
//! line oriented over bytes: a line is everything up to a newline, the newline not included, and
//! the last line of a file needs none. Patterns come from `-e` and `-f` (any number of each) or
//! the first operand; a pattern with newlines in it is one pattern per line, and a line matches
//! when any of them does. A null pattern matches every line; `-f /dev/null` matches none.
//!
//! - Syntax: `-G` basic regular expressions (the default), `-E` extended, `-F` fixed strings.
//!   `-i` (and the obsolete `-y`) ignores case, `-w` matches only whole words (bounded by
//!   characters other than letters, digits and `_`, or the line's ends), `-x` whole lines.
//! - Selection: `-v` selects the lines that don't match; `-m num` stops each file after `num`
//!   selected lines.
//! - Output: the lines, each prefixed with its file name when more than one file is searched or
//!   `-r` is given (`-H` always, `-h` never), then `-n` its line number and `-b` its byte offset.
//!   `-o` prints only the matching parts, one per line. `-c` counts instead; `-l` names the files
//!   with a selected line, `-L` those without; `-q` prints nothing and stops at the first. `-A`,
//!   `-B` and `-C` (or `-num`) add lines of context after, before or around, a `--` line between
//!   groups that aren't adjacent; context lines take `-` where selected lines take `:`.
//!   `--color` (`auto` on a terminal, `always`, `never`) highlights matches in `GREP_COLOR` or
//!   `GREP_COLORS`'s `mt=`/`ms=` (default `01;31`). `--null` ends a file name with a NUL byte.
//!   `--line-buffered` flushes every line.
//! - Files: `-` is the standard input, as is no operand at all (or the working directory with
//!   `-r`). `-r` and `-R` search directories recursively without following symbolic links found
//!   inside them (`-p`, the default); `-S` follows every link, `-O` only those on the command
//!   line (which are always followed). `--include`, `--exclude` and `--exclude-dir` filter what
//!   a recursive search reads by a glob on the base name. `-d skip|read|recurse` says what to do
//!   with a directory operand (`read` fails, as reading a directory does). `-s` keeps quiet
//!   about missing and unreadable files.
//! - Binary files (a NUL byte in their first 32 KiB): a match prints `Binary file NAME matches`
//!   instead of the line; `-a` (or `--binary-files=text`) treats them as text, `-I` (or
//!   `--binary-files=without-match`) as not matching. `-U` is accepted.
//!
//! The exit status is 0 when a line was selected, 1 when none was, and 2 on an error, except
//! that with `-q` a selected line gives 0 regardless (POSIX). Output is buffered (a console
//! write costs about a millisecond) and flushed at exit, before error messages, and per line
//! with `--line-buffered`.

use std::collections::VecDeque;
use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use posixre::{CompileFlags, ExecFlags, Regex};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Syntax {
    Basic,
    Extended,
    Fixed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lines,
    Count,
    FilesWith,
    FilesWithout,
    Quiet,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Binary {
    Report,
    Text,
    NoMatch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Follow {
    None,
    CommandLine,
    All,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirAction {
    Read,
    Skip,
    Recurse,
}

struct Opts {
    syntax: Syntax,
    icase: bool,
    word: bool,
    line: bool,
    invert: bool,
    max: Option<u64>,
    mode: Mode,
    names: Option<bool>,
    number: bool,
    offset: bool,
    only: bool,
    after: usize,
    before: usize,
    color: Option<Vec<u8>>,
    null: bool,
    line_buffered: bool,
    binary: Binary,
    dirs: DirAction,
    follow: Follow,
    quiet_errors: bool,
    include: Vec<Vec<u8>>,
    exclude: Vec<Vec<u8>>,
    exclude_dir: Vec<Vec<u8>>,
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: grep [-abcEFGHhIiLlnOopqRrSsUvwxy] [-A num] [-B num] [-C num] [-d action]\n\
         \t[-e pattern] [-f file] [-m num] [--color[=when]] [--exclude=glob]\n\
         \t[--exclude-dir=glob] [--include=glob] [--line-buffered] [--null]\n\
         \t[pattern] [file ...]"
    );
    ExitCode::from(2)
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// The compiled patterns.
enum Matcher {
    Fixed(Vec<Vec<u8>>),
    Regex(Vec<Regex>),
}

struct Pats {
    m: Matcher,
    icase: bool,
    word: bool,
    line: bool,
}

/// Where `pat` occurs in `hay` at or after `from`, ignoring ASCII case if asked.
fn find_fixed(hay: &[u8], pat: &[u8], from: usize, icase: bool) -> Option<usize> {
    if pat.is_empty() {
        return (from <= hay.len()).then_some(from);
    }
    if hay.len() < pat.len() {
        return None;
    }
    let last = hay.len() - pat.len();
    let p0 = pat[0];
    let mut i = from;
    while i <= last {
        let c = hay[i];
        if (c == p0 || (icase && c.eq_ignore_ascii_case(&p0)))
            && (if icase { hay[i..i + pat.len()].eq_ignore_ascii_case(pat) } else { &hay[i..i + pat.len()] == pat })
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

impl Pats {
    /// The leftmost-longest match of one pattern starting the search at `from`, before `-w`.
    fn raw_find(&self, idx: usize, line: &[u8], from: usize) -> Option<(usize, usize)> {
        match &self.m {
            Matcher::Fixed(ps) => find_fixed(line, &ps[idx], from, self.icase).map(|s| (s, s + ps[idx].len())),
            Matcher::Regex(rs) => {
                let fl = if from > 0 { ExecFlags::NOTBOL } else { ExecFlags::NONE };
                rs[idx].try_find_at(line, from..line.len(), fl).ok().flatten()
            }
        }
    }

    fn count(&self) -> usize {
        match &self.m {
            Matcher::Fixed(p) => p.len(),
            Matcher::Regex(r) => r.len(),
        }
    }

    /// One pattern's first match at or after `from` that satisfies `-w` and `-x`.
    fn find_one(&self, idx: usize, line: &[u8], from: usize) -> Option<(usize, usize)> {
        if self.line {
            if from > 0 {
                return None;
            }
            // The longest match from the start covers the line if any match does.
            return match self.raw_find(idx, line, 0) {
                Some((0, e)) if e == line.len() => Some((0, e)),
                _ => None,
            };
        }
        let mut pos = from;
        loop {
            let (s, e) = self.raw_find(idx, line, pos)?;
            if !self.word {
                return Some((s, e));
            }
            let ok_start = s == 0 || !is_word(line[s - 1]);
            let ok_end = e == line.len() || !is_word(line[e]);
            if ok_start && ok_end {
                return Some((s, e));
            }
            // A shorter match at the same start may end on a boundary (FreeBSD tries again one
            // byte on; a regular expression can only report its longest).
            if ok_start && e > s {
                if let Some(end) = self.shorter_word_end(idx, line, s, e) {
                    return Some((s, end));
                }
            }
            if s >= line.len() {
                return None;
            }
            pos = s + 1;
        }
    }

    /// For `-w`: the longest end before `e` at which pattern `idx` matches `line[s..end]` whole
    /// and `end` is a word boundary.
    fn shorter_word_end(&self, idx: usize, line: &[u8], s: usize, e: usize) -> Option<usize> {
        let Matcher::Regex(rs) = &self.m else { return None };
        let fl = if s > 0 { ExecFlags::NOTBOL } else { ExecFlags::NONE };
        let mut end = e;
        while end > s + 1 {
            end -= 1;
            if is_word(line[end]) {
                continue;
            }
            if let Ok(Some((ms, me))) = rs[idx].try_find_at(line, s..end, fl | ExecFlags::NOTEOL) {
                if ms == s && me == end {
                    return Some(end);
                }
            }
        }
        None
    }

    /// The leftmost (then longest) match of any pattern at or after `from`.
    fn find(&self, line: &[u8], from: usize) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        for i in 0..self.count() {
            if let Some((s, e)) = self.find_one(i, line, from) {
                best = match best {
                    Some((bs, be)) if bs < s || (bs == s && be >= e) => Some((bs, be)),
                    _ => Some((s, e)),
                };
                if s == from && !self.line && best == Some((s, e)) && e == line.len() {
                    break;
                }
            }
        }
        best
    }

    fn matches(&self, line: &[u8]) -> bool {
        if !self.word && !self.line {
            match &self.m {
                Matcher::Regex(rs) => return rs.iter().any(|r| r.is_match(line, ExecFlags::NONE)),
                Matcher::Fixed(ps) => return ps.iter().any(|p| find_fixed(line, p, 0, self.icase).is_some()),
            }
        }
        (0..self.count()).any(|i| self.find_one(i, line, 0).is_some())
    }
}

/// A shell glob (`*`, `?`, `[...]` with `!` or `^` negation and ranges, `\` quoting) over a base
/// name, for `--include` and `--exclude`.
fn glob(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() {
            match p[pi] {
                b'*' => {
                    star = Some((pi, si));
                    pi += 1;
                    continue;
                }
                b'?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                b'[' => {
                    if let Some((ok, next)) = bracket(p, pi, s[si]) {
                        if ok {
                            pi = next;
                            si += 1;
                            continue;
                        }
                    } else if s[si] == b'[' {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
                b'\\' if pi + 1 < p.len() => {
                    if p[pi + 1] == s[si] {
                        pi += 2;
                        si += 1;
                        continue;
                    }
                }
                c => {
                    if c == s[si] {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
            }
        }
        match star {
            Some((sp, ss)) => {
                pi = sp + 1;
                si = ss + 1;
                star = Some((sp, ss + 1));
            }
            None => return false,
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// A bracket expression at `p[i]`: whether it matches `c`, and the index past it; `None` if it
/// isn't closed (then `[` is literal).
fn bracket(p: &[u8], i: usize, c: u8) -> Option<(bool, usize)> {
    let mut j = i + 1;
    let neg = matches!(p.get(j), Some(b'!' | b'^'));
    if neg {
        j += 1;
    }
    let mut hit = false;
    let mut first = true;
    loop {
        let a = *p.get(j)?;
        if a == b']' && !first {
            return Some((hit != neg, j + 1));
        }
        first = false;
        if p.get(j + 1) == Some(&b'-') && p.get(j + 2).is_some_and(|&b| b != b']') {
            let b = p[j + 2];
            if a <= c && c <= b {
                hit = true;
            }
            j += 3;
        } else {
            if a == c {
                hit = true;
            }
            j += 1;
        }
    }
}

struct Grep {
    o: Opts,
    pats: Pats,
    out: BufWriter<io::Stdout>,
    matched: bool,
    error: bool,
    /// Ancestors (dev, ino) of a recursive search that follows links, against loops.
    seen: Vec<(u64, u64)>,
}

/// The lines held for `-B`.
struct Held {
    lineno: u64,
    offset: u64,
    text: Vec<u8>,
}

impl Grep {
    fn warn(&mut self, msg: &str) {
        let _ = self.out.flush();
        eprintln!("grep: {msg}");
    }

    fn file_error(&mut self, name: &[u8], e: &io::Error) {
        self.error = true;
        if !self.o.quiet_errors {
            let n = String::from_utf8_lossy(name).into_owned();
            self.warn(&format!("{n}: {}", strerror(e)));
        }
    }

    fn wr(&mut self, b: &[u8]) {
        if let Err(e) = self.out.write_all(b) {
            eprintln!("grep: stdout: {}", strerror(&e));
            std::process::exit(2);
        }
    }

    fn end_line(&mut self) {
        self.wr(b"\n");
        if self.o.line_buffered {
            if let Err(e) = self.out.flush() {
                eprintln!("grep: stdout: {}", strerror(&e));
                std::process::exit(2);
            }
        }
    }

    fn prefix(&mut self, name: &[u8], show_name: bool, lineno: u64, offset: u64, sep: u8) {
        if show_name {
            self.wr(name);
            self.wr(if self.o.null { b"\0" } else { std::slice::from_ref(&sep) });
        }
        if self.o.number {
            self.wr(format!("{lineno}").as_bytes());
            self.wr(&[sep]);
        }
        if self.o.offset {
            self.wr(format!("{offset}").as_bytes());
            self.wr(&[sep]);
        }
    }

    fn colored(&mut self, text: &[u8]) {
        let c = self.o.color.clone().unwrap();
        self.wr(b"\x1b[");
        self.wr(&c);
        self.wr(b"m\x1b[K");
        self.wr(text);
        self.wr(b"\x1b[m\x1b[K");
    }

    /// Writes a selected (`sep` `:`) or context (`-`) line.
    fn emit(&mut self, name: &[u8], show_name: bool, lineno: u64, offset: u64, line: &[u8], selected: bool) {
        let sep = if selected { b':' } else { b'-' };
        if self.o.only {
            if !selected || self.o.invert {
                return;
            }
            let mut pos = 0;
            while let Some((s, e)) = self.pats.find(line, pos) {
                if e == s {
                    if s >= line.len() {
                        break;
                    }
                    pos = s + 1;
                    continue;
                }
                self.prefix(name, show_name, lineno, offset + s as u64, sep);
                if self.o.color.is_some() {
                    self.colored(&line[s..e]);
                } else {
                    self.wr(&line[s..e]);
                }
                self.end_line();
                pos = e;
            }
            return;
        }
        self.prefix(name, show_name, lineno, offset, sep);
        if self.o.color.is_some() && selected && !self.o.invert {
            let mut pos = 0;
            let mut done = 0;
            while let Some((s, e)) = self.pats.find(line, pos) {
                if e == s {
                    if s >= line.len() {
                        break;
                    }
                    pos = s + 1;
                    continue;
                }
                self.wr(&line[done..s]);
                self.colored(&line[s..e]);
                done = e;
                pos = e;
            }
            self.wr(&line[done..]);
        } else {
            self.wr(line);
        }
        self.end_line();
    }

    /// Searches one input. Returns the number of selected lines.
    fn search(&mut self, r: &mut dyn Read, name: &[u8], show_name: bool) -> u64 {
        let mut rd = BufReader::with_capacity(64 * 1024, r);
        let mut binary = false;
        if self.o.binary != Binary::Text {
            // The first block decides: a NUL byte makes the file binary.
            loop {
                match rd.fill_buf() {
                    Ok(b) => {
                        binary = b.contains(&0);
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        self.file_error(name, &e);
                        return 0;
                    }
                }
            }
            if binary && self.o.binary == Binary::NoMatch {
                return self.finish(name, show_name, 0);
            }
        }
        let report_binary = binary && self.o.mode == Mode::Lines;
        let ctx = self.o.mode == Mode::Lines && !report_binary && (self.o.after > 0 || self.o.before > 0);
        let mut held: VecDeque<Held> = VecDeque::new();
        let mut after_left = 0usize;
        // The last line written (for the `--` separator), 0 for none yet.
        let mut last_out: u64 = 0;
        let mut count: u64 = 0;
        let mut lineno: u64 = 0;
        let mut offset: u64 = 0;
        let mut buf: Vec<u8> = Vec::new();
        let max = self.o.max;
        if max == Some(0) {
            return self.finish(name, show_name, 0);
        }
        loop {
            buf.clear();
            match rd.read_until(b'\n', &mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.file_error(name, &e);
                    break;
                }
            }
            lineno += 1;
            let line_off = offset;
            offset += buf.len() as u64;
            let line: &[u8] = if buf.last() == Some(&b'\n') { &buf[..buf.len() - 1] } else { &buf };
            let selected = self.pats.matches(line) != self.o.invert;
            if !selected {
                if ctx {
                    if after_left > 0 {
                        after_left -= 1;
                        self.emit(name, show_name, lineno, line_off, line, false);
                        last_out = lineno;
                    } else if self.o.before > 0 {
                        if held.len() == self.o.before {
                            held.pop_front();
                        }
                        held.push_back(Held { lineno, offset: line_off, text: line.to_vec() });
                    }
                    if max.is_some_and(|m| count >= m) && after_left == 0 {
                        break;
                    }
                }
                continue;
            }
            if max.is_some_and(|m| count >= m) {
                // Past -m: only the trailing context goes on, and a selected line ends it.
                break;
            }
            count += 1;
            self.matched = true;
            match self.o.mode {
                Mode::Quiet => {
                    let _ = self.out.flush();
                    std::process::exit(0);
                }
                Mode::FilesWith | Mode::FilesWithout => break,
                Mode::Count => {}
                Mode::Lines if report_binary => {
                    let n = String::from_utf8_lossy(name).into_owned();
                    self.wr(format!("Binary file {n} matches").as_bytes());
                    self.end_line();
                    return count;
                }
                Mode::Lines => {
                    if ctx {
                        let first = held.front().map_or(lineno, |h| h.lineno);
                        if last_out > 0 && first > last_out + 1 {
                            self.wr(b"--");
                            self.end_line();
                        }
                        while let Some(h) = held.pop_front() {
                            self.emit(name, show_name, h.lineno, h.offset, &h.text, false);
                        }
                        after_left = self.o.after;
                    }
                    self.emit(name, show_name, lineno, line_off, line, true);
                    last_out = lineno;
                }
            }
            if max.is_some_and(|m| count >= m) && !(ctx && after_left > 0) {
                break;
            }
        }
        self.finish(name, show_name, count)
    }

    fn name_line(&mut self, name: &[u8]) {
        self.wr(name);
        if self.o.null {
            self.wr(b"\0");
            if self.o.line_buffered {
                let _ = self.out.flush();
            }
        } else {
            self.end_line();
        }
    }

    fn finish(&mut self, name: &[u8], show_name: bool, count: u64) -> u64 {
        match self.o.mode {
            Mode::Count => {
                if show_name {
                    self.wr(name);
                    self.wr(if self.o.null { b"\0" } else { b":" });
                }
                self.wr(format!("{count}").as_bytes());
                self.end_line();
            }
            Mode::FilesWith if count > 0 => self.name_line(name),
            Mode::FilesWithout if count == 0 => self.name_line(name),
            _ => {}
        }
        count
    }

    fn search_path(&mut self, path: &Path, show_name: bool) {
        let name = path.as_os_str().as_bytes().to_vec();
        match File::open(path) {
            Ok(mut f) => {
                self.search(&mut f, &name, show_name);
            }
            Err(e) => self.file_error(&name, &e),
        }
    }

    /// A file operand.
    fn operand(&mut self, f: &OsStr, show_name: bool) {
        if f.as_bytes() == b"-" {
            let stdin = io::stdin();
            let mut l = stdin.lock();
            self.search(&mut l, b"(standard input)", show_name);
            return;
        }
        let path = Path::new(f);
        // Operands are followed whatever -O/-S/-p say.
        match std::fs::metadata(path) {
            Ok(m) if m.is_dir() => match self.o.dirs {
                DirAction::Skip => {}
                DirAction::Recurse => {
                    self.seen.clear();
                    self.seen.push((m.dev(), m.ino()));
                    self.walk(path, show_name);
                }
                DirAction::Read => {
                    let name = f.as_bytes().to_vec();
                    self.file_error(&name, &io::Error::from_raw_os_error(libc::EISDIR));
                }
            },
            Ok(_) => self.search_path(path, show_name),
            Err(e) => self.file_error(f.as_bytes(), &e),
        }
    }

    fn excluded(&self, base: &[u8], dir: bool) -> bool {
        if dir {
            return self.o.exclude_dir.iter().any(|g| glob(g, base));
        }
        if self.o.exclude.iter().any(|g| glob(g, base)) {
            return true;
        }
        !self.o.include.is_empty() && !self.o.include.iter().any(|g| glob(g, base))
    }

    fn walk(&mut self, dir: &Path, show_name: bool) {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => return self.file_error(dir.as_os_str().as_bytes(), &e),
        };
        let mut ents: Vec<(Vec<u8>, PathBuf)> = Vec::new();
        for ent in rd {
            match ent {
                Ok(ent) => ents.push((ent.file_name().into_vec(), ent.path())),
                Err(e) => self.file_error(dir.as_os_str().as_bytes(), &e),
            }
        }
        ents.sort();
        for (base, path) in ents {
            let lm = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    self.file_error(path.as_os_str().as_bytes(), &e);
                    continue;
                }
            };
            let m = if lm.file_type().is_symlink() {
                if self.o.follow != Follow::All {
                    continue;
                }
                match std::fs::metadata(&path) {
                    Ok(m) => m,
                    Err(e) => {
                        self.file_error(path.as_os_str().as_bytes(), &e);
                        continue;
                    }
                }
            } else {
                lm
            };
            if m.is_dir() {
                if self.excluded(&base, true) {
                    continue;
                }
                let id = (m.dev(), m.ino());
                if self.seen.contains(&id) {
                    if !self.o.quiet_errors {
                        let p = path.display().to_string();
                        self.warn(&format!("warning: {p}: recursive directory loop"));
                    }
                    continue;
                }
                self.seen.push(id);
                self.walk(&path, show_name);
                self.seen.pop();
            } else if m.is_file() {
                if !self.excluded(&base, false) {
                    self.search_path(&path, show_name);
                }
            }
            // Devices, FIFOs and sockets found in a tree are skipped: reading one can block.
        }
    }
}

/// Reads `-f`'s patterns: one per line.
fn read_pattern_file(path: &OsStr, pats: &mut Vec<Vec<u8>>) -> Result<(), String> {
    let mut data = Vec::new();
    let r = if path.as_bytes() == b"-" {
        io::stdin().lock().read_to_end(&mut data)
    } else {
        File::open(path).and_then(|mut f| f.read_to_end(&mut data))
    };
    if let Err(e) = r {
        return Err(format!("{}: {}", path.to_string_lossy(), strerror(&e)));
    }
    if data.last() == Some(&b'\n') {
        data.pop();
    } else if data.is_empty() {
        return Ok(());
    }
    pats.extend(data.split(|&c| c == b'\n').map(<[u8]>::to_vec));
    Ok(())
}

fn color_from_env() -> Vec<u8> {
    if let Some(gcs) = std::env::var_os("GREP_COLORS") {
        for f in gcs.as_bytes().split(|&c| c == b':') {
            for key in [&b"mt="[..], b"ms="] {
                if let Some(v) = f.strip_prefix(key) {
                    if !v.is_empty() {
                        return v.to_vec();
                    }
                }
            }
        }
    }
    match std::env::var_os("GREP_COLOR") {
        Some(c) if !c.is_empty() => c.into_vec(),
        _ => b"01;31".to_vec(),
    }
}

fn parse_num(s: &OsStr, what: &str) -> Result<u64, ExitCode> {
    match s.to_str().and_then(|t| t.parse::<u64>().ok()) {
        Some(n) => Ok(n),
        None => {
            eprintln!("grep: {}: invalid {what} argument", s.to_string_lossy());
            Err(ExitCode::from(2))
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(c) | Err(c) => c,
    }
}

fn run() -> Result<ExitCode, ExitCode> {
    let mut argv = std::env::args_os();
    let prog = argv.next().map(|a| a.into_vec()).unwrap_or_default();
    let base = prog.rsplit(|&c| c == b'/').next().unwrap_or(b"grep").to_vec();
    let args: Vec<std::ffi::OsString> = argv.collect();
    let mut o = Opts {
        syntax: match &base[..] {
            b"egrep" => Syntax::Extended,
            b"fgrep" => Syntax::Fixed,
            _ => Syntax::Basic,
        },
        icase: false,
        word: false,
        line: false,
        invert: false,
        max: None,
        mode: Mode::Lines,
        names: None,
        number: false,
        offset: false,
        only: false,
        after: 0,
        before: 0,
        color: None,
        null: false,
        line_buffered: false,
        binary: Binary::Report,
        dirs: DirAction::Read,
        follow: Follow::None,
        quiet_errors: false,
        include: Vec::new(),
        exclude: Vec::new(),
        exclude_dir: Vec::new(),
    };
    let mut pats: Vec<Vec<u8>> = Vec::new();
    let mut have_pats = false;
    let mut operands: Vec<std::ffi::OsString> = Vec::new();
    let mut color_when: Option<String> = None;
    let (mut count, mut list, mut quiet) = (false, None, false);
    // `-num` context: digits accumulate within one argument.
    let mut i = 0;
    let mut only_operands = false;
    while i < args.len() {
        let a = args[i].as_bytes();
        i += 1;
        if only_operands || a.len() < 2 || a[0] != b'-' {
            operands.push(OsStr::from_bytes(a).to_os_string());
            continue;
        }
        if a == b"--" {
            only_operands = true;
            continue;
        }
        if let Some(long) = a.strip_prefix(b"--") {
            let (key, val) = match long.iter().position(|&c| c == b'=') {
                Some(p) => (&long[..p], Some(OsStr::from_bytes(&long[p + 1..]).to_os_string())),
                None => (long, None),
            };
            let key = String::from_utf8_lossy(key).into_owned();
            let need = |val: Option<std::ffi::OsString>, i: &mut usize| -> Result<std::ffi::OsString, ExitCode> {
                if let Some(v) = val {
                    return Ok(v);
                }
                if *i < args.len() {
                    *i += 1;
                    return Ok(args[*i - 1].clone());
                }
                eprintln!("grep: option `--{key}' requires an argument");
                Err(usage())
            };
            match key.as_str() {
                "color" | "colour" => color_when = Some(val.map_or("auto".into(), |v| v.to_string_lossy().into_owned())),
                "include" => o.include.push(need(val, &mut i)?.into_vec()),
                "exclude" => o.exclude.push(need(val, &mut i)?.into_vec()),
                "exclude-dir" => o.exclude_dir.push(need(val, &mut i)?.into_vec()),
                "line-buffered" => o.line_buffered = true,
                "null" => o.null = true,
                "context" => {
                    let n = match val {
                        Some(v) => parse_num(&v, "context length")? as usize,
                        None => 2,
                    };
                    o.after = n;
                    o.before = n;
                }
                "binary-files" => {
                    o.binary = match need(val, &mut i)?.as_bytes() {
                        b"binary" => Binary::Report,
                        b"text" => Binary::Text,
                        b"without-match" => Binary::NoMatch,
                        v => {
                            eprintln!("grep: unknown binary-files option: {}", String::from_utf8_lossy(v));
                            return Err(usage());
                        }
                    }
                }
                "recursive" => o.dirs = DirAction::Recurse,
                "help" => return Err(usage()),
                _ => {
                    eprintln!("grep: unrecognized option `--{key}'");
                    return Err(usage());
                }
            }
            continue;
        }
        let mut j = 1;
        let mut digits: Option<usize> = None;
        while j < a.len() {
            let c = a[j];
            j += 1;
            if c.is_ascii_digit() {
                let d = digits.unwrap_or(0).saturating_mul(10).saturating_add((c - b'0') as usize);
                digits = Some(d);
                o.after = d;
                o.before = d;
                continue;
            }
            digits = None;
            if b"ABCdefm".contains(&c) {
                let val: std::ffi::OsString = if j < a.len() {
                    let v = OsStr::from_bytes(&a[j..]).to_os_string();
                    j = a.len();
                    v
                } else if i < args.len() {
                    i += 1;
                    args[i - 1].clone()
                } else {
                    eprintln!("grep: option requires an argument -- {}", c as char);
                    return Err(usage());
                };
                match c {
                    b'A' => o.after = parse_num(&val, "context length")? as usize,
                    b'B' => o.before = parse_num(&val, "context length")? as usize,
                    b'C' => {
                        let n = parse_num(&val, "context length")? as usize;
                        o.after = n;
                        o.before = n;
                    }
                    b'd' => {
                        o.dirs = match val.as_bytes() {
                            b"read" => DirAction::Read,
                            b"skip" => DirAction::Skip,
                            b"recurse" => DirAction::Recurse,
                            _ => {
                                eprintln!("grep: invalid argument `{}' for -d", val.to_string_lossy());
                                return Err(usage());
                            }
                        }
                    }
                    b'e' => {
                        have_pats = true;
                        pats.extend(val.as_bytes().split(|&c| c == b'\n').map(<[u8]>::to_vec));
                    }
                    b'f' => {
                        have_pats = true;
                        if let Err(m) = read_pattern_file(&val, &mut pats) {
                            eprintln!("grep: {m}");
                            return Err(ExitCode::from(2));
                        }
                    }
                    _ => o.max = Some(parse_num(&val, "max count")?),
                }
                continue;
            }
            match c {
                b'E' => o.syntax = Syntax::Extended,
                b'F' => o.syntax = Syntax::Fixed,
                b'G' => o.syntax = Syntax::Basic,
                b'H' => o.names = Some(true),
                b'h' => o.names = Some(false),
                b'I' => o.binary = Binary::NoMatch,
                b'a' => o.binary = Binary::Text,
                b'U' => {}
                b'i' | b'y' => o.icase = true,
                b'w' => o.word = true,
                b'x' => o.line = true,
                b'v' => o.invert = true,
                b'c' => count = true,
                b'l' => list = Some(Mode::FilesWith),
                b'L' => list = Some(Mode::FilesWithout),
                b'q' => quiet = true,
                b'n' => o.number = true,
                b'b' => o.offset = true,
                b'o' => o.only = true,
                b'r' | b'R' => o.dirs = DirAction::Recurse,
                b'O' => o.follow = Follow::CommandLine,
                b'S' => o.follow = Follow::All,
                b'p' => o.follow = Follow::None,
                b's' => o.quiet_errors = true,
                _ => {
                    eprintln!("grep: illegal option -- {}", c as char);
                    return Err(usage());
                }
            }
        }
    }
    // -q outranks -l and -L, and those -c, whatever the order given.
    o.mode = if quiet {
        Mode::Quiet
    } else if let Some(m) = list {
        m
    } else if count {
        Mode::Count
    } else {
        Mode::Lines
    };
    if !have_pats {
        if operands.is_empty() {
            return Err(usage());
        }
        let p = operands.remove(0);
        pats.extend(p.as_bytes().split(|&c| c == b'\n').map(<[u8]>::to_vec));
    }
    let recursive = o.dirs == DirAction::Recurse;
    if operands.is_empty() {
        operands.push(if recursive { ".".into() } else { "-".into() });
    }
    o.color = match color_when.as_deref() {
        None | Some("never") | Some("no") | Some("none") => None,
        Some("always") | Some("yes") | Some("force") => Some(color_from_env()),
        Some("auto") | Some("tty") | Some("if-tty") => {
            // SAFETY: isatty only reads its argument.
            if unsafe { libc::isatty(1) } == 1 && std::env::var_os("TERM").is_none_or(|t| t != "dumb") {
                Some(color_from_env())
            } else {
                None
            }
        }
        Some(w) => {
            eprintln!("grep: invalid --color argument `{w}'");
            return Err(usage());
        }
    };
    let matcher = match o.syntax {
        Syntax::Fixed => Matcher::Fixed(pats),
        _ => {
            let mut fl = if o.syntax == Syntax::Extended { CompileFlags::EXTENDED } else { CompileFlags::BASIC };
            if o.icase {
                fl = fl | CompileFlags::ICASE;
            }
            let mut rs = Vec::with_capacity(pats.len());
            for p in &pats {
                match Regex::new(p, fl) {
                    Ok(r) => rs.push(r),
                    Err(e) => {
                        eprintln!("grep: {}", e.kind.message());
                        return Err(ExitCode::from(2));
                    }
                }
            }
            Matcher::Regex(rs)
        }
    };
    let pats = Pats { m: matcher, icase: o.icase, word: o.word, line: o.line };
    let show_name = o.names.unwrap_or(operands.len() > 1 || recursive);
    let mut g = Grep { o, pats, out: BufWriter::with_capacity(64 * 1024, io::stdout()), matched: false, error: false, seen: Vec::new() };
    for f in &operands {
        g.operand(f, show_name);
    }
    if let Err(e) = g.out.flush() {
        eprintln!("grep: stdout: {}", strerror(&e));
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::from(match (g.matched, g.error) {
        (true, false) => 0,
        (true, true) => 2,
        (false, false) => 1,
        (false, true) => 2,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob(b"*.c", b"a.c"));
        assert!(!glob(b"*.c", b"a.h"));
        assert!(glob(b"a?c", b"abc"));
        assert!(glob(b"[ab]*", b"bx"));
        assert!(!glob(b"[!ab]*", b"bx"));
        assert!(glob(b"*", b""));
        assert!(glob(b"a*b*c", b"axxbyyc"));
        assert!(!glob(b"a*b*c", b"axxbyy"));
        assert!(glob(b"[a-c]", b"b"));
    }

    fn rx(p: &str, word: bool, line: bool) -> Pats {
        Pats { m: Matcher::Regex(vec![Regex::new(p.as_bytes(), CompileFlags::BASIC).unwrap()]), icase: false, word, line }
    }

    #[test]
    fn words() {
        assert!(rx("ab*", true, false).matches(b"x abb y"));
        assert!(!rx("ab*", true, false).matches(b"abb_"));
        assert!(rx("ab*", true, false).matches(b"abb_ ab"));
        // The longest match ends inside a word, a shorter one on a boundary.
        assert_eq!(rx("a.*", true, false).find(b"a b_c", 0), Some((0, 5)));
        assert_eq!(rx("foo.*", true, false).find(b"foo barx", 0), Some((0, 8)));
        assert_eq!(rx("foo b*", true, false).find(b"foo bbx", 0), None);
        assert_eq!(rx("foo b*", true, false).find(b"foo bb.x", 0), Some((0, 6)));
        assert_eq!(rx("a*", true, false).find(b"xa a", 0), Some((3, 4)));
        assert!(rx("a.c", false, true).matches(b"abc"));
        assert!(!rx("a.c", false, true).matches(b"abcd"));
    }

    #[test]
    fn fixed() {
        assert_eq!(find_fixed(b"hello", b"LL", 0, true), Some(2));
        assert_eq!(find_fixed(b"hello", b"", 3, false), Some(3));
        assert_eq!(find_fixed(b"hello", b"lo", 4, false), None);
    }
}
