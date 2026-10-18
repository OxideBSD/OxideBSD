//! `ed(1)`: the standard line editor.
//!
//! ```text
//! ed [-] [-s] [-p string] [file]
//! ```
//!
//! POSIX's ed over a buffer of lines held in memory. Commands come from the standard input; with
//! `-p` (or after `P`) a prompt is written before each. `-s` (or the historical `-`) leaves out
//! byte counts and the `!` after a shell command.
//!
//! - Addresses: `.`, `$`, a number, `'x` (a mark), `/re/` and `?re?` (searching forward or
//!   backward from the current line, wrapping around), each optionally followed by `+n`, `-n`,
//!   `+`, `-` or `^` (and, as in the BSDs, a number after a blank adds to it). `,` and `%` alone
//!   are `1,$`, `;` alone `.,$`; `a;b` makes `a` current before `b` is evaluated.
//! - Commands: `a`, `c`, `d`, `e`, `E`, `f`, `g`, `G`, `h`, `H`, `i`, `j`, `k`, `l`, `m`, `n`,
//!   `p`, `P`, `q`, `Q`, `r`, `s`, `t`, `u`, `v`, `V`, `w`, `W`, `=`, `!` and the null command, as
//!   POSIX describes them, plus the BSDs' `wq` and `z`. `p`, `l` and `n` may follow most commands.
//!   `s` takes the flags `g`, a count, `p`, `l` and `n`; a replacement of `%` alone is the last
//!   one, and an escaped newline splits the line. `s` with only flags repeats the last
//!   substitution. `u` undoes the last command that changed the buffer (a `g` as a whole), and a
//!   second `u` redoes it. `e`, `r` and `w` take `!command` to read from or write to a shell
//!   command; in `!`, `%` is the current file name and `!!` the last command.
//! - Regular expressions are basic ones; an empty one is the last used.
//!
//! On an error, ed writes `?` (and, after `H`, the explanation) to the standard error; `h`
//! explains the last one. When the standard input is not a terminal an error ends ed with
//! status 2 (as in the BSDs; POSIX requires it for a regular file), and so does a file named on
//! the command line that can't be read. `q` and `e` warn once before discarding unsaved changes.

use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, ExitCode, Stdio};
use std::rc::Rc;

use posixre::{CompileFlags, ExecFlags, Regex};

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

type Res<T> = Result<T, Error>;

#[derive(Debug)]
enum Error {
    /// An ordinary error: `?`, and this explanation for `h`/`H`.
    Msg(String),
    /// `q` or `e` with unsaved changes (the first time).
    Modified,
}

fn err<T>(m: &str) -> Res<T> {
    Err(Error::Msg(m.to_string()))
}

#[derive(Clone)]
struct Line {
    id: u64,
    text: Rc<[u8]>,
    gmark: bool,
}

#[derive(Clone)]
struct Snapshot {
    buf: Vec<Line>,
    dot: usize,
    modified: bool,
}

#[derive(Clone)]
struct LastSub {
    repl: Vec<u8>,
    global: bool,
    nth: usize,
}

/// Where command lines come from: the standard input, or a `g` command list.
struct Source {
    lines: Vec<Vec<u8>>,
    pos: usize,
}

struct Ed {
    buf: Vec<Line>,
    /// The current line, 1-based; 0 when the buffer is empty.
    dot: usize,
    modified: bool,
    warned: bool,
    fname: Option<Vec<u8>>,
    marks: [Option<u64>; 26],
    last_re: Option<Rc<Regex>>,
    last_sub: Option<LastSub>,
    undo: Option<Snapshot>,
    prompt: Vec<u8>,
    prompting: bool,
    scripted: bool,
    verbose: bool,
    last_err: Option<String>,
    next_id: u64,
    last_shell: Option<Vec<u8>>,
    out: BufWriter<io::Stdout>,
    stdin: BufReader<io::Stdin>,
    interactive: bool,
    /// The command list of the `g` being run.
    global: Option<Source>,
    in_global: bool,
    lineno: u64,
    quit: Option<u8>,
}

/// Parsed print suffixes.
#[derive(Clone, Copy, Default)]
struct Print {
    p: bool,
    l: bool,
    n: bool,
}

impl Print {
    fn any(self) -> bool {
        self.p || self.l || self.n
    }
}

fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

impl Ed {
    fn last(&self) -> usize {
        self.buf.len()
    }

    fn new_line(&mut self, text: &[u8]) -> Line {
        self.next_id += 1;
        Line { id: self.next_id, text: Rc::from(text), gmark: false }
    }

    fn wr(&mut self, b: &[u8]) {
        if let Err(e) = self.out.write_all(b) {
            eprintln!("ed: stdout: {}", strerror(&e));
            std::process::exit(2);
        }
    }

    fn flush(&mut self) {
        let _ = self.out.flush();
    }

    /// Reads a line of input (a command or text), without its newline; `None` at the end.
    fn read_line(&mut self) -> Option<Vec<u8>> {
        if let Some(src) = &mut self.global {
            if src.pos < src.lines.len() {
                src.pos += 1;
                return Some(src.lines[src.pos - 1].clone());
            }
            return None;
        }
        self.read_stdin()
    }

    fn read_stdin(&mut self) -> Option<Vec<u8>> {
        self.flush();
        let mut v = Vec::new();
        loop {
            match self.stdin.read_until(b'\n', &mut v) {
                Ok(0) => return if v.is_empty() { None } else { Some(v) },
                Ok(_) => {
                    if v.last() == Some(&b'\n') {
                        v.pop();
                    }
                    self.lineno += 1;
                    return Some(v);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    // An interrupt at the terminal: POSIX ed writes ? and goes on.
                    v.clear();
                    continue;
                }
                Err(_) => return None,
            }
        }
    }

    fn snapshot(&mut self) {
        self.undo = Some(Snapshot { buf: self.buf.clone(), dot: self.dot, modified: self.modified });
    }

    fn set_modified(&mut self) {
        self.modified = true;
        self.warned = false;
    }

    // --- addresses -----------------------------------------------------------------------

    fn compile(&mut self, pat: &[u8]) -> Res<Rc<Regex>> {
        if pat.is_empty() {
            return self.last_re.clone().ok_or_else(|| Error::Msg("no previous pattern".into()));
        }
        match Regex::new(pat, CompileFlags::BASIC) {
            Ok(r) => {
                let r = Rc::new(r);
                self.last_re = Some(r.clone());
                Ok(r)
            }
            Err(e) => err(e.kind.message()),
        }
    }

    /// The pattern up to `delim` (or the end of the line): `\delim` is a literal delimiter, and
    /// a bracket expression is taken whole.
    fn pattern(s: &[u8], p: &mut usize, delim: u8) -> Vec<u8> {
        let mut out = Vec::new();
        while *p < s.len() {
            let c = s[*p];
            if c == delim {
                break;
            }
            if c == b'\\' && *p + 1 < s.len() {
                let n = s[*p + 1];
                *p += 2;
                if n == delim {
                    if b".[]\\*^$".contains(&n) {
                        out.push(b'\\');
                    }
                    out.push(n);
                } else {
                    out.push(b'\\');
                    out.push(n);
                }
                continue;
            }
            if c == b'[' {
                let st = *p;
                *p += 1;
                if s.get(*p) == Some(&b'^') {
                    *p += 1;
                }
                if s.get(*p) == Some(&b']') {
                    *p += 1;
                }
                while *p < s.len() && s[*p] != b']' {
                    if s[*p] == b'[' && matches!(s.get(*p + 1), Some(b'.' | b':' | b'=')) {
                        let k = s[*p + 1];
                        *p += 2;
                        while *p + 1 < s.len() && !(s[*p] == k && s[*p + 1] == b']') {
                            *p += 1;
                        }
                        *p += 2;
                    } else {
                        *p += 1;
                    }
                }
                *p = (*p + 1).min(s.len());
                out.extend_from_slice(&s[st..*p]);
                continue;
            }
            out.push(c);
            *p += 1;
        }
        out
    }

    fn line_matches(&self, re: &Regex, n: usize) -> bool {
        re.is_match(&self.buf[n - 1].text, ExecFlags::NONE)
    }

    fn mark_line(&self, c: u8) -> Res<usize> {
        if !c.is_ascii_lowercase() {
            return err("invalid mark character");
        }
        let Some(id) = self.marks[(c - b'a') as usize] else { return err("invalid address") };
        match self.buf.iter().position(|l| l.id == id) {
            Some(i) => Ok(i + 1),
            None => err("invalid address"),
        }
    }

    fn number(s: &[u8], p: &mut usize) -> Res<usize> {
        let mut n: usize = 0;
        while *p < s.len() && s[*p].is_ascii_digit() {
            n = match n.checked_mul(10).and_then(|n| n.checked_add((s[*p] - b'0') as usize)) {
                Some(n) => n,
                None => return err("number out of range"),
            };
            *p += 1;
        }
        Ok(n)
    }

    /// One address with its offsets, or `None` if there is none here.
    fn one_address(&mut self, s: &[u8], p: &mut usize) -> Res<Option<usize>> {
        while *p < s.len() && is_blank(s[*p]) {
            *p += 1;
        }
        let mut base: Option<isize> = None;
        match s.get(*p) {
            Some(b'.') => {
                *p += 1;
                base = Some(self.dot as isize);
            }
            Some(b'$') => {
                *p += 1;
                base = Some(self.last() as isize);
            }
            Some(c) if c.is_ascii_digit() => base = Some(Self::number(s, p)? as isize),
            Some(b'\'') => {
                *p += 1;
                let Some(&c) = s.get(*p) else { return err("invalid mark character") };
                *p += 1;
                base = Some(self.mark_line(c)? as isize);
            }
            Some(&d @ (b'/' | b'?')) => {
                *p += 1;
                let pat = Self::pattern(s, p, d);
                if *p < s.len() {
                    *p += 1;
                }
                let re = self.compile(&pat)?;
                let n = self.last();
                if n == 0 {
                    return err("no match");
                }
                let mut i = self.dot;
                let mut found = None;
                for _ in 0..n {
                    i = if d == b'/' { if i >= n { 1 } else { i + 1 } } else if i <= 1 { n } else { i - 1 };
                    if self.line_matches(&re, i) {
                        found = Some(i);
                        break;
                    }
                }
                match found {
                    Some(i) => base = Some(i as isize),
                    None => return err("no match"),
                }
            }
            _ => {}
        }
        loop {
            let save = *p;
            while *p < s.len() && is_blank(s[*p]) {
                *p += 1;
            }
            match s.get(*p) {
                Some(&c @ (b'+' | b'-' | b'^')) => {
                    *p += 1;
                    let n = if s.get(*p).is_some_and(u8::is_ascii_digit) { Self::number(s, p)? as isize } else { 1 };
                    let b = base.unwrap_or(self.dot as isize);
                    base = Some(if c == b'+' { b + n } else { b - n });
                }
                Some(c) if c.is_ascii_digit() && base.is_some() && *p > save => {
                    let n = Self::number(s, p)? as isize;
                    base = Some(base.unwrap() + n);
                }
                _ => {
                    *p = save;
                    break;
                }
            }
        }
        match base {
            None => Ok(None),
            Some(b) if b < 0 || b as usize > self.last() => err("invalid address"),
            Some(b) => Ok(Some(b as usize)),
        }
    }

    /// The address list before a command: how many were given (at most 2 count) and the last
    /// two (both the current line when none).
    fn addresses(&mut self, s: &[u8], p: &mut usize) -> Res<(usize, usize, usize)> {
        let mut addrs: Vec<usize> = Vec::new();
        let mut leading = false;
        let mut after_sep = false;
        loop {
            let a = self.one_address(s, p)?;
            while *p < s.len() && is_blank(s[*p]) {
                *p += 1;
            }
            let c = s.get(*p).copied();
            let sep = matches!(c, Some(b',' | b';')) || (c == Some(b'%') && a.is_none() && addrs.is_empty());
            match a {
                Some(a) => {
                    addrs.push(a);
                    leading = false;
                }
                None if sep => {
                    if addrs.is_empty() {
                        addrs.push(if c == Some(b';') { self.dot } else { 1 });
                        leading = true;
                    } else {
                        let l = *addrs.last().unwrap();
                        addrs.push(l);
                    }
                }
                None => {
                    if after_sep {
                        let l = if leading { self.last() } else { *addrs.last().unwrap() };
                        addrs.push(l);
                    }
                    break;
                }
            }
            if !sep {
                break;
            }
            *p += 1;
            after_sep = true;
            if c == Some(b';') {
                self.dot = *addrs.last().unwrap();
            }
        }
        Ok(match addrs.len() {
            0 => (0, self.dot, self.dot),
            1 => (1, addrs[0], addrs[0]),
            n => (2, addrs[n - 2], addrs[n - 1]),
        })
    }

    // --- printing ------------------------------------------------------------------------

    fn print_lines(&mut self, a: usize, b: usize, pf: Print) -> Res<()> {
        if a == 0 || b > self.last() || a > b {
            return err("invalid address");
        }
        for n in a..=b {
            let text = self.buf[n - 1].text.clone();
            if pf.n {
                self.wr(format!("{n}\t").as_bytes());
            }
            if pf.l {
                self.list(&text);
            } else {
                self.wr(&text);
                self.wr(b"\n");
            }
        }
        self.dot = b;
        Ok(())
    }

    fn list(&mut self, t: &[u8]) {
        let width = 72;
        let mut o = Vec::new();
        let mut col = 0;
        for &c in t {
            let esc: Vec<u8> = match c {
                b'\\' => b"\\\\".to_vec(),
                0x07 => b"\\a".to_vec(),
                0x08 => b"\\b".to_vec(),
                0x0c => b"\\f".to_vec(),
                b'\r' => b"\\r".to_vec(),
                b'\t' => b"\\t".to_vec(),
                0x0b => b"\\v".to_vec(),
                c if (0x20..0x7f).contains(&c) => vec![c],
                c => format!("\\{c:03o}").into_bytes(),
            };
            if col + esc.len() > width - 1 {
                o.extend_from_slice(b"\\\n");
                col = 0;
            }
            col += esc.len();
            o.extend_from_slice(&esc);
        }
        o.extend_from_slice(b"$\n");
        self.wr(&o);
    }

    // --- files ---------------------------------------------------------------------------

    /// The file name argument of e, E, f, r, w, W: blanks, then the rest of the line.
    fn filename(s: &[u8], p: &mut usize) -> Res<Vec<u8>> {
        if *p < s.len() && !is_blank(s[*p]) {
            return err("unexpected command suffix");
        }
        while *p < s.len() && is_blank(s[*p]) {
            *p += 1;
        }
        let f = s[*p..].to_vec();
        *p = s.len();
        Ok(f)
    }

    /// Expands `%` and `!` in a shell command (`\%` is a literal `%`); writes it if changed.
    fn shell_command(&mut self, cmd: &[u8]) -> Res<Vec<u8>> {
        let mut out = Vec::new();
        let mut changed = false;
        let mut i = 0;
        if cmd.first() == Some(&b'!') {
            let Some(prev) = self.last_shell.clone() else { return err("no previous command") };
            out.extend_from_slice(&prev);
            changed = true;
            i = 1;
        }
        while i < cmd.len() {
            match cmd[i] {
                b'\\' if cmd.get(i + 1) == Some(&b'%') => {
                    out.push(b'%');
                    i += 2;
                }
                b'%' => {
                    let Some(f) = self.fname.clone() else { return err("no current filename") };
                    out.extend_from_slice(&f);
                    changed = true;
                    i += 1;
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        if changed {
            let o = out.clone();
            self.wr(&o);
            self.wr(b"\n");
        }
        self.last_shell = Some(out.clone());
        Ok(out)
    }

    /// Reads a file or `!command` into lines; returns them and the byte count.
    fn read_source(&mut self, name: &[u8]) -> Res<(Vec<Vec<u8>>, usize)> {
        let data = if let Some(cmd) = name.strip_prefix(b"!") {
            let cmd = self.shell_command(cmd)?;
            self.flush();
            match Command::new("/bin/sh").arg("-c").arg(OsStr::from_bytes(&cmd)).stderr(Stdio::inherit()).output() {
                Ok(o) => o.stdout,
                Err(e) => return Err(Error::Msg(format!("cannot run command: {}", strerror(&e)))),
            }
        } else {
            let mut d = Vec::new();
            match File::open(OsStr::from_bytes(name)).and_then(|mut f| f.read_to_end(&mut d)) {
                Ok(_) => d,
                Err(e) => {
                    self.flush();
                    eprintln!("{}: {}", String::from_utf8_lossy(name), strerror(&e));
                    return err("cannot open input file");
                }
            }
        };
        let n = data.len();
        let mut lines: Vec<Vec<u8>> = data.split(|&c| c == b'\n').map(<[u8]>::to_vec).collect();
        if data.last() == Some(&b'\n') || data.is_empty() {
            lines.pop();
        }
        Ok((lines, n))
    }

    fn insert_lines(&mut self, after: usize, lines: &[Vec<u8>]) {
        let new: Vec<Line> = lines.iter().map(|l| self.new_line(l)).collect();
        let k = new.len();
        self.buf.splice(after..after, new);
        if k > 0 {
            self.dot = after + k;
            self.set_modified();
        }
    }

    fn write_out(&mut self, a: usize, b: usize, name: &[u8], append: bool) -> Res<usize> {
        let mut data = Vec::new();
        if a > 0 {
            for l in &self.buf[a - 1..b] {
                data.extend_from_slice(&l.text);
                data.push(b'\n');
            }
        }
        if let Some(cmd) = name.strip_prefix(b"!") {
            let cmd = self.shell_command(cmd)?;
            self.flush();
            let child = Command::new("/bin/sh").arg("-c").arg(OsStr::from_bytes(&cmd)).stdin(Stdio::piped()).spawn();
            match child {
                Ok(mut ch) => {
                    if let Some(mut si) = ch.stdin.take() {
                        let _ = si.write_all(&data);
                    }
                    let _ = ch.wait();
                }
                Err(e) => return Err(Error::Msg(format!("cannot run command: {}", strerror(&e)))),
            }
            return Ok(data.len());
        }
        let f = std::fs::OpenOptions::new().write(true).create(true).append(append).truncate(!append).open(OsStr::from_bytes(name));
        match f.and_then(|mut f| f.write_all(&data)) {
            Ok(()) => Ok(data.len()),
            Err(e) => {
                self.flush();
                eprintln!("{}: {}", String::from_utf8_lossy(name), strerror(&e));
                err("cannot open output file")
            }
        }
    }

    fn count(&mut self, n: usize) {
        if !self.scripted {
            self.wr(format!("{n}\n").as_bytes());
        }
    }

    // --- text input ----------------------------------------------------------------------

    /// Input mode: lines up to one with only `.` (or the end of the input).
    fn read_text(&mut self) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Some(l) = self.read_line() {
            if l == b"." {
                break;
            }
            v.push(l);
        }
        v
    }

    // --- substitution --------------------------------------------------------------------

    /// `s` over `a..=b`. Returns whether anything was replaced.
    fn substitute(&mut self, a: usize, b: usize, re: &Regex, repl: &[u8], global: bool, nth: usize) -> Res<bool> {
        // The replacement's parts: literal bytes and group numbers (0 is &).
        enum Part {
            Lit(u8),
            Group(usize),
        }
        let mut parts = Vec::new();
        let mut i = 0;
        while i < repl.len() {
            match repl[i] {
                b'\\' if i + 1 < repl.len() => {
                    let n = repl[i + 1];
                    if n.is_ascii_digit() {
                        let g = (n - b'0') as usize;
                        if g > re.nsub() {
                            return err("invalid back-reference");
                        }
                        parts.push(Part::Group(g));
                    } else {
                        parts.push(Part::Lit(n));
                    }
                    i += 2;
                }
                b'&' => {
                    parts.push(Part::Group(0));
                    i += 1;
                }
                c => {
                    parts.push(Part::Lit(c));
                    i += 1;
                }
            }
        }
        let groups = parts.iter().any(|p| matches!(p, Part::Group(g) if *g > 0));
        let mut any = false;
        let mut n = a;
        let mut end = b;
        while n <= end {
            let text = self.buf[n - 1].text.clone();
            let len = text.len();
            let mut out: Vec<u8> = Vec::new();
            let mut pos = 0;
            let mut count = 0;
            let mut made = false;
            let mut last_end: Option<usize> = None;
            while pos <= len {
                let fl = if pos > 0 { ExecFlags::NOTBOL } else { ExecFlags::NONE };
                let r = if groups { re.try_captures_at(&text, pos..len, fl) } else { re.try_find_at(&text, pos..len, fl).map(|m| m.map(|m| vec![Some(m)])) };
                let caps = match r {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(e) => return err(e.kind.message()),
                };
                let (s, e) = caps[0].unwrap();
                if s == e && last_end == Some(s) {
                    if s >= len {
                        break;
                    }
                    out.push(text[s]);
                    pos = s + 1;
                    continue;
                }
                count += 1;
                out.extend_from_slice(&text[pos..s]);
                if count >= nth {
                    for part in &parts {
                        match part {
                            Part::Lit(c) => out.push(*c),
                            Part::Group(g) => {
                                if let Some(Some((x, y))) = caps.get(*g) {
                                    out.extend_from_slice(&text[*x..*y]);
                                }
                            }
                        }
                    }
                    made = true;
                } else {
                    out.extend_from_slice(&text[s..e]);
                }
                last_end = Some(e);
                pos = e;
                if made && !global {
                    break;
                }
                if s == e {
                    if s >= len {
                        break;
                    }
                    out.push(text[s]);
                    pos = s + 1;
                }
            }
            if !made {
                n += 1;
                continue;
            }
            if pos < len {
                out.extend_from_slice(&text[pos..]);
            }
            any = true;
            // An escaped newline in the replacement splits the line.
            let pieces: Vec<&[u8]> = out.split(|&c| c == b'\n').collect();
            let id = self.buf[n - 1].id;
            self.buf[n - 1] = Line { id, text: Rc::from(pieces[0]), gmark: false };
            let extra: Vec<Line> = pieces[1..].iter().map(|p| self.new_line(p)).collect();
            let k = extra.len();
            self.buf.splice(n..n, extra);
            end += k;
            self.dot = n + k;
            n += k + 1;
        }
        if any {
            self.set_modified();
        }
        Ok(any)
    }

    // --- commands ------------------------------------------------------------------------

    /// Print suffixes, then the end of the command.
    fn suffix(s: &[u8], p: &mut usize) -> Res<Print> {
        let mut pf = Print::default();
        while *p < s.len() {
            match s[*p] {
                b'p' => pf.p = true,
                b'l' => pf.l = true,
                b'n' => pf.n = true,
                _ => return err("invalid command suffix"),
            }
            *p += 1;
        }
        Ok(pf)
    }

    fn check_range(&self, a: usize, b: usize, zero_ok: bool) -> Res<()> {
        if a > b || b > self.last() || (!zero_ok && a == 0) {
            return err("invalid address");
        }
        Ok(())
    }

    /// Reads continuation lines for a command ending in an unescaped backslash (`s`, `g`).
    fn continued(&mut self, mut s: Vec<u8>, keep_backslash: bool) -> Vec<u8> {
        loop {
            let trailing = s.iter().rev().take_while(|&&c| c == b'\\').count();
            if trailing % 2 == 0 {
                return s;
            }
            if !keep_backslash {
                s.pop();
            }
            let Some(next) = self.read_line() else { return s };
            s.push(b'\n');
            s.extend_from_slice(&next);
        }
    }

    fn exec(&mut self, line: Vec<u8>) -> Res<()> {
        let mut s = line;
        let mut p = 0;
        let (cnt, mut a1, mut a2) = self.addresses(&s, &mut p)?;
        while p < s.len() && is_blank(s[p]) {
            p += 1;
        }
        let Some(&c) = s.get(p) else {
            // The null command: print the addressed line, or the next one.
            let n = if cnt == 0 { self.dot + 1 } else { a2 };
            if n == 0 || n > self.last() {
                return err("invalid address");
            }
            return self.print_lines(n, n, Print { p: true, ..Print::default() });
        };
        p += 1;
        let no_addr = |cnt: usize| if cnt > 0 { err("unexpected address") } else { Ok(()) };
        let mut pf = Print::default();
        match c {
            b'a' | b'i' | b'c' => {
                pf = Self::suffix(&s, &mut p)?;
                let zero_ok = c != b'c';
                if cnt == 0 {
                    a1 = self.dot;
                    a2 = self.dot;
                }
                self.check_range(a1, a2, zero_ok)?;
                if c == b'c' && self.last() == 0 {
                    return err("invalid address");
                }
                let text = self.read_text();
                self.snapshot();
                match c {
                    b'a' => {
                        self.dot = a2;
                        self.insert_lines(a2, &text);
                    }
                    b'i' => {
                        let at = a2.max(1) - 1;
                        self.dot = a2.max(1).min(self.last());
                        self.insert_lines(at, &text);
                    }
                    _ => {
                        self.delete(a1, a2);
                        self.dot = a1 - 1;
                        self.insert_lines(a1 - 1, &text);
                        if text.is_empty() {
                            self.dot = if a1 <= self.last() { a1 } else { self.last() };
                        }
                        self.set_modified();
                    }
                }
            }
            b'd' => {
                pf = Self::suffix(&s, &mut p)?;
                self.check_range(a1, a2, false)?;
                self.snapshot();
                self.delete(a1, a2);
                self.dot = if a1 <= self.last() { a1 } else { self.last() };
                self.set_modified();
            }
            b'e' | b'E' => {
                no_addr(cnt)?;
                let f = Self::filename(&s, &mut p)?;
                if c == b'e' && self.modified && !self.warned {
                    self.warned = true;
                    return Err(Error::Modified);
                }
                let name = if f.is_empty() {
                    self.fname.clone().ok_or_else(|| Error::Msg("no current filename".into()))?
                } else {
                    f.clone()
                };
                if !name.starts_with(b"!") {
                    self.fname = Some(name.clone());
                }
                self.snapshot();
                self.buf.clear();
                self.dot = 0;
                self.marks = [None; 26];
                let (lines, n) = self.read_source(&name)?;
                self.insert_lines(0, &lines);
                self.modified = false;
                self.warned = false;
                self.count(n);
            }
            b'f' => {
                no_addr(cnt)?;
                let f = Self::filename(&s, &mut p)?;
                if !f.is_empty() {
                    if f.starts_with(b"!") {
                        return err("invalid redirection");
                    }
                    self.fname = Some(f);
                }
                let Some(n) = self.fname.clone() else { return err("no current filename") };
                self.wr(&n);
                self.wr(b"\n");
            }
            b'g' | b'v' | b'G' | b'V' => {
                if self.in_global {
                    return err("cannot nest global commands");
                }
                if cnt == 0 {
                    a1 = 1;
                    a2 = self.last();
                }
                self.check_range(a1, a2, self.last() == 0)?;
                let Some(&d) = s.get(p) else { return err("invalid pattern delimiter") };
                if d == b' ' || d == b'\n' {
                    return err("invalid pattern delimiter");
                }
                p += 1;
                let pat = Self::pattern(&s, &mut p, d);
                let re = self.compile(&pat)?;
                if p < s.len() {
                    p += 1;
                }
                let interactive = c == b'G' || c == b'V';
                let rest = s[p..].to_vec();
                let list = if interactive { rest } else { self.continued(rest, false) };
                if interactive && !list.is_empty() {
                    return err("invalid command suffix");
                }
                let want = c == b'g' || c == b'G';
                for l in &mut self.buf {
                    l.gmark = false;
                }
                for n in a1.max(1)..=a2 {
                    let m = self.line_matches(&re, n) == want;
                    self.buf[n - 1].gmark = m;
                }
                self.snapshot();
                let saved_undo = self.undo.clone();
                self.in_global = true;
                let r = self.run_global(list, interactive);
                self.in_global = false;
                self.global = None;
                for l in &mut self.buf {
                    l.gmark = false;
                }
                self.undo = saved_undo;
                r?;
                return Ok(());
            }
            b'h' => {
                no_addr(cnt)?;
                Self::suffix(&s, &mut p)?;
                if let Some(m) = self.last_err.clone() {
                    self.flush();
                    eprintln!("{m}");
                }
            }
            b'H' => {
                no_addr(cnt)?;
                Self::suffix(&s, &mut p)?;
                self.verbose = !self.verbose;
                if self.verbose {
                    if let Some(m) = self.last_err.clone() {
                        self.flush();
                        eprintln!("{m}");
                    }
                }
            }
            b'j' => {
                pf = Self::suffix(&s, &mut p)?;
                if cnt == 0 {
                    a1 = self.dot;
                    a2 = self.dot + 1;
                }
                self.check_range(a1, a2, false)?;
                if a1 < a2 {
                    self.snapshot();
                    let mut joined = Vec::new();
                    for l in &self.buf[a1 - 1..a2] {
                        joined.extend_from_slice(&l.text);
                    }
                    let id = self.buf[a1 - 1].id;
                    self.buf.splice(a1 - 1..a2, [Line { id, text: Rc::from(joined), gmark: false }]);
                    self.set_modified();
                }
                self.dot = a1;
            }
            b'k' => {
                let Some(&m) = s.get(p) else { return err("invalid mark character") };
                p += 1;
                pf = Self::suffix(&s, &mut p)?;
                if !m.is_ascii_lowercase() {
                    return err("invalid mark character");
                }
                if a2 == 0 || a2 > self.last() {
                    return err("invalid address");
                }
                self.marks[(m - b'a') as usize] = Some(self.buf[a2 - 1].id);
            }
            b'l' | b'n' | b'p' => {
                pf = Self::suffix(&s, &mut p)?;
                match c {
                    b'l' => pf.l = true,
                    b'n' => pf.n = true,
                    _ => pf.p = true,
                }
                self.check_range(a1, a2, false)?;
                self.print_lines(a1, a2, pf)?;
                return Ok(());
            }
            b'm' | b't' => {
                self.check_range(a1, a2, false)?;
                let dest = match self.one_address(&s, &mut p)? {
                    Some(d) => d,
                    None => {
                        // POSIX: no destination is an error (some eds take `.`); the BSDs
                        // take `.`.
                        self.dot
                    }
                };
                pf = Self::suffix(&s, &mut p)?;
                if c == b'm' && dest >= a1 && dest < a2 {
                    return err("invalid destination");
                }
                self.snapshot();
                if c == b't' {
                    let copies: Vec<Line> = self.buf[a1 - 1..a2].to_vec().iter().map(|l| self.new_line(&l.text.clone())).collect();
                    let k = copies.len();
                    self.buf.splice(dest..dest, copies);
                    self.dot = dest + k;
                } else {
                    let moved: Vec<Line> = self.buf.drain(a1 - 1..a2).collect();
                    let k = moved.len();
                    let at = if dest >= a2 { dest - k } else { dest };
                    self.buf.splice(at..at, moved);
                    self.dot = at + k;
                }
                self.set_modified();
            }
            b'P' => {
                no_addr(cnt)?;
                Self::suffix(&s, &mut p)?;
                self.prompting = !self.prompting;
            }
            b'q' | b'Q' => {
                no_addr(cnt)?;
                Self::suffix(&s, &mut p)?;
                if c == b'q' && self.modified && !self.warned {
                    self.warned = true;
                    return Err(Error::Modified);
                }
                self.quit = Some(0);
            }
            b'r' => {
                let f = Self::filename(&s, &mut p)?;
                if cnt == 0 {
                    a2 = self.last();
                }
                if a2 > self.last() {
                    return err("invalid address");
                }
                let name = if f.is_empty() {
                    self.fname.clone().ok_or_else(|| Error::Msg("no current filename".into()))?
                } else {
                    f.clone()
                };
                if self.fname.is_none() && !name.starts_with(b"!") {
                    self.fname = Some(name.clone());
                }
                let (lines, n) = self.read_source(&name)?;
                self.snapshot();
                self.insert_lines(a2, &lines);
                self.count(n);
            }
            b's' => {
                self.check_range(a1, a2, false)?;
                if self.last() == 0 {
                    return err("invalid address");
                }
                let repeat = p >= s.len() || matches!(s[p], b'g' | b'p' | b'l' | b'n' | b'r' | b'0'..=b'9');
                let (re, repl, mut global, mut nth);
                if repeat {
                    let Some(ls) = self.last_sub.clone() else { return err("no previous substitution") };
                    re = self.last_re.clone().ok_or_else(|| Error::Msg("no previous pattern".into()))?;
                    repl = ls.repl;
                    global = ls.global;
                    nth = ls.nth;
                    while p < s.len() {
                        match s[p] {
                            b'g' => global = !global,
                            b'r' => {}
                            b'0'..=b'9' => {
                                nth = Self::number(&s, &mut p)?;
                                if nth == 0 {
                                    return err("invalid count");
                                }
                                continue;
                            }
                            b'p' => pf.p = true,
                            b'l' => pf.l = true,
                            b'n' => pf.n = true,
                            _ => return err("invalid command suffix"),
                        }
                        p += 1;
                    }
                } else {
                    let d = s[p];
                    if d == b' ' || d == b'\n' {
                        return err("invalid pattern delimiter");
                    }
                    p += 1;
                    let pat = Self::pattern(&s, &mut p, d);
                    if p >= s.len() {
                        return err("no replacement string");
                    }
                    p += 1;
                    re = self.compile(&pat)?;
                    // The replacement may go on over escaped newlines.
                    s = self.continued(s, true);
                    let mut r = Vec::new();
                    let mut closed = false;
                    while p < s.len() {
                        let ch = s[p];
                        if ch == d {
                            closed = true;
                            p += 1;
                            break;
                        }
                        if ch == b'\\' && p + 1 < s.len() {
                            if s[p + 1] == d {
                                r.push(d);
                            } else if s[p + 1] == b'\n' {
                                r.push(b'\n');
                            } else {
                                r.push(b'\\');
                                r.push(s[p + 1]);
                            }
                            p += 2;
                            continue;
                        }
                        r.push(ch);
                        p += 1;
                    }
                    if r == b"%" {
                        let Some(ls) = &self.last_sub else { return err("no previous substitution") };
                        r = ls.repl.clone();
                    }
                    repl = r;
                    global = false;
                    nth = 1;
                    // An unclosed replacement is the rest of the line, printing it (POSIX).
                    if !closed {
                        pf.p = true;
                    }
                    while p < s.len() {
                        match s[p] {
                            b'g' => global = true,
                            b'0'..=b'9' => {
                                nth = Self::number(&s, &mut p)?;
                                if nth == 0 {
                                    return err("invalid count");
                                }
                                continue;
                            }
                            b'p' => pf.p = true,
                            b'l' => pf.l = true,
                            b'n' => pf.n = true,
                            _ => return err("invalid command suffix"),
                        }
                        p += 1;
                    }
                }
                self.last_sub = Some(LastSub { repl: repl.clone(), global, nth });
                if !self.in_global {
                    self.snapshot();
                }
                let any = self.substitute(a1, a2, &re, &repl, global, nth)?;
                if !any && !self.in_global {
                    return err("no match");
                }
            }
            b'u' => {
                no_addr(cnt)?;
                pf = Self::suffix(&s, &mut p)?;
                let Some(snap) = self.undo.take() else { return err("nothing to undo") };
                let cur = Snapshot { buf: std::mem::take(&mut self.buf), dot: self.dot, modified: self.modified };
                self.buf = snap.buf;
                self.dot = snap.dot.min(self.last());
                self.modified = snap.modified || cur.modified;
                self.undo = Some(cur);
            }
            b'w' | b'W' => {
                let mut quit_after = false;
                if c == b'w' && s.get(p) == Some(&b'q') {
                    quit_after = true;
                    p += 1;
                }
                let f = Self::filename(&s, &mut p)?;
                if cnt == 0 {
                    a1 = if self.last() == 0 { 0 } else { 1 };
                    a2 = self.last();
                }
                self.check_range(a1, a2, self.last() == 0)?;
                let name = if f.is_empty() {
                    self.fname.clone().ok_or_else(|| Error::Msg("no current filename".into()))?
                } else {
                    f.clone()
                };
                if self.fname.is_none() && !name.starts_with(b"!") {
                    self.fname = Some(name.clone());
                }
                let n = self.write_out(a1, a2, &name, c == b'W')?;
                if !name.starts_with(b"!") && (a1 <= 1 && a2 == self.last()) {
                    self.modified = false;
                }
                self.count(n);
                if quit_after {
                    if self.modified && !self.warned {
                        self.warned = true;
                        return Err(Error::Modified);
                    }
                    self.quit = Some(0);
                }
            }
            b'z' => {
                let n = if cnt == 0 { self.dot + 1 } else { a2 };
                let win = if s.get(p).is_some_and(u8::is_ascii_digit) { Self::number(&s, &mut p)? } else { 22 };
                pf = Self::suffix(&s, &mut p)?;
                if n == 0 || n > self.last() {
                    return err("invalid address");
                }
                let end = (n + win.max(1) - 1).min(self.last());
                let pp = Print { p: true, ..pf };
                return self.print_lines(n, end, pp);
            }
            b'=' => {
                pf = Self::suffix(&s, &mut p)?;
                let n = if cnt == 0 { self.last() } else { a2 };
                self.wr(format!("{n}\n").as_bytes());
            }
            b'!' => {
                no_addr(cnt)?;
                let cmd = self.shell_command(&s[p..].to_vec())?;
                self.flush();
                let _ = Command::new("/bin/sh").arg("-c").arg(OsStr::from_bytes(&cmd)).status();
                if !self.scripted {
                    self.wr(b"!\n");
                }
            }
            _ => return err("unknown command"),
        }
        if pf.any() {
            if self.dot == 0 {
                return err("invalid address");
            }
            let d = self.dot;
            self.print_lines(d, d, Print { p: true, ..pf })?;
        }
        Ok(())
    }

    fn delete(&mut self, a: usize, b: usize) {
        self.buf.drain(a - 1..b);
    }

    /// Runs `g`'s command list on each marked line in turn (`G` asks for a command per line).
    fn run_global(&mut self, list: Vec<u8>, interactive: bool) -> Res<()> {
        let lines: Vec<Vec<u8>> = if list.is_empty() { vec![b"p".to_vec()] } else { list.split(|&c| c == b'\n').map(<[u8]>::to_vec).collect() };
        let mut prev_cmd: Option<Vec<u8>> = None;
        let mut from = 0;
        loop {
            // The next marked line: from where the last one was, wrapping once.
            let n = self.buf.len();
            let mut found = None;
            for k in 0..n {
                let i = (from + k) % n;
                if self.buf[i].gmark {
                    found = Some(i);
                    break;
                }
            }
            let Some(i) = found else { return Ok(()) };
            self.buf[i].gmark = false;
            self.dot = i + 1;
            from = i;
            if interactive {
                self.print_lines(i + 1, i + 1, Print { p: true, ..Print::default() })?;
                self.global = None;
                let Some(cmd) = self.read_stdin() else { return Ok(()) };
                let cmd = if cmd == b"&" {
                    match &prev_cmd {
                        Some(c) => c.clone(),
                        None => return err("no previous command"),
                    }
                } else {
                    cmd
                };
                if cmd.is_empty() {
                    continue;
                }
                prev_cmd = Some(cmd.clone());
                self.exec(cmd)?;
            } else {
                self.global = Some(Source { lines: lines.clone(), pos: 0 });
                while let Some(cmd) = self.read_line() {
                    self.exec(cmd)?;
                    if self.quit.is_some() {
                        return Ok(());
                    }
                }
            }
            if self.quit.is_some() {
                return Ok(());
            }
        }
    }

    fn report(&mut self, e: Error) {
        let msg = match e {
            Error::Msg(m) => m,
            Error::Modified => "warning: buffer modified".to_string(),
        };
        self.flush();
        eprintln!("?");
        if !self.interactive {
            if self.verbose {
                eprintln!("script, line {}: {msg}", self.lineno);
            }
            self.last_err = Some(msg);
            self.quit = Some(2);
            return;
        }
        if self.verbose {
            eprintln!("{msg}");
        }
        self.last_err = Some(msg);
    }

    fn main_loop(&mut self) -> u8 {
        loop {
            if self.prompting {
                let p = self.prompt.clone();
                self.wr(&p);
            }
            let Some(line) = self.read_stdin() else {
                // The end of the input is `q`.
                if self.modified && !self.warned {
                    self.warned = true;
                    self.report(Error::Modified);
                    if let Some(q) = self.quit {
                        return q;
                    }
                    continue;
                }
                return 0;
            };
            if let Err(e) = self.exec(line) {
                self.report(e);
            }
            if let Some(q) = self.quit {
                return q;
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<Vec<u8>> = std::env::args_os().skip(1).map(|a| a.as_bytes().to_vec()).collect();
    let mut scripted = false;
    let mut prompt: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == b"--" {
            i += 1;
            break;
        }
        if a == b"-" {
            scripted = true;
            i += 1;
            continue;
        }
        if a.len() < 2 || a[0] != b'-' {
            break;
        }
        i += 1;
        let mut j = 1;
        while j < a.len() {
            match a[j] {
                b's' => scripted = true,
                b'p' => {
                    if j + 1 < a.len() {
                        prompt = Some(a[j + 1..].to_vec());
                    } else if i < args.len() {
                        prompt = Some(args[i].clone());
                        i += 1;
                    } else {
                        eprintln!("ed: option requires an argument -- p");
                        eprintln!("usage: ed [-] [-s] [-p string] [file]");
                        return ExitCode::from(2);
                    }
                    j = a.len();
                    continue;
                }
                c => {
                    eprintln!("ed: illegal option -- {}", c as char);
                    eprintln!("usage: ed [-] [-s] [-p string] [file]");
                    return ExitCode::from(2);
                }
            }
            j += 1;
        }
    }
    if args.len() > i + 1 {
        eprintln!("usage: ed [-] [-s] [-p string] [file]");
        return ExitCode::from(2);
    }
    // SAFETY: isatty only reads its argument.
    let interactive = unsafe { libc::isatty(0) } == 1;
    let mut ed = Ed {
        buf: Vec::new(),
        dot: 0,
        modified: false,
        warned: false,
        fname: None,
        marks: [None; 26],
        last_re: None,
        last_sub: None,
        undo: None,
        prompting: prompt.is_some(),
        prompt: prompt.unwrap_or_else(|| b"*".to_vec()),
        scripted,
        verbose: false,
        last_err: None,
        next_id: 0,
        last_shell: None,
        out: BufWriter::with_capacity(16 * 1024, io::stdout()),
        stdin: BufReader::new(io::stdin()),
        interactive,
        global: None,
        in_global: false,
        lineno: 0,
        quit: None,
    };
    if let Some(f) = args.get(i) {
        if !f.starts_with(b"!") {
            ed.fname = Some(f.clone());
        }
        match ed.read_source(f) {
            Ok((lines, n)) => {
                ed.insert_lines(0, &lines);
                ed.modified = false;
                ed.count(n);
            }
            Err(Error::Msg(m)) => {
                ed.last_err = Some(m);
                if !interactive {
                    ed.flush();
                    return ExitCode::from(2);
                }
            }
            Err(Error::Modified) => {}
        }
    }
    let st = ed.main_loop();
    ed.flush();
    ExitCode::from(st)
}
