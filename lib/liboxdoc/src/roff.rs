//! The roff layer (MAN.md §3.1, stage 1): reads input lines, runs roff requests (strings,
//! registers, macro definitions, conditionals, ignore blocks, includes), expands escapes, and
//! hands each resulting line to a language parser as a [`Line`].
//!
//! Escapes are decoded into text: special characters become their Unicode form (renderers map
//! back to ASCII when they must), and escapes with no character of their own become the private
//! markers in [`mark`], which only renderers interpret.

use std::collections::HashMap;

use crate::chars;
use crate::diag::{Diagnostics, Level};

/// Private-use characters standing for escapes that aren't text.
pub mod mark {
    /// `\&`: a zero-width character. It stops a word from being a delimiter or a macro name, and
    /// stops a line-ending period from ending a sentence.
    pub const ZERO: char = '\u{E000}';
    /// `\c` at the end of a text line: the next line continues this one without a space.
    pub const CONT: char = '\u{E001}';
    /// `\ `, `\~`, `\0`: a space that neither breaks nor stretches.
    pub const NBSP: char = '\u{E002}';
    /// `\-`: a minus sign (`-` in ASCII, and in UTF-8 too, as mandoc renders it).
    pub const MINUS: char = '\u{E003}';
    /// `\(hy`-style hyphen from `\%`-free text is plain `-`; this is `\e` (a printable backslash).
    pub const BACKSLASH: char = '\u{E004}';
    /// Font changes: `\fR`, `\fB`, `\fI`, `\f(BI`, `\fC`..., and `\fP` (previous).
    pub const FONT_R: char = '\u{E010}';
    pub const FONT_B: char = '\u{E011}';
    pub const FONT_I: char = '\u{E012}';
    pub const FONT_BI: char = '\u{E013}';
    pub const FONT_CW: char = '\u{E014}';
    pub const FONT_P: char = '\u{E01F}';

    pub fn is_font(c: char) -> bool {
        ('\u{E010}'..='\u{E01F}').contains(&c)
    }
}

/// A line after roff processing.
#[derive(Clone, Debug, PartialEq)]
pub enum Line {
    /// A macro or request the language parser handles: its name and arguments, with quotes
    /// removed and escapes decoded.
    Macro { name: String, args: Vec<String>, line: usize, no_break: bool },
    /// A text line, escapes decoded. `sentence_end` is set when it ends a sentence (§4.1).
    Text { text: String, line: usize },
    /// An empty line: a paragraph break in both languages.
    Blank { line: usize },
}

/// A condition being skipped or taken, for `.if`/`.ie`/`.el` with a `\{` ... `\}` body.
struct Cond {
    /// Whether lines in this body are processed.
    active: bool,
}

pub struct Roff<'a> {
    strings: HashMap<String, String>,
    registers: HashMap<String, i64>,
    macros: HashMap<String, Vec<String>>,
    /// The `.ie` result the next `.el` inverts.
    last_ie: Vec<bool>,
    /// Open `\{` bodies.
    conds: Vec<Cond>,
    /// An open `.de`/`.am`: (name, end marker, lines).
    defining: Option<(String, String, Vec<String>)>,
    /// An open `.ig`: its end marker.
    ignoring: Option<String>,
    /// `.tr` translations.
    translate: HashMap<char, char>,
    cc: char,
    /// The escape character; `None` after `.eo`.
    ec: Option<char>,
    /// Arguments of the macro being expanded, innermost last, for `\$n`.
    frames: Vec<Vec<String>>,
    diag: &'a mut Diagnostics,
    /// Reads a `.so` include by its path, relative to the manual tree root.
    include: Option<&'a dyn Fn(&str) -> Option<String>>,
    pending_cont: bool,
    out: Vec<Line>,
}

/// Macro expansion depth limit, so a recursive `.de` can't hang.
const MAX_DEPTH: usize = 64;

impl<'a> Roff<'a> {
    pub fn new(diag: &'a mut Diagnostics) -> Roff<'a> {
        let mut strings = HashMap::new();
        // The predefined strings, exactly mandoc's set (found by probing every one- and
        // two-letter name).
        for (k, v) in [("Ai", "ANSI"), ("Am", "&"), ("Ba", "|"), ("Ge", "\u{2265}"), ("Gt", ">"), ("If", "infinity"), ("Le", "\u{2264}"), ("Lq", "\u{201C}"), ("Lt", "<"), ("Na", "NaN"), ("Ne", "\u{2260}"), ("Pi", "pi"), ("Pm", "\u{00B1}"), ("Px", "POSIX"), ("R", "\u{00AE}"), ("Rq", "\u{201D}"), ("Tm", "(Tm)"), ("aa", "\u{00B4}"), ("ga", "`"), ("lp", "("), ("lq", "\u{201C}"), ("q", "\""), ("rp", ")"), ("rq", "\u{201D}"), ("ua", "\u{2191}"), ("va", "\u{2195}")] {
            strings.insert(k.to_string(), v.to_string());
        }
        Roff {
            strings,
            registers: HashMap::new(),
            macros: HashMap::new(),
            last_ie: Vec::new(),
            conds: Vec::new(),
            defining: None,
            ignoring: None,
            translate: HashMap::new(),
            cc: '.',
            ec: Some('\\'),
            frames: Vec::new(),
            diag,
            include: None,
            pending_cont: false,
            out: Vec::new(),
        }
    }

    pub fn set_include(&mut self, f: &'a dyn Fn(&str) -> Option<String>) {
        self.include = Some(f);
    }

    /// Processes a whole document.
    pub fn run(mut self, input: &str) -> Vec<Line> {
        let input = input.strip_suffix('\n').unwrap_or(input);
        let mut pending = String::new();
        let mut start = 0;
        for (i, line) in input.split('\n').enumerate() {
            // A line ending in an unescaped backslash continues on the next one.
            let line = line.strip_suffix('\r').unwrap_or(line);
            let trailing = line.len() - line.trim_end_matches('\\').len();
            if pending.is_empty() {
                start = i + 1;
            }
            if trailing % 2 == 1 && self.ec == Some('\\') {
                pending.push_str(&line[..line.len() - 1]);
                continue;
            }
            pending.push_str(line);
            let l = std::mem::take(&mut pending);
            self.line(&l, start, 0);
        }
        if !pending.is_empty() {
            let l = std::mem::take(&mut pending);
            self.line(&l, start, 0);
        }
        if self.defining.is_some() {
            self.diag.report(Level::Error, 0, 0, "end of input in macro definition", "");
        }
        self.out
    }

    fn escape_char(&self) -> Option<char> {
        self.ec
    }

    /// One input line, at macro-expansion depth `depth`.
    fn line(&mut self, raw: &str, lineno: usize, depth: usize) {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);

        if let Some(end) = &self.ignoring {
            if is_end_marker(raw, self.cc, end) {
                self.ignoring = None;
            }
            return;
        }
        if let Some((_, end, body)) = &mut self.defining {
            if is_end_marker(raw, self.cc, end) {
                let (name, _, body) = self.defining.take().unwrap();
                self.macros.insert(name, body);
            } else {
                // Copy mode: `\\` becomes `\`, so `\\$1` in a definition is `\$1` when called.
                body.push(match self.ec {
                    Some(ec) => raw.replace(&format!("{ec}{ec}"), &ec.to_string()),
                    None => raw.to_string(),
                });
            }
            return;
        }

        // Inside a false `\{` body: only track nesting.
        if self.conds.last().is_some_and(|c| !c.active) {
            self.skip_conds(raw);
            return;
        }

        let text = raw;
        let is_control = text.starts_with(self.cc) || text.starts_with('\'');
        if is_control {
            let no_break = text.starts_with('\'');
            let rest = &text[1..];
            // `.\"` comment line.
            if rest.trim_start().starts_with("\\\"") || rest.trim_start().starts_with("\\#") {
                self.close_conds(raw);
                return;
            }
            let rest = strip_comment(rest, self.ec);
            let rest = rest.trim_start_matches([' ', '\t']);
            if rest.is_empty() {
                // A lone control character is ignored.
                return;
            }
            let (name, argstr) = split_name(rest);
            let name = self.interpolate_name(name);
            if self.request(&name, argstr, lineno, depth) {
                // `.if`/`.ie`/`.el` process their own rest of line, closes included.
                if !matches!(name.as_str(), "if" | "ie" | "el") {
                    self.close_conds(raw);
                }
                return;
            }
            if let Some(body) = self.macros.get(&name).cloned() {
                if depth >= MAX_DEPTH {
                    self.diag.report(Level::Error, lineno, 0, "input stack limit exceeded, infinite loop?", &name);
                    return;
                }
                let args = self.macro_args(argstr, lineno);
                for l in body {
                    let l = self.substitute_args(&l, &args);
                    self.frames.push(args.clone());
                    self.line(&l, lineno, depth + 1);
                    self.frames.pop();
                }
                self.close_conds(raw);
                return;
            }
            let args = self.macro_args(argstr, lineno);
            self.close_conds(raw);
            self.emit(Line::Macro { name, args, line: lineno, no_break });
            return;
        }

        if text.is_empty() {
            self.emit(Line::Blank { line: lineno });
            return;
        }
        let mut expanded = self.expand(text, lineno);
        // A line holding only a comment or a `\}` produces nothing.
        if expanded.is_empty() {
            self.close_conds(raw);
            return;
        }
        if !self.translate.is_empty() {
            expanded = expanded.chars().map(|c| *self.translate.get(&c).unwrap_or(&c)).collect();
        }
        self.close_conds(raw);
        self.emit(Line::Text { text: expanded, line: lineno });
    }

    fn emit(&mut self, line: Line) {
        // `\c`: join this line onto the previous text.
        if self.pending_cont {
            self.pending_cont = false;
            if let (Some(Line::Text { text: prev, .. }), Line::Text { text, .. }) = (self.out.last_mut(), &line) {
                prev.push_str(text);
                if prev.ends_with(mark::CONT) {
                    prev.pop();
                    self.pending_cont = true;
                }
                return;
            }
        }
        if let Line::Text { text, .. } = &line
            && text.ends_with(mark::CONT)
        {
            self.pending_cont = true;
            let mut l = line;
            if let Line::Text { text, .. } = &mut l {
                text.pop();
            }
            self.out.push(l);
            return;
        }
        self.out.push(line);
    }

    /// Closes one condition body for each `\}` on a line that was processed.
    fn close_conds(&mut self, raw: &str) {
        let Some(ec) = self.ec else { return };
        let closes = raw.matches(&format!("{ec}}}")).count();
        for _ in 0..closes {
            self.conds.pop();
        }
    }

    /// Tracks nesting on a line inside a skipped body: `\{` opens another skipped body, `\}`
    /// closes the innermost.
    fn skip_conds(&mut self, raw: &str) {
        let Some(ec) = self.ec else { return };
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c == ec {
                match chars.next() {
                    Some('}') => {
                        self.conds.pop();
                    }
                    Some('{') => self.conds.push(Cond { active: false }),
                    _ => {}
                }
            }
        }
    }

    /// Replaces `\$1`..`\$9`, `\$*`, `\$@` and `\n(.$` in one line of a macro body.
    fn substitute_args(&self, line: &str, args: &[String]) -> String {
        let Some(ec) = self.ec else { return line.to_string() };
        let chars: Vec<char> = line.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == ec && chars.get(i + 1) == Some(&'$') {
                match chars.get(i + 2) {
                    Some(d) if d.is_ascii_digit() => {
                        let n = d.to_digit(10).unwrap() as usize;
                        if n >= 1 && let Some(a) = args.get(n - 1) {
                            out.push_str(a);
                        }
                        i += 3;
                        continue;
                    }
                    Some('(') | Some('[') => {
                        let (name, next) = read_name(&chars, i + 2);
                        if let Ok(n) = name.parse::<usize>() && n >= 1 && let Some(a) = args.get(n - 1) {
                            out.push_str(a);
                        }
                        i = next;
                        continue;
                    }
                    Some('*') | Some('@') => {
                        let quote = chars[i + 2] == '@';
                        let joined: Vec<String> = args.iter().map(|a| if quote { format!("\"{a}\"") } else { a.clone() }).collect();
                        out.push_str(&joined.join(" "));
                        i += 3;
                        continue;
                    }
                    _ => {}
                }
            }
            if chars[i] == ec && chars.get(i + 1) == Some(&ec) {
                out.push(ec);
                out.push(ec);
                i += 2;
                continue;
            }
            out.push(chars[i]);
            i += 1;
        }
        out.replace(&format!("{ec}n(.$"), &args.len().to_string())
    }

    /// Runs a roff request. Returns false if `name` isn't one this layer handles.
    fn request(&mut self, name: &str, argstr: &str, lineno: usize, depth: usize) -> bool {
        match name {
            "ds" | "as" => {
                let (key, value) = split_name(argstr);
                let value = value.strip_prefix('"').unwrap_or(value);
                // String values are stored unexpanded and expanded at interpolation.
                let key = key.to_string();
                if name == "as" {
                    self.strings.entry(key).or_default().push_str(value);
                } else {
                    self.strings.insert(key, value.to_string());
                }
                true
            }
            "nr" => {
                let mut it = argstr.split_whitespace();
                if let Some(key) = it.next() {
                    let expr = it.next().unwrap_or("0");
                    let cur = *self.registers.get(key).unwrap_or(&0);
                    let v = if let Some(e) = expr.strip_prefix('+') {
                        cur + self.number(e)
                    } else if let Some(e) = expr.strip_prefix('-') {
                        cur - self.number(e)
                    } else {
                        self.number(expr)
                    };
                    self.registers.insert(key.to_string(), v);
                }
                true
            }
            "rr" => {
                for k in argstr.split_whitespace() {
                    self.registers.remove(k);
                }
                true
            }
            "rm" => {
                for k in argstr.split_whitespace() {
                    self.strings.remove(k);
                    self.macros.remove(k);
                }
                true
            }
            "rn" => {
                let mut it = argstr.split_whitespace();
                if let (Some(a), Some(b)) = (it.next(), it.next()) {
                    if let Some(m) = self.macros.remove(a) {
                        self.macros.insert(b.to_string(), m);
                    } else if let Some(s) = self.strings.remove(a) {
                        self.strings.insert(b.to_string(), s);
                    }
                }
                true
            }
            "als" => {
                let mut it = argstr.split_whitespace();
                if let (Some(new), Some(old)) = (it.next(), it.next())
                    && let Some(m) = self.macros.get(old).cloned()
                {
                    self.macros.insert(new.to_string(), m);
                }
                true
            }
            "de" | "de1" | "dei" | "am" | "am1" | "ami" => {
                let mut it = argstr.split_whitespace();
                let Some(key) = it.next() else { return true };
                let end = it.next().unwrap_or(".").to_string();
                let body = if name.starts_with("am") { self.macros.get(key).cloned().unwrap_or_default() } else { Vec::new() };
                self.defining = Some((key.to_string(), end, body));
                true
            }
            "ig" => {
                self.ignoring = Some(argstr.split_whitespace().next().unwrap_or(".").to_string());
                true
            }
            "if" | "ie" => {
                let (cond, rest) = self.condition(argstr);
                if name == "ie" {
                    self.last_ie.push(cond);
                }
                self.conditional_body(cond, rest, lineno, depth);
                true
            }
            "el" => {
                let cond = !self.last_ie.pop().unwrap_or(true);
                self.conditional_body(cond, argstr, lineno, depth);
                true
            }
            "so" => {
                let path = argstr.trim();
                let text = self.include.and_then(|f| f(path));
                match text {
                    Some(t) if depth < MAX_DEPTH => {
                        for (i, l) in t.lines().enumerate() {
                            self.line(l, i + 1, depth + 1);
                        }
                    }
                    _ => self.diag.report(Level::Error, lineno, 0, ".so request failed", path),
                }
                true
            }
            "tr" => {
                let s: Vec<char> = self.expand(argstr.trim(), lineno).chars().collect();
                for pair in s.chunks(2) {
                    let to = pair.get(1).copied().unwrap_or(' ');
                    self.translate.insert(pair[0], to);
                }
                true
            }
            "cc" => {
                self.cc = argstr.trim().chars().next().unwrap_or('.');
                true
            }
            "ec" => {
                self.ec = Some(argstr.trim().chars().next().unwrap_or('\\'));
                true
            }
            "eo" => {
                self.ec = None;
                true
            }
            // Requests with no effect on terminal or HTML output.
            "hy" | "nh" | "hw" | "hc" | "ad" | "na" | "pl" | "pn" | "po" | "ps" | "vs" | "ss" | "cs" | "bd" | "uf" | "lg" | "ev" | "mk" | "rt" | "ch" | "wh" | "dt" | "it" | "itc" | "em" | "pc" | "lf" | "tm" | "tm1" | "tmc" | "ab" | "ex" | "fl" | "ftr" | "fam" | "fcolor" | "gcolor" | "defcolor" | "do" | "cp" | "nx" | "rd" | "pso" | "open" | "opena" | "write" | "close" | "trf" | "cf" | "shift" | "while" | "break" | "continue" | "blm" | "lsm" | "kern" | "nm" | "nn" | "sy" | "warn" | "hla" | "hlm" | "hpf" | "hym" | "hys" | "pvs" | "tkf" | "vpt" | "ecs" | "ecr" | "nop" | "char" | "fchar" | "schar" | "rchar" | "fschar" | "return" | "substring" | "length" | "chop" | "asciify" | "unformat" | "di" | "da" | "box" | "boxa" | "tl" | "mc" | "ns" | "rs" | "os" | "sv" | "rj" | "fp" | "fspecial" | "special" | "sizes" | "ptr" | "pm" | "psbb" | "fzoom" | "gtl" | "ss_" | "tag" | "taga" | "spreadwarn" => {
                if name == "nop" {
                    // `.nop text`: the text as a text line.
                    let t = self.expand(argstr, lineno);
                    self.emit(Line::Text { text: t, line: lineno });
                }
                true
            }
            _ => false,
        }
    }

    /// The body of `.if`/`.ie`/`.el` after its condition: a rest-of-line, or a `\{` block.
    fn conditional_body(&mut self, cond: bool, rest: &str, lineno: usize, depth: usize) {
        let rest = rest.trim_start();
        let Some(ec) = self.ec else { return };
        let open = format!("{ec}{{");
        if let Some(body) = rest.strip_prefix(&open) {
            // Pushed before the rest of the line is processed, so a `\}` on it closes this body.
            self.conds.push(Cond { active: cond });
            let body = body.trim_start();
            if cond && !body.is_empty() {
                self.line(body, lineno, depth);
            } else if !body.is_empty() {
                self.skip_conds(body);
            }
            return;
        }
        if cond && !rest.is_empty() {
            self.line(rest, lineno, depth);
        }
    }

    /// Evaluates the condition at the start of `s`, returning it and the rest of the line.
    fn condition<'s>(&mut self, s: &'s str) -> (bool, &'s str) {
        let s = s.trim_start();
        let (neg, s) = match s.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, s),
        };
        let mut chars = s.chars();
        let (value, rest) = match chars.next() {
            // Terminal output: `n` (nroff) is true, `t` (troff) false; odd and even pages both
            // hold, as in mandoc.
            Some('n') | Some('o') => (true, chars.as_str()),
            Some('t') | Some('e') | Some('v') => (false, chars.as_str()),
            Some('d') | Some('r') | Some('c') | Some('m') | Some('F') | Some('S') => {
                let kind = s.as_bytes()[0];
                let rest = chars.as_str().trim_start();
                let (name, rest) = split_name(rest);
                let v = match kind {
                    b'd' => self.strings.contains_key(name) || self.macros.contains_key(name),
                    b'r' => self.registers.contains_key(name),
                    b'c' => true,
                    _ => false,
                };
                (v, rest)
            }
            Some(q) if !q.is_ascii_alphanumeric() && q != '(' && q != '-' && q != '+' && q != '\\' => {
                // `'a'b'`: string comparison.
                let body = chars.as_str();
                let mut parts = body.splitn(3, q);
                let a = parts.next().unwrap_or("");
                let b = parts.next().unwrap_or("");
                let rest = parts.next().unwrap_or("");
                let ea = self.expand(a, 0);
                let eb = self.expand(b, 0);
                (ea == eb, rest)
            }
            _ => {
                // A numeric expression, up to the first space.
                let end = s.find([' ', '\t']).unwrap_or(s.len());
                let expr = self.expand(&s[..end], 0);
                (self.number(&expr) > 0, &s[end..])
            }
        };
        (value != neg, rest)
    }

    /// A numeric expression: integers, `+ - * / %`, comparisons and parentheses, left to right as
    /// roff evaluates them; scaling units are ignored.
    fn number(&self, s: &str) -> i64 {
        fn term(b: &[u8], i: &mut usize) -> i64 {
            if *i < b.len() && b[*i] == b'(' {
                *i += 1;
                let v = expr(b, i);
                if *i < b.len() && b[*i] == b')' {
                    *i += 1;
                }
                return v;
            }
            let neg = if *i < b.len() && (b[*i] == b'-' || b[*i] == b'+') {
                *i += 1;
                b[*i - 1] == b'-'
            } else {
                false
            };
            let start = *i;
            while *i < b.len() && b[*i].is_ascii_digit() {
                *i += 1;
            }
            let v: i64 = std::str::from_utf8(&b[start..*i]).unwrap().parse().unwrap_or(0);
            // A scaling unit.
            while *i < b.len() && (b[*i] == b'.' || b[*i].is_ascii_digit() || b"icpPmMnuvsf".contains(&b[*i])) {
                *i += 1;
            }
            if neg { -v } else { v }
        }
        fn expr(b: &[u8], i: &mut usize) -> i64 {
            let mut v = term(b, i);
            while *i < b.len() {
                let op = b[*i];
                let two = if *i + 1 < b.len() { &b[*i..*i + 2] } else { &b[*i..*i + 1] };
                let (len, f): (usize, fn(i64, i64) -> i64) = match (op, two) {
                    (_, b"<=") => (2, |a, b| (a <= b) as i64),
                    (_, b">=") => (2, |a, b| (a >= b) as i64),
                    (_, b"==") => (2, |a, b| (a == b) as i64),
                    (_, b"<>") => (2, |a, b| (a != b) as i64),
                    (b'<', _) => (1, |a, b| (a < b) as i64),
                    (b'>', _) => (1, |a, b| (a > b) as i64),
                    (b'=', _) => (1, |a, b| (a == b) as i64),
                    (b'+', _) => (1, |a, b| a + b),
                    (b'-', _) => (1, |a, b| a - b),
                    (b'*', _) => (1, |a, b| a * b),
                    (b'/', _) => (1, |a, b| if b == 0 { 0 } else { a / b }),
                    (b'%', _) => (1, |a, b| if b == 0 { 0 } else { a % b }),
                    (b'&', _) => (1, |a, b| (a > 0 && b > 0) as i64),
                    (b':', _) => (1, |a, b| (a > 0 || b > 0) as i64),
                    _ => break,
                };
                *i += len;
                let r = term(b, i);
                v = f(v, r);
            }
            v
        }
        let b = s.trim().as_bytes();
        let mut i = 0;
        expr(b, &mut i)
    }

    /// Expands escapes in the name position of a control line (`.\*[name]` is rare but legal).
    fn interpolate_name(&mut self, name: &str) -> String {
        if name.contains('\\') { self.expand(name, 0) } else { name.to_string() }
    }

    /// A macro line's arguments, as roff finds them: strings, registers and macro arguments
    /// are interpolated first (so a string holding spaces yields several arguments), then the
    /// line is split at unescaped spaces and quotes, then each argument's remaining escapes are
    /// decoded. Splitting after full decoding would take an escaped quote (`\(dq`) for a real one.
    fn macro_args(&mut self, argstr: &str, lineno: usize) -> Vec<String> {
        let raw = self.interpolate(argstr, lineno, 0);
        let Some(ec) = self.ec else { return split_args(&raw, true) };
        split_raw(&raw, ec).into_iter().map(|a| self.expand(&a, lineno)).collect()
    }

    /// Replaces `\*` strings, `\n` registers and `\$` arguments, leaving other escapes as typed.
    fn interpolate(&mut self, s: &str, lineno: usize, depth: usize) -> String {
        let Some(ec) = self.ec else { return s.to_string() };
        let chars: Vec<char> = s.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] != ec || i + 1 >= chars.len() {
                out.push(chars[i]);
                i += 1;
                continue;
            }
            match chars[i + 1] {
                '*' => {
                    let (name, next) = read_name(&chars, i + 2);
                    i = next;
                    let name = name.split_whitespace().next().unwrap_or("").to_string();
                    match self.strings.get(&name).cloned() {
                        Some(v) if depth < MAX_DEPTH => out.push_str(&self.interpolate(&v, lineno, depth + 1)),
                        Some(_) => {}
                        None => self.diag.report(Level::Warning, lineno, 0, "undefined string, using \"\"", &name),
                    }
                }
                'n' | '$' => {
                    // Decoded here, with the full escape expander, so that they can't split.
                    let start = i;
                    let mut j = i + 2;
                    if matches!(chars.get(j), Some('+') | Some('-')) && chars[i + 1] == 'n' {
                        j += 1;
                    }
                    let (_, next) = if chars.get(j) == Some(&ec) { (String::new(), (j + 3).min(chars.len())) } else { read_name(&chars, j) };
                    let esc: String = chars[start..next].iter().collect();
                    out.push_str(&self.expand_depth(&esc, lineno, depth + 1));
                    i = next;
                }
                c => {
                    out.push(ec);
                    out.push(c);
                    i += 2;
                }
            }
        }
        out
    }

    /// Decodes escapes in `s` (see the module comment).
    pub fn expand(&mut self, s: &str, lineno: usize) -> String {
        self.expand_depth(s, lineno, 0)
    }

    fn expand_depth(&mut self, s: &str, lineno: usize, depth: usize) -> String {
        let Some(ec) = self.escape_char() else { return s.to_string() };
        let mut out = String::with_capacity(s.len());
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c != ec {
                out.push(c);
                i += 1;
                continue;
            }
            i += 1;
            let Some(&e) = chars.get(i) else {
                // A trailing backslash: a line continuation, handled by callers as nothing.
                break;
            };
            i += 1;
            match e {
                '"' | '#' => break,
                'e' | '\\' => out.push(mark::BACKSLASH),
                '-' => out.push(mark::MINUS),
                '&' => out.push(mark::ZERO),
                ' ' | '~' | '0' => out.push(mark::NBSP),
                '|' | '^' | '%' | ':' | ',' | '/' | 'a' | 'd' | 'u' | 'r' | 'p' | 'E' | ')' | 'z' | '{' | '}' => {
                    // No output on a terminal. (`\{`/`\}` are handled by the condition code.)
                }
                'c' => {
                    if i >= chars.len() {
                        out.push(mark::CONT);
                    }
                }
                't' => out.push('\t'),
                '.' => out.push('.'),
                '\'' => out.push('\u{00B4}'),
                '`' => out.push('`'),
                '_' => out.push('_'),
                '!' => {}
                'f' => {
                    let (name, next) = read_name(&chars, i);
                    i = next;
                    out.push(font_mark(&name));
                }
                's' => {
                    // Size: \sN, \s±N, \s(NN, \s[N], \s'N'.
                    if matches!(chars.get(i), Some('+') | Some('-')) {
                        i += 1;
                    }
                    match chars.get(i) {
                        Some('(') => i += 3,
                        Some('[') | Some('\'') => {
                            let close = if chars[i] == '[' { ']' } else { '\'' };
                            i += 1;
                            while i < chars.len() && chars[i] != close {
                                i += 1;
                            }
                            i += 1;
                        }
                        Some(d) if d.is_ascii_digit() => {
                            i += 1;
                            // \s1 through \s3 may take a second digit.
                            if matches!(chars[i - 1], '1'..='3') && chars.get(i).is_some_and(|c| c.is_ascii_digit()) {
                                i += 1;
                            }
                        }
                        _ => {}
                    }
                }
                'm' | 'M' | 'F' | 'V' | 'Y' | 'k' | 'O' => {
                    let (_, next) = read_name(&chars, i);
                    i = next;
                }
                'h' | 'v' | 'w' | 'o' | 'b' | 'x' | 'l' | 'L' | 'D' | 'X' | 'R' | 'S' | 'H' | 'Z' | 'A' | 'B' => {
                    // Quoted-argument escapes.
                    let delim = chars.get(i).copied().unwrap_or('\'');
                    i += 1;
                    let start = i;
                    while i < chars.len() && chars[i] != delim {
                        i += 1;
                    }
                    let arg: String = chars[start..i.min(chars.len())].iter().collect();
                    i += 1;
                    match e {
                        'l' => {
                            // A horizontal line: its length, then optionally the character to
                            // draw it with (an underscore by default).
                            let digits: String = arg.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                            let rest = &arg[digits.len()..];
                            let unit_len = rest.chars().take_while(|c| c.is_ascii_alphabetic()).count();
                            let n = scale_cols(&arg[..digits.len() + unit_len.min(1)]);
                            let draw = &rest[unit_len.min(1)..];
                            let ch = if draw.is_empty() { "_".to_string() } else { self.expand_depth(draw, lineno, depth + 1) };
                            for _ in 0..n.min(200) {
                                out.push_str(&ch);
                            }
                        }
                        'h' => {
                            // Horizontal motion: whole ens become spaces, as mandoc does.
                            let n = self.number(&arg);
                            for _ in 0..n.clamp(0, 80) {
                                out.push(mark::NBSP);
                            }
                        }
                        'w' => {
                            let w = self.expand_depth(&arg, lineno, depth + 1).chars().filter(|c| !is_marker(*c)).count();
                            out.push_str(&(w * 24).to_string());
                        }
                        'o' => out.push_str(&arg),
                        'Z' => out.push_str(&self.expand_depth(&arg, lineno, depth + 1)),
                        'A' => out.push('1'),
                        'B' => out.push(if self.number(&arg) != 0 || arg.chars().any(|c| c.is_ascii_digit()) { '1' } else { '0' }),
                        _ => {}
                    }
                }
                'N' => {
                    let delim = chars.get(i).copied().unwrap_or('\'');
                    i += 1;
                    let start = i;
                    while i < chars.len() && chars[i] != delim {
                        i += 1;
                    }
                    let n: String = chars[start..i.min(chars.len())].iter().collect();
                    i += 1;
                    if let Some(ch) = n.parse::<u32>().ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                }
                'C' => {
                    let delim = chars.get(i).copied().unwrap_or('\'');
                    i += 1;
                    let start = i;
                    while i < chars.len() && chars[i] != delim {
                        i += 1;
                    }
                    let name: String = chars[start..i.min(chars.len())].iter().collect();
                    i += 1;
                    out.push_str(&self.special(&name, lineno));
                }
                '(' | '[' => {
                    let (name, next) = read_name(&chars, i - 1);
                    i = next;
                    out.push_str(&self.special(&name, lineno));
                }
                '*' => {
                    let (name, next) = read_name(&chars, i);
                    i = next;
                    // `\*[name arg ...]` passes arguments; take the name.
                    let name = name.split_whitespace().next().unwrap_or("").to_string();
                    match self.strings.get(&name).cloned() {
                        Some(v) if depth < MAX_DEPTH => out.push_str(&self.expand_depth(&v, lineno, depth + 1)),
                        Some(_) => {}
                        None => {
                            self.diag.report(Level::Warning, lineno, 0, "undefined string, using \"\"", &name);
                        }
                    }
                }
                'n' => {
                    let mut incr = 0;
                    if matches!(chars.get(i), Some('+') | Some('-')) {
                        incr = if chars[i] == '+' { 1 } else { -1 };
                        i += 1;
                    }
                    let (name, next) = if chars.get(i) == Some(&ec) {
                        // An escape as the name (`\n\n"`): the name is what it interpolates to.
                        let mut j = i + 1;
                        let nested: String = if chars.get(j) == Some(&'n') {
                            j += 1;
                            let (inner, after) = read_name(&chars, j);
                            j = after;
                            self.registers.get(&inner).copied().unwrap_or(0).to_string()
                        } else {
                            j += 1;
                            String::new()
                        };
                        (nested, j)
                    } else {
                        read_name(&chars, i)
                    };
                    i = next;
                    let v = self.registers.entry(name.clone()).or_insert(0);
                    *v += incr;
                    let v = *v;
                    out.push_str(&match name.as_str() {
                        // Built-in registers: the output line length and indentation, in basic
                        // units, and the troff/nroff mode.
                        ".T" | ".A" => "1".to_string(),
                        ".g" => "0".to_string(),
                        ".$" => self.frames.last().map(|f| f.len()).unwrap_or(0).to_string(),
                        _ => v.to_string(),
                    });
                }
                '$' => {
                    let frame = self.frames.last().cloned().unwrap_or_default();
                    match chars.get(i) {
                        Some('*') | Some('@') => {
                            let quote = chars[i] == '@';
                            i += 1;
                            let joined: Vec<String> = frame.iter().map(|a| if quote { format!("\"{a}\"") } else { a.clone() }).collect();
                            out.push_str(&joined.join(" "));
                        }
                        _ => {
                            let (name, next) = read_name(&chars, i);
                            i = next;
                            if let Ok(n) = name.parse::<usize>()
                                && n >= 1
                                && let Some(a) = frame.get(n - 1)
                            {
                                // Arguments were expanded when the macro was called.
                                out.push_str(a);
                            }
                        }
                    }
                }
                'g' | 'j' | 'P' => {
                    let (_, next) = read_name(&chars, i);
                    i = next;
                }
                c if c == ec => out.push(mark::BACKSLASH),
                other => {
                    // An unknown escape prints its character, as in roff.
                    self.diag.report(Level::Warning, lineno, 0, "undefined escape, printing literally", &format!("\\{other}"));
                    out.push(other);
                }
            }
        }
        out
    }

    fn special(&mut self, name: &str, lineno: usize) -> String {
        if let Some((u, _)) = chars::lookup(name) {
            return u.to_string();
        }
        // `\[uXXXX]` and `\[uXXXX_YYYY]`.
        if let Some(hex) = name.strip_prefix('u') {
            let s: Option<String> = hex.split('_').map(|h| u32::from_str_radix(h, 16).ok().and_then(char::from_u32)).collect();
            if let Some(s) = s {
                return s;
            }
        }
        // `\[char65]`.
        if let Some(n) = name.strip_prefix("char")
            && let Some(c) = n.parse::<u32>().ok().and_then(char::from_u32)
        {
            return c.to_string();
        }
        self.diag.report(Level::Warning, lineno, 0, "invalid special character", name);
        String::new()
    }
}

fn is_marker(c: char) -> bool {
    ('\u{E000}'..='\u{E01F}').contains(&c)
}

/// A roff length in terminal columns: `n`/`m` and no unit are columns, `i` ten, `c` about four,
/// `p` a seventh.
fn scale_cols(s: &str) -> usize {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let v: f64 = digits.parse().unwrap_or(0.0);
    let cols = match &s[digits.len()..] {
        "i" => v * 10.0,
        "c" => v * 10.0 / 2.54,
        "p" => v / 7.2,
        "P" => v * 10.0 / 6.0,
        "u" => v / 24.0,
        _ => v,
    };
    cols.round() as usize
}

/// The font marker for a `\f` name.
fn font_mark(name: &str) -> char {
    match name {
        "B" | "3" | "CB" => mark::FONT_B,
        "I" | "2" | "CI" => mark::FONT_I,
        "BI" | "4" => mark::FONT_BI,
        "CW" | "C" | "CR" | "CO" | "L" => mark::FONT_CW,
        "P" | "" => mark::FONT_P,
        _ => mark::FONT_R,
    }
}

/// Reads an escape's name at `chars[i]`: one character, `(xx`, or `[name]`. Returns the name and
/// the index after it.
fn read_name(chars: &[char], i: usize) -> (String, usize) {
    match chars.get(i) {
        Some('(') => {
            let n: String = chars.iter().skip(i + 1).take(2).collect();
            (n, (i + 3).min(chars.len()))
        }
        Some('[') => {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != ']' {
                j += 1;
            }
            (chars[i + 1..j].iter().collect(), (j + 1).min(chars.len()))
        }
        Some(&c) => (c.to_string(), i + 1),
        None => (String::new(), i),
    }
}

/// Removes a `\"` comment (not one escaped as `\\"`).
fn strip_comment(s: &str, ec: Option<char>) -> &str {
    let Some(ec) = ec else { return s };
    let b: Vec<(usize, char)> = s.char_indices().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i].1 == ec {
            if let Some(&(_, n)) = b.get(i + 1) {
                if n == '"' || n == '#' {
                    return s[..b[i].0].trim_end_matches([' ', '\t']);
                }
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    s
}

fn is_end_marker(raw: &str, cc: char, end: &str) -> bool {
    let rest = raw.strip_prefix(cc).or_else(|| raw.strip_prefix('\'')).map(|r| r.trim_start());
    rest.is_some_and(|r| split_name(r).0 == end)
}

/// Splits a request or macro name from its arguments.
fn split_name(s: &str) -> (&str, &str) {
    let end = s.find([' ', '\t']).unwrap_or(s.len());
    (&s[..end], s[end..].trim_start_matches([' ', '\t']))
}

/// Splits raw (still escaped) macro arguments at unescaped spaces, honoring double quotes
/// (`""` inside quotes is one quote). Escapes are copied through for decoding later.
fn split_raw(s: &str, ec: char) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut args = Vec::new();
    let mut i = 0;
    loop {
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut arg = String::new();
        let quoted = chars[i] == '"';
        if quoted {
            i += 1;
        }
        while i < chars.len() {
            let c = chars[i];
            if c == ec && i + 1 < chars.len() {
                arg.push(c);
                arg.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if quoted && c == '"' {
                if chars.get(i + 1) == Some(&'"') {
                    arg.push('"');
                    i += 2;
                    continue;
                }
                i += 1;
                break;
            }
            if !quoted && (c == ' ' || c == '\t') {
                break;
            }
            arg.push(c);
            i += 1;
        }
        args.push(arg);
    }
    args
}

/// Splits macro arguments at spaces, honoring double quotes (`""` inside quotes is one quote).
/// Escapes have already been decoded, so an escaped space is [`mark::NBSP`] and doesn't split.
pub fn split_args(s: &str, _macro_line: bool) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
            chars.next();
        }
        let Some(&first) = chars.peek() else { break };
        let mut arg = String::new();
        if first == '"' {
            chars.next();
            loop {
                match chars.next() {
                    None => break,
                    Some('"') => {
                        if chars.peek() == Some(&'"') {
                            chars.next();
                            arg.push('"');
                        } else {
                            break;
                        }
                    }
                    Some(c) => arg.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ' ' || c == '\t' {
                    break;
                }
                arg.push(c);
                chars.next();
            }
        }
        args.push(arg);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str) -> Vec<Line> {
        let mut d = Diagnostics::new("t");
        Roff::new(&mut d).run(input)
    }

    #[test]
    fn strings_and_escapes() {
        let l = run(".ds Xx hello\n\\*(Xx \\(em \\fBb\\fR\n");
        assert_eq!(l, vec![Line::Text { text: format!("hello \u{2014} {}b{}", mark::FONT_B, mark::FONT_R), line: 2 }]);
    }

    #[test]
    fn macros_and_args() {
        let l = run(".de XX\n.YY \\\\$2 \\\\$1\n..\n.XX a \"b c\"\n");
        assert_eq!(l, vec![Line::Macro { name: "YY".into(), args: vec!["b".into(), "c".into(), "a".into()], line: 4, no_break: false }]);
    }

    #[test]
    fn conditionals() {
        let l = run(".if n on\n.if t off\n.ie '\\*(Zz'' empty\n.el not\n.if 1 \\{\\\nyes\n.\\}\n.if 0 \\{\nno\n.\\}\nafter\n");
        let texts: Vec<String> = l.iter().filter_map(|l| if let Line::Text { text, .. } = l { Some(text.clone()) } else { None }).collect();
        assert_eq!(texts, ["on", "empty", "yes", "after"]);
        let l = run(".if 1 \\{ one \\}\n.if 0 \\{ two \\}\nthree\n");
        let texts: Vec<String> = l.iter().filter_map(|l| if let Line::Text { text, .. } = l { Some(text.trim().to_string()) } else { None }).collect();
        assert_eq!(texts, ["one", "three"]);
    }

    #[test]
    fn quoting() {
        assert_eq!(split_args("a \"b c\" \"d \"\"e\"\"\"", true), ["a", "b c", "d \"e\""]);
    }
}
