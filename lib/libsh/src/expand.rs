//! Word expansion (XCU 2.6): tilde, parameter, command substitution, arithmetic, field
//! splitting, pathname expansion, quote removal.
//!
//! Every character produced carries a `Kind`, which decides what the later steps may do to it:
//! unquoted literal source text is globbed but never split, unquoted expansion results are split
//! and globbed, and quoted characters are left alone. `"$@"` additionally inserts forced field
//! boundaries.

use crate::ast::*;
use crate::pattern::{self, PatChar};
use crate::shell::{Flow, Shell};
use crate::sys;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Literal,
    Expanded,
    Quoted,
}

#[derive(Default)]
struct Field {
    chars: Vec<(char, Kind)>,
    /// Contains a quoted part, even an empty one (`""`): the field survives even if empty.
    quoted: bool,
}

#[derive(Default)]
struct Builder {
    done: Vec<Field>,
    cur: Field,
}

impl Builder {
    fn push(&mut self, s: &str, kind: Kind) {
        self.cur.chars.extend(s.chars().map(|c| (c, kind)));
        if kind == Kind::Quoted {
            self.cur.quoted = true;
        }
    }

    fn mark_quoted(&mut self) {
        self.cur.quoted = true;
    }

    /// A forced field boundary (between the words of `"$@"`).
    fn split(&mut self) {
        let f = std::mem::take(&mut self.cur);
        self.done.push(f);
    }

    fn finish(mut self) -> Vec<Field> {
        self.done.push(self.cur);
        self.done
    }
}

/// How the expansion is used: full (split and glob), a single string (assignments, redirection
/// targets, `case` words, here-documents), or a pattern (quoting preserved).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Fields,
    Single,
}

impl Shell {
    /// Full expansion of a command's words into fields.
    pub fn expand_words(&mut self, words: &[Word]) -> Result<Vec<String>, Flow> {
        let mut out = Vec::new();
        for w in words {
            out.extend(self.expand_fields(w)?);
        }
        Ok(out)
    }

    fn expand_fields(&mut self, word: &Word) -> Result<Vec<String>, Flow> {
        let mut b = Builder::default();
        self.expand_parts(word, false, false, Mode::Fields, &mut b, true)?;
        let fields = self.split_fields(b.finish());
        let mut out = Vec::new();
        for f in fields {
            if !self.opts.noglob && has_unquoted_magic(&f.chars) {
                let pat: Vec<PatChar> = f.chars.iter().map(|&(c, k)| PatChar { c, quoted: k == Kind::Quoted }).collect();
                let matches = glob(&pat);
                if !matches.is_empty() {
                    out.extend(matches);
                    continue;
                }
            }
            out.push(f.chars.iter().map(|&(c, _)| c).collect());
        }
        Ok(out)
    }

    /// Expansion to a single string, with no field splitting or pathname expansion.
    pub fn expand_string(&mut self, word: &Word) -> Result<String, Flow> {
        let mut b = Builder::default();
        self.expand_parts(word, false, false, Mode::Single, &mut b, true)?;
        let fields = b.finish();
        let strings: Vec<String> = fields.iter().map(|f| f.chars.iter().map(|&(c, _)| c).collect()).collect();
        Ok(strings.join(" "))
    }

    /// Expansion for use as a pattern (`case`, `${x#pat}`): quoted characters stay literal.
    pub fn expand_pattern(&mut self, word: &Word) -> Result<Vec<PatChar>, Flow> {
        let mut b = Builder::default();
        self.expand_parts(word, false, false, Mode::Single, &mut b, true)?;
        let mut out = Vec::new();
        for (i, f) in b.finish().into_iter().enumerate() {
            if i > 0 {
                out.push(PatChar { c: ' ', quoted: true });
            }
            out.extend(f.chars.into_iter().map(|(c, k)| PatChar { c, quoted: k == Kind::Quoted }));
        }
        Ok(out)
    }

    /// `in_dq`: inside double quotes. `nested`: inside `${x-word}`, whose literal text behaves
    /// like an expansion result (it's split when the enclosing expansion is unquoted).
    fn expand_parts(&mut self, parts: &[WordPart], in_dq: bool, nested: bool, mode: Mode, b: &mut Builder, word_start: bool) -> Result<(), Flow> {
        for (i, part) in parts.iter().enumerate() {
            match part {
                WordPart::Literal(s) => {
                    let s = if i == 0 && word_start && !in_dq { self.tilde(s, parts.len() == 1) } else { s.clone() };
                    let kind = if in_dq {
                        Kind::Quoted
                    } else if nested {
                        Kind::Expanded
                    } else {
                        Kind::Literal
                    };
                    b.push(&s, kind);
                }
                WordPart::Quoted(s) => b.push(s, Kind::Quoted),
                WordPart::DoubleQuoted(inner) => {
                    let only_at = inner.len() == 1
                        && matches!(&inner[0], WordPart::Param(ParamExpansion { param: Param::Special('@'), op: ParamOp::Plain }));
                    if !(only_at && self.positional.is_empty()) {
                        b.mark_quoted();
                    }
                    self.expand_parts(inner, true, nested, mode, b, false)?;
                }
                WordPart::Param(pe) => self.expand_param(pe, in_dq, mode, b)?,
                WordPart::CommandSubst(list) => {
                    let out = self.capture(list)?;
                    b.push(&out, if in_dq { Kind::Quoted } else { Kind::Expanded });
                }
                WordPart::Arith(expr) => {
                    let text = {
                        let mut ib = Builder::default();
                        self.expand_parts(expr, true, false, Mode::Single, &mut ib, false)?;
                        ib.finish().into_iter().map(|f| f.chars.into_iter().map(|(c, _)| c).collect::<String>()).collect::<Vec<_>>().join(" ")
                    };
                    let value = crate::arith::eval(&text, &mut ArithVars(self)).map_err(|e| {
                        self.error(&format!("arithmetic expression: {e}: \"{}\"", text.trim()));
                        Flow::Exit(2)
                    })?;
                    b.push(&value.to_string(), if in_dq { Kind::Quoted } else { Kind::Expanded });
                }
            }
        }
        Ok(())
    }

    /// `~` and `~user` at the start of an unquoted word (up to the first `/`).
    fn tilde(&self, s: &str, whole_word_literal: bool) -> String {
        let _ = whole_word_literal;
        let Some(rest) = s.strip_prefix('~') else { return s.to_string() };
        let (user, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let home = if user.is_empty() { self.get("HOME") } else { sys::home_of(user) };
        match home {
            Some(h) => format!("{h}{tail}"),
            None => s.to_string(),
        }
    }

    /// The value of a parameter, `None` if unset. `$@`/`$*` join with spaces here.
    pub fn param_value(&self, p: &Param) -> Option<String> {
        match p {
            Param::Named(n) => self.get(n),
            Param::Positional(n) => self.positional.get(n.wrapping_sub(1)).cloned(),
            Param::Special(c) => match c {
                '#' => Some(self.positional.len().to_string()),
                '?' => Some(self.status.to_string()),
                '$' => Some(self.shell_pid.to_string()),
                '!' => self.last_bg.map(|p| p.to_string()),
                '0' => Some(self.arg0.clone()),
                '-' => Some(self.option_letters()),
                '@' | '*' => {
                    if self.positional.is_empty() {
                        None
                    } else {
                        Some(self.positional.join(" "))
                    }
                }
                _ => None,
            },
        }
    }

    pub fn option_letters(&self) -> String {
        let mut s = String::new();
        for &(c, _) in crate::shell::Options::LETTERS {
            let mut o = self.opts;
            if o.flag_mut(c).is_some_and(|f| *f) {
                s.push(c);
            }
        }
        s
    }

    fn expand_param(&mut self, pe: &ParamExpansion, in_dq: bool, mode: Mode, b: &mut Builder) -> Result<(), Flow> {
        let kind = if in_dq { Kind::Quoted } else { Kind::Expanded };
        let is_at_or_star = matches!(pe.param, Param::Special('@' | '*'));
        let name = param_name(&pe.param);
        let value = self.param_value(&pe.param);
        let set_and_nonempty = |colon: bool, v: &Option<String>| match v {
            None => false,
            Some(s) => !(colon && s.is_empty()),
        };
        match &pe.op {
            ParamOp::Plain => {
                if value.is_none() && self.opts.nounset && !is_at_or_star {
                    self.error(&format!("{name}: parameter not set"));
                    return Err(Flow::Exit(2));
                }
                if is_at_or_star {
                    self.push_positional(pe.param == Param::Special('@'), in_dq, mode, b);
                } else if let Some(v) = value {
                    b.push(&v, kind);
                }
            }
            ParamOp::Length => {
                if value.is_none() && self.opts.nounset && !is_at_or_star {
                    self.error(&format!("{name}: parameter not set"));
                    return Err(Flow::Exit(2));
                }
                let n = if is_at_or_star { self.positional.len() } else { value.unwrap_or_default().chars().count() };
                b.push(&n.to_string(), kind);
            }
            ParamOp::Default { colon, word } => {
                if set_and_nonempty(*colon, &value) {
                    if is_at_or_star {
                        self.push_positional(pe.param == Param::Special('@'), in_dq, mode, b);
                    } else {
                        b.push(&value.unwrap(), kind);
                    }
                } else {
                    self.expand_parts(word, in_dq, true, mode, b, false)?;
                }
            }
            ParamOp::Alternative { colon, word } => {
                if set_and_nonempty(*colon, &value) {
                    self.expand_parts(word, in_dq, true, mode, b, false)?;
                }
            }
            ParamOp::Assign { colon, word } => {
                if set_and_nonempty(*colon, &value) {
                    b.push(&value.unwrap(), kind);
                } else {
                    let Param::Named(n) = &pe.param else {
                        self.error(&format!("{name}: bad variable name"));
                        return Err(Flow::Exit(2));
                    };
                    let v = self.expand_string(word)?;
                    if let Err(e) = self.set(n, &v) {
                        self.error(&e);
                        return Err(Flow::Exit(2));
                    }
                    b.push(&v, kind);
                }
            }
            ParamOp::Error { colon, word } => {
                if set_and_nonempty(*colon, &value) {
                    b.push(&value.unwrap(), kind);
                } else {
                    let msg = self.expand_string(word)?;
                    let msg = if msg.is_empty() { "parameter not set".to_string() } else { msg };
                    self.error(&format!("{name}: {msg}"));
                    return Err(Flow::Exit(2));
                }
            }
            ParamOp::RemovePrefix { longest, pattern } | ParamOp::RemoveSuffix { longest, pattern } => {
                if value.is_none() && self.opts.nounset {
                    self.error(&format!("{name}: parameter not set"));
                    return Err(Flow::Exit(2));
                }
                let v = value.unwrap_or_default();
                let pat = self.expand_pattern(pattern)?;
                let suffix = matches!(pe.op, ParamOp::RemoveSuffix { .. });
                b.push(&remove_affix(&v, &pat, suffix, *longest), kind);
            }
        }
        Ok(())
    }

    fn push_positional(&mut self, at: bool, in_dq: bool, mode: Mode, b: &mut Builder) {
        if in_dq && !at {
            // "$*": joined with the first character of IFS.
            let sep = self.ifs().chars().next().map(String::from).unwrap_or_default();
            b.push(&self.positional.join(&sep), Kind::Quoted);
            return;
        }
        let kind = if in_dq { Kind::Quoted } else { Kind::Expanded };
        let params = self.positional.clone();
        for (i, p) in params.iter().enumerate() {
            if i > 0 {
                if mode == Mode::Fields {
                    b.split();
                } else {
                    b.push(" ", kind);
                }
                if in_dq {
                    b.mark_quoted();
                }
            }
            b.push(p, kind);
        }
    }

    /// Field splitting (XCU 2.6.5) over the `Expanded` characters of each field.
    fn split_fields(&self, fields: Vec<Field>) -> Vec<Field> {
        let ifs = self.ifs();
        let is_ifs_ws = |c: char| ifs.contains(c) && matches!(c, ' ' | '\t' | '\n');
        let mut out = Vec::new();
        for f in fields {
            if ifs.is_empty() {
                if !f.chars.is_empty() || f.quoted {
                    out.push(f);
                }
                continue;
            }
            let first_out = out.len();
            let mut cur = Field { chars: Vec::new(), quoted: false };
            let mut started = false;
            // The previous delimiter consisted of IFS whitespace only (a following non-whitespace
            // IFS character joins it rather than starting another empty field).
            let mut after_ws_delim = false;
            for (c, k) in f.chars {
                if k == Kind::Expanded && ifs.contains(c) {
                    if is_ifs_ws(c) {
                        if started {
                            out.push(std::mem::replace(&mut cur, Field { chars: Vec::new(), quoted: false }));
                            started = false;
                            after_ws_delim = true;
                        }
                    } else {
                        if !after_ws_delim || started {
                            out.push(std::mem::replace(&mut cur, Field { chars: Vec::new(), quoted: false }));
                        }
                        started = false;
                        after_ws_delim = false;
                    }
                    continue;
                }
                cur.chars.push((c, k));
                started = true;
                after_ws_delim = false;
            }
            if f.quoted && out.len() == first_out && !started {
                cur.quoted = true;
                out.push(cur);
            } else if started {
                cur.quoted = f.quoted;
                out.push(cur);
            }
        }
        out
    }

    /// `$( … )`: runs `list` in a subshell and returns its output without trailing newlines.
    pub fn capture(&mut self, list: &List) -> Result<String, Flow> {
        let (r, w) = sys::pipe().map_err(|e| {
            self.error(&format!("cannot create pipe: {e}"));
            Flow::Exit(2)
        })?;
        match sys::fork() {
            Ok(0) => {
                sys::close(r);
                let _ = sys::dup2(w, 1);
                if w != 1 {
                    sys::close(w);
                }
                self.enter_subshell();
                let status = match self.run_list(list) {
                    Ok(s) => s,
                    Err(Flow::Exit(s) | Flow::Return(s)) => s,
                    Err(_) => self.status,
                };
                let status = self.finish(status);
                sys::exit_child(status);
            }
            Ok(pid) => {
                sys::close(w);
                let bytes = sys::read_to_end(r).unwrap_or_default();
                sys::close(r);
                let status = sys::wait_pid(pid).unwrap_or(1);
                self.status = status;
                self.subst_status = Some(status);
                let mut s = String::from_utf8_lossy(&bytes).into_owned();
                while s.ends_with('\n') {
                    s.pop();
                }
                Ok(s)
            }
            Err(e) => {
                self.error(&format!("cannot fork: {e}"));
                Err(Flow::Exit(2))
            }
        }
    }
}

struct ArithVars<'a>(&'a mut Shell);

impl crate::arith::Vars for ArithVars<'_> {
    fn get(&self, name: &str) -> Option<String> {
        self.0.get(name)
    }
    fn set(&mut self, name: &str, value: i64) -> Result<(), String> {
        self.0.set(name, &value.to_string())
    }
}

fn param_name(p: &Param) -> String {
    match p {
        Param::Named(n) => n.clone(),
        Param::Positional(n) => n.to_string(),
        Param::Special(c) => c.to_string(),
    }
}

fn has_unquoted_magic(chars: &[(char, Kind)]) -> bool {
    chars.iter().any(|&(c, k)| k != Kind::Quoted && matches!(c, '*' | '?' | '['))
}

/// `${x#p}`, `${x##p}`, `${x%p}`, `${x%%p}`.
fn remove_affix(value: &str, pat: &[PatChar], suffix: bool, longest: bool) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    let candidates: Box<dyn Iterator<Item = usize>> = match (suffix, longest) {
        // prefix lengths
        (false, false) => Box::new(0..=n),
        (false, true) => Box::new((0..=n).rev()),
        // suffix start positions
        (true, false) => Box::new((0..=n).rev()),
        (true, true) => Box::new(0..=n),
    };
    for k in candidates {
        let (matched, keep): (String, String) = if suffix {
            (chars[k..].iter().collect(), chars[..k].iter().collect())
        } else {
            (chars[..k].iter().collect(), chars[k..].iter().collect())
        };
        if pattern::matches(pat, &matched) {
            return keep;
        }
    }
    value.to_string()
}

/// Pathname expansion: every existing path matching the pattern, sorted; empty if none.
fn glob(pat: &[PatChar]) -> Vec<String> {
    let absolute = pat.first().is_some_and(|p| p.c == '/');
    let components: Vec<&[PatChar]> = pat.split(|p| p.c == '/').filter(|c| !c.is_empty()).collect();
    let mut paths: Vec<String> = vec![if absolute { "/".into() } else { String::new() }];
    // `dir/*/`: a trailing slash means even the last component must name a directory.
    let trailing_slash = pat.last().is_some_and(|p| p.c == '/');
    for (i, comp) in components.iter().enumerate() {
        let last = i + 1 == components.len() && !trailing_slash;
        let mut next = Vec::new();
        for base in &paths {
            if !pattern::has_magic(comp) {
                let name: String = comp.iter().map(|p| p.c).collect();
                let path = join(base, &name);
                if last || std::path::Path::new(&path).is_dir() {
                    if !last || std::fs::symlink_metadata(&path).is_ok() {
                        next.push(path);
                    }
                }
                continue;
            }
            let dir = if base.is_empty() { ".".to_string() } else { base.clone() };
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            let mut names: Vec<String> = entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().map(String::from))
                .filter(|n| pattern::matches_filename(comp, n))
                .collect();
            names.sort();
            for n in names {
                let path = join(base, &n);
                if last || std::path::Path::new(&path).is_dir() {
                    next.push(path);
                }
            }
        }
        paths = next;
        if paths.is_empty() {
            break;
        }
    }
    if trailing_slash {
        paths = paths.into_iter().map(|p| format!("{p}/")).collect();
    }
    paths.sort();
    paths
}

fn join(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}
