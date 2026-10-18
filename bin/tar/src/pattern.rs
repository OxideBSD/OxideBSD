//! Name patterns: the shell-style globs of `--exclude`, `-X` and the operands of `-t`/`-x`, and
//! `-s`'s substitutions.
//!
//! As in bsdtar, an exclusion matches a name if it matches the whole name, any part of it that
//! starts after a `/`, or any part that ends before one: `--exclude '*.o'` leaves out
//! `src/a.o`, `--exclude CVS` every `CVS` directory and what is in it. An operand of `-t` or
//! `-x` must match from the start of a name, the whole name or a leading part of it ending
//! before a `/`, so a directory's name selects what is in it. In both, `*` and `?` match `/`
//! too, and a leading `./` is ignored on either side.

use posixre::{CompileFlags, ExecFlags, Regex};

/// fnmatch(3) without flags: `*`, `?`, `[...]` (with `!` or `^` negation and ranges), `\`
/// quoting the next character.
pub fn glob(p: &[u8], s: &[u8]) -> bool {
    // Iterative, with one backtrack point for the last `*`: linear for every pattern.
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
                    if let Some((ok, end)) = class(p, pi, s[si]) {
                        if ok {
                            pi = end;
                            si += 1;
                            continue;
                        }
                    } else if s[si] == b'[' {
                        // An unclosed bracket is an ordinary character.
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

/// A bracket expression at `p[at]` against `c`: (matched, index after it), or None if it is
/// not closed.
fn class(p: &[u8], at: usize, c: u8) -> Option<(bool, usize)> {
    let mut i = at + 1;
    let neg = matches!(p.get(i), Some(b'!' | b'^'));
    if neg {
        i += 1;
    }
    let mut hit = false;
    let mut first = true;
    loop {
        let &b = p.get(i)?;
        if b == b']' && !first {
            return Some((hit != neg, i + 1));
        }
        first = false;
        let lo = if b == b'\\' && i + 1 < p.len() {
            i += 1;
            p[i]
        } else {
            b
        };
        if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|&x| x != b']') {
            let hi = p[i + 2];
            hit |= (lo..=hi).contains(&c);
            i += 3;
        } else {
            hit |= lo == c;
            i += 1;
        }
    }
}

fn strip_dot(s: &[u8]) -> &[u8] {
    let mut s = s;
    while let Some(r) = s.strip_prefix(b"./") {
        s = r;
        while let Some(r) = s.strip_prefix(b"/") {
            s = r;
        }
    }
    s
}

/// Where a name may be cut: its end, and before each `/`.
fn ends(s: &[u8]) -> impl Iterator<Item = usize> + '_ {
    (1..s.len()).filter(|&i| s[i] == b'/').chain(std::iter::once(s.len()))
}

/// Whether exclusion pattern `p` matches `name` (see the module comment).
pub fn excludes(p: &[u8], name: &[u8]) -> bool {
    let p = strip_dot(p);
    let s = strip_dot(name);
    let starts = std::iter::once(0).chain((0..s.len()).filter(|&i| s[i] == b'/').map(|i| i + 1));
    for a in starts {
        for b in ends(s) {
            if b > a && glob(p, &s[a..b]) {
                return true;
            }
        }
    }
    false
}

/// Whether operand pattern `p` selects `name`.
pub fn includes(p: &[u8], name: &[u8]) -> bool {
    let p = strip_dot(p);
    let p = p.strip_suffix(b"/").unwrap_or(p);
    let s = strip_dot(name);
    let s = s.strip_suffix(b"/").unwrap_or(s);
    ends(s).any(|b| glob(p, &s[..b]))
}

/// One `-s /old/new/flags` rule.
pub struct Subst {
    re: Regex,
    new: Vec<u8>,
    global: bool,
    print: bool,
    regular: bool,
    hardlinks: bool,
    symlinks: bool,
}

/// Which name a substitution is applied to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Name,
    HardLink,
    Symlink,
}

impl Subst {
    /// Parses `/old/new/[gpHhRrSs]`; any character may stand for the `/`.
    pub fn parse(spec: &[u8]) -> Result<Subst, String> {
        let &d = spec.first().ok_or("Invalid replacement string")?;
        let mut parts: Vec<Vec<u8>> = vec![Vec::new()];
        let mut i = 1;
        while i < spec.len() && parts.len() < 3 {
            let c = spec[i];
            if c == b'\\' && i + 1 < spec.len() && spec[i + 1] == d {
                parts.last_mut().unwrap().push(d);
                i += 2;
                continue;
            }
            if c == b'\\' && i + 1 < spec.len() {
                parts.last_mut().unwrap().extend_from_slice(&spec[i..i + 2]);
                i += 2;
                continue;
            }
            if c == d {
                parts.push(Vec::new());
            } else {
                parts.last_mut().unwrap().push(c);
            }
            i += 1;
        }
        if parts.len() < 3 {
            return Err("Invalid replacement string".into());
        }
        let flags = &spec[i..];
        let mut s = Subst {
            re: Regex::new(&parts[0], CompileFlags::BASIC).map_err(|e| format!("Invalid regular expression: {e}"))?,
            new: parts[1].clone(),
            global: false,
            print: false,
            regular: true,
            hardlinks: true,
            symlinks: true,
        };
        for &f in flags {
            match f {
                b'g' => s.global = true,
                b'p' => s.print = true,
                b'H' => s.hardlinks = false,
                b'h' => s.hardlinks = true,
                b'R' => s.regular = false,
                b'r' => s.regular = true,
                b'S' => s.symlinks = false,
                b's' => s.symlinks = true,
                _ => return Err("Invalid replacement flag".into()),
            }
        }
        Ok(s)
    }

    fn applies(&self, t: Target) -> bool {
        match t {
            Target::Name => self.regular,
            Target::HardLink => self.hardlinks,
            Target::Symlink => self.symlinks,
        }
    }

    /// The name with this rule applied, or None if it does not match.
    fn apply(&self, name: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut at = 0;
        let mut any = false;
        while at <= name.len() {
            let flags = if at > 0 { ExecFlags::NOTBOL } else { ExecFlags::NONE };
            let Ok(Some(groups)) = self.re.try_captures_at(name, at..name.len(), flags) else { break };
            let Some(m) = groups[0] else { break };
            any = true;
            out.extend_from_slice(&name[at..m.0]);
            let mut i = 0;
            while i < self.new.len() {
                let c = self.new[i];
                if c == b'&' {
                    out.extend_from_slice(&name[m.0..m.1]);
                } else if c == b'\\' && i + 1 < self.new.len() {
                    i += 1;
                    let d = self.new[i];
                    if d.is_ascii_digit() && d != b'0' {
                        if let Some(Some(g)) = groups.get(usize::from(d - b'0')) {
                            out.extend_from_slice(&name[g.0..g.1]);
                        }
                    } else {
                        out.push(d);
                    }
                } else {
                    out.push(c);
                }
                i += 1;
            }
            if m.1 == m.0 {
                // An empty match: copy one byte and try after it.
                if m.1 < name.len() {
                    out.push(name[m.1]);
                }
                at = m.1 + 1;
            } else {
                at = m.1;
            }
            if !self.global {
                break;
            }
        }
        if !any {
            return None;
        }
        if at < name.len() {
            out.extend_from_slice(&name[at..]);
        }
        Some(out)
    }
}

/// Applies the first rule of `rules` that matches `name`, as pax(1) does. `print` gets the
/// rule's `p` flag.
pub fn substitute(rules: &[Subst], name: &[u8], t: Target) -> (Vec<u8>, bool) {
    for r in rules.iter().filter(|r| r.applies(t)) {
        if let Some(n) = r.apply(name) {
            return (n, r.print);
        }
    }
    (name.to_vec(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob(b"*.c", b"a.c"));
        assert!(glob(b"*.c", b"d/a.c"));
        assert!(!glob(b"*.c", b"a.h"));
        assert!(glob(b"a?c", b"abc"));
        assert!(glob(b"[a-c]x", b"bx"));
        assert!(!glob(b"[!a-c]x", b"bx"));
        assert!(glob(b"[]]", b"]"));
        assert!(glob(b"\\*", b"*"));
        assert!(!glob(b"\\*", b"a"));
        assert!(glob(b"a*b*c", b"aXXbYYc"));
        assert!(!glob(b"a*b*c", b"aXXbYY"));
        assert!(glob(b"[", b"["));
    }

    #[test]
    fn matching() {
        assert!(excludes(b"*.o", b"src/a.o"));
        assert!(excludes(b"CVS", b"a/CVS/Root"));
        assert!(!excludes(b"CVS", b"a/CVSx"));
        assert!(excludes(b"./a", b"a/b"));
        assert!(includes(b"dir", b"dir/x"));
        assert!(includes(b"dir/", b"./dir/x"));
        assert!(!includes(b"x", b"dir/x"));
        assert!(includes(b"d*", b"dir/x"));
    }

    #[test]
    fn substitutions() {
        let s = Subst::parse(b"/a/b/").unwrap();
        assert_eq!(s.apply(b"xaya"), Some(b"xbya".to_vec()));
        let s = Subst::parse(b"/a/b/g").unwrap();
        assert_eq!(s.apply(b"xaya"), Some(b"xbyb".to_vec()));
        let s = Subst::parse(b",^\\(.*\\)/\\(.*\\)$,\\2-\\1&,").unwrap();
        assert_eq!(s.apply(b"d/f"), Some(b"f-dd/f".to_vec()));
        let s = Subst::parse(b"/^/pre\\//").unwrap();
        assert_eq!(s.apply(b"f"), Some(b"pre/f".to_vec()));
        assert!(Subst::parse(b"/a/b").is_err());
        assert!(Subst::parse(b"/a/b/z").is_err());
    }
}
