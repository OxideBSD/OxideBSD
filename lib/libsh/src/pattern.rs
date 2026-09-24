//! Pattern matching notation (XCU 2.13): `*`, `?`, and bracket expressions. Used by `case`,
//! `${x%pattern}`-style expansions, and pathname expansion.
//!
//! A pattern is a sequence of characters that each remember whether they were quoted: a quoted
//! `*` matches only a literal `*`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatChar {
    pub c: char,
    pub quoted: bool,
}

pub type Pattern = [PatChar];

/// Whether the pattern contains any unquoted special character (used to skip pathname expansion
/// for plain words).
pub fn has_magic(p: &Pattern) -> bool {
    p.iter().any(|pc| !pc.quoted && matches!(pc.c, '*' | '?' | '['))
}

/// Matches the whole of `s` against `p`.
pub fn matches(p: &Pattern, s: &str) -> bool {
    let s: Vec<char> = s.chars().collect();
    match_at(p, &s, false)
}

/// Pathname-component matching: a leading `.` must be matched explicitly.
pub fn matches_filename(p: &Pattern, s: &str) -> bool {
    let s: Vec<char> = s.chars().collect();
    match_at(p, &s, true)
}

fn match_at(p: &Pattern, s: &[char], leading_dot_explicit: bool) -> bool {
    if leading_dot_explicit
        && s.first() == Some(&'.')
        && !matches!(p.first(), Some(PatChar { c: '.', .. }))
    {
        return false;
    }
    // Iterative matcher with single-star backtracking (star positions are independent for `*`).
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() {
            let pc = p[pi];
            if !pc.quoted && pc.c == '*' {
                star = Some((pi, si));
                pi += 1;
                continue;
            }
            if !pc.quoted && pc.c == '?' {
                pi += 1;
                si += 1;
                continue;
            }
            if !pc.quoted && pc.c == '['
                && let Some((matched, next_pi)) = bracket(p, pi, s[si])
            {
                if matched {
                    pi = next_pi;
                    si += 1;
                    continue;
                }
            } else if pc.c == s[si] && (pc.quoted || pc.c != '[' || bracket(p, pi, s[si]).is_none()) {
                pi += 1;
                si += 1;
                continue;
            }
        }
        match star {
            Some((spi, ssi)) => {
                pi = spi + 1;
                si = ssi + 1;
                star = Some((spi, ssi + 1));
            }
            None => return false,
        }
    }
    while pi < p.len() && !p[pi].quoted && p[pi].c == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Evaluates the bracket expression starting at `p[start] == '['` against `c`. Returns
/// `(matched, index after the closing ']')`, or `None` if there is no closing `]` (then `[` is an
/// ordinary character).
fn bracket(p: &Pattern, start: usize, c: char) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let negate = i < p.len() && !p[i].quoted && matches!(p[i].c, '!' | '^');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let pc = *p.get(i)?;
        if pc.c == ']' && !pc.quoted && !first {
            return Some((matched != negate, i + 1));
        }
        first = false;
        // [:class:]
        if pc.c == '[' && !pc.quoted && p.get(i + 1).is_some_and(|n| n.c == ':') {
            let rest: String = p[i + 2..].iter().map(|x| x.c).collect();
            if let Some(end) = rest.find(":]") {
                if class_matches(&rest[..end], c) {
                    matched = true;
                }
                i += 2 + end + 2;
                continue;
            }
        }
        // range a-z (a `-` first or last is literal)
        if p.get(i + 1).is_some_and(|d| d.c == '-' && !d.quoted)
            && p.get(i + 2).is_some_and(|e| !(e.c == ']' && !e.quoted))
        {
            let lo = pc.c;
            let hi = p[i + 2].c;
            if lo <= c && c <= hi {
                matched = true;
            }
            i += 3;
            continue;
        }
        if pc.c == c {
            matched = true;
        }
        i += 1;
    }
}

fn class_matches(class: &str, c: char) -> bool {
    match class {
        "alnum" => c.is_ascii_alphanumeric(),
        "alpha" => c.is_ascii_alphabetic(),
        "blank" => c == ' ' || c == '\t',
        "cntrl" => c.is_ascii_control(),
        "digit" => c.is_ascii_digit(),
        "graph" => c.is_ascii_graphic(),
        "lower" => c.is_ascii_lowercase(),
        "print" => c.is_ascii_graphic() || c == ' ',
        "punct" => c.is_ascii_punctuation(),
        "space" => c.is_ascii_whitespace() || c == '\x0b',
        "upper" => c.is_ascii_uppercase(),
        "xdigit" => c.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Converts plain text (all characters unquoted) into a pattern — convenience for tests and
/// callers that already hold an unquoted string.
pub fn unquoted(s: &str) -> Vec<PatChar> {
    s.chars().map(|c| PatChar { c, quoted: false }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, s: &str) -> bool {
        matches(&unquoted(p), s)
    }

    #[test]
    fn basics() {
        assert!(m("*", ""));
        assert!(m("a*c", "abbbc"));
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(m("*.txt", "notes.txt"));
        assert!(!m("*.txt", "notes.txt.bak"));
        assert!(m("[abc]x", "bx"));
        assert!(m("[!abc]x", "dx"));
        assert!(m("[a-c]", "b"));
        assert!(!m("[a-c]", "d"));
        assert!(m("[]]", "]"));
        assert!(m("[[:digit:]]*", "7up"));
        assert!(m("[", "["));
        assert!(m("a[", "a["));
    }

    #[test]
    fn quoted_specials_are_literal() {
        let p = vec![PatChar { c: '*', quoted: true }];
        assert!(matches(&p, "*"));
        assert!(!matches(&p, "abc"));
    }

    #[test]
    fn leading_dot() {
        assert!(!matches_filename(&unquoted("*"), ".hidden"));
        assert!(matches_filename(&unquoted(".*"), ".hidden"));
    }
}
