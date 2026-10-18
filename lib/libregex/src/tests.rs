use crate::*;

const B: CompileFlags = CompileFlags::BASIC;
const E: CompileFlags = CompileFlags::EXTENDED;
const N: ExecFlags = ExecFlags::NONE;

fn re(p: &str, f: CompileFlags) -> Regex {
    Regex::new(p.as_bytes(), f).unwrap_or_else(|e| panic!("{p:?}: {e}"))
}

fn err(p: &str, f: CompileFlags) -> ErrorKind {
    match Regex::new(p.as_bytes(), f) {
        Ok(_) => panic!("{p:?} compiled"),
        Err(e) => e.kind,
    }
}

/// Captures as "(s,e)(s,e)(?,?)", the AT&T test notation.
fn caps(p: &str, f: CompileFlags, t: &str) -> String {
    match re(p, f).captures(t.as_bytes(), N) {
        None => "NOMATCH".into(),
        Some(v) => v
            .iter()
            .map(|c| match c {
                Some((s, e)) => format!("({s},{e})"),
                None => "(?,?)".into(),
            })
            .collect(),
    }
}

#[test]
fn literals_and_dot() {
    assert_eq!(caps("abc", B, "xxabcxx"), "(2,5)");
    assert_eq!(caps("a.c", B, "abc"), "(0,3)");
    assert_eq!(caps("a.c", B, "ac"), "NOMATCH");
    assert_eq!(caps("", B, "abc"), "(0,0)");
    assert_eq!(caps("", E, ""), "(0,0)");
    assert!(re("a\\.c", B).find(b"abc", N).is_none());
    assert_eq!(re("a\\.c", B).find(b"xa.c", N), Some((1, 4)));
}

#[test]
fn leftmost_longest() {
    assert_eq!(caps("a*", B, "baaa"), "(0,0)");
    assert_eq!(caps("a+", E, "baaa"), "(1,4)");
    assert_eq!(caps("abcd|c", E, "abcd"), "(0,4)");
    assert_eq!(caps("a|ab|abc", E, "abcd"), "(0,3)");
    assert_eq!(caps("(a|ab)(c|bcd)", E, "abcd"), "(0,4)(0,1)(1,4)");
    assert_eq!(caps("x*y*z", E, "aaxxyyz"), "(2,7)");
}

#[test]
fn posix_subexpressions() {
    assert_eq!(caps("(a|ab)(c|bcd)(d*)", E, "abcd"), "(0,4)(0,2)(2,3)(3,4)");
    assert_eq!(caps("(a*)(b|abc)(c*)", E, "abc"), "(0,3)(0,1)(1,2)(2,3)");
    assert_eq!(caps("(a|ab|c|bcd)*(d*)", E, "abcd"), "(0,4)(1,4)(4,4)");
    assert_eq!(caps("(a*)*", E, "b"), "(0,0)(0,0)");
    assert_eq!(caps("(a*)*", E, "aa"), "(0,2)(0,2)");
    assert_eq!(caps("(a*)+", E, "b"), "(0,0)(0,0)");
    assert_eq!(caps("(a)*", E, "b"), "(0,0)(?,?)");
    assert_eq!(caps("(a(b)?)+", E, "aba"), "(0,3)(2,3)(?,?)");
    assert_eq!(caps("(a(b)?)+", E, "aab"), "(0,3)(1,3)(2,3)");
    assert_eq!(caps("((a)|b)+", E, "ab"), "(0,2)(1,2)(?,?)");
    assert_eq!(caps("((a)|(a))", E, "a"), "(0,1)(0,1)(0,1)(?,?)");
    assert_eq!(caps("(a*){2}", E, "a"), "(0,1)(1,1)");
    assert_eq!(caps("(.)*", E, "abc"), "(0,3)(2,3)");
    assert_eq!(caps("a*(a*)", E, "aaa"), "(0,3)(3,3)");
    assert_eq!(caps("(a*)a*", E, "aaa"), "(0,3)(0,3)");
    assert_eq!(caps("()", E, "x"), "(0,0)(0,0)");
    assert_eq!(caps("(a)|b", E, "b"), "(0,1)(?,?)");
}

#[test]
fn brackets() {
    assert_eq!(caps("[abc]+", E, "xxcabx"), "(2,5)");
    assert_eq!(caps("[^abc]+", E, "abxyc"), "(2,4)");
    assert_eq!(caps("[]a]+", E, "x]a]"), "(1,4)");
    assert_eq!(caps("[^]a]+", E, "]a]xy"), "(3,5)");
    assert_eq!(caps("[a-]+", E, "x-a-"), "(1,4)");
    assert_eq!(caps("[[:digit:]]+", E, "ab123c"), "(2,5)");
    assert_eq!(caps("[[:alpha:][:digit:]]+", E, "-a1b2-"), "(1,5)");
    assert_eq!(caps("[[.-.]]", E, "a-b"), "(1,2)");
    assert_eq!(caps("[[=a=]b]+", E, "xab"), "(1,3)");
    assert_eq!(caps("[[.a.]-c]+", E, "xabc"), "(1,4)");
    assert_eq!(caps("[\\]+", E, "a\\\\"), "(1,3)");
    assert_eq!(caps("[--/]+", E, "a-./"), "(1,4)");
    assert_eq!(err("[a", E), ErrorKind::Brack);
    assert_eq!(err("[[:foo:]]", E), ErrorKind::Ctype);
    assert_eq!(err("[z-a]", E), ErrorKind::Range);
    assert_eq!(err("[[.ab.]]", E), ErrorKind::Collate);
    assert_eq!(err("[[=a=]-z]", E), ErrorKind::Range);
    assert_eq!(err("[a-c-e]", E), ErrorKind::Range);
    assert_eq!(err("[[:alpha:", E), ErrorKind::Brack);
}

#[test]
fn bre_syntax() {
    assert_eq!(caps("\\(a\\)\\(b*\\)", B, "abb"), "(0,3)(0,1)(1,3)");
    assert_eq!(caps("a\\{2,3\\}", B, "aaaa"), "(0,3)");
    assert_eq!(caps("*a", B, "x*a"), "(1,3)");
    assert_eq!(caps("^*a", B, "*a"), "(0,2)");
    assert_eq!(caps("\\(*a\\)", B, "*a"), "(0,2)(0,2)");
    assert_eq!(caps("a^b", B, "a^b"), "(0,3)");
    assert_eq!(caps("a$b", B, "a$b"), "(0,3)");
    assert_eq!(caps("\\(^a\\)", B, "a"), "(0,1)(0,1)");
    assert_eq!(caps("\\(a$\\)", B, "a"), "(0,1)(0,1)");
    assert_eq!(caps("a|b", B, "a|b"), "(0,3)");
    assert_eq!(caps("a+?", B, "a+?"), "(0,3)");
    assert_eq!(caps("(a)", B, "(a)"), "(0,3)");
    assert_eq!(caps("a**", B, "aa"), "(0,2)");
    assert_eq!(err("\\(a", B), ErrorKind::Paren);
    assert_eq!(err("a\\)", B), ErrorKind::Paren);
    assert_eq!(err("a\\{1", B), ErrorKind::Brace);
    assert_eq!(err("a\\{1,x\\}", B), ErrorKind::BadBr);
    assert_eq!(err("a\\{3,1\\}", B), ErrorKind::BadBr);
    assert_eq!(err("a\\{256\\}", B), ErrorKind::BadBr);
    assert_eq!(err("\\{1\\}", B), ErrorKind::BadRpt);
    assert_eq!(err("a\\", B), ErrorKind::Escape);
    assert_eq!(err("\\(a\\)\\2", B), ErrorKind::Subreg);
    assert_eq!(err("\\(a\\1\\)", B), ErrorKind::Subreg);
}

#[test]
fn ere_syntax() {
    assert_eq!(caps("a{2}", E, "aaa"), "(0,2)");
    assert_eq!(caps("a{2,}", E, "aaaa"), "(0,4)");
    assert_eq!(caps("a{0}b", E, "ab"), "(1,2)");
    assert_eq!(caps("a)", E, "a)"), "(0,2)");
    assert_eq!(caps("(|a)+", E, "aa"), "(0,2)(1,2)");
    assert_eq!(caps("a?b", E, "b"), "(0,1)");
    assert_eq!(err("*a", E), ErrorKind::BadRpt);
    assert_eq!(err("a|*b", E), ErrorKind::BadRpt);
    assert_eq!(err("(+a)", E), ErrorKind::BadRpt);
    assert_eq!(err("^*", E), ErrorKind::BadRpt);
    assert_eq!(err("(a", E), ErrorKind::Paren);
    assert_eq!(err("a{1", E), ErrorKind::Brace);
    assert_eq!(err("a{,2}", E), ErrorKind::BadBr);
    assert_eq!(err("a{2,1}", E), ErrorKind::BadBr);
}

#[test]
fn anchors_and_newline() {
    assert_eq!(caps("^a", E, "ba"), "NOMATCH");
    assert_eq!(caps("a$", E, "ab"), "NOMATCH");
    assert_eq!(caps("^$", E, ""), "(0,0)");
    assert_eq!(caps("^b", E, "a\nb"), "NOMATCH");
    let nl = E | CompileFlags::NEWLINE;
    assert_eq!(caps("^b", nl, "a\nb"), "(2,3)");
    assert_eq!(caps("a$", nl, "a\nb"), "(0,1)");
    assert_eq!(caps("a.b", nl, "a\nb"), "NOMATCH");
    assert_eq!(caps("a[^x]b", nl, "a\nb"), "NOMATCH");
    assert_eq!(caps("a.b", E, "a\nb"), "(0,3)");
    assert_eq!(caps("a[^x]b", E, "a\nb"), "(0,3)");
    assert_eq!(caps("a[\n]b", nl, "a\nb"), "(0,3)");
    let r = re("^a", E);
    assert!(!r.is_match(b"a", ExecFlags::NOTBOL));
    assert!(re("^a", nl).is_match(b"x\na", ExecFlags::NOTBOL));
    assert!(!re("a$", E).is_match(b"a", ExecFlags::NOTEOL));
    assert!(re("a$", nl).is_match(b"a\nx", ExecFlags::NOTEOL));
    assert_eq!(caps("(^|x)a", E, "xa"), "(0,2)(0,1)");
    assert_eq!(caps("a(^b)?", E, "ab"), "(0,1)(?,?)");
}

#[test]
fn icase() {
    let i = E | CompileFlags::ICASE;
    assert_eq!(caps("abc", i, "xABC"), "(1,4)");
    assert_eq!(caps("[a-c]+", i, "xAbC"), "(1,4)");
    assert_eq!(caps("[^a]", i, "Ab"), "(1,2)");
    assert_eq!(caps("[[:upper:]]+", i, "abC"), "(0,3)");
    assert_eq!(caps("(a)\\1", i, "aA"), "(0,2)(0,1)");
}

#[test]
fn backrefs() {
    assert_eq!(caps("\\(a*\\)b\\1", B, "aabaa"), "(0,5)(0,2)");
    assert_eq!(caps("\\(a*\\)b\\1", B, "aaba"), "(1,4)(1,2)");
    assert_eq!(caps("\\(.\\)\\1", B, "abccd"), "(2,4)(2,3)");
    assert_eq!(caps("(a|b)*\\1", E, "abb"), "(0,3)(1,2)");
    assert_eq!(caps("\\(a\\)*\\1", B, "b"), "NOMATCH");
    assert_eq!(caps("(.+)\\1", E, "abcabcx"), "(0,6)(0,3)");
    assert_eq!(caps("^(.+)\\1$", E, "abab"), "(0,4)(0,2)");
    assert_eq!(caps("^(.+)\\1$", E, "abcab"), "NOMATCH");
    assert_eq!(caps("(a)(b)\\2\\1", E, "xabba"), "(1,5)(1,2)(2,3)");
    assert_eq!(caps("\\(^a\\)\\1", B, "aa"), "(0,2)(0,1)");
    // Group 2 is cleared by the iteration that matched `b` (XBD 9.1), so `\2` is unset.
    assert_eq!(caps("((a)|b)*\\2", E, "aba"), "NOMATCH");
    assert!(re("(a*)*\\1", E).is_match(b"aaaa", N));
}

#[test]
fn startend_and_flags() {
    let r = re("^b", E);
    assert_eq!(r.try_find_at(b"abc", 1..3, N).unwrap(), Some((1, 2)));
    assert_eq!(r.try_find_at(b"abc", 1..3, ExecFlags::NOTBOL).unwrap(), None);
    let r = re("c$", E);
    assert_eq!(r.try_find_at(b"abcd", 0..3, N).unwrap(), Some((2, 3)));
    let r = re("(a)(b)", E | CompileFlags::NOSUB);
    assert_eq!(r.nsub(), 2);
    assert_eq!(r.captures(b"ab", N), Some(Vec::new()));
    assert_eq!(r.find(b"xab", N), Some((1, 3)));
}

#[test]
fn bytes_pass_through() {
    let r = re("é+", E);
    // `+` repeats the last byte of the two-byte sequence.
    assert_eq!(r.find(b"a\xc3\xa9\xa9", N), Some((1, 4)));
    assert_eq!(re("a.b", E).find(b"a\0b", N), Some((0, 3)));
    assert_eq!(re("[^a]", E).find(b"a\xff", N), Some((1, 2)));
}

#[test]
fn errors_text() {
    assert_eq!(regerror(ErrorKind::Brack), "brackets ([ ]) not balanced");
    assert_eq!(ErrorKind::BadRpt.code(), 13);
    assert_eq!(ErrorKind::NoMatch.code(), 1);
    assert_eq!(err("a{1000}", E), ErrorKind::BadBr);
}

#[test]
fn no_exponential_blowup() {
    let t = vec![b'a'; 30];
    let r = re("(a*)*(a*)*(a*)*(a*)*b", E);
    assert!(!r.is_match(&t, N));
    assert_eq!(r.captures(&t, N), None);
    let r = re("(a|aa)*(a|aa)*c", E);
    assert!(r.find(&[b'a'; 5000], N).is_none());
    let r = re("((a*)*)*$", E);
    assert_eq!(r.captures(&[b'a'; 2000], N).unwrap()[0], Some((0, 2000)));
}

#[test]
fn long_texts() {
    let mut t = vec![b'x'; 1 << 20];
    t.extend_from_slice(b"hello");
    assert_eq!(re("hel+o", E).find(&t, N), Some((1 << 20, (1 << 20) + 5)));
    let t = vec![b'a'; 200_000];
    assert_eq!(re("(a)*", E).captures(&t, N).unwrap()[1], Some((199_999, 200_000)));
    assert_eq!(re("(a|b)*", E).captures(&t, N).unwrap()[1], Some((199_999, 200_000)));
    assert_eq!(re("(.*)", E).captures(&t, N).unwrap()[1], Some((0, 200_000)));
}

#[test]
fn backref_bound() {
    // Exponential under backtracking; must end with REG_ESPACE or an answer, not hang.
    let r = re("((a|aa)*)*\\1z", E);
    let mut t = vec![b'a'; 40];
    t.push(b'z');
    let t0 = std::time::Instant::now();
    let res = r.try_is_match_at(&t, 0..t.len(), N);
    eprintln!("backref_bound: {res:?} in {:?}", t0.elapsed());
    match res {
        Ok(m) => assert!(m),
        Err(e) => assert_eq!(e.kind, ErrorKind::Space),
    }
}

#[test]
fn big_counts() {
    assert!(re("(a{255}){10}", E).is_match(&[b'a'; 2550], N));
    assert!(!re("(a{255}){10}", E).is_match(&[b'a'; 2549], N));
    assert_eq!(err("((a{255}){255}){255}", E), ErrorKind::Space);
}

fn rnd(r: &mut u64, n: u64) -> u64 {
    *r ^= *r << 13;
    *r ^= *r >> 7;
    *r ^= *r << 17;
    *r % n
}

/// Random EREs (no back-references) over {a, b}.
fn random_ere(r: &mut u64, depth: u32) -> String {
    let nalt = if depth < 3 && rnd(r, 4) == 0 { 2 } else { 1 };
    let mut alts = Vec::new();
    for _ in 0..nalt {
        let mut s = String::new();
        for _ in 0..1 + rnd(r, 3) {
            let anchor = match rnd(r, if depth < 3 { 11 } else { 6 }) {
                0 | 1 => {
                    s.push('a');
                    false
                }
                2 => {
                    s.push('b');
                    false
                }
                3 => {
                    s.push('.');
                    false
                }
                4 => {
                    s.push_str("[ab]");
                    false
                }
                5 => {
                    let k = rnd(r, 3) as usize;
                    s.push_str(["^", "$", "()"][k]);
                    k < 2
                }
                _ => {
                    let inner = random_ere(r, depth + 1);
                    s.push_str(&format!("({inner})"));
                    false
                }
            };
            if !anchor {
                match rnd(r, 10) {
                    0 | 1 => s.push('*'),
                    2 => s.push('+'),
                    3 => s.push('?'),
                    4 => {
                        let k = rnd(r, 5) as usize;
                        s.push_str(["{2}", "{0,1}", "{1,2}", "{0,2}", "{2,}"][k]);
                    }
                    _ => {}
                }
            }
        }
        alts.push(s);
    }
    alts.join("|")
}

/// The backtracking engine, made to enumerate every choice, must agree with the automaton
/// path (Pike VM extent plus `assign`) on patterns without back-references: two independent
/// implementations of the same XBD 9.1 rules.
#[test]
fn engines_agree() {
    let mut r = 0x2545_f491_4f6c_dd1du64;
    let mut n = 0;
    for round in 0..10000 {
        let p = random_ere(&mut r, 0);
        let nl = round % 3 == 0;
        let cf = if nl { E | CompileFlags::NEWLINE } else { E };
        let Ok(rx) = Regex::new(p.as_bytes(), cf) else { continue };
        for _ in 0..5 {
            let len = rnd(&mut r, 10);
            let t: Vec<u8> = (0..len)
                .map(|_| match rnd(&mut r, 8) {
                    0 | 1 => b'b',
                    2 if nl => b'\n',
                    _ => b'a',
                })
                .collect();
            for f in [N, ExecFlags::NOTBOL, ExecFlags::NOTEOL] {
                let (d, p) = rx.extents(&t, f);
                assert_eq!(d, p, "extent of {p:?} on {:?}", String::from_utf8_lossy(&t));
            }
            let fast = rx.captures(&t, N);
            let tx = crate::sim::Text { t: &t, notbol: false, noteol: false, nl };
            let mut ex = crate::exec::Exec::new(&rx.ast, &rx.nfa, tx, false);
            ex.no_indep = true;
            let slow = match ex.search(0) {
                Ok(Some(_)) => Some(ex.caps.clone()),
                Ok(None) => None,
                Err(e) => panic!("{p:?} {t:?}: {e}"),
            };
            assert_eq!(fast, slow, "{p:?} on {:?}", String::from_utf8_lossy(&t));
            n += 1;
        }
    }
    eprintln!("engines_agree: {n} cases");
}

/// Deep continuation nesting ends in REG_ESPACE, not a stack overflow (test threads have 2 MiB).
#[test]
fn deep_backref_recursion() {
    let r = re("(a)(\\1)*$", E);
    let t = vec![b'a'; 20_000];
    match r.try_find_at(&t, 0..t.len(), N) {
        Ok(m) => assert_eq!(m, Some((0, t.len()))),
        Err(e) => assert_eq!(e.kind, ErrorKind::Space),
    }
    assert_eq!(r.find(&t[..200], N), Some((0, 200)));
}

#[test]
fn nesting_limit() {
    let deep = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
    let r = re(&deep(400), E);
    assert_eq!(r.captures(b"a", N).unwrap()[400], Some((0, 1)));
    assert_eq!(err(&deep(600), E), ErrorKind::Space);
    assert_eq!(err(&format!("a{}", "*".repeat(1000)), E), ErrorKind::Space);
    assert!(re(&format!("a{}", "*".repeat(100)), E).is_match(b"aa", N));
}

#[test]
fn shareable() {
    fn check<T: Send + Sync>() {}
    check::<Regex>();
    let r = std::sync::Arc::new(re("(a|b)+c", E));
    let hs: Vec<_> = (0..4)
        .map(|i| {
            let r = r.clone();
            std::thread::spawn(move || (0..200).filter(|j| r.is_match(format!("{i}{j}abac").as_bytes(), N)).count())
        })
        .collect();
    for h in hs {
        assert_eq!(h.join().unwrap(), 200);
    }
}
