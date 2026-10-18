//! Differential tests against the host C library's `regcomp`/`regexec` (glibc, in the C locale).
//! glibc is a reasonable POSIX reference but not a perfect one; the cases where it departs from
//! XBD 9 are listed in `DEVIATIONS` with what POSIX requires, and checked against both.
//!
//! glibc runs in a child process (this binary with `--helper`): on some patterns it loops
//! forever (`((a*|bab{0,1})*|a?)*a` on `baaa`) or recurses until the stack overflows, and a
//! case it can't answer within `TIMEOUT` is reported as such and skipped.

use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use posixre::{CompileFlags, ExecFlags, Regex};

type Caps = Option<Vec<Option<(usize, usize)>>>;

/// glibc's `regex_t` (the libc crate keeps `re_nsub` private).
#[repr(C)]
struct RegexT {
    buffer: *mut libc::c_void,
    allocated: libc::size_t,
    used: libc::size_t,
    syntax: libc::c_ulong,
    fastmap: *mut libc::c_char,
    translate: *mut libc::c_char,
    re_nsub: libc::size_t,
    bits: u8,
}

unsafe extern "C" {
    fn regcomp(re: *mut RegexT, pat: *const libc::c_char, cflags: libc::c_int) -> libc::c_int;
    fn regexec(re: *const RegexT, s: *const libc::c_char, n: libc::size_t, m: *mut libc::regmatch_t, eflags: libc::c_int) -> libc::c_int;
    fn regfree(re: *mut RegexT);
}

/// glibc's answer: Err(()) if it fails to compile.
fn glibc(pat: &[u8], cf: u32, text: &[u8], ef: u32) -> Result<Caps, ()> {
    let p = CString::new(pat).unwrap();
    let t = CString::new(text).unwrap();
    unsafe {
        let mut re: RegexT = std::mem::zeroed();
        if regcomp(&mut re, p.as_ptr(), cf as i32) != 0 {
            return Err(());
        }
        let n = re.re_nsub + 1;
        let mut m = vec![libc::regmatch_t { rm_so: -1, rm_eo: -1 }; n];
        let r = regexec(&re, t.as_ptr(), n, m.as_mut_ptr(), ef as i32);
        regfree(&mut re);
        if r != 0 {
            return Ok(None);
        }
        Ok(Some(m.iter().map(|m| if m.rm_so < 0 { None } else { Some((m.rm_so as usize, m.rm_eo as usize)) }).collect()))
    }
}

fn ours(pat: &[u8], cf: u32, text: &[u8], ef: u32) -> Result<Caps, ()> {
    let re = Regex::new(pat, CompileFlags(cf)).map_err(|_| ())?;
    Ok(re.try_captures_at(text, 0..text.len(), ExecFlags(ef)).expect("REG_ESPACE"))
}

/// Under `REG_NOSUB` only match or no match is comparable (glibc leaves `pmatch` alone).
fn nosub(cf: u32, s: String) -> String {
    if cf & 8 != 0 && s != "NOMATCH" && s != "ERROR" { "MATCH".into() } else { s }
}

fn show(c: &Result<Caps, ()>) -> String {
    match c {
        Err(()) => "ERROR".into(),
        Ok(None) => "NOMATCH".into(),
        Ok(Some(v)) => v
            .iter()
            .map(|c| match c {
                Some((s, e)) => format!("({s},{e})"),
                None => "(?,?)".into(),
            })
            .collect(),
    }
}

fn hex(b: &[u8]) -> String {
    let mut s: String = b.iter().map(|c| format!("{c:02x}")).collect();
    s.push('.'); // never empty
    s
}

fn unhex(s: &str) -> Vec<u8> {
    let s = &s[..s.len() - 1];
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

const TIMEOUT: Duration = Duration::from_secs(2);

/// The child running glibc.
struct Helper {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
}

impl Helper {
    fn spawn() -> Helper {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--helper")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for l in out.lines() {
                let Ok(l) = l else { break };
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Helper { child, stdin, rx }
    }

    /// glibc's answer as `show` prints it, or `None` if it hung or crashed.
    fn ask(&mut self, pat: &[u8], cf: u32, text: &[u8], ef: u32) -> Option<String> {
        let ok = writeln!(self.stdin, "{} {cf} {} {ef}", hex(pat), hex(text)).is_ok() && self.stdin.flush().is_ok();
        match ok.then(|| self.rx.recv_timeout(TIMEOUT)) {
            Some(Ok(r)) => Some(r),
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                *self = Helper::spawn();
                None
            }
        }
    }
}

fn helper_main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for l in stdin.lock().lines() {
        let l = l.unwrap();
        let f: Vec<&str> = l.split(' ').collect();
        let r = glibc(&unhex(f[0]), f[1].parse().unwrap(), &unhex(f[2]), f[3].parse().unwrap());
        writeln!(out, "{}", show(&r)).unwrap();
        out.flush().unwrap();
    }
}

/// `%n` newline, `%t` tab, `%%` percent.
fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 1 < b.len() {
            out.push(match b[i + 1] {
                b'n' => b'\n',
                b't' => b'\t',
                c => c,
            });
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Flags field: `E` extended (else basic), `i` icase, `n` newline, `s` nosub, `^` notbol, `$`
/// noteol.
fn flags(f: &str) -> (u32, u32) {
    let (mut cf, mut ef) = (0, 0);
    for c in f.chars() {
        match c {
            'B' => {}
            'E' => cf |= 1,
            'i' => cf |= 2,
            'n' => cf |= 4,
            's' => cf |= 8,
            '^' => ef |= 1,
            '$' => ef |= 2,
            _ => panic!("flag {c}"),
        }
    }
    (cf, ef)
}

struct Case {
    line: usize,
    f: String,
    pat: Vec<u8>,
    text: Vec<u8>,
}

fn corpus() -> Vec<Case> {
    let src = include_str!("corpus.txt");
    let mut v = Vec::new();
    for (n, l) in src.lines().enumerate() {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut f = l.split('\t');
        let (fl, p, t) = (f.next().unwrap(), f.next().unwrap_or_else(|| panic!("line {}", n + 1)), f.next().unwrap_or(""));
        v.push(Case { line: n + 1, f: fl.into(), pat: unescape(p), text: unescape(t) });
    }
    v
}

/// A small deterministic PRNG (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A random ERE over {a, b}; `groups` counts the groups opened so far, `closed` those closed
/// (for back-references).
fn gen_re(r: &mut Rng, depth: u32, groups: &mut u32, closed: &mut Vec<u32>, backrefs: bool) -> String {
    let nalt = if depth < 3 && r.below(4) == 0 { 2 } else { 1 };
    let mut alts = Vec::new();
    for _ in 0..nalt {
        if depth == 0 {
            // glibc refuses a back-reference to a group in another alternative (`(a)|\1`).
            closed.clear();
        }
        let mut s = String::new();
        for _ in 0..1 + r.below(3) {
            let atom = match r.below(if depth < 3 { 10 } else { 6 }) {
                0 | 1 => "a".to_string(),
                2 => "b".to_string(),
                3 => ".".to_string(),
                4 => ["[ab]", "[^a]", "[b]"][r.below(3) as usize].to_string(),
                // Only unquantified, outside groups: glibc recurses without bound (or loops) on
                // back-references inside repeated groups, e.g. `([^a]*((a*)(\3?\3){0,2})*)+`.
                5 if backrefs && depth == 0 && closed.iter().any(|&g| g <= 9) => {
                    closed.retain(|&g| g <= 9);
                    s.push_str(&format!("\\{}", closed[r.below(closed.len() as u64) as usize]));
                    continue;
                }
                5 => "a".to_string(),
                _ => {
                    *groups += 1;
                    let g = *groups;
                    let inner = gen_re(r, depth + 1, groups, closed, backrefs);
                    closed.push(g);
                    format!("({inner})")
                }
            };
            s.push_str(&atom);
            match r.below(10) {
                0 | 1 => s.push('*'),
                2 => s.push('+'),
                3 => s.push('?'),
                4 => s.push_str(["{2}", "{0,1}", "{1,2}", "{0,2}"][r.below(4) as usize]),
                _ => {}
            }
        }
        alts.push(s);
    }
    alts.join("|")
}

fn gen_text(r: &mut Rng) -> Vec<u8> {
    (0..r.below(9)).map(|_| if r.below(3) == 0 { b'b' } else { b'a' }).collect()
}

/// Where glibc departs from POSIX: flags, pattern, text, the XBD 9 answer (ours). Each was
/// checked by hand against XBD 9.1 ("each subpattern, from left to right, shall match the
/// longest possible string") and the `regexec` rules for reporting subexpressions.
const DEVIATIONS: &[(&str, &str, &str, &str)] = &[
    // Accepted by the BSDs; POSIX leaves stacked BRE duplication symbols undefined, glibc
    // rejects them.
    ("B", "a**", "aaa", "(0,3)"),
    ("B", "a**", "", "(0,0)"),
    // A back-reference to a group in another alternative: glibc refuses to compile it; POSIX
    // only says it can't match (the group never participates).
    ("E", "(a)|\\1", "a", "(0,1)(0,1)"),
    ("E", "(a)|b\\1", "b", "NOMATCH"),
    // The first subpattern must be the longest: glibc shortens it to lengthen a later one.
    ("E", "(a|ab)(c|bcd)(d*)", "abcd", "(0,4)(0,2)(2,3)(3,4)"),
    ("E", "(a|ab)(bcd|c)(d*)", "abcd", "(0,4)(0,2)(2,3)(3,4)"),
    ("E", "(a|ab)(bc|c)", "abc", "(0,3)(0,2)(2,3)"),
    ("E", "(foo|foobar)(bar)?", "foobar", "(0,6)(0,6)(?,?)"),
    ("E", "(aa{1,2})*.*", "aaaa", "(0,4)(2,4)"),
    ("E", "(aa{1,2})*.*", "aaaaaaab", "(0,8)(5,7)"),
    ("E", "((b?)+([ab]{0,2}|a+).*)*.", "abab", "(0,4)(0,3)(0,0)(0,2)"),
    ("E", "(.|a*[b]*(a{1,2}))(a(a?))?b*", "baabaaa", "(0,4)(0,3)(1,3)(?,?)(?,?)"),
    ("E", "(a*|ab*(b*|.([^a])))+[b]?", "aaaaaab", "(0,7)(5,7)(7,7)(?,?)"),
    ("E", "(.{0,1}|b*([b]{0,2}[b]{1,2})a{1,2})+", "baba", "(0,4)(2,4)(2,3)"),
    // A group in a repetition reports its last iteration, and a group inside it only within
    // that iteration: glibc keeps values from earlier iterations, or reports the wrong one.
    ("E", "(.(b)?)*", "baabb", "(0,5)(4,5)(?,?)"),
    ("E", "(.(b)?)*", "bbaa", "(0,4)(3,4)(?,?)"),
    ("E", ".(a((b*)*a)*)b?", "babaabb", "(0,6)(1,5)(4,5)(4,4)"),
    ("E", "(((a*){1,2})b{0,2})*a", "aaaaaba", "(0,7)(0,6)(0,5)(0,5)"),
    ("E", "((a|(a?)([^a]*b))+(b+|.?))", "aabba", "(0,5)(0,5)(4,5)(?,?)(?,?)(5,5)"),
    ("E", "((([b]+.)|(a*a?a?)(.))b?)+", "bababa", "(0,6)(5,6)(5,6)(?,?)(5,5)(5,6)"),
    ("E", "(((.)(a*)|a{2}ab)?){2}aa{0,2}", "aabbb", "(0,2)(1,1)(?,?)(?,?)(?,?)"),
    ("E", "a*((b{1,2}(a*.?)|b.*[ab]){0,1}(b)){0,2}", "bbbb", "(0,4)(0,4)(0,3)(2,3)(3,4)"),
    // Not POSIX-mandated, a choice POSIX leaves open (see the crate docs): a repetition takes
    // no empty iteration after a non-empty one; glibc adds one when its count allows.
    ("E", "a+(b*){0,2}", "abbaa", "(0,3)(1,3)"),
    // Back-references: glibc misses longer (or any) matches,
    ("E", "(a*)+\\1", "abbbaab", "(0,1)(1,1)"),
    ("E", "(.|(a+)*){2}\\1", "babb", "(0,1)(1,1)(?,?)"),
    ("E", "a*(b*a*([^a].{0,2}b*)){1,2}\\2", "babbbaaa", "(0,5)(3,4)(3,4)"),
    ("E", "((a(a{0,2}a))a[^a]|ba)(aa([b]{0,2}a?)+)*\\4", "aabaaaaa", "(2,8)(2,4)(?,?)(?,?)(4,6)(6,6)"),
    ("E", "(a*(b{0,1}(a{2}){0,1}){2}.)*\\2|a.", "aaab", "(0,4)(0,4)(3,3)(?,?)"),
    ("E", "a(a|b*)*\\1", "aab", "(0,3)(3,3)"),
    // and matches a back-reference against a group's earlier iteration, which POSIX's
    // reporting rule has already cleared (group 3 took no part in the last iteration).
    ("E", "((a*a(a*aa)|.))*\\3", "aaabaa", "NOMATCH"),
    ("E", "((a)|b)*\\2", "aba", "NOMATCH"),
];

fn printable(b: &[u8]) -> String {
    format!("{:?}", String::from_utf8_lossy(b))
}

/// Every corpus case must agree with glibc, except the listed deviations.
fn corpus_cases(g: &mut Helper) -> Vec<String> {
    let mut bad = Vec::new();
    let (mut n, mut hung) = (0, 0);
    for c in corpus() {
        let (cf, ef) = flags(&c.f);
        if DEVIATIONS.iter().any(|d| d.0 == c.f && unescape(d.1) == c.pat && unescape(d.2) == c.text) {
            continue;
        }
        n += 1;
        let o = nosub(cf, show(&ours(&c.pat, cf, &c.text, ef)));
        let Some(gl) = g.ask(&c.pat, cf, &c.text, ef).map(|s| nosub(cf, s)) else {
            hung += 1;
            eprintln!("corpus line {}: glibc hung or crashed (ours {o})", c.line);
            continue;
        };
        if gl != o {
            bad.push(format!("corpus line {}: {} {} {}: glibc {gl} ours {o}", c.line, c.f, printable(&c.pat), printable(&c.text)));
        }
    }
    eprintln!("corpus: {n} cases compared, {hung} glibc could not answer, {} mismatches", bad.len());
    bad
}

/// Each deviation: ours gives the POSIX answer, glibc doesn't.
fn deviations(g: &mut Helper) -> Vec<String> {
    let mut bad = Vec::new();
    for &(f, p, t, posix) in DEVIATIONS {
        let (cf, ef) = flags(f);
        let (p, t) = (unescape(p), unescape(t));
        let o = show(&ours(&p, cf, &t, ef));
        let gl = g.ask(&p, cf, &t, ef).unwrap_or_else(|| "HANG".into());
        if o != posix {
            bad.push(format!("deviation {f} {} {}: ours {o}, POSIX {posix}", printable(&p), printable(&t)));
        }
        if gl == posix {
            bad.push(format!("deviation {f} {} {}: glibc now agrees ({gl})", printable(&p), printable(&t)));
        }
    }
    eprintln!("deviations: {} checked, {} wrong", DEVIATIONS.len(), bad.len());
    bad
}

/// Random EREs without back-references: compile success, match and the overall match must
/// equal glibc's. Submatch differences are counted (and printed with `RANDOM_SHOW=1`) for
/// review, not failed: glibc's submatch rules are not POSIX's in many nested cases.
fn random_extents(g: &mut Helper) -> Vec<String> {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let show_all = std::env::var("RANDOM_SHOW").is_ok();
    let (mut n, mut subdiff, mut hung) = (0, 0, 0);
    let mut bad = Vec::new();
    for _ in 0..4000 {
        let (mut gr, mut c) = (0, Vec::new());
        let p = gen_re(&mut r, 0, &mut gr, &mut c, false);
        for _ in 0..4 {
            let t = gen_text(&mut r);
            n += 1;
            let o = show(&ours(p.as_bytes(), 1, &t, 0));
            let Some(gl) = g.ask(p.as_bytes(), 1, &t, 0) else {
                hung += 1;
                if show_all {
                    eprintln!("HANG {p:?} {}: ours {o}", printable(&t));
                }
                continue;
            };
            // Up to the first group: the overall match.
            let whole = |s: &str| s.split_inclusive(')').next().unwrap_or("").to_string();
            if whole(&gl) != whole(&o) {
                bad.push(format!("random {p:?} {}: glibc {gl} ours {o}", printable(&t)));
            } else if gl != o {
                subdiff += 1;
                if show_all {
                    eprintln!("SUB {p:?} {}: glibc {gl} ours {o}", printable(&t));
                }
            }
        }
    }
    eprintln!("random: {n} cases, {hung} glibc could not answer, {subdiff} submatch differences, {} mismatches", bad.len());
    bad
}

/// Random EREs with back-references: compile success must agree. Other differences are only
/// counted (and printed with `RANDOM_SHOW=1`): glibc's back-reference matcher is wrong often
/// enough (missed and shortened matches, stale groups; see `DEVIATIONS`) that it can't serve
/// as an oracle here. Every difference reviewed so far was glibc's error.
fn random_backrefs(g: &mut Helper) -> Vec<String> {
    let mut r = Rng(0x0123_4567_89ab_cdef);
    let show_all = std::env::var("RANDOM_SHOW").is_ok();
    let (mut n, mut subdiff, mut hung) = (0, 0, 0);
    let mut bad = Vec::new();
    for _ in 0..2000 {
        let (mut gr, mut c) = (0, Vec::new());
        let p = gen_re(&mut r, 0, &mut gr, &mut c, true);
        for _ in 0..4 {
            let t = gen_text(&mut r);
            n += 1;
            let o = show(&ours(p.as_bytes(), 1, &t, 0));
            let Some(gl) = g.ask(p.as_bytes(), 1, &t, 0) else {
                hung += 1;
                continue;
            };
            if (gl == "ERROR") != (o == "ERROR") {
                bad.push(format!("random backref {p:?} {}: glibc {gl} ours {o}", printable(&t)));
            } else if gl != o {
                subdiff += 1;
                if show_all {
                    eprintln!("BR {p:?} {}: glibc {gl} ours {o}", printable(&t));
                }
            }
        }
    }
    eprintln!("random back-references: {n} cases, {hung} glibc could not answer, {subdiff} differences, {} mismatches", bad.len());
    bad
}

fn main() {
    if std::env::args().any(|a| a == "--helper") {
        return helper_main();
    }
    // `cargo test` passes libtest's flags; a name filter selects parts.
    let filter: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
    let want = |name: &str| filter.is_empty() || filter.iter().any(|f| name.contains(f.as_str()));
    let mut g = Helper::spawn();
    let mut bad = Vec::new();
    if want("corpus") {
        bad.extend(corpus_cases(&mut g));
    }
    if want("deviations") {
        bad.extend(deviations(&mut g));
    }
    if want("random_extents") {
        bad.extend(random_extents(&mut g));
    }
    if want("random_backrefs") {
        bad.extend(random_backrefs(&mut g));
    }
    let _ = g.child.kill();
    for b in &bad {
        eprintln!("FAIL {b}");
    }
    if !bad.is_empty() {
        eprintln!("{} failures", bad.len());
        std::process::exit(1);
    }
    eprintln!("glibc differential: ok");
}
