//! Shared by the integration tests: a deterministic PRNG, test data, and the host tools.
#![allow(dead_code)]

use std::io::Write;
use std::process::{Command, Stdio};

/// xorshift64*: deterministic, so a failure reproduces.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Words-ish text with a skewed vocabulary, like prose or source.
pub fn text(rng: &mut Rng, n: usize) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the", "of", "and", "a", "to", "in", "is", "fn", "let", "mut", "self", "return", "if", "else", "for", "while",
        "match", "struct", "impl", "pub", "use", "crate", "vnode", "process", "kernel", "buffer", "len", "Some", "None",
        "Ok(())", "{", "}", "(", ")", ";", "\n", "    ", "//", "0x1f", "error", "signal", "inode", "block",
    ];
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        // Square the draw to skew towards the first words.
        let r = rng.below(WORDS.len() * WORDS.len());
        let w = WORDS[(r as f64).sqrt() as usize % WORDS.len()];
        out.extend_from_slice(w.as_bytes());
        out.push(b' ');
    }
    out.truncate(n);
    out
}

/// The data sets the round trips run over.
pub fn datasets() -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut far = rng.bytes(40_000);
    // Repeats exactly 32768 bytes back, the longest distance there is.
    let copy = far[..20_000].to_vec();
    far.truncate(32_768);
    far.extend_from_slice(&copy);
    let mut mixed = text(&mut rng, 300_000);
    mixed.extend(rng.bytes(100_000));
    mixed.extend(vec![0u8; 100_000]);
    mixed.extend(text(&mut rng, 300_000));
    vec![
        ("empty", vec![]),
        ("one byte", vec![b'x']),
        ("two bytes", b"ab".to_vec()),
        ("zeros 1M", vec![0; 1 << 20]),
        ("random 300K", rng.bytes(300_000)),
        ("text 200K", text(&mut rng, 200_000)),
        ("distance 32768", far),
        ("period 3", b"abc".repeat(70_000)),
        ("mixed 1.6M", mixed),
        ("ramp", (0..200_000u32).map(|i| (i / 7) as u8).collect()),
    ]
}

/// The host tool's output on `input`, or None if it is missing or fails.
pub fn run(cmd: &str, args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    let mut child =
        Command::new(cmd).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut stdin = child.stdin.take()?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out = child.wait_with_output().ok()?;
    writer.join().ok()?;
    out.status.success().then_some(out.stdout)
}

pub fn have(cmd: &str, args: &[&str]) -> bool {
    run(cmd, args, b"").is_some()
}

pub fn have_gzip() -> bool {
    let ok = have("gzip", &["-c"]);
    if !ok {
        eprintln!("gzip not found: skipping");
    }
    ok
}

pub fn have_python() -> bool {
    let ok = have("python3", &["-c", "import zlib"]);
    if !ok {
        eprintln!("python3 with zlib not found: skipping");
    }
    ok
}

/// Runs a python3 snippet that reads stdin as `d` (bytes) and writes `o` (bytes) to stdout.
pub fn python(code: &str, input: &[u8]) -> Option<Vec<u8>> {
    let prog = format!("import sys, zlib, gzip\nd = sys.stdin.buffer.read()\n{code}\nsys.stdout.buffer.write(o)\n");
    run("python3", &["-I", "-c", &prog], input)
}
