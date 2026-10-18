//! Hostile input: random and mutated streams must never panic or hang, must get the same
//! verdict as zlib (accept with the same output and length, truncated, or rejected), and must
//! decode the same however the input and output are split.

mod common;

use common::{Rng, have_python, run, text};
use flate::{Error, Inflater, Status, deflate, gzip, inflate, zlib};

const LIMIT: usize = 1 << 26;

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Ok { used: usize, len: usize, crc: u32 },
    Truncated,
    Error,
    TooBig,
}

fn ours(data: &[u8]) -> Verdict {
    match inflate::decompress_prefix(data, LIMIT) {
        Ok((out, used)) => Verdict::Ok { used, len: out.len(), crc: flate::crc32::crc32(&out) },
        Err(Error::Truncated) => Verdict::Truncated,
        Err(Error::OutputLimit) => Verdict::TooBig,
        Err(_) => Verdict::Error,
    }
}

/// The same, streamed in random pieces.
fn ours_streamed(data: &[u8], rng: &mut Rng) -> Verdict {
    let mut inf = Inflater::new();
    let mut crc = flate::crc32::Crc32::new();
    let mut len = 0;
    let mut pos = 0;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = (1 + rng.below(300)).min(data.len() - pos);
        let o = 1 + rng.below(4096);
        match inf.inflate(&data[pos..pos + n], &mut buf[..o]) {
            Err(Error::Truncated) => unreachable!(),
            Err(_) => return Verdict::Error,
            Ok(p) => {
                pos += p.consumed;
                crc.update(&buf[..p.produced]);
                len += p.produced;
                if len > LIMIT {
                    return Verdict::TooBig;
                }
                match p.status {
                    Status::StreamEnd => return Verdict::Ok { used: pos, len, crc: crc.value() },
                    Status::NeedsInput if pos == data.len() => return Verdict::Truncated,
                    _ => {}
                }
            }
        }
    }
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut d = seed.to_vec();
    match rng.below(7) {
        0 | 1 => {
            for _ in 0..1 + rng.below(4) {
                if !d.is_empty() {
                    let i = rng.below(d.len());
                    d[i] ^= 1 << rng.below(8);
                }
            }
        }
        2 => d.truncate(rng.below(d.len() + 1)),
        3 => {
            if !d.is_empty() {
                let i = rng.below(d.len());
                d[i] = rng.next() as u8;
            }
        }
        4 => {
            let i = rng.below(d.len() + 1);
            d.insert(i, rng.next() as u8);
        }
        5 => {
            if !d.is_empty() {
                d.remove(rng.below(d.len()));
            }
        }
        _ => {
            // Flips concentrated in the first bytes, where the code descriptions are.
            for _ in 0..1 + rng.below(3) {
                let i = rng.below(d.len().clamp(1, 64));
                if i < d.len() {
                    d[i] ^= 1 << rng.below(8);
                }
            }
        }
    }
    d
}

fn cases() -> Vec<Vec<u8>> {
    let mut rng = Rng(0xdead_beef);
    let mut seeds = Vec::new();
    for (i, n) in [100, 2000, 20_000].into_iter().enumerate() {
        let t = text(&mut rng, n);
        for level in [1, 6, 9] {
            seeds.push(deflate::compress(&t, level));
        }
        let mut m = rng.bytes(n / 4);
        m.extend(b"xyz".repeat(n / 3));
        seeds.push(deflate::compress(&m, 4 + i as u32));
    }
    seeds.push(deflate::compress(&rng.bytes(3000), 0));
    let mut out = Vec::new();
    // FLATE_FUZZ_CASES scales the run for a longer soak.
    let n: usize = std::env::var("FLATE_FUZZ_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(35_000);
    for _ in 0..n * 6 / 7 {
        let s = &seeds[rng.below(seeds.len())];
        out.push(mutate(&mut rng, s));
    }
    for _ in 0..n / 7 {
        // Random bytes, mostly made to start a dynamic block.
        let n = rng.below(600);
        let mut d = rng.bytes(n);
        if !d.is_empty() && rng.below(4) != 0 {
            d[0] = (d[0] & !6) | 4;
        }
        out.push(d);
    }
    out
}

#[test]
fn random_and_mutated_streams_match_zlib() {
    let cases = cases();
    let mut rng = Rng(77);
    let mut verdicts = Vec::with_capacity(cases.len());
    let start = std::time::Instant::now();
    for c in &cases {
        let v = ours(c);
        assert_eq!(ours_streamed(c, &mut rng), v, "streamed vs whole: {c:02x?}");
        verdicts.push(v);
    }
    eprintln!("{} cases decoded in {:?}", cases.len(), start.elapsed());
    let tally = |f: fn(&Verdict) -> bool| verdicts.iter().filter(|v| f(v)).count();
    eprintln!(
        "ok {} truncated {} error {}",
        tally(|v| matches!(v, Verdict::Ok { .. })),
        tally(|v| *v == Verdict::Truncated),
        tally(|v| *v == Verdict::Error)
    );
    if !have_python() {
        return;
    }
    let mut input = Vec::new();
    for c in &cases {
        input.extend_from_slice(&(c.len() as u32).to_le_bytes());
        input.extend_from_slice(c);
    }
    let prog = r#"
import sys, zlib, struct
d = sys.stdin.buffer.read()
p = 0
res = []
while p < len(d):
    (n,) = struct.unpack_from('<I', d, p)
    c = d[p + 4:p + 4 + n]
    p += 4 + n
    o = zlib.decompressobj(-15)
    try:
        out = o.decompress(c, 1 << 26)
        if o.eof:
            res.append('ok %d %d %d' % (n - len(o.unused_data), len(out), zlib.crc32(out)))
        elif o.unconsumed_tail:
            res.append('big')
        else:
            res.append('trunc')
    except zlib.error:
        res.append('err')
sys.stdout.write('\n'.join(res) + '\n')
"#;
    let out = run("python3", &["-I", "-c", prog], &input).expect("python3 oracle");
    let out = String::from_utf8(out).unwrap();
    let mut mismatches = 0;
    for ((line, v), c) in out.lines().zip(&verdicts).zip(&cases) {
        let z = match line.split(' ').collect::<Vec<_>>()[..] {
            ["ok", u, l, c] => Verdict::Ok { used: u.parse().unwrap(), len: l.parse().unwrap(), crc: c.parse().unwrap() },
            ["trunc"] => Verdict::Truncated,
            ["err"] => Verdict::Error,
            _ => Verdict::TooBig,
        };
        if z == Verdict::TooBig || *v == Verdict::TooBig {
            continue;
        }
        if z != *v {
            mismatches += 1;
            eprintln!("zlib says {z:?}, we say {v:?}: {:02x?}", &c[..c.len().min(64)]);
        }
    }
    assert_eq!(out.lines().count(), cases.len());
    assert_eq!(mismatches, 0);
}

#[test]
fn wrappers_survive_mutation() {
    let mut rng = Rng(0x5eed);
    let t = text(&mut rng, 5000);
    let g = gzip::compress(&t, 6);
    let z = zlib::compress(&t, 6);
    let mut mg = g.clone();
    mg.extend(gzip::compress(b"second", 1));
    for _ in 0..20_000 {
        let m = mutate(&mut rng, &mg);
        let r = gzip::decompress_with_limit(&m, LIMIT);
        // Any change the checks do not catch must leave the data intact (mutations past the
        // first member's trailer can, for instance, only cost the second member).
        if let Ok(out) = r {
            assert!(out.starts_with(&t) || m.len() != mg.len(), "undetected corruption");
        }
        let m = mutate(&mut rng, &z);
        if let Ok(out) = zlib::decompress_with_limit(&m, LIMIT) {
            assert_eq!(out, t, "undetected zlib corruption");
        }
        // Random garbage at the start.
        let n = rng.below(64);
        let r = rng.bytes(n);
        let _ = gzip::decompress(&r);
        let _ = zlib::decompress(&r);
    }
}
