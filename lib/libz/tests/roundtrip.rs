//! Round trips at every level over varied data, whole-buffer and streamed in odd pieces.

mod common;

use common::{Rng, datasets};
use flate::{Deflater, Flush, Inflater, Status, deflate, gzip, inflate, zlib};

/// Inflates `data` feeding at most `ic` input bytes and `oc` output bytes per call.
fn inflate_chunked(data: &[u8], rng: &mut Rng, ic: usize, oc: usize) -> Vec<u8> {
    let mut inf = Inflater::new();
    let mut out = Vec::new();
    let mut pos = 0;
    let mut buf = vec![0u8; oc];
    let mut calls = 0u64;
    loop {
        calls += 1;
        assert!(calls < 50_000_000, "no progress");
        let n = (1 + rng.below(ic)).min(data.len() - pos);
        let o = 1 + rng.below(oc);
        let p = inf.inflate(&data[pos..pos + n], &mut buf[..o]).unwrap();
        pos += p.consumed;
        out.extend_from_slice(&buf[..p.produced]);
        match p.status {
            Status::StreamEnd => {
                assert_eq!(pos, data.len(), "consumed exactly the stream");
                return out;
            }
            Status::NeedsInput => assert!(pos < data.len(), "truncated"),
            Status::NeedsOutput => {}
        }
    }
}

#[test]
fn every_level_every_dataset() {
    for (name, data) in datasets() {
        for level in 0..=9 {
            let c = deflate::compress(&data, level);
            assert_eq!(inflate::decompress(&c).unwrap(), data, "{name} level {level}");
            let g = gzip::compress(&data, level);
            assert_eq!(gzip::decompress(&g).unwrap(), data, "{name} gzip level {level}");
            let z = zlib::compress(&data, level);
            assert_eq!(zlib::decompress(&z).unwrap(), data, "{name} zlib level {level}");
        }
    }
}

#[test]
fn compression_actually_compresses() {
    let zeros = vec![0u8; 1 << 20];
    for level in 1..=9 {
        assert!(deflate::compress(&zeros, level).len() < 5000, "level {level}");
    }
    // Incompressible data costs no more than stored blocks.
    let mut rng = Rng(7);
    let r = rng.bytes(500_000);
    for level in 0..=9 {
        let c = deflate::compress(&r, level);
        assert!(c.len() <= r.len() + 5 * (r.len() / 16000 + 2), "level {level}: {}", c.len());
    }
}

#[test]
fn streaming_both_ways_in_odd_pieces() {
    let mut rng = Rng(42);
    for (name, data) in datasets() {
        for level in [0, 1, 3, 6, 9] {
            let mut d = Deflater::new(level);
            let mut c = Vec::new();
            let mut pos = 0;
            while pos < data.len() {
                let n = (1 + rng.below(70_000)).min(data.len() - pos);
                let flush = match rng.below(20) {
                    0 => Flush::Sync,
                    1 => Flush::Full,
                    _ => Flush::None,
                };
                d.compress(&data[pos..pos + n], flush, &mut c).unwrap();
                pos += n;
            }
            d.finish(&mut c).unwrap();
            assert_eq!(d.write(b"x", &mut c), Err(flate::Error::Finished));
            assert_eq!(inflate_chunked(&c, &mut rng, 5000, 70_000), data, "{name} level {level}");
        }
        // Byte-at-a-time on both sides of the decoder.
        if data.len() <= 300_000 {
            let c = deflate::compress(&data, 6);
            assert_eq!(inflate_chunked(&c, &mut rng, 1, 1), data, "{name} tiny pieces");
        }
    }
}

#[test]
fn sync_flush_makes_everything_decodable() {
    let mut rng = Rng(3);
    let data = common::text(&mut rng, 100_000);
    let mut d = Deflater::new(6);
    let mut c = Vec::new();
    let mut inf = Inflater::new();
    let mut got = Vec::new();
    let mut fed = 0;
    let mut buf = vec![0u8; 1 << 16];
    let mut sent = 0;
    for piece in data.chunks(7777) {
        d.compress(piece, Flush::Sync, &mut c).unwrap();
        sent += piece.len();
        assert_eq!(&c[c.len() - 4..], &[0, 0, 0xff, 0xff]);
        loop {
            let p = inf.inflate(&c[fed..], &mut buf).unwrap();
            fed += p.consumed;
            got.extend_from_slice(&buf[..p.produced]);
            if p.status == Status::NeedsInput {
                break;
            }
        }
        assert_eq!(&got[..], &data[..sent]);
    }
    assert_eq!(got, data);
}

#[test]
fn full_flush_restarts_history() {
    let mut rng = Rng(5);
    let data = common::text(&mut rng, 50_000);
    let mut d = Deflater::new(9);
    let mut c = Vec::new();
    d.compress(&data, Flush::Full, &mut c).unwrap();
    let cut = c.len();
    d.compress(&data, Flush::Finish, &mut c).unwrap();
    // A fresh decoder can start at the flush point.
    assert_eq!(inflate::decompress(&c[cut..]).unwrap(), data);
    let mut both = data.clone();
    both.extend_from_slice(&data);
    assert_eq!(inflate::decompress(&c).unwrap(), both);
}

#[test]
fn io_adapters() {
    use std::io::{Read, Write};
    let mut rng = Rng(9);
    let data = common::text(&mut rng, 400_000);
    let mut e = gzip::GzEncoder::new(Vec::new(), 6);
    for piece in data.chunks(1000) {
        e.write_all(piece).unwrap();
    }
    let g = e.finish().unwrap();
    let mut out = Vec::new();
    // A one-byte BufReader makes every header and trailer straddle reads.
    let r = std::io::BufReader::with_capacity(1, &g[..]);
    gzip::GzDecoder::new(r).read_to_end(&mut out).unwrap();
    assert_eq!(out, data);

    let mut e = zlib::ZlibEncoder::new(Vec::new(), 9);
    e.write_all(&data).unwrap();
    e.flush().unwrap();
    e.write_all(&data[..10]).unwrap();
    let z = e.finish().unwrap();
    let mut out = Vec::new();
    zlib::ZlibDecoder::new(std::io::BufReader::with_capacity(3, &z[..])).read_to_end(&mut out).unwrap();
    assert_eq!(out.len(), data.len() + 10);

    let mut e = deflate::DeflateEncoder::new(Vec::new(), 1);
    e.write_all(&data).unwrap();
    let mut raw = e.finish().unwrap();
    raw.extend_from_slice(b"TAIL");
    let mut d = inflate::DeflateDecoder::new(&raw[..]);
    let mut out = Vec::new();
    d.read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
    assert_eq!(d.into_inner(), b"TAIL");
}

#[test]
fn decompression_limit() {
    let z = vec![0u8; 1 << 20];
    let c = gzip::compress(&z, 9);
    assert_eq!(gzip::decompress_with_limit(&c, 1000), Err(flate::Error::OutputLimit));
    assert_eq!(gzip::decompress_with_limit(&c, 1 << 20).unwrap().len(), 1 << 20);
    let c = deflate::compress(&z, 9);
    assert_eq!(inflate::decompress_with_limit(&c, (1 << 20) - 1), Err(flate::Error::OutputLimit));
}
