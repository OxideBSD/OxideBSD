//! Interoperability with the reference implementations on the host: gzip(1) and Python's
//! zlib module (which is zlib itself). Each test skips when its tool is missing.

mod common;

use common::{datasets, have_gzip, have_python, python, run};
use flate::{deflate, gzip, inflate, zlib};

#[test]
fn gzip_reads_ours() {
    if !have_gzip() {
        return;
    }
    for (name, data) in datasets() {
        for level in 0..=9 {
            let g = gzip::compress(&data, level);
            assert_eq!(run("gzip", &["-dc"], &g).as_deref(), Some(&data[..]), "{name} level {level}");
        }
    }
}

#[test]
fn we_read_gzips() {
    if !have_gzip() {
        return;
    }
    for (name, data) in datasets() {
        for level in 1..=9 {
            let g = run("gzip", &["-c", &format!("-{level}")], &data).unwrap();
            assert_eq!(gzip::decompress(&g).unwrap(), data, "{name} level {level}");
        }
    }
}

#[test]
fn gzip_header_fields_both_ways() {
    if !have_gzip() {
        return;
    }
    // gzip -N records the name and mtime of a file; feed it one.
    let dir = std::env::temp_dir().join(format!("flate-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("some name.txt");
    std::fs::write(&f, b"named contents").unwrap();
    let out = std::process::Command::new("gzip").arg("-cN").arg(&f).output().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let mut d = gzip::GzDecoder::new(&out.stdout[..]);
    let mut s = Vec::new();
    std::io::Read::read_to_end(&mut d, &mut s).unwrap();
    assert_eq!(s, b"named contents");
    let h = d.header().unwrap();
    assert_eq!(h.name.as_deref(), Some(&b"some name.txt"[..]));
    assert!(h.mtime > 1_000_000_000);

    // Ours with every optional field, FHCRC included: gzip must accept it and see the name.
    let h = gzip::Header {
        text: true,
        mtime: 1_700_000_000,
        xfl: 0,
        os: gzip::OS_UNIX,
        extra: Some(b"Ox\x03\x00abc".to_vec()),
        name: Some(b"original.c".to_vec()),
        comment: Some(b"made by flate".to_vec()),
        hcrc: true,
    };
    let mut e = gzip::GzEncoder::with_header(Vec::new(), 9, &h).unwrap();
    std::io::Write::write_all(&mut e, b"payload payload payload").unwrap();
    let g = e.finish().unwrap();
    assert_eq!(run("gzip", &["-dc"], &g).as_deref(), Some(&b"payload payload payload"[..]));
    // gzip -lN reads the header (FHCRC, FEXTRA and FCOMMENT skipped correctly) for the name.
    let l = String::from_utf8(run("gzip", &["-lN"], &g).unwrap()).unwrap();
    assert!(l.contains("original.c"), "gzip -lN: {l}");
}

#[test]
fn multi_member_from_gzip() {
    if !have_gzip() {
        return;
    }
    let mut cat = run("gzip", &["-c"], b"first member\n").unwrap();
    cat.extend(gzip::compress(b"second member\n", 6));
    cat.extend(run("gzip", &["-c9"], b"third member\n").unwrap());
    assert_eq!(gzip::decompress(&cat).unwrap(), b"first member\nsecond member\nthird member\n");
    assert_eq!(run("gzip", &["-dc"], &cat).unwrap(), b"first member\nsecond member\nthird member\n");
}

#[test]
fn python_zlib_reads_ours() {
    if !have_python() {
        return;
    }
    for (name, data) in datasets() {
        for level in [0, 1, 2, 4, 6, 9] {
            let raw = deflate::compress(&data, level);
            let got = python("o = zlib.decompress(d, -15)", &raw);
            assert_eq!(got.as_deref(), Some(&data[..]), "{name} raw level {level}");
            let z = zlib::compress(&data, level);
            let got = python("o = zlib.decompress(d)", &z);
            assert_eq!(got.as_deref(), Some(&data[..]), "{name} zlib level {level}");
        }
    }
}

#[test]
fn we_read_python_zlib() {
    if !have_python() {
        return;
    }
    for (name, data) in datasets() {
        for level in [0, 1, 5, 9] {
            let z = python(&format!("o = zlib.compress(d, {level})"), &data).unwrap();
            assert_eq!(zlib::decompress(&z).unwrap(), data, "{name} zlib level {level}");
            // Raw, with a small memLevel and the Huffman-only and RLE strategies, which
            // make shapes zlib's default does not.
            for (mem, strat) in [(1, 0), (9, 2), (8, 3), (8, 4)] {
                let code = format!(
                    "c = zlib.compressobj({level}, zlib.DEFLATED, -15, {mem}, {strat})\no = c.compress(d) + c.flush()"
                );
                let raw = python(&code, &data).unwrap();
                assert_eq!(inflate::decompress(&raw).unwrap(), data, "{name} raw {level} mem {mem} strategy {strat}");
            }
        }
    }
}

#[test]
fn python_reads_our_flushes() {
    if !have_python() {
        return;
    }
    let mut rng = common::Rng(11);
    let data = common::text(&mut rng, 200_000);
    let mut d = flate::Deflater::new(6);
    let mut c = Vec::new();
    for (i, piece) in data.chunks(10_000).enumerate() {
        let f = if i % 3 == 0 { flate::Flush::Full } else { flate::Flush::Sync };
        d.compress(piece, f, &mut c).unwrap();
    }
    d.finish(&mut c).unwrap();
    assert_eq!(python("o = zlib.decompress(d, -15)", &c).as_deref(), Some(&data[..]));
}
