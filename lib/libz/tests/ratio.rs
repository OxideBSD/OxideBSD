//! Compression ratio and speed against gzip(1) on a source corpus: by default the OxideBSD
//! kernel's `sys/**/*.rs` (found from this crate's place in the tree), or the directory named
//! by FLATE_CORPUS. Run with `--nocapture` to see the table.

mod common;

use std::path::{Path, PathBuf};
use std::time::Instant;

use flate::{deflate, inflate};

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs" || x == "c" || x == "h") {
            out.push(p);
        }
    }
}

fn corpus() -> (String, Vec<u8>) {
    let dir = std::env::var_os("FLATE_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sys"));
    let mut files = Vec::new();
    collect(&dir, &mut files);
    files.sort();
    let mut data = Vec::new();
    for f in &files {
        data.extend(std::fs::read(f).unwrap_or_default());
    }
    if data.len() < 100_000 {
        // Out of the tree: this crate's own sources and generated text.
        collect(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        for f in &files {
            data.extend(std::fs::read(f).unwrap_or_default());
        }
        data.extend(common::text(&mut common::Rng(1), 1 << 20));
        return ("crate sources + generated text".into(), data);
    }
    (format!("{} ({} files)", dir.display(), files.len()), data)
}

/// Best of three: the host may be busy.
fn best_of<T>(mut f: impl FnMut() -> T) -> (T, f64) {
    let mut best = f64::MAX;
    let mut out = None;
    for _ in 0..3 {
        let t = Instant::now();
        out = Some(f());
        best = best.min(t.elapsed().as_secs_f64());
    }
    (out.unwrap(), best)
}

#[test]
fn ratio_against_gzip() {
    let (name, data) = corpus();
    eprintln!("corpus: {name}, {} bytes", data.len());
    eprintln!("sizes are of the raw deflate stream; MB/s best of 3, zlib's measured inside python3");
    eprintln!("level  flate bytes   gzip bytes   zlib bytes  flate/gzip  flate/zlib  flate MB/s c/d    zlib MB/s c/d");
    let gz = common::have_gzip();
    let py = common::have_python();
    let mb = data.len() as f64 / 1e6;
    for level in 0..=9 {
        let (c, ct) = best_of(|| deflate::compress(&data, level));
        let (d, dt) = best_of(|| inflate::decompress(&c).unwrap());
        assert_eq!(d, data);
        // gzip's size less its 18-byte header and trailer (no name: it reads stdin).
        let g = if gz && level > 0 {
            common::run("gzip", &["-c", &format!("-{level}")], &data).map(|g| g.len() - 18)
        } else {
            None
        };
        let z = if py {
            let code = format!(
                "import time\nb = [1e9, 1e9]\nfor _ in range(3):\n    t = time.perf_counter(); c = zlib.compress(d, {level}); b[0] = min(b[0], time.perf_counter() - t)\n    t = time.perf_counter(); zlib.decompress(c); b[1] = min(b[1], time.perf_counter() - t)\no = ('%d %f %f' % (len(c) - 6, b[0], b[1])).encode()"
            );
            common::python(&code, &data).map(|o| {
                let o = String::from_utf8(o).unwrap();
                let v: Vec<f64> = o.split(' ').map(|x| x.parse().unwrap()).collect();
                (v[0] as usize, mb / v[1], mb / v[2])
            })
        } else {
            None
        };
        let ratio = |x: Option<usize>| x.map_or("-".to_string(), |x| format!("{:.4}", c.len() as f64 / x as f64));
        eprintln!(
            "{level:>5}  {:>11}  {:>11}  {:>11}  {:>10}  {:>10}  {:>7.1} {:>6.1}  {:>7}",
            c.len(),
            g.map_or("-".into(), |g| g.to_string()),
            z.map_or("-".into(), |z| z.0.to_string()),
            ratio(g),
            ratio(z.map(|z| z.0)),
            mb / ct,
            mb / dt,
            z.map_or("-".into(), |z| format!("{:.1} {:.1}", z.1, z.2)),
        );
        for r in [g, z.map(|z| z.0)].into_iter().flatten().map(|x| c.len() as f64 / x as f64) {
            assert!(r < 1.03, "level {level}: {r:.4} of the reference's size");
        }
    }
}
