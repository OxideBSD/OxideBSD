//! `fsconf_mkdb(8)`: compiles `/etc/fstab` into `/boot/fsconf`, the binary form the kernel reads
//! before any file system is mounted to find the root (`fsconf(5)`, OxideBSD-doc `RAM_FLOOR.md`
//! §3.4.5). Run after editing `/etc/fstab`, like `pwd_mkdb(8)` after the password file.
//!
//! ```text
//! fsconf_mkdb [-f fstab] [-o fsconf]
//! ```
//!
//! The file is written beside its final name and renamed into place, so a reader never sees half
//! of it. The boot loader loads `/boot/fsconf` from the boot partition; on a system whose boot
//! partition isn't the root file system, copy it there.
//!
//! Format (`fsconf(5)`), little-endian: the magic `OXFSCONF`, a `u32` version (1), a `u32` entry
//! count, then per entry four length-prefixed (`u16`) strings -- device, mount point, type,
//! options (comma-separated) -- and two `u32`s, the dump frequency and the fsck pass.

use std::process::ExitCode;

const MAGIC: &[u8; 8] = b"OXFSCONF";
const VERSION: u32 = 1;

fn usage() -> ExitCode {
    eprintln!("usage: fsconf_mkdb [-f fstab] [-o fsconf]");
    ExitCode::from(1)
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), String> {
    let len = u16::try_from(s.len()).map_err(|_| format!("field too long: {s}"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn encode(entries: &[fstab::Entry]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        put_str(&mut out, &e.spec)?;
        put_str(&mut out, &e.file)?;
        put_str(&mut out, &e.vfstype)?;
        put_str(&mut out, &e.options.join(","))?;
        out.extend_from_slice(&e.freq.to_le_bytes());
        out.extend_from_slice(&e.passno.to_le_bytes());
    }
    Ok(out)
}

fn main() -> ExitCode {
    let (mut input, mut output) = (String::from("/etc/fstab"), String::from("/boot/fsconf"));
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "-f" => &mut input,
            "-o" => &mut output,
            _ => return usage(),
        };
        match args.next() {
            Some(v) => *slot = v,
            None => return usage(),
        }
    }
    let text = match std::fs::read_to_string(&input) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("fsconf_mkdb: {input}: {e}");
            return ExitCode::from(1);
        }
    };
    let (entries, errors) = fstab::parse(&text);
    for (line, msg) in &errors {
        eprintln!("fsconf_mkdb: {input}:{line}: {msg}");
    }
    if !errors.is_empty() {
        return ExitCode::from(1);
    }
    if !entries.iter().any(|e| e.file == "/") {
        eprintln!("fsconf_mkdb: {input}: no entry for /");
        return ExitCode::from(1);
    }
    let bytes = match encode(&entries) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fsconf_mkdb: {e}");
            return ExitCode::from(1);
        }
    };
    let tmp = format!("{output}.tmp");
    if let Err(e) = std::fs::write(&tmp, &bytes).and_then(|()| std::fs::rename(&tmp, &output)) {
        eprintln!("fsconf_mkdb: {output}: {e}");
        let _ = std::fs::remove_file(&tmp);
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
