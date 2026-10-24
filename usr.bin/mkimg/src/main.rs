//! `mkimg(1)`: assembles partition images into a partitioned disk image (OxideBSD-doc
//! `RAM_FLOOR.md` §4.4.2), as FreeBSD's mkimg does. The system's disk images are built with it
//! on the host; it is installed on the target too.
//!
//! ```text
//! mkimg -s scheme -o outfile [-S secsz] [-c capacity] [-b bootcode] -p partition ...
//! ```
//!
//! - `-s gpt` or `-s mbr`: the partitioning scheme.
//! - `-o outfile`: the disk image written.
//! - `-S secsz`: the disk's logical sector size, which its tables count in: 512 (the default),
//!   1024, 2048 or 4096 (a "4Kn" disk). Not with `-b`.
//! - `-c capacity`: the disk's size at least, in bytes or with a `k`, `m` or `g` suffix; the last
//!   partition does not grow into it.
//! - `-p type[/label]:=file`: a partition holding `file`; `-p type[/label]::size`: an empty one
//!   of `size`. Types: `oxfs`, `efi`, `bios` (a GPT BIOS boot partition, for `-b`), `fat16b`, `fat32`,
//!   `fat32lba`, `ms-basic-data` (FAT; on GPT all a Microsoft basic data partition). A label is
//!   GPT's partition name (`/dev/gpt/<label>`).
//! - `-b bootcode`: BIOS boot code, Limine's hard-disk image (`limine-bios-hdd.bin`), installed
//!   as `limine bios-install` does (`RAM_FLOOR.md` §4.4.4): its first sector becomes the boot
//!   sector, keeping the disk's timestamp and partition table, and the rest, stage 2, goes into
//!   the GPT's `bios` partition, or on an MBR disk into the gap before the first partition; the
//!   boot sector is told where (a little-endian byte offset at `0x1a4`). An MBR disk's first
//!   partition is marked active if none is, as some BIOSes need. Stage 2 finds
//!   `limine-bios.sys` and `limine.conf` on a FAT partition of the disk.
//!
//! Partitions start at 1 MiB and on 1 MiB boundaries, and are whole 4 KiB blocks. A GPT disk's
//! and partitions' GUIDs are derived from the layout, so the same partitions give the same disk:
//! an image is reproducible. Zero blocks of a partition image are skipped, so the output stays
//! as sparse as its inputs.

use part::{Kind, Table, TypeCode};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

/// The unit partitions are laid out in; the disk's own sectors (`-S`) are a multiple of it.
const SECTOR: u64 = 512;
/// Partitions start on this boundary, in 512-byte sectors (1 MiB).
const ALIGN: u64 = 2048;
/// The GPT entry array's bytes (16 KiB): a whole number of sectors of every size `-S` takes.
const GPT_ENTRY_BYTES: u64 = 128 * 128;

fn usage() -> ExitCode {
    eprintln!("usage: mkimg -s gpt|mbr -o outfile [-S secsz] [-c capacity] [-b bootcode] -p type[/label]:=file|::size ...");
    ExitCode::from(1)
}

#[derive(Clone, Copy, PartialEq)]
enum Scheme {
    Gpt,
    Mbr,
}

#[derive(Clone, Copy)]
#[derive(PartialEq)]
enum PartType {
    Oxfs,
    Efi,
    Bios,
    /// FAT, under FreeBSD's MBR names: `fat16b` (0x06), `fat32` (0x0b), `fat32lba` (0x0c); on GPT
    /// each is a Microsoft basic data partition, as is `ms-basic-data`.
    Fat(u8),
}

impl PartType {
    /// Its type as `scheme`'s table stores it (libpart's names, but each FAT type its own on MBR).
    fn code(self, scheme: part::Scheme) -> TypeCode {
        let kind = match self {
            PartType::Oxfs => Kind::Oxfs,
            PartType::Efi => Kind::Efi,
            PartType::Bios => Kind::BiosBoot,
            PartType::Fat(t) if scheme == part::Scheme::Mbr => return TypeCode::Mbr(t),
            PartType::Fat(_) => Kind::MsBasicData,
        };
        kind.code(scheme).expect("a bios partition is refused on MBR")
    }

    fn guid(self) -> [u8; 16] {
        match self.code(part::Scheme::Gpt) {
            TypeCode::Gpt(g) => g,
            TypeCode::Mbr(_) => unreachable!(),
        }
    }
}

struct Part {
    kind: PartType,
    label: String,
    /// The image to copy in, if any.
    file: Option<File>,
    /// Size and start in 512-byte sectors, whole 4 KiB blocks.
    sectors: u64,
    first: u64,
}

fn parse_size(s: &str) -> Option<u64> {
    let (num, mult) = match s.as_bytes().last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1 << 10),
        b'm' | b'M' => (&s[..s.len() - 1], 1 << 20),
        b'g' | b'G' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// `type[/label]:=file` or `type[/label]::size`.
fn parse_part(s: &str) -> Result<Part, String> {
    let (head, spec) = s.split_once(':').ok_or(format!("{s}: no `:=file` or `::size`"))?;
    let (kind, label) = head.split_once('/').unwrap_or((head, ""));
    let kind = match kind {
        "oxfs" => PartType::Oxfs,
        "efi" => PartType::Efi,
        "bios" => PartType::Bios,
        "fat16b" => PartType::Fat(0x06),
        "fat32" => PartType::Fat(0x0B),
        "fat32lba" | "ms-basic-data" => PartType::Fat(0x0C),
        _ => return Err(format!("{kind}: unknown partition type (oxfs, efi, bios, fat16b, fat32, fat32lba, ms-basic-data)")),
    };
    if label.encode_utf16().count() > 36 || label.contains('/') {
        return Err(format!("{label}: a label is at most 36 characters, without `/`"));
    }
    let (file, bytes) = if let Some(path) = spec.strip_prefix('=') {
        let f = File::open(path).map_err(|e| format!("{path}: {e}"))?;
        let len = f.metadata().map_err(|e| format!("{path}: {e}"))?.len();
        (Some(f), len)
    } else if let Some(size) = spec.strip_prefix(':') {
        (None, parse_size(size).ok_or(format!("{size}: bad size"))?)
    } else {
        return Err(format!("{s}: no `:=file` or `::size`"));
    };
    if bytes == 0 {
        return Err(format!("{s}: an empty partition"));
    }
    Ok(Part { kind, label: label.to_string(), file, sectors: bytes.div_ceil(4096) * 8, first: 0 })
}

/// The table of a disk of `total` sectors of `ss` bytes holding `parts` (laid out in 512-byte
/// sectors). A GPT's disk and partition GUIDs are derived from the layout, so the same
/// partitions give the same disk.
fn table(scheme: Scheme, total: u64, parts: &[Part], ss: u64) -> Result<Table, String> {
    let scale = ss / SECTOR;
    let layout: Vec<u8> = parts
        .iter()
        .flat_map(|p| [&p.kind.guid()[..], p.label.as_bytes(), &p.first.to_le_bytes(), &p.sectors.to_le_bytes()].concat())
        .chain(total.to_le_bytes())
        .collect();
    let s = match scheme {
        Scheme::Gpt => part::Scheme::Gpt,
        Scheme::Mbr => part::Scheme::Mbr,
    };
    let disk_guid = if s == part::Scheme::Gpt { part::guid_from(&[b"disk".as_slice(), &layout].concat()) } else { [0; 16] };
    let mut t = Table::new(s, ss as u32, total, disk_guid).map_err(|e| e.to_string())?;
    for (i, p) in parts.iter().enumerate() {
        let guid = if s == part::Scheme::Gpt { part::guid_from(&[&layout[..], &(i as u64).to_le_bytes()].concat()) } else { [0; 16] };
        t.add(p.kind.code(s), &p.label, Some(p.first / scale), Some(p.sectors / scale), guid).map_err(|e| e.to_string())?;
    }
    Ok(t)
}

fn run(scheme: Scheme, out: &str, ss: u64, capacity: u64, bootcode: Option<&[u8]>, mut parts: Vec<Part>) -> Result<(), String> {
    if bootcode.is_some() && ss != SECTOR {
        return Err("-b needs 512-byte sectors".into());
    }
    let scale = ss / SECTOR;
    if scheme == Scheme::Mbr && parts.len() > 4 {
        return Err("MBR holds at most four partitions".into());
    }
    if scheme == Scheme::Mbr && parts.iter().any(|p| p.kind == PartType::Bios) {
        return Err("a bios partition is GPT's; on MBR, -b uses the gap before the first partition".into());
    }
    let mut next = ALIGN;
    for p in &mut parts {
        p.first = next;
        next = (p.first + p.sectors).div_ceil(ALIGN) * ALIGN;
    }
    let end = parts.last().map_or(ALIGN, |p| p.first + p.sectors);
    // Room after the last partition for the backup GPT; the disk in its own sectors.
    let tail = if scheme == Scheme::Gpt { (GPT_ENTRY_BYTES / ss + 1) * scale } else { 0 };
    let total = (end + tail).max(capacity.div_ceil(SECTOR)).div_ceil(scale);
    if scheme == Scheme::Mbr && total > u32::MAX as u64 {
        return Err("too large for MBR (2 TiB)".into());
    }
    let disk = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out)
        .map_err(|e| format!("{out}: {e}"))?;
    disk.set_len(total * ss).map_err(|e| format!("{out}: {e}"))?;
    let io = |e: std::io::Error| format!("{out}: {e}");
    let mut t = table(scheme, total, &parts, ss)?;
    // `-b`: Limine's boot sector and stage 2 (libpart's `set_bios_bootcode`).
    let stage2 = match bootcode {
        Some(code) => Some(t.set_bios_bootcode(code).map_err(|e| format!("{out}: boot code: {e}"))?),
        None => None,
    };
    for (lba, bytes) in t.write().into_iter().chain(stage2) {
        disk.write_all_at(&bytes, lba * ss).map_err(io)?;
    }
    let mut buf = vec![0u8; 1 << 20];
    for p in &mut parts {
        let Some(f) = p.file.as_mut() else { continue };
        let mut at = p.first * SECTOR;
        loop {
            let n = read_full(f, &mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            // Zero 4 KiB blocks are left as holes.
            for (i, chunk) in buf[..n].chunks(4096).enumerate() {
                if chunk.iter().any(|&b| b != 0) {
                    disk.write_all_at(chunk, at + (i * 4096) as u64).map_err(io)?;
                }
            }
            at += n as u64;
        }
    }
    disk.sync_all().map_err(io)
}

fn read_full(f: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match f.read(&mut buf[got..])? {
            0 => break,
            n => got += n,
        }
    }
    Ok(got)
}

fn main() -> ExitCode {
    let (mut scheme, mut out, mut capacity, mut parts, mut bootcode) = (None, None, 0, Vec::new(), None);
    let mut ss = SECTOR;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let Some(value) = args.next() else { return usage() };
        match arg.as_str() {
            "-s" => {
                scheme = match value.as_str() {
                    "gpt" => Some(Scheme::Gpt),
                    "mbr" => Some(Scheme::Mbr),
                    _ => return usage(),
                }
            }
            "-o" => out = Some(value),
            "-S" => match value.parse::<u64>() {
                Ok(n @ (512 | 1024 | 2048 | 4096)) => ss = n,
                _ => return usage(),
            },
            "-b" => match std::fs::read(&value) {
                Ok(code) => bootcode = Some(code),
                Err(e) => {
                    eprintln!("mkimg: {value}: {e}");
                    return ExitCode::from(1);
                }
            },
            "-c" => match parse_size(&value) {
                Some(n) => capacity = n,
                None => return usage(),
            },
            "-p" => match parse_part(&value) {
                Ok(p) => parts.push(p),
                Err(e) => {
                    eprintln!("mkimg: {e}");
                    return ExitCode::from(1);
                }
            },
            _ => return usage(),
        }
    }
    let (Some(scheme), Some(out)) = (scheme, out) else { return usage() };
    if parts.is_empty() {
        return usage();
    }
    match run(scheme, &out, ss, capacity, bootcode.as_deref(), parts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkimg: {e}");
            ExitCode::from(1)
        }
    }
}
