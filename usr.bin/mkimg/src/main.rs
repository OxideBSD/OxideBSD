//! `mkimg(1)`: assembles partition images into a partitioned disk image (OxideBSD-doc
//! `RAM_FLOOR.md` §4.4.2), as FreeBSD's mkimg does. The system's disk images are built with it
//! on the host; it is installed on the target too.
//!
//! ```text
//! mkimg -s scheme -o outfile [-c capacity] -p partition ...
//! ```
//!
//! - `-s gpt` or `-s mbr`: the partitioning scheme.
//! - `-o outfile`: the disk image written.
//! - `-c capacity`: the disk's size at least, in bytes or with a `k`, `m` or `g` suffix; the last
//!   partition does not grow into it.
//! - `-p type[/label]:=file`: a partition holding `file`; `-p type[/label]::size`: an empty one
//!   of `size`. Types: `oxfs`, `efi`. A label is GPT's partition name (`/dev/gpt/<label>`).
//!
//! Partitions start at 1 MiB and on 1 MiB boundaries, and are whole 4 KiB blocks. A GPT disk's
//! and partitions' GUIDs are derived from the layout, so the same partitions give the same disk:
//! an image is reproducible. Zero blocks of a partition image are skipped, so the output stays
//! as sparse as its inputs.

use oxfs_format::{OXFS_MBR_TYPE, OXFS_TYPE_GUID, guid_bytes};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

const SECTOR: u64 = 512;
/// Partitions start on this boundary, in sectors (1 MiB).
const ALIGN: u64 = 2048;
const GPT_ENTRIES: u64 = 128;
const GPT_ENTRY_SIZE: u64 = 128;
const GPT_ENTRY_SECTORS: u64 = GPT_ENTRIES * GPT_ENTRY_SIZE / SECTOR;
/// The EFI system partition's type, `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`.
const EFI_TYPE_GUID: [u8; 16] = guid_bytes(0xC12A_7328, 0xF81F, 0x11D2, [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]);
const EFI_MBR_TYPE: u8 = 0xEF;

fn usage() -> ExitCode {
    eprintln!("usage: mkimg -s gpt|mbr -o outfile [-c capacity] -p type[/label]:=file|::size ...");
    ExitCode::from(1)
}

#[derive(Clone, Copy, PartialEq)]
enum Scheme {
    Gpt,
    Mbr,
}

#[derive(Clone, Copy)]
enum PartType {
    Oxfs,
    Efi,
}

impl PartType {
    fn guid(self) -> [u8; 16] {
        match self {
            PartType::Oxfs => OXFS_TYPE_GUID,
            PartType::Efi => EFI_TYPE_GUID,
        }
    }

    fn mbr(self) -> u8 {
        match self {
            PartType::Oxfs => OXFS_MBR_TYPE,
            PartType::Efi => EFI_MBR_TYPE,
        }
    }
}

struct Part {
    kind: PartType,
    label: String,
    /// The image to copy in, if any.
    file: Option<File>,
    /// Size in sectors, a whole number of 4 KiB blocks.
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
        _ => return Err(format!("{kind}: unknown partition type (oxfs, efi)")),
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

/// CRC-32 (IEEE 802.3, reflected), as GPT uses.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// A version 4 (random-shaped) GUID from `seed`: FNV-1a over it, stretched to 16 bytes.
fn derived_guid(seed: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (half, chunk) in out.chunks_mut(8).enumerate() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ half as u64;
        for &b in seed {
            h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01B3);
        }
        chunk.copy_from_slice(&h.to_le_bytes());
    }
    out[7] = (out[7] & 0x0F) | 0x40;
    out[8] = (out[8] & 0x3F) | 0x80;
    out
}

/// The GPT: the first `2 + GPT_ENTRY_SECTORS` sectors (protective MBR, header, entries) and the
/// last `GPT_ENTRY_SECTORS + 1` (backup entries and header).
fn gpt(total: u64, parts: &[Part]) -> (Vec<u8>, Vec<u8>) {
    let layout: Vec<u8> = parts
        .iter()
        .flat_map(|p| [&p.kind.guid()[..], p.label.as_bytes(), &p.first.to_le_bytes(), &p.sectors.to_le_bytes()].concat())
        .chain(total.to_le_bytes())
        .collect();
    let disk_guid = derived_guid(&[b"disk".as_slice(), &layout].concat());
    let mut entries = vec![0u8; (GPT_ENTRIES * GPT_ENTRY_SIZE) as usize];
    for (i, p) in parts.iter().enumerate() {
        let e = &mut entries[i * GPT_ENTRY_SIZE as usize..(i + 1) * GPT_ENTRY_SIZE as usize];
        e[0..16].copy_from_slice(&p.kind.guid());
        e[16..32].copy_from_slice(&derived_guid(&[&layout[..], &(i as u64).to_le_bytes()].concat()));
        e[32..40].copy_from_slice(&p.first.to_le_bytes());
        e[40..48].copy_from_slice(&(p.first + p.sectors - 1).to_le_bytes());
        for (j, unit) in p.label.encode_utf16().enumerate() {
            e[56 + j * 2..58 + j * 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let entries_crc = crc32(&entries);
    let last_usable = total - 2 - GPT_ENTRY_SECTORS;
    let header = |this: u64, other: u64, entries_lba: u64| -> Vec<u8> {
        let mut h = vec![0u8; SECTOR as usize];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&this.to_le_bytes());
        h[32..40].copy_from_slice(&other.to_le_bytes());
        h[40..48].copy_from_slice(&(2 + GPT_ENTRY_SECTORS).to_le_bytes());
        h[48..56].copy_from_slice(&last_usable.to_le_bytes());
        h[56..72].copy_from_slice(&disk_guid);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&(GPT_ENTRIES as u32).to_le_bytes());
        h[84..88].copy_from_slice(&(GPT_ENTRY_SIZE as u32).to_le_bytes());
        h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let crc = crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    let mut head = vec![0u8; (SECTOR * (2 + GPT_ENTRY_SECTORS)) as usize];
    // The protective MBR: one 0xEE entry over the disk (capped at 32 bits).
    mbr_entry(&mut head, 0, 0xEE, 1, total - 1);
    head[SECTOR as usize..2 * SECTOR as usize].copy_from_slice(&header(1, total - 1, 2));
    head[2 * SECTOR as usize..].copy_from_slice(&entries);
    let mut tail = vec![0u8; (SECTOR * (GPT_ENTRY_SECTORS + 1)) as usize];
    tail[..entries.len()].copy_from_slice(&entries);
    tail[entries.len()..].copy_from_slice(&header(total - 1, 1, total - 1 - GPT_ENTRY_SECTORS));
    (head, tail)
}

/// Writes MBR entry `i` of sector 0 in `sector0` (LBA fields only; CHS saturated), and the
/// signature.
fn mbr_entry(sector0: &mut [u8], i: usize, kind: u8, first: u64, sectors: u64) {
    let e = &mut sector0[446 + i * 16..462 + i * 16];
    e[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[4] = kind;
    e[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[8..12].copy_from_slice(&(first.min(u32::MAX as u64) as u32).to_le_bytes());
    e[12..16].copy_from_slice(&(sectors.min(u32::MAX as u64) as u32).to_le_bytes());
    sector0[510] = 0x55;
    sector0[511] = 0xAA;
}

fn run(scheme: Scheme, out: &str, capacity: u64, mut parts: Vec<Part>) -> Result<(), String> {
    if scheme == Scheme::Mbr && parts.len() > 4 {
        return Err("MBR holds at most four partitions".into());
    }
    let mut next = ALIGN;
    for p in &mut parts {
        p.first = next;
        next = (p.first + p.sectors).div_ceil(ALIGN) * ALIGN;
    }
    let end = parts.last().map_or(ALIGN, |p| p.first + p.sectors);
    // Room after the last partition for the backup GPT.
    let tail = if scheme == Scheme::Gpt { GPT_ENTRY_SECTORS + 1 } else { 0 };
    let total = (end + tail).max(capacity.div_ceil(SECTOR));
    if scheme == Scheme::Mbr && total > u32::MAX as u64 {
        return Err("too large for MBR (2 TiB)".into());
    }
    let disk = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out)
        .map_err(|e| format!("{out}: {e}"))?;
    disk.set_len(total * SECTOR).map_err(|e| format!("{out}: {e}"))?;
    let io = |e: std::io::Error| format!("{out}: {e}");
    match scheme {
        Scheme::Gpt => {
            let (head, tail) = gpt(total, &parts);
            disk.write_all_at(&head, 0).map_err(io)?;
            disk.write_all_at(&tail, (total - GPT_ENTRY_SECTORS - 1) * SECTOR).map_err(io)?;
        }
        Scheme::Mbr => {
            let mut sector0 = vec![0u8; SECTOR as usize];
            for (i, p) in parts.iter().enumerate() {
                mbr_entry(&mut sector0, i, p.kind.mbr(), p.first, p.sectors);
            }
            disk.write_all_at(&sector0, 0).map_err(io)?;
        }
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
    let (mut scheme, mut out, mut capacity, mut parts) = (None, None, 0, Vec::new());
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
    match run(scheme, &out, capacity, parts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkimg: {e}");
            ExitCode::from(1)
        }
    }
}
