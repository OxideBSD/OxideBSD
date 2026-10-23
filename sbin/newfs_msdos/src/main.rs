//! `newfs_msdos(8)`: makes an empty FAT12, FAT16 or FAT32 file system (OxideBSD-doc `VFS.md`
//! §9), with FreeBSD's options. The layout is `lib/libmsdosfs`'s (`Bpb::layout`), shared with
//! makefs(8) and the kernel's msdosfs.
//!
//! ```text
//! newfs_msdos [-N] [-@ offset] [-C create-size] [-F FAT-type] [-I VolumeID] [-L label]
//!             [-S sector-size] [-T timestamp] [-b block-size] [-c cluster-size] [-e DirEnts]
//!             [-m media] [-n FATs] [-o hidden] [-r reserved] [-s total] special
//! ```
//!
//! Sizes take a `k`, `m`, `g` or `s` (sectors) suffix where FreeBSD's do. The type, cluster size,
//! root directory size and reserved sectors not given are chosen from the size (Microsoft's
//! tables). FreeBSD's boot code (`-B`), geometry (`-h`, `-u`), FAT size (`-a`), FSInfo and backup
//! sector placement (`-i`, `-k`) and floppy formats (`-f`) are not offered: the volume's boot
//! sector only halts, and FAT32's FSInfo and backup are in sectors 1 and 6.

use msdosfs_format::{Bpb, DIR_ENTRY_SIZE, DirEntry, DosTime, FatType, Layout, ATTR_VOLUME_ID, fat, volume_label, write_fsinfo};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

const USAGE: &str = "usage: newfs_msdos [-N] [-@ offset] [-C create-size] [-F FAT-type] [-I VolumeID] [-L label]\n\
                     \x20                  [-S sector-size] [-T timestamp] [-b block-size] [-c cluster-size] [-e DirEnts]\n\
                     \x20                  [-m media] [-n FATs] [-o hidden] [-r reserved] [-s total] special";

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(1)
}

/// `special`'s size in bytes: a regular file's length, else the disk's size.
fn media_size(f: &File) -> std::io::Result<u64> {
    if f.metadata()?.is_file() {
        return Ok(f.metadata()?.len());
    }
    disk_size(f)
}

#[cfg(target_os = "oxidebsd")]
fn disk_size(f: &File) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd;
    /// `<sys/disk.h>`'s `DIOCGMEDIASIZE`, as the kernel defines it (`sys/drivers/disk.rs`).
    const DIOCGMEDIASIZE: libc::c_int = 0x8008_6481_u32 as libc::c_int;
    let mut size: i64 = 0;
    // SAFETY: the request writes one i64 through the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), DIOCGMEDIASIZE as _, &mut size) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(size as u64)
}

/// A host block device: its end.
#[cfg(not(target_os = "oxidebsd"))]
fn disk_size(mut f: &File) -> std::io::Result<u64> {
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::End(0))
}

/// A number, decimal or `0x` hex, with an optional size suffix: `k`, `m`, `g` (bytes) or `s`
/// (sectors of `sector` bytes). Without a suffix it's `unit`s.
fn size_arg(s: &str, unit: u64, sector: u64) -> Option<u64> {
    let (digits, mult) = match s.char_indices().last()? {
        (i, 'k' | 'K') => (&s[..i], 1 << 10),
        (i, 'm' | 'M') => (&s[..i], 1 << 20),
        (i, 'g' | 'G') => (&s[..i], 1 << 30),
        (i, 's' | 'S') => (&s[..i], sector),
        _ => (s, unit),
    };
    let n = match digits.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok()?,
        None => digits.parse().ok()?,
    };
    n.checked_mul(mult)
}

#[derive(Default)]
struct Opts {
    dry_run: bool,
    offset: u64,
    create: Option<u64>,
    fat_type: Option<FatType>,
    volume_id: Option<u32>,
    label: Option<String>,
    sector: Option<u64>,
    timestamp: Option<i64>,
    block: Option<u64>,
    cluster: Option<u64>,
    root_entries: Option<u16>,
    media: Option<u8>,
    fats: Option<u8>,
    hidden: Option<u32>,
    reserved: Option<u16>,
    total: Option<u64>,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub(crate) fn main() -> ExitCode {
    let mut o = Opts::default();
    let mut special = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let Some(flag) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            if special.replace(arg).is_some() {
                return usage();
            }
            continue;
        };
        let mut chars = flag.chars();
        let c = chars.next().unwrap();
        if c == 'N' && chars.as_str().is_empty() {
            o.dry_run = true;
            continue;
        }
        // Every other option takes a value, attached or next.
        let rest = chars.as_str();
        let value = if rest.is_empty() { args.next() } else { Some(rest.to_string()) };
        let Some(v) = value else { return usage() };
        let num = |v: &str| size_arg(v, 1, 1);
        let ok = match c {
            '@' => size_arg(&v, 1, 512).map(|n| o.offset = n),
            'C' => size_arg(&v, 1, 512).map(|n| o.create = Some(n)),
            'F' => match v.as_str() {
                "12" => Some(FatType::Fat12),
                "16" => Some(FatType::Fat16),
                "32" => Some(FatType::Fat32),
                _ => None,
            }
            .map(|t| o.fat_type = Some(t)),
            'I' => num(&v).and_then(|n| u32::try_from(n).ok()).map(|n| o.volume_id = Some(n)),
            'L' => Some(o.label = Some(v.clone())),
            'S' => num(&v).filter(|n| n.is_power_of_two() && (512..=4096).contains(n)).map(|n| o.sector = Some(n)),
            'T' => v.parse().ok().map(|n| o.timestamp = Some(n)),
            'b' => size_arg(&v, 1, 512).map(|n| o.block = Some(n)),
            'c' => num(&v).map(|n| o.cluster = Some(n)),
            'e' => num(&v).and_then(|n| u16::try_from(n).ok()).map(|n| o.root_entries = Some(n)),
            'm' => num(&v).and_then(|n| u8::try_from(n).ok()).filter(|&m| m == 0xF0 || m >= 0xF8).map(|n| o.media = Some(n)),
            'n' => num(&v).and_then(|n| u8::try_from(n).ok()).filter(|&n| n > 0).map(|n| o.fats = Some(n)),
            'o' => num(&v).and_then(|n| u32::try_from(n).ok()).map(|n| o.hidden = Some(n)),
            'r' => num(&v).and_then(|n| u16::try_from(n).ok()).filter(|&n| n > 0).map(|n| o.reserved = Some(n)),
            's' => size_arg(&v, 1, 1).map(|n| o.total = Some(n)),
            'A' | 'B' | 'O' | 'a' | 'f' | 'h' | 'i' | 'k' | 'u' => {
                eprintln!("newfs_msdos: -{c} is not supported");
                return ExitCode::from(1);
            }
            _ => return usage(),
        };
        if ok.is_none() {
            eprintln!("newfs_msdos: -{c} {v}: bad value");
            return ExitCode::from(1);
        }
    }
    let Some(special) = special else { return usage() };
    match newfs(&special, &o) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("newfs_msdos: {special}: {e}");
            ExitCode::from(1)
        }
    }
}

fn newfs(special: &str, o: &Opts) -> Result<(), String> {
    let sector = o.sector.unwrap_or(512);
    let file = match o.create {
        Some(size) if !o.dry_run => {
            let f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(special).map_err(|e| e.to_string())?;
            if f.metadata().map_err(|e| e.to_string())?.len() < o.offset + size {
                f.set_len(o.offset + size).map_err(|e| e.to_string())?;
            }
            f
        }
        _ => OpenOptions::new().read(true).write(!o.dry_run).open(special).map_err(|e| e.to_string())?,
    };
    let media = match o.create {
        Some(size) => o.offset + size,
        None => media_size(&file).map_err(|e| format!("can't get its size: {e}"))?,
    };
    let avail = media.checked_sub(o.offset).ok_or("the offset is past its end")?;
    // -s: sectors (FreeBSD's unit) unless a suffix said bytes.
    let total_bytes = match o.total {
        Some(n) if n <= avail / sector => n * sector,
        Some(_) => return Err("-s is larger than the device".into()),
        None => avail,
    };
    let total_sectors = u32::try_from(total_bytes / sector).map_err(|_| "too large for FAT with this sector size")?;
    let spc = match (o.block, o.cluster) {
        (Some(b), _) => b / sector,
        (None, Some(c)) => c,
        (None, None) => 0,
    };
    let label = o.label.as_deref().unwrap_or("");
    let stamp = o.timestamp.unwrap_or_else(now);
    let mut layout = Layout {
        kind: o.fat_type,
        bytes_per_sector: sector as u16,
        sectors_per_cluster: u8::try_from(spc).map_err(|_| "cluster size too large")?,
        reserved_sectors: o.reserved.unwrap_or(0),
        fats: o.fats.unwrap_or(0),
        root_entries: o.root_entries.unwrap_or(0),
        media: o.media.unwrap_or(0xF8),
        hidden_sectors: o.hidden.unwrap_or(0),
        volume_id: o.volume_id.unwrap_or_else(|| (stamp as u32).wrapping_mul(0x9E37_79B9) ^ std::process::id()),
        volume_label: volume_label(label),
        ..Layout::new(total_sectors)
    };
    layout.total_sectors = total_sectors;
    let bpb = Bpb::layout(&layout).map_err(|e| format!("can't lay out a FAT file system of {total_sectors} sectors ({e:?})"))?;
    let kind = bpb.fat_type().map_err(|e| format!("{e:?}"))?;
    let clusters = bpb.clusters().map_err(|e| format!("{e:?}"))?;
    println!(
        "{special}: {} sector{} in {clusters} FAT{} cluster{} ({} bytes/cluster)",
        total_sectors,
        if total_sectors == 1 { "" } else { "s" },
        match kind {
            FatType::Fat12 => 12,
            FatType::Fat16 => 16,
            FatType::Fat32 => 32,
        },
        if clusters == 1 { "" } else { "s" },
        bpb.cluster_bytes()
    );
    println!(
        "BytesPerSec={} SecPerClust={} ResSectors={} FATs={} RootDirEnts={} Media={:#x} FATsecs={} HiddenSecs={} TotalSecs={}",
        bpb.bytes_per_sector, bpb.sectors_per_cluster, bpb.reserved_sectors, bpb.fats, bpb.root_entries, bpb.media, bpb.fat_sectors, bpb.hidden_sectors, bpb.total_sectors
    );
    if o.dry_run {
        return Ok(());
    }
    write(&file, o.offset, &bpb, kind, clusters, label, stamp).map_err(|e| e.to_string())
}

/// Writes the empty file system: the reserved area (boot sector; FAT32's FSInfo and backups),
/// every FAT, and the root directory, zeroed but for the entries a new volume has.
fn write(file: &File, base: u64, bpb: &Bpb, kind: FatType, clusters: u32, label: &str, stamp: i64) -> std::io::Result<()> {
    let bps = bpb.bytes_per_sector as usize;
    let at = |sector: u64| base + sector * bps as u64;
    let zero = vec![0u8; 64 * 1024];
    let zero_run = |from: u64, sectors: u64| -> std::io::Result<()> {
        let (mut off, end) = (at(from), at(from + sectors));
        while off < end {
            let n = (end - off).min(zero.len() as u64) as usize;
            file.write_all_at(&zero[..n], off)?;
            off += n as u64;
        }
        Ok(())
    };
    zero_run(0, bpb.reserved_sectors as u64)?;
    let mut sector = vec![0u8; bps];
    bpb.write_boot_sector(&mut sector).map_err(|e| std::io::Error::other(format!("{e:?}")))?;
    file.write_all_at(&sector, at(0))?;
    if kind == FatType::Fat32 {
        file.write_all_at(&sector, at(bpb.backup_boot_sector as u64))?;
        let mut info = vec![0u8; bps];
        // The root directory has cluster 2; the next free one is 3.
        write_fsinfo(&mut info, clusters - 1, 3);
        file.write_all_at(&info, at(bpb.fsinfo_sector as u64))?;
        file.write_all_at(&info, at(bpb.backup_boot_sector as u64 + bpb.fsinfo_sector as u64))?;
    }
    // Each FAT: entries 0 and 1 (clean), and on FAT32 the root's one-cluster chain.
    let mut head = vec![0u8; bps];
    fat::set(kind, 0, &mut head[fat::entry_offset(kind, 0)..], fat::entry0(kind, bpb.media));
    fat::set(kind, 1, &mut head[fat::entry_offset(kind, 1)..], kind.eoc());
    if kind == FatType::Fat32 {
        fat::set(kind, 2, &mut head[fat::entry_offset(kind, 2)..], kind.eoc());
    }
    for copy in 0..bpb.fats as u64 {
        let start = bpb.fat_start() as u64 + copy * bpb.fat_sectors as u64;
        zero_run(start, bpb.fat_sectors as u64)?;
        file.write_all_at(&head, at(start))?;
    }
    // The root directory: the fixed area, or FAT32's cluster 2.
    let (root, root_sectors) = if kind == FatType::Fat32 {
        (bpb.cluster_sector(bpb.root_cluster) as u64, bpb.sectors_per_cluster as u64)
    } else {
        ((bpb.fat_start() + bpb.fats as u32 * bpb.fat_sectors) as u64, bpb.root_dir_sectors() as u64)
    };
    zero_run(root, root_sectors)?;
    if !label.is_empty() {
        let mut e = [0u8; DIR_ENTRY_SIZE];
        let t = DosTime::from_unix(stamp);
        DirEntry { name: bpb.volume_label, attr: ATTR_VOLUME_ID, modified: t, ..DirEntry::default() }.write(&mut e);
        file.write_all_at(&e, at(root))?;
    }
    file.sync_all()
}
