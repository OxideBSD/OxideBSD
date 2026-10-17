//! `makefs -t msdos`: a FAT image from the tree (OxideBSD-doc `RAM_FLOOR.md` §4.4.4), for the
//! EFI system partition and msdosfs's test volumes. The format is `lib/libmsdosfs`'s.
//!
//! Everything is laid out before anything is written: the root directory (FAT32: in cluster 2;
//! FAT12 and FAT16: in its fixed area after the FATs), then every directory and file in path
//! order, each in one contiguous run of clusters. Names that
//! aren't 8.3 get long-name entries and a short alias with a numeric tail. FAT keeps no owners,
//! modes or links: a file without its owner's write bit is read-only, a hard link becomes a copy,
//! and symbolic links and FIFOs are refused.
//!
//! Options (`-o`, FreeBSD's names): `fat_type=12|16|32` (32 by default), `volume_label=`,
//! `volume_id=` (default: derived from the label and the time, so an image is reproducible),
//! `sectors_per_cluster=`.

use crate::{Body, Node, Tree, show};
use msdosfs_format::{
    ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_READ_ONLY, ATTR_VOLUME_ID, Bpb, DIR_ENTRY_SIZE, DirEntry, DosTime, FIRST_CLUSTER, FatType, LFN_MAX,
    Layout, ShortName, fat, lfn_entries, long_name_char, short_name_checksum, short_name_for, with_numeric_tail, write_fsinfo,
    write_lfn_entry,
};
use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;

const SECTOR: u64 = 512;

#[derive(Default)]
pub struct Options {
    pub fat_type: Option<u32>,
    pub volume_label: String,
    pub volume_id: Option<u32>,
    pub sectors_per_cluster: u8,
}

impl Options {
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let num = |v: &str| -> Result<u32, String> {
            match v.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => v.parse(),
            }
            .map_err(|_| format!("bad {key}={v}"))
        };
        match key {
            "fat_type" => self.fat_type = Some(num(value)?),
            "volume_label" => self.volume_label = value.to_string(),
            "volume_id" => self.volume_id = Some(num(value)?),
            "sectors_per_cluster" => self.sectors_per_cluster = u8::try_from(num(value)?).map_err(|_| format!("bad {key}={value}"))?,
            _ => return Err(format!("unknown msdos option {key}")),
        }
        Ok(())
    }
}

/// One name in a directory, as it goes on disk.
struct Name {
    short: [u8; 11],
    nt_case: u8,
    /// The long name's UTF-16 units, if it needs one.
    long: Option<Vec<u16>>,
}

impl Name {
    fn slots(&self) -> usize {
        1 + self.long.as_ref().map_or(0, |l| lfn_entries(l.len()))
    }
}

/// A directory or file's place in the image.
struct Placed<'a> {
    path: &'a [u8],
    node: &'a Node,
    /// Its first cluster (0: an empty file) and how many.
    cluster: u32,
    clusters: u32,
    size: u64,
}

/// The names in each directory, short aliases chosen; long names are checked here.
fn name_directories(tree: &Tree) -> Result<BTreeMap<&[u8], Vec<(&[u8], Name)>>, String> {
    let mut dirs: BTreeMap<&[u8], Vec<(&[u8], Name)>> = BTreeMap::new();
    let mut used: BTreeMap<&[u8], (HashSet<[u8; 11]>, HashSet<String>)> = BTreeMap::new();
    for (path, node) in tree {
        if matches!(node.body, Body::Dir) {
            dirs.entry(path).or_default();
        }
        if path.is_empty() {
            continue;
        }
        match node.body {
            Body::Link(_) => return Err(format!("{}: FAT has no symbolic links", show(path))),
            Body::Fifo => return Err(format!("{}: FAT has no FIFOs", show(path))),
            _ => {}
        }
        let split = path.iter().rposition(|&b| b == b'/');
        let (parent, leaf) = match split {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => (&path[..0], &path[..]),
        };
        let leaf_str = std::str::from_utf8(leaf).map_err(|_| format!("{}: a FAT name must be UTF-8", show(path)))?;
        if !leaf_str.chars().all(long_name_char) || leaf_str.ends_with(['.', ' ']) {
            return Err(format!("{}: not a valid FAT name", show(path)));
        }
        let units: Vec<u16> = leaf_str.encode_utf16().collect();
        if units.len() > LFN_MAX {
            return Err(format!("{}: longer than 255 characters", show(path)));
        }
        let (shorts, longs) = used.entry(parent).or_default();
        // FAT names are unique whatever their case.
        if !longs.insert(leaf_str.to_uppercase()) {
            return Err(format!("{}: differs from another name only in case", show(path)));
        }
        let name = match short_name_for(leaf_str) {
            ShortName::Exact { name, nt_case } if !shorts.contains(&name) => Name { short: name, nt_case, long: None },
            ShortName::Exact { name: basis, .. } | ShortName::Basis { name: basis, .. } => {
                let lossy = !matches!(short_name_for(leaf_str), ShortName::Basis { lossy: false, .. });
                let short = if !lossy && !shorts.contains(&basis) {
                    basis
                } else {
                    (1..)
                        .map(|n| with_numeric_tail(&basis, n))
                        .find(|s| !shorts.contains(s))
                        .unwrap()
                };
                Name { short, nt_case: 0, long: Some(units) }
            }
        };
        shorts.insert(name.short);
        dirs.get_mut(parent).ok_or(format!("{}: its directory isn't in the image", show(path)))?.push((path, name));
    }
    Ok(dirs)
}

/// Directory entries a directory needs: its names, `.` and `..` (not in the root), and the
/// volume label (only in the root).
fn dir_slots(path: &[u8], names: &[(&[u8], Name)], label: bool) -> usize {
    let own = if path.is_empty() { usize::from(label) } else { 2 };
    own + names.iter().map(|(_, n)| n.slots()).sum::<usize>()
}

fn file_size(node: &Node) -> Result<u64, String> {
    match &node.body {
        Body::File(host) => std::fs::metadata(host).map(|m| m.len()).map_err(|e| format!("{}: {e}", host.display())),
        _ => Ok(0),
    }
}

/// A volume id from the label and the time (FNV-1a), for repeatable images.
fn derived_volume_id(label: &str, time: i64) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for b in label.bytes().chain(time.to_le_bytes()) {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    h
}

pub fn build(image: &Path, tree: &Tree, size: Option<u64>, opts: &Options, timestamp: Option<i64>) -> Result<(u64, usize), String> {
    let kind = match opts.fat_type.unwrap_or(32) {
        12 => FatType::Fat12,
        16 => FatType::Fat16,
        32 => FatType::Fat32,
        t => return Err(format!("fat_type={t}: not 12, 16 or 32")),
    };
    let time = |n: &Node| timestamp.unwrap_or(n.time);
    let root_time = time(&tree[&b""[..]]);
    let label = msdosfs_format::volume_label(&opts.volume_label);
    let has_label = !opts.volume_label.is_empty();
    let volume_id = opts.volume_id.unwrap_or_else(|| derived_volume_id(&opts.volume_label, root_time));
    let dirs = name_directories(tree)?;

    // Bytes each directory and file needs, in path order.
    let mut needs: Vec<(&[u8], &Node, u64)> = Vec::new();
    for (path, node) in tree {
        let bytes = match node.body {
            Body::Dir => (dir_slots(path, &dirs[&path[..]], has_label) * DIR_ENTRY_SIZE) as u64,
            _ => file_size(node)?,
        };
        if bytes > u32::MAX as u64 {
            return Err(format!("{}: FAT files are under 4 GiB", show(path)));
        }
        needs.push((path, node, bytes));
    }
    // FAT12 and FAT16 keep the root in a fixed area of at least 512 entries (a whole sector's).
    let root_slots = dir_slots(b"", &dirs[&b""[..]], has_label);
    let fixed_root = kind != FatType::Fat32;
    let root_entries = if fixed_root { (root_slots.max(512).div_ceil(16) * 16).min(0xFFF0) as u16 } else { 0 };
    if fixed_root && root_slots > root_entries as usize {
        return Err("too many names in the root directory for FAT12/16".into());
    }
    let make = |sectors: u32| -> Result<Bpb, String> {
        if kind == FatType::Fat32 {
            return Bpb::fat32(sectors, opts.sectors_per_cluster, volume_id, label).map_err(|e| format!("{e:?}"));
        }
        let l = Layout { kind: Some(kind), sectors_per_cluster: opts.sectors_per_cluster, root_entries, volume_id, volume_label: label, ..Layout::new(sectors) };
        Bpb::layout(&l).map_err(|e| format!("{e:?}"))
    };
    let in_clusters = |p: &[u8]| !(fixed_root && p.is_empty());

    // The volume: as given, or the smallest of the type that holds everything with a twentieth
    // spare.
    let bpb = match size {
        Some(bytes) => {
            let sectors = u32::try_from(bytes / SECTOR).map_err(|_| "too large for FAT with 512-byte sectors")?;
            make(sectors).map_err(|e| format!("{bytes} bytes can't be FAT{} ({e})", opts.fat_type.unwrap_or(32)))?
        }
        None => {
            let mut sectors: u32 = match kind {
                FatType::Fat12 => 64,
                FatType::Fat16 => 8400,
                FatType::Fat32 => 66_600 + 32 + 2 * 520,
            };
            loop {
                if let Ok(b) = make(sectors) {
                    let cb = b.cluster_bytes() as u64;
                    let used: u64 = needs
                        .iter()
                        .filter(|(p, ..)| in_clusters(p))
                        .map(|(_, n, bytes)| bytes.div_ceil(cb).max(u64::from(matches!(n.body, Body::Dir))))
                        .sum();
                    if used + used / 20 + 16 <= b.clusters().unwrap() as u64 {
                        break b;
                    }
                }
                sectors = sectors.checked_add(sectors / 8).ok_or("too large for FAT")?;
            }
        }
    };
    let cb = bpb.cluster_bytes() as u64;
    let total_clusters = bpb.clusters().map_err(|e| format!("{e:?}"))?;

    // Clusters, in path order from cluster 2 (the FAT32 root comes first).
    let mut placed: Vec<Placed> = Vec::new();
    let mut next = FIRST_CLUSTER;
    for (path, node, bytes) in needs {
        if !in_clusters(path) {
            placed.push(Placed { path, node, cluster: 0, clusters: 0, size: bytes });
            continue;
        }
        let clusters = bytes.div_ceil(cb).max(u64::from(matches!(node.body, Body::Dir))) as u32;
        let cluster = if clusters == 0 { 0 } else { next };
        next = next.checked_add(clusters).ok_or("the image is full (-s)")?;
        if next - FIRST_CLUSTER > total_clusters {
            return Err("the image is full (-s)".into());
        }
        placed.push(Placed { path, node, cluster, clusters, size: bytes });
    }
    let first_of: BTreeMap<&[u8], u32> = placed.iter().map(|p| (p.path, p.cluster)).collect();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(image)
        .map_err(|e| format!("{}: {e}", image.display()))?;
    let total_bytes = bpb.total_sectors as u64 * SECTOR;
    file.set_len(total_bytes).map_err(|e| format!("{}: {e}", image.display()))?;
    let io = |e: std::io::Error| format!("{}: {e}", image.display());

    // Boot sector, and on FAT32 FSInfo and their backups.
    let mut sector = [0u8; 512];
    let used_clusters = next - FIRST_CLUSTER;
    let bases: &[u64] = if kind == FatType::Fat32 { &[0, bpb.backup_boot_sector as u64] } else { &[0] };
    for &base in bases {
        bpb.write_boot_sector(&mut sector).map_err(|e| format!("{e:?}"))?;
        file.write_all_at(&sector, base * SECTOR).map_err(io)?;
        if kind == FatType::Fat32 {
            write_fsinfo(&mut sector, total_clusters - used_clusters, next);
            file.write_all_at(&sector, (base + bpb.fsinfo_sector as u64) * SECTOR).map_err(io)?;
        }
    }

    // The FAT, every copy the same: each run chained, its last cluster the end. Entry 1 is an
    // end of chain with the clean bit set.
    let mut fat_bytes = vec![0u8; bpb.fat_sectors as usize * SECTOR as usize];
    let mut put = |c: u32, v: u32| fat::set(kind, c, &mut fat_bytes[fat::entry_offset(kind, c)..], v);
    put(0, fat::entry0(kind, bpb.media));
    put(1, kind.eoc());
    for p in &placed {
        for i in 0..p.clusters {
            let c = p.cluster + i;
            put(c, if i + 1 == p.clusters { kind.eoc() } else { c + 1 });
        }
    }
    for copy in 0..bpb.fats as u64 {
        file.write_all_at(&fat_bytes, (bpb.fat_start() as u64 + copy * bpb.fat_sectors as u64) * SECTOR).map_err(io)?;
    }

    // Directories and files.
    let entry = |name: [u8; 11], attr: u8, nt_case: u8, t: i64, cluster: u32, size: u32| DirEntry {
        name,
        attr,
        nt_case,
        created: DosTime::from_unix(t),
        accessed_date: DosTime::from_unix(t).date,
        modified: DosTime::from_unix(t),
        cluster,
        size,
    };
    let mut buf = vec![0u8; 1 << 20];
    let root_at = (bpb.fat_start() + bpb.fats as u32 * bpb.fat_sectors) as u64 * SECTOR;
    for p in &placed {
        let at = if in_clusters(p.path) { bpb.cluster_sector(p.cluster.max(FIRST_CLUSTER)) as u64 * SECTOR } else { root_at };
        match &p.node.body {
            Body::Dir => {
                let room = if in_clusters(p.path) { p.clusters as u64 * cb } else { bpb.root_dir_sectors() as u64 * SECTOR };
                let mut data = vec![0u8; room as usize];
                let mut slot = 0;
                let put = |e: &DirEntry, data: &mut [u8], slot: &mut usize| {
                    e.write(&mut data[*slot * DIR_ENTRY_SIZE..]);
                    *slot += 1;
                };
                let t = time(p.node);
                if p.path.is_empty() {
                    if has_label {
                        put(&entry(label, ATTR_VOLUME_ID, 0, t, 0, 0), &mut data, &mut slot);
                    }
                } else {
                    let parent = p.path.iter().rposition(|&b| b == b'/').map_or(&p.path[..0], |i| &p.path[..i]);
                    // `..` names the root as cluster 0.
                    let up = if parent.is_empty() { 0 } else { first_of[parent] };
                    put(&entry(*b".          ", ATTR_DIRECTORY, 0, t, p.cluster, 0), &mut data, &mut slot);
                    put(&entry(*b"..         ", ATTR_DIRECTORY, 0, time(&tree[parent]), up, 0), &mut data, &mut slot);
                }
                for (child, name) in &dirs[p.path] {
                    let node = &tree[*child];
                    if let Some(long) = &name.long {
                        let sum = short_name_checksum(&name.short);
                        for i in (0..lfn_entries(long.len())).rev() {
                            write_lfn_entry(&mut data[slot * DIR_ENTRY_SIZE..], long, i, sum);
                            slot += 1;
                        }
                    }
                    let (attr, size) = match node.body {
                        Body::Dir => (ATTR_DIRECTORY, 0),
                        _ => (ATTR_ARCHIVE, file_size(node)? as u32),
                    };
                    let ro = if node.mode & 0o200 == 0 { ATTR_READ_ONLY } else { 0 };
                    put(&entry(name.short, attr | ro, name.nt_case, time(node), first_of[*child], size), &mut data, &mut slot);
                }
                file.write_all_at(&data, at).map_err(io)?;
            }
            Body::File(host) => {
                let mut f = File::open(host).map_err(|e| format!("{}: {e}", host.display()))?;
                let mut off = 0u64;
                while off < p.size {
                    let n = f.read(&mut buf).map_err(|e| format!("{}: {e}", host.display()))?;
                    if n == 0 {
                        return Err(format!("{}: shrank while being read", host.display()));
                    }
                    file.write_all_at(&buf[..n], at + off).map_err(io)?;
                    off += n as u64;
                }
            }
            Body::Link(_) | Body::Fifo => unreachable!(),
        }
    }
    file.sync_all().map_err(io)?;
    Ok((total_bytes, placed.len()))
}
