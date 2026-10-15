//! The FAT file system's on-disk format (FAT12, FAT16 and FAT32, with long names), shared by
//! makefs(8)'s `-t msdos` writer and, later, the kernel's msdosfs, so neither keeps its own copy
//! of a layout or a name rule. Microsoft's "FAT: General Overview of On-Disk Format" (1.03) is
//! the reference; section names below are its.
//!
//! `no_std` and allocation-free; builds for the kernel, the target and the host alike.

#![no_std]

pub const DIR_ENTRY_SIZE: usize = 32;

pub const ATTR_READ_ONLY: u8 = 0x01;
pub const ATTR_HIDDEN: u8 = 0x02;
pub const ATTR_SYSTEM: u8 = 0x04;
pub const ATTR_VOLUME_ID: u8 = 0x08;
pub const ATTR_DIRECTORY: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
/// A long-name entry's attribute byte.
pub const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

/// A directory entry's first byte: the entry is free (`0xE5`), or it and every later one are
/// (`0x00`).
pub const ENTRY_FREE: u8 = 0xE5;
pub const ENTRY_END: u8 = 0x00;

/// FAT32 entries are 28 bits; the top four are reserved and kept.
pub const FAT32_MASK: u32 = 0x0FFF_FFFF;
/// End of a cluster chain (any value from `0x0FFF_FFF8` up reads as one).
pub const FAT32_EOC: u32 = 0x0FFF_FFFF;
pub const FAT32_BAD: u32 = 0x0FFF_FFF7;
/// The first data cluster's number.
pub const FIRST_CLUSTER: u32 = 2;
/// The cluster counts that decide the FAT type (§3.5): fewer than 4085 is FAT12, fewer than
/// 65525 FAT16, anything else FAT32.
pub const FAT12_MAX_CLUSTERS: u32 = 4084;
pub const FAT16_MAX_CLUSTERS: u32 = 65524;
/// The most clusters a FAT32 volume may have.
pub const FAT32_MAX_CLUSTERS: u32 = 0x0FFF_FFF5 - 1;

pub const FSINFO_LEAD_SIG: u32 = 0x4161_5252;
pub const FSINFO_STRUC_SIG: u32 = 0x6141_7272;
pub const FSINFO_TRAIL_SIG: u32 = 0xAA55_0000;
/// FSInfo's "not known" for its free count and next free cluster.
pub const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatType {
    Fat12,
    Fat16,
    Fat32,
}

impl FatType {
    /// The type a volume with `clusters` data clusters is (§3.5): the count alone decides it.
    pub fn for_clusters(clusters: u32) -> FatType {
        if clusters <= FAT12_MAX_CLUSTERS {
            FatType::Fat12
        } else if clusters <= FAT16_MAX_CLUSTERS {
            FatType::Fat16
        } else {
            FatType::Fat32
        }
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// The BIOS parameter block of a boot sector (§3.1-3.3), the fields every FAT type has plus
/// FAT32's extension. On FAT12/16, `root_entries` is the fixed root directory's size; on FAT32
/// it is zero and the root is a cluster chain from `root_cluster`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bpb {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fats: u8,
    pub root_entries: u16,
    pub total_sectors: u32,
    pub media: u8,
    /// Sectors per FAT.
    pub fat_sectors: u32,
    pub sectors_per_track: u16,
    pub heads: u16,
    pub hidden_sectors: u32,
    /// FAT32: the root directory's first cluster, the FSInfo sector and the backup boot sector.
    pub root_cluster: u32,
    pub fsinfo_sector: u16,
    pub backup_boot_sector: u16,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpbError {
    /// No `0x55 0xAA` at the end of the sector.
    Signature,
    /// A field no FAT volume has (a sector size that isn't a power of two from 512 to 4096, no
    /// FATs, a cluster size that isn't a power of two, ...).
    Field(&'static str),
    /// The layout leaves no room for data, or its cluster count and FAT disagree.
    Geometry,
}

impl Bpb {
    /// The FAT32 layout for a volume of `total_sectors` 512-byte sectors (§3.5's algorithm): 32
    /// reserved sectors, two FATs, the root in cluster 2, FSInfo in sector 1 and the backup boot
    /// sector in 6. `sectors_per_cluster` 0 picks the size Microsoft's table gives for the
    /// volume's size. Fails if the volume is too small or too large to be FAT32 with that cluster
    /// size.
    pub fn fat32(total_sectors: u32, sectors_per_cluster: u8, volume_id: u32, volume_label: [u8; 11]) -> Result<Bpb, BpbError> {
        let spc = match sectors_per_cluster {
            0 => match total_sectors {
                ..=532_480 => 1,
                ..=16_777_216 => 8,
                ..=33_554_432 => 16,
                ..=67_108_864 => 32,
                _ => 64,
            },
            n if n.is_power_of_two() => n,
            _ => return Err(BpbError::Field("sectors per cluster")),
        };
        let reserved = 32u32;
        let fats = 2u32;
        // §3.5: the FAT size, which errs slightly large.
        let tmp1 = total_sectors.checked_sub(reserved).ok_or(BpbError::Geometry)?;
        let tmp2 = (256 * spc as u32 + fats) / 2;
        let fat_sectors = tmp1.div_ceil(tmp2);
        let bpb = Bpb {
            bytes_per_sector: 512,
            sectors_per_cluster: spc,
            reserved_sectors: reserved as u16,
            fats: fats as u8,
            root_entries: 0,
            total_sectors,
            media: 0xF8,
            fat_sectors,
            sectors_per_track: 63,
            heads: 255,
            hidden_sectors: 0,
            root_cluster: FIRST_CLUSTER,
            fsinfo_sector: 1,
            backup_boot_sector: 6,
            volume_id,
            volume_label,
        };
        if bpb.fat_type()? != FatType::Fat32 {
            return Err(BpbError::Geometry);
        }
        Ok(bpb)
    }

    /// Sectors of the fixed FAT12/16 root directory (zero on FAT32).
    pub fn root_dir_sectors(&self) -> u32 {
        (self.root_entries as u32 * DIR_ENTRY_SIZE as u32).div_ceil(self.bytes_per_sector as u32)
    }

    /// The first FAT's first sector.
    pub fn fat_start(&self) -> u32 {
        self.reserved_sectors as u32
    }

    /// The first data sector: cluster 2's.
    pub fn data_start(&self) -> u32 {
        self.reserved_sectors as u32 + self.fats as u32 * self.fat_sectors + self.root_dir_sectors()
    }

    /// Data clusters, numbered from `FIRST_CLUSTER`.
    pub fn clusters(&self) -> Result<u32, BpbError> {
        let data = self.total_sectors.checked_sub(self.data_start()).ok_or(BpbError::Geometry)?;
        Ok(data / self.sectors_per_cluster as u32)
    }

    pub fn fat_type(&self) -> Result<FatType, BpbError> {
        let clusters = self.clusters()?;
        let kind = FatType::for_clusters(clusters);
        // The FAT must hold an entry for every cluster, and FAT32 has a ceiling.
        let entries = clusters as u64 + 2;
        let fat_bytes = self.fat_sectors as u64 * self.bytes_per_sector as u64;
        let need = match kind {
            FatType::Fat12 => (entries * 3).div_ceil(2),
            FatType::Fat16 => entries * 2,
            FatType::Fat32 => entries * 4,
        };
        if clusters == 0 || need > fat_bytes || (kind == FatType::Fat32 && clusters > FAT32_MAX_CLUSTERS) {
            return Err(BpbError::Geometry);
        }
        Ok(kind)
    }

    /// The first sector of data cluster `cluster`.
    pub fn cluster_sector(&self, cluster: u32) -> u32 {
        self.data_start() + (cluster - FIRST_CLUSTER) * self.sectors_per_cluster as u32
    }

    pub fn cluster_bytes(&self) -> u32 {
        self.sectors_per_cluster as u32 * self.bytes_per_sector as u32
    }

    /// Writes this BPB as a boot sector into `sector` (512 bytes or more): a jump over the BPB to
    /// a `hlt` loop (the volume isn't bootable by its boot sector), the extended boot signature,
    /// and the `0x55 0xAA` signature.
    pub fn write_boot_sector(&self, sector: &mut [u8]) -> Result<(), BpbError> {
        let kind = self.fat_type()?;
        sector[..512].fill(0);
        sector[0..3].copy_from_slice(&[0xEB, if kind == FatType::Fat32 { 0x58 } else { 0x3C }, 0x90]);
        sector[3..11].copy_from_slice(b"OXIDEBSD");
        put16(sector, 11, self.bytes_per_sector);
        sector[13] = self.sectors_per_cluster;
        put16(sector, 14, self.reserved_sectors);
        sector[16] = self.fats;
        put16(sector, 17, self.root_entries);
        if self.total_sectors < 0x1_0000 && kind != FatType::Fat32 {
            put16(sector, 19, self.total_sectors as u16);
        } else {
            put32(sector, 32, self.total_sectors);
        }
        sector[21] = self.media;
        put16(sector, 24, self.sectors_per_track);
        put16(sector, 26, self.heads);
        put32(sector, 28, self.hidden_sectors);
        let ext = if kind == FatType::Fat32 {
            put32(sector, 36, self.fat_sectors);
            put32(sector, 44, self.root_cluster);
            put16(sector, 48, self.fsinfo_sector);
            put16(sector, 50, self.backup_boot_sector);
            64
        } else {
            put16(sector, 22, self.fat_sectors as u16);
            36
        };
        sector[ext] = 0x80;
        sector[ext + 2] = 0x29;
        put32(sector, ext + 3, self.volume_id);
        sector[ext + 7..ext + 18].copy_from_slice(&self.volume_label);
        sector[ext + 18..ext + 26].copy_from_slice(match kind {
            FatType::Fat12 => b"FAT12   ",
            FatType::Fat16 => b"FAT16   ",
            FatType::Fat32 => b"FAT32   ",
        });
        // Where the jump lands: `cli; hlt; jmp $-1`.
        let code = ext + 26;
        sector[code..code + 4].copy_from_slice(&[0xFA, 0xF4, 0xEB, 0xFD]);
        sector[510] = 0x55;
        sector[511] = 0xAA;
        Ok(())
    }

    /// Reads a boot sector's BPB, checking what every FAT volume has.
    pub fn read_boot_sector(sector: &[u8]) -> Result<Bpb, BpbError> {
        if sector.len() < 512 || sector[510] != 0x55 || sector[511] != 0xAA {
            return Err(BpbError::Signature);
        }
        let bytes_per_sector = le16(sector, 11);
        if !bytes_per_sector.is_power_of_two() || !(512..=4096).contains(&bytes_per_sector) {
            return Err(BpbError::Field("bytes per sector"));
        }
        let sectors_per_cluster = sector[13];
        if !sectors_per_cluster.is_power_of_two() {
            return Err(BpbError::Field("sectors per cluster"));
        }
        let reserved_sectors = le16(sector, 14);
        let fats = sector[16];
        if reserved_sectors == 0 || fats == 0 {
            return Err(BpbError::Field("reserved sectors or FAT count"));
        }
        let root_entries = le16(sector, 17);
        let total_sectors = match le16(sector, 19) {
            0 => le32(sector, 32),
            n => n as u32,
        };
        let fat16_sectors = le16(sector, 22);
        let fat32 = fat16_sectors == 0;
        let ext = if fat32 { 64 } else { 36 };
        let mut volume_label = [b' '; 11];
        let has_ext = sector[ext + 2] == 0x29;
        if has_ext {
            volume_label.copy_from_slice(&sector[ext + 7..ext + 18]);
        }
        let bpb = Bpb {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            fats,
            root_entries,
            total_sectors,
            media: sector[21],
            fat_sectors: if fat32 { le32(sector, 36) } else { fat16_sectors as u32 },
            sectors_per_track: le16(sector, 24),
            heads: le16(sector, 26),
            hidden_sectors: le32(sector, 28),
            root_cluster: if fat32 { le32(sector, 44) } else { 0 },
            fsinfo_sector: if fat32 { le16(sector, 48) } else { 0 },
            backup_boot_sector: if fat32 { le16(sector, 50) } else { 0 },
            volume_id: if has_ext { le32(sector, ext + 3) } else { 0 },
            volume_label,
        };
        if bpb.fat_sectors == 0 {
            return Err(BpbError::Field("sectors per FAT"));
        }
        // The two ways of telling FAT32 apart must agree.
        if (bpb.fat_type()? == FatType::Fat32) != fat32 || (fat32 && root_entries != 0) {
            return Err(BpbError::Geometry);
        }
        Ok(bpb)
    }
}

/// Writes a FAT32 FSInfo sector (§5) into `sector`.
pub fn write_fsinfo(sector: &mut [u8], free_clusters: u32, next_free: u32) {
    sector[..512].fill(0);
    put32(sector, 0, FSINFO_LEAD_SIG);
    put32(sector, 484, FSINFO_STRUC_SIG);
    put32(sector, 488, free_clusters);
    put32(sector, 492, next_free);
    put32(sector, 508, FSINFO_TRAIL_SIG);
}

/// A FAT date and time (§6.1): `date` is day, month and years since 1980; `time` is two-second
/// units, minutes and hours. Times before 1980 clamp to 1980-01-01, after 2107 to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DosTime {
    pub date: u16,
    pub time: u16,
}

impl DosTime {
    /// From seconds since the epoch, UTC (the FAT has no time zone).
    pub fn from_unix(secs: i64) -> DosTime {
        const MIN: i64 = 315_532_800; // 1980-01-01
        const MAX: i64 = 4_354_819_199; // 2107-12-31 23:59:59
        let secs = secs.clamp(MIN, MAX);
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        // Howard Hinnant's days-to-civil.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
        DosTime {
            date: (((year - 1980) << 9) | (month << 5) | day) as u16,
            time: (((rem / 3600) << 11) | ((rem / 60 % 60) << 5) | (rem % 60 / 2)) as u16,
        }
    }

    /// Back to seconds since the epoch, UTC.
    pub fn to_unix(self) -> i64 {
        let year = 1980 + (self.date >> 9) as i64;
        let month = ((self.date >> 5) & 0x0F).clamp(1, 12) as i64;
        let day = (self.date & 0x1F).max(1) as i64;
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = if month > 2 { month - 3 } else { month + 9 };
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468;
        days * 86_400 + (self.time >> 11) as i64 * 3600 + ((self.time >> 5) & 0x3F) as i64 * 60 + (self.time & 0x1F) as i64 * 2
    }
}

/// A short (8.3) directory entry (§6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DirEntry {
    /// The name, space-padded: eight bytes of base, three of extension.
    pub name: [u8; 11],
    pub attr: u8,
    /// Windows NT's case flags (byte 12): `0x08` the base, `0x10` the extension, is lower case.
    pub nt_case: u8,
    pub created: DosTime,
    pub accessed_date: u16,
    pub modified: DosTime,
    pub cluster: u32,
    pub size: u32,
}

impl DirEntry {
    pub fn write(&self, b: &mut [u8]) {
        b[..DIR_ENTRY_SIZE].fill(0);
        b[0..11].copy_from_slice(&self.name);
        b[11] = self.attr;
        b[12] = self.nt_case;
        put16(b, 14, self.created.time);
        put16(b, 16, self.created.date);
        put16(b, 18, self.accessed_date);
        put16(b, 20, (self.cluster >> 16) as u16);
        put16(b, 22, self.modified.time);
        put16(b, 24, self.modified.date);
        put16(b, 26, self.cluster as u16);
        put32(b, 28, self.size);
    }

    pub fn read(b: &[u8]) -> DirEntry {
        let mut name = [0u8; 11];
        name.copy_from_slice(&b[0..11]);
        DirEntry {
            name,
            attr: b[11],
            nt_case: b[12],
            created: DosTime { time: le16(b, 14), date: le16(b, 16) },
            accessed_date: le16(b, 18),
            modified: DosTime { time: le16(b, 22), date: le16(b, 24) },
            cluster: (le16(b, 20) as u32) << 16 | le16(b, 26) as u32,
            size: le32(b, 28),
        }
    }

    pub fn is_long_name(b: &[u8]) -> bool {
        b[11] & 0x3F == ATTR_LONG_NAME
    }
}

/// The checksum of a short name that its long-name entries carry (§7.2).
pub fn short_name_checksum(name: &[u8; 11]) -> u8 {
    name.iter().fold(0u8, |sum, &b| (sum >> 1 | sum << 7).wrapping_add(b))
}

/// UTF-16 units one long-name entry holds.
pub const LFN_CHARS: usize = 13;
/// The most UTF-16 units a long name may have.
pub const LFN_MAX: usize = 255;
/// Byte offsets of a long-name entry's 13 characters.
const LFN_OFFSETS: [usize; LFN_CHARS] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

/// How many long-name entries a name of `units` UTF-16 units takes.
pub fn lfn_entries(units: usize) -> usize {
    units.div_ceil(LFN_CHARS)
}

/// Writes long-name entry `index` (0 is the name's first 13 units) of `name` into `b`: entries
/// go on disk last index first, each with `checksum` of the short entry after them; the last one
/// carries `0x40`. Past the name's end comes one `0x0000` and then `0xFFFF` padding.
pub fn write_lfn_entry(b: &mut [u8], name: &[u16], index: usize, checksum: u8) {
    b[..DIR_ENTRY_SIZE].fill(0);
    let last = index + 1 == lfn_entries(name.len());
    b[0] = (index as u8 + 1) | if last { 0x40 } else { 0 };
    b[11] = ATTR_LONG_NAME;
    b[13] = checksum;
    for (i, &off) in LFN_OFFSETS.iter().enumerate() {
        let at = index * LFN_CHARS + i;
        let unit = match at.cmp(&name.len()) {
            core::cmp::Ordering::Less => name[at],
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 0xFFFF,
        };
        put16(b, off, unit);
    }
}

/// Reads long-name entry `b`'s sequence number (1-based, without `0x40`), whether it's the last,
/// its checksum, and its 13 units into `out`.
pub fn read_lfn_entry(b: &[u8], out: &mut [u16; LFN_CHARS]) -> (u8, bool, u8) {
    for (i, &off) in LFN_OFFSETS.iter().enumerate() {
        out[i] = le16(b, off);
    }
    (b[0] & 0x1F, b[0] & 0x40 != 0, b[13])
}

/// Whether `c` may appear in a short name as it is (§6.1): upper-case letters, digits, and
/// `$ % ' - _ @ ~ ` ! ( ) { } ^ # &`.
pub fn short_name_char(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || b"$%'-_@~`!(){}^#&".contains(&c)
}

/// Whether `c` may appear in a long name: anything but control characters and `" * / : < > ? \ |`.
pub fn long_name_char(c: char) -> bool {
    !(c < ' ' || "\"*/:<>?\\|".contains(c))
}

/// What a name needs on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortName {
    /// The name is an 8.3 name, possibly in lower case (the NT case flags say which part): no
    /// long name.
    Exact { name: [u8; 11], nt_case: u8 },
    /// A long name is needed, with this short basis (§7.4's steps 1-6) for a numeric tail;
    /// `lossy` if characters were dropped or replaced, so the tail is needed even if the basis
    /// is free.
    Basis { name: [u8; 11], lossy: bool },
}

/// The short name for long name `name` (§7.4), before any numeric tail. `name` is UTF-8 and
/// valid as a long name.
pub fn short_name_for(name: &str) -> ShortName {
    let mut out = [b' '; 11];
    // An exact 8.3 name: one optional dot, base 1-8 and extension 0-3 valid characters, each part
    // all lower or all upper case.
    let (base, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i + 1..]),
        _ => (name, ""),
    };
    let part_case = |s: &str| -> Option<bool> {
        let mut lower = None;
        for c in s.bytes() {
            let lc = c.is_ascii_lowercase();
            if !(short_name_char(c.to_ascii_uppercase())) {
                return None;
            }
            if c.is_ascii_alphabetic() {
                match lower {
                    None => lower = Some(lc),
                    Some(l) if l != lc => return None,
                    _ => {}
                }
            }
        }
        Some(lower.unwrap_or(false))
    };
    let dot_ok = name.bytes().filter(|&c| c == b'.').count() <= 1 && !name.ends_with('.');
    if dot_ok && (1..=8).contains(&base.len()) && ext.len() <= 3 && name != "." && name != ".." {
        if let (Some(bl), Some(el)) = (part_case(base), part_case(ext)) {
            for (i, c) in base.bytes().enumerate() {
                out[i] = c.to_ascii_uppercase();
            }
            for (i, c) in ext.bytes().enumerate() {
                out[8 + i] = c.to_ascii_uppercase();
            }
            return ShortName::Exact { name: out, nt_case: if bl { 0x08 } else { 0 } | if el { 0x10 } else { 0 } };
        }
    }
    // §7.4: upper-case; drop spaces and leading periods; invalid characters become `_`; the base
    // is up to 8 characters before the last period, the extension up to 3 after it.
    let mut lossy = false;
    let trimmed = name.trim_start_matches('.');
    lossy |= trimmed.len() != name.len();
    let last_dot = trimmed.rfind('.');
    let (base, ext) = match last_dot {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (trimmed, ""),
    };
    let fill = |src: &str, out: &mut [u8]| -> bool {
        let mut n = 0;
        let mut dropped = false;
        for c in src.chars() {
            if c == ' ' || c == '.' {
                dropped = true;
                continue;
            }
            let b = if c.is_ascii() && short_name_char((c as u8).to_ascii_uppercase()) { (c as u8).to_ascii_uppercase() } else { b'_' };
            if b == b'_' && c != '_' {
                dropped = true;
            }
            if n == out.len() {
                return true;
            }
            out[n] = b;
            n += 1;
        }
        dropped
    };
    lossy |= fill(base, &mut out[..8]);
    lossy |= fill(ext, &mut out[8..]);
    if out[0] == b' ' {
        out[0] = b'_';
        lossy = true;
    }
    ShortName::Basis { name: out, lossy }
}

/// `basis` with numeric tail `~n` (§7.4 step 7): the base is cut so that the tail fits in its
/// eight characters.
pub fn with_numeric_tail(basis: &[u8; 11], n: u32) -> [u8; 11] {
    let mut digits = [0u8; 10];
    let mut len = 0;
    let mut v = n;
    loop {
        digits[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let tail = len + 1;
    let base_len = basis[..8].iter().position(|&c| c == b' ').unwrap_or(8).min(8 - tail);
    let mut out = *basis;
    out[base_len] = b'~';
    for i in 0..len {
        out[base_len + 1 + i] = digits[len - 1 - i];
    }
    for c in &mut out[base_len + tail..8] {
        *c = b' ';
    }
    out
}

/// A volume label from `label` (§3.1's `BS_VolLab`): upper-cased, space-padded, invalid
/// characters as `_`, `NO NAME` when empty.
pub fn volume_label(label: &str) -> [u8; 11] {
    let mut out = *b"NO NAME    ";
    if !label.is_empty() {
        out = [b' '; 11];
        for (i, c) in label.chars().take(11).enumerate() {
            out[i] = if c.is_ascii() && (c == ' ' || short_name_char((c as u8).to_ascii_uppercase())) { (c as u8).to_ascii_uppercase() } else { b'_' };
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat32_64m() {
        let bpb = Bpb::fat32(131_072, 0, 0x1234_5678, volume_label("EFI")).unwrap();
        assert_eq!(bpb.sectors_per_cluster, 1);
        assert_eq!(bpb.fat_type().unwrap(), FatType::Fat32);
        let mut s = [0u8; 512];
        bpb.write_boot_sector(&mut s).unwrap();
        assert_eq!(Bpb::read_boot_sector(&s).unwrap(), bpb);
    }

    #[test]
    fn too_small_for_fat32() {
        assert_eq!(Bpb::fat32(40_000, 1, 0, volume_label("")), Err(BpbError::Geometry));
    }

    #[test]
    fn dos_time_round_trip() {
        let t = 1_760_000_000; // 2025-10-09 08:53:20 UTC
        let d = DosTime::from_unix(t);
        assert_eq!(d.date >> 9, 2025 - 1980);
        assert_eq!((d.date >> 5) & 0xF, 10);
        assert_eq!(d.date & 0x1F, 9);
        assert_eq!(d.to_unix(), t);
        assert_eq!(DosTime::from_unix(0).to_unix(), 315_532_800);
    }

    #[test]
    fn names() {
        assert_eq!(short_name_for("BOOTX64.EFI"), ShortName::Exact { name: *b"BOOTX64 EFI", nt_case: 0 });
        assert_eq!(short_name_for("kernel"), ShortName::Exact { name: *b"KERNEL     ", nt_case: 0x08 });
        assert_eq!(short_name_for("limine.conf"), ShortName::Basis { name: *b"LIMINE  CON", lossy: true });
        assert!(matches!(short_name_for("limine-bios.sys"), ShortName::Basis { name, lossy: true } if &name == b"LIMINE-BSYS"));
        assert!(matches!(short_name_for("Mixed.txt"), ShortName::Basis { lossy: false, .. }));
        assert_eq!(&with_numeric_tail(b"LIMINE  CON", 1), b"LIMINE~1CON");
        assert_eq!(&with_numeric_tail(b"LIMINE-BSYS", 12), b"LIMIN~12SYS");
    }

    #[test]
    fn checksum_and_lfn() {
        let name: [u16; 11] = core::array::from_fn(|i| "limine.conf".as_bytes()[i] as u16);
        let mut e = [0u8; 32];
        write_lfn_entry(&mut e, &name, 0, short_name_checksum(b"LIMINE~1CON"));
        let mut out = [0u16; LFN_CHARS];
        let (seq, last, _) = read_lfn_entry(&e, &mut out);
        assert_eq!((seq, last), (1, true));
        assert_eq!(&out[..11], &name);
        assert_eq!(out[11], 0);
        assert_eq!(out[12], 0xFFFF);
    }
}
