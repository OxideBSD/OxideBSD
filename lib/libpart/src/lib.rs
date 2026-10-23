//! Partition tables (OxideBSD-doc `INSTALLER.md` §8.1): GPT, with its backup header and entries,
//! and MBR's four primary entries. Read by the kernel, written by mkimg(1) and gpart(8), edited
//! by the installer.
//!
//! A [`Table`] counts in its disk's own sectors (512 bytes, or 4096 on a "4Kn" disk). It is
//! [`parse`]d from the disk's first sectors (and, for a GPT whose primary header is damaged, its
//! last), changed in memory ([`Table::add`], [`Table::delete`], [`Table::resize`], ...), each
//! change checked against the others, and [`Table::write`] gives back the sectors to write.
//! Nothing here touches a disk: the caller reads and writes.
//!
//! A table read from a disk keeps what this library doesn't interpret: the boot code and disk
//! signature in sector 0, each GPT entry's GUID and attribute bits, and another system's partition
//! types ([`TypeCode`]), so writing a table back changes only what was edited.
//!
//! Everything read from a disk is checked before it's used: a damaged or hostile table is refused
//! (or, for GPT, the backup used), never trusted to index past the buffers it came in.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use oxfs_format::{OXFS_MBR_TYPE, OXFS_TYPE_GUID, guid_bytes};

/// An MBR entry of this type covers a GPT disk (the protective MBR).
pub const MBR_GPT_PROTECTIVE: u8 = 0xEE;
/// Where new partitions start, and the boundary they're laid on: 1 MiB.
pub const ALIGN_BYTES: u64 = 1 << 20;
/// A partition's size is a whole number of these (oxfs's block).
pub const BLOCK_BYTES: u64 = 4096;
/// The entries a GPT made here has, and each one's size.
const GPT_ENTRIES: u32 = 128;
const GPT_ENTRY_SIZE: u32 = 128;
/// The longest GPT partition name, in UTF-16 code units.
pub const GPT_LABEL_UNITS: usize = 36;

const EFI_GUID: [u8; 16] = guid_bytes(0xC12A_7328, 0xF81F, 0x11D2, [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]);
/// GRUB's and Limine's BIOS boot partition: the GUID spells "Hah!IdontNeedEFI".
const BIOS_BOOT_GUID: [u8; 16] = *b"Hah!IdontNeedEFI";
const SWAP_GUID: [u8; 16] = guid_bytes(0xA06A_2C8D, 0xF34E, 0x4D76, [0x9E, 0x98, 0x1C, 0x1E, 0x90, 0xB5, 0x5C, 0x8D]);
const MS_BASIC_DATA_GUID: [u8; 16] =
    guid_bytes(0xEBD0_A0A2, 0xB9E5, 0x4433, [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7]);
const LINUX_DATA_GUID: [u8; 16] = guid_bytes(0x0FC6_3DAF, 0x8483, 0x4772, [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4]);
const LINUX_SWAP_GUID: [u8; 16] = guid_bytes(0x0657_FD6D, 0xA4AB, 0x43C4, [0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F]);
/// OxideBSD's swap on an MBR disk.
const SWAP_MBR_TYPE: u8 = 0xA3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    Gpt,
    Mbr,
}

impl Scheme {
    pub fn name(self) -> &'static str {
        match self {
            Scheme::Gpt => "GPT",
            Scheme::Mbr => "MBR",
        }
    }
}

/// A partition's type as the table stores it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TypeCode {
    Gpt([u8; 16]),
    Mbr(u8),
}

/// The partition types this system names (§8.2); any other is `Other`, kept as it is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Oxfs,
    Efi,
    BiosBoot,
    Swap,
    MsBasicData,
    LinuxData,
    LinuxSwap,
    Other(TypeCode),
}

impl Kind {
    /// The names gpart(8) and the installer take, and show.
    pub const NAMED: [(&'static str, Kind); 7] = [
        ("oxfs", Kind::Oxfs),
        ("efi", Kind::Efi),
        ("bios-boot", Kind::BiosBoot),
        ("swap", Kind::Swap),
        ("ms-basic-data", Kind::MsBasicData),
        ("linux-data", Kind::LinuxData),
        ("linux-swap", Kind::LinuxSwap),
    ];

    /// The kind of a stored type.
    pub fn of(code: TypeCode) -> Kind {
        let found = Kind::NAMED.iter().map(|&(_, k)| k).find(|k| match code {
            TypeCode::Gpt(g) => k.gpt() == Some(g),
            TypeCode::Mbr(b) => k.mbr() == Some(b) || (*k == Kind::MsBasicData && is_mbr_fat_or_ntfs(b)),
        });
        found.unwrap_or(Kind::Other(code))
    }

    fn gpt(self) -> Option<[u8; 16]> {
        Some(match self {
            Kind::Oxfs => OXFS_TYPE_GUID,
            Kind::Efi => EFI_GUID,
            Kind::BiosBoot => BIOS_BOOT_GUID,
            Kind::Swap => SWAP_GUID,
            Kind::MsBasicData => MS_BASIC_DATA_GUID,
            Kind::LinuxData => LINUX_DATA_GUID,
            Kind::LinuxSwap => LINUX_SWAP_GUID,
            Kind::Other(TypeCode::Gpt(g)) => g,
            Kind::Other(TypeCode::Mbr(_)) => return None,
        })
    }

    fn mbr(self) -> Option<u8> {
        Some(match self {
            Kind::Oxfs => OXFS_MBR_TYPE,
            Kind::Efi => 0xEF,
            Kind::BiosBoot => return None,
            Kind::Swap => SWAP_MBR_TYPE,
            // FAT32 with LBA: what a new Windows-readable partition gets.
            Kind::MsBasicData => 0x0C,
            Kind::LinuxData => 0x83,
            Kind::LinuxSwap => 0x82,
            Kind::Other(TypeCode::Mbr(b)) => b,
            Kind::Other(TypeCode::Gpt(_)) => return None,
        })
    }

    /// How a table of `scheme` stores this kind; `None` if it can't (a BIOS boot partition on
    /// MBR, another scheme's raw type).
    pub fn code(self, scheme: Scheme) -> Option<TypeCode> {
        match scheme {
            Scheme::Gpt => self.gpt().map(TypeCode::Gpt),
            Scheme::Mbr => self.mbr().map(TypeCode::Mbr),
        }
    }

    /// Its name: one of `NAMED`'s, or `!` and the raw type (`!0x83`, `!<guid>`) as FreeBSD's gpart
    /// shows a type it doesn't know.
    pub fn name(self) -> String {
        if let Some((n, _)) = Kind::NAMED.iter().find(|(_, k)| *k == self) {
            return String::from(*n);
        }
        match self {
            Kind::Other(TypeCode::Mbr(b)) => alloc::format!("!{b:#04x}"),
            Kind::Other(TypeCode::Gpt(g)) => alloc::format!("!{}", guid_string(&g)),
            _ => unreachable!(),
        }
    }

    /// A kind from its name, or a raw type in `name`'s `!` form.
    pub fn parse(s: &str) -> Option<Kind> {
        if let Some((_, k)) = Kind::NAMED.iter().find(|(n, _)| *n == s) {
            return Some(*k);
        }
        let raw = s.strip_prefix('!')?;
        if let Some(hex) = raw.strip_prefix("0x") {
            return u8::from_str_radix(hex, 16).ok().map(|b| Kind::of(TypeCode::Mbr(b)));
        }
        if let Ok(b) = raw.parse::<u8>() {
            return Some(Kind::of(TypeCode::Mbr(b)));
        }
        parse_guid(raw).map(|g| Kind::of(TypeCode::Gpt(g)))
    }
}

/// MBR types Windows reads: FAT12/16/32 (CHS or LBA), NTFS/exFAT.
fn is_mbr_fat_or_ntfs(b: u8) -> bool {
    matches!(b, 0x01 | 0x04 | 0x06 | 0x07 | 0x0B | 0x0C | 0x0E)
}

/// A GUID's usual text form (`C12A7328-F81F-11D2-BA4B-00A0C93EC93B`).
pub fn guid_string(g: &[u8; 16]) -> String {
    let a = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let b = u16::from_le_bytes([g[4], g[5]]);
    let c = u16::from_le_bytes([g[6], g[7]]);
    let mut s = alloc::format!("{a:08X}-{b:04X}-{c:04X}-{:02X}{:02X}-", g[8], g[9]);
    for x in &g[10..] {
        s += &alloc::format!("{x:02X}");
    }
    s
}

/// `guid_string`'s form back to the stored bytes.
pub fn parse_guid(s: &str) -> Option<[u8; 16]> {
    let parts: Vec<&str> = s.split('-').collect();
    let [a, b, c, d, e] = parts.as_slice() else { return None };
    if (a.len(), b.len(), c.len(), d.len(), e.len()) != (8, 4, 4, 4, 12) {
        return None;
    }
    let mut tail = [0u8; 8];
    let de: String = [*d, *e].concat();
    for (i, t) in tail.iter_mut().enumerate() {
        *t = u8::from_str_radix(de.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(guid_bytes(
        u32::from_str_radix(a, 16).ok()?,
        u16::from_str_radix(b, 16).ok()?,
        u16::from_str_radix(c, 16).ok()?,
        tail,
    ))
}

/// A version 4 (random-shaped) GUID from `seed`: FNV-1a over it, stretched to 16 bytes. For
/// reproducible images (mkimg); a live disk's GUIDs come from the caller's randomness.
pub fn guid_from(seed: &[u8]) -> [u8; 16] {
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

/// CRC-32 (IEEE 802.3, reflected), as GPT uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// One partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its number from 1: its GPT slot, or its MBR entry.
    pub index: u32,
    pub code: TypeCode,
    /// Where it starts, and its length, in the disk's sectors.
    pub first: u64,
    pub sectors: u64,
    /// GPT's partition name (`/dev/gpt/<label>`); empty on MBR.
    pub label: String,
    /// GPT's unique partition GUID.
    pub guid: [u8; 16],
    /// GPT's attribute bits.
    pub attributes: u64,
    /// MBR's boot flag.
    pub active: bool,
}

impl Entry {
    pub fn kind(&self) -> Kind {
        Kind::of(self.code)
    }

    /// The sector after its last.
    pub fn end(&self) -> u64 {
        self.first + self.sectors
    }
}

/// Why a change was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The disk is too small for the table.
    DiskTooSmall,
    /// Every entry of the table is used.
    TableFull,
    /// No free space where it was asked for, or none at all, or not enough.
    NoSpace,
    /// It would overlap another partition, or leave the usable sectors.
    Overlap,
    /// No partition of that number.
    NoSuchPartition,
    /// The type can't be stored in this scheme.
    WrongScheme,
    /// MBR has no names; or a GPT name is too long.
    BadLabel,
    /// Past what MBR's 32-bit fields can hold (2 TiB of 512-byte sectors).
    TooBigForMbr,
    /// A size or start of zero, or not whole 4 KiB blocks.
    BadSize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::DiskTooSmall => "the disk is too small for the table",
            Error::TableFull => "every entry of the table is in use",
            Error::NoSpace => "not enough free space",
            Error::Overlap => "it would overlap another partition or leave the disk's usable space",
            Error::NoSuchPartition => "no such partition",
            Error::WrongScheme => "that type can't be stored in this scheme",
            Error::BadLabel => "labels are GPT's, at most 36 characters",
            Error::TooBigForMbr => "past MBR's 2 TiB",
            Error::BadSize => "sizes are whole 4 KiB blocks, more than none",
        })
    }
}

/// A disk's partition table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub scheme: Scheme,
    /// The disk's sector size in bytes, and its size in those sectors.
    pub sector_size: u32,
    pub disk_sectors: u64,
    /// GPT's disk GUID.
    pub disk_guid: [u8; 16],
    /// The first and last sectors partitions may use (inclusive).
    pub first_usable: u64,
    pub last_usable: u64,
    /// By index.
    pub entries: Vec<Entry>,
    /// The entries the table has room for: GPT's (128 here), MBR's 4.
    pub slots: u32,
    /// Sector 0's first 446 bytes (boot code, the disk signature), kept as they were.
    pub boot: Vec<u8>,
    /// Read from GPT's backup header: the primary was damaged. Writing repairs it.
    pub from_backup: bool,
}

/// How many sectors a GPT's entries take.
fn gpt_entry_sectors(sector_size: u32, count: u32, size: u32) -> u64 {
    (count as u64 * size as u64).div_ceil(sector_size as u64)
}

/// The sectors [`parse`] wants from the start of a disk of `sector_size`-byte sectors, and from
/// its end: a GPT's header and entries made here (`Table::new`), or a little more.
pub fn head_and_tail_sectors(sector_size: u32) -> (u64, u64) {
    let entries = gpt_entry_sectors(sector_size, GPT_ENTRIES, GPT_ENTRY_SIZE);
    (2 + entries, 1 + entries)
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// The table on a disk of `disk_sectors` sectors of `sector_size` bytes, from its first sectors
/// (`head`, at least [`head_and_tail_sectors`]'s first number of them) and its last (`tail`, at
/// least the second number, or empty if unavailable): the GPT, from its primary header or failing
/// that its backup, if the MBR has a protective entry; else the MBR's primary entries (also when
/// both GPT headers are damaged, as the BIOS reads such a hybrid disk). `None` for a disk with no
/// table (no `55 AA` signature).
pub fn parse(head: &[u8], tail: &[u8], sector_size: u32, disk_sectors: u64) -> Option<Table> {
    let ss = sector_size as usize;
    if !sector_size.is_power_of_two() || sector_size < 512 || head.len() < 2 * ss || head[510..512] != [0x55, 0xAA] {
        return None;
    }
    let boot = head[..446].to_vec();
    let mbr_types: Vec<u8> = (0..4).map(|i| head[446 + i * 16 + 4]).collect();
    if mbr_types.contains(&MBR_GPT_PROTECTIVE) {
        if let Some(t) = parse_gpt(head, 1, 0, sector_size, disk_sectors, &boot) {
            return Some(t);
        }
        if let Some(tail_first) = disk_sectors.checked_sub((tail.len() / ss) as u64)
            && !tail.is_empty()
            && let Some(mut t) = parse_gpt(tail, disk_sectors - 1, tail_first, sector_size, disk_sectors, &boot)
        {
            t.from_backup = true;
            return Some(t);
        }
    }
    Some(parse_mbr(head, sector_size, disk_sectors, boot))
}

/// The GPT whose header is at sector `header_lba`, from `buf`, which holds the disk's sectors
/// from `buf_first` on: header and entries checked (signature, sizes, both CRCs, the header's own
/// position, the usable range), entries within `buf`.
fn parse_gpt(buf: &[u8], header_lba: u64, buf_first: u64, sector_size: u32, disk_sectors: u64, boot: &[u8]) -> Option<Table> {
    let ss = sector_size as u64;
    let at = |lba: u64| -> Option<usize> { usize::try_from(lba.checked_sub(buf_first)?.checked_mul(ss)?).ok() };
    let h_at = at(header_lba)?;
    let h = buf.get(h_at..h_at + 512)?;
    if &h[0..8] != b"EFI PART" {
        return None;
    }
    let header_size = le32(h, 12) as usize;
    if !(92..=512).contains(&header_size) {
        return None;
    }
    let mut copy = h[..header_size].to_vec();
    copy[16..20].fill(0);
    if crc32(&copy) != le32(h, 16) || le64(h, 24) != header_lba {
        return None;
    }
    let (first_usable, last_usable) = (le64(h, 40), le64(h, 48));
    if first_usable > last_usable || last_usable >= disk_sectors {
        return None;
    }
    let (count, size) = (le32(h, 80), le32(h, 84));
    if !(128..=4096).contains(&size) || size % 8 != 0 || count > 1024 {
        return None;
    }
    // `Table::write` puts the entries (as 128-byte ones) in the standard places: after the primary
    // header, and before the backup. A table with no room for them there isn't one it can keep.
    let entry_sectors = gpt_entry_sectors(sector_size, count, GPT_ENTRY_SIZE);
    if 2 + entry_sectors > first_usable || last_usable + 1 + entry_sectors > disk_sectors - 1 {
        return None;
    }
    let start = at(le64(h, 72))?;
    let end = start.checked_add(count as usize * size as usize)?;
    let entries_bytes = buf.get(start..end)?;
    if crc32(entries_bytes) != le32(h, 88) {
        return None;
    }
    let mut entries = Vec::new();
    for (i, e) in entries_bytes.chunks(size as usize).enumerate() {
        let code: [u8; 16] = e[0..16].try_into().unwrap();
        if code == [0; 16] {
            continue;
        }
        let (first, last) = (le64(e, 32), le64(e, 40));
        if first > last {
            continue;
        }
        let units = e[56..128].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0);
        let label: String = char::decode_utf16(units).map(|c| c.unwrap_or('?')).collect();
        entries.push(Entry {
            index: i as u32 + 1,
            code: TypeCode::Gpt(code),
            first,
            sectors: last - first + 1,
            label,
            guid: e[16..32].try_into().unwrap(),
            attributes: le64(e, 48),
            active: false,
        });
    }
    Some(Table {
        scheme: Scheme::Gpt,
        sector_size,
        disk_sectors,
        disk_guid: h[56..72].try_into().unwrap(),
        first_usable,
        last_usable,
        entries,
        slots: count,
        boot: boot.to_vec(),
        from_backup: false,
    })
}

/// The MBR's four primary entries (a protective one left out).
fn parse_mbr(head: &[u8], sector_size: u32, disk_sectors: u64, boot: Vec<u8>) -> Table {
    let entries = (0..4)
        .filter_map(|i| {
            let e = &head[446 + i * 16..462 + i * 16];
            let (kind, first, sectors) = (e[4], le32(e, 8) as u64, le32(e, 12) as u64);
            (kind != 0 && kind != MBR_GPT_PROTECTIVE && sectors > 0).then(|| Entry {
                index: i as u32 + 1,
                code: TypeCode::Mbr(kind),
                first,
                sectors,
                label: String::new(),
                guid: [0; 16],
                attributes: 0,
                active: e[0] == 0x80,
            })
        })
        .collect();
    Table {
        scheme: Scheme::Mbr,
        sector_size,
        disk_sectors,
        disk_guid: [0; 16],
        first_usable: 1,
        last_usable: disk_sectors.min(1 << 32) - 1,
        entries,
        slots: 4,
        boot,
        from_backup: false,
    }
}

/// Reading a table from a disk: its geometry, and its sectors.
pub trait Disk {
    fn sector_size(&self) -> u32;
    fn sectors(&self) -> u64;
    /// Reads whole sectors from `lba` into `buf`; `false` on an error.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool;
}

/// [`parse`] of `disk`'s first and last sectors; `Err(())` if they couldn't be read.
pub fn read(disk: &mut dyn Disk) -> Result<Option<Table>, ()> {
    let (ss, total) = (disk.sector_size(), disk.sectors());
    let (head_n, tail_n) = head_and_tail_sectors(ss);
    if total < head_n + tail_n {
        let mut head = vec![0u8; (total.min(head_n) * ss as u64) as usize];
        if !head.is_empty() && !disk.read(0, &mut head) {
            return Err(());
        }
        return Ok(parse(&head, &[], ss, total));
    }
    let mut head = vec![0u8; (head_n * ss as u64) as usize];
    let mut tail = vec![0u8; (tail_n * ss as u64) as usize];
    if !disk.read(0, &mut head) || !disk.read(total - tail_n, &mut tail) {
        return Err(());
    }
    Ok(parse(&head, &tail, ss, total))
}

impl Table {
    /// An empty table of `scheme` for a disk of `disk_sectors` sectors of `sector_size` bytes,
    /// with GPT's disk GUID `disk_guid`.
    pub fn new(scheme: Scheme, sector_size: u32, disk_sectors: u64, disk_guid: [u8; 16]) -> Result<Table, Error> {
        let (first_usable, last_usable, slots) = match scheme {
            Scheme::Gpt => {
                let entries = gpt_entry_sectors(sector_size, GPT_ENTRIES, GPT_ENTRY_SIZE);
                let last = disk_sectors.checked_sub(2 + entries).ok_or(Error::DiskTooSmall)?;
                (2 + entries, last, GPT_ENTRIES)
            }
            Scheme::Mbr => (1, disk_sectors.min(1 << 32).checked_sub(1).ok_or(Error::DiskTooSmall)?, 4),
        };
        if first_usable > last_usable {
            return Err(Error::DiskTooSmall);
        }
        Ok(Table {
            scheme,
            sector_size,
            disk_sectors,
            disk_guid,
            first_usable,
            last_usable,
            entries: Vec::new(),
            slots,
            boot: vec![0; 446],
            from_backup: false,
        })
    }

    /// The alignment and size unit, in sectors.
    fn align(&self) -> u64 {
        (ALIGN_BYTES / self.sector_size as u64).max(1)
    }

    fn block(&self) -> u64 {
        (BLOCK_BYTES / self.sector_size as u64).max(1)
    }

    pub fn entry(&self, index: u32) -> Option<&Entry> {
        self.entries.iter().find(|e| e.index == index)
    }

    /// The usable sectors no partition has, as `(first, sectors)`, in order.
    pub fn free(&self) -> Vec<(u64, u64)> {
        let mut used: Vec<(u64, u64)> = self.entries.iter().map(|e| (e.first, e.end())).collect();
        used.sort();
        let mut free = Vec::new();
        let mut at = self.first_usable;
        for (first, end) in used {
            if first > at {
                free.push((at, first - at));
            }
            at = at.max(end);
        }
        if at <= self.last_usable {
            free.push((at, self.last_usable + 1 - at));
        }
        free
    }

    /// Whether `[first, first + sectors)` is usable and touches no partition but `except`'s.
    fn fits(&self, first: u64, sectors: u64, except: Option<u32>) -> bool {
        let Some(end) = first.checked_add(sectors) else { return false };
        first >= self.first_usable
            && end <= self.last_usable + 1
            && self.entries.iter().filter(|e| Some(e.index) != except).all(|e| end <= e.first || first >= e.end())
    }

    fn check_mbr_range(&self, first: u64, sectors: u64) -> Result<(), Error> {
        if self.scheme == Scheme::Mbr && (first > u32::MAX as u64 || sectors > u32::MAX as u64) {
            return Err(Error::TooBigForMbr);
        }
        Ok(())
    }

    fn check_label(&self, label: &str) -> Result<(), Error> {
        let ok = match self.scheme {
            Scheme::Mbr => label.is_empty(),
            Scheme::Gpt => label.encode_utf16().count() <= GPT_LABEL_UNITS && !label.contains(['\0', '/']),
        };
        if ok { Ok(()) } else { Err(Error::BadLabel) }
    }

    /// Adds a partition of type `code`, named `label`, its unique GUID `guid` (GPT): at `first`
    /// exactly if given, else at the first 1 MiB boundary of the first free space it fits; of
    /// `sectors` (rounded down to whole 4 KiB blocks) if given, else the rest of that free space.
    /// Its number, the lowest unused.
    pub fn add(&mut self, code: TypeCode, label: &str, first: Option<u64>, sectors: Option<u64>, guid: [u8; 16]) -> Result<u32, Error> {
        if matches!((self.scheme, code), (Scheme::Gpt, TypeCode::Mbr(_)) | (Scheme::Mbr, TypeCode::Gpt(_))) {
            return Err(Error::WrongScheme);
        }
        self.check_label(label)?;
        let index = (1..=self.slots).find(|i| self.entry(*i).is_none()).ok_or(Error::TableFull)?;
        let block = self.block();
        let want = match sectors {
            Some(n) => Some(n / block * block).filter(|&n| n > 0).ok_or(Error::BadSize)?.into(),
            None => None,
        };
        let (start, len) = self.place(first, want)?;
        self.check_mbr_range(start, len)?;
        self.entries.push(Entry {
            index,
            code,
            first: start,
            sectors: len,
            label: String::from(label),
            guid,
            attributes: 0,
            active: false,
        });
        self.entries.sort_by_key(|e| e.index);
        Ok(index)
    }

    /// Where a new partition goes (`add`).
    fn place(&self, first: Option<u64>, want: Option<u64>) -> Result<(u64, u64), Error> {
        let block = self.block();
        let extents = self.free();
        if let Some(first) = first {
            let (at, n) = extents.iter().copied().find(|&(at, n)| first >= at && first < at + n).ok_or(Error::NoSpace)?;
            let room = (at + n - first) / block * block;
            let len = want.unwrap_or(room);
            if len == 0 || len > room {
                return Err(Error::NoSpace);
            }
            return Ok((first, len));
        }
        let align = self.align();
        for (at, n) in extents {
            let start = at.div_ceil(align) * align;
            if start >= at + n {
                continue;
            }
            let room = (at + n - start) / block * block;
            match want {
                Some(len) if len <= room => return Ok((start, len)),
                None if room > 0 => return Ok((start, room)),
                _ => {}
            }
        }
        Err(Error::NoSpace)
    }

    /// Removes partition `index`; what it was.
    pub fn delete(&mut self, index: u32) -> Result<Entry, Error> {
        let i = self.entries.iter().position(|e| e.index == index).ok_or(Error::NoSuchPartition)?;
        Ok(self.entries.remove(i))
    }

    /// Makes partition `index` `sectors` long (rounded down to whole 4 KiB blocks), or, with
    /// `None`, as long as the free space after it allows; its start stays.
    pub fn resize(&mut self, index: u32, sectors: Option<u64>) -> Result<(), Error> {
        let e = self.entry(index).ok_or(Error::NoSuchPartition)?.clone();
        let block = self.block();
        let limit = self
            .entries
            .iter()
            .filter(|o| o.index != index && o.first >= e.end())
            .map(|o| o.first)
            .min()
            .unwrap_or(self.last_usable + 1);
        let len = match sectors {
            Some(n) => n / block * block,
            None => (limit - e.first) / block * block,
        };
        if len == 0 {
            return Err(Error::BadSize);
        }
        if !self.fits(e.first, len, Some(index)) {
            return Err(Error::Overlap);
        }
        self.check_mbr_range(e.first, len)?;
        self.entries.iter_mut().find(|x| x.index == index).unwrap().sectors = len;
        Ok(())
    }

    /// Changes partition `index`'s type and/or name.
    pub fn modify(&mut self, index: u32, code: Option<TypeCode>, label: Option<&str>) -> Result<(), Error> {
        if let Some(c) = code
            && matches!((self.scheme, c), (Scheme::Gpt, TypeCode::Mbr(_)) | (Scheme::Mbr, TypeCode::Gpt(_)))
        {
            return Err(Error::WrongScheme);
        }
        if let Some(l) = label {
            self.check_label(l)?;
        }
        let e = self.entries.iter_mut().find(|e| e.index == index).ok_or(Error::NoSuchPartition)?;
        if let Some(c) = code {
            e.code = c;
        }
        if let Some(l) = label {
            e.label = String::from(l);
        }
        Ok(())
    }

    /// Sets (or clears) MBR partition `index`'s boot flag; setting it clears the others'.
    pub fn set_active(&mut self, index: u32, active: bool) -> Result<(), Error> {
        if self.scheme != Scheme::Mbr {
            return Err(Error::WrongScheme);
        }
        if self.entry(index).is_none() {
            return Err(Error::NoSuchPartition);
        }
        for e in &mut self.entries {
            if e.index == index {
                e.active = active;
            } else if active {
                e.active = false;
            }
        }
        Ok(())
    }

    /// The sectors that write this table, as `(lba, bytes)`: sector 0 (its boot code kept), and
    /// for GPT the primary header and entries and the backup entries and header.
    pub fn write(&self) -> Vec<(u64, Vec<u8>)> {
        let ss = self.sector_size as usize;
        let mut sector0 = vec![0u8; ss];
        sector0[..446].copy_from_slice(&self.boot[..446]);
        sector0[510] = 0x55;
        sector0[511] = 0xAA;
        match self.scheme {
            Scheme::Mbr => {
                for e in &self.entries {
                    let code = match e.code {
                        TypeCode::Mbr(b) => b,
                        TypeCode::Gpt(_) => continue,
                    };
                    mbr_entry(&mut sector0, e.index as usize - 1, code, e.first, e.sectors, e.active);
                }
                vec![(0, sector0)]
            }
            Scheme::Gpt => {
                mbr_entry(&mut sector0, 0, MBR_GPT_PROTECTIVE, 1, self.disk_sectors - 1, false);
                let mut entries = vec![0u8; (self.slots * GPT_ENTRY_SIZE) as usize];
                for e in &self.entries {
                    let TypeCode::Gpt(code) = e.code else { continue };
                    let at = (e.index - 1) as usize * GPT_ENTRY_SIZE as usize;
                    let x = &mut entries[at..at + GPT_ENTRY_SIZE as usize];
                    x[0..16].copy_from_slice(&code);
                    x[16..32].copy_from_slice(&e.guid);
                    x[32..40].copy_from_slice(&e.first.to_le_bytes());
                    x[40..48].copy_from_slice(&(e.end() - 1).to_le_bytes());
                    x[48..56].copy_from_slice(&e.attributes.to_le_bytes());
                    for (j, unit) in e.label.encode_utf16().take(GPT_LABEL_UNITS).enumerate() {
                        x[56 + j * 2..58 + j * 2].copy_from_slice(&unit.to_le_bytes());
                    }
                }
                let entry_sectors = gpt_entry_sectors(self.sector_size, self.slots, GPT_ENTRY_SIZE);
                let mut padded = entries.clone();
                padded.resize(entry_sectors as usize * ss, 0);
                let crc = crc32(&entries);
                let backup = self.disk_sectors - 1;
                let header = |this: u64, other: u64, entries_lba: u64| -> Vec<u8> {
                    let mut h = vec![0u8; ss];
                    h[0..8].copy_from_slice(b"EFI PART");
                    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
                    h[12..16].copy_from_slice(&92u32.to_le_bytes());
                    h[24..32].copy_from_slice(&this.to_le_bytes());
                    h[32..40].copy_from_slice(&other.to_le_bytes());
                    h[40..48].copy_from_slice(&self.first_usable.to_le_bytes());
                    h[48..56].copy_from_slice(&self.last_usable.to_le_bytes());
                    h[56..72].copy_from_slice(&self.disk_guid);
                    h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
                    h[80..84].copy_from_slice(&self.slots.to_le_bytes());
                    h[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());
                    h[88..92].copy_from_slice(&crc.to_le_bytes());
                    let hcrc = crc32(&h[..92]);
                    h[16..20].copy_from_slice(&hcrc.to_le_bytes());
                    h
                };
                vec![
                    (0, sector0),
                    (1, header(1, backup, 2)),
                    (2, padded.clone()),
                    (backup - entry_sectors, padded),
                    (backup, header(backup, 1, backup - entry_sectors)),
                ]
            }
        }
    }

    /// The sectors that remove this table, as `write`'s: sector 0's partition entries cleared
    /// (its boot code kept) and for GPT both headers zeroed, as FreeBSD's `gpart destroy` does.
    pub fn destroy(&self) -> Vec<(u64, Vec<u8>)> {
        let ss = self.sector_size as usize;
        let mut sector0 = vec![0u8; ss];
        sector0[..446].copy_from_slice(&self.boot[..446]);
        let mut out = vec![(0, sector0)];
        if self.scheme == Scheme::Gpt {
            out.push((1, vec![0u8; ss]));
            out.push((self.disk_sectors - 1, vec![0u8; ss]));
        }
        out
    }
}

/// Writes MBR entry `i` of `sector0` (LBA fields; CHS saturated, as for any disk past 8 GiB) and
/// the signature.
fn mbr_entry(sector0: &mut [u8], i: usize, kind: u8, first: u64, sectors: u64, active: bool) {
    let e = &mut sector0[446 + i * 16..462 + i * 16];
    e[0] = if active { 0x80 } else { 0 };
    e[1..4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[4] = kind;
    e[5..8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
    e[8..12].copy_from_slice(&(first.min(u32::MAX as u64) as u32).to_le_bytes());
    e[12..16].copy_from_slice(&(sectors.min(u32::MAX as u64) as u32).to_le_bytes());
    sector0[510] = 0x55;
    sector0[511] = 0xAA;
}

#[cfg(test)]
mod tests;
