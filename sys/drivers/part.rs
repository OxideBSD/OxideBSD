//! Partition tables (`OxideBSD-doc/RAM_FLOOR.md` §3.4.5): reading a disk's GPT, or its MBR when it
//! has no GPT, and writing a fresh GPT with one oxfs partition on a blank disk (only when the
//! kernel is booted with `format-blank`).
//!
//! Disks are addressed here in 512-byte sectors (LBAs), as both tables are; `drivers::disk` works
//! in 4 KiB blocks, so a partition oxfs can use must start and end on a block boundary. GPT
//! partitions are named `<disk>p<N>`, MBR ones `<disk>s<N>` (N from 1); only the four MBR primary
//! entries are read, no extended or logical partitions yet.

use alloc::vec;
use alloc::vec::Vec;

use oxfs_format::{OXFS_MBR_TYPE, OXFS_TYPE_GUID};

/// An MBR entry of this type covers a GPT disk (the protective MBR).
const MBR_GPT_PROTECTIVE: u8 = 0xEE;
const SECTOR: usize = 512;
/// GPT entries this kernel writes: the usual 128 of 128 bytes, 32 sectors.
const GPT_ENTRIES: u32 = 128;
const GPT_ENTRY_SIZE: u32 = 128;
const GPT_ENTRY_SECTORS: u64 = (GPT_ENTRIES * GPT_ENTRY_SIZE) as u64 / SECTOR as u64;
/// Where the written partition starts: 1 MiB, the usual alignment.
const FIRST_PARTITION_LBA: u64 = 2048;

/// Which table a partition came from (and so how it's named).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    Gpt,
    Mbr,
}

/// One partition: its index from 1, where it is in sectors, whether it's oxfs's, and its GPT
/// name (the label `/dev/gpt/<label>` names it by), if it has one.
#[derive(Clone, Debug)]
pub struct Partition {
    pub scheme: Scheme,
    pub index: u32,
    pub first_lba: u64,
    pub sectors: u64,
    pub oxfs: bool,
    pub label: Option<alloc::string::String>,
}

impl Partition {
    /// The partition's name suffix: `p1` (GPT) or `s1` (MBR).
    pub fn suffix(&self) -> alloc::string::String {
        let letter = if self.scheme == Scheme::Gpt { 'p' } else { 's' };
        alloc::format!("{letter}{}", self.index)
    }

    /// Its extent in 4 KiB blocks, if it's block-aligned.
    pub fn blocks(&self) -> Option<(u64, u64)> {
        (self.first_lba.is_multiple_of(8) && self.sectors >= 8)
            .then_some((self.first_lba / 8, self.sectors / 8))
    }
}

/// The partitions in `head`, the disk's first 34 sectors (MBR, GPT header and entries): the GPT's
/// if there is a valid one, else the MBR's primary entries. Empty for a disk with neither.
pub fn read(head: &[u8]) -> Vec<Partition> {
    if head.len() < SECTOR * 34 || head[510..512] != [0x55, 0xAA] {
        return Vec::new();
    }
    let mbr_types: Vec<u8> = (0..4).map(|i| head[446 + i * 16 + 4]).collect();
    if mbr_types.contains(&MBR_GPT_PROTECTIVE)
        && let Some(gpt) = read_gpt(head)
    {
        return gpt;
    }
    (0..4)
        .filter_map(|i| {
            let e = &head[446 + i * 16..446 + i * 16 + 16];
            let kind = e[4];
            let first = u32::from_le_bytes(e[8..12].try_into().unwrap()) as u64;
            let sectors = u32::from_le_bytes(e[12..16].try_into().unwrap()) as u64;
            (kind != 0 && kind != MBR_GPT_PROTECTIVE && sectors > 0).then_some(Partition {
                scheme: Scheme::Mbr,
                index: i as u32 + 1,
                first_lba: first,
                sectors,
                oxfs: kind == OXFS_MBR_TYPE,
                label: None,
            })
        })
        .collect()
}

/// The GPT's used entries, if the header at LBA 1 is valid (signature, header CRC, entries CRC)
/// and its entries lie within `head`.
fn read_gpt(head: &[u8]) -> Option<Vec<Partition>> {
    let h = &head[SECTOR..2 * SECTOR];
    if &h[0..8] != b"EFI PART" {
        return None;
    }
    let header_size = u32::from_le_bytes(h[12..16].try_into().unwrap()) as usize;
    if !(92..=SECTOR).contains(&header_size) {
        return None;
    }
    let mut copy = h[..header_size].to_vec();
    copy[16..20].fill(0);
    if crc32(&copy) != u32::from_le_bytes(h[16..20].try_into().unwrap()) {
        return None;
    }
    let entries_lba = u64::from_le_bytes(h[72..80].try_into().unwrap()) as usize;
    let count = u32::from_le_bytes(h[80..84].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(h[84..88].try_into().unwrap()) as usize;
    let start = entries_lba * SECTOR;
    let end = start.checked_add(count.checked_mul(size)?)?;
    if size < 128 || end > head.len() {
        return None;
    }
    let entries = &head[start..end];
    if crc32(entries) != u32::from_le_bytes(h[88..92].try_into().unwrap()) {
        return None;
    }
    Some(
        entries
            .chunks(size)
            .enumerate()
            .filter(|(_, e)| e[0..16] != [0u8; 16])
            .map(|(i, e)| {
                let first = u64::from_le_bytes(e[32..40].try_into().unwrap());
                let last = u64::from_le_bytes(e[40..48].try_into().unwrap());
                let units = e[56..128.min(e.len())]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&u| u != 0);
                let label: alloc::string::String =
                    char::decode_utf16(units).map(|c| c.unwrap_or('?')).collect();
                Partition {
                    scheme: Scheme::Gpt,
                    index: i as u32 + 1,
                    first_lba: first,
                    sectors: last.saturating_sub(first) + 1,
                    oxfs: e[0..16] == OXFS_TYPE_GUID,
                    label: (!label.is_empty() && !label.contains('/')).then_some(label),
                }
            })
            .collect(),
    )
}

/// A fresh GPT for a disk of `total_sectors` with one oxfs partition, named `rootfs` (so
/// `/dev/gpt/rootfs`, which `/etc/fstab` names the root by), from 1 MiB to the last usable
/// sector, rounded down to whole 4 KiB blocks: `(head, tail)`, the bytes for the disk's
/// first 34 sectors and its last 33 (backup entries and header). `disk_guid` and `part_guid`
/// identify the disk and the partition.
pub fn fresh_gpt(total_sectors: u64, disk_guid: [u8; 16], part_guid: [u8; 16]) -> (Vec<u8>, Vec<u8>) {
    let last_usable = total_sectors - 1 - GPT_ENTRY_SECTORS - 1;
    let first = FIRST_PARTITION_LBA;
    let last = first + ((last_usable + 1 - first) / 8) * 8 - 1;

    let mut entries = vec![0u8; (GPT_ENTRIES * GPT_ENTRY_SIZE) as usize];
    entries[0..16].copy_from_slice(&OXFS_TYPE_GUID);
    entries[16..32].copy_from_slice(&part_guid);
    entries[32..40].copy_from_slice(&first.to_le_bytes());
    entries[40..48].copy_from_slice(&last.to_le_bytes());
    for (i, unit) in "rootfs".encode_utf16().enumerate() {
        entries[56 + i * 2..58 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    let entries_crc = crc32(&entries);

    let header = |this: u64, other: u64, entries_lba: u64| -> Vec<u8> {
        let mut h = vec![0u8; SECTOR];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&this.to_le_bytes());
        h[32..40].copy_from_slice(&other.to_le_bytes());
        h[40..48].copy_from_slice(&(2 + GPT_ENTRY_SECTORS).to_le_bytes());
        h[48..56].copy_from_slice(&last_usable.to_le_bytes());
        h[56..72].copy_from_slice(&disk_guid);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&GPT_ENTRIES.to_le_bytes());
        h[84..88].copy_from_slice(&GPT_ENTRY_SIZE.to_le_bytes());
        h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let crc = crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };

    // Protective MBR: one 0xEE entry covering the disk (capped at 32 bits).
    let mut head = vec![0u8; SECTOR * (2 + GPT_ENTRY_SECTORS as usize)];
    let e = &mut head[446..462];
    e[1..4].copy_from_slice(&[0x00, 0x02, 0x00]);
    e[4] = MBR_GPT_PROTECTIVE;
    e[5..8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    e[8..12].copy_from_slice(&1u32.to_le_bytes());
    e[12..16].copy_from_slice(&((total_sectors - 1).min(u32::MAX as u64) as u32).to_le_bytes());
    head[510] = 0x55;
    head[511] = 0xAA;
    head[SECTOR..2 * SECTOR].copy_from_slice(&header(1, total_sectors - 1, 2));
    head[2 * SECTOR..].copy_from_slice(&entries);

    let mut tail = vec![0u8; SECTOR * (GPT_ENTRY_SECTORS as usize + 1)];
    tail[..entries.len()].copy_from_slice(&entries);
    let backup_entries = total_sectors - 1 - GPT_ENTRY_SECTORS;
    tail[entries.len()..].copy_from_slice(&header(total_sectors - 1, 1, backup_entries));
    (head, tail)
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
