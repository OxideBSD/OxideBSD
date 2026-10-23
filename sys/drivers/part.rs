//! Partition tables (`OxideBSD-doc/RAM_FLOOR.md` §3.4.5): reading a disk's GPT, or its MBR when it
//! has no GPT, through `lib/libpart` (INSTALLER.md §8.1). The kernel never writes one (RAM_FLOOR.md
//! §4.2.1): mkimg(1), gpart(8) and the installer do.
//!
//! A table counts in its disk's own sectors (512 bytes, or 4096 on a "4Kn" disk; a CD's hybrid
//! image counts 512, as it does written to a USB stick); `read` returns partitions in 512-byte
//! sectors, the block layer's unit. oxfs works in 4 KiB blocks, so a partition it can use must
//! start and end on a block boundary. GPT
//! partitions are named `<disk>p<N>`, MBR ones `<disk>s<N>` (N from 1); only the four MBR primary
//! entries are read, no extended or logical partitions yet.

use alloc::vec::Vec;

const SECTOR: usize = 512;

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

/// The partitions in `head`, the first sectors of a disk of `disk_sectors` sectors of `sector`
/// bytes (at least `libpart::head_and_tail_sectors`' first number of them): the GPT's if there
/// is a valid one, else the MBR's primary entries (`libpart::parse`). Empty for a disk with
/// neither. Positions in 512-byte sectors.
pub fn read(head: &[u8], sector: usize, disk_sectors: u64) -> Vec<Partition> {
    let Some(table) = part::parse(head, &[], sector as u32, disk_sectors) else { return Vec::new() };
    let scale = (sector / SECTOR) as u64;
    let scheme = match table.scheme {
        part::Scheme::Gpt => Scheme::Gpt,
        part::Scheme::Mbr => Scheme::Mbr,
    };
    table
        .entries
        .into_iter()
        .filter_map(|e| {
            Some(Partition {
                scheme,
                index: e.index,
                first_lba: e.first.checked_mul(scale)?,
                sectors: e.sectors.checked_mul(scale)?,
                oxfs: e.kind() == part::Kind::Oxfs,
                label: (scheme == Scheme::Gpt && !e.label.is_empty() && !e.label.contains('/')).then_some(e.label),
            })
        })
        .collect()
}
