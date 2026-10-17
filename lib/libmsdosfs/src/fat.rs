//! The file allocation table (§4): one entry per cluster, 12, 16 or 28 bits wide, naming the next
//! cluster of a chain, the chain's end, a bad cluster, or a free one.
//!
//! An entry is read and written through a small window of the FAT's bytes starting at its byte
//! offset (`entry_offset`), so a caller holding the FAT in pieces (the kernel's buffer cache, a
//! sector at a time) needs only those bytes: two for FAT12 and FAT16, four for FAT32. A FAT12
//! entry may straddle two sectors; the window then spans them.

use crate::FatType;

/// What an entry says (§4.1). `Reserved` is a value no chain may hold: 1, the cluster numbers
/// past the volume's last, and FAT32's `0x0FFF_FFF0..=0x0FFF_FFF6`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Free,
    Next(u32),
    Bad,
    End,
    Reserved,
}

impl FatType {
    /// Bits an entry holds.
    pub fn entry_bits(self) -> u32 {
        match self {
            FatType::Fat12 => 12,
            FatType::Fat16 => 16,
            FatType::Fat32 => 28,
        }
    }

    /// The value written to end a chain.
    pub fn eoc(self) -> u32 {
        match self {
            FatType::Fat12 => 0xFFF,
            FatType::Fat16 => 0xFFFF,
            FatType::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// The value marking a bad cluster.
    pub fn bad(self) -> u32 {
        self.eoc() - 8
    }

    /// The bytes of the window an entry is read through.
    pub fn window(self) -> usize {
        if self == FatType::Fat32 { 4 } else { 2 }
    }

    /// Bytes a FAT for `entries` entries takes (entries 0 and 1 included).
    pub fn fat_bytes(self, entries: u32) -> u64 {
        match self {
            FatType::Fat12 => (entries as u64 * 3).div_ceil(2),
            FatType::Fat16 => entries as u64 * 2,
            FatType::Fat32 => entries as u64 * 4,
        }
    }

    /// What `value` means on a volume whose last cluster is `max_cluster`.
    pub fn classify(self, value: u32, max_cluster: u32) -> Entry {
        let eoc = self.eoc();
        match value {
            0 => Entry::Free,
            v if v == self.bad() => Entry::Bad,
            v if v >= eoc - 7 => Entry::End,
            v if (crate::FIRST_CLUSTER..=max_cluster).contains(&v) => Entry::Next(v),
            _ => Entry::Reserved,
        }
    }

    /// FAT entry 1's "volume clean" bit (FAT16 and FAT32 only, §4.2): clear while mounted
    /// read-write, so a volume that wasn't unmounted is known.
    pub fn clean_bit(self) -> Option<u32> {
        match self {
            FatType::Fat12 => None,
            FatType::Fat16 => Some(0x8000),
            FatType::Fat32 => Some(0x0800_0000),
        }
    }

    /// FAT entry 1's "no disk errors" bit: cleared by a driver that met an I/O error.
    pub fn no_error_bit(self) -> Option<u32> {
        match self {
            FatType::Fat12 => None,
            FatType::Fat16 => Some(0x4000),
            FatType::Fat32 => Some(0x0400_0000),
        }
    }
}

/// The byte offset within the FAT of `cluster`'s entry.
pub fn entry_offset(kind: FatType, cluster: u32) -> usize {
    let c = cluster as usize;
    match kind {
        FatType::Fat12 => c + c / 2,
        FatType::Fat16 => c * 2,
        FatType::Fat32 => c * 4,
    }
}

/// `cluster`'s entry, from `window`: the FAT's bytes from `entry_offset` (at least
/// `kind.window()` of them). FAT32's reserved top four bits are dropped.
pub fn get(kind: FatType, cluster: u32, window: &[u8]) -> u32 {
    match kind {
        FatType::Fat12 => {
            let v = u16::from_le_bytes([window[0], window[1]]) as u32;
            if cluster & 1 == 0 { v & 0xFFF } else { v >> 4 }
        }
        FatType::Fat16 => u16::from_le_bytes([window[0], window[1]]) as u32,
        FatType::Fat32 => u32::from_le_bytes([window[0], window[1], window[2], window[3]]) & crate::FAT32_MASK,
    }
}

/// Sets `cluster`'s entry to `value` in `window` (as `get`'s), keeping the bits it shares with a
/// neighbour (FAT12) and FAT32's reserved top four.
pub fn set(kind: FatType, cluster: u32, window: &mut [u8], value: u32) {
    match kind {
        FatType::Fat12 => {
            let old = u16::from_le_bytes([window[0], window[1]]);
            let v = (value & 0xFFF) as u16;
            let new = if cluster & 1 == 0 { (old & 0xF000) | v } else { (old & 0x000F) | (v << 4) };
            window[..2].copy_from_slice(&new.to_le_bytes());
        }
        FatType::Fat16 => window[..2].copy_from_slice(&(value as u16).to_le_bytes()),
        FatType::Fat32 => {
            let old = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
            let new = (old & !crate::FAT32_MASK) | (value & crate::FAT32_MASK);
            window[..4].copy_from_slice(&new.to_le_bytes());
        }
    }
}

/// Entry 0's value: the media byte, the rest of the entry's bits set (§4.2).
pub fn entry0(kind: FatType, media: u8) -> u32 {
    (kind.eoc() & !0xFF) | media as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat12_neighbours() {
        let mut fat = [0u8; 8];
        for c in 0..5u32 {
            let o = entry_offset(FatType::Fat12, c);
            set(FatType::Fat12, c, &mut fat[o..], 0xA00 + c);
        }
        for c in 0..5u32 {
            let o = entry_offset(FatType::Fat12, c);
            assert_eq!(get(FatType::Fat12, c, &fat[o..]), 0xA00 + c);
        }
        // Entries 0 and 1 share byte 1: 0xA00, 0xA01 -> 00 1A A0.
        assert_eq!(&fat[..3], &[0x00, 0x1A, 0xA0]);
    }

    #[test]
    fn fat32_keeps_reserved_bits() {
        let mut w = 0xF000_0000u32.to_le_bytes();
        set(FatType::Fat32, 2, &mut w, 0x0FFF_FFFF);
        assert_eq!(u32::from_le_bytes(w), 0xFFFF_FFFF);
        assert_eq!(get(FatType::Fat32, 2, &w), 0x0FFF_FFFF);
    }

    #[test]
    fn classify() {
        let k = FatType::Fat16;
        assert_eq!(k.classify(0, 100), Entry::Free);
        assert_eq!(k.classify(1, 100), Entry::Reserved);
        assert_eq!(k.classify(50, 100), Entry::Next(50));
        assert_eq!(k.classify(101, 100), Entry::Reserved);
        assert_eq!(k.classify(0xFFF7, 100), Entry::Bad);
        assert_eq!(k.classify(0xFFF8, 100), Entry::End);
        assert_eq!(FatType::Fat12.classify(0xFF0, 100), Entry::Reserved);
        assert_eq!(entry0(FatType::Fat12, 0xF8), 0xFF8);
    }
}
