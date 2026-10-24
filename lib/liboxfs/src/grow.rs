//! Growing an oxfs to fill a larger device (`growfs(8)`, OxideBSD-doc `INSTALLER.md` §8.2): the
//! partition grown first, then this, with the file system unmounted.
//!
//! The superblock's `data_blocks` sets the bitmap's length, and data block `i` lies at device
//! block `1 + bitmap blocks + i`: while the bitmap's last block has room for the new blocks' bits
//! only `data_blocks` changes; past that, `k` more bitmap blocks push every data block `k` device
//! blocks further in. Nothing on the disk names a device block -- every pointer is a data block's
//! number -- so only the used data blocks move, the highest first (each lands where a higher one
//! was, already moved), then the new bitmap blocks are zeroed (all their blocks free) and the
//! superblock written last. The move is not safe against a crash: a power cut in it leaves the
//! file system damaged.

use crate::{BITMAP_START, BITS_PER_BITMAP_BLOCK, BLOCK_SIZE, BlockDevice, Superblock, layout_for};

/// What `grow` did: data blocks before and after, and how many device blocks the data moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grown {
    pub old_blocks: u32,
    pub new_blocks: u32,
    pub moved_by: u32,
}

/// Why `grow` didn't.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowError<E> {
    Device(E),
    Superblock(crate::SuperblockError),
    /// Not marked clean: check it (`fsck_oxfs`) first.
    NotClean,
    /// The device holds no more data blocks than the file system has.
    NoRoom,
}

impl<E> From<E> for GrowError<E> {
    fn from(e: E) -> Self {
        GrowError::Device(e)
    }
}

fn bit(map: &[u8; BLOCK_SIZE], i: u32) -> bool {
    map[i as usize / 8] & (1 << (i % 8)) != 0
}

/// What `grow` would make of the oxfs on `dev` on a device of `device_blocks` blocks, nothing
/// written.
pub fn plan<D: BlockDevice>(dev: &mut D, device_blocks: u64) -> Result<Grown, GrowError<D::Error>> {
    let mut block = [0u8; BLOCK_SIZE];
    dev.read_block(0, &mut block)?;
    let sb = Superblock::decode(&block).map_err(GrowError::Superblock)?;
    let (new_blocks, new_bitmap) = layout_for(device_blocks);
    if new_blocks <= sb.data_blocks {
        return Err(GrowError::NoRoom);
    }
    Ok(Grown { old_blocks: sb.data_blocks, new_blocks, moved_by: new_bitmap - sb.bitmap_blocks() })
}

/// Grows the oxfs on `dev`, unmounted and clean, to fill `device_blocks` blocks.
pub fn grow<D: BlockDevice>(dev: &mut D, device_blocks: u64) -> Result<Grown, GrowError<D::Error>> {
    let g = plan(dev, device_blocks)?;
    let mut block = [0u8; BLOCK_SIZE];
    dev.read_block(0, &mut block)?;
    let mut sb = Superblock::decode(&block).map_err(GrowError::Superblock)?;
    if !sb.clean {
        return Err(GrowError::NotClean);
    }
    let old_bitmap = sb.bitmap_blocks();
    let old_start = BITMAP_START + old_bitmap;
    let new_start = old_start + g.moved_by;
    let mut map = [0u8; BLOCK_SIZE];
    let mut data = [0u8; BLOCK_SIZE];
    if g.moved_by > 0 {
        // Highest first: each block lands on one already moved, never on one still to move.
        for index in (0..old_bitmap).rev() {
            dev.read_block((BITMAP_START + index) as u64, &mut map)?;
            let base = index * BITS_PER_BITMAP_BLOCK;
            let bits = (g.old_blocks - base).min(BITS_PER_BITMAP_BLOCK);
            for b in (0..bits).rev() {
                if bit(&map, b) {
                    let i = base + b;
                    dev.read_block((old_start + i) as u64, &mut data)?;
                    dev.write_block((new_start + i) as u64, &data)?;
                }
            }
        }
        // The new bitmap blocks: every block they cover is free.
        let zero = [0u8; BLOCK_SIZE];
        for b in old_start..new_start {
            dev.write_block(b as u64, &zero)?;
        }
    }
    // The old last bitmap block's bits past the old end: free too, whatever they held.
    let last = old_bitmap - 1;
    dev.read_block((BITMAP_START + last) as u64, &mut map)?;
    let from = g.old_blocks - last * BITS_PER_BITMAP_BLOCK;
    for b in from..BITS_PER_BITMAP_BLOCK {
        map[b as usize / 8] &= !(1 << (b % 8));
    }
    dev.write_block((BITMAP_START + last) as u64, &map)?;
    sb.data_blocks = g.new_blocks;
    sb.encode(&mut block);
    dev.write_block(0, &block)?;
    Ok(g)
}
