//! md: a memory disk, the data disk when there is no real one (`OxideBSD-doc/RAM_FLOOR.md`
//! §3.1.3.1), or the mfsroot an install medium boots into (`INSTALLER.md` §4). oxfs uses it
//! exactly as it would a disk, through the same cache, so a diskless boot needs no second storage
//! path.
//!
//! Its RAM cost is only what has been written: a block gets a frame on its first write; before
//! that it reads as zeros, or, on an mfsroot, as the image the boot loader loaded, read in place
//! (copied into the block's frame at that first write). Frames are never given back (oxfs doesn't
//! tell a disk which blocks it freed), so a busy diskless system grows toward the capacity, never
//! past it.
//!
//! An mfsroot may be compressed (FreeBSD's `geom_uzip`, `INSTALLER.md` §4.3): its image is cut
//! into chunks, each compressed alone, so a block is read by decompressing only its chunk (the
//! last two decompressed are kept). The format, all numbers little-endian:
//!
//! ```text
//! 0   8   magic "OXUZIP01"
//! 8   4   chunk size in bytes (a multiple of the 4 KiB block)
//! 12  4   number of chunks, N
//! 16  8   the image's size, uncompressed
//! 24  8*(N+1)  each chunk's offset in this file, then the end of the last one
//! ...      the chunks: each a zstd frame, or stored as it is when that was no smaller (its
//!          length then the chunk's own, which only the last may have short)
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use spin::Mutex;
use x86_64::VirtAddr;

const BLOCK: usize = 4096;

struct MemoryDisk {
    /// Physical address of each block's frame; `0` until the block is first written.
    frames: Vec<u64>,
    /// What an unwritten block holds, from its start: the mfsroot image, else nothing (zeros).
    image: &'static [u8],
    /// The mfsroot's chunks, when it's compressed (`image` is then empty).
    compressed: Option<Compressed>,
    phys_mem_offset: VirtAddr,
}

/// A compressed mfsroot (see the module's doc comment).
struct Compressed {
    file: &'static [u8],
    chunk: usize,
    chunks: usize,
    size: usize,
    /// The chunks decompressed last, by number, the most recent first.
    cache: Vec<(usize, Box<[u8]>)>,
    decoder: ruzstd::decoding::FrameDecoder,
}

const MAGIC: &[u8; 8] = b"OXUZIP01";
/// How many decompressed chunks are kept.
const CACHED_CHUNKS: usize = 2;

impl Compressed {
    /// Checks `file`'s header and offsets; `None` (logged) if they're wrong.
    fn new(file: &'static [u8]) -> Option<Compressed> {
        let u32_at = |at: usize| file.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
        let u64_at = |at: usize| file.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()) as usize);
        let (chunk, chunks, size) = (u32_at(8)?, u32_at(12)?, u64_at(16)?);
        let sane = chunk > 0
            && chunk % BLOCK == 0
            && chunk <= 1 << 20
            && size.div_ceil(chunk) == chunks
            && (0..=chunks).all(|i| u64_at(24 + 8 * i).is_some_and(|o| o <= file.len()))
            && (0..chunks).all(|i| u64_at(24 + 8 * i) <= u64_at(32 + 8 * i));
        if !sane {
            crate::serial_println!("[boot] md: the compressed mfsroot's header is damaged");
            return None;
        }
        let mut decoder = ruzstd::decoding::FrameDecoder::new();
        // A chunk never needs a window larger than itself.
        decoder.set_max_window_size(chunk as u64);
        Some(Compressed { file, chunk, chunks, size, cache: Vec::new(), decoder })
    }

    /// Chunk `n`, decompressed (from the cache, or into it); `None` if it doesn't decompress.
    fn chunk(&mut self, n: usize) -> Option<&[u8]> {
        if let Some(i) = self.cache.iter().position(|(c, _)| *c == n) {
            let hit = self.cache.remove(i);
            self.cache.insert(0, hit);
            return Some(&self.cache[0].1);
        }
        let at = |i: usize| u64::from_le_bytes(self.file[24 + 8 * i..32 + 8 * i].try_into().unwrap()) as usize;
        let stored = &self.file[at(n)..at(n + 1)];
        let len = self.chunk.min(self.size - n * self.chunk);
        let mut out = alloc::vec![0u8; len].into_boxed_slice();
        if stored.len() == len {
            out.copy_from_slice(stored);
        } else if self.decoder.decode_all(stored, &mut out).ok() != Some(len) {
            crate::serial_println!("[md] the mfsroot's chunk {} doesn't decompress", n);
            return None;
        }
        self.cache.truncate(CACHED_CHUNKS - 1);
        self.cache.insert(0, (n, out));
        Some(&self.cache[0].1)
    }

    /// Copies block `b` into `out` (zeros past the image's end).
    fn read_block(&mut self, b: usize, out: &mut [u8]) -> bool {
        let at = b * BLOCK;
        if at >= self.size {
            out.fill(0);
            return true;
        }
        let chunk_size = self.chunk;
        let n = at / chunk_size;
        if n >= self.chunks {
            return false;
        }
        let Some(data) = self.chunk(n) else { return false };
        let from = at - n * chunk_size;
        let to = (from + BLOCK).min(data.len());
        out[..to - from].copy_from_slice(&data[from..to]);
        out[to - from..].fill(0);
        true
    }
}

static DISK: Mutex<Option<MemoryDisk>> = Mutex::new(None);

/// Creates the memory disk, `capacity_blocks` 4 KiB blocks, none of them backed yet.
pub fn init(capacity_blocks: u64, phys_mem_offset: VirtAddr) {
    *DISK.lock() = Some(MemoryDisk { frames: vec![0; capacity_blocks as usize], image: &[], compressed: None, phys_mem_offset });
}

/// Creates the memory disk over `image` (the mfsroot, which stays where the boot loader put it),
/// compressed or not: its size, rounded up to a block. `false` if a compressed one is damaged.
pub fn init_image(image: &'static [u8], phys_mem_offset: VirtAddr) -> bool {
    let (image, compressed) = if image.starts_with(MAGIC) {
        match Compressed::new(image) {
            Some(c) => (&[][..], Some(c)),
            None => return false,
        }
    } else {
        (image, None)
    };
    let size = compressed.as_ref().map_or(image.len(), |c| c.size);
    *DISK.lock() = Some(MemoryDisk { frames: vec![0; size.div_ceil(BLOCK)], image, compressed, phys_mem_offset });
    true
}

/// The disk's size in 4 KiB blocks.
pub fn capacity_blocks() -> u64 {
    DISK.lock().as_ref().map_or(0, |disk| disk.frames.len() as u64)
}

impl MemoryDisk {
    /// Copies block `b`'s contents into `out` (a whole block); `false` past the end, or if a
    /// compressed mfsroot's chunk doesn't decompress.
    fn read_block(&mut self, b: usize, out: &mut [u8]) -> bool {
        let Some(&frame) = self.frames.get(b) else { return false };
        if frame != 0 {
            // SAFETY: `frame` is a frame this disk owns, mapped through the HHDM.
            out.copy_from_slice(unsafe { &*((self.phys_mem_offset + frame).as_ptr::<[u8; BLOCK]>()) });
        } else if let Some(c) = &mut self.compressed {
            return c.read_block(b, out);
        } else {
            let from = (b * BLOCK).min(self.image.len());
            let to = (from + BLOCK).min(self.image.len());
            out[..to - from].copy_from_slice(&self.image[from..to]);
            out[to - from..].fill(0);
        }
        true
    }

    /// Block `b`'s frame, taken (holding what the block read as) on its first write.
    fn writable_block(&mut self, b: usize) -> Option<&mut [u8; BLOCK]> {
        if *self.frames.get(b)? == 0 {
            let new = crate::memory::allocate_frame()?;
            let frame = new.start_address().as_u64();
            // SAFETY: a frame just allocated, reached through the HHDM; nothing else maps it.
            let dst = unsafe { &mut *((self.phys_mem_offset + frame).as_mut_ptr::<[u8; BLOCK]>()) };
            if !self.read_block(b, dst) {
                // SAFETY: nothing else has seen the frame.
                unsafe { crate::memory::free_frame(new) };
                return None;
            }
            self.frames[b] = frame;
        }
        // SAFETY: as above.
        Some(unsafe { &mut *((self.phys_mem_offset + self.frames[b]).as_mut_ptr::<[u8; BLOCK]>()) })
    }
}

/// Reads blocks from `start_block` into `buf` (a whole number of blocks).
pub fn read_blocks(start_block: u64, buf: &mut [u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    buf.chunks_mut(BLOCK).enumerate().all(|(i, chunk)| disk.read_block(start_block as usize + i, chunk))
}

/// Reads sectors from `lba` into `buf` (whole 512-byte sectors): the block layer's way in, for a
/// file system with smaller blocks than the disk's 4 KiB frames.
pub fn read_sectors(lba: u64, buf: &mut [u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    let mut block = [0u8; BLOCK];
    for (i, sector) in buf.chunks_mut(512).enumerate() {
        let at = lba + i as u64;
        if !disk.read_block((at / 8) as usize, &mut block) {
            return false;
        }
        let off = (at % 8) as usize * 512;
        sector.copy_from_slice(&block[off..off + 512]);
    }
    true
}

/// Writes sectors at `lba` from `buf` (whole sectors).
pub fn write_sectors(lba: u64, buf: &[u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    for (i, sector) in buf.chunks(512).enumerate() {
        let at = lba + i as u64;
        let Some(dst) = disk.writable_block((at / 8) as usize) else { return false };
        let off = (at % 8) as usize * 512;
        dst[off..off + 512].copy_from_slice(sector);
    }
    true
}

/// Writes blocks from `buf` at `start_block`, backing each with a frame on its first write.
pub fn write_blocks(start_block: u64, buf: &[u8]) -> bool {
    let mut guard = DISK.lock();
    let Some(disk) = guard.as_mut() else { return false };
    for (i, chunk) in buf.chunks(BLOCK).enumerate() {
        let Some(dst) = disk.writable_block(start_block as usize + i) else { return false };
        dst.copy_from_slice(chunk);
    }
    true
}
