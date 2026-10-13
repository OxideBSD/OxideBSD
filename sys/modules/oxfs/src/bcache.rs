//! The buffer cache (`OxideBSD-doc/RAM_FLOOR.md` §3.2): a fixed set of 4 KiB buffers, sized from
//! RAM at boot, holding recently used blocks of the data disk. Every disk block oxfs touches --
//! superblock aside -- goes through here by its *device* block number: data blocks, the inode
//! file, directories, index blocks and the block-used bitmap alike. A miss evicts the least
//! recently used buffer and reads the block (and a few after it, `READ_AHEAD`) from the disk.
//!
//! A buffer is `DIRTY` when it holds a write the disk hasn't seen. While the filesystem is being
//! formatted (`write_through` false) every write stays dirty until `flush_all`; afterwards
//! writes go to the disk before the system call returns, either at once (`write`) or as one batch
//! per contiguous run (`store` then `flush_run`, the shape `write_inode_with` uses for a file's
//! data). A dirty buffer chosen for eviction is written out first.
//!
//! Modules have no `alloc`: the buffers, their headers and the hash table come from
//! `oxidebsd_module_alloc_zeroed` in `init`, which must run inside `module_init`. Everything is
//! single-core and syscall-serialized, like the rest of oxfs, and nothing may call back into the
//! cache from inside a `with` closure (that's what makes lending the buffer safe).

use crate::{BLOCK_SIZE, log, oxidebsd_block_read_batch, oxidebsd_block_write_batch, oxidebsd_module_alloc_zeroed};

/// "No buffer" in the LRU links and hash chains.
const NIL: u32 = u32::MAX;
/// A buffer whose `block` means nothing yet.
const FREE_BLOCK: u32 = u32::MAX;
/// Blocks read in one command on a miss: the missed block plus up to this many after it, stopping
/// at one that's already cached. Programs and files are mostly laid out contiguously
/// (`alloc_block` is a forward cursor), so the next blocks are usually wanted next.
const READ_AHEAD: usize = 16;
/// Largest run written in one command (`flush_run`, `flush_all`): the staging buffer's size.
const STAGE_BLOCKS: usize = 32;
/// The cache's size: `RAM / 8`, between these.
const MIN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Header {
    block: u32,
    dirty: bool,
    /// LRU neighbours: `prev` toward the most recently used end.
    prev: u32,
    next: u32,
    /// Next buffer in the same hash chain.
    hash_next: u32,
}

struct Cache {
    data: *mut [u8; BLOCK_SIZE],
    headers: *mut Header,
    hash: *mut u32,
    count: u32,
    hash_mask: u32,
    /// Most and least recently used buffers.
    head: u32,
    tail: u32,
    write_through: bool,
    stage: [[u8; BLOCK_SIZE]; STAGE_BLOCKS],
}

static mut CACHE: Cache = Cache {
    data: core::ptr::null_mut(),
    headers: core::ptr::null_mut(),
    hash: core::ptr::null_mut(),
    count: 0,
    hash_mask: 0,
    head: NIL,
    tail: NIL,
    write_through: false,
    stage: [[0; BLOCK_SIZE]; STAGE_BLOCKS],
};

fn cache() -> &'static mut Cache {
    // SAFETY: single-core, syscall-serialized (see the module doc comment); callers never hold
    // two of these across a call that takes another.
    unsafe { &mut *core::ptr::addr_of_mut!(CACHE) }
}

impl Cache {
    fn header(&mut self, i: u32) -> &mut Header {
        // SAFETY: `i < count`, inside the `init` allocation.
        unsafe { &mut *self.headers.add(i as usize) }
    }

    fn buffer(&mut self, i: u32) -> &mut [u8; BLOCK_SIZE] {
        // SAFETY: as `header`.
        unsafe { &mut *self.data.add(i as usize) }
    }

    fn bucket(&mut self, block: u32) -> &mut u32 {
        let slot = (block.wrapping_mul(0x9E37_79B1) & self.hash_mask) as usize;
        // SAFETY: `slot <= hash_mask`, inside the `init` allocation.
        unsafe { &mut *self.hash.add(slot) }
    }

    fn lookup(&mut self, block: u32) -> Option<u32> {
        let mut i = *self.bucket(block);
        while i != NIL {
            if self.header(i).block == block {
                return Some(i);
            }
            i = self.header(i).hash_next;
        }
        None
    }

    fn unhash(&mut self, i: u32) {
        let block = self.header(i).block;
        if block == FREE_BLOCK {
            return;
        }
        let next = self.header(i).hash_next;
        let first = *self.bucket(block);
        if first == i {
            *self.bucket(block) = next;
            return;
        }
        let mut j = first;
        while j != NIL {
            if self.header(j).hash_next == i {
                self.header(j).hash_next = next;
                return;
            }
            j = self.header(j).hash_next;
        }
    }

    fn rehash(&mut self, i: u32, block: u32) {
        self.unhash(i);
        self.header(i).block = block;
        self.header(i).hash_next = *self.bucket(block);
        *self.bucket(block) = i;
    }

    fn unlink(&mut self, i: u32) {
        let Header { prev, next, .. } = *self.header(i);
        if prev == NIL { self.head = next } else { self.header(prev).next = next }
        if next == NIL { self.tail = prev } else { self.header(next).prev = prev }
    }

    /// Marks buffer `i` most recently used.
    fn touch(&mut self, i: u32) {
        if self.head == i {
            return;
        }
        self.unlink(i);
        let head = self.head;
        *self.header(i) = Header { prev: NIL, next: head, ..*self.header(i) };
        if head != NIL {
            self.header(head).prev = i;
        }
        self.head = i;
        if self.tail == NIL {
            self.tail = i;
        }
    }

    /// The least recently used buffer, written out if dirty, ready to hold another block.
    fn victim(&mut self) -> u32 {
        let i = self.tail;
        if self.header(i).dirty {
            let block = self.header(i).block;
            let data = self.buffer(i).as_ptr() as u64;
            // SAFETY: FFI call; `data` is one live block.
            if unsafe { oxidebsd_block_write_batch(block as u64, 1, data) } != 0 {
                log("[oxfs] cache: write failed evicting a dirty block\n");
            }
            self.header(i).dirty = false;
        }
        i
    }

    /// Buffer `i` now holds `block`, most recently used.
    fn claim(&mut self, i: u32, block: u32) {
        self.rehash(i, block);
        self.header(i).dirty = false;
        self.touch(i);
    }

    /// The buffer holding `block`, read from the disk (with read-ahead) on a miss.
    fn get(&mut self, block: u32) -> u32 {
        if let Some(i) = self.lookup(block) {
            self.touch(i);
            return i;
        }
        let mut run = 1;
        while run < READ_AHEAD && block.checked_add(run as u32).is_some_and(|b| self.lookup(b).is_none()) {
            run += 1;
        }
        let stage = self.stage.as_mut_ptr() as u64;
        // SAFETY: FFI call; the staging area holds `STAGE_BLOCKS >= READ_AHEAD` blocks.
        if unsafe { oxidebsd_block_read_batch(block as u64, run as u64, stage) } != 0 {
            // Past the end of the device, most likely: read the block alone.
            run = 1;
            // SAFETY: as above.
            if unsafe { oxidebsd_block_read_batch(block as u64, 1, stage) } != 0 {
                log("[oxfs] cache: read failed\n");
                self.stage[0] = [0; BLOCK_SIZE];
            }
        }
        // Claim the read-ahead blocks first, so the wanted one ends up most recently used.
        let mut wanted = NIL;
        for k in (0..run).rev() {
            let i = self.victim();
            self.claim(i, block + k as u32);
            let staged = self.stage[k];
            *self.buffer(i) = staged;
            wanted = i;
        }
        wanted
    }

    /// The buffer for `block` without reading it: the caller overwrites the whole block.
    fn get_for_overwrite(&mut self, block: u32) -> u32 {
        if let Some(i) = self.lookup(block) {
            self.touch(i);
            return i;
        }
        let i = self.victim();
        self.claim(i, block);
        i
    }

    /// Writes the dirty buffers among `[start, start + len)`, a contiguous run at a time.
    fn write_run(&mut self, start: u32, len: u32) {
        let mut b = start;
        while b < start + len {
            let mut staged = 0;
            while staged < STAGE_BLOCKS && b + (staged as u32) < start + len {
                match self.lookup(b + staged as u32) {
                    Some(i) if self.header(i).dirty => {
                        let data = *self.buffer(i);
                        self.stage[staged] = data;
                        staged += 1;
                    }
                    _ => break,
                }
            }
            if staged == 0 {
                b += 1;
                continue;
            }
            let stage = self.stage.as_ptr() as u64;
            // SAFETY: FFI call; `staged` blocks are in the staging area.
            if unsafe { oxidebsd_block_write_batch(b as u64, staged as u64, stage) } != 0 {
                log("[oxfs] cache: write failed\n");
            }
            for k in 0..staged as u32 {
                if let Some(i) = self.lookup(b + k) {
                    self.header(i).dirty = false;
                }
            }
            b += staged as u32;
        }
    }
}

/// How many bytes of buffers a machine with `ram` bytes gets.
fn cache_bytes(ram: u64) -> u64 {
    (ram / 8).clamp(MIN_BYTES, MAX_BYTES)
}

/// Allocates the cache for a machine with `ram` bytes. Must run inside `module_init`.
pub fn init(ram: u64) -> bool {
    let count = (cache_bytes(ram) / BLOCK_SIZE as u64) as u32;
    let buckets = count.next_power_of_two();
    let header_bytes = count as u64 * core::mem::size_of::<Header>() as u64;
    // SAFETY: FFI calls to a kernel-exported function, matching its declared signature.
    let (data, headers, hash) = unsafe {
        (
            oxidebsd_module_alloc_zeroed(count as u64 * BLOCK_SIZE as u64),
            oxidebsd_module_alloc_zeroed(header_bytes),
            oxidebsd_module_alloc_zeroed(buckets as u64 * 4),
        )
    };
    if data == 0 || headers == 0 || hash == 0 {
        return false;
    }
    let c = cache();
    c.data = data as *mut [u8; BLOCK_SIZE];
    c.headers = headers as *mut Header;
    c.hash = hash as *mut u32;
    c.count = count;
    c.hash_mask = buckets - 1;
    for b in 0..buckets {
        *c.bucket_at(b) = NIL;
    }
    // Every buffer starts free, chained in LRU order 0 (most recent) .. count - 1.
    for i in 0..count {
        *c.header(i) = Header {
            block: FREE_BLOCK,
            dirty: false,
            prev: if i == 0 { NIL } else { i - 1 },
            next: if i + 1 == count { NIL } else { i + 1 },
            hash_next: NIL,
        };
    }
    c.head = 0;
    c.tail = count - 1;
    true
}

impl Cache {
    fn bucket_at(&mut self, slot: u32) -> &mut u32 {
        // SAFETY: `slot <= hash_mask`, inside the `init` allocation.
        unsafe { &mut *self.hash.add(slot as usize) }
    }
}

/// The cache's size in buffers, for the boot log.
pub fn buffers() -> u32 {
    cache().count
}

/// From now on, writes reach the disk before the system call returns (§3.3 until delayed writes).
pub fn set_write_through(on: bool) {
    cache().write_through = on;
}

/// Runs `f` on device block `block`'s contents. `f` must not use the cache.
pub fn with<R>(block: u32, f: impl FnOnce(&[u8; BLOCK_SIZE]) -> R) -> R {
    let c = cache();
    let i = c.get(block);
    f(c.buffer(i))
}

/// A copy of device block `block`.
pub fn read(block: u32) -> [u8; BLOCK_SIZE] {
    with(block, |b| *b)
}

/// Writes device block `block`: to the disk at once when write-through, else left dirty.
pub fn write(block: u32, data: &[u8; BLOCK_SIZE]) {
    store(block, data);
    if cache().write_through {
        cache().write_run(block, 1);
    }
}

/// Stores `data` as device block `block`, dirty, without writing it: the caller ends the run with
/// `flush_run`. Lets a long write go to the disk as a few large commands.
pub fn store(block: u32, data: &[u8; BLOCK_SIZE]) {
    let c = cache();
    let i = c.get_for_overwrite(block);
    *c.buffer(i) = *data;
    c.header(i).dirty = true;
}

/// Writes the dirty blocks of `[start, start + len)` when write-through; nothing before then
/// (`flush_all` writes them).
pub fn flush_run(start: u32, len: u32) {
    if len > 0 && cache().write_through {
        cache().write_run(start, len);
    }
}

/// Writes every dirty buffer, as contiguous runs.
pub fn flush_all() -> u32 {
    let c = cache();
    let mut written = 0;
    for i in 0..c.count {
        if !c.header(i).dirty {
            continue;
        }
        // Start each run at its first dirty block, so runs aren't split in the middle.
        let mut start = c.header(i).block;
        while start > 0 && c.lookup(start - 1).is_some_and(|j| c.header(j).dirty) {
            start -= 1;
        }
        let mut len = 0;
        while c.lookup(start + len).is_some_and(|j| c.header(j).dirty) {
            len += 1;
        }
        c.write_run(start, len);
        written += len;
    }
    written
}

/// Forgets every buffer (dirty ones included): the disk changed underneath the cache.
pub fn invalidate_all() {
    let c = cache();
    for i in 0..c.count {
        c.unhash(i);
        let h = c.header(i);
        h.block = FREE_BLOCK;
        h.dirty = false;
        h.hash_next = NIL;
    }
}
