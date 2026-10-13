//! The buffer cache (`OxideBSD-doc/RAM_FLOOR.md` §3.2-3.3): a fixed set of 4 KiB buffers, sized
//! from RAM at boot, holding recently used blocks of the data disk. Every disk block oxfs touches
//! -- superblock aside -- goes through here by its *device* block number: data blocks, the inode
//! file, directories, index blocks and the block-used bitmap alike. A miss evicts the least
//! recently used buffer and reads the block (and a few after it, `READ_AHEAD`) from the disk.
//!
//! A buffer is dirty when it holds a write the disk hasn't seen. `write` puts a block on the disk
//! before returning (structural metadata, §3.3.1); `store` leaves it dirty, tagged with what it is
//! (`Kind`), for a later flush (a regular file's data, index blocks and inode record, §3.3.2).
//! While the filesystem is being formatted (`write_through` false) even `write` only stores, and
//! `flush_all` writes everything at the end.
//!
//! **Ordering (§3.3.3): a pointer never reaches the disk before what it points at.** Before an
//! inode-file block is written, the dirty data and index blocks of the inodes in it are; before an
//! index block is, its file's dirty data blocks are. Every path to the disk -- `write`, a flush,
//! evicting a dirty buffer -- goes through `write_buffer`, which does that first. So after a crash
//! an inode on disk points only at blocks holding its own data (an older size at worst), never at
//! another file's freed contents.
//!
//! Modules have no `alloc`: the buffers, their headers and the hash table come from
//! `oxidebsd_module_alloc_zeroed` in `init`, which must run inside `module_init`. Everything is
//! single-core and syscall-serialized, like the rest of oxfs, and nothing may call back into the
//! cache from inside a `with` closure (that's what makes lending the buffer safe).

use crate::{BLOCK_SIZE, log, oxidebsd_block_read_batch, oxidebsd_block_write_batch, oxidebsd_module_alloc_zeroed};

/// "No buffer" in the LRU, dirty and hash links.
const NIL: u32 = u32::MAX;
/// A buffer whose `block` means nothing yet.
const FREE_BLOCK: u32 = u32::MAX;
/// Blocks read in one command on a miss: the missed block plus up to this many after it, stopping
/// at one that's already cached. Programs and files are mostly laid out contiguously
/// (`alloc_block` is a forward cursor), so the next blocks are usually wanted next.
const READ_AHEAD: usize = 16;
/// Largest run written in one command: the staging buffer's size.
const STAGE_BLOCKS: usize = 32;
/// The cache's size: `RAM / 8`, between these.
const MIN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Inodes per inode-file block (`INODES_PER_BLOCK` in the crate root).
const INODES_PER_BLOCK: u32 = 32;

/// What a dirty buffer holds, for the write ordering.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Anything written synchronously, or during a format: no ordering.
    Meta,
    /// A data block of regular file `owner`.
    Data(u32),
    /// An index (indirect) block of regular file `owner`.
    Index(u32),
    /// An inode-file block holding inodes `first .. first + INODES_PER_BLOCK`.
    Inodes(u32),
}

#[derive(Clone, Copy)]
struct Header {
    block: u32,
    dirty: bool,
    kind: Kind,
    /// LRU neighbours: `prev` toward the most recently used end.
    prev: u32,
    next: u32,
    /// Next buffer in the same hash chain.
    hash_next: u32,
    /// Dirty-list neighbours, while `dirty`.
    dirty_prev: u32,
    dirty_next: u32,
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
    /// First dirty buffer, and how many there are.
    dirty_head: u32,
    dirty_count: u32,
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
    dirty_head: NIL,
    dirty_count: 0,
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
        let slot = block.wrapping_mul(0x9E37_79B1) & self.hash_mask;
        self.bucket_at(slot)
    }

    fn bucket_at(&mut self, slot: u32) -> &mut u32 {
        // SAFETY: `slot <= hash_mask`, inside the `init` allocation.
        unsafe { &mut *self.hash.add(slot as usize) }
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
        let h = self.header(i);
        h.prev = NIL;
        h.next = head;
        if head != NIL {
            self.header(head).prev = i;
        }
        self.head = i;
        if self.tail == NIL {
            self.tail = i;
        }
    }

    fn mark_dirty(&mut self, i: u32, kind: Kind) {
        self.header(i).kind = kind;
        if self.header(i).dirty {
            return;
        }
        let head = self.dirty_head;
        let h = self.header(i);
        h.dirty = true;
        h.dirty_prev = NIL;
        h.dirty_next = head;
        if head != NIL {
            self.header(head).dirty_prev = i;
        }
        self.dirty_head = i;
        self.dirty_count += 1;
    }

    fn mark_clean(&mut self, i: u32) {
        if !self.header(i).dirty {
            return;
        }
        let Header { dirty_prev, dirty_next, .. } = *self.header(i);
        if dirty_prev == NIL { self.dirty_head = dirty_next } else { self.header(dirty_prev).dirty_next = dirty_next }
        if dirty_next != NIL {
            self.header(dirty_next).dirty_prev = dirty_prev;
        }
        let h = self.header(i);
        h.dirty = false;
        h.kind = Kind::Meta;
        self.dirty_count -= 1;
    }

    /// Writes every dirty buffer `wanted` picks out, after what it depends on.
    fn write_where(&mut self, wanted: impl Fn(Kind) -> bool) {
        let mut i = self.dirty_head;
        while i != NIL {
            let next = self.header(i).dirty_next;
            if !wanted(self.header(i).kind) {
                i = next;
                continue;
            }
            self.write_buffer(i);
            // Writing `i` may have cleaned others (its run, its dependencies): carry on from
            // `next` while it's still on the list, else start over.
            i = if next != NIL && self.header(next).dirty { next } else { self.dirty_head };
        }
    }

    /// Writes what buffer `i`'s contents point at, so `i` itself can go to the disk.
    fn write_dependencies(&mut self, kind: Kind) {
        match kind {
            Kind::Meta | Kind::Data(_) => {}
            Kind::Index(owner) => self.write_where(|k| k == Kind::Data(owner)),
            Kind::Inodes(first) => {
                let mine = |owner: u32| owner.wrapping_sub(first) < INODES_PER_BLOCK;
                self.write_where(|k| matches!(k, Kind::Data(o) if mine(o)));
                self.write_where(|k| matches!(k, Kind::Index(o) if mine(o)));
            }
        }
    }

    /// Writes dirty buffer `i` (with its dependencies first), together with any dirty buffers
    /// right after it that need nothing written first, in one command.
    fn write_buffer(&mut self, i: u32) {
        let kind = self.header(i).kind;
        self.write_dependencies(kind);
        if !self.header(i).dirty {
            return;
        }
        let start = self.header(i).block;
        let first = *self.buffer(i);
        self.stage[0] = first;
        let mut run = 1;
        while run < STAGE_BLOCKS {
            match start.checked_add(run as u32).and_then(|b| self.lookup(b)) {
                Some(j) if self.header(j).dirty && matches!(self.header(j).kind, Kind::Meta | Kind::Data(_)) => {
                    let data = *self.buffer(j);
                    self.stage[run] = data;
                    run += 1;
                }
                _ => break,
            }
        }
        let stage = self.stage.as_ptr() as u64;
        // SAFETY: FFI call; `run` blocks are in the staging area.
        if unsafe { oxidebsd_block_write_batch(start as u64, run as u64, stage) } != 0 {
            log("[oxfs] cache: write failed\n");
        }
        for k in 0..run as u32 {
            if let Some(j) = self.lookup(start + k) {
                self.mark_clean(j);
            }
        }
    }

    /// The least recently used buffer, written out first if dirty, ready to hold another block.
    fn victim(&mut self) -> u32 {
        let i = self.tail;
        if self.header(i).dirty {
            self.write_buffer(i);
        }
        i
    }

    /// Buffer `i` now holds `block`, clean, most recently used.
    fn claim(&mut self, i: u32, block: u32) {
        self.rehash(i, block);
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
        // Evict first: a dirty victim's write uses the staging area this read fills.
        let mut victims = [NIL; READ_AHEAD];
        for slot in victims.iter_mut().take(run) {
            let i = self.victim();
            // Out of the LRU's tail, so the next `victim` picks another buffer.
            self.touch(i);
            *slot = i;
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
        for k in (0..run).rev() {
            let i = victims[k];
            self.claim(i, block + k as u32);
            let staged = self.stage[k];
            *self.buffer(i) = staged;
        }
        victims[0]
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
            kind: Kind::Meta,
            prev: if i == 0 { NIL } else { i - 1 },
            next: if i + 1 == count { NIL } else { i + 1 },
            hash_next: NIL,
            dirty_prev: NIL,
            dirty_next: NIL,
        };
    }
    c.head = 0;
    c.tail = count - 1;
    true
}

/// The cache's size in buffers, for the boot log.
pub fn buffers() -> u32 {
    cache().count
}

/// Whether more than half the cache is dirty: the writer should flush (back-pressure, §3.2.5).
pub fn mostly_dirty() -> bool {
    let c = cache();
    c.dirty_count > c.count / 2
}

/// From now on, `write` reaches the disk before returning (until now, during a format, it only
/// stores).
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

/// Writes device block `block` (`kind` says what it is) to the disk before returning, after
/// anything it points at. While formatting, only stores it.
pub fn write(block: u32, data: &[u8; BLOCK_SIZE], kind: Kind) {
    let c = cache();
    let i = c.get_for_overwrite(block);
    *c.buffer(i) = *data;
    c.mark_dirty(i, kind);
    if c.write_through {
        c.write_buffer(i);
    }
}

/// Stores `data` as device block `block`, dirty, for a later flush (§3.3.2).
pub fn store(block: u32, data: &[u8; BLOCK_SIZE], kind: Kind) {
    let c = cache();
    let i = c.get_for_overwrite(block);
    *c.buffer(i) = *data;
    c.mark_dirty(i, kind);
}

/// Drops device block `block` from the cache without writing it: the block was freed.
pub fn discard(block: u32) {
    let c = cache();
    if let Some(i) = c.lookup(block) {
        c.mark_clean(i);
    }
}

/// Drops the dirty data and index blocks of file `owner` without writing them: it's being freed.
pub fn discard_owned(owner: u32) {
    let c = cache();
    let mut i = c.dirty_head;
    while i != NIL {
        let next = c.header(i).dirty_next;
        if matches!(c.header(i).kind, Kind::Data(o) | Kind::Index(o) if o == owner) {
            c.mark_clean(i);
        }
        i = next;
    }
}

/// `fsync(2)` of file `owner`, whose record is in inode-file block `inode_block`: its data, its
/// index blocks, then that block.
pub fn flush_file(owner: u32, inode_block: Option<u32>) {
    let c = cache();
    c.write_where(|k| k == Kind::Data(owner));
    c.write_where(|k| k == Kind::Index(owner));
    if let Some(block) = inode_block
        && let Some(i) = c.lookup(block)
        && c.header(i).dirty
    {
        c.write_buffer(i);
    }
}

/// Writes every dirty buffer: data first, then index blocks, then inode-file blocks, then the
/// rest. Returns how many were dirty.
pub fn flush_all() -> u32 {
    let c = cache();
    let dirty = c.dirty_count;
    c.write_where(|k| matches!(k, Kind::Data(_)));
    c.write_where(|k| matches!(k, Kind::Index(_)));
    c.write_where(|k| matches!(k, Kind::Inodes(_)));
    c.write_where(|_| true);
    dirty
}

/// Forgets every buffer (dirty ones included): the disk changed underneath the cache.
pub fn invalidate_all() {
    let c = cache();
    for i in 0..c.count {
        c.mark_clean(i);
        c.unhash(i);
        let h = c.header(i);
        h.block = FREE_BLOCK;
        h.hash_next = NIL;
    }
}
