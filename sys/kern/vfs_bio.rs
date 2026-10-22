//! The buffer cache (FreeBSD's `buf` layer in miniature, OxideBSD-doc `VFS.md` §7.4): recently
//! used blocks of every block device (`vfs_bdev`), shared by the file systems on them. A buffer is
//! `(device, block, size)`: the block in 512-byte sectors, the size any whole number of sectors up
//! to `MAXBSIZE`, each file system choosing its own (oxfs 4 KiB, msdosfs its cluster). As on
//! FreeBSD, a file system never reads overlapping buffers of different sizes; asking for a cached
//! block at another size writes it out (if dirty) and reads it again at the new one.
//!
//! **Memory.** Each buffer owns a fixed `MAXBSIZE` slot of a kernel window (one level-4 slot, its
//! level-3 table made at boot, `reserve_window`), and only the pages its size needs are mapped in.
//! The cache may hold `RAM / 8` bytes of pages, between 2 and 512 MiB (oxfs's old `bcache.rs`'s
//! sizing); a miss past that evicts the least recently used buffers that nobody holds.
//!
//! **Use.** `bread`/`getblk` hand out a buffer held (busy) until `brelse`, `bwrite` or `bdwrite`
//! gives it back; a held buffer is never evicted. `bwrite` writes now, `bdwrite` leaves the buffer
//! dirty with a file system `tag` for later, when it's evicted or flushed (`bflush`).
//!
//! **Write ordering (decided 2026-10-16: FreeBSD's `bioops`/soft updates shape).** A file system
//! may set a pre-write hook for its device (`set_hook`). Before any dirty buffer of that device
//! goes to the disk -- `bwrite`, eviction, a flush -- the cache calls the hook with the buffer's
//! block and tag, and the hook writes what the buffer depends on first (through the cache, so
//! recursively). The hook's answer says whether the buffer may share one disk command with the
//! dirty buffers next to it (`HOOK_CLUSTER`): blocks in one command can reach the disk in any
//! order, so a block others must precede goes alone. Without a hook, every dirty buffer clusters
//! and nothing is ordered.
//!
//! **Locking.** Disk transfers can sleep, so no spin lock may be held across them; the cache is
//! the filesystem lock's (`fs::fslock`) to protect, like the file systems that use it: every
//! caller holds it (modules marked `oxidebsd_module_serialize`, or a `module_init`, which runs
//! alone at boot). The state is a `static mut` accessed only that way, on one core.

use alloc::vec::Vec;

use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, Size4KiB,
};

use crate::kern::vfs_bdev::{self, SECTOR};
use crate::syscall::{EINVAL, EIO, ENOMEM};

/// The largest buffer: FreeBSD's `MAXBSIZE`.
pub(crate) const MAXBSIZE: u64 = 64 * 1024;
const PAGE: u64 = 4096;
/// Level-4 slot 387, after the heap's 386.
const WINDOW_BASE: u64 = 0xffff_c180_0000_0000;
const WINDOW_SIZE: u64 = 512 << 30;
/// Read-ahead on a miss and write clustering stop at this many bytes in one disk command.
const MAX_RUN_BYTES: u64 = 128 * 1024;
const MIN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_BYTES: u64 = 512 * 1024 * 1024;

const NIL: u32 = u32::MAX;

/// The pre-write hook's answer: this buffer may go out in one command with its neighbours.
pub(crate) const HOOK_CLUSTER: i64 = 1;

/// `(device, block, tag) -> HOOK_*`: writes what the buffer depends on, through the cache.
pub(crate) type Hook = extern "C" fn(u64, u64, u64) -> i64;

#[derive(Clone, Copy)]
struct Buf {
    dev: u32,
    /// In sectors.
    blkno: u64,
    /// In bytes; `0` while the buffer holds nothing.
    size: u32,
    /// Pages mapped into its slot.
    pages: u32,
    valid: bool,
    dirty: bool,
    tag: u64,
    /// Holders (`bread`/`getblk` until `brelse`), and the cache itself while writing it.
    busy: u32,
    /// LRU neighbours (`prev` toward the most recently used end), or the free list's `next`.
    prev: u32,
    next: u32,
    hash_next: u32,
    dirty_prev: u32,
    dirty_next: u32,
}

const EMPTY: Buf = Buf {
    dev: 0,
    blkno: 0,
    size: 0,
    pages: 0,
    valid: false,
    dirty: false,
    tag: 0,
    busy: 0,
    prev: NIL,
    next: NIL,
    hash_next: NIL,
    dirty_prev: NIL,
    dirty_next: NIL,
};

struct Cache {
    bufs: Vec<Buf>,
    hash: Vec<u32>,
    head: u32,
    tail: u32,
    free: u32,
    dirty_head: u32,
    dirty_pages: u64,
    pages: u64,
    budget: u64,
    hooks: Vec<(u32, Hook)>,
    stage: Vec<u8>,
}

static mut CACHE: Option<Cache> = None;

/// Makes the window's level-3 table in the boot page tables, before the first `AddressSpace`
/// copies the kernel's level-4 entries (as `memory::kstack::reserve_window`).
pub fn reserve_window(mapper: &mut OffsetPageTable<'static>, frame_allocator: &mut impl FrameAllocator<Size4KiB>) {
    let index = VirtAddr::new(WINDOW_BASE).p4_index();
    let offset = mapper.phys_offset();
    let entry = &mut mapper.level_4_table_mut()[index];
    if !entry.is_unused() {
        panic!("buffer cache window's level-4 slot is already in use");
    }
    let frame = frame_allocator.allocate_frame().expect("no frame for the buffer cache window's level-3 table");
    // SAFETY: a freshly allocated frame, reachable through the physical-memory window.
    unsafe { (offset + frame.start_address().as_u64()).as_mut_ptr::<PageTable>().write(PageTable::new()) };
    // Buffers hold data only: no-execute at the top level covers the whole window.
    entry.set_frame(frame, PageTableFlags::PRESENT | PageTableFlags::WRITABLE | crate::cpu::nx::no_execute());
}

fn cache() -> &'static mut Cache {
    // SAFETY: single-core, under the filesystem lock (see the module doc comment); no caller holds
    // a reference across a call that takes another.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(CACHE) };
    slot.get_or_insert_with(|| {
        let budget = (crate::memory::usable_ram_bytes() / 8).clamp(MIN_BYTES, MAX_BYTES) / PAGE;
        let count = budget.min(WINDOW_SIZE / MAXBSIZE) as u32;
        let mut bufs = alloc::vec![EMPTY; count as usize];
        for (i, b) in bufs.iter_mut().enumerate() {
            b.next = if i + 1 == count as usize { NIL } else { i as u32 + 1 };
        }
        let buckets = count.next_power_of_two() as usize;
        Cache {
            bufs,
            hash: alloc::vec![NIL; buckets],
            head: NIL,
            tail: NIL,
            free: 0,
            dirty_head: NIL,
            dirty_pages: 0,
            pages: 0,
            budget,
            hooks: Vec::new(),
            stage: Vec::new(),
        }
    })
}

/// A page-table view of the active level-4 table.
fn mapper() -> Option<OffsetPageTable<'static>> {
    let offset = crate::memory::try_phys_mem_offset()?;
    let (l4, _) = x86_64::registers::control::Cr3::read();
    // SAFETY: CR3's level-4 table is live and reachable through the physical-memory window; only
    // the buffer window's entries are touched through this view, on one core.
    let table = unsafe { &mut *(offset + l4.start_address().as_u64()).as_mut_ptr::<PageTable>() };
    // SAFETY: as above.
    Some(unsafe { OffsetPageTable::new(table, offset) })
}

fn slot_addr(i: u32) -> u64 {
    WINDOW_BASE + i as u64 * MAXBSIZE
}

fn pages_for(size: u32) -> u32 {
    (size as u64).div_ceil(PAGE) as u32
}

impl Cache {
    fn bucket(&self, dev: u32, blkno: u64) -> usize {
        let h = (blkno ^ ((dev as u64) << 40)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (h >> 32) as usize & (self.hash.len() - 1)
    }

    fn lookup(&self, dev: u32, blkno: u64) -> Option<u32> {
        let mut i = self.hash[self.bucket(dev, blkno)];
        while i != NIL {
            let b = &self.bufs[i as usize];
            if b.size != 0 && b.dev == dev && b.blkno == blkno {
                return Some(i);
            }
            i = b.hash_next;
        }
        None
    }

    fn hash_insert(&mut self, i: u32) {
        let (dev, blkno) = (self.bufs[i as usize].dev, self.bufs[i as usize].blkno);
        let slot = self.bucket(dev, blkno);
        self.bufs[i as usize].hash_next = self.hash[slot];
        self.hash[slot] = i;
    }

    fn hash_remove(&mut self, i: u32) {
        let (dev, blkno) = (self.bufs[i as usize].dev, self.bufs[i as usize].blkno);
        let slot = self.bucket(dev, blkno);
        let next = self.bufs[i as usize].hash_next;
        if self.hash[slot] == i {
            self.hash[slot] = next;
            return;
        }
        let mut j = self.hash[slot];
        while j != NIL {
            if self.bufs[j as usize].hash_next == i {
                self.bufs[j as usize].hash_next = next;
                return;
            }
            j = self.bufs[j as usize].hash_next;
        }
    }

    fn lru_remove(&mut self, i: u32) {
        let Buf { prev, next, .. } = self.bufs[i as usize];
        if prev == NIL { self.head = next } else { self.bufs[prev as usize].next = next }
        if next == NIL { self.tail = prev } else { self.bufs[next as usize].prev = prev }
    }

    fn lru_push_head(&mut self, i: u32) {
        let head = self.head;
        let b = &mut self.bufs[i as usize];
        b.prev = NIL;
        b.next = head;
        if head != NIL {
            self.bufs[head as usize].prev = i;
        }
        self.head = i;
        if self.tail == NIL {
            self.tail = i;
        }
    }

    /// Marks buffer `i` most recently used.
    fn touch(&mut self, i: u32) {
        if self.head != i {
            self.lru_remove(i);
            self.lru_push_head(i);
        }
    }

    fn mark_dirty(&mut self, i: u32, tag: u64) {
        self.bufs[i as usize].tag = tag;
        if self.bufs[i as usize].dirty {
            return;
        }
        let head = self.dirty_head;
        let b = &mut self.bufs[i as usize];
        b.dirty = true;
        b.dirty_prev = NIL;
        b.dirty_next = head;
        let pages = b.pages as u64;
        if head != NIL {
            self.bufs[head as usize].dirty_prev = i;
        }
        self.dirty_head = i;
        self.dirty_pages += pages;
    }

    fn mark_clean(&mut self, i: u32) {
        if !self.bufs[i as usize].dirty {
            return;
        }
        let Buf { dirty_prev, dirty_next, pages, .. } = self.bufs[i as usize];
        if dirty_prev == NIL { self.dirty_head = dirty_next } else { self.bufs[dirty_prev as usize].dirty_next = dirty_next }
        if dirty_next != NIL {
            self.bufs[dirty_next as usize].dirty_prev = dirty_prev;
        }
        let b = &mut self.bufs[i as usize];
        b.dirty = false;
        b.tag = 0;
        self.dirty_pages -= pages as u64;
    }

    /// Maps or unmaps pages so buffer `i`'s slot holds `want` of them. `false` when frames run out.
    fn set_pages(&mut self, i: u32, want: u32) -> bool {
        let have = self.bufs[i as usize].pages;
        if have == want {
            return true;
        }
        let Some(mut mapper) = mapper() else { return false };
        let base = slot_addr(i);
        if want > have {
            let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | crate::cpu::nx::no_execute();
            for p in have..want {
                let page = Page::<Size4KiB>::containing_address(VirtAddr::new(base + p as u64 * PAGE));
                let Some(frame) = crate::memory::allocate_frame() else { return false };
                // SAFETY: this page of the slot is unmapped (only `pages` of it are mapped).
                match unsafe { mapper.map_to(page, frame, flags, &mut crate::memory::GlobalFrameAllocator) } {
                    Ok(flush) => flush.ignore(), // never mapped since its last unmap's flush
                    Err(_) => {
                        // SAFETY: never mapped.
                        unsafe { crate::memory::free_frame(frame) };
                        return false;
                    }
                }
                self.bufs[i as usize].pages = p + 1;
                self.pages += 1;
            }
        } else {
            for p in want..have {
                let page = Page::<Size4KiB>::containing_address(VirtAddr::new(base + p as u64 * PAGE));
                if let Ok((frame, flush)) = mapper.unmap(page) {
                    flush.flush();
                    // SAFETY: the buffer's only mapping, just removed.
                    unsafe { crate::memory::free_frame(frame) };
                }
                self.pages -= 1;
            }
            self.bufs[i as usize].pages = want;
        }
        true
    }

    fn data(&mut self, i: u32) -> &'static mut [u8] {
        let size = self.bufs[i as usize].size as usize;
        // SAFETY: `pages_for(size)` pages of the slot are mapped, writable, and only this buffer
        // uses them; the caller holds the buffer.
        unsafe { core::slice::from_raw_parts_mut(slot_addr(i) as *mut u8, size) }
    }

    /// Empties buffer `i` (written first if dirty) and puts it on the free list.
    fn evict(&mut self, i: u32) -> bool {
        if self.bufs[i as usize].dirty {
            self.write_buffer(i);
        }
        // Writing its dependencies may have taken a hold on it (a hook reading it): keep it then.
        if self.bufs[i as usize].busy != 0 {
            return false;
        }
        self.hash_remove(i);
        self.lru_remove(i);
        self.set_pages(i, 0);
        let free = self.free;
        let b = &mut self.bufs[i as usize];
        *b = EMPTY;
        b.next = free;
        self.free = i;
        true
    }

    /// The least recently used buffer nobody holds.
    fn victim(&self) -> Option<u32> {
        let mut i = self.tail;
        while i != NIL && self.bufs[i as usize].busy != 0 {
            i = self.bufs[i as usize].prev;
        }
        (i != NIL).then_some(i)
    }

    /// An empty buffer slot with room in the budget for `pages` pages, evicting what it must.
    fn take_empty(&mut self, pages: u32) -> Result<u32, u64> {
        while self.free == NIL || self.pages + pages as u64 > self.budget {
            let i = self.victim().ok_or(ENOMEM)?;
            if !self.evict(i) {
                self.touch(i);
            }
        }
        let i = self.free;
        self.free = self.bufs[i as usize].next;
        Ok(i)
    }

    /// Buffer `(dev, blkno, size)`, held, from the cache or freshly empty (`valid` false).
    fn getblk(&mut self, dev: u32, blkno: u64, size: u32) -> Result<u32, u64> {
        if size == 0 || size as u64 > MAXBSIZE || size as u64 % SECTOR != 0 {
            return Err(EINVAL);
        }
        if let Some(i) = self.lookup(dev, blkno) {
            if self.bufs[i as usize].size == size {
                self.bufs[i as usize].busy += 1;
                self.touch(i);
                return Ok(i);
            }
            // The same block at another size: out with the old buffer.
            if self.bufs[i as usize].busy != 0 {
                return Err(EINVAL);
            }
            if !self.evict(i) {
                return Err(EINVAL);
            }
        }
        let pages = pages_for(size);
        let i = self.take_empty(pages)?;
        {
            let b = &mut self.bufs[i as usize];
            b.dev = dev;
            b.blkno = blkno;
            b.size = size;
            b.busy = 1;
        }
        if !self.set_pages(i, pages) {
            self.set_pages(i, 0);
            let free = self.free;
            self.bufs[i as usize] = Buf { next: free, ..EMPTY };
            self.free = i;
            return Err(ENOMEM);
        }
        self.hash_insert(i);
        self.lru_push_head(i);
        Ok(i)
    }

    fn release(&mut self, i: u32) {
        let b = &mut self.bufs[i as usize];
        b.busy = b.busy.saturating_sub(1);
    }

    fn hook(&self, dev: u32) -> Option<Hook> {
        self.hooks.iter().find(|(d, _)| *d == dev).map(|&(_, h)| h)
    }

    /// Asks dirty buffer `i`'s file system to write what it depends on; whether it may cluster.
    fn prepare(&mut self, i: u32) -> bool {
        let Buf { dev, blkno, tag, .. } = self.bufs[i as usize];
        let Some(hook) = self.hook(dev) else { return true };
        self.bufs[i as usize].busy += 1;
        let answer = hook(dev as u64, blkno, tag);
        self.release(i);
        answer & HOOK_CLUSTER != 0
    }

    /// Whether `j` is a dirty buffer of `dev` sized `size` that may go out with others.
    fn joins(&mut self, j: u32, dev: u32, size: u32) -> bool {
        let b = self.bufs[j as usize];
        b.dirty && b.busy == 0 && b.dev == dev && b.size == size && self.prepare(j) && self.bufs[j as usize].dirty
    }

    /// Writes dirty buffer `i` to the disk, its dependencies first (the hook), with the dirty
    /// buffers around it that may cluster, up to `MAX_RUN_BYTES` in one command.
    fn write_buffer(&mut self, i: u32) -> bool {
        let clusters = self.prepare(i);
        if !self.bufs[i as usize].dirty {
            return true;
        }
        let Buf { dev, blkno, size, .. } = self.bufs[i as usize];
        let step = size as u64 / SECTOR;
        let max = (MAX_RUN_BYTES / size as u64).max(1);
        self.bufs[i as usize].busy += 1;
        let mut run: Vec<u32> = alloc::vec![i];
        let mut start = blkno;
        if clusters {
            while (run.len() as u64) < max
                && let Some(j) = start.checked_sub(step).and_then(|b| self.lookup(dev, b))
                && self.joins(j, dev, size)
            {
                self.bufs[j as usize].busy += 1;
                run.insert(0, j);
                start -= step;
            }
            while (run.len() as u64) < max
                && let Some(j) = self.lookup(dev, start + run.len() as u64 * step)
                && self.joins(j, dev, size)
            {
                self.bufs[j as usize].busy += 1;
                run.push(j);
            }
        }
        let mut stage = core::mem::take(&mut self.stage);
        stage.clear();
        for &j in &run {
            let data = self.data(j);
            stage.extend_from_slice(data);
        }
        let ok = vfs_bdev::write(dev, start, &stage).is_ok();
        self.stage = stage;
        if !ok {
            // Logged and dropped, as oxfs's cache did: kept dirty, a flush would retry it forever.
            crate::serial_println!("[bio] write of {} sectors at {} failed", run.len() as u64 * step, start);
        }
        for &j in &run {
            self.mark_clean(j);
            self.release(j);
        }
        ok
    }

    /// Fills held buffer `i` from the disk, with up to `ahead` uncached blocks after it of the same
    /// size in the same command (read-ahead), stopping at the device's end.
    fn fill(&mut self, i: u32, ahead: u32) -> Result<(), u64> {
        let Buf { dev, blkno, size, .. } = self.bufs[i as usize];
        let step = size as u64 / SECTOR;
        let sectors = vfs_bdev::extent(dev).map_or(0, |(_, s, _)| s);
        let max = (MAX_RUN_BYTES / size as u64).max(1).min(ahead as u64 + 1);
        let mut run: Vec<u32> = alloc::vec![i];
        while (run.len() as u64) < max {
            let b = blkno + run.len() as u64 * step;
            if b + step > sectors || self.lookup(dev, b).is_some() {
                break;
            }
            match self.getblk(dev, b, size) {
                Ok(j) => run.push(j),
                Err(_) => break,
            }
        }
        let mut stage = core::mem::take(&mut self.stage);
        stage.clear();
        stage.resize(run.len() * size as usize, 0);
        let mut result = vfs_bdev::read(dev, blkno, &mut stage);
        if result.is_err() && run.len() > 1 {
            // Past the end, or a bad block among the read-ahead: the wanted block alone.
            result = vfs_bdev::read(dev, blkno, &mut stage[..size as usize]);
            for &j in &run[1..] {
                self.release(j);
                let _ = self.evict(j);
            }
            run.truncate(1);
        }
        if result.is_ok() {
            for (k, &j) in run.iter().enumerate() {
                let at = k * size as usize;
                self.data(j).copy_from_slice(&stage[at..at + size as usize]);
                self.bufs[j as usize].valid = true;
            }
        }
        self.stage = stage;
        // Read-ahead buffers are released, right behind the wanted one in the LRU.
        for &j in &run[1..] {
            self.release(j);
        }
        self.touch(i);
        result.map_err(|_| EIO)
    }

    /// Writes every dirty buffer of `dev` whose tag matches `mask`/`value`, each after its
    /// dependencies.
    fn flush(&mut self, dev: u32, mask: u64, value: u64) {
        let mut i = self.dirty_head;
        while i != NIL {
            let b = self.bufs[i as usize];
            let next = b.dirty_next;
            if b.dev != dev || b.tag & mask != value || b.busy != 0 {
                i = next;
                continue;
            }
            self.write_buffer(i);
            // Writing `i` may have cleaned others (its run, its dependencies): carry on from
            // `next` while it's still on the list, else start over.
            i = if next != NIL && self.bufs[next as usize].dirty { next } else { self.dirty_head };
        }
    }
}

/// `bread(9)`: block `blkno` (sectors) of device `dev`, `size` bytes, read from the disk on a
/// miss with up to `ahead` blocks after it; held until `brelse`/`bwrite`/`bdwrite`.
pub(crate) fn bread(dev: u32, blkno: u64, size: u32, ahead: u32) -> Result<u32, u64> {
    let c = cache();
    let i = c.getblk(dev, blkno, size)?;
    if !c.bufs[i as usize].valid
        && let Err(e) = c.fill(i, ahead)
    {
        c.release(i);
        return Err(e);
    }
    Ok(i)
}

/// `getblk(9)`: as `bread` without reading: the caller overwrites the whole block.
pub(crate) fn getblk(dev: u32, blkno: u64, size: u32) -> Result<u32, u64> {
    let c = cache();
    let i = c.getblk(dev, blkno, size)?;
    c.bufs[i as usize].valid = true;
    Ok(i)
}

/// `brelse(9)`: gives a held buffer back, unchanged (dirty stays dirty).
pub(crate) fn brelse(b: u32) {
    cache().release(b);
}

/// `bdwrite(9)`: marks a held buffer dirty with `tag` and gives it back; it reaches the disk when
/// evicted or flushed, after what its file system's hook says it depends on.
pub(crate) fn bdwrite(b: u32, tag: u64) {
    let c = cache();
    c.mark_dirty(b, tag);
    c.release(b);
}

/// `bwrite(9)`: writes a held buffer (tagged `tag`) now, its dependencies first, and gives it
/// back. `EIO` if the disk refused it (it stays dirty).
pub(crate) fn bwrite(b: u32, tag: u64) -> Result<(), u64> {
    let c = cache();
    c.mark_dirty(b, tag);
    // The caller's hold keeps it out of clusters it didn't ask for: release it first.
    c.release(b);
    if c.write_buffer(b) { Ok(()) } else { Err(EIO) }
}

/// Writes every dirty buffer of `dev` whose tag matches `mask`/`value` (`0`/`0`: all).
pub(crate) fn bflush(dev: u32, mask: u64, value: u64) {
    cache().flush(dev, mask, value);
}

/// Forgets the dirty contents of `dev`'s buffers whose tag matches: the blocks were freed.
pub(crate) fn bdiscard(dev: u32, mask: u64, value: u64) {
    let c = cache();
    let mut i = c.dirty_head;
    while i != NIL {
        let b = c.bufs[i as usize];
        if b.dev == dev && b.tag & mask == value {
            c.mark_clean(i);
        }
        i = b.dirty_next;
    }
}

/// Forgets block `blkno` of `dev` without writing it (freed).
pub(crate) fn binval(dev: u32, blkno: u64) {
    let c = cache();
    if let Some(i) = c.lookup(dev, blkno) {
        c.mark_clean(i);
    }
}

/// Forgets every buffer of `dev`, dirty ones included: the disk changed underneath the cache.
pub(crate) fn binvalall(dev: u32) {
    let c = cache();
    let mine: Vec<u32> = (0..c.bufs.len() as u32).filter(|&i| c.bufs[i as usize].size != 0 && c.bufs[i as usize].dev == dev).collect();
    for i in mine {
        c.mark_clean(i);
        c.bufs[i as usize].busy = 0;
        let _ = c.evict(i);
    }
}

/// Whether more than half the cache's budget is dirty: writers should flush (back-pressure).
pub(crate) fn mostly_dirty() -> bool {
    let c = cache();
    c.dirty_pages > c.budget / 2
}

/// Sets device `dev`'s pre-write hook (`Hook`), replacing any.
pub(crate) fn set_hook(dev: u32, hook: Hook) {
    let c = cache();
    c.hooks.retain(|(d, _)| *d != dev);
    c.hooks.push((dev, hook));
}

/// `(bytes cached, bytes dirty, budget)`: `vfs.bufspace`, `vfs.dirtybufspace`, `vfs.maxbufspace`.
pub(crate) fn stats() -> (u64, u64, u64) {
    let c = cache();
    (c.pages * PAGE, c.dirty_pages * PAGE, c.budget * PAGE)
}

fn ret(r: Result<u32, u64>) -> i64 {
    match r {
        Ok(b) => b as i64,
        Err(e) => -(e as i64),
    }
}

// The module interface: buffers by number, contents by address.

pub(crate) extern "C" fn oxidebsd_bread(dev: u64, blkno: u64, size: u64, ahead: u64) -> i64 {
    ret(bread(dev as u32, blkno, size as u32, ahead as u32))
}

pub(crate) extern "C" fn oxidebsd_getblk(dev: u64, blkno: u64, size: u64) -> i64 {
    ret(getblk(dev as u32, blkno, size as u32))
}

pub(crate) extern "C" fn oxidebsd_bdata(b: u64) -> u64 {
    slot_addr(b as u32)
}

pub(crate) extern "C" fn oxidebsd_brelse(b: u64) {
    brelse(b as u32);
}

pub(crate) extern "C" fn oxidebsd_bdwrite(b: u64, tag: u64) {
    bdwrite(b as u32, tag);
}

pub(crate) extern "C" fn oxidebsd_bwrite(b: u64, tag: u64) -> i64 {
    match bwrite(b as u32, tag) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

pub(crate) extern "C" fn oxidebsd_bflush(dev: u64, mask: u64, value: u64) {
    bflush(dev as u32, mask, value);
}

pub(crate) extern "C" fn oxidebsd_bdiscard(dev: u64, mask: u64, value: u64) {
    bdiscard(dev as u32, mask, value);
}

pub(crate) extern "C" fn oxidebsd_binval(dev: u64, blkno: u64) {
    binval(dev as u32, blkno);
}

pub(crate) extern "C" fn oxidebsd_binvalall(dev: u64) {
    binvalall(dev as u32);
}

pub(crate) extern "C" fn oxidebsd_bmostly_dirty() -> i64 {
    mostly_dirty() as i64
}

pub(crate) extern "C" fn oxidebsd_bio_set_hook(dev: u64, hook: Hook) {
    set_hook(dev as u32, hook);
}
