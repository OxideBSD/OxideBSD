//! The read-only page cache (OxideBSD-doc `PAGECACHE.md`): one physical frame per page of a
//! file, read once and mapped read-only into every process that runs the file (`execve`'s
//! read-only segments) or maps it privately without write access (`mmap`), instead of a fresh
//! copy each time.
//!
//! - An **entry** is a file, by content id (the oxfs inode number), with its size when the
//!   entry was made and a frame per page, filled on first use.
//! - Each `AddressSpace` lists the entries it uses (`AddressSpace::cached`); an entry's `uses` is
//!   how many address spaces list it. `fork` copies the list, teardown releases it.
//! - Cached frames are mapped without `WRITABLE`, with `SHARED_LEAF` (teardown leaves them, `fork`
//!   aliases them) and `CACHED_LEAF` (`mprotect` copies one before making it writable). They're freed when their entry has left the cache (the file changed,
//!   `oxidebsd_content_changed`, or eviction) and no address space uses it.
//! - At most a quarter of memory is held in entries nobody uses; beyond that the least recently
//!   used go.
//!
//! **Locking.** `execve` and `mmap` fill entries while holding the frame allocator, so
//! `oxidebsd_content_changed`, which oxfs calls, never takes it: it only retires the entry, and
//! frames are queued in `pending_free` and given back by `collect`, where a deallocator is at
//! hand. The cache lock is dropped while a page is read from the file.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::Write;
use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, FrameDeallocator, PhysFrame, Size4KiB};

pub type EntryId = u64;

const PAGE: u64 = 4096;

struct Entry {
    content_id: u64,
    size: u64,
    frames: Vec<Option<PhysFrame<Size4KiB>>>,
    /// Address spaces listing this entry.
    uses: u64,
    /// Still found by its content id; false once retired (file changed, evicted).
    cached: bool,
    last_used: u64,
}

impl Entry {
    fn held(&self) -> u64 {
        self.frames.iter().filter(|f| f.is_some()).count() as u64
    }
}

struct Cache {
    by_content: BTreeMap<u64, EntryId>,
    entries: BTreeMap<EntryId, Entry>,
    next_id: EntryId,
    clock: u64,
    hits: u64,
    misses: u64,
    /// Frames of retired, unused entries, to give back at the next `collect`.
    pending_free: Vec<PhysFrame<Size4KiB>>,
}

static CACHE: Mutex<Cache> = Mutex::new(Cache {
    by_content: BTreeMap::new(),
    entries: BTreeMap::new(),
    next_id: 1,
    clock: 0,
    hits: 0,
    misses: 0,
    pending_free: Vec::new(),
});

/// Frames that entries nobody uses may hold: a quarter of memory.
fn limit() -> u64 {
    super::frame_counts().0 / 4
}

/// Retires entry `id`: no longer found by content id; its frames are queued for freeing if no
/// address space uses it.
fn retire(c: &mut Cache, id: EntryId) {
    let Some(e) = c.entries.get_mut(&id) else { return };
    if e.cached {
        e.cached = false;
        if c.by_content.get(&e.content_id) == Some(&id) {
            c.by_content.remove(&e.content_id);
        }
    }
    if e.uses == 0
        && let Some(e) = c.entries.remove(&id)
    {
        c.pending_free.extend(e.frames.into_iter().flatten());
    }
}

/// The entry for file `content_id`, made if there isn't one (or the one there is for an older
/// size of the file). `None` for something that isn't a regular file of some size.
pub fn entry_for(content_id: u64) -> Option<EntryId> {
    let size = crate::fs::fd::content_size(content_id);
    if size <= 0 {
        return None;
    }
    let size = size as u64;
    let mut c = CACHE.lock();
    c.clock += 1;
    let clock = c.clock;
    if let Some(&id) = c.by_content.get(&content_id) {
        if c.entries.get(&id).is_some_and(|e| e.size == size) {
            c.entries.get_mut(&id).unwrap().last_used = clock;
            return Some(id);
        }
        retire(&mut c, id);
    }
    let id = c.next_id;
    c.next_id += 1;
    let pages = size.div_ceil(PAGE) as usize;
    c.entries.insert(
        id,
        Entry { content_id, size, frames: alloc::vec![None; pages], uses: 0, cached: true, last_used: clock },
    );
    c.by_content.insert(content_id, id);
    Some(id)
}

/// The frame holding page `page` of entry `id`, read from the file if it isn't yet. `None` past
/// the end of the file, out of memory, or if the file reads short: the caller copies the page.
pub fn frame(id: EntryId, page: u64, fa: &mut impl FrameAllocator<Size4KiB>) -> Option<PhysFrame<Size4KiB>> {
    let (content_id, size) = {
        let mut c = CACHE.lock();
        let e = c.entries.get(&id)?;
        let (slot, content_id, size) = (*e.frames.get(page as usize)?, e.content_id, e.size);
        if let Some(f) = slot {
            c.hits += 1;
            return Some(f);
        }
        c.misses += 1;
        (content_id, size)
    };
    // Filled with the cache unlocked.
    let frame = fa.allocate_frame()?;
    let ptr = (super::phys_mem_offset() + frame.start_address().as_u64()).as_mut_ptr::<u8>();
    let off = page * PAGE;
    let len = (size - off).min(PAGE);
    // SAFETY: a frame just allocated, mapped through the direct map.
    unsafe { core::ptr::write_bytes(ptr, 0, PAGE as usize) };
    let read_whole = crate::fs::fd::content_read(content_id, off, ptr as u64, len) == len as i64;
    let mut c = CACHE.lock();
    let slot = c.entries.get_mut(&id).map(|e| e.frames[page as usize]);
    match slot {
        Some(None) if read_whole => {
            c.entries.get_mut(&id).unwrap().frames[page as usize] = Some(frame);
            Some(frame)
        }
        // Filled meanwhile (not possible on one core, but harmless).
        Some(Some(existing)) => {
            c.pending_free.push(frame);
            Some(existing)
        }
        // The file read short (it shrank: the next lookup makes a new entry), or the entry is
        // gone. Never published, so the caller copies the page itself.
        _ => {
            c.pending_free.push(frame);
            None
        }
    }
}

/// Records that the address space whose list is `uses` maps frames of entry `id`.
pub fn add_use(uses: &Mutex<BTreeSet<EntryId>>, id: EntryId) {
    if uses.lock().insert(id) {
        let mut c = CACHE.lock();
        if let Some(e) = c.entries.get_mut(&id) {
            e.uses += 1;
        }
    }
}

/// A forked address space's list: the parent's, each entry used once more.
pub fn fork_uses(parent: &Mutex<BTreeSet<EntryId>>) -> BTreeSet<EntryId> {
    let set = parent.lock().clone();
    let mut c = CACHE.lock();
    for id in &set {
        if let Some(e) = c.entries.get_mut(id) {
            e.uses += 1;
        }
    }
    set
}

/// An address space going away: each entry it used is used once less.
pub fn release_all(uses: &Mutex<BTreeSet<EntryId>>, fa: &mut impl FrameDeallocator<Size4KiB>) {
    let set = core::mem::take(&mut *uses.lock());
    {
        let mut c = CACHE.lock();
        for id in set {
            let Some(e) = c.entries.get_mut(&id) else { continue };
            e.uses = e.uses.saturating_sub(1);
            if e.uses == 0 && !e.cached {
                retire(&mut c, id);
            }
        }
    }
    collect(fa);
}

/// Gives back queued frames, and evicts unused entries, least recently used first, while they
/// hold more than the limit.
pub fn collect(fa: &mut impl FrameDeallocator<Size4KiB>) {
    let freed = {
        let mut c = CACHE.lock();
        let limit = limit();
        loop {
            let unused: u64 = c.entries.values().filter(|e| e.uses == 0).map(Entry::held).sum();
            if unused <= limit {
                break;
            }
            let Some(oldest) = c.entries.iter().filter(|(_, e)| e.uses == 0).min_by_key(|(_, e)| e.last_used).map(|(&id, _)| id)
            else {
                break;
            };
            retire(&mut c, oldest);
        }
        core::mem::take(&mut c.pending_free)
    };
    for f in freed {
        // SAFETY: a frame of a retired entry no address space uses.
        unsafe { fa.deallocate_frame(f) };
    }
}

/// Called by oxfs when inode `content_id`'s contents change or it is freed: later users read it
/// afresh; processes already mapping the old pages keep them until they exit.
#[unsafe(no_mangle)]
pub extern "C" fn oxidebsd_content_changed(content_id: u64) {
    let mut c = CACHE.lock();
    if let Some(&id) = c.by_content.get(&content_id) {
        retire(&mut c, id);
    }
}

/// `vm.pagecache.*`: entries, frames held, hits, misses and the limit on unused frames.
pub fn stats() -> (u64, u64, u64, u64, u64) {
    let c = CACHE.lock();
    let pages = c.entries.values().map(Entry::held).sum();
    (c.entries.len() as u64, pages, c.hits, c.misses, limit())
}

/// A line per entry, for debugging: content id, size, frames held, uses, whether still cached.
pub fn describe() -> Vec<u8> {
    let c = CACHE.lock();
    let mut s = alloc::string::String::new();
    for (id, e) in &c.entries {
        let _ = writeln!(s, "{id} inode {} size {} held {} uses {} {}", e.content_id, e.size, e.held(), e.uses, if e.cached { "cached" } else { "retired" });
    }
    s.into_bytes()
}
