//! The read-only page cache (OxideBSD-doc `PAGECACHE.md`): one physical frame per page of a
//! file, read once and mapped read-only into every process that runs the file (`execve`'s
//! read-only segments) or maps it privately without write access (`mmap`), instead of a fresh
//! copy each time.
//!
//! - An **entry** is a file, by content id (its vnode, `kern::vfs_vnops::object_vp`), with its
//!   size when the entry was made and a frame per page, filled on first use. The entry holds the
//!   vnode's memory (`vhold`); while an address space uses it, the file too (`vref`), so a running
//!   or mapped file stays even unlinked. An entry nobody uses doesn't keep its file: when the
//!   vnode goes (`vgone`), so does the entry (`vnode_gone`).
//! - Each `AddressSpace` lists the entries it uses (`AddressSpace::cached`); an entry's `uses` is
//!   how many address spaces list it. `fork` copies the list, teardown releases it.
//! - Cached frames are mapped without `WRITABLE`, with `SHARED_LEAF` (teardown leaves them, `fork`
//!   aliases them) and `CACHED_LEAF` (`mprotect` copies one before making it writable). They're
//!   freed when their entry has left the cache (the file changed, `changed`; its vnode went; or
//!   eviction) and no address space uses it.
//! - At most a quarter of memory is held in entries nobody uses; beyond that the least recently
//!   used go. When the frame allocator runs out, it takes them back too (`reclaim`).
//!
//! - **Demand paging** (OxideBSD-doc `DEMANDPAGE.md`): an entry for a file on the disk keeps its
//!   **block map** (`vfs_vnops::content_block_map`, from `vop_bmap`) and its device, and its pages
//!   are filled from the device directly, not through the file system, on a mapping's first touch (`process::mm::try_fill_file_page`), so a fault
//!   inside oxfs never re-enters it. A file without one (tmpfs) is filled when mapped, as before.
//!
//! **Locking.** `execve` and `mmap` fill entries while holding the frame allocator, so
//! `changed`, which the VFS calls before a file's blocks change, never takes it: it only retires the entry, and
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
    /// The file's device and its blocks there, as runs `[file page, block, length]`
    /// (`DEMANDPAGE.md` §5.1); `None` for a file with no device blocks, whose pages are read
    /// through the file system.
    blocks: Option<(u32, Vec<[u64; 3]>)>,
    /// Retired while in use with pages never filled, which its old blocks may no longer hold
    /// (§5.3): those pages are never filled now.
    stale: bool,
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
    /// Ids of removed entries, reused so ids stay small enough for a page table entry
    /// (`address_space::FILE_LEAF`): an entry is removed only once no address space uses it, so
    /// none still names it.
    free_ids: Vec<EntryId>,
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
    free_ids: Vec::new(),
    clock: 0,
    hits: 0,
    misses: 0,
    pending_free: Vec::new(),
});

/// Ids fit in the 20 bits a `FILE_LEAF` entry has for them.
pub const MAX_ENTRY_ID: EntryId = (1 << 20) - 1;

/// Removes entry `id` and frees its id.
fn remove(c: &mut Cache, id: EntryId) -> Option<Entry> {
    let e = c.entries.remove(&id)?;
    if c.by_content.get(&e.content_id) == Some(&id) {
        c.by_content.remove(&e.content_id);
    }
    c.free_ids.push(id);
    crate::kern::vfs_subr::vdrop(e.content_id as *mut vfs_if::Vnode);
    Some(e)
}

/// One more address space uses `e`: the first keeps its file in use.
fn use_entry(e: &mut Entry) {
    e.uses += 1;
    if e.uses == 1 {
        crate::kern::vfs_subr::vref(e.content_id as *mut vfs_if::Vnode);
    }
}

/// One fewer does: the last lets the file go (deferred: this runs as an address space is torn
/// down, where a file system can't be entered).
fn unuse_entry(e: &mut Entry) {
    if e.uses == 0 {
        return;
    }
    e.uses -= 1;
    if e.uses == 0 {
        crate::kern::vfs_subr::vrele_deferred(e.content_id as *mut vfs_if::Vnode);
    }
}

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
        && let Some(e) = remove(c, id)
    {
        c.pending_free.extend(e.frames.into_iter().flatten());
    }
}

/// The entry for file `content_id`, made if there isn't one (or the one there is for an older
/// size of the file). `None` for something that isn't a regular file of some size.
pub fn entry_for(content_id: u64) -> Option<EntryId> {
    let size = crate::kern::vfs_vnops::content_size(content_id);
    if size <= 0 {
        return None;
    }
    let size = size as u64;
    let current = |c: &mut Cache| {
        c.clock += 1;
        let clock = c.clock;
        let id = *c.by_content.get(&content_id)?;
        let e = c.entries.get_mut(&id)?;
        (e.size == size).then(|| {
            e.last_used = clock;
            id
        })
    };
    if let Some(id) = current(&mut CACHE.lock()) {
        return Some(id);
    }
    // Asked of the filesystem with the cache unlocked.
    let blocks = crate::kern::vfs_vnops::content_block_map(content_id);
    let mut c = CACHE.lock();
    if let Some(id) = current(&mut c) {
        return Some(id);
    }
    if let Some(&old) = c.by_content.get(&content_id) {
        retire(&mut c, old);
    }
    let id = match c.free_ids.pop() {
        Some(id) => id,
        None if c.next_id <= MAX_ENTRY_ID => {
            c.next_id += 1;
            c.next_id - 1
        }
        None => return None,
    };
    let pages = size.div_ceil(PAGE) as usize;
    let clock = c.clock;
    crate::kern::vfs_subr::vhold(content_id as *mut vfs_if::Vnode);
    c.entries.insert(
        id,
        Entry {
            content_id,
            size,
            frames: alloc::vec![None; pages],
            blocks,
            stale: false,
            uses: 0,
            cached: true,
            last_used: clock,
        },
    );
    c.by_content.insert(content_id, id);
    Some(id)
}

/// Whether entry `id`'s pages may be filled on first touch: it has a block map (`DEMANDPAGE.md`
/// §5). Else a mapping fills them when it's made.
pub fn demand(id: EntryId) -> bool {
    CACHE.lock().entries.get(&id).is_some_and(|e| e.blocks.is_some())
}

/// Where a fill is done from, which decides whether it may wait for the filesystem lock
/// (`DEMANDPAGE.md` §4.2): a system call or a ring-3 fault holds no spin lock and may; a fault in
/// a copy routine may not know, so it fills only if the lock is free or already its own.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fill {
    Syscall,
    UserFault,
    KernelFault,
}

/// The disk block holding `page` in `runs`, `None` for a hole.
fn block_of(runs: &[[u64; 3]], page: u64) -> Option<u64> {
    let i = runs.partition_point(|r| r[0] + r[2] <= page);
    let r = runs.get(i)?;
    (r[0] <= page).then(|| r[1] + (page - r[0]))
}

/// The frame holding page `page` of entry `id`, read from the file if it isn't yet. `None` past
/// the end of the file, out of memory, or if the file reads short: the caller copies the page.
///
/// Takes the frame allocator itself, briefly: callers MUST NOT hold it, since the read can sleep
/// on the disk (COW.md §4.4).
pub fn frame(id: EntryId, page: u64, from: Fill) -> Option<PhysFrame<Size4KiB>> {
    fill(id, page, from).ok()
}

/// Why `fill` gave no frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FillError {
    /// No frame to fill: the OOM killer's case.
    NoMemory,
    /// Past the end of the file, the entry gone or stale, the read failed, or a fault in a copy
    /// routine while another process is in the filesystem.
    Unavailable,
}

/// `frame`, saying why it failed.
pub fn fill(id: EntryId, page: u64, from: Fill) -> Result<PhysFrame<Size4KiB>, FillError> {
    use FillError::{NoMemory, Unavailable};
    let (content_id, size, block) = {
        let mut c = CACHE.lock();
        let e = c.entries.get(&id).ok_or(Unavailable)?;
        let (slot, content_id, size) = (*e.frames.get(page as usize).ok_or(Unavailable)?, e.content_id, e.size);
        if let Some(f) = slot {
            c.hits += 1;
            return Ok(f);
        }
        if e.stale {
            return Err(Unavailable);
        }
        let block = e.blocks.as_ref().map(|(dev, runs)| (*dev, block_of(runs, page)));
        c.misses += 1;
        (content_id, size, block)
    };
    // From a copy routine, not knowing what spin locks the interrupted code holds, wait for no
    // one: the fill fails (the copy with `EFAULT`) if another process is in the filesystem.
    if from == Fill::KernelFault && crate::fs::fslock::busy() {
        crate::serial_println!(
            "[vm] pid {}: a page of a file mapping can't be read from inside the kernel now (the filesystem is busy)",
            crate::process::scheduler::current_pid()
        );
        return Err(Unavailable);
    }
    // Filled with the cache unlocked. From a copy routine, nothing may wait: not for the frame
    // allocator (the interrupted code may hold it), nor sleep for the disk below (it may hold a
    // spin lock a sleep would need -- found at 28 MB: a system call copying in under the process
    // table's lock, the disk wait then spinning on that lock forever).
    let frame = if from == Fill::KernelFault {
        super::try_with_frame_allocator(|fa| fa.allocate_frame()).ok_or(Unavailable)?.ok_or(NoMemory)?
    } else {
        super::with_frame_allocator(|fa| fa.allocate_frame()).ok_or(NoMemory)?
    };
    let ptr = (super::phys_mem_offset() + frame.start_address().as_u64()).as_mut_ptr::<u8>();
    let off = page * PAGE;
    let len = (size - off).min(PAGE);
    // SAFETY: a frame just allocated, mapped through the direct map.
    unsafe { core::ptr::write_bytes(ptr, 0, PAGE as usize) };
    let read_whole = match block {
        // Straight from the disk (`DEMANDPAGE.md` §5.2), under the filesystem lock -- which
        // serializes the disk -- but never through oxfs. A hole stays zero.
        Some((dev, Some(block))) => {
            let _poll = (from == Fill::KernelFault).then(crate::fs::fslock::NoSleep::new);
            crate::fs::fslock::enter();
            // The file's block on its mount's device (`kern::vfs_bdev`, VFS.md §7.2), in 4 KiB
            // blocks: read around the buffer cache, which holds metadata only (§7.4).
            // SAFETY: the frame's PAGE bytes, just allocated.
            let page = unsafe { core::slice::from_raw_parts_mut(ptr, PAGE as usize) };
            let ok = crate::kern::vfs_bdev::read(dev, block * 8, page).is_ok();
            if from == Fill::KernelFault {
                crate::fs::fslock::exit_quiet();
            } else {
                crate::fs::fslock::exit();
            }
            if ok && len < PAGE {
                // The tail of the last block past the end of the file reads as zero.
                // SAFETY: inside the frame.
                unsafe { core::ptr::write_bytes(ptr.add(len as usize), 0, (PAGE - len) as usize) };
            }
            ok
        }
        Some((_, None)) => true,
        None => crate::kern::vfs_vnops::content_read(content_id, off, ptr as u64, len) == len as i64,
    };
    let mut c = CACHE.lock();
    let slot = c.entries.get_mut(&id).map(|e| e.frames[page as usize]);
    match slot {
        Some(None) if read_whole => {
            c.entries.get_mut(&id).unwrap().frames[page as usize] = Some(frame);
            Ok(frame)
        }
        // Filled meanwhile, by another process while this one slept reading the disk.
        Some(Some(existing)) => {
            c.pending_free.push(frame);
            Ok(existing)
        }
        // The file read short (it shrank: the next lookup makes a new entry), or the entry is
        // gone. Never published, so the caller copies the page itself.
        _ => {
            c.pending_free.push(frame);
            Err(Unavailable)
        }
    }
}

/// Records that the address space whose list is `uses` maps frames of entry `id`.
pub fn add_use(uses: &Mutex<BTreeSet<EntryId>>, id: EntryId) {
    if uses.lock().insert(id) {
        let mut c = CACHE.lock();
        if let Some(e) = c.entries.get_mut(&id) {
            use_entry(e);
        }
    }
}

/// A forked address space's list: the parent's, each entry used once more.
pub fn fork_uses(parent: &Mutex<BTreeSet<EntryId>>) -> BTreeSet<EntryId> {
    let set = parent.lock().clone();
    let mut c = CACHE.lock();
    for id in &set {
        if let Some(e) = c.entries.get_mut(id) {
            use_entry(e);
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
            unuse_entry(e);
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

/// Gives `free` the frames of retired entries, else of the least recently used entry no address
/// space uses, for a frame allocator that has run out. `false` when there's nothing to give, or
/// the cache is locked (the allocation came from inside it). Allocates nothing: it runs inside the
/// frame allocator.
pub fn reclaim(free: &mut dyn FnMut(PhysFrame<Size4KiB>)) -> bool {
    let Some(mut c) = CACHE.try_lock() else { return false };
    if !c.pending_free.is_empty() {
        c.pending_free.drain(..).for_each(&mut *free);
        return true;
    }
    let Some(oldest) = c.entries.iter().filter(|(_, e)| e.uses == 0).min_by_key(|(_, e)| e.last_used).map(|(&id, _)| id)
    else {
        return false;
    };
    let e = remove(&mut c, oldest).unwrap();
    e.frames.into_iter().flatten().for_each(free);
    true
}

/// The VFS's, before file `content_id`'s blocks change (`kern::vnode_if`: a write, a truncate, an
/// allocation): later users read it afresh; processes already mapping the old pages keep them
/// until they exit. An entry still in use, with pages never filled, fills them now from
/// its blocks, while they still hold the old contents (`DEMANDPAGE.md` §5.3); a page it can't fill
/// is never filled later (`stale`), so nothing reads a block oxfs may give to another file.
pub fn changed(content_id: u64) {
    let unfilled: Vec<u64> = {
        let c = CACHE.lock();
        let Some(e) = c.by_content.get(&content_id).and_then(|id| c.entries.get(id)) else { return };
        if e.uses == 0 || e.blocks.is_none() {
            Vec::new()
        } else {
            (0..e.frames.len() as u64).filter(|&p| e.frames[p as usize].is_none()).collect()
        }
    };
    let id = CACHE.lock().by_content.get(&content_id).copied();
    let Some(id) = id else { return };
    let mut complete = true;
    for page in unfilled {
        // The VFS is the caller, holding the giant lock: the fill re-takes it.
        complete &= frame(id, page, Fill::Syscall).is_some();
    }
    let mut c = CACHE.lock();
    if !complete && let Some(e) = c.entries.get_mut(&id) {
        e.stale = true;
        e.blocks = None;
    }
    retire(&mut c, id);
}

/// Vnode `content_id` is going (`vfs_subr::vgone`): its entry leaves the cache, its pages freed
/// once nobody maps them.
pub fn vnode_gone(content_id: u64) {
    let mut c = CACHE.lock();
    if let Some(&id) = c.by_content.get(&content_id) {
        // Still mapped (revoked, or its mount forcibly unmounted): what's loaded stays, and a page
        // never loaded never will be (`SIGBUS`), since its blocks may be another file's soon.
        if let Some(e) = c.entries.get_mut(&id)
            && e.uses > 0
        {
            e.stale = true;
            e.blocks = None;
        }
        retire(&mut c, id);
    }
}

/// `vm.pagecache.*`: entries, frames held, hits, misses and the limit on unused frames.
pub fn stats() -> (u64, u64, u64, u64, u64) {
    let c = CACHE.lock();
    let pages = c.entries.values().map(Entry::held).sum();
    (c.entries.len() as u64, pages, c.hits, c.misses, limit())
}

/// `(frames held, frames held by entries no address space uses)`: what `/proc/meminfo` reports as
/// `Cached`, and the part of it `reclaim` can give back on demand (counted as available).
pub fn meminfo_pages() -> (u64, u64) {
    let c = CACHE.lock();
    let held = c.entries.values().map(Entry::held).sum();
    let unused = c.entries.values().filter(|e| e.uses == 0).map(Entry::held).sum();
    (held, unused)
}

/// A line per entry, for debugging: content id, size, frames held, uses, whether still cached.
pub fn describe() -> Vec<u8> {
    let c = CACHE.lock();
    let mut s = alloc::string::String::new();
    for (id, e) in &c.entries {
        // SAFETY: an entry holds its vnode.
        let fileid = unsafe { (*(e.content_id as *const vfs_if::Vnode)).v_fileid };
        let _ = writeln!(s, "{id} file {fileid} size {} held {} uses {} {}", e.size, e.held(), e.uses, if e.cached { "cached" } else { "retired" });
    }
    s.into_bytes()
}
