//! mmap/munmap/mprotect/brk syscalls -- split out of the original process.rs.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::mapper::TranslateResult;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB, Translate,
};

use super::*;
use crate::memory::{self, with_frame_allocator};
use crate::syscall::{EACCES, EAGAIN, EBADF, EBUSY, EINVAL, ENODEV, ENOMEM, ENXIO, EOVERFLOW};

/// Fixed VA window for anonymous `SYS_MMAP` allocations — a fresh region, not reused from
/// `module::MODULE_VA_BASE` (that one's kernel-mapped and shared across every address space; an
/// mmap region has to be per-process, mapped `USER_ACCESSIBLE` only in the calling process's own
/// table). Bump-allocated and never reclaimed, same "hand out forward, never reuse" policy as
/// `module::NEXT_MODULE_PAGE`/`BootInfoFrameAllocator` — consistent with this whole codebase
/// having no deallocation path anywhere yet. A single global counter is safe even across multiple
/// processes: this only hands out VA *values*, mapped separately into whichever process's own
/// address space asked for one — two different processes reusing the same numeric VA in their own
/// tables never interferes, no shared visibility (the same reasoning `USER_STACK_TOP` already
/// relies on being "fixed but per-address-space").
const MMAP_REGION_BASE: u64 = 0x_2000_0000_0000;
const MMAP_REGION_CEILING: u64 = 0x_3000_0000_0000;
static NEXT_MMAP_PAGE: Mutex<u64> = Mutex::new(MMAP_REGION_BASE);

/// Real per-process cap on the number of live fd-backed mappings — matches real Linux's own
/// `vm.max_map_count` default (`65530`), which is what actually produces `ENOMEM` in practice for
/// `mmap/24-1.c`'s own "keep mapping the same object in a tight loop until `ENOMEM`" probe, not
/// genuine `MMAP_REGION_CEILING` byte-range exhaustion — that range is `2^44` bytes (16 TiB),
/// which at one page per iteration would need billions of loop iterations to ever exhaust,
/// timing out this pilot file's own 40s bound long before reaching real VA exhaustion (found
/// live: `mmap/24-1.c` TIMEOUT with no cap in place). Real Linux hits its own count-based limit
/// almost immediately regardless of how much raw address space remains, which is exactly the
/// behavior this mirrors. Scoped to `mmap_file_regions` only (not the separate anonymous-mmap
/// path, which has no per-region bookkeeping struct to count against) — no pilot file or real
/// caller in this kernel's own call graph exercises the anonymous case at this scale.
const MAX_MMAP_FILE_REGIONS: usize = 65530;

/// Real `PROT_READ`/`PROT_WRITE` (match every real Unix's values). `do_mmap_anon` maps every
/// anonymous page `PRESENT` unconditionally (this kernel eager-allocates every anon page
/// regardless of protection, matching its established no-demand-paging precedent everywhere else),
/// but only grants `WRITABLE`/`USER_ACCESSIBLE` per these bits — real `PROT_NONE` (neither set)
/// leaves a page present-but-ring3-inaccessible, faulting exactly like an unmapped page would (see
/// `do_mprotect`'s own doc comment for why this specific shape — present, not absent — is what
/// makes a later `mprotect()` able to grant access back with no new bookkeeping). `PROT_WRITE`
/// additionally decides whether a real fd-backed mapping's frames get write-back on `munmap`/exit;
/// `PROT_READ`/`PROT_WRITE` together (real `PROT_NONE` when neither is set) decide whether a
/// file-backed mapping's covered pages get a page-table entry at all — see that function's own doc
/// comment for why leaving them unmapped is enough to produce a real `SIGSEGV` with no new
/// machinery (`mmap/6-2.c`).
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;

/// Real `flags` bits `SYS_MMAP` understands, unpacked from `oxidebsd_sys_mmap`'s own `packed_prot`
/// register (see that function's own doc comment for the wire format) — matches musl's own real
/// `<sys/mman.h>` values exactly, not invented here: musl's patched `__mmap()` packs its real,
/// caller-supplied `flags` argument verbatim (just shifted), so there's no reason to number these
/// any differently. Only these four are ever consulted; anything else (`MAP_NORESERVE`,
/// `MAP_POPULATE`, `MAP_STACK`, ...) rides along in the packed value but is silently ignored, same
/// tier as `prot`'s own unenforced bits.
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANON: u64 = 0x20;

/// Real Linux's own `RLIMIT_MEMLOCK` index into `Process::rlimits` -- `8` on every arch this
/// kernel's own `x86_64` target shares numbering with (see `third_party/musl/include/sys/
/// resource.h`). The one `RLIMIT_*` resource `do_mmap` actually enforces, and only for the one
/// real trigger POSIX documents for it (`mlockall(MCL_FUTURE)`'s own auto-lock-on-map contract,
/// see the `auto_lock` handling below) -- every other `RLIMIT_*` stays the same honest
/// stored-but-unenforced tier `Process::rlimits`'s own doc comment already establishes.
const RLIMIT_MEMLOCK: u64 = 8;

/// Real, cross-open shared physical-frame cache for fd-backed `MAP_SHARED` mappings — keyed by
/// `crate::fs::fd::content_id_of`'s real inode identity, not by `real_fd`/pid. **This is what
/// makes two *separate* `open()` calls on the same underlying file (`shm_open`'s own documented
/// re-open-by-name pattern, or any two processes independently opening the same path) actually
/// share live writes with no `msync` needed** — real POSIX `MAP_SHARED` guarantees exactly this,
/// and there is no page-fault/dirty-tracking machinery in this kernel to synthesize it any other
/// way; sharing the *same physical frames* directly, the same trick `crate::fs::sysv_shm` already
/// uses for real SysV shared memory, sidesteps needing one. Grows in place while any mapping is
/// still live (never shrinks/discards a shorter existing entry — see `do_mmap_file_backed`'s own
/// doc comment) — but **is evicted, not leaked, once `MMAP_FILE_REFCOUNT` for a `content_id` drops
/// to zero** (every live mapping of it torn down). Found live, not designed in up front: a
/// never-evicted cache made an in-memory-only modification to the partial page beyond a mapped
/// object's own real length outlive every mapping of it, including across a full `munmap`+
/// process-exit+fresh-`open`+fresh-`mmap` cycle — `mmap/11-4.c`/`11-5.c` write such a byte and
/// require a *later, independent* mapping to never see it (real POSIX: that partial-page content
/// was never part of the object to begin with, only ever visible through the specific mapping that
/// wrote it). Eviction doesn't free the frames themselves (this kernel has no frame-deallocation
/// path anywhere) — a later mmap of the same file just allocates a fresh set and re-populates from
/// the real (correctly `writeback_region`-clamped) file content, exactly as if it were the first
/// mmap of that file ever.
static MMAP_FILE_CACHE: Mutex<BTreeMap<u64, Vec<PhysFrame<Size4KiB>>>> =
    Mutex::new(BTreeMap::new());

/// How many currently-live `MmapFileRegion`s (across every process) reference each `content_id` —
/// see `MMAP_FILE_CACHE`'s own doc comment for why this drives real cache eviction rather than
/// being purely informational.
static MMAP_FILE_REFCOUNT: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

/// Releases one reference to `content_id`'s cache entry — call after `writeback_region` has
/// already run for the region being torn down. Evicts `MMAP_FILE_CACHE`'s own entry once the
/// count reaches zero (see that static's own doc comment).
fn release_mmap_file_ref(content_id: u64) {
    let mut refs = MMAP_FILE_REFCOUNT.lock();
    let Some(count) = refs.get_mut(&content_id) else {
        return;
    };
    *count -= 1;
    if *count == 0 {
        refs.remove(&content_id);
        drop(refs);
        MMAP_FILE_CACHE.lock().remove(&content_id);
    }
}

/// Real `fork()` semantics for a fd-backed `MAP_SHARED` mapping the child inherits by virtue of
/// the whole address space being duplicated. `AddressSpace::fork`'s own `SHARED_LEAF` handling
/// already makes the child's page table alias the exact same real frames the parent's does for
/// every `shared` `MmapFileRegion` -- what was missing was the accounting: `do_munmap`/`do_msync`/
/// `cleanup_mmap_file_regions_for_exit` all key writeback exclusively off the *calling* process's
/// own `mmap_file_regions` list, so with the child's list left empty (the original, unconditional
/// behavior), nothing the child did with its share of the mapping ever wrote those bytes back to
/// the file -- see `MmapFileRegion`'s own doc comment for the concrete failure case this fixes.
/// Called from `do_fork_from_current` right after the child's table entry exists, same convention
/// `fs::sysv_shm::inherit_attachments_for_fork` already established for the identical underlying
/// gap. `MAP_PRIVATE` regions are deliberately skipped -- see `MmapFileRegion::shared`'s own doc
/// comment for why fork already gives those a genuinely private, independent frame with nothing
/// left for this list to track.
pub(crate) fn inherit_mmap_file_regions_for_fork(parent_pid: Pid, child_pid: Pid) {
    let regions: Vec<MmapFileRegion> = {
        let table = PROCESS_TABLE.lock();
        let Some(parent) = table.get(&parent_pid) else {
            return;
        };
        parent
            .shared
            .lock()
            .mmap_file_regions
            .iter()
            .filter(|r| r.shared)
            .copied()
            .collect()
    };
    if regions.is_empty() {
        return;
    }
    {
        let mut refs = MMAP_FILE_REFCOUNT.lock();
        for r in &regions {
            *refs.entry(r.content_id).or_insert(0) += 1;
        }
    }
    let table = PROCESS_TABLE.lock();
    if let Some(child) = table.get(&child_pid) {
        child.shared.lock().mmap_file_regions.extend(regions);
    }
}

/// One real fd-backed `MAP_SHARED` mapping still live in a process's own address space — enough
/// state for `do_munmap` (or exit/`execve` cleanup) to write real content back to the underlying
/// file (via `crate::fs::fd::content_write`, keyed by `content_id` alone — no fd/`real_fd`
/// involved at all, see that function's own doc comment for why). A `shared` (`MAP_SHARED`) entry
/// *is* now inherited across `fork` -- see `inherit_mmap_file_regions_for_fork`'s own doc comment
/// for why: `AddressSpace::fork`'s `SHARED_LEAF` handling already makes the child's page table
/// alias the exact same real frames the parent's does, so leaving the child's own list empty (the
/// original behavior, matching `Process::sysv_shm_attach`'s now-fixed precedent) meant nothing the
/// child did with its share -- write through it, `munmap` it, exit -- ever wrote those bytes back
/// to the file, a real, silent data-loss bug. A `MAP_PRIVATE` entry stays uninherited: `do_mmap_
/// file_backed` never marks a private mapping's frames `SHARED_LEAF`, so `AddressSpace::fork`
/// already gives the child a genuinely private, eagerly-copied frame there -- correct fork
/// semantics on its own, nothing for this list to additionally track.
#[derive(Clone, Copy)]
pub struct MmapFileRegion {
    va_start: u64,
    npages: u64,
    /// How many pages starting at `va_start` are actually backed by real frames -- always
    /// `<= npages`, computed once at `mmap()` time from the object's own real length rounded up to
    /// a whole page (`do_mmap_file_backed`'s own doc comment). Frozen at creation, not re-checked
    /// against the object's current length on every fault -- a documented simplification (real
    /// Linux dynamically re-checks the current inode size on each fault, letting a later
    /// `ftruncate()` grow retroactively into what SIGBUSed before; no test in this kernel's own
    /// conformance pilot exercises that). Pages `[mapped_pages, npages)` are deliberately left
    /// *unmapped* in the caller's page table -- real POSIX MPR: a reference anywhere in that range
    /// must raise `SIGBUS`, not silently succeed against a zero-filled page -- see
    /// `signal_for_user_fault` below, which is what actually turns "unmapped" into a real signal
    /// instead of the reboot every other unmapped ring-3 reference still gets.
    mapped_pages: u64,
    content_id: u64,
    writable: bool,
    /// `true` for a real `MAP_SHARED` mapping (cross-open cache-backed, real writeback on
    /// `munmap`/`msync`/exit — the original, only behavior this kernel had before real `MAP_PRIVATE`
    /// support existed). `false` for a real `MAP_PRIVATE` mapping: still registered here so the
    /// same MPR `SIGBUS`-on-reserved-tail machinery (`signal_for_user_fault` below) covers it too,
    /// but its own frames are a fresh, never-cached, never-shared copy (see `do_mmap_file_backed`'s
    /// own doc comment) — `writeback_region` and `release_mmap_file_ref` both no-op for one of
    /// these, real POSIX "modifications... discarded" `MAP_PRIVATE` semantics.
    shared: bool,
    /// `true` once `mlockall(MCL_CURRENT)` has snapshotted this region as locked (`do_mlockall`).
    /// No real page-level locking exists to back this (same honesty tier `do_mlock`/`do_munlock`
    /// already document) -- the one real behavior it drives is `do_msync`'s own `MS_INVALIDATE`
    /// check: real POSIX documents `EBUSY` when `msync(MS_INVALIDATE)` targets a locked mapping,
    /// since invalidating a locked page's content would need evicting memory the caller asked to
    /// keep pinned (`mlockall/3-6.c`). Cleared by `munlockall`, mirroring `ThreadGroupShared::
    /// mlockall_future`'s own reset.
    locked: bool,
}

/// `SYS_MMAP`'s real logic — OxideBSD's own invention, not modeled on any real OS's `mmap` (see
/// `src/syscall.rs`'s module doc comment). `flags` is real now too, decoded by the caller
/// (`src/syscall/ffi.rs`'s `oxidebsd_sys_mmap`) from the same packed register `prot` rides in — see
/// that function's own doc comment for the wire format. Real POSIX validation this now performs
/// that it didn't before `flags` existed on the wire: exactly one of `MAP_SHARED`/`MAP_PRIVATE`
/// must be set (`EINVAL` otherwise — covers both "neither" and "both", the same clause real
/// `mmap(2)` documents), and a non-anonymous request (`MAP_ANON` unset) needs a real, non-negative
/// `fd` (`EBADF` otherwise — previously any `fd < 0` silently became an anonymous mapping
/// regardless of what `flags` actually said, since `flags` never reached the kernel at all). `fd`
/// is ignored once `MAP_ANON` is set, matching real POSIX (callers conventionally still pass `-1`,
/// but nothing requires it). `MAP_FIXED` is real too now: `addr_hint` must be page-aligned
/// (`EINVAL` otherwise) and is honored as the mapping's actual address rather than always
/// bump-allocating a fresh one — see the `fixed_base` handling below for the real "replace any
/// previous mapping" semantics real POSIX documents for it.
pub fn do_mmap(
    caller_pid: Pid,
    addr_hint: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i32,
    off: u32,
) -> Result<u64, u64> {
    if len == 0 {
        return Err(EINVAL);
    }
    let shared = flags & MAP_SHARED != 0;
    let private = flags & MAP_PRIVATE != 0;
    if shared == private {
        // Neither bit set, or both -- real POSIX EINVAL either way.
        return Err(EINVAL);
    }
    let anon = flags & MAP_ANON != 0;
    let fixed = flags & MAP_FIXED != 0;
    if !anon && fd < 0 {
        return Err(EBADF);
    }
    let effective_fd = if anon { -1 } else { fd };

    let page_count = len.div_ceil(4096);
    let region_len = page_count.checked_mul(4096).ok_or(ENOMEM)?;

    // Real MAP_FIXED: `addr_hint` becomes the mapping's actual address (not just a discarded hint,
    // the every-other-case behavior below), page-alignment-validated up front (real POSIX EINVAL),
    // and whatever whole pages it lands on get unmapped first -- "the mapping established by
    // mmap() shall replace any previous mappings for those whole pages containing any part of the
    // address space of the process starting at pa and continuing for len bytes". Reuses
    // `do_munmap` wholesale rather than duplicating its unmap/writeback/refcount-release logic --
    // that function is already safe and idempotent against a range with nothing mapped in it (see
    // its own doc comment), and already does exactly the real cleanup a displaced fd-backed region
    // needs.
    //
    // **`ENOMEM`, not `EINVAL`, once alignment is past**: real POSIX's own `MAP_FIXED` clause reads
    // "[ENOMEM] MAP_FIXED was specified, and the range [addr,addr+len) exceeds that allowed for the
    // address space of a process" -- an `addr+len` that overflows `u64` entirely, or lands outside
    // this arch's canonical 48-bit range, is exactly that clause, not a generic argument-shape
    // `EINVAL` (reserved for real misalignment, checked separately just above). Found live:
    // `mmap/24-2.c` requests `len == RLIMIT_AS` (this kernel's own default `rlim_cur` is
    // `RLIM_INFINITY`/`u64::MAX`, see `Process::rlimits`'s own doc comment) at an already-valid
    // `addr` -- `addr + len` overflows `u64` outright, so this never needed real `RLIMIT_AS`
    // enforcement at all, just the correct errno for an address range that can't possibly exist.
    let fixed_base = if fixed {
        if !addr_hint.is_multiple_of(4096) {
            return Err(EINVAL);
        }
        let end_inclusive = addr_hint
            .checked_add(region_len)
            .and_then(|e| e.checked_sub(1))
            .ok_or(ENOMEM)?;
        if VirtAddr::try_new(addr_hint).is_err() || VirtAddr::try_new(end_inclusive).is_err() {
            return Err(ENOMEM);
        }
        let _ = do_munmap(caller_pid, addr_hint, region_len);
        Some(addr_hint)
    } else {
        None
    };

    // Real `mlockall(MCL_FUTURE)` + `RLIMIT_MEMLOCK` enforcement (`mmap/18-1.c`): decided up front,
    // before actually establishing the mapping -- a process that called `mlockall(MCL_FUTURE)`
    // implicitly locks every future mapping, and if that would push its own total locked bytes
    // past `RLIMIT_MEMLOCK`, real POSIX has the whole `mmap()` fail `EAGAIN` rather than partially
    // mapping. `mlockall_future`/`locked_bytes` live on `ThreadGroupShared`, not `Process`, since
    // real memory locks are a property of the address space, not the individual thread -- see
    // that struct's own doc comment; a `CLONE_THREAD` sibling shares this state automatically via
    // the same `Arc` `mmap_file_regions` already does.
    let auto_lock = {
        let table = PROCESS_TABLE.lock();
        let me = table
            .get(&caller_pid)
            .expect("mmap: current process missing from table");
        let shared = me.shared.lock();
        if shared.mlockall_future {
            let (rlim_cur, _) = me.rlimits[RLIMIT_MEMLOCK as usize];
            if shared.locked_bytes.saturating_add(region_len) > rlim_cur {
                return Err(EAGAIN);
            }
        }
        shared.mlockall_future
    };

    // A real `/dev/fb0` fd is checked *before* the ordinary file-backed path -- see
    // `crate::fs::fd::framebuffer_geometry_of`'s own doc comment: this fd's own `content_id_of`
    // always returns `None`/`ENODEV` too (oxfs's `OpenFile::Framebuffer` has no real inode behind
    // it), so it would otherwise just fail there instead of ever reaching real MMIO-mapping logic.
    let fb_geometry = if effective_fd >= 0 {
        crate::fs::fd::framebuffer_geometry_of(effective_fd as u64)
    } else {
        None
    };

    let result = if let Some(geom) = fb_geometry {
        do_mmap_fb(caller_pid, geom, page_count, fixed_base)
    } else if effective_fd >= 0 {
        do_mmap_file_backed(
            caller_pid,
            effective_fd as u64,
            off,
            page_count,
            prot,
            private,
            fixed_base,
        )
    } else {
        do_mmap_anon(caller_pid, fixed_base, region_len, prot)
    };

    if auto_lock && result.is_ok() {
        let table = PROCESS_TABLE.lock();
        if let Some(me) = table.get(&caller_pid) {
            me.shared.lock().locked_bytes += region_len;
        }
    }

    result
}

/// The anonymous-mapping half of `do_mmap` (`fd < 0`, i.e. `MAP_ANON`) -- split out so `do_mmap`
/// itself can apply the real `mlockall(MCL_FUTURE)` accounting uniformly across both this and
/// `do_mmap_file_backed` without duplicating it in each. `fixed_base`, when set, is a real
/// `MAP_FIXED` address (already alignment/canonical-validated, and already had `do_mmap`'s own
/// `do_munmap` pre-clear run against it); otherwise a fresh VA is bump-allocated as before.
///
/// **Real `PROT_NONE` (neither `PROT_READ` nor `PROT_WRITE`) skips mapping the region at all** --
/// reusing `do_mmap_file_backed`'s own precedent (see that function's doc comment) rather than
/// mapping present-but-inaccessible pages. This isn't just consistency: `AddressSpace::teardown`'s
/// own frame-freeing walk (`free_table_level`) treats a clear `USER_ACCESSIBLE` bit *anywhere* as
/// an absolute guarantee that nothing user-owned lives beneath it, and skips freeing there
/// unconditionally (see that function's own doc comment) -- a present-but-`USER_ACCESSIBLE`-clear
/// leaf would be a real, permanent per-guard-page frame leak on every address-space teardown, not
/// just formally inconsistent. Leaving the region genuinely unmapped costs nothing here (no
/// pre-existing content to preserve) and reuses the exact same "unmapped access -> real `SIGSEGV`"
/// path `do_mmap_file_backed`'s own `PROT_NONE` case already established.
///
/// `do_mprotect` is what actually reifies a `PROT_NONE` sub-range later widened to real access --
/// see that function's own doc comment for the demand-mapping half of this design (musl's own
/// `pthread_create()` `mmap()`s the whole guard+usable region `PROT_NONE` in one call, then
/// `mprotect()`s just the usable tail back to `PROT_READ|PROT_WRITE`).
fn do_mmap_anon(
    caller_pid: Pid,
    fixed_base: Option<u64>,
    region_len: u64,
    prot: u64,
) -> Result<u64, u64> {
    let base = match fixed_base {
        Some(base) => base,
        None => {
            let mut next = NEXT_MMAP_PAGE.lock();
            let base = *next;
            let end = base.checked_add(region_len).ok_or(ENOMEM)?;
            if end > MMAP_REGION_CEILING {
                return Err(ENOMEM);
            }
            *next = end;
            base
        }
    };

    let prot_accessible = prot & (PROT_READ | PROT_WRITE) != 0;
    if !prot_accessible {
        // Real PROT_NONE: reserve the VA (already done above) but map nothing -- see this
        // function's own doc comment.
        return Ok(base);
    }
    let writable = prot & PROT_WRITE != 0;

    let phys_offset = memory::phys_mem_offset();
    let mut table = PROCESS_TABLE.lock();
    let me = table
        .get_mut(&caller_pid)
        .expect("mmap: current process missing from table");
    // SAFETY: me.address_space is the currently active address space -- mmap runs synchronously on
    // the caller's own kernel stack mid-syscall, with its own CR3 still live -- sound for the same
    // reason AddressSpace::fork's own doc comment already establishes for this "active table" case.
    let mut mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };

    let mut leaf_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        leaf_flags |= PageTableFlags::WRITABLE;
    }
    // Always fully open, regardless of this call's own leaf flags -- see `do_mprotect`'s own doc
    // comment: a later `mprotect()` widening just the leaf (e.g. a real `PROT_READ`-only region
    // upgraded to add `PROT_WRITE`) must not find an intermediate P2/P3/P4 entry this same region
    // created non-writable/non-accessible, since real x86 ANDs those bits down through every
    // paging level and `update_flags` only ever touches the leaf.
    let parent_table_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base + region_len - 1));
    with_frame_allocator(|fa| -> Result<(), u64> {
        for page in Page::range_inclusive(start_page, end_page) {
            let frame = fa.allocate_frame().ok_or(ENOMEM)?;
            // SAFETY: frame was just allocated (unused, per BootInfoFrameAllocator's contract),
            // and page falls in this process's own, freshly bump-allocated mmap region.
            unsafe {
                mapper
                    .map_to_with_table_flags(page, frame, leaf_flags, parent_table_flags, fa)
                    .map_err(|_| ENOMEM)?
                    .flush();
            }
            // Real anonymous mmap guarantees zero-filled pages; frames from BootInfoFrameAllocator
            // aren't pre-zeroed, so this has to happen explicitly (same technique elf::load uses
            // for BSS).
            let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
            unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
        }
        Ok(())
    })?;

    Ok(base)
}

/// One real, still-live physical (MMIO) mapping in a process's own address space -- currently only
/// ever a real `/dev/fb0` mapping (`do_mmap_fb` below), but named generically since any future
/// device-backed mmap needing raw physical frames (not oxfs content) would use the identical
/// shape. Distinct from `MmapFileRegion`: no content/writeback semantics apply to MMIO -- these
/// frames are never allocator-owned RAM, so there's nothing to free on unmap and nothing to write
/// back on exit, unlike a real fd-backed mapping.
pub struct MmapPhysRegion {
    va_start: u64,
    /// Not read yet -- `do_munmap`'s own generic per-page loop (not this field) is what actually
    /// drives unmapping, keyed by the caller's own `addr`/`len`. Kept for parity with
    /// `MmapFileRegion::npages` and because a real future partial-unmap check (POSIX allows
    /// `munmap()` of a sub-range) would need it.
    #[allow(dead_code)]
    npages: u64,
}

/// Real `/dev/fb0` mmap -- maps the console framebuffer's own real physical frames directly into
/// the caller's address space, entirely bypassing `MMAP_FILE_CACHE`/`content_id` (this isn't oxfs
/// content, it's raw MMIO -- see `crate::fs::fd::framebuffer_geometry_of`'s own doc comment).
/// Reuses `drivers::usb::xhci`'s own `map_bar_pages` mapping shape (kernel-owned MMIO mapped into a
/// *user* page table this time, instead of the kernel's) -- every mapped leaf is tagged
/// `SHARED_LEAF` so `do_munmap`'s generic per-page unmap loop (and `AddressSpace::teardown`'s own
/// walk) never return these frames to the RAM frame allocator: they were never RAM to begin with,
/// and handing one back would let a later, wholly unrelated allocation get real framebuffer
/// physical memory. Clamped to the real framebuffer's own extent (`geom.len`) regardless of what
/// length the caller's `mmap()` requested -- asking for more than the real device provides maps
/// exactly the real device, never a page past its own physical end.
fn do_mmap_fb(
    caller_pid: Pid,
    geom: crate::drivers::fbdev::FbGeometry,
    requested_pages: u64,
    fixed_base: Option<u64>,
) -> Result<u64, u64> {
    let max_pages = (geom.len.max(1)).div_ceil(4096);
    let page_count = requested_pages.min(max_pages);
    let region_len = page_count * 4096;

    let base = match fixed_base {
        Some(base) => base,
        None => {
            let mut next = NEXT_MMAP_PAGE.lock();
            let base = *next;
            let end = base.checked_add(region_len).ok_or(ENOMEM)?;
            if end > MMAP_REGION_CEILING {
                return Err(ENOMEM);
            }
            *next = end;
            base
        }
    };

    let phys_offset = memory::phys_mem_offset();
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("mmap: current process missing from table");
    // SAFETY: me.address_space is the currently active address space -- same reasoning
    // do_mmap_anon's own identical comment already establishes.
    let mut mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };

    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | memory::address_space::SHARED_LEAF;
    for i in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(base + i * 4096));
        let frame = PhysFrame::<Size4KiB>::containing_address(x86_64::PhysAddr::new(
            geom.phys_base + i * 4096,
        ));
        with_frame_allocator(|fa| {
            // SAFETY: `frame` is the real framebuffer's own physical MMIO range (never RAM this
            // kernel hands out for anything else); `page` is this process's own freshly
            // bump-allocated (or MAP_FIXED-cleared) mmap VA -- can't alias any other live mapping.
            match unsafe { mapper.map_to(page, frame, flags, fa) } {
                Ok(flush) => flush.flush(),
                Err(x86_64::structures::paging::mapper::MapToError::PageAlreadyMapped(_)) => {}
                Err(_) => {}
            }
        });
    }
    me.shared.lock().mmap_phys_regions.push(MmapPhysRegion {
        va_start: base,
        npages: page_count,
    });
    drop(table);
    crate::console::framebuffer::set_owned_by_userspace(true);
    // See `console::stdin::RAW_KEYBOARD_OWNED`'s own doc comment -- a real `/dev/fb0` mapper is
    // exactly the shape of program that also wants exclusive raw keyboard ownership.
    crate::console::stdin::set_raw_keyboard_owned(true);
    Ok(base)
}

/// Real fd-backed mapping — `do_mmap`'s `fd >= 0` case, now honoring the caller's real
/// `MAP_SHARED`/`MAP_PRIVATE` choice (`private`) instead of always behaving as `MAP_SHARED`. Scoped
/// deliberately: a nonzero `off` is never actually populated/mapped from — a real, in-bounds
/// request still gets an honest `EINVAL` (no real caller in this kernel's own call graph, BusyBox/
/// TinyCC/musl itself, ever requests one), and one genuinely out-of-bounds gets a real `ENXIO` —
/// see the `off != 0` handling below for why that split exists and doesn't conflict with this same
/// function's own MPR handling for the (far more common) `off == 0` case.
///
/// **Content population/writeback goes through `crate::fs::fd::content_read`/`content_write`
/// (keyed by `content_id`, a real inode number), not any fd's own read/write callbacks** — found
/// live, not designed in from the start: `modules/oxfs`'s `oxfs_read` unconditionally fails
/// (`-EBADF`) for a fd still in `OpenFile::Write` state, which is exactly the state every real
/// caller's fd is still in at `mmap()` time (`open(O_CREAT|O_RDWR) -> ftruncate()/fstat() ->
/// mmap()`, never `close()`d first) — a population path built on the generic per-fd `read`
/// callback silently populated nothing for every real test that exercises this. Content-by-
/// identity sidesteps that, and (unlike a fd's own stream position, which `write()`/`fstat()`
/// calls before `mmap()` already moved forward) always reads from real offset `0`.
///
/// `fixed_base`, when set, is a real `MAP_FIXED` address (already alignment/canonical-validated,
/// and already had `do_mmap`'s own `do_munmap` pre-clear run against it) — used directly instead of
/// bump-allocating a fresh VA.
fn do_mmap_file_backed(
    caller_pid: Pid,
    fd: u64,
    off: u32,
    page_count: u64,
    prot: u64,
    private: bool,
    fixed_base: Option<u64>,
) -> Result<u64, u64> {
    // Real POSIX `[EOVERFLOW]`: "the value of off plus len exceeds the offset maximum established
    // in the open file description associated with fildes" (`mmap/31-1.c` in the conformance
    // pilot) -- a pure arithmetic check against this ABI's real `off_t` range (a 64-bit *signed*
    // type, matching musl's own x86_64 `off_t`; `i64::MAX`, not `u64::MAX`, is the real ceiling),
    // independent of the target object's own identity, so it runs before `content_id` is even
    // resolved. Checked with `u128` arithmetic -- `off` (already `u64`) plus a `len` approaching
    // `u64::MAX` would otherwise wrap `u64` itself, silently hiding the very overflow being tested
    // for. `off` only ever carries the wire format's own low 32 bits (see `oxidebsd_sys_mmap`'s own
    // doc comment) -- narrower than real POSIX `off_t`, but for exactly this check's purpose
    // (detecting a request that's *already* absurdly oversized) `len` alone reaching this magnitude
    // is what actually trips it; a real off_t-range caller past 4 GiB of file offset doesn't exist
    // anywhere in this kernel's own call graph (oxfs's own real per-file cap is ~4 MiB).
    let region_len = page_count * 4096;
    if (off as u128) + (region_len as u128) > i64::MAX as u128 {
        return Err(EOVERFLOW);
    }

    let content_id = crate::fs::fd::content_id_of(fd).ok_or(ENODEV)?;

    // Real POSIX MPR: "the file descriptor fildes shall have been opened with read permission,
    // regardless of the protection options specified. If PROT_WRITE is specified, the application
    // shall ensure that it has opened the file descriptor fildes with write permission unless
    // MAP_PRIVATE is specified" (`mmap/6-4.c`/`6-6.c`) -- neither was ever checked before, since
    // nothing before `crate::fs::fd::access_mode_of` existed queried a fd's real open-time access
    // mode at all. `6-6.c` fails the first (unconditional) half: a `MAP_PRIVATE`+`PROT_READ`
    // mapping of a fd opened `O_WRONLY` still needs read permission to populate the mapping's
    // initial content, private-copy semantics notwithstanding. `6-4.c` fails the second: `PROT_WRITE`
    // with `MAP_SHARED` on a fd opened `O_RDONLY`.
    let (fd_readable, fd_writable) = crate::fs::fd::access_mode_of(fd);
    if !fd_readable {
        return Err(EACCES);
    }
    if prot & PROT_WRITE != 0 && !private && !fd_writable {
        return Err(EACCES);
    }

    if PROCESS_TABLE
        .lock()
        .get(&caller_pid)
        .expect("mmap: current process missing from table")
        .shared
        .lock()
        .mmap_file_regions
        .len()
        >= MAX_MMAP_FILE_REGIONS
    {
        return Err(ENOMEM);
    }

    let phys_offset = memory::phys_mem_offset();
    let real_size = crate::fs::fd::content_size(content_id).max(0) as u64;

    if off != 0 {
        let off = off as u64;
        // Real POSIX `[ENXIO]`: "Addresses in the range [off,off+len) are invalid for the object
        // specified by fildes" (`mmap/28-1.c` in the conformance pilot) -- deliberately scoped to a
        // nonzero, caller-chosen starting offset. `off == 0` is never ENXIO here even when `len`
        // extends past the object's own real size -- that's real POSIX MPR territory instead (a
        // legal, common pattern this kernel already handles via a real *deferred* SIGBUS on the
        // actual out-of-bounds *reference*, not an upfront mmap()-time failure -- see
        // `covered_pages` below and `mmap/11-2.c`/`11-3.c`, which depend on that succeeding).
        if off >= real_size || off.saturating_add(region_len) > real_size {
            return Err(ENXIO);
        }
        // Still no real support for actually populating from a nonzero offset -- no real caller in
        // this kernel's own call graph (BusyBox, TinyCC, musl itself) ever requests one, and the
        // one case that does (a within-bounds nonzero offset) is purely hypothetical here, so this
        // stays an honest EINVAL rather than silently reading from offset 0 instead.
        return Err(EINVAL);
    }
    // Real POSIX MPR (`mmap/11-2.c`/`11-3.c` in the conformance pilot): only pages actually
    // overlapping the object's own real content -- including its final, real-content-plus-
    // zero-padding partial page -- ever get backed by a real frame. Anything past that, up to the
    // caller's own requested `page_count`, is deliberately left unmapped so a reference there
    // real-faults instead of silently succeeding against a zero-filled page; `signal_for_user_fault`
    // below is what turns that fault into a real `SIGBUS` rather than a reboot. Applies to both
    // MAP_SHARED and MAP_PRIVATE alike -- real POSIX MPR doesn't distinguish the two.
    let covered_pages = real_size.div_ceil(4096).min(page_count);

    let frames: Vec<PhysFrame<Size4KiB>> = if private {
        // Real MAP_PRIVATE: a fresh copy, populated once from the object's own real content but
        // never entered into MMAP_FILE_CACHE -- a second, independent MAP_PRIVATE of the same file
        // (by this or any other process) must never see this mapping's own writes, and this
        // mapping must never see another's. This kernel gets that "for free" by copying eagerly at
        // mmap() time instead of lazily copying-on-write at fault time, the same design choice
        // `fork` already makes elsewhere. Never written back either -- see `writeback_region`'s own
        // `shared` check below.
        let new_frames = with_frame_allocator(|fa| -> Result<Vec<PhysFrame<Size4KiB>>, u64> {
            let mut new_frames = Vec::with_capacity(covered_pages as usize);
            for _ in 0..covered_pages {
                let frame = fa.allocate_frame().ok_or(ENOMEM)?;
                let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
                unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
                new_frames.push(frame);
            }
            Ok(new_frames)
        })?;
        let covered_len = covered_pages * 4096;
        let read_len = real_size.min(covered_len);
        if read_len > 0 {
            let mut staging = alloc::vec![0u8; read_len as usize];
            let n =
                crate::fs::fd::content_read(content_id, 0, staging.as_mut_ptr() as u64, read_len);
            if n > 0 {
                staging.truncate(n as usize);
                for (i, chunk) in staging.chunks(4096).enumerate() {
                    let frame_ptr =
                        (phys_offset + new_frames[i].start_address().as_u64()).as_mut_ptr::<u8>();
                    unsafe {
                        core::ptr::copy_nonoverlapping(chunk.as_ptr(), frame_ptr, chunk.len())
                    };
                }
            }
        }
        new_frames
    } else {
        let mut cache = MMAP_FILE_CACHE.lock();
        let existing_len = cache.get(&content_id).map(Vec::len).unwrap_or(0) as u64;
        if existing_len < covered_pages {
            // First mmap of this file, or a later mmap asking for more real-content pages than any
            // earlier one did -- allocate+zero exactly the *new* frames needed and append them,
            // never discarding whatever's already cached (those frames may already be live in
            // another process's, or this same process's, own page table -- see MMAP_FILE_CACHE's
            // own doc comment for why replacing them outright would be a real correctness bug, not
            // just a missed optimization).
            let new_frames: Vec<PhysFrame<Size4KiB>> = with_frame_allocator(|fa| {
                let mut new_frames = Vec::with_capacity((covered_pages - existing_len) as usize);
                for _ in existing_len..covered_pages {
                    let frame = fa.allocate_frame().ok_or(ENOMEM)?;
                    let frame_ptr =
                        (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
                    unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
                    new_frames.push(frame);
                }
                Ok::<_, u64>(new_frames)
            })?;
            // Populate only the genuinely new region from real file content, via one staging
            // buffer read (read_inode_at already walks the real block chain internally, so this
            // doesn't need its own frame-by-frame loop the way population once did) then copied
            // out page by page (frames from a bump allocator aren't guaranteed physically
            // contiguous, so a single multi-page write through the phys-mem-offset window isn't
            // safe). Clamped to the real object's own current length -- a file shorter than the
            // requested mapping leaves the remainder zero (already true: `new_frames` start
            // zeroed), matching POSIX's own "bytes past EOF within the mapped region read as
            // zero".
            let new_region_start = existing_len * 4096;
            let covered_len = covered_pages * 4096;
            let read_len = real_size
                .saturating_sub(new_region_start)
                .min(covered_len - new_region_start);
            if read_len > 0 {
                let mut staging = alloc::vec![0u8; read_len as usize];
                let n = crate::fs::fd::content_read(
                    content_id,
                    new_region_start,
                    staging.as_mut_ptr() as u64,
                    read_len,
                );
                if n > 0 {
                    staging.truncate(n as usize);
                    for (i, chunk) in staging.chunks(4096).enumerate() {
                        let frame_ptr = (phys_offset + new_frames[i].start_address().as_u64())
                            .as_mut_ptr::<u8>();
                        unsafe {
                            core::ptr::copy_nonoverlapping(chunk.as_ptr(), frame_ptr, chunk.len())
                        };
                    }
                }
            }
            cache.entry(content_id).or_default().extend(new_frames);
        }
        // `.entry(...).or_default()`, not `.get(...).expect(...)`: the growth block above is
        // skipped entirely when `covered_pages == 0` (an object with no real content yet, e.g. a
        // freshly `open(O_CREAT)`'d file `mmap()`'d before any `write()`/`ftruncate()`) *and*
        // nothing was cached for this content_id before (`existing_len == 0`, so `0 < 0` is
        // false) -- the very first such mmap of a file had no entry to `.get()`, and the `.expect`
        // here panicked instead of just producing the correct empty `frames` list. Found live, not
        // caught by this session's own smoke test (every scenario there `ftruncate`s first).
        cache
            .entry(content_id)
            .or_default()
            .iter()
            .take(covered_pages as usize)
            .copied()
            .collect()
    };

    let base = match fixed_base {
        Some(base) => base,
        None => {
            let mut next = NEXT_MMAP_PAGE.lock();
            let base = *next;
            let end = next
                .checked_add(region_len)
                .filter(|&e| e <= MMAP_REGION_CEILING)
                .ok_or(ENOMEM)?;
            *next = end;
            base
        }
    };

    let writable = prot & PROT_WRITE != 0;
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if !private {
        // SHARED_LEAF: these frames are owned by MMAP_FILE_CACHE (keyed by content_id, real
        // cross-open sharing -- see that cache's own doc comment), not by this one mapping -- marks
        // every leaf so a real address-space teardown (`memory::address_space::AddressSpace::
        // teardown`) never frees one still cached/still live in another process's or another
        // mapping's own page table. See `SHARED_LEAF`'s own doc comment. A private mapping's own
        // frames are never shared this way, so they're left unmarked and get freed like any other
        // private leaf (matches every other private-anon-mmap/heap/stack frame already does).
        flags |= memory::address_space::SHARED_LEAF;
    }
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }

    let mut table = PROCESS_TABLE.lock();
    let me = table
        .get_mut(&caller_pid)
        .expect("mmap: current process missing from table");
    // SAFETY: see do_mmap's identical reasoning -- me.address_space is the currently active
    // address space.
    let mut mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };
    // Real `PROT_NONE` (`mmap/6-2.c`): neither `PROT_READ` nor `PROT_WRITE` set. Skipping the
    // mapping loop entirely reuses `signal_for_user_fault`'s own existing default with zero new
    // machinery -- that function already reports `SIGBUS` only for an address in a region's
    // `[mapped_pages, npages)` reserved-but-unbacked tail, `SIGSEGV` for everything else unmapped.
    // `mapped_pages` below is still recorded as the real `covered_pages` extent regardless (not
    // `0`), so a reference anywhere in `[va_start, va_start + covered_pages*4096)` -- real content
    // that exists but is genuinely off-limits under `PROT_NONE` -- correctly falls into that
    // "everything else" `SIGSEGV` case rather than being misclassified as the reserved tail.
    let prot_accessible = prot & (PROT_READ | PROT_WRITE) != 0;
    // Only `[base, base + covered_pages*4096)` is actually mapped -- `[covered_pages, page_count)`
    // is deliberately left with no page-table entry at all, real POSIX MPR (see MmapFileRegion's
    // own `mapped_pages` field doc comment); `covered_pages == 0` (the whole reservation is beyond
    // the object's own real content) skips this loop entirely.
    if covered_pages > 0 && prot_accessible {
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
        let end_page =
            Page::<Size4KiB>::containing_address(VirtAddr::new(base + covered_pages * 4096 - 1));
        with_frame_allocator(|fa| -> Result<(), u64> {
            for (page, frame) in Page::range_inclusive(start_page, end_page).zip(frames.iter()) {
                // SAFETY: `frame` is either one of MMAP_FILE_CACHE's own real backing frames (a
                // shared mapping, never reused for anything else) or a fresh, exclusively-owned
                // private frame (a private mapping, allocated just above) -- either way this
                // kernel has no frame-deallocation path for it to have gone stale, and `page` falls
                // in this process's own, freshly bump-allocated (or MAP_FIXED-validated) mmap
                // region.
                unsafe {
                    mapper
                        .map_to(page, *frame, flags, fa)
                        .map_err(|_| ENOMEM)?
                        .flush();
                }
            }
            Ok(())
        })?;
    }

    if !private {
        *MMAP_FILE_REFCOUNT.lock().entry(content_id).or_insert(0) += 1;
    }
    me.shared.lock().mmap_file_regions.push(MmapFileRegion {
        va_start: base,
        npages: page_count,
        mapped_pages: covered_pages,
        content_id,
        writable,
        shared: !private,
        locked: false,
    });

    Ok(base)
}

/// Real POSIX MPR (`mmap/11-2.c`/`11-3.c`): resolves what signal a ring-3 reference to `addr`
/// should raise, for `interrupts::page_fault_handler`'s own real-fault-to-signal delivery.
/// `SIGBUS` when `addr` falls inside a live fd-backed mapping's own reserved-but-unbacked tail
/// (`[mapped_pages, npages)` of one of `caller_pid`'s own `mmap_file_regions` -- see
/// `MmapFileRegion::mapped_pages`'s own doc comment), `SIGSEGV` for every other unmapped ring-3
/// reference (a real general fix in its own right -- this kernel used to reboot on any such
/// reference at all, ring-3 or not, rather than terminate just the one offending process).
pub fn signal_for_user_fault(caller_pid: Pid, addr: u64) -> u64 {
    let table = PROCESS_TABLE.lock();
    let Some(me) = table.get(&caller_pid) else {
        return crate::process::SIGSEGV;
    };
    let in_reserved_tail = me.shared.lock().mmap_file_regions.iter().any(|r| {
        let backed_end = r.va_start + r.mapped_pages * 4096;
        let reserved_end = r.va_start + r.npages * 4096;
        addr >= backed_end && addr < reserved_end
    });
    if in_reserved_tail {
        crate::process::SIGBUS
    } else {
        crate::process::SIGSEGV
    }
}

/// Writes one region's current frame content back to its real underlying file via
/// `crate::fs::fd::content_write`, keyed by `content_id` alone — real POSIX `MAP_SHARED`
/// correctness (a plain `read()` of the file after `munmap`, through a *fresh* `open()`, should
/// see what was written through the mapping), on top of what `MMAP_FILE_CACHE`'s own frame-sharing
/// already gives other *live* mappings for free. A no-op for a read-only mapping. **Clamped to the
/// real object's own current length, queried fresh (not cached from population time)** — real
/// POSIX: "the system shall never write out any modified portions of the last page of an object
/// which are beyond its end" (found live: `mmap/11-4.c`/`11-5.c` write a byte into the partial
/// page past a half-page-sized object's own end and require it to *never* persist — an earlier
/// version of this function wrote back the whole, page-rounded region unconditionally, silently
/// failing exactly this check). **Known, accepted simplification**: if the real object has grown
/// past what *this* region's own `npages` covers (a different fd resized it after this mapping was
/// created), writeback only touches the first `npages * 4096` bytes and leaves the rest of the
/// file's real content untouched by skipping entirely rather than risking a destructive partial
/// overwrite — no real caller in this kernel's own call graph hits this. Idempotent (safe to call
/// more than once, or on more than one still-live mapping of the same file) — oxfs's own write
/// model always replaces a file's whole content in one shot (see `modules/oxfs`'s `OpenFile::Write`
/// doc comment), so a redundant write-back just re-commits the same bytes.
fn writeback_region(region: &MmapFileRegion, phys_offset: VirtAddr) {
    if !region.shared || !region.writable {
        return;
    }
    let current_size = crate::fs::fd::content_size(region.content_id).max(0) as u64;
    let region_len = region.npages * 4096;
    if current_size > region_len {
        // See this function's own doc comment -- a partial-coverage writeback here would
        // truncate/destroy real content past what this one mapping ever saw.
        return;
    }
    let write_len = current_size;
    if write_len == 0 {
        return;
    }
    // Stages a contiguous buffer from MMAP_FILE_CACHE's own frame list (indexed `0..npages`, not
    // re-derived from `va_start`) -- this runs from `do_munmap`/exit cleanup, potentially after
    // the page is already unmapped from the caller's own table, so the content has to come from
    // the frame itself, not a fresh page-table walk; frames aren't guaranteed physically
    // contiguous, so `content_write` needs one assembled buffer, not a per-frame call (which would
    // also incorrectly re-replace the whole object's content on every single page).
    let mut staging = alloc::vec![0u8; write_len as usize];
    {
        let cache = MMAP_FILE_CACHE.lock();
        let Some(frames) = cache.get(&region.content_id) else {
            return;
        };
        for (i, chunk) in staging.chunks_mut(4096).enumerate() {
            let Some(frame) = frames.get(i) else { break };
            let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_ptr::<u8>();
            unsafe { core::ptr::copy_nonoverlapping(frame_ptr, chunk.as_mut_ptr(), chunk.len()) };
        }
    }
    crate::fs::fd::content_write(region.content_id, staging.as_ptr() as u64, write_len);
}

/// `SYS_MUNMAP`'s real logic. Unmaps every page actually present in `[addr, addr + len)` from the
/// caller's own table (sound without a `FrameDeallocator` -- only *freeing* the backing frames
/// would need one, and this kernel has no frame-deallocation path anywhere; frames leak, same
/// policy as `MMAP_REGION_BASE`/`module::NEXT_MODULE_PAGE`). Doesn't error on a page that was
/// never mapped (matches real `munmap(2)`, which only fails for a misaligned `addr`, never for
/// "nothing was mapped there"). Separately, if `addr` exactly matches a live fd-backed region's own
/// `va_start` (the shape every real caller here always uses -- `munmap` exactly what `mmap`
/// returned), writes its content back and releases the extra reference `do_mmap_file_backed` took
/// out (see `crate::fs::fd::capture_for_mmap`'s own doc comment for why that reference exists at
/// all) -- real POSIX: the file itself is never actually removed by this kernel (no deallocation
/// anywhere), so "removed when there are no more mappings" is honestly satisfied by "no longer
/// artificially kept open past the caller's own `close()`".
pub fn do_munmap(caller_pid: Pid, addr: u64, len: u64) -> Result<u64, u64> {
    if len == 0 {
        return Err(EINVAL);
    }
    // Real POSIX: "the implementation shall require that addr be a multiple of the page size" --
    // `munmap/3-1.c` in the conformance pilot exercises this directly.
    if !addr.is_multiple_of(4096) {
        return Err(EINVAL);
    }
    let page_count = len.div_ceil(4096);
    // Real, checked arithmetic, not `page_count * 4096` / `addr + region_len - 1` -- found live by
    // the POSIX conformance pilot's own `mmap/31-1.c`: it deliberately calls `munmap((void*)-1,
    // ULONG_MAX)` (an *unconditional* cleanup call after an expected-to-fail `mmap()`, not even
    // gated on that mmap having actually succeeded), and the old unchecked arithmetic panicked
    // ("attempt to add with overflow") on exactly that input, rebooting the whole VM instead of a
    // clean per-syscall error return -- a real hardening gap independent of the pilot itself, since
    // any real userland program passing similarly extreme values would hit the same panic. `addr`
    // and the computed end address are also rejected outright unless both are canonical
    // (`VirtAddr::try_new`, not `new`, which panics the same way) -- a non-canonical `addr` is
    // never a real prior `mmap()` result, so `EINVAL` is the correct response, not a second panic.
    let Some(region_len) = page_count.checked_mul(4096) else {
        return Err(EINVAL);
    };
    let Some(end_addr_inclusive) = addr.checked_add(region_len).and_then(|e| e.checked_sub(1))
    else {
        return Err(EINVAL);
    };
    if VirtAddr::try_new(addr).is_err() || VirtAddr::try_new(end_addr_inclusive).is_err() {
        return Err(EINVAL);
    }
    let phys_offset = memory::phys_mem_offset();

    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("munmap: current process missing from table");

    let file_region_idx = me
        .shared
        .lock()
        .mmap_file_regions
        .iter()
        .position(|r| r.va_start == addr);
    let phys_region_idx = me
        .shared
        .lock()
        .mmap_phys_regions
        .iter()
        .position(|r| r.va_start == addr);

    // SAFETY: me.address_space is the currently active address space -- same reasoning do_mmap's
    // own identical comment already establishes.
    let mut mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };
    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(end_addr_inclusive));

    // Real x86 hardware DIRTY-bit check, read *before* unmapping (Mapper::unmap removes the PTE
    // entirely, so this has to happen first) -- lets writeback_region below skip real work
    // entirely for a mapping that was never actually written through, not just a writable one.
    // Found live, not designed in up front: `mmap/10-1.c` (the POSIX conformance pilot)
    // mmap()+munmap()s the same never-written-to file 100,000 times in a loop -- harmless with no
    // real disk attached (every automated `cargo test` target boots that way, see CLAUDE.md's
    // disk-persistence section), but with a real persistent disk attached (an ordinary interactive
    // `cargo run`), unconditional writeback meant 100,000 real, individually-polled-PIO ATA writes
    // -- easily enough to blow past `t0`'s own 40s timeout on real hardware/QEMU-TCG timing, even
    // though not one byte was ever actually modified.
    let any_dirty = file_region_idx.is_some()
        && Page::range_inclusive(start_page, end_page).any(|page| {
            matches!(
                mapper.translate(page.start_address()),
                TranslateResult::Mapped { flags, .. } if flags.contains(PageTableFlags::DIRTY)
            )
        });

    for page in Page::range_inclusive(start_page, end_page) {
        // Real hardening, not just tidiness: a kernel-only (non-USER_ACCESSIBLE) mapping is always
        // a *shared*, kernel-half PML4/PDPT/PD entry aliased into every address space by reference
        // (see `memory::address_space::copy_table_level`'s own doc comment) -- `Mapper::unmap`
        // would still happily remove such an entry if asked, corrupting that shared mapping for
        // every other process, not just this one. `addr`/`len` are entirely caller-controlled with
        // no prior validation that they ever came from a real `mmap()` return value, so this check
        // is the only thing standing between a wild `munmap()` call and exactly that.
        //
        // Real frame reclaim, found live chasing the POSIX conformance pilot's own full-corpus
        // frame exhaustion: `Mapper::unmap` hands back the exact frame it just unmapped, but this
        // used to discard it (`(_, flush)`) instead of ever returning it to the frame allocator --
        // a genuine, permanent leak of every page any real `munmap()` call ever unmapped, distinct
        // from (and far more common than) the already-documented "no frame dealloc for module/
        // SysV-shm/MAP_SHARED-owned frames" gap. Real musl's own `pthread_join()`/`__munmap`
        // unmaps a joined thread's stack on every single join, and the POSIX pilot's own `mmap/
        // munmap` directories call this directly too -- both silently leaked one frame per unmapped
        // page forever. `SHARED_LEAF` frames (fd-backed `MAP_SHARED`) are the one real exception,
        // same as `AddressSpace::teardown`'s own walk -- that content is owned by
        // `MMAP_FILE_CACHE`, released via `release_mmap_file_ref` below instead, never by this
        // per-page free.
        let translated = mapper.translate(page.start_address());
        let (is_user_page, is_shared_leaf) = match translated {
            TranslateResult::Mapped { flags, .. } => (
                flags.contains(PageTableFlags::USER_ACCESSIBLE),
                flags.contains(memory::address_space::SHARED_LEAF),
            ),
            _ => (false, false),
        };
        if !is_user_page {
            continue;
        }
        if let Ok((frame, flush)) = mapper.unmap(page) {
            flush.flush();
            if !is_shared_leaf {
                // SAFETY: this frame was exclusively backing this one now-removed mapping (a
                // private/anonymous page, never a SHARED_LEAF one, checked above) -- no other
                // page table can be viewing it, same ownership guarantee `AddressSpace::teardown`'s
                // own per-leaf free already relies on.
                with_frame_allocator(|fa| unsafe { fa.deallocate_frame(frame) });
            }
        }
    }

    if let Some(idx) = file_region_idx {
        let region = me.shared.lock().mmap_file_regions.remove(idx);
        drop(table);
        if any_dirty {
            writeback_region(&region, phys_offset);
        }
        // A private region was never entered into MMAP_FILE_CACHE/MMAP_FILE_REFCOUNT in the first
        // place (see do_mmap_file_backed's own doc comment) -- releasing a reference for it would
        // either be a no-op (nothing shared this content_id yet) or, worse, wrongly decrement a
        // real shared mapping's own refcount if one happens to exist for the same file.
        if region.shared {
            release_mmap_file_ref(region.content_id);
        }
    } else if let Some(idx) = phys_region_idx {
        // No writeback/refcount to release -- see MmapPhysRegion's own doc comment. The per-page
        // unmap loop above already skipped freeing these frames (SHARED_LEAF) -- this just drops
        // this process's own bookkeeping entry and, once no such mapping remains anywhere, lets
        // `console::framebuffer::redraw()` resume (see `set_owned_by_userspace`'s own doc
        // comment).
        let mut shared = me.shared.lock();
        shared.mmap_phys_regions.remove(idx);
        let none_left = shared.mmap_phys_regions.is_empty();
        drop(shared);
        drop(table);
        if none_left {
            crate::console::framebuffer::set_owned_by_userspace(false);
            crate::console::stdin::set_raw_keyboard_owned(false);
        }
    }

    Ok(0)
}

/// `SYS_MSYNC`'s real logic — real Linux value `26`, unremapped (see `writeback_region`'s own doc
/// comment for why this used to be a structural non-issue: mmap was always anonymous/private).
/// Flushes a live fd-backed `MAP_SHARED` region back to its real underlying file on demand — the
/// same `writeback_region` `do_munmap`/exit cleanup already call, just invoked mid-mapping instead
/// of at teardown. `addr` must be page-aligned (real POSIX `EINVAL` otherwise — unlike
/// `mlock`/`munlock` below, `msync(2)` actually documents this requirement) and must fall inside a
/// still-live mapping in the caller's own `mmap_file_regions` (`ENOMEM` otherwise, matching real
/// Linux's own "address doesn't correspond to a mapping" error). `MS_ASYNC`/`MS_SYNC` aren't
/// distinguished — no async I/O queue exists to differentiate them, so both just flush
/// synchronously before returning, same honesty tier `fsync`'s own doc comment already sets;
/// `MS_INVALIDATE` is otherwise a no-op — this kernel has no separate page-cache copy to
/// invalidate, `MAP_SHARED` here already shares `MMAP_FILE_CACHE`'s own live frames directly —
/// **except** against a region `mlockall(MCL_CURRENT)` marked `locked` (`MmapFileRegion::locked`'s
/// own doc comment): real POSIX documents `EBUSY` there ("a mapping... could not be synchronized
/// because it is locked", `mlockall/3-6.c`), so that combination is checked and rejected before
/// any writeback happens, real page-pinning or not. `len` isn't range-checked against the region's
/// own extent — every real caller in this kernel's own call graph flushes a whole mapping at once
/// (the shape `msync(addr, real_len, ...)` always takes), and `writeback_region` itself only ever
/// writes the region's real content regardless.
pub fn do_msync(caller_pid: Pid, addr: u64, len: u64, flags: u64) -> Result<u64, u64> {
    const MS_ASYNC: u64 = 1;
    const MS_INVALIDATE: u64 = 2;
    const MS_SYNC: u64 = 4;
    let _ = len;
    if !addr.is_multiple_of(4096) || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 {
        return Err(EINVAL);
    }
    if flags & MS_ASYNC != 0 && flags & MS_SYNC != 0 {
        return Err(EINVAL);
    }

    let phys_offset = memory::phys_mem_offset();
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("msync: current process missing from table");
    let shared = me.shared.lock();
    let region = shared
        .mmap_file_regions
        .iter()
        .find(|r| addr >= r.va_start && addr < r.va_start + r.npages * 4096)
        .ok_or(ENOMEM)?;
    if flags & MS_INVALIDATE != 0 && region.locked {
        return Err(EBUSY);
    }
    writeback_region(region, phys_offset);
    Ok(0)
}

/// Real cleanup for every fd-backed mapping a process still had live at exit/`execve` — writes
/// back and releases each one's `MMAP_FILE_CACHE` reference, the same way an explicit `munmap`
/// would, since neither event ever calls `do_munmap` itself. Called from
/// `process::lifecycle::terminate_process` (before `PROCESS_TABLE` is locked, same placement
/// `crate::fs::sysv_shm::detach_all_for_exit`'s own call site already establishes) and from
/// `do_execve` (after the new `AddressSpace` is committed -- the old one, and every page mapped
/// into it, just became unreachable, matching real Linux's own implicit-unmap-on-execve).
pub fn cleanup_mmap_file_regions_for_exit(pid: Pid) {
    let regions = {
        let table = PROCESS_TABLE.lock();
        let Some(me) = table.get(&pid) else {
            return;
        };
        core::mem::take(&mut me.shared.lock().mmap_file_regions)
    };
    if regions.is_empty() {
        return;
    }
    let phys_offset = memory::phys_mem_offset();
    for region in &regions {
        writeback_region(region, phys_offset);
        // See do_munmap's own identical guard -- a private region was never counted in
        // MMAP_FILE_REFCOUNT to begin with.
        if region.shared {
            release_mmap_file_ref(region.content_id);
        }
    }
}

/// Real cleanup for every real `/dev/fb0` (or future MMIO-backed) mapping a process still had live
/// at exit/`execve` -- sibling of `cleanup_mmap_file_regions_for_exit` above, called from the same
/// two sites. No writeback/refcount to release (see `MmapPhysRegion`'s own doc comment); the actual
/// page-table teardown for a self-exit or execve happens generically elsewhere (`AddressSpace::
/// teardown`'s own `SHARED_LEAF`-skipping walk) -- this just drops the bookkeeping and, once no
/// such mapping remains anywhere, lets `console::framebuffer::redraw()` resume.
pub fn cleanup_mmap_phys_regions_for_exit(pid: Pid) {
    let had_any = {
        let table = PROCESS_TABLE.lock();
        let Some(me) = table.get(&pid) else {
            return;
        };
        let mut shared = me.shared.lock();
        let had_any = !shared.mmap_phys_regions.is_empty();
        shared.mmap_phys_regions.clear();
        had_any
    };
    if had_any {
        crate::console::framebuffer::set_owned_by_userspace(false);
        crate::console::stdin::set_raw_keyboard_owned(false);
    }
}

/// Whether `pid` currently holds any live real `/dev/fb0` (or future MMIO) mapping -- used by
/// `process::signals`'s own real `SIGSTOP`/`SIGTSTP`/`SIGCONT` handling to correctly suspend and
/// restore display/keyboard ownership across a real job-control stop/resume (Ctrl+Z / `fg`), not
/// just a full process exit. **Found live, a real bug**: without this, stopping a process that
/// owns the framebuffer left `console::framebuffer::redraw()` permanently suppressed and
/// `console::stdin`'s own echo permanently gated off even once control genuinely returned to the
/// foreground shell -- the shell kept running and reading input correctly, but with the graphical
/// screen frozen on the stopped program's last frame and every subsequent keystroke silently
/// unechoed, looking exactly like "nothing responds anymore" even though the shell itself was
/// perfectly alive underneath.
pub fn has_live_phys_mapping(pid: Pid) -> bool {
    PROCESS_TABLE
        .lock()
        .get(&pid)
        .is_some_and(|p| !p.shared.lock().mmap_phys_regions.is_empty())
}

/// `SYS_MPROTECT`'s real logic — scoped real enforcement, not the total no-op this used to be.
/// `NO_EXECUTE`/`EFER.NXE` still isn't plumbed anywhere in this kernel, so `PROT_EXEC` is silently
/// ignored same as before; `PROT_READ`/`PROT_WRITE` now genuinely toggle `USER_ACCESSIBLE`/
/// `WRITABLE` on the caller's own existing page-table entries -- **but only for an address range
/// entirely inside the mmap-managed VA window** (`MMAP_REGION_BASE..MMAP_REGION_CEILING`, where
/// every `mmap()`'d region -- anonymous or file-backed -- already lives, see `NEXT_MMAP_PAGE`).
/// Anything outside it (a `PT_LOAD` ELF segment, the heap, a thread's own fixed-VA stack, ...)
/// stays the exact permissive no-op this function has always been, unconditionally `Ok(0)` --
/// real, unmodified `ld.so`'s own RELRO step (`mprotect`ing its relocated `PT_GNU_RELRO` segment
/// read-only, far outside this window) must keep working exactly as it did before this landed.
///
/// This isn't just scope discipline, it's a real safety requirement: this window is the only VA
/// range guaranteed to hold nothing but *this exact process's own* freshly-allocated page-table
/// structures. The module/kernel region's lower page-table levels are the same physical frames
/// referenced from every process's own L4 table (`AddressSpace::new`'s own doc comment) --
/// blindly granting `USER_ACCESSIBLE` there from an ordinary unprivileged `mprotect()` call would
/// leak a kernel-owned mapping to every process on the system, not just the caller.
///
/// Real `EINVAL` for a misaligned `addr`, checked only once already inside the window (so it can
/// never newly reject a call this function used to silently accept outside it). **No
/// `range_fully_mapped`/`ENOMEM` precondition** -- unlike `do_mlock`/`do_munlock`'s identical-
/// looking check, a page inside this window can legitimately be currently *unmapped*: a real
/// `PROT_NONE` guard region (`do_mmap_anon`'s own doc comment) is reserved VA with no page-table
/// entry at all, and widening it back to real access is exactly the scenario this function has to
/// handle -- a not-yet-`Mapped` page here demand-allocates a fresh, zeroed frame and maps it with
/// fully-open intermediate flags (identical reasoning to `do_mmap_anon`'s own `parent_table_flags`)
/// rather than erroring; an already-`Mapped` page just has its existing leaf's `WRITABLE`/
/// `USER_ACCESSIBLE` bits toggled via `update_flags`, preserving every other bit (`SHARED_LEAF`
/// included).
pub fn do_mprotect(caller_pid: Pid, addr: u64, len: u64, prot: u64) -> Result<u64, u64> {
    if len == 0 {
        return Ok(0);
    }
    let Some(end_inclusive) = addr.checked_add(len).and_then(|e| e.checked_sub(1)) else {
        return Ok(0);
    };
    if addr < MMAP_REGION_BASE || end_inclusive >= MMAP_REGION_CEILING {
        return Ok(0);
    }
    if !addr.is_multiple_of(4096) {
        return Err(EINVAL);
    }

    let prot_accessible = prot & (PROT_READ | PROT_WRITE) != 0;
    let writable = prot & PROT_WRITE != 0;
    let mut leaf_flags = PageTableFlags::PRESENT;
    if prot_accessible {
        leaf_flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    if writable {
        leaf_flags |= PageTableFlags::WRITABLE;
    }
    // Always fully open -- see do_mmap_anon's identical reasoning.
    let parent_table_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

    let phys_offset = memory::phys_mem_offset();
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("mprotect: current process missing from table");
    // SAFETY: see do_mmap's identical reasoning -- me.address_space is the currently active
    // address space.
    let mut mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };
    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(end_inclusive));
    with_frame_allocator(|fa| -> Result<(), u64> {
        for page in Page::range_inclusive(start_page, end_page) {
            match mapper.translate(page.start_address()) {
                TranslateResult::Mapped {
                    flags: old_flags, ..
                } => {
                    let mut new_flags =
                        old_flags & !(PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE);
                    new_flags |=
                        leaf_flags & (PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE);
                    // SAFETY: only ever narrows/widens WRITABLE/USER_ACCESSIBLE on a page this
                    // exact process already owns inside its own private mmap window (or, for a
                    // real CLONE_VM/CLONE_THREAD sibling, the whole shared address space --
                    // matching real POSIX: mprotect changes the entire process's protections,
                    // visible to every thread sharing it). A real flush, not `.ignore()`: unlike a
                    // freshly-mapped page with no prior TLB entry, this can be *narrowing* an
                    // already-cached mapping's permissions, which must take effect immediately.
                    unsafe {
                        mapper
                            .update_flags(page, new_flags)
                            .map_err(|_| ENOMEM)?
                            .flush();
                    }
                }
                _ => {
                    // Not yet backed -- a still-PROT_NONE guard sub-range being widened for the
                    // first time. Demand-allocate now, matching do_mmap_anon's own eager-zero-fill
                    // convention for every other anonymous page.
                    let frame = fa.allocate_frame().ok_or(ENOMEM)?;
                    let frame_ptr =
                        (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
                    unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
                    // SAFETY: frame was just allocated (unused, per BootInfoFrameAllocator's
                    // contract); page is confirmed not-Mapped above, and falls inside this
                    // process's own mmap window.
                    unsafe {
                        mapper
                            .map_to_with_table_flags(
                                page,
                                frame,
                                leaf_flags,
                                parent_table_flags,
                                fa,
                            )
                            .map_err(|_| ENOMEM)?
                            .flush();
                    }
                }
            }
        }
        Ok(())
    })?;
    Ok(0)
}

/// True only if every page in `[addr, addr+len)` is currently mapped in `caller_pid`'s own address
/// space — the one real check `do_mlock`/`do_munlock` below actually perform, matching real Linux's
/// own `ENOMEM` ("address range doesn't correspond to mapped pages") for both calls. Read-only
/// (`Translate`, not `Mapper::map_to`/`unmap`) — this never changes what's mapped, only reports on
/// it.
fn range_fully_mapped(caller_pid: Pid, addr: u64, len: u64) -> bool {
    let Some(end_inclusive) = addr.checked_add(len).and_then(|e| e.checked_sub(1)) else {
        return false;
    };
    if VirtAddr::try_new(addr).is_err() || VirtAddr::try_new(end_inclusive).is_err() {
        return false;
    }
    let phys_offset = memory::phys_mem_offset();
    let table = PROCESS_TABLE.lock();
    let Some(me) = table.get(&caller_pid) else {
        return false;
    };
    // SAFETY: me.address_space is the currently active address space -- same reasoning do_mmap's
    // own identical comment already establishes; read-only here, no mutation.
    let mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };
    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(end_inclusive));
    Page::range_inclusive(start_page, end_page).all(|page| {
        matches!(
            mapper.translate(page.start_address()),
            TranslateResult::Mapped { .. }
        )
    })
}

/// `SYS_MLOCK`/`SYS_MUNLOCK`'s real logic — real Linux values `509`/`510` (moved off the real
/// `149`/`150` slots, which collide with this ABI's own live `SYS_SOCKETPAIR`/`SYS_SET_TID_ADDRESS`
/// — see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own collision table). Deliberately a no-op success
/// beyond the range check below: this kernel never pages anything out (no swap, no reclaim of any
/// kind anywhere), so "lock this page so it can't be swapped" is a no-op by construction, not a
/// missing capability — same honesty tier `do_mprotect` above already establishes. Still performs
/// the one real, cheap check both real `mlock(2)`/`munlock(2)` document: `ENOMEM` if the requested
/// range isn't entirely mapped (`range_fully_mapped`) — a genuine correctness bound even though
/// nothing is actually locked. `len == 0` always succeeds trivially (matches real Linux).
pub fn do_mlock(caller_pid: Pid, addr: u64, len: u64) -> Result<u64, u64> {
    if len == 0 {
        return Ok(0);
    }
    if range_fully_mapped(caller_pid, addr, len) {
        Ok(0)
    } else {
        Err(ENOMEM)
    }
}

/// See `do_mlock`'s own doc comment — `munlock(2)` documents the identical `ENOMEM` range
/// requirement, and there's no real per-page locked state anywhere in this kernel to actually
/// clear, so the two share one implementation.
pub fn do_munlock(caller_pid: Pid, addr: u64, len: u64) -> Result<u64, u64> {
    do_mlock(caller_pid, addr, len)
}

/// `SYS_MLOCKALL`/`SYS_MUNLOCKALL`'s real logic — real Linux values `511`/`512`, moved off `151`/
/// `152` for the same `SYS_FCNTL`/`SYS_SHUTDOWN` collision reasons `do_mlock` documents. `mlockall`
/// validates `flags` is a real, nonzero combination of `MCL_CURRENT`/`MCL_FUTURE`/`MCL_ONFAULT`
/// (real Linux `EINVAL` otherwise — at least one of `MCL_CURRENT`/`MCL_FUTURE` is required).
/// `MCL_ONFAULT` stays the same unenforced no-op tier `do_mlock` above documents (no fault-time
/// locking exists to make real). `MCL_FUTURE` flips `ThreadGroupShared::mlockall_future`, which
/// `do_mmap` consults on every later mapping — see that field's own doc comment. `MCL_CURRENT`
/// snapshots every one of the caller's own currently-live `mmap_file_regions` as `locked` (real
/// POSIX: locks pages *currently* mapped, not a standing policy for future ones the way
/// `MCL_FUTURE` is) — the one place this becomes observable is `do_msync`'s own `MS_INVALIDATE`
/// check (`mlockall/3-6.c`), still no real page-pinning/eviction-prevention beyond that. `munlockall`
/// clears `mlockall_future`, `locked_bytes`, and every region's own `locked` flag (real POSIX:
/// `munlockall()` unlocks everything and cancels a prior `MCL_FUTURE`) and otherwise always
/// succeeds.
pub fn do_mlockall(caller_pid: Pid, flags: u64) -> Result<u64, u64> {
    const MCL_CURRENT: u64 = 1;
    const MCL_FUTURE: u64 = 2;
    const MCL_ONFAULT: u64 = 4;
    if flags == 0 || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0 {
        return Err(EINVAL);
    }
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("mlockall: current process missing from table");
    let mut shared = me.shared.lock();
    if flags & MCL_FUTURE != 0 {
        shared.mlockall_future = true;
    }
    if flags & MCL_CURRENT != 0 {
        for region in shared.mmap_file_regions.iter_mut() {
            region.locked = true;
        }
    }
    Ok(0)
}

pub fn do_munlockall(caller_pid: Pid) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("munlockall: current process missing from table");
    let mut shared = me.shared.lock();
    shared.mlockall_future = false;
    shared.locked_bytes = 0;
    for region in shared.mmap_file_regions.iter_mut() {
        region.locked = false;
    }
    Ok(0)
}

/// Ceiling for `SYS_BRK`-managed heap growth — matches `module::MODULE_VA_BASE` so a growing heap
/// can never collide with the kernel-mapped module region every address space shares. Moved
/// 0x10000000 -> 0x20000000 alongside that constant -- see its own doc comment.
const BRK_REGION_CEILING: u64 = 0x_2000_0000;
/// `SYS_BRK`'s real logic. `addr == 0` queries the current value without changing it (the
/// convention every real `sbrk(0)` already relies on). Shrinking just lowers the stored value —
/// no unmap, same no-reclaim simplification `do_munmap` above documents. Growing maps freshly
/// zeroed pages from the first not-yet-mapped page onward: `brk` isn't necessarily page-aligned
/// (a previous grow may have stopped mid-page), so the *page containing* the old value is already
/// mapped and must be skipped, not re-mapped (`Mapper::map_to` fails on an already-present page).
pub fn do_brk(caller_pid: Pid, addr: u64) -> Result<u64, u64> {
    let phys_offset = memory::phys_mem_offset();
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("brk: current process missing from table");
    let mut shared = me.shared.lock();

    if addr == 0 {
        return Ok(shared.brk.as_u64());
    }
    if addr <= shared.brk.as_u64() {
        shared.brk = VirtAddr::new(addr);
        return Ok(addr);
    }
    if addr > BRK_REGION_CEILING {
        return Err(ENOMEM);
    }

    let old_top = shared.brk.as_u64();
    let new_top = addr;
    let map_start = old_top.div_ceil(4096) * 4096;
    if new_top > map_start {
        // SAFETY: see do_mmap's identical reasoning -- me.address_space is the currently active
        // address space.
        let mut mapper = unsafe {
            me.address_space
                .as_ref()
                .expect("mm: caller has no address space")
                .mapper(phys_offset)
        };
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(map_start));
        let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(new_top - 1));
        with_frame_allocator(|fa| -> Result<(), u64> {
            for page in Page::range_inclusive(start_page, end_page) {
                let frame = fa.allocate_frame().ok_or(ENOMEM)?;
                // SAFETY: frame was just allocated; page starts at the first not-yet-mapped page
                // past the current brk, so it isn't already present.
                unsafe {
                    mapper
                        .map_to(
                            page,
                            frame,
                            PageTableFlags::PRESENT
                                | PageTableFlags::WRITABLE
                                | PageTableFlags::USER_ACCESSIBLE,
                            fa,
                        )
                        .map_err(|_| ENOMEM)?
                        .flush();
                }
                let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
                unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
            }
            Ok(())
        })?;
    }

    shared.brk = VirtAddr::new(new_top);
    Ok(new_top)
}
