use alloc::sync::Arc;

use x86_64::VirtAddr;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, OffsetPageTable, PageTable, PageTableFlags, PhysFrame,
    Size4KiB,
};

use crate::memory::frame_to_page_table;

/// Marks a leaf page-table entry as **not** exclusively owned by the address space it's mapped
/// into — real SysV `shmat` (`fs::sysv_shm::do_shmat`) and real fd-backed `MAP_SHARED` mmap
/// (`process::mm::do_mmap_file_backed`) both set this on every leaf they map, since both point
/// multiple processes' own page tables at the *same* physical frames (a real, separately-owned
/// backing store — `SEGMENTS`' own `frames: Vec<PhysFrame>` for shm, `MMAP_FILE_CACHE` for
/// fd-backed mmap). `free_table_level` below (`AddressSpace::teardown`'s own recursive walk) checks
/// this on every leaf and skips freeing any that carries it — the sole mechanism that makes real
/// per-address-space frame reclaim safe to add without also reworking either subsystem's own
/// already-established "detach releases a reference/count, doesn't necessarily unmap" cleanup
/// timing (see `fs::sysv_shm::detach_all_for_exit`'s own doc comment, which explicitly still never
/// unmaps on a real process exit). Reuses `PageTableFlags::BIT_9`, one of the hardware-ignored
/// "available for OS use" bits (9-11) — unused anywhere else in this codebase before this.
///
/// **Fixed**: `copy_table_level`'s own real eager-copy `fork()` path now special-cases a leaf
/// carrying this flag — instead of copying its content into a freshly allocated private frame (the
/// treatment every other leaf gets), it aliases the *exact same* physical frame into the child's
/// table, matching real POSIX fork() semantics for an inherited `shmat`/`MAP_SHARED` mapping (a
/// write through either process's own mapping is genuinely visible through the other's). Still
/// always safe for `teardown` to skip freeing regardless of how many address spaces now alias it —
/// see that method's own doc comment. `fs::sysv_shm::inherit_attachments_for_fork` is the matching
/// `nattch`/attach-list bookkeeping half for the SysV case, called right after `AddressSpace::fork`
/// from `do_fork_from_current`; a fd-backed `MAP_SHARED` mmap's own `ThreadGroupShared::
/// mmap_file_regions` bookkeeping is deliberately *not* given the same treatment (out of scope —
/// no live caller needed it, and it's a fresh `ThreadGroupShared` per forked child regardless, same
/// as every other `ThreadGroupShared` field) — the underlying page content is still correctly
/// shared either way, only that list's own refcount/writeback tracking stays unaware of the child's
/// implicit inheritance, a narrower and already-precedented gap (matches `shmat`'s own "mapping
/// never unmaps on exit" laissez-faire tracking).
pub const SHARED_LEAF: PageTableFlags = PageTableFlags::BIT_9;

/// A separate top-level page table — a distinct virtual address space from the kernel's own.
///
/// New address spaces start as a **shallow** copy of the kernel's own level 4 table: the copy is
/// just 512 raw entries (pointers to lower-level tables), so it shares every one of the kernel's
/// existing mappings (code, heap, stacks, the physical-memory-offset window) with the original,
/// rather than duplicating them. That's deliberate — the kernel must stay identically mapped and
/// reachable no matter which address space is active, since interrupt/exception handlers run in
/// the *kernel's* context regardless of what was running when they fired. Only entries this
/// address space adds later (e.g. a loaded ELF's segments) are actually new and private to it.
///
/// `level_4_frame` is `Arc`-wrapped so real `clone(2)`/`CLONE_VM` threads can genuinely share one
/// address space (`share()` below) rather than each getting their own eager copy the way `fork()`
/// does — `Clone` on this whole type is just an `Arc::clone` refcount bump, safe and cheap.
#[derive(Clone)]
pub struct AddressSpace {
    level_4_frame: Arc<PhysFrame>,
}

impl AddressSpace {
    /// Creates a new address space seeded with the kernel's current mappings.
    ///
    /// **Only safe to call when the currently active table's low half (user-space entries) is
    /// already empty** -- this clones *all* 512 entries unconditionally, not just the kernel
    /// half, so if the active table already has real user mappings (i.e. this is called from
    /// inside an already-running process, not at boot against the kernel's own address space),
    /// the result silently *aliases* those mappings into the new table instead of leaving room
    /// for fresh ones. True for `process::spawn` (only ever called while the *kernel's own*
    /// address space -- no user mappings at all -- is active) but **not** for `AddressSpace::fork`
    /// or `process::do_execve`'s replacement address space, both of which run with the calling
    /// process's own, already-populated address space active and need `fork`/
    /// `new_excluding_user` below instead.
    ///
    /// # Errors
    ///
    /// `Err(())` on real frame exhaustion -- see `build_from_active`'s own doc comment for the
    /// real-crash-vs-real-`ENOMEM` reasoning this and every other constructor here now shares. No
    /// partial state to clean up on this path: the single allocation below is the only one this
    /// constructor ever does (the rest is a plain, non-allocating raw-entry clone), so a failure
    /// here never left anything behind. `#[allow(clippy::result_unit_err)]`: no real error-detail
    /// type exists anywhere in this codebase's own OOM paths yet (see `build_from_active`'s own
    /// doc comment) -- every caller only ever branches on `Ok`/`Err`, never inspects the value.
    #[allow(clippy::result_unit_err)]
    pub fn new(
        physical_memory_offset: VirtAddr,
        frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<Self, ()> {
        let new_frame = frame_allocator.allocate_frame().ok_or(())?;
        let (active_frame, _flags) = Cr3::read();

        // SAFETY: physical_memory_offset is the bootloader's phys-memory mapping (same
        // requirement as memory::init); active_frame is CR3's own live level 4 table, read fresh
        // above, and new_frame was just allocated so nothing else can be viewing it yet.
        let (active_table, new_table) = unsafe {
            (
                frame_to_page_table(active_frame, physical_memory_offset),
                frame_to_page_table(new_frame, physical_memory_offset),
            )
        };
        *new_table = active_table.clone();

        Ok(AddressSpace {
            level_4_frame: Arc::new(new_frame),
        })
    }

    /// Builds a fresh address space that shares every one of the currently active table's
    /// kernel-only mappings but excludes its user-accessible ones entirely (used by
    /// `process::do_execve`, which needs a totally clean user address space, not the calling
    /// process's inherited one). Thin wrapper over the same recursive walk `fork` uses, just
    /// without copying user leaves at all -- see `copy_table_level`'s own doc comment for why a
    /// naive "clone everything, then zero out low addresses" approach (an earlier, broken version
    /// of this code) doesn't work: this kernel has no clean higher-half split. Kernel code, the
    /// heap, the phys-mem-offset window, and every user ELF's load address all coexist in the low
    /// canonical range at different indices -- the only thing that reliably distinguishes "safe to
    /// share" from "must be fresh" at *any* level is the `USER_ACCESSIBLE` flag itself, which the
    /// MMU's own hierarchical walk requires to be set at *every* level down to a user page (so a
    /// clear `USER_ACCESSIBLE` bit anywhere guarantees nothing user-facing exists beneath it, safe
    /// to alias as-is).
    ///
    /// # Errors
    ///
    /// `Err(())` on real frame exhaustion -- see `build_from_active`'s own doc comment.
    pub(crate) fn new_excluding_user(
        physical_memory_offset: VirtAddr,
        frame_allocator: &mut (impl FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>),
    ) -> Result<Self, ()> {
        Self::build_from_active(physical_memory_offset, frame_allocator, false)
    }

    /// Builds a **deep** copy of the currently active address space's user-space mappings into a
    /// fresh child -- the `fork()` half of `fork()`/`execve()`/`wait()` (`sys/process.rs`'s
    /// `do_fork_from_current`). Kernel-only subtrees are shared (aliased) with the parent, exactly
    /// like `new_excluding_user`; every subtree that leads to at least one user-accessible leaf
    /// page is instead freshly allocated and recursed into, and each user leaf itself is copied
    /// byte-for-byte (via the phys-mem-offset window, the same technique `elf::load` already uses
    /// to write segment bytes) into a freshly allocated frame. No copy-on-write -- a full eager
    /// copy, matching this codebase's existing correctness-over-cleverness bias (see e.g.
    /// `BootInfoFrameAllocator`'s own no-reuse policy).
    ///
    /// # Errors
    ///
    /// `Err(())` on real frame exhaustion -- see `build_from_active`'s own doc comment for why
    /// this no longer panics (matches `process::KernelStack::new`'s own real-`ENOMEM`-not-a-
    /// kernel-panic fix). Still panics on an unexpected huge page (`copy_table_level`'s own
    /// `assert!`) -- nothing here creates one, so encountering one means a future change violated
    /// that assumption, a real logic bug rather than a resource limit any caller could recover
    /// from.
    ///
    /// # Safety requirement, not enforced by the type system
    ///
    /// Must only be called on the **currently active** address space (`self`'s level 4 frame must
    /// be what `CR3` currently points at) -- real `fork()` always forks the calling process, which
    /// is necessarily active mid-syscall (`do_fork_from_current` runs synchronously on the
    /// caller's own kernel stack with its own CR3 still loaded), so this holds for every call site
    /// this codebase has -- but a hypothetical future caller trying to fork some other, non-running
    /// process would silently copy the *wrong* table.
    #[allow(clippy::result_unit_err)] // see AddressSpace::new's own identical allow.
    pub fn fork(
        &self,
        physical_memory_offset: VirtAddr,
        frame_allocator: &mut (impl FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>),
    ) -> Result<AddressSpace, ()> {
        Self::build_from_active(physical_memory_offset, frame_allocator, true)
    }

    /// Shared implementation behind `new_excluding_user`/`fork`: allocates a fresh level 4 table
    /// and recursively walks it against the currently active one via `copy_table_level`.
    ///
    /// **Real, not-a-kernel-panic `ENOMEM` on frame exhaustion** -- same motivation as
    /// `process::KernelStack::new`'s own fix (`sys/process/mod.rs`): a real `fork()`/`execve()`
    /// hitting resource exhaustion mid-copy must fail that one syscall, not take the whole kernel
    /// down. Requires `FrameDeallocator` now, not just `FrameAllocator` (tightened from this
    /// function's own prior bound): a `copy_table_level` failure partway through can leave `child`
    /// holding a real, partially-built subtree that must be freed before returning the error, or
    /// every one of its already-allocated frames leaks permanently. That cleanup reuses
    /// `free_table_level` directly rather than needing any new walk of its own -- safe to call on
    /// a partially-built table for the same reason `AddressSpace::teardown` (which also uses it)
    /// documents `child` is completely `zero()`'d immediately before `copy_table_level` ever
    /// starts, so every entry `copy_table_level` didn't get to yet is still `!PRESENT`, and
    /// `free_table_level` already skips every non-`PRESENT` entry outright -- it only ever touches
    /// exactly the (real, exclusively-owned) subset this call actually built.
    fn build_from_active(
        physical_memory_offset: VirtAddr,
        frame_allocator: &mut (impl FrameAllocator<Size4KiB> + FrameDeallocator<Size4KiB>),
        copy_user_leaves: bool,
    ) -> Result<AddressSpace, ()> {
        let new_frame = frame_allocator.allocate_frame().ok_or(())?;
        let (active_frame, _flags) = Cr3::read();

        // SAFETY: physical_memory_offset is the bootloader's phys-memory mapping (same
        // requirement as memory::init); active_frame is CR3's own live level 4 table; new_frame
        // was just allocated so nothing else can be viewing it yet.
        let (active_table, new_table) = unsafe {
            (
                frame_to_page_table(active_frame, physical_memory_offset),
                frame_to_page_table(new_frame, physical_memory_offset),
            )
        };
        new_table.zero();
        if copy_table_level(
            active_table,
            new_table,
            4,
            physical_memory_offset,
            frame_allocator,
            copy_user_leaves,
        )
        .is_err()
        {
            // See this function's own doc comment: new_table is fully zeroed except for whatever
            // copy_table_level actually managed to build before failing, so this frees exactly
            // that (and nothing it never touched) before also freeing new_frame itself.
            free_table_level(new_table, 4, physical_memory_offset, frame_allocator);
            // SAFETY: new_frame was never activated as CR3 (this AddressSpace never got past this
            // constructor), and free_table_level just above only ever frees content strictly
            // beneath it, never the frame itself -- exclusively ours to free here.
            unsafe { frame_allocator.deallocate_frame(new_frame) };
            return Err(());
        }

        Ok(AddressSpace {
            level_4_frame: Arc::new(new_frame),
        })
    }

    /// Returns a new `AddressSpace` handle sharing the exact same underlying level 4 table (an
    /// `Arc::clone` refcount bump, no new frame, no copying) — real `clone(2)`'s `CLONE_VM`
    /// semantics (`process::lifecycle::do_clone`), distinct from `fork`'s eager private copy
    /// above. A write through either handle's own mapping is genuinely visible through the other,
    /// since both ultimately point `CR3`/`mapper()` at the identical physical level 4 frame.
    pub(crate) fn share(&self) -> AddressSpace {
        AddressSpace {
            level_4_frame: Arc::clone(&self.level_4_frame),
        }
    }

    /// Builds a mapper over this address space's own level 4 table, independent of whichever
    /// address space `CR3` currently points at — lets a loader map pages into a not-yet-active
    /// address space.
    ///
    /// # Safety
    ///
    /// `physical_memory_offset` must be where the bootloader mapped all of physical memory (same
    /// requirement as `memory::init`), and there must be no other live `&mut` view of this
    /// address space's level 4 table.
    pub unsafe fn mapper(&self, physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
        let level_4_table =
            unsafe { frame_to_page_table(*self.level_4_frame, physical_memory_offset) };
        unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
    }

    /// Switches to this address space by writing `CR3`.
    ///
    /// # Safety
    ///
    /// Every mapping the currently-running code needs (its own instructions, stack, and anything
    /// an interrupt handler might touch) must already be present in this address space — true by
    /// construction for a freshly-`new`'d one, but code that later removes kernel entries from a
    /// process's address space must not activate it from a context that depends on what it removed.
    pub unsafe fn activate(&self) {
        unsafe { Cr3::write(*self.level_4_frame, Cr3Flags::empty()) };
    }

    /// Real reclaim: frees every frame this address space privately owns -- every
    /// `USER_ACCESSIBLE` leaf (the actual ELF image/stack/heap/private-anon-mmap content) and every
    /// `USER_ACCESSIBLE` intermediate page-table frame (PDPT/PD/PT) beneath this table, then this
    /// address space's own level 4 frame -- back to `frame_allocator`'s real free list (see
    /// `memory::BootInfoFrameAllocator`'s own `FrameDeallocator` impl). Closes the "no frame
    /// deallocation anywhere" gap for the common case (ordinary process exit/`execve`); still never
    /// frees anything genuinely *shared* across address spaces -- `free_table_level` recognizes and
    /// skips those specifically (`SHARED_LEAF`) rather than never encountering them -- see this
    /// method's own safety section.
    ///
    /// # Why this is always safe
    ///
    /// **Every frame this walk touches is exclusively owned by this one address space.** Two
    /// separate guarantees combine to make that true, both already established elsewhere in this
    /// codebase rather than invented here:
    /// - **Every page-table *structure* frame (levels 2-4) is always freshly allocated per address
    ///   space, never shared** -- `copy_table_level`'s own doc comment already establishes this: a
    ///   kernel-only (non-`USER_ACCESSIBLE`) entry is the *only* thing ever aliased across address
    ///   spaces, and this walk -- like that one -- never recurses into or touches one.
    /// - **Every `USER_ACCESSIBLE` leaf frame not marked `SHARED_LEAF` is genuinely private.** Fork
    ///   never shares a leaf either (a real eager copy, not COW -- same doc comment). The two real
    ///   exceptions that *can* alias a leaf across address spaces -- SysV `shmat`
    ///   (`fs::sysv_shm::do_shmat`) and fd-backed `MAP_SHARED` mmap
    ///   (`process::mm::do_mmap_file_backed`) -- both mark every leaf they map with `SHARED_LEAF`
    ///   (see that constant's own doc comment), which `free_table_level` below checks and skips.
    ///   Deliberately *not* relying on those regions already being unmapped by the time this method
    ///   runs -- `fs::sysv_shm::detach_all_for_exit`'s own doc comment explicitly documents that a
    ///   real process exit never unmaps shm PTEs at all (only `nattch`-decrements), so a page-table
    ///   walk here genuinely can still find them present; `SHARED_LEAF` is what makes that safe
    ///   regardless of either subsystem's own cleanup-call ordering or timing.
    ///
    /// # Safety
    ///
    /// This address space's level 4 frame must **not** be the one `CR3` currently names -- freeing
    /// a frame still backing the live page table (or still holding code/data the CPU is actively
    /// executing/reading through it) would hand out memory that's still in use. Both real call
    /// sites (`process::lifecycle::do_execve`'s old-address-space discard, always called *after*
    /// `new_address_space.activate()` already switched `CR3` away; and process reaping in
    /// `do_wait4`, which only ever reaps an already-`Zombie` process -- one that stopped running,
    /// and thus stopped being the active `CR3`, back when it originally called `do_exit`) satisfy
    /// this by construction, not by convention alone.
    ///
    /// **Real `clone(2)`/`CLONE_VM` threads (`share()` above) share this exact `Arc`.** If any
    /// other `Process`/`AddressSpace` handle still holds a clone of it, this whole free walk would
    /// be unsound -- it assumes exclusive ownership of every frame it touches (see "Why this is
    /// always safe" above), an assumption that only holds for the *last* surviving handle. So this
    /// checks `Arc::strong_count` first and, if anything else is still sharing it, does nothing at
    /// all beyond dropping `self`'s own reference -- the real free walk only ever runs once, when
    /// whichever thread tears down last gets here and finds itself alone.
    pub unsafe fn teardown(
        self,
        physical_memory_offset: VirtAddr,
        frame_allocator: &mut impl FrameDeallocator<Size4KiB>,
    ) {
        if Arc::strong_count(&self.level_4_frame) > 1 {
            // Still shared with at least one other thread in the same address space -- just drop
            // our own reference (implicit, `self` goes out of scope here) and leave the real walk
            // for whichever handle tears down last.
            return;
        }
        // SAFETY: level_4_frame is this address space's own table, guaranteed not to be the active
        // CR3 by this method's own safety contract -- no other code can be viewing it concurrently.
        // strong_count == 1, confirmed just above, so no sibling AddressSpace handle exists either.
        let table = unsafe { frame_to_page_table(*self.level_4_frame, physical_memory_offset) };
        free_table_level(table, 4, physical_memory_offset, frame_allocator);
        // SAFETY: this exact frame is what the walk above has now fully emptied of live content --
        // safe to return to the allocator's own free list, same as every leaf/table frame it just
        // freed.
        unsafe { frame_allocator.deallocate_frame(*self.level_4_frame) };
    }
}

/// Recursively walks and frees every `USER_ACCESSIBLE` frame beneath `table` at `level` (`4` =
/// PML4 down to `1` = the leaf level -- same level numbering `copy_table_level` above uses) --
/// the free-side mirror of that function's own copy walk. See `AddressSpace::teardown`'s own doc
/// comment for why every frame this function frees is guaranteed to be exclusively owned by this
/// one address space.
fn free_table_level(
    table: &mut PageTable,
    level: u8,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameDeallocator<Size4KiB>,
) {
    for i in 0..512usize {
        let entry = &table[i];
        if !entry.flags().contains(PageTableFlags::PRESENT)
            || !entry.flags().contains(PageTableFlags::USER_ACCESSIBLE)
        {
            // Absent, or kernel-only (and therefore shared, per this function's own doc comment) --
            // never ours to touch.
            continue;
        }
        if level == 1 {
            // A real leaf: skip it entirely if it's marked SHARED_LEAF (see that constant's own
            // doc comment) -- some other subsystem's own backing store still owns this exact
            // frame, possibly still mapped into another process's page table too. Every other
            // leaf here is exclusively this address space's own (see AddressSpace::teardown's own
            // doc comment), safe to free directly.
            if !entry.flags().contains(SHARED_LEAF) {
                let frame = entry.frame().expect("present leaf entry must have a frame");
                // SAFETY: private leaf, exclusively owned by this address space -- see
                // AddressSpace::teardown's own doc comment.
                unsafe { frame_allocator.deallocate_frame(frame) };
            }
            continue;
        }
        // A non-leaf USER_ACCESSIBLE entry: always this address space's own private table
        // structure (see AddressSpace::teardown's own doc comment -- SHARED_LEAF only ever marks
        // an actual leaf, never an intermediate table), so always safe to recurse into and free.
        let frame = entry
            .frame()
            .expect("present non-leaf entry must have a frame");
        // SAFETY: physical_memory_offset is the bootloader's phys-memory mapping; frame is a real,
        // live next-level table -- and, per AddressSpace::teardown's own safety contract, this
        // whole address space is no longer the active one, so no concurrent view of it exists.
        let child_table = unsafe { frame_to_page_table(frame, physical_memory_offset) };
        free_table_level(
            child_table,
            level - 1,
            physical_memory_offset,
            frame_allocator,
        );
        // SAFETY: this now-emptied table structure frame is exclusively this address space's own.
        unsafe { frame_allocator.deallocate_frame(frame) };
    }
}

/// Recursively walks `parent`'s `level` (`4` = PML4, `3` = PDPT, `2` = PD, `1` = PT -- the leaf
/// level, where entries point at actual 4 KiB data frames rather than further tables) alongside
/// `child` (already zeroed by the caller), populating `child` entry-by-entry:
///
/// - A present entry that is **not** `USER_ACCESSIBLE` is guaranteed, by the MMU's own
///   hierarchical walk requirements, to lead to nothing but kernel-only content -- safe to alias
///   directly (`child[i] = parent[i].clone()`) without recursing any further.
/// - A present, `USER_ACCESSIBLE` entry at the **leaf** level (`level == 1`) is an actual user
///   page. If `copy_user_leaves` is `false` (building an `execve` target's fresh address space),
///   it's simply skipped, leaving `child`'s slot unused. If `true` (forking), a fresh frame is
///   allocated and the parent's bytes are copied into it (via the phys-mem-offset window), and
///   `child[i]` is pointed at the copy with the same flags.
/// - A present, `USER_ACCESSIBLE` entry above the leaf level leads to *at least one* user page
///   somewhere beneath it (possibly alongside purely-kernel siblings under the same entry -- e.g.
///   this kernel's own PML4 index 0 hosts both its own code and every userland ELF's load
///   address, since it has no higher-half split). It can't be aliased *or* skipped outright:
///   `child` gets its own fresh, zeroed next-level table, and this function recurses into it.
///
/// # Errors
///
/// `Err(())` on real frame exhaustion -- deliberately leaves `child` exactly as it stood at the
/// point of failure (whatever was already fully built stays built, everything not yet reached
/// stays zeroed/absent) rather than unwinding any partial state itself. `build_from_active`'s own
/// single top-level `free_table_level` sweep over the *whole* table already correctly frees
/// exactly that partial subset and nothing else (see its own doc comment) -- so there's no need
/// for this function, or its own recursive calls, to do any cleanup of their own on this path.
fn copy_table_level(
    parent: &PageTable,
    child: &mut PageTable,
    level: u8,
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    copy_user_leaves: bool,
) -> Result<(), ()> {
    for i in 0..512usize {
        let entry = &parent[i];
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        if !entry.flags().contains(PageTableFlags::USER_ACCESSIBLE) {
            // Kernel-only beneath this entry, guaranteed by the MMU's hierarchy rules -- share it
            // as-is, whether it's itself a leaf or points to a further table.
            child[i] = entry.clone();
            continue;
        }

        assert!(
            !entry.flags().contains(PageTableFlags::HUGE_PAGE),
            "address space copy: unexpected huge page at level {level} -- nothing in this \
             codebase creates one"
        );

        if level == 1 {
            // A real user leaf page.
            if !copy_user_leaves {
                continue;
            }
            let src_frame = entry.frame().expect("present leaf entry must have a frame");
            if entry.flags().contains(SHARED_LEAF) {
                // A real SysV shmat/MAP_SHARED leaf: its backing frame is owned by a separate
                // store (`fs::sysv_shm::SEGMENTS`/`MMAP_FILE_CACHE`), not by this address space --
                // real fork() semantics inherit the *same* live sharing, not a private snapshot.
                // Alias the identical frame instead of copying: no new allocation, no memcpy, and
                // the child's own write is genuinely visible to every other attached process, same
                // as an unrelated process's own independent shmat/mmap already is. See
                // SHARED_LEAF's own doc comment -- this closes the "known minor gap" that comment
                // used to flag here. The matching attach-count bookkeeping half (so a later
                // shmdt/exit in either process decrements exactly once) lives in
                // `fs::sysv_shm::inherit_attachments_for_fork`, called from `do_fork_from_current`
                // once the child is actually in the process table.
                child[i].set_frame(src_frame, entry.flags());
                continue;
            }
            let new_frame = frame_allocator.allocate_frame().ok_or(())?;
            let src = (physical_memory_offset + src_frame.start_address().as_u64()).as_ptr::<u8>();
            let dst =
                (physical_memory_offset + new_frame.start_address().as_u64()).as_mut_ptr::<u8>();
            // SAFETY: src is a live, present physical frame (just read through the parent's own
            // page table); dst is a frame allocate_frame just handed out, unused by construction
            // -- both viewed through the same phys-mem-offset window elf::load already relies on
            // for the same kind of copy.
            unsafe { core::ptr::copy_nonoverlapping(src, dst, 4096) };
            child[i].set_frame(new_frame, entry.flags());
            continue;
        }

        // Mixed (or purely user) subtree above the leaf level: child needs its own private,
        // fresh table here, then recurse.
        let parent_next = entry
            .frame()
            .expect("present non-leaf entry must have a frame");
        let child_next_frame = frame_allocator.allocate_frame().ok_or(())?;
        // SAFETY: physical_memory_offset is the bootloader's phys-memory mapping; parent_next is a
        // real, live next-level table (entry is PRESENT and not a leaf at this level);
        // child_next_frame was just allocated, so nothing else can be viewing it yet.
        let (parent_next_table, child_next_table) = unsafe {
            (
                frame_to_page_table(parent_next, physical_memory_offset),
                frame_to_page_table(child_next_frame, physical_memory_offset),
            )
        };
        child_next_table.zero();
        child[i].set_frame(child_next_frame, entry.flags());
        copy_table_level(
            parent_next_table,
            child_next_table,
            level - 1,
            physical_memory_offset,
            frame_allocator,
            copy_user_leaves,
        )?;
    }
    Ok(())
}
