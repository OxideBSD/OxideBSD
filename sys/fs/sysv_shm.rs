//! Real SysV shared memory (`shmget`/`shmat`/`shmctl`/`shmdt` -- items 17-20 of
//! `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of implementation"
//! batch, `SYS_SHMGET = 542` through `SYS_SHMDT = 545`). No live caller anywhere in the current
//! roster (`ipcrm`/`ipcs` were already cut from the BusyBox roster before v0.1 specifically
//! because this didn't exist) -- the last sub-batch, closing the whole 28-syscall batch out.
//!
//! **The only sub-batch that needs real memory-management plumbing, not just a `BTreeMap`
//! namespace** -- unlike `crate::fs::sysv_msg`/`crate::fs::sysv_sem` (both pure in-kernel data
//! structures with an integer-`key_t` front door), a shared memory segment's whole point is real
//! content visible through more than one process's own page tables at once. `shmget` eagerly
//! allocates a fixed `Vec<PhysFrame>` for the segment up front (same "hand out forward, never
//! reclaim" policy `crate::process::mm`'s own `do_mmap`/`BootInfoFrameAllocator` already
//! establish); every `shmat` against that segment -- by any process, related or not -- maps
//! *those exact same frames* into the caller's own page table at a freshly bump-allocated VA
//! (`SHM_REGION_BASE = 0x_4000_0000_0000`, a fresh window distinct from `crate::process::mm`'s
//! own `MMAP_REGION_BASE`), so a write through one process's mapping is genuinely visible through
//! another's -- real shared memory, not a per-process private copy.
//!
//! **Real inheritance across `fork`.** This kernel's own `fork` is a full eager address-space copy,
//! not real copy-on-write (see CLAUDE.md's process section) -- but `AddressSpace::fork`'s own
//! `copy_table_level` now special-cases any leaf marked `memory::address_space::SHARED_LEAF`
//! (every leaf this module's own `do_shmat` maps carries it) and aliases the segment's *real* frame
//! into the child's table instead of copying its content into a fresh private one. That closes the
//! actual sharing gap; `inherit_attachments_for_fork` below (called from `process::lifecycle::
//! do_fork_from_current` right after the child's `Process` entry exists) closes the matching
//! bookkeeping half -- the child gets its own real `sysv_shm_attach` copy and each referenced
//! segment's `nattch` is bumped to match, exactly as if the child had called `shmat` itself. Matches
//! `Process::sysv_sem_undo`'s own *opposite* "starts fresh across fork" precedent deliberately: real
//! SysV semaphore adjustments are documented `fork`-local by POSIX itself, while a `shmat` mapping
//! genuinely is inherited.
//!
//! **A real `nattch`/`IPC_RMID` lifecycle**, same shape `crate::fs::sysv_sem`'s own `SemSet`
//! removal already established for its own `IPC_RMID`: marking a segment for removal detaches its
//! key immediately (a fresh `shmget` on that key can never find it again) but the segment itself,
//! and its real backing frames, survive until the last attached process detaches (`shmdt`, or a
//! real process exit via `detach_all_for_exit`, called from `process::lifecycle::terminate_process`
//! the same way `crate::fs::sysv_sem::apply_undo_for_exit` already is -- see that call site's own
//! comment for why it must run before `PROCESS_TABLE` is locked). Detaching never actually
//! reclaims the underlying frames even once `nattch` reaches zero and the segment is fully
//! removed -- consistent with this whole kernel having no frame-deallocation path anywhere.
//!
//! **`shmat`'s own page-table mapping never unmaps on exit** -- only the `nattch`/removal
//! bookkeeping runs. Harmless: a `Zombie` process's address space is never freed either (no
//! reclamation model exists), and once reaped there's nothing left to unmap from at all.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
};

use crate::fs::sysv_ipc::{IPC_64, IPC_RMID, IPC_SET, IPC_STAT, RawIpcPerm};
use crate::memory::{self, with_frame_allocator};
use crate::process::{self, Pid};
use crate::syscall::{EACCES, EAGAIN, EEXIST, EIDRM, EINVAL, ENOENT, ENOMEM};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
/// Real Linux's own `SHM_RDONLY` -- the only `shmat` flag bit this module honors (omits
/// `PageTableFlags::WRITABLE` on the caller's own mapping when set). `SHM_RND`/`SHM_REMAP`/
/// `SHM_EXEC` are accepted (masked off, not rejected) but make no behavioral difference: `shmaddr`
/// is always ignored (this kernel always picks the address itself, same simplification
/// `crate::process::mm::do_mmap` already applies to its own `addr_hint`), so `SHM_RND`'s rounding
/// has nothing to round; `SHM_REMAP` has no prior mapping at a caller-chosen address to replace;
/// `SHM_EXEC` has no meaning since this kernel maps every user page executable already (no
/// `NO_EXECUTE`/`EFER.NXE` anywhere yet, a known gap CLAUDE.md's own user-mode section documents).
const SHM_RDONLY: u64 = 0o10000;

/// A small, sane per-segment cap -- no privileged-override/`rlimit`-driven `SHMMAX` ceiling exists
/// here the way real Linux has one; no live caller to size this against, same "small, plausible
/// number" reasoning `crate::fs::sysv_sem::MAX_SEMS_PER_SET`/`crate::fs::sysv_msg::
/// MAX_SYSV_MSG_QUEUES` already use. 4 MiB matches `sys/modules/oxfs`'s own real per-file size ceiling
/// (12 direct blocks + one single-indirect block), a plausible real-world "big shared buffer" size
/// without risking exhausting `BootInfoFrameAllocator`'s own never-reclaimed frame pool across
/// several live segments at once.
const MAX_SHM_SEGMENT_SIZE: usize = 4 * 1024 * 1024;
const MAX_SYSV_SHM_SEGMENTS: usize = 32;

struct ShmSegment {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    /// Low 9 bits are the real rwx permission bits (`shmget`'s own `shmflg & 0777`); nothing above
    /// that is meaningful, same convention `crate::fs::sysv_sem::SemSet::mode`/`crate::fs::
    /// sysv_msg::MsgQueue::mode` already use.
    mode: u32,
    /// The real, caller-requested byte size (`shmget`'s own `size` argument) -- **not** rounded up
    /// to a page boundary, matching real `shmid_ds.shm_segsz`'s own documented meaning (the kernel
    /// rounds internally for the real backing allocation, `frames.len() * 4096`, but always
    /// reports the size the caller actually asked for back through `IPC_STAT`).
    size: u64,
    /// The segment's real, eagerly-allocated backing store -- shared by every `shmat` against this
    /// `shmid`, never reclaimed even once the segment itself is fully removed (this kernel has no
    /// frame-deallocation path anywhere).
    frames: Vec<PhysFrame<Size4KiB>>,
    cpid: Pid,
    lpid: Pid,
    atime: i64,
    dtime: i64,
    ctime: i64,
    nattch: u64,
    /// Set by `shmctl(IPC_RMID)` when `nattch > 0` at the time of the call -- the segment survives
    /// (real frames, real content) until the last attached process detaches, at which point it's
    /// actually removed from `SEGMENTS`. The segment's `key`, if any, is removed from `KEYS`
    /// immediately regardless -- real SysV semantics: a fresh `shmget` on that key can never find
    /// this segment again, even while old attachments are still winding down.
    marked_for_removal: bool,
}

fn check_access(s: &ShmSegment, uid: u32, gid: u32, want_write: bool) -> bool {
    crate::fs::sysv_ipc::check_access(s.uid, s.gid, s.mode, uid, gid, want_write)
}

fn is_owner_or_creator(s: &ShmSegment, uid: u32) -> bool {
    crate::fs::sysv_ipc::is_owner_or_creator(s.uid, s.cuid, uid)
}

static NEXT_SHMID: spin::Mutex<i32> = spin::Mutex::new(1);
static SEGMENTS: spin::Mutex<BTreeMap<i32, ShmSegment>> = spin::Mutex::new(BTreeMap::new());
/// Non-`IPC_PRIVATE` keys only, same convention `crate::fs::sysv_sem::KEYS`/`crate::fs::sysv_msg::
/// KEYS` already establish.
static KEYS: spin::Mutex<BTreeMap<i32, i32>> = spin::Mutex::new(BTreeMap::new());

/// Fixed VA window for `shmat` mappings -- a fresh region, not reused from `crate::process::mm::
/// MMAP_REGION_BASE` (that one hands out per-process-private anonymous pages; this one hands out
/// VA *values* that get mapped to the exact same physical frames across however many processes
/// attach the same segment). Same "single global bump counter is safe -- it only ever hands out
/// numeric VA values, mapped separately into whichever process's own table asked for one" reasoning
/// `MMAP_REGION_BASE`'s own doc comment already establishes.
const SHM_REGION_BASE: u64 = 0x_4000_0000_0000;
/// Stops where the main thread's stack reserve begins (`USER_STACK_RESERVE` below
/// `USER_STACK_TOP`), so the two regions are genuinely disjoint.
const SHM_REGION_CEILING: u64 =
    crate::process::USER_STACK_TOP - crate::process::USER_STACK_RESERVE;
static NEXT_SHM_PAGE: spin::Mutex<u64> = spin::Mutex::new(SHM_REGION_BASE);

/// musl's own `struct shmid_ds` on x86_64 (`external/mit/musl/arch/generic/bits/shm.h`) -- 112
/// bytes, verified via a direct `musl-gcc`/`sizeof`/`offsetof` probe against that exact field
/// list (against this port's own patched sysroot, `target/musl-sysroot`), same rigor `RawIpcPerm`/
/// `RawMsqidDs`/`RawSemidDs` already established.
#[repr(C)]
struct RawShmidDs {
    shm_perm: RawIpcPerm,
    shm_segsz: u64,
    shm_atime: i64,
    shm_dtime: i64,
    shm_ctime: i64,
    shm_cpid: i32,
    shm_lpid: i32,
    shm_nattch: u64,
    pad1: i64,
    pad2: i64,
}

const _: () = assert!(core::mem::size_of::<RawShmidDs>() == 112);

/// `SYS_SHMGET` (`542`, item 17) -- matches real `shmget(2)`'s exact `(key, size, shmflg)` wire
/// format, no musl call-site patch needed (confirmed directly against `external/mit/musl/src/ipc/
/// shmget.c`: no `SYS_ipc` multiplexer is ever defined on this arch, same "zero musl-side patches"
/// finding `crate::fs::sysv_sem`'s own doc comment already made for its sub-batch). `IPC_PRIVATE`
/// always creates a fresh, key-less segment; otherwise looks up `key` in `KEYS`, applying real
/// `IPC_CREAT`/`IPC_EXCL` semantics. Real semantics for an existing-key lookup: `size` may be `0`
/// or anything up to the existing segment's own real size; a `size` *larger* than the existing
/// segment is `EINVAL` (real `shmget(2)`'s own documented behavior -- distinct from `semget`'s
/// "must match exactly" rule, since a segment's size can never change after creation either way).
pub(crate) fn do_shmget(key: u64, size: u64, shmflg: u64) -> Result<u64, u64> {
    let key = key as i32;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let creat = shmflg & IPC_CREAT != 0;
    let excl = shmflg & IPC_EXCL != 0;

    if key != IPC_PRIVATE {
        let existing = KEYS.lock().get(&key).copied();
        if let Some(shmid) = existing {
            if creat && excl {
                return Err(EEXIST);
            }
            let segs = SEGMENTS.lock();
            let s = segs
                .get(&shmid)
                .expect("KEYS entry with no matching SEGMENTS entry");
            if size > s.size {
                return Err(EINVAL);
            }
            if !check_access(s, uid, gid, false) {
                return Err(EACCES);
            }
            return Ok(shmid as u64);
        }
        if !creat {
            return Err(ENOENT);
        }
    }

    if size == 0 || size as usize > MAX_SHM_SEGMENT_SIZE {
        return Err(EINVAL);
    }

    let mut segs = SEGMENTS.lock();
    if segs.len() >= MAX_SYSV_SHM_SEGMENTS {
        return Err(EAGAIN);
    }

    let page_count = (size as usize).div_ceil(4096);
    let phys_offset = memory::phys_mem_offset();
    let frames = with_frame_allocator(|fa| -> Result<Vec<PhysFrame<Size4KiB>>, u64> {
        let mut frames = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            let frame = fa.allocate_frame().ok_or(ENOMEM)?;
            // Real SysV shm guarantees zero-filled pages on first attach, matching anonymous
            // mmap's own guarantee (crate::process::mm::do_mmap's identical reasoning) -- zeroed
            // once, up front, since these frames are shared and only ever allocated here.
            let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
            unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
            frames.push(frame);
        }
        Ok(frames)
    })?;

    let shmid = {
        let mut next = NEXT_SHMID.lock();
        let v = *next;
        *next += 1;
        v
    };
    let now = crate::cpu::rtc::unix_epoch_now_precise().0;
    segs.insert(
        shmid,
        ShmSegment {
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode: (shmflg & 0o777) as u32,
            size,
            frames,
            cpid: process::scheduler::current_pid(),
            lpid: 0,
            atime: 0,
            dtime: 0,
            ctime: now,
            nattch: 0,
            marked_for_removal: false,
        },
    );
    drop(segs);
    if key != IPC_PRIVATE {
        KEYS.lock().insert(key, shmid);
    }
    Ok(shmid as u64)
}

/// `SYS_SHMAT` (`543`, item 18) -- matches real `shmat(2)`'s exact `(id, shmaddr, shmflg)` wire
/// format, no musl call-site patch needed. `shmaddr` is always ignored (this kernel always picks
/// the address itself, same simplification `crate::process::mm::do_mmap` already applies to its
/// own `addr_hint`) -- real callers pass `NULL` for exactly this "let the kernel choose" case
/// anyway. Returns the real mapped address on success (not `0`/`1`) -- the caller's own return
/// value *is* the pointer, matching real `void *shmat(...)`'s calling convention exactly (this
/// ABI's own carry-flag success path already puts the return value in `RAX`, so no special casing
/// is needed here). An invalid/unknown `id` is a real `EINVAL` (real `shmat(2)`'s own documented
/// errno for this case -- unlike `shmctl`'s own `EIDRM` for the same underlying situation, see that
/// function's own doc comment for why the two differ).
pub(crate) fn do_shmat(id: u64, _shmaddr: u64, shmflg: u64) -> Result<u64, u64> {
    let shmid = id as i32;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let caller = process::scheduler::current_pid();
    let want_write = shmflg & SHM_RDONLY == 0;

    let frames = {
        let mut segs = SEGMENTS.lock();
        let seg = segs.get_mut(&shmid).ok_or(EINVAL)?;
        if !check_access(seg, uid, gid, want_write) {
            return Err(EACCES);
        }
        seg.nattch += 1;
        seg.lpid = caller;
        seg.atime = crate::cpu::rtc::unix_epoch_now_precise().0;
        seg.frames.clone()
    };

    let region_len = frames.len() as u64 * 4096;
    let base = {
        let mut next = NEXT_SHM_PAGE.lock();
        let base = *next;
        let end = base.checked_add(region_len).ok_or(ENOMEM)?;
        if end > SHM_REGION_CEILING {
            return Err(ENOMEM);
        }
        *next = end;
        base
    };

    let phys_offset = memory::phys_mem_offset();
    let mut table = process::table().lock();
    let me = table
        .get_mut(&caller)
        .expect("shmat: current process missing from table");
    // SAFETY: me.address_space is the currently active address space -- shmat runs synchronously
    // on the caller's own kernel stack mid-syscall, with its own CR3 still live -- sound for the
    // same reason crate::process::mm::do_mmap's own identical comment already establishes.
    let mut mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };

    // SHARED_LEAF: this segment's own `frames` are owned by `SEGMENTS`, not by any one attaching
    // process's address space -- marks every leaf mapped from them so a real address-space teardown
    // (`memory::address_space::AddressSpace::teardown`) never frees one out from under a still-live
    // segment or a still-attached other process. See `SHARED_LEAF`'s own doc comment.
    let mut flags = PageTableFlags::PRESENT
        | PageTableFlags::USER_ACCESSIBLE
        | memory::address_space::SHARED_LEAF;
    if want_write {
        flags |= PageTableFlags::WRITABLE;
    }
    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base + region_len - 1));
    with_frame_allocator(|fa| -> Result<(), u64> {
        for (page, frame) in Page::range_inclusive(start_page, end_page).zip(frames.iter()) {
            // SAFETY: `frame` is one of the segment's own real backing frames (owned by `SEGMENTS`,
            // marked SHARED_LEAF above so real address-space teardown never frees it), and `page`
            // falls in this process's own, freshly bump-allocated shm region, never mapped before.
            unsafe {
                mapper
                    .map_to(page, *frame, flags, fa)
                    .map_err(|_| ENOMEM)?
                    .ignore();
            }
        }
        Ok(())
    })?;

    me.sysv_shm_attach.push((base, shmid));
    Ok(base)
}

/// `SYS_SHMDT` (`545`, item 20, last of the batch) -- matches real `shmdt(2)`'s exact `(shmaddr)`
/// wire format, no musl call-site patch needed. Real errno for "no shared memory segment is
/// attached at shmaddr": `EINVAL`.
pub(crate) fn do_shmdt(shmaddr: u64) -> Result<u64, u64> {
    let caller = process::scheduler::current_pid();
    let phys_offset = memory::phys_mem_offset();

    let mut table = process::table().lock();
    let me = table
        .get_mut(&caller)
        .expect("shmdt: current process missing from table");
    let idx = me
        .sysv_shm_attach
        .iter()
        .rposition(|&(addr, _)| addr == shmaddr)
        .ok_or(EINVAL)?;
    let (_, shmid) = me.sysv_shm_attach.remove(idx);

    // The segment can't have vanished while we still held one of its nattch counts -- IPC_RMID
    // only actually removes SEGMENTS once nattch reaches zero (see this module's own doc comment).
    let page_count = SEGMENTS
        .lock()
        .get(&shmid)
        .map(|s| s.frames.len() as u64)
        .expect("shmdt: segment vanished while still attached (nattch was still held)");

    // SAFETY: see do_shmat's identical reasoning -- me.address_space is the currently active
    // address space.
    let mut mapper = unsafe {
        me.address_space
            .as_ref()
            .expect("mm: caller has no address space")
            .mapper(phys_offset)
    };
    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(shmaddr));
    let end_page =
        Page::<Size4KiB>::containing_address(VirtAddr::new(shmaddr + page_count * 4096 - 1));
    for page in Page::range_inclusive(start_page, end_page) {
        if let Ok((_, flush)) = mapper.unmap(page) {
            flush.flush();
        }
    }
    drop(table);

    let mut segs = SEGMENTS.lock();
    let mut key_to_remove = None;
    if let Some(seg) = segs.get_mut(&shmid) {
        seg.nattch = seg.nattch.saturating_sub(1);
        seg.dtime = crate::cpu::rtc::unix_epoch_now_precise().0;
        if seg.marked_for_removal && seg.nattch == 0 {
            key_to_remove = Some(seg.key);
        }
    }
    if key_to_remove.is_some() {
        segs.remove(&shmid);
    }
    drop(segs);
    if let Some(key) = key_to_remove
        && key != IPC_PRIVATE
    {
        KEYS.lock().remove(&key);
    }
    Ok(0)
}

/// Called from `process::lifecycle::terminate_process` on every real process termination, the same
/// "before `PROCESS_TABLE` is locked there" placement `crate::fs::sysv_sem::apply_undo_for_exit`
/// already establishes (and for the identical reason: this function takes that same lock itself,
/// briefly, to drain the attachment list). Applies the real `nattch`-decrement/possible-removal
/// tail every `shmdt` call already performs -- **does not** unmap any page-table entries (unlike
/// `do_shmdt`): a terminating process's own address space is never freed anywhere in this kernel,
/// so there's nothing that needs unmapping before it becomes a `Zombie`, and once reaped there's no
/// address space left to unmap from at all.
pub(crate) fn detach_all_for_exit(pid: Pid) {
    let attach_list = {
        let mut table = process::table().lock();
        let Some(me) = table.get_mut(&pid) else {
            return;
        };
        core::mem::take(&mut me.sysv_shm_attach)
    };
    if attach_list.is_empty() {
        return;
    }
    let mut segs = SEGMENTS.lock();
    let mut keys_to_remove: Vec<i32> = Vec::new();
    for (_, shmid) in &attach_list {
        let mut remove_now = false;
        let mut key = IPC_PRIVATE;
        if let Some(seg) = segs.get_mut(shmid) {
            seg.nattch = seg.nattch.saturating_sub(1);
            seg.dtime = crate::cpu::rtc::unix_epoch_now_precise().0;
            if seg.marked_for_removal && seg.nattch == 0 {
                remove_now = true;
                key = seg.key;
            }
        }
        if remove_now {
            segs.remove(shmid);
            if key != IPC_PRIVATE {
                keys_to_remove.push(key);
            }
        }
    }
    drop(segs);
    if !keys_to_remove.is_empty() {
        let mut keys = KEYS.lock();
        for key in keys_to_remove {
            keys.remove(&key);
        }
    }
}

/// Called from `process::lifecycle::do_fork_from_current`, right after the child's own `Process`
/// entry is inserted into the table and its `AddressSpace::fork` has already aliased (not copied)
/// every `SHARED_LEAF` leaf — see that flag's own doc comment. Real POSIX fork() semantics: a child
/// that inherits an attached segment's own live mapping counts as a genuinely separate attachment,
/// exactly like an unrelated process's own independent `shmat` would — so `IPC_RMID` on a segment
/// still attached only in a forked descendant must not complete early, and each of the parent's and
/// child's own later `shmdt`/exit must decrement `nattch` exactly once, not zero times (if the
/// child's copy were silently ignored) or twice (if both ended up sharing one bookkeeping entry).
/// Fixed by giving the child a real, independent copy of the parent's own `sysv_shm_attach` list
/// (the `(addr, shmid)` pairs carry over unchanged — `AddressSpace::fork` preserves every VA
/// exactly, so the child's mapping sits at the identical address) and bumping each referenced
/// segment's own `nattch` to match, the same increment `do_shmat` itself performs for a real attach.
pub(crate) fn inherit_attachments_for_fork(parent_pid: Pid, child_pid: Pid) {
    let attach_list = {
        let table = process::table().lock();
        table
            .get(&parent_pid)
            .map(|p| p.sysv_shm_attach.clone())
            .unwrap_or_default()
    };
    if attach_list.is_empty() {
        return;
    }
    {
        let mut segs = SEGMENTS.lock();
        for &(_, shmid) in &attach_list {
            if let Some(seg) = segs.get_mut(&shmid) {
                seg.nattch += 1;
            }
        }
    }
    if let Some(child) = process::table().lock().get_mut(&child_pid) {
        child.sysv_shm_attach = attach_list;
    }
}

/// `SYS_SHMCTL` (`544`, item 19) -- matches real `shmctl(2)`'s exact `(id, cmd, buf)` wire format,
/// no musl call-site patch needed. `cmd` always arrives with real glibc/musl's `IPC_64` bit OR'd in
/// (`external/mit/musl/src/ipc/shmctl.c`'s own call site), masked off before matching, same
/// `IPC_CMD()` convention `crate::fs::sysv_sem::do_semctl`/`crate::fs::sysv_msg::do_msgctl` already
/// establish. Only `IPC_STAT`/`IPC_SET`/`IPC_RMID` are implemented -- `SHM_LOCK`/`SHM_UNLOCK`/
/// `SHM_STAT`/`SHM_STAT_ANY`/`SHM_INFO` are real `/proc`-introspection- or privilege-shaped
/// commands with no live caller, honest `EINVAL`, matching `semctl`/`msgctl`'s own tier for their
/// analogous unimplemented commands. **An id lookup miss is `EIDRM`, not `EINVAL`** -- deliberately
/// different from `do_shmat`'s own choice for the identical underlying situation: real `shmat(2)`'s
/// own man page documents only `EINVAL` for a bad id, while real `shmctl(2)`'s documents both
/// (`EINVAL` for a never-valid id, `EIDRM` for a since-removed one) -- this port doesn't distinguish
/// the two cases (a plain `BTreeMap` lookup miss either way), so `shmctl` follows `semctl`/
/// `msgctl`'s own established "`EIDRM` for any lookup miss" convention instead.
pub(crate) fn do_shmctl(id: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    let shmid = id as i32;
    let real_cmd = cmd & !IPC_64;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;

    match real_cmd {
        IPC_STAT => {
            let segs = SEGMENTS.lock();
            let s = segs.get(&shmid).ok_or(EIDRM)?;
            if !check_access(s, uid, gid, false) {
                return Err(EACCES);
            }
            let raw = RawShmidDs {
                shm_perm: RawIpcPerm {
                    key: s.key,
                    uid: s.uid,
                    gid: s.gid,
                    cuid: s.cuid,
                    cgid: s.cgid,
                    mode: s.mode,
                    seq: 0,
                    pad1: 0,
                    pad2: 0,
                },
                shm_segsz: s.size,
                shm_atime: s.atime,
                shm_dtime: s.dtime,
                shm_ctime: s.ctime,
                shm_cpid: s.cpid as i32,
                shm_lpid: s.lpid as i32,
                shm_nattch: s.nattch,
                pad1: 0,
                pad2: 0,
            };
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // codebase already has.
            unsafe { (arg as *mut RawShmidDs).write_unaligned(raw) };
            Ok(0)
        }
        IPC_SET => {
            let mut segs = SEGMENTS.lock();
            let s = segs.get_mut(&shmid).ok_or(EIDRM)?;
            if !is_owner_or_creator(s, uid) {
                return Err(EACCES);
            }
            // SAFETY: same known pointer-validation gap every other user-memory read in this
            // codebase already has.
            let raw = unsafe { (arg as *const RawShmidDs).read_unaligned() };
            s.uid = raw.shm_perm.uid;
            s.gid = raw.shm_perm.gid;
            s.mode = raw.shm_perm.mode & 0o777;
            s.ctime = crate::cpu::rtc::unix_epoch_now_precise().0;
            Ok(0)
        }
        IPC_RMID => {
            let mut segs = SEGMENTS.lock();
            let s = segs.get_mut(&shmid).ok_or(EIDRM)?;
            if !is_owner_or_creator(s, uid) {
                return Err(EACCES);
            }
            let key = s.key;
            if s.nattch == 0 {
                segs.remove(&shmid);
            } else {
                s.marked_for_removal = true;
            }
            drop(segs);
            if key != IPC_PRIVATE {
                KEYS.lock().remove(&key);
            }
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}
