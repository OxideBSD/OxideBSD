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
use crate::syscall::{EACCES, EAGAIN, EBADF, EBUSY, EINVAL, ENODEV, ENOMEM, ENOTSUP, ENXIO, EOVERFLOW};

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
/// Real Unix stack growth: maps one fresh zeroed page for a not-present fault inside the main
/// thread's stack reserve (`USER_STACK_RESERVE` below `USER_STACK_TOP`), so the faulting
/// instruction simply retries. Called first thing by `page_fault_handler`, for **both** rings:
/// the kernel writes into user stacks too (`read()` into an on-stack buffer, signal frames), and
/// a ring-0 fault there would otherwise reboot the machine.
///
/// Deliberately lock-light, since the fault can interrupt kernel code: the mapper comes straight
/// from the live `CR3` (no process-table lock -- the active table *is* the faulting process's),
/// and the frame allocator is only `try_lock`ed. `false` whenever growth doesn't apply or can't
/// happen right now; the caller then takes its normal fault path.
/// A copy-on-write fault (OxideBSD-doc `COW.md` §4): a write to a present `COW_LEAF` user page,
/// from ring 3 or from a copy routine in ring 0. `None` when the fault isn't one; `Some(true)`
/// when the page is now the writer's own and writable (copied, or just made writable when no
/// other address space maps the frame); `Some(false)` when there was no frame to copy into.
pub fn try_resolve_cow(fault_addr: u64) -> Option<bool> {
    use memory::address_space::COW_LEAF;
    if fault_addr >= crate::memory::usercopy::VM_MAXUSER || scheduler::current_pid() == 0 {
        return None;
    }
    let phys_offset = memory::phys_mem_offset();
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    // SAFETY: CR3's level-4 table, live and reachable through the physical-memory window; single
    // core, interrupts off in the fault handler.
    let l4 = unsafe { &mut *(phys_offset + l4_frame.start_address().as_u64()).as_mut_ptr::<x86_64::structures::paging::PageTable>() };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(fault_addr));
    let entry = memory::address_space::leaf_entry(l4, phys_offset, page.start_address())?;
    let flags = entry.flags();
    if !flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE) || !flags.contains(COW_LEAF) {
        return None;
    }
    let old = entry.frame().ok()?;
    let writable = (flags - COW_LEAF) | PageTableFlags::WRITABLE;
    if memory::refs::sole_owner(old) {
        // The other side copied or went away: the page is just this one's again.
        entry.set_flags(writable);
        x86_64::instructions::tlb::flush(page.start_address());
        count_fault(false);
        return Some(true);
    }
    // The frame allocator is never held while user code runs or a copy routine works (COW.md
    // §4.4), so the lock is free.
    let Some(Some(new)) = memory::try_with_frame_allocator(|fa| fa.allocate_frame()) else {
        return Some(false);
    };
    let src = (phys_offset + old.start_address().as_u64()).as_ptr::<u8>();
    let dst = (phys_offset + new.start_address().as_u64()).as_mut_ptr::<u8>();
    // SAFETY: the shared frame, and one just allocated, through the physical-memory window.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, 4096) };
    entry.set_addr(new.start_address(), writable);
    x86_64::instructions::tlb::flush(page.start_address());
    if memory::refs::release(old) {
        // The last other mapping went meanwhile (not possible on one core, but it would leak).
        memory::try_with_frame_allocator(|fa| unsafe { fa.deallocate_frame(old) });
    }
    count_fault(false);
    Some(true)
}

/// What a `FILE_LEAF` fault came to (`try_fill_file_page`).
pub enum FileFill {
    /// Mapped: the instruction retries.
    Done,
    /// No frame for it: the OOM killer's case.
    NoMemory,
    /// The page can't be had (stale, past the file, or the filesystem busy for a copy routine):
    /// the fault goes the usual way.
    Failed,
}

/// The first touch of a page cache mapping's page (OxideBSD-doc `DEMANDPAGE.md` §4): a
/// not-present fault on a `FILE_LEAF` entry, from ring 3 or a copy routine in ring 0, gets the
/// page from the cache (reading it from the disk if it must) and maps it read-only, shared and
/// cached, as a mapping made whole would have. `None` when the fault isn't one.
pub fn try_fill_file_page(fault_addr: u64, from_user: bool) -> Option<FileFill> {
    use memory::address_space::{CACHED_LEAF, SHARED_LEAF, file_entry, leaf_entry};
    if fault_addr >= crate::memory::usercopy::VM_MAXUSER || scheduler::current_pid() == 0 {
        return None;
    }
    let phys_offset = memory::phys_mem_offset();
    let page_va = VirtAddr::new(fault_addr & !0xfff);
    let l4 = || {
        let (l4_frame, _) = x86_64::registers::control::Cr3::read();
        // SAFETY: CR3's level-4 table, live and reachable through the physical-memory window.
        unsafe { &mut *(phys_offset + l4_frame.start_address().as_u64()).as_mut_ptr::<x86_64::structures::paging::PageTable>() }
    };
    let pending = leaf_entry(l4(), phys_offset, page_va)?;
    let (id, file_page, executable) = file_entry(pending)?;
    let raw = pending.addr().as_u64() | pending.flags().bits();
    let from = if from_user { memory::pagecache::Fill::UserFault } else { memory::pagecache::Fill::KernelFault };
    // Major if the page has to come from the disk.
    let major = !memory::pagecache::cached(id, file_page);
    let frame = match memory::pagecache::fill(id, file_page, from) {
        Ok(frame) => frame,
        Err(memory::pagecache::FillError::NoMemory) => return Some(FileFill::NoMemory),
        Err(memory::pagecache::FillError::Unavailable) => return Some(FileFill::Failed),
    };
    // The fill may have slept on the disk: another thread may have filled the page, or unmapped
    // it, meanwhile. Only the entry as it was is replaced.
    count_fault(major);
    let Some(entry) = leaf_entry(l4(), phys_offset, page_va) else { return Some(FileFill::Done) };
    if entry.addr().as_u64() | entry.flags().bits() == raw {
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | SHARED_LEAF | CACHED_LEAF;
        if !executable {
            flags |= crate::cpu::nx::no_execute();
        }
        entry.set_addr(frame.start_address(), flags);
        x86_64::instructions::tlb::flush(page_va);
    }
    Some(FileFill::Done)
}

/// The running process's soft `RLIMIT_STACK`, page-rounded and at most the reserve: how far below
/// `USER_STACK_TOP` its stack may grow. Kept here rather than read from the process table because
/// the stack fault may interrupt the kernel holding the table's lock; the scheduler sets it at each
/// switch (`set_stack_limit`), `setrlimit` when the running process changes its own.
static STACK_LIMIT: AtomicU64 = AtomicU64::new(super::limits::DFLSSIZ);

pub(crate) fn set_stack_limit(rlim_cur: u64) {
    STACK_LIMIT.store(rlim_cur.min(USER_STACK_RESERVE) & !0xfff, Ordering::Relaxed);
}

pub(crate) fn stack_limit() -> u64 {
    STACK_LIMIT.load(Ordering::Relaxed)
}

/// A not-present fault inside the stack reserve: maps the page. `None` when the fault isn't stack
/// growth; `Some(false)` when there was no frame for it (the OOM killer's case).
pub fn try_grow_user_stack(fault_addr: u64) -> Option<bool> {
    let reserve_bottom = USER_STACK_TOP - stack_limit();
    if !(reserve_bottom..USER_STACK_TOP).contains(&fault_addr)
        || scheduler::current_pid() == 0
    {
        return None;
    }
    let phys_offset = memory::phys_mem_offset();
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    let l4_ptr = (phys_offset + l4_frame.start_address().as_u64())
        .as_mut_ptr::<x86_64::structures::paging::PageTable>();
    // SAFETY: CR3's level-4 table is live and reachable through the physical-memory window, and
    // nothing else touches page tables while this fault handler runs (single core, IF clear).
    let mut mapper =
        unsafe { x86_64::structures::paging::OffsetPageTable::new(&mut *l4_ptr, phys_offset) };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(fault_addr));
    // Anything in the slot already (a mapped page, or a PROT_NONE one, which `translate` doesn't
    // see) makes this a real fault, not growth -- checked before a frame is taken for it.
    if memory::address_space::leaf_entry(mapper.level_4_table_mut(), phys_offset, page.start_address())
        .is_some_and(|e| !e.is_unused())
    {
        return None;
    }
    let parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    // Executable only if the stack exec mapped at exec is (`lifecycle::map_user_stack`, from the
    // program's `PT_GNU_STACK`): read from the stack's top page rather than the process table,
    // which this fault may have interrupted the kernel holding.
    let top = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_STACK_TOP - 1));
    let exec = matches!(
        mapper.translate(top.start_address()),
        TranslateResult::Mapped { flags, .. } if !flags.contains(PageTableFlags::NO_EXECUTE)
    );
    let leaf = parent | if exec { PageTableFlags::empty() } else { crate::cpu::nx::no_execute() };
    let mapped = memory::try_with_frame_allocator(|fa| {
        let Some(frame) = fa.allocate_frame() else {
            return Some(false);
        };
        let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
        // SAFETY: a freshly allocated, unused frame; stack pages must start zeroed.
        unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
        // SAFETY: `page` is unmapped (checked above) and inside this process's own stack reserve.
        unsafe { mapper.map_to_with_table_flags(page, frame, leaf, parent, fa) }
            .map(|flush| flush.flush())
            .ok()
            .map(|()| true)
    });
    // No frame: out of memory. A table frame `map_to` couldn't get, or the allocator lock held by
    // the interrupted code: a plain fault.
    let mapped = mapped.flatten();
    if mapped == Some(true) {
        count_fault(false);
    }
    mapped
}

/// The running thread's resolved page faults since it was switched in, minor and major
/// (`Process::minflt`): the fault handler may interrupt the kernel holding the process table, so
/// it counts here, and the scheduler moves the counts to the thread.
static FAULTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

pub(crate) fn count_fault(major: bool) {
    FAULTS[major as usize].fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn take_faults() -> (u64, u64) {
    (FAULTS[0].swap(0, Ordering::Relaxed), FAULTS[1].swap(0, Ordering::Relaxed))
}

/// The running address space's `VmState` and its level 4 table, set by `AddressSpace::activate`
/// (VMMAP.md §5.3): the anonymous-memory fault reads the map through it, since the fault may have
/// interrupted the kernel holding the process table's lock. The table is checked against `CR3`
/// before the pointer is used.
static CURRENT_VM: core::sync::atomic::AtomicPtr<spin::Mutex<VmState>> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static CURRENT_VM_L4: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_current_vm(vm: *const spin::Mutex<VmState>, l4_phys: u64) {
    CURRENT_VM.store(vm.cast_mut(), Ordering::Release);
    CURRENT_VM_L4.store(l4_phys, Ordering::Release);
}

/// A not-present fault on a page of private anonymous memory or the heap (`mmap(MAP_ANON)`,
/// `brk`) that the map allows the access to: maps a zeroed page (VMMAP.md §5.1). `None` when the
/// fault isn't one; `Some(false)` when there was no frame (the OOM killer's case). From ring 3,
/// a copy routine, or the kernel filling a range itself (`mlock`). Never waits: the map is taken
/// with `try_lock`, and a fault finding it locked is a kernel bug, reported and failed.
pub fn try_fill_anon(fault_addr: u64, write: bool, exec: bool) -> Option<bool> {
    use super::vm_map::{PROT_EXEC, PROT_READ, PROT_WRITE, VmKind};
    if scheduler::current_pid() == 0 {
        return None;
    }
    let phys_offset = memory::phys_mem_offset();
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    let vm = CURRENT_VM.load(Ordering::Acquire);
    if vm.is_null() || CURRENT_VM_L4.load(Ordering::Acquire) != l4_frame.start_address().as_u64() {
        return None;
    }
    let prot = {
        // SAFETY: the running address space's state, alive while its table is CR3's.
        let Some(state) = (unsafe { &*vm }).try_lock() else {
            crate::serial_println!("[vm] fault with the map locked at {:#x}", fault_addr);
            return None;
        };
        let (_, e) = state.map.lookup(fault_addr)?;
        if !matches!(e.kind, VmKind::Anon | VmKind::Heap) || e.shared {
            return None;
        }
        let need = if exec { PROT_EXEC } else if write { PROT_WRITE } else { PROT_READ };
        if e.prot & need == 0 {
            return None;
        }
        e.prot
    };
    let l4_ptr = (phys_offset + l4_frame.start_address().as_u64())
        .as_mut_ptr::<x86_64::structures::paging::PageTable>();
    // SAFETY: CR3's level-4 table is live and reachable through the physical-memory window, and
    // nothing else touches page tables while this runs (single core, IF clear).
    let mut mapper =
        unsafe { x86_64::structures::paging::OffsetPageTable::new(&mut *l4_ptr, phys_offset) };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(fault_addr));
    // A slot in use (a page, PROT_NONE, a file page) isn't this fault's to fill.
    if memory::address_space::leaf_entry(mapper.level_4_table_mut(), phys_offset, page.start_address())
        .is_some_and(|e| !e.is_unused())
    {
        return None;
    }
    let parent = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    let leaf = prot_leaf_flags(prot as u64);
    let mapped = memory::try_with_frame_allocator(|fa| {
        let Some(frame) = fa.allocate_frame() else {
            return Some(false);
        };
        let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
        // SAFETY: a freshly allocated, unused frame; anonymous memory starts zeroed.
        unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
        // SAFETY: `page` is unused (checked above) and inside this process's own mapping.
        unsafe { mapper.map_to_with_table_flags(page, frame, leaf, parent, fa) }
            .map(|flush| flush.flush())
            .ok()
            .map(|()| true)
    });
    let mapped = mapped.flatten();
    if mapped == Some(true) {
        count_fault(false);
    }
    mapped
}

/// Fills the anonymous pages of `[addr, end)` the map allows reading (`mlock`, `mlockall`):
/// `EAGAIN` with no memory for them.
fn fill_anon_range(addr: u64, end: u64) -> Result<(), u64> {
    for va in (addr & !0xfff..end).step_by(4096) {
        if try_fill_anon(va, false, false) == Some(false) {
            return Err(crate::syscall::EAGAIN);
        }
    }
    Ok(())
}

/// The window `mmap` and `shmat` take addresses from when the caller names none (`VmMap::
/// find_space`, from the address space's randomized `mmap_base`).
pub(crate) const MMAP_REGION_BASE: u64 = 0x_2000_0000_0000;
pub(crate) const MMAP_REGION_CEILING: u64 = 0x_3000_0000_0000;

/// Where an exec's mappings start: a random page in the first TiB of the window (ASLR).
pub(crate) fn pick_mmap_base() -> u64 {
    let pages = (1u64 << 40) / 4096;
    MMAP_REGION_BASE + (crate::random::kernel_random_u64() % pages) * 4096
}

/// A free range of `len` bytes for a mapping, near `hint` when it's in the window
/// (`find_space`); `ENOMEM` when nothing fits, or when `RLIMIT_AS` would be passed (`as_limit`).
pub(crate) fn alloc_va(vm: &VmState, len: u64, hint: u64, as_limit: u64) -> Result<u64, u64> {
    check_as(vm, len, as_limit)?;
    let hint = if (MMAP_REGION_BASE..MMAP_REGION_CEILING).contains(&hint) { hint & !0xfff } else { 0 };
    vm.map.find_space(len, hint, vm.mmap_base, MMAP_REGION_BASE, MMAP_REGION_CEILING).ok_or(ENOMEM)
}

/// `ENOMEM` if `more` bytes of mappings would take the address space past `RLIMIT_AS`.
pub(crate) fn check_as(vm: &VmState, more: u64, as_limit: u64) -> Result<(), u64> {
    if vm.map.size().saturating_add(more) > as_limit { Err(ENOMEM) } else { Ok(()) }
}

/// Records a program's (or its interpreter's) `PT_LOAD` segments, loaded at `bias`, in a fresh
/// map.
pub(crate) fn record_segments(vm: &mut VmState, elf: &super::elf::Elf, bias: u64) {
    use super::vm_map::{PROT_ALL, VmEntry, VmKind};
    for (start, end, prot) in elf.load_ranges(bias) {
        let kind = VmKind::Text { content: elf.content(), page: (start - bias) / 4096 };
        let _ = vm.map.insert(start, VmEntry::new(end, prot, PROT_ALL, false, kind));
    }
}

/// Records the rest of a new image's address space: the stack's whole reserve (no mapping may
/// take it), the fault trampoline's pages, and a fresh mmap base.
pub(crate) fn record_exec_tail(vm: &mut VmState, exec_stack: bool) {
    use super::vm_map::{PROT_ALL, PROT_EXEC, PROT_READ, PROT_WRITE, VmEntry, VmKind};
    let stack_prot = PROT_READ | PROT_WRITE | if exec_stack { PROT_EXEC } else { 0 };
    let _ = vm.map.insert(
        USER_STACK_TOP - USER_STACK_RESERVE,
        VmEntry::new(USER_STACK_TOP, stack_prot, PROT_ALL, false, VmKind::Stack),
    );
    let tramp = super::fault_trampoline::FAULT_SCRATCH_VA;
    let rx = PROT_READ | PROT_EXEC;
    let _ = vm.map.insert(tramp, VmEntry::new(tramp + 0x2000, rx, rx, false, VmKind::Kernel));
    vm.mmap_base = pick_mmap_base();
    vm.map.set_base(vm.mmap_base);
}

/// Reserves the range a new mapping of `len` bytes goes in, entering it in the caller's map
/// first, so nothing else can take it while the pages are made: at `fixed` (`MAP_FIXED`, whose
/// old pages `do_munmap` already took out), else a free range near `hint` (`alloc_va`).
/// `ENOMEM` past `RLIMIT_AS` or with no room. A caller that then fails unmaps the range (`do_munmap`).
pub(crate) fn reserve(
    caller_pid: Pid,
    fixed: Option<u64>,
    hint: u64,
    len: u64,
    entry: impl FnOnce(u64) -> super::vm_map::VmEntry,
) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let me = table.get(&caller_pid).expect("mmap: current process missing from table");
    let as_limit = me.rlimits[super::limits::RLIMIT_AS].0;
    let mut vm = me.vm();
    let base = match fixed {
        Some(base) => {
            check_as(&vm, len, as_limit)?;
            base
        }
        None => alloc_va(&vm, len, hint, as_limit)?,
    };
    vm.map.insert(base, entry(base + len)).map_err(|_| ENOMEM)?;
    Ok(base)
}


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
/// `PROT_EXEC`: the page is mapped without `NO_EXECUTE` (THREAT_MODEL.md §3.3); every other user
/// page is not executable. Implies read access, as on all x86 hardware.
const PROT_EXEC: u64 = 0x4;

/// `prot` as the map keeps it (`vm_map::PROT_*`, the same bits).
fn map_prot(prot: u64) -> u8 {
    (prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) as u8
}

/// Whether `prot` grants any access at all (anything but `PROT_NONE`).
fn prot_accessible(prot: u64) -> bool {
    prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0
}

/// The leaf flags for an accessible user page with protection `prot`: writable only with
/// `PROT_WRITE`, executable only with `PROT_EXEC`.
pub(crate) fn prot_leaf_flags(prot: u64) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if prot & PROT_WRITE != 0 {
        flags |= PageTableFlags::WRITABLE;
    }
    if prot & PROT_EXEC == 0 {
        flags |= crate::cpu::nx::no_execute();
    }
    flags
}

/// `kern.wxabort`: a W^X violation (`check_wx`) also sends the process `SIGABRT`, for finding
/// the caller in a debugger or core dump. Off by default, as on OpenBSD.
pub(crate) static WXABORT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// W^X (THREAT_MODEL.md §3.3, OpenBSD's policy): no mapping may be writable and executable at
/// once. `mmap`/`mprotect` asking for both fail with `ENOTSUP` and are logged, unless the process
/// is a marked `wxneeded` program run from a `wxallowed` mount (`VmState::wx_allowed`).
fn check_wx(caller_pid: Pid, prot: u64, call: &str) -> Result<(), u64> {
    if prot & (PROT_WRITE | PROT_EXEC) != PROT_WRITE | PROT_EXEC {
        return Ok(());
    }
    let table = PROCESS_TABLE.lock();
    let Some(me) = table.get(&caller_pid) else {
        return Err(ENOTSUP);
    };
    if me.vm().wx_allowed {
        return Ok(());
    }
    crate::serial_println!(
        "[wx] pid {} ({}): {} W^X violation",
        caller_pid,
        core::str::from_utf8(&me.comm).unwrap_or("?"),
        call
    );
    drop(table);
    if WXABORT.load(core::sync::atomic::Ordering::Relaxed) {
        let _ = crate::process::signals::do_kill(caller_pid, caller_pid as i64, SIGABRT as i64);
    }
    Err(ENOTSUP)
}

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
/// `MAP_FIXED` that fails (`EEXIST`) instead of replacing what's mapped (VMMAP.md §4.3; FreeBSD's
/// `MAP_EXCL`, whose number musl gives `MAP_NORESERVE`).
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

/// `RLIMIT_MEMLOCK` (musl's number): bounds what `mlockall(MCL_FUTURE)` locks of later mappings
/// (`do_mmap`'s `auto_lock`).
const RLIMIT_MEMLOCK: u64 = 8;

/// Real, cross-open shared physical-frame cache for fd-backed `MAP_SHARED` mappings — keyed by
/// `crate::fs::fd::content_id_of`'s identity of the file (the vnode holding it), not by
/// `real_fd`/pid. **This is what
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
        // Torn down with locks held (exit, munmap under the process table): deferred.
        crate::kern::vfs_subr::vrele_deferred(content_id as *mut vfs_if::Vnode);
    }
}

/// Takes one reference to `content_id`'s cache entry for a new shared region: the first keeps the
/// file (its vnode) in use until the last region of it goes, so writeback can still reach it.
fn add_mmap_file_ref(content_id: u64) {
    let mut refs = MMAP_FILE_REFCOUNT.lock();
    let count = refs.entry(content_id).or_insert(0);
    *count += 1;
    if *count == 1 {
        crate::kern::vfs_subr::vref(content_id as *mut vfs_if::Vnode);
    }
}

/// The memory bookkeeping of one address space, FreeBSD's `vmspace`: it lives in the
/// `AddressSpace` (`AddressSpace::vm`), so everything sharing the page tables shares it -- the
/// threads of a group, and a vfork child borrowing its parent's (COW.md §7). Kept with the table
/// rather than with a process because a mapping's bookkeeping has to match the mapping: a vfork
/// child with its own copy could detach a SysV segment at exec, freeing frames the parent still
/// maps. `execve` and `spawn` start an empty one with their new table; `fork` copies what a child
/// inherits (`inherit_vm_for_fork`). The last live process using it cleans it up at exit or exec
/// (`lifecycle::last_live_user`).
pub struct VmState {
    /// The map of the user mappings (OxideBSD-doc `VMMAP.md`): what is mapped where, with what
    /// protection; `mmap`, `munmap`, `mprotect`, `brk` and `shmat` keep it, exec starts it.
    pub map: super::vm_map::VmMap,
    /// Where `mmap` starts looking for free addresses (`alloc_va`), random per exec.
    pub mmap_base: u64,
    /// The program break (`do_brk`).
    pub brk: VirtAddr,
    /// Where `execve` put the break: `RLIMIT_DATA` bounds how far past it the break may move.
    pub brk_base: VirtAddr,
    /// The fd-backed mappings, for writeback and the page cache's reference counts.
    pub mmap_file_regions: Vec<MmapFileRegion>,
    /// Still-live `/dev/fb0` (or any future MMIO-backed) mappings -- see `MmapPhysRegion`'s own
    /// doc comment. Not inherited by `fork`.
    pub mmap_phys_regions: Vec<MmapPhysRegion>,
    /// `mlockall(MCL_FUTURE)`: every later `mmap()` is locked too, subject to `RLIMIT_MEMLOCK`
    /// (`do_mmap`'s `auto_lock`). Neither inherited by `fork` nor kept across `execve` (POSIX).
    pub mlockall_future: bool,
    /// Bytes locked through `mlockall_future`, what `RLIMIT_MEMLOCK` is checked against. An
    /// explicit `mlock`/`munlock` doesn't count (`do_mlock`: no per-page locked state exists).
    pub locked_bytes: u64,
    /// Whether this program may map pages writable and executable at once (`check_wx`): a
    /// `wxneeded` program run from a `wxallowed` mount. Set by `execve`, kept across `fork`.
    pub wx_allowed: bool,
    /// One `(addr, shmid)` per SysV `shmat`, in call order (`crate::fs::sysv_shm`): `shmdt` finds
    /// its entry here, and cleanup at exit or exec drops every segment's `nattch` once. A forked
    /// child gets its own copy, each segment's `nattch` raised to match.
    pub shm_attach: Vec<(u64, i32)>,
    /// The programs this address space runs (the executable and its interpreter): vnodes it holds
    /// in use and counts in their `v_textcount`, so they can't be opened for writing (`ETXTBSY`)
    /// and stay while running, even unlinked (FreeBSD's `p_textvp`). Kept by `fork`.
    pub text: Vec<u64>,
}

impl VmState {
    /// Runs `vp` (the vnode holding a program's contents): counts it as text and holds it.
    pub fn add_text(&mut self, vp: u64) {
        let v = vp as *mut vfs_if::Vnode;
        crate::kern::vfs_subr::vref(v);
        // SAFETY: just referenced.
        unsafe { (*v).v_textcount += 1 };
        self.text.push(vp);
    }
}

impl Drop for VmState {
    /// The address space is gone: its programs aren't running here any more (deferred: this runs
    /// where a file system can't be entered).
    fn drop(&mut self) {
        for &vp in &self.text {
            let v = vp as *mut vfs_if::Vnode;
            // SAFETY: held since `add_text`.
            unsafe { (*v).v_textcount -= 1 };
            crate::kern::vfs_subr::vrele_deferred(v);
        }
    }
}

impl Default for VmState {
    fn default() -> Self {
        Self {
            map: super::vm_map::VmMap::new(),
            mmap_base: MMAP_REGION_BASE,
            brk: VirtAddr::zero(),
            brk_base: VirtAddr::zero(),
            mmap_file_regions: Vec::new(),
            mmap_phys_regions: Vec::new(),
            mlockall_future: false,
            locked_bytes: 0,
            wx_allowed: false,
            shm_attach: Vec::new(),
            text: Vec::new(),
        }
    }
}

/// Fills a forked child's `VmState` from its parent's, once `AddressSpace::fork` has built the
/// child's table: the break and W^X permission carry over; so does every `MAP_SHARED` file
/// region (the child's table aliases the same frames, so its writes must be written back too,
/// and each region holds a reference on the file's mapping) and every SysV shm attachment
/// (`sysv_shm::inherit_attachments_for_fork`). Private regions are left out: fork gave the child
/// its own copy-on-write pages, with nothing left to write back. Memory locks are not inherited.
pub(crate) fn inherit_vm_for_fork(parent: &AddressSpace, child: &AddressSpace) {
    let (brk, brk_base, wx_allowed, regions, text, map, mmap_base) = {
        let vm = parent.vm();
        let regions: Vec<MmapFileRegion> =
            vm.mmap_file_regions.iter().filter(|r| r.shared).copied().collect();
        (vm.brk, vm.brk_base, vm.wx_allowed, regions, vm.text.clone(), vm.map.clone(), vm.mmap_base)
    };
    for r in &regions {
        add_mmap_file_ref(r.content_id);
    }
    {
        let mut vm = child.vm();
        vm.brk = brk;
        vm.brk_base = brk_base;
        vm.wx_allowed = wx_allowed;
        vm.mmap_file_regions = regions;
        vm.map = map;
        vm.mmap_base = mmap_base;
        for vp in text {
            vm.add_text(vp);
        }
    }
    crate::fs::sysv_shm::inherit_attachments_for_fork(parent, child);
}

/// One real fd-backed `MAP_SHARED` mapping still live in a process's own address space — enough
/// state for `do_munmap` (or exit/`execve` cleanup) to write real content back to the underlying
/// file (via `crate::fs::fd::content_write`, keyed by `content_id` alone — no fd/`real_fd`
/// involved at all, see that function's own doc comment for why). A `shared` (`MAP_SHARED`) entry
/// *is* now inherited across `fork` -- see `inherit_vm_for_fork`'s own doc comment for why:
/// `AddressSpace::fork`'s `SHARED_LEAF` handling already makes the child's page table alias the
/// exact same real frames the parent's does, so leaving the child's own list empty (the original
/// behavior, matching the SysV shm attachment list's now-fixed precedent) meant nothing the
/// child did with its share -- write through it, `munmap` it, exit -- ever wrote those bytes back
/// to the file, a real, silent data-loss bug. A `MAP_PRIVATE` entry stays uninherited: `do_mmap_
/// file_backed` never marks a private mapping's frames `SHARED_LEAF`, so `AddressSpace::fork`
/// already gives the child a genuinely private, eagerly-copied frame there -- correct fork
/// semantics on its own, nothing for this list to additionally track.
#[derive(Clone, Copy)]
pub struct MmapFileRegion {
    va_start: u64,
    npages: u64,
    /// The object page mapped at `va_start` (the `mmap` offset in pages).
    file_page: u64,
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
/// `sys/syscall.rs`'s module doc comment). `flags` is real now too, decoded by the caller
/// (`sys/syscall/ffi.rs`'s `oxidebsd_sys_mmap`) from the same packed register `prot` rides in — see
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
    let noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    let fixed = flags & MAP_FIXED != 0 || noreplace;
    if !anon && fd < 0 {
        return Err(EBADF);
    }
    let effective_fd = if anon { -1 } else { fd };
    check_wx(caller_pid, prot, "mmap")?;

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
        if addr_hint < crate::memory::usercopy::VM_MINUSER
            || end_inclusive >= crate::memory::usercopy::VM_MAXUSER
        {
            return Err(ENOMEM);
        }
        if noreplace {
            let table = PROCESS_TABLE.lock();
            let me = table.get(&caller_pid).expect("mmap: current process missing from table");
            if me.vm().map.overlaps(addr_hint, addr_hint + region_len) {
                return Err(crate::syscall::EEXIST);
            }
        } else {
            let _ = do_munmap(caller_pid, addr_hint, region_len);
        }
        Some(addr_hint)
    } else {
        None
    };

    // Real `mlockall(MCL_FUTURE)` + `RLIMIT_MEMLOCK` enforcement (`mmap/18-1.c`): decided up front,
    // before actually establishing the mapping -- a process that called `mlockall(MCL_FUTURE)`
    // implicitly locks every future mapping, and if that would push its own total locked bytes
    // past `RLIMIT_MEMLOCK`, real POSIX has the whole `mmap()` fail `EAGAIN` rather than partially
    // mapping. `mlockall_future`/`locked_bytes` live in the address space's `VmState`: memory
    // locks are a property of the address space, shared by everything running in it.
    let auto_lock = {
        let table = PROCESS_TABLE.lock();
        let me = table
            .get(&caller_pid)
            .expect("mmap: current process missing from table");
        let shared = me.vm();
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
        do_mmap_fb(caller_pid, geom, page_count, fixed_base, addr_hint)
    } else if effective_fd >= 0 {
        do_mmap_file_backed(
            caller_pid,
            effective_fd as u64,
            off,
            page_count,
            prot,
            private,
            fixed_base,
            addr_hint,
        )
    } else {
        do_mmap_anon(caller_pid, fixed_base, region_len, prot, addr_hint, shared || auto_lock)
    };

    if auto_lock && result.is_ok() {
        let table = PROCESS_TABLE.lock();
        if let Some(me) = table.get(&caller_pid) {
            me.vm().locked_bytes += region_len;
        }
    }

    result
}

/// The anonymous-mapping half of `do_mmap` (`fd < 0`, i.e. `MAP_ANON`), split out so `do_mmap`
/// applies the `mlockall(MCL_FUTURE)` accounting to it and to `do_mmap_file_backed` alike.
/// `fixed_base`, when set, is a `MAP_FIXED` address (validated, and cleared by `do_mmap`'s
/// `do_munmap`); otherwise the map finds one. Private memory is only recorded: a page is made
/// at its first touch, with the map's protection then (`try_fill_anon`, VMMAP.md §5), so a
/// `PROT_NONE` mapping and a guard region stay empty. `eager` makes the pages now: a shared
/// mapping, or one `mlockall(MCL_FUTURE)` locks.
fn do_mmap_anon(
    caller_pid: Pid,
    fixed_base: Option<u64>,
    region_len: u64,
    prot: u64,
    hint: u64,
    eager: bool,
) -> Result<u64, u64> {
    use super::vm_map::{PROT_ALL, VmEntry, VmKind};
    let base = reserve(caller_pid, fixed_base, hint, region_len, |end| {
        VmEntry::new(end, map_prot(prot), PROT_ALL, false, VmKind::Anon)
    })?;
    // Private memory is made at its first touch (`try_fill_anon`); a shared mapping, or one
    // `mlockall(MCL_FUTURE)` locks, now.
    if !eager {
        return Ok(base);
    }
    let mapped = map_anon_pages(caller_pid, base, region_len, prot);
    if mapped.is_err() {
        // Frees what did get mapped, and the reservation.
        let _ = do_munmap(caller_pid, base, region_len);
    }
    mapped.map(|()| base)
}

/// Makes the pages of a new anonymous mapping (allocated now, zeroed).
fn map_anon_pages(caller_pid: Pid, base: u64, region_len: u64, prot: u64) -> Result<(), u64> {
    if !prot_accessible(prot) {
        // Real PROT_NONE: reserve the VA (already done above) but map nothing -- see this
        // function's own doc comment.
        return Ok(());
    }

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

    let leaf_flags = prot_leaf_flags(prot);
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

    Ok(())
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
    hint: u64,
) -> Result<u64, u64> {
    let max_pages = (geom.len.max(1)).div_ceil(4096);
    let page_count = requested_pages.min(max_pages);
    let region_len = page_count * 4096;

    use super::vm_map::{PROT_READ as R, PROT_WRITE as W, VmEntry, VmKind};
    let base = reserve(caller_pid, fixed_base, hint, region_len, |end| VmEntry::new(end, R | W, R | W, true, VmKind::Phys))?;

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

    // Never executable, whatever `prot` asked for: it's a framebuffer.
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | memory::address_space::SHARED_LEAF
        | memory::address_space::MAY_WRITE_LEAF
        | crate::cpu::nx::no_execute();
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
    me.vm().mmap_phys_regions.push(MmapPhysRegion {
        va_start: base,
        npages: page_count,
    });
    drop(table);
    crate::console::framebuffer::set_owned_by_userspace(true);
    // See `tty::console::RAW_KEYBOARD_OWNED`'s own doc comment -- a real `/dev/fb0` mapper is
    // exactly the shape of program that also wants exclusive raw keyboard ownership.
    crate::tty::console::set_raw_keyboard_owned(true);
    Ok(base)
}

/// Real fd-backed mapping — `do_mmap`'s `fd >= 0` case, now honoring the caller's real
/// `MAP_SHARED`/`MAP_PRIVATE` choice (`private`) instead of always behaving as `MAP_SHARED`. `off`
/// (page-aligned) picks the object's first mapped page: musl's `ld.so` maps each `PT_LOAD` segment
/// of a shared library from its own file offset. A regular file may be mapped past its end at any
/// offset (the pages past it `SIGBUS`, below); a shared memory object may not, at a nonzero offset
/// (`ENXIO`, see the `off != 0` handling below), as on FreeBSD.
///
/// **Content population/writeback goes through `crate::fs::fd::content_read`/`content_write`
/// (keyed by `content_id`, a real inode number), not any fd's own read/write callbacks** — found
/// live, not designed in from the start: `sys/modules/oxfs`'s `oxfs_read` unconditionally fails
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
    hint: u64,
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
        .vm()
        .mmap_file_regions
        .len()
        >= MAX_MMAP_FILE_REGIONS
    {
        return Err(ENOMEM);
    }

    let phys_offset = memory::phys_mem_offset();
    let real_size = crate::fs::fd::content_size(content_id).max(0) as u64;

    let off = off as u64;
    if !off.is_multiple_of(4096) {
        return Err(EINVAL);
    }
    // Real POSIX `[ENXIO]`: "Addresses in the range [off,off+len) are invalid for the object
    // specified by fildes" (`mmap/28-1.c` in the conformance pilot, on a shared memory object).
    // Only for a shared memory object, and only at a nonzero offset: `off == 0` past the object's
    // end is real POSIX MPR territory instead (a deferred `SIGBUS` on the actual out-of-bounds
    // *reference*, see `covered_pages` below and `mmap/11-2.c`/`11-3.c`), and a regular file may be
    // mapped past its end at any offset -- `ld.so` does exactly that for a library's last segment,
    // whose `.bss` runs past the file.
    if off != 0
        && crate::fs::fd::content_is_shm(content_id)
        && (off >= real_size || off.saturating_add(region_len) > real_size)
    {
        return Err(ENXIO);
    }
    // The first object page this mapping shows.
    let file_page = off / 4096;
    // Real POSIX MPR (`mmap/11-2.c`/`11-3.c` in the conformance pilot): only pages actually
    // overlapping the object's own real content -- including its final, real-content-plus-
    // zero-padding partial page -- ever get backed by a real frame. Anything past that, up to the
    // caller's own requested `page_count`, is deliberately left unmapped so a reference there
    // real-faults instead of silently succeeding against a zero-filled page; `signal_for_user_fault`
    // below is what turns that fault into a real `SIGBUS` rather than a reboot. Applies to both
    // MAP_SHARED and MAP_PRIVATE alike -- real POSIX MPR doesn't distinguish the two.
    let covered_pages = real_size.div_ceil(4096).saturating_sub(file_page).min(page_count);

    // A private mapping that can't be written shows the page cache's frames, shared with every
    // other such mapping and every exec of the file (PAGECACHE.md §3.2). A page the cache can't
    // supply is copied, as for any private mapping.
    let cache_entry = if private && prot & PROT_WRITE == 0 && !crate::fs::fd::content_is_shm(content_id) {
        memory::pagecache::entry_for(content_id)
    } else {
        None
    };
    let mut cached_pages: Vec<bool> = Vec::new();

    // Used by this address space before any page is filled, as exec's are (`exec_cache_entry`):
    // filling allocates, an allocation may reclaim from the cache, and an entry nothing uses yet
    // is fair game -- found at 24 MB, reclaim freed the very entry being filled, frames this
    // mapping then mapped while the allocator handed them out again. A failed mmap leaves the use
    // until the address space goes, which only keeps the entry from being reclaimed early.
    if let Some(id) = cache_entry {
        let table = PROCESS_TABLE.lock();
        if let Some(space) = table.get(&caller_pid).and_then(|me| me.address_space.as_ref()) {
            space.use_cached(id);
        }
    }
    // Filled on first touch (DEMANDPAGE.md): the pages get `FILE_LEAF` entries below, not frames.
    let demand = cache_entry.filter(|&id| {
        memory::pagecache::demand(id) && file_page + covered_pages <= 0xf_ffff
    });
    let frames: Vec<PhysFrame<Size4KiB>> = if demand.is_some() {
        Vec::new()
    } else if let Some(id) = cache_entry {
        // The frame allocator only around each allocation: the reads can sleep on the disk
        // (COW.md §4.4).
        let mut frames = Vec::with_capacity(covered_pages as usize);
        for i in 0..covered_pages {
            let page = file_page + i;
            let (frame, cached) = match memory::pagecache::frame(id, page, memory::pagecache::Fill::Syscall) {
                Some(frame) => (frame, true),
                None => {
                    let frame = with_frame_allocator(|fa| fa.allocate_frame()).ok_or(ENOMEM)?;
                    let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
                    unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
                    let len = real_size.saturating_sub(page * 4096).min(4096);
                    crate::fs::fd::content_read(content_id, page * 4096, frame_ptr as u64, len);
                    (frame, false)
                }
            };
            frames.push(frame);
            cached_pages.push(cached);
        }
        frames
    } else if private {
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
        let read_len = real_size.saturating_sub(off).min(covered_len);
        if read_len > 0 {
            let mut staging = alloc::vec![0u8; read_len as usize];
            let n =
                crate::fs::fd::content_read(content_id, off, staging.as_mut_ptr() as u64, read_len);
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
        // The cache holds the object's pages from its start, so it has to reach this mapping's end.
        let cached_pages = file_page + covered_pages;
        // Grown with the cache unlocked: the read goes into the filesystem, which takes its own
        // lock and may wait for the disk (`fs::fslock`); a spin lock held across that would stop
        // every other process that maps a file.
        let existing_len =
            MMAP_FILE_CACHE.lock().get(&content_id).map(Vec::len).unwrap_or(0) as u64;
        let grown = if existing_len < cached_pages {
            // First mmap of this file, or a later mmap asking for more real-content pages than any
            // earlier one did -- allocate+zero exactly the *new* frames needed and append them,
            // never discarding whatever's already cached (those frames may already be live in
            // another process's, or this same process's, own page table -- see MMAP_FILE_CACHE's
            // own doc comment for why replacing them outright would be a real correctness bug, not
            // just a missed optimization).
            let new_frames: Vec<PhysFrame<Size4KiB>> = with_frame_allocator(|fa| {
                let mut new_frames = Vec::with_capacity((cached_pages - existing_len) as usize);
                for _ in existing_len..cached_pages {
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
            let covered_len = cached_pages * 4096;
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
            Some(new_frames)
        } else {
            None
        };
        let mut cache = MMAP_FILE_CACHE.lock();
        if let Some(new_frames) = grown {
            if cache.get(&content_id).map(Vec::len).unwrap_or(0) as u64 == existing_len {
                cache.entry(content_id).or_default().extend(new_frames);
            } else {
                // Another mapping grew the entry meanwhile: its frames stand, these go back.
                with_frame_allocator(|fa| {
                    for frame in new_frames {
                        // SAFETY: allocated above, never mapped anywhere.
                        unsafe { fa.deallocate_frame(frame) };
                    }
                });
            }
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
            .skip(file_page as usize)
            .take(covered_pages as usize)
            .copied()
            .collect()
    };

    let base = {
        use super::vm_map::{PROT_ALL, PROT_EXEC, PROT_READ as R, VmEntry, VmKind};
        // A shared mapping of a file opened read-only can never be made writable (`mprotect`).
        let max_prot = if !private && !fd_writable { R | PROT_EXEC } else { PROT_ALL };
        let kind = VmKind::File { content: content_id, page: file_page, eof_page: file_page + covered_pages };
        reserve(caller_pid, fixed_base, hint, region_len, |end| VmEntry::new(end, map_prot(prot), max_prot, !private, kind))?
    };

    let writable = prot & PROT_WRITE != 0;
    let mut flags = prot_leaf_flags(prot);
    if !private {
        // SHARED_LEAF: these frames are owned by MMAP_FILE_CACHE (keyed by content_id, real
        // cross-open sharing -- see that cache's own doc comment), not by this one mapping -- marks
        // every leaf so a real address-space teardown (`memory::address_space::AddressSpace::
        // teardown`) never frees one still cached/still live in another process's or another
        // mapping's own page table. See `SHARED_LEAF`'s own doc comment. A private mapping's own
        // frames are never shared this way, so they're left unmarked and get freed like any other
        // private leaf (matches every other private-anon-mmap/heap/stack frame already does).
        flags |= memory::address_space::SHARED_LEAF;
        if fd_writable {
            flags |= memory::address_space::MAY_WRITE_LEAF;
        }
    }

    let mut table = PROCESS_TABLE.lock();
    let me = table
        .get_mut(&caller_pid)
        .expect("mmap: current process missing from table");
    let address_space = me.address_space.as_ref().expect("mm: caller has no address space");
    // SAFETY: see do_mmap's identical reasoning -- me.address_space is the currently active
    // address space.
    let mut mapper = unsafe { address_space.mapper(phys_offset) };
    // `PROT_NONE` (`mmap/6-2.c`) maps nothing: a touch is SIGSEGV (`signal_for_user_fault`). Only
    // the file's pages are mapped; past its end (the entry's `eof_page`) is SIGBUS, POSIX's MPR.
    let accessible = prot_accessible(prot);
    if covered_pages > 0 && accessible {
        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
        let end_page =
            Page::<Size4KiB>::containing_address(VirtAddr::new(base + covered_pages * 4096 - 1));
        if let Some(id) = demand {
            let executable = !flags.contains(PageTableFlags::NO_EXECUTE);
            with_frame_allocator(|fa| -> Result<(), u64> {
                for (i, page) in Page::range_inclusive(start_page, end_page).enumerate() {
                    let entry = memory::address_space::leaf_entry_or_create(
                        mapper.level_4_table_mut(),
                        phys_offset,
                        page.start_address(),
                        fa,
                    )
                    .ok_or(ENOMEM)?;
                    memory::address_space::set_file_entry(entry, id, file_page + i as u64, executable)
                        .ok_or(ENOMEM)?;
                }
                Ok(())
            })?;
        }
        with_frame_allocator(|fa| -> Result<(), u64> {
            for (i, (page, frame)) in Page::range_inclusive(start_page, end_page).zip(frames.iter()).enumerate() {
                let flags = if cached_pages.get(i) == Some(&true) {
                    flags | memory::address_space::SHARED_LEAF | memory::address_space::CACHED_LEAF
                } else {
                    flags
                };
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
        add_mmap_file_ref(content_id);
    }
    me.vm().mmap_file_regions.push(MmapFileRegion {
        va_start: base,
        npages: page_count,
        file_page,
        content_id,
        writable,
        shared: !private,
        locked: false,
    });

    Ok(base)
}

/// The signal for a ring-3 fault at `addr` nothing could resolve: `SIGBUS` past the end of the
/// file a mapping maps (as it was when mapped: POSIX's MPR, `mmap/11-2.c`), else `SIGSEGV`. Read
/// from the map, so a mapping cut by `munmap` or `MAP_FIXED` answers for what's left of it.
pub fn signal_for_user_fault(caller_pid: Pid, addr: u64) -> u64 {
    let table = PROCESS_TABLE.lock();
    let Some(me) = table.get(&caller_pid) else {
        return crate::process::SIGSEGV;
    };
    let vm = me.vm();
    match vm.map.lookup(addr) {
        Some((start, e)) => match e.kind {
            super::vm_map::VmKind::File { page, eof_page, .. } if page + (addr - start) / 4096 >= eof_page => {
                crate::process::SIGBUS
            }
            _ => crate::process::SIGSEGV,
        },
        None => crate::process::SIGSEGV,
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
/// model always replaces a file's whole content in one shot (see `sys/modules/oxfs`'s `OpenFile::Write`
/// doc comment), so a redundant write-back just re-commits the same bytes.
fn writeback_region(region: &MmapFileRegion, phys_offset: VirtAddr) {
    if !region.shared || !region.writable {
        return;
    }
    let current_size = crate::fs::fd::content_size(region.content_id).max(0) as u64;
    let region_len = (region.file_page + region.npages) * 4096;
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
    // The map first: everything in the range leaves it (a split at either end if need be), but
    // not the kernel's own pages (`EINVAL`).
    if me.vm().map.remove(addr, addr + region_len).is_err() {
        return Err(EINVAL);
    }

    let file_region_idx = me
        .vm()
        .mmap_file_regions
        .iter()
        .position(|r| r.va_start == addr);
    let phys_region_idx = me
        .vm()
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
        // A page cache page not filled yet owns no frame: just forgotten (DEMANDPAGE.md).
        if let Some(entry) =
            memory::address_space::leaf_entry(mapper.level_4_table_mut(), phys_offset, page.start_address())
            && memory::address_space::file_entry(entry).is_some()
        {
            entry.set_unused();
            continue;
        }
        // A PROT_NONE page isn't present, so `translate` doesn't see it: remove it here.
        if let Some(entry) =
            memory::address_space::leaf_entry(mapper.level_4_table_mut(), phys_offset, page.start_address())
            && memory::address_space::is_prot_none(entry)
        {
            let frame = PhysFrame::<Size4KiB>::containing_address(entry.addr());
            let shared = entry.flags().contains(memory::address_space::SHARED_LEAF);
            entry.set_unused();
            if !shared && memory::refs::release(frame) {
                // SAFETY: a private PROT_NONE leaf, just removed, no other address space maps.
                with_frame_allocator(|fa| unsafe { fa.deallocate_frame(frame) });
            }
            continue;
        }
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
            if !is_shared_leaf && memory::refs::release(frame) {
                // SAFETY: a private page no other address space maps any more (`memory::refs`),
                // never a SHARED_LEAF one (checked above).
                with_frame_allocator(|fa| unsafe { fa.deallocate_frame(frame) });
            }
        }
    }

    if let Some(idx) = file_region_idx {
        let region = me.vm().mmap_file_regions.remove(idx);
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
        let mut shared = me.vm();
        shared.mmap_phys_regions.remove(idx);
        let none_left = shared.mmap_phys_regions.is_empty();
        drop(shared);
        drop(table);
        if none_left {
            crate::console::framebuffer::set_owned_by_userspace(false);
            crate::tty::console::set_raw_keyboard_owned(false);
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
    let shared = me.vm();
    let region = shared
        .mmap_file_regions
        .iter()
        .find(|r| addr >= r.va_start && addr < r.va_start + r.npages * 4096)
        .ok_or(ENOMEM)?;
    if flags & MS_INVALIDATE != 0 && region.locked {
        return Err(EBUSY);
    }
    // Written back with no lock held: the write goes into the filesystem, which takes its own
    // lock and may wait for the disk (`fs::fslock`).
    let region = region.clone();
    drop(shared);
    drop(table);
    writeback_region(&region, phys_offset);
    Ok(0)
}

/// Real cleanup for every fd-backed mapping a process still had live at exit/`execve` — writes
/// back and releases each one's `MMAP_FILE_CACHE` reference, the same way an explicit `munmap`
/// would, since neither event ever calls `do_munmap` itself. Called with no lock held by the
/// last live process using `space` (`lifecycle::last_live_user`), from `terminate_process` and
/// from `do_execve` once the new `AddressSpace` is committed.
pub fn cleanup_mmap_file_regions_for_exit(space: &AddressSpace) {
    let regions = core::mem::take(&mut space.vm().mmap_file_regions);
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
pub fn cleanup_mmap_phys_regions_for_exit(space: &AddressSpace) {
    let had_any = {
        let mut vm = space.vm();
        let had_any = !vm.mmap_phys_regions.is_empty();
        vm.mmap_phys_regions.clear();
        had_any
    };
    if had_any {
        crate::console::framebuffer::set_owned_by_userspace(false);
        crate::tty::console::set_raw_keyboard_owned(false);
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
        .is_some_and(|p| !p.vm().mmap_phys_regions.is_empty())
}

/// `SYS_MPROTECT`'s real logic. `PROT_READ`/`PROT_WRITE`/`PROT_EXEC` set `USER_ACCESSIBLE`/
/// `WRITABLE`/`NO_EXECUTE` on the caller's own page-table entries, anywhere in the user range:
/// `mmap` regions, ELF segments (`ld.so`'s RELRO step), the `brk` heap, the stack. Asking for
/// `PROT_WRITE | PROT_EXEC` is a W^X violation (`check_wx`). `PROT_NONE` leaves the page
/// non-present with its frame kept (`PROT_NONE_LEAF`).
///
/// Every page is checked before any changes (all or nothing):
///
/// - `ENOMEM` for a range outside `[VM_MINUSER, VM_MAXUSER)`, or for a page with nothing mapped,
///   except inside the `mmap` window, where a `PROT_NONE` reservation (`do_mmap_anon`) is VA with
///   no entry at all and widening it allocates a fresh zeroed page. Only a user leaf (present and
///   `USER_ACCESSIBLE`, or `PROT_NONE_LEAF`) is ever changed; nothing kernel-only lies in the user
///   range (`usercopy::check_user_range_layout`), and anything else is refused, not touched.
/// - `EACCES` for `PROT_WRITE` on a shared page (`SHARED_LEAF`) whose owner doesn't allow writing
///   (`MAY_WRITE_LEAF`: a `MAP_SHARED` mapping of a file not open for writing, an `SHM_RDONLY`
///   attachment), as POSIX requires. A page cache page (`CACHED_LEAF`) made writable becomes a
///   private copy instead.
pub fn do_mprotect(caller_pid: Pid, addr: u64, len: u64, prot: u64) -> Result<u64, u64> {
    if len == 0 {
        return Ok(0);
    }
    if !addr.is_multiple_of(4096) {
        return Err(EINVAL);
    }
    let Some(end_inclusive) = addr.checked_add(len).and_then(|e| e.checked_sub(1)) else {
        return Err(ENOMEM);
    };
    check_wx(caller_pid, prot, "mprotect")?;
    if addr < crate::memory::usercopy::VM_MINUSER || end_inclusive >= crate::memory::usercopy::VM_MAXUSER {
        return Err(ENOMEM);
    }
    // The map decides first, changing nothing on a refusal (POSIX): `ENOMEM` if a page isn't
    // mapped, `EACCES` past a mapping's maximum protection (a shared mapping of a file opened
    // read-only) or on the kernel's own pages. Pages not made yet (anonymous memory never touched,
    // the stack's reserve, a file's tail past its end) stay as they are: the map's protection is
    // what their first touch gets (`try_fill_anon`).
    {
        use super::vm_map::MapError;
        let table = PROCESS_TABLE.lock();
        let me = table.get(&caller_pid).expect("mprotect: current process missing from table");
        let page_end = (end_inclusive | 0xfff) + 1;
        match me.vm().map.protect(addr, page_end, map_prot(prot)) {
            Ok(_) => {}
            Err(MapError::Unmapped | MapError::Invalid) => return Err(ENOMEM),
            Err(_) => return Err(EACCES),
        }
    }

    let writable = prot & PROT_WRITE != 0;
    let accessible = prot_accessible(prot);
    let leaf_flags = prot_leaf_flags(prot);
    // The bits `mprotect` owns on an existing leaf; every other bit (`SHARED_LEAF`, ...) is kept.
    let prot_bits = PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;

    // Page cache pages not filled yet are filled first, as a touch would, so the new permissions
    // apply to a real page (DEMANDPAGE.md): left as they were, a page made PROT_NONE would fill and
    // become readable at its first touch. Before any lock: a fill may sleep on the disk.
    for va in (addr..=end_inclusive).step_by(4096) {
        if let Some(FileFill::NoMemory) = try_fill_file_page(va, true) {
            return Err(ENOMEM);
        }
    }

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
    // The checks, before anything changes (this function's doc comment).
    let mut shared_written = false;
    for page in Page::range_inclusive(start_page, end_page) {
        let entry = memory::address_space::leaf_entry(mapper.level_4_table_mut(), phys_offset, page.start_address());
        let Some(entry) = entry.filter(|e| !e.is_unused()) else {
            continue; // in a mapping (checked above), not made yet
        };
        let flags = entry.flags();
        let user_leaf = memory::address_space::is_prot_none(entry)
            || flags.contains(PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE);
        if !user_leaf {
            return Err(ENOMEM);
        }
        let shared = flags.contains(memory::address_space::SHARED_LEAF) && !flags.contains(memory::address_space::CACHED_LEAF);
        if writable && shared {
            if !flags.contains(memory::address_space::MAY_WRITE_LEAF) {
                return Err(EACCES);
            }
            shared_written = true;
        }
    }
    if shared_written {
        // A `MAP_SHARED` file mapping made writable is written back like one mapped writable.
        let mut shared = me.vm();
        for r in shared.mmap_file_regions.iter_mut().filter(|r| r.shared) {
            if r.va_start <= end_inclusive && addr < r.va_start + r.npages * 4096 {
                r.writable = true;
            }
        }
    }
    with_frame_allocator(|fa| -> Result<(), u64> {
        for page in Page::range_inclusive(start_page, end_page) {
            let va = page.start_address();
            // A PROT_NONE page (`PROT_NONE_LEAF`) comes back present, with the flags it had,
            // before the permissions below are applied; one staying PROT_NONE is left alone.
            if let Some(entry) = memory::address_space::leaf_entry(mapper.level_4_table_mut(), phys_offset, va)
                && memory::address_space::is_prot_none(entry)
            {
                if !accessible {
                    continue;
                }
                let flags = (entry.flags() - memory::address_space::PROT_NONE_LEAF) | PageTableFlags::PRESENT;
                entry.set_addr(entry.addr(), flags);
            }
            match mapper.translate(va) {
                TranslateResult::Mapped { flags: old_flags, .. } if !accessible => {
                    // To PROT_NONE: not present, keeping its frame and flags (`PROT_NONE_LEAF`).
                    let entry = memory::address_space::leaf_entry(mapper.level_4_table_mut(), phys_offset, va)
                        .expect("a mapped page has a leaf entry");
                    let flags = (old_flags - PageTableFlags::PRESENT) | memory::address_space::PROT_NONE_LEAF;
                    entry.set_addr(entry.addr(), flags);
                    x86_64::instructions::tlb::flush(va);
                }
                TranslateResult::Mapped {
                    frame: old_frame,
                    flags: old_flags,
                    ..
                } => {
                    let mut new_flags = (old_flags & !prot_bits) | (leaf_flags & prot_bits);
                    // A private page fork still shares (COW.md §5.2): writable means copy on
                    // write; read-only drops the copy-on-write intent. Unshared, it's plain.
                    if !old_flags.contains(memory::address_space::SHARED_LEAF) {
                        new_flags -= memory::address_space::COW_LEAF;
                        if new_flags.contains(PageTableFlags::WRITABLE) && !matches!(old_frame, x86_64::structures::paging::mapper::MappedFrame::Size4KiB(f) if memory::refs::sole_owner(f))
                        {
                            new_flags = (new_flags - PageTableFlags::WRITABLE) | memory::address_space::COW_LEAF;
                        }
                    }
                    if writable && old_flags.contains(memory::address_space::CACHED_LEAF) {
                        // A page cache page made writable: this process's own copy from now on,
                        // the cache's page left as it is (PAGECACHE.md §3.2).
                        let copy = fa.allocate_frame().ok_or(ENOMEM)?;
                        let src = (phys_offset + old_frame.start_address().as_u64()).as_ptr::<u8>();
                        let dst = (phys_offset + copy.start_address().as_u64()).as_mut_ptr::<u8>();
                        // SAFETY: a live cache frame, and a frame just allocated.
                        unsafe { core::ptr::copy_nonoverlapping(src, dst, 4096) };
                        new_flags &= !(memory::address_space::SHARED_LEAF | memory::address_space::CACHED_LEAF);
                        // SAFETY: replaces this process's own leaf; the cache frame stays the
                        // cache's (never freed here).
                        unsafe {
                            mapper.unmap(page).map_err(|_| ENOMEM)?.1.flush();
                            mapper.map_to(page, copy, new_flags, fa).map_err(|_| ENOMEM)?.flush();
                        }
                        continue;
                    }
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
                // Not made yet: its first touch gets the new protection from the map.
                _ => {}
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
    // Locked pages are resident: page cache pages and anonymous memory not made yet are made now
    // (DEMANDPAGE.md, VMMAP.md §5.2).
    if let Some(end) = addr.checked_add(len) {
        for va in (addr & !0xfff..end).step_by(4096) {
            if let Some(FileFill::NoMemory) = try_fill_file_page(va, true) {
                return Err(crate::syscall::EAGAIN);
            }
        }
        fill_anon_range(addr, end)?;
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
/// locking exists to make real). `MCL_FUTURE` flips `VmState::mlockall_future`, which
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
    let mut shared = me.vm();
    if flags & MCL_FUTURE != 0 {
        shared.mlockall_future = true;
    }
    let mut anon = Vec::new();
    if flags & MCL_CURRENT != 0 {
        for region in shared.mmap_file_regions.iter_mut() {
            region.locked = true;
        }
        if flags & MCL_ONFAULT == 0 {
            anon.extend(shared.map.iter().filter_map(|(start, e)| {
                matches!(e.kind, super::vm_map::VmKind::Anon | super::vm_map::VmKind::Heap).then_some((start, e.end))
            }));
        }
    }
    drop(shared);
    drop(table);
    // Everything mapped now is made resident (VMMAP.md §5.2), with no lock held: the fill takes
    // the map itself.
    for (start, end) in anon {
        fill_anon_range(start, end)?;
    }
    Ok(0)
}

pub fn do_munlockall(caller_pid: Pid) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("munlockall: current process missing from table");
    let mut shared = me.vm();
    shared.mlockall_future = false;
    shared.locked_bytes = 0;
    for region in shared.mmap_file_regions.iter_mut() {
        region.locked = false;
    }
    Ok(0)
}

/// Ceiling for a fixed-address (`ET_EXEC`) binary's `SYS_BRK` heap, below the mmap window and
/// the fault trampoline. A PIE's heap starts after its biased image, inside the ASLR window
/// (`aslr::PIE_ASLR_BASE` up), and may grow to `PIE_BRK_CEILING` instead.
const BRK_REGION_CEILING: u64 = 0x_2000_0000;
/// Ceiling for a PIE's `SYS_BRK` heap: the start of the SysV shared memory region.
const PIE_BRK_CEILING: u64 = 0x_4000_0000_0000;
/// `SYS_BRK`'s real logic. `addr == 0` queries the current value without changing it (the
/// convention every real `sbrk(0)` already relies on). Shrinking just lowers the stored value —
/// no unmap, same no-reclaim simplification `do_munmap` above documents. Growing maps freshly
/// zeroed pages from the first not-yet-mapped page onward: `brk` isn't necessarily page-aligned
/// (a previous grow may have stopped mid-page), so the *page containing* the old value is already
/// mapped and must be skipped, not re-mapped (`Mapper::map_to` fails on an already-present page).
pub fn do_brk(caller_pid: Pid, addr: u64) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let me = table
        .get(&caller_pid)
        .expect("brk: current process missing from table");
    let mut shared = me.vm();

    if addr == 0 {
        return Ok(shared.brk.as_u64());
    }
    if addr <= shared.brk.as_u64() {
        shared.brk = VirtAddr::new(addr);
        return Ok(addr);
    }
    let ceiling = if shared.brk.as_u64() >= crate::process::aslr::PIE_ASLR_BASE {
        PIE_BRK_CEILING
    } else {
        BRK_REGION_CEILING
    };
    if addr > ceiling || shared.brk.as_u64() < crate::memory::usercopy::VM_MINUSER {
        return Err(ENOMEM);
    }
    if addr.saturating_sub(shared.brk_base.as_u64()) > me.rlimits[super::limits::RLIMIT_DATA].0 {
        return Err(ENOMEM);
    }

    let old_top = shared.brk.as_u64();
    let new_top = addr;
    let map_start = old_top.div_ceil(4096) * 4096;
    let new_end = new_top.div_ceil(4096) * 4096;
    if new_end > map_start {
        // The heap's entry grows over the new pages (made on the first growth past the image),
        // within RLIMIT_AS and only into free space.
        check_as(&shared, new_end - map_start, me.rlimits[super::limits::RLIMIT_AS].0)?;
        let heap_start = shared.brk_base.as_u64().div_ceil(4096) * 4096;
        let grown = match shared.map.lookup(map_start - 1) {
            Some((start, e)) if e.kind == super::vm_map::VmKind::Heap => shared.map.set_end(start, new_end),
            _ => shared.map.insert(
                map_start.max(heap_start),
                super::vm_map::VmEntry::new(new_end, super::vm_map::PROT_READ | super::vm_map::PROT_WRITE, super::vm_map::PROT_ALL, false, super::vm_map::VmKind::Heap),
            ),
        };
        grown.map_err(|_| ENOMEM)?;
    }
    // The new pages are made at their first touch (`try_fill_anon`, VMMAP.md §5.1).
    shared.brk = VirtAddr::new(new_top);
    Ok(new_top)
}
