//! Process lifecycle: spawn/fork/execve/wait4/exit/reboot -- split out of the original process.rs.

use crate::memory::usercopy::{PATH_MAX, Pod, UserPtr, copyin_val, copyin_vec, copyout_val};
use crate::syscall::ENAMETOOLONG;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
};

use super::*;
use crate::memory::address_space::AddressSpace;
use crate::memory::{self, with_frame_allocator};
use crate::process::elf::{self, Elf};
use crate::process::scheduler;
use crate::syscall::{
    self, E2BIG, EACCES, EBADF, ECHILD, EINVAL, EIO, ELOOP, ENOENT, ENOEXEC, ENOMEM, SyscallFrame,
};

/// `execveat`'s open -- see `do_execveat`. OxideBSD's own number (`sys/modules/oxfs`'s
/// `SYS_OPENAT`); its `RawAtPath` is the caller's own, a user pointer.
const SYS_OPENAT: u64 = 560;
/// Builds a brand-new process from `elf_bytes`: a fresh `AddressSpace` (`AddressSpace::new`, same
/// as the old one-shot demo path), the ELF loaded into it (`elf::load`), a mapped user stack, and
/// a fresh kernel stack seeded (`context_switch::seed_spawn_frame`) so its first-ever run lands in
/// `spawn_trampoline_asm` rather than resuming mid-syscall like every other switch does. Inserts
/// into the process table in `Ready` state and enqueues it — does not itself switch to it (the
/// caller decides when, via `scheduler::schedule`/`start`).
pub fn spawn(elf_bytes: &[u8], parent: Option<Pid>) -> Result<Pid, SpawnError> {
    spawn_with(elf_bytes, parent, &[b"(init)"], DEFAULT_ENVP)
}

/// The environment `spawn` gives a boot-spawned process (with `argv` just `(init)`: an embedded
/// ELF has no path to name it by). `TERM=linux` matches the console (`sys/console/vga.rs`'s
/// VT100/ANSI parser); `PS1` uses the backslash escapes both `/bin/sh` and hush expand at print
/// time, `\[ \]` marking the colour codes as taking no room.
pub const DEFAULT_ENVP: &[&[u8]] = &[
    // The PATH of hier(7) and login.conf: most of the base system lives outside /bin
    // (a missing directory here once left a seeded /usr/bin/nano unreachable by name).
    b"PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/games",
    b"TERM=linux",
    b"PS1=\\[\\e[1;32m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ ",
];

/// `spawn` with an explicit `argv` and `envp` (the real boot's pid 1, `/bin/sh` as a login
/// shell, needs `argv[0] = "-sh"` and `HOME`).
pub fn spawn_with(elf_bytes: &[u8], parent: Option<Pid>, argv: &[&[u8]], envp: &[&[u8]]) -> Result<Pid, SpawnError> {
    spawn_boot(elf_bytes, parent, argv, envp, true)
}

/// `spawn_with`, choosing whether the console becomes the process's controlling terminal. The
/// real boot's `/sbin/init` starts without one, as on the BSDs, so that its children can make
/// it theirs (INIT.md §5).
pub fn spawn_boot(
    elf_bytes: &[u8],
    parent: Option<Pid>,
    argv: &[&[u8]],
    envp: &[&[u8]],
    console: bool,
) -> Result<Pid, SpawnError> {
    // Boot-time only: the active address space is the kernel's own, with nothing in user space.
    let phys_offset = memory::phys_mem_offset();
    let address_space = with_frame_allocator(|fa| AddressSpace::new(phys_offset, fa))
        .map_err(|()| SpawnError::OutOfMemory)?;
    spawn_into(address_space, None, elf_bytes, parent, argv, envp, console)
}

/// A process with no program yet, as pid `pid` (FreeBSD's process 1 before `start_init`): its
/// first switch-in runs `init::start_in_context`, which reads the program from the root file
/// system in this process's own context -- a live process, so the read may sleep on the disk --
/// and loads it (`load_into_current`). Until then its address space has only the kernel's half.
pub(crate) fn spawn_unloaded(pid: Pid, name: &[u8], console: bool) -> Result<Pid, SpawnError> {
    let phys_offset = memory::phys_mem_offset();
    let address_space = with_frame_allocator(|fa| AddressSpace::new_excluding_user(phys_offset, fa))
        .map_err(|()| SpawnError::OutOfMemory)?;
    let Ok(kernel_stack) = KernelStack::new() else {
        with_frame_allocator(|fa| unsafe { address_space.teardown(phys_offset, fa) });
        return Err(SpawnError::OutOfMemory);
    };
    let zero = VirtAddr::zero();
    spawn_finish(address_space, kernel_stack, Some(pid), zero, zero, zero, None, &[name], &[], console)
}

/// Gives the calling process, started by `spawn_unloaded`, its program: builds the image in a
/// new address space, switches to it and drops the empty one. Returns where to enter user mode:
/// the entry point and the initial stack pointer.
pub(crate) fn load_into_current(
    elf_bytes: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<(VirtAddr, VirtAddr), SpawnError> {
    let pid = scheduler::current_pid();
    let phys_offset = memory::phys_mem_offset();
    let space = with_frame_allocator(|fa| AddressSpace::new_excluding_user(phys_offset, fa))
        .map_err(|()| SpawnError::OutOfMemory)?;
    let (brk, entry, initial_rsp) = match load_image(&space, elf_bytes, argv, envp) {
        Ok(l) => l,
        Err(e) => {
            // SAFETY: never activated.
            with_frame_allocator(|fa| unsafe { space.teardown(phys_offset, fa) });
            return Err(e);
        }
    };
    {
        let mut vm = space.vm();
        vm.brk = brk;
        vm.brk_base = brk;
    }
    let arg0 = argv.first().copied().unwrap_or(b"(init)");
    let old = {
        let mut table = PROCESS_TABLE.lock();
        let me = table.get_mut(&pid).expect("load_into_current: caller missing from the table");
        me.entry_point = entry;
        me.user_stack_top = initial_rsp;
        me.comm = basename(arg0.strip_prefix(b"-").unwrap_or(arg0)).to_vec();
        me.cmdline = build_cmdline(argv);
        me.environ = build_cmdline(envp);
        let old = me.address_space.replace(space);
        // SAFETY: the new table carries the kernel's half like every address space.
        unsafe { me.address_space.as_ref().unwrap().activate() };
        old
    };
    if let Some(old) = old {
        // SAFETY: no longer the current CR3, and nothing else uses an unloaded process's table.
        with_frame_allocator(|fa| unsafe { old.teardown(phys_offset, fa) });
    }
    Ok((entry, initial_rsp))
}

fn spawn_into(
    address_space: AddressSpace,
    pid: Option<Pid>,
    elf_bytes: &[u8],
    parent: Option<Pid>,
    argv: &[&[u8]],
    envp: &[&[u8]],
    console: bool,
) -> Result<Pid, SpawnError> {
    let phys_offset = memory::phys_mem_offset();
    let loaded = load_image(&address_space, elf_bytes, argv, envp);
    let (brk, entry, initial_rsp) = match loaded {
        Ok(l) => l,
        Err(e) => {
            // SAFETY: never activated, so not the current CR3.
            with_frame_allocator(|fa| unsafe { address_space.teardown(phys_offset, fa) });
            return Err(e);
        }
    };
    let Ok(kernel_stack) = KernelStack::new() else {
        with_frame_allocator(|fa| unsafe { address_space.teardown(phys_offset, fa) });
        return Err(SpawnError::OutOfMemory);
    };
    spawn_finish(address_space, kernel_stack, pid, brk, entry, initial_rsp, parent, argv, envp, console)
}

/// Loads the program and builds its initial user stack in a not-yet-active address space.
/// Returns the start of its `brk` heap (after the biased image), its entry point and its initial
/// stack pointer.
fn load_image(
    address_space: &AddressSpace,
    elf_bytes: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<(VirtAddr, VirtAddr, VirtAddr), SpawnError> {
    let phys_offset = memory::phys_mem_offset();
    // SAFETY: phys_offset is the bootloader's phys-memory mapping; this is the only live view of
    // address_space's own (not-yet-active) level 4 table right now.
    let mut mapper = unsafe { address_space.mapper(phys_offset) };

    let elf = Elf::parse(elf_bytes).map_err(SpawnError::Elf)?;
    if !matches!(elf.interpreter(), Ok(None)) {
        return Err(SpawnError::NeedsInterpreter);
    }
    // A static PIE (ET_DYN) gets a randomized bias, as in do_execve; a fixed-address ET_EXEC none.
    let bias = if elf.is_dynamic() { crate::process::aslr::pick_bias() } else { 0 };
    let entry = elf::load(&elf, &mut mapper, phys_offset, bias).map_err(SpawnError::Elf)?;

    let stack_top = VirtAddr::new(USER_STACK_TOP);
    let mapped_pages =
        map_user_stack(&mut mapper, stack_top, user_stack_pages(), elf.exec_stack()).map_err(|()| SpawnError::OutOfMemory)?;
    crate::process::fault_trampoline::map(&mut mapper, phys_offset).map_err(|()| SpawnError::OutOfMemory)?;
    {
        let mut vm = address_space.vm();
        crate::process::mm::record_segments(&mut vm, &elf, bias);
        crate::process::mm::record_exec_tail(&mut vm, elf.exec_stack());
    }
    let initial_rsp = crate::process::user_stack::build(
        &elf,
        argv,
        envp,
        stack_top,
        user_stack_bottom(stack_top, user_stack_pages()),
        &mapped_pages,
        phys_offset,
        None,
        bias,
        false,
    );
    Ok((VirtAddr::new(bias + elf.highest_loaded_address()), entry, initial_rsp))
}

fn spawn_finish(
    address_space: AddressSpace,
    kernel_stack: KernelStack,
    pid: Option<Pid>,
    brk: VirtAddr,
    entry: VirtAddr,
    initial_rsp: VirtAddr,
    parent: Option<Pid>,
    argv: &[&[u8]],
    envp: &[&[u8]],
    console: bool,
) -> Result<Pid, SpawnError> {
    let pid = pid.inspect(|&p| reserve_pid(p)).unwrap_or_else(alloc_pid);
    // No parent to inherit a process group from (spawn doesn't inherit anything else from parent
    // either -- cwd/fs_base/brk all start fresh too) -- becomes its own group leader, same
    // convention as a real init/session leader.
    let pgid = pid;
    // Named after its `argv[0]`, as exec names a process after its path (a login shell's
    // leading `-` isn't part of the name).
    let arg0 = argv.first().copied().unwrap_or(b"(init)");
    let comm = basename(arg0.strip_prefix(b"-").unwrap_or(arg0)).to_vec();
    let cmdline = build_cmdline(argv);
    let kernel_stack_top = kernel_stack.top();
    let rsp = crate::process::context_switch::seed_spawn_frame(kernel_stack_top);
    {
        let mut vm = address_space.vm();
        vm.brk = brk;
        vm.brk_base = brk;
    }

    let process = Process {
        pid,
        // pid 1's own thread group of one -- see Process::tgid's own doc comment.
        tgid: pid,
        parent,
        children: Vec::new(),
        state: ProcState::Ready,
        address_space: Some(address_space),
        kernel_stack,
        kernel_stack_top,
        rsp,
        entry_point: entry,
        user_stack_top: initial_rsp,
        shared: Arc::new(Mutex::new(ThreadGroupShared {
            cwd: 0,
            root: 0,
            umask: 0o022,
            cred: Cred::root(),
            sigactions: [SigAction::DEFAULT; (SIGRTMAX + 1) as usize],
            oom_adj: 0,
        })),
        fs_base: 0,
        start_ticks: crate::cpu::interrupts::ticks(),
        clear_child_tid: 0,
        pending_signals: 0,
        blocked_signals: 0,
        signal_stack: Vec::new(),
        altstack: AltStack::default(),
        on_altstack: false,
        // Not inherited -- see Process::preempted_resume's own doc comment.
        preempted_resume: None,
        estcpu: 0,
        pgid,
        sid: pid,
        comm,
        cmdline,
        environ: build_cmdline(envp),
        real_timer_deadline: None,
        real_timer_interval_ticks: 0,
        posix_timers: [None; MAX_POSIX_TIMERS],
        // No login mechanism exists -- pid 1 (and every process descending from it) starts as
        // root, same reasoning as ThreadGroupShared::uid's own doc comment (via Process::shared
        // above).
        rlimits: super::limits::initial_rlimits(),
        nice: 0,
        sched_policy: SCHED_DEFAULT,
        sched_priority: 0,
        stop_notify_pending: false,
        cont_notify_pending: false,
        sigsuspend_restore_mask: None,
        sysv_sem_undo: Vec::new(),
        pending_siginfo: [QueuedSigInfo::default(); 35],
        rt_queue: core::array::from_fn(|_| Vec::new()),
        fpu_state: crate::cpu::fpu::clean_state(),
        cpu_ticks: 0,
        minflt: 0,
        majflt: 0,
        sys_ticks: 0,
        child_cpu_ticks: 0,
        child_sys_ticks: 0,
        // A fresh process/thread always starts with a full quantum -- see `Process::
        // quantum_ticks_left`'s own doc comment.
        quantum_ticks_left: crate::cpu::interrupts::PREEMPT_QUANTUM_TICKS,
        off_cpu_cycles: 0,
        switched_out_at: 0,
        // No cascade in progress for a process that hasn't run yet -- see `Process::
        // cascade_budget`'s own doc comment.
        cascade_budget: None,
        tty_timed_out: false,
        vfork_parent: None,
    };

    {
        let mut table = PROCESS_TABLE.lock();
        if let Some(parent_pid) = parent
            && let Some(p) = table.get_mut(&parent_pid)
        {
            p.children.push(pid);
        }
        table.insert(pid, Box::new(process));
    }
    // A process the kernel starts runs on the console. Unless it's the real `/sbin/init`, the
    // console also becomes its controlling terminal -- as the BSDs' init does for single-user
    // mode -- so a shell or the emergency program has job control without opening it itself.
    if console {
        crate::tty::assign(crate::tty::TTYV0, pid, pid);
    }
    // Bootstraps this process's own stdin/stdout/stderr from crate::fs::fd::init's own pseudo-pid
    // registration -- the same fork_inherit path a real fork() uses, see that function's own doc
    // comment.
    crate::fs::fd::fork_inherit(0, pid);
    scheduler::enqueue_ready(pid);
    Ok(pid)
}

/// Maps a fresh user stack ending at `stack_top`, returning the `(Page, PhysFrame)` map of every
/// page it just mapped — `user_stack::build` needs this to write the argv/envp/auxv image into the
/// right physical frames afterward, the same way `elf::load` already tracks its own mapped pages
/// for BSS zeroing.
///
/// # Errors
///
/// `Err(())` on real frame exhaustion -- same "a real resource limit must fail one syscall, not
/// panic the kernel" motivation as `process::KernelStack::new`/`AddressSpace::build_from_active`/
/// `fault_trampoline::map`. Deliberately doesn't unmap/free whatever pages this call already
/// mapped before hitting exhaustion -- `do_execve`, this function's one fallible-path caller, has
/// no established convention for tearing down its own scratch `new_address_space` on *any*
/// mid-build failure yet (an `ENOEXEC` found partway through `elf::load`, for instance, leaks the
/// same way today) -- not introducing a new, inconsistent partial-cleanup discipline for just this
/// one call site. `spawn`'s boot-time call site still panics on this, same as every other
/// boot-time allocation site.
fn map_user_stack(
    mapper: &mut impl Mapper<Size4KiB>,
    stack_top: VirtAddr,
    pages: u64,
    exec: bool,
) -> Result<BTreeMap<Page<Size4KiB>, PhysFrame<Size4KiB>>, ()> {
    let stack_bottom_page = Page::containing_address(stack_top - pages * 4096);
    let stack_top_page = Page::containing_address(stack_top - 1u64);
    let phys_offset = memory::phys_mem_offset();
    // Not executable unless the program's `PT_GNU_STACK` asks for it (`Elf::exec_stack`); pages
    // the stack grows into later copy this (`mm::try_grow_user_stack`).
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    if exec {
        if crate::cpu::nx::enabled() {
            crate::serial_println!(
                "[wx] pid {}: executable stack (PT_GNU_STACK)",
                crate::process::scheduler::current_pid()
            );
        }
    } else {
        flags |= crate::cpu::nx::no_execute();
    }
    with_frame_allocator(|fa| {
        let mut mapped_pages = BTreeMap::new();
        for page in Page::range_inclusive(stack_bottom_page, stack_top_page) {
            let frame = fa.allocate_frame().ok_or(())?;
            // SAFETY: frame was just allocated (unused, per BootInfoFrameAllocator's contract),
            // and page falls in this address space's own, not-yet-active range.
            let flush = unsafe {
                mapper.map_to(page, frame, flags, fa)
            };
            match flush {
                // Real, resource-exhaustion-triggerable: map_to's own internal page-table-
                // structure allocation can hit the same frame exhaustion the leaf allocation just
                // above already reports as a real ENOMEM, not a kernel panic.
                Err(x86_64::structures::paging::mapper::MapToError::FrameAllocationFailed) => {
                    return Err(());
                }
                // A real logic-invariant violation, not a resource limit -- this range is always
                // freshly computed and unmapped in a brand-new address space, so hitting either
                // means a future change broke that assumption, worth a loud panic rather than a
                // silently-wrong ENOMEM.
                Err(e) => panic!("failed to map a user stack page: {e:?}"),
                Ok(flush) => flush.flush(),
            }
            // A real frame handed back by `allocate_frame` may be a reused one (see
            // `BootInfoFrameAllocator`'s own `FrameDeallocator` impl) carrying a previous,
            // unrelated process's leftover stack content -- `user_stack::build` only ever writes
            // the top of this region (argv/envp/auxv); everything below that is directly visible
            // to the new process's own uninitialized locals otherwise, a real cross-process
            // information leak. Same technique `elf::load`'s BSS zeroing and `do_mmap`'s
            // anonymous-mapping zeroing already use.
            let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
            unsafe { core::ptr::write_bytes(frame_ptr, 0, 4096) };
            mapped_pages.insert(page, frame);
        }
        Ok(mapped_pages)
    })
}

/// `stack_top` minus enough room for `user_stack::build`'s image to always fit, regardless of
/// argv/envp length -- `map_user_stack` itself already computed this same bound (`user_stack_pages()`
/// below `stack_top`); re-derived here rather than threading an extra return value through, since
/// both callers already have `stack_top` in scope.
fn user_stack_bottom(stack_top: VirtAddr, pages: u64) -> VirtAddr {
    stack_top - pages * 4096
}

/// How many stack pages to map eagerly at exec: the usual `user_stack_pages()`, or enough to hold
/// the whole argv/envp/auxv image `user_stack::build` writes through those pages' frames. The rest
/// of the stack grows on demand (`mm::try_grow_user_stack`). `E2BIG` when the image doesn't fit in
/// the stack `RLIMIT_STACK` allows.
fn user_stack_eager_pages(arg_bytes: u64) -> Result<u64, u64> {
    // Pointer arrays, auxv and alignment slack on top of the raw strings.
    const IMAGE_OVERHEAD: u64 = 64 * 1024;
    let needed = (arg_bytes + IMAGE_OVERHEAD).div_ceil(4096);
    let limit = crate::process::mm::stack_limit() / 4096;
    if needed > limit {
        return Err(E2BIG);
    }
    Ok(needed.max(user_stack_pages()).min(limit))
}

/// `sys_fork`'s real logic: deep-copies the calling process's address space
/// (`AddressSpace::fork`), builds a fresh kernel stack seeded so the child's first switch-in
/// resumes it as if returning from this very same syscall with `0`
/// (`context_switch::seed_fork_frame`), and enqueues it `Ready`. The parent's own return value
/// (the child's pid) flows back through the completely ordinary `Ok(child_pid)` -> `frame.rax`
/// path — no special-casing needed on the parent side.
///
/// **A forked child's PIE ASLR bias, if any, is never re-picked here** — this function (and
/// everything `fork_impl` calls) contains no `elf::load` call anywhere; `AddressSpace::fork` deep-
/// copies the parent's already-mapped, already-biased pages verbatim. A process's `process::aslr`
/// bias is decided exactly once, by whichever `execve()` last loaded its current image — `fork()`
/// only ever duplicates whatever is already there.
pub fn do_fork_from_current() -> Result<u64, u64> {
    fork_impl(ForkKind::Fork)
}

/// `vfork(2)` (`SYS_VFORK`, the `vfork` module; OxideBSD-doc `COW.md` §7): the child borrows the
/// caller's address space instead of copying it, and resumes at the call site with `0`, on the
/// caller's own stack; the caller sleeps until the child execs or exits, then returns the
/// child's pid. Everything else is fork's: the child is a process of its own, with its own copy
/// of the fd table, credentials and signal dispositions. POSIX leaves anything but `exec` or
/// `_exit` in the child undefined; here it is whatever the shared memory makes of it, and the
/// kernel's bookkeeping stays right either way (`mm::VmState` goes with the table).
pub fn do_vfork() -> Result<u64, u64> {
    fork_impl(ForkKind::Vfork)
}

/// `clone(fn, stack, CLONE_VM|CLONE_VFORK|SIGCHLD, arg)`, the shape musl's `posix_spawn()`
/// issues (`external/mit/musl/src/process/posix_spawn.c`; found through the on-target Clang
/// driver, which spawns every tool that way): vfork, except that the child starts at `fn` on
/// `stack` (`context_switch::seed_clone_frame`) rather than at the call site. The child borrows
/// the address space and the caller sleeps until it execs or exits, as for `do_vfork`.
pub fn do_vfork_clone(new_user_rsp: u64) -> Result<u64, u64> {
    fork_impl(ForkKind::VforkClone(new_user_rsp))
}

/// What `fork_impl` makes.
#[derive(Clone, Copy)]
enum ForkKind {
    /// `fork(2)`: a copy-on-write copy of the address space; the child resumes at the call site.
    Fork,
    /// `vfork(2)`: the child borrows the address space and resumes at the call site.
    Vfork,
    /// `clone(CLONE_VM|CLONE_VFORK)`: the child borrows the address space and starts on this stack.
    VforkClone(u64),
}

impl ForkKind {
    /// Whether the child borrows the caller's address space, the caller sleeping until it's done.
    fn borrows(self) -> bool {
        !matches!(self, ForkKind::Fork)
    }
}

/// A vfork child is done with its parent's address space: it exec'd (`exec_image`, after the
/// switch to its new table) or is exiting (`terminate_process`). Wakes the parent thread asleep
/// in `fork_impl`, if it still is: it may have been killed, or stopped and not yet continued (it
/// sees the borrow is over once it runs). Nothing for a process that isn't borrowing.
pub(crate) fn vfork_release(child_pid: Pid) {
    let mut table = PROCESS_TABLE.lock();
    let Some(parent_pid) = table.get_mut(&child_pid).and_then(|c| c.vfork_parent.take()) else {
        return;
    };
    if let Some(parent) = table.get_mut(&parent_pid)
        && parent.state == ProcState::Blocked(BlockReason::WaitingForVforkChild(child_pid))
    {
        parent.state = ProcState::Ready;
        scheduler::enqueue_ready(parent_pid);
    }
}

/// `kern.maxproc` (SYSCTL.md §§5-6), as FreeBSD's `fork1` applies it: processes (thread groups,
/// zombies included) at the limit refuse everyone with `EAGAIN`, and the last ten slots are
/// root's, so root can still log in and clean up. Then `RLIMIT_NPROC`: a caller whose real user
/// ID already has that many processes gets `EAGAIN` too, unless it is the superuser.
fn check_maxproc() -> Result<(), u64> {
    let max = *crate::kern::kern_sysctl::MAXPROC.lock() as usize;
    let caller_pid = scheduler::current_pid();
    let table = PROCESS_TABLE.lock();
    let nprocs = table.values().filter(|p| p.pid == p.tgid).count();
    let Some(me) = table.get(&caller_pid) else {
        return Ok(());
    };
    let cred = me.shared.lock().cred.clone();
    let root = cred.privileged();
    if nprocs >= max || (!root && nprocs + 10 >= max) {
        return Err(crate::syscall::EAGAIN);
    }
    let nproc_limit = me.rlimits[super::limits::RLIMIT_NPROC].0;
    if !root && nproc_limit != super::limits::RLIM_INFINITY {
        let mine = table
            .values()
            .filter(|p| p.pid == p.tgid && p.shared.lock().cred.ruid == cred.ruid)
            .count() as u64;
        if mine >= nproc_limit {
            return Err(crate::syscall::EAGAIN);
        }
    }
    Ok(())
}

fn fork_impl(kind: ForkKind) -> Result<u64, u64> {
    let caller_pid = scheduler::current_pid();
    let parent_frame = syscall::current_frame() as *const SyscallFrame;
    let phys_offset = memory::phys_mem_offset();
    check_maxproc()?;

    let child_pid = alloc_pid();
    let (
        child_address_space,
        parent_space,
        child_shared,
        parent_fs_base,
        parent_pgid,
        parent_sid,
        parent_blocked_signals,
        parent_signal_stack,
        parent_altstack,
        parent_comm,
        (parent_cmdline, parent_environ),
        parent_rlimits,
        parent_nice,
        parent_sched_policy,
        parent_sched_priority,
        parent_fpu_state,
    ) = {
        let mut table = PROCESS_TABLE.lock();
        let parent = table
            .get_mut(&caller_pid)
            .expect("fork: current process missing from table");
        // `.expect()`: the live, currently-running caller of a syscall always has Some -- only a
        // Zombie ever has None, and a Zombie can't be mid-syscall.
        let parent_space = parent.address_space.as_ref().expect("fork: caller has no address space");
        // A vfork child borrows the table (and its `VmState`), as a thread does.
        // SAFETY: AddressSpace::fork requires self to be the currently active address space --
        // true here, since sys_fork runs synchronously on the calling process's own kernel stack
        // with its own CR3 still live.
        let child_address_space = if kind.borrows() {
            Ok(parent_space.share())
        } else {
            with_frame_allocator(|fa| parent_space.fork(phys_offset, fa))
        };
        // Real ENOMEM, not a kernel panic, on real frame exhaustion mid-copy -- see
        // AddressSpace::build_from_active's own doc comment. Nothing to tear down on this
        // particular path (unlike the matching KernelStack::new failure below): a failed `fork()`
        // already freed everything it allocated internally before returning `Err` here.
        let Ok(child_address_space) = child_address_space else {
            return Err(ENOMEM);
        };
        // fork() semantics for the `ThreadGroupShared` fields: cwd/root/umask/cred are
        // copied (a forked child is a process of its own, with its own ThreadGroupShared, never
        // the parent's -- sharing it is do_clone's CLONE_THREAD behaviour). The memory bookkeeping
        // goes with the address space instead (`mm::VmState`, filled by `inherit_vm_for_fork`).
        let child_shared = {
            let parent_shared = parent.shared.lock();
            Arc::new(Mutex::new(ThreadGroupShared {
                cwd: crate::kern::vfs_subr::vref_raw(parent_shared.cwd),
                root: crate::kern::vfs_subr::vref_raw(parent_shared.root),
                umask: parent_shared.umask,
                cred: parent_shared.cred.clone(),
                // Real fork() semantics: signal disposition is copied (see ThreadGroupShared::
                // sigactions's own doc comment for why this field lives here, not on Process).
                sigactions: parent_shared.sigactions,
                oom_adj: parent_shared.oom_adj,
            }))
        };
        (
            child_address_space,
            // A second handle on the parent's table, only to read its `VmState` once the table
            // lock is dropped (`inherit_vm_for_fork` takes the shm and mmap locks).
            parent_space.share(),
            child_shared,
            parent.fs_base,
            parent.pgid,
            parent.sid,
            // Real fork() semantics: signal disposition and the blocked-signal mask are
            // inherited; pending signals are not (the child starts with an empty pending set —
            // see the child's own construction below). signal_stack is inherited too, in case the
            // parent forked from inside one or more handlers — the child gets its own independent
            // copy of that same in-progress-handler bookkeeping (each entry is plain data, no
            // pointers into the parent's own address space beyond what `saved` already carries).
            parent.blocked_signals,
            parent.signal_stack.clone(),
            // Real fork() semantics: the alt stack's own address stays valid in the child (the
            // whole address space is duplicated) -- see AltStack's own doc comment.
            parent.altstack,
            // Real fork() semantics: the child keeps the parent's comm/cmdline until it execs its
            // own -- same reasoning as brk/fs_base/cwd above.
            parent.comm.clone(),
            (parent.cmdline.clone(), parent.environ.clone()),
            // Real POSIX rlimit/nice/scheduling-attribute/fork semantics: all four are copied,
            // same as uid/gid/pgid -- see Process::rlimits's own doc comment.
            parent.rlimits,
            parent.nice,
            parent.sched_policy,
            parent.sched_priority,
            // Real fork() semantics: the child's own FPU/SSE register state starts as an exact
            // copy of the parent's live state at the moment of the fork() call (the parent's own
            // in-flight computation, if any, is a real thing the child should see too) -- same
            // "copied, not reset" treatment as uid/gid/rlimits above.
            parent.fpu_state,
        )
    };

    let Ok(kernel_stack) = KernelStack::new() else {
        // child_address_space was already built above (a real, freshly-allocated deep copy via
        // AddressSpace::fork) and would otherwise leak permanently -- nothing else references it
        // yet (it was never installed into the process table or activated as CR3), so tearing it
        // down here is safe and required to avoid trading this panic for a silent frame leak.
        // SAFETY: child_address_space's level 4 frame was never activated (CR3 never switched to
        // it) -- exactly teardown's own safety requirement.
        unsafe {
            with_frame_allocator(|fa| child_address_space.teardown(phys_offset, fa));
        }
        return Err(ENOMEM);
    };
    let kernel_stack_top = kernel_stack.top();
    if !kind.borrows() {
        mm::inherit_vm_for_fork(&parent_space, &child_address_space);
    }
    drop(parent_space);
    // SAFETY: parent_frame is the caller's own live SyscallFrame, valid for the duration of this
    // call (we're still inside sys_fork's/sys_clone's own handling of it).
    let rsp = unsafe {
        match kind {
            ForkKind::VforkClone(new_rsp) => crate::process::context_switch::seed_clone_frame(
                kernel_stack_top,
                parent_frame,
                new_rsp,
            ),
            ForkKind::Fork | ForkKind::Vfork => {
                crate::process::context_switch::seed_fork_frame(kernel_stack_top, parent_frame)
            }
        }
    };

    let child = Process {
        pid: child_pid,
        // A forked child is a real POSIX process, not a thread -- its own tgid, never the
        // parent's. See Process::tgid's own doc comment.
        tgid: child_pid,
        parent: Some(caller_pid),
        children: Vec::new(),
        state: ProcState::Ready,
        address_space: Some(child_address_space),
        kernel_stack,
        kernel_stack_top,
        rsp,
        entry_point: VirtAddr::zero(),
        user_stack_top: VirtAddr::zero(),
        shared: child_shared,
        fs_base: parent_fs_base,
        start_ticks: crate::cpu::interrupts::ticks(),
        // Not inherited -- a forked child was never itself the target of a clone(2) call, see
        // Process::clear_child_tid's own doc comment.
        clear_child_tid: 0,
        pending_signals: 0,
        blocked_signals: parent_blocked_signals,
        signal_stack: parent_signal_stack,
        altstack: parent_altstack,
        // Not inherited -- see Process::on_altstack's own doc comment.
        on_altstack: false,
        // Not inherited -- see Process::preempted_resume's own doc comment.
        preempted_resume: None,
        estcpu: 0,
        pgid: parent_pgid,
        sid: parent_sid,
        comm: parent_comm,
        cmdline: parent_cmdline,
        environ: parent_environ,
        // Not inherited -- see `real_timer_deadline`'s own doc comment (real POSIX itimer/fork
        // semantics: a forked child starts with its own disarmed timer).
        real_timer_deadline: None,
        real_timer_interval_ticks: 0,
        // Not inherited either -- see `Process::posix_timers`'s own doc comment (real
        // `timer_create(2)` semantics: not inherited across `fork`).
        posix_timers: [None; MAX_POSIX_TIMERS],
        rlimits: parent_rlimits,
        nice: parent_nice,
        sched_policy: parent_sched_policy,
        sched_priority: parent_sched_priority,
        // A forked child is never born stopped, and hasn't just resumed from anything -- real
        // POSIX fork() semantics, same "starts fresh" story as real_timer_deadline above.
        stop_notify_pending: false,
        cont_notify_pending: false,
        // Never straddles a fork boundary -- see this field's own doc comment on Process.
        sigsuspend_restore_mask: None,
        // Not inherited -- see this field's own doc comment (real SysV semadj/fork semantics).
        sysv_sem_undo: Vec::new(),
        // Not inherited -- see this field's own doc comment (pending_signals itself starts at 0
        // for a forked child too, so there's nothing meaningful to carry over).
        pending_siginfo: [QueuedSigInfo::default(); 35],
        // Not inherited -- same reasoning as pending_siginfo above.
        rt_queue: core::array::from_fn(|_| Vec::new()),
        fpu_state: parent_fpu_state,
        // Not inherited -- real POSIX: a forked child's own CPU time starts at 0, it hasn't run
        // yet (see this field's own doc comment on Process).
        cpu_ticks: 0,
        minflt: 0,
        majflt: 0,
        sys_ticks: 0,
        // Not inherited -- a fresh child hasn't reaped any children of its own yet (see this
        // field's own doc comment on Process).
        child_cpu_ticks: 0,
        child_sys_ticks: 0,
        // A fresh process/thread always starts with a full quantum -- see `Process::
        // quantum_ticks_left`'s own doc comment.
        quantum_ticks_left: crate::cpu::interrupts::PREEMPT_QUANTUM_TICKS,
        off_cpu_cycles: 0,
        switched_out_at: 0,
        // No cascade in progress for a process that hasn't run yet -- see `Process::
        // cascade_budget`'s own doc comment.
        cascade_budget: None,
        tty_timed_out: false,
        vfork_parent: kind.borrows().then_some(caller_pid),
    };

    {
        let mut table = PROCESS_TABLE.lock();
        table.get_mut(&caller_pid).unwrap().children.push(child_pid);
        table.insert(child_pid, Box::new(child));
    }
    // Real fork() semantics: the child gets its own independently-closable copy of every fd the
    // parent's own thread group currently has open, not a shared view of those table entries --
    // see crate::fs::fd::fork_inherit's own doc comment for why this specifically matters for
    // pipes. Sourced from the caller's tgid, not raw caller_pid -- the fd table is tgid-scoped
    // (real CLONE_FILES sharing) -- though the two are identical until a real `clone(2)`-created
    // thread can fork. child_pid is used unchanged as the destination key: a forked child is
    // always its own fresh thread group of one (Process::tgid == its own pid), never inheriting
    // the parent's tgid.
    crate::fs::fd::fork_inherit(scheduler::current_tgid(), child_pid);
    scheduler::enqueue_ready(child_pid);
    if kind.borrows() {
        // The child runs in this address space now: sleep until it execs or exits
        // (`vfork_release`). Re-checked after every wake: a stop and continue makes this Ready
        // early. A fatal signal ends the process here, in its sleep.
        loop {
            {
                let mut table = PROCESS_TABLE.lock();
                if !table.get(&child_pid).is_some_and(|c| c.vfork_parent == Some(caller_pid)) {
                    break;
                }
                if let Some(me) = table.get_mut(&caller_pid) {
                    me.state = ProcState::Blocked(BlockReason::WaitingForVforkChild(child_pid));
                }
            }
            scheduler::schedule();
        }
    }
    Ok(child_pid)
}

/// Real `clone(2)`'s own bit values (`external/mit/musl/include/sched.h`, unremapped -- real Linux's
/// own numbers, confirmed against `pthread_create.c`'s real call site). `do_clone` below only ever
/// accepts the *exact* combination real `pthread_create` issues -- see that function's own doc
/// comment for why a flag-by-flag general implementation isn't attempted.
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_DETACHED: u64 = 0x0040_0000;
const PTHREAD_CLONE_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED;

/// The second (and, for now, only other) accepted flag combination -- real `vfork()`-via-`clone()`,
/// exactly what `musl`'s own `posix_spawn()` issues (`external/mit/musl/src/process/posix_spawn.c`).
/// See `do_vfork_clone`'s own doc comment for the real consumer this was found through.
const CLONE_VFORK: u64 = 0x0000_4000;
const SIGCHLD: u64 = 17;
const VFORK_CLONE_FLAGS: u64 = CLONE_VM | CLONE_VFORK | SIGCHLD;

/// `SYS_CLONE`'s real logic -- real `pthread_create()`'s own kernel-facing half. `pthread_join`
/// itself needs no kernel support: it's pure userspace futex logic against the child's own
/// `detach_state`, already fully backed by phase 3's real `futex(2)` once both threads share a
/// `tgid`. **But real `CLONE_CHILD_CLEARTID` support genuinely is needed anyway** -- found live,
/// not predicted: real musl's own `pthread_create.c` sets `ctid` to `&__thread_list_lock`, and
/// `__pthread_exit`'s own comment explains why that lock's release is deliberately routed through
/// this exact kernel mechanism rather than a plain userspace unlock (the change must not become
/// visible to other threads until *after* the exiting thread's real `SYS_exit`, which only a real
/// kernel-driven clear-and-wake at true task-exit time can guarantee) -- see `Process::
/// clear_child_tid`'s own doc comment for the full story, and `terminate_process` below for where
/// the real write-zero-and-wake actually happens. Only the *exact* flag combination real
/// `pthread_create` issues is accepted (`PTHREAD_CLONE_FLAGS` above) -- `EINVAL` otherwise, same
/// "support the one real shape a live caller needs" discipline `do_mmap`/`mount`/`msgrcv` already
/// established; a real general-purpose `clone(2)` (arbitrary flag subsets, `vfork`-shaped calls,
/// process-creating `clone` without `CLONE_THREAD`, ...) is out of scope.
///
/// `newsp`/`ptid`/`ctid` arrive through the normal 4-argument `dispatch()` path (`rdi`/`rsi`/`rdx`/
/// `r10`, real `clone.s`'s own register shuffle) alongside `flags`. `tls` (in `r8`) doesn't fit
/// this ABI's 4-register convention at all, so it's read directly off the live frame (`syscall::
/// frame_tls`) -- the same raw-frame-access route `sys_fork`/`sys_execve` already use, needed here
/// regardless since `do_clone` also needs the whole raw parent frame to seed the child's own
/// initial state.
///
/// **The real `CLONE_THREAD` sharing**: `address_space` = `parent.address_space.share()` (an
/// `Arc::clone` of the level 4 table, `memory::address_space::AddressSpace::share`'s own doc
/// comment) -- a write through either thread's own mapping is genuinely visible through the
/// other's, real `CLONE_VM`. `shared` = `Arc::clone(&parent.shared)` -- the new thread sees (and
/// can mutate) the exact same `cwd`/`root_inode`/`umask`/`uid`/`gid`/`brk`/`mmap_file_regions` the
/// caller does, real `CLONE_FS`/(the uid/gid/umask half of what a real process shares). `tgid` is
/// the caller's own, not a fresh allocation (real `CLONE_THREAD`: `getpid()` reports the same
/// value from every thread in the group -- see `Process::tgid`'s own doc comment, written for
/// exactly this line). `crate::fs::fd::fork_inherit` below (despite the name -- the same function
/// `do_fork_from_current` already uses) copies the caller's *current* fd table into the child's
/// own tgid-keyed slot, real `CLONE_FILES`: from that point on both tgids alias the exact same
/// `real_fd`s (see `crate::fs::fd`'s own module doc comment on `real_fd`+refcounting).
///
/// Everything else mirrors `do_fork_from_current`'s own field-by-field policy for state that isn't
/// now-shared: kernel stack and FPU state fresh/copied the same way; signal mask/`sigactions`
/// copied (real `CLONE_SIGHAND`); `pending_signals`/`signal_stack`/`altstack`/itimers/posix-timers
/// start empty/disarmed, same as a forked child; `rlimits`/`nice`/`sched_policy`/`sched_priority`
/// copied. **Not added to the caller's own `children` list, and never wait4-reapable** -- a real
/// `CLONE_THREAD` child is never an independent `wait4` target (`pthread_join` doesn't go through
/// `wait4` at all -- see this function's own doc comment above); `process::lifecycle::
/// terminate_process`'s own tgid-aware exit handling (a later addition, see its own doc comment)
/// is what actually reaps a non-leader thread instead.
pub fn do_clone(flags: u64, newsp: u64, ptid: u64, ctid: u64) -> Result<u64, u64> {
    if flags == VFORK_CLONE_FLAGS {
        return do_vfork_clone(newsp);
    }
    if flags != PTHREAD_CLONE_FLAGS {
        return Err(EINVAL);
    }
    let caller_pid = scheduler::current_pid();
    let parent_frame = syscall::current_frame() as *const SyscallFrame;
    // SAFETY: parent_frame is this exact syscall's own live frame (do_clone is only ever reached
    // through dispatch(SYS_CLONE, ...), called from syscall_dispatch, which set CURRENT_FRAME to
    // it just before) -- the same precondition do_fork_from_current's identical read already
    // relies on.
    let tls = unsafe { syscall::frame_tls(parent_frame) };

    let child_pid = alloc_pid();
    let (
        child_address_space,
        child_shared,
        tgid,
        parent_field,
        parent_pgid,
        parent_sid,
        parent_blocked_signals,
        parent_signal_stack,
        parent_altstack,
        parent_comm,
        (parent_cmdline, parent_environ),
        parent_rlimits,
        parent_nice,
        parent_sched_policy,
        parent_sched_priority,
        parent_fpu_state,
    ) = {
        let table = PROCESS_TABLE.lock();
        let caller = table
            .get(&caller_pid)
            .expect("clone: current process missing from table");
        (
            // Real CLONE_VM: an Arc::clone of the exact same level 4 table, not a fresh copy --
            // see AddressSpace::share's own doc comment. `.expect()`: same reasoning as
            // do_fork_from_current's identical call -- the live caller always has Some.
            caller
                .address_space
                .as_ref()
                .expect("clone: caller has no address space")
                .share(),
            // Real CLONE_THREAD sharing: the new thread gets the exact same
            // cwd/root/umask/uid/gid/brk/mmap_file_regions Arc, not its own copy -- see
            // ThreadGroupShared's own doc comment.
            Arc::clone(&caller.shared),
            // Real CLONE_THREAD: getpid() reports the same value from every thread sharing this
            // tgid -- see Process::tgid's own doc comment.
            caller.tgid,
            caller.parent,
            caller.pgid,
            caller.sid,
            caller.blocked_signals,
            caller.signal_stack.clone(),
            caller.altstack,
            caller.comm.clone(),
            (caller.cmdline.clone(), caller.environ.clone()),
            caller.rlimits,
            caller.nice,
            caller.sched_policy,
            caller.sched_priority,
            caller.fpu_state,
        )
    };

    // Unlike do_fork_from_current's identical failure path, no teardown is needed here on
    // failure: child_address_space above is a real CLONE_VM AddressSpace::share -- a plain
    // Arc::clone, not a fresh deep copy -- so dropping it here (via early return) just decrements
    // that Arc's refcount back to where it was, no frames allocated, nothing to free.
    let Ok(kernel_stack) = KernelStack::new() else {
        return Err(ENOMEM);
    };
    let kernel_stack_top = kernel_stack.top();
    // SAFETY: parent_frame is valid per the same reasoning as the frame_tls read above; newsp is
    // the caller's own real clone(2) argument, already validated to be a real user-space stack
    // pointer by musl's own __clone asm before this syscall is ever issued.
    let rsp = unsafe {
        crate::process::context_switch::seed_clone_frame(kernel_stack_top, parent_frame, newsp)
    };

    let child = Process {
        pid: child_pid,
        tgid,
        parent: parent_field,
        children: Vec::new(),
        state: ProcState::Ready,
        address_space: Some(child_address_space),
        kernel_stack,
        kernel_stack_top,
        rsp,
        entry_point: VirtAddr::zero(),
        user_stack_top: VirtAddr::zero(),
        shared: child_shared,
        // Real CLONE_SETTLS: this thread's own IA32_FS_BASE, distinct from every sibling's --
        // never copied from the caller (see Process::fs_base's own doc comment).
        fs_base: tls,
        start_ticks: crate::cpu::interrupts::ticks(),
        // Real CLONE_CHILD_CLEARTID -- see Process::clear_child_tid's own doc comment.
        clear_child_tid: ctid,
        pending_signals: 0,
        blocked_signals: parent_blocked_signals,
        signal_stack: parent_signal_stack,
        altstack: parent_altstack,
        // Not inherited -- see Process::on_altstack's own doc comment.
        on_altstack: false,
        // Not inherited -- see Process::preempted_resume's own doc comment.
        preempted_resume: None,
        estcpu: 0,
        pgid: parent_pgid,
        sid: parent_sid,
        comm: parent_comm,
        cmdline: parent_cmdline,
        environ: parent_environ,
        // Not inherited -- same "starts fresh" policy do_fork_from_current's own construction
        // already establishes for these two fields.
        real_timer_deadline: None,
        real_timer_interval_ticks: 0,
        posix_timers: [None; MAX_POSIX_TIMERS],
        rlimits: parent_rlimits,
        nice: parent_nice,
        sched_policy: parent_sched_policy,
        sched_priority: parent_sched_priority,
        stop_notify_pending: false,
        cont_notify_pending: false,
        sigsuspend_restore_mask: None,
        sysv_sem_undo: Vec::new(),
        pending_siginfo: [QueuedSigInfo::default(); 35],
        rt_queue: core::array::from_fn(|_| Vec::new()),
        fpu_state: parent_fpu_state,
        cpu_ticks: 0,
        minflt: 0,
        majflt: 0,
        sys_ticks: 0,
        // A `clone(2)`-created thread never becomes an independent `wait4` target (see
        // `do_clone`'s own doc comment) and never reaps children of its own -- starts at 0, same
        // reasoning as `do_fork_from_current`'s own copy of this field.
        child_cpu_ticks: 0,
        child_sys_ticks: 0,
        // A fresh process/thread always starts with a full quantum -- see `Process::
        // quantum_ticks_left`'s own doc comment.
        quantum_ticks_left: crate::cpu::interrupts::PREEMPT_QUANTUM_TICKS,
        off_cpu_cycles: 0,
        switched_out_at: 0,
        // No cascade in progress for a process that hasn't run yet -- see `Process::
        // cascade_budget`'s own doc comment.
        cascade_budget: None,
        tty_timed_out: false,
        vfork_parent: None,
    };

    {
        let mut table = PROCESS_TABLE.lock();
        // Deliberately not pushed into caller's own `children` -- see this function's own doc
        // comment on why a CLONE_THREAD child is never an independent wait4 target.
        table.insert(child_pid, Box::new(child));
        // Real race closed here -- see `Process::quantum_ticks_left`'s own doc comment. Give the
        // caller a fresh, full quantum right as its new child becomes schedulable (below), so any
        // immediate follow-up work (a `pthread_join`/`pthread_detach` racing the new thread's own
        // exit, the shape that exposed this) gets a real, guaranteed window to finish before the
        // brand-new child -- which does no real work here yet -- could possibly preempt it.
        if let Some(me) = table.get_mut(&caller_pid) {
            me.quantum_ticks_left = crate::cpu::interrupts::PREEMPT_QUANTUM_TICKS;
        }
    }
    // Real CLONE_FILES: unlike do_fork_from_current, no explicit fs::fd::fork_inherit call is
    // needed here at all -- the child's own tgid is the same as the caller's (set above), and
    // crate::fs::fd's own table is keyed by tgid, not raw pid, so every fd lookup the child ever
    // makes (via scheduler::current_tgid()) already resolves to the exact same entries the caller
    // sees, real aliasing, not a copy -- see crate::fs::fd's own module doc comment.
    // CLONE_PARENT_SETTID: the child's id, a `pid_t` (4 bytes: it used to be written as 8, over
    // whatever followed, `struct pthread`'s `errno_val` in musl's `pthread_create`), only when
    // asked for. A bad pointer is ignored, as on Linux: the thread exists either way.
    if flags & CLONE_PARENT_SETTID != 0 && ptid != 0 {
        let _ = copyout_val(&(child_pid as i32), UserPtr::new(ptid));
    }
    scheduler::enqueue_ready(child_pid);
    Ok(child_pid)
}

/// `sys_execve`'s real logic. Reuses `syscall::dispatch` directly to drive an internal
/// open/read-loop/close against whatever `path_ptr`/`path_len` (the caller's own user-space
/// pointer, still valid since the caller's address space is what's currently active) names —
/// exactly the same fd/fat32 machinery `stsh`'s `cat` already exercises through the public
/// syscall path. Every fallible step (open, each read, close, `Elf::parse`, the new
/// `AddressSpace`, `elf::load`, mapping the user stack) completes *before* any mutation of the
/// live syscall frame, `CR3`, or the process's stored `AddressSpace` — real `execve(2)` semantics:
/// a failure at any point must leave the calling program completely untouched.
/// Wire format for `SYS_EXECVE`'s optional third and fourth arguments (`argv_ptr`/`envp_ptr`) --
/// OxideBSD's own invention, not modeled on real `execve`'s NUL-terminated `char **argv`/`char
/// **envp` (this ABI's syscalls are length-prefixed throughout instead -- see CLAUDE.md's syscall
/// ABI section). A sequence of these structs, terminated by a `ptr == 0` entry, describes either
/// argv[] or envp[] (same shape, read the same way -- see `read_ptr_len_array` below).
/// `argv_ptr == 0` (or a non-null `argv_ptr` whose very first entry is already the `{0, 0}`
/// terminator) falls back to a synthesized one-element `argv = [path_bytes]`, matching real
/// `execve`'s convention that `argv[0]` always exists even when the caller passes an empty/absent
/// array -- every caller before `stsh`'s own execve wrapper grew argument support relied on
/// exactly this fallback, and keeps doing so unaffected. **A non-empty `argv_ptr` supplies the
/// *complete* array, including `argv[0]` -- it is no longer implicitly `path_bytes` glued onto
/// `argv_ptr`'s own contents.** This matches real `execve(2)` semantics (the caller chooses
/// `argv[0]`, which need not equal the path used to find the file at all -- e.g. a login shell's
/// `argv[0]` of `-bash`) and is what makes real multi-call-binary dispatch (a `busybox`-style
/// binary picking an applet by `argv[0]`/basename) possible at all; it used to be silently
/// unreachable, since `do_execve` always overwrote `argv[0]` with the exec path itself regardless
/// of what a real caller supplied. `envp_ptr` is `R10`, the ABI's 4th argument -- see
/// `sys/syscall.rs`'s module doc comment for why that register only became a real, read argument
/// once this needed it.
#[derive(Clone, Copy)]
#[repr(C)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

// SAFETY: two u64s, no padding.
unsafe impl Pod for RawArgvEntry {}

/// Bounded as a sanity cap against a runaway/garbage `argv_ptr`/`envp_ptr`, not a deliberate
/// argument/environment-count limit. Raised 32 -> 256 for the real on-target Clang/LLVM port (see
/// CLAUDE.md's Clang/LLVM port section): a real `clang -cc1` invocation for even a trivial `hello.c`
/// already carries ~25 tokens (resource-dir/sysroot/isystem flags alone), and `ld.lld`'s own
/// internal invocation adds more per extra object file/library -- 32 was already close to
/// insufficient for the simplest real case.
const MAX_PTR_LEN_ENTRIES: usize = 256;

/// Total bytes of argv + envp strings one `execve` may carry -- Linux's effective limit (a quarter
/// of an 8 MiB stack), not musl's advertised `ARG_MAX` (128 KiB), which a real `ld.lld` link line
/// for a large project can exceed. Past it is a real `E2BIG`. Found live: before this cap, a
/// garbage `len` (a `char **` argv passed where this ABI expects `RawArgvEntry`s -- an early
/// `fexecve` patch did exactly that) went straight into an allocation and panicked the kernel
/// (`memory allocation of 4923351820889817167 bytes failed`) -- any process could take the whole
/// VM down with one bad `execve`.
pub(crate) const MAX_EXEC_ARG_BYTES: u64 = 2 * 1024 * 1024;

/// Reads the `RawArgvEntry` array `ptr` describes, if any -- shared by `argv_ptr` (argv[1..]) and
/// `envp_ptr` (envp[]), which use the exact same wire format (see `RawArgvEntry`'s own doc
/// comment). `budget` is the remaining `MAX_EXEC_ARG_BYTES`, shared across both arrays.
fn read_ptr_len_array(ptr: u64, budget: &mut u64) -> Result<Vec<Vec<u8>>, u64> {
    let mut entries_out = Vec::new();
    if ptr == 0 {
        return Ok(entries_out);
    }
    for i in 0..MAX_PTR_LEN_ENTRIES {
        let entry: RawArgvEntry = copyin_val(UserPtr::new(ptr).add(i as u64 * 16))?;
        if entry.ptr == 0 {
            break;
        }
        *budget = budget.checked_sub(entry.len).ok_or(E2BIG)?;
        // Already within `budget`, so this bound never bites.
        entries_out.push(copyin_vec(UserPtr::new(entry.ptr), entry.len as usize, usize::MAX, E2BIG)?);
    }
    Ok(entries_out)
}

/// Tail of `path` after its last `/` (the whole slice if there's none) -- used to derive
/// `Process::comm` from the path `execve`/`spawn` actually loaded, matching real Linux's own
/// "comm comes from the executable's filename, not argv[0]" rule.
fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Real `/proc/[pid]/cmdline` wire format: each `argv` entry followed by one NUL byte, no
/// trailing separator beyond that.
fn build_cmdline<T: AsRef<[u8]>>(argv: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    for arg in argv {
        out.extend_from_slice(arg.as_ref());
        out.push(0);
    }
    out
}

/// The kernel's open of a path in kernel memory (`kern::vfs_syscalls::kern_open`, BSD's `namei`
/// with `UIO_SYSSPACE`): a held file's handle, not an fd.
fn kernel_open_path(path: &[u8]) -> Result<u64, u64> {
    crate::kern::vfs_syscalls::kern_open(path).map_err(|e| e as u64)
}

/// Opens a program for `exec_image` and reads its head (`ExecFile`), given the kernel's own copy of
/// its path (a top-level `execve` target, or a `#!`/`PT_INTERP` interpreter parsed out of a file).
fn open_exec_file(path: &[u8]) -> Result<ExecFile, u64> {
    read_exec_head_and_release(kernel_open_path(path)?)
}

/// A whole program, read from the root file system by path, for the kernel to start as pid 1
/// (`init::start`; FreeBSD execs it inside process 1, `start_init`). The buffer is the caller's,
/// dropped once the image is mapped. `ENOEXEC` for anything but a non-empty oxfs file.
pub(crate) fn read_program(path: &[u8]) -> Result<Vec<u8>, u64> {
    let handle = kernel_open_path(path)?;
    let read = || -> Result<Vec<u8>, u64> {
        let content = crate::fs::fd::content_id_of_handle(handle).ok_or(ENOEXEC)?;
        let size = u64::try_from(crate::fs::fd::content_size(content)).map_err(|_| ENOEXEC)?;
        if size == 0 {
            return Err(ENOEXEC);
        }
        let mut image = alloc::vec![0u8; size as usize];
        if crate::fs::fd::content_read(content, 0, image.as_mut_ptr() as u64, size) != size as i64 {
            return Err(EIO);
        }
        Ok(image)
    };
    let result = read();
    crate::fs::fd::release(handle);
    result
}

/// `open_exec_file`, but opened through `SYS_OPENAT` with the caller's own `RawAtPath` --
/// `execveat`'s dirfd-relative (and `AT_SYMLINK_NOFOLLOW`) target -- as a file the kernel holds.
fn open_exec_file_at(at_ptr: u64, nofollow: bool) -> Result<ExecFile, u64> {
    const O_NOFOLLOW: u64 = 0o400000;
    let flags = if nofollow { O_NOFOLLOW } else { 0 };
    let handle = crate::fs::fd::kernel_open(|| match syscall::dispatch(SYS_OPENAT, at_ptr, flags, 0, 0) {
        Ok(h) => h as i64,
        Err(e) => -(e as i64),
    });
    if handle < 0 {
        return Err(-handle as u64);
    }
    read_exec_head_and_release(handle as u64)
}

/// How much one `read` asks for while loading an executable. Large, because the per-call cost
/// is what matters: at 512 bytes, exec of a 100 MB program (clang) took ~200,000 calls, and a
/// `configure` running the compiler dozens of times took minutes. The buffer is the result
/// itself, on the heap, never the kernel stack.
const EXEC_READ_CHUNK: usize = 1 << 20;

/// Reads file `handle` to its end into one buffer, with `read` (`pread == false`, from its offset)
/// or `pread` from offset 0, which leaves the caller's own offset alone.
fn read_fd_to_end(handle: u64, pread: bool) -> Result<Vec<u8>, u64> {
    let mut bytes: Vec<u8> = Vec::new();
    loop {
        // Straight into the spare capacity: no zero-filling first, which in the unoptimized
        // kernel build is a per-byte loop (measured: it made exec slower than the 512-byte reads).
        let len = bytes.len();
        bytes.reserve(EXEC_READ_CHUNK);
        let buf = bytes.spare_capacity_mut().as_mut_ptr() as u64;
        // A kernel-segment transfer: the buffer is the kernel's (USERMEM.md §4.4).
        use crate::kern::subr_uio::{FOF_OFFSET, IoSeg, Uio, UioRw, UioSeg};
        let seg = alloc::vec![IoSeg { base: buf, len: EXEC_READ_CHUNK as u64 }];
        let mut uio = Uio::new(seg, UioRw::Read, UioSeg::Kernel, len as u64)?;
        let flags = if pread { FOF_OFFSET } else { 0 };
        let raw = crate::fs::fd::read_handle(handle, &mut uio, flags).ok_or(EBADF)?;
        if raw < 0 {
            return Err(-raw as u64);
        }
        let n = raw as usize;
        if n == 0 {
            return Ok(bytes);
        }
        // SAFETY: the read wrote `n` (at most EXEC_READ_CHUNK, all reserved) bytes there.
        unsafe { bytes.set_len(len + n.min(EXEC_READ_CHUNK)) };
    }
}



/// What `exec_image` reads of a program before loading it: its head (`#!` line, or ELF and
/// program headers), and the file the rest is read from, a page at a time and only where a
/// page isn't mapped from the page cache. A file not on oxfs is read whole into `head`.
struct ExecFile {
    head: Vec<u8>,
    size: u64,
    content: Option<u64>,
    /// Mode bits, owner and group, for set-user-ID and set-group-ID (`identity::Cred::exec`);
    /// the set-ID bits are already cleared under a `nosuid` mount. `None` off oxfs.
    setid: Option<(u32, u32, u32)>,
    /// Whether the program is under a `wxallowed` mount (`mm::check_wx`).
    wxallowed: bool,
}

impl Drop for ExecFile {
    fn drop(&mut self) {
        if let Some(vp) = self.content {
            crate::kern::vfs_subr::vrele_deferred(vp as *mut vfs_if::Vnode);
        }
    }
}

impl ExecFile {
    fn whole(image: Vec<u8>) -> Self {
        ExecFile { size: image.len() as u64, head: image, content: None, setid: None, wxallowed: false }
    }
}

/// How much of a program `exec_image` reads up front: the ELF and program headers of anything
/// our toolchains link fit in the first page, and the `#!` line too.
const EXEC_HEAD: u64 = 4096;

/// musl's `ETXTBSY`: a program open for writing, or a running program opened for writing.
const ETXTBSY: u64 = 26;

fn read_exec_head_and_release(handle: u64) -> Result<ExecFile, u64> {
    let result = read_exec_head(handle, false);
    crate::fs::fd::release(handle);
    result
}

/// Reads the head of file `handle` for `exec_image`, never moving its offset unless it isn't on
/// oxfs and `pread` is false.
fn read_exec_head(handle: u64, pread: bool) -> Result<ExecFile, u64> {
    let content = crate::fs::fd::content_id_of_handle(handle);
    let size = content.map_or(-1, crate::fs::fd::content_size);
    let (Some(content), Ok(size)) = (content, u64::try_from(size)) else {
        return read_fd_to_end(handle, pread).map(ExecFile::whole);
    };
    // A program open for writing can't run (`ETXTBSY`, as on the BSDs).
    // SAFETY: the open file holds the vnode.
    if unsafe { (*(content as *mut vfs_if::Vnode)).v_writecount } > 0 {
        return Err(ETXTBSY);
    }
    let (setid, wxallowed) = match crate::fs::fd::exec_setid_handle(handle) {
        // Nothing on a `noexec` mount runs, as on the BSDs.
        Some((_, _, true)) => return Err(EACCES),
        Some((setid, wxallowed, false)) => (Some(setid), wxallowed),
        None => (None, false),
    };
    let read = |len: u64| -> Result<Vec<u8>, u64> {
        let mut head = alloc::vec![0u8; len as usize];
        if crate::fs::fd::content_read(content, 0, head.as_mut_ptr() as u64, len) != len as i64 {
            return Err(EIO);
        }
        Ok(head)
    };
    let mut head = read(size.min(EXEC_HEAD))?;
    // Program headers past the first page: read up to their end (a sane bound, else ENOEXEC
    // from `Elf::parse_file`).
    if head.len() >= 64 && head[..4] == *b"\x7fELF" {
        let phoff = u64::from_le_bytes(head[32..40].try_into().unwrap());
        let phsize = u64::from(u16::from_le_bytes([head[54], head[55]]))
            * u64::from(u16::from_le_bytes([head[56], head[57]]));
        let end = phoff.saturating_add(phsize);
        if end > head.len() as u64 && end <= size.min(1 << 20) {
            head = read(end)?;
        }
    }
    // Held by the `ExecFile` from here: the file is released before the image is mapped. Taken
    // last, so no early return above leaves it held.
    crate::kern::vfs_subr::vref(content as *mut vfs_if::Vnode);
    Ok(ExecFile { head, size, content: Some(content), setid, wxallowed })
}

/// The page cache entry for `file`'s pages, used by `space` from now on (PAGECACHE.md §3.1).
fn exec_cache_entry(file: &ExecFile, space: &AddressSpace) -> Option<crate::memory::pagecache::EntryId> {
    // The program runs here from now on (`ETXTBSY` for a writer, kept while running).
    space.vm().add_text(file.content?);
    let id = crate::memory::pagecache::entry_for(file.content?)?;
    space.use_cached(id);
    Some(id)
}

/// Leading/trailing ASCII-whitespace trim -- `core::slice` has no built-in for `&[u8]` the way
/// `str::trim` does.
fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Parses a `#!interpreter [optional-single-arg]` first line out of `bytes` (already confirmed to
/// start with `#!`) -- real Linux `binfmt_script` semantics: the interpreter path runs up to the
/// first whitespace, then *at most one* further whitespace-trimmed argument runs to the end of
/// the line (never further word-split, unlike a normal shell command line). An empty interpreter
/// (a bare `#!` with nothing else on the line) is reported as `None` -- `do_execve`'s own caller
/// turns that into `ENOEXEC`, matching real Linux's own refusal to exec a scriptless shebang.
fn parse_shebang_line(bytes: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    let line = trim_ascii_whitespace(&bytes[2..line_end]);
    let interpreter_end = line
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let interpreter = &line[..interpreter_end];
    if interpreter.is_empty() {
        return None;
    }
    let rest = trim_ascii_whitespace(&line[interpreter_end..]);
    let optional_arg = if rest.is_empty() {
        None
    } else {
        Some(rest.to_vec())
    };
    Some((interpreter.to_vec(), optional_arg))
}

/// Real Linux caps `#!`-chain recursion (a script whose own interpreter is itself another `#!`
/// script) rather than following it forever -- this kernel has no equivalent existing constant to
/// reuse (`sys/modules/oxfs`'s own `MAX_SYMLINK_DEPTH` lives in a separate, unlinkable module), so a
/// small, independently-chosen bound of the same shape.
const MAX_SHEBANG_DEPTH: u32 = 4;

/// Real, kernel-chosen runtime base for a `PT_INTERP` interpreter, added as `elf::load`'s `bias`
/// parameter (see that function's own doc comment for why this must be a real additive bias, not
/// a link-time-fixed address the interpreter file itself assumes). Clear of every existing fixed
/// userland load base (`0x8000000`-`0xff00000`, see every `regress/*/linker.ld`) and of
/// `module::MODULE_VA_BASE`/`BRK_REGION_CEILING` (`0x20000000`) -- picked once, reused for every
/// `PT_INTERP` load rather than per-binary, since nothing here needs more than one interpreter
/// image loaded at a time.
const INTERP_LOAD_BASE: u64 = 0x10000000; // was 0xc000000; +0x4000000, see module::MODULE_VA_BASE's own doc comment

pub fn do_execve(
    caller_pid: Pid,
    path_ptr: u64,
    path_len: u64,
    argv_ptr: u64,
    envp_ptr: u64,
) -> Result<u64, u64> {
    // Copied in now, while the caller's own address space (where path_ptr/argv_ptr/envp_ptr are
    // valid) is still active -- used for the new program's initial stack, built further down, by
    // which point a fresh (as-yet-unactivated) address space is what's live instead.
    let path_bytes = copyin_vec(UserPtr::new(path_ptr), path_len as usize, PATH_MAX, ENAMETOOLONG)?;
    exec_image(caller_pid, path_bytes, None, true, argv_ptr, envp_ptr)
}

/// Real `execveat(2)`: `at_ptr` is a `RawAtPath` (`{dirfd, path_ptr, path_len}`, see
/// `sys/modules/oxfs`'s "`*at()` family" section), `flags` takes `AT_EMPTY_PATH`/
/// `AT_SYMLINK_NOFOLLOW`. musl uses it for `fexecve(fd)` (`AT_EMPTY_PATH`, empty path).
///
/// `AT_FDCWD`/absolute without `AT_SYMLINK_NOFOLLOW` is exactly `execve`. Anything else reads the
/// first image up front -- through `SYS_OPENAT`, or `pread` on the fd itself for `AT_EMPTY_PATH`.
/// Known limit: when that image is a `#!` script reached through a dirfd or an fd, there's no path
/// the interpreter could reopen it by (Linux hands it `/dev/fd/N`, which doesn't exist here), so
/// it's `ENOENT` -- the same error real Linux gives when that fd is close-on-exec.
pub fn do_execveat(
    caller_pid: Pid,
    at_ptr: u64,
    argv_ptr: u64,
    envp_ptr: u64,
    flags: u64,
) -> Result<u64, u64> {
    const AT_FDCWD: i64 = -100;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let [dirfd, path_ptr, path_len]: [u64; 3] = copyin_val(UserPtr::new(at_ptr))?;
    let dirfd = dirfd as i64;
    let path_bytes: Vec<u8> = if path_ptr == 0 {
        Vec::new()
    } else {
        copyin_vec(UserPtr::new(path_ptr), path_len as usize, PATH_MAX, ENAMETOOLONG)?
    };

    if path_bytes.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        // Real Linux: the cwd is a directory, and directories aren't executable.
        if dirfd == AT_FDCWD {
            return Err(EACCES);
        }
        if dirfd < 0 {
            return Err(EBADF);
        }
        let handle = crate::fs::fd::real_fd_of(dirfd as u64).ok_or(EBADF)?;
        let image = read_exec_head(handle, true)?;
        return exec_image(caller_pid, path_bytes, Some(image), false, argv_ptr, envp_ptr);
    }

    let path_is_cwd_relative = dirfd == AT_FDCWD || path_bytes[0] == b'/';
    let nofollow = flags & AT_SYMLINK_NOFOLLOW != 0;
    if path_is_cwd_relative && !nofollow {
        return exec_image(caller_pid, path_bytes, None, true, argv_ptr, envp_ptr);
    }
    let image = open_exec_file_at(at_ptr, nofollow)?;
    exec_image(
        caller_pid,
        path_bytes,
        Some(image),
        path_is_cwd_relative,
        argv_ptr,
        envp_ptr,
    )
}

/// `execve`'s real work, shared with `execveat`. `path_bytes` names the program (argv fallback,
/// `comm`, and the script path a `#!` interpreter reopens). `first_image`, when present, is the
/// already-read first file (`execveat`); `path_reopenable` says whether `path_bytes` can still find
/// that same file relative to the cwd, which a `#!` script needs.
fn exec_image(
    caller_pid: Pid,
    path_bytes: Vec<u8>,
    first_image: Option<ExecFile>,
    path_reopenable: bool,
    argv_ptr: u64,
    envp_ptr: u64,
) -> Result<u64, u64> {
    let mut arg_budget = MAX_EXEC_ARG_BYTES;
    // Phase timing for `debug.syscall.stats` (`syscall::stats::exec_phases`).
    let mut marks = [0u64; 9];
    marks[0] = crate::cpu::tsc::now();
    let raw_argv = read_ptr_len_array(argv_ptr, &mut arg_budget)?;
    let envp = read_ptr_len_array(envp_ptr, &mut arg_budget)?;

    // Real Unix `execve()` on a `#!`-prefixed file re-execs the named interpreter instead of
    // trying to load the script itself as an ELF (this kernel's own `elf::load` has no shebang
    // awareness at all -- a script handed to it directly fails `Elf::parse` with `ENOEXEC`, "Exec
    // format error", the same error a real kernel gives for any genuinely non-ELF file). Found
    // live: hush has no userspace `ENOEXEC`-fallback-to-script-interpretation logic of its own
    // (real Linux shells generally don't need one, since the kernel already handles `#!`) -- a
    // real script's own `+x` bit alone was never going to be enough to run it directly without
    // this. `effective_path` starts as the caller's own target and is replaced by each
    // interpreter in turn; `shebang_argv_prefix`, once any `#!` is followed, becomes the real
    // `[interpreter, optional-arg?, script-path]` prefix `argv` is built from below instead of the
    // caller's original `argv[0]`.
    let mut effective_path: Vec<u8> = path_bytes.clone();
    let mut shebang_argv_prefix: Option<Vec<Vec<u8>>> = None;
    let mut shebang_depth: u32 = 0;
    let mut first_image = first_image;
    let file: ExecFile = loop {
        let from_first_image = first_image.is_some();
        let file = match first_image.take() {
            Some(image) => image,
            None => open_exec_file(&effective_path)?,
        };
        let bytes = &file.head;
        if bytes.len() < 2 || &bytes[0..2] != b"#!" {
            break file;
        }
        // See `do_execveat`'s doc comment: a script only reachable through a dirfd/fd has no path
        // its interpreter could open.
        if from_first_image && !path_reopenable {
            return Err(ENOENT);
        }
        shebang_depth += 1;
        if shebang_depth > MAX_SHEBANG_DEPTH {
            return Err(ELOOP);
        }
        let (interpreter, optional_arg) = parse_shebang_line(bytes).ok_or(ENOEXEC)?;
        let mut prefix = alloc::vec![interpreter.clone()];
        if let Some(arg) = optional_arg {
            prefix.push(arg);
        }
        prefix.push(effective_path);
        shebang_argv_prefix = Some(prefix);
        effective_path = interpreter;
    };

    marks[1] = crate::cpu::tsc::now();
    let mut elf = Elf::parse_file(&file.head, file.size, file.content).map_err(|_| ENOEXEC)?;

    let phys_offset = memory::phys_mem_offset();
    // new_excluding_user, not AddressSpace::new: the currently active address space here is the
    // calling process's own, already-populated one (execve runs mid-syscall, on the caller's own
    // kernel stack, with its own CR3 still live) -- AddressSpace::new would shallow-copy that
    // process's *user* mappings too, aliasing them into what's supposed to be a fresh image.
    let new_address_space =
        with_frame_allocator(|fa| AddressSpace::new_excluding_user(phys_offset, fa))
            .map_err(|_| ENOMEM)?;
    // SAFETY: phys_offset is the bootloader's phys-memory mapping; this is the only live view of
    // new_address_space's own (not-yet-active) level 4 table right now.
    let mut mapper = unsafe { new_address_space.mapper(phys_offset) };

    // Everything that can fail while building the new image. On failure the half-built address
    // space is torn down: never active, and it may already use page cache entries.
    let built = (|| -> Result<_, u64> {
        // Checked once, before the main binary's own load, so both the bias decision below and the
        // interpreter-loading branch reuse the same parse instead of scanning PT_INTERP twice.
        marks[2] = crate::cpu::tsc::now();
        let interp_path = elf.interpreter().map_err(|_| ENOEXEC)?;

        // Any ET_DYN main binary gets a randomized bias (`process::aslr`): a static PIE, which the
        // kernel loads alone, and a dynamically linked PIE, where `ld.so` finds the bias through
        // `AT_PHDR` (`user_stack::build` adds it) and relocates the image itself. Linked at 0, an
        // unbiased PIE would map over the null page. A fixed-address ET_EXEC keeps bias 0.
        let main_bias: u64 = if elf.is_dynamic() {
            crate::process::aslr::pick_bias()
        } else {
            0
        };
        elf.cache = exec_cache_entry(&file, &new_address_space);
        let entry = elf::load(&elf, &mut mapper, phys_offset, main_bias).map_err(|_| ENOEXEC)?;

        // A real PT_INTERP dynamic linker, if the binary carries one, gets loaded into the same
        // not-yet-active address space right here, immediately after the main binary's own segments --
        // `SYSRETQ` needs to land in the interpreter's own entry, not the main binary's (the
        // interpreter relocates/resolves itself, then jumps to the main binary's real entry on its
        // own, via AT_ENTRY -- see `user_stack.rs`). `jump_entry`/`interp_base` stay `entry`/`None`
        // when there's no interpreter (true for both a fixed-address main binary and a no-PT_INTERP
        // PIE main binary -- `main_bias` above already covers the latter's own real bias, entirely
        // independent of `interp_base`, which is the *interpreter's* bias, not the main binary's).
        // `INTERP_LOAD_BASE` is a real, kernel-chosen runtime bias applied by `elf::load` itself, not
        // a link-time address the interpreter file assumes -- see that function's own doc comment for
        // the real bug (a wild pointer inside the interpreter's own relocation self-processing) a
        // fixed-link-time-base interpreter caused, and why this bias has to be applied here instead.
        marks[3] = crate::cpu::tsc::now();
        let mut jump_entry = entry;
        let mut interp_base: Option<u64> = None;
        if let Some(interp_path) = interp_path {
            let interp_file = open_exec_file(&interp_path)?;
            let mut interp_elf = Elf::parse_file(&interp_file.head, interp_file.size, interp_file.content)
                .map_err(|_| ENOEXEC)?;
            interp_elf.cache = exec_cache_entry(&interp_file, &new_address_space);
            let interp_entry =
                elf::load(&interp_elf, &mut mapper, phys_offset, INTERP_LOAD_BASE).map_err(|_| ENOEXEC)?;
            crate::process::mm::record_segments(&mut new_address_space.vm(), &interp_elf, INTERP_LOAD_BASE);
            jump_entry = interp_entry;
            interp_base = Some(INTERP_LOAD_BASE);
        }

        marks[4] = crate::cpu::tsc::now();
        let stack_top = VirtAddr::new(USER_STACK_TOP);
        let arg_bytes: u64 = raw_argv
            .iter()
            .chain(envp.iter())
            .chain(shebang_argv_prefix.iter().flatten())
            .map(|a| a.len() as u64 + 1)
            .sum();
        let stack_pages = user_stack_eager_pages(arg_bytes)?;
        let mapped_pages =
            map_user_stack(&mut mapper, stack_top, stack_pages, elf.exec_stack()).map_err(|_| ENOMEM)?;
        crate::process::fault_trampoline::map(&mut mapper, phys_offset).map_err(|_| ENOMEM)?;
        {
            let mut vm = new_address_space.vm();
            crate::process::mm::record_segments(&mut vm, &elf, main_bias);
            crate::process::mm::record_exec_tail(&mut vm, elf.exec_stack());
        }
        Ok((main_bias, jump_entry, interp_base, stack_top, stack_pages, mapped_pages))
    })();
    let (main_bias, jump_entry, interp_base, stack_top, stack_pages, mapped_pages) = match built {
        Ok(built) => built,
        Err(e) => {
            // SAFETY: never activated, and nothing else holds it.
            with_frame_allocator(|fa| unsafe { new_address_space.teardown(phys_offset, fa) });
            return Err(e);
        }
    };
    // raw_argv (read above, while the caller's own address space was still active) is the caller's
    // complete, real argv[] -- including a real, caller-chosen argv[0], which need not equal
    // path_bytes (see RawArgvEntry's own doc comment). An empty raw_argv (argv_ptr == 0, or a
    // present-but-immediately-terminated array) falls back to a synthesized single-element
    // argv = [path_bytes], the same fallback every pre-existing caller already relies on. envp is
    // real too -- whatever the caller's own envp_ptr described, or empty if it passed 0.
    //
    // When a `#!` shebang was followed above (`shebang_argv_prefix` is `Some`), real
    // `binfmt_script` semantics replace the whole thing instead: `[interpreter, optional-arg?,
    // script-path]` followed by the caller's own *original* `argv[1..]` -- `argv[0]` is always
    // discarded, matching real Linux (the script's own path, not the caller's `argv[0]`, is what
    // ends up in the new argv, since they need not be equal -- see `RawArgvEntry`'s own doc
    // comment referenced above).
    // Set-user-ID and set-group-ID (`OxideBSD-doc/SUDO.md` §5.1.2): only for a program executed
    // directly; the bits on a `#!` script are ignored, as on NetBSD, OpenBSD and Linux (the file
    // checked and the one the interpreter opens could differ).
    let setid = if shebang_argv_prefix.is_none() { file.setid } else { None };
    let wx_allowed = elf.wxneeded() && file.wxallowed;
    if elf.wxneeded() && !file.wxallowed {
        crate::serial_println!(
            "[wx] pid {}: {} is marked wxneeded but not on a wxallowed mount: W^X enforced",
            caller_pid,
            core::str::from_utf8(basename(&effective_path)).unwrap_or("?")
        );
    }
    let mut new_cred = crate::process::identity::current_cred();
    let setid_applied = new_cred.exec(setid);
    let secure = setid_applied || new_cred.euid != new_cred.ruid || new_cred.egid != new_cred.rgid;
    let argv_owned: Vec<Vec<u8>> = if let Some(mut prefix) = shebang_argv_prefix {
        if !raw_argv.is_empty() {
            prefix.extend(raw_argv[1..].iter().cloned());
        }
        prefix
    } else if raw_argv.is_empty() {
        alloc::vec![path_bytes.clone()]
    } else {
        raw_argv.clone()
    };
    let argv: Vec<&[u8]> = argv_owned.iter().map(Vec::as_slice).collect();
    let envp_refs: Vec<&[u8]> = envp.iter().map(Vec::as_slice).collect();
    let initial_rsp = crate::process::user_stack::build(
        &elf,
        &argv,
        &envp_refs,
        stack_top,
        user_stack_bottom(stack_top, stack_pages),
        &mapped_pages,
        phys_offset,
        interp_base,
        main_bias,
        secure,
    );

    // ---- commit point: nothing above may fail past here ----
    // SAFETY: new_address_space carries the kernel's own mappings (shallow-copied at construction,
    // same as every address space) plus the just-loaded ELF and user stack -- the same guarantee
    // AddressSpace::activate's own contract requires. Activating it mid-syscall, still running on
    // the caller's own kernel stack, is safe: the kernel half is identical no matter which address
    // space is live.
    marks[5] = crate::cpu::tsc::now();
    unsafe { new_address_space.activate() };
    let old_address_space = {
        let mut table = PROCESS_TABLE.lock();
        let me = table
            .get_mut(&caller_pid)
            .expect("execve: current process missing from table");
        // Old AddressSpace captured here, torn down for real below (once this lock is dropped) --
        // see AddressSpace::teardown's own doc comment for why this exact call site is safe:
        // new_address_space.activate() above already switched CR3 away from it.
        let old_address_space = me.address_space.replace(new_address_space);
        me.user_stack_top = initial_rsp;
        // The real jump target (interpreter's own entry when PT_INTERP loaded one, else the main
        // binary's) -- not read again for this exact pid (only a never-run process's first switch,
        // via spawn_trampoline_inner, ever consults entry_point; an execve'd process is already
        // running and jumps immediately via redirect_frame below), kept in sync anyway since it's
        // the honest answer to "where does this process's AddressSpace currently expect to run".
        me.entry_point = jump_entry;
        me.shared.lock().cred = new_cred;
        {
            // A fresh `VmState` came with the new table: no mappings, no memory locks (POSIX:
            // `execve` removes them).
            let mut vm = me.vm();
            vm.brk = VirtAddr::new(main_bias + elf.highest_loaded_address());
            vm.brk_base = vm.brk;
            // W^X's escape hatch (THREAT_MODEL.md §3.3, OpenBSD's): a program marked `wxneeded`,
            // run from a `wxallowed` mount.
            vm.wx_allowed = wx_allowed;
        }
        // effective_path is whichever path actually got loaded as the real ELF above -- the
        // caller's own original path_bytes when there was no `#!` to follow, or the final
        // interpreter in a shebang chain otherwise. Matches real Linux: `/proc/[pid]/comm` names
        // the actual binary execve() loaded (the interpreter), not the script argument handed to
        // it, since only the interpreter is ever really "exec'd" at the kernel level.
        me.comm = basename(&effective_path).to_vec();
        me.cmdline = build_cmdline(&argv);
        me.environ = build_cmdline(&envp);
        // The old program's TLS base doesn't mean anything to the new one -- reset the stored value
        // (restored on every future context switch, see Process::fs_base's own doc comment) *and*
        // the live MSR right now, since execve keeps running as this exact process/kernel stack with
        // no context switch in between; leaving the stale value live until the new program's own
        // crt1 gets around to calling SYS_SET_FS_BASE would be a real (if narrow) window for it to
        // read garbage through %fs before then.
        me.fs_base = 0;
        x86_64::registers::model_specific::FsBase::write(VirtAddr::new(0));
        // Real execve() semantics: a caught signal's handler address means nothing in the new
        // program image, so it resets to SIG_DFL; SIG_IGN and already-SIG_DFL entries are left
        // alone (both are position-independent of any particular program's own code), and so is
        // pending_signals/blocked_signals -- both persist across execve on a real system too.
        for action in me.shared.lock().sigactions.iter_mut() {
            if action.handler > 1 {
                *action = SigAction::DEFAULT;
            }
        }
        // Real execve() semantics: an established alt stack's address belongs to the old program
        // image and means nothing in the new one -- reset to disabled, same reasoning fs_base
        // above already uses.
        me.altstack = AltStack::default();
        me.on_altstack = false;
        // Real `timer_create(2)` semantics: POSIX per-process timers are disarmed and deleted
        // across execve -- see `Process::posix_timers`'s own doc comment.
        me.posix_timers = [None; MAX_POSIX_TIMERS];
        old_address_space
    };
    // The old image's mappings are gone from this process: their bookkeeping is cleaned up
    // (SysV shm detached, `MAP_SHARED` file pages written back, `/dev/fb0` released) by whoever
    // uses the old table last -- this process, unless it was a vfork child borrowing its
    // parent's, or a thread whose siblings keep running in it. Then the table itself is torn
    // down: CR3 already moved, and `teardown` only frees it once no handle remains.
    // `.expect()`: a live, executing process always had Some -- only a Zombie has None.
    marks[6] = crate::cpu::tsc::now();
    let old_address_space = old_address_space.expect("execve: old address space already gone");
    if last_live_user(&PROCESS_TABLE.lock(), caller_pid, &old_address_space) {
        cleanup_vm(&old_address_space);
    }
    with_frame_allocator(|fa| unsafe { old_address_space.teardown(phys_offset, fa) });
    marks[7] = crate::cpu::tsc::now();
    // Real close-on-exec: any fd this process marked FD_CLOEXEC (fcntl(F_SETFD)/open(O_CLOEXEC),
    // see `crate::fs::fd::CLOEXEC`'s own doc comment) doesn't survive into the new program image.
    // Keyed by tgid, not caller_pid directly -- see `crate::fs::fd`'s own module doc comment on
    // why the fd/CLOEXEC tables are tgid-scoped -- though the two are identical until a real
    // `clone(2)`-created thread can execve.
    crate::fs::fd::close_cloexec(scheduler::current_tgid());
    // A vfork child has its own address space now: its parent may run again.
    vfork_release(caller_pid);
    marks[8] = crate::cpu::tsc::now();
    syscall::stats::exec_phases(&marks);

    let frame = syscall::current_frame();
    // SAFETY: frame is this exact syscall's own live frame -- do_execve is only ever reached via
    // dispatch(SYS_EXECVE, ...), called from within syscall_dispatch, which set CURRENT_FRAME to
    // it just before.
    unsafe { syscall::redirect_frame(frame, jump_entry, initial_rsp) };
    Ok(0)
}
/// Real `wait4(2)` `options` bits (`external/mit/musl/include/sys/wait.h`) -- musl's own wrapper
/// passes these straight through as the real 3rd syscall argument, no call-site patch needed.
pub const WNOHANG: u64 = 1;
pub const WUNTRACED: u64 = 2;
pub const WCONTINUED: u64 = 8;

/// What `do_wait4` found to report back, before it's translated into the real wire-format
/// `status` value below -- kept distinct from that encoding so the three real, mutually exclusive
/// shapes (exited/stopped/continued) can't be confused with each other while being decided.
enum Reported {
    Exited(Pid, i32),
    Stopped(Pid, u64),
    Continued(Pid),
}

/// `sys_wait4`'s real logic. If the caller already has a `Zombie` child matching `target_pid`
/// (`-1` = any), reaps it immediately (removes it from the table, writes its exit code through the
/// optional `status_ptr`, returns its pid). Real `WUNTRACED`/`WCONTINUED` support: if `options`
/// requests them and a matching child has `stop_notify_pending`/`cont_notify_pending` set (see
/// `ProcState::Stopped`'s own doc comment for why a plain state flip is enough to make this safe),
/// reports that instead -- without reaping, since the child is still alive. If the caller has no
/// child matching `target_pid` at all, `ECHILD`. If nothing reportable exists yet and `options`
/// includes real `WNOHANG`, returns `0` immediately rather than blocking -- load-bearing, not just
/// a nice-to-have: `hush`'s own `checkjobs()` (background job-status polling, run throughout its
/// interactive main loop) always passes `WUNTRACED | WNOHANG`, and without a real `WNOHANG`, any
/// call that reached the real syscall with a still-running child would block the entire
/// interactive shell. **This used to be true unconditionally**, since this kernel never delivered a
/// real `SIGCHLD` to a parent at all -- `hush`'s own `CONFIG_HUSH_FAST` short-circuit (skip the
/// real syscall unless a `SIGCHLD` counter changed) was silently permanently active, since that
/// counter could never move. Real `SIGCHLD` generation now exists (`signals::
/// notify_parent_sigchld`, called from every real exit/stop/continue transition), so `hush`'s own
/// counter genuinely increments now and `CONFIG_HUSH_FAST` behaves as actually designed -- `WNOHANG`
/// is still load-bearing for the calls that do go through, just no longer masking *every* call.
/// Otherwise blocks (`ProcState::Blocked`) and calls `scheduler::schedule()`, which only returns
/// once something (`do_exit`/the real stop/continue transitions in `process::signals`/
/// `do_stop_self`) wakes the parent — at which point the loop re-checks from the top, since a
/// wakeup never hands the child's info across directly (and, per `ProcState::Stopped`'s own doc
/// comment, a wakeup that turns out not to match what this exact call actually asked for is safe
/// to just re-block on).
pub fn do_wait4(
    caller_pid: Pid,
    target_pid: i64,
    options: u64,
    status_ptr: u64,
    rusage_ptr: u64,
) -> Result<u64, u64> {
    let matches = |pid: Pid| target_pid == -1 || target_pid as u64 == pid;

    loop {
        // Set only by the `Reported::Exited` arm below, to the just-reaped child's own address
        // space -- real reclaim happens after this loop iteration's own `table` lock is dropped
        // (see the real teardown call further below, and AddressSpace::teardown's own doc comment
        // for why this exact call site -- a reaped process, necessarily not the active `CR3` since
        // it already stopped running back when it originally called `do_exit` -- is safe).
        let mut reaped_address_space: Option<AddressSpace> = None;
        // The reaped child's own CPU time and the kernel part of it, for `rusage_ptr`.
        let mut reaped_ticks = (0u64, 0u64);
        let reported = {
            let mut table = PROCESS_TABLE.lock();

            let children: Vec<Pid> = table
                .get(&caller_pid)
                .expect("wait4: current process missing from table")
                .children
                .iter()
                .copied()
                .filter(|&c| matches(c))
                .collect();
            if children.is_empty() {
                return Err(ECHILD);
            }

            let zombie =
                children
                    .iter()
                    .copied()
                    .find_map(|c| match table.get(&c).map(|p| p.state) {
                        Some(ProcState::Zombie(code)) => Some((c, code)),
                        _ => None,
                    });

            if let Some((child_pid, code)) = zombie {
                let removed = table
                    .remove(&child_pid)
                    .expect("wait4: zombie child vanished under the same lock that found it");
                // Already `None` here if `terminate_process` already tore this down for real at
                // exit time (the common case now -- see `ProcState`/`Process::address_space`'s own
                // doc comments); `Some` only for the narrower cases that still defer teardown all
                // the way to reap (e.g. a genuinely still-running self-exit whose own
                // `queue_thread_reap` hasn't drained yet by the time this reap runs).
                reaped_address_space = removed.address_space;
                // Real `times(2)`/`tms_cutime`/`tms_cstime` accumulation -- see
                // `Process::child_cpu_ticks`'s own doc comment for why this is transitive (folds in
                // whatever the child itself had already accumulated from its own reaped children,
                // not just its direct `cpu_ticks`) without any extra recursion needed here.
                let child_total = removed.cpu_ticks + removed.child_cpu_ticks;
                let child_sys = removed.sys_ticks + removed.child_sys_ticks;
                reaped_ticks = (removed.cpu_ticks, removed.sys_ticks);
                let parent = table.get_mut(&caller_pid).unwrap();
                parent.child_cpu_ticks += child_total;
                parent.child_sys_ticks += child_sys;
                parent.children.retain(|&c| c != child_pid);
                Some(Reported::Exited(child_pid, code))
            } else if options & WUNTRACED != 0
                && let Some(&child_pid) = children
                    .iter()
                    .find(|&&c| table.get(&c).is_some_and(|p| p.stop_notify_pending))
            {
                let ProcState::Stopped(stopsig) = table.get(&child_pid).unwrap().state else {
                    unreachable!(
                        "stop_notify_pending is always cleared in the same lock as the state \
                         transition back out of Stopped -- see Process::stop_notify_pending's own \
                         doc comment"
                    )
                };
                table.get_mut(&child_pid).unwrap().stop_notify_pending = false;
                Some(Reported::Stopped(child_pid, stopsig))
            } else if options & WCONTINUED != 0
                && let Some(&child_pid) = children
                    .iter()
                    .find(|&&c| table.get(&c).is_some_and(|p| p.cont_notify_pending))
            {
                table.get_mut(&child_pid).unwrap().cont_notify_pending = false;
                Some(Reported::Continued(child_pid))
            } else if options & WNOHANG != 0 {
                return Ok(0);
            } else {
                let target = if target_pid == -1 {
                    None
                } else {
                    Some(target_pid as u64)
                };
                table.get_mut(&caller_pid).unwrap().state =
                    ProcState::Blocked(BlockReason::WaitingForChild(target));
                None
            }
        }; // table lock dropped here, before schedule() -- see table()'s own doc comment

        // Real reclaim: only set by the Exited arm above, always safe here (see
        // reaped_address_space's own doc comment).
        if let Some(address_space) = reaped_address_space {
            let phys_offset = memory::phys_mem_offset();
            with_frame_allocator(|fa| unsafe { address_space.teardown(phys_offset, fa) });
        }

        if let Some(reported) = reported {
            let (child_pid, status) = match reported {
                // `code` is already the real, fully wait(2)-encoded status by the time it reaches
                // Zombie(code) -- either WEXITSTATUS-shifted at oxidebsd_sys_exit (normal exit) or
                // the pre-encoded 128+sig value terminate_process's own Terminate path passes
                // directly (signal termination) -- see CLAUDE.md's own note on this. Written
                // through verbatim, not re-shifted.
                Reported::Exited(child_pid, code) => (child_pid, code),
                // 0x7f | (stopsig << 8) -- real WIFSTOPPED wire shape (confirmed disjoint from
                // both the exit encoding above, low byte always 0x00, and terminate_process's own
                // 128+sig signal-termination encoding, low byte always 0x81..0x9f).
                Reported::Stopped(child_pid, stopsig) => {
                    (child_pid, 0x7f | ((stopsig as i32) << 8))
                }
                // The real, exact WIFCONTINUED wire value -- no other bits allowed.
                Reported::Continued(child_pid) => (child_pid, 0xffff),
            };
            // Copied out after the child is reaped, so a bad pointer is EFAULT with the child gone,
            // as on FreeBSD.
            if status_ptr != 0 {
                crate::memory::usercopy::copyout_val(
                    &status,
                    crate::memory::usercopy::UserPtr::new(status_ptr),
                )?;
            }
            crate::syscall::write_rusage(rusage_ptr, reaped_ticks.0, reaped_ticks.1)?;
            return Ok(child_pid);
        }

        scheduler::schedule();
    }
}
/// `sys_exit`'s real, per-process logic (reached only through `syscall::oxidebsd_sys_exit`, the
/// native ABI's own exit handler). Marks the caller `Zombie(code)`; if its parent is blocked waiting on it
/// (or on any child), wakes the parent; then yields to the scheduler, which is guaranteed to
/// either switch to something else or `hlt_loop()` if nothing else is runnable — a `Zombie` is
/// never re-enqueued, so this call never returns.
///
/// Orphaned grandchildren are *not* reparented to a pid-1 "init" this pass — an accepted
/// simplification (see CLAUDE.md), not required for fork/exec/wait correctness.
pub fn do_exit(caller_pid: Pid, code: i32) -> ! {
    terminate_process(caller_pid, code);
    scheduler::schedule();
    unreachable!("do_exit: schedule() returned control to a Zombie process");
}

/// `sys_exit_group`'s real, whole-thread-group logic (reached only through
/// `syscall::oxidebsd_sys_exit_group`, real `exit()`/`_Exit()`'s own kernel entry point -- see
/// `external/mit/musl/arch/x86_64/bits/syscall.h.in`'s `__NR_exit_group` doc comment for why this
/// must be a genuinely distinct syscall from `do_exit`/`SYS_EXIT`). Real POSIX/Linux
/// `exit_group(2)` semantics: terminates every thread sharing the caller's `tgid`, not just the
/// calling thread -- found live, the hard way, chasing the Open POSIX Test Suite pilot's
/// `pthread_attr_init/2-1.c` permanent hang. Before this syscall existed, `exit()`/`_Exit()` and a
/// bare per-thread `SYS_exit` (real musl's own `__pthread_exit` cleanup path,
/// `external/mit/musl/src/thread/pthread_create.c`) shared the exact same syscall number, so a
/// thread-group leader's own `main()` returning only ever tore down the leader itself, silently
/// orphaning any still-alive sibling thread. That orphaned sibling then ran on indefinitely
/// (`pthread_attr_init/2-1.c`'s own detached, still-sleeping worker thread), eventually
/// deadlocking against musl's own userspace thread-list bookkeeping (`__tl_lock`/
/// `__thread_list_lock`) inside its own later `pthread_exit()` -- that bookkeeping's own
/// `self->next == self` fast-path assumes a real `exit_group` already unlinked the leader from the
/// live-thread list atomically at process-exit time, which never happened here. Worse, the
/// leader's own pending `alarm()`-based rescue timer (the whole POSIX pilot's `t0` harness relies
/// on this to bound every test) died with the leader too, so the orphaned sibling could spin
/// forever with nothing left to time it out.
///
/// Terminates every *other* live thread in the group first -- each independently reaches
/// `terminate_process`'s own `other_thread_alive` branch (marked `Zombie` and deferred to
/// `scheduler::queue_thread_reap`, exactly like an ordinary non-leader thread's own bare `SYS_exit`
/// already does, real per-thread teardown safety unchanged) -- then the caller itself last. By
/// then `other_thread_alive` is false for the caller, so `terminate_process` takes its real "last
/// thread of the group" path: `close_all`/SysV cleanup/mmap writeback run exactly once, and the
/// parent gets exactly one `SIGCHLD` for the whole process, not one per thread.
pub fn do_exit_group(caller_pid: Pid, code: i32) -> ! {
    terminate_thread_group(caller_pid, code);
    scheduler::schedule();
    unreachable!("do_exit_group: schedule() returned control to a Zombie process");
}

/// The actual "kill every other thread in the group, then this one" logic `do_exit_group` needs —
/// factored out so `do_kill`'s cross-process `Action::Terminate` and `deliver_pending_signal`'s
/// self-signal `SignalDelivery::Terminate` (see that match arm's own doc comment) can reach the
/// exact same real POSIX behavior for a target that isn't necessarily the currently-running
/// process, without `do_exit_group`'s own diverging `scheduler::schedule()` epilogue (only correct
/// when the *caller* is terminating itself).
///
/// **Real bug this closed**: both of those call sites used to call `terminate_process` directly on
/// just the one named/signaled thread. If that thread happened to be a thread-group *leader* with
/// still-live sibling threads, `terminate_process`'s own `other_thread_alive` check saw those
/// siblings and concluded this was "just another disposable `CLONE_THREAD` sibling exiting" —
/// silently marking the *leader* `Zombie` and queuing it for full removal, without ever calling
/// `wake_parent_if_waiting`/`notify_parent_sigchld` (correct for an *actual* non-leader sibling,
/// which is never an independent `wait4` target — wrong for the leader, which is the one process a
/// real `wait4()` is ever watching). The parent's `wait4(-1, ...)` then blocked forever: the pid it
/// was tracking either vanished outright (once the queued removal drained) or sat as an
/// unreachable, un-notified zombie, with no second wake ever coming. Found chasing a flaky
/// crash-or-hang in `pthread_attr_setdetachstate/2-1.c`: real musl's `pthread_join()`/
/// `pthread_detach()` against an already-detached thread deliberately executes `a_crash()` (a raw
/// ring-3 `hlt`, `#GP`-faulting into a self-`SIGSEGV`) — reaching exactly this path, on a process
/// that, in this exact test, still has one live sibling thread at that moment.
///
/// **A second, distinct ordering bug in this exact function, since also fixed**: the loop used to
/// terminate every "sibling" (everyone but `target_pid`) first, then `target_pid` itself last —
/// this doc comment's own "by then `other_thread_alive` is false for the caller" reasoning only
/// actually holds when `target_pid` happens to *be* the group's leader. If `target_pid` is a
/// non-leader thread (any thread besides the main one can legally call `exit()`) and the leader is
/// one of the *siblings*, the leader gets processed before `target_pid` — at that exact moment
/// `target_pid` is still alive and not yet `Zombie`, so `terminate_process(leader)` sees
/// `other_thread_alive == true` and wrongly takes the disposable non-leader path on the *leader*
/// itself — the same silent-stranding bug described just above, just reached via a different call
/// order. Found live via `pthread_cond_timedwait/4-1.c`: a `pthread_create`d worker thread calls
/// `exit()` after a timed condvar wait while the main thread (the real leader) sits blocked in its
/// own `pthread_join()` futex wait — the leader was a "sibling" here, terminated ahead of the
/// actual `target_pid`, and was silently marked `Zombie` with no parent notification, hanging the
/// parent's `wait4()` forever. Fixed by terminating every non-leader member of the group first
/// (`target_pid` included, if it isn't the leader), then the leader (`pid == tgid`) always last,
/// regardless of whether it's `target_pid` itself or one of its "siblings" — by the time the
/// leader's own `terminate_process` call runs, every other real member of the group is already
/// `Zombie`, so `other_thread_alive` correctly reads `false` and it takes the real, wait4-visible
/// final-teardown path.
pub(crate) fn terminate_thread_group(target_pid: Pid, code: i32) {
    let tgid = {
        let table = PROCESS_TABLE.lock();
        match table.get(&target_pid) {
            Some(p) => p.tgid,
            None => return,
        }
    };
    // Terminating another process closes its files, which enters the filesystem: not while that
    // would wait (from an interrupt handler it can't) or land inside an operation asleep partway
    // through. Carried out when the filesystem lock is released (`fs::fslock`). A process ending
    // itself just waits for the lock like any other caller.
    if tgid != scheduler::current_tgid() && crate::fs::fslock::busy() {
        crate::fs::fslock::defer_termination(target_pid, code);
        return;
    }
    let siblings: Vec<Pid> = {
        let table = PROCESS_TABLE.lock();
        table
            .iter()
            .filter(|&(&pid, proc)| {
                pid != target_pid
                    && proc.tgid == tgid
                    && !matches!(proc.state, ProcState::Zombie(_))
            })
            .map(|(&pid, _)| pid)
            .collect()
    };
    for pid in siblings.into_iter().chain(core::iter::once(target_pid)) {
        if pid != tgid {
            terminate_process(pid, code);
        }
    }
    terminate_process(tgid, code);
}

/// The actual state transition `do_exit` (the caller terminating itself) and `do_kill` (one
/// process terminating a *different* one, for a default-disposition signal — see that function's
/// own doc comment) both need: closes every fd `pid` still has open, marks it `Zombie(code)`, and
/// wakes its parent if it's blocked waiting on it (or on any child). Deliberately does *not* call
/// `scheduler::schedule()` — `do_exit` (terminating the *currently running* process) needs to
/// yield afterward; `do_kill` (terminating some other, not-currently-running process — only one
/// process is ever `Running` at a time on this cooperatively-scheduled kernel, so `target !=
/// caller` always means "not the one currently executing") must not, since the calling process
/// itself is still running and hasn't blocked or exited.
/// Real pid 1 -- `init` in every real Unix, `hush` here (see `spawn`'s own doc comment). The one
/// process every real orphan gets reparented to.
pub(crate) const INIT_PID: Pid = 1;

/// Whether no live process but `pid` uses `space`: a thread group's threads share one table, and
/// a vfork child borrows its parent's. The last live user cleans up its `VmState` at exit or
/// exec (`cleanup_vm`); a zombie still holding a handle doesn't count.
pub(crate) fn last_live_user(
    table: &BTreeMap<Pid, Box<Process>>,
    pid: Pid,
    space: &AddressSpace,
) -> bool {
    let id = space.id();
    !table.iter().any(|(&other, p)| {
        other != pid
            && !matches!(p.state, ProcState::Zombie(_))
            && p.address_space.as_ref().is_some_and(|a| a.id() == id)
    })
}

/// Ends every mapping's bookkeeping in `space` (`mm::VmState`), for its last live user at exit or
/// exec: each attached SysV segment's `nattch` drops, `MAP_SHARED` file pages are written back
/// and their references released, `/dev/fb0` goes back to the console. The page tables stay
/// (`AddressSpace::teardown` frees them). Takes the process table and other locks: call it with
/// none held.
fn cleanup_vm(space: &AddressSpace) {
    crate::fs::sysv_shm::detach_all_for_exit(space);
    mm::cleanup_mmap_file_regions_for_exit(space);
    mm::cleanup_mmap_phys_regions_for_exit(space);
}

/// Hands `pid`'s children to `INIT_PID` as it exits (POSIX: their parent process ID becomes 1),
/// and init reaps them like any child of its own (`waitpid(-1, ...)`, `init(8)`). One that has
/// already exited is a zombie init hasn't heard of: it gets `SIGCHLD` for it, as on FreeBSD. No-op
/// for `INIT_PID` itself.
fn reparent_orphans(pid: Pid) {
    if pid == INIT_PID {
        return;
    }
    let mut table = PROCESS_TABLE.lock();
    let Some(children) = table
        .get_mut(&pid)
        .map(|me| core::mem::take(&mut me.children))
    else {
        return;
    };
    if children.is_empty() {
        return;
    }
    let mut zombies = Vec::new();
    for &child_pid in &children {
        if let Some(child) = table.get_mut(&child_pid) {
            child.parent = Some(INIT_PID);
            if let ProcState::Zombie(status) = child.state {
                zombies.push((child_pid, status));
            }
        }
    }
    if let Some(init) = table.get_mut(&INIT_PID) {
        init.children.extend(children);
    }
    for (child_pid, status) in zombies {
        let (code, value) = if status & 0x7f != 0 {
            (if status & 0x80 != 0 { CLD_DUMPED } else { CLD_KILLED }, (status & 0x7f) as u64)
        } else {
            (CLD_EXITED, ((status >> 8) & 0xff) as u64)
        };
        notify_parent_sigchld(&mut table, child_pid, code, value);
        wake_parent_if_waiting(&mut table, child_pid);
    }
}

pub(crate) fn terminate_process(pid: Pid, code: i32) {
    crate::kern::kern_core::forget(pid);
    // A vfork child's exit ends its borrow: its parent may run again.
    vfork_release(pid);
    // Real orphan reparenting -- see `reparent_orphans`'s own doc comment. Runs unconditionally,
    // before any of the branches below, since even a non-leader `CLONE_THREAD` sibling (the
    // `other_thread_alive` branch just below) can have forked real children of its own under its
    // own real pid.
    reparent_orphans(pid);
    // A process killed while blocked in a FIFO open() still holds that open's reader/writer count.
    crate::fs::pipe::abandon_fifo_open(pid);
    // Real CLONE_THREAD semantics: only the whole thread group ever generates a wait4-visible
    // zombie, not each individual thread (a real pthread_join never goes through wait4 at all --
    // see process::lifecycle::do_clone's own doc comment). A plain scan for any *other* live
    // PROCESS_TABLE entry sharing this exiting process's own tgid, same cost/style as
    // process::limits::do_futex's own FUTEX_WAKE scan.
    let tgid = {
        let table = PROCESS_TABLE.lock();
        match table.get(&pid) {
            Some(me) => me.tgid,
            None => return,
        }
    };
    // Real CLONE_CHILD_CLEARTID (`do_clone`'s own `ctid` argument) -- writes real `0` to the real
    // clear-tid address and wakes up to 1 real futex waiter there, matching real Linux's own
    // task-exit behavior exactly. Must run here, at real per-thread exit time (applies to *every*
    // exiting thread, leader or not -- a real Linux `child_tid` clear is per-task, independent of
    // whether this happens to also be the whole thread group's last member), not sooner: real
    // musl's own `__tl_lock`/`__thread_list_lock` mechanism (`external/mit/musl/src/thread/
    // pthread_create.c`) depends on this firing only after the exiting thread has genuinely
    // committed to exit -- found live chasing a real `pthread_join` hang, see `Process::
    // clear_child_tid`'s own doc comment for the full story.
    let clear_child_tid = {
        let table = PROCESS_TABLE.lock();
        table.get(&pid).map(|p| p.clear_child_tid).unwrap_or(0)
    };
    if clear_child_tid != 0 {
        // A bad address is ignored, as on Linux: the thread is exiting either way.
        let _ = copyout_val(&0u32, UserPtr::new(clear_child_tid));
        wake_futex(tgid, clear_child_tid, 1);
    }
    let other_thread_alive = {
        let table = PROCESS_TABLE.lock();
        table.iter().any(|(&other_pid, other)| {
            other_pid != pid && other.tgid == tgid && !matches!(other.state, ProcState::Zombie(_))
        })
    };
    if other_thread_alive {
        // A non-leader thread exiting while siblings remain. **Can't remove this Process entry
        // right here** -- this function is running on *this exact thread's own kernel stack*,
        // still, and `do_exit`'s caller is about to call `scheduler::schedule()`, which needs the
        // outgoing process's own table entry to still exist (to check its state, save its live
        // FPU state, and get a pointer to its own `rsp` field -- see `scheduler::schedule`'s own
        // body). Dropping the entry now would deallocate this thread's own `KernelStack` while
        // still executing on it, and would panic `schedule()`'s own table lookup regardless.
        //
        // So: mark it `Zombie` (the same "don't re-enqueue, entry still exists" state a real
        // wait4-reapable process uses, satisfying every one of `schedule()`'s own requirements
        // unmodified) but skip `wake_parent_if_waiting` -- a real CLONE_THREAD child is never an
        // independent wait4 target (see `do_clone`'s own doc comment), so no parent is ever
        // watching for this state change. Real removal -- which is what actually drops this
        // thread's own `KernelStack` and decrements its Arc-shared `address_space`/`shared`
        // fields' refcounts (a real, refcounted release, not a leak -- see `AddressSpace::
        // teardown`'s own `Arc::strong_count` gate and `ThreadGroupShared`'s own doc comment) --
        // is deferred to `scheduler::queue_thread_reap`, which only actually runs once some
        // *other*, still-running process confirms (via `current_pid()`) that execution has
        // genuinely moved off this stack.
        //
        // Deliberately skips close_all/sysv-undo/sysv-detach/mmap-cleanup below -- those only
        // make sense once the whole thread group is gone (see each call's own reasoning right
        // below, in the branch that actually runs them).
        let mut table = PROCESS_TABLE.lock();
        if let Some(me) = table.get_mut(&pid) {
            me.state = ProcState::Zombie(code);
        }
        scheduler::remove_ready(pid);
        drop(table);
        scheduler::queue_thread_reap(pid, scheduler::ReapKind::RemoveEntry);
        return;
    }
    // Real exit() semantics: every fd this thread group still has open gets closed automatically.
    // Genuinely load-bearing, not just tidiness -- see crate::fs::fd::close_all's own doc comment
    // for why a leaked fd here can leave a pipe's reader blocked forever. Keyed by `tgid`, not
    // `pid` -- the fd table is tgid-scoped (real CLONE_FILES sharing, see crate::fs::fd's own
    // module doc comment) -- the two are identical unless the tgid's own leader already exited
    // and a still-running clone(2)-created sibling is the one reaching this branch last.
    crate::fs::fd::close_all(tgid);
    // Real SysV SEM_UNDO semantics: every accumulated adjustment this process ever recorded gets
    // applied (added back) on termination -- see `Process::sysv_sem_undo`'s own doc comment. Must
    // run *before* `PROCESS_TABLE` is locked below: `apply_undo_for_exit` takes that same lock
    // itself (briefly, to drain the list) and then wakes any blocked `semop` waiters via a second,
    // separate `process::table()` lock -- both would deadlock against `spin::Mutex`'s non-reentrant
    // guarantee if nested inside the lock this function is about to take.
    crate::fs::sysv_sem::apply_undo_for_exit(pid);
    // The address space's bookkeeping (SysV shm detach, `MAP_SHARED` writeback, `/dev/fb0`), if
    // this is the last live process using it: not while a vfork child still borrows it, nor for
    // a vfork child exiting while its parent runs on. After `close_all` above (which drops each
    // mapped fd's own reference, leaving the mapping's), before `PROCESS_TABLE` is locked below
    // (the cleanups take it and other locks). The extra handle only lives for the cleanup.
    let space = {
        let table = PROCESS_TABLE.lock();
        table
            .get(&pid)
            .and_then(|me| me.address_space.as_ref())
            .filter(|space| last_live_user(&table, pid, space))
            .map(AddressSpace::share)
    };
    if let Some(space) = space {
        cleanup_vm(&space);
    }
    let mut table = PROCESS_TABLE.lock();
    match table.get_mut(&pid) {
        Some(me) if matches!(me.state, ProcState::Zombie(_)) => return, // already dead
        Some(me) => me.state = ProcState::Zombie(code),
        None => return,
    }
    // A session leader's exit hangs up its controlling terminal (TTY.md §5.4).
    if table.get(&pid).is_some_and(|me| me.sid == tgid) {
        drop(table);
        crate::tty::session_leader_exited(tgid);
        table = PROCESS_TABLE.lock();
    }
    // The system's init: the kernel records the death and starts pid 1 again (INIT.md §9).
    if tgid == INIT_PID {
        drop(table);
        if crate::process::init::pid1_died(pid, code) {
            return;
        }
        table = PROCESS_TABLE.lock();
    }
    // Real hardening, found live: `do_kill`'s cross-process `Action::Terminate` branch (a default-
    // disposition signal killing a target this process didn't just switch away from) can target a
    // process that's currently `Ready` and still sitting in `scheduler::READY_QUEUE` -- unlike the
    // adjacent `Action::Stop` branch, which already dequeues first (see that branch's own comment),
    // this path used to leave the queue entry dangling. If the caller (`do_wait4`) then reaps this
    // exact pid before the scheduler ever pops that stale entry, `PROCESS_TABLE` no longer has it
    // at all by the time `scheduler::activate_and_prepare` tries to switch to it -- a real panic
    // ("pid missing from table"), not just a logic bug. Found by the expanded POSIX conformance
    // pilot's own `sigaction/9-1.c`: its final `kill(pid, SIGHUP)` racing a child that (thanks to
    // `select()` immediately `ENOSYS`-ing rather than truly blocking, see `process::do_futex`'s own
    // doc comment for the identical-in-spirit `sem_wait` finding) cycles through `Ready` far more
    // often than a real system's `select()` ever would, made this race easy to hit. Safe (and cheap)
    // to call unconditionally here rather than gating on `state == Ready` first, unlike `Action::
    // Stop`'s own check -- `do_exit`'s self-termination path (this function's *other* caller) is
    // never `Ready` when it calls this (it's the one process currently `Running`), so this is a
    // harmless no-op there; `remove_ready` itself is already a no-op for a pid that isn't queued.
    scheduler::remove_ready(pid);
    wake_parent_if_waiting(&mut table, pid);
    // Real POSIX SIGCHLD generation -- see notify_parent_sigchld's own doc comment. `code` is
    // already real wait(2)-encoded: WIFEXITED (low 7 bits zero) means CLD_EXITED with the real
    // exit code in bits 8-15; otherwise this was a signal-terminated exit (CLD_KILLED), with the
    // real terminating signal number in the low 7 bits -- the same encoding WEXITSTATUS/WTERMSIG
    // already decode elsewhere in this codebase.
    if code & 0x7f == 0 {
        notify_parent_sigchld(&mut table, pid, CLD_EXITED, ((code >> 8) & 0xff) as u64);
    } else {
        let how = if code & 0x80 != 0 { CLD_DUMPED } else { CLD_KILLED };
        notify_parent_sigchld(&mut table, pid, how, (code & 0x7f) as u64);
    }
    // Real SA_NOCLDWAIT semantics (`sigaction/21-1.c`): if the parent's own SIGCHLD action has
    // this flag set, a child is never left as a wait4-reapable zombie at all -- real POSIX
    // (`sigaction(2)`, XSI): "if a process's SIGCHLD action... has the SA_NOCLDWAIT flag set...
    // child processes... shall not be transformed into zombie processes". SIGCHLD generation
    // itself is unaffected (matches real Linux -- this flag only governs zombie retention, unlike
    // SA_NOCLDSTOP's own signal-suppression for stop/continue), so this must run *after* the
    // notify_parent_sigchld calls above, not instead of them. Detaches from the parent's
    // `children` list immediately either way, so a parent with no other children gets a real
    // `ECHILD` on its very next `wait()` call instead of blocking forever.
    let auto_reap = table
        .get(&pid)
        .and_then(|me| me.parent)
        .and_then(|parent_pid| table.get(&parent_pid))
        .is_some_and(|parent| parent.shared.lock().sigactions[SIGCHLD as usize].flags & SA_NOCLDWAIT != 0);
    if auto_reap {
        let parent_pid = table.get(&pid).unwrap().parent;
        if let Some(parent_pid) = parent_pid
            && let Some(parent) = table.get_mut(&parent_pid)
        {
            parent.children.retain(|&c| c != pid);
        }
        // Real frame reclaim (`AddressSpace::teardown`) requires this entry's own address space to
        // *not* be the currently active `CR3` -- true immediately for a cross-process kill
        // (`do_kill`'s `Action::Terminate`, target != caller, exactly like `do_wait4`'s own normal
        // reap), but **not** for the common case: `do_exit` calling this on *itself*, still
        // running on this exact entry's own address space/kernel stack at this exact point (same
        // hazard the `other_thread_alive` branch above documents for the identical reason). Deferred
        // via `scheduler::queue_thread_reap`'s `ReapKind::RemoveEntry` -- real removal *and* real
        // teardown now (see that enum's own doc comment; it used to only remove the entry, leaking
        // this one address space's frames -- closed as part of the same fix that closes the much
        // bigger default-path leak just below).
        if pid == scheduler::current_pid() {
            scheduler::remove_ready(pid);
            drop(table);
            scheduler::queue_thread_reap(pid, scheduler::ReapKind::RemoveEntry);
            return;
        }
        let removed = table
            .remove(&pid)
            .expect("terminate_process: just-set zombie vanished under the same lock");
        drop(table);
        if let Some(address_space) = removed.address_space {
            let phys_offset = memory::phys_mem_offset();
            with_frame_allocator(|fa| unsafe { address_space.teardown(phys_offset, fa) });
        }
        return;
    }
    // Real frame reclaim, real POSIX zombie semantics: the address space's own physical frames get
    // reclaimed *right now* (deferred only as long as it takes to safely leave this exact stack, for
    // a self-exit), not left pinned for however long it takes some parent to actually call
    // `wait4()` -- the table entry itself still survives in `ProcState::Zombie` either way, for a
    // real future `wait4` to find and report exit status/rusage from (see `do_wait4`'s own reap
    // path, which now correctly finds `address_space` already `None` here and skips its own
    // teardown call as a no-op).
    //
    // **Why this matters, found live**: this codebase never reparents an orphan to a pid-1 "init"
    // (see `do_wait4`'s own doc comment on that accepted simplification) -- so any process whose
    // real parent already exited (or simply never calls `wait4()` on this specific child) leaves a
    // zombie that is *never* reaped by anyone, ever. Before this fix, that permanently pinned the
    // zombie's *entire* address space -- every mapped page, not just bookkeeping -- for the rest of
    // the boot. Across the POSIX conformance pilot's own ~1675-file corpus (many `pthread_*`/`fork`
    // tests legitimately fork a child and exit without joining/waiting it, as part of what they're
    // actually testing), this compounded until physical memory was exhausted: a real, reproducible
    // kernel panic (`out of memory mapping a user stack`, `map_user_stack`'s own
    // `allocate_frame().expect(...)`) partway through the corpus, confirmed via a supervised
    // multi-hour run that hit the identical panic site repeatedly regardless of which specific file
    // happened to be running when the shared frame pool finally ran dry.
    if pid == scheduler::current_pid() {
        scheduler::remove_ready(pid);
        drop(table);
        scheduler::queue_thread_reap(pid, scheduler::ReapKind::TeardownOnly);
        return;
    }
    let address_space = table.get_mut(&pid).and_then(|me| me.address_space.take());
    drop(table);
    if let Some(address_space) = address_space {
        let phys_offset = memory::phys_mem_offset();
        with_frame_allocator(|fa| unsafe { address_space.teardown(phys_offset, fa) });
    }
}

/// Wakes `child_pid`'s parent if it's blocked in `wait4` waiting on this child (or on any child) --
/// shared by `terminate_process` (a real exit) and the real stop/continue transitions in
/// `process::signals`/`do_stop_self` below (a `WUNTRACED`/`WCONTINUED`-observable state change,
/// not just exit). Spurious wakes are safe: `do_wait4`'s own loop always re-checks its real
/// condition fresh after `scheduler::schedule()` returns rather than trusting "state==Ready now"
/// to mean "my specific event happened" (see `ProcState::Stopped`'s own doc comment) -- so waking a
/// parent whose particular `wait4` call didn't actually request `WUNTRACED`/`WCONTINUED` just costs
/// it one harmless extra reschedule before it re-blocks.
pub(crate) fn wake_parent_if_waiting(table: &mut BTreeMap<Pid, Box<Process>>, child_pid: Pid) {
    let Some(parent_pid) = table.get(&child_pid).and_then(|p| p.parent) else {
        return;
    };
    let Some(parent) = table.get_mut(&parent_pid) else {
        return;
    };
    let should_wake = matches!(
        parent.state,
        ProcState::Blocked(BlockReason::WaitingForChild(target))
            if target.is_none() || target == Some(child_pid)
    );
    if should_wake {
        parent.state = ProcState::Ready;
        scheduler::enqueue_ready(parent_pid);
    }
}

/// Real self-targeted `SIGSTOP`/`SIGTSTP` (default disposition) -- reached from
/// `deliver_pending_signal`'s new `SignalDelivery::Stop` arm, the self-signal counterpart to
/// `process::signals`'s cross-process `Action::Stop` handling (`do_kill`/
/// `signal_foreground_group` -- a self-stop can only happen via an explicit
/// `kill(getpid(), SIGSTOP/SIGTSTP)`, since the interactive Ctrl+Z path always targets a
/// *different*, not-currently-running process). Sets `Stopped(signum)` + `stop_notify_pending`,
/// wakes a waiting parent, then blocks via the same `scheduler::schedule()` shape `do_nanosleep`
/// already uses -- resumes normally (does not diverge) once a later `SIGCONT` flips `state` back
/// to `Ready`.
pub(crate) fn do_stop_self(pid: Pid, signum: u64) {
    {
        let mut table = PROCESS_TABLE.lock();
        let me = table
            .get_mut(&pid)
            .expect("do_stop_self: current process missing from table");
        me.state = ProcState::Stopped(signum);
        me.stop_notify_pending = true;
        wake_parent_if_waiting(&mut table, pid);
        notify_parent_sigchld(&mut table, pid, CLD_STOPPED, signum);
    } // table lock dropped before schedule() -- see table()'s own doc comment
    scheduler::schedule();
}
/// Real Linux `reboot(2)` magic values (`external/mit/musl/include/sys/reboot.h`) -- `reboot.c`'s
/// own musl wrapper passes these straight through as the real 3rd syscall argument, no call-site
/// patch needed (see this ABI's own remap comment in `bits/syscall.h.in`).
const RB_AUTOBOOT: u64 = 0x01234567;
const RB_HALT_SYSTEM: u64 = 0xcdef0123;
const RB_POWER_OFF: u64 = 0x4321fedc;
/// The root switch (RAM_FLOOR.md §5.1): FreeBSD's `RB_REROOT` value (Linux has none). Its
/// argument, the fourth register, is a NUL-terminated `[type:]special`.
const RB_REROOT: u64 = 0x0020_0000;
/// With a reboot, halt or power off, in the fourth register: don't write the file systems'
/// delayed blocks or mark them clean (FreeBSD's `RB_NOSYNC` value; `reboot -q -n`).
const RB_NOSYNC: u64 = 0x4;

/// `SYS_REBOOT`'s real logic -- matches real Linux's own magic `cmd` values against this kernel's
/// three real actions (`sys/reboot.rs`). Root only (`EPERM` otherwise, checked before `cmd`, as
/// Linux does for `CAP_SYS_BOOT`). Every success arm diverges (`-> !`) -- the `Result` return
/// type exists only for the error cases. Each first unmounts everything and runs the modules'
/// shutdown hooks, as BSD `reboot(2)` syncs the filesystems: oxfs writes its delayed blocks and
/// marks itself clean -- unless `RB_NOSYNC` is given in the fourth register.
///
/// `RB_REROOT` switches the root file system instead (RAM_FLOOR.md §5.1). From any root process
/// (`reboot -r`) it takes the new root's `[type:]special`, looks it up (an error comes back to
/// the caller), records it and asks init with `SIGPWR`; init, its shutdown done, calls it with no
/// argument, and pid 1 ends: the supervisor unmounts everything, mounts the new root and starts
/// init on it (`init::pid1_died`).
pub fn do_reboot(cmd: u64, arg: u64) -> Result<u64, u64> {
    if crate::process::identity::oxidebsd_current_uid() != 0 {
        return Err(crate::syscall::EPERM);
    }
    if cmd == RB_REROOT {
        let caller = scheduler::current_pid();
        let is_init = PROCESS_TABLE.lock().get(&caller).is_some_and(|p| p.tgid == INIT_PID);
        if !super::init::supervised() {
            return Err(crate::syscall::EPERM);
        }
        if is_init && arg == 0 {
            // init's call, after its shutdown: the switch `reboot -r` asked for.
            if !super::init::reroot_requested() {
                return Err(EINVAL);
            }
            super::init::switch_root();
            terminate_thread_group(INIT_PID, 0);
            // As in do_exit_group: pid 1 ended itself, and a zombie must not return to user mode.
            scheduler::schedule();
            unreachable!("do_reboot: schedule() returned to pid 1 after RB_REROOT");
        }
        if arg == 0 {
            return Err(EINVAL);
        }
        let mut spec = Vec::new();
        loop {
            let mut b = [0u8; 1];
            crate::memory::usercopy::copyin(crate::memory::usercopy::UserPtr::new(arg.wrapping_add(spec.len() as u64)), &mut b)
                .map_err(|_| crate::syscall::EFAULT)?;
            if b[0] == 0 {
                break;
            }
            if spec.len() >= 1024 {
                return Err(crate::syscall::ENAMETOOLONG);
            }
            spec.push(b[0]);
        }
        let target = crate::kern::vfs_mount::reroot_target(&spec).map_err(|e| e as u64)?;
        super::init::reroot_pending(target);
        if is_init {
            super::init::switch_root();
            terminate_thread_group(INIT_PID, 0);
            scheduler::schedule();
            unreachable!("do_reboot: schedule() returned to pid 1 after RB_REROOT");
        }
        // init does the shutdown, then calls back with no argument.
        const SIGPWR: i64 = 30;
        super::signals::do_kill(caller, INIT_PID as i64, SIGPWR)?;
        return Ok(0);
    }
    if !matches!(cmd, RB_AUTOBOOT | RB_HALT_SYSTEM | RB_POWER_OFF) || arg & !RB_NOSYNC != 0 {
        return Err(EINVAL);
    }
    if arg & RB_NOSYNC == 0 {
        crate::kern::vfs_mount::unmount_all();
        crate::module::run_shutdown_hooks();
    }
    match cmd {
        RB_AUTOBOOT => crate::reboot::reboot(),
        RB_HALT_SYSTEM => crate::reboot::halt(),
        RB_POWER_OFF => crate::reboot::poweroff(),
        _ => Err(EINVAL),
    }
}
/// The calling thread group's working directory (`cwd` true) or root directory, a vnode, not
/// referenced for the caller; null for the system's root (and before any process exists).
pub(crate) fn current_dir_vnode(cwd: bool) -> *mut vfs_if::Vnode {
    let pid = scheduler::current_pid();
    if pid == 0 {
        return core::ptr::null_mut();
    }
    let raw = table().lock().get(&pid).map_or(0, |p| {
        let shared = p.shared.lock();
        if cwd { shared.cwd } else { shared.root }
    });
    raw as *mut vfs_if::Vnode
}

/// Makes `vp` (referenced by the caller, which gives the reference up; null for the system's
/// root) the calling thread group's working directory (`cwd` true) or root directory. The old
/// one's reference is released.
pub(crate) fn set_current_dir_vnode(cwd: bool, vp: *mut vfs_if::Vnode) {
    let pid = scheduler::current_pid();
    let mut vp = vp;
    if vp == crate::kern::vfs_mount::rootvnode() && !vp.is_null() {
        crate::kern::vfs_subr::vrele(vp);
        vp = core::ptr::null_mut();
    }
    if pid == 0 {
        if !vp.is_null() {
            crate::kern::vfs_subr::vrele(vp);
        }
        return;
    }
    let old = table().lock().get(&pid).map(|p| {
        let mut shared = p.shared.lock();
        let slot = if cwd { &mut shared.cwd } else { &mut shared.root };
        core::mem::replace(slot, vp as u64)
    });
    match old {
        Some(old) if old != 0 => crate::kern::vfs_subr::vrele(old as *mut vfs_if::Vnode),
        Some(_) => {}
        None if !vp.is_null() => crate::kern::vfs_subr::vrele(vp),
        None => {}
    }
}

/// The landing point for a never-run process's very first switch-in
/// (`context_switch::spawn_trampoline_asm` `call`s straight into this). Reads the current
/// process's stored entry point/user stack top and jumps into ring 3 exactly like the old one-shot
/// demo path did — `usermode::jump_to_usermode` itself is unchanged, just reached through a
/// different route now.
#[unsafe(no_mangle)]
extern "C" fn spawn_trampoline_inner() -> ! {
    let pid = scheduler::current_pid();
    if let Some((entry, stack_top)) = super::init::start_in_context(pid) {
        // SAFETY: `load_into_current` activated the program's address space just now.
        unsafe { crate::process::usermode::jump_to_usermode(entry, stack_top) }
    }
    let (entry, stack_top) = {
        let table = PROCESS_TABLE.lock();
        let p = table
            .get(&pid)
            .expect("spawn_trampoline_inner: current pid not in table");
        (p.entry_point, p.user_stack_top)
    };
    // SAFETY: this process's AddressSpace was activated (CR3) and its RSP0 repointed by
    // scheduler::start/schedule immediately before switching to it; its ELF segments and user
    // stack were mapped by spawn() when the process was created -- the same preconditions the old
    // run_userland_demo satisfied directly.
    unsafe { crate::process::usermode::jump_to_usermode(entry, stack_top) }
}
