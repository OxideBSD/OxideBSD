//! A tiny, real, kernel-authored piece of user-executable code, mapped at a fixed VA in every
//! process's own address space, purely to make real signal-handler invocation from a hardware
//! page fault possible.
//!
//! **Why this exists at all**: `interrupts::page_fault_handler` runs as `extern "x86-interrupt"`,
//! whose compiler-generated entry/exit saves and restores every clobbered register itself, with no
//! Rust-visible field for them -- unlike `syscall::SyscallFrame`, which the `SYSCALL` entry stub
//! (`syscall_entry`) builds by hand, with every GPR as an explicit, mutable field.
//! `syscall::deliver_pending_signal` already knows how to redirect a live `SyscallFrame` into a
//! real, argument-correct handler invocation (`rdi`/`rsi`/`rdx`/`rcx`/`user_rsp` all set directly)
//! -- but a page fault has no `SyscallFrame` to redirect, only an `InterruptStackFrame` whose only
//! mutable fields are `instruction_pointer`/`stack_pointer`/`cpu_flags`/the segment selectors, not
//! GPRs.
//!
//! The fix: don't try to invoke the handler directly from the fault. Instead, `page_fault_handler`
//! records the real signal as pending on the faulting process (`process::do_kill`'s own
//! self-signal path -- just sets the bit, doesn't act on it yet) and redirects the interrupted
//! context's `instruction_pointer` to land *here* instead of resuming the faulting instruction.
//! These few bytes (`mov eax, SYS_FAULT_PUMP` / `syscall`) do nothing but force the process
//! straight back through a real `SYSCALL` instruction -- landing in `syscall_entry`, which captures
//! every GPR into a genuine `SyscallFrame`, and `syscall_dispatch`, which (for this specific,
//! never-issued-by-real-userland number) skips the normal dispatch table and calls
//! `deliver_pending_signal` directly. That function then finds the signal this same fault just
//! queued and redirects the *real* `SyscallFrame` -- the exact same machinery already proven
//! correct for `kill()`-shaped signal delivery, reused verbatim rather than duplicated.
//! `stack_pointer` is left untouched (the process's own real user stack, still valid -- the
//! trampoline itself never touches it, and `SYSCALL` doesn't require any particular stack
//! contents), and `cpu_flags`/the segment selectors don't need to change either (this kernel has
//! exactly one ring-3 code/data selector pair, already correct).
//!
//! A `ud2` tail is a real safety net, not decoration: it should never execute (a fault always
//! queues a real pending signal before redirecting here, and `deliver_pending_signal` always finds
//! *something* deliverable -- worst case, default-`Terminate` disposition, which calls
//! `process::do_exit` and never returns to `syscall_return_tail` at all), so actually reaching it
//! is a real bug worth a hard stop, not a silent spin.
//!
//! **A real, second consumer since `interrupts::timer_interrupt_handler` gained its own redirect
//! into this same page** (see `Process::preempted_resume`'s own doc comment): that path, unlike
//! the page-fault one, genuinely needs the interrupted instruction to resume *transparently* --
//! but `mov eax, SYS_FAULT_PUMP` unavoidably clobbers the live, real `RAX` the interrupted code was
//! relying on (the `SYSCALL` ABI leaves no other register to carry the syscall number in, and
//! `timer_interrupt_handler`'s own `extern "x86-interrupt"` entry has no Rust-visible GPR fields to
//! save it from beforehand -- the exact same limitation this module's own doc comment above already
//! explains for why this trampoline exists at all). Found live: an earlier version of this redirect
//! didn't account for this, and a stray default-disposition signal (e.g. `SIGCHLD`) landing on
//! `hush` mid-instruction silently stomped a live computation's `RAX`, corrupting real control flow
//! with no crash to point at it. Fixed by having the trampoline itself stash the real `RAX` to
//! `RAX_SCRATCH_OFFSET` (via `MOV moffs64, RAX`, before it's clobbered) -- `syscall_dispatch`'s own
//! `SYS_FAULT_PUMP` handling reads it back and restores `frame.rax` right alongside `rcx`/`user_rsp`/
//! `r11`, but only when `Process::preempted_resume` was actually `Some` (the ordinary page-fault
//! case has no real prior `RAX` worth preserving and leaves the scratch slot unread). Runs
//! unconditionally regardless of which path redirected here -- one store is cheap, and branching
//! inside a 4-instruction trampoline to skip it buys nothing.

use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB};

use crate::memory::with_frame_allocator;

/// One page, fixed, identical in every process's own address space -- directly below
/// `mm::MMAP_REGION_BASE` (`0x_2000_0000_0000`), a huge, otherwise entirely unused canonical gap
/// far from every other fixed region this codebase hands out (`module::MODULE_VA_BASE`/
/// `_REGION_CEILING`, userland ELF load bases, `mm::BRK_REGION_CEILING`, `USER_STACK_TOP`,
/// `lifecycle::INTERP_LOAD_BASE`, `fs::sysv_shm::SHM_REGION_BASE`).
pub const FAULT_TRAMPOLINE_VA: u64 = 0x_1FFF_FFFF_F000;

/// Real length, in bytes, of the trampoline's own instruction sequence (`map`'s own `code` array
/// below) -- `interrupts::timer_interrupt_handler` uses this to recognize "currently mid-trampoline"
/// and defer preemption/redirect decisions until the thread has actually left this tiny window; see
/// `RAX_SCRATCH_OFFSET`'s own doc comment for why that matters now.
pub const CODE_LEN: u64 = 33;

/// Offset of the second-stage "restore stub" -- see `RCX_SCRATCH_OFFSET`'s own doc comment for
/// why it exists. `interrupts::timer_interrupt_handler`'s own "don't preempt mid-trampoline" guard
/// covers this range too, not just `CODE_LEN`'s own entry sequence -- the stub reads/consumes the
/// same shared scratch cells the entry sequence writes, so it's exposed to the identical
/// cross-`CLONE_THREAD`-sibling race `RAX_SCRATCH_OFFSET` already documents.
pub const STUB_OFFSET: u64 = 0x40;

/// Real length, in bytes, of the restore stub at `STUB_OFFSET`.
pub const STUB_LEN: u64 = 27;

/// Offset within the trampoline's own page where the real, pre-clobber `RAX` is stashed -- well
/// past the ~19 bytes of real code, arbitrary otherwise (nothing else ever lives on this page).
/// One frame per address space, so no cross-*process* race is possible.
///
/// **Was documented (wrongly, once real threading landed) as also race-free across threads** --
/// "single-core, so no cross-thread race is possible". True only while every `AddressSpace` was
/// exclusive to one schedulable entity; real `CLONE_THREAD` (see "Real threading") makes this page
/// the *same physical frame* for every thread sharing that address space (`AddressSpace::share`'s
/// `Arc::clone`), and single-core doesn't prevent two threads from *interleaving* through it via
/// preemption -- only from running it *simultaneously*. A thread preempted between its own
/// `mov [scratch],rax` and `syscall` leaves a live, unconsumed value sitting in this shared cell;
/// if a sibling thread of the same tgid enters the trampoline before the first one resumes and
/// reads it back, the sibling's own store clobbers it, and the first thread resumes with the
/// *sibling's* `rax` instead of its own. Found live via `pthread_mutex_trylock/4-3.c` (a real
/// `CRASH(139)` on OxideBSD that runs clean on real musl+Linux): three threads of one process
/// hammering `kill()`-driven `SIGUSR1`/`SIGUSR2` at high frequency for a full second gave enough
/// timer ticks landing mid-trampoline for this to actually happen -- a stray corrupted `rax`
/// resuming right where a compiled array-index computation (`count_ope % (NSCENAR+2)`) was about
/// to turn into a pointer, producing a wild `pthread_mutex_t*` and a real page fault one call
/// later. Confirmed by temporarily disabling `timer_interrupt_handler`'s whole async-redirect path:
/// the crash became a clean `TIMEOUT` instead (the signal simply never got delivered), ruling out
/// every other candidate.
///
/// **Mitigated, not fixed outright** -- not by giving each thread its own scratch cell, but by
/// never letting a thread be preempted while `rip` is inside `[FAULT_TRAMPOLINE_VA,
/// FAULT_TRAMPOLINE_VA + CODE_LEN)` in the first place, closing *this exact* interleaving (this
/// shared cell, this window) at its source -- see `timer_interrupt_handler`'s own guard. A 16-run
/// A/B batch of `pthread_mutex_trylock/4-3.c` in isolation confirms a real, measured improvement:
/// 10/16 (62.5%) `CRASH(139)` *without* this guard,
/// 6/16 (37.5%) *with* it -- real, but leaves a second, unisolated interleaving path into this
/// same bug class. A live-traced instance of the residual crash showed a plausible, non-garbage
/// restored `rax` from this exact redirect/restore mechanism, followed *much* later (after several
/// further, individually-correct redirect/handler/sigreturn cycles logged in between) by a fault
/// with a corrupted `rdi` holding what looks like a stray code address -- meaning the residual
/// corruption isn't this same mechanism recurring, and doesn't come from `do_clone` remapping this
/// page either (confirmed it doesn't -- `AddressSpace::share`'s `Arc::clone` is the only sharing
/// mechanism, exactly as assumed above). Every GPR round-trips correctly through `syscall_entry`'s
/// own push/pop sequence and `SyscallFrame`'s whole-struct copy in `stash_signal_context`/
/// `take_signal_saved_frame` (both independently verified by direct reading, not just inference) --
/// so the remaining corruption source is still open. Left for a follow-up investigation with more
/// live tracing (a full GPR dump spanning several complete `deliver_pending_signal`
/// handler-invoke-and-return cycles leading up to a caught crash would be the next step, ideally
/// with minimal added instrumentation -- extra `serial_println!` calls measurably perturb timing
/// enough to mask the race in smaller batches) rather than guessed at further here.
pub const RAX_SCRATCH_OFFSET: u64 = 0x100;

/// **A second, distinct bug in this same mechanism, found chasing the flaky
/// `pthread_mutex_lock/3-1.c` corruption this module's own `RAX_SCRATCH_OFFSET` doc comment left
/// open ("the remaining corruption source is still open")**: real `SYSCALL`/`SYSRETQ` hardware
/// unconditionally overwrites `RCX` with the return address and `R11` with `RFLAGS` -- not just
/// `RAX_SCRATCH_OFFSET`'s already-documented `RAX` clobber from this trampoline's own `mov eax,
/// imm32`, but the `syscall` instruction *itself*. For an ordinary, deliberate syscall a real
/// userland program issues on purpose, this is harmless and expected (every syscall wrapper stub
/// already treats `RCX`/`R11` as clobbered, matching real x86-64 ABI convention). It is *not*
/// harmless here: this trampoline exists specifically to let an *asynchronous* redirect (a timer
/// tick catching a ring-3 thread with a deliverable signal, or a page fault) transparently resume
/// code that never issued a syscall at all and had no reason to expect `RCX`/`R11` to survive --
/// exactly the class of code `pthread_mutex_lock/3-1.c`'s own `threaded()` hits, computing
/// `&m[i]` into `RCX` across several instructions (`lea rcx,[rbp-0xd0]` ... `add rax,rcx`) with no
/// syscall of its own anywhere in between. `syscall::syscall_dispatch`'s own `SYS_FAULT_PUMP`
/// handling used to set `frame.rcx = rip`/`frame.r11 = rflags` (the real *resume* target/flags,
/// needed for `SYSRETQ` to land back at the right instruction) -- but `SYSRETQ`'s own semantics
/// (`RIP := RCX`, `RFLAGS := R11`, neither register cleared afterward) mean the resumed code
/// *always* finds `RCX == RIP` at that exact instant, permanently destroying whatever real, live
/// value (like `&m[i]`) `RCX` held before the redirect -- with no `RAX_SCRATCH_OFFSET`-style
/// stash-and-restore ever protecting it. Confirmed live via a real crash-time register dump
/// (`syscall_dispatch`'s own `SYS_FAULT_PUMP` path, temporarily instrumented): `R14` (a
/// callee-saved register `threaded()` uses to carry `&m[i]` across its `pthread_mutex_lock`/
/// `pthread_mutex_unlock` calls) held a real, exact, in-range *code address* inside `threaded()`
/// itself -- exactly the shape `RCX == the interrupted resume RIP` predicts, not a random wild
/// pointer.
///
/// **The fix**: `SYSRETQ`'s `RIP := RCX` coupling makes it physically impossible to resume at an
/// arbitrary `RIP` while also handing the resumed code back its own, different, true `RCX`
/// content through the same register -- so the *final* hop back to genuinely-interrupted code
/// can't be a direct `SYSRETQ` at all. Instead, `SYS_FAULT_PUMP`'s "nothing/no-longer anything
/// deliverable, genuinely resume" path points `frame.rcx` at `STUB_OFFSET`'s own tiny
/// "restore stub" (still reached via an ordinary `SYSRETQ`, landing safely on the process's own
/// real, correct `user_rsp`) instead of the true resume `rip` directly; the true `rcx`/`r11`
/// (as plain GPR content, not `SYSRETQ`'s special reading of them)/`rflags`/final resume `rip` are
/// stashed here, in four more per-address-space scratch cells (same "one frame per address space,
/// so no cross-*process* race, but a real cross-*thread* race for a `CLONE_THREAD` sibling sharing
/// this same physical page" caveat `RAX_SCRATCH_OFFSET` already documents -- mitigated the same
/// way, not fixed outright: `interrupts::timer_interrupt_handler`'s "don't preempt mid-trampoline"
/// guard now also covers `STUB_OFFSET`'s own instruction range). If `deliver_pending_signal`
/// instead installs a real handler, it overwrites `frame.rcx` with the handler's own entry point
/// as before -- entering a fresh function call has no expectation about `RCX`'s prior content
/// either way, so that path needs no change; the stashed true values here simply survive
/// untouched (nothing but this stub itself ever reads them) until whatever handler chain
/// eventually finishes and a genuine resume is due, however many real syscalls or nested
/// deliveries happened in between.
pub const RCX_SCRATCH_OFFSET: u64 = 0x108;

/// The true, live `R11` *GPR content* (as opposed to `SYSRETQ`'s own reading of `frame.r11` as
/// "resume RFLAGS") at the moment of an async redirect -- see `RCX_SCRATCH_OFFSET`'s own doc
/// comment. `R11` suffers the identical `SYSRETQ`-coupling problem `RCX` does (real `SYSCALL`
/// hardware clobbers it for `RFLAGS` too), so it needs the same stash-and-restore treatment.
pub const R11_SCRATCH_OFFSET: u64 = 0x110;

/// The true, live `RFLAGS` at the moment of an async redirect -- a *third*, separate piece of
/// state from `R11_SCRATCH_OFFSET`'s own GPR content (two genuinely different 64-bit quantities
/// this ABI's `SyscallFrame.r11` field otherwise conflates for `SYSRETQ`'s sake alone). Restored
/// via a real `push`+`popfq` in the restore stub, not a `mov` (`RFLAGS` can't be loaded directly
/// from memory) -- matters for a thread resumed exactly between a flag-setting instruction (`cmp`/
/// `test`/...) and the conditional branch reading it.
pub const TRUE_RFLAGS_OFFSET: u64 = 0x118;

/// The real, final resume `rip` the restore stub's own trailing indirect `jmp` reads -- see
/// `RCX_SCRATCH_OFFSET`'s own doc comment. Distinct from `Process::preempted_resume`'s `rip` field
/// (which is consumed once, by `syscall_dispatch`'s `SYS_FAULT_PUMP` handling, and copied here for
/// the stub to use however many handler invocations/syscalls/nested deliveries happen before a
/// genuine resume is actually due).
pub const TRUE_RESUME_RIP_OFFSET: u64 = 0x120;

/// Maps `FAULT_TRAMPOLINE_VA` into `mapper`'s own (not-yet-active) address space with real
/// `mov [FAULT_TRAMPOLINE_VA + RAX_SCRATCH_OFFSET], rax; mov eax, SYS_FAULT_PUMP; syscall; ud2`
/// bytes -- called once per fresh address space (`process::spawn` at boot, `do_execve` on every
/// exec; a forked child gets its own copy for free, same as every other user page, via
/// `AddressSpace::fork`'s existing full eager copy of `USER_ACCESSIBLE` content). **Now real
/// `WRITABLE`** -- the leading `RAX`-stashing store needs it (this kernel has no W^X enforcement
/// anywhere regardless, see CLAUDE.md's own note on `elf::load`, so this costs nothing).
///
/// # Errors
///
/// `Err(())` on real frame exhaustion -- same "a real resource limit must fail one syscall, not
/// panic the kernel" motivation as `process::KernelStack::new`/`AddressSpace::build_from_active`.
/// `do_execve`'s own caller propagates this as a real `ENOMEM`; `spawn`'s boot-time call site
/// still panics (no syscall caller to report to that early, matching every other boot-time
/// allocation site).
#[allow(clippy::result_unit_err)] // see AddressSpace::new's own identical allow.
pub fn map(mapper: &mut impl Mapper<Size4KiB>, phys_offset: VirtAddr) -> Result<(), ()> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(FAULT_TRAMPOLINE_VA));
    with_frame_allocator(|fa| {
        let frame = fa.allocate_frame().ok_or(())?;
        // SAFETY: frame was just allocated (unused, per BootInfoFrameAllocator's contract), and
        // page falls in this address space's own, not-yet-active, otherwise-unused VA range.
        let flush = unsafe {
            mapper.map_to(
                page,
                frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE,
                fa,
            )
        };
        match flush {
            // Real, resource-exhaustion-triggerable: map_to's own internal page-table-structure
            // allocation (for this page's not-yet-existing PT/PD/PDPT entries) can hit the exact
            // same frame exhaustion this whole function exists to report as a real ENOMEM, not a
            // kernel panic -- same reasoning as the leaf frame allocation just above.
            Err(x86_64::structures::paging::mapper::MapToError::FrameAllocationFailed) => {
                return Err(());
            }
            // Anything else (ParentEntryHugePage/PageAlreadyMapped) is a real logic-invariant
            // violation, not a resource limit -- this VA is always fresh in a brand-new address
            // space, so hitting either means a future change broke that assumption, worth a loud
            // panic rather than a silently-wrong ENOMEM.
            Err(e) => panic!("failed to map the fault trampoline page: {e:?}"),
            Ok(flush) => flush.flush(),
        }
        let frame_ptr = (phys_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
        let imm = (crate::syscall::SYS_FAULT_PUMP as u32).to_le_bytes();
        let scratch_addr = (FAULT_TRAMPOLINE_VA + RAX_SCRATCH_OFFSET).to_le_bytes();
        // RIP-relative displacements: the byte offset from "the address of the instruction right
        // after this one" to the target -- independent of `FAULT_TRAMPOLINE_VA`'s own actual
        // value, since both ends of the subtraction share it. `verified against a real assembler
        // (`as`/`objdump`) before landing, not hand-encoded from memory alone.
        let disp = |instr_end_offset: u64, target_offset: u64| -> [u8; 4] {
            ((target_offset as i64 - instr_end_offset as i64) as i32).to_le_bytes()
        };
        let d_rcx_store = disp(0x11, RCX_SCRATCH_OFFSET); // mov [rip+d], rcx -- entry, ends at 0x11
        let d_r11_store = disp(0x18, R11_SCRATCH_OFFSET); // mov [rip+d], r11 -- entry, ends at 0x18
        #[rustfmt::skip]
        let code: [u8; CODE_LEN as usize] = [
            0x48, 0xA3, scratch_addr[0], scratch_addr[1], scratch_addr[2], scratch_addr[3],
                        scratch_addr[4], scratch_addr[5], scratch_addr[6], scratch_addr[7],
                                              // mov [RAX_SCRATCH_OFFSET], rax -- see this
                                              // module's own doc comment
            0x48, 0x89, 0x0D, d_rcx_store[0], d_rcx_store[1], d_rcx_store[2], d_rcx_store[3],
                                              // mov [rip+d], rcx -- see RCX_SCRATCH_OFFSET's doc
            0x4C, 0x89, 0x1D, d_r11_store[0], d_r11_store[1], d_r11_store[2], d_r11_store[3],
                                              // mov [rip+d], r11 -- see R11_SCRATCH_OFFSET's doc
            0xB8, imm[0], imm[1], imm[2], imm[3], // mov eax, imm32
            0x0F, 0x05,                           // syscall
            0x0F, 0x0B,                           // ud2 -- see this module's own doc comment
        ];
        assert_eq!(
            code.len() as u64,
            CODE_LEN,
            "CODE_LEN drifted from the real trampoline encoding"
        );

        // The restore stub (`STUB_OFFSET`'s own doc comment): reached via an ordinary `SYSRETQ`
        // when `syscall_dispatch`'s `SYS_FAULT_PUMP` handling decides nothing further needs
        // delivering and it's time to genuinely resume -- restores the true `rcx`/`r11`/`rflags`
        // this trampoline's own entry sequence stashed, then jumps to the true resume `rip`,
        // entirely bypassing `SYSRETQ`'s own `RIP := RCX` coupling for this final hop.
        let d_rcx_load = disp(STUB_OFFSET + 0x07, RCX_SCRATCH_OFFSET); // mov rcx,[rip+d]
        let d_r11_load = disp(STUB_OFFSET + 0x0E, R11_SCRATCH_OFFSET); // mov r11,[rip+d]
        let d_rflags = disp(STUB_OFFSET + 0x14, TRUE_RFLAGS_OFFSET); // push [rip+d]
        let d_resume_rip = disp(STUB_OFFSET + 0x1B, TRUE_RESUME_RIP_OFFSET); // jmp [rip+d]
        #[rustfmt::skip]
        let stub: [u8; STUB_LEN as usize] = [
            0x48, 0x8B, 0x0D, d_rcx_load[0], d_rcx_load[1], d_rcx_load[2], d_rcx_load[3],
                                              // mov rcx, [rip+d]
            0x4C, 0x8B, 0x1D, d_r11_load[0], d_r11_load[1], d_r11_load[2], d_r11_load[3],
                                              // mov r11, [rip+d]
            0xFF, 0x35, d_rflags[0], d_rflags[1], d_rflags[2], d_rflags[3],
                                              // push QWORD PTR [rip+d]
            0x9D,                             // popfq
            0xFF, 0x25, d_resume_rip[0], d_resume_rip[1], d_resume_rip[2], d_resume_rip[3],
                                              // jmp QWORD PTR [rip+d]
        ];
        assert_eq!(
            stub.len() as u64,
            STUB_LEN,
            "STUB_LEN drifted from the real stub encoding"
        );

        // SAFETY: frame_ptr points at the whole, just-allocated, not-yet-active 4096-byte frame.
        unsafe {
            core::ptr::write_bytes(frame_ptr, 0, 4096);
            core::ptr::copy_nonoverlapping(code.as_ptr(), frame_ptr, code.len());
            core::ptr::copy_nonoverlapping(
                stub.as_ptr(),
                frame_ptr.add(STUB_OFFSET as usize),
                stub.len(),
            );
        }
        Ok(())
    })
}
