//! OxideBSD's native syscall ABI: `SYSCALL`/`SYSRETQ`, syscall number in `RAX`, up to four
//! arguments in `RDI`/`RSI`/`RDX`/`R10`, success/failure signaled via the **carry flag** — the
//! traditional BSD (and general historical x86 Unix) convention, layered on top of the modern
//! fast-syscall instruction pair instead of the legacy `int 0x80` software-interrupt gate this
//! kernel used up through its first process/scheduler milestone. On success, `CF = 0` and `RAX`
//! holds the return value; on failure, `CF = 1` and `RAX` holds the *positive* `errno`. Register
//! placement (`RDI`/`RSI`/`RDX`/`R10`, avoiding `RCX`/`R11` since `SYSCALL` itself clobbers them
//! to save `RIP`/`RFLAGS`) mirrors real BSD's own `SYSCALL`-based convention.
//!
//! **`R10` used to be reserved but unread** — the entry stub always pushed it (uniform GPR
//! save/restore, see `SyscallFrame`'s own doc comment), but `syscall_dispatch`/`dispatch` only
//! ever forwarded `RDI`/`RSI`/`RDX` to a handler. Wired up for real once `SYS_EXECVE` needed a 4th
//! argument (`envp_ptr`, alongside the existing `path_ptr`/`path_len`/`argv_ptr`) to support real
//! `envp` passthrough — see `CLAUDE.md`'s BusyBox section. `SyscallHandler` is now a 4-argument
//! function pointer; every registered handler across every module gained a 4th parameter (ignored
//! by every syscall except `execve`), not just `execve`'s own — a real 4th argument is now a
//! permanent part of this ABI, available to any future syscall that needs one, not a one-off
//! special case threaded through only where `execve` needed it.
//!
//! **This mechanism used to be split across two files**: this module's own `int 0x80` gate, and a
//! separate `src/linux_syscall.rs` that proved the `SYSCALL`/`SYSRETQ` mechanism in isolation
//! (Linux's numbering, negative-`RAX` error convention — deliberately different from this ABI, as
//! a stepping stone toward eventually running unmodified Linux binaries). That plan changed: this
//! kernel is instead porting musl to speak *this* ABI directly (see `CLAUDE.md`'s "musl" section),
//! so there was no longer a reason to keep two different syscall-numbering/error conventions each
//! tied to a different trap instruction. `IA32_LSTAR` can only point at one entry stub, so this
//! ABI now **owns** the `SYSCALL`/`SYSRETQ` mechanism outright — `src/linux_syscall.rs` and its
//! dedicated `regress/linux-syscall-smoke/` test are gone, having already served their purpose of
//! proving the mechanism (`IA32_STAR`/`LSTAR`/`SFMASK` setup, the GDT segment-ordering
//! requirement, the stack-switch-on-entry problem) works at all.
//!
//! Syscall numbers match real FreeBSD's long-stable values for the calls implemented so far, as a
//! deliberate nod to authenticity — not a claim of binary compatibility with real BSD userland
//! (newer syscalls this ABI invents for itself, e.g. `mmap`/`brk`/TLS-base-set, don't extend that
//! convention — see `sys/modules/native_abi/`). errno values are *mostly* shared across Linux and the
//! BSDs (`EBADF`, `EINVAL` are identical), but not universally — `ENOSYS` is `38` on Linux, `78` on
//! FreeBSD. **`ENOSYS` itself uses the Linux/musl value (`38`), not the FreeBSD one** — the one
//! deliberate exception to this file's own "FreeBSD authenticity" framing, fixed after it was found
//! live blocking real functionality: whatever this file returns via the carry-flag ABI becomes
//! musl's raw `errno` directly (see `EPROTONOSUPPORT`'s own doc comment below for the full
//! mechanism), so a FreeBSD-authentic-but-musl-wrong value here isn't just cosmetic — BusyBox's own
//! `libbb/change_identity.c` has a real upstream fallback (`errno == ENOSYS && target_uid ==
//! getuid()` → treat a failed `initgroups()` as a harmless no-op, the correct behavior on a kernel
//! with no supplementary-group concept, real Linux's own convention for `CONFIG_MULTIUSER=n`) that
//! silently never fired while this returned FreeBSD's `78` instead of musl's real `38`, making `su`
//! die outright instead of degrading gracefully. Was previously deliberately left unfixed pending a
//! wider scope discussion (this constant is referenced far more broadly than the group below) —
//! fixed once a live test demonstrated a concrete functional blocker, not as a preemptive sweep.
//!
//! **The number → handler mapping (`dispatch`'s table) is populated by a dynamically loaded
//! kernel module, not hardcoded here.** `sys/modules/native_abi/` registers `SYS_EXIT`/`SYS_READ`/
//! `SYS_WRITE`/etc. via `oxidebsd_register_syscall` from its own `module_init` — see `CLAUDE.md`'s
//! module-loading section. What stays kernel-resident, deliberately *not* moved into that module,
//! is the actual `sys_exit`/`sys_read`/`sys_write` *behavior*, in `ffi.rs` alongside this file's
//! other syscall-handler implementations. `oxidebsd_sys_exit`/`oxidebsd_sys_read`/
//! `oxidebsd_sys_write` in that same file are the thin FFI adapters the module actually calls
//! through.
//!
//! This file itself (`mod.rs`) is just the real ABI mechanism: `SyscallFrame`, the `SYSCALL`/
//! `SYSRETQ` entry stub and its dispatch table, `redirect_frame`/signal delivery, and errno
//! constants — see `ffi.rs` for every actual syscall handler this kernel implements directly
//! (rather than delegating straight to `process::do_*`).

pub mod ffi;

pub use ffi::*;

use alloc::collections::{BTreeMap, BTreeSet};
use core::arch::global_asm;
use core::sync::atomic::{AtomicPtr, Ordering};

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

use crate::cpu::gdt;
/// musl's own `siginfo_t` on x86_64, real sender-identity/payload-populated now -- lives in
/// `crate::process` (`RawSiginfo`) since `process::signals`'s own `do_sigtimedwait`/`do_sigqueue`
/// need the exact same wire layout; re-imported here under its original name rather than every
/// call site in this file growing a `crate::process::` prefix.
use crate::process::RawSiginfo;
use crate::serial_println;

/// Standard, POSIX-heritage errno values. `EBADF`/`EINVAL`/`ECHILD`/`ENOEXEC`/`EPIPE` happen to be
/// identical on Linux and the BSDs; `ENOSYS` is not (see module doc comment) — unlike this group's
/// other members, it uses musl's real Linux value (`38`), not FreeBSD's (`78`).
pub(crate) const EBADF: u64 = 9;
pub(crate) const EINVAL: u64 = 22;
pub(crate) const ENOSYS: u64 = 38;
/// Identical on Linux and the BSDs. Real POSIX `pread`/`pwrite`'s own documented errno for a fd
/// that "is associated with a pipe, FIFO, or socket" (or, in this codebase, any other fd kind with
/// no real seekable position) -- see `crate::fs::fd::FdReadWriteAt`'s own doc comment.
pub(crate) const ESPIPE: u64 = 29;
/// Identical on Linux and the BSDs. This codebase's usual convention for a bad user pointer is to
/// let the real dereference page-fault and go through the real ring-3 fault-to-signal path (see
/// CLAUDE.md's "Real ring-3 fault-to-signal delivery" section) rather than pre-validate — but a
/// handler whose own output pointer is *required*, not optional (unlike `getrlimit`'s `old_limit`/
/// `sigaction`'s `oldact`/etc., which already treat a null pointer as "caller doesn't want this
/// back" and simply skip the write), needs a real, explicit check first: found live via
/// `sched_getparam/speculative/7-1.c`'s deliberate null `param` — Rust's own debug-mode UB check on
/// `ptr::write_unaligned` intercepts a null destination *before* the write ever reaches real
/// hardware (only the alignment half of its precondition is waived, not the non-null half),
/// panicking the whole kernel instead of the intended "the one offending process page-faults" —
/// this constant exists so those specific call sites can return a real `EFAULT` instead of ever
/// attempting the write.
pub(crate) const EFAULT: u64 = 14;
pub(crate) const ECHILD: u64 = 10;
pub(crate) const ENOEXEC: u64 = 8;
pub(crate) const ENOMEM: u64 = 12;
/// Used by `process::mm::do_mmap`'s real fd-backed path: a real, open fd that isn't backed by an
/// identifiable file (`crate::fs::fd::content_id_of` returns `None` -- a pipe, socket, console,
/// or a brand-new not-yet-committed write fd, see that function's own doc comment). Same value on
/// Linux and the BSDs.
pub(crate) const ENODEV: u64 = 19;
/// Returned by `crate::fs::pipe`'s `pipe_write` once a pipe's read end has been closed.
pub(crate) const EPIPE: u64 = 32;
/// Returned by `sys_kill` when the target pid doesn't exist -- "no such process," identical on
/// Linux and the BSDs.
pub(crate) const ESRCH: u64 = 3;
/// Returned by `sys_ioctl` for a tty-specific request issued against a non-console fd -- identical
/// on Linux and the BSDs, same as most of this group.
pub(crate) const ENOTTY: u64 = 25;
/// Returned by `sys_socketpair` for any domain/type other than `AF_UNIX`/`SOCK_STREAM`. `93`, not
/// FreeBSD's `43` (unlike this group's other members, Linux and the BSDs actually diverge here) --
/// matches the value musl's own compiled-in `bits/errno.h` (`external/mit/musl/arch/generic/bits/
/// errno.h`, since no x86_64-specific override exists) will compare `errno` against, which is what
/// actually matters: whatever this file returns via the carry-flag ABI becomes musl's raw `errno`
/// value directly (see `external/mit/musl/arch/x86_64/syscall_arch.h`'s `jnc`/`neg` conversion), so
/// it must match musl's *own* macro value, not a real-BSD-authenticity nod like `ENOSYS` below is.
/// `sys/net/udp.rs`'s own local copy of this constant (previously `43`, following this file's now-
/// corrected mistake) needs the same fix.
pub(crate) const EPROTONOSUPPORT: u64 = 93;
/// Returned by `crate::fs::pipe`'s `blocking_read` for a real `O_NONBLOCK` fd (`sys_fcntl`) with
/// nothing to read yet. `11`, matching musl's own compiled-in value (`EWOULDBLOCK` is the same
/// value there too) -- same "must match musl's macro, not real-BSD numbering" reasoning as
/// `EPROTONOSUPPORT` above.
pub(crate) const EAGAIN: u64 = 11;
/// Returned by `sys_shutdown` for any fd that isn't one of `crate::fs::pipe`'s `AF_UNIX` socketpair
/// endpoints (a TCP/UDP socket, a plain pipe end, a regular oxfs file, ...) -- this pass only
/// implements real half-close semantics for the socketpair shape `wget`'s HTTPS path actually
/// needs, not real sockets. `88`, matching musl's own compiled-in value, same reasoning as
/// `EPROTONOSUPPORT`/`EAGAIN` above.
pub(crate) const ENOTSOCK: u64 = 88;
/// Returned by `process::do_setuid`/`do_setgid` when a non-root caller tries to become a uid/gid
/// other than its own -- identical value on Linux/BSD/musl, no divergence to worry about, unlike
/// most of this group's other members.
pub(crate) const EPERM: u64 = 1;
/// Returned by `process::do_execve` when a `#!`-line interpreter chain (a script whose own
/// interpreter is itself another `#!`-line script) nests deeper than `do_execve`'s own
/// `MAX_SHEBANG_DEPTH` -- matches real Linux's own `ELOOP` for excessive `binfmt_script`
/// recursion. `40`, musl's real compiled value (identical to `sys/modules/oxfs`'s own local copy of
/// this constant for symlink-depth overflow, same reasoning as `EPROTONOSUPPORT`/`EAGAIN` above:
/// must match musl's macro, not a real-BSD nod).
pub(crate) const ELOOP: u64 = 40;
/// Returned by `process::do_pause` once a deliverable signal wakes it -- real `pause(2)`'s only
/// possible return value. `4`, identical on Linux/BSD/musl, no divergence to worry about.
pub(crate) const EINTR: u64 = 4;
/// Returned by `crate::fs::mqueue`'s `do_mq_open` (no `O_CREAT`, name not found) / `do_mq_unlink`
/// (name not found). `2`, identical on Linux/BSD/musl.
pub(crate) const ENOENT: u64 = 2;
/// Returned by `crate::fs::mqueue`'s `do_mq_open` (`O_CREAT | O_EXCL` against an already-existing
/// name). `17`, identical on Linux/BSD/musl.
pub(crate) const EEXIST: u64 = 17;
/// Returned by `crate::fs::mqueue`'s `do_mq_notify` when a second process tries to register a
/// notification while one is already live -- real POSIX `mq_notify(3)`'s own documented error for
/// this case. `16`, identical on Linux/BSD/musl.
pub(crate) const EBUSY: u64 = 16;
/// Returned by `crate::fs::mqueue`'s `do_mq_timedsend` (message longer than the queue's own
/// `mq_msgsize`) / `do_mq_timedreceive` (caller's buffer shorter than it). `90`, matching musl's
/// own compiled-in value -- same "must match musl's macro, not a real-BSD nod" reasoning
/// `EPROTONOSUPPORT`/`EAGAIN` above already establish.
pub(crate) const EMSGSIZE: u64 = 90;
/// Returned by `crate::fs::mqueue`'s `do_mq_timedsend`/`do_mq_timedreceive` once a real
/// `TIMER_ABSTIME`-style deadline (the `at` argument) passes while still blocked. `110`, matching
/// musl's own compiled-in value, same reasoning as `EMSGSIZE` just above.
pub(crate) const ETIMEDOUT: u64 = 110;
/// Returned by `crate::fs::sysv_msg`'s permission checks (`msgsnd`/`msgrcv` against the real
/// `ipc_perm` rwx-style bits, `msgctl`'s `IPC_SET`/`IPC_RMID` against owner/creator/root). `13`,
/// identical on Linux/BSD/musl.
pub(crate) const EACCES: u64 = 13;
/// Returned by `crate::fs::sysv_msg`'s `msgsnd` (a message longer than the queue's own hard
/// `msgmax` cap -- a single message can never fit regardless of queue occupancy) / `msgrcv` (the
/// received message is longer than the caller's buffer and `MSG_NOERROR` wasn't set). `7`,
/// matching musl's own compiled-in value, same "must match musl's macro, not a real-BSD nod"
/// reasoning `EPROTONOSUPPORT`/`EAGAIN` above already establish.
pub(crate) const E2BIG: u64 = 7;
/// Returned by `crate::fs::sysv_msg`'s `msgrcv` for a real `IPC_NOWAIT` call with no matching
/// message available. `42`, matching musl's own compiled-in value, same reasoning as `E2BIG`.
pub(crate) const ENOMSG: u64 = 42;
/// Returned by `crate::fs::sysv_msg`'s `msgsnd`/`msgrcv` once a real `msgctl(IPC_RMID)` removes
/// the queue out from under a still-blocked caller -- real SysV IPC semantics. `43`, matching
/// musl's own compiled-in value, same reasoning as `E2BIG`.
pub(crate) const EIDRM: u64 = 43;
/// Returned by `crate::fs::sysv_sem`'s `semop`/`semtimedop` for a `sem_num` outside the target
/// set's own real `nsems` -- real SysV IPC's own (slightly surprising, but documented) choice of
/// errno for this case, not `EINVAL`. `27`, matching musl's own compiled-in value, same
/// must-match-musl reasoning `E2BIG`/`ENOMSG`/`EIDRM` above already establish.
pub(crate) const EFBIG: u64 = 27;
/// Returned by `crate::fs::sysv_sem`'s `semctl(SETVAL)`/`semop`'s own `SEM_UNDO` accumulation path
/// when a value would fall outside real SysV's `[0, SEMVMX]` range. `34`, matching musl's own
/// compiled-in value, same reasoning as `EFBIG`.
pub(crate) const ERANGE: u64 = 34;
/// Returned by `process::mm::do_mmap_file_backed` for a real `mmap(2)` request with a nonzero
/// `off` whose `[off, off+len)` range genuinely doesn't fit within the target object's own real
/// size (`mmap/28-1.c`) — deliberately not raised for `off == 0`, real POSIX MPR territory
/// instead (see that function's own doc comment). `6`, identical on Linux/BSD/musl (matches
/// `sys/modules/oxfs`'s own local copy of this constant, used for its unrelated `ENXIO`-on-`open()`
/// device-node case).
pub(crate) const ENXIO: u64 = 6;
/// Returned by `process::mm::do_mmap_file_backed` when a real `off`/`len` combination against a
/// regular file exceeds the real offset maximum this ABI's `off_t` (a 64-bit signed type, matching
/// musl's own x86_64 `off_t`) can represent (`mmap/31-1.c`) — checked kernel-side now that
/// `external/mit/musl`'s own `mmap.c` no longer pre-empts this with a blanket `ENOMEM` before the
/// syscall is even issued (see that file's own doc comment for why). `75`, identical on Linux/BSD/
/// musl.
pub(crate) const EOVERFLOW: u64 = 75;
/// Real value, identical across Linux/BSD/musl -- a name exceeding an interface's own length
/// ceiling (`mq_open/27-1.c`: `mq_open()` given a name longer than `PATH_MAX`).
pub(crate) const ENAMETOOLONG: u64 = 36;

/// A registered syscall handler's own FFI return convention: negative is `-errno`, non-negative
/// is the success value. Deliberately distinct from the public syscall ABI's own carry-flag
/// convention (see this file's module doc comment) — it's purely this internal module↔kernel
/// registration boundary's own shape, chosen because it's representable in a plain scalar FFI
/// return without a `#[repr(C)]` result struct.
pub type SyscallHandler = extern "C" fn(u64, u64, u64, u64) -> i64;

static SYSCALL_TABLE: Mutex<BTreeMap<u64, SyscallHandler>> = Mutex::new(BTreeMap::new());

/// Registers `handler` for `number` in the table `dispatch` consults. `pub`, not `pub(crate)`:
/// the primary caller is a loaded module's `module_init` (currently `sys/modules/native_abi/`,
/// crossing the module-relocation FFI boundary) populating what used to be `dispatch`'s own
/// hardcoded `match`, but integration tests under `tests/` (a separate crate linking against this
/// one) also need to register test-only syscall numbers directly — see `tests/fork_wait.rs`'s
/// `SYS_TEST_EXIT` handler, which sidesteps the fact that `scheduler::start`/`process::do_exit`
/// never return control to a test's own `main` the way a normal QEMU-exit-based test does.
/// Returns `0` on success, `-1` if `number` is already registered: nothing registers the same
/// number twice today, but silently overwriting a handler would be a far more confusing failure
/// mode than refusing outright.
pub extern "C" fn oxidebsd_register_syscall(number: u64, handler: SyscallHandler) -> i32 {
    let mut table = SYSCALL_TABLE.lock();
    if table.contains_key(&number) {
        return -1;
    }
    table.insert(number, handler);
    0
}

/// RFLAGS bit 0.
const CARRY_FLAG: u64 = 1;

/// Configures `SYSCALL`/`SYSRETQ`: `IA32_STAR` (from the real GDT selectors — `sys/cpu/gdt.rs`'s
/// segment ordering exists specifically to satisfy `SYSRETQ`'s fixed-offset selector-reconstruction
/// scheme; `Star::write` validates this and fails loudly rather than silently misprogramming it),
/// `IA32_LSTAR` (this file's own `syscall_entry`), `IA32_SFMASK` (clears `RFLAGS::INTERRUPT_FLAG`
/// on entry, same as the old `int 0x80` gate did), and `EFER.SCE` — without which `SYSCALL` raises
/// `#UD` (handled, fatally, by `invalid_opcode_handler`), so forgetting this step fails loudly.
pub fn init() {
    serial_println!("[boot] configuring SYSCALL/SYSRETQ (native ABI)");

    // SAFETY: kernel_code_selector/kernel_data_selector are DPL 0, user_code_selector/
    // user_data_selector are DPL 3, and sys/cpu/gdt.rs lays the GDT out specifically so their
    // offsets satisfy Star::write's own validation -- an error here means the GDT layout regressed.
    Star::write(
        gdt::user_code_selector(),
        gdt::user_data_selector(),
        gdt::kernel_code_selector(),
        gdt::kernel_data_selector(),
    )
    .expect("IA32_STAR: GDT layout doesn't satisfy SYSCALL/SYSRETQ's fixed offset scheme");

    let entry_addr = VirtAddr::new(syscall_entry as *const () as u64);
    LStar::write(entry_addr);
    SFMask::write(RFlags::INTERRUPT_FLAG);

    // SAFETY: STAR/LSTAR/SFMASK are all configured above; enabling SCE now is what actually makes
    // SYSCALL start dispatching to syscall_entry instead of raising #UD.
    unsafe { Efer::update(|flags| flags.insert(EferFlags::SYSTEM_CALL_EXTENSIONS)) };

    serial_println!("[boot] SYSCALL/SYSRETQ ready");
}

unsafe extern "C" {
    /// Defined in the `global_asm!` block below: switches onto the current process's own kernel
    /// stack (`SYSCALL` doesn't do this automatically the way an interrupt gate + TSS `RSP0`
    /// does), saves every general-purpose register plus the user's own `RSP`, calls
    /// `syscall_dispatch` with a pointer to them, restores everything, and `SYSRETQ`s back to
    /// whatever issued `SYSCALL`.
    pub fn syscall_entry();
}

/// The saved register state `syscall_entry` hands to `syscall_dispatch`, as a single pointer
/// (`RDI`, System V's first argument register) rather than loose arguments — `RAX`-for-number and
/// `RDI`/`RSI`/`RDX`-for-args don't line up with System V's own `call` convention closely enough
/// to just pass straight through, and this shape doubles as the mechanism for the carry-flag
/// trick below. Field order matches the entry stub's push order exactly (last pushed = lowest
/// address = first field). Two fields do double duty, both forced by `SYSCALL`'s own hardware
/// contract rather than a choice made here: `rcx` holds the user `RIP` to resume at (`SYSCALL`
/// clobbers real `RCX` with it on entry, so whatever the user program's actual `RCX` held before
/// the call is unrecoverable — the same reason every userland syscall stub declares `RCX`
/// clobbered), and `r11` holds the user `RFLAGS` (same story) — `SYSRETQ` reads both back
/// directly from registers, not from memory, so `syscall_dispatch` flips bit 0 of the saved `r11`
/// value to signal `CF` exactly the way it used to flip a dedicated `rflags` field for `iretq`.
/// `user_rsp` is the one genuinely new field: `SYSCALL` doesn't switch stacks the way an
/// interrupt gate does, so the entry stub has to save/restore the user's `RSP` itself (see
/// `gdt::CURRENT_RSP0`), and unlike `RCX`/`R11` there's no GPR slot already carrying it.
// pub(crate), not private: sys/process/context_switch.rs needs to name this type (to size a fork
// child's seeded stack region and to type its `parent_frame`/`dst` pointers) without being able to
// touch its fields directly -- field access stays private to this module; only
// `copy_frame_for_fork`/`redirect_frame`/`current_frame` below cross that boundary, deliberately
// narrow.
//
// `Clone`/`Copy`: lets `process::Process` hold a `signal_stack: Vec<SignalStackFrame>` of these
// snapshots (moved/copied by value, never needing field access outside this module) for signal
// delivery/`sigreturn` -- see `deliver_pending_signal`/`do_sigreturn` below.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct SyscallFrame {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,
    user_rsp: u64,
}

/// The in-flight syscall's own `SyscallFrame`, valid only between `syscall_dispatch` storing it
/// and returning. `SyscallHandler`'s `(u64, u64, u64) -> i64` signature can't carry a frame
/// pointer, but `sys_fork`/`sys_execve`/`process::lifecycle::do_clone` all need raw access to the
/// live frame (fork copies it into the child's own kernel stack; execve overwrites `rip`/`rsp` in
/// place; `do_clone` does the same as fork, plus reads `r8` for `tls` — the one real `clone(2)`
/// argument that doesn't fit this ABI's normal 4-register `dispatch()` path, see `frame_tls`'s own
/// doc comment) — a narrow, explicit exception for these three, not a signature change for every
/// syscall.
/// Plain `AtomicPtr`, not a lock: this is single-core and `SYSFMASK` clears `RFLAGS::INTERRUPT_FLAG`
/// on every `SYSCALL` entry, so nothing can preempt a syscall in progress to observe a
/// half-updated value (same reasoning `sys/console/stdin.rs`'s ring buffer doc comment already
/// relies on).
static CURRENT_FRAME: AtomicPtr<SyscallFrame> = AtomicPtr::new(core::ptr::null_mut());

/// The currently in-flight syscall's frame — only valid to call from within a syscall handler
/// (i.e. from code reachable through `dispatch`), and only for as long as that handler is still
/// running.
pub(crate) fn current_frame() -> *mut SyscallFrame {
    CURRENT_FRAME.load(Ordering::Relaxed)
}

/// Copies `*src` into `*dst` (byte-for-byte, all 16 fields), then forces the copy's `rax` to `0`
/// *and* clears its `CARRY_FLAG` bit (in the copy's `r11` field, which doubles as the saved
/// `RFLAGS` — see `SyscallFrame`'s own doc comment) — used by `sys_fork` to seed a forked child's
/// kernel stack so its first-ever "return" looks exactly like returning from the same `fork()`
/// call the parent made, but with a clean success return (child pid `0`) of its own. Clearing
/// `CARRY_FLAG` explicitly matters, not just zeroing `rax`: at the moment this runs, `*src`'s
/// `r11` still holds whatever `CF` happened to be *before* the parent ever executed `SYSCALL` for
/// this `fork()` call (ordinary instructions like `mov` don't touch `EFLAGS`, so that bit is
/// really just leftover state from earlier in the parent's execution, not anything this syscall
/// itself set yet — `syscall_dispatch`'s own CF-clearing/setting for the *parent's* return happens
/// later, after `dispatch()`/`do_fork_from_current` returns, and only touches the parent's live
/// frame, never this copy). Without this, the child could spuriously see `Err` from a stale `CF`
/// bit that predates the call entirely. `dst` is raw, uninitialized stack memory (not yet a live
/// `SyscallFrame` reference), so this writes through pointers rather than going through `&mut`.
///
/// # Safety
///
/// `dst` must point at `size_of::<SyscallFrame>()` writable bytes; `src` must point at a valid,
/// fully-initialized `SyscallFrame`.
pub(crate) unsafe fn copy_frame_for_fork(dst: *mut SyscallFrame, src: *const SyscallFrame) {
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, 1);
        (*dst).rax = 0;
        (*dst).r11 &= !CARRY_FLAG;
    }
}

/// `copy_frame_for_fork`'s sibling for real `clone(2)`/`CLONE_THREAD` (`process::lifecycle::
/// do_clone`) — identical body, plus one extra override: `user_rsp` comes from the real `newsp`
/// argument the caller passed to `clone(2)`, not copied from the parent (a cloned thread starts on
/// its own, caller-supplied stack, unlike `fork`'s child, which keeps running on a byte-for-byte
/// copy of the parent's own stack).
///
/// # Safety
///
/// Same contract as `copy_frame_for_fork`: `dst` must point at `size_of::<SyscallFrame>()`
/// writable bytes; `src` must point at a valid, fully-initialized `SyscallFrame`.
pub(crate) unsafe fn copy_frame_for_clone(
    dst: *mut SyscallFrame,
    src: *const SyscallFrame,
    new_user_rsp: u64,
) {
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, 1);
        (*dst).rax = 0;
        (*dst).r11 &= !CARRY_FLAG;
        (*dst).user_rsp = new_user_rsp;
    }
}

/// Reads `r8` out of a raw `SyscallFrame` — `do_clone`'s real `tls` argument (`CLONE_SETTLS`)
/// lands there (see `clone.s`'s own register shuffle, `external/mit/musl/src/thread/x86_64/
/// clone.s`), one register past what this ABI's normal 4-argument `dispatch()` path threads
/// through (`rdi`/`rsi`/`rdx`/`r10`) — so, like `sys_fork`/`sys_execve` needing the whole frame to
/// seed/redirect it, `do_clone` needs this one extra field via the same raw-frame-access route
/// (`current_frame()`) rather than a 5th `dispatch()` argument that doesn't exist.
///
/// # Safety
///
/// `frame` must point at the currently in-flight syscall's live frame (i.e. `current_frame()`'s
/// return value, called from within that same syscall's handling).
pub(crate) unsafe fn frame_tls(frame: *const SyscallFrame) -> u64 {
    unsafe { (*frame).r8 }
}

/// Redirects the live syscall frame at `frame` to resume execution at `rip` on `rsp` instead of
/// returning normally to the caller — used by `sys_execve` on success to hand the calling process
/// a whole new program image. Resets every GPR to `0` and the saved `RFLAGS` (`r11`) to
/// `usermode::USER_RFLAGS` (hygiene: a freshly exec'd program shouldn't see the old program's
/// register/flag state); doesn't touch `CS`/`SS` at all (there's no per-frame field for them any
/// more — `SYSRETQ` always reconstructs both from `IA32_STAR`), which is fine since `execve`
/// doesn't change privilege level anyway.
///
/// # Safety
///
/// `frame` must point at the currently in-flight syscall's live frame (i.e. `current_frame()`'s
/// return value, called from within that same syscall's handling).
pub(crate) unsafe fn redirect_frame(frame: *mut SyscallFrame, rip: VirtAddr, rsp: VirtAddr) {
    unsafe {
        let frame = &mut *frame;
        frame.r15 = 0;
        frame.r14 = 0;
        frame.r13 = 0;
        frame.r12 = 0;
        frame.r11 = 0;
        frame.r10 = 0;
        frame.r9 = 0;
        frame.r8 = 0;
        frame.rbp = 0;
        frame.rdi = 0;
        frame.rsi = 0;
        frame.rdx = 0;
        frame.rcx = 0;
        frame.rbx = 0;
        frame.rax = 0;
        frame.rcx = rip.as_u64();
        frame.r11 = crate::process::usermode::USER_RFLAGS;
        frame.user_rsp = rsp.as_u64();
    }
}

/// OxideBSD's own invention -- see `bits/syscall.h.in`'s own comment on the musl fork for why
/// this bypasses `SYSCALL_TABLE`/`dispatch` entirely (`do_sigreturn` below) rather than being
/// registered like every other syscall.
const SYS_SIGRETURN: u64 = 119;

/// OxideBSD's own invention, continuing this ABI's own highest already-assigned number (past
/// `SYS_MSGCTL = 553`) -- see `process::fault_trampoline`'s own module doc comment for why this
/// exists at all: it's never issued by real regress/musl, only by the tiny kernel-authored
/// trampoline page a ring-3 page fault gets redirected into. Bypasses `SYSCALL_TABLE`/`dispatch`
/// entirely, same shape as `SYS_SIGRETURN` above -- its only job is to *be* a real `SYSCALL`
/// instruction (so this function's own GPR-capturing entry/exit runs), not to do anything once
/// it's landed here.
pub(crate) const SYS_FAULT_PUMP: u64 = 554;

#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch(frame: *mut SyscallFrame) {
    // SAFETY: frame points at syscall_entry's just-pushed register block, on the current
    // process's own kernel stack, valid and exclusively ours for the duration of this call.
    let frame = unsafe { &mut *frame };

    // A real, narrow exception, not routed through the normal table/Ok-Err machinery below:
    // sigreturn must restore the interrupted context's own saved carry flag (in `r11`) bit for
    // bit, but the normal `Ok(value)`/`Err(errno)` convention can only ever force that bit to one
    // fixed polarity (clear on `Ok`, set on `Err`) -- neither can reproduce an arbitrary restored
    // value. See `do_sigreturn`'s own doc comment.
    if frame.rax == SYS_SIGRETURN {
        do_sigreturn(frame);
        return;
    }

    // Also bypasses the normal table lookup -- see this constant's own doc comment. The real
    // pending fault-signal `interrupts::page_fault_handler` recorded before redirecting here is
    // exactly what `deliver_pending_signal` finds and acts on; nothing else about this "syscall"
    // needs to happen at all.
    if frame.rax == SYS_FAULT_PUMP {
        // Real `interrupts::timer_interrupt_handler` redirect (see `Process::preempted_resume`'s
        // own doc comment): unlike the page-fault-triggered redirect (where the faulting
        // instruction is never meant to transparently resume), this frame's own `rcx`/`r11`/
        // `user_rsp` right now describe the *trampoline's* own internal `syscall` instruction, not
        // the real point execution should continue from once `deliver_pending_signal` is done
        // (whether that's "no handler, just resume" or "handler installed, resume here after
        // `sigreturn`"). A `None` here (the ordinary page-fault case) leaves the frame exactly as
        // the trampoline set it, unchanged.
        if let Some((rip, rsp, rflags)) = crate::process::table()
            .lock()
            .get_mut(&crate::process::scheduler::current_pid())
            .and_then(|p| p.preempted_resume.take())
        {
            // **Not** `frame.rcx = rip; frame.r11 = rflags;` -- see `fault_trampoline::
            // RCX_SCRATCH_OFFSET`'s own doc comment for the real bug this replaced: `SYSRETQ`'s
            // `RIP := RCX` hardware coupling means the resumed code always finds `RCX == RIP`,
            // permanently destroying whatever real, live value (e.g. a computed pointer) `RCX`
            // held at the moment of this async redirect, with no chance to recover it. Instead,
            // point the eventual resume at the trampoline's own restore stub (which finishes the
            // real job -- true `rcx`/`r11`/`rflags` back into place, then a bare indirect `jmp` to
            // `rip` that never goes through `RCX` at all) and stash what it needs to do that. If
            // `deliver_pending_signal` below installs a real handler instead, it overwrites
            // `frame.rcx`/`r11` with the handler's own entry point/flags regardless -- a fresh
            // function call has no expectation about prior `RCX` content either way, so this
            // stashed state simply survives untouched (nothing else ever reads it) until whatever
            // handler chain finishes and a genuine resume is actually due.
            // SAFETY: same reasoning as the `RAX_SCRATCH_OFFSET` read below -- this address is
            // mapped `PRESENT | WRITABLE` in this exact process's own currently-active address
            // space.
            unsafe {
                ((crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
                    + crate::process::fault_trampoline::TRUE_RESUME_RIP_OFFSET)
                    as *mut u64)
                    .write(rip);
                ((crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
                    + crate::process::fault_trampoline::TRUE_RFLAGS_OFFSET)
                    as *mut u64)
                    .write(rflags);
            }
            frame.rcx = crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
                + crate::process::fault_trampoline::STUB_OFFSET;
            frame.user_rsp = rsp;
            frame.r11 = crate::process::usermode::USER_RFLAGS;
            // Real, live-found bug: the trampoline's own `mov eax, SYS_FAULT_PUMP` unavoidably
            // clobbers the interrupted code's real `RAX` before this frame was even captured --
            // harmless for the ordinary page-fault redirect (nothing meaningful ever resumes a
            // faulting instruction transparently), fatal here (a stray default-disposition signal
            // corrupting a live computation's `RAX` with no crash to point at it -- see
            // `fault_trampoline`'s own doc comment). The trampoline stashes the real value at
            // `RAX_SCRATCH_OFFSET` before clobbering it specifically so it can be restored here.
            // SAFETY: this address is mapped `PRESENT | WRITABLE` in every process's own address
            // space (`fault_trampoline::map`), and `syscall_dispatch` runs with the interrupted
            // process's own page tables still active (`SYSCALL` never switches `CR3`).
            frame.rax = unsafe {
                *((crate::process::fault_trampoline::FAULT_TRAMPOLINE_VA
                    + crate::process::fault_trampoline::RAX_SCRATCH_OFFSET)
                    as *const u64)
            };
        }
        deliver_pending_signal(frame, false);
        return;
    }

    CURRENT_FRAME.store(frame as *mut SyscallFrame, Ordering::Relaxed);
    let result = dispatch(frame.rax, frame.rdi, frame.rsi, frame.rdx, frame.r10);
    match result {
        Ok(value) => {
            frame.rax = value;
            frame.r11 &= !CARRY_FLAG;
        }
        Err(errno) => {
            frame.rax = errno;
            frame.r11 |= CARRY_FLAG;
        }
    }
    CURRENT_FRAME.store(core::ptr::null_mut(), Ordering::Relaxed);

    // Every path back to userspace this kernel has funnels through here (a blocked-then-woken
    // process resumes by finishing the very syscall it blocked inside, same as any other) except
    // a never-run process's very first launch (`spawn_trampoline_inner`, which can't have a signal
    // pending before it's even executed once) -- so checking here, once, covers every real case.
    // See `deliver_pending_signal`'s own doc comment.
    deliver_pending_signal(frame, false);
}

/// Pops one entry off this process's own `Process::signal_stack` (see
/// `deliver_pending_signal` below) and restores `*frame` from it, byte for byte -- including
/// `rax`/`r11`'s carry-flag bit, which is exactly why this bypasses `syscall_dispatch`'s normal
/// `Ok`/`Err` rewrite instead of being a registered handler returning a plain `Result` like every
/// other syscall. If nothing is actually stashed (a spurious/duplicate call -- the trampoline this
/// codebase installs only ever calls this once, right after a real handler returns, so this should
/// never happen in practice, but nothing about a syscall number is trustworthy input), fails the
/// call directly here (the normal error-signaling convention, just applied by hand since the usual
/// `dispatch()`/`Result` path isn't reached for this number at all).
///
/// **The real signal-stack chain**: after restoring `*frame` to whatever this entry says should
/// run next, this re-checks for a further deliverable signal (`deliver_pending_signal`) *before*
/// ever letting that restored state actually resume as real userspace execution. If another signal
/// is deliverable right now -- more instances still queued behind the one the handler that just
/// `sigreturn`ed was invoked for, or a different signal that only became unblocked once this
/// handler's own extra `blocked_signals` bits were lifted -- it redirects `*frame` into that next
/// handler instead, pushing a fresh `signal_stack` entry on top (`stash_signal_context`). Only once
/// a `sigreturn` finds genuinely nothing else deliverable does the popped state actually resume.
/// This is what closes the previously-documented "only one snapshot, not a real signal stack" gap:
/// several already-queued signal instances unblocked by a single `sigprocmask`/`sigrelse` call now
/// all get delivered (real handler invocation, not just a bitmask flip) before the unblocking call
/// itself is ever observed to return to its own caller.
fn do_sigreturn(frame: &mut SyscallFrame) {
    let pid = crate::process::scheduler::current_pid();
    match crate::process::take_signal_saved_frame(pid) {
        Some((saved, ucontext_addr)) => {
            *frame = saved;
            if ucontext_addr != 0 {
                // Real sigreturn(2) semantics: restore machine state from the *real* ucontext_t
                // the handler was actually given (and may have modified), not just the kernel's
                // own pre-handler snapshot -- see `SignalStackFrame::ucontext_addr`'s own doc
                // comment for the real bug this closes. `saved` above already covers the case
                // where the handler never touched it (this overlay reproduces the exact same
                // values then, since the ucontext was originally populated from `saved` itself).
                // SAFETY: same known pointer-validation gap every other user-memory read in this
                // file already has -- `ucontext_addr` was a real, live address on this exact
                // process's own user stack when `deliver_pending_signal` wrote it, and a handler
                // that corrupts/frees it before returning is the same class of real memory-safety
                // violation as any other wild pointer a userspace program can commit.
                let gregs = unsafe { (ucontext_addr as *const RawUcontext).read_unaligned() }
                    .uc_mcontext
                    .gregs;
                frame.r8 = gregs[REG_R8] as u64;
                frame.r9 = gregs[REG_R9] as u64;
                frame.r10 = gregs[REG_R10] as u64;
                frame.r12 = gregs[REG_R12] as u64;
                frame.r13 = gregs[REG_R13] as u64;
                frame.r14 = gregs[REG_R14] as u64;
                frame.r15 = gregs[REG_R15] as u64;
                frame.rdi = gregs[REG_RDI] as u64;
                frame.rsi = gregs[REG_RSI] as u64;
                frame.rbp = gregs[REG_RBP] as u64;
                frame.rbx = gregs[REG_RBX] as u64;
                frame.rdx = gregs[REG_RDX] as u64;
                frame.rax = gregs[REG_RAX] as u64;
                frame.user_rsp = gregs[REG_RSP] as u64;
                // rcx/r11 double as resume RIP/RFLAGS (see SyscallFrame's own doc comment) --
                // read back from REG_RIP/REG_EFL specifically, not REG_RCX/REG_R11, matching
                // real Linux's own sigreturn (a handler redirects resume execution by writing
                // MC_PC, i.e. gregs[REG_RIP] -- exactly what musl's own pthread_cancel() does).
                frame.rcx = gregs[REG_RIP] as u64;
                frame.r11 = gregs[REG_EFL] as u64;
            }
            deliver_pending_signal(frame, true);
        }
        None => {
            frame.rax = EINVAL;
            frame.r11 |= CARRY_FLAG;
        }
    }
}

/// musl's own `mcontext_t` on x86_64 under `_GNU_SOURCE` (`external/mit/musl/arch/x86_64/bits/
/// signal.h`) -- the layout this kernel's actual userland (BusyBox, built with `-D_GNU_SOURCE`)
/// compiles against. `gregs` is real -- populated from the interrupted syscall's own saved
/// `SyscallFrame` below, the actual pre-signal machine state, not a placeholder. `fpregs`/
/// `reserved1` are always `0`/`null` -- this kernel never saves FPU state anywhere (`sys/cpu/
/// fpu.rs`'s own documented gap), so there is no real value to point at.
#[repr(C)]
struct RawMcontext {
    gregs: [i64; 23],
    fpregs: u64,
    reserved1: [u64; 8],
}

const _: () = assert!(core::mem::size_of::<RawMcontext>() == 256);

/// Real Linux/x86_64 `REG_*` indices into `RawMcontext::gregs` (`external/mit/musl/arch/x86_64/
/// bits/signal.h`'s own `_GNU_SOURCE` enum).
const REG_R8: usize = 0;
const REG_R9: usize = 1;
const REG_R10: usize = 2;
const REG_R11: usize = 3;
const REG_R12: usize = 4;
const REG_R13: usize = 5;
const REG_R14: usize = 6;
const REG_R15: usize = 7;
const REG_RDI: usize = 8;
const REG_RSI: usize = 9;
const REG_RBP: usize = 10;
const REG_RBX: usize = 11;
const REG_RDX: usize = 12;
const REG_RAX: usize = 13;
const REG_RCX: usize = 14;
const REG_RSP: usize = 15;
const REG_RIP: usize = 16;
const REG_EFL: usize = 17;

/// musl's own `stack_t`/`struct sigaltstack` on x86_64 -- `ss_sp`, `ss_flags` (padded to 8 bytes),
/// `ss_size`. Only ever used for `RawUcontext::uc_stack` below, always zeroed there (a real,
/// separate gap from `SA_ONSTACK` handler placement itself -- see `Process::altstack`'s own doc
/// comment -- no current pilot test exercises it).
#[repr(C)]
struct RawStackT {
    ss_sp: u64,
    ss_flags: i32,
    _pad: u32,
    ss_size: u64,
}

/// musl's own `ucontext_t` on x86_64 under `_GNU_SOURCE` -- `uc_flags`/`uc_link`/`uc_stack`/
/// `uc_mcontext`/`uc_sigmask`/`__fpregs_mem` in that order, 936 bytes total. Exists so a real
/// `SA_SIGINFO` handler that dereferences its third argument gets a correctly-sized, correctly-
/// shaped structure with real general-purpose-register values (see `RawMcontext` above) instead of
/// faulting on `NULL` -- the gap this whole function used to document as unfixed.
#[repr(C)]
struct RawUcontext {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: RawStackT,
    uc_mcontext: RawMcontext,
    /// The real `blocked_signals` mask in effect *before* this handler's own extra `mask_to_add`
    /// was applied (`stash_signal_context`'s own return value) -- matches real Linux's "the mask
    /// the interrupted program was actually running under" semantics for `uc_sigmask`. Only the
    /// first `u64` of the real 128-byte `sigset_t` is ever meaningful on this ABI (see
    /// `do_sigprocmask`'s own doc comment for why) -- the rest is real zero padding, not truncated
    /// data.
    uc_sigmask: [u64; 16],
    /// No real FPU state exists anywhere on this kernel to report -- always zeroed, same story as
    /// `RawMcontext::fpregs` above.
    fpregs_mem: [u64; 64],
}

const _: () = assert!(core::mem::size_of::<RawUcontext>() == 936);

/// Checked once, at the tail of every completed syscall (see `syscall_dispatch` above): if the
/// current process has a pending, unblocked signal, act on it now, right before control actually
/// returns to userspace. Real Unix semantics for the same reason: a signal only ever "arrives"
/// (steps a handler, or ends the process) between one instruction and the next of the process's
/// own userspace execution, never mid-syscall.
///
/// `SigDisposition::Terminate` calls `process::do_exit`, which never returns -- this function
/// itself can too, for that one case (it just never reaches its own tail).
/// `SigDisposition::Handler` rewrites `*frame` in place so the *next* thing this process's own
/// `sysretq` resumes into is the handler, not whatever userspace code the syscall originally
/// interrupted -- the interrupted state is snapshotted onto `Process::signal_stack` first (see
/// `process::stash_signal_context`), restored later by `do_sigreturn` once the handler itself
/// returns (via the trampoline `sa_restorer` names -- musl's own `__restore_rt`, patched to call
/// `SYS_SIGRETURN` -- see `bits/syscall.h.in`'s own comment on the musl fork).
///
/// **`SA_SIGINFO` is supported**: when the installed action has that flag set, the handler is
/// invoked as a real 3-argument `void (*)(int, siginfo_t *, void *)` -- `rsi`/`rdx` point at a
/// real, correctly-sized `RawSiginfo`/`RawUcontext` constructed on the handler's own stack frame
/// (see those structs' own doc comments for exactly what is and isn't faithfully populated: real
/// general-purpose registers and the real pre-handler `blocked_signals` mask, but no sender
/// identity for `si_pid`/`si_uid` -- `pending_signals` is a plain bitmask with no sender attached)
/// rather than the `NULL` this used to hand every such handler. Without `SA_SIGINFO`, the handler
/// is still invoked the plain 1-argument way (`rdi = signum` only, `rsi`/`rdx` zeroed), matching
/// real Unix's own distinction between the two handler shapes.
///
/// **Real signal-stack chaining, not just one snapshot**: this function is called from two places
/// -- `syscall_dispatch`'s own tail (the normal "about to resume real userspace" check) and
/// `do_sigreturn`, right after it pops and restores a `signal_stack` entry, *before* treating that
/// restored state as final. If a `Handler` delivery is found the second way, it pushes a fresh
/// entry on top instead of resuming, so a chain of N deliverable signals (e.g. several more
/// already-queued instances of an RT signal a single `sigprocmask` call just unblocked) plays out
/// as N real handler invocations -- each one's own `sigreturn` triggering the next -- before the
/// original interrupted userspace code is ever actually resumed. This closes what used to be a
/// documented gap here (a single `Option<SyscallFrame>` snapshot that a second deliverable signal
/// during handler execution would silently clobber instead of nesting into) -- see
/// `Process::signal_stack`'s own doc comment for the data-structure side of this fix.
///
/// **`chained` distinguishes a genuine return-to-userspace call from `do_sigreturn`'s own
/// synchronous chaining call** -- see `Process::cascade_budget`'s own doc comment for the real
/// bug this closes (a handler-driven resend loop, e.g. musl's own `pthread_cancel()`, could
/// otherwise spin forever inside a single sigreturn without the interrupted frame ever actually
/// resuming). `false` at both of this function's non-`do_sigreturn` call sites (a completed
/// syscall's own tail, and the fault trampoline) -- both are genuine "about to resume real
/// userspace" points; `true` only from `do_sigreturn`'s own chained call below.
fn deliver_pending_signal(frame: &mut SyscallFrame, chained: bool) {
    let pid = crate::process::scheduler::current_pid();
    if pid == 0 {
        // Boot time (module_init self-checks, etc.) -- no real Process to carry signal state.
        return;
    }
    // Set only by a `do_sigsuspend` (`sys/process/signals.rs`) that just woke up -- see that
    // function's own doc comment for why the mask restore has to happen here, not there, split
    // three ways below by how the woken signal actually resolves.
    let sigsuspend_restore = crate::process::take_sigsuspend_restore_mask(pid);
    let Some(delivery) = crate::process::take_deliverable_signal(pid, chained) else {
        // Every pending-but-unblocked bit that woke sigsuspend turned out to be SIG_IGN/default-
        // Ignore -- no handler will ever run to restore the mask via sigreturn, so do it now.
        if let Some(orig) = sigsuspend_restore {
            crate::process::restore_blocked_signals(pid, orig);
        }
        return;
    };
    match delivery {
        crate::process::SignalDelivery::Terminate(code) => {
            // Real POSIX semantics: an uncaught, default-disposition-terminating signal kills the
            // *whole* thread group, not just the one thread that happened to receive/generate it
            // (e.g. `a_crash()`'s deliberate ring-3 `hlt` -> `#GP` -> self-`SIGSEGV`, reached here).
            // `do_exit` alone let `terminate_process`'s own `other_thread_alive` check see this
            // thread's still-live siblings and wrongly treat it as "just another disposable
            // CLONE_THREAD sibling" -- even when it was the thread-group *leader*, the one process
            // a real `wait4()` is actually watching -- silently zombifying-and-removing it with no
            // parent notification at all, permanently hanging the parent's own `wait4(-1, ...)`.
            // `do_exit_group` is a strict superset of `do_exit`'s own behavior for a genuinely
            // single-threaded caller (its own sibling scan finds nothing, falls straight through to
            // the same "last thread of group" path `do_exit` alone would have taken) so this is
            // safe unconditionally, not just for the multi-threaded case that exposed the bug.
            // Found chasing a flaky crash-or-hang in `pthread_attr_setdetachstate/2-1.c`.
            crate::process::do_exit_group(pid, code);
        }
        crate::process::SignalDelivery::Stop(signum) => {
            crate::process::do_stop_self(pid, signum);
            // The process doesn't die and no handler is going to run -- restore now, same
            // reasoning as the no-more-deliverable-signal branch above.
            if let Some(orig) = sigsuspend_restore {
                crate::process::restore_blocked_signals(pid, orig);
            }
        }
        crate::process::SignalDelivery::Handler {
            signum,
            handler,
            restorer,
            mask_to_add,
            flags,
            siginfo: delivery_siginfo,
        } => {
            // Real `SA_ONSTACK` (`sigaltstack/1-1.c`/`6-1.c`/`7-1.c`) -- decided (and
            // `Process::on_altstack` flipped) before `stash_signal_context` below records whether
            // *this* delivery is the one that did so. See `begin_altstack_if_requested`'s own doc
            // comment for the real eligibility rules.
            let altstack = crate::process::begin_altstack_if_requested(pid, flags);
            // Snapshotted *before* frame is mutated below -- this is the exact state the
            // interrupted syscall was about to resume into.
            let saved = *frame;

            // A real alt stack runs fresh from its own top (no red-zone concern -- nothing else
            // has ever run here yet); the normal path keeps its existing 128-byte red-zone
            // headroom under the interrupted code's own live `user_rsp`.
            let mut sp = match altstack {
                Some((stack_sp, stack_size)) => stack_sp.wrapping_add(stack_size),
                None => frame.user_rsp.wrapping_sub(128),
            };

            // Addresses only, computed *before* `stash_signal_context` below (which needs
            // `ucontext_addr` up front -- see `SignalStackFrame::ucontext_addr`'s own doc comment
            // -- but whose own return value, `old_mask`, is in turn needed to actually populate
            // `uc_sigmask` further down). Real POSIX MPR doesn't apply here (this is genuinely
            // this process's own live stack, never a fd-backed mapping).
            let (siginfo_addr, ucontext_addr) = if flags & crate::process::SA_SIGINFO != 0 {
                sp = sp.wrapping_sub(core::mem::size_of::<RawUcontext>() as u64);
                sp &= !0xF;
                let ucontext_addr = sp;

                sp = sp.wrapping_sub(core::mem::size_of::<RawSiginfo>() as u64);
                sp &= !0xF;
                let siginfo_addr = sp;
                (siginfo_addr, ucontext_addr)
            } else {
                (0, 0)
            };

            // `old_mask` is what the interrupted state was actually running under -- what
            // `uc_sigmask` reports below, for the SA_SIGINFO case.
            let old_mask = crate::process::stash_signal_context(
                pid,
                saved,
                mask_to_add,
                altstack.is_some(),
                ucontext_addr,
            );
            // A real handler is about to run -- defer the sigsuspend mask restore until it
            // returns (`sigreturn`/`take_signal_saved_frame`) rather than doing it now, real
            // POSIX semantics (see `do_sigsuspend`'s own doc comment).
            if let Some(orig) = sigsuspend_restore {
                crate::process::set_signal_saved_blocked_override(pid, orig);
            }

            if flags & crate::process::SA_SIGINFO != 0 {
                let mut gregs = [0i64; 23];
                gregs[REG_R8] = saved.r8 as i64;
                gregs[REG_R9] = saved.r9 as i64;
                gregs[REG_R10] = saved.r10 as i64;
                gregs[REG_R11] = saved.r11 as i64;
                gregs[REG_R12] = saved.r12 as i64;
                gregs[REG_R13] = saved.r13 as i64;
                gregs[REG_R14] = saved.r14 as i64;
                gregs[REG_R15] = saved.r15 as i64;
                gregs[REG_RDI] = saved.rdi as i64;
                gregs[REG_RSI] = saved.rsi as i64;
                gregs[REG_RBP] = saved.rbp as i64;
                gregs[REG_RBX] = saved.rbx as i64;
                gregs[REG_RDX] = saved.rdx as i64;
                gregs[REG_RAX] = saved.rax as i64;
                gregs[REG_RCX] = saved.rcx as i64;
                gregs[REG_RSP] = saved.user_rsp as i64;
                gregs[REG_RIP] = saved.rcx as i64; // rcx doubles as resume RIP, see SyscallFrame's own doc comment
                gregs[REG_EFL] = saved.r11 as i64; // r11 doubles as resume RFLAGS, same story

                let mut uc_sigmask = [0u64; 16];
                uc_sigmask[0] = old_mask;

                let ucontext = RawUcontext {
                    uc_flags: 0,
                    uc_link: 0,
                    uc_stack: RawStackT {
                        ss_sp: 0,
                        ss_flags: 0,
                        _pad: 0,
                        ss_size: 0,
                    },
                    uc_mcontext: RawMcontext {
                        gregs,
                        fpregs: 0,
                        reserved1: [0; 8],
                    },
                    uc_sigmask,
                    fpregs_mem: [0; 64],
                };
                let siginfo = RawSiginfo {
                    si_signo: signum as i32,
                    si_code: delivery_siginfo.code,
                    si_errno: 0,
                    _pad0: 0,
                    si_pid: delivery_siginfo.pid as i32,
                    si_uid: delivery_siginfo.uid as i32,
                    si_value: delivery_siginfo.value,
                    _tail: [0; 128 - 4 * 4 - 2 * 4 - 8],
                };
                // SAFETY: same known pointer-validation gap every other user-memory write in this
                // file already has -- both addresses are derived from this process's own live
                // user_rsp, and this process's own address space is the one currently active.
                unsafe {
                    (ucontext_addr as *mut RawUcontext).write_unaligned(ucontext);
                    (siginfo_addr as *mut RawSiginfo).write_unaligned(siginfo);
                }
            }

            // 16-byte-align down, then back off 8 more bytes so the slot this writes to lands
            // exactly where an ordinary `call`'s own implicit return-address push would -- i.e.
            // RSP%16==8 at the handler's own entry, matching System V's calling convention.
            sp &= !0xF;
            sp = sp.wrapping_sub(8);
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // file already has -- sp is derived from this process's own live user_rsp, and this
            // process's own address space is the one currently active (signals are only ever
            // delivered to the process that's actually running right now).
            unsafe { (sp as *mut u64).write(restorer) };

            frame.rdi = signum;
            frame.rsi = siginfo_addr;
            frame.rdx = ucontext_addr;
            frame.rcx = handler; // resume RIP
            frame.r11 = crate::process::usermode::USER_RFLAGS; // resume RFLAGS
            frame.user_rsp = sp;
        }
    }
}

/// Numbers `dispatch` has already logged an "unrecognized syscall" line for — see `dispatch`'s own
/// doc comment for why this exists: a real interactive session (`sh.elf` with no `-c`, run for
/// real rather than as a single smoke-tested command) calls the *same* missing syscall repeatedly
/// (concretely, `hush` re-issues `rt_sigaction`/`rt_sigprocmask` around every command it runs), and
/// logging it every single time drowns out the actual command output on the same serial console —
/// discovered by actually using this interactively, not by inspection.
static LOGGED_UNRECOGNIZED: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

/// The actual dispatch logic, kept separate from `syscall_dispatch`'s raw pointer/frame handling
/// so it's directly unit-testable (see the `test_syscall_dispatch_*` tests in `sys/lib.rs`). A
/// pure lookup into `SYSCALL_TABLE` — no number is special-cased here anymore, they're all
/// registered externally by whatever module chose to claim them.
pub(crate) fn dispatch(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> Result<u64, u64> {
    let handler = SYSCALL_TABLE.lock().get(&number).copied();
    match handler {
        Some(handler) => {
            // Tells module_panic_trampoline whether a panic inside this specific call should
            // reboot the system or just halt -- see CURRENT_MODULE_FATAL's own doc comment in
            // sys/module.rs. Must happen right before the call: this flag has no meaning except
            // for whatever module code is currently executing.
            crate::module::mark_active_module_by_address(handler as usize as u64);
            ffi_result_to_result(handler(arg0, arg1, arg2, arg3))
        }
        None => {
            // Only the first occurrence of a given number is logged -- see LOGGED_UNRECOGNIZED's
            // own doc comment. Still the intended tool for discovering what a program's startup
            // needs (every *distinct* unimplemented number still gets one line), just no longer at
            // the cost of spamming every repeat once real interactive use started producing many.
            if LOGGED_UNRECOGNIZED.lock().insert(number) {
                serial_println!("[boot] unrecognized syscall number {}", number);
            }
            Err(ENOSYS)
        }
    }
}

/// Converts a registered handler's own `SyscallHandler` FFI return (negative = `-errno`) into a
/// plain `Result` — used by `dispatch()` above, and by `ffi.rs`'s own `sys_read`/`sys_write` (both
/// delegate straight to `crate::fs::fd::read`/`write`, which share this same negative-errno FFI
/// shape). Private to this module (`syscall`), not `pub(crate)` — Rust's own ancestor-visibility
/// rule already lets `ffi.rs` (a child module of this one) call it as `super::ffi_result_to_result`
/// without any explicit re-export.
fn ffi_result_to_result(raw: i64) -> Result<u64, u64> {
    if raw < 0 {
        Err((-raw) as u64)
    } else {
        Ok(raw as u64)
    }
}

// `static mut`, not `static`: only ever written/read by this file's own raw asm (`mov [X], rsp`,
// never through a Rust `&`/`&mut`), invisible to the optimizer either way -- same defensive
// treatment as `gdt::CURRENT_RSP0`. Transiently holds the user's `RSP` for the handful of
// instructions between "SYSCALL just landed, RSP is still the user's" and "pushed as the first
// field of this process's own SyscallFrame, on this process's own kernel stack" -- genuinely a
// single global for that brief window (this kernel is single-core and SFMASK keeps interrupts off
// for the whole entry sequence, so at most one syscall can be *entering* at once), but safe past
// that window regardless, since by the time any Rust code able to call scheduler::schedule() runs,
// the saved RSP already lives in the (per-process) SyscallFrame instead of here. A single global
// scratch slot living for the *entire* syscall the way src/linux_syscall.rs's old
// USER_RSP_SCRATCH did would not have been safe here: do_wait4 already blocks and reschedules
// mid-syscall, so a second process could enter its own syscall before the first one returns.
#[unsafe(no_mangle)]
static mut SYSCALL_RSP_SCRATCH: u64 = 0;

global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    // SYSCALL leaves RSP on the user's own stack (unlike an interrupt gate + TSS RSP0, there's no
    // automatic switch) -- stash it, then move onto *this process's own* kernel stack (mirrored
    // into CURRENT_RSP0 by gdt::set_kernel_stack on every context switch) before pushing anything.
    "mov [SYSCALL_RSP_SCRATCH], rsp",
    "mov rsp, [CURRENT_RSP0]",
    "push qword ptr [SYSCALL_RSP_SCRATCH]", // user_rsp -- see SyscallFrame's doc comment
    "push rax",
    "push rbx",
    "push rcx", // = user RIP (SYSCALL saved it here)
    "push rdx",
    "push rsi",
    "push rdi",
    "push rbp",
    "push r8",
    "push r9",
    "push r10",
    "push r11", // = user RFLAGS (SYSCALL saved it here)
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp", // &mut SyscallFrame, System V's first argument register
    "call syscall_dispatch",
    // Labeled separately (not just a fallthrough) so sys/process/context_switch.rs's fork
    // trampoline can jump straight here: a freshly forked child's kernel stack is seeded with a
    // copy of its parent's SyscallFrame (rax forced to 0), placed at exactly the stack offset this
    // tail expects, so "return from fork() with 0" and "return from any other syscall" are the
    // same code path. See CLAUDE.md's process/scheduler section.
    ".global syscall_return_tail",
    "syscall_return_tail:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax", // dispatcher's return value or errno, written directly into this stack slot
    "pop rsp", // user_rsp -- must be the very last pop, right before sysretq
    "sysretq",
);
