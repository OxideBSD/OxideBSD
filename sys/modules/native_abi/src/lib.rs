//! Converts OxideBSD's native `SYSCALL`/`SYSRETQ` syscall ABI's number → handler dispatch table
//! (in `sys/syscall.rs`) from a hardcoded `match` into something a dynamically loaded module
//! populates — see `CLAUDE.md`'s module-loading section for the full design and, in particular,
//! why the underlying `sys_exit`/`sys_read`/`sys_write`/`sys_fork`/`sys_wait4`/`sys_execve`/
//! `sys_getpid` *behavior* stays kernel-resident rather than moving here too: this module can't use
//! `alloc` (see CLAUDE.md's module-loading section), and the process table/scheduler need
//! `Vec`/`BTreeMap` freely. What this module actually owns is just which syscall *numbers* route
//! to which handlers — registered here, once, at `module_init` time.
//!
//! Syscall numbers (`SYS_EXIT = 1`, `SYS_FORK = 2`, `SYS_READ = 3`, `SYS_WRITE = 4`,
//! `SYS_WAIT4 = 7`, `SYS_GETPID = 20`, `SYS_EXECVE = 59`) match real FreeBSD's long-stable values
//! — hand-duplicated here rather than shared via a crate with the kernel, the same "no shared
//! crate across this ABI boundary" convention already used for the raw syscall stub's own
//! constants inside `regress/*/src/main.rs`.
//!
//! `SYS_MMAP = 100`/`SYS_MUNMAP = 101`/`SYS_BRK = 102`/`SYS_SET_FS_BASE = 103` are different: they
//! don't chase FreeBSD authenticity the way the numbers above do. They're OxideBSD's own
//! invention — numbers and argument shapes chosen for what porting musl's userland actually needs
//! (see `sys/process.rs`'s `do_mmap`/`do_munmap`/`do_brk` and `sys/syscall.rs`'s
//! `sys_set_fs_base`), not copied from any real OS's syscall table.
//!
//! `SYS_GETPPID = 107` is the same kind of OxideBSD-own invention, added once porting `sh`
//! (BusyBox's `hush`) surfaced it as an unrecognized syscall (`hush` reads `$PPID` at startup).
//! `Process.parent` (`sys/process.rs`) already exists for `wait4`'s own reparenting logic, so
//! `do_getppid` just reads it back — `0` for a process with no parent, matching real
//! `getppid()`'s convention for the boot/init process.
//!
//! `SYS_SET_TID_ADDRESS = 150` continues the sequence right past `sys/modules/posix_compat`'s own
//! `SYS_SOCKETPAIR = 149`, but lives here rather than there: musl's own startup code
//! (`__init_tls.c`) calls this unconditionally for *every* process, the same "core, not a specific
//! feature" reasoning `SYS_SET_FS_BASE` above already earned its spot in this module for. Real
//! logic (`sys/syscall.rs`'s `sys_set_tid_address`) just echoes the caller's own pid back — no real
//! threading exists on this kernel, so tid and pid are the same concept here.
//!
//! `SYS_READV = 153` continues the sequence past `sys/modules/posix_compat`'s own `SYS_SHUTDOWN =
//! 152`, but lives here, right next to `SYS_WRITEV` above -- the exact same "musl's entire stdio
//! path goes through the `*v` call, not the plain one" story, just for reads: any buffered
//! `fread()`/`fgets()` call goes through `readv`, not `read`, whenever the `FILE*` has real
//! internal buffering (`external/mit/musl/src/stdio/__stdio_read.c`). Real logic (`sys/syscall.rs`'s
//! `sys_readv`) is kernel-resident, same reasoning as `sys_writev` above.
//!
//! `SYS_MSYNC = 26` is real x86_64 Linux's own `__NR_msync`, unremapped -- confirmed unclaimed
//! anywhere in this ABI's own registry, and `external/mit/musl/src/mman/msync.c` already targets it
//! directly with no argument-convention issue (a real 3-argument `(addr, len, flags)` call fits
//! this ABI's register width exactly). Lives here, next to `SYS_MMAP`/`SYS_MUNMAP`/`SYS_MPROTECT`
//! above, same "core mmap-family syscall" reasoning. Real logic (`process::mm::do_msync`) flushes a
//! live fd-backed `MAP_SHARED` region back to its file on demand -- see that function's own doc
//! comment for why this went from a structural non-issue to a genuine gap once real fd-backed
//! `MAP_SHARED` mmap landed.
//!
//! `SYS_PREAD = 17`/`SYS_PWRITE = 18` are real x86_64 Linux's own `__NR_pread64`/`__NR_pwrite64`,
//! unremapped -- see `SYS_PREAD`'s own doc comment below. Real logic
//! (`crate::fs::fd::pread`/`pwrite`, kernel tree) is a pure registry lookup, the exact same shape
//! `sys_read`/`sys_write` already are, just with an explicit offset that bypasses the fd's own
//! current file position -- `sys/modules/oxfs`'s own real, on-disk-backed `OpenFile::Write` variant
//! (its `readwrite`/`position` fields) is the one real implementation today (found live via the
//! Open POSIX Test Suite's `aio_read`/`aio_write`/`lio_listio` pilot: musl's own threads-based
//! `aio.c` calls `pread`/`pwrite` directly for any seekable fd).
#![no_std]

unsafe extern "C" {
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_exit(code: u64) -> !;
    fn oxidebsd_sys_exit_group(code: u64) -> !;
    fn oxidebsd_sys_read(fd: u64, ptr: u64, len: u64) -> i64;
    fn oxidebsd_sys_write(fd: u64, ptr: u64, len: u64) -> i64;
    fn oxidebsd_sys_pread(fd: u64, ptr: u64, len: u64, offset: u64) -> i64;
    fn oxidebsd_sys_pwrite(fd: u64, ptr: u64, len: u64, offset: u64) -> i64;
    fn oxidebsd_sys_fork() -> i64;
    fn oxidebsd_sys_wait4(pid: u64, status_ptr: u64, options: u64, rusage_ptr: u64) -> i64;
    fn oxidebsd_sys_execve(path_ptr: u64, path_len: u64, argv_ptr: u64, envp_ptr: u64) -> i64;
    fn oxidebsd_sys_execveat(at_ptr: u64, argv_ptr: u64, envp_ptr: u64, flags: u64) -> i64;
    fn oxidebsd_sys_getpid() -> i64;
    fn oxidebsd_sys_getppid() -> i64;
    fn oxidebsd_sys_mmap(addr_hint: u64, len: u64, prot: u64, packed: u64) -> i64;
    fn oxidebsd_sys_munmap(addr: u64, len: u64) -> i64;
    fn oxidebsd_sys_brk(addr: u64) -> i64;
    fn oxidebsd_sys_mprotect(addr: u64, len: u64, prot: u64) -> i64;
    fn oxidebsd_sys_msync(addr: u64, len: u64, flags: u64) -> i64;
    fn oxidebsd_sys_set_fs_base(base: u64) -> i64;
    fn oxidebsd_sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64;
    fn oxidebsd_sys_set_tid_address(tidptr: u64) -> i64;
    fn oxidebsd_sys_readv(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64;
    fn oxidebsd_sys_pwritev2(fd: u64, iov_ptr: u64, iovcnt: u64, ofs: u64) -> i64;
    fn oxidebsd_sys_clone(flags: u64, newsp: u64, ptid: u64, ctid: u64) -> i64;
}

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
/// Real, unremapped x86_64 Linux `__NR_pread64`/`__NR_pwrite64` values -- confirmed unclaimed
/// (grepped every already-registered syscall number in this ABI) and, unlike almost every other
/// ported syscall, need zero musl-side remap at all: `external/mit/musl/src/unistd/{pread,
/// pwrite}.c` already issue these exact numbers directly with a real 4-argument shape
/// (`fd, buf, count, offset`) that fits this ABI's own 4-register max with no packing tricks. See
/// `oxidebsd_sys_pread`'s own doc comment (kernel tree) for why `pwrite()` needs both this and a
/// harmless `SYS_pwritev2` `ENOSYS` first.
const SYS_PREAD: u64 = 17;
const SYS_PWRITE: u64 = 18;
const SYS_WAIT4: u64 = 7;
const SYS_GETPID: u64 = 20;
const SYS_EXECVE: u64 = 59;
/// `execveat(2)` -- the one `*at()` call that isn't a filesystem op (`sys/modules/oxfs` owns
/// `560`-`573`). musl reaches it through `fexecve()`.
const SYS_EXECVEAT: u64 = 574;
const SYS_MMAP: u64 = 100;
const SYS_MUNMAP: u64 = 101;
const SYS_BRK: u64 = 102;
const SYS_SET_FS_BASE: u64 = 103;
const SYS_WRITEV: u64 = 104;
const SYS_GETPPID: u64 = 107;
const SYS_SET_TID_ADDRESS: u64 = 150;
const SYS_READV: u64 = 153;
/// Real, unremapped Linux `__NR_pwritev2=328` (confirmed unclaimed) -- see `sys_pwritev2`'s own
/// doc comment in `sys/syscall/ffi.rs` for the real wire-format-shrinking musl call-site patch
/// this needs. Lives here, next to `SYS_WRITEV`/`SYS_READV`, not a feature module -- same
/// "core vectored-I/O family" reasoning as those two.
const SYS_PWRITEV2: u64 = 328;
/// Continues the ABI's own invented-number sequence from `sys/modules/oxfs`'s/`sys/modules/posix_compat`'s
/// `SYS_GETRUSAGE = 491` (the current highest assigned anywhere in this ABI as of this addition),
/// not real Linux's `mprotect = 10` — same collision-avoidance discipline as that whole `471+`
/// block (see `sys/syscall.rs`'s own module doc comment for the full history of why). Lives here,
/// not in a feature module, for the same reason `SYS_MMAP`/`SYS_MUNMAP`/`SYS_BRK` above do: a real
/// dynamic linker's own RELRO-protection step needs this at the same "core, every real program
/// eventually calls it" tier once dynamic linking exists at all.
const SYS_MPROTECT: u64 = 492;
const SYS_MSYNC: u64 = 26;
/// Already reserved since "Real threading phase 1" (`external/mit/musl/src/thread/x86_64/clone.s`'s
/// own hardcoded `mov $555,%eax` -- see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`) -- this is the real
/// handler registration that number was always waiting for, not a fresh pick.
const SYS_CLONE: u64 = 555;
/// Real POSIX/Linux `exit_group(2)` -- genuinely distinct from `SYS_EXIT` above (real `exit()`/
/// `_Exit()`'s own kernel entry point, not a bare per-thread `SYS_exit`), continuing right past
/// `SYS_CLONE = 555` (the current highest assigned anywhere in this ABI as of this addition). See
/// `process::do_exit_group`'s own doc comment for why this needed its own number: sharing
/// `SYS_EXIT`'s number left every sibling thread silently orphaned whenever a thread-group
/// leader's own `main()` returned while other threads were still alive.
const SYS_EXIT_GROUP: u64 = 556;

extern "C" fn handle_exit(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_exit(code) }
}

extern "C" fn handle_exit_group(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_exit_group(code) }
}

extern "C" fn handle_read(fd: u64, ptr: u64, len: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_read(fd, ptr, len) }
}

extern "C" fn handle_write(fd: u64, ptr: u64, len: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_write(fd, ptr, len) }
}

/// One of two handlers in this module that actually read their 4th argument (`offset`, via `R10`)
/// -- see `handle_execve`'s own doc comment above for the general rule.
extern "C" fn handle_pread(fd: u64, ptr: u64, len: u64, offset: u64) -> i64 {
    unsafe { oxidebsd_sys_pread(fd, ptr, len, offset) }
}

extern "C" fn handle_pwrite(fd: u64, ptr: u64, len: u64, offset: u64) -> i64 {
    unsafe { oxidebsd_sys_pwrite(fd, ptr, len, offset) }
}

extern "C" fn handle_fork(_arg0: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_fork() }
}

extern "C" fn handle_wait4(pid: u64, status_ptr: u64, options: u64, rusage_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_wait4(pid, status_ptr, options, rusage_ptr) }
}

/// One of two handlers in this module that actually read their 4th argument (`envp_ptr`, via
/// `R10`) -- see `sys/syscall.rs`'s module doc comment for why `R10` only became a real, read
/// argument once `execve` needed real `envp` passthrough. `handle_mmap` below is the other.
extern "C" fn handle_execve(path_ptr: u64, path_len: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_execve(path_ptr, path_len, argv_ptr, envp_ptr) }
}

extern "C" fn handle_execveat(at_ptr: u64, argv_ptr: u64, envp_ptr: u64, flags: u64) -> i64 {
    unsafe { oxidebsd_sys_execveat(at_ptr, argv_ptr, envp_ptr, flags) }
}

extern "C" fn handle_getpid(_arg0: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_getpid() }
}

extern "C" fn handle_getppid(_arg0: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_getppid() }
}

/// `packed` (real `R10`) carries `fd`/`off` -- see the kernel-side `oxidebsd_sys_mmap`'s own doc
/// comment for the packed wire format.
extern "C" fn handle_mmap(addr_hint: u64, len: u64, prot: u64, packed: u64) -> i64 {
    unsafe { oxidebsd_sys_mmap(addr_hint, len, prot, packed) }
}

extern "C" fn handle_munmap(addr: u64, len: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_munmap(addr, len) }
}

extern "C" fn handle_brk(addr: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_brk(addr) }
}

/// Real `clone.s`'s own register shuffle puts `flags`/`newsp`/`ptid` into this ABI's normal
/// `rdi`/`rsi`/`rdx` and `ctid` into `r10` -- `tls` (in `r8`) doesn't fit and is read kernel-side
/// off the raw frame instead, see `oxidebsd_sys_clone`'s own doc comment.
extern "C" fn handle_clone(flags: u64, newsp: u64, ptid: u64, ctid: u64) -> i64 {
    unsafe { oxidebsd_sys_clone(flags, newsp, ptid, ctid) }
}

extern "C" fn handle_set_fs_base(base: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_set_fs_base(base) }
}

extern "C" fn handle_mprotect(addr: u64, len: u64, prot: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_mprotect(addr, len, prot) }
}

extern "C" fn handle_msync(addr: u64, len: u64, flags: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_msync(addr, len, flags) }
}

extern "C" fn handle_writev(fd: u64, iov_ptr: u64, iovcnt: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_writev(fd, iov_ptr, iovcnt) }
}

extern "C" fn handle_pwritev2(fd: u64, iov_ptr: u64, iovcnt: u64, ofs: u64) -> i64 {
    unsafe { oxidebsd_sys_pwritev2(fd, iov_ptr, iovcnt, ofs) }
}

extern "C" fn handle_set_tid_address(tidptr: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_set_tid_address(tidptr) }
}

extern "C" fn handle_readv(fd: u64, iov_ptr: u64, iovcnt: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_readv(fd, iov_ptr, iovcnt) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_EXIT, handle_exit);
        oxidebsd_register_syscall(SYS_EXIT_GROUP, handle_exit_group);
        oxidebsd_register_syscall(SYS_READ, handle_read);
        oxidebsd_register_syscall(SYS_WRITE, handle_write);
        oxidebsd_register_syscall(SYS_PREAD, handle_pread);
        oxidebsd_register_syscall(SYS_PWRITE, handle_pwrite);
        oxidebsd_register_syscall(SYS_FORK, handle_fork);
        oxidebsd_register_syscall(SYS_CLONE, handle_clone);
        oxidebsd_register_syscall(SYS_WAIT4, handle_wait4);
        oxidebsd_register_syscall(SYS_EXECVE, handle_execve);
        oxidebsd_register_syscall(SYS_EXECVEAT, handle_execveat);
        oxidebsd_register_syscall(SYS_GETPID, handle_getpid);
        oxidebsd_register_syscall(SYS_GETPPID, handle_getppid);
        oxidebsd_register_syscall(SYS_MMAP, handle_mmap);
        oxidebsd_register_syscall(SYS_MUNMAP, handle_munmap);
        oxidebsd_register_syscall(SYS_BRK, handle_brk);
        oxidebsd_register_syscall(SYS_MPROTECT, handle_mprotect);
        oxidebsd_register_syscall(SYS_MSYNC, handle_msync);
        oxidebsd_register_syscall(SYS_SET_FS_BASE, handle_set_fs_base);
        oxidebsd_register_syscall(SYS_WRITEV, handle_writev);
        oxidebsd_register_syscall(SYS_PWRITEV2, handle_pwritev2);
        oxidebsd_register_syscall(SYS_SET_TID_ADDRESS, handle_set_tid_address);
        oxidebsd_register_syscall(SYS_READV, handle_readv);
    }
    0
}
