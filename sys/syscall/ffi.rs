//! Every syscall handler this kernel implements directly in the `syscall` module (rather than
//! delegating straight to a `process::do_*` function) — real `sys_*` logic, plus the thin
//! `oxidebsd_sys_*` `extern "C"` FFI adapters `sys/modules/native_abi`/`sys/modules/posix_compat`/etc.
//! actually call through (see `super`'s own module doc comment for why the real behavior stays
//! kernel-resident rather than moving into those modules). Split out from `syscall.rs`'s original
//! single file purely for size — this is still conceptually the same "syscall ABI" module, just
//! its handler-implementation half rather than its dispatch-mechanism half (`super`/`mod.rs`).

use x86_64::VirtAddr;

use crate::serial_println;

use super::{EBADF, EINVAL, ENOTTY, EPERM, EPIPE, ffi_result_to_result};
use crate::kern::subr_uio::{FOF_OFFSET, IoSeg, Uio, UioRw, UioSeg};
use crate::memory::usercopy::{Pod, UserPtr, copyin_val, copyout_val};
use crate::process::SIGPIPE;

/// Reads up to `len` bytes into `ptr` from `fd` — a pure lookup into `crate::fs::fd`'s registry now,
/// for *every* fd including 0/1/2 (see `sys/fs/fd.rs`'s module doc comment for why stdin/stdout/
/// stderr moved from being special-cased here into being ordinary, `dup2`-able registry entries:
/// stdin's own non-blocking-ring-buffer behavior lives in that file's `stdin_read` now, not here).
/// `EBADF` if `fd` isn't registered at all.
pub(crate) fn sys_read(fd: u64, ptr: u64, len: u64) -> Result<u64, u64> {
    let mut uio = Uio::user(ptr, len, UioRw::Read, 0)?;
    do_read(fd, &mut uio, 0)
}

/// Every read-side system call ends here, with its transfer built (`kern::subr_uio`).
fn do_read(fd: u64, uio: &mut Uio, flags: u64) -> Result<u64, u64> {
    match crate::fs::fd::read(fd, uio, flags) {
        Some(raw) => ffi_result_to_result(raw),
        None => Err(EBADF),
    }
}

/// Writes `len` bytes at `ptr` to `fd` — a pure lookup into `crate::fs::fd`'s registry now, for
/// *every* fd including 0/1/2 (see `sys/fs/fd.rs`'s module doc comment; stdout/stderr's own
/// UTF-8-checked `serial_print!` path lives in that file's `stdout_write` now, not here). `EBADF`
/// if `fd` isn't registered at all.
///
/// A write that fails `EPIPE` (a pipe, FIFO, socketpair or TCP connection with no reader left)
/// also raises `SIGPIPE` at the caller, as POSIX requires (not on a socket with `SO_NOSIGPIPE`); `EPIPE` is still returned for a caller
/// that ignores, blocks or catches it. Skipped for pid 0 (kernel context), where `kill`'s target
/// `0` would mean a process group.
pub(crate) fn sys_write(fd: u64, ptr: u64, len: u64) -> Result<u64, u64> {
    let mut uio = Uio::user(ptr, len, UioRw::Write, 0)?;
    do_write(fd, &mut uio, 0)
}

/// Every write-side system call ends here: `EPIPE` also raises `SIGPIPE`, unless the socket has
/// `SO_NOSIGPIPE`.
fn do_write(fd: u64, uio: &mut Uio, flags: u64) -> Result<u64, u64> {
    match crate::fs::fd::write(fd, uio, flags) {
        Some(raw) if raw == -(EPIPE as i64) => {
            let pid = crate::process::scheduler::current_pid();
            let quiet = crate::fs::fd::real_fd_of(fd)
                .is_some_and(crate::kern::uipc_socket::suppresses_sigpipe);
            if pid != 0 && !quiet {
                let _ = crate::process::signals::do_kill(pid, pid as i64, SIGPIPE as i64);
            }
            Err(EPIPE)
        }
        Some(raw) => ffi_result_to_result(raw),
        None => Err(EBADF),
    }
}

/// Real `SYS_PREAD=17`/`SYS_PWRITE=18` -- real, unremapped x86_64 Linux `__NR_pread64`/
/// `__NR_pwrite64` values (confirmed unclaimed: no prior pass in this ABI ever registered them, and
/// musl's own `pread()`/`pwrite()` -- `external/mit/musl/src/unistd/{pread,pwrite}.c` -- already
/// issue these exact numbers directly with no OxideBSD-side remap needed, unlike almost every other
/// ported syscall; `pwrite()` first tries `SYS_pwritev2` for real `RWF_NOAPPEND` support, which
/// naturally `ENOSYS`'s here (never registered) and falls through to this same plain `pwrite`
/// call). See `crate::fs::fd::pread`/`pwrite`'s own doc comments -- unlike `sys_read`/`sys_write`,
/// these never touch the fd's own current file position.
/// Real POSIX `pread`/`pwrite`: `[EINVAL] The offset argument is invalid` (`offset < 0`) --
/// checked here, once, for both, rather than in every fd kind's own callback (`offset` arrives as
/// a raw `u64` register value; reinterpreting it as `i64` matches real `off_t`'s own signed
/// convention, same as `oxfs_lseek` already does for its own offset argument). Found live via the
/// Open POSIX Test Suite's `aio_read/11-1.c`/`aio_write/9-1.c`: a real `aio_offset = -1` reached
/// `oxfs_pread`/`oxfs_pwrite` as `u64::MAX`, read as "so far past EOF" (silently 0 bytes) instead
/// of a real, reportable error.
pub(crate) fn sys_pread(fd: u64, ptr: u64, len: u64, offset: u64) -> Result<u64, u64> {
    if (offset as i64) < 0 {
        return Err(EINVAL);
    }
    let mut uio = Uio::user(ptr, len, UioRw::Read, offset)?;
    do_read(fd, &mut uio, FOF_OFFSET)
}

pub(crate) fn sys_pwrite(fd: u64, ptr: u64, len: u64, offset: u64) -> Result<u64, u64> {
    if (offset as i64) < 0 {
        return Err(EINVAL);
    }
    let mut uio = Uio::user(ptr, len, UioRw::Write, offset)?;
    do_write(fd, &mut uio, FOF_OFFSET)
}

/// A C `struct iovec { void *iov_base; size_t iov_len; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    base: u64,
    len: u64,
}

// SAFETY: two u64s, no padding, any bit pattern valid.
unsafe impl crate::memory::usercopy::Pod for IoVec {}

/// `IOV_MAX` (musl's `limits.h`).
const IOV_MAX: u64 = 1024;

/// Copies a whole `iovec` array in before any I/O, as the BSDs' `copyinuio` does: a bad array
/// fails with `EFAULT` having transferred nothing. More than `IOV_MAX` entries is `EINVAL`.
fn copyin_iovecs(iov_ptr: u64, iovcnt: u64) -> Result<alloc::vec::Vec<IoSeg>, u64> {
    if iovcnt > IOV_MAX {
        return Err(EINVAL);
    }
    (0..iovcnt)
        .map(|i| {
            copyin_val::<IoVec>(UserPtr::new(iov_ptr).add(i * 16))
                .map(|v| IoSeg { base: v.base, len: v.len })
        })
        .collect()
}

/// `SYS_WRITEV = 104` — OxideBSD's own invention, added specifically because musl's *entire*
/// stdio write path goes through `writev`, never plain `write` (see `external/mit/musl`'s
/// `src/stdio/__stdio_write.c`) — without this, `printf` et al. silently produce no output at all.
/// `(fd, iov_ptr, iovcnt)` matches real `writev`'s own argument positions exactly (unlike
/// `SYS_MMAP`, nothing here needs to be dropped to fit into this ABI's argument registers). Reads
/// `iovcnt` real C `struct iovec { void *iov_base; size_t iov_len; }` entries (16 bytes each,
/// standard layout) from `iov_ptr`, and hands them to the backend as one transfer (a `Uio`,
/// USERMEM.md §4.4), so a `writev` is as atomic as a `write` of the same total length.
pub(crate) fn sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> Result<u64, u64> {
    let mut uio = Uio::new(copyin_iovecs(iov_ptr, iovcnt)?, UioRw::Write, UioSeg::User, 0)?;
    do_write(fd, &mut uio, 0)
}

/// Real, unremapped Linux `__NR_pwritev2=328`. Real `pwritev2(2)`'s wire format is 6 real
/// arguments (`fd, iov, count, ofs_lo, ofs_hi, flags`) -- doesn't fit this ABI's 4-register
/// convention, so `external/mit/musl/src/linux/pwritev2.c`'s own call site is patched (`oxidebsd`
/// branch) to pass just `(fd, iov, count, ofs)`: `ofs_lo`/`ofs_hi` collapse into one real 64-bit
/// value (the split only ever existed for 32-bit-ABI portability shared across archs; real `off_t`
/// is already 64-bit natively here), and `flags` (`RWF_DSYNC`/`RWF_HIPRI`/etc.) is dropped
/// entirely -- none of those hints have any real effect on this filesystem's own always-durable-
/// at-commit write model, so silently ignoring them (rather than plumbing a value nothing would
/// ever consult) is honest, not a shortcut. `ofs == u64::MAX` (real `-1`) means "at the current
/// file position" per real `pwritev2(2)` semantics -- exactly what musl's own wrapper already
/// special-cased for the *non*-vectored, no-flags case (`writev`) before ever reaching this
/// syscall at all; this handler covers every other case (a genuine offset, or any nonzero `flags`)
/// uniformly through the one real code path. One transfer, as `sys_writev` above.
///
/// **Any other negative `ofs` is a real `EINVAL`, matching real Linux** -- only the exact `-1`
/// sentinel means "current position"; every other negative value is a genuinely invalid offset,
/// same as plain `pwrite`'s own check in `sys_pwrite` above. This handler used to skip that check
/// entirely and call `crate::fs::fd::pwrite` directly, which mattered because real, unmodified
/// musl's own `pwrite()` (`external/mit/musl/src/unistd/pwrite.c`) issues `SYS_pwritev2` first, not
/// `SYS_pwrite` -- so `sys_pwrite`'s own offset check was never actually reached for a plain
/// `pwrite()` call. musl's `pwrite()` also deliberately maps a caller-supplied `ofs == -1` to `-2`
/// before issuing the syscall (`if (ofs == -1) ofs--`), specifically so the real "-1 = current
/// position" sentinel isn't accidentally triggered by a genuinely invalid `pwrite(fd, buf, n, -1)`
/// call -- so `-2` (not `u64::MAX`) is exactly what reached this handler unvalidated. Found live
/// chasing a real, severe POSIX-pilot regression: `aio_write/9-1.c` (`aio_offset = -1`) spawns a
/// real worker thread that calls `pwrite(fd, buf, len, -1)`, which used to sail straight through to
/// `write_inode_at`/`resize_inode_data` with an effective offset near `u64::MAX` -- draining oxfs's
/// *entire* remaining free-block pool in one call (bounded, not a memory-safety bug -- `alloc_block`
/// just returns `None` once exhausted -- but a real, severe resource-exhaustion cascade) before
/// finally failing with `EIO` instead of the `EINVAL` real POSIX requires, starving every later test
/// in the same boot that needed to write any file at all.
pub(crate) fn sys_pwritev2(fd: u64, iov_ptr: u64, iovcnt: u64, ofs: u64) -> Result<u64, u64> {
    if ofs != u64::MAX && (ofs as i64) < 0 {
        return Err(EINVAL);
    }
    let iovs = copyin_iovecs(iov_ptr, iovcnt)?;
    if ofs == u64::MAX {
        let mut uio = Uio::new(iovs, UioRw::Write, UioSeg::User, 0)?;
        do_write(fd, &mut uio, 0)
    } else {
        let mut uio = Uio::new(iovs, UioRw::Write, UioSeg::User, ofs)?;
        do_write(fd, &mut uio, FOF_OFFSET)
    }
}

/// `SYS_READV = 153` — OxideBSD's own invention, continuing the sequence past `SYS_SHUTDOWN =
/// 152`. Added specifically because musl's stdio read path goes through `readv`, not plain
/// `read`, whenever a `FILE*` has real internal buffering enabled (`external/mit/musl`'s
/// `src/stdio/__stdio_read.c`: a 2-iovec scatter-read, the caller's own buffer plus musl's own
/// internal `FILE` buffer) — the exact same "musl doesn't call the simpler syscall you'd expect"
/// story `SYS_WRITEV` already told for the write side, just found much later because nothing had
/// exercised a *buffered* `fread()`/`fgets()` call against a real, slow-arriving data source until
/// BusyBox's `wget` actually downloaded a real file over HTTPS (confirmed live: the TLS/TCP fix
/// chain in this file's own known-gaps entry all worked — real response bytes came through —
/// then this surfaced on the very next buffered read). `(fd, iov_ptr, iovcnt)` matches real
/// `readv`'s own argument positions exactly. One transfer over every `iovec` (a `Uio`, USERMEM.md
/// §4.4): the backend fills them in order and stops where its data does, so a short read ends the
/// call there.
pub(crate) fn sys_readv(fd: u64, iov_ptr: u64, iovcnt: u64) -> Result<u64, u64> {
    let mut uio = Uio::new(copyin_iovecs(iov_ptr, iovcnt)?, UioRw::Read, UioSeg::User, 0)?;
    do_read(fd, &mut uio, 0)
}

/// `SYS_PIPE` (`105`) — unlike most of this ABI's own inventions, matches real `pipe(2)`'s wire
/// format exactly (a single pointer to a `[i32; 2]` the kernel fills in): there's no
/// argument-convention reason to invent anything different the way `open`/`execve` needed to (see
/// "musl port"/"BusyBox port" in CLAUDE.md). Delegates to `crate::fs::pipe` for the real logic — a
/// genuinely new subsystem, needed once `sh` (BusyBox's `hush`) required real pipeline support;
/// see that module's own doc comment for why a pipe read needs to actually block (not just return
/// `Ok(0)`/`EAGAIN` the way `sys_read`'s stdin case does) for a pipeline to work at all on this
/// single-core, cooperatively-scheduled kernel.
pub(crate) fn sys_pipe(fds_ptr: u64) -> Result<u64, u64> {
    crate::fs::pipe::do_pipe(fds_ptr)
}

/// Real, unremapped Linux `__NR_pipe2=293`. `pipe2.c`'s own real fallback (plain `pipe()` +
/// `fcntl(F_SETFD)`/`fcntl(F_SETFL)` per requested flag, once for each end) already made this
/// syscall's absence harmless -- registering it directly just collapses that into one round trip,
/// applying the same `set_cloexec`/`set_nonblocking` calls `sys_fcntl`'s own `F_SETFD`/`F_SETFL`
/// handling above uses, directly to both ends `do_pipe` just created.
pub(crate) fn sys_pipe2(fds_ptr: u64, flags: u64) -> Result<u64, u64> {
    let (read_fd, write_fd) = crate::fs::pipe::create_pipe()?;
    if flags & O_CLOEXEC != 0 {
        let pid = crate::process::scheduler::current_tgid();
        crate::fs::fd::set_cloexec(pid, read_fd, true);
        crate::fs::fd::set_cloexec(pid, write_fd, true);
    }
    if flags & O_NONBLOCK != 0 {
        for fd in [read_fd, write_fd] {
            if let Some(real_fd) = crate::fs::fd::real_fd_of(fd) {
                crate::fs::fd::set_nonblocking(real_fd, true);
            }
        }
    }
    crate::fs::pipe::copyout_fds(read_fd, write_fd, fds_ptr)?;
    Ok(0)
}

/// `SYS_DUP2` (`106`) — matches real `dup2(2)`'s exact `(oldfd, newfd)` signature (no
/// argument-convention mismatch here either). Delegates to `crate::fs::fd::dup2` — see that
/// function's own doc comment, and `sys/fs/fd.rs`'s module doc comment, for the refcount-aware
/// fd-aliasing this needs to actually work (not just copy function pointers around).
pub(crate) fn sys_dup2(oldfd: u64, newfd: u64) -> Result<u64, u64> {
    crate::fs::fd::dup2(oldfd, newfd).map_err(|_| EBADF)
}

/// `SYS_DUP` (`125`) — matches real `dup(2)`'s exact single-argument `(oldfd)` signature.
/// Delegates to `crate::fs::fd::dup` — see that function's own doc comment for why this exists at
/// all (BusyBox's `hush`, with `CONFIG_HUSH_JOB` on, needs it to set up `G_interactive_fd`).
pub(crate) fn sys_dup(oldfd: u64) -> Result<u64, u64> {
    crate::fs::fd::dup(oldfd).map_err(|_| EBADF)
}

/// `SYS_SET_TID_ADDRESS` (`150`) — real `set_tid_address(2)`'s exact single-pointer wire format.
/// Called unconditionally by every musl-linked program at startup (`external/mit/musl/src/env/
/// __init_tls.c`, storing the result as the main thread's own `tid`) and again after every real
/// `fork()` (`external/mit/musl/src/process/_Fork.c`) -- previously entirely unregistered, so every
/// process on this kernel silently ran with `tid = -ENOSYS` the whole time (harmless *so far*,
/// since nothing here reads `pthread_self()->tid` for anything correctness-critical, but a real,
/// previously undiscovered gap all the same, found while tracing an unrelated `wget` HTTPS
/// failure). No real threading exists on this kernel (see CLAUDE.md) -- `tid` and `pid` are the
/// same concept here, so this just echoes `scheduler::current_pid()` back, ignoring `_tidptr`
/// entirely (no `clear_child_tid`-on-exit futex wake to honor without real `pthread_create`-spawned
/// threads).
pub(crate) fn sys_set_tid_address(_tidptr: u64) -> Result<u64, u64> {
    Ok(crate::process::scheduler::current_pid())
}

/// `SYS_FCNTL` (`151`) — real `fcntl(2)`'s `(fd, cmd, arg)` shape, already only 3 arguments (musl's
/// own wrapper, `external/mit/musl/src/fcntl/fcntl.c`, always calls it this way for every command
/// this kernel implements). Only the commands BusyBox's own `libbb/xfuncs.c` (`ndelay_on`/
/// `ndelay_off`/`close_on_exec_on`) and musl's `F_DUPFD_CLOEXEC` fallback dance actually reach are
/// implemented -- everything else is `EINVAL`, matching real `fcntl`'s own behavior for a command
/// it doesn't recognize.
///
/// `F_GETFL`/`F_SETFL` only ever track/report `O_NONBLOCK` (`crate::fs::fd::is_nonblocking`/
/// `set_nonblocking`) -- real `F_GETFL` also reports the access-mode bits (`O_RDONLY`/`O_WRONLY`/
/// `O_RDWR`), not tracked here at all, a real simplification nothing in this port's roster needs
/// yet. `crate::fs::pipe::blocking_read` is the *only* reader that currently consults this flag
/// (see that module's own doc comment) -- a TCP/UDP socket or oxfs file's own read path already
/// returns promptly on "no data yet" by a different, pre-existing convention (see
/// `sys/netinet/tcp.rs`'s `tcp_read`), so `O_NONBLOCK` on one of those is accepted and tracked but
/// doesn't change behavior.
///
/// **`F_GETFD`/`F_SETFD` are real now** -- `crate::fs::fd::is_cloexec`/`set_cloexec`, a genuine
/// per-`(pid, fd)` `FD_CLOEXEC` bit, enforced by `process::do_execve` via `close_cloexec` (found
/// live: `shm_open/11-1.c`, the Open POSIX Test Suite pilot, checks it directly via `F_GETFD` --
/// real `shm_open()` always passes `O_CLOEXEC` to `open()`). `F_DUPFD`/`F_DUPFD_CLOEXEC` delegate
/// to `crate::fs::fd::dup` (ignoring the real "minimum fd number" hint in `arg` -- this kernel's
/// bump allocator has no notion of it); `F_DUPFD_CLOEXEC` additionally marks the *new* fd
/// close-on-exec (real POSIX: unlike a plain `dup`/`F_DUPFD`, this variant's whole point is
/// atomically setting the flag on the fresh fd) -- added mainly so musl's own `F_DUPFD_CLOEXEC`
/// fallback in `fcntl.c` (which always tries that command first, then falls back through
/// `F_DUPFD`) resolves cleanly instead of chasing `EINVAL` down every branch.
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;
const O_NONBLOCK: u64 = 0o4000;
/// Real `open(2)` `O_APPEND` value (`external/mit/musl/arch/generic/bits/fcntl.h`) -- `F_GETFL`
/// reports this bit back via `crate::fs::fd::is_append_of`, see that function's own doc comment
/// for the real bug (`aio_write/2-1.c`) this closes.
const O_APPEND: u64 = 0o2000;
/// Real `fcntl(2)` `FD_CLOEXEC` value (`external/mit/musl/include/fcntl.h`) -- distinct from
/// `open(2)`'s own `O_CLOEXEC` flag value (`0o2000000`, consulted by `sys/modules/oxfs`'s `oxfs_open`
/// directly, not here).
const FD_CLOEXEC: u64 = 1;
/// `open(2)`/`pipe2(2)`'s own `O_CLOEXEC` flag value -- a real, classic POSIX gotcha: this is a
/// *different* bit (`0o2000000`) from `fcntl(2)`'s `FD_CLOEXEC` (`1`) above, despite both meaning
/// "close-on-exec". `sys_pipe2` below is the one place in this file that needs to accept it on the
/// wire (matching real Linux's `pipe2(2)` flags argument) rather than just consult it internally.
const O_CLOEXEC: u64 = 0o2000000;

pub(crate) fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    let Some(real_fd) = crate::fs::fd::real_fd_of(fd) else {
        return Err(EBADF);
    };
    // Tgid, not raw pid -- CLOEXEC (like TABLE itself) is scoped by thread group, real CLONE_FILES
    // sharing -- see `crate::fs::fd`'s own module doc comment.
    let pid = crate::process::scheduler::current_tgid();
    match cmd {
        F_GETFL => {
            let mut flags = 0;
            if crate::fs::fd::is_nonblocking(real_fd) {
                flags |= O_NONBLOCK;
            }
            if crate::fs::fd::is_append_of(fd) {
                flags |= O_APPEND;
            }
            Ok(flags)
        }
        F_SETFL => {
            crate::fs::fd::set_nonblocking(real_fd, arg & O_NONBLOCK != 0);
            Ok(0)
        }
        F_GETFD => Ok(if crate::fs::fd::is_cloexec(pid, fd) {
            FD_CLOEXEC
        } else {
            0
        }),
        F_SETFD => {
            crate::fs::fd::set_cloexec(pid, fd, arg & FD_CLOEXEC != 0);
            Ok(0)
        }
        F_DUPFD => crate::fs::fd::dup_min(fd, arg).map_err(|_| EBADF),
        F_DUPFD_CLOEXEC => {
            let newfd = crate::fs::fd::dup_min(fd, arg).map_err(|_| EBADF)?;
            crate::fs::fd::set_cloexec(pid, newfd, true);
            Ok(newfd)
        }
        _ => Err(EINVAL),
    }
}

/// `SYS_SET_FS_BASE` (`103`) — OxideBSD's own invention, not modeled on any real OS's syscall (see
/// `sys/modules/native_abi/`'s doc comment for why new syscalls this ABI adds don't chase FreeBSD
/// authenticity the way the pre-existing ones do). musl's x86_64 port needs a way to point `FS`
/// at a thread's TLS block during startup — real Linux uses `arch_prctl(ARCH_SET_FS, addr)`, real
/// BSD uses `sysarch(AMD64_SET_FSBASE, &addr)`; this just takes the base address directly, no
/// subcommand or indirection needed since it's the only operation this call will ever perform.
/// Always succeeds: writing `IA32_FS_BASE` has no failure mode on this kernel (no permission check,
/// no address validation — same known gap `sys_write`/`sys_read` already have for user pointers).
///
/// **Also records `base` into the calling process's own `Process::fs_base`**, not just the live
/// MSR — `IA32_FS_BASE` is a single global register, not saved/restored per-process by
/// `context_switch::switch_context` the way `RSP`/callee-saved GPRs are, so without this every
/// *other* process's `%fs`-relative TLS access (including the stack-protector canary check every
/// musl-linked binary emits) would silently break the instant a second musl-linked process ever
/// ran. `scheduler`'s own `activate_and_prepare` restores this stored value into the MSR on every
/// switch into a process — see `Process::fs_base`'s own doc comment for the real crash this fixed.
pub(crate) fn sys_set_fs_base(base: u64) -> Result<u64, u64> {
    x86_64::registers::model_specific::FsBase::write(VirtAddr::new(base));
    if let Some(me) = crate::process::table()
        .lock()
        .get_mut(&crate::process::scheduler::current_pid())
    {
        me.fs_base = base;
    }
    Ok(0)
}

/// `SYS_KILL` (`116`) — matches real `kill(2)`'s exact `(pid, sig)` wire format, same
/// "no argument-convention patch needed" story `sys_pipe`/`sys_dup2` already established.
/// Delegates to `process::do_kill` — see that function's own doc comment for what's and isn't
/// supported (no process-group/broadcast targeting, signals 0-31 -- `0` is the real POSIX
/// existence-check convention, no signal actually sent -- no `EINTR` for a signal that arrives
/// while the target is already blocked on something else).
pub(crate) fn sys_kill(pid: u64, sig: u64) -> Result<u64, u64> {
    crate::process::do_kill(
        crate::process::scheduler::current_pid(),
        pid as i64,
        sig as i64,
    )
}

/// `SYS_SIGACTION` (`117`) — matches real `rt_sigaction(2)`'s exact
/// `(sig, act_ptr, oldact_ptr, sigsetsize)` wire format (`sigsetsize` is read but not otherwise
/// validated — this ABI always treats a signal set as a single `u64`, matching what musl's own
/// `_NSIG/8` happens to already be on this ABI). `SIGKILL`/`SIGSTOP` can never be caught, matching
/// real `sigaction()`'s own `EINVAL` for them.
///
/// **`1..=34`, not `1..=31`** -- a real bug, found live via `pthread_cancel/5-2.c` going
/// `UNRESOLVED`: `32..=34` (`SIGTIMER`/`SIGCANCEL`/`SIGSYNCCALL`) are real, valid signal numbers
/// from a kernel's own point of view, "permanently unclaimed" only as a *libc-level* convention
/// (real glibc/musl reserve them for internal NPTL-style machinery, not a POSIX or Linux
/// kernel-enforced restriction). Real, unmodified musl's own `init_cancellation()`
/// (`external/mit/musl/src/thread/pthread_cancel.c`) genuinely calls `sigaction(SIGCANCEL=33,
/// ...)` -- rejecting it here as `EINVAL` (silently, since that call's own return value is never
/// checked) left no real handler ever installed for `SIGCANCEL`, so the *actual* visible failure
/// surfaced one level up, at `pthread_cancel`'s own `pthread_kill(t, SIGCANCEL)` call hitting the
/// identical range check in `process::do_kill` (see that function's own doc comment for the
/// matching fix). Both call sites needed the same fix -- this one is necessary but not
/// sufficient on its own.
pub(crate) fn sys_sigaction(
    sig: u64,
    act_ptr: u64,
    oldact_ptr: u64,
    sigsetsize: u64,
) -> Result<u64, u64> {
    let _ = sigsetsize;
    let in_range = (1..=34).contains(&sig)
        || (crate::process::SIGRTMIN..=crate::process::SIGRTMAX).contains(&sig);
    if !in_range || sig == crate::process::SIGKILL || sig == crate::process::SIGSTOP {
        return Err(EINVAL);
    }
    crate::process::do_sigaction(
        crate::process::scheduler::current_pid(),
        sig,
        act_ptr,
        oldact_ptr,
    )
}

/// `SYS_SIGPROCMASK` (`118`) — matches real `rt_sigprocmask(2)`'s exact
/// `(how, set_ptr, oldset_ptr, sigsetsize)` wire format, same story as `sys_sigaction` above.
pub(crate) fn sys_sigprocmask(
    how: u64,
    set_ptr: u64,
    oldset_ptr: u64,
    sigsetsize: u64,
) -> Result<u64, u64> {
    let _ = sigsetsize;
    crate::process::do_sigprocmask(
        crate::process::scheduler::current_pid(),
        how,
        set_ptr,
        oldset_ptr,
    )
}

/// `SYS_SIGPENDING` (real `rt_sigpending`'s own wire slot, `494` after the collision sweep in
/// `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md` redirected it off its previous accidental home at `SYS_STAT =
/// 127`) — matches real `sigpending(2)`'s exact `(set_ptr, sigsetsize)` wire format, same
/// "sigsetsize read but not otherwise validated" story `sys_sigaction`/`sys_sigprocmask` already
/// have. Delegates to `process::do_sigpending`.
pub(crate) fn sys_sigpending(set_ptr: u64, sigsetsize: u64) -> Result<u64, u64> {
    let _ = sigsetsize;
    crate::process::do_sigpending(crate::process::scheduler::current_pid(), set_ptr)
}

/// `SYS_SIGALTSTACK` (`528`, item 3 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
/// pre-reserved batch) — matches real `sigaltstack(2)`'s exact `(ss_ptr, old_ptr)` wire format
/// (`external/mit/musl/src/signal/sigaltstack.c` is a bare 2-argument `syscall`, no call-site patch
/// needed beyond the number remap already sitting in `bits/syscall.h.in`). Delegates straight to
/// `process::do_sigaltstack` — see that function's and `AltStack`'s own doc comments for the real
/// bookkeeping-only semantics.
pub(crate) fn sys_sigaltstack(ss_ptr: u64, old_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sigaltstack(crate::process::scheduler::current_pid(), ss_ptr, old_ptr)
}

/// `SYS_PAUSE` (`529`, item 4 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved
/// batch) — matches real `pause(2)`'s exact zero-argument wire format
/// (`external/mit/musl/src/internal/syscall.h`'s `__sys_pause_cp` is a bare `__syscall_cp(SYS_pause)`,
/// no call-site patch needed beyond the number remap already sitting in `bits/syscall.h.in`).
/// Delegates straight to `process::do_pause` — see that function's and `BlockReason::
/// WaitingForSignal`'s own doc comments for the real block/wake primitive this needed.
pub(crate) fn sys_pause() -> Result<u64, u64> {
    crate::process::do_pause(crate::process::scheduler::current_pid())
}

/// `SYS_SIGSUSPEND` (`530`, item 5 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
/// pre-reserved batch) — matches real `sigsuspend(2)`'s exact `(mask_ptr, sigsetsize)` wire format
/// (`external/mit/musl/src/signal/sigsuspend.c` is a bare `syscall_cp(SYS_rt_sigsuspend, mask,
/// _NSIG/8)`, no call-site patch needed beyond the number remap already sitting in
/// `bits/syscall.h.in`). `sigsetsize` is read but not otherwise validated, same story
/// `sys_sigprocmask`/`sys_sigpending` already have. Delegates straight to `process::do_sigsuspend`
/// — see that function's own doc comment for the real block/wake-with-temporary-mask primitive
/// this needed.
pub(crate) fn sys_sigsuspend(mask_ptr: u64, sigsetsize: u64) -> Result<u64, u64> {
    let _ = sigsetsize;
    crate::process::do_sigsuspend(crate::process::scheduler::current_pid(), mask_ptr)
}

/// `SYS_SIGTIMEDWAIT` (`495`, real, unclaimed `__NR_rt_sigtimedwait`) — matches real
/// `sigtimedwait(2)`'s exact `(mask_ptr, info_ptr, ts_ptr, sigsetsize)` wire format, no musl
/// call-site patch needed. Delegates straight to `process::signals::do_sigtimedwait` — see that
/// function's own doc comment for the real signal-consuming (not handler-invoking) semantics this
/// needed, and why it's a genuinely different primitive from `do_pause`/`do_sigsuspend`.
pub(crate) fn sys_sigtimedwait(
    mask_ptr: u64,
    info_ptr: u64,
    ts_ptr: u64,
    sigsetsize: u64,
) -> Result<u64, u64> {
    let _ = sigsetsize;
    crate::process::do_sigtimedwait(
        crate::process::scheduler::current_pid(),
        mask_ptr,
        info_ptr,
        ts_ptr,
    )
}

/// `SYS_SIGQUEUE` (`496`, real, unclaimed `__NR_rt_sigqueueinfo`) — matches real `sigqueue(2)`'s
/// exact `(pid, sig, siginfo_ptr)` wire format, no musl call-site patch needed. Delegates straight
/// to `process::signals::do_sigqueue` — see that function's own doc comment for the real
/// sender-identity/payload delivery this needed.
pub(crate) fn sys_sigqueue(pid: u64, sig: u64, siginfo_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sigqueue(
        crate::process::scheduler::current_pid(),
        pid as i64,
        sig as i64,
        siginfo_ptr,
    )
}

/// `SYS_TKILL` (real, unclaimed Linux number `200` — used directly, no invented number or musl-
/// side remap needed, same "still completely unassigned in this ABI's own registry" story
/// `SYS_FCHMOD`/`SYS_FCHDIR` already have). Matches real `tkill(2)`'s exact `(tid, sig)` wire
/// format. `raise()`/`abort()`/`pthread_kill()`/`pthread_cancel()`/`timer_delete()` all call this
/// directly (`external/mit/musl/src/signal/raise.c`, `src/exit/abort.c`), never through `kill()` —
/// previously a flat `ENOSYS`, so `abort()`/`assert()` fell through to a raw trap instead of real
/// `SIGABRT` delivery. Since `SYS_SET_TID_ADDRESS` already returns the real pid as `tid` on this
/// single-threaded kernel, `tkill(tid, sig)` is exactly `kill(tid, sig)` — a thin wrapper over the
/// existing `do_kill`, not a new primitive.
pub(crate) fn sys_tkill(tid: u64, sig: u64) -> Result<u64, u64> {
    crate::process::do_kill(
        crate::process::scheduler::current_pid(),
        tid as i64,
        sig as i64,
    )
}

/// `SYS_SETPGID` (`120`) — matches real `setpgid(2)`'s exact `(pid, pgid)` wire format, same
/// "no argument-convention patch needed" story `sys_pipe`/`sys_dup2`/`sys_kill` already
/// established. Delegates to `process::do_setpgid` — see that function's own doc comment for the
/// real, documented simplification (no permission/session checks — this kernel has no uid model at
/// all yet).
pub(crate) fn sys_setpgid(pid: u64, pgid: u64) -> Result<u64, u64> {
    crate::process::do_setpgid(
        crate::process::scheduler::current_pid(),
        pid as i64,
        pgid as i64,
    )
}

/// `SYS_GETPGID` (`121`) — matches real `getpgid(2)`'s exact `(pid)` wire format.
pub(crate) fn sys_getpgid(pid: u64) -> Result<u64, u64> {
    crate::process::do_getpgid(crate::process::scheduler::current_pid(), pid as i64)
}

/// `SYS_SETSID` — real x86_64 Linux's own `__NR_setsid` value (`112`, confirmed against
/// `external/mit/musl/arch/x86_64/bits/syscall.h.in` directly, not assumed from a generic/other-arch
/// table — the exact class of mismatch CLAUDE.md's syscall-ABI section warns about elsewhere).
/// `external/mit/musl/src/unistd/setsid.c` is a bare `syscall(SYS_setsid)` with no arguments and no
/// call-site patch needed at all — registering a handler at `112` is the complete fix, unlike
/// `open`/`execve`/`chown`/... which also needed musl-side argument-shape patches. Delegates to
/// `process::do_setsid` — see that function's own doc comment.
pub(crate) fn sys_setsid() -> Result<u64, u64> {
    crate::process::do_setsid(crate::process::scheduler::current_pid())
}

/// `SYS_GETSID` (`177` — an invented number, unlike `SYS_SETSID`: real x86_64 Linux's own
/// `__NR_getsid` is `124`, which already means `SYS_IOCTL` in this ABI, so it needed the usual
/// remap-in-musl treatment `open`/`chown`/... get, not a free ride). Matches real `getsid(2)`'s
/// exact `(pid)` wire format. Delegates to `process::do_getsid` — see that function's own doc
/// comment for why this exists (`getty`'s own real fallback path).
pub(crate) fn sys_getsid(pid: u64) -> Result<u64, u64> {
    crate::process::do_getsid(crate::process::scheduler::current_pid(), pid as i64)
}

/// The credential calls (`OxideBSD-doc/SUDO.md` §5.1; `process::identity`), registered by
/// `sys/modules/posix_compat`: `getuid`/`geteuid`/`getgid`/`getegid` (158-161), `setuid`/`setgid`
/// (162/163), `getgroups` (164), `setgroups` (178), `setreuid`/`setregid` (113/114), and
/// `setresuid`/`getresuid`/`setresgid`/`getresgid` (499-502). Each takes plain integers and
/// pointers; a `-1` ID means "unchanged".
fn me() -> crate::process::Pid {
    crate::process::scheduler::current_pid()
}

pub(crate) fn sys_getuid() -> u64 {
    crate::process::do_getuid(me())
}

pub(crate) fn sys_geteuid() -> u64 {
    crate::process::do_geteuid(me())
}

pub(crate) fn sys_getgid() -> u64 {
    crate::process::do_getgid(me())
}

pub(crate) fn sys_getegid() -> u64 {
    crate::process::do_getegid(me())
}

pub(crate) fn sys_setuid(uid: u64) -> Result<u64, u64> {
    crate::process::do_setuid(me(), uid as u32)
}

pub(crate) fn sys_setgid(gid: u64) -> Result<u64, u64> {
    crate::process::do_setgid(me(), gid as u32)
}

pub(crate) fn sys_setreuid(ruid: u64, euid: u64) -> Result<u64, u64> {
    crate::process::do_setreid(me(), ruid, euid, false)
}

pub(crate) fn sys_setregid(rgid: u64, egid: u64) -> Result<u64, u64> {
    crate::process::do_setreid(me(), rgid, egid, true)
}

pub(crate) fn sys_setresuid(ruid: u64, euid: u64, suid: u64) -> Result<u64, u64> {
    crate::process::do_setresid(me(), ruid, euid, suid, false)
}

pub(crate) fn sys_setresgid(rgid: u64, egid: u64, sgid: u64) -> Result<u64, u64> {
    crate::process::do_setresid(me(), rgid, egid, sgid, true)
}

pub(crate) fn sys_getresuid(r: u64, e: u64, s: u64) -> Result<u64, u64> {
    crate::process::do_getresid(me(), r, e, s, false)
}

pub(crate) fn sys_getresgid(r: u64, e: u64, s: u64) -> Result<u64, u64> {
    crate::process::do_getresid(me(), r, e, s, true)
}

pub(crate) fn sys_getgroups(size: u64, list_ptr: u64) -> Result<u64, u64> {
    crate::process::do_getgroups(me(), size as i64, list_ptr)
}

pub(crate) fn sys_setgroups(count: u64, list_ptr: u64) -> Result<u64, u64> {
    crate::process::do_setgroups(me(), count, list_ptr)
}

/// `SYS_PRLIMIT64` (`478`) — real `prlimit64(2)`'s exact `(pid, resource, new_limit, old_limit)`
/// wire format. See `process::do_prlimit64`'s own doc comment for the real logic and why nothing
/// it stores is actually enforced.
pub(crate) fn sys_prlimit64(
    pid: u64,
    resource: u64,
    new_ptr: u64,
    old_ptr: u64,
) -> Result<u64, u64> {
    crate::process::do_prlimit64(
        crate::process::scheduler::current_pid(),
        pid as i64,
        resource,
        new_ptr,
        old_ptr,
    )
}

/// `SYS_SETPRIORITY` (`479`) — real `setpriority(2)`'s exact `(which, who, prio)` wire format.
pub(crate) fn sys_setpriority(which: u64, who: u64, prio: u64) -> Result<u64, u64> {
    crate::process::do_setpriority(
        crate::process::scheduler::current_pid(),
        which,
        who as i64,
        prio as i32,
    )
}

/// `SYS_GETPRIORITY` (`480`) — real `getpriority(2)`'s exact `(which, who)` wire format. See
/// `process::do_getpriority`'s own doc comment for the real `20 - nice` return-value convention.
pub(crate) fn sys_getpriority(which: u64, who: u64) -> Result<u64, u64> {
    crate::process::do_getpriority(crate::process::scheduler::current_pid(), which, who as i64)
}

/// `SYS_UMASK` (`487`) — real `umask(2)`'s exact single-`mask`-argument wire format. See
/// `process::do_umask`'s own doc comment for the real always-succeeds/returns-previous-mask
/// semantics this backs.
pub(crate) fn sys_umask(new_mask: u64) -> Result<u64, u64> {
    crate::process::do_umask(crate::process::scheduler::current_pid(), new_mask as u32)
}

/// `SYS_SCHED_SETSCHEDULER` (`481`) — real `sched_setscheduler(2)`'s exact
/// `(pid, policy, param_ptr)` wire format.
pub(crate) fn sys_sched_setscheduler(pid: u64, policy: u64, param_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sched_setscheduler(
        crate::process::scheduler::current_pid(),
        pid as i64,
        policy as i32,
        param_ptr,
    )
}

/// `SYS_SCHED_SETPARAM` (`507`) — real `sched_setparam(2)`'s exact `(pid, param_ptr)` wire format.
/// See `process::do_sched_setparam`'s own doc comment for why this was missing until now (musl's
/// own wrapper was permanently stubbed to `ENOSYS`, so no caller ever reached a kernel handler).
pub(crate) fn sys_sched_setparam(pid: u64, param_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sched_setparam(
        crate::process::scheduler::current_pid(),
        pid as i64,
        param_ptr,
    )
}

/// `SYS_SCHED_GETSCHEDULER` (`482`) — real `sched_getscheduler(2)`'s exact `(pid)` wire format.
pub(crate) fn sys_sched_getscheduler(pid: u64) -> Result<u64, u64> {
    crate::process::do_sched_getscheduler(crate::process::scheduler::current_pid(), pid as i64)
}

/// `SYS_SCHED_GETPARAM` (`483`) — real `sched_getparam(2)`'s exact `(pid, param_ptr)` wire format.
pub(crate) fn sys_sched_getparam(pid: u64, param_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sched_getparam(
        crate::process::scheduler::current_pid(),
        pid as i64,
        param_ptr,
    )
}

/// `SYS_SCHED_GETAFFINITY` — real Linux's own `__NR_sched_getaffinity = 204`, used directly (see
/// `process::do_sched_getaffinity`'s own doc comment for why no invented number/musl remap was
/// needed) — real `sched_getaffinity(2)`'s exact `(pid, cpusetsize, mask_ptr)` wire format.
pub(crate) fn sys_sched_getaffinity(pid: u64, cpusetsize: u64, mask_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sched_getaffinity(
        crate::process::scheduler::current_pid(),
        pid as i64,
        cpusetsize,
        mask_ptr,
    )
}

/// `SYS_SCHED_GET_PRIORITY_MAX`/`SYS_SCHED_GET_PRIORITY_MIN` (`484`/`485`) — real
/// `sched_get_priority_max/min(2)`'s exact single-`policy`-argument wire format. Pure functions of
/// `policy` alone — no current-process state involved.
pub(crate) fn sys_sched_get_priority_max(policy: u64) -> Result<u64, u64> {
    crate::process::do_sched_get_priority_max(policy as i32)
}

pub(crate) fn sys_sched_get_priority_min(policy: u64) -> Result<u64, u64> {
    crate::process::do_sched_get_priority_min(policy as i32)
}

/// `SYS_SCHED_RR_GET_INTERVAL` — real Linux's own unclaimed `508`, already pre-reserved in
/// `bits/syscall.h.in` — real `sched_rr_get_interval(2)`'s exact `(pid, ts_ptr)` wire format. See
/// `process::do_sched_rr_get_interval`'s own doc comment for the real logic.
pub(crate) fn sys_sched_rr_get_interval(pid: u64, ts_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sched_rr_get_interval(
        crate::process::scheduler::current_pid(),
        pid as i64,
        ts_ptr,
    )
}

/// `SYS_SCHED_YIELD` — real Linux's own unclaimed `24`, unremapped (musl's own `sched_yield()`
/// already calls straight through). See `process::do_sched_yield`'s own doc comment for the real
/// logic — a genuine, not fabricated, voluntary yield on this kernel's cooperative scheduler.
pub(crate) fn sys_sched_yield() -> Result<u64, u64> {
    crate::process::do_sched_yield()
}

/// `SYS_REBOOT` (`486`) — real `reboot(2)`'s exact single-`cmd`-argument wire format (musl's own
/// `reboot.c` passes the two real magic numbers as the first two syscall args and `cmd` as the
/// third — this ABI's 4-register width holds all three whole, no call-site patch needed). See
/// `process::do_reboot`'s own doc comment: every success path diverges.
pub(crate) fn sys_reboot(cmd: u64) -> Result<u64, u64> {
    crate::process::do_reboot(cmd)
}

/// `SYS_FUTEX` (real Linux's own `__NR_futex = 202`) -- real `futex(2)`'s `(uaddr, op, val, to)`
/// wire format, already exactly this ABI's 4 real registers (`__futex4_cp`, musl's own call site,
/// never issues more than these 4 args) -- no register-packing trick needed. See
/// `process::do_futex`'s own doc comment for the real `FUTEX_WAIT`/`FUTEX_WAKE` logic.
pub(crate) fn sys_futex(addr: u64, op: u64, val: u64, to: u64) -> Result<u64, u64> {
    crate::process::do_futex(crate::process::scheduler::current_pid(), addr, op, val, to)
}

/// `SYS_FUTEX_REQUEUE` (`557`, OxideBSD's own invention — real Linux's `FUTEX_REQUEUE` op doesn't
/// fit `SYS_FUTEX`'s plain 4-register wire format, see `process::do_futex_requeue`'s own doc
/// comment). `(uaddr, uaddr2, nr_wake, nr_requeue)` — exactly this ABI's 4 real registers, the
/// exact set of args the one real call site (`pthread_cond_timedwait.c`'s `unlock_requeue`, patched
/// on the `oxidebsd` musl branch to call this syscall directly) ever needs.
pub(crate) fn sys_futex_requeue(
    addr: u64,
    addr2: u64,
    nr_wake: u64,
    nr_requeue: u64,
) -> Result<u64, u64> {
    crate::process::do_futex_requeue(
        crate::process::scheduler::current_pid(),
        addr,
        addr2,
        nr_wake,
        nr_requeue,
    )
}

/// Real Linux/generic `ioctl` request codes (`external/mit/musl`'s `arch/generic/bits/ioctl.h`) --
/// this ABI's `SYS_IOCTL` reuses these verbatim as its own `request` argument values (they're
/// already architecture-generic constants, not syscall numbers, so there's nothing to remap the
/// way `open`/`execve` needed -- see `sys_ioctl`'s own doc comment).
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TCSBRK: u64 = 0x5409;
const TCXONC: u64 = 0x540A;
const TCFLSH: u64 = 0x540B;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCOUTQ: u64 = 0x5411;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const FIONREAD: u64 = 0x541B;
const FIONBIO: u64 = 0x5421;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGSID: u64 = 0x5429;
/// OxideBSD's own invention, not real Linux's `FBIOGET_VSCREENINFO` (`0x4600`) -- deliberately a
/// distinct, smaller wire struct (`RawFbInfo` below) rather than emulating that ioctl's real,
/// much larger `struct fb_var_screeninfo` layout, since nothing in this port's roster needs real
/// Linux fbdev source compatibility (see the doomgeneric/fbdoom port's own design notes: a
/// backend file written against this kernel's own syscalls, not a literal Linux fbdev emulation).
const FBIOGET_OXIDEBSD: u64 = 0x4600;

/// `FBIOGET_OXIDEBSD`'s own wire struct -- real, runtime-queried framebuffer geometry (see
/// `drivers::fbdev::FbGeometry`, which this mirrors exactly, minus `phys_base`/`len`: a userland
/// caller has no use for the physical address itself, only what `mmap()` on the same fd already
/// hands back as a virtual pointer).
#[derive(Clone, Copy)]
#[repr(C)]
struct RawFbInfo {
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
}

/// `SYS_IOCTL` (`124`), with musl's (Linux's) request codes. Terminal requests (TTY.md §5.6) act
/// on the terminal `fd` is a description of, and fail with `ENOTTY` on anything else -- musl's
/// `isatty()` is `ioctl(fd, TIOCGWINSZ)`, so this is what makes a pipe or a file not a tty.
/// `FBIOGET_OXIDEBSD` acts on a `/dev/fb0` descriptor. Unknown requests are logged.
pub(crate) fn sys_ioctl(fd: u64, request: u64, argp: u64) -> Result<u64, u64> {
    // musl's ioctl() takes the request as an int, so one with bit 31 set (`TIOCGPTN`,
    // 0x80045430) arrives sign-extended; requests are 32 bits.
    let request = request as u32 as u64;
    let real_fd = crate::fs::fd::real_fd_of(fd).ok_or(EBADF)?;
    if request == FBIOGET_OXIDEBSD {
        let geom = crate::fs::fd::framebuffer_geometry_of(fd).ok_or(ENOTTY)?;
        let info = RawFbInfo { width: geom.width, height: geom.height, pitch: geom.pitch, bpp: geom.bpp };
        copyout_val(&info, UserPtr::new(argp))?;
        return Ok(0);
    }
    if request == FIONBIO {
        // Not terminal-specific: sets O_NONBLOCK on the description.
        // SAFETY: as above.
        let on = unsafe { *(argp as *const i32) } != 0;
        crate::fs::fd::set_nonblocking(real_fd, on);
        return Ok(0);
    }
    if let Some(r) = crate::tty::pty::ioctl(real_fd, request, argp) {
        return r;
    }
    let Some(tty) = crate::tty::of_real_fd(real_fd) else {
        if !matches!(request, TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ | TIOCSCTTY | TIOCGPGRP | TIOCSPGRP | TIOCNOTTY | TIOCGSID | FIONREAD | TCFLSH | TCXONC | TCSBRK | TIOCOUTQ) {
            serial_println!("[boot] unrecognized ioctl request 0x{:x}", request);
        }
        return Err(ENOTTY);
    };
    let cx = crate::tty::caller(crate::fs::fd::is_nonblocking(real_fd));
    let int_arg = || -> i32 {
        // SAFETY: as above.
        unsafe { *(argp as *const i32) }
    };
    match request {
        TCGETS => {
            // SAFETY: as above.
            unsafe { *(argp as *mut crate::tty::RawTermios) = crate::tty::termios(tty) };
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            // SAFETY: as above.
            let t = unsafe { *(argp as *const crate::tty::RawTermios) };
            // Output is written synchronously, so draining it (TCSETSW) is immediate.
            crate::tty::set_termios(tty, t, request == TCSETSF, &cx).map(|()| 0)
        }
        TIOCGWINSZ => {
            // SAFETY: as above.
            unsafe { *(argp as *mut crate::tty::Winsize) = crate::tty::winsize(tty) };
            Ok(0)
        }
        TIOCSWINSZ => {
            // SAFETY: as above.
            crate::tty::set_winsize(tty, unsafe { *(argp as *const crate::tty::Winsize) });
            Ok(0)
        }
        TIOCSCTTY => crate::tty::set_controlling(tty, &cx).map(|()| 0),
        TIOCNOTTY => crate::tty::release(tty, &cx).map(|()| 0),
        TIOCGPGRP => {
            let pgrp = crate::tty::pgrp(tty, &cx)?;
            copyout_val(&(pgrp as i32), UserPtr::new(argp))?;
            Ok(0)
        }
        TIOCSPGRP => {
            let pgid = int_arg();
            if pgid <= 0 {
                return Err(EINVAL);
            }
            crate::tty::set_pgrp(tty, pgid as u64, &cx).map(|()| 0)
        }
        TIOCGSID => {
            let sid = crate::tty::session_of(tty, &cx)?;
            copyout_val(&(sid as i32), UserPtr::new(argp))?;
            Ok(0)
        }
        FIONREAD => {
            copyout_val(&(crate::tty::pending_input(tty) as i32), UserPtr::new(argp))?;
            Ok(0)
        }
        // Output is never queued: nothing waits in it and draining finishes at once.
        TIOCOUTQ => {
            copyout_val(&0i32, UserPtr::new(argp))?;
            Ok(0)
        }
        TCSBRK => Ok(0),
        TCFLSH => crate::tty::flush(tty, argp).map(|()| 0),
        TCXONC => crate::tty::flow(tty, argp).map(|()| 0),
        _ => {
            serial_println!("[boot] unrecognized ioctl request 0x{:x}", request);
            Err(ENOTTY)
        }
    }
}

/// `SYS_GET_KEYEVENT` (`558`) — real, general-purpose raw keyboard-event polling: pops one
/// `console::keyevents::RawKeyEvent` (press/release, this kernel's own small stable keycode
/// space) into the caller's pointer. **Never blocks** — `Ok(0)` means nothing is currently
/// buffered (not an error), `Ok(1)` means one event was written to `out_ptr`. Deliberately
/// distinct from `console::stdin`'s own (blocking) ASCII byte stream — see
/// `console::keyevents`'s own module doc comment for why a held-key-state consumer (a game loop,
/// a future window system) needs this instead.
pub(crate) fn sys_get_keyevent(out_ptr: u64) -> Result<u64, u64> {
    match crate::console::keyevents::pop_event() {
        Some(event) => {
            crate::memory::usercopy::copyout_val(
                &event,
                crate::memory::usercopy::UserPtr::new(out_ptr),
            )?;
            Ok(1)
        }
        None => Ok(0),
    }
}

/// musl's own `struct utsname` (`external/mit/musl/include/sys/utsname.h`): six fixed 65-byte
/// NUL-padded fields, no padding between them -- same "byte-exact against the real musl layout"
/// discipline `sys/modules/oxfs`'s `MuslStat` already follows for `stat(2)`.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawUtsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

// SAFETY: six byte arrays, no padding.
unsafe impl crate::memory::usercopy::Pod for RawUtsname {}

/// The host name, NUL-terminated as `struct utsname` holds it; `oxidebsd` until
/// `/etc/rc.d/hostname` sets one.
static HOSTNAME: spin::Mutex<[u8; 65]> = spin::Mutex::new(utsname_field("oxidebsd"));

/// The NIS domain name (`kern.domainname`, `uname`'s `domainname`); empty until set.
static DOMAINNAME: spin::Mutex<[u8; 65]> = spin::Mutex::new([0; 65]);

/// `uname -v` and, with a newline, `kern.version`.
pub(crate) const UNAME_VERSION: &str = concat!("OxideBSD ", env!("CARGO_PKG_VERSION"), " GENERIC");

fn field_bytes(field: &[u8; 65]) -> alloc::vec::Vec<u8> {
    let end = field.iter().position(|&b| b == 0).unwrap_or(64);
    field[..end].to_vec()
}

/// Stores `name` in a `utsname`-sized field: at most 64 bytes, as Linux and the BSDs'
/// `MAXHOSTNAMELEN - 1` allow.
fn set_field(field: &spin::Mutex<[u8; 65]>, name: &[u8]) -> Result<(), u64> {
    if name.len() > 64 {
        return Err(EINVAL);
    }
    let mut new = [0u8; 65];
    new[..name.len()].copy_from_slice(name);
    *field.lock() = new;
    Ok(())
}

/// The host name, shared by `sethostname(2)`, `uname(2)` and `kern.hostname`.
pub(crate) fn hostname() -> alloc::vec::Vec<u8> {
    field_bytes(&HOSTNAME.lock())
}

pub(crate) fn set_hostname(name: &[u8]) -> Result<(), u64> {
    set_field(&HOSTNAME, name)
}

pub(crate) fn domainname() -> alloc::vec::Vec<u8> {
    field_bytes(&DOMAINNAME.lock())
}

pub(crate) fn set_domainname(name: &[u8]) -> Result<(), u64> {
    set_field(&DOMAINNAME, name)
}

/// `SYS_SETHOSTNAME` (576, registered by `sys/modules/posix_compat`): `sethostname(name, len)`.
/// Root only.
pub(crate) fn sys_sethostname(name_ptr: u64, len: u64) -> Result<u64, u64> {
    if crate::process::identity::oxidebsd_current_uid() != 0 {
        return Err(EPERM);
    }
    if len > 64 {
        return Err(EINVAL);
    }
    // SAFETY: the same unvalidated-user-pointer gap every other copy in this file has.
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, len as usize) };
    set_hostname(name)?;
    Ok(0)
}

const fn utsname_field(s: &str) -> [u8; 65] {
    let mut field = [0u8; 65];
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && i < 64 {
        field[i] = bytes[i];
        i += 1;
    }
    field
}

/// `SYS_UNAME` (registered as `137` by `sys/modules/posix_compat`, continuing on from `SYS_MKDIR =
/// 136`) — happens to match real `uname(2)`'s exact single-pointer wire format (musl's own
/// `uname()`, `external/mit/musl/src/misc/uname.c`, is just `syscall(SYS_uname, uts)` — no
/// derived-argument computation from the pointer the way `open`'s `strlen` needed, so no
/// argument-convention patch was needed on the musl side beyond the usual number remap).
///
/// `nodename` is the host name `sethostname(2)` set (`HOSTNAME`). `release` is this crate's own
/// `CARGO_PKG_VERSION`, so bumping `Cargo.toml`'s `version` moves what `uname -a`/`uname -r`
/// report. `version` is shaped as the BSDs shape it -- system, release, kernel configuration
/// (FreeBSD's `FreeBSD 14.1-RELEASE ... GENERIC`, NetBSD's `NetBSD 10.0 (GENERIC) #0: ...`) --
/// without a build number or date, which this kernel has no source for, and without Linux's
/// feature tags (it used to claim `SMP PREEMPT`, on a single-core kernel).
pub(crate) fn sys_uname(uts_ptr: u64) -> Result<u64, u64> {
    let uts = RawUtsname {
        sysname: utsname_field("OxideBSD"),
        nodename: *HOSTNAME.lock(),
        release: utsname_field(env!("CARGO_PKG_VERSION")),
        version: utsname_field(UNAME_VERSION),
        machine: utsname_field(crate::kern::kern_sysctl::MACHINE),
        domainname: *DOMAINNAME.lock(),
    };
    crate::memory::usercopy::copyout_val(&uts, crate::memory::usercopy::UserPtr::new(uts_ptr))?;
    Ok(0)
}

/// musl's own `struct timeval` on x86_64 (`external/mit/musl/include/alltypes.h.in`'s `STRUCT
/// timeval` template): a `time_t`/`suseconds_t` pair, both 8 bytes on this arch.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RawTimeval {
    tv_sec: i64,
    tv_usec: i64,
}

/// musl's own `struct rusage` on x86_64 (`external/mit/musl/include/sys/resource.h`): two
/// `timeval`s, then 14 `long` fields, then a 16-`long` reserved tail -- 272 bytes total. Backs both
/// `SYS_GETRUSAGE` and `SYS_WAIT4`'s own optional 4th `rusage_ptr` argument (see
/// `write_zeroed_rusage`, below). This kernel tracks no per-process CPU time/memory-usage
/// accounting at all (`/proc/stat`'s own `cpu` line is already an honest all-zero placeholder for
/// the identical reason) -- every field here is a real, correctly-shaped, honestly-zeroed
/// placeholder rather than an invented number, same tier as `/proc/meminfo`'s `MemFree ==
/// MemTotal`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RawRusage {
    ru_utime: RawTimeval,
    ru_stime: RawTimeval,
    fields: [i64; 14],
    reserved: [i64; 16],
}

const _: () = assert!(core::mem::size_of::<RawRusage>() == 272);

/// Writes an all-zero `RawRusage` to `ptr` if it's non-null -- shared by `sys_getrusage` and
/// `do_wait4`'s own optional `rusage_ptr` argument (`sys/process.rs`), the same "one real helper,
/// two call sites" shape `write_stat`-style functions elsewhere in this codebase already use.
pub(crate) fn write_zeroed_rusage(ptr: u64) -> Result<(), u64> {
    if ptr == 0 {
        return Ok(());
    }
    copyout_val(&RawRusage::default(), UserPtr::new(ptr))
}

/// `SYS_GETRUSAGE` (registered by `sys/modules/posix_compat`, continuing on from `SYS_UMASK = 487`) --
/// real `getrusage(2)`'s exact `(who, rusage_ptr)` wire format (musl's own `getrusage()`,
/// `external/mit/musl/src/misc/getrusage.c`, already issues a plain 2-argument raw syscall with a
/// bare pointer, no length-prefixing involved, so no call-site patch was needed beyond the usual
/// number remap). `who` (`RUSAGE_SELF`/`RUSAGE_CHILDREN`) makes no difference to the answer -- see
/// `RawRusage`'s own doc comment for why. **Same latent staleness `sys_times` had until its own
/// fix** (this call site also predates `Process::cpu_ticks`) -- `ru_utime`/`ru_stime` could be
/// derived from `cpu_ticks`/`child_cpu_ticks` the same way, but nothing currently depends on it
/// (unlike `times(2)`, which `fork/8-1.c` needed real values from to avoid a permanent hang) --
/// left as an honest all-zero placeholder, a known follow-up, not silently forgotten.
pub(crate) fn sys_getrusage(who: u64, rusage_ptr: u64) -> Result<u64, u64> {
    let _ = who;
    write_zeroed_rusage(rusage_ptr)?;
    Ok(0)
}

/// musl's own `struct tms` on x86_64 (`external/mit/musl/include/sys/times.h`): four `clock_t`
/// (`long`, 8 bytes on this arch) fields, no padding -- 32 bytes total.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RawTms {
    tms_utime: i64,
    tms_stime: i64,
    tms_cutime: i64,
    tms_cstime: i64,
}

const _: () = assert!(core::mem::size_of::<RawTms>() == 32);

/// `SYS_TIMES` (real `times`'s own wire slot, `493` after the collision sweep in
/// `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md` redirected it off its previous accidental home at
/// `SYS_MMAP = 100`) -- matches real `times(2)`'s exact `(tms_ptr)` wire format
/// (`external/mit/musl/src/time/times.c` is a bare `__syscall(SYS_times, tms)`, no call-site patch
/// needed). The return value (real `times(2)`'s "clock ticks since an arbitrary point in the
/// past") is `crate::cpu::interrupts::ticks()` itself, the same real `TIMER_HZ`-cadence counter
/// `sys_clock_gettime`'s own `CLOCK_MONOTONIC` arm already uses -- an honest, non-fabricated
/// value, just not tied to any particular epoch (matching the standard's own "arbitrary point"
/// wording).
///
/// **`tms_utime`/`tms_cutime` are real, not fabricated** -- `Process::cpu_ticks`/`child_cpu_ticks`
/// (see each field's own doc comment), the same real per-process CPU-time counter
/// `CLOCK_PROCESS_CPUTIME_ID` already reads. **Was previously an unconditional all-zero
/// placeholder** (this call site predates `cpu_ticks`, added later purely for
/// `clock_gettime`, and was never revisited) -- a real, permanent hang, found live via
/// `fork/8-1.c`: its child thread busy-loops forever on `while ((tms_utime + tms_stime) <= 0)`,
/// which an always-zero `tms_utime` can never satisfy, and its parent separately checks
/// `tms_cutime`/`tms_cstime` become nonzero after `waitpid` reaps that child. **`tms_stime`/
/// `tms_cstime` stay honest zero** -- this kernel tracks one undifferentiated per-process tick
/// counter, not a real user/kernel split (same tier `cpu_ticks`'s own doc comment already
/// establishes); putting the whole count in the `u`-side buckets (time spent running the
/// process's own code) is the more accurate choice for what actually gets measured here than
/// splitting it arbitrarily. `getrusage(2)`'s own `ru_utime`/`ru_stime` have the identical latent
/// staleness (see `sys_getrusage`'s own doc comment) -- not fixed here, since nothing currently
/// depends on it the way this hang did.
pub(crate) fn sys_times(tms_ptr: u64) -> Result<u64, u64> {
    if tms_ptr != 0 {
        let proc = crate::process::table()
            .lock()
            .get(&crate::process::scheduler::current_pid())
            .map(|p| (p.cpu_ticks, p.child_cpu_ticks));
        let (cpu_ticks, child_cpu_ticks) = proc.unwrap_or((0, 0));
        copyout_val(&RawTms {
                tms_utime: cpu_ticks as i64,
                tms_stime: 0,
                tms_cutime: child_cpu_ticks as i64,
                tms_cstime: 0,
            }, UserPtr::new(tms_ptr))?;
    }
    Ok(crate::cpu::interrupts::ticks())
}

/// Real `getrandom(2)`'s `GRND_NONBLOCK`/`GRND_RANDOM` flag bits -- not syscall numbers, no
/// remapping needed.
const GRND_NONBLOCK: u64 = 0x0001;
const GRND_RANDOM: u64 = 0x0002;

/// `SYS_GETRANDOM` (`526`, pre-reserved ahead of implementation in
/// `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md` -- item 1 of that doc's own 28-syscall planned-
/// implementation-order batch) -- real `getrandom(2)`'s exact `(buf_ptr, buflen, flags)` wire
/// format (`external/mit/musl/src/linux/getrandom.c` is a bare 3-argument `syscall_cp`, no
/// call-site patch needed beyond the number remap already in `bits/syscall.h.in`). Only reachable
/// via `getentropy()` in this port's own roster (BusyBox's `seedrng` applet doesn't build here --
/// missing `linux/random.h`) -- and `external/mit/musl/src/misc/getentropy.c` caps `len` at `256`
/// itself and loops calling `getrandom()` until satisfied, so this handler can safely always fill
/// the whole request in one shot: never partial, never blocking. `sys/random.rs`'s own generator
/// never fails or waits on an entropy-availability threshold (see that module's own doc comment
/// on why `/dev/random`/`/dev/urandom` already share one source), so that loop always exits after
/// its first iteration here -- matching real `getrandom(2)`'s contract in the only case that
/// actually matters to any live caller.
///
/// `flags` are accepted but make no difference to the output for the same reason -- no
/// blocking-on-low-entropy distinction exists to honor `GRND_NONBLOCK` against, and `GRND_RANDOM`
/// (draw from `/dev/random`'s pool specifically) is moot when both device nodes are already the
/// same source. Any bit outside that pair is a real `EINVAL`, matching real Linux.
pub(crate) fn sys_getrandom(buf_ptr: u64, buflen: u64, flags: u64) -> Result<u64, u64> {
    if flags & !(GRND_NONBLOCK | GRND_RANDOM) != 0 {
        return Err(EINVAL);
    }
    // Generated a kernel chunk at a time and copied out.
    let mut chunk = [0u8; 256];
    let mut done = 0u64;
    while done < buflen {
        let n = (buflen - done).min(chunk.len() as u64) as usize;
        crate::random::oxidebsd_random_bytes(chunk.as_mut_ptr() as u64, n as u64);
        crate::memory::usercopy::copyout(&chunk[..n], UserPtr::new(buf_ptr).add(done))?;
        done += n as u64;
    }
    Ok(buflen)
}

/// musl's own `struct sysinfo` on x86_64 (`external/mit/musl/include/sys/sysinfo.h`) -- confirmed
/// 368 bytes via a direct `offsetof`/`sizeof` probe against that exact field list (Rust's own
/// `repr(C)` layout rules match a C compiler's here since every field is a plain scalar/array with
/// no explicit alignment override, but the *value* was verified rather than assumed given how easy
/// an off-by-a-few-bytes struct-layout bug is to get wrong silently). An 8-byte gap after
/// `procs`/`pad` (offset 84) before `totalhigh` (offset 88) is real, natural `unsigned long`
/// alignment padding, not a missing field.
#[derive(Clone, Copy)]
#[repr(C)]
struct RawSysinfo {
    uptime: u64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    /// The alignment gap before `totalhigh`, explicit so it goes out zeroed, not as whatever
    /// kernel stack bytes were there (it did, before `copyout_val`).
    pad_align: u32,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    reserved: [u8; 256],
    /// Trailing alignment to 368 bytes, explicit for the same reason.
    pad_end: u32,
}

const _: () = assert!(core::mem::size_of::<RawSysinfo>() == 368);

/// `SYS_SYSINFO` (`527`, item 2 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved
/// batch) -- real `sysinfo(2)`'s exact `(info_ptr)` wire format (`external/mit/musl/src/linux/
/// sysinfo.c` is a bare 1-argument `syscall(SYS_sysinfo, info)`, no call-site patch needed beyond
/// the number remap already in `bits/syscall.h.in`). Not a POSIX interface at all (Linux-specific),
/// but the confirmed live blocker for `free`/`uptime`'s primary numbers (`procps/{free,uptime}.c`)
/// -- see `OxideBSD-doc/BUSYBOX_APPLETS.md`'s own `NEEDS_PROC` entries for those two applets.
///
/// Same honesty tier as `RawRusage`/`RawTms` above: real fields where this kernel actually tracks
/// the concept, an honest placeholder (not a fabricated number) everywhere it doesn't.
/// - `uptime`: real, `ticks() / TIMER_HZ` -- the same conversion `/proc/uptime`
///   (`oxidebsd_proc_uptime`) and `sys_clock_gettime`'s `CLOCK_MONOTONIC` arm already use.
/// - `totalram`: real, `memory::usable_ram_bytes()`, with `mem_unit = 1` so the byte count needs
///   no further scaling -- matches `/proc/meminfo`'s own `MemTotal` source exactly.
/// - `freeram`/`sharedram`: free pages and pages shared between processes, from
///   `memory::vm_meter` (SYSCTL.md §10.3).
/// - `loads`: the load average (`kern::kern_synch`), rescaled from `FSCALE` to `sysinfo`'s own
///   16-bit fraction (SYSCTL.md §9.2).
/// - `procs`: real, the live process table's own length (`process::table().lock().len()`) --
///   truncated to `u16` (real `sysinfo(2)`'s own field width; this table will never remotely
///   approach 65536 entries on this kernel).
/// - `bufferram`/`totalswap`/`freeswap`/`totalhigh`/`freehigh`: honest `0` -- no buffer cache
///   (the read-only page cache, `memory::pagecache`, isn't one) and no swap exist, same tier as `/proc/meminfo`'s own `Buffers`/`Cached`/`SwapTotal`/`SwapFree`
///   placeholders.
pub(crate) fn sys_sysinfo(info_ptr: u64) -> Result<u64, u64> {
    let ticks = crate::cpu::interrupts::ticks();
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let total_ram = crate::memory::usable_ram_bytes();
    let procs = crate::process::table().lock().len().min(u16::MAX as usize) as u16;
    let vm = crate::memory::vm_meter::stats();
    // `SI_LOAD_SHIFT` is 16, `FSHIFT` 11.
    let loads = crate::kern::kern_synch::averages().map(|a| (a as u64) << (16 - crate::kern::kern_synch::FSHIFT));
    let info = RawSysinfo {
        uptime: ticks / hz,
        loads,
        totalram: total_ram,
        freeram: vm.free * 4096,
        sharedram: vm.shared * 4096,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs,
        pad: 0,
        pad_align: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 1,
        reserved: [0; 256],
        pad_end: 0,
    };
    copyout_val(&info, UserPtr::new(info_ptr))?;
    Ok(0)
}

/// musl's own `struct timespec` on x86_64 (`external/mit/musl/include/alltypes.h.in`'s `STRUCT
/// timespec` template, `time_t`/`long` both 8 bytes on this arch): two `i64`s, no padding.
#[derive(Clone, Copy)]
#[repr(C)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

const _: () = assert!(core::mem::size_of::<RawSysinfo>() == 368);
// SAFETY: integers and integer arrays, no padding (RawSysinfo's gaps are explicit fields).
unsafe impl Pod for RawTimespec {}
unsafe impl Pod for RawTimeval {}
unsafe impl Pod for RawRusage {}
unsafe impl Pod for RawTms {}
unsafe impl Pod for RawSysinfo {}
unsafe impl Pod for RawFbInfo {}

/// Real, architecture-generic `clockid_t` values (`external/mit/musl/include/time.h`) -- not
/// syscall numbers, so no remapping needed, unlike `SYS_clock_gettime` itself below.
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;

/// Linux's other clocks, which musl defines and programs use (sudo-rs's session records use
/// `CLOCK_BOOTTIME`), as the two clocks they amount to here: OxideBSD never suspends, so time
/// since boot is the monotonic clock, and nothing is coarser or rawer than the tick.
fn canonical_clock(clockid: u64) -> u64 {
    const CLOCK_MONOTONIC_RAW: u64 = 4;
    const CLOCK_REALTIME_COARSE: u64 = 5;
    const CLOCK_MONOTONIC_COARSE: u64 = 6;
    const CLOCK_BOOTTIME: u64 = 7;
    match clockid {
        CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => CLOCK_MONOTONIC,
        CLOCK_REALTIME_COARSE => CLOCK_REALTIME,
        other => other,
    }
}

/// Decodes a real, dynamic per-process/per-thread `clockid_t` -- the encoding
/// `clock_getcpuclockid(2)`'s own musl implementation produces
/// (`external/mit/musl/src/time/clock_getcpuclockid.c`: `clockid_t id = (-pid-1)*8U + 2`, matching
/// real Linux's own `MAKE_PROCESS_CPUCLOCK`/`CPUCLOCK_PID` scheme). The wire value arrives here
/// already sign-extended to 64 bits (musl's own `__syscall` takes `long` arguments, and a C call
/// site passing a negative `int` widens it that way automatically) -- any negative `clockid`
/// therefore packs a target pid into its high bits, recovered via `pid = !(id >> 3)` (arithmetic
/// right shift, matching real Linux's own `pid_for_clock` decode exactly; the low 3 bits this
/// discards are `clock_getcpuclockid`'s own `CPUCLOCK_*` sub-selector, meaningless here since this
/// kernel has no real threads for `CPUCLOCK_PERTHREAD_MASK` to distinguish). A decoded pid of `0`
/// is real Linux's own "the calling process itself" convention (`pid_for_clock`'s `upid == 0`
/// special case) -- what `clock_getcpuclockid(0, ...)` itself produces.
///
/// Returns `None` for a non-negative (real standard) `clockid`, letting every caller's own `match`
/// fall through to its ordinary `_ => Err(EINVAL)` arm for a genuinely unrecognized positive value
/// (`clock_getres/6-1.c`/`6-2.c`, `clock_settime/17-1.c`).
fn decode_dynamic_cpu_clock_pid(
    caller_pid: crate::process::Pid,
    clockid: u64,
) -> Option<crate::process::Pid> {
    let raw = clockid as i64;
    if raw >= 0 {
        return None;
    }
    // Real Linux's own `CPUCLOCK_WHICH(clock) >= CPUCLOCK_MAX` check: the low 2 bits are a real
    // sub-selector (`CPUCLOCK_PROF`/`_VIRT`/`_SCHED` = 0/1/2), and `3` is not a valid value for it
    // -- rejecting it here is what makes a genuinely-garbage negative `clockid` like `-1` (whose
    // low 2 bits are `11` = 3) real `EINVAL` instead of silently decoding as a valid clock
    // (`clock_gettime/8-2.c`). musl's own `clock_getcpuclockid()` always encodes `2` (`CPUCLOCK_
    // SCHED`) in this position, so a legitimately-encoded id is never affected.
    if raw & 3 == 3 {
        return None;
    }
    let decoded = !(raw >> 3);
    Some(if decoded == 0 {
        caller_pid
    } else {
        decoded as crate::process::Pid
    })
}

/// `cpu_ticks` -> `(tv_sec, tv_nsec)`, shared by `sys_clock_gettime`'s `CLOCK_PROCESS_CPUTIME_ID`/
/// `CLOCK_THREAD_CPUTIME_ID`/dynamic-clock arms and `sys_clock_getres`'s own resolution report.
fn cpu_time_ticks_to_ts(cpu_ticks: u64) -> RawTimespec {
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    RawTimespec {
        tv_sec: (cpu_ticks / hz) as i64,
        tv_nsec: ((cpu_ticks % hz) * 1_000_000_000 / hz) as i64,
    }
}

/// `SYS_CLOCK_GETTIME` (registered as `138` by `sys/modules/clock`, continuing on from `SYS_UNAME =
/// 137`) — matches real `clock_gettime(2)`'s exact `(clockid, timespec_ptr)` wire format, so only
/// the number needed remapping. musl's own `time()`/`gettimeofday()` (`external/mit/musl/src/time/
/// time.c`/`gettimeofday.c`) are both plain wrappers around `clock_gettime(CLOCK_REALTIME, ...)`
/// at the C level, not separate syscalls, so this one remap is enough to unlock all three.
///
/// `CLOCK_REALTIME` reports real, sub-second-precision wall-clock time
/// (`sys/cpu/rtc.rs`'s `unix_epoch_now_precise` -- a `ticks()`-derived offset calibrated once
/// against the CMOS RTC, not a fresh RTC read every call; see that function's own doc comment for
/// why). `CLOCK_MONOTONIC` converts `sys/cpu/interrupts.rs`'s `ticks()` against `sys/cpu/pit.rs`'s
/// now-known `TIMER_HZ`, seconds since boot -- not wall-clock time, matching real `CLOCK_MONOTONIC`
/// semantics (unspecified epoch, only meaningful as a delta between two readings).
/// `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID` both read `Process::cpu_ticks` (see that
/// field's own doc comment for why real threading's absence makes the two clockids equivalent
/// here, and for the real gap this closes: `clock_gettime/4-1.c`, the Open POSIX Test Suite
/// pilot). Any other `clockid` is `EINVAL`.
pub(crate) fn sys_clock_gettime(clockid: u64, ts_ptr: u64) -> Result<u64, u64> {
    let clockid = canonical_clock(clockid);
    let caller_pid = crate::process::scheduler::current_pid();
    let ts = match clockid {
        CLOCK_REALTIME => {
            let (tv_sec, tv_nsec) = crate::cpu::rtc::unix_epoch_now_precise();
            RawTimespec { tv_sec, tv_nsec }
        }
        CLOCK_MONOTONIC => {
            let ticks = crate::cpu::interrupts::ticks();
            let hz = crate::cpu::pit::TIMER_HZ as u64;
            RawTimespec {
                tv_sec: (ticks / hz) as i64,
                tv_nsec: ((ticks % hz) * 1_000_000_000 / hz) as i64,
            }
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            let cpu_ticks = crate::process::table()
                .lock()
                .get(&caller_pid)
                .map(|p| p.cpu_ticks)
                .unwrap_or(0);
            cpu_time_ticks_to_ts(cpu_ticks)
        }
        _ => {
            // Real `clock_getcpuclockid(2)` support -- see `decode_dynamic_cpu_clock_pid`'s own
            // doc comment. A decoded pid this kernel has no process for is `EINVAL`
            // (`clock_getcpuclockid`'s own musl wrapper maps that to `ESRCH` client-side; a direct
            // `clock_gettime` caller sees the plain `EINVAL`, matching real Linux).
            let target_pid = decode_dynamic_cpu_clock_pid(caller_pid, clockid).ok_or(EINVAL)?;
            let cpu_ticks = crate::process::table()
                .lock()
                .get(&target_pid)
                .map(|p| p.cpu_ticks)
                .ok_or(EINVAL)?;
            cpu_time_ticks_to_ts(cpu_ticks)
        }
    };
    copyout_val(&ts, UserPtr::new(ts_ptr))?;
    Ok(0)
}

/// `SYS_CLOCK_GETRES` -- real Linux's own unclaimed `229` (confirmed against every `SYS_*`
/// constant already registered in this ABI; musl's `bits/syscall.h.in` already carries this value
/// unremapped, and `external/mit/musl/src/time/clock_getres.c` calls straight through, so no
/// musl-side patch was needed, just a kernel-side handler). Every clock this kernel implements
/// ticks at a real, honest `TIMER_HZ` (`sys/cpu/pit.rs`) cadence by default -- including the
/// sub-second `CLOCK_REALTIME` reading `sys_clock_gettime` derives from it -- so
/// `1_000_000_000 / TIMER_HZ`ns is the fallback resolution value for every recognized `clockid`,
/// standard or dynamic per-process (see `decode_dynamic_cpu_clock_pid`). **`CLOCK_REALTIME`/
/// `CLOCK_MONOTONIC` report `cpu::hpet::resolution_ns()` instead whenever a real ACPI HPET was
/// found this boot** (`cpu::hpet`'s own module doc comment has the full story) -- genuinely finer
/// than one PIT tick, since `process::timers`' own POSIX interval-timer overrun accounting now
/// backs it with real sub-tick precision for exactly these two clockids (see `PosixTimer::
/// deadline_ns`). The two cputime clockids keep the plain `TIMER_HZ` value unconditionally --
/// `Process::cpu_ticks` is still genuinely tick-quantized, so claiming finer resolution there
/// would be dishonest. `res_ptr == 0` is real POSIX-legal (the resolution query alone, `clockid`
/// validity is still checked) so only written when non-null. Closes `clock_getres/1-1.c`/`3-1.c`/
/// `6-1.c`/`6-2.c`/`7-1.c`/`8-1.c` and, transitively (this is the only syscall
/// `clock_getcpuclockid(2)`'s own musl implementation issues, purely to validate the pid before
/// handing the encoded `clockid_t` back), `clock_getcpuclockid/1-1.c`/`2-1.c`; later,
/// `timer_getoverrun/2-3.c` (its own `expectedoverruns`/fudge-factor math needs a resolution well
/// under 10ms to have any pass window at all -- see `cpu::hpet`'s own module doc comment).
pub(crate) fn sys_clock_getres(clockid: u64, res_ptr: u64) -> Result<u64, u64> {
    let clockid = canonical_clock(clockid);
    let caller_pid = crate::process::scheduler::current_pid();
    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {}
        _ => {
            let target_pid = decode_dynamic_cpu_clock_pid(caller_pid, clockid).ok_or(EINVAL)?;
            if !crate::process::table().lock().contains_key(&target_pid) {
                return Err(EINVAL);
            }
        }
    }
    if res_ptr != 0 {
        let tick_res_ns = 1_000_000_000 / crate::cpu::pit::TIMER_HZ as i64;
        let res_ns = if matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC) {
            crate::cpu::hpet::resolution_ns()
                .map(|ns| ns as i64)
                .unwrap_or(tick_res_ns)
        } else {
            tick_res_ns
        };
        copyout_val(&RawTimespec {
                tv_sec: 0,
                tv_nsec: res_ns,
            }, UserPtr::new(res_ptr))?;
    }
    Ok(0)
}

/// `SYS_CLOCK_SETTIME` -- real Linux's own unclaimed `227` (same "already carried unremapped in
/// `bits/syscall.h.in`, only a kernel-side handler was missing" story as `sys_clock_getres` above).
///
/// `CLOCK_REALTIME` recalibrates `cpu::rtc`'s live wall-clock offset (`rtc::set_unix_epoch`) --
/// closes `clock_settime/1-1.c`/`4-1.c`/`5-1.c`/`7-1.c`/`8-1.c` (all previously `UNRESOLVED`
/// purely because this syscall didn't exist, `ENOSYS`ing before ever reaching each test's own
/// pass/fail logic) and the `helpers.h` `getBeforeTime`/`setBackTime` pair every one of them uses
/// to restore the clock afterward. `CLOCK_MONOTONIC` is never settable (`EINVAL`, real POSIX
/// "Monotonic Clock" requirement) -- closes `clock_settime/6-1.c`/`20-1.c`. A dynamic per-process
/// clock (`decode_dynamic_cpu_clock_pid`) overwrites that process's own `Process::cpu_ticks`
/// directly -- what `clock_getcpuclockid/2-1.c` needs: set one dynamic clockid decoding to the
/// caller's own pid, then immediately read it back through a second one (`clock_getcpuclockid(0,
/// ...)`, also decoding to the caller) and see the same value. Any other `clockid` (a
/// positive-but-unrecognized value, or a dynamic one whose decoded pid has no live process) is
/// `EINVAL` -- closes `clock_settime/17-1.c`. An out-of-range `tv_nsec` is `EINVAL` regardless of
/// `clockid` (checked first) -- closes `clock_settime/19-1.c`.
pub(crate) fn sys_clock_settime(clockid: u64, ts_ptr: u64) -> Result<u64, u64> {
    let ts: RawTimespec = copyin_val(UserPtr::new(ts_ptr))?;
    if !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(EINVAL);
    }
    match clockid {
        CLOCK_REALTIME => {
            crate::cpu::rtc::set_unix_epoch(ts.tv_sec, ts.tv_nsec);
            crate::process::timers::wake_realtime_sleepers_after_clock_change();
            Ok(0)
        }
        CLOCK_MONOTONIC => Err(EINVAL),
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => set_cpu_ticks(
            crate::process::scheduler::current_pid(),
            ts.tv_sec,
            ts.tv_nsec,
        ),
        _ => {
            let caller_pid = crate::process::scheduler::current_pid();
            let target_pid = decode_dynamic_cpu_clock_pid(caller_pid, clockid).ok_or(EINVAL)?;
            set_cpu_ticks(target_pid, ts.tv_sec, ts.tv_nsec)
        }
    }
}

fn set_cpu_ticks(pid: crate::process::Pid, sec: i64, nsec: i64) -> Result<u64, u64> {
    if sec < 0 {
        return Err(EINVAL);
    }
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let ticks = sec as u64 * hz + (nsec as u64 * hz) / 1_000_000_000;
    let mut table = crate::process::table().lock();
    let proc = table.get_mut(&pid).ok_or(EINVAL)?;
    proc.cpu_ticks = ticks;
    Ok(0)
}

/// Thin FFI adapters over `sys_read`/`sys_write` for `sys/modules/native_abi/` to call — see `super`'s
/// own module doc comment for why the underlying behavior stays here rather than being duplicated
/// into that module. Converts each function's `Result<u64, u64>` into `SyscallHandler`'s plain
/// `i64` FFI convention.
///
/// `oxidebsd_sys_exit` goes through `process::do_exit` — real, per-process termination that hands
/// control to whatever the scheduler picks next, only falling back to a full `hlt_loop()` when
/// nothing else is runnable.
///
/// **The exit code is shifted into bits 8-15 before reaching `do_exit`, matching real
/// `wait(2)`'s status-word encoding** (`WIFEXITED(status)` is `(status & 0x7f) == 0`;
/// `WEXITSTATUS(status)` is `(status >> 8) & 0xff`) — found live, the hard way: an earlier
/// version stored the caller's raw exit code unshifted, which happened to round-trip fine
/// against this kernel's own test suite (every test that checks `wait4`'s reported status against
/// a raw exit code agreed with itself, since both the write side and the read side used the same
/// wrong convention) but is real POSIX-incompatible ABI breakage for a real caller checking the
/// status the standard way. Confirmed live: BusyBox's `hush`, driving real applets through this
/// exact wait4/status path, uses the real `WIFSIGNALED`/`WTERMSIG` macros
/// (`external/gpl2/busybox/shell/hush.c`'s `checkjobs`) to decide whether to print a
/// `strsignal()`-derived death message -- with the unshifted encoding, *any* applet exiting
/// normally with a nonzero code (extremely common: `touch`/`tee`/`rm`/... all do this on their own
/// ordinary internal errors) had its raw low byte misread as "terminated by signal N", e.g. exit
/// code `1` decoded as `WTERMSIG == 1 == SIGHUP` -- printing a spurious "Hangup" after essentially
/// any failing command and (per `checkjobs`' own default-signal-death handling) corrupting later
/// commands in the same interactive session. Signal-based termination (`process::do_kill`'s
/// `Terminate` branch, and `SignalDelivery::Terminate`'s own self-delivery path in this same file)
/// already passes `terminate_process`/`do_exit` a pre-encoded `128 + sig` value directly -- *not*
/// shifted here, and must stay that way: its low 7 bits already equal the real signal number
/// (`(128 + sig) & 0x7f == sig` for `sig < 128`), which is everything `WIFSIGNALED`/`WTERMSIG`
/// actually look at, so it was already real-wait-status-compatible before this fix and shifting it
/// again here would corrupt it. This function is the *only* place a genuine user-supplied
/// `exit(code)` value becomes a `Zombie` status, which is why the shift belongs here and not
/// inside `do_exit`/`terminate_process` themselves (shared by both conventions).
pub(crate) extern "C" fn oxidebsd_sys_exit(code: u64) -> ! {
    let status = ((code as i32) & 0xff) << 8;
    crate::process::do_exit(crate::process::scheduler::current_pid(), status)
}

/// `oxidebsd_sys_exit_group` goes through `process::do_exit_group` -- real, whole-thread-group
/// termination, distinct from `oxidebsd_sys_exit` above. See `process::do_exit_group`'s own doc
/// comment and `external/mit/musl/arch/x86_64/bits/syscall.h.in`'s `__NR_exit_group` doc comment
/// for why real `exit()`/`_Exit()` need a genuinely separate syscall from a bare per-thread
/// `SYS_exit`. Same real `wait(2)`-status-word encoding as `oxidebsd_sys_exit` above -- this is
/// the *other* place a genuine user-supplied `exit(code)` value becomes a `Zombie` status.
pub(crate) extern "C" fn oxidebsd_sys_exit_group(code: u64) -> ! {
    let status = ((code as i32) & 0xff) << 8;
    crate::process::do_exit_group(crate::process::scheduler::current_pid(), status)
}

// `pub` for the in-kernel `tests/tcp_smoke.rs` (retired 2026-10-06: it called handlers as Rust functions); modules import it through
// `module.rs`'s symbol table.
pub extern "C" fn oxidebsd_sys_read(fd: u64, ptr: u64, len: u64) -> i64 {
    result_to_ffi(sys_read(fd, ptr, len))
}

pub extern "C" fn oxidebsd_sys_write(fd: u64, ptr: u64, len: u64) -> i64 {
    result_to_ffi(sys_write(fd, ptr, len))
}

pub(crate) extern "C" fn oxidebsd_sys_pread(fd: u64, ptr: u64, len: u64, offset: u64) -> i64 {
    result_to_ffi(sys_pread(fd, ptr, len, offset))
}

pub(crate) extern "C" fn oxidebsd_sys_pwrite(fd: u64, ptr: u64, len: u64, offset: u64) -> i64 {
    result_to_ffi(sys_pwrite(fd, ptr, len, offset))
}

pub(crate) extern "C" fn oxidebsd_sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    result_to_ffi(sys_writev(fd, iov_ptr, iovcnt))
}

pub(crate) extern "C" fn oxidebsd_sys_pwritev2(
    fd: u64,
    iov_ptr: u64,
    iovcnt: u64,
    ofs: u64,
) -> i64 {
    result_to_ffi(sys_pwritev2(fd, iov_ptr, iovcnt, ofs))
}

// `pub` for the in-kernel `tests/readv_smoke.rs` (retired 2026-10-06: it called handlers as Rust functions).
pub extern "C" fn oxidebsd_sys_readv(fd: u64, iov_ptr: u64, iovcnt: u64) -> i64 {
    result_to_ffi(sys_readv(fd, iov_ptr, iovcnt))
}

pub(crate) extern "C" fn oxidebsd_sys_pipe(fds_ptr: u64) -> i64 {
    result_to_ffi(sys_pipe(fds_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_pipe2(fds_ptr: u64, flags: u64) -> i64 {
    result_to_ffi(sys_pipe2(fds_ptr, flags))
}

pub(crate) extern "C" fn oxidebsd_sys_dup2(oldfd: u64, newfd: u64) -> i64 {
    result_to_ffi(sys_dup2(oldfd, newfd))
}

// `pub`, not `pub(crate)` -- same "kept public for test use" precedent above.
pub extern "C" fn oxidebsd_sys_set_tid_address(tidptr: u64) -> i64 {
    result_to_ffi(sys_set_tid_address(tidptr))
}

// `pub`, not `pub(crate)` -- same "kept public for test use" precedent above; a future smoke test
// for real O_NONBLOCK behavior would call this directly, the same way tests already do for
// read/write/socketpair.
pub extern "C" fn oxidebsd_sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    result_to_ffi(sys_fcntl(fd, cmd, arg))
}

pub(crate) extern "C" fn oxidebsd_sys_dup(oldfd: u64) -> i64 {
    result_to_ffi(sys_dup(oldfd))
}

pub(crate) extern "C" fn oxidebsd_sys_set_fs_base(base: u64) -> i64 {
    result_to_ffi(sys_set_fs_base(base))
}

pub(crate) extern "C" fn oxidebsd_sys_kill(pid: u64, sig: u64) -> i64 {
    result_to_ffi(sys_kill(pid, sig))
}

pub(crate) extern "C" fn oxidebsd_sys_sigaction(
    sig: u64,
    act_ptr: u64,
    oldact_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    result_to_ffi(sys_sigaction(sig, act_ptr, oldact_ptr, sigsetsize))
}

pub(crate) extern "C" fn oxidebsd_sys_sigprocmask(
    how: u64,
    set_ptr: u64,
    oldset_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    result_to_ffi(sys_sigprocmask(how, set_ptr, oldset_ptr, sigsetsize))
}

pub(crate) extern "C" fn oxidebsd_sys_sigpending(set_ptr: u64, sigsetsize: u64) -> i64 {
    result_to_ffi(sys_sigpending(set_ptr, sigsetsize))
}

pub(crate) extern "C" fn oxidebsd_sys_sigaltstack(ss_ptr: u64, old_ptr: u64) -> i64 {
    result_to_ffi(sys_sigaltstack(ss_ptr, old_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_pause() -> i64 {
    result_to_ffi(sys_pause())
}

pub(crate) extern "C" fn oxidebsd_sys_sigsuspend(mask_ptr: u64, sigsetsize: u64) -> i64 {
    result_to_ffi(sys_sigsuspend(mask_ptr, sigsetsize))
}

pub(crate) extern "C" fn oxidebsd_sys_sigtimedwait(
    mask_ptr: u64,
    info_ptr: u64,
    ts_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    result_to_ffi(sys_sigtimedwait(mask_ptr, info_ptr, ts_ptr, sigsetsize))
}

pub(crate) extern "C" fn oxidebsd_sys_sigqueue(
    pid: u64,
    sig: u64,
    siginfo_ptr: u64,
    _a3: u64,
) -> i64 {
    result_to_ffi(sys_sigqueue(pid, sig, siginfo_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_tkill(tid: u64, sig: u64) -> i64 {
    result_to_ffi(sys_tkill(tid, sig))
}

pub(crate) extern "C" fn oxidebsd_sys_setpgid(pid: u64, pgid: u64) -> i64 {
    result_to_ffi(sys_setpgid(pid, pgid))
}

pub(crate) extern "C" fn oxidebsd_sys_getpgid(pid: u64) -> i64 {
    result_to_ffi(sys_getpgid(pid))
}

pub(crate) extern "C" fn oxidebsd_sys_setsid() -> i64 {
    result_to_ffi(sys_setsid())
}

pub(crate) extern "C" fn oxidebsd_sys_getsid(pid: u64) -> i64 {
    result_to_ffi(sys_getsid(pid))
}

pub(crate) extern "C" fn oxidebsd_sys_getuid() -> i64 {
    sys_getuid() as i64
}

pub(crate) extern "C" fn oxidebsd_sys_geteuid() -> i64 {
    sys_geteuid() as i64
}

pub(crate) extern "C" fn oxidebsd_sys_getgid() -> i64 {
    sys_getgid() as i64
}

pub(crate) extern "C" fn oxidebsd_sys_getegid() -> i64 {
    sys_getegid() as i64
}

pub(crate) extern "C" fn oxidebsd_sys_setuid(uid: u64) -> i64 {
    result_to_ffi(sys_setuid(uid))
}

pub(crate) extern "C" fn oxidebsd_sys_setgid(gid: u64) -> i64 {
    result_to_ffi(sys_setgid(gid))
}

pub(crate) extern "C" fn oxidebsd_sys_setresuid(ruid: u64, euid: u64, suid: u64) -> i64 {
    result_to_ffi(sys_setresuid(ruid, euid, suid))
}

pub(crate) extern "C" fn oxidebsd_sys_close_range(first: u64, last: u64, flags: u64) -> i64 {
    result_to_ffi(crate::fs::fd::close_range(first, last, flags))
}

pub(crate) extern "C" fn oxidebsd_sys_setresgid(rgid: u64, egid: u64, sgid: u64) -> i64 {
    result_to_ffi(sys_setresgid(rgid, egid, sgid))
}

pub(crate) extern "C" fn oxidebsd_sys_setreuid(ruid: u64, euid: u64) -> i64 {
    result_to_ffi(sys_setreuid(ruid, euid))
}

pub(crate) extern "C" fn oxidebsd_sys_setregid(rgid: u64, egid: u64) -> i64 {
    result_to_ffi(sys_setregid(rgid, egid))
}

pub(crate) extern "C" fn oxidebsd_sys_getresuid(r: u64, e: u64, s: u64) -> i64 {
    result_to_ffi(sys_getresuid(r, e, s))
}

pub(crate) extern "C" fn oxidebsd_sys_getresgid(r: u64, e: u64, s: u64) -> i64 {
    result_to_ffi(sys_getresgid(r, e, s))
}

pub(crate) extern "C" fn oxidebsd_sys_getgroups(size: u64, list_ptr: u64) -> i64 {
    result_to_ffi(sys_getgroups(size, list_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_setgroups(count: u64, list_ptr: u64) -> i64 {
    result_to_ffi(sys_setgroups(count, list_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_prlimit64(
    pid: u64,
    resource: u64,
    new_ptr: u64,
    old_ptr: u64,
) -> i64 {
    result_to_ffi(sys_prlimit64(pid, resource, new_ptr, old_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_setpriority(which: u64, who: u64, prio: u64) -> i64 {
    result_to_ffi(sys_setpriority(which, who, prio))
}

pub(crate) extern "C" fn oxidebsd_sys_getpriority(which: u64, who: u64) -> i64 {
    result_to_ffi(sys_getpriority(which, who))
}

pub(crate) extern "C" fn oxidebsd_sys_umask(new_mask: u64) -> i64 {
    result_to_ffi(sys_umask(new_mask))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_setscheduler(
    pid: u64,
    policy: u64,
    param_ptr: u64,
) -> i64 {
    result_to_ffi(sys_sched_setscheduler(pid, policy, param_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_setparam(pid: u64, param_ptr: u64) -> i64 {
    result_to_ffi(sys_sched_setparam(pid, param_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_getscheduler(pid: u64) -> i64 {
    result_to_ffi(sys_sched_getscheduler(pid))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_getparam(pid: u64, param_ptr: u64) -> i64 {
    result_to_ffi(sys_sched_getparam(pid, param_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_getaffinity(
    pid: u64,
    cpusetsize: u64,
    mask_ptr: u64,
) -> i64 {
    result_to_ffi(sys_sched_getaffinity(pid, cpusetsize, mask_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_get_priority_max(policy: u64) -> i64 {
    result_to_ffi(sys_sched_get_priority_max(policy))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_get_priority_min(policy: u64) -> i64 {
    result_to_ffi(sys_sched_get_priority_min(policy))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_rr_get_interval(pid: u64, ts_ptr: u64) -> i64 {
    result_to_ffi(sys_sched_rr_get_interval(pid, ts_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_sched_yield() -> i64 {
    result_to_ffi(sys_sched_yield())
}

pub(crate) extern "C" fn oxidebsd_sys_reboot(cmd: u64) -> i64 {
    result_to_ffi(sys_reboot(cmd))
}

pub(crate) extern "C" fn oxidebsd_sys_futex(addr: u64, op: u64, val: u64, to: u64) -> i64 {
    result_to_ffi(sys_futex(addr, op, val, to))
}

pub(crate) extern "C" fn oxidebsd_sys_futex_requeue(
    addr: u64,
    addr2: u64,
    nr_wake: u64,
    nr_requeue: u64,
) -> i64 {
    result_to_ffi(sys_futex_requeue(addr, addr2, nr_wake, nr_requeue))
}

pub(crate) extern "C" fn oxidebsd_sys_ioctl(fd: u64, request: u64, argp: u64) -> i64 {
    result_to_ffi(sys_ioctl(fd, request, argp))
}

pub(crate) extern "C" fn oxidebsd_sys_get_keyevent(out_ptr: u64) -> i64 {
    result_to_ffi(sys_get_keyevent(out_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_uname(uts_ptr: u64) -> i64 {
    result_to_ffi(sys_uname(uts_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_sethostname(name_ptr: u64, len: u64) -> i64 {
    result_to_ffi(sys_sethostname(name_ptr, len))
}

pub(crate) extern "C" fn oxidebsd_sys_clock_gettime(clockid: u64, ts_ptr: u64) -> i64 {
    result_to_ffi(sys_clock_gettime(clockid, ts_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_clock_getres(clockid: u64, res_ptr: u64) -> i64 {
    result_to_ffi(sys_clock_getres(clockid, res_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_clock_settime(clockid: u64, ts_ptr: u64) -> i64 {
    result_to_ffi(sys_clock_settime(clockid, ts_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_clock_nanosleep(
    clockid: u64,
    flags: u64,
    req_ptr: u64,
    rem_ptr: u64,
) -> i64 {
    result_to_ffi(crate::process::do_clock_nanosleep(
        crate::process::scheduler::current_pid(),
        clockid,
        flags,
        req_ptr,
        rem_ptr,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_nanosleep(req_ptr: u64, rem_ptr: u64) -> i64 {
    result_to_ffi(crate::process::do_nanosleep(
        crate::process::scheduler::current_pid(),
        req_ptr,
        rem_ptr,
    ))
}

/// `SYS_SETITIMER = 156`/`SYS_GETITIMER = 157` (registered by `sys/modules/clock`, continuing on from
/// `SYS_SYMLINK = 155`) — see `process::do_setitimer`'s own doc comment for the real logic and why
/// this one syscall is enough to back both `setitimer(2)` and real `alarm(2)` (a thin musl-side
/// wrapper around it).
pub(crate) extern "C" fn oxidebsd_sys_setitimer(which: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    result_to_ffi(crate::process::do_setitimer(
        crate::process::scheduler::current_pid(),
        which,
        new_ptr,
        old_ptr,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_getitimer(which: u64, old_ptr: u64) -> i64 {
    result_to_ffi(crate::process::do_getitimer(
        crate::process::scheduler::current_pid(),
        which,
        old_ptr,
    ))
}

/// `SYS_TIMER_CREATE = 531`/`SYS_TIMER_SETTIME = 532`/`SYS_TIMER_GETTIME = 533`/
/// `SYS_TIMER_GETOVERRUN = 534`/`SYS_TIMER_DELETE = 535` (registered by `sys/modules/clock`, items
/// 6-10 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch) -- real POSIX
/// per-process timers, a natural extension of the already-implemented `setitimer`/`getitimer`
/// (`ITIMER_REAL`-only) infrastructure just above, now that per-timer-id tracking exists
/// (`process::PosixTimer`/`Process::posix_timers`). See `process::do_timer_create`'s own doc
/// comment for the real wire format/semantics of the whole sub-batch.
pub(crate) extern "C" fn oxidebsd_sys_timer_create(
    clockid: u64,
    evp_ptr: u64,
    timerid_ptr: u64,
) -> i64 {
    result_to_ffi(crate::process::do_timer_create(
        crate::process::scheduler::current_pid(),
        clockid,
        evp_ptr,
        timerid_ptr,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_timer_settime(
    timerid: u64,
    flags: u64,
    new_ptr: u64,
    old_ptr: u64,
) -> i64 {
    result_to_ffi(crate::process::do_timer_settime(
        crate::process::scheduler::current_pid(),
        timerid,
        flags,
        new_ptr,
        old_ptr,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_timer_gettime(timerid: u64, val_ptr: u64) -> i64 {
    result_to_ffi(crate::process::do_timer_gettime(
        crate::process::scheduler::current_pid(),
        timerid,
        val_ptr,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_timer_getoverrun(timerid: u64) -> i64 {
    result_to_ffi(crate::process::do_timer_getoverrun(
        crate::process::scheduler::current_pid(),
        timerid,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_timer_delete(timerid: u64) -> i64 {
    result_to_ffi(crate::process::do_timer_delete(
        crate::process::scheduler::current_pid(),
        timerid,
    ))
}

/// `SYS_MQ_OPEN = 536` through `SYS_MQ_GETSETATTR = 541` (registered by `sys/modules/posix_compat`,
/// items 11-16 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch) -- real
/// POSIX message queues, built on `crate::fs::mqueue`. See that module's own doc comment for the
/// full wire-format/blocking/notify design.
pub(crate) fn sys_mq_open(name_ptr: u64, flags: u64, mode: u64, attr_ptr: u64) -> Result<u64, u64> {
    crate::fs::mqueue::do_mq_open(name_ptr, flags, mode, attr_ptr)
}

pub(crate) fn sys_mq_unlink(name_ptr: u64) -> Result<u64, u64> {
    crate::fs::mqueue::do_mq_unlink(name_ptr)
}

pub(crate) fn sys_mq_timedsend(
    mqd_and_len: u64,
    msg_ptr: u64,
    prio: u64,
    at_ptr: u64,
) -> Result<u64, u64> {
    crate::fs::mqueue::do_mq_timedsend(mqd_and_len, msg_ptr, prio, at_ptr)
}

pub(crate) fn sys_mq_timedreceive(
    mqd_and_len: u64,
    msg_ptr: u64,
    prio_ptr: u64,
    at_ptr: u64,
) -> Result<u64, u64> {
    crate::fs::mqueue::do_mq_timedreceive(mqd_and_len, msg_ptr, prio_ptr, at_ptr)
}

pub(crate) fn sys_mq_notify(mqd: u64, sev_ptr: u64) -> Result<u64, u64> {
    crate::fs::mqueue::do_mq_notify(mqd, sev_ptr)
}

pub(crate) fn sys_mq_getsetattr(mqd: u64, new_ptr: u64, old_ptr: u64) -> Result<u64, u64> {
    crate::fs::mqueue::do_mq_getsetattr(mqd, new_ptr, old_ptr)
}

pub(crate) extern "C" fn oxidebsd_sys_mq_open(
    name_ptr: u64,
    flags: u64,
    mode: u64,
    attr_ptr: u64,
) -> i64 {
    result_to_ffi(sys_mq_open(name_ptr, flags, mode, attr_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_mq_unlink(name_ptr: u64) -> i64 {
    result_to_ffi(sys_mq_unlink(name_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_mq_timedsend(
    mqd_and_len: u64,
    msg_ptr: u64,
    prio: u64,
    at_ptr: u64,
) -> i64 {
    result_to_ffi(sys_mq_timedsend(mqd_and_len, msg_ptr, prio, at_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_mq_timedreceive(
    mqd_and_len: u64,
    msg_ptr: u64,
    prio_ptr: u64,
    at_ptr: u64,
) -> i64 {
    result_to_ffi(sys_mq_timedreceive(mqd_and_len, msg_ptr, prio_ptr, at_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_mq_notify(mqd: u64, sev_ptr: u64) -> i64 {
    result_to_ffi(sys_mq_notify(mqd, sev_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_mq_getsetattr(mqd: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    result_to_ffi(sys_mq_getsetattr(mqd, new_ptr, old_ptr))
}

/// `SYS_MSGGET = 550` through `SYS_MSGCTL = 553` (registered by `sys/modules/posix_compat`, items
/// 25-28 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch -- the last
/// sub-batch) -- real SysV message queues, built on `crate::fs::sysv_msg`. See that module's own
/// doc comment for the full wire-format/permission/blocking design, and how it differs from
/// `crate::fs::mqueue`'s POSIX message queues.
pub(crate) fn sys_msgget(key: u64, flag: u64) -> Result<u64, u64> {
    crate::fs::sysv_msg::do_msgget(key, flag)
}

pub(crate) fn sys_msgsnd(q: u64, m: u64, len: u64, flag: u64) -> Result<u64, u64> {
    crate::fs::sysv_msg::do_msgsnd(q, m, len, flag)
}

pub(crate) fn sys_msgrcv(q_and_flag: u64, m: u64, len: u64, msgtyp: u64) -> Result<u64, u64> {
    crate::fs::sysv_msg::do_msgrcv(q_and_flag, m, len, msgtyp)
}

pub(crate) fn sys_msgctl(q: u64, cmd: u64, buf_ptr: u64) -> Result<u64, u64> {
    crate::fs::sysv_msg::do_msgctl(q, cmd, buf_ptr)
}

pub(crate) extern "C" fn oxidebsd_sys_msgget(key: u64, flag: u64, _a2: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_msgget(key, flag))
}

pub(crate) extern "C" fn oxidebsd_sys_msgsnd(q: u64, m: u64, len: u64, flag: u64) -> i64 {
    result_to_ffi(sys_msgsnd(q, m, len, flag))
}

pub(crate) extern "C" fn oxidebsd_sys_msgrcv(
    q_and_flag: u64,
    m: u64,
    len: u64,
    msgtyp: u64,
) -> i64 {
    result_to_ffi(sys_msgrcv(q_and_flag, m, len, msgtyp))
}

pub(crate) extern "C" fn oxidebsd_sys_msgctl(q: u64, cmd: u64, buf_ptr: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_msgctl(q, cmd, buf_ptr))
}

/// `SYS_SEMGET = 546` through `SYS_SEMTIMEDOP = 549` (registered by `sys/modules/posix_compat`, items
/// 21-24 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch) -- real SysV
/// semaphores, built on `crate::fs::sysv_sem`. See that module's own doc comment for the full
/// wire-format/permission/blocking/`SEM_UNDO` design.
pub(crate) fn sys_semget(key: u64, nsems: u64, flag: u64) -> Result<u64, u64> {
    crate::fs::sysv_sem::do_semget(key, nsems, flag)
}

pub(crate) fn sys_semop(id: u64, sops_ptr: u64, nsops: u64) -> Result<u64, u64> {
    crate::fs::sysv_sem::do_semop(id, sops_ptr, nsops)
}

pub(crate) fn sys_semctl(id: u64, semnum: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    crate::fs::sysv_sem::do_semctl(id, semnum, cmd, arg)
}

pub(crate) fn sys_semtimedop(id: u64, sops_ptr: u64, nsops: u64, ts_ptr: u64) -> Result<u64, u64> {
    crate::fs::sysv_sem::do_semtimedop(id, sops_ptr, nsops, ts_ptr)
}

pub(crate) extern "C" fn oxidebsd_sys_semget(key: u64, nsems: u64, flag: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_semget(key, nsems, flag))
}

pub(crate) extern "C" fn oxidebsd_sys_semop(id: u64, sops_ptr: u64, nsops: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_semop(id, sops_ptr, nsops))
}

pub(crate) extern "C" fn oxidebsd_sys_semctl(id: u64, semnum: u64, cmd: u64, arg: u64) -> i64 {
    result_to_ffi(sys_semctl(id, semnum, cmd, arg))
}

pub(crate) extern "C" fn oxidebsd_sys_semtimedop(
    id: u64,
    sops_ptr: u64,
    nsops: u64,
    ts_ptr: u64,
) -> i64 {
    result_to_ffi(sys_semtimedop(id, sops_ptr, nsops, ts_ptr))
}

/// `SYS_SHMGET = 542` through `SYS_SHMDT = 545` (registered by `sys/modules/posix_compat`, items
/// 17-20 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch, the last
/// sub-batch, closing the whole thing out) -- real SysV shared memory, built on `crate::fs::
/// sysv_shm`. See that module's own doc comment for the full wire-format/permission/real-mapping
/// design.
pub(crate) fn sys_shmget(key: u64, size: u64, shmflg: u64) -> Result<u64, u64> {
    crate::fs::sysv_shm::do_shmget(key, size, shmflg)
}

pub(crate) fn sys_shmat(id: u64, shmaddr: u64, shmflg: u64) -> Result<u64, u64> {
    crate::fs::sysv_shm::do_shmat(id, shmaddr, shmflg)
}

pub(crate) fn sys_shmctl(id: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    crate::fs::sysv_shm::do_shmctl(id, cmd, arg)
}

pub(crate) fn sys_shmdt(shmaddr: u64) -> Result<u64, u64> {
    crate::fs::sysv_shm::do_shmdt(shmaddr)
}

pub(crate) extern "C" fn oxidebsd_sys_shmget(key: u64, size: u64, shmflg: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_shmget(key, size, shmflg))
}

pub(crate) extern "C" fn oxidebsd_sys_shmat(id: u64, shmaddr: u64, shmflg: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_shmat(id, shmaddr, shmflg))
}

pub(crate) extern "C" fn oxidebsd_sys_shmctl(id: u64, cmd: u64, arg: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_shmctl(id, cmd, arg))
}

pub(crate) extern "C" fn oxidebsd_sys_shmdt(shmaddr: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    result_to_ffi(sys_shmdt(shmaddr))
}

/// Thin FFI adapters over `sys/process.rs`'s `do_fork_from_current`/`do_wait4`/`do_execve`/
/// `do_getpid`/`do_mmap`/`do_munmap`/`do_brk` for `sys/modules/native_abi/` to call — same pattern as
/// the exit/read/write adapters above, real logic kept kernel-side since module code can't use
/// `alloc`.
pub(crate) extern "C" fn oxidebsd_sys_fork() -> i64 {
    result_to_ffi(crate::process::do_fork_from_current())
}

/// `SYS_CLONE = 555`'s FFI adapter over `do_clone` -- `ctid` (the real `clone(2)` 4th argument,
/// carried in `r10`) really is used: real `CLONE_CHILD_CLEARTID` support, see `Process::
/// clear_child_tid`'s own doc comment for what it's actually for (not `pthread_join`, which needs
/// no kernel help at all).
pub(crate) extern "C" fn oxidebsd_sys_clone(flags: u64, newsp: u64, ptid: u64, ctid: u64) -> i64 {
    result_to_ffi(crate::process::do_clone(flags, newsp, ptid, ctid))
}

pub(crate) extern "C" fn oxidebsd_sys_wait4(
    pid: u64,
    status_ptr: u64,
    options: u64,
    rusage_ptr: u64,
) -> i64 {
    result_to_ffi(crate::process::do_wait4(
        crate::process::scheduler::current_pid(),
        pid as i64,
        options,
        status_ptr,
        rusage_ptr,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_getrusage(who: u64, rusage_ptr: u64) -> i64 {
    result_to_ffi(sys_getrusage(who, rusage_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_times(tms_ptr: u64) -> i64 {
    result_to_ffi(sys_times(tms_ptr))
}

pub(crate) extern "C" fn oxidebsd_sys_getrandom(buf_ptr: u64, buflen: u64, flags: u64) -> i64 {
    result_to_ffi(sys_getrandom(buf_ptr, buflen, flags))
}

pub(crate) extern "C" fn oxidebsd_sys_sysinfo(info_ptr: u64) -> i64 {
    result_to_ffi(sys_sysinfo(info_ptr))
}

/// `execveat(2)` -- `at_ptr` is a `RawAtPath`, see `process::do_execveat`.
pub(crate) extern "C" fn oxidebsd_sys_execveat(
    at_ptr: u64,
    argv_ptr: u64,
    envp_ptr: u64,
    flags: u64,
) -> i64 {
    result_to_ffi(crate::process::do_execveat(
        crate::process::scheduler::current_pid(),
        at_ptr,
        argv_ptr,
        envp_ptr,
        flags,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_execve(
    path_ptr: u64,
    path_len: u64,
    argv_ptr: u64,
    envp_ptr: u64,
) -> i64 {
    result_to_ffi(crate::process::do_execve(
        crate::process::scheduler::current_pid(),
        path_ptr,
        path_len,
        argv_ptr,
        envp_ptr,
    ))
}

/// `packed` carries real `fd`/`off` — the one spare ABI register `SYS_MMAP` has room for (this
/// call already spends `addr_hint`/`len`/a packed `prot` on its first three registers), packed by
/// `external/mit/musl/src/mman/mmap.c`'s own patched `__mmap()` since real `mmap(2)`'s 6-arg shape
/// can't fit this ABI's 4-register width otherwise. Low 32 bits: real `fd` (`-1`, i.e.
/// `0xffff_ffff`, for an anonymous mapping — musl's own convention, not invented here). High 32
/// bits: real `off` (always `0` for every real caller in this kernel's own call graph — see
/// `process::mm::do_mmap_file_backed`'s own doc comment for why a nonzero value is an honest
/// `EINVAL` rather than silently supported). The third register (`packed_prot`) additionally
/// carries real `flags` in its own unused high bits — see `process::mm::do_mmap`'s own doc comment
/// for why `flags` needed a real wire path (`MAP_FIXED`/`MAP_SHARED`/`MAP_PRIVATE`/`MAP_ANON`
/// validation, not just the old `fd == -1` guess) and `mmap.c`'s own patch comment for how it's
/// packed: low 8 bits real `prot` (only ever 3 meaningful bits — `PROT_READ`/`WRITE`/`EXEC`), the
/// rest real `flags` shifted left by 8.
pub(crate) extern "C" fn oxidebsd_sys_mmap(
    addr_hint: u64,
    len: u64,
    packed_prot: u64,
    packed: u64,
) -> i64 {
    let fd = (packed as u32) as i32;
    let off = (packed >> 32) as u32;
    let prot = packed_prot & 0xff;
    let flags = packed_prot >> 8;
    result_to_ffi(crate::process::do_mmap(
        crate::process::scheduler::current_pid(),
        addr_hint,
        len,
        prot,
        flags,
        fd,
        off,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_munmap(addr: u64, len: u64) -> i64 {
    result_to_ffi(crate::process::do_munmap(
        crate::process::scheduler::current_pid(),
        addr,
        len,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_brk(addr: u64) -> i64 {
    result_to_ffi(crate::process::do_brk(
        crate::process::scheduler::current_pid(),
        addr,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    result_to_ffi(crate::process::do_mprotect(
        crate::process::scheduler::current_pid(),
        addr,
        len,
        prot,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_msync(addr: u64, len: u64, flags: u64) -> i64 {
    result_to_ffi(crate::process::do_msync(
        crate::process::scheduler::current_pid(),
        addr,
        len,
        flags,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_mlock(addr: u64, len: u64) -> i64 {
    result_to_ffi(crate::process::do_mlock(
        crate::process::scheduler::current_pid(),
        addr,
        len,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_munlock(addr: u64, len: u64) -> i64 {
    result_to_ffi(crate::process::do_munlock(
        crate::process::scheduler::current_pid(),
        addr,
        len,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_mlockall(flags: u64) -> i64 {
    result_to_ffi(crate::process::do_mlockall(
        crate::process::scheduler::current_pid(),
        flags,
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_munlockall() -> i64 {
    result_to_ffi(crate::process::do_munlockall(
        crate::process::scheduler::current_pid(),
    ))
}

pub(crate) extern "C" fn oxidebsd_sys_getpid() -> i64 {
    crate::process::do_getpid() as i64
}

pub(crate) extern "C" fn oxidebsd_sys_getppid() -> i64 {
    crate::process::do_getppid() as i64
}

fn result_to_ffi(result: Result<u64, u64>) -> i64 {
    match result {
        Ok(value) => value as i64,
        Err(errno) => -(errno as i64),
    }
}
