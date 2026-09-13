//! Every syscall handler this kernel implements directly in the `syscall` module (rather than
//! delegating straight to a `process::do_*` function) — real `sys_*` logic, plus the thin
//! `oxidebsd_sys_*` `extern "C"` FFI adapters `modules/native_abi`/`modules/posix_compat`/etc.
//! actually call through (see `super`'s own module doc comment for why the real behavior stays
//! kernel-resident rather than moving into those modules). Split out from `syscall.rs`'s original
//! single file purely for size — this is still conceptually the same "syscall ABI" module, just
//! its handler-implementation half rather than its dispatch-mechanism half (`super`/`mod.rs`).

use x86_64::VirtAddr;

use crate::serial_println;

use super::{EBADF, EINVAL, ENOTTY, EPERM, EPROTONOSUPPORT, ffi_result_to_result};

/// Reads up to `len` bytes into `ptr` from `fd` — a pure lookup into `crate::fs::fd`'s registry now,
/// for *every* fd including 0/1/2 (see `src/fs/fd.rs`'s module doc comment for why stdin/stdout/
/// stderr moved from being special-cased here into being ordinary, `dup2`-able registry entries:
/// stdin's own non-blocking-ring-buffer behavior lives in that file's `stdin_read` now, not here).
/// `EBADF` if `fd` isn't registered at all.
pub(crate) fn sys_read(fd: u64, ptr: u64, len: u64) -> Result<u64, u64> {
    match crate::fs::fd::read(fd, ptr, len) {
        Some(raw) => ffi_result_to_result(raw),
        None => Err(EBADF),
    }
}

/// Writes `len` bytes at `ptr` to `fd` — a pure lookup into `crate::fs::fd`'s registry now, for
/// *every* fd including 0/1/2 (see `src/fs/fd.rs`'s module doc comment; stdout/stderr's own
/// UTF-8-checked `serial_print!` path lives in that file's `stdout_write` now, not here). `EBADF`
/// if `fd` isn't registered at all.
pub(crate) fn sys_write(fd: u64, ptr: u64, len: u64) -> Result<u64, u64> {
    match crate::fs::fd::write(fd, ptr, len) {
        Some(raw) => ffi_result_to_result(raw),
        None => Err(EBADF),
    }
}

/// Real `SYS_PREAD=17`/`SYS_PWRITE=18` -- real, unremapped x86_64 Linux `__NR_pread64`/
/// `__NR_pwrite64` values (confirmed unclaimed: no prior pass in this ABI ever registered them, and
/// musl's own `pread()`/`pwrite()` -- `third_party/musl/src/unistd/{pread,pwrite}.c` -- already
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
    match crate::fs::fd::pread(fd, ptr, len, offset) {
        Some(raw) => ffi_result_to_result(raw),
        None => Err(EBADF),
    }
}

pub(crate) fn sys_pwrite(fd: u64, ptr: u64, len: u64, offset: u64) -> Result<u64, u64> {
    if (offset as i64) < 0 {
        return Err(EINVAL);
    }
    match crate::fs::fd::pwrite(fd, ptr, len, offset) {
        Some(raw) => ffi_result_to_result(raw),
        None => Err(EBADF),
    }
}

/// `SYS_WRITEV = 104` — OxideBSD's own invention, added specifically because musl's *entire*
/// stdio write path goes through `writev`, never plain `write` (see `third_party/musl`'s
/// `src/stdio/__stdio_write.c`) — without this, `printf` et al. silently produce no output at all.
/// `(fd, iov_ptr, iovcnt)` matches real `writev`'s own argument positions exactly (unlike
/// `SYS_MMAP`, nothing here needs to be dropped to fit into this ABI's argument registers). Reads
/// `iovcnt` real C `struct iovec { void *iov_base; size_t iov_len; }` entries (16 bytes each,
/// standard layout) from `iov_ptr`, and calls `sys_write` once per entry, accumulating the total.
/// Matches real `writev`'s partial-write semantics: if an entry fails after at least one earlier
/// entry already succeeded, returns `Ok(total so far)` rather than propagating the failure (a
/// later `write` call surfaces it instead); only propagates `Err` if the very first entry fails.
pub(crate) fn sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> Result<u64, u64> {
    #[repr(C)]
    struct IoVec {
        base: u64,
        len: u64,
    }

    let mut total: u64 = 0;
    for i in 0..iovcnt {
        // SAFETY: same known pointer-validation gap sys_read/sys_write already document -- iov_ptr
        // isn't checked against the caller's actual mappings before it's dereferenced.
        let iov = unsafe { &*(iov_ptr as *const IoVec).add(i as usize) };
        match sys_write(fd, iov.base, iov.len) {
            Ok(n) => total += n,
            Err(errno) => return if total > 0 { Ok(total) } else { Err(errno) },
        }
    }
    Ok(total)
}

/// Real, unremapped Linux `__NR_pwritev2=328`. Real `pwritev2(2)`'s wire format is 6 real
/// arguments (`fd, iov, count, ofs_lo, ofs_hi, flags`) -- doesn't fit this ABI's 4-register
/// convention, so `third_party/musl/src/linux/pwritev2.c`'s own call site is patched (`oxidebsd`
/// branch) to pass just `(fd, iov, count, ofs)`: `ofs_lo`/`ofs_hi` collapse into one real 64-bit
/// value (the split only ever existed for 32-bit-ABI portability shared across archs; real `off_t`
/// is already 64-bit natively here), and `flags` (`RWF_DSYNC`/`RWF_HIPRI`/etc.) is dropped
/// entirely -- none of those hints have any real effect on this filesystem's own always-durable-
/// at-commit write model, so silently ignoring them (rather than plumbing a value nothing would
/// ever consult) is honest, not a shortcut. `ofs == u64::MAX` (real `-1`) means "at the current
/// file position" per real `pwritev2(2)` semantics -- exactly what musl's own wrapper already
/// special-cased for the *non*-vectored, no-flags case (`writev`) before ever reaching this
/// syscall at all; this handler covers every other case (a genuine offset, or any nonzero `flags`)
/// uniformly through the one real code path. Same partial-write semantics as `sys_writev` above.
///
/// **Any other negative `ofs` is a real `EINVAL`, matching real Linux** -- only the exact `-1`
/// sentinel means "current position"; every other negative value is a genuinely invalid offset,
/// same as plain `pwrite`'s own check in `sys_pwrite` above. This handler used to skip that check
/// entirely and call `crate::fs::fd::pwrite` directly, which mattered because real, unmodified
/// musl's own `pwrite()` (`third_party/musl/src/unistd/pwrite.c`) issues `SYS_pwritev2` first, not
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
    #[repr(C)]
    struct IoVec {
        base: u64,
        len: u64,
    }

    if ofs != u64::MAX && (ofs as i64) < 0 {
        return Err(EINVAL);
    }

    let mut total: u64 = 0;
    let mut cur_ofs = ofs;
    for i in 0..iovcnt {
        // SAFETY: same known pointer-validation gap sys_read/sys_write already document.
        let iov = unsafe { &*(iov_ptr as *const IoVec).add(i as usize) };
        let result = if ofs == u64::MAX {
            sys_write(fd, iov.base, iov.len)
        } else {
            match crate::fs::fd::pwrite(fd, iov.base, iov.len, cur_ofs) {
                Some(raw) => ffi_result_to_result(raw),
                None => Err(EBADF),
            }
        };
        match result {
            Ok(n) => {
                total += n;
                cur_ofs = cur_ofs.wrapping_add(n);
            }
            Err(errno) => return if total > 0 { Ok(total) } else { Err(errno) },
        }
    }
    Ok(total)
}

/// `SYS_READV = 153` — OxideBSD's own invention, continuing the sequence past `SYS_SHUTDOWN =
/// 152`. Added specifically because musl's stdio read path goes through `readv`, not plain
/// `read`, whenever a `FILE*` has real internal buffering enabled (`third_party/musl`'s
/// `src/stdio/__stdio_read.c`: a 2-iovec scatter-read, the caller's own buffer plus musl's own
/// internal `FILE` buffer) — the exact same "musl doesn't call the simpler syscall you'd expect"
/// story `SYS_WRITEV` already told for the write side, just found much later because nothing had
/// exercised a *buffered* `fread()`/`fgets()` call against a real, slow-arriving data source until
/// BusyBox's `wget` actually downloaded a real file over HTTPS (confirmed live: the TLS/TCP fix
/// chain in this file's own known-gaps entry all worked — real response bytes came through —
/// then this surfaced on the very next buffered read). `(fd, iov_ptr, iovcnt)` matches real
/// `readv`'s own argument positions exactly. Calls `sys_read` once per `iovec` entry, stopping at
/// the first short read (an entry only partially filled) — matches real `readv`'s own contract: a
/// read returning less than requested ends the whole call there, it doesn't move on to the next
/// iovec expecting more to somehow still be available. Same partial-success semantics as
/// `sys_writev`: only propagates `Err` if the very first entry fails with nothing read yet.
pub(crate) fn sys_readv(fd: u64, iov_ptr: u64, iovcnt: u64) -> Result<u64, u64> {
    #[repr(C)]
    struct IoVec {
        base: u64,
        len: u64,
    }

    let mut total: u64 = 0;
    for i in 0..iovcnt {
        // SAFETY: same known pointer-validation gap sys_read/sys_write already document -- iov_ptr
        // isn't checked against the caller's actual mappings before it's dereferenced.
        let iov = unsafe { &*(iov_ptr as *const IoVec).add(i as usize) };
        match sys_read(fd, iov.base, iov.len) {
            Ok(n) => {
                total += n;
                if n < iov.len {
                    break; // short read -- real readv stops here, not the next iovec
                }
            }
            Err(errno) => return if total > 0 { Ok(total) } else { Err(errno) },
        }
    }
    Ok(total)
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
    crate::fs::pipe::do_pipe(fds_ptr)?;
    // SAFETY: do_pipe just wrote two real, freshly allocated fd numbers here (same known
    // pointer-validation gap every other user-memory read in this file already has).
    let (read_fd, write_fd) = unsafe {
        (
            (fds_ptr as *const i32).read() as u64,
            (fds_ptr as *const i32).add(1).read() as u64,
        )
    };
    if flags & O_CLOEXEC != 0 {
        let pid = crate::process::scheduler::current_tgid();
        crate::fs::fd::set_cloexec(pid, read_fd, true);
        crate::fs::fd::set_cloexec(pid, write_fd, true);
    }
    if flags & O_NONBLOCK != 0 {
        crate::fs::fd::set_nonblocking(read_fd, true);
        crate::fs::fd::set_nonblocking(write_fd, true);
    }
    Ok(0)
}

/// `SYS_DUP2` (`106`) — matches real `dup2(2)`'s exact `(oldfd, newfd)` signature (no
/// argument-convention mismatch here either). Delegates to `crate::fs::fd::dup2` — see that
/// function's own doc comment, and `src/fs/fd.rs`'s module doc comment, for the refcount-aware
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

/// `SYS_SOCKETPAIR` (`149`) — real `socketpair(2)`'s exact `(domain, type, protocol, sv_ptr)`
/// wire format, already only 4 arguments so (unlike `open`/`execve`) nothing needed inventing
/// (see `third_party/musl`'s own `arch/x86_64/bits/syscall.h.in` comment on `__NR_socketpair`).
/// `AF_UNIX`/`SOCK_STREAM` only — the one shape BusyBox's `wget` needs (see CLAUDE.md's "Real
/// networking" known-gaps entry on `spawn_ssl_client`); anything else is `EPROTONOSUPPORT`, same
/// masking convention `net::udp::oxidebsd_sys_socket` already uses for `SOCK_CLOEXEC`/
/// `SOCK_NONBLOCK`. Delegates to `crate::fs::pipe::do_socketpair` for the real logic — not a real
/// `AF_UNIX` abstraction, just the same blocking pipe-buffer machinery `sys_pipe` already uses,
/// cross-wired into a full-duplex pair (see that module's own doc comment).
const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_CLOEXEC: u64 = 0o2000000;
const SOCK_NONBLOCK: u64 = 0o4000;

pub(crate) fn sys_socketpair(
    domain: u64,
    ty: u64,
    _protocol: u64,
    fds_ptr: u64,
) -> Result<u64, u64> {
    let base_ty = ty & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    if domain != AF_UNIX || base_ty != SOCK_STREAM {
        return Err(EPROTONOSUPPORT);
    }
    crate::fs::pipe::do_socketpair(fds_ptr)
}

/// `SYS_SET_TID_ADDRESS` (`150`) — real `set_tid_address(2)`'s exact single-pointer wire format.
/// Called unconditionally by every musl-linked program at startup (`third_party/musl/src/env/
/// __init_tls.c`, storing the result as the main thread's own `tid`) and again after every real
/// `fork()` (`third_party/musl/src/process/_Fork.c`) -- previously entirely unregistered, so every
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
/// own wrapper, `third_party/musl/src/fcntl/fcntl.c`, always calls it this way for every command
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
/// `src/net/tcp.rs`'s `tcp_read`), so `O_NONBLOCK` on one of those is accepted and tracked but
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
/// Real `open(2)` `O_APPEND` value (`third_party/musl/arch/generic/bits/fcntl.h`) -- `F_GETFL`
/// reports this bit back via `crate::fs::fd::is_append_of`, see that function's own doc comment
/// for the real bug (`aio_write/2-1.c`) this closes.
const O_APPEND: u64 = 0o2000;
/// Real `fcntl(2)` `FD_CLOEXEC` value (`third_party/musl/include/fcntl.h`) -- distinct from
/// `open(2)`'s own `O_CLOEXEC` flag value (`0o2000000`, consulted by `modules/oxfs`'s `oxfs_open`
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
        F_DUPFD => crate::fs::fd::dup(fd).map_err(|_| EBADF),
        F_DUPFD_CLOEXEC => {
            let newfd = crate::fs::fd::dup(fd).map_err(|_| EBADF)?;
            crate::fs::fd::set_cloexec(pid, newfd, true);
            Ok(newfd)
        }
        _ => Err(EINVAL),
    }
}

/// `SYS_SHUTDOWN` (`152`) — real `shutdown(2)`'s exact `(fd, how)` shape. Resolves the caller's
/// `fd` to its own `real_fd` first (same pattern `oxfs_fstat` already established for a handler
/// that isn't routed through `crate::fs::fd::read`/`write`'s own automatic resolution) and
/// delegates to `crate::fs::pipe::do_shutdown` — real half-close semantics for an `AF_UNIX`/
/// `SOCK_STREAM` socketpair endpoint only (`ENOTSOCK` for anything else); see that function's own
/// doc comment.
pub(crate) fn sys_shutdown(fd: u64, how: u64) -> Result<u64, u64> {
    let Some(real_fd) = crate::fs::fd::real_fd_of(fd) else {
        return Err(EBADF);
    };
    crate::fs::pipe::do_shutdown(real_fd, how)
}

/// `SYS_SET_FS_BASE` (`103`) — OxideBSD's own invention, not modeled on any real OS's syscall (see
/// `modules/native_abi/`'s doc comment for why new syscalls this ABI adds don't chase FreeBSD
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
    crate::process::do_kill(crate::process::scheduler::current_pid(), pid as i64, sig as i64)
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
/// (`third_party/musl/src/thread/pthread_cancel.c`) genuinely calls `sigaction(SIGCANCEL=33,
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
    crate::process::do_sigaction(crate::process::scheduler::current_pid(), sig, act_ptr, oldact_ptr)
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
    crate::process::do_sigprocmask(crate::process::scheduler::current_pid(), how, set_ptr, oldset_ptr)
}

/// `SYS_SIGPENDING` (real `rt_sigpending`'s own wire slot, `494` after the collision sweep in
/// `docs/MISSING_POSIX_SYSCALLS.md` redirected it off its previous accidental home at `SYS_STAT =
/// 127`) — matches real `sigpending(2)`'s exact `(set_ptr, sigsetsize)` wire format, same
/// "sigsetsize read but not otherwise validated" story `sys_sigaction`/`sys_sigprocmask` already
/// have. Delegates to `process::do_sigpending`.
pub(crate) fn sys_sigpending(set_ptr: u64, sigsetsize: u64) -> Result<u64, u64> {
    let _ = sigsetsize;
    crate::process::do_sigpending(crate::process::scheduler::current_pid(), set_ptr)
}

/// `SYS_SIGALTSTACK` (`528`, item 3 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
/// pre-reserved batch) — matches real `sigaltstack(2)`'s exact `(ss_ptr, old_ptr)` wire format
/// (`third_party/musl/src/signal/sigaltstack.c` is a bare 2-argument `syscall`, no call-site patch
/// needed beyond the number remap already sitting in `bits/syscall.h.in`). Delegates straight to
/// `process::do_sigaltstack` — see that function's and `AltStack`'s own doc comments for the real
/// bookkeeping-only semantics.
pub(crate) fn sys_sigaltstack(ss_ptr: u64, old_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sigaltstack(crate::process::scheduler::current_pid(), ss_ptr, old_ptr)
}

/// `SYS_PAUSE` (`529`, item 4 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved
/// batch) — matches real `pause(2)`'s exact zero-argument wire format
/// (`third_party/musl/src/internal/syscall.h`'s `__sys_pause_cp` is a bare `__syscall_cp(SYS_pause)`,
/// no call-site patch needed beyond the number remap already sitting in `bits/syscall.h.in`).
/// Delegates straight to `process::do_pause` — see that function's and `BlockReason::
/// WaitingForSignal`'s own doc comments for the real block/wake primitive this needed.
pub(crate) fn sys_pause() -> Result<u64, u64> {
    crate::process::do_pause(crate::process::scheduler::current_pid())
}

/// `SYS_SIGSUSPEND` (`530`, item 5 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
/// pre-reserved batch) — matches real `sigsuspend(2)`'s exact `(mask_ptr, sigsetsize)` wire format
/// (`third_party/musl/src/signal/sigsuspend.c` is a bare `syscall_cp(SYS_rt_sigsuspend, mask,
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
pub(crate) fn sys_sigtimedwait(mask_ptr: u64, info_ptr: u64, ts_ptr: u64, sigsetsize: u64) -> Result<u64, u64> {
    let _ = sigsetsize;
    crate::process::do_sigtimedwait(crate::process::scheduler::current_pid(), mask_ptr, info_ptr, ts_ptr)
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
/// directly (`third_party/musl/src/signal/raise.c`, `src/exit/abort.c`), never through `kill()` —
/// previously a flat `ENOSYS`, so `abort()`/`assert()` fell through to a raw trap instead of real
/// `SIGABRT` delivery. Since `SYS_SET_TID_ADDRESS` already returns the real pid as `tid` on this
/// single-threaded kernel, `tkill(tid, sig)` is exactly `kill(tid, sig)` — a thin wrapper over the
/// existing `do_kill`, not a new primitive.
pub(crate) fn sys_tkill(tid: u64, sig: u64) -> Result<u64, u64> {
    crate::process::do_kill(crate::process::scheduler::current_pid(), tid as i64, sig as i64)
}

/// `SYS_SETPGID` (`120`) — matches real `setpgid(2)`'s exact `(pid, pgid)` wire format, same
/// "no argument-convention patch needed" story `sys_pipe`/`sys_dup2`/`sys_kill` already
/// established. Delegates to `process::do_setpgid` — see that function's own doc comment for the
/// real, documented simplification (no permission/session checks — this kernel has no uid model at
/// all yet).
pub(crate) fn sys_setpgid(pid: u64, pgid: u64) -> Result<u64, u64> {
    crate::process::do_setpgid(crate::process::scheduler::current_pid(), pid as i64, pgid as i64)
}

/// `SYS_GETPGID` (`121`) — matches real `getpgid(2)`'s exact `(pid)` wire format.
pub(crate) fn sys_getpgid(pid: u64) -> Result<u64, u64> {
    crate::process::do_getpgid(crate::process::scheduler::current_pid(), pid as i64)
}

/// `SYS_SETSID` — real x86_64 Linux's own `__NR_setsid` value (`112`, confirmed against
/// `third_party/musl/arch/x86_64/bits/syscall.h.in` directly, not assumed from a generic/other-arch
/// table — the exact class of mismatch CLAUDE.md's syscall-ABI section warns about elsewhere).
/// `third_party/musl/src/unistd/setsid.c` is a bare `syscall(SYS_setsid)` with no arguments and no
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

/// `SYS_GETUID`/`SYS_GETEUID`/`SYS_GETGID`/`SYS_GETEGID` (`158`-`161`, registered by
/// `modules/posix_compat`, continuing on from `SYS_SETITIMER`/`SYS_GETITIMER = 156`/`157`) — all
/// four are real zero-argument `getuid(2)`-family calls, so only the number needed remapping on
/// the musl side. Delegate to `process::do_getuid`/`do_getgid` — see `Process::uid`'s own doc
/// comment for why there's no distinct effective value to compute.
pub(crate) fn sys_getuid() -> u64 {
    crate::process::do_getuid(crate::process::scheduler::current_pid())
}

pub(crate) fn sys_geteuid() -> u64 {
    crate::process::do_getuid(crate::process::scheduler::current_pid())
}

pub(crate) fn sys_getgid() -> u64 {
    crate::process::do_getgid(crate::process::scheduler::current_pid())
}

pub(crate) fn sys_getegid() -> u64 {
    crate::process::do_getgid(crate::process::scheduler::current_pid())
}

/// `SYS_SETUID`/`SYS_SETGID` (`162`/`163`) — real single-argument `setuid(2)`/`setgid(2)` wire
/// format. Delegates to `process::do_setuid`/`do_setgid` for the real POSIX permission rule (root
/// may become any uid/gid, anything else may only "become" its own current one).
pub(crate) fn sys_setuid(uid: u64) -> Result<u64, u64> {
    crate::process::do_setuid(crate::process::scheduler::current_pid(), uid as u32)
}

pub(crate) fn sys_setgid(gid: u64) -> Result<u64, u64> {
    crate::process::do_setgid(crate::process::scheduler::current_pid(), gid as u32)
}

/// `SYS_SETRESUID` (`499` — real, unclaimed `__NR_setresuid`, see `docs/MISSING_POSIX_SYSCALLS.md`'s
/// numeric-collision sweep for why it isn't at its original real value `117`) — real `(ruid, euid,
/// suid)` wire format, each a `uid_t` cast through `int`/`long` so a real `-1` ("leave unchanged")
/// arrives sign-extended and reads back correctly as `i64`. See `process::do_setresuid`'s own doc
/// comment for the real POSIX permission rule and why this single handler also backs `seteuid()`.
pub(crate) fn sys_setresuid(ruid: u64, euid: u64, suid: u64) -> Result<u64, u64> {
    crate::process::do_setresuid(
        crate::process::scheduler::current_pid(),
        ruid as i64,
        euid as i64,
        suid as i64,
    )
}

/// `SYS_GETGROUPS` (`164`) — real `getgroups(int size, gid_t list[])` wire format, no
/// argument-convention patch needed (a plain `(size, ptr)` pair, no string argument to mismatch).
/// See `process::do_getgroups`'s own doc comment for why the caller's own `gid` is the complete,
/// correct answer on a kernel with no supplementary-group concept.
pub(crate) fn sys_getgroups(size: u64, list_ptr: u64) -> Result<u64, u64> {
    crate::process::do_getgroups(crate::process::scheduler::current_pid(), size as i64, list_ptr)
}

/// `SYS_SETGROUPS` (`178` — an *invented* number, not real Linux's own `__NR_setgroups` (`116`):
/// that value was already independently claimed by this ABI's own `SYS_KILL`, a real collision
/// found live — see `third_party/musl/arch/x86_64/bits/syscall.h.in`'s own comment on this line
/// for the full story). Real `(size, gid_list_ptr)` wire format, no argument-convention patch
/// needed. See `process::do_setgroups`'s own doc comment for why this is a real, permission-
/// checked no-op rather than either an unconditional success or a plain `ENOSYS`.
pub(crate) fn sys_setgroups(count: u64, list_ptr: u64) -> Result<u64, u64> {
    crate::process::do_setgroups(crate::process::scheduler::current_pid(), count, list_ptr)
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
    crate::process::do_sched_setparam(crate::process::scheduler::current_pid(), pid as i64, param_ptr)
}

/// `SYS_SCHED_GETSCHEDULER` (`482`) — real `sched_getscheduler(2)`'s exact `(pid)` wire format.
pub(crate) fn sys_sched_getscheduler(pid: u64) -> Result<u64, u64> {
    crate::process::do_sched_getscheduler(crate::process::scheduler::current_pid(), pid as i64)
}

/// `SYS_SCHED_GETPARAM` (`483`) — real `sched_getparam(2)`'s exact `(pid, param_ptr)` wire format.
pub(crate) fn sys_sched_getparam(pid: u64, param_ptr: u64) -> Result<u64, u64> {
    crate::process::do_sched_getparam(crate::process::scheduler::current_pid(), pid as i64, param_ptr)
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
    crate::process::do_sched_rr_get_interval(crate::process::scheduler::current_pid(), pid as i64, ts_ptr)
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

/// Real Linux/generic `ioctl` request codes (`third_party/musl`'s `arch/generic/bits/ioctl.h`) --
/// this ABI's `SYS_IOCTL` reuses these verbatim as its own `request` argument values (they're
/// already architecture-generic constants, not syscall numbers, so there's nothing to remap the
/// way `open`/`execve` needed -- see `sys_ioctl`'s own doc comment).
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
/// Session/controlling-tty requests (see CLAUDE.md's session/controlling-tty notes, and
/// `process::Process::sid`/`stdin::CONTROLLING_SESSION`/`stdin::FOREGROUND_PGID`) — added
/// specifically to get `sulogin`/`getty` (both call `setsid()` then one of these) past their own
/// startup sequence, since this kernel had no session/foreground-process-group concept at all
/// before.
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCNOTTY: u64 = 0x5422;
/// OxideBSD's own invention, not real Linux's `FBIOGET_VSCREENINFO` (`0x4600`) -- deliberately a
/// distinct, smaller wire struct (`RawFbInfo` below) rather than emulating that ioctl's real,
/// much larger `struct fb_var_screeninfo` layout, since nothing in this port's roster needs real
/// Linux fbdev source compatibility (see the doomgeneric/fbdoom port's own design notes: a
/// backend file written against this kernel's own syscalls, not a literal Linux fbdev emulation).
const FBIOGET_OXIDEBSD: u64 = 0x4600;

/// A fixed, plausible `struct winsize` (`third_party/musl`'s `include/alltypes.h.in`: four `u16`s,
/// `ws_row`/`ws_col`/`ws_xpixel`/`ws_ypixel`, no padding) -- this kernel has no real display-size
/// concept to report (VGA text mode is a fixed 80x25, but nothing downstream actually depends on
/// the exact number, same "value now, precision later" reasoning `AT_RANDOM`'s own placeholder
/// bytes already use), so `80x24` (leaving one row of headroom, the traditional default terminal
/// size real `stty size`/`resize`-less setups already assume) is picked purely to look sane, not
/// measured from anything.
#[repr(C)]
struct RawWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}
const FIXED_WINSIZE: RawWinsize = RawWinsize {
    ws_row: 24,
    ws_col: 80,
    ws_xpixel: 0,
    ws_ypixel: 0,
};

/// `FBIOGET_OXIDEBSD`'s own wire struct -- real, runtime-queried framebuffer geometry (see
/// `drivers::fbdev::FbGeometry`, which this mirrors exactly, minus `phys_base`/`len`: a userland
/// caller has no use for the physical address itself, only what `mmap()` on the same fd already
/// hands back as a virtual pointer).
#[repr(C)]
struct RawFbInfo {
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
}

/// `SYS_IOCTL` (`124`) — real request codes (see above), but **not** real `ioctl(2)`'s full
/// surface: only the handful of tty-specific requests this kernel's own console can plausibly
/// answer (`TCGETS`/`TCSETS*`/`TIOCGWINSZ`/`TIOCSWINSZ`/`TIOCSCTTY`/`TIOCNOTTY`/`TIOCGPGRP`/
/// `TIOCSPGRP`) are handled; anything else is `ENOTTY`, logged the same way an unregistered
/// syscall number already is, so a future need is discoverable the same "boot it and read the log"
/// way every other gap in this codebase was found.
///
/// **Only ever succeeds against the console** (`crate::fs::fd::real_fd_of(fd)` resolving to
/// stdin's or stdout's own `real_fd`, `0`/`1` -- see `src/fs/fd.rs`'s module doc comment for why
/// checking `fd` itself, rather than what it currently resolves to, would be wrong after a
/// `dup2`) **or a real `/dev/fb0` fd** (`crate::fs::fd::framebuffer_geometry_of`, backing
/// `FBIOGET_OXIDEBSD` below), `ENOTTY` otherwise. This is load-bearing, not incidental: musl's own `isatty(fd)`
/// (`third_party/musl`'s `src/unistd/isatty.c`) is implemented as "does `ioctl(fd, TIOCGWINSZ,
/// ...)` succeed" -- if this answered every fd successfully, every regular `oxfs` file and every
/// pipe end would suddenly report itself as a tty too, which would be a real regression: BusyBox's
/// own graceful "not a tty" degradation (see CLAUDE.md's musl-port/BusyBox-port sections) is what
/// currently keeps e.g. a redirected/piped `cat`/`more` behaving like a real Unix pipeline.
///
/// **`TCSETS`/`TCSETSW`/`TCSETSF` are all treated identically** — real Unix distinguishes them by
/// *when* the change takes effect relative to already-queued output/input (immediately, after
/// output drains, or after input is also flushed), a distinction this kernel has no queued-output
/// concept to make meaningful at all, so applying the new settings immediately, unconditionally,
/// is already the correct behavior for the two "drain first" variants and a harmless
/// oversimplification for the third.
pub(crate) fn sys_ioctl(fd: u64, request: u64, argp: u64) -> Result<u64, u64> {
    // Widened for a real `/dev/fb0` fd (see `FBIOGET_OXIDEBSD` below) -- checked only once the
    // fast console-fd path already fails, so the ordinary tty-ioctl case never pays for the extra
    // FFI round trip.
    let is_console = matches!(crate::fs::fd::real_fd_of(fd), Some(0) | Some(1));
    if !is_console && crate::fs::fd::framebuffer_geometry_of(fd).is_none() {
        return Err(ENOTTY);
    }

    match request {
        TCGETS => {
            let termios = crate::console::stdin::get_termios();
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // file already has -- argp isn't checked against the caller's actual mappings first.
            unsafe { *(argp as *mut crate::console::stdin::RawTermios) = termios };
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            // SAFETY: same known pointer-validation gap as above, for a read this time.
            let termios = unsafe { *(argp as *const crate::console::stdin::RawTermios) };
            crate::console::stdin::set_termios(termios);
            Ok(0)
        }
        TIOCGWINSZ => {
            // SAFETY: same known pointer-validation gap as above.
            unsafe { *(argp as *mut RawWinsize) = FIXED_WINSIZE };
            Ok(0)
        }
        TIOCSWINSZ => Ok(0), // accepted, silently discarded -- nothing reads window size back out
        TIOCSCTTY => {
            let caller_pid = crate::process::scheduler::current_pid();
            let table = crate::process::table().lock();
            let Some(proc) = table.get(&caller_pid) else {
                return Err(ENOTTY);
            };
            // Real Linux requires the caller be a session leader unless `force` (the raw `argp`
            // value here, not a pointer -- real `ioctl(fd, TIOCSCTTY, arg)` passes `arg` by value
            // for this request) is set; this kernel has no permission model gating `force` itself
            // (only root has ever existed as a concept predating this pass), so any caller may
            // force-steal the controlling tty, matching real Linux's own "force requires
            // CAP_SYS_ADMIN" collapsing to "always allowed" on a kernel with no capability model.
            if proc.sid != caller_pid && argp == 0 {
                return Err(EPERM);
            }
            let sid = proc.sid;
            drop(table);
            crate::console::stdin::set_controlling_session(sid);
            Ok(0)
        }
        TIOCNOTTY => {
            let caller_pid = crate::process::scheduler::current_pid();
            let sid = crate::process::table()
                .lock()
                .get(&caller_pid)
                .map(|p| p.sid)
                .ok_or(ENOTTY)?;
            crate::console::stdin::clear_controlling_session_if(sid);
            Ok(0)
        }
        TIOCGPGRP => {
            let caller_pid = crate::process::scheduler::current_pid();
            let sid = crate::process::table()
                .lock()
                .get(&caller_pid)
                .map(|p| p.sid)
                .ok_or(ENOTTY)?;
            if crate::console::stdin::controlling_session() != Some(sid) {
                return Err(ENOTTY);
            }
            let pgid = crate::console::stdin::foreground_pgid().unwrap_or(sid) as i32;
            // SAFETY: same known pointer-validation gap every other user-memory write in this file
            // already has.
            unsafe { *(argp as *mut i32) = pgid };
            Ok(0)
        }
        TIOCSPGRP => {
            let caller_pid = crate::process::scheduler::current_pid();
            let sid = crate::process::table()
                .lock()
                .get(&caller_pid)
                .map(|p| p.sid)
                .ok_or(ENOTTY)?;
            if crate::console::stdin::controlling_session() != Some(sid) {
                return Err(ENOTTY);
            }
            // SAFETY: same known pointer-validation gap as above, for a read this time.
            let pgid = unsafe { *(argp as *const i32) };
            if pgid <= 0 {
                return Err(EINVAL);
            }
            crate::console::stdin::set_foreground_pgid(pgid as u64);
            Ok(0)
        }
        FBIOGET_OXIDEBSD => {
            let geom = crate::fs::fd::framebuffer_geometry_of(fd).ok_or(ENOTTY)?;
            let info = RawFbInfo {
                width: geom.width,
                height: geom.height,
                pitch: geom.pitch,
                bpp: geom.bpp,
            };
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // file already has.
            unsafe { *(argp as *mut RawFbInfo) = info };
            Ok(0)
        }
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
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // file already has.
            unsafe { *(out_ptr as *mut crate::console::keyevents::RawKeyEvent) = event };
            Ok(1)
        }
        None => Ok(0),
    }
}

/// musl's own `struct utsname` (`third_party/musl/include/sys/utsname.h`): six fixed 65-byte
/// NUL-padded fields, no padding between them -- same "byte-exact against the real musl layout"
/// discipline `modules/oxfs`'s `MuslStat` already follows for `stat(2)`.
#[repr(C)]
struct RawUtsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

fn utsname_field(s: &str) -> [u8; 65] {
    let mut field = [0u8; 65];
    let bytes = s.as_bytes();
    let len = bytes.len().min(64);
    field[..len].copy_from_slice(&bytes[..len]);
    field
}

/// `SYS_UNAME` (registered as `137` by `modules/posix_compat`, continuing on from `SYS_MKDIR =
/// 136`) — happens to match real `uname(2)`'s exact single-pointer wire format (musl's own
/// `uname()`, `third_party/musl/src/misc/uname.c`, is just `syscall(SYS_uname, uts)` — no
/// derived-argument computation from the pointer the way `open`'s `strlen` needed, so no
/// argument-convention patch was needed on the musl side beyond the usual number remap).
///
/// Every field is a fixed placeholder — this kernel has no real hostname-configuration mechanism
/// (`nodename` is a constant, not settable via a `sethostname(2)` this ABI doesn't have) and no
/// real build-timestamp source (`version` is a plausible-looking, hand-picked string, not derived
/// from anything). `release` is the one field that isn't fully static: it's this crate's own
/// `CARGO_PKG_VERSION`, so bumping `Cargo.toml`'s `version` moves what `uname -a`/`uname -r`
/// reports without touching this function again.
pub(crate) fn sys_uname(uts_ptr: u64) -> Result<u64, u64> {
    let uts = RawUtsname {
        sysname: utsname_field("OxideBSD"),
        nodename: utsname_field("oxidebsd"),
        release: utsname_field(env!("CARGO_PKG_VERSION")),
        version: utsname_field("#1 SMP PREEMPT"),
        machine: utsname_field("x86_64"),
        domainname: utsname_field("(none)"),
    };
    // SAFETY: same known pointer-validation gap every other user-memory write in this file
    // already has -- uts_ptr isn't checked against the caller's actual mappings first.
    unsafe { *(uts_ptr as *mut RawUtsname) = uts };
    Ok(0)
}

/// musl's own `struct timeval` on x86_64 (`third_party/musl/include/alltypes.h.in`'s `STRUCT
/// timeval` template): a `time_t`/`suseconds_t` pair, both 8 bytes on this arch.
#[repr(C)]
#[derive(Default)]
struct RawTimeval {
    tv_sec: i64,
    tv_usec: i64,
}

/// musl's own `struct rusage` on x86_64 (`third_party/musl/include/sys/resource.h`): two
/// `timeval`s, then 14 `long` fields, then a 16-`long` reserved tail -- 272 bytes total. Backs both
/// `SYS_GETRUSAGE` and `SYS_WAIT4`'s own optional 4th `rusage_ptr` argument (see
/// `write_zeroed_rusage`, below). This kernel tracks no per-process CPU time/memory-usage
/// accounting at all (`/proc/stat`'s own `cpu` line is already an honest all-zero placeholder for
/// the identical reason) -- every field here is a real, correctly-shaped, honestly-zeroed
/// placeholder rather than an invented number, same tier as `/proc/meminfo`'s `MemFree ==
/// MemTotal`.
#[repr(C)]
#[derive(Default)]
struct RawRusage {
    ru_utime: RawTimeval,
    ru_stime: RawTimeval,
    fields: [i64; 14],
    reserved: [i64; 16],
}

const _: () = assert!(core::mem::size_of::<RawRusage>() == 272);

/// Writes an all-zero `RawRusage` to `ptr` if it's non-null -- shared by `sys_getrusage` and
/// `do_wait4`'s own optional `rusage_ptr` argument (`src/process.rs`), the same "one real helper,
/// two call sites" shape `write_stat`-style functions elsewhere in this codebase already use.
pub(crate) fn write_zeroed_rusage(ptr: u64) {
    if ptr == 0 {
        return;
    }
    // SAFETY: same known pointer-validation gap every other user-memory write in this file already
    // has -- an arbitrary caller-supplied pointer isn't checked against the caller's actual
    // mappings first. `write_unaligned` since a real `struct rusage*` has no alignment guarantee
    // this kernel can rely on (unlike `RawUtsname` above, which is only ever reached from
    // `sys_uname`'s own single, always-aligned-in-practice call site).
    unsafe { (ptr as *mut RawRusage).write_unaligned(RawRusage::default()) };
}

/// `SYS_GETRUSAGE` (registered by `modules/posix_compat`, continuing on from `SYS_UMASK = 487`) --
/// real `getrusage(2)`'s exact `(who, rusage_ptr)` wire format (musl's own `getrusage()`,
/// `third_party/musl/src/misc/getrusage.c`, already issues a plain 2-argument raw syscall with a
/// bare pointer, no length-prefixing involved, so no call-site patch was needed beyond the usual
/// number remap). `who` (`RUSAGE_SELF`/`RUSAGE_CHILDREN`) makes no difference to the answer -- see
/// `RawRusage`'s own doc comment for why. **Same latent staleness `sys_times` had until its own
/// fix** (this call site also predates `Process::cpu_ticks`) -- `ru_utime`/`ru_stime` could be
/// derived from `cpu_ticks`/`child_cpu_ticks` the same way, but nothing currently depends on it
/// (unlike `times(2)`, which `fork/8-1.c` needed real values from to avoid a permanent hang) --
/// left as an honest all-zero placeholder, a known follow-up, not silently forgotten.
pub(crate) fn sys_getrusage(who: u64, rusage_ptr: u64) -> Result<u64, u64> {
    let _ = who;
    write_zeroed_rusage(rusage_ptr);
    Ok(0)
}

/// musl's own `struct tms` on x86_64 (`third_party/musl/include/sys/times.h`): four `clock_t`
/// (`long`, 8 bytes on this arch) fields, no padding -- 32 bytes total.
#[repr(C)]
#[derive(Default)]
struct RawTms {
    tms_utime: i64,
    tms_stime: i64,
    tms_cutime: i64,
    tms_cstime: i64,
}

const _: () = assert!(core::mem::size_of::<RawTms>() == 32);

/// `SYS_TIMES` (real `times`'s own wire slot, `493` after the collision sweep in
/// `docs/MISSING_POSIX_SYSCALLS.md` redirected it off its previous accidental home at
/// `SYS_MMAP = 100`) -- matches real `times(2)`'s exact `(tms_ptr)` wire format
/// (`third_party/musl/src/time/times.c` is a bare `__syscall(SYS_times, tms)`, no call-site patch
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
        // SAFETY: same known pointer-validation gap every other user-memory write in this file
        // already has.
        unsafe {
            (tms_ptr as *mut RawTms).write_unaligned(RawTms {
                tms_utime: cpu_ticks as i64,
                tms_stime: 0,
                tms_cutime: child_cpu_ticks as i64,
                tms_cstime: 0,
            })
        };
    }
    Ok(crate::cpu::interrupts::ticks())
}

/// Real `getrandom(2)`'s `GRND_NONBLOCK`/`GRND_RANDOM` flag bits -- not syscall numbers, no
/// remapping needed.
const GRND_NONBLOCK: u64 = 0x0001;
const GRND_RANDOM: u64 = 0x0002;

/// `SYS_GETRANDOM` (`526`, pre-reserved ahead of implementation in
/// `docs/MISSING_POSIX_SYSCALLS.md` -- item 1 of that doc's own 28-syscall planned-
/// implementation-order batch) -- real `getrandom(2)`'s exact `(buf_ptr, buflen, flags)` wire
/// format (`third_party/musl/src/linux/getrandom.c` is a bare 3-argument `syscall_cp`, no
/// call-site patch needed beyond the number remap already in `bits/syscall.h.in`). Only reachable
/// via `getentropy()` in this port's own roster (BusyBox's `seedrng` applet doesn't build here --
/// missing `linux/random.h`) -- and `third_party/musl/src/misc/getentropy.c` caps `len` at `256`
/// itself and loops calling `getrandom()` until satisfied, so this handler can safely always fill
/// the whole request in one shot: never partial, never blocking. `src/random.rs`'s own generator
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
    Ok(crate::random::oxidebsd_random_bytes(buf_ptr, buflen) as u64)
}

/// musl's own `struct sysinfo` on x86_64 (`third_party/musl/include/sys/sysinfo.h`) -- confirmed
/// 368 bytes via a direct `offsetof`/`sizeof` probe against that exact field list (Rust's own
/// `repr(C)` layout rules match a C compiler's here since every field is a plain scalar/array with
/// no explicit alignment override, but the *value* was verified rather than assumed given how easy
/// an off-by-a-few-bytes struct-layout bug is to get wrong silently). An 8-byte gap after
/// `procs`/`pad` (offset 84) before `totalhigh` (offset 88) is real, natural `unsigned long`
/// alignment padding, not a missing field.
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
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    reserved: [u8; 256],
}

const _: () = assert!(core::mem::size_of::<RawSysinfo>() == 368);

/// `SYS_SYSINFO` (`527`, item 2 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved
/// batch) -- real `sysinfo(2)`'s exact `(info_ptr)` wire format (`third_party/musl/src/linux/
/// sysinfo.c` is a bare 1-argument `syscall(SYS_sysinfo, info)`, no call-site patch needed beyond
/// the number remap already in `bits/syscall.h.in`). Not a POSIX interface at all (Linux-specific),
/// but the confirmed live blocker for `free`/`uptime`'s primary numbers (`procps/{free,uptime}.c`)
/// -- see `docs/BUSYBOX_APPLETS.md`'s own `NEEDS_PROC` entries for those two applets.
///
/// Same honesty tier as `RawRusage`/`RawTms` above: real fields where this kernel actually tracks
/// the concept, an honest placeholder (not a fabricated number) everywhere it doesn't.
/// - `uptime`: real, `ticks() / TIMER_HZ` -- the same conversion `/proc/uptime`
///   (`oxidebsd_proc_uptime`) and `sys_clock_gettime`'s `CLOCK_MONOTONIC` arm already use.
/// - `totalram`: real, `memory::usable_ram_bytes()`, with `mem_unit = 1` so the byte count needs
///   no further scaling -- matches `/proc/meminfo`'s own `MemTotal` source exactly.
/// - `freeram`: set equal to `totalram`, same reasoning `/proc/meminfo`'s own doc comment already
///   gives for `MemFree == MemTotal` -- no free-memory/deallocation tracking exists anywhere in
///   this kernel (the frame allocator never reclaims a frame), so "as much as there ever was" is
///   genuinely the most honest answer available, not an invented one.
/// - `procs`: real, the live process table's own length (`process::table().lock().len()`) --
///   truncated to `u16` (real `sysinfo(2)`'s own field width; this table will never remotely
///   approach 65536 entries on this kernel).
/// - `sharedram`/`bufferram`/`totalswap`/`freeswap`/`totalhigh`/`freehigh`/`loads`: honest `0` --
///   no page cache, no swap, and no load-average tracking exist, same tier as `/proc/meminfo`'s
///   own `Buffers`/`Cached`/`SwapTotal`/`SwapFree` placeholders.
pub(crate) fn sys_sysinfo(info_ptr: u64) -> Result<u64, u64> {
    let ticks = crate::cpu::interrupts::ticks();
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let total_ram = crate::memory::usable_ram_bytes();
    let procs = crate::process::table().lock().len().min(u16::MAX as usize) as u16;
    let info = RawSysinfo {
        uptime: ticks / hz,
        loads: [0; 3],
        totalram: total_ram,
        freeram: total_ram,
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs,
        pad: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 1,
        reserved: [0; 256],
    };
    // SAFETY: same known pointer-validation gap every other user-memory write in this file already
    // has -- info_ptr isn't checked against the caller's actual mappings first.
    unsafe { (info_ptr as *mut RawSysinfo).write_unaligned(info) };
    Ok(0)
}

/// musl's own `struct timespec` on x86_64 (`third_party/musl/include/alltypes.h.in`'s `STRUCT
/// timespec` template, `time_t`/`long` both 8 bytes on this arch): two `i64`s, no padding.
#[derive(Clone, Copy)]
#[repr(C)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Real, architecture-generic `clockid_t` values (`third_party/musl/include/time.h`) -- not
/// syscall numbers, so no remapping needed, unlike `SYS_clock_gettime` itself below.
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;

/// Decodes a real, dynamic per-process/per-thread `clockid_t` -- the encoding
/// `clock_getcpuclockid(2)`'s own musl implementation produces
/// (`third_party/musl/src/time/clock_getcpuclockid.c`: `clockid_t id = (-pid-1)*8U + 2`, matching
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
fn decode_dynamic_cpu_clock_pid(caller_pid: crate::process::Pid, clockid: u64) -> Option<crate::process::Pid> {
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

/// `SYS_CLOCK_GETTIME` (registered as `138` by `modules/clock`, continuing on from `SYS_UNAME =
/// 137`) — matches real `clock_gettime(2)`'s exact `(clockid, timespec_ptr)` wire format, so only
/// the number needed remapping. musl's own `time()`/`gettimeofday()` (`third_party/musl/src/time/
/// time.c`/`gettimeofday.c`) are both plain wrappers around `clock_gettime(CLOCK_REALTIME, ...)`
/// at the C level, not separate syscalls, so this one remap is enough to unlock all three.
///
/// `CLOCK_REALTIME` reports real, sub-second-precision wall-clock time
/// (`src/cpu/rtc.rs`'s `unix_epoch_now_precise` -- a `ticks()`-derived offset calibrated once
/// against the CMOS RTC, not a fresh RTC read every call; see that function's own doc comment for
/// why). `CLOCK_MONOTONIC` converts `src/cpu/interrupts.rs`'s `ticks()` against `src/cpu/pit.rs`'s
/// now-known `TIMER_HZ`, seconds since boot -- not wall-clock time, matching real `CLOCK_MONOTONIC`
/// semantics (unspecified epoch, only meaningful as a delta between two readings).
/// `CLOCK_PROCESS_CPUTIME_ID`/`CLOCK_THREAD_CPUTIME_ID` both read `Process::cpu_ticks` (see that
/// field's own doc comment for why real threading's absence makes the two clockids equivalent
/// here, and for the real gap this closes: `clock_gettime/4-1.c`, the Open POSIX Test Suite
/// pilot). Any other `clockid` is `EINVAL`.
pub(crate) fn sys_clock_gettime(clockid: u64, ts_ptr: u64) -> Result<u64, u64> {
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
    // SAFETY: same known pointer-validation gap every other user-memory write in this file
    // already has -- ts_ptr isn't checked against the caller's actual mappings first.
    unsafe { *(ts_ptr as *mut RawTimespec) = ts };
    Ok(0)
}

/// `SYS_CLOCK_GETRES` -- real Linux's own unclaimed `229` (confirmed against every `SYS_*`
/// constant already registered in this ABI; musl's `bits/syscall.h.in` already carries this value
/// unremapped, and `third_party/musl/src/time/clock_getres.c` calls straight through, so no
/// musl-side patch was needed, just a kernel-side handler). Every clock this kernel implements
/// ticks at a real, honest `TIMER_HZ` (`src/cpu/pit.rs`) cadence -- including the sub-second
/// `CLOCK_REALTIME` reading `sys_clock_gettime` derives from it -- so `1_000_000_000 / TIMER_HZ`ns
/// is the one real resolution value reported for every recognized `clockid`, standard or dynamic
/// per-process (see `decode_dynamic_cpu_clock_pid`). `res_ptr == 0` is real POSIX-legal (the
/// resolution query alone, `clockid` validity is still checked) so only written when non-null.
/// Closes `clock_getres/1-1.c`/`3-1.c`/`6-1.c`/`6-2.c`/`7-1.c`/`8-1.c` and, transitively (this is
/// the only syscall `clock_getcpuclockid(2)`'s own musl implementation issues, purely to validate
/// the pid before handing the encoded `clockid_t` back), `clock_getcpuclockid/1-1.c`/`2-1.c`.
pub(crate) fn sys_clock_getres(clockid: u64, res_ptr: u64) -> Result<u64, u64> {
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
        let hz = crate::cpu::pit::TIMER_HZ as i64;
        // SAFETY: same known pointer-validation gap every other user-memory write in this file
        // already has.
        unsafe {
            *(res_ptr as *mut RawTimespec) = RawTimespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000 / hz,
            }
        };
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
    // SAFETY: same known pointer-validation gap every other user-memory read in this file already
    // has.
    let ts = unsafe { *(ts_ptr as *const RawTimespec) };
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
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            set_cpu_ticks(crate::process::scheduler::current_pid(), ts.tv_sec, ts.tv_nsec)
        }
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

/// Thin FFI adapters over `sys_read`/`sys_write` for `modules/native_abi/` to call — see `super`'s
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
/// (`third_party/busybox/shell/hush.c`'s `checkjobs`) to decide whether to print a
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
/// comment and `third_party/musl/arch/x86_64/bits/syscall.h.in`'s `__NR_exit_group` doc comment
/// for why real `exit()`/`_Exit()` need a genuinely separate syscall from a bare per-thread
/// `SYS_exit`. Same real `wait(2)`-status-word encoding as `oxidebsd_sys_exit` above -- this is
/// the *other* place a genuine user-supplied `exit(code)` value becomes a `Zombie` status.
pub(crate) extern "C" fn oxidebsd_sys_exit_group(code: u64) -> ! {
    let status = ((code as i32) & 0xff) << 8;
    crate::process::do_exit_group(crate::process::scheduler::current_pid(), status)
}

// `pub`, not `pub(crate)` -- same "kept public for test use" precedent `oxidebsd_register_syscall`
// already has (see `tests/fork_wait.rs`). `tests/tcp_smoke.rs` needs the real SYS_READ/SYS_WRITE
// entry point (not a lower-level shortcut) to exercise an accepted TCP connection's fd-ops
// callbacks the exact way a real process's read()/write() would reach them.
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

pub(crate) extern "C" fn oxidebsd_sys_pwritev2(fd: u64, iov_ptr: u64, iovcnt: u64, ofs: u64) -> i64 {
    result_to_ffi(sys_pwritev2(fd, iov_ptr, iovcnt, ofs))
}

// `pub`, not `pub(crate)` -- same "kept public for test use" precedent above; `tests/
// readv_smoke.rs` calls this directly.
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

// `pub`, not `pub(crate)` -- same "kept public for test use" precedent `oxidebsd_sys_read`/
// `oxidebsd_sys_write` already have; `tests/socketpair_smoke.rs` calls this directly.
pub extern "C" fn oxidebsd_sys_socketpair(
    domain: u64,
    ty: u64,
    protocol: u64,
    fds_ptr: u64,
) -> i64 {
    result_to_ffi(sys_socketpair(domain, ty, protocol, fds_ptr))
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

pub extern "C" fn oxidebsd_sys_shutdown(fd: u64, how: u64) -> i64 {
    result_to_ffi(sys_shutdown(fd, how))
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

pub(crate) extern "C" fn oxidebsd_sys_sigqueue(pid: u64, sig: u64, siginfo_ptr: u64, _a3: u64) -> i64 {
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

/// `SYS_SETITIMER = 156`/`SYS_GETITIMER = 157` (registered by `modules/clock`, continuing on from
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
/// `SYS_TIMER_GETOVERRUN = 534`/`SYS_TIMER_DELETE = 535` (registered by `modules/clock`, items
/// 6-10 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch) -- real POSIX
/// per-process timers, a natural extension of the already-implemented `setitimer`/`getitimer`
/// (`ITIMER_REAL`-only) infrastructure just above, now that per-timer-id tracking exists
/// (`process::PosixTimer`/`Process::posix_timers`). See `process::do_timer_create`'s own doc
/// comment for the real wire format/semantics of the whole sub-batch.
pub(crate) extern "C" fn oxidebsd_sys_timer_create(clockid: u64, evp_ptr: u64, timerid_ptr: u64) -> i64 {
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

/// `SYS_MQ_OPEN = 536` through `SYS_MQ_GETSETATTR = 541` (registered by `modules/posix_compat`,
/// items 11-16 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch) -- real
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

/// `SYS_MSGGET = 550` through `SYS_MSGCTL = 553` (registered by `modules/posix_compat`, items
/// 25-28 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch -- the last
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

/// `SYS_SEMGET = 546` through `SYS_SEMTIMEDOP = 549` (registered by `modules/posix_compat`, items
/// 21-24 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch) -- real SysV
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

/// `SYS_SHMGET = 542` through `SYS_SHMDT = 545` (registered by `modules/posix_compat`, items
/// 17-20 of `docs/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch, the last
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

/// Thin FFI adapters over `src/process.rs`'s `do_fork_from_current`/`do_wait4`/`do_execve`/
/// `do_getpid`/`do_mmap`/`do_munmap`/`do_brk` for `modules/native_abi/` to call — same pattern as
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
/// `third_party/musl/src/mman/mmap.c`'s own patched `__mmap()` since real `mmap(2)`'s 6-arg shape
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
    result_to_ffi(crate::process::do_mprotect(addr, len, prot))
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
