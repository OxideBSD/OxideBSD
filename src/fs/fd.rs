//! A minimal kernel-owned file-descriptor registry — the only channel two independently loaded
//! modules have to coordinate with each other, since modules can only ever call *into* the
//! kernel, never directly into another module (see `src/module.rs`'s doc comment). Concretely:
//! `modules/fat32/`'s open files register their read/write/close callbacks here; `src/syscall.rs`'s
//! `sys_read`/`sys_write` delegate to this registry unconditionally, for *every* fd, including
//! 0/1/2 (see below) — no fd is special-cased in `sys_read`/`sys_write` itself.
//!
//! **Scoped per-*thread-group* (`(tgid, fd)`), not a single flat table keyed by fd alone** — the
//! table used to be exactly that (a real, deliberate simplification, documented as a known
//! limitation: "two unrelated process trees allocating fds independently would collide"), but that
//! turned out to be more than a hypothetical collision risk once `sh` (BusyBox's `hush`) actually
//! built a real pipeline (`cmd1 | cmd2`): `pipe(2)` creates two fds in the shell process, which
//! then forks twice and each child `dup2`s one end onto its own stdin/stdout and closes its own copy of the
//! originals. With a single flat table, the *parent* closing its own copy of a pipe fd (completely
//! ordinary, expected shell behavior — the parent doesn't need the pipe once both children have it)
//! tore the entry down globally, out from under children that still needed it via `dup2`, and a
//! child's own `dup2` couldn't even find an fd the *parent* had allocated if the parent hadn't
//! forked it into being yet. Real `fork()` duplicates the whole fd table into the child (each
//! process gets its own independently-closable entry referring to the same underlying resource) —
//! `fork_inherit` below is what actually does that now.
//!
//! Known, deliberate limitation kept from before: fd numbers (and the `real_fd` identity described
//! below) are handed out by a simple global bump counter and never reused, even after every
//! reference to one is closed — consistent with this kernel's broader "no deallocation" pattern
//! elsewhere (e.g. `memory::BootInfoFrameAllocator`, `module::allocate_region`).
//!
//! **stdin/stdout/stderr are registered entries here, not special cases in `sys_read`/`sys_write`**
//! — forced by `dup2`: a shell redirecting a pipeline's stdout (`dup2(pipe_write_fd, 1)`) needs fd 1
//! itself to become an ordinary, overwritable registry entry. Bootstrapped once at boot (`init`,
//! before any real process exists) under a reserved pseudo-pid (`0`, never a real running process)
//! and inherited into every subsequently spawned process the same way a forked child inherits its
//! parent's fds (`process::spawn` calls `fork_inherit(0, new_pid)`) — see `init`'s own doc comment.
//!
//! **`real_fd` + refcounting is what makes `dup2`/`fork_inherit` actually alias shared state, not
//! just copy function pointers.** A naive alias that copied `FdOps` verbatim into a new `(pid, fd)`
//! slot would call the *same* callback functions but pass that new fd number as their first
//! argument — wrong, since e.g. `modules/fat32/`'s open-file table (or `src/pipe.rs`'s pipe-buffer
//! table) is keyed by whatever fd the resource was originally opened/created under, not by every
//! later alias. `FdOps::real_fd` (a globally unique identity, independent of which process(es) can
//! currently see it) is threaded through every alias: `read`/`write`/`close` below always invoke
//! the registered callback with `ops.real_fd`, never the `(pid, fd)` that was actually looked up.
//! `REFCOUNTS` (keyed by `real_fd`, shared across every process that has an alias of it, not per
//! `(pid, fd)`) ensures the underlying resource's own `close` callback only actually fires once
//! every alias — across every process that ever had one — has been closed.

use alloc::collections::{BTreeMap, BTreeSet};

use spin::Mutex;

use crate::process::scheduler;
use crate::syscall::{EBADF, ESPIPE};

/// Matches `syscall::SyscallHandler`'s own FFI convention (negative = `-errno`, non-negative =
/// success value) for the same reason — see that type's doc comment. Kept as a separate type
/// here (rather than reusing `SyscallHandler` directly) since the two represent conceptually
/// different things — syscall-number dispatch vs. per-fd operations — even though their shapes
/// happen to coincide.
pub(crate) type FdReadWrite = extern "C" fn(u64, u64, u64) -> i64;
pub(crate) type FdClose = extern "C" fn(u64) -> i64;
/// Real `pread(2)`/`pwrite(2)`: `(real_fd, ptr, len, offset)` — like `FdReadWrite` above, but with
/// an explicit offset that (per real POSIX) neither reads nor updates the fd's own current file
/// position, unlike plain `read`/`write`. Optional per fd kind (defaults to `no_pread_pwrite`,
/// below) since most registered fd kinds (pipes, sockets, mqueues, devices) have no real seekable
/// position at all — only `modules/oxfs`'s own real, on-disk-backed `OpenFile` variants register
/// real implementations (see `oxidebsd_set_fd_pread_pwrite`).
pub(crate) type FdReadWriteAt = extern "C" fn(u64, u64, u64, u64) -> i64;

/// Default `pread`/`pwrite` callback for any fd kind that never calls `oxidebsd_set_fd_pread_pwrite`
/// — real POSIX `ESPIPE`, matching what `lseek(2)` on the same kind of fd already reports.
extern "C" fn no_pread_pwrite(_real_fd: u64, _ptr: u64, _len: u64, _offset: u64) -> i64 {
    -(ESPIPE as i64)
}

/// `content_id`'s shape — real Linux/POSIX has no analogous concept at the syscall boundary, this
/// is purely internal plumbing for `crate::process::mm::do_mmap`'s fd-backed `MAP_SHARED` support:
/// a stable identity for "the same underlying file," queried live (not cached at registration
/// time) so it reflects a fd's *current* state — e.g. `modules/oxfs`'s own `OpenFile::Write`
/// variant only gets a real backing inode once `ftruncate`/`write`/`close` actually allocates one,
/// which can happen strictly after `open()` but before `mmap()` in the same real call sequence
/// (`open(O_CREAT|O_EXCL) -> ftruncate() -> mmap()`, the shape every POSIX conformance test that
/// needs this uses). Returns `-1` for "not identifiable / not mmap-able as a real file" (every fd
/// kind except `modules/oxfs`'s own file-backed `OpenFile` variants, via `no_content_id` below).
pub(crate) type FdContentId = extern "C" fn(u64) -> i64;

extern "C" fn no_content_id(_real_fd: u64) -> i64 {
    -1
}

/// A fd's real, fixed-at-`open()`-time access mode -- bit 0 (`0b01`) readable, bit 1 (`0b10`)
/// writable, queried live like `content_id` rather than cached at registration (same reasoning:
/// simpler to let the owning module's own callback answer from its own already-authoritative state
/// than to duplicate it here). Unlike `content_id`, this never actually changes over a fd's
/// lifetime (POSIX has no call that changes an already-open fd's access mode), but the callback
/// shape stays consistent with `content_id`'s own "discriminates by variant itself" convention
/// (`crate::process::mm::do_mmap_file_backed`'s own real POSIX MPR access-mode check, `mmap/6-4.c`/
/// `6-6.c`). The default (`default_access_mode` below, readable+writable) is correct for every fd
/// kind except `modules/oxfs`'s own file-backed `OpenFile` variants -- every other kind (pipes,
/// sockets, mqueues, devices) never reaches `do_mmap_file_backed`'s check at all, since
/// `content_id_of` already returns `None`/`ENODEV` for them first.
pub(crate) type FdAccessMode = extern "C" fn(u64) -> i64;

extern "C" fn default_access_mode(_real_fd: u64) -> i64 {
    0b11
}

/// A fd's real, fixed-at-`open()`-time `O_APPEND` bit -- queried live like `content_id`/
/// `access_mode` rather than cached here, same reasoning as both (the owning module already has
/// to remember this for its own write-positioning logic, see `modules/oxfs`'s `OpenFile::Write::
/// append`). Unlike `O_NONBLOCK` (which `fcntl(F_SETFL, ...)` can flip after the fact, hence its
/// own separate mutable `NONBLOCKING` set below), POSIX gives `O_APPEND` no such setter here (this
/// port's `F_SETFL` only ever touches `O_NONBLOCK`), so a fixed-at-open callback is sufficient.
///
/// Found live via the Open POSIX Test Suite's `aio_write/2-1.c`: `sys_fcntl`'s `F_GETFL` used to
/// report only `O_NONBLOCK`, never `O_APPEND` -- real, unmodified musl's own AIO implementation
/// (`third_party/musl/src/aio/aio.c`) queries exactly this bit once per fd (`q->append =
/// !seekable || (fcntl(fd, F_GETFL) & O_APPEND)`) to decide whether a queued `aio_write()` must
/// serialize behind any other still-in-flight write to the same fd. A false negative here made
/// every `O_APPEND`-opened aio fd look non-appending, which (a) let musl skip that ordering wait
/// entirely and (b) made it call `pwrite(fd, buf, len, aio_offset)` instead of `write(fd, buf,
/// len)` -- and since this suite's own `aiocb`s are `memset` to all-zero, every one of the three
/// concurrent writes landed at the *same* offset `0`, each fully overwriting the last (confirmed
/// live: the final file held only the last-completing write's own content). The default
/// (`default_is_append` below, `false`) is correct for every fd kind except `modules/oxfs`'s own
/// file-backed `OpenFile::Write` variant opened with `O_APPEND` -- every other kind (pipes,
/// sockets, mqueues, devices, and a `Write` fd opened without `O_APPEND`) has no real append
/// semantics to report.
pub(crate) type FdIsAppend = extern "C" fn(u64) -> i64;

extern "C" fn default_is_append(_real_fd: u64) -> i64 {
    0
}

/// Real framebuffer geometry query -- see `crate::drivers::fbdev::FbGeometry`'s own doc comment
/// for the wire shape and `process::mm::do_mmap_fb`'s own doc comment for the one real consumer.
/// `(real_fd, out_ptr_as_u64) -> i32` (`0` = wrote a real `FbGeometry` through `out_ptr`, `-1` =
/// not a framebuffer fd) -- same "plain `u64`s at the module FFI boundary, discriminate inside"
/// shape `FdContentId`/`FdAccessMode` already establish. Optional per fd kind (defaults to
/// `no_fb_geometry` below) -- only `modules/oxfs`'s own `OpenFile::Framebuffer` fds ever register
/// a real one.
pub(crate) type FdFbGeometry = extern "C" fn(u64, u64) -> i32;

extern "C" fn no_fb_geometry(_real_fd: u64, _out: u64) -> i32 {
    -1
}

#[derive(Clone, Copy)]
struct FdOps {
    read: FdReadWrite,
    write: FdReadWrite,
    close: FdClose,
    content_id: FdContentId,
    access_mode: FdAccessMode,
    is_append: FdIsAppend,
    fb_geometry: FdFbGeometry,
    pread: FdReadWriteAt,
    pwrite: FdReadWriteAt,
    /// The fd this entry's callbacks are actually invoked with — itself for a fresh registration,
    /// or another entry's own `real_fd` for a `dup2`/`fork_inherit`-created alias (see this file's
    /// module doc comment). Chains never nest more than one level deep in practice, but every alias
    /// is built by copying the *source* entry's already-resolved `real_fd`, not the source's own
    /// `(pid, fd)`, so an alias-of-an-alias still resolves directly rather than accumulating a
    /// chain.
    real_fd: u64,
}

/// A pseudo-pid, never a real running process (`process::alloc_pid` starts at `1`) — the identity
/// `init` registers fd 0/1/2 under, so `process::spawn` can bootstrap every real process's own
/// stdin/stdout/stderr via the exact same `fork_inherit` path a real `fork()` uses, rather than a
/// separate one-off "seed the new process's fds" routine.
const BOOTSTRAP_PID: u64 = 0;

/// 0/1/2 reserved for stdin/stdout/stderr, registered by `init` below — never handed out by
/// `oxidebsd_alloc_fd`.
static NEXT_FD: Mutex<u64> = Mutex::new(3);
static TABLE: Mutex<BTreeMap<(u64, u64), FdOps>> = Mutex::new(BTreeMap::new());
/// Keyed by `real_fd` (a global identity, not a `(pid, fd)` pair) — how many live `TABLE` entries,
/// across *every* process that has one, currently resolve to this underlying resource. See this
/// file's module doc comment.
static REFCOUNTS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());
/// `O_NONBLOCK`, as set via `fcntl(F_SETFL, ...)` (`syscall::sys_fcntl`). Keyed by `real_fd`, the
/// same "open file description" scoping `REFCOUNTS` already uses -- POSIX defines `O_NONBLOCK` as
/// a property of the *description*, shared correctly across `dup`/`dup2`/`fork_inherit` aliases,
/// not the individual `(pid, fd)` handle, which is why this isn't a field on `FdOps` itself. Only
/// `src/pipe.rs`'s `blocking_read` actually consults this today -- a real, deliberate
/// simplification, not every blocking read path in this kernel honors it yet (see that module's
/// own doc comment). Never cleaned up on close, consistent with this file's own fd-number/refcount
/// convention of never reusing/reclaiming identities.
static NONBLOCKING: Mutex<BTreeSet<u64>> = Mutex::new(BTreeSet::new());

pub(crate) fn set_nonblocking(real_fd: u64, on: bool) {
    if on {
        NONBLOCKING.lock().insert(real_fd);
    } else {
        NONBLOCKING.lock().remove(&real_fd);
    }
}

pub(crate) fn is_nonblocking(real_fd: u64) -> bool {
    NONBLOCKING.lock().contains(&real_fd)
}

/// Real per-`(pid, fd)` `FD_CLOEXEC` state -- unlike `NONBLOCKING` above, POSIX defines this as a
/// property of the file descriptor itself, not the underlying open file description, so it's keyed
/// by the same `(pid, fd)` pair `TABLE` uses (found live via `shm_open/11-1.c`, the Open POSIX Test
/// Suite pilot: musl's own `shm_open()` always passes real `O_CLOEXEC` to `open()`, and the test
/// reads it back via `fcntl(fd, F_GETFD)`). Set by `modules/oxfs`'s own `open()` path when the
/// caller's real `O_CLOEXEC` flag is present, or by `fcntl(F_SETFD, FD_CLOEXEC)`
/// (`syscall::sys_fcntl`); `dup`/`dup2` deliberately do *not* copy it to the new `(pid, fd)` entry
/// (real POSIX: only `F_DUPFD_CLOEXEC`/`dup3(..., O_CLOEXEC)` would, and this kernel's own
/// `F_DUPFD_CLOEXEC` handling sets it explicitly afterward rather than inheriting it here) --
/// `fork_inherit` does copy it (real `fork()` preserves each fd's own close-on-exec flag into the
/// child). Never cleaned up on close, same "identities aren't reclaimed" convention `NONBLOCKING`
/// already documents.
static CLOEXEC: Mutex<BTreeSet<(u64, u64)>> = Mutex::new(BTreeSet::new());

pub(crate) fn set_cloexec(pid: u64, fd: u64, on: bool) {
    if on {
        CLOEXEC.lock().insert((pid, fd));
    } else {
        CLOEXEC.lock().remove(&(pid, fd));
    }
}

pub(crate) fn is_cloexec(pid: u64, fd: u64) -> bool {
    CLOEXEC.lock().contains(&(pid, fd))
}

/// Sets `FD_CLOEXEC` on `fd` in the *current* process's own table -- exported to modules (see
/// `src/module.rs`'s kernel API table), since `set_cloexec` above needs the caller's real pid,
/// which modules can't resolve themselves (only the kernel exports `scheduler::current_pid`
/// indirectly, through functions like this one). `modules/oxfs`'s own `oxfs_open` is the one real
/// caller today, right after a successful real `O_CLOEXEC` open.
pub(crate) extern "C" fn oxidebsd_set_fd_cloexec(fd: u64, on: u64) -> i64 {
    set_cloexec(scheduler::current_tgid(), fd, on != 0);
    0
}

/// Real `execve()` close-on-exec enforcement -- closes every fd this process has marked
/// `FD_CLOEXEC`, real Unix semantics ("file descriptors open... which are marked
/// close-on-exec... shall be closed"). Called from `process::do_execve`, right after the new
/// program image is committed (fds live in this file's own table, entirely independent of the
/// address space `do_execve` otherwise replaces, so this is a genuinely separate step, not
/// something that happens automatically). Not previously implemented at all -- `F_SETFD` used to
/// be a pure no-op (see `syscall::sys_fcntl`'s own doc comment), so there was nothing to enforce.
pub(crate) fn close_cloexec(pid: u64) {
    let fds: alloc::vec::Vec<u64> = CLOEXEC
        .lock()
        .iter()
        .filter(|&&(p, _)| p == pid)
        .map(|&(_, fd)| fd)
        .collect();
    for fd in fds {
        close_one(pid, fd);
        CLOEXEC.lock().remove(&(pid, fd));
    }
}

pub(crate) extern "C" fn oxidebsd_alloc_fd() -> u64 {
    let mut next = NEXT_FD.lock();
    let fd = *next;
    *next += 1;
    fd
}

pub(crate) extern "C" fn oxidebsd_register_fd_ops(
    fd: u64,
    read: FdReadWrite,
    write: FdReadWrite,
    close: FdClose,
) -> i32 {
    register(scheduler::current_tgid(), fd, read, write, close, no_content_id);
    0
}

/// Same as `oxidebsd_register_fd_ops`, plus a `content_id` callback — only `modules/oxfs` calls
/// this (for its own file-backed `OpenFile` variants; its synthetic ones still pass `no_content_id`
/// via the plain function above), so every other fd-registering module (pipes, sockets, mqueues,
/// ...) needed zero changes. See `FdContentId`'s own doc comment for why this exists.
pub(crate) extern "C" fn oxidebsd_register_fd_ops_with_content_id(
    fd: u64,
    read: FdReadWrite,
    write: FdReadWrite,
    close: FdClose,
    content_id: FdContentId,
) -> i32 {
    register(scheduler::current_tgid(), fd, read, write, close, content_id);
    0
}

/// The non-`extern "C"` body every registration entry point (`oxidebsd_register_fd_ops`,
/// `oxidebsd_register_fd_ops_with_content_id`, `init`'s stdin/stdout/stderr) shares.
fn register(
    pid: u64,
    fd: u64,
    read: FdReadWrite,
    write: FdReadWrite,
    close: FdClose,
    content_id: FdContentId,
) {
    TABLE.lock().insert(
        (pid, fd),
        FdOps {
            read,
            write,
            close,
            content_id,
            access_mode: default_access_mode,
            is_append: default_is_append,
            fb_geometry: no_fb_geometry,
            pread: no_pread_pwrite,
            pwrite: no_pread_pwrite,
            real_fd: fd,
        },
    );
    *REFCOUNTS.lock().entry(fd).or_insert(0) += 1;
}

/// Overrides `real_fd`'s `access_mode` callback after the fact -- same "separate post-hoc setter,
/// not a `register`/`oxidebsd_register_fd_ops*` parameter" shape `oxidebsd_set_fd_pread_pwrite`
/// already establishes, for the identical reason: every existing fd-registering call site keeps the
/// `default_access_mode` `register` already sets. `modules/oxfs` is the one real caller today.
pub(crate) extern "C" fn oxidebsd_set_fd_access_mode(fd: u64, access_mode: FdAccessMode) {
    if let Some(ops) = TABLE.lock().get_mut(&(scheduler::current_tgid(), fd)) {
        ops.access_mode = access_mode;
    }
}

/// Overrides `real_fd`'s `is_append` callback after the fact -- same shape
/// `oxidebsd_set_fd_access_mode` already establishes. `modules/oxfs` is the one real caller,
/// unconditionally for every `OpenFile::Write` fd it registers (the callback itself discriminates
/// by whether that fd was actually opened with `O_APPEND`, same "always registered, harmless
/// default for everything else" precedent `oxidebsd_set_fd_access_mode`'s own call site sets).
pub(crate) extern "C" fn oxidebsd_set_fd_append(fd: u64, is_append: FdIsAppend) {
    if let Some(ops) = TABLE.lock().get_mut(&(scheduler::current_tgid(), fd)) {
        ops.is_append = is_append;
    }
}

/// Overrides `real_fd`'s `fb_geometry` callback after the fact -- same shape
/// `oxidebsd_set_fd_access_mode` already establishes. `modules/oxfs` is the one real caller,
/// unconditionally for every fd it registers (the callback itself discriminates by `OpenFile`
/// variant, same "always registered, harmless default for everything else" precedent
/// `oxidebsd_set_fd_access_mode`'s own call site already sets).
pub(crate) extern "C" fn oxidebsd_set_fd_fb_geometry(fd: u64, fb_geometry: FdFbGeometry) {
    if let Some(ops) = TABLE.lock().get_mut(&(scheduler::current_tgid(), fd)) {
        ops.fb_geometry = fb_geometry;
    }
}

/// Overrides `real_fd`'s `pread`/`pwrite` callbacks after the fact — a separate setter, not a
/// parameter on `register`/`oxidebsd_register_fd_ops*`, so every existing fd-registering call site
/// (pipes, sockets, mqueues, ttys, ...) needed zero changes; they keep the `no_pread_pwrite`
/// default `register` already sets. Exported to modules (`crate::module`'s kernel API table) as
/// `oxidebsd_set_fd_pread_pwrite` — `modules/oxfs` is the one real caller today, right after
/// `register_open_file` for its own real, on-disk-backed `OpenFile` variants.
pub(crate) extern "C" fn oxidebsd_set_fd_pread_pwrite(
    fd: u64,
    pread: FdReadWriteAt,
    pwrite: FdReadWriteAt,
) {
    if let Some(ops) = TABLE.lock().get_mut(&(scheduler::current_tgid(), fd)) {
        ops.pread = pread;
        ops.pwrite = pwrite;
    }
}

/// Removes the calling process's own `fd` from the registry; only actually invokes the underlying
/// resource's `close` callback once its refcount (shared across every alias, in every process,
/// created by `dup2`/`fork_inherit`) reaches zero — see this file's module doc comment. `0` on
/// success, `-1` if the calling process has no such `fd` registered at all.
///
/// `pub`, not `pub(crate)` -- same "kept public for test use" precedent `syscall::
/// oxidebsd_sys_read`/`oxidebsd_sys_write` already have; `tests/socketpair_smoke.rs` calls this
/// directly to exercise EOF/EPIPE-on-close without loading a real close-registering module
/// (`modules/oxfs`'s `SYS_CLOSE` handler is the only other caller).
pub extern "C" fn oxidebsd_close_fd(fd: u64) -> i32 {
    if close_one(scheduler::current_tgid(), fd) {
        0
    } else {
        -1
    }
}

/// Shared by `oxidebsd_close_fd` and `close_all` — closes exactly one `(pid, fd)` entry. Returns
/// `false` if there was no such entry (not registered, or already closed).
fn close_one(pid: u64, fd: u64) -> bool {
    let Some(ops) = TABLE.lock().remove(&(pid, fd)) else {
        return false;
    };
    let mut refcounts = REFCOUNTS.lock();
    let count = refcounts.get_mut(&ops.real_fd).expect(
        "fd registry: real_fd missing from REFCOUNTS -- every TABLE entry must have one, \
         maintained by register/dup2/fork_inherit",
    );
    *count -= 1;
    if *count == 0 {
        refcounts.remove(&ops.real_fd);
        drop(refcounts); // don't hold the lock across the callback
        (ops.close)(ops.real_fd);
    }
    true
}

/// Closes every fd the given process still has open — real `exit()` semantics ("all of the
/// descriptors open in the calling process are closed"), not previously implemented at all (the
/// old flat, unscoped table had no notion of "this process's own fds" to close in the first
/// place). Genuinely load-bearing now, not just tidiness: a pipe's reader blocks until it sees the
/// write end's refcount reach zero (`src/pipe.rs`) — if an exiting writer process leaked its own
/// copy of that fd instead of it being closed automatically, the reader would block forever, since
/// nothing else would ever bring the refcount down. Called from `process::do_exit`.
pub(crate) fn close_all(pid: u64) {
    let fds: alloc::vec::Vec<u64> = TABLE
        .lock()
        .keys()
        .filter(|&&(p, _)| p == pid)
        .map(|&(_, fd)| fd)
        .collect();
    for fd in fds {
        close_one(pid, fd);
    }
}

/// Copies every fd the given `parent` pid currently has open into `child`'s own, freshly-forking
/// process — real `fork()` semantics (the child gets its own independently-closable reference to
/// each of the parent's open files, not a shared view of the parent's own table slots). Also used
/// by `process::spawn` to bootstrap a brand-new process's stdin/stdout/stderr from the pseudo-pid
/// `init` registered them under (see this file's module doc comment) — spawning is "inheriting from
/// the boot-time bootstrap identity" in exactly the same sense forking is "inheriting from a real
/// parent," so this one function serves both.
pub(crate) fn fork_inherit(parent: u64, child: u64) {
    let parent_entries: alloc::vec::Vec<(u64, FdOps)> = TABLE
        .lock()
        .iter()
        .filter(|&(&(p, _), _)| p == parent)
        .map(|(&(_, fd), &ops)| (fd, ops))
        .collect();
    let mut table = TABLE.lock();
    let mut refcounts = REFCOUNTS.lock();
    for (fd, ops) in parent_entries {
        table.insert((child, fd), ops);
        *refcounts.entry(ops.real_fd).or_insert(0) += 1;
        // Real fork() preserves each fd's own close-on-exec flag into the child -- see CLOEXEC's
        // own doc comment for why this is a per-(pid, fd) copy, not shared state.
        if is_cloexec(parent, fd) {
            set_cloexec(child, fd, true);
        }
    }
}

/// `SYS_DUP2`'s real logic (`src/syscall.rs`'s `sys_dup2` is a thin wrapper over this), scoped to
/// the calling process's own fds — real `dup2` is always within one process. `newfd == oldfd` is a
/// no-op *if* `oldfd` is actually open (matching real `dup2`'s own documented special case);
/// otherwise whatever `newfd` previously referred to is closed first (through the same
/// refcount-aware path `oxidebsd_close_fd` uses, so an in-use underlying resource survives if
/// another alias — in this process or any other — still references it), then `newfd` becomes a
/// fresh alias of `oldfd`'s own `real_fd`.
pub(crate) fn dup2(oldfd: u64, newfd: u64) -> Result<u64, ()> {
    let pid = scheduler::current_tgid();
    if oldfd == newfd {
        return if TABLE.lock().contains_key(&(pid, oldfd)) {
            Ok(newfd)
        } else {
            Err(())
        };
    }
    let old_ops = *TABLE.lock().get(&(pid, oldfd)).ok_or(())?;
    if TABLE.lock().contains_key(&(pid, newfd)) {
        close_one(pid, newfd);
    }
    TABLE.lock().insert(
        (pid, newfd),
        FdOps {
            real_fd: old_ops.real_fd,
            ..old_ops
        },
    );
    *REFCOUNTS.lock().entry(old_ops.real_fd).or_insert(0) += 1;
    Ok(newfd)
}

/// `SYS_DUP`'s real logic (`src/syscall.rs`'s `sys_dup` is a thin wrapper over this) — real
/// `dup(2)`'s single-argument form: allocate a fresh fd (via the same bump counter
/// `oxidebsd_alloc_fd` uses) and alias it to `oldfd`'s own `real_fd`, same aliasing mechanics as
/// `dup2` above minus the caller-chosen-target-fd/close-first cases `dup2` has to handle. Added
/// specifically because BusyBox's `hush` (`CONFIG_HUSH_JOB`) calls `dup_CLOEXEC`, which tries
/// `fcntl(fd, F_DUPFD_CLOEXEC, ...)` first — this kernel has no `fcntl` at all, so that call
/// harmlessly `ENOSYS`s — and only then falls back to plain `dup(fd)`; without this, hush's own
/// `G_interactive_fd` setup gives up entirely and silently treats itself as non-interactive, the
/// exact thing turning on real interactive mode was for. See CLAUDE.md's "Interactive shell"
/// section for the full trace of why `fcntl` itself doesn't need implementing for this to work.
pub(crate) fn dup(oldfd: u64) -> Result<u64, ()> {
    let pid = scheduler::current_tgid();
    let old_ops = *TABLE.lock().get(&(pid, oldfd)).ok_or(())?;
    let newfd = oxidebsd_alloc_fd();
    TABLE.lock().insert(
        (pid, newfd),
        FdOps {
            real_fd: old_ops.real_fd,
            ..old_ops
        },
    );
    *REFCOUNTS.lock().entry(old_ops.real_fd).or_insert(0) += 1;
    Ok(newfd)
}

/// Looks the calling process's own `fd` up and, if registered, calls its read callback (with
/// `real_fd`, not `fd` — see this file's module doc comment). `None` (not any particular error
/// value) means the calling process has no such `fd` registered — `syscall::sys_read` treats that
/// as `EBADF`.
/// `len == 0` short-circuits *before* reaching any registered callback, for every fd alike — a
/// real, previously-latent bug, found only by running BusyBox's `hush` as pid 1 long enough for
/// its own stdio layer to flush an empty buffer: real `write(fd, buf, 0)`/`read(fd, buf, 0)` is
/// POSIX-guaranteed not to touch `buf` at all and to return `0` immediately, regardless of whether
/// `buf` is even a valid pointer — musl's own stdio does call `write()` this way (an `fflush()` on
/// an empty buffer, seen in practice as `write(1, NULL, 0)`). Every registered callback
/// (`stdin_read`, `stdout_write`, `modules/oxfs`'s file read/write, `src/pipe.rs`'s pipe ends) used
/// to construct a slice via `core::slice::from_raw_parts(_mut)` unconditionally, which Rust's own
/// safety contract requires a non-null, aligned pointer for even at length `0` — a real, not just
/// theoretical, panic once a null pointer actually reached one. Guarding once here, centrally,
/// covers every one of them without touching each callback individually, since `sys_read`/
/// `sys_write` (`src/syscall.rs`) route every fd through these two functions unconditionally.
pub(crate) fn read(fd: u64, ptr: u64, len: u64) -> Option<i64> {
    let ops = *TABLE.lock().get(&(scheduler::current_tgid(), fd))?;
    if len == 0 {
        return Some(0);
    }
    Some((ops.read)(ops.real_fd, ptr, len))
}

pub(crate) fn write(fd: u64, ptr: u64, len: u64) -> Option<i64> {
    let ops = *TABLE.lock().get(&(scheduler::current_tgid(), fd))?;
    if len == 0 {
        return Some(0);
    }
    Some((ops.write)(ops.real_fd, ptr, len))
}

/// Real `pread(2)` — like `read` above, but never touches the fd's own current file position (real
/// POSIX: `pread`/`pwrite` are independent of, and don't affect, `lseek`'s own cursor). `None` if
/// `fd` isn't registered at all (`EBADF`, matching `read`/`write`'s own convention); `-ESPIPE` (via
/// `no_pread_pwrite`) for any fd kind with no real seekable position.
pub(crate) fn pread(fd: u64, ptr: u64, len: u64, offset: u64) -> Option<i64> {
    let ops = *TABLE.lock().get(&(scheduler::current_tgid(), fd))?;
    if len == 0 {
        return Some(0);
    }
    Some((ops.pread)(ops.real_fd, ptr, len, offset))
}

/// Real `pwrite(2)` — see `pread`'s own doc comment just above.
pub(crate) fn pwrite(fd: u64, ptr: u64, len: u64, offset: u64) -> Option<i64> {
    let ops = *TABLE.lock().get(&(scheduler::current_tgid(), fd))?;
    if len == 0 {
        return Some(0);
    }
    Some((ops.pwrite)(ops.real_fd, ptr, len, offset))
}

/// Looks up the calling process's own `fd` and returns its `real_fd` — the underlying resource
/// identity a `dup2`/`fork_inherit` alias ultimately resolves to (see this file's module doc
/// comment), not necessarily `fd` itself. `None` if the calling process has no such `fd`
/// registered. Used by `syscall::sys_ioctl` to answer "is this fd actually the console" correctly
/// even after `dup2` — checking `fd == 0/1/2` directly would be wrong, since a shell can `dup2` a
/// pipe end onto fd 0/1 (real pipelines already do exactly this), and a program can just as
/// legitimately `dup2` its real stdout onto some other fd number.
pub(crate) fn real_fd_of(fd: u64) -> Option<u64> {
    TABLE
        .lock()
        .get(&(scheduler::current_tgid(), fd))
        .map(|ops| ops.real_fd)
}

/// Live "is this fd backed by an identifiable real file, and if so which one" query — see
/// `FdContentId`'s own doc comment for why this calls the registered callback fresh every time
/// rather than reading a value cached at registration. Used by `crate::process::mm::do_mmap` to
/// decide whether a real fd-backed `MAP_SHARED` mapping is even possible, and to key its own
/// cross-open shared-frame cache. `None` covers both "no such fd" and "not identifiable right now."
pub(crate) fn content_id_of(fd: u64) -> Option<u64> {
    let ops = *TABLE.lock().get(&(scheduler::current_tgid(), fd))?;
    let id = (ops.content_id)(ops.real_fd);
    if id < 0 { None } else { Some(id as u64) }
}

/// `(readable, writable)`, per `FdAccessMode`'s own doc comment. `(true, true)` for a fd not found
/// in `TABLE` at all -- inert in practice, since `crate::process::mm::do_mmap_file_backed`'s own
/// caller (`do_mmap`) always calls `content_id_of` first and bails `ENODEV` before this could ever
/// matter for an unregistered fd.
pub(crate) fn access_mode_of(fd: u64) -> (bool, bool) {
    let Some(ops) = TABLE.lock().get(&(scheduler::current_tgid(), fd)).copied() else {
        return (true, true);
    };
    let bits = (ops.access_mode)(ops.real_fd);
    (bits & 0b01 != 0, bits & 0b10 != 0)
}

/// Real, fixed-at-`open()`-time `O_APPEND` state, per `FdIsAppend`'s own doc comment. Used by
/// `syscall::sys_fcntl`'s `F_GETFL` arm to report this bit back correctly -- `false` for a fd not
/// found in `TABLE` at all, matching `F_GETFL`'s existing `EBADF`-before-ever-reaching-this
/// resolution (`real_fd_of` already fails first for that case).
pub(crate) fn is_append_of(fd: u64) -> bool {
    let Some(ops) = TABLE.lock().get(&(scheduler::current_tgid(), fd)).copied() else {
        return false;
    };
    (ops.is_append)(ops.real_fd) != 0
}

/// Live "is this fd a real `/dev/fb0` mapping-eligible framebuffer, and if so what's its real
/// geometry" query -- see `FdFbGeometry`'s own doc comment. `None` covers both "no such fd" and
/// "not a framebuffer fd." Used by `crate::process::mm::do_mmap` (checked *before* `content_id_of`
/// -- a framebuffer fd's `content_id_of` always returns `None`/`ENODEV` too, so order matters) and
/// by `syscall::ffi::sys_ioctl`'s framebuffer-info request.
pub(crate) fn framebuffer_geometry_of(fd: u64) -> Option<crate::drivers::fbdev::FbGeometry> {
    let ops = *TABLE.lock().get(&(scheduler::current_tgid(), fd))?;
    let mut geom = crate::drivers::fbdev::FbGeometry {
        phys_base: 0,
        len: 0,
        width: 0,
        height: 0,
        pitch: 0,
        bpp: 0,
    };
    let ok = (ops.fb_geometry)(ops.real_fd, &mut geom as *mut crate::drivers::fbdev::FbGeometry as u64);
    if ok == 0 { Some(geom) } else { None }
}

/// Real fd-backed `MAP_SHARED` mmap (`crate::process::mm`) reads/writes content *directly* by
/// `content_id` (a real inode number), not through a fd's own read/write callbacks — found live,
/// not designed in up front: `modules/oxfs`'s `oxfs_read` unconditionally fails (`-EBADF`) for a
/// fd still in `OpenFile::Write` state, which is exactly the state every real caller's fd is still
/// in at `mmap()` time (`open(O_CREAT|O_RDWR) -> ftruncate()/fstat() -> mmap()`, never `close()`d
/// first) — so a population/writeback path built on the generic per-fd `read`/`write` callbacks
/// could never actually read or write real content for any of them. Content-by-identity sidesteps
/// this entirely (and, as a bonus, needs no positioned/`pread`-style read either, and gives
/// writeback a real, queryable object length to clamp against — see `crate::process::mm::
/// do_mmap_file_backed`'s own doc comment for why that clamp matters). A **global** registration,
/// not per-fd like `FdOps` — `content_id` is a stable identity independent of which fd (if any) is
/// currently open against it, so there's nothing to key a per-fd table by. Only `modules/oxfs`
/// calls this (once, from its own `module_init`); every other fd-registering module is unaffected.
pub(crate) type ContentRead = extern "C" fn(u64, u64, u64, u64) -> i64;
pub(crate) type ContentWrite = extern "C" fn(u64, u64, u64) -> i64;
pub(crate) type ContentSize = extern "C" fn(u64) -> i64;

static CONTENT_ACCESSORS: Mutex<Option<(ContentRead, ContentWrite, ContentSize)>> =
    Mutex::new(None);

pub(crate) extern "C" fn oxidebsd_register_content_accessors(
    read: ContentRead,
    write: ContentWrite,
    size: ContentSize,
) {
    *CONTENT_ACCESSORS.lock() = Some((read, write, size));
}

/// `(content_id, offset, ptr, len) -> bytes read`, `-1` if no module ever registered content
/// accessors (never happens once `modules/oxfs` has loaded, which it always has by the time any
/// real syscall is reachable).
pub(crate) fn content_read(content_id: u64, offset: u64, ptr: u64, len: u64) -> i64 {
    match *CONTENT_ACCESSORS.lock() {
        Some((read, _, _)) => read(content_id, offset, ptr, len),
        None => -1,
    }
}

/// `(content_id, ptr, len) -> bytes written` — always replaces the object's complete content with
/// exactly `len` bytes, matching `modules/oxfs`'s own one-shot write model (see that module's
/// `OpenFile::Write` doc comment).
pub(crate) fn content_write(content_id: u64, ptr: u64, len: u64) -> i64 {
    match *CONTENT_ACCESSORS.lock() {
        Some((_, write, _)) => write(content_id, ptr, len),
        None => -1,
    }
}

/// Real current content length of `content_id`, in bytes.
pub(crate) fn content_size(content_id: u64) -> i64 {
    match *CONTENT_ACCESSORS.lock() {
        Some((_, _, size)) => size(content_id),
        None => -1,
    }
}

/// FFI wrapper over `real_fd_of` for modules that own their own fd-keyed state (`modules/oxfs`'s
/// `OPEN_FILES`, keyed by `real_fd` like every `FdOps` callback already is) but can't call
/// `crate::fd` directly -- modules only ever call *into* the kernel, through their own hand-curated
/// symbol table (see `src/module.rs`). `SYS_FSTAT`'s handler is the first case that needs this:
/// unlike `SYS_READ`/`SYS_WRITE`, which this file's own `read`/`write` already resolve fd -> real_fd
/// for before invoking a callback, a syscall-number-registered handler (`oxfs_fstat`) receives the
/// caller's raw `fd` argument directly and has to do that resolution itself. Returns `-1` (never a
/// valid `real_fd`, which starts at `3`) for an fd the calling process doesn't have open, rather than
/// `Option`, to stay in this codebase's plain-`i64`-FFI-boundary convention (see `SyscallHandler`'s
/// own doc comment in `src/syscall.rs`).
pub(crate) extern "C" fn oxidebsd_real_fd_of(fd: u64) -> i64 {
    match real_fd_of(fd) {
        Some(real_fd) => real_fd as i64,
        None => -1,
    }
}

/// The `index`-th fd number (this *process's own* numbering, not `real_fd`) currently open for
/// `pid`, ascending, `-1` once `index` is past the end -- mirrors `process::oxidebsd_proc_pid_at`'s
/// identical "loop until -1" shape, for `modules/oxfs`'s own `/proc/<pid>/fd/` directory listing.
/// `TABLE`'s key is `(tgid, fd)`, not `(pid, fd)`, since real `CLONE_FILES` threads share one fd
/// table -- `pid` here is an arbitrary real Linux-style target from a `/proc/<pid>/fd/` path, not
/// necessarily the calling thread's own, so it's resolved to its owning thread group's `tgid`
/// first (same lookup `scheduler::current_tgid()` does for the *calling* process, just against an
/// arbitrary target instead). A plain tuple `Ord` (lexicographic: `tgid` first, `fd` second), so a
/// bounded range scan over just that `tgid`'s own slice is enough -- no separate per-pid index
/// needed.
pub(crate) extern "C" fn oxidebsd_fd_at(pid: u64, index: u64) -> i64 {
    let tgid = crate::process::table()
        .lock()
        .get(&pid)
        .map(|p| p.tgid)
        .unwrap_or(pid);
    TABLE
        .lock()
        .range((tgid, 0)..(tgid.saturating_add(1), 0))
        .nth(index as usize)
        .map(|(&(_, fd), _)| fd as i64)
        .unwrap_or(-1)
}

extern "C" fn stdin_read(_real_fd: u64, ptr: u64, len: u64) -> i64 {
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has -- [ptr, ptr+len) isn't checked against the caller's actual mappings first.
    // len == 0 is already handled by this file's own read() above, never reaching here.
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
    crate::console::stdin::read(buf) as i64
}

extern "C" fn write_not_permitted(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -(EBADF as i64)
}

extern "C" fn read_not_permitted(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -(EBADF as i64)
}

/// Shared by fd 1 (stdout) and, via `dup2`-style aliasing, fd 2 (stderr) — see this file's module
/// doc comment for why stderr isn't a genuinely separate destination.
extern "C" fn stdout_write(_real_fd: u64, ptr: u64, len: u64) -> i64 {
    // SAFETY: same known pointer-validation gap sys_read/sys_write already document.
    // len == 0 is already handled by this file's own write() above, never reaching here.
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    match core::str::from_utf8(bytes) {
        Ok(s) => {
            crate::serial_print!("{s}");
            len as i64
        }
        Err(_) => -(crate::syscall::EINVAL as i64),
    }
}

extern "C" fn stdio_close(_real_fd: u64) -> i64 {
    0
}

/// Registers fd 0/1/2 under `BOOTSTRAP_PID` — called once at boot (`src/main.rs`, before any
/// process is spawned). `process::spawn` (used both for `stsh`, pid 1, and any later
/// non-`fork`-based process creation) calls `fork_inherit(BOOTSTRAP_PID, new_pid)` right after
/// creating each new process, giving it its own independent stdin/stdout/stderr the exact same way
/// a real `fork()`ed child inherits its parent's — see this file's module doc comment. fd 2 is a
/// `dup2`-style alias of fd 1 from the moment it's created, not a second independent registration —
/// matching real shell convention (`2>&1` is normally already true by default in practice) and
/// this kernel's own total lack of a second output destination.
pub fn init() {
    register(
        BOOTSTRAP_PID,
        0,
        stdin_read,
        write_not_permitted,
        stdio_close,
        no_content_id,
    );
    register(
        BOOTSTRAP_PID,
        1,
        read_not_permitted,
        stdout_write,
        stdio_close,
        no_content_id,
    );
    TABLE.lock().insert(
        (BOOTSTRAP_PID, 2),
        FdOps {
            read: read_not_permitted,
            write: stdout_write,
            close: stdio_close,
            content_id: no_content_id,
            access_mode: default_access_mode,
            is_append: default_is_append,
            fb_geometry: no_fb_geometry,
            pread: no_pread_pwrite,
            pwrite: no_pread_pwrite,
            real_fd: 1,
        },
    );
    *REFCOUNTS.lock().entry(1).or_insert(0) += 1;
}
