//! A minimal kernel-owned file-descriptor registry — the only channel two independently loaded
//! modules have to coordinate with each other, since modules can only ever call *into* the
//! kernel, never directly into another module (see `sys/module.rs`'s doc comment). Concretely:
//! `modules/fat32/`'s open files register their read/write/close callbacks here; `sys/syscall.rs`'s
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
//! **Two tables, like a real Unix kernel's descriptor table and file table.** `TABLE` maps a
//! process's own fd number to a `real_fd`; `DESCRIPTIONS` maps a `real_fd` (one open file
//! description, shared by every `dup`/`fork` alias) to its callbacks and refcount. fd numbers are
//! per process and always the lowest free one, as POSIX requires of `open`/`pipe`/`socket`/`dup`/
//! `accept`. `real_fd`s come from a global bump counter and are never reused, so a module's own
//! `real_fd`-keyed state can never be confused with a later, unrelated open.
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
//! the registered callback with `real_fd`, never the `(pid, fd)` that was actually looked up.
//! `DESCRIPTIONS`' refcount (keyed by `real_fd`, shared across every process that has an alias of it, not per
//! `(pid, fd)`) ensures the underlying resource's own `close` callback only actually fires once
//! every alias — across every process that ever had one — has been closed.

use alloc::collections::{BTreeMap, BTreeSet};

use spin::Mutex;

use crate::process::scheduler;
use crate::kern::subr_uio::{FOF_OFFSET, Uio};
use crate::syscall::{EAGAIN, EINTR, ESPIPE};
use crate::tty::ERESTART;

/// Matches `syscall::SyscallHandler`'s own FFI convention (negative = `-errno`, non-negative =
/// success value) for the same reason — see that type's doc comment. Kept as a separate type
/// here (rather than reusing `SyscallHandler` directly) since the two represent conceptually
/// different things — syscall-number dispatch vs. per-fd operations — even though their shapes
/// happen to coincide.
///
/// `read`/`write`: `(real_fd, uio, flags)` (USERMEM.md §4.4). The backend moves data with
/// `uiomove` (`kern::subr_uio`) and returns the count transferred; `flags & FOF_OFFSET` asks for
/// the uio's offset instead of the description's own position (`pread`/`pwrite`), which a
/// backend with no position fails with `ESPIPE`. Modules receive the uio as an opaque pointer.
pub(crate) type FdReadWrite = extern "C" fn(u64, *mut Uio, u64) -> i64;
pub(crate) type FdClose = extern "C" fn(u64) -> i64;

/// Real framebuffer geometry query -- see `crate::drivers::fbdev::FbGeometry`'s own doc comment
/// for the wire shape and `process::mm::do_mmap_fb`'s own doc comment for the one real consumer.
/// `(real_fd, out_ptr_as_u64) -> i32` (`0` = wrote a real `FbGeometry` through `out_ptr`, `-1` =
/// not a framebuffer fd) -- same "plain `u64`s at the module FFI boundary, discriminate inside"
/// shape the other operations have. Optional per kind of file -- only `sys/modules/oxfs`'s
/// own `OpenFile::Framebuffer` fds answer it.
pub(crate) type FdFbGeometry = extern "C" fn(u64, u64) -> i32;

/// An open file's operations (FreeBSD's `struct fileops`, OxideBSD-doc `VFS.md` §6.4): one static
/// table per kind of file, shared by every file of that kind, given to `finstall` with the file's
/// own `data`. Every operation gets the file's handle (its `real_fd`), as the old per-descriptor
/// callbacks did, so a backend keeps keying its state by it; `oxidebsd_file_data(handle)` gives
/// the object `finstall` was handed. A null entry takes the kernel's default: `EBADF` for
/// `read`/`write` (the access mode is checked first), nothing for `close`, no mapping for
/// `content_id` and `fb_geometry`. `#[repr(C)]`: modules declare their own copies
/// (`sys/modules/*`), so the field order is part of the module ABI.
#[repr(C)]
pub(crate) struct FileOps {
    /// `DFLAG_*`.
    pub flags: u32,
    pub read: Option<FdReadWrite>,
    pub write: Option<FdReadWrite>,
    pub close: Option<FdClose>,
    /// `(handle, request, arg) -> result | -errno` (`ioctl(2)`, after the kernel's own requests,
    /// `kern::sys_generic`); `ENOTTY` when null. `arg` is the caller's, a user pointer or a value.
    pub ioctl: Option<extern "C" fn(u64, u64, u64) -> i64>,
    /// `(handle, events) -> POLL_*` bits (`poll`, `select`); always readable and writable when null,
    /// as POSIX has regular files.
    pub poll: Option<extern "C" fn(u64, u64) -> i64>,
    /// `(handle, out) -> 0 | -errno` (`fstat(2)`): fills the musl `struct stat` at `out`, a kernel
    /// buffer. When null, `fallback_stat` answers: the vnode the file was opened through
    /// (`f_vnode`), for a FIFO, terminal or device.
    pub stat: Option<extern "C" fn(u64, u64) -> i64>,
    /// `(handle, length) -> 0 | -errno` (`ftruncate(2)`, open for writing); `EINVAL` when null.
    pub truncate: Option<extern "C" fn(u64, u64) -> i64>,
    /// `(handle, data_only) -> 0 | -errno` (`fsync(2)`, `fdatasync(2)`); `EINVAL` when null.
    pub sync: Option<extern "C" fn(u64, u64) -> i64>,
    pub fb_geometry: Option<FdFbGeometry>,
}

impl FileOps {
    /// Every operation the kernel's default, for `..FileOps::NONE` in a type's table.
    pub(crate) const NONE: FileOps = FileOps {
        flags: 0,
        read: None,
        write: None,
        close: None,
        ioctl: None,
        poll: None,
        stat: None,
        truncate: None,
        sync: None,
        fb_geometry: None,
    };
}

/// `FileOps::poll`'s answer: readiness bits, and whether the file can be waited on by blocking
/// (`poll` sleeps until woken) or must be looked at again (`POLL_PULLED`: network sockets, whose
/// packets arrive only when someone polls, and `/dev/klog`).
pub(crate) const POLL_READABLE: i64 = 1;
pub(crate) const POLL_WRITABLE: i64 = 2;
pub(crate) const POLL_HANGUP: i64 = 4;
pub(crate) const POLL_ERROR: i64 = 8;
pub(crate) const POLL_PULLED: i64 = 0x100;

/// `FileOps::poll`'s bits for a `Readiness`.
pub(crate) fn poll_bits(r: crate::fs::Readiness, pulled: bool) -> i64 {
    (r.readable as i64 * POLL_READABLE)
        | (r.writable as i64 * POLL_WRITABLE)
        | (r.hangup as i64 * POLL_HANGUP)
        | (r.error as i64 * POLL_ERROR)
        | (pulled as i64 * POLL_PULLED)
}

/// `FileOps::flags`: the file has an offset (`lseek`, `pread`/`pwrite`), which the kernel keeps:
/// every `read`/`write` reaches the backend with the uio at an offset, `FOF_OFFSET` when the
/// caller gave it (`pread`/`pwrite`), `FOF_NEXTOFF` when it's the file's own, which is stored
/// back from the uio afterwards. Without it `pread`/`pwrite` are `ESPIPE`.
pub(crate) const DFLAG_SEEKABLE: u32 = 1;

/// A file's `f_flag` (FreeBSD's): open for reading, open for writing, and the open flags that
/// stay with the description (musl's values, as `F_GETFL` reports them).
pub(crate) const FREAD: u32 = 1;
pub(crate) const FWRITE: u32 = 2;
pub(crate) const FAPPEND: u32 = 0o2000;
pub(crate) const FNONBLOCK: u32 = 0o4000;

/// `f_flag` for a file opened with `open(2)` flags `oflags` (FreeBSD's `FFLAGS`): the access mode
/// plus one is `FREAD`/`FWRITE`, and `O_APPEND`/`O_NONBLOCK` carry over.
pub(crate) fn open_flag(oflags: u64) -> u32 {
    (((oflags & 3) + 1) as u32 & (FREAD | FWRITE)) | (oflags as u32 & (FAPPEND | FNONBLOCK))
}

extern "C" fn fo_denied(_handle: u64, _uio: *mut Uio, _flags: u64) -> i64 {
    -(crate::syscall::EBADF as i64)
}

extern "C" fn fo_no_close(_handle: u64) -> i64 {
    0
}

/// What a kernel-owned description is, for `readlink("/proc/<pid>/fd/<n>")` (TTY.md §6.3) and
/// `fstat`. Descriptions a module owns (`sys/modules/oxfs`'s files) are `Module`: the module knows
/// what they are. Terminals aren't tagged here: `tty::of_real_fd` already knows them.
#[derive(Clone, Copy)]
pub(crate) enum FdKind {
    Module,
    /// Both ends of one pipe carry its buffer id.
    Pipe(u64),
    Socket(u64),
    /// A FIFO, by the vnode holding its node (`kern::vfs_vnops::object_vp`).
    Fifo(u64),
    Mqueue,
    /// A device opened through devfs (`devfs::oxidebsd_dev_open`), by number: `major << 8 |
    /// minor`, as a device node's `st_rdev`. Its driver's callbacks are the description's.
    Device(u64),
    /// A vnode's file (`kern::vfs_vnops::VN_OPS`): its data is the vnode.
    Vnode,
}

/// Tags a description its driver registered as a plain module-owned one as device `dev`; one
/// that already has a kind of its own (a terminal's, a pipe's) keeps it.
pub(crate) fn tag_device(real_fd: u64, dev: u64) {
    with_description_full(real_fd, |d| {
        if matches!(d.kind, FdKind::Module) {
            d.kind = FdKind::Device(dev);
        }
    });
}

/// `oxidebsd_real_fd_kind`'s codes; `sys/modules/oxfs` mirrors them.
const KIND_MODULE: i64 = 0;
const KIND_TTY: i64 = 1;
const KIND_PIPE: i64 = 2;
const KIND_SOCKET: i64 = 3;
const KIND_FIFO: i64 = 4;
const KIND_MQUEUE: i64 = 5;
const KIND_DEVICE: i64 = 6;
const KIND_VNODE: i64 = 7;

/// What description `real_fd` is: one of the `KIND_*` codes, with its argument (a terminal's
/// packed `major << 8 | minor`, a pipe or socket's id, a FIFO's inode, a vnode file's vnode) stored
/// through `arg`.
/// `-1` if no such description exists.
pub(crate) extern "C" fn oxidebsd_real_fd_kind(real_fd: u64, arg: *mut u64) -> i64 {
    let (code, value) = if let Some(id) = crate::tty::of_real_fd(real_fd) {
        let (major, minor) = crate::tty::device(id);
        (KIND_TTY, (major as u64) << 8 | minor as u64)
    } else {
        let Some(kind) = DESCRIPTIONS.lock().get(&real_fd).map(|d| d.kind) else {
            return -1;
        };
        match kind {
            FdKind::Module => (KIND_MODULE, 0),
            FdKind::Pipe(id) => (KIND_PIPE, id),
            FdKind::Socket(id) => (KIND_SOCKET, id),
            FdKind::Fifo(inode) => (KIND_FIFO, inode),
            FdKind::Mqueue => (KIND_MQUEUE, 0),
            FdKind::Device(dev) => (KIND_DEVICE, dev),
            FdKind::Vnode => (KIND_VNODE, file_of(real_fd).map_or(0, |f| f.3)),
        }
    };
    // SAFETY: a module-owned out-pointer into its own stack.
    unsafe { *arg = value };
    code
}

/// `pid`'s (any process's, unlike `oxidebsd_real_fd_of`) `real_fd` for its fd `fd`, or `-1`.
pub(crate) extern "C" fn oxidebsd_real_fd_of_pid(pid: u64, fd: u64) -> i64 {
    let tgid = crate::process::table().lock().get(&pid).map(|p| p.tgid);
    let Some(tgid) = tgid else { return -1 };
    TABLE.lock().get(&(tgid, fd)).map_or(-1, |&real_fd| real_fd as i64)
}

/// One open file description (FreeBSD's `struct file`): its operations, its object, its open
/// flags and offset, its kind, and how many `TABLE` entries (across every process) plus messages
/// in flight refer to it. `close` runs when `refs` reaches zero.
struct Description {
    ops: &'static FileOps,
    data: u64,
    /// `FREAD | FWRITE | FAPPEND | FNONBLOCK`.
    flag: u32,
    /// The file offset, for a seekable file (`DFLAG_SEEKABLE`).
    offset: u64,
    kind: FdKind,
    refs: u32,
    /// The vnode a device or FIFO was opened through (FreeBSD's `f_vnode`), referenced, or 0: what
    /// `/proc/<pid>/fd/<n>` names, and what `revoke(2)` finds. A vnode file's own vnode is its
    /// `data`.
    vnode: u64,
}

/// A pseudo-pid, never a real running process (`process::alloc_pid` starts at `1`) — the identity
/// `init` registers fd 0/1/2 under, so `process::spawn` can bootstrap every real process's own
/// stdin/stdout/stderr via the exact same `fork_inherit` path a real `fork()` uses, rather than a
/// separate one-off "seed the new process's fds" routine.
const BOOTSTRAP_PID: u64 = 0;

/// Next `real_fd`. 0 and 1 are the console's input and output, registered by `init` below — never
/// handed out by `oxidebsd_alloc_fd`.
static NEXT_REAL_FD: Mutex<u64> = Mutex::new(3);
/// `(tgid, fd)` -> `real_fd`. Lock order: `TABLE` before `DESCRIPTIONS`.
static TABLE: Mutex<BTreeMap<(u64, u64), u64>> = Mutex::new(BTreeMap::new());
static DESCRIPTIONS: Mutex<BTreeMap<u64, Description>> = Mutex::new(BTreeMap::new());

/// The lowest fd number >= `min` that `pid` doesn't have open.
fn lowest_free(table: &BTreeMap<(u64, u64), u64>, pid: u64, min: u64) -> u64 {
    let mut candidate = min;
    for &(_, fd) in table.range((pid, min)..=(pid, u64::MAX)).map(|(k, _)| k) {
        if fd != candidate {
            break;
        }
        candidate += 1;
    }
    candidate
}

/// Takes a reference to `real_fd`'s description that no descriptor slot holds: a message in
/// flight holding it (`SCM_RIGHTS`, `UNIX.md` §8.1). The description stays open until `release`.
pub(crate) fn hold(real_fd: u64) {
    if let Some(d) = DESCRIPTIONS.lock().get_mut(&real_fd) {
        d.refs += 1;
    }
}

/// Gives up a reference `hold` took; the last one closes the description.
pub(crate) fn release(real_fd: u64) {
    let mut descriptions = DESCRIPTIONS.lock();
    let Some(d) = descriptions.get_mut(&real_fd) else { return };
    d.refs -= 1;
    if d.refs == 0 {
        let close = d.ops.close.unwrap_or(fo_no_close);
        drop(descriptions); // don't hold the lock across the callback
        // Closed before it leaves the table: the operation may ask for its own object
        // (`oxidebsd_file_data`). Nothing can reach it meanwhile, with no reference left.
        {
            let _lock = crate::fs::fslock::Guard::for_call(close as usize as u64);
            close(real_fd);
        }
        let vnode = DESCRIPTIONS.lock().remove(&real_fd).map_or(0, |d| d.vnode);
        if vnode != 0 {
            crate::kern::vfs_subr::vrele_deferred(vnode as *mut vfs_if::Vnode);
        }
    }
}

/// Every reference to `real_fd`'s description: descriptor slots and messages in flight.
pub(crate) fn refs(real_fd: u64) -> u32 {
    DESCRIPTIONS.lock().get(&real_fd).map_or(0, |d| d.refs)
}

/// Turns a reference `hold` took into a descriptor of the calling process, at the lowest free
/// number, with `FD_CLOEXEC` if `cloexec` (a received `SCM_RIGHTS`, `UNIX.md` §8.2).
pub(crate) fn install_held(real_fd: u64, cloexec: bool) -> u64 {
    let tgid = scheduler::current_tgid();
    let fd = {
        let mut table = TABLE.lock();
        let fd = lowest_free(&table, tgid, 0);
        table.insert((tgid, fd), real_fd);
        fd
    };
    if cloexec {
        set_cloexec(tgid, fd, true);
    }
    fd
}

/// Points `(pid, fd)` at `real_fd`, which must already have a description, and counts the
/// reference. The caller has already closed whatever `(pid, fd)` held before.
fn install(table: &mut BTreeMap<(u64, u64), u64>, pid: u64, fd: u64, real_fd: u64) {
    table.insert((pid, fd), real_fd);
    DESCRIPTIONS
        .lock()
        .get_mut(&real_fd)
        .expect("fd registry: installing an fd for a real_fd with no description")
        .refs += 1;
}

/// The calling process's `fd`, resolved to its `real_fd` and callbacks.
fn lookup(fd: u64) -> Option<(u64, &'static FileOps)> {
    let real_fd = *TABLE.lock().get(&(scheduler::current_tgid(), fd))?;
    let ops = DESCRIPTIONS.lock().get(&real_fd)?.ops;
    Some((real_fd, ops))
}

/// `real_fd`'s operations, flags, offset and object, copied out of the table's lock.
pub(crate) fn file_of(real_fd: u64) -> Option<(&'static FileOps, u32, u64, u64)> {
    DESCRIPTIONS.lock().get(&real_fd).map(|d| (d.ops, d.flag, d.offset, d.data))
}

/// The calling process's `fd`: its `real_fd` and `file_of`'s answer.
pub(crate) fn file(fd: u64) -> Option<(u64, &'static FileOps, u32, u64)> {
    let real_fd = real_fd_of(fd)?;
    let (ops, flag, offset, _) = file_of(real_fd)?;
    Some((real_fd, ops, flag, offset))
}

/// Whether a vnode file of mount `mp` is open for writing (refusing a remount read-only).
pub(crate) fn writers_on(mp: *mut vfs_if::Mount) -> bool {
    DESCRIPTIONS.lock().values().any(|d| {
        core::ptr::eq(d.ops, &crate::kern::vfs_vnops::VN_OPS)
            && d.flag & FWRITE != 0
            // SAFETY: an open vnode file holds its vnode.
            && unsafe { (*(d.data as *mut vfs_if::Vnode)).v_mount } == mp
    })
}

/// Revokes every open description `matches` picks (`revoke(2)`, a forced unmount): its file is
/// closed under it, as at its last close, and it becomes deadfs's (`kern::vfs_dead`), which every
/// descriptor and message holding it keeps. `matches` gets the description's handle and the
/// vnode it's open on or came through (`vnode_of`), if any. Returns how many were revoked.
pub(crate) fn revoke_where(matches: impl Fn(u64, Option<*mut vfs_if::Vnode>) -> bool) -> usize {
    use crate::kern::vfs_dead::DEAD_OPS;
    let handles: alloc::vec::Vec<u64> = DESCRIPTIONS
        .lock()
        .iter()
        .filter(|(_, d)| !core::ptr::eq(d.ops, &DEAD_OPS))
        .map(|(&h, _)| h)
        .collect();
    let mut revoked = 0;
    for handle in handles {
        if !matches(handle, vnode_of(handle)) {
            continue;
        }
        let Some((ops, ..)) = file_of(handle) else { continue };
        if let Some(close) = ops.close {
            let _lock = crate::fs::fslock::Guard::for_call(close as usize as u64);
            close(handle);
        }
        let mut vnode = 0;
        with_description_full(handle, |d| {
            d.ops = &DEAD_OPS;
            d.data = 0;
            d.kind = FdKind::Module;
            vnode = core::mem::take(&mut d.vnode);
        });
        if vnode != 0 {
            crate::kern::vfs_subr::vrele_deferred(vnode as *mut vfs_if::Vnode);
        }
        revoked += 1;
    }
    revoked
}

/// Records that `real_fd` was opened through `vp` (giving it the caller's reference); a
/// description that already has one keeps it, and the reference is dropped.
pub(crate) fn set_vnode(real_fd: u64, vp: *mut vfs_if::Vnode) {
    let mut kept = false;
    with_description_full(real_fd, |d| {
        if d.vnode == 0 {
            d.vnode = vp as u64;
            kept = true;
        }
    });
    if !kept {
        crate::kern::vfs_subr::vrele_deferred(vp);
    }
}

/// The vnode `real_fd` is open on or was opened through, if any (not referenced for the caller).
pub(crate) fn vnode_of(real_fd: u64) -> Option<*mut vfs_if::Vnode> {
    let descriptions = DESCRIPTIONS.lock();
    let d = descriptions.get(&real_fd)?;
    if core::ptr::eq(d.ops, &crate::kern::vfs_vnops::VN_OPS) {
        return Some(d.data as *mut vfs_if::Vnode);
    }
    (d.vnode != 0).then_some(d.vnode as *mut vfs_if::Vnode)
}

/// What `/proc/<pid>/fd/<n>` links to (Linux's and FreeBSD's procfs shapes): the path of the file
/// it was opened through, else `pipe:[id]`, `socket:[id]`, `anon_inode:[mqueue]`. Exported to
/// procfs; the length written, or `-errno`.
pub(crate) extern "C" fn oxidebsd_fd_link(pid: u64, fd: u64, buf: *mut u8, cap: u64) -> i64 {
    let r = (|| -> Result<alloc::vec::Vec<u8>, i64> {
        let real_fd = oxidebsd_real_fd_of_pid(pid, fd);
        if real_fd < 0 {
            return Err(-2);
        }
        let real_fd = real_fd as u64;
        // A terminal is named as itself, whatever node it came through (`/dev/tty`, TTY.md §6.3).
        if let Some(id) = crate::tty::of_real_fd(real_fd) {
            return Ok(alloc::format!("/dev/{}", crate::tty::name(id)).into_bytes());
        }
        if let Some(vp) = vnode_of(real_fd) {
            crate::kern::vfs_subr::vref(vp);
            let _giant = crate::fs::fslock::Giant::enter();
            let cred = crate::kern::vfs_subr::current_ucred();
            let path = crate::kern::vfs_syscalls::fullpath(vp, &cred);
            // An unlinked file is named as it was, marked (Linux's procfs shape).
            let unlinked = crate::kern::vnode_if::vop_getattr(vp).is_ok_and(|va| va.va_nlink == 0);
            crate::kern::vfs_subr::vrele(vp);
            let mut path = path.map_err(|e| -(e as i64))?;
            if unlinked {
                path.extend_from_slice(b" (deleted)");
            }
            return Ok(path);
        }
        let kind = DESCRIPTIONS.lock().get(&real_fd).map(|d| d.kind).ok_or(-2i64)?;
        let tagged = |tag: &str, n: u64| alloc::format!("{tag}:[{n}]").into_bytes();
        Ok(match kind {
            FdKind::Pipe(id) => tagged("pipe", id),
            FdKind::Socket(id) => tagged("socket", id),
            FdKind::Fifo(id) => tagged("fifo", id),
            FdKind::Mqueue => alloc::vec::Vec::from(&b"anon_inode:[mqueue]"[..]),
            _ => match crate::tty::of_real_fd(real_fd) {
                Some(id) => alloc::format!("/dev/{}", crate::tty::name(id)).into_bytes(),
                None => return Err(-2),
            },
        })
    })();
    match r {
        Ok(text) => {
            let n = text.len().min(cap as usize);
            // SAFETY: procfs passes a buffer of `cap` bytes.
            unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), buf, n) };
            n as i64
        }
        Err(e) => e,
    }
}

/// Sets a seekable file's offset (`lseek`).
pub(crate) fn set_offset(real_fd: u64, offset: u64) {
    with_description_full(real_fd, |d| d.offset = offset);
}

/// `fstat` of a file whose table has no `stat` operation: the node it was opened through (a
/// FIFO, a device), a terminal's node in `/dev`, or a record made up for a pipe or socket.
pub(crate) fn fallback_stat(real_fd: u64) -> Option<crate::kern::vfs_vnops::Stat> {
    use crate::kern::vfs_vnops::{Stat, vn_stat};
    let synthetic = |mode: u32, rdev: u64, ino: u64| Stat {
        st_ino: ino,
        st_nlink: 1,
        st_mode: mode,
        st_rdev: rdev,
        st_blksize: 4096,
        ..Stat::default()
    };
    let _giant = crate::fs::fslock::Giant::enter();
    if let Some(id) = crate::tty::of_real_fd(real_fd) {
        // A terminal is its own node in /dev, whatever it was opened through (`/dev/tty`), and
        // the console, which the kernel opened itself, too.
        let path = alloc::format!("/dev/{}", crate::tty::name(id));
        let cred = crate::kern::vfs_subr::current_ucred();
        let nd = crate::kern::vfs_lookup::NameiData {
            path: path.as_bytes(),
            nameiop: vfs_if::LOOKUP,
            follow: true,
            startdir: core::ptr::null_mut(),
            cred: &cred,
        };
        if let Ok(ni) = crate::kern::vfs_lookup::namei(&nd) {
            let vp = ni.into_vp();
            let st = vn_stat(vp).ok();
            crate::kern::vfs_subr::vrele(vp);
            return st;
        }
        let (major, minor) = crate::tty::device(id);
        return Some(synthetic(0o020600, (major as u64) << 8 | minor as u64, 0));
    }
    if let Some(vp) = vnode_of(real_fd) {
        return vn_stat(vp).ok();
    }
    match DESCRIPTIONS.lock().get(&real_fd)?.kind {
        FdKind::Pipe(id) => Some(synthetic(0o010600, 0, id)),
        FdKind::Socket(id) => Some(synthetic(0o140777, 0, id)),
        FdKind::Mqueue => Some(synthetic(0o100600, 0, 0)),
        _ => None,
    }
}

fn with_description_full(real_fd: u64, f: impl FnOnce(&mut Description)) {
    if let Some(d) = DESCRIPTIONS.lock().get_mut(&real_fd) {
        f(d);
    }
}
/// `O_NONBLOCK`, as set at open or by `fcntl(F_SETFL, ...)` (`syscall::sys_fcntl`): `FNONBLOCK` in
/// the description's `flag`, so `dup`/`dup2`/`fork` aliases share it, as POSIX defines it.
pub(crate) fn set_nonblocking(real_fd: u64, on: bool) {
    if let Some(d) = DESCRIPTIONS.lock().get_mut(&real_fd) {
        if on {
            d.flag |= FNONBLOCK;
        } else {
            d.flag &= !FNONBLOCK;
        }
    }
}

pub(crate) fn is_nonblocking(real_fd: u64) -> bool {
    DESCRIPTIONS.lock().get(&real_fd).is_some_and(|d| d.flag & FNONBLOCK != 0)
}

/// The object `finstall` was given for `handle` (a pipe's buffer id, a module's own slot), `0` if
/// none.
pub(crate) extern "C" fn oxidebsd_file_data(handle: u64) -> u64 {
    DESCRIPTIONS.lock().get(&handle).map_or(0, |d| d.data)
}

/// `finstall` for modules: `ops` is the module's static table (modules are never unloaded), the
/// open flags are `open(2)`'s (`open_flag`). The fd, or `-errno`.
pub(crate) extern "C" fn oxidebsd_finstall(real_fd: u64, ops: *const FileOps, data: u64, oflags: u64) -> i64 {
    // SAFETY: a module's own `static` table, valid for the kernel's lifetime.
    let ops: &'static FileOps = unsafe { &*ops };
    finstall(real_fd, ops, data, open_flag(oflags), FdKind::Module)
}

/// A seekable file's offset (`lseek`, `getdents`' record cursor while oxfs answers it).
pub(crate) extern "C" fn oxidebsd_file_offset(handle: u64) -> u64 {
    DESCRIPTIONS.lock().get(&handle).map_or(0, |d| d.offset)
}

pub(crate) extern "C" fn oxidebsd_file_set_offset(handle: u64, offset: u64) {
    with_description_full(handle, |d| d.offset = offset);
}

/// Makes `real_fd` (from `oxidebsd_alloc_fd`) a file with operations `ops`, object `data`, open
/// flags `flag` (`FREAD`/`FWRITE`/`FAPPEND`/`FNONBLOCK`) and kind `kind`, and gives the calling
/// process the lowest free fd for it. Returns the fd, or `-ENFILE` past `kern.maxfiles` (callers
/// have made room first, `check_room`).
///
/// Inside `kernel_open` the file is the kernel's instead: it gets no fd, one reference the
/// kernel drops with `release`, and the return value is its handle.
pub(crate) fn finstall(real_fd: u64, ops: &'static FileOps, data: u64, flag: u32, kind: FdKind) -> i64 {
    let pid = scheduler::current_tgid();
    let held = kernel_opening();
    {
        let mut descriptions = DESCRIPTIONS.lock();
        if descriptions.len() >= crate::kern::kern_sysctl::maxfiles() {
            return -ENFILE;
        }
        let refs = held as u32;
        descriptions.insert(real_fd, Description { ops, data, flag, offset: 0, kind, refs, vnode: 0 });
    }
    if held {
        *KERNEL_OPEN.lock() = None;
        return real_fd as i64;
    }
    let mut table = TABLE.lock();
    let fd = lowest_free(&table, pid, 0);
    install(&mut table, pid, fd, real_fd);
    fd as i64
}

/// Real per-`(pid, fd)` `FD_CLOEXEC` state -- unlike `O_NONBLOCK` above, POSIX defines this as a
/// property of the file descriptor itself, not the underlying open file description, so it's keyed
/// by the same `(pid, fd)` pair `TABLE` uses (found live via `shm_open/11-1.c`, the Open POSIX Test
/// Suite pilot: musl's own `shm_open()` always passes real `O_CLOEXEC` to `open()`, and the test
/// reads it back via `fcntl(fd, F_GETFD)`). Set by `sys/modules/oxfs`'s own `open()` path when the
/// caller's real `O_CLOEXEC` flag is present, or by `fcntl(F_SETFD, FD_CLOEXEC)`
/// (`syscall::sys_fcntl`); `dup`/`dup2` deliberately do *not* copy it to the new `(pid, fd)` entry
/// (real POSIX: only `F_DUPFD_CLOEXEC`/`dup3(..., O_CLOEXEC)` would, and this kernel's own
/// `F_DUPFD_CLOEXEC` handling sets it explicitly afterward rather than inheriting it here) --
/// `fork_inherit` does copy it (real `fork()` preserves each fd's own close-on-exec flag into the
/// child). Dropped when the fd is closed, since fd numbers are reused.
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
/// `sys/module.rs`'s kernel API table), since `set_cloexec` above needs the caller's real pid,
/// which modules can't resolve themselves (only the kernel exports `scheduler::current_pid`
/// indirectly, through functions like this one). `sys/modules/oxfs`'s own `oxfs_open` is the one real
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

/// `close_range(2)` (FreeBSD's and Linux's): closes the caller's descriptors `first..=last`, or
/// with `CLOSE_RANGE_CLOEXEC` marks them close-on-exec. `CLOSE_RANGE_UNSHARE` changes nothing:
/// threads already share one table.
pub(crate) fn close_range(first: u64, last: u64, flags: u64) -> Result<u64, u64> {
    const CLOSE_RANGE_UNSHARE: u64 = 2;
    const CLOSE_RANGE_CLOEXEC: u64 = 4;
    let (first, last) = (first as u32 as u64, last as u32 as u64);
    if first > last || flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 {
        return Err(crate::syscall::EINVAL);
    }
    let pid = scheduler::current_tgid();
    let fds: alloc::vec::Vec<u64> = TABLE
        .lock()
        .keys()
        .filter(|&&(p, fd)| p == pid && (first..=last).contains(&fd))
        .map(|&(_, fd)| fd)
        .collect();
    for fd in fds {
        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            set_cloexec(pid, fd, true);
        } else {
            close_one(pid, fd);
            CLOEXEC.lock().remove(&(pid, fd));
        }
    }
    Ok(0)
}

/// A fresh `real_fd`: the identity a module keys its own state by, and later passes to
/// `finstall`/`oxidebsd_finstall` to make it a file and give the calling process an fd for it.
pub(crate) extern "C" fn oxidebsd_alloc_fd() -> u64 {
    let mut next = NEXT_REAL_FD.lock();
    let real_fd = *next;
    *next += 1;
    real_fd
}

/// `ENFILE` (musl's value): the system-wide open-file limit, `kern.maxfiles`, is reached.
const ENFILE: i64 = 23;
/// `EMFILE`: the process's own limit, `RLIMIT_NOFILE` (`process::limits::current_nofile`), is
/// reached.
const EMFILE: i64 = 24;

/// How many fd numbers below `limit` `pid` has free.
fn free_below(table: &BTreeMap<(u64, u64), u64>, pid: u64, limit: u64) -> u64 {
    limit.saturating_sub(table.range((pid, 0)..(pid, limit)).count() as u64)
}

/// The process (by pid: an open can wait on the disk, and others run meanwhile) whose current open
/// is the kernel's own (`kernel_open`).
static KERNEL_OPEN: Mutex<Option<u64>> = Mutex::new(None);

/// Whether the current open is the kernel's own (`kernel_open`): its result is a handle, not an fd.
pub(crate) fn is_kernel_opening() -> bool {
    kernel_opening()
}

fn kernel_opening() -> bool {
    *KERNEL_OPEN.lock() == Some(scheduler::current_pid())
}

/// Runs `open`, a file system's open call made by the kernel for itself (exec's open of a program,
/// FreeBSD's `vn_open` with no fd), so that the file it makes is held by the kernel: no fd, not
/// counted against `RLIMIT_NOFILE`, its handle returned where the fd would be. The caller drops
/// it with `release(handle)`. An open that fails, or makes no file, leaves nothing held.
pub(crate) fn kernel_open(open: impl FnOnce() -> i64) -> i64 {
    *KERNEL_OPEN.lock() = Some(scheduler::current_pid());
    let r = open();
    *KERNEL_OPEN.lock() = None;
    r
}

/// Whether `n` more open-file descriptions fit under `kern.maxfiles` (SYSCTL.md §§5-6), which
/// counts descriptions, as FreeBSD's counts `struct file`s: `dup` and `fork` share one and don't
/// count; and whether the calling process has `n` fd numbers free under its `RLIMIT_NOFILE`
/// (`EMFILE`). Every creator of descriptions checks before building its own state, so a refusal
/// leaves nothing to undo; `register` refuses too, as a backstop.
pub(crate) fn check_room(n: usize) -> Result<(), i64> {
    let max = crate::kern::kern_sysctl::maxfiles();
    if DESCRIPTIONS.lock().len() + n > max {
        return Err(ENFILE);
    }
    let limit = crate::process::limits::current_nofile();
    if !kernel_opening() && free_below(&TABLE.lock(), scheduler::current_tgid(), limit) < n as u64 {
        return Err(EMFILE);
    }
    Ok(())
}

/// `check_room` for modules: `0`, `-ENFILE` or `-EMFILE`.
pub(crate) extern "C" fn oxidebsd_fd_check_room(n: u64) -> i64 {
    match check_room(n as usize) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

/// Removes the calling process's own `fd` from the registry; only actually invokes the underlying
/// resource's `close` callback once its refcount (shared across every alias, in every process,
/// created by `dup2`/`fork_inherit`) reaches zero — see this file's module doc comment. `0` on
/// success, `-1` if the calling process has no such `fd` registered at all.
///
/// `pub` for the in-kernel `tests/socketpair_smoke.rs` (retired 2026-10-06: it called handlers as Rust functions); `sys/modules/oxfs`'s
/// `SYS_CLOSE` handler is the other caller.
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
    let Some(real_fd) = TABLE.lock().remove(&(pid, fd)) else {
        return false;
    };
    CLOEXEC.lock().remove(&(pid, fd));
    let mut descriptions = DESCRIPTIONS.lock();
    let d = descriptions.get_mut(&real_fd).expect(
        "fd registry: real_fd missing from DESCRIPTIONS -- every TABLE entry must have one, \
         maintained by register/install",
    );
    d.refs -= 1;
    if d.refs == 0 {
        let close = d.ops.close.unwrap_or(fo_no_close);
        drop(descriptions); // don't hold the lock across the callback
        // Closed before it leaves the table: the operation may ask for its own object
        // (`oxidebsd_file_data`). Nothing can reach it meanwhile, with no reference left.
        {
            let _lock = crate::fs::fslock::Guard::for_call(close as usize as u64);
            close(real_fd);
        }
        let vnode = DESCRIPTIONS.lock().remove(&real_fd).map_or(0, |d| d.vnode);
        if vnode != 0 {
            crate::kern::vfs_subr::vrele_deferred(vnode as *mut vfs_if::Vnode);
        }
    } else {
        drop(descriptions);
        // What's left may be only messages in flight: a socket sent over itself (UNIX.md §8.4).
        crate::kern::uipc_usrreq::descriptor_closed(real_fd);
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
    let mut table = TABLE.lock();
    let parent_entries: alloc::vec::Vec<(u64, u64)> = table
        .range((parent, 0)..=(parent, u64::MAX))
        .map(|(&(_, fd), &real_fd)| (fd, real_fd))
        .collect();
    for (fd, real_fd) in parent_entries {
        install(&mut table, child, fd, real_fd);
        // Real fork() preserves each fd's own close-on-exec flag into the child -- see CLOEXEC's
        // own doc comment for why this is a per-(pid, fd) copy, not shared state.
        if is_cloexec(parent, fd) {
            set_cloexec(child, fd, true);
        }
    }
}

/// `SYS_DUP2`'s real logic (`sys/syscall.rs`'s `sys_dup2` is a thin wrapper over this), scoped to
/// the calling process's own fds — real `dup2` is always within one process. `newfd == oldfd` is a
/// no-op *if* `oldfd` is actually open (matching real `dup2`'s own documented special case);
/// otherwise whatever `newfd` previously referred to is closed first (through the same
/// refcount-aware path `oxidebsd_close_fd` uses, so an in-use underlying resource survives if
/// another alias — in this process or any other — still references it), then `newfd` becomes a
/// fresh alias of `oldfd`'s own `real_fd`.
///
/// `EBADF` for an `oldfd` that isn't open or a `newfd` at or past the process's `RLIMIT_NOFILE`.
pub(crate) fn dup2(oldfd: u64, newfd: u64) -> Result<u64, u64> {
    let pid = scheduler::current_tgid();
    let limit = crate::process::limits::current_nofile();
    let real_fd = *TABLE.lock().get(&(pid, oldfd)).ok_or(crate::syscall::EBADF)?;
    if newfd >= limit {
        return Err(crate::syscall::EBADF);
    }
    if oldfd == newfd {
        return Ok(newfd);
    }
    close_one(pid, newfd);
    install(&mut TABLE.lock(), pid, newfd, real_fd);
    Ok(newfd)
}

/// `SYS_DUP`'s real logic (`sys/syscall.rs`'s `sys_dup` is a thin wrapper over this) — real
/// `dup(2)`'s single-argument form: the lowest free fd becomes an alias to `oldfd`'s own `real_fd`, same aliasing mechanics as
/// `dup2` above minus the caller-chosen-target-fd/close-first cases `dup2` has to handle. Added
/// specifically because BusyBox's `hush` (`CONFIG_HUSH_JOB`) calls `dup_CLOEXEC`, which tries
/// `fcntl(fd, F_DUPFD_CLOEXEC, ...)` first — this kernel has no `fcntl` at all, so that call
/// harmlessly `ENOSYS`s — and only then falls back to plain `dup(fd)`; without this, hush's own
/// `G_interactive_fd` setup gives up entirely and silently treats itself as non-interactive, the
/// exact thing turning on real interactive mode was for. See CLAUDE.md's "Interactive shell"
/// section for the full trace of why `fcntl` itself doesn't need implementing for this to work.
pub(crate) fn dup(oldfd: u64) -> Result<u64, u64> {
    dup_min(oldfd, 0)
}

/// `fcntl(F_DUPFD, min)`: like `dup`, but the new fd is the lowest free one >= `min`. `EBADF` for
/// an `oldfd` that isn't open, `EINVAL` for a `min` at or past the process's `RLIMIT_NOFILE`,
/// `EMFILE` when no number below it is free.
pub(crate) fn dup_min(oldfd: u64, min: u64) -> Result<u64, u64> {
    let pid = scheduler::current_tgid();
    let limit = crate::process::limits::current_nofile();
    let mut table = TABLE.lock();
    let real_fd = *table.get(&(pid, oldfd)).ok_or(crate::syscall::EBADF)?;
    if min >= limit {
        return Err(crate::syscall::EINVAL);
    }
    let newfd = lowest_free(&table, pid, min);
    if newfd >= limit {
        return Err(EMFILE as u64);
    }
    install(&mut table, pid, newfd, real_fd);
    Ok(newfd)
}

/// `read(2)` and its vector and positioned forms on the calling process's `fd`: the backend's
/// read operation (called with `real_fd`, see this file's module doc comment) over `uio`. `None`
/// if the process has no such `fd` (`EBADF`). A transfer of zero bytes returns `0` without
/// reaching the backend, whatever the buffer is, as POSIX requires (musl's stdio does
/// `write(1, NULL, 0)`). An error after some bytes moved returns the count if it is `EINTR`,
/// `ERESTART` or `EAGAIN`, the error otherwise (USERMEM.md §4.4).
pub(crate) fn read(fd: u64, uio: &mut Uio, flags: u64) -> Option<i64> {
    read_handle(real_fd_of(fd)?, uio, flags)
}

/// `read` on a file by its handle, one the kernel holds itself (`kernel_open`).
pub(crate) fn read_handle(real_fd: u64, uio: &mut Uio, flags: u64) -> Option<i64> {
    let (ops, ..) = file_of(real_fd)?;
    Some(transfer(ops.read.unwrap_or(fo_denied), ops, FREAD, real_fd, uio, flags))
}

/// `write(2)` and its forms: as `read`, through the backend's write operation.
pub(crate) fn write(fd: u64, uio: &mut Uio, flags: u64) -> Option<i64> {
    let (real_fd, ops) = lookup(fd)?;
    Some(transfer(ops.write.unwrap_or(fo_denied), ops, FWRITE, real_fd, uio, flags))
}

/// The kernel's part of a transfer: the access mode allows `need` (`FREAD`/`FWRITE`) or it's
/// `EBADF`; a seekable file's own offset is the kernel's to keep, unless the call gives one
/// (`pread`/`pwrite`, `FOF_OFFSET`), which a file without an offset refuses (`ESPIPE`).
fn transfer(op: FdReadWrite, ops: &FileOps, need: u32, real_fd: u64, uio: &mut Uio, flags: u64) -> i64 {
    let seekable = ops.flags & DFLAG_SEEKABLE != 0;
    if flags & FOF_OFFSET != 0 && !seekable {
        return -(ESPIPE as i64);
    }
    let Some((_, flag, offset, _)) = file_of(real_fd) else {
        return -(crate::syscall::EBADF as i64);
    };
    if flag & need == 0 {
        return -(crate::syscall::EBADF as i64);
    }
    let mut kept_offset = false;
    let mut flags = flags;
    if seekable && flags & FOF_OFFSET == 0 {
        uio.set_offset(offset);
        flags |= crate::kern::subr_uio::FOF_NEXTOFF;
        kept_offset = true;
    }
    let len = uio.resid();
    if len == 0 {
        return 0;
    }
    let r = {
        let _lock = crate::fs::fslock::Guard::for_call_sleepable(op as usize as u64);
        op(real_fd, uio, flags)
    };
    if kept_offset {
        let offset = uio.offset();
        with_description_full(real_fd, |d| d.offset = offset);
    }
    let moved = len - uio.resid();
    if r < 0 && moved > 0 && [EINTR, ERESTART, EAGAIN].contains(&(-r as u64)) {
        moved as i64
    } else {
        r
    }
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
        .copied()
}

/// Live "is this fd backed by an identifiable real file, and if so which one" query — see
/// `FdContentId`'s own doc comment for why this calls the registered callback fresh every time
/// rather than reading a value cached at registration. Used by `crate::process::mm::do_mmap` to
/// decide whether a real fd-backed `MAP_SHARED` mapping is even possible, and to key its own
/// cross-open shared-frame cache. `None` covers both "no such fd" and "not identifiable right now."
pub(crate) fn content_id_of(fd: u64) -> Option<u64> {
    content_id_of_handle(real_fd_of(fd)?)
}

/// `content_id_of` by handle.
pub(crate) fn content_id_of_handle(real_fd: u64) -> Option<u64> {
    let (ops, _, _, data) = file_of(real_fd)?;
    if !core::ptr::eq(ops, &crate::kern::vfs_vnops::VN_OPS) {
        return None;
    }
    let vp = crate::kern::vfs_vnops::object_vp(data as *mut vfs_if::Vnode);
    // SAFETY: the open file holds its vnode, and that its lower one.
    (unsafe { (*vp).v_type } == vfs_if::VREG).then_some(vp as u64)
}

/// `(readable, writable)`, per `FdAccessMode`'s own doc comment. `(true, true)` for a fd not found
/// in `TABLE` at all -- inert in practice, since `crate::process::mm::do_mmap_file_backed`'s own
/// caller (`do_mmap`) always calls `content_id_of` first and bails `ENODEV` before this could ever
/// matter for an unregistered fd.
pub(crate) fn access_mode_of(fd: u64) -> (bool, bool) {
    match real_fd_of(fd).and_then(file_of) {
        Some((_, flag, _, _)) => (flag & FREAD != 0, flag & FWRITE != 0),
        None => (true, true),
    }
}

/// Whether `fd` was opened `O_APPEND`, for `F_GETFL`.
pub(crate) fn is_append_of(fd: u64) -> bool {
    real_fd_of(fd).and_then(file_of).is_some_and(|(_, flag, _, _)| flag & FAPPEND != 0)
}

/// Live "is this fd a real `/dev/fb0` mapping-eligible framebuffer, and if so what's its real
/// geometry" query -- see `FdFbGeometry`'s own doc comment. `None` covers both "no such fd" and
/// "not a framebuffer fd." Used by `crate::process::mm::do_mmap` (checked *before* `content_id_of`
/// -- a framebuffer fd's `content_id_of` always returns `None`/`ENODEV` too, so order matters) and
/// by `syscall::ffi::sys_ioctl`'s framebuffer-info request.
pub(crate) fn framebuffer_geometry_of(fd: u64) -> Option<crate::drivers::fbdev::FbGeometry> {
    let (real_fd, ops) = lookup(fd)?;
    let mut geom = crate::drivers::fbdev::FbGeometry {
        phys_base: 0,
        len: 0,
        width: 0,
        height: 0,
        pitch: 0,
        bpp: 0,
    };
    let fb_geometry = ops.fb_geometry?;
    let _lock = crate::fs::fslock::Guard::for_call(fb_geometry as usize as u64);
    let ok = fb_geometry(
        real_fd,
        &mut geom as *mut crate::drivers::fbdev::FbGeometry as u64,
    );
    if ok == 0 { Some(geom) } else { None }
}

/// The mode bits, owner and group of the program open as `real_fd`, for `execve`
/// (`process::identity::Cred::exec`), and whether it is under a `wxallowed` mount and under a
/// `noexec` one.
pub(crate) fn exec_setid_handle(real_fd: u64) -> Option<((u32, u32, u32), bool, bool)> {
    let (ops, _, _, data) = file_of(real_fd)?;
    if !core::ptr::eq(ops, &crate::kern::vfs_vnops::VN_OPS) {
        return None;
    }
    crate::kern::vfs_vnops::exec_setid(data as *mut vfs_if::Vnode)
}

/// A file's contents by content ID (its vnode: `kern::vfs_vnops`), for `mmap`'s population and
/// writeback, the page cache and exec. Not through a descriptor's own read and write: the
/// descriptor `mmap` was given may not be readable, and writeback runs after it's closed.
pub(crate) fn content_read(content_id: u64, offset: u64, ptr: u64, len: u64) -> i64 {
    crate::kern::vfs_vnops::content_read(content_id, offset, ptr, len)
}

/// Writes `len` bytes at the start of the file (a shared mapping's writeback).
pub(crate) fn content_write(content_id: u64, ptr: u64, len: u64) -> i64 {
    crate::kern::vfs_vnops::content_write(content_id, ptr, len)
}

/// The file's size in bytes.
pub(crate) fn content_size(content_id: u64) -> i64 {
    crate::kern::vfs_vnops::content_size(content_id)
}

/// Whether the file is a POSIX shared memory object: `mmap` bounds a mapping of one at its size.
pub(crate) fn content_is_shm(content_id: u64) -> bool {
    crate::kern::vfs_vnops::content_is_shm(content_id)
}

/// FFI wrapper over `real_fd_of` for modules that own their own fd-keyed state (`sys/modules/oxfs`'s
/// `OPEN_FILES`, keyed by `real_fd` like every `FdOps` callback already is) but can't call
/// `crate::fd` directly -- modules only ever call *into* the kernel, through their own hand-curated
/// symbol table (see `sys/module.rs`). `SYS_FSTAT`'s handler is the first case that needs this:
/// unlike `SYS_READ`/`SYS_WRITE`, which this file's own `read`/`write` already resolve fd -> real_fd
/// for before invoking a callback, a syscall-number-registered handler (`oxfs_fstat`) receives the
/// caller's raw `fd` argument directly and has to do that resolution itself. Returns `-1` (never a
/// valid `real_fd`, which starts at `3`) for an fd the calling process doesn't have open, rather than
/// `Option`, to stay in this codebase's plain-`i64`-FFI-boundary convention (see `SyscallHandler`'s
/// own doc comment in `sys/syscall.rs`).
pub(crate) extern "C" fn oxidebsd_real_fd_of(fd: u64) -> i64 {
    match real_fd_of(fd) {
        Some(real_fd) => real_fd as i64,
        None => -1,
    }
}

/// The `index`-th fd number (this *process's own* numbering, not `real_fd`) currently open for
/// `pid`, ascending, `-1` once `index` is past the end -- mirrors `process::oxidebsd_proc_pid_at`'s
/// identical "loop until -1" shape, for `sys/modules/oxfs`'s own `/proc/<pid>/fd/` directory listing.
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

/// Registers fd 0/1/2 under `BOOTSTRAP_PID`: one read-write description of the console
/// terminal, `ttyv0` (TTY.md §6.1), inherited by every process the kernel spawns through
/// `fork_inherit(BOOTSTRAP_PID, pid)`.
///
/// Runs after the modules load, so anything a `module_init` left open under `BOOTSTRAP_PID` can
/// already hold fd 0-2 -- those get closed so stdio lands on its real numbers.
pub fn init() {
    for fd in 0..3 {
        close_one(BOOTSTRAP_PID, fd);
    }
    crate::tty::console::init();
    let ops = &crate::tty::TTY_OPS;
    let kind = FdKind::Module;
    DESCRIPTIONS.lock().insert(0, Description { ops, data: 0, flag: FREAD | FWRITE, offset: 0, kind, refs: 0, vnode: 0 });
    crate::tty::bind(0, crate::tty::TTYV0);
    let mut table = TABLE.lock();
    for fd in 0..3 {
        install(&mut table, BOOTSTRAP_PID, fd, 0);
    }
}
