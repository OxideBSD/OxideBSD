//! Real POSIX message queues (`mq_open`/`mq_unlink`/`mq_timedsend`/`mq_timedreceive`/`mq_notify`/
//! `mq_getsetattr` -- items 11-16 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
//! "pre-reserved ahead of implementation" batch, `SYS_MQ_OPEN = 536` through
//! `SYS_MQ_GETSETATTR = 541`). No live caller anywhere in the current roster (confirmed by that
//! doc) -- built anyway, in real POSIX implementation order, continuing straight on from the
//! per-process-timer sub-batch just above it.
//!
//! **A real, separate namespace, not backed by `oxfs`** -- POSIX message queues live in their own
//! flat name-to-queue mapping (`NAMES`/`QUEUES` below), the same way a real Linux mqueue
//! pseudo-filesystem is conceptually distinct from the caller's ordinary filesystem even though it
//! happens to be mountable at a path. `mq_open`'s own `name` argument is a **plain NUL-terminated
//! C string, not this codebase's usual length-prefixed `(ptr, len)` convention** -- deliberately:
//! real `mq_open(3)`'s own raw syscall (`third_party/musl/src/mq/mq_open.c`) already fills all 4
//! of this ABI's register slots (`name, flags, mode, attr`), leaving no room for a 5th `path_len`
//! argument the way `open`/`chmod`/... gained one, and real Linux's own `sys_mq_open` doesn't
//! length-prefix the name either (a bounded `strncpy_from_user`) -- so matching that exactly avoids
//! a musl call-site patch entirely for this one. `read_cstr` below does the same bounded scan
//! kernel-side.
//!
//! **`mq_timedsend`/`mq_timedreceive` are the one real wire-format wrinkle in this batch**: real
//! Linux needs 5 syscall args (`mqd, msg, len, prio[_ptr], at`) and this ABI only carries 4 --
//! `third_party/musl/src/mq/mq_timedsend.c`/`mq_timedreceive.c` are patched (see those files' own
//! comments, `oxidebsd` branch) to pack `mqd`/`len` into a single register (`high 32 = len, low
//! 32 = mqd`) rather than the usual "drop a redundant argument" trick (`utimensat`'s always-
//! `AT_FDCWD` `fd`) -- there's nothing redundant to drop here, every one of the 5 real values is
//! load-bearing.
//!
//! **`mq_close` isn't its own syscall at all** -- real `mq_close(3)` (`third_party/musl/src/mq/
//! mq_close.c`) is a bare `syscall(SYS_close, mqd)`, so an mqd is a real fd from this ABI's own
//! perspective and rides the ordinary `crate::fs::fd` registry exactly like a pipe/socketpair end
//! (`MQ_ENDS` below mirrors `pipe.rs`'s own `PIPE_ENDS`/`SOCK_ENDS` keying-by-`real_fd`
//! convention). `mq_send`/`mq_receive`/`mq_getattr` are pure musl-side wrappers around
//! `mq_timedsend`/`mq_timedreceive`/`mq_setattr` too (see those files) -- no separate syscalls for
//! any of the three.
//!
//! **Blocking reuses this codebase's own established shape** (`fs/pipe.rs`'s "block, `schedule()`,
//! loop and re-check" pattern), extended with a real timeout: `BlockReason::WaitingForMqData`/
//! `WaitingForMqSpace` carry a deadline (`u64::MAX` for "no timeout" -- the plain `mq_send`/
//! `mq_receive` wrapper's own null-`at` case), woken either by the matching send/receive draining
//! the condition or by `interrupts::timer_interrupt_handler`'s own deadline scan (see that
//! function's own doc comment) -- same dual-wake shape `Sleeping` already has, just merged with a
//! real event-driven wake instead of being purely time-based.
//!
//! **`mq_notify`'s `SIGEV_SIGNAL` delivery reuses `process::do_kill` directly**, not a bespoke
//! delivery path -- calling it with the notifying process as both "caller" and "target" is a real
//! self-signal, always taking `do_kill`'s own self-target early-return (never its cross-process
//! permission check, see `src/process/signals.rs`'s `has_signal_permission` -- irrelevant here
//! regardless, since a process always has permission to signal itself), so this is exactly the
//! real POSIX behavior (respects `SIG_IGN`/a caught handler/default disposition, same as an actual
//! `kill()` would). `SIGEV_THREAD`/`SIGEV_THREAD_ID` are real `EINVAL` -- this kernel
//! has no `clone(2)`/`AF_NETLINK`, and real musl's own `SIGEV_THREAD` emulation
//! (`third_party/musl/src/mq/mq_notify.c`) never even issues the raw syscall for that case (it's
//! handled entirely in userspace over a netlink socket this port doesn't have). `si_value`
//! (`sigev_value`) is read but never delivered -- same already-documented gap `sigqueue`'s own
//! "Missing, live caller confirmed" entry in `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md` has: `pending_signals`
//! is a plain bitmask with nowhere to stash a payload.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use spin::Mutex;

use crate::process::scheduler;
use crate::process::{self, BlockReason, Pid, ProcState};
use crate::syscall::{
    EAGAIN, EBADF, EBUSY, EEXIST, EINTR, EINVAL, EMSGSIZE, ENAMETOOLONG, ENOENT, ETIMEDOUT,
};

const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: i64 = 0o4000;

/// Real Linux's own defaults (`/proc/sys/fs/mqueue/{msg_default,msgsize_default}`) for an
/// `O_CREAT` open with no `attr` -- matched for authenticity, not load-bearing on their own.
const MQ_DEFAULT_MAXMSG: i64 = 10;
const MQ_DEFAULT_MSGSIZE: i64 = 8192;
/// Hard caps this port enforces (`EINVAL` past either): no privileged-override/`rlimit`-driven
/// ceiling exists here the way real Linux's `RLIMIT_MSGQUEUE` provides, and each queue is a plain
/// heap-backed `Vec` with no block-allocator-style bound the way `oxfs` has -- an unbounded
/// `maxmsg * msgsize` here would be the exact "unbounded heap growth reachable from userspace" bug
/// `fs/pipe.rs`'s own `PIPE_CAPACITY` was already added to close for pipes (see that module's own
/// doc comment).
const MQ_MAX_MAXMSG: i64 = 256;
const MQ_MAX_MSGSIZE: i64 = 65536;
/// Real Linux's own `MQ_PRIO_MAX` (`limits.h`, not re-exposed by this musl fork's own headers
/// since no live caller needs the macro) -- a priority at or above this is `EINVAL`.
const MQ_PRIO_MAX: u64 = 32768;
/// A generous bound on `mq_open`'s raw NUL-terminated name scan (see this module's own doc comment
/// for why it's not length-prefixed) -- real Linux's own mqueue names are capped by `NAME_MAX`
/// (255); matched here purely as a sane ceiling against a runaway/unterminated pointer, not a
/// meaningful POSIX limit this kernel enforces elsewhere.
const MQ_NAME_MAX: usize = 255;

struct Message {
    priority: u32,
    data: Vec<u8>,
}

/// `mq_notify`'s single live registration (real POSIX: at most one process may be registered per
/// queue at a time -- a second attempt while one is live is `EBUSY`, see `do_mq_notify`).
/// `SIGEV_NONE` still occupies the slot (matches real semantics: it's a real registration, just
/// one that never fires) even though this port has no `poll`-on-mqd path that would ever consult
/// it -- kept anyway for a caller that only ever calls `mq_notify(mqd, &sigev_none)` to test
/// whether registration itself succeeds.
enum Notify {
    Signal { pid: Pid, signo: u64 },
    None,
}

struct MessageQueue {
    max_msg: i64,
    msg_size: i64,
    /// Kept sorted highest-priority-first, FIFO among equal priorities -- `insert_by_priority`
    /// maintains this invariant on every insert; `do_mq_timedreceive` always drains index `0`.
    messages: Vec<Message>,
    /// How many open descriptors (across every process, following `crate::fs::fd`'s own
    /// `real_fd`-scoped refcounting convention) currently reference this queue -- real POSIX
    /// semantics: `mq_unlink` removes the *name* immediately but the queue itself survives until
    /// the last open descriptor closes (`unlinked` below tracks whether that removal is still
    /// pending).
    open_count: u32,
    unlinked: bool,
    notify: Option<Notify>,
    /// The `real_fd` that currently owns `notify`, if any -- real POSIX `mq_close(3)`: closing the
    /// descriptor a notification was registered through removes that registration, freeing the
    /// queue for another process to register one (`mq_close/2-1.c`). `notify`/`notify_owner_fd`
    /// are always set and cleared together.
    notify_owner_fd: Option<u64>,
}

#[derive(Clone, Copy)]
struct MqEnd {
    mq_id: u64,
    /// `flags & O_ACCMODE` at open time -- real POSIX requires a descriptor opened `O_RDONLY`/
    /// `O_WRONLY` to reject the opposite operation with `EBADF`, same direction-check shape
    /// `fs/pipe.rs`'s `write_denied`/`read_denied` already enforce for a plain pipe end (there via
    /// two different callback functions; here via one runtime check, since both directions share
    /// the same two syscalls).
    access: u64,
}

static NEXT_MQ_ID: Mutex<u64> = Mutex::new(1);
static QUEUES: Mutex<BTreeMap<u64, MessageQueue>> = Mutex::new(BTreeMap::new());
static NAMES: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
/// Keyed by `real_fd`, same convention as `fs/pipe.rs`'s `PIPE_ENDS`/`SOCK_ENDS` -- stable across
/// any `dup2` alias of an mqd, since `do_mq_timedsend`/etc. always resolve the caller's own raw
/// `mqd` argument through `crate::fs::fd::real_fd_of` first (see this module's own doc comment on
/// why `mq_close` isn't a distinct syscall).
static MQ_ENDS: Mutex<BTreeMap<u64, MqEnd>> = Mutex::new(BTreeMap::new());

/// musl's own `struct mq_attr` on x86_64 (`third_party/musl/include/mqueue.h`): four `long`s plus
/// four reserved `long`s, no padding (every field is 8 bytes on this arch) -- 64 bytes total.
#[repr(C)]
struct RawMqAttr {
    mq_flags: i64,
    mq_maxmsg: i64,
    mq_msgsize: i64,
    mq_curmsgs: i64,
    unused: [i64; 4],
}

const _: () = assert!(core::mem::size_of::<RawMqAttr>() == 64);

/// Bounded raw-pointer NUL-terminated string read -- same known pointer-validation gap every
/// other user-memory access in this codebase already has (see `sys_read`/`sys_write`'s own doc
/// comment). `None` if no NUL turns up within `max_len` bytes, or the bytes aren't valid UTF-8
/// (real mqueue names are opaque bytes on Linux, but this port's own `NAMES` map is keyed by
/// `String` -- no live caller to exercise a non-UTF-8 name today).
/// `Err(EINVAL)` for a null pointer or invalid UTF-8; `Err(ENAMETOOLONG)` specifically when no NUL
/// terminator turns up within `max_len` bytes -- real POSIX `ENAMETOOLONG` (`mq_open/27-1.c`, a
/// name deliberately longer than `PATH_MAX`), previously conflated with every other failure mode
/// into a flat `EINVAL`.
fn read_cstr(ptr: u64, max_len: usize) -> Result<String, u64> {
    if ptr == 0 {
        return Err(EINVAL);
    }
    let mut bytes = Vec::with_capacity(16);
    for i in 0..max_len {
        // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
        // already has.
        let b = unsafe { *((ptr as *const u8).add(i)) };
        if b == 0 {
            return String::from_utf8(bytes).map_err(|_| EINVAL);
        }
        bytes.push(b);
    }
    Err(ENAMETOOLONG)
}

fn insert_by_priority(messages: &mut Vec<Message>, priority: u32, data: Vec<u8>) {
    let pos = messages
        .iter()
        .position(|m| m.priority < priority)
        .unwrap_or(messages.len());
    messages.insert(pos, Message { priority, data });
}

/// Wakes every process blocked in `do_mq_timedreceive` on `mq_id` -- returns whether it woke at
/// least one, which `do_mq_timedsend` needs to decide whether an empty-to-non-empty `mq_notify`
/// registration should actually fire (real semantics: only when *no* thread was already blocked
/// waiting, see `do_mq_timedsend`'s own doc comment).
fn wake_blocked_receivers(mq_id: u64) -> bool {
    let mut table = process::table().lock();
    let mut woke = false;
    for (&pid, proc) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::WaitingForMqData(id, _)) = proc.state
            && id == mq_id
        {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
            woke = true;
        }
    }
    woke
}

fn wake_blocked_senders(mq_id: u64) {
    let mut table = process::table().lock();
    for (&pid, proc) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::WaitingForMqSpace(id, _)) = proc.state
            && id == mq_id
        {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}

/// `at_ptr == 0` -- the plain `mq_send`/`mq_receive` wrapper's own null-timeout case -- blocks
/// indefinitely (`u64::MAX`, see `BlockReason::WaitingForMqData`'s own doc comment for why that's
/// a safe sentinel on this kernel). Otherwise reads a real `struct timespec` and converts it via
/// `process::abstime_to_ticks`, always against `CLOCK_REALTIME` (`0`) -- real POSIX
/// `mq_timedsend`/`mq_timedreceive`'s own `at` argument is *always* wall-clock, never
/// configurable the way `timer_settime`'s `clockid` is.
fn resolve_deadline(at_ptr: u64) -> Result<u64, u64> {
    if at_ptr == 0 {
        return Ok(u64::MAX);
    }
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let (sec, nsec) = unsafe {
        let ts = at_ptr as *const i64;
        (*ts, *ts.add(1))
    };
    if !(0..1_000_000_000).contains(&nsec) {
        return Err(EINVAL);
    }
    const CLOCK_REALTIME: u64 = 0;
    Ok(process::abstime_to_ticks(CLOCK_REALTIME, sec, nsec))
}

/// `SYS_MQ_OPEN` (`536`, item 11 of the pre-reserved batch) -- matches real `mq_open(2)`'s exact
/// `(name, flags, mode, attr)` wire format, no musl call-site patch needed (see this module's own
/// doc comment for why `name` is a raw NUL-terminated pointer here, not length-prefixed). `mode`
/// is accepted but unused -- this port has no permission model for the mqueue namespace, same
/// honesty tier as `oxfs`'s own pre-permission-model days.
pub(crate) fn do_mq_open(name_ptr: u64, flags: u64, mode: u64, attr_ptr: u64) -> Result<u64, u64> {
    let _ = mode;
    let name = read_cstr(name_ptr, MQ_NAME_MAX)?;
    if name.is_empty() {
        return Err(EINVAL);
    }
    let creat = flags & O_CREAT != 0;
    let excl = flags & O_EXCL != 0;

    let mut names = NAMES.lock();
    let mq_id = if let Some(&id) = names.get(&name) {
        if creat && excl {
            return Err(EEXIST);
        }
        id
    } else {
        if !creat {
            return Err(ENOENT);
        }
        let (max_msg, msg_size) = if attr_ptr != 0 {
            // SAFETY: same known pointer-validation gap every other user-memory read in this
            // codebase already has.
            let attr = unsafe { (attr_ptr as *const RawMqAttr).read_unaligned() };
            (attr.mq_maxmsg, attr.mq_msgsize)
        } else {
            (MQ_DEFAULT_MAXMSG, MQ_DEFAULT_MSGSIZE)
        };
        if max_msg <= 0 || msg_size <= 0 || max_msg > MQ_MAX_MAXMSG || msg_size > MQ_MAX_MSGSIZE {
            return Err(EINVAL);
        }
        let id = {
            let mut next = NEXT_MQ_ID.lock();
            let v = *next;
            *next += 1;
            v
        };
        QUEUES.lock().insert(
            id,
            MessageQueue {
                max_msg,
                msg_size,
                messages: Vec::new(),
                open_count: 0,
                unlinked: false,
                notify: None,
                notify_owner_fd: None,
            },
        );
        names.insert(name, id);
        id
    };
    drop(names);

    if let Some(q) = QUEUES.lock().get_mut(&mq_id) {
        q.open_count += 1;
    }

    let fd = crate::fs::fd::oxidebsd_alloc_fd();
    MQ_ENDS.lock().insert(
        fd,
        MqEnd {
            mq_id,
            access: flags & O_ACCMODE,
        },
    );
    crate::fs::fd::oxidebsd_register_fd_ops(fd, mq_read_denied, mq_write_denied, mq_close);
    if flags & (O_NONBLOCK as u64) != 0 {
        crate::fs::fd::set_nonblocking(fd, true);
    }
    Ok(fd)
}

extern "C" fn mq_read_denied(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -(EBADF as i64)
}

extern "C" fn mq_write_denied(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -(EBADF as i64)
}

/// Registered as this mqd's `close` callback -- real `mq_close(3)` is a bare `syscall(SYS_close,
/// mqd)` (see this module's own doc comment), so this fires from the ordinary `SYS_CLOSE` path via
/// `crate::fs::fd`'s own refcounted teardown, not a dedicated syscall. Decrements `open_count` and
/// only actually removes the queue once it's both unreferenced and already `mq_unlink`ed.
extern "C" fn mq_close(real_fd: u64) -> i64 {
    let Some(end) = MQ_ENDS.lock().remove(&real_fd) else {
        return -(EBADF as i64);
    };
    let mut queues = QUEUES.lock();
    if let Some(q) = queues.get_mut(&end.mq_id) {
        if q.notify_owner_fd == Some(real_fd) {
            q.notify = None;
            q.notify_owner_fd = None;
        }
        q.open_count = q.open_count.saturating_sub(1);
        if q.open_count == 0 && q.unlinked {
            queues.remove(&end.mq_id);
        }
    }
    0
}

/// `SYS_MQ_UNLINK` (`537`, item 12) -- matches real `mq_unlink(2)`'s exact single-argument wire
/// format (`third_party/musl/src/mq/mq_unlink.c` is a bare `__syscall(SYS_mq_unlink, name)`, no
/// call-site patch needed). Removes the name immediately; the queue itself survives until every
/// open descriptor closes (`mq_close`'s own doc comment).
pub(crate) fn do_mq_unlink(name_ptr: u64) -> Result<u64, u64> {
    let name = read_cstr(name_ptr, MQ_NAME_MAX)?;
    let mut names = NAMES.lock();
    let Some(id) = names.remove(&name) else {
        return Err(ENOENT);
    };
    drop(names);
    let mut queues = QUEUES.lock();
    if let Some(q) = queues.get_mut(&id) {
        if q.open_count == 0 {
            queues.remove(&id);
        } else {
            q.unlinked = true;
        }
    }
    Ok(0)
}

/// `SYS_MQ_TIMEDSEND` (`538`, item 13) -- `mqd_and_len` packs the real `(mqd, len)` pair (see this
/// module's own doc comment on the musl-side patch); `msg_ptr`/`prio` match real `mq_timedsend`'s
/// own remaining two register args, `at_ptr` the timeout (`resolve_deadline`).
///
/// Inserting into a previously-empty queue is the one case that can trigger `mq_notify`: real
/// POSIX semantics only fire the registered notification when the queue transitions empty ->
/// non-empty *and* no thread was already blocked in `mq_timedreceive` waiting for exactly this --
/// `wake_blocked_receivers`'s own return value (did it actually wake someone) is what decides
/// that, checked *after* the wake attempt so there's no race between "check if anyone's waiting"
/// and "wake them."
pub(crate) fn do_mq_timedsend(
    mqd_and_len: u64,
    msg_ptr: u64,
    prio: u64,
    at_ptr: u64,
) -> Result<u64, u64> {
    let mqd = mqd_and_len & 0xffff_ffff;
    let len = (mqd_and_len >> 32) as usize;
    if prio >= MQ_PRIO_MAX {
        return Err(EINVAL);
    }
    let Some(real_fd) = crate::fs::fd::real_fd_of(mqd) else {
        return Err(EBADF);
    };
    let Some(end) = MQ_ENDS.lock().get(&real_fd).copied() else {
        return Err(EBADF);
    };
    if end.access == 0 {
        // O_RDONLY
        return Err(EBADF);
    }
    let deadline = resolve_deadline(at_ptr)?;

    loop {
        let mut fire_notify = None;
        {
            let mut queues = QUEUES.lock();
            let Some(q) = queues.get_mut(&end.mq_id) else {
                return Err(EBADF);
            };
            if len > q.msg_size as usize {
                return Err(EMSGSIZE);
            }
            if (q.messages.len() as i64) < q.max_msg {
                let was_empty = q.messages.is_empty();
                // SAFETY: same known pointer-validation gap every other user-memory read in this
                // codebase already has.
                let data =
                    unsafe { core::slice::from_raw_parts(msg_ptr as *const u8, len) }.to_vec();
                insert_by_priority(&mut q.messages, prio as u32, data);
                if was_empty {
                    fire_notify = match &q.notify {
                        Some(Notify::Signal { pid, signo }) => Some((*pid, *signo)),
                        _ => None,
                    };
                }
            } else {
                if crate::fs::fd::is_nonblocking(real_fd) {
                    return Err(EAGAIN);
                }
                if crate::cpu::interrupts::ticks() >= deadline {
                    return Err(ETIMEDOUT);
                }
                let caller = scheduler::current_pid();
                let mut table = process::table().lock();
                let proc = table.get_mut(&caller).unwrap();
                // Real POSIX: a signal that will invoke a caught handler interrupts a blocking
                // mq_send() early -- same reasoning do_mq_timedreceive's own identical check above
                // already establishes.
                if process::signals::has_interrupting_signal(proc) {
                    drop(table);
                    drop(queues);
                    return Err(EINTR);
                }
                proc.state =
                    ProcState::Blocked(BlockReason::WaitingForMqSpace(end.mq_id, deadline));
                drop(table);
                drop(queues);
                scheduler::schedule();
                continue;
            }
        } // queues lock dropped

        let had_waiting_receiver = wake_blocked_receivers(end.mq_id);
        if had_waiting_receiver {
            fire_notify = None;
        }
        if let Some((pid, signo)) = fire_notify {
            // One-shot: consumed the instant it fires, matching real POSIX semantics -- the
            // process must re-register after every notification it receives.
            if let Some(q) = QUEUES.lock().get_mut(&end.mq_id) {
                q.notify = None;
                q.notify_owner_fd = None;
            }
            let _ = process::do_kill(pid, pid as i64, signo as i64);
        }
        return Ok(0);
    }
}

/// `SYS_MQ_TIMEDRECEIVE` (`539`, item 14) -- same `mqd_and_len` packing as `do_mq_timedsend`;
/// `prio_ptr` is real `mq_timedreceive`'s own output parameter (the received message's priority),
/// left untouched if null (real POSIX allows a null `msg_prio`).
///
/// **`at_ptr` is deliberately resolved lazily, only once actually about to block** -- real POSIX:
/// "If the message can be removed from the queue immediately, the operation shall never fail and
/// the validity of `abs_timeout` need not be checked" (closes `mq_timedreceive/10-2.c`, which
/// passes a deliberately-invalid `tv_nsec` alongside an already-available message).
pub(crate) fn do_mq_timedreceive(
    mqd_and_len: u64,
    msg_ptr: u64,
    prio_ptr: u64,
    at_ptr: u64,
) -> Result<u64, u64> {
    let mqd = mqd_and_len & 0xffff_ffff;
    let len = (mqd_and_len >> 32) as usize;
    let Some(real_fd) = crate::fs::fd::real_fd_of(mqd) else {
        return Err(EBADF);
    };
    let Some(end) = MQ_ENDS.lock().get(&real_fd).copied() else {
        return Err(EBADF);
    };
    if end.access == 1 {
        // O_WRONLY
        return Err(EBADF);
    }

    loop {
        let msg = {
            let mut queues = QUEUES.lock();
            let Some(q) = queues.get_mut(&end.mq_id) else {
                return Err(EBADF);
            };
            if (len as i64) < q.msg_size {
                return Err(EMSGSIZE);
            }
            if !q.messages.is_empty() {
                q.messages.remove(0)
            } else {
                if crate::fs::fd::is_nonblocking(real_fd) {
                    return Err(EAGAIN);
                }
                let deadline = resolve_deadline(at_ptr)?;
                if crate::cpu::interrupts::ticks() >= deadline {
                    return Err(ETIMEDOUT);
                }
                let caller = scheduler::current_pid();
                let mut table = process::table().lock();
                let proc = table.get_mut(&caller).unwrap();
                // Real POSIX: a signal that will invoke a caught handler interrupts a blocking
                // mq_receive() early -- checked before (re-)blocking, same "avoid a lost wakeup"
                // reasoning do_pause's/do_nanosleep's own identical check already establishes. See
                // signals::wake_if_mq_waiting's own doc comment for why this hook is real,
                // load-bearing plumbing here, not just a nicety.
                if process::signals::has_interrupting_signal(proc) {
                    drop(table);
                    drop(queues);
                    return Err(EINTR);
                }
                proc.state = ProcState::Blocked(BlockReason::WaitingForMqData(end.mq_id, deadline));
                drop(table);
                drop(queues);
                scheduler::schedule();
                continue;
            }
        }; // queues lock dropped

        // SAFETY: same known pointer-validation gap every other user-memory write in this
        // codebase already has.
        unsafe {
            core::ptr::copy_nonoverlapping(msg.data.as_ptr(), msg_ptr as *mut u8, msg.data.len());
        }
        if prio_ptr != 0 {
            unsafe { (prio_ptr as *mut u32).write_unaligned(msg.priority) };
        }
        wake_blocked_senders(end.mq_id);
        return Ok(msg.data.len() as u64);
    }
}

/// `SYS_MQ_NOTIFY` (`540`, item 15) -- matches real `mq_notify(2)`'s exact `(mqd, sev_ptr)` wire
/// format (`third_party/musl/src/mq/mq_notify.c` issues this raw syscall directly whenever
/// `sev->sigev_notify != SIGEV_THREAD`, no call-site patch needed). `sev_ptr == 0` deregisters.
/// See this module's own doc comment for `SIGEV_SIGNAL`'s real `do_kill`-based delivery and why
/// `SIGEV_THREAD`/`SIGEV_THREAD_ID` are `EINVAL`.
pub(crate) fn do_mq_notify(mqd: u64, sev_ptr: u64) -> Result<u64, u64> {
    let Some(real_fd) = crate::fs::fd::real_fd_of(mqd) else {
        return Err(EBADF);
    };
    let Some(end) = MQ_ENDS.lock().get(&real_fd).copied() else {
        return Err(EBADF);
    };
    let mut queues = QUEUES.lock();
    let Some(q) = queues.get_mut(&end.mq_id) else {
        return Err(EBADF);
    };

    if sev_ptr == 0 {
        if q.notify_owner_fd == Some(real_fd) {
            q.notify = None;
            q.notify_owner_fd = None;
        }
        return Ok(0);
    }
    if q.notify.is_some() {
        return Err(EBUSY);
    }

    // `struct sigevent` (`third_party/musl/include/signal.h`): `sigev_value` (8 bytes) at offset
    // 0, `sigev_signo`/`sigev_notify` (both `int`) at offsets 8/12.
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let sigev_signo = unsafe { *((sev_ptr + 8) as *const i32) };
    let sigev_notify = unsafe { *((sev_ptr + 12) as *const i32) };
    const SIGEV_SIGNAL: i32 = 0;
    const SIGEV_NONE: i32 = 1;
    match sigev_notify {
        SIGEV_NONE => q.notify = Some(Notify::None),
        SIGEV_SIGNAL => {
            // Real Linux's own `valid_signal()` check for this path accepts `0..=_NSIG` (`64`
            // here, `SIGRTMAX`) -- notably including `0`, unlike `kill(2)`'s own stricter
            // `1..=31`/RT range (`mq_close/2-1.c` registers a real notification with
            // `sigev_signo = 0` and expects it to succeed; a fired signal-`0` notification is
            // just a harmless no-op through `do_kill`'s own existing `sig == 0` existence-check
            // convention, same as `kill(pid, 0)`).
            if !(0..=64).contains(&sigev_signo) {
                return Err(EINVAL);
            }
            q.notify = Some(Notify::Signal {
                pid: scheduler::current_pid(),
                signo: sigev_signo as u64,
            });
        }
        // SIGEV_THREAD/SIGEV_THREAD_ID -- no clone(2)/AF_NETLINK on this kernel, see this module's
        // own doc comment.
        _ => return Err(EINVAL),
    }
    q.notify_owner_fd = Some(real_fd);
    Ok(0)
}

/// `SYS_MQ_GETSETATTR` (`541`, item 16, last of the batch) -- matches real `mq_getsetattr(2)`'s
/// exact `(mqd, new, old)` wire format (both `mq_getattr`/`mq_setattr` are pure musl-side wrappers
/// around this one syscall, see `third_party/musl/src/mq/mq_{get,set}attr.c`). Real semantics:
/// only `mq_flags`'s `O_NONBLOCK` bit is actually settable through `new` -- `mq_maxmsg`/
/// `mq_msgsize` are fixed at creation and silently ignored here too, matching real Linux.
pub(crate) fn do_mq_getsetattr(mqd: u64, new_ptr: u64, old_ptr: u64) -> Result<u64, u64> {
    let Some(real_fd) = crate::fs::fd::real_fd_of(mqd) else {
        return Err(EBADF);
    };
    let Some(end) = MQ_ENDS.lock().get(&real_fd).copied() else {
        return Err(EBADF);
    };

    if old_ptr != 0 {
        let queues = QUEUES.lock();
        let Some(q) = queues.get(&end.mq_id) else {
            return Err(EBADF);
        };
        let attr = RawMqAttr {
            mq_flags: if crate::fs::fd::is_nonblocking(real_fd) {
                O_NONBLOCK
            } else {
                0
            },
            mq_maxmsg: q.max_msg,
            mq_msgsize: q.msg_size,
            mq_curmsgs: q.messages.len() as i64,
            unused: [0; 4],
        };
        // SAFETY: same known pointer-validation gap every other user-memory write in this
        // codebase already has.
        unsafe { (old_ptr as *mut RawMqAttr).write_unaligned(attr) };
    }
    if new_ptr != 0 {
        // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
        // already has.
        let new_flags = unsafe { (new_ptr as *const RawMqAttr).read_unaligned() }.mq_flags;
        crate::fs::fd::set_nonblocking(real_fd, new_flags & O_NONBLOCK != 0);
    }
    Ok(0)
}
