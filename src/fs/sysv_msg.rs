//! Real SysV message queues (`msgget`/`msgsnd`/`msgrcv`/`msgctl` -- items 25-28, the last
//! sub-batch of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of
//! implementation" batch, `SYS_MSGGET = 550` through `SYS_MSGCTL = 553`). No live caller anywhere
//! in the current roster (confirmed by that doc -- `ipcrm`/`ipcs` were already cut from the
//! BusyBox roster before v0.1 specifically because this didn't exist yet).
//!
//! **A fundamentally different lifecycle from `src/fs/mqueue.rs`'s POSIX message queues, despite
//! the superficial similarity** -- worth stating plainly since this is the second "message queue"
//! subsystem in this codebase:
//! - Identified by an integer `key_t`, not a name, via `msgget(key, flag)`. `IPC_PRIVATE` (`0`)
//!   always allocates a fresh, unfindable-by-key queue (real semantics -- every `IPC_PRIVATE` call
//!   is its own new queue, `KEYS` below is never consulted for it).
//! - **`msgget` returns a bare integer id, not a real fd** -- no `crate::fs::fd` involvement at
//!   all. A SysV queue has no "open"/"close" step; it exists system-wide from `msgget` until an
//!   explicit `msgctl(IPC_RMID)` (or the whole kernel reboots) -- real POSIX/SysV IPC semantics,
//!   the opposite lifecycle from a POSIX mqueue's real-fd-backed, refcounted one.
//! - **Real `ipc_perm`-based permission checking** (`check_access` below): `msgsnd`/`msgrcv` need
//!   the real owner/group/other rwx bit for the caller's relationship to the queue (exactly like a
//!   file's own mode bits); `msgctl`'s `IPC_SET`/`IPC_RMID` instead require the caller be root, the
//!   owner (`uid`), or the creator (`cuid`) -- a stricter check than plain write permission, same
//!   real SysV IPC distinction. No live caller to test against, but implemented for real rather
//!   than left a no-op, matching this codebase's usual honesty tier for a from-scratch subsystem.
//! - **No timeout concept at all** -- unlike `mq_timedsend`/`mq_timedreceive`, real `msgsnd`/
//!   `msgrcv` only ever block indefinitely or (`IPC_NOWAIT`) fail immediately; there's no
//!   `semtimedop`-style deadline argument to plumb through, so no timer-IRQ deadline scan is
//!   needed here the way `crate::fs::mqueue` needed one.
//! - **`msgrcv`'s `msgtyp` selection is real, not simplified**: `0` = the oldest message in the
//!   queue regardless of type (real FIFO); `> 0` = the oldest message with that exact `mtype`
//!   (or, with `MSG_EXCEPT`, the oldest message with any *other* `mtype`); `< 0` = among messages
//!   with `mtype <= |msgtyp|`, the oldest message of the *smallest* such `mtype` -- see
//!   `find_matching_index`'s own doc comment.
//!
//! **`msgrcv` is the one real wire-format wrinkle**: real Linux needs 5 syscall args (`q, m, len,
//! type, flag`) and this ABI only carries 4 -- `third_party/musl/src/ipc/msgrcv.c` is patched
//! (`oxidebsd` branch, see that file's own comment) to pack `q`/`flag` into a single register
//! (`high 32 = flag, low 32 = q`), same shape `mq_timedsend`/`mq_timedreceive`'s own patches
//! already established. `msgget`/`msgsnd`/`msgctl` all already fit in 4 real register args, no
//! patch needed beyond the number remap already sitting in `bits/syscall.h.in`.
//!
//! **`msgctl`'s real `cmd` argument always arrives with `IPC_64` (`0x100`) OR'd in** -- musl's own
//! `IPC_CMD(cmd)` macro does this unconditionally on every call (`third_party/musl/src/ipc/
//! msgctl.c`), a real glibc/musl-shared convention for "this caller understands the modern
//! `struct msqid_ds` layout" (this port's `IPC_TIME64` is always `0` here -- x86_64 is already
//! 64-bit `time_t`, so the `#if IPC_TIME64` branch in that file never compiles in at all, confirmed
//! directly: `IPC_STAT` is `2`, `IPC_TIME64 = (IPC_STAT & 0x100) = 0`). `do_msgctl` masks `cmd`
//! with `!IPC_64` before matching.
//!
//! **Blocking reuses this codebase's own established shape** one more time (`fs/pipe.rs`'s "block,
//! `schedule()`, loop and re-check" pattern, same as `fs/mqueue.rs`): `BlockReason::
//! WaitingForSysvMsgSend`/`WaitingForSysvMsgRecv`, woken by the matching send/receive draining the
//! condition. `msgctl(IPC_RMID)` needs no distinct wake signal of its own -- it just removes the
//! queue from `QUEUES` and wakes everyone blocked on it; the woken loop finds the id gone and
//! returns a real `EIDRM`, the same "re-check the real condition from scratch after waking, never
//! trust the wake reason alone" discipline every blocking primitive in this codebase already
//! follows.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use spin::Mutex;

use crate::fs::sysv_ipc::{IPC_64, IPC_RMID, IPC_SET, IPC_STAT, RawIpcPerm};
use crate::process::{self, BlockReason, Pid, ProcState};
use crate::process::scheduler;
use crate::syscall::{E2BIG, EACCES, EAGAIN, EIDRM, EINVAL, ENOENT, ENOMSG};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const MSG_NOERROR: u64 = 0o10000;
const MSG_EXCEPT: u64 = 0o20000;

/// Real Linux's own `MSGMNB` default (max total bytes queued at once) -- what a fresh `msgget`
/// with no privileged override starts at; adjustable per-queue via `msgctl(IPC_SET)`.
const SYSV_MSG_DEFAULT_QBYTES: u64 = 16384;
/// Real Linux's own `MSGMAX` (a single message's hard content-length ceiling, independent of a
/// specific queue's own `qbytes`).
const SYSV_MSGMAX: u64 = 8192;
/// A small, sane cap on live queues system-wide -- no privileged-override/`rlimit`-driven ceiling
/// exists here the way real Linux's `MSGMNI` is (root-tunable via `/proc/sys/kernel/msgmni`); no
/// live caller to size this against, same "small, plausible number" reasoning
/// `MAX_POSIX_TIMERS`/`crate::fs::mqueue`'s own caps already use.
const MAX_SYSV_MSG_QUEUES: usize = 32;

struct SysvMessage {
    mtype: i64,
    data: Vec<u8>,
}

struct MsgQueue {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    /// Low 9 bits are the real rwx permission bits (`msgget`'s own `flag & 0777`); nothing above
    /// that is meaningful (no `SysV` "extra" mode bits this port interprets).
    mode: u32,
    qbytes: u64,
    /// Real, not honest-zero: `crate::cpu::rtc::unix_epoch_seconds()` at creation/every successful
    /// `msgsnd`/`msgrcv`/`msgctl(IPC_SET)` -- cheap (the same CMOS read `CLOCK_REALTIME` already
    /// uses) and meaningfully more useful than a placeholder for a struct whose whole job is
    /// reporting these three timestamps.
    stime: i64,
    rtime: i64,
    ctime: i64,
    lspid: Pid,
    lrpid: Pid,
    /// FIFO overall send order -- `msgrcv`'s own `msgtyp` filtering scans this without reordering
    /// it, see `find_matching_index`'s own doc comment.
    messages: Vec<SysvMessage>,
}

impl MsgQueue {
    fn cbytes(&self) -> u64 {
        self.messages.iter().map(|m| m.data.len() as u64).sum()
    }
}

static NEXT_MSQID: Mutex<i32> = Mutex::new(1);
static QUEUES: Mutex<BTreeMap<i32, MsgQueue>> = Mutex::new(BTreeMap::new());
/// Non-`IPC_PRIVATE` keys only -- an `IPC_PRIVATE` queue is never findable by key again, real
/// semantics (see this module's own doc comment).
static KEYS: Mutex<BTreeMap<i32, i32>> = Mutex::new(BTreeMap::new());

/// musl's own `struct msqid_ds` on x86_64 (`third_party/musl/arch/generic/bits/msg.h`) -- same
/// probe-confirmed rigor as `crate::fs::sysv_ipc::RawIpcPerm` above (120 bytes total).
#[repr(C)]
struct RawMsqidDs {
    msg_perm: RawIpcPerm,
    msg_stime: i64,
    msg_rtime: i64,
    msg_ctime: i64,
    msg_cbytes: u64,
    msg_qnum: u64,
    msg_qbytes: u64,
    msg_lspid: i32,
    msg_lrpid: i32,
    unused: [u64; 2],
}

const _: () = assert!(core::mem::size_of::<RawMsqidDs>() == 120);

/// Real SysV IPC rwx permission check: `uid == 0` (root) bypasses entirely; otherwise picks the
/// owner/group/other bit exactly like a file's own mode bits, comparing against the queue's real
/// `uid`/`gid` (first match wins) -- same shape `modules/oxfs`'s own `check_access` already
/// established for inode permissions, just against `MsgQueue` instead.
fn check_access(q: &MsgQueue, uid: u32, gid: u32, want_write: bool) -> bool {
    crate::fs::sysv_ipc::check_access(q.uid, q.gid, q.mode, uid, gid, want_write)
}

fn is_owner_or_creator(q: &MsgQueue, uid: u32) -> bool {
    crate::fs::sysv_ipc::is_owner_or_creator(q.uid, q.cuid, uid)
}

fn wake_blocked_senders(msqid: i32) {
    let mut table = process::table().lock();
    for (&pid, proc) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::WaitingForSysvMsgSend(id)) = proc.state
            && id == msqid as u64
        {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}

fn wake_blocked_receivers(msqid: i32) {
    let mut table = process::table().lock();
    for (&pid, proc) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::WaitingForSysvMsgRecv(id)) = proc.state
            && id == msqid as u64
        {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}

/// `SYS_MSGGET` (`550`, item 25) -- matches real `msgget(2)`'s exact `(key, flag)` wire format, no
/// musl call-site patch needed. `IPC_PRIVATE` always creates a fresh, key-less queue;
/// otherwise looks up `key` in `KEYS`, applying real `IPC_CREAT`/`IPC_EXCL` semantics.
pub(crate) fn do_msgget(key: u64, flag: u64) -> Result<u64, u64> {
    let key = key as i32;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let creat = flag & IPC_CREAT != 0;
    let excl = flag & IPC_EXCL != 0;

    if key != IPC_PRIVATE {
        let existing = KEYS.lock().get(&key).copied();
        if let Some(msqid) = existing {
            if creat && excl {
                return Err(crate::syscall::EEXIST);
            }
            let queues = QUEUES.lock();
            let q = queues.get(&msqid).expect("KEYS entry with no matching QUEUES entry");
            if !check_access(q, uid, gid, false) {
                return Err(EACCES);
            }
            return Ok(msqid as u64);
        }
        if !creat {
            return Err(ENOENT);
        }
    }

    let mut queues = QUEUES.lock();
    if queues.len() >= MAX_SYSV_MSG_QUEUES {
        return Err(EAGAIN);
    }
    let msqid = {
        let mut next = NEXT_MSQID.lock();
        let v = *next;
        *next += 1;
        v
    };
    let now = crate::cpu::rtc::unix_epoch_seconds();
    queues.insert(
        msqid,
        MsgQueue {
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode: (flag & 0o777) as u32,
            qbytes: SYSV_MSG_DEFAULT_QBYTES,
            stime: 0,
            rtime: 0,
            ctime: now,
            lspid: 0,
            lrpid: 0,
            messages: Vec::new(),
        },
    );
    drop(queues);
    if key != IPC_PRIVATE {
        KEYS.lock().insert(key, msqid);
    }
    Ok(msqid as u64)
}

/// `SYS_MSGSND` (`551`, item 26) -- matches real `msgsnd(2)`'s exact `(q, m, len, flag)` wire
/// format, no musl call-site patch needed (already fits this ABI's 4 real register args). `m`
/// points at a real `{long mtype; char mtext[len];}` buffer -- `mtype` must be `>= 1` (real POSIX
/// requirement, `EINVAL` otherwise).
pub(crate) fn do_msgsnd(q: u64, m: u64, len: u64, flag: u64) -> Result<u64, u64> {
    let msqid = q as i32;
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let mtype = unsafe { *(m as *const i64) };
    if mtype < 1 {
        return Err(EINVAL);
    }
    if len > SYSV_MSGMAX {
        return Err(EINVAL);
    }
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let caller = scheduler::current_pid();

    loop {
        {
            let mut queues = QUEUES.lock();
            let Some(qref) = queues.get_mut(&msqid) else {
                return Err(EIDRM);
            };
            if !check_access(qref, uid, gid, true) {
                return Err(EACCES);
            }
            if len > qref.qbytes {
                return Err(EINVAL);
            }
            if qref.cbytes() + len <= qref.qbytes {
                // SAFETY: same known pointer-validation gap every other user-memory read in this
                // codebase already has.
                let data = unsafe {
                    core::slice::from_raw_parts((m + 8) as *const u8, len as usize)
                }
                .to_vec();
                qref.messages.push(SysvMessage { mtype, data });
                qref.lspid = caller;
                qref.stime = crate::cpu::rtc::unix_epoch_seconds();
                drop(queues);
                wake_blocked_receivers(msqid);
                return Ok(0);
            }
            if flag & IPC_NOWAIT != 0 {
                return Err(EAGAIN);
            }
            let mut table = process::table().lock();
            table.get_mut(&caller).unwrap().state =
                ProcState::Blocked(BlockReason::WaitingForSysvMsgSend(msqid as u64));
        }
        scheduler::schedule();
    }
}

/// `SYS_MSGRCV` (`552`, item 27) -- `q_and_flag` packs the real `(q, flag)` pair (see this
/// module's own doc comment on the musl-side patch); `m`/`len`/`msgtyp` match real `msgrcv`'s own
/// remaining three register args.
pub(crate) fn do_msgrcv(q_and_flag: u64, m: u64, len: u64, msgtyp: u64) -> Result<u64, u64> {
    let msqid = (q_and_flag & 0xffff_ffff) as i32;
    let flag = q_and_flag >> 32;
    let msgtyp = msgtyp as i64;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let caller = scheduler::current_pid();
    let except = flag & MSG_EXCEPT != 0;

    loop {
        {
            let mut queues = QUEUES.lock();
            let Some(qref) = queues.get_mut(&msqid) else {
                return Err(EIDRM);
            };
            if !check_access(qref, uid, gid, false) {
                return Err(EACCES);
            }
            if let Some(idx) = find_matching_index(&qref.messages, msgtyp, except) {
                // Real semantics: a message that's too big for the caller's buffer (without
                // MSG_NOERROR) is *not* consumed -- it must stay queued for a future receive with
                // a bigger buffer or MSG_NOERROR set. Checked by peeking *before* removing, not
                // after (removing first would silently destroy the message on a failed receive).
                if qref.messages[idx].data.len() as u64 > len && flag & MSG_NOERROR == 0 {
                    return Err(E2BIG);
                }
                let msg = qref.messages.remove(idx);
                qref.lrpid = caller;
                qref.rtime = crate::cpu::rtc::unix_epoch_seconds();
                drop(queues);
                let copy_len = (msg.data.len() as u64).min(len) as usize;
                // SAFETY: same known pointer-validation gap every other user-memory write in
                // this codebase already has.
                unsafe {
                    (m as *mut i64).write_unaligned(msg.mtype);
                    core::ptr::copy_nonoverlapping(
                        msg.data.as_ptr(),
                        (m + 8) as *mut u8,
                        copy_len,
                    );
                }
                wake_blocked_senders(msqid);
                return Ok(copy_len as u64);
            }
            if flag & IPC_NOWAIT != 0 {
                return Err(ENOMSG);
            }
            let mut table = process::table().lock();
            table.get_mut(&caller).unwrap().state =
                ProcState::Blocked(BlockReason::WaitingForSysvMsgRecv(msqid as u64));
        }
        scheduler::schedule();
    }
}

/// Real `msgrcv(2)` `msgtyp` selection (see `man 2 msgrcv`): `0` = the oldest message in the
/// queue, any type; `> 0` (without `MSG_EXCEPT`) = the oldest message of exactly that `mtype`, or
/// (with `MSG_EXCEPT`) the oldest message of any *other* `mtype`; `< 0` = among every message
/// whose `mtype` is `<= |msgtyp|`, the oldest message carrying the *smallest* such `mtype` --
/// **not** simply the oldest message satisfying the bound. `messages` is always FIFO overall
/// (`do_msgsnd` only ever pushes), so "oldest" is always "lowest index."
fn find_matching_index(messages: &[SysvMessage], msgtyp: i64, except: bool) -> Option<usize> {
    if msgtyp == 0 {
        return if messages.is_empty() { None } else { Some(0) };
    }
    if msgtyp > 0 {
        return if except {
            messages.iter().position(|m| m.mtype != msgtyp)
        } else {
            messages.iter().position(|m| m.mtype == msgtyp)
        };
    }
    let limit = -msgtyp;
    let min_type = messages.iter().filter(|m| m.mtype <= limit).map(|m| m.mtype).min()?;
    messages.iter().position(|m| m.mtype == min_type)
}

/// `SYS_MSGCTL` (`553`, item 28, last of the batch) -- matches real `msgctl(2)`'s exact
/// `(q, cmd, buf)` wire format, no musl call-site patch needed. Only `IPC_STAT`/`IPC_SET`/
/// `IPC_RMID` are implemented (`MSG_STAT`/`MSG_STAT_ANY`/`IPC_INFO`/`MSG_INFO` are real `/proc`-
/// introspection-shaped commands with no live caller -- honest `EINVAL`, not a silent no-op).
pub(crate) fn do_msgctl(q: u64, cmd: u64, buf_ptr: u64) -> Result<u64, u64> {
    let msqid = q as i32;
    let real_cmd = cmd & !IPC_64;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;

    match real_cmd {
        IPC_STAT => {
            let queues = QUEUES.lock();
            let qref = queues.get(&msqid).ok_or(EIDRM)?;
            if !check_access(qref, uid, gid, false) {
                return Err(EACCES);
            }
            let raw = RawMsqidDs {
                msg_perm: RawIpcPerm {
                    key: qref.key,
                    uid: qref.uid,
                    gid: qref.gid,
                    cuid: qref.cuid,
                    cgid: qref.cgid,
                    mode: qref.mode,
                    seq: 0,
                    pad1: 0,
                    pad2: 0,
                },
                msg_stime: qref.stime,
                msg_rtime: qref.rtime,
                msg_ctime: qref.ctime,
                msg_cbytes: qref.cbytes(),
                msg_qnum: qref.messages.len() as u64,
                msg_qbytes: qref.qbytes,
                msg_lspid: qref.lspid as i32,
                msg_lrpid: qref.lrpid as i32,
                unused: [0; 2],
            };
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // codebase already has.
            unsafe { (buf_ptr as *mut RawMsqidDs).write_unaligned(raw) };
            Ok(0)
        }
        IPC_SET => {
            let mut queues = QUEUES.lock();
            let qref = queues.get_mut(&msqid).ok_or(EIDRM)?;
            if !is_owner_or_creator(qref, uid) {
                return Err(EACCES);
            }
            // SAFETY: same known pointer-validation gap every other user-memory read in this
            // codebase already has.
            let raw = unsafe { (buf_ptr as *const RawMsqidDs).read_unaligned() };
            qref.uid = raw.msg_perm.uid;
            qref.gid = raw.msg_perm.gid;
            qref.mode = raw.msg_perm.mode & 0o777;
            qref.qbytes = raw.msg_qbytes;
            qref.ctime = crate::cpu::rtc::unix_epoch_seconds();
            Ok(0)
        }
        IPC_RMID => {
            let mut queues = QUEUES.lock();
            let qref = queues.get(&msqid).ok_or(EIDRM)?;
            if !is_owner_or_creator(qref, uid) {
                return Err(EACCES);
            }
            let key = qref.key;
            queues.remove(&msqid);
            drop(queues);
            if key != IPC_PRIVATE {
                KEYS.lock().remove(&key);
            }
            // Every blocked sender/receiver re-checks QUEUES from scratch on wake and finds
            // msqid gone -- returns a real EIDRM, no distinct wake signal needed (see this
            // module's own doc comment).
            wake_blocked_senders(msqid);
            wake_blocked_receivers(msqid);
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}
