//! Real SysV semaphores (`semget`/`semop`/`semctl`/`semtimedop` -- items 21-24 of
//! `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of implementation"
//! batch, `SYS_SEMGET = 546` through `SYS_SEMTIMEDOP = 549`). No live caller anywhere in the
//! current roster (confirmed by that doc -- `ipcrm`/`ipcs` were already cut from the BusyBox
//! roster before v0.1 specifically because this didn't exist yet) -- built anyway, in real POSIX/
//! SysV implementation order, closing out the last sub-batch of the whole 28-syscall batch (items
//! 17-20, SysV shared memory, remain unimplemented -- see that doc's own tracking checklist).
//!
//! **Wire formats already fit this ABI's 4 real register args, unlike `msgrcv`/`mq_timedsend`/
//! `mq_timedreceive`** -- confirmed directly against every one of `external/mit/musl/src/ipc/
//! sem{get,op,ctl,timedop}.c`'s own call sites (no `SYS_ipc` multiplexer is ever defined on this
//! arch, so each issues its own direct `syscall(SYS_sem*, ...)`): `semget(key, n, fl)` (3 args),
//! `semop(id, buf, n)` (3 args), `semctl(id, num, cmd, ...)` (real Linux's own raw syscall is
//! always exactly `(id, num, IPC_CMD(cmd), arg)`, 4 args), `semtimedop(id, buf, n, ts)` (4 args)
//! -- **zero musl call-site patches needed for this entire sub-batch**, the first SysV IPC
//! sub-batch that's been true for (`msgrcv` needed one; `mq_timedsend`/`mq_timedreceive` needed
//! one each).
//!
//! **`semctl`'s 4th argument is polymorphic based on `cmd`, same as real Linux** -- musl's own
//! `union semun` is passed by value in a single register: for `SETVAL` it's the raw integer value
//! itself (not a pointer), for everything else (`IPC_STAT`/`IPC_SET`/`GETALL`/`SETALL`) it's a
//! real user pointer. `do_semctl` below branches on `cmd` before deciding which interpretation to
//! use, matching real `sys_semctl`'s own behavior.
//!
//! **A real, separate id-keyed namespace, not backed by `oxfs`** -- same "`key_t` -> id via
//! `KEYS`/`SETS`, `IPC_PRIVATE` always fresh, real `IPC_CREAT`/`IPC_EXCL` semantics, bare integer
//! id with no `crate::fs::fd` involvement" shape `crate::fs::sysv_msg` already established for
//! its own `msgget`/`KEYS`/`QUEUES`. `crate::fs::sysv_ipc` factors out the two subsystems' shared
//! `RawIpcPerm`/rwx-permission-check plumbing now that a second SysV IPC subsystem exists.
//!
//! **`semop`/`semtimedop` apply a whole `sembuf` array atomically** -- real SysV semantics: either
//! every operation in the array succeeds at once, or (if any op would block and `IPC_NOWAIT` isn't
//! set) none of them are applied and the caller blocks, then retries the *entire* array from
//! scratch once woken (same "block, `schedule()`, loop and re-check the real condition from
//! scratch" pattern every blocking primitive in this codebase already follows -- see
//! `crate::fs::sysv_msg`'s own doc comment). A negative `sem_op` decrements (blocking if it would
//! go below zero -- a real "wait"/P operation); a positive `sem_op` increments (a real "signal"/V
//! operation, always succeeds immediately); a zero `sem_op` blocks until the semaphore's value is
//! exactly zero. Real POSIX allows an implementation to pick *any* representative op for a wait
//! queue when a multi-op array blocks -- this one always picks the first op in program order that
//! couldn't proceed, both for retry ordering and as the `(semnum, waiting_for_zero)` pair
//! `BlockReason::WaitingForSemOp` carries for `semctl(GETNCNT)`/`semctl(GETZCNT)` to report a
//! real, not fabricated, count against (see that variant's own doc comment, `sys/process/mod.rs`).
//!
//! **`semtimedop`'s timeout is real-relative, not absolute** -- unlike `mq_timedsend`/
//! `mq_timedreceive`'s own `at` argument (always wall-clock `CLOCK_REALTIME`), real
//! `semtimedop(2)`'s `timeout` is a plain relative `struct timespec`, the exact same "duration,
//! converted to an absolute tick deadline via `interrupts::ticks() + ...`" shape
//! `do_nanosleep` already establishes (`resolve_relative_deadline` below mirrors that function's
//! own whole-second/sub-second tick rounding exactly) -- deliberately *not*
//! `crate::process::abstime_to_ticks` (`crate::fs::mqueue`'s own helper), which converts an
//! *absolute* timestamp against a chosen clock instead.
//!
//! **Real `SEM_UNDO` support**: every `sembuf` with `SEM_UNDO` set accumulates a signed adjustment
//! in the calling process's own `Process::sysv_sem_undo` list (`record_undo` below) -- applied
//! (added back) automatically on process termination via `apply_undo_for_exit`, called from
//! `process::lifecycle::terminate_process` *before* that function takes `PROCESS_TABLE`'s own lock
//! (see that call site's own comment for why). **Known, accepted simplification**: real Linux also
//! clears/adjusts other processes' outstanding undo entries when a `semctl(SETVAL)`/
//! `semctl(SETALL)`/`semop` on the *same* semaphore changes its value out from under an existing
//! undo adjustment -- this port doesn't track that cross-process bookkeeping (would need a global
//! scan of every process's own undo list on every value-changing call); no live caller to exercise
//! the difference, and `IPC_RMID` (the one case that matters most -- undoing into a since-removed
//! set) is already handled correctly since `apply_undo_for_exit` just finds the `semid` gone in
//! `SETS` and silently skips it, the same "re-check the real condition, a missing id is a no-op"
//! discipline `crate::fs::sysv_msg`'s own `IPC_RMID` already established.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::fs::sysv_ipc::{IPC_64, IPC_RMID, IPC_SET, IPC_STAT, RawIpcPerm};
use crate::process::scheduler;
use crate::process::{self, BlockReason, Pid, ProcState};
use crate::syscall::{EACCES, EFBIG, EIDRM, EINVAL, ENOENT, ERANGE};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const SEM_UNDO: i16 = 0o1000;
/// `IPC_NOWAIT` -- real Linux's own value, shared bit position across every SysV IPC syscall's own
/// `flag`/`sem_flg` argument (same value `crate::fs::sysv_msg`'s own `IPC_NOWAIT` already uses,
/// duplicated rather than factored into `sysv_ipc` since `msgsnd`/`msgrcv` take it as a distinct
/// `flag` register argument while `semop`/`semtimedop` take it per-op inside `sem_flg` -- different
/// enough shapes that sharing the constant alone wouldn't save much).
const IPC_NOWAIT: i16 = 0o4000;

/// Real Linux's own `SEMVMX` (`include/uapi/linux/sem.h`) -- the maximum value a single
/// semaphore may ever hold. `semctl(SETVAL)`/`SEM_UNDO` accumulation both enforce this.
const SEMVMX: i32 = 32767;
/// A small, sane cap on semaphores per set and live sets system-wide -- no privileged-override/
/// `rlimit`-driven ceiling exists here the way real Linux's `SEMMSL`/`SEMMNI` are, and no live
/// caller to size either against, same "small, plausible number" reasoning
/// `MAX_POSIX_TIMERS`/`crate::fs::sysv_msg::MAX_SYSV_MSG_QUEUES` already use.
const MAX_SEMS_PER_SET: usize = 4096;
const MAX_SYSV_SEM_SETS: usize = 32;
/// A sane bound on a single `semop`/`semtimedop` call's own `nsops` -- real Linux's own `SEMOPM`
/// default is `32`, matched here for authenticity even though nothing enforces it being a
/// meaningful limit on this port.
const MAX_SEMOPS_PER_CALL: usize = 32;

struct Semaphore {
    val: i32,
    /// pid of the last process that successfully `semop`'d or `semctl`'d this specific semaphore
    /// -- real `semctl(GETPID)`'s own backing store.
    sempid: Pid,
}

struct SemSet {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    /// Low 9 bits are the real rwx permission bits (`semget`'s own `flag & 0777`); nothing above
    /// that is meaningful, same convention `crate::fs::sysv_msg::MsgQueue::mode` already uses.
    mode: u32,
    /// Real, not honest-zero, same "cheap CMOS read, meaningfully useful" reasoning
    /// `crate::fs::sysv_msg`'s own `stime`/`rtime`/`ctime` already establish. Unlike a message
    /// queue's three-timestamp shape, a `semid_ds` only has two: `sem_otime` (last successful
    /// `semop`) and `sem_ctime` (creation, or last `semctl(IPC_SET)`/`SETVAL`/`SETALL`).
    otime: i64,
    ctime: i64,
    semas: Vec<Semaphore>,
}

fn check_access(s: &SemSet, uid: u32, gid: u32, want_write: bool) -> bool {
    crate::fs::sysv_ipc::check_access(s.uid, s.gid, s.mode, uid, gid, want_write)
}

fn is_owner_or_creator(s: &SemSet, uid: u32) -> bool {
    crate::fs::sysv_ipc::is_owner_or_creator(s.uid, s.cuid, uid)
}

static NEXT_SEMID: spin::Mutex<i32> = spin::Mutex::new(1);
static SETS: spin::Mutex<BTreeMap<i32, SemSet>> = spin::Mutex::new(BTreeMap::new());
/// Non-`IPC_PRIVATE` keys only, same convention `crate::fs::sysv_msg::KEYS` already establishes.
static KEYS: spin::Mutex<BTreeMap<i32, i32>> = spin::Mutex::new(BTreeMap::new());

/// musl's own `struct sembuf` (`external/mit/musl/include/sys/sem.h`) -- 6 bytes, verified via a
/// direct `musl-gcc`/`sizeof`/`offsetof` probe, same rigor `RawIpcPerm`/`RawMsqidDs` already
/// established.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawSembuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

const _: () = assert!(core::mem::size_of::<RawSembuf>() == 6);

/// musl's own `struct semid_ds` on x86_64 (`external/mit/musl/arch/generic/bits/sem.h`) -- same
/// probe-confirmed rigor as `RawSembuf` above (88 bytes total: 48-byte `ipc_perm` + two 8-byte
/// `time_t`s + a 2-byte `sem_nsems` padded out to 8 + two reserved 8-byte longs).
#[repr(C)]
struct RawSemidDs {
    sem_perm: RawIpcPerm,
    sem_otime: i64,
    sem_ctime: i64,
    sem_nsems: u16,
    pad: [u8; 6],
    unused3: i64,
    unused4: i64,
}

const _: () = assert!(core::mem::size_of::<RawSemidDs>() == 88);

/// Wakes every process blocked in `do_semop`/`do_semtimedop` on `semid` **whose own `semnum` is
/// one of `touched`** -- called after any successful `semop`/`semctl(SETVAL/SETALL)`/
/// `apply_undo_for_exit` adjustment. Deliberately *not* a blanket "wake everyone blocked on this
/// semid" -- a process waiting on one semaphore's value has no reason to wake (and, more
/// importantly, no reason to transiently stop counting as blocked) when a *different* semaphore in
/// the same set changes. **Found live by this module's own smoke test**: an earlier draft ignored
/// `touched` entirely and woke every blocked waiter on any successful op regardless of which
/// semnum it actually mutated -- harmless for `semop`'s own correctness (the retry loop always
/// re-checks the real condition from scratch, so a spuriously woken process just re-blocks on its
/// next turn), but it broke `semctl(GETNCNT)`/`semctl(GETZCNT)`'s own "real, not fabricated" count:
/// a process still genuinely blocked on an *untouched* semaphore would read back as `Ready`
/// (merely not yet rescheduled to re-block) the instant some *other* semaphore in the set changed,
/// undercounting a real waiter. `semctl(IPC_RMID)` is the one caller that still wants the old
/// broad behavior (the semid itself is gone, so every blocked process needs to wake and discover a
/// real `EIDRM` regardless of which semnum it cared about) -- see `wake_blocked_semop_all` below.
fn wake_blocked_semop(semid: i32, touched: &[u16]) {
    let mut table = process::table().lock();
    for (&pid, proc) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::WaitingForSemOp(id, num, _, _)) = proc.state
            && id == semid as u64
            && touched.contains(&num)
        {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}

/// The broad counterpart `semctl(IPC_RMID)` alone needs -- see `wake_blocked_semop`'s own doc
/// comment for why every other caller wants the precise, `touched`-filtered version instead.
fn wake_blocked_semop_all(semid: i32) {
    let mut table = process::table().lock();
    for (&pid, proc) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::WaitingForSemOp(id, _, _, _)) = proc.state
            && id == semid as u64
        {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}

/// Accumulates one `SEM_UNDO` adjustment for `(semid, semnum)` on the *calling* process (`pid`) --
/// real semantics: `sem_op` was just applied to the live value, so the undo entry must move by
/// `-sem_op` to be able to reverse it later. Multiple `SEM_UNDO` ops against the same
/// `(semid, semnum)` accumulate into one entry, same as real Linux's own `semadj` array.
fn record_undo(pid: Pid, semid: i32, semnum: u16, sem_op: i16) {
    let mut table = process::table().lock();
    let Some(me) = table.get_mut(&pid) else {
        return;
    };
    if let Some(entry) = me
        .sysv_sem_undo
        .iter_mut()
        .find(|(id, num, _)| *id == semid && *num == semnum)
    {
        entry.2 -= sem_op as i32;
    } else {
        me.sysv_sem_undo.push((semid, semnum, -(sem_op as i32)));
    }
}

/// Called from `process::lifecycle::terminate_process` on every real process termination (`exit`
/// or a default-disposition signal kill) -- see that call site's own comment for why this must run
/// *before* `PROCESS_TABLE` is locked there. Applies every accumulated adjustment, clamped into
/// `[0, SEMVMX]` (real Linux behavior: an undo that would push a value out of range is silently
/// clamped rather than left to fail -- there's no way for `exit(2)` itself to report an error),
/// then wakes anyone blocked on that `semid` in case the adjustment unblocked them. A `semid`
/// already removed (`SETS` lookup misses) is a silent no-op -- see this module's own doc comment.
pub(crate) fn apply_undo_for_exit(pid: Pid) {
    let undo_list = {
        let mut table = process::table().lock();
        let Some(me) = table.get_mut(&pid) else {
            return;
        };
        core::mem::take(&mut me.sysv_sem_undo)
    };
    if undo_list.is_empty() {
        return;
    }
    // Grouped by semid so each set's own wake call only names the semnums this pid's own undo
    // list actually touched -- same precise-wake reasoning `wake_blocked_semop`'s own doc comment
    // establishes.
    let mut touched_by_semid: alloc::collections::BTreeMap<i32, Vec<u16>> =
        alloc::collections::BTreeMap::new();
    {
        let mut sets = SETS.lock();
        for (semid, semnum, adjustment) in undo_list {
            let Some(set) = sets.get_mut(&semid) else {
                continue;
            };
            let Some(sem) = set.semas.get_mut(semnum as usize) else {
                continue;
            };
            sem.val = (sem.val + adjustment).clamp(0, SEMVMX);
            touched_by_semid.entry(semid).or_default().push(semnum);
        }
    }
    for (semid, touched) in touched_by_semid {
        wake_blocked_semop(semid, &touched);
    }
}

/// `SYS_SEMGET` (`546`, item 21) -- matches real `semget(2)`'s exact `(key, nsems, flag)` wire
/// format, no musl call-site patch needed. `IPC_PRIVATE` always creates a fresh, key-less set;
/// otherwise looks up `key` in `KEYS`, applying real `IPC_CREAT`/`IPC_EXCL` semantics. Real
/// semantics for an existing-key lookup: `nsems == 0` matches any existing set's size, a nonzero
/// `nsems` must match exactly (`EINVAL` otherwise) -- real `semget(2)`'s own documented behavior.
pub(crate) fn do_semget(key: u64, nsems: u64, flag: u64) -> Result<u64, u64> {
    let key = key as i32;
    let nsems = nsems as i64;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let creat = flag & IPC_CREAT != 0;
    let excl = flag & IPC_EXCL != 0;

    if key != IPC_PRIVATE {
        let existing = KEYS.lock().get(&key).copied();
        if let Some(semid) = existing {
            if creat && excl {
                return Err(crate::syscall::EEXIST);
            }
            let sets = SETS.lock();
            let s = sets
                .get(&semid)
                .expect("KEYS entry with no matching SETS entry");
            if nsems != 0 && nsems as usize != s.semas.len() {
                return Err(EINVAL);
            }
            if !check_access(s, uid, gid, false) {
                return Err(EACCES);
            }
            return Ok(semid as u64);
        }
        if !creat {
            return Err(ENOENT);
        }
    }

    if nsems <= 0 || nsems as usize > MAX_SEMS_PER_SET {
        return Err(EINVAL);
    }
    let mut sets = SETS.lock();
    if sets.len() >= MAX_SYSV_SEM_SETS {
        return Err(crate::syscall::EAGAIN);
    }
    let semid = {
        let mut next = NEXT_SEMID.lock();
        let v = *next;
        *next += 1;
        v
    };
    let mut semas = Vec::with_capacity(nsems as usize);
    for _ in 0..nsems {
        semas.push(Semaphore { val: 0, sempid: 0 });
    }
    let now = crate::cpu::rtc::unix_epoch_now_precise().0;
    sets.insert(
        semid,
        SemSet {
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode: (flag & 0o777) as u32,
            otime: 0,
            ctime: now,
            semas,
        },
    );
    drop(sets);
    if key != IPC_PRIVATE {
        KEYS.lock().insert(key, semid);
    }
    Ok(semid as u64)
}

/// Reads a real `sembuf[nsops]` array off `sops_ptr` -- bounded by `MAX_SEMOPS_PER_CALL` (see this
/// module's own doc comment; real Linux enforces its own `SEMOPM` the same way, `E2BIG` past it,
/// but `EINVAL` is used here to match this port's existing "no dedicated array-too-large errno
/// distinction" tier elsewhere).
fn read_sembufs(sops_ptr: u64, nsops: u64) -> Result<Vec<RawSembuf>, u64> {
    if nsops == 0 || nsops as usize > MAX_SEMOPS_PER_CALL {
        return Err(EINVAL);
    }
    let mut ops = Vec::with_capacity(nsops as usize);
    for i in 0..nsops {
        // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
        // already has.
        let op = unsafe { *(sops_ptr as *const RawSembuf).add(i as usize) };
        ops.push(op);
    }
    Ok(ops)
}

/// Shared `semop`/`semtimedop` core -- see this module's own doc comment for the real atomic-
/// array/blocking/`SEM_UNDO` semantics. `deadline` is `u64::MAX` for `semop`'s own "block
/// indefinitely" case.
fn do_semop_impl(semid: i32, ops: &[RawSembuf], deadline: u64) -> Result<u64, u64> {
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let caller = scheduler::current_pid();

    loop {
        {
            let mut sets = SETS.lock();
            let Some(set) = sets.get_mut(&semid) else {
                return Err(EIDRM);
            };
            let want_write = ops.iter().any(|op| op.sem_op != 0);
            if !check_access(set, uid, gid, want_write) {
                return Err(EACCES);
            }
            for op in ops {
                if op.sem_num as usize >= set.semas.len() {
                    return Err(EFBIG);
                }
            }

            // Real atomicity: simulate the whole array against a scratch copy of every touched
            // value first: if every op can proceed, commit them all at once; if any op would
            // block, apply nothing and either fail (`IPC_NOWAIT`) or block on that specific op.
            let mut scratch: Vec<i32> = set.semas.iter().map(|s| s.val).collect();
            let mut blocking_op: Option<&RawSembuf> = None;
            for op in ops {
                let idx = op.sem_num as usize;
                if op.sem_op > 0 {
                    scratch[idx] += op.sem_op as i32;
                } else if op.sem_op < 0 {
                    if scratch[idx] + (op.sem_op as i32) < 0 {
                        blocking_op = Some(op);
                        break;
                    }
                    scratch[idx] += op.sem_op as i32;
                } else if scratch[idx] != 0 {
                    blocking_op = Some(op);
                    break;
                }
            }

            if let Some(op) = blocking_op {
                if op.sem_flg & IPC_NOWAIT != 0 {
                    return Err(crate::syscall::EAGAIN);
                }
                if crate::cpu::interrupts::ticks() >= deadline {
                    return Err(crate::syscall::ETIMEDOUT);
                }
                let waiting_for_zero = op.sem_op == 0;
                let semnum = op.sem_num;
                let mut table = process::table().lock();
                table.get_mut(&caller).unwrap().state = ProcState::Blocked(
                    BlockReason::WaitingForSemOp(semid as u64, semnum, waiting_for_zero, deadline),
                );
                drop(table);
                drop(sets);
                scheduler::schedule();
                continue;
            }

            // Every op can proceed at once -- commit only the semaphores this array actually
            // named, not a blanket write-back of the whole set. **A real bug found live by this
            // module's own smoke test's `GETPID` check**: an earlier draft wrote every
            // semaphore's `val`/`sempid` from the full `scratch` copy unconditionally -- harmless
            // for `val` (untouched entries' scratch values are identical copies), but it
            // misattributed `sempid` (real `semctl(GETPID)`'s own backing store) to this caller
            // for every semaphore in the set, not just the ones this specific call touched.
            for op in ops {
                let idx = op.sem_num as usize;
                set.semas[idx].val = scratch[idx];
                set.semas[idx].sempid = caller;
            }
            set.otime = crate::cpu::rtc::unix_epoch_now_precise().0;
        } // sets lock dropped

        let mut touched: Vec<u16> = Vec::with_capacity(ops.len());
        for op in ops {
            if op.sem_flg & SEM_UNDO != 0 && op.sem_op != 0 {
                record_undo(caller, semid, op.sem_num, op.sem_op);
            }
            if op.sem_op != 0 {
                touched.push(op.sem_num);
            }
        }
        wake_blocked_semop(semid, &touched);
        return Ok(0);
    }
}

/// `SYS_SEMOP` (`547`, item 22) -- matches real `semop(2)`'s exact `(id, sops, nsops)` wire
/// format, no musl call-site patch needed. Blocks indefinitely (`deadline = u64::MAX`) unless an
/// individual op sets `IPC_NOWAIT`.
pub(crate) fn do_semop(id: u64, sops_ptr: u64, nsops: u64) -> Result<u64, u64> {
    let ops = read_sembufs(sops_ptr, nsops)?;
    do_semop_impl(id as i32, &ops, u64::MAX)
}

/// Real relative-timeout conversion for `semtimedop` -- deliberately mirrors `do_nanosleep`'s own
/// whole-second/sub-second tick rounding exactly (see this module's own doc comment for why this
/// is *not* `crate::process::abstime_to_ticks`, which is absolute-clock-based). `ts_ptr == 0`
/// blocks indefinitely, matching real `semop()`'s own null-equivalent behavior (real
/// `semtimedop(2)` requires a non-null `timeout`, but nothing stops a raw caller from passing null
/// -- treated the same as "no timeout" rather than an arbitrary `EFAULT`, since this port doesn't
/// validate pointers here anyway).
fn resolve_relative_deadline(ts_ptr: u64) -> Result<u64, u64> {
    if ts_ptr == 0 {
        return Ok(u64::MAX);
    }
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let (sec, nsec) = unsafe {
        let ts = ts_ptr as *const i64;
        (*ts, *ts.add(1))
    };
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(EINVAL);
    }
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let whole_second_ticks = sec as u64 * hz;
    let sub_second_ticks = (nsec as u64 * hz).div_ceil(1_000_000_000);
    Ok(crate::cpu::interrupts::ticks() + whole_second_ticks + sub_second_ticks)
}

/// `SYS_SEMTIMEDOP` (`549`, item 24, last of the batch) -- matches real `semtimedop(2)`'s exact
/// `(id, sops, nsops, timeout)` wire format, no musl call-site patch needed.
pub(crate) fn do_semtimedop(id: u64, sops_ptr: u64, nsops: u64, ts_ptr: u64) -> Result<u64, u64> {
    let ops = read_sembufs(sops_ptr, nsops)?;
    let deadline = resolve_relative_deadline(ts_ptr)?;
    do_semop_impl(id as i32, &ops, deadline)
}

/// `SYS_SEMCTL` (`548`, item 23) -- matches real `semctl(2)`'s exact `(id, num, cmd, arg)` wire
/// format, no musl call-site patch needed. `cmd` always arrives with real glibc/musl's `IPC_64`
/// bit OR'd in (same `IPC_CMD()` convention `crate::fs::sysv_msg`'s own `msgctl` already
/// documents) -- masked off before matching. Only `IPC_STAT`/`IPC_SET`/`IPC_RMID`/`GETVAL`/
/// `SETVAL`/`GETALL`/`SETALL`/`GETPID`/`GETNCNT`/`GETZCNT` are implemented (`SEM_STAT`/
/// `SEM_STAT_ANY`/`IPC_INFO`/`SEM_INFO` are real `/proc`-introspection-shaped commands with no
/// live caller -- honest `EINVAL`, matching `msgctl`'s own tier for its analogous commands).
pub(crate) fn do_semctl(id: u64, semnum: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    const GETPID: u64 = 11;
    const GETVAL: u64 = 12;
    const GETALL: u64 = 13;
    const GETNCNT: u64 = 14;
    const GETZCNT: u64 = 15;
    const SETVAL: u64 = 16;
    const SETALL: u64 = 17;

    let semid = id as i32;
    let real_cmd = cmd & !IPC_64;
    let uid = process::oxidebsd_current_uid() as u32;
    let gid = process::oxidebsd_current_gid() as u32;
    let caller = scheduler::current_pid();

    match real_cmd {
        IPC_STAT => {
            let sets = SETS.lock();
            let s = sets.get(&semid).ok_or(EIDRM)?;
            if !check_access(s, uid, gid, false) {
                return Err(EACCES);
            }
            let raw = RawSemidDs {
                sem_perm: RawIpcPerm {
                    key: s.key,
                    uid: s.uid,
                    gid: s.gid,
                    cuid: s.cuid,
                    cgid: s.cgid,
                    mode: s.mode,
                    seq: 0,
                    pad1: 0,
                    pad2: 0,
                },
                sem_otime: s.otime,
                sem_ctime: s.ctime,
                sem_nsems: s.semas.len() as u16,
                pad: [0; 6],
                unused3: 0,
                unused4: 0,
            };
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // codebase already has.
            unsafe { (arg as *mut RawSemidDs).write_unaligned(raw) };
            Ok(0)
        }
        IPC_SET => {
            let mut sets = SETS.lock();
            let s = sets.get_mut(&semid).ok_or(EIDRM)?;
            if !is_owner_or_creator(s, uid) {
                return Err(EACCES);
            }
            // SAFETY: same known pointer-validation gap every other user-memory read in this
            // codebase already has.
            let raw = unsafe { (arg as *const RawSemidDs).read_unaligned() };
            s.uid = raw.sem_perm.uid;
            s.gid = raw.sem_perm.gid;
            s.mode = raw.sem_perm.mode & 0o777;
            s.ctime = crate::cpu::rtc::unix_epoch_now_precise().0;
            Ok(0)
        }
        IPC_RMID => {
            let mut sets = SETS.lock();
            let s = sets.get(&semid).ok_or(EIDRM)?;
            if !is_owner_or_creator(s, uid) {
                return Err(EACCES);
            }
            let key = s.key;
            sets.remove(&semid);
            drop(sets);
            if key != IPC_PRIVATE {
                KEYS.lock().remove(&key);
            }
            // Every blocked semop waiter re-checks SETS from scratch on wake and finds semid
            // gone -- real EIDRM, no distinct wake payload needed (same discipline
            // crate::fs::sysv_msg's own IPC_RMID already established). The broad, unfiltered
            // wake (see that function's own doc comment for why this is the one caller that
            // still wants it).
            wake_blocked_semop_all(semid);
            Ok(0)
        }
        GETVAL => {
            let sets = SETS.lock();
            let s = sets.get(&semid).ok_or(EIDRM)?;
            if !check_access(s, uid, gid, false) {
                return Err(EACCES);
            }
            let sem = s.semas.get(semnum as usize).ok_or(EFBIG)?;
            Ok(sem.val as u64)
        }
        SETVAL => {
            let mut sets = SETS.lock();
            let s = sets.get_mut(&semid).ok_or(EIDRM)?;
            if !check_access(s, uid, gid, true) {
                return Err(EACCES);
            }
            let sem = s.semas.get_mut(semnum as usize).ok_or(EFBIG)?;
            // Real semctl(SETVAL) wire format: `arg` is the raw value itself, not a pointer --
            // see this module's own doc comment.
            let val = arg as i32;
            if !(0..=SEMVMX).contains(&val) {
                return Err(ERANGE);
            }
            sem.val = val;
            sem.sempid = caller;
            s.ctime = crate::cpu::rtc::unix_epoch_now_precise().0;
            drop(sets);
            wake_blocked_semop(semid, &[semnum as u16]);
            Ok(0)
        }
        GETALL => {
            let sets = SETS.lock();
            let s = sets.get(&semid).ok_or(EIDRM)?;
            if !check_access(s, uid, gid, false) {
                return Err(EACCES);
            }
            // SAFETY: same known pointer-validation gap every other user-memory write in this
            // codebase already has.
            for (i, sem) in s.semas.iter().enumerate() {
                unsafe { ((arg as *mut u16).add(i)).write_unaligned(sem.val as u16) };
            }
            Ok(0)
        }
        SETALL => {
            let mut sets = SETS.lock();
            let s = sets.get_mut(&semid).ok_or(EIDRM)?;
            if !check_access(s, uid, gid, true) {
                return Err(EACCES);
            }
            let n = s.semas.len();
            let mut new_vals = Vec::with_capacity(n);
            for i in 0..n {
                // SAFETY: same known pointer-validation gap every other user-memory read in this
                // codebase already has.
                let v = unsafe { *((arg as *const u16).add(i)) } as i32;
                if !(0..=SEMVMX).contains(&v) {
                    return Err(ERANGE);
                }
                new_vals.push(v);
            }
            for (sem, v) in s.semas.iter_mut().zip(new_vals) {
                sem.val = v;
                sem.sempid = caller;
            }
            s.ctime = crate::cpu::rtc::unix_epoch_now_precise().0;
            drop(sets);
            // Every semaphore in the set potentially changed -- the full 0..n range, not the
            // blanket wake_blocked_semop_all (which would also spuriously match on an already-
            // removed semid, a case SETALL itself can never reach since it already holds a live
            // SETS lookup above).
            let all_semnums: Vec<u16> = (0..n as u16).collect();
            wake_blocked_semop(semid, &all_semnums);
            Ok(0)
        }
        GETPID => {
            let sets = SETS.lock();
            let s = sets.get(&semid).ok_or(EIDRM)?;
            let sem = s.semas.get(semnum as usize).ok_or(EFBIG)?;
            Ok(sem.sempid)
        }
        GETNCNT => {
            let sets = SETS.lock();
            let s = sets.get(&semid).ok_or(EIDRM)?;
            if semnum as usize >= s.semas.len() {
                return Err(EFBIG);
            }
            drop(sets);
            Ok(count_semop_waiters(semid, semnum as u16, false) as u64)
        }
        GETZCNT => {
            let sets = SETS.lock();
            let s = sets.get(&semid).ok_or(EIDRM)?;
            if semnum as usize >= s.semas.len() {
                return Err(EFBIG);
            }
            drop(sets);
            Ok(count_semop_waiters(semid, semnum as u16, true) as u64)
        }
        _ => Err(EINVAL),
    }
}

/// Real, not fabricated, `semctl(GETNCNT)`/`semctl(GETZCNT)` backing -- scans `process::table()`
/// for exactly the `(semid, semnum, waiting_for_zero)` triple `BlockReason::WaitingForSemOp`
/// carries. See that variant's own doc comment for the "one representative blocking op per
/// process" simplification this counts against.
fn count_semop_waiters(semid: i32, semnum: u16, want_zero: bool) -> usize {
    let table = process::table().lock();
    table
        .values()
        .filter(|p| {
            matches!(
                p.state,
                ProcState::Blocked(BlockReason::WaitingForSemOp(id, num, zero, _))
                    if id == semid as u64 && num == semnum && zero == want_zero
            )
        })
        .count()
}
