//! uid/gid/pgid/sid syscalls -- split out of the original process.rs.

use super::*;
use crate::process::scheduler;
use crate::syscall::{EINVAL, EPERM, ESRCH};

/// Real `getpid()` returns the caller's **thread-group id**, not its raw schedulable pid — see
/// `Process::tgid`'s own doc comment. Identical today (no real thread creation exists yet), but
/// this is the one line that needs to already be correct before `clone(2)` lands, so a
/// `CLONE_THREAD` child's `getpid()` reports its parent's pid, not its own.
pub fn do_getpid() -> u64 {
    scheduler::current_tgid()
}

/// `0` for a process with no parent (pid 1 itself), matching real `getppid()`'s convention for
/// the boot/init process — every other process always has one, set at `fork`/`spawn` time.
pub fn do_getppid() -> u64 {
    let table = table().lock();
    table
        .get(&scheduler::current_pid())
        .and_then(|p| p.parent)
        .unwrap_or(0)
}

/// `SYS_SETPGID`'s real logic — matches real `setpgid(pid_t pid, pid_t pgid)`'s exact wire format
/// and `pid == 0`/`pgid == 0` "use the caller"/"use `pid` itself" conventions. **A real, documented
/// simplification, not full POSIX semantics**: this kernel has no uid/permission model at all yet
/// (see CLAUDE.md's BusyBox gap analysis — "uid/permissions stub" is its own, separate,
/// unimplemented gap), so unlike real `setpgid`, any live pid can retarget any other live pid's
/// group — there's no restriction to "only the caller itself, or a child that hasn't `execve`'d
/// yet" the way real `setpgid` enforces, and no session-membership check on `pgid` either (a real
/// `Process::sid` field exists now — see `do_setsid` — but nothing here cross-checks `pgid`
/// against it). Good enough for the case that actually matters here: a
/// shell with job control calling `setpgid` on its own freshly forked children right after `fork`,
/// the same "value now, correctness later" tradeoff `do_kill`'s own cross-process case already
/// documents.
pub fn do_setpgid(caller_pid: Pid, pid: i64, pgid: i64) -> Result<u64, u64> {
    if pid < 0 || pgid < 0 {
        return Err(EINVAL);
    }
    let target = if pid == 0 { caller_pid } else { pid as u64 };
    let mut table = PROCESS_TABLE.lock();
    let proc = table.get_mut(&target).ok_or(ESRCH)?;
    proc.pgid = if pgid == 0 { target } else { pgid as u64 };
    Ok(0)
}

/// `SYS_GETPGID`'s real logic — matches real `getpgid(pid_t pid)`'s exact wire format and
/// `pid == 0` "use the caller" convention.
pub fn do_getpgid(caller_pid: Pid, pid: i64) -> Result<u64, u64> {
    if pid < 0 {
        return Err(EINVAL);
    }
    let target = if pid == 0 { caller_pid } else { pid as u64 };
    let table = PROCESS_TABLE.lock();
    table.get(&target).map(|p| p.pgid).ok_or(ESRCH)
}

/// `SYS_SETSID`'s real logic — matches real `setsid(void)`'s exact no-argument wire format (real
/// Linux's own syscall number, `66`, trivial enough to reuse verbatim, same as `uname`/
/// `getgroups` before it — see CLAUDE.md's syscall-ABI section). Real POSIX rule: fails `EPERM` if
/// the caller is already a process-group leader (`pgid == caller_pid`) — the same "can't start a
/// new session while still leading the old group" check real `setsid()` enforces (a session leader
/// is always also its new group's leader, and a pid can't lead two groups at once). On success the
/// caller becomes leader of both a fresh session and a fresh process group (`sid = pgid =
/// caller_pid`). Deliberately doesn't touch `stdin::CONTROLLING_SESSION` at all: that global is
/// keyed by *session id*, not by pid, so a caller landing on a brand-new `sid` is automatically not
/// its owner without any explicit release step — real `setsid()`'s own "detaches from any
/// controlling terminal" contract falls out for free. The *old* session (and any other processes
/// still in it) keeps whatever controlling-tty claim it already had; nothing here revokes it, the
/// same way a real non-leader process calling `setsid()` doesn't drag its former session's tty away
/// from the processes staying behind.
pub fn do_setsid(caller_pid: Pid) -> Result<u64, u64> {
    let mut table = PROCESS_TABLE.lock();
    let proc = table.get_mut(&caller_pid).ok_or(ESRCH)?;
    if proc.pgid == caller_pid {
        return Err(EPERM);
    }
    proc.sid = caller_pid;
    proc.pgid = caller_pid;
    Ok(caller_pid)
}

/// `SYS_GETSID`'s real logic — matches real `getsid(pid_t pid)`'s exact wire format and
/// `pid == 0` "use the caller" convention. Added specifically for `getty`'s own real, documented
/// fallback path (`third_party/busybox/loginutils/getty.c`): when `setsid()` fails (real POSIX
/// rule — the caller is already a process-group leader, the common case for `getty` launched as a
/// job-control shell's own foreground child, since the shell puts it in a fresh pgroup *before*
/// `getty` gets to call `setsid()` itself), real `getty` calls `getsid(0)` to double-check whether
/// it's already the session leader it needs to be before giving up. Without this, that fallback
/// path would see a spurious `ENOSYS` instead of a real answer.
pub fn do_getsid(caller_pid: Pid, pid: i64) -> Result<u64, u64> {
    if pid < 0 {
        return Err(EINVAL);
    }
    let target = if pid == 0 { caller_pid } else { pid as u64 };
    let table = PROCESS_TABLE.lock();
    table.get(&target).map(|p| p.sid).ok_or(ESRCH)
}

/// `SYS_GETUID`/`SYS_GETEUID` — both echo `Process::uid` back (see that field's own doc comment
/// for why there's no distinct effective value to report). Real `getuid(2)`/`geteuid(2)` never
/// fail against the calling process's own table entry, which always exists while this is running.
pub fn do_getuid(caller_pid: Pid) -> u64 {
    PROCESS_TABLE
        .lock()
        .get(&caller_pid)
        .map(|p| p.shared.lock().uid as u64)
        .unwrap_or(0)
}

/// `SYS_GETGID`/`SYS_GETEGID` — `do_getuid`'s counterpart for `Process::gid`.
pub fn do_getgid(caller_pid: Pid) -> u64 {
    PROCESS_TABLE
        .lock()
        .get(&caller_pid)
        .map(|p| p.shared.lock().gid as u64)
        .unwrap_or(0)
}

/// `SYS_SETUID`'s real logic — matches real `setuid(uid_t uid)`'s single-argument wire format and
/// its actual POSIX permission rule: a process running as root (`uid == 0`) may become any uid;
/// anything else may only "become" the uid it already is (a no-op success, not a privilege
/// escalation vector) — real `setuid()` allows this specific no-op case even for a non-root caller.
/// Any other target is `EPERM`. No saved-set-uid/real-vs-effective distinction to update beyond the
/// single `uid` field itself (see `Process::uid`'s own doc comment).
pub fn do_setuid(caller_pid: Pid, uid: u32) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let proc = table
        .get(&caller_pid)
        .expect("setuid: current process missing from table");
    let mut shared = proc.shared.lock();
    if shared.uid != 0 && uid != shared.uid {
        return Err(EPERM);
    }
    shared.uid = uid;
    Ok(0)
}

/// `SYS_SETGID`'s real logic — `do_setuid`'s counterpart for `Process::gid`, gated on the caller's
/// own `uid` (real `setgid()` is likewise a root-only privilege, not gated on the caller's current
/// `gid`).
pub fn do_setgid(caller_pid: Pid, gid: u32) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let proc = table
        .get(&caller_pid)
        .expect("setgid: current process missing from table");
    let mut shared = proc.shared.lock();
    if shared.uid != 0 && gid != shared.gid {
        return Err(EPERM);
    }
    shared.gid = gid;
    Ok(0)
}

/// `SYS_SETRESUID`'s real logic — backs both real `setresuid(3)` directly and `seteuid(2)`
/// (musl's own `seteuid(euid)` is a thin wrapper: `setresuid(-1, euid, -1)`, confirmed against
/// `third_party/musl/src/unistd/seteuid.c` — both funnel through the exact same `__setxid(
/// SYS_setresuid, ...)` call musl's own `setuid()`/`setgid()` already prove works correctly on
/// this kernel's single-threaded model, see `do_setuid`'s own doc comment). Found live: `sem_open`
/// conformance test `sem_open/3-1.c` (Open POSIX Test Suite) needs to drop root privilege via
/// `seteuid()` before it can exercise its own real assertion, and reported a misleading
/// `PTS_UNTESTED` instead — not because `sem_open` itself doesn't exist here (that's a separate,
/// much bigger, already-tracked gap, see `OxideBSD-doc/POSIX_COMPLIANCE_CHECKLIST.md`), but because
/// `seteuid()` itself was an `[boot] unrecognized syscall number 499` the whole time.
///
/// **Real `-1`-means-"leave unchanged" semantics** (each argument arrives sign-extended from a
/// `uid_t` cast to `int` then to a 64-bit syscall register — real `-1` reads back as `i64::-1`
/// reliably at every step of that chain, confirmed against `setxid.c`'s own call sites). **A real,
/// documented simplification**: this kernel's `Process` has no separate real/effective/saved-uid
/// fields to update independently (see `do_setuid`'s own doc comment) — every provided (non `-1`)
/// value is checked against the exact same root-or-no-op `do_setuid` rule, and the *effective* one
/// (`euid` if given, else `ruid`, else `suid`) is what actually lands in the single `Process::uid`
/// field, matching `seteuid()`'s own real-world purpose (change what governs future permission
/// checks) even though a real three-way split isn't tracked.
pub fn do_setresuid(caller_pid: Pid, ruid: i64, euid: i64, suid: i64) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let proc = table
        .get(&caller_pid)
        .expect("setresuid: current process missing from table");
    let mut shared = proc.shared.lock();
    for requested in [ruid, euid, suid] {
        if requested != -1 && shared.uid != 0 && requested as u32 != shared.uid {
            return Err(EPERM);
        }
    }
    if let Some(target) = [euid, ruid, suid].into_iter().find(|&v| v != -1) {
        shared.uid = target as u32;
    }
    Ok(0)
}

/// `SYS_GETGROUPS`'s real logic — this kernel has no supplementary-group concept at all, so the
/// calling process's own single group (`Process::gid`) is the complete, correct group list to
/// report, matching a real POSIX user with no supplementary groups. `size == 0` is the real
/// POSIX "just tell me the count" query (must not touch `list_ptr`, which may be null/dangling for
/// exactly this call shape); `size >= 1` writes that one gid and returns `1`. A `size` too small to
/// hold the (always-one-element) real list is `EINVAL`, matching real `getgroups(2)`.
pub fn do_getgroups(caller_pid: Pid, size: i64, list_ptr: u64) -> Result<u64, u64> {
    if size == 0 {
        return Ok(1);
    }
    if size < 1 {
        return Err(EINVAL);
    }
    let gid = do_getgid(caller_pid) as u32;
    // SAFETY: same known pointer-validation gap every other user-memory write in this codebase
    // already has -- list_ptr isn't checked against the caller's actual mappings first.
    unsafe { (list_ptr as *mut u32).write(gid) };
    Ok(1)
}

/// `SYS_SETGROUPS`'s real logic — real `setgroups(2)` requires `CAP_SYS_ADMIN`/root unconditionally
/// (unlike `setuid`/`setgid`, there's no "become what you already are" no-op allowance for a
/// non-root caller, since a group *list* isn't a single value to trivially compare for equality).
/// A root caller's call is accepted as a real, honest no-op — this kernel has no supplementary-
/// group concept to actually store the list in (see `do_getgroups`'s own doc comment), so there's
/// nothing to do beyond confirming the caller was allowed to ask. Exists specifically so
/// `su`/`login`'s own `initgroups()` → `setgroups()` call (always issued while still root, right
/// before `change_identity` drops privilege) succeeds outright rather than needing BusyBox's own
/// narrower `errno == ENOSYS && target_uid == getuid()` fallback (`libbb/change_identity.c`) to
/// carry it — that fallback only covers "switching to the uid you already are," not a genuine
/// `su otheruser`. Doesn't read `list_ptr` at all (nothing to do with the contents), but does
/// require a real `EPERM` for anything a non-root caller attempts, matching real Linux's own
/// unconditional permission check rather than silently no-op-succeeding for everyone.
pub fn do_setgroups(caller_pid: Pid, _count: u64, _list_ptr: u64) -> Result<u64, u64> {
    let table = PROCESS_TABLE.lock();
    let proc = table
        .get(&caller_pid)
        .expect("setgroups: current process missing from table");
    if proc.shared.lock().uid != 0 {
        return Err(EPERM);
    }
    Ok(0)
}

/// Resolves a real POSIX "`0` means the caller itself, otherwise a specific target pid" argument
/// (the shared convention `setpriority`'s `who`, `sched_setscheduler`/`sched_getscheduler`/
/// `sched_getparam`'s `pid`, and `prlimit64`'s `pid` all use) -- `ESRCH` for a nonzero target that
/// doesn't exist. No further permission check beyond existence: this kernel has no capability
/// model and (today) exactly one uid that's ever run anything other than as itself, the same
/// "collapses to always-allowed" reasoning `do_setpgid`'s own doc comment already uses.
pub(crate) fn resolve_target_pid(caller_pid: Pid, target: i64) -> Result<Pid, u64> {
    if target == 0 {
        return Ok(caller_pid);
    }
    let pid = target as Pid;
    if PROCESS_TABLE.lock().contains_key(&pid) {
        Ok(pid)
    } else {
        Err(ESRCH)
    }
}
/// Exposed to `modules/oxfs` (see `src/module.rs`'s `resolve_external_symbol`) for real permission
/// checks on `open`/`chmod`/`chown` — same "the kernel resolves `current_pid()` itself, no pid
/// crosses the module boundary" shape `oxidebsd_get_cwd` above already established. `pid == 0`
/// (oxfs's own `module_init` self-check, running before any real process exists — see
/// `BOOT_CWD`'s own doc comment) reports root (`0`), the same identity that self-check's own
/// chmod/chown/open calls need to succeed unconditionally.
pub(crate) extern "C" fn oxidebsd_current_uid() -> u64 {
    let pid = scheduler::current_pid();
    if pid == 0 {
        return 0;
    }
    do_getuid(pid)
}

pub(crate) extern "C" fn oxidebsd_current_gid() -> u64 {
    let pid = scheduler::current_pid();
    if pid == 0 {
        return 0;
    }
    do_getgid(pid)
}

/// Exposed to `modules/oxfs` the same way `oxidebsd_current_uid`/`_gid` are — real per-process
/// `Process::umask` (real, tracked state since `SYS_UMASK` landed, see CLAUDE.md's own umask
/// section) finally gets consulted at the one place that creates a new inode's mode:
/// `oxfs_open`'s own `O_CREAT` create-path. `pid == 0` (oxfs's own boot self-check, before any
/// real process exists) reports `0` (no bits masked off) — matches `oxidebsd_current_uid`'s own
/// "report root, unmasked" self-check convention.
pub(crate) extern "C" fn oxidebsd_current_umask() -> u64 {
    let pid = scheduler::current_pid();
    if pid == 0 {
        return 0;
    }
    PROCESS_TABLE
        .lock()
        .get(&pid)
        .map(|p| p.shared.lock().umask as u64)
        .unwrap_or(0)
}
