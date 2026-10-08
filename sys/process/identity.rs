//! uid/gid/pgid/sid syscalls -- split out of the original process.rs.

use super::*;
use crate::memory::usercopy::{UserPtr, copyin_val, copyout_val};
use crate::process::scheduler;
use crate::syscall::{EFAULT, EINVAL, EPERM, ESRCH};

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
/// fallback path (`external/gpl2/busybox/loginutils/getty.c`): when `setsid()` fails (real POSIX
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

/// A thread group's credentials (`OxideBSD-doc/SUDO.md` §5.1): real, effective and saved user and
/// group IDs, and the supplementary groups. Permission checks use the effective IDs and the groups;
/// `access(2)` uses the real ones. Shared by every thread of a group (`ThreadGroupShared::cred`),
/// copied by `fork`, changed by `execve` only for a set-user-ID or set-group-ID program.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Cred {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub groups: Vec<u32>,
}

/// `<limits.h>`'s `NGROUPS_MAX` in OxideBSD's musl, and `kern.ngroups`.
pub const NGROUPS_MAX: usize = 32;

/// `(uid_t)-1` as a `set*id` argument: leave that ID alone. musl's `__setxid` passes `int`s, so it
/// arrives sign-extended; a caller passing a plain `uid_t` gives `0xffff_ffff`.
fn unchanged(v: u64) -> bool {
    v as u32 == u32::MAX
}

impl Cred {
    /// The superuser, as the kernel's first process starts.
    pub fn root() -> Cred {
        Cred::default()
    }

    pub fn privileged(&self) -> bool {
        self.euid == 0
    }

    /// Whether `gid` is the effective (or, for `access(2)`, the real) group or a supplementary one.
    pub fn in_group(&self, gid: u32, real: bool) -> bool {
        (if real { self.rgid } else { self.egid }) == gid || self.groups.contains(&gid)
    }

    /// `kill(2)`'s rule (POSIX, FreeBSD's `p_cansignal`): the superuser, or a sender whose real or
    /// effective user ID is the target's real or saved one.
    pub fn may_signal(&self, target: &Cred) -> bool {
        self.privileged()
            || [self.ruid, self.euid].iter().any(|&id| id == target.ruid || id == target.suid)
    }

    /// `setpriority(2)` and the `sched_*` calls (FreeBSD's `p_cansched`): the superuser, or a caller
    /// whose effective user ID is the target's real or effective one.
    pub fn may_schedule(&self, target: &Cred) -> bool {
        self.privileged() || self.euid == target.ruid || self.euid == target.euid
    }

    /// `execve` of a set-user-ID or set-group-ID file (`mode` holds `S_ISUID`/`S_ISGID`): the
    /// effective ID becomes the file's owner or group; then, as for every `execve`, the saved IDs
    /// take the effective ones (POSIX). Returns whether a set-ID bit took effect.
    pub fn exec(&mut self, setid: Option<(u32, u32, u32)>) -> bool {
        const S_ISUID: u32 = 0o4000;
        const S_ISGID: u32 = 0o2000;
        let mut applied = false;
        if let Some((mode, uid, gid)) = setid {
            if mode & S_ISUID != 0 {
                self.euid = uid;
                applied = true;
            }
            if mode & S_ISGID != 0 {
                self.egid = gid;
                applied = true;
            }
        }
        self.suid = self.euid;
        self.sgid = self.egid;
        applied
    }
}

fn with_cred<R>(caller_pid: Pid, f: impl FnOnce(&mut Cred) -> R) -> R {
    let table = PROCESS_TABLE.lock();
    let proc = table.get(&caller_pid).expect("credentials: current process missing from table");
    let mut shared = proc.shared.lock();
    f(&mut shared.cred)
}

/// The calling thread group's credentials; root before any process exists (oxfs's boot
/// self-check, `scheduler::current_pid() == 0`).
pub fn current_cred() -> Cred {
    let pid = scheduler::current_pid();
    if pid == 0 {
        return Cred::root();
    }
    PROCESS_TABLE.lock().get(&pid).map(|p| p.shared.lock().cred.clone()).unwrap_or_else(Cred::root)
}

/// `getuid(2)`, `geteuid(2)`, `getgid(2)`, `getegid(2)`: never fail.
pub fn do_getuid(caller_pid: Pid) -> u64 {
    with_cred(caller_pid, |c| c.ruid as u64)
}

pub fn do_geteuid(caller_pid: Pid) -> u64 {
    with_cred(caller_pid, |c| c.euid as u64)
}

pub fn do_getgid(caller_pid: Pid) -> u64 {
    with_cred(caller_pid, |c| c.rgid as u64)
}

pub fn do_getegid(caller_pid: Pid) -> u64 {
    with_cred(caller_pid, |c| c.egid as u64)
}

/// `setuid(2)`: the superuser sets all three user IDs; anyone else may set the effective ID to
/// the real or saved one (POSIX with `_POSIX_SAVED_IDS`).
pub fn do_setuid(caller_pid: Pid, uid: u32) -> Result<u64, u64> {
    with_cred(caller_pid, |c| {
        if c.privileged() {
            (c.ruid, c.euid, c.suid) = (uid, uid, uid);
        } else if uid == c.ruid || uid == c.suid {
            c.euid = uid;
        } else {
            return Err(EPERM);
        }
        Ok(0)
    })
}

/// `setgid(2)`: `do_setuid` for the group IDs; the privilege is still the effective user ID's.
pub fn do_setgid(caller_pid: Pid, gid: u32) -> Result<u64, u64> {
    with_cred(caller_pid, |c| {
        if c.privileged() {
            (c.rgid, c.egid, c.sgid) = (gid, gid, gid);
        } else if gid == c.rgid || gid == c.sgid {
            c.egid = gid;
        } else {
            return Err(EPERM);
        }
        Ok(0)
    })
}

/// `setreuid(2)` and `setregid(2)` (`group` picks which), FreeBSD's rules: without privilege the
/// real ID may become the real or effective one, and the effective ID the real, effective or saved
/// one. Setting the real ID, or the effective ID to anything but the real one, also sets the saved
/// ID to the new effective one, so the old privilege can't be regained.
pub fn do_setreid(caller_pid: Pid, r: u64, e: u64, group: bool) -> Result<u64, u64> {
    with_cred(caller_pid, |c| {
        let privileged = c.privileged();
        let (real, eff, saved) = if group {
            (&mut c.rgid, &mut c.egid, &mut c.sgid)
        } else {
            (&mut c.ruid, &mut c.euid, &mut c.suid)
        };
        let (r_new, e_new) = (r as u32, e as u32);
        if !privileged
            && ((!unchanged(r) && r_new != *real && r_new != *eff)
                || (!unchanged(e) && e_new != *real && e_new != *eff && e_new != *saved))
        {
            return Err(EPERM);
        }
        let old_real = *real;
        if !unchanged(e) {
            *eff = e_new;
        }
        if !unchanged(r) {
            *real = r_new;
        }
        if !unchanged(r) || (!unchanged(e) && e_new != old_real) {
            *saved = *eff;
        }
        Ok(0)
    })
}

/// `setresuid(2)` and `setresgid(2)` (`group` picks which); `seteuid(3)`/`setegid(3)` are
/// `setres*id(-1, id, -1)` in musl. Without privilege each new ID must be one of the current three.
pub fn do_setresid(caller_pid: Pid, r: u64, e: u64, s: u64, group: bool) -> Result<u64, u64> {
    with_cred(caller_pid, |c| {
        let privileged = c.privileged();
        let ids = if group {
            [&mut c.rgid, &mut c.egid, &mut c.sgid]
        } else {
            [&mut c.ruid, &mut c.euid, &mut c.suid]
        };
        let current = [*ids[0], *ids[1], *ids[2]];
        let wanted = [r, e, s];
        if !privileged && wanted.iter().any(|&v| !unchanged(v) && !current.contains(&(v as u32))) {
            return Err(EPERM);
        }
        for (id, v) in ids.into_iter().zip(wanted) {
            if !unchanged(v) {
                *id = v as u32;
            }
        }
        Ok(0)
    })
}

/// `getresuid(2)` and `getresgid(2)`: the three IDs, stored through the caller's pointers.
pub fn do_getresid(caller_pid: Pid, r_ptr: u64, e_ptr: u64, s_ptr: u64, group: bool) -> Result<u64, u64> {
    let ids = with_cred(caller_pid, |c| if group { [c.rgid, c.egid, c.sgid] } else { [c.ruid, c.euid, c.suid] });
    for (ptr, id) in [r_ptr, e_ptr, s_ptr].into_iter().zip(ids) {
        if ptr == 0 {
            return Err(EFAULT);
        }
        copyout_val(&id, UserPtr::new(ptr))?;
    }
    Ok(0)
}

/// `getgroups(2)`: the supplementary groups; `size == 0` asks only for their number, and a `size`
/// too small for them is `EINVAL`. The effective group isn't added (POSIX leaves it unspecified;
/// `initgroups(3)` puts the user's group in the list).
pub fn do_getgroups(caller_pid: Pid, size: i64, list_ptr: u64) -> Result<u64, u64> {
    let groups = with_cred(caller_pid, |c| c.groups.clone());
    if size == 0 {
        return Ok(groups.len() as u64);
    }
    if size < 0 || (size as usize) < groups.len() {
        return Err(EINVAL);
    }
    for (i, g) in groups.iter().enumerate() {
        copyout_val(g, UserPtr::new(list_ptr).add(i as u64 * 4))?;
    }
    Ok(groups.len() as u64)
}

/// `setgroups(2)`: replaces the supplementary groups; the superuser only, at most `NGROUPS_MAX`.
pub fn do_setgroups(caller_pid: Pid, count: u64, list_ptr: u64) -> Result<u64, u64> {
    if count as usize > NGROUPS_MAX {
        return Err(EINVAL);
    }
    let mut groups = Vec::with_capacity(count as usize);
    for i in 0..count {
        groups.push(copyin_val::<u32>(UserPtr::new(list_ptr).add(i * 4))?);
    }
    with_cred(caller_pid, |c| {
        if !c.privileged() {
            return Err(EPERM);
        }
        c.groups = groups;
        Ok(0)
    })
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
/// Exposed to modules (`sys/module.rs`'s `resolve_external_symbol`): the calling thread group's
/// effective user and group IDs, which permission checks use. Before any process exists (oxfs's
/// boot self-check) the caller is root.
pub(crate) extern "C" fn oxidebsd_current_uid() -> u64 {
    current_cred().euid as u64
}

pub(crate) extern "C" fn oxidebsd_current_gid() -> u64 {
    current_cred().egid as u64
}

/// The real IDs, for `access(2)`.
pub(crate) extern "C" fn oxidebsd_current_ruid() -> u64 {
    current_cred().ruid as u64
}

pub(crate) extern "C" fn oxidebsd_current_rgid() -> u64 {
    current_cred().rgid as u64
}

/// `1` if `gid` is the caller's effective group (the real one when `real` is nonzero, for
/// `access(2)`) or one of its supplementary groups.
pub(crate) extern "C" fn oxidebsd_current_in_group(gid: u64, real: u64) -> u64 {
    current_cred().in_group(gid as u32, real != 0) as u64
}

/// Exposed to `sys/modules/oxfs` the same way `oxidebsd_current_uid`/`_gid` are — real per-process
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
