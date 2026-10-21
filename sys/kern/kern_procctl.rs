//! `procctl(2)` (OxideBSD-doc `COW.md` §6.3), system call 585: per-process controls, in the shape
//! of FreeBSD's `procctl(idtype, id, cmd, data)`, with OxideBSD's own commands and numbers. The
//! `procctl` module registers it.
//!
//! `idtype` is `<sys/wait.h>`'s `idtype_t` (musl's values): `P_PID` names one process (`id` 0: the
//! caller), `P_PGID` a process group (`id` 0: the caller's). A command applies to each named
//! process's thread group.
//!
//! Commands:
//! - `PROC_OOM_ADJ_CTL` (1): `data` points to an `int`, the new OOM adjustment (`-1000..=1000`,
//!   else `EINVAL`). Raising it needs the permission `kill(2)` needs; lowering it needs the
//!   superuser (`EPERM`).
//! - `PROC_OOM_ADJ_STATUS` (2): `data` points to an `int` the adjustment is written to. `P_PID`
//!   only (`EINVAL`).

use alloc::vec::Vec;

use crate::memory::usercopy::{UserPtr, copyin_val, copyout_val};
use crate::process::{self, Pid, ProcState};
use crate::syscall::{EINVAL, EPERM, ESRCH};

/// `<sys/wait.h>`'s `P_PID`.
const P_PID: u64 = 1;
/// `<sys/wait.h>`'s `P_PGID`.
const P_PGID: u64 = 2;

const PROC_OOM_ADJ_CTL: u64 = 1;
const PROC_OOM_ADJ_STATUS: u64 = 2;

/// The lowest OOM adjustment, which the OOM killer never chooses.
pub const OOM_ADJ_MIN: i16 = -1000;
/// The highest: a process's pages count double.
pub const OOM_ADJ_MAX: i16 = 1000;

/// `procctl(2)`: `Ok` is the return value, `Err` a positive errno.
fn procctl(idtype: u64, id: u64, cmd: u64, data: u64) -> Result<u64, u64> {
    let caller = process::scheduler::current_pid();
    let targets = targets(caller, idtype, id)?;
    match cmd {
        PROC_OOM_ADJ_STATUS => {
            let [tgid] = targets[..] else { return Err(EINVAL) };
            let adj = with_shared(tgid, |s| s.oom_adj).ok_or(ESRCH)?;
            copyout_val(&(adj as i32), UserPtr::new(data))?;
            Ok(0)
        }
        PROC_OOM_ADJ_CTL => {
            let value: i32 = copyin_val(UserPtr::new(data))?;
            if !(OOM_ADJ_MIN as i32..=OOM_ADJ_MAX as i32).contains(&value) {
                return Err(EINVAL);
            }
            let value = value as i16;
            let cred = process::identity::current_cred();
            // FreeBSD's procctl over a group: done for every process it may, EPERM only when it
            // could do none.
            let mut done = 0;
            for tgid in targets {
                let allowed = with_shared(tgid, |s| {
                    let lowering = value < s.oom_adj;
                    let ok = if lowering { cred.privileged() } else { cred.may_signal(&s.cred) };
                    if ok {
                        s.oom_adj = value;
                    }
                    ok
                });
                if allowed == Some(true) {
                    done += 1;
                }
            }
            if done == 0 { Err(EPERM) } else { Ok(0) }
        }
        _ => Err(EINVAL),
    }
}

/// The thread groups `idtype`/`id` names, by leader pid; `ESRCH` if none.
fn targets(caller: Pid, idtype: u64, id: u64) -> Result<Vec<Pid>, u64> {
    let table = process::table().lock();
    let me = table.get(&caller).ok_or(ESRCH)?;
    let live = |p: &process::Process| !matches!(p.state, ProcState::Zombie(_));
    let found: Vec<Pid> = match idtype {
        P_PID => {
            let pid = if id == 0 { me.tgid } else { id as Pid };
            match table.get(&pid) {
                Some(p) if process::is_kernel_thread(p) => return Err(EPERM),
                Some(p) if live(p) => alloc::vec![p.tgid],
                _ => Vec::new(),
            }
        }
        P_PGID => {
            let pgid = if id == 0 { me.pgid } else { id as Pid };
            table.iter().filter(|&(&pid, p)| pid == p.tgid && p.pgid == pgid && live(p)).map(|(&pid, _)| pid).collect()
        }
        _ => return Err(EINVAL),
    };
    if found.is_empty() { Err(ESRCH) } else { Ok(found) }
}

fn with_shared<R>(tgid: Pid, f: impl FnOnce(&mut process::ThreadGroupShared) -> R) -> Option<R> {
    let table = process::table().lock();
    let p = table.get(&tgid)?;
    let mut shared = p.shared.lock();
    Some(f(&mut shared))
}

/// The `procctl` module's handler.
#[unsafe(no_mangle)]
pub extern "C" fn oxidebsd_sys_procctl(idtype: u64, id: u64, cmd: u64, data: u64) -> i64 {
    match procctl(idtype, id, cmd, data) {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
    }
}
