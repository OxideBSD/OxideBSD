//! Shared SysV IPC plumbing between `crate::fs::sysv_msg`, `crate::fs::sysv_sem`, and
//! `crate::fs::sysv_shm` -- all three subsystems need the exact same `struct ipc_perm` wire shape
//! and the exact same real owner/group/other rwx permission-check shape a file's own mode bits
//! already use (`sys/modules/oxfs`'s `check_access`), just against an IPC object's `(uid, gid, mode)`
//! triple instead of an inode's. Factored out here rather than duplicated a second time now that a
//! second (then third) SysV IPC subsystem exists.

/// Real `IPC_RMID`/`IPC_SET`/`IPC_STAT` command values (shared across every SysV IPC `*ctl`
/// syscall -- `msgctl`/`semctl`/the not-yet-implemented `shmctl`).
pub(crate) const IPC_RMID: u64 = 0;
pub(crate) const IPC_SET: u64 = 1;
pub(crate) const IPC_STAT: u64 = 2;
/// Real glibc/musl `IPC_64` bit -- every `*ctl` syscall's own `cmd` argument always arrives with
/// this OR'd in (`external/mit/musl/src/ipc/{msgctl,semctl}.c`'s own `IPC_CMD()` macro), masked off
/// before matching. `IPC_TIME64` is always `0` on this arch (`IPC_STAT & 0x100 == 0`, confirmed
/// directly -- see `crate::fs::sysv_msg`'s own doc comment), so that's the only bit ever set.
pub(crate) const IPC_64: u64 = 0x100;

/// musl's own `struct ipc_perm` on x86_64 (`external/mit/musl/arch/generic/bits/ipc.h`) -- 48
/// bytes, verified via a direct `musl-gcc`/`sizeof`/`offsetof` probe against that exact field
/// list, same rigor `RawSysinfo` (`sys/syscall/ffi.rs`) already established, rather than assumed
/// from Rust `repr(C)` layout rules alone.
#[repr(C)]
pub(crate) struct RawIpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
    pub seq: i32,
    pub pad1: i64,
    pub pad2: i64,
}

const _: () = assert!(core::mem::size_of::<RawIpcPerm>() == 48);

/// Real SysV IPC rwx permission check: `uid == 0` (root) bypasses entirely; otherwise picks the
/// owner/group/other bit exactly like a file's own mode bits, comparing against the object's real
/// `obj_uid`/`obj_gid` (first match wins) -- same shape `sys/modules/oxfs`'s own `check_access`
/// already established for inode permissions, generalized here over a plain `(uid, gid, mode)`
/// triple so both `MsgQueue` and `SemSet` can share it without either owning the other's type.
pub(crate) fn check_access(
    obj_uid: u32,
    obj_gid: u32,
    obj_mode: u32,
    uid: u32,
    gid: u32,
    want_write: bool,
) -> bool {
    if uid == 0 {
        return true;
    }
    let bit = if want_write { 0o2 } else { 0o4 };
    let shift = if uid == obj_uid {
        6
    } else if gid == obj_gid {
        3
    } else {
        0
    };
    (obj_mode >> shift) & bit != 0
}

/// `IPC_SET`/`IPC_RMID`'s own stricter check -- real SysV semantics: only root, the owner, or the
/// *creator* (which can differ from the current owner after a prior `IPC_SET` changed `uid`) may
/// reconfigure or remove an IPC object, regardless of its rwx bits.
pub(crate) fn is_owner_or_creator(obj_uid: u32, obj_cuid: u32, uid: u32) -> bool {
    uid == 0 || uid == obj_uid || uid == obj_cuid
}
