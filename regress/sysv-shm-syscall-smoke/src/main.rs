//! Real-`SYSCALL` smoke test for `SYS_SHMGET = 542` through `SYS_SHMDT = 545`
//! (`sys/modules/posix_compat`'s `handle_shm*` -> `sys/syscall/ffi.rs`'s `sys_shm*` ->
//! `sys/fs/sysv_shm.rs`'s `do_shm*`) -- items 17-20 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own
//! 28-syscall pre-reserved batch: real SysV shared memory, the last sub-batch, closing the whole
//! batch out.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- this feature depends on real per-process page-table mapping and real
//! process-table state (`nattch` bookkeeping across `fork`/exit) the same class of bug this
//! codebase's Test architecture section documents catching only through a real syscall
//! instruction.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper (same convention `regress/sysv-sem-syscall-smoke/` already established).
//!
//! Scenario, driven entirely by `tests/sysv_shm_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `IPC_CREAT | IPC_EXCL` succeeds; a second one against the same key is a real `EEXIST`; a
//!    missing key without `IPC_CREAT` is a real `ENOENT`; an existing-key lookup with `size`
//!    larger than the real segment is `EINVAL`, `size = 0` matches regardless.
//! 2. `shmat` maps the segment; a real pattern is written through the returned pointer;
//!    `shmctl(IPC_STAT)` reports real `key`/`mode`/`segsz`/`nattch == 1`/a nonzero `cpid`.
//! 3. **The core proof of real physical sharing**: `fork()`s, then the child performs its own
//!    *independent* `shmat` against the same `shmid` (this kernel's own `fork` doesn't inherit
//!    attachments -- see `crate::fs::sysv_shm`'s own doc comment -- so this is a from-scratch
//!    attach, not an inherited mapping) and confirms it reads back the parent's exact pattern,
//!    proving the two mappings genuinely alias the same physical frames, not independent copies.
//!    The child then writes its own pattern back and `shmdt`s before exiting; the parent, after
//!    reaping it, confirms *it* now sees the child's pattern through its own original mapping --
//!    real bidirectional sharing, not just initial-content sharing.
//! 4. `shmctl(IPC_STAT)` confirms `nattch` dropped back to `1` once the child both explicitly
//!    detached and exited (proving `shmdt` and real-exit detach don't double-decrement).
//! 5. Real `IPC_RMID`-while-still-attached lifecycle on a second key: marks a still-attached
//!    segment for removal, confirms a fresh `shmget` on the same key immediately creates a
//!    *different* id (the key is freed right away even though the old segment survives), then
//!    `shmdt`s the last attachment and confirms the old id is now a real `EIDRM`.
//! 6. `shmdt` back to `nattch == 0` on the first segment, then `shmctl(IPC_RMID)` performs an
//!    *immediate* removal (no attachments left); confirms `shmget` without `IPC_CREAT` is now
//!    `ENOENT` and a second `shmdt` against the already-detached address is `EINVAL`.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_SHMGET: u64 = 542;
const SYS_SHMAT: u64 = 543;
const SYS_SHMCTL: u64 = 544;
const SYS_SHMDT: u64 = 545;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sysv_shm_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const SHM_RDONLY: u64 = 0o10000;

const IPC_RMID: u64 = 0;
const IPC_STAT: u64 = 2;
/// Real glibc/musl `IPC_64` bit -- `shmctl`'s real `cmd` argument always arrives with this OR'd in
/// on this build (see `sys/fs/sysv_shm.rs`'s own doc comment); a raw `syscall()` caller like this
/// crate (no musl wrapper) has to set it manually to exercise the real kernel-side masking.
const IPC_64: u64 = 0x100;

const ENOENT: u64 = 2;
const EINVAL: u64 = 22;
const EEXIST: u64 = 17;
const EIDRM: u64 = 43;

const KEY_A: u64 = 0x54c54c01;
const KEY_B: u64 = 0x54c54c02;
const KEY_C: u64 = 0x54c54c03;
const KEY_MISSING: u64 = 0x54c54c99;
const SEG_SIZE: u64 = 4096;

const PARENT_PATTERN: u8 = 0xaa;
const CHILD_PATTERN: u8 = 0x55;
const PARENT_PATTERN2: u8 = 0xcc;
const CHILD_PATTERN2: u8 = 0x33;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10`. Explicitly zeroing `r10` on every 3-arg
/// call above (rather than leaving it unspecified) is the exact audit CLAUDE.md's own "any future
/// syscall that upgrades from 3 to 4 real arguments" note calls out -- `SYSCALL` doesn't clear
/// `r10` itself.
#[inline(always)]
unsafe fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Result<u64, u64> {
    let ret: u64;
    let failed: u8;
    unsafe {
        asm!(
            "syscall",
            "setc {failed}",
            inlateout("rax") number => ret,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            failed = out(reg_byte) failed,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    if failed != 0 { Err(ret) } else { Ok(ret) }
}

fn write_bytes(s: &[u8]) {
    unsafe {
        let _ = syscall(SYS_WRITE, STDOUT, s.as_ptr() as u64, s.len() as u64);
    }
}

fn test_exit(pass: bool) -> ! {
    unsafe {
        let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            write_bytes(concat!("sysv-shm-syscall-smoke: FAIL -- ", $msg, "\n").as_bytes());
            test_exit(false);
        }
    };
}

/// Matches the kernel's own `RawIpcPerm` (`sys/fs/sysv_ipc.rs`) exactly.
#[repr(C)]
struct RawIpcPerm {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    seq: i32,
    pad1: i64,
    pad2: i64,
}

/// Matches the kernel's own `RawShmidDs` (`sys/fs/sysv_shm.rs`) exactly.
#[repr(C)]
struct RawShmidDs {
    shm_perm: RawIpcPerm,
    shm_segsz: u64,
    shm_atime: i64,
    shm_dtime: i64,
    shm_ctime: i64,
    shm_cpid: i32,
    shm_lpid: i32,
    shm_nattch: u64,
    pad1: i64,
    pad2: i64,
}

fn shmget(key: u64, size: u64, shmflg: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_SHMGET, key, size, shmflg) }
}

fn shmat(id: u64, shmflg: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_SHMAT, id, 0, shmflg) }
}

fn shmdt(addr: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_SHMDT, addr, 0, 0) }
}

fn shmctl_raw(id: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_SHMCTL, id, cmd | IPC_64, arg) }
}

fn shmctl_stat(id: u64) -> Result<RawShmidDs, u64> {
    let mut buf = RawShmidDs {
        shm_perm: RawIpcPerm {
            key: 0,
            uid: 0,
            gid: 0,
            cuid: 0,
            cgid: 0,
            mode: 0,
            seq: 0,
            pad1: 0,
            pad2: 0,
        },
        shm_segsz: 0,
        shm_atime: 0,
        shm_dtime: 0,
        shm_ctime: 0,
        shm_cpid: 0,
        shm_lpid: 0,
        shm_nattch: 0,
        pad1: 0,
        pad2: 0,
    };
    shmctl_raw(id, IPC_STAT, &mut buf as *mut RawShmidDs as u64)?;
    Ok(buf)
}

fn shmctl_rmid(id: u64) -> Result<u64, u64> {
    shmctl_raw(id, IPC_RMID, 0)
}

fn wait4(pid: u64) -> Result<(u64, i32), u64> {
    let mut status: i32 = -1;
    let ret = unsafe { syscall4(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0, 0) }?;
    Ok((ret, status))
}

/// Runs entirely inside the forked child -- see part 3's own inline commentary in `_start` for
/// exactly what this proves.
fn child_process(shmid: u64) -> ! {
    write_bytes(b"sysv-shm-syscall-smoke: child running\n");

    // A real, independent shmat -- not an inherited mapping (this kernel's own fork doesn't
    // inherit shm attachments, see crate::fs::sysv_shm's own doc comment).
    let addr = shmat(shmid, 0).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: child's shmat failed\n");
        test_exit(false);
    });
    let byte = unsafe { core::ptr::read_volatile(addr as *const u8) };
    check!(
        byte == PARENT_PATTERN,
        "child didn't see the parent's real pattern through its own independent shmat -- not truly shared memory"
    );

    unsafe { core::ptr::write_volatile(addr as *mut u8, CHILD_PATTERN) };

    check!(shmdt(addr).is_ok(), "child's shmdt failed");

    write_bytes(b"sysv-shm-syscall-smoke: child exiting\n");
    unsafe {
        let _ = syscall(SYS_EXIT, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

/// Runs entirely inside a forked child that never calls `shmat` itself -- the exact real-fork-
/// inheritance case `fs::sysv_shm::inherit_attachments_for_fork` closes. `addr_c`/`shmid_c` are the
/// parent's own already-attached mapping, expected to work purely because it was inherited across
/// `fork` (real `AddressSpace::fork` now aliases the segment's actual frame at this VA -- see
/// `memory::address_space::SHARED_LEAF`'s own doc comment).
fn child_process_inherited(addr_c: u64, shmid_c: u64) -> ! {
    write_bytes(b"sysv-shm-syscall-smoke: inherited-child running\n");

    // Real nattch bookkeeping: the parent's own shmat set it to 1; a real fork-inherited
    // attachment must show up as a genuinely separate one, exactly like an unrelated process's own
    // independent shmat would (see fs::sysv_shm::inherit_attachments_for_fork's own doc comment).
    let stat = shmctl_stat(shmid_c).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: inherited-child's shmctl(IPC_STAT) failed\n");
        test_exit(false);
    });
    check!(
        stat.shm_nattch == 2,
        "nattch wasn't 2 right after fork with an inherited attachment still live in both processes"
    );

    // No shmat call at all here -- addr_c is purely inherited from the parent's own pre-fork
    // mapping. Reading real content through it (with zero shmat calls of its own) is the actual
    // proof this test exists for.
    let byte = unsafe { core::ptr::read_volatile(addr_c as *const u8) };
    check!(
        byte == PARENT_PATTERN2,
        "inherited child didn't see the parent's real pattern through a purely fork-inherited mapping"
    );

    unsafe { core::ptr::write_volatile(addr_c as *mut u8, CHILD_PATTERN2) };

    check!(shmdt(addr_c).is_ok(), "inherited child's shmdt of its own inherited attachment failed");

    write_bytes(b"sysv-shm-syscall-smoke: inherited-child exiting\n");
    unsafe {
        let _ = syscall(SYS_EXIT, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sysv-shm-syscall-smoke: starting\n");

    // --- Part 1: shmget / EEXIST / ENOENT / EINVAL ---
    let shmid = match shmget(KEY_A, SEG_SIZE, IPC_CREAT | IPC_EXCL | 0o600) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"sysv-shm-syscall-smoke: initial shmget failed\n");
            test_exit(false);
        }
    };
    check!(
        shmget(KEY_A, SEG_SIZE, IPC_CREAT | IPC_EXCL | 0o600) == Err(EEXIST),
        "IPC_CREAT|IPC_EXCL against an existing key wasn't EEXIST"
    );
    check!(
        shmget(KEY_MISSING, 0, 0) == Err(ENOENT),
        "shmget against a missing key without IPC_CREAT wasn't ENOENT"
    );
    check!(
        shmget(KEY_A, SEG_SIZE * 2, 0) == Err(EINVAL),
        "shmget against an existing key with size larger than the real segment wasn't EINVAL"
    );
    check!(
        shmget(KEY_A, 0, 0) == Ok(shmid),
        "shmget against an existing key with size=0 didn't match regardless"
    );
    write_bytes(b"sysv-shm-syscall-smoke: part 1 (shmget/EEXIST/ENOENT/EINVAL) OK\n");

    // --- Part 2: shmat, real content, IPC_STAT ---
    let addr1 = shmat(shmid, 0).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: parent's shmat failed\n");
        test_exit(false);
    });
    unsafe { core::ptr::write_volatile(addr1 as *mut u8, PARENT_PATTERN) };

    let stat = shmctl_stat(shmid).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: shmctl(IPC_STAT) failed\n");
        test_exit(false);
    });
    check!(
        stat.shm_perm.key as u32 == KEY_A as u32
            && stat.shm_perm.mode == 0o600
            && stat.shm_segsz == SEG_SIZE
            && stat.shm_nattch == 1
            && stat.shm_cpid != 0,
        "IPC_STAT after the parent's own shmat reported fields that didn't match real state"
    );
    write_bytes(b"sysv-shm-syscall-smoke: part 2 (shmat, real content, IPC_STAT) OK\n");

    // A safe (read-only, never-written) exercise of the SHM_RDONLY flag path -- confirms it maps
    // real, correctly-shared content without ever attempting a write that would page-fault.
    let addr_ro = shmat(shmid, SHM_RDONLY).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: SHM_RDONLY shmat failed\n");
        test_exit(false);
    });
    check!(
        unsafe { core::ptr::read_volatile(addr_ro as *const u8) } == PARENT_PATTERN,
        "SHM_RDONLY shmat didn't see the real shared content"
    );
    check!(shmdt(addr_ro).is_ok(), "shmdt on the SHM_RDONLY mapping failed");

    // --- Part 3: real cross-process sharing across fork + independent shmat ---
    let fork_result = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid = match fork_result {
        Ok(0) => child_process(shmid),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"sysv-shm-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    };

    write_bytes(b"sysv-shm-syscall-smoke: parent waiting for child\n");
    let (reaped_pid, status) = wait4(child_pid).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: wait4 failed\n");
        test_exit(false);
    });
    check!(reaped_pid == child_pid && status == 0, "wait4 didn't report a clean child exit");

    let byte = unsafe { core::ptr::read_volatile(addr1 as *const u8) };
    check!(
        byte == CHILD_PATTERN,
        "parent didn't see the child's real write through its own original mapping -- sharing wasn't bidirectional"
    );
    write_bytes(b"sysv-shm-syscall-smoke: part 3 (real cross-process sharing via fork) OK\n");

    // --- Part 4: nattch back to 1 after the child both shmdt'd and exited ---
    let stat = shmctl_stat(shmid).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: shmctl(IPC_STAT) after child exit failed\n");
        test_exit(false);
    });
    check!(
        stat.shm_nattch == 1,
        "nattch wasn't back to 1 after the child's own shmdt + real exit -- double-decremented or leaked"
    );
    write_bytes(b"sysv-shm-syscall-smoke: part 4 (nattch bookkeeping) OK\n");

    // --- Part 5: IPC_RMID while still attached -- key freed immediately, segment survives ---
    let shmid_b1 = shmget(KEY_B, SEG_SIZE, IPC_CREAT | IPC_EXCL | 0o600).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: shmget(KEY_B) failed\n");
        test_exit(false);
    });
    let addr_b = shmat(shmid_b1, 0).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: shmat(KEY_B) failed\n");
        test_exit(false);
    });
    check!(shmctl_rmid(shmid_b1).is_ok(), "shmctl(IPC_RMID) on a still-attached segment failed");
    let shmid_b2 = shmget(KEY_B, SEG_SIZE, IPC_CREAT | 0o600).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: fresh shmget(KEY_B) after IPC_RMID failed\n");
        test_exit(false);
    });
    check!(
        shmid_b2 != shmid_b1,
        "a fresh shmget on a key marked-for-removal-but-still-attached didn't get a genuinely new id"
    );
    check!(shmdt(addr_b).is_ok(), "shmdt of the old KEY_B attachment failed");
    check!(
        shmctl_stat(shmid_b1).is_err_and(|e| e == EIDRM),
        "the old KEY_B segment wasn't really removed once its last attachment detached"
    );
    write_bytes(b"sysv-shm-syscall-smoke: part 5 (IPC_RMID while attached) OK\n");

    // --- Part 6: shmdt to nattch == 0, immediate IPC_RMID, ENOENT/EINVAL afterward ---
    check!(shmdt(addr1).is_ok(), "parent's final shmdt failed");
    check!(
        shmdt(addr1) == Err(EINVAL),
        "a second shmdt against an already-detached address wasn't EINVAL"
    );
    check!(shmctl_rmid(shmid).is_ok(), "shmctl(IPC_RMID) on a fully-detached segment failed");
    check!(
        shmget(KEY_A, 0, 0) == Err(ENOENT),
        "shmget against a removed key without IPC_CREAT wasn't ENOENT"
    );
    check!(
        shmctl_stat(shmid).is_err_and(|e| e == EIDRM),
        "shmctl(IPC_STAT) against a fully-removed shmid wasn't EIDRM"
    );
    write_bytes(b"sysv-shm-syscall-smoke: part 6 (immediate IPC_RMID, ENOENT/EINVAL) OK\n");

    // --- Part 7: real attachment inheritance across fork (no shmat call in the child at all) ---
    let shmid_c = shmget(KEY_C, SEG_SIZE, IPC_CREAT | IPC_EXCL | 0o600).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: shmget(KEY_C) failed\n");
        test_exit(false);
    });
    let addr_c = shmat(shmid_c, 0).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: shmat(KEY_C) failed\n");
        test_exit(false);
    });
    unsafe { core::ptr::write_volatile(addr_c as *mut u8, PARENT_PATTERN2) };

    let fork_result2 = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid2 = match fork_result2 {
        Ok(0) => child_process_inherited(addr_c, shmid_c),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"sysv-shm-syscall-smoke: part 7 fork failed\n");
            test_exit(false);
        }
    };

    let (reaped_pid2, status2) = wait4(child_pid2).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: part 7 wait4 failed\n");
        test_exit(false);
    });
    check!(
        reaped_pid2 == child_pid2 && status2 == 0,
        "part 7's wait4 didn't report a clean inherited-child exit"
    );

    let byte2 = unsafe { core::ptr::read_volatile(addr_c as *const u8) };
    check!(
        byte2 == CHILD_PATTERN2,
        "parent didn't see the inherited child's real write through its own original mapping"
    );

    let stat_c = shmctl_stat(shmid_c).unwrap_or_else(|_| {
        write_bytes(b"sysv-shm-syscall-smoke: shmctl(IPC_STAT) after inherited-child exit failed\n");
        test_exit(false);
    });
    check!(
        stat_c.shm_nattch == 1,
        "nattch wasn't back to 1 after the inherited child's own shmdt + real exit"
    );

    check!(shmdt(addr_c).is_ok(), "parent's final shmdt of the KEY_C attachment failed");
    write_bytes(b"sysv-shm-syscall-smoke: part 7 (real attachment inheritance across fork) OK\n");

    write_bytes(b"sysv-shm-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
