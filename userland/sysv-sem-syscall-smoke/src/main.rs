//! Real-`SYSCALL` smoke test for `SYS_SEMGET = 546` through `SYS_SEMTIMEDOP = 549`
//! (`modules/posix_compat`'s `handle_sem*` -> `src/syscall/ffi.rs`'s `sys_sem*` ->
//! `src/fs/sysv_sem.rs`'s `do_sem*`) -- items 21-24 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own
//! 28-syscall pre-reserved batch: real SysV semaphores.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- this feature depends on real per-process `ProcState`/scheduling behavior
//! (atomic multi-op blocking, `SEM_UNDO` applied on real process exit) the same class of bug this
//! codebase's Test architecture section documents catching only through a real syscall
//! instruction.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper (same convention `userland/sysv-msg-syscall-smoke/` already established).
//!
//! Scenario, driven entirely by `tests/sysv_sem_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `IPC_CREAT | IPC_EXCL` succeeds (`nsems = 3`); a second one against the same key is a real
//!    `EEXIST`; a missing key without `IPC_CREAT` is a real `ENOENT`; an existing-key lookup with
//!    a mismatched nonzero `nsems` is `EINVAL`, `nsems = 0` matches regardless.
//! 2. `semctl(SETVAL)`/`GETVAL` round trip; `SETALL`/`GETALL` round trip; a `sem_num` past the
//!    set's real `nsems` is `EFBIG`.
//! 3. A real atomic multi-op `semop`: one call applying two ops (`+1`/`-1`) to two different
//!    semaphores at once, confirmed via `GETALL` afterward.
//! 4. `IPC_NOWAIT` `EAGAIN` on an op that would block.
//! 5. Real `semtimedop` `ETIMEDOUT` -- a relative timeout that genuinely expires while blocked.
//! 6. A real block/wake pair across `fork()`, exercising `GETNCNT` (waiting-for-increase),
//!    `GETZCNT` (waiting-for-zero), and real `SEM_UNDO` (a decrement the child never explicitly
//!    reverses, restored automatically the instant it exits) all in one orchestrated round trip --
//!    see the inline comments in `_start` for the exact interleaving.
//! 7. `semctl(IPC_STAT)` reports real `key`/`mode`/`nsems`; `IPC_RMID` removes the set, after
//!    which `semop`/`semctl`/`semtimedop` against the same `semid` are all real `EIDRM`.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_SEMGET: u64 = 546;
const SYS_SEMOP: u64 = 547;
const SYS_SEMCTL: u64 = 548;
const SYS_SEMTIMEDOP: u64 = 549;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sysv_sem_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: i16 = 0o4000;
const SEM_UNDO: i16 = 0o1000;

const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
/// Real glibc/musl `IPC_64` bit -- `semctl`'s real `cmd` argument always arrives with this OR'd in
/// on this build (see `src/fs/sysv_sem.rs`'s own doc comment); a raw `syscall()` caller like this
/// crate (no musl wrapper) has to set it manually to exercise the real kernel-side masking.
const IPC_64: u64 = 0x100;
const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;

const EEXIST: u64 = 17;
const ENOENT: u64 = 2;
const EINVAL: u64 = 22;
const EAGAIN: u64 = 11;
const EFBIG: u64 = 27;
const ETIMEDOUT: u64 = 110;
const EIDRM: u64 = 43;

const KEY_A: u64 = 0x5e5e1234;
const KEY_MISSING: u64 = 0x5e5e9999;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `wait4`'s own `rusage_ptr`
/// and every `sem*` call's own 4th register. Explicitly zeroing `r10` on every 3-arg call above
/// (rather than leaving it unspecified) is the exact audit CLAUDE.md's own "any future syscall
/// that upgrades from 3 to 4 real arguments" note calls out -- `SYSCALL` doesn't clear `r10`
/// itself.
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

/// Polls `f` (a non-blocking check, e.g. a `semctl(GET*CNT)` call) until it returns `true` or a
/// generous bound is exhausted -- **required now that the scheduler is real preemptive**, not
/// just defensive: an event another process just triggered (a real block registering, a real
/// wake) used to be guaranteed observable by this exact process's very next syscall, back when
/// this kernel's scheduler only ever switched at an explicit blocking point (strict, fully
/// deterministic cooperative round-robin). Real preemption (see CLAUDE.md's own scheduler section)
/// means the *other* process can now be interrupted and resumed at arbitrary points relative to
/// this one, so "the other side already reached its checkpoint by the time I check" is no longer
/// something a single one-shot check can assume -- it has to be polled for. Busy-spinning (not a
/// blocking syscall) is deliberate and correct here: this process's own repeated non-blocking
/// checks don't stop the other process from making progress, since the timer preempts *this*
/// process's ring-3 loop on a fixed quantum regardless of what it's doing.
fn poll_until(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..2_000_000u32 {
        if f() {
            return true;
        }
        for _ in 0..64 {
            spin_loop();
        }
    }
    false
}

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            write_bytes(concat!("sysv-sem-syscall-smoke: FAIL -- ", $msg, "\n").as_bytes());
            test_exit(false);
        }
    };
}

/// Matches the kernel's own `RawSembuf` (`src/fs/sysv_sem.rs`) exactly -- 6 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawSembuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

/// Matches the kernel's own `RawIpcPerm` (`src/fs/sysv_ipc.rs`) exactly.
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

/// Matches the kernel's own `RawSemidDs` (`src/fs/sysv_sem.rs`) exactly.
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

/// Matches the kernel's own `RawTimespec` shape (a plain `{i64, i64}` pair, same as every other
/// timespec-taking syscall in this codebase).
#[repr(C)]
struct RawTimespec {
    sec: i64,
    nsec: i64,
}

fn semget(key: u64, nsems: u64, flag: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_SEMGET, key, nsems, flag) }
}

fn semop(id: u64, ops: &[RawSembuf]) -> Result<u64, u64> {
    unsafe { syscall(SYS_SEMOP, id, ops.as_ptr() as u64, ops.len() as u64) }
}

fn semtimedop(id: u64, ops: &[RawSembuf], ts: &RawTimespec) -> Result<u64, u64> {
    unsafe {
        syscall4(
            SYS_SEMTIMEDOP,
            id,
            ops.as_ptr() as u64,
            ops.len() as u64,
            ts as *const RawTimespec as u64,
        )
    }
}

fn semctl_raw(id: u64, semnum: u64, cmd: u64, arg: u64) -> Result<u64, u64> {
    unsafe { syscall4(SYS_SEMCTL, id, semnum, cmd | IPC_64, arg) }
}

fn semctl_getval(id: u64, semnum: u64) -> Result<i32, u64> {
    semctl_raw(id, semnum, GETVAL, 0).map(|v| v as i32)
}

fn semctl_setval(id: u64, semnum: u64, val: i32) -> Result<u64, u64> {
    semctl_raw(id, semnum, SETVAL, val as u64)
}

fn semctl_getall(id: u64, out: &mut [u16]) -> Result<u64, u64> {
    semctl_raw(id, 0, GETALL, out.as_mut_ptr() as u64)
}

fn semctl_setall(id: u64, vals: &[u16]) -> Result<u64, u64> {
    semctl_raw(id, 0, SETALL, vals.as_ptr() as u64)
}

fn semctl_stat(id: u64) -> Result<RawSemidDs, u64> {
    let mut buf = RawSemidDs {
        sem_perm: RawIpcPerm {
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
        sem_otime: 0,
        sem_ctime: 0,
        sem_nsems: 0,
        pad: [0; 6],
        unused3: 0,
        unused4: 0,
    };
    semctl_raw(id, 0, IPC_STAT, &mut buf as *mut RawSemidDs as u64)?;
    Ok(buf)
}

fn semctl_rmid(id: u64) -> Result<u64, u64> {
    semctl_raw(id, 0, IPC_RMID, 0)
}

fn wait4(pid: u64) -> Result<(u64, i32), u64> {
    let mut status: i32 = -1;
    let ret = unsafe { syscall4(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0, 0) }?;
    Ok((ret, status))
}

/// Runs entirely inside the forked child -- see part 6's own inline commentary in `_start` for
/// exactly why each of these steps happens in this order and what it proves.
fn child_process(semid: u64) -> ! {
    write_bytes(b"sysv-sem-syscall-smoke: child running\n");

    // The parent is (or is about to be) blocked wanting sem0 to increase -- real GETNCNT. Polled,
    // not a one-shot check: under real preemption the parent's own blocking semop call isn't
    // guaranteed to have already run by the time this freshly forked child gets its first turn --
    // see poll_until's own doc comment.
    check!(
        poll_until(|| semctl_raw(semid, 0, GETNCNT, 0) == Ok(1)),
        "child's GETNCNT(sem0) didn't see the parent's real block"
    );

    // Wakes the parent's blocked decrement. Under the old cooperative-only scheduler the parent
    // was guaranteed to stay merely Ready (not actually resumed) until this child hit its own next
    // blocking call -- real preemption means the parent can now genuinely run concurrently with
    // whatever this child does next (including being preempted mid-syscall-sequence and racing
    // ahead), which is exactly why the parent's own corresponding GETZCNT(sem1) check below is
    // polled rather than a one-shot assumption.
    check!(
        semop(semid, &[RawSembuf { sem_num: 0, sem_op: 1, sem_flg: 0 }]).is_ok(),
        "child's wake-up V on sem0 failed"
    );

    // A real SEM_UNDO decrement this child never explicitly reverses -- proven reversed
    // automatically once this process exits, at the very end of this function.
    check!(
        semop(
            semid,
            &[RawSembuf { sem_num: 2, sem_op: -2, sem_flg: SEM_UNDO }],
        )
        .is_ok(),
        "child's SEM_UNDO decrement on sem2 failed"
    );

    // sem1 is still 3 here -- this genuinely blocks (wait-for-zero), which is what finally hands
    // the CPU back to the parent.
    write_bytes(b"sysv-sem-syscall-smoke: child blocking wait-for-zero on sem1\n");
    check!(
        semop(semid, &[RawSembuf { sem_num: 1, sem_op: 0, sem_flg: 0 }]).is_ok(),
        "child's wait-for-zero on sem1 failed"
    );

    write_bytes(b"sysv-sem-syscall-smoke: child exiting (SEM_UNDO should now reverse)\n");
    unsafe {
        let _ = syscall(SYS_EXIT, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sysv-sem-syscall-smoke: starting\n");

    // --- Part 1: semget / EEXIST / ENOENT / nsems-mismatch EINVAL ---
    let semid = match semget(KEY_A, 3, IPC_CREAT | IPC_EXCL | 0o600) {
        Ok(id) => id,
        Err(_) => {
            write_bytes(b"sysv-sem-syscall-smoke: initial semget failed\n");
            test_exit(false);
        }
    };
    check!(
        semget(KEY_A, 3, IPC_CREAT | IPC_EXCL | 0o600) == Err(EEXIST),
        "IPC_CREAT|IPC_EXCL against an existing key wasn't EEXIST"
    );
    check!(
        semget(KEY_MISSING, 0, 0) == Err(ENOENT),
        "semget against a missing key without IPC_CREAT wasn't ENOENT"
    );
    check!(
        semget(KEY_A, 5, 0) == Err(EINVAL),
        "semget against an existing key with a mismatched nonzero nsems wasn't EINVAL"
    );
    check!(
        semget(KEY_A, 0, 0) == Ok(semid),
        "semget against an existing key with nsems=0 didn't match regardless"
    );
    write_bytes(b"sysv-sem-syscall-smoke: part 1 (semget/EEXIST/ENOENT/EINVAL) OK\n");

    // --- Part 2: SETVAL/GETVAL, SETALL/GETALL, EFBIG ---
    check!(semctl_setval(semid, 0, 10).is_ok(), "SETVAL(sem0, 10) failed");
    check!(semctl_getval(semid, 0) == Ok(10), "GETVAL(sem0) didn't read back 10");
    check!(semctl_setall(semid, &[1, 2, 3]).is_ok(), "SETALL([1,2,3]) failed");
    let mut all = [0u16; 3];
    check!(semctl_getall(semid, &mut all).is_ok(), "GETALL failed");
    check!(all == [1, 2, 3], "GETALL didn't read back [1,2,3]");
    check!(
        semctl_getval(semid, 99) == Err(EFBIG),
        "GETVAL past the real nsems wasn't EFBIG"
    );
    write_bytes(b"sysv-sem-syscall-smoke: part 2 (SETVAL/GETVAL/SETALL/GETALL/EFBIG) OK\n");

    // --- Part 3: real atomic multi-op semop ---
    check!(
        semop(
            semid,
            &[
                RawSembuf { sem_num: 0, sem_op: 1, sem_flg: 0 },
                RawSembuf { sem_num: 1, sem_op: -1, sem_flg: 0 },
            ],
        )
        .is_ok(),
        "atomic two-op semop failed"
    );
    check!(semctl_getall(semid, &mut all).is_ok(), "GETALL after atomic semop failed");
    check!(all == [2, 1, 3], "atomic multi-op semop didn't apply both ops together");
    check!(
        semctl_raw(semid, 0, GETPID, 0).is_ok_and(|pid| pid != 0),
        "GETPID(sem0) after a real semop didn't report a nonzero pid"
    );
    write_bytes(b"sysv-sem-syscall-smoke: part 3 (atomic multi-op semop, GETPID) OK\n");

    // --- Part 4: IPC_NOWAIT EAGAIN ---
    check!(semctl_setval(semid, 0, 0).is_ok(), "SETVAL(sem0, 0) before EAGAIN check failed");
    check!(
        semop(semid, &[RawSembuf { sem_num: 0, sem_op: -1, sem_flg: IPC_NOWAIT }]) == Err(EAGAIN),
        "a nonblocking decrement past zero wasn't EAGAIN"
    );
    write_bytes(b"sysv-sem-syscall-smoke: part 4 (IPC_NOWAIT EAGAIN) OK\n");

    // --- Part 5: real semtimedop ETIMEDOUT ---
    let short_timeout = RawTimespec { sec: 0, nsec: 30_000_000 }; // 30ms, well under a second
    check!(
        semtimedop(
            semid,
            &[RawSembuf { sem_num: 0, sem_op: -1, sem_flg: 0 }],
            &short_timeout,
        ) == Err(ETIMEDOUT),
        "a real semtimedop timeout didn't expire with ETIMEDOUT"
    );
    write_bytes(b"sysv-sem-syscall-smoke: part 5 (semtimedop ETIMEDOUT) OK\n");

    // --- Part 6: real block/wake across fork, exercising GETNCNT/GETZCNT/SEM_UNDO ---
    // sem0=0 (the child will V it to wake us), sem1=3 (the child will wait-for-zero on it, we
    // drain it to wake the child back), sem2=5 (the child SEM_UNDO-decrements it by 2 and never
    // explicitly reverses -- proven auto-reversed once it exits).
    check!(semctl_setall(semid, &[0, 3, 5]).is_ok(), "SETALL priming the fork scenario failed");

    let fork_result = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid = match fork_result {
        Ok(0) => child_process(semid),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"sysv-sem-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    };

    // Genuinely blocks (sem0 == 0) -- hands the CPU to the freshly forked child, which performs
    // the real GETNCNT(sem0) check against this exact block before waking it.
    write_bytes(b"sysv-sem-syscall-smoke: parent blocking wait-for-increase on sem0\n");
    check!(
        semop(semid, &[RawSembuf { sem_num: 0, sem_op: -1, sem_flg: 0 }]).is_ok(),
        "parent's blocking decrement on sem0 didn't eventually succeed"
    );

    // sem0's own waiter count is back to zero the moment this process resumes (it was the only
    // waiter, and it just woke) -- not a race, no polling needed.
    check!(
        semctl_raw(semid, 0, GETNCNT, 0) == Ok(0),
        "GETNCNT(sem0) after waking didn't drop back to 0"
    );
    // The child moves on to blocking wait-for-zero on sem1 next (see child_process), but under real
    // preemption isn't guaranteed to have reached it yet by the time this parent resumes -- polled,
    // same reasoning as the child's own GETNCNT poll above (see poll_until's own doc comment).
    check!(
        poll_until(|| semctl_raw(semid, 1, GETZCNT, 0) == Ok(1)),
        "GETZCNT(sem1) didn't see the child's real wait-for-zero block"
    );

    // Drains sem1 to zero, waking the child's wait-for-zero block.
    check!(
        semop(semid, &[RawSembuf { sem_num: 1, sem_op: -3, sem_flg: 0 }]).is_ok(),
        "parent's drain of sem1 failed"
    );

    // The child hasn't exited yet -- this genuinely blocks too, giving the child the CPU to
    // finish (its own wait-for-zero returns immediately since sem1 is already 0) and exit,
    // which is exactly where its SEM_UNDO adjustment on sem2 gets reversed.
    write_bytes(b"sysv-sem-syscall-smoke: parent blocking in wait4 for the child\n");
    let (reaped_pid, status) = wait4(child_pid).unwrap_or_else(|_| {
        write_bytes(b"sysv-sem-syscall-smoke: wait4 failed\n");
        test_exit(false);
    });
    check!(reaped_pid == child_pid && status == 0, "wait4 didn't report a clean child exit");

    check!(semctl_getval(semid, 0) == Ok(0), "sem0 wasn't 0 after the fork round");
    check!(semctl_getval(semid, 1) == Ok(0), "sem1 wasn't 0 after the fork round");
    check!(
        semctl_getval(semid, 2) == Ok(5),
        "sem2 wasn't restored to 5 -- SEM_UNDO didn't reverse on child exit"
    );
    write_bytes(b"sysv-sem-syscall-smoke: part 6 (block/wake, GETNCNT/GETZCNT, SEM_UNDO) OK\n");

    // --- Part 7: IPC_STAT/IPC_RMID, real EIDRM afterward ---
    let stat = semctl_stat(semid).unwrap_or_else(|_| {
        write_bytes(b"sysv-sem-syscall-smoke: semctl(IPC_STAT) failed\n");
        test_exit(false);
    });
    check!(
        stat.sem_perm.key as u32 == KEY_A as u32 && stat.sem_perm.mode == 0o600 && stat.sem_nsems == 3,
        "IPC_STAT reported fields that didn't match real set state"
    );

    // IPC_SET, changing the real mode bits -- confirmed via a fresh IPC_STAT read-back.
    let mut set_buf = RawSemidDs {
        sem_perm: RawIpcPerm {
            key: 0,
            uid: stat.sem_perm.uid,
            gid: stat.sem_perm.gid,
            cuid: 0,
            cgid: 0,
            mode: 0o644,
            seq: 0,
            pad1: 0,
            pad2: 0,
        },
        sem_otime: 0,
        sem_ctime: 0,
        sem_nsems: 0,
        pad: [0; 6],
        unused3: 0,
        unused4: 0,
    };
    check!(
        semctl_raw(semid, 0, IPC_SET, &mut set_buf as *mut RawSemidDs as u64).is_ok(),
        "semctl(IPC_SET) failed"
    );
    let restat = semctl_stat(semid).unwrap_or_else(|_| {
        write_bytes(b"sysv-sem-syscall-smoke: semctl(IPC_STAT) after IPC_SET failed\n");
        test_exit(false);
    });
    check!(restat.sem_perm.mode == 0o644, "IPC_SET didn't change the real mode bits");

    check!(semctl_rmid(semid).is_ok(), "semctl(IPC_RMID) failed");
    check!(
        semop(semid, &[RawSembuf { sem_num: 0, sem_op: 1, sem_flg: 0 }]) == Err(EIDRM),
        "semop after IPC_RMID wasn't EIDRM"
    );
    check!(semctl_getval(semid, 0) == Err(EIDRM), "semctl after IPC_RMID wasn't EIDRM");
    check!(
        semtimedop(
            semid,
            &[RawSembuf { sem_num: 0, sem_op: 1, sem_flg: 0 }],
            &RawTimespec { sec: 0, nsec: 0 },
        ) == Err(EIDRM),
        "semtimedop after IPC_RMID wasn't EIDRM"
    );
    write_bytes(b"sysv-sem-syscall-smoke: part 7 (IPC_STAT/IPC_RMID/EIDRM) OK\n");

    write_bytes(b"sysv-sem-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
