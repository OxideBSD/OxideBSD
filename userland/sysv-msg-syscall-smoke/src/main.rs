//! Real-`SYSCALL` smoke test for `SYS_MSGGET = 550` through `SYS_MSGCTL = 553`
//! (`modules/posix_compat`'s `handle_msg*` -> `src/syscall/ffi.rs`'s `sys_msg*` ->
//! `src/fs/sysv_msg.rs`'s `do_msg*`) -- items 25-28 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own
//! 28-syscall pre-reserved batch, the last sub-batch: real SysV message queues.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- this feature depends on real per-process `ProcState`/scheduling behavior
//! (blocking send/receive) the same class of bug this codebase's Test architecture section
//! documents catching only through a real syscall instruction.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper (same convention `userland/mq-syscall-smoke/` already established).
//! `q_and_flag` packing for `msgrcv` (see `src/fs/sysv_msg.rs`'s own doc comment) is done by hand
//! here too, mirroring `third_party/musl/src/ipc/msgrcv.c`'s own patch.
//!
//! Scenario, driven entirely by `tests/sysv_msg_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `IPC_CREAT | IPC_EXCL` succeeds; a second `IPC_CREAT | IPC_EXCL` against the same key is a
//!    real `EEXIST`; a missing key without `IPC_CREAT` is a real `ENOENT`.
//! 2. A plain `msgsnd`/`msgrcv(msgtyp=0)` round trip preserves `mtype` and content.
//! 3. Real `msgtyp` selection: three sends at types `7, 3, 5` -- `msgtyp=5` receives the type-5
//!    message out of FIFO order; `msgtyp=-4` (negative) then receives the type-3 message (the
//!    smallest remaining type `<= 4`, *not* just the oldest); `msgtyp=0` then drains the
//!    remaining type-7 message. Plus `MSG_EXCEPT`: a `msgtyp=1` receive with `MSG_EXCEPT` set
//!    skips a type-1 message and receives a type-2 one instead.
//! 4. Real `E2BIG`/`MSG_NOERROR`: a receive buffer shorter than a queued message is `E2BIG` and
//!    does **not** consume the message (verified by a second, truncating `MSG_NOERROR` receive
//!    immediately after successfully returning the same message, shortened).
//! 5. `msgctl(IPC_SET)` shrinks a queue's own `qbytes`; a `msgsnd` that no longer fits is real
//!    `EINVAL` (message longer than the queue's own capacity) or, once queued near-full, a real
//!    `IPC_NOWAIT` `EAGAIN`; an `IPC_NOWAIT` receive against an empty queue is real `ENOMSG`.
//! 6. A real block/wake pair across `fork()`: the parent immediately calls a blocking `msgrcv` on
//!    an empty queue (genuinely blocks, `BlockReason::WaitingForSysvMsgRecv`), forcing the freshly
//!    forked child to run next; the child `msgsnd`s a message and exits; the parent wakes and
//!    receives exactly that message, then reaps the child.
//! 7. `msgctl(IPC_STAT)` reports real `key`/`mode`/`qbytes`/`qnum`/`cbytes`; `IPC_RMID` removes
//!    the queue, after which `msgsnd`/`msgrcv`/`msgctl` against the same `msqid` are all real
//!    `EIDRM`.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_MSGGET: u64 = 550;
const SYS_MSGSND: u64 = 551;
const SYS_MSGRCV: u64 = 552;
const SYS_MSGCTL: u64 = 553;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sysv_msg_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const MSG_NOERROR: u64 = 0o10000;
const MSG_EXCEPT: u64 = 0o20000;

const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
/// Real glibc/musl `IPC_64` bit -- `msgctl`'s real `cmd` argument always arrives with this OR'd
/// in on this build (see `src/fs/sysv_msg.rs`'s own doc comment); a raw `syscall()` caller like
/// this crate (no musl wrapper) has to set it manually to exercise the real kernel-side masking.
const IPC_64: u64 = 0x100;

const EEXIST: u64 = 17;
const ENOENT: u64 = 2;
const EINVAL: u64 = 22;
const E2BIG: u64 = 7;
const EAGAIN: u64 = 11;
const ENOMSG: u64 = 42;
const EIDRM: u64 = 43;

const KEY_A: u64 = 0x5a5a1234;
const KEY_MISSING: u64 = 0x5a5a9999;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `wait4`'s own `rusage_ptr`
/// and every `msg*` call's own 4th register. Explicitly zeroing `r10` on every 3-arg call above
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

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            write_bytes(concat!("sysv-msg-syscall-smoke: FAIL -- ", $msg, "\n").as_bytes());
            test_exit(false);
        }
    };
}

const MSG_CAP: usize = 32;

/// A real `{long mtype; char mtext[MSG_CAP];}` layout -- `mtype` at offset 0, `mtext` immediately
/// after at offset 8 (no padding: `i64` is already 8-aligned, `mtext` is byte-aligned), matching
/// exactly what `do_msgsnd`/`do_msgrcv` read/write at `m`/`m + 8`.
#[repr(C)]
struct RawMsgBuf {
    mtype: i64,
    mtext: [u8; MSG_CAP],
}

fn msgget(key: u64, flag: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_MSGGET, key, flag, 0) }
}

fn msgsnd(q: u64, mtype: i64, data: &[u8], flag: u64) -> Result<u64, u64> {
    let mut buf = RawMsgBuf { mtype, mtext: [0; MSG_CAP] };
    buf.mtext[..data.len()].copy_from_slice(data);
    unsafe {
        syscall4(SYS_MSGSND, q, &buf as *const RawMsgBuf as u64, data.len() as u64, flag)
    }
}

/// Returns `(mtype, received byte count)`; the received bytes land in `out` (only the first
/// `n` bytes, matching the kernel's own real `copy_len` semantics).
fn msgrcv(q: u64, out: &mut [u8], msgtyp: i64, flag: u64) -> Result<(i64, usize), u64> {
    let mut buf = RawMsgBuf { mtype: 0, mtext: [0; MSG_CAP] };
    let packed = q | (flag << 32);
    let n = unsafe {
        syscall4(
            SYS_MSGRCV,
            packed,
            &mut buf as *mut RawMsgBuf as u64,
            out.len() as u64,
            msgtyp as u64,
        )
    }? as usize;
    out[..n].copy_from_slice(&buf.mtext[..n]);
    Ok((buf.mtype, n))
}

/// Matches the kernel's own `RawIpcPerm` (`src/fs/sysv_msg.rs`) exactly.
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

/// Matches the kernel's own `RawMsqidDs` (`src/fs/sysv_msg.rs`) exactly.
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

fn msgctl_stat(q: u64) -> Result<RawMsqidDs, u64> {
    let mut buf = RawMsqidDs {
        msg_perm: RawIpcPerm {
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
        msg_stime: 0,
        msg_rtime: 0,
        msg_ctime: 0,
        msg_cbytes: 0,
        msg_qnum: 0,
        msg_qbytes: 0,
        msg_lspid: 0,
        msg_lrpid: 0,
        unused: [0; 2],
    };
    unsafe {
        syscall(
            SYS_MSGCTL,
            q,
            IPC_STAT | IPC_64,
            &mut buf as *mut RawMsqidDs as u64,
        )
    }?;
    Ok(buf)
}

fn msgctl_set(q: u64, mode: u32, qbytes: u64) -> Result<u64, u64> {
    let buf = RawMsqidDs {
        msg_perm: RawIpcPerm {
            key: 0,
            uid: 0,
            gid: 0,
            cuid: 0,
            cgid: 0,
            mode,
            seq: 0,
            pad1: 0,
            pad2: 0,
        },
        msg_stime: 0,
        msg_rtime: 0,
        msg_ctime: 0,
        msg_cbytes: 0,
        msg_qnum: 0,
        msg_qbytes: qbytes,
        msg_lspid: 0,
        msg_lrpid: 0,
        unused: [0; 2],
    };
    unsafe { syscall(SYS_MSGCTL, q, IPC_SET | IPC_64, &buf as *const RawMsqidDs as u64) }
}

fn msgctl_rmid(q: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_MSGCTL, q, IPC_RMID | IPC_64, 0) }
}

fn child_process(q: u64) -> ! {
    write_bytes(b"sysv-msg-syscall-smoke: child sending wake message\n");
    if msgsnd(q, 42, b"wake", 0).is_err() {
        write_bytes(b"sysv-msg-syscall-smoke: child's msgsnd failed\n");
        unsafe {
            let _ = syscall(SYS_EXIT, 1, 0, 0);
        }
    }
    unsafe {
        let _ = syscall(SYS_EXIT, 0, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sysv-msg-syscall-smoke: starting\n");

    // --- Part 1: msgget / EEXIST / ENOENT ---
    let q = match msgget(KEY_A, IPC_CREAT | IPC_EXCL | 0o600) {
        Ok(q) => q,
        Err(_) => {
            write_bytes(b"sysv-msg-syscall-smoke: initial msgget failed\n");
            test_exit(false);
        }
    };
    check!(
        msgget(KEY_A, IPC_CREAT | IPC_EXCL | 0o600) == Err(EEXIST),
        "IPC_CREAT|IPC_EXCL against an existing key wasn't EEXIST"
    );
    check!(
        msgget(KEY_MISSING, 0) == Err(ENOENT),
        "msgget against a missing key without IPC_CREAT wasn't ENOENT"
    );
    write_bytes(b"sysv-msg-syscall-smoke: part 1 (msgget/EEXIST/ENOENT) OK\n");

    // --- Part 2: plain round trip ---
    check!(msgsnd(q, 1, b"hello", 0).is_ok(), "send hello failed");
    let mut buf = [0u8; MSG_CAP];
    let (mtype, n) = msgrcv(q, &mut buf, 0, 0).unwrap_or((0, 0));
    check!(mtype == 1 && &buf[..n] == b"hello", "plain round trip failed");
    write_bytes(b"sysv-msg-syscall-smoke: part 2 (round trip) OK\n");

    // --- Part 3: msgtyp selection ---
    check!(msgsnd(q, 7, b"seven", 0).is_ok(), "send seven(type 7) failed");
    check!(msgsnd(q, 3, b"three", 0).is_ok(), "send three(type 3) failed");
    check!(msgsnd(q, 5, b"five", 0).is_ok(), "send five(type 5) failed");
    let (mtype, n) = msgrcv(q, &mut buf, 5, 0).unwrap_or((0, 0));
    check!(mtype == 5 && &buf[..n] == b"five", "msgtyp=5 didn't receive the type-5 message");
    let (mtype, n) = msgrcv(q, &mut buf, -4, 0).unwrap_or((0, 0));
    check!(
        mtype == 3 && &buf[..n] == b"three",
        "msgtyp=-4 didn't receive the smallest-type-<=4 message (type 3)"
    );
    let (mtype, n) = msgrcv(q, &mut buf, 0, 0).unwrap_or((0, 0));
    check!(mtype == 7 && &buf[..n] == b"seven", "msgtyp=0 didn't drain the remaining message");

    check!(msgsnd(q, 1, b"one", 0).is_ok(), "send one(type 1) failed");
    check!(msgsnd(q, 2, b"two", 0).is_ok(), "send two(type 2) failed");
    let (mtype, n) = msgrcv(q, &mut buf, 1, MSG_EXCEPT).unwrap_or((0, 0));
    check!(
        mtype == 2 && &buf[..n] == b"two",
        "msgtyp=1 with MSG_EXCEPT didn't skip type 1 and receive type 2"
    );
    let (mtype, n) = msgrcv(q, &mut buf, 0, 0).unwrap_or((0, 0));
    check!(mtype == 1 && &buf[..n] == b"one", "draining the remaining type-1 message failed");
    write_bytes(b"sysv-msg-syscall-smoke: part 3 (msgtyp selection) OK\n");

    // --- Part 4: real E2BIG, message not consumed, then MSG_NOERROR truncation ---
    check!(msgsnd(q, 9, b"0123456789", 0).is_ok(), "send a 10-byte message failed");
    let mut small = [0u8; 4];
    check!(
        msgrcv(q, &mut small, 0, 0) == Err(E2BIG),
        "a receive buffer shorter than the message wasn't E2BIG"
    );
    let (mtype, n) = msgrcv(q, &mut small, 0, MSG_NOERROR).unwrap_or((0, 0));
    check!(
        mtype == 9 && n == 4 && &small[..4] == b"0123",
        "MSG_NOERROR truncation didn't return the same (still-queued) message"
    );
    write_bytes(b"sysv-msg-syscall-smoke: part 4 (E2BIG/MSG_NOERROR) OK\n");

    // --- Part 5: msgctl(IPC_SET) shrinking qbytes, real EAGAIN/ENOMSG ---
    check!(msgctl_set(q, 0o600, 10).is_ok(), "msgctl(IPC_SET qbytes=10) failed");
    check!(
        msgsnd(q, 1, b"0123456789ab", 0) == Err(EINVAL),
        "a message longer than the queue's own qbytes wasn't EINVAL"
    );
    check!(msgsnd(q, 1, b"0123456789", 0).is_ok(), "filling the shrunk queue exactly failed");
    check!(
        msgsnd(q, 1, b"x", IPC_NOWAIT) == Err(EAGAIN),
        "a nonblocking send against a full queue wasn't EAGAIN"
    );
    let (_, _) = msgrcv(q, &mut buf, 0, 0).unwrap_or((0, 0));
    check!(
        msgrcv(q, &mut buf, 0, IPC_NOWAIT) == Err(ENOMSG),
        "a nonblocking receive against an empty queue wasn't ENOMSG"
    );
    check!(msgctl_set(q, 0o600, 16384).is_ok(), "restoring qbytes failed");
    write_bytes(b"sysv-msg-syscall-smoke: part 5 (qbytes/EAGAIN/ENOMSG) OK\n");

    // --- Part 6: real block/wake pair across fork ---
    let fork_result = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid = match fork_result {
        Ok(0) => child_process(q),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"sysv-msg-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    };
    write_bytes(b"sysv-msg-syscall-smoke: parent blocking in msgrcv\n");
    match msgrcv(q, &mut buf, 0, 0) {
        Ok((mtype, n)) => check!(
            mtype == 42 && &buf[..n] == b"wake",
            "woke with the wrong message"
        ),
        Err(_) => {
            write_bytes(b"sysv-msg-syscall-smoke: blocking msgrcv failed\n");
            test_exit(false);
        }
    }
    let mut status: i32 = -1;
    check!(
        unsafe { syscall4(SYS_WAIT4, child_pid, &mut status as *mut i32 as u64, 0, 0) }
            == Ok(child_pid)
            && status == 0,
        "wait4 didn't report a clean child exit"
    );
    write_bytes(b"sysv-msg-syscall-smoke: part 6 (block/wake pair) OK\n");

    // --- Part 7: msgctl(IPC_STAT)/IPC_RMID, real EIDRM afterward ---
    check!(msgsnd(q, 1, b"stat-check", 0).is_ok(), "send before IPC_STAT check failed");
    let stat = msgctl_stat(q).unwrap_or_else(|_| {
        write_bytes(b"sysv-msg-syscall-smoke: msgctl(IPC_STAT) failed\n");
        test_exit(false);
    });
    check!(
        stat.msg_perm.key as u32 == KEY_A as u32
            && stat.msg_perm.mode == 0o600
            && stat.msg_qbytes == 16384
            && stat.msg_qnum == 1
            && stat.msg_cbytes == 10,
        "IPC_STAT reported fields that didn't match real queue state"
    );
    check!(msgctl_rmid(q).is_ok(), "msgctl(IPC_RMID) failed");
    check!(msgsnd(q, 1, b"x", 0) == Err(EIDRM), "msgsnd after IPC_RMID wasn't EIDRM");
    check!(msgrcv(q, &mut buf, 0, IPC_NOWAIT) == Err(EIDRM), "msgrcv after IPC_RMID wasn't EIDRM");
    check!(msgctl_stat(q).is_err_and(|e| e == EIDRM), "msgctl(IPC_STAT) after IPC_RMID wasn't EIDRM");
    write_bytes(b"sysv-msg-syscall-smoke: part 7 (IPC_STAT/IPC_RMID) OK\n");

    write_bytes(b"sysv-msg-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
