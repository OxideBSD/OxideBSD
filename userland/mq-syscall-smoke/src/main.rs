//! Real-`SYSCALL` smoke test for `SYS_MQ_OPEN = 536` through `SYS_MQ_GETSETATTR = 541`
//! (`modules/posix_compat`'s `handle_mq_*` -> `src/syscall/ffi.rs`'s `sys_mq_*` ->
//! `src/fs/mqueue.rs`'s `do_mq_*`) -- items 11-16 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own
//! 28-syscall pre-reserved batch, the real POSIX message-queue sub-batch.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call -- this feature depends on real per-process `ProcState`/scheduling behavior
//! (blocking send/receive) and real signal delivery (`mq_notify`), the same class of bug this
//! codebase's Test architecture section documents catching only through a real syscall
//! instruction.
//!
//! **No musl involved** -- this crate is a bare `#![no_std]` binary with its own hand-rolled
//! `syscall()` helper and its own minimal `sigreturn_trampoline` (same convention
//! `userland/pause-syscall-smoke/` already established). `mqd_and_len` packing (see
//! `src/fs/mqueue.rs`'s own doc comment) is done by hand here too, mirroring
//! `third_party/musl/src/mq/mq_timedsend.c`'s own patch.
//!
//! Scenario, driven entirely by `tests/mq_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `O_CREAT | O_EXCL` open succeeds; a second `O_CREAT | O_EXCL` against the same name is a
//!    real `EEXIST`; opening a name that doesn't exist without `O_CREAT` is a real `ENOENT`.
//! 2. Real priority-ordered delivery: three sends at priorities `1, 5, 1` come back `5, 1, 1` --
//!    highest priority first, FIFO among equal priorities.
//! 3. Real `EMSGSIZE` both directions (a send longer than `mq_msgsize`, a receive into a buffer
//!    shorter than it).
//! 4. Filling the queue to `mq_maxmsg`, then a real `EAGAIN` on a further `O_NONBLOCK` send; a
//!    `mq_getsetattr` readback confirms `mq_curmsgs`/`mq_maxmsg`/`mq_msgsize`/`mq_flags`.
//! 5. A real deadline: `mq_timedreceive` against an empty queue with an `at` a short time in the
//!    future returns `ETIMEDOUT` once it passes, not before.
//! 6. A real block/wake pair: `fork()`s; the parent immediately calls a non-timed-out
//!    `mq_timedreceive` on the empty queue (genuinely blocks, `BlockReason::WaitingForMqData`),
//!    forcing the freshly forked child to run next; the child `mq_timedsend`s a message and
//!    exits; the parent wakes and receives exactly that message, then reaps the child.
//! 7. `mq_notify`/`SIGEV_SIGNAL`: registers, then a send into the (now empty again) queue with no
//!    receiver blocked fires the registered `SIGUSR1` handler exactly once (real POSIX ordering:
//!    delivered before this same `mq_timedsend` call is even observed to "return", same mechanism
//!    `pause-syscall-smoke` already proved) -- a second send afterward does *not* fire it again
//!    (one-shot, matching real semantics; nothing re-registers).
//! 8. `mq_unlink` removes the name (`mq_open` without `O_CREAT` against it is now `ENOENT`) but
//!    the already-open descriptor keeps working (real POSIX: the queue survives until every open
//!    descriptor closes) -- confirmed with one more send/receive round trip, then a real `close()`.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_CLOSE: u64 = 6;
const SYS_WAIT4: u64 = 7;
const SYS_KILL: u64 = 116;
const SYS_SIGACTION: u64 = 117;
const SYS_SIGPROCMASK: u64 = 118;
const SYS_SIGTIMEDWAIT: u64 = 495;
/// Real, unremapped Linux `__NR_sigreturn` slot -- see `third_party/musl/src/signal/x86_64/
/// restore.s`'s own comment for why every arch's restorer hardcodes its trap number directly
/// rather than going through a shared macro.
const SYS_SIGRETURN: u64 = 119;
const SYS_CLOCK_GETTIME: u64 = 138;
const SYS_NANOSLEEP: u64 = 139;
const SYS_MQ_OPEN: u64 = 536;
const SYS_MQ_UNLINK: u64 = 537;
const SYS_MQ_TIMEDSEND: u64 = 538;
const SYS_MQ_TIMEDRECEIVE: u64 = 539;
const SYS_MQ_NOTIFY: u64 = 540;
const SYS_MQ_GETSETATTR: u64 = 541;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// mq_syscall_smoke.rs` registers this one directly against a test-only handler, same convention
/// every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGUSR1: u64 = 10;

const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: i64 = 0o4000;

const EEXIST: u64 = 17;
const ENOENT: u64 = 2;
const EMSGSIZE: u64 = 90;
const EAGAIN: u64 = 11;
const ETIMEDOUT: u64 = 110;

const CLOCK_REALTIME: u64 = 0;
const SIGEV_SIGNAL: i32 = 0;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// Like `syscall`, but with a real 4th argument in `r10` -- needed for `sigaction`'s own
/// `sigsetsize`, `wait4`'s own `rusage_ptr`, and every `mq_*` call's own 4th register. Explicitly
/// zeroing `r10` on every 3-arg call above (rather than leaving it unspecified) is the exact audit
/// CLAUDE.md's own "any future syscall that upgrades from 3 to 4 real arguments" note calls out --
/// `SYSCALL` doesn't clear `r10` itself.
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
            write_bytes(concat!("mq-syscall-smoke: FAIL -- ", $msg, "\n").as_bytes());
            test_exit(false);
        }
    };
}

/// Matches the kernel's own `RawMqAttr` (`src/fs/mqueue.rs`) exactly -- four `long`s plus four
/// reserved `long`s, no padding.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawMqAttr {
    mq_flags: i64,
    mq_maxmsg: i64,
    mq_msgsize: i64,
    mq_curmsgs: i64,
    unused: [i64; 4],
}

const _: () = assert!(core::mem::size_of::<RawMqAttr>() == 64);

/// A real `struct sigevent` shape (`third_party/musl/include/signal.h`) -- only `sigev_value`/
/// `sigev_signo`/`sigev_notify` are ever read by the kernel (`do_mq_notify`), but sized to the
/// real 64-byte struct for authenticity.
#[repr(C)]
struct RawSigevent {
    sigev_value: u64,
    sigev_signo: i32,
    sigev_notify: i32,
    pad: [u8; 48],
}

const _: () = assert!(core::mem::size_of::<RawSigevent>() == 64);

#[repr(C)]
struct RawTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn mq_open(name: &[u8], flags: u64, mode: u64, attr: Option<&RawMqAttr>) -> Result<u64, u64> {
    let attr_ptr = attr.map(|a| a as *const RawMqAttr as u64).unwrap_or(0);
    unsafe { syscall4(SYS_MQ_OPEN, name.as_ptr() as u64, flags, mode, attr_ptr) }
}

fn mq_unlink(name: &[u8]) -> Result<u64, u64> {
    unsafe { syscall(SYS_MQ_UNLINK, name.as_ptr() as u64, 0, 0) }
}

fn mq_timedsend(mqd: u64, msg: &[u8], prio: u64, at: Option<&RawTimespec>) -> Result<u64, u64> {
    let packed = mqd | ((msg.len() as u64) << 32);
    let at_ptr = at.map(|t| t as *const RawTimespec as u64).unwrap_or(0);
    unsafe { syscall4(SYS_MQ_TIMEDSEND, packed, msg.as_ptr() as u64, prio, at_ptr) }
}

fn mq_timedreceive(
    mqd: u64,
    buf: &mut [u8],
    prio_out: &mut u32,
    at: Option<&RawTimespec>,
) -> Result<u64, u64> {
    let packed = mqd | ((buf.len() as u64) << 32);
    let at_ptr = at.map(|t| t as *const RawTimespec as u64).unwrap_or(0);
    unsafe {
        syscall4(
            SYS_MQ_TIMEDRECEIVE,
            packed,
            buf.as_mut_ptr() as u64,
            prio_out as *mut u32 as u64,
            at_ptr,
        )
    }
}

fn mq_notify(mqd: u64, sev: Option<&RawSigevent>) -> Result<u64, u64> {
    let sev_ptr = sev.map(|s| s as *const RawSigevent as u64).unwrap_or(0);
    unsafe { syscall(SYS_MQ_NOTIFY, mqd, sev_ptr, 0) }
}

fn mq_getsetattr(
    mqd: u64,
    new: Option<&RawMqAttr>,
    old: Option<&mut RawMqAttr>,
) -> Result<u64, u64> {
    let new_ptr = new.map(|a| a as *const RawMqAttr as u64).unwrap_or(0);
    let old_ptr = old.map(|a| a as *mut RawMqAttr as u64).unwrap_or(0);
    unsafe { syscall4(SYS_MQ_GETSETATTR, mqd, new_ptr, old_ptr, 0) }
}

/// Matches `src/process/signals.rs`'s `do_sigaction`'s own `RawSigAction` wire format exactly.
#[repr(C)]
struct RawSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// This crate's own minimal `__restore_rt` equivalent -- see `userland/pause-syscall-smoke/src/
/// main.rs`'s own module doc comment for why a hand-rolled one is needed here (no musl to provide
/// the real one). Never called directly from Rust; its address is installed as `sigaction`'s own
/// `restorer` field.
global_asm!(
    ".global sigreturn_trampoline",
    "sigreturn_trampoline:",
    "mov rax, {sigreturn}",
    "syscall",
    sigreturn = const SYS_SIGRETURN,
);

unsafe extern "C" {
    fn sigreturn_trampoline();
}

static SIGUSR1_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" fn sigusr1_handler(_signum: i64) {
    SIGUSR1_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn install_sigusr1_handler() -> bool {
    let act = RawSigAction {
        handler: sigusr1_handler as u64,
        flags: 0,
        restorer: sigreturn_trampoline as u64,
        mask: 0,
    };
    unsafe {
        syscall4(SYS_SIGACTION, SIGUSR1, &act as *const RawSigAction as u64, 0, 8).is_ok()
    }
}

fn clock_realtime() -> RawTimespec {
    let mut ts = RawTimespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        let _ = syscall(
            SYS_CLOCK_GETTIME,
            CLOCK_REALTIME,
            &mut ts as *mut RawTimespec as u64,
            0,
        );
    }
    ts
}

fn add_ms(ts: &RawTimespec, ms: i64) -> RawTimespec {
    let mut sec = ts.tv_sec + ms / 1000;
    let mut nsec = ts.tv_nsec + (ms % 1000) * 1_000_000;
    if nsec >= 1_000_000_000 {
        nsec -= 1_000_000_000;
        sec += 1;
    }
    RawTimespec { tv_sec: sec, tv_nsec: nsec }
}

const SIG_BLOCK: u64 = 0;

fn sigprocmask(how: u64, mask: u64) -> Result<u64, u64> {
    unsafe { syscall4(SYS_SIGPROCMASK, how, &mask as *const u64 as u64, 0, 8) }
}

/// Real `sigwait(3)` shape -- musl's own wrapper is a thin call over `sigtimedwait` with a null
/// timeout (see `sig-syscall-smoke`'s own identical helper). A `[u8; 128]` stand-in buffer for
/// `siginfo_t` since this part never needs to interpret its fields, just the returned signal
/// number.
fn sigwait_real(wait_set: u64) -> Result<u64, u64> {
    let mut info = [0u8; 128];
    unsafe {
        syscall4(
            SYS_SIGTIMEDWAIT,
            &wait_set as *const u64 as u64,
            info.as_mut_ptr() as u64,
            0,
            8,
        )
    }
}

/// Part 11's own child: mirrors the Open POSIX Test Suite pilot's `mq_timedsend/16-1.c` shape as
/// closely as this bare-metal crate can -- real `sigprocmask(SIG_BLOCK)` + real blocking
/// `sigwait()` for a signal the parent sends, *then* fills a fresh queue and blocks in
/// `mq_timedsend` with a real multi-second deadline. Part 9 already proved the fork+concurrent-
/// nanosleep shape alone isn't the trigger; this adds the one remaining unreplicated piece from
/// the real pilot test -- a real prior `sigwait()` completion on the same process.
fn sigwait_then_timedsend_child(mqd: u64) -> ! {
    if sigprocmask(SIG_BLOCK, 1 << (SIGUSR1 - 1)).is_err() {
        write_bytes(b"mq-syscall-smoke: part 10 child sigprocmask failed\n");
        unsafe {
            let _ = syscall(SYS_EXIT, 1, 0, 0);
        }
    }
    write_bytes(b"mq-syscall-smoke: part 10 child sigwaiting\n");
    if sigwait_real(1 << (SIGUSR1 - 1)) != Ok(SIGUSR1) {
        write_bytes(b"mq-syscall-smoke: part 10 child sigwait didn't return SIGUSR1\n");
        unsafe {
            let _ = syscall(SYS_EXIT, 1, 0, 0);
        }
    }
    write_bytes(b"mq-syscall-smoke: part 10 child woke from sigwait, filling queue\n");
    for msg in [&b"h0"[..], &b"h1"[..], &b"h2"[..], &b"h3"[..]] {
        if mq_timedsend(mqd, msg, 0, None).is_err() {
            write_bytes(b"mq-syscall-smoke: part 10 child fill failed\n");
            unsafe {
                let _ = syscall(SYS_EXIT, 1, 0, 0);
            }
        }
    }
    let deadline = add_ms(&clock_realtime(), 1500);
    let result = mq_timedsend(mqd, b"overflow", 0, Some(&deadline));
    write_bytes(b"mq-syscall-smoke: part 10 child's blocking mq_timedsend returned\n");
    unsafe {
        let _ = syscall(SYS_EXIT, if result == Err(ETIMEDOUT) { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

fn nanosleep_ms(ms: i64) {
    let ts = RawTimespec { tv_sec: ms / 1000, tv_nsec: (ms % 1000) * 1_000_000 };
    unsafe {
        let _ = syscall(SYS_NANOSLEEP, &ts as *const RawTimespec as u64, 0, 0);
    }
}

/// Part 9's own child: fills a fresh queue to `mq_maxmsg` then blocks in `mq_timedsend` with a
/// real multi-second-scale deadline against it -- mirrors the Open POSIX Test Suite pilot's own
/// `mq_timedsend/16-1.c` shape (a forked child blocking send-side while the parent independently
/// blocks in its own concurrent `nanosleep`), which hangs against the real kernel even though this
/// crate's own simpler, single-process part 5b (no concurrent second blocked process) already
/// proved the same `WaitingForMqSpace` deadline-expiry mechanism works in isolation.
fn timedsend_child(mqd: u64) -> ! {
    for msg in [&b"g0"[..], &b"g1"[..], &b"g2"[..], &b"g3"[..]] {
        if mq_timedsend(mqd, msg, 0, None).is_err() {
            write_bytes(b"mq-syscall-smoke: part 9 child fill failed\n");
            unsafe {
                let _ = syscall(SYS_EXIT, 1, 0, 0);
            }
        }
    }
    let deadline = add_ms(&clock_realtime(), 1500);
    let result = mq_timedsend(mqd, b"overflow", 0, Some(&deadline));
    write_bytes(b"mq-syscall-smoke: part 9 child's blocking mq_timedsend returned\n");
    unsafe {
        let _ = syscall(SYS_EXIT, if result == Err(ETIMEDOUT) { 0 } else { 1 }, 0, 0);
    }
    loop {
        spin_loop();
    }
}

fn child_process(mqd: u64) -> ! {
    write_bytes(b"mq-syscall-smoke: child sending wake message\n");
    if mq_timedsend(mqd, b"wake", 0, None).is_err() {
        write_bytes(b"mq-syscall-smoke: child's mq_timedsend failed\n");
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

const NAME1: &[u8] = b"/mqsmoke1\0";
const NAME2: &[u8] = b"/mqsmoke2\0";
const NAME3: &[u8] = b"/mqsmoke3\0";
const NAME_MISSING: &[u8] = b"/mqsmoke_missing\0";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"mq-syscall-smoke: starting\n");

    if !install_sigusr1_handler() {
        write_bytes(b"mq-syscall-smoke: sigaction failed\n");
        test_exit(false);
    }

    // --- Part 1: open/EEXIST/ENOENT ---
    let attr = RawMqAttr {
        mq_flags: 0,
        mq_maxmsg: 4,
        mq_msgsize: 16,
        mq_curmsgs: 0,
        unused: [0; 4],
    };
    let mqd = match mq_open(NAME1, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr)) {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"mq-syscall-smoke: initial mq_open failed\n");
            test_exit(false);
        }
    };
    check!(
        mq_open(NAME1, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr)) == Err(EEXIST),
        "O_CREAT|O_EXCL against an existing name wasn't EEXIST"
    );
    check!(
        mq_open(NAME_MISSING, O_RDWR, 0, None) == Err(ENOENT),
        "opening a missing name without O_CREAT wasn't ENOENT"
    );
    write_bytes(b"mq-syscall-smoke: part 1 (open/EEXIST/ENOENT) OK\n");

    // --- Part 2: priority ordering ---
    check!(mq_timedsend(mqd, b"aaa", 1, None).is_ok(), "send aaa(prio 1) failed");
    check!(mq_timedsend(mqd, b"bbb", 5, None).is_ok(), "send bbb(prio 5) failed");
    check!(mq_timedsend(mqd, b"ccc", 1, None).is_ok(), "send ccc(prio 1) failed");
    let mut buf = [0u8; 16];
    let mut prio = 0u32;
    let n = mq_timedreceive(mqd, &mut buf, &mut prio, None).unwrap_or(0) as usize;
    check!(&buf[..n] == b"bbb" && prio == 5, "highest-priority message wasn't received first");
    let n = mq_timedreceive(mqd, &mut buf, &mut prio, None).unwrap_or(0) as usize;
    check!(&buf[..n] == b"aaa" && prio == 1, "equal-priority FIFO order broken (expected aaa)");
    let n = mq_timedreceive(mqd, &mut buf, &mut prio, None).unwrap_or(0) as usize;
    check!(&buf[..n] == b"ccc" && prio == 1, "equal-priority FIFO order broken (expected ccc)");
    write_bytes(b"mq-syscall-smoke: part 2 (priority ordering) OK\n");

    // --- Part 3: EMSGSIZE both directions ---
    let too_long = [0u8; 20];
    check!(
        mq_timedsend(mqd, &too_long, 0, None) == Err(EMSGSIZE),
        "a message longer than mq_msgsize wasn't EMSGSIZE"
    );
    check!(mq_timedsend(mqd, b"fits!", 0, None).is_ok(), "send fits! failed");
    let mut small_buf = [0u8; 4];
    check!(
        mq_timedreceive(mqd, &mut small_buf, &mut prio, None) == Err(EMSGSIZE),
        "a receive buffer shorter than mq_msgsize wasn't EMSGSIZE"
    );
    let n = mq_timedreceive(mqd, &mut buf, &mut prio, None).unwrap_or(0) as usize;
    check!(&buf[..n] == b"fits!", "draining the fits! message failed");
    write_bytes(b"mq-syscall-smoke: part 3 (EMSGSIZE) OK\n");

    // --- Part 4: fill to mq_maxmsg, real EAGAIN, attr readback ---
    for msg in [&b"m0"[..], &b"m1"[..], &b"m2"[..], &b"m3"[..]] {
        check!(mq_timedsend(mqd, msg, 0, None).is_ok(), "filling the queue to mq_maxmsg failed");
    }
    let nonblock_attr = RawMqAttr {
        mq_flags: O_NONBLOCK,
        mq_maxmsg: 0,
        mq_msgsize: 0,
        mq_curmsgs: 0,
        unused: [0; 4],
    };
    check!(
        mq_getsetattr(mqd, Some(&nonblock_attr), None).is_ok(),
        "mq_getsetattr(set O_NONBLOCK) failed"
    );
    check!(
        mq_timedsend(mqd, b"overflow", 0, None) == Err(EAGAIN),
        "a nonblocking send against a full queue wasn't EAGAIN"
    );
    let mut readback = RawMqAttr {
        mq_flags: 0,
        mq_maxmsg: 0,
        mq_msgsize: 0,
        mq_curmsgs: 0,
        unused: [0; 4],
    };
    check!(
        mq_getsetattr(mqd, None, Some(&mut readback)).is_ok(),
        "mq_getsetattr(get) failed"
    );
    check!(
        readback.mq_flags == O_NONBLOCK
            && readback.mq_maxmsg == 4
            && readback.mq_msgsize == 16
            && readback.mq_curmsgs == 4,
        "mq_getsetattr readback didn't match real queue state"
    );
    write_bytes(b"mq-syscall-smoke: part 4 (maxmsg/EAGAIN/attr readback) OK\n");

    // Drain the 4 filler messages, confirm empty-queue EAGAIN, then clear O_NONBLOCK.
    for _ in 0..4 {
        check!(
            mq_timedreceive(mqd, &mut buf, &mut prio, None).is_ok(),
            "draining a filler message failed"
        );
    }
    check!(
        mq_timedreceive(mqd, &mut buf, &mut prio, None) == Err(EAGAIN),
        "a nonblocking receive against an empty queue wasn't EAGAIN"
    );
    let blocking_attr = RawMqAttr {
        mq_flags: 0,
        mq_maxmsg: 0,
        mq_msgsize: 0,
        mq_curmsgs: 0,
        unused: [0; 4],
    };
    check!(
        mq_getsetattr(mqd, Some(&blocking_attr), None).is_ok(),
        "mq_getsetattr(clear O_NONBLOCK) failed"
    );

    // --- Part 5: a real deadline actually expiring ---
    let deadline = add_ms(&clock_realtime(), 50);
    check!(
        mq_timedreceive(mqd, &mut buf, &mut prio, Some(&deadline)) == Err(ETIMEDOUT),
        "a real 50ms deadline against an empty queue didn't expire with ETIMEDOUT"
    );
    write_bytes(b"mq-syscall-smoke: part 5 (real timeout) OK\n");

    // --- Part 5b: a real deadline expiring while blocked on a FULL queue (WaitingForMqSpace,
    // not WaitingForMqData like part 5 above) -- found live via the Open POSIX Test Suite pilot's
    // own mq_timedsend/16-1.c, which never returns from this exact call shape.
    for msg in [&b"f0"[..], &b"f1"[..], &b"f2"[..], &b"f3"[..]] {
        check!(mq_timedsend(mqd, msg, 0, None).is_ok(), "filling the queue for part 5b failed");
    }
    let send_deadline = add_ms(&clock_realtime(), 50);
    check!(
        mq_timedsend(mqd, b"overflow", 0, Some(&send_deadline)) == Err(ETIMEDOUT),
        "a real 50ms deadline against a full queue didn't expire with ETIMEDOUT"
    );
    for _ in 0..4 {
        check!(
            mq_timedreceive(mqd, &mut buf, &mut prio, None).is_ok(),
            "draining a part 5b filler message failed"
        );
    }
    write_bytes(b"mq-syscall-smoke: part 5b (real timeout while send-blocked) OK\n");

    // --- Part 6: real block/wake pair across fork ---
    let fork_result = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid = match fork_result {
        Ok(0) => child_process(mqd),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"mq-syscall-smoke: fork failed\n");
            test_exit(false);
        }
    };
    write_bytes(b"mq-syscall-smoke: parent blocking in mq_timedreceive\n");
    match mq_timedreceive(mqd, &mut buf, &mut prio, None) {
        Ok(n) => check!(&buf[..n as usize] == b"wake", "woke with the wrong message"),
        Err(_) => {
            write_bytes(b"mq-syscall-smoke: blocking mq_timedreceive failed\n");
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
    write_bytes(b"mq-syscall-smoke: part 6 (block/wake pair) OK\n");

    // --- Part 7: mq_notify/SIGEV_SIGNAL, one-shot ---
    let sev = RawSigevent {
        sigev_value: 0,
        sigev_signo: SIGUSR1 as i32,
        sigev_notify: SIGEV_SIGNAL,
        pad: [0; 48],
    };
    check!(mq_notify(mqd, Some(&sev)).is_ok(), "mq_notify registration failed");
    check!(
        mq_timedsend(mqd, b"notify1", 0, None).is_ok(),
        "notify-triggering send failed"
    );
    // Real POSIX ordering: the caught handler already ran (hijacking this same mq_timedsend
    // call's own return path) by the time control resumes here -- see this file's own module doc
    // comment, part 7, and `pause-syscall-smoke`'s identical proof for `pause()`.
    check!(SIGUSR1_COUNT.load(Ordering::SeqCst) == 1, "mq_notify didn't fire exactly once");
    check!(
        mq_timedsend(mqd, b"notify2", 0, None).is_ok(),
        "second send after notify fired failed"
    );
    check!(
        SIGUSR1_COUNT.load(Ordering::SeqCst) == 1,
        "mq_notify fired again without being re-registered (should be one-shot)"
    );
    // Drain both notify messages so the queue is empty again for part 8.
    check!(mq_timedreceive(mqd, &mut buf, &mut prio, None).is_ok(), "draining notify1 failed");
    check!(mq_timedreceive(mqd, &mut buf, &mut prio, None).is_ok(), "draining notify2 failed");
    write_bytes(b"mq-syscall-smoke: part 7 (mq_notify, one-shot) OK\n");

    // --- Part 8: mq_unlink survives an open descriptor ---
    check!(mq_unlink(NAME1).is_ok(), "mq_unlink failed");
    check!(
        mq_open(NAME1, O_RDWR, 0, None) == Err(ENOENT),
        "the name was still openable after mq_unlink"
    );
    check!(
        mq_timedsend(mqd, b"still alive", 0, None).is_ok(),
        "send against the still-open, already-unlinked queue failed"
    );
    let n = mq_timedreceive(mqd, &mut buf, &mut prio, None).unwrap_or(0) as usize;
    check!(
        &buf[..n] == b"still alive",
        "receive against the still-open, already-unlinked queue failed"
    );
    check!(
        unsafe { syscall(SYS_CLOSE, mqd, 0, 0) }.is_ok(),
        "closing the mqd failed"
    );
    write_bytes(b"mq-syscall-smoke: part 8 (unlink survives open descriptor) OK\n");

    // --- Part 9: a real deadline expiring while send-blocked in a forked child, concurrently
    // with the parent independently blocked in its own nanosleep -- see timedsend_child's own doc
    // comment for why this is a distinct scenario from part 5b.
    let attr2 = RawMqAttr {
        mq_flags: 0,
        mq_maxmsg: 4,
        mq_msgsize: 16,
        mq_curmsgs: 0,
        unused: [0; 4],
    };
    let mqd2 = match mq_open(NAME2, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr2)) {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"mq-syscall-smoke: part 9 mq_open failed\n");
            test_exit(false);
        }
    };
    let fork_result2 = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid2 = match fork_result2 {
        Ok(0) => timedsend_child(mqd2),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"mq-syscall-smoke: part 9 fork failed\n");
            test_exit(false);
        }
    };
    write_bytes(b"mq-syscall-smoke: parent nanosleeping while child send-blocks\n");
    nanosleep_ms(3000);
    let mut status2: i32 = -1;
    check!(
        unsafe { syscall4(SYS_WAIT4, child_pid2, &mut status2 as *mut i32 as u64, 0, 0) }
            == Ok(child_pid2),
        "part 9 wait4 didn't report the child"
    );
    check!(status2 == 0, "part 9 child's blocking mq_timedsend didn't return real ETIMEDOUT");
    write_bytes(b"mq-syscall-smoke: part 9 (concurrent send-block timeout) OK\n");

    // --- Part 10: the real mq_timedsend/16-1.c shape -- a forked child that real-`sigwait()`s
    // for a signal from the parent *before* blocking in mq_timedsend against a full queue.
    let attr3 = RawMqAttr {
        mq_flags: 0,
        mq_maxmsg: 4,
        mq_msgsize: 16,
        mq_curmsgs: 0,
        unused: [0; 4],
    };
    let mqd3 = match mq_open(NAME3, O_CREAT | O_EXCL | O_RDWR, 0o600, Some(&attr3)) {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"mq-syscall-smoke: part 10 mq_open failed\n");
            test_exit(false);
        }
    };
    let fork_result3 = unsafe { syscall(SYS_FORK, 0, 0, 0) };
    let child_pid3 = match fork_result3 {
        Ok(0) => sigwait_then_timedsend_child(mqd3),
        Ok(child_pid) => child_pid,
        Err(_) => {
            write_bytes(b"mq-syscall-smoke: part 10 fork failed\n");
            test_exit(false);
        }
    };
    nanosleep_ms(200);
    write_bytes(b"mq-syscall-smoke: parent sending SIGUSR1 to part 10 child\n");
    check!(
        unsafe { syscall(SYS_KILL, child_pid3, SIGUSR1, 0) }.is_ok(),
        "part 10 kill(SIGUSR1) failed"
    );
    let mut status3: i32 = -1;
    check!(
        unsafe { syscall4(SYS_WAIT4, child_pid3, &mut status3 as *mut i32 as u64, 0, 0) }
            == Ok(child_pid3),
        "part 10 wait4 didn't report the child"
    );
    check!(
        status3 == 0,
        "part 10 child's sigwait-then-mq_timedsend didn't return real ETIMEDOUT"
    );
    write_bytes(b"mq-syscall-smoke: part 10 (sigwait then send-block timeout) OK\n");

    write_bytes(b"mq-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = unsafe { syscall(SYS_EXIT, 1, 0, 0) };
    loop {
        spin_loop();
    }
}
