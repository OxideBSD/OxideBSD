//! Real-`SYSCALL` driver for the module allocator (VFS.md §3.1): drives the test-only
//! `alloc_smoke` module (`sys/modules/alloc_smoke`), whose system call handler allocates through
//! `lib/libkern-mod`, and checks through `tests/kmod_alloc_syscall_smoke.rs`'s `SYS_ALLOC_STATS`
//! that what the module holds is charged to it and goes back to zero when freed.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
/// Must match `tests/kmod_alloc_syscall_smoke.rs`.
const SYS_TEST_EXIT: u64 = 9999;
/// Must match `sys/modules/alloc_smoke`.
const SYS_ALLOC_SMOKE: u64 = 9995;
/// Must match `tests/kmod_alloc_syscall_smoke.rs`: `alloc_smoke`'s charged bytes (arg 0) or
/// allocation count (arg 1).
const SYS_ALLOC_STATS: u64 = 9994;

const OP_FILL: u64 = 1;
const OP_DROP: u64 = 2;
const OP_HUGE: u64 = 3;

const SEED: u64 = 0x1234;
/// `alloc_smoke`'s checksum for `SEED`: squares 1..=64 (89440), rects n x (n+1) (91520), map value
/// lengths 0..256 (32640), and `alloc_smoke seed=0x1234 shapes=128 keys=(0, "z")\n` (49 bytes).
const FILL_SUM: u64 = 89440 + 91520 + 32640 + 49;

const STDOUT: u64 = 1;

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
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
            in("r10") 0u64,
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
            write_bytes(b"kmod-alloc-syscall-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
}

fn alloc_smoke(op: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_ALLOC_SMOKE, op, SEED, 0) }
}

fn charged_bytes() -> u64 {
    unsafe { syscall(SYS_ALLOC_STATS, 0, 0, 0) }.unwrap_or(u64::MAX)
}

fn charged_count() -> u64 {
    unsafe { syscall(SYS_ALLOC_STATS, 1, 0, 0) }.unwrap_or(u64::MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"kmod-alloc-syscall-smoke: starting\n");

    check!(charged_bytes() == 0, b"module_init's allocation wasn't freed (or wasn't charged back)");

    for round in 0..2 {
        check!(alloc_smoke(OP_FILL) == Ok(FILL_SUM), b"OP_FILL's checksum");
        // 128 boxes, the Vec, 256 map values plus the map's nodes, the string.
        check!(charged_count() >= 128 + 256 + 2, b"OP_FILL's allocations weren't charged to the module");
        check!(charged_bytes() >= 32640, b"OP_FILL's bytes weren't charged to the module");
        check!(alloc_smoke(OP_DROP) == Ok(0), b"OP_DROP");
        check!(charged_bytes() == 0, b"bytes still charged after OP_DROP");
        check!(charged_count() == 0, b"allocations still charged after OP_DROP");
        if round == 0 {
            write_bytes(b"kmod-alloc-syscall-smoke: fill/drop round 0 ok\n");
        }
    }

    check!(alloc_smoke(OP_HUGE) == Ok(0), b"try_reserve(1 TiB) didn't fail cleanly");
    check!(charged_bytes() == 0, b"a failed allocation was charged");

    write_bytes(b"kmod-alloc-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
