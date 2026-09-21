//! Real-`SYSCALL` smoke test for `SYS_GETRANDOM = 526` (`sys/modules/posix_compat`'s
//! `handle_getrandom` -> `sys/syscall/ffi.rs`'s `sys_getrandom` -> `sys/random.rs`'s existing
//! generator) -- item 1 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- `tests/random_smoke.rs` already covers
//! `sys/random.rs`'s own cryptographic logic directly (see that test's own doc comment for why
//! that's the right call for the generator itself); this test's job is narrower and different:
//! proving the *syscall plumbing* actually reaches it -- number registration, the module's
//! `extern "C"` wrapper, and the real `(buf_ptr, buflen, flags)` argument convention -- through an
//! actual `SYSCALL` instruction, the same class of bug the musl-port section of CLAUDE.md
//! documents repeatedly catching (a matched number with a mismatched argument shape).
//!
//! Four parts, all through `tests/getrandom_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. A 32-byte request succeeds, returns 32, and isn't a degenerate single-repeated-byte buffer.
//! 2. A second 32-byte request produces different output than the first (real per-call entropy,
//!    not a fixed buffer a stub could also satisfy).
//! 3. `len == 0` returns `0` and leaves the buffer untouched, matching this codebase's own
//!    established convention for every other zero-length read/write.
//! 4. An invalid flag bit (anything outside real `GRND_NONBLOCK`/`GRND_RANDOM`) fails real
//!    `EINVAL`; `GRND_NONBLOCK`/`GRND_RANDOM` themselves are each accepted without error (this
//!    generator has no blocking-on-low-entropy distinction to honor them against, but real Linux
//!    callers -- musl's own `getentropy()` passes `flags = 0`, but real Linux's `getrandom(2)`
//!    manpage documents both as valid -- must not be rejected).
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_GETRANDOM: u64 = 526;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// getrandom_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

/// Real `getrandom(2)` flag bits (`external/mit/musl/include/sys/random.h`).
const GRND_NONBLOCK: u64 = 0x0001;
const GRND_RANDOM: u64 = 0x0002;
/// Real value, matches `sys/syscall/mod.rs`'s own `EINVAL`; identical on Linux/BSD/musl.
const EINVAL: u64 = 22;

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

fn getrandom(buf: &mut [u8], flags: u64) -> Result<u64, u64> {
    unsafe { syscall(SYS_GETRANDOM, buf.as_mut_ptr() as u64, buf.len() as u64, flags) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"getrandom-syscall-smoke: starting\n");

    // Part 1: a real 32-byte request.
    let mut buf_a = [0u8; 32];
    match getrandom(&mut buf_a, 0) {
        Ok(32) => {}
        Ok(n) => {
            write_bytes(b"getrandom-syscall-smoke: wrong byte count on first call\n");
            let _ = n;
            test_exit(false);
        }
        Err(_) => {
            write_bytes(b"getrandom-syscall-smoke: first getrandom() call failed\n");
            test_exit(false);
        }
    }
    if buf_a.iter().all(|&b| b == buf_a[0]) {
        write_bytes(b"getrandom-syscall-smoke: output is a single repeated byte\n");
        test_exit(false);
    }
    write_bytes(b"getrandom-syscall-smoke: 32-byte request OK, not degenerate\n");

    // Part 2: a second request must produce different bytes.
    let mut buf_b = [0u8; 32];
    if getrandom(&mut buf_b, 0) != Ok(32) {
        write_bytes(b"getrandom-syscall-smoke: second getrandom() call failed\n");
        test_exit(false);
    }
    if buf_a == buf_b {
        write_bytes(b"getrandom-syscall-smoke: two consecutive calls produced identical output\n");
        test_exit(false);
    }
    write_bytes(b"getrandom-syscall-smoke: two consecutive calls differ -- real per-call entropy\n");

    // Part 3: len == 0 must be a harmless no-op.
    let mut empty = [0xAAu8; 4];
    match getrandom(&mut empty[..0], 0) {
        Ok(0) => {}
        _ => {
            write_bytes(b"getrandom-syscall-smoke: len == 0 should return 0\n");
            test_exit(false);
        }
    }
    if empty != [0xAA; 4] {
        write_bytes(b"getrandom-syscall-smoke: len == 0 touched the buffer\n");
        test_exit(false);
    }
    write_bytes(b"getrandom-syscall-smoke: len == 0 verified as a no-op\n");

    // Part 4: flag handling.
    let mut buf_c = [0u8; 8];
    if getrandom(&mut buf_c, GRND_NONBLOCK) != Ok(8) {
        write_bytes(b"getrandom-syscall-smoke: GRND_NONBLOCK was rejected\n");
        test_exit(false);
    }
    if getrandom(&mut buf_c, GRND_RANDOM) != Ok(8) {
        write_bytes(b"getrandom-syscall-smoke: GRND_RANDOM was rejected\n");
        test_exit(false);
    }
    if getrandom(&mut buf_c, 0xFFFF_FFFF) != Err(EINVAL) {
        write_bytes(b"getrandom-syscall-smoke: an invalid flag bit didn't fail EINVAL\n");
        test_exit(false);
    }
    write_bytes(b"getrandom-syscall-smoke: flag handling (GRND_NONBLOCK/GRND_RANDOM/EINVAL) OK\n");

    write_bytes(b"getrandom-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
