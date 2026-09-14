//! Real-`SYSCALL` smoke test for `SYS_SIGALTSTACK = 528` (`modules/signal`'s `handle_sigaltstack`
//! -> `src/syscall/ffi.rs`'s `sys_sigaltstack` -> `src/process/signals.rs`'s `do_sigaltstack`/
//! `AltStack`) -- item 3 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- the same class of bug the musl-port section of
//! CLAUDE.md documents repeatedly catching (a matched number with a mismatched argument/struct-
//! layout shape) is only visible through a real syscall instruction. `RawSigaltstackLocal` below
//! is a userland-side mirror of the kernel's own `RawSigaltstack` (24 bytes: `ss_sp`/`ss_flags`/
//! `ss_size`, matching real musl `struct sigaltstack`) -- no shared crate exists across this ABI
//! boundary, same convention every other userland/kernel pair here uses.
//!
//! This is a real, raw `syscall()` driven test, not `sigaltstack()` through musl's own libc
//! wrapper -- musl's wrapper filters `SS_ONSTACK`/an undersized `ss_size` client-side before ever
//! reaching the kernel (see `do_sigaltstack`'s own doc comment), so exercising the kernel's own
//! `EINVAL` path for a bad flag bit needs a call that bypasses it.
//!
//! Five parts, all through `tests/sigaltstack_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. The real POSIX startup state: disabled (`SS_DISABLE` set, `sp == 0`, `size == 0`).
//! 2. Setting a real alt stack (`flags == 0`) succeeds.
//! 3. Reading it back reports the same `sp`/`size`, and `flags == 0` -- neither `SS_DISABLE` (it's
//!    enabled) nor `SS_ONSTACK` (this kernel never actually executes a handler on it).
//! 4. A combined set+read-old call in one shot reports the *previous* state before applying the
//!    new one.
//! 5. An invalid flag bit is a real `EINVAL`, and disabling (`SS_DISABLE`) resets `sp`/`size` back
//!    to `0`.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_SIGALTSTACK: u64 = 528;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sigaltstack_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

/// Real `sigaltstack(2)` flag bits (`third_party/musl/include/signal.h`).
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
/// Real value, matches `src/syscall/mod.rs`'s own `EINVAL`; identical on Linux/BSD/musl.
const EINVAL: u64 = 22;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSigaltstackLocal {
    sp: u64,
    flags: i32,
    size: u64,
}

const _: () = assert!(core::mem::size_of::<RawSigaltstackLocal>() == 24);

impl RawSigaltstackLocal {
    const fn zeroed() -> Self {
        RawSigaltstackLocal {
            sp: 0,
            flags: 0,
            size: 0,
        }
    }
}

/// A real backing region for the alt stack we install -- large enough to clear any real
/// `_SC_MINSIGSTKSZ` floor musl's own client-side check might enforce, though this test never
/// goes through that wrapper anyway (see this crate's own module doc comment).
static mut ALTSTACK_REGION: [u8; 16384] = [0u8; 16384];

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

fn sigaltstack(
    new: Option<&RawSigaltstackLocal>,
    old: Option<&mut RawSigaltstackLocal>,
) -> Result<u64, u64> {
    let ss_ptr = new.map(|r| r as *const RawSigaltstackLocal as u64).unwrap_or(0);
    let old_ptr = old
        .map(|r| r as *mut RawSigaltstackLocal as u64)
        .unwrap_or(0);
    unsafe { syscall(SYS_SIGALTSTACK, ss_ptr, old_ptr, 0) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sigaltstack-syscall-smoke: starting\n");

    // Part 1: real POSIX startup state -- disabled.
    let mut initial = RawSigaltstackLocal::zeroed();
    if sigaltstack(None, Some(&mut initial)) != Ok(0) {
        write_bytes(b"sigaltstack-syscall-smoke: initial read call failed\n");
        test_exit(false);
    }
    if initial.flags & SS_DISABLE == 0 || initial.sp != 0 || initial.size != 0 {
        write_bytes(b"sigaltstack-syscall-smoke: initial state wasn't disabled/zeroed\n");
        test_exit(false);
    }
    write_bytes(b"sigaltstack-syscall-smoke: initial state OK (disabled, sp=0, size=0)\n");

    // Part 2: install a real alt stack.
    let region_ptr = &raw mut ALTSTACK_REGION as *mut u8 as u64;
    let region_size = 16384u64;
    let new_stack = RawSigaltstackLocal {
        sp: region_ptr,
        flags: 0,
        size: region_size,
    };
    if sigaltstack(Some(&new_stack), None) != Ok(0) {
        write_bytes(b"sigaltstack-syscall-smoke: installing a new alt stack failed\n");
        test_exit(false);
    }
    write_bytes(b"sigaltstack-syscall-smoke: installed a new alt stack\n");

    // Part 3: read it back.
    let mut readback = RawSigaltstackLocal::zeroed();
    if sigaltstack(None, Some(&mut readback)) != Ok(0) {
        write_bytes(b"sigaltstack-syscall-smoke: read-back call failed\n");
        test_exit(false);
    }
    if readback.sp != region_ptr || readback.size != region_size || readback.flags != 0 {
        write_bytes(b"sigaltstack-syscall-smoke: read-back didn't match what was installed\n");
        test_exit(false);
    }
    write_bytes(b"sigaltstack-syscall-smoke: read-back matches (sp/size/flags==0) OK\n");

    // Part 4: combined set+read-old in one shot -- reports the state from just before.
    let replacement = RawSigaltstackLocal {
        sp: region_ptr,
        flags: 0,
        size: region_size / 2,
    };
    let mut old_state = RawSigaltstackLocal::zeroed();
    if sigaltstack(Some(&replacement), Some(&mut old_state)) != Ok(0) {
        write_bytes(b"sigaltstack-syscall-smoke: combined set+read-old call failed\n");
        test_exit(false);
    }
    if old_state.sp != region_ptr || old_state.size != region_size || old_state.flags != 0 {
        write_bytes(b"sigaltstack-syscall-smoke: combined call's old-state didn't match\n");
        test_exit(false);
    }
    write_bytes(b"sigaltstack-syscall-smoke: combined set+read-old OK\n");

    // Part 5: an invalid flag bit is EINVAL, and disabling zeroes sp/size.
    let bad = RawSigaltstackLocal {
        sp: region_ptr,
        flags: 0xFF,
        size: region_size,
    };
    if sigaltstack(Some(&bad), None) != Err(EINVAL) {
        write_bytes(b"sigaltstack-syscall-smoke: an invalid flag bit didn't fail EINVAL\n");
        test_exit(false);
    }
    let disable = RawSigaltstackLocal {
        sp: 0,
        flags: SS_DISABLE,
        size: 0,
    };
    if sigaltstack(Some(&disable), None) != Ok(0) {
        write_bytes(b"sigaltstack-syscall-smoke: disabling the alt stack failed\n");
        test_exit(false);
    }
    let mut after_disable = RawSigaltstackLocal::zeroed();
    if sigaltstack(None, Some(&mut after_disable)) != Ok(0) {
        write_bytes(b"sigaltstack-syscall-smoke: post-disable read call failed\n");
        test_exit(false);
    }
    if after_disable.flags & SS_DISABLE == 0 || after_disable.sp != 0 || after_disable.size != 0 {
        write_bytes(b"sigaltstack-syscall-smoke: post-disable state wasn't disabled/zeroed\n");
        test_exit(false);
    }
    if after_disable.flags & SS_ONSTACK != 0 {
        write_bytes(b"sigaltstack-syscall-smoke: SS_ONSTACK was reported set\n");
        test_exit(false);
    }
    write_bytes(b"sigaltstack-syscall-smoke: EINVAL + disable OK\n");

    write_bytes(b"sigaltstack-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
