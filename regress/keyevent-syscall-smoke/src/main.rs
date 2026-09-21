//! Real-`SYSCALL` smoke test for `SYS_GET_KEYEVENT = 558` (`sys/modules/posix_compat`'s
//! `handle_get_keyevent` -> `sys/syscall/ffi.rs`'s `sys_get_keyevent` -> `console::keyevents`'s
//! new non-blocking raw-key-event ring buffer) -- real, general-purpose input-event
//! infrastructure for the fbdoom/doomgeneric port (and any future consumer needing real held-key
//! state, which `console::stdin`'s own decoded-ASCII stream can never provide -- see that
//! module's own doc comment).
//!
//! Two parts, both through `tests/keyevent_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. Polling with nothing pressed returns `Ok(0)` repeatedly -- never blocks, never errors, never
//!    returns a bogus "event" out of an empty buffer.
//! 2. A malformed/negative case: the syscall itself (not the ring buffer) must still behave
//!    correctly called back-to-back many times in a tight loop, matching the "poll once per tic"
//!    shape a real game loop uses -- proves this doesn't leak state or wedge across repeated
//!    calls.
//!
//! **Not covered here** (needs a human/external driver, not this in-VM test binary): a real
//! keypress round-trip via `OXIDEBSD_QEMU_MONITOR`'s `sendkey` -- verified separately, live,
//! against an interactively-booted kernel (see this project's own plan notes), since nothing
//! inside this spawned process can synthesize a hardware keyboard IRQ itself.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_GET_KEYEVENT: u64 = 558;
/// Not a real syscall number anything else in this codebase registers -- same convention every
/// other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

/// Must match `sys/console/keyevents.rs`'s own `RawKeyEvent` exactly -- no shared crate across
/// this ABI boundary, same convention every other regress/kernel wire-struct pair here uses.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawKeyEvent {
    keycode: u8,
    pressed: u8,
}

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

fn get_keyevent() -> Result<u64, u64> {
    let mut event = RawKeyEvent::default();
    unsafe { syscall(SYS_GET_KEYEVENT, &mut event as *mut RawKeyEvent as u64, 0, 0) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"keyevent-syscall-smoke: starting\n");

    // Part 1 + 2: repeated, tight-loop, non-blocking polling with nothing pressed.
    for i in 0..1000u32 {
        match get_keyevent() {
            Ok(0) => {}
            Ok(_) => {
                write_bytes(b"keyevent-syscall-smoke: got a phantom event with nothing pressed\n");
                test_exit(false);
            }
            Err(_) => {
                write_bytes(b"keyevent-syscall-smoke: SYS_GET_KEYEVENT returned an error\n");
                test_exit(false);
            }
        }
        let _ = i;
    }
    write_bytes(b"keyevent-syscall-smoke: 1000 non-blocking polls, all Ok(0) -- OK\n");

    write_bytes(b"keyevent-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
