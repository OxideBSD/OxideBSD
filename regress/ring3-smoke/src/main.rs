//! A minimal freestanding ring-3 smoke test.
//!
//! Not part of the kernel — this is a standalone ELF binary, built by the kernel's `build.rs` and
//! embedded via `include_bytes!`, that the kernel loads and jumps into to prove paging, address
//! space separation, ELF loading, and OxideBSD's native (BSD-style) syscall ABI all actually work.
//! It does a bit of arithmetic (so there's real work for the CPU to have done), writes a success
//! message via `SYS_WRITE`, deliberately triggers an `EBADF` failure to exercise the carry-flag
//! error convention in *both* directions (not just the happy path), then terminates via `SYS_EXIT`
//! with the computed checksum as its exit code.
//!
//! The syscall numbers/register convention here must match `sys/syscall.rs` in the kernel
//! exactly — there's no shared crate between the two, this is the ABI boundary itself.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_WRITE: u64 = 4;
const STDOUT: u64 = 1;
const INVALID_FD: u64 = 42;
const EBADF: u64 = 9;

/// Issues a syscall via `SYSCALL`: number in `rax`, up to three arguments in `rdi`/`rsi`/`rdx`.
/// Success/failure comes back via the carry flag (OxideBSD's native, BSD-style convention) —
/// `Ok(value)` if `CF` came back clear, `Err(errno)` if it came back set. `rcx`/`r11` must be
/// declared clobbered: `SYSCALL` itself overwrites them (to save `RIP`/`RFLAGS` on entry), so
/// whatever this program had in them beforehand doesn't survive the call — the kernel's
/// `syscall_entry` preserves every other register.
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut checksum: u64 = 0;
    for i in 0..1000u64 {
        checksum = checksum.wrapping_add(i);
    }

    unsafe {
        let message = b"ring3-smoke: hello from ring 3, via SYS_WRITE\n";
        let _ = syscall(
            SYS_WRITE,
            STDOUT,
            message.as_ptr() as u64,
            message.len() as u64,
        );

        // Deliberately fail: an invalid fd should come back Err(EBADF), not just "something
        // nonzero" -- this is the actual proof the carry-flag convention (and the RFLAGS-in-the-
        // hardware-frame trick that implements it) works in the failure direction too, not only
        // the happy path.
        let bad_fd_result = syscall(
            SYS_WRITE,
            INVALID_FD,
            message.as_ptr() as u64,
            message.len() as u64,
        );
        let outcome_message: &[u8] = if bad_fd_result == Err(EBADF) {
            b"ring3-smoke: EBADF correctly reported via carry flag\n"
        } else {
            b"ring3-smoke: !!! carry-flag error reporting is broken !!!\n"
        };
        let _ = syscall(
            SYS_WRITE,
            STDOUT,
            outcome_message.as_ptr() as u64,
            outcome_message.len() as u64,
        );

        let _ = syscall(SYS_EXIT, checksum, 0, 0);
    }

    // SYS_EXIT never returns, but the kernel's dispatcher is a normal Rust match, not something
    // the type system knows diverges from all the way out here through the asm! call above.
    loop {
        spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
