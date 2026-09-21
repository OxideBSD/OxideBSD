//! Raw `SYSCALL` stubs for OxideBSD's own native, BSD-flavored ABI (see `CLAUDE.md`'s Syscall ABI
//! section) -- the exact `asm!("syscall", "setc ...")` block every freestanding `regress/*`/
//! `usr.bin/*` crate in this codebase has, until now, each hand-duplicated separately. Number in
//! `RAX`, up to four arguments in `RDI`/`RSI`/`RDX`/`R10` (not `RCX`/`R11`, clobbered by `SYSCALL`
//! itself), success/failure via the carry flag (`CF=0` success, value in `RAX`; `CF=1` failure,
//! positive errno in `RAX`).

use core::arch::asm;

/// A 3-argument syscall (`R10` zeroed -- most syscalls this ABI defines only ever look at three).
#[inline(always)]
pub unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
}

/// A 4-argument syscall -- `SYS_EXECVE`'s `envp` and a real `open(O_CREAT)`'s mode both need the
/// real 4th argument (`R10`).
#[inline(always)]
pub unsafe fn syscall4(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> Result<u64, u64> {
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
