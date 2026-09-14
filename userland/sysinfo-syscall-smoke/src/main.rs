//! Real-`SYSCALL` smoke test for `SYS_SYSINFO = 527` (`modules/posix_compat`'s `handle_sysinfo`
//! -> `src/syscall/ffi.rs`'s `sys_sysinfo`/`RawSysinfo`) -- item 2 of
//! `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch.
//!
//! Deliberately a real spawned ELF driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust
//! function call from a test's own `main()` -- the same class of bug the musl-port section of
//! CLAUDE.md documents repeatedly catching (a matched number with a mismatched argument/struct-
//! layout shape) is only visible through a real syscall instruction.
//!
//! `RawSysinfoLocal` below is a userland-side mirror of the kernel's own `RawSysinfo` (368 bytes,
//! confirmed via a direct C `offsetof`/`sizeof` probe against musl's real `struct sysinfo`) -- no
//! shared crate exists across this ABI boundary, same convention every other userland/kernel pair
//! here uses.
//!
//! Three parts, all through `tests/sysinfo_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. A real call succeeds (`CF=0`), `mem_unit == 1`, `totalram > 0`, `freeram == totalram`
//!    (this kernel's own documented "no deallocation tracking" honesty tier), `procs >= 1` (this
//!    process itself), and every field with no real backing (`loads`, `sharedram`, `bufferram`,
//!    `totalswap`, `freeswap`, `totalhigh`, `freehigh`) is honestly zero, not fabricated.
//! 2. A second call's `uptime` is never less than the first's -- a real, monotonically
//!    non-decreasing tick-derived value, not a fixed/stubbed number.
//! 3. `totalram` is stable across both calls (a real, unchanging RAM-size constant).
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_SYSINFO: u64 = 527;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// sysinfo_syscall_smoke.rs` registers this one directly against a test-only handler, same
/// convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSysinfoLocal {
    uptime: u64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    reserved: [u8; 256],
}

const _: () = assert!(core::mem::size_of::<RawSysinfoLocal>() == 368);

impl RawSysinfoLocal {
    const fn zeroed() -> Self {
        RawSysinfoLocal {
            uptime: 0,
            loads: [0; 3],
            totalram: 0,
            freeram: 0,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 0,
            pad: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 0,
            reserved: [0; 256],
        }
    }
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

fn sysinfo() -> Result<RawSysinfoLocal, u64> {
    let mut info = RawSysinfoLocal::zeroed();
    let ptr = &mut info as *mut RawSysinfoLocal as u64;
    unsafe { syscall(SYS_SYSINFO, ptr, 0, 0) }?;
    Ok(info)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"sysinfo-syscall-smoke: starting\n");

    // Part 1: a real call, checked field by field.
    let info_a = match sysinfo() {
        Ok(info) => info,
        Err(_) => {
            write_bytes(b"sysinfo-syscall-smoke: first sysinfo() call failed\n");
            test_exit(false);
        }
    };
    if info_a.mem_unit != 1 {
        write_bytes(b"sysinfo-syscall-smoke: mem_unit != 1\n");
        test_exit(false);
    }
    if info_a.totalram == 0 {
        write_bytes(b"sysinfo-syscall-smoke: totalram == 0\n");
        test_exit(false);
    }
    if info_a.freeram != info_a.totalram {
        write_bytes(b"sysinfo-syscall-smoke: freeram != totalram\n");
        test_exit(false);
    }
    if info_a.procs < 1 {
        write_bytes(b"sysinfo-syscall-smoke: procs < 1\n");
        test_exit(false);
    }
    if info_a.loads != [0; 3]
        || info_a.sharedram != 0
        || info_a.bufferram != 0
        || info_a.totalswap != 0
        || info_a.freeswap != 0
        || info_a.totalhigh != 0
        || info_a.freehigh != 0
    {
        write_bytes(b"sysinfo-syscall-smoke: an untracked field wasn't honestly zero\n");
        test_exit(false);
    }
    write_bytes(b"sysinfo-syscall-smoke: first call OK (mem_unit/totalram/freeram/procs/zeroed fields)\n");

    // Part 2 + 3: a second call -- uptime non-decreasing, totalram stable.
    let info_b = match sysinfo() {
        Ok(info) => info,
        Err(_) => {
            write_bytes(b"sysinfo-syscall-smoke: second sysinfo() call failed\n");
            test_exit(false);
        }
    };
    if info_b.uptime < info_a.uptime {
        write_bytes(b"sysinfo-syscall-smoke: uptime went backwards\n");
        test_exit(false);
    }
    if info_b.totalram != info_a.totalram {
        write_bytes(b"sysinfo-syscall-smoke: totalram changed between calls\n");
        test_exit(false);
    }
    write_bytes(b"sysinfo-syscall-smoke: second call OK (uptime non-decreasing, totalram stable)\n");

    write_bytes(b"sysinfo-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
