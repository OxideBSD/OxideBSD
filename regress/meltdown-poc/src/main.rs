//! Meltdown PoC regression test (tier 1), spawned as pid 1 by `tests/meltdown_poc_smoke.rs`.
//!
//! KPTI (`OxideBSD-doc/THREAT_MODEL.md` §3.4) stops Meltdown by running ring 3 on page tables that
//! don't map the kernel, so a speculative read of a kernel address has no translation to resolve.
//! This proves that property two ways, without a cache-timing side channel:
//!
//! 1. **Behavioural:** a ring-3 read of a kernel address faults (`SIGSEGV`) rather than returning
//!    data -- true with or without KPTI, a sanity check that supervisor memory is off limits.
//! 2. **Structural (the real KPTI proof):** `SYS_KPTI_PROBE` asks the kernel to walk this process's
//!    own user table and confirm those kernel addresses are genuinely absent from it (present only
//!    in the kernel table), so there is nothing for Meltdown to speculate against. The kernel
//!    reports the verdict and exits the test; when KPTI is off it reports SKIP.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
/// Registered by `tests/meltdown_poc_smoke.rs`: asks the kernel to run the structural probe and
/// exit the test with the result (PASS / SKIP / FAIL).
const SYS_KPTI_PROBE: u64 = 9996;
/// Registered by the harness; used only if the probe somehow returns.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGSEGV: i32 = 11;

/// Kernel addresses a ring-3 read must never reach: the top-2 GiB kernel image base, and the
/// kernel heap (`allocator::HEAP_START`). Both are supervisor pages, and under KPTI both are
/// absent from this process's page tables entirely.
const KERNEL_IMAGE_BASE: u64 = 0xffff_ffff_8000_0000;
const KERNEL_HEAP_BASE: u64 = 0xffff_c100_0000_0000;

fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
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
    let _ = syscall(SYS_WRITE, STDOUT, s.as_ptr() as u64, s.len() as u64);
}

fn exit(code: u64) -> ! {
    let _ = syscall(SYS_EXIT, code, 0, 0);
    loop {
        spin_loop();
    }
}

fn fail(what: &[u8]) -> ! {
    write_bytes(b"meltdown-poc: FAIL: ");
    write_bytes(what);
    write_bytes(b"\n");
    let _ = syscall(SYS_TEST_EXIT, 1, 0, 0);
    loop {
        spin_loop();
    }
}

/// Reads one byte from `addr`. If the read ever completes, the value is returned (a leak); the
/// point is that it must fault instead.
fn read_kernel(addr: u64) {
    let mut v: u64;
    unsafe { asm!("mov {v}, [{a}]", v = out(reg) v, a = in(reg) addr) };
    // Keep the load from being optimised away.
    unsafe { asm!("", in("rax") v, options(nostack)) };
}

/// Runs `child` in a forked child and expects it to die of `signal`.
fn expect_signal(what: &[u8], signal: i32, child: fn()) {
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            child();
            exit(0); // only reached if nothing trapped
        }
        Ok(pid) => {
            let mut status: i32 = 0;
            if syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0).is_err() {
                fail(b"wait4");
            }
            if status & 0x7f != signal {
                write_bytes(b"meltdown-poc: FAIL: ");
                write_bytes(what);
                write_bytes(b": ring 3 did not fault on a kernel address (it may have leaked)\n");
                let _ = syscall(SYS_TEST_EXIT, 1, 0, 0);
                exit(1);
            }
        }
        Err(_) => fail(b"fork"),
    }
}

fn read_kernel_image() {
    read_kernel(KERNEL_IMAGE_BASE);
}

fn read_kernel_heap() {
    read_kernel(KERNEL_HEAP_BASE);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"meltdown-poc: starting\n");

    // Part 1: ring 3 can't read kernel memory at all.
    expect_signal(b"read kernel image", SIGSEGV, read_kernel_image);
    expect_signal(b"read kernel heap", SIGSEGV, read_kernel_heap);
    write_bytes(b"meltdown-poc: part 1 OK (ring 3 faults on kernel addresses)\n");

    // Part 2: the kernel proves those addresses aren't in our page tables at all (or reports SKIP
    // when KPTI is off). This never returns -- the handler exits the test.
    write_bytes(b"meltdown-poc: asking the kernel to audit this process's user table\n");
    let _ = syscall(SYS_KPTI_PROBE, 0, 0, 0);

    fail(b"SYS_KPTI_PROBE returned");
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fail(b"panic");
}
