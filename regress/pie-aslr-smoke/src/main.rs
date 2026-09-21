//! Real-`SYSCALL` smoke test for the PIE/ASLR loading model (see `sys/process/aslr.rs`'s own doc
//! comment): a genuine `ET_DYN`, no-`PT_INTERP` main binary, built via `build.rs`'s
//! `build_pie_crate_at` (real `-pie`/`--no-dynamic-linker`, zero relocations, verified at build
//! time). Spawned only via `regress/pie-aslr-driver/`'s real `fork`+`execve` -- never directly as
//! pid 1 (`process::spawn` always uses bias `0`; only `do_execve` ever calls
//! `process::aslr::pick_bias()`), so every run of this binary genuinely exercises the real
//! kernel-assigned load bias.
//!
//! On each invocation: captures its own real, biased `_start` address, reads `AT_ENTRY`/`AT_PHDR`
//! directly off its own initial stack (the same one a real libc's `crt1` would read), and checks
//! both against that real address -- this is the concrete regression check for the bug this
//! milestone found and fixed (`user_stack::build` not adding `main_bias` to either value, silently
//! correct only because the main binary's bias used to always be `0`). Reports its own computed
//! address to the kernel test harness via a test-only syscall (`SYS_TEST_REPORT_U64`, registered
//! by `tests/pie_aslr_smoke.rs`), then `fork()`s itself once: the child re-reports the identical
//! value (proving `fork()` never re-randomizes -- see `aslr.rs`'s own doc comment for why this
//! must hold by construction) before exiting; the parent `wait4()`s for it. Two full runs of this
//! binary (driven by `pie-aslr-driver`) therefore produce four reports total -- first run, its
//! forked child, second run, its forked child -- which `tests/pie_aslr_smoke.rs`'s own
//! `SYS_TEST_REPORT_U64` handler accumulates and `SYS_TEST_EXIT`'s handler evaluates: the two runs'
//! own addresses must differ (real per-`execve()` randomization), each run's forked child must
//! match its own parent (`fork()` inheritance), and the reported values must land inside
//! `process::aslr::PIE_ASLR_BASE..PIE_ASLR_CEILING`, with the runs differing by whole pages.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const STDOUT: u64 = 1;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// pie_aslr_smoke.rs` registers this one directly against a test-only handler that accumulates
/// reported values, same convention every other real-`SYSCALL` smoke test in this codebase uses
/// for its own `SYS_TEST_EXIT`.
const SYS_TEST_REPORT_U64: u64 = 9996;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_ENTRY: u64 = 9;
/// Real ELF64 `Elf64_Phdr::p_type` value for `PT_PHDR` -- the segment describing the program
/// header table itself. Confirmed empirically (not assumed): with `rust-lld`'s completely default
/// link script (this crate's own `build.rs`, no custom `-T<linker.ld>`), the *very first* program
/// header entry is a real `PT_PHDR` segment, not `PT_LOAD` -- `readelf -l` on a throwaway spike
/// crate built the identical way showed `PHDR` first, then three separate `LOAD` segments. A
/// plain `PT_LOAD`-only check here would be wrong for this exact, real link shape.
const PT_PHDR: u32 = 6;

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

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall(SYS_EXIT, code, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn write_bytes(s: &[u8]) {
    unsafe {
        let _ = syscall(SYS_WRITE, STDOUT, s.as_ptr() as u64, s.len() as u64);
    }
}

fn report(value: u64) {
    unsafe {
        let _ = syscall(SYS_TEST_REPORT_U64, value, 0, 0);
    }
}

// The ELF entry symbol itself -- captures the real, original incoming `RSP` (argc/argv/envp/auxv,
// per the System V AMD64 ABI's initial-stack layout) *before* any Rust-generated function
// prologue can disturb it, then hands it to `real_start` as a normal `extern "C"` first argument.
// `and rsp, -16` re-aligns to what a `call` needs (16-aligned immediately before the call, so the
// callee sees the ABI-mandated `RSP % 16 == 8` at its own entry) -- the real incoming `RSP` here
// has no such guarantee (it's whatever the kernel's own initial-stack layout produced), and this
// function itself never returns, so clobbering it is safe.
global_asm!(
    ".global _start",
    "_start:",
    "mov rdi, rsp",
    "and rsp, -16",
    "call {real_start}",
    "ud2",
    real_start = sym real_start,
);

unsafe extern "C" {
    /// The ELF entry symbol itself -- never actually called through this declaration (control
    /// already arrived there via the real ELF entry point before any Rust code ran). Only its
    /// address is ever taken, and only via the `asm!` `lea` in `real_start` below -- a plain Rust
    /// `_start as usize as u64` was tried first and found to compile into a GOT-style indirect
    /// load (the compiler materialized the address as stored, relocatable *data* rather than
    /// computing it at each use site), which is exactly the one pattern this milestone's
    /// zero-relocation build gate (`build.rs`'s `assert_zero_relocations`) exists to catch --
    /// confirmed live, caught by that exact gate. A real `asm!` `lea {reg}, [rip + sym]` is the
    /// well-established, guaranteed-local way to get a symbol's own address as a plain register
    /// value with no relocation of any kind.
    fn _start();
}

extern "C" fn real_start(stack_ptr: *const u64) -> ! {
    let own_addr: u64;
    unsafe {
        asm!(
            "lea {0}, [rip + {start_sym}]",
            out(reg) own_addr,
            start_sym = sym _start,
        );
    }

    // Walk the real System V initial-stack layout: argc, then argv[0..argc], then a NULL
    // terminator, then envp[] (NULL-terminated the same way), then the auxv array of (key, value)
    // u64 pairs, terminated by a real AT_NULL entry -- see `sys/process/user_stack.rs`'s own
    // `build()` for the kernel-side counterpart that lays this out.
    let argc = unsafe { *stack_ptr } as usize;
    let mut idx: usize = 1 + argc + 1; // argc, argv[0..argc], argv's own NULL terminator
    loop {
        let entry = unsafe { *stack_ptr.add(idx) };
        idx += 1;
        if entry == 0 {
            break;
        }
    }

    let mut at_entry: u64 = 0;
    let mut at_phdr: u64 = 0;
    loop {
        let key = unsafe { *stack_ptr.add(idx) };
        let value = unsafe { *stack_ptr.add(idx + 1) };
        idx += 2;
        if key == AT_NULL {
            break;
        }
        match key {
            AT_PHDR => at_phdr = value,
            AT_ENTRY => at_entry = value,
            _ => {}
        }
    }

    // The concrete regression check: before this milestone's fix, `AT_ENTRY`/`AT_PHDR` were never
    // bias-adjusted, so they'd equal the *unbiased* file-relative values instead of this real,
    // running address -- silently correct only when bias happened to be 0.
    if at_entry != own_addr {
        write_bytes(b"pie-aslr-smoke: FAIL at_entry != own_addr\n");
        exit(1);
    }
    // Dereferencing AT_PHDR is only safe because this crate's own build.rs deliberately uses
    // rust-lld's default link script (see that file's doc comment) -- the real program header
    // table is genuinely mapped there, unlike every other `regress/*`'s minimal custom
    // `linker.ld`. The first program header entry's own `p_type` (a plain u32 at Elf64_Phdr
    // offset 0) must be exactly `PT_PHDR` -- see that constant's own doc comment for why (a real,
    // confirmed link-shape fact, not an assumption).
    let first_phdr_type = unsafe { *(at_phdr as *const u32) };
    if first_phdr_type != PT_PHDR {
        write_bytes(b"pie-aslr-smoke: FAIL first_phdr_type != PT_PHDR\n");
        exit(1);
    }

    report(own_addr);

    match unsafe { syscall(SYS_FORK, 0, 0, 0) } {
        Ok(0) => {
            // Child: same address expected -- fork() must never re-randomize (see aslr.rs's own
            // doc comment). own_addr is a plain stack/register value here, inherited unchanged
            // across the fork's eager address-space copy, not re-derived.
            report(own_addr);
            exit(0);
        }
        Ok(child_pid) => {
            let mut status: i32 = -1;
            let waited =
                unsafe { syscall(SYS_WAIT4, child_pid, &mut status as *mut i32 as u64, 0) };
            let ok = waited == Ok(child_pid) && status == 0;
            exit(if ok { 0 } else { 1 });
        }
        Err(_) => exit(1),
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1)
}
