//! Real-`SYSCALL` smoke test for the trap entry path (`sys/cpu/trap.rs`), spawned as pid 1 by
//! `tests/trap_syscall_smoke.rs`.
//!
//! 1. Every exception ring 3 can raise kills it with the BSD signal for it, never the kernel:
//!    `ud2` is `SIGILL`, divide by zero is `SIGFPE`, `int3` is `SIGTRAP`, a privileged
//!    instruction, a non-canonical address and an unmapped page are `SIGSEGV`.
//! 2. Ring 3 can't reach a hardware interrupt's handler with `int n`: the gate refuses it and the
//!    resulting `#GP` is `SIGSEGV`.
//! 3. Every general-purpose register survives hundreds of timer interrupts landing on ring 3.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_CLOCK_GETTIME: u64 = 138;
/// Registered by `tests/trap_syscall_smoke.rs` against a test-only handler.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const CLOCK_MONOTONIC: u64 = 1;
const SIGILL: i32 = 4;
const SIGTRAP: i32 = 5;
const SIGFPE: i32 = 8;
const SIGSEGV: i32 = 11;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

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

fn test_exit(pass: bool) -> ! {
    let _ = syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }, 0, 0);
    loop {
        spin_loop();
    }
}

fn exit(code: u64) -> ! {
    let _ = syscall(SYS_EXIT, code, 0, 0);
    loop {
        spin_loop();
    }
}

fn fail(what: &[u8]) -> ! {
    write_bytes(b"trap-syscall-smoke: FAIL: ");
    write_bytes(what);
    write_bytes(b"\n");
    test_exit(false);
}

fn monotonic_ms() -> i64 {
    let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
    if syscall(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC, &mut ts as *mut Timespec as u64, 0).is_err() {
        fail(b"clock_gettime");
    }
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

/// Runs `child` in a forked child and expects it to die of `signal`.
fn expect_signal(what: &[u8], signal: i32, child: fn()) {
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            child();
            // Only reached if nothing trapped.
            exit(0);
        }
        Ok(pid) => {
            let mut status: i32 = 0;
            if syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0).is_err() {
                fail(b"wait4");
            }
            if status & 0x7f != signal {
                write_bytes(b"trap-syscall-smoke: FAIL: ");
                write_bytes(what);
                write_bytes(b": wrong fate, wait status ");
                write_hex(status as u64);
                write_bytes(b"\n");
                test_exit(false);
            }
        }
        Err(_) => fail(b"fork"),
    }
}

fn write_hex(mut v: u64) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in (2..18).rev() {
        buf[i] = b"0123456789abcdef"[(v & 0xf) as usize];
        v >>= 4;
    }
    write_bytes(&buf);
}

fn undefined_opcode() {
    unsafe { asm!("ud2") };
}

fn divide_by_zero() {
    // Through registers, so the compiler can't see (and reject or fold) the zero divisor.
    unsafe {
        asm!(
            "xor edx, edx",
            "div {zero}",
            zero = in(reg) 0u64,
            inout("rax") 1u64 => _,
            out("rdx") _,
        )
    };
}

fn breakpoint() {
    unsafe { asm!("int3") };
}

fn privileged_instruction() {
    unsafe { asm!("hlt") };
}

fn non_canonical_address() {
    unsafe { asm!("mov rax, [{a}]", a = in(reg) 0x8000_0000_0000_0000u64, out("rax") _) };
}

fn unmapped_page() {
    unsafe { asm!("mov rax, [{a}]", a = in(reg) 0x10u64, out("rax") _) };
}

/// Vector 0x21, the PS/2 keyboard's: a hardware interrupt gate, DPL 0.
fn software_keyboard_interrupt() {
    unsafe { asm!("int 0x21") };
}

/// Vector 0x20, the timer's.
fn software_timer_interrupt() {
    unsafe { asm!("int 0x20") };
}

// check_regs(iterations) -> 0 if every register still held its pattern on every iteration, else 1.
// Every general-purpose register but RSP (and RCX, the loop counter) is set to a distinct 64-bit
// pattern and compared against it in a tight loop that interrupts keep landing in.
global_asm!(
    ".pushsection .text.check_regs, \"ax\"",
    ".global check_regs",
    "check_regs:",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rcx, rdi",
    "mov rax, [rip + REG_PATTERNS + 0*8]",
    "mov rbx, [rip + REG_PATTERNS + 1*8]",
    "mov rdx, [rip + REG_PATTERNS + 2*8]",
    "mov rsi, [rip + REG_PATTERNS + 3*8]",
    "mov rdi, [rip + REG_PATTERNS + 4*8]",
    "mov rbp, [rip + REG_PATTERNS + 5*8]",
    "mov r8,  [rip + REG_PATTERNS + 6*8]",
    "mov r9,  [rip + REG_PATTERNS + 7*8]",
    "mov r10, [rip + REG_PATTERNS + 8*8]",
    "mov r11, [rip + REG_PATTERNS + 9*8]",
    "mov r12, [rip + REG_PATTERNS + 10*8]",
    "mov r13, [rip + REG_PATTERNS + 11*8]",
    "mov r14, [rip + REG_PATTERNS + 12*8]",
    "mov r15, [rip + REG_PATTERNS + 13*8]",
    "2:",
    "cmp rax, [rip + REG_PATTERNS + 0*8]",
    "jne 3f",
    "cmp rbx, [rip + REG_PATTERNS + 1*8]",
    "jne 3f",
    "cmp rdx, [rip + REG_PATTERNS + 2*8]",
    "jne 3f",
    "cmp rsi, [rip + REG_PATTERNS + 3*8]",
    "jne 3f",
    "cmp rdi, [rip + REG_PATTERNS + 4*8]",
    "jne 3f",
    "cmp rbp, [rip + REG_PATTERNS + 5*8]",
    "jne 3f",
    "cmp r8,  [rip + REG_PATTERNS + 6*8]",
    "jne 3f",
    "cmp r9,  [rip + REG_PATTERNS + 7*8]",
    "jne 3f",
    "cmp r10, [rip + REG_PATTERNS + 8*8]",
    "jne 3f",
    "cmp r11, [rip + REG_PATTERNS + 9*8]",
    "jne 3f",
    "cmp r12, [rip + REG_PATTERNS + 10*8]",
    "jne 3f",
    "cmp r13, [rip + REG_PATTERNS + 11*8]",
    "jne 3f",
    "cmp r14, [rip + REG_PATTERNS + 12*8]",
    "jne 3f",
    "cmp r15, [rip + REG_PATTERNS + 13*8]",
    "jne 3f",
    "dec rcx",
    "jnz 2b",
    "xor eax, eax",
    "jmp 4f",
    "3:",
    "mov eax, 1",
    "4:",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "ret",
    ".popsection",
    ".pushsection .rodata.reg_patterns, \"a\"",
    ".balign 8",
    "REG_PATTERNS:",
    ".quad 0xa0a0a0a0a0a0a0a0, 0xb1b1b1b1b1b1b1b1, 0xd3d3d3d3d3d3d3d3, 0x5151515151515151",
    ".quad 0xd1d1d1d1d1d1d1d1, 0xbebebebebebebebe, 0x0808080808080808, 0x0909090909090909",
    ".quad 0x1010101010101010, 0x1111111111111111, 0x1212121212121212, 0x1313131313131313",
    ".quad 0x1414141414141414, 0x1515151515151515",
    ".popsection",
);

unsafe extern "C" {
    fn check_regs(iterations: u64) -> u64;
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"trap-syscall-smoke: starting\n");

    // Part 1: exceptions become signals.
    expect_signal(b"ud2", SIGILL, undefined_opcode);
    expect_signal(b"hlt", SIGSEGV, privileged_instruction);
    expect_signal(b"non-canonical load", SIGSEGV, non_canonical_address);
    expect_signal(b"unmapped load", SIGSEGV, unmapped_page);
    expect_signal(b"divide by zero", SIGFPE, divide_by_zero);
    expect_signal(b"int3", SIGTRAP, breakpoint);
    write_bytes(b"trap-syscall-smoke: part 1 OK (exceptions become signals)\n");

    // Part 2: hardware vectors are closed to `int n`.
    expect_signal(b"int 0x21", SIGSEGV, software_keyboard_interrupt);
    expect_signal(b"int 0x20", SIGSEGV, software_timer_interrupt);
    write_bytes(b"trap-syscall-smoke: part 2 OK (int n can't reach an IRQ handler)\n");

    // Part 3: registers survive interrupts. At least a second of ring-3 spinning: about 100
    // timer ticks, each one a full trap entry and exit around the loop.
    let start = monotonic_ms();
    while monotonic_ms() - start < 1000 {
        // SAFETY: plain System V function, defined above.
        if unsafe { check_regs(1 << 20) } != 0 {
            fail(b"a register changed under an interrupt");
        }
    }
    write_bytes(b"trap-syscall-smoke: part 3 OK (registers survive interrupts)\n");

    write_bytes(b"trap-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fail(b"panic");
}
