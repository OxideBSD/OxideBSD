//! Real-`SYSCALL` smoke test for the trap entry path (`sys/cpu/trap.rs`), spawned as pid 1 by
//! `tests/trap_syscall_smoke.rs`.
//!
//! 1. Every exception ring 3 can raise kills it with the BSD signal for it, never the kernel:
//!    `ud2` is `SIGILL`, divide by zero is `SIGFPE`, `int3` is `SIGTRAP`, a privileged
//!    instruction, a non-canonical address and an unmapped page are `SIGSEGV`.
//! 2. Ring 3 can't reach a hardware interrupt's handler with `int n`: the gate refuses it and the
//!    resulting `#GP` is `SIGSEGV`.
//! 3. Every general-purpose register survives hundreds of timer interrupts landing on ring 3.
//! 4. `sigreturn` can't hand ring 3 privileged RFLAGS: IOPL and NT come back clear and IF set,
//!    whatever the handler wrote into its ucontext. A resume address outside the user range (from
//!    the ucontext, or as the handler itself) kills only the process, with `SIGSEGV`.
//! 5. An ELF whose entry point isn't a user address fails `execve` with `ENOEXEC`.
//! 6. The process starts with every general-purpose register zero (checked by `_start` before
//!    any Rust runs): nothing the kernel had in them leaks into ring 3.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, Ordering};
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_GETPID: u64 = 20;
const SYS_EXECVE: u64 = 59;
const SYS_SIGACTION: u64 = 117;
const SYS_SIGRETURN: u64 = 119;
const SYS_CHMOD: u64 = 165;
const SYS_TKILL: u64 = 200;
const SYS_CLOCK_GETTIME: u64 = 138;
/// Registered by `tests/trap_syscall_smoke.rs` against a test-only handler.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const CLOCK_MONOTONIC: u64 = 1;
const SIGILL: i32 = 4;
const SIGTRAP: i32 = 5;
const SIGFPE: i32 = 8;
const SIGUSR1: u64 = 10;
const SIGSEGV: i32 = 11;
const SA_SIGINFO: u64 = 0x4;
const O_CREAT: u64 = 0o100;
const O_WRONLY: u64 = 0o1;
const ENOEXEC: u64 = 8;

/// `gregs` indices (musl's `bits/signal.h`).
const REG_RIP: usize = 16;
const REG_EFL: usize = 17;
const RFLAGS_IF: u64 = 0x200;
const RFLAGS_IOPL: u64 = 0x3000;
const RFLAGS_NT: u64 = 0x4000;
/// The lowest non-canonical address.
const NON_CANONICAL: u64 = 0x8000_0000_0000_0000;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    syscall4(number, arg0, arg1, arg2, 0)
}

fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Result<u64, u64> {
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

fn write_dec(mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if v == 0 {
        write_bytes(b"0");
        return;
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    write_bytes(&buf[i..]);
}

/// Times a tight `getpid` loop and prints nanoseconds per call -- the KPTI entry/exit cost shows
/// up here as the difference between a `pti=on` and a `pti=off` run of this same test.
fn time_getpid() {
    const N: u64 = 2_000_000;
    let start = monotonic_ms();
    let mut i = 0u64;
    while i < N {
        let _ = syscall(SYS_GETPID, 0, 0, 0);
        i += 1;
    }
    let ms = (monotonic_ms() - start) as u64;
    let ns_per = ms * 1_000_000 / N;
    write_bytes(b"trap-syscall-smoke: getpid x");
    write_dec(N);
    write_bytes(b" took ");
    write_dec(ms);
    write_bytes(b" ms (");
    write_dec(ns_per);
    write_bytes(b" ns/call)\n");
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
    fn sigreturn_trampoline();
}

// What a handler's `ret` lands on: musl's `__restore_rt`, which this crate doesn't link.
global_asm!(
    ".pushsection .text.sigreturn_trampoline, \"ax\"",
    ".global sigreturn_trampoline",
    "sigreturn_trampoline:",
    "mov rax, {sigreturn}",
    "syscall",
    ".popsection",
    sigreturn = const SYS_SIGRETURN,
);

/// `sys/process/signals.rs`'s `RawSigAction`.
#[repr(C)]
struct RawSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// `sys/syscall/mod.rs`'s `RawUcontext`, up to the general registers, all a handler here touches.
#[repr(C)]
struct UcontextHead {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: [u64; 3],
    gregs: [u64; 23],
}

fn sigaction(signal: u64, handler: u64) {
    let act = RawSigAction {
        handler,
        flags: SA_SIGINFO,
        restorer: sigreturn_trampoline as u64,
        mask: 0,
    };
    if syscall4(SYS_SIGACTION, signal, &act as *const RawSigAction as u64, 0, 8).is_err() {
        fail(b"sigaction");
    }
}

/// Sends `SIGUSR1` to the calling process; its handler runs before this returns.
fn raise_usr1() {
    let Ok(pid) = syscall(SYS_GETPID, 0, 0, 0) else { fail(b"getpid") };
    let _ = syscall(SYS_TKILL, pid, SIGUSR1, 0);
}

fn rflags() -> u64 {
    let flags: u64;
    unsafe { asm!("pushfq", "pop {}", out(reg) flags) };
    flags
}

static ASK_FOR_PRIVILEGE_RAN: AtomicBool = AtomicBool::new(false);

/// Asks `sigreturn` for IOPL 3, NT and interrupts off.
extern "C" fn ask_for_privilege(_signal: i64, _info: u64, uc: *mut UcontextHead) {
    unsafe {
        let gregs = &mut (*uc).gregs;
        gregs[REG_EFL] = (gregs[REG_EFL] | RFLAGS_IOPL | RFLAGS_NT) & !RFLAGS_IF;
    }
    ASK_FOR_PRIVILEGE_RAN.store(true, Ordering::SeqCst);
}

/// Asks `sigreturn` to resume at a non-canonical address.
extern "C" fn resume_non_canonical(_signal: i64, _info: u64, uc: *mut UcontextHead) {
    unsafe { (*uc).gregs[REG_RIP] = NON_CANONICAL };
}

fn sigreturn_to_non_canonical() {
    sigaction(SIGUSR1, resume_non_canonical as u64);
    raise_usr1();
}

fn handler_at_non_canonical() {
    sigaction(SIGUSR1, NON_CANONICAL);
    raise_usr1();
}

/// A minimal `ET_EXEC`: one `PT_LOAD` at 0x400000 covering the headers, `e_entry` = `entry`.
fn elf_with_entry(entry: u64) -> [u8; 120] {
    let mut elf = [0u8; 120];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // little-endian
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&entry.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    let ph = &mut elf[64..120];
    ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    ph[16..24].copy_from_slice(&0x40_0000u64.to_le_bytes()); // p_vaddr
    ph[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes()); // p_paddr
    ph[32..40].copy_from_slice(&120u64.to_le_bytes()); // p_filesz
    ph[40..48].copy_from_slice(&120u64.to_le_bytes()); // p_memsz
    ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
    elf
}

/// `SYS_EXECVE`'s argv/envp entry (`sys/process/mod.rs`'s `RawArgvEntry`).
#[repr(C)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

/// Writes an ELF with entry point `entry` to `path` and execs it; returns `execve`'s result.
fn exec_with_entry(path: &[u8], entry: u64) -> Result<u64, u64> {
    let elf = elf_with_entry(entry);
    let Ok(fd) = syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, O_CREAT | O_WRONLY) else {
        fail(b"open")
    };
    if syscall(SYS_WRITE, fd, elf.as_ptr() as u64, elf.len() as u64) != Ok(elf.len() as u64) {
        fail(b"write");
    }
    let _ = syscall(SYS_CLOSE, fd, 0, 0);
    if syscall(SYS_CHMOD, path.as_ptr() as u64, path.len() as u64, 0o755).is_err() {
        fail(b"chmod");
    }
    let argv = [RawArgvEntry { ptr: path.as_ptr() as u64, len: path.len() as u64 }, RawArgvEntry { ptr: 0, len: 0 }];
    let envp = [RawArgvEntry { ptr: 0, len: 0 }];
    syscall4(SYS_EXECVE, path.as_ptr() as u64, path.len() as u64, argv.as_ptr() as u64, envp.as_ptr() as u64)
}

// _start: ORs together every general-purpose register but RSP, as the kernel handed them over,
// into START_REGS, then calls `main`.
global_asm!(
    ".pushsection .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "or rax, rbx",
    "or rax, rcx",
    "or rax, rdx",
    "or rax, rsi",
    "or rax, rdi",
    "or rax, rbp",
    "or rax, r8",
    "or rax, r9",
    "or rax, r10",
    "or rax, r11",
    "or rax, r12",
    "or rax, r13",
    "or rax, r14",
    "or rax, r15",
    "mov [rip + START_REGS], rax",
    "call main",
    "ud2",
    ".popsection",
);

/// What `_start` found in the registers, ORed together.
#[unsafe(no_mangle)]
static mut START_REGS: u64 = u64::MAX;

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
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

    // Part 4: sigreturn's RFLAGS and RIP are vetted.
    sigaction(SIGUSR1, ask_for_privilege as u64);
    raise_usr1();
    let flags = rflags();
    if !ASK_FOR_PRIVILEGE_RAN.load(Ordering::SeqCst) {
        fail(b"the SIGUSR1 handler didn't run");
    }
    if flags & (RFLAGS_IOPL | RFLAGS_NT) != 0 || flags & RFLAGS_IF == 0 {
        write_bytes(b"trap-syscall-smoke: FAIL: sigreturn let RFLAGS through: ");
        write_hex(flags);
        write_bytes(b"\n");
        test_exit(false);
    }
    expect_signal(b"sigreturn to a non-canonical RIP", SIGSEGV, sigreturn_to_non_canonical);
    expect_signal(b"a non-canonical handler", SIGSEGV, handler_at_non_canonical);
    write_bytes(b"trap-syscall-smoke: part 4 OK (sigreturn can't raise privilege or resume anywhere)\n");

    // Part 5: an entry point outside the user range is refused before anything jumps to it.
    for (path, entry) in [
        (&b"/trap-entry-non-canonical"[..], NON_CANONICAL),
        (&b"/trap-entry-kernel"[..], 0xffff_8000_0000_0000),
        (&b"/trap-entry-zero-page"[..], 0x10),
    ] {
        if exec_with_entry(path, entry) != Err(ENOEXEC) {
            write_bytes(b"trap-syscall-smoke: FAIL: execve didn't refuse ");
            write_bytes(path);
            write_bytes(b" with ENOEXEC\n");
            test_exit(false);
        }
    }
    write_bytes(b"trap-syscall-smoke: part 5 OK (bad entry points are ENOEXEC)\n");

    // Part 6: registers at process start.
    // SAFETY: written once by `_start`, before anything else ran.
    let start_regs = unsafe { core::ptr::read_volatile(&raw const START_REGS) };
    if start_regs != 0 {
        write_bytes(b"trap-syscall-smoke: FAIL: the process started with nonzero registers (ORed: ");
        write_hex(start_regs);
        write_bytes(b")\n");
        test_exit(false);
    }
    write_bytes(b"trap-syscall-smoke: part 6 OK (registers start at zero)\n");

    time_getpid();

    write_bytes(b"trap-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fail(b"panic");
}
