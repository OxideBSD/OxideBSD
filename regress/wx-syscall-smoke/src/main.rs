//! Real-`SYSCALL` smoke test for no-execute and W^X (`OxideBSD-doc/THREAT_MODEL.md` §3.3),
//! spawned as pid 1 by `tests/wx_syscall_smoke.rs`.
//!
//! 1. Data doesn't run: a `ret` written into an anonymous `mmap` page, onto the stack, into
//!    `.data` and onto the `brk` heap kills the process with `SIGSEGV` when called, and so does a
//!    write into the program's own code.
//! 2. Nothing is writable and executable at once: `mmap` and `mprotect` asking for
//!    `PROT_WRITE | PROT_EXEC` fail with `ENOTSUP`.
//! 3. Code can still be made the W^X way: written into a writable page, then `mprotect`ed to
//!    `PROT_READ | PROT_EXEC`, it runs; `mprotect`ed back to `PROT_READ`, it no longer does.
//! 4. A `PROT_NONE` page is copied by `fork` like any other page, not shared with the child.
//! 5. `mprotect` works outside the `mmap` window too: `.data` made read-only can't be written.
//! 6. A shared page whose owner doesn't allow writing stays read-only: `mprotect` of an
//!    `SHM_RDONLY` SysV attachment to `PROT_WRITE` fails with `EACCES`.
//! 7. The escape hatch: `/usr/tests/wx/wx-needed` (linked `-z wxneeded`) may map W|X only when run
//!    from a `wxallowed` mount; `wx-plain` (not marked) may not even there.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::{black_box, spin_loop};
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_WRITE: u64 = 4;
const SYS_WAIT4: u64 = 7;
const SYS_MMAP: u64 = 100;
const SYS_BRK: u64 = 102;
const SYS_MPROTECT: u64 = 492;
const SYS_SHMGET: u64 = 542;
const SYS_SHMAT: u64 = 543;
const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const SHM_RDONLY: u64 = 0o10000;
const EACCES: u64 = 13;
const SYS_EXECVE: u64 = 59;
const SYS_MKDIR: u64 = 136;
const SYS_NMOUNT: u64 = 584;
/// Registered by `tests/wx_syscall_smoke.rs` against a test-only handler.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGSEGV: i32 = 11;
const ENOTSUP: u64 = 95;
const PROT_NONE: u64 = 0x0;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANON: u64 = 0x20;
const PAGE: u64 = 4096;

/// `ret`.
const RET: u8 = 0xc3;
/// `mov eax, 42; ret`.
const RETURN_42: [u8; 6] = [0xb8, 42, 0, 0, 0, 0xc3];

/// A page of `.data`, filled with `ret`s.
#[repr(C, align(4096))]
struct DataPage([u8; PAGE as usize]);
static mut DATA: DataPage = DataPage([RET; PAGE as usize]);

#[inline(always)]
unsafe fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> Result<u64, u64> {
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

fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
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
    write_bytes(b"wx-syscall-smoke: FAIL: ");
    write_bytes(what);
    write_bytes(b"\n");
    test_exit(false);
}

fn fail_two(a: &[u8], b: &[u8]) -> ! {
    write_bytes(b"wx-syscall-smoke: FAIL: ");
    write_bytes(a);
    write_bytes(b);
    write_bytes(b"\n");
    test_exit(false);
}

fn mmap_anon(len: u64, prot: u64) -> Result<u64, u64> {
    let packed_prot = (prot & 0xff) | ((MAP_PRIVATE | MAP_ANON) << 8);
    let packed = 0xffff_ffff; // fd -1, offset 0
    unsafe { syscall4(SYS_MMAP, 0, len, packed_prot, packed) }
}

fn mprotect(addr: u64, len: u64, prot: u64) -> Result<u64, u64> {
    syscall(SYS_MPROTECT, addr, len, prot)
}

/// Calls the code at `addr`.
fn call(addr: u64) -> u32 {
    // SAFETY: the test's whole point: `addr` holds `ret` or `RETURN_42`, or calling it faults.
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(black_box(addr)) };
    f()
}

/// Runs `child` in a forked child and expects it to die of `SIGSEGV`.
fn expect_segv(what: &[u8], child: fn()) {
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            child();
            // Only reached if nothing faulted.
            exit(0);
        }
        Ok(pid) => {
            let mut status: i32 = 0;
            if syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0).is_err() {
                fail(b"wait4");
            }
            if status & 0x7f != SIGSEGV {
                fail_two(what, b": expected death by SIGSEGV");
            }
        }
        Err(_) => fail(b"fork"),
    }
}

fn exec_mmap_page() {
    let page = mmap_anon(PAGE, PROT_READ | PROT_WRITE).unwrap_or_else(|_| fail(b"mmap RW"));
    unsafe { *(page as *mut u8) = RET };
    call(page);
}

fn exec_stack() {
    let code = black_box([RET; 16]);
    call(code.as_ptr() as u64);
}

fn exec_data() {
    call((&raw const DATA) as u64);
}

fn exec_brk() {
    let top = syscall(SYS_BRK, 0, 0, 0).unwrap_or_else(|_| fail(b"brk(0)"));
    if syscall(SYS_BRK, top + PAGE, 0, 0).is_err() {
        fail(b"brk grow");
    }
    unsafe { *(top as *mut u8) = RET };
    call(top);
}

fn write_text() {
    unsafe { core::ptr::write_volatile(black_box(exec_stack as *const () as u64) as *mut u8, RET) };
}

fn exec_after_dropping_x() {
    let page = jit_page();
    if call(page) != 42 {
        exit(1);
    }
    if mprotect(page, PAGE, PROT_READ).is_err() {
        exit(1);
    }
    call(page);
}

fn write_readonly_data() {
    let data = (&raw mut DATA) as u64;
    if mprotect(data, PAGE, PROT_READ).is_err() {
        exit(1);
    }
    unsafe { core::ptr::write_volatile(data as *mut u8, 0) };
}

/// A page holding `RETURN_42`, written while writable, then made `PROT_READ | PROT_EXEC`.
fn jit_page() -> u64 {
    let page = mmap_anon(PAGE, PROT_READ | PROT_WRITE).unwrap_or_else(|_| fail(b"mmap RW for code"));
    unsafe { core::ptr::copy_nonoverlapping(RETURN_42.as_ptr(), page as *mut u8, RETURN_42.len()) };
    if mprotect(page, PAGE, PROT_READ | PROT_EXEC).is_err() {
        fail(b"mprotect RW -> RX");
    }
    page
}

/// `SYS_EXECVE`'s argv/envp entry (`sys/process/mod.rs`'s `RawArgvEntry`).
#[repr(C)]
#[derive(Clone, Copy)]
struct RawArgvEntry {
    ptr: u64,
    len: u64,
}

/// One `struct iovec`.
#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    base: u64,
    len: u64,
}

/// `nmount(2)` with name/value pairs (each NUL-terminated).
fn nmount(pairs: &[(&[u8], &[u8])]) -> Result<u64, u64> {
    let mut iov = [IoVec { base: 0, len: 0 }; 8];
    for (i, (name, value)) in pairs.iter().enumerate() {
        iov[2 * i] = IoVec { base: name.as_ptr() as u64, len: name.len() as u64 };
        iov[2 * i + 1] = IoVec { base: value.as_ptr() as u64, len: value.len() as u64 };
    }
    syscall(SYS_NMOUNT, iov.as_ptr() as u64, 2 * pairs.len() as u64, 0)
}

/// Runs `path` in a forked child and returns its exit status (`wait4`'s, decoded), or `None` if
/// it didn't exit normally.
fn run(path: &[u8]) -> Option<i32> {
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            let argv = [RawArgvEntry { ptr: path.as_ptr() as u64, len: path.len() as u64 }, RawArgvEntry { ptr: 0, len: 0 }];
            let envp = [RawArgvEntry { ptr: 0, len: 0 }];
            let _ = unsafe {
                syscall4(SYS_EXECVE, path.as_ptr() as u64, path.len() as u64, argv.as_ptr() as u64, envp.as_ptr() as u64)
            };
            exit(127);
        }
        Ok(pid) => {
            let mut status: i32 = 0;
            if syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0).is_err() {
                fail(b"wait4");
            }
            (status & 0x7f == 0).then_some((status >> 8) & 0xff)
        }
        Err(_) => fail(b"fork"),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"wx-syscall-smoke: starting\n");

    // Part 1: data doesn't run.
    expect_segv(b"calling an RW mmap page", exec_mmap_page);
    expect_segv(b"calling the stack", exec_stack);
    expect_segv(b"calling .data", exec_data);
    expect_segv(b"calling the brk heap", exec_brk);
    expect_segv(b"writing to .text", write_text);
    write_bytes(b"wx-syscall-smoke: part 1 OK (data pages are not executable)\n");

    // Part 2: no W|X.
    match mmap_anon(PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) {
        Err(ENOTSUP) => {}
        Err(_) => fail(b"mmap RWX: wrong errno, expected ENOTSUP"),
        Ok(_) => fail(b"mmap RWX succeeded"),
    }
    let page = mmap_anon(PAGE, PROT_READ | PROT_WRITE).unwrap_or_else(|_| fail(b"mmap RW"));
    match mprotect(page, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) {
        Err(ENOTSUP) => {}
        Err(_) => fail(b"mprotect RWX: wrong errno, expected ENOTSUP"),
        Ok(_) => fail(b"mprotect RWX succeeded"),
    }
    match mprotect((&raw const DATA) as u64, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC) {
        Err(ENOTSUP) => {}
        _ => fail(b"mprotect .data RWX: expected ENOTSUP"),
    }
    write_bytes(b"wx-syscall-smoke: part 2 OK (W|X refused with ENOTSUP)\n");

    // Part 3: W, then X.
    if call(jit_page()) != 42 {
        fail(b"code made RX after being written did not return 42");
    }
    expect_segv(b"calling code after mprotect dropped PROT_EXEC", exec_after_dropping_x);
    write_bytes(b"wx-syscall-smoke: part 3 OK (write, then mprotect to RX, runs)\n");

    // Part 4: a PROT_NONE page across fork.
    let page = mmap_anon(PAGE, PROT_READ | PROT_WRITE).unwrap_or_else(|_| fail(b"mmap RW"));
    unsafe { *(page as *mut u8) = 0x11 };
    if mprotect(page, PAGE, PROT_NONE).is_err() {
        fail(b"mprotect PROT_NONE");
    }
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            if mprotect(page, PAGE, PROT_READ | PROT_WRITE).is_err() {
                exit(1);
            }
            if unsafe { *(page as *const u8) } != 0x11 {
                exit(2);
            }
            unsafe { *(page as *mut u8) = 0x22 };
            exit(0);
        }
        Ok(pid) => {
            let mut status: i32 = 0;
            if syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0).is_err() {
                fail(b"wait4");
            }
            if status != 0 {
                fail(b"the child could not use its copy of the PROT_NONE page");
            }
        }
        Err(_) => fail(b"fork"),
    }
    if mprotect(page, PAGE, PROT_READ | PROT_WRITE).is_err() {
        fail(b"mprotect the PROT_NONE page back to RW");
    }
    if unsafe { *(page as *const u8) } != 0x11 {
        fail(b"a PROT_NONE page was shared with a forked child, not copied");
    }
    write_bytes(b"wx-syscall-smoke: part 4 OK (PROT_NONE pages are copied by fork)\n");

    // Part 5: mprotect outside the mmap window.
    expect_segv(b"writing .data after mprotect PROT_READ", write_readonly_data);
    write_bytes(b"wx-syscall-smoke: part 5 OK (mprotect works on .data)\n");

    // Part 6: a read-only shared attachment can't be made writable.
    let id = syscall(SYS_SHMGET, IPC_PRIVATE, PAGE, IPC_CREAT | 0o600).unwrap_or_else(|_| fail(b"shmget"));
    let ro = syscall(SYS_SHMAT, id, 0, SHM_RDONLY).unwrap_or_else(|_| fail(b"shmat SHM_RDONLY"));
    match mprotect(ro, PAGE, PROT_READ | PROT_WRITE) {
        Err(EACCES) => {}
        Err(_) => fail(b"mprotect an SHM_RDONLY attachment RW: wrong errno, expected EACCES"),
        Ok(_) => fail(b"mprotect made an SHM_RDONLY attachment writable"),
    }
    let rw = syscall(SYS_SHMAT, id, 0, 0).unwrap_or_else(|_| fail(b"shmat"));
    if mprotect(rw, PAGE, PROT_READ).is_err() || mprotect(rw, PAGE, PROT_READ | PROT_WRITE).is_err() {
        fail(b"mprotect a writable attachment R then RW again");
    }
    write_bytes(b"wx-syscall-smoke: part 6 OK (read-only shared pages stay read-only)\n");

    // Part 7: wxneeded + wxallowed. Exit status 0: W|X allowed; 1: ENOTSUP (regress/wx-needed).
    if run(b"/usr/tests/wx/wx-needed") != Some(1) {
        fail(b"wx-needed off a wxallowed mount: expected W|X refused (exit 1)");
    }
    let dir = b"/wxallowed";
    if syscall(SYS_MKDIR, dir.as_ptr() as u64, dir.len() as u64, 0o755).is_err() {
        fail(b"mkdir /wxallowed");
    }
    let mounted = nmount(&[
        (b"fstype\0", b"nullfs\0"),
        (b"fspath\0", b"/wxallowed\0"),
        (b"target\0", b"/usr/tests/wx\0"),
        (b"wxallowed\0", b""),
    ]);
    if mounted.is_err() {
        fail(b"nmount nullfs wxallowed");
    }
    match run(b"/wxallowed/wx-needed") {
        Some(0) => {}
        Some(1) => fail(b"wx-needed on a wxallowed mount: W|X refused"),
        _ => fail(b"wx-needed on a wxallowed mount: didn't run the W|X page"),
    }
    if run(b"/wxallowed/wx-plain") != Some(1) {
        fail(b"wx-plain (not wxneeded) on a wxallowed mount: expected W|X refused (exit 1)");
    }
    write_bytes(b"wx-syscall-smoke: part 7 OK (W|X only for wxneeded on a wxallowed mount)\n");

    write_bytes(b"wx-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fail(b"panic");
}
