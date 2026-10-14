//! Real-`SYSCALL` smoke test for copy-on-write fork (`OxideBSD-doc/COW.md` §8), spawned as pid 1
//! by `tests/cow_syscall_smoke.rs`.
//!
//! 1. Writes after fork are private on both sides, for every kind of private page: `.data`, the
//!    stack, the `brk` heap, an anonymous `mmap` page, a page `mprotect`ed read-only before fork
//!    and writable after it, and a `PROT_NONE` page made accessible after fork. Each is written
//!    from ring 3 and by the kernel (`read(2)` into it), with the child going first and then the
//!    parent going first, so both the "copy" and the "last sharer, just make it writable" sides of
//!    the write fault run, in both rings.
//! 2. A page `mprotect`ed read-only after fork still faults (`SIGSEGV`) when written: the
//!    copy-on-write intent doesn't override the protection.
//! 3. Fork copies nothing up front: a child forked from a parent with a large touched heap finds
//!    `/proc/meminfo`'s `MemFree` barely moved.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_FORK: u64 = 2;
const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_WAIT4: u64 = 7;
const SYS_MMAP: u64 = 100;
const SYS_BRK: u64 = 102;
const SYS_PIPE: u64 = 105;
const SYS_MPROTECT: u64 = 492;
/// Registered by `tests/cow_syscall_smoke.rs` against a test-only handler.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGSEGV: i32 = 11;
const PROT_NONE: u64 = 0x0;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANON: u64 = 0x20;
const PAGE: u64 = 4096;

/// The value every test byte holds at fork.
const BEFORE: u8 = 0xa1;
/// Written by the child through `read(2)` (ring 0).
const CHILD_KERNEL: u8 = 0xb2;
/// Written by the parent from ring 3.
const PARENT_USER: u8 = 0xc3;
/// Written by the child from ring 3.
const CHILD_USER: u8 = 0xd4;
/// Written by the parent through `read(2)`.
const PARENT_KERNEL: u8 = 0xe5;

/// A page of `.data`.
#[repr(C, align(4096))]
struct DataPage([u8; PAGE as usize]);
static mut DATA: DataPage = DataPage([0; PAGE as usize]);

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
    write_bytes(b"cow-syscall-smoke: FAIL: ");
    write_bytes(what);
    write_bytes(b"\n");
    test_exit(false);
}

fn fail_two(a: &[u8], b: &[u8]) -> ! {
    write_bytes(b"cow-syscall-smoke: FAIL: ");
    write_bytes(a);
    write_bytes(b);
    write_bytes(b"\n");
    test_exit(false);
}

fn mmap_anon(len: u64, prot: u64) -> u64 {
    let packed_prot = (prot & 0xff) | ((MAP_PRIVATE | MAP_ANON) << 8);
    let packed = 0xffff_ffff; // fd -1, offset 0
    unsafe { syscall4(SYS_MMAP, 0, len, packed_prot, packed) }.unwrap_or_else(|_| fail(b"mmap"))
}

fn mprotect(addr: u64, len: u64, prot: u64) {
    if syscall(SYS_MPROTECT, addr, len, prot).is_err() {
        fail(b"mprotect");
    }
}

fn pipe() -> (u64, u64) {
    let mut fds: [i32; 2] = [-1, -1];
    if syscall(SYS_PIPE, fds.as_mut_ptr() as u64, 0, 0).is_err() {
        fail(b"pipe");
    }
    (fds[0] as u64, fds[1] as u64)
}

fn close(fd: u64) {
    let _ = syscall(SYS_CLOSE, fd, 0, 0);
}

/// Sends one byte down a pipe.
fn send(fd: u64, byte: u8) {
    if syscall(SYS_WRITE, fd, &byte as *const u8 as u64, 1) != Ok(1) {
        fail(b"write to a pipe");
    }
}

/// Reads one byte from a pipe into `dst`: the kernel's copy routine writes it.
fn receive_into(fd: u64, dst: *mut u8) -> bool {
    syscall(SYS_READ, fd, dst as u64, 1) == Ok(1)
}

/// Waits for a pipe's byte, into a stack byte.
fn wait_for(fd: u64) -> bool {
    let mut byte = 0u8;
    receive_into(fd, &mut byte)
}

/// Writes `value` into `dst` through the kernel: down a pipe to ourselves, then `read(2)` into it.
fn kernel_write(dst: *mut u8, value: u8) -> bool {
    let (rd, wr) = pipe();
    send(wr, value);
    let ok = receive_into(rd, dst);
    close(rd);
    close(wr);
    ok
}

fn get(p: *mut u8, i: usize) -> u8 {
    unsafe { core::ptr::read_volatile(p.add(i)) }
}

fn set(p: *mut u8, i: usize, v: u8) {
    unsafe { core::ptr::write_volatile(p.add(i), v) }
}

fn wait_child(pid: u64) -> i32 {
    let mut status: i32 = 0;
    if syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0).is_err() {
        fail(b"wait4");
    }
    status
}

/// Sets a region's 4 test bytes to `BEFORE`.
fn fill(region: *mut u8) {
    for i in 0..4 {
        set(region, i, BEFORE);
    }
}

/// One region across one fork. `region` holds at least 4 bytes, all `BEFORE`. The child writes
/// byte 1 through the kernel and byte 2 from ring 3; the parent writes byte 0 from ring 3 and byte
/// 3 through the kernel. Each side must see only its own writes.
///
/// `child_first`: the child writes before the parent does (the child copies, the parent finds
/// itself the last sharer), else the parent writes first. `before_write` runs on each side before
/// its writes (an `mprotect` that makes the region writable after fork).
fn privacy(what: &[u8], region: *mut u8, child_first: bool, before_write: fn(*mut u8)) {
    let (p2c_rd, p2c_wr) = pipe();
    let (c2p_rd, c2p_wr) = pipe();
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            if !child_first && !wait_for(p2c_rd) {
                exit(10);
            }
            before_write(region);
            if !kernel_write(unsafe { region.add(1) }, CHILD_KERNEL) {
                exit(11);
            }
            set(region, 2, CHILD_USER);
            if child_first {
                send(c2p_wr, 1);
                if !wait_for(p2c_rd) {
                    exit(12);
                }
            }
            // The parent has written bytes 0 and 3 by now, either way.
            if get(region, 0) != BEFORE || get(region, 3) != BEFORE {
                exit(13);
            }
            if get(region, 1) != CHILD_KERNEL || get(region, 2) != CHILD_USER {
                exit(14);
            }
            exit(0);
        }
        Ok(pid) => {
            if child_first && !wait_for(c2p_rd) {
                fail_two(what, b": no word from the child");
            }
            before_write(region);
            set(region, 0, PARENT_USER);
            if !kernel_write(unsafe { region.add(3) }, PARENT_KERNEL) {
                fail_two(what, b": read(2) into the parent's copy-on-write page failed");
            }
            send(p2c_wr, 1);
            match wait_child(pid) {
                0 => {}
                s if s == 10 << 8 || s == 12 << 8 => fail_two(what, b": the child got no word from the parent"),
                s if s == 11 << 8 => fail_two(what, b": read(2) into the child's copy-on-write page failed"),
                s if s == 13 << 8 => fail_two(what, b": the parent's writes reached the child"),
                s if s == 14 << 8 => fail_two(what, b": the child's own writes didn't stick"),
                s if s & 0x7f == SIGSEGV => fail_two(what, b": the child died of SIGSEGV writing its page"),
                _ => fail_two(what, b": the child failed"),
            }
            if get(region, 1) != BEFORE || get(region, 2) != BEFORE {
                fail_two(what, b": the child's writes reached the parent");
            }
            if get(region, 0) != PARENT_USER || get(region, 3) != PARENT_KERNEL {
                fail_two(what, b": the parent's own writes didn't stick");
            }
        }
        Err(_) => fail(b"fork"),
    }
    close(p2c_rd);
    close(p2c_wr);
    close(c2p_rd);
    close(c2p_wr);
}

fn nothing(_: *mut u8) {}

fn make_writable(region: *mut u8) {
    mprotect(region as u64 & !(PAGE - 1), PAGE, PROT_READ | PROT_WRITE);
}

/// Every kind of private page, child first and parent first.
fn part1() {
    for child_first in [true, false] {
        let data = unsafe { (&raw mut DATA.0).cast::<u8>() };
        fill(data);
        privacy(b".data", data, child_first, nothing);

        let mut stack = [0u8; 64];
        fill(stack.as_mut_ptr());
        privacy(b"the stack", stack.as_mut_ptr(), child_first, nothing);

        let top = syscall(SYS_BRK, 0, 0, 0).unwrap_or_else(|_| fail(b"brk(0)"));
        if syscall(SYS_BRK, top + PAGE, 0, 0).is_err() {
            fail(b"brk grow");
        }
        fill(top as *mut u8);
        privacy(b"the brk heap", top as *mut u8, child_first, nothing);

        let anon = mmap_anon(PAGE, PROT_READ | PROT_WRITE) as *mut u8;
        fill(anon);
        privacy(b"an anonymous mmap page", anon, child_first, nothing);

        // Read-only at fork, made writable on both sides after it.
        let ro = mmap_anon(PAGE, PROT_READ | PROT_WRITE) as *mut u8;
        fill(ro);
        mprotect(ro as u64, PAGE, PROT_READ);
        privacy(b"a page mprotected read-only before fork", ro, child_first, make_writable);

        // PROT_NONE at fork, made accessible on both sides after it.
        let none = mmap_anon(PAGE, PROT_READ | PROT_WRITE) as *mut u8;
        fill(none);
        mprotect(none as u64, PAGE, PROT_NONE);
        privacy(b"a PROT_NONE page", none, child_first, make_writable);
    }
    // The stack frames `privacy` ran in, and this one's `stack`, were shared too and survived.
    write_bytes(b"cow-syscall-smoke: part 1 OK (private pages stay private after fork)\n");
}

/// A shared page made read-only after fork is read-only: writing it is `SIGSEGV`.
fn part2() {
    let page = mmap_anon(PAGE, PROT_READ | PROT_WRITE) as *mut u8;
    set(page, 0, BEFORE);
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            mprotect(page as u64, PAGE, PROT_READ);
            set(page, 0, CHILD_USER);
            exit(0);
        }
        Ok(pid) => {
            let status = wait_child(pid);
            if status & 0x7f != SIGSEGV {
                fail(b"writing a copy-on-write page mprotected read-only didn't SIGSEGV");
            }
        }
        Err(_) => fail(b"fork"),
    }
    if get(page, 0) != BEFORE {
        fail(b"the child's refused write reached the parent");
    }
    write_bytes(b"cow-syscall-smoke: part 2 OK (read-only after fork stays read-only)\n");
}

/// `MemFree` from `/proc/meminfo`, in KiB.
fn mem_free_kib() -> u64 {
    let path = b"/proc/meminfo";
    let fd = syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0)
        .unwrap_or_else(|_| fail(b"open /proc/meminfo"));
    let mut buf = [0u8; 1024];
    let n = syscall(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
        .unwrap_or_else(|_| fail(b"read /proc/meminfo")) as usize;
    close(fd);
    let text = &buf[..n];
    let key = b"MemFree:";
    let at = text
        .windows(key.len())
        .position(|w| w == key)
        .unwrap_or_else(|| fail(b"no MemFree in /proc/meminfo"));
    let mut value = 0u64;
    let mut seen = false;
    for &c in &text[at + key.len()..] {
        match c {
            b'0'..=b'9' => {
                value = value * 10 + (c - b'0') as u64;
                seen = true;
            }
            b' ' | b'\t' if !seen => {}
            _ => break,
        }
    }
    if !seen {
        fail(b"MemFree has no number");
    }
    value
}

/// Fork of a 16 MiB touched heap: the child finds less than 1 MiB gone (page tables and a few
/// stack pages), where an eager copy would take all 16.
fn part3() {
    const HEAP: u64 = 16 << 20;
    let heap = mmap_anon(HEAP, PROT_READ | PROT_WRITE) as *mut u8;
    for off in (0..HEAP).step_by(PAGE as usize) {
        set(heap, off as usize, 1);
    }
    let before = mem_free_kib();
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            let after = mem_free_kib();
            exit(if before.saturating_sub(after) < 1024 { 0 } else { 1 });
        }
        Ok(pid) => match wait_child(pid) {
            0 => {}
            s if s == 1 << 8 => fail(b"fork of a 16 MiB heap took 1 MiB or more"),
            _ => fail(b"the meminfo child failed"),
        },
        Err(_) => fail(b"fork"),
    }
    write_bytes(b"cow-syscall-smoke: part 3 OK (fork copies nothing up front)\n");
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"cow-syscall-smoke: starting\n");
    part1();
    part2();
    part3();
    write_bytes(b"cow-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fail(b"panic");
}
