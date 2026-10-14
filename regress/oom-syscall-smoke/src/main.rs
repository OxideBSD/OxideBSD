//! Real-`SYSCALL` smoke test for the out-of-memory killer (`OxideBSD-doc/COW.md` §6), spawned as
//! pid 1 by `tests/oom_syscall_smoke.rs` in 128 MB.
//!
//! 1. The biggest process dies, not the faulter: a hog maps and touches half of free memory and
//!    waits on a pipe; a writer, forked from a parent holding a region of 30%, writes all of its
//!    copy-on-write copy of it. The copies run out, the hog is killed (`SIGKILL`), and the writer
//!    finishes and exits 0. The parent's region is untouched.
//! 2. The faulter dies when it's the biggest: a child writes all of its copy of a region of 60% of
//!    free memory, which can't fit; it is killed, and pid 1 (never chosen) keeps its region.
//! 3. `procctl(2)`'s OOM adjustment: out-of-range values are `EINVAL`, a child inherits its
//!    parent's, `/proc/<pid>/oom_adj` shows it; and it steers the killer: a hog protected with
//!    `-1000` survives although it's the biggest, while a smaller sibling at `1000` is killed.
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
const SYS_MUNMAP: u64 = 101;
const SYS_PIPE: u64 = 105;
const SYS_PROCCTL: u64 = 585;
const P_PID: u64 = 1;
const PROC_OOM_ADJ_CTL: u64 = 1;
const PROC_OOM_ADJ_STATUS: u64 = 2;
const EINVAL: u64 = 22;
/// Registered by `tests/oom_syscall_smoke.rs` against a test-only handler.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const SIGKILL: i32 = 9;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANON: u64 = 0x20;
const PAGE: u64 = 4096;

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
    write_bytes(b"oom-syscall-smoke: FAIL: ");
    write_bytes(what);
    write_bytes(b"\n");
    test_exit(false);
}

/// An anonymous private mapping of `len` bytes (filled with zeroes by the kernel, so resident).
fn mmap_anon(len: u64) -> *mut u8 {
    let packed_prot = ((PROT_READ | PROT_WRITE) & 0xff) | ((MAP_PRIVATE | MAP_ANON) << 8);
    let packed = 0xffff_ffff; // fd -1, offset 0
    unsafe { syscall4(SYS_MMAP, 0, len, packed_prot, packed) }.unwrap_or_else(|_| fail(b"mmap")) as *mut u8
}

fn munmap(p: *mut u8, len: u64) {
    if syscall(SYS_MUNMAP, p as u64, len, 0).is_err() {
        fail(b"munmap");
    }
}

/// Writes `value` into the first byte of every page of `[p, p + len)`.
fn touch(p: *mut u8, len: u64, value: u8) {
    for off in (0..len).step_by(PAGE as usize) {
        unsafe { core::ptr::write_volatile(p.add(off as usize), value) };
    }
}

/// Whether every page of `[p, p + len)` starts with `value`.
fn holds(p: *mut u8, len: u64, value: u8) -> bool {
    (0..len).step_by(PAGE as usize).all(|off| unsafe { core::ptr::read_volatile(p.add(off as usize)) } == value)
}

fn pipe() -> (u64, u64) {
    let mut fds: [i32; 2] = [-1, -1];
    if syscall(SYS_PIPE, fds.as_mut_ptr() as u64, 0, 0).is_err() {
        fail(b"pipe");
    }
    (fds[0] as u64, fds[1] as u64)
}

fn wait_child(pid: u64) -> i32 {
    let mut status: i32 = 0;
    if syscall(SYS_WAIT4, pid, &mut status as *mut i32 as u64, 0).is_err() {
        fail(b"wait4");
    }
    status
}

/// `MemFree` from `/proc/meminfo`, in bytes.
fn mem_free() -> u64 {
    let path = b"/proc/meminfo";
    let fd = syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0)
        .unwrap_or_else(|_| fail(b"open /proc/meminfo"));
    let mut buf = [0u8; 1024];
    let n = syscall(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
        .unwrap_or_else(|_| fail(b"read /proc/meminfo")) as usize;
    let _ = syscall(SYS_CLOSE, fd, 0, 0);
    let text = &buf[..n];
    let key = b"MemFree:";
    let at = text
        .windows(key.len())
        .position(|w| w == key)
        .unwrap_or_else(|| fail(b"no MemFree in /proc/meminfo"));
    let mut kib = 0u64;
    for &c in &text[at + key.len()..] {
        match c {
            b'0'..=b'9' => kib = kib * 10 + (c - b'0') as u64,
            b' ' | b'\t' if kib == 0 => {}
            _ => break,
        }
    }
    kib * 1024
}

/// `percent`% of `total` bytes, in whole pages.
fn share(total: u64, percent: u64) -> u64 {
    total / 100 * percent / PAGE * PAGE
}

fn part1() {
    // Shares of what's free now: 30 + 50 + the writer's 30 don't fit.
    let free = mem_free();
    let region_len = share(free, 30);
    let region = mmap_anon(region_len);
    touch(region, region_len, 0x11);
    write_bytes(b"oom-syscall-smoke: part 1: region mapped\n");

    // The hog: half of what's free, touched, then it waits (blocked in a pipe read) to be killed.
    let hog_len = share(free, 50);
    let (ready_rd, ready_wr) = pipe();
    let (wait_rd, wait_wr) = pipe();
    let hog = match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            let _ = syscall(SYS_CLOSE, wait_wr, 0, 0);
            let mine = mmap_anon(hog_len);
            touch(mine, hog_len, 0x22);
            let _ = syscall(SYS_WRITE, ready_wr, b"r".as_ptr() as u64, 1);
            let mut byte = 0u8;
            let _ = syscall(SYS_READ, wait_rd, &mut byte as *mut u8 as u64, 1);
            exit(3);
        }
        Ok(pid) => pid,
        Err(_) => fail(b"fork the hog"),
    };
    let mut byte = 0u8;
    if syscall(SYS_READ, ready_rd, &mut byte as *mut u8 as u64, 1) != Ok(1) {
        fail(b"the hog never got its memory");
    }
    write_bytes(b"oom-syscall-smoke: part 1: the hog holds its memory\n");

    // The writer: its copy of the region doesn't fit beside the hog.
    let writer = match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            touch(region, region_len, 0x33);
            exit(if holds(region, region_len, 0x33) { 0 } else { 1 });
        }
        Ok(pid) => pid,
        Err(_) => fail(b"fork the writer"),
    };
    match wait_child(writer) {
        0 => {}
        s if s & 0x7f == SIGKILL => fail(b"the writer was killed, not the bigger hog"),
        _ => fail(b"the writer failed"),
    }
    // A hog still alive (nothing ran out) reads end of file and exits 3.
    let _ = syscall(SYS_CLOSE, wait_wr, 0, 0);
    let status = wait_child(hog);
    if status == 3 << 8 {
        fail(b"the writer never ran out of memory: the hog wasn't killed");
    }
    if status & 0x7f != SIGKILL {
        fail(b"the hog wasn't killed with SIGKILL");
    }
    if !holds(region, region_len, 0x11) {
        fail(b"the writer's copy reached the parent");
    }
    munmap(region, region_len);
    write_bytes(b"oom-syscall-smoke: part 1 OK (the biggest process was killed, the writer finished)\n");
}

fn part2() {
    let region_len = share(mem_free(), 60);
    let region = mmap_anon(region_len);
    touch(region, region_len, 0x44);
    let child = match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            touch(region, region_len, 0x55);
            exit(0);
        }
        Ok(pid) => pid,
        Err(_) => fail(b"fork"),
    };
    let status = wait_child(child);
    if status & 0x7f != SIGKILL {
        fail(b"the child that couldn't fit its copy wasn't killed with SIGKILL");
    }
    if !holds(region, region_len, 0x44) {
        fail(b"pid 1's region changed");
    }
    munmap(region, region_len);
    write_bytes(b"oom-syscall-smoke: part 2 OK (the faulter, the biggest, was killed; pid 1 never)\n");
}

fn set_adj(pid: u64, adj: i32) -> Result<u64, u64> {
    unsafe { syscall4(SYS_PROCCTL, P_PID, pid, PROC_OOM_ADJ_CTL, &adj as *const i32 as u64) }
}

fn get_adj(pid: u64) -> i32 {
    let mut adj: i32 = 12345;
    if unsafe { syscall4(SYS_PROCCTL, P_PID, pid, PROC_OOM_ADJ_STATUS, &mut adj as *mut i32 as u64) }.is_err() {
        fail(b"procctl PROC_OOM_ADJ_STATUS");
    }
    adj
}

/// `/proc/<pid>/oom_adj`'s contents.
fn proc_oom_adj(pid: u64, buf: &mut [u8; 16]) -> usize {
    let mut path = *b"/proc/0000000000/oom_adj";
    let mut digits = [0u8; 10];
    let mut n = pid;
    let mut len = 0;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut at = 6;
    for i in (0..len).rev() {
        path[at] = digits[i];
        at += 1;
    }
    let tail = b"/oom_adj";
    path[at..at + tail.len()].copy_from_slice(tail);
    let path_len = at + tail.len();
    let fd = syscall(SYS_OPEN, path.as_ptr() as u64, path_len as u64, 0).unwrap_or_else(|_| fail(b"open /proc/<pid>/oom_adj"));
    let n = syscall(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64).unwrap_or_else(|_| fail(b"read /proc/<pid>/oom_adj"));
    let _ = syscall(SYS_CLOSE, fd, 0, 0);
    n as usize
}

fn part3() {
    if get_adj(0) != 0 {
        fail(b"pid 1's OOM adjustment isn't 0 at first");
    }
    if set_adj(0, 1001) != Err(EINVAL) || set_adj(0, -1001) != Err(EINVAL) {
        fail(b"an out-of-range OOM adjustment wasn't EINVAL");
    }
    // Inherited across fork.
    if set_adj(0, 5).is_err() {
        fail(b"procctl PROC_OOM_ADJ_CTL on itself");
    }
    match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => exit(if get_adj(0) == 5 { 0 } else { 1 }),
        Ok(pid) => {
            if wait_child(pid) != 0 {
                fail(b"a child didn't inherit its parent's OOM adjustment");
            }
        }
        Err(_) => fail(b"fork"),
    }
    if set_adj(0, 0).is_err() {
        fail(b"procctl back to 0");
    }

    // 25% shared region, a protected hog of 40%, a sibling at 1000 holding 25%, and a writer
    // copying the region's 25%: 115%. Killing the sibling makes room.
    let free = mem_free();
    let region_len = share(free, 25);
    let region = mmap_anon(region_len);
    touch(region, region_len, 0x66);
    let (ready_rd, ready_wr) = pipe();
    let (wait_rd, wait_wr) = pipe();
    let mut children = [0u64; 2];
    for (i, (len, value)) in [(share(free, 40), 0x77u8), (share(free, 25), 0x88u8)].into_iter().enumerate() {
        children[i] = match syscall(SYS_FORK, 0, 0, 0) {
            Ok(0) => {
                let _ = syscall(SYS_CLOSE, wait_wr, 0, 0);
                let mine = mmap_anon(len);
                touch(mine, len, value);
                let _ = syscall(SYS_WRITE, ready_wr, b"r".as_ptr() as u64, 1);
                let mut byte = 0u8;
                let _ = syscall(SYS_READ, wait_rd, &mut byte as *mut u8 as u64, 1);
                exit(if holds(mine, len, value) { 3 } else { 4 });
            }
            Ok(pid) => pid,
            Err(_) => fail(b"fork a holder"),
        };
        let mut byte = 0u8;
        if syscall(SYS_READ, ready_rd, &mut byte as *mut u8 as u64, 1) != Ok(1) {
            fail(b"a holder never got its memory");
        }
    }
    let [hog, sibling] = children;
    if set_adj(hog, -1000).is_err() || set_adj(sibling, 1000).is_err() {
        fail(b"procctl PROC_OOM_ADJ_CTL on another process");
    }
    let mut buf = [0u8; 16];
    let n = proc_oom_adj(hog, &mut buf);
    if &buf[..n] != b"-1000\n" {
        fail(b"/proc/<hog>/oom_adj doesn't read -1000");
    }
    let writer = match syscall(SYS_FORK, 0, 0, 0) {
        Ok(0) => {
            touch(region, region_len, 0x99);
            exit(if holds(region, region_len, 0x99) { 0 } else { 1 });
        }
        Ok(pid) => pid,
        Err(_) => fail(b"fork the writer"),
    };
    match wait_child(writer) {
        0 => {}
        s if s & 0x7f == SIGKILL => fail(b"the writer was killed, not the sibling at 1000"),
        _ => fail(b"the writer failed"),
    }
    let _ = syscall(SYS_CLOSE, wait_wr, 0, 0);
    match wait_child(hog) {
        s if s == 3 << 8 => {}
        s if s & 0x7f == SIGKILL => fail(b"the protected hog was killed"),
        _ => fail(b"the protected hog's memory changed"),
    }
    match wait_child(sibling) {
        s if s & 0x7f == SIGKILL => {}
        s if s == 3 << 8 => fail(b"the writer never ran out of memory: the sibling wasn't killed"),
        _ => fail(b"the sibling failed"),
    }
    if !holds(region, region_len, 0x66) {
        fail(b"the writer's copy reached the parent");
    }
    munmap(region, region_len);
    write_bytes(b"oom-syscall-smoke: part 3 OK (oom_adj: protected hog kept, sibling at 1000 killed)\n");
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"oom-syscall-smoke: starting\n");
    part1();
    part2();
    part3();
    write_bytes(b"oom-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    fail(b"panic");
}
