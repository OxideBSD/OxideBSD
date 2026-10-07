//! Real-`SYSCALL` smoke test for user memory access (`OxideBSD-doc/USERMEM.md` §6), spawned as
//! pid 1 by `tests/usermem_syscall_smoke.rs`.
//!
//! 1. The direction flag: `uname` called with `DF` set must still copy forwards. `SYSCALL`'s
//!    `SFMASK` has to clear `DF`, or the kernel's own `memcpy` runs backwards over whatever lies
//!    below its destination; a canary below the buffer catches that.
//! 2. Bad pointers get `EFAULT` and the system keeps running: null, the kernel heap (and where it
//!    used to be), the kernel image, a range past the end of the user range, a non-canonical
//!    address, a buffer that runs from a mapped page onto an unmapped one, and a read-only page
//!    as an output buffer. Through `uname`, `pipe2`, and the `iovec` arrays of `readv`/`writev`.
//! 3. Good calls still work afterwards: `uname`, `writev`, and `readv` through a pipe, one write
//!    scattered across two `iovec`s, and a short read that stops at the first partly filled one
//!    (from the retired in-kernel `tests/readv_smoke.rs`).
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_MMAP: u64 = 100;
const SYS_MUNMAP: u64 = 101;
const SYS_WRITEV: u64 = 104;
const SYS_UNAME: u64 = 137;
const SYS_READV: u64 = 153;
const SYS_PIPE2: u64 = 293;
/// Registered by `tests/usermem_syscall_smoke.rs` against a test-only handler.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const EFAULT: u64 = 14;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANON: u64 = 0x20;
const PAGE: u64 = 4096;

/// musl's `struct utsname`: six 65-byte fields.
const UTSNAME_SIZE: usize = 6 * 65;

#[repr(C, align(4096))]
struct Area([u8; 2 * PAGE as usize]);
static mut AREA: Area = Area([0; 2 * PAGE as usize]);

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

fn fail(what: &[u8]) -> ! {
    write_bytes(b"usermem-syscall-smoke: FAIL: ");
    write_bytes(what);
    write_bytes(b"\n");
    test_exit(false);
}

fn mmap_anon(len: u64, prot: u64) -> u64 {
    let packed_prot = (prot & 0xff) | ((MAP_PRIVATE | MAP_ANON) << 8);
    let packed = 0xffff_ffff; // fd -1, offset 0
    match unsafe { syscall4(SYS_MMAP, 0, len, packed_prot, packed) } {
        Ok(addr) => addr,
        Err(_) => fail(b"mmap"),
    }
}

/// Expects `EFAULT` from `number(arg0, arg1, arg2)`.
fn expect_efault(what: &[u8], number: u64, arg0: u64, arg1: u64, arg2: u64) {
    match syscall(number, arg0, arg1, arg2) {
        Err(EFAULT) => {}
        Err(_) => fail_two(what, b": wrong errno, expected EFAULT"),
        Ok(_) => fail_two(what, b": succeeded, expected EFAULT"),
    }
}

fn fail_two(a: &[u8], b: &[u8]) -> ! {
    write_bytes(b"usermem-syscall-smoke: FAIL: ");
    write_bytes(a);
    write_bytes(b);
    write_bytes(b"\n");
    test_exit(false);
}

#[repr(C)]
struct IoVec {
    base: u64,
    len: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"usermem-syscall-smoke: starting\n");
    let area = (&raw mut AREA) as u64;

    // Part 1: uname with the direction flag set. The buffer starts on the second page; the last
    // 512 bytes of the first page are a canary.
    let canary = area + PAGE - 512;
    let buf = area + PAGE;
    unsafe { core::ptr::write_bytes(canary as *mut u8, 0xa5, 512) };
    let ret: u64;
    let failed: u8;
    unsafe {
        asm!(
            "std",
            "syscall",
            "setc {failed}",
            "cld",
            inlateout("rax") SYS_UNAME => ret,
            in("rdi") buf,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            failed = out(reg_byte) failed,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    let _ = ret;
    if failed != 0 {
        fail(b"uname with DF set failed");
    }
    let canary_bytes = unsafe { core::slice::from_raw_parts(canary as *const u8, 512) };
    if canary_bytes.iter().any(|&b| b != 0xa5) {
        fail(b"uname with DF set wrote below its buffer (kernel copied backwards)");
    }
    if unsafe { core::slice::from_raw_parts(buf as *const u8, 8) } != b"OxideBSD" {
        fail(b"uname with DF set returned the wrong sysname");
    }
    write_bytes(b"usermem-syscall-smoke: part 1 OK (DF set: kernel copies forwards)\n");

    // Part 2: bad pointers.
    let bad: [(&[u8], u64); 6] = [
        (b"null", 0),
        (b"kernel heap", 0xffff_c100_0000_0000),
        (b"old heap location", 0x4444_4444_0000),
        (b"kernel image", 0xffff_ffff_8000_0000),
        (b"past the user range", 0x7fff_ffff_ff00),
        (b"non-canonical", 0x8000_0000_0000),
    ];
    for &(what, addr) in bad.iter() {
        expect_efault(what, SYS_UNAME, addr, 0, 0);
        expect_efault(what, SYS_PIPE2, addr, 0, 0);
        expect_efault(what, SYS_READV, 0, addr, 1);
        expect_efault(what, SYS_WRITEV, STDOUT, addr, 1);
    }

    // A buffer whose first part is mapped: two pages, the second unmapped again.
    let two = mmap_anon(2 * PAGE, PROT_READ | PROT_WRITE);
    if syscall(SYS_MUNMAP, two + PAGE, PAGE, 0).is_err() {
        fail(b"munmap");
    }
    expect_efault(b"uname onto an unmapped page", SYS_UNAME, two + PAGE - 100, 0, 0);
    let iov_split = two + PAGE - 8; // half an iovec on the mapped page
    expect_efault(b"readv iovec onto an unmapped page", SYS_READV, 0, iov_split, 1);

    // A read-only page as an output buffer.
    let ro = mmap_anon(PAGE, PROT_READ);
    expect_efault(b"uname into a read-only page", SYS_UNAME, ro, 0, 0);
    expect_efault(b"pipe2 into a read-only page", SYS_PIPE2, ro, 0, 0);
    write_bytes(b"usermem-syscall-smoke: part 2 OK (bad pointers get EFAULT)\n");

    // Part 3: good calls still work.
    let good = [0u8; UTSNAME_SIZE];
    if syscall(SYS_UNAME, good.as_ptr() as u64, 0, 0).is_err() || &good[..8] != b"OxideBSD" {
        fail(b"a good uname after the bad ones");
    }
    let msg = b"usermem-syscall-smoke: writev through a good iovec\n";
    let iov = IoVec { base: msg.as_ptr() as u64, len: msg.len() as u64 };
    match syscall(SYS_WRITEV, STDOUT, &iov as *const IoVec as u64, 1) {
        Ok(n) if n == msg.len() as u64 => {}
        _ => fail(b"a good writev"),
    }

    let mut fds = [0i32; 2];
    if syscall(SYS_PIPE2, fds.as_mut_ptr() as u64, 0, 0).is_err() {
        fail(b"a good pipe2");
    }
    let (rfd, wfd) = (fds[0] as u64, fds[1] as u64);
    let data = b"hello, readv test";
    if syscall(SYS_WRITE, wfd, data.as_ptr() as u64, data.len() as u64) != Ok(data.len() as u64) {
        fail(b"write into the pipe");
    }
    let mut a = [0u8; 5];
    let mut b = [0u8; 32];
    let iovs = [
        IoVec { base: a.as_mut_ptr() as u64, len: a.len() as u64 },
        IoVec { base: b.as_mut_ptr() as u64, len: b.len() as u64 },
    ];
    if syscall(SYS_READV, rfd, iovs.as_ptr() as u64, 2) != Ok(data.len() as u64)
        || a[..] != data[..5]
        || b[..data.len() - 5] != data[5..]
    {
        fail(b"readv scattering one write across two iovecs");
    }
    let short = b"ab";
    if syscall(SYS_WRITE, wfd, short.as_ptr() as u64, 2) != Ok(2) {
        fail(b"second write into the pipe");
    }
    let mut c = [0u8; 10];
    let mut d = [0u8; 10];
    let iovs = [
        IoVec { base: c.as_mut_ptr() as u64, len: c.len() as u64 },
        IoVec { base: d.as_mut_ptr() as u64, len: d.len() as u64 },
    ];
    if syscall(SYS_READV, rfd, iovs.as_ptr() as u64, 2) != Ok(2) || &c[..2] != short {
        fail(b"readv stopping at a short first iovec");
    }
    write_bytes(b"usermem-syscall-smoke: part 3 OK (uname, writev, readv)\n");

    write_bytes(b"usermem-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
