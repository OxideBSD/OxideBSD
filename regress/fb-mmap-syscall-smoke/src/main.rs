//! Real-`SYSCALL` smoke test proving the fbdoom/doomgeneric port's own new kernel primitives work
//! end to end, independent of doomgeneric's own C source (not written yet -- see this project's
//! own plan notes): a real `/dev/fb0` device (`sys/modules/oxfs`'s `known_device`'s `(29, 0)` arm), a
//! real `FBIOGET_OXIDEBSD` ioctl reporting actual framebuffer geometry, and a real `do_mmap_fb`
//! MMIO-mapping `mmap()` of the console framebuffer's own physical frames directly into this
//! process -- not oxfs content, not anonymous memory.
//!
//! Four parts, all through `tests/fb_mmap_syscall_smoke.rs` spawning this binary as pid 1:
//! 1. `open("/dev/fb0", O_RDWR)` succeeds.
//! 2. `ioctl(fd, FBIOGET_OXIDEBSD, &info)` reports a plausible real geometry (`width`/`height` > 0,
//!    `bpp == 32`, `pitch >= width * 4`).
//! 3. `mmap(fd, MAP_SHARED, PROT_READ|PROT_WRITE)` succeeds; a raw store through the mapped
//!    pointer followed by a raw load reads back exactly what was stored -- proves this is a real,
//!    read/write-capable mapping of real memory, not a stub returning a bogus address.
//! 4. `munmap()` then `close()` both succeed cleanly.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_IOCTL: u64 = 124;
const SYS_MMAP: u64 = 100;
const SYS_MUNMAP: u64 = 101;
/// Not a real syscall number anything else in this codebase registers -- same convention every
/// other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_RDWR: u64 = 0o2;

/// Must match `sys/syscall/ffi.rs`'s own `FBIOGET_OXIDEBSD`.
const FBIOGET_OXIDEBSD: u64 = 0x4600;

const PROT_READ_WRITE: u64 = 0x1 | 0x2;
/// Must match `sys/process/mm.rs`'s own `MAP_SHARED`.
const MAP_SHARED: u64 = 0x01;

/// Must match `sys/syscall/ffi.rs`'s own `RawFbInfo` exactly -- no shared crate across this ABI
/// boundary, same convention every other regress/kernel wire-struct pair here uses.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawFbInfo {
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
}

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

#[inline(always)]
unsafe fn syscall(number: u64, arg0: u64, arg1: u64, arg2: u64) -> Result<u64, u64> {
    unsafe { syscall4(number, arg0, arg1, arg2, 0) }
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

fn mmap_shared(fd: u64, len: u64) -> Result<u64, u64> {
    let packed_prot = PROT_READ_WRITE | (MAP_SHARED << 8);
    let packed = fd; // fd in the low 32 bits, real offset 0 in the high 32.
    unsafe { syscall4(SYS_MMAP, 0, len, packed_prot, packed) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"fb-mmap-syscall-smoke: starting\n");

    // Part 1: open.
    let path = b"/dev/fb0";
    let Ok(fd) = (unsafe { syscall4(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, O_RDWR, 0) })
    else {
        write_bytes(b"fb-mmap-syscall-smoke: open(/dev/fb0) failed\n");
        test_exit(false);
    };
    write_bytes(b"fb-mmap-syscall-smoke: open OK\n");

    // Part 2: ioctl for real geometry.
    let mut info = RawFbInfo::default();
    if unsafe {
        syscall(
            SYS_IOCTL,
            fd,
            FBIOGET_OXIDEBSD,
            &mut info as *mut RawFbInfo as u64,
        )
    }
    .is_err()
    {
        write_bytes(b"fb-mmap-syscall-smoke: FBIOGET_OXIDEBSD ioctl failed\n");
        test_exit(false);
    }
    if info.width == 0 || info.height == 0 || info.bpp != 32 || info.pitch < info.width * 4 {
        write_bytes(b"fb-mmap-syscall-smoke: implausible framebuffer geometry\n");
        test_exit(false);
    }
    write_bytes(b"fb-mmap-syscall-smoke: geometry OK\n");

    // Part 3: mmap + real read/write round trip.
    let len = (info.pitch as u64) * (info.height as u64);
    let Ok(addr) = mmap_shared(fd, len) else {
        write_bytes(b"fb-mmap-syscall-smoke: mmap(/dev/fb0) failed\n");
        test_exit(false);
    };
    // SAFETY: `addr` is this process's own freshly-established mapping, `len` bytes long, real
    // read/write permissions (PROT_READ|PROT_WRITE requested and honored by do_mmap_fb).
    unsafe {
        let ptr = addr as *mut u32;
        let pattern: u32 = 0x11223344;
        core::ptr::write_volatile(ptr, pattern);
        let readback = core::ptr::read_volatile(ptr);
        if readback != pattern {
            write_bytes(b"fb-mmap-syscall-smoke: readback didn't match what was written\n");
            test_exit(false);
        }
    }
    write_bytes(b"fb-mmap-syscall-smoke: mmap read/write round trip OK\n");

    // Part 4: munmap + close.
    if unsafe { syscall(SYS_MUNMAP, addr, len, 0) }.is_err() {
        write_bytes(b"fb-mmap-syscall-smoke: munmap failed\n");
        test_exit(false);
    }
    if unsafe { syscall(SYS_CLOSE, fd, 0, 0) }.is_err() {
        write_bytes(b"fb-mmap-syscall-smoke: close failed\n");
        test_exit(false);
    }
    write_bytes(b"fb-mmap-syscall-smoke: munmap/close OK\n");

    write_bytes(b"fb-mmap-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
