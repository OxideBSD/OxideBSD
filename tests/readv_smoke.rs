//! Smoke test for `SYS_READV = 153` (`sys/syscall.rs`'s `sys_readv`) -- added because musl's
//! entire stdio *read* path goes through `readv`, not plain `read`, whenever a `FILE*` has real
//! internal buffering (`external/mit/musl/src/stdio/__stdio_read.c`). Found live: BusyBox's `wget`
//! completed a real HTTPS download (the TLS/TCP fix chain all worked, real response bytes came
//! through) and then failed on the very next buffered read -- see CLAUDE.md's "Real networking"
//! known-gaps entry for the full trace.
//!
//! Uses a socketpair as the underlying fd (already-verified plumbing from `tests/
//! socketpair_smoke.rs`) rather than anything readv-specific, since `sys_readv` is just a thin
//! per-iovec loop over the same `sys_read` every other test already exercises.
//!
//! Covers: a single `readv()` call scattering one write's worth of data across two iovecs, and
//! real `readv` short-read semantics (a partially-filled iovec ends the call there, rather than
//! moving on to the next iovec expecting more to somehow still be available).
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::{oxidebsd_sys_readv, oxidebsd_sys_socketpair, oxidebsd_sys_write};

limine_entry_point!(main);

const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;

#[repr(C)]
struct IoVec {
    base: u64,
    len: u64,
}

fn main(boot_info: &'static BootInfo) -> ! {
    oxidebsd::init(boot_info);

    let mut fds: [i32; 2] = [-1, -1];
    let rc = oxidebsd_sys_socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr() as u64);
    assert_eq!(rc, 0, "socketpair() failed: {rc}");
    let (fd0, fd1) = (fds[0] as u64, fds[1] as u64);

    // --- A single write, scattered across two iovecs on the read side ---
    let msg = b"hello-readv-world";
    let n = oxidebsd_sys_write(fd0, msg.as_ptr() as u64, msg.len() as u64);
    assert_eq!(n, msg.len() as i64, "write() failed: {n}");

    let mut buf_a = [0u8; 5];
    let mut buf_b = [0u8; 32];
    let iov = [
        IoVec {
            base: buf_a.as_mut_ptr() as u64,
            len: buf_a.len() as u64,
        },
        IoVec {
            base: buf_b.as_mut_ptr() as u64,
            len: buf_b.len() as u64,
        },
    ];
    let n = oxidebsd_sys_readv(fd1, iov.as_ptr() as u64, 2);
    assert_eq!(
        n,
        msg.len() as i64,
        "readv() didn't return the full write's length: {n}"
    );
    assert_eq!(&buf_a, &msg[..5], "first iovec didn't get its share");
    assert_eq!(
        &buf_b[..msg.len() - 5],
        &msg[5..],
        "second iovec didn't get the remainder"
    );
    serial_println!("readv_smoke: single write scattered across two iovecs verified");

    // --- Short-read semantics: a partially-filled first iovec ends the call there ---
    let short_msg = b"ab";
    let n = oxidebsd_sys_write(fd0, short_msg.as_ptr() as u64, short_msg.len() as u64);
    assert_eq!(n, short_msg.len() as i64, "write() (2nd) failed: {n}");

    let mut buf_c = [0u8; 10]; // bigger than short_msg -- real readv should stop, not block
    let mut buf_d = [0u8; 10];
    let iov2 = [
        IoVec {
            base: buf_c.as_mut_ptr() as u64,
            len: buf_c.len() as u64,
        },
        IoVec {
            base: buf_d.as_mut_ptr() as u64,
            len: buf_d.len() as u64,
        },
    ];
    let n = oxidebsd_sys_readv(fd1, iov2.as_ptr() as u64, 2);
    assert_eq!(
        n,
        short_msg.len() as i64,
        "readv() should stop at the short first iovec: {n}"
    );
    assert_eq!(&buf_c[..2], short_msg, "first iovec content mismatch");
    serial_println!(
        "readv_smoke: short-read-stops-at-first-iovec semantics verified -- SYS_READV verified end to end"
    );

    exit_qemu(QemuExitCode::Success);
    oxidebsd::hlt_loop();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
