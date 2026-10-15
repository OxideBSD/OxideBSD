//! Serial console input (OxideBSD-doc `TTY.md` §2.5): pid 1 announces `serial input: ready`, and
//! the runner types `tests/serial_input_smoke.serial` on COM1 (`scripts/qemu_common.sh`). The
//! bytes reach `ttyv0` through the COM1 interrupt and its line discipline: two lines read from
//! fd 0 must be `hello from COM1` and `abc` (typed `abx`, DEL, `c`, CR: the erase character and
//! CR-to-NL, as a serial terminal sends them).
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
/// Registered by `tests/serial_input_smoke.rs` against a test-only handler, as in every other
/// real-`SYSCALL` smoke test.
const SYS_TEST_EXIT: u64 = 9999;

const STDIN: u64 = 0;
const STDOUT: u64 = 1;

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

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            write_bytes(b"serial-input-syscall-smoke: FAIL: ");
            write_bytes($msg);
            write_bytes(b"\n");
            test_exit(false);
        }
    };
}

/// One line from the terminal: a canonical-mode read returns at most one.
fn read_line<'a>(buf: &'a mut [u8; 128]) -> &'a [u8] {
    match unsafe { syscall(SYS_READ, STDIN, buf.as_mut_ptr() as u64, buf.len() as u64) } {
        Ok(n) => &buf[..n as usize],
        Err(_) => &[],
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"serial-input-syscall-smoke: serial input: ready\n");

    let mut buf = [0u8; 128];
    let line = read_line(&mut buf);
    check!(line == b"hello from COM1\n", b"the first line typed on COM1 didn't arrive whole");
    write_bytes(b"serial-input-syscall-smoke: a line from COM1 OK\n");

    let line = read_line(&mut buf);
    check!(line == b"abc\n", b"DEL didn't erase, or CR didn't end the line as NL");
    write_bytes(b"serial-input-syscall-smoke: erase and CR OK\n");

    write_bytes(b"serial-input-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
