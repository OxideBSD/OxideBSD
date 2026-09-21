//! Real-`SYSCALL` smoke test for `sys/modules/oxfs`'s write-through disk persistence (see that
//! crate's own "Real disk persistence" section and `src/ata.rs`). Deliberately a real spawned ELF
//! driven through genuine `SYSCALL`/`SYSRETQ`, not a plain Rust function call from a test's own
//! `main()` -- the whole reason this pass exists is that `write_block`/`write_inode`/
//! `set_block_used` now call into `src/ata.rs`'s PIO driver on every mutation, and that driver's
//! bounded busy-wait must actually work with `RFLAGS::INTERRUPT_FLAG` masked (real syscall
//! context) -- see CLAUDE.md's own `hlt()`-in-syscall/`ticks()`-frozen-during-syscall history for
//! why this codebase specifically distrusts a plain-Rust-function test for exactly this class of
//! bug.
//!
//! `tests/oxfs_persistence_syscall_smoke.rs` boots with `src/ata.rs`'s data disk attached (a
//! freshly zeroed `target/oxfs_test_disk.img`, so `oxfs`'s `module_init` takes the format-then-
//! flush path -- see that function's own doc comment), then spawns this binary as pid 1. This
//! doesn't (and can't, within one QEMU boot) prove persistence survives an actual reboot -- that's
//! inherently two separate `cargo run` invocations, handed to the user as a manual verification
//! step instead (see the implementation plan's own Verification section). What this *does* prove:
//! a real create+write+close, each step going through the real write-through path with interrupts
//! masked, completes without hanging or corrupting the in-memory read-back.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;
const SYS_READ: u64 = 3;
/// Not a real syscall number anything else in this codebase registers -- `tests/
/// oxfs_persistence_syscall_smoke.rs` registers this one directly against a test-only handler,
/// same convention every other real-`SYSCALL` smoke test in this codebase uses.
const SYS_TEST_EXIT: u64 = 9999;

const STDOUT: u64 = 1;
const O_CREAT: u64 = 0o100;
/// Real POSIX `open(2)` access-mode bit -- needed explicitly now that `sys/modules/oxfs`'s own
/// `oxfs_open` enforces the caller's real requested access mode even on a brand-new `O_CREAT`
/// file (`OpenFile::Write::readonly`, see that field's own doc comment) rather than always
/// granting write access regardless of what was actually asked for.
const O_WRONLY: u64 = 0o1;

const CONTENT: &[u8] = b"real disk persistence, write-through, verified live\n";

// `r10` is real OxideBSD `open(O_CREAT)`'s own 4th argument (the real requested creation mode) as
// of the fix threading mode through the syscall ABI (see sys/modules/oxfs's `oxfs_open` doc comment) --
// `SYSCALL` doesn't clear it, so it must be explicitly zeroed here even though this crate never
// reads it back, or this fd's `O_CREAT | O_WRONLY` open below would create `/persisttest` with
// whatever garbage happened to be sitting in `r10`.
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_bytes(b"oxfs-persistence-syscall-smoke: starting\n");

    let path = b"/persisttest";

    // Create + write + close -- each of these goes through oxfs's real write-through path
    // (write_inode/write_block/set_block_used -> oxidebsd_block_write) with interrupts masked,
    // the exact scenario this test exists to exercise. A hang here (the class of bug this test is
    // for) means the whole QEMU instance times out rather than reporting FAIL cleanly -- see this
    // file's own module doc comment.
    let fd = unsafe {
        syscall(
            SYS_OPEN,
            path.as_ptr() as u64,
            path.len() as u64,
            O_CREAT | O_WRONLY,
        )
    };
    let Ok(fd) = fd else {
        write_bytes(b"oxfs-persistence-syscall-smoke: creating /persisttest failed\n");
        test_exit(false);
    };
    let written = unsafe { syscall(SYS_WRITE, fd, CONTENT.as_ptr() as u64, CONTENT.len() as u64) };
    if written != Ok(CONTENT.len() as u64) {
        write_bytes(b"oxfs-persistence-syscall-smoke: write /persisttest failed\n");
        test_exit(false);
    }
    if unsafe { syscall(SYS_CLOSE, fd, 0, 0) }.is_err() {
        write_bytes(b"oxfs-persistence-syscall-smoke: close /persisttest failed\n");
        test_exit(false);
    }
    write_bytes(
        b"oxfs-persistence-syscall-smoke: create+write+close through write-through path OK\n",
    );

    // Real read-back, through a fresh open -- ordinary functional correctness, on top of the
    // write-through path having already run cleanly above.
    let fd = unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0) };
    let Ok(fd) = fd else {
        write_bytes(b"oxfs-persistence-syscall-smoke: reopening /persisttest failed\n");
        test_exit(false);
    };
    let mut buf = [0u8; CONTENT.len()];
    let n = unsafe { syscall(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) };
    let _ = unsafe { syscall(SYS_CLOSE, fd, 0, 0) };
    if n != Ok(CONTENT.len() as u64) || buf != *CONTENT {
        write_bytes(b"oxfs-persistence-syscall-smoke: read-back content mismatch\n");
        test_exit(false);
    }

    write_bytes(b"oxfs-persistence-syscall-smoke: PASS\n");
    test_exit(true);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}
