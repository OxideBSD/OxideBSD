//! `lsoxmod` -- lists OxideBSD's own dynamically loaded kernel modules (`sys/module.rs`'s
//! `native_abi`/`posix_compat`/`oxfs`/... loader, see CLAUDE.md's "Dynamic kernel modules"
//! section), not Linux kernel modules. A real standalone Rust userland ELF, deliberately outside
//! both BusyBox's and musl's context (same freestanding, raw-`SYSCALL`, no-libc category as
//! `regress/ring3-smoke/`) -- real BusyBox ships its own `lsmod` applet, but that one parses
//! Linux's own `/proc/modules` expecting Linux kernel modules, which don't exist on this kernel.
//! Seeded into oxfs at `/bin/lsoxmod` with `/bin/lsmod` as a real symlink alias (see
//! `sys/modules/oxfs/src/lib.rs`'s `module_init`), so typing the familiar name at the `hush` prompt
//! reaches this instead.
//!
//! Does no introspection of its own -- every field comes straight from a real read of
//! `/proc/modules`, which `sys/modules/oxfs` synthesizes from `sys/module.rs`'s own `LOADED_MODULES`
//! registry (`oxidebsd_proc_modules`). This binary's only job is formatting that real data into a
//! human-readable table, the same division of labor real `lsmod` has with the real Linux kernel.
#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const SYS_EXIT: u64 = 1;
const SYS_READ: u64 = 3;
const SYS_WRITE: u64 = 4;
const SYS_OPEN: u64 = 5;
const SYS_CLOSE: u64 = 6;

const STDOUT: u64 = 1;
const O_RDONLY: u64 = 0;

/// Real `/proc/modules`-line field count this program understands (`name size refcount deps
/// state address`, `sys/module.rs`'s `oxidebsd_proc_modules` own doc comment) -- a line with
/// fewer fields than this is malformed and skipped rather than risking an out-of-bounds field
/// index.
const EXPECTED_FIELDS: usize = 6;

// `r10` is real OxideBSD `open(O_CREAT)`'s own 4th argument (the real requested creation mode) as
// of the fix threading mode through the syscall ABI (see sys/modules/oxfs's `oxfs_open` doc comment) --
// `SYSCALL` doesn't clear it, so it must be explicitly zeroed here (this crate's own `SYS_OPEN`
// call below is `O_RDONLY`, never `O_CREAT`, so it's unused in practice, but a stray garbage value
// left in `r10` should never be able to influence a syscall this crate didn't intend to send one).
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

/// A fixed-size output line buffer with simple `push`/pad helpers -- no `alloc` in a freestanding
/// binary like this one, so every buffer here is stack-allocated and fixed-capacity.
struct LineBuf {
    data: [u8; 128],
    len: usize,
}

impl LineBuf {
    fn new() -> Self {
        LineBuf {
            data: [0; 128],
            len: 0,
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.data.len() - self.len);
        self.data[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    /// Pads with spaces until the buffer is at least `width` bytes long -- used to left-justify
    /// whatever was just pushed (real `lsmod`'s own "Module" column convention).
    fn pad_to(&mut self, width: usize) {
        while self.len < width && self.len < self.data.len() {
            self.data[self.len] = b' ';
            self.len += 1;
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Splits `line` on single spaces into up to `EXPECTED_FIELDS` fields, formats and writes one
/// output row. Silently skips a line with fewer fields than expected (malformed/truncated --
/// shouldn't happen against `oxidebsd_proc_modules`'s own real output, but this is untrusted
/// kernel-buffer content crossing a real read(), not a compile-time-known shape).
fn print_module_line(line: &[u8]) {
    let mut fields: [&[u8]; EXPECTED_FIELDS] = [&[]; EXPECTED_FIELDS];
    let mut count = 0;
    for field in line.split(|&b| b == b' ') {
        if count >= EXPECTED_FIELDS {
            break;
        }
        fields[count] = field;
        count += 1;
    }
    if count < EXPECTED_FIELDS {
        return;
    }

    let name = fields[0];
    let size = fields[1];
    let address = fields[5];

    let mut out = LineBuf::new();
    out.push_bytes(name);
    out.pad_to(24);
    // Right-justify the size within a 10-column field -- pad first, then push the digits.
    let size_col = 10usize;
    let pad = size_col.saturating_sub(size.len());
    for _ in 0..pad {
        out.push_bytes(b" ");
    }
    out.push_bytes(size);
    out.push_bytes(b"  ");
    out.push_bytes(address);
    out.push_bytes(b"\n");
    write_bytes(out.as_slice());
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let path = b"/proc/modules";
    let fd = match unsafe { syscall(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, O_RDONLY) }
    {
        Ok(fd) => fd,
        Err(_) => {
            write_bytes(b"lsoxmod: open /proc/modules failed\n");
            exit(1);
        }
    };

    let mut buf = [0u8; 4096];
    let n = unsafe { syscall(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) }
        .unwrap_or(0) as usize;
    unsafe {
        let _ = syscall(SYS_CLOSE, fd, 0, 0);
    }

    write_bytes(b"Module                      Size  Base\n");
    for line in buf[..n].split(|&b| b == b'\n') {
        if !line.is_empty() {
            print_module_line(line);
        }
    }

    exit(0);
}

fn exit(code: u64) -> ! {
    unsafe {
        let _ = syscall(SYS_EXIT, code, 0, 0);
    }
    loop {
        spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(1);
}
