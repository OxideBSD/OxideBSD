//! Minimal output helpers over `SYS_WRITE` -- no buffering, no formatting machinery (no
//! `core::fmt`: its trait-object vtables are exactly the address-as-data pattern the PIE zero-
//! relocation gate exists to catch, see `build.rs`'s `build_pie_crate_at`).

use crate::syscall::syscall3;

const SYS_WRITE: u64 = 4;

pub const STDIN: u64 = 0;
pub const STDOUT: u64 = 1;
pub const STDERR: u64 = 2;

/// Writes all of `buf` to `fd`, looping over short writes.
pub fn write_all(fd: u64, mut buf: &[u8]) -> Result<(), u64> {
    while !buf.is_empty() {
        let n = unsafe { syscall3(SYS_WRITE, fd, buf.as_ptr() as u64, buf.len() as u64) }? as usize;
        if n == 0 {
            return Err(5); // EIO -- a zero-length write making no progress
        }
        buf = &buf[n..];
    }
    Ok(())
}

pub fn print(s: &[u8]) {
    let _ = write_all(STDOUT, s);
}

pub fn eprint(s: &[u8]) {
    let _ = write_all(STDERR, s);
}

/// Formats `n` in decimal into the tail of `buf`, returning the used suffix.
pub fn fmt_u64(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

/// A human-readable message for the errno values this kernel actually returns (see `sys/modules/
/// oxfs`'s own `E*` constants -- note `ENOTEMPTY` is FreeBSD's `66` here, not musl's `39`, a known,
/// documented mismatch). An `if` chain, not a `match`/table: a table of `&[u8]` slices is a
/// static full of stored addresses, which under real PIE would need relocations.
pub fn errno_str(errno: u64) -> &'static [u8] {
    if errno == 1 {
        b"Operation not permitted"
    } else if errno == 2 {
        b"No such file or directory"
    } else if errno == 9 {
        b"Bad file descriptor"
    } else if errno == 13 {
        b"Permission denied"
    } else if errno == 17 {
        b"File exists"
    } else if errno == 18 {
        b"Cross-device link"
    } else if errno == 20 {
        b"Not a directory"
    } else if errno == 21 {
        b"Is a directory"
    } else if errno == 22 {
        b"Invalid argument"
    } else if errno == 28 {
        b"No space left on device"
    } else if errno == 36 {
        b"File name too long"
    } else if errno == 39 || errno == 66 {
        b"Directory not empty"
    } else {
        b"I/O error"
    }
}

/// `prog: path: message\n` on stderr -- the shape every classic Unix utility reports a failed
/// operation in.
pub fn eprint_errno(prog: &[u8], path: &[u8], errno: u64) {
    eprint(prog);
    eprint(b": ");
    eprint(path);
    eprint(b": ");
    eprint(errno_str(errno));
    eprint(b"\n");
}
