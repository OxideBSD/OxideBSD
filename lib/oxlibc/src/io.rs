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

const SYS_IOCTL: u64 = 124;
const TIOCGWINSZ: u64 = 0x5413;

/// `(rows, columns)` if `fd` is a terminal, `None` otherwise -- i.e. this doubles as `isatty()`.
/// This kernel only answers `TIOCGWINSZ` for the real console (and follows `dup2`, so a redirected
/// stdout correctly reports "not a terminal").
pub fn tty_size(fd: u64) -> Option<(u16, u16)> {
    let mut ws = [0u16; 4]; // struct winsize { ws_row, ws_col, ws_xpixel, ws_ypixel }
    unsafe { syscall3(SYS_IOCTL, fd, TIOCGWINSZ, ws.as_mut_ptr() as u64) }.ok()?;
    Some((ws[0], ws[1]))
}

const BUF_CAP: usize = 4096;

/// A buffered writer. A `write` syscall to the console is expensive -- `ls /bin` (~260 entries,
/// two writes each) took 770 ms to the console but 30 ms to `/dev/null`, i.e. ~1 ms per write -- so
/// a utility that prints many small pieces should batch them. Flushes when full, on `flush()`, and
/// on drop; errors are ignored, like `print`.
pub struct BufWriter {
    fd: u64,
    buf: [u8; BUF_CAP],
    len: usize,
}

impl BufWriter {
    pub fn new(fd: u64) -> BufWriter {
        BufWriter {
            fd,
            buf: [0; BUF_CAP],
            len: 0,
        }
    }

    pub fn write(&mut self, s: &[u8]) {
        if s.len() >= BUF_CAP {
            self.flush();
            let _ = write_all(self.fd, s);
            return;
        }
        if self.len + s.len() > BUF_CAP {
            self.flush();
        }
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.len += s.len();
    }

    /// `n` spaces.
    pub fn spaces(&mut self, n: usize) {
        const SPACES: &[u8] = b"                ";
        let mut left = n;
        while left > 0 {
            let k = left.min(SPACES.len());
            self.write(&SPACES[..k]);
            left -= k;
        }
    }

    pub fn flush(&mut self) {
        if self.len > 0 {
            let _ = write_all(self.fd, &self.buf[..self.len]);
            self.len = 0;
        }
    }
}

impl Drop for BufWriter {
    fn drop(&mut self) {
        self.flush();
    }
}
