//! `cat` -- concatenates files to stdout. With no file arguments (or a `-` argument) it reads
//! stdin instead. Note this kernel's `read()` on the *interactive console* stdin is non-blocking by
//! design (returns 0 immediately when empty, not a real EOF -- see `CLAUDE.md`), so bare `cat` at a
//! prompt just exits; reading from a pipe (`cmd | cat`) blocks and works normally.
#![no_std]
#![no_main]

use oxlibc::args::positional_args;
use oxlibc::fs::{O_RDONLY, close, open, read};
use oxlibc::io::{STDIN, STDOUT, eprint_errno, write_all};

/// Copies `fd` to stdout until EOF. `Err(errno)` on the first read or write failure.
fn copy_fd(fd: u64) -> Result<(), u64> {
    let mut buf = [0u8; 4096];
    loop {
        let n = read(fd, &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        write_all(STDOUT, &buf[..n])?;
    }
}

fn main(argv: &[&[u8]]) -> u64 {
    let mut status = 0;
    let mut any = false;
    for path in positional_args(argv) {
        any = true;
        let result = if path == b"-" {
            copy_fd(STDIN)
        } else {
            match open(path, O_RDONLY, 0) {
                Ok(fd) => {
                    let r = copy_fd(fd);
                    close(fd);
                    r
                }
                Err(e) => Err(e),
            }
        };
        if let Err(errno) = result {
            eprint_errno(b"cat", path, errno);
            status = 1;
        }
    }
    if !any && let Err(errno) = copy_fd(STDIN) {
        eprint_errno(b"cat", b"stdin", errno);
        status = 1;
    }
    status
}

oxlibc::entry_point!(main);
