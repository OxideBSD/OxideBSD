//! `touch` -- sets each named file's access and modification times to now, creating it (empty) if
//! it doesn't exist. `-c` doesn't create a missing file. `utimensat` reports `ENOENT` for a
//! missing path, which is how this knows to fall back to `open(O_CREAT)`.
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{ENOENT, O_CREAT, O_WRONLY, close, open, utimensat};
use oxlibc::io::{eprint, eprint_errno};

fn main(argv: &[&[u8]]) -> u64 {
    let no_create = has_flag(argv, b'c', None);
    let mut status = 0;
    let mut any = false;
    for path in positional_args(argv) {
        any = true;
        match utimensat(path) {
            Ok(()) => {}
            Err(ENOENT) if !no_create => match open(path, O_WRONLY | O_CREAT, 0o644) {
                // The new (empty) file's inode and directory entry are only committed on close.
                Ok(fd) => close(fd),
                Err(errno) => {
                    eprint_errno(b"touch", path, errno);
                    status = 1;
                }
            },
            Err(ENOENT) => {}
            Err(errno) => {
                eprint_errno(b"touch", path, errno);
                status = 1;
            }
        }
    }
    if !any {
        eprint(b"usage: touch [-c] file...\n");
        return 1;
    }
    status
}

oxlibc::entry_point!(main);
