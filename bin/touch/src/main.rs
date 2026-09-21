//! `touch` -- makes sure each named file exists. `-c` doesn't create a missing file. On an
//! existing file it issues a real `utimensat` (this kernel's handler is currently an existence
//! check that doesn't move timestamps -- see `sys/modules/oxfs`'s `oxfs_utimensat` -- so an existing
//! file's mtime isn't actually advanced yet); on `ENOENT` it creates the file via `open(O_CREAT)`.
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
