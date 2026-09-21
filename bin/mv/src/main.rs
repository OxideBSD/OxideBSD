//! `mv` -- `mv src dst` renames; if the last argument is an existing directory, each source is
//! moved *into* it under its own basename (`mv a b c dir/`). Just `rename(2)`: oxfs is the only
//! root store, so there's no cross-device copy-and-delete fallback to implement.
#![no_std]
#![no_main]

use oxlibc::args::positional_args;
use oxlibc::fs::{rename, stat};
use oxlibc::io::{eprint, eprint_errno};
use oxlibc::path::join_basename;

fn main(argv: &[&[u8]]) -> u64 {
    let count = positional_args(argv).count();
    let Some(dest) = positional_args(argv).last().filter(|_| count >= 2) else {
        eprint(b"usage: mv source... target\n");
        return 1;
    };
    let dest_is_dir = stat(dest).map(|s| s.is_dir()).unwrap_or(false);
    if count > 2 && !dest_is_dir {
        eprint_errno(b"mv", dest, 20); // ENOTDIR
        return 1;
    }

    let mut status = 0;
    for src in positional_args(argv).take(count - 1) {
        let joined;
        let target: &[u8] = if dest_is_dir {
            match join_basename(dest, src) {
                Some(p) => {
                    joined = p;
                    joined.as_bytes()
                }
                None => {
                    eprint_errno(b"mv", dest, 36); // ENAMETOOLONG
                    status = 1;
                    continue;
                }
            }
        } else {
            dest
        };
        if let Err(errno) = rename(src, target) {
            eprint_errno(b"mv", src, errno);
            status = 1;
        }
    }
    status
}

oxlibc::entry_point!(main);
