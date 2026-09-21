//! `ln` -- `ln target linkname` makes a hard link; `-s` makes a symbolic link instead. If the last
//! argument is an existing directory, each `target` is linked *into* it under its own basename
//! (so `ln a b c dir/` works); otherwise exactly two arguments are expected.
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{link, stat, symlink};
use oxlibc::io::{eprint, eprint_errno};
use oxlibc::path::join_basename;

fn main(argv: &[&[u8]]) -> u64 {
    let symbolic = has_flag(argv, b's', None);
    let count = positional_args(argv).count();
    let Some(dest) = positional_args(argv).last().filter(|_| count >= 2) else {
        eprint(b"usage: ln [-s] target... linkname\n");
        return 1;
    };
    let dest_is_dir = stat(dest).map(|s| s.is_dir()).unwrap_or(false);
    if count > 2 && !dest_is_dir {
        eprint_errno(b"ln", dest, 20); // ENOTDIR
        return 1;
    }

    let mut status = 0;
    for target in positional_args(argv).take(count - 1) {
        let joined;
        let linkpath: &[u8] = if dest_is_dir {
            match join_basename(dest, target) {
                Some(p) => {
                    joined = p;
                    joined.as_bytes()
                }
                None => {
                    eprint_errno(b"ln", dest, 36); // ENAMETOOLONG
                    status = 1;
                    continue;
                }
            }
        } else {
            dest
        };
        let result = if symbolic {
            symlink(target, linkpath)
        } else {
            link(target, linkpath)
        };
        if let Err(errno) = result {
            eprint_errno(b"ln", linkpath, errno);
            status = 1;
        }
    }
    status
}

oxlibc::entry_point!(main);
