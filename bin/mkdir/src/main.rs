//! `mkdir` -- creates directories. `-p` creates missing intermediate directories and doesn't
//! complain if the final one already exists (as a directory).
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{EEXIST, mkdir, stat};
use oxlibc::io::eprint_errno;

const ENOTDIR: u64 = 20;

/// Creates every prefix of `path` in turn, tolerating `EEXIST` -- the real `mkdir -p` algorithm.
/// Empty prefixes (a leading `/`, doubled slashes) are skipped.
fn mkdir_p(path: &[u8]) -> Result<(), u64> {
    for end in 1..=path.len() {
        let at_boundary = end == path.len() || path[end] == b'/';
        if !at_boundary || path[end - 1] == b'/' {
            continue;
        }
        match mkdir(&path[..end]) {
            Ok(()) => {}
            Err(EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    // Every prefix "existing" isn't enough: the final one must really be a directory.
    match stat(path) {
        Ok(st) if st.is_dir() => Ok(()),
        Ok(_) => Err(ENOTDIR),
        Err(e) => Err(e),
    }
}

fn main(argv: &[&[u8]]) -> u64 {
    let parents = has_flag(argv, b'p', None);
    let mut status = 0;
    let mut any = false;
    for path in positional_args(argv) {
        any = true;
        let result = if parents { mkdir_p(path) } else { mkdir(path) };
        if let Err(errno) = result {
            eprint_errno(b"mkdir", path, errno);
            status = 1;
        }
    }
    if !any {
        oxlibc::io::eprint(b"usage: mkdir [-p] directory...\n");
        return 1;
    }
    status
}

oxlibc::entry_point!(main);
