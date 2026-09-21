//! `cp` -- `cp src dst` copies a file; `-r` copies directories recursively. If the last argument is
//! an existing directory, each source is copied *into* it under its own basename (`cp a b dir/`).
//! Follows symlinks (copies what they point at), preserves permission bits, not timestamps.
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{
    Dirents, EEXIST, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, close, getdents, is_dot_or_dotdot,
    mkdir, open, read, stat, write,
};
use oxlibc::io::{eprint, eprint_errno};
use oxlibc::path::{PathBuf, join_basename};

fn copy_fd_to_fd(from: u64, to: u64) -> Result<(), u64> {
    let mut buf = [0u8; 4096];
    loop {
        let n = read(from, &mut buf)?;
        if n == 0 {
            return Ok(());
        }
        let mut done = 0;
        while done < n {
            let w = write(to, &buf[done..n])?;
            if w == 0 {
                return Err(5); // EIO
            }
            done += w;
        }
    }
}

/// Copies one regular file, reporting any failure against the path it happened on.
fn copy_file(src: &[u8], dst: &[u8], perm: u64) -> bool {
    let from = match open(src, O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(errno) => {
            eprint_errno(b"cp", src, errno);
            return false;
        }
    };
    let to = match open(dst, O_WRONLY | O_CREAT | O_TRUNC, perm) {
        Ok(fd) => fd,
        Err(errno) => {
            eprint_errno(b"cp", dst, errno);
            close(from);
            return false;
        }
    };
    let result = copy_fd_to_fd(from, to);
    close(from);
    // The destination's contents (and, if it's new, its directory entry) are committed on close.
    close(to);
    if let Err(errno) = result {
        eprint_errno(b"cp", dst, errno);
        return false;
    }
    true
}

/// Copies the tree at `src` to `dst`, both restored to their original lengths on return.
fn cp_tree(src: &mut PathBuf, dst: &mut PathBuf) -> bool {
    let st = match stat(src.as_bytes()) {
        Ok(st) => st,
        Err(errno) => {
            eprint_errno(b"cp", src.as_bytes(), errno);
            return false;
        }
    };
    if !st.is_dir() {
        return copy_file(src.as_bytes(), dst.as_bytes(), st.perm());
    }

    match mkdir(dst.as_bytes()) {
        Ok(()) | Err(EEXIST) => {}
        Err(errno) => {
            eprint_errno(b"cp", dst.as_bytes(), errno);
            return false;
        }
    }
    let fd = match open(src.as_bytes(), O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(errno) => {
            eprint_errno(b"cp", src.as_bytes(), errno);
            return false;
        }
    };
    let (src_base, dst_base) = (src.len(), dst.len());
    let mut ok = true;
    let mut buf = [0u8; 1024];
    loop {
        let n = match getdents(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(errno) => {
                eprint_errno(b"cp", src.as_bytes(), errno);
                ok = false;
                break;
            }
        };
        for (name, _dtype) in Dirents::new(&buf[..n]) {
            if is_dot_or_dotdot(name) {
                continue;
            }
            if !(src.push(name) && dst.push(name)) {
                eprint_errno(b"cp", name, 36); // ENAMETOOLONG
                ok = false;
            } else if !cp_tree(src, dst) {
                ok = false;
            }
            src.truncate(src_base);
            dst.truncate(dst_base);
        }
    }
    close(fd);
    ok
}

fn main(argv: &[&[u8]]) -> u64 {
    let recursive = has_flag(argv, b'r', None) || has_flag(argv, b'R', None);
    let count = positional_args(argv).count();
    let Some(dest) = positional_args(argv).last().filter(|_| count >= 2) else {
        eprint(b"usage: cp [-r] source... target\n");
        return 1;
    };
    let dest_is_dir = stat(dest).map(|s| s.is_dir()).unwrap_or(false);
    if count > 2 && !dest_is_dir {
        eprint_errno(b"cp", dest, 20); // ENOTDIR
        return 1;
    }

    let mut status = 0;
    for src in positional_args(argv).take(count - 1) {
        let target = if dest_is_dir {
            join_basename(dest, src)
        } else {
            PathBuf::from(dest)
        };
        let (Some(mut dst), Some(mut from)) = (target, PathBuf::from(src)) else {
            eprint_errno(b"cp", src, 36); // ENAMETOOLONG
            status = 1;
            continue;
        };
        if let Ok(st) = stat(src)
            && st.is_dir()
            && !recursive
        {
            eprint(b"cp: omitting directory '");
            eprint(src);
            eprint(b"'\n");
            status = 1;
            continue;
        }
        if !cp_tree(&mut from, &mut dst) {
            status = 1;
        }
    }
    status
}

oxlibc::entry_point!(main);
