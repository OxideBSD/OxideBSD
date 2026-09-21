//! `rm` -- removes files. `-r` removes directories recursively; `-f` ignores nonexistent paths and
//! never prompts (there's nothing to prompt with anyway). Flags may be clustered (`-rf`).
//!
//! Directory removal reads a batch of entries, deletes them, then *re-opens* the directory and
//! reads again rather than continuing one `getdents` cursor: `oxfs`'s cursor counts *used* records,
//! so deleting entries out from under a live cursor would make it skip the ones that shift down.
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{
    Dirents, ENOENT, O_RDONLY, close, getdents, is_dot_or_dotdot, lstat, open, rmdir, unlink,
};
use oxlibc::io::{eprint, eprint_errno};
use oxlibc::path::PathBuf;

/// Removes the directory tree rooted at `path` (which is left as it was on return). `true` on
/// full success; failures are reported as they happen.
fn rm_tree(path: &mut PathBuf, force: bool) -> bool {
    let mut ok = true;
    loop {
        let fd = match open(path.as_bytes(), O_RDONLY, 0) {
            Ok(fd) => fd,
            Err(errno) => {
                eprint_errno(b"rm", path.as_bytes(), errno);
                return false;
            }
        };
        let mut buf = [0u8; 1024];
        let n = getdents(fd, &mut buf);
        close(fd);
        let n = match n {
            Ok(n) => n,
            Err(errno) => {
                eprint_errno(b"rm", path.as_bytes(), errno);
                return false;
            }
        };

        let mut saw_entry = false;
        let mut progress = false;
        let base = path.len();
        for (name, _dtype) in Dirents::new(&buf[..n]) {
            if is_dot_or_dotdot(name) {
                continue;
            }
            saw_entry = true;
            if !path.push(name) {
                eprint_errno(b"rm", name, 36); // ENAMETOOLONG
                ok = false;
                continue;
            }
            let removed = match lstat(path.as_bytes()) {
                Ok(st) if st.is_dir() => rm_tree(path, force),
                Ok(_) => match unlink(path.as_bytes()) {
                    Ok(()) => true,
                    Err(errno) => {
                        eprint_errno(b"rm", path.as_bytes(), errno);
                        false
                    }
                },
                Err(errno) => {
                    eprint_errno(b"rm", path.as_bytes(), errno);
                    false
                }
            };
            path.truncate(base);
            if removed {
                progress = true;
            } else {
                ok = false;
            }
        }

        if !saw_entry {
            break; // empty (only `.`/`..` left): ready to remove the directory itself
        }
        if !progress {
            return false; // nothing in this batch could be removed -- don't loop forever
        }
    }
    if !ok {
        return false;
    }
    match rmdir(path.as_bytes()) {
        Ok(()) => true,
        Err(errno) => {
            eprint_errno(b"rm", path.as_bytes(), errno);
            false
        }
    }
}

fn main(argv: &[&[u8]]) -> u64 {
    let recursive = has_flag(argv, b'r', None) || has_flag(argv, b'R', None);
    let force = has_flag(argv, b'f', None);
    let mut status = 0;
    let mut any = false;
    for path in positional_args(argv) {
        any = true;
        if path == b"/" {
            eprint(b"rm: refusing to remove '/'\n");
            status = 1;
            continue;
        }
        match lstat(path) {
            Err(ENOENT) if force => {}
            Err(errno) => {
                eprint_errno(b"rm", path, errno);
                status = 1;
            }
            Ok(st) if st.is_dir() => {
                if !recursive {
                    eprint_errno(b"rm", path, 21); // EISDIR
                    status = 1;
                    continue;
                }
                let Some(mut buf) = PathBuf::from(path) else {
                    eprint_errno(b"rm", path, 36); // ENAMETOOLONG
                    status = 1;
                    continue;
                };
                if !rm_tree(&mut buf, force) {
                    status = 1;
                }
            }
            Ok(_) => {
                if let Err(errno) = unlink(path) {
                    eprint_errno(b"rm", path, errno);
                    status = 1;
                }
            }
        }
    }
    if !any && !force {
        eprint(b"usage: rm [-rf] file...\n");
        return 1;
    }
    status
}

oxlibc::entry_point!(main);
