//! `ls` -- lists directories (or names files). Sorted bytewise, one entry per line. `-a` includes
//! dotfiles (and `.`/`..`); `-l` prints `mode nlink uid gid size name` (no timestamp column, no
//! symlink-target suffix yet). Flags may be clustered (`-la`).
//!
//! No heap: a directory's names are collected into a fixed `.bss` buffer plus an index array, then
//! insertion-sorted. Listings past those fixed capacities are cut short with a message on stderr.
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{Dirents, O_RDONLY, Stat, close, getdents, lstat, open};
use oxlibc::io::{eprint, eprint_errno, fmt_u64, print};
use oxlibc::path::PathBuf;

const NAMES_CAP: usize = 64 * 1024;
const ENTRIES_CAP: usize = 2048;

static mut NAMES: [u8; NAMES_CAP] = [0; NAMES_CAP];
/// `(offset, length)` of each collected name inside `NAMES`.
static mut ENTRIES: [(u32, u16); ENTRIES_CAP] = [(0, 0); ENTRIES_CAP];

fn mode_string(st: &Stat) -> [u8; 10] {
    let mut s = *b"----------";
    if st.is_dir() {
        s[0] = b'd';
    } else if st.is_symlink() {
        s[0] = b'l';
    }
    let bits = b"rwxrwxrwx";
    for i in 0..9 {
        if st.mode & (0o400 >> i) != 0 {
            s[i + 1] = bits[i];
        }
    }
    s
}

fn print_num(n: u64) {
    let mut buf = [0u8; 20];
    print(fmt_u64(n, &mut buf));
}

/// One output row for `name`; `full` (the path to lstat) is only used for `-l`.
fn print_entry(name: &[u8], full: &[u8], long: bool) {
    if long {
        match lstat(full) {
            Ok(st) => {
                print(&mode_string(&st));
                print(b" ");
                print_num(st.nlink);
                print(b" ");
                print_num(st.uid as u64);
                print(b" ");
                print_num(st.gid as u64);
                print(b" ");
                print_num(st.size);
                print(b" ");
            }
            Err(errno) => {
                eprint_errno(b"ls", full, errno);
                return;
            }
        }
    }
    print(name);
    print(b"\n");
}

fn list_dir(path: &[u8], all: bool, long: bool) -> bool {
    let fd = match open(path, O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(errno) => {
            eprint_errno(b"ls", path, errno);
            return false;
        }
    };
    // SAFETY: single-threaded process; these two statics are only ever touched through these slices,
    // one directory at a time. Built from raw pointers (edition 2024 forbids `&`/`&mut` to a
    // `static mut`).
    let names: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(&raw mut NAMES as *mut u8, NAMES_CAP) };
    let entries: &mut [(u32, u16)] = unsafe {
        core::slice::from_raw_parts_mut(&raw mut ENTRIES as *mut (u32, u16), ENTRIES_CAP)
    };

    let (mut used, mut count) = (0usize, 0usize);
    let mut truncated = false;
    let mut ok = true;
    let mut buf = [0u8; 2048];
    'read: loop {
        let n = match getdents(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(errno) => {
                eprint_errno(b"ls", path, errno);
                ok = false;
                break;
            }
        };
        for (name, _dtype) in Dirents::new(&buf[..n]) {
            if !all && name.first() == Some(&b'.') {
                continue;
            }
            if count == ENTRIES_CAP || used + name.len() > NAMES_CAP {
                truncated = true;
                break 'read;
            }
            names[used..used + name.len()].copy_from_slice(name);
            entries[count] = (used as u32, name.len() as u16);
            used += name.len();
            count += 1;
        }
    }
    close(fd);

    let name_of = |e: (u32, u16)| &names[e.0 as usize..e.0 as usize + e.1 as usize];
    // Insertion sort over the index array (bytewise, like `LC_ALL=C ls`).
    for i in 1..count {
        let key = entries[i];
        let mut j = i;
        while j > 0 && name_of(entries[j - 1]) > name_of(key) {
            entries[j] = entries[j - 1];
            j -= 1;
        }
        entries[j] = key;
    }

    let Some(mut full) = PathBuf::from(path) else {
        eprint_errno(b"ls", path, 36); // ENAMETOOLONG
        return false;
    };
    let base = full.len();
    for &e in &entries[..count] {
        let name = name_of(e);
        if long {
            if !full.push(name) {
                eprint_errno(b"ls", name, 36);
                ok = false;
                continue;
            }
            print_entry(name, full.as_bytes(), true);
            full.truncate(base);
        } else {
            print_entry(name, name, false);
        }
    }
    if truncated {
        eprint(b"ls: listing truncated (directory too large for the fixed buffer)\n");
        ok = false;
    }
    ok
}

fn main(argv: &[&[u8]]) -> u64 {
    let all = has_flag(argv, b'a', None);
    let long = has_flag(argv, b'l', None);
    let count = positional_args(argv).count();
    let mut status = 0;
    let mut first = true;

    if count == 0 {
        if !list_dir(b".", all, long) {
            status = 1;
        }
        return status;
    }
    for path in positional_args(argv) {
        let st = match lstat(path) {
            Ok(st) => st,
            Err(errno) => {
                eprint_errno(b"ls", path, errno);
                status = 1;
                continue;
            }
        };
        if !st.is_dir() {
            print_entry(path, path, long);
            first = false;
            continue;
        }
        if count > 1 {
            if !first {
                print(b"\n");
            }
            print(path);
            print(b":\n");
        }
        first = false;
        if !list_dir(path, all, long) {
            status = 1;
        }
    }
    status
}

oxlibc::entry_point!(main);
