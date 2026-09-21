//! `ls` -- lists directories (or names files). Sorted bytewise, one entry per line. `-a` includes
//! dotfiles (and `.`/`..`). `-l` prints `mode nlink owner group size mtime name` with aligned
//! columns, a `total` line for directory listings, owner/group *names* from `/etc/passwd` and
//! `/etc/group` (numeric if absent), and ` -> target` for symlinks. Times are UTC (no timezone
//! database). Flags may be clustered (`-la`).
//!
//! No heap: a directory's names are collected into a fixed `.bss` buffer plus an index array, then
//! insertion-sorted. Listings past those fixed capacities are cut short with a message on stderr.
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{Dirents, O_RDONLY, Stat, close, getdents, lstat, open, read, readlink};
use oxlibc::io::{eprint, eprint_errno, fmt_u64, print};
use oxlibc::path::{MAX_PATH, PathBuf};
use oxlibc::time::{format_ls_time, now};

const NAMES_CAP: usize = 64 * 1024;
const ENTRIES_CAP: usize = 2048;
const DB_CAP: usize = 4096;
const NAME_CAP: usize = 32;

static mut NAMES: [u8; NAMES_CAP] = [0; NAMES_CAP];
/// `(offset, length)` of each collected name inside `NAMES`.
static mut ENTRIES: [(u32, u16); ENTRIES_CAP] = [(0, 0); ENTRIES_CAP];

/// Everything `-l` needs that's loaded once per run.
struct Ctx {
    all: bool,
    long: bool,
    now: i64,
    passwd: [u8; DB_CAP],
    passwd_len: usize,
    group: [u8; DB_CAP],
    group_len: usize,
}

/// Column widths for one listing, so `-l` output lines up.
#[derive(Default)]
struct Widths {
    nlink: usize,
    owner: usize,
    group: usize,
    size: usize,
}

fn digits(mut n: u64) -> usize {
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut n: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(n)
}

/// Reads up to `buf.len()` bytes of `path` (an `/etc` database); `0` if it can't be read.
fn slurp(path: &[u8], buf: &mut [u8]) -> usize {
    let Ok(fd) = open(path, O_RDONLY, 0) else {
        return 0;
    };
    let mut len = 0;
    while len < buf.len() {
        match read(fd, &mut buf[len..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => len += n,
        }
    }
    close(fd);
    len
}

/// Writes the name for `id` from a `name:x:id:...` database into `out` (the id in decimal if it
/// isn't listed), returning the length used.
fn id_name(db: &[u8], id: u32, out: &mut [u8; NAME_CAP]) -> usize {
    for line in db.split(|&b| b == b'\n') {
        let mut fields = line.split(|&b| b == b':');
        let (Some(name), Some(_), Some(id_field)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if parse_u32(id_field) == Some(id) {
            let n = name.len().min(NAME_CAP);
            out[..n].copy_from_slice(&name[..n]);
            return n;
        }
    }
    let mut buf = [0u8; 20];
    let s = fmt_u64(id as u64, &mut buf);
    out[..s.len()].copy_from_slice(s);
    s.len()
}

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

fn print_padded(s: &[u8], width: usize, right_align: bool) {
    let pad = width.saturating_sub(s.len());
    if right_align {
        for _ in 0..pad {
            print(b" ");
        }
    }
    print(s);
    if !right_align {
        for _ in 0..pad {
            print(b" ");
        }
    }
}

/// Grows `w` to fit `st`'s columns.
fn measure(ctx: &Ctx, st: &Stat, w: &mut Widths) {
    let mut tmp = [0u8; NAME_CAP];
    w.nlink = w.nlink.max(digits(st.nlink));
    w.size = w.size.max(digits(st.size));
    w.owner = w
        .owner
        .max(id_name(&ctx.passwd[..ctx.passwd_len], st.uid, &mut tmp));
    w.group = w
        .group
        .max(id_name(&ctx.group[..ctx.group_len], st.gid, &mut tmp));
}

/// One output row. `full` is the path to `readlink` for a symlink's target (only used for `-l`).
fn print_row(ctx: &Ctx, name: &[u8], full: &[u8], st: &Stat, w: &Widths) {
    if !ctx.long {
        print(name);
        print(b"\n");
        return;
    }
    let mut num = [0u8; 20];
    let mut who = [0u8; NAME_CAP];

    print(&mode_string(st));
    print(b" ");
    print_padded(fmt_u64(st.nlink, &mut num), w.nlink, true);
    print(b" ");
    let n = id_name(&ctx.passwd[..ctx.passwd_len], st.uid, &mut who);
    print_padded(&who[..n], w.owner, false);
    print(b" ");
    let n = id_name(&ctx.group[..ctx.group_len], st.gid, &mut who);
    print_padded(&who[..n], w.group, false);
    print(b" ");
    print_padded(fmt_u64(st.size, &mut num), w.size, true);
    print(b" ");
    let mut when = [0u8; 12];
    format_ls_time(st.mtime, ctx.now, &mut when);
    print(&when);
    print(b" ");
    print(name);
    if st.is_symlink() {
        let mut target = [0u8; MAX_PATH];
        if let Ok(n) = readlink(full, &mut target) {
            print(b" -> ");
            print(&target[..n]);
        }
    }
    print(b"\n");
}

fn list_dir(ctx: &Ctx, path: &[u8], with_header_total: bool) -> bool {
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
            if !ctx.all && name.first() == Some(&b'.') {
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

    // `-l` measuring pass: column widths and the `total` line (in 1K blocks, from 512-byte ones).
    let mut widths = Widths::default();
    if ctx.long {
        let mut blocks = 0u64;
        for &e in &entries[..count] {
            if full.push(name_of(e)) {
                if let Ok(st) = lstat(full.as_bytes()) {
                    measure(ctx, &st, &mut widths);
                    blocks += st.blocks;
                }
            }
            full.truncate(base);
        }
        if with_header_total {
            let mut num = [0u8; 20];
            print(b"total ");
            print(fmt_u64(blocks / 2, &mut num));
            print(b"\n");
        }
    }

    for &e in &entries[..count] {
        let name = name_of(e);
        if !ctx.long {
            print(name);
            print(b"\n");
            continue;
        }
        if !full.push(name) {
            eprint_errno(b"ls", name, 36);
            ok = false;
            continue;
        }
        match lstat(full.as_bytes()) {
            Ok(st) => print_row(ctx, name, full.as_bytes(), &st, &widths),
            Err(errno) => {
                eprint_errno(b"ls", full.as_bytes(), errno);
                ok = false;
            }
        }
        full.truncate(base);
    }
    if truncated {
        eprint(b"ls: listing truncated (directory too large for the fixed buffer)\n");
        ok = false;
    }
    ok
}

fn main(argv: &[&[u8]]) -> u64 {
    let long = has_flag(argv, b'l', None);
    let mut ctx = Ctx {
        all: has_flag(argv, b'a', None),
        long,
        now: 0,
        passwd: [0; DB_CAP],
        passwd_len: 0,
        group: [0; DB_CAP],
        group_len: 0,
    };
    if long {
        ctx.now = now().unwrap_or(0);
        ctx.passwd_len = slurp(b"/etc/passwd", &mut ctx.passwd);
        ctx.group_len = slurp(b"/etc/group", &mut ctx.group);
    }

    let count = positional_args(argv).count();
    let mut status = 0;
    let mut first = true;

    if count == 0 {
        return if list_dir(&ctx, b".", true) { 0 } else { 1 };
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
            let mut w = Widths::default();
            measure(&ctx, &st, &mut w);
            print_row(&ctx, path, path, &st, &w);
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
        if !list_dir(&ctx, path, true) {
            status = 1;
        }
    }
    status
}

oxlibc::entry_point!(main);
