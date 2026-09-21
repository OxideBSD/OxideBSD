//! `ls` -- lists directories (or names files). Sorted bytewise.
//!
//! On a terminal (this kernel only answers `TIOCGWINSZ` for the console, so redirected/piped
//! output is correctly one-per-line and uncolored) a plain `ls` is laid out in columns, column-
//! major like every real `ls`, and names are colored: directories bold blue, symlinks bold cyan,
//! executables bold green. `-1` forces one per line, `-C` forces columns (80 wide off a
//! terminal), `--color=always|never|auto` overrides coloring.
//!
//! `-a` includes dotfiles (and `.`/`..`). `-l` prints `mode nlink owner group size mtime name` with
//! aligned columns, a `total` line for directory listings, owner/group *names* from `/etc/passwd`
//! and `/etc/group` (numeric if absent), UTC times, and ` -> target` for symlinks. Flags may be
//! clustered (`-la`).
//!
//! All output goes through a buffer: console writes cost ~1 ms each, so `ls /bin` used to take
//! 770 ms to the console but 30 ms to `/dev/null`.
//!
//! No heap: a directory's names are collected into a fixed `.bss` buffer plus an index array, then
//! insertion-sorted. Listings past those fixed capacities are cut short with a message on stderr.
#![no_std]
#![no_main]

use oxlibc::args::{has_flag, positional_args};
use oxlibc::fs::{Dirents, O_RDONLY, Stat, close, getdents, lstat, open, read, readlink};
use oxlibc::io::{BufWriter, STDOUT, eprint, eprint_errno, fmt_u64, tty_size};
use oxlibc::path::{MAX_PATH, PathBuf};
use oxlibc::time::{format_ls_time, now};

const NAMES_CAP: usize = 64 * 1024;
const ENTRIES_CAP: usize = 2048;
const DB_CAP: usize = 4096;
const NAME_CAP: usize = 32;
/// Width assumed for `-C` when stdout isn't a terminal.
const DEFAULT_COLUMNS: usize = 80;

const RESET: &[u8] = b"\x1b[0m";

/// How a name is colored.
const PLAIN: u8 = 0;
const DIR: u8 = 1;
const SYMLINK: u8 = 2;
const EXEC: u8 = 3;

/// `(offset, length, kind)` of each collected name: where it sits in `NAMES`, and its color kind.
type Entry = (u32, u16, u8);

static mut NAMES: [u8; NAMES_CAP] = [0; NAMES_CAP];
static mut ENTRIES: [Entry; ENTRIES_CAP] = [(0, 0, PLAIN); ENTRIES_CAP];

/// Everything decided once per run.
struct Ctx {
    all: bool,
    long: bool,
    color: bool,
    /// `Some(width)` if a plain listing should be laid out in columns.
    columns: Option<usize>,
    now: i64,
    passwd: [u8; DB_CAP],
    passwd_len: usize,
    group: [u8; DB_CAP],
    group_len: usize,
}

/// Column widths for one `-l` listing, so it lines up.
#[derive(Default)]
struct Widths {
    nlink: usize,
    owner: usize,
    group: usize,
    size: usize,
}

fn color_code(kind: u8) -> &'static [u8] {
    if kind == DIR {
        b"\x1b[1;34m"
    } else if kind == SYMLINK {
        b"\x1b[1;36m"
    } else {
        b"\x1b[1;32m"
    }
}

fn kind_of(st: &Stat) -> u8 {
    if st.is_dir() {
        DIR
    } else if st.is_symlink() {
        SYMLINK
    } else if st.mode & 0o111 != 0 {
        EXEC
    } else {
        PLAIN
    }
}

/// Writes `name`, wrapped in its color if coloring is on and it has one.
fn emit_name(ctx: &Ctx, out: &mut BufWriter, name: &[u8], kind: u8) {
    if ctx.color && kind != PLAIN {
        out.write(color_code(kind));
        out.write(name);
        out.write(RESET);
    } else {
        out.write(name);
    }
}

/// Reports an error in order with buffered stdout.
fn fail(out: &mut BufWriter, path: &[u8], errno: u64) {
    out.flush();
    eprint_errno(b"ls", path, errno);
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

fn write_padded(out: &mut BufWriter, s: &[u8], width: usize, right_align: bool) {
    let pad = width.saturating_sub(s.len());
    if right_align {
        out.spaces(pad);
    }
    out.write(s);
    if !right_align {
        out.spaces(pad);
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

/// One `-l` row. `full` is the path to `readlink` for a symlink's target.
fn write_long_row(ctx: &Ctx, out: &mut BufWriter, name: &[u8], full: &[u8], st: &Stat, w: &Widths) {
    let mut num = [0u8; 20];
    let mut who = [0u8; NAME_CAP];

    out.write(&mode_string(st));
    out.write(b" ");
    write_padded(out, fmt_u64(st.nlink, &mut num), w.nlink, true);
    out.write(b" ");
    let n = id_name(&ctx.passwd[..ctx.passwd_len], st.uid, &mut who);
    write_padded(out, &who[..n], w.owner, false);
    out.write(b" ");
    let n = id_name(&ctx.group[..ctx.group_len], st.gid, &mut who);
    write_padded(out, &who[..n], w.group, false);
    out.write(b" ");
    write_padded(out, fmt_u64(st.size, &mut num), w.size, true);
    out.write(b" ");
    let mut when = [0u8; 12];
    format_ls_time(st.mtime, ctx.now, &mut when);
    out.write(&when);
    out.write(b" ");
    emit_name(ctx, out, name, kind_of(st));
    if st.is_symlink() {
        let mut target = [0u8; MAX_PATH];
        if let Ok(n) = readlink(full, &mut target) {
            out.write(b" -> ");
            out.write(&target[..n]);
        }
    }
    out.write(b"\n");
}

/// A plain listing in `width` columns, filled down each column first (like every real `ls`).
fn write_columns(ctx: &Ctx, out: &mut BufWriter, names: &[u8], entries: &[Entry], width: usize) {
    let count = entries.len();
    if count == 0 {
        return;
    }
    let col_width = entries.iter().map(|e| e.1 as usize).max().unwrap_or(0) + 2;
    let per_row = (width / col_width).clamp(1, count);
    let rows = count.div_ceil(per_row);
    let cols = count.div_ceil(rows); // drop columns that would come out empty
    for r in 0..rows {
        for c in 0..cols {
            let i = c * rows + r;
            let Some(&(off, len, kind)) = entries.get(i) else {
                break;
            };
            let name = &names[off as usize..off as usize + len as usize];
            emit_name(ctx, out, name, kind);
            // Pad to the column edge -- but not after the last name on the row.
            if c + 1 < cols && i + rows < count {
                out.spaces(col_width - len as usize);
            }
        }
        out.write(b"\n");
    }
}

fn list_dir(ctx: &Ctx, out: &mut BufWriter, path: &[u8]) -> bool {
    let fd = match open(path, O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(errno) => {
            fail(out, path, errno);
            return false;
        }
    };
    // SAFETY: single-threaded process; these two statics are only ever touched through these slices,
    // one directory at a time. Built from raw pointers (edition 2024 forbids `&`/`&mut` to a
    // `static mut`).
    let names: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(&raw mut NAMES as *mut u8, NAMES_CAP) };
    let entries: &mut [Entry] =
        unsafe { core::slice::from_raw_parts_mut(&raw mut ENTRIES as *mut Entry, ENTRIES_CAP) };

    let Some(mut full) = PathBuf::from(path) else {
        fail(out, path, 36); // ENAMETOOLONG
        close(fd);
        return false;
    };
    let base = full.len();

    let (mut used, mut count) = (0usize, 0usize);
    let mut truncated = false;
    let mut ok = true;
    let mut buf = [0u8; 2048];
    'read: loop {
        let n = match getdents(fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(errno) => {
                fail(out, path, errno);
                ok = false;
                break;
            }
        };
        for (name, dtype) in Dirents::new(&buf[..n]) {
            if !ctx.all && name.first() == Some(&b'.') {
                continue;
            }
            if count == ENTRIES_CAP || used + name.len() > NAMES_CAP {
                truncated = true;
                break 'read;
            }
            // A color kind for each name: directories and symlinks come free from `d_type`; a
            // regular file needs an `lstat` to see whether it's executable (only when coloring).
            let kind = if !ctx.color {
                PLAIN
            } else if dtype == oxlibc::fs::DT_DIR {
                DIR
            } else if dtype == oxlibc::fs::DT_LNK {
                SYMLINK
            } else if full.push(name) {
                let k = lstat(full.as_bytes())
                    .map(|st| kind_of(&st))
                    .unwrap_or(PLAIN);
                full.truncate(base);
                k
            } else {
                PLAIN
            };
            names[used..used + name.len()].copy_from_slice(name);
            entries[count] = (used as u32, name.len() as u16, kind);
            used += name.len();
            count += 1;
        }
    }
    close(fd);

    let name_of = |e: Entry| &names[e.0 as usize..e.0 as usize + e.1 as usize];
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

    if ctx.long {
        // Measuring pass: column widths and the `total` line (in 1K blocks, from 512-byte ones).
        let mut widths = Widths::default();
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
        let mut num = [0u8; 20];
        out.write(b"total ");
        out.write(fmt_u64(blocks / 2, &mut num));
        out.write(b"\n");

        for &e in &entries[..count] {
            let name = name_of(e);
            if !full.push(name) {
                fail(out, name, 36);
                ok = false;
                continue;
            }
            match lstat(full.as_bytes()) {
                Ok(st) => write_long_row(ctx, out, name, full.as_bytes(), &st, &widths),
                Err(errno) => {
                    fail(out, full.as_bytes(), errno);
                    ok = false;
                }
            }
            full.truncate(base);
        }
    } else if let Some(width) = ctx.columns {
        write_columns(ctx, out, names, &entries[..count], width);
    } else {
        for &e in &entries[..count] {
            emit_name(ctx, out, name_of(e), e.2);
            out.write(b"\n");
        }
    }

    if truncated {
        out.flush();
        eprint(b"ls: listing truncated (directory too large for the fixed buffer)\n");
        ok = false;
    }
    ok
}

/// `--color[=WHEN]`: `Some(true/false)` if given, `None` for "auto" (color only on a terminal).
fn color_choice(argv: &[&[u8]]) -> Option<bool> {
    let mut choice = None;
    for &arg in argv.iter().skip(1) {
        if arg == b"--" {
            break;
        }
        if arg == b"--color" || arg == b"--color=always" {
            choice = Some(true);
        } else if arg == b"--color=never" {
            choice = Some(false);
        } else if arg == b"--color=auto" {
            choice = None;
        }
    }
    choice
}

fn main(argv: &[&[u8]]) -> u64 {
    let long = has_flag(argv, b'l', None);
    let term = tty_size(STDOUT);
    let force_columns = has_flag(argv, b'C', None);
    let one_per_line = has_flag(argv, b'1', None);
    let mut ctx = Ctx {
        all: has_flag(argv, b'a', None),
        long,
        color: color_choice(argv).unwrap_or(term.is_some()),
        columns: if long || one_per_line {
            None
        } else if force_columns || term.is_some() {
            Some(match term {
                Some((_, cols)) if cols > 0 => cols as usize,
                _ => DEFAULT_COLUMNS,
            })
        } else {
            None
        },
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

    let mut out = BufWriter::new(STDOUT);
    let count = positional_args(argv).count();
    let mut status = 0;

    if count == 0 {
        return if list_dir(&ctx, &mut out, b".") { 0 } else { 1 };
    }
    let mut first = true;
    for path in positional_args(argv) {
        let st = match lstat(path) {
            Ok(st) => st,
            Err(errno) => {
                fail(&mut out, path, errno);
                status = 1;
                continue;
            }
        };
        if !st.is_dir() {
            if ctx.long {
                let mut w = Widths::default();
                measure(&ctx, &st, &mut w);
                write_long_row(&ctx, &mut out, path, path, &st, &w);
            } else {
                emit_name(&ctx, &mut out, path, kind_of(&st));
                out.write(b"\n");
            }
            first = false;
            continue;
        }
        if count > 1 {
            if !first {
                out.write(b"\n");
            }
            out.write(path);
            out.write(b":\n");
        }
        first = false;
        if !list_dir(&ctx, &mut out, path) {
            status = 1;
        }
    }
    status
}

oxlibc::entry_point!(main);
