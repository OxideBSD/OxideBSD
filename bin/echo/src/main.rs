//! `echo` -- a real, native OxideBSD `/bin` utility, not a BusyBox applet. Prints its arguments
//! separated by single spaces, followed by a newline unless a leading `-n` was given. Only exact
//! leading `-n` arguments are options (real `echo` semantics -- `echo -x` prints `-x`, so the
//! generic flag scanner in `oxlibc::args` is deliberately not used here). No backslash escapes.
#![no_std]
#![no_main]

use oxlibc::io::{STDOUT, print, write_all};

fn main(argv: &[&[u8]]) -> u64 {
    let mut args = argv.iter().skip(1).copied().peekable();
    let mut newline = true;
    while args.peek() == Some(&&b"-n"[..]) {
        newline = false;
        args.next();
    }
    let mut first = true;
    for arg in args {
        if !first {
            print(b" ");
        }
        if write_all(STDOUT, arg).is_err() {
            return 1;
        }
        first = false;
    }
    if newline {
        print(b"\n");
    }
    0
}

oxlibc::entry_point!(main);
