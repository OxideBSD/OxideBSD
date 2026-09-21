//! `false` -- exits `1`, ignoring its arguments.
#![no_std]
#![no_main]

fn main(_argv: &[&[u8]]) -> u64 {
    1
}

oxlibc::entry_point!(main);
