//! `true` -- exits `0`, ignoring its arguments.
#![no_std]
#![no_main]

fn main(_argv: &[&[u8]]) -> u64 {
    0
}

oxlibc::entry_point!(main);
