//! `pwd` -- prints the current working directory (`SYS_GETCWD`).
#![no_std]
#![no_main]

use oxlibc::fs::getcwd;
use oxlibc::io::{eprint_errno, print};
use oxlibc::path::MAX_PATH;

fn main(_argv: &[&[u8]]) -> u64 {
    let mut buf = [0u8; MAX_PATH];
    match getcwd(&mut buf) {
        Ok(len) => {
            print(&buf[..len]);
            print(b"\n");
            0
        }
        Err(errno) => {
            eprint_errno(b"pwd", b"getcwd", errno);
            1
        }
    }
}

oxlibc::entry_point!(main);
