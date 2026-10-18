//! Account management: FreeBSD's `pw(8)` and the NetBSD/OpenBSD commands `useradd(8)`,
//! `userdel(8)`, `usermod(8)`, `groupadd(8)`, `groupdel(8)` and `groupmod(8)`, one program over
//! the same code. The name it is run as picks the interface.
//!
//! ```text
//! pw [-V etcdir] useradd|userdel|usermod|usershow|usernext|lock|unlock [name] [options]
//! pw [-V etcdir] groupadd|groupdel|groupmod|groupshow|groupnext [name] [options]
//! useradd [-mov] [-b base-dir] [-c comment] [-d home] [-e expiry] [-G group[,group]]
//!         [-g gid|name|=uid] [-k skel] [-L class] [-p password-hash] [-s shell] [-u uid] user
//! ```
//!
//! Every change is made under the account database's lock ([`db`]), checked by `libpwd` and `libgrp`, and
//! written as `pwd_mkdb -p` would. Defaults come from `/etc/usermgmt.conf` ([`conf`]); exit
//! statuses are sysexits(3)'s, as FreeBSD's pw.

mod args;
mod conf;
mod db;
mod group;
mod home;
mod pw;
mod user;
mod usermgmt;

use std::process::ExitCode;
use std::sync::OnceLock;

pub const EX_USAGE: u8 = 64;
pub const EX_DATAERR: u8 = 65;
pub const EX_NOUSER: u8 = 67;
pub const EX_SOFTWARE: u8 = 70;
pub const EX_OSERR: u8 = 71;
pub const EX_OSFILE: u8 = 72;
pub const EX_CANTCREAT: u8 = 73;
pub const EX_IOERR: u8 = 74;
pub const EX_TEMPFAIL: u8 = 75;
pub const EX_NOPERM: u8 = 77;

/// A failure: the exit status, and the message (or, for `EX_USAGE`, the usage line).
#[derive(Debug)]
pub struct Error {
    pub code: u8,
    pub msg: String,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn err<T>(code: u8, msg: impl Into<String>) -> Result<T> {
    Err(Error { code, msg: msg.into() })
}

static PROG: OnceLock<String> = OnceLock::new();
static QUIET: OnceLock<bool> = OnceLock::new();

/// The name messages are prefixed with: the command run (`pw`, `useradd`, ...).
pub fn prog() -> &'static str {
    PROG.get().map_or("pw", String::as_str)
}

/// Suppresses error messages (`pw -q`); the exit status still tells.
pub fn set_quiet() {
    let _ = QUIET.set(true);
}

pub fn warn(msg: &str) {
    if QUIET.get() != Some(&true) {
        eprintln!("{}: {msg}", prog());
    }
}

fn main() -> ExitCode {
    let mut argv = std::env::args();
    let arg0 = argv.next().unwrap_or_default();
    let mut name = arg0.rsplit('/').next().unwrap_or("pw");
    let args: Vec<String> = argv.collect();
    let run: fn(&[String]) -> Result<()> = match name {
        "useradd" => usermgmt::useradd,
        "userdel" => usermgmt::userdel,
        "usermod" => usermgmt::usermod,
        "groupadd" => usermgmt::groupadd,
        "groupdel" => usermgmt::groupdel,
        "groupmod" => usermgmt::groupmod,
        _ => {
            name = "pw";
            pw::main
        }
    };
    let _ = PROG.set(name.to_string());
    let r = run(&args);
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if e.code == EX_USAGE {
                if QUIET.get() != Some(&true) {
                    eprintln!("{}", e.msg);
                }
            } else {
                warn(&e.msg);
            }
            ExitCode::from(e.code)
        }
    }
}
