//! `update(8)`: puts the file system's delayed writes on the disk every 30 seconds
//! (OxideBSD-doc `RAM_FLOOR.md` §3.3.6), as 4.3BSD's `update` did; FreeBSD's syncer kernel
//! process does the same job.
//!
//! ```text
//! update [-i seconds]
//! ```
//!
//! Detaches into the background, records its pid in `/var/run/update.pid` for rc(8), and calls
//! `sync(2)` every `seconds` (30 by default) until killed.

use std::process::ExitCode;
use std::time::Duration;

const PIDFILE: &str = "/var/run/update.pid";

fn usage() -> ExitCode {
    eprintln!("usage: update [-i seconds]");
    ExitCode::from(1)
}

/// Into the background: a session of its own, `/` as its directory, standard descriptors on
/// `/dev/null`.
fn daemonize() {
    // SAFETY: single-threaded here, so fork is safe; the parent only exits.
    unsafe {
        match libc::fork() {
            -1 => {
                eprintln!("update: fork: {}", std::io::Error::last_os_error());
                std::process::exit(1);
            }
            0 => {}
            _ => libc::_exit(0),
        }
        libc::setsid();
        libc::chdir(c"/".as_ptr());
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..3 {
                libc::dup2(null, fd);
            }
            if null > 2 {
                libc::close(null);
            }
        }
    }
}

fn main() -> ExitCode {
    let mut interval = 30u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-i" => match args.next().and_then(|s| s.parse().ok()).filter(|&n| n > 0) {
                Some(n) => interval = n,
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    daemonize();
    // Not fatal if it can't be written: only rc(8)'s stop needs it.
    let _ = std::fs::write(PIDFILE, format!("{}\n", std::process::id()));
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        // SAFETY: sync takes no arguments.
        unsafe { libc::sync() };
    }
}
