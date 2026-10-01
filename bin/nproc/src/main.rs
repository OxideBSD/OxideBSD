//! `nproc(1)`: the number of processors available, or with `--all` installed, less
//! `--ignore=count` (never below 1), as FreeBSD's.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut all = false;
    let mut ignore: u64 = 0;
    for arg in std::env::args().skip(1) {
        if arg == "--all" {
            all = true;
        } else if let Some(n) = arg.strip_prefix("--ignore=").and_then(|n| n.parse().ok()) {
            ignore = n;
        } else {
            eprintln!("usage: nproc [--all] [--ignore=count]");
            return ExitCode::from(1);
        }
    }
    let name = if all {
        libc::_SC_NPROCESSORS_CONF
    } else {
        libc::_SC_NPROCESSORS_ONLN
    };
    // SAFETY: sysconf(3) takes no pointers.
    let n = unsafe { libc::sysconf(name) }.max(1) as u64;
    println!("{}", n.saturating_sub(ignore).max(1));
    ExitCode::SUCCESS
}
