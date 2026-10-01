//! `nologin(8)`: the login shell of an account that must not log in. It shows why (the text of
//! `/etc/nologin.txt`, as OpenBSD, or a fixed message), logs the attempt at `auth.crit`, as
//! FreeBSD, and fails. Whatever arguments it's given (`-c command` from `su`, say) are ignored.

use std::ffi::CString;
use std::io::Write;

const MESSAGE_FILE: &str = "/etc/nologin.txt";
const MESSAGE: &str = "This account is currently not available.\n";

fn main() {
    let text = std::fs::read_to_string(MESSAGE_FILE).unwrap_or_else(|_| MESSAGE.into());
    let _ = std::io::stdout().write_all(text.as_bytes());

    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid {}", unsafe { libc::getuid() }));
    let tty = std::fs::read_link("/proc/self/fd/0")
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "an unknown terminal".into());
    let msg = CString::new(format!("Attempted login by {user} on {tty}").replace('\0', "")).unwrap_or_default();
    // SAFETY: a static identity, a constant format and a NUL-terminated argument.
    unsafe {
        libc::openlog(c"nologin".as_ptr(), libc::LOG_CONS, libc::LOG_AUTH);
        libc::syslog(libc::LOG_CRIT, c"%s".as_ptr(), msg.as_ptr());
    }
    std::process::exit(1);
}
