//! `/sbin/emergency`: what the kernel runs as pid 1 when init has died three times within 30
//! seconds (INIT.md §9.4). It shows each recorded death (`/proc/initdeaths`) and offers two ways
//! out: a root shell to repair the system -- the kernel starts init again when this program
//! exits -- or restarting the computer.
//!
//! On an `insecure` console (ttys(5)), the shell needs root's password, as single-user mode does;
//! like FreeBSD's init, a root account with no password (or none readable) isn't asked for one.

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

// musl has crypt(3) in libc; a glibc host (for `cargo test`) keeps it in libcrypt.
#[cfg_attr(target_os = "linux", link(name = "crypt"))]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// One `/proc/initdeaths` line, made readable: `<epoch> exit <n>` or
/// `<epoch> signal <n> [ip <hex> [addr <hex>]]`.
fn describe(line: &str) -> String {
    let w: Vec<&str> = line.split_whitespace().collect();
    let when = w.first().and_then(|t| t.parse::<i64>().ok()).map_or_else(|| "?".into(), local_time);
    let what = match w.get(1..) {
        Some(["exit", n, ..]) => format!("exited with status {n}"),
        Some(["signal", n, rest @ ..]) => {
            let mut s = format!("killed by signal {n}{}", signal_name(n));
            for pair in rest.chunks(2) {
                if let [k, v] = pair {
                    s.push_str(&format!(", {} {v}", if *k == "addr" { "address" } else { k }));
                }
            }
            s
        }
        _ => line.to_string(),
    };
    format!("  {when}  {what}")
}

fn signal_name(n: &str) -> &'static str {
    match n.parse::<i32>().unwrap_or(0) {
        libc::SIGILL => " (SIGILL)",
        libc::SIGABRT => " (SIGABRT)",
        libc::SIGBUS => " (SIGBUS)",
        libc::SIGFPE => " (SIGFPE)",
        libc::SIGSEGV => " (SIGSEGV)",
        _ => "",
    }
}

fn local_time(t: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// Reads a line from the console, which has no line discipline: stops at CR or LF, handles
/// backspace. `None` at end of input.
fn read_line() -> Option<String> {
    let mut line = Vec::new();
    let mut stdin = std::io::stdin();
    let mut b = [0u8];
    loop {
        match stdin.read(&mut b) {
            Ok(0) | Err(_) => return (!line.is_empty()).then(|| String::from_utf8_lossy(&line).into_owned()),
            Ok(_) => match b[0] {
                b'\r' | b'\n' => return Some(String::from_utf8_lossy(&line).into_owned()),
                0x7f | 0x08 => {
                    line.pop();
                }
                c => line.push(c),
            },
        }
    }
}

/// Reads a line with echo off.
fn read_secret() -> Option<String> {
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have_tty = unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    if have_tty {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &quiet) };
    }
    let line = read_line();
    if have_tty {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
    }
    println!();
    line
}

/// Root's password hash; `None` if root has none, or it can't be read.
fn root_hash() -> Option<CString> {
    let sp = unsafe { libc::getspnam(c"root".as_ptr()) };
    if sp.is_null() {
        return None;
    }
    let hash = unsafe { CStr::from_ptr((*sp).sp_pwdp) };
    (!hash.is_empty()).then(|| hash.to_owned())
}

fn password_ok(hash: &CStr) -> bool {
    print!("Password: ");
    let _ = std::io::stdout().flush();
    let Some(input) = read_secret() else { return false };
    let Ok(key) = CString::new(input) else { return false };
    let out = unsafe { crypt(key.as_ptr(), hash.as_ptr()) };
    !out.is_null() && unsafe { CStr::from_ptr(out) } == hash
}

fn shell() {
    let env = [("PATH", "/sbin:/bin:/usr/sbin:/usr/bin"), ("HOME", "/"), ("TERM", "linux"), ("PS1", "emergency# ")];
    for sh in ["/bin/sh", "/bin/hush"] {
        match Command::new(sh).arg0("-sh").env_clear().envs(env).current_dir("/").status() {
            Ok(_) => return,
            Err(e) => eprintln!("emergency: {sh}: {e}"),
        }
    }
}

fn main() {
    let deaths = std::fs::read_to_string("/proc/initdeaths").unwrap_or_default();
    println!();
    println!("*** OxideBSD emergency mode ***");
    println!();
    println!("init keeps dying, so the kernel has stopped restarting it. Recorded deaths:");
    for line in deaths.lines() {
        println!("{}", describe(line));
    }
    if deaths.trim().is_empty() {
        println!("  (none recorded)");
    }
    println!();
    println!("Look for the failure's cause above, and in the kernel's messages on the console.");

    let hash = if ttyent::is_secure("console") { None } else { root_hash() };
    loop {
        println!();
        println!("  s  open a root shell to repair the system (init starts again when it exits)");
        println!("  r  restart the computer");
        print!("Choice [s/r]: ");
        let _ = std::io::stdout().flush();
        let Some(choice) = read_line() else { continue };
        println!();
        match choice.trim() {
            "s" | "S" => {
                if let Some(h) = &hash
                    && !password_ok(h)
                {
                    println!("Login incorrect");
                    continue;
                }
                shell();
                println!("emergency: starting init again");
                std::process::exit(0);
            }
            "r" | "R" => {
                println!("Restarting...");
                unsafe {
                    libc::sync();
                    libc::reboot(libc::RB_AUTOBOOT);
                }
                eprintln!("emergency: reboot: {}", std::io::Error::last_os_error());
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deaths_read_well() {
        assert!(describe("0 exit 3").ends_with("  exited with status 3"));
        assert!(describe("0 signal 11 ip 0x401000 addr 0x0").ends_with("killed by signal 11 (SIGSEGV), ip 0x401000, address 0x0"));
        assert!(describe("0 signal 9").ends_with("killed by signal 9"));
    }
}
