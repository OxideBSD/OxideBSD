//! `start_init`: what the kernel runs as pid 1 when the command line names init's program with
//! `init_path=` (a colon-separated list, FreeBSD's) or `init=` (one path) (INIT.md §4.1). Embedded
//! in the kernel and never installed; without either option the kernel runs its embedded
//! `/sbin/init` directly and this program isn't used.
//!
//! The kernel can only start a process from an image in memory, so this does what FreeBSD's
//! `start_init()` does inside process 1: execs each path in turn, keeping pid 1, until one runs.
//! `start_init <paths> [flags...]`: each program gets the flags (`-s` from the boot flags; `-R`
//! when the kernel restarts init after a death, given only to `/sbin/init`, INIT.md §9.3). When
//! none can be run, `/bin/sh` is tried on the console; if that fails too, this exits, and the
//! kernel's supervision of pid 1 (§9) restarts it and in the end runs `/sbin/emergency`.

use std::ffi::CString;

fn exec(path: &str, args: &[&str]) -> std::io::Error {
    let Ok(cpath) = CString::new(path) else { return std::io::ErrorKind::InvalidInput.into() };
    let argv: Vec<CString> = args.iter().filter_map(|a| CString::new(*a).ok()).collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    // The kernel's environment for pid 1, passed on; /sbin/init builds its own (INIT.md §4.2).
    let env: Vec<CString> = std::env::vars().filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok()).collect();
    let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    // SAFETY: NUL-terminated strings in NULL-terminated arrays, alive across the call.
    unsafe { libc::execve(cpath.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr()) };
    std::io::Error::last_os_error()
}

/// Makes the console the controlling terminal and standard input, output and error, for the
/// shell of last resort.
fn take_console() {
    // SAFETY: plain system calls on a descriptor this process owns.
    unsafe {
        let fd = libc::open(c"/dev/console".as_ptr(), libc::O_RDWR);
        if fd >= 0 {
            libc::ioctl(fd, libc::TIOCSCTTY, 0);
            for target in 0..3 {
                libc::dup2(fd, target);
            }
            if fd > 2 {
                libc::close(fd);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = args.first().cloned().unwrap_or_default();
    let flags: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    for path in paths.split(':').filter(|p| !p.is_empty()) {
        let mut argv = vec![path];
        argv.extend(flags.iter().copied().filter(|&f| f != "-R" || path == "/sbin/init"));
        let err = exec(path, &argv);
        eprintln!("start_init: {path}: {err}");
    }
    eprintln!("start_init: no init could be started; trying /bin/sh");
    take_console();
    let err = exec("/bin/sh", &["-sh"]);
    eprintln!("start_init: /bin/sh: {err}");
    std::process::exit(1);
}
