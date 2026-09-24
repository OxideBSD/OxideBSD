//! Thin wrappers over the POSIX calls a shell needs and `std` doesn't expose (a shell forks
//! *itself* for subshells and pipelines). All output goes through `write(2)` directly, never
//! Rust's buffered stdout: a child forked with unflushed buffered output would print it twice.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;

pub type Fd = i32;

fn check(r: i32) -> io::Result<i32> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

pub fn cstr(s: &str) -> CString {
    CString::new(s.as_bytes()).unwrap_or_else(|_| CString::new(s.replace('\0', "")).unwrap())
}

pub fn write_all(fd: Fd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

/// Reads one byte; `Ok(None)` at end of file.
pub fn read_byte(fd: Fd) -> io::Result<Option<u8>> {
    let mut b = 0u8;
    loop {
        let n = unsafe { libc::read(fd, (&mut b as *mut u8).cast(), 1) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(if n == 0 { None } else { Some(b) });
    }
}

pub fn read_to_end(fd: Fd) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
}

pub fn fork() -> io::Result<libc::pid_t> {
    check(unsafe { libc::fork() })
}

pub fn pipe() -> io::Result<(Fd, Fd)> {
    let mut fds = [0; 2];
    check(unsafe { libc::pipe(fds.as_mut_ptr()) })?;
    Ok((fds[0], fds[1]))
}

pub fn dup2(from: Fd, to: Fd) -> io::Result<()> {
    if from != to {
        check(unsafe { libc::dup2(from, to) })?;
    }
    Ok(())
}

/// Duplicates `fd` to a descriptor >= 10, close-on-exec (for saving a descriptor a redirection
/// is about to replace).
pub fn dup_high(fd: Fd) -> io::Result<Fd> {
    check(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) })
}

pub fn close(fd: Fd) {
    unsafe {
        libc::close(fd);
    }
}

pub fn is_open(fd: Fd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

pub fn open(path: &str, flags: i32, mode: u32) -> io::Result<Fd> {
    let p = cstr(path);
    check(unsafe { libc::open(p.as_ptr(), flags, mode as libc::c_uint) })
}

/// Waits for `pid`; returns its shell status (exit code, or 128 + signal).
pub fn wait_pid(pid: libc::pid_t) -> io::Result<i32> {
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        return Ok(decode_status(status));
    }
}

pub fn decode_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        status
    }
}

/// Ends a forked child immediately, without running the parent's destructors or atexit handlers.
pub fn exit_child(status: i32) -> ! {
    unsafe { libc::_exit(status & 0xff) }
}

pub fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

pub fn getppid() -> i32 {
    unsafe { libc::getppid() }
}

/// `execve` with an argv/envp built from Rust strings. Returns only on failure.
pub fn execve(path: &str, argv: &[String], envp: &[String]) -> io::Error {
    let path_c = cstr(path);
    let argv_c: Vec<CString> = argv.iter().map(|a| cstr(a)).collect();
    let envp_c: Vec<CString> = envp.iter().map(|e| cstr(e)).collect();
    let mut argv_p: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut envp_p: Vec<*const libc::c_char> = envp_c.iter().map(|c| c.as_ptr()).collect();
    envp_p.push(std::ptr::null());
    unsafe {
        libc::execve(path_c.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
    }
    io::Error::last_os_error()
}

pub fn is_executable_file(path: &str) -> bool {
    let p = cstr(path);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(p.as_ptr(), &mut st) } != 0 {
        return false;
    }
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG && unsafe { libc::access(p.as_ptr(), libc::X_OK) } == 0
}

pub fn home_of(user: &str) -> Option<String> {
    let u = cstr(user);
    let pw = unsafe { libc::getpwnam(u.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    Some(OsStr::from_bytes(dir.to_bytes()).to_string_lossy().into_owned())
}

pub fn umask(mask: u32) -> u32 {
    unsafe { libc::umask(mask as libc::mode_t) as u32 }
}

pub fn kill(pid: i32, sig: i32) -> io::Result<()> {
    check(unsafe { libc::kill(pid, sig) }).map(|_| ())
}

/// Signal names, as `kill -l` and `trap` use them (no `SIG` prefix).
pub const SIGNALS: &[(&str, i32)] = &[
    ("HUP", libc::SIGHUP),
    ("INT", libc::SIGINT),
    ("QUIT", libc::SIGQUIT),
    ("ILL", libc::SIGILL),
    ("TRAP", libc::SIGTRAP),
    ("ABRT", libc::SIGABRT),
    ("BUS", libc::SIGBUS),
    ("FPE", libc::SIGFPE),
    ("KILL", libc::SIGKILL),
    ("USR1", libc::SIGUSR1),
    ("SEGV", libc::SIGSEGV),
    ("USR2", libc::SIGUSR2),
    ("PIPE", libc::SIGPIPE),
    ("ALRM", libc::SIGALRM),
    ("TERM", libc::SIGTERM),
    ("CHLD", libc::SIGCHLD),
    ("CONT", libc::SIGCONT),
    ("STOP", libc::SIGSTOP),
    ("TSTP", libc::SIGTSTP),
    ("TTIN", libc::SIGTTIN),
    ("TTOU", libc::SIGTTOU),
];

pub fn signal_number(name: &str) -> Option<i32> {
    if let Ok(n) = name.parse::<i32>() {
        return Some(n);
    }
    let name = name.strip_prefix("SIG").unwrap_or(name);
    SIGNALS.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|&(_, v)| v)
}

pub fn signal_name(num: i32) -> Option<&'static str> {
    SIGNALS.iter().find(|&&(_, v)| v == num).map(|&(n, _)| n)
}

/// The bare C library message for an error ("No such file or directory"), without Rust's
/// " (os error N)" suffix.
pub fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

// --- Terminals and process groups (interactive mode, job control) -----------------------------

pub fn isatty(fd: Fd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

pub fn tcgetattr(fd: Fd) -> io::Result<libc::termios> {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    check(unsafe { libc::tcgetattr(fd, &mut t) })?;
    Ok(t)
}

pub fn tcsetattr(fd: Fd, t: &libc::termios) -> io::Result<()> {
    check(unsafe { libc::tcsetattr(fd, libc::TCSADRAIN, t) }).map(|_| ())
}

/// Gives the terminal on `fd` to process group `pgid`.
pub fn tcsetpgrp(fd: Fd, pgid: libc::pid_t) -> io::Result<()> {
    check(unsafe { libc::tcsetpgrp(fd, pgid) }).map(|_| ())
}

pub fn tcgetpgrp(fd: Fd) -> libc::pid_t {
    unsafe { libc::tcgetpgrp(fd) }
}

pub fn setpgid(pid: libc::pid_t, pgid: libc::pid_t) -> io::Result<()> {
    check(unsafe { libc::setpgid(pid, pgid) }).map(|_| ())
}

pub fn getpgrp() -> libc::pid_t {
    unsafe { libc::getpgrp() }
}

/// What `waitpid` reported for one child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildState {
    /// Exited or killed: the shell status (exit code, or 128 + signal).
    Done(i32),
    /// Stopped by this signal.
    Stopped(i32),
    /// Resumed by SIGCONT.
    Continued,
}

/// `waitpid` with `WUNTRACED`, plus `WNOHANG`/`WCONTINUED` if asked. `Ok(None)`: nothing to report
/// (only with `nohang`).
pub fn wait_any(pid: libc::pid_t, nohang: bool) -> io::Result<Option<(libc::pid_t, ChildState)>> {
    let mut status = 0;
    let flags = libc::WUNTRACED | if nohang { libc::WNOHANG | libc::WCONTINUED } else { 0 };
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, flags) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if r == 0 {
            return Ok(None);
        }
        let state = if libc::WIFSTOPPED(status) {
            ChildState::Stopped(libc::WSTOPSIG(status))
        } else if libc::WIFCONTINUED(status) {
            ChildState::Continued
        } else {
            ChildState::Done(decode_status(status))
        };
        return Ok(Some((r, state)));
    }
}

/// The terminal's width in columns, if `fd` is one.
pub fn term_columns(fd: Fd) -> Option<usize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 { Some(ws.ws_col as usize) } else { None }
}

pub fn geteuid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn user_name(uid: u32) -> Option<String> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    Some(name.to_string_lossy().into_owned())
}

pub fn hostname() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(u.nodename.as_ptr()) }.to_string_lossy().into_owned()
}

/// Sets a signal's disposition (`SIG_DFL`/`SIG_IGN`/a handler).
pub fn set_signal(sig: i32, handler: libc::sighandler_t) {
    unsafe {
        libc::signal(sig, handler);
    }
}
