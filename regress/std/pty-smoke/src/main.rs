//! Pseudo-terminals (`OxideBSD-doc/PTY.md` §6.1), checked by `tests/pty_syscall_smoke.rs`, which
//! starts this as pid 1. Each check prints a line; the result goes to the kernel through
//! `SYS_TEST_EXIT`.

use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const SYS_TEST_EXIT: libc::c_long = 9999;
const TIOCPKT: libc::Ioctl = 0x5420;
const TIOCSIG: libc::Ioctl = 0x4004_5436;
const TIOCPKT_FLUSHREAD: u8 = 1;

unsafe extern "C" {
    fn posix_openpt(flags: libc::c_int) -> libc::c_int;
    fn unlockpt(fd: libc::c_int) -> libc::c_int;
    fn ptsname_r(fd: libc::c_int, buf: *mut libc::c_char, len: libc::size_t) -> libc::c_int;
    fn openpty(
        master: *mut libc::c_int,
        slave: *mut libc::c_int,
        name: *mut libc::c_char,
        termp: *const libc::termios,
        winp: *const libc::winsize,
    ) -> libc::c_int;
}

fn finish(pass: bool, why: &str) -> ! {
    println!("pty-smoke: {} {why}", if pass { "PASS" } else { "FAIL" });
    unsafe { libc::syscall(SYS_TEST_EXIT, if pass { 0 } else { 1 }) };
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn check(ok: bool, why: &str) {
    if !ok {
        finish(false, why);
    }
    println!("pty-smoke: ok: {why}");
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn pty() -> (i32, i32) {
    let (mut m, mut s) = (-1, -1);
    let r = unsafe { openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) };
    check(r == 0, "openpty");
    (m, s)
}

fn ptsname(m: i32) -> String {
    let mut buf = [0u8; 64];
    unsafe { ptsname_r(m, buf.as_mut_ptr().cast(), buf.len()) };
    CStr::from_bytes_until_nul(&buf).unwrap().to_string_lossy().into_owned()
}

fn write(fd: i32, bytes: &[u8]) -> isize {
    unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) }
}

/// Reads whatever arrives within a short while (the master doesn't block forever in the test).
fn read_some(fd: i32) -> Vec<u8> {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut pfd, 1, 2000) } <= 0 {
        return Vec::new();
    }
    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 { Vec::new() } else { buf[..n as usize].to_vec() }
}

fn wait_status(pid: i32) -> i32 {
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    status
}

static WINCH: AtomicBool = AtomicBool::new(false);
extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::Relaxed);
}

/// A child that makes `slave` its controlling terminal in a new session, then runs `f`.
fn session_child(master: i32, slave: i32, f: impl FnOnce()) -> i32 {
    match unsafe { libc::fork() } {
        0 => {
            unsafe {
                libc::close(master);
                libc::setsid();
                if libc::ioctl(slave, libc::TIOCSCTTY, 0) != 0 {
                    libc::_exit(90);
                }
            }
            f();
            unsafe { libc::_exit(0) };
        }
        pid => pid,
    }
}

fn main() {
    if std::process::id() != 1 {
        finish(false, "not started as pid 1");
    }

    // Names and the lock (§2, §3.1).
    let m = unsafe { posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    check(m >= 0, "posix_openpt");
    let name = ptsname(m);
    check(name == "/dev/pts/0", &format!("ptsname is /dev/pts/0 ({name})"));
    let cname = CString::new(name.clone()).unwrap();
    let early = unsafe { libc::open(cname.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    check(early == -1 && errno() == libc::EIO, "a locked slave can't be opened");
    check(unsafe { unlockpt(m) } == 0, "unlockpt");
    let s = unsafe { libc::open(cname.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    check(s >= 0, "the slave opens after unlockpt");
    let mut tn = [0u8; 64];
    unsafe { libc::ttyname_r(s, tn.as_mut_ptr().cast(), tn.len()) };
    check(CStr::from_bytes_until_nul(&tn).unwrap().to_bytes() == name.as_bytes(), "ttyname of the slave");
    check(unsafe { libc::isatty(m) } == 1, "isatty(master)");
    let mode = std::fs::metadata(&name).map(|md| std::os::unix::fs::PermissionsExt::mode(&md.permissions()) & 0o777).unwrap_or(0);
    check(mode == 0o600, &format!("the slave node is 0600 ({mode:o})"));

    // Data (§4): slave output with ONLCR, master input with echo and a canonical line.
    check(write(s, b"hello\n") == 6, "write the slave");
    check(read_some(m) == b"hello\r\n", "the master reads it, NL as CR NL");
    check(write(m, b"abc\n") == 4, "write the master");
    check(read_some(m) == b"abc\r\n", "the slave's echo comes back to the master");
    let mut buf = [0u8; 16];
    let n = unsafe { libc::read(s, buf.as_mut_ptr().cast(), buf.len()) };
    check(n == 4 && &buf[..4] == b"abc\n", "the slave reads the line");

    // Window size and SIGWINCH, then ^C as SIGINT, in a session on the slave (§5.1).
    let child = session_child(m, s, || unsafe {
        libc::signal(libc::SIGWINCH, on_winch as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::write(s, b"R".as_ptr().cast(), 1);
        while !WINCH.load(Ordering::Relaxed) {
            libc::pause();
        }
        let mut ws: libc::winsize = std::mem::zeroed();
        libc::ioctl(s, libc::TIOCGWINSZ, &mut ws);
        if ws.ws_row == 33 && ws.ws_col == 99 {
            libc::write(s, b"W".as_ptr().cast(), 1);
        }
        loop {
            libc::pause();
        }
    });
    check(read_some(m) == b"R", "a session on the slave is ready");
    let ws = libc::winsize { ws_row: 33, ws_col: 99, ws_xpixel: 0, ws_ypixel: 0 };
    check(unsafe { libc::ioctl(m, libc::TIOCSWINSZ, &ws) } == 0, "TIOCSWINSZ on the master");
    check(read_some(m) == b"W", "the slave sees the size, after SIGWINCH");
    check(write(m, b"\x03") == 1, "write ^C to the master");
    let st = wait_status(child);
    check(libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGINT, "^C killed the slave's process with SIGINT");
    let _ = read_some(m); // the echoed ^C

    // TIOCSIG (§5.2).
    let child = session_child(m, s, || unsafe {
        libc::write(s, b"R".as_ptr().cast(), 1);
        loop {
            libc::pause();
        }
    });
    check(read_some(m) == b"R", "a second session on the slave");
    check(unsafe { libc::ioctl(m, TIOCSIG, libc::SIGTERM) } == 0, "TIOCSIG SIGTERM");
    let st = wait_status(child);
    check(libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGTERM, "TIOCSIG delivered SIGTERM");

    // TIOCPKT (§5.3).
    let on: libc::c_int = 1;
    check(unsafe { libc::ioctl(m, TIOCPKT, &on) } == 0, "TIOCPKT on");
    check(unsafe { libc::tcflush(s, libc::TCIFLUSH) } == 0, "flush the slave's input");
    check(read_some(m) == [TIOCPKT_FLUSHREAD], "a TIOCPKT_FLUSHREAD status byte");
    check(write(s, b"x") == 1, "write the slave in packet mode");
    check(read_some(m) == [0, b'x'], "data comes after a zero byte");
    let off: libc::c_int = 0;
    unsafe { libc::ioctl(m, TIOCPKT, &off) };

    // Slave closed: the master reads end-of-file (§3.4).
    unsafe { libc::close(s) };
    let n = unsafe { libc::read(m, buf.as_mut_ptr().cast(), buf.len()) };
    check(n == 0, &format!("the master reads end-of-file once the slave is closed ({n})"));
    unsafe { libc::close(m) };
    check(std::fs::metadata("/dev/pts/0").is_err(), "the closed pair's node is gone");

    // The number is reused (§2.2); closing the master hangs up the slave's session (§3.3).
    let (m, s) = pty();
    check(ptsname(m) == "/dev/pts/0", "pts/0 is reused");
    let child = session_child(m, s, || unsafe {
        libc::write(s, b"R".as_ptr().cast(), 1);
        let mut b = [0u8; 1];
        libc::read(s, b.as_mut_ptr().cast(), 1);
        libc::_exit(3);
    });
    check(read_some(m) == b"R", "a session waits reading the slave");
    unsafe { libc::close(m) };
    let st = wait_status(child);
    check(libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGHUP, "closing the master sent SIGHUP");
    check(write(s, b"y") == -1 && errno() == libc::EIO, "the hung-up slave can't be written");
    unsafe { libc::close(s) };

    finish(true, "pseudo-terminals");
}
