//! `login(1)`: authenticates a user through PAM and starts their session (LOGIN.md §5 in
//! OxideBSD-doc).
//!
//! ```text
//! login [-fp] [-h host] [user]
//! ```
//!
//! `getty(8)` runs it as `login -p <name>`. `-f` skips authentication (root only), `-p` keeps
//! the environment, `-h` names the remote host. login stays as the shell's parent, so that it can
//! close the PAM session and record the logout when the shell exits.

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;

use logincap::Class;

const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin";
const MOTD: &str = "/etc/motd";

fn say(s: &str) {
    let mut o = std::io::stdout();
    let _ = o.write_all(s.as_bytes());
    let _ = o.flush();
}

fn die(msg: &str) -> ! {
    eprintln!("login: {msg}");
    std::process::exit(1);
}

/// This terminal's name under `/dev` (`ttyv0`), for PAM, utmpx and ownership.
fn tty_name() -> Option<String> {
    let mut buf = [0 as libc::c_char; 64];
    // SAFETY: ttyname_r into a local buffer.
    if unsafe { libc::ttyname_r(0, buf.as_mut_ptr(), buf.len()) } != 0 {
        return None;
    }
    let path = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned();
    Some(path.strip_prefix("/dev/").unwrap_or(&path).to_string())
}

fn read_line(prompt: &str) -> Option<String> {
    say(prompt);
    let mut line = Vec::new();
    let mut b = [0u8];
    loop {
        match std::io::stdin().read(&mut b) {
            Ok(0) => return None,
            Ok(_) if b[0] == b'\n' => return Some(String::from_utf8_lossy(&line).trim().to_string()),
            Ok(_) => line.push(b[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

struct Args {
    force: bool,
    preserve: bool,
    host: Option<String>,
    user: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args { force: false, preserve: false, host: None, user: None };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-f" => a.force = true,
            "-p" => a.preserve = true,
            "-h" => a.host = args.next(),
            "--" => {
                a.user = args.next();
                break;
            }
            s if s.starts_with('-') => die("usage: login [-fp] [-h host] [user]"),
            s => {
                a.user = Some(s.to_string());
                break;
            }
        }
    }
    a
}

/// A PAM handle for one attempt.
struct Pam(*mut pam::PamHandle);

static CONV: pam::PamConv = pam::PamConv { conv: Some(pam::openpam_ttyconv), appdata_ptr: std::ptr::null_mut() };

impl Pam {
    fn start(user: &str, tty: &str, host: Option<&str>) -> Pam {
        let user = CString::new(user).unwrap_or_default();
        let mut h = std::ptr::null_mut();
        // SAFETY: CONV lives for the program; OpenPAM copies the strings.
        let r = unsafe { pam::pam_start(c"login".as_ptr(), user.as_ptr(), &CONV, &mut h) };
        if r != pam::PAM_SUCCESS {
            die(&format!("pam_start: {}", pam::strerror(h, r)));
        }
        let tty = CString::new(tty).unwrap_or_default();
        unsafe { pam::pam_set_item(h, pam::PAM_TTY, tty.as_ptr().cast()) };
        if let Some(host) = host.and_then(|h| CString::new(h).ok()) {
            unsafe { pam::pam_set_item(h, pam::PAM_RHOST, host.as_ptr().cast()) };
        }
        Pam(h)
    }

    fn end(self, status: libc::c_int) {
        // SAFETY: the handle from pam_start.
        unsafe { pam::pam_end(self.0, status) };
    }

    /// Environment variables the modules set.
    fn env(&self) -> Vec<(String, String)> {
        // SAFETY: pam_getenvlist returns a malloc'd NULL-terminated array.
        let list = unsafe { pam::pam_getenvlist(self.0) };
        let mut out = Vec::new();
        if list.is_null() {
            return out;
        }
        let mut i = 0;
        loop {
            let p = unsafe { *list.add(i) };
            if p.is_null() {
                break;
            }
            if let Some((k, v)) = unsafe { CStr::from_ptr(p) }.to_string_lossy().split_once('=') {
                out.push((k.to_string(), v.to_string()));
            }
            unsafe { libc::free(p.cast()) };
            i += 1;
        }
        unsafe { libc::free(list.cast()) };
        out
    }
}

unsafe extern "C" {
    /// Appends a record to a wtmpx file (musl, `_BSD_SOURCE`); the libc crate doesn't bind it.
    fn updwtmpx(file: *const libc::c_char, ut: *const libc::utmpx);
}

/// A session record in `/var/run/utmpx` and `/var/log/wtmpx` (LOGIN.md §8).
// The libc crate marks musl's utmpx functions deprecated because stock musl stubs them;
// OxideBSD's musl implements them.
#[allow(deprecated)]
fn record(kind: libc::c_short, user: &str, tty: &str, host: Option<&str>) {
    // SAFETY: a zeroed utmpx filled in field by field, then pututxline.
    let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
    ut.ut_type = kind;
    ut.ut_pid = std::process::id() as libc::pid_t;
    let copy = |dst: &mut [libc::c_char], s: &str| {
        let room = dst.len() - 1;
        for (d, b) in dst.iter_mut().zip(s.bytes().take(room)) {
            *d = b as libc::c_char;
        }
    };
    copy(&mut ut.ut_line, tty);
    copy(&mut ut.ut_id, tty.trim_start_matches("tty"));
    if kind == libc::USER_PROCESS {
        copy(&mut ut.ut_user, user);
        copy(&mut ut.ut_host, host.unwrap_or(""));
    }
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    ut.ut_tv.tv_sec = tv.tv_sec as _;
    ut.ut_tv.tv_usec = tv.tv_usec as _;
    unsafe {
        libc::setutxent();
        libc::pututxline(&ut);
        libc::endutxent();
        updwtmpx(c"/var/log/wtmpx".as_ptr(), &ut);
    }
}

/// The `tty` group, if there is one.
fn tty_gid() -> Option<libc::gid_t> {
    // SAFETY: getgrnam returns a static entry or NULL.
    let g = unsafe { libc::getgrnam(c"tty".as_ptr()) };
    (!g.is_null()).then(|| unsafe { (*g).gr_gid })
}

fn chown_tty(tty: &str, uid: u32, gid: u32, mode: libc::mode_t) {
    let Ok(path) = CString::new(format!("/dev/{tty}")) else { return };
    // SAFETY: chown/chmod on the terminal's device node.
    unsafe {
        libc::chown(path.as_ptr(), uid, gid);
        libc::chmod(path.as_ptr(), mode);
    }
}

fn main() {
    pam::link();
    let args = parse_args();
    // SAFETY: getuid(2).
    if unsafe { libc::getuid() } != 0 {
        die("must be run by root");
    }
    let tty = tty_name().unwrap_or_else(|| "console".into());

    let default_class = Class::load("default");
    let timeout = default_class.number("login-timeout", 300);
    // SAFETY: alarm(2): an unfinished login ends, and init starts a new getty.
    unsafe { libc::alarm(timeout as u32) };
    let retries = default_class.number("login-retries", 10);
    let backoff = default_class.number("login-backoff", 3);

    let mut user = args.user.clone();
    let mut failures = 0u64;
    let (pam, name) = loop {
        let name = match user.take() {
            Some(u) if !u.is_empty() => u,
            _ => match read_line("login: ") {
                Some(u) if !u.is_empty() => u,
                Some(_) => continue,
                None => std::process::exit(0),
            },
        };
        let pam = Pam::start(&name, &tty, args.host.as_deref());
        // -f: already authenticated by the caller (getty's autologin, or root).
        let r = if args.force { pam::PAM_SUCCESS } else { unsafe { pam::pam_authenticate(pam.0, 0) } };
        if r == pam::PAM_SUCCESS {
            break (pam, name);
        }
        pam.end(r);
        failures += 1;
        say("Login incorrect\n");
        if failures > backoff {
            if failures >= retries {
                std::process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_secs((failures - backoff) * 5));
        }
    };

    // SAFETY: the handle from a successful pam_start.
    let r = unsafe { pam::pam_acct_mgmt(pam.0, 0) };
    if r == pam::PAM_NEW_AUTHTOK_REQD {
        let r = unsafe { pam::pam_chauthtok(pam.0, pam::PAM_CHANGE_EXPIRED_AUTHTOK) };
        if r != pam::PAM_SUCCESS {
            say(&format!("{}\n", pam::strerror(pam.0, r)));
            pam.end(r);
            std::process::exit(1);
        }
    } else if r != pam::PAM_SUCCESS {
        say("Login incorrect\n");
        pam.end(r);
        std::process::exit(1);
    }
    let Some(entry) = pwd::lookup(&name) else {
        pam.end(pam::PAM_USER_UNKNOWN);
        die("no such user");
    };
    let class = Class::load(if entry.uid == 0 && entry.class.is_empty() { "root" } else { entry.login_class() });
    unsafe { libc::alarm(0) };

    // A class that refuses logins (`nologin=file`) shows why.
    if entry.uid != 0
        && let Some(file) = class.string("nologin")
        && let Ok(text) = std::fs::read_to_string(file)
    {
        say(&text);
        pam.end(pam::PAM_PERM_DENIED);
        std::process::exit(1);
    }
    let home_ok = std::path::Path::new(&entry.home).is_dir();
    if !home_ok && class.flag("requirehome") {
        say("Home directory not available\n");
        pam.end(pam::PAM_PERM_DENIED);
        std::process::exit(1);
    }

    chown_tty(&tty, entry.uid, tty_gid().unwrap_or(entry.gid), 0o620);
    record(libc::USER_PROCESS, &name, &tty, args.host.as_deref());
    unsafe {
        pam::pam_setcred(pam.0, pam::PAM_ESTABLISH_CRED);
        pam::pam_open_session(pam.0, 0);
    }
    let pam_env = pam.env();

    let shell = class.string("shell").map(String::from).unwrap_or_else(|| {
        if entry.shell.is_empty() { "/bin/sh".into() } else { entry.shell.clone() }
    });
    // SAFETY: fork(2); the child becomes the user's shell.
    let child = unsafe { libc::fork() };
    if child < 0 {
        die(&format!("fork: {}", std::io::Error::last_os_error()));
    }
    if child == 0 {
        // The class's limits, priority and umask, then groups and user (LOGIN.md §7.2).
        if logincap::setusercontext(&class, &name, entry.uid, entry.gid, logincap::LOGIN_SETALL).is_err() {
            die("can't set user id");
        }
        let dir = if home_ok { entry.home.as_str() } else { "/" };
        if !home_ok {
            say("No home directory.\nLogging in with home = \"/\".\n");
        }
        let term = std::env::var("TERM").unwrap_or_else(|_| "unknown".into());
        let mut cmd = std::process::Command::new(&shell);
        if !args.preserve {
            cmd.env_clear();
        }
        let path = class.path(dir).unwrap_or_else(|| DEFAULT_PATH.into());
        cmd.env("HOME", dir)
            .env("SHELL", &shell)
            .env("USER", &name)
            .env("LOGNAME", &name)
            .env("PATH", path)
            .env("TERM", term)
            .env("MAIL", format!("/var/mail/{name}"));
        cmd.envs(class.environment(&name, dir));
        cmd.envs(pam_env);
        let hush = class.flag("hushlogin") || std::path::Path::new(dir).join(".hushlogin").exists();
        if !hush && let Ok(motd) = std::fs::read_to_string(class.string("welcome").unwrap_or(MOTD)) {
            say(&motd);
        }
        let base = shell.rsplit('/').next().unwrap_or(&shell);
        let err = cmd.current_dir(dir).arg0(format!("-{base}")).exec();
        die(&format!("{shell}: {err}"));
    }

    // The parent waits for the shell, then ends the session (§5.5). The shell's job control
    // stops and continues its jobs, not login.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
        libc::signal(libc::SIGTSTP, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
    }
    let mut status = 0;
    while unsafe { libc::waitpid(child, &mut status, 0) } < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {}
    unsafe {
        pam::pam_close_session(pam.0, 0);
        pam::pam_setcred(pam.0, pam::PAM_DELETE_CRED);
    }
    pam.end(pam::PAM_SUCCESS);
    record(libc::DEAD_PROCESS, &name, &tty, None);
    chown_tty(&tty, 0, 0, 0o600);
}
