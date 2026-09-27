//! `getty(8)`: sets up a terminal and reads a login name (LOGIN.md §4 in OxideBSD-doc).
//!
//! `init` runs `getty [type] [tty]` for each terminal in `/etc/ttys`. getty opens `/dev/<tty>` as
//! a new session's controlling terminal, configures it from the `gettytab(5)` record `<type>`
//! (default `default`), prints the banner, reads a name and runs `login(1)`.

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;

const GETTYTAB: &str = "/etc/gettytab";
const DEFAULT_IM: &str = "\r\n\r\n%s/%m (%h) (%t)\r\n\r\n";
const DEFAULT_LM: &str = "login: ";
const DEFAULT_LO: &str = "/usr/bin/login";

fn uname() -> [String; 4] {
    // SAFETY: uname into a local.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut u) };
    let s = |f: &[libc::c_char]| {
        let b: Vec<u8> = f.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&b).into_owned()
    };
    [s(&u.sysname), s(&u.nodename), s(&u.release), s(&u.machine)]
}

fn date() -> String {
    // SAFETY: time + localtime_r into locals.
    let t = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    const DAYS: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    const MONTHS: [&str; 12] =
        ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    format!(
        "{}, {} {} {} {:02}:{:02}",
        DAYS[tm.tm_wday as usize % 7],
        MONTHS[tm.tm_mon as usize % 12],
        tm.tm_mday,
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min
    )
}

/// The BSDs' `%` escapes in `im`, `if` and `lm`.
fn expand(text: &str, tty: &str) -> String {
    let [sysname, host, release, machine] = uname();
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push_str(tty),
            Some('h') => out.push_str(&host),
            Some('s') => out.push_str(&sysname),
            Some('m') => out.push_str(&machine),
            Some('r') => out.push_str(&release),
            Some('v') => out.push_str(&release),
            Some('d') => out.push_str(&date()),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

fn baud(speed: i64) -> Option<libc::speed_t> {
    Some(match speed {
        300 => libc::B300,
        1200 => libc::B1200,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19200 => libc::B19200,
        38400 => libc::B38400,
        57600 => libc::B57600,
        115200 => libc::B115200,
        _ => return None,
    })
}

/// Configures the terminal from the record: speed, character size and parity, control
/// characters, echo style and tabs.
fn configure(e: &getcap::Entry) {
    // SAFETY: tcgetattr/tcsetattr on fd 0 with a local struct.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
        return;
    }
    if let Some(b) = e.num("sp").and_then(baud) {
        unsafe { libc::cfsetspeed(&mut t, b) };
    }
    t.c_cflag &= !(libc::CSIZE | libc::PARENB | libc::PARODD);
    if e.flag("ep") && !e.flag("op") {
        t.c_cflag |= libc::CS7 | libc::PARENB;
    } else if e.flag("op") && !e.flag("ep") {
        t.c_cflag |= libc::CS7 | libc::PARENB | libc::PARODD;
    } else if e.flag("ep") && e.flag("op") || e.flag("ap") {
        t.c_cflag |= libc::CS7;
    } else {
        t.c_cflag |= libc::CS8;
    }
    t.c_cflag |= libc::CREAD | if e.flag("hc") { 0 } else { libc::HUPCL };
    t.c_iflag = libc::ICRNL | libc::IXON | libc::IXANY | libc::IMAXBEL | libc::BRKINT;
    t.c_oflag = libc::OPOST | libc::ONLCR;
    if !e.flag("ht") {
        // The libc crate types TAB3 as c_int for musl, not tcflag_t.
        t.c_oflag |= libc::TAB3 as libc::tcflag_t;
    }
    t.c_lflag = libc::ICANON | libc::ISIG | libc::IEXTEN | libc::ECHO | libc::ECHOCTL;
    // `ce`/`ck`: a CRT, where erase and kill wipe what they remove.
    if e.flag("ce") {
        t.c_lflag |= libc::ECHOE;
    }
    if e.flag("ck") {
        t.c_lflag |= libc::ECHOKE;
    }
    for (cap, idx) in [
        ("er", libc::VERASE),
        ("kl", libc::VKILL),
        ("et", libc::VEOF),
        ("in", libc::VINTR),
        ("qu", libc::VQUIT),
        ("su", libc::VSUSP),
        ("rp", libc::VREPRINT),
        ("we", libc::VWERASE),
        ("ln", libc::VLNEXT),
        ("st", libc::VSTOP),
        ("sa", libc::VSTART),
    ] {
        if let Some(s) = e.string(cap)
            && let Some(&b) = s.as_bytes().first()
        {
            t.c_cc[idx] = b;
        }
    }
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
}

/// Opens `/dev/<tty>` as a new session's controlling terminal, and as descriptors 0, 1 and 2.
fn take_terminal(tty: &str) -> std::io::Result<()> {
    let path = CString::new(format!("/dev/{tty}")).unwrap();
    // SAFETY: plain system calls.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::setsid();
        if libc::ioctl(fd, libc::TIOCSCTTY, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for target in 0..3 {
            libc::dup2(fd, target);
        }
        if fd > 2 {
            libc::close(fd);
        }
    }
    Ok(())
}

fn out(s: &str) {
    let mut o = std::io::stdout();
    let _ = o.write_all(s.as_bytes());
    let _ = o.flush();
}

/// Reads a login name. `None` at end of input; `Some("")` for an empty line; a line holding a
/// NUL (a break on a serial line) as `Some("\0")`.
fn read_name() -> Option<String> {
    let mut line = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match std::io::stdin().read(&mut buf) {
            Ok(0) => return if line.is_empty() { None } else { Some(String::from_utf8_lossy(&line).into_owned()) },
            Ok(n) => {
                line.extend_from_slice(&buf[..n]);
                if line.ends_with(b"\n") {
                    line.pop();
                    return Some(String::from_utf8_lossy(&line).trim().to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut kind = args.first().cloned().unwrap_or_else(|| "default".into());
    let tty = args.get(1).cloned();
    if let Some(tty) = tty.as_deref().filter(|t| *t != "-")
        && let Err(e) = take_terminal(tty)
    {
        eprintln!("getty: /dev/{tty}: {e}");
        std::process::exit(1);
    }
    // `-` (or nothing): the terminal getty was started on, named as ttyname(3) reports it.
    let tty_name = match tty.filter(|t| t != "-") {
        Some(t) => t,
        None => {
            // SAFETY: ttyname returns a static string or NULL.
            let p = unsafe { libc::ttyname(0) };
            if p.is_null() {
                "console".into()
            } else {
                let path = unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy();
                path.strip_prefix("/dev/").unwrap_or(&path).to_string()
            }
        }
    };
    let db = getcap::Db::read(GETTYTAB).unwrap_or_default();

    loop {
        let Some(e) = db.get(&kind).or_else(|| db.get("default")) else {
            eprintln!("getty: no gettytab entry `{kind}' or `default'");
            std::process::exit(1);
        };
        configure(&e);
        if let Some(clear) = e.string("cl") {
            out(clear);
        }
        let banner = e.string("if").and_then(|f| std::fs::read_to_string(f).ok());
        match banner {
            Some(text) => out(&expand(&text, &tty_name)),
            None => out(&expand(e.string("im").unwrap_or(DEFAULT_IM), &tty_name)),
        }
        let login = e.string("lo").unwrap_or(DEFAULT_LO).to_string();
        let mut env: Vec<(String, String)> = Vec::new();
        if let Some(term) = e.string("tt") {
            env.push(("TERM".into(), term.into()));
        }
        if let Some(user) = e.string("al") {
            let err = std::process::Command::new(&login).arg0("login").args(["-f", user]).envs(env).exec();
            eprintln!("getty: {login}: {err}");
            std::process::exit(1);
        }
        if let Some(to) = e.num("to") {
            // SAFETY: alarm(2); an unanswered prompt ends getty, and init starts a new one.
            unsafe { libc::alarm(to as u32) };
        }
        loop {
            out(&expand(e.string("lm").unwrap_or(DEFAULT_LM), &tty_name));
            match read_name() {
                None => std::process::exit(0),
                Some(name) if name.contains('\0') => {
                    // A break: try the next speed.
                    if let Some(next) = e.string("nx") {
                        kind = next.to_string();
                    }
                    break;
                }
                Some(name) if name.is_empty() || name.starts_with('-') => continue,
                Some(name) => {
                    unsafe { libc::alarm(0) };
                    let err = std::process::Command::new(&login).arg0("login").args(["-p", &name]).envs(env).exec();
                    eprintln!("getty: {login}: {err}");
                    std::process::exit(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        let s = expand("%t on %h (%s/%m) 100%% %q", "ttyv0");
        assert!(s.starts_with("ttyv0 on "));
        assert!(s.contains(" 100% %q"));
    }
}
