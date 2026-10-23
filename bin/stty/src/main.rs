//! `stty(1)`: shows or changes a terminal's settings.
//!
//! ```text
//! stty [-a | -e | -g] [-f file] [operand ...]
//! ```
//!
//! The terminal is the standard input, or `-f file`. With no operand stty writes its settings
//! as the BSDs do: the speed, then the flags that differ from the defaults and the control
//! characters that do; `-e` writes all of them with the window size, `-a` the same with the
//! control characters as `name = value;`, and `-g` one line that, given back as the operand,
//! restores them all (`stty "$(stty -g)"`).
//!
//! Operands change settings: a flag (`echo`, `-echo`, ...), a combination (`raw`, `cooked`,
//! `sane`, `cbreak`, `evenp`, `oddp`, `parity`, `pass8`, `litout`, `crt`, `dec`, `ek`, `tabs`),
//! a control character and its value (`intr ^C`, `erase undef`, `min 1`), a speed (`9600`,
//! `ispeed n`, `ospeed n`) or the window size (`rows n`, `cols n`). `size` and `speed` write the
//! window size and speed. All operands are applied together, at once (`TCSANOW`).

use std::ffi::CString;
use std::io::{self, Write};
use std::process::ExitCode;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    I,
    O,
    C,
    L,
}

/// A flag operand: `set` bits turned on and `clear` bits off in `field`.
struct Mode {
    name: &'static str,
    field: Field,
    set: libc::tcflag_t,
    clear: libc::tcflag_t,
}

macro_rules! m {
    ($name:expr, $field:ident, $set:expr, $clear:expr) => {
        Mode { name: $name, field: Field::$field, set: $set as libc::tcflag_t, clear: $clear as libc::tcflag_t }
    };
}

/// Each flag `x` as `x` and `-x`, then the combinations (FreeBSD's `modes.c`, less what this
/// terminal interface lacks).
fn modes() -> Vec<Mode> {
    use libc::*;
    let flags: &[(&str, Field, tcflag_t)] = &[
        ("cstopb", Field::C, CSTOPB),
        ("cread", Field::C, CREAD),
        ("parenb", Field::C, PARENB),
        ("parodd", Field::C, PARODD),
        ("hupcl", Field::C, HUPCL),
        ("hup", Field::C, HUPCL),
        ("clocal", Field::C, CLOCAL),
        ("crtscts", Field::C, CRTSCTS),
        ("ignbrk", Field::I, IGNBRK),
        ("brkint", Field::I, BRKINT),
        ("ignpar", Field::I, IGNPAR),
        ("parmrk", Field::I, PARMRK),
        ("inpck", Field::I, INPCK),
        ("istrip", Field::I, ISTRIP),
        ("inlcr", Field::I, INLCR),
        ("igncr", Field::I, IGNCR),
        ("icrnl", Field::I, ICRNL),
        ("ixon", Field::I, IXON),
        ("ixoff", Field::I, IXOFF),
        ("tandem", Field::I, IXOFF),
        ("ixany", Field::I, IXANY),
        ("decctlq", Field::I, IXANY),
        ("imaxbel", Field::I, IMAXBEL),
        ("echoke", Field::L, ECHOKE),
        ("crtkill", Field::L, ECHOKE),
        ("echoe", Field::L, ECHOE),
        ("crterase", Field::L, ECHOE),
        ("echo", Field::L, ECHO),
        ("echok", Field::L, ECHOK),
        ("echonl", Field::L, ECHONL),
        ("echoctl", Field::L, ECHOCTL),
        ("ctlecho", Field::L, ECHOCTL),
        ("echoprt", Field::L, ECHOPRT),
        ("prterase", Field::L, ECHOPRT),
        ("isig", Field::L, ISIG),
        ("icanon", Field::L, ICANON),
        ("iexten", Field::L, IEXTEN),
        ("tostop", Field::L, TOSTOP),
        ("noflsh", Field::L, NOFLSH),
        ("flusho", Field::L, FLUSHO),
        ("pendin", Field::L, PENDIN),
        ("opost", Field::O, OPOST),
        ("onlcr", Field::O, ONLCR),
        ("ocrnl", Field::O, OCRNL),
        ("onocr", Field::O, ONOCR),
        ("onlret", Field::O, ONLRET),
    ];
    let mut v = Vec::new();
    for &(name, field, bit) in flags {
        v.push(Mode { name, field, set: bit, clear: 0 });
        v.push(Mode { name: Box::leak(format!("-{name}").into_boxed_str()), field, set: 0, clear: bit });
    }
    v.extend([
        m!("cs5", C, CS5, CSIZE),
        m!("cs6", C, CS6, CSIZE),
        m!("cs7", C, CS7, CSIZE),
        m!("cs8", C, CS8, CSIZE),
        m!("parity", C, PARENB | CS7, PARODD | CSIZE),
        m!("-parity", C, CS8, PARENB | CSIZE),
        m!("evenp", C, PARENB | CS7, PARODD | CSIZE),
        m!("-evenp", C, CS8, PARENB | CSIZE),
        m!("oddp", C, PARENB | CS7 | PARODD, CSIZE),
        m!("-oddp", C, CS8, PARENB | CSIZE),
        m!("pass8", C, CS8, PARENB | CSIZE),
        m!("-pass8", C, PARENB | CS7, CSIZE),
        m!("crt", L, ECHOE | ECHOKE | ECHOCTL, ECHOK | ECHOPRT),
        m!("-crt", L, ECHOK, ECHOE | ECHOKE | ECHOCTL),
        m!("newcrt", L, ECHOE | ECHOKE | ECHOCTL, ECHOK | ECHOPRT),
        m!("-newcrt", L, ECHOK, ECHOE | ECHOKE | ECHOCTL),
        m!("oxtabs", O, TAB3, TABDLY),
        m!("-oxtabs", O, TAB0, TABDLY),
        m!("tabs", O, TAB0, TABDLY),
        m!("-tabs", O, TAB3, TABDLY),
    ]);
    v
}

/// The control characters: name, index, default (FreeBSD's `cchars1`, less `dsusp`, `erase2` and
/// `status`, which this interface lacks).
const CCHARS: &[(&str, usize, u8)] = &[
    ("discard", libc::VDISCARD, 0x0f),
    ("eof", libc::VEOF, 0x04),
    ("eol", libc::VEOL, VDISABLE),
    ("eol2", libc::VEOL2, VDISABLE),
    ("erase", libc::VERASE, 0x7f),
    ("intr", libc::VINTR, 0x03),
    ("kill", libc::VKILL, 0x15),
    ("lnext", libc::VLNEXT, 0x16),
    ("min", libc::VMIN, 1),
    ("quit", libc::VQUIT, 0x1c),
    ("reprint", libc::VREPRINT, 0x12),
    ("start", libc::VSTART, 0x11),
    ("stop", libc::VSTOP, 0x13),
    ("susp", libc::VSUSP, 0x1a),
    ("time", libc::VTIME, 0),
    ("werase", libc::VWERASE, 0x17),
];
/// Other names for some (`cchars2`).
const CCHAR_ALIASES: &[(&str, &str)] = &[("brk", "eol"), ("flush", "discard"), ("rprnt", "reprint")];

/// musl's `_POSIX_VDISABLE`.
const VDISABLE: u8 = 0;

const SPEEDS: &[(libc::speed_t, u32)] = &[
    (libc::B0, 0),
    (libc::B50, 50),
    (libc::B75, 75),
    (libc::B110, 110),
    (libc::B134, 134),
    (libc::B150, 150),
    (libc::B200, 200),
    (libc::B300, 300),
    (libc::B600, 600),
    (libc::B1200, 1200),
    (libc::B1800, 1800),
    (libc::B2400, 2400),
    (libc::B4800, 4800),
    (libc::B9600, 9600),
    (libc::B19200, 19200),
    (libc::B38400, 38400),
    (libc::B57600, 57600),
    (libc::B115200, 115200),
    (libc::B230400, 230400),
    (libc::B460800, 460800),
    (libc::B500000, 500000),
    (libc::B576000, 576000),
    (libc::B921600, 921600),
    (libc::B1000000, 1000000),
    (libc::B1152000, 1152000),
    (libc::B1500000, 1500000),
    (libc::B2000000, 2000000),
    (libc::B2500000, 2500000),
    (libc::B3000000, 3000000),
    (libc::B3500000, 3500000),
    (libc::B4000000, 4000000),
];

fn speed_number(code: libc::speed_t) -> u32 {
    SPEEDS.iter().find(|s| s.0 == code).map_or(code as u32, |s| s.1)
}

fn speed_code(n: &str) -> Option<libc::speed_t> {
    let n: u32 = n.parse().ok()?;
    SPEEDS.iter().find(|s| s.1 == n).map(|s| s.0)
}

/// The defaults FreeBSD's `cfmakesane` gives: 4.4BSD's `<sys/ttydefaults.h>`.
const DEF_IFLAG: libc::tcflag_t = libc::BRKINT | libc::ICRNL | libc::IMAXBEL | libc::IXON | libc::IXANY;
const DEF_OFLAG: libc::tcflag_t = libc::OPOST | libc::ONLCR;
const DEF_LFLAG: libc::tcflag_t =
    libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN | libc::ECHOE | libc::ECHOKE | libc::ECHOCTL;
const DEF_CFLAG: libc::tcflag_t = libc::CREAD | libc::CS8 | libc::HUPCL;

/// The speed bits in `c_cflag`.
const SPEED_MASK: libc::tcflag_t = libc::CBAUD | libc::CIBAUD;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Fmt {
    NotSet,
    Bsd,
    Posix,
}

struct Tty {
    t: libc::termios,
    win: libc::winsize,
    set: bool,
    wset: bool,
}

fn field(t: &mut libc::termios, f: Field) -> &mut libc::tcflag_t {
    match f {
        Field::I => &mut t.c_iflag,
        Field::O => &mut t.c_oflag,
        Field::C => &mut t.c_cflag,
        Field::L => &mut t.c_lflag,
    }
}

/// A control character as FreeBSD's `ccval` writes it.
fn ccval(sub: usize, c: u8) -> String {
    if sub == libc::VMIN || sub == libc::VTIME {
        return c.to_string();
    }
    if c == VDISABLE {
        return "<undef>".to_string();
    }
    let mut s = String::new();
    let mut c = c;
    if c & 0x80 != 0 {
        s.push_str("M-");
        c &= 0x7f;
    }
    if c == 0x7f {
        s.push_str("^?");
    } else if c < 0x20 {
        s.push('^');
        s.push((c + b'@') as char);
    } else {
        s.push(c as char);
    }
    s
}

/// A control character's value: `^X`, `^?`, `^-` or `undef` (disabled), or one character.
fn parse_cc(v: &str) -> Option<u8> {
    let b = v.as_bytes();
    match b {
        b"undef" | b"^-" | b"<undef>" => Some(VDISABLE),
        [c] => Some(*c),
        [b'^', b'?'] => Some(0x7f),
        [b'^', c] => Some(c.to_ascii_uppercase() & 0x1f),
        _ => None,
    }
}

/// FreeBSD's `bput`: flag names after a label, wrapped at 72 columns.
struct Lines {
    out: String,
    col: usize,
    label: &'static str,
}

impl Lines {
    fn binit(&mut self, label: &'static str) {
        if self.col > 0 {
            self.out.push('\n');
        }
        self.col = 0;
        self.label = label;
    }

    fn bput(&mut self, s: &str) {
        if self.col == 0 {
            let piece = format!("{}: {s}", self.label);
            self.col = piece.len();
            self.out += &piece;
            return;
        }
        if self.col + s.len() > 72 {
            self.out += "\n\t";
            self.out += s;
            self.col = s.len() + 8;
            return;
        }
        self.out.push(' ');
        self.out += s;
        self.col += s.len() + 1;
    }
}

/// FreeBSD's `print`.
fn print(t: &libc::termios, w: &libc::winsize, fmt: Fmt) -> String {
    let mut l = Lines { out: String::new(), col: 0, label: "" };
    // SAFETY: reading the termios.
    let (ispeed, ospeed) = unsafe { (libc::cfgetispeed(t), libc::cfgetospeed(t)) };
    let (ispeed, ospeed) = (speed_number(ispeed), speed_number(ospeed));
    let mut line = if ispeed != ospeed {
        format!("ispeed {ispeed} baud; ospeed {ospeed} baud;")
    } else {
        format!("speed {ispeed} baud;")
    };
    if fmt >= Fmt::Bsd {
        line += &format!(" {} rows; {} columns;", w.ws_row, w.ws_col);
    }
    l.out += &line;
    l.out.push('\n');

    let all = fmt >= Fmt::Bsd;
    let put = |l: &mut Lines, flags: libc::tcflag_t, name: &str, bit: libc::tcflag_t, def: bool| {
        let on = flags & bit != 0;
        if all || on != def {
            l.bput(if on { &name[1..] } else { name });
        }
    };
    use libc::*;
    l.binit("lflags");
    let f = t.c_lflag;
    put(&mut l, f, "-icanon", ICANON, true);
    put(&mut l, f, "-isig", ISIG, true);
    put(&mut l, f, "-iexten", IEXTEN, true);
    put(&mut l, f, "-echo", ECHO, true);
    put(&mut l, f, "-echoe", ECHOE, false);
    put(&mut l, f, "-echok", ECHOK, false);
    put(&mut l, f, "-echoke", ECHOKE, false);
    put(&mut l, f, "-echonl", ECHONL, false);
    put(&mut l, f, "-echoctl", ECHOCTL, false);
    put(&mut l, f, "-echoprt", ECHOPRT, false);
    put(&mut l, f, "-noflsh", NOFLSH, false);
    put(&mut l, f, "-tostop", TOSTOP, false);
    put(&mut l, f, "-flusho", FLUSHO, false);
    put(&mut l, f, "-pendin", PENDIN, false);

    l.binit("iflags");
    let f = t.c_iflag;
    put(&mut l, f, "-istrip", ISTRIP, false);
    put(&mut l, f, "-icrnl", ICRNL, true);
    put(&mut l, f, "-inlcr", INLCR, false);
    put(&mut l, f, "-igncr", IGNCR, false);
    put(&mut l, f, "-ixon", IXON, true);
    put(&mut l, f, "-ixoff", IXOFF, false);
    put(&mut l, f, "-ixany", IXANY, true);
    put(&mut l, f, "-imaxbel", IMAXBEL, true);
    put(&mut l, f, "-ignbrk", IGNBRK, false);
    put(&mut l, f, "-brkint", BRKINT, true);
    put(&mut l, f, "-inpck", INPCK, false);
    put(&mut l, f, "-ignpar", IGNPAR, false);
    put(&mut l, f, "-parmrk", PARMRK, false);

    l.binit("oflags");
    let f = t.c_oflag;
    put(&mut l, f, "-opost", OPOST, true);
    put(&mut l, f, "-onlcr", ONLCR, true);
    put(&mut l, f, "-ocrnl", OCRNL, false);
    // (The constants' types differ between libc targets.)
    let tabs = f & TABDLY as tcflag_t;
    if tabs == TAB3 as tcflag_t {
        l.bput("tab3");
    } else if tabs == TAB0 as tcflag_t && all {
        l.bput("tab0");
    }
    put(&mut l, f, "-onocr", ONOCR, false);
    put(&mut l, f, "-onlret", ONLRET, false);

    l.binit("cflags");
    let f = t.c_cflag;
    put(&mut l, f, "-cread", CREAD, true);
    let size = match f & CSIZE {
        CS5 => "cs5",
        CS6 => "cs6",
        CS7 => "cs7",
        _ => "cs8",
    };
    l.bput(size);
    l.bput(if f & PARENB != 0 { "parenb" } else { "-parenb" });
    put(&mut l, f, "-parodd", PARODD, false);
    put(&mut l, f, "-hupcl", HUPCL, true);
    put(&mut l, f, "-clocal", CLOCAL, false);
    put(&mut l, f, "-cstopb", CSTOPB, false);
    put(&mut l, f, "-crtscts", CRTSCTS, false);

    if fmt == Fmt::Posix {
        l.binit("cchars");
        for &(name, sub, _) in CCHARS {
            l.bput(&format!("{name} = {};", ccval(sub, t.c_cc[sub])));
        }
        l.binit("");
    } else {
        l.binit("");
        let (mut b1, mut b2) = (String::new(), String::new());
        let mut cnt = 0;
        for &(name, sub, def) in CCHARS {
            if fmt != Fmt::Bsd && t.c_cc[sub] == def {
                continue;
            }
            b1 += &format!("{name:<8}");
            b2 += &format!("{:<8}", ccval(sub, t.c_cc[sub]));
            cnt += 1;
            if cnt == 72 / 8 {
                l.out += &format!("{}\n{}\n", b1.trim_end(), b2.trim_end());
                (b1, b2, cnt) = (String::new(), String::new(), 0);
            }
        }
        if cnt > 0 {
            l.out += &format!("{}\n{}\n", b1.trim_end(), b2.trim_end());
        }
    }
    l.out
}

/// `-g`: FreeBSD's `gprint`.
fn gprint(t: &libc::termios) -> String {
    let mut s = format!("gfmt1:cflag={:x}:iflag={:x}:lflag={:x}:oflag={:x}:", t.c_cflag, t.c_iflag, t.c_lflag, t.c_oflag);
    for &(name, sub, _) in CCHARS {
        s += &format!("{name}={:x}:", t.c_cc[sub]);
    }
    // SAFETY: reading the termios.
    let (i, o) = unsafe { (libc::cfgetispeed(t), libc::cfgetospeed(t)) };
    s += &format!("ispeed={}:ospeed={}\n", speed_number(i), speed_number(o));
    s
}

/// A `-g` line given back: FreeBSD's `gread`.
fn gread(t: &mut libc::termios, s: &str) -> Result<(), String> {
    let bad = || format!("illegal gfmt1 option -- {s}");
    for item in s.strip_prefix("gfmt1:").ok_or_else(bad)?.split(':') {
        if item.is_empty() {
            continue;
        }
        let (k, v) = item.split_once('=').ok_or_else(bad)?;
        let hex = || libc::tcflag_t::from_str_radix(v, 16).map_err(|_| bad());
        match k {
            "cflag" => t.c_cflag = hex()?,
            "iflag" => t.c_iflag = hex()?,
            "lflag" => t.c_lflag = hex()?,
            "oflag" => t.c_oflag = hex()?,
            "ispeed" | "ospeed" => {
                let code = speed_code(v).ok_or_else(bad)?;
                // SAFETY: setting a speed in our termios.
                unsafe {
                    if k == "ispeed" {
                        libc::cfsetispeed(t, code);
                    } else {
                        libc::cfsetospeed(t, code);
                    }
                }
            }
            _ => {
                let (_, sub, _) = CCHARS.iter().find(|c| c.0 == k).ok_or_else(bad)?;
                t.c_cc[*sub] = u8::from_str_radix(v, 16).map_err(|_| bad())?;
            }
        }
    }
    Ok(())
}

fn sane(t: &mut libc::termios) {
    use libc::*;
    let keep_l = ECHOKE | ECHOE | ECHOK | ECHOPRT | ECHOCTL | TOSTOP | NOFLSH;
    t.c_cflag = DEF_CFLAG | (t.c_cflag & (CLOCAL | SPEED_MASK));
    t.c_iflag = DEF_IFLAG;
    t.c_lflag = DEF_LFLAG | (t.c_lflag & keep_l);
    t.c_oflag = DEF_OFLAG;
}

/// strerror(3) of errno.
fn last_error() -> String {
    let n = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // SAFETY: strerror returns a NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned()
}

fn usage() -> ExitCode {
    eprintln!("usage: stty [-a | -e | -g] [-f file] [arguments]");
    ExitCode::from(1)
}

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut fmt = Fmt::NotSet;
    let mut gflag = false;
    let mut file: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        // "-echo" is a setting, not options: options are only words of a, e, g and f.
        let Some(opts) = a.strip_prefix('-').filter(|o| !o.is_empty() && o.chars().all(|c| "aefg".contains(c))) else {
            break;
        };
        let mut chars = opts.char_indices();
        while let Some((pos, c)) = chars.next() {
            match c {
                'a' => {
                    fmt = Fmt::Posix;
                    gflag = false;
                }
                'e' => {
                    fmt = Fmt::Bsd;
                    gflag = false;
                }
                'g' => gflag = true,
                'f' => {
                    let rest = &opts[pos + 1..];
                    file = Some(if !rest.is_empty() {
                        rest.to_string()
                    } else {
                        i += 1;
                        match args.get(i) {
                            Some(f) => f.clone(),
                            None => return usage(),
                        }
                    });
                    break;
                }
                _ => unreachable!(),
            }
        }
        i += 1;
    }

    let fd = match &file {
        Some(f) => {
            let c = CString::new(f.as_str()).unwrap_or_default();
            // SAFETY: a NUL-terminated path.
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
            if fd < 0 {
                eprintln!("stty: {f}: {}", last_error());
                return ExitCode::from(1);
            }
            fd
        }
        None => 0,
    };
    // SAFETY: zeroed structs for the calls to fill.
    let mut tty = Tty { t: unsafe { std::mem::zeroed() }, win: unsafe { std::mem::zeroed() }, set: false, wset: false };
    if unsafe { libc::tcgetattr(fd, &mut tty.t) } < 0 {
        match &file {
            Some(f) => eprintln!("stty: {f} isn't a terminal"),
            None => eprintln!("stty: stdin isn't a terminal"),
        }
        return ExitCode::from(1);
    }
    // SAFETY: TIOCGWINSZ fills a winsize; a terminal without one leaves it zero.
    unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut tty.win) };

    let mut out = String::new();
    let ops = &args[i..];
    if ops.is_empty() {
        out = if gflag { gprint(&tty.t) } else { print(&tty.t, &tty.win, fmt) };
    } else if gflag || fmt != Fmt::NotSet {
        return usage();
    }
    let table = modes();
    let mut j = 0;
    while j < ops.len() {
        let op = ops[j].as_str();
        let arg = ops.get(j + 1).map(String::as_str);
        let need = |name: &str| -> Result<&str, ExitCode> {
            arg.ok_or_else(|| {
                eprintln!("stty: {name} requires an argument");
                usage()
            })
        };
        j += 1;
        if let Some(m) = table.iter().find(|m| m.name == op) {
            let f = field(&mut tty.t, m.field);
            *f = (*f & !m.clear) | m.set;
            tty.set = true;
            continue;
        }
        let cc_name = CCHAR_ALIASES.iter().find(|a| a.0 == op).map_or(op, |a| a.1);
        if let Some(&(name, sub, _)) = CCHARS.iter().find(|c| c.0 == cc_name) {
            let v = match need(name) {
                Ok(v) => v,
                Err(e) => return e,
            };
            j += 1;
            let val = if sub == libc::VMIN || sub == libc::VTIME {
                v.parse::<u8>().ok()
            } else {
                parse_cc(v)
            };
            match val {
                Some(c) => tty.t.c_cc[sub] = c,
                None => {
                    eprintln!("stty: {v}: illegal value for {name}");
                    return ExitCode::from(1);
                }
            }
            tty.set = true;
            continue;
        }
        if op.starts_with("gfmt1:") {
            if let Err(e) = gread(&mut tty.t, op) {
                eprintln!("stty: {e}");
                return ExitCode::from(1);
            }
            tty.set = true;
            continue;
        }
        if op.bytes().all(|b| b.is_ascii_digit()) {
            let Some(code) = speed_code(op) else {
                eprintln!("stty: {op}: unsupported speed");
                return ExitCode::from(1);
            };
            // SAFETY: setting speeds in our termios.
            unsafe {
                libc::cfsetispeed(&mut tty.t, code);
                libc::cfsetospeed(&mut tty.t, code);
            }
            tty.set = true;
            continue;
        }
        match op {
            "all" => out += &print(&tty.t, &tty.win, Fmt::Bsd),
            "everything" => out += &print(&tty.t, &tty.win, Fmt::Posix),
            "size" => out += &format!("{} {}\n", tty.win.ws_row, tty.win.ws_col),
            "speed" => {
                // SAFETY: reading our termios.
                out += &format!("{}\n", speed_number(unsafe { libc::cfgetospeed(&tty.t) }));
            }
            "ispeed" | "ospeed" => {
                let v = match need(op) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                j += 1;
                let Some(code) = speed_code(v) else {
                    eprintln!("stty: {v}: unsupported speed");
                    return ExitCode::from(1);
                };
                // SAFETY: setting a speed in our termios.
                unsafe {
                    if op == "ispeed" {
                        libc::cfsetispeed(&mut tty.t, code);
                    } else {
                        libc::cfsetospeed(&mut tty.t, code);
                    }
                }
                tty.set = true;
            }
            "rows" | "cols" | "columns" => {
                let v = match need(op) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                j += 1;
                let Ok(n) = v.parse::<u16>() else {
                    eprintln!("stty: {v}: illegal number for {op}");
                    return ExitCode::from(1);
                };
                if op == "rows" {
                    tty.win.ws_row = n;
                } else {
                    tty.win.ws_col = n;
                }
                tty.wset = true;
            }
            "sane" | "cooked" | "-raw" | "-cbreak" => {
                sane(&mut tty.t);
                tty.set = true;
            }
            "raw" => {
                // SAFETY: our termios.
                unsafe { libc::cfmakeraw(&mut tty.t) };
                tty.t.c_cflag = (tty.t.c_cflag & !(libc::CSIZE | libc::PARENB)) | libc::CS8;
                tty.set = true;
            }
            "cbreak" => {
                tty.t.c_iflag |= libc::BRKINT | libc::IXON | libc::IMAXBEL;
                tty.t.c_oflag |= libc::OPOST;
                tty.t.c_lflag |= libc::ISIG | libc::IEXTEN;
                tty.t.c_lflag &= !libc::ICANON;
                tty.set = true;
            }
            "litout" => {
                tty.t.c_cflag = (tty.t.c_cflag & !(libc::CSIZE | libc::PARENB)) | libc::CS8;
                tty.t.c_oflag &= !libc::OPOST;
                tty.set = true;
            }
            "-litout" => {
                tty.t.c_cflag = (tty.t.c_cflag & !libc::CSIZE) | libc::CS7 | libc::PARENB;
                tty.t.c_oflag |= libc::OPOST;
                tty.set = true;
            }
            "ek" => {
                tty.t.c_cc[libc::VERASE] = 0x7f;
                tty.t.c_cc[libc::VKILL] = 0x15;
                tty.set = true;
            }
            "dec" => {
                tty.t.c_cc[libc::VERASE] = 0x7f;
                tty.t.c_cc[libc::VKILL] = 0x15;
                tty.t.c_cc[libc::VINTR] = 0x03;
                tty.t.c_lflag &= !libc::ECHOPRT;
                tty.t.c_lflag |= libc::ECHOE | libc::ECHOKE | libc::ECHOCTL;
                tty.t.c_iflag &= !libc::IXANY;
                tty.set = true;
            }
            _ => {
                eprintln!("stty: illegal option -- {op}");
                return usage();
            }
        }
    }
    // SAFETY: our descriptor and filled structs.
    if tty.set && unsafe { libc::tcsetattr(fd, libc::TCSANOW, &tty.t) } < 0 {
        eprintln!("stty: tcsetattr: {}", last_error());
        return ExitCode::from(1);
    }
    if tty.wset && unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &tty.win) } < 0 {
        eprintln!("stty: TIOCSWINSZ: {}", last_error());
        return ExitCode::from(1);
    }
    if !out.is_empty() {
        let mut o = io::stdout().lock();
        if o.write_all(out.as_bytes()).and_then(|_| o.flush()).is_err() {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}
