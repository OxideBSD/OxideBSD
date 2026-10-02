//! Terminals (TTY.md in OxideBSD-doc): every terminal device is one `Tty`, with its own input
//! queues, `termios`, window size, session and foreground process group, and the POSIX line
//! discipline (XBD chapter 11) applied between its device and its readers and writers.
//!
//! Locking: `TTYS` is taken from interrupt handlers (keyboard, UART) and from syscalls, which run
//! with interrupts masked on this single core, so it is never contended. Output drivers,
//! signals and wakeups are called only after it is dropped: a driver can feed input back (the
//! console answers `ESC[6n` through its input), and signal delivery takes the process table.

pub mod console;
pub mod pty;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use spin::Mutex;

use crate::process::{self, BlockReason, Pid, ProcState, scheduler};

// musl's (Linux's) termios bits: user space sees these through its own <termios.h>.
pub const IGNBRK: u32 = 0o1;
pub const BRKINT: u32 = 0o2;
pub const ISTRIP: u32 = 0o40;
pub const INLCR: u32 = 0o100;
pub const IGNCR: u32 = 0o200;
pub const ICRNL: u32 = 0o400;
pub const IXON: u32 = 0o2000;
pub const IXANY: u32 = 0o4000;
pub const IXOFF: u32 = 0o10000;
pub const IMAXBEL: u32 = 0o20000;

pub const OPOST: u32 = 0o1;
pub const ONLCR: u32 = 0o4;
pub const OCRNL: u32 = 0o10;
pub const ONOCR: u32 = 0o20;
pub const ONLRET: u32 = 0o40;
pub const TABDLY: u32 = 0o14000;
pub const TAB3: u32 = 0o14000;

pub const CBAUD: u32 = 0o10017;
pub const B9600: u32 = 0o15;
pub const B38400: u32 = 0o17;
pub const CSIZE: u32 = 0o60;
pub const CS8: u32 = 0o60;
pub const CSTOPB: u32 = 0o100;
pub const CREAD: u32 = 0o200;
pub const PARENB: u32 = 0o400;
pub const PARODD: u32 = 0o1000;
pub const HUPCL: u32 = 0o2000;
pub const CLOCAL: u32 = 0o4000;

pub const ISIG: u32 = 0o1;
pub const ICANON: u32 = 0o2;
pub const ECHO: u32 = 0o10;
pub const ECHOE: u32 = 0o20;
pub const ECHOK: u32 = 0o40;
pub const ECHONL: u32 = 0o100;
pub const NOFLSH: u32 = 0o200;
pub const TOSTOP: u32 = 0o400;
pub const ECHOCTL: u32 = 0o1000;
pub const ECHOPRT: u32 = 0o2000;
pub const ECHOKE: u32 = 0o4000;
pub const IEXTEN: u32 = 0o100000;

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;
/// A control character set to this is disabled.
const VDISABLE: u8 = 0;

/// musl's `struct termios` (60 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

/// `struct winsize`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

const fn ctrl(c: u8) -> u8 {
    c & 0x1f
}

/// 4.4BSD's `<sys/ttydefaults.h>`, which all three BSDs share (TTY.md §3.8).
pub const fn default_termios(speed: u32) -> RawTermios {
    let mut cc = [VDISABLE; 32];
    cc[VINTR] = ctrl(b'c');
    cc[VQUIT] = 0x1c;
    cc[VERASE] = 0x7f;
    cc[VKILL] = ctrl(b'u');
    cc[VEOF] = ctrl(b'd');
    cc[VTIME] = 0;
    cc[VMIN] = 1;
    cc[VSTART] = ctrl(b'q');
    cc[VSTOP] = ctrl(b's');
    cc[VSUSP] = ctrl(b'z');
    cc[VREPRINT] = ctrl(b'r');
    cc[VDISCARD] = ctrl(b'o');
    cc[VWERASE] = ctrl(b'w');
    cc[VLNEXT] = ctrl(b'v');
    RawTermios {
        c_iflag: BRKINT | ICRNL | IMAXBEL | IXON | IXANY,
        c_oflag: OPOST | ONLCR,
        c_cflag: CREAD | CS8 | HUPCL | speed,
        c_lflag: ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL,
        c_line: 0,
        c_cc: cc,
        c_ispeed: speed,
        c_ospeed: speed,
    }
}

pub type TtyId = usize;

/// How a terminal's bytes leave the machine. Called without `TTYS` held.
pub trait Driver: Sync {
    /// `raw` is what the program or the echo produced, `cooked` the same after output
    /// processing; a driver sends `cooked` (the console also copies `raw` to COM1).
    fn output(&self, raw: &[u8], cooked: &[u8]);
    /// The line settings changed (speed, parity...). Most devices ignore it.
    fn configure(&self, _termios: &RawTermios) {}
    /// The last descriptor was closed with `HUPCL` set.
    fn hangup(&self) {}
    /// Whether output can be accepted now; a writer waits while it can't (a pseudo-terminal's
    /// master not reading, `PTY.md` §4.1).
    fn room(&self) -> bool {
        true
    }
    /// The other end is gone (a pseudo-terminal whose master was closed, `PTY.md` §3.3): reads
    /// with nothing queued return end-of-file and writes fail with `EIO`.
    fn hung_up(&self) -> bool {
        false
    }
    /// The last descriptor was closed (whether or not `HUPCL` is set).
    fn last_close(&self) {}
    /// A `read` took input, so there is room for more.
    fn drained(&self) {}
    /// Packet-mode events (`TIOCPKT_*` bits, `PTY.md` §5.3): a flush, output stopped or
    /// restarted, `IXON` turned off or on.
    fn status(&self, _bits: u8) {}
}

/// `TIOCPKT_*` (`<sys/ioctl.h>`), the events `Driver::status` reports.
pub const TIOCPKT_FLUSHREAD: u8 = 1;
pub const TIOCPKT_FLUSHWRITE: u8 = 2;
pub const TIOCPKT_STOP: u8 = 4;
pub const TIOCPKT_START: u8 = 8;
pub const TIOCPKT_NOSTOP: u8 = 16;
pub const TIOCPKT_DOSTOP: u8 = 32;

/// Most input a terminal holds before dropping further input (and ringing the bell, with
/// `IMAXBEL`): 4.4BSD's `TTYHOG` and `MAX_CANON`.
const TTYHOG: usize = 8192;
const MAX_CANON: usize = 1024;

pub struct Tty {
    pub name: &'static str,
    pub major: u32,
    pub minor: u32,
    pub termios: RawTermios,
    pub winsize: Winsize,
    /// The session this is the controlling terminal of.
    pub session: Option<Pid>,
    pub pgrp: Option<Pid>,
    /// Sessions whose leader exited while this was their controlling terminal: their processes
    /// read end-of-file and can't write (§5.4).
    revoked: Vec<Pid>,
    /// Input ready for `read`: bytes, and in canonical mode the lengths of the complete lines
    /// at its front (a 0-length line is an end-of-file from `VEOF`).
    ready: VecDeque<u8>,
    lines: VecDeque<usize>,
    /// The line being edited, in canonical mode.
    canon: Vec<u8>,
    /// The next input byte is taken literally (`VLNEXT`).
    literal: bool,
    /// Output is stopped (`VSTOP`).
    stopped: bool,
    /// Output column, for erasing tabs and `ONOCR`.
    column: usize,
    /// `ticks()` when input last arrived, for `VTIME`.
    last_input: u64,
    /// Open descriptions.
    pub opens: usize,
}

static TTYS: Mutex<Vec<Tty>> = Mutex::new(Vec::new());
static DRIVERS: Mutex<Vec<&'static dyn Driver>> = Mutex::new(Vec::new());

/// The framebuffer console (`/dev/ttyv0`), always terminal 0.
pub const TTYV0: TtyId = 0;

/// The `tty` group (`/etc/group`), which owns terminals' device nodes.
pub const TTY_GID: u32 = 4;

/// Opens a terminal's device node (the registry's open function for every terminal).
extern "C" fn dev_open(major: u64, minor: u64, flags: u64) -> i64 {
    oxidebsd_tty_open(major, minor, flags)
}

/// Registers a terminal, and its node in `/dev` (root's, group `tty`, mode 0600, as the BSDs'
/// devfs makes them; login(1) gives it to the user); returns its id.
pub fn register(name: &'static str, major: u32, minor: u32, speed: u32, winsize: Winsize, driver: &'static dyn Driver) -> TtyId {
    let _ = crate::fs::devfs::make_dev(name, major, minor, 0, TTY_GID, 0o600, dev_open);
    register_bare(name, major, minor, speed, winsize, driver)
}

/// `register` without the device node: for a terminal whose node its driver makes itself
/// (`pty`).
pub fn register_bare(name: &'static str, major: u32, minor: u32, speed: u32, winsize: Winsize, driver: &'static dyn Driver) -> TtyId {
    let mut ttys = TTYS.lock();
    ttys.push(Tty {
        name,
        major,
        minor,
        termios: default_termios(speed),
        winsize,
        session: None,
        pgrp: None,
        revoked: Vec::new(),
        ready: VecDeque::new(),
        lines: VecDeque::new(),
        canon: Vec::new(),
        literal: false,
        stopped: false,
        column: 0,
        last_input: 0,
        opens: 0,
    });
    DRIVERS.lock().push(driver);
    ttys.len() - 1
}

/// Puts terminal `id` back as `register` made it, for reuse (a pseudo-terminal's number).
pub fn reset(id: TtyId, speed: u32) {
    with(id, |t| {
        t.termios = default_termios(speed);
        t.winsize = Winsize::default();
        t.session = None;
        t.pgrp = None;
        t.revoked.clear();
        t.flush_input();
        t.stopped = false;
        t.column = 0;
        t.opens = 0;
    });
}

fn driver(id: TtyId) -> &'static dyn Driver {
    DRIVERS.lock()[id]
}

pub fn find(major: u32, minor: u32) -> Option<TtyId> {
    TTYS.lock().iter().position(|t| t.major == major && t.minor == minor)
}

pub fn name(id: TtyId) -> &'static str {
    TTYS.lock()[id].name
}

pub fn device(id: TtyId) -> (u32, u32) {
    let t = &TTYS.lock()[id];
    (t.major, t.minor)
}

pub fn with<R>(id: TtyId, f: impl FnOnce(&mut Tty) -> R) -> R {
    f(&mut TTYS.lock()[id])
}

/// The terminal `sid` controls, if any.
pub fn controlling(sid: Pid) -> Option<TtyId> {
    TTYS.lock().iter().position(|t| t.session == Some(sid))
}

// --- side effects collected under the lock, performed after it ------------------------------

#[derive(Default)]
struct Effects {
    echo_raw: Vec<u8>,
    echo: Vec<u8>,
    signal: Option<(Pid, u64)>,
    wake_readers: bool,
    wake_writers: bool,
    /// `TIOCPKT_*` events for `Driver::status`.
    pkt: u8,
}

fn perform(id: TtyId, fx: Effects) {
    if !fx.echo.is_empty() {
        driver(id).output(&fx.echo_raw, &fx.echo);
    }
    if fx.pkt != 0 {
        driver(id).status(fx.pkt);
    }
    if let Some((pgrp, sig)) = fx.signal {
        process::signal_foreground_group(pgrp, sig);
    }
    if fx.wake_readers || fx.wake_writers {
        wake(id, fx.wake_readers, fx.wake_writers);
    }
}

pub(crate) fn wake(id: TtyId, readers: bool, writers: bool) {
    let mut table = process::table().lock();
    for (&pid, p) in table.iter_mut() {
        let hit = match p.state {
            ProcState::Blocked(BlockReason::WaitingForTty(t, _)) => readers && t == id,
            ProcState::Blocked(BlockReason::WaitingForTtyOutput(t)) => writers && t == id,
            _ => false,
        };
        if hit {
            p.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
    if readers {
        process::wake_pollers(&mut table);
    }
}

// --- output processing ------------------------------------------------------------------------

impl Tty {
    /// Output processing (`c_oflag`), appending the result to `out`.
    fn cook(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        let o = self.termios.c_oflag;
        if o & OPOST == 0 {
            out.extend_from_slice(bytes);
            return;
        }
        for &b in bytes {
            match b {
                b'\n' => {
                    if o & ONLCR != 0 {
                        out.extend_from_slice(b"\r\n");
                        self.column = 0;
                    } else {
                        out.push(b'\n');
                        if o & ONLRET != 0 {
                            self.column = 0;
                        }
                    }
                }
                b'\r' => {
                    if o & ONOCR != 0 && self.column == 0 {
                        continue;
                    }
                    if o & OCRNL != 0 {
                        out.push(b'\n');
                        if o & ONLRET != 0 {
                            self.column = 0;
                        }
                    } else {
                        out.push(b'\r');
                        self.column = 0;
                    }
                }
                b'\t' => {
                    let n = 8 - self.column % 8;
                    if o & TABDLY == TAB3 {
                        out.extend(core::iter::repeat_n(b' ', n));
                    } else {
                        out.push(b'\t');
                    }
                    self.column += n;
                }
                0x08 => {
                    out.push(b);
                    self.column = self.column.saturating_sub(1);
                }
                0x20..=0x7e => {
                    out.push(b);
                    self.column += 1;
                }
                _ => out.push(b),
            }
        }
    }

    // --- echo ---------------------------------------------------------------------------------

    fn echo_byte(&mut self, b: u8, fx: &mut Effects) {
        let l = self.termios.c_lflag;
        let visible: &[u8] = &[b];
        if l & ECHOCTL != 0 && (b < 0x20 && b != b'\t' && b != b'\n' || b == 0x7f) {
            let pair = [b'^', if b == 0x7f { b'?' } else { b + 0x40 }];
            fx.echo_raw.extend_from_slice(&pair);
            self.cook(&pair, &mut fx.echo);
        } else {
            fx.echo_raw.extend_from_slice(visible);
            self.cook(visible, &mut fx.echo);
        }
    }

    fn echo_str(&mut self, s: &[u8], fx: &mut Effects) {
        fx.echo_raw.extend_from_slice(s);
        self.cook(s, &mut fx.echo);
    }

    /// Visually erases the last byte of the pending line (`ECHOE`).
    fn erase_echo(&mut self, b: u8, fx: &mut Effects) {
        let l = self.termios.c_lflag;
        if l & ECHO == 0 {
            return;
        }
        if l & ECHOE == 0 {
            self.echo_byte(self.termios.c_cc[VERASE], fx);
            return;
        }
        let width = if b == b'\t' {
            // Recompute where the tab started from the rest of the line.
            let mut col = 0usize;
            for &c in &self.canon {
                col = if c == b'\t' { col + 8 - col % 8 } else { col + 1 };
            }
            let before = self.column.saturating_sub(col);
            before.max(1)
        } else if l & ECHOCTL != 0 && (b < 0x20 || b == 0x7f) {
            2
        } else {
            1
        };
        for _ in 0..width {
            self.echo_str(b"\x08 \x08", fx);
        }
    }

    fn flush_input(&mut self) {
        self.ready.clear();
        self.lines.clear();
        self.canon.clear();
        self.literal = false;
    }

    /// Moves the pending line into `ready` as a complete line.
    fn finish_line(&mut self, fx: &mut Effects) {
        let n = self.canon.len();
        self.ready.extend(self.canon.drain(..));
        self.lines.push_back(n);
        fx.wake_readers = true;
    }

    // --- input --------------------------------------------------------------------------------

    fn input(&mut self, mut b: u8, fx: &mut Effects) {
        let t = self.termios;
        let (i, l, cc) = (t.c_iflag, t.c_lflag, t.c_cc);
        self.last_input = crate::cpu::interrupts::ticks();
        let is = |c: usize, b: u8| cc[c] != VDISABLE && cc[c] == b;

        if self.literal {
            self.literal = false;
            if l & ECHO != 0 {
                self.erase_echo(b'^', fx);
                self.echo_byte(b, fx);
            }
            self.store(b, fx);
            return;
        }
        if i & ISTRIP != 0 {
            b &= 0x7f;
        }
        if i & IXON != 0 {
            if is(VSTOP, b) {
                self.stopped = true;
                fx.pkt |= TIOCPKT_STOP;
                return;
            }
            if is(VSTART, b) {
                self.stopped = false;
                fx.wake_writers = true;
                fx.pkt |= TIOCPKT_START;
                return;
            }
            if self.stopped && i & IXANY != 0 {
                self.stopped = false;
                fx.wake_writers = true;
                fx.pkt |= TIOCPKT_START;
            }
        }
        match b {
            b'\r' if i & IGNCR != 0 => return,
            b'\r' if i & ICRNL != 0 => b = b'\n',
            b'\n' if i & INLCR != 0 => b = b'\r',
            _ => {}
        }
        if l & ISIG != 0 {
            let sig = if is(VINTR, b) {
                Some(process::SIGINT)
            } else if is(VQUIT, b) {
                Some(process::SIGQUIT)
            } else if is(VSUSP, b) {
                Some(process::SIGTSTP)
            } else {
                None
            };
            if let Some(sig) = sig {
                if l & NOFLSH == 0 {
                    self.flush_input();
                }
                if l & ECHO != 0 {
                    self.echo_byte(b, fx);
                    self.echo_str(b"\n", fx);
                }
                if let Some(pgrp) = self.pgrp {
                    fx.signal = Some((pgrp, sig));
                }
                return;
            }
        }
        if l & ICANON != 0 {
            if l & IEXTEN != 0 && is(VLNEXT, b) {
                self.literal = true;
                if l & ECHO != 0 {
                    self.echo_str(b"^\x08", fx);
                }
                return;
            }
            if is(VERASE, b) {
                if let Some(c) = self.canon.pop() {
                    self.erase_echo(c, fx);
                }
                return;
            }
            if l & IEXTEN != 0 && is(VWERASE, b) {
                while self.canon.last().is_some_and(|c| c.is_ascii_whitespace()) {
                    let c = self.canon.pop().unwrap();
                    self.erase_echo(c, fx);
                }
                while self.canon.last().is_some_and(|c| !c.is_ascii_whitespace()) {
                    let c = self.canon.pop().unwrap();
                    self.erase_echo(c, fx);
                }
                return;
            }
            if is(VKILL, b) {
                if l & ECHO != 0 && l & ECHOKE != 0 && l & ECHOE != 0 {
                    while let Some(c) = self.canon.pop() {
                        self.erase_echo(c, fx);
                    }
                } else {
                    self.canon.clear();
                    if l & ECHO != 0 {
                        self.echo_byte(b, fx);
                        if l & ECHOK != 0 {
                            self.echo_str(b"\n", fx);
                        }
                    }
                }
                return;
            }
            if l & IEXTEN != 0 && is(VREPRINT, b) {
                if l & ECHO != 0 {
                    self.echo_byte(b, fx);
                    self.echo_str(b"\n", fx);
                    let line = self.canon.clone();
                    for c in line {
                        self.echo_byte(c, fx);
                    }
                }
                return;
            }
            if is(VEOF, b) {
                self.finish_line(fx);
                return;
            }
        }
        if l & ECHO != 0 || (b == b'\n' && l & ECHONL != 0 && l & ICANON != 0) {
            self.echo_byte(b, fx);
        }
        self.store(b, fx);
    }

    /// Queues an input byte after editing.
    fn store(&mut self, b: u8, fx: &mut Effects) {
        if self.termios.c_lflag & ICANON != 0 {
            if self.canon.len() >= MAX_CANON {
                if self.termios.c_iflag & IMAXBEL != 0 {
                    self.echo_str(b"\x07", fx);
                }
                return;
            }
            self.canon.push(b);
            let cc = self.termios.c_cc;
            if b == b'\n' || (cc[VEOL] != VDISABLE && b == cc[VEOL]) || (cc[VEOL2] != VDISABLE && b == cc[VEOL2]) {
                self.finish_line(fx);
            }
        } else {
            if self.ready.len() >= TTYHOG {
                if self.termios.c_iflag & IMAXBEL != 0 {
                    self.echo_str(b"\x07", fx);
                }
                return;
            }
            self.ready.push_back(b);
            fx.wake_readers = true;
        }
    }

    /// Bytes a `read` could return now, without waiting (canonical mode: through the end of
    /// the first complete line).
    fn readable(&self) -> Option<usize> {
        if self.termios.c_lflag & ICANON != 0 {
            // Bytes queued before the switch to canonical mode read as they are.
            let lined: usize = self.lines.iter().sum();
            if self.ready.len() > lined {
                return Some(self.ready.len() - lined);
            }
            self.lines.front().copied()
        } else {
            (!self.ready.is_empty()).then_some(self.ready.len())
        }
    }

    /// Takes up to `buf.len()` of the readable bytes.
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let canonical = self.termios.c_lflag & ICANON != 0;
        let lined: usize = self.lines.iter().sum();
        let unlined = self.ready.len() - lined;
        if canonical && unlined == 0 {
            let Some(len) = self.lines.front().copied() else { return 0 };
            let n = len.min(buf.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.ready.pop_front().unwrap();
            }
            if n == len {
                self.lines.pop_front();
            } else {
                *self.lines.front_mut().unwrap() = len - n;
            }
            return n;
        }
        let limit = if canonical { unlined } else { self.ready.len() };
        let n = limit.min(buf.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.ready.pop_front().unwrap();
        }
        // Non-canonical reads consume across line boundaries.
        let mut consumed = n.saturating_sub(unlined);
        while consumed > 0 {
            let front = self.lines.front_mut().unwrap();
            let k = consumed.min(*front);
            *front -= k;
            consumed -= k;
            if *front == 0 {
                self.lines.pop_front();
            }
        }
        n
    }

    fn is_revoked(&self, sid: Pid) -> bool {
        self.revoked.contains(&sid)
    }
}

// --- the interface to devices and descriptors ------------------------------------------------

/// A byte from the device (keyboard, UART receive). Safe from interrupt context. Returns whether
/// a signal character sent a signal.
pub fn input(id: TtyId, bytes: &[u8]) -> bool {
    let mut fx = Effects::default();
    {
        let mut ttys = TTYS.lock();
        let t = &mut ttys[id];
        for &b in bytes {
            t.input(b, &mut fx);
            // A signal ends this batch: the rest belongs to whoever runs next.
            if fx.signal.is_some() {
                break;
            }
        }
    }
    let signaled = fx.signal.is_some();
    perform(id, fx);
    signaled
}

pub struct IoContext {
    pub pid: Pid,
    pub pgid: Pid,
    pub sid: Pid,
    pub nonblock: bool,
}

pub fn caller(nonblock: bool) -> IoContext {
    let pid = scheduler::current_pid();
    let table = process::table().lock();
    let p = table.get(&pid);
    IoContext {
        pid,
        pgid: p.map_or(0, |p| p.pgid),
        sid: p.map_or(0, |p| p.sid),
        nonblock,
    }
}

/// Kernel-internal: the syscall is restarted after a signal stops the caller or runs a
/// `SA_RESTART` handler, and fails with `EINTR` otherwise (`syscall_dispatch`).
pub const ERESTART: u64 = 512;

enum JobControl {
    Allowed,
    /// The caller was sent `sig`; restart the call once it continues.
    Signaled,
    Refused,
}

/// POSIX background-process rules (TTY.md §5.3): `sig` is `SIGTTIN` for reads and `SIGTTOU` for
/// writes and settings changes.
fn job_control(id: TtyId, cx: &IoContext, sig: u64) -> JobControl {
    let (session, pgrp) = with(id, |t| (t.session, t.pgrp));
    if session != Some(cx.sid) || pgrp.is_none() || pgrp == Some(cx.pgid) {
        return JobControl::Allowed;
    }
    let (ignored, blocked) = process::signal_disposition(cx.pid, sig);
    if ignored || blocked {
        return if sig == process::SIGTTIN { JobControl::Refused } else { JobControl::Allowed };
    }
    process::signal_foreground_group(cx.pgid, sig);
    stop_if_stopped(cx.pid);
    JobControl::Signaled
}

/// A process just stopped by its own action gives up the processor until it continues.
fn stop_if_stopped(pid: Pid) {
    let stopped = matches!(process::table().lock().get(&pid).map(|p| p.state), Some(ProcState::Stopped(_)));
    if stopped {
        scheduler::schedule();
    }
}

/// `read(2)` on a terminal.
pub fn read(id: TtyId, buf: &mut [u8], cx: &IoContext) -> Result<usize, u64> {
    let r = read_inner(id, buf, cx);
    if matches!(r, Ok(n) if n > 0) {
        driver(id).drained();
    }
    r
}

fn read_inner(id: TtyId, buf: &mut [u8], cx: &IoContext) -> Result<usize, u64> {
    if buf.is_empty() {
        return Ok(0);
    }
    // `VMIN == 0 && VTIME > 0`: the read timer runs from the first wait.
    let mut read_timer: Option<u64> = None;
    loop {
        match job_control(id, cx, process::SIGTTIN) {
            JobControl::Allowed => {}
            JobControl::Signaled => return Err(ERESTART),
            JobControl::Refused => return Err(crate::syscall::EIO),
        }
        let deadline = {
            let mut ttys = TTYS.lock();
            let t = &mut ttys[id];
            if t.is_revoked(cx.sid) {
                return Ok(0);
            }
            let canonical = t.termios.c_lflag & ICANON != 0;
            let (vmin, vtime) = (t.termios.c_cc[VMIN] as usize, t.termios.c_cc[VTIME] as u64);
            let avail = t.readable().unwrap_or(0);
            let now = crate::cpu::interrupts::ticks();
            let ticks_of = |tenths: u64| tenths * crate::cpu::pit::TIMER_HZ as u64 / 10;
            if canonical {
                if t.readable().is_some() {
                    return Ok(t.take(buf));
                }
                None
            } else if vmin == 0 && vtime == 0 {
                return Ok(t.take(buf));
            } else if vmin == 0 {
                // A read timer: data, or nothing after VTIME.
                if avail > 0 {
                    return Ok(t.take(buf));
                }
                if read_timer.is_some() && cx_timed_out(cx.pid) {
                    return Ok(0);
                }
                Some(*read_timer.get_or_insert(now + ticks_of(vtime)))
            } else {
                let want = vmin.min(buf.len());
                if avail >= want {
                    return Ok(t.take(buf));
                }
                if vtime > 0 && avail > 0 {
                    // An inter-byte timer, started by the first byte.
                    let due = t.last_input + ticks_of(vtime);
                    if now >= due {
                        return Ok(t.take(buf));
                    }
                    Some(due)
                } else {
                    None
                }
            }
        };
        if driver(id).hung_up() {
            return Ok(0);
        }
        if cx.nonblock {
            return Err(crate::syscall::EAGAIN);
        }
        if interrupted(cx.pid) {
            return Err(ERESTART);
        }
        block(cx.pid, BlockReason::WaitingForTty(id, deadline));
    }
}

/// A signal that runs a handler or ends the process is pending: a wait must stop.
fn interrupted(pid: Pid) -> bool {
    process::table().lock().get(&pid).is_some_and(|p| process::has_interrupting_signal(p))
}

/// Whether the caller's last wait on a terminal ended at its deadline.
fn cx_timed_out(pid: Pid) -> bool {
    process::table().lock().get(&pid).is_some_and(|p| p.tty_timed_out)
}

fn block(pid: Pid, reason: BlockReason) {
    {
        let mut table = process::table().lock();
        let p = table.get_mut(&pid).unwrap();
        p.tty_timed_out = false;
        p.state = ProcState::Blocked(reason);
    }
    scheduler::schedule();
}

/// `write(2)` on a terminal.
pub fn write(id: TtyId, bytes: &[u8], cx: &IoContext) -> Result<usize, u64> {
    loop {
        if with(id, |t| t.termios.c_lflag & TOSTOP != 0) {
            match job_control(id, cx, process::SIGTTOU) {
                JobControl::Signaled => return Err(ERESTART),
                _ => {}
            }
        }
        if driver(id).hung_up() {
            return Err(crate::syscall::EIO);
        }
        let room = driver(id).room();
        let mut raw = Vec::new();
        let mut cooked = Vec::new();
        {
            let mut ttys = TTYS.lock();
            let t = &mut ttys[id];
            if t.is_revoked(cx.sid) {
                return Err(crate::syscall::EIO);
            }
            if !t.stopped && room {
                raw.extend_from_slice(bytes);
                t.cook(bytes, &mut cooked);
            }
        }
        if !cooked.is_empty() || bytes.is_empty() {
            driver(id).output(&raw, &cooked);
            return Ok(bytes.len());
        }
        if cx.nonblock {
            return Err(crate::syscall::EAGAIN);
        }
        if interrupted(cx.pid) {
            return Err(ERESTART);
        }
        block(cx.pid, BlockReason::WaitingForTtyOutput(id));
    }
}

/// Kernel messages and other output not from a descriptor (the console, §2.3).
pub fn write_kernel(id: TtyId, bytes: &[u8]) {
    let mut cooked = Vec::new();
    with(id, |t| t.cook(bytes, &mut cooked));
    driver(id).output(bytes, &cooked);
}

/// `poll`/`select`: `(readable, writable)`.
pub fn poll_state(id: TtyId, sid: Pid) -> (bool, bool) {
    let ttys = TTYS.lock();
    let t = &ttys[id];
    if t.is_revoked(sid) {
        return (true, true);
    }
    let canonical = t.termios.c_lflag & ICANON != 0;
    let readable = if canonical { t.readable().is_some() } else { !t.ready.is_empty() };
    (readable, !t.stopped)
}

/// The timer interrupt: wakes terminal readers whose `VTIME` ran out.
pub fn expire_timers(table: &mut alloc::collections::BTreeMap<Pid, alloc::boxed::Box<process::Process>>, now: u64) {
    for (&pid, p) in table.iter_mut() {
        if let ProcState::Blocked(BlockReason::WaitingForTty(_, Some(deadline))) = p.state
            && now >= deadline
        {
            p.tty_timed_out = true;
            p.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}

// --- settings and control --------------------------------------------------------------------

pub fn termios(id: TtyId) -> RawTermios {
    with(id, |t| t.termios)
}

/// `tcsetattr`: `TCSANOW`, `TCSADRAIN` (output is written synchronously, so the same), or
/// `TCSAFLUSH` (`flush` discards pending input).
pub fn set_termios(id: TtyId, new: RawTermios, flush: bool, cx: &IoContext) -> Result<(), u64> {
    if let JobControl::Signaled = job_control(id, cx, process::SIGTTOU) {
        return Err(ERESTART);
    }
    let mut fx = Effects::default();
    {
        let mut ttys = TTYS.lock();
        let t = &mut ttys[id];
        let was_canonical = t.termios.c_lflag & ICANON != 0;
        let old_ixon = t.termios.c_iflag & IXON != 0;
        t.termios = new;
        if flush {
            t.flush_input();
        }
        if was_canonical && new.c_lflag & ICANON == 0 {
            // Leaving canonical mode: the pending line becomes readable input.
            let pending = core::mem::take(&mut t.canon);
            t.ready.extend(pending);
            t.lines.clear();
            fx.wake_readers = true;
        }
        if t.stopped && new.c_iflag & IXON == 0 {
            t.stopped = false;
            fx.wake_writers = true;
        }
        match (old_ixon, new.c_iflag & IXON != 0) {
            (true, false) => fx.pkt |= TIOCPKT_NOSTOP,
            (false, true) => fx.pkt |= TIOCPKT_DOSTOP,
            _ => {}
        }
    }
    driver(id).configure(&new);
    perform(id, fx);
    Ok(())
}

pub fn winsize(id: TtyId) -> Winsize {
    with(id, |t| t.winsize)
}

/// `TIOCSWINSZ`: a change sends `SIGWINCH` to the foreground process group (§5.5).
pub fn set_winsize(id: TtyId, ws: Winsize) {
    let pgrp = with(id, |t| {
        let changed = (t.winsize.ws_row, t.winsize.ws_col, t.winsize.ws_xpixel, t.winsize.ws_ypixel)
            != (ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
        t.winsize = ws;
        if changed { t.pgrp } else { None }
    });
    if let Some(pgrp) = pgrp {
        process::signal_foreground_group(pgrp, process::SIGWINCH);
    }
}

/// `TIOCSCTTY` (§5.1): a session leader without a controlling terminal takes this one, if no
/// other session has it. As in all three BSDs, there is no way to take it from another session.
pub fn set_controlling(id: TtyId, cx: &IoContext) -> Result<(), u64> {
    if cx.sid != cx.pid {
        return Err(crate::syscall::EPERM);
    }
    let mut ttys = TTYS.lock();
    if ttys.iter().any(|t| t.session == Some(cx.sid)) {
        // Already has one: only a no-op re-claim of the same terminal is allowed.
        return if ttys[id].session == Some(cx.sid) { Ok(()) } else { Err(crate::syscall::EPERM) };
    }
    let t = &mut ttys[id];
    if t.session.is_some() {
        return Err(crate::syscall::EPERM);
    }
    t.session = Some(cx.sid);
    t.pgrp = Some(cx.pgid);
    t.revoked.retain(|&s| s != cx.sid);
    Ok(())
}

/// Makes `id` the controlling terminal of `sid` with `pgrp` in the foreground, for the kernel's
/// own first process.
pub fn assign(id: TtyId, sid: Pid, pgrp: Pid) {
    with(id, |t| {
        t.session = Some(sid);
        t.pgrp = Some(pgrp);
        t.revoked.retain(|&s| s != sid);
    });
}

/// `TIOCNOTTY`: as in NetBSD and OpenBSD, a process other than the session leader may detach
/// from its controlling terminal -- which, with the terminal kept per session, changes nothing
/// -- and the session leader may not (`EINVAL`); it gives the terminal up by exiting (§5.4).
pub fn release(id: TtyId, cx: &IoContext) -> Result<(), u64> {
    if with(id, |t| t.session != Some(cx.sid)) {
        return Err(crate::syscall::ENOTTY);
    }
    if cx.sid == cx.pid {
        return Err(crate::syscall::EINVAL);
    }
    Ok(())
}

pub fn pgrp(id: TtyId, cx: &IoContext) -> Result<Pid, u64> {
    with(id, |t| if t.session == Some(cx.sid) { Ok(t.pgrp.unwrap_or(cx.sid)) } else { Err(crate::syscall::ENOTTY) })
}

pub fn session_of(id: TtyId, cx: &IoContext) -> Result<Pid, u64> {
    with(id, |t| if t.session == Some(cx.sid) { Ok(cx.sid) } else { Err(crate::syscall::ENOTTY) })
}

/// `TIOCSPGRP` (§5.2): only a process group of the terminal's own session.
pub fn set_pgrp(id: TtyId, pgid: Pid, cx: &IoContext) -> Result<(), u64> {
    if with(id, |t| t.session != Some(cx.sid)) {
        return Err(crate::syscall::ENOTTY);
    }
    let in_session = process::table().lock().values().any(|p| p.pgid == pgid && p.sid == cx.sid);
    if !in_session {
        return Err(crate::syscall::EPERM);
    }
    if let JobControl::Signaled = job_control(id, cx, process::SIGTTOU) {
        return Err(ERESTART);
    }
    with(id, |t| t.pgrp = Some(pgid));
    Ok(())
}

pub fn pending_input(id: TtyId) -> usize {
    with(id, |t| if t.termios.c_lflag & ICANON != 0 { t.readable().unwrap_or(0) } else { t.ready.len() })
}

/// `TCFLSH`: `0` input, `1` output (nothing is ever queued), `2` both.
pub fn flush(id: TtyId, which: u64) -> Result<(), u64> {
    let bits = match which {
        0 => TIOCPKT_FLUSHREAD,
        1 => TIOCPKT_FLUSHWRITE,
        2 => TIOCPKT_FLUSHREAD | TIOCPKT_FLUSHWRITE,
        _ => return Err(crate::syscall::EINVAL),
    };
    if bits & TIOCPKT_FLUSHREAD != 0 {
        with(id, |t| t.flush_input());
    }
    driver(id).status(bits);
    Ok(())
}

/// `TCXONC`: `0` stop output, `1` restart it, `2`/`3` send STOP/START.
pub fn flow(id: TtyId, action: u64) -> Result<(), u64> {
    match action {
        0 => {
            with(id, |t| t.stopped = true);
            driver(id).status(TIOCPKT_STOP);
        }
        1 => {
            with(id, |t| t.stopped = false);
            wake(id, false, true);
            driver(id).status(TIOCPKT_START);
        }
        2 | 3 => {
            let c = with(id, |t| t.termios.c_cc[if action == 2 { VSTOP } else { VSTART }]);
            if c != VDISABLE {
                driver(id).output(&[c], &[c]);
            }
        }
        _ => return Err(crate::syscall::EINVAL),
    }
    Ok(())
}

/// A session leader exited: its controlling terminal is hung up (§5.4).
pub fn session_leader_exited(sid: Pid) {
    let hit = {
        let mut ttys = TTYS.lock();
        ttys.iter_mut().position(|t| t.session == Some(sid)).map(|id| {
            let t = &mut ttys[id];
            let pgrp = t.pgrp;
            t.session = None;
            t.pgrp = None;
            t.revoked.push(sid);
            t.flush_input();
            (id, pgrp)
        })
    };
    if let Some((id, pgrp)) = hit {
        if let Some(pgrp) = pgrp {
            process::signal_foreground_group(pgrp, process::SIGHUP);
            process::signal_foreground_group(pgrp, process::SIGCONT);
        }
        wake(id, true, true);
    }
}

/// A description of `id` was opened or closed.
pub fn opened(id: TtyId) {
    with(id, |t| t.opens += 1);
}

pub fn closed(id: TtyId) {
    let (last, hangup) = with(id, |t| {
        t.opens = t.opens.saturating_sub(1);
        (t.opens == 0, t.opens == 0 && t.termios.c_cflag & HUPCL != 0)
    });
    if hangup {
        driver(id).hangup();
    }
    if last {
        driver(id).last_close();
    }
}

/// The far end of terminal `id` went away (a pseudo-terminal's master was closed, `PTY.md`
/// §3.3), as a modem hangup: the session it controls is revoked and gets `SIGHUP` and `SIGCONT`,
/// in its foreground process group and its leader.
pub fn hang_up(id: TtyId) {
    let (session, pgrp) = with(id, |t| {
        let s = (t.session, t.pgrp);
        if let Some(sid) = t.session {
            t.revoked.push(sid);
        }
        t.session = None;
        t.pgrp = None;
        t.flush_input();
        s
    });
    for target in [pgrp, session].into_iter().flatten() {
        process::signal_foreground_group(target, process::SIGHUP);
        process::signal_foreground_group(target, process::SIGCONT);
    }
    wake(id, true, true);
}

/// `input` without stopping at a signal character: a pseudo-terminal master's write is data
/// that must all arrive (`PTY.md` §4.2).
pub fn input_all(id: TtyId, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        let mut fx = Effects::default();
        let used = {
            let mut ttys = TTYS.lock();
            let t = &mut ttys[id];
            let mut used = 0;
            for &b in rest {
                t.input(b, &mut fx);
                used += 1;
                if fx.signal.is_some() {
                    break;
                }
            }
            used
        };
        perform(id, fx);
        rest = &rest[used..];
    }
}

/// Room left in terminal `id`'s input queue, for a pseudo-terminal's master (`PTY.md` §4.2).
pub fn input_room(id: TtyId) -> usize {
    with(id, |t| TTYHOG.saturating_sub(t.ready.len() + t.canon.len()))
}

/// The foreground process group of terminal `id`, for `TIOCSIG`.
pub fn foreground(id: TtyId) -> Option<Pid> {
    with(id, |t| t.pgrp)
}

/// With the keyboard owned by the screen's owner (`console::raw_keyboard_owned`), only the
/// signal characters still act (§7.2). Returns whether one sent a signal.
pub fn signal_character(id: TtyId, b: u8) -> bool {
    let sig = with(id, |t| {
        let (l, cc) = (t.termios.c_lflag, t.termios.c_cc);
        let is = |c: usize| cc[c] != VDISABLE && cc[c] == b;
        if l & ISIG == 0 {
            None
        } else if is(VINTR) {
            Some(process::SIGINT)
        } else if is(VQUIT) {
            Some(process::SIGQUIT)
        } else if is(VSUSP) {
            Some(process::SIGTSTP)
        } else {
            None
        }
        .zip(t.pgrp)
    });
    if let Some((sig, pgrp)) = sig {
        process::signal_foreground_group(pgrp, sig);
        return true;
    }
    false
}

// --- descriptors (TTY.md §6) -------------------------------------------------------------------

/// One terminal description (`real_fd`): which terminal, and the access it was opened with.
#[derive(Clone, Copy)]
struct TtyFd {
    id: TtyId,
    readable: bool,
    writable: bool,
}

static FDS: Mutex<alloc::collections::BTreeMap<u64, TtyFd>> = Mutex::new(alloc::collections::BTreeMap::new());

pub fn of_real_fd(real_fd: u64) -> Option<TtyId> {
    FDS.lock().get(&real_fd).map(|f| f.id)
}

fn to_ffi(r: Result<usize, u64>) -> i64 {
    match r {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

pub(crate) extern "C" fn fd_read(real_fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(f) = FDS.lock().get(&real_fd).copied() else { return -(crate::syscall::EBADF as i64) };
    if !f.readable {
        return -(crate::syscall::EBADF as i64);
    }
    // SAFETY: the unvalidated-user-pointer gap every read path has.
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
    to_ffi(read(f.id, buf, &caller(crate::fs::fd::is_nonblocking(real_fd))))
}

pub(crate) extern "C" fn fd_write(real_fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(f) = FDS.lock().get(&real_fd).copied() else { return -(crate::syscall::EBADF as i64) };
    if !f.writable {
        return -(crate::syscall::EBADF as i64);
    }
    // SAFETY: as fd_read.
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    to_ffi(write(f.id, bytes, &caller(crate::fs::fd::is_nonblocking(real_fd))))
}

pub(crate) extern "C" fn fd_close(real_fd: u64) -> i64 {
    if let Some(f) = FDS.lock().remove(&real_fd) {
        closed(f.id);
    }
    0
}

/// `F_GETFL`'s access mode (`fs::fd::FdAccessMode`: bit 0 readable, bit 1 writable).
extern "C" fn fd_access_mode(real_fd: u64) -> i64 {
    FDS.lock().get(&real_fd).map_or(0, |f| f.readable as i64 | (f.writable as i64) << 1)
}

/// Makes `real_fd` a read-write description of `id`.
pub fn bind(real_fd: u64, id: TtyId) {
    bind_with(real_fd, id, true, true);
}

fn bind_with(real_fd: u64, id: TtyId, readable: bool, writable: bool) {
    FDS.lock().insert(real_fd, TtyFd { id, readable, writable });
    opened(id);
}

/// `/dev/tty` (TTY.md §2.4, §2.6).
pub const CTTY_DEVICE: (u32, u32) = (5, 0);
/// `/dev/console` (§2.3); `ttyv0` until the console becomes a device of its own (§10.2, slice 5).
pub const CONSOLE_DEVICE: (u32, u32) = (5, 1);

/// `open(2)` of a terminal device node (`sys/modules/oxfs`'s `InodeKind::Device` dispatch, the
/// way FIFOs go through `oxidebsd_fifo_open`): a new description of the terminal numbered
/// `major:minor`, in the calling process. Returns its fd, or `-ENXIO` if no such terminal exists
/// -- for `/dev/tty`, if the caller has no controlling terminal. `O_NOCTTY` has nothing to
/// suppress: opening never makes a terminal controlling (§5.1).
pub(crate) extern "C" fn oxidebsd_tty_open(major: u64, minor: u64, flags: u64) -> i64 {
    const O_ACCMODE: u64 = 3;
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_NONBLOCK: u64 = 0o4000;
    let enxio = -(crate::syscall::ENXIO as i64);
    let dev = (major as u32, minor as u32);
    let id = if dev == CTTY_DEVICE {
        match controlling(caller(false).sid) {
            Some(id) => id,
            None => return enxio,
        }
    } else if dev == CONSOLE_DEVICE {
        TTYV0
    } else {
        match find(dev.0, dev.1) {
            Some(id) => id,
            None => return enxio,
        }
    };
    let (readable, writable) = match flags & O_ACCMODE {
        O_WRONLY => (false, true),
        O_RDWR => (true, true),
        _ => (true, false),
    };
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -e;
    }
    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    bind_with(real_fd, id, readable, writable);
    if flags & O_NONBLOCK != 0 {
        crate::fs::fd::set_nonblocking(real_fd, true);
    }
    let fd = crate::fs::fd::oxidebsd_register_fd_ops(real_fd, fd_read, fd_write, fd_close);
    crate::fs::fd::oxidebsd_set_fd_access_mode(real_fd, fd_access_mode);
    fd
}
