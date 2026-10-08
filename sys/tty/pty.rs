//! Pseudo-terminals (`OxideBSD-doc/PTY.md`). Opening `/dev/ptmx` creates a pair: a master
//! descriptor, here, and a slave terminal `/dev/pts/N`, an ordinary `Tty` whose driver
//! (`PtsDriver`) queues its output for the master. Writing the master is the slave's input.
//!
//! Lock order: never hold `PAIRS` while calling into the terminal layer (`super::*`), which
//! takes `TTYS` and calls drivers, whose methods take `PAIRS`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use super::{Driver, TtyId, Winsize, B38400};
use crate::kern::subr_uio::Uio;
use crate::process::{self, scheduler, BlockReason, Pid, ProcState};
use crate::syscall::{EAGAIN, EINTR, EINVAL, EIO, ENOTTY};

/// `/dev/ptmx` (§2.1).
pub const PTMX_DEVICE: (u32, u32) = (5, 2);
/// `/dev/pts/N` is `PTS_MAJOR:N` (§2.2).
pub const PTS_MAJOR: u32 = 136;
/// Output queued for the master before a slave writer waits (§4.1).
const OUTQ_MAX: usize = 8192;

/// `kern.tty.pty_max` (§2.4).
pub static PTY_MAX: AtomicU32 = AtomicU32::new(256);

struct Pair {
    /// The slave terminal, registered once per number and reused.
    slave: TtyId,
    used: bool,
    /// Opening the slave fails until `unlockpt` (§3.1).
    locked: bool,
    master_open: bool,
    slave_opened: bool,
    /// Slave output waiting for the master.
    out: VecDeque<u8>,
    /// `TIOCPKT` (§5.3) and the events not yet reported.
    packet: bool,
    status: u8,
}

static PAIRS: Mutex<Vec<Pair>> = Mutex::new(Vec::new());
/// Master descriptions: `real_fd` to pair number.
static MASTERS: Mutex<BTreeMap<u64, usize>> = Mutex::new(BTreeMap::new());

/// The slave terminal's driver.
struct PtsDriver {
    n: usize,
}

impl PtsDriver {
    fn slave(&self) -> TtyId {
        PAIRS.lock()[self.n].slave
    }
}

impl Driver for PtsDriver {
    fn output(&self, _raw: &[u8], cooked: &[u8]) {
        let slave = {
            let mut pairs = PAIRS.lock();
            let p = &mut pairs[self.n];
            if !p.master_open {
                return;
            }
            p.out.extend(cooked);
            p.slave
        };
        super::wake(slave, true, false);
    }

    fn room(&self) -> bool {
        let pairs = PAIRS.lock();
        let p = &pairs[self.n];
        !p.master_open || p.out.len() < OUTQ_MAX
    }

    fn hung_up(&self) -> bool {
        !PAIRS.lock()[self.n].master_open
    }

    fn last_close(&self) {
        // The master reads end-of-file now (§3.4).
        super::wake(self.slave(), true, true);
        maybe_free(self.n);
    }

    fn drained(&self) {
        // A master writer may be waiting for room in the slave's input (§4.2).
        super::wake(self.slave(), false, true);
    }

    fn status(&self, bits: u8) {
        let wake = {
            let mut pairs = PAIRS.lock();
            let p = &mut pairs[self.n];
            if bits & super::TIOCPKT_FLUSHWRITE != 0 {
                p.out.clear();
            }
            if p.packet {
                p.status |= bits;
            }
            p.packet.then_some(p.slave)
        };
        if let Some(slave) = wake {
            super::wake(slave, true, false);
        }
    }
}

/// Makes `/dev/ptmx`; called once at boot, after the console.
pub fn init() {
    let _ = crate::fs::devfs::make_dev("ptmx", PTMX_DEVICE.0, PTMX_DEVICE.1, 0, 0, 0o666, ptmx_open);
}

fn slave_closed(p_slave: TtyId, slave_opened: bool) -> bool {
    slave_opened && super::with(p_slave, |t| t.opens) == 0
}

/// Frees pair `n` once both sides are closed (§3.5).
fn maybe_free(n: usize) {
    let (free, slave) = {
        let pairs = PAIRS.lock();
        let p = &pairs[n];
        (p.used && !p.master_open, p.slave)
    };
    if free && super::with(slave, |t| t.opens) == 0 {
        let _ = crate::fs::devfs::destroy_dev(PTS_MAJOR, n as u32);
        PAIRS.lock()[n].used = false;
    }
}

/// Opening `/dev/ptmx`: a new pair, and its master as a descriptor of the caller's (§2.1).
extern "C" fn ptmx_open(_major: u64, _minor: u64, flags: u64) -> i64 {
    const O_NONBLOCK: u64 = 0o4000;
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -(e as i64);
    }
    // The lowest free number, registering a new slave terminal if none can be reused.
    let max = PTY_MAX.load(Ordering::Relaxed) as usize;
    let reuse = PAIRS.lock().iter().position(|p| !p.used);
    let n = match reuse {
        Some(n) => {
            super::reset(PAIRS.lock()[n].slave, B38400);
            n
        }
        None => {
            let n = PAIRS.lock().len();
            if n >= max {
                return -(EAGAIN as i64);
            }
            let name: &'static str = Box::leak(format!("pts/{n}").into_boxed_str());
            let driver: &'static PtsDriver = Box::leak(Box::new(PtsDriver { n }));
            let slave = super::register_bare(name, PTS_MAJOR, n as u32, B38400, Winsize::default(), driver);
            PAIRS.lock().push(Pair {
                slave,
                used: false,
                locked: true,
                master_open: false,
                slave_opened: false,
                out: VecDeque::new(),
                packet: false,
                status: 0,
            });
            n
        }
    };
    if n >= max {
        return -(EAGAIN as i64);
    }
    {
        let mut pairs = PAIRS.lock();
        let p = &mut pairs[n];
        p.used = true;
        p.locked = true;
        p.master_open = true;
        p.slave_opened = false;
        p.out.clear();
        p.packet = false;
        p.status = 0;
    }
    // §2.3: the opener's, 0600.
    let owner = crate::process::identity::current_cred().ruid;
    let name = format!("pts/{n}");
    let _ = crate::fs::devfs::make_dev(&name, PTS_MAJOR, n as u32, owner, super::TTY_GID, 0o600, pts_open);

    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    MASTERS.lock().insert(real_fd, n);
    if flags & O_NONBLOCK != 0 {
        crate::fs::fd::set_nonblocking(real_fd, true);
    }
    crate::fs::fd::oxidebsd_register_fd_ops(real_fd, master_read, master_write, master_close)
}

/// Opening `/dev/pts/N`: refused while the pair is locked (§3.1), else an ordinary terminal open.
extern "C" fn pts_open(major: u64, minor: u64, flags: u64) -> i64 {
    {
        let mut pairs = PAIRS.lock();
        match pairs.get_mut(minor as usize) {
            Some(p) if p.used && !p.locked && p.master_open => p.slave_opened = true,
            _ => return -(EIO as i64),
        }
    }
    super::oxidebsd_tty_open(major, minor, flags)
}

fn pair_of(real_fd: u64) -> Option<usize> {
    MASTERS.lock().get(&real_fd).copied()
}

/// Gives up the processor until something wakes the caller (`reason`), as the terminal layer's
/// waits do.
fn block(pid: Pid, reason: BlockReason) {
    {
        let mut table = process::table().lock();
        if let Some(p) = table.get_mut(&pid) {
            p.tty_timed_out = false;
            p.state = ProcState::Blocked(reason);
        }
    }
    scheduler::schedule();
}

fn interrupted(pid: Pid) -> bool {
    process::table().lock().get(&pid).is_some_and(|p| process::has_interrupting_signal(p))
}

/// Reading the master: the slave's output (§4.1), in packet mode framed by a status byte (§5.3).
extern "C" fn master_read(real_fd: u64, uio: *mut Uio, _flags: u64) -> i64 {
    let Some(n) = pair_of(real_fd) else { return -(crate::syscall::EBADF as i64) };
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    super::read_uio(uio, |buf| ffi_result(master_read_into(real_fd, n, buf)))
}

/// `-errno` or a count, as a `Result`.
fn ffi_result(r: i64) -> Result<usize, u64> {
    if r < 0 { Err(-r as u64) } else { Ok(r as usize) }
}

fn master_read_into(real_fd: u64, n: usize, buf: &mut [u8]) -> i64 {
    if buf.is_empty() {
        return 0;
    }
    let pid = scheduler::current_pid();
    loop {
        let (slave, slave_opened) = {
            let pairs = PAIRS.lock();
            (pairs[n].slave, pairs[n].slave_opened)
        };
        let gone = slave_closed(slave, slave_opened);
        let got = {
            let mut pairs = PAIRS.lock();
            let p = &mut pairs[n];
            if p.packet && p.status != 0 {
                buf[0] = core::mem::take(&mut p.status);
                Some(1)
            } else if !p.out.is_empty() {
                let start = p.packet as usize;
                if start == 1 {
                    buf[0] = 0;
                }
                let k = (buf.len() - start).min(p.out.len());
                for (dst, b) in buf[start..start + k].iter_mut().zip(p.out.drain(..k)) {
                    *dst = b;
                }
                Some(start + k)
            } else {
                None
            }
        };
        if let Some(k) = got {
            // Room in the output queue: a slave writer may continue.
            super::wake(slave, false, true);
            return k as i64;
        }
        if gone {
            return 0;
        }
        if crate::fs::fd::is_nonblocking(real_fd) {
            return -(EAGAIN as i64);
        }
        if interrupted(pid) {
            return -(EINTR as i64);
        }
        block(pid, BlockReason::WaitingForTty(slave, None));
    }
}

/// Writing the master: the slave's input (§4.2), as much as its input queue has room for.
extern "C" fn master_write(real_fd: u64, uio: *mut Uio, _flags: u64) -> i64 {
    let Some(n) = pair_of(real_fd) else { return -(crate::syscall::EBADF as i64) };
    // SAFETY: as master_read.
    let uio = unsafe { &mut *uio };
    super::write_uio(uio, |bytes| ffi_result(master_write_from(real_fd, n, bytes)))
}

fn master_write_from(real_fd: u64, n: usize, bytes: &[u8]) -> i64 {
    let pid = scheduler::current_pid();
    loop {
        let (slave, slave_opened) = {
            let pairs = PAIRS.lock();
            (pairs[n].slave, pairs[n].slave_opened)
        };
        if slave_closed(slave, slave_opened) {
            return -(EIO as i64);
        }
        if bytes.is_empty() {
            return 0;
        }
        let room = super::input_room(slave);
        if room > 0 {
            let k = room.min(bytes.len());
            super::input_all(slave, &bytes[..k]);
            return k as i64;
        }
        if crate::fs::fd::is_nonblocking(real_fd) {
            return -(EAGAIN as i64);
        }
        if interrupted(pid) {
            return -(EINTR as i64);
        }
        block(pid, BlockReason::WaitingForTtyOutput(slave));
    }
}

/// Closing the master: the slave is hung up (§3.3), and the pair freed if the slave is closed too.
extern "C" fn master_close(real_fd: u64) -> i64 {
    let Some(n) = MASTERS.lock().remove(&real_fd) else { return 0 };
    let slave = {
        let mut pairs = PAIRS.lock();
        let p = &mut pairs[n];
        p.master_open = false;
        p.out.clear();
        p.slave
    };
    super::hang_up(slave);
    maybe_free(n);
    0
}

/// `poll`/`select` on a master (§4.4); `None` if `real_fd` isn't one.
pub(crate) fn readiness(real_fd: u64) -> Option<crate::fs::Readiness> {
    let n = pair_of(real_fd)?;
    let (slave, slave_opened, queued) = {
        let pairs = PAIRS.lock();
        let p = &pairs[n];
        (p.slave, p.slave_opened, !p.out.is_empty() || (p.packet && p.status != 0))
    };
    let gone = slave_closed(slave, slave_opened);
    Some(crate::fs::Readiness {
        readable: queued || gone,
        writable: !gone && super::input_room(slave) > 0,
        hangup: gone,
        ..Default::default()
    })
}

/// Requests on a master (§5); `None` if `real_fd` isn't one. Settings and window size requests act
/// on the slave.
pub(crate) fn ioctl(real_fd: u64, request: u64, argp: u64) -> Option<Result<u64, u64>> {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541B;
    const TIOCPKT: u64 = 0x5420;
    const TIOCGPTN: u64 = 0x8004_5430;
    const TIOCSPTLCK: u64 = 0x4004_5431;
    const TIOCSIG: u64 = 0x4004_5436;
    let n = pair_of(real_fd)?;
    let slave = PAIRS.lock()[n].slave;
    // SAFETY (each access through `argp`): the unvalidated-user-pointer gap every ioctl has.
    let r = match request {
        TIOCGPTN => {
            unsafe { *(argp as *mut u32) = n as u32 };
            Ok(0)
        }
        TIOCSPTLCK => {
            let lock = unsafe { *(argp as *const i32) } != 0;
            PAIRS.lock()[n].locked = lock;
            Ok(0)
        }
        TIOCPKT => {
            let on = unsafe { *(argp as *const i32) } != 0;
            let mut pairs = PAIRS.lock();
            pairs[n].packet = on;
            pairs[n].status = 0;
            Ok(0)
        }
        TIOCSIG => {
            let sig = argp;
            if sig == 0 || sig > 64 {
                Err(EINVAL)
            } else {
                if let Some(pgrp) = super::foreground(slave) {
                    process::signal_foreground_group(pgrp, sig);
                }
                Ok(0)
            }
        }
        FIONREAD => {
            let queued = PAIRS.lock()[n].out.len();
            unsafe { *(argp as *mut i32) = queued as i32 };
            Ok(0)
        }
        TCGETS => {
            unsafe { *(argp as *mut super::RawTermios) = super::termios(slave) };
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let t = unsafe { *(argp as *const super::RawTermios) };
            let cx = super::caller(crate::fs::fd::is_nonblocking(real_fd));
            super::set_termios(slave, t, request == TCSETSF, &cx).map(|()| 0)
        }
        TIOCGWINSZ => {
            unsafe { *(argp as *mut Winsize) = super::winsize(slave) };
            Ok(0)
        }
        TIOCSWINSZ => {
            super::set_winsize(slave, unsafe { *(argp as *const Winsize) });
            Ok(0)
        }
        _ => Err(ENOTTY),
    };
    Some(r)
}
