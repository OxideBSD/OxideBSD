//! The kernel message buffer and `/dev/klog` (OxideBSD-doc `SYSLOG.md` §§3-4).
//!
//! Every kernel print (`console::serial::_print`, which the modules' `oxidebsd_log` also goes
//! through) is copied into a circular buffer of `kern.msgbufsize` bytes, the oldest bytes giving
//! way when it's full. `kern.msgbuf` reads the whole of it for `dmesg(8)`; `/dev/klog` reads it
//! once, consuming, for `syslogd(8)`. User output to the console takes another path
//! (`tty::console`) and never lands here: user space can't write to this buffer.
//!
//! Kernel messages start before the heap exists, so they go first into a small static buffer,
//! moved into the real one by `init` once the heap is up.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::Mutex;

use crate::fs::Readiness;
use crate::kern::subr_uio::Uio;
use crate::syscall::{EAGAIN, EBADF};
use crate::tty::ERESTART;

const EBUSY: i64 = 16;
const EOPNOTSUPP: i64 = 95;

/// `kern.msgbufsize`'s default (`SYSCTL.md` §6.3).
pub(crate) const DEFAULT_SIZE: usize = 64 * 1024;
/// `kern.msgbufsize`: fixed at boot (a tunable), before `init`.
pub(crate) static SIZE: AtomicUsize = AtomicUsize::new(DEFAULT_SIZE);

/// What's held before the heap exists; the first boot messages fit easily.
const EARLY_SIZE: usize = 16 * 1024;

struct MsgBuf {
    early: [u8; EARLY_SIZE],
    /// The real buffer, once `init` has run.
    heap: Option<Vec<u8>>,
    /// Bytes ever written: the next byte goes at `written % capacity`.
    written: u64,
    /// `kern.msgbuf_clear`: `kern.msgbuf` shows nothing written before this.
    cleared: u64,
    /// How far `/dev/klog` has read.
    klog: u64,
}

impl MsgBuf {
    fn store(&mut self) -> &mut [u8] {
        match &mut self.heap {
            Some(v) => v,
            None => &mut self.early,
        }
    }

    fn capacity(&self) -> u64 {
        self.heap.as_ref().map_or(EARLY_SIZE, |v| v.len()) as u64
    }

    fn put(&mut self, bytes: &[u8]) {
        let cap = self.capacity();
        for &b in bytes {
            let at = (self.written % cap) as usize;
            self.store()[at] = b;
            self.written += 1;
        }
    }

    /// Where the oldest byte still held is, for a reader at `from`.
    fn start(&self, from: u64) -> u64 {
        from.max(self.written.saturating_sub(self.capacity()))
    }

    /// At most `max` bytes still held from byte `from` on, and the position after them.
    fn read_from(&self, from: u64, max: usize) -> (Vec<u8>, u64) {
        let cap = self.capacity();
        let start = self.start(from);
        let end = self.written.min(start.saturating_add(max as u64));
        let store: &[u8] = self.heap.as_deref().unwrap_or(&self.early);
        let out = (start..end).map(|i| store[(i % cap) as usize]).collect();
        (out, end)
    }
}

static MSGBUF: Mutex<MsgBuf> =
    Mutex::new(MsgBuf { early: [0; EARLY_SIZE], heap: None, written: 0, cleared: 0, klog: 0 });

/// Runs `f` on the buffer with interrupts off, so an interrupt handler that prints can't find it
/// locked by the code it interrupted.
fn with<R>(f: impl FnOnce(&mut MsgBuf) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut MSGBUF.lock()))
}

/// Moves the early messages into a buffer of `kern.msgbufsize` bytes. Once, after the heap.
/// `/dev/klog`'s device number (`DEVFS.md` §3.5).
pub const KLOG_DEVICE: (u32, u32) = (7, 0);

extern "C" fn dev_open(_major: u64, _minor: u64, flags: u64) -> i64 {
    oxidebsd_klog_open(flags)
}

pub(crate) fn init() {
    let _ = crate::fs::devfs::make_dev("klog", KLOG_DEVICE.0, KLOG_DEVICE.1, 0, 0, 0o600, dev_open);
    with(|m| {
        let (early, _) = m.read_from(0, EARLY_SIZE);
        m.heap = Some(vec![0; SIZE.load(Ordering::Relaxed)]);
        m.written = 0;
        m.cleared = 0;
        m.klog = 0;
        m.put(&early);
    });
}

struct Writer<'a>(&'a mut MsgBuf);

impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.put(s.as_bytes());
        Ok(())
    }
}

/// Records one kernel print. A print made while the buffer is locked (a panic inside this module)
/// is left out rather than deadlocking.
pub(crate) fn log(args: fmt::Arguments) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        if let Some(mut m) = MSGBUF.try_lock() {
            let _ = fmt::Write::write_fmt(&mut Writer(&mut m), args);
        }
    });
}

/// `kern.msgbuf`: the whole buffer since the last clear, NUL-terminated.
pub(crate) fn contents() -> Vec<u8> {
    let mut v = with(|m| m.read_from(m.cleared, usize::MAX).0);
    v.push(0);
    v
}

/// `kern.msgbuf_clear`.
pub(crate) fn clear() {
    with(|m| m.cleared = m.written);
}

// ---- /dev/klog ----

/// Whether `/dev/klog` is open: it's exclusive (`SYSLOG.md` §4.2).
static KLOG_OPEN: AtomicBool = AtomicBool::new(false);
/// The open `/dev/klog`'s `real_fd`, for `readiness`.
static KLOG_FD: Mutex<Option<u64>> = Mutex::new(None);

const O_NONBLOCK: u64 = 0o4000;

/// Opens `/dev/klog` (oxfs hands its device node here, having checked its permissions): the new
/// descriptor, or `-EBUSY` if it's already open.
pub(crate) extern "C" fn oxidebsd_klog_open(flags: u64) -> i64 {
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -e;
    }
    if KLOG_OPEN.swap(true, Ordering::AcqRel) {
        return -EBUSY;
    }
    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    *KLOG_FD.lock() = Some(real_fd);
    let fd = crate::fs::fd::oxidebsd_register_fd_ops(real_fd, klog_read, klog_write, klog_close);
    if flags & O_NONBLOCK != 0 {
        crate::fs::fd::set_nonblocking(real_fd, true);
    }
    fd
}

/// Reads what the buffer holds past the reader's position, advancing it; waits when there's
/// nothing, woken every 50 ms to look again (a kernel print can't take the locks a wakeup needs).
extern "C" fn klog_read(real_fd: u64, uio: *mut Uio, _flags: u64) -> i64 {
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let len = uio.resid();
    loop {
        // Resumes at the oldest byte held if unread ones were overwritten (`SYSLOG.md` §4.3).
        let data = with(|m| {
            let (data, end) = m.read_from(m.klog, len as usize);
            m.klog = end;
            data
        });
        // Copied with the buffer unlocked: touching the caller's memory may fault in a stack
        // page, and the fault path prints.
        if !data.is_empty() || len == 0 {
            return match uio.uiomove_out(&data) {
                Ok(n) => n as i64,
                Err(e) => -(e as i64),
            };
        }
        if crate::fs::fd::is_nonblocking(real_fd) {
            return -(EAGAIN as i64);
        }
        if crate::net::wait_for_change(true, u64::MAX).is_err() {
            return -(ERESTART as i64);
        }
    }
}

extern "C" fn klog_write(_real_fd: u64, _uio: *mut Uio, _flags: u64) -> i64 {
    -EOPNOTSUPP
}

extern "C" fn klog_close(real_fd: u64) -> i64 {
    let mut fd = KLOG_FD.lock();
    if *fd != Some(real_fd) {
        return -(EBADF as i64);
    }
    *fd = None;
    KLOG_OPEN.store(false, Ordering::Release);
    0
}

/// `poll(2)` state of `real_fd` if it's `/dev/klog`: readable when there's unread data.
pub(crate) fn readiness(real_fd: u64) -> Option<Readiness> {
    if *KLOG_FD.lock() != Some(real_fd) {
        return None;
    }
    let readable = with(|m| m.start(m.klog) < m.written);
    Some(Readiness { readable, ..Default::default() })
}
