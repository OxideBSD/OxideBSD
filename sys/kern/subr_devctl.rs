//! Device events and `/dev/devctl` (OxideBSD-doc `DEVD.md` §§3-4).
//!
//! The kernel reports each device change -- a disk attached or detached, a `/dev` node made or
//! removed, a CD's disc found or gone, the root's drive lost -- as one text line, `verb class
//! name=value ...`, its values quoted as sh quotes them (§3.2), so a device's own strings can't
//! forge fields or lines. The lines wait in a bounded queue, filled from boot whether or not
//! anyone reads it (the oldest dropped when it's full, and counted); `/dev/devctl`, opened by one
//! reader at a time (`devd(8)`), takes them off its front. Closing it keeps the queue (less the
//! rest of a line read in part).
//!
//! An event is made in a system call or a kernel thread, never in an interrupt handler (it
//! allocates), and never under the process table's lock (it wakes the reader through it).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use spin::Mutex;

use crate::fs::Readiness;
use crate::kern::subr_uio::Uio;
use crate::syscall::{EACCES, EAGAIN, EBADF, EBUSY};
use crate::tty::ERESTART;

/// `/dev/devctl`'s device number (`DEVFS.md` §3.5).
pub const DEVCTL_DEVICE: (u32, u32) = (7, 1);

/// `kern.devctl.queue`'s default and least value (§4.3).
pub(crate) const DEFAULT_QUEUE: usize = 256;
pub(crate) const MIN_QUEUE: usize = 16;
/// `kern.devctl.queue`: how many lines the queue holds.
pub(crate) static QUEUE_MAX: AtomicUsize = AtomicUsize::new(DEFAULT_QUEUE);
/// `kern.devctl.dropped`: lines dropped since boot.
pub(crate) static DROPPED: AtomicU64 = AtomicU64::new(0);

struct Queue {
    /// Whole lines, newline included, oldest first.
    lines: VecDeque<String>,
    /// Lines dropped since the reader was last told (`lost devctl count=`).
    lost: u64,
    /// What's left of the line a `read` gave in part: the reader's, so a drop can't cut it.
    partial: Vec<u8>,
}

static QUEUE: Mutex<Queue> = Mutex::new(Queue { lines: VecDeque::new(), lost: 0, partial: Vec::new() });

/// Whether a value can be written bare (§3.2).
fn bare(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_./:+-,@%".contains(&b))
}

/// An event being built: `event(verb, class).field(..)....post()`.
pub(crate) struct Event(String);

/// Starts an event. `verb` and `class` are lower-case words (§3.1).
pub(crate) fn event(verb: &str, class: &str) -> Event {
    let mut line = String::new();
    let _ = write!(line, "{verb} {class}");
    Event(line)
}

impl Event {
    /// Adds field `name` (a lower-case shell name) with `value`, quoted if it needs it; a control
    /// character in it is written `?`.
    pub(crate) fn field(mut self, name: &str, value: impl fmt::Display) -> Self {
        let mut v = String::new();
        let _ = write!(v, "{value}");
        let v: String = v.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
        self.0.push(' ');
        self.0.push_str(name);
        self.0.push('=');
        if bare(&v) {
            self.0.push_str(&v);
        } else {
            self.0.push('\'');
            self.0.push_str(&v.replace('\'', "'\\''"));
            self.0.push('\'');
        }
        self
    }

    /// Queues the event (dropping the oldest when the queue is full) and wakes the reader.
    pub(crate) fn post(mut self) {
        self.0.push('\n');
        {
            let mut q = QUEUE.lock();
            let max = QUEUE_MAX.load(Ordering::Relaxed);
            while q.lines.len() >= max {
                q.lines.pop_front();
                q.lost += 1;
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
            q.lines.push_back(self.0);
        }
        // A blocked read and `poll` both wait as `Polling`. Interrupts off: the timer takes the
        // table's lock, and a kernel thread runs with them on.
        x86_64::instructions::interrupts::without_interrupts(|| {
            crate::process::wake_pollers(&mut crate::process::table().lock());
        });
    }
}

/// Takes up to `max` bytes off the queue's front as one stream: a pending partial line first,
/// then, after drops, the `lost devctl` line, then whole lines, the last perhaps in part.
fn take(max: usize) -> Vec<u8> {
    let mut q = QUEUE.lock();
    let mut out = Vec::new();
    while out.len() < max {
        if q.partial.is_empty() {
            if q.lost > 0 {
                let mut lost = String::new();
                let _ = writeln!(lost, "lost devctl count={}", q.lost);
                q.partial = lost.into_bytes();
                q.lost = 0;
            } else if let Some(line) = q.lines.pop_front() {
                q.partial = line.into_bytes();
            } else {
                break;
            }
        }
        let n = q.partial.len().min(max - out.len());
        out.extend(q.partial.drain(..n));
    }
    out
}

fn readable() -> bool {
    let q = QUEUE.lock();
    !q.partial.is_empty() || q.lost > 0 || !q.lines.is_empty()
}

// ---- /dev/devctl ----

/// Whether `/dev/devctl` is open: one reader at a time (§4.1).
static OPEN: AtomicBool = AtomicBool::new(false);
/// The open `/dev/devctl`'s `real_fd`.
static OPEN_FD: Mutex<Option<u64>> = Mutex::new(None);

pub(crate) fn init() {
    let _ = crate::fs::devfs::make_dev("devctl", DEVCTL_DEVICE.0, DEVCTL_DEVICE.1, 0, 0, 0o600, dev_open);
}

/// Opens `/dev/devctl` read-only: `-EACCES` for any other mode, `-EBUSY` if it's open already.
extern "C" fn dev_open(_major: u64, _minor: u64, flags: u64) -> i64 {
    if flags & 3 != 0 {
        return -(EACCES as i64);
    }
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -e;
    }
    if OPEN.swap(true, Ordering::AcqRel) {
        return -(EBUSY as i64);
    }
    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    *OPEN_FD.lock() = Some(real_fd);
    crate::fs::fd::finstall(real_fd, &DEVCTL_OPS, 0, crate::fs::fd::open_flag(flags), crate::fs::fd::FdKind::Module)
}

static DEVCTL_OPS: crate::fs::fd::FileOps = crate::fs::fd::FileOps {
    read: Some(devctl_read),
    close: Some(devctl_close),
    poll: Some(devctl_poll),
    ..crate::fs::fd::FileOps::NONE
};

extern "C" fn devctl_poll(_real_fd: u64, _events: u64) -> i64 {
    crate::fs::fd::poll_bits(Readiness { readable: readable(), ..Default::default() }, false)
}

/// Reads queued lines; waits, interruptibly, while there are none (§4.2).
extern "C" fn devctl_read(real_fd: u64, uio: *mut Uio, _flags: u64) -> i64 {
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let len = uio.resid() as usize;
    loop {
        let data = take(len);
        // Copied with the queue unlocked: touching the caller's memory may fault.
        if !data.is_empty() || len == 0 {
            return match uio.uiomove_out(&data) {
                Ok(n) => n as i64,
                Err(e) => -(e as i64),
            };
        }
        if crate::fs::fd::is_nonblocking(real_fd) {
            return -(EAGAIN as i64);
        }
        // No event can come between the look and the wait: a system call runs with interrupts
        // masked, and events come from other threads.
        if crate::net::wait_for_change(false, u64::MAX).is_err() {
            return -(ERESTART as i64);
        }
    }
}

extern "C" fn devctl_close(real_fd: u64) -> i64 {
    let mut fd = OPEN_FD.lock();
    if *fd != Some(real_fd) {
        return -(EBADF as i64);
    }
    *fd = None;
    // The rest of a line the closed reader started is its own: the next reader starts on a whole one.
    QUEUE.lock().partial.clear();
    OPEN.store(false, Ordering::Release);
    0
}
