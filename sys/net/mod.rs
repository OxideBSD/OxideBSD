//! Networking. Phase 1: PCI discovery (`crate::pci`) + a real NIC driver (`rtl8139`) sending and
//! receiving raw Ethernet frames, IRQ-driven. Phase 2: a real protocol stack on top of it
//! (`ethernet`/`arp`/`ipv4`/`icmp`) -- enough to answer/originate ICMP echo requests against real
//! (if virtualized) network traffic. No `sys/modules/net` syscall shim yet -- see this repo's
//! networking plan for what's still deferred.

use crate::syscall::{EINTR, EINVAL};

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod nic;
pub mod rtl8139;
pub mod tcp;
pub mod udp;

/// Drains every frame currently queued in the NIC's RX ring and dispatches each through the
/// protocol stack. Never blocks.
///
/// Not wired into the normal boot path yet -- nothing outside a dedicated test needs live
/// traffic processing until `sys/modules/net`'s syscalls exist (a later phase) give userland a
/// reason to receive something. Callers today (`tests/icmp_smoke.rs`, `ipv4::send_packet`'s own
/// ARP-resolution wait) call this directly from their own loop, the same pattern
/// `tests/rtl8139_smoke.rs` established for raw frames.
pub fn poll() {
    tcp::check_retransmits();
    loop {
        let frame = {
            let mut guard = nic::NIC.lock();
            let Some(driver) = guard.as_mut() else {
                return;
            };
            driver.poll_recv()
        };
        match frame {
            Some(frame) => ethernet::handle_frame(&frame),
            None => return,
        }
    }
}

const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const POLLRDNORM: i16 = 0x0040;
const POLLWRNORM: i16 = 0x0100;

/// Real Linux/musl `struct pollfd` layout (`int fd; short events; short revents;`) -- no padding
/// needed, already 8-byte aligned as a whole.
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// How a not-yet-ready fd can become ready, which decides how `poll`/`select` wait for it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Changes only when another process runs (pipes, socketpairs) or a key is pressed (the
    /// console): the waiter can genuinely block (`BlockReason::Polling`) and be woken.
    Wakeable,
    /// A network socket. Incoming packets are only processed when someone calls `poll()` (the NIC
    /// is pull-based), so the waiter must keep running, yielding between passes.
    Pulled,
}

/// Current readiness of `real_fd` and how it changes. Regular files, devices and anything else
/// without a blocking model are always readable and writable, as POSIX specifies for files.
fn fd_readiness(real_fd: u64) -> (crate::fs::Readiness, Source) {
    use crate::fs::Readiness;
    // real_fd 0-2 are the console (a fixed mapping, see `sys/fs/fd.rs`'s `init`).
    if real_fd <= 2 {
        let r = Readiness {
            readable: crate::console::stdin::has_bytes_available(),
            writable: true,
            ..Default::default()
        };
        return (r, Source::Wakeable);
    }
    if let Some(r) = crate::fs::pipe::readiness(real_fd) {
        return (r, Source::Wakeable);
    }
    if let Some(r) = tcp::readiness(real_fd) {
        return (r, Source::Pulled);
    }
    if let Some(readable) = udp::has_data_ready(real_fd).or_else(|| icmp::has_data_ready(real_fd)) {
        return (Readiness { readable, writable: true, ..Default::default() }, Source::Pulled);
    }
    let always = Readiness { readable: true, writable: true, ..Default::default() };
    (always, Source::Wakeable)
}

/// `poll(2)` `revents` for one fd: the requested subset of `POLLIN`/`POLLOUT` (and their `*NORM`
/// aliases), plus `POLLHUP`/`POLLERR`, which are always reported whether requested or not.
fn poll_revents(r: crate::fs::Readiness, events: i16) -> i16 {
    let mut ready = 0;
    if r.readable {
        ready |= POLLIN | POLLRDNORM;
    }
    if r.writable {
        ready |= POLLOUT | POLLWRNORM;
    }
    let mut revents = ready & events;
    if r.hangup {
        revents |= POLLHUP;
    }
    if r.error {
        revents |= POLLERR;
    }
    revents
}

/// Shared waiting step of `poll`/`select` once nothing is ready: `Err(EINTR)` for a deliverable
/// signal, otherwise waits for something to change and returns so the caller re-checks every fd.
/// `deadline_tick` is `u64::MAX` for no timeout.
///
/// Waits on sockets yield without blocking: the NIC is pull-based, so a blocked poller would
/// never see a packet arrive. Every other wait blocks as `BlockReason::Polling`, woken by pipe
/// activity, a keystroke, a signal, or the deadline. The syscall runs with interrupts masked, so
/// a blocking wait is also the only way a keystroke can ever arrive during one.
fn wait_for_change(any_pulled: bool, deadline_tick: u64) -> Result<(), i64> {
    let pid = crate::process::scheduler::current_pid();
    {
        let mut table = crate::process::table().lock();
        let proc = table.get_mut(&pid).expect("poll: current process missing from table");
        if crate::process::signals::has_interrupting_signal(proc) {
            return Err(-(EINTR as i64));
        }
        if !any_pulled {
            proc.state = crate::process::ProcState::Blocked(
                crate::process::BlockReason::Polling(deadline_tick),
            );
        }
    } // table lock dropped before schedule() -- see process::table()'s own doc comment
    crate::process::scheduler::schedule();
    Ok(())
}

/// Converts a millisecond timeout into an absolute timer-tick deadline for `wait_for_change`,
/// rounded up so the tick deadline never fires before the TSC one. Negative means none.
fn deadline_tick_for(timeout_ms: i64) -> u64 {
    if timeout_ms < 0 {
        return u64::MAX;
    }
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    crate::cpu::interrupts::ticks() + (timeout_ms as u64 * hz).div_ceil(1000) + 1
}

/// `SYS_POLL = 148` (see `bits/syscall.h.in`'s own comment on why `__NR_poll`'s real, unremapped
/// value can't be used here -- it collides with this ABI's own `SYS_WAIT4`). First added for
/// musl's stub DNS resolver, which multiplexes retries across nameservers with it.
///
/// Reports real `POLLIN`/`POLLOUT`/`POLLHUP`/`POLLERR`/`POLLNVAL` per fd (`fd_readiness`), waits
/// genuinely rather than spinning (`wait_for_change`), and fails `EINTR` when a signal arrives.
/// Pipes used to be reported readable even when empty, so a `read()` right after `poll` blocked.
///
/// `timeout` is measured on the TSC, not `ticks()`: this handler runs with interrupts masked (the
/// syscall entry's `SFMASK`), so `ticks()` stands still whenever it doesn't actually block.
pub extern "C" fn oxidebsd_sys_poll(fds_ptr: u64, nfds: u64, timeout_ms: u64) -> i64 {
    if fds_ptr == 0 && nfds > 0 {
        return -(EINVAL as i64);
    }
    // `timeout` is a signed `int` in the real ABI (`-1` means "block forever") -- R10/RDX only
    // ever carries its raw bit pattern, so reinterpret it here rather than truncating it to an
    // always-positive u64.
    let timeout_ms = timeout_ms as i32 as i64;
    // `poll(NULL, 0, timeout)` -- the portable-sleep idiom -- is legal and common, but a slice may
    // never be built from a null pointer, even with length 0. Found live via `ppoll(NULL, 0, ...)`
    // in `regress/ppoll-smoke`: the kernel panicked on this precondition check, reachable from
    // any process through plain `poll` too.
    let entries: &mut [PollFd] = if nfds == 0 {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(fds_ptr as *mut PollFd, nfds as usize) }
    };
    let deadline = (timeout_ms >= 0)
        .then(|| crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(timeout_ms as u64));
    let deadline_tick = deadline_tick_for(timeout_ms);

    loop {
        if nfds > 0 {
            poll(); // drain the NIC / run the protocol stack once per pass, same as recvfrom's self-poll
        }
        let mut ready_count: i64 = 0;
        let mut any_pulled = false;
        for entry in entries.iter_mut() {
            entry.revents = 0;
            if entry.fd < 0 {
                continue; // negative fd: real poll() skips these entirely, not an error
            }
            let Some(real_fd) = crate::fs::fd::real_fd_of(entry.fd as u64) else {
                entry.revents = POLLNVAL;
                ready_count += 1;
                continue;
            };
            let (readiness, source) = fd_readiness(real_fd);
            any_pulled |= source == Source::Pulled;
            entry.revents = poll_revents(readiness, entry.events);
            if entry.revents != 0 {
                ready_count += 1;
            }
        }
        if ready_count > 0 {
            return ready_count;
        }
        if deadline.is_some_and(|d| crate::cpu::tsc::now() >= d) {
            return 0;
        }
        if let Err(e) = wait_for_change(any_pulled, deadline_tick) {
            return e;
        }
    }
}

/// `SYS_PPOLL = 575` -- real `ppoll(2)`: `oxidebsd_sys_poll` with a `struct timespec` timeout
/// (`NULL` = forever) and an optional signal mask installed atomically for the wait. musl's call
/// passes `_NSIG/8` as a 5th argument (`R8`), which this ABI never reads, so it's simply ignored.
/// Needed by ninja (`src/subprocess-posix.cc`, `USE_PPOLL`), which relies on the mask swap to
/// handle `SIGINT`/`SIGTERM`/`SIGCHLD` without a race against its child-output wait.
///
/// The mask swap reuses `do_sigsuspend`'s machinery (`process::begin_temporary_sigmask`/
/// `end_temporary_sigmask`), so a signal caught during the call runs its handler under the
/// temporary mask and `sigreturn` restores the original. A signal arriving during the wait ends it
/// with `EINTR` (`oxidebsd_sys_poll`'s own check, made under the temporary mask).
pub extern "C" fn oxidebsd_sys_ppoll(fds_ptr: u64, nfds: u64, timeout_ptr: u64, mask_ptr: u64) -> i64 {
    let timeout_ms: i64 = if timeout_ptr == 0 {
        -1
    } else {
        // SAFETY: caller-owned `struct timespec { tv_sec: i64, tv_nsec: i64 }`, same trust
        // boundary as every other user pointer here.
        let [sec, nsec] = unsafe { (timeout_ptr as *const [i64; 2]).read_unaligned() };
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return -(EINVAL as i64);
        }
        // Rounded up, so a nonzero sub-millisecond timeout never becomes a zero-timeout poll.
        sec.saturating_mul(1000)
            .saturating_add((nsec + 999_999) / 1_000_000)
            .min(i32::MAX as i64)
    };
    if mask_ptr == 0 {
        return oxidebsd_sys_poll(fds_ptr, nfds, timeout_ms as u64);
    }
    let pid = crate::process::scheduler::current_pid();
    let original = crate::process::begin_temporary_sigmask(pid, mask_ptr);
    // Already deliverable under the new mask: real ppoll returns EINTR without waiting at all.
    if crate::process::has_interrupting_signal_now(pid) {
        crate::process::end_temporary_sigmask(pid, original);
        return -(EINTR as i64);
    }
    let ready = oxidebsd_sys_poll(fds_ptr, nfds, timeout_ms as u64);
    let deferred = crate::process::end_temporary_sigmask(pid, original);
    if deferred && ready == 0 {
        -(EINTR as i64)
    } else {
        ready
    }
}

/// A real `fd_set` (`external/mit/musl/include/sys/select.h`: `FD_SETSIZE = 1024`, laid out as
/// `unsigned long fds_bits[1024/8/sizeof(long)]` -- 16 `u64` words on this LP64 target, 128 bytes
/// total).
const FD_SETSIZE: usize = 1024;
const FD_SET_WORDS: usize = FD_SETSIZE / 64;

/// `external/mit/musl/src/select/select.c` (`oxidebsd` branch)'s own on-stack request struct --
/// real `select(2)` needs 5 real values (`n`, three `fd_set*`, and a timeout) and this ABI only
/// carries 4 registers, so musl bundles them into one struct and passes its address as the sole
/// argument (the same "pack everything behind one pointer" convention `execve`'s own argv/envp
/// arrays already established, rather than dropping or further packing any of these -- nothing
/// here is redundant to drop). `tv_sec < 0` is this pair's own "no timeout, wait forever" sentinel
/// (musl's own call site substitutes it whenever the caller's `tv` was `NULL`) -- real,
/// non-negative timeouts are already range-checked musl-side before this is ever built.
#[repr(C)]
struct RawSelectRequest {
    n: i32,
    _pad: i32,
    rfds: u64,
    wfds: u64,
    efds: u64,
    tv_sec: i64,
    tv_usec: i64,
}

fn fd_set_bit(ptr: u64, idx: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let word = unsafe { *((ptr as *const u64).add(idx / 64)) };
    word & (1u64 << (idx % 64)) != 0
}

/// Writes `words` back into the real `fd_set` at `ptr` (a no-op for a `NULL` set, matching real
/// `select()` -- a caller that never passed a given set has nothing for this to touch). Real
/// `select()` semantics: on return, each set holds *only* the fds that turned out ready, replacing
/// whatever the caller originally passed in.
fn fd_set_write_back(ptr: u64, words: &[u64; FD_SET_WORDS]) {
    if ptr == 0 {
        return;
    }
    for (i, word) in words.iter().enumerate() {
        // SAFETY: same known pointer-validation gap every other user-memory write in this
        // codebase already has.
        unsafe { *((ptr as *mut u64).add(i)) = *word };
    }
}

/// `SYS_SELECT = 23` (registered by `sys/modules/net`, real Linux's own unclaimed legacy `select(2)`
/// number -- this arch's `bits/syscall.h.in` still defines `__NR_select`, confirmed free in this
/// ABI's own registry first, same reasoning `fchmod`/`sched_getaffinity` already established for
/// landing directly on a real-but-inert Linux number instead of an invented one). Takes a single
/// `RawSelectRequest*` -- see that struct's own doc comment for why.
///
/// Same readiness and waiting as `oxidebsd_sys_poll`, mapped the way Linux maps them: an fd is
/// readable on data, end-of-file, hangup or error, and writable when writable or on error. The
/// exceptional set means out-of-band data (`POLLPRI`), which nothing here produces, so it is never
/// set; it used to be reported set for every fd, as were all write bits. A requested fd this
/// process doesn't actually have open is treated as simply never-ready rather than modeling a real
/// `EBADF` -- no caller in this port's own corpus needs that distinction.
///
/// `select(0, NULL, NULL, NULL, &tv)` -- a plain "sleep until timeout or signal" idiom, found via
/// `sigaction/10-1,11-1,17-1.c` and `sigaction/9-1.c` (`NULL` timeout) -- falls out of the same
/// loop with an empty scan.
pub extern "C" fn oxidebsd_sys_select(req_ptr: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    if req_ptr == 0 {
        return -(EINVAL as i64);
    }
    // SAFETY: same known pointer-validation gap every other user-memory read in this codebase
    // already has.
    let req = unsafe { &*(req_ptr as *const RawSelectRequest) };
    if !(0..=FD_SETSIZE as i32).contains(&req.n) {
        return -(EINVAL as i64);
    }
    let n = req.n as usize;

    let timeout_ms = (req.tv_sec >= 0).then(|| req.tv_sec * 1000 + req.tv_usec / 1000);
    let deadline = timeout_ms
        .map(|ms| crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(ms as u64));
    let deadline_tick = deadline_tick_for(timeout_ms.unwrap_or(-1));

    loop {
        if n > 0 {
            poll(); // drain the NIC / run the protocol stack once per pass, same as oxidebsd_sys_poll
        }
        let mut ready_count: i64 = 0;
        let mut any_pulled = false;
        let mut rout = [0u64; FD_SET_WORDS];
        let mut wout = [0u64; FD_SET_WORDS];
        let eout = [0u64; FD_SET_WORDS];

        for fd in 0..n {
            let wants_r = fd_set_bit(req.rfds, fd);
            let wants_w = fd_set_bit(req.wfds, fd);
            if !wants_r && !wants_w {
                continue;
            }
            let Some(real_fd) = crate::fs::fd::real_fd_of(fd as u64) else {
                continue; // no such fd -- never-ready, see this function's own doc comment
            };
            let (r, source) = fd_readiness(real_fd);
            any_pulled |= source == Source::Pulled;
            let bit = 1u64 << (fd % 64);
            if wants_r && (r.readable || r.hangup || r.error) {
                rout[fd / 64] |= bit;
                ready_count += 1;
            }
            if wants_w && (r.writable || r.error) {
                wout[fd / 64] |= bit;
                ready_count += 1;
            }
        }

        let timed_out = deadline.is_some_and(|d| crate::cpu::tsc::now() >= d);
        if ready_count > 0 || timed_out {
            fd_set_write_back(req.rfds, &rout);
            fd_set_write_back(req.wfds, &wout);
            fd_set_write_back(req.efds, &eout);
            return ready_count;
        }
        if let Err(e) = wait_for_change(any_pulled, deadline_tick) {
            return e;
        }
    }
}
