//! Networking. Phase 1: PCI discovery (`crate::pci`) + a real NIC driver (`rtl8139`) sending and
//! receiving raw Ethernet frames, IRQ-driven. Phase 2: a real protocol stack on top of it
//! (`ethernet`/`arp`/`ipv4`/`icmp`) -- enough to answer/originate ICMP echo requests against real
//! (if virtualized) network traffic. No `sys/modules/socket` syscall shim yet -- see this repo's
//! networking plan for what's still deferred.

use crate::netinet::tcp;
use crate::memory::usercopy::{Pod, UserPtr, copyin_val, copyout_val};
use crate::syscall::{EINTR, EINVAL};

pub mod ethernet;
pub mod if_loop;
pub mod ifnet;
pub mod nic;

/// Drains every frame currently queued in the NIC's RX ring and dispatches each through the
/// protocol stack. Never blocks.
///
/// Not wired into the normal boot path yet -- nothing outside a dedicated test needs live
/// traffic processing until `sys/modules/socket`'s syscalls exist (a later phase) give userland a
/// reason to receive something. Callers today (`tests/icmp_smoke.rs`, `ipv4::send_packet`'s own
/// ARP-resolution wait) call this directly from their own loop, the same pattern
/// `tests/rtl8139_smoke.rs` established for raw frames.
pub fn poll() {
    tcp::check_retransmits();
    // Looped packets first. Taking one can queue more (a TCP reply), so a pass takes a bounded
    // number and leaves the rest to the next.
    for _ in 0..256 {
        let Some(packet) = if_loop::dequeue() else { break };
        crate::netinet::ipv4::handle_packet(&packet, ifnet::Interface::Loopback);
    }
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
#[derive(Clone, Copy)]
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

// SAFETY: integers only, no padding (8 bytes).
unsafe impl Pod for PollFd {}

/// How a not-yet-ready fd can become ready, which decides how `poll`/`select` wait for it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Changes only when another process runs (pipes, socketpairs) or a key is pressed (the
    /// console): the waiter can genuinely block (`BlockReason::Polling`) and be woken.
    Wakeable,
    /// A network socket. Incoming packets are only processed when someone calls `poll()` (the NIC
    /// is pull-based), so the waiter wakes periodically to do it (`wait_for_change`).
    Pulled,
}

/// Current readiness of `real_fd` and how it changes. Regular files, devices and anything else
/// without a blocking model are always readable and writable, as POSIX specifies for files.
fn fd_readiness(real_fd: u64) -> (crate::fs::Readiness, Source) {
    use crate::fs::Readiness;
    if let Some(tty) = crate::tty::of_real_fd(real_fd) {
        let sid = crate::tty::caller(false).sid;
        let (readable, writable) = crate::tty::poll_state(tty, sid);
        return (Readiness { readable, writable, ..Default::default() }, Source::Wakeable);
    }
    if let Some(r) = crate::tty::pty::readiness(real_fd) {
        return (r, Source::Wakeable);
    }
    if let Some(r) = crate::fs::pipe::readiness(real_fd) {
        return (r, Source::Wakeable);
    }
    if let Some(r) = crate::kern::subr_msgbuf::readiness(real_fd) {
        // Kernel prints can't wake anyone, so its readers look again every 50 ms.
        return (r, Source::Pulled);
    }
    if let Some((r, pulled)) = crate::kern::uipc_socket::readiness(real_fd) {
        return (r, if pulled { Source::Pulled } else { Source::Wakeable });
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

/// How often a waiter on a network socket wakes to drive the interface itself (`poll`, and
/// TCP's retransmission timer in it), in timer ticks: 50 ms. A received frame wakes it sooner.
const PULL_INTERVAL_TICKS: u64 = 5;

/// Shared waiting step of `poll`/`select` and the socket layer once nothing is ready:
/// `Err(-EINTR)` for a deliverable signal, otherwise blocks until something may have changed and
/// returns so the caller re-checks. `deadline_tick` is `u64::MAX` for no timeout.
///
/// The wait blocks as `BlockReason::Polling`, woken by pipe and socket activity, a keystroke, a
/// received frame (`rtl8139`'s interrupt), a signal, or the deadline. Blocking is what lets
/// interrupts in at all: the syscall itself runs with them masked, so a spinning waiter would see
/// no keystroke, no frame and no timer (`alarm(2)` included). A wait involving a network socket
/// (`any_pulled`) also wakes every `PULL_INTERVAL_TICKS`, since the interface is serviced only
/// by its waiters.
pub(crate) fn wait_for_change(any_pulled: bool, deadline_tick: u64) -> Result<(), i64> {
    let pid = crate::process::scheduler::current_pid();
    {
        let mut table = crate::process::table().lock();
        let Some(proc) = table.get_mut(&pid) else {
            // Kernel context (pid 0: boot code, or a test calling this directly) has no process
            // to block; spin once and let the caller re-check against its TSC deadline.
            core::hint::spin_loop();
            return Ok(());
        };
        if crate::process::signals::has_interrupting_signal(proc) {
            return Err(-(EINTR as i64));
        }
        let wake = if any_pulled {
            deadline_tick.min(crate::cpu::interrupts::ticks() + PULL_INTERVAL_TICKS)
        } else {
            deadline_tick
        };
        proc.state = crate::process::ProcState::Blocked(crate::process::BlockReason::Polling(wake));
    } // table lock dropped before schedule() -- see process::table()'s own doc comment
    crate::process::scheduler::schedule();
    Ok(())
}

/// Converts a millisecond timeout into an absolute timer-tick deadline for `wait_for_change`,
/// rounded up so the tick deadline never fires before the TSC one. Negative means none.
pub(crate) fn deadline_tick_for(timeout_ms: i64) -> u64 {
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
    // More entries than open files can exist is EINVAL (as FreeBSD bounds it), so a huge `nfds`
    // never becomes a huge allocation.
    if nfds > *crate::kern::kern_sysctl::MAXFILES.lock() as u64 {
        return -(EINVAL as i64);
    }
    // The array is copied in whole and back out on success, as on the BSDs.
    let mut entries = alloc::vec::Vec::with_capacity(nfds as usize);
    for i in 0..nfds {
        match copyin_val::<PollFd>(UserPtr::new(fds_ptr).add(i * 8)) {
            Ok(e) => entries.push(e),
            Err(e) => return -(e as i64),
        }
    }
    let r = poll_entries(&mut entries, timeout_ms);
    if r >= 0 {
        for (i, e) in entries.iter().enumerate() {
            if let Err(e) = copyout_val(e, UserPtr::new(fds_ptr).add(i as u64 * 8)) {
                return -(e as i64);
            }
        }
    }
    r
}

/// `poll`'s loop, over the kernel's copy of the caller's `pollfd` array.
fn poll_entries(entries: &mut [PollFd], timeout_ms: u64) -> i64 {
    let nfds = entries.len() as u64;
    // `timeout` is a signed `int` in the real ABI (`-1` means "block forever") -- R10/RDX only
    // ever carries its raw bit pattern, so reinterpret it here rather than truncating it to an
    // always-positive u64.
    let timeout_ms = timeout_ms as i32 as i64;
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
        let [sec, nsec]: [i64; 2] = match copyin_val(UserPtr::new(timeout_ptr)) {
            Ok(ts) => ts,
            Err(e) => return -(e as i64),
        };
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
    let original = match crate::process::begin_temporary_sigmask(pid, mask_ptr) {
        Ok(original) => original,
        Err(e) => return -(e as i64),
    };
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
#[derive(Clone, Copy)]
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

// SAFETY: integers only, no padding (the gap is the explicit `_pad`).
unsafe impl Pod for RawSelectRequest {}

/// The first `n` bits of the caller's `fd_set` at `ptr`, copied in (an empty set for `NULL`).
/// Only the words those bits occupy are read, so a smaller set at the end of a mapping is fine.
fn fd_set_copyin(ptr: u64, n: usize) -> Result<[u64; FD_SET_WORDS], u64> {
    let mut words = [0u64; FD_SET_WORDS];
    if ptr != 0 {
        for (i, w) in words.iter_mut().enumerate().take(n.div_ceil(64)) {
            *w = copyin_val(UserPtr::new(ptr).add(i as u64 * 8))?;
        }
    }
    Ok(words)
}

/// Writes the result set back over the caller's `fd_set` at `ptr` (nothing for `NULL`): only the
/// words its first `n` bits occupy, as Linux and the BSDs do. Real `select()` semantics: on
/// return, each set holds *only* the fds that turned out ready.
fn fd_set_copyout(ptr: u64, n: usize, words: &[u64; FD_SET_WORDS]) -> Result<(), u64> {
    if ptr == 0 {
        return Ok(());
    }
    for (i, w) in words.iter().enumerate().take(n.div_ceil(64)) {
        copyout_val(w, UserPtr::new(ptr).add(i as u64 * 8))?;
    }
    Ok(())
}

/// `SYS_SELECT = 23` (registered by `sys/modules/socket`, real Linux's own unclaimed legacy `select(2)`
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
    let req: RawSelectRequest = match copyin_val(UserPtr::new(req_ptr)) {
        Ok(req) => req,
        Err(e) => return -(e as i64),
    };
    if !(0..=FD_SETSIZE as i32).contains(&req.n) {
        return -(EINVAL as i64);
    }
    let n = req.n as usize;
    // The sets are copied in once, as on the BSDs.
    let (rin, win) = match (fd_set_copyin(req.rfds, n), fd_set_copyin(req.wfds, n)) {
        (Ok(r), Ok(w)) => (r, w),
        (Err(e), _) | (_, Err(e)) => return -(e as i64),
    };
    let set = |words: &[u64; FD_SET_WORDS], fd: usize| words[fd / 64] & (1u64 << (fd % 64)) != 0;

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
            let wants_r = set(&rin, fd);
            let wants_w = set(&win, fd);
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
            let written = fd_set_copyout(req.rfds, n, &rout)
                .and_then(|()| fd_set_copyout(req.wfds, n, &wout))
                .and_then(|()| fd_set_copyout(req.efds, n, &eout));
            return match written {
                Ok(()) => ready_count,
                Err(e) => -(e as i64),
            };
        }
        if let Err(e) = wait_for_change(any_pulled, deadline_tick) {
            return e;
        }
    }
}
