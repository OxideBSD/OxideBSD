//! Networking. Phase 1: PCI discovery (`crate::pci`) + a real NIC driver (`rtl8139`) sending and
//! receiving raw Ethernet frames, IRQ-driven. Phase 2: a real protocol stack on top of it
//! (`ethernet`/`arp`/`ipv4`/`icmp`) -- enough to answer/originate ICMP echo requests against real
//! (if virtualized) network traffic. No `modules/net` syscall shim yet -- see this repo's
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
/// traffic processing until `modules/net`'s syscalls exist (a later phase) give userland a
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
const POLLNVAL: i16 = 0x0020;

/// Real Linux/musl `struct pollfd` layout (`int fd; short events; short revents;`) -- no padding
/// needed, already 8-byte aligned as a whole.
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

/// `SYS_POLL = 148` (see `bits/syscall.h.in`'s own comment on why `__NR_poll`'s real, unremapped
/// value can't be used here -- it collides with this ABI's own `SYS_WAIT4`). Exists to unblock a
/// real DNS resolver: musl's own stub resolver (`third_party/musl/src/network/res_msend.c`) is
/// already a real userspace UDP client built on `socket`/`sendto`/`recvfrom` -- it just also needs
/// `poll()` to multiplex retries across nameservers with a timeout, the one primitive this stack
/// didn't have yet.
///
/// Only ever reports `POLLIN` -- the only event class any fd in this kernel has real blocking
/// semantics for. A `real_fd` that doesn't belong to any protocol's socket table (a regular oxfs
/// file, a pipe, stdin, ...) is treated as always-ready, matching real POSIX behavior for regular
/// files and a reasonable stand-in for everything else this stack doesn't model blocking for.
pub extern "C" fn oxidebsd_sys_poll(fds_ptr: u64, nfds: u64, timeout_ms: u64) -> i64 {
    if fds_ptr == 0 && nfds > 0 {
        return -(EINVAL as i64);
    }
    // `timeout` is a signed `int` in the real ABI (`-1` means "block forever") -- R10/RDX only
    // ever carries its raw bit pattern, so reinterpret it here rather than truncating it to an
    // always-positive u64.
    let timeout_ms = timeout_ms as i32 as i64;
    let entries = unsafe { core::slice::from_raw_parts_mut(fds_ptr as *mut PollFd, nfds as usize) };

    // `crate::tsc`, not `crate::cpu::interrupts::ticks()`: this is a real syscall handler, and
    // `ticks()` is driven entirely by the timer IRQ, which can't fire for the syscall's *entire*
    // duration (`src/syscall.rs`'s SFMASK clears `RFLAGS::INTERRUPT_FLAG` at entry) -- a
    // tick-based deadline here would be frozen at the value it had when the syscall began and
    // could never actually elapse. Confirmed live: `tests/poll_syscall_smoke.rs`'s real `SYSCALL`
    // path hung solid on exactly this before `crate::tsc` existed -- see that module's own doc
    // comment. RDTSC keeps advancing regardless of the interrupt-enable state.
    let deadline =
        (timeout_ms >= 0).then(|| crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(timeout_ms as u64));

    loop {
        if nfds > 0 {
            poll(); // drain the NIC / run the protocol stack once per pass, same as recvfrom's self-poll
        }
        let mut ready_count: i64 = 0;
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
            let ready = udp::has_data_ready(real_fd)
                .or_else(|| tcp::has_data_ready(real_fd))
                .or_else(|| icmp::has_data_ready(real_fd))
                .unwrap_or(true);
            if ready {
                entry.revents = entry.events & POLLIN;
                ready_count += 1;
            }
        }
        if ready_count > 0 {
            return ready_count;
        }
        if deadline.is_some_and(|d| crate::cpu::tsc::now() >= d) {
            return 0;
        }
        // `hint::spin_loop()`, not `hlt()`: this is a real syscall handler, and
        // `src/syscall.rs`'s SFMASK setup clears `RFLAGS::INTERRUPT_FLAG` for the syscall's
        // *entire* duration -- `hlt()` only wakes on an unmasked interrupt or an NMI, so it would
        // freeze the CPU permanently the first time nothing was ready yet (no timer tick to ever
        // advance a tick-based deadline's own check either, no NMI under normal operation). See
        // `ipv4::resolve_with_retry`'s own doc comment for the fuller explanation and the same
        // fix, applied there for the identical reason.
        //
        // **`nfds == 0` (no fd involved, "poll used as a portable sleep" idiom) is a real, separate
        // livelock risk if given `timeout_ms == -1` (block forever)**: nothing here checks
        // `pending_signals` at all, so on this single-core kernel a caller in exactly that shape
        // would spin forever with no possible escape -- starving every *other* process too,
        // including whichever one might otherwise deliver a signal, since a bare CPU hint never
        // actually yields. No pilot caller currently reaches this exact shape, but `n > 0`'s real
        // fd-readiness case must keep spinning (yielding here would stop this process from ever
        // pumping the NIC again for a connection nothing else services -- see this function's own
        // doc comment).
        if nfds == 0 {
            crate::process::scheduler::schedule();
        } else {
            core::hint::spin_loop();
        }
    }
}

/// A real `fd_set` (`third_party/musl/include/sys/select.h`: `FD_SETSIZE = 1024`, laid out as
/// `unsigned long fds_bits[1024/8/sizeof(long)]` -- 16 `u64` words on this LP64 target, 128 bytes
/// total).
const FD_SETSIZE: usize = 1024;
const FD_SET_WORDS: usize = FD_SETSIZE / 64;

/// `third_party/musl/src/select/select.c` (`oxidebsd` branch)'s own on-stack request struct --
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

/// `SYS_SELECT = 23` (registered by `modules/net`, real Linux's own unclaimed legacy `select(2)`
/// number -- this arch's `bits/syscall.h.in` still defines `__NR_select`, confirmed free in this
/// ABI's own registry first, same reasoning `fchmod`/`sched_getaffinity` already established for
/// landing directly on a real-but-inert Linux number instead of an invented one). Takes a single
/// `RawSelectRequest*` -- see that struct's own doc comment for why.
///
/// Real fd-readiness monitoring, reusing `oxidebsd_sys_poll`'s own per-fd resolution chain
/// (`udp::has_data_ready`/`tcp::has_data_ready`/`icmp::has_data_ready`, defaulting to always-ready
/// for anything this stack doesn't model blocking for -- a regular oxfs file, a pipe, a real
/// mqueue end, ...) and its identical spin-loop-with-`crate::tsc`-deadline shape (`hlt()` would
/// freeze the CPU permanently for the same reason `oxidebsd_sys_poll`'s own doc comment already
/// explains, and network readiness here is genuinely pull-based -- nothing drives the NIC while
/// blocked any other way). **Only `POLLIN`-shaped read-readiness is real** -- this kernel has no
/// write-backpressure or exceptional-condition model for *any* fd kind, so every requested `wfds`/
/// `efds` bit is reported ready immediately, matching `oxidebsd_sys_poll`'s own identical scope
/// (`POLLIN` is the only event class it can ever report either). A requested fd this process
/// doesn't actually have open is treated as simply never-ready rather than modeling a real
/// `EBADF` -- no caller in this port's own corpus needs that distinction.
///
/// **Real signal-interrupt support `oxidebsd_sys_poll` itself doesn't have**: checked once per
/// spin pass via `process::signals::has_interrupting_signal`, same real-delivery-aware check
/// every other blocking primitive in this codebase uses -- found live via three Open POSIX Test
/// Suite pilot files
/// (`sigaction/10-1,11-1,17-1.c`) that use `select(0, NULL, NULL, NULL, &tv)` purely as a
/// "block until this timeout elapses or a signal arrives" idiom, no fd involved at all; that
/// shape falls out of this same general implementation for free (the `0..n` readiness scan is
/// simply empty).
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

    let deadline = (req.tv_sec >= 0).then(|| {
        crate::cpu::tsc::now()
            + crate::cpu::tsc::ms_to_cycles(req.tv_sec as u64 * 1000 + req.tv_usec as u64 / 1000)
    });
    let caller_pid = crate::process::scheduler::current_pid();

    loop {
        if n > 0 {
            poll(); // drain the NIC / run the protocol stack once per pass, same as oxidebsd_sys_poll
        }
        let mut ready_count: i64 = 0;
        let mut rout = [0u64; FD_SET_WORDS];
        let mut wout = [0u64; FD_SET_WORDS];
        let mut eout = [0u64; FD_SET_WORDS];

        for fd in 0..n {
            let wants_r = fd_set_bit(req.rfds, fd);
            let wants_w = fd_set_bit(req.wfds, fd);
            let wants_e = fd_set_bit(req.efds, fd);
            if !wants_r && !wants_w && !wants_e {
                continue;
            }
            if wants_r {
                let Some(real_fd) = crate::fs::fd::real_fd_of(fd as u64) else {
                    continue; // no such fd -- never-ready, see this function's own doc comment
                };
                let ready = udp::has_data_ready(real_fd)
                    .or_else(|| tcp::has_data_ready(real_fd))
                    .or_else(|| icmp::has_data_ready(real_fd))
                    .unwrap_or(true);
                if ready {
                    rout[fd / 64] |= 1u64 << (fd % 64);
                    ready_count += 1;
                }
            }
            // No real write-backpressure/exceptional-condition model exists anywhere in this
            // kernel -- see this function's own doc comment.
            if wants_w {
                wout[fd / 64] |= 1u64 << (fd % 64);
                ready_count += 1;
            }
            if wants_e {
                eout[fd / 64] |= 1u64 << (fd % 64);
                ready_count += 1;
            }
        }

        if ready_count > 0 {
            fd_set_write_back(req.rfds, &rout);
            fd_set_write_back(req.wfds, &wout);
            fd_set_write_back(req.efds, &eout);
            return ready_count;
        }

        if deadline.is_some_and(|d| crate::cpu::tsc::now() >= d) {
            fd_set_write_back(req.rfds, &rout);
            fd_set_write_back(req.wfds, &wout);
            fd_set_write_back(req.efds, &eout);
            return 0;
        }

        let signal_pending = crate::process::table()
            .lock()
            .get(&caller_pid)
            .is_some_and(|proc| crate::process::signals::has_interrupting_signal(proc));
        if signal_pending {
            return -(EINTR as i64);
        }

        // A real, previously-live deadlock, not just a missed optimization: `n == 0` (no fd
        // involved at all, the plain "block until timeout/signal" idiom this function's own doc
        // comment already covers for `sigaction/10-1,11-1,17-1.c`) has nothing to poll for, so
        // spinning here bought nothing -- but a *pure* `spin_loop()` hint never actually yields the
        // CPU. On this single-core kernel, a caller blocked this way (no fds, `deadline == None`,
        // i.e. a real `NULL` timeout -- `sigaction/9-1.c`'s own `select(0, NULL, NULL, NULL, NULL)`)
        // can *only* ever escape via `signal_pending` above, which requires some *other* process to
        // actually run and deliver that signal -- impossible if this process never gives up the CPU,
        // a genuine livelock, not a slow test. Real `core::hint::spin_loop()` is kept for the `n > 0`
        // case (matches every already-passing real-socket-readiness caller's existing behavior
        // unchanged -- see this function's own doc comment for why yielding there would stop
        // anything from ever pumping the NIC again) since those calls always carry a real deadline
        // in every pilot caller today, bounding the wait regardless.
        if n == 0 {
            crate::process::scheduler::schedule();
        } else {
            core::hint::spin_loop();
        }
    }
}
