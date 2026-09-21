//! Real pipes — `src/fd.rs`'s registry gains two new kinds of registered fd (a pipe's read end and
//! write end), backed by an actual, blocking, in-kernel buffer. Added specifically because `sh`
//! (BusyBox's `hush` — see CLAUDE.md's BusyBox section) needs real `cmd1 | cmd2` pipeline support,
//! which `pipe(2)`/`dup2(2)` alone can't provide without something to actually hold the bytes in
//! flight between the two processes.
//!
//! **A pipe read has to genuinely block, not just return `Ok(0)`/`EAGAIN` the way stdin's own
//! non-blocking `sys_read` does.** This kernel is single-core and purely cooperatively scheduled
//! (see `src/scheduler.rs`'s own doc comment) — nothing preempts a running process. If a
//! pipeline's reader (say `cmd2` in `cmd1 | cmd2`) polled an empty pipe and got `Ok(0)`/`EAGAIN`
//! back immediately instead of actually yielding the CPU, it would spin forever on its own kernel
//! stack: `cmd1` (the writer) would never get a chance to run and produce the data `cmd2` is
//! waiting for, since nothing else can interrupt `cmd2`'s busy loop. `pipe_read` below instead
//! blocks for real — `process::BlockReason::WaitingForPipeData`, the exact same
//! block-then-`scheduler::schedule()` pattern `process::do_wait4` already established for blocking
//! on a child process — and `pipe_write`/`pipe_close` wake any process blocked on the pipe they
//! just touched, the same way `process::do_exit` wakes a parent blocked in `wait4`.
//!
//! **Bounded at `PIPE_CAPACITY` (64 KiB, matching real Linux's default pipe size), with a real
//! blocking writer.** Earlier revisions left the buffer an unboundedly-growable `VecDeque<u8>`, so
//! `pipe_write` always succeeded immediately and completely — fine for a shell's own interactive
//! pipeline commands, but a real, live bug for a producer that never yields on its own (`yes |
//! head`: `yes` has no blocking syscall in its write loop, so with no preemption `head` never gets
//! scheduled to read its three lines and close its end, and the buffer grew without limit until
//! the kernel heap allocator itself panicked — see CLAUDE.md's BusyBox section). `write_into` now
//! blocks (`BlockReason::WaitingForPipeSpace`, the write-side mirror of `WaitingForPipeData`) once
//! the buffer is full, writing what fits and looping rather than requiring the whole call to land
//! in one shot — the same partial-write-then-block shape a real blocking pipe write has.
//!
//! **`SYS_SOCKETPAIR`'s `AF_UNIX`/`SOCK_STREAM` support (`do_socketpair` below) is built from this
//! exact same `PipeBuffer`/blocking machinery**, not a separate abstraction — a full-duplex
//! endpoint is just two one-directional buffers cross-wired (this end's writes are the peer's
//! reads and vice versa), so `blocking_read`/`write_into`/`close_direction` are factored out of
//! `pipe_read`/`pipe_write`/`pipe_close` for both to share. Added to unblock BusyBox's `wget`
//! HTTPS path (see CLAUDE.md's "Real networking" known-gaps entry): `spawn_ssl_client`
//! (`networking/wget.c`) forks a TLS-helper child and talks to it over a local socketpair, with no
//! fallback if it doesn't exist. Not a real `AF_UNIX` abstraction — this kernel has no socket
//! address-family concept beyond UDP/TCP/raw-ICMP's own `AF_INET` (`sys/net/udp.rs`) — just enough
//! behavior (blocking full-duplex byte stream, real EOF/EPIPE on close) for that one handoff.

use alloc::collections::{BTreeMap, VecDeque};

use spin::Mutex;

use crate::process::scheduler;
use crate::process::{self, BlockReason, ProcState};
use crate::syscall::{EAGAIN, ENOTSOCK, EPIPE};

struct PipeBuffer {
    data: VecDeque<u8>,
    read_closed: bool,
    write_closed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum End {
    Read,
    Write,
}

static NEXT_PIPE_ID: Mutex<u64> = Mutex::new(1);
static PIPES: Mutex<BTreeMap<u64, PipeBuffer>> = Mutex::new(BTreeMap::new());
/// Keyed by a pipe end's own `real_fd` (see `src/fd.rs`'s module doc comment) — stable across any
/// `dup2` alias of that end, since `crate::fs::fd::read`/`write`/`close` always invoke a registered
/// callback with `real_fd`, never whichever fd was actually looked up.
static PIPE_ENDS: Mutex<BTreeMap<u64, (u64, End)>> = Mutex::new(BTreeMap::new());
/// Same keying convention as `PIPE_ENDS`, but for a socketpair endpoint: each entry names *two*
/// independent buffers (this end's own outgoing direction and incoming direction), since unlike a
/// plain pipe end a socket endpoint is full-duplex — see this module's own doc comment.
static SOCK_ENDS: Mutex<BTreeMap<u64, SocketEnd>> = Mutex::new(BTreeMap::new());

#[derive(Clone, Copy)]
struct SocketEnd {
    /// Pipe id this end's writes land in — the peer's own `read_pipe`.
    write_pipe: u64,
    /// Pipe id this end's reads drain — the peer's own `write_pipe`.
    read_pipe: u64,
}

const EBADF: i64 = 9;

/// Matches real Linux's default pipe capacity — chosen for authenticity as much as for the fix
/// itself; any small-ish bound closes the unbounded-growth panic (see this module's own doc
/// comment).
const PIPE_CAPACITY: usize = 65536;

/// Allocates a fresh, empty pipe buffer and returns its id — the shared first step `do_pipe` and
/// `do_socketpair` both need (a socketpair is two of these, cross-wired, instead of one).
fn new_pipe_buffer() -> u64 {
    let pipe_id = {
        let mut next = NEXT_PIPE_ID.lock();
        let id = *next;
        *next += 1;
        id
    };
    PIPES.lock().insert(
        pipe_id,
        PipeBuffer {
            data: VecDeque::new(),
            read_closed: false,
            write_closed: false,
        },
    );
    pipe_id
}

/// Shared blocking-read body for a plain pipe's read end (`pipe_read`) and a socketpair
/// endpoint's read half (`sock_read`) — see this module's own doc comment for why a real block,
/// not `Ok(0)`/`EAGAIN`, is required by default here. `real_fd` is the *caller's own* fd (not
/// necessarily `pipe_id`'s only reader, though today it always is) -- consulted against
/// `crate::fd`'s own `O_NONBLOCK` tracking (`syscall::sys_fcntl`) so a real `fcntl(F_SETFL,
/// O_NONBLOCK)` caller gets real `EAGAIN` instead of blocking, matching what BusyBox's `wget`
/// (`ndelay_on`/`ndelay_off` around its own progress-bar/timeout loop) actually needs.
fn blocking_read(pipe_id: u64, ptr: u64, len: u64, real_fd: u64) -> i64 {
    loop {
        {
            let mut pipes = PIPES.lock();
            let Some(pipe) = pipes.get_mut(&pipe_id) else {
                // Buffer already fully torn down -- only reachable if this same fd previously
                // shut down its own read side (see `close_direction`'s own doc comment) and then
                // read anyway. Treat it the same as an ordinary EOF.
                return 0;
            };
            if !pipe.data.is_empty() {
                let n = (len as usize).min(pipe.data.len());
                // SAFETY: same known pointer-validation gap sys_read/sys_write already document.
                let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, n) };
                for slot in buf.iter_mut() {
                    *slot = pipe.data.pop_front().unwrap();
                }
                drop(pipes); // must drop before waking -- see process::table()'s own doc comment
                wake_blocked_writers(pipe_id);
                return n as i64;
            }
            if pipe.write_closed {
                return 0; // EOF: no data, and nothing left to ever write more
            }
            if crate::fs::fd::is_nonblocking(real_fd) {
                return -(EAGAIN as i64);
            }
            // Empty, write end still open -- block and let something else run (see this module's
            // own doc comment for why this can't just return Ok(0)/EAGAIN instead).
            let caller = scheduler::current_pid();
            let mut table = process::table().lock();
            table.get_mut(&caller).unwrap().state =
                ProcState::Blocked(BlockReason::WaitingForPipeData(pipe_id));
        } // every lock dropped before schedule() -- see process::table()'s own doc comment
        scheduler::schedule();
        // Woken by write_into/close_direction (write end closing counts too) -- loop back and
        // re-check from the top.
    }
}

/// Shared write body for a plain pipe's write end (`pipe_write`) and a socketpair endpoint's
/// write half (`sock_write`). Blocks (writing what fits first) once the buffer is at
/// `PIPE_CAPACITY` — see this module's own doc comment for why an unbounded buffer here was a
/// real, live bug. `real_fd` is consulted the same way `blocking_read`'s own is, for a real
/// `O_NONBLOCK` writer.
fn write_into(pipe_id: u64, ptr: u64, len: u64, real_fd: u64) -> i64 {
    let total = len as usize;
    let mut written = 0usize;
    loop {
        {
            let mut pipes = PIPES.lock();
            let Some(pipe) = pipes.get_mut(&pipe_id) else {
                // Already fully torn down -- only reachable the same way `blocking_read`'s own
                // missing case is (a prior partial `shutdown()` on this same direction, now
                // written to anyway).
                return if written > 0 {
                    written as i64
                } else {
                    -(EPIPE as i64)
                };
            };
            if pipe.read_closed || pipe.write_closed {
                // `read_closed`: the peer doesn't want any more data. `write_closed`: *this* end
                // already called `shutdown(SHUT_WR)` on itself (`syscall::sys_shutdown`) -- real
                // `write()` after your own half-close fails the same way.
                return if written > 0 {
                    written as i64
                } else {
                    -(EPIPE as i64)
                };
            }
            let available = PIPE_CAPACITY.saturating_sub(pipe.data.len());
            if available > 0 {
                let n = (total - written).min(available);
                // SAFETY: same known pointer-validation gap sys_read/sys_write already document.
                let bytes =
                    unsafe { core::slice::from_raw_parts((ptr as *const u8).add(written), n) };
                pipe.data.extend(bytes.iter().copied());
                written += n;
                drop(pipes); // must drop before waking -- see process::table()'s own doc comment
                wake_blocked_readers(pipe_id);
                if written == total {
                    return written as i64;
                }
                continue; // more to write -- buffer is now full, loop back and block below
            }
            if crate::fs::fd::is_nonblocking(real_fd) {
                return if written > 0 {
                    written as i64
                } else {
                    -(EAGAIN as i64)
                };
            }
            // Full, read end still open -- block and let something else run (e.g. the reader
            // that'll drain space) instead of growing the buffer without limit.
            let caller = scheduler::current_pid();
            let mut table = process::table().lock();
            table.get_mut(&caller).unwrap().state =
                ProcState::Blocked(BlockReason::WaitingForPipeSpace(pipe_id));
        } // every lock dropped before schedule() -- see process::table()'s own doc comment
        scheduler::schedule();
        // Woken by blocking_read draining space or close_direction closing the read side -- loop
        // back and re-check from the top.
    }
}

/// Marks one direction of `pipe_id`'s buffer closed, removing the buffer entirely once both
/// directions are — shared by `pipe_close`/`sock_close` (a real close, both directions for a
/// socket endpoint) and `do_shutdown` (a *partial* close: marks a direction without removing the
/// fd's own registration, so the same buffer can legitimately receive a second, later call here
/// once the real close eventually happens). That reuse is exactly why this doesn't `.expect()` a
/// present `pipe_id` the way earlier revisions did -- a real close arriving after the peer already
/// fully closed (or after this end's own prior partial shutdown let the buffer get removed first)
/// must be a harmless no-op, not a panic. Wakes whichever side (if any) is blocked on the closed
/// direction: a write close wakes a blocked reader (waiting to see EOF), a read close wakes a
/// blocked writer (waiting to see `EPIPE`, now that closing the read side can never free space).
fn close_direction(pipe_id: u64, dir: End) {
    {
        let mut pipes = PIPES.lock();
        let Some(pipe) = pipes.get_mut(&pipe_id) else {
            return;
        };
        match dir {
            End::Read => pipe.read_closed = true,
            End::Write => pipe.write_closed = true,
        }
        if pipe.read_closed && pipe.write_closed {
            pipes.remove(&pipe_id);
        }
    } // must drop before waking -- see process::table()'s own doc comment
    match dir {
        End::Write => wake_blocked_readers(pipe_id),
        End::Read => wake_blocked_writers(pipe_id),
    }
}

/// `SYS_PIPE`'s real logic. Allocates a fresh pipe id and buffer, allocates two fds
/// (`crate::fs::fd::oxidebsd_alloc_fd`) and registers each end's own callbacks against them, then
/// writes `[read_fd, write_fd]` at `fds_ptr` as two `i32`s — matching real `pipe(2)`'s exact wire
/// format (a pointer to `int pipefd[2]`), since nothing about this call's shape needed inventing
/// the way `open`/`execve` did (see `sys/syscall.rs`'s own doc comment on `sys_pipe`).
pub(crate) fn do_pipe(fds_ptr: u64) -> Result<u64, u64> {
    let pipe_id = new_pipe_buffer();

    let read_fd = crate::fs::fd::oxidebsd_alloc_fd();
    let write_fd = crate::fs::fd::oxidebsd_alloc_fd();
    PIPE_ENDS.lock().insert(read_fd, (pipe_id, End::Read));
    PIPE_ENDS.lock().insert(write_fd, (pipe_id, End::Write));
    crate::fs::fd::oxidebsd_register_fd_ops(read_fd, pipe_read, write_denied, pipe_close);
    crate::fs::fd::oxidebsd_register_fd_ops(write_fd, read_denied, pipe_write, pipe_close);

    // SAFETY: same known pointer-validation gap every other user-memory write in this codebase
    // already has -- fds_ptr isn't checked against the caller's actual mappings first.
    unsafe {
        (fds_ptr as *mut i32).write(read_fd as i32);
        (fds_ptr as *mut i32).add(1).write(write_fd as i32);
    }
    Ok(0)
}

extern "C" fn write_denied(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -EBADF
}

extern "C" fn read_denied(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -EBADF
}

extern "C" fn pipe_read(real_fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(&(pipe_id, end)) = PIPE_ENDS.lock().get(&real_fd) else {
        return -EBADF;
    };
    debug_assert_eq!(
        end,
        End::Read,
        "pipe_read called against a pipe's write end"
    );
    blocking_read(pipe_id, ptr, len, real_fd)
}

extern "C" fn pipe_write(real_fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(&(pipe_id, end)) = PIPE_ENDS.lock().get(&real_fd) else {
        return -EBADF;
    };
    debug_assert_eq!(
        end,
        End::Write,
        "pipe_write called against a pipe's read end"
    );
    write_into(pipe_id, ptr, len, real_fd)
}

extern "C" fn pipe_close(real_fd: u64) -> i64 {
    let Some((pipe_id, end)) = PIPE_ENDS.lock().remove(&real_fd) else {
        return -EBADF;
    };
    // A blocked reader needs to wake up and re-check even without new data if this was the write
    // end (waiting to see write_closed flip to true, i.e. EOF) -- and symmetrically a blocked
    // writer needs waking if this was the read end (waiting to see read_closed, i.e. EPIPE, now
    // that the buffer can never drain further). `close_direction` wakes whichever applies.
    close_direction(pipe_id, end);
    0
}

/// `SYS_SOCKETPAIR`'s real logic (`AF_UNIX`/`SOCK_STREAM` only — validated by
/// `syscall::sys_socketpair` before this is ever reached). Two fresh pipe buffers, cross-wired so
/// each new fd's writes are the other's reads — see this module's own doc comment. Writes
/// `[fd0, fd1]` at `fds_ptr` as two `i32`s, matching real `socketpair(2)`'s exact wire format (a
/// pointer to `int sv[2]`).
pub(crate) fn do_socketpair(fds_ptr: u64) -> Result<u64, u64> {
    let pipe_a = new_pipe_buffer(); // fd0 -> fd1 direction
    let pipe_b = new_pipe_buffer(); // fd1 -> fd0 direction

    let fd0 = crate::fs::fd::oxidebsd_alloc_fd();
    let fd1 = crate::fs::fd::oxidebsd_alloc_fd();
    SOCK_ENDS.lock().insert(
        fd0,
        SocketEnd {
            write_pipe: pipe_a,
            read_pipe: pipe_b,
        },
    );
    SOCK_ENDS.lock().insert(
        fd1,
        SocketEnd {
            write_pipe: pipe_b,
            read_pipe: pipe_a,
        },
    );
    crate::fs::fd::oxidebsd_register_fd_ops(fd0, sock_read, sock_write, sock_close);
    crate::fs::fd::oxidebsd_register_fd_ops(fd1, sock_read, sock_write, sock_close);

    // SAFETY: same known pointer-validation gap every other user-memory write in this codebase
    // already has -- fds_ptr isn't checked against the caller's actual mappings first.
    unsafe {
        (fds_ptr as *mut i32).write(fd0 as i32);
        (fds_ptr as *mut i32).add(1).write(fd1 as i32);
    }
    Ok(0)
}

extern "C" fn sock_read(real_fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(end) = SOCK_ENDS.lock().get(&real_fd).copied() else {
        return -EBADF;
    };
    blocking_read(end.read_pipe, ptr, len, real_fd)
}

extern "C" fn sock_write(real_fd: u64, ptr: u64, len: u64) -> i64 {
    let Some(end) = SOCK_ENDS.lock().get(&real_fd).copied() else {
        return -EBADF;
    };
    write_into(end.write_pipe, ptr, len, real_fd)
}

extern "C" fn sock_close(real_fd: u64) -> i64 {
    let Some(end) = SOCK_ENDS.lock().remove(&real_fd) else {
        return -EBADF;
    };
    // Closing an endpoint closes both directions it owns: its own outgoing buffer's write side
    // (the peer's next read sees EOF once drained, waking any blocked reader) and its own
    // incoming buffer's read side (the peer's next write sees EPIPE, waking any blocked writer).
    // `close_direction` wakes whichever applies for each.
    close_direction(end.write_pipe, End::Write);
    close_direction(end.read_pipe, End::Read);
    0
}

/// `SYS_SHUTDOWN`'s real logic (`syscall::sys_shutdown`), for a socketpair endpoint only — a plain
/// pipe end or any other fd kind (TCP/UDP, oxfs files, stdio) isn't a socket at all and gets
/// `ENOTSOCK`, same as real `shutdown(2)` would. A *partial* close: unlike `sock_close`, the fd
/// stays registered and fully usable in the direction(s) not shut down — only
/// `close_direction`'s own idempotent-on-a-missing-buffer handling (see its doc comment) makes
/// this safe to layer under a real, later `close()` of the same fd. Added specifically to unblock
/// BusyBox's `wget` HTTPS path (`wget.c`'s own `shutdown(fileno(sfp), SHUT_WR)` after sending the
/// request, over exactly this kind of pair — see CLAUDE.md's "Real networking" known-gaps entry).
pub(crate) fn do_shutdown(real_fd: u64, how: u64) -> Result<u64, u64> {
    let Some(end) = SOCK_ENDS.lock().get(&real_fd).copied() else {
        return Err(ENOTSOCK);
    };
    const SHUT_RD: u64 = 0;
    const SHUT_WR: u64 = 1;
    const SHUT_RDWR: u64 = 2;
    match how {
        SHUT_RD => {
            close_direction(end.read_pipe, End::Read);
        }
        SHUT_WR => {
            close_direction(end.write_pipe, End::Write);
        }
        SHUT_RDWR => {
            close_direction(end.read_pipe, End::Read);
            close_direction(end.write_pipe, End::Write);
        }
        _ => return Err(crate::syscall::EINVAL),
    }
    Ok(0)
}

fn wake_blocked_readers(pipe_id: u64) {
    let mut table = process::table().lock();
    for (&pid, proc) in table.iter_mut() {
        if proc.state == ProcState::Blocked(BlockReason::WaitingForPipeData(pipe_id)) {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}

fn wake_blocked_writers(pipe_id: u64) {
    let mut table = process::table().lock();
    for (&pid, proc) in table.iter_mut() {
        if proc.state == ProcState::Blocked(BlockReason::WaitingForPipeSpace(pipe_id)) {
            proc.state = ProcState::Ready;
            scheduler::enqueue_ready(pid);
        }
    }
}
