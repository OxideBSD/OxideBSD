//! /proc formatting helpers (not in the original split plan -- a real, ~230-line cluster found while executing it, split out on its own rather than crammed into mod.rs).

use alloc::vec::Vec;

use super::*;

/// Appends `value`'s decimal representation (no leading zeros; `0` prints as `"0"`) -- kernel-side
/// equivalent of `modules/oxfs`'s own `ByteBuf::push_decimal`, duplicated rather than shared since
/// modules can't depend on kernel-crate internals and vice versa. `pub(crate)` (not private) so
/// `src/module.rs`'s own `oxidebsd_proc_modules` can reuse it too -- that's ordinary
/// within-the-kernel-crate sharing, not the module<->kernel boundary the doc comment above is
/// actually warning about.
pub(crate) fn push_decimal(out: &mut Vec<u8>, value: u64) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    out.extend(digits[..n].iter().rev());
}

/// Copies `min(content.len(), buf_cap)` bytes into the caller-owned `buf_ptr`, returning that
/// count -- the shape every `/proc` accessor below returns content through, since modules can't
/// receive a `Vec`/`&str` directly across the FFI boundary (same raw pointer+len convention
/// `oxidebsd_log` and oxfs's own `write_stat` already use). `pub(crate)`, same reasoning as
/// `push_decimal` above.
pub(crate) fn copy_into(content: &[u8], buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let n = content.len().min(buf_cap as usize);
    // SAFETY: the caller (modules/oxfs, via the FFI boundary these functions are exported across)
    // owns buf_ptr for at least buf_cap bytes -- same trust boundary as every other module<->kernel
    // raw-pointer handoff in this codebase.
    unsafe { core::ptr::copy_nonoverlapping(content.as_ptr(), buf_ptr, n) };
    n as i64
}

fn state_char(state: ProcState) -> u8 {
    match state {
        ProcState::Ready | ProcState::Running => b'R',
        ProcState::Blocked(_) => b'S',
        ProcState::Zombie(_) => b'Z',
        ProcState::Stopped(_) => b'T',
    }
}

/// Exposed to `modules/oxfs` for its `/proc` directory listing -- `1`/`0` rather than `bool` to
/// stay a plain FFI scalar, same convention `oxidebsd_register_syscall`'s own return already uses.
pub(crate) extern "C" fn oxidebsd_proc_exists(pid: u64) -> i32 {
    if PROCESS_TABLE.lock().contains_key(&pid) {
        1
    } else {
        0
    }
}

/// The `index`-th live pid in ascending order (`BTreeMap` iteration is already sorted), `-1` once
/// `index` is past the end -- lets `modules/oxfs` enumerate `/proc`'s own directory listing without
/// a "how many pids" call of its own (just loop until `-1`).
pub(crate) extern "C" fn oxidebsd_proc_pid_at(index: u64) -> i64 {
    PROCESS_TABLE
        .lock()
        .keys()
        .nth(index as usize)
        .map(|&pid| pid as i64)
        .unwrap_or(-1)
}

/// Formats a real `/proc/[pid]/stat` line (`pid (comm) state ppid pgrp session ...`, all ~52
/// space-separated fields real Linux defines) into `buf_ptr`/`buf_cap`. Real values for
/// `pid`/`comm`/`state`/`ppid`/`pgrp`/`session`/`num_threads`/`blocked`/`start_brk`; `0` for
/// everything else this kernel doesn't track (`utime`/`vsize`/`rss`/...) -- same "documented fixed
/// placeholder" precedent as oxfs's own `write_stat` uses for `st_uid`/`st_gid`/timestamps.
/// Returns bytes written, or `-1` if `pid` no longer exists (a race between the caller's own
/// existence check and this call -- the process table isn't locked across both).
pub(crate) extern "C" fn oxidebsd_proc_stat_line(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid) else {
        return -1;
    };
    let ppid = proc.parent.unwrap_or(0);
    let pgid = proc.pgid;
    let brk = proc.shared.lock().brk.as_u64();
    let blocked = proc.blocked_signals;

    let mut out = Vec::new();
    push_decimal(&mut out, pid);
    out.push(b' ');
    out.push(b'(');
    out.extend_from_slice(&proc.comm);
    out.push(b')');
    out.push(b' ');
    out.push(state_char(proc.state));

    // Fields 4 (ppid) through 52 (exit_code) -- see proc(5). Non-zero entries: pgrp/session
    // (idx 1/2), priority (idx 14), num_threads (idx 16), blocked (idx 28), exit_signal (idx 34,
    // SIGCHLD), start_brk (idx 43).
    let fields: [u64; 49] = [
        ppid, pgid, pgid, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 4-13
        20, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 14-27 (priority, nice, num_threads, ...)
        blocked, 0, 0, 0, 0, 0, // 28-33
        17, 0, 0, 0, 0, 0, 0, // 34-40 (exit_signal, processor, rt_priority, ...)
        0, 0, brk, 0, 0, 0, 0, 0, // 41-48 (start_data, end_data, start_brk, ...)
    ];
    for f in fields {
        out.push(b' ');
        push_decimal(&mut out, f);
    }
    drop(table);
    copy_into(&out, buf_ptr, buf_cap)
}

/// Raw copy of `Process::cmdline` (already real `/proc/[pid]/cmdline` wire format) into
/// `buf_ptr`/`buf_cap`. `-1` if `pid` no longer exists.
pub(crate) extern "C" fn oxidebsd_proc_cmdline(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid) else {
        return -1;
    };
    copy_into(&proc.cmdline, buf_ptr, buf_cap)
}

/// A handful of `Key:\tvalue\n` lines into `buf_ptr`/`buf_cap`, the fields this tier's target
/// applets plausibly read (`Name`/`State`/`Tgid`/`Pid`/`PPid`/`Threads`) -- a small subset of real
/// Linux's own much longer `/proc/[pid]/status`. `-1` if `pid` no longer exists.
pub(crate) extern "C" fn oxidebsd_proc_status(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid) else {
        return -1;
    };
    let ppid = proc.parent.unwrap_or(0);

    let mut out = Vec::new();
    out.extend_from_slice(b"Name:\t");
    out.extend_from_slice(&proc.comm);
    out.push(b'\n');
    out.extend_from_slice(b"State:\t");
    out.extend_from_slice(match proc.state {
        ProcState::Ready | ProcState::Running => b"R (running)".as_slice(),
        ProcState::Blocked(_) => b"S (sleeping)".as_slice(),
        ProcState::Zombie(_) => b"Z (zombie)".as_slice(),
        ProcState::Stopped(_) => b"T (stopped)".as_slice(),
    });
    out.push(b'\n');
    out.extend_from_slice(b"Tgid:\t");
    push_decimal(&mut out, pid);
    out.push(b'\n');
    out.extend_from_slice(b"Pid:\t");
    push_decimal(&mut out, pid);
    out.push(b'\n');
    out.extend_from_slice(b"PPid:\t");
    push_decimal(&mut out, ppid);
    out.push(b'\n');
    out.extend_from_slice(b"Threads:\t1\n");
    drop(table);
    copy_into(&out, buf_ptr, buf_cap)
}

/// `/proc/meminfo` -- system-wide, not per-pid (named `_meminfo`, not tied to any single process).
/// `MemTotal` is real (`memory::usable_ram_bytes()`); `MemFree`/`MemAvailable` are set **equal to
/// `MemTotal`** -- no free-memory/deallocation tracking exists anywhere in this kernel (see
/// `memory.rs`'s own doc comments: the frame allocator never reclaims a frame), so there is
/// genuinely nothing more honest to report than "as much as there ever was" -- same documented
/// fixed-placeholder precedent `write_stat`/`write_proc_stat` already use for `st_uid`/`st_gid`/
/// timestamps. `Buffers`/`Cached`/`SwapTotal`/`SwapFree` are fixed `0` (no page cache, no swap).
/// Never fails (no pid-race case the per-pid accessors above have).
pub(crate) extern "C" fn oxidebsd_proc_meminfo(buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let total_kb = crate::memory::usable_ram_bytes() / 1024;
    let mut out = Vec::new();
    out.extend_from_slice(b"MemTotal:       ");
    push_decimal(&mut out, total_kb);
    out.extend_from_slice(b" kB\n");
    out.extend_from_slice(b"MemFree:        ");
    push_decimal(&mut out, total_kb);
    out.extend_from_slice(b" kB\n");
    out.extend_from_slice(b"MemAvailable:   ");
    push_decimal(&mut out, total_kb);
    out.extend_from_slice(b" kB\n");
    out.extend_from_slice(b"Buffers:        0 kB\n");
    out.extend_from_slice(b"Cached:         0 kB\n");
    out.extend_from_slice(b"SwapTotal:      0 kB\n");
    out.extend_from_slice(b"SwapFree:       0 kB\n");
    copy_into(&out, buf_ptr, buf_cap)
}

/// `/proc/uptime` -- real Linux's two-field format (`"<uptime> <idle>\n"`, both seconds with two
/// decimal places). Both fields are identical: no separate idle-time accounting exists in this
/// kernel (see `oxidebsd_proc_stat_global`'s own doc comment for the same gap), so "idle" here is
/// just "uptime" again, not a distinct measurement. Same `ticks()`/`TIMER_HZ` conversion
/// `sys_clock_gettime`'s own `CLOCK_MONOTONIC` arm already uses.
pub(crate) extern "C" fn oxidebsd_proc_uptime(buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let ticks = crate::cpu::interrupts::ticks();
    let hz = crate::cpu::pit::TIMER_HZ as u64;
    let secs = ticks / hz;
    let centis = (ticks % hz) * 100 / hz;
    let mut out = Vec::new();
    push_decimal(&mut out, secs);
    out.push(b'.');
    if centis < 10 {
        out.push(b'0');
    }
    push_decimal(&mut out, centis);
    out.push(b' ');
    push_decimal(&mut out, secs);
    out.push(b'.');
    if centis < 10 {
        out.push(b'0');
    }
    push_decimal(&mut out, centis);
    out.push(b'\n');
    copy_into(&out, buf_ptr, buf_cap)
}

/// `/proc/stat` -- system-wide (named `_global` to avoid colliding with the existing per-pid
/// `oxidebsd_proc_stat_line` above). Just the one `cpu` summary line real `top` actually parses
/// (`user nice system idle iowait irq softirq steal`, real Linux's own field order) -- every field
/// but `idle` is a fixed `0` (no per-tick user/system/idle breakdown is tracked anywhere in this
/// kernel). `idle` is `ticks()` itself: a real, monotonically increasing number, so a caller
/// computing CPU% from two successive reads (`top`'s own delta method) divides by a real,
/// nonzero, growing denominator instead of two identical samples -- the honest consequence is that
/// `top`'s CPU% column reads permanently ~0% used / ~100% idle, a truthful reflection of "no real
/// per-process CPU accounting exists," not a bug to chase.
pub(crate) extern "C" fn oxidebsd_proc_stat_global(buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let idle = crate::cpu::interrupts::ticks();
    let mut out = Vec::new();
    out.extend_from_slice(b"cpu  0 0 0 ");
    push_decimal(&mut out, idle);
    out.extend_from_slice(b" 0 0 0 0\n");
    copy_into(&out, buf_ptr, buf_cap)
}
