//! /proc formatting helpers (not in the original split plan -- a real, ~230-line cluster found while executing it, split out on its own rather than crammed into mod.rs).

use alloc::vec::Vec;

use super::*;

/// Appends `value`'s decimal representation (no leading zeros; `0` prints as `"0"`) -- kernel-side
/// equivalent of `sys/modules/oxfs`'s own `ByteBuf::push_decimal`, duplicated rather than shared since
/// modules can't depend on kernel-crate internals and vice versa. `pub(crate)` (not private) so
/// `sys/module.rs`'s own `oxidebsd_proc_modules` can reuse it too -- that's ordinary
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
    // SAFETY: the caller (sys/modules/oxfs, via the FFI boundary these functions are exported across)
    // owns buf_ptr for at least buf_cap bytes -- same trust boundary as every other module<->kernel
    // raw-pointer handoff in this codebase.
    unsafe { core::ptr::copy_nonoverlapping(content.as_ptr(), buf_ptr, n) };
    n as i64
}

fn state_char(state: ProcState) -> u8 {
    match state {
        ProcState::Ready | ProcState::Running => b'R',
        ProcState::Blocked(
            BlockReason::WaitingForDisk
            | BlockReason::WaitingForFsLock
            | BlockReason::WaitingForVforkChild(_),
        ) => b'D',
        ProcState::Blocked(_) => b'S',
        ProcState::Zombie(_) => b'Z',
        ProcState::Stopped(_) => b'T',
    }
}

/// Whether a caller with `cred` sees process `p` in `/proc` (so in `ps`): FreeBSD's
/// `security.bsd.see_other_uids` rule on its real user ID (`Cred::may_see`). A hidden process is
/// as if it didn't exist. `cred` is read before the process table is locked (`current_cred`
/// takes it).
fn sees(cred: &identity::Cred, p: &Process) -> bool {
    cred.may_see(&[p.shared.lock().cred.ruid])
}

/// Exposed to `sys/modules/oxfs` for its `/proc` directory listing -- `1`/`0` rather than `bool` to
/// stay a plain FFI scalar, same convention `oxidebsd_register_syscall`'s own return already uses.
pub(crate) extern "C" fn oxidebsd_proc_exists(pid: u64) -> i32 {
    let cred = identity::current_cred();
    if PROCESS_TABLE.lock().get(&pid).is_some_and(|p| sees(&cred, p)) {
        1
    } else {
        0
    }
}

/// The `index`-th live pid in ascending order (`BTreeMap` iteration is already sorted), `-1` once
/// `index` is past the end -- lets `sys/modules/oxfs` enumerate `/proc`'s own directory listing without
/// a "how many pids" call of its own (just loop until `-1`).
pub(crate) extern "C" fn oxidebsd_proc_pid_at(index: u64) -> i64 {
    let cred = identity::current_cred();
    PROCESS_TABLE
        .lock()
        .iter()
        .filter(|(_, p)| sees(&cred, p))
        .nth(index as usize)
        .map(|(&pid, _)| pid as i64)
        .unwrap_or(-1)
}

/// Formats a real `/proc/[pid]/stat` line (`pid (comm) state ppid pgrp session ...`, all ~52
/// space-separated fields real Linux defines) into `buf_ptr`/`buf_cap`; `0` for what this kernel
/// doesn't track (`vsize`, `rss`, fault counts, ...).
/// Returns bytes written, or `-1` if `pid` no longer exists (a race between the caller's own
/// existence check and this call -- the process table isn't locked across both).
pub(crate) extern "C" fn oxidebsd_proc_stat_line(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let cred = identity::current_cred();
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid).filter(|p| sees(&cred, p)) else {
        return -1;
    };
    let ppid = proc.parent.unwrap_or(0);
    let pgid = proc.pgid;
    let sid = proc.sid;
    let brk = proc.address_space.as_ref().map_or(0, |space| space.vm().brk.as_u64());
    let blocked = proc.blocked_signals;
    let state = state_char(proc.state);
    let comm = proc.comm.clone();
    let start = proc.start_ticks;
    let vsize = proc.address_space.as_ref().map_or(0, |space| space.vm().map.size());
    let (utime, stime) = (proc.cpu_ticks.saturating_sub(proc.sys_ticks), proc.sys_ticks);
    let (cutime, cstime) = (proc.child_cpu_ticks.saturating_sub(proc.child_sys_ticks), proc.child_sys_ticks);
    // proc(5)'s priority: 20 + nice for a time-sharing thread, -1 - rank for a real-time one.
    let rt = super::sched_4bsd::key(proc) < super::sched_4bsd::REALTIME_KEYS;
    let (priority, nice) = if rt { (-1 - proc.sched_priority as i64, 0) } else { (20 + proc.nice as i64, proc.nice as i64) };
    // The terminal layer is asked without the process table held.
    drop(table);

    // TTY.md §6.4: the session's controlling terminal (`major << 8 | minor`, 0 for none) and
    // its foreground process group (-1 for none), as proc(5) encodes them.
    let (tty_nr, tpgid) = match crate::tty::controlling(sid) {
        Some(id) => {
            let (major, minor) = crate::tty::device(id);
            let tpgid = crate::tty::with(id, |t| t.pgrp);
            ((major as u64) << 8 | minor as u64, tpgid)
        }
        None => (0, None),
    };

    let mut out = Vec::new();
    push_decimal(&mut out, pid);
    out.push(b' ');
    out.push(b'(');
    out.extend_from_slice(&comm);
    out.push(b')');
    out.push(b' ');
    out.push(state);

    // Fields 4 (ppid) through 52 (exit_code) -- see proc(5). Non-zero entries: pgrp/session/
    // tty_nr (idx 1/2/3), tpgid (idx 4, written separately: it can be -1), utime..cstime (idx
    // 10-13, clock ticks), priority and nice (idx 14/15), num_threads (idx 16), blocked (idx 28),
    // exit_signal (idx 34, SIGCHLD), start_brk (idx 43).
    let fields: [i64; 49] = [
        ppid as i64, pgid as i64, sid as i64, tty_nr as i64, 0, 0, 0, 0, 0, 0, // 4-13
        utime as i64, stime as i64, cutime as i64, cstime as i64,
        // priority (18), nice, num_threads, itrealvalue, starttime (22, in clock ticks since boot:
        // the tick is 100 Hz, sysconf(_SC_CLK_TCK)), ...
        priority, nice, 1, 0, start as i64, vsize as i64, 0, 0, 0, 0, 0, 0, 0, 0,
        blocked as i64, 0, 0, 0, 0, 0, // 28-33
        17, 0, 0, 0, 0, 0, 0, // 34-40 (exit_signal, processor, rt_priority, ...)
        0, 0, brk as i64, 0, 0, 0, 0, 0, // 41-48 (start_data, end_data, start_brk, ...)
    ];
    for (i, f) in fields.into_iter().enumerate() {
        out.push(b' ');
        match (i, tpgid) {
            (4, None) => out.extend_from_slice(b"-1"),
            (4, Some(pgrp)) => push_decimal(&mut out, pgrp),
            _ if f < 0 => {
                out.push(b'-');
                push_decimal(&mut out, f.unsigned_abs());
            }
            _ => push_decimal(&mut out, f as u64),
        }
    }
    copy_into(&out, buf_ptr, buf_cap)
}

/// `/proc/<pid>/map` in FreeBSD procfs's format or, with `linux`, `/proc/<pid>/maps` in Linux's:
/// one line per entry of the process's map (`vm_map`), the kernel's own pages left out. Paths of
/// mapped files aren't known yet (FreeBSD's `-`, Linux's blank). `-1` if `pid` is gone.
pub(crate) extern "C" fn oxidebsd_proc_map(pid: u64, linux: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    use super::vm_map::{PROT_EXEC, PROT_READ, PROT_WRITE, VmKind};
    let cred = identity::current_cred();
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid).filter(|p| sees(&cred, p)) else {
        return -1;
    };
    let Some(space) = proc.address_space.as_ref() else {
        return copy_into(b"", buf_ptr, buf_cap);
    };
    let entries: Vec<(u64, super::vm_map::VmEntry)> =
        space.vm().map.iter().filter(|(_, e)| e.kind != VmKind::Kernel).map(|(s, e)| (s, *e)).collect();
    // Resident pages: those with a frame in the page tables.
    let phys_offset = crate::memory::phys_mem_offset();
    // SAFETY: only read, under the process table's lock, which every page table change takes.
    let mut mapper = unsafe { space.mapper(phys_offset) };
    let mut resident = |start: u64, end: u64| -> u64 {
        use x86_64::structures::paging::mapper::{Translate, TranslateResult};
        let mut n = 0;
        let mut va = start;
        while va < end {
            if let TranslateResult::Mapped { .. } = mapper.translate(x86_64::VirtAddr::new(va)) {
                n += 1;
            }
            va += 4096;
        }
        n
    };
    let mut out = Vec::new();
    let hex = |out: &mut Vec<u8>, v: u64, width: usize| {
        let digits = b"0123456789abcdef";
        let mut tmp = [0u8; 16];
        let mut n = v;
        let mut i = 16;
        loop {
            i -= 1;
            tmp[i] = digits[(n & 0xf) as usize];
            n >>= 4;
            if n == 0 && 16 - i >= width {
                break;
            }
        }
        out.extend_from_slice(&tmp[i..]);
    };
    for (start, e) in entries {
        let r = |bit, c| if e.prot & bit != 0 { c } else { b'-' };
        if linux != 0 {
            // start-end perms offset dev inode path
            hex(&mut out, start, 8);
            out.push(b'-');
            hex(&mut out, e.end, 8);
            out.extend_from_slice(&[b' ', r(PROT_READ, b'r'), r(PROT_WRITE, b'w'), r(PROT_EXEC, b'x'), if e.shared { b's' } else { b'p' }, b' ']);
            let offset = match e.kind {
                VmKind::File { page, .. } | VmKind::Text { page, .. } => page * 4096,
                _ => 0,
            };
            hex(&mut out, offset, 8);
            out.extend_from_slice(b" 00:00 0");
            match e.kind {
                VmKind::Heap => out.extend_from_slice(b"                          [heap]"),
                VmKind::Stack => out.extend_from_slice(b"                          [stack]"),
                _ => {}
            }
        } else {
            // start end resident private-resident object prot refcount shadowcount flags cow
            // needs-copy type path charged uid
            out.extend_from_slice(b"0x");
            hex(&mut out, start, 1);
            out.extend_from_slice(b" 0x");
            hex(&mut out, e.end, 1);
            out.push(b' ');
            let res = resident(start, e.end);
            push_decimal(&mut out, res);
            out.push(b' ');
            push_decimal(&mut out, if e.shared { 0 } else { res });
            out.extend_from_slice(&[b' ', b'0', b'x', b'0', b' ', r(PROT_READ, b'r'), r(PROT_WRITE, b'w'), r(PROT_EXEC, b'x')]);
            out.extend_from_slice(b" 1 0 0x0 ");
            out.extend_from_slice(if e.shared { b"NCOW" } else { b"COW" });
            out.extend_from_slice(b" NNC ");
            out.extend_from_slice(match e.kind {
                VmKind::File { .. } | VmKind::Text { .. } => b"vnode",
                VmKind::Phys => b"phys",
                VmKind::Anon | VmKind::Shm { .. } | VmKind::Heap | VmKind::Stack => b"swap",
                VmKind::Kernel => b"none",
            });
            out.extend_from_slice(b" - NCH -1");
        }
        out.push(b'\n');
    }
    drop(table);
    copy_into(&out, buf_ptr, buf_cap)
}

/// The calling process's pid as `/proc/self` names it: its thread group's.
pub(crate) extern "C" fn oxidebsd_current_tgid() -> u64 {
    scheduler::current_tgid()
}

/// Raw copy of `Process::cmdline` (already real `/proc/[pid]/cmdline` wire format) into
/// `buf_ptr`/`buf_cap`. `-1` if `pid` no longer exists.
pub(crate) extern "C" fn oxidebsd_proc_cmdline(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let cred = identity::current_cred();
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid).filter(|p| sees(&cred, p)) else {
        return -1;
    };
    copy_into(&proc.cmdline, buf_ptr, buf_cap)
}

/// `/proc/<pid>/oom_adj`: the thread group's OOM adjustment (OxideBSD-doc `COW.md` §6.3), as
/// decimal and a newline. `-1` if `pid` no longer exists.
pub(crate) extern "C" fn oxidebsd_proc_oom_adj(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let cred = identity::current_cred();
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid).filter(|p| sees(&cred, p)) else {
        return -1;
    };
    let adj = proc.shared.lock().oom_adj;
    let mut out = Vec::new();
    if adj < 0 {
        out.push(b'-');
    }
    push_decimal(&mut out, adj.unsigned_abs() as u64);
    out.push(b'\n');
    copy_into(&out, buf_ptr, buf_cap)
}

/// A handful of `Key:\tvalue\n` lines into `buf_ptr`/`buf_cap`, the fields this tier's target
/// applets plausibly read (`Name`/`State`/`Tgid`/`Pid`/`PPid`/`Threads`) -- a small subset of real
/// Linux's own much longer `/proc/[pid]/status`. `-1` if `pid` no longer exists.
pub(crate) extern "C" fn oxidebsd_proc_status(pid: u64, buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let cred = identity::current_cred();
    let table = PROCESS_TABLE.lock();
    let Some(proc) = table.get(&pid).filter(|p| sees(&cred, p)) else {
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
        ProcState::Blocked(BlockReason::WaitingForDisk | BlockReason::WaitingForFsLock) => {
            b"D (disk sleep)".as_slice()
        }
        // FreeBSD's wait channel for it.
        ProcState::Blocked(BlockReason::WaitingForVforkChild(_)) => b"D (ppwait)".as_slice(),
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
    // proc(5)'s order: real, effective, saved, and the filesystem ID (the effective one here).
    let cred = proc.shared.lock().cred.clone();
    for (name, ids) in [
        (b"Uid:".as_slice(), [cred.ruid, cred.euid, cred.suid, cred.euid]),
        (b"Gid:".as_slice(), [cred.rgid, cred.egid, cred.sgid, cred.egid]),
    ] {
        out.extend_from_slice(name);
        for id in ids {
            out.push(b'\t');
            push_decimal(&mut out, id as u64);
        }
        out.push(b'\n');
    }
    out.extend_from_slice(b"Groups:");
    for g in &cred.groups {
        out.push(b' ');
        push_decimal(&mut out, *g as u64);
    }
    out.push(b'\n');
    out.extend_from_slice(b"Threads:\t1\n");
    // FreeBSD's `P_PPWAIT` (`ps`'s `V`): a vfork child still borrowing its parent's memory.
    out.extend_from_slice(if proc.vfork_parent.is_some() { b"PPWait:\t1\n" } else { b"PPWait:\t0\n" });
    drop(table);
    copy_into(&out, buf_ptr, buf_cap)
}

/// `/proc/meminfo` -- system-wide, not per-pid. From the frame allocator's count: `MemFree` is
/// the frames never handed out, `Cached` the page cache's frames (`memory::pagecache`), and
/// `MemAvailable` the free ones plus the cached frames no address space maps, which the allocator
/// takes back when it runs out. oxfs's buffer cache and tmpfs pool are reserved at boot and count
/// as used (`Buffers` stays `0`); there is no swap. Never fails.
pub(crate) extern "C" fn oxidebsd_proc_meminfo(buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let (total_frames, used_frames) = crate::memory::frame_counts();
    let free_frames = total_frames.saturating_sub(used_frames);
    let (cached, reclaimable) = crate::memory::pagecache::meminfo_pages();
    let mut out = Vec::new();
    for (name, kb) in [
        (b"MemTotal:       ".as_slice(), total_frames * 4),
        (b"MemFree:        ", free_frames * 4),
        (b"MemAvailable:   ", (free_frames + reclaimable) * 4),
        (b"Buffers:        ", 0),
        (b"Cached:         ", cached * 4),
        (b"SwapTotal:      ", 0),
        (b"SwapFree:       ", 0),
    ] {
        out.extend_from_slice(name);
        push_decimal(&mut out, kb);
        out.extend_from_slice(b" kB\n");
    }
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
