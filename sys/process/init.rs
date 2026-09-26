//! Process 1's supervision by the kernel (INIT.md §9 in OxideBSD-doc): pid 1 is protected from
//! user-space signals it has no handler for, and when it dies the kernel records why and starts
//! it again -- or, after repeated deaths, starts `/sbin/emergency` instead.
//!
//! Only armed once `register` names the program to run as pid 1 (the real boot,
//! `kernel_main::run_real_system`); test kernels that spawn their own pid 1 keep the old
//! behavior, where pid 1 is an ordinary process and its exit leaves the system idle.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::*;
use crate::memory::with_frame_allocator;

/// What the kernel runs as pid 1.
pub struct InitProgram {
    /// Its image. Embedded in the kernel, so a damaged file system can't stop init from starting.
    pub elf: &'static [u8],
    pub argv: &'static [&'static [u8]],
    /// `argv` for a restart after a death: `/sbin/init` takes `-R` (recovery mode, §9.3).
    pub restart_argv: &'static [&'static [u8]],
    pub envp: &'static [&'static [u8]],
}

struct Supervisor {
    init: InitProgram,
    emergency: InitProgram,
    /// Pid 1 is currently the emergency program, not init.
    in_emergency: bool,
}

static SUPERVISOR: Mutex<Option<Supervisor>> = Mutex::new(None);

/// How pid 1 ended.
#[derive(Clone, Copy)]
enum Cause {
    Exit(u8),
    Signal { sig: u8, fault: Option<Fault> },
}

#[derive(Clone, Copy)]
struct Fault {
    ip: u64,
    addr: Option<u64>,
}

#[derive(Clone, Copy)]
struct Death {
    /// Seconds since the epoch, for `/proc/initdeaths`.
    time: i64,
    /// `ticks()` at death, for the repeated-failure window.
    ticks: u64,
    cause: Cause,
}

/// Recent deaths, oldest first; cleared when the emergency program hands back to init.
static DEATHS: Mutex<VecDeque<Death>> = Mutex::new(VecDeque::new());
const DEATHS_KEPT: usize = 16;
/// §9.4: this many deaths within `REPEAT_WINDOW_TICKS` starts the emergency program.
const REPEAT_LIMIT: usize = 3;
const REPEAT_WINDOW_TICKS: u64 = 30 * crate::cpu::pit::TIMER_HZ as u64;

/// The most recent ring-3 fault in pid 1, so its death can say where it crashed.
static LAST_FAULT: Mutex<Option<Fault>> = Mutex::new(None);

/// Arms supervision; called once, before pid 1 is spawned.
pub fn register(init: InitProgram, emergency: InitProgram) {
    *SUPERVISOR.lock() = Some(Supervisor { init, emergency, in_emergency: false });
}

fn armed() -> bool {
    SUPERVISOR.lock().is_some()
}

/// §9.1: whether a signal from user space to `target` is discarded -- `target` is in pid 1's
/// thread group and has no handler for `sig` (`SIGKILL` and `SIGSTOP` never do). Faults don't
/// come through here (`signals::force_fault_signal`).
pub(crate) fn discards(target: &Process, sig: u64) -> bool {
    target.tgid == INIT_PID && target.shared.lock().sigactions[sig as usize].handler <= 1 && armed()
}

/// Called by the fault handlers for every ring-3 fault; remembered only for pid 1.
pub(crate) fn note_fault(pid: Pid, ip: u64, addr: Option<u64>) {
    if pid == INIT_PID {
        *LAST_FAULT.lock() = Some(Fault { ip, addr });
    }
}

/// Called by `terminate_process` when the last thread of pid 1's group has become a zombie
/// (`exiting` is that thread; `code` is `wait(2)`-encoded). Returns false if supervision isn't
/// armed, leaving the caller to finish the exit as for any process.
///
/// The exiting thread may still be running on its own kernel stack and address space (a
/// self-exit), so its entry can't be dropped here: the pid-1 entry is moved to a fresh pid and
/// reaped later like any exited thread, which frees pid 1 for the replacement started here.
pub(crate) fn pid1_died(exiting: Pid, code: i32) -> bool {
    let (cause, elf, argv, envp, emergency) = {
        let mut guard = SUPERVISOR.lock();
        let Some(sup) = guard.as_mut() else { return false };
        let (cause, emergency) = record_death(code, sup.in_emergency);
        sup.in_emergency = emergency;
        let p = if emergency { &sup.emergency } else { &sup.init };
        // Init restarts in recovery mode, even after the emergency program: services the
        // operator left running must not be started twice.
        let argv = if emergency { p.argv } else { p.restart_argv };
        (cause, p.elf, argv, p.envp, emergency)
    };

    retire_old_pid1(exiting);

    crate::serial_println!(
        "init: {} -- {}",
        describe(cause),
        if emergency { "it keeps dying; starting /sbin/emergency" } else { "starting it again" }
    );
    match lifecycle::spawn_as(INIT_PID, elf, argv, envp) {
        Ok(_) => {
            // The old pid 1's jobs lose the terminal; the new one starts in the foreground.
            crate::console::stdin::set_foreground_pgid(INIT_PID);
            adopt_orphans();
        }
        Err(e) => {
            crate::serial_println!("init: could not start pid 1: {:?}; the system is idle", e);
        }
    }
    true
}

/// Records a death (unless pid 1 was the emergency program, whose exit means the operator is
/// done: the history is cleared and init gets a fresh start, §9.4). Returns the cause and
/// whether the next pid 1 must be the emergency program.
fn record_death(code: i32, was_emergency: bool) -> (Cause, bool) {
    let fault = LAST_FAULT.lock().take();
    let cause = if code & 0x7f == 0 {
        Cause::Exit(((code >> 8) & 0xff) as u8)
    } else {
        Cause::Signal { sig: (code & 0x7f) as u8, fault }
    };
    let mut deaths = DEATHS.lock();
    if was_emergency {
        deaths.clear();
        return (cause, false);
    }
    let now = crate::cpu::interrupts::ticks();
    if deaths.len() == DEATHS_KEPT {
        deaths.pop_front();
    }
    deaths.push_back(Death { time: crate::cpu::rtc::unix_epoch_now_precise().0, ticks: now, cause });
    let recent = deaths.iter().filter(|d| now - d.ticks <= REPEAT_WINDOW_TICKS).count();
    (cause, recent >= REPEAT_LIMIT)
}

/// Moves pid 1's table entry to a fresh pid and queues it for reaping, and drops any other
/// already-exited thread of the group.
fn retire_old_pid1(exiting: Pid) {
    let retired = alloc_pid();
    let mut table = PROCESS_TABLE.lock();
    if let Some(mut old) = table.remove(&INIT_PID) {
        old.pid = retired;
        old.tgid = retired;
        table.insert(retired, old);
    }
    for p in table.values_mut() {
        if p.tgid == INIT_PID {
            p.tgid = retired;
        }
    }
    drop(table);
    if scheduler::current_pid() == INIT_PID {
        scheduler::set_current_pid(retired);
    }
    scheduler::remove_ready(INIT_PID);
    scheduler::queue_thread_reap(retired, scheduler::ReapKind::RemoveEntry);
    if exiting != INIT_PID {
        scheduler::queue_thread_reap(exiting, scheduler::ReapKind::RemoveEntry);
    }
}

/// §9.2 step 3: the old pid 1's children become the new pid 1's, as adopted orphans (reaped
/// automatically). Those that had already exited are reaped now.
fn adopt_orphans() {
    let current = scheduler::current_pid();
    let mut table = PROCESS_TABLE.lock();
    let orphans: Vec<Pid> =
        table.iter().filter(|(pid, p)| **pid != INIT_PID && p.parent == Some(INIT_PID)).map(|(pid, _)| *pid).collect();
    let mut dead = Vec::new();
    for pid in orphans {
        let p = table.get_mut(&pid).unwrap();
        p.adopted = true;
        if matches!(p.state, ProcState::Zombie(_)) && pid != current {
            dead.push(pid);
        } else if let Some(init) = table.get_mut(&INIT_PID) {
            init.children.push(pid);
        }
    }
    for pid in dead {
        if let Some(address_space) = table.remove(&pid).and_then(|p| p.address_space) {
            let phys_offset = memory::phys_mem_offset();
            with_frame_allocator(|fa| unsafe { address_space.teardown(phys_offset, fa) });
        }
    }
}

fn signal_name(sig: u8) -> &'static str {
    match sig as u64 {
        SIGHUP => "SIGHUP",
        SIGINT => "SIGINT",
        SIGQUIT => "SIGQUIT",
        SIGILL => "SIGILL",
        SIGTRAP => "SIGTRAP",
        SIGABRT => "SIGABRT",
        SIGBUS => "SIGBUS",
        SIGFPE => "SIGFPE",
        SIGKILL => "SIGKILL",
        SIGSEGV => "SIGSEGV",
        SIGPIPE => "SIGPIPE",
        SIGALRM => "SIGALRM",
        SIGTERM => "SIGTERM",
        _ => "signal",
    }
}

fn describe(cause: Cause) -> alloc::string::String {
    match cause {
        Cause::Exit(status) => alloc::format!("pid 1 exited with status {status}"),
        Cause::Signal { sig, fault: None } => alloc::format!("pid 1 was killed by {} ({sig})", signal_name(sig)),
        Cause::Signal { sig, fault: Some(Fault { ip, addr: Some(addr) }) } => {
            alloc::format!("pid 1 was killed by {} ({sig}) at ip {ip:#x}, address {addr:#x}", signal_name(sig))
        }
        Cause::Signal { sig, fault: Some(Fault { ip, addr: None }) } => {
            alloc::format!("pid 1 was killed by {} ({sig}) at ip {ip:#x}", signal_name(sig))
        }
    }
}

/// `/proc/initdeaths`: one line per recorded death of pid 1, oldest first --
/// `<epoch seconds> exit <status>` or `<epoch seconds> signal <number> [ip <hex> [addr <hex>]]`.
pub(crate) extern "C" fn oxidebsd_proc_initdeaths(buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let mut out = Vec::new();
    for d in DEATHS.lock().iter() {
        let line = match d.cause {
            Cause::Exit(status) => alloc::format!("{} exit {status}\n", d.time),
            Cause::Signal { sig, fault } => {
                let mut s = alloc::format!("{} signal {sig}", d.time);
                if let Some(f) = fault {
                    s.push_str(&alloc::format!(" ip {:#x}", f.ip));
                    if let Some(a) = f.addr {
                        s.push_str(&alloc::format!(" addr {a:#x}"));
                    }
                }
                s.push('\n');
                s
            }
        };
        out.extend_from_slice(line.as_bytes());
    }
    procfs::copy_into(&out, buf_ptr, buf_cap)
}
