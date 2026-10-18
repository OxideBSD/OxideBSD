//! Process 1's supervision by the kernel (INIT.md §9 in OxideBSD-doc): pid 1 is protected from
//! user-space signals it has no handler for, and when it dies the kernel records why and starts
//! it again -- or, after repeated deaths, starts `/sbin/emergency` instead.
//!
//! Only armed once `arm` names the programs to run as pid 1 (the real boot,
//! `kernel_main::run_real_system`); test kernels that spawn their own pid 1 keep the old
//! behavior, where pid 1 is an ordinary process and its exit leaves the system idle.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::*;
use crate::memory::with_frame_allocator;

/// What the kernel starts as pid 1, read from the root file system when it's needed (RAM_FLOOR.md
/// §4.6.3, FreeBSD's `start_init`): nothing userland is embedded in the kernel.
#[derive(Clone)]
pub struct Program {
    /// Tried in order until one starts (`init_path`).
    pub paths: Vec<Vec<u8>>,
    /// Arguments after `argv[0]` (the path) for a start.
    pub args: Vec<Vec<u8>>,
    /// What a restart after a death passes instead.
    pub restart: Restart,
    pub env: Env,
    /// Whether the console becomes its controlling terminal. Not for `/sbin/init`, which runs
    /// without one so that its children can take it (INIT.md §5); a shell or the emergency
    /// program needs it for job control.
    pub console: bool,
    /// When no path starts, try `/bin/sh` on the console (the boot's init only).
    pub shell_fallback: bool,
}

/// A restart's arguments.
#[derive(Clone)]
pub enum Restart {
    /// `-R` (recovery mode, INIT.md §9.3), given only to `/sbin/init`; anything else none.
    Recovery,
    /// The same arguments as a start.
    Same,
}

/// A program's environment.
#[derive(Clone)]
pub enum Env {
    /// `/sbin/init` starts with an empty one (INIT.md §4.2); anything else `init_path` names gets
    /// the kernel's default, to pass on.
    Boot,
    Given(Vec<Vec<u8>>),
}

impl Program {
    fn argv(&self, path: &[u8], restart: bool) -> Vec<Vec<u8>> {
        let mut argv = alloc::vec![path.to_vec()];
        match (&self.restart, restart) {
            (Restart::Recovery, true) => {
                if path == crate::boot::INIT_PATH {
                    argv.push(b"-R".to_vec());
                }
            }
            _ => argv.extend(self.args.iter().cloned()),
        }
        argv
    }

    fn envp(&self, path: &[u8]) -> Vec<Vec<u8>> {
        match &self.env {
            Env::Boot if path == crate::boot::INIT_PATH => Vec::new(),
            Env::Boot => lifecycle::DEFAULT_ENVP.iter().map(|e| e.to_vec()).collect(),
            Env::Given(envp) => envp.clone(),
        }
    }
}

/// The boot's init (INIT.md §4.1): `init=`'s and `init_path=`'s programs (FreeBSD's colon-separated
/// list), else `/sbin/init`, each with `-s` for a single-user boot.
pub fn boot_init() -> Program {
    let paths = match crate::boot::init_paths() {
        Some(list) => list.split(':').filter(|p| !p.is_empty()).map(|p| p.as_bytes().to_vec()).collect(),
        None => alloc::vec![crate::boot::INIT_PATH.to_vec()],
    };
    let args = if crate::boot::single_user() { alloc::vec![b"-s".to_vec()] } else { Vec::new() };
    Program { paths, args, restart: Restart::Recovery, env: Env::Boot, console: false, shell_fallback: true }
}

/// `/sbin/emergency` (INIT.md §9.4), on the console.
pub fn boot_emergency() -> Program {
    let env = alloc::vec![lifecycle::DEFAULT_ENVP[0].to_vec(), lifecycle::DEFAULT_ENVP[1].to_vec(), b"HOME=/".to_vec()];
    Program {
        paths: alloc::vec![b"/sbin/emergency".to_vec()],
        args: Vec::new(),
        restart: Restart::Same,
        env: Env::Given(env),
        console: true,
        shell_fallback: false,
    }
}

/// Starts `program` as pid 1 (`restart`: after a death, as `INIT_PID`; else the first process):
/// the first of its paths that can be read and loaded, else `/bin/sh` on the console if it may
/// fall back to it. `None` when nothing could be started; each failure is logged.
fn start(program: &Program, restart: bool) -> Option<Pid> {
    let spawn = |path: &[u8], argv: &[Vec<u8>], envp: &[Vec<u8>], console: bool| -> Result<Pid, alloc::string::String> {
        let image = lifecycle::read_program(path).map_err(|e| alloc::format!("errno {e}"))?;
        let argv: Vec<&[u8]> = argv.iter().map(Vec::as_slice).collect();
        let envp: Vec<&[u8]> = envp.iter().map(Vec::as_slice).collect();
        let started = if restart {
            lifecycle::spawn_as(INIT_PID, &image, &argv, &envp, console)
        } else {
            lifecycle::spawn_boot(&image, None, &argv, &envp, console)
        };
        started.map_err(|e| alloc::format!("{e:?}"))
    };
    for path in &program.paths {
        match spawn(path, &program.argv(path, restart), &program.envp(path), program.console) {
            Ok(pid) => {
                crate::serial_println!("[boot] pid 1: {}", core::str::from_utf8(path).unwrap_or("?"));
                return Some(pid);
            }
            Err(why) => {
                crate::serial_println!("[boot] pid 1: {}: {}", core::str::from_utf8(path).unwrap_or("?"), why);
            }
        }
    }
    if program.shell_fallback {
        crate::serial_println!("[boot] pid 1: no init could be started; trying /bin/sh");
        let env = alloc::vec![
            lifecycle::DEFAULT_ENVP[0].to_vec(),
            lifecycle::DEFAULT_ENVP[1].to_vec(),
            lifecycle::DEFAULT_ENVP[2].to_vec(),
            b"HOME=/".to_vec(),
        ];
        match spawn(b"/bin/sh", &[b"-sh".to_vec()], &env, true) {
            Ok(pid) => return Some(pid),
            Err(why) => {
                crate::serial_println!("[boot] pid 1: /bin/sh: {}", why);
            }
        }
    }
    None
}

struct Supervisor {
    init: Program,
    emergency: Program,
    /// Pid 1 is currently the emergency program, not init.
    in_emergency: bool,
}

static SUPERVISOR: Mutex<Option<Supervisor>> = Mutex::new(None);

/// A root switch pid 1 asked for (`reboot(RB_REROOT)`): the type, device and name of the new
/// root, done when pid 1 is gone (`pid1_died`).
static REROOT: Mutex<Option<(&'static vfs_if::VfsConf, u64, Vec<u8>)>> = Mutex::new(None);

/// A root switch done (`switch_root`): pid 1's coming end is not a death, and init starts fresh
/// from this image (path and contents), read from the new root while pid 1 could still sleep on
/// the disk (`pid1_died` runs on the retired pid 1, which may be reaped while it sleeps).
static REROOTED: Mutex<Option<(Vec<u8>, Vec<u8>)>> = Mutex::new(None);

/// Records the root switch `reboot -r` asked for.
pub(crate) fn reroot_pending(target: (&'static vfs_if::VfsConf, u64, Vec<u8>)) {
    *REROOT.lock() = Some(target);
}

/// Switches the root (RAM_FLOOR.md §5.1.3), in pid 1's `reboot(RB_REROOT)`, its shutdown done:
/// pid 1 is still a live process here, so the unmounts and the mount may sleep on the disk; what
/// it holds of the old root is revoked as the file systems go, and it never returns to user mode.
/// Its end follows (`pid1_died`, which starts init on the new root).
pub(crate) fn switch_root() {
    let Some((vfc, dev, from)) = REROOT.lock().take() else { return };
    crate::serial_println!("init: switching the root to {}", core::str::from_utf8(&from).unwrap_or("?"));
    if let Err(e) = crate::kern::vfs_mount::reroot(vfc, dev, &from) {
        crate::serial_println!("init: the root switch failed ({}); back on the old root", e);
    }
    let Some(paths) = SUPERVISOR.lock().as_ref().map(|s| s.init.paths.clone()) else { return };
    for path in paths {
        match lifecycle::read_program(&path) {
            Ok(image) => {
                *REROOTED.lock() = Some((path, image));
                return;
            }
            Err(e) => {
                crate::serial_println!("init: {}: errno {}", core::str::from_utf8(&path).unwrap_or("?"), e);
            }
        }
    }
    crate::serial_println!("init: no init on the new root");
}

/// Whether a root switch has been asked for (`reboot -r`) and not yet done.
pub(crate) fn reroot_requested() -> bool {
    REROOT.lock().is_some()
}

/// Whether pid 1 is supervised (the real boot), so it can be restarted after a root switch.
pub(crate) fn supervised() -> bool {
    armed()
}

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

/// Arms supervision of pid 1 (§9), which will restart `init`, or after repeated deaths start
/// `emergency`; called once, before pid 1 starts.
pub fn arm(init: Program, emergency: Program) {
    *SUPERVISOR.lock() = Some(Supervisor { init, emergency, in_emergency: false });
}

/// Starts the armed init as the first process (`kernel_main`): `None` when no program could be.
pub fn start_pid1() -> Option<Pid> {
    let init = SUPERVISOR.lock().as_ref().map(|s| s.init.clone())?;
    start(&init, false)
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
    let rerooted = REROOTED.lock().take();
    if let Some((path, image)) = rerooted {
        // Not a death: init asked for the switch (`switch_root`), and comes up as at boot.
        let Some(init) = SUPERVISOR.lock().as_ref().map(|s| s.init.clone()) else { return false };
        retire_old_pid1(exiting);
        let argv = init.argv(&path, false);
        let envp = init.envp(&path);
        let argv: Vec<&[u8]> = argv.iter().map(Vec::as_slice).collect();
        let envp: Vec<&[u8]> = envp.iter().map(Vec::as_slice).collect();
        match lifecycle::spawn_as(INIT_PID, &image, &argv, &envp, init.console) {
            Ok(_) => {
                crate::serial_println!("[boot] pid 1: {}", core::str::from_utf8(&path).unwrap_or("?"));
                adopt_orphans();
            }
            Err(e) => {
                crate::serial_println!("init: could not start pid 1 ({:?}); the system is idle", e);
            }
        }
        return true;
    }
    let (cause, program, emergency) = {
        let mut guard = SUPERVISOR.lock();
        let Some(sup) = guard.as_mut() else { return false };
        let (cause, emergency) = record_death(code, sup.in_emergency);
        sup.in_emergency = emergency;
        // Init restarts in recovery mode, even after the emergency program: services the
        // operator left running must not be started twice.
        (cause, if emergency { sup.emergency.clone() } else { sup.init.clone() }, emergency)
    };

    retire_old_pid1(exiting);

    crate::serial_println!(
        "init: {} -- {}",
        describe(cause),
        if emergency { "it keeps dying; starting /sbin/emergency" } else { "starting it again" }
    );
    // Read from the root file system now, as FreeBSD's start_init would.
    match start(&program, true) {
        Some(_) => adopt_orphans(),
        None => {
            crate::serial_println!("init: could not start pid 1; the system is idle");
        }
    }
    true
}

/// `debug.kill_init` (sysctl(8)): kills pid 1 with `sig` as if the signal had been delivered to
/// it, so that its restart in recovery mode (§9.2, §9.3) can be tested. Nothing in user space can
/// do this otherwise: §9.1 discards every signal pid 1 has no handler for, `SIGKILL` included.
/// `EINVAL` for a signal outside `1..=64`, `ESRCH` when pid 1 isn't supervised (a test kernel's
/// own pid 1). Pid 1 may write it itself, and then never returns.
pub(crate) fn kill_for_debug(sig: i32) -> Result<(), i64> {
    if !(1..=64).contains(&sig) {
        return Err(crate::syscall::EINVAL as i64);
    }
    if !armed() {
        return Err(crate::syscall::ESRCH as i64);
    }
    let caller = scheduler::current_pid();
    let suicide = PROCESS_TABLE.lock().get(&caller).is_some_and(|p| p.tgid == INIT_PID);
    lifecycle::terminate_thread_group(INIT_PID, 128 + sig);
    if suicide {
        // As in do_exit_group: pid 1 killed itself, and a zombie must not return to user mode.
        scheduler::schedule();
        unreachable!("kill_for_debug: schedule() returned to the killed pid 1");
    }
    Ok(())
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
