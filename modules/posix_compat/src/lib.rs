//! The home for whatever POSIX/libc-surface syscalls a real C program's musl-linked startup path
//! needs beyond what `modules/native_abi/` (the small, BSD-authentic core: `exit`/`read`/`write`/
//! `fork`/`wait4`/`execve`/`getpid`, plus the musl-port-driven `mmap`/`munmap`/`brk`/
//! `set_fs_base`/`writev`) and `modules/fat32/` (`open`/`close`/`chdir`/`mkdir`) already register —
//! deliberately kept a separate module rather than folded into `native_abi` further, so that one
//! stays "the authentic core" while this one carries whatever extra function real userland C
//! programs turn out to need. `true`/`echo`/`cat` didn't need anything from here; `sh` (BusyBox's
//! `hush`) is what actually filled it in, once real pipeline support (`cmd1 | cmd2`) turned out to
//! need `pipe(2)`/`dup2(2)` — see CLAUDE.md's BusyBox section.
//!
//! Same "module registers, kernel implements" split every other syscall module in this codebase
//! already uses: this crate only ever gains thin `extern "C" fn handle_x` wrappers over
//! kernel-resident `oxidebsd_sys_x` functions, never the actual behavior itself (this module can't
//! use `alloc` — see CLAUDE.md's module-loading section; the real pipe-buffer/fd-aliasing logic
//! lives in `src/pipe.rs`/`src/fd.rs`, ordinary kernel code that can).
//!
//! `SYS_SETPGID = 120`/`SYS_GETPGID = 121` (see CLAUDE.md's "BusyBox gap analysis" — the "process
//! groups" gap) continue the invented-number sequence right past `SYS_SIGRETURN = 119`, and — like
//! `SYS_PIPE`/`SYS_DUP2` above — happen to match real `setpgid(2)`/`getpgid(2)`'s own wire formats
//! exactly, no argument-convention patch needed on the musl side beyond the usual number remap.
//! Real logic (`process::do_setpgid`/`do_getpgid`, a new `Process::pgid` field) is kernel-resident,
//! same reasoning as everything else this module only ever calls through to.
//!
//! `SYS_SETSID = 112` is the one exception to "continue the invented sequence": it's real x86_64
//! Linux's own `__NR_setsid` value (confirmed against `third_party/musl/arch/x86_64/bits/
//! syscall.h.in` directly), reused verbatim because `third_party/musl/src/unistd/setsid.c` is a
//! bare no-argument `syscall(SYS_setsid)` — registering a handler at `112` is the complete fix,
//! no musl patch needed at all. Backs `process::do_setsid`/a new `Process::sid` field — see
//! CLAUDE.md's session/controlling-tty notes for why this exists (unblocking `sulogin`/`getty`).
//! `SYS_GETSID = 177` is its counterpart, but *does* need an invented number (real `__NR_getsid`
//! is `124`, already claimed by `SYS_IOCTL` here) — needed by `getty`'s own real fallback path
//! when `setsid()` fails, see `process::do_getsid`'s own doc comment.
//!
//! `SYS_IOCTL = 124` (see CLAUDE.md's "BusyBox gap analysis" — the "termios/ioctl + pty" gap)
//! continues the sequence right past `getpgid` (`122`/`123` reserved for a future clock/
//! `nanosleep` pass). `(fd, request, argp)` matches real `ioctl(2)`'s own argument positions, and
//! the request codes (`TCGETS`/`TCSETS*`/`TIOCGWINSZ`/`TIOCSWINSZ`) this ABI actually recognizes
//! are real Linux/generic values too — see `src/syscall.rs`'s `sys_ioctl` for what's actually
//! implemented (a real, kernel-resident termios-echo toggle plus a fixed winsize; not real
//! `ioctl`'s full surface) and why only the console fd (never a pipe/regular file) is ever allowed
//! to answer at all (`isatty()`'s own correctness depends on it).
//!
//! `SYS_DUP = 125` — real `dup(2)`'s single-argument form, needed once `CONFIG_HUSH_JOB` (see
//! CLAUDE.md's "Interactive shell" section) turned out to reach for it: `hush`'s own
//! `dup_CLOEXEC` helper tries `fcntl(fd, F_DUPFD_CLOEXEC, ...)` first, which this kernel doesn't
//! implement at all (harmlessly `ENOSYS`s), then falls back to plain `dup(fd)` — without this,
//! that fallback fails too and `hush` silently gives up on interactive mode entirely. See
//! `src/fd.rs`'s `dup` for the real aliasing logic.
//!
//! `SYS_UNAME = 137` (see CLAUDE.md's "BusyBox gap analysis" — the "uname/gethostname" gap)
//! continues the sequence past `modules/oxfs`'s `SYS_MKDIR = 136`. Real logic (`src/syscall.rs`'s
//! `sys_uname`, filling in a fixed `struct utsname`) is kernel-resident, same reasoning as
//! everything else this module only ever calls through to.
//!
//! `SYS_SOCKETPAIR = 149` (see CLAUDE.md's "Real networking" known-gaps entry) continues the
//! sequence right past `modules/net`'s own `SYS_POLL = 148`. Registered here, not in
//! `modules/net/`, because it never touches the actual network stack at all -- real
//! `socketpair(2)`'s `(domain, type, protocol, sv_ptr)` shape matches this ABI's 4-register width
//! whole, so no argument-convention patch was needed on the musl side beyond the usual `__NR_*`
//! remap. Real logic (`src/syscall.rs`'s `sys_socketpair`, delegating to `crate::pipe::
//! do_socketpair`) is kernel-resident and pipe-shaped, not socket-shaped -- see that module's own
//! doc comment for why an `AF_UNIX`/`SOCK_STREAM` pair is just two cross-wired pipe buffers here,
//! same reasoning as everything else this module only ever calls through to.
//!
//! `SYS_FCNTL = 151`/`SYS_SHUTDOWN = 152` continue the sequence past `modules/native_abi`'s own
//! `SYS_SET_TID_ADDRESS = 150` (itself right past this module's `SYS_SOCKETPAIR = 149`) -- found
//! missing while tracing BusyBox's `wget` HTTPS path (see CLAUDE.md's "Real networking" known-gaps
//! entry): `libbb/xfuncs.c`'s `ndelay_on`/`ndelay_off`/`close_on_exec_on` call `fcntl`, and
//! `wget.c` itself calls `shutdown(fd, SHUT_WR)` on the same kind of socketpair endpoint
//! `SYS_SOCKETPAIR` already provides. Both `(fd, cmd, arg)`/`(fd, how)` already fit this ABI's
//! register width whole, no argument-convention patch needed. `SYS_SHUTDOWN` lives here rather
//! than `modules/net/`, same reasoning as `SYS_SOCKETPAIR` above -- it only implements real
//! half-close semantics for a `crate::pipe`-backed socketpair endpoint, not a real TCP/UDP socket.
//! Real logic (`src/syscall.rs`'s `sys_fcntl`/`sys_shutdown`) is kernel-resident, same reasoning as
//! everything else this module only ever calls through to.
//!
//! `SYS_GETUID = 158`/`SYS_GETEUID = 159`/`SYS_GETGID = 160`/`SYS_GETEGID = 161`/
//! `SYS_SETUID = 162`/`SYS_SETGID = 163`/`SYS_GETGROUPS = 164` (see CLAUDE.md's "BusyBox gap
//! analysis" -- the "uid/passwd-db model" gap) continue the sequence past `modules/clock`'s own
//! `SYS_GETITIMER = 157`. All seven are real Linux/generic `getuid(2)`-family wire formats
//! (zero/one/two plain-integer arguments, no string argument to mismatch), so only the usual
//! `__NR_*` number remap was needed on the musl side. Real logic (`process::do_getuid`/`do_getgid`/
//! `do_setuid`/`do_setgid`/`do_getgroups`, a new `Process::uid`/`gid` pair) is kernel-resident,
//! same reasoning as everything else this module only ever calls through to -- see those
//! functions' own doc comments for the real POSIX permission rule `setuid`/`setgid` enforce (root
//! may become any uid/gid, anything else may only "become" what it already is) and why
//! `getgroups` reporting a single-element list (the caller's own `gid`) is the complete, correct
//! answer on a kernel with no supplementary-group concept.
//!
//! `SYS_SETGROUPS = 178` is `getgroups`'s write-side counterpart, but — unlike every other syscall
//! in this paragraph — needed an *invented* number: real Linux's own `__NR_setgroups` (`116`) was
//! already independently claimed by this ABI's own `SYS_KILL` (see `modules/signal/`), a real
//! collision found live tracing why `su`'s own `initgroups()` call was dying instead of degrading
//! gracefully (see `src/syscall.rs`'s `ENOSYS` doc comment for the other half of that story). Real
//! logic (`process::do_setgroups`) is a permission-checked no-op — root-only (matching real
//! `setgroups(2)`'s unconditional `CAP_SYS_ADMIN` requirement, unlike `setuid`/`setgid`'s narrower
//! "become yourself" allowance for non-root), doesn't touch the actual list at all since there's
//! still no supplementary-group concept to store it in.
//!
//! `SYS_GETRANDOM = 526` is item 1 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall
//! "pre-reserved ahead of implementation" batch — the first one actually implemented. Matches real
//! `getrandom(2)`'s exact `(buf_ptr, buflen, flags)` wire format, no argument-convention patch
//! needed beyond the number remap already in `bits/syscall.h.in`. Real logic (`src/syscall/
//! ffi.rs`'s `sys_getrandom`) is kernel-resident and delegates straight to `src/random.rs`'s
//! existing SHA-256/ChaCha20 generator (the same one already backing `/dev/random`/`/dev/
//! urandom`) — see that module's own doc comment for the persistent entropy pool and the
//! hypervisor-distrust gate on `RDRAND`/`RDSEED` this syscall inherits for free.
//!
//! `SYS_SYSINFO = 527` is item 2 of the same batch. Matches real `sysinfo(2)`'s exact
//! `(info_ptr)` wire format, no argument-convention patch needed. Real logic (`src/syscall/
//! ffi.rs`'s `sys_sysinfo`/`RawSysinfo`) is kernel-resident and honest about what this kernel
//! actually tracks — real `uptime`/`totalram`/`procs`, `freeram == totalram` (same "no
//! deallocation tracking" reasoning `/proc/meminfo`'s `MemFree` already uses), zero everywhere
//! else (no swap, no page cache, no load average). Not itself a POSIX interface, but the confirmed
//! live blocker for `free`/`uptime`'s primary numbers.
#![no_std]

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_register_syscall(
        number: u64,
        handler: extern "C" fn(u64, u64, u64, u64) -> i64,
    ) -> i32;
    fn oxidebsd_sys_pipe(fds_ptr: u64) -> i64;
    fn oxidebsd_sys_pipe2(fds_ptr: u64, flags: u64) -> i64;
    fn oxidebsd_sys_dup2(oldfd: u64, newfd: u64) -> i64;
    fn oxidebsd_sys_setpgid(pid: u64, pgid: u64) -> i64;
    fn oxidebsd_sys_getpgid(pid: u64) -> i64;
    fn oxidebsd_sys_setsid() -> i64;
    fn oxidebsd_sys_getsid(pid: u64) -> i64;
    fn oxidebsd_sys_ioctl(fd: u64, request: u64, argp: u64) -> i64;
    fn oxidebsd_sys_get_keyevent(out_ptr: u64) -> i64;
    fn oxidebsd_sys_dup(oldfd: u64) -> i64;
    fn oxidebsd_sys_uname(uts_ptr: u64) -> i64;
    fn oxidebsd_sys_socketpair(domain: u64, ty: u64, protocol: u64, fds_ptr: u64) -> i64;
    fn oxidebsd_sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64;
    fn oxidebsd_sys_shutdown(fd: u64, how: u64) -> i64;
    fn oxidebsd_sys_getuid() -> i64;
    fn oxidebsd_sys_geteuid() -> i64;
    fn oxidebsd_sys_getgid() -> i64;
    fn oxidebsd_sys_getegid() -> i64;
    fn oxidebsd_sys_setuid(uid: u64) -> i64;
    fn oxidebsd_sys_setgid(gid: u64) -> i64;
    fn oxidebsd_sys_setresuid(ruid: u64, euid: u64, suid: u64) -> i64;
    fn oxidebsd_sys_getgroups(size: u64, list_ptr: u64) -> i64;
    fn oxidebsd_sys_setgroups(count: u64, list_ptr: u64) -> i64;
    fn oxidebsd_sys_prlimit64(pid: u64, resource: u64, new_ptr: u64, old_ptr: u64) -> i64;
    fn oxidebsd_sys_setpriority(which: u64, who: u64, prio: u64) -> i64;
    fn oxidebsd_sys_getpriority(which: u64, who: u64) -> i64;
    fn oxidebsd_sys_sched_setscheduler(pid: u64, policy: u64, param_ptr: u64) -> i64;
    fn oxidebsd_sys_sched_setparam(pid: u64, param_ptr: u64) -> i64;
    fn oxidebsd_sys_sched_getscheduler(pid: u64) -> i64;
    fn oxidebsd_sys_sched_getparam(pid: u64, param_ptr: u64) -> i64;
    fn oxidebsd_sys_sched_getaffinity(pid: u64, cpusetsize: u64, mask_ptr: u64) -> i64;
    fn oxidebsd_sys_sched_get_priority_max(policy: u64) -> i64;
    fn oxidebsd_sys_sched_get_priority_min(policy: u64) -> i64;
    fn oxidebsd_sys_sched_rr_get_interval(pid: u64, ts_ptr: u64) -> i64;
    fn oxidebsd_sys_sched_yield() -> i64;
    fn oxidebsd_sys_reboot(cmd: u64) -> i64;
    fn oxidebsd_sys_futex(addr: u64, op: u64, val: u64, to: u64) -> i64;
    fn oxidebsd_sys_futex_requeue(addr: u64, addr2: u64, nr_wake: u64, nr_requeue: u64) -> i64;
    fn oxidebsd_sys_mlock(addr: u64, len: u64) -> i64;
    fn oxidebsd_sys_munlock(addr: u64, len: u64) -> i64;
    fn oxidebsd_sys_mlockall(flags: u64) -> i64;
    fn oxidebsd_sys_munlockall() -> i64;
    fn oxidebsd_sys_umask(new_mask: u64) -> i64;
    fn oxidebsd_sys_getrusage(who: u64, rusage_ptr: u64) -> i64;
    fn oxidebsd_sys_times(tms_ptr: u64) -> i64;
    fn oxidebsd_sys_getrandom(buf_ptr: u64, buflen: u64, flags: u64) -> i64;
    fn oxidebsd_sys_sysinfo(info_ptr: u64) -> i64;
    fn oxidebsd_sys_mq_open(name_ptr: u64, flags: u64, mode: u64, attr_ptr: u64) -> i64;
    fn oxidebsd_sys_mq_unlink(name_ptr: u64) -> i64;
    fn oxidebsd_sys_mq_timedsend(mqd_and_len: u64, msg_ptr: u64, prio: u64, at_ptr: u64) -> i64;
    fn oxidebsd_sys_mq_timedreceive(
        mqd_and_len: u64,
        msg_ptr: u64,
        prio_ptr: u64,
        at_ptr: u64,
    ) -> i64;
    fn oxidebsd_sys_mq_notify(mqd: u64, sev_ptr: u64) -> i64;
    fn oxidebsd_sys_mq_getsetattr(mqd: u64, new_ptr: u64, old_ptr: u64) -> i64;
    fn oxidebsd_sys_msgget(key: u64, flag: u64) -> i64;
    fn oxidebsd_sys_msgsnd(q: u64, m: u64, len: u64, flag: u64) -> i64;
    fn oxidebsd_sys_msgrcv(q_and_flag: u64, m: u64, len: u64, msgtyp: u64) -> i64;
    fn oxidebsd_sys_msgctl(q: u64, cmd: u64, buf_ptr: u64) -> i64;
    fn oxidebsd_sys_semget(key: u64, nsems: u64, flag: u64) -> i64;
    fn oxidebsd_sys_semop(id: u64, sops_ptr: u64, nsops: u64) -> i64;
    fn oxidebsd_sys_semctl(id: u64, semnum: u64, cmd: u64, arg: u64) -> i64;
    fn oxidebsd_sys_semtimedop(id: u64, sops_ptr: u64, nsops: u64, ts_ptr: u64) -> i64;
    fn oxidebsd_sys_shmget(key: u64, size: u64, shmflg: u64) -> i64;
    fn oxidebsd_sys_shmat(id: u64, shmaddr: u64, shmflg: u64) -> i64;
    fn oxidebsd_sys_shmctl(id: u64, cmd: u64, arg: u64) -> i64;
    fn oxidebsd_sys_shmdt(shmaddr: u64) -> i64;
}

fn log(message: &str) {
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
}

/// `SYS_PIPE = 105`/`SYS_DUP2 = 106` — OxideBSD's own invention, numbered continuing on from the
/// musl-port-driven `mmap`/`munmap`/`brk`/`set_fs_base`/`writev` (`100`-`104`) `native_abi`
/// already registers, though both happen to match real `pipe(2)`/`dup2(2)`'s own argument shapes
/// exactly (see `src/syscall.rs`'s own doc comments on `sys_pipe`/`sys_dup2` for why neither needed
/// an invented wire format the way `open`/`execve` did).
const SYS_PIPE: u64 = 105;
const SYS_DUP2: u64 = 106;
const SYS_SETPGID: u64 = 120;
const SYS_GETPGID: u64 = 121;
/// Real x86_64 Linux's own `__NR_setsid` (`112`) -- see `sys_setsid`'s own doc comment in
/// `src/syscall.rs` for why this is the one syscall in this whole module that needed neither an
/// invented number nor a musl-side call-site patch.
const SYS_SETSID: u64 = 112;
const SYS_IOCTL: u64 = 124;
const SYS_DUP: u64 = 125;
const SYS_UNAME: u64 = 137;
const SYS_SOCKETPAIR: u64 = 149;
const SYS_FCNTL: u64 = 151;
const SYS_SHUTDOWN: u64 = 152;
const SYS_GETUID: u64 = 158;
const SYS_GETEUID: u64 = 159;
const SYS_GETGID: u64 = 160;
const SYS_GETEGID: u64 = 161;
const SYS_SETUID: u64 = 162;
const SYS_SETGID: u64 = 163;
/// Real, unclaimed `__NR_setresuid` -- moved here from its original real value `117` by the
/// numeric-collision sweep (see `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own table: `117` collided with
/// this ABI's own `SYS_SIGACTION`). Also backs `seteuid()` -- see `process::do_setresuid`'s own
/// doc comment.
const SYS_SETRESUID: u64 = 499;
const SYS_GETGROUPS: u64 = 164;
/// Invented -- real `__NR_setgroups` (`116`) was already independently claimed by this ABI's own
/// `SYS_KILL`, a real collision found live (see `third_party/musl/arch/x86_64/bits/syscall.h.in`'s
/// own comment on that line for the full story). Continues the invented sequence right past
/// `SYS_GETSID = 177`.
const SYS_SETGROUPS: u64 = 178;
/// Invented -- real x86_64 Linux's own `__NR_getsid` (`124`) already means `SYS_IOCTL` here, see
/// `sys_getsid`'s own doc comment in `src/syscall.rs`. Continues the invented sequence right past
/// `modules/oxfs`'s own `SYS_UMOUNT2 = 176`.
const SYS_GETSID: u64 = 177;

/// `SYS_PRLIMIT64 = 478` through `SYS_REBOOT = 486` are this ABI's process-attribute half of the
/// NEEDS_SYSCALL gap-table pass (`modules/oxfs`'s own `SYS_FSYNC = 471` through `SYS_FSTATFS =
/// 477` are the filesystem-owned half). None of these six continue this module's own existing
/// 105-178 invented sequence -- a first attempt at that collided with a *second* set of real,
/// still-inert Linux syscalls sharing those same low numbers (see `third_party/musl/arch/
/// x86_64/bits/syscall.h.in`'s own comment on `__NR_flock`, right near `__NR_fsync`, for the full
/// story on why 471-486 is used instead).
const SYS_PRLIMIT64: u64 = 478;
const SYS_SETPRIORITY: u64 = 479;
const SYS_GETPRIORITY: u64 = 480;
const SYS_SCHED_SETSCHEDULER: u64 = 481;
const SYS_SCHED_GETSCHEDULER: u64 = 482;
const SYS_SCHED_GETPARAM: u64 = 483;
/// Real x86_64 Linux's own `__NR_sched_setparam` (`142`) is already claimed by this ABI's own
/// `SYS_SENDTO` -- `third_party/musl/arch/x86_64/bits/syscall.h.in` already remapped
/// `__NR_sched_setparam` to `507` (an unclaimed real-Linux value past this ABI's own highest
/// invented number), but no kernel handler was ever registered at it -- musl's own
/// `sched_setparam(2)` wrapper was left permanently stubbed to `ENOSYS`, so the remap was
/// unreachable dead code until now. See `process::do_sched_setparam`'s own doc comment.
const SYS_SCHED_SETPARAM: u64 = 507;
/// Real Linux's own `__NR_sched_getaffinity = 204`, used directly rather than continuing this
/// module's `478`-`491` invented batch -- confirmed unassigned anywhere in this ABI's own registry
/// before landing here (same reverse-direction check as always: no invented number already claims
/// this real value). See `process::do_sched_getaffinity`'s own doc comment in `src/process.rs` for
/// the real single-core-mask logic and the BusyBox `nproc` bug this closes.
const SYS_SCHED_GETAFFINITY: u64 = 204;
const SYS_SCHED_GET_PRIORITY_MAX: u64 = 484;
const SYS_SCHED_GET_PRIORITY_MIN: u64 = 485;
/// OxideBSD's own invention -- already pre-reserved (with no kernel handler) in
/// `bits/syscall.h.in` back when the rest of this `sched_*` batch first landed; only now given a
/// real `process::do_sched_rr_get_interval` handler. See that function's own doc comment.
const SYS_SCHED_RR_GET_INTERVAL: u64 = 508;
/// Real x86_64 Linux's own `__NR_sched_yield` (`24`), unremapped -- musl's own `sched_yield()`
/// already calls straight through with no argument-convention issue (a real zero-argument call).
/// See `process::do_sched_yield`'s own doc comment.
const SYS_SCHED_YIELD: u64 = 24;
/// Real Linux's own `__NR_futex = 202`, used directly -- same "confirmed unassigned in this ABI's
/// own registry" reasoning `SYS_SCHED_GETAFFINITY` above already establishes. See
/// `process::do_futex`'s own doc comment in `src/process/limits.rs` for why this is a real, honest
/// failure stub (not real futex support) and the live `sem_wait/7-1.c` infinite-busy-loop it closes.
const SYS_FUTEX: u64 = 202;
/// OxideBSD's own invention (`557`, continuing right past `SYS_EXIT_GROUP=556`, the current
/// highest assigned number as of this addition). See `process::do_futex_requeue`'s own doc comment
/// in `src/process/limits.rs` for why real `FUTEX_REQUEUE` needed a dedicated syscall rather than
/// riding `SYS_FUTEX` itself, and the real `pthread_cond_timedwait/2-5.c` hang this closes.
const SYS_FUTEX_REQUEUE: u64 = 557;
/// OxideBSD's own invention (`558`, continuing right past `SYS_FUTEX_REQUEUE=557`, the current
/// highest assigned number as of this addition) -- real, general-purpose raw keyboard-event
/// polling for the fbdoom/doomgeneric port and any future consumer needing held-key state (not
/// recoverable from `console::stdin`'s own decoded-ASCII stream). See
/// `console::keyevents`'s own module doc comment and `syscall::ffi::sys_get_keyevent`'s doc
/// comment.
const SYS_GET_KEYEVENT: u64 = 558;
/// Real Linux's own `__NR_mlock`/`__NR_munlock`/`__NR_mlockall`/`__NR_munlockall` are `149`-`152`,
/// but those slots are already claimed by this ABI's own live `SYS_SOCKETPAIR`/
/// `SYS_SET_TID_ADDRESS`/`SYS_FCNTL`/`SYS_SHUTDOWN` — `third_party/musl/arch/x86_64/bits/
/// syscall.h.in` (the `oxidebsd` branch) was already patched in a prior collision-avoidance sweep
/// to move them here (`509`-`512`), continuing the same `493+` block `docs/
/// MISSING_POSIX_SYSCALLS.md`'s own collision table documents — but no kernel-side handler was ever
/// registered at the new numbers, so every real caller (including the POSIX conformance pilot's own
/// `mlock`/`munlock`/`mlockall`/`munlockall` test files) hit a clean `ENOSYS` until now. See
/// `process::mm::do_mlock`'s own doc comment for why these are honest, range-checked no-op
/// successes rather than real memory locking.
const SYS_MLOCK: u64 = 509;
const SYS_MUNLOCK: u64 = 510;
const SYS_MLOCKALL: u64 = 511;
const SYS_MUNLOCKALL: u64 = 512;
const SYS_REBOOT: u64 = 486;
/// Continues the same 471-486 batch one past `SYS_REBOOT = 486` -- see this module's own
/// `SYS_PRLIMIT64` doc comment for why that batch landed there instead of continuing this
/// module's earlier 105-178 invented sequence. Found live testing `chmod +x` on a real script:
/// BusyBox's `libbb/parse_mode.c` calls `umask(0)`/`umask(old)` unconditionally to compute
/// symbolic mode changes, and with this unmapped it silently read back a garbage `ENOSYS`-derived
/// value instead of a real mask (real POSIX `umask()` can't fail, so musl's own wrapper never
/// checks for an error at all). See `src/process.rs`'s `do_umask`/`Process::umask` for the real
/// per-process, stored-not-enforced semantics this backs.
const SYS_UMASK: u64 = 487;
/// Invented -- continues past `modules/oxfs`'s own `SYS_CHROOT = 490` (the highest number assigned
/// anywhere in this ABI as of that pass), not this module's own `105`-`178`/`478`-`487` sequences.
/// Same "grep every still-inert real Linux `__NR_*` value in `bits/syscall.h.in`" audit as always
/// -- real `__NR_getrusage` is `98`, nowhere near `491`. Process-resource-adjacent, same module as
/// `SYS_PRLIMIT64`/`SYS_SETPRIORITY` above, not `modules/oxfs` (no filesystem state involved). See
/// `src/syscall.rs`'s own `sys_getrusage`/`RawRusage` for the real (honestly all-zero) logic.
const SYS_GETRUSAGE: u64 = 491;
/// Real `times`'s own wire slot -- redirected here off its previous accidental collision with
/// `SYS_MMAP = 100` by the full header sweep in `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`. Same
/// process-resource-adjacent placement as `SYS_GETRUSAGE` just above (`src/syscall/ffi.rs`'s
/// `sys_times`/`RawTms` for the real, honestly all-zero logic).
const SYS_TIMES: u64 = 493;
/// Item 1 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of
/// implementation" batch -- a permanent OxideBSD-invented number claimed before this handler
/// existed (see that doc's own numbering-discipline note for why: this ABI doesn't want its own
/// planned syscalls sitting at borrowed real-Linux numbers just because the slot happened to be
/// free). Real logic (`src/syscall/ffi.rs`'s `sys_getrandom`, delegating to `src/random.rs`'s
/// existing generator) is kernel-resident, same reasoning as everything else this module only
/// ever calls through to.
const SYS_GETRANDOM: u64 = 526;
/// Item 2 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall "pre-reserved ahead of
/// implementation" batch -- same pre-claimed-before-the-handler-existed reasoning as
/// `SYS_GETRANDOM` just above. Real logic (`src/syscall/ffi.rs`'s `sys_sysinfo`/`RawSysinfo`) is
/// kernel-resident; this module only ever calls through to it.
const SYS_SYSINFO: u64 = 527;
/// Items 11-16 of the same 28-syscall pre-reserved batch -- the POSIX message-queue sub-batch,
/// see `src/fs/mqueue.rs`'s own doc comment for the real logic (`crate::fs::mqueue`, kernel-
/// resident since this module can't use `alloc`). `mq_close` isn't its own number -- see that
/// module's doc comment for why an mqd rides the ordinary `SYS_CLOSE` path instead.
const SYS_MQ_OPEN: u64 = 536;
const SYS_MQ_UNLINK: u64 = 537;
const SYS_MQ_TIMEDSEND: u64 = 538;
const SYS_MQ_TIMEDRECEIVE: u64 = 539;
const SYS_MQ_NOTIFY: u64 = 540;
const SYS_MQ_GETSETATTR: u64 = 541;
/// Items 25-28, last sub-batch of the same 28-syscall pre-reserved batch -- real SysV message
/// queues, see `src/fs/sysv_msg.rs`'s own doc comment (`crate::fs::sysv_msg`, kernel-resident
/// since this module can't use `alloc`) for the real logic and how it differs from the POSIX
/// `mq_*` family just above.
const SYS_MSGGET: u64 = 550;
const SYS_MSGSND: u64 = 551;
const SYS_MSGRCV: u64 = 552;
const SYS_MSGCTL: u64 = 553;
/// Items 21-24 of `OxideBSD-doc/MISSING_POSIX_SYSCALLS.md`'s own 28-syscall pre-reserved batch. See
/// `src/fs/sysv_sem.rs`'s own doc comment for the full design.
const SYS_SEMGET: u64 = 546;
const SYS_SEMOP: u64 = 547;
const SYS_SEMCTL: u64 = 548;
const SYS_SEMTIMEDOP: u64 = 549;
/// Items 17-20, the last sub-batch of the same 28-syscall pre-reserved batch, closing the whole
/// thing out. See `src/fs/sysv_shm.rs`'s own doc comment for the full design.
const SYS_SHMGET: u64 = 542;
const SYS_SHMAT: u64 = 543;
const SYS_SHMCTL: u64 = 544;
const SYS_SHMDT: u64 = 545;

/// Real, unremapped Linux `__NR_set_robust_list=273` (confirmed unclaimed) -- both of this musl
/// fork's own real callers (`src/thread/pthread_create.c`, `src/thread/pthread_mutex_trylock.c`)
/// issue it as pure best-effort bookkeeping and discard its return value entirely, so a real,
/// honest no-op success is exactly as correct as a genuine robust-mutex-crash-recovery list would
/// be from any caller's own perspective -- this kernel has no equivalent recovery mechanism to
/// register into regardless (no crash-time futex-owner cleanup exists here at all).
const SYS_SET_ROBUST_LIST: u64 = 273;
/// Real, unremapped Linux `__NR_pipe2=293` (confirmed unclaimed). Was already reachable via
/// `third_party/musl/src/unistd/pipe2.c`'s own `ENOSYS`-triggered fallback (plain `pipe()` +
/// `fcntl(F_SETFD)`/`fcntl(F_SETFL)` per requested flag) -- registering the real syscall directly
/// just collapses that into one round trip instead of up to three, real functional behavior
/// unchanged either way.
const SYS_PIPE2: u64 = 293;

extern "C" fn handle_pipe(fds_ptr: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_pipe(fds_ptr) }
}

extern "C" fn handle_set_robust_list(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    0
}

/// Real `pipe2(2)` -- thin delegator, same shape as `handle_pipe`/`handle_fcntl` above. The real
/// logic (pipe creation plus applying `O_CLOEXEC`/`O_NONBLOCK` to both ends) stays kernel-resident
/// in `oxidebsd_sys_pipe2` -- it needs `crate::process::scheduler::current_pid()` for
/// `set_cloexec`, not reachable from a relocated module.
extern "C" fn handle_pipe2(fds_ptr: u64, flags: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_pipe2(fds_ptr, flags) }
}

extern "C" fn handle_dup2(oldfd: u64, newfd: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_dup2(oldfd, newfd) }
}

extern "C" fn handle_setpgid(pid: u64, pgid: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_setpgid(pid, pgid) }
}

extern "C" fn handle_getpgid(pid: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_getpgid(pid) }
}

extern "C" fn handle_setsid(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_setsid() }
}

extern "C" fn handle_getsid(pid: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getsid(pid) }
}

extern "C" fn handle_ioctl(fd: u64, request: u64, argp: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_ioctl(fd, request, argp) }
}

extern "C" fn handle_get_keyevent(out_ptr: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_get_keyevent(out_ptr) }
}

extern "C" fn handle_dup(oldfd: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_dup(oldfd) }
}

extern "C" fn handle_uname(uts_ptr: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_uname(uts_ptr) }
}

extern "C" fn handle_socketpair(domain: u64, ty: u64, protocol: u64, fds_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_socketpair(domain, ty, protocol, fds_ptr) }
}

extern "C" fn handle_fcntl(fd: u64, cmd: u64, arg: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_fcntl(fd, cmd, arg) }
}

extern "C" fn handle_shutdown(fd: u64, how: u64, _arg2: u64, _arg3: u64) -> i64 {
    unsafe { oxidebsd_sys_shutdown(fd, how) }
}

extern "C" fn handle_getuid(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getuid() }
}

extern "C" fn handle_geteuid(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_geteuid() }
}

extern "C" fn handle_getgid(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getgid() }
}

extern "C" fn handle_getegid(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getegid() }
}

extern "C" fn handle_setuid(uid: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_setuid(uid) }
}

extern "C" fn handle_setgid(gid: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_setgid(gid) }
}

extern "C" fn handle_setresuid(ruid: u64, euid: u64, suid: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_setresuid(ruid, euid, suid) }
}

extern "C" fn handle_getgroups(size: u64, list_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getgroups(size, list_ptr) }
}

extern "C" fn handle_setgroups(count: u64, list_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_setgroups(count, list_ptr) }
}

extern "C" fn handle_prlimit64(pid: u64, resource: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_prlimit64(pid, resource, new_ptr, old_ptr) }
}

extern "C" fn handle_setpriority(which: u64, who: u64, prio: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_setpriority(which, who, prio) }
}

extern "C" fn handle_getpriority(which: u64, who: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getpriority(which, who) }
}

extern "C" fn handle_sched_setscheduler(pid: u64, policy: u64, param_ptr: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_setscheduler(pid, policy, param_ptr) }
}

extern "C" fn handle_sched_setparam(pid: u64, param_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_setparam(pid, param_ptr) }
}

extern "C" fn handle_sched_getscheduler(pid: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_getscheduler(pid) }
}

extern "C" fn handle_sched_getparam(pid: u64, param_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_getparam(pid, param_ptr) }
}

extern "C" fn handle_sched_getaffinity(
    pid: u64,
    cpusetsize: u64,
    mask_ptr: u64,
    _a3: u64,
) -> i64 {
    unsafe { oxidebsd_sys_sched_getaffinity(pid, cpusetsize, mask_ptr) }
}

extern "C" fn handle_sched_get_priority_max(policy: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_get_priority_max(policy) }
}

extern "C" fn handle_sched_get_priority_min(policy: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_get_priority_min(policy) }
}

extern "C" fn handle_sched_rr_get_interval(pid: u64, ts_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_rr_get_interval(pid, ts_ptr) }
}

extern "C" fn handle_sched_yield(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sched_yield() }
}

/// Real `reboot(int type)`'s musl-side call site (`third_party/musl/src/linux/reboot.c`) passes
/// the two real magic numbers as the syscall's first two arguments and `type` as the third --
/// this handler picks `cmd` out of the third register (`argp`-equivalent position) rather than the
/// first, matching that real wire shape instead of assuming a single-argument one.
extern "C" fn handle_reboot(_magic1: u64, _magic2: u64, cmd: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_reboot(cmd) }
}

extern "C" fn handle_futex(addr: u64, op: u64, val: u64, to: u64) -> i64 {
    unsafe { oxidebsd_sys_futex(addr, op, val, to) }
}

extern "C" fn handle_futex_requeue(addr: u64, addr2: u64, nr_wake: u64, nr_requeue: u64) -> i64 {
    unsafe { oxidebsd_sys_futex_requeue(addr, addr2, nr_wake, nr_requeue) }
}

extern "C" fn handle_mlock(addr: u64, len: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_mlock(addr, len) }
}

extern "C" fn handle_munlock(addr: u64, len: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_munlock(addr, len) }
}

extern "C" fn handle_mlockall(flags: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_mlockall(flags) }
}

extern "C" fn handle_munlockall(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_munlockall() }
}

extern "C" fn handle_umask(new_mask: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_umask(new_mask) }
}

extern "C" fn handle_getrusage(who: u64, rusage_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getrusage(who, rusage_ptr) }
}

extern "C" fn handle_times(tms_ptr: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_times(tms_ptr) }
}

extern "C" fn handle_getrandom(buf_ptr: u64, buflen: u64, flags: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_getrandom(buf_ptr, buflen, flags) }
}

extern "C" fn handle_sysinfo(info_ptr: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_sysinfo(info_ptr) }
}

extern "C" fn handle_mq_open(name_ptr: u64, flags: u64, mode: u64, attr_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_mq_open(name_ptr, flags, mode, attr_ptr) }
}

extern "C" fn handle_mq_unlink(name_ptr: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_mq_unlink(name_ptr) }
}

extern "C" fn handle_mq_timedsend(mqd_and_len: u64, msg_ptr: u64, prio: u64, at_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_mq_timedsend(mqd_and_len, msg_ptr, prio, at_ptr) }
}

extern "C" fn handle_mq_timedreceive(
    mqd_and_len: u64,
    msg_ptr: u64,
    prio_ptr: u64,
    at_ptr: u64,
) -> i64 {
    unsafe { oxidebsd_sys_mq_timedreceive(mqd_and_len, msg_ptr, prio_ptr, at_ptr) }
}

extern "C" fn handle_mq_notify(mqd: u64, sev_ptr: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_mq_notify(mqd, sev_ptr) }
}

extern "C" fn handle_mq_getsetattr(mqd: u64, new_ptr: u64, old_ptr: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_mq_getsetattr(mqd, new_ptr, old_ptr) }
}

extern "C" fn handle_msgget(key: u64, flag: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_msgget(key, flag) }
}

extern "C" fn handle_msgsnd(q: u64, m: u64, len: u64, flag: u64) -> i64 {
    unsafe { oxidebsd_sys_msgsnd(q, m, len, flag) }
}

extern "C" fn handle_msgrcv(q_and_flag: u64, m: u64, len: u64, msgtyp: u64) -> i64 {
    unsafe { oxidebsd_sys_msgrcv(q_and_flag, m, len, msgtyp) }
}

extern "C" fn handle_msgctl(q: u64, cmd: u64, buf_ptr: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_msgctl(q, cmd, buf_ptr) }
}

extern "C" fn handle_semget(key: u64, nsems: u64, flag: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_semget(key, nsems, flag) }
}

extern "C" fn handle_semop(id: u64, sops_ptr: u64, nsops: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_semop(id, sops_ptr, nsops) }
}

extern "C" fn handle_semctl(id: u64, semnum: u64, cmd: u64, arg: u64) -> i64 {
    unsafe { oxidebsd_sys_semctl(id, semnum, cmd, arg) }
}

extern "C" fn handle_semtimedop(id: u64, sops_ptr: u64, nsops: u64, ts_ptr: u64) -> i64 {
    unsafe { oxidebsd_sys_semtimedop(id, sops_ptr, nsops, ts_ptr) }
}

extern "C" fn handle_shmget(key: u64, size: u64, shmflg: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_shmget(key, size, shmflg) }
}

extern "C" fn handle_shmat(id: u64, shmaddr: u64, shmflg: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_shmat(id, shmaddr, shmflg) }
}

extern "C" fn handle_shmctl(id: u64, cmd: u64, arg: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_shmctl(id, cmd, arg) }
}

extern "C" fn handle_shmdt(shmaddr: u64, _a1: u64, _a2: u64, _a3: u64) -> i64 {
    unsafe { oxidebsd_sys_shmdt(shmaddr) }
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    unsafe {
        oxidebsd_register_syscall(SYS_PIPE, handle_pipe);
        oxidebsd_register_syscall(SYS_PIPE2, handle_pipe2);
        oxidebsd_register_syscall(SYS_SET_ROBUST_LIST, handle_set_robust_list);
        oxidebsd_register_syscall(SYS_DUP2, handle_dup2);
        oxidebsd_register_syscall(SYS_SETPGID, handle_setpgid);
        oxidebsd_register_syscall(SYS_GETPGID, handle_getpgid);
        oxidebsd_register_syscall(SYS_SETSID, handle_setsid);
        oxidebsd_register_syscall(SYS_GETSID, handle_getsid);
        oxidebsd_register_syscall(SYS_IOCTL, handle_ioctl);
        oxidebsd_register_syscall(SYS_GET_KEYEVENT, handle_get_keyevent);
        oxidebsd_register_syscall(SYS_DUP, handle_dup);
        oxidebsd_register_syscall(SYS_UNAME, handle_uname);
        oxidebsd_register_syscall(SYS_SOCKETPAIR, handle_socketpair);
        oxidebsd_register_syscall(SYS_FCNTL, handle_fcntl);
        oxidebsd_register_syscall(SYS_SHUTDOWN, handle_shutdown);
        oxidebsd_register_syscall(SYS_GETUID, handle_getuid);
        oxidebsd_register_syscall(SYS_GETEUID, handle_geteuid);
        oxidebsd_register_syscall(SYS_GETGID, handle_getgid);
        oxidebsd_register_syscall(SYS_GETEGID, handle_getegid);
        oxidebsd_register_syscall(SYS_SETUID, handle_setuid);
        oxidebsd_register_syscall(SYS_SETGID, handle_setgid);
        oxidebsd_register_syscall(SYS_SETRESUID, handle_setresuid);
        oxidebsd_register_syscall(SYS_GETGROUPS, handle_getgroups);
        oxidebsd_register_syscall(SYS_SETGROUPS, handle_setgroups);
        oxidebsd_register_syscall(SYS_PRLIMIT64, handle_prlimit64);
        oxidebsd_register_syscall(SYS_SETPRIORITY, handle_setpriority);
        oxidebsd_register_syscall(SYS_GETPRIORITY, handle_getpriority);
        oxidebsd_register_syscall(SYS_SCHED_SETSCHEDULER, handle_sched_setscheduler);
        oxidebsd_register_syscall(SYS_SCHED_SETPARAM, handle_sched_setparam);
        oxidebsd_register_syscall(SYS_SCHED_GETSCHEDULER, handle_sched_getscheduler);
        oxidebsd_register_syscall(SYS_SCHED_GETPARAM, handle_sched_getparam);
        oxidebsd_register_syscall(SYS_SCHED_GETAFFINITY, handle_sched_getaffinity);
        oxidebsd_register_syscall(SYS_SCHED_GET_PRIORITY_MAX, handle_sched_get_priority_max);
        oxidebsd_register_syscall(SYS_SCHED_GET_PRIORITY_MIN, handle_sched_get_priority_min);
        oxidebsd_register_syscall(SYS_SCHED_RR_GET_INTERVAL, handle_sched_rr_get_interval);
        oxidebsd_register_syscall(SYS_SCHED_YIELD, handle_sched_yield);
        oxidebsd_register_syscall(SYS_REBOOT, handle_reboot);
        oxidebsd_register_syscall(SYS_FUTEX, handle_futex);
        oxidebsd_register_syscall(SYS_FUTEX_REQUEUE, handle_futex_requeue);
        oxidebsd_register_syscall(SYS_MLOCK, handle_mlock);
        oxidebsd_register_syscall(SYS_MUNLOCK, handle_munlock);
        oxidebsd_register_syscall(SYS_MLOCKALL, handle_mlockall);
        oxidebsd_register_syscall(SYS_MUNLOCKALL, handle_munlockall);
        oxidebsd_register_syscall(SYS_UMASK, handle_umask);
        oxidebsd_register_syscall(SYS_GETRUSAGE, handle_getrusage);
        oxidebsd_register_syscall(SYS_TIMES, handle_times);
        oxidebsd_register_syscall(SYS_GETRANDOM, handle_getrandom);
        oxidebsd_register_syscall(SYS_SYSINFO, handle_sysinfo);
        oxidebsd_register_syscall(SYS_MQ_OPEN, handle_mq_open);
        oxidebsd_register_syscall(SYS_MQ_UNLINK, handle_mq_unlink);
        oxidebsd_register_syscall(SYS_MQ_TIMEDSEND, handle_mq_timedsend);
        oxidebsd_register_syscall(SYS_MQ_TIMEDRECEIVE, handle_mq_timedreceive);
        oxidebsd_register_syscall(SYS_MQ_NOTIFY, handle_mq_notify);
        oxidebsd_register_syscall(SYS_MQ_GETSETATTR, handle_mq_getsetattr);
        oxidebsd_register_syscall(SYS_MSGGET, handle_msgget);
        oxidebsd_register_syscall(SYS_MSGSND, handle_msgsnd);
        oxidebsd_register_syscall(SYS_MSGRCV, handle_msgrcv);
        oxidebsd_register_syscall(SYS_MSGCTL, handle_msgctl);
        oxidebsd_register_syscall(SYS_SEMGET, handle_semget);
        oxidebsd_register_syscall(SYS_SEMOP, handle_semop);
        oxidebsd_register_syscall(SYS_SEMCTL, handle_semctl);
        oxidebsd_register_syscall(SYS_SEMTIMEDOP, handle_semtimedop);
        oxidebsd_register_syscall(SYS_SHMGET, handle_shmget);
        oxidebsd_register_syscall(SYS_SHMAT, handle_shmat);
        oxidebsd_register_syscall(SYS_SHMCTL, handle_shmctl);
        oxidebsd_register_syscall(SYS_SHMDT, handle_shmdt);
    }
    log(
        "[module] posix_compat: module_init running (registered SYS_PIPE/SYS_PIPE2/SYS_SET_ROBUST_LIST/SYS_DUP2/SYS_SETPGID/SYS_GETPGID/SYS_SETSID/SYS_GETSID/SYS_IOCTL/SYS_DUP/SYS_UNAME/SYS_SOCKETPAIR/SYS_FCNTL/SYS_SHUTDOWN/SYS_GETUID/SYS_GETEUID/SYS_GETGID/SYS_GETEGID/SYS_SETUID/SYS_SETGID/SYS_SETRESUID/SYS_GETGROUPS/SYS_SETGROUPS/SYS_PRLIMIT64/SYS_SETPRIORITY/SYS_GETPRIORITY/SYS_SCHED_SETSCHEDULER/SYS_SCHED_SETPARAM/SYS_SCHED_GETSCHEDULER/SYS_SCHED_GETPARAM/SYS_SCHED_GETAFFINITY/SYS_SCHED_GET_PRIORITY_MAX/SYS_SCHED_GET_PRIORITY_MIN/SYS_SCHED_RR_GET_INTERVAL/SYS_SCHED_YIELD/SYS_REBOOT/SYS_FUTEX/SYS_FUTEX_REQUEUE/SYS_MLOCK/SYS_MUNLOCK/SYS_MLOCKALL/SYS_MUNLOCKALL/SYS_UMASK/SYS_GETRUSAGE/SYS_TIMES/SYS_GETRANDOM/SYS_SYSINFO/SYS_MQ_OPEN/SYS_MQ_UNLINK/SYS_MQ_TIMEDSEND/SYS_MQ_TIMEDRECEIVE/SYS_MQ_NOTIFY/SYS_MQ_GETSETATTR/SYS_MSGGET/SYS_MSGSND/SYS_MSGRCV/SYS_MSGCTL/SYS_SEMGET/SYS_SEMOP/SYS_SEMCTL/SYS_SEMTIMEDOP/SYS_SHMGET/SYS_SHMAT/SYS_SHMCTL/SYS_SHMDT/SYS_GET_KEYEVENT)\n",
    );
    0
}
