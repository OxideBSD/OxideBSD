//! Boots the kernel and spawns `regress/kern-syscall-smoke/` as pid 1, which runs
//! `/usr/tests/kern/run.sh`: the kernel's process and descriptor rules each have a fixture there
//! (resource limits, descriptor numbering, ...), added as the shortcuts in OxideBSD-doc
//! `CLEANUP.md` are removed.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oxidebsd::boot::BootInfo;
use oxidebsd::limine_entry_point;
use oxidebsd::qemu::{QemuExitCode, exit_qemu};
use oxidebsd::serial_println;
use oxidebsd::syscall::oxidebsd_register_syscall;

limine_entry_point!(main);

/// Kernel threads (OxideBSD-doc KTHREAD.md §10 step 1): `SYS_TEST_KTHREAD` tells
/// `regress/kern-smoke/kthread.c` the id of a kernel thread that sleeps for good (`0`), the
/// verdict of the threads' own checks below (`1`: 0 while they run, 1 when all passed, else 2 |
/// the failed checks << 8), and whether the sleeper is still there (`2`).
const SYS_TEST_KTHREAD: u64 = 9996;

mod kthreads {
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

    use oxidebsd::cpu::interrupts::ticks;
    use oxidebsd::kern::kern_kthread::{alive, kthread_add, kthread_exit, kthread_yield};
    use oxidebsd::kern::kern_synch::{Slept, pause, tsleep, wakeup, wakeup_one};
    use oxidebsd::kern::subr_taskqueue::{self as tq, TASKQUEUE_THREAD, Task};

    /// One bit per check below.
    const CHECKS: u32 = 14;
    static PASSED: AtomicU32 = AtomicU32::new(0);
    static FAILED: AtomicU32 = AtomicU32::new(0);
    pub static VERDICT: AtomicU64 = AtomicU64::new(0);
    pub static SLEEPER: AtomicU64 = AtomicU64::new(0);
    static EXITER: AtomicU64 = AtomicU64::new(0);

    static FLAG: AtomicBool = AtomicBool::new(false);
    static ONE: AtomicU32 = AtomicU32::new(0);
    static TIMEOUT_CHAN: u8 = 0;
    static NEVER_CHAN: u8 = 0;

    fn chan<T>(x: &'static T) -> usize {
        x as *const T as usize
    }

    fn result(check: u32, ok: bool) {
        oxidebsd::serial_println!("kthread-smoke: {}: check {}", if ok { "ok" } else { "FAIL" }, check);
        if ok { &PASSED } else { &FAILED }.fetch_or(1 << check, Ordering::Relaxed);
    }

    /// 0: sleeps until `waker` sets the flag and wakes it.
    fn sleeper(_: usize) {
        let mut woken = 0;
        while !FLAG.load(Ordering::Relaxed) {
            if tsleep(chan(&FLAG), None) == Slept::Woken {
                woken += 1;
            }
        }
        result(0, woken >= 1);
    }

    /// 1: sets the flag after a while, and wakes the sleeper.
    fn waker(_: usize) {
        pause(5);
        FLAG.store(true, Ordering::Relaxed);
        wakeup(chan(&FLAG));
        result(1, true);
    }

    /// 2: a timeout of 3 ticks times out, after 3 ticks.
    fn timeout(_: usize) {
        let t0 = ticks();
        let slept = tsleep(chan(&TIMEOUT_CHAN), Some(3));
        result(2, slept == Slept::TimedOut && ticks() - t0 >= 3);
    }

    fn one_sleeper(_: usize) {
        tsleep(chan(&ONE), None);
        ONE.fetch_add(1, Ordering::Relaxed);
    }

    /// 3, 4: `wakeup_one` wakes one of the two sleepers, then the other.
    fn one_waker(_: usize) {
        pause(3);
        wakeup_one(chan(&ONE));
        pause(3);
        result(3, ONE.load(Ordering::Relaxed) == 1);
        wakeup_one(chan(&ONE));
        pause(3);
        result(4, ONE.load(Ordering::Relaxed) == 2);
    }

    /// 5: yielding comes back.
    fn yielder(_: usize) {
        kthread_yield();
        kthread_yield();
        result(5, true);
    }

    /// 6: runs 150 ms without sleeping: the scheduler logs it ("[kthread] hog ran").
    fn hog(_: usize) {
        let until = oxidebsd::cpu::tsc::now() + oxidebsd::cpu::tsc::ms_to_cycles(150);
        while oxidebsd::cpu::tsc::now() < until {
            core::hint::spin_loop();
        }
        result(6, true);
    }

    /// 7: ends itself with `kthread_exit` (8: and is gone afterwards).
    fn exiter(_: usize) {
        result(7, true);
        kthread_exit();
    }

    /// Sleeps for good: `kthread.c` tries to signal and renice it.
    fn forever(_: usize) {
        loop {
            tsleep(chan(&NEVER_CHAN), None);
        }
    }

    /// Sleeps a tick at a time until `done` holds, for up to a second: the taskq thread may be
    /// running another test's task (`slow` sleeps 5 ticks), so a fixed pause would be a race.
    fn wait_for(done: impl Fn() -> bool) {
        for _ in 0..100 {
            if done() {
                return;
            }
            pause(1);
        }
    }

    /// 9: a task enqueued three times before it runs runs once, told of all three.
    static COALESCED: Task = Task::new(coalesced, 0);
    static COALESCED_SEEN: AtomicU32 = AtomicU32::new(0);
    fn coalesced(_: usize, pending: u32) {
        COALESCED_SEEN.fetch_add(pending << 8 | 1, Ordering::Relaxed);
    }
    fn coalescer(_: usize) {
        for _ in 0..3 {
            tq::enqueue(&TASKQUEUE_THREAD, &COALESCED);
        }
        wait_for(|| COALESCED_SEEN.load(Ordering::Relaxed) != 0);
        pause(5);
        // One run (low byte 1) with pending 3.
        result(9, COALESCED_SEEN.load(Ordering::Relaxed) == 3 << 8 | 1);
    }

    /// 10: a task enqueued by an interrupt handler runs. IRQ 13 (the old FPU line) is free under
    /// QEMU; `int` raises its vector by hand.
    static FROM_IRQ: Task = Task::new(from_irq, 0);
    static FROM_IRQ_SEEN: AtomicU32 = AtomicU32::new(0);
    static IRQ_ARMED: AtomicBool = AtomicBool::new(false);
    fn from_irq(_: usize, pending: u32) {
        FROM_IRQ_SEEN.fetch_add(pending, Ordering::Relaxed);
    }
    fn irq13() {
        if IRQ_ARMED.swap(false, Ordering::Relaxed) {
            tq::enqueue(&TASKQUEUE_THREAD, &FROM_IRQ);
        }
    }
    fn irq_raiser(_: usize) {
        const _: () = assert!(oxidebsd::cpu::pic::PIC_1_OFFSET + 13 == 45);
        oxidebsd::cpu::interrupts::register_irq_handler(13, irq13);
        IRQ_ARMED.store(true, Ordering::Relaxed);
        // SAFETY: vector 45 is IRQ 13's stub; its handlers are ours.
        unsafe { core::arch::asm!("int 45") };
        wait_for(|| FROM_IRQ_SEEN.load(Ordering::Relaxed) != 0);
        pause(5);
        result(10, FROM_IRQ_SEEN.load(Ordering::Relaxed) == 1);
    }

    /// 11: a task enqueued again while it runs runs again.
    static AGAIN: Task = Task::new(again, 0);
    static AGAIN_RUNS: AtomicU32 = AtomicU32::new(0);
    fn again(_: usize, pending: u32) {
        if AGAIN_RUNS.fetch_add(pending, Ordering::Relaxed) == 0 {
            tq::enqueue(&TASKQUEUE_THREAD, &AGAIN);
        }
    }
    fn againer(_: usize) {
        tq::enqueue(&TASKQUEUE_THREAD, &AGAIN);
        wait_for(|| AGAIN_RUNS.load(Ordering::Relaxed) >= 2);
        pause(5);
        result(11, AGAIN_RUNS.load(Ordering::Relaxed) == 2);
    }

    /// 12: `drain` returns only once a task that sleeps has finished.
    static SLOW: Task = Task::new(slow, 0);
    static SLOW_DONE: AtomicBool = AtomicBool::new(false);
    fn slow(_: usize, _: u32) {
        pause(5);
        SLOW_DONE.store(true, Ordering::Relaxed);
    }
    fn drainer(_: usize) {
        tq::enqueue(&TASKQUEUE_THREAD, &SLOW);
        tq::drain(&TASKQUEUE_THREAD, &SLOW);
        result(12, SLOW_DONE.load(Ordering::Relaxed));
    }

    /// 13: a queue of one's own, with two threads of its own, runs its tasks.
    static OWN: Task = Task::new(own, 0);
    static OWN_RAN_ON: AtomicU64 = AtomicU64::new(0);
    fn own(_: usize, _: u32) {
        OWN_RAN_ON.store(oxidebsd::process::scheduler::current_pid(), Ordering::Relaxed);
    }
    fn owner(_: usize) {
        let queue = tq::create("tq-test");
        let ok = tq::start_threads(queue, 2).is_ok();
        tq::enqueue(queue, &OWN);
        tq::drain(queue, &OWN);
        // Only its own threads run it: on a kernel thread, not this one.
        let on = OWN_RAN_ON.load(Ordering::Relaxed);
        result(13, ok && alive(on) && on != oxidebsd::process::scheduler::current_pid());
    }

    /// Waits for the others (up to 10 s), then gives the verdict.
    fn judge(_: usize) {
        let all = (1 << CHECKS) - 1;
        for _ in 0..1000 {
            pause(1);
            if PASSED.load(Ordering::Relaxed) | FAILED.load(Ordering::Relaxed) == all & !(1 << 8) {
                break;
            }
        }
        result(8, !alive(EXITER.load(Ordering::Relaxed)));
        let failed = FAILED.load(Ordering::Relaxed) | (all & !PASSED.load(Ordering::Relaxed));
        VERDICT.store(if failed == 0 { 1 } else { 2 | (failed as u64) << 8 }, Ordering::Relaxed);
    }

    pub fn start() {
        let add = |f: fn(usize), name| kthread_add(f, 0, name).unwrap_or_else(|e| panic!("kthread_add {name}: {e}"));
        add(sleeper, "sleeper");
        add(waker, "waker");
        add(timeout, "timeout");
        add(one_sleeper, "one-a");
        add(one_sleeper, "one-b");
        add(one_waker, "one-waker");
        add(yielder, "yielder");
        add(hog, "hog");
        EXITER.store(add(exiter, "exiter"), Ordering::Relaxed);
        SLEEPER.store(add(forever, "forever"), Ordering::Relaxed);
        add(coalescer, "coalescer");
        add(irq_raiser, "irq-raiser");
        add(againer, "againer");
        add(drainer, "drainer");
        add(owner, "owner");
        add(judge, "judge");
    }
}

extern "C" fn test_kthread_handler(what: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    use core::sync::atomic::Ordering;
    match what {
        0 => kthreads::SLEEPER.load(Ordering::Relaxed) as i64,
        1 => kthreads::VERDICT.load(Ordering::Relaxed) as i64,
        2 => oxidebsd::kern::kern_kthread::alive(kthreads::SLEEPER.load(Ordering::Relaxed)) as i64,
        _ => -22,
    }
}

/// Must match `regress/kern-syscall-smoke/src/main.rs`'s own `SYS_TEST_EXIT` constant -- no
/// shared crate across this ABI boundary, same convention every other regress/kernel pair here
/// uses.
const SYS_TEST_EXIT: u64 = 9999;

extern "C" fn test_exit_handler(code: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    serial_println!(
        "kern_syscall_smoke: child reported {}",
        if code == 0 { "PASS" } else { "FAIL" }
    );
    exit_qemu(if code == 0 {
        QemuExitCode::Success
    } else {
        QemuExitCode::Failed
    });
    oxidebsd::hlt_loop();
}

fn main(boot_info: &'static BootInfo) -> ! {
    let (mut mapper, mut frame_allocator) = oxidebsd::init(boot_info);
    let physical_memory_offset = x86_64::VirtAddr::new(boot_info.physical_memory_offset);

    // Populates SYS_EXIT/SYS_READ/SYS_WRITE/SYS_FORK/SYS_WAIT4/SYS_EXECVE/SYS_GETPID/SYS_CLONE/
    // SYS_MMAP/SYS_MUNMAP/SYS_BRK/SYS_MPROTECT/SYS_SET_FS_BASE/SYS_SET_TID_ADDRESS -- must load
    // before kern-syscall-smoke, below, is spawned.
    const NATIVE_ABI_MOD: &[u8] = include_bytes!(env!("NATIVE_ABI_MOD_PATH"));
    const NATIVE_ABI_PANIC_SYMBOL: &str = env!("NATIVE_ABI_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "native_abi",
        NATIVE_ABI_MOD,
        NATIVE_ABI_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the native_abi module: {e:?}"));
    // close, lseek, fstat, ioctl, ftruncate, fsync, fdatasync (VFS.md §6.4).
    const VFS_MOD: &[u8] = include_bytes!(env!("VFS_MOD_PATH"));
    const VFS_PANIC_SYMBOL: &str = env!("VFS_MOD_PANIC_SYMBOL");
    oxidebsd::module::load("vfs", VFS_MOD, VFS_PANIC_SYMBOL, false, &mut mapper, &mut frame_allocator)
        .unwrap_or_else(|e| panic!("failed to load the vfs module: {e:?}"));

    // vfork(2) (COW.md §7), as at boot: BusyBox's spawn() and musl's vfork() call it.
    const VFORK_MOD: &[u8] = include_bytes!(env!("VFORK_MOD_PATH"));
    const VFORK_PANIC_SYMBOL: &str = env!("VFORK_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "vfork",
        VFORK_MOD,
        VFORK_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the vfork module: {e:?}"));

    // Populates SYS_KILL/SYS_SIGACTION/SYS_SIGPROCMASK/SYS_SIGRETURN -- musl's own fork() path
    // blocks and restores signals around the real SYS_FORK.
    const SIGNAL_MOD: &[u8] = include_bytes!(env!("SIGNAL_MOD_PATH"));
    const SIGNAL_PANIC_SYMBOL: &str = env!("SIGNAL_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "signal",
        SIGNAL_MOD,
        SIGNAL_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the signal module: {e:?}"));

    // Populates fcntl/ioctl/dup and friends -- stdio's isatty() probe and the fixture's fds.
    const POSIX_COMPAT_MOD: &[u8] = include_bytes!(env!("POSIX_COMPAT_MOD_PATH"));
    const POSIX_COMPAT_PANIC_SYMBOL: &str = env!("POSIX_COMPAT_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "posix_compat",
        POSIX_COMPAT_MOD,
        POSIX_COMPAT_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the posix_compat module: {e:?}"));

    // Populates SYS_CLOCK_GETTIME -- tmpnam()/tmpfile()'s random names are seeded from it.
    const CLOCK_MOD: &[u8] = include_bytes!(env!("CLOCK_MOD_PATH"));
    const CLOCK_PANIC_SYMBOL: &str = env!("CLOCK_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "clock",
        CLOCK_MOD,
        CLOCK_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the clock module: {e:?}"));

    // The data disk first, as kernel_main does: oxfs mounts the system image on it.
    oxidebsd::drivers::disk::init(&mut frame_allocator, &mut mapper, physical_memory_offset);

    // The file system modules, as at boot: oxfs mounts the system image, then procfs and tmpfs.
    oxidebsd::kernel_main::load_file_systems(&mut mapper, &mut frame_allocator);

    // Local sockets (/dev/log) and poll(2), syslogd's loop.
    const SOCKET_MOD: &[u8] = include_bytes!(env!("SOCKET_MOD_PATH"));
    const SOCKET_PANIC_SYMBOL: &str = env!("SOCKET_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "socket",
        SOCKET_MOD,
        SOCKET_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the socket module: {e:?}"));

    // sysctl(2), which tzsetup's and syslogd's C library may ask for.
    const SYSCTL_MOD: &[u8] = include_bytes!(env!("SYSCTL_MOD_PATH"));
    const SYSCTL_PANIC_SYMBOL: &str = env!("SYSCTL_MOD_PANIC_SYMBOL");
    oxidebsd::module::load(
        "sysctl",
        SYSCTL_MOD,
        SYSCTL_PANIC_SYMBOL,
        false,
        &mut mapper,
        &mut frame_allocator,
    )
    .unwrap_or_else(|e| panic!("failed to load the sysctl module: {e:?}"));

    oxidebsd::memory::install_global_memory_state(frame_allocator, physical_memory_offset);
    oxidebsd::fs::fd::init();

    assert_eq!(
        oxidebsd_register_syscall(SYS_TEST_EXIT, test_exit_handler),
        0,
        "SYS_TEST_EXIT registration failed -- number collided with a real syscall?"
    );

    const KERN_SYSCALL_SMOKE_ELF: &[u8] = include_bytes!(env!("KERN_SYSCALL_SMOKE_ELF_PATH"));
    serial_println!(
        "kern_syscall_smoke: spawning kern-syscall-smoke as pid 1 ({} byte ELF)",
        KERN_SYSCALL_SMOKE_ELF.len()
    );
    let pid1 = oxidebsd::process::spawn(KERN_SYSCALL_SMOKE_ELF, None)
        .unwrap_or_else(|e| panic!("failed to spawn kern-syscall-smoke: {e:?}"));
    // After pid 1, which keeps its number.
    assert_eq!(oxidebsd_register_syscall(SYS_TEST_KTHREAD, test_kthread_handler), 0, "SYS_TEST_KTHREAD registration failed");
    kthreads::start();

    oxidebsd::process::scheduler::start(pid1)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    oxidebsd::test_panic_handler(info)
}
