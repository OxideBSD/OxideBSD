//! The kernel's management information base (OxideBSD-doc `SYSCTL.md`): a tree of named, typed
//! variables, read and set through `sysctl(2)` (system call 583, registered by
//! `sys/modules/sysctl`), as in FreeBSD.
//!
//! Every entry is keyed by its numeric name (OID) in one `BTreeMap`, whose order on integer
//! sequences is exactly the depth-first order `{0, 2}` ("next") walks. Top-level nodes and the
//! variables FreeBSD numbers in `<sys/sysctl.h>` keep FreeBSD's numbers; everything else is
//! numbered from 256 up at registration (`OID_AUTO`). A leaf's value is produced by a function
//! each time it's read, so it's always current, and set through another where it's writable.

use crate::memory::usercopy::{UserPtr, copyin, copyin_val, copyout, copyout_val};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use spin::Mutex;

use crate::syscall::{EINVAL, ENOENT, ENOMEM, EPERM};

const EISDIR: i64 = 21;

/// `CTLTYPE_*` (FreeBSD's values).
pub(crate) const CTLTYPE_NODE: u32 = 1;
pub(crate) const CTLTYPE_INT: u32 = 2;
pub(crate) const CTLTYPE_STRING: u32 = 3;
pub(crate) const CTLTYPE_OPAQUE: u32 = 5;
pub(crate) const CTLTYPE_UINT: u32 = 6;
pub(crate) const CTLTYPE_ULONG: u32 = 8;

/// `CTLFLAG_*`: readable, writable, tunable (fixed at boot from the command line).
pub(crate) const CTLFLAG_RD: u32 = 0x8000_0000;
pub(crate) const CTLFLAG_WR: u32 = 0x4000_0000;
pub(crate) const CTLFLAG_RW: u32 = CTLFLAG_RD | CTLFLAG_WR;
pub(crate) const CTLFLAG_TUN: u32 = 0x0008_0000;
pub(crate) const CTLFLAG_RDTUN: u32 = CTLFLAG_RD | CTLFLAG_TUN;
/// Left out of the `{0, 2}` walk, so `sysctl -a` doesn't show it; still read and set by name.
pub(crate) const CTLFLAG_SKIP: u32 = 0x0100_0000;

/// Top-level nodes (`CTL_*`).
const CTL_KERN: i32 = 1;
const CTL_VM: i32 = 2;
const CTL_VFS: i32 = 3;
const CTL_NET: i32 = 4;
const CTL_DEBUG: i32 = 5;
const CTL_HW: i32 = 6;
const CTL_MACHDEP: i32 = 7;
const CTL_USER: i32 = 8;

/// The first automatically assigned number under a node.
const OID_AUTO_START: i32 = 256;
/// `CTL_MAXNAME`: the longest OID `sysctl(2)` takes.
const CTL_MAXNAME: usize = 24;

/// A leaf's value, as the bytes `sysctl(2)` copies out.
pub(crate) type Getter = fn() -> Vec<u8>;
/// Sets a leaf from the bytes `sysctl(2)` was given; a positive errno on failure.
pub(crate) type Setter = fn(&[u8]) -> Result<(), i64>;

struct Oid {
    /// The dotted name, `kern.ostype`.
    name: String,
    kind: u32,
    flags: u32,
    fmt: &'static str,
    descr: &'static str,
    get: Option<Getter>,
    set: Option<Setter>,
}

static TREE: Mutex<BTreeMap<Vec<i32>, Oid>> = Mutex::new(BTreeMap::new());

/// The tree, built on first use.
fn tree() -> spin::MutexGuard<'static, BTreeMap<Vec<i32>, Oid>> {
    let mut t = TREE.lock();
    if t.is_empty() {
        populate(&mut t);
    }
    t
}

/// The number for a new child of `parent`: `number`, or the next free one from 256.
fn child_number(t: &BTreeMap<Vec<i32>, Oid>, parent: &[i32], number: Option<i32>) -> i32 {
    if let Some(n) = number {
        return n;
    }
    let mut next = OID_AUTO_START;
    for oid in t.keys() {
        if oid.len() == parent.len() + 1 && oid.starts_with(parent) && oid[parent.len()] >= next {
            next = oid[parent.len()] + 1;
        }
    }
    next
}

fn full_name(t: &BTreeMap<Vec<i32>, Oid>, parent: &[i32], name: &str) -> String {
    match t.get(parent) {
        Some(p) => alloc::format!("{}.{}", p.name, name),
        None => String::from(name),
    }
}

/// Adds an interior node under `parent` and returns its OID.
fn add_node(
    t: &mut BTreeMap<Vec<i32>, Oid>,
    parent: &[i32],
    number: Option<i32>,
    name: &str,
    descr: &'static str,
) -> Vec<i32> {
    let mut oid = parent.to_vec();
    oid.push(child_number(t, parent, number));
    let name = full_name(t, parent, name);
    t.insert(oid.clone(), Oid { name, kind: CTLTYPE_NODE, flags: CTLFLAG_RD, fmt: "N", descr, get: None, set: None });
    oid
}

/// One variable: where it goes, what it is, and how it's read and set.
pub(crate) struct Leaf {
    pub number: Option<i32>,
    pub name: &'static str,
    pub kind: u32,
    pub fmt: &'static str,
    pub flags: u32,
    pub descr: &'static str,
    pub get: Getter,
    pub set: Option<Setter>,
}

fn add_leaf(t: &mut BTreeMap<Vec<i32>, Oid>, parent: &[i32], leaf: Leaf) {
    let mut oid = parent.to_vec();
    oid.push(child_number(t, parent, leaf.number));
    let name = full_name(t, parent, leaf.name);
    t.insert(
        oid,
        Oid {
            name,
            kind: leaf.kind,
            flags: leaf.flags,
            fmt: leaf.fmt,
            descr: leaf.descr,
            get: Some(leaf.get),
            set: leaf.set,
        },
    );
}

/// The OID of the node named `name` (`kern`, `vm.stats`), if any.
fn oid_of(t: &BTreeMap<Vec<i32>, Oid>, name: &str) -> Option<Vec<i32>> {
    t.iter().find(|(_, o)| o.name == name).map(|(k, _)| k.clone())
}

// ---- Value encoders ----

pub(crate) fn int(v: i32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

/// An `unsigned int` value; page counts are held as `u64` and fit.
pub(crate) fn uint(v: u64) -> Vec<u8> {
    (v as u32).to_ne_bytes().to_vec()
}

pub(crate) fn ulong(v: u64) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

/// A string value: its bytes and a terminating NUL, as the BSDs return it.
pub(crate) fn string(s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    v.push(0);
    v
}

/// A string being set: the bytes up to the first NUL.
pub(crate) fn new_string(new: &[u8]) -> &[u8] {
    let end = new.iter().position(|&b| b == 0).unwrap_or(new.len());
    &new[..end]
}

// ---- The kernel's variables (SYSCTL.md §5) ----

const KERN_OSTYPE: i32 = 1;
const KERN_OSRELEASE: i32 = 2;
const KERN_VERSION: i32 = 4;
const KERN_MAXPROC: i32 = 6;
const KERN_MAXFILES: i32 = 7;
const KERN_ARGMAX: i32 = 8;
const KERN_HOSTNAME: i32 = 10;
const KERN_CLOCKRATE: i32 = 12;
const KERN_NGROUPS: i32 = 18;
const KERN_BOOTTIME: i32 = 21;
const KERN_NISDOMAINNAME: i32 = 22;
const KERN_IOV_MAX: i32 = 35;
const VM_TOTAL: i32 = 1;
const VM_LOADAVG: i32 = 2;
const HW_MACHINE: i32 = 1;
const HW_MODEL: i32 = 2;
const HW_NCPU: i32 = 3;
const HW_BYTEORDER: i32 = 4;
const HW_PHYSMEM: i32 = 5;
const HW_USERMEM: i32 = 6;
const HW_PAGESIZE: i32 = 7;
const HW_MACHINE_ARCH: i32 = 11;

/// `hw.machine` and `uname -m` (`SYSCTL.md` §5.1).
pub(crate) const MACHINE: &str = "amd64";
pub(crate) const MACHINE_ARCH: &str = "amd64";

/// `kern.maxproc` and `kern.maxfiles`: boot tunables (`SYSCTL.md` §6). `fork` refuses past the
/// first (`process::lifecycle::check_maxproc`), creating an open file past the second
/// (`fs::fd::check_room`).
pub(crate) static MAXPROC: Mutex<i32> = Mutex::new(4096);
pub(crate) static MAXFILES: Mutex<i32> = Mutex::new(8192);

/// Sets boot tunable `name` from the kernel command line's `name=value` (`SYSCTL.md` §6): before
/// the heap exists, so no allocation. An unknown name or a value out of range is logged and
/// ignored.
pub(crate) fn set_tunable(name: &str, value: &str) {
    let parsed: Option<u64> = value.parse().ok();
    let ok = match name {
        "kern.msgbufsize" => parsed
            .filter(|v| (4096..=16 * 1024 * 1024).contains(v))
            .map(|v| crate::kern::subr_msgbuf::SIZE.store(v as usize, core::sync::atomic::Ordering::Relaxed)),
        "kern.maxproc" => parsed.filter(|v| (32..=1_000_000).contains(v)).map(|v| *MAXPROC.lock() = v as i32),
        "kern.maxfiles" => parsed.filter(|v| (64..=1_000_000).contains(v)).map(|v| *MAXFILES.lock() = v as i32),
        "kern.tty.pty_max" => parsed
            .filter(|v| (1..=4096).contains(v))
            .map(|v| crate::tty::pty::PTY_MAX.store(v as u32, core::sync::atomic::Ordering::Relaxed)),
        _ => {
            crate::serial_println!("[boot] unknown tunable {}, ignored", name);
            return;
        }
    };
    if ok.is_none() {
        crate::serial_println!("[boot] tunable {}={} out of range, ignored", name, value);
    } else {
        crate::serial_println!("[boot] tunable {}={}", name, value);
    }
}

/// The processor's brand string (`CPUID` leaves `0x8000_0002..=4`).
fn cpu_model() -> Vec<u8> {
    use core::arch::x86_64::__cpuid;
    let max = __cpuid(0x8000_0000).eax;
    if max < 0x8000_0004 {
        return string(b"unknown");
    }
    let mut out = Vec::with_capacity(48);
    for leaf in 0x8000_0002u32..=0x8000_0004 {
        let r = __cpuid(leaf);
        for reg in [r.eax, r.ebx, r.ecx, r.edx] {
            out.extend_from_slice(&reg.to_le_bytes());
        }
    }
    let end = out.iter().position(|&b| b == 0).unwrap_or(out.len());
    let s = core::str::from_utf8(&out[..end]).unwrap_or("unknown").trim();
    string(s.as_bytes())
}

fn populate(t: &mut BTreeMap<Vec<i32>, Oid>) {
    let kern = add_node(t, &[], Some(CTL_KERN), "kern", "High kernel, proc, limits &c");
    let vm = add_node(t, &[], Some(CTL_VM), "vm", "Virtual memory");
    add_node(t, &[], Some(CTL_VFS), "vfs", "File system");
    add_node(t, &[], Some(CTL_NET), "net", "Network, (see socket.h)");
    let debug = add_node(t, &[], Some(CTL_DEBUG), "debug", "Debugging");
    let hw = add_node(t, &[], Some(CTL_HW), "hw", "hardware");
    add_node(t, &[], Some(CTL_MACHDEP), "machdep", "machine dependent");
    add_node(t, &[], Some(CTL_USER), "user", "user-level");

    let leaves = [
        Leaf {
            number: Some(KERN_OSTYPE),
            name: "ostype",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "Operating system type",
            get: || string(b"OxideBSD"),
            set: None,
        },
        Leaf {
            number: Some(KERN_OSRELEASE),
            name: "osrelease",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "Operating system release",
            get: || string(env!("CARGO_PKG_VERSION").as_bytes()),
            set: None,
        },
        Leaf {
            number: Some(KERN_VERSION),
            name: "version",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "Kernel version",
            get: || {
                let mut v = crate::syscall::ffi::UNAME_VERSION.as_bytes().to_vec();
                v.push(b'\n');
                string(&v)
            },
            set: None,
        },
        Leaf {
            number: Some(KERN_MAXPROC),
            name: "maxproc",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RDTUN,
            descr: "Maximum number of processes",
            get: || int(*MAXPROC.lock()),
            set: None,
        },
        Leaf {
            number: Some(KERN_MAXFILES),
            name: "maxfiles",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RDTUN,
            descr: "Maximum number of files",
            get: || int(*MAXFILES.lock()),
            set: None,
        },
        Leaf {
            number: Some(KERN_ARGMAX),
            name: "argmax",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RD,
            descr: "Maximum bytes of argument to execve(2)",
            get: || int(crate::process::MAX_EXEC_ARG_BYTES as i32),
            set: None,
        },
        Leaf {
            number: Some(KERN_HOSTNAME),
            name: "hostname",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RW,
            descr: "Hostname",
            get: || string(&crate::syscall::ffi::hostname()),
            set: Some(|new| crate::syscall::ffi::set_hostname(new_string(new)).map_err(|e| e as i64)),
        },
        Leaf {
            number: Some(KERN_CLOCKRATE),
            name: "clockrate",
            kind: CTLTYPE_OPAQUE,
            fmt: "S,clockinfo",
            flags: CTLFLAG_RD,
            descr: "Rate and period of various kernel clocks",
            get: || {
                // struct clockinfo { int hz, tick, spare, stathz, profhz; }
                let hz = crate::cpu::pit::TIMER_HZ as i32;
                [hz, 1_000_000 / hz, 0, hz, hz].iter().flat_map(|v| v.to_ne_bytes()).collect()
            },
            set: None,
        },
        Leaf {
            number: Some(KERN_NGROUPS),
            name: "ngroups",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RD,
            descr: "Maximum number of supplemental groups a user can belong to",
            // Only a process's own group ID until supplementary groups exist (SUDO.md).
            get: || int(1),
            set: None,
        },
        Leaf {
            number: Some(KERN_BOOTTIME),
            name: "boottime",
            kind: CTLTYPE_OPAQUE,
            fmt: "S,timeval",
            flags: CTLFLAG_RD,
            descr: "Estimated system boottime",
            get: || {
                let (sec, usec) = crate::cpu::rtc::boot_time();
                let mut v = sec.to_ne_bytes().to_vec();
                v.extend_from_slice(&usec.to_ne_bytes());
                v
            },
            set: None,
        },
        Leaf {
            number: Some(KERN_NISDOMAINNAME),
            name: "domainname",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RW,
            descr: "Name of the current YP/NIS domain",
            get: || string(&crate::syscall::ffi::domainname()),
            set: Some(|new| crate::syscall::ffi::set_domainname(new_string(new)).map_err(|e| e as i64)),
        },
        Leaf {
            number: Some(KERN_IOV_MAX),
            name: "iov_max",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RD,
            descr: "Maximum number of elements in an I/O vector; sysconf(_SC_IOV_MAX)",
            get: || int(1024),
            set: None,
        },
        Leaf {
            number: None,
            name: "msgbuf",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD | CTLFLAG_SKIP,
            descr: "Contents of kernel message buffer",
            get: crate::kern::subr_msgbuf::contents,
            set: None,
        },
        Leaf {
            number: None,
            name: "msgbufsize",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RDTUN,
            descr: "Size of the kernel message buffer",
            get: || int(crate::kern::subr_msgbuf::SIZE.load(core::sync::atomic::Ordering::Relaxed) as i32),
            set: None,
        },
        Leaf {
            number: None,
            name: "msgbuf_clear",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RW | CTLFLAG_SKIP,
            descr: "Clear kernel message buffer",
            get: || int(0),
            set: Some(|_| {
                crate::kern::subr_msgbuf::clear();
                Ok(())
            }),
        },
        Leaf {
            number: None,
            name: "hz",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RD,
            descr: "Number of clock ticks per second",
            get: || int(crate::cpu::pit::TIMER_HZ as i32),
            set: None,
        },
    ];
    for leaf in leaves {
        add_leaf(t, &kern, leaf);
    }

    let hw_leaves = [
        Leaf {
            number: Some(HW_MACHINE),
            name: "machine",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "Machine class",
            get: || string(MACHINE.as_bytes()),
            set: None,
        },
        Leaf {
            number: Some(HW_MODEL),
            name: "model",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "Machine model",
            get: cpu_model,
            set: None,
        },
        Leaf {
            number: Some(HW_NCPU),
            name: "ncpu",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RD,
            descr: "Number of active CPUs",
            get: || int(1),
            set: None,
        },
        Leaf {
            number: Some(HW_BYTEORDER),
            name: "byteorder",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RD,
            descr: "System byte order",
            get: || int(1234),
            set: None,
        },
        Leaf {
            number: Some(HW_PHYSMEM),
            name: "physmem",
            kind: CTLTYPE_ULONG,
            fmt: "LU",
            flags: CTLFLAG_RD,
            descr: "Amount of physical memory (in bytes)",
            get: || ulong(crate::memory::usable_ram_bytes()),
            set: None,
        },
        Leaf {
            number: Some(HW_USERMEM),
            name: "usermem",
            kind: CTLTYPE_ULONG,
            fmt: "LU",
            flags: CTLFLAG_RD,
            descr: "Amount of memory (in bytes) which is not wired",
            get: || ulong(crate::memory::usable_ram_bytes() - crate::memory::vm_meter::stats().wired * 4096),
            set: None,
        },
        Leaf {
            number: Some(HW_PAGESIZE),
            name: "pagesize",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RD,
            descr: "System memory page size",
            get: || int(4096),
            set: None,
        },
        Leaf {
            number: Some(HW_MACHINE_ARCH),
            name: "machine_arch",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "System architecture",
            get: || string(MACHINE_ARCH.as_bytes()),
            set: None,
        },
    ];
    for leaf in hw_leaves {
        add_leaf(t, &hw, leaf);
    }

    let vm_leaves = [
        Leaf {
            number: Some(VM_TOTAL),
            name: "vmtotal",
            kind: CTLTYPE_OPAQUE,
            fmt: "S,vmtotal",
            flags: CTLFLAG_RD,
            descr: "System virtual memory statistics",
            get: vmtotal,
            set: None,
        },
        Leaf {
            number: Some(VM_LOADAVG),
            name: "loadavg",
            kind: CTLTYPE_OPAQUE,
            fmt: "S,loadavg",
            flags: CTLFLAG_RD,
            descr: "Machine loadaverage history",
            get: || {
                // struct loadavg { fixpt_t ldavg[3]; long fscale; }
                let mut v: Vec<u8> = crate::kern::kern_synch::averages().iter().flat_map(|a| a.to_ne_bytes()).collect();
                v.extend_from_slice(&[0; 4]); // padding before the long
                v.extend_from_slice(&(crate::kern::kern_synch::FSCALE as i64).to_ne_bytes());
                v
            },
            set: None,
        },
    ];
    for leaf in vm_leaves {
        add_leaf(t, &vm, leaf);
    }
    // System call costs (`syscall::stats`): debug.syscall.stats, zeroed by debug.syscall.reset=1.
    let syscall = add_node(t, &debug, None, "syscall", "System call costs");
    add_leaf(
        t,
        &syscall,
        Leaf {
            number: None,
            name: "stats",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "Calls, wall and CPU time per system call since boot or the last reset",
            get: || string(&crate::syscall::stats::report()),
            set: None,
        },
    );
    add_leaf(
        t,
        &syscall,
        Leaf {
            number: None,
            name: "reset",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RW,
            descr: "Write 1 to zero debug.syscall.stats",
            get: || int(0),
            set: Some(|new| {
                if new.len() >= 4 && i32::from_ne_bytes([new[0], new[1], new[2], new[3]]) != 0 {
                    crate::syscall::stats::reset();
                }
                Ok(())
            }),
        },
    );
    // Pseudo-terminals (PTY.md §2.4).
    let tty = add_node(t, &kern, None, "tty", "Terminals");
    add_leaf(
        t,
        &tty,
        Leaf {
            number: None,
            name: "pty_max",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RW | CTLFLAG_TUN,
            descr: "Maximum number of pseudo-terminals",
            get: || int(crate::tty::pty::PTY_MAX.load(core::sync::atomic::Ordering::Relaxed) as i32),
            set: Some(|new| {
                if new.len() < 4 {
                    return Err(EINVAL as i64);
                }
                let v = i32::from_ne_bytes([new[0], new[1], new[2], new[3]]);
                if !(1..=4096).contains(&v) {
                    return Err(EINVAL as i64);
                }
                crate::tty::pty::PTY_MAX.store(v as u32, core::sync::atomic::Ordering::Relaxed);
                Ok(())
            }),
        },
    );
    // INIT.md §9: kill pid 1 with a signal, to exercise the kernel's restart of init.
    add_leaf(
        t,
        &debug,
        Leaf {
            number: None,
            name: "kill_init",
            kind: CTLTYPE_INT,
            fmt: "I",
            flags: CTLFLAG_RW,
            descr: "Write a signal number to kill init with it; the kernel restarts init",
            get: || int(0),
            set: Some(|new| {
                if new.len() < 4 {
                    return Err(EINVAL as i64);
                }
                crate::process::init::kill_for_debug(i32::from_ne_bytes([new[0], new[1], new[2], new[3]]))
            }),
        },
    );
    // The read-only page cache (`memory::pagecache`, PAGECACHE.md §4).
    let pagecache = add_node(t, &vm, None, "pagecache", "Read-only file page cache");
    // Page counts are `u_int`, like `vm.stats.vm.*`; hits and misses count up forever, `u_long`.
    let counts: [(&'static str, &'static str, Getter, bool); 5] = [
        ("entries", "Files with cached pages", || uint(crate::memory::pagecache::stats().0), false),
        ("pages", "Frames held", || uint(crate::memory::pagecache::stats().1), false),
        ("hits", "Pages mapped that were already cached", || ulong(crate::memory::pagecache::stats().2), true),
        ("misses", "Pages read into the cache", || ulong(crate::memory::pagecache::stats().3), true),
        ("limit", "Frames unused files may hold", || uint(crate::memory::pagecache::stats().4), false),
    ];
    for (name, descr, get, long) in counts {
        let (kind, fmt) = if long { (CTLTYPE_ULONG, "LU") } else { (CTLTYPE_UINT, "IU") };
        add_leaf(
            t,
            &pagecache,
            Leaf { number: None, name, kind, fmt, flags: CTLFLAG_RD, descr, get, set: None },
        );
    }
    add_leaf(
        t,
        &pagecache,
        Leaf {
            number: None,
            name: "list",
            kind: CTLTYPE_STRING,
            fmt: "A",
            flags: CTLFLAG_RD,
            descr: "One line per entry: inode, size, frames held, uses",
            get: || string(&crate::memory::pagecache::describe()),
            set: None,
        },
    );
    let stats = add_node(t, &vm, None, "stats", "VM meter stats");
    let stats_vm = add_node(t, &stats, None, "vm", "VM meter vm stats");
    let counts: [(&'static str, &'static str, Getter); 4] = [
        ("v_page_count", "Page count for system", || uint(crate::memory::vm_meter::stats().page_count)),
        ("v_free_count", "Free pages", || uint(crate::memory::vm_meter::stats().free)),
        ("v_wire_count", "Wired pages", || uint(crate::memory::vm_meter::stats().wired)),
        ("v_user_count", "Pages mapped into processes", || uint(crate::memory::vm_meter::stats().user)),
    ];
    for (name, descr, get) in counts {
        add_leaf(
            t,
            &stats_vm,
            Leaf { number: None, name, kind: CTLTYPE_UINT, fmt: "IU", flags: CTLFLAG_RD, descr, get, set: None },
        );
    }
}

/// FreeBSD's `struct vmtotal`: nine `uint64_t` page counts, then five `int16_t` thread counts and
/// padding (88 bytes). There is no paging, so virtual and real totals are the pages processes have
/// mapped, all of them active.
fn vmtotal() -> Vec<u8> {
    let s = crate::memory::vm_meter::stats();
    let mut v = Vec::with_capacity(88);
    // t_vm, t_avm, t_rm, t_arm, t_vmshr, t_avmshr, t_rmshr, t_armshr, t_free
    for n in [s.user, s.user, s.user, s.user, s.shared, s.shared, s.shared, s.shared, s.free] {
        v.extend_from_slice(&n.to_ne_bytes());
    }
    // t_rq, t_dw, t_pw, t_sl, t_sw, t_pad[3]
    for n in [s.runnable, s.disk_wait, 0, s.sleeping, 0, 0, 0, 0] {
        v.extend_from_slice(&(n.min(i16::MAX as u64) as i16).to_ne_bytes());
    }
    v
}

// ---- sysctl(2) ----

/// The six arguments, as `sysctl(3)` lays them out for the native ABI's one pointer (`SYSCTL.md`
/// §4.1).
struct Args {
    name: u64,
    namelen: u64,
    oldp: u64,
    oldlenp: u64,
    newp: u64,
    newlen: u64,
}

/// The longest new value `sysctl(2)` takes; every node's value is far smaller.
const MAX_NEWLEN: u64 = 4096;

/// A user buffer copied in (`USERMEM.md`); empty for a null pointer or zero length.
fn user_bytes(ptr: u64, len: u64) -> Result<Vec<u8>, i64> {
    if ptr == 0 || len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_NEWLEN {
        return Err(EINVAL as i64);
    }
    let mut v = alloc::vec![0u8; len as usize];
    copyin(UserPtr::new(ptr), &mut v).map_err(|e| e as i64)?;
    Ok(v)
}

/// Hands `value` back as FreeBSD does: its size alone if `oldp` is null, else as much as fits,
/// `ENOMEM` if that wasn't all of it. `*oldlenp` becomes the bytes copied (or the size).
fn copy_out(a: &Args, value: &[u8]) -> Result<(), i64> {
    if a.oldlenp == 0 {
        return Ok(());
    }
    // `oldlenp` is a `size_t *`.
    let lenp = UserPtr::new(a.oldlenp);
    let e = |e: u64| e as i64;
    if a.oldp == 0 {
        return copyout_val(&(value.len() as u64), lenp).map_err(e);
    }
    let room = copyin_val::<u64>(lenp).map_err(e)? as usize;
    let n = room.min(value.len());
    copyout(&value[..n], UserPtr::new(a.oldp)).map_err(e)?;
    copyout_val(&(n as u64), lenp).map_err(e)?;
    if n < value.len() { Err(ENOMEM as i64) } else { Ok(()) }
}

fn oid_bytes(oid: &[i32]) -> Vec<u8> {
    oid.iter().flat_map(|v| v.to_ne_bytes()).collect()
}

/// The `sysctl` node, `{0, ...}` (`SYSCTL.md` §3.5).
fn meta(a: &Args, name: &[i32]) -> Result<(), i64> {
    const NAME: i32 = 1;
    const NEXT: i32 = 2;
    const NAME2OID: i32 = 3;
    const OIDFMT: i32 = 4;
    const OIDDESCR: i32 = 5;
    let t = tree();
    let target = &name[2..];
    match name[1] {
        NAME => {
            let o = t.get(target).ok_or(ENOENT as i64)?;
            let v = string(o.name.as_bytes());
            drop(t);
            copy_out(a, &v)
        }
        NEXT => {
            use core::ops::Bound::{Excluded, Unbounded};
            // The first leaf after `target` in depth-first order (under it, if it's a node), not
            // counting those flagged `CTLFLAG_SKIP`: the whole message buffer isn't `sysctl -a`
            // material.
            let next = t
                .range::<[i32], _>((Excluded(target), Unbounded))
                .find(|(_, o)| o.kind != CTLTYPE_NODE && o.flags & CTLFLAG_SKIP == 0)
                .map(|(k, _)| oid_bytes(k))
                .ok_or(ENOENT as i64)?;
            drop(t);
            copy_out(a, &next)
        }
        NAME2OID => {
            let wanted_buf = user_bytes(a.newp, a.newlen)?;
            let wanted = new_string(&wanted_buf);
            let wanted = core::str::from_utf8(wanted).map_err(|_| ENOENT as i64)?;
            let oid = oid_of(&t, wanted).ok_or(ENOENT as i64)?;
            drop(t);
            copy_out(a, &oid_bytes(&oid))
        }
        OIDFMT => {
            let o = t.get(target).ok_or(ENOENT as i64)?;
            let mut v = (o.kind | o.flags).to_ne_bytes().to_vec();
            v.extend_from_slice(&string(o.fmt.as_bytes()));
            drop(t);
            copy_out(a, &v)
        }
        OIDDESCR => {
            let o = t.get(target).ok_or(ENOENT as i64)?;
            let v = string(o.descr.as_bytes());
            drop(t);
            copy_out(a, &v)
        }
        _ => Err(ENOENT as i64),
    }
}

fn sysctl(a: &Args) -> Result<(), i64> {
    if a.namelen < 2 || a.namelen as usize > CTL_MAXNAME || a.name == 0 {
        return Err(EINVAL as i64);
    }
    let name: Vec<i32> = user_bytes(a.name, a.namelen * 4)?
        .chunks_exact(4)
        .map(|c| i32::from_ne_bytes(c.try_into().unwrap()))
        .collect();
    if name[0] == 0 {
        return meta(a, &name);
    }
    let (get, set, flags) = {
        let t = tree();
        let o = t.get(&name).ok_or(ENOENT as i64)?;
        if o.kind == CTLTYPE_NODE {
            return Err(EISDIR);
        }
        (o.get, o.set, o.flags)
    };
    // The value is produced outside the tree's lock: a getter may take other locks.
    let value = get.map(|g| g()).unwrap_or_default();
    copy_out(a, &value)?;
    if a.newp != 0 {
        if crate::process::identity::oxidebsd_current_uid() != 0 {
            return Err(EPERM as i64);
        }
        let set = set.filter(|_| flags & CTLFLAG_WR != 0).ok_or(EPERM as i64)?;
        set(&user_bytes(a.newp, a.newlen)?)?;
    }
    Ok(())
}

/// `sysctl(2)`, system call 583: `args` points to `{ name, namelen, oldp, oldlenp, newp, newlen }`.
pub extern "C" fn oxidebsd_sys_sysctl(args: u64) -> i64 {
    if args == 0 {
        return -(EINVAL as i64);
    }
    let a = match copyin_val::<[u64; 6]>(UserPtr::new(args)) {
        Ok([name, namelen, oldp, oldlenp, newp, newlen]) => {
            Args { name, namelen, oldp, oldlenp, newp, newlen }
        }
        Err(e) => return -(e as i64),
    };
    match sysctl(&a) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}
