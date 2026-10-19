//! procfs (OxideBSD-doc `VFS.md` §8.3): `/proc` as a file system of its own, mounted on `/proc`
//! by the kernel as soon as it's registered. It answers through the VFS, so it obeys `chroot` and
//! every spelling of a path (before the VFS, oxfs matched the literal prefix `/proc`).
//!
//! Every node is synthetic: its file ID says what it is (`kind << 56 | pid << 24 | sub`), and its
//! contents come from the kernel's process accessors, rendered again on every read (FreeBSD's
//! pseudofs does the same), so nothing is kept between calls and nothing is cut short.
//!
//! - `/proc/{meminfo,uptime,stat,modules,mounts,initdeaths}`: the system's.
//! - `/proc/self`: a link to the caller's pid.
//! - `/proc/<pid>/{stat,cmdline,status,oom_adj,map,maps,environ,wchan}`, `/proc/<pid>/fd/<n>` (links to what each fd
//!   names), `/proc/<pid>/task/<pid>/{stat,cmdline,status}` (one task per process).
#![no_std]

extern crate alloc;
use kern_mod as _;

use alloc::vec::Vec;
use core::ptr;

use vfs_if::*;

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    fn oxidebsd_uiomove(kbuf: *mut u8, len: u64, uio: u64) -> i64;
    fn oxidebsd_uio_resid(uio: u64) -> u64;
    fn oxidebsd_uio_offset(uio: u64) -> u64;
    fn oxidebsd_uio_set_offset(uio: u64, offset: u64);
    fn oxidebsd_current_tgid() -> u64;
    fn oxidebsd_proc_exists(pid: u64) -> i32;
    fn oxidebsd_proc_pid_at(index: u64) -> i64;
    fn oxidebsd_fd_at(pid: u64, index: u64) -> i64;
    fn oxidebsd_real_fd_of_pid(pid: u64, fd: u64) -> i64;
    fn oxidebsd_fd_link(pid: u64, fd: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_mounts_render(buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_stat_line(pid: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_map(pid: u64, linux: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_cmdline(pid: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_oom_adj(pid: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_environ(pid: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_wchan(pid: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_status(pid: u64, buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_meminfo(buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_initdeaths(buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_uptime(buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_stat_global(buf: *mut u8, cap: u64) -> i64;
    fn oxidebsd_proc_modules(buf: *mut u8, cap: u64) -> i64;
}

const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EACCES: i32 = 13;
const EFAULT: i32 = 14;
const ENOMEM: i32 = 12;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;

// --- Nodes ------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    Root,
    Sys(SysFile),
    SelfLink,
    PidDir(u32),
    PidFile(u32, Leaf),
    TaskDir(u32),
    TaskPid(u32),
    TaskFile(u32, Leaf),
    FdDir(u32),
    FdLink(u32, u32),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SysFile {
    Meminfo,
    Uptime,
    Stat,
    Modules,
    Mounts,
    InitDeaths,
}

const SYS_FILES: [(SysFile, &[u8]); 6] = [
    (SysFile::Meminfo, b"meminfo"),
    (SysFile::Uptime, b"uptime"),
    (SysFile::Stat, b"stat"),
    (SysFile::Modules, b"modules"),
    (SysFile::Mounts, b"mounts"),
    (SysFile::InitDeaths, b"initdeaths"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Leaf {
    Stat,
    Cmdline,
    Status,
    OomAdj,
    /// The address-space map, FreeBSD's format.
    Map,
    /// The same, Linux's format.
    Maps,
    /// The environment the program started with (its own user and root only).
    Environ,
    /// What it sleeps on.
    Wchan,
}

const PID_LEAVES: [(Leaf, &[u8]); 8] = [
    (Leaf::Stat, b"stat"),
    (Leaf::Cmdline, b"cmdline"),
    (Leaf::Status, b"status"),
    (Leaf::OomAdj, b"oom_adj"),
    (Leaf::Map, b"map"),
    (Leaf::Maps, b"maps"),
    (Leaf::Environ, b"environ"),
    (Leaf::Wchan, b"wchan"),
];

impl Node {
    fn fileid(self) -> u64 {
        let enc = |kind: u64, pid: u32, sub: u64| kind << 56 | (pid as u64) << 24 | sub;
        match self {
            Node::Root => enc(1, 0, 0),
            Node::Sys(f) => enc(2, 0, f as u64),
            Node::SelfLink => enc(3, 0, 0),
            Node::PidDir(p) => enc(4, p, 0),
            Node::PidFile(p, l) => enc(5, p, l as u64),
            Node::TaskDir(p) => enc(6, p, 0),
            Node::TaskPid(p) => enc(7, p, 0),
            Node::TaskFile(p, l) => enc(8, p, l as u64),
            Node::FdDir(p) => enc(9, p, 0),
            Node::FdLink(p, fd) => enc(10, p, fd as u64),
        }
    }

    fn from_fileid(id: u64) -> Option<Node> {
        let (kind, pid, sub) = (id >> 56, (id >> 24) as u32, id & 0xff_ffff);
        let sys = |i: u64| SYS_FILES.get(i as usize).map(|f| f.0);
        let leaf = |i: u64| PID_LEAVES.get(i as usize).map(|l| l.0);
        Some(match kind {
            1 => Node::Root,
            2 => Node::Sys(sys(sub)?),
            3 => Node::SelfLink,
            4 => Node::PidDir(pid),
            5 => Node::PidFile(pid, leaf(sub)?),
            6 => Node::TaskDir(pid),
            7 => Node::TaskPid(pid),
            8 => Node::TaskFile(pid, leaf(sub)?),
            9 => Node::FdDir(pid),
            10 => Node::FdLink(pid, sub as u32),
            _ => return None,
        })
    }

    fn vtype(self) -> VType {
        match self {
            Node::Root | Node::PidDir(_) | Node::TaskDir(_) | Node::TaskPid(_) | Node::FdDir(_) => VDIR,
            Node::SelfLink | Node::FdLink(..) => VLNK,
            _ => VREG,
        }
    }

    /// The process a node is about, if any.
    fn pid(self) -> Option<u32> {
        match self {
            Node::PidDir(p) | Node::PidFile(p, _) | Node::TaskDir(p) | Node::TaskPid(p) | Node::TaskFile(p, _) => Some(p),
            Node::FdDir(p) | Node::FdLink(p, _) => Some(p),
            _ => None,
        }
    }

    /// Whether what the node names still exists (its process, its descriptor).
    fn alive(self) -> bool {
        match self {
            // SAFETY: kernel exports, called as declared.
            Node::FdLink(p, fd) => (unsafe { oxidebsd_real_fd_of_pid(p as u64, fd as u64) }) >= 0,
            n => n.pid().is_none_or(|p| unsafe { oxidebsd_proc_exists(p as u64) } != 0),
        }
    }

    fn parent(self) -> Node {
        match self {
            Node::PidFile(p, _) | Node::TaskDir(p) | Node::FdDir(p) => Node::PidDir(p),
            Node::TaskPid(p) => Node::TaskDir(p),
            Node::TaskFile(p, _) => Node::TaskPid(p),
            Node::FdLink(p, _) => Node::FdDir(p),
            _ => Node::Root,
        }
    }
}

fn parse_number(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 10 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0u32, |v, &b| v.checked_mul(10)?.checked_add((b - b'0') as u32))
}

fn decimal(mut v: u64) -> Vec<u8> {
    let mut digits = Vec::new();
    loop {
        digits.push(b'0' + (v % 10) as u8);
        v /= 10;
        if v == 0 {
            break;
        }
    }
    digits.reverse();
    digits
}

/// `name` in directory `dir`.
fn child(dir: Node, name: &[u8]) -> Option<Node> {
    let child = match dir {
        Node::Root => {
            if let Some(&(f, _)) = SYS_FILES.iter().find(|(_, n)| *n == name) {
                Node::Sys(f)
            } else if name == b"self" {
                Node::SelfLink
            } else {
                Node::PidDir(parse_number(name)?)
            }
        }
        Node::PidDir(p) => match name {
            b"fd" => Node::FdDir(p),
            b"task" => Node::TaskDir(p),
            _ => Node::PidFile(p, PID_LEAVES.iter().find(|(_, n)| *n == name)?.0),
        },
        Node::TaskDir(p) => (parse_number(name)? == p).then_some(Node::TaskPid(p))?,
        Node::TaskPid(p) => {
            let leaf = PID_LEAVES.iter().find(|(_, n)| *n == name)?.0;
            (leaf != Leaf::OomAdj).then_some(Node::TaskFile(p, leaf))?
        }
        Node::FdDir(p) => Node::FdLink(p, parse_number(name)?),
        _ => return None,
    };
    child.alive().then_some(child)
}

/// The `n`th entry of directory `dir`: its name and node.
fn nth_entry(dir: Node, n: usize) -> Option<(Vec<u8>, Node)> {
    match dir {
        Node::Root => {
            if let Some(&(f, name)) = SYS_FILES.get(n) {
                return Some((name.to_vec(), Node::Sys(f)));
            }
            if n == SYS_FILES.len() {
                return Some((b"self".to_vec(), Node::SelfLink));
            }
            // SAFETY: kernel export.
            let pid = unsafe { oxidebsd_proc_pid_at((n - SYS_FILES.len() - 1) as u64) };
            (pid >= 0).then(|| (decimal(pid as u64), Node::PidDir(pid as u32)))
        }
        Node::PidDir(p) => match n {
            0..4 => Some((PID_LEAVES[n].1.to_vec(), Node::PidFile(p, PID_LEAVES[n].0))),
            4 => Some((b"fd".to_vec(), Node::FdDir(p))),
            5 => Some((b"task".to_vec(), Node::TaskDir(p))),
            _ => None,
        },
        Node::TaskDir(p) => (n == 0).then(|| (decimal(p as u64), Node::TaskPid(p))),
        Node::TaskPid(p) => (n < 3).then(|| (PID_LEAVES[n].1.to_vec(), Node::TaskFile(p, PID_LEAVES[n].0))),
        Node::FdDir(p) => {
            // SAFETY: kernel export.
            let fd = unsafe { oxidebsd_fd_at(p as u64, n as u64) };
            (fd >= 0).then(|| (decimal(fd as u64), Node::FdLink(p, fd as u32)))
        }
        _ => None,
    }
}

// --- Contents ---------------------------------------------------------------------------------

/// Renders through `fill` (`(buf, cap) -> length | -errno`), doubling the buffer while it comes
/// back full, up to 1 MiB.
fn render(mut fill: impl FnMut(*mut u8, u64) -> i64) -> Result<Vec<u8>, i32> {
    let mut cap = 1024usize;
    loop {
        let mut buf: Vec<u8> = Vec::new();
        buf.try_reserve_exact(cap).map_err(|_| ENOMEM)?;
        buf.resize(cap, 0);
        let n = fill(buf.as_mut_ptr(), cap as u64);
        if n < 0 {
            return Err((-n) as i32);
        }
        let n = (n as usize).min(cap);
        if n < cap || cap >= 1 << 20 {
            buf.truncate(n);
            return Ok(buf);
        }
        cap *= 2;
    }
}

fn contents(node: Node) -> Result<Vec<u8>, i32> {
    let leaf = |pid: u32, leaf: Leaf| {
        render(|buf, cap| {
            // SAFETY: kernel exports, with this module's buffer.
            let n = unsafe {
                match leaf {
                    Leaf::Stat => oxidebsd_proc_stat_line(pid as u64, buf, cap),
                    Leaf::Cmdline => oxidebsd_proc_cmdline(pid as u64, buf, cap),
                    Leaf::Status => oxidebsd_proc_status(pid as u64, buf, cap),
                    Leaf::OomAdj => oxidebsd_proc_oom_adj(pid as u64, buf, cap),
                    Leaf::Map => oxidebsd_proc_map(pid as u64, 0, buf, cap),
                    Leaf::Maps => oxidebsd_proc_map(pid as u64, 1, buf, cap),
                    Leaf::Environ => oxidebsd_proc_environ(pid as u64, buf, cap),
                    Leaf::Wchan => oxidebsd_proc_wchan(pid as u64, buf, cap),
                }
            };
            match n {
                -2 => -(EACCES as i64),
                _ if n < 0 => -(ESRCH as i64),
                _ => n,
            }
        })
    };
    match node {
        // SAFETY (each arm): kernel exports, with this module's buffer.
        Node::Sys(f) => render(|buf, cap| unsafe {
            match f {
                SysFile::Meminfo => oxidebsd_proc_meminfo(buf, cap),
                SysFile::Uptime => oxidebsd_proc_uptime(buf, cap),
                SysFile::Stat => oxidebsd_proc_stat_global(buf, cap),
                SysFile::Modules => oxidebsd_proc_modules(buf, cap),
                SysFile::Mounts => oxidebsd_mounts_render(buf, cap),
                SysFile::InitDeaths => oxidebsd_proc_initdeaths(buf, cap),
            }
        }),
        Node::PidFile(p, l) | Node::TaskFile(p, l) => leaf(p, l),
        _ => Err(EINVAL),
    }
}

fn link_target(node: Node) -> Result<Vec<u8>, i32> {
    match node {
        // SAFETY: kernel export.
        Node::SelfLink => Ok(decimal(unsafe { oxidebsd_current_tgid() })),
        Node::FdLink(p, fd) => render(|buf, cap| unsafe { oxidebsd_fd_link(p as u64, fd as u64, buf, cap) })
            .map_err(|_| ENOENT),
        _ => Err(EINVAL),
    }
}

// --- The type -----------------------------------------------------------------------------------

static PROCFS_NAME: &[u8] = b"procfs";

static PROCFS_VFSCONF: VfsConf = VfsConf {
    name: PROCFS_NAME.as_ptr(),
    name_len: 6,
    ops: &PROCFS_VFSOPS,
    vops: &PROCFS_VOPS,
    mnt_data_size: 0,
    v_data_size: 0,
    flags: VFCF_SYNTHETIC | VFCF_NOCACHE,
};

static PROCFS_VFSOPS: VfsOps = VfsOps {
    mount: Some(procfs_mount),
    unmount: None,
    root: Some(procfs_root),
    statfs: Some(procfs_statfs),
    sync: None,
    vget: Some(procfs_vget),
};

static PROCFS_VOPS: VopVector = VopVector {
    lookup: Some(procfs_lookup),
    getattr: Some(procfs_getattr),
    read: Some(procfs_read),
    readdir: Some(procfs_readdir),
    readlink: Some(procfs_readlink),
    ..VopVector::DEFAULT
};

extern "C" fn procfs_mount(mp: *mut Mount, _args: *const MountArgs) -> i32 {
    // SAFETY: the kernel's mount.
    if unsafe { (*mp).mnt_flag } & MNT_UPDATE != 0 { EINVAL } else { 0 }
}

extern "C" fn procfs_root(mp: *mut Mount, vpp: *mut *mut Vnode) -> i32 {
    procfs_vget(mp, Node::Root.fileid(), vpp)
}

/// `/proc/<pid>/mounts`'s `statfs`: a "procfs" magic and no space (`df` shows it empty).
extern "C" fn procfs_statfs(_mp: *mut Mount, sbp: *mut Statfs) -> i32 {
    // SAFETY: the kernel's record.
    let sb = unsafe { &mut *sbp };
    sb.f_bsize = 4096;
    sb.f_iosize = 4096;
    sb.f_namemax = 255;
    sb.f_magic = 0x9fa0; // Linux's PROC_SUPER_MAGIC, which programs that check for /proc compare
    0
}

extern "C" fn procfs_vget(mp: *mut Mount, fileid: u64, vpp: *mut *mut Vnode) -> i32 {
    let Some(node) = Node::from_fileid(fileid) else { return ENOENT };
    // SAFETY: kernel exports, called as declared.
    unsafe {
        let vp = oxidebsd_vfs_hash_get(mp, fileid);
        if !vp.is_null() {
            *vpp = vp;
            return 0;
        }
        let mut vp = ptr::null_mut();
        let e = oxidebsd_getnewvnode(mp, node.vtype(), fileid, &mut vp);
        if e != 0 {
            return e;
        }
        if node == Node::Root {
            (*vp).v_flag |= VV_ROOT;
        }
        oxidebsd_vfs_hash_insert(vp);
        *vpp = vp;
    }
    0
}

fn node_of(vp: *mut Vnode) -> Node {
    // SAFETY: the kernel passes a live vnode of ours, whose file ID `procfs_vget` decoded.
    Node::from_fileid(unsafe { (*vp).v_fileid }).unwrap_or(Node::Root)
}

extern "C" fn procfs_lookup(dvp: *mut Vnode, cnp: *const ComponentName, vpp: *mut *mut Vnode) -> i32 {
    let dir = node_of(dvp);
    if dir.vtype() != VDIR {
        return ENOTDIR;
    }
    if !dir.alive() {
        return ENOENT;
    }
    // SAFETY: the kernel's component.
    let (flags, name) = unsafe { ((*cnp).cn_flags, (*cnp).name()) };
    let node = if flags & ISDOTDOT != 0 { Some(dir.parent()) } else { child(dir, name) };
    match node {
        // SAFETY: as above.
        Some(n) => procfs_vget(unsafe { (*dvp).v_mount }, n.fileid(), vpp),
        None => ENOENT,
    }
}

extern "C" fn procfs_getattr(vp: *mut Vnode, vap: *mut Vattr) -> i32 {
    let node = node_of(vp);
    if !node.alive() {
        return ENOENT;
    }
    let vtype = node.vtype();
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: the kernel's record.
    let va = unsafe { &mut *vap };
    *va = Vattr {
        va_type: vtype,
        va_mode: match vtype {
            VDIR => 0o555,
            VLNK => 0o777,
            _ => 0o444,
        },
        va_nlink: if vtype == VDIR { 2 } else { 1 },
        va_uid: 0,
        va_gid: 0,
        va_fsid: 0,
        va_fileid: node.fileid(),
        va_size: 0,
        va_blocksize: 4096,
        va_atime: zero,
        va_mtime: zero,
        va_ctime: zero,
        va_birthtime: zero,
        va_gen: 0,
        va_flags: 0,
        va_rdev: 0,
        va_bytes: 0,
        va_vaflags: 0,
    };
    0
}

/// Moves `data[offset..]` out through `uio`.
fn uio_from(uio: u64, data: &[u8]) -> i64 {
    // SAFETY: kernel exports, with the kernel's uio and this module's buffer.
    unsafe {
        let offset = oxidebsd_uio_offset(uio) as usize;
        if offset >= data.len() {
            return 0;
        }
        let n = (data.len() - offset).min(oxidebsd_uio_resid(uio) as usize);
        oxidebsd_uiomove(data.as_ptr().add(offset) as *mut u8, n as u64, uio)
    }
}

extern "C" fn procfs_read(vp: *mut Vnode, uio: u64, _ioflag: u32, _cred: *const Ucred) -> i64 {
    match contents(node_of(vp)) {
        Ok(data) => uio_from(uio, &data),
        Err(e) => -(e as i64),
    }
}

extern "C" fn procfs_readlink(vp: *mut Vnode, uio: u64, _cred: *const Ucred) -> i64 {
    match link_target(node_of(vp)) {
        // SAFETY: kernel exports.
        Ok(target) => unsafe {
            let n = target.len().min(oxidebsd_uio_resid(uio) as usize);
            oxidebsd_uiomove(target.as_ptr() as *mut u8, n as u64, uio)
        },
        Err(e) => -(e as i64),
    }
}

extern "C" fn procfs_readdir(vp: *mut Vnode, uio: u64, _cred: *const Ucred, eofflag: *mut i32) -> i64 {
    let dir = node_of(vp);
    if !dir.alive() {
        return -(ENOENT as i64);
    }
    // SAFETY: kernel exports.
    let mut cursor = unsafe { oxidebsd_uio_offset(uio) } as usize;
    let mut record = [0u8; dirent_reclen(255)];
    let mut written = 0i64;
    let mut eof = true;
    while let Some((name, node)) = nth_entry(dir, cursor) {
        let reclen = dirent_reclen(name.len());
        // SAFETY: kernel export.
        if (unsafe { oxidebsd_uio_resid(uio) } as usize) < reclen {
            eof = false;
            break;
        }
        dirent_encode(&mut record, node.fileid(), (cursor + 1) as i64, vtype_to_dt(node.vtype()), &name);
        // SAFETY: kernel export, with this module's buffer.
        let moved = unsafe { oxidebsd_uiomove(record.as_mut_ptr(), reclen as u64, uio) };
        if moved < reclen as i64 {
            if written == 0 {
                return -(EFAULT as i64);
            }
            eof = false;
            break;
        }
        written += reclen as i64;
        cursor += 1;
    }
    // SAFETY: as above.
    unsafe {
        oxidebsd_uio_set_offset(uio, cursor as u64);
        *eofflag = eof as i32;
    }
    written
}

#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // SAFETY: a static table.
    let e = unsafe { oxidebsd_vfs_register(&PROCFS_VFSCONF) };
    let message = "[module] procfs: registered (the kernel mounts it on /proc)\n";
    // SAFETY: kernel export.
    unsafe { oxidebsd_log(message.as_ptr(), message.len() as u64) };
    if e != 0 { -1 } else { 0 }
}
