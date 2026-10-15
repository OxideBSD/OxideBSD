//! The kernel's System V IPC tables (`kern.ipc.msqids`, `kern.ipc.shmsegs`, `kern.ipc.sema`) and
//! what `ipcs(1)` and `ipcrm(1)` print them with. Shared by both (`ipcrm` includes this file).
//!
//! A table is an array of records, one per live object: `{int id; int pad; struct *id_ds}`, the
//! `*id_ds` in musl's x86_64 layout, as `IPC_STAT` fills it. In the table, a mode carries a few
//! state bits above the permissions, as on the BSDs: `SHM_DEST` on a segment marked for removal,
//! `MSG_RWAIT`/`MSG_WAIT` on a queue a receiver or a sender is waiting on. These structs must
//! match the kernel's (`sys/fs/sysv_*.rs`); there's no shared crate across the ABI.

use std::ffi::{CStr, CString};
use std::io;

/// A segment marked for removal, still attached somewhere (Linux's value).
pub const SHM_DEST: u32 = 0o1000;
/// A process waits to receive from the queue.
pub const MSG_RWAIT: u32 = 0o2000;
/// A process waits to send to the queue.
pub const MSG_WAIT: u32 = 0o4000;

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct IpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
    pub seq: i32,
    pad0: u32,
    pad1: i64,
    pad2: i64,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Msq {
    pub perm: IpcPerm,
    pub stime: i64,
    pub rtime: i64,
    pub ctime: i64,
    pub cbytes: u64,
    pub qnum: u64,
    pub qbytes: u64,
    pub lspid: i32,
    pub lrpid: i32,
    unused: [u64; 2],
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Shm {
    pub perm: IpcPerm,
    pub segsz: u64,
    pub atime: i64,
    pub dtime: i64,
    pub ctime: i64,
    pub cpid: i32,
    pub lpid: i32,
    pub nattch: u64,
    pad1: i64,
    pad2: i64,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Sem {
    pub perm: IpcPerm,
    pub otime: i64,
    unused1: i64,
    pub ctime: i64,
    unused2: i64,
    pub nsems: u16,
    pad: [u8; 6],
    unused3: i64,
    unused4: i64,
}

const _: () = assert!(size_of::<IpcPerm>() == 48);
const _: () = assert!(size_of::<Msq>() == 120);
const _: () = assert!(size_of::<Shm>() == 112);
const _: () = assert!(size_of::<Sem>() == 104);

/// A plain-data record, read from the table's bytes.
pub trait Record: Copy + Default {}
impl Record for Msq {}
impl Record for Shm {}
impl Record for Sem {}

#[cfg(target_os = "oxidebsd")]
unsafe extern "C" {
    fn sysctlbyname(
        name: *const libc::c_char,
        oldp: *mut libc::c_void,
        oldlenp: *mut usize,
        newp: *const libc::c_void,
        newlen: usize,
    ) -> libc::c_int;
}

/// The value of sysctl variable `name`.
#[cfg(target_os = "oxidebsd")]
fn sysctl(name: &str) -> io::Result<Vec<u8>> {
    let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // The table may grow between asking its size and reading it: retry with room to spare.
    for _ in 0..8 {
        let mut len = 0usize;
        if unsafe { sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; len + 4096];
        let mut len = buf.len();
        if unsafe { sysctlbyname(cname.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null(), 0) } == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) {
            return Err(err);
        }
    }
    Err(io::Error::from_raw_os_error(libc::ENOMEM))
}

/// There's no `sysctl(2)` on the host; unit tests don't reach this.
#[cfg(not(target_os = "oxidebsd"))]
fn sysctl(_name: &str) -> io::Result<Vec<u8>> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// A table's records: `(id, *id_ds)` pairs.
pub fn read<T: Record>(name: &str) -> io::Result<Vec<(i32, T)>> {
    parse(&sysctl(name)?)
}

fn parse<T: Record>(bytes: &[u8]) -> io::Result<Vec<(i32, T)>> {
    let size = 8 + size_of::<T>();
    if bytes.len() % size != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "table size isn't a whole number of records"));
    }
    Ok(bytes
        .chunks_exact(size)
        .map(|rec| {
            let id = i32::from_ne_bytes(rec[..4].try_into().unwrap());
            let mut ds = T::default();
            // SAFETY: T is a repr(C) struct of integers, any bit pattern valid; the chunk holds
            // exactly size_of::<T>() bytes after the 8-byte header.
            unsafe {
                std::ptr::copy_nonoverlapping(rec[8..].as_ptr(), (&mut ds as *mut T).cast::<u8>(), size_of::<T>())
            };
            (id, ds)
        })
        .collect())
}

/// An unsigned integer variable (`kern.ipc.shmmax`), `int` or `long` sized.
pub fn read_ulong(name: &str) -> io::Result<u64> {
    let v = sysctl(name)?;
    match v.len() {
        4 => Ok(u32::from_ne_bytes(v[..4].try_into().unwrap()) as u64),
        8 => Ok(u64::from_ne_bytes(v[..8].try_into().unwrap())),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "not an integer")),
    }
}

/// The mode column: two state letters, then the permissions as `ls -l` prints them.
pub fn mode_string(perm: &IpcPerm, kind: char) -> String {
    let m = perm.mode;
    let (first, second) = match kind {
        'm' => (if m & SHM_DEST != 0 { 'D' } else { '-' }, '-'),
        'q' => (if m & MSG_RWAIT != 0 { 'R' } else { '-' }, if m & MSG_WAIT != 0 { 'S' } else { '-' }),
        _ => ('-', '-'),
    };
    let mut s = String::with_capacity(11);
    s.push(first);
    s.push(second);
    for (bit, c) in [(0o400, 'r'), (0o200, 'w'), (0o100, 'a'), (0o40, 'r'), (0o20, 'w'), (0o10, 'a'), (0o4, 'r'), (0o2, 'w'), (0o1, 'a')] {
        s.push(if m & bit != 0 { c } else { '-' });
    }
    s
}

pub fn user_name(uid: u32) -> String {
    // SAFETY: getpwuid returns null or a pointer to a static entry, read before the next call.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            uid.to_string()
        } else {
            CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
        }
    }
}

pub fn group_name(gid: u32) -> String {
    // SAFETY: as user_name.
    unsafe {
        let gr = libc::getgrgid(gid);
        if gr.is_null() {
            gid.to_string()
        } else {
            CStr::from_ptr((*gr).gr_name).to_string_lossy().into_owned()
        }
    }
}

/// A user name or number.
pub fn uid_of(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    // SAFETY: as user_name.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if !pw.is_null() {
            return Some((*pw).pw_uid);
        }
    }
    name.parse().ok()
}

/// A time column: the local time of day, or `no-entry` for never.
pub fn time_string(t: i64) -> String {
    if t == 0 {
        return "no-entry".to_string();
    }
    let t = t as libc::time_t;
    // SAFETY: localtime_r fills `tm` from `t`; both live on this stack.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return "no-entry".to_string();
        }
        format!("{:2}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

/// Now, as `ctime(3)` prints it, without its newline.
pub fn now_string() -> String {
    // SAFETY: time with a null pointer only returns; localtime_r fills `tm`; asctime_r writes at
    // most 26 bytes into `buf`.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        let mut buf = [0 as libc::c_char; 32];
        if libc::localtime_r(&now, &mut tm).is_null() || libc::asctime_r(&tm, buf.as_mut_ptr()).is_null() {
            return String::new();
        }
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        let mut p = IpcPerm { mode: 0o640, ..Default::default() };
        assert_eq!(mode_string(&p, 'm'), "--rw-r-----");
        p.mode |= SHM_DEST;
        assert_eq!(mode_string(&p, 'm'), "D-rw-r-----");
        p.mode = 0o600 | MSG_RWAIT | MSG_WAIT;
        assert_eq!(mode_string(&p, 'q'), "RSrw-------");
    }

    #[test]
    fn records() {
        let mut bytes = Vec::new();
        for id in [7i32, 9] {
            bytes.extend_from_slice(&id.to_ne_bytes());
            bytes.extend_from_slice(&[0; 4]);
            let mut ds = [0u8; size_of::<Sem>()];
            ds[48 + 32..48 + 34].copy_from_slice(&(id as u16 * 2).to_ne_bytes());
            bytes.extend_from_slice(&ds);
        }
        let rows: Vec<(i32, Sem)> = parse(&bytes).unwrap();
        assert_eq!(rows.iter().map(|(id, s)| (*id, s.nsems)).collect::<Vec<_>>(), [(7, 14), (9, 18)]);
        assert!(parse::<Sem>(&bytes[1..]).is_err());
    }
}
