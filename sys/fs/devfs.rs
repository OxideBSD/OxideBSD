//! The device registry (OxideBSD-doc `DEVFS.md` §3): every character device, with the name,
//! number, owner, group and mode its `/dev` node gets, and the function that opens it. Drivers in
//! the kernel register here (`make_dev`), modules through `oxidebsd_make_dev`; oxfs builds devfs,
//! the file system on `/dev`, from the table (`oxidebsd_dev_entry`, `oxidebsd_dev_generation`),
//! and opens every device node, in devfs or not, through `oxidebsd_dev_open`. FreeBSD's
//! `make_dev(9)`, much reduced.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Opens device `major:minor` with `open(2)`'s `flags`: a descriptor, or `-errno`.
pub type DevOpen = extern "C" fn(major: u64, minor: u64, flags: u64) -> i64;

/// The longest name (a path under `/dev`).
pub const NAME_MAX: usize = 63;

struct Dev {
    name: String,
    major: u32,
    minor: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    open: DevOpen,
}

static DEVS: Mutex<Vec<Dev>> = Mutex::new(Vec::new());
/// Changes on every registration and removal (§3.3).
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Registers a device. `EEXIST` if its name or number is taken, `EINVAL` for a bad name.
pub fn make_dev(name: &str, major: u32, minor: u32, uid: u32, gid: u32, mode: u16, open: DevOpen) -> Result<(), i64> {
    let bad = name.is_empty()
        || name.len() > NAME_MAX
        || name.starts_with('/')
        || name.split('/').any(|c| c.is_empty() || c == "." || c == "..");
    if bad {
        return Err(crate::syscall::EINVAL as i64);
    }
    let mut devs = DEVS.lock();
    if devs.iter().any(|d| d.name == name || (d.major, d.minor) == (major, minor)) {
        return Err(crate::syscall::EEXIST as i64);
    }
    devs.push(Dev { name: String::from(name), major, minor, uid, gid, mode: mode & 0o7777, open });
    GENERATION.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Removes device `major:minor`; `ENXIO` if there is none. Descriptors already open stay open.
pub fn destroy_dev(major: u32, minor: u32) -> Result<(), i64> {
    let mut devs = DEVS.lock();
    let Some(i) = devs.iter().position(|d| (d.major, d.minor) == (major, minor)) else {
        return Err(crate::syscall::ENXIO as i64);
    };
    devs.remove(i);
    GENERATION.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// `oxidebsd_make_dev(name_ptr, name_len, major, minor, owner, mode, open)`: `owner` is
/// `uid << 32 | gid`. 0 or `-errno`.
pub(crate) extern "C" fn oxidebsd_make_dev(
    name_ptr: u64,
    name_len: u64,
    major: u64,
    minor: u64,
    owner: u64,
    mode: u64,
    open: DevOpen,
) -> i64 {
    if name_len as usize > NAME_MAX {
        return -(crate::syscall::EINVAL as i64);
    }
    // SAFETY: a module's buffer of that length.
    let bytes = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len as usize) };
    let Ok(name) = core::str::from_utf8(bytes) else {
        return -(crate::syscall::EINVAL as i64);
    };
    match make_dev(name, major as u32, minor as u32, (owner >> 32) as u32, owner as u32, mode as u16, open) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

pub(crate) extern "C" fn oxidebsd_destroy_dev(major: u64, minor: u64) -> i64 {
    match destroy_dev(major as u32, minor as u32) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

/// Opens device `major:minor` through its driver (§3.4); `-ENXIO` if none is registered. The
/// table's lock is released before the driver runs, since opening may block (a terminal) or
/// register devices of its own.
pub(crate) extern "C" fn oxidebsd_dev_open(major: u64, minor: u64, flags: u64) -> i64 {
    let open = DEVS
        .lock()
        .iter()
        .find(|d| (d.major as u64, d.minor as u64) == (major, minor))
        .map(|d| d.open);
    match open {
        Some(open) => open(major, minor, flags),
        None => -(crate::syscall::ENXIO as i64),
    }
}

pub(crate) extern "C" fn oxidebsd_dev_generation() -> u64 {
    GENERATION.load(Ordering::Relaxed)
}

/// One registry entry, as `oxidebsd_dev_entry` copies it out. Duplicated in `sys/modules/oxfs`.
#[repr(C)]
pub struct RawDevEntry {
    pub name: [u8; NAME_MAX + 1],
    pub name_len: u32,
    pub major: u32,
    pub minor: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// Copies entry `index` to `out`: 0, or -1 past the last.
pub(crate) extern "C" fn oxidebsd_dev_entry(index: u64, out: *mut RawDevEntry) -> i64 {
    let devs = DEVS.lock();
    let Some(d) = devs.get(index as usize) else {
        return -1;
    };
    let mut name = [0u8; NAME_MAX + 1];
    name[..d.name.len()].copy_from_slice(d.name.as_bytes());
    let entry = RawDevEntry {
        name,
        name_len: d.name.len() as u32,
        major: d.major,
        minor: d.minor,
        uid: d.uid,
        gid: d.gid,
        mode: d.mode as u32,
    };
    // SAFETY: the module's buffer for one entry.
    unsafe { out.write(entry) };
    0
}
