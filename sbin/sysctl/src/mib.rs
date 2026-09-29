//! The kernel's tree through `sysctl(3)`: values, and the `{0, ...}` meta-OIDs that describe it.

use std::io;

/// A numeric name.
pub type Oid = Vec<i32>;

#[cfg(target_os = "oxidebsd")]
unsafe extern "C" {
    fn sysctl(name: *const i32, namelen: u32, oldp: *mut u8, oldlenp: *mut usize, newp: *const u8, newlen: usize) -> i32;
    fn sysctlnametomib(name: *const libc::c_char, mibp: *mut i32, sizep: *mut usize) -> i32;
}

/// `sysctl(3)`: reads into `old` (or just its size with `None`) and writes `new`.
#[cfg(target_os = "oxidebsd")]
fn call(name: &[i32], old: Option<&mut Vec<u8>>, new: Option<&[u8]>) -> io::Result<usize> {
    let (newp, newlen) = new.map_or((std::ptr::null(), 0), |n| (n.as_ptr(), n.len()));
    let mut len = old.as_ref().map_or(0, |o| o.len());
    let oldp = old.map_or(std::ptr::null_mut(), |o| o.as_mut_ptr());
    // SAFETY: every pointer is valid for the length passed with it.
    let r = unsafe { sysctl(name.as_ptr(), name.len() as u32, oldp, &mut len, newp, newlen) };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(len) }
}

/// There's no `sysctl(2)` on the host; unit tests don't reach this.
#[cfg(not(target_os = "oxidebsd"))]
fn call(_name: &[i32], _old: Option<&mut Vec<u8>>, _new: Option<&[u8]>) -> io::Result<usize> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Reads a whole value: asks its size first, then reads with a little room to spare, since a value
/// (the message buffer) may grow in between.
fn read(name: &[i32]) -> io::Result<Vec<u8>> {
    loop {
        let size = call(name, None, None)?;
        let mut buf = vec![0u8; size + 512];
        match call(name, Some(&mut buf), None) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOMEM) => continue,
            Err(e) => return Err(e),
        }
    }
}

fn meta(which: i32, oid: &[i32]) -> io::Result<Vec<u8>> {
    let mut q = vec![0, which];
    q.extend_from_slice(oid);
    read(&q)
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

pub fn get(oid: &[i32]) -> io::Result<Vec<u8>> {
    read(oid)
}

pub fn set(oid: &[i32], value: &[u8]) -> io::Result<()> {
    call(oid, None, Some(value)).map(|_| ())
}

/// `{0, 1}`: the dotted name.
pub fn name(oid: &[i32]) -> io::Result<String> {
    meta(1, oid).map(|b| cstr(&b))
}

/// `{0, 2}`: the next variable after `oid` in depth-first order (the first, for an empty `oid`).
pub fn next(oid: &[i32]) -> io::Result<Oid> {
    meta(2, oid).map(|b| b.chunks_exact(4).map(|c| i32::from_ne_bytes(c.try_into().unwrap())).collect())
}

/// `{0, 4}`: the type and flags, and the format string.
pub fn format(oid: &[i32]) -> io::Result<(u32, String)> {
    let b = meta(4, oid)?;
    if b.len() < 4 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok((u32::from_ne_bytes(b[..4].try_into().unwrap()), cstr(&b[4..])))
}

/// `{0, 5}`: the one-line description.
pub fn description(oid: &[i32]) -> io::Result<String> {
    meta(5, oid).map(|b| cstr(&b))
}

/// `sysctlnametomib(3)`.
#[cfg(target_os = "oxidebsd")]
pub fn name_to_oid(name: &str) -> io::Result<Oid> {
    let c = std::ffi::CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut mib = [0i32; 24];
    let mut n = mib.len();
    // SAFETY: `mib` has room for `n` entries.
    if unsafe { sysctlnametomib(c.as_ptr(), mib.as_mut_ptr(), &mut n) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(mib[..n].to_vec())
}

#[cfg(not(target_os = "oxidebsd"))]
pub fn name_to_oid(_name: &str) -> io::Result<Oid> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
