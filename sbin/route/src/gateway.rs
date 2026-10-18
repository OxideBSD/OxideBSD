//! The kernel's default route: the only route OxideBSD can set (a routing table is later work).
//!
//! It is the sysctl `net.inet.ip.default_gateway`, a string `"a.b.c.d"`, or `""` for none,
//! readable by anyone and writable by root, reached the way `sysctl(8)` does: the name turned
//! into a MIB with `sysctlnametomib(3)`, then `sysctl(3)`. A new value is written as its bytes
//! with no terminating NUL; clearing it writes zero bytes (a non-NULL new pointer, length 0).
//! On a system without the variable (any host but OxideBSD) every call fails with
//! [`io::ErrorKind::Unsupported`].

use std::io;
use std::net::Ipv4Addr;

pub const NAME: &str = "net.inet.ip.default_gateway";

#[cfg(target_os = "oxidebsd")]
mod sys {
    use std::io;

    unsafe extern "C" {
        fn sysctl(name: *const i32, namelen: u32, oldp: *mut u8, oldlenp: *mut usize, newp: *const u8, newlen: usize) -> i32;
        fn sysctlnametomib(name: *const libc::c_char, mibp: *mut i32, sizep: *mut usize) -> i32;
    }

    fn mib() -> io::Result<Vec<i32>> {
        let c = std::ffi::CString::new(super::NAME).unwrap();
        let mut mib = [0i32; 24];
        let mut n = mib.len();
        // SAFETY: `mib` has room for `n` entries.
        if unsafe { sysctlnametomib(c.as_ptr(), mib.as_mut_ptr(), &mut n) } < 0 {
            let e = io::Error::last_os_error();
            // No such variable: this kernel has no settable default route.
            if e.raw_os_error() == Some(libc::ENOENT) {
                return Err(io::Error::from(io::ErrorKind::Unsupported));
            }
            return Err(e);
        }
        Ok(mib[..n.min(mib.len())].to_vec())
    }

    pub fn read() -> io::Result<Vec<u8>> {
        let mib = mib()?;
        // A dotted quad and its NUL fit with room to spare; the size is asked first anyway.
        let mut len = 0usize;
        // SAFETY: a size query: no buffers.
        if unsafe { sysctl(mib.as_ptr(), mib.len() as u32, std::ptr::null_mut(), &mut len, std::ptr::null(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; len.clamp(16, 256) + 16];
        let mut len = buf.len();
        // SAFETY: `buf` holds `len` bytes.
        if unsafe { sysctl(mib.as_ptr(), mib.len() as u32, buf.as_mut_ptr(), &mut len, std::ptr::null(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(len);
        Ok(buf)
    }

    pub fn write(value: &[u8]) -> io::Result<()> {
        let mib = mib()?;
        // Never a null new pointer: that would mean "don't write", even for the empty value.
        static EMPTY: [u8; 1] = [0];
        let p = if value.is_empty() { EMPTY.as_ptr() } else { value.as_ptr() };
        // SAFETY: `p` is valid for `value.len()` bytes.
        if unsafe { sysctl(mib.as_ptr(), mib.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), p, value.len()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(target_os = "oxidebsd"))]
mod sys {
    use std::io;

    pub fn read() -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub fn write(_value: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Parses the variable's value: `None` for no default route.
pub fn parse(raw: &[u8]) -> io::Result<Option<Ipv4Addr>> {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    let s = std::str::from_utf8(&raw[..end]).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let a: Ipv4Addr = s.parse().map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(if a.is_unspecified() { None } else { Some(a) })
}

/// The default gateway, if there is one.
pub fn get() -> io::Result<Option<Ipv4Addr>> {
    parse(&sys::read()?)
}

/// Sets the default gateway, or removes it with `None`.
pub fn set(gw: Option<Ipv4Addr>) -> io::Result<()> {
    match gw {
        Some(a) => sys::write(a.to_string().as_bytes()),
        None => sys::write(b""),
    }
}
