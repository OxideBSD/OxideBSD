//! The client's socket and what it does to the system: the kernel side of DHCP.
//!
//! OxideBSD's kernel lets a UDP socket bound to 0.0.0.0:68 with `SO_BROADCAST` send to
//! 255.255.255.255:67 while the interface has no address (from 0.0.0.0, as an Ethernet
//! broadcast), and until it has one delivers UDP for port 68 whatever the destination address,
//! so an OFFER sent to the offered address arrives. Once configured, the usual rules apply: a
//! renewal is unicast to the server from our address. On Linux (host tests only) the socket is
//! also bound to the interface (`SO_BINDTODEVICE`), which Linux needs to send with no address.
//!
//! A lease is applied through [`ifnet`](crate::ifnet) (address, mask, up) and
//! [`gateway`](crate::gateway) (the default route), and its name servers written to
//! `resolv.conf` by [`write_atomic`].

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;

pub struct Socket {
    fd: OwnedFd,
}

fn sockaddr(a: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid.
    let mut s: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    s.sin_family = libc::AF_INET as libc::sa_family_t;
    s.sin_port = port.to_be();
    s.sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.octets()) };
    s
}

fn setopt(fd: RawFd, level: libc::c_int, name: libc::c_int, v: libc::c_int) -> io::Result<()> {
    // SAFETY: `v` is a c_int, the size passed.
    let r = unsafe {
        libc::setsockopt(fd, level, name, (&v as *const libc::c_int).cast(), size_of::<libc::c_int>() as libc::socklen_t)
    };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

impl Socket {
    /// The client socket: 0.0.0.0:68, broadcasting, non-blocking. `Err` names the step.
    pub fn open(ifname: &str) -> Result<Socket, (String, io::Error)> {
        // SAFETY: socket(2) takes no pointers.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return Err(("socket".into(), io::Error::last_os_error()));
        }
        // SAFETY: a descriptor we just opened and own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();
        setopt(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1).map_err(|e| ("SO_REUSEADDR".to_string(), e))?;
        setopt(raw, libc::SOL_SOCKET, libc::SO_BROADCAST, 1).map_err(|e| ("SO_BROADCAST".to_string(), e))?;
        #[cfg(target_os = "linux")]
        {
            let name = ifname.as_bytes();
            // SAFETY: the name and its length.
            let r = unsafe {
                libc::setsockopt(raw, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_ptr().cast(), name.len() as libc::socklen_t)
            };
            if r < 0 {
                return Err(("SO_BINDTODEVICE".into(), io::Error::last_os_error()));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = ifname;
        let sa = sockaddr(Ipv4Addr::UNSPECIFIED, CLIENT_PORT);
        // SAFETY: `sa` is a sockaddr_in of the size passed.
        let r = unsafe { libc::bind(raw, (&sa as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as libc::socklen_t) };
        if r < 0 {
            return Err(("bind 0.0.0.0:68".into(), io::Error::last_os_error()));
        }
        Ok(Socket { fd })
    }

    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn send_to(&self, p: &[u8], to: Ipv4Addr) -> io::Result<()> {
        let sa = sockaddr(to, SERVER_PORT);
        // SAFETY: `p` and `sa` are valid for the lengths passed.
        let r = unsafe {
            libc::sendto(
                self.raw(),
                p.as_ptr().cast(),
                p.len(),
                0,
                (&sa as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// One datagram, and who sent it; `Ok(None)` when there's nothing to read. A datagram that
    /// filled the buffer may have been cut short and is reported as `(0 bytes)`.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<(usize, Ipv4Addr, u16)>> {
        // SAFETY: zeroed sockaddr_in is valid.
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SAFETY: `buf` and `sa` are valid for the lengths passed.
        let n = unsafe {
            libc::recvfrom(self.raw(), buf.as_mut_ptr().cast(), buf.len(), 0, (&mut sa as *mut libc::sockaddr_in).cast(), &mut len)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock => Ok(None),
                io::ErrorKind::Interrupted => Ok(None),
                _ => Err(e),
            };
        }
        let n = n as usize;
        let from = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
        Ok(Some((if n >= buf.len() { 0 } else { n }, from, u16::from_be(sa.sin_port))))
    }
}

/// Writes `path` whole or not at all: a new file beside it, synced, then renamed over it.
pub fn write_atomic(path: &str, contents: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let p = std::path::Path::new(path);
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    let base = p.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let tmp = dir.join(format!(".{}.dhclient.{}", base.to_string_lossy(), std::process::id()));
    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&tmp)
    };
    let mut f = match open() {
        Ok(f) => f,
        // One left by an earlier run with our pid: never followed, just replaced.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&tmp)?;
            open()?
        }
        Err(e) => return Err(e),
    };
    let r = f.write_all(contents).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = r.and_then(|_| std::fs::rename(&tmp, p)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}
