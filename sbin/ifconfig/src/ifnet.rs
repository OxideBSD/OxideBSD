//! The kernel's interface ABI: everything this program knows about how OxideBSD names, reads and
//! changes a network interface is in this module, so it can follow the kernel alone.
//!
//! The requests are ioctls on an `AF_INET` datagram socket with musl's `struct ifreq` (a 16-byte
//! name, then a 24-byte union) and Linux's request numbers, which OxideBSD's musl keeps.
//! Addresses travel as a `struct sockaddr_in` in the union. The flags word is Linux's
//! (`IFF_MULTICAST` is 0x1000); [`bsd_flags`] turns it into the BSD bits ifconfig prints.
//!
//! Assumed of the kernel: setting the address 0.0.0.0 removes it; an interface without an
//! address reads back 0.0.0.0 or fails with `EADDRNOTAVAIL` (both mean "none"); the setting
//! requests need root (`EPERM`); a name that isn't an interface fails with `ENXIO` (or `ENODEV`).

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const SIOCGIFCONF: u64 = 0x8912;
pub const SIOCGIFFLAGS: u64 = 0x8913;
pub const SIOCSIFFLAGS: u64 = 0x8914;
pub const SIOCGIFADDR: u64 = 0x8915;
pub const SIOCSIFADDR: u64 = 0x8916;
pub const SIOCGIFBRDADDR: u64 = 0x8919;
pub const SIOCGIFNETMASK: u64 = 0x891b;
pub const SIOCSIFNETMASK: u64 = 0x891c;
pub const SIOCGIFMTU: u64 = 0x8921;
pub const SIOCGIFHWADDR: u64 = 0x8927;
pub const SIOCGIFINDEX: u64 = 0x8933;

/// The kernel's (Linux-numbered) flags.
pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_POINTOPOINT: u32 = 0x10;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_NOARP: u32 = 0x80;
pub const IFF_PROMISC: u32 = 0x100;
pub const IFF_ALLMULTI: u32 = 0x200;
pub const IFF_MULTICAST: u32 = 0x1000;

/// `ARPHRD_ETHER`: the hardware address family of an Ethernet.
pub const ARPHRD_ETHER: u16 = 1;

pub const IFNAMSIZ: usize = 16;

/// musl's `struct ifreq`: the name, then a union whose largest member (`struct ifmap`) is 24
/// bytes on a 64-bit machine.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IfReq {
    pub name: [u8; IFNAMSIZ],
    pub data: [u8; 24],
}

/// `struct ifconf`: a length and a buffer of `ifreq`s.
#[repr(C)]
struct IfConf {
    len: libc::c_int,
    buf: *mut IfReq,
}

/// The name of each request, for messages (`ioctl (SIOCSIFADDR): ...`, as the BSDs print).
pub fn request_name(req: u64) -> &'static str {
    match req {
        SIOCGIFCONF => "SIOCGIFCONF",
        SIOCGIFFLAGS => "SIOCGIFFLAGS",
        SIOCSIFFLAGS => "SIOCSIFFLAGS",
        SIOCGIFADDR => "SIOCGIFADDR",
        SIOCSIFADDR => "SIOCSIFADDR",
        SIOCGIFBRDADDR => "SIOCGIFBRDADDR",
        SIOCGIFNETMASK => "SIOCGIFNETMASK",
        SIOCSIFNETMASK => "SIOCSIFNETMASK",
        SIOCGIFMTU => "SIOCGIFMTU",
        SIOCGIFHWADDR => "SIOCGIFHWADDR",
        SIOCGIFINDEX => "SIOCGIFINDEX",
        _ => "ioctl",
    }
}

/// A failed request: which one, and why.
#[derive(Debug)]
pub struct Error {
    pub req: u64,
    pub err: io::Error,
}

impl Error {
    /// The interface doesn't exist.
    pub fn no_such_interface(&self) -> bool {
        matches!(self.err.raw_os_error(), Some(libc::ENXIO) | Some(libc::ENODEV))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The socket the requests go through.
pub struct Ifnet {
    fd: OwnedFd,
}

fn sockaddr_in(a: Ipv4Addr) -> [u8; 24] {
    let mut d = [0u8; 24];
    d[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    d[4..8].copy_from_slice(&a.octets());
    d
}

fn in_addr_of(d: &[u8; 24]) -> Ipv4Addr {
    Ipv4Addr::new(d[4], d[5], d[6], d[7])
}

fn name_of(raw: &[u8; IFNAMSIZ]) -> String {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(IFNAMSIZ);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

impl Ifnet {
    pub fn open() -> io::Result<Ifnet> {
        // SAFETY: socket(2) takes no pointers.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor we just opened and own.
        Ok(Ifnet { fd: unsafe { OwnedFd::from_raw_fd(fd) } })
    }

    fn request(name: &str) -> Result<IfReq> {
        let b = name.as_bytes();
        // A name that can't be an interface's is one that doesn't exist.
        if b.is_empty() || b.len() >= IFNAMSIZ || b.contains(&0) {
            return Err(Error { req: SIOCGIFFLAGS, err: io::Error::from_raw_os_error(libc::ENXIO) });
        }
        let mut r = IfReq { name: [0; IFNAMSIZ], data: [0; 24] };
        r.name[..b.len()].copy_from_slice(b);
        Ok(r)
    }

    fn ioctl(&self, req: u64, r: &mut IfReq) -> Result<()> {
        // SAFETY: `r` is a whole `struct ifreq`, which is what every request here reads or fills.
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), req as _, r as *mut IfReq) } < 0 {
            return Err(Error { req, err: io::Error::last_os_error() });
        }
        Ok(())
    }

    fn get(&self, name: &str, req: u64) -> Result<IfReq> {
        let mut r = Self::request(name)?;
        self.ioctl(req, &mut r)?;
        Ok(r)
    }

    /// The interfaces' names, in the kernel's order.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut cap = 16usize;
        loop {
            let mut reqs = vec![IfReq { name: [0; IFNAMSIZ], data: [0; 24] }; cap];
            let mut conf = IfConf { len: (cap * size_of::<IfReq>()) as libc::c_int, buf: reqs.as_mut_ptr() };
            // SAFETY: `conf` points at `cap` ifreqs, the length it states.
            if unsafe { libc::ioctl(self.fd.as_raw_fd(), SIOCGIFCONF as _, &mut conf as *mut IfConf) } < 0 {
                return Err(Error { req: SIOCGIFCONF, err: io::Error::last_os_error() });
            }
            let n = (conf.len.max(0) as usize / size_of::<IfReq>()).min(cap);
            // A full buffer may have been cut short: ask again with more room.
            if n == cap && cap < 4096 {
                cap *= 4;
                continue;
            }
            let mut names: Vec<String> = Vec::new();
            for r in &reqs[..n] {
                let s = name_of(&r.name);
                if !s.is_empty() && !names.contains(&s) {
                    names.push(s);
                }
            }
            self.add_unlisted(&mut names);
            names.sort_by_key(|n| self.index(n).unwrap_or(i32::MAX));
            return Ok(names);
        }
    }

    /// Interfaces `SIOCGIFCONF` may leave out because they have no address: on Linux it lists
    /// only addressed ones, so the host's `/proc/net/dev` names the rest; on OxideBSD lo0 and rl0
    /// are probed by name in case the kernel does the same.
    fn add_unlisted(&self, names: &mut Vec<String>) {
        #[cfg(not(target_os = "oxidebsd"))]
        let candidates: Vec<String> = std::fs::read_to_string("/proc/net/dev")
            .unwrap_or_default()
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(|n| n.trim().to_string()))
            .collect();
        #[cfg(target_os = "oxidebsd")]
        let candidates: Vec<String> = vec!["lo0".into(), "rl0".into()];
        for c in candidates {
            if !names.contains(&c) && self.flags(&c).is_ok() {
                names.push(c);
            }
        }
    }

    /// The flags, in the kernel's (Linux) bits.
    pub fn flags(&self, name: &str) -> Result<u32> {
        let r = self.get(name, SIOCGIFFLAGS)?;
        Ok(u16::from_ne_bytes([r.data[0], r.data[1]]) as u32)
    }

    pub fn set_flags(&self, name: &str, flags: u32) -> Result<()> {
        let mut r = Self::request(name)?;
        r.data[..2].copy_from_slice(&(flags as u16).to_ne_bytes());
        self.ioctl(SIOCSIFFLAGS, &mut r)
    }

    /// The address, `None` when it has none.
    pub fn addr(&self, name: &str) -> Result<Option<Ipv4Addr>> {
        match self.get(name, SIOCGIFADDR) {
            Ok(r) => {
                let a = in_addr_of(&r.data);
                Ok(if a.is_unspecified() { None } else { Some(a) })
            }
            Err(e) if e.err.raw_os_error() == Some(libc::EADDRNOTAVAIL) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Sets the address; 0.0.0.0 removes it.
    pub fn set_addr(&self, name: &str, a: Ipv4Addr) -> Result<()> {
        let mut r = Self::request(name)?;
        r.data = sockaddr_in(a);
        self.ioctl(SIOCSIFADDR, &mut r)
    }

    pub fn netmask(&self, name: &str) -> Result<Ipv4Addr> {
        self.get(name, SIOCGIFNETMASK).map(|r| in_addr_of(&r.data))
    }

    pub fn set_netmask(&self, name: &str, m: Ipv4Addr) -> Result<()> {
        let mut r = Self::request(name)?;
        r.data = sockaddr_in(m);
        self.ioctl(SIOCSIFNETMASK, &mut r)
    }

    pub fn broadcast(&self, name: &str) -> Result<Ipv4Addr> {
        self.get(name, SIOCGIFBRDADDR).map(|r| in_addr_of(&r.data))
    }

    pub fn mtu(&self, name: &str) -> Result<u32> {
        let r = self.get(name, SIOCGIFMTU)?;
        Ok(i32::from_ne_bytes(r.data[..4].try_into().unwrap()).max(0) as u32)
    }

    /// The Ethernet address, `None` for an interface that has none (the loopback).
    pub fn ether(&self, name: &str) -> Result<Option<[u8; 6]>> {
        let r = self.get(name, SIOCGIFHWADDR)?;
        let family = u16::from_ne_bytes([r.data[0], r.data[1]]);
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&r.data[2..8]);
        Ok(if family == ARPHRD_ETHER && mac != [0; 6] { Some(mac) } else { None })
    }

    pub fn index(&self, name: &str) -> Result<i32> {
        let r = self.get(name, SIOCGIFINDEX)?;
        Ok(i32::from_ne_bytes(r.data[..4].try_into().unwrap()))
    }
}

/// The BSD flag bits (FreeBSD's `if.h`) for the kernel's: what ifconfig prints. An interface
/// that broadcasts and isn't a loopback is an Ethernet, which can't hear itself (`SIMPLEX`).
pub fn bsd_flags(k: u32) -> u32 {
    const MAP: &[(u32, u32)] = &[
        (IFF_UP, 0x1),
        (IFF_BROADCAST, 0x2),
        (IFF_LOOPBACK, 0x8),
        (IFF_POINTOPOINT, 0x10),
        (IFF_RUNNING, 0x40),
        (IFF_NOARP, 0x80),
        (IFF_PROMISC, 0x100),
        (IFF_ALLMULTI, 0x200),
        (IFF_MULTICAST, 0x8000),
    ];
    let mut f = MAP.iter().filter(|(k_bit, _)| k & k_bit != 0).fold(0, |f, (_, b)| f | b);
    if k & IFF_BROADCAST != 0 && k & IFF_LOOPBACK == 0 {
        f |= 0x800;
    }
    f
}

/// The names of BSD flag bits, in bit order.
pub const BSD_FLAG_NAMES: &[(u32, &str)] = &[
    (0x1, "UP"),
    (0x2, "BROADCAST"),
    (0x8, "LOOPBACK"),
    (0x10, "POINTOPOINT"),
    (0x40, "RUNNING"),
    (0x80, "NOARP"),
    (0x100, "PROMISC"),
    (0x200, "ALLMULTI"),
    (0x800, "SIMPLEX"),
    (0x8000, "MULTICAST"),
];
