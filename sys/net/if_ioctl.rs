//! The interface requests a socket takes (FreeBSD's `ifioctl`), in musl's (Linux's) numbering and
//! `struct ifreq`/`struct ifconf` layouts, which `ifconfig(8)`, `route(8)` and `dhclient(8)`
//! use: list the interfaces, read an interface's flags, addresses, MTU, hardware address and
//! index, and (root only) set `rl0`'s address, netmask and `IFF_UP`. Any socket takes them.
//!
//! `lo0` is fixed at 127.0.0.1/8 and always up: setting it to that is all it takes.

use crate::memory::usercopy::{Pod, UserPtr, copyin_val, copyout_val};
use crate::net::ifnet::{self, ANY};
use crate::netinet::ipv4::Ipv4Addr;

const SIOCGIFCONF: u64 = 0x8912;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCGIFADDR: u64 = 0x8915;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCGIFBRDADDR: u64 = 0x8919;
const SIOCGIFNETMASK: u64 = 0x891b;
const SIOCSIFNETMASK: u64 = 0x891c;
const SIOCGIFMTU: u64 = 0x8921;
const SIOCGIFHWADDR: u64 = 0x8927;
const SIOCGIFINDEX: u64 = 0x8933;

pub const IFF_UP: i16 = 0x1;
pub const IFF_BROADCAST: i16 = 0x2;
pub const IFF_LOOPBACK: i16 = 0x8;
pub const IFF_RUNNING: i16 = 0x40;
pub const IFF_MULTICAST: i16 = 0x1000;

const AF_INET: u16 = 2;
const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;

const EPERM: i64 = 1;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ENXIO: i64 = 6;
const EADDRNOTAVAIL: i64 = 99;

const IFNAMSIZ: usize = 16;

/// `struct ifreq`: a name, then a 24-byte union (here a `struct sockaddr` and padding).
#[derive(Clone, Copy)]
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    data: [u8; 24],
}

// SAFETY: bytes only.
unsafe impl Pod for IfReq {}

/// `struct ifconf`: the buffer's length, then its address.
#[derive(Clone, Copy)]
#[repr(C)]
struct IfConf {
    len: i32,
    _pad: i32,
    buf: u64,
}

// SAFETY: integers only; `_pad` makes the padding explicit.
unsafe impl Pod for IfConf {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum If {
    Lo0,
    Rl0,
}

impl If {
    fn name(self) -> &'static [u8] {
        match self {
            If::Lo0 => b"lo0",
            If::Rl0 => b"rl0",
        }
    }

    fn by_name(name: &[u8; IFNAMSIZ]) -> Option<If> {
        let len = name.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
        present().into_iter().flatten().find(|i| i.name() == &name[..len])
    }

    /// Address, prefix length.
    fn inet(self) -> (Ipv4Addr, u8) {
        match self {
            If::Lo0 => (ifnet::LOOPBACK_ADDR, 8),
            If::Rl0 => {
                let e = ifnet::ether();
                (e.addr, e.prefix_len)
            }
        }
    }

    fn flags(self) -> i16 {
        match self {
            If::Lo0 => IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_MULTICAST,
            If::Rl0 => {
                let up = if ifnet::ether().up { IFF_UP | IFF_RUNNING } else { 0 };
                up | IFF_BROADCAST | IFF_MULTICAST
            }
        }
    }
}

/// The interfaces there are: `lo0`, and `rl0` with a card.
fn present() -> [Option<If>; 2] {
    [Some(If::Lo0), ifnet::ether_present().then_some(If::Rl0)]
}

fn mask_of(prefix_len: u8) -> Ipv4Addr {
    (if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len as u32) }).to_be_bytes()
}

/// The prefix length of a netmask, if its ones are contiguous.
fn prefix_of(mask: Ipv4Addr) -> Option<u8> {
    let m = u32::from_be_bytes(mask);
    let len = m.leading_ones();
    (m.checked_shl(len).unwrap_or(0) == 0).then_some(len as u8)
}

/// The network class's mask, as `SIOCSIFADDR` sets it for an interface with none yet.
fn classful_prefix(addr: Ipv4Addr) -> u8 {
    match addr[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}

fn sockaddr_in(addr: Ipv4Addr) -> [u8; 24] {
    let mut d = [0u8; 24];
    d[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
    d[4..8].copy_from_slice(&addr);
    d
}

fn sockaddr_in_of(data: &[u8; 24]) -> Result<Ipv4Addr, i64> {
    let family = u16::from_ne_bytes([data[0], data[1]]);
    // Linux and FreeBSD both take a zero family as AF_INET here.
    if family != AF_INET && family != 0 {
        return Err(EINVAL);
    }
    Ok(data[4..8].try_into().unwrap())
}

fn out<T: Pod>(v: &T, argp: u64) -> Result<i64, i64> {
    copyout_val(v, UserPtr::new(argp)).map(|()| 0).map_err(|_| EFAULT)
}

fn privileged() -> Result<(), i64> {
    if crate::process::identity::current_cred().privileged() { Ok(()) } else { Err(EPERM) }
}

/// `FileOps::ioctl` for a socket's interface requests: `Some(result)` (`-errno` on failure), or
/// `None` for a request that isn't one.
pub fn ifioctl(request: u64, argp: u64) -> Option<i64> {
    let r = match request {
        SIOCGIFCONF => ifconf(argp),
        SIOCGIFFLAGS | SIOCSIFFLAGS | SIOCGIFADDR | SIOCSIFADDR | SIOCGIFBRDADDR | SIOCGIFNETMASK
        | SIOCSIFNETMASK | SIOCGIFMTU | SIOCGIFHWADDR | SIOCGIFINDEX => ifreq(request, argp),
        _ => return None,
    };
    Some(r.unwrap_or_else(|e| -e))
}

/// `SIOCGIFCONF`: an `ifreq` with its address for each interface, as many as fit; a null buffer
/// asks only for the length all of them need.
fn ifconf(argp: u64) -> Result<i64, i64> {
    let mut conf: IfConf = copyin_val(UserPtr::new(argp)).map_err(|_| EFAULT)?;
    let size = core::mem::size_of::<IfReq>();
    let mut n = 0usize;
    for i in present().into_iter().flatten() {
        if conf.buf != 0 {
            if (n + 1) * size > conf.len.max(0) as usize {
                break;
            }
            let mut req = IfReq { name: [0; IFNAMSIZ], data: sockaddr_in(i.inet().0) };
            req.name[..i.name().len()].copy_from_slice(i.name());
            copyout_val(&req, UserPtr::new(conf.buf + (n * size) as u64)).map_err(|_| EFAULT)?;
        }
        n += 1;
    }
    conf.len = (n * size) as i32;
    out(&conf, argp)
}

fn ifreq(request: u64, argp: u64) -> Result<i64, i64> {
    let mut req: IfReq = copyin_val(UserPtr::new(argp)).map_err(|_| EFAULT)?;
    let i = If::by_name(&req.name).ok_or(ENXIO)?;
    let (addr, prefix) = i.inet();
    match request {
        SIOCGIFFLAGS => {
            req.data = [0; 24];
            req.data[0..2].copy_from_slice(&i.flags().to_ne_bytes());
        }
        SIOCGIFADDR | SIOCGIFNETMASK | SIOCGIFBRDADDR => {
            if addr == ANY {
                return Err(EADDRNOTAVAIL);
            }
            req.data = sockaddr_in(match request {
                SIOCGIFADDR => addr,
                SIOCGIFNETMASK => mask_of(prefix),
                _ if i == If::Lo0 => return Err(EINVAL),
                _ => ifnet::subnet_broadcast(addr, prefix),
            });
        }
        SIOCGIFMTU => {
            let mtu: i32 = if i == If::Lo0 { 16384 } else { 1500 };
            req.data = [0; 24];
            req.data[0..4].copy_from_slice(&mtu.to_ne_bytes());
        }
        SIOCGIFINDEX => {
            let index: i32 = if i == If::Lo0 { 1 } else { 2 };
            req.data = [0; 24];
            req.data[0..4].copy_from_slice(&index.to_ne_bytes());
        }
        SIOCGIFHWADDR => {
            req.data = [0; 24];
            let (family, mac) = match i {
                If::Lo0 => (ARPHRD_LOOPBACK, [0; 6]),
                If::Rl0 => (ARPHRD_ETHER, crate::net::ethernet::our_mac().unwrap_or([0; 6])),
            };
            req.data[0..2].copy_from_slice(&family.to_ne_bytes());
            req.data[2..8].copy_from_slice(&mac);
        }
        SIOCSIFFLAGS => {
            privileged()?;
            let flags = i16::from_ne_bytes([req.data[0], req.data[1]]);
            if i == If::Rl0 {
                ifnet::set_ether(|e| e.up = flags & IFF_UP != 0);
            }
            return Ok(0);
        }
        SIOCSIFADDR => {
            privileged()?;
            let new = sockaddr_in_of(&req.data)?;
            if i == If::Lo0 {
                // Its one address may be set again (`ifconfig_lo0` in rc.conf), nothing else.
                return if new == ifnet::LOOPBACK_ADDR { Ok(0) } else { Err(EINVAL) };
            }
            if new != ANY && (new[0] == 127 || new[0] >= 224 || new == ifnet::BROADCAST) {
                return Err(EINVAL);
            }
            ifnet::set_ether(|e| {
                if e.addr == ANY {
                    e.prefix_len = classful_prefix(new);
                }
                e.addr = new;
            });
            return Ok(0);
        }
        SIOCSIFNETMASK => {
            privileged()?;
            let len = prefix_of(sockaddr_in_of(&req.data)?).ok_or(EINVAL)?;
            if i == If::Lo0 {
                return if len == 8 { Ok(0) } else { Err(EINVAL) };
            }
            if addr == ANY {
                return Err(EADDRNOTAVAIL);
            }
            ifnet::set_ether(|e| e.prefix_len = len);
            return Ok(0);
        }
        _ => return Err(ENOTTY),
    }
    out(&req, argp)
}
