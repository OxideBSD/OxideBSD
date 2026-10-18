//! Network interfaces and the route lookup over them (BSD's `ifnet` and, reduced to what a host
//! with one Ethernet interface needs, its routing table).
//!
//! Two interfaces:
//!
//! - `lo0`, the loopback interface: 127.0.0.1/8, always. Output goes to `if_loop`'s queue and
//!   comes back in through `net::poll`.
//! - `rl0`, the Ethernet interface (`rtl8139`, FreeBSD's `rl`). Its address and the default
//!   gateway are set at run time (`SIOCSIFADDR`/`SIOCSIFNETMASK`, `net.inet.ip.default_gateway`):
//!   by `rc.d/netif` from `ifconfig_rl0`, or by `dhclient(8)`. A real boot starts it with none
//!   (`unconfigure`); a test kernel keeps QEMU user networking's 10.0.2.15/24 via 10.0.2.2.
//!
//! [`route`] decides, for a destination, which interface a packet leaves by, the next hop whose
//! link address it's sent to, and the source address it carries: loopback for 127.0.0.0/8 and for
//! the host's own addresses (as BSD routes a host's own address through `lo0`), the connected
//! subnet directly, the limited broadcast 255.255.255.255 out of `rl0` (from 0.0.0.0 before it has
//! an address: DHCP), anything else by the default gateway.

use crate::netinet::ipv4::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    Loopback,
    Ethernet,
}

/// `lo0`'s address.
pub const LOOPBACK_ADDR: Ipv4Addr = [127, 0, 0, 1];
/// QEMU user networking's guest address, gateway and DNS relay: `rl0`'s setting in a test kernel.
pub const QEMU_ADDR: Ipv4Addr = [10, 0, 2, 15];
pub const QEMU_GATEWAY: Ipv4Addr = [10, 0, 2, 2];
pub const QEMU_DNS: Ipv4Addr = [10, 0, 2, 3];
/// `255.255.255.255`, the limited broadcast.
pub const BROADCAST: Ipv4Addr = [255, 255, 255, 255];

/// `rl0`'s setting: its address and prefix (0.0.0.0/0: none), whether it's up, and the default
/// gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ether {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    pub up: bool,
    pub gateway: Option<Ipv4Addr>,
}

static ETHER: spin::Mutex<Ether> =
    spin::Mutex::new(Ether { addr: QEMU_ADDR, prefix_len: 24, up: true, gateway: Some(QEMU_GATEWAY) });

/// `rl0`'s setting now.
pub fn ether() -> Ether {
    *ETHER.lock()
}

/// Changes `rl0`'s setting (`SIOCS*` ioctls, the gateway sysctl). An address 0.0.0.0 removes it,
/// and with it a gateway it no longer reaches.
pub fn set_ether(f: impl FnOnce(&mut Ether)) {
    let mut e = ETHER.lock();
    f(&mut e);
    if e.addr == ANY {
        e.prefix_len = 0;
    }
    if e.gateway.is_some_and(|g| e.addr == ANY || !in_prefix(g, e.addr, e.prefix_len)) {
        e.gateway = None;
    }
    crate::netinet::arp::forget_all();
}

/// Whether there is an `rl0`: an Ethernet card the kernel drives.
pub fn ether_present() -> bool {
    crate::net::nic::NIC.lock().is_some()
}

/// A real boot: `rl0` has no address until `rc.d/netif` gives it one.
pub fn unconfigure() {
    set_ether(|e| {
        e.addr = ANY;
        e.gateway = None;
    });
}

/// Whether `rl0` has an address.
pub fn ether_configured() -> bool {
    ether().addr != ANY
}

/// `0.0.0.0`, `INADDR_ANY`.
pub const ANY: Ipv4Addr = [0, 0, 0, 0];

pub(crate) fn in_prefix(ip: Ipv4Addr, net: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len as u32) };
    u32::from_be_bytes(ip) & mask == u32::from_be_bytes(net) & mask
}

/// Whether `ip` is in 127.0.0.0/8, loopback's network.
pub fn is_loopback_net(ip: Ipv4Addr) -> bool {
    ip[0] == 127
}

/// Whether `ip` is an address of this host: `rl0`'s, or anywhere in 127.0.0.0/8 (every address
/// there is the host itself).
pub fn is_local(ip: Ipv4Addr) -> bool {
    is_loopback_net(ip) || (ip != ANY && ether().addr == ip)
}

/// Whether `ip` is a broadcast address `rl0` receives: the limited broadcast, or its subnet's.
pub fn is_broadcast(ip: Ipv4Addr) -> bool {
    let e = ether();
    ip == BROADCAST || (e.addr != ANY && e.prefix_len < 31 && ip == subnet_broadcast(e.addr, e.prefix_len))
}

/// The broadcast address of `addr`'s subnet.
pub fn subnet_broadcast(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let host = if prefix_len == 0 { u32::MAX } else { u32::MAX >> prefix_len as u32 };
    (u32::from_be_bytes(addr) | host).to_be_bytes()
}

/// Where a packet to some destination goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub interface: Interface,
    /// The address whose link address the frame is sent to: the destination on the connected
    /// subnet, the gateway otherwise. The destination itself for loopback.
    pub next_hop: Ipv4Addr,
    /// The source address a packet the host originates carries.
    pub src: Ipv4Addr,
}

/// The route to `dst`. `None` for a destination nothing reaches (`0.0.0.0`, anything off-link
/// with no gateway, anything at all while `rl0` is down or has no address but the limited
/// broadcast).
pub fn route(dst: Ipv4Addr) -> Option<Route> {
    if dst == ANY {
        return None;
    }
    if is_loopback_net(dst) {
        return Some(Route { interface: Interface::Loopback, next_hop: dst, src: LOOPBACK_ADDR });
    }
    let e = ether();
    if e.addr != ANY && e.addr == dst {
        // The host's own address: looped back, from that same address.
        return Some(Route { interface: Interface::Loopback, next_hop: dst, src: e.addr });
    }
    if !e.up {
        return None;
    }
    if is_broadcast(dst) {
        return Some(Route { interface: Interface::Ethernet, next_hop: dst, src: e.addr });
    }
    if e.addr == ANY {
        return None;
    }
    let next_hop = if in_prefix(dst, e.addr, e.prefix_len) { dst } else { e.gateway? };
    Some(Route { interface: Interface::Ethernet, next_hop, src: e.addr })
}

/// The source address for a socket bound to `bound` sending to `dst`: the bound address, unless
/// that's `INADDR_ANY` (then the route's).
pub fn source_for(bound: Ipv4Addr, dst: Ipv4Addr) -> Option<Ipv4Addr> {
    if bound != ANY {
        return Some(bound);
    }
    route(dst).map(|r| r.src)
}
