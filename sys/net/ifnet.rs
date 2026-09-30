//! Network interfaces and the route lookup over them (BSD's `ifnet` and, reduced to what a host
//! with one Ethernet interface needs, its routing table).
//!
//! Two interfaces, both configured at boot, as the stack's addressing has always been static (no
//! DHCP client, no `ifconfig` yet):
//!
//! - `lo0`, the loopback interface: 127.0.0.1/8. Output goes to `if_loop`'s queue and comes back
//!   in through `net::poll`.
//! - `rl0`, the Ethernet interface: QEMU user networking's 10.0.2.15/24, gateway 10.0.2.2. Output
//!   goes through the installed NIC driver (`rtl8139`, FreeBSD's `rl`); without one it fails.
//!
//! [`route`] decides, for a destination, which interface a packet leaves by, the next hop whose
//! link address it's sent to, and the source address it carries: loopback for 127.0.0.0/8 and for
//! the host's own addresses (as BSD routes a host's own address through `lo0`), the connected
//! subnet directly, anything else by the default gateway.

use crate::netinet::ipv4::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    Loopback,
    Ethernet,
}

pub struct Ifnet {
    pub name: &'static str,
    pub kind: Interface,
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

/// `lo0`'s address.
pub const LOOPBACK_ADDR: Ipv4Addr = [127, 0, 0, 1];
/// `rl0`'s address: QEMU user networking's default guest address.
pub const ETHER_ADDR: Ipv4Addr = [10, 0, 2, 15];
/// The default route's gateway, on `rl0`'s subnet: QEMU user networking's.
pub const DEFAULT_GATEWAY: Ipv4Addr = [10, 0, 2, 2];

/// The interfaces, in the order `ifconfig` would list them.
pub static INTERFACES: [Ifnet; 2] = [
    Ifnet { name: "lo0", kind: Interface::Loopback, addr: LOOPBACK_ADDR, prefix_len: 8 },
    Ifnet { name: "rl0", kind: Interface::Ethernet, addr: ETHER_ADDR, prefix_len: 24 },
];

/// `0.0.0.0`, `INADDR_ANY`.
pub const ANY: Ipv4Addr = [0, 0, 0, 0];

fn in_prefix(ip: Ipv4Addr, net: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len as u32) };
    u32::from_be_bytes(ip) & mask == u32::from_be_bytes(net) & mask
}

/// Whether `ip` is in 127.0.0.0/8, loopback's network.
pub fn is_loopback_net(ip: Ipv4Addr) -> bool {
    ip[0] == 127
}

/// Whether `ip` is an address of this host: an interface's address, or anywhere in 127.0.0.0/8
/// (every address there is the host itself).
pub fn is_local(ip: Ipv4Addr) -> bool {
    is_loopback_net(ip) || INTERFACES.iter().any(|i| i.addr == ip)
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

/// The route to `dst`. `None` for a destination nothing reaches (`0.0.0.0`).
pub fn route(dst: Ipv4Addr) -> Option<Route> {
    if dst == ANY {
        return None;
    }
    if is_loopback_net(dst) {
        return Some(Route { interface: Interface::Loopback, next_hop: dst, src: LOOPBACK_ADDR });
    }
    if let Some(i) = INTERFACES.iter().find(|i| i.addr == dst) {
        // The host's own address: looped back, from that same address.
        return Some(Route { interface: Interface::Loopback, next_hop: dst, src: i.addr });
    }
    let ether = INTERFACES.iter().find(|i| i.kind == Interface::Ethernet)?;
    let next_hop = if in_prefix(dst, ether.addr, ether.prefix_len) { dst } else { DEFAULT_GATEWAY };
    Some(Route { interface: Interface::Ethernet, next_hop, src: ether.addr })
}

/// The source address for a socket bound to `bound` sending to `dst`: the bound address, unless
/// that's `INADDR_ANY` (then the route's).
pub fn source_for(bound: Ipv4Addr, dst: Ipv4Addr) -> Option<Ipv4Addr> {
    if bound != ANY {
        return Some(bound);
    }
    route(dst).map(|r| r.src)
}
