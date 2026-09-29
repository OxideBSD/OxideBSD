//! The Internet protocols: IPv4, ARP, ICMP, UDP and TCP, over the interfaces in `crate::net`.
//! UDP, TCP and raw ICMP sockets are protocols of the socket layer (`crate::kern::uipc_socket`).

pub mod arp;
pub mod icmp;
pub mod ipv4;
pub mod tcp;
pub mod udp;

use crate::kern::uipc_socket::{AF_INET, SockAddr};
use ipv4::Ipv4Addr;

/// `sizeof(struct sockaddr_in)`.
pub(crate) const SOCKADDR_IN_LEN: usize = 16;

/// The address and port of a `struct sockaddr_in` (family, port in network order, address);
/// `None` if it's too short. The family isn't checked: callers never have checked it.
pub(crate) fn parse_sockaddr_in(addr: &[u8]) -> Option<(Ipv4Addr, u16)> {
    if addr.len() < 8 {
        return None;
    }
    let port = u16::from_be_bytes([addr[2], addr[3]]);
    Some((addr[4..8].try_into().unwrap(), port))
}

/// A `struct sockaddr_in`.
pub(crate) fn sockaddr_in(ip: Ipv4Addr, port: u16) -> SockAddr {
    let mut bytes = alloc::vec![0u8; SOCKADDR_IN_LEN];
    bytes[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes()); // sa_family_t is host order
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    bytes[4..8].copy_from_slice(&ip);
    bytes
}
