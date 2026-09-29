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

/// `IPPROTO_IP` and `IPPROTO_TCP` option levels, and the options accepted at them.
const IPPROTO_IP: i64 = 0;
pub(crate) const IPPROTO_TCP: i64 = 6;
const IP_TOS: i64 = 1;
const IP_TTL: i64 = 2;
const IP_MULTICAST_IF: i64 = 32;
const IP_MULTICAST_TTL: i64 = 33;
const IP_MULTICAST_LOOP: i64 = 34;
const TCP_NODELAY: i64 = 1;

/// Values set for the IP- and TCP-level options, per socket. They're recorded and reported back
/// but not yet acted on: packets go out with the stack's own TTL and TOS, and TCP sends every
/// segment at once anyway (stop-and-wait), which is what `TCP_NODELAY` asks for.
static OPTIONS: spin::Mutex<alloc::collections::BTreeMap<(u64, i64, i64), alloc::vec::Vec<u8>>> =
    spin::Mutex::new(alloc::collections::BTreeMap::new());

/// Whether `(level, name)` is an option an Internet socket accepts; `tcp` adds `IPPROTO_TCP`'s.
fn known_option(level: i64, name: i64, tcp: bool) -> bool {
    match level {
        IPPROTO_IP => matches!(
            name,
            IP_TOS | IP_TTL | IP_MULTICAST_IF | IP_MULTICAST_TTL | IP_MULTICAST_LOOP
        ),
        IPPROTO_TCP => tcp && name == TCP_NODELAY,
        _ => false,
    }
}

pub(crate) fn set_option(so: u64, level: i64, name: i64, val: &[u8], tcp: bool) -> Result<(), i64> {
    use crate::kern::uipc_socket::ENOPROTOOPT;
    if !known_option(level, name, tcp) {
        return Err(ENOPROTOOPT);
    }
    if val.len() < 4 {
        return Err(crate::syscall::EINVAL as i64);
    }
    OPTIONS.lock().insert((so, level, name), val.to_vec());
    Ok(())
}

pub(crate) fn get_option(so: u64, level: i64, name: i64, tcp: bool) -> Result<alloc::vec::Vec<u8>, i64> {
    use crate::kern::uipc_socket::ENOPROTOOPT;
    if !known_option(level, name, tcp) {
        return Err(ENOPROTOOPT);
    }
    let default = match (level, name) {
        (IPPROTO_IP, IP_TTL) => ipv4::DEFAULT_TTL as i32,
        (IPPROTO_IP, IP_MULTICAST_TTL | IP_MULTICAST_LOOP) => 1,
        (IPPROTO_TCP, TCP_NODELAY) => 1,
        _ => 0,
    };
    Ok(OPTIONS.lock().get(&(so, level, name)).cloned().unwrap_or_else(|| default.to_ne_bytes().to_vec()))
}

/// Drops a closed socket's options.
pub(crate) fn forget_options(so: u64) {
    OPTIONS.lock().retain(|&(s, _, _), _| s != so);
}
