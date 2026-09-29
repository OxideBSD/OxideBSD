//! ICMP: answers echo requests (`ping`) directed at us, can originate our own echo requests, and
//! -- since a real userspace `ping` needs it -- is the socket layer's raw ICMP protocol
//! (`RAW_ICMP`, `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`). No other ICMP message types are
//! handled.
//!
//! Unlike UDP/TCP, a raw socket isn't port-addressed: real Linux delivers every inbound ICMP
//! packet to every open raw ICMP socket (the app filters by `icmp_id`/type itself -- see
//! `external/mit/musl`'s vendored BusyBox `ping.c`'s own `unpack4`), so `deliver_to_raw_sockets`
//! fans each packet out to all of them rather than routing by a key the way `udp::handle_packet`
//! does. It also needs the *raw IP header* prepended to what a caller reads back (again matching
//! real Linux raw-socket semantics `ping.c` directly relies on: `iphdr->ihl`/`iphdr->ttl` are
//! read straight out of the receive buffer) -- `handle_packet`'s caller,
//! `ipv4::handle_packet`, hands over the whole packet for exactly this reason, not just the ICMP
//! portion the echo-request/reply logic below operates on.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use spin::Mutex;

use super::ipv4::{self, Ipv4Addr};
use crate::fs::Readiness;
use crate::kern::uipc_socket::{Protocol, Received, SockAddr};
use crate::syscall::{EAGAIN, EBADF, EINVAL};

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_ECHO_REQUEST: u8 = 8;
const HEADER_LEN: usize = 8;

const EDESTADDRREQ: i64 = 89;
const EHOSTUNREACH: i64 = 113;

/// Bounded for the same reason `udp::MAX_QUEUED_DATAGRAMS` is -- a raw socket nobody's reading
/// from can't grow without limit.
const MAX_QUEUED_PACKETS: usize = 32;

/// The most recent echo reply seen, if any -- set by `handle_packet`, consumed by
/// `take_echo_reply`. Only `tests/icmp_smoke.rs` still uses this (a kernel-internal check that
/// doesn't go through a real socket) -- a real userland `ping` uses `RAW_SOCKETS`/`recvfrom`
/// below instead.
static LAST_ECHO_REPLY: Mutex<Option<(Ipv4Addr, u16, u16)>> = Mutex::new(None);

struct RawSocket {
    /// (source IP, full IP packet incl. header) -- see this module's own doc comment for why the
    /// header has to stay attached here, unlike every other per-protocol receive queue in this
    /// stack.
    recv_queue: VecDeque<(Ipv4Addr, Vec<u8>)>,
}

static RAW_SOCKETS: Mutex<BTreeMap<u64, RawSocket>> = Mutex::new(BTreeMap::new());

/// Takes (clears) the most recently observed echo reply's (source IP, identifier, sequence).
pub fn take_echo_reply() -> Option<(Ipv4Addr, u16, u16)> {
    LAST_ECHO_REPLY.lock().take()
}

/// `ip_packet` is the *whole* IP packet (header included) -- see this module's own doc comment.
pub fn handle_packet(ip_packet: &[u8], src_ip: Ipv4Addr) {
    if ip_packet.len() < ipv4::HEADER_LEN {
        return;
    }
    let payload = &ip_packet[ipv4::HEADER_LEN..];
    if payload.len() >= HEADER_LEN {
        let icmp_type = payload[0];
        let identifier = u16::from_be_bytes([payload[4], payload[5]]);
        let sequence = u16::from_be_bytes([payload[6], payload[7]]);

        match icmp_type {
            TYPE_ECHO_REQUEST => {
                reply_to_echo(src_ip, identifier, sequence, &payload[HEADER_LEN..]);
            }
            TYPE_ECHO_REPLY => {
                *LAST_ECHO_REPLY.lock() = Some((src_ip, identifier, sequence));
            }
            _ => {}
        }
    }

    deliver_to_raw_sockets(src_ip, ip_packet);
}

fn deliver_to_raw_sockets(src_ip: Ipv4Addr, ip_packet: &[u8]) {
    let mut sockets = RAW_SOCKETS.lock();
    for socket in sockets.values_mut() {
        if socket.recv_queue.len() >= MAX_QUEUED_PACKETS {
            socket.recv_queue.pop_front(); // drop oldest -- same backpressure udp.rs uses
        }
        socket.recv_queue.push_back((src_ip, ip_packet.to_vec()));
    }
}

/// The socket layer's raw ICMP protocol.
pub(crate) struct RawIcmp;
pub(crate) static RAW_ICMP: RawIcmp = RawIcmp;

impl Protocol for RawIcmp {
    fn attach(&self, so: u64) -> Result<(), i64> {
        RAW_SOCKETS.lock().insert(so, RawSocket { recv_queue: VecDeque::new() });
        Ok(())
    }

    fn detach(&self, so: u64) {
        RAW_SOCKETS.lock().remove(&so);
        super::forget_options(so);
    }

    /// A raw socket has no port: the address is checked and otherwise ignored (real `ping`
    /// binds only with `-I`).
    fn bind(&self, _so: u64, addr: &[u8]) -> Result<(), i64> {
        super::parse_sockaddr_in(addr).map(|_| ()).ok_or(EINVAL as i64)
    }

    /// Sends `data` (a complete ICMP message, header and checksum built by the caller, as
    /// `ping.c` does) in an IPv4 envelope.
    fn send(&self, _so: u64, data: &[u8], to: Option<&[u8]>, _flags: i64) -> Result<usize, i64> {
        let (dest_ip, _) = to.and_then(super::parse_sockaddr_in).ok_or(EDESTADDRREQ)?;
        match ipv4::send_packet(dest_ip, ipv4::PROTO_ICMP, data) {
            Some(()) => Ok(data.len()),
            None => Err(EHOSTUNREACH),
        }
    }

    /// The oldest queued packet, IP header included (see this module's doc comment); `EAGAIN`
    /// with none.
    fn recv(&self, so: u64, buf: &mut [u8], peek: bool) -> Result<Received, i64> {
        crate::net::poll();
        let mut sockets = RAW_SOCKETS.lock();
        let socket = sockets.get_mut(&so).ok_or(EBADF as i64)?;
        let Some((src_ip, data)) = socket.recv_queue.front() else {
            return Err(EAGAIN as i64);
        };
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        // ICMP has no port.
        let received =
            Received { n, full: data.len(), from: Some(super::sockaddr_in(*src_ip, 0)), eor: false };
        if !peek {
            socket.recv_queue.pop_front();
        }
        Ok(received)
    }

    fn setopt(&self, so: u64, level: i64, name: i64, val: &[u8]) -> Result<(), i64> {
        super::set_option(so, level, name, val, false)
    }

    fn getopt(&self, so: u64, level: i64, name: i64) -> Result<Vec<u8>, i64> {
        super::get_option(so, level, name, false)
    }

    fn sockname(&self, _so: u64) -> Result<SockAddr, i64> {
        Ok(super::sockaddr_in(ipv4::GUEST_IP, 0))
    }

    fn readiness(&self, so: u64) -> Readiness {
        let readable = RAW_SOCKETS.lock().get(&so).is_some_and(|s| !s.recv_queue.is_empty());
        Readiness { readable, writable: true, ..Default::default() }
    }

    fn pulled(&self) -> bool {
        true
    }
}

fn build_packet(icmp_type: u8, identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER_LEN + data.len());
    packet.push(icmp_type);
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum placeholder
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(data);

    let sum = ipv4::checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    packet
}

fn reply_to_echo(dest_ip: Ipv4Addr, identifier: u16, sequence: u16, data: &[u8]) {
    let packet = build_packet(TYPE_ECHO_REPLY, identifier, sequence, data);
    if ipv4::send_packet(dest_ip, ipv4::PROTO_ICMP, &packet).is_none() {
        crate::serial_println!(
            "[net] icmp: failed to reply to echo request from {:?} (ARP resolution failed?)",
            dest_ip
        );
    }
}

/// Originates an echo request -- what `tests/icmp_smoke.rs` uses to ping the SLIRP gateway.
pub fn send_echo_request(
    dest_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    data: &[u8],
) -> Option<()> {
    let packet = build_packet(TYPE_ECHO_REQUEST, identifier, sequence, data);
    ipv4::send_packet(dest_ip, ipv4::PROTO_ICMP, &packet)
}
