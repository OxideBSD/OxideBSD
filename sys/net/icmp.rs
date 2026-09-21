//! ICMP: answers echo requests (`ping`) directed at us, can originate our own echo requests, and
//! -- since a real userspace `ping` needs it -- backs real `socket(AF_INET, SOCK_RAW,
//! IPPROTO_ICMP)` sockets (`oxidebsd_sys_socket`'s `SOCK_RAW` case in `udp.rs`, which owns socket
//! dispatch for every protocol, not just UDP). No other ICMP message types are handled.
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
use crate::syscall::EINVAL;

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_ECHO_REQUEST: u8 = 8;
const HEADER_LEN: usize = 8;

const ENOTSOCK: i64 = 38;
const EDESTADDRREQ: i64 = 39;
const EHOSTUNREACH: i64 = 65;

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

/// `None` if `real_fd` isn't a raw ICMP socket (caller, `net::oxidebsd_sys_poll`, keeps looking in
/// the other protocols' tables).
pub fn has_data_ready(real_fd: u64) -> Option<bool> {
    RAW_SOCKETS
        .lock()
        .get(&real_fd)
        .map(|socket| !socket.recv_queue.is_empty())
}

extern "C" fn raw_read(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    // Same story as udp::udp_read -- real programs read a raw socket via recvfrom (it needs the
    // source address), not plain read().
    -ENOTSOCK
}

extern "C" fn raw_write(_real_fd: u64, _ptr: u64, _len: u64) -> i64 {
    -EDESTADDRREQ
}

extern "C" fn raw_close(real_fd: u64) -> i64 {
    RAW_SOCKETS.lock().remove(&real_fd);
    0
}

/// Called from `udp::oxidebsd_sys_socket`'s `SOCK_RAW`/`IPPROTO_ICMP` case -- socket dispatch for
/// every protocol lives there, not per-module, same as `tcp::create_socket`.
pub fn create_socket() -> u64 {
    let fd = crate::fs::fd::oxidebsd_alloc_fd();
    RAW_SOCKETS.lock().insert(
        fd,
        RawSocket {
            recv_queue: VecDeque::new(),
        },
    );
    crate::fs::fd::oxidebsd_register_fd_ops(fd, raw_read, raw_write, raw_close);
    fd
}

/// `None` if `real_fd` isn't a raw ICMP socket (caller keeps looking in its own table); `Some`
/// otherwise. A raw socket has no port to bind -- accepted and ignored, same as `setsockopt`
/// below (real `ping` never actually calls this outside `-I`, but accepting it costs nothing and
/// matches every other socket type's own not-mine-vs-mine fallback convention).
pub fn bind(real_fd: u64, addr_ptr: u64) -> Option<i64> {
    if !RAW_SOCKETS.lock().contains_key(&real_fd) {
        return None;
    }
    if super::udp::read_sockaddr(addr_ptr).is_none() {
        return Some(-(EINVAL as i64));
    }
    Some(0)
}

/// Same not-mine-vs-mine convention as `bind` above. Ignores `level`/`optname` -- real `ping`
/// sets `SO_BROADCAST`/`SO_RCVBUF`/`IP_TTL`, none of which this stack's single-gateway,
/// no-fragmentation network model needs to actually honor.
pub fn setsockopt(real_fd: u64) -> Option<i64> {
    RAW_SOCKETS.lock().contains_key(&real_fd).then_some(0)
}

/// Sends `buf` (a complete, caller-built ICMP message -- type/code/checksum/id/seq/payload, see
/// `ping.c`'s own `pkt->icmp_cksum = inet_cksum(...)`) as-is, wrapped in an IPv4/ICMP envelope.
/// Unlike `udp::oxidebsd_sys_sendto`, nothing here builds a protocol header -- a raw socket's
/// whole point is that the caller already did.
pub fn sendto(real_fd: u64, buf_ptr: u64, buf_len: u64, dest_ip: Ipv4Addr) -> Option<i64> {
    if !RAW_SOCKETS.lock().contains_key(&real_fd) {
        return None;
    }
    if buf_ptr == 0 && buf_len > 0 {
        return Some(-(EINVAL as i64));
    }
    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, buf_len as usize) };
    Some(match ipv4::send_packet(dest_ip, ipv4::PROTO_ICMP, data) {
        Some(()) => data.len() as i64,
        None => -EHOSTUNREACH,
    })
}

/// Pops the oldest queued packet (full IP header + ICMP), if any -- non-blocking, same convention
/// `udp::oxidebsd_sys_recvfrom` established (its caller already called `net::poll()` before
/// falling back here, so there's no need to do it again).
pub fn recvfrom(real_fd: u64, buf_ptr: u64, buf_len: u64, addr_out_ptr: u64) -> Option<i64> {
    let mut sockets = RAW_SOCKETS.lock();
    let socket = sockets.get_mut(&real_fd)?;
    let Some((src_ip, data)) = socket.recv_queue.pop_front() else {
        return Some(0);
    };
    drop(sockets);

    let n = data.len().min(buf_len as usize);
    if buf_ptr != 0 && n > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr as *mut u8, n);
        }
    }
    // ICMP has no port -- 0 is the only sensible filler for write_sockaddr's port field.
    super::udp::write_sockaddr(addr_out_ptr, src_ip, 0);
    Some(n as i64)
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
