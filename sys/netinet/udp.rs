//! UDP: header parse/build, a table of bound sockets, and the socket layer's UDP protocol
//! (`UDP`, `crate::kern::uipc_socket`). Inbound datagrams are queued on the socket bound to their
//! destination port by `handle_packet`; `recv` hands them out with their sender's address.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use spin::Mutex;

use super::ipv4::{self, Ipv4Addr};
use crate::fs::Readiness;
use crate::kern::uipc_socket::{ENOTCONN, Protocol, Received, SockAddr, is_unspec};
use crate::syscall::{EAGAIN, EBADF, EINVAL, EMSGSIZE};

pub const PROTO_UDP: u8 = 17;

/// errno values are musl's (`bits/errno.h`): they become userland's `errno` unchanged.
const EDESTADDRREQ: i64 = 89;
const EADDRINUSE: i64 = 98;
const EISCONN: i64 = 106;
const EHOSTUNREACH: i64 = 113;

const HEADER_LEN: usize = 8;
const EPHEMERAL_PORT_START: u16 = 49152;
/// Bounded so a socket nobody's reading from can't grow without limit -- same backpressure
/// reasoning as `src/pipe.rs`'s own bounded buffer, except nothing here blocks an outrunning
/// sender (UDP is unreliable by nature; a full queue just drops the newest datagram instead of
/// backpressuring the network stack itself).
const MAX_QUEUED_DATAGRAMS: usize = 32;

struct UdpSocket {
    local_port: Option<u16>,
    /// The default destination set by `connect(2)`; while set, only its datagrams are received,
    /// as in the BSDs.
    peer: Option<(Ipv4Addr, u16)>,
    recv_queue: VecDeque<(Ipv4Addr, u16, Vec<u8>)>,
}

impl UdpSocket {
    const fn new() -> Self {
        UdpSocket {
            local_port: None,
            peer: None,
            recv_queue: VecDeque::new(),
        }
    }
}

struct UdpState {
    sockets: BTreeMap<u64, UdpSocket>,
    /// local port -> owning socket's `real_fd`, so `handle_packet` can route an inbound datagram
    /// to the right socket's queue.
    ports: BTreeMap<u16, u64>,
    next_ephemeral: u16,
}

impl UdpState {
    const fn new() -> Self {
        UdpState {
            sockets: BTreeMap::new(),
            ports: BTreeMap::new(),
            next_ephemeral: EPHEMERAL_PORT_START,
        }
    }

    fn alloc_ephemeral_port(&mut self) -> Option<u16> {
        let start = self.next_ephemeral;
        loop {
            let port = self.next_ephemeral;
            self.next_ephemeral = if self.next_ephemeral == u16::MAX {
                EPHEMERAL_PORT_START
            } else {
                self.next_ephemeral + 1
            };
            if !self.ports.contains_key(&port) {
                return Some(port);
            }
            if self.next_ephemeral == start {
                return None; // wrapped all the way around -- the ephemeral range is exhausted
            }
        }
    }

    /// Returns the socket's bound local port, auto-assigning an ephemeral one on first use if it
    /// was never explicitly `bind`-ed (standard implicit-bind-on-first-send behavior).
    fn ensure_bound(&mut self, real_fd: u64) -> Option<u16> {
        if let Some(port) = self.sockets.get(&real_fd).and_then(|s| s.local_port) {
            return Some(port);
        }
        let port = self.alloc_ephemeral_port()?;
        self.ports.insert(port, real_fd);
        self.sockets.get_mut(&real_fd).unwrap().local_port = Some(port);
        Some(port)
    }
}

static STATE: Mutex<UdpState> = Mutex::new(UdpState::new());

/// Parses one UDP datagram (already IP-payload-only, see `ipv4::handle_packet`) and, if a socket
/// is bound to its destination port, queues it there. No listener means the datagram is silently
/// dropped -- a real stack would send back an ICMP port-unreachable; not implemented.
pub fn handle_packet(payload: &[u8], src_ip: Ipv4Addr) {
    if payload.len() < HEADER_LEN {
        return;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if length < HEADER_LEN || length > payload.len() {
        return;
    }
    let data = &payload[HEADER_LEN..length];

    let mut state = STATE.lock();
    let Some(&real_fd) = state.ports.get(&dst_port) else {
        return;
    };
    let Some(socket) = state.sockets.get_mut(&real_fd) else {
        return;
    };
    if socket.peer.is_some_and(|peer| peer != (src_ip, src_port)) {
        return;
    }
    if socket.recv_queue.len() >= MAX_QUEUED_DATAGRAMS {
        socket.recv_queue.pop_front(); // drop oldest -- simple backpressure, no flow control
    }
    socket
        .recv_queue
        .push_back((src_ip, src_port, data.to_vec()));
}

/// The socket layer's UDP protocol.
pub(crate) struct Udp;
pub(crate) static UDP: Udp = Udp;

impl Protocol for Udp {
    fn attach(&self, so: u64) -> Result<(), i64> {
        STATE.lock().sockets.insert(so, UdpSocket::new());
        Ok(())
    }

    fn detach(&self, so: u64) {
        let mut state = STATE.lock();
        if let Some(socket) = state.sockets.remove(&so)
            && let Some(port) = socket.local_port
        {
            state.ports.remove(&port);
        }
        super::forget_options(so);
    }

    fn bind(&self, so: u64, addr: &[u8]) -> Result<(), i64> {
        let (_local_addr, port) = super::parse_sockaddr_in(addr).ok_or(EINVAL as i64)?;
        let mut state = STATE.lock();
        if state.sockets.get(&so).ok_or(EBADF as i64)?.local_port.is_some() {
            return Err(EINVAL as i64);
        }
        let port = if port == 0 {
            state.alloc_ephemeral_port().ok_or(EADDRINUSE)?
        } else if state.ports.contains_key(&port) {
            return Err(EADDRINUSE);
        } else {
            port
        };
        state.ports.insert(port, so);
        state.sockets.get_mut(&so).ok_or(EBADF as i64)?.local_port = Some(port);
        Ok(())
    }

    /// Sets (or, with `AF_UNSPEC`, clears) the default destination, binding first if needed.
    fn connect(&self, so: u64, addr: &[u8]) -> Result<(), i64> {
        let mut state = STATE.lock();
        if is_unspec(addr) {
            state.sockets.get_mut(&so).ok_or(EBADF as i64)?.peer = None;
            return Ok(());
        }
        let peer = super::parse_sockaddr_in(addr).ok_or(EINVAL as i64)?;
        state.ensure_bound(so).ok_or(EADDRINUSE)?;
        let socket = state.sockets.get_mut(&so).ok_or(EBADF as i64)?;
        socket.peer = Some(peer);
        // Datagrams already queued from anyone else are no longer this socket's to receive.
        socket.recv_queue.retain(|&(ip, port, _)| (ip, port) == peer);
        Ok(())
    }

    fn send(&self, so: u64, data: &[u8], to: Option<&[u8]>, _flags: i64) -> Result<usize, i64> {
        let peer = STATE.lock().sockets.get(&so).ok_or(EBADF as i64)?.peer;
        let (dest_ip, dest_port) = match to {
            Some(_) if peer.is_some() => return Err(EISCONN),
            Some(to) => super::parse_sockaddr_in(to).ok_or(EINVAL as i64)?,
            None => peer.ok_or(EDESTADDRREQ)?,
        };
        if HEADER_LEN + data.len() > u16::MAX as usize {
            return Err(EMSGSIZE as i64);
        }
        let local_port = STATE.lock().ensure_bound(so).ok_or(EADDRINUSE)?;

        let mut packet = Vec::with_capacity(HEADER_LEN + data.len());
        packet.extend_from_slice(&local_port.to_be_bytes());
        packet.extend_from_slice(&dest_port.to_be_bytes());
        packet.extend_from_slice(&((HEADER_LEN + data.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]); // checksum: 0 is a legal "not computed" value over IPv4
        packet.extend_from_slice(data);

        match ipv4::send_packet(dest_ip, PROTO_UDP, &packet) {
            Some(()) => Ok(data.len()),
            None => Err(EHOSTUNREACH),
        }
    }

    /// `EAGAIN` with nothing queued. Drives the network interface first, since nothing else
    /// will (`crate::net::poll`).
    fn recv(&self, so: u64, buf: &mut [u8], peek: bool) -> Result<Received, i64> {
        crate::net::poll();
        let mut state = STATE.lock();
        let socket = state.sockets.get_mut(&so).ok_or(EBADF as i64)?;
        let Some((src_ip, src_port, data)) = socket.recv_queue.front() else {
            return Err(EAGAIN as i64);
        };
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        let received = Received {
            n,
            full: data.len(),
            from: Some(super::sockaddr_in(*src_ip, *src_port)),
            eor: false,
        };
        if !peek {
            socket.recv_queue.pop_front();
        }
        Ok(received)
    }

    fn sockname(&self, so: u64) -> Result<SockAddr, i64> {
        let port = STATE.lock().sockets.get(&so).ok_or(EBADF as i64)?.local_port;
        Ok(super::sockaddr_in(ipv4::GUEST_IP, port.unwrap_or(0)))
    }

    fn peername(&self, so: u64) -> Result<SockAddr, i64> {
        let peer = STATE.lock().sockets.get(&so).ok_or(EBADF as i64)?.peer;
        peer.map(|(ip, port)| super::sockaddr_in(ip, port)).ok_or(ENOTCONN)
    }

    fn setopt(&self, so: u64, level: i64, name: i64, val: &[u8]) -> Result<(), i64> {
        super::set_option(so, level, name, val, false)
    }

    fn getopt(&self, so: u64, level: i64, name: i64) -> Result<Vec<u8>, i64> {
        super::get_option(so, level, name, false)
    }

    fn readiness(&self, so: u64) -> Readiness {
        let readable = STATE.lock().sockets.get(&so).is_some_and(|s| !s.recv_queue.is_empty());
        Readiness { readable, writable: true, ..Default::default() }
    }

    fn pulled(&self) -> bool {
        true
    }
}
