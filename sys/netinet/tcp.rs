//! Minimal TCP: a real (if simplified) state machine -- one segment in flight at a time
//! (stop-and-wait, no sliding window/congestion control), a fixed 536-byte MSS (RFC 1122's safe
//! default; this kernel does no IP fragmentation, so staying under the guaranteed minimum path
//! MTU avoids ever needing it), a fixed retransmission timeout (no RTT estimation), and no
//! TIME_WAIT/out-of-order reassembly/urgent-pointer/options support beyond correctly skipping
//! past whatever the peer's `data_offset` says (real interoperability doesn't need parsing
//! options we don't use, just not misreading their length as payload). See this repo's
//! networking plan for the full list of what's deferred.
//!
//! It is the socket layer's TCP protocol (`TCP`, `crate::kern::uipc_socket`): `connect` sends a
//! SYN and reports `EINPROGRESS`, `accept`/`recv` report `EAGAIN` when nothing is ready, and the
//! socket layer does the waiting. A connection torn down under its socket (refused, timed out,
//! reset) leaves the reason in `TcpState::errors` for `SO_ERROR` or the next call.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use spin::Mutex;

use super::ipv4::{self, Ipv4Addr};
use crate::net::ifnet;
use crate::kern::uipc_socket::{EINPROGRESS, EOPNOTSUPP, Protocol, Received, SockAddr};
use crate::syscall::{EBADF, EINVAL};

pub const PROTO_TCP: u8 = 6;

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

const HEADER_LEN: usize = 20;
const MSS: usize = 536;
const MAX_RECV_BUF: usize = 65536;
const EPHEMERAL_PORT_START: u16 = 49152;
const RETRANSMIT_TICKS: u64 = 100; // ~1s at 100 Hz
const MAX_RETRANSMITS: u32 = 5;
const ACCEPT_BACKLOG_MIN: usize = 1;
const ACCEPT_BACKLOG_MAX: usize = 128;

/// errno values are musl's (`bits/errno.h`), since they become userland's `errno` unchanged. All
/// but `EAGAIN` used to be FreeBSD's.
const EAGAIN: i64 = 11;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const ECONNREFUSED: i64 = 111;
const ECONNRESET: i64 = 104;
const EPIPE: i64 = 32;
const ETIMEDOUT: i64 = 110;
const EADDRINUSE: i64 = 98;
const EHOSTUNREACH: i64 = 113;
const EADDRNOTAVAIL: i64 = 99;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closed,
}

struct Connection {
    state: ConnState,
    /// The address this end uses: what the peer sent to, or the route's source for a connect.
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    send_next: u32,
    send_unacked: u32,
    recv_next: u32,
    send_buf: VecDeque<u8>,
    recv_buf: VecDeque<u8>,
    /// The raw bytes of the last segment sent that still needs an ACK -- retransmitted verbatim
    /// on timeout (see `check_retransmits`). `None` means nothing is currently in flight.
    unacked_segment: Option<Vec<u8>>,
    retransmit_deadline: Option<u64>,
    retransmit_count: u32,
    /// `shutdown(SHUT_RD)`: receives report end-of-file.
    rd_shut: bool,
    /// A close or `shutdown(SHUT_WR)` asked for a FIN while data was still waiting to go out: the
    /// state to move to once it has, when `try_send` sends the FIN after the last of the data.
    fin_pending: Option<ConnState>,
}

struct Listener {
    /// The bound address: `INADDR_ANY`, or the one address whose SYNs it takes.
    addr: Ipv4Addr,
    backlog: usize,
    /// `real_fd`s of connections that completed their handshake and are waiting for `accept()`
    /// to claim them.
    pending: VecDeque<u64>,
}

enum TcpSocket {
    /// Created by `socket()`, not yet `bind()`/`connect()`/`listen()`-ed.
    Unbound {
        local_port: Option<u16>,
        /// The bound address, `INADDR_ANY` until bound to one.
        local_addr: Ipv4Addr,
    },
    Listener(Listener),
    Connection(Connection),
}

struct TcpState {
    /// Every TCP socket this kernel knows about, keyed by the same `real_fd` identity
    /// `crate::fd` uses -- including connections still mid-handshake, which get an id (via
    /// `oxidebsd_alloc_fd`) the moment a SYN arrives, well before `accept()` ever attaches one to
    /// a calling process's own fd table (real TCP stacks track half-open connections
    /// independently of any fd too; reusing the same id space just avoids a second one).
    sockets: BTreeMap<u64, TcpSocket>,
    /// local port -> the `Listener`'s own `real_fd`, so a fresh inbound SYN can be routed there.
    listeners: BTreeMap<u16, u64>,
    /// (local ip, local port, remote ip, remote port) -> that connection's `real_fd`, for
    /// demuxing every other inbound segment. The local address is part of it: over loopback
    /// both ends of a connection are here.
    connections: BTreeMap<(Ipv4Addr, u16, Ipv4Addr, u16), u64>,
    /// Why a connection was torn down under its socket (a refused or timed-out connect, a reset):
    /// reported once, by `SO_ERROR` or the next call on the socket.
    errors: BTreeMap<u64, i64>,
    next_ephemeral: u16,
}

impl TcpState {
    const fn new() -> Self {
        TcpState {
            sockets: BTreeMap::new(),
            listeners: BTreeMap::new(),
            connections: BTreeMap::new(),
            errors: BTreeMap::new(),
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
            if !self.listeners.contains_key(&port) {
                return Some(port);
            }
            if self.next_ephemeral == start {
                return None; // wrapped all the way around -- exhausted
            }
        }
    }
}

static STATE: Mutex<TcpState> = Mutex::new(TcpState::new());
static ISN_KEY: spin::Once<[u8; 16]> = spin::Once::new();

/// RFC 6528 initial sequence number: `M + F(local, remote, secret)`. `M` is a clock ticking
/// every 4 microseconds (from the TSC, so it advances inside a syscall too); `F` is SHA-256 over
/// the connection 4-tuple and a boot-time random key. The clock keeps a reused 4-tuple's sequence
/// space moving forward past any old duplicate segments; the keyed hash keeps an off-path attacker
/// from predicting it.
fn isn(local_ip: Ipv4Addr, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> u32 {
    use sha2::{Digest, Sha256};
    let key = *ISN_KEY.call_once(|| {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&crate::random::kernel_random_u64().to_le_bytes());
        key[8..].copy_from_slice(&crate::random::kernel_random_u64().to_le_bytes());
        key
    });
    let mut h = Sha256::new();
    h.update(local_ip);
    h.update(local_port.to_be_bytes());
    h.update(remote_ip);
    h.update(remote_port.to_be_bytes());
    h.update(key);
    let f = u32::from_le_bytes(h.finalize()[..4].try_into().unwrap());
    // 250 ticks of M per millisecond.
    let cycles_per_tick = (crate::cpu::tsc::ms_to_cycles(1) / 250).max(1);
    let m = (crate::cpu::tsc::now() / cycles_per_tick) as u32;
    m.wrapping_add(f)
}

fn window_for(recv_buf_len: usize) -> u16 {
    MAX_RECV_BUF
        .saturating_sub(recv_buf_len)
        .min(u16::MAX as usize) as u16
}

/// TCP's checksum covers a 12-byte pseudo-header (src/dst IP, zero, protocol, segment length)
/// prepended to the real segment -- mandatory for TCP, unlike UDP/ICMP over IPv4 where a zero
/// checksum is legal. Built as one temporary buffer and handed to `ipv4::checksum`, which knows
/// nothing about pseudo-headers itself.
fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + segment.len());
    buf.extend_from_slice(&src_ip);
    buf.extend_from_slice(&dst_ip);
    buf.push(0);
    buf.push(PROTO_TCP);
    buf.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(segment);
    ipv4::checksum(&buf)
}

fn build_segment(
    local_port: u16,
    remote_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(HEADER_LEN + data.len());
    seg.extend_from_slice(&local_port.to_be_bytes());
    seg.extend_from_slice(&remote_port.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(5 << 4); // data offset = 5 (20 bytes, no options); reserved bits = 0
    seg.push(flags);
    seg.extend_from_slice(&window.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent pointer, unused
    seg.extend_from_slice(data);
    seg
}

/// Builds, checksums, and transmits one segment. Returns the built segment's own bytes (for
/// retransmission tracking) on success. Nine parameters, the source address and one per real
/// TCP header field this layer actually varies -- grouping them into a params struct wouldn't make a raw
/// header-building function any clearer.
#[allow(clippy::too_many_arguments)]
fn send_segment(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    data: &[u8],
) -> Option<Vec<u8>> {
    let mut seg = build_segment(local_port, remote_port, seq, ack, flags, window, data);
    let cksum = tcp_checksum(local_ip, remote_ip, &seg);
    seg[16..18].copy_from_slice(&cksum.to_be_bytes());
    ipv4::send_packet(local_ip, remote_ip, PROTO_TCP, &seg)?;
    Some(seg)
}

/// Sends a segment for an existing connection and, if it carries a SYN/FIN/data (anything the
/// peer must ACK), tracks it for retransmission. `seq`/`ack`/`flags`/`data` are explicit
/// (rather than always read straight from the connection) since callers building a SYN/FIN use a
/// seq value distinct from `send_next` at the moment they call this.
fn send_and_track(real_fd: u64, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Option<()> {
    let (local_ip, local_port, remote_ip, remote_port, window) = {
        let state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get(&real_fd) else {
            return None;
        };
        (
            conn.local_ip,
            conn.local_port,
            conn.remote_ip,
            conn.remote_port,
            window_for(conn.recv_buf.len()),
        )
    };
    let segment = send_segment(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        seq,
        ack,
        flags,
        window,
        data,
    )?;

    if flags & (FLAG_SYN | FLAG_FIN) != 0 || !data.is_empty() {
        let mut state = STATE.lock();
        if let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) {
            conn.unacked_segment = Some(segment);
            conn.retransmit_deadline = Some(crate::cpu::interrupts::ticks() + RETRANSMIT_TICKS);
        }
    }
    Some(())
}

fn teardown(state: &mut TcpState, real_fd: u64) {
    if let Some(TcpSocket::Connection(conn)) = state.sockets.get(&real_fd) {
        let key = (conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port);
        state.connections.remove(&key);
    }
    state.sockets.remove(&real_fd);
}

/// Sends a buffered chunk (up to `MSS`) if nothing's currently in flight and the connection can
/// still send, or, once the buffer is empty, a FIN a close left pending. Called after `write()`
/// and after any state change that might have freed up the single in-flight slot (an ACK, a fresh
/// accept).
fn try_send(real_fd: u64) {
    let sendable = {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };
        if conn.unacked_segment.is_some()
            || !matches!(conn.state, ConnState::Established | ConnState::CloseWait)
        {
            None
        } else if conn.send_buf.is_empty() {
            if let Some(next) = conn.fin_pending.take() {
                drop(state);
                send_fin_and_transition(real_fd, next);
            }
            return;
        } else {
            let take = conn.send_buf.len().min(MSS);
            let chunk: Vec<u8> = conn.send_buf.drain(..take).collect();
            Some((conn.send_next, conn.recv_next, chunk))
        }
    };
    let Some((seq, ack, chunk)) = sendable else {
        return;
    };

    if send_and_track(real_fd, seq, ack, FLAG_ACK | FLAG_PSH, &chunk).is_some() {
        let mut state = STATE.lock();
        if let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) {
            conn.send_next = seq.wrapping_add(chunk.len() as u32);
        }
    } else {
        // Send failed (e.g. ARP resolution failed) -- put the bytes back so a later attempt can
        // retry, rather than silently losing them.
        let mut state = STATE.lock();
        if let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) {
            for &b in chunk.iter().rev() {
                conn.send_buf.push_front(b);
            }
        }
    }
}

/// Closes the sending side of a connection in `Established`/`CloseWait`, moving it to
/// `next_state`: a FIN now if everything written has been sent and acknowledged, otherwise after
/// the rest of the data (`try_send`). Sending it at once used to drop whatever `write` had
/// buffered: a peer that wrote and closed was cut short.
fn close_sending(real_fd: u64, next_state: ConnState) {
    let idle = {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };
        let idle = conn.send_buf.is_empty() && conn.unacked_segment.is_none();
        if !idle {
            conn.fin_pending = Some(next_state);
        }
        idle
    };
    if idle {
        send_fin_and_transition(real_fd, next_state);
    }
}

/// Sends a FIN for a connection currently in `Established`/`CloseWait` and transitions it to
/// `next_state`.
fn send_fin_and_transition(real_fd: u64, next_state: ConnState) {
    let pair = {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };
        let pair = (conn.send_next, conn.recv_next);
        conn.state = next_state;
        pair
    };
    let (seq, ack) = pair;
    send_and_track(real_fd, seq, ack, FLAG_FIN | FLAG_ACK, &[]);
    let mut state = STATE.lock();
    if let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) {
        conn.send_next = seq.wrapping_add(1);
    }
}

/// Checks every connection's retransmission deadline, resending or giving up as needed. Called
/// from `net::poll()` -- the same self-driving mechanism every socket syscall already funnels
/// through, so this runs whenever anything touches the network, not on a dedicated timer.
pub fn check_retransmits() {
    let now = crate::cpu::interrupts::ticks();
    let due: Vec<u64> = {
        let state = STATE.lock();
        state
            .sockets
            .iter()
            .filter_map(|(&fd, sock)| match sock {
                TcpSocket::Connection(conn)
                    if conn.retransmit_deadline.is_some_and(|d| now >= d) =>
                {
                    Some(fd)
                }
                _ => None,
            })
            .collect()
    };
    for fd in due {
        retransmit_or_give_up(fd);
    }
}

fn retransmit_or_give_up(real_fd: u64) {
    let outcome = {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };
        conn.retransmit_count += 1;
        if conn.retransmit_count > MAX_RETRANSMITS {
            None
        } else {
            conn.retransmit_deadline = Some(crate::cpu::interrupts::ticks() + RETRANSMIT_TICKS);
            Some((conn.unacked_segment.clone(), conn.local_ip, conn.remote_ip))
        }
    };
    match outcome {
        None => {
            let mut state = STATE.lock();
            teardown(&mut state, real_fd);
            state.errors.insert(real_fd, ETIMEDOUT);
        }
        Some((Some(segment), local_ip, remote_ip)) => {
            let _ = ipv4::send_packet(local_ip, remote_ip, PROTO_TCP, &segment);
        }
        Some((None, _, _)) => {}
    }
}

/// Parses one inbound TCP segment (already IP-payload-only, see `ipv4::handle_packet`) and
/// routes it to an existing connection, a listener (for a fresh SYN), or an RST (for anything
/// else -- a segment to a closed port, matching real TCP).
pub fn handle_packet(payload: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
    if payload.len() < HEADER_LEN {
        return;
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
    let ack = u32::from_be_bytes(payload[8..12].try_into().unwrap());
    let data_offset = ((payload[12] >> 4) as usize) * 4;
    let flags = payload[13];
    if data_offset < HEADER_LEN || data_offset > payload.len() {
        return;
    }
    let data = &payload[data_offset..];

    let key = (dst_ip, dst_port, src_ip, src_port);
    let existing = STATE.lock().connections.get(&key).copied();

    if let Some(real_fd) = existing {
        handle_for_connection(real_fd, seq, ack, flags, data);
        return;
    }

    if flags & FLAG_SYN != 0 && flags & FLAG_ACK == 0 {
        handle_new_syn(dst_ip, dst_port, src_ip, src_port, seq);
        return;
    }

    if flags & FLAG_RST == 0 {
        let _ = send_segment(
            dst_ip,
            dst_port,
            src_ip,
            src_port,
            0,
            seq.wrapping_add(1),
            FLAG_RST | FLAG_ACK,
            0,
            &[],
        );
    }
}

fn handle_new_syn(local_ip: Ipv4Addr, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16, their_seq: u32) {
    // The port's listener, if it takes this address: bound to it, or to INADDR_ANY.
    let listener_fd = {
        let state = STATE.lock();
        state.listeners.get(&local_port).copied().filter(|fd| match state.sockets.get(fd) {
            Some(TcpSocket::Listener(l)) => l.addr == ifnet::ANY || l.addr == local_ip,
            _ => false,
        })
    };
    let Some(listener_fd) = listener_fd else {
        let _ = send_segment(
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            0,
            their_seq.wrapping_add(1),
            FLAG_RST | FLAG_ACK,
            0,
            &[],
        );
        return;
    };
    let backlog_full = {
        let state = STATE.lock();
        match state.sockets.get(&listener_fd) {
            Some(TcpSocket::Listener(l)) => l.pending.len() >= l.backlog,
            _ => true,
        }
    };
    if backlog_full {
        return; // silently drop -- the peer's own SYN retransmission will retry later
    }

    let seq = isn(local_ip, local_port, remote_ip, remote_port);
    let conn_fd = crate::fs::fd::oxidebsd_alloc_fd();
    let conn = Connection {
        state: ConnState::SynReceived,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        send_next: seq.wrapping_add(1),
        send_unacked: seq,
        recv_next: their_seq.wrapping_add(1),
        send_buf: VecDeque::new(),
        recv_buf: VecDeque::new(),
        unacked_segment: None,
        retransmit_deadline: None,
        retransmit_count: 0,
        rd_shut: false,
        fin_pending: None,
    };
    {
        let mut state = STATE.lock();
        state
            .connections
            .insert((local_ip, local_port, remote_ip, remote_port), conn_fd);
        state.sockets.insert(conn_fd, TcpSocket::Connection(conn));
    }
    send_and_track(
        conn_fd,
        seq,
        their_seq.wrapping_add(1),
        FLAG_SYN | FLAG_ACK,
        &[],
    );
}

fn handle_for_connection(real_fd: u64, seq: u32, ack: u32, flags: u8, data: &[u8]) {
    if flags & FLAG_RST != 0 {
        let mut state = STATE.lock();
        let refused = matches!(
            state.sockets.get(&real_fd),
            Some(TcpSocket::Connection(Connection { state: ConnState::SynSent, .. }))
        );
        teardown(&mut state, real_fd);
        state.errors.insert(real_fd, if refused { ECONNREFUSED } else { ECONNRESET });
        return;
    }

    let cur_state = {
        let state = STATE.lock();
        match state.sockets.get(&real_fd) {
            Some(TcpSocket::Connection(conn)) => conn.state,
            _ => return,
        }
    };

    match cur_state {
        ConnState::SynSent => handle_syn_sent(real_fd, seq, ack, flags),
        ConnState::SynReceived => handle_syn_received(real_fd, ack, flags),
        ConnState::Established
        | ConnState::FinWait1
        | ConnState::FinWait2
        | ConnState::CloseWait => process_established(real_fd, seq, ack, flags, data),
        ConnState::LastAck => {
            if flags & FLAG_ACK != 0 {
                let mut state = STATE.lock();
                teardown(&mut state, real_fd);
            }
        }
        ConnState::Closed => {}
    }
}

fn handle_syn_sent(real_fd: u64, seq: u32, ack: u32, flags: u8) {
    if flags & FLAG_SYN == 0 || flags & FLAG_ACK == 0 {
        return;
    }
    let outcome = {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };
        if ack != conn.send_next {
            None
        } else {
            conn.recv_next = seq.wrapping_add(1);
            conn.send_unacked = conn.send_next;
            conn.unacked_segment = None;
            conn.retransmit_deadline = None;
            conn.state = ConnState::Established;
            Some((
                conn.local_ip,
                conn.local_port,
                conn.remote_ip,
                conn.remote_port,
                conn.send_next,
                conn.recv_next,
                window_for(conn.recv_buf.len()),
            ))
        }
    };
    if let Some((li, lp, ri, rp, sn, rn, window)) = outcome {
        let _ = send_segment(li, lp, ri, rp, sn, rn, FLAG_ACK, window, &[]);
    }
}

fn handle_syn_received(real_fd: u64, ack: u32, flags: u8) {
    if flags & FLAG_ACK == 0 {
        return;
    }
    let mut state = STATE.lock();
    let local_port = {
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };
        if ack != conn.send_next {
            return;
        }
        conn.send_unacked = conn.send_next;
        conn.unacked_segment = None;
        conn.retransmit_deadline = None;
        conn.state = ConnState::Established;
        conn.local_port
    };
    if let Some(&listener_fd) = state.listeners.get(&local_port)
        && let Some(TcpSocket::Listener(l)) = state.sockets.get_mut(&listener_fd)
    {
        l.pending.push_back(real_fd);
    }
}

fn process_established(real_fd: u64, seq: u32, ack: u32, flags: u8, data: &[u8]) {
    let outcome = {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };

        if flags & FLAG_ACK != 0 && ack != conn.send_unacked && ack == conn.send_next {
            conn.send_unacked = conn.send_next;
            conn.unacked_segment = None;
            conn.retransmit_deadline = None;
            conn.retransmit_count = 0;
            if conn.state == ConnState::FinWait1 {
                conn.state = ConnState::FinWait2;
            }
        }

        // In-order data only -- no reassembly for out-of-order segments (a known simplification).
        if !data.is_empty() && seq == conn.recv_next {
            let room = MAX_RECV_BUF.saturating_sub(conn.recv_buf.len());
            let take = data.len().min(room);
            conn.recv_buf.extend(&data[..take]);
            conn.recv_next = conn.recv_next.wrapping_add(take as u32);
        }

        let mut fin_seen = false;
        if flags & FLAG_FIN != 0 && seq.wrapping_add(data.len() as u32) == conn.recv_next {
            conn.recv_next = conn.recv_next.wrapping_add(1);
            fin_seen = true;
            conn.state = match conn.state {
                ConnState::Established => ConnState::CloseWait,
                ConnState::FinWait1 | ConnState::FinWait2 => ConnState::Closed,
                other => other,
            };
        }

        let should_ack = !data.is_empty() || fin_seen;
        (
            should_ack,
            conn.local_ip,
            conn.local_port,
            conn.remote_ip,
            conn.remote_port,
            conn.send_next,
            conn.recv_next,
            window_for(conn.recv_buf.len()),
        )
    };
    let (should_ack, li, lp, ri, rp, sn, rn, window) = outcome;
    if should_ack {
        let _ = send_segment(li, lp, ri, rp, sn, rn, FLAG_ACK, window, &[]);
    }
    try_send(real_fd);
}

/// Test-support only, not part of the real syscall ABI (same "kept `pub` for a test" precedent
/// `syscall::oxidebsd_register_syscall` already has for `tests/fork_wait.rs`'s own
/// `SYS_TEST_EXIT`) -- a scripted-peer test (`tests/tcp_smoke.rs`) needs to construct valid
/// reply segments, which means knowing sequence numbers this module generates internally
/// (`isn()`'s output isn't predictable from outside, by design) rather than guessing them.
pub fn debug_connection_for(local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> Option<u64> {
    STATE
        .lock()
        .connections
        .iter()
        .find(|&(&(_, lp, ri, rp), _)| (lp, ri, rp) == (local_port, remote_ip, remote_port))
        .map(|(_, &fd)| fd)
}

/// See `debug_connection_for`'s own doc comment.
pub fn debug_send_next(real_fd: u64) -> Option<u32> {
    match STATE.lock().sockets.get(&real_fd) {
        Some(TcpSocket::Connection(conn)) => Some(conn.send_next),
        _ => None,
    }
}

/// `poll`/`select` readiness, Linux-shaped.
fn readiness_of(so: u64) -> crate::fs::Readiness {
    let mut r = crate::fs::Readiness::default();
    let state = STATE.lock();
    match state.sockets.get(&so) {
        Some(TcpSocket::Connection(conn)) => {
            let peer_finished =
                matches!(conn.state, ConnState::CloseWait | ConnState::LastAck | ConnState::Closed);
            r.readable = !conn.recv_buf.is_empty() || peer_finished;
            // Stop-and-wait: one segment in flight at a time.
            r.writable = matches!(conn.state, ConnState::Established | ConnState::CloseWait)
                && conn.unacked_segment.is_none();
            r.hangup = matches!(conn.state, ConnState::LastAck | ConnState::Closed);
        }
        Some(TcpSocket::Listener(l)) => r.readable = !l.pending.is_empty(),
        // Linux reports an unconnected TCP socket as hung up.
        Some(TcpSocket::Unbound { .. }) => r.hangup = true,
        // Torn down: the next call reports why.
        None => {
            r.hangup = true;
            r.readable = true;
            r.error = state.errors.contains_key(&so);
        }
    }
    r
}

/// The socket layer's TCP protocol.
pub(crate) struct Tcp;
pub(crate) static TCP: Tcp = Tcp;

impl Protocol for Tcp {
    fn attach(&self, so: u64) -> Result<(), i64> {
        STATE.lock().sockets.insert(so, TcpSocket::Unbound { local_port: None, local_addr: ifnet::ANY });
        Ok(())
    }

    fn detach(&self, so: u64) {
        super::forget_options(so);
        let mut state = STATE.lock();
        state.errors.remove(&so);
        let conn_state = match state.sockets.get(&so) {
            Some(TcpSocket::Connection(conn)) => Some(conn.state),
            _ => None,
        };
        match conn_state {
            Some(ConnState::Established) => {
                drop(state);
                close_sending(so, ConnState::FinWait1);
            }
            Some(ConnState::CloseWait) => {
                drop(state);
                close_sending(so, ConnState::LastAck);
            }
            Some(_) => teardown(&mut state, so),
            None => {
                state.listeners.retain(|_, &mut v| v != so);
                state.sockets.remove(&so);
            }
        }
    }

    fn bind(&self, so: u64, addr: &[u8]) -> Result<(), i64> {
        let mut state = STATE.lock();
        match state.sockets.get(&so) {
            Some(TcpSocket::Unbound { .. }) => {}
            Some(_) => return Err(EISCONN),
            None => return Err(EBADF as i64),
        }
        let (ip, port) = super::parse_sockaddr_in(addr).ok_or(EINVAL as i64)?;
        if ip != ifnet::ANY && !ifnet::is_local(ip) {
            return Err(EADDRNOTAVAIL);
        }
        let port = if port == 0 { state.alloc_ephemeral_port().ok_or(EADDRINUSE)? } else { port };
        if let Some(TcpSocket::Unbound { local_port, local_addr }) = state.sockets.get_mut(&so) {
            *local_port = Some(port);
            *local_addr = ip;
        }
        Ok(())
    }

    fn connect(&self, so: u64, addr: &[u8]) -> Result<(), i64> {
        let real_fd = so;
        let (remote_ip, remote_port) = super::parse_sockaddr_in(addr).ok_or(EINVAL as i64)?;
        let (local_ip, local_port) = {
            let mut state = STATE.lock();
            let (existing_port, bound) = match state.sockets.get(&real_fd) {
                Some(TcpSocket::Unbound { local_port, local_addr }) => (*local_port, *local_addr),
                Some(_) => return Err(EISCONN),
                None => return Err(EBADF as i64),
            };
            let local_ip = ifnet::source_for(bound, remote_ip).ok_or(EHOSTUNREACH)?;
            let port = match existing_port {
                Some(p) => p,
                None => state.alloc_ephemeral_port().ok_or(EADDRINUSE)?,
            };
            (local_ip, port)
        };

        let seq = isn(local_ip, local_port, remote_ip, remote_port);
        let conn = Connection {
            state: ConnState::SynSent,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            send_next: seq.wrapping_add(1),
            send_unacked: seq,
            recv_next: 0,
            send_buf: VecDeque::new(),
            recv_buf: VecDeque::new(),
            unacked_segment: None,
            retransmit_deadline: None,
            retransmit_count: 0,
            rd_shut: false,
            fin_pending: None,
        };
        {
            let mut state = STATE.lock();
            state
                .connections
                .insert((local_ip, local_port, remote_ip, remote_port), real_fd);
            state.sockets.insert(real_fd, TcpSocket::Connection(conn));
        }

        if send_and_track(real_fd, seq, 0, FLAG_SYN, &[]).is_none() {
            let mut state = STATE.lock();
            teardown(&mut state, real_fd);
            return Err(EHOSTUNREACH);
        }
        // The socket layer waits (`connect_result`); a lost SYN is retransmitted and, after
        // `MAX_RETRANSMITS`, the attempt ends with `ETIMEDOUT` (`retransmit_or_give_up`).
        Err(EINPROGRESS)
    }

    fn connect_result(&self, so: u64) -> Option<Result<(), i64>> {
        crate::net::poll();
        let mut state = STATE.lock();
        match state.sockets.get(&so) {
            Some(TcpSocket::Connection(conn)) => match conn.state {
                ConnState::SynSent => None,
                ConnState::Closed => Some(Err(ECONNREFUSED)),
                _ => Some(Ok(())),
            },
            Some(_) => Some(Err(ECONNREFUSED)),
            None => Some(Err(state.errors.remove(&so).unwrap_or(ECONNREFUSED))),
        }
    }

    fn listen(&self, so: u64, backlog: i64) -> Result<(), i64> {
        let mut state = STATE.lock();
        let (local_port, addr) = match state.sockets.get(&so) {
            Some(TcpSocket::Unbound { local_port, local_addr }) => (*local_port, *local_addr),
            Some(TcpSocket::Listener(_)) => return Ok(()), // already listening -- idempotent
            Some(_) => return Err(EISCONN),
            None => return Err(EBADF as i64),
        };
        let local_port = match local_port {
            Some(p) => p,
            None => state.alloc_ephemeral_port().ok_or(EADDRINUSE)?,
        };
        if state.listeners.contains_key(&local_port) {
            return Err(EADDRINUSE);
        }
        let backlog = (backlog.max(0) as usize).clamp(ACCEPT_BACKLOG_MIN, ACCEPT_BACKLOG_MAX);
        let listener = Listener { addr, backlog, pending: VecDeque::new() };
        state.sockets.insert(so, TcpSocket::Listener(listener));
        state.listeners.insert(local_port, so);
        Ok(())
    }

    /// Never blocks: `EAGAIN` with no completed connection waiting.
    fn accept(&self, so: u64) -> Result<(u64, SockAddr), i64> {
        crate::net::poll();
        let conn_fd = match STATE.lock().sockets.get_mut(&so) {
            Some(TcpSocket::Listener(l)) => l.pending.pop_front(),
            Some(_) => return Err(EOPNOTSUPP),
            None => return Err(EBADF as i64),
        };
        let conn_fd = conn_fd.ok_or(EAGAIN)?;
        match STATE.lock().sockets.get(&conn_fd) {
            Some(TcpSocket::Connection(conn)) => {
                Ok((conn_fd, super::sockaddr_in(conn.remote_ip, conn.remote_port)))
            }
            _ => Err(ECONNREFUSED), // torn down (e.g. RST) between promotion and accept()
        }
    }

    fn send(&self, so: u64, data: &[u8], _to: Option<&[u8]>, _flags: i64) -> Result<usize, i64> {
        {
            let mut state = STATE.lock();
            let conn = match state.sockets.get_mut(&so) {
                Some(TcpSocket::Connection(conn)) => conn,
                Some(_) => return Err(ENOTCONN),
                None => return Err(state.errors.remove(&so).unwrap_or(EPIPE)),
            };
            match conn.state {
                // Our side has asked to close, the FIN waiting on buffered data.
                _ if conn.fin_pending.is_some() => return Err(EPIPE),
                ConnState::Established | ConnState::CloseWait => {}
                ConnState::SynSent | ConnState::SynReceived => return Err(ENOTCONN),
                // Our side has sent its FIN (`close` or `shutdown(SHUT_WR)`).
                _ => return Err(EPIPE),
            }
            conn.send_buf.extend(data);
        }
        try_send(so);
        Ok(data.len())
    }

    /// End-of-file (`n == 0`) only once the peer has really closed (a FIN), `EAGAIN` while the
    /// connection is open and nothing has arrived: an early 0 used to read as EOF and end
    /// BusyBox's TLS handshake before the server's reply came (`networking/tls.c`). The socket
    /// layer waits, blocking between polls of the interface (`net::wait_for_change`).
    fn recv(&self, so: u64, buf: &mut [u8], peek: bool) -> Result<Received, i64> {
        crate::net::poll();
        let mut state = STATE.lock();
        let conn = match state.sockets.get_mut(&so) {
            Some(TcpSocket::Connection(conn)) => conn,
            Some(_) => return Err(ENOTCONN),
            None => return state.errors.remove(&so).map_or(Ok(Received::bytes(0)), Err),
        };
        if conn.rd_shut {
            return Ok(Received::bytes(0));
        }
        let n = conn.recv_buf.len().min(buf.len());
        if n > 0 {
            for (dst, src) in buf.iter_mut().zip(conn.recv_buf.iter()) {
                *dst = *src;
            }
            if !peek {
                conn.recv_buf.drain(..n);
            }
            return Ok(Received::bytes(n));
        }
        if matches!(conn.state, ConnState::CloseWait | ConnState::FinWait2 | ConnState::Closed) {
            return Ok(Received::bytes(0)); // real EOF: the peer has actually signaled closure
        }
        Err(EAGAIN)
    }

    fn shutdown(&self, so: u64, how: i64) -> Result<(), i64> {
        let conn_state = {
            let mut state = STATE.lock();
            let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&so) else {
                return Err(ENOTCONN);
            };
            if how != 1 {
                conn.rd_shut = true; // SHUT_RD or SHUT_RDWR
            }
            conn.state
        };
        if how != 0 {
            match conn_state {
                ConnState::Established => close_sending(so, ConnState::FinWait1),
                ConnState::CloseWait => close_sending(so, ConnState::LastAck),
                _ => {}
            }
        }
        Ok(())
    }

    fn peername(&self, so: u64) -> Result<SockAddr, i64> {
        match STATE.lock().sockets.get(&so) {
            Some(TcpSocket::Connection(conn)) if conn.state != ConnState::SynSent => {
                Ok(super::sockaddr_in(conn.remote_ip, conn.remote_port))
            }
            _ => Err(ENOTCONN),
        }
    }

    fn setopt(&self, so: u64, level: i64, name: i64, val: &[u8]) -> Result<(), i64> {
        super::set_option(so, level, name, val, true)
    }

    fn getopt(&self, so: u64, level: i64, name: i64) -> Result<Vec<u8>, i64> {
        super::get_option(so, level, name, true)
    }

    fn take_error(&self, so: u64) -> i64 {
        STATE.lock().errors.remove(&so).unwrap_or(0)
    }

    /// Real `getsockname(2)` semantics -- succeeds even on a never-`bind`-ed socket, reporting
    /// port `0` (real Linux does the same; this must not have the side effect of allocating an
    /// ephemeral port the way an explicit `bind`/implicit-bind-on-send does).
    fn sockname(&self, so: u64) -> Result<SockAddr, i64> {
        let state = STATE.lock();
        let (addr, local_port) = match state.sockets.get(&so).ok_or(EBADF as i64)? {
            TcpSocket::Unbound { local_port, local_addr } => (*local_addr, local_port.unwrap_or(0)),
            // A `Listener`'s own port isn't stored on itself -- reverse-look it up from
            // `TcpState::listeners`, the only place a listening socket's port lives.
            TcpSocket::Listener(l) => (
                l.addr,
                state.listeners.iter().find(|&(_, &fd)| fd == so).map(|(&port, _)| port).unwrap_or(0),
            ),
            TcpSocket::Connection(conn) => (conn.local_ip, conn.local_port),
        };
        Ok(super::sockaddr_in(addr, local_port))
    }

    fn readiness(&self, so: u64) -> crate::fs::Readiness {
        readiness_of(so)
    }

    fn pulled(&self) -> bool {
        true
    }
}
