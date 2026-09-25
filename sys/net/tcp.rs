//! Minimal TCP: a real (if simplified) state machine -- one segment in flight at a time
//! (stop-and-wait, no sliding window/congestion control), a fixed 536-byte MSS (RFC 1122's safe
//! default; this kernel does no IP fragmentation, so staying under the guaranteed minimum path
//! MTU avoids ever needing it), a fixed retransmission timeout (no RTT estimation), and no
//! TIME_WAIT/out-of-order reassembly/urgent-pointer/options support beyond correctly skipping
//! past whatever the peer's `data_offset` says (real interoperability doesn't need parsing
//! options we don't use, just not misreading their length as payload). See this repo's
//! networking plan for the full list of what's deferred.
//!
//! `connect()`/`listen()`/`accept()` are dedicated syscalls (state transitions, not data flow);
//! once a connection reaches `Established`, its `read`/`write` fd-ops callbacks genuinely are
//! plain-byte-stream-shaped (an implicit peer, no address argument needed) -- the one place in
//! this whole design where existing `SYS_READ`/`SYS_WRITE` machinery carries socket data, exactly
//! mirroring how `fat32`/`oxfs` register file read/write today.
//!
//! `connect`/`accept` are non-blocking-with-self-poll, same convention `udp.rs`'s `recvfrom`
//! already established (matches this kernel's own `sys_read`-on-stdin precedent) rather than
//! real scheduler blocking -- a well-justified follow-up once real interactive use (a program
//! that wants to sit in `accept()` indefinitely) actually needs it, not built speculatively now.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use spin::Mutex;

use super::ipv4::{self, Ipv4Addr};
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
const CONNECT_TIMEOUT_TICKS: u64 = 500; // ~5s
const ACCEPT_BACKLOG_MIN: usize = 1;
const ACCEPT_BACKLOG_MAX: usize = 128;

/// errno values are musl's (`bits/errno.h`), since they become userland's `errno` unchanged. All
/// but `EAGAIN` used to be FreeBSD's.
const EAGAIN: i64 = 11;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const ECONNREFUSED: i64 = 111;
const ETIMEDOUT: i64 = 110;
const EOPNOTSUPP: i64 = 95;
const EADDRINUSE: i64 = 98;
const EHOSTUNREACH: i64 = 113;

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
}

struct Listener {
    backlog: usize,
    /// `real_fd`s of connections that completed their handshake and are waiting for `accept()`
    /// to claim them.
    pending: VecDeque<u64>,
}

enum TcpSocket {
    /// Created by `socket()`, not yet `bind()`/`connect()`/`listen()`-ed.
    Unbound {
        local_port: Option<u16>,
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
    /// (local port, remote ip, remote port) -> that connection's `real_fd`, for demuxing every
    /// other inbound segment.
    connections: BTreeMap<(u16, Ipv4Addr, u16), u64>,
    next_ephemeral: u16,
}

impl TcpState {
    const fn new() -> Self {
        TcpState {
            sockets: BTreeMap::new(),
            listeners: BTreeMap::new(),
            connections: BTreeMap::new(),
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

fn resolve(fd: u64) -> Option<u64> {
    crate::fs::fd::real_fd_of(fd)
}

/// RFC 6528 initial sequence number: `M + F(local, remote, secret)`. `M` is a clock ticking
/// every 4 microseconds (from the TSC, so it advances inside a syscall too); `F` is SHA-256 over
/// the connection 4-tuple and a boot-time random key. The clock keeps a reused 4-tuple's sequence
/// space moving forward past any old duplicate segments; the keyed hash keeps an off-path attacker
/// from predicting it.
fn isn(local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> u32 {
    use sha2::{Digest, Sha256};
    let key = *ISN_KEY.call_once(|| {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&crate::random::kernel_random_u64().to_le_bytes());
        key[8..].copy_from_slice(&crate::random::kernel_random_u64().to_le_bytes());
        key
    });
    let mut h = Sha256::new();
    h.update(crate::net::ipv4::GUEST_IP);
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
/// retransmission tracking) on success. Eight parameters, one per real TCP header field this
/// layer actually varies -- grouping them into a params struct wouldn't make a raw
/// header-building function any clearer.
#[allow(clippy::too_many_arguments)]
fn send_segment(
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
    let cksum = tcp_checksum(ipv4::GUEST_IP, remote_ip, &seg);
    seg[16..18].copy_from_slice(&cksum.to_be_bytes());
    ipv4::send_packet(remote_ip, PROTO_TCP, &seg)?;
    Some(seg)
}

/// Sends a segment for an existing connection and, if it carries a SYN/FIN/data (anything the
/// peer must ACK), tracks it for retransmission. `seq`/`ack`/`flags`/`data` are explicit
/// (rather than always read straight from the connection) since callers building a SYN/FIN use a
/// seq value distinct from `send_next` at the moment they call this.
fn send_and_track(real_fd: u64, seq: u32, ack: u32, flags: u8, data: &[u8]) -> Option<()> {
    let (local_port, remote_ip, remote_port, window) = {
        let state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get(&real_fd) else {
            return None;
        };
        (
            conn.local_port,
            conn.remote_ip,
            conn.remote_port,
            window_for(conn.recv_buf.len()),
        )
    };
    let segment = send_segment(
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
        let key = (conn.local_port, conn.remote_ip, conn.remote_port);
        state.connections.remove(&key);
    }
    state.sockets.remove(&real_fd);
}

/// Sends a buffered chunk (up to `MSS`) if nothing's currently in flight and the connection can
/// still send. Called after `write()` and after any state change that might have freed up the
/// single in-flight slot (an ACK, a fresh accept).
fn try_send(real_fd: u64) {
    let sendable = {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return;
        };
        if conn.unacked_segment.is_some()
            || conn.send_buf.is_empty()
            || !matches!(conn.state, ConnState::Established | ConnState::CloseWait)
        {
            None
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

/// Sends a FIN for a connection currently in `Established`/`CloseWait` and transitions it to
/// `next_state`. Shared by `tcp_close`'s two graceful-shutdown cases.
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
            Some((conn.unacked_segment.clone(), conn.remote_ip))
        }
    };
    match outcome {
        None => {
            let mut state = STATE.lock();
            teardown(&mut state, real_fd);
        }
        Some((Some(segment), remote_ip)) => {
            let _ = ipv4::send_packet(remote_ip, PROTO_TCP, &segment);
        }
        Some((None, _)) => {}
    }
}

/// Parses one inbound TCP segment (already IP-payload-only, see `ipv4::handle_packet`) and
/// routes it to an existing connection, a listener (for a fresh SYN), or an RST (for anything
/// else -- a segment to a closed port, matching real TCP).
pub fn handle_packet(payload: &[u8], src_ip: Ipv4Addr) {
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

    let key = (dst_port, src_ip, src_port);
    let existing = STATE.lock().connections.get(&key).copied();

    if let Some(real_fd) = existing {
        handle_for_connection(real_fd, seq, ack, flags, data);
        return;
    }

    if flags & FLAG_SYN != 0 && flags & FLAG_ACK == 0 {
        handle_new_syn(dst_port, src_ip, src_port, seq);
        return;
    }

    if flags & FLAG_RST == 0 {
        let _ = send_segment(
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

fn handle_new_syn(local_port: u16, remote_ip: Ipv4Addr, remote_port: u16, their_seq: u32) {
    let listener_fd = {
        let state = STATE.lock();
        state.listeners.get(&local_port).copied()
    };
    let Some(listener_fd) = listener_fd else {
        let _ = send_segment(
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

    let seq = isn(local_port, remote_ip, remote_port);
    let conn_fd = crate::fs::fd::oxidebsd_alloc_fd();
    let conn = Connection {
        state: ConnState::SynReceived,
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
    };
    {
        let mut state = STATE.lock();
        state
            .connections
            .insert((local_port, remote_ip, remote_port), conn_fd);
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
        teardown(&mut state, real_fd);
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
                conn.local_port,
                conn.remote_ip,
                conn.remote_port,
                conn.send_next,
                conn.recv_next,
                window_for(conn.recv_buf.len()),
            ))
        }
    };
    if let Some((lp, ri, rp, sn, rn, window)) = outcome {
        let _ = send_segment(lp, ri, rp, sn, rn, FLAG_ACK, window, &[]);
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
            conn.local_port,
            conn.remote_ip,
            conn.remote_port,
            conn.send_next,
            conn.recv_next,
            window_for(conn.recv_buf.len()),
        )
    };
    let (should_ack, lp, ri, rp, sn, rn, window) = outcome;
    if should_ack {
        let _ = send_segment(lp, ri, rp, sn, rn, FLAG_ACK, window, &[]);
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
        .get(&(local_port, remote_ip, remote_port))
        .copied()
}

/// See `debug_connection_for`'s own doc comment.
pub fn debug_send_next(real_fd: u64) -> Option<u32> {
    match STATE.lock().sockets.get(&real_fd) {
        Some(TcpSocket::Connection(conn)) => Some(conn.send_next),
        _ => None,
    }
}

/// `None` if `real_fd` isn't a TCP socket at all (caller, `net::oxidebsd_sys_poll`, keeps looking
/// in the other protocols' tables). `Some(true)` means readable right now: real bytes queued for
/// an established connection, or a completed handshake waiting on `accept()` for a listener --
/// the same two events real `poll(POLLIN)` reports for a stream socket.
pub fn has_data_ready(real_fd: u64) -> Option<bool> {
    match STATE.lock().sockets.get(&real_fd) {
        Some(TcpSocket::Connection(conn)) => Some(!conn.recv_buf.is_empty()),
        Some(TcpSocket::Listener(l)) => Some(!l.pending.is_empty()),
        Some(TcpSocket::Unbound { .. }) => Some(false),
        None => None,
    }
}

/// `poll`/`select` readiness, Linux-shaped. `None` if `real_fd` isn't a TCP socket.
pub fn readiness(real_fd: u64) -> Option<crate::fs::Readiness> {
    let mut r = crate::fs::Readiness::default();
    match STATE.lock().sockets.get(&real_fd)? {
        TcpSocket::Connection(conn) => {
            let peer_finished =
                matches!(conn.state, ConnState::CloseWait | ConnState::LastAck | ConnState::Closed);
            r.readable = !conn.recv_buf.is_empty() || peer_finished;
            // Stop-and-wait: one segment in flight at a time.
            r.writable = matches!(conn.state, ConnState::Established | ConnState::CloseWait)
                && conn.unacked_segment.is_none();
            r.hangup = matches!(conn.state, ConnState::LastAck | ConnState::Closed);
        }
        TcpSocket::Listener(l) => r.readable = !l.pending.is_empty(),
        // Linux reports an unconnected TCP socket as hung up.
        TcpSocket::Unbound { .. } => r.hangup = true,
    }
    Some(r)
}

pub fn create_socket() -> u64 {
    let fd = crate::fs::fd::oxidebsd_alloc_fd();
    STATE
        .lock()
        .sockets
        .insert(fd, TcpSocket::Unbound { local_port: None });
    crate::fs::fd::oxidebsd_register_fd_ops(fd, tcp_read, tcp_write, tcp_close)
}

/// `None` if `real_fd` isn't a TCP socket at all (the caller, `udp::oxidebsd_sys_bind`, should
/// keep looking in its own table); `Some(result)` if it is.
pub fn bind(real_fd: u64, addr_ptr: u64) -> Option<i64> {
    let mut state = STATE.lock();
    match state.sockets.get(&real_fd) {
        Some(TcpSocket::Unbound { .. }) => {}
        Some(_) => return Some(-EISCONN),
        None => return None,
    }
    let Some((_ip, port)) = super::udp::read_sockaddr(addr_ptr) else {
        return Some(-(EINVAL as i64));
    };
    let port = if port == 0 {
        match state.alloc_ephemeral_port() {
            Some(p) => p,
            None => return Some(-EADDRINUSE),
        }
    } else {
        port
    };
    if let Some(TcpSocket::Unbound { local_port }) = state.sockets.get_mut(&real_fd) {
        *local_port = Some(port);
    }
    Some(0)
}

/// Same not-mine-vs-mine `Option` convention as `bind` above. Real `getsockname(2)` semantics --
/// succeeds even on a never-`bind`-ed socket, reporting port `0` (real Linux does the same; this
/// must not have the side effect of allocating an ephemeral port the way an explicit `bind`/
/// implicit-bind-on-send does).
pub fn getsockname(real_fd: u64, addr_out_ptr: u64, addrlen_ptr: u64) -> Option<i64> {
    let state = STATE.lock();
    let local_port = match state.sockets.get(&real_fd)? {
        TcpSocket::Unbound { local_port } => local_port.unwrap_or(0),
        // A `Listener`'s own port isn't stored on itself -- reverse-look it up from
        // `TcpState::listeners`, the only place a listening socket's port lives.
        TcpSocket::Listener(_) => state
            .listeners
            .iter()
            .find(|&(_, &fd)| fd == real_fd)
            .map(|(&port, _)| port)
            .unwrap_or(0),
        TcpSocket::Connection(conn) => conn.local_port,
    };
    drop(state);
    super::udp::write_sockaddr(addr_out_ptr, super::ipv4::GUEST_IP, local_port);
    if addrlen_ptr != 0 {
        unsafe {
            *(addrlen_ptr as *mut u32) = 16;
        }
    }
    Some(0)
}

/// Same not-mine-vs-mine `Option` convention as `bind` above.
pub fn setsockopt(real_fd: u64) -> Option<i64> {
    STATE.lock().sockets.get(&real_fd).map(|_| 0)
}

pub extern "C" fn oxidebsd_sys_connect(fd: u64, addr_ptr: u64, len: u64) -> i64 {
    let _ = len;
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };
    let Some((remote_ip, remote_port)) = super::udp::read_sockaddr(addr_ptr) else {
        return -(EINVAL as i64);
    };

    let local_port = {
        let mut state = STATE.lock();
        let existing_port = match state.sockets.get(&real_fd) {
            Some(TcpSocket::Unbound { local_port }) => *local_port,
            Some(_) => return -EISCONN,
            None => return -(EBADF as i64),
        };
        match existing_port {
            Some(p) => p,
            None => match state.alloc_ephemeral_port() {
                Some(p) => p,
                None => return -EADDRINUSE,
            },
        }
    };

    let seq = isn(local_port, remote_ip, remote_port);
    let conn = Connection {
        state: ConnState::SynSent,
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
    };
    {
        let mut state = STATE.lock();
        state
            .connections
            .insert((local_port, remote_ip, remote_port), real_fd);
        state.sockets.insert(real_fd, TcpSocket::Connection(conn));
    }

    if send_and_track(real_fd, seq, 0, FLAG_SYN, &[]).is_none() {
        let mut state = STATE.lock();
        teardown(&mut state, real_fd);
        return -EHOSTUNREACH;
    }

    // `crate::tsc`, not `crate::cpu::interrupts::ticks()`: `ticks()` is driven entirely by the timer
    // IRQ, which can't fire while this syscall has interrupts masked (`sys/syscall.rs`'s SFMASK
    // setup) -- a tick-based deadline here would be frozen at whatever value it had when the
    // syscall began and could never actually elapse, turning "give up after N ticks" into "never
    // gives up" for a peer that never completes the handshake. Confirmed live by the identical
    // bug in `net::oxidebsd_sys_poll` (see `crate::tsc`'s own doc comment) -- fixed here for the
    // same reason. `CONNECT_TIMEOUT_TICKS` is still the budget, just converted to `tsc` cycles.
    let deadline =
        crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(CONNECT_TIMEOUT_TICKS * 10);
    loop {
        super::poll();
        let outcome = {
            let state = STATE.lock();
            match state.sockets.get(&real_fd) {
                Some(TcpSocket::Connection(conn)) => match conn.state {
                    ConnState::Established => Some(0),
                    ConnState::Closed => Some(-ECONNREFUSED),
                    _ => None,
                },
                _ => Some(-ECONNREFUSED),
            }
        };
        if let Some(result) = outcome {
            return result;
        }
        if crate::cpu::tsc::now() >= deadline {
            let mut state = STATE.lock();
            teardown(&mut state, real_fd);
            return -ETIMEDOUT;
        }
        // `hint::spin_loop()`, not `hlt()` -- this is a real syscall handler (`connect()`), and
        // interrupts stay masked for a syscall's entire duration (`sys/syscall.rs`'s SFMASK
        // setup), not just its entry. `hlt()` here would freeze the CPU permanently the moment
        // the handshake hadn't already completed before this loop started, since nothing can
        // wake it. See `ipv4::resolve_with_retry`'s own doc comment for the fuller explanation.
        core::hint::spin_loop();
    }
}

pub extern "C" fn oxidebsd_sys_listen(fd: u64, backlog: u64) -> i64 {
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };
    let mut state = STATE.lock();
    let local_port = match state.sockets.get(&real_fd) {
        Some(TcpSocket::Unbound { local_port }) => *local_port,
        Some(TcpSocket::Listener(_)) => return 0, // already listening -- idempotent
        Some(_) => return -EISCONN,
        None => return -(EBADF as i64),
    };
    let local_port = match local_port {
        Some(p) => p,
        None => match state.alloc_ephemeral_port() {
            Some(p) => p,
            None => return -EADDRINUSE,
        },
    };
    if state.listeners.contains_key(&local_port) {
        return -EADDRINUSE;
    }
    let backlog = (backlog as usize).clamp(ACCEPT_BACKLOG_MIN, ACCEPT_BACKLOG_MAX);
    state.sockets.insert(
        real_fd,
        TcpSocket::Listener(Listener {
            backlog,
            pending: VecDeque::new(),
        }),
    );
    state.listeners.insert(local_port, real_fd);
    0
}

pub extern "C" fn oxidebsd_sys_accept(fd: u64, addr_out_ptr: u64, addrlen_ptr: u64) -> i64 {
    let Some(real_fd) = resolve(fd) else {
        return -(EBADF as i64);
    };

    super::poll();

    let conn_fd = {
        let mut state = STATE.lock();
        match state.sockets.get_mut(&real_fd) {
            Some(TcpSocket::Listener(l)) => l.pending.pop_front(),
            Some(_) => return -EOPNOTSUPP,
            None => return -(EBADF as i64),
        }
    };
    let Some(conn_fd) = conn_fd else {
        return -EAGAIN;
    };

    let addr = {
        let state = STATE.lock();
        match state.sockets.get(&conn_fd) {
            Some(TcpSocket::Connection(conn)) => Some((conn.remote_ip, conn.remote_port)),
            _ => None, // torn down (e.g. RST) between promotion and accept()
        }
    };
    let Some((remote_ip, remote_port)) = addr else {
        return -ECONNREFUSED;
    };

    let user_fd =
        crate::fs::fd::oxidebsd_register_fd_ops(conn_fd, tcp_read, tcp_write, tcp_close);
    super::udp::write_sockaddr(addr_out_ptr, remote_ip, remote_port);
    if addrlen_ptr != 0 {
        unsafe {
            *(addrlen_ptr as *mut u32) = 16;
        }
    }
    user_fd as i64
}

/// Genuinely blocks (unless `O_NONBLOCK` is set -- `crate::fs::fd::is_nonblocking`, `syscall::
/// sys_fcntl`) while the connection is still open and simply has nothing buffered *yet* -- only
/// returns `0` (real EOF) once the peer has actually signaled closure (`CloseWait`/`FinWait2`/
/// `Closed`, reached via a real FIN, not just an empty buffer). Previously returned `0` the
/// instant `recv_buf` was momentarily empty regardless of connection state -- indistinguishable
/// from real EOF to a caller, which is exactly what killed BusyBox's own TLS handshake read
/// (`tls_xread_record` in `networking/tls.c`, which correctly-by-its-own-logic treated that early
/// `0` as "abrupt EOF, no TLS shutdown" and gave up, even though the real server's ServerHello
/// just hadn't arrived yet) -- see CLAUDE.md's own "Real networking" known-gaps entry for the full
/// trace that found this. Plain HTTP happened not to trigger it in practice (by the time `wget`'s
/// own body-reading loop gets there, there's usually already been enough round-trip latency for
/// data to be sitting in the buffer), but it was always a real, latent race.
///
/// **Spins (`core::hint::spin_loop()`), does *not* use `process::BlockReason`/
/// `scheduler::schedule()` the way `crate::pipe`'s own blocking reads do** -- a deliberate,
/// load-bearing difference, not an oversight: incoming-packet processing on this kernel is
/// pull-based, driven entirely by whichever process happens to call `super::poll()` (the rtl8139
/// IRQ handler itself does no heap allocation and touches no protocol state, just sets a flag --
/// see `sys/net/rtl8139.rs`'s own doc comment). If this yielded to the scheduler the way a pipe
/// read does, nothing would ever call `poll()` again on this connection's behalf once the only
/// process that cares about it (the one blocked right here) stops running -- a real hang, worse
/// than the false-EOF bug this replaces. Same reasoning already established for `oxidebsd_sys_
/// connect`'s own handshake wait and `ipv4::resolve_with_retry`'s ARP wait (see CLAUDE.md's own
/// "Real networking" section on the `hlt()`-in-syscall freeze those two were fixed for) -- ordinary
/// interrupts (timer, keyboard) still fire throughout, only a voluntary yield to another
/// *schedulable* process doesn't happen. No timeout: unlike connection *establishment* (which
/// reasonably needs an upper bound before giving up), blocking indefinitely for more data on an
/// already-open connection is correct, ordinary blocking-`read()` behavior -- the same accepted
/// "spins for the syscall's whole duration against a genuinely unresponsive peer" tradeoff
/// CLAUDE.md's own `hlt()` fix already documents for this same class of wait.
extern "C" fn tcp_read(real_fd: u64, ptr: u64, len: u64) -> i64 {
    loop {
        super::poll();
        let bytes = {
            let mut state = STATE.lock();
            let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
                return -(EBADF as i64);
            };
            let n = conn.recv_buf.len().min(len as usize);
            if n > 0 {
                Some(conn.recv_buf.drain(..n).collect::<Vec<u8>>())
            } else if matches!(
                conn.state,
                ConnState::CloseWait | ConnState::FinWait2 | ConnState::Closed
            ) {
                return 0; // real EOF: the peer has actually signaled closure
            } else if crate::fs::fd::is_nonblocking(real_fd) {
                return -EAGAIN;
            } else {
                None
            }
        };
        let Some(bytes) = bytes else {
            core::hint::spin_loop();
            continue;
        };
        // SAFETY: same known pointer-validation gap sys_read/sys_write already document.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
        }
        return bytes.len() as i64;
    }
}

extern "C" fn tcp_write(real_fd: u64, ptr: u64, len: u64) -> i64 {
    {
        let mut state = STATE.lock();
        let Some(TcpSocket::Connection(conn)) = state.sockets.get_mut(&real_fd) else {
            return -(EBADF as i64);
        };
        if !matches!(conn.state, ConnState::Established | ConnState::CloseWait) {
            return -ENOTCONN;
        }
        let data = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
        conn.send_buf.extend(data);
    }
    try_send(real_fd);
    len as i64
}

extern "C" fn tcp_close(real_fd: u64) -> i64 {
    let mut state = STATE.lock();
    let conn_state = match state.sockets.get(&real_fd) {
        Some(TcpSocket::Connection(conn)) => Some(conn.state),
        _ => None,
    };
    match conn_state {
        Some(ConnState::Established) => {
            drop(state);
            send_fin_and_transition(real_fd, ConnState::FinWait1);
        }
        Some(ConnState::CloseWait) => {
            drop(state);
            send_fin_and_transition(real_fd, ConnState::LastAck);
        }
        Some(_) => teardown(&mut state, real_fd),
        None => {
            state.listeners.retain(|_, &mut v| v != real_fd);
            state.sockets.remove(&real_fd);
        }
    }
    0
}
