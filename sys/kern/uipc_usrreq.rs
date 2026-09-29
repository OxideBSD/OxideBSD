//! Local sockets, `AF_UNIX` (OxideBSD-doc `UNIX.md` §§5-7, 10): stream, datagram and
//! sequenced-packet sockets, named by a file (a socket inode in oxfs), by a name in the abstract
//! namespace, or not at all.
//!
//! Every local socket has one control block (`Unp`, the BSDs' `unpcb`) in `STATE`, keyed by its
//! `real_fd`. A connected pair points at each other through `peer`; data sent is queued on the
//! receiver's `queue`, whose capacity is the receiver's `SO_RCVBUF`. Nothing here blocks: a full
//! buffer or an empty queue is `EAGAIN`, the socket layer waits, and every change of state wakes
//! the waiters (`wake`), as pipes do.
//!
//! Path names live in oxfs, which the kernel can't call directly (modules call the kernel, not the
//! other way round): oxfs hands over two functions at `module_init`
//! (`oxidebsd_register_socket_nodes`). A socket file's inode number maps to the socket bound to it
//! in `STATE.nodes`; a file with no entry (its socket closed, or made in an earlier boot) refuses
//! connections.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use spin::Mutex;

use super::uipc_socket::{
    self, AF_UNIX, DEFAULT_BUF, ENOTCONN, EOPNOTSUPP, EPROTOTYPE, Protocol, Received, SOCK_DGRAM,
    SOCK_SEQPACKET, SOCK_STREAM, SockAddr,
};
use crate::fs::Readiness;
use crate::syscall::{EAGAIN, EBADF, EINVAL, EMSGSIZE, ENAMETOOLONG, EPIPE};

const EADDRINUSE: i64 = 98;
const ECONNRESET: i64 = 104;
const ENOBUFS: i64 = 105;
const EISCONN: i64 = 106;
const ECONNREFUSED: i64 = 111;

/// `sizeof(struct sockaddr_un)`: the family, then 108 bytes of `sun_path`.
const SOCKADDR_UN_LEN: usize = 110;
/// The most connections a listener queues (`UNIX.md` §6.1).
const SOMAXCONN: usize = 128;

/// A local socket's name (`UNIX.md` §5.1).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Name {
    /// A file, by the path given to `bind(2)`.
    Path(Vec<u8>),
    /// A name in the abstract namespace; any bytes, NULs included.
    Abstract(Vec<u8>),
}

/// What an address passed in names.
enum Addr {
    Unnamed,
    Named(Name),
}

/// Parses a `struct sockaddr_un` of `addr.len()` bytes.
fn parse_addr(addr: &[u8]) -> Result<Addr, i64> {
    if addr.len() < 2 || addr.len() > SOCKADDR_UN_LEN {
        return Err(EINVAL as i64);
    }
    if u16::from_ne_bytes([addr[0], addr[1]]) as i64 != AF_UNIX {
        return Err(uipc_socket::EAFNOSUPPORT);
    }
    let path = &addr[2..];
    match path.first() {
        None => Ok(Addr::Unnamed),
        Some(0) => Ok(Addr::Named(Name::Abstract(path[1..].to_vec()))),
        Some(_) => {
            let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            Ok(Addr::Named(Name::Path(path[..end].to_vec())))
        }
    }
}

/// The `struct sockaddr_un` for `name`, as long as `UNIX.md` §5.4 says: a path with its NUL, an
/// abstract name after its leading NUL, or just the family.
fn sockaddr(name: Option<&Name>) -> SockAddr {
    let mut out = (AF_UNIX as u16).to_ne_bytes().to_vec();
    match name {
        None => {}
        Some(Name::Path(p)) => {
            out.extend_from_slice(p);
            out.push(0);
        }
        Some(Name::Abstract(a)) => {
            out.push(0);
            out.extend_from_slice(a);
        }
    }
    out
}

/// One queued message: a datagram, a record, or a run of stream bytes.
struct Msg {
    data: Vec<u8>,
    /// Bytes of `data` already read (a stream reads a message in pieces).
    off: usize,
    /// The sender's name (datagrams only).
    from: Option<Option<Name>>,
}

impl Msg {
    fn left(&self) -> usize {
        self.data.len() - self.off
    }
}

/// A local socket's control block.
struct Unp {
    ty: i64,
    name: Option<Name>,
    /// The socket file's inode, for a path name: dropped from `State::nodes` on close.
    node: Option<u64>,
    /// The other end of a connection (streams and sequenced packets), or the default destination
    /// (datagrams).
    peer: Option<u64>,
    /// The peer's name as of connecting, for `getpeername(2)`.
    peer_name: Option<Name>,
    /// Ever connected: a stream that lost its peer is disconnected, not unconnected.
    connected: bool,
    listening: bool,
    backlog: usize,
    /// Connections made to this listener and not yet accepted, oldest first.
    pending: VecDeque<u64>,
    queue: VecDeque<Msg>,
    /// Bytes in `queue`, unread.
    queued: usize,
    /// `shutdown(SHUT_RD)`: arriving data is dropped, reads see end-of-file.
    rd_shut: bool,
    /// `shutdown(SHUT_WR)`: sends fail with `EPIPE`.
    wr_shut: bool,
    /// The peer will send nothing more: it shut down its write side, or closed.
    eof: bool,
    /// The peer closed.
    peer_gone: bool,
    /// Queued on a listener that closed before accepting it (`UNIX.md` §6.6).
    reset: bool,
}

impl Unp {
    fn new(ty: i64) -> Self {
        Unp {
            ty,
            name: None,
            node: None,
            peer: None,
            peer_name: None,
            connected: false,
            listening: false,
            backlog: 0,
            pending: VecDeque::new(),
            queue: VecDeque::new(),
            queued: 0,
            rd_shut: false,
            wr_shut: false,
            eof: false,
            peer_gone: false,
            reset: false,
        }
    }

    fn drop_queue(&mut self) {
        self.queue.clear();
        self.queued = 0;
    }
}

struct State {
    socks: BTreeMap<u64, Unp>,
    /// Abstract names bound, to their sockets.
    abstract_names: BTreeMap<Vec<u8>, u64>,
    /// Socket-file inodes, to the sockets bound to them.
    nodes: BTreeMap<u64, u64>,
    /// The next autobind name to try (`UNIX.md` §5.3).
    next_autobind: u32,
}

static STATE: Mutex<State> = Mutex::new(State {
    socks: BTreeMap::new(),
    abstract_names: BTreeMap::new(),
    nodes: BTreeMap::new(),
    next_autobind: 0,
});

type NodeFn = extern "C" fn(u64, u64) -> i64;

/// oxfs's socket-file functions: `(create, lookup)`, each `(path_ptr, path_len) -> inode | -errno`.
static NODE_FNS: Mutex<Option<(NodeFn, NodeFn)>> = Mutex::new(None);

/// Called once by oxfs's `module_init`.
pub(crate) extern "C" fn oxidebsd_register_socket_nodes(create: NodeFn, lookup: NodeFn) {
    *NODE_FNS.lock() = Some((create, lookup));
}

/// Runs oxfs's `create` (`true`) or `lookup` on `path`, in the caller's context. Not under
/// `STATE`'s lock: oxfs's work is its own.
fn node_call(create: bool, path: &[u8]) -> Result<u64, i64> {
    let Some((c, l)) = *NODE_FNS.lock() else { return Err(uipc_socket::EAFNOSUPPORT) };
    if path.len() >= SOCKADDR_UN_LEN - 2 {
        return Err(ENAMETOOLONG as i64);
    }
    let f = if create { c } else { l };
    let r = f(path.as_ptr() as u64, path.len() as u64);
    if r < 0 { Err(-r) } else { Ok(r as u64) }
}

/// The receive capacity of socket `so`: its `SO_RCVBUF`, or the default for a connection not yet
/// accepted (it isn't in the socket layer's table until then). May be called under `STATE`'s
/// lock: the socket layer never calls a protocol while holding its own.
fn rcvbuf(so: u64) -> usize {
    uipc_socket::options(so).map_or(DEFAULT_BUF, |o| o.rcvbuf)
}

fn sndbuf(so: u64) -> usize {
    uipc_socket::options(so).map_or(DEFAULT_BUF, |o| o.sndbuf)
}

/// Every local-socket waiter re-checks: something changed.
fn wake() {
    let mut table = crate::process::table().lock();
    crate::process::wake_pollers(&mut table);
}

/// The socket a name refers to, for connecting or sending. A path is looked up in the file
/// system (permissions, `ENOTSOCK`); a file with no socket bound refuses.
fn resolve(name: &Name) -> Result<u64, i64> {
    match name {
        Name::Abstract(a) => STATE.lock().abstract_names.get(a).copied().ok_or(ECONNREFUSED),
        Name::Path(p) => {
            let inode = node_call(false, p)?;
            STATE.lock().nodes.get(&inode).copied().ok_or(ECONNREFUSED)
        }
    }
}

/// Makes `a` and `b` (both attached, of type `ty`) each other's peer: `socketpair(2)`.
pub(crate) fn pair(a: u64, b: u64) {
    let mut st = STATE.lock();
    for (me, other) in [(a, b), (b, a)] {
        if let Some(u) = st.socks.get_mut(&me) {
            u.peer = Some(other);
            u.connected = true;
        }
    }
}

/// The three local-socket protocols, one per type.
pub(crate) struct Local {
    ty: i64,
}

pub(crate) static STREAM: Local = Local { ty: SOCK_STREAM };
pub(crate) static DGRAM: Local = Local { ty: SOCK_DGRAM };
pub(crate) static SEQPACKET: Local = Local { ty: SOCK_SEQPACKET };

/// The protocol for a local socket of type `ty`.
pub(crate) fn protocol(ty: i64, protocol: i64) -> Result<&'static dyn Protocol, i64> {
    if protocol != 0 {
        return Err(crate::syscall::EPROTONOSUPPORT as i64);
    }
    match ty {
        SOCK_STREAM => Ok(&STREAM),
        SOCK_DGRAM => Ok(&DGRAM),
        SOCK_SEQPACKET => Ok(&SEQPACKET),
        _ => Err(crate::syscall::EPROTONOSUPPORT as i64),
    }
}

impl Local {
    fn connected_type(&self) -> bool {
        self.ty != SOCK_DGRAM
    }

    /// Queues `data` on `to`'s receive queue. A stream takes what fits; a record or datagram goes
    /// whole or not at all.
    fn deliver(&self, st: &mut State, to: u64, data: &[u8], from: Option<Option<Name>>, cap: usize) -> Result<usize, i64> {
        let Some(dst) = st.socks.get_mut(&to) else { return Err(EPIPE as i64) };
        if dst.rd_shut {
            return Ok(data.len()); // discarded (`UNIX.md` §6.6)
        }
        let room = cap.saturating_sub(dst.queued);
        match self.ty {
            SOCK_STREAM => {
                let n = data.len().min(room);
                if n == 0 && !data.is_empty() {
                    return Err(EAGAIN as i64);
                }
                match dst.queue.back_mut() {
                    Some(last) => last.data.extend_from_slice(&data[..n]),
                    None => dst.queue.push_back(Msg { data: data[..n].to_vec(), off: 0, from: None }),
                }
                dst.queued += n;
                Ok(n)
            }
            _ => {
                if data.len() > room {
                    return Err(if self.ty == SOCK_DGRAM { ENOBUFS } else { EAGAIN as i64 });
                }
                dst.queue.push_back(Msg { data: data.to_vec(), off: 0, from });
                dst.queued += data.len();
                Ok(data.len())
            }
        }
    }
}

impl Protocol for Local {
    fn attach(&self, so: u64) -> Result<(), i64> {
        STATE.lock().socks.insert(so, Unp::new(self.ty));
        Ok(())
    }

    fn detach(&self, so: u64) {
        let mut st = STATE.lock();
        let Some(u) = st.socks.remove(&so) else { return };
        match &u.name {
            Some(Name::Abstract(a)) => {
                st.abstract_names.remove(a);
            }
            Some(Name::Path(_)) => {
                if let Some(inode) = u.node {
                    st.nodes.remove(&inode);
                }
            }
            None => {}
        }
        // Connections never accepted are reset; their other ends read ECONNRESET.
        for conn in u.pending {
            if let Some(c) = st.socks.remove(&conn)
                && let Some(client) = c.peer
                && let Some(cu) = st.socks.get_mut(&client)
            {
                cu.reset = true;
                cu.peer_gone = true;
                cu.eof = true;
            }
        }
        if self.connected_type()
            && let Some(peer) = u.peer
            && let Some(p) = st.socks.get_mut(&peer)
        {
            p.eof = true;
            p.peer_gone = true;
        }
        drop(st);
        wake();
    }

    fn bind(&self, so: u64, addr: &[u8]) -> Result<(), i64> {
        let name = match parse_addr(addr)? {
            Addr::Named(n) => n,
            Addr::Unnamed => {
                // Autobind: a fresh abstract name of five hex digits.
                let mut st = STATE.lock();
                if st.socks.get(&so).ok_or(EBADF as i64)?.name.is_some() {
                    return Err(EINVAL as i64);
                }
                for _ in 0..0x100000 {
                    let n = st.next_autobind & 0xfffff;
                    st.next_autobind = st.next_autobind.wrapping_add(1);
                    let hex = alloc::format!("{n:05x}").into_bytes();
                    if !st.abstract_names.contains_key(&hex) {
                        st.abstract_names.insert(hex.clone(), so);
                        st.socks.get_mut(&so).unwrap().name = Some(Name::Abstract(hex));
                        return Ok(());
                    }
                }
                return Err(EADDRINUSE);
            }
        };
        if STATE.lock().socks.get(&so).ok_or(EBADF as i64)?.name.is_some() {
            return Err(EINVAL as i64);
        }
        match &name {
            Name::Abstract(a) => {
                let mut st = STATE.lock();
                if st.abstract_names.contains_key(a) {
                    return Err(EADDRINUSE);
                }
                st.abstract_names.insert(a.clone(), so);
                st.socks.get_mut(&so).ok_or(EBADF as i64)?.name = Some(name);
            }
            Name::Path(p) => {
                let inode = node_call(true, p)?;
                let mut st = STATE.lock();
                st.nodes.insert(inode, so);
                let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
                u.name = Some(name);
                u.node = Some(inode);
            }
        }
        Ok(())
    }

    fn connect(&self, so: u64, addr: &[u8]) -> Result<(), i64> {
        if !self.connected_type() && uipc_socket::is_unspec(addr) {
            let mut st = STATE.lock();
            let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
            u.peer = None;
            u.peer_name = None;
            u.connected = false;
            return Ok(());
        }
        let Addr::Named(name) = parse_addr(addr)? else { return Err(EINVAL as i64) };
        let target = resolve(&name)?;
        let mut st = STATE.lock();
        let target_ty = st.socks.get(&target).ok_or(ECONNREFUSED)?.ty;
        if target_ty != self.ty {
            return Err(EPROTOTYPE);
        }
        if !self.connected_type() {
            let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
            u.peer = Some(target);
            u.peer_name = Some(name);
            u.connected = true;
            return Ok(());
        }
        let me = st.socks.get(&so).ok_or(EBADF as i64)?;
        if me.listening {
            return Err(EINVAL as i64);
        }
        if me.connected {
            return Err(EISCONN);
        }
        let my_name = me.name.clone();
        let listener = st.socks.get(&target).ok_or(ECONNREFUSED)?;
        if !listener.listening || listener.pending.len() >= listener.backlog {
            return Err(ECONNREFUSED);
        }
        let listener_name = listener.name.clone();
        // The server's end of the connection: a socket of its own, handed out by accept(2).
        let server = crate::fs::fd::oxidebsd_alloc_fd();
        let mut su = Unp::new(self.ty);
        su.name = listener_name.clone();
        su.peer = Some(so);
        su.peer_name = my_name;
        su.connected = true;
        st.socks.insert(server, su);
        st.socks.get_mut(&target).unwrap().pending.push_back(server);
        let me = st.socks.get_mut(&so).unwrap();
        me.peer = Some(server);
        me.peer_name = listener_name;
        me.connected = true;
        drop(st);
        wake();
        Ok(())
    }

    fn listen(&self, so: u64, backlog: i64) -> Result<(), i64> {
        if !self.connected_type() {
            return Err(EOPNOTSUPP);
        }
        let mut st = STATE.lock();
        let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
        if u.name.is_none() || u.connected {
            return Err(EINVAL as i64);
        }
        u.listening = true;
        u.backlog = (backlog.max(1) as usize).min(SOMAXCONN);
        Ok(())
    }

    fn accept(&self, so: u64) -> Result<(u64, SockAddr), i64> {
        let mut st = STATE.lock();
        let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
        if !u.listening {
            return Err(EINVAL as i64);
        }
        let conn = u.pending.pop_front().ok_or(EAGAIN as i64)?;
        let peer = st.socks.get(&conn).map(|c| sockaddr(c.peer_name.as_ref())).unwrap_or_default();
        Ok((conn, peer))
    }

    fn send(&self, so: u64, data: &[u8], to: Option<&[u8]>, _flags: i64) -> Result<usize, i64> {
        if self.ty == SOCK_DGRAM {
            if data.len() > sndbuf(so) {
                return Err(EMSGSIZE as i64);
            }
            let dest = match to {
                Some(addr) => match parse_addr(addr)? {
                    Addr::Named(name) => resolve(&name)?,
                    Addr::Unnamed => return Err(EINVAL as i64),
                },
                None => {
                    let st = STATE.lock();
                    let u = st.socks.get(&so).ok_or(EBADF as i64)?;
                    // Gone since connect(2): ENOTCONN, as for never connected (§7.4).
                    u.peer.filter(|p| st.socks.contains_key(p)).ok_or(ENOTCONN)?
                }
            };
            let cap = rcvbuf(dest);
            let mut st = STATE.lock();
            let u = st.socks.get(&so).ok_or(EBADF as i64)?;
            if u.wr_shut {
                return Err(EPIPE as i64);
            }
            let from = Some(u.name.clone());
            match st.socks.get(&dest) {
                Some(d) if d.ty != SOCK_DGRAM => return Err(EPROTOTYPE),
                Some(_) => {}
                None => return Err(ECONNREFUSED),
            }
            let n = self.deliver(&mut st, dest, data, from, cap)?;
            drop(st);
            wake();
            return Ok(n);
        }
        let peer = {
            let st = STATE.lock();
            let u = st.socks.get(&so).ok_or(EBADF as i64)?;
            if to.is_some() {
                return Err(if u.connected { EISCONN } else { EOPNOTSUPP });
            }
            if u.wr_shut || u.peer_gone {
                return Err(EPIPE as i64);
            }
            if !u.connected {
                return Err(ENOTCONN);
            }
            u.peer.ok_or(ENOTCONN)?
        };
        let cap = rcvbuf(peer);
        if self.ty == SOCK_SEQPACKET && data.len() > cap {
            return Err(EMSGSIZE as i64);
        }
        let mut st = STATE.lock();
        let n = self.deliver(&mut st, peer, data, None, cap)?;
        drop(st);
        wake();
        Ok(n)
    }

    fn recv(&self, so: u64, buf: &mut [u8], peek: bool) -> Result<Received, i64> {
        let mut st = STATE.lock();
        let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
        if u.queue.is_empty() {
            if u.reset {
                return Err(ECONNRESET);
            }
            if u.rd_shut || u.eof {
                return Ok(Received::bytes(0));
            }
            if self.connected_type() && !u.connected {
                return Err(ENOTCONN);
            }
            return Err(EAGAIN as i64);
        }
        let got = if self.ty == SOCK_STREAM {
            let mut n = 0;
            for m in u.queue.iter() {
                if n == buf.len() {
                    break;
                }
                let k = m.left().min(buf.len() - n);
                buf[n..n + k].copy_from_slice(&m.data[m.off..m.off + k]);
                n += k;
            }
            if !peek {
                let mut left = n;
                while left > 0 {
                    let m = u.queue.front_mut().unwrap();
                    let k = m.left().min(left);
                    m.off += k;
                    left -= k;
                    if m.left() == 0 {
                        u.queue.pop_front();
                    }
                }
                u.queued -= n;
            }
            Received::bytes(n)
        } else {
            let m = u.queue.front().unwrap();
            let n = m.data.len().min(buf.len());
            buf[..n].copy_from_slice(&m.data[..n]);
            let r = Received {
                n,
                full: m.data.len(),
                from: m.from.as_ref().map(|f| sockaddr(f.as_ref())),
                eor: self.ty == SOCK_SEQPACKET,
            };
            if !peek {
                let m = u.queue.pop_front().unwrap();
                u.queued -= m.data.len();
            }
            r
        };
        drop(st);
        if !peek {
            wake(); // a sender may be waiting for room
        }
        Ok(got)
    }

    fn shutdown(&self, so: u64, how: i64) -> Result<(), i64> {
        let mut st = STATE.lock();
        let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
        if self.connected_type() && !u.connected {
            return Err(ENOTCONN);
        }
        let (rd, wr) = (how == 0 || how == 2, how == 1 || how == 2);
        if rd {
            u.rd_shut = true;
            u.drop_queue();
        }
        let peer = u.peer;
        if wr {
            u.wr_shut = true;
            if self.connected_type()
                && let Some(p) = peer.and_then(|p| st.socks.get_mut(&p))
            {
                p.eof = true;
            }
        }
        drop(st);
        wake();
        Ok(())
    }

    fn sockname(&self, so: u64) -> Result<SockAddr, i64> {
        let st = STATE.lock();
        Ok(sockaddr(st.socks.get(&so).ok_or(EBADF as i64)?.name.as_ref()))
    }

    fn peername(&self, so: u64) -> Result<SockAddr, i64> {
        let st = STATE.lock();
        let u = st.socks.get(&so).ok_or(EBADF as i64)?;
        let live = match u.peer {
            Some(p) => st.socks.contains_key(&p) && !u.peer_gone,
            None => false,
        };
        if !u.connected || !live {
            return Err(ENOTCONN);
        }
        Ok(sockaddr(u.peer_name.as_ref()))
    }

    fn readiness(&self, so: u64) -> Readiness {
        let st = STATE.lock();
        let Some(u) = st.socks.get(&so) else {
            return Readiness { error: true, hangup: true, ..Default::default() };
        };
        let mut r = Readiness::default();
        if u.listening {
            r.readable = !u.pending.is_empty();
            return r;
        }
        r.readable = !u.queue.is_empty() || u.eof || u.rd_shut || u.reset;
        if self.ty == SOCK_DGRAM {
            r.writable = !u.wr_shut;
            return r;
        }
        if u.connected {
            let peer_room = u.peer.and_then(|p| Some((p, st.socks.get(&p)?))).map(|(so, p)| {
                if p.rd_shut { usize::MAX } else { rcvbuf(so).saturating_sub(p.queued) }
            });
            // A send that would fail at once (EPIPE) doesn't block either.
            r.writable = u.wr_shut || u.peer_gone || peer_room.is_none_or(|room| room > 0);
            r.hangup = u.peer_gone || (u.wr_shut && (u.rd_shut || u.eof));
        }
        r
    }

    fn pulled(&self) -> bool {
        false
    }
}
