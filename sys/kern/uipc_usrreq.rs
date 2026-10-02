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
//!
//! Messages carry control data (`UNIX.md` §§8-9). Descriptors sent with `SCM_RIGHTS` are held by
//! the message (`fs::fd::hold`) until received, when they're installed in the receiver, or until
//! the message is discarded, when they're released. A socket sent over itself, or a cycle of
//! them, can make itself unreachable: `gc` finds such sockets and flushes them, as the BSDs'
//! `unp_gc` does. Credentials are recorded per message (the sender's) and per connection (the
//! peer's), and handed out in whichever forms the receiver asked for.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use core::sync::atomic::{AtomicBool, Ordering};
use alloc::vec::Vec;

use spin::Mutex;

use super::uipc_socket::{
    self, AF_UNIX, DEFAULT_BUF, ENOPROTOOPT, ENOTCONN, EOPNOTSUPP, EPROTOTYPE, Protocol, Received,
    RecvCtl, RecvMsg, SO_PASSCRED, SO_PEERCRED, SOCK_DGRAM, SOCK_SEQPACKET, SOCK_STREAM, SOL_LOCAL,
    SockAddr,
};
use crate::fs::Readiness;
use crate::syscall::{EAGAIN, EBADF, EINVAL, EMSGSIZE, ENAMETOOLONG, EPERM, EPIPE};

const EADDRINUSE: i64 = 98;
const ECONNRESET: i64 = 104;
const ENOBUFS: i64 = 105;
const EISCONN: i64 = 106;
const ECONNREFUSED: i64 = 111;
const ETOOMANYREFS: i64 = 109;

/// `SOL_SOCKET` control messages: FreeBSD's `SCM_CREDS`/`SCM_CREDS2` values, musl's (Linux's)
/// `SCM_RIGHTS`/`SCM_CREDENTIALS` (`UNIX.md` §9.6).
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const SCM_CREDS: i32 = 3;
const SCM_CREDS2: i32 = 8;
/// `SOL_LOCAL` options, OxideBSD's values (FreeBSD's 1-3 are `SO_*` values in musl).
const LOCAL_PEERCRED: i64 = 0x1001;
const LOCAL_CREDS: i64 = 0x1002;
const LOCAL_CREDS_PERSISTENT: i64 = 0x1003;

/// `struct cmsghdr` on x86_64 musl: `cmsg_len` (32 bits, then 4 bytes of padding), level, type.
const CMSG_HDR: usize = 16;
/// Descriptions one user may have in flight, and the whole system (`UNIX.md` §8.5).
const MAX_INFLIGHT_USER: u32 = 1024;
const MAX_INFLIGHT: u32 = 4096;

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

/// A process's credentials as local sockets pass them (`UNIX.md` §9.1): real and effective IDs,
/// and the groups as FreeBSD's `cr_groups` holds them, the effective group first and then the
/// supplementary groups, at most `CMGROUP_MAX` (16).
#[derive(Clone, Copy, PartialEq, Eq)]
struct Cred {
    pid: u32,
    ruid: u32,
    euid: u32,
    rgid: u32,
    egid: u32,
    ngroups: u32,
    groups: [u32; 16],
}

fn current_cred() -> Cred {
    let c = crate::process::identity::current_cred();
    let mut groups = [0u32; 16];
    groups[0] = c.egid;
    let mut ngroups = 1;
    for &g in c.groups.iter().take(groups.len() - 1) {
        groups[ngroups] = g;
        ngroups += 1;
    }
    Cred {
        pid: crate::process::scheduler::current_tgid() as u32,
        ruid: c.ruid,
        euid: c.euid,
        rgid: c.rgid,
        egid: c.egid,
        ngroups: ngroups as u32,
        groups,
    }
}

fn words(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|w| w.to_ne_bytes()).collect()
}

/// `struct xucred` (`LOCAL_PEERCRED`): version, effective uid, `short` group count, 16 groups,
/// and the pid in an 8-byte union at the end; 88 bytes.
fn xucred(c: Cred) -> Vec<u8> {
    let mut v = words(&[0, c.euid]);
    v.extend_from_slice(&(c.ngroups as i16).to_ne_bytes());
    v.extend_from_slice(&[0; 2]);
    v.extend_from_slice(&words(&c.groups));
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(&(c.pid as u64).to_ne_bytes());
    v
}

/// `struct ucred` (`SO_PEERCRED`, `SCM_CREDENTIALS`): pid and the effective uid and gid, as Linux
/// reports them.
fn ucred(c: Cred) -> Vec<u8> {
    words(&[c.pid, c.euid, c.egid])
}

/// `struct cmsgcred` (`SCM_CREDS` the sender asked for): pid, real uid, effective uid, real gid,
/// a `short` group count and 16 groups; 84 bytes.
fn cmsgcred(c: Cred) -> Vec<u8> {
    let mut v = words(&[c.pid, c.ruid, c.euid, c.rgid]);
    v.extend_from_slice(&(c.ngroups as i16).to_ne_bytes());
    v.extend_from_slice(&[0; 2]);
    v.extend_from_slice(&words(&c.groups));
    v
}

/// `struct sockcred` (`LOCAL_CREDS`): real and effective uid and gid, the group count, the groups.
fn sockcred(c: Cred) -> Vec<u8> {
    let mut v = words(&[c.ruid, c.euid, c.rgid, c.egid, c.ngroups]);
    v.extend_from_slice(&words(&c.groups[..c.ngroups as usize]));
    v
}

/// `struct sockcred2` (`LOCAL_CREDS_PERSISTENT`): `sockcred` after a version and the pid.
fn sockcred2(c: Cred) -> Vec<u8> {
    let mut v = words(&[0, c.pid]);
    v.extend_from_slice(&sockcred(c));
    v
}

/// What a message carries besides its bytes, as the sender gave it.
#[derive(Default)]
struct Control {
    /// `SCM_RIGHTS`: descriptions held for the receiver.
    rights: Vec<u64>,
    /// `SCM_CREDS`: the sender asked for its credentials to go along (the kernel fills them in).
    creds: bool,
    /// `SCM_CREDENTIALS`: credentials the sender supplied, already checked.
    credentials: Option<Cred>,
}

/// One queued message: a datagram, a record, or a run of stream bytes.
struct Msg {
    data: Vec<u8>,
    /// Bytes of `data` already read (a stream reads a message in pieces).
    off: usize,
    /// The sender's name (datagrams only).
    from: Option<Option<Name>>,
    sender: Cred,
    /// Control data, if the send had any. A stream never runs bytes sent with control data
    /// together with earlier ones (`UNIX.md` §6.4).
    control: Option<Control>,
}

impl Msg {
    fn left(&self) -> usize {
        self.data.len() - self.off
    }
}

/// `LOCAL_CREDS` and `LOCAL_CREDS_PERSISTENT` (`UNIX.md` §9.5); at most one is set.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LocalCreds {
    Off,
    Once,
    Persistent,
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
    /// The peer's credentials as of connecting (`UNIX.md` §9.2).
    peer_cred: Option<Cred>,
    /// This socket's own, as of `listen(2)`: what connecting sockets record as their peer's.
    listen_cred: Option<Cred>,
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
    /// `SO_PASSCRED`.
    passcred: bool,
    local_creds: LocalCreds,
    /// `LOCAL_CREDS` on a stream gives credentials with the first receive only.
    creds_given: bool,
}

impl Unp {
    fn new(ty: i64) -> Self {
        Unp {
            ty,
            name: None,
            node: None,
            peer: None,
            peer_name: None,
            peer_cred: None,
            listen_cred: None,
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
            passcred: false,
            local_creds: LocalCreds::Off,
            creds_given: false,
        }
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
    /// Descriptions in flight: how many messages hold each (a description sent twice counts
    /// twice).
    inflight: BTreeMap<u64, u32>,
    /// In flight per sending user, and in all (`UNIX.md` §8.5).
    inflight_by_uid: BTreeMap<u32, u32>,
    inflight_total: u32,
}

/// Whether a socket is bound to socket-file inode `inode`, for oxfs's `oxidebsd_inode_in_use`:
/// a reused inode number would connect a new socket file to this socket. `None` if the lock is
/// busy (a descriptor being closed from inside this module, say); the caller then keeps the inode.
pub(crate) fn node_bound(inode: u64) -> Option<bool> {
    Some(STATE.try_lock()?.nodes.contains_key(&inode))
}

static STATE: Mutex<State> = Mutex::new(State {
    socks: BTreeMap::new(),
    abstract_names: BTreeMap::new(),
    nodes: BTreeMap::new(),
    next_autobind: 0,
    inflight: BTreeMap::new(),
    inflight_by_uid: BTreeMap::new(),
    inflight_total: 0,
});

impl State {
    /// Counts `rights` as in flight for a message from `uid`, or refuses (`ETOOMANYREFS`). Root
    /// is held to the system-wide limit only.
    fn take_inflight(&mut self, uid: u32, rights: &[u64]) -> Result<(), i64> {
        let n = rights.len() as u32;
        let mine = self.inflight_by_uid.get(&uid).copied().unwrap_or(0);
        if self.inflight_total + n > MAX_INFLIGHT || (uid != 0 && mine + n > MAX_INFLIGHT_USER) {
            return Err(ETOOMANYREFS);
        }
        for &r in rights {
            *self.inflight.entry(r).or_insert(0) += 1;
        }
        *self.inflight_by_uid.entry(uid).or_insert(0) += n;
        self.inflight_total += n;
        Ok(())
    }

    /// Undoes `take_inflight` for `rights` sent by `uid`: they've arrived or are being dropped.
    fn put_inflight(&mut self, uid: u32, rights: &[u64]) {
        for r in rights {
            if let Some(c) = self.inflight.get_mut(r) {
                *c -= 1;
                if *c == 0 {
                    self.inflight.remove(r);
                }
            }
        }
        if let Some(c) = self.inflight_by_uid.get_mut(&uid) {
            *c -= rights.len() as u32;
        }
        self.inflight_total -= rights.len() as u32;
    }

    /// Discards `msgs`, returning the descriptions they held for the caller to release once
    /// `STATE` is unlocked (releasing may close a socket, which comes back here).
    fn discard(&mut self, msgs: impl IntoIterator<Item = Msg>) -> Vec<u64> {
        let mut out = Vec::new();
        for m in msgs {
            if let Some(c) = m.control
                && !c.rights.is_empty()
            {
                self.put_inflight(m.sender.euid, &c.rights);
                out.extend(c.rights);
            }
        }
        out
    }

    /// Empties `so`'s receive queue; the descriptions to release.
    fn flush(&mut self, so: u64) -> Vec<u64> {
        let Some(u) = self.socks.get_mut(&so) else { return Vec::new() };
        let msgs: Vec<Msg> = u.queue.drain(..).collect();
        u.queued = 0;
        self.discard(msgs)
    }
}

/// Releases descriptions a discarded message held.
fn release_all(rights: Vec<u64>) {
    for r in rights {
        crate::fs::fd::release(r);
    }
}

static GC_RUNNING: AtomicBool = AtomicBool::new(false);

/// A descriptor for `real_fd` was closed and others remain. If messages in flight are among them,
/// the rest may be only those messages: collect.
pub(crate) fn descriptor_closed(real_fd: u64) {
    if STATE.lock().inflight.contains_key(&real_fd) {
        gc();
    }
}

/// Collects local sockets that only messages in flight can reach (`UNIX.md` §8.4), the BSDs'
/// `unp_gc`: a socket is reachable if a descriptor refers to it (more references than messages
/// hold) or it sits in the queue of a reachable socket; one with descriptions in flight and
/// neither is garbage, and its queue is flushed. Flushing releases what its messages held, which
/// closes the sockets in the cycle in turn.
fn gc() {
    if GC_RUNNING.swap(true, Ordering::AcqRel) {
        return; // the closes gc causes run it again
    }
    loop {
        let garbage: Vec<u64> = {
            let st = STATE.lock();
            if st.inflight_total == 0 {
                break;
            }
            let mut marked = BTreeSet::new();
            let mut work = Vec::new();
            for &so in st.socks.keys() {
                let held = st.inflight.get(&so).copied().unwrap_or(0);
                let refs = crate::fs::fd::refs(so);
                // A connection not yet accepted has no description; its listener reaches it.
                if refs > held {
                    marked.insert(so);
                    work.push(so);
                }
            }
            while let Some(so) = work.pop() {
                let Some(u) = st.socks.get(&so) else { continue };
                let inside = u
                    .queue
                    .iter()
                    .filter_map(|m| m.control.as_ref())
                    .flat_map(|c| c.rights.iter().copied())
                    .chain(u.pending.iter().copied());
                for r in inside {
                    if st.socks.contains_key(&r) && marked.insert(r) {
                        work.push(r);
                    }
                }
            }
            st.socks
                .keys()
                .copied()
                .filter(|so| st.inflight.contains_key(so) && !marked.contains(so))
                .collect()
        };
        if garbage.is_empty() {
            break;
        }
        let rights: Vec<u64> = {
            let mut st = STATE.lock();
            garbage.iter().flat_map(|&so| st.flush(so)).collect()
        };
        release_all(rights);
    }
    GC_RUNNING.store(false, Ordering::Release);
}

/// Parses a send's control data (`struct cmsghdr`s) into what the message will carry. Descriptors
/// aren't held yet (`send_control` does that under `STATE`); a bad one is `EBADF`.
fn parse_control(control: &[u8], me: Cred) -> Result<Option<Control>, i64> {
    if control.is_empty() {
        return Ok(None);
    }
    let mut c = Control::default();
    let mut off = 0;
    while off + CMSG_HDR <= control.len() {
        let len = u32::from_ne_bytes(control[off..off + 4].try_into().unwrap()) as usize;
        let level = i32::from_ne_bytes(control[off + 8..off + 12].try_into().unwrap());
        let ty = i32::from_ne_bytes(control[off + 12..off + 16].try_into().unwrap());
        if len < CMSG_HDR || off + len > control.len() {
            return Err(EINVAL as i64);
        }
        let data = &control[off + CMSG_HDR..off + len];
        match (level, ty) {
            (SOL_SOCKET, SCM_RIGHTS) => {
                if data.len() % 4 != 0 {
                    return Err(EINVAL as i64);
                }
                for fd in data.chunks_exact(4) {
                    let fd = i32::from_ne_bytes(fd.try_into().unwrap());
                    let real = if fd < 0 { None } else { crate::fs::fd::real_fd_of(fd as u64) };
                    c.rights.push(real.ok_or(EBADF as i64)?);
                }
            }
            // The kernel fills it in: whatever the sender wrote is ignored (§9.3).
            (SOL_SOCKET, SCM_CREDS) => c.creds = true,
            (SOL_SOCKET, SCM_CREDENTIALS) => {
                if data.len() < 12 {
                    return Err(EINVAL as i64);
                }
                let w = |i: usize| u32::from_ne_bytes(data[i..i + 4].try_into().unwrap());
                let (pid, uid, gid) = (w(0), w(4), w(8));
                let mut groups = [0u32; 16];
                groups[0] = gid;
                let given = Cred { pid, ruid: uid, euid: uid, rgid: gid, egid: gid, ngroups: 1, groups };
                // Only one's own (its pid, its real or effective IDs), unless root (§9.4).
                let own = pid == me.pid && (uid == me.ruid || uid == me.euid) && (gid == me.rgid || gid == me.egid);
                if !own && me.euid != 0 {
                    return Err(EPERM as i64);
                }
                c.credentials = Some(given);
            }
            _ => return Err(EINVAL as i64),
        }
        off += (len + 7) & !7;
    }
    Ok(Some(c))
}

/// Control data being built for a receiver whose buffer has `room` bytes: each message is
/// `CMSG_SPACE` long except that the last may lose its padding; one that doesn't fit is dropped
/// and `MSG_CTRUNC` reported.
struct CmsgBuf {
    out: Vec<u8>,
    room: usize,
    truncated: bool,
}

impl CmsgBuf {
    fn push(&mut self, ty: i32, data: &[u8]) -> bool {
        let len = CMSG_HDR + data.len();
        let left = self.room.saturating_sub(self.out.len());
        if len > left {
            self.truncated = true;
            return false;
        }
        self.out.extend_from_slice(&(len as u32).to_ne_bytes());
        self.out.extend_from_slice(&[0; 4]);
        self.out.extend_from_slice(&SOL_SOCKET.to_ne_bytes());
        self.out.extend_from_slice(&ty.to_ne_bytes());
        self.out.extend_from_slice(data);
        let pad = ((len + 7) & !7) - len;
        let pad = pad.min(self.room - self.out.len());
        self.out.extend(core::iter::repeat_n(0, pad));
        true
    }
}

/// The control data the receiver `u` gets with message `m` (`UNIX.md` §§8.2, 9.3-9.5):
/// credentials in whichever forms it asked for, then any descriptors, installed at its lowest
/// free descriptors. Descriptors that don't fit are released and `MSG_CTRUNC` reported. A peek
/// shows credentials but leaves descriptors in the message. Returns the bytes, the truncation,
/// and the descriptions to release after `STATE` is unlocked.
fn externalize(st: &mut State, so: u64, m: &mut Msg, ctl: RecvCtl, peek: bool) -> (Vec<u8>, bool, Vec<u64>) {
    let mut b = CmsgBuf { out: Vec::new(), room: ctl.room, truncated: false };
    let u = st.socks.get_mut(&so).expect("externalize: receiver gone");
    let sender = m.sender;
    let asked_creds = m.control.as_ref().is_some_and(|c| c.creds);
    if asked_creds && u.local_creds == LocalCreds::Off {
        b.push(SCM_CREDS, &cmsgcred(sender));
    }
    match u.local_creds {
        LocalCreds::Once if u.ty == SOCK_DGRAM || !u.creds_given => {
            b.push(SCM_CREDS, &sockcred(sender));
            if !peek {
                u.creds_given = true;
            }
        }
        LocalCreds::Persistent => {
            b.push(SCM_CREDS2, &sockcred2(sender));
        }
        _ => {}
    }
    if u.passcred {
        let given = m.control.as_ref().and_then(|c| c.credentials);
        b.push(SCM_CREDENTIALS, &ucred(given.unwrap_or(sender)));
    }
    let mut release = Vec::new();
    if !peek
        && let Some(c) = m.control.as_mut()
        && !c.rights.is_empty()
    {
        let rights = core::mem::take(&mut c.rights);
        st.put_inflight(sender.euid, &rights);
        let left = ctl.room.saturating_sub(b.out.len());
        let fit = left.saturating_sub(CMSG_HDR) / 4;
        let n = rights.len().min(fit);
        if n > 0 {
            let fds: Vec<u32> = rights[..n].iter().map(|&r| crate::fs::fd::install_held(r, ctl.cloexec) as u32).collect();
            b.push(SCM_RIGHTS, &words(&fds));
        }
        if n < rights.len() {
            b.truncated = true;
            release.extend_from_slice(&rights[n..]);
        }
    }
    (b.out, b.truncated, release)
}

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

/// Makes `a` and `b` (both attached, of type `ty`) each other's peer: `socketpair(2)`. Each end
/// records its creator's credentials as its peer's (`UNIX.md` §9.2).
pub(crate) fn pair(a: u64, b: u64) {
    let cred = current_cred();
    let mut st = STATE.lock();
    for (me, other) in [(a, b), (b, a)] {
        if let Some(u) = st.socks.get_mut(&me) {
            u.peer = Some(other);
            u.peer_cred = Some(cred);
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
    /// whole or not at all. Control data goes in a message of its own, which a stream never
    /// merges with the one before. A receiver that shut its read side takes nothing: the message
    /// is dropped, and the descriptions it would have held are returned for release.
    #[allow(clippy::too_many_arguments)]
    fn deliver(
        &self,
        st: &mut State,
        to: u64,
        data: &[u8],
        from: Option<Option<Name>>,
        cap: usize,
        sender: Cred,
        control: &mut Option<Control>,
    ) -> Result<(usize, Vec<u64>), i64> {
        let Some(dst) = st.socks.get_mut(&to) else { return Err(EPIPE as i64) };
        if dst.rd_shut {
            let dropped = control.take().map(|c| Msg { data: Vec::new(), off: 0, from: None, sender, control: Some(c) });
            return Ok((data.len(), st.discard(dropped))); // discarded (`UNIX.md` §6.6)
        }
        let room = cap.saturating_sub(dst.queued);
        match self.ty {
            SOCK_STREAM => {
                let n = data.len().min(room);
                if n == 0 && !data.is_empty() {
                    return Err(EAGAIN as i64);
                }
                match dst.queue.back_mut() {
                    Some(last) if control.is_none() && last.sender == sender => {
                        last.data.extend_from_slice(&data[..n])
                    }
                    _ => dst.queue.push_back(Msg {
                        data: data[..n].to_vec(),
                        off: 0,
                        from: None,
                        sender,
                        control: control.take(),
                    }),
                }
                dst.queued += n;
                Ok((n, Vec::new()))
            }
            _ => {
                if data.len() > room {
                    return Err(if self.ty == SOCK_DGRAM { ENOBUFS } else { EAGAIN as i64 });
                }
                dst.queue.push_back(Msg { data: data.to_vec(), off: 0, from, sender, control: control.take() });
                dst.queued += data.len();
                Ok((data.len(), Vec::new()))
            }
        }
    }

    /// Where a send goes: the destination socket and, for a datagram, the sender's name.
    fn destination(&self, so: u64, to: Option<&[u8]>) -> Result<(u64, Option<Option<Name>>), i64> {
        if self.ty == SOCK_DGRAM {
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
            let st = STATE.lock();
            let u = st.socks.get(&so).ok_or(EBADF as i64)?;
            if u.wr_shut {
                return Err(EPIPE as i64);
            }
            match st.socks.get(&dest) {
                Some(d) if d.ty != SOCK_DGRAM => return Err(EPROTOTYPE),
                Some(_) => {}
                None => return Err(ECONNREFUSED),
            }
            return Ok((dest, Some(u.name.clone())));
        }
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
        Ok((u.peer.ok_or(ENOTCONN)?, None))
    }
}

impl Protocol for Local {
    fn attach(&self, so: u64) -> Result<(), i64> {
        STATE.lock().socks.insert(so, Unp::new(self.ty));
        Ok(())
    }

    fn detach(&self, so: u64) {
        let mut st = STATE.lock();
        let Some(mut u) = st.socks.remove(&so) else { return };
        // Messages still queued go, and with them the descriptions they held (`UNIX.md` §8.3).
        let mut release: Vec<u64> = {
            let msgs: Vec<Msg> = u.queue.drain(..).collect();
            st.discard(msgs)
        };
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
            let Some(mut c) = st.socks.remove(&conn) else { continue };
            let msgs: Vec<Msg> = c.queue.drain(..).collect();
            release.extend(st.discard(msgs));
            if let Some(client) = c.peer
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
        let collect = st.inflight_total > 0;
        drop(st);
        release_all(release);
        if collect {
            gc();
        }
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
        let listener_cred = listener.listen_cred;
        // The server's end of the connection: a socket of its own, handed out by accept(2).
        let server = crate::fs::fd::oxidebsd_alloc_fd();
        let mut su = Unp::new(self.ty);
        su.name = listener_name.clone();
        su.peer = Some(so);
        su.peer_name = my_name;
        su.peer_cred = Some(current_cred());
        su.connected = true;
        st.socks.insert(server, su);
        st.socks.get_mut(&target).unwrap().pending.push_back(server);
        let me = st.socks.get_mut(&so).unwrap();
        me.peer = Some(server);
        me.peer_name = listener_name;
        me.peer_cred = listener_cred;
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
        u.listen_cred = Some(current_cred());
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

    fn send(&self, so: u64, data: &[u8], to: Option<&[u8]>, flags: i64) -> Result<usize, i64> {
        self.send_msg(so, data, to, flags, &[])
    }

    fn send_msg(&self, so: u64, data: &[u8], to: Option<&[u8]>, _flags: i64, control: &[u8]) -> Result<usize, i64> {
        if self.ty == SOCK_DGRAM && data.len() > sndbuf(so) {
            return Err(EMSGSIZE as i64);
        }
        let sender = current_cred();
        let mut control = parse_control(control, sender)?;
        let (dest, from) = self.destination(so, to)?;
        let cap = rcvbuf(dest);
        if self.ty == SOCK_SEQPACKET && data.len() > cap {
            return Err(EMSGSIZE as i64);
        }
        let mut st = STATE.lock();
        let rights = control.as_ref().map(|c| c.rights.clone()).unwrap_or_default();
        if !rights.is_empty() {
            st.take_inflight(sender.euid, &rights)?;
            for &r in &rights {
                crate::fs::fd::hold(r);
            }
        }
        let result = self.deliver(&mut st, dest, data, from, cap, sender, &mut control);
        // Not delivered (no room, or no receiver): the descriptions go back.
        let undone = match &result {
            Err(_) if !rights.is_empty() => {
                st.put_inflight(sender.euid, &rights);
                rights
            }
            _ => Vec::new(),
        };
        drop(st);
        release_all(undone);
        let (n, dropped) = result?;
        release_all(dropped);
        wake();
        Ok(n)
    }

    fn recv(&self, so: u64, buf: &mut [u8], peek: bool) -> Result<Received, i64> {
        let ctl = RecvCtl { room: 0, cloexec: false, continuing: false };
        self.recv_msg(so, buf, peek, ctl).map(|m| m.r)
    }

    fn recv_msg(&self, so: u64, buf: &mut [u8], peek: bool, ctl: RecvCtl) -> Result<RecvMsg, i64> {
        let mut st = STATE.lock();
        let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
        let Some(mut m) = u.queue.pop_front() else {
            if u.reset {
                return Err(ECONNRESET);
            }
            if u.rd_shut || u.eof {
                return Ok(RecvMsg { r: Received::bytes(0), control: Vec::new(), ctrunc: false, stopped: false });
            }
            if self.connected_type() && !u.connected {
                return Err(ENOTCONN);
            }
            return Err(EAGAIN as i64);
        };
        if self.ty == SOCK_STREAM && ctl.continuing && m.control.is_some() {
            // Bytes sent with control data aren't run together with earlier ones (§6.4).
            u.queue.push_front(m);
            return Ok(RecvMsg { r: Received::bytes(0), control: Vec::new(), ctrunc: false, stopped: true });
        }
        let (control, ctrunc, release) = if m.control.is_some() || u.passcred || u.local_creds != LocalCreds::Off {
            externalize(&mut st, so, &mut m, ctl, peek)
        } else {
            (Vec::new(), false, Vec::new())
        };
        // Control data is handed out once, with the first bytes read.
        if !peek {
            m.control = None;
        }
        let u = st.socks.get_mut(&so).unwrap();
        let r = if self.ty == SOCK_STREAM {
            // This message, then as many after it as fit, stopping at one sent with control data.
            let mut n = m.left().min(buf.len());
            buf[..n].copy_from_slice(&m.data[m.off..m.off + n]);
            if !peek {
                m.off += n;
            }
            let mut consumed_rest = 0;
            for next in u.queue.iter() {
                if n == buf.len() || next.control.is_some() {
                    break;
                }
                let k = next.left().min(buf.len() - n);
                buf[n..n + k].copy_from_slice(&next.data[next.off..next.off + k]);
                n += k;
                consumed_rest += k;
            }
            if !peek {
                let mut left = consumed_rest;
                while left > 0 {
                    let next = u.queue.front_mut().unwrap();
                    let k = next.left().min(left);
                    next.off += k;
                    left -= k;
                    if next.left() == 0 {
                        u.queue.pop_front();
                    }
                }
                u.queued -= n;
            }
            if peek || m.left() > 0 {
                u.queue.push_front(m);
            }
            Received::bytes(n)
        } else {
            let n = m.data.len().min(buf.len());
            buf[..n].copy_from_slice(&m.data[..n]);
            let r = Received {
                n,
                full: m.data.len(),
                from: m.from.as_ref().map(|f| sockaddr(f.as_ref())),
                eor: self.ty == SOCK_SEQPACKET,
            };
            if peek {
                u.queue.push_front(m);
            } else {
                u.queued -= m.data.len();
            }
            r
        };
        drop(st);
        release_all(release);
        if !peek {
            wake(); // a sender may be waiting for room
        }
        Ok(RecvMsg { r, control, ctrunc, stopped: false })
    }

    fn shutdown(&self, so: u64, how: i64) -> Result<(), i64> {
        let mut st = STATE.lock();
        let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
        if self.connected_type() && !u.connected {
            return Err(ENOTCONN);
        }
        let (rd, wr) = (how == 0 || how == 2, how == 1 || how == 2);
        let mut release = Vec::new();
        if rd {
            u.rd_shut = true;
            release = st.flush(so);
        }
        let u = st.socks.get_mut(&so).unwrap();
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
        release_all(release);
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

    fn setopt(&self, so: u64, level: i64, name: i64, val: &[u8]) -> Result<(), i64> {
        let on = || -> Result<bool, i64> { Ok(i32::from_ne_bytes(val.get(..4).ok_or(EINVAL as i64)?.try_into().unwrap()) != 0) };
        let mut st = STATE.lock();
        let u = st.socks.get_mut(&so).ok_or(EBADF as i64)?;
        match (level, name) {
            (uipc_socket::SOL_SOCKET_LEVEL, SO_PASSCRED) => u.passcred = on()?,
            (SOL_LOCAL, LOCAL_CREDS | LOCAL_CREDS_PERSISTENT) => {
                let want = if name == LOCAL_CREDS { LocalCreds::Once } else { LocalCreds::Persistent };
                if on()? {
                    // The two are exclusive (§9.5).
                    if u.local_creds != LocalCreds::Off && u.local_creds != want {
                        return Err(EINVAL as i64);
                    }
                    u.local_creds = want;
                } else if u.local_creds == want {
                    u.local_creds = LocalCreds::Off;
                }
            }
            (SOL_LOCAL, LOCAL_PEERCRED) => return Err(EINVAL as i64),
            _ => return Err(ENOPROTOOPT),
        }
        Ok(())
    }

    fn getopt(&self, so: u64, level: i64, name: i64) -> Result<Vec<u8>, i64> {
        let st = STATE.lock();
        let u = st.socks.get(&so).ok_or(EBADF as i64)?;
        let int = |b: bool| (b as i32).to_ne_bytes().to_vec();
        Ok(match (level, name) {
            (uipc_socket::SOL_SOCKET_LEVEL, SO_PASSCRED) => int(u.passcred),
            (uipc_socket::SOL_SOCKET_LEVEL, SO_PEERCRED) => ucred(u.peer_cred.ok_or(ENOTCONN)?),
            (SOL_LOCAL, LOCAL_PEERCRED) => xucred(u.peer_cred.ok_or(ENOTCONN)?),
            (SOL_LOCAL, LOCAL_CREDS) => int(u.local_creds == LocalCreds::Once),
            (SOL_LOCAL, LOCAL_CREDS_PERSISTENT) => int(u.local_creds == LocalCreds::Persistent),
            _ => return Err(ENOPROTOOPT),
        })
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
