//! `dhclient(8)`: the DHCPv4 client (RFC 2131).
//!
//! ```text
//! dhclient [-bdrv] [-l leasefile] [-p pidfile] interface
//! ```
//!
//! A small daemon in the manner of OpenBSD's dhcpleased, under FreeBSD's name and file layout,
//! one per interface. It runs RFC 2131's state machine: INIT (DHCPDISCOVER), SELECTING (the
//! first acceptable DHCPOFFER), REQUESTING, BOUND; at T1 RENEWING (DHCPREQUEST unicast to the
//! server), at T2 REBINDING (broadcast), and at the lease's end it takes the address away and
//! starts again. A lease saved by an earlier run (`/var/db/dhclient.leases.<if>`) that hasn't
//! expired is asked for again first (INIT-REBOOT). Requests are retransmitted after 4, 8, 16,
//! 32 and then every 64 seconds, each ±1 s at random.
//!
//! A lease is applied directly: the interface's address and mask, the default route (the
//! lease's first router) and `/etc/resolv.conf` (its name servers and domain). Without `-d` the
//! client stays in the foreground until it is bound, or for 60 seconds, so the boot goes on with
//! the network configured, then goes into the background; `-b` goes at once. It logs through
//! `syslog(3)` (and to the standard error while in the foreground). SIGTERM, SIGINT and SIGHUP
//! end it, keeping the lease and the configuration as they are; with `-r` it sends a
//! DHCPRELEASE and removes the address first.
//!
//! Everything from the network is checked before use ([`packet`], [`lease`]): messages with the
//! wrong transaction ID, hardware address or source port are ignored, and so is anything
//! malformed.

mod gateway;
#[allow(dead_code)]
mod ifnet;
mod lease;
mod net;
mod packet;

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lease::Lease;
use packet::{DHCPACK, DHCPDISCOVER, DHCPNAK, DHCPOFFER, DHCPRELEASE, DHCPREQUEST};

const PIDFILE_DIR: &str = "/var/run/dhclient";
const LEASE_DIR: &str = "/var/db";
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// How long the client waits in the foreground for a first lease (FreeBSD's `timeout`).
const DETACH_AFTER: Duration = Duration::from_secs(60);
/// The first retransmission interval, and the longest (RFC 2131 §4.1).
const FIRST_INTERVAL: Duration = Duration::from_secs(4);
const MAX_INTERVAL: Duration = Duration::from_secs(64);
/// While renewing or rebinding, never retransmit sooner than this (RFC 2131 §4.4.5).
const MIN_RENEW_INTERVAL: Duration = Duration::from_secs(60);
/// DHCPREQUESTs sent in REQUESTING, and in INIT-REBOOT, before starting over.
const REQUEST_TRIES: u32 = 4;
const REBOOT_TRIES: u32 = 2;
/// At most this many datagrams are read per wakeup, so a flood can't starve the timers.
const RECV_BURST: usize = 64;

static SIGNO: AtomicI32 = AtomicI32::new(0);
static SIG_PIPE: AtomicI32 = AtomicI32::new(-1);
/// Messages also go to the standard error (until the client is in the background).
static ECHO: AtomicBool = AtomicBool::new(true);
static VERBOSE: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(sig: libc::c_int) {
    SIGNO.store(sig, Ordering::Relaxed);
    let fd = SIG_PIPE.load(Ordering::Relaxed);
    if fd >= 0 {
        // SAFETY: write(2) is async-signal-safe; the byte only wakes the loop.
        unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
    }
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn log(prio: libc::c_int, msg: &str) {
    if prio == libc::LOG_DEBUG && !VERBOSE.load(Ordering::Relaxed) {
        return;
    }
    if let Ok(c) = CString::new(msg.replace('\0', "?")) {
        // SAFETY: a "%s" format with one C string.
        unsafe { libc::syslog(prio, c"%s".as_ptr(), c.as_ptr()) };
    }
    if ECHO.load(Ordering::Relaxed) {
        eprintln!("{msg}");
    }
}

fn info(msg: &str) {
    log(libc::LOG_INFO, msg)
}

fn warn(msg: &str) {
    log(libc::LOG_WARNING, msg)
}

fn debug(msg: &str) {
    log(libc::LOG_DEBUG, msg)
}

fn wall_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// A random number from the kernel, for transaction IDs and jitter; if `/dev/urandom` can't be
/// read, a mix of the clock, the pid and a counter (good enough for jitter, weak for IDs, and
/// logged).
fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    if File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_ok() {
        return u32::from_ne_bytes(b);
    }
    static COUNTER: AtomicI32 = AtomicI32::new(0);
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        warn("/dev/urandom unreadable; transaction IDs are guessable");
    }
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let mut z = n ^ ((std::process::id() as u64) << 32) ^ COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (z ^ (z >> 31)) as u32
}

/// `d` ±1 second at random (RFC 2131 §4.1), never below a second.
fn jitter(d: Duration) -> Duration {
    let j = (random_u32() % 2001) as i64 - 1000;
    Duration::from_millis((d.as_millis() as i64 + j).max(1000) as u64)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    Init,
    Selecting,
    Requesting,
    Rebooting,
    Bound,
    Renewing,
    Rebinding,
}

struct Opts {
    foreground: bool,
    background: bool,
    release: bool,
    ifname: String,
    lease_file: String,
    pid_file: String,
}

struct Client {
    ifname: String,
    mac: [u8; 6],
    sock: net::Socket,
    net: ifnet::Ifnet,
    lease_file: String,
    resolv_conf: String,

    state: State,
    xid: u32,
    /// When this exchange began (the `secs` field counts from it).
    began: Instant,
    tries: u32,
    interval: Duration,
    next_send: Instant,
    /// When INIT may send (after a NAK, the wait doubles up to a minute).
    init_at: Instant,
    nak_wait: Duration,
    /// The offer being requested: address and server.
    offer: Option<(Ipv4Addr, Ipv4Addr)>,

    /// The lease held (BOUND, RENEWING, REBINDING) or asked for again (INIT-REBOOT), and its
    /// deadlines (`None`: never).
    lease: Option<Lease>,
    t1_at: Option<Instant>,
    t2_at: Option<Instant>,
    expire_at: Option<Instant>,
    /// The default route this client set, so it only ever removes its own.
    our_gateway: Option<Ipv4Addr>,

    /// Still in the foreground, waiting to go into the background at `detach_at`.
    detach_at: Option<Instant>,
    pidfile: Option<File>,
}

impl Client {
    fn new_exchange(&mut self, now: Instant) {
        self.xid = random_u32();
        self.began = now;
        self.tries = 0;
        self.interval = FIRST_INTERVAL;
        self.next_send = now;
    }

    fn secs(&self) -> u16 {
        self.began.elapsed().as_secs().min(u16::MAX as u64) as u16
    }

    fn request(&self, kind: u8) -> packet::Request {
        packet::Request {
            kind,
            xid: self.xid,
            secs: self.secs(),
            mac: self.mac,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested: None,
            server: None,
        }
    }

    fn send(&self, r: &packet::Request, to: Ipv4Addr, interval: Option<Duration>) {
        let what = packet::type_name(r.kind);
        match interval {
            Some(i) => info(&format!("{what} on {} to {to} port {} interval {}", self.ifname, net::SERVER_PORT, i.as_secs())),
            None => info(&format!("{what} on {} to {to} port {}", self.ifname, net::SERVER_PORT)),
        }
        if let Err(e) = self.sock.send_to(&packet::build(r), to) {
            warn(&format!("send_packet: {}", strerror(&e)));
        }
    }

    /// Schedules the next retransmission with backoff.
    fn backoff(&mut self, now: Instant) {
        self.tries += 1;
        self.next_send = now + jitter(self.interval);
        self.interval = (self.interval * 2).min(MAX_INTERVAL);
    }

    fn send_discover(&mut self, now: Instant) {
        let mut r = self.request(DHCPDISCOVER);
        // The address we had, as a hint (RFC 2131 §4.4.1).
        r.requested = self.lease.as_ref().map(|l| l.addr);
        self.send(&r, Ipv4Addr::BROADCAST, Some(self.interval));
        self.backoff(now);
    }

    fn send_selecting_request(&mut self, now: Instant) {
        let Some((addr, server)) = self.offer else { return };
        let mut r = self.request(DHCPREQUEST);
        r.requested = Some(addr);
        r.server = Some(server);
        self.send(&r, Ipv4Addr::BROADCAST, None);
        self.backoff(now);
    }

    fn send_reboot_request(&mut self, now: Instant) {
        let Some(l) = &self.lease else { return };
        let mut r = self.request(DHCPREQUEST);
        r.requested = Some(l.addr);
        self.send(&r, Ipv4Addr::BROADCAST, None);
        self.backoff(now);
    }

    /// RENEWING (unicast to the server) or REBINDING (broadcast): `ciaddr` is our address and
    /// neither address option is sent. The next try is halfway to `until`, a minute at least.
    fn send_extend(&mut self, now: Instant, until: Option<Instant>) {
        let Some(l) = &self.lease else { return };
        let mut r = self.request(DHCPREQUEST);
        r.ciaddr = l.addr;
        let to = if self.state == State::Renewing { l.server } else { Ipv4Addr::BROADCAST };
        self.send(&r, to, None);
        let half = until.map_or(MIN_RENEW_INTERVAL, |u| u.saturating_duration_since(now) / 2);
        self.next_send = now + half.max(MIN_RENEW_INTERVAL);
        if let Some(u) = until {
            self.next_send = self.next_send.min(u);
        }
    }

    fn deadlines(&mut self, l: &Lease, now: Instant, wall: i64) {
        let at = |t: i64| -> Option<Instant> {
            if t == i64::MAX {
                return None;
            }
            now.checked_add(Duration::from_secs(t.saturating_sub(wall).max(0) as u64))
        };
        self.t1_at = at(l.renew);
        self.t2_at = at(l.rebind);
        self.expire_at = at(l.expire);
    }

    /// Back to INIT, after a wait that doubles with each refusal.
    fn restart(&mut self, now: Instant, after_nak: bool) {
        self.state = State::Init;
        self.offer = None;
        if after_nak {
            self.init_at = now + self.nak_wait;
            self.nak_wait = (self.nak_wait * 2).clamp(Duration::from_secs(1), Duration::from_secs(60));
        } else {
            self.init_at = now;
        }
    }

    /// Takes away what the lease gave: the address (if it's still the lease's) and the default
    /// route (if it's still ours). `resolv.conf` stays, as in FreeBSD.
    fn unconfigure(&mut self) {
        let Some(l) = self.lease.clone() else { return };
        if self.net.addr(&self.ifname).ok().flatten() == Some(l.addr) {
            match self.net.set_addr(&self.ifname, Ipv4Addr::UNSPECIFIED) {
                Ok(()) => info(&format!("{}: removed address {}", self.ifname, l.addr)),
                Err(e) => warn(&format!("{}: removing {}: {}", self.ifname, l.addr, strerror(&e.err))),
            }
        }
        if let Some(g) = self.our_gateway.take() {
            if gateway::get().ok().flatten() == Some(g) {
                if let Err(e) = gateway::set(None) {
                    warn(&format!("removing the default route: {}", strerror(&e)));
                }
            }
        }
    }

    /// Puts a lease into effect. `Err` when the address couldn't be set.
    fn apply(&mut self, l: &Lease) -> Result<(), String> {
        let ifn = &self.ifname;
        let e = |what: &str, err: ifnet::Error| format!("{ifn}: {what}: {}", strerror(&err.err));
        let cur = self.net.addr(ifn).map_err(|x| e("SIOCGIFADDR", x))?;
        let cur_mask = if cur.is_some() { self.net.netmask(ifn).ok() } else { None };
        if cur != Some(l.addr) || cur_mask != Some(l.mask) {
            self.net.set_addr(ifn, l.addr).map_err(|x| e("SIOCSIFADDR", x))?;
            self.net.set_netmask(ifn, l.mask).map_err(|x| e("SIOCSIFNETMASK", x))?;
        }
        if let Ok(f) = self.net.flags(ifn) {
            if f & ifnet::IFF_UP == 0 {
                let _ = self.net.set_flags(ifn, f | ifnet::IFF_UP);
            }
        }
        match l.router() {
            Some(g) => match gateway::get() {
                Ok(cur) if cur == Some(g) => self.our_gateway = Some(g),
                Ok(_) => match gateway::set(Some(g)) {
                    Ok(()) => self.our_gateway = Some(g),
                    Err(err) => warn(&format!("setting the default route to {g}: {}", strerror(&err))),
                },
                Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                    static SAID: AtomicBool = AtomicBool::new(false);
                    if !SAID.swap(true, Ordering::Relaxed) {
                        warn(&format!("can't set the default route to {g}: {} doesn't exist", gateway::NAME));
                    }
                }
                Err(err) => warn(&format!("{}: {}", gateway::NAME, strerror(&err))),
            },
            None => {
                if let Some(old) = self.our_gateway.take() {
                    if gateway::get().ok().flatten() == Some(old) {
                        let _ = gateway::set(None);
                    }
                }
            }
        }
        if let Some(text) = lease::resolv_conf(l) {
            if std::fs::read_to_string(&self.resolv_conf).ok().as_deref() != Some(text.as_str()) {
                if let Err(err) = net::write_atomic(&self.resolv_conf, text.as_bytes(), 0o644) {
                    warn(&format!("{}: {}", self.resolv_conf, strerror(&err)));
                }
            }
        }
        if let Err(err) = net::write_atomic(&self.lease_file, l.render().as_bytes(), 0o644) {
            warn(&format!("{}: {}", self.lease_file, strerror(&err)));
        }
        Ok(())
    }

    fn bind(&mut self, r: &packet::Reply, now: Instant) {
        let wall = wall_now();
        let mut notes = Vec::new();
        let l = match Lease::from_ack(&self.ifname, r, wall, &mut notes) {
            Ok(l) => l,
            Err(why) => {
                warn(&format!("ignoring DHCPACK from {}: {why}", r.server_id.unwrap_or(Ipv4Addr::UNSPECIFIED)));
                return;
            }
        };
        info(&format!("DHCPACK from {}", l.server));
        for n in &notes {
            warn(n);
        }
        // A different address than before: the old one goes first.
        if self.lease.as_ref().is_some_and(|old| old.addr != l.addr) {
            self.unconfigure();
        }
        if let Err(m) = self.apply(&l) {
            warn(&m);
            self.lease = Some(l);
            self.unconfigure();
            self.lease = None;
            self.restart(now, true);
            return;
        }
        self.deadlines(&l, now, wall);
        if l.t1 == lease::INFINITE {
            info(&format!("bound to {} -- infinite lease.", l.addr));
        } else {
            info(&format!("bound to {} -- renewal in {} seconds.", l.addr, l.t1));
        }
        self.lease = Some(l);
        self.state = State::Bound;
        self.offer = None;
        self.nak_wait = Duration::from_secs(1);
        if self.detach_at.is_some() {
            self.detach();
        }
    }

    fn detach(&mut self) {
        self.detach_at = None;
        ECHO.store(false, Ordering::Relaxed);
        daemonize();
        if let Some(f) = self.pidfile.as_mut() {
            let _ = f.set_len(0);
            let _ = writeln!(f, "{}", std::process::id());
        }
    }

    fn on_packet(&mut self, buf: &[u8], from: Ipv4Addr, port: u16, now: Instant) {
        if port != net::SERVER_PORT {
            debug(&format!("ignoring a datagram from {from} port {port}"));
            return;
        }
        let r = match packet::parse(buf) {
            Ok(r) => r,
            Err(why) => {
                debug(&format!("ignoring a message from {from}: {why}"));
                return;
            }
        };
        if r.xid != self.xid || r.chaddr != self.mac {
            debug(&format!("ignoring {} from {from}: not ours", packet::type_name(r.kind)));
            return;
        }
        let server = r.server_id;
        let nak = |s: &str| {
            let why = r.message.as_deref().map(|m| format!(" ({m})")).unwrap_or_default();
            info(&format!("DHCPNAK from {}{why}{s}", server.unwrap_or(from)));
        };
        match (self.state, r.kind) {
            (State::Selecting, DHCPOFFER) => {
                if let Err(why) = Lease::from_ack(&self.ifname, &r, 0, &mut Vec::new()) {
                    debug(&format!("ignoring DHCPOFFER from {from}: {why}"));
                    return;
                }
                let server = server.unwrap();
                info(&format!("DHCPOFFER from {server}"));
                self.offer = Some((r.yiaddr, server));
                self.state = State::Requesting;
                self.tries = 0;
                self.interval = FIRST_INTERVAL;
                self.send_selecting_request(now);
            }
            (State::Requesting, DHCPACK) if server == self.offer.map(|o| o.1) => self.bind(&r, now),
            (State::Requesting, DHCPNAK) if server.is_none() || server == self.offer.map(|o| o.1) => {
                nak("");
                self.restart(now, true);
            }
            (State::Rebooting, DHCPACK) => self.bind(&r, now),
            (State::Rebooting, DHCPNAK) => {
                nak("");
                // The saved lease is no good here: forget it.
                self.lease = None;
                let _ = std::fs::remove_file(&self.lease_file);
                self.restart(now, true);
            }
            (State::Renewing, DHCPACK) if server.is_none() || server == self.lease.as_ref().map(|l| l.server) => {
                self.bind(&r, now)
            }
            (State::Rebinding, DHCPACK) => self.bind(&r, now),
            (State::Renewing, DHCPNAK) if server.is_none() || server == self.lease.as_ref().map(|l| l.server) => {
                nak("; lease lost");
                self.unconfigure();
                self.lease = None;
                self.restart(now, true);
            }
            (State::Rebinding, DHCPNAK) => {
                nak("; lease lost");
                self.unconfigure();
                self.lease = None;
                self.restart(now, true);
            }
            _ => debug(&format!("ignoring {} from {from} in state {:?}", packet::type_name(r.kind), self.state)),
        }
    }

    /// Does what is due at `now`.
    fn tick(&mut self, now: Instant) {
        if self.detach_at.is_some_and(|d| now >= d) && self.state != State::Bound {
            info("No working leases in persistent database - sleeping.");
            self.detach();
        }
        let due = |t: Option<Instant>| t.is_some_and(|t| now >= t);
        match self.state {
            State::Init if now >= self.init_at => {
                self.new_exchange(now);
                self.state = State::Selecting;
                self.send_discover(now);
            }
            State::Selecting if now >= self.next_send => self.send_discover(now),
            State::Requesting if now >= self.next_send => {
                if self.tries >= REQUEST_TRIES {
                    info("no DHCPACK received; starting over");
                    self.restart(now, false);
                } else {
                    self.send_selecting_request(now);
                }
            }
            State::Rebooting if due(self.expire_at) || (now >= self.next_send && self.tries >= REBOOT_TRIES) => {
                // Not confirmed: ask from scratch, the old address as a hint.
                self.restart(now, false);
            }
            State::Rebooting if now >= self.next_send => self.send_reboot_request(now),
            State::Bound if due(self.t1_at) => {
                self.state = State::Renewing;
                self.new_exchange(now);
            }
            State::Renewing if due(self.t2_at) => {
                self.state = State::Rebinding;
                self.new_exchange(now);
            }
            State::Renewing if now >= self.next_send => self.send_extend(now, self.t2_at),
            State::Rebinding if due(self.expire_at) => {
                info(&format!("lease on {} expired", self.ifname));
                self.unconfigure();
                self.restart(now, false);
            }
            State::Rebinding if now >= self.next_send => self.send_extend(now, self.expire_at),
            _ => {}
        }
    }

    /// When `tick` next has something to do (`None`: only a packet or a signal can matter).
    fn next_deadline(&self) -> Option<Instant> {
        let t = match self.state {
            State::Init => Some(self.init_at),
            State::Selecting | State::Requesting => Some(self.next_send),
            State::Rebooting => Some(self.expire_at.map_or(self.next_send, |e| e.min(self.next_send))),
            State::Bound => self.t1_at,
            State::Renewing => Some(self.t2_at.map_or(self.next_send, |t| t.min(self.next_send))),
            State::Rebinding => Some(self.expire_at.map_or(self.next_send, |t| t.min(self.next_send))),
        };
        match (t, self.detach_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    fn release(&mut self) {
        let Some(l) = self.lease.clone() else { return };
        if !matches!(self.state, State::Bound | State::Renewing | State::Rebinding) {
            return;
        }
        self.xid = random_u32();
        let mut r = self.request(DHCPRELEASE);
        r.ciaddr = l.addr;
        r.server = Some(l.server);
        r.secs = 0;
        self.send(&r, l.server, None);
        self.unconfigure();
        let _ = std::fs::remove_file(&self.lease_file);
    }
}

/// Into the background: a session of its own, `/` as its directory, standard descriptors on
/// `/dev/null`.
fn daemonize() {
    // SAFETY: single-threaded, so fork is safe; the parent only exits.
    unsafe {
        match libc::fork() {
            -1 => {
                log(libc::LOG_ERR, &format!("fork: {}", io::Error::last_os_error()));
                return;
            }
            0 => {}
            _ => libc::_exit(0),
        }
        libc::setsid();
        libc::chdir(c"/".as_ptr());
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            for fd in 0..3 {
                libc::dup2(null, fd);
            }
            if null > 2 {
                libc::close(null);
            }
        }
    }
}

/// Opens and locks the pid file, as FreeBSD's `pidfile_open(3)`: a second client for the same
/// interface finds it locked and exits.
fn lock_pidfile(path: &str) -> Result<File, String> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            let _ = std::fs::DirBuilder::new().recursive(true).mode(0o755).create(dir);
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{path}: {}", strerror(&e)))?;
    // SAFETY: a valid descriptor.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            let pid = std::fs::read_to_string(path).unwrap_or_default();
            return Err(format!("already running, pid: {}.", pid.trim()));
        }
        return Err(format!("{path}: {}", strerror(&e)));
    }
    Ok(file)
}

use std::os::unix::fs::DirBuilderExt;

fn usage() -> ExitCode {
    eprintln!("usage: dhclient [-bdrv] [-l leasefile] [-p pidfile] interface");
    ExitCode::from(1)
}

fn parse_args(args: &[String]) -> Result<Opts, ()> {
    let (mut fg, mut bg, mut rel) = (false, false, false);
    let (mut lf, mut pf) = (None, None);
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i].len() > 1 {
        if args[i] == "--" {
            i += 1;
            break;
        }
        let a = &args[i];
        let mut chars = a[1..].char_indices();
        while let Some((at, c)) = chars.next() {
            match c {
                'b' => bg = true,
                'd' => fg = true,
                'r' => rel = true,
                'v' => VERBOSE.store(true, Ordering::Relaxed),
                'l' | 'p' => {
                    let rest = &a[1 + at + 1..];
                    let v = if !rest.is_empty() {
                        rest.to_string()
                    } else {
                        i += 1;
                        args.get(i).cloned().ok_or(())?
                    };
                    if c == 'l' { lf = Some(v) } else { pf = Some(v) }
                    break;
                }
                _ => {
                    eprintln!("dhclient: illegal option -- {c}");
                    return Err(());
                }
            }
        }
        i += 1;
    }
    let [ifname] = &args[i..] else { return Err(()) };
    if ifname.is_empty() || ifname.len() >= ifnet::IFNAMSIZ || !ifname.bytes().all(|c| c.is_ascii_alphanumeric()) {
        eprintln!("dhclient: {ifname}: no such interface");
        return Err(());
    }
    Ok(Opts {
        foreground: fg,
        background: bg,
        release: rel,
        lease_file: lf.unwrap_or_else(|| format!("{LEASE_DIR}/dhclient.leases.{ifname}")),
        pid_file: pf.unwrap_or_else(|| format!("{PIDFILE_DIR}/dhclient.{ifname}.pid")),
        ifname: ifname.clone(),
    })
}

/// Where `resolv.conf` is: always `/etc/resolv.conf` on OxideBSD; a host test build may point
/// it elsewhere with `DHCLIENT_RESOLV_CONF`.
fn resolv_conf_path() -> String {
    #[cfg(not(target_os = "oxidebsd"))]
    if let Ok(p) = std::env::var("DHCLIENT_RESOLV_CONF") {
        return p;
    }
    RESOLV_CONF.to_string()
}

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Ok(o) = parse_args(&args) else { return usage() };
    // SAFETY: geteuid can't fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("dhclient: must be root");
        return ExitCode::from(1);
    }
    // SAFETY: umask(2) can't fail; openlog keeps a pointer to a static string.
    unsafe {
        libc::umask(0o022);
        libc::openlog(c"dhclient".as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, libc::LOG_DAEMON);
    }
    let net = match ifnet::Ifnet::open() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("dhclient: socket: {}", strerror(&e));
            return ExitCode::from(1);
        }
    };
    let flags = match net.flags(&o.ifname) {
        Ok(f) => f,
        Err(e) if e.no_such_interface() => {
            eprintln!("dhclient: {}: no such interface", o.ifname);
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("dhclient: {}: {}: {}", o.ifname, ifnet::request_name(e.req), strerror(&e.err));
            return ExitCode::from(1);
        }
    };
    let mac = match net.ether(&o.ifname) {
        Ok(Some(m)) => m,
        Ok(None) => {
            eprintln!("dhclient: {}: not an Ethernet interface", o.ifname);
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("dhclient: {}: SIOCGIFHWADDR: {}", o.ifname, strerror(&e.err));
            return ExitCode::from(1);
        }
    };
    let pidfile = match lock_pidfile(&o.pid_file) {
        Ok(f) => f,
        Err(m) => {
            eprintln!("dhclient: {m}");
            return ExitCode::from(1);
        }
    };
    if flags & ifnet::IFF_UP == 0 {
        if let Err(e) = net.set_flags(&o.ifname, flags | ifnet::IFF_UP) {
            eprintln!("dhclient: {}: SIOCSIFFLAGS: {}", o.ifname, strerror(&e.err));
            let _ = std::fs::remove_file(&o.pid_file);
            return ExitCode::from(1);
        }
    }
    let sock = match net::Socket::open(&o.ifname) {
        Ok(s) => s,
        Err((what, e)) => {
            eprintln!("dhclient: {what}: {}", strerror(&e));
            let _ = std::fs::remove_file(&o.pid_file);
            return ExitCode::from(1);
        }
    };
    if let Some(dir) = std::path::Path::new(&o.lease_file).parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            let _ = std::fs::DirBuilder::new().recursive(true).mode(0o755).create(dir);
        }
    }

    // The signal pipe: a handler writes a byte, which wakes poll(2).
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` has room for two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        eprintln!("dhclient: pipe: {}", strerror(&io::Error::last_os_error()));
        return ExitCode::from(1);
    }
    SIG_PIPE.store(fds[1], Ordering::Relaxed);
    // SAFETY: a handler that only stores and writes; no SA_RESTART, so poll returns EINTR.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaction(s, &sa, std::ptr::null_mut());
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let now = Instant::now();
    let mut c = Client {
        ifname: o.ifname.clone(),
        mac,
        sock,
        net,
        lease_file: o.lease_file.clone(),
        resolv_conf: resolv_conf_path(),
        state: State::Init,
        xid: 0,
        began: now,
        tries: 0,
        interval: FIRST_INTERVAL,
        next_send: now,
        init_at: now,
        nak_wait: Duration::from_secs(1),
        offer: None,
        lease: None,
        t1_at: None,
        t2_at: None,
        expire_at: None,
        our_gateway: None,
        detach_at: None,
        pidfile: Some(pidfile),
    };
    // A saved lease still good: INIT-REBOOT.
    let wall = wall_now();
    if let Some(l) = std::fs::read_to_string(&o.lease_file).ok().and_then(|t| Lease::parse(&t, &o.ifname)) {
        if l.expire > wall {
            debug(&format!("trying the saved lease for {}", l.addr));
            c.deadlines(&l, now, wall);
            c.lease = Some(l);
            c.state = State::Rebooting;
            c.new_exchange(now);
        } else {
            // Expired: a hint for DISCOVER only.
            c.lease = Some(l);
        }
    }
    if o.foreground {
        if let Some(f) = c.pidfile.as_mut() {
            let _ = f.set_len(0);
            let _ = writeln!(f, "{}", std::process::id());
        }
    } else if o.background {
        c.detach();
    } else {
        c.detach_at = Some(now + DETACH_AFTER);
    }

    let mut buf = vec![0u8; packet::MAX_LEN * 2];
    while SIGNO.load(Ordering::Relaxed) == 0 {
        c.tick(Instant::now());
        let timeout = c.next_deadline().map_or(-1, |d| {
            let ms = d.saturating_duration_since(Instant::now()).as_millis();
            // Round up, so a deadline isn't polled for in a tight loop just short of it.
            (ms + 1).min(i32::MAX as u128) as i32
        });
        let mut pfd = [
            libc::pollfd { fd: c.sock.raw(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: fds[0], events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: two pollfds.
        let n = unsafe { libc::poll(pfd.as_mut_ptr(), 2, timeout) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log(libc::LOG_ERR, &format!("poll: {}", strerror(&e)));
            break;
        }
        if pfd[0].revents & (libc::POLLIN | libc::POLLERR) != 0 {
            for _ in 0..RECV_BURST {
                match c.sock.recv(&mut buf) {
                    Ok(Some((0, from, _))) => debug(&format!("ignoring an oversized datagram from {from}")),
                    Ok(Some((len, from, port))) => {
                        let p = buf[..len].to_vec();
                        c.on_packet(&p, from, port, Instant::now());
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug(&format!("recvfrom: {}", strerror(&e)));
                        break;
                    }
                }
            }
        }
        if pfd[1].revents & libc::POLLIN != 0 {
            let mut b = [0u8; 16];
            // SAFETY: draining our own pipe into a local buffer.
            while unsafe { libc::read(fds[0], b.as_mut_ptr().cast(), b.len()) } > 0 {}
        }
    }
    let sig = SIGNO.load(Ordering::Relaxed);
    if o.release {
        c.release();
    }
    if sig != 0 {
        info(&format!("exiting on signal {sig}"));
    }
    let _ = std::fs::remove_file(&o.pid_file);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Result<Opts, ()> {
        parse_args(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn options() {
        let o = args("rl0").unwrap();
        assert_eq!(o.lease_file, "/var/db/dhclient.leases.rl0");
        assert_eq!(o.pid_file, "/var/run/dhclient/dhclient.rl0.pid");
        assert!(!o.foreground && !o.background && !o.release);
        let o = args("-dv -l /tmp/l -p/tmp/p rl0").unwrap();
        assert!(o.foreground);
        assert_eq!((o.lease_file.as_str(), o.pid_file.as_str()), ("/tmp/l", "/tmp/p"));
        assert!(args("").is_err());
        assert!(args("-x rl0").is_err());
        assert!(args("rl0 rl1").is_err());
        assert!(args("../etc").is_err());
        assert!(args("-l").is_err());
    }

    #[test]
    fn jitter_bounds() {
        for _ in 0..200 {
            let j = jitter(Duration::from_secs(4));
            assert!(j >= Duration::from_secs(3) && j <= Duration::from_secs(5));
            assert!(jitter(Duration::from_secs(0)) >= Duration::from_secs(1));
        }
    }
}
