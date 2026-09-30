//! syslog over TCP (RFC 6587) and TLS (RFC 5425), `SYSLOG.md` §8.3-8.5, driven by the daemon's one
//! `poll(2)` loop: every socket is non-blocking, and each connection is a state machine that says
//! which events it waits for (`interest`) and advances when they come (`ready`). TLS is OpenSSL's,
//! whose `WANT_READ`/`WANT_WRITE` say which way a handshake, read or write is blocked.
//!
//! Sending ([`Sender`], one per `@@host` or `@[host]` action): messages are framed by octet
//! counting (`LENGTH SP MESSAGE`) and queued, up to 1024 messages or 1 MiB, the oldest dropped
//! beyond that; the connection is (re)made in the background, retried after 10 seconds, doubling
//! to 10 minutes, and the queue drains once it's up.
//!
//! Receiving ([`Listener`], [`Inbound`]): `tcp_server` and `tls_server` listeners, each accepted
//! connection read as octet-counted or newline-terminated messages (`take_frames`).

use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::{
    ErrorCode, HandshakeError, MidHandshakeSslStream, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslMode,
    SslStream, SslVerifyMode, SslVersion,
};
use openssl::x509::store::X509Lookup;
use openssl::x509::{X509, X509Ref, X509StoreContextRef};

use crate::conf::{NetOptions, PeerCheck};

/// What a sender queues at most while its connection is down (`SYSLOG.md` §8.5).
const QUEUE_MESSAGES: usize = 1024;
const QUEUE_BYTES: usize = 1 << 20;
/// Reconnection delays, in seconds: the first, doubling up to the last.
const RETRY_FIRST: i64 = 10;
const RETRY_MAX: i64 = 600;
/// The longest octet-counted message accepted; a longer count ends the connection.
const MAX_FRAME: usize = 64 * 1024;

pub const POLLIN: i16 = libc::POLLIN;
pub const POLLOUT: i16 = libc::POLLOUT;

/// One message framed for a stream: `LENGTH SP MESSAGE`.
pub fn frame(message: &str) -> Vec<u8> {
    let mut f = format!("{} ", message.len()).into_bytes();
    f.extend_from_slice(message.as_bytes());
    f
}

/// Takes the complete messages at the start of `buf` (RFC 6587): octet-counted when it starts
/// with a digit, else ended by a newline. A newline-framed message longer than `max_line` is
/// taken in pieces. `Err` for a count too large to be a message: the peer isn't speaking syslog.
pub fn take_frames(buf: &mut Vec<u8>, max_line: usize) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    loop {
        let start = buf.iter().position(|&b| b != b'\n' && b != b'\r' && b != 0).unwrap_or(buf.len());
        buf.drain(..start);
        if buf.is_empty() {
            return Ok(out);
        }
        if buf[0].is_ascii_digit() {
            let digits = buf.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == buf.len() {
                if digits > 7 {
                    return Err("bad octet count".into());
                }
                return Ok(out); // the count isn't all here yet
            }
            if buf[digits] != b' ' || digits > 7 {
                return Err("bad octet count".into());
            }
            let len: usize = std::str::from_utf8(&buf[..digits]).unwrap().parse().unwrap();
            if len > MAX_FRAME {
                return Err(format!("message of {len} bytes"));
            }
            if buf.len() < digits + 1 + len {
                return Ok(out);
            }
            let msg: Vec<u8> = buf[digits + 1..digits + 1 + len].to_vec();
            buf.drain(..digits + 1 + len);
            out.push(msg);
            continue;
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(nl) => {
                let msg: Vec<u8> = buf.drain(..=nl).take(nl).collect();
                out.push(msg);
            }
            None if buf.len() > max_line => out.push(buf.drain(..max_line).collect()),
            None => return Ok(out),
        }
    }
}

/// A connected stream, plain or TLS.
enum Stream {
    Plain(TcpStream),
    Tls(SslStream<TcpStream>),
}

/// How a read or write on a stream ended when it didn't move data.
enum Blocked {
    /// Waiting for these `poll` events.
    On(i16),
    /// The peer closed the connection.
    Closed,
    Error(String),
}

impl Stream {
    fn fd(&self) -> RawFd {
        match self {
            Stream::Plain(s) => s.as_raw_fd(),
            Stream::Tls(s) => s.get_ref().as_raw_fd(),
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Blocked> {
        match self {
            Stream::Plain(s) => match s.write(buf) {
                Ok(0) => Err(Blocked::Closed),
                Ok(n) => Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => Err(Blocked::On(POLLOUT)),
                Err(e) => Err(Blocked::Error(e.to_string())),
            },
            Stream::Tls(s) => s.ssl_write(buf).map_err(tls_blocked),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Blocked> {
        match self {
            Stream::Plain(s) => match s.read(buf) {
                Ok(0) => Err(Blocked::Closed),
                Ok(n) => Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => Err(Blocked::On(POLLIN)),
                Err(e) => Err(Blocked::Error(e.to_string())),
            },
            Stream::Tls(s) => match s.ssl_read(buf) {
                Ok(0) => Err(Blocked::Closed),
                Ok(n) => Ok(n),
                Err(e) => Err(tls_blocked(e)),
            },
        }
    }
}

fn tls_blocked(e: openssl::ssl::Error) -> Blocked {
    match e.code() {
        ErrorCode::WANT_READ => Blocked::On(POLLIN),
        ErrorCode::WANT_WRITE => Blocked::On(POLLOUT),
        ErrorCode::ZERO_RETURN => Blocked::Closed,
        _ => match e.io_error() {
            Some(io) if io.kind() == ErrorKind::WouldBlock => Blocked::On(POLLIN),
            _ => Blocked::Error(e.to_string()),
        },
    }
}

/// The events a TLS handshake waits for.
fn handshake_wants(mid: &MidHandshakeSslStream<TcpStream>) -> i16 {
    if mid.error().code() == ErrorCode::WANT_WRITE { POLLOUT } else { POLLIN }
}

/// Starts a non-blocking connection to `addr`: `connect(2)` on a non-blocking socket, which
/// reports `EINPROGRESS` and completes later.
fn start_connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let SocketAddr::V4(v4) = addr else {
        return Err(io::Error::new(ErrorKind::Unsupported, "no IPv6"));
    };
    // SAFETY: a new socket, owned by the TcpStream once made; the sockaddr_in is initialized.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = TcpStream::from_raw_fd(fd);
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_port = v4.port().to_be();
        sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
        let r = libc::connect(fd, (&sin as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as libc::socklen_t);
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(e);
            }
        }
        Ok(stream)
    }
}

/// Whether `cert` is one a check lets through on its own, whatever vouches for it: a pinned
/// fingerprint (SHA-256 of its DER) or an identical pinned certificate.
fn pinned(cert: &X509Ref, fingerprints: &[Vec<u8>], certs: &[Vec<u8>]) -> bool {
    let fp = cert.digest(MessageDigest::sha256()).map(|d| d.to_vec()).unwrap_or_default();
    let der = cert.to_der().unwrap_or_default();
    fingerprints.iter().any(|f| *f == fp) || certs.iter().any(|c| *c == der)
}

/// The chain's leaf certificate: what's pinned is always the peer's own.
fn leaf(ctx: &X509StoreContextRef) -> Option<X509> {
    ctx.chain().and_then(|c| c.get(0)).map(|c| c.to_owned()).or_else(|| ctx.current_cert().map(|c| c.to_owned()))
}

/// Whether `cert`'s common name or one of its `subjectAltName` DNS names or addresses is `name`
/// (ASCII case ignored).
fn has_name(cert: &X509Ref, name: &str) -> bool {
    let cn = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .any(|e| e.data().to_string().is_ok_and(|s| s.eq_ignore_ascii_case(name)));
    let alt = cert.subject_alt_names().is_some_and(|names| {
        names.iter().any(|n| {
            n.dnsname().is_some_and(|d| d.eq_ignore_ascii_case(name))
                || n.ipaddress().is_some_and(|ip| match (ip.len(), name.parse::<std::net::IpAddr>()) {
                    (4, Ok(std::net::IpAddr::V4(v4))) => ip == v4.octets(),
                    _ => false,
                })
        })
    });
    cn || alt
}

/// Reads the certificates in PEM files (`cert=`, `tls_allow_clientcerts`), as DER.
fn load_certs(paths: &[&Path]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    for p in paths {
        let pem = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let certs = X509::stack_from_pem(&pem).map_err(|e| format!("{}: {e}", p.display()))?;
        if certs.is_empty() {
            return Err(format!("{}: no certificate", p.display()));
        }
        out.extend(certs.iter().filter_map(|c| c.to_der().ok()));
    }
    Ok(out)
}

/// Adds the configured authorities (`tls_ca`, `tls_cadir`) to a context's store; with neither,
/// OpenSSL's defaults (`/etc/ssl/cert.pem`, `/etc/ssl/certs`, certctl(8)).
fn add_authorities(b: &mut openssl::ssl::SslContextBuilder, net: &NetOptions) -> Result<(), String> {
    if net.tls_ca.is_none() && net.tls_cadir.is_none() {
        return b.set_default_verify_paths().map_err(|e| e.to_string());
    }
    if let Some(ca) = &net.tls_ca {
        b.set_ca_file(ca).map_err(|e| format!("tls_ca {}: {e}", ca.display()))?;
    }
    if let Some(dir) = &net.tls_cadir {
        let lookup = b.cert_store_mut().add_lookup(X509Lookup::hash_dir()).map_err(|e| e.to_string())?;
        lookup
            .add_dir(dir.to_str().unwrap_or(""), SslFiletype::PEM)
            .map_err(|e| format!("tls_cadir {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// This host's key and certificate (`tls_keyfile`, `tls_certfile`), if configured.
fn add_identity(b: &mut openssl::ssl::SslContextBuilder, net: &NetOptions) -> Result<bool, String> {
    let (Some(key), Some(cert)) = (&net.tls_keyfile, &net.tls_certfile) else { return Ok(false) };
    b.set_certificate_chain_file(cert).map_err(|e| format!("tls_certfile {}: {e}", cert.display()))?;
    b.set_private_key_file(key, SslFiletype::PEM).map_err(|e| format!("tls_keyfile {}: {e}", key.display()))?;
    b.check_private_key().map_err(|e| format!("{}: key doesn't match the certificate: {e}", key.display()))?;
    Ok(true)
}

/// The client side of a TLS action: verification by `peer`'s options (`SYSLOG.md` §8.4). Returns
/// the connector and whether OpenSSL should check the host name (neither pinned nor `subject=`).
fn connector(peer: &PeerCheck, net: &NetOptions) -> Result<(SslConnector, bool), String> {
    let mut b = SslConnector::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2)).map_err(|e| e.to_string())?;
    b.set_mode(SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
    add_authorities(&mut b, net)?;
    add_identity(&mut b, net)?;
    let pinned_certs = match &peer.cert {
        Some(p) => load_certs(&[p.as_path()])?,
        None => Vec::new(),
    };
    let fingerprints: Vec<Vec<u8>> = peer.fingerprint.iter().cloned().collect();
    let check_host = if peer.no_verify {
        b.set_verify(SslVerifyMode::NONE);
        false
    } else if !fingerprints.is_empty() || !pinned_certs.is_empty() {
        // Pinned: the peer's own certificate decides, not who vouches for it.
        b.set_verify_callback(SslVerifyMode::PEER, move |preverify, ctx| {
            preverify || leaf(ctx).is_some_and(|c| pinned(&c, &fingerprints, &pinned_certs))
        });
        false
    } else if let Some(subject) = peer.subject.clone() {
        // Vouched for, and named `subject` instead of the host name.
        b.set_verify_callback(SslVerifyMode::PEER, move |preverify, ctx| {
            preverify && (ctx.error_depth() != 0 || ctx.current_cert().is_some_and(|c| has_name(c, &subject)))
        });
        false
    } else {
        b.set_verify(SslVerifyMode::PEER);
        true
    };
    Ok((b.build(), check_host))
}

/// The server side: `tls_server`'s acceptor. With `tls_verify`, a client must present a
/// certificate the authorities vouch for, or one of `tls_allow_fingerprints` or
/// `tls_allow_clientcerts`.
pub fn acceptor(net: &NetOptions) -> Result<SslAcceptor, String> {
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).map_err(|e| e.to_string())?;
    b.set_min_proto_version(Some(SslVersion::TLS1_2)).map_err(|e| e.to_string())?;
    if !add_identity(&mut b, net)? {
        return Err("tls_server needs tls_keyfile and tls_certfile".into());
    }
    add_authorities(&mut b, net)?;
    if net.tls_verify {
        let fingerprints = net.tls_allow_fingerprints.clone();
        let paths: Vec<&Path> = net.tls_allow_clientcerts.iter().map(|p| p.as_path()).collect();
        let certs = load_certs(&paths)?;
        b.set_verify_callback(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT, move |preverify, ctx| {
            preverify || leaf(ctx).is_some_and(|c| pinned(&c, &fingerprints, &certs))
        });
    } else {
        b.set_verify(SslVerifyMode::NONE);
    }
    Ok(b.build())
}

/// `tls_gen_cert`: makes a key and a self-signed certificate for `host` at `tls_keyfile` and
/// `tls_certfile` when either is missing. Returns what it did, for the log.
pub fn generate_identity(net: &NetOptions, host: &str) -> Result<Option<String>, String> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::pkey::PKey;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509Builder, X509NameBuilder};
    let (Some(keyfile), Some(certfile)) = (&net.tls_keyfile, &net.tls_certfile) else { return Ok(None) };
    if !net.tls_gen_cert || (keyfile.exists() && certfile.exists()) {
        return Ok(None);
    }
    let e = |e: openssl::error::ErrorStack| e.to_string();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(e)?;
    let key = PKey::from_ec_key(EcKey::generate(&group).map_err(e)?).map_err(e)?;
    let mut name = X509NameBuilder::new().map_err(e)?;
    name.append_entry_by_nid(Nid::COMMONNAME, host).map_err(e)?;
    let name = name.build();
    let mut b = X509Builder::new().map_err(e)?;
    b.set_version(2).map_err(e)?;
    let mut serial = BigNum::new().map_err(e)?;
    serial.rand(64, MsbOption::MAYBE_ZERO, false).map_err(e)?;
    let serial = serial.to_asn1_integer().map_err(e)?;
    b.set_serial_number(&serial).map_err(e)?;
    b.set_subject_name(&name).map_err(e)?;
    b.set_issuer_name(&name).map_err(e)?;
    b.set_pubkey(&key).map_err(e)?;
    let (not_before, not_after) = (Asn1Time::days_from_now(0).map_err(e)?, Asn1Time::days_from_now(3650).map_err(e)?);
    b.set_not_before(&not_before).map_err(e)?;
    b.set_not_after(&not_after).map_err(e)?;
    let san = SubjectAlternativeName::new().dns(host).build(&b.x509v3_context(None, None)).map_err(e)?;
    b.append_extension(san).map_err(e)?;
    b.sign(&key, MessageDigest::sha256()).map_err(e)?;
    let cert = b.build();
    let write = |path: &Path, bytes: &[u8], mode: u32| -> Result<(), String> {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .and_then(|mut f| f.write_all(bytes))
            .map_err(|er| format!("{}: {er}", path.display()))
    };
    write(keyfile, &key.private_key_to_pem_pkcs8().map_err(e)?, 0o600)?;
    write(certfile, &cert.to_pem().map_err(e)?, 0o644)?;
    let fp = cert.digest(MessageDigest::sha256()).map_err(e)?;
    let hex: Vec<String> = fp.iter().map(|b| format!("{b:02X}")).collect();
    Ok(Some(format!("generated {} and {}, fingerprint SHA-256:{}", keyfile.display(), certfile.display(), hex.join(":"))))
}

enum Link {
    /// Not connected; try again at this time.
    Down { retry_at: i64 },
    Connecting(TcpStream),
    Handshake(MidHandshakeSslStream<TcpStream>),
    Up { stream: Stream, blocked: Option<i16> },
}

/// A TCP or TLS action's connection and queue.
pub struct Sender {
    /// How the action is named in log messages: `@@host:port`, `@[host]:port`.
    pub name: String,
    host: String,
    port: u16,
    tls: Option<(SslConnector, bool)>,
    link: Link,
    queue: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    /// Bytes of the queue's first frame already written.
    head_written: usize,
    dropped: u64,
    delay: i64,
    /// Set once a failure has been logged; cleared when the connection comes up.
    failure_logged: bool,
}

impl Sender {
    /// A TCP (`tls` `None`) or TLS sender. Connects as soon as `pump` runs.
    pub fn new(host: &str, port: u16, tls: Option<(&PeerCheck, &NetOptions)>) -> Result<Sender, String> {
        let (name, tls) = match tls {
            Some((peer, net)) => (format!("@[{host}]:{port}"), Some(connector(peer, net)?)),
            None => (format!("@@{host}:{port}"), None),
        };
        Ok(Sender {
            name,
            host: host.to_string(),
            port,
            tls,
            link: Link::Down { retry_at: 0 },
            queue: VecDeque::new(),
            queued_bytes: 0,
            head_written: 0,
            dropped: 0,
            delay: RETRY_FIRST,
            failure_logged: false,
        })
    }

    /// Queues a framed message, dropping the oldest when the queue is full, and sends what it can.
    pub fn send(&mut self, frame: Vec<u8>, now: i64) -> Vec<String> {
        while !self.queue.is_empty() && (self.queue.len() >= QUEUE_MESSAGES || self.queued_bytes + frame.len() > QUEUE_BYTES) {
            // A frame partly written stays: the rest of it has to follow.
            let victim = if self.head_written > 0 && self.queue.len() > 1 { 1 } else { 0 };
            if victim == 0 && self.head_written > 0 {
                break;
            }
            let f = self.queue.remove(victim).unwrap();
            self.queued_bytes -= f.len();
            self.dropped += 1;
        }
        self.queued_bytes += frame.len();
        self.queue.push_back(frame);
        self.pump(now, 0)
    }

    /// The descriptor and events to poll for, if any.
    pub fn interest(&self) -> Option<(RawFd, i16)> {
        match &self.link {
            Link::Down { .. } => None,
            Link::Connecting(s) => Some((s.as_raw_fd(), POLLOUT)),
            Link::Handshake(mid) => Some((mid.get_ref().as_raw_fd(), handshake_wants(mid))),
            // Always readable, to see the peer close; writable while there's something to send.
            Link::Up { stream, blocked } => {
                let want = blocked.unwrap_or(if self.queue.is_empty() { 0 } else { POLLOUT });
                Some((stream.fd(), POLLIN | want))
            }
        }
    }

    /// When the next reconnection is due, while the connection is down.
    pub fn due(&self) -> Option<i64> {
        match self.link {
            Link::Down { retry_at } => Some(retry_at),
            _ => None,
        }
    }

    /// Takes the connection down after a failure: logged once until it comes up again, retried
    /// after the current delay, which doubles.
    fn fail(&mut self, why: &str, now: i64, log: &mut Vec<String>) {
        if !self.failure_logged {
            log.push(format!("{}: {why}; retrying every {}s up to {}s", self.name, self.delay, RETRY_MAX));
            self.failure_logged = true;
        }
        self.link = Link::Down { retry_at: now + self.delay };
        self.delay = (self.delay * 2).min(RETRY_MAX);
        // A frame cut off by the failure is sent again whole.
        self.head_written = 0;
    }

    fn up(&mut self, stream: Stream, log: &mut Vec<String>) {
        self.link = Link::Up { stream, blocked: None };
        self.delay = RETRY_FIRST;
        if self.failure_logged {
            log.push(format!("{}: connected", self.name));
            self.failure_logged = false;
        }
        if self.dropped > 0 {
            log.push(format!("{}: {} messages dropped while the connection was down", self.name, self.dropped));
            self.dropped = 0;
        }
    }

    /// Advances the connection as far as it goes without blocking; `revents` is what `poll`
    /// reported for it (0 when called for another reason). Returns what to log.
    pub fn pump(&mut self, now: i64, revents: i16) -> Vec<String> {
        let mut log = Vec::new();
        loop {
            let link = std::mem::replace(&mut self.link, Link::Down { retry_at: 0 });
            match link {
                Link::Down { retry_at } => {
                    if now < retry_at {
                        self.link = Link::Down { retry_at };
                        return log;
                    }
                    let addr = (self.host.as_str(), self.port).to_socket_addrs().ok().and_then(|mut a| a.find(|a| a.is_ipv4()));
                    let Some(addr) = addr else {
                        self.fail(&format!("{}: host not found", self.host), now, &mut log);
                        return log;
                    };
                    match start_connect(addr) {
                        Ok(s) => self.link = Link::Connecting(s),
                        Err(e) => {
                            self.fail(&e.to_string(), now, &mut log);
                            return log;
                        }
                    }
                }
                Link::Connecting(s) => {
                    match s.take_error() {
                        Ok(Some(e)) | Err(e) => {
                            self.fail(&e.to_string(), now, &mut log);
                            return log;
                        }
                        Ok(None) => {}
                    }
                    if s.peer_addr().is_err() {
                        if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                            self.fail("connection refused", now, &mut log);
                        } else {
                            self.link = Link::Connecting(s);
                        }
                        return log;
                    }
                    match &self.tls {
                        None => self.up(Stream::Plain(s), &mut log),
                        Some((c, check_host)) => {
                            let config = match c.configure() {
                                Ok(cfg) => cfg.verify_hostname(*check_host),
                                Err(e) => {
                                    self.fail(&e.to_string(), now, &mut log);
                                    return log;
                                }
                            };
                            match config.connect(&self.host, s) {
                                Ok(tls) => self.up(Stream::Tls(tls), &mut log),
                                Err(HandshakeError::WouldBlock(mid)) => {
                                    self.link = Link::Handshake(mid);
                                    return log;
                                }
                                Err(e) => {
                                    self.fail(&handshake_failure(e), now, &mut log);
                                    return log;
                                }
                            }
                        }
                    }
                }
                Link::Handshake(mid) => match mid.handshake() {
                    Ok(tls) => self.up(Stream::Tls(tls), &mut log),
                    Err(HandshakeError::WouldBlock(mid)) => {
                        self.link = Link::Handshake(mid);
                        return log;
                    }
                    Err(e) => {
                        self.fail(&handshake_failure(e), now, &mut log);
                        return log;
                    }
                },
                Link::Up { mut stream, .. } => {
                    // Whatever the peer sends is read and ignored; its end of file ends the
                    // connection.
                    let mut scratch = [0u8; 512];
                    let read_blocked = loop {
                        match stream.read(&mut scratch) {
                            Ok(_) => continue,
                            Err(Blocked::On(ev)) => break Some(ev),
                            Err(Blocked::Closed) => {
                                self.fail("connection closed by the peer", now, &mut log);
                                return log;
                            }
                            Err(Blocked::Error(e)) => {
                                self.fail(&e, now, &mut log);
                                return log;
                            }
                        }
                    };
                    let mut blocked = None;
                    while let Some(head) = self.queue.front() {
                        match stream.write(&head[self.head_written..]) {
                            Ok(n) => {
                                self.head_written += n;
                                if self.head_written == head.len() {
                                    self.queued_bytes -= head.len();
                                    self.queue.pop_front();
                                    self.head_written = 0;
                                }
                            }
                            Err(Blocked::On(ev)) => {
                                blocked = Some(ev);
                                break;
                            }
                            Err(Blocked::Closed) => {
                                self.fail("connection closed by the peer", now, &mut log);
                                return log;
                            }
                            Err(Blocked::Error(e)) => {
                                self.fail(&e, now, &mut log);
                                return log;
                            }
                        }
                    }
                    // A TLS read that wants to write (a renegotiation) waits on that too.
                    let blocked = match (blocked, read_blocked) {
                        (Some(w), _) => Some(w),
                        (None, Some(POLLOUT)) => Some(POLLOUT),
                        _ => None,
                    };
                    self.link = Link::Up { stream, blocked };
                    return log;
                }
            }
        }
    }
}

fn handshake_failure(e: HandshakeError<TcpStream>) -> String {
    match e {
        HandshakeError::SetupFailure(s) => s.to_string(),
        HandshakeError::Failure(mid) => {
            let verify = mid.ssl().verify_result();
            if verify.as_raw() != 0 {
                format!("TLS: certificate not accepted: {}", verify.error_string())
            } else {
                format!("TLS: {}", mid.error())
            }
        }
        HandshakeError::WouldBlock(_) => "TLS handshake blocked".into(),
    }
}

/// A `tcp_server` or `tls_server` listening socket.
pub struct Listener {
    pub socket: TcpListener,
    pub tls: Option<std::sync::Arc<SslAcceptor>>,
}

impl Listener {
    /// Listens on `host` (all addresses when `None`) and `port`.
    pub fn bind(host: Option<&str>, port: u16, tls: Option<SslAcceptor>) -> io::Result<Listener> {
        let socket = TcpListener::bind((host.unwrap_or("0.0.0.0"), port))?;
        socket.set_nonblocking(true)?;
        Ok(Listener { socket, tls: tls.map(std::sync::Arc::new) })
    }

    /// The connections waiting to be accepted.
    pub fn accept(&self) -> Vec<(TcpStream, SocketAddr)> {
        let mut out = Vec::new();
        while let Ok((s, peer)) = self.socket.accept() {
            if s.set_nonblocking(true).is_ok() {
                out.push((s, peer));
            }
        }
        out
    }
}

enum InLink {
    Handshake(MidHandshakeSslStream<TcpStream>),
    Up(Stream),
}

/// An accepted connection sending messages.
pub struct Inbound {
    pub peer: SocketAddr,
    link: Option<InLink>,
    buf: Vec<u8>,
}

/// What reading an inbound connection gave.
pub enum Inflow {
    /// Messages, and whether the connection is still open.
    Messages(Vec<Vec<u8>>, bool),
    /// It ended with this failure, for the log (a TLS peer that wasn't accepted).
    Failed(String),
}

impl Inbound {
    pub fn new(stream: TcpStream, peer: SocketAddr, tls: Option<&SslAcceptor>) -> Result<Inbound, String> {
        let link = match tls {
            None => InLink::Up(Stream::Plain(stream)),
            Some(a) => match a.accept(stream) {
                Ok(s) => InLink::Up(Stream::Tls(s)),
                Err(HandshakeError::WouldBlock(mid)) => InLink::Handshake(mid),
                Err(e) => return Err(format!("TLS from {peer}: {}", handshake_failure(e))),
            },
        };
        Ok(Inbound { peer, link: Some(link), buf: Vec::new() })
    }

    pub fn interest(&self) -> (RawFd, i16) {
        match self.link.as_ref().unwrap() {
            InLink::Handshake(mid) => (mid.get_ref().as_raw_fd(), handshake_wants(mid)),
            InLink::Up(s) => (s.fd(), POLLIN),
        }
    }

    /// Advances the handshake or reads what's there.
    pub fn ready(&mut self, max_line: usize) -> Inflow {
        let link = self.link.take().unwrap();
        let mut stream = match link {
            InLink::Handshake(mid) => match mid.handshake() {
                Ok(s) => Stream::Tls(s),
                Err(HandshakeError::WouldBlock(mid)) => {
                    self.link = Some(InLink::Handshake(mid));
                    return Inflow::Messages(Vec::new(), true);
                }
                Err(e) => return Inflow::Failed(format!("TLS from {}: {}", self.peer, handshake_failure(e))),
            },
            InLink::Up(s) => s,
        };
        let mut chunk = [0u8; 4096];
        let mut open = true;
        loop {
            match stream.read(&mut chunk) {
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    if self.buf.len() > MAX_FRAME * 2 {
                        break;
                    }
                }
                Err(Blocked::On(_)) => break,
                Err(Blocked::Closed) | Err(Blocked::Error(_)) => {
                    open = false;
                    break;
                }
            }
        }
        let messages = match take_frames(&mut self.buf, max_line) {
            Ok(m) => m,
            Err(e) => return Inflow::Failed(format!("from {}: {e}", self.peer)),
        };
        if open {
            self.link = Some(InLink::Up(stream));
        }
        Inflow::Messages(messages, open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing() {
        assert_eq!(frame("<13>hi"), b"6 <13>hi");
        let mut buf = b"6 <13>hi11 <14>a b c d<15>newline\n\n<16>part".to_vec();
        let got = take_frames(&mut buf, 100).unwrap();
        assert_eq!(got, vec![b"<13>hi".to_vec(), b"<14>a b c d".to_vec(), b"<15>newline".to_vec()]);
        assert_eq!(buf, b"<16>part");
        // An octet count split across reads waits for the rest.
        let mut buf = b"11".to_vec();
        assert!(take_frames(&mut buf, 100).unwrap().is_empty());
        buf.extend_from_slice(b" <13>x y z w");
        assert_eq!(take_frames(&mut buf, 100).unwrap(), vec![b"<13>x y z w".to_vec()]);
        // Too long a newline-framed message comes in pieces; a silly count is an error.
        let mut buf = vec![b'<'; 250];
        assert_eq!(take_frames(&mut buf, 100).unwrap().len(), 2);
        assert!(take_frames(&mut b"99999999 x".to_vec(), 100).is_err());
        assert!(take_frames(&mut b"12x".to_vec(), 100).is_err());
    }
}
