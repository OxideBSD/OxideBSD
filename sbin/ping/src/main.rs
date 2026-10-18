//! `ping(8)`: sends ICMP echo requests to a host and reports its echo replies.
//!
//! ```text
//! ping [-afnoqv] [-c count] [-i wait] [-l preload] [-m ttl] [-p pattern] [-S src_addr]
//!      [-s packetsize] [-t timeout] [-W waittime] [-z tos] host
//! ```
//!
//! FreeBSD's IPv4 ping, its output included: a `PING` line, a line per reply (`icmp_seq`, `ttl`,
//! the round trip time, `(DUP!)` for a duplicate), and on the way out (the count reached, `-t`'s
//! timeout, or an interrupt) the statistics with min/avg/max/stddev. The round trip is timed from
//! a timestamp in the first 8 data bytes (none with `-s` below 8); the rest are `-p`'s pattern or
//! counting bytes, checked in each reply.
//!
//! OxideBSD's ICMP is a raw socket (`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`, the kernel's
//! `sys/netinet/icmp.rs`) that hands up every ICMP packet the host receives, IP header included,
//! so replies are picked by identifier, and the reply's TTL read from its header. Where a raw
//! socket isn't allowed (Linux without `CAP_NET_RAW`) an ICMP datagram socket is used instead:
//! the kernel then owns the identifier and strips the header, so no TTL is shown.
//!
//! Exit status: 0 if any reply came, 2 if none did, else a `sysexits(3)` value (64 for a bad
//! command line, 68 for an unknown host, 71 for a system error, 77 for an option only root may
//! use).

use std::ffi::{CStr, CString};
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

const EX_USAGE: u8 = 64;
const EX_NOHOST: u8 = 68;
const EX_OSERR: u8 = 71;
const EX_NOPERM: u8 = 77;

const ICMP_ECHOREPLY: u8 = 0;
const ICMP_ECHO: u8 = 8;
const ICMP_MINLEN: usize = 8;
/// The timestamp in the data: seconds and nanoseconds, 32 bits each, network order.
const TV_LEN: usize = 8;
const IP_MAXPACKET: usize = 65535;
const MAXDATA: usize = IP_MAXPACKET - 20 - ICMP_MINLEN;
const DEFDATALEN: usize = 56;
/// How long to wait for a reply once the last request is out with none received, in ms
/// (FreeBSD's `MAXWAIT`).
const MAXWAIT_MS: u64 = 10_000;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: ping [-afnoqv] [-c count] [-i wait] [-l preload] [-m ttl] [-p pattern]\n            \
         [-S src_addr] [-s packetsize] [-t timeout] [-W waittime] [-z tos] host"
    );
    ExitCode::from(EX_USAGE)
}

fn die(code: u8, msg: &str) -> ExitCode {
    eprintln!("ping: {msg}");
    ExitCode::from(code)
}

/// Monotonic time in nanoseconds.
fn mono() -> u64 {
    // SAFETY: clock_gettime fills ts.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// The Internet checksum (RFC 1071).
fn cksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn type_name(t: u8) -> &'static str {
    match t {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        4 => "Source Quench",
        5 => "Redirect",
        8 => "Echo Request",
        11 => "Time to live exceeded",
        12 => "Parameter problem",
        13 => "Timestamp",
        14 => "Timestamp Reply",
        _ => "Bad ICMP type",
    }
}

/// Resolves `host` to an IPv4 address and the name to show for it.
fn resolve(host: &str) -> Result<([u8; 4], String), String> {
    let c = CString::new(host).map_err(|_| format!("cannot resolve {host}: Unknown host"))?;
    // SAFETY: getaddrinfo with valid hints; the list is freed below.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_family = libc::AF_INET;
        hints.ai_socktype = libc::SOCK_RAW;
        hints.ai_flags = libc::AI_CANONNAME;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        let rc = libc::getaddrinfo(c.as_ptr(), std::ptr::null(), &hints, &mut res);
        if rc != 0 || res.is_null() {
            // hstrerror(3)'s words, as FreeBSD's ping gives them.
            let why = if rc == libc::EAI_AGAIN { "Host name lookup failure" } else { "Unknown host" };
            return Err(format!("cannot resolve {host}: {why}"));
        }
        let sin = &*((*res).ai_addr as *const libc::sockaddr_in);
        let ip = sin.sin_addr.s_addr.to_ne_bytes();
        let name = if (*res).ai_canonname.is_null() {
            host.to_string()
        } else {
            CStr::from_ptr((*res).ai_canonname).to_string_lossy().into_owned()
        };
        libc::freeaddrinfo(res);
        Ok((ip, name))
    }
}

fn ip_str(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn sockaddr(ip: [u8; 4]) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr.s_addr = u32::from_ne_bytes(ip);
    sa
}

/// A number option's value, or the usage error FreeBSD gives.
fn number<T: std::str::FromStr + PartialOrd>(v: &str, what: &str, lo: T, hi: T) -> Result<T, ExitCode> {
    match v.parse::<T>() {
        Ok(n) if n >= lo && n <= hi => Ok(n),
        _ => Err(die(EX_USAGE, &format!("invalid {what}: `{v}'"))),
    }
}

struct Stats {
    sent: u64,
    received: u64,
    repeats: u64,
    tmin: f64,
    tmax: f64,
    tsum: f64,
    tsumsq: f64,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // SAFETY: getuid has no preconditions.
    let root = unsafe { libc::getuid() } == 0;
    let (mut audible, mut flood, mut once, mut quiet, mut verbose) = (false, false, false, false, false);
    let mut count: u64 = 0;
    let mut interval_ms: u64 = 1000;
    let mut preload: u64 = 0;
    let mut ttl: Option<i32> = None;
    let mut tos: Option<i32> = None;
    let mut pattern: Vec<u8> = Vec::new();
    let mut source: Option<String> = None;
    let mut datalen = DEFDATALEN;
    let mut timeout_s: Option<u64> = None;
    let mut waittime: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        i += 1;
        let b = a.as_bytes();
        let mut j = 1;
        while j < b.len() {
            let c = b[j] as char;
            j += 1;
            if !"cilmpSstWz".contains(c) {
                match c {
                    'a' => audible = true,
                    'f' => {
                        if !root {
                            return die(EX_NOPERM, "-f flag: Operation not permitted");
                        }
                        flood = true;
                    }
                    'n' => {} // replies are always shown by address
                    'o' => once = true,
                    'q' => quiet = true,
                    'v' => verbose = true,
                    _ => {
                        eprintln!("ping: illegal option -- {c}");
                        return usage();
                    }
                }
                continue;
            }
            let v = if j < b.len() {
                let v = a[j..].to_string();
                j = b.len();
                v
            } else if i < args.len() {
                i += 1;
                args[i - 1].clone()
            } else {
                eprintln!("ping: option requires an argument -- {c}");
                return usage();
            };
            let r: Result<(), ExitCode> = (|| {
                match c {
                    'c' => count = number(&v, "count of packets to transmit", 1u64, u64::MAX)?,
                    'i' => {
                        let t: f64 = number(&v, "timing interval", 0.0, 1e7)?;
                        let ms = (t * 1000.0) as u64;
                        if ms < 1000 && !root {
                            return Err(die(EX_NOPERM, "-i interval too short: Operation not permitted"));
                        }
                        interval_ms = ms.max(1);
                    }
                    'l' => {
                        if !root {
                            return Err(die(EX_NOPERM, "-l flag: Operation not permitted"));
                        }
                        preload = number(&v, "preload value", 0u64, 1 << 20)?;
                    }
                    'm' => ttl = Some(number(&v, "TTL", 0i32, 255)?),
                    'p' => {
                        let h = v.as_bytes();
                        if h.is_empty() || !h.iter().all(u8::is_ascii_hexdigit) {
                            return Err(die(EX_USAGE, "patterns must be specified as hex digits"));
                        }
                        pattern = h
                            .chunks(2)
                            .take(16)
                            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                            .collect();
                    }
                    'S' => source = Some(v.clone()),
                    's' => datalen = number(&v, "packet size", 0usize, MAXDATA)?,
                    't' => timeout_s = Some(number(&v, "timeout", 1u64, u64::MAX / 1_000_000_000)?),
                    'W' => waittime = Some(number(&v, "timing interval", 0u64, u64::MAX / 1_000_000)?),
                    'z' => tos = Some(number(&v, "TOS", 0i32, 255)?),
                    _ => unreachable!(),
                }
                Ok(())
            })();
            if let Err(code) = r {
                return code;
            }
        }
    }
    if args.len() != i + 1 {
        return usage();
    }
    let host = &args[i];
    if flood && interval_ms != 1000 {
        return die(EX_USAGE, "-f and -i: Incompatible options");
    }
    if flood {
        interval_ms = 10;
    }

    let (dst, hostname) = match resolve(host) {
        Ok(r) => r,
        Err(e) => return die(EX_NOHOST, &e),
    };
    let src = match &source {
        Some(s) => match resolve(s) {
            Ok((ip, _)) => Some(ip),
            Err(e) => return die(EX_NOHOST, &e),
        },
        None => None,
    };

    // SAFETY: socket creation; fd is owned from here on.
    let (fd, raw) = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
        if fd >= 0 {
            (fd, true)
        } else {
            let first = io::Error::last_os_error();
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
            if fd < 0 {
                return die(EX_OSERR, &format!("socket: {}", strerror(&first)));
            }
            (fd, false)
        }
    };
    // Root's work is done: the socket is open (ping may be set-user-ID root).
    // SAFETY: dropping privilege to the real user.
    unsafe {
        if libc::setuid(libc::getuid()) != 0 {
            return die(EX_OSERR, &format!("setuid: {}", strerror(&io::Error::last_os_error())));
        }
    }
    let setopt = |level: libc::c_int, name: libc::c_int, val: i32, what: &str| -> Result<(), ExitCode> {
        // SAFETY: an int option.
        let rc = unsafe {
            libc::setsockopt(fd, level, name, (&val as *const i32).cast(), std::mem::size_of::<i32>() as libc::socklen_t)
        };
        if rc != 0 {
            return Err(die(EX_OSERR, &format!("setsockopt {what}: {}", strerror(&io::Error::last_os_error()))));
        }
        Ok(())
    };
    if let Some(t) = ttl {
        if let Err(c) = setopt(libc::IPPROTO_IP, libc::IP_TTL, t, "IP_TTL") {
            return c;
        }
    }
    if let Some(t) = tos {
        if let Err(c) = setopt(libc::IPPROTO_IP, libc::IP_TOS, t, "IP_TOS") {
            return c;
        }
    }
    if let Some(ip) = src {
        let sa = sockaddr(ip);
        // SAFETY: binding a sockaddr_in.
        let rc = unsafe {
            libc::bind(fd, (&sa as *const libc::sockaddr_in).cast(), std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        };
        if rc != 0 {
            return die(EX_OSERR, &format!("bind: {}", strerror(&io::Error::last_os_error())));
        }
    }

    // SAFETY: handlers that only set an atomic; no SA_RESTART, so poll returns early.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }

    // SAFETY: getpid has no preconditions.
    let ident = (unsafe { libc::getpid() } & 0xffff) as u16;
    let timing = datalen >= TV_LEN;
    let fill: Vec<u8> = (0..datalen)
        .map(|n| match (pattern.is_empty(), timing) {
            (true, _) => n as u8,
            (false, true) => pattern[n.saturating_sub(TV_LEN) % pattern.len()],
            (false, false) => pattern[n % pattern.len()],
        })
        .collect();

    let mut out = BufWriter::new(io::stdout().lock());
    let _ = write!(out, "PING {hostname} ({})", ip_str(dst));
    if let Some(s) = src {
        let _ = write!(out, " from {}", ip_str(s));
    }
    let _ = writeln!(out, ": {datalen} data bytes");
    let _ = out.flush();

    let dest = sockaddr(dst);
    let mut st = Stats { sent: 0, received: 0, repeats: 0, tmin: f64::MAX, tmax: 0.0, tsum: 0.0, tsumsq: 0.0 };
    let mut seen = vec![0u64; 65536 / 64];
    let started = mono();
    let deadline = timeout_s.map(|t| started + t * 1_000_000_000);
    let mut packet = vec![0u8; ICMP_MINLEN + datalen];
    let mut buf = vec![0u8; IP_MAXPACKET];

    let mut send = |st: &mut Stats, seen: &mut [u64], out: &mut BufWriter<io::StdoutLock>| {
        let seq = st.sent as u16;
        packet.fill(0);
        packet[0] = ICMP_ECHO;
        packet[4..6].copy_from_slice(&ident.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        packet[ICMP_MINLEN..].copy_from_slice(&fill);
        if timing {
            let t = mono();
            packet[8..12].copy_from_slice(&((t / 1_000_000_000) as u32).to_be_bytes());
            packet[12..16].copy_from_slice(&((t % 1_000_000_000) as u32).to_be_bytes());
        }
        seen[seq as usize / 64] &= !(1 << (seq % 64));
        let sum = cksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
        // SAFETY: sending a buffer to a sockaddr_in.
        let n = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr().cast(),
                packet.len(),
                0,
                (&dest as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            let _ = out.flush();
            eprintln!("ping: sendto: {}", strerror(&io::Error::last_os_error()));
        } else if n as usize != packet.len() {
            let _ = out.flush();
            eprintln!("ping: wrote {hostname} {} chars, ret={n}", packet.len());
        }
        st.sent += 1;
        if flood {
            let _ = out.write_all(b".");
            let _ = out.flush();
        }
    };

    for _ in 0..preload {
        send(&mut st, &mut seen, &mut out);
    }
    let mut next = mono();
    let mut almost_done = false;
    loop {
        if STOP.load(Ordering::Relaxed) {
            break;
        }
        let now = mono();
        if deadline.is_some_and(|d| now >= d) {
            break;
        }
        if now >= next {
            if count == 0 || st.sent < count {
                send(&mut st, &mut seen, &mut out);
                next += interval_ms * 1_000_000;
                if next < now {
                    next = now + interval_ms * 1_000_000;
                }
            } else {
                if almost_done {
                    break;
                }
                almost_done = true;
                let wait_ms = if st.received > 0 {
                    ((2.0 * st.tmax) as u64).max(1000)
                } else {
                    waittime.unwrap_or(MAXWAIT_MS)
                };
                next = now + wait_ms * 1_000_000;
            }
        }
        if count > 0 && st.received >= count {
            break;
        }
        if once && st.received > 0 {
            break;
        }
        let mut wait_ns = next.saturating_sub(mono());
        if let Some(d) = deadline {
            wait_ns = wait_ns.min(d.saturating_sub(mono()));
        }
        // Short enough that an interrupt is seen soon, whether or not it cuts the poll short.
        let wait_ms = (wait_ns / 1_000_000).min(200) as libc::c_int;
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, wait_ms) };
        if rc <= 0 || pfd.revents & libc::POLLIN == 0 {
            continue;
        }
        // SAFETY: an all-zero sockaddr_in is valid; recvfrom fills at most buf.len() bytes.
        let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut fromlen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let n = unsafe { libc::recvfrom(fd, buf.as_mut_ptr().cast(), buf.len(), 0, (&mut from as *mut libc::sockaddr_in).cast(), &mut fromlen) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted && e.kind() != io::ErrorKind::WouldBlock {
                let _ = out.flush();
                eprintln!("ping: recvfrom: {}", strerror(&e));
            }
            continue;
        }
        let arrived = mono();
        let pkt = &buf[..n as usize];
        let from_ip = from.sin_addr.s_addr.to_ne_bytes();
        // A raw socket's packet starts with the IP header.
        let (hlen, rttl) = if raw {
            if pkt.len() < 20 {
                continue;
            }
            ((pkt[0] & 0x0f) as usize * 4, Some(pkt[8]))
        } else {
            (0, None)
        };
        if pkt.len() < hlen + ICMP_MINLEN {
            if verbose {
                let _ = writeln!(out, "packet too short ({} bytes) from {}", pkt.len(), ip_str(from_ip));
            }
            continue;
        }
        let icmp = &pkt[hlen..];
        let cc = icmp.len();
        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
        if icmp[0] != ICMP_ECHOREPLY || (raw && id != ident) {
            // Our own requests come back up a raw socket on loopback: not news.
            if verbose && !(icmp[0] == ICMP_ECHO && id == ident) {
                let _ = writeln!(out, "{cc} bytes from {}: {}", ip_str(from_ip), type_name(icmp[0]));
                let _ = out.flush();
            }
            continue;
        }
        st.received += 1;
        let mut rtt = None;
        if timing && cc >= ICMP_MINLEN + TV_LEN {
            let s = u32::from_be_bytes(icmp[8..12].try_into().unwrap()) as u64;
            let ns = u32::from_be_bytes(icmp[12..16].try_into().unwrap()) as u64;
            let t = arrived.saturating_sub(s * 1_000_000_000 + ns) as f64 / 1e6;
            rtt = Some(t);
            st.tsum += t;
            st.tsumsq += t * t;
            st.tmin = st.tmin.min(t);
            st.tmax = st.tmax.max(t);
        }
        let bit = 1u64 << (seq % 64);
        let dup = seen[seq as usize / 64] & bit != 0;
        if dup {
            st.repeats += 1;
            st.received -= 1;
        } else {
            seen[seq as usize / 64] |= bit;
        }
        // A reply later than -W allows counts, but isn't shown.
        let late = waittime.is_some_and(|w| rtt.is_some_and(|t| t > w as f64));
        if flood {
            let _ = out.write_all(b"\x08");
            let _ = out.flush();
        } else if !quiet && !late {
            let _ = write!(out, "{cc} bytes from {}: icmp_seq={seq}", ip_str(from_ip));
            if let Some(t) = rttl {
                let _ = write!(out, " ttl={t}");
            }
            if let Some(t) = rtt {
                let _ = write!(out, " time={t:.3} ms");
            }
            if dup {
                let _ = write!(out, " (DUP!)");
            }
            if audible {
                let _ = write!(out, "\x07");
            }
            if cksum(icmp) != 0 {
                let _ = write!(out, " (BAD CHECKSUM)");
            }
            let _ = writeln!(out);
            // The data past the timestamp must be what was sent.
            let start = ICMP_MINLEN + if timing { TV_LEN } else { 0 };
            for k in start..cc.min(ICMP_MINLEN + datalen) {
                if icmp[k] != fill[k - ICMP_MINLEN] {
                    let _ = writeln!(
                        out,
                        "wrong data byte #{} should be 0x{:x} but was 0x{:x}",
                        k - ICMP_MINLEN,
                        fill[k - ICMP_MINLEN],
                        icmp[k]
                    );
                    break;
                }
            }
            let _ = out.flush();
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "--- {hostname} ping statistics ---");
    let _ = write!(out, "{} packets transmitted, {} packets received, ", st.sent, st.received);
    if st.repeats > 0 {
        let _ = write!(out, "+{} duplicates, ", st.repeats);
    }
    if st.sent > 0 {
        if st.received > st.sent {
            let _ = write!(out, "-- somebody's printing up packets!");
        } else {
            let loss = (st.sent - st.received) as f64 * 100.0 / st.sent as f64;
            let _ = write!(out, "{loss:.1}% packet loss");
        }
    }
    let _ = writeln!(out);
    let n = (st.received + st.repeats) as f64;
    if st.received > 0 && timing && n > 0.0 {
        let avg = st.tsum / n;
        let var = (st.tsumsq / n - avg * avg).max(0.0);
        let _ = writeln!(
            out,
            "round-trip min/avg/max/stddev = {:.3}/{:.3}/{:.3}/{:.3} ms",
            st.tmin,
            avg,
            st.tmax,
            var.sqrt()
        );
    }
    let _ = out.flush();
    // SAFETY: closing our socket.
    unsafe { libc::close(fd) };
    if st.received > 0 { ExitCode::SUCCESS } else { ExitCode::from(2) }
}
