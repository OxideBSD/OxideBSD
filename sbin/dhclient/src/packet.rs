//! DHCPv4 messages (RFC 2131, options RFC 2132): building the client's, and taking servers'
//! apart.
//!
//! Everything a server sends is hostile until it parses: every length is checked against what
//! is left of its area before it is read, a value of the wrong size rejects the whole message,
//! and text options are reduced to a safe character set before anything else sees them (they go
//! into `resolv.conf` and the lease file). An option split over several instances (RFC 3396) is
//! put back together, up to [`MAX_OPTION`] bytes, and the `file` and `sname` fields are read for
//! options when the overload option (52) says so.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;
pub const HTYPE_ETHER: u8 = 1;

pub const DHCPDISCOVER: u8 = 1;
pub const DHCPOFFER: u8 = 2;
pub const DHCPREQUEST: u8 = 3;
pub const DHCPDECLINE: u8 = 4;
pub const DHCPACK: u8 = 5;
pub const DHCPNAK: u8 = 6;
pub const DHCPRELEASE: u8 = 7;

pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTERS: u8 = 3;
pub const OPT_DNS: u8 = 6;
pub const OPT_HOSTNAME: u8 = 12;
pub const OPT_DOMAIN: u8 = 15;
pub const OPT_BROADCAST: u8 = 28;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_LEASE_TIME: u8 = 51;
pub const OPT_OVERLOAD: u8 = 52;
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_LIST: u8 = 55;
pub const OPT_MESSAGE: u8 = 56;
pub const OPT_MAX_SIZE: u8 = 57;
pub const OPT_T1: u8 = 58;
pub const OPT_T2: u8 = 59;
pub const OPT_CLIENT_ID: u8 = 61;
pub const OPT_END: u8 = 255;

pub const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// The fixed part: op through `file`.
pub const FIXED_LEN: usize = 236;
const SNAME: std::ops::Range<usize> = 44..108;
const FILE: std::ops::Range<usize> = 108..236;
/// The options start after the magic cookie.
pub const OPTIONS_AT: usize = FIXED_LEN + 4;
/// BOOTP's minimum message (RFC 1542 §2.1): shorter requests are padded to it.
pub const MIN_LEN: usize = 300;
/// The largest message we say we take (option 57) and the most we read.
pub const MAX_LEN: usize = 1500;
/// The most bytes one option may add up to across its instances.
pub const MAX_OPTION: usize = 1024;
/// At most this many name servers are kept, as `resolv.conf` uses (`MAXNS`).
pub const MAX_DNS: usize = 3;
/// At most this many routers are kept.
pub const MAX_ROUTERS: usize = 8;

/// The options the client asks for.
const PARAMS: &[u8] = &[
    OPT_SUBNET_MASK,
    OPT_ROUTERS,
    OPT_DNS,
    OPT_HOSTNAME,
    OPT_DOMAIN,
    OPT_BROADCAST,
    OPT_LEASE_TIME,
    OPT_SERVER_ID,
    OPT_T1,
    OPT_T2,
];

pub fn type_name(t: u8) -> &'static str {
    match t {
        DHCPDISCOVER => "DHCPDISCOVER",
        DHCPOFFER => "DHCPOFFER",
        DHCPREQUEST => "DHCPREQUEST",
        DHCPDECLINE => "DHCPDECLINE",
        DHCPACK => "DHCPACK",
        DHCPNAK => "DHCPNAK",
        DHCPRELEASE => "DHCPRELEASE",
        8 => "DHCPINFORM",
        _ => "DHCP message of unknown type",
    }
}

/// A message from the client.
#[derive(Debug, Clone)]
pub struct Request {
    pub kind: u8,
    pub xid: u32,
    pub secs: u16,
    pub mac: [u8; 6],
    /// Our address, while renewing, rebinding or releasing.
    pub ciaddr: Ipv4Addr,
    /// Option 50.
    pub requested: Option<Ipv4Addr>,
    /// Option 54.
    pub server: Option<Ipv4Addr>,
}

fn opt(out: &mut Vec<u8>, code: u8, data: &[u8]) {
    debug_assert!(data.len() <= 255);
    out.push(code);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// The wire form of a client message.
pub fn build(r: &Request) -> Vec<u8> {
    let mut p = vec![0u8; FIXED_LEN];
    p[0] = BOOTREQUEST;
    p[1] = HTYPE_ETHER;
    p[2] = 6;
    p[4..8].copy_from_slice(&r.xid.to_be_bytes());
    p[8..10].copy_from_slice(&r.secs.to_be_bytes());
    // flags (10..12) stay 0: OxideBSD's kernel hands us a unicast reply even before we have an
    // address, so no broadcast replies are asked for.
    p[12..16].copy_from_slice(&r.ciaddr.octets());
    p[28..34].copy_from_slice(&r.mac);
    p.extend_from_slice(&MAGIC);
    opt(&mut p, OPT_MSG_TYPE, &[r.kind]);
    let mut cid = [0u8; 7];
    cid[0] = HTYPE_ETHER;
    cid[1..].copy_from_slice(&r.mac);
    opt(&mut p, OPT_CLIENT_ID, &cid);
    if let Some(a) = r.requested {
        opt(&mut p, OPT_REQUESTED_IP, &a.octets());
    }
    if let Some(s) = r.server {
        opt(&mut p, OPT_SERVER_ID, &s.octets());
    }
    if r.kind == DHCPDISCOVER || r.kind == DHCPREQUEST {
        opt(&mut p, OPT_MAX_SIZE, &(MAX_LEN as u16).to_be_bytes());
        opt(&mut p, OPT_PARAM_LIST, PARAMS);
    }
    p.push(OPT_END);
    if p.len() < MIN_LEN {
        p.resize(MIN_LEN, OPT_PAD);
    }
    p
}

/// A server's message, its options checked and decoded.
#[derive(Debug, Clone, PartialEq)]
pub struct Reply {
    pub kind: u8,
    pub xid: u32,
    pub yiaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    pub server_id: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub hostname: Option<String>,
    pub lease: Option<u32>,
    pub t1: Option<u32>,
    pub t2: Option<u32>,
    /// Option 56 (a NAK's reason), made printable.
    pub message: Option<String>,
    /// Text options that were dropped as unsafe, for the log.
    pub dropped: Vec<u8>,
}

impl Default for Reply {
    fn default() -> Self {
        Reply {
            kind: 0,
            xid: 0,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 6],
            server_id: None,
            mask: None,
            routers: Vec::new(),
            dns: Vec::new(),
            domain: None,
            hostname: None,
            lease: None,
            t1: None,
            t2: None,
            message: None,
            dropped: Vec::new(),
        }
    }
}

/// Collects the options of one area into `opts`. `Err` for a malformed area.
fn walk(area: &[u8], opts: &mut BTreeMap<u8, Vec<u8>>) -> Result<(), &'static str> {
    let mut i = 0;
    while i < area.len() {
        let code = area[i];
        i += 1;
        match code {
            OPT_PAD => continue,
            OPT_END => return Ok(()),
            _ => {}
        }
        let Some(&len) = area.get(i) else { return Err("truncated option") };
        i += 1;
        let len = len as usize;
        if len > area.len() - i {
            return Err("truncated option");
        }
        let v = opts.entry(code).or_default();
        if v.len() + len > MAX_OPTION {
            return Err("oversized option");
        }
        v.extend_from_slice(&area[i..i + len]);
        i += len;
    }
    // No end option: tolerated if everything before it was whole.
    Ok(())
}

fn ip_at(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn one_addr(v: &[u8]) -> Result<Ipv4Addr, &'static str> {
    if v.len() != 4 { Err("bad address option") } else { Ok(ip_at(v)) }
}

fn addrs(v: &[u8], cap: usize) -> Result<Vec<Ipv4Addr>, &'static str> {
    if v.is_empty() || v.len() % 4 != 0 {
        return Err("bad address list option");
    }
    Ok(v.chunks_exact(4).map(ip_at).filter(|a| !a.is_unspecified() && !a.is_broadcast()).take(cap).collect())
}

fn u32_of(v: &[u8]) -> Result<u32, &'static str> {
    if v.len() != 4 { Err("bad time option") } else { Ok(u32::from_be_bytes([v[0], v[1], v[2], v[3]])) }
}

/// A domain or host name, if it is one: labels of letters, digits, `-` and `_` joined by dots,
/// at most 253 bytes. Trailing NULs (some servers count one) are dropped first. Anything else
/// (spaces, newlines, quotes, other bytes) gets the whole option thrown away: it would end up in
/// `resolv.conf` and the lease file.
pub fn sanitize_name(v: &[u8]) -> Option<String> {
    let end = v.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
    let v = &v[..end];
    let v = v.strip_suffix(b".").unwrap_or(v);
    if v.is_empty() || v.len() > 253 {
        return None;
    }
    for label in v.split(|&c| c == b'.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            return None;
        }
        if label[0] == b'-' {
            return None;
        }
    }
    Some(String::from_utf8(v.to_vec()).ok()?)
}

/// A contiguous mask (ones, then zeros).
pub fn mask_ok(m: Ipv4Addr) -> bool {
    let b = u32::from(m);
    b.leading_ones() + b.trailing_zeros() == 32
}

/// Takes a server's message apart. `Err` says why it was thrown away.
pub fn parse(p: &[u8]) -> Result<Reply, &'static str> {
    if p.len() < OPTIONS_AT {
        return Err("short message");
    }
    if p.len() > MAX_LEN * 2 {
        return Err("oversized message");
    }
    if p[0] != BOOTREPLY {
        return Err("not a BOOTREPLY");
    }
    if p[1] != HTYPE_ETHER || p[2] != 6 {
        return Err("not for an Ethernet address");
    }
    if p[FIXED_LEN..OPTIONS_AT] != MAGIC {
        return Err("no DHCP magic cookie");
    }
    let mut opts = BTreeMap::new();
    walk(&p[OPTIONS_AT..], &mut opts)?;
    // Overload: only from the options area itself, and only once.
    if let Some(o) = opts.remove(&OPT_OVERLOAD) {
        let o = match o.as_slice() {
            [o @ 1..=3] => *o,
            _ => return Err("bad overload option"),
        };
        if o & 1 != 0 {
            walk(&p[FILE], &mut opts)?;
        }
        if o & 2 != 0 {
            walk(&p[SNAME], &mut opts)?;
        }
        if opts.contains_key(&OPT_OVERLOAD) {
            return Err("nested overload option");
        }
    }

    let mut r = Reply {
        xid: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        yiaddr: ip_at(&p[16..20]),
        ..Reply::default()
    };
    r.chaddr.copy_from_slice(&p[28..34]);
    r.kind = match opts.get(&OPT_MSG_TYPE).map(Vec::as_slice) {
        Some([t]) => *t,
        Some(_) => return Err("bad message type option"),
        None => return Err("no message type (a BOOTP reply)"),
    };
    for (&code, v) in &opts {
        match code {
            OPT_SERVER_ID => r.server_id = Some(one_addr(v)?),
            OPT_SUBNET_MASK => {
                let m = one_addr(v)?;
                if !mask_ok(m) {
                    return Err("non-contiguous subnet mask");
                }
                r.mask = Some(m);
            }
            OPT_ROUTERS => r.routers = addrs(v, MAX_ROUTERS)?,
            OPT_DNS => r.dns = addrs(v, MAX_DNS)?,
            OPT_LEASE_TIME => r.lease = Some(u32_of(v)?),
            OPT_T1 => r.t1 = Some(u32_of(v)?),
            OPT_T2 => r.t2 = Some(u32_of(v)?),
            OPT_DOMAIN => match sanitize_name(v) {
                Some(d) => r.domain = Some(d),
                None => r.dropped.push(code),
            },
            OPT_HOSTNAME => match sanitize_name(v) {
                Some(h) => r.hostname = Some(h),
                None => r.dropped.push(code),
            },
            OPT_MESSAGE => {
                let s: String = v.iter().take(255).map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '?' }).collect();
                r.message = Some(s);
            }
            _ => {}
        }
    }
    Ok(r)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    /// A server's reply, as QEMU's (slirp's) built-in server sends it: the extra options follow
    /// the usual ones.
    pub fn server_reply(kind: u8, xid: u32, extra: &[(u8, &[u8])]) -> Vec<u8> {
        let mut p = vec![0u8; FIXED_LEN];
        p[0] = BOOTREPLY;
        p[1] = 1;
        p[2] = 6;
        p[4..8].copy_from_slice(&xid.to_be_bytes());
        p[16..20].copy_from_slice(&[10, 0, 2, 15]);
        p[20..24].copy_from_slice(&[10, 0, 2, 2]);
        p[28..34].copy_from_slice(&MAC);
        p.extend_from_slice(&MAGIC);
        opt(&mut p, OPT_MSG_TYPE, &[kind]);
        opt(&mut p, OPT_SERVER_ID, &[10, 0, 2, 2]);
        opt(&mut p, OPT_LEASE_TIME, &86400u32.to_be_bytes());
        opt(&mut p, OPT_SUBNET_MASK, &[255, 255, 255, 0]);
        opt(&mut p, OPT_ROUTERS, &[10, 0, 2, 2]);
        opt(&mut p, OPT_DNS, &[10, 0, 2, 3]);
        for (c, v) in extra {
            opt(&mut p, *c, v);
        }
        p.push(OPT_END);
        p.resize(MIN_LEN.max(p.len()), 0);
        p
    }

    #[test]
    fn builds_requests() {
        let r = Request {
            kind: DHCPREQUEST,
            xid: 0xdeadbeef,
            secs: 3,
            mac: MAC,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested: Some(Ipv4Addr::new(10, 0, 2, 15)),
            server: Some(Ipv4Addr::new(10, 0, 2, 2)),
        };
        let p = build(&r);
        assert_eq!(p.len(), MIN_LEN);
        assert_eq!(&p[..4], &[1, 1, 6, 0]);
        assert_eq!(&p[4..8], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&p[8..10], &[0, 3]);
        assert_eq!(&p[28..34], &MAC);
        assert_eq!(&p[236..240], &MAGIC);
        let mut opts = BTreeMap::new();
        walk(&p[OPTIONS_AT..], &mut opts).unwrap();
        assert_eq!(opts[&OPT_MSG_TYPE], vec![DHCPREQUEST]);
        assert_eq!(opts[&OPT_CLIENT_ID], vec![1, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(opts[&OPT_REQUESTED_IP], vec![10, 0, 2, 15]);
        assert_eq!(opts[&OPT_SERVER_ID], vec![10, 0, 2, 2]);
        assert_eq!(opts[&OPT_MAX_SIZE], vec![0x05, 0xdc]);
        assert!(opts[&OPT_PARAM_LIST].contains(&OPT_DNS));
        // A DISCOVER names neither address; a RELEASE asks for nothing.
        let d = build(&Request { kind: DHCPDISCOVER, requested: None, server: None, ..r.clone() });
        let mut opts = BTreeMap::new();
        walk(&d[OPTIONS_AT..], &mut opts).unwrap();
        assert!(!opts.contains_key(&OPT_REQUESTED_IP) && !opts.contains_key(&OPT_SERVER_ID));
        let rel = build(&Request { kind: DHCPRELEASE, ciaddr: Ipv4Addr::new(10, 0, 2, 15), requested: None, ..r });
        let mut opts = BTreeMap::new();
        walk(&rel[OPTIONS_AT..], &mut opts).unwrap();
        assert!(!opts.contains_key(&OPT_PARAM_LIST));
        assert_eq!(&rel[12..16], &[10, 0, 2, 15]);
    }

    #[test]
    fn parses_offer_and_ack() {
        let p = server_reply(DHCPOFFER, 7, &[(OPT_DOMAIN, b"example.org\0"), (OPT_T1, &43200u32.to_be_bytes())]);
        let r = parse(&p).unwrap();
        assert_eq!(r.kind, DHCPOFFER);
        assert_eq!(r.xid, 7);
        assert_eq!(r.chaddr, MAC);
        assert_eq!(r.yiaddr, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(r.server_id, Some(Ipv4Addr::new(10, 0, 2, 2)));
        assert_eq!(r.mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(r.routers, vec![Ipv4Addr::new(10, 0, 2, 2)]);
        assert_eq!(r.dns, vec![Ipv4Addr::new(10, 0, 2, 3)]);
        assert_eq!(r.domain.as_deref(), Some("example.org"));
        assert_eq!(r.lease, Some(86400));
        assert_eq!(r.t1, Some(43200));
        let a = parse(&server_reply(DHCPACK, 7, &[])).unwrap();
        assert_eq!(a.kind, DHCPACK);
        let n = parse(&server_reply(DHCPNAK, 7, &[(OPT_MESSAGE, b"wrong\nnetwork")])).unwrap();
        assert_eq!(n.message.as_deref(), Some("wrong?network"));
    }

    #[test]
    fn rejects_hostile_messages() {
        let good = server_reply(DHCPACK, 1, &[]);
        assert!(parse(&good[..OPTIONS_AT - 1]).is_err());
        let mut p = good.clone();
        p[0] = BOOTREQUEST;
        assert!(parse(&p).is_err());
        let mut p = good.clone();
        p[2] = 16;
        assert!(parse(&p).is_err());
        let mut p = good.clone();
        p[237] ^= 1;
        assert!(parse(&p).is_err());
        // An option running past the end.
        let mut p = good[..OPTIONS_AT].to_vec();
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, DHCPACK, OPT_DNS, 200, 10, 0, 2, 3]);
        assert_eq!(parse(&p), Err("truncated option"));
        // A length byte with nothing after it.
        let mut p = good[..OPTIONS_AT].to_vec();
        p.extend_from_slice(&[OPT_MSG_TYPE, 1, DHCPACK, OPT_DNS]);
        assert_eq!(parse(&p), Err("truncated option"));
        // Wrong sizes.
        assert!(parse(&server_reply(DHCPACK, 1, &[(OPT_LEASE_TIME, &[1, 2])])).is_err());
        assert!(parse(&server_reply(DHCPACK, 1, &[(OPT_DNS, &[1, 2, 3])])).is_err());
        assert!(parse(&server_reply(DHCPACK, 1, &[(OPT_SUBNET_MASK, &[255, 0, 255, 0])])).is_err());
        assert!(parse(&server_reply(DHCPACK, 1, &[(OPT_MSG_TYPE, &[5, 5])])).is_err());
        // No message type: BOOTP.
        let mut p = good[..OPTIONS_AT].to_vec();
        p.push(OPT_END);
        assert!(parse(&p).is_err());
        // A repeated option is joined (RFC 3396), but only so far.
        let big = [7u8; 255];
        let ext: Vec<(u8, &[u8])> = (0..5).map(|_| (OPT_HOSTNAME, &big[..])).collect();
        assert_eq!(parse(&server_reply(DHCPACK, 1, &ext)), Err("oversized option"));
        // A text option with a newline is dropped, not the message.
        let r = parse(&server_reply(DHCPACK, 1, &[(OPT_DOMAIN, b"evil.org\nnameserver 6.6.6.6")])).unwrap();
        assert_eq!(r.domain, None);
        assert_eq!(r.dropped, vec![OPT_DOMAIN]);
        // Too many name servers: the first three kept.
        let many: Vec<u8> = (1..=5).flat_map(|i| [10, 0, 0, i]).collect();
        assert_eq!(parse(&server_reply(DHCPACK, 1, &[(OPT_DNS, &many)])).unwrap().dns.len(), 3);
    }

    #[test]
    fn overload() {
        let mut p = server_reply(DHCPACK, 1, &[(OPT_OVERLOAD, &[1])]);
        // The file field carries the domain.
        let f = [OPT_DOMAIN, 3, b'l', b'a', b'n', OPT_END];
        p[FILE.start..FILE.start + f.len()].copy_from_slice(&f);
        assert_eq!(parse(&p).unwrap().domain.as_deref(), Some("lan"));
        // An overload inside the overloaded field is refused.
        let f = [OPT_OVERLOAD, 1, 2, OPT_END];
        p[FILE.start..FILE.start + f.len()].copy_from_slice(&f);
        assert!(parse(&p).is_err());
        assert!(parse(&server_reply(DHCPACK, 1, &[(OPT_OVERLOAD, &[4])])).is_err());
    }

    #[test]
    fn names() {
        assert_eq!(sanitize_name(b"example.org").as_deref(), Some("example.org"));
        assert_eq!(sanitize_name(b"example.org.").as_deref(), Some("example.org"));
        assert_eq!(sanitize_name(b"host_1\0\0").as_deref(), Some("host_1"));
        for bad in [&b""[..], b"a b", b"a..b", b"-a", b"\"q\"", b"a\nb", b"\xff", b"a;b", b"\0"] {
            assert_eq!(sanitize_name(bad), None, "{bad:?}");
        }
        assert_eq!(sanitize_name(&[b'a'; 64]), None);
        assert_eq!(sanitize_name(&[b'a'; 300]), None);
    }

    #[test]
    fn fuzz_never_panics() {
        // A cheap deterministic fuzz: random bytes after a valid header, and every truncation of
        // a real message.
        let good = server_reply(DHCPACK, 1, &[(OPT_DOMAIN, b"x.org"), (OPT_OVERLOAD, &[3])]);
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
        let mut s: u64 = 0x1234_5678_9abc_def0;
        for _ in 0..20_000 {
            let mut p = good[..OPTIONS_AT].to_vec();
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let len = (s % 400) as usize;
            for k in 0..len {
                p.push((s.rotate_left(k as u32 % 64) >> 3) as u8);
            }
            let _ = parse(&p);
        }
    }
}
