//! A lease: what a server's ACK grants, checked; its form in the lease file (FreeBSD's
//! `dhclient.leases(5)` layout, times in UTC); and the `resolv.conf` it makes.

use std::net::Ipv4Addr;

use super::packet::{self, Reply};

/// Leases shorter than this are stretched to it, so a hostile or broken server can't make the
/// client spin.
pub const MIN_LEASE: u32 = 60;
/// `0xffffffff` seconds is an infinite lease (RFC 2131 §3.3).
pub const INFINITE: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    pub interface: String,
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub hostname: Option<String>,
    pub server: Ipv4Addr,
    /// In seconds: the lease and its renewal (T1) and rebinding (T2) times.
    pub lease: u32,
    pub t1: u32,
    pub t2: u32,
    /// The wall-clock times (seconds since the epoch) it renews, rebinds and expires at;
    /// `i64::MAX` for never.
    pub renew: i64,
    pub rebind: i64,
    pub expire: i64,
}

pub fn classful_mask(a: Ipv4Addr) -> Ipv4Addr {
    let len = match a.octets()[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    };
    Ipv4Addr::from(u32::MAX << (32 - len))
}

/// An address a host may be given: not 0/8, loopback, link-local's opposite (multicast),
/// class E or the limited broadcast.
pub fn assignable(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(o[0] == 0 || a.is_loopback() || a.is_multicast() || o[0] >= 240)
}

fn in_subnet(a: Ipv4Addr, net: Ipv4Addr, mask: Ipv4Addr) -> bool {
    u32::from(a) & u32::from(mask) == u32::from(net) & u32::from(mask)
}

fn at(now: i64, secs: u32) -> i64 {
    if secs == INFINITE { i64::MAX } else { now.saturating_add(secs as i64) }
}

impl Lease {
    /// The lease an ACK grants, received at `now` (wall clock). `Err` says why the ACK can't be
    /// used; `notes` collects what was fixed up or dropped, for the log.
    pub fn from_ack(interface: &str, r: &Reply, now: i64, notes: &mut Vec<String>) -> Result<Lease, String> {
        let addr = r.yiaddr;
        if !assignable(addr) {
            return Err(format!("unusable address {addr}"));
        }
        let Some(server) = r.server_id else { return Err("no server identifier".into()) };
        let Some(mut lease) = r.lease else { return Err("no lease time".into()) };
        let mask = r.mask.unwrap_or_else(|| classful_mask(addr));
        let host = u32::from(addr) & !u32::from(mask);
        if mask.octets()[3] != 0xff && mask.octets() != [255, 255, 255, 254] && (host == 0 || host == !u32::from(mask)) {
            return Err(format!("{addr} is its subnet's network or broadcast address"));
        }
        if lease < MIN_LEASE {
            notes.push(format!("lease of {lease} seconds stretched to {MIN_LEASE}"));
            lease = MIN_LEASE;
        }
        // T1 < T2 < lease, or the RFC's defaults (half, and seven eighths).
        let (mut t1, mut t2) = (r.t1.unwrap_or(lease / 2), r.t2.unwrap_or((lease as u64 * 7 / 8) as u32));
        if lease != INFINITE && !(t1 < t2 && t2 < lease) {
            if r.t1.is_some() || r.t2.is_some() {
                notes.push("renewal/rebinding times out of order; using the defaults".into());
            }
            t1 = lease / 2;
            t2 = (lease as u64 * 7 / 8) as u32;
        }
        if lease == INFINITE {
            t1 = INFINITE;
            t2 = INFINITE;
        }
        let routers: Vec<Ipv4Addr> = r
            .routers
            .iter()
            .copied()
            .filter(|&g| {
                let ok = g != addr && assignable(g) && in_subnet(g, addr, mask);
                if !ok {
                    notes.push(format!("router {g} is not on {addr}'s subnet; ignored"));
                }
                ok
            })
            .collect();
        for &c in &r.dropped {
            notes.push(format!("option {c} is not a valid name; ignored"));
        }
        Ok(Lease {
            interface: interface.to_string(),
            addr,
            mask,
            routers,
            dns: r.dns.iter().copied().filter(|d| !d.is_unspecified()).collect(),
            domain: r.domain.clone(),
            hostname: r.hostname.clone(),
            server,
            lease,
            t1,
            t2,
            renew: at(now, t1),
            rebind: at(now, t2),
            expire: at(now, lease),
        })
    }

    pub fn router(&self) -> Option<Ipv4Addr> {
        self.routers.first().copied()
    }

    /// The lease file's text.
    pub fn render(&self) -> String {
        let mut s = String::from("lease {\n");
        s += &format!("  interface \"{}\";\n", self.interface);
        s += &format!("  fixed-address {};\n", self.addr);
        s += &format!("  option subnet-mask {};\n", self.mask);
        let list = |v: &[Ipv4Addr]| v.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
        if !self.routers.is_empty() {
            s += &format!("  option routers {};\n", list(&self.routers));
        }
        if !self.dns.is_empty() {
            s += &format!("  option domain-name-servers {};\n", list(&self.dns));
        }
        if let Some(d) = &self.domain {
            s += &format!("  option domain-name \"{d}\";\n");
        }
        if let Some(h) = &self.hostname {
            s += &format!("  option host-name \"{h}\";\n");
        }
        s += &format!("  option dhcp-lease-time {};\n", self.lease);
        s += &format!("  option dhcp-renewal-time {};\n", self.t1);
        s += &format!("  option dhcp-rebinding-time {};\n", self.t2);
        s += &format!("  option dhcp-server-identifier {};\n", self.server);
        s += &format!("  renew {};\n", date(self.renew));
        s += &format!("  rebind {};\n", date(self.rebind));
        s += &format!("  expire {};\n", date(self.expire));
        s += "}\n";
        s
    }

    /// Reads the last lease for `interface` from a lease file's text. Anything it doesn't
    /// understand makes it give up on that lease: the file is a cache, never trusted further.
    pub fn parse(text: &str, interface: &str) -> Option<Lease> {
        let mut found = None;
        let mut cur: Option<Vec<(String, String)>> = None;
        for line in text.lines().take(1000) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "lease {" {
                cur = Some(Vec::new());
            } else if line == "}" {
                if let Some(fields) = cur.take() {
                    if let Some(l) = Self::from_fields(&fields, interface) {
                        found = Some(l);
                    }
                }
            } else if let Some(fields) = cur.as_mut() {
                let body = line.strip_suffix(';')?;
                let body = body.strip_prefix("option ").unwrap_or(body);
                let (k, v) = body.split_once(' ')?;
                if fields.len() > 32 {
                    return None;
                }
                fields.push((k.to_string(), v.trim().to_string()));
            }
        }
        found
    }

    fn from_fields(fields: &[(String, String)], interface: &str) -> Option<Lease> {
        let get = |k: &str| fields.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        let quoted = |v: &str| v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).map(str::to_string);
        if quoted(get("interface")?)? != interface {
            return None;
        }
        let ip = |v: &str| v.parse::<Ipv4Addr>().ok();
        let list = |v: Option<&str>| -> Option<Vec<Ipv4Addr>> {
            match v {
                None => Some(Vec::new()),
                Some(v) => v.split(',').map(|a| ip(a.trim())).collect(),
            }
        };
        let name = |k: &str| -> Option<Option<String>> {
            match get(k) {
                None => Some(None),
                Some(v) => Some(Some(packet::sanitize_name(quoted(v)?.as_bytes())?)),
            }
        };
        let addr = ip(get("fixed-address")?)?;
        let mask = ip(get("subnet-mask")?)?;
        if !assignable(addr) || !packet::mask_ok(mask) {
            return None;
        }
        let mut dns = list(get("domain-name-servers"))?;
        dns.truncate(packet::MAX_DNS);
        let mut routers = list(get("routers"))?;
        routers.truncate(packet::MAX_ROUTERS);
        Some(Lease {
            interface: interface.to_string(),
            addr,
            mask,
            routers,
            dns,
            domain: name("domain-name")?,
            hostname: name("host-name")?,
            server: ip(get("dhcp-server-identifier")?)?,
            lease: get("dhcp-lease-time")?.parse().ok()?,
            t1: get("dhcp-renewal-time")?.parse().ok()?,
            t2: get("dhcp-rebinding-time")?.parse().ok()?,
            renew: parse_date(get("renew")?)?,
            rebind: parse_date(get("rebind")?)?,
            expire: parse_date(get("expire")?)?,
        })
    }
}

/// `resolv.conf`'s text for a lease, or `None` when it names no server (the file is then left
/// as it is).
pub fn resolv_conf(l: &Lease) -> Option<String> {
    if l.dns.is_empty() {
        return None;
    }
    let mut s = format!("# Generated by dhclient(8) for {}; rewritten with each new lease.\n", l.interface);
    if let Some(d) = &l.domain {
        s += &format!("search {d}\n");
    }
    for n in &l.dns {
        s += &format!("nameserver {n}\n");
    }
    Some(s)
}

// --- dates ---------------------------------------------------------------------------------------

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// FreeBSD's lease-file date: `W YYYY/MM/DD HH:MM:SS` (weekday 0 is Sunday), UTC; `never`.
pub fn date(t: i64) -> String {
    if t == i64::MAX {
        return "never".into();
    }
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let wday = (days + 4).rem_euclid(7);
    format!("{wday} {y:04}/{m:02}/{d:02} {:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

pub fn parse_date(s: &str) -> Option<i64> {
    if s == "never" {
        return Some(i64::MAX);
    }
    let mut it = s.split_whitespace();
    let _wday: u32 = it.next()?.parse().ok()?;
    let ymd: Vec<&str> = it.next()?.split('/').collect();
    let hms: Vec<&str> = it.next()?.split(':').collect();
    if it.next().is_some() || ymd.len() != 3 || hms.len() != 3 {
        return None;
    }
    let (y, m, d): (i64, u32, u32) = (ymd[0].parse().ok()?, ymd[1].parse().ok()?, ymd[2].parse().ok()?);
    let (hh, mm, ss): (i64, i64, i64) = (hms[0].parse().ok()?, hms[1].parse().ok()?, hms[2].parse().ok()?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::packet::tests::server_reply;
    use super::super::packet::*;

    #[test]
    fn dates() {
        assert_eq!(date(0), "4 1970/01/01 00:00:00");
        // 2026-10-18 is a Sunday.
        let t = days_from_civil(2026, 10, 18) * 86_400 + 12 * 3600 + 34 * 60 + 56;
        assert_eq!(date(t), "0 2026/10/18 12:34:56");
        assert_eq!(parse_date(&date(t)), Some(t));
        assert_eq!(date(i64::MAX), "never");
        assert_eq!(parse_date("never"), Some(i64::MAX));
        assert_eq!(parse_date("0 2026/13/18 12:34:56"), None);
        assert_eq!(parse_date("0 2026/10/18"), None);
        for d in [-1i64, 59, 951_782_400, 4_102_444_800] {
            assert_eq!(parse_date(&date(d.max(0))), Some(d.max(0)));
        }
    }

    fn ack(extra: &[(u8, &[u8])]) -> Reply {
        parse(&server_reply(DHCPACK, 1, extra)).unwrap()
    }

    #[test]
    fn from_ack() {
        let mut notes = Vec::new();
        let l = Lease::from_ack("rl0", &ack(&[(OPT_DOMAIN, b"example.org")]), 1000, &mut notes).unwrap();
        assert_eq!(l.addr, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(l.router(), Some(Ipv4Addr::new(10, 0, 2, 2)));
        assert_eq!((l.lease, l.t1, l.t2), (86400, 43200, 75600));
        assert_eq!((l.renew, l.rebind, l.expire), (1000 + 43200, 1000 + 75600, 1000 + 86400));
        assert!(notes.is_empty());
        // A second lease-time option is joined to the first (RFC 3396), making it the wrong
        // size: the whole message is refused.
        assert!(parse(&server_reply(DHCPACK, 1, &[(OPT_LEASE_TIME, &5u32.to_be_bytes())])).is_err());
        // A router off the subnet is dropped.
        let mut notes = Vec::new();
        let l = Lease::from_ack("rl0", &Reply { routers: vec![Ipv4Addr::new(8, 8, 8, 8)], ..ack(&[]) }, 0, &mut notes).unwrap();
        assert_eq!(l.router(), None);
        assert_eq!(notes.len(), 1);
        // No usable address, no server id, no lease time.
        let bad = [
            Reply { yiaddr: Ipv4Addr::new(127, 0, 0, 1), ..ack(&[]) },
            Reply { yiaddr: Ipv4Addr::new(224, 0, 0, 1), ..ack(&[]) },
            Reply { yiaddr: Ipv4Addr::new(10, 0, 2, 255), ..ack(&[]) },
            Reply { yiaddr: Ipv4Addr::UNSPECIFIED, ..ack(&[]) },
            Reply { server_id: None, ..ack(&[]) },
            Reply { lease: None, ..ack(&[]) },
        ];
        for r in bad {
            assert!(Lease::from_ack("rl0", &r, 0, &mut Vec::new()).is_err(), "{r:?}");
        }
        let l = Lease::from_ack("rl0", &Reply { lease: Some(10), t1: Some(9), t2: Some(3), ..ack(&[]) }, 0, &mut Vec::new()).unwrap();
        assert_eq!((l.lease, l.t1, l.t2), (60, 30, 52));
        let l = Lease::from_ack("rl0", &Reply { lease: Some(INFINITE), ..ack(&[]) }, 0, &mut Vec::new()).unwrap();
        assert_eq!((l.renew, l.expire), (i64::MAX, i64::MAX));
    }

    #[test]
    fn lease_file_round_trip() {
        let l = Lease::from_ack("rl0", &ack(&[(OPT_DOMAIN, b"example.org"), (OPT_HOSTNAME, b"box")]), 1_760_000_000, &mut Vec::new()).unwrap();
        let text = l.render();
        assert!(text.contains("  fixed-address 10.0.2.15;\n"), "{text}");
        assert!(text.contains("  option domain-name \"example.org\";\n"));
        assert_eq!(Lease::parse(&text, "rl0"), Some(l.clone()));
        assert_eq!(Lease::parse(&text, "rl1"), None);
        // The last lease of the interface wins; a broken one is skipped.
        let broken = text.replace("10.0.2.15", "10.0.2");
        let two = format!("{text}{broken}");
        assert_eq!(Lease::parse(&two, "rl0"), Some(l.clone()));
        let bad = text.replace("\"example.org\"", "\"evil\nnameserver 6.6.6.6\"");
        assert_eq!(Lease::parse(&bad, "rl0"), None);
        assert_eq!(Lease::parse("garbage {{{", "rl0"), None);
        let conf = resolv_conf(&l).unwrap();
        assert_eq!(
            conf,
            "# Generated by dhclient(8) for rl0; rewritten with each new lease.\nsearch example.org\nnameserver 10.0.2.3\n"
        );
        assert_eq!(resolv_conf(&Lease { dns: Vec::new(), ..l }), None);
    }
}
