//! `ifconfig(8)`: shows and sets network interfaces' IPv4 configuration.
//!
//! ```text
//! ifconfig [-a] [-d] [-u]
//! ifconfig -l [-d] [-u]
//! ifconfig interface [inet] [address[/prefixlen]] [netmask mask] [broadcast address]
//!          [alias | -alias | delete] [up | down]
//! ```
//!
//! The BSDs' syntax and FreeBSD's output: a line per interface with its flags, metric and MTU,
//! then its Ethernet address and its IPv4 address with the mask in hexadecimal and the broadcast
//! address. `media:` and `status:` lines are left out, since the kernel doesn't report either.
//!
//! An OxideBSD interface has at most one IPv4 address. Setting one replaces the old; `alias`
//! adds one only to an interface without, and refuses to make a second; `-alias` and `delete`
//! remove it. With no mask given the address's class decides it, as in the BSDs. Setting an
//! address also brings the interface up, unless `down` says otherwise. The broadcast address is
//! always the subnet's: `broadcast` is accepted only when it names that one.
//!
//! How each request reaches the kernel is in [`ifnet`].

mod ifnet;

use std::ffi::CStr;
use std::io::{self, BufWriter, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;

use ifnet::Ifnet;

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: ifconfig [-a] [-d] [-u]\n       ifconfig -l [-d] [-u]\n       \
         ifconfig interface [inet] [address[/prefixlen]] [netmask mask]\n                \
         [broadcast address] [alias | -alias | delete] [up | down]"
    );
    ExitCode::from(1)
}

/// The message for a failed request: the BSDs name the interface when it doesn't exist, and the
/// request otherwise.
fn ioctl_error(name: &str, e: &ifnet::Error) -> String {
    if e.no_such_interface() {
        format!("interface {name} does not exist")
    } else {
        format!("ioctl ({}): {}", ifnet::request_name(e.req), strerror(&e.err))
    }
}

/// An IPv4 address in dotted form only (no `inet_aton` shorthands such as `10.1`).
fn parse_addr(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}

/// The mask of a prefix length.
fn prefix_mask(len: u32) -> Ipv4Addr {
    Ipv4Addr::from(if len == 0 { 0 } else { u32::MAX << (32 - len) })
}

/// The class mask the BSDs give an address set without one.
fn classful_mask(a: Ipv4Addr) -> Ipv4Addr {
    match a.octets()[0] {
        0..=127 => prefix_mask(8),
        128..=191 => prefix_mask(16),
        _ => prefix_mask(24),
    }
}

/// A mask, dotted (`255.255.255.0`) or hexadecimal (`0xffffff00`); it must be contiguous.
fn parse_mask(s: &str) -> Option<Ipv4Addr> {
    let m = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) if !h.is_empty() && h.len() <= 8 => Ipv4Addr::from(u32::from_str_radix(h, 16).ok()?),
        Some(_) => return None,
        None => parse_addr(s)?,
    };
    let bits = u32::from(m);
    // Contiguous: the ones are all at the top.
    if bits.leading_ones() + bits.trailing_zeros() == 32 || bits == 0 { Some(m) } else { None }
}

/// `address[/prefixlen]`.
fn parse_cidr(s: &str) -> Option<(Ipv4Addr, Option<Ipv4Addr>)> {
    match s.split_once('/') {
        Some((a, len)) => {
            let len: u32 = len.parse().ok().filter(|&l| l <= 32 && !len.starts_with('+'))?;
            Some((parse_addr(a)?, Some(prefix_mask(len))))
        }
        None => Some((parse_addr(s)?, None)),
    }
}

fn broadcast_of(a: Ipv4Addr, m: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(a) | !u32::from(m))
}

#[derive(Debug, Default, PartialEq)]
enum AddrOp {
    /// Replace the address (or set it, if there's none).
    #[default]
    Set,
    Alias,
    Delete,
}

#[derive(Debug, Default, PartialEq)]
struct Change {
    addr: Option<Ipv4Addr>,
    mask: Option<Ipv4Addr>,
    broadcast: Option<Ipv4Addr>,
    op: AddrOp,
    /// `up` (true) or `down` (false), the last given.
    up: Option<bool>,
    /// Only `inet` was given: show the interface's IPv4 lines.
    show_inet: bool,
}

/// Parses what follows the interface name.
fn parse_change(args: &[String]) -> Result<Change, String> {
    let mut c = Change::default();
    let mut i = 0;
    if args.first().map(String::as_str) == Some("inet") {
        i = 1;
    } else if let Some(f) = args.first().filter(|a| matches!(a.as_str(), "inet6" | "link" | "ether" | "lladdr")) {
        return Err(format!("{f}: address family not supported"));
    }
    while i < args.len() {
        let a = args[i].as_str();
        let mut value = || -> Result<&str, String> {
            i += 1;
            args.get(i).map(String::as_str).ok_or_else(|| format!("{a}: missing argument"))
        };
        match a {
            "up" => c.up = Some(true),
            "down" => c.up = Some(false),
            "alias" | "add" => c.op = AddrOp::Alias,
            "-alias" | "delete" | "remove" => c.op = AddrOp::Delete,
            "netmask" => {
                let v = value()?;
                c.mask = Some(parse_mask(v).ok_or_else(|| format!("{v}: bad value"))?);
            }
            "broadcast" => {
                let v = value()?;
                c.broadcast = Some(parse_addr(v).ok_or_else(|| format!("{v}: bad value"))?);
            }
            "mtu" | "metric" | "media" | "mediaopt" | "lladdr" | "ether" | "description" | "name" | "vlan" => {
                return Err(format!("{a}: not supported by this system"));
            }
            _ if c.addr.is_none() => {
                let (addr, mask) = parse_cidr(a).ok_or_else(|| format!("{a}: bad value"))?;
                c.addr = Some(addr);
                if mask.is_some() {
                    c.mask = mask;
                }
            }
            _ => return Err(format!("{a}: bad value")),
        }
        i += 1;
    }
    c.show_inet = args.len() == 1 && args[0] == "inet";
    Ok(c)
}

/// What the interface ends up with: `None` for the address to remove it.
#[derive(Debug, PartialEq)]
struct Plan {
    addr: Option<Option<Ipv4Addr>>,
    mask: Option<Ipv4Addr>,
}

/// Decides the address and mask to set from the change and what the interface has now.
fn plan(c: &Change, current: Option<Ipv4Addr>, current_mask: Ipv4Addr, name: &str) -> Result<Plan, String> {
    match c.op {
        AddrOp::Delete => {
            let Some(cur) = current else {
                return Err("ioctl (SIOCDIFADDR): Can't assign requested address".into());
            };
            if c.addr.is_some_and(|a| a != cur) {
                return Err("ioctl (SIOCDIFADDR): Can't assign requested address".into());
            }
            Ok(Plan { addr: Some(None), mask: None })
        }
        AddrOp::Set | AddrOp::Alias => {
            let Some(addr) = c.addr else {
                // A mask (or a broadcast address) alone changes the current address's.
                if c.mask.is_none() && c.broadcast.is_none() {
                    return Ok(Plan { addr: None, mask: None });
                }
                let Some(cur) = current else {
                    return Err(format!("{name}: no address to change the mask of"));
                };
                let mask = c.mask.unwrap_or(current_mask);
                check_broadcast(c, cur, mask)?;
                return Ok(Plan { addr: None, mask: c.mask });
            };
            if addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast() {
                return Err(format!("{addr}: bad value"));
            }
            if c.op == AddrOp::Alias && current.is_some_and(|cur| cur != addr) {
                return Err(format!(
                    "{name}: only one address per interface (remove {} first)",
                    current.unwrap()
                ));
            }
            let mask = c.mask.unwrap_or_else(|| classful_mask(addr));
            check_broadcast(c, addr, mask)?;
            Ok(Plan { addr: Some(Some(addr)), mask: Some(mask) })
        }
    }
}

fn check_broadcast(c: &Change, addr: Ipv4Addr, mask: Ipv4Addr) -> Result<(), String> {
    match c.broadcast {
        Some(b) if b != broadcast_of(addr, mask) => {
            Err(format!("broadcast {b}: only the subnet's broadcast address ({}) can be used", broadcast_of(addr, mask)))
        }
        _ => Ok(()),
    }
}

fn flag_string(f: u32) -> String {
    let names: Vec<&str> = ifnet::BSD_FLAG_NAMES.iter().filter(|(b, _)| f & b != 0).map(|&(_, n)| n).collect();
    format!("flags={f:x}<{}>", names.join(","))
}

/// The interface's lines, FreeBSD's way.
fn describe(net: &Ifnet, name: &str, inet_only: bool) -> Result<String, ifnet::Error> {
    let kflags = net.flags(name)?;
    let flags = ifnet::bsd_flags(kflags);
    let mut s = String::new();
    if !inet_only {
        let mtu = net.mtu(name).unwrap_or(0);
        s += &format!("{name}: {} metric 0 mtu {mtu}\n", flag_string(flags));
        if let Ok(Some(m)) = net.ether(name) {
            s += &format!(
                "\tether {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                m[0], m[1], m[2], m[3], m[4], m[5]
            );
        }
    }
    if let Some(a) = net.addr(name)? {
        let mask = net.netmask(name).unwrap_or(Ipv4Addr::UNSPECIFIED);
        s += &format!("\tinet {a} netmask 0x{:08x}", u32::from(mask));
        if kflags & ifnet::IFF_BROADCAST != 0 {
            let b = net.broadcast(name).ok().filter(|b| !b.is_unspecified()).unwrap_or_else(|| broadcast_of(a, mask));
            s += &format!(" broadcast {b}");
        }
        s.push('\n');
    }
    Ok(s)
}

/// Makes the change. Errors are already worded for printing.
fn apply(net: &Ifnet, name: &str, c: &Change) -> Result<(), String> {
    let e = |err: ifnet::Error| ioctl_error(name, &err);
    let flags = net.flags(name).map_err(e)?;
    let current = net.addr(name).map_err(e)?;
    let current_mask = if current.is_some() { net.netmask(name).map_err(e)? } else { Ipv4Addr::UNSPECIFIED };
    let p = plan(c, current, current_mask, name)?;
    if let Some(addr) = p.addr {
        net.set_addr(name, addr.unwrap_or(Ipv4Addr::UNSPECIFIED)).map_err(e)?;
    }
    if let Some(mask) = p.mask {
        net.set_netmask(name, mask).map_err(e)?;
    }
    // As in the BSDs, giving an interface an address brings it up.
    let up = c.up.or(if matches!(p.addr, Some(Some(_))) { Some(true) } else { None });
    if let Some(up) = up {
        let flags = net.flags(name).unwrap_or(flags);
        let want = if up { flags | ifnet::IFF_UP } else { flags & !ifnet::IFF_UP };
        if want != flags {
            net.set_flags(name, want).map_err(e)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct ListOpts {
    all: bool,
    list: bool,
    only_up: bool,
    only_down: bool,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut o = ListOpts::default();
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i].len() > 1 {
        if args[i] == "--" {
            i += 1;
            break;
        }
        // `-alias` after an interface name is a keyword, never options.
        for ch in args[i][1..].chars() {
            match ch {
                'a' => o.all = true,
                'l' => o.list = true,
                'u' => o.only_up = true,
                'd' => o.only_down = true,
                _ => {
                    eprintln!("ifconfig: illegal option -- {ch}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    let rest = &args[i..];
    if o.list && !rest.is_empty() || (o.all && !rest.is_empty()) {
        return usage();
    }

    let net = match Ifnet::open() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("ifconfig: socket: {}", strerror(&e));
            return ExitCode::from(1);
        }
    };
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    if rest.is_empty() {
        let names = match net.names() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("ifconfig: {}", ioctl_error("", &e));
                return ExitCode::from(1);
            }
        };
        let names: Vec<String> = names
            .into_iter()
            .filter(|n| {
                let up = net.flags(n).map(|f| f & ifnet::IFF_UP != 0).unwrap_or(false);
                !(o.only_up && !up || o.only_down && up)
            })
            .collect();
        if o.list {
            let _ = writeln!(out, "{}", names.join(" "));
        } else {
            for n in &names {
                match describe(&net, n, false) {
                    Ok(s) => {
                        let _ = out.write_all(s.as_bytes());
                    }
                    // Gone in between: skip it.
                    Err(_) => continue,
                }
            }
        }
        if let Err(e) = out.flush() {
            eprintln!("ifconfig: stdout: {}", strerror(&e));
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    let name = rest[0].as_str();
    let change = match parse_change(&rest[1..]) {
        Ok(c) => c,
        Err(m) => {
            eprintln!("ifconfig: {m}");
            return ExitCode::from(1);
        }
    };
    if rest.len() == 1 || change.show_inet {
        match describe(&net, name, change.show_inet) {
            Ok(s) => {
                let _ = out.write_all(s.as_bytes());
            }
            Err(e) => {
                eprintln!("ifconfig: {}", ioctl_error(name, &e));
                return ExitCode::from(1);
            }
        }
        if let Err(e) = out.flush() {
            eprintln!("ifconfig: stdout: {}", strerror(&e));
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }
    if let Err(m) = apply(&net, name, &change) {
        eprintln!("ifconfig: {m}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(s: &str) -> Result<Change, String> {
        parse_change(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn masks() {
        assert_eq!(parse_mask("255.255.255.0"), Some(ip("255.255.255.0")));
        assert_eq!(parse_mask("0xffffff00"), Some(ip("255.255.255.0")));
        assert_eq!(parse_mask("0xff00ff00"), None);
        assert_eq!(parse_mask("255.0.255.0"), None);
        assert_eq!(parse_mask("0x"), None);
        assert_eq!(parse_mask("0x1ffffffff"), None);
        assert_eq!(parse_mask("0.0.0.0"), Some(ip("0.0.0.0")));
        assert_eq!(classful_mask(ip("10.0.2.15")), ip("255.0.0.0"));
        assert_eq!(classful_mask(ip("172.16.1.1")), ip("255.255.0.0"));
        assert_eq!(classful_mask(ip("192.168.1.1")), ip("255.255.255.0"));
    }

    #[test]
    fn cidr() {
        assert_eq!(parse_cidr("10.0.2.15/24"), Some((ip("10.0.2.15"), Some(ip("255.255.255.0")))));
        assert_eq!(parse_cidr("10.0.2.15/0"), Some((ip("10.0.2.15"), Some(ip("0.0.0.0")))));
        assert_eq!(parse_cidr("10.0.2.15/32"), Some((ip("10.0.2.15"), Some(ip("255.255.255.255")))));
        assert_eq!(parse_cidr("10.0.2.15/33"), None);
        assert_eq!(parse_cidr("10.0.2.15/+3"), None);
        assert_eq!(parse_cidr("10.1"), None);
        assert_eq!(parse_cidr("10.0.2.15"), Some((ip("10.0.2.15"), None)));
    }

    #[test]
    fn arguments() {
        let c = change("inet 10.0.2.15/24").unwrap();
        assert_eq!((c.addr, c.mask, c.op), (Some(ip("10.0.2.15")), Some(ip("255.255.255.0")), AddrOp::Set));
        let c = change("inet 10.0.2.15 netmask 255.255.255.0 broadcast 10.0.2.255 up").unwrap();
        assert_eq!((c.mask, c.broadcast, c.up), (Some(ip("255.255.255.0")), Some(ip("10.0.2.255")), Some(true)));
        assert_eq!(change("10.0.2.15 -alias").unwrap().op, AddrOp::Delete);
        assert_eq!(change("delete").unwrap().op, AddrOp::Delete);
        assert_eq!(change("inet 10.0.2.15 alias").unwrap().op, AddrOp::Alias);
        assert!(change("inet").unwrap().show_inet);
        assert!(change("inet6 ::1").is_err());
        assert!(change("mtu 9000").is_err());
        assert!(change("netmask").is_err());
        assert!(change("1.2.3.4 5.6.7.8").is_err());
        assert!(change("bogus").is_err());
    }

    #[test]
    fn plans() {
        let none = Ipv4Addr::UNSPECIFIED;
        let p = plan(&change("10.0.2.15").unwrap(), None, none, "rl0").unwrap();
        assert_eq!(p, Plan { addr: Some(Some(ip("10.0.2.15"))), mask: Some(ip("255.0.0.0")) });
        // alias adds only where there's no address.
        assert!(plan(&change("10.0.2.16 alias").unwrap(), Some(ip("10.0.2.15")), ip("255.255.255.0"), "rl0").is_err());
        assert!(plan(&change("10.0.2.15/24 alias").unwrap(), Some(ip("10.0.2.15")), ip("255.0.0.0"), "rl0").is_ok());
        // A plain address replaces.
        assert!(plan(&change("10.0.2.16/24").unwrap(), Some(ip("10.0.2.15")), ip("255.255.255.0"), "rl0").is_ok());
        // Delete: the address must match.
        assert!(plan(&change("10.0.2.16 -alias").unwrap(), Some(ip("10.0.2.15")), none, "rl0").is_err());
        assert_eq!(plan(&change("delete").unwrap(), Some(ip("10.0.2.15")), none, "rl0").unwrap().addr, Some(None));
        assert!(plan(&change("delete").unwrap(), None, none, "rl0").is_err());
        // Broadcast must be the subnet's.
        assert!(plan(&change("10.0.2.15/24 broadcast 10.0.2.255").unwrap(), None, none, "rl0").is_ok());
        assert!(plan(&change("10.0.2.15/24 broadcast 10.0.255.255").unwrap(), None, none, "rl0").is_err());
        // A mask alone.
        let p = plan(&change("netmask 255.255.0.0").unwrap(), Some(ip("10.0.2.15")), ip("255.0.0.0"), "rl0").unwrap();
        assert_eq!(p, Plan { addr: None, mask: Some(ip("255.255.0.0")) });
        assert!(plan(&change("255.255.255.255").unwrap(), None, none, "rl0").is_err());
    }

    #[test]
    fn flags() {
        let rl0 = ifnet::IFF_UP | ifnet::IFF_BROADCAST | ifnet::IFF_RUNNING | ifnet::IFF_MULTICAST;
        assert_eq!(flag_string(ifnet::bsd_flags(rl0)), "flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>");
        let lo0 = ifnet::IFF_UP | ifnet::IFF_LOOPBACK | ifnet::IFF_RUNNING | ifnet::IFF_MULTICAST;
        assert_eq!(flag_string(ifnet::bsd_flags(lo0)), "flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>");
        assert_eq!(flag_string(ifnet::bsd_flags(ifnet::IFF_LOOPBACK)), "flags=8<LOOPBACK>");
    }
}
