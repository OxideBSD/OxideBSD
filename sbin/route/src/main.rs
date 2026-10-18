//! `route(8)`: shows and sets the IPv4 default route.
//!
//! ```text
//! route [-nqv] add [-inet] [-net] default gateway
//! route [-nqv] change [-inet] [-net] default gateway
//! route [-nqv] delete [-inet] [-net] default [gateway]
//! route [-nqv] get [-inet] default | address
//! route [-nqv] show
//! route [-nqv] flush
//! ```
//!
//! OxideBSD's kernel has no routing table yet: an interface's subnet is reached directly, and
//! everything else through the one default gateway. So `add`, `change` and `delete` take only
//! the default route (`default`, `0.0.0.0` or `0.0.0.0/0`); any other destination is refused
//! with `EX_UNAVAILABLE`. `get` answers for the default or for any address, as FreeBSD's does,
//! and `show` lists the routes there are, in `netstat -rn`'s form: the default, each configured
//! interface's subnet, and the host routes of its addresses. Addresses are always shown as
//! numbers.
//!
//! The messages are FreeBSD's (`add net default: gateway 10.0.2.2`). How the default route
//! reaches the kernel is in [`gateway`], the interfaces in [`ifnet`].

mod gateway;
#[allow(dead_code)]
mod ifnet;

use std::ffi::CStr;
use std::io::{self, BufWriter, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;

const EX_USAGE: u8 = 64;
const EX_NOHOST: u8 = 68;
const EX_UNAVAILABLE: u8 = 69;
const EX_OSERR: u8 = 71;
const EX_NOPERM: u8 = 77;

fn strerror(e: &io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a NUL-terminated static string.
        Some(n) => unsafe { CStr::from_ptr(libc::strerror(n)) }.to_string_lossy().into_owned(),
        None => e.to_string(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: route [-nqv] add|change [-inet] [-net] default gateway\n       \
         route [-nqv] delete [-inet] [-net] default [gateway]\n       \
         route [-nqv] get [-inet] default | address\n       \
         route [-nqv] show | flush"
    );
    ExitCode::from(EX_USAGE)
}

/// The message and status for a failed reach of the default route.
fn gateway_error(e: &io::Error) -> ExitCode {
    if e.kind() == io::ErrorKind::Unsupported {
        eprintln!("route: this system has no settable default route ({} does not exist)", gateway::NAME);
        return ExitCode::from(EX_UNAVAILABLE);
    }
    eprintln!("route: {}: {}", gateway::NAME, strerror(e));
    ExitCode::from(if e.raw_os_error() == Some(libc::EPERM) { EX_NOPERM } else { EX_OSERR })
}

#[derive(Debug, PartialEq)]
enum Cmd {
    Add(Ipv4Addr),
    Change(Ipv4Addr),
    Delete(Option<Ipv4Addr>),
    Get(Option<Ipv4Addr>),
    Show,
    Flush,
}

#[derive(Debug, Default)]
struct Flags {
    quiet: bool,
    verbose: bool,
}

/// Why a command line was refused: the message, and the exit status.
#[derive(Debug, PartialEq)]
struct Refusal(String, u8);

fn is_default(dest: &str) -> bool {
    matches!(dest, "default" | "0.0.0.0" | "0.0.0.0/0" | "0/0" | "0")
}

/// Parses a command after the options.
fn parse_cmd(args: &[String]) -> Result<Cmd, Refusal> {
    let usage_err = || Refusal(String::new(), EX_USAGE);
    let (cmd, rest) = args.split_first().ok_or_else(usage_err)?;
    // The modifiers that change nothing here: the address family, and -net, which `default`
    // implies. A netmask is accepted only when it is the default route's.
    let mut words: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "-inet" | "-4" | "-net" | "-static" => {}
            "-netmask" => {
                i += 1;
                match rest.get(i).map(String::as_str) {
                    Some("0.0.0.0") | Some("0") => {}
                    Some(_) => return Err(Refusal("only the default route can be set".into(), EX_UNAVAILABLE)),
                    None => return Err(usage_err()),
                }
            }
            "-inet6" | "-6" => return Err(Refusal("IPv6 is not supported".into(), EX_UNAVAILABLE)),
            "-host" if cmd != "get" => return Err(Refusal("only the default route can be set".into(), EX_UNAVAILABLE)),
            "-host" => {}
            w if w.starts_with('-') && cmd != "get" => {
                return Err(Refusal(format!("{w}: not supported (only the default route can be set)"), EX_UNAVAILABLE));
            }
            w => words.push(w),
        }
        i += 1;
    }
    let gw = |s: &str| -> Result<Ipv4Addr, Refusal> {
        s.parse().map_err(|_| Refusal(format!("bad address: {s}"), EX_NOHOST))
    };
    match cmd.as_str() {
        "add" | "change" => {
            let [dest, g] = words[..] else { return Err(usage_err()) };
            if !is_default(dest) {
                return Err(Refusal("only the default route can be set".into(), EX_UNAVAILABLE));
            }
            let g = gw(g)?;
            if g.is_unspecified() || g.is_broadcast() || g.is_multicast() {
                return Err(Refusal(format!("bad address: {g}"), EX_NOHOST));
            }
            Ok(if cmd == "add" { Cmd::Add(g) } else { Cmd::Change(g) })
        }
        "delete" => match words[..] {
            [dest] if is_default(dest) => Ok(Cmd::Delete(None)),
            [dest, g] if is_default(dest) => Ok(Cmd::Delete(Some(gw(g)?))),
            [_] | [_, _] => Err(Refusal("only the default route can be set".into(), EX_UNAVAILABLE)),
            _ => Err(usage_err()),
        },
        "get" => match words[..] {
            [dest] if is_default(dest) => Ok(Cmd::Get(None)),
            [dest] => Ok(Cmd::Get(Some(gw(dest.split('/').next().unwrap_or(dest))?))),
            _ => Err(usage_err()),
        },
        "show" | "print" if words.is_empty() => Ok(Cmd::Show),
        "flush" if words.is_empty() => Ok(Cmd::Flush),
        "monitor" => Err(Refusal("monitor: no routing socket on this system".into(), EX_UNAVAILABLE)),
        _ => Err(usage_err()),
    }
}

/// One configured interface: its name, index, address, mask, MTU, and whether it loops back.
struct Iface {
    name: String,
    index: i32,
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    mtu: u32,
    loopback: bool,
}

fn interfaces() -> Vec<Iface> {
    let Ok(net) = ifnet::Ifnet::open() else { return Vec::new() };
    let mut v = Vec::new();
    for name in net.names().unwrap_or_default() {
        let Ok(flags) = net.flags(&name) else { continue };
        let Ok(Some(addr)) = net.addr(&name) else { continue };
        if flags & ifnet::IFF_UP == 0 {
            continue;
        }
        v.push(Iface {
            index: net.index(&name).unwrap_or(0),
            mask: net.netmask(&name).unwrap_or(Ipv4Addr::BROADCAST),
            mtu: net.mtu(&name).unwrap_or(0),
            loopback: flags & ifnet::IFF_LOOPBACK != 0,
            addr,
            name,
        });
    }
    v
}

fn in_subnet(a: Ipv4Addr, net: Ipv4Addr, mask: Ipv4Addr) -> bool {
    u32::from(a) & u32::from(mask) == u32::from(net) & u32::from(mask)
}

/// The interface a gateway is reached through: the one whose subnet holds it.
fn iface_for(ifs: &[Iface], a: Ipv4Addr) -> Option<&Iface> {
    ifs.iter().filter(|i| !i.loopback).find(|i| in_subnet(a, i.addr, i.mask))
        .or_else(|| ifs.iter().find(|i| in_subnet(a, i.addr, i.mask)))
}

fn prefix_len(mask: Ipv4Addr) -> u32 {
    u32::from(mask).leading_ones()
}

/// `route get`, FreeBSD's layout.
fn get_report(dest: Option<Ipv4Addr>, gw: Option<Ipv4Addr>, ifs: &[Iface]) -> Option<String> {
    let mut s = String::new();
    let line = |s: &mut String, k: &str, v: &str| s.push_str(&format!("{k:>11}: {v}\n"));
    let target = dest.map_or("default".to_string(), |d| d.to_string());
    line(&mut s, "route to", &target);
    let (iface, flags) = match dest {
        Some(d) if ifs.iter().any(|i| i.addr == d) => {
            line(&mut s, "destination", &d.to_string());
            (ifs.iter().find(|i| i.loopback), "<UP,HOST,DONE,STATIC>")
        }
        Some(d) if iface_for(ifs, d).is_some() => {
            let i = iface_for(ifs, d).unwrap();
            let net = Ipv4Addr::from(u32::from(i.addr) & u32::from(i.mask));
            line(&mut s, "destination", &net.to_string());
            line(&mut s, "mask", &i.mask.to_string());
            (Some(i), "<UP,DONE,PINNED>")
        }
        _ => {
            let gw = gw?;
            line(&mut s, "destination", "default");
            line(&mut s, "mask", "default");
            line(&mut s, "gateway", &gw.to_string());
            (iface_for(ifs, gw), "<UP,GATEWAY,DONE,STATIC>")
        }
    };
    line(&mut s, "fib", "0");
    line(&mut s, "interface", iface.map_or("-", |i| i.name.as_str()));
    line(&mut s, "flags", flags);
    s.push_str(" recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire\n");
    s.push_str(&format!(
        "{:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}\n",
        0,
        0,
        0,
        0,
        iface.map_or(0, |i| i.mtu),
        1,
        0
    ));
    Some(s)
}

/// `route show`: `netstat -rn`'s Internet table.
fn show_report(gw: Option<Ipv4Addr>, ifs: &[Iface]) -> String {
    let mut s = String::from("Routing tables\n\nInternet:\n");
    let row = |s: &mut String, d: &str, g: &str, f: &str, i: &str| {
        s.push_str(&format!("{d:<18} {g:<18} {f:<8} {i:>6}\n"));
    };
    row(&mut s, "Destination", "Gateway", "Flags", "Netif");
    if let Some(g) = gw {
        row(&mut s, "default", &g.to_string(), "UGS", iface_for(ifs, g).map_or("-", |i| i.name.as_str()));
    }
    let lo = ifs.iter().find(|i| i.loopback);
    for i in ifs {
        let link = format!("link#{}", i.index);
        if i.loopback {
            row(&mut s, &i.addr.to_string(), &link, "UH", &i.name);
            continue;
        }
        let net = Ipv4Addr::from(u32::from(i.addr) & u32::from(i.mask));
        row(&mut s, &format!("{net}/{}", prefix_len(i.mask)), &link, "U", &i.name);
        let (lo_link, lo_name) = lo.map_or((link.clone(), i.name.as_str()), |l| (format!("link#{}", l.index), l.name.as_str()));
        row(&mut s, &i.addr.to_string(), &lo_link, "UHS", lo_name);
    }
    s
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut f = Flags::default();
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i].len() > 1 {
        if args[i] == "--" {
            i += 1;
            break;
        }
        for ch in args[i][1..].chars() {
            match ch {
                // Addresses are always numbers here.
                'n' => {}
                'q' => f.quiet = true,
                'v' => f.verbose = true,
                _ => {
                    eprintln!("route: illegal option -- {ch}");
                    return usage();
                }
            }
        }
        i += 1;
    }
    let cmd = match parse_cmd(&args[i..]) {
        Ok(c) => c,
        Err(Refusal(m, code)) => {
            if code == EX_USAGE && m.is_empty() {
                return usage();
            }
            eprintln!("route: {m}");
            return ExitCode::from(code);
        }
    };
    let changes = matches!(cmd, Cmd::Add(_) | Cmd::Change(_) | Cmd::Delete(_) | Cmd::Flush);
    // SAFETY: geteuid can't fail.
    if changes && unsafe { libc::geteuid() } != 0 {
        eprintln!("route: must be root to alter routing table");
        return ExitCode::from(EX_NOPERM);
    }
    let current = match gateway::get() {
        Ok(g) => g,
        // Reading the routes still works without the variable: there's just no default.
        Err(e) if !changes && e.kind() == io::ErrorKind::Unsupported => {
            eprintln!("route: warning: {} does not exist; no default route shown", gateway::NAME);
            None
        }
        Err(e) => return gateway_error(&e),
    };
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut status = ExitCode::SUCCESS;
    match cmd {
        Cmd::Add(g) => {
            if current.is_some() {
                eprintln!("route: writing to routing socket: File exists");
                let _ = writeln!(out, "add net default: gateway {g} fib 0: route already in table");
                status = ExitCode::from(1);
            } else if let Err(e) = gateway::set(Some(g)) {
                return gateway_error(&e);
            } else if !f.quiet {
                let _ = writeln!(out, "add net default: gateway {g}");
            }
        }
        Cmd::Change(g) => {
            if current.is_none() {
                eprintln!("route: writing to routing socket: No such process");
                let _ = writeln!(out, "change net default: gateway {g} fib 0: not in table");
                status = ExitCode::from(1);
            } else if let Err(e) = gateway::set(Some(g)) {
                return gateway_error(&e);
            } else if !f.quiet {
                let _ = writeln!(out, "change net default: gateway {g}");
            }
        }
        Cmd::Delete(want) => match current {
            Some(cur) if want.is_none_or(|w| w == cur) => {
                if let Err(e) = gateway::set(None) {
                    return gateway_error(&e);
                }
                if !f.quiet {
                    let _ = writeln!(out, "delete net default: gateway {cur}");
                }
            }
            _ => {
                eprintln!("route: writing to routing socket: No such process");
                let _ = writeln!(out, "delete net default: not in table");
                status = ExitCode::from(1);
            }
        },
        Cmd::Flush => {
            if let Some(cur) = current {
                if let Err(e) = gateway::set(None) {
                    return gateway_error(&e);
                }
                if !f.quiet {
                    let _ = writeln!(out, "{:<29} {:<19} done", "default", cur.to_string());
                }
            }
        }
        Cmd::Get(dest) => match get_report(dest, current, &interfaces()) {
            Some(s) => {
                let _ = out.write_all(s.as_bytes());
            }
            None => {
                eprintln!("route: route has not been found");
                status = ExitCode::from(1);
            }
        },
        Cmd::Show => {
            let _ = out.write_all(show_report(current, &interfaces()).as_bytes());
        }
    }
    if f.verbose && changes {
        let _ = writeln!(out, "default gateway now: {}", gateway::get().ok().flatten().map_or("none".into(), |g| g.to_string()));
    }
    if let Err(e) = out.flush() {
        eprintln!("route: stdout: {}", strerror(&e));
        return ExitCode::from(1);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(s: &str) -> Result<Cmd, Refusal> {
        parse_cmd(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn commands() {
        assert_eq!(cmd("add default 10.0.2.2"), Ok(Cmd::Add(ip("10.0.2.2"))));
        assert_eq!(cmd("add -inet -net 0.0.0.0/0 10.0.2.2"), Ok(Cmd::Add(ip("10.0.2.2"))));
        assert_eq!(cmd("add -net 0.0.0.0 -netmask 0.0.0.0 10.0.2.2"), Ok(Cmd::Add(ip("10.0.2.2"))));
        assert_eq!(cmd("change default 10.0.2.3"), Ok(Cmd::Change(ip("10.0.2.3"))));
        assert_eq!(cmd("delete default"), Ok(Cmd::Delete(None)));
        assert_eq!(cmd("delete default 10.0.2.2"), Ok(Cmd::Delete(Some(ip("10.0.2.2")))));
        assert_eq!(cmd("get default"), Ok(Cmd::Get(None)));
        assert_eq!(cmd("get 10.0.2.9"), Ok(Cmd::Get(Some(ip("10.0.2.9")))));
        assert_eq!(cmd("get -host 10.0.2.9"), Ok(Cmd::Get(Some(ip("10.0.2.9")))));
        assert_eq!(cmd("show"), Ok(Cmd::Show));
        assert_eq!(cmd("flush"), Ok(Cmd::Flush));
    }

    #[test]
    fn refusals() {
        let unavailable = |s: &str| matches!(cmd(s), Err(Refusal(_, EX_UNAVAILABLE)));
        assert!(unavailable("add -net 192.168.0.0/24 10.0.2.2"));
        assert!(unavailable("add 192.168.0.0 10.0.2.2"));
        assert!(unavailable("add -host 10.0.3.4 10.0.2.2"));
        assert!(unavailable("add -net 0.0.0.0 -netmask 255.0.0.0 10.0.2.2"));
        assert!(unavailable("delete 10.1.0.0"));
        assert!(unavailable("add -inet6 default ::1"));
        assert!(unavailable("add default 10.0.2.2 -mtu 1400"));
        assert_eq!(cmd("add default gw.example"), Err(Refusal("bad address: gw.example".into(), EX_NOHOST)));
        assert!(matches!(cmd("add default 255.255.255.255"), Err(Refusal(_, EX_NOHOST))));
        assert!(matches!(cmd("add default"), Err(Refusal(_, EX_USAGE))));
        assert!(matches!(cmd(""), Err(Refusal(_, EX_USAGE))));
        assert!(matches!(cmd("frob"), Err(Refusal(_, EX_USAGE))));
    }

    fn ifs() -> Vec<Iface> {
        vec![
            Iface { name: "rl0".into(), index: 1, addr: ip("10.0.2.15"), mask: ip("255.255.255.0"), mtu: 1500, loopback: false },
            Iface { name: "lo0".into(), index: 2, addr: ip("127.0.0.1"), mask: ip("255.0.0.0"), mtu: 16384, loopback: true },
        ]
    }

    #[test]
    fn reports() {
        let s = show_report(Some(ip("10.0.2.2")), &ifs());
        assert!(s.contains("\ndefault            10.0.2.2           UGS         rl0\n"), "{s}");
        assert!(s.contains("\n10.0.2.0/24        link#1             U           rl0\n"), "{s}");
        assert!(s.contains("\n10.0.2.15          link#2             UHS         lo0\n"), "{s}");
        assert!(s.contains("\n127.0.0.1          link#2             UH          lo0\n"), "{s}");
        let g = get_report(None, Some(ip("10.0.2.2")), &ifs()).unwrap();
        assert!(g.contains("    gateway: 10.0.2.2\n") && g.contains("  interface: rl0\n"), "{g}");
        assert!(g.contains("1500"), "{g}");
        assert!(get_report(None, None, &ifs()).is_none());
        let g = get_report(Some(ip("10.0.2.77")), None, &ifs()).unwrap();
        assert!(g.contains("destination: 10.0.2.0\n") && !g.contains("gateway"), "{g}");
        assert!(get_report(Some(ip("8.8.8.8")), None, &ifs()).is_none());
        assert_eq!(gateway::parse(b"10.0.2.2\0").unwrap(), Some(ip("10.0.2.2")));
        assert_eq!(gateway::parse(b"").unwrap(), None);
        assert_eq!(gateway::parse(b"\0").unwrap(), None);
        assert!(gateway::parse(b"10.0.2").is_err());
    }
}
