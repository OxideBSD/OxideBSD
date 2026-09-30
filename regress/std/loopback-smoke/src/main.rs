//! The loopback interface, `lo0` (`sys/net/ifnet.rs`, `if_loop.rs`), from a program: seeded as
//! `/usr/tests/net/loopback-smoke` and run by `regress/loopback-syscall-smoke/run.sh`. Prints one
//! line per check; exits with the number of failures.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
/// rl0's address: the host itself, reached over lo0 too.
const OWN: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

fn check(what: &str, r: Result<()>, failed: &mut i32) {
    match r {
        Ok(()) => println!("loopback-smoke: ok: {what}"),
        Err(e) => {
            println!("loopback-smoke: FAIL: {what}: {e}");
            *failed += 1;
        }
    }
}

fn ensure(cond: bool, why: &str) -> Result<()> {
    if cond { Ok(()) } else { Err(why.to_string().into()) }
}

fn localhost_resolves() -> Result<()> {
    let addrs: Vec<SocketAddr> = ("localhost", 7).to_socket_addrs()?.collect();
    ensure(addrs.iter().any(|a| a.ip() == IpAddr::V4(LOCALHOST)), &format!("got {addrs:?}"))
}

fn udp_round_trip(to: Ipv4Addr, bind_rx: Ipv4Addr) -> Result<()> {
    let rx = UdpSocket::bind((bind_rx, 0))?;
    let rx_port = rx.local_addr()?.port();
    rx.set_read_timeout(Some(Duration::from_secs(5)))?;
    let tx = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    tx.send_to(b"over lo0", (to, rx_port))?;
    let mut buf = [0u8; 64];
    let (n, from) = rx.recv_from(&mut buf)?;
    ensure(&buf[..n] == b"over lo0", "wrong datagram")?;
    // The sender's source is the destination's own kind of address, as the route picks it.
    ensure(from.ip() == IpAddr::V4(to), &format!("from {from}"))?;
    ensure(rx.local_addr()?.ip() == IpAddr::V4(bind_rx), &format!("bound {}", rx.local_addr()?))
}

fn tcp_echo() -> Result<()> {
    let listener = TcpListener::bind((LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    ensure(addr.ip() == IpAddr::V4(LOCALHOST), &format!("listener at {addr}"))?;
    let server = std::thread::spawn(move || -> Result<()> {
        let (mut s, peer) = listener.accept()?;
        ensure(peer.ip() == IpAddr::V4(LOCALHOST), &format!("peer {peer}"))?;
        let mut buf = vec![0u8; 10_000];
        s.read_exact(&mut buf)?;
        s.write_all(&buf)?;
        Ok(())
    });
    let mut c = TcpStream::connect(addr)?;
    c.set_read_timeout(Some(Duration::from_secs(30)))?;
    ensure(c.local_addr()?.ip() == IpAddr::V4(LOCALHOST), &format!("client at {}", c.local_addr()?))?;
    ensure(c.peer_addr()? == addr, "peer_addr")?;
    // Larger than one segment (536-byte MSS): the stop-and-wait exchange over lo0.
    let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
    c.write_all(&data)?;
    let mut back = vec![0u8; data.len()];
    c.read_exact(&mut back)?;
    server.join().map_err(|_| "server panicked")??;
    ensure(back == data, "echoed bytes differ")
}

fn bound_listener_ignores_other_address() -> Result<()> {
    let listener = TcpListener::bind((LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    match TcpStream::connect_timeout(&SocketAddr::from((OWN, port)), Duration::from_secs(5)) {
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => Ok(()),
        Err(e) => Err(format!("expected refused, got {e}").into()),
        Ok(_) => Err("connected to a listener bound to 127.0.0.1 through 10.0.2.15".into()),
    }
}

fn closed_port_refused() -> Result<()> {
    let start = Instant::now();
    match TcpStream::connect((LOCALHOST, 1)) {
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
            // A reset over lo0, not a SYN timing out.
            ensure(start.elapsed() < Duration::from_secs(2), &format!("took {:?}", start.elapsed()))
        }
        Err(e) => Err(format!("expected refused, got {e}").into()),
        Ok(_) => Err("connected to port 1".into()),
    }
}

fn foreign_address_not_available() -> Result<()> {
    match UdpSocket::bind((Ipv4Addr::new(10, 0, 2, 99), 0)) {
        Err(e) if e.kind() == ErrorKind::AddrNotAvailable => {}
        other => return Err(format!("UDP: {other:?}").into()),
    }
    match TcpListener::bind((Ipv4Addr::new(192, 0, 2, 1), 0)) {
        Err(e) if e.kind() == ErrorKind::AddrNotAvailable => Ok(()),
        other => Err(format!("TCP: {other:?}").into()),
    }
}

fn main() {
    let mut failed = 0;
    check("localhost resolves to 127.0.0.1", localhost_resolves(), &mut failed);
    check("UDP over 127.0.0.1", udp_round_trip(LOCALHOST, LOCALHOST), &mut failed);
    check("UDP to the host's own address", udp_round_trip(OWN, Ipv4Addr::UNSPECIFIED), &mut failed);
    check("TCP echo of 10000 bytes over 127.0.0.1", tcp_echo(), &mut failed);
    check("a listener on 127.0.0.1 refuses 10.0.2.15", bound_listener_ignores_other_address(), &mut failed);
    check("a closed port is refused at once", closed_port_refused(), &mut failed);
    check("binding another host's address is EADDRNOTAVAIL", foreign_address_not_available(), &mut failed);
    std::process::exit(failed);
}
