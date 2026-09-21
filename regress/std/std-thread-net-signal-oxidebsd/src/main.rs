//! Extends v0.3.0's real `std` consumer proof past `std-process-fs-oxidebsd` (fs +
//! `process::Command`) into `std::thread`, `std::net`, and signal handling -- see
//! `OxideBSD-doc/ROADMAP.md`'s v0.3.0 entry.
//!
//! No `#![feature(restricted_std)]` -- same real, fully-supported target as the other
//! `regress/std/*-oxidebsd` crates.

use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// Matches `sys/net/ipv4.rs`'s own `GUEST_IP` -- the one real address this kernel's single NIC
/// answers to (no loopback interface exists, so this proves real socket()/bind()/listen()/
/// accept() plumbing through `std::net`, not a full external round trip -- see this crate's own
/// `test_net` doc comment).
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

fn test_threads() {
    // Real std::thread::spawn + join.
    let handle = thread::spawn(|| 21 + 21);
    let result = handle.join().expect("thread panicked");
    assert_eq!(result, 42, "joined thread returned the wrong value");

    // Real shared-state synchronization: Arc<Mutex<_>> across genuinely concurrent threads --
    // pthread_mutex is pure userspace logic over real futex(2) (see CLAUDE.md's "Real threading"
    // section), not kernel-mode locking, so this is a real test of that whole chain.
    let counter = Arc::new(Mutex::new(0u32));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let counter = Arc::clone(&counter);
            thread::spawn(move || {
                for _ in 0..1000 {
                    *counter.lock().expect("mutex poisoned") += 1;
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker thread panicked");
    }
    assert_eq!(
        *counter.lock().expect("mutex poisoned"),
        4000,
        "lost updates across real threads -- Arc<Mutex<_>> synchronization is broken"
    );

    println!("std-thread-net-signal-oxidebsd: std::thread (spawn/join + Arc<Mutex<_>>) real and correct");
}

fn test_signals() {
    // Real SIGPIPE-ignored-at-startup behavior: std's runtime init installs SIG_IGN for SIGPIPE
    // so a broken pipe surfaces as a real io::Error, not a silent process kill -- the thing that
    // would otherwise make almost every real Unix CLI tool unusable.
    let mut child = Command::new("/bin/true")
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to spawn /bin/true");
    // Take stdin *before* wait() -- Child::wait()'s own documented behavior is to close the
    // child's stdin handle first (deadlock avoidance), which would drop our write end too if we
    // waited first. /bin/true exits immediately without ever reading stdin; wait() reaps it,
    // which tears down its fd table and closes the pipe's read end for real.
    let mut stdin = child.stdin.take().expect("child stdin missing");
    child.wait().expect("failed to wait for /bin/true");
    match stdin.write_all(b"written after the read end closed\n") {
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("expected a broken-pipe error, got {e:?}"),
        Ok(()) => panic!("expected a broken-pipe error, write_all reported success"),
    }

    // Real signal delivery + real wait(2)-encoded status decoding: Child::kill() issues a real
    // SIGKILL via libc::kill, and ExitStatusExt::signal() must correctly decode the kernel's own
    // non-shifted "128 + sig"-shaped signal-termination status (see CLAUDE.md's "Process
    // abstraction..." section on do_wait4's status encoding).
    let mut child = Command::new("/bin/sleep")
        .arg("100")
        .spawn()
        .expect("failed to spawn /bin/sleep");
    child.kill().expect("failed to kill /bin/sleep");
    let status = child.wait().expect("failed to wait for killed /bin/sleep");
    assert!(!status.success(), "killed child reported success");
    assert_eq!(
        status.signal(),
        Some(9),
        "expected SIGKILL (9), got {:?}",
        status.signal()
    );

    println!(
        "std-thread-net-signal-oxidebsd: signals (SIGPIPE-ignored write + SIGKILL/ExitStatusExt) real and correct"
    );
}

fn test_net() {
    // Real socket()/bind()/getsockname() through std::net::UdpSocket. No loopback interface
    // exists on this kernel (single real NIC, see sys/net/ipv4.rs's own doc comment) -- this
    // proves the real plumbing works, not a full external round trip.
    let udp = UdpSocket::bind((GUEST_IP, 0)).expect("UdpSocket::bind failed");
    let local = udp.local_addr().expect("UdpSocket::local_addr failed");
    assert_eq!(local.ip(), GUEST_IP, "bound UDP socket reported the wrong address");

    // Real socket()/bind()/listen() through std::net::TcpListener, plus real O_NONBLOCK
    // (fcntl) + a real EAGAIN-returning accept() path (sys/net/tcp.rs's oxidebsd_sys_accept).
    let listener = TcpListener::bind((GUEST_IP, 0)).expect("TcpListener::bind failed");
    let local = listener
        .local_addr()
        .expect("TcpListener::local_addr failed");
    assert_eq!(local.ip(), GUEST_IP, "bound TCP listener reported the wrong address");
    listener
        .set_nonblocking(true)
        .expect("TcpListener::set_nonblocking failed");
    match listener.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        other => panic!("expected WouldBlock (no real peer ever connects), got {other:?}"),
    }

    println!(
        "std-thread-net-signal-oxidebsd: std::net (UDP bind/local_addr, TCP bind/listen/nonblocking accept) real and correct"
    );
}

fn main() {
    test_threads();
    test_signals();
    test_net();

    println!(
        "std-thread-net-signal-oxidebsd: threads + signals + net all real, target_os = {}",
        std::env::consts::OS
    );

    std::process::exit(42);
}
