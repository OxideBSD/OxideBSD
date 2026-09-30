//! TCP and TLS between two syslogd processes on the host (`SYSLOG.md` §12.1): a sender whose
//! rule forwards everything, a receiver whose rule writes everything to a file. Each daemon gets
//! its own local socket (`-l`), pid file (`-P`), UDP port (`-b 127.0.0.1:0`) and scratch directory.
//!
//! Not as root: syslogd always binds `/dev/log` too, which as an ordinary user fails harmlessly,
//! but as root would replace the host's.

use std::io::Read;
use std::net::TcpListener;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Builder, X509NameBuilder};

struct Daemon {
    child: Child,
    socket: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    fn start(dir: &Path, name: &str, config: &str) -> Daemon {
        let conf = dir.join(format!("{name}.conf"));
        std::fs::write(&conf, config).unwrap();
        // A socket's path has to fit sun_path (about 100 bytes); the scratch directory's doesn't.
        let short = std::env::temp_dir().join(format!("syslogd-t{}", std::process::id()));
        std::fs::create_dir_all(&short).unwrap();
        let socket = short.join(format!("{}-{name}", dir.file_name().unwrap().to_str().unwrap()));
        let child = Command::new(env!("CARGO_BIN_EXE_syslogd"))
            .args(["-d", "-C", "-b", "127.0.0.1:0", "-f"])
            .arg(&conf)
            .arg("-P")
            .arg(dir.join(format!("{name}.pid")))
            .arg("-l")
            .arg(&socket)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "{name} didn't start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Daemon { child, socket }
    }

    fn log(&self, text: &str) {
        UnixDatagram::unbound().unwrap().send_to(format!("<13>test: {text}").as_bytes(), &self.socket).unwrap();
    }

    /// Stops it and returns what it wrote to standard error (its own messages, with -d).
    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let mut err = String::new();
        self.child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
        err
    }
}

fn scratch(name: &str) -> Option<PathBuf> {
    // SAFETY: geteuid(2) can't fail.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("not run as root: syslogd would replace the host's /dev/log");
        return None;
    }
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Some(dir)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Whether `file` comes to hold `text` within a few seconds.
fn arrives(file: &Path, text: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if std::fs::read_to_string(file).is_ok_and(|s| s.contains(text)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn key() -> PKey<Private> {
    PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap()).unwrap()
}

/// A certificate for `cn` (also its `subjectAltName`), signed by `issuer` or itself.
fn cert(cn: &str, key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>, ca: bool) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(issuer.map_or(&*name, |(c, _)| c.subject_name())).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    if ca {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    } else {
        let san = SubjectAlternativeName::new().dns(cn).build(&b.x509v3_context(issuer.map(|(c, _)| &**c), None)).unwrap();
        b.append_extension(san).unwrap();
    }
    b.sign(issuer.map_or(key, |(_, k)| k), MessageDigest::sha256()).unwrap();
    b.build()
}

fn write_pem(dir: &Path, name: &str, key: &PKey<Private>, cert: &X509) -> (PathBuf, PathBuf) {
    let (k, c) = (dir.join(format!("{name}.key")), dir.join(format!("{name}.pem")));
    std::fs::write(&k, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    std::fs::write(&c, cert.to_pem().unwrap()).unwrap();
    (k, c)
}

fn fingerprint(cert: &X509) -> String {
    let d = cert.digest(MessageDigest::sha256()).unwrap();
    "SHA-256:".to_string() + &d.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

#[test]
fn tcp() {
    let Some(dir) = scratch("tcp") else { return };
    let port = free_port();
    let out = dir.join("received.log");
    let rx = Daemon::start(
        &dir,
        "rx",
        &format!("tcp_server=on\ntcp_bindhost=127.0.0.1\ntcp_bindport={port}\n*.*\t-{}\n", out.display()),
    );
    let tx = Daemon::start(&dir, "tx", &format!("*.*\t@@127.0.0.1:{port}\n"));
    tx.log("over tcp");
    assert!(arrives(&out, "test: over tcp"), "{}", rx.stop());
    // A second message on the same connection.
    tx.log("again");
    assert!(arrives(&out, "test: again"));
    drop(tx);
}

#[test]
fn tcp_reconnects_and_queues() {
    let Some(dir) = scratch("tcp-queue") else { return };
    let port = free_port();
    let out = dir.join("received.log");
    // The sender starts first: its connection fails, the message waits in the queue.
    let tx = Daemon::start(&dir, "tx", &format!("*.*\t@@127.0.0.1:{port}\n"));
    tx.log("queued while down");
    std::thread::sleep(Duration::from_millis(500));
    let _rx = Daemon::start(
        &dir,
        "rx",
        &format!("tcp_server=on\ntcp_bindhost=127.0.0.1\ntcp_bindport={port}\n*.*\t-{}\n", out.display()),
    );
    // Retried after 10 seconds.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !std::fs::read_to_string(&out).is_ok_and(|s| s.contains("queued while down")) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let err = tx.stop();
    assert!(std::fs::read_to_string(&out).unwrap_or_default().contains("queued while down"), "{err}");
    assert!(err.contains("retrying"), "{err}");
}

/// TLS with a test authority: each side's certificate issued by it, the client checking the
/// server's name with `subject=` and the server requiring a client certificate (`tls_verify`).
#[test]
fn tls_with_authority() {
    let Some(dir) = scratch("tls-ca") else { return };
    let ca_key = key();
    let ca = cert("syslogd test CA", &ca_key, None, true);
    std::fs::write(dir.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
    let server_key = key();
    let (skey, scert) = write_pem(&dir, "server", &server_key, &cert("loghost.test", &server_key, Some((&ca, &ca_key)), false));
    let client_key = key();
    let (ckey, ccert) = write_pem(&dir, "client", &client_key, &cert("client.test", &client_key, Some((&ca, &ca_key)), false));
    let port = free_port();
    let out = dir.join("received.log");
    let rx = Daemon::start(
        &dir,
        "rx",
        &format!(
            "tls_server=on\ntls_bindhost=127.0.0.1\ntls_bindport={port}\ntls_keyfile={}\ntls_certfile={}\n\
             tls_ca={}\n*.*\t-{}\n",
            skey.display(),
            scert.display(),
            dir.join("ca.pem").display(),
            out.display()
        ),
    );
    let tx = Daemon::start(
        &dir,
        "tx",
        &format!(
            "tls_keyfile={}\ntls_certfile={}\ntls_ca={}\n*.*\t@[127.0.0.1]:{port}(subject=\"loghost.test\")\n",
            ckey.display(),
            ccert.display(),
            dir.join("ca.pem").display()
        ),
    );
    tx.log("over tls");
    let ok = arrives(&out, "test: over tls");
    let (terr, rerr) = (tx.stop(), rx.stop());
    assert!(ok, "sender: {terr}\nreceiver: {rerr}");
}

/// A self-signed server certificate (`tls_gen_cert`), accepted by its pinned fingerprint; the
/// server takes any client (`tls_verify=off`). Then a wrong fingerprint is refused.
#[test]
fn tls_pinned_fingerprint_and_rejection() {
    let Some(dir) = scratch("tls-pin") else { return };
    let port = free_port();
    let out = dir.join("received.log");
    let (k, c) = (dir.join("rx.key"), dir.join("rx.pem"));
    let rx = Daemon::start(
        &dir,
        "rx",
        &format!(
            "tls_server=on\ntls_bindhost=127.0.0.1\ntls_bindport={port}\ntls_keyfile={}\ntls_certfile={}\n\
             tls_gen_cert=on\ntls_verify=off\n*.*\t-{}\n",
            k.display(),
            c.display(),
            out.display()
        ),
    );
    let generated = X509::from_pem(&std::fs::read(&c).expect("tls_gen_cert made no certificate")).unwrap();
    let tx = Daemon::start(&dir, "tx", &format!("*.*\t@[127.0.0.1]:{port}(fingerprint=\"{}\")\n", fingerprint(&generated)));
    tx.log("pinned");
    let ok = arrives(&out, "test: pinned");
    let terr = tx.stop();
    assert!(ok, "sender: {terr}");

    let other = X509::from_pem(&cert("someone else", &key(), None, true).to_pem().unwrap()).unwrap();
    let bad = Daemon::start(&dir, "bad", &format!("*.*\t@[127.0.0.1]:{port}(fingerprint=\"{}\")\n", fingerprint(&other)));
    bad.log("must not arrive");
    std::thread::sleep(Duration::from_secs(2));
    let berr = bad.stop();
    drop(rx);
    assert!(!std::fs::read_to_string(&out).unwrap().contains("must not arrive"));
    assert!(berr.contains("certificate not accepted"), "{berr}");
}

/// The server refuses a client whose certificate no authority it trusts vouches for.
#[test]
fn tls_server_rejects_unknown_client() {
    let Some(dir) = scratch("tls-client") else { return };
    let ca_key = key();
    let ca = cert("syslogd test CA", &ca_key, None, true);
    std::fs::write(dir.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
    let server_key = key();
    let (skey, scert) = write_pem(&dir, "server", &server_key, &cert("loghost.test", &server_key, Some((&ca, &ca_key)), false));
    let stranger_key = key();
    let (ckey, ccert) = write_pem(&dir, "stranger", &stranger_key, &cert("stranger", &stranger_key, None, false));
    let port = free_port();
    let out = dir.join("received.log");
    let rx = Daemon::start(
        &dir,
        "rx",
        &format!(
            "tls_server=on\ntls_bindhost=127.0.0.1\ntls_bindport={port}\ntls_keyfile={}\ntls_certfile={}\n\
             tls_ca={}\n*.*\t-{}\n",
            skey.display(),
            scert.display(),
            dir.join("ca.pem").display(),
            out.display()
        ),
    );
    let tx = Daemon::start(
        &dir,
        "tx",
        &format!(
            "tls_keyfile={}\ntls_certfile={}\ntls_ca={}\n*.*\t@[127.0.0.1]:{port}(subject=\"loghost.test\")\n",
            ckey.display(),
            ccert.display(),
            dir.join("ca.pem").display()
        ),
    );
    tx.log("from a stranger");
    std::thread::sleep(Duration::from_secs(2));
    let _ = tx.stop();
    let rerr = rx.stop();
    assert!(!std::fs::read_to_string(&out).unwrap_or_default().contains("from a stranger"));
    assert!(rerr.contains("TLS from 127.0.0.1"), "{rerr}");
}
