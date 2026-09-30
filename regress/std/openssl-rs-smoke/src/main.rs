//! The `openssl` crate on OxideBSD: `openssl-sys` built against the system OpenSSL
//! (`/usr/lib/libssl.so.3`, `libcrypto.so.3`), in a dynamically linked Rust program. Seeded as
//! `/usr/tests/openssl/openssl-rs-smoke` and run by `regress/openssl-syscall-smoke/run.sh`.
//!
//! A SHA-256 known answer; MD4 through the `dlopen`ed legacy provider; a root from the system
//! trust store (`/etc/ssl`, certctl(8)) verifying through OpenSSL's default paths; and a TLS 1.3
//! connection between two threads over a `UnixStream` pair, with a certificate chain made here
//! (a CA and a `localhost` server certificate) and the client checking the host name. Prints one
//! line per check; exits with the number of failures.

use std::os::unix::net::UnixStream;
use std::thread;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::provider::Provider;
use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVersion};
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509Builder, X509NameBuilder, X509StoreContext};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_known_answer() -> Result<bool> {
    Ok(hex(&openssl::sha::sha256(b"abc"))
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
}

fn md4_through_legacy() -> Result<bool> {
    let _legacy = Provider::load(None, "legacy")?;
    let _default = Provider::load(None, "default")?;
    let md4 = MessageDigest::from_name("MD4").ok_or("no MD4")?;
    Ok(hex(&hash(md4, b"abc")?) == "a448017aaf21d8525fc10ae87aa6729d")
}

fn system_root_verifies() -> Result<bool> {
    let root = X509::from_pem(&std::fs::read("/usr/share/certs/trusted/ISRG_Root_X1.pem")?)?;
    let mut store = X509StoreBuilder::new()?;
    store.set_default_paths()?;
    let store = store.build();
    let chain = openssl::stack::Stack::new()?;
    let mut ctx = X509StoreContext::new()?;
    Ok(ctx.init(&store, &root, &chain, |c| c.verify_cert())?)
}

fn p256_key() -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

/// A certificate for `cn`, signed by `issuer` (self-signed when `None`), valid for a day.
fn certificate(
    cn: &str,
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
) -> Result<X509> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, cn)?;
    let name = name.build();
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    let (not_before, not_after) = (Asn1Time::days_from_now(0)?, Asn1Time::days_from_now(1)?);
    b.set_serial_number(&serial)?;
    b.set_subject_name(&name)?;
    b.set_pubkey(key)?;
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    match issuer {
        None => {
            b.set_issuer_name(&name)?;
            b.append_extension(BasicConstraints::new().critical().ca().build()?)?;
            b.sign(key, MessageDigest::sha256())?;
        }
        Some((ca, ca_key)) => {
            b.set_issuer_name(ca.subject_name())?;
            let san = SubjectAlternativeName::new().dns(cn).build(&b.x509v3_context(Some(ca), None))?;
            b.append_extension(san)?;
            b.sign(ca_key, MessageDigest::sha256())?;
        }
    }
    Ok(b.build())
}

fn tls13_over_unix_socket() -> Result<bool> {
    let ca_key = p256_key()?;
    let ca = certificate("OxideBSD test CA", &ca_key, None)?;
    let server_key = p256_key()?;
    let server_cert = certificate("localhost", &server_key, Some((&ca, &ca_key)))?;

    let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())?;
    acceptor.set_private_key(&server_key)?;
    acceptor.set_certificate(&server_cert)?;
    let acceptor = acceptor.build();

    let mut connector = SslConnector::builder(SslMethod::tls_client())?;
    connector.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    connector.cert_store_mut().add_cert(ca)?;
    let connector = connector.build();

    let (client_sock, server_sock) = UnixStream::pair()?;
    let server = thread::spawn(move || -> Result<()> {
        use std::io::{Read, Write};
        let mut s = acceptor.accept(server_sock)?;
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf)?;
        if &buf != b"ping" {
            return Err("server read the wrong bytes".into());
        }
        s.write_all(b"pong")?;
        s.shutdown()?;
        Ok(())
    });

    use std::io::{Read, Write};
    let mut c = connector.connect("localhost", client_sock)?;
    println!(
        "openssl-rs-smoke: handshake: {}, {}",
        c.ssl().version_str(),
        c.ssl().current_cipher().map(|x| x.name()).unwrap_or("?")
    );
    let tls13 = c.ssl().version2() == Some(SslVersion::TLS1_3);
    c.write_all(b"ping")?;
    let mut buf = [0u8; 4];
    c.read_exact(&mut buf)?;
    server.join().map_err(|_| "server thread panicked")??;
    Ok(tls13 && &buf == b"pong")
}

fn main() {
    println!("openssl-rs-smoke: {}", openssl::version::version());
    let checks: [(&str, fn() -> Result<bool>); 4] = [
        ("SHA-256 known answer", sha256_known_answer),
        ("MD4 known answer (legacy provider)", md4_through_legacy),
        ("a system root verifies through the default paths", system_root_verifies),
        ("TLS 1.3 over a UnixStream pair, host name checked", tls13_over_unix_socket),
    ];
    let mut failed = 0;
    for (what, check) in checks {
        match check() {
            Ok(true) => println!("openssl-rs-smoke: ok: {what}"),
            Ok(false) => {
                println!("openssl-rs-smoke: FAIL: {what}");
                failed += 1;
            }
            Err(e) => {
                println!("openssl-rs-smoke: FAIL: {what}: {e}");
                failed += 1;
            }
        }
    }
    std::process::exit(failed);
}
