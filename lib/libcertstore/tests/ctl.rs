//! `ctl` on a scratch tree: rehash, untrust, trust, with roots from the vendored `certdata.txt`.

use std::path::Path;

use libcertstore::{certdata, ctl, name, pem};

#[test]
fn rehash_untrust_trust() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../external/mpl2/nss/certdata.txt"),
    )
    .unwrap();
    let roots: Vec<_> = certdata::parse(&text).unwrap().into_iter().take(3).collect();
    let dest = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ctl");
    let _ = std::fs::remove_dir_all(&dest);
    let cfg = ctl::Config::standard(dest.to_str().unwrap(), "", "/usr/local");
    let trusted = dest.join("usr/share/certs/trusted");
    std::fs::create_dir_all(&trusted).unwrap();
    for r in &roots {
        std::fs::write(trusted.join(certdata::file_name(&r.label)), pem::encode(&r.der)).unwrap();
    }
    // A bundle file on the local trust path: its certificate is a duplicate, so no new link.
    let local = dest.join("usr/local/share/certs");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(local.join("dup.crt"), pem::encode(&roots[0].der) + &pem::encode(&roots[0].der))
        .unwrap();

    assert_eq!(ctl::rehash(&cfg).unwrap(), 3);
    let listed = ctl::list(&cfg.certs_dir);
    assert_eq!(listed.len(), 3);
    for (link, _) in &listed {
        // Each link resolves, relatively, to a certificate with that hash.
        let der = pem::decode_all(&std::fs::read(cfg.certs_dir.join(link)).unwrap()).remove(0);
        assert!(link.starts_with(&format!("{:08x}.", name::subject_hash(&der).unwrap())));
        let target = std::fs::read_link(cfg.certs_dir.join(link)).unwrap();
        assert!(target.is_relative(), "{}", target.display());
    }
    assert_eq!(pem::decode_all(&std::fs::read(&cfg.bundle).unwrap()).len(), 3);
    // OpenSSL itself finds each root through the links alone, and through the bundle alone.
    if std::process::Command::new("openssl").arg("version").output().is_ok() {
        for r in &roots {
            let pem_file = trusted.join(certdata::file_name(&r.label));
            for how in [["-CApath", cfg.certs_dir.to_str().unwrap()], ["-CAfile", cfg.bundle.to_str().unwrap()]] {
                let out = std::process::Command::new("openssl")
                    .args(["verify", "-no-CAstore", "-partial_chain"])
                    .args(if how[0] == "-CApath" { vec!["-no-CAfile"] } else { vec!["-no-CApath"] })
                    .args(how)
                    .arg(&pem_file)
                    .output()
                    .unwrap();
                assert!(out.status.success(), "{} {}: {}", how[0], r.label, String::from_utf8_lossy(&out.stderr));
            }
        }
    }

    let first = trusted.join(certdata::file_name(&roots[0].label));
    assert_eq!(ctl::untrust(&cfg, &first).unwrap(), 1);
    assert_eq!(ctl::untrust(&cfg, &first).unwrap(), 0, "already untrusted");
    assert_eq!(ctl::rehash(&cfg).unwrap(), 2);
    assert_eq!(ctl::list(&cfg.untrusted_dir).len(), 1);
    assert_eq!(pem::decode_all(&std::fs::read(&cfg.bundle).unwrap()).len(), 2);

    assert!(matches!(ctl::trust(&cfg, first.to_str().unwrap()), Ok(1)));
    assert_eq!(ctl::rehash(&cfg).unwrap(), 3);
    assert!(ctl::list(&cfg.untrusted_dir).is_empty());

    // A certificate on the system's untrusted list can't be trusted by `trust`.
    let untrusted = dest.join("usr/share/certs/untrusted");
    std::fs::create_dir_all(&untrusted).unwrap();
    std::fs::rename(trusted.join(certdata::file_name(&roots[1].label)), untrusted.join("x.pem")).unwrap();
    assert_eq!(ctl::rehash(&cfg).unwrap(), 2);
    let (name, _) = ctl::list(&cfg.untrusted_dir).remove(0);
    assert!(matches!(ctl::trust(&cfg, &name), Err(ctl::TrustError::SystemList(_))));
}
