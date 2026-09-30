//! Checks the subject name hash against the host's `openssl x509 -subject_hash`: every root in the
//! vendored `certdata.txt`, and certificates made here with awkward subjects. Skipped (passing)
//! when the host has no `openssl`.

use std::path::{Path, PathBuf};
use std::process::Command;

use libcertstore::{certdata, name, pem};

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().is_ok_and(|o| o.status.success())
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn openssl_hash(pem_path: &Path) -> String {
    let out = Command::new("openssl")
        .args(["x509", "-noout", "-subject_hash", "-in"])
        .arg(pem_path)
        .output()
        .unwrap();
    assert!(out.status.success(), "openssl failed on {}", pem_path.display());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn every_mozilla_root() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../external/mpl2/nss/certdata.txt"),
    )
    .unwrap();
    let roots = certdata::parse(&text).unwrap();
    assert!(roots.len() > 100, "only {} roots parsed", roots.len());
    if !have_openssl() {
        eprintln!("no host openssl; hash cross-check skipped");
        return;
    }
    let dir = scratch("roots");
    for (i, root) in roots.iter().enumerate() {
        let path = dir.join(format!("{i}.pem"));
        std::fs::write(&path, pem::encode(&root.der)).unwrap();
        let ours = format!("{:08x}", name::subject_hash(&root.der).unwrap());
        assert_eq!(ours, openssl_hash(&path), "root \"{}\"", root.label);
    }
}

#[test]
fn awkward_subjects() {
    if !have_openssl() {
        eprintln!("no host openssl; hash cross-check skipped");
        return;
    }
    let dir = scratch("awkward");
    let subjects: &[(&str, &[&str])] = &[
        ("/CN=  Mixed   CASE\tName  /O=Example", &[]),
        ("/C=DE/O=Grüße GmbH/CN=Straße", &["-utf8"]),
        ("/CN=a+OU=b+O=c/C=US", &["-multivalue-rdn"]),
        ("/CN=Zeta+CN=alpha", &["-multivalue-rdn"]),
        ("/CN=bmp  VALUE", &["-utf8", "-set_serial", "7"]),
        ("/emailAddress=Root@Example.ORG/CN=x", &[]),
        ("/CN=    ", &[]),
    ];
    for (i, (subject, extra)) in subjects.iter().enumerate() {
        let key = dir.join(format!("{i}.key"));
        let cert = dir.join(format!("{i}.pem"));
        let mut cmd = Command::new("openssl");
        cmd.args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"])
            .args(["-nodes", "-days", "1", "-subj", subject])
            .args(*extra)
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert);
        // One subject as BMPString values, which OpenSSL writes when the string mask asks for it.
        if subject.starts_with("/CN=bmp") {
            cmd.args(["-config", "/dev/null", "-reqopt", "no_sigdump"]);
            let cfg = dir.join("bmp.cnf");
            std::fs::write(&cfg, "[req]\ndistinguished_name=dn\nstring_mask=MASK:0x800\n[dn]\n")
                .unwrap();
            cmd = Command::new("openssl");
            cmd.args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"])
                .args(["-nodes", "-days", "1", "-subj", subject, "-config"])
                .arg(&cfg)
                .arg("-keyout")
                .arg(&key)
                .arg("-out")
                .arg(&cert);
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{subject}: {}", String::from_utf8_lossy(&out.stderr));
        let der = pem::decode_all(&std::fs::read(&cert).unwrap()).remove(0);
        let ours = format!("{:08x}", name::subject_hash(&der).unwrap());
        assert_eq!(ours, openssl_hash(&cert), "subject {subject}");
    }
}
