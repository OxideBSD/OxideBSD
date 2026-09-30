//! NSS's root list, `certdata.txt` (`lib/ckfw/builtins/certdata.txt` in NSS): a sequence of
//! PKCS #11 objects, each a run of `ATTRIBUTE TYPE VALUE` lines, where a `MULTILINE_OCTAL` value
//! follows on `\ooo`-escaped lines up to `END`. A `CKO_CERTIFICATE` object holds a root; a
//! `CKO_NSS_TRUST` object, matched to it by issuer and serial number, says what it's trusted for.

use std::collections::HashMap;

use crate::sha1::sha1;

/// What a root is trusted for as a TLS server certificate issuer (`CKA_TRUST_SERVER_AUTH`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerTrust {
    /// `CKT_NSS_TRUSTED_DELEGATOR`: a trusted CA.
    Trusted,
    /// `CKT_NSS_NOT_TRUSTED`: explicitly distrusted.
    Distrusted,
    /// Anything else (`CKT_NSS_MUST_VERIFY_TRUST`): no opinion, such as an e-mail-only root.
    Unspecified,
}

pub struct Root {
    /// `CKA_LABEL`.
    pub label: String,
    /// The certificate, DER.
    pub der: Vec<u8>,
    pub server_trust: ServerTrust,
}

enum Value {
    Token(String),
    Text(String),
    Bytes(Vec<u8>),
}

type Object = HashMap<String, Value>;

/// Every root in `text`, in file order. An error names the first thing that doesn't parse, a
/// certificate without a trust object, or a trust object whose certificate hash doesn't match.
pub fn parse(text: &str) -> Result<Vec<Root>, String> {
    let mut objects: Vec<Object> = Vec::new();
    let mut lines = text.lines().enumerate();
    while let Some((n, line)) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line == "BEGINDATA" {
            continue;
        }
        let mut words = line.splitn(3, ' ');
        let (Some(name), Some(ty)) = (words.next(), words.next()) else {
            return Err(format!("certdata.txt:{}: malformed line", n + 1));
        };
        let value = match ty {
            "MULTILINE_OCTAL" => {
                let mut bytes = Vec::new();
                loop {
                    let Some((n, l)) = lines.next() else {
                        return Err(format!("certdata.txt:{}: missing END", n + 1));
                    };
                    let l = l.trim();
                    if l == "END" {
                        break;
                    }
                    for oct in l.split('\\').filter(|s| !s.is_empty()) {
                        bytes.push(u8::from_str_radix(oct, 8).map_err(|_| {
                            format!("certdata.txt:{}: bad octal escape \\{oct}", n + 1)
                        })?);
                    }
                }
                Value::Bytes(bytes)
            }
            "UTF8" => {
                let v = words.next().unwrap_or("");
                Value::Text(v.trim().trim_matches('"').to_string())
            }
            _ => Value::Token(words.next().unwrap_or("").trim().to_string()),
        };
        if name == "CKA_CLASS" {
            objects.push(Object::new());
        }
        let Some(object) = objects.last_mut() else {
            return Err(format!("certdata.txt:{}: attribute before any CKA_CLASS", n + 1));
        };
        object.insert(name.to_string(), value);
    }

    let token = |o: &Object, k: &str| match o.get(k) {
        Some(Value::Token(t)) => Some(t.clone()),
        _ => None,
    };
    let bytes = |o: &Object, k: &str| match o.get(k) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let label = |o: &Object| match o.get("CKA_LABEL") {
        Some(Value::Text(t)) => t.clone(),
        _ => String::new(),
    };

    // (issuer, serial) -> (server auth trust, certificate SHA-1)
    let mut trust: HashMap<(Vec<u8>, Vec<u8>), (String, Vec<u8>)> = HashMap::new();
    for o in &objects {
        if token(o, "CKA_CLASS").as_deref() != Some("CKO_NSS_TRUST") {
            continue;
        }
        let (Some(issuer), Some(serial)) = (bytes(o, "CKA_ISSUER"), bytes(o, "CKA_SERIAL_NUMBER"))
        else {
            return Err(format!("trust object \"{}\" lacks an issuer or serial", label(o)));
        };
        let server = token(o, "CKA_TRUST_SERVER_AUTH").unwrap_or_default();
        let hash = bytes(o, "CKA_CERT_SHA1_HASH").unwrap_or_default();
        trust.insert((issuer, serial), (server, hash));
    }

    let mut roots = Vec::new();
    for o in &objects {
        if token(o, "CKA_CLASS").as_deref() != Some("CKO_CERTIFICATE") {
            continue;
        }
        let label = label(o);
        let (Some(der), Some(issuer), Some(serial)) =
            (bytes(o, "CKA_VALUE"), bytes(o, "CKA_ISSUER"), bytes(o, "CKA_SERIAL_NUMBER"))
        else {
            return Err(format!("certificate \"{label}\" lacks its value, issuer or serial"));
        };
        let Some((server, hash)) = trust.get(&(issuer, serial)) else {
            return Err(format!("certificate \"{label}\" has no trust object"));
        };
        if !hash.is_empty() && hash[..] != sha1(&der)[..] {
            return Err(format!("certificate \"{label}\" doesn't match its trust object's hash"));
        }
        let server_trust = match server.as_str() {
            "CKT_NSS_TRUSTED_DELEGATOR" => ServerTrust::Trusted,
            "CKT_NSS_NOT_TRUSTED" => ServerTrust::Distrusted,
            _ => ServerTrust::Unspecified,
        };
        roots.push(Root { label, der, server_trust });
    }
    Ok(roots)
}

/// A file name for a root, from its label: ASCII letters, digits, `-` and `.` kept, anything else
/// made `_`, and `.pem` added.
pub fn file_name(label: &str) -> String {
    let stem: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect();
    format!("{stem}.pem")
}
