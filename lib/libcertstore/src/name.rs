//! OpenSSL's subject name hash, `X509_NAME_hash_ex` (what `openssl x509 -subject_hash` prints):
//! the first four bytes, little-endian, of the SHA-1 of the name's canonical encoding. OpenSSL
//! looks a certificate up in a `-CApath` directory such as `/etc/ssl/certs` by this hash, as the
//! file `<hash as %08x>.<n>`.
//!
//! The canonical encoding (OpenSSL's `x509_name_canon` and `asn1_string_canon`, `crypto/x509/
//! x_name.c`): each attribute value of a string type is converted to UTF-8, leading and trailing
//! whitespace dropped, each inner run of whitespace made one space, ASCII letters lowercased, and
//! re-encoded as a `UTF8String`; a value of any other type is kept as it is. Each RDN is then
//! re-encoded as a DER `SET OF` (so its attributes are sorted), and the RDNs are concatenated
//! without the enclosing `SEQUENCE`.

use crate::der::{self, Tlv};
use crate::sha1::sha1;

const UTF8_STRING: u8 = 0x0c;
const PRINTABLE_STRING: u8 = 0x13;
const T61_STRING: u8 = 0x14;
const IA5_STRING: u8 = 0x16;
const VISIBLE_STRING: u8 = 0x1a;
const UNIVERSAL_STRING: u8 = 0x1c;
const BMP_STRING: u8 = 0x1e;

/// The subject name hash of the DER certificate `cert`, `None` if it doesn't parse.
pub fn subject_hash(cert: &[u8]) -> Option<u32> {
    name_hash(der::subject(cert)?.content)
}

/// The hash of a `Name` given by its content (the RDNs, without the `SEQUENCE` header).
pub fn name_hash(name: &[u8]) -> Option<u32> {
    let mut canon = Vec::new();
    for rdn in der::elements(name)? {
        if rdn.tag != der::SET {
            return None;
        }
        let mut entries = Vec::new();
        for ava in der::elements(rdn.content)? {
            entries.push(canonical_ava(ava)?);
        }
        // DER SET OF order (OpenSSL's der_cmp): bytewise, then the shorter first.
        entries.sort_by(|a, b| {
            let n = a.len().min(b.len());
            a[..n].cmp(&b[..n]).then(a.len().cmp(&b.len()))
        });
        canon.extend(der::encode(der::SET, &entries.concat()));
    }
    let md = sha1(&canon);
    Some(u32::from_le_bytes([md[0], md[1], md[2], md[3]]))
}

/// `AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }`, canonicalized.
fn canonical_ava(ava: Tlv<'_>) -> Option<Vec<u8>> {
    if ava.tag != der::SEQUENCE {
        return None;
    }
    let parts = der::elements(ava.content)?;
    let [oid, value] = parts.as_slice() else { return None };
    if oid.tag != der::OID {
        return None;
    }
    let value = match to_utf8(value.tag, value.content) {
        Some(Ok(utf8)) => der::encode(UTF8_STRING, &canonical_text(&utf8)),
        Some(Err(())) => return None,
        None => value.raw.to_vec(),
    };
    Some(der::encode(der::SEQUENCE, &[oid.raw, &value[..]].concat()))
}

/// OpenSSL's `ossl_isspace`: space, and `\t` through `\r`.
fn is_space(b: u8) -> bool {
    b == b' ' || (0x09..=0x0d).contains(&b)
}

fn canonical_text(s: &[u8]) -> Vec<u8> {
    let start = s.iter().position(|&b| !is_space(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|&b| !is_space(b)).map_or(start, |i| i + 1);
    let mut out = Vec::with_capacity(end - start);
    let mut i = start;
    while i < end {
        let b = s[i];
        if b >= 0x80 {
            out.push(b);
            i += 1;
        } else if is_space(b) {
            out.push(b' ');
            while i < end && is_space(s[i]) {
                i += 1;
            }
        } else {
            out.push(b.to_ascii_lowercase());
            i += 1;
        }
    }
    out
}

/// A string-typed value as UTF-8, as OpenSSL's `ASN1_STRING_to_UTF8` converts it: `None` for a
/// type that isn't one of the string types canonicalization covers, `Some(Err)` for a malformed
/// value. The single-byte types are taken as Latin-1, `BMPString` as UCS-2 and `UniversalString`
/// as UCS-4, both big-endian.
fn to_utf8(tag: u8, content: &[u8]) -> Option<Result<Vec<u8>, ()>> {
    let code_points: Vec<u32> = match tag {
        UTF8_STRING => {
            return Some(match core::str::from_utf8(content) {
                Ok(_) => Ok(content.to_vec()),
                Err(_) => Err(()),
            });
        }
        PRINTABLE_STRING | T61_STRING | IA5_STRING | VISIBLE_STRING => {
            content.iter().map(|&b| b as u32).collect()
        }
        BMP_STRING if content.len() % 2 == 0 => content
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
            .collect(),
        UNIVERSAL_STRING if content.len() % 4 == 0 => content
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
        BMP_STRING | UNIVERSAL_STRING => return Some(Err(())),
        _ => return None,
    };
    let mut out = Vec::with_capacity(code_points.len());
    for cp in code_points {
        // OpenSSL's UTF8_putc, which encodes any value below 0x110000.
        match cp {
            0..=0x7f => out.push(cp as u8),
            0x80..=0x7ff => out.extend([0xc0 | (cp >> 6) as u8, 0x80 | (cp & 0x3f) as u8]),
            0x800..=0xffff => out.extend([
                0xe0 | (cp >> 12) as u8,
                0x80 | ((cp >> 6) & 0x3f) as u8,
                0x80 | (cp & 0x3f) as u8,
            ]),
            0x1_0000..=0x10_ffff => out.extend([
                0xf0 | (cp >> 18) as u8,
                0x80 | ((cp >> 12) & 0x3f) as u8,
                0x80 | ((cp >> 6) & 0x3f) as u8,
                0x80 | (cp & 0x3f) as u8,
            ]),
            _ => return Some(Err(())),
        }
    }
    Some(Ok(out))
}

/// The value of a certificate's subject attribute to show for it: its common name, else its
/// organizational unit, else its organization (as FreeBSD's `certctl list`). `None` if it has none
/// of them or doesn't parse.
pub fn subject_display(cert: &[u8]) -> Option<String> {
    const CN: &[u8] = &[0x55, 0x04, 0x03];
    const OU: &[u8] = &[0x55, 0x04, 0x0b];
    const O: &[u8] = &[0x55, 0x04, 0x0a];
    let subject = der::subject(cert)?;
    let mut values: Vec<(&[u8], String)> = Vec::new();
    for rdn in der::elements(subject.content)? {
        for ava in der::elements(rdn.content)? {
            let parts = der::elements(ava.content)?;
            if let [oid, value] = parts.as_slice()
                && let Some(Ok(utf8)) = to_utf8(value.tag, value.content)
            {
                values.push((oid.content, String::from_utf8_lossy(&utf8).into_owned()));
            }
        }
    }
    [CN, OU, O]
        .iter()
        .find_map(|want| values.iter().find(|(oid, _)| oid == want).map(|(_, v)| v.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_text_folds_like_openssl() {
        assert_eq!(canonical_text(b"  Foo \t\n Bar  "), b"foo bar");
        assert_eq!(canonical_text(b"   "), b"");
        assert_eq!(canonical_text("Ünï  Côde".as_bytes()), "Ünï côde".as_bytes());
    }
}
