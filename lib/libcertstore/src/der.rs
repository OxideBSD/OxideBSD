//! Just enough DER (X.690) to walk a certificate to its subject name and take a name apart.

/// One element: its tag byte, its content, and its whole encoding (tag, length and content).
#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const OID: u8 = 0x06;

/// Reads the element at the start of `input`; returns it and what follows. Single-byte tags only
/// (all a certificate's structure uses) and definite lengths only (DER has no other kind).
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | b as usize;
        }
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return None;
    }
    let header = input.len() - rest.len();
    let tlv = Tlv { tag, content: &rest[..len], raw: &input[..header + len] };
    Some((tlv, &rest[len..]))
}

/// Every element in `content`, in order; `None` if any is malformed.
pub fn elements(mut content: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tlv, rest) = read(content)?;
        out.push(tlv);
        content = rest;
    }
    Some(out)
}

/// The DER encoding of an element with `tag` and `content`.
pub fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A certificate's subject `Name`, whole encoding included.
///
/// `Certificate ::= SEQUENCE { tbsCertificate, ... }`, and `TBSCertificate ::= SEQUENCE {
/// [0] version OPTIONAL, serialNumber, signature, issuer, validity, subject, ... }`.
pub fn subject(cert: &[u8]) -> Option<Tlv<'_>> {
    let (cert, _) = read(cert)?;
    let (tbs, _) = read(cert.content)?;
    let fields = elements(tbs.content)?;
    let skip = if fields.first()?.tag == 0xa0 { 1 } else { 0 };
    let subject = *fields.get(skip + 4)?;
    (subject.tag == SEQUENCE).then_some(subject)
}
