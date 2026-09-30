//! PEM (RFC 7468) for certificates.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// `der` as a PEM certificate block, base64 in 64-column lines.
pub fn encode(der: &[u8]) -> String {
    let mut b64 = String::with_capacity(der.len() * 4 / 3 + 4);
    for chunk in der.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                b64.push(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = String::from(BEGIN);
    out.push('\n');
    for line in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// Every certificate in `text`: the contents of its `CERTIFICATE` PEM blocks, with anything
/// around them (comments, `openssl x509 -text` output) ignored. A file that holds no block but is
/// itself a DER certificate gives that. A block whose base64 is malformed is skipped.
pub fn decode_all(text: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let s = String::from_utf8_lossy(text);
    let mut rest: &str = &s;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.find(END) else { break };
        if let Some(der) = base64_decode(&after[..end]) {
            out.push(der);
        }
        rest = &after[end + END.len()..];
    }
    if out.is_empty() && crate::der::subject(text).is_some() {
        out.push(text.to_vec());
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    let mut padding = false;
    for c in s.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding = true;
            continue;
        }
        if padding {
            return None;
        }
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for len in 0..70 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode_all(encode(&data).as_bytes()), vec![data.clone()]);
        }
    }

    #[test]
    fn rfc_4648_vectors() {
        let body = |pem: String| pem.lines().nth(1).unwrap_or("").to_string();
        assert_eq!(body(encode(b"f")), "Zg==");
        assert_eq!(body(encode(b"fo")), "Zm8=");
        assert_eq!(body(encode(b"foo")), "Zm9v");
        assert_eq!(body(encode(b"foobar")), "Zm9vYmFy");
    }
}
