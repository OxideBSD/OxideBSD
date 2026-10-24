//! UEFI GUIDs as the firmware stores them (`EFI_GUID`: a little-endian `u32` and two `u16`s,
//! then eight bytes as they are), their text form, and the well-known ones by name.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Guid(pub [u8; 16]);

/// Well-known vendor GUIDs (`efivar -L`), as stored.
pub const KNOWN: &[(&str, [u8; 16])] = &[
    // EFI_GLOBAL_VARIABLE, 8be4df61-93ca-11d2-aa0d-00e098032b8c.
    ("global", [0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]),
    // OxideBSD's own, 916e441e-ead7-4301-9aaf-6e0ba5a85339.
    ("oxidebsd", [0x1e, 0x44, 0x6e, 0x91, 0xd7, 0xea, 0x01, 0x43, 0x9a, 0xaf, 0x6e, 0x0b, 0xa5, 0xa8, 0x53, 0x39]),
    // EFI_IMAGE_SECURITY_DATABASE_GUID (db, dbx), d719b2cb-3d3a-4596-a3bc-dad00e67656f.
    ("security", [0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f]),
    // The UEFI shell's, 158def5a-f656-419c-b027-7a3192c079d2.
    ("shell", [0x5a, 0xef, 0x8d, 0x15, 0x56, 0xf6, 0x9c, 0x41, 0xb0, 0x27, 0x7a, 0x31, 0x92, 0xc0, 0x79, 0xd2]),
];

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

impl Guid {
    /// From `8be4df61-93ca-11d2-aa0d-00e098032b8c` or a well-known name.
    pub fn parse(s: &str) -> Option<Guid> {
        if let Some((_, g)) = KNOWN.iter().find(|(n, _)| *n == s) {
            return Some(Guid(*g));
        }
        let parts: Vec<&str> = s.split('-').collect();
        let lens = [8, 4, 4, 4, 12];
        if parts.len() != 5 || parts.iter().zip(lens).any(|(p, l)| p.len() != l || !p.bytes().all(|c| c.is_ascii_hexdigit())) {
            return None;
        }
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&u32::from_str_radix(parts[0], 16).ok()?.to_le_bytes());
        b[4..6].copy_from_slice(&u16::from_str_radix(parts[1], 16).ok()?.to_le_bytes());
        b[6..8].copy_from_slice(&u16::from_str_radix(parts[2], 16).ok()?.to_le_bytes());
        let tail = format!("{}{}", parts[3], parts[4]);
        for i in 0..8 {
            b[8 + i] = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Guid(b))
    }

    /// Its well-known name, or its text form.
    pub fn symbolic(&self) -> String {
        KNOWN.iter().find(|(_, g)| *g == self.0).map_or_else(|| self.to_string(), |(n, _)| n.to_string())
    }
}

/// `GUID-name` (or `known-name`) into its GUID and name.
pub fn split_name(s: &str) -> Option<(Guid, String)> {
    if let Some((n, g)) = KNOWN.iter().find_map(|(n, g)| s.strip_prefix(n).and_then(|r| r.strip_prefix('-')).map(|r| (r, g))) {
        return (!n.is_empty()).then(|| (Guid(*g), n.to_string()));
    }
    if s.len() < 38 || s.as_bytes()[36] != b'-' {
        return None;
    }
    let g = Guid::parse(&s[..36])?;
    Some((g, s[37..].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn round_trip() {
        let g = Guid::parse("8be4df61-93ca-11d2-aa0d-00e098032b8c").unwrap();
        assert_eq!(g.0, KNOWN[0].1);
        assert_eq!(g.to_string(), "8be4df61-93ca-11d2-aa0d-00e098032b8c");
        assert_eq!(g.symbolic(), "global");
        for (name, b) in KNOWN {
            assert_eq!(Guid::parse(&Guid(*b).to_string()), Some(Guid(*b)), "{name}");
        }
        assert_eq!(Guid::parse("oxidebsd"), Some(Guid(KNOWN[1].1)));
        assert_eq!(Guid::parse("916e441e-ead7-4301-9aaf-6e0ba5a85339"), Some(Guid(KNOWN[1].1)));
        assert!(Guid::parse("8be4df61-93ca-11d2-aa0d-00e098032b8").is_none());
        assert!(Guid::parse("zbe4df61-93ca-11d2-aa0d-00e098032b8c").is_none());
    }

    #[test]
    fn names() {
        assert_eq!(split_name("global-BootOrder"), Some((Guid(KNOWN[0].1), "BootOrder".into())));
        assert_eq!(split_name("8be4df61-93ca-11d2-aa0d-00e098032b8c-Boot0001"), Some((Guid(KNOWN[0].1), "Boot0001".into())));
        assert_eq!(split_name("global-"), None);
        assert_eq!(split_name("BootOrder"), None);
    }
}
