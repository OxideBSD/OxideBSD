//! UEFI variables' formats (OxideBSD-doc `EFIRT.md` §6), for efivar(8) and efibootmgr(8):
//! vendor GUIDs (`guid`), device paths (`devpath`: their binary nodes and the specification's
//! text form, UEFI 2.10 §10.6) and boot entries (`EFI_LOAD_OPTION`, the `Boot####` variables,
//! `LoadOption`).
//!
//! Everything read from a variable is checked before it's used: a malformed device path or load
//! option is refused, never trusted to index past its buffer. Nothing here talks to the firmware:
//! the tools do, through `/dev/efi`.

#![no_std]

extern crate alloc;
#[cfg(feature = "dev")]
extern crate std;

#[cfg(feature = "dev")]
pub mod dev;
pub mod devpath;
pub mod guid;

use alloc::string::String;
use alloc::vec::Vec;

pub use guid::Guid;

/// `LOAD_OPTION_ACTIVE`: the firmware may boot it.
pub const LOAD_OPTION_ACTIVE: u32 = 0x1;
/// `LOAD_OPTION_HIDDEN`: not shown in the firmware's boot menu.
pub const LOAD_OPTION_HIDDEN: u32 = 0x8;

/// A boot entry, `EFI_LOAD_OPTION` (§3.1.3): its attributes, description, device path (the
/// whole list of instances, as stored) and the bytes after it, passed to the loader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadOption {
    pub attributes: u32,
    pub description: String,
    pub path: Vec<u8>,
    pub optional: Vec<u8>,
}

impl LoadOption {
    /// Reads one from a `Boot####` variable's value.
    pub fn parse(data: &[u8]) -> Option<LoadOption> {
        if data.len() < 6 {
            return None;
        }
        let attributes = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let path_len = u16::from_le_bytes(data[4..6].try_into().ok()?) as usize;
        let mut at = 6;
        let mut units = Vec::new();
        loop {
            let c = u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?);
            at += 2;
            if c == 0 {
                break;
            }
            units.push(c);
        }
        let description = String::from_utf16_lossy(&units);
        let path = data.get(at..at.checked_add(path_len)?)?.to_vec();
        devpath::parse(&path)?;
        let optional = data[at + path_len..].to_vec();
        Some(LoadOption { attributes, description, path, optional })
    }

    /// Its value as a `Boot####` variable holds it.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.attributes.to_le_bytes());
        out.extend_from_slice(&(self.path.len() as u16).to_le_bytes());
        for c in self.description.encode_utf16().chain(core::iter::once(0)) {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.extend_from_slice(&self.path);
        out.extend_from_slice(&self.optional);
        out
    }
}

/// `BootOrder` (or `DriverOrder`): little-endian `u16` entry numbers.
pub fn parse_order(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

pub fn encode_order(order: &[u16]) -> Vec<u8> {
    order.iter().flat_map(|n| n.to_le_bytes()).collect()
}

/// `Boot####`'s name for entry `n`.
pub fn boot_name(n: u16) -> String {
    alloc::format!("Boot{n:04X}")
}

/// The entry number of a `Boot####` name (or of `####` alone, or `boot####`, as efibootmgr(8)
/// takes it).
pub fn parse_boot_number(s: &str) -> Option<u16> {
    let hex = s.strip_prefix("Boot").or_else(|| s.strip_prefix("boot")).unwrap_or(s);
    (!hex.is_empty() && hex.len() <= 4).then(|| u16::from_str_radix(hex, 16).ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn load_option_round_trip() {
        let mut path = devpath::hard_drive_gpt(1, 2048, 532480, [7; 16]);
        path.extend(devpath::file_path("\\EFI\\OxideBSD\\BOOTX64.EFI"));
        path.extend(devpath::end());
        let o = LoadOption { attributes: LOAD_OPTION_ACTIVE, description: "OxideBSD".into(), path, optional: Vec::new() };
        let bytes = o.encode();
        assert_eq!(LoadOption::parse(&bytes), Some(o.clone()));
        assert_eq!(
            devpath::to_text(&o.path).unwrap(),
            "HD(1,GPT,07070707-0707-0707-0707-070707070707,0x800,0x82000)/\\EFI\\OxideBSD\\BOOTX64.EFI"
        );
        // Cut short anywhere, or a path length past the end: refused.
        for n in 0..bytes.len() - 1 {
            if n < 6 + 18 + o.path.len() {
                assert!(LoadOption::parse(&bytes[..n]).is_none(), "cut at {n}");
            }
        }
        let mut bad = bytes.clone();
        bad[4] = 0xff;
        assert!(LoadOption::parse(&bad).is_none());
    }

    #[test]
    fn orders_and_numbers() {
        assert_eq!(parse_order(&[1, 0, 0, 0, 0x0a, 0]), [1, 0, 10]);
        assert_eq!(encode_order(&[1, 0x1a]), [1, 0, 0x1a, 0]);
        assert_eq!(boot_name(0x1a), "Boot001A");
        assert_eq!(parse_boot_number("Boot001A"), Some(0x1a));
        assert_eq!(parse_boot_number("boot9"), Some(9));
        assert_eq!(parse_boot_number("0009"), Some(9));
        assert_eq!(parse_boot_number("12345"), None);
        assert_eq!(parse_boot_number("Boot"), None);
        assert_eq!("x".to_string(), "x");
    }
}
