//! UEFI device paths (UEFI 2.10 §10): a list of nodes, each a type, a subtype, a little-endian
//! length (header included) and its data, ending in an end node; `0x7f`/`0x01` ends an instance
//! and another follows. `to_text` gives the specification's text form (§10.6:
//! `PciRoot(0x0)/Pci(0x1,0x1)/Ata(Secondary,Master,0x0)`, `HD(1,GPT,<guid>,0x800,0x82000)/
//! \EFI\BOOT\BOOTX64.EFI`), a node it doesn't know as the generic `Path(type,subtype,data)`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::Guid;

const HARDWARE: u8 = 1;
const ACPI: u8 = 2;
const MESSAGING: u8 = 3;
const MEDIA: u8 = 4;
const BBS: u8 = 5;
const END: u8 = 0x7f;
const END_INSTANCE: u8 = 0x01;
const END_ENTIRE: u8 = 0xff;

/// One node: its type, subtype and data (without the header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node<'a> {
    pub kind: u8,
    pub subtype: u8,
    pub data: &'a [u8],
}

/// The nodes of `path`, its end nodes included; `None` if a node's length is short, runs past
/// the buffer, or the path doesn't end in an end-of-entire-path node.
pub fn parse(path: &[u8]) -> Option<Vec<Node<'_>>> {
    let mut nodes = Vec::new();
    let mut at = 0;
    while at < path.len() {
        let header = path.get(at..at + 4)?;
        let len = u16::from_le_bytes([header[2], header[3]]) as usize;
        if len < 4 {
            return None;
        }
        let data = path.get(at + 4..at + len)?;
        let node = Node { kind: header[0], subtype: header[1], data };
        nodes.push(node);
        at += len;
        if node.kind == END && node.subtype == END_ENTIRE {
            return (at == path.len()).then_some(nodes);
        }
    }
    None
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(at..at + 8)?.try_into().ok()?))
}

fn guid_at(d: &[u8], at: usize) -> Option<Guid> {
    Some(Guid(d.get(at..at + 16)?.try_into().ok()?))
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02X}")).collect()
}

/// An EISA ID (`PNP0A03`), as ACPI nodes store one: three 5-bit letters, then a 16-bit product.
fn eisa(id: u32) -> String {
    let v = id & 0xffff;
    let letter = |shift: u32| char::from(0x40 + ((v >> shift) & 0x1f) as u8);
    format!("{}{}{}{:04X}", letter(10), letter(5), letter(0), id >> 16)
}

/// The text of one node; `None` when its data is too short for its kind (the caller then writes
/// the generic form).
fn node_text(n: &Node) -> Option<String> {
    let d = n.data;
    Some(match (n.kind, n.subtype) {
        (HARDWARE, 1) => format!("Pci(0x{:X},0x{:X})", d.get(1)?, d.first()?),
        (HARDWARE, 3) => format!("MemoryMapped(0x{:X},0x{:X},0x{:X})", u32_at(d, 0)?, u64_at(d, 4)?, u64_at(d, 12)?),
        (HARDWARE, 4) => format!("VenHw({}{})", guid_at(d, 0)?, opt_hex(&d[16..])),
        (ACPI, 1) => {
            let (hid, uid) = (u32_at(d, 0)?, u32_at(d, 4)?);
            match eisa(hid).as_str() {
                "PNP0A03" => format!("PciRoot(0x{uid:X})"),
                "PNP0A08" => format!("PcieRoot(0x{uid:X})"),
                id => format!("Acpi({id},0x{uid:X})"),
            }
        }
        (MESSAGING, 1) => format!(
            "Ata({},{},0x{:X})",
            if *d.first()? == 0 { "Primary" } else { "Secondary" },
            if *d.get(1)? == 0 { "Master" } else { "Slave" },
            u16_at(d, 2)?
        ),
        (MESSAGING, 2) => format!("Scsi(0x{:X},0x{:X})", u16_at(d, 0)?, u16_at(d, 2)?),
        (MESSAGING, 5) => format!("USB(0x{:X},0x{:X})", d.first()?, d.get(1)?),
        (MESSAGING, 10) => format!("VenMsg({}{})", guid_at(d, 0)?, opt_hex(&d[16..])),
        (MESSAGING, 11) => format!("MAC({},0x{:X})", hex(d.get(0..6)?), d.get(32)?),
        (MESSAGING, 18) => format!("Sata(0x{:X},0x{:X},0x{:X})", u16_at(d, 0)?, u16_at(d, 2)?, u16_at(d, 4)?),
        (MESSAGING, 23) => {
            let eui: Vec<String> = d.get(4..12)?.iter().rev().map(|b| format!("{b:02X}")).collect();
            format!("NVMe(0x{:X},{})", u32_at(d, 0)?, eui.join("-"))
        }
        (MEDIA, 1) => {
            let (part, start, size) = (u32_at(d, 0)?, u64_at(d, 4)?, u64_at(d, 12)?);
            let sig = match (d.get(37)?, d.get(36)?) {
                (2, 2) => format!("GPT,{}", guid_at(d, 20)?),
                (1, 1) => format!("MBR,0x{:X}", u32_at(d, 20)?),
                (t, _) => format!("{t},0"),
            };
            format!("HD({part},{sig},0x{start:X},0x{size:X})")
        }
        (MEDIA, 2) => format!("CDROM(0x{:X},0x{:X},0x{:X})", u32_at(d, 0)?, u64_at(d, 4)?, u64_at(d, 12)?),
        (MEDIA, 3) => format!("VenMedia({}{})", guid_at(d, 0)?, opt_hex(&d[16..])),
        (MEDIA, 4) => {
            let units: Vec<u16> = d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
            String::from_utf16_lossy(&units)
        }
        (MEDIA, 6) => format!("FvFile({})", guid_at(d, 0)?),
        (MEDIA, 7) => format!("Fv({})", guid_at(d, 0)?),
        (BBS, 1) => format!("BBS(0x{:X},{},0x{:X})", u16_at(d, 0)?, bbs_description(d.get(4..)?), u16_at(d, 2)?),
        _ => return None,
    })
}

fn opt_hex(d: &[u8]) -> String {
    if d.is_empty() { String::new() } else { format!(",{}", hex(d)) }
}

fn bbs_description(d: &[u8]) -> String {
    d.iter().take_while(|&&b| b != 0).map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '?' }).collect()
}

/// The text form of `path`: nodes joined by `/`, instances by `,`; `None` for a malformed path.
pub fn to_text(path: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut first = true;
    for n in parse(path)? {
        match (n.kind, n.subtype) {
            (END, END_ENTIRE) => break,
            (END, END_INSTANCE) => {
                out.push(',');
                first = true;
                continue;
            }
            _ => {}
        }
        if !first {
            out.push('/');
        }
        first = false;
        match node_text(&n) {
            Some(t) => out.push_str(&t),
            None => out.push_str(&format!("Path({},{},{})", n.kind, n.subtype, hex(n.data))),
        }
    }
    Some(out)
}

/// The GPT partition a path's hard-drive node names: `(partition number, start, size, GUID)`.
pub fn hard_drive(path: &[u8]) -> Option<(u32, u64, u64, Guid)> {
    parse(path)?.iter().find(|n| n.kind == MEDIA && n.subtype == 1 && n.data.get(36..38) == Some(&[2, 2])).and_then(|n| {
        Some((u32_at(n.data, 0)?, u64_at(n.data, 4)?, u64_at(n.data, 12)?, guid_at(n.data, 20)?))
    })
}

/// The file path a path's file node holds.
pub fn file(path: &[u8]) -> Option<String> {
    let nodes = parse(path)?;
    let n = nodes.iter().find(|n| n.kind == MEDIA && n.subtype == 4)?;
    node_text(n)
}

fn node(kind: u8, subtype: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.push(kind);
    v.push(subtype);
    v.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// A hard-drive node for GPT partition number `partition`, `start` and `size` in the disk's
/// sectors, of partition GUID `guid` (as stored).
pub fn hard_drive_gpt(partition: u32, start: u64, size: u64, guid: [u8; 16]) -> Vec<u8> {
    let mut d = Vec::with_capacity(38);
    d.extend_from_slice(&partition.to_le_bytes());
    d.extend_from_slice(&start.to_le_bytes());
    d.extend_from_slice(&size.to_le_bytes());
    d.extend_from_slice(&guid);
    // Partition format GPT, signature type GUID.
    d.extend_from_slice(&[2, 2]);
    node(MEDIA, 1, &d)
}

/// A file-path node: `path`, with backslashes, in UTF-16 with its NUL.
pub fn file_path(path: &str) -> Vec<u8> {
    let d: Vec<u8> = path.encode_utf16().chain(core::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect();
    node(MEDIA, 4, &d)
}

/// The end-of-entire-path node.
pub fn end() -> Vec<u8> {
    node(END, END_ENTIRE, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OVMF's `Boot0001` path for the secondary IDE master, as QEMU's OVMF writes it.
    fn ovmf_ata() -> Vec<u8> {
        let mut p = node(ACPI, 1, &[0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0]);
        p.extend(node(HARDWARE, 1, &[1, 1]));
        p.extend(node(MESSAGING, 1, &[1, 0, 0, 0]));
        p.extend(end());
        p
    }

    #[test]
    fn text() {
        assert_eq!(to_text(&ovmf_ata()).unwrap(), "PciRoot(0x0)/Pci(0x1,0x1)/Ata(Secondary,Master,0x0)");
        let mut p = hard_drive_gpt(2, 0x800, 0x82000, Guid::parse("c12a7328-f81f-11d2-ba4b-00a0c93ec93b").unwrap().0);
        p.extend(file_path("\\EFI\\BOOT\\BOOTX64.EFI"));
        p.extend(node(END, END_INSTANCE, &[]));
        p.extend(node(MEDIA, 7, &[0x11; 16]));
        p.extend(node(0x42, 9, &[0xab, 0xcd]));
        p.extend(end());
        assert_eq!(
            to_text(&p).unwrap(),
            "HD(2,GPT,c12a7328-f81f-11d2-ba4b-00a0c93ec93b,0x800,0x82000)/\\EFI\\BOOT\\BOOTX64.EFI,Fv(11111111-1111-1111-1111-111111111111)/Path(66,9,ABCD)"
        );
        assert_eq!(hard_drive(&p).map(|h| (h.0, h.1, h.2)), Some((2, 0x800, 0x82000)));
        assert_eq!(file(&p).as_deref(), Some("\\EFI\\BOOT\\BOOTX64.EFI"));
        assert_eq!(eisa(0x0a0341d0), "PNP0A03");
    }

    #[test]
    fn hostile() {
        let good = ovmf_ata();
        // No end node, a short length, a length past the buffer, data after the end.
        assert!(parse(&good[..good.len() - 4]).is_none());
        let mut short = good.clone();
        short[2] = 3;
        assert!(parse(&short).is_none());
        let mut long = good.clone();
        long[2] = 0xff;
        assert!(parse(&long).is_none());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_none());
        // A known node too short for its kind: the generic form, not a panic.
        let mut p = node(MEDIA, 1, &[1, 0]);
        p.extend(end());
        assert_eq!(to_text(&p).unwrap(), "Path(4,1,0100)");
    }
}
