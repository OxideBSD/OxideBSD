//! ISO 9660's on-disk format (ECMA-119), with the Rock Ridge extensions (RRIP 1.12 over SUSP 1.12)
//! and Joliet, for the kernel's cd9660 module (`OxideBSD-doc/INSTALLER.md` §6). Pure parsing, no
//! I/O: the module reads the blocks and hands them here.
//!
//! Everything on a disc is untrusted: every parser here checks its lengths against the bytes it
//! was given and returns `None` (or stops) on anything malformed, never panicking.
//!
//! `no_std` with `alloc` (names and link targets are built as `String`s); builds for the kernel
//! and the host alike.

#![no_std]

extern crate alloc;

use alloc::string::String;

/// A logical block, as every disc this reads uses (ECMA-119 allows others; nobody writes them).
pub const BLOCK: usize = 2048;
/// The first volume descriptor's block (the 32 KiB before it are the system area).
pub const FIRST_DESCRIPTOR: u32 = 16;

/// Directory record flags (ECMA-119 9.1.6).
pub const FLAG_HIDDEN: u8 = 0x01;
pub const FLAG_DIRECTORY: u8 = 0x02;
pub const FLAG_ASSOCIATED: u8 = 0x04;
/// The file continues in the next record (a file of more than one extent).
pub const FLAG_MULTI_EXTENT: u8 = 0x80;

/// POSIX file type bits in a Rock Ridge `PX` mode.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFLNK: u32 = 0o120000;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

// --- Volume descriptors ---------------------------------------------------------------------------

/// What a volume descriptor block holds.
pub enum Descriptor<'a> {
    /// The primary volume descriptor (type 1).
    Primary(Volume<'a>),
    /// A supplementary one (type 2) with a Joliet escape sequence: UCS-2 names.
    Joliet(Volume<'a>),
    /// The set terminator (type 255): no descriptors follow.
    Terminator,
    /// A boot record, a non-Joliet supplementary descriptor, a partition descriptor.
    Other,
}

/// A primary or Joliet volume: where its tree starts.
pub struct Volume<'a> {
    /// The volume's size in logical blocks.
    pub blocks: u32,
    pub block_size: u16,
    /// The root directory's record (34 bytes).
    pub root: Record<'a>,
    /// The volume identifier, trailing spaces kept (a Joliet one is UCS-2).
    pub volume_id: &'a [u8],
}

/// Parses one volume descriptor block; `None` if it isn't one (no `CD001`).
pub fn descriptor(b: &[u8]) -> Option<Descriptor<'_>> {
    if b.len() < BLOCK || &b[1..6] != b"CD001" {
        return None;
    }
    fn volume(b: &[u8]) -> Option<Volume<'_>> {
        Some(Volume { blocks: le32(b, 80), block_size: le16(b, 128), root: record(&b[156..190])?, volume_id: &b[40..72] })
    }
    Some(match b[0] {
        1 => Descriptor::Primary(volume(b)?),
        2 => {
            // Joliet's escape sequences: UCS-2 levels 1, 2 and 3.
            let esc = &b[88..91];
            if esc == b"%/@" || esc == b"%/C" || esc == b"%/E" {
                Descriptor::Joliet(volume(b)?)
            } else {
                Descriptor::Other
            }
        }
        255 => Descriptor::Terminator,
        _ => Descriptor::Other,
    })
}

// --- Directory records ----------------------------------------------------------------------------

/// One directory record (ECMA-119 9.1).
#[derive(Clone, Copy)]
pub struct Record<'a> {
    /// The record's length in bytes.
    pub len: usize,
    /// The first logical block of the file's data (past any extended attribute record).
    pub extent: u32,
    /// The data's length in bytes.
    pub size: u32,
    pub flags: u8,
    /// The recording time, seconds since the epoch.
    pub recorded: i64,
    /// The file identifier as stored (`NAME.EXT;1`, UCS-2 under Joliet, `\0`/`\1` for `.`/`..`).
    pub name: &'a [u8],
    /// The System Use area: Rock Ridge's entries.
    pub system_use: &'a [u8],
}

impl Record<'_> {
    pub fn is_dir(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    /// The `.` record (a directory's first).
    pub fn is_self(&self) -> bool {
        self.name == [0]
    }

    /// The `..` record (a directory's second).
    pub fn is_parent(&self) -> bool {
        self.name == [1]
    }
}

/// Parses the record at the start of `b`. `None` for a zero length byte (the rest of the block is
/// padding: records never cross a block) or a malformed record.
pub fn record(b: &[u8]) -> Option<Record<'_>> {
    let len = *b.first()? as usize;
    if len < 34 || len > b.len() {
        return None;
    }
    let ext_attr = b[1] as u32;
    let name_len = b[32] as usize;
    if 33 + name_len > len {
        return None;
    }
    // A padding byte follows a name of even length, so the System Use area starts even.
    let su = 33 + name_len + (name_len + 1) % 2;
    Some(Record {
        len,
        extent: le32(b, 2).checked_add(ext_attr)?,
        size: le32(b, 10),
        flags: b[25],
        recorded: time7(&b[18..25]),
        name: &b[33..33 + name_len],
        system_use: if su <= len { &b[su..len] } else { &[] },
    })
}

/// Walks the records of one directory block, in order, with each one's offset in the block.
pub fn records(block: &[u8]) -> impl Iterator<Item = (usize, Record<'_>)> {
    let mut at = 0;
    core::iter::from_fn(move || {
        let r = record(block.get(at..)?)?;
        let here = at;
        at += r.len;
        Some((here, r))
    })
}

// --- Names ----------------------------------------------------------------------------------------

/// A plain ISO 9660 name as shown: the version (`;1`) and a trailing dot dropped, in lower case
/// (FreeBSD's default for discs without Rock Ridge or Joliet).
pub fn plain_name(name: &[u8]) -> String {
    let base = name.split(|&c| c == b';').next().unwrap_or(&[]);
    let base = base.strip_suffix(b".").unwrap_or(base);
    base.iter().map(|&c| (c as char).to_ascii_lowercase()).collect()
}

/// A Joliet name as shown: UCS-2 (big-endian; UTF-16 surrogates decoded too), the version and a
/// trailing dot dropped.
pub fn joliet_name(name: &[u8]) -> String {
    let units = name.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]]));
    let mut s: String = char::decode_utf16(units).map(|c| c.unwrap_or('\u{FFFD}')).collect();
    if let Some(i) = s.rfind(';')
        && s[i + 1..].bytes().all(|c| c.is_ascii_digit())
    {
        s.truncate(i);
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

// --- Rock Ridge -----------------------------------------------------------------------------------

/// What a file's System Use entries say, gathered over its System Use area and any continuation
/// areas (`CE`).
#[derive(Default)]
pub struct RockRidge {
    /// `SP`: SUSP is in use; the bytes to skip at the start of every System Use area.
    pub sp_skip: Option<u8>,
    /// `ER` or `RR`: Rock Ridge is the extension in use.
    pub extension: bool,
    /// `PX`: POSIX mode (with type bits), links, owner, group.
    pub mode: Option<u32>,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// `NM`: the POSIX name, pieced together.
    pub name: Option<String>,
    /// `SL`: a symbolic link's target, pieced together.
    pub link: Option<String>,
    /// Whether `link`'s last component continues in the next component record.
    link_continues: bool,
    /// `TF`: times, seconds since the epoch.
    pub birthtime: Option<i64>,
    pub mtime: Option<i64>,
    pub atime: Option<i64>,
    pub ctime: Option<i64>,
    /// `CL`: this entry stands for a directory relocated to this block.
    pub child: Option<u32>,
    /// `PL`: (in a relocated directory's `..`) its real parent's block.
    pub parent: Option<u32>,
    /// `RE`: this is a relocated directory's own entry, shown only at its `CL` entry.
    pub relocated: bool,
    /// `CE`: the next continuation area, `(block, offset, length)`.
    pub continuation: Option<(u32, u32, u32)>,
    /// Some entry was understood: the area is Rock Ridge's.
    pub any: bool,
}

/// Name and link flags (`NM`, `SL` components).
const NM_CONTINUE: u8 = 0x01;
const NM_CURRENT: u8 = 0x02;
const NM_PARENT: u8 = 0x04;
const SL_ROOT: u8 = 0x08;
const SL_VOLROOT: u8 = 0x10;
const SL_HOST: u8 = 0x20;

impl RockRidge {
    /// Reads the SUSP entries in `area` (a System Use area or a continuation area) into `self`.
    /// A `CE` entry is recorded in `continuation` (replacing the one being followed): the caller
    /// reads that area next and calls this again, bounding how many it follows.
    pub fn parse(&mut self, area: &[u8]) {
        self.continuation = None;
        let mut at = 0;
        while at + 4 <= area.len() {
            let sig = [area[at], area[at + 1]];
            let len = area[at + 2] as usize;
            if sig[0] == 0 || len < 4 || at + len > area.len() {
                break;
            }
            let e = &area[at..at + len];
            match &sig {
                b"SP" if len >= 7 && e[4] == 0xBE && e[5] == 0xEF => self.sp_skip = Some(e[6]),
                b"CE" if len >= 28 => self.continuation = Some((le32(e, 4), le32(e, 12), le32(e, 20))),
                b"ER" | b"RR" => self.extension = true,
                b"ST" => break,
                b"PX" if len >= 36 => {
                    self.mode = Some(le32(e, 4));
                    self.nlink = le32(e, 12);
                    self.uid = le32(e, 20);
                    self.gid = le32(e, 28);
                    self.any = true;
                }
                b"NM" if len >= 5 => {
                    let name = self.name.get_or_insert_with(String::new);
                    if e[4] & NM_CURRENT != 0 {
                        name.push('.');
                    } else if e[4] & NM_PARENT != 0 {
                        name.push_str("..");
                    } else {
                        name.push_str(&String::from_utf8_lossy(&e[5..]));
                    }
                    self.any = true;
                }
                b"SL" if len >= 5 => {
                    self.link_components(&e[5..]);
                    self.any = true;
                }
                b"TF" if len >= 5 => {
                    self.times(e[4], &e[5..]);
                    self.any = true;
                }
                b"CL" if len >= 12 => {
                    self.child = Some(le32(e, 4));
                    self.any = true;
                }
                b"PL" if len >= 12 => {
                    self.parent = Some(le32(e, 4));
                    self.any = true;
                }
                b"RE" => {
                    self.relocated = true;
                    self.any = true;
                }
                _ => {}
            }
            at += len;
        }
    }

    /// An `SL` entry's component records, appended to `link`.
    fn link_components(&mut self, mut c: &[u8]) {
        let link = self.link.get_or_insert_with(String::new);
        while c.len() >= 2 {
            let (flags, len) = (c[0], c[1] as usize);
            if 2 + len > c.len() {
                break;
            }
            let text = &c[2..2 + len];
            if !self.link_continues && !link.is_empty() && !link.ends_with('/') {
                link.push('/');
            }
            if flags & (SL_ROOT | SL_VOLROOT | SL_HOST) != 0 {
                link.clear();
                link.push('/');
            } else if flags & NM_CURRENT != 0 {
                link.push('.');
            } else if flags & NM_PARENT != 0 {
                link.push_str("..");
            } else {
                link.push_str(&String::from_utf8_lossy(text));
            }
            self.link_continues = flags & NM_CONTINUE != 0;
            c = &c[2 + len..];
        }
    }

    /// A `TF` entry's stamps, in their fixed order, each present if its flag is set.
    fn times(&mut self, flags: u8, mut stamps: &[u8]) {
        const LONG_FORM: u8 = 0x80;
        let size = if flags & LONG_FORM != 0 { 17 } else { 7 };
        for bit in 0..7 {
            if flags & (1 << bit) == 0 {
                continue;
            }
            if stamps.len() < size {
                break;
            }
            let t = if size == 17 { time17(&stamps[..17]) } else { time7(&stamps[..7]) };
            match bit {
                0 => self.birthtime = Some(t),
                1 => self.mtime = Some(t),
                2 => self.atime = Some(t),
                3 => self.ctime = Some(t),
                _ => {} // backup, expiration, effective
            }
            stamps = &stamps[size..];
        }
    }
}

// --- Times ----------------------------------------------------------------------------------------

/// Days from 1970-01-01 to `y`-`m`-`d` (proleptic Gregorian; Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64, gmt_quarters: i8) -> i64 {
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return 0;
    }
    days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - gmt_quarters as i64 * 900
}

/// A 7-byte directory record time (ECMA-119 9.1.5): years since 1900, month, day, hour, minute,
/// second, offset from GMT in 15-minute steps. `0` for an unset one.
pub fn time7(b: &[u8]) -> i64 {
    if b.len() < 7 {
        return 0;
    }
    unix(1900 + b[0] as i64, b[1] as i64, b[2] as i64, b[3] as i64, b[4] as i64, b[5] as i64, b[6] as i8)
}

/// A 17-byte volume descriptor time (ECMA-119 8.4.26.1): sixteen ASCII digits
/// `YYYYMMDDHHMMSScc` and the GMT offset byte. `0` for an unset (all-zero-digit) one.
pub fn time17(b: &[u8]) -> i64 {
    if b.len() < 17 {
        return 0;
    }
    let num = |r: core::ops::Range<usize>| {
        b[r].iter().try_fold(0i64, |n, &c| c.is_ascii_digit().then(|| n * 10 + (c - b'0') as i64))
    };
    match (num(0..4), num(4..6), num(6..8), num(8..10), num(10..12), num(12..14)) {
        (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) => unix(y, mo, d, h, mi, s, b[16] as i8),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec::Vec;

    fn rec(name: &[u8], flags: u8, su: &[u8]) -> Vec<u8> {
        let mut r = alloc::vec![0u8; 33];
        r[2..6].copy_from_slice(&20u32.to_le_bytes());
        r[10..14].copy_from_slice(&4096u32.to_le_bytes());
        r[18..25].copy_from_slice(&[125, 10, 18, 12, 0, 0, 0]);
        r[25] = flags;
        r[32] = name.len() as u8;
        r.extend_from_slice(name);
        if name.len() % 2 == 0 {
            r.push(0);
        }
        r.extend_from_slice(su);
        if r.len() % 2 == 1 {
            r.push(0);
        }
        r[0] = r.len() as u8;
        r
    }

    #[test]
    fn records_and_names() {
        let mut block = rec(&[0], FLAG_DIRECTORY, &[]);
        block.extend(rec(&[1], FLAG_DIRECTORY, &[]));
        block.extend(rec(b"README.TXT;1", 0, &[]));
        block.extend(rec(b"NOEXT.;1", 0, &[]));
        block.resize(BLOCK, 0);
        let all: Vec<_> = records(&block).collect();
        assert_eq!(all.len(), 4);
        assert!(all[0].1.is_self() && all[1].1.is_parent() && all[0].1.is_dir());
        assert_eq!(plain_name(all[2].1.name), "readme.txt");
        assert_eq!(plain_name(all[3].1.name), "noext");
        assert_eq!(all[2].1.extent, 20);
        assert_eq!(all[2].1.size, 4096);
        assert_eq!(all[2].1.recorded, 1_760_788_800); // 2025-10-18 12:00:00 UTC
    }

    #[test]
    fn malformed_records_stop() {
        assert!(record(&[0u8; 40]).is_none());
        let mut r = rec(b"A;1", 0, &[]);
        r[32] = 200; // a name longer than the record
        assert!(record(&r).is_none());
        let r = rec(b"A;1", 0, &[]);
        assert!(record(&r[..20]).is_none()); // cut short
    }

    #[test]
    fn joliet() {
        let name: Vec<u8> = "Mixed Case ünï.txt;1".encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        assert_eq!(joliet_name(&name), "Mixed Case ünï.txt");
        let name: Vec<u8> = "dir".encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
        assert_eq!(joliet_name(&name), "dir");
    }

    #[test]
    fn rock_ridge() {
        let mut su = Vec::new();
        su.extend([b'S', b'P', 7, 1, 0xBE, 0xEF, 0]);
        su.extend([b'R', b'R', 5, 1, 0x89]);
        let mut px = alloc::vec![b'P', b'X', 44, 1];
        for v in [0o100644u32, 1, 1000, 100, 0] {
            px.extend(v.to_le_bytes());
            px.extend(v.to_be_bytes());
        }
        su.extend(px);
        su.extend([b'N', b'M', 9, 1, NM_CONTINUE, b'l', b'o', b'n', b'g']);
        su.extend([b'N', b'M', 10, 1, 0, b'-', b'n', b'a', b'm', b'e']);
        // a/../b, the first component split over two records, then the root.
        su.extend([b'S', b'L', 17, 1, 0, NM_CONTINUE, 1, b'a', 0, 1, b'b', NM_PARENT, 0, 0, 1, b'c', 0]);
        su.extend([b'T', b'F', 12, 1, 0x02, 125, 10, 18, 12, 0, 0, 4]);
        let mut rr = RockRidge::default();
        rr.parse(&su);
        assert_eq!(rr.sp_skip, Some(0));
        assert!(rr.extension && rr.any);
        assert_eq!(rr.mode, Some(0o100644));
        assert_eq!((rr.uid, rr.gid), (1000, 100));
        assert_eq!(rr.name.as_deref(), Some("long-name"));
        assert_eq!(rr.link.as_deref(), Some("ab/../c"));
        assert_eq!(rr.mtime, Some(1_760_788_800 - 3600));
        let mut root = RockRidge::default();
        root.parse(&[b'S', b'L', 7, 1, 0, SL_ROOT, 0, b'S', b'L', 10, 1, 0, 0, 3, b'u', b's', b'r']);
        // An SL entry ends its last component unless it says otherwise.
        assert_eq!(root.link.as_deref(), Some("/usr"));
    }

    #[test]
    fn rock_ridge_malformed() {
        let mut rr = RockRidge::default();
        rr.parse(&[b'P', b'X', 200, 1, 0, 0]); // longer than the area
        assert!(rr.mode.is_none());
        rr.parse(&[b'N', b'M', 2, 1]); // shorter than a header
        assert!(rr.name.is_none());
        rr.parse(&[b'C', b'E', 28, 1, 5, 0, 0, 0, 0, 0, 0, 5, 9, 0, 0, 0, 0, 0, 0, 9, 7, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(rr.continuation, Some((5, 9, 7)));
    }

    #[test]
    fn times() {
        assert_eq!(time7(&[70, 1, 1, 0, 0, 0, 0]), 0);
        assert_eq!(time7(&[0; 7]), 0);
        assert_eq!(time17(b"2025101812000000\0"), 1_760_788_800);
        assert_eq!(time17(b"0000000000000000\0"), 0);
    }
}
