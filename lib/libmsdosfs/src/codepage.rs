//! Code pages: how a short (8.3) name's bytes map to characters (§7's "OEM code page"). Long
//! names are UTF-16 and need none. CP437, the original IBM PC's and FAT's default, is built in;
//! any other comes as a compiled table (`compile`), which mount_msdosfs(8) makes from a file in
//! `/usr/share/msdosfs` and passes to the kernel with the mount (FreeBSD's `-D`).
//!
//! A compiled table, little-endian: the magic `OXCP`, a `u16` version (1), a `u16` count `n`, a
//! 32-byte bitmap of the double-byte lead bytes, `n` pairs of `u16` code and `u16` character
//! sorted by code, then `n` `u16` indices of those pairs sorted by character. A single byte below
//! `0x80` that isn't listed (and isn't a lead) is itself; any other code that isn't listed is
//! undefined. Characters are the Basic Multilingual Plane's.

const MAGIC: &[u8; 4] = b"OXCP";
const VERSION: u16 = 1;
const HEADER: usize = 8 + 32;

/// CP437's characters for bytes `0x80..=0xFF`.
static CP437_HIGH: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
    0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
    0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4,
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
];

/// A code page.
#[derive(Clone, Copy, Debug)]
pub enum Codepage<'a> {
    Cp437,
    Table(Table<'a>),
}

/// A compiled table, checked by `Codepage::parse`.
#[derive(Clone, Copy, Debug)]
pub struct Table<'a> {
    lead: &'a [u8],
    pairs: &'a [u8],
    by_char: &'a [u8],
    n: usize,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

impl<'a> Table<'a> {
    fn code(&self, i: usize) -> u16 {
        le16(self.pairs, i * 4)
    }

    fn char_of(&self, i: usize) -> u16 {
        le16(self.pairs, i * 4 + 2)
    }

    fn by_char(&self, i: usize) -> usize {
        le16(self.by_char, i * 2) as usize
    }

    fn lookup_code(&self, code: u16) -> Option<u16> {
        let (mut lo, mut hi) = (0, self.n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            match self.code(mid).cmp(&code) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(self.char_of(mid)),
            }
        }
        None
    }

    /// The lowest code for character `c`: ties are sorted by code, so the first of them.
    fn lookup_char(&self, c: u16) -> Option<u16> {
        let (mut lo, mut hi) = (0, self.n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.char_of(self.by_char(mid)) < c {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        (lo < self.n && self.char_of(self.by_char(lo)) == c).then(|| self.code(self.by_char(lo)))
    }
}

impl<'a> Codepage<'a> {
    /// A compiled table's code page, if `bytes` is a well-formed one.
    pub fn parse(bytes: &'a [u8]) -> Option<Codepage<'a>> {
        if bytes.len() < HEADER || &bytes[..4] != MAGIC || le16(bytes, 4) != VERSION {
            return None;
        }
        let n = le16(bytes, 6) as usize;
        if bytes.len() != HEADER + n * 6 {
            return None;
        }
        let t = Table { lead: &bytes[8..HEADER], pairs: &bytes[HEADER..HEADER + n * 4], by_char: &bytes[HEADER + n * 4..], n };
        for i in 0..n {
            let code = t.code(i);
            // A code is one byte, or a lead byte and a trail byte.
            let ok = if code > 0xFF { t.lead[(code >> 11) as usize] & (1 << ((code >> 8) & 7)) != 0 } else { t.lead[(code >> 3) as usize] & (1 << (code & 7)) == 0 };
            if !ok || (i > 0 && t.code(i - 1) >= code) || t.by_char(i) >= n || (i > 0 && t.char_of(t.by_char(i - 1)) > t.char_of(t.by_char(i))) {
                return None;
            }
        }
        Some(Codepage::Table(t))
    }

    /// Whether `b` begins a two-byte code.
    pub fn is_lead(&self, b: u8) -> bool {
        match self {
            Codepage::Cp437 => false,
            Codepage::Table(t) => t.lead[(b >> 3) as usize] & (1 << (b & 7)) != 0,
        }
    }

    /// The character at `bytes[*at..]`, moving `at` past it: `None` if its code is undefined
    /// (`at` still moves past it).
    pub fn decode(&self, bytes: &[u8], at: &mut usize) -> Option<char> {
        let b = bytes[*at];
        *at += 1;
        let code = if self.is_lead(b) {
            let Some(&trail) = bytes.get(*at) else { return None };
            *at += 1;
            (b as u16) << 8 | trail as u16
        } else {
            b as u16
        };
        let c = match self {
            Codepage::Cp437 => if code < 0x80 { code } else { CP437_HIGH[code as usize - 0x80] },
            Codepage::Table(t) => match t.lookup_code(code) {
                Some(c) => c,
                None if code < 0x80 => code,
                None => return None,
            },
        };
        char::from_u32(c as u32)
    }

    /// `c`'s code into `out`: its length (1 or 2), or 0 if this code page can't represent it.
    pub fn encode(&self, c: char, out: &mut [u8; 2]) -> usize {
        let Ok(u) = u16::try_from(c as u32) else { return 0 };
        let code = match self {
            Codepage::Cp437 => {
                if u < 0x80 {
                    u
                } else {
                    match CP437_HIGH.iter().position(|&x| x == u) {
                        Some(i) => 0x80 + i as u16,
                        None => return 0,
                    }
                }
            }
            Codepage::Table(t) => match t.lookup_char(u) {
                Some(code) => code,
                // ASCII is itself, unless the table moved it elsewhere (CP864's `%`).
                None if u < 0x80 && t.lookup_code(u).is_none() && !self.is_lead(u as u8) => u,
                None => return 0,
            },
        };
        if code > 0xFF {
            *out = code.to_be_bytes();
            2
        } else {
            out[0] = code as u8;
            1
        }
    }
}

/// Bytes a compiled table of `n` codes takes.
pub fn table_len(n: usize) -> usize {
    HEADER + n * 6
}

/// Compiles `pairs` (code, character) and the lead bytes `leads` into `out` (`table_len` bytes):
/// `pairs` is sorted by code here. `None` if there are more than 65535, or two share a code.
pub fn compile(leads: &[u8], pairs: &mut [(u16, u16)], out: &mut [u8]) -> Option<()> {
    let n = u16::try_from(pairs.len()).ok()?;
    if out.len() != table_len(pairs.len()) {
        return None;
    }
    pairs.sort_unstable();
    if pairs.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }
    out[..4].copy_from_slice(MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&n.to_le_bytes());
    out[8..HEADER].fill(0);
    for &l in leads {
        out[8 + (l >> 3) as usize] |= 1 << (l & 7);
    }
    for (i, &(code, c)) in pairs.iter().enumerate() {
        let at = HEADER + i * 4;
        out[at..at + 2].copy_from_slice(&code.to_le_bytes());
        out[at + 2..at + 4].copy_from_slice(&c.to_le_bytes());
    }
    // The indices sorted by character, ties by code (so the lowest code wins an encode): an
    // insertion sort in place, no allocation (a table has a few thousand entries at most and is
    // compiled once per mount).
    let idx = HEADER + pairs.len() * 4;
    for i in 0..pairs.len() {
        out[idx + i * 2..idx + i * 2 + 2].copy_from_slice(&(i as u16).to_le_bytes());
    }
    let key = |out: &[u8], k: usize| -> (u16, u16) {
        let i = le16(out, idx + k * 2) as usize;
        (pairs[i].1, pairs[i].0)
    };
    // Shell sort: fast enough for 22000 entries, still allocation-free.
    let mut gap = pairs.len() / 2;
    while gap > 0 {
        for i in gap..pairs.len() {
            let mut j = i;
            while j >= gap && key(out, j - gap) > key(out, j) {
                let (a, b) = (idx + (j - gap) * 2, idx + j * 2);
                let (x, y) = ([out[a], out[a + 1]], [out[b], out[b + 1]]);
                out[a..a + 2].copy_from_slice(&y);
                out[b..b + 2].copy_from_slice(&x);
                j -= gap;
            }
        }
        gap /= 2;
    }
    Some(())
}

/// Parses a `/usr/share/msdosfs` file's text (see `share/msdosfs/mkcodepages.py`) into `pairs`
/// and `leads` through the two callbacks; `Err` names the first bad line.
pub fn parse_text(text: &str, mut pair: impl FnMut(u16, u16), mut lead: impl FnMut(u8)) -> Result<(), usize> {
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_whitespace();
        let (Some(a), Some(b), None) = (f.next(), f.next(), f.next()) else { return Err(n + 1) };
        let code = u16::from_str_radix(a, 16).map_err(|_| n + 1)?;
        if b == "lead" {
            lead(u8::try_from(code).map_err(|_| n + 1)?);
        } else {
            pair(code, u16::from_str_radix(b, 16).map_err(|_| n + 1)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Every file `/usr/share/msdosfs` installs compiles, and each code decodes to its character
    /// and back (to itself, or to the lowest code sharing that character).
    #[test]
    fn shipped_tables() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../share/msdosfs");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.file_name().unwrap().to_str().unwrap().starts_with("CP") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let (mut pairs, mut leads) = (Vec::new(), Vec::new());
            parse_text(&text, |c, u| pairs.push((c, u)), |l| leads.push(l)).unwrap();
            let mut buf = std::vec![0u8; table_len(pairs.len())];
            compile(&leads, &mut pairs, &mut buf).unwrap();
            let cp = Codepage::parse(&buf).unwrap_or_else(|| panic!("{}", path.display()));
            for &(code, u) in &pairs {
                let bytes = if code > 0xFF { std::vec![(code >> 8) as u8, code as u8] } else { std::vec![code as u8] };
                let mut at = 0;
                assert_eq!(cp.decode(&bytes, &mut at).map(|c| c as u32), Some(u as u32), "{} {code:x}", path.display());
                let mut out = [0u8; 2];
                let n = cp.encode(char::from_u32(u as u32).unwrap(), &mut out);
                let back = if n == 2 { u16::from_be_bytes(out) } else { out[0] as u16 };
                let lowest = pairs.iter().filter(|p| p.1 == u).map(|p| p.0).min().unwrap();
                assert_eq!(back, lowest, "{} {code:x}", path.display());
            }
            count += 1;
        }
        assert_eq!(count, 30);
    }

    #[test]
    fn cp437() {
        let cp = Codepage::Cp437;
        let mut at = 0;
        assert_eq!(cp.decode(&[0x82], &mut at), Some('é'));
        let mut out = [0; 2];
        assert_eq!(cp.encode('É', &mut out), 1);
        assert_eq!(out[0], 0x90);
        assert_eq!(cp.encode('A', &mut out), 1);
        assert_eq!(cp.encode('€', &mut out), 0);
    }

    #[test]
    fn dbcs_round_trip() {
        // A tiny "code page": 0x81 a lead byte, 0x8140 an ideographic space, 0x5C a yen sign.
        let mut pairs = [(0x8140u16, 0x3000u16), (0x5C, 0xA5), (0xA1, 0xFF61)];
        let mut buf = [0u8; 64];
        let len = table_len(pairs.len());
        compile(&[0x81], &mut pairs, &mut buf[..len]).unwrap();
        let cp = Codepage::parse(&buf[..len]).unwrap();
        let mut at = 0;
        let s = [0x81, 0x40, 0x5C, b'A', 0xA1];
        let decoded: [Option<char>; 4] = core::array::from_fn(|_| cp.decode(&s, &mut at));
        assert_eq!(decoded, [Some('\u{3000}'), Some('¥'), Some('A'), Some('\u{FF61}')]);
        let mut out = [0; 2];
        assert_eq!(cp.encode('\u{3000}', &mut out), 2);
        assert_eq!(out, [0x81, 0x40]);
        // The yen sign took 0x5C, so a backslash has no code.
        assert_eq!(cp.encode('\\', &mut out), 0);
        assert!(Codepage::parse(&buf[..len - 1]).is_none());
    }
}
