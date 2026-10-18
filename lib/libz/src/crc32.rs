//! CRC-32 as gzip and zip use it (reflected polynomial 0xedb88320), slicing-by-8: eight bytes
//! per step through eight 256-entry tables built at compile time.

const fn make_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut s = 1;
        while s < 8 {
            t[s][i] = (t[s - 1][i] >> 8) ^ t[0][(t[s - 1][i] & 0xff) as usize];
            s += 1;
        }
        i += 1;
    }
    t
}

static T: [[u32; 256]; 8] = make_tables();

/// A running CRC-32.
#[derive(Clone, Copy, Debug)]
pub struct Crc32 {
    /// The register, kept inverted between calls.
    reg: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Crc32::new()
    }
}

impl Crc32 {
    pub const fn new() -> Crc32 {
        Crc32 { reg: !0 }
    }

    /// Continues from a finished value (`crc32(a)` then `update(b)` gives `crc32(a ++ b)`).
    pub const fn resume(value: u32) -> Crc32 {
        Crc32 { reg: !value }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut c = self.reg;
        let mut chunks = data.chunks_exact(8);
        for b in &mut chunks {
            let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) ^ c;
            let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
            c = T[7][(lo & 0xff) as usize]
                ^ T[6][((lo >> 8) & 0xff) as usize]
                ^ T[5][((lo >> 16) & 0xff) as usize]
                ^ T[4][(lo >> 24) as usize]
                ^ T[3][(hi & 0xff) as usize]
                ^ T[2][((hi >> 8) & 0xff) as usize]
                ^ T[1][((hi >> 16) & 0xff) as usize]
                ^ T[0][(hi >> 24) as usize];
        }
        for &b in chunks.remainder() {
            c = T[0][((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
        }
        self.reg = c;
    }

    pub const fn value(&self) -> u32 {
        !self.reg
    }
}

/// The CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bitwise definition, to check the tables against.
    fn slow(data: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            }
        }
        !c
    }

    #[test]
    fn vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414f_a339);
    }

    #[test]
    fn matches_bitwise_at_every_alignment() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        for start in 0..9 {
            for len in [0, 1, 7, 8, 9, 15, 16, 17, 100, 991 - start] {
                assert_eq!(crc32(&data[start..start + len]), slow(&data[start..start + len]));
            }
        }
        let mut c = Crc32::new();
        c.update(&data[..333]);
        let mut r = Crc32::resume(c.value());
        r.update(&data[333..]);
        assert_eq!(r.value(), slow(&data));
    }
}
