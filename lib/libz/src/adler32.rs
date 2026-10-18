//! Adler-32 (RFC 1950 §9), the zlib wrapper's check value.

const BASE: u32 = 65521;
/// The most bytes summed before `b` can overflow 32 bits (zlib's NMAX).
const NMAX: usize = 5552;

/// A running Adler-32.
#[derive(Clone, Copy, Debug)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

impl Default for Adler32 {
    fn default() -> Self {
        Adler32::new()
    }
}

impl Adler32 {
    pub const fn new() -> Adler32 {
        Adler32 { a: 1, b: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        let (mut a, mut b) = (self.a, self.b);
        for chunk in data.chunks(NMAX) {
            for &x in chunk {
                a += x as u32;
                b += a;
            }
            a %= BASE;
            b %= BASE;
        }
        self.a = a;
        self.b = b;
    }

    pub const fn value(&self) -> u32 {
        (self.b << 16) | self.a
    }
}

/// The Adler-32 of `data`.
pub fn adler32(data: &[u8]) -> u32 {
    let mut a = Adler32::new();
    a.update(data);
    a.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        // All 0xff: the worst case for the deferred modulo.
        let ff = vec![0xffu8; 100_000];
        let (mut a, mut b) = (1u64, 0u64);
        for &x in &ff {
            a = (a + x as u64) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!(adler32(&ff), ((b << 16) | a) as u32);
    }
}
