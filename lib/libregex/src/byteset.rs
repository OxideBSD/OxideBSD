//! A set of bytes: what one position of the pattern (a literal, `.` or a bracket expression)
//! accepts. Matching is byte-oriented, in the POSIX locale.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ByteSet([u64; 4]);

impl ByteSet {
    pub const fn new() -> ByteSet {
        ByteSet([0; 4])
    }

    pub const fn full() -> ByteSet {
        ByteSet([!0; 4])
    }

    pub fn single(b: u8) -> ByteSet {
        let mut s = ByteSet::new();
        s.insert(b);
        s
    }

    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] >> (b & 63) & 1 != 0
    }

    pub fn insert(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1 << (b & 63);
    }

    pub fn remove(&mut self, b: u8) {
        self.0[(b >> 6) as usize] &= !(1 << (b & 63));
    }

    pub fn insert_range(&mut self, lo: u8, hi: u8) {
        for b in lo..=hi {
            self.insert(b);
        }
    }

    pub fn union(&mut self, o: &ByteSet) {
        for i in 0..4 {
            self.0[i] |= o.0[i];
        }
    }

    pub fn negate(&mut self) {
        for w in &mut self.0 {
            *w = !*w;
        }
    }

    /// Adds the other case of every ASCII letter (`REG_ICASE`; the POSIX locale has no others).
    pub fn fold_case(&mut self) {
        for b in b'a'..=b'z' {
            let u = b.to_ascii_uppercase();
            if self.contains(b) || self.contains(u) {
                self.insert(b);
                self.insert(u);
            }
        }
    }
}

/// The POSIX locale's character classes (XBD 7.3.1), or `None` for an unknown name.
pub fn class(name: &[u8]) -> Option<ByteSet> {
    let mut s = ByteSet::new();
    let mut add = |lo: u8, hi: u8| s.insert_range(lo, hi);
    match name {
        b"alpha" => {
            add(b'A', b'Z');
            add(b'a', b'z');
        }
        b"digit" => add(b'0', b'9'),
        b"alnum" => {
            add(b'0', b'9');
            add(b'A', b'Z');
            add(b'a', b'z');
        }
        b"upper" => add(b'A', b'Z'),
        b"lower" => add(b'a', b'z'),
        b"space" => {
            add(b'\t', b'\r');
            add(b' ', b' ');
        }
        b"blank" => {
            add(b'\t', b'\t');
            add(b' ', b' ');
        }
        b"punct" => {
            add(0x21, 0x2f);
            add(0x3a, 0x40);
            add(0x5b, 0x60);
            add(0x7b, 0x7e);
        }
        b"print" => add(0x20, 0x7e),
        b"graph" => add(0x21, 0x7e),
        b"cntrl" => {
            add(0, 0x1f);
            add(0x7f, 0x7f);
        }
        b"xdigit" => {
            add(b'0', b'9');
            add(b'A', b'F');
            add(b'a', b'f');
        }
        _ => return None,
    }
    Some(s)
}
