//! The fixed tables of RFC 1951 §3.2.5, shared by both directions.

/// Base lengths of length symbols 257..=285.
pub const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
pub const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];

/// Base distances of distance symbols 0..=29.
pub const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
pub const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// The order code length code lengths are sent in.
pub const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// The fixed literal/length code (§3.2.6).
pub const fn fixed_lit_lengths() -> [u8; 288] {
    let mut l = [0u8; 288];
    let mut i = 0;
    while i < 288 {
        l[i] = if i < 144 {
            8
        } else if i < 256 {
            9
        } else if i < 280 {
            7
        } else {
            8
        };
        i += 1;
    }
    l
}

/// The fixed distance code: all 32 symbols, five bits each (30 and 31 are invalid to use, but
/// they make the code complete).
pub const FIXED_DIST_LENGTHS: [u8; 32] = [5; 32];

/// Length symbol index (0..=28, add 257) of each match length minus 3.
pub const LEN_CODE: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut code = 0;
    while code < 28 {
        let base = LEN_BASE[code] as usize - 3;
        let mut k = 0;
        while k < (1 << LEN_EXTRA[code]) {
            t[base + k] = code as u8;
            k += 1;
        }
        code += 1;
    }
    // 258 has its own symbol, 285, though 284 with extra bits 31 also reaches it.
    t[255] = 28;
    t
};

/// Distance symbol of a distance 1..=32768.
#[inline]
pub fn dist_code(dist: u32) -> usize {
    let x = dist - 1;
    if x < 4 {
        x as usize
    } else {
        let nb = 31 - x.leading_zeros();
        (2 * nb + ((x >> (nb - 1)) & 1)) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_cover_their_ranges() {
        for len in 3..=258usize {
            let c = LEN_CODE[len - 3] as usize;
            let base = LEN_BASE[c] as usize;
            assert!(len >= base && len - base < (1 << LEN_EXTRA[c]), "length {len}");
        }
        for d in 1..=32768u32 {
            let c = dist_code(d);
            let base = DIST_BASE[c] as u32;
            assert!(d >= base && d - base < (1 << DIST_EXTRA[c]), "distance {d}");
        }
    }
}
