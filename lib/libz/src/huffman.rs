//! Huffman codes: optimal length-limited code lengths for the compressor (package-merge),
//! canonical codes from lengths, and the decoder's lookup tables.

use crate::Error;

/// Optimal code lengths for `freqs`, none longer than `limit` bits, written to `out`
/// (`out.len() == freqs.len()`). Unused symbols get 0. Like zlib, at least two symbols always
/// get a code, so a code is never a single zero-bit one: when fewer than two are used, the
/// lowest unused ones are given length 1.
///
/// Package-merge (Larmore and Hirschberg): the cheapest way to pick 2n - 2 items from `limit`
/// copies of the leaves, each copy after the first only as half of a pair ("package"), gives
/// each symbol a length equal to the number of its copies chosen. `n <= 2^limit` must hold.
pub fn lengths(freqs: &[u32], limit: u32, out: &mut [u8]) {
    debug_assert_eq!(freqs.len(), out.len());
    out.fill(0);
    let mut syms: Vec<usize> = (0..freqs.len()).filter(|&i| freqs[i] != 0).collect();
    if syms.len() < 2 {
        let mut want = 2 - syms.len();
        for (i, l) in out.iter_mut().enumerate() {
            if want == 0 {
                break;
            }
            if freqs[i] == 0 {
                *l = 1;
                want -= 1;
            }
        }
        if let Some(&s) = syms.first() {
            out[s] = 1;
        }
        return;
    }
    syms.sort_by_key(|&s| (freqs[s], s));
    let n = syms.len();
    debug_assert!(n <= 1 << limit);

    // Node `i < n` is the leaf syms[i]; later nodes are packages of two earlier ones.
    let mut weight: Vec<u64> = syms.iter().map(|&s| freqs[s] as u64).collect();
    let mut kids: Vec<(u32, u32)> = vec![(0, 0); n];
    let leaves: Vec<u32> = (0..n as u32).collect();
    let mut list = leaves.clone();
    for _ in 1..limit {
        let mut packages = Vec::with_capacity(list.len() / 2);
        for pair in list.chunks_exact(2) {
            let id = weight.len() as u32;
            weight.push(weight[pair[0] as usize] + weight[pair[1] as usize]);
            kids.push((pair[0], pair[1]));
            packages.push(id);
        }
        // Merge by weight; leaves first on ties, which keeps codes short for the same cost.
        let mut merged = Vec::with_capacity(n + packages.len());
        let (mut i, mut j) = (0, 0);
        while i < n || j < packages.len() {
            if j == packages.len() || (i < n && weight[leaves[i] as usize] <= weight[packages[j] as usize]) {
                merged.push(leaves[i]);
                i += 1;
            } else {
                merged.push(packages[j]);
                j += 1;
            }
        }
        list = merged;
    }
    // Every node below the chosen items belongs to exactly one of them, so this walk visits
    // each node at most once.
    let mut stack: Vec<u32> = list[..2 * n - 2].to_vec();
    while let Some(id) = stack.pop() {
        let id = id as usize;
        if id < n {
            out[syms[id]] += 1;
        } else {
            stack.push(kids[id].0);
            stack.push(kids[id].1);
        }
    }
}

/// Reverses the low `len` bits of `code`: DEFLATE sends Huffman codes most significant bit
/// first into an LSB-first bit stream.
#[inline]
pub fn reverse(code: u32, len: u32) -> u32 {
    code.reverse_bits() >> (32 - len)
}

/// Canonical codes (§3.2.2) for `lens`, bit-reversed ready to send.
pub fn codes(lens: &[u8], out: &mut [u16]) {
    let mut count = [0u32; 16];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut code = 0;
    for l in 1..16 {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    for (i, &l) in lens.iter().enumerate() {
        if l != 0 {
            out[i] = reverse(next[l as usize], l as u32) as u16;
            next[l as usize] += 1;
        } else {
            out[i] = 0;
        }
    }
}

/// Entry flags. An entry is `symbol << 16 | flags | length`, with the code's full length in
/// the low five bits; a subtable link is `offset << 16 | SUB | subtable bits`.
pub const SUB: u32 = 0x20;
pub const BAD: u32 = 0x40;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    CodeLen,
    LitLen,
    Dist,
}

/// A decoding table: `1 << root` primary entries indexed by the next `root` input bits, then
/// the subtables for longer codes, each indexed by the bits after the first `root`.
#[derive(Clone)]
pub struct Table {
    e: Vec<u32>,
    root: u32,
}

impl Table {
    /// A table every lookup of which fails (a block with no distance codes).
    pub fn empty() -> Table {
        Table { e: vec![BAD], root: 0 }
    }

    /// Builds the table for code lengths `lens` (each 0..=15). Validation follows zlib's
    /// inflate, the reference everyone interoperates with: an over-subscribed code is always
    /// an error; an incomplete one is accepted only for literal/length or distance codes made
    /// of a single one-bit code; no codes at all is accepted for distances (a block of only
    /// literals) and for literal/lengths (the caller rejects that: no end-of-block).
    pub fn build(lens: &[u8], root: u32, kind: Kind) -> Result<Table, Error> {
        let err = match kind {
            Kind::CodeLen => Error::BadCodeLengths,
            Kind::LitLen => Error::BadLitLenCode,
            Kind::Dist => Error::BadDistCode,
        };
        let mut count = [0i32; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let max = (1..16).rev().find(|&l| count[l] != 0).unwrap_or(0);
        if max == 0 {
            return if kind == Kind::CodeLen { Err(err) } else { Ok(Table::empty()) };
        }
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - c;
            if left < 0 {
                return Err(err);
            }
        }
        if left > 0 && (kind == Kind::CodeLen || max != 1) {
            return Err(err);
        }

        let root = root.min(max as u32);
        let size = 1usize << root;
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for l in 1..16 {
            code = (code + count[l - 1] as u32) << 1;
            next[l] = code;
        }
        let mut e = vec![BAD; size];
        let mut rev = vec![0u32; lens.len()];
        let mut sub_bits = vec![0u32; size];
        for (s, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = l as u32;
            let r = reverse(next[l as usize], l);
            next[l as usize] += 1;
            rev[s] = r;
            if l <= root {
                let mut i = r as usize;
                while i < size {
                    e[i] = (s as u32) << 16 | l;
                    i += 1 << l;
                }
            } else {
                let p = r as usize & (size - 1);
                sub_bits[p] = sub_bits[p].max(l - root);
            }
        }
        for (p, &sb) in sub_bits.iter().enumerate() {
            if sb != 0 {
                let off = e.len();
                e.resize(off + (1 << sb), BAD);
                e[p] = (off as u32) << 16 | SUB | sb;
            }
        }
        for (s, &l) in lens.iter().enumerate() {
            let l = l as u32;
            if l <= root {
                continue;
            }
            let link = e[rev[s] as usize & (size - 1)];
            let off = (link >> 16) as usize;
            let sb = link & 0x1f;
            let mut i = (rev[s] >> root) as usize;
            while i < 1 << sb {
                e[off + i] = (s as u32) << 16 | l;
                i += 1 << (l - root);
            }
        }
        Ok(Table { e, root })
    }

    /// The entry for the code at the bottom of `bits` (which must hold at least 15 bits, zero
    /// padded past the end of the input). The caller checks `BAD` and that the length is
    /// really available.
    #[inline]
    pub fn get(&self, bits: u64) -> u32 {
        let ent = self.e[(bits & ((1u64 << self.root) - 1)) as usize];
        if ent & SUB == 0 {
            return ent;
        }
        let off = (ent >> 16) as usize;
        let sb = ent & 0x1f;
        self.e[off + ((bits >> self.root) & ((1u64 << sb) - 1)) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kraft(lens: &[u8]) -> f64 {
        lens.iter().filter(|&&l| l != 0).map(|&l| 0.5f64.powi(l as i32)).sum()
    }

    #[test]
    fn package_merge_limits_and_completes() {
        // Fibonacci weights make an unlimited Huffman code as deep as possible.
        let mut f = vec![0u32; 286];
        let (mut a, mut b) = (1u32, 1u32);
        for x in f.iter_mut().take(40) {
            *x = a;
            let c = a.saturating_add(b);
            a = b;
            b = c;
        }
        for limit in [7, 9, 15] {
            let mut l = vec![0u8; f.len()];
            lengths(&f, limit, &mut l);
            assert!(l.iter().all(|&x| x as u32 <= limit));
            assert!((kraft(&l) - 1.0).abs() < 1e-12, "complete code");
            assert_eq!(l.iter().filter(|&&x| x != 0).count(), 40);
        }
    }

    #[test]
    fn package_merge_is_huffman_when_unconstrained() {
        let f = [5u32, 9, 12, 13, 16, 45];
        let mut l = [0u8; 6];
        lengths(&f, 15, &mut l);
        let cost: u32 = f.iter().zip(&l).map(|(&f, &l)| f * l as u32).sum();
        assert_eq!(cost, 224); // the textbook optimum
    }

    #[test]
    fn degenerate_inputs_get_two_codes() {
        let mut l = [0u8; 30];
        lengths(&[0; 30], 15, &mut l);
        assert_eq!(&l[..3], &[1, 1, 0]);
        let mut f = [0u32; 30];
        f[7] = 100;
        lengths(&f, 15, &mut l);
        assert_eq!((l[0], l[7], l.iter().filter(|&&x| x != 0).count()), (1, 1, 2));
    }

    #[test]
    fn table_validation() {
        assert_eq!(Table::build(&[1, 1, 1], 9, Kind::LitLen).err(), Some(Error::BadLitLenCode));
        assert_eq!(Table::build(&[1, 2, 0], 9, Kind::Dist).err(), Some(Error::BadDistCode));
        assert!(Table::build(&[0, 1, 0], 9, Kind::Dist).is_ok());
        assert_eq!(Table::build(&[0, 1, 0], 7, Kind::CodeLen).err(), Some(Error::BadCodeLengths));
        assert_eq!(Table::build(&[0; 19], 7, Kind::CodeLen).err(), Some(Error::BadCodeLengths));
    }

    #[test]
    fn table_decodes_long_codes() {
        let mut f = vec![1u32; 286];
        f[0] = 1 << 20;
        f[1] = 1 << 19;
        let mut l = vec![0u8; 286];
        lengths(&f, 15, &mut l);
        let mut c = vec![0u16; 286];
        codes(&l, &mut c);
        let t = Table::build(&l, 9, Kind::LitLen).unwrap();
        for s in 0..286 {
            let ent = t.get(c[s] as u64 | 0x5555_0000_0000 << l[s]);
            assert_eq!((ent >> 16, ent & 0x1f), (s as u32, l[s] as u32));
        }
    }
}
