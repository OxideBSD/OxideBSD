//! Known streams, and hand-built streams for each edge case and error zlib's inflate knows.

use flate::{Error, inflate, zlib};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn zlib_made_vectors() {
    assert_eq!(zlib::decompress(&hex("789ccb48cdc9c90700062c0215")).unwrap(), b"hello");
    assert_eq!(zlib::compress(b"hello", 6), hex("789ccb48cdc9c90700062c0215"));
    assert_eq!(
        zlib::decompress(&hex("78dacb48cdc9c957c8c020cbf38b72527490398a1934510a000ffc2f44")).unwrap(),
        b"hello hello hello hello world, hello world!".repeat(3)
    );
    let mut want = b"Hello, OxideBSD! ".repeat(5);
    want.extend(0..=255u8);
    let raw = hex(concat!(
        "f348cdc9c9d751f0afc84c49750a765154f0a08200032313330b2b1b3b072717370f2f1fbf80a090b088a898b884a494",
        "b48cac9cbc82a292b28aaa9aba86a696b68eae9ebe81a191b189a999b985a595b58dad9dbd83a393b38bab9bbb87a797",
        "b78faf9f7f4060507048685878446454744c6c5c7c426252724a6a5a7a466656764e6e5e7e4161517149695979456555",
        "754d6d5d7d436353734b6b5b7b476757774f6f5fff848993264f993a6dfa8c99b366cf993b6ffe82858b162f59ba6cf9",
        "8a95ab56af59bb6efd868d9b366fd9ba6dfb8e9dbb76efd9bb6fff8183870e1f397aecf88993a74e9f397beefc858b97",
        "2e5fb97aedfa8d9bb76edfb97beffe83878f1e3f79faecf98b97af5ebf79fbeefd878f9f3e7ff9faedfb8f9fbf7efff9",
        "fbef3f00"
    ));
    assert_eq!(inflate::decompress(&raw).unwrap(), want);
}

/// Bits out, least significant first, as DEFLATE packs them.
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn new() -> Bits {
        Bits { out: vec![], acc: 0, n: 0 }
    }

    fn put(&mut self, v: u32, len: u32) {
        self.acc |= (v as u64) << self.n;
        self.n += len;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// A Huffman code, given MSB first.
    fn code(&mut self, code: u32, len: u32) {
        self.put(code.reverse_bits() >> (32 - len), len);
    }

    fn done(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// Fixed-code literal/length symbol.
fn fixed_sym(b: &mut Bits, s: u32) {
    match s {
        0..=143 => b.code(0x30 + s, 8),
        144..=255 => b.code(0x190 + s - 144, 9),
        256..=279 => b.code(s - 256, 7),
        _ => b.code(0xc0 + s - 280, 8),
    }
}

#[test]
fn distance_32768_and_length_258() {
    // A stored block of 32768 bytes, then a fixed block copying 258 bytes from 32768 back.
    let pre: Vec<u8> = (0..32768u32).map(|i| (i * 7 + i / 255) as u8).collect();
    let mut s = Vec::new();
    for c in pre.chunks(16384) {
        s.push(0);
        s.extend_from_slice(&(c.len() as u16).to_le_bytes());
        s.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        s.extend_from_slice(c);
    }
    let mut b = Bits::new();
    b.put(0b011, 3); // final, fixed
    fixed_sym(&mut b, 285); // length 258
    b.code(29, 5); // distance 24577 + 13 extra bits
    b.put(32768 - 24577, 13);
    // And 258 again through symbol 284 with all five extra bits set (227 + 31), which zlib
    // accepts.
    fixed_sym(&mut b, 284);
    b.put(31, 5);
    b.code(0, 5); // distance 1
    fixed_sym(&mut b, 256);
    s.extend(b.done());
    let out = inflate::decompress(&s).unwrap();
    assert_eq!(out.len(), 32768 + 258 + 258);
    assert_eq!(&out[32768..32768 + 258], &pre[..258]);
    assert!(out[32768 + 258..].iter().all(|&x| x == pre[257]));
}

fn fixed_block(f: impl FnOnce(&mut Bits)) -> Vec<u8> {
    let mut b = Bits::new();
    b.put(0b011, 3);
    f(&mut b);
    b.done()
}

#[test]
fn fixed_block_errors() {
    // A match before any output.
    let s = fixed_block(|b| {
        fixed_sym(b, 257);
        b.code(0, 5);
        fixed_sym(b, 256);
    });
    assert_eq!(inflate::decompress(&s), Err(Error::DistanceTooFar));
    // One byte out, then distance 2.
    let s = fixed_block(|b| {
        fixed_sym(b, b'a' as u32);
        fixed_sym(b, 257);
        b.code(1, 5);
        fixed_sym(b, 256);
    });
    assert_eq!(inflate::decompress(&s), Err(Error::DistanceTooFar));
    for sym in [286, 287] {
        let s = fixed_block(|b| {
            fixed_sym(b, sym);
            b.put(0, 16);
        });
        assert_eq!(inflate::decompress(&s), Err(Error::InvalidCode), "symbol {sym}");
    }
    for d in [30, 31] {
        let s = fixed_block(|b| {
            fixed_sym(b, b'a' as u32);
            fixed_sym(b, 257);
            b.code(d, 5);
            b.put(0, 16);
        });
        assert_eq!(inflate::decompress(&s), Err(Error::InvalidCode), "distance symbol {d}");
    }
    // Truncated mid-block.
    let s = fixed_block(|b| fixed_sym(b, b'a' as u32));
    assert_eq!(inflate::decompress(&s), Err(Error::Truncated));
}

/// Canonical codes (MSB first) for `lens`.
fn canon(lens: &[u8]) -> Vec<u32> {
    let mut count = [0u32; 16];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; 16];
    let mut c = 0;
    for l in 1..16 {
        c = (c + count[l - 1]) << 1;
        next[l] = c;
    }
    lens.iter()
        .map(|&l| {
            let v = next[l as usize];
            next[l as usize] += 1;
            v
        })
        .collect()
}

/// A dynamic block header for `ll`/`dl`, the code lengths sent as `cl_syms` (code length
/// symbols with their extra bits) if given, else one by one. The code length code is fixed
/// at 4 bits for symbols 0-12 and 5 for 13-18 (complete).
fn dynamic(b: &mut Bits, last: bool, hlit: usize, hdist: usize, ll: &[u8], dl: &[u8], cl_syms: Option<&[(u32, u32)]>) {
    let cl: Vec<u8> = (0..19).map(|i| if i < 13 { 4 } else { 5 }).collect();
    let clc = canon(&cl);
    b.put(last as u32 | 2 << 1, 3);
    b.put((hlit - 257) as u32, 5);
    b.put((hdist - 1) as u32, 5);
    b.put(15, 4);
    for k in [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15] {
        b.put(cl[k] as u32, 3);
    }
    let own: Vec<(u32, u32)>;
    let syms = match cl_syms {
        Some(s) => s,
        None => {
            own = ll.iter().chain(dl).map(|&l| (l as u32, 0)).collect();
            &own
        }
    };
    for &(s, x) in syms {
        b.code(clc[s as usize], cl[s as usize] as u32);
        match s {
            16 => b.put(x, 2),
            17 => b.put(x, 3),
            18 => b.put(x, 7),
            _ => {}
        }
    }
}

/// Literal/length lengths: `a` and `b` and end-of-block, each 2 bits... padded to complete
/// with 'c' (four symbols of length 2).
fn small_ll() -> Vec<u8> {
    let mut ll = vec![0u8; 257];
    for s in [b'a' as usize, b'b' as usize, b'c' as usize, 256] {
        ll[s] = 2;
    }
    ll
}

#[test]
fn dynamic_blocks() {
    let ll = small_ll();
    let llc = canon(&ll);
    // A single one-bit distance code: incomplete, accepted (zlib does).
    let mut b = Bits::new();
    dynamic(&mut b, true, 257, 1, &ll, &[1], None);
    for s in [b'a', b'b', b'c'] {
        b.code(llc[s as usize], 2);
    }
    b.code(llc[256], 2);
    assert_eq!(inflate::decompress(&b.done()).unwrap(), b"abc");

    // No distance codes at all: fine while no match is used.
    let mut b = Bits::new();
    dynamic(&mut b, true, 257, 1, &ll, &[0], None);
    b.code(llc[b'a' as usize], 2);
    b.code(llc[256], 2);
    assert_eq!(inflate::decompress(&b.done()).unwrap(), b"a");

    // Repeat codes, the last run crossing from the literal/length lengths into the distance
    // ones: 1, 0 x 255, then 2 x 6 (end-of-block, 257 and distances 0-3).
    let mut ll2 = vec![0u8; 258];
    ll2[0] = 1;
    ll2[256] = 2;
    ll2[257] = 2;
    let syms = [(1, 0), (18, 138 - 11), (18, 117 - 11), (2, 0), (16, 5 - 3)];
    let mut b = Bits::new();
    dynamic(&mut b, true, 258, 4, &ll2, &[2; 4], Some(&syms));
    let llc2 = canon(&ll2);
    b.code(llc2[0], 1);
    b.code(llc2[0], 1);
    b.code(llc2[257], 2); // length 3
    b.code(canon(&[2; 4])[1], 2); // distance 2
    b.code(llc2[256], 2);
    assert_eq!(inflate::decompress(&b.done()).unwrap(), [0; 5]);
}

fn dyn_err(hlit: usize, hdist: usize, ll: &[u8], dl: &[u8], syms: Option<&[(u32, u32)]>) -> Result<Vec<u8>, Error> {
    let mut b = Bits::new();
    dynamic(&mut b, true, hlit, hdist, ll, dl, syms);
    b.put(0, 32);
    inflate::decompress(&b.done())
}

#[test]
fn dynamic_header_errors() {
    let ll = small_ll();
    // HLIT 287 / HDIST 31.
    assert_eq!(dyn_err(287, 1, &[0; 287], &[1], None), Err(Error::TooManyCodes));
    assert_eq!(dyn_err(257, 31, &ll, &[0; 31], None), Err(Error::TooManyCodes));
    // A repeat with nothing before it.
    assert_eq!(dyn_err(257, 1, &ll, &[1], Some(&[(16, 0)])), Err(Error::BadRepeat));
    // A run past the end.
    let run = [(18, 127), (18, 127), (18, 127)];
    assert_eq!(dyn_err(257, 1, &ll, &[1], Some(&run)), Err(Error::BadRepeat));
    // No end-of-block code.
    let mut noeob = vec![0u8; 257];
    noeob[0] = 1;
    noeob[1] = 1;
    assert_eq!(dyn_err(257, 1, &noeob, &[1], None), Err(Error::MissingEndOfBlock));
    // Over-subscribed and incomplete literal/length codes.
    let mut over = small_ll();
    over[b'd' as usize] = 2;
    assert_eq!(dyn_err(257, 1, &over, &[1], None), Err(Error::BadLitLenCode));
    let mut inc = small_ll();
    inc[b'c' as usize] = 0;
    assert_eq!(dyn_err(257, 1, &inc, &[1], None), Err(Error::BadLitLenCode));
    // A lone one-bit end-of-block code is the one incomplete code allowed.
    let mut lone = vec![0u8; 257];
    lone[256] = 1;
    let mut b = Bits::new();
    dynamic(&mut b, true, 257, 1, &lone, &[0], None);
    b.put(0, 1);
    assert_eq!(inflate::decompress(&b.done()).unwrap(), b"");
    // Incomplete and over-subscribed distance codes.
    assert_eq!(dyn_err(257, 2, &ll, &[1, 2], None), Err(Error::BadDistCode));
    assert_eq!(dyn_err(257, 3, &ll, &[1, 1, 1], None), Err(Error::BadDistCode));
    // An incomplete code length code.
    let mut b = Bits::new();
    b.put(0b101, 3);
    b.put(0, 5);
    b.put(0, 5);
    b.put(0, 4); // four code length code lengths: 16, 17, 18, 0
    for l in [1, 0, 0, 0] {
        b.put(l, 3);
    }
    b.put(0, 32);
    assert_eq!(inflate::decompress(&b.done()), Err(Error::BadCodeLengths));
}

#[test]
fn empty_and_multi_block_streams() {
    // Empty stored, empty fixed, empty dynamic... then a final empty fixed block.
    let mut b = Bits::new();
    b.put(0, 3);
    b.put(0, 5); // pad
    b.put(0, 16);
    b.put(0xffff, 16);
    b.put(0b010, 3);
    fixed_sym(&mut b, 256);
    let ll = small_ll();
    dynamic(&mut b, false, 257, 1, &ll, &[1], None);
    b.code(canon(&ll)[256], 2);
    b.put(0b011, 3);
    fixed_sym(&mut b, b'!' as u32);
    fixed_sym(&mut b, 256);
    assert_eq!(inflate::decompress(&b.done()).unwrap(), b"!");
}
