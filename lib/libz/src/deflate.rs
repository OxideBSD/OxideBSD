//! Compression to raw DEFLATE streams (RFC 1951).
//!
//! The match finder is zlib's: a 64 KiB window over the input, 3-byte strings hashed into
//! chains of earlier positions, and zlib's per-level table of how hard to search. Levels 1-3
//! take the first acceptable match (greedy); 4-9 look one byte ahead and keep a match only if
//! the next position does not start a longer one (lazy). Literals and matches are tallied into
//! blocks of up to 16K symbols; each block goes out as whichever of stored, fixed Huffman or
//! dynamic Huffman is shortest, the dynamic codes built by package-merge (optimal under the
//! 15-bit limit; 7 bits for the code length code). Level 0 sends stored blocks only.
//!
//! Matching zlib's choices keeps the output's size within a hair of `gzip -N`'s.

use crate::Error;
use crate::huffman;
use crate::tables::{
    CL_ORDER, DIST_BASE, DIST_EXTRA, FIXED_DIST_LENGTHS, LEN_BASE, LEN_CODE, LEN_EXTRA, dist_code, fixed_lit_lengths,
};

const WSIZE: usize = 1 << 15;
const WMASK: usize = WSIZE - 1;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Lookahead kept before searching, so a match can always run its full length.
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;
/// The farthest match zlib allows: it keeps the window slide from cutting a match short.
const MAX_DIST: usize = WSIZE - MIN_LOOKAHEAD;
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
/// No position. Position 0 is thus never matched, as in zlib: the price of 16-bit positions,
/// which halve the chains' cache footprint.
const NIL: u16 = 0;
/// Symbols per block (zlib's lit_bufsize at its default memLevel).
const LIT_BUFSIZE: usize = 1 << 14;
/// A 3-byte match farther than this costs more than its three literals (zlib's TOO_FAR).
const TOO_FAR: usize = 4096;
/// The largest stored block.
const MAX_STORED: usize = 65535;

/// zlib's search parameters: below `good` the chain is searched in full, past it a quarter;
/// a lazy match is only looked for while the current one is under `lazy` (for the greedy
/// levels, `lazy` instead caps the length of matches whose strings are all hashed); `nice`
/// ends a search; `chain` caps its steps.
struct Config {
    good: usize,
    lazy: usize,
    nice: usize,
    chain: usize,
    slow: bool,
}

const CONFIGS: [Config; 10] = [
    Config { good: 0, lazy: 0, nice: 0, chain: 0, slow: false },
    Config { good: 4, lazy: 4, nice: 8, chain: 4, slow: false },
    Config { good: 4, lazy: 5, nice: 16, chain: 8, slow: false },
    Config { good: 4, lazy: 6, nice: 32, chain: 32, slow: false },
    Config { good: 4, lazy: 4, nice: 16, chain: 16, slow: true },
    Config { good: 8, lazy: 16, nice: 32, chain: 32, slow: true },
    Config { good: 8, lazy: 16, nice: 128, chain: 128, slow: true },
    Config { good: 8, lazy: 32, nice: 128, chain: 256, slow: true },
    Config { good: 32, lazy: 128, nice: 258, chain: 1024, slow: true },
    Config { good: 32, lazy: 258, nice: 258, chain: 4096, slow: true },
];

/// What a call does after taking its input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flush {
    /// Nothing: output may lag the input.
    None,
    /// Emit everything so far and end on a byte boundary with an empty stored block
    /// (`00 00 ff ff`); a decoder given the output so far can produce all the input so far.
    Sync,
    /// Sync, and forget the history, so decoding can start again from here.
    Full,
    /// End the stream. Nothing may follow but [`Deflater::reset`].
    Finish,
}

/// Bits out, least significant first.
struct BitWriter {
    acc: u64,
    n: u32,
    buf: Vec<u8>,
}

impl BitWriter {
    #[inline]
    fn put(&mut self, bits: u32, len: u32) {
        debug_assert!(len <= 16 && (len == 32 || bits >> len == 0));
        self.acc |= (bits as u64) << self.n;
        self.n += len;
        if self.n >= 32 {
            self.buf.extend_from_slice(&(self.acc as u32).to_le_bytes());
            self.acc >>= 32;
            self.n -= 32;
        }
    }

    /// Pads to a byte boundary with zero bits and moves everything to `buf`.
    fn align(&mut self) {
        while self.n > 0 {
            self.buf.push(self.acc as u8);
            self.acc >>= 8;
            self.n = self.n.saturating_sub(8);
        }
        self.acc = 0;
    }

    fn stored(&mut self, data: &[u8], last: bool) {
        let mut chunks = data.chunks(MAX_STORED).peekable();
        if data.is_empty() {
            self.put(last as u32, 3);
            self.align();
            self.buf.extend_from_slice(&[0, 0, 0xff, 0xff]);
            return;
        }
        while let Some(c) = chunks.next() {
            self.put((last && chunks.peek().is_none()) as u32, 3);
            self.align();
            let len = c.len() as u16;
            self.buf.extend_from_slice(&len.to_le_bytes());
            self.buf.extend_from_slice(&(!len).to_le_bytes());
            self.buf.extend_from_slice(c);
        }
    }
}

/// Bits to send `len` bytes as stored blocks when `n` bits are pending in the last byte.
fn stored_cost(len: usize, n: u32) -> u64 {
    let blocks = len.div_ceil(MAX_STORED).max(1) as u64;
    let first_pad = (8 - (n + 3) % 8) % 8;
    // Later blocks start aligned: 3 header bits, 5 padding.
    blocks * (3 + 32) + first_pad as u64 + (blocks - 1) * 5 + 8 * len as u64
}

/// The current block's symbols and the encoder for them.
struct Blocks {
    bw: BitWriter,
    /// `dist << 8 | literal` or `dist << 8 | (length - 3)`; dist 0 marks a literal.
    syms: Vec<u32>,
    lit_freq: [u32; 286],
    dist_freq: [u32; 30],
    fixed_lit: ([u8; 288], [u16; 288]),
    fixed_dist: ([u8; 32], [u16; 32]),
}

impl Blocks {
    fn new() -> Blocks {
        let fl = fixed_lit_lengths();
        let mut fc = [0u16; 288];
        huffman::codes(&fl, &mut fc);
        let mut dc = [0u16; 32];
        huffman::codes(&FIXED_DIST_LENGTHS, &mut dc);
        Blocks {
            bw: BitWriter { acc: 0, n: 0, buf: Vec::new() },
            syms: Vec::with_capacity(LIT_BUFSIZE),
            lit_freq: [0; 286],
            dist_freq: [0; 30],
            fixed_lit: (fl, fc),
            fixed_dist: (FIXED_DIST_LENGTHS, dc),
        }
    }

    #[inline]
    fn lit(&mut self, c: u8) -> bool {
        self.syms.push(c as u32);
        self.lit_freq[c as usize] += 1;
        self.syms.len() == LIT_BUFSIZE - 1
    }

    #[inline]
    fn rmatch(&mut self, dist: usize, len: usize) -> bool {
        debug_assert!((1..=WSIZE).contains(&dist) && (MIN_MATCH..=MAX_MATCH).contains(&len));
        self.syms.push((dist as u32) << 8 | (len - MIN_MATCH) as u32);
        self.lit_freq[257 + LEN_CODE[len - MIN_MATCH] as usize] += 1;
        self.dist_freq[dist_code(dist as u32)] += 1;
        self.syms.len() == LIT_BUFSIZE - 1
    }

    /// Sends the tallied symbols as one block (or several stored ones). `raw` is the input
    /// they encode, when it is still in the window.
    fn flush(&mut self, raw: Option<&[u8]>, last: bool) {
        self.lit_freq[256] += 1;
        let mut ll = [0u8; 286];
        huffman::lengths(&self.lit_freq, 15, &mut ll);
        let mut dl = [0u8; 30];
        huffman::lengths(&self.dist_freq, 15, &mut dl);
        let hlit = (257..286).rev().find(|&i| ll[i] != 0).map_or(257, |i| i + 1);
        let hdist = (1..30).rev().find(|&i| dl[i] != 0).map_or(1, |i| i + 1);

        // The code lengths, run-length coded (§3.2.7). Runs may cross from the literal/length
        // lengths into the distance ones.
        let mut all = [0u8; 286 + 30];
        all[..hlit].copy_from_slice(&ll[..hlit]);
        all[hlit..hlit + hdist].copy_from_slice(&dl[..hdist]);
        let all = &all[..hlit + hdist];
        let mut rle: Vec<(u8, u8)> = Vec::with_capacity(all.len());
        let mut i = 0;
        while i < all.len() {
            let v = all[i];
            let mut run = all[i..].iter().take_while(|&&x| x == v).count();
            i += run;
            if v == 0 {
                while run >= 11 {
                    let r = run.min(138);
                    rle.push((18, (r - 11) as u8));
                    run -= r;
                }
                if run >= 3 {
                    rle.push((17, (run - 3) as u8));
                    run = 0;
                }
            } else {
                rle.push((v, 0));
                run -= 1;
                while run >= 3 {
                    let r = run.min(6);
                    rle.push((16, (r - 3) as u8));
                    run -= r;
                }
            }
            for _ in 0..run {
                rle.push((v, 0));
            }
        }
        let mut cl_freq = [0u32; 19];
        for &(s, _) in &rle {
            cl_freq[s as usize] += 1;
        }
        let mut cl = [0u8; 19];
        huffman::lengths(&cl_freq, 7, &mut cl);
        let hclen = (4..19).rev().find(|&i| cl[CL_ORDER[i]] != 0).map_or(4, |i| i + 1);

        let extra: u64 = (0..29).map(|i| self.lit_freq[257 + i] as u64 * LEN_EXTRA[i] as u64).sum::<u64>()
            + (0..30).map(|i| self.dist_freq[i] as u64 * DIST_EXTRA[i] as u64).sum::<u64>();
        let cost = |l: &[u8], d: &[u8]| -> u64 {
            (0..286).map(|i| self.lit_freq[i] as u64 * l[i] as u64).sum::<u64>()
                + (0..30).map(|i| self.dist_freq[i] as u64 * d[i] as u64).sum::<u64>()
                + extra
        };
        let rle_bits: u64 = rle.iter().map(|&(s, _)| cl[s as usize] as u64 + [2, 3, 7].get((s as usize).wrapping_sub(16)).copied().unwrap_or(0)).sum();
        let dyn_bits = 3 + 14 + 3 * hclen as u64 + rle_bits + cost(&ll, &dl);
        let fixed_bits = 3 + cost(&self.fixed_lit.0, &self.fixed_dist.0);
        let stored_bits = raw.map(|r| stored_cost(r.len(), self.bw.n));

        if let Some(raw) = raw.filter(|_| stored_bits.unwrap() <= dyn_bits.min(fixed_bits)) {
            self.bw.stored(raw, last);
        } else if fixed_bits <= dyn_bits {
            self.bw.put(last as u32 | 1 << 1, 3);
            let (fl, fc) = self.fixed_lit;
            let (fdl, fdc) = self.fixed_dist;
            self.emit(&fl, &fc, &fdl, &fdc);
        } else {
            self.bw.put(last as u32 | 2 << 1, 3);
            self.bw.put((hlit - 257) as u32, 5);
            self.bw.put((hdist - 1) as u32, 5);
            self.bw.put((hclen - 4) as u32, 4);
            for &k in &CL_ORDER[..hclen] {
                self.bw.put(cl[k] as u32, 3);
            }
            let mut clc = [0u16; 19];
            huffman::codes(&cl, &mut clc);
            for &(s, x) in &rle {
                self.bw.put(clc[s as usize] as u32, cl[s as usize] as u32);
                match s {
                    16 => self.bw.put(x as u32, 2),
                    17 => self.bw.put(x as u32, 3),
                    18 => self.bw.put(x as u32, 7),
                    _ => {}
                }
            }
            let mut lc = [0u16; 286];
            huffman::codes(&ll, &mut lc);
            let mut dc = [0u16; 30];
            huffman::codes(&dl, &mut dc);
            self.emit(&ll, &lc, &dl, &dc);
        }
        self.syms.clear();
        self.lit_freq = [0; 286];
        self.dist_freq = [0; 30];
    }

    fn emit(&mut self, ll: &[u8], lc: &[u16], dl: &[u8], dc: &[u16]) {
        let bw = &mut self.bw;
        for &s in &self.syms {
            let d = s >> 8;
            let v = (s & 0xff) as usize;
            if d == 0 {
                bw.put(lc[v] as u32, ll[v] as u32);
                continue;
            }
            let code = LEN_CODE[v] as usize;
            bw.put(lc[257 + code] as u32, ll[257 + code] as u32);
            if LEN_EXTRA[code] != 0 {
                bw.put((v + MIN_MATCH - LEN_BASE[code] as usize) as u32, LEN_EXTRA[code] as u32);
            }
            let dcode = dist_code(d);
            bw.put(dc[dcode] as u32, dl[dcode] as u32);
            if DIST_EXTRA[dcode] != 0 {
                bw.put(d - DIST_BASE[dcode] as u32, DIST_EXTRA[dcode] as u32);
            }
        }
        bw.put(lc[256] as u32, ll[256] as u32);
    }
}

/// A raw DEFLATE compressor.
pub struct Deflater {
    level: usize,
    window: Vec<u8>,
    /// Most recent position of each hash, and the previous position with the same hash of
    /// each window position (mod 32K). Positions are window offsets.
    head: Vec<u16>,
    prev: Vec<u16>,
    strstart: usize,
    lookahead: usize,
    /// Window offset where the current block's input starts; negative once slid out.
    block_start: isize,
    /// Positions before `strstart` not yet hashed, for want of the bytes after them.
    insert: usize,
    match_length: usize,
    match_start: usize,
    prev_length: usize,
    prev_match: usize,
    match_available: bool,
    blocks: Blocks,
    /// Level 0's block being filled.
    stored: Vec<u8>,
    finished: bool,
}

impl Deflater {
    /// A compressor at `level` 0-9 (higher is clamped to 9). zlib's default is 6.
    pub fn new(level: u32) -> Deflater {
        let level = level.min(9) as usize;
        let mut d = Deflater {
            level,
            window: Vec::new(),
            head: Vec::new(),
            prev: Vec::new(),
            strstart: 0,
            lookahead: 0,
            block_start: 0,
            insert: 0,
            match_length: MIN_MATCH - 1,
            match_start: 0,
            prev_length: MIN_MATCH - 1,
            prev_match: 0,
            match_available: false,
            blocks: Blocks::new(),
            stored: Vec::new(),
            finished: false,
        };
        if level != 0 {
            d.window = vec![0; 2 * WSIZE];
            d.head = vec![NIL; HASH_SIZE];
            d.prev = vec![NIL; WSIZE];
        }
        d
    }

    pub fn level(&self) -> u32 {
        self.level as u32
    }

    /// Starts a new stream at the same level, keeping the allocations.
    pub fn reset(&mut self) {
        self.head.fill(NIL);
        self.prev.fill(NIL);
        self.strstart = 0;
        self.lookahead = 0;
        self.block_start = 0;
        self.insert = 0;
        self.match_length = MIN_MATCH - 1;
        self.prev_length = MIN_MATCH - 1;
        self.match_available = false;
        self.blocks.syms.clear();
        self.blocks.lit_freq = [0; 286];
        self.blocks.dist_freq = [0; 30];
        self.blocks.bw = BitWriter { acc: 0, n: 0, buf: Vec::new() };
        self.stored.clear();
        self.finished = false;
    }

    /// Compresses all of `input`, then flushes as `flush` says, appending the output made so
    /// far to `out`.
    pub fn compress(&mut self, input: &[u8], flush: Flush, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.finished {
            return Err(Error::Finished);
        }
        if self.level == 0 {
            self.compress_stored(input, flush);
        } else {
            let mut input = input;
            if CONFIGS[self.level].slow {
                self.deflate_slow(&mut input, flush);
            } else {
                self.deflate_fast(&mut input, flush);
            }
            if flush != Flush::None {
                self.end(flush);
            }
        }
        if flush == Flush::Finish {
            self.blocks.bw.align();
            self.finished = true;
        }
        out.append(&mut self.blocks.bw.buf);
        Ok(())
    }

    pub fn write(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        self.compress(input, Flush::None, out)
    }

    pub fn flush(&mut self, mode: Flush, out: &mut Vec<u8>) -> Result<(), Error> {
        self.compress(&[], mode, out)
    }

    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.compress(&[], Flush::Finish, out)
    }

    fn compress_stored(&mut self, mut input: &[u8], flush: Flush) {
        while !input.is_empty() {
            if self.stored.len() == MAX_STORED {
                self.blocks.bw.stored(&self.stored, false);
                self.stored.clear();
            }
            let n = (MAX_STORED - self.stored.len()).min(input.len());
            self.stored.extend_from_slice(&input[..n]);
            input = &input[n..];
        }
        match flush {
            Flush::None => {}
            Flush::Finish => self.blocks.bw.stored(&self.stored, true),
            Flush::Sync | Flush::Full => {
                if !self.stored.is_empty() {
                    self.blocks.bw.stored(&self.stored, false);
                }
                self.blocks.bw.stored(&[], false);
            }
        }
        if flush != Flush::None {
            self.stored.clear();
        }
    }

    /// The end of a flushing call: the last block, and for a sync or full flush the empty
    /// stored block that byte-aligns the output.
    fn end(&mut self, flush: Flush) {
        self.insert = self.strstart.min(MIN_MATCH - 1);
        match flush {
            Flush::Finish => self.flush_block(true),
            _ => {
                if !self.blocks.syms.is_empty() {
                    self.flush_block(false);
                }
                self.blocks.bw.stored(&[], false);
                if flush == Flush::Full {
                    self.head.fill(NIL);
                    self.insert = 0;
                }
            }
        }
    }

    fn flush_block(&mut self, last: bool) {
        let raw = if self.block_start >= 0 {
            Some(&self.window[self.block_start as usize..self.strstart])
        } else {
            None
        };
        self.blocks.flush(raw, last);
        self.block_start = self.strstart as isize;
    }

    #[inline]
    fn hash(&self, pos: usize) -> usize {
        let w = &self.window;
        let v = w[pos] as u32 | (w[pos + 1] as u32) << 8 | (w[pos + 2] as u32) << 16;
        (v.wrapping_mul(0x9e37_79b1) >> (32 - HASH_BITS)) as usize
    }

    /// Hashes the string at `pos` into its chain; returns the previous head.
    #[inline]
    fn insert_string(&mut self, pos: usize) -> u16 {
        let h = self.hash(pos);
        let old = self.head[h];
        self.prev[pos & WMASK] = old;
        self.head[h] = pos as u16;
        old
    }

    /// Slides the window when needed and fills it from `input`, until the lookahead is
    /// enough to search or the input is gone.
    fn fill_window(&mut self, input: &mut &[u8]) {
        loop {
            if self.strstart >= WSIZE + MAX_DIST {
                self.window.copy_within(WSIZE.., 0);
                self.match_start = self.match_start.saturating_sub(WSIZE);
                self.strstart -= WSIZE;
                self.block_start -= WSIZE as isize;
                self.insert = self.insert.min(self.strstart);
                for p in self.head.iter_mut().chain(self.prev.iter_mut()) {
                    *p = if *p as usize >= WSIZE { *p - WSIZE as u16 } else { NIL };
                }
            }
            let end = self.strstart + self.lookahead;
            if input.is_empty() || end == self.window.len() {
                return;
            }
            let n = (self.window.len() - end).min(input.len());
            self.window[end..end + n].copy_from_slice(&input[..n]);
            *input = &input[n..];
            self.lookahead += n;
            let end = end + n;
            while self.insert > 0 && self.strstart - self.insert + MIN_MATCH <= end {
                self.insert_string(self.strstart - self.insert);
                self.insert -= 1;
            }
            if self.lookahead >= MIN_LOOKAHEAD {
                return;
            }
        }
    }

    /// The longest match for `strstart` along the chain from `cur`, at least
    /// `prev_length + 1` long to count; sets `match_start`. zlib's `longest_match`.
    fn longest_match(&mut self, mut cur: u16) -> usize {
        let cfg = &CONFIGS[self.level];
        let s = self.strstart;
        let maxlen = MAX_MATCH.min(self.lookahead);
        let mut best = self.prev_length;
        if best >= maxlen {
            return maxlen;
        }
        let mut chain = if self.prev_length >= cfg.good { cfg.chain >> 2 } else { cfg.chain }.max(1);
        let nice = cfg.nice.min(maxlen);
        let w = &self.window[..];
        let prev = &self.prev[..];
        let pair = |i: usize| u16::from_le_bytes([w[i], w[i + 1]]);
        // Cheap rejections first, as zlib does: a longer match must agree on the two bytes
        // ending at `best` and on the first two.
        let start = pair(s);
        let mut end = pair(s + best - 1);
        let mut found = self.match_start;
        loop {
            let c = cur as usize;
            if pair(c + best - 1) == end && pair(c) == start {
                let len = 2 + match_len(w, c + 2, s + 2, maxlen - 2);
                if len > best {
                    found = c;
                    best = len;
                    if len >= nice {
                        break;
                    }
                    end = pair(s + best - 1);
                }
            }
            chain -= 1;
            if chain == 0 {
                break;
            }
            let next = prev[c & WMASK];
            if next == NIL || next as usize >= c || s - next as usize > MAX_DIST {
                break;
            }
            cur = next;
        }
        self.match_start = found;
        best
    }

    /// Greedy matching, levels 1-3 (zlib's `deflate_fast`).
    fn deflate_fast(&mut self, input: &mut &[u8], flush: Flush) {
        let max_insert = CONFIGS[self.level].lazy;
        loop {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(input);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return;
                }
                if self.lookahead == 0 {
                    return;
                }
            }
            let mut head = NIL;
            if self.lookahead >= MIN_MATCH {
                head = self.insert_string(self.strstart);
            }
            self.match_length = 0;
            if head != NIL && self.strstart - head as usize <= MAX_DIST {
                self.prev_length = MIN_MATCH - 1;
                self.match_length = self.longest_match(head);
            }
            let full;
            if self.match_length >= MIN_MATCH {
                full = self.blocks.rmatch(self.strstart - self.match_start, self.match_length);
                self.lookahead -= self.match_length;
                if self.match_length <= max_insert && self.lookahead >= MIN_MATCH {
                    for _ in 1..self.match_length {
                        self.strstart += 1;
                        self.insert_string(self.strstart);
                    }
                    self.strstart += 1;
                } else {
                    self.strstart += self.match_length;
                }
            } else {
                full = self.blocks.lit(self.window[self.strstart]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if full {
                self.flush_block(false);
            }
        }
    }

    /// Lazy matching, levels 4-9 (zlib's `deflate_slow`).
    fn deflate_slow(&mut self, input: &mut &[u8], flush: Flush) {
        let cfg = &CONFIGS[self.level];
        let (max_lazy, mut done) = (cfg.lazy, false);
        while !done {
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(input);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::None {
                    return;
                }
                if self.lookahead == 0 {
                    done = true;
                    continue;
                }
            }
            let mut head = NIL;
            if self.lookahead >= MIN_MATCH {
                head = self.insert_string(self.strstart);
            }
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH - 1;
            if head != NIL && self.prev_length < max_lazy && self.strstart - head as usize <= MAX_DIST {
                self.match_length = self.longest_match(head);
                if self.match_length == MIN_MATCH && self.strstart - self.match_start > TOO_FAR {
                    self.match_length = MIN_MATCH - 1;
                }
            }
            if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
                // The match at the previous position wins.
                let max_insert = self.strstart + self.lookahead - MIN_MATCH;
                let full = self.blocks.rmatch(self.strstart - 1 - self.prev_match, self.prev_length);
                self.lookahead -= self.prev_length - 1;
                for _ in 0..self.prev_length - 2 {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH - 1;
                self.strstart += 1;
                if full {
                    self.flush_block(false);
                }
            } else if self.match_available {
                // No better match here: the previous byte goes out as a literal.
                if self.blocks.lit(self.window[self.strstart - 1]) {
                    self.flush_block(false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
            } else {
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }
        if self.match_available {
            self.blocks.lit(self.window[self.strstart - 1]);
            self.match_available = false;
        }
    }
}

/// How many bytes from `a` and `b` (a < b) agree, up to `max`.
#[inline]
fn match_len(w: &[u8], a: usize, b: usize, max: usize) -> usize {
    let mut n = 0;
    while n + 8 <= max {
        let x = u64::from_le_bytes(w[a + n..a + n + 8].try_into().unwrap());
        let y = u64::from_le_bytes(w[b + n..b + n + 8].try_into().unwrap());
        if x != y {
            return n + ((x ^ y).trailing_zeros() / 8) as usize;
        }
        n += 8;
    }
    while n < max && w[a + n] == w[b + n] {
        n += 1;
    }
    n
}

/// Compresses `data` into a raw DEFLATE stream at `level` 0-9.
pub fn compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut d = Deflater::new(level);
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    d.compress(data, Flush::Finish, &mut out).expect("a fresh compressor is not finished");
    out
}

/// A `Write` adapter compressing into a raw DEFLATE stream. `flush` does a sync flush; call
/// [`finish`](Self::finish) to end the stream (dropping it unfinished finishes it too,
/// ignoring errors).
pub struct DeflateEncoder<W: std::io::Write> {
    w: Option<W>,
    d: Deflater,
    buf: Vec<u8>,
}

impl<W: std::io::Write> DeflateEncoder<W> {
    pub fn new(w: W, level: u32) -> Self {
        DeflateEncoder { w: Some(w), d: Deflater::new(level), buf: Vec::new() }
    }

    pub fn get_ref(&self) -> &W {
        self.w.as_ref().unwrap()
    }

    fn push(&mut self, input: &[u8], flush: Flush) -> std::io::Result<()> {
        self.d.compress(input, flush, &mut self.buf)?;
        let w = self.w.as_mut().unwrap();
        w.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }

    /// Ends the stream and returns the writer.
    pub fn finish(mut self) -> std::io::Result<W> {
        self.push(&[], Flush::Finish)?;
        Ok(self.w.take().unwrap())
    }
}

impl<W: std::io::Write> std::io::Write for DeflateEncoder<W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.push(data, Flush::None)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.push(&[], Flush::Sync)?;
        self.w.as_mut().unwrap().flush()
    }
}

impl<W: std::io::Write> Drop for DeflateEncoder<W> {
    fn drop(&mut self) {
        if self.w.is_some() && !self.d.finished {
            let _ = self.push(&[], Flush::Finish);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inflate::decompress;

    #[test]
    fn empty_is_fixed_eob() {
        assert_eq!(compress(b"", 6), [0x03, 0x00]);
        assert_eq!(compress(b"", 0), [0x01, 0x00, 0x00, 0xff, 0xff]);
    }

    #[test]
    fn small_round_trips() {
        for level in 0..=9 {
            for data in [&b"a"[..], b"abcabcabcabcabcabc", b"hello hello hello world"] {
                assert_eq!(decompress(&compress(data, level)).unwrap(), data, "level {level}");
            }
        }
    }

    #[test]
    fn stored_cost_is_exact() {
        for n in 0..8 {
            for len in [0usize, 1, 100, 65535, 65536, 200_000] {
                let mut bw = BitWriter { acc: 0, n: 0, buf: Vec::new() };
                bw.put(0, n);
                bw.stored(&vec![7; len], true);
                bw.align();
                assert_eq!(n as u64 + stored_cost(len, n), bw.buf.len() as u64 * 8, "n {n} len {len}");
            }
        }
    }
}
