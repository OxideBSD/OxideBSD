//! Decompression of raw DEFLATE streams (RFC 1951).
//!
//! [`Inflater`] is resumable: give it input and output space in any amounts and it does what
//! it can. Internally it decodes in units (a block header including its whole dynamic code
//! description, one literal or length/distance pair, a stored block's LEN/NLEN, a run of
//! stored bytes) and commits a unit only once all of its bits are present; short of that it
//! keeps the partial unit's bytes and asks for more. A unit is at most a few hundred bytes, so
//! the input it holds back is small, and it never takes more input than it can use: after the
//! end of the stream, [`Progress::consumed`] stops exactly at the stream's last byte, which is
//! what lets gzip find the next member.
//!
//! Hostile input: every loop is bounded by input or output consumed, every table index is
//! checked, and every error (zlib's set: see [`Error`]) is final for the stream.

use crate::Error;
use crate::huffman::{BAD, Kind, Table};
use crate::tables::{CL_ORDER, DIST_BASE, DIST_EXTRA, FIXED_DIST_LENGTHS, LEN_BASE, LEN_EXTRA, fixed_lit_lengths};

/// The history a distance can reach.
const WSIZE: usize = 1 << 15;
/// The output window: 32 KiB of history plus up to 32 KiB + one match not yet delivered, with
/// room left so sliding it down is rare.
const WIN_CAP: usize = 3 * WSIZE;
/// Input taken per refill, bounding the memory a partial unit's buffer can use.
const MAX_APPEND: usize = 1 << 16;
const LIT_ROOT: u32 = 10;
const DIST_ROOT: u32 = 8;
const CL_ROOT: u32 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Expecting BFINAL and BTYPE (and, for a dynamic block, the code description).
    Header,
    /// A stored block's LEN and NLEN, after the padding to a byte boundary.
    StoredLen,
    /// A stored block's remaining bytes.
    Stored(u16),
    /// Inside a Huffman-coded block.
    Codes,
    Done,
}

/// Why the decoding loop stopped.
enum Stall {
    Input,
    Output,
    Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The stream ended and all of its output has been delivered.
    StreamEnd,
    /// All input was taken; more is needed to go on.
    NeedsInput,
    /// The output buffer is full; call again with more space.
    NeedsOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Input bytes taken. Taken input is never handed back.
    pub consumed: usize,
    /// Output bytes written.
    pub produced: usize,
    pub status: Status,
}

/// A raw DEFLATE decoder.
pub struct Inflater {
    state: State,
    /// The current block is the last.
    last: bool,
    /// The current Huffman block uses the fixed codes.
    fixed: bool,
    /// Input not yet decoded; `bitpos` counts the bits of it already used.
    inbuf: Vec<u8>,
    bitpos: usize,
    win: Vec<u8>,
    /// Bytes written to `win`, and of those, bytes delivered to the caller.
    wpos: usize,
    dpos: usize,
    total_out: u64,
    lit: Table,
    dist: Table,
    fixed_lit: Table,
    fixed_dist: Table,
    failed: Option<Error>,
}

impl Default for Inflater {
    fn default() -> Self {
        Inflater::new()
    }
}

/// The next 56 or more bits from bit `bitpos` of `buf`, zero past its end.
#[inline]
fn peek(buf: &[u8], bitpos: usize) -> u64 {
    let i = bitpos >> 3;
    let v = if let Some(b) = buf.get(i..i + 8) {
        u64::from_le_bytes(b.try_into().unwrap())
    } else {
        let mut t = [0u8; 8];
        if i < buf.len() {
            t[..buf.len() - i].copy_from_slice(&buf[i..]);
        }
        u64::from_le_bytes(t)
    };
    v >> (bitpos & 7)
}

/// Slides the window down so a match fits, keeping 32 KiB of history and all undelivered
/// output.
#[inline]
fn slide(win: &mut [u8], wpos: &mut usize, dpos: &mut usize) {
    if *wpos <= WSIZE {
        return;
    }
    let s = (*wpos - WSIZE).min(*dpos);
    win.copy_within(s..*wpos, 0);
    *wpos -= s;
    *dpos -= s;
}

impl Inflater {
    pub fn new() -> Inflater {
        Inflater {
            state: State::Header,
            last: false,
            fixed: false,
            inbuf: Vec::new(),
            bitpos: 0,
            win: vec![0; WIN_CAP],
            wpos: 0,
            dpos: 0,
            total_out: 0,
            lit: Table::empty(),
            dist: Table::empty(),
            fixed_lit: Table::build(&fixed_lit_lengths(), LIT_ROOT, Kind::LitLen).unwrap(),
            fixed_dist: Table::build(&FIXED_DIST_LENGTHS, DIST_ROOT, Kind::Dist).unwrap(),
            failed: None,
        }
    }

    /// Starts over on a new stream, keeping the allocations.
    pub fn reset(&mut self) {
        self.state = State::Header;
        self.last = false;
        self.inbuf.clear();
        self.bitpos = 0;
        self.wpos = 0;
        self.dpos = 0;
        self.total_out = 0;
        self.failed = None;
    }

    /// Bytes of output produced so far (delivered or not).
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// The stream has ended (its output may not all be delivered yet).
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// Decodes from `input` into `output`. An error is final: every later call returns it.
    pub fn inflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let r = self.run(input, output);
        if let Err(e) = r {
            self.failed = Some(e);
        }
        r
    }

    fn run(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut used = 0;
        let mut produced = 0;
        // Where this call's input starts in `inbuf`: bytes before it were reported consumed by
        // an earlier call and can no longer be handed back.
        let mut call_start = self.inbuf.len();
        let mut starved = false;
        let status = loop {
            let n = (self.wpos - self.dpos).min(output.len() - produced);
            output[produced..produced + n].copy_from_slice(&self.win[self.dpos..self.dpos + n]);
            self.dpos += n;
            produced += n;
            if self.dpos == self.wpos && self.state == State::Done {
                break Status::StreamEnd;
            }
            if produced == output.len() {
                break Status::NeedsOutput;
            }
            if starved {
                break Status::NeedsInput;
            }
            match self.step()? {
                Stall::Output | Stall::Done => {}
                Stall::Input => {
                    if used == input.len() {
                        // Deliver what was decoded before saying so.
                        starved = true;
                        continue;
                    }
                    let drop = self.bitpos / 8;
                    self.inbuf.drain(..drop);
                    self.bitpos -= drop * 8;
                    call_start = call_start.saturating_sub(drop);
                    let n = (input.len() - used).min(MAX_APPEND);
                    self.inbuf.extend_from_slice(&input[used..used + n]);
                    used += n;
                }
            }
        };
        if status != Status::NeedsInput {
            // Hand back this call's bytes that decoding has not reached: after the end of the
            // stream they are someone else's, and otherwise the caller can resend them.
            let keep = self.bitpos.div_ceil(8).max(call_start).min(self.inbuf.len());
            used -= self.inbuf.len() - keep;
            self.inbuf.truncate(keep);
        }
        Ok(Progress { consumed: used, produced, status })
    }

    fn end_block(&self) -> State {
        if self.last { State::Done } else { State::Header }
    }

    /// Decodes until input runs out, undelivered output reaches 32 KiB, or the stream ends.
    fn step(&mut self) -> Result<Stall, Error> {
        loop {
            match self.state {
                State::Done => return Ok(Stall::Done),
                State::Header => {
                    if self.inbuf.len() * 8 - self.bitpos < 3 {
                        return Ok(Stall::Input);
                    }
                    let b = peek(&self.inbuf, self.bitpos);
                    let last = b & 1 != 0;
                    match (b >> 1) & 3 {
                        0 => {
                            self.bitpos += 3;
                            self.state = State::StoredLen;
                        }
                        1 => {
                            self.bitpos += 3;
                            self.fixed = true;
                            self.state = State::Codes;
                        }
                        2 => match self.read_dynamic(self.bitpos + 3)? {
                            None => return Ok(Stall::Input),
                            Some((pos, lit, dist)) => {
                                self.bitpos = pos;
                                self.lit = lit;
                                self.dist = dist;
                                self.fixed = false;
                                self.state = State::Codes;
                            }
                        },
                        _ => return Err(Error::InvalidBlockType),
                    }
                    self.last = last;
                }
                State::StoredLen => {
                    let p = self.bitpos.div_ceil(8);
                    let Some(h) = self.inbuf.get(p..p + 4) else {
                        return Ok(Stall::Input);
                    };
                    let len = u16::from_le_bytes([h[0], h[1]]);
                    if len != !u16::from_le_bytes([h[2], h[3]]) {
                        return Err(Error::StoredLength);
                    }
                    self.bitpos = (p + 4) * 8;
                    self.state = if len == 0 { self.end_block() } else { State::Stored(len) };
                }
                State::Stored(rem) => {
                    if self.wpos - self.dpos >= WSIZE {
                        return Ok(Stall::Output);
                    }
                    if WIN_CAP - self.wpos < WSIZE {
                        slide(&mut self.win, &mut self.wpos, &mut self.dpos);
                    }
                    // Stored data starts byte aligned and stays so.
                    let bp = self.bitpos / 8;
                    let have = self.inbuf.len() - bp;
                    if have == 0 {
                        return Ok(Stall::Input);
                    }
                    let n = (rem as usize)
                        .min(have)
                        .min(WIN_CAP - self.wpos)
                        .min(WSIZE - (self.wpos - self.dpos));
                    if n == 0 {
                        return Ok(Stall::Output);
                    }
                    self.win[self.wpos..self.wpos + n].copy_from_slice(&self.inbuf[bp..bp + n]);
                    self.wpos += n;
                    self.total_out += n as u64;
                    self.bitpos += n * 8;
                    let rem = rem - n as u16;
                    self.state = if rem == 0 { self.end_block() } else { State::Stored(rem) };
                }
                State::Codes => {
                    if let Some(stall) = self.codes()? {
                        return Ok(stall);
                    }
                }
            }
        }
    }

    /// Decodes literals and matches until the block ends (None) or a stall.
    fn codes(&mut self) -> Result<Option<Stall>, Error> {
        let (lit, dist) = if self.fixed { (&self.fixed_lit, &self.fixed_dist) } else { (&self.lit, &self.dist) };
        let inbuf = &self.inbuf[..];
        let win = &mut self.win[..];
        let total_bits = inbuf.len() * 8;
        let mut bitpos = self.bitpos;
        let mut wpos = self.wpos;
        let mut dpos = self.dpos;
        let mut total = self.total_out;
        let mut result = Ok(None);
        loop {
            if wpos - dpos >= WSIZE {
                result = Ok(Some(Stall::Output));
                break;
            }
            if wpos + 258 > WIN_CAP {
                slide(win, &mut wpos, &mut dpos);
                if wpos + 258 > WIN_CAP {
                    result = Ok(Some(Stall::Output));
                    break;
                }
            }
            let avail = total_bits - bitpos;
            let b = peek(inbuf, bitpos);
            let e = lit.get(b);
            let l = (e & 0x1f) as usize;
            if e & BAD != 0 || l > avail {
                // An unassigned code is only certain once 15 real bits are there.
                if e & BAD != 0 && avail >= 15 {
                    result = Err(Error::InvalidCode);
                } else {
                    result = Ok(Some(Stall::Input));
                }
                break;
            }
            let sym = (e >> 16) as usize;
            if sym < 256 {
                win[wpos] = sym as u8;
                wpos += 1;
                total += 1;
                bitpos += l;
                continue;
            }
            if sym == 256 {
                bitpos += l;
                self.state = if self.last { State::Done } else { State::Header };
                break;
            }
            if sym > 285 {
                result = Err(Error::InvalidCode);
                break;
            }
            let ls = sym - 257;
            let leb = LEN_EXTRA[ls] as usize;
            let length = LEN_BASE[ls] as usize + ((b >> l) & ((1 << leb) - 1)) as usize;
            let used = l + leb;
            let b2 = b >> used;
            let de = dist.get(b2);
            let dl = (de & 0x1f) as usize;
            let after = avail.saturating_sub(used);
            if de & BAD != 0 || used + dl > avail {
                if de & BAD != 0 && after >= 15 {
                    result = Err(Error::InvalidCode);
                } else {
                    result = Ok(Some(Stall::Input));
                }
                break;
            }
            let ds = (de >> 16) as usize;
            if ds > 29 {
                result = Err(Error::InvalidCode);
                break;
            }
            let deb = DIST_EXTRA[ds] as usize;
            let used = used + dl + deb;
            if used > avail {
                result = Ok(Some(Stall::Input));
                break;
            }
            let d = DIST_BASE[ds] as usize + ((b2 >> dl) & ((1 << deb) - 1)) as usize;
            if d as u64 > total {
                result = Err(Error::DistanceTooFar);
                break;
            }
            let Some(src) = wpos.checked_sub(d) else {
                result = Err(Error::DistanceTooFar);
                break;
            };
            if d >= length {
                win.copy_within(src..src + length, wpos);
            } else {
                for i in 0..length {
                    win[wpos + i] = win[src + i];
                }
            }
            wpos += length;
            total += length as u64;
            bitpos += used;
        }
        self.bitpos = bitpos;
        self.wpos = wpos;
        self.dpos = dpos;
        self.total_out = total;
        result
    }

    /// Reads a dynamic block's code description starting at bit `start`: the new position and
    /// tables, or None if the input ends first.
    fn read_dynamic(&self, start: usize) -> Result<Option<(usize, Table, Table)>, Error> {
        let buf = &self.inbuf[..];
        let total = buf.len() * 8;
        let mut pos = start;
        if pos + 14 > total {
            return Ok(None);
        }
        let b = peek(buf, pos);
        let hlit = (b & 31) as usize + 257;
        let hdist = ((b >> 5) & 31) as usize + 1;
        let hclen = ((b >> 10) & 15) as usize + 4;
        pos += 14;
        if hlit > 286 || hdist > 30 {
            return Err(Error::TooManyCodes);
        }
        if pos + 3 * hclen > total {
            return Ok(None);
        }
        let mut cl = [0u8; 19];
        for &i in &CL_ORDER[..hclen] {
            cl[i] = (peek(buf, pos) & 7) as u8;
            pos += 3;
        }
        let clt = Table::build(&cl, CL_ROOT, Kind::CodeLen)?;
        let n = hlit + hdist;
        let mut lens = [0u8; 286 + 30];
        let mut i = 0;
        while i < n {
            let avail = total - pos;
            let b = peek(buf, pos);
            let e = clt.get(b);
            let l = (e & 0x1f) as usize;
            if e & BAD != 0 {
                // Unreachable for a complete code, but cheap to keep honest.
                return if avail >= 7 { Err(Error::BadCodeLengths) } else { Ok(None) };
            }
            let sym = (e >> 16) as u8;
            // Nothing is decided until every bit of the symbol is really there: past the end
            // of the input, `b` is zero padding.
            let extra = [2, 3, 7].get((sym as usize).wrapping_sub(16)).copied().unwrap_or(0);
            if l + extra > avail {
                return Ok(None);
            }
            let (rep, val) = match sym {
                0..=15 => (1, sym),
                16 => {
                    if i == 0 {
                        return Err(Error::BadRepeat);
                    }
                    (3 + ((b >> l) & 3) as usize, lens[i - 1])
                }
                17 => (3 + ((b >> l) & 7) as usize, 0),
                _ => (11 + ((b >> l) & 127) as usize, 0),
            };
            if i + rep > n {
                return Err(Error::BadRepeat);
            }
            lens[i..i + rep].fill(val);
            i += rep;
            pos += l + extra;
        }
        if lens[256] == 0 {
            return Err(Error::MissingEndOfBlock);
        }
        let lit = Table::build(&lens[..hlit], LIT_ROOT, Kind::LitLen)?;
        let dist = Table::build(&lens[hlit..n], DIST_ROOT, Kind::Dist)?;
        Ok(Some((pos, lit, dist)))
    }
}

/// Decompresses a whole raw DEFLATE stream, which must be all of `data`.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    decompress_with_limit(data, usize::MAX)
}

/// [`decompress`], failing with [`Error::OutputLimit`] rather than produce more than `limit`
/// bytes: a few KiB of hostile input can claim gigabytes.
pub fn decompress_with_limit(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let (out, used) = decompress_prefix(data, limit)?;
    if used != data.len() {
        return Err(Error::TrailingGarbage);
    }
    Ok(out)
}

/// Decompresses the raw DEFLATE stream at the start of `data`, returning the output and the
/// number of input bytes the stream took.
pub fn decompress_prefix(data: &[u8], limit: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut inf = Inflater::new();
    let mut out = Vec::new();
    let mut used = 0;
    let mut chunk = vec![0u8; 1 << 16];
    loop {
        let p = inf.inflate(&data[used..], &mut chunk)?;
        used += p.consumed;
        if out.len() + p.produced > limit {
            return Err(Error::OutputLimit);
        }
        out.extend_from_slice(&chunk[..p.produced]);
        match p.status {
            Status::StreamEnd => return Ok((out, used)),
            Status::NeedsInput => return Err(Error::Truncated),
            Status::NeedsOutput => {}
        }
    }
}

/// A `Read` adapter decompressing a raw DEFLATE stream from a `BufRead`. It reads exactly the
/// stream's bytes from the source, leaving anything after them unread.
pub struct DeflateDecoder<R> {
    r: R,
    inf: Inflater,
}

impl<R: std::io::BufRead> DeflateDecoder<R> {
    pub fn new(r: R) -> Self {
        DeflateDecoder { r, inf: Inflater::new() }
    }

    pub fn get_ref(&self) -> &R {
        &self.r
    }

    pub fn into_inner(self) -> R {
        self.r
    }
}

/// One step of an adapter's read: decodes from `r` into `buf` until something is produced,
/// returning the count and whether the stream ended.
pub(crate) fn read_body<R: std::io::BufRead>(
    r: &mut R,
    inf: &mut Inflater,
    buf: &mut [u8],
) -> std::io::Result<(usize, bool)> {
    loop {
        let input = r.fill_buf()?;
        let eof = input.is_empty();
        let p = inf.inflate(input, buf)?;
        r.consume(p.consumed);
        match p.status {
            Status::StreamEnd => return Ok((p.produced, true)),
            Status::NeedsInput if eof && p.produced == 0 => return Err(Error::Truncated.into()),
            _ => {}
        }
        if p.produced > 0 {
            return Ok((p.produced, false));
        }
    }
}

impl<R: std::io::BufRead> std::io::Read for DeflateDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || (self.inf.is_done() && self.inf.dpos == self.inf.wpos) {
            return Ok(0);
        }
        Ok(read_body(&mut self.r, &mut self.inf, buf)?.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_fixed_block() {
        assert_eq!(decompress(&[0x03, 0x00]).unwrap(), b"");
    }

    #[test]
    fn stored_block() {
        let s = [0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(decompress(&s).unwrap(), b"hello");
        let mut bad = s;
        bad[3] = 0xfb;
        assert_eq!(decompress(&bad), Err(Error::StoredLength));
        assert_eq!(decompress(&s[..7]), Err(Error::Truncated));
    }

    #[test]
    fn block_type_3() {
        assert_eq!(decompress(&[0x07]), Err(Error::InvalidBlockType));
    }

    #[test]
    fn consumed_stops_at_stream_end() {
        let mut s = vec![0x03, 0x00];
        s.extend_from_slice(b"after");
        let (out, used) = decompress_prefix(&s, 100).unwrap();
        assert_eq!((out.len(), used), (0, 2));
    }
}
