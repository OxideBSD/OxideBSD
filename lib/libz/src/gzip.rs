//! The gzip file format (RFC 1952): members of a header, a DEFLATE stream and a trailer of
//! the data's CRC-32 and length mod 2^32. A file may hold several members back to back;
//! reading one gives the concatenation of their data, as gunzip does.

use std::io::{self, BufRead, Read, Write};

use crate::crc32::Crc32;
use crate::deflate::{Deflater, Flush};
use crate::inflate::{Inflater, read_body};
use crate::{Error, unwrap_io};

const FTEXT: u8 = 1;
const FHCRC: u8 = 2;
const FEXTRA: u8 = 4;
const FNAME: u8 = 8;
const FCOMMENT: u8 = 16;

/// The longest file name or comment accepted. The format has no limit; this one keeps a
/// hostile header from claiming unbounded memory.
pub const MAX_FIELD: usize = 1 << 20;

/// Operating system codes for [`Header::os`].
pub const OS_UNIX: u8 = 3;
pub const OS_UNKNOWN: u8 = 255;

/// A member header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// FTEXT: the data is probably text.
    pub text: bool,
    /// Modification time of the original, seconds since the epoch; 0 for none.
    pub mtime: u32,
    /// Extra flags: 2 for maximum compression, 4 for fastest. Written from the level.
    pub xfl: u8,
    pub os: u8,
    pub extra: Option<Vec<u8>>,
    /// The original file name, ISO 8859-1, without NULs.
    pub name: Option<Vec<u8>>,
    pub comment: Option<Vec<u8>>,
    /// FHCRC: protect the header with a CRC-16 (rarely used; gzip(1) reads it).
    pub hcrc: bool,
}

impl Default for Header {
    fn default() -> Self {
        Header { text: false, mtime: 0, xfl: 0, os: OS_UNIX, extra: None, name: None, comment: None, hcrc: false }
    }
}

impl Header {
    /// The header's bytes, with XFL set for `level`.
    pub fn to_bytes(&self, level: u32) -> Result<Vec<u8>, Error> {
        let mut flg = 0;
        if self.text {
            flg |= FTEXT;
        }
        if self.hcrc {
            flg |= FHCRC;
        }
        if self.extra.is_some() {
            flg |= FEXTRA;
        }
        if self.name.is_some() {
            flg |= FNAME;
        }
        if self.comment.is_some() {
            flg |= FCOMMENT;
        }
        let xfl = match level {
            9 => 2,
            1 => 4,
            _ => 0,
        };
        let mut h = vec![0x1f, 0x8b, 8, flg];
        h.extend_from_slice(&self.mtime.to_le_bytes());
        h.extend_from_slice(&[xfl, self.os]);
        if let Some(x) = &self.extra {
            let len = u16::try_from(x.len()).map_err(|_| Error::BadHeaderField)?;
            h.extend_from_slice(&len.to_le_bytes());
            h.extend_from_slice(x);
        }
        for s in [&self.name, &self.comment].into_iter().flatten() {
            if s.contains(&0) || s.len() > MAX_FIELD {
                return Err(Error::BadHeaderField);
            }
            h.extend_from_slice(s);
            h.push(0);
        }
        if self.hcrc {
            let c = crate::crc32::crc32(&h) as u16;
            h.extend_from_slice(&c.to_le_bytes());
        }
        Ok(h)
    }

    /// Parses a header at the start of `buf`: the header and its length, or None if `buf`
    /// ends first.
    pub fn parse(buf: &[u8]) -> Result<Option<(Header, usize)>, Error> {
        if buf.first().is_some_and(|&b| b != 0x1f) || buf.get(1).is_some_and(|&b| b != 0x8b) {
            return Err(Error::BadMagic);
        }
        if buf.len() < 10 {
            return Ok(None);
        }
        if buf[2] != 8 {
            return Err(Error::BadMethod);
        }
        let flg = buf[3];
        if flg & 0xe0 != 0 {
            return Err(Error::ReservedFlags);
        }
        let mut h = Header {
            text: flg & FTEXT != 0,
            mtime: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            xfl: buf[8],
            os: buf[9],
            extra: None,
            name: None,
            comment: None,
            hcrc: flg & FHCRC != 0,
        };
        let mut p = 10;
        if flg & FEXTRA != 0 {
            let Some(l) = buf.get(p..p + 2) else { return Ok(None) };
            let len = u16::from_le_bytes([l[0], l[1]]) as usize;
            let Some(x) = buf.get(p + 2..p + 2 + len) else { return Ok(None) };
            h.extra = Some(x.to_vec());
            p += 2 + len;
        }
        for (bit, field) in [(FNAME, &mut h.name), (FCOMMENT, &mut h.comment)] {
            if flg & bit == 0 {
                continue;
            }
            let rest = &buf[p..];
            match rest.iter().take(MAX_FIELD + 1).position(|&b| b == 0) {
                Some(n) => {
                    *field = Some(rest[..n].to_vec());
                    p += n + 1;
                }
                None if rest.len() > MAX_FIELD => return Err(Error::HeaderTooLong),
                None => return Ok(None),
            }
        }
        if h.hcrc {
            let Some(c) = buf.get(p..p + 2) else { return Ok(None) };
            if u16::from_le_bytes([c[0], c[1]]) != crate::crc32::crc32(&buf[..p]) as u16 {
                return Err(Error::HeaderCrc);
            }
            p += 2;
        }
        Ok(Some((h, p)))
    }
}

/// A `Write` adapter writing one gzip member. `flush` does a sync flush; call
/// [`finish`](Self::finish) to write the trailer (dropping it unfinished finishes it too,
/// ignoring errors).
pub struct GzEncoder<W: Write> {
    w: Option<W>,
    header: Option<Vec<u8>>,
    d: Deflater,
    crc: Crc32,
    size: u32,
    buf: Vec<u8>,
}

impl<W: Write> GzEncoder<W> {
    /// A member with the default header: no name, no time, OS Unix.
    pub fn new(w: W, level: u32) -> Self {
        Self::with_header(w, level, &Header::default()).expect("the default header encodes")
    }

    pub fn with_header(w: W, level: u32, header: &Header) -> Result<Self, Error> {
        let d = Deflater::new(level);
        let header = Some(header.to_bytes(d.level())?);
        Ok(GzEncoder { w: Some(w), header, d, crc: Crc32::new(), size: 0, buf: Vec::new() })
    }

    pub fn get_ref(&self) -> &W {
        self.w.as_ref().unwrap()
    }

    fn push(&mut self, input: &[u8], flush: Flush) -> io::Result<()> {
        if let Some(h) = self.header.take() {
            self.buf = h;
        }
        self.d.compress(input, flush, &mut self.buf)?;
        self.crc.update(input);
        self.size = self.size.wrapping_add(input.len() as u32);
        if flush == Flush::Finish {
            self.buf.extend_from_slice(&self.crc.value().to_le_bytes());
            self.buf.extend_from_slice(&self.size.to_le_bytes());
        }
        let w = self.w.as_mut().unwrap();
        w.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }

    /// Writes the end of the member and returns the writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.push(&[], Flush::Finish)?;
        Ok(self.w.take().unwrap())
    }
}

impl<W: Write> Write for GzEncoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.push(data, Flush::None)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.push(&[], Flush::Sync)?;
        self.w.as_mut().unwrap().flush()
    }
}

impl<W: Write> Drop for GzEncoder<W> {
    fn drop(&mut self) {
        if self.w.is_some() {
            let _ = self.push(&[], Flush::Finish);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    Body,
    Trailer,
    /// Between members: end of input, another member, or garbage.
    Next,
    Done,
    Failed(Error),
}

/// A `Read` adapter decompressing gzip data from a `BufRead`: every member in turn (or only
/// the first, see [`single_member`](Self::single_member)), checking each trailer. Data after
/// the last member that is not another member fails the read with
/// [`Error::TrailingGarbage`] once everything before it has been returned.
pub struct GzDecoder<R> {
    r: R,
    state: State,
    inf: Inflater,
    crc: Crc32,
    size: u32,
    /// Header or trailer bytes taken so far, when one straddles reads.
    acc: Vec<u8>,
    header: Option<Header>,
    members: u64,
    multi: bool,
}

impl<R: BufRead> GzDecoder<R> {
    pub fn new(r: R) -> Self {
        GzDecoder {
            r,
            state: State::Header,
            inf: Inflater::new(),
            crc: Crc32::new(),
            size: 0,
            acc: Vec::new(),
            header: None,
            members: 0,
            multi: true,
        }
    }

    /// Stops after the first member, leaving what follows unread in the source.
    pub fn single_member(mut self) -> Self {
        self.multi = false;
        self
    }

    /// The current (or last) member's header, once read.
    pub fn header(&self) -> Option<&Header> {
        self.header.as_ref()
    }

    /// Members completed so far.
    pub fn members(&self) -> u64 {
        self.members
    }

    pub fn get_ref(&self) -> &R {
        &self.r
    }

    pub fn into_inner(self) -> R {
        self.r
    }

    /// Takes the bytes of a `need`-shaped structure (a header or trailer) from the source
    /// without reading past it: `parse` sees what has arrived so far.
    fn gather<T>(&mut self, parse: impl Fn(&[u8]) -> Result<Option<(T, usize)>, Error>) -> io::Result<T> {
        loop {
            let input = self.r.fill_buf()?;
            let mut all = std::mem::take(&mut self.acc);
            let had = all.len();
            all.extend_from_slice(input);
            match parse(&all)? {
                Some((v, n)) => {
                    self.r.consume(n.saturating_sub(had));
                    return Ok(v);
                }
                None if input.is_empty() => return Err(Error::Truncated.into()),
                None => {
                    let n = input.len();
                    self.r.consume(n);
                    self.acc = all;
                }
            }
        }
    }

    fn read_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.state {
                State::Done => return Ok(0),
                State::Failed(e) => return Err(e.into()),
                State::Header => {
                    let first = self.members == 0;
                    let h = self.gather(Header::parse).map_err(|e| match Error::from_io(&e) {
                        Some(Error::BadMagic) if !first => Error::TrailingGarbage.into(),
                        _ => e,
                    })?;
                    self.header = Some(h);
                    self.inf.reset();
                    self.crc = Crc32::new();
                    self.size = 0;
                    self.state = State::Body;
                }
                State::Body => {
                    let (n, end) = read_body(&mut self.r, &mut self.inf, buf)?;
                    self.crc.update(&buf[..n]);
                    self.size = self.size.wrapping_add(n as u32);
                    if end {
                        self.state = State::Trailer;
                    }
                    if n > 0 {
                        return Ok(n);
                    }
                }
                State::Trailer => {
                    let t = self.gather(|b| Ok(b.get(..8).map(|t| (<[u8; 8]>::try_from(t).unwrap(), 8))))?;
                    if u32::from_le_bytes([t[0], t[1], t[2], t[3]]) != self.crc.value() {
                        return Err(Error::Crc.into());
                    }
                    if u32::from_le_bytes([t[4], t[5], t[6], t[7]]) != self.size {
                        return Err(Error::Length.into());
                    }
                    self.members += 1;
                    self.state = if self.multi { State::Next } else { State::Done };
                }
                State::Next => {
                    let input = self.r.fill_buf()?;
                    if input.is_empty() {
                        self.state = State::Done;
                    } else if input[0] != 0x1f {
                        return Err(Error::TrailingGarbage.into());
                    } else {
                        self.state = State::Header;
                    }
                }
            }
        }
    }
}

impl<R: BufRead> Read for GzDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let r = self.read_inner(buf);
        if let Err(e) = &r
            && let Some(le) = Error::from_io(e)
        {
            self.state = State::Failed(le);
        }
        r
    }
}

/// Compresses `data` into a single gzip member with the default header.
pub fn compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), level);
    e.write_all(data).expect("writing to a Vec cannot fail");
    e.finish().expect("writing to a Vec cannot fail")
}

/// Decompresses all the gzip members in `data`, which must hold nothing else.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    decompress_with_limit(data, usize::MAX)
}

/// [`decompress`], failing with [`Error::OutputLimit`] rather than produce more than `limit`
/// bytes.
pub fn decompress_with_limit(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    read_limited(GzDecoder::new(data), limit)
}

pub(crate) fn read_limited(mut r: impl Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 1 << 16];
    loop {
        let n = r.read(&mut chunk).map_err(unwrap_io)?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > limit {
            return Err(Error::OutputLimit);
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let h = Header {
            text: true,
            mtime: 0x1234_5678,
            xfl: 2,
            os: 3,
            extra: Some(b"AB\x02\x00hi".to_vec()),
            name: Some(b"file.txt".to_vec()),
            comment: Some(b"a comment".to_vec()),
            hcrc: true,
        };
        let b = h.to_bytes(9).unwrap();
        assert_eq!(Header::parse(&b).unwrap(), Some((h, b.len())));
        for cut in 0..b.len() {
            assert_eq!(Header::parse(&b[..cut]).unwrap(), None, "cut {cut}");
        }
        let mut bad = b.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(Header::parse(&bad), Err(Error::HeaderCrc));
    }

    #[test]
    fn multi_member_and_garbage() {
        let mut two = compress(b"hello, ", 6);
        two.extend(compress(b"world", 1));
        assert_eq!(decompress(&two).unwrap(), b"hello, world");
        let mut g = two.clone();
        g.extend_from_slice(b"\0\0\0");
        assert_eq!(decompress(&g), Err(Error::TrailingGarbage));
        let mut g = two.clone();
        g.extend_from_slice(b"\x1f\x00");
        assert_eq!(decompress(&g), Err(Error::TrailingGarbage));
        let mut d = GzDecoder::new(&two[..]).single_member();
        let mut s = Vec::new();
        d.read_to_end(&mut s).unwrap();
        assert_eq!(s, b"hello, ");
        assert_eq!(d.into_inner().len(), two.len() - compress(b"hello, ", 6).len());
    }

    #[test]
    fn trailer_checks() {
        let g = compress(b"some data", 6);
        let n = g.len();
        let mut bad = g.clone();
        bad[n - 8] ^= 1;
        assert_eq!(decompress(&bad), Err(Error::Crc));
        let mut bad = g.clone();
        bad[n - 1] ^= 1;
        assert_eq!(decompress(&bad), Err(Error::Length));
        assert_eq!(decompress(&g[..n - 1]), Err(Error::Truncated));
        assert_eq!(decompress(b""), Err(Error::Truncated));
    }
}
