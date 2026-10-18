//! The zlib format (RFC 1950): a two-byte header, a DEFLATE stream and the data's Adler-32.

use std::io::{self, BufRead, Read, Write};

use crate::adler32::Adler32;
use crate::deflate::{Deflater, Flush};
use crate::inflate::{Inflater, read_body};
use crate::Error;

/// The header for `level`: CM 8, CINFO 7 (32 KiB window), FLEVEL as zlib sets it, and
/// FCHECK making the pair a multiple of 31.
fn header(level: u32) -> [u8; 2] {
    let cmf = 0x78u8;
    let flevel = match level {
        0 | 1 => 0,
        2..=5 => 1,
        6 => 2,
        _ => 3,
    };
    let mut flg = flevel << 6;
    flg += (31 - ((cmf as u16 * 256 + flg as u16) % 31) as u8) % 31;
    [cmf, flg]
}

/// Checks a header: deflate, a window of at most 32 KiB, FCHECK right, no preset dictionary.
fn check_header(h: [u8; 2]) -> Result<(), Error> {
    if !(h[0] as u16 * 256 + h[1] as u16).is_multiple_of(31) || h[0] & 0x0f != 8 || h[0] >> 4 > 7 {
        return Err(Error::BadZlibHeader);
    }
    if h[1] & 0x20 != 0 {
        return Err(Error::PresetDictionary);
    }
    Ok(())
}

/// A `Write` adapter writing a zlib stream. `flush` does a sync flush; call
/// [`finish`](Self::finish) to write the trailer (dropping it unfinished finishes it too,
/// ignoring errors).
pub struct ZlibEncoder<W: Write> {
    w: Option<W>,
    started: bool,
    d: Deflater,
    adler: Adler32,
    buf: Vec<u8>,
}

impl<W: Write> ZlibEncoder<W> {
    pub fn new(w: W, level: u32) -> Self {
        ZlibEncoder { w: Some(w), started: false, d: Deflater::new(level), adler: Adler32::new(), buf: Vec::new() }
    }

    pub fn get_ref(&self) -> &W {
        self.w.as_ref().unwrap()
    }

    fn push(&mut self, input: &[u8], flush: Flush) -> io::Result<()> {
        if !self.started {
            self.buf.extend_from_slice(&header(self.d.level()));
            self.started = true;
        }
        self.d.compress(input, flush, &mut self.buf)?;
        self.adler.update(input);
        if flush == Flush::Finish {
            self.buf.extend_from_slice(&self.adler.value().to_be_bytes());
        }
        let w = self.w.as_mut().unwrap();
        w.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }

    /// Writes the end of the stream and returns the writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.push(&[], Flush::Finish)?;
        Ok(self.w.take().unwrap())
    }
}

impl<W: Write> Write for ZlibEncoder<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.push(data, Flush::None)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.push(&[], Flush::Sync)?;
        self.w.as_mut().unwrap().flush()
    }
}

impl<W: Write> Drop for ZlibEncoder<W> {
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
    Done,
    Failed(Error),
}

/// A `Read` adapter decompressing a zlib stream from a `BufRead`, reading exactly the
/// stream's bytes from it.
pub struct ZlibDecoder<R> {
    r: R,
    state: State,
    inf: Inflater,
    adler: Adler32,
    acc: Vec<u8>,
}

impl<R: BufRead> ZlibDecoder<R> {
    pub fn new(r: R) -> Self {
        ZlibDecoder { r, state: State::Header, inf: Inflater::new(), adler: Adler32::new(), acc: Vec::new() }
    }

    pub fn get_ref(&self) -> &R {
        &self.r
    }

    pub fn into_inner(self) -> R {
        self.r
    }

    /// Reads exactly `n` (at most 4) more bytes into `acc`.
    fn take(&mut self, n: usize) -> io::Result<()> {
        while self.acc.len() < n {
            let input = self.r.fill_buf()?;
            if input.is_empty() {
                return Err(Error::Truncated.into());
            }
            let k = (n - self.acc.len()).min(input.len());
            self.acc.extend_from_slice(&input[..k]);
            self.r.consume(k);
        }
        Ok(())
    }

    fn read_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.state {
                State::Done => return Ok(0),
                State::Failed(e) => return Err(e.into()),
                State::Header => {
                    self.take(2)?;
                    check_header([self.acc[0], self.acc[1]])?;
                    self.acc.clear();
                    self.state = State::Body;
                }
                State::Body => {
                    let (n, end) = read_body(&mut self.r, &mut self.inf, buf)?;
                    self.adler.update(&buf[..n]);
                    if end {
                        self.state = State::Trailer;
                    }
                    if n > 0 {
                        return Ok(n);
                    }
                }
                State::Trailer => {
                    self.take(4)?;
                    let a = u32::from_be_bytes([self.acc[0], self.acc[1], self.acc[2], self.acc[3]]);
                    if a != self.adler.value() {
                        return Err(Error::Adler.into());
                    }
                    self.state = State::Done;
                }
            }
        }
    }
}

impl<R: BufRead> Read for ZlibDecoder<R> {
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

/// Compresses `data` into a zlib stream.
pub fn compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), level);
    e.write_all(data).expect("writing to a Vec cannot fail");
    e.finish().expect("writing to a Vec cannot fail")
}

/// Decompresses a zlib stream, which must be all of `data`.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, Error> {
    decompress_with_limit(data, usize::MAX)
}

/// [`decompress`], failing with [`Error::OutputLimit`] rather than produce more than `limit`
/// bytes.
pub fn decompress_with_limit(data: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut d = ZlibDecoder::new(data);
    let out = crate::gzip::read_limited(&mut d, limit)?;
    if !d.into_inner().is_empty() {
        return Err(Error::TrailingGarbage);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        assert_eq!(header(6), [0x78, 0x9c]);
        assert_eq!(header(1), [0x78, 0x01]);
        assert_eq!(header(9), [0x78, 0xda]);
        for l in 0..=9 {
            check_header(header(l)).unwrap();
        }
        assert_eq!(check_header([0x78, 0xbb]), Err(Error::PresetDictionary));
        assert_eq!(check_header([0x78, 0x9d]), Err(Error::BadZlibHeader));
    }

    #[test]
    fn round_trip_and_checks() {
        let z = compress(b"zlib zlib zlib zlib", 6);
        assert_eq!(decompress(&z).unwrap(), b"zlib zlib zlib zlib");
        let mut bad = z.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(decompress(&bad), Err(Error::Adler));
        assert_eq!(decompress(&z[..z.len() - 1]), Err(Error::Truncated));
    }
}
