//! The archive stream: reading members (with their pax and GNU long-name headers folded in)
//! and writing them in records, through gzip (OxideBSD's `flate`) or zstd (the base system's
//! `/sbin/zstd`, run as a filter).
//!
//! Reading detects the compression from the data, as bsdtar does: gzip and zstd are expanded,
//! bzip2, xz and compress(1) data are refused by name. Writing pads the tar stream with zeros
//! to a whole record (20 blocks, 10240 bytes, unless `-b`) before compressing it.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};

use flate::gzip::{GzDecoder, GzEncoder};

use super::header::{self, BLOCK, Block, Entry, FormatError, Kind, MAX_META, Pax};

const BUF: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Comp {
    None,
    Gzip,
    Zstd,
}

/// zstd(1): the base system's, else whatever `PATH` finds.
fn zstd_command() -> Command {
    let p = Path::new("/sbin/zstd");
    if p.exists() { Command::new(p) } else { Command::new("zstd") }
}

pub enum ReadError {
    Io(io::Error),
    Format(FormatError),
    /// The data ended inside a header or a member.
    Truncated,
    /// The very first block is not a tar header.
    NotTar,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Io(e) => f.write_str(&super::strerror(e)),
            ReadError::Format(e) => write!(f, "{e}"),
            ReadError::Truncated => f.write_str("Truncated tar archive"),
            ReadError::NotTar => f.write_str("Error opening archive: Unrecognized archive format"),
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof { ReadError::Truncated } else { ReadError::Io(e) }
    }
}

/// Reads until `buf` is full or the input ends: the bytes read.
fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub struct Reader {
    r: Box<dyn BufRead>,
    /// Bytes of the tar stream consumed.
    pos: u64,
    /// The current member's data still unread, and the padding after it.
    left: u64,
    pad: u64,
    global: Pax,
    /// Where the end-of-archive blocks start (the end of the data if there are none).
    pub end: u64,
    child: Option<Child>,
    feeder: Option<std::thread::JoinHandle<()>>,
    /// The member's name had a pax header marking it sparse.
    pub sparse: bool,
}

/// The magic numbers recognised at the start of an archive.
fn sniff(head: &[u8]) -> Result<Comp, String> {
    if head.starts_with(&[0x1f, 0x8b]) {
        Ok(Comp::Gzip)
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Ok(Comp::Zstd)
    } else if head.starts_with(b"BZh") {
        Err("bzip2 compression is not supported".into())
    } else if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        Err("xz compression is not supported".into())
    } else if head.starts_with(&[0x1f, 0x9d]) {
        Err("compress (.Z) compression is not supported".into())
    } else {
        Ok(Comp::None)
    }
}

/// The first few bytes of an input, then the rest of it.
struct Head<R> {
    head: Vec<u8>,
    at: usize,
    r: R,
}

impl<R: Read> Read for Head<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.at < self.head.len() {
            let n = (self.head.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.head[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.r.read(buf)
    }
}

/// Peeks at the start of `r`: the compression, and a reader giving all of it back.
fn peek<R: Read>(mut r: R) -> Result<(Comp, Head<R>), String> {
    let mut head = vec![0u8; 6];
    let n = read_full(&mut r, &mut head).map_err(|e| super::strerror(&e))?;
    head.truncate(n);
    let c = sniff(&head)?;
    Ok((c, Head { head, at: 0, r }))
}

impl Reader {
    fn new(r: Box<dyn BufRead>) -> Reader {
        Reader { r, pos: 0, left: 0, pad: 0, global: Pax::default(), end: 0, child: None, feeder: None, sparse: false }
    }

    /// Opens archive `name` ("-": the standard input) for reading, expanding it if it is
    /// compressed.
    pub fn open(name: &OsStr) -> Result<Reader, String> {
        if name == "-" {
            let (c, h) = peek(io::stdin())?;
            return Self::wrap(c, h);
        }
        let f = File::open(name).map_err(|e| super::strerror(&e))?;
        let (c, h) = peek(f)?;
        if c == Comp::Zstd {
            // A file can be zstd's own standard input, from its start.
            let mut f = h.r;
            f.seek(SeekFrom::Start(0)).map_err(|e| super::strerror(&e))?;
            return Self::zstd(Stdio::from(f));
        }
        Self::wrap(c, h)
    }

    fn wrap<R: Read + Send + 'static>(c: Comp, h: Head<R>) -> Result<Reader, String> {
        match c {
            Comp::None => Ok(Reader::new(Box::new(BufReader::with_capacity(BUF, h)))),
            Comp::Gzip => {
                let d = GzDecoder::new(BufReader::with_capacity(BUF, h));
                Ok(Reader::new(Box::new(BufReader::with_capacity(BUF, d))))
            }
            Comp::Zstd => {
                // A pipe: feed zstd from a thread, the bytes already read first.
                let mut r = Self::zstd(Stdio::piped())?;
                let mut stdin = r.child.as_mut().unwrap().stdin.take().unwrap();
                let mut h = h;
                r.feeder = Some(std::thread::spawn(move || {
                    let _ = io::copy(&mut h, &mut stdin);
                }));
                Ok(r)
            }
        }
    }

    fn zstd(input: Stdio) -> Result<Reader, String> {
        let mut child = zstd_command()
            .args(["-d", "-c", "-q"])
            .stdin(input)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run zstd: {}", super::strerror(&e)))?;
        let out = child.stdout.take().unwrap();
        let mut r = Reader::new(Box::new(BufReader::with_capacity(BUF, out)));
        r.child = Some(child);
        Ok(r)
    }

    /// Opens an archive file for -r/-u: plain tar only.
    pub fn open_file(f: File) -> Result<Reader, String> {
        let (c, h) = peek(f)?;
        if c != Comp::None {
            return Err("Cannot append to a compressed archive".into());
        }
        Ok(Reader::new(Box::new(BufReader::with_capacity(BUF, h))))
    }

    fn block(&mut self, b: &mut [u8; BLOCK]) -> Result<bool, ReadError> {
        let n = read_full(&mut self.r, b)?;
        self.pos += n as u64;
        match n {
            0 => Ok(false),
            BLOCK => Ok(true),
            _ => Err(ReadError::Truncated),
        }
    }

    fn skip(&mut self, mut n: u64) -> Result<(), ReadError> {
        while n > 0 {
            let buf = self.r.fill_buf()?;
            if buf.is_empty() {
                return Err(ReadError::Truncated);
            }
            let k = (buf.len() as u64).min(n) as usize;
            self.r.consume(k);
            self.pos += k as u64;
            n -= k as u64;
        }
        Ok(())
    }

    fn meta(&mut self, size: u64) -> Result<Vec<u8>, ReadError> {
        if size > MAX_META {
            return Err(ReadError::Format(FormatError::BadPax));
        }
        let mut v = vec![0u8; size as usize];
        if read_full(&mut self.r, &mut v)? != v.len() {
            return Err(ReadError::Truncated);
        }
        self.pos += size;
        self.skip((BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64)?;
        Ok(v)
    }

    /// The next member, or None at the end of the archive. The previous member's data, if
    /// it was not read, is skipped.
    pub fn next(&mut self) -> Result<Option<Entry>, ReadError> {
        let rest = self.left + self.pad;
        self.left = 0;
        self.pad = 0;
        self.skip(rest)?;
        let mut local = Pax::default();
        let (mut long_name, mut long_link) = (None, None);
        let mut b = [0u8; BLOCK];
        let mut metas = 0;
        loop {
            let at = self.pos;
            let got = self.block(&mut b).map_err(|e| match e {
                ReadError::Truncated if at == 0 => ReadError::NotTar,
                e => e,
            })?;
            if !got {
                if metas > 0 {
                    return Err(ReadError::Truncated);
                }
                self.end = at;
                return Ok(None);
            }
            let parsed =
                header::parse(&b).map_err(|e| if at == 0 { ReadError::NotTar } else { ReadError::Format(e) })?;
            match parsed {
                Block::Zero => {
                    self.end = at;
                    // One zero block ends it (bsdtar's leniency); whatever follows is ignored.
                    return Ok(None);
                }
                Block::Meta { flag, size } => {
                    metas += 1;
                    let data = self.meta(size)?;
                    let strip = |mut v: Vec<u8>| {
                        while v.last() == Some(&0) {
                            v.pop();
                        }
                        v
                    };
                    match flag {
                        b'x' => local.parse(&data).map_err(ReadError::Format)?,
                        b'g' => self.global.parse(&data).map_err(ReadError::Format)?,
                        b'L' => long_name = Some(strip(data)),
                        _ => long_link = Some(strip(data)),
                    }
                }
                Block::Member(mut e) => {
                    if let Some(n) = long_name {
                        e.path = n;
                    }
                    if let Some(l) = long_link {
                        e.link = l;
                    }
                    self.global.apply(&mut e);
                    local.apply(&mut e);
                    self.sparse = self.global.sparse || local.sparse;
                    if self.sparse {
                        e.kind = Kind::Other(b'S');
                    }
                    if e.kind == Kind::File && e.path.ends_with(b"/") && e.size == 0 {
                        e.kind = Kind::Dir;
                    }
                    self.left = e.data_len();
                    self.pad = (BLOCK as u64 - self.left % BLOCK as u64) % BLOCK as u64;
                    return Ok(Some(e));
                }
            }
        }
    }

    /// Reads the current member's data.
    pub fn read_data(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.left == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.left) as usize;
        let n = loop {
            match self.r.read(&mut buf[..want]) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        };
        if n == 0 {
            return Err(ReadError::Truncated);
        }
        self.left -= n as u64;
        self.pos += n as u64;
        Ok(n)
    }

    /// Ends reading: waits for a zstd filter. Reading stops at the end-of-archive blocks, so
    /// a filter killed by the closed pipe is not an error.
    pub fn close(mut self) {
        self.r = Box::new(io::empty());
        if let Some(mut c) = self.child.take() {
            let _ = c.wait();
        }
        if let Some(t) = self.feeder.take() {
            let _ = t.join();
        }
    }
}

// --- writing ---------------------------------------------------------------------------------

enum Sink {
    Plain(Box<dyn Write>),
    Gzip(GzEncoder<Box<dyn Write>>),
    Zstd(BufWriter<ChildStdin>, Child),
}

pub struct Writer {
    sink: Option<Sink>,
    /// Bytes of the tar stream written (counted from the archive's start for -r/-u).
    pos: u64,
    record: u64,
}

impl Write for Writer {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = match self.sink.as_mut().unwrap() {
            Sink::Plain(w) => w.write(b)?,
            Sink::Gzip(w) => w.write(b)?,
            Sink::Zstd(w, _) => w.write(b)?,
        };
        self.pos += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.sink.as_mut().unwrap() {
            Sink::Plain(w) => w.flush(),
            Sink::Gzip(w) => w.flush(),
            Sink::Zstd(w, _) => w.flush(),
        }
    }
}

impl Writer {
    /// A writer onto `out`, compressing with `comp`. `pos` is where in the archive it starts.
    pub fn new(
        out: Box<dyn Write>,
        out_stdio: Option<Stdio>,
        comp: Comp,
        record: usize,
        pos: u64,
    ) -> Result<Writer, String> {
        let sink = match comp {
            Comp::None => Sink::Plain(out),
            Comp::Gzip => Sink::Gzip(GzEncoder::new(out, 6)),
            Comp::Zstd => {
                let mut child = zstd_command()
                    .args(["-q", "-c"])
                    .stdin(Stdio::piped())
                    .stdout(out_stdio.unwrap_or_else(Stdio::inherit))
                    .spawn()
                    .map_err(|e| format!("cannot run zstd: {}", super::strerror(&e)))?;
                let stdin = child.stdin.take().unwrap();
                Sink::Zstd(BufWriter::with_capacity(BUF, stdin), child)
            }
        };
        Ok(Writer { sink: Some(sink), pos, record: record as u64 })
    }

    pub fn entry(&mut self, header: &[u8]) -> io::Result<()> {
        self.write_all(header)
    }

    /// Pads a member's data to a whole block.
    pub fn pad(&mut self) -> io::Result<()> {
        let n = (BLOCK as u64 - self.pos % BLOCK as u64) % BLOCK as u64;
        self.write_all(&vec![0u8; n as usize])
    }

    /// Writes the end-of-archive blocks and the record's padding, and ends the stream.
    pub fn finish(mut self) -> io::Result<u64> {
        self.write_all(&[0u8; 2 * BLOCK])?;
        let n = (self.record - self.pos % self.record) % self.record;
        self.write_all(&vec![0u8; n as usize])?;
        let pos = self.pos;
        match self.sink.take().unwrap() {
            Sink::Plain(mut w) => w.flush()?,
            Sink::Gzip(w) => w.finish()?.flush()?,
            Sink::Zstd(mut w, mut child) => {
                w.flush()?;
                drop(w);
                let st = child.wait()?;
                if !st.success() {
                    return Err(io::Error::other(format!("zstd failed: {st}")));
                }
            }
        }
        Ok(pos)
    }
}
