//! The tar formats: ustar(5) header blocks, with pax extended headers (`x`, `g`) and GNU long
//! names (`L`, `K`) read, and pax headers written for whatever a ustar field cannot hold.
//!
//! The writer is the one in the tree's `build_install.rs` (the dist sets' archives), grown up:
//! a path longer than 100 bytes is split into `prefix` and `name` at a `/`, numbers are
//! zero-padded octal ending in a NUL, the checksum is six octal digits, a NUL and a space.
//! What does not fit (a path no split holds, a link target over 100 bytes, a size of 8 GiB or
//! more, an id over 2097151, a time before 1970 or past 2242, an owner name over 32 bytes)
//! goes in a pax header before the entry, bsdtar's "restricted pax": a plain ustar archive
//! whenever one can be written. The ustar fields then hold what fits (the number in base-256,
//! as GNU tar and bsdtar read it).

use std::fmt;

pub const BLOCK: usize = 512;

/// The largest pax or GNU long-name header read: a hostile archive's 8 GiB "path" must not
/// claim the memory of a 64 MB machine.
pub const MAX_META: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    HardLink,
    Symlink,
    Char,
    Block,
    Dir,
    Fifo,
    /// A type this tar does not create (GNU sparse, volume labels, ...); its data is skipped.
    Other(u8),
}

impl Kind {
    pub fn flag(self) -> u8 {
        match self {
            Kind::File => b'0',
            Kind::HardLink => b'1',
            Kind::Symlink => b'2',
            Kind::Char => b'3',
            Kind::Block => b'4',
            Kind::Dir => b'5',
            Kind::Fifo => b'6',
            Kind::Other(c) => c,
        }
    }

    fn from_flag(c: u8) -> Kind {
        match c {
            b'0' | 0 | b'7' => Kind::File,
            b'1' => Kind::HardLink,
            b'2' => Kind::Symlink,
            b'3' => Kind::Char,
            b'4' => Kind::Block,
            b'5' => Kind::Dir,
            b'6' => Kind::Fifo,
            c => Kind::Other(c),
        }
    }

    /// Whether data blocks follow the header for an entry of this kind with a size. POSIX
    /// stores none for links, devices, directories and FIFOs; a hard link may carry data in
    /// pax, which is skipped.
    pub fn has_data(self) -> bool {
        matches!(self, Kind::File | Kind::HardLink | Kind::Other(_))
    }
}

/// One archive member, its pax and GNU overrides applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: Vec<u8>,
    /// A symbolic link's target, or the earlier member a hard link names.
    pub link: Vec<u8>,
    pub kind: Kind,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub uname: Vec<u8>,
    pub gname: Vec<u8>,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: u32,
    pub devmajor: u32,
    pub devminor: u32,
}

impl Entry {
    pub fn new(path: Vec<u8>, kind: Kind) -> Entry {
        Entry {
            path,
            link: Vec::new(),
            kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            uname: Vec::new(),
            gname: Vec::new(),
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            devmajor: 0,
            devminor: 0,
        }
    }

    /// The bytes of data that follow the header.
    pub fn data_len(&self) -> u64 {
        if self.kind.has_data() { self.size } else { 0 }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FormatError {
    /// Not a header at all: checksum or number fields wrong.
    Damaged,
    /// A pax header that does not parse, or one too large.
    BadPax,
    /// A value that cannot be written in the chosen format.
    TooLong(&'static str),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::Damaged => f.write_str("Damaged tar archive"),
            FormatError::BadPax => f.write_str("Invalid pax extended header"),
            FormatError::TooLong(what) => write!(f, "{what} does not fit the ustar format"),
        }
    }
}

// --- numbers ---------------------------------------------------------------------------------

/// The largest value an `n`-byte octal field (with its NUL) holds.
fn octal_max(n: usize) -> u64 {
    (1u64 << (3 * (n - 1))) - 1
}

fn put(h: &mut [u8], at: usize, len: usize, bytes: &[u8]) {
    let n = bytes.len().min(len);
    h[at..at + n].copy_from_slice(&bytes[..n]);
}

/// Writes `v` in an octal field, or base-256 if it does not fit.
fn put_num(h: &mut [u8], at: usize, len: usize, v: i64) {
    if v >= 0 && (v as u64) <= octal_max(len) {
        let text = format!("{:0width$o}", v, width = len - 1);
        put(h, at, len - 1, text.as_bytes());
        h[at + len - 1] = 0;
    } else {
        // Base-256: the first byte's high bit set, the rest big-endian two's complement.
        let bytes = v.to_be_bytes();
        let f = &mut h[at..at + len];
        let fill = if v < 0 { 0xff } else { 0 };
        f.fill(fill);
        f[len - 8..].copy_from_slice(&bytes);
        f[0] = if v < 0 { 0xff } else { 0x80 };
    }
}

/// Reads an octal (or base-256) number field.
pub fn get_num(f: &[u8]) -> Result<i64, FormatError> {
    if f.first().is_some_and(|&b| b & 0x80 != 0) {
        let neg = f[0] == 0xff;
        let mut v: i64 = if neg { -1 } else { 0 };
        let start = f.len().saturating_sub(8);
        // Any byte before the last eight must be sign fill, or the value does not fit.
        for (i, &b) in f.iter().enumerate() {
            let b = if i == 0 { b & 0x7f | if neg { 0x80 } else { 0 } } else { b };
            if i < start {
                if b != if neg { 0xff } else { 0 } && !(i == 0 && b & 0x7f == 0) {
                    return Err(FormatError::Damaged);
                }
                continue;
            }
            v = (v << 8) | i64::from(b);
        }
        if !neg && v < 0 {
            return Err(FormatError::Damaged);
        }
        return Ok(v);
    }
    let mut v: i64 = 0;
    let mut i = 0;
    while i < f.len() && (f[i] == b' ' || f[i] == 0) {
        i += 1;
    }
    if i == f.len() {
        return Ok(0);
    }
    while i < f.len() && (b'0'..=b'7').contains(&f[i]) {
        v = v.checked_mul(8).and_then(|v| v.checked_add(i64::from(f[i] - b'0'))).ok_or(FormatError::Damaged)?;
        i += 1;
    }
    if i < f.len() && f[i] != b' ' && f[i] != 0 {
        return Err(FormatError::Damaged);
    }
    Ok(v)
}

fn get_str(f: &[u8]) -> Vec<u8> {
    let n = f.iter().position(|&b| b == 0).unwrap_or(f.len());
    f[..n].to_vec()
}

fn checksum(h: &[u8; BLOCK]) -> (i64, i64) {
    let mut u: i64 = 0;
    let mut s: i64 = 0;
    for (i, &b) in h.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        u += i64::from(b);
        s += i64::from(b as i8);
    }
    (u, s)
}

// --- reading ---------------------------------------------------------------------------------

/// What a header block is.
pub enum Block {
    /// All zeros: the end of the archive.
    Zero,
    /// A pax extended header for the next member (`x`) or all that follow (`g`), a GNU long
    /// name (`L`) or long link target (`K`): `size` bytes of data follow.
    Meta {
        flag: u8,
        size: u64,
    },
    Member(Entry),
}

pub fn parse(h: &[u8; BLOCK]) -> Result<Block, FormatError> {
    if h.iter().all(|&b| b == 0) {
        return Ok(Block::Zero);
    }
    let want = get_num(&h[148..156])?;
    let (u, s) = checksum(h);
    if want != u && want != s {
        return Err(FormatError::Damaged);
    }
    let flag = h[156];
    let size = get_num(&h[124..136])?;
    if size < 0 {
        return Err(FormatError::Damaged);
    }
    let size = size as u64;
    if matches!(flag, b'x' | b'g' | b'L' | b'K') {
        return Ok(Block::Meta { flag, size });
    }
    let posix = &h[257..263] == b"ustar\0";
    let mut path = get_str(&h[0..100]);
    if posix {
        let prefix = get_str(&h[345..500]);
        if !prefix.is_empty() {
            let mut p = prefix;
            p.push(b'/');
            p.extend_from_slice(&path);
            path = p;
        }
    }
    let mut kind = Kind::from_flag(flag);
    // Old (v7) archives mark a directory with a trailing slash on a regular file.
    if flag == 0 && path.ends_with(b"/") {
        kind = Kind::Dir;
    }
    let ustarish = posix || &h[257..265] == b"ustar  \0";
    let num = |r: std::ops::Range<usize>| get_num(&h[r]);
    let mut e = Entry::new(path, kind);
    e.link = get_str(&h[157..257]);
    e.mode = (num(100..108)? & 0o7777_7777) as u32;
    e.uid = num(108..116)?.max(0) as u64;
    e.gid = num(116..124)?.max(0) as u64;
    e.size = size;
    e.mtime = num(136..148)?;
    if ustarish {
        e.uname = get_str(&h[265..297]);
        e.gname = get_str(&h[297..329]);
        if matches!(kind, Kind::Char | Kind::Block) {
            e.devmajor = num(329..337)?.clamp(0, u32::MAX.into()) as u32;
            e.devminor = num(337..345)?.clamp(0, u32::MAX.into()) as u32;
        }
    }
    Ok(Block::Member(e))
}

/// The overrides a pax header gives.
#[derive(Clone, Default, Debug)]
pub struct Pax {
    pub path: Option<Vec<u8>>,
    pub link: Option<Vec<u8>>,
    pub size: Option<u64>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub uname: Option<Vec<u8>>,
    pub gname: Option<Vec<u8>>,
    pub mtime: Option<(i64, u32)>,
    /// GNU.sparse.* keys: a sparse file, which this tar does not expand.
    pub sparse: bool,
}

fn dec(v: &[u8]) -> Option<u64> {
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

/// A pax time: `[-]seconds[.fraction]`.
fn pax_time(v: &[u8]) -> Option<(i64, u32)> {
    let (neg, v) = match v.strip_prefix(b"-") {
        Some(r) => (true, r),
        None => (false, v),
    };
    let (secs, frac) = match v.iter().position(|&b| b == b'.') {
        Some(i) => (&v[..i], &v[i + 1..]),
        None => (v, &b""[..]),
    };
    let s = dec(secs)? as i64;
    if !frac.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut ns: u32 = 0;
    for i in 0..9 {
        ns = ns * 10 + frac.get(i).map_or(0, |&d| u32::from(d - b'0'));
    }
    if neg {
        // -1.25 is 1.25 s before the epoch: seconds -2, 750 ms.
        if ns > 0 { Some((-s - 1, 1_000_000_000 - ns)) } else { Some((-s, 0)) }
    } else {
        Some((s, ns))
    }
}

impl Pax {
    /// Parses `len key=value\n` records into `self`.
    pub fn parse(&mut self, mut data: &[u8]) -> Result<(), FormatError> {
        while !data.is_empty() {
            if data.iter().all(|&b| b == 0) {
                break;
            }
            let sp = data.iter().take(21).position(|&b| b == b' ').ok_or(FormatError::BadPax)?;
            let len = dec(&data[..sp]).ok_or(FormatError::BadPax)? as usize;
            if len <= sp + 1 || len > data.len() || data[len - 1] != b'\n' {
                return Err(FormatError::BadPax);
            }
            let rec = &data[sp + 1..len - 1];
            let eq = rec.iter().position(|&b| b == b'=').ok_or(FormatError::BadPax)?;
            let (k, v) = (&rec[..eq], &rec[eq + 1..]);
            match k {
                b"path" => self.path = Some(v.to_vec()),
                b"linkpath" => self.link = Some(v.to_vec()),
                b"size" => self.size = Some(dec(v).ok_or(FormatError::BadPax)?),
                b"uid" => self.uid = Some(dec(v).ok_or(FormatError::BadPax)?),
                b"gid" => self.gid = Some(dec(v).ok_or(FormatError::BadPax)?),
                b"uname" => self.uname = Some(v.to_vec()),
                b"gname" => self.gname = Some(v.to_vec()),
                b"mtime" => self.mtime = Some(pax_time(v).ok_or(FormatError::BadPax)?),
                _ if k.starts_with(b"GNU.sparse.") => self.sparse = true,
                _ => {}
            }
            data = &data[len..];
        }
        Ok(())
    }

    pub fn apply(&self, e: &mut Entry) {
        if let Some(p) = &self.path {
            e.path = p.clone();
        }
        if let Some(l) = &self.link {
            e.link = l.clone();
        }
        if let Some(s) = self.size {
            e.size = s;
        }
        if let Some(u) = self.uid {
            e.uid = u;
        }
        if let Some(g) = self.gid {
            e.gid = g;
        }
        if let Some(u) = &self.uname {
            e.uname = u.clone();
        }
        if let Some(g) = &self.gname {
            e.gname = g.clone();
        }
        if let Some((s, ns)) = self.mtime {
            e.mtime = s;
            e.mtime_nsec = ns;
        }
    }
}

// --- writing ---------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// ustar, with pax headers only for what ustar cannot hold (the default).
    Restricted,
    /// Plain ustar: what does not fit is an error.
    Ustar,
    /// pax: a pax header for every member, carrying the time to the nanosecond.
    Pax,
}

/// Splits `path` into ustar's `prefix` and `name`, or None if no split fits.
fn split(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= 100 {
        return Some((b"", path));
    }
    // The first `/` that leaves `name` at most 100 bytes and `prefix` at most 155.
    let i = (1..path.len().saturating_sub(1)).find(|&i| path[i] == b'/' && i <= 155 && path.len() - i - 1 <= 100)?;
    Some((&path[..i], &path[i + 1..]))
}

fn record(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    let base = key.len() + value.len() + 3;
    let mut len = base + 1;
    while len != base + len.to_string().len() {
        len = base + len.to_string().len();
    }
    out.extend_from_slice(len.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn ustar_block(name: &[u8], prefix: &[u8], e: &Entry, flag: u8, size: u64, link: &[u8]) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    put(&mut h, 0, 100, name);
    put_num(&mut h, 100, 8, i64::from(e.mode & 0o7777));
    put_num(&mut h, 108, 8, e.uid.min(i64::MAX as u64) as i64);
    put_num(&mut h, 116, 8, e.gid.min(i64::MAX as u64) as i64);
    put_num(&mut h, 124, 12, size.min(i64::MAX as u64) as i64);
    put_num(&mut h, 136, 12, e.mtime);
    h[156] = flag;
    put(&mut h, 157, 100, link);
    put(&mut h, 257, 6, b"ustar\0");
    put(&mut h, 263, 2, b"00");
    put(&mut h, 265, 32, &e.uname);
    put(&mut h, 297, 32, &e.gname);
    if matches!(e.kind, Kind::Char | Kind::Block) {
        put_num(&mut h, 329, 8, i64::from(e.devmajor));
        put_num(&mut h, 337, 8, i64::from(e.devminor));
    } else {
        put_num(&mut h, 329, 8, 0);
        put_num(&mut h, 337, 8, 0);
    }
    put(&mut h, 345, 155, prefix);
    h[148..156].fill(b' ');
    let (sum, _) = checksum(&h);
    put(&mut h, 148, 8, format!("{sum:06o}\0 ").as_bytes());
    h
}

/// The blocks for `e`: a pax header (and its data) if one is needed, then the ustar header.
/// The member's data, if any, follows.
pub fn encode(e: &Entry, fmt: Format) -> Result<Vec<u8>, FormatError> {
    let mut pax = Vec::new();
    let all = fmt == Format::Pax;
    let ustar = fmt == Format::Ustar;
    let (prefix, name) = match split(&e.path) {
        Some(s) if !all => s,
        s => {
            if ustar {
                return Err(FormatError::TooLong("pathname"));
            }
            record(&mut pax, "path", &e.path);
            // What a reader without pax sees: as much of the end of the name as fits.
            s.unwrap_or_else(|| {
                let tail = &e.path[e.path.len() - 100..];
                (b"", tail)
            })
        }
    };
    let link: &[u8] = if e.link.len() > 100 || (all && !e.link.is_empty()) {
        if ustar {
            return Err(FormatError::TooLong("linkname"));
        }
        record(&mut pax, "linkpath", &e.link);
        &e.link[..e.link.len().min(100)]
    } else {
        &e.link
    };
    let size = e.data_len();
    let checks: [(&str, bool, Vec<u8>); 3] = [
        ("size", size > octal_max(12), size.to_string().into_bytes()),
        ("uid", e.uid > octal_max(8), e.uid.to_string().into_bytes()),
        ("gid", e.gid > octal_max(8), e.gid.to_string().into_bytes()),
    ];
    for (key, over, value) in checks {
        if over {
            if ustar {
                return Err(FormatError::TooLong(key));
            }
            record(&mut pax, key, &value);
        }
    }
    let time_over = e.mtime < 0 || e.mtime as u64 > octal_max(12);
    if time_over || all {
        if ustar && time_over {
            return Err(FormatError::TooLong("mtime"));
        }
        let v = if e.mtime_nsec != 0 && all {
            let (s, ns) =
                if e.mtime < 0 { (e.mtime + 1, 1_000_000_000 - e.mtime_nsec) } else { (e.mtime, e.mtime_nsec) };
            let sign = if e.mtime < 0 && s == 0 { "-" } else { "" };
            format!("{sign}{s}.{ns:09}")
        } else {
            e.mtime.to_string()
        };
        let v = if v.contains('.') { v.trim_end_matches('0').trim_end_matches('.') } else { &v };
        record(&mut pax, "mtime", v.as_bytes());
    }
    for (key, v) in [("uname", &e.uname), ("gname", &e.gname)] {
        if v.len() > 32 {
            if ustar {
                return Err(FormatError::TooLong(key));
            }
            record(&mut pax, key, v);
        }
    }
    let mut out = Vec::with_capacity(BLOCK * 2);
    if !pax.is_empty() {
        // The pax header's own name: ./PaxHeaders/<the member's last component>.
        let base = e.path.rsplit(|&b| b == b'/').find(|c| !c.is_empty()).unwrap_or(b"");
        let mut pname = b"./PaxHeaders/".to_vec();
        pname.extend_from_slice(&base[..base.len().min(100 - pname.len())]);
        let mut pe = Entry::new(pname.clone(), Kind::Other(b'x'));
        pe.mtime = e.mtime.clamp(0, octal_max(12) as i64);
        pe.uid = e.uid.min(octal_max(8));
        pe.gid = e.gid.min(octal_max(8));
        out.extend_from_slice(&ustar_block(&pname, b"", &pe, b'x', pax.len() as u64, b""));
        let n = pax.len();
        out.extend_from_slice(&pax);
        out.resize(out.len() + (BLOCK - n % BLOCK) % BLOCK, 0);
    }
    out.extend_from_slice(&ustar_block(name, prefix, e, e.kind.flag(), size, link));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(e: &Entry, fmt: Format) -> Entry {
        let b = encode(e, fmt).unwrap();
        let mut pax = Pax::default();
        let mut at = 0;
        loop {
            let blk: &[u8; BLOCK] = b[at..at + BLOCK].try_into().unwrap();
            at += BLOCK;
            match parse(blk).unwrap() {
                Block::Meta { size, .. } => {
                    pax.parse(&b[at..at + size as usize]).unwrap();
                    at += (size as usize).div_ceil(BLOCK) * BLOCK;
                }
                Block::Member(mut m) => {
                    pax.apply(&mut m);
                    return m;
                }
                Block::Zero => panic!("zero"),
            }
        }
    }

    #[test]
    fn round_trips() {
        let mut e = Entry::new(b"a/b".to_vec(), Kind::File);
        e.size = 5;
        e.mtime = 1_700_000_000;
        e.uname = b"root".to_vec();
        assert_eq!(round(&e, Format::Restricted), e);
        let long = [b"d/".repeat(200), b"file".to_vec()].concat();
        e.path = long.clone();
        assert_eq!(round(&e, Format::Restricted), e);
        assert!(encode(&e, Format::Ustar).is_err());
        e.path = [b"p/".repeat(60), b"q".repeat(90)].concat();
        assert_eq!(encode(&e, Format::Ustar).unwrap().len(), BLOCK);
        e.size = 20 << 30;
        e.uid = 1 << 40;
        e.mtime = -12345;
        e.link = b"l".repeat(300);
        e.kind = Kind::Symlink;
        let mut want = e.clone();
        want.size = 0;
        assert_eq!(round(&e, Format::Restricted), want);
        e.kind = Kind::File;
        want = e.clone();
        assert_eq!(round(&e, Format::Restricted), want);
        e.kind = Kind::File;
        e.mtime = 5;
        e.mtime_nsec = 250_000_000;
        assert_eq!(round(&e, Format::Pax), e);
        e.mtime = -2;
        e.mtime_nsec = 750_000_000;
        assert_eq!(round(&e, Format::Pax), e);
    }

    #[test]
    fn numbers() {
        let mut h = [0u8; 12];
        for v in [0i64, 1, 0o77777777777, 0o100000000000, 1 << 62, -1, -(1 << 40)] {
            put_num(&mut h, 0, 12, v);
            assert_eq!(get_num(&h).unwrap(), v, "{v}");
        }
        assert_eq!(get_num(b"  0644 \0"), Ok(0o644));
        assert!(get_num(b"0689\0").is_err());
    }

    #[test]
    fn pax_records() {
        let mut v = Vec::new();
        record(&mut v, "path", b"x");
        assert_eq!(v, b"9 path=x\n");
        let mut v = Vec::new();
        record(&mut v, "path", &[b'a'; 92]);
        assert_eq!(v.len(), 102);
        assert!(v.starts_with(b"102 path="));
        let mut p = Pax::default();
        p.parse(&v).unwrap();
        assert_eq!(p.path.as_deref(), Some(&[b'a'; 92][..]));
        assert!(p.parse(b"99 path=x\n").is_err());
        assert!(p.parse(b"x").is_err());
        assert_eq!(pax_time(b"-1.25"), Some((-2, 750_000_000)));
    }
}
