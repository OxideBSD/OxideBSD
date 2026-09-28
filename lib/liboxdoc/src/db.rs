//! `oxdoc.db`, the index `makewhatis` writes and `apropos` reads (MAN.md §7.2). One file per
//! manual tree, read whole; all numbers little-endian `u32`:
//!
//! ```text
//! header    "OXDOCDB\0", version, pages (count, offset), keys (count, offset),
//!           postings (count, offset), strings (length, offset)
//! pages     file, section, arch, names, links (both NUL-separated), description: each a
//!           string
//! keys      class, value (a string), postings (first, count); sorted by class, then value
//! postings  page numbers
//! strings   UTF-8 text; a string is (offset, length) into it
//! ```
//!
//! A key is stored once with the list of pages it occurs in, which keeps the full-text words
//! (`Tx`, one per distinct word of a page) small.

use crate::keys::Page;
use std::collections::{BTreeMap, HashMap};

pub const MAGIC: &[u8; 8] = b"OXDOCDB\0";
pub const VERSION: u32 = 1;
const HEADER: usize = 8 + 4 * 9;
const PAGE_SIZE: usize = 6 * 8;
const KEY_SIZE: usize = 4 + 8 + 8;

/// Why a file isn't a readable index.
#[derive(Debug, PartialEq)]
pub enum Error {
    NotIndex,
    /// A version this program doesn't know (MAN.md §7.4): the file is ignored.
    Version(u32),
    Corrupt,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NotIndex => f.write_str("not an oxdoc.db file"),
            Error::Version(v) => write!(f, "unknown oxdoc.db version {v}, expected {VERSION}; run makewhatis"),
            Error::Corrupt => f.write_str("corrupt oxdoc.db file"),
        }
    }
}

struct Strings {
    bytes: Vec<u8>,
    seen: HashMap<String, (u32, u32)>,
}

impl Strings {
    fn put(&mut self, s: &str) -> (u32, u32) {
        if let Some(r) = self.seen.get(s) {
            return *r;
        }
        let r = (self.bytes.len() as u32, s.len() as u32);
        self.bytes.extend_from_slice(s.as_bytes());
        self.seen.insert(s.to_string(), r);
        r
    }
}

/// The index of `pages`, as bytes.
pub fn write(pages: &[Page]) -> Vec<u8> {
    let mut strings = Strings { bytes: Vec::new(), seen: HashMap::new() };
    let mut page_bytes = Vec::new();
    let mut postings_of: BTreeMap<(u8, &str), Vec<u32>> = BTreeMap::new();
    for (i, p) in pages.iter().enumerate() {
        for s in [p.file.as_str(), p.section.as_str(), p.arch.as_str(), p.names.join("\0").as_str(), p.links.join("\0").as_str(), p.desc.as_str()] {
            let (o, l) = strings.put(s);
            page_bytes.extend_from_slice(&o.to_le_bytes());
            page_bytes.extend_from_slice(&l.to_le_bytes());
        }
        for (c, v) in &p.keys {
            postings_of.entry((*c, v.as_str())).or_default().push(i as u32);
        }
    }
    let mut key_bytes = Vec::new();
    let mut postings: Vec<u32> = Vec::new();
    for ((c, v), list) in &postings_of {
        let (o, l) = strings.put(v);
        key_bytes.extend_from_slice(&(*c as u32).to_le_bytes());
        key_bytes.extend_from_slice(&o.to_le_bytes());
        key_bytes.extend_from_slice(&l.to_le_bytes());
        key_bytes.extend_from_slice(&(postings.len() as u32).to_le_bytes());
        key_bytes.extend_from_slice(&(list.len() as u32).to_le_bytes());
        postings.extend(list);
    }
    let pages_off = HEADER;
    let keys_off = pages_off + page_bytes.len();
    let post_off = keys_off + key_bytes.len();
    let str_off = post_off + postings.len() * 4;
    let mut out = Vec::with_capacity(str_off + strings.bytes.len());
    out.extend_from_slice(MAGIC);
    for v in [
        VERSION,
        pages.len() as u32,
        pages_off as u32,
        postings_of.len() as u32,
        keys_off as u32,
        postings.len() as u32,
        post_off as u32,
        strings.bytes.len() as u32,
        str_off as u32,
    ] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&page_bytes);
    out.extend_from_slice(&key_bytes);
    for p in postings {
        out.extend_from_slice(&p.to_le_bytes());
    }
    out.extend_from_slice(&strings.bytes);
    out
}

/// A read index.
pub struct Db {
    bytes: Vec<u8>,
    npages: usize,
    pages_off: usize,
    nkeys: usize,
    keys_off: usize,
    npost: usize,
    post_off: usize,
    str_len: usize,
    str_off: usize,
}

/// A page of the index, its strings borrowed from it.
#[derive(Clone, Debug)]
pub struct PageRef<'a> {
    pub file: &'a str,
    pub section: &'a str,
    pub arch: &'a str,
    pub names: Vec<&'a str>,
    pub links: Vec<&'a str>,
    pub desc: &'a str,
}

/// A key: its class and value, and the pages it occurs in.
pub struct KeyRef<'a> {
    pub class: u8,
    pub value: &'a str,
    pub pages: Vec<u32>,
}

/// A NUL-separated list.
fn list(s: &str) -> Vec<&str> {
    if s.is_empty() { Vec::new() } else { s.split('\0').collect() }
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
}

impl Db {
    pub fn read(bytes: Vec<u8>) -> Result<Db, Error> {
        if bytes.len() < HEADER || &bytes[..8] != MAGIC {
            return Err(Error::NotIndex);
        }
        let h = |i: usize| u32_at(&bytes, 8 + 4 * i).unwrap();
        if h(0) as u32 != VERSION {
            return Err(Error::Version(h(0) as u32));
        }
        let db = Db { npages: h(1), pages_off: h(2), nkeys: h(3), keys_off: h(4), npost: h(5), post_off: h(6), str_len: h(7), str_off: h(8), bytes };
        // Every table within the file.
        let fits = |off: usize, len: Option<usize>| len.and_then(|l| off.checked_add(l)).is_some_and(|end| end <= db.bytes.len());
        if !fits(db.pages_off, db.npages.checked_mul(PAGE_SIZE))
            || !fits(db.keys_off, db.nkeys.checked_mul(KEY_SIZE))
            || !fits(db.post_off, db.npost.checked_mul(4))
            || !fits(db.str_off, Some(db.str_len))
        {
            return Err(Error::Corrupt);
        }
        Ok(db)
    }

    fn str_at(&self, at: usize) -> &str {
        let (o, l) = (u32_at(&self.bytes, at).unwrap_or(0), u32_at(&self.bytes, at + 4).unwrap_or(0));
        let strings = &self.bytes[self.str_off..self.str_off + self.str_len];
        strings.get(o..o.saturating_add(l)).and_then(|b| std::str::from_utf8(b).ok()).unwrap_or("")
    }

    pub fn page_count(&self) -> usize {
        self.npages
    }

    pub fn page(&self, i: usize) -> PageRef<'_> {
        let at = self.pages_off + i * PAGE_SIZE;
        PageRef {
            file: self.str_at(at),
            section: self.str_at(at + 8),
            arch: self.str_at(at + 16),
            names: list(self.str_at(at + 24)),
            links: list(self.str_at(at + 32)),
            desc: self.str_at(at + 40),
        }
    }

    pub fn key_count(&self) -> usize {
        self.nkeys
    }

    pub fn key(&self, i: usize) -> KeyRef<'_> {
        let at = self.keys_off + i * KEY_SIZE;
        let class = u32_at(&self.bytes, at).unwrap_or(0) as u8;
        let first = u32_at(&self.bytes, at + 12).unwrap_or(0);
        let count = u32_at(&self.bytes, at + 16).unwrap_or(0);
        let pages = (first..(first + count).min(self.npost)).filter_map(|p| u32_at(&self.bytes, self.post_off + p * 4)).map(|p| p as u32).collect();
        KeyRef { class, value: self.str_at(at + 4), pages }
    }

    fn key_class(&self, i: usize) -> u8 {
        u32_at(&self.bytes, self.keys_off + i * KEY_SIZE).unwrap_or(0) as u8
    }

    /// The keys of `class`, as a range of key numbers (they are sorted by class).
    pub fn class_range(&self, class: u8) -> std::ops::Range<usize> {
        let lo = partition(self.nkeys, |i| self.key_class(i) < class);
        let hi = partition(self.nkeys, |i| self.key_class(i) <= class);
        lo..hi
    }
}

/// The first index in `0..n` for which `before` is false.
fn partition(n: usize, before: impl Fn(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if before(mid) { lo = mid + 1 } else { hi = mid }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pages = vec![
            Page { file: "man1/ls.1".into(), section: "1".into(), arch: String::new(), names: vec!["ls".into()], links: vec![], desc: "list directory contents".into(), keys: vec![(0, "ls".into()), (38, "list".into())] },
            Page { file: "man1/cp.1".into(), section: "1".into(), arch: String::new(), names: vec!["cp".into(), "copy".into()], links: vec!["copy".into()], desc: "copy files".into(), keys: vec![(0, "cp".into()), (38, "list".into())] },
        ];
        let db = Db::read(write(&pages)).unwrap();
        assert_eq!(db.page_count(), 2);
        assert_eq!(db.page(1).names, vec!["cp", "copy"]);
        assert_eq!(db.page(1).links, vec!["copy"]);
        assert_eq!(db.page(0).desc, "list directory contents");
        let r = db.class_range(38);
        assert_eq!(r.len(), 1);
        assert_eq!(db.key(r.start).value, "list");
        assert_eq!(db.key(r.start).pages, vec![0, 1]);
        assert_eq!(db.class_range(0).len(), 2);
        assert_eq!(Db::read(b"nonsense".to_vec()).err(), Some(Error::NotIndex));
        let mut bad = write(&pages);
        bad[8] = 9;
        assert_eq!(Db::read(bad).err(), Some(Error::Version(9)));
    }
}
