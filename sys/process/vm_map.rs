//! A per-address-space map of the user mappings (OxideBSD-doc `VMMAP.md`), BSD `vm_map` in
//! shape: page-aligned, disjoint, non-empty entries keyed by start address, each with its
//! protection, maximum protection, inheritance and backing. The page tables are a cache of what
//! the map says; operations on a range split the entries at its ends first.
//!
//! This module is bookkeeping only: it never touches a page table or a frame. Callers do that
//! for the pieces it hands back (`remove`) or after it says yes (`protect`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub const PAGE: u64 = 4096;

pub const PROT_READ: u8 = 1;
pub const PROT_WRITE: u8 = 2;
pub const PROT_EXEC: u8 = 4;
pub const PROT_ALL: u8 = PROT_READ | PROT_WRITE | PROT_EXEC;

/// What an entry's pages come from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmKind {
    /// Zero-filled memory (`mmap(MAP_ANON)`).
    Anon,
    /// A file, from page `page` of it: `content` is the kernel's identity for the file's
    /// contents (its vnode). From file page `eof_page` on, the file ended when it was mapped: a
    /// touch there is `SIGBUS` (POSIX), not `SIGSEGV`.
    File { content: u64, page: u64, eof_page: u64 },
    /// Device memory (`/dev/fb0`), never RAM.
    Phys,
    /// A SysV shared memory segment.
    Shm { shmid: i32 },
    /// The main thread's stack, growing down.
    Stack,
    /// The program break.
    Heap,
    /// A `PT_LOAD` segment of the program or its interpreter, from page `page` of the file.
    Text { content: u64, page: u64 },
    /// The kernel's own pages in the user range (the fault trampoline and its scratch page):
    /// never unmapped, counted or listed.
    Kernel,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VmEntry {
    pub end: u64,
    pub prot: u8,
    pub max_prot: u8,
    /// `MAP_SHARED`: fork shares it; otherwise fork copies it.
    pub shared: bool,
    pub kind: VmKind,
}

impl VmEntry {
    pub fn new(end: u64, prot: u8, max_prot: u8, shared: bool, kind: VmKind) -> Self {
        VmEntry { end, prot, max_prot, shared, kind }
    }

    /// The entry from `start` with its first `skip` bytes cut off: a file's page moves on.
    fn tail(&self, start: u64, at: u64) -> (u64, VmEntry) {
        let pages = (at - start) / PAGE;
        let kind = match self.kind {
            VmKind::File { content, page, eof_page } => VmKind::File { content, page: page + pages, eof_page },
            VmKind::Text { content, page } => VmKind::Text { content, page: page + pages },
            k => k,
        };
        (at, VmEntry { kind, ..*self })
    }
}

/// Why a range operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapError {
    /// The range overlaps an entry (`insert`) or includes an address no entry covers (`protect`).
    Overlap,
    Unmapped,
    /// `protect` asked for more than an entry's `max_prot`.
    Exceeds,
    /// Not page-aligned, empty, or wrapping.
    Invalid,
    /// The range touches a `Kernel` entry.
    Kernel,
}

#[derive(Clone, Default, Debug)]
pub struct VmMap {
    entries: BTreeMap<u64, VmEntry>,
    /// The sum of the entries' lengths, `Kernel` and `Stack` ones left out (the stack's entry is
    /// its whole reserve, grown or not): what `RLIMIT_AS` measures.
    size: u64,
    /// `(base, at)`: no page of `[base, at)` is free, so a search from `base` may start at `at`
    /// (`find_space`; without it, mapping n regions one after another costs n^2).
    cursor: (u64, u64),
}

fn check_range(start: u64, end: u64) -> Result<(), MapError> {
    if start % PAGE != 0 || end % PAGE != 0 || end <= start {
        return Err(MapError::Invalid);
    }
    Ok(())
}

fn counted(e: &VmEntry, start: u64) -> u64 {
    if matches!(e.kind, VmKind::Kernel | VmKind::Stack) { 0 } else { e.end - start }
}

impl VmMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &VmEntry)> {
        self.entries.iter().map(|(&s, e)| (s, e))
    }

    /// The entry containing `addr`.
    pub fn lookup(&self, addr: u64) -> Option<(u64, &VmEntry)> {
        let (&start, e) = self.entries.range(..=addr).next_back()?;
        (addr < e.end).then_some((start, e))
    }

    /// Whether any entry overlaps `[start, end)`.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        if let Some((_, e)) = self.entries.range(..start).next_back()
            && e.end > start
        {
            return true;
        }
        self.entries.range(start..end).next().is_some()
    }

    /// Whether every page of `[start, end)` is in some entry.
    pub fn covered(&self, start: u64, end: u64) -> bool {
        let mut at = start;
        while at < end {
            match self.lookup(at) {
                Some((_, e)) => at = e.end,
                None => return false,
            }
        }
        true
    }

    /// Adds an entry for `[start, entry.end)`, which must be free.
    pub fn insert(&mut self, start: u64, entry: VmEntry) -> Result<(), MapError> {
        check_range(start, entry.end)?;
        if self.overlaps(start, entry.end) {
            return Err(MapError::Overlap);
        }
        self.size += counted(&entry, start);
        self.entries.insert(start, entry);
        // The cursor moves over entries that start where it is.
        let (base, mut at) = self.cursor;
        while let Some(e) = self.entries.get(&at) {
            at = e.end;
        }
        self.cursor = (base, at);
        Ok(())
    }

    /// Splits the entry containing `at` (if any, and if `at` is inside it, not at its start) in
    /// two at `at`.
    fn split_at(&mut self, at: u64) {
        let Some((start, e)) = self.lookup(at).map(|(s, e)| (s, *e)) else { return };
        if start == at {
            return;
        }
        let (tail_start, tail) = e.tail(start, at);
        self.entries.get_mut(&start).unwrap().end = at;
        self.entries.insert(tail_start, tail);
    }

    /// Whether `[start, end)` touches a `Kernel` entry.
    fn touches_kernel(&self, start: u64, end: u64) -> bool {
        self.lookup(start).is_some_and(|(_, e)| e.kind == VmKind::Kernel)
            || self.entries.range(start..end).any(|(_, e)| e.kind == VmKind::Kernel)
    }

    /// Takes `[start, end)` out of the map, splitting the entries at its ends, and returns the
    /// pieces removed (start and entry each), for the caller to free what they held. Nothing
    /// mapped there is no error (`munmap`, POSIX).
    pub fn remove(&mut self, start: u64, end: u64) -> Result<Vec<(u64, VmEntry)>, MapError> {
        check_range(start, end)?;
        if self.touches_kernel(start, end) {
            return Err(MapError::Kernel);
        }
        self.split_at(start);
        self.split_at(end);
        let keys: Vec<u64> = self.entries.range(start..end).map(|(&s, _)| s).collect();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let e = self.entries.remove(&k).unwrap();
            self.size -= counted(&e, k);
            out.push((k, e));
        }
        self.freed(start);
        Ok(out)
    }

    /// Sets `prot` on `[start, end)`: `Unmapped` if some page isn't mapped, `Exceeds` past an
    /// entry's `max_prot`, the map unchanged in either case (`mprotect`, POSIX). Returns the
    /// pieces as they now are.
    pub fn protect(&mut self, start: u64, end: u64, prot: u8) -> Result<Vec<(u64, VmEntry)>, MapError> {
        check_range(start, end)?;
        if !self.covered(start, end) {
            return Err(MapError::Unmapped);
        }
        if self.touches_kernel(start, end) {
            return Err(MapError::Kernel);
        }
        let mut at = start;
        while at < end {
            let (s, e) = self.lookup(at).unwrap();
            if prot & !e.max_prot != 0 {
                return Err(MapError::Exceeds);
            }
            at = e.end.max(s + PAGE);
        }
        self.split_at(start);
        self.split_at(end);
        let mut out = Vec::new();
        for (&s, e) in self.entries.range_mut(start..end) {
            e.prot = prot;
            out.push((s, *e));
        }
        Ok(out)
    }

    /// Moves the end of the entry starting at `start` to `new_end` (the heap growing or
    /// shrinking): growing needs the space free; shrinking to `start` removes it.
    pub fn set_end(&mut self, start: u64, new_end: u64) -> Result<(), MapError> {
        let e = *self.entries.get(&start).ok_or(MapError::Unmapped)?;
        if new_end % PAGE != 0 || new_end < start {
            return Err(MapError::Invalid);
        }
        if new_end > e.end && self.overlaps(e.end, new_end) {
            return Err(MapError::Overlap);
        }
        self.size = self.size - counted(&e, start);
        self.freed(new_end);
        if new_end == start {
            self.entries.remove(&start);
            return Ok(());
        }
        let e = self.entries.get_mut(&start).unwrap();
        e.end = new_end;
        self.size += counted(e, start);
        Ok(())
    }

    /// Moves the start of the entry starting at `start` down to `new_start` (the stack growing),
    /// which must be free.
    pub fn set_start(&mut self, start: u64, new_start: u64) -> Result<(), MapError> {
        let e = *self.entries.get(&start).ok_or(MapError::Unmapped)?;
        if new_start % PAGE != 0 || new_start >= e.end {
            return Err(MapError::Invalid);
        }
        if new_start < start && self.overlaps(new_start, start) {
            return Err(MapError::Overlap);
        }
        self.entries.remove(&start);
        self.freed(start);
        self.size = self.size - counted(&e, start) + counted(&e, new_start);
        self.entries.insert(new_start, e);
        Ok(())
    }

    /// Space from `at` up was freed: the cursor can't be past it.
    fn freed(&mut self, at: u64) {
        let (base, cur) = self.cursor;
        if at < cur {
            self.cursor = (base, at.max(base));
        }
    }

    /// A free range of `len` bytes inside `[lo, hi)`: the first that fits at or above `hint`,
    /// else at or above `base`, else anywhere from `lo` (FreeBSD's `vm_map_find`, bottom-up).
    pub fn find_space(&self, len: u64, hint: u64, base: u64, lo: u64, hi: u64) -> Option<u64> {
        if len == 0 || len % PAGE != 0 {
            return None;
        }
        let first_fit = |from: u64| -> Option<u64> {
            let mut at = from.max(lo).next_multiple_of(PAGE);
            // An entry containing `at` pushes the start past it.
            if let Some((_, e)) = self.lookup(at) {
                at = e.end;
            }
            for (&s, e) in self.entries.range(at..) {
                if s >= hi {
                    break;
                }
                if s.checked_sub(at)? >= len {
                    return Some(at);
                }
                at = at.max(e.end);
            }
            (at.checked_add(len)? <= hi).then_some(at)
        };
        if hint != 0
            && let Some(a) = first_fit(hint)
        {
            return Some(a);
        }
        let from = if self.cursor.0 == base { self.cursor.1.max(base) } else { base };
        first_fit(from).or_else(|| first_fit(lo))
    }

    /// Searches from `base` start where the last ones left off (`cursor`); set when the base is
    /// chosen (exec).
    pub fn set_base(&mut self, base: u64) {
        self.cursor = (base, base);
        let mut at = base;
        if let Some((_, e)) = self.lookup(at) {
            at = e.end;
        }
        while let Some(e) = self.entries.get(&at) {
            at = e.end;
        }
        self.cursor = (base, at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: u8 = PROT_READ | PROT_WRITE;

    fn anon(end: u64) -> VmEntry {
        VmEntry::new(end, RW, PROT_ALL, false, VmKind::Anon)
    }

    fn pieces(m: &VmMap) -> Vec<(u64, u64, u8)> {
        m.iter().map(|(s, e)| (s, e.end, e.prot)).collect()
    }

    #[test]
    fn insert_and_lookup() {
        let mut m = VmMap::new();
        m.insert(0x10000, anon(0x14000)).unwrap();
        assert_eq!(m.size(), 0x4000);
        assert_eq!(m.lookup(0x13fff).map(|(s, _)| s), Some(0x10000));
        assert!(m.lookup(0x14000).is_none());
        assert!(m.lookup(0xffff).is_none());
        assert_eq!(m.insert(0x13000, anon(0x15000)), Err(MapError::Overlap));
        assert_eq!(m.insert(0xf000, anon(0x11000)), Err(MapError::Overlap));
        assert_eq!(m.insert(0x14001, anon(0x15000)), Err(MapError::Invalid));
        m.insert(0x14000, anon(0x15000)).unwrap();
        assert!(m.covered(0x10000, 0x15000));
        assert!(!m.covered(0x10000, 0x16000));
    }

    #[test]
    fn remove_splits() {
        let mut m = VmMap::new();
        m.insert(0x10000, anon(0x20000)).unwrap();
        let gone = m.remove(0x12000, 0x13000).unwrap();
        assert_eq!(gone, vec![(0x12000, anon(0x13000))]);
        assert_eq!(pieces(&m), vec![(0x10000, 0x12000, RW), (0x13000, 0x20000, RW)]);
        assert_eq!(m.size(), 0xf000);
        // Across a hole and two entries.
        let gone = m.remove(0x11000, 0x14000).unwrap();
        assert_eq!(gone.len(), 2);
        assert_eq!(pieces(&m), vec![(0x10000, 0x11000, RW), (0x14000, 0x20000, RW)]);
        // Nothing there: fine.
        assert!(m.remove(0x30000, 0x31000).unwrap().is_empty());
        assert_eq!(m.size(), 0xd000);
    }

    #[test]
    fn file_pages_follow_splits() {
        let mut m = VmMap::new();
        m.insert(0x10000, VmEntry::new(0x18000, PROT_READ, PROT_READ, false, VmKind::File { content: 7, page: 3, eof_page: 9 }))
            .unwrap();
        m.remove(0x12000, 0x13000).unwrap();
        let kinds: Vec<_> = m.iter().map(|(s, e)| (s, e.kind)).collect();
        assert_eq!(
            kinds,
            vec![(0x10000, VmKind::File { content: 7, page: 3, eof_page: 9 }), (0x13000, VmKind::File { content: 7, page: 6, eof_page: 9 })]
        );
    }

    #[test]
    fn protect() {
        let mut m = VmMap::new();
        m.insert(0x10000, anon(0x14000)).unwrap();
        m.insert(0x14000, VmEntry::new(0x16000, PROT_READ, PROT_READ, true, VmKind::File { content: 1, page: 0, eof_page: 2 }))
            .unwrap();
        assert_eq!(m.protect(0x10000, 0x17000, PROT_READ), Err(MapError::Unmapped));
        assert_eq!(m.protect(0x13000, 0x15000, RW), Err(MapError::Exceeds));
        assert_eq!(pieces(&m).len(), 2, "a refused protect changes nothing");
        m.protect(0x11000, 0x12000, PROT_READ).unwrap();
        assert_eq!(pieces(&m), vec![(0x10000, 0x11000, RW), (0x11000, 0x12000, PROT_READ), (0x12000, 0x14000, RW), (0x14000, 0x16000, PROT_READ)]);
        assert_eq!(m.size(), 0x6000);
    }

    #[test]
    fn kernel_entries() {
        let mut m = VmMap::new();
        m.insert(0x10000, VmEntry::new(0x12000, PROT_READ | PROT_EXEC, PROT_READ | PROT_EXEC, false, VmKind::Kernel))
            .unwrap();
        assert_eq!(m.size(), 0);
        assert_eq!(m.remove(0xf000, 0x11000), Err(MapError::Kernel));
        assert_eq!(m.protect(0x10000, 0x11000, PROT_READ), Err(MapError::Kernel));
        assert_eq!(pieces(&m).len(), 1);
    }

    #[test]
    fn heap_and_stack() {
        let mut m = VmMap::new();
        m.insert(0x20000, VmEntry::new(0x21000, RW, PROT_ALL, false, VmKind::Heap)).unwrap();
        m.set_end(0x20000, 0x25000).unwrap();
        assert_eq!(m.size(), 0x5000);
        m.insert(0x26000, anon(0x27000)).unwrap();
        assert_eq!(m.set_end(0x20000, 0x27000), Err(MapError::Overlap));
        m.set_end(0x20000, 0x20000).unwrap();
        assert!(m.lookup(0x20000).is_none());
        m.insert(0x50000, VmEntry::new(0x60000, RW, PROT_ALL, false, VmKind::Stack)).unwrap();
        m.set_start(0x50000, 0x4c000).unwrap();
        assert_eq!(m.lookup(0x4c000).map(|(s, e)| (s, e.end)), Some((0x4c000, 0x60000)));
        assert_eq!(m.set_start(0x4c000, 0x26000), Err(MapError::Overlap));
        assert_eq!(m.size(), 0x1000, "the stack isn't counted");
    }

    #[test]
    fn cursor_keeps_find_space_flat() {
        let mut m = VmMap::new();
        let (lo, hi) = (0x100000, 0x1_0000_0000);
        m.set_base(lo);
        for _ in 0..20000 {
            let a = m.find_space(0x1000, 0, lo, lo, hi).unwrap();
            m.insert(a, anon(a + 0x1000)).unwrap();
        }
        assert_eq!(m.find_space(0x1000, 0, lo, lo, hi), Some(lo + 20000 * 0x1000));
        // A hole low down is found again.
        m.remove(lo + 0x5000, lo + 0x6000).unwrap();
        assert_eq!(m.find_space(0x1000, 0, lo, lo, hi), Some(lo + 0x5000));
        m.insert(lo + 0x5000, anon(lo + 0x6000)).unwrap();
        assert_eq!(m.find_space(0x1000, 0, lo, lo, hi), Some(lo + 20000 * 0x1000));
    }

    #[test]
    fn find_space_first_fit() {
        let mut m = VmMap::new();
        let (lo, hi) = (0x100000, 0x200000);
        assert_eq!(m.find_space(0x2000, 0, 0x150000, lo, hi), Some(0x150000));
        m.insert(0x150000, anon(0x152000)).unwrap();
        m.insert(0x153000, anon(0x154000)).unwrap();
        // The one-page gap is too small; the next fit is past the second entry.
        assert_eq!(m.find_space(0x2000, 0, 0x150000, lo, hi), Some(0x154000));
        assert_eq!(m.find_space(0x1000, 0, 0x150000, lo, hi), Some(0x152000));
        // A free hint is used; a taken one moves on.
        assert_eq!(m.find_space(0x1000, 0x180000, 0x150000, lo, hi), Some(0x180000));
        assert_eq!(m.find_space(0x1000, 0x151000, 0x150000, lo, hi), Some(0x152000));
        // Nothing above the base fits: wrap to the bottom.
        m.insert(0x154000, anon(0x200000)).unwrap();
        assert_eq!(m.find_space(0x3000, 0, 0x150000, lo, hi), Some(0x100000));
        // Freed space is reused.
        m.remove(0x160000, 0x170000).unwrap();
        assert_eq!(m.find_space(0x10000, 0, 0x150000, lo, hi), Some(0x160000));
        // Full.
        m.insert(lo, anon(0x150000)).unwrap();
        assert_eq!(m.find_space(0x20000, 0, 0x150000, lo, hi), None);
    }
}
