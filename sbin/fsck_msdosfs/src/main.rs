//! `fsck_msdosfs(8)`: checks and repairs a FAT12, FAT16 or FAT32 file system (OxideBSD-doc
//! `VFS.md` §9), with FreeBSD's flags. fsck(8) runs it for `msdosfs` lines of `/etc/fstab`.
//!
//! ```text
//! fsck_msdosfs [-CfnpyM] device
//! ```
//!
//! Phases, as FreeBSD's: (1) the boot sector and every copy of the FAT are read and compared,
//! and each entry is checked to name a cluster of the volume, the end of a chain, a bad cluster
//! or a free one; (2) the tree is walked from the root, each file and directory claiming its
//! cluster chain, so that a chain crossing another, looping, running past its size or stopping
//! short of it is found, and each directory's `.`, `..`, long-name entries and volume label are
//! checked; (3) the clusters nothing claimed are found, and each lost chain is saved as
//! `LOST.DIR/FILEnnnn.CHK` (`LOST.DIR` is made if missing); (4) the free cluster count and, on
//! FAT32, the FSInfo sector are corrected (FSInfo's count and next free cluster are hints other
//! systems don't keep exact either: corrected whenever the device is writable, never a failure). Then the volume is marked clean (FAT16 and FAT32 keep
//! a clean bit in FAT entry 1; FAT12 has none).
//!
//! An interrupted write can leave only some of these: FAT copies that differ, a chain one cluster
//! longer or shorter than its file, a chain that ends in a free cluster, lost clusters, long-name
//! entries without their short entry, a wrong free count, the clean bit clear. `-p` (preen)
//! repairs those without asking. Anything else (a chain crossing another or looping, an entry
//! naming no cluster of the volume, a broken `.` or `..`) means something worse: preen leaves it
//! with status 8 for `-y` (repair everything) or `-n` (report only, the device opened read-only).
//! Without `-p`, `-y` or `-n` only reporting is safe, as there's no one to ask. `-p` skips a
//! clean volume unless `-f`; `-C` skips a clean one in any mode. `-M` (FreeBSD: don't use
//! mmap(2)) is accepted and means nothing here.

use msdosfs_format::fat::Entry;
use msdosfs_format::*;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

/// Exit statuses, as fsck_oxfs's.
const EXIT_OK: u8 = 0;
const EXIT_UNRESOLVED: u8 = 8;
const EXIT_USAGE: u8 = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// `-p`: repair what a crash leaves without asking; leave anything worse.
    Preen,
    /// `-y`: repair everything.
    Yes,
    /// `-n`: report only.
    No,
}

/// Who claimed a cluster: nothing, a file or directory (its index in `Fsck::owners`), or a lost
/// chain being saved.
const UNCLAIMED: u32 = 0;
const LOST_OWNER: u32 = u32::MAX;

/// A directory to walk: its chain (empty: the FAT12/16 root's fixed area), and its path.
struct Dir {
    first: u32,
    parent: u32,
    path: String,
}

/// A directory's entries as read: the bytes, and where each 32-byte slot lives on the device.
struct DirData {
    bytes: Vec<u8>,
    offsets: Vec<u64>,
}

pub struct Fsck {
    dev: File,
    writable: bool,
    mode: Mode,
    bpb: Bpb,
    kind: FatType,
    bps: u64,
    cb: u64,
    /// The last cluster's number.
    max: u32,
    /// FAT copy 0 as on the device, and its entries decoded (edits go to `fat`; `raw` keeps
    /// FAT32's reserved bits when it's written back).
    raw: Vec<u8>,
    fat: Vec<u32>,
    fat_dirty: bool,
    claimed: Vec<u32>,
    owners: Vec<String>,
    /// Problems found, and the ones left unrepaired.
    found: u32,
    unresolved: u32,
    /// Hints corrected (FSInfo's): not inconsistencies, so they don't fail `-n`.
    noted: u32,
    files: u32,
    dirs: u32,
}

impl Fsck {
    /// Reports `what`; whether to repair it (`preen_ok`: a crash's leftovers, which `-p` repairs).
    fn problem(&mut self, what: &str, fix: &str, preen_ok: bool) -> bool {
        self.found += 1;
        println!("{what}");
        let yes = match self.mode {
            Mode::Yes => true,
            Mode::Preen => preen_ok,
            Mode::No => false,
        };
        if yes {
            println!("  {fix}{}", if self.mode == Mode::Preen { " (preen)" } else { "" });
        } else {
            self.unresolved += 1;
            if self.mode == Mode::Preen {
                println!("  UNEXPECTED INCONSISTENCY; RUN fsck_msdosfs MANUALLY.");
            } else {
                println!("  {fix}? no");
            }
        }
        yes
    }

    /// Reports a wrong hint; whether to correct it (whenever the device is writable).
    fn note(&mut self, what: &str) -> bool {
        println!("{what}");
        if self.writable {
            println!("  FIXED");
            self.noted += 1;
        }
        self.writable
    }

    fn at_sector(&self, sector: u64) -> u64 {
        sector * self.bps
    }

    fn cluster_at(&self, c: u32) -> u64 {
        self.at_sector(self.bpb.cluster_sector(c) as u64)
    }

    fn read(&self, buf: &mut [u8], at: u64) -> Result<(), String> {
        self.dev.read_exact_at(buf, at).map_err(|e| format!("read at byte {at}: {e}"))
    }

    fn write(&self, buf: &[u8], at: u64) -> Result<(), String> {
        assert!(self.writable);
        self.dev.write_all_at(buf, at).map_err(|e| format!("write at byte {at}: {e}"))
    }

    fn entry(&self, c: u32) -> Entry {
        self.kind.classify(self.fat[c as usize], self.max)
    }

    fn set(&mut self, c: u32, v: u32) {
        self.fat[c as usize] = v;
        self.fat_dirty = true;
    }

    // --- Phase 1 ------------------------------------------------------------------------------

    fn read_fats(&mut self) -> Result<(), String> {
        let len = self.bpb.fat_sectors as usize * self.bps as usize;
        let mut raw = vec![0u8; len];
        self.read(&mut raw, self.at_sector(self.bpb.fat_start() as u64))?;
        let entries = self.max as usize + 1;
        let used = self.kind.fat_bytes(entries as u32) as usize;
        let mut differ = Vec::new();
        for copy in 1..self.bpb.fats as u64 {
            let mut other = vec![0u8; len];
            self.read(&mut other, self.at_sector(self.bpb.fat_start() as u64 + copy * self.bpb.fat_sectors as u64))?;
            if other[..used] != raw[..used] {
                differ.push(copy);
            }
        }
        self.fat = (0..entries as u32).map(|c| fat::get(self.kind, c, &raw[fat::entry_offset(self.kind, c)..])).collect();
        self.raw = raw;
        for copy in differ {
            if self.problem(&format!("FAT {copy} differs from FAT 0"), "COPIED FROM FAT 0", true) {
                self.fat_dirty = true;
            }
        }
        if self.fat[0] & 0xFF != self.bpb.media as u32 {
            let what = format!("FAT 0's media byte {:#x} isn't the boot sector's {:#x}", self.fat[0] & 0xFF, self.bpb.media);
            if self.problem(&what, "FIXED", true) {
                let v = fat::entry0(self.kind, self.bpb.media);
                self.set(0, v);
            }
        }
        // Each entry names a cluster of the volume, the end of a chain, a bad cluster, or none.
        for c in FIRST_CLUSTER..=self.max {
            match self.entry(c) {
                Entry::Reserved => {
                    let what = format!("cluster {c} continues with out-of-range cluster {:#x}", self.fat[c as usize]);
                    if self.problem(&what, "TRUNCATED", false) {
                        let eoc = self.kind.eoc();
                        self.set(c, eoc);
                    }
                }
                Entry::Next(n) if self.entry(n) == Entry::Free => {
                    if self.problem(&format!("cluster {c} continues with free cluster {n}"), "TRUNCATED", true) {
                        let eoc = self.kind.eoc();
                        self.set(c, eoc);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // --- Phase 2 ------------------------------------------------------------------------------

    /// Claims the chain from `first` for `owner`, stopping where it crosses another file, loops,
    /// or meets an entry that can't continue a chain; returns its clusters.
    fn claim(&mut self, first: u32, owner: u32, path: &str) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut c = first;
        loop {
            let holder = self.claimed[c as usize];
            if holder != UNCLAIMED {
                let other = if holder == owner {
                    "itself (a loop)".to_string()
                } else if holder == LOST_OWNER {
                    "a lost chain".to_string()
                } else {
                    self.owners[holder as usize - 1].clone()
                };
                let prev = *chain.last().unwrap();
                if self.problem(&format!("{path}: cluster chain crosses {other} at cluster {c}"), "TRUNCATED", false) {
                    let eoc = self.kind.eoc();
                    self.set(prev, eoc);
                }
                return chain;
            }
            self.claimed[c as usize] = owner;
            chain.push(c);
            match self.entry(c) {
                Entry::Next(n) => c = n,
                // Phase 1 truncated or reported every other case.
                _ => return chain,
            }
        }
    }

    /// Frees the chain from `first` (clusters no one else claimed).
    fn free_chain(&mut self, first: u32) {
        let mut c = first;
        let mut steps = 0;
        while (FIRST_CLUSTER..=self.max).contains(&c) && steps <= self.max {
            let next = self.fat[c as usize];
            if self.claimed[c as usize] != UNCLAIMED {
                break;
            }
            self.set(c, 0);
            match self.kind.classify(next, self.max) {
                Entry::Next(n) => c = n,
                _ => break,
            }
            steps += 1;
        }
    }

    fn read_dir(&self, chain: &[u32], fixed_root: bool) -> Result<DirData, String> {
        let mut d = DirData { bytes: Vec::new(), offsets: Vec::new() };
        if fixed_root {
            let start = self.at_sector((self.bpb.fat_start() + self.bpb.fats as u32 * self.bpb.fat_sectors) as u64);
            d.bytes = vec![0u8; self.bpb.root_entries as usize * DIR_ENTRY_SIZE];
            self.read(&mut d.bytes, start)?;
            d.offsets = (0..self.bpb.root_entries as u64).map(|i| start + i * DIR_ENTRY_SIZE as u64).collect();
        } else {
            for &c in chain {
                let at = self.cluster_at(c);
                let mut buf = vec![0u8; self.cb as usize];
                self.read(&mut buf, at)?;
                d.bytes.extend_from_slice(&buf);
                d.offsets.extend((0..self.cb / DIR_ENTRY_SIZE as u64).map(|i| at + i * DIR_ENTRY_SIZE as u64));
            }
        }
        Ok(d)
    }

    fn put_slot(&self, d: &mut DirData, slot: usize, f: impl FnOnce(&mut [u8])) -> Result<(), String> {
        let b = &mut d.bytes[slot * DIR_ENTRY_SIZE..(slot + 1) * DIR_ENTRY_SIZE];
        f(b);
        if self.writable {
            self.write(b, d.offsets[slot])?;
        }
        Ok(())
    }

    /// Checks directory `dir` and returns the subdirectories to walk, with their owner ids.
    fn check_dir(&mut self, dir: &Dir, owner: u32) -> Result<Vec<(Dir, u32)>, String> {
        let fixed_root = dir.first == 0;
        let chain = if fixed_root { Vec::new() } else { self.claim(dir.first, owner, &dir.path) };
        let mut d = self.read_dir(&chain, fixed_root)?;
        let is_root = dir.path == "/";
        let slots = d.offsets.len();
        let mut subdirs = Vec::new();
        // Long-name entries seen since the last short one: their slots, and what they expect.
        let mut lfn: Vec<usize> = Vec::new();
        let mut lfn_next = 0u8;
        let mut lfn_sum = 0u8;
        let mut name_units: Vec<u16> = Vec::new();
        for slot in 0..slots {
            let b = &d.bytes[slot * DIR_ENTRY_SIZE..(slot + 1) * DIR_ENTRY_SIZE];
            if b[0] == ENTRY_END {
                break;
            }
            if b[0] == ENTRY_FREE {
                self.orphan_lfn(&mut d, &mut lfn, &dir.path)?;
                continue;
            }
            if DirEntry::is_long_name(b) {
                let mut units = [0u16; LFN_CHARS];
                let (seq, last, sum) = read_lfn_entry(b, &mut units);
                if last {
                    self.orphan_lfn(&mut d, &mut lfn, &dir.path)?;
                    lfn_next = seq;
                    lfn_sum = sum;
                    name_units.clear();
                }
                if seq == 0 || seq != lfn_next || sum != lfn_sum || (!last && lfn.is_empty()) {
                    lfn.push(slot);
                    self.orphan_lfn(&mut d, &mut lfn, &dir.path)?;
                    lfn_next = 0;
                    continue;
                }
                lfn.push(slot);
                lfn_next -= 1;
                let mut chunk: Vec<u16> = units.iter().copied().take_while(|&u| u != 0).collect();
                chunk.extend(core::mem::take(&mut name_units));
                name_units = chunk;
                continue;
            }
            let e = DirEntry::read(b);
            // The long name belongs to this entry only if complete and its checksum matches.
            let long = if !lfn.is_empty() && lfn_next == 0 && lfn_sum == short_name_checksum(&e.name) {
                lfn.clear();
                Some(String::from_utf16_lossy(&name_units))
            } else {
                self.orphan_lfn(&mut d, &mut lfn, &dir.path)?;
                None
            };
            if e.attr & ATTR_VOLUME_ID != 0 {
                if !is_root && self.problem(&format!("{}: a volume label outside the root directory", dir.path), "REMOVED", false) {
                    self.put_slot(&mut d, slot, |b| b[0] = ENTRY_FREE)?;
                }
                continue;
            }
            let mut text = [0u8; 48];
            let n = short_name_text(&e.name, e.nt_case, &codepage::Codepage::Cp437, &mut text);
            let short = String::from_utf8_lossy(&text[..n]).into_owned();
            let name = long.unwrap_or(short);
            let path = if is_root { format!("/{name}") } else { format!("{}/{name}", dir.path) };
            if &e.name == b".          " || &e.name == b"..         " {
                self.check_dot(&mut d, slot, &e, dir, is_root)?;
                continue;
            }
            if e.name[..].iter().any(|&c| c < 0x20 && c != 0x05) {
                println!("{path}: a name with control characters (left as it is)");
            }
            if e.attr & ATTR_DIRECTORY != 0 {
                self.dirs += 1;
                if e.cluster < FIRST_CLUSTER || e.cluster > self.max || matches!(self.entry(e.cluster), Entry::Free | Entry::Bad | Entry::Reserved) || self.claimed[e.cluster as usize] != UNCLAIMED {
                    let what = format!("{path}: directory with an invalid or shared first cluster {}", e.cluster);
                    if self.problem(&what, "REMOVED", false) {
                        self.put_slot(&mut d, slot, |b| b[0] = ENTRY_FREE)?;
                    }
                    continue;
                }
                if e.size != 0 && self.problem(&format!("{path}: directory with size {}", e.size), "FIXED", true) {
                    self.put_slot(&mut d, slot, |b| b[28..32].fill(0))?;
                }
                self.owners.push(path.clone());
                subdirs.push((Dir { first: e.cluster, parent: if is_root { 0 } else { dir.first }, path }, self.owners.len() as u32));
                continue;
            }
            self.files += 1;
            self.check_file(&mut d, slot, &e, &path)?;
        }
        self.orphan_lfn(&mut d, &mut lfn, &dir.path)?;
        // Each claims its chain when walked.
        Ok(subdirs)
    }

    /// Long-name entries `lfn` that no short entry took: cleared.
    fn orphan_lfn(&mut self, d: &mut DirData, lfn: &mut Vec<usize>, path: &str) -> Result<(), String> {
        if lfn.is_empty() {
            return Ok(());
        }
        let what = format!("{path}: {} long-name entr{} without a short entry", lfn.len(), if lfn.len() == 1 { "y" } else { "ies" });
        if self.problem(&what, "CLEARED", true) {
            for &s in lfn.iter() {
                self.put_slot(d, s, |b| b[0] = ENTRY_FREE)?;
            }
        }
        lfn.clear();
        Ok(())
    }

    fn check_dot(&mut self, d: &mut DirData, slot: usize, e: &DirEntry, dir: &Dir, is_root: bool) -> Result<(), String> {
        let dot = e.name[1] == b' ';
        if is_root {
            if self.problem(&format!("/: a `{}' entry in the root directory", if dot { "." } else { ".." }), "REMOVED", false) {
                self.put_slot(d, slot, |b| b[0] = ENTRY_FREE)?;
            }
            return Ok(());
        }
        let (want_slot, want) = if dot { (0, dir.first) } else { (1, dir.parent) };
        if slot != want_slot {
            if self.problem(&format!("{}: `{}' out of place", dir.path, if dot { "." } else { ".." }), "REMOVED", false) {
                self.put_slot(d, slot, |b| b[0] = ENTRY_FREE)?;
            }
            return Ok(());
        }
        // FAT32 lets `..` name the root by its cluster as well as by 0.
        let ok = e.cluster == want || (!dot && want == 0 && self.kind == FatType::Fat32 && e.cluster == self.bpb.root_cluster);
        if !ok {
            let what = format!("{}: `{}' names cluster {}, not {want}", dir.path, if dot { "." } else { ".." }, e.cluster);
            if self.problem(&what, "FIXED", false) {
                self.put_slot(d, slot, |b| {
                    b[20..22].copy_from_slice(&((want >> 16) as u16).to_le_bytes());
                    b[26..28].copy_from_slice(&(want as u16).to_le_bytes());
                })?;
            }
        }
        Ok(())
    }

    fn check_file(&mut self, d: &mut DirData, slot: usize, e: &DirEntry, path: &str) -> Result<(), String> {
        let set_entry = |this: &Self, d: &mut DirData, cluster: u32, size: u32| {
            this.put_slot(d, slot, |b| {
                b[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
                b[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
                b[28..32].copy_from_slice(&size.to_le_bytes());
            })
        };
        if e.cluster == 0 {
            if e.size != 0 && self.problem(&format!("{path}: size {} but no clusters", e.size), "TRUNCATED", true) {
                set_entry(self, d, 0, 0)?;
            }
            return Ok(());
        }
        if e.cluster < FIRST_CLUSTER || e.cluster > self.max || matches!(self.entry(e.cluster), Entry::Free | Entry::Bad | Entry::Reserved) {
            if self.problem(&format!("{path}: invalid first cluster {}", e.cluster), "TRUNCATED", false) {
                set_entry(self, d, 0, 0)?;
            }
            return Ok(());
        }
        if self.claimed[e.cluster as usize] != UNCLAIMED {
            let holder = self.claimed[e.cluster as usize];
            let other = if holder == LOST_OWNER { "a lost chain".into() } else { self.owners[holder as usize - 1].clone() };
            if self.problem(&format!("{path}: starts in {other}'s clusters, at {}", e.cluster), "TRUNCATED", false) {
                set_entry(self, d, 0, 0)?;
            }
            return Ok(());
        }
        self.owners.push(path.to_string());
        let owner = self.owners.len() as u32;
        let chain = self.claim(e.cluster, owner, path);
        let need = (e.size as u64).div_ceil(self.cb) as usize;
        let have = chain.len();
        if need < have {
            let what = format!("{path}: {have} clusters for {} bytes", e.size);
            if self.problem(&what, "TRUNCATED", true) {
                if need == 0 {
                    for &c in &chain {
                        self.claimed[c as usize] = UNCLAIMED;
                    }
                    self.free_chain(chain[0]);
                    set_entry(self, d, 0, 0)?;
                } else {
                    let eoc = self.kind.eoc();
                    for &c in &chain[need..] {
                        self.claimed[c as usize] = UNCLAIMED;
                    }
                    let rest = self.fat[chain[need - 1] as usize];
                    self.set(chain[need - 1], eoc);
                    if let Entry::Next(n) = self.kind.classify(rest, self.max) {
                        self.free_chain(n);
                    }
                }
            }
        } else if need > have {
            let size = (have as u64 * self.cb).min(u32::MAX as u64) as u32;
            let what = format!("{path}: size {} past the end of its {have} clusters", e.size);
            if self.problem(&what, "TRUNCATED", true) {
                set_entry(self, d, e.cluster, size)?;
            }
        }
        Ok(())
    }

    // --- Phase 3 ------------------------------------------------------------------------------

    fn lost(&mut self) -> Result<(), String> {
        let lost: Vec<u32> = (FIRST_CLUSTER..=self.max)
            .filter(|&c| self.claimed[c as usize] == UNCLAIMED && !matches!(self.entry(c), Entry::Free | Entry::Bad))
            .collect();
        if lost.is_empty() {
            return Ok(());
        }
        // A chain's head: a lost cluster no other lost cluster leads to.
        let mut pointed = vec![false; self.max as usize + 1];
        for &c in &lost {
            if let Entry::Next(n) = self.entry(c) {
                pointed[n as usize] = true;
            }
        }
        let heads: Vec<u32> = lost.iter().copied().filter(|&c| !pointed[c as usize]).collect();
        let mut saved = 0u32;
        let mut lost_dir: Option<(u32, Vec<u32>)> = None;
        for head in heads {
            let chain = self.claim(head, LOST_OWNER, "a lost chain");
            let what = format!("lost cluster chain at cluster {head}: {} cluster{}", chain.len(), if chain.len() == 1 { "" } else { "s" });
            if !self.problem(&what, "RECONNECTED", true) {
                continue;
            }
            if lost_dir.is_none() {
                lost_dir = Some(self.lost_dir()?);
            }
            let (dir_first, _) = lost_dir.as_ref().unwrap();
            let dir_first = *dir_first;
            let size = (chain.len() as u64 * self.cb).min(u32::MAX as u64) as u32;
            loop {
                let name = format!("FILE{saved:04}CHK");
                saved += 1;
                let mut short = [b' '; 11];
                short.copy_from_slice(name.as_bytes());
                match self.add_entry(dir_first, short, 0, head, size)? {
                    Added::Yes => break,
                    Added::Exists => continue,
                }
            }
        }
        // What's still lost is a loop with no head: freed.
        let left: Vec<u32> = (FIRST_CLUSTER..=self.max)
            .filter(|&c| self.claimed[c as usize] == UNCLAIMED && !matches!(self.entry(c), Entry::Free | Entry::Bad))
            .collect();
        if !left.is_empty() && self.problem(&format!("{} lost clusters in loops", left.len()), "FREED", true) {
            for c in left {
                self.set(c, 0);
            }
        }
        Ok(())
    }

    /// `LOST.DIR` in the root: found, or made.
    fn lost_dir(&mut self) -> Result<(u32, Vec<u32>), String> {
        let root_first = if self.kind == FatType::Fat32 { self.bpb.root_cluster } else { 0 };
        let root = self.dir_chain(root_first);
        let d = self.read_dir(&root, root_first == 0)?;
        for slot in 0..d.offsets.len() {
            let b = &d.bytes[slot * DIR_ENTRY_SIZE..(slot + 1) * DIR_ENTRY_SIZE];
            if b[0] == ENTRY_END {
                break;
            }
            if &b[0..11] == b"LOST    DIR" && b[11] & ATTR_DIRECTORY != 0 {
                let e = DirEntry::read(b);
                return Ok((e.cluster, self.dir_chain(e.cluster)));
            }
        }
        let c = self.alloc().ok_or("no free cluster for LOST.DIR")?;
        let mut data = vec![0u8; self.cb as usize];
        let now = DosTime::from_unix(now());
        let dot = |name: &[u8; 11], cluster: u32| DirEntry { name: *name, attr: ATTR_DIRECTORY, created: now, modified: now, accessed_date: now.date, cluster, ..DirEntry::default() };
        dot(b".          ", c).write(&mut data[0..]);
        dot(b"..         ", 0).write(&mut data[DIR_ENTRY_SIZE..]);
        self.write(&data, self.cluster_at(c))?;
        if let Added::Exists = self.add_entry(root_first, *b"LOST    DIR", ATTR_DIRECTORY, c, 0)? {
            return Err("LOST.DIR exists but isn't a directory".into());
        }
        println!("  (made LOST.DIR)");
        Ok((c, vec![c]))
    }

    fn dir_chain(&self, first: u32) -> Vec<u32> {
        let mut chain = Vec::new();
        let mut c = first;
        while (FIRST_CLUSTER..=self.max).contains(&c) && chain.len() <= self.max as usize {
            chain.push(c);
            match self.entry(c) {
                Entry::Next(n) => c = n,
                _ => break,
            }
        }
        chain
    }

    fn alloc(&mut self) -> Option<u32> {
        let c = (FIRST_CLUSTER..=self.max).find(|&c| self.fat[c as usize] == 0)?;
        let eoc = self.kind.eoc();
        self.set(c, eoc);
        self.claimed[c as usize] = LOST_OWNER;
        Some(c)
    }

    /// Adds a short entry to directory `first` (0: the fixed root), growing it by a cluster if
    /// it's full (not the fixed root).
    fn add_entry(&mut self, first: u32, name: [u8; 11], attr: u8, cluster: u32, size: u32) -> Result<Added, String> {
        let chain = self.dir_chain(first);
        let mut d = self.read_dir(&chain, first == 0)?;
        let mut free = None;
        for slot in 0..d.offsets.len() {
            let b = &d.bytes[slot * DIR_ENTRY_SIZE..(slot + 1) * DIR_ENTRY_SIZE];
            if b[0] == ENTRY_END || b[0] == ENTRY_FREE {
                free.get_or_insert(slot);
                if b[0] == ENTRY_END {
                    break;
                }
                continue;
            }
            if b[0..11] == name {
                return Ok(Added::Exists);
            }
        }
        let now = DosTime::from_unix(now());
        let e = DirEntry { name, attr, created: now, modified: now, accessed_date: now.date, cluster, size, ..DirEntry::default() };
        let slot = match free {
            Some(s) => s,
            None => {
                if first == 0 {
                    return Err("the root directory is full".into());
                }
                let c = self.alloc().ok_or("no free cluster to grow a directory")?;
                let last = *chain.last().unwrap();
                self.set(last, c);
                self.write(&vec![0u8; self.cb as usize], self.cluster_at(c))?;
                d.bytes.extend(vec![0u8; self.cb as usize]);
                let at = self.cluster_at(c);
                d.offsets.extend((0..self.cb / DIR_ENTRY_SIZE as u64).map(|i| at + i * DIR_ENTRY_SIZE as u64));
                d.offsets.len() - (self.cb / DIR_ENTRY_SIZE as u64) as usize
            }
        };
        self.put_slot(&mut d, slot, |b| e.write(b))?;
        Ok(Added::Yes)
    }

    // --- Phase 4 ------------------------------------------------------------------------------

    fn free_space(&mut self) -> Result<u32, String> {
        let free = (FIRST_CLUSTER..=self.max).filter(|&c| self.fat[c as usize] == 0).count() as u32;
        if self.kind != FatType::Fat32 || self.bpb.fsinfo_sector == 0 || self.bpb.fsinfo_sector == 0xFFFF {
            return Ok(free);
        }
        let at = self.at_sector(self.bpb.fsinfo_sector as u64);
        let mut s = vec![0u8; self.bps as usize];
        self.read(&mut s, at)?;
        let u32_at = |s: &[u8], o: usize| u32::from_le_bytes(s[o..o + 4].try_into().unwrap());
        let sig_ok = u32_at(&s, 0) == FSINFO_LEAD_SIG && u32_at(&s, 484) == FSINFO_STRUC_SIG && u32_at(&s, 508) == FSINFO_TRAIL_SIG;
        let first_free = (FIRST_CLUSTER..=self.max).find(|&c| self.fat[c as usize] == 0).unwrap_or(FIRST_CLUSTER);
        let (count, next) = (u32_at(&s, 488), u32_at(&s, 492));
        let next_ok = next == FSINFO_UNKNOWN || ((FIRST_CLUSTER..=self.max).contains(&next));
        let what = if !sig_ok {
            Some("the FSInfo sector has no signature".to_string())
        } else if count != free && count != FSINFO_UNKNOWN {
            Some(format!("free cluster count in FSInfo is {count}, not {free}"))
        } else if !next_ok {
            Some(format!("next free cluster in FSInfo is {next}, past the end"))
        } else {
            None
        };
        if let Some(what) = what {
            if self.note(&what) {
                write_fsinfo(&mut s, free, first_free);
                self.write(&s, at)?;
            }
        }
        Ok(free)
    }

    fn write_fats(&mut self) -> Result<(), String> {
        for c in 0..=self.max {
            let off = fat::entry_offset(self.kind, c);
            fat::set(self.kind, c, &mut self.raw[off..], self.fat[c as usize]);
        }
        for copy in 0..self.bpb.fats as u64 {
            self.write(&self.raw, self.at_sector(self.bpb.fat_start() as u64 + copy * self.bpb.fat_sectors as u64))?;
        }
        Ok(())
    }
}

enum Added {
    Yes,
    Exists,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Checks `device`; the exit status.
pub fn check(device: &str, mode: Mode, force: bool, skip_clean: bool) -> Result<u8, String> {
    let writable = mode != Mode::No;
    let dev = match OpenOptions::new().read(true).write(writable).open(device) {
        Ok(dev) => dev,
        // The kernel refuses to write a mounted read-write file system's device; preen leaves it
        // be, as fsck_ffs -p does a mounted file system.
        Err(e) if mode == Mode::Preen && e.kind() == std::io::ErrorKind::PermissionDenied => {
            println!("{device}: mounted read-write; not checked");
            return Ok(EXIT_OK);
        }
        Err(e) => return Err(e.to_string()),
    };
    let mut boot = vec![0u8; 4096];
    let n = dev.read_at(&mut boot, 0).map_err(|e| format!("can't read the boot sector: {e}"))?;
    if n < 512 {
        return Err("can't read the boot sector".into());
    }
    let bpb = Bpb::read_boot_sector(&boot[..n.min(4096)]).map_err(|e| format!("not a FAT file system ({e:?})"))?;
    let kind = bpb.fat_type().map_err(|e| format!("{e:?}"))?;
    let max = bpb.clusters().map_err(|e| format!("{e:?}"))? + 1;
    let mut fs = Fsck {
        dev,
        writable,
        mode,
        bpb,
        kind,
        bps: bpb.bytes_per_sector as u64,
        cb: bpb.cluster_bytes() as u64,
        max,
        raw: Vec::new(),
        fat: Vec::new(),
        fat_dirty: false,
        claimed: vec![UNCLAIMED; max as usize + 1],
        owners: Vec::new(),
        found: 0,
        unresolved: 0,
        noted: 0,
        files: 0,
        dirs: 0,
    };
    // The clean bit, before anything else is read.
    let mut w = [0u8; 4];
    fs.read(&mut w[..kind.window()], fs.at_sector(bpb.fat_start() as u64) + fat::entry_offset(kind, 1) as u64)?;
    let entry1 = fat::get(kind, 1, &w);
    let clean = kind.clean_bit().is_some_and(|b| entry1 & b != 0);
    if clean && !force && (mode == Mode::Preen || skip_clean) {
        println!("{device}: clean");
        return Ok(EXIT_OK);
    }
    println!("** {device}{}", if writable { "" } else { " (NO WRITE)" });
    println!(
        "** FAT{}, {} clusters of {} bytes",
        match kind {
            FatType::Fat12 => 12,
            FatType::Fat16 => 16,
            FatType::Fat32 => 32,
        },
        max - 1,
        fs.cb
    );
    if kind == FatType::Fat32 && bpb.backup_boot_sector != 0 && bpb.backup_boot_sector != 0xFFFF {
        let mut backup = vec![0u8; fs.bps as usize];
        fs.read(&mut backup, fs.at_sector(bpb.backup_boot_sector as u64))?;
        if backup[..90] != boot[..90] || backup[510..512] != boot[510..512] {
            if fs.problem("the backup boot sector differs from the boot sector", "COPIED", true) {
                fs.write(&boot[..fs.bps as usize], fs.at_sector(bpb.backup_boot_sector as u64))?;
            }
        }
    }

    println!("** Phase 1 - Read and Compare FATs");
    fs.read_fats()?;

    println!("** Phase 2 - Check Cluster Chains and Directories");
    let root = if kind == FatType::Fat32 {
        if !(FIRST_CLUSTER..=max).contains(&bpb.root_cluster) || matches!(fs.entry(bpb.root_cluster), Entry::Free | Entry::Bad | Entry::Reserved) {
            return Err(format!("the root directory's cluster {} is invalid; can't check further", bpb.root_cluster));
        }
        bpb.root_cluster
    } else {
        0
    };
    fs.owners.push("/".into());
    let mut queue = vec![(Dir { first: root, parent: 0, path: "/".into() }, 1u32)];
    while let Some((dir, owner)) = queue.pop() {
        queue.extend(fs.check_dir(&dir, owner)?);
    }

    println!("** Phase 3 - Check for Lost Files");
    fs.lost()?;

    println!("** Phase 4 - Check Free Space");
    if fs.writable && fs.unresolved == 0 {
        // Clean, and no disk errors known: entry 1's two flags.
        let mut e1 = fs.fat[1];
        if let Some(b) = kind.clean_bit() {
            e1 |= b;
        }
        if let Some(b) = kind.no_error_bit() {
            e1 |= b;
        }
        if e1 != fs.fat[1] {
            fs.set(1, e1);
        }
    }
    if fs.writable && fs.fat_dirty {
        fs.write_fats()?;
    }
    let free = fs.free_space()?;
    println!("{} files, {} directories, {} KiB free ({} clusters)", fs.files, fs.dirs, free as u64 * fs.cb / 1024, free);
    if fs.writable && (fs.found > fs.unresolved || fs.noted > 0) {
        fs.dev.sync_all().map_err(|e| e.to_string())?;
        println!("\n***** FILE SYSTEM WAS MODIFIED *****");
    }
    if fs.unresolved > 0 {
        return Ok(EXIT_UNRESOLVED);
    }
    if fs.found > 0 && mode == Mode::No {
        return Ok(EXIT_UNRESOLVED);
    }
    if !clean && mode == Mode::No && kind.clean_bit().is_some() {
        println!("{device}: not marked clean");
    }
    Ok(EXIT_OK)
}

fn usage() -> ExitCode {
    eprintln!("usage: fsck_msdosfs [-CfnpyM] device");
    ExitCode::from(EXIT_USAGE)
}

fn main() -> ExitCode {
    let (mut mode, mut force, mut skip_clean) = (Mode::Yes, false, false);
    let mut device = None;
    let mut answer_given = false;
    for arg in std::env::args().skip(1) {
        match arg.strip_prefix('-') {
            Some(flags) if !flags.is_empty() => {
                for c in flags.chars() {
                    match c {
                        'p' => mode = Mode::Preen,
                        'y' => {
                            mode = Mode::Yes;
                            answer_given = true;
                        }
                        'n' => {
                            mode = Mode::No;
                            answer_given = true;
                        }
                        'f' => force = true,
                        'C' => skip_clean = true,
                        'M' => {}
                        _ => return usage(),
                    }
                }
            }
            _ if device.is_none() => device = Some(arg),
            _ => return usage(),
        }
    }
    let Some(device) = device else { return usage() };
    // Without -p, -y or -n, only reporting is safe: there's no one to ask.
    if mode == Mode::Yes && !answer_given {
        mode = Mode::No;
    }
    match check(&device, mode, force, skip_clean) {
        Ok(status) => ExitCode::from(status),
        Err(e) => {
            eprintln!("fsck_msdosfs: {device}: {e}");
            ExitCode::from(EXIT_UNRESOLVED)
        }
    }
}

#[cfg(test)]
mod tests;
