//! Host tests: volumes made here, damaged the ways a crash (or worse) damages them, then checked;
//! `fsck.fat -n` (dosfstools) cross-checks the repaired volume when the host has it.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

struct Img {
    path: PathBuf,
    bpb: Bpb,
    kind: FatType,
    next: u32,
}

impl Drop for Img {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Img {
    /// A new, empty volume of `sectors` 512-byte sectors and type `kind`, as newfs_msdos makes.
    fn new(kind: FatType, sectors: u32) -> Img {
        let path = std::env::temp_dir().join(format!("fsck_msdosfs-{}-{}.img", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
        let bpb = Bpb::layout(&Layout { kind: Some(kind), ..Layout::new(sectors) }).unwrap();
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        f.set_len(sectors as u64 * 512).unwrap();
        let mut s = [0u8; 512];
        bpb.write_boot_sector(&mut s).unwrap();
        f.write_all_at(&s, 0).unwrap();
        let clusters = bpb.clusters().unwrap();
        if kind == FatType::Fat32 {
            f.write_all_at(&s, bpb.backup_boot_sector as u64 * 512).unwrap();
            write_fsinfo(&mut s, clusters - 1, 3);
            f.write_all_at(&s, bpb.fsinfo_sector as u64 * 512).unwrap();
        }
        let mut img = Img { path, bpb, kind, next: if kind == FatType::Fat32 { 3 } else { 2 } };
        img.set_all(0, fat::entry0(kind, bpb.media));
        img.set_all(1, kind.eoc() | kind.clean_bit().unwrap_or(0) | kind.no_error_bit().unwrap_or(0));
        if kind == FatType::Fat32 {
            img.set_all(2, kind.eoc());
        }
        img
    }

    fn file(&self) -> File {
        OpenOptions::new().read(true).write(true).open(&self.path).unwrap()
    }

    fn fat_at(&self, copy: u32, c: u32) -> u64 {
        (self.bpb.fat_start() + copy * self.bpb.fat_sectors) as u64 * 512 + fat::entry_offset(self.kind, c) as u64
    }

    fn get(&self, copy: u32, c: u32) -> u32 {
        let mut w = [0u8; 4];
        self.file().read_exact_at(&mut w[..self.kind.window()], self.fat_at(copy, c)).unwrap();
        fat::get(self.kind, c, &w)
    }

    fn set(&self, copy: u32, c: u32, v: u32) {
        let f = self.file();
        let mut w = [0u8; 4];
        let n = self.kind.window();
        f.read_exact_at(&mut w[..n], self.fat_at(copy, c)).unwrap();
        fat::set(self.kind, c, &mut w, v);
        f.write_all_at(&w[..n], self.fat_at(copy, c)).unwrap();
    }

    fn set_all(&mut self, c: u32, v: u32) {
        for copy in 0..self.bpb.fats as u32 {
            self.set(copy, c, v);
        }
    }

    fn root_at(&self) -> u64 {
        if self.kind == FatType::Fat32 {
            self.bpb.cluster_sector(self.bpb.root_cluster) as u64 * 512
        } else {
            (self.bpb.fat_start() + self.bpb.fats as u32 * self.bpb.fat_sectors) as u64 * 512
        }
    }

    /// A chain of `n` new clusters, consecutive; its first.
    fn chain(&mut self, n: u32) -> u32 {
        let first = self.next;
        for i in 0..n {
            let c = first + i;
            self.set_all(c, if i + 1 == n { self.kind.eoc() } else { c + 1 });
        }
        self.next += n;
        if self.kind == FatType::Fat32 {
            // FSInfo's free count stays exact, as a careful driver keeps it.
            let at = self.bpb.fsinfo_sector as u64 * 512 + 488;
            let mut w = [0u8; 4];
            self.file().read_exact_at(&mut w, at).unwrap();
            self.file().write_all_at(&(u32::from_le_bytes(w) - n).to_le_bytes(), at).unwrap();
        }
        first
    }

    /// Writes raw entry bytes into root slot `slot`.
    fn root_slot(&self, slot: u64, b: &[u8; 32]) {
        self.file().write_all_at(b, self.root_at() + slot * 32).unwrap();
    }

    /// A file in the root at `slot` with `clusters` clusters and `size` bytes.
    fn add_file(&mut self, slot: u64, name: &[u8; 11], clusters: u32, size: u32) -> u32 {
        let first = if clusters == 0 { 0 } else { self.chain(clusters) };
        let mut b = [0u8; 32];
        DirEntry { name: *name, attr: ATTR_ARCHIVE, cluster: first, size, ..DirEntry::default() }.write(&mut b);
        self.root_slot(slot, &b);
        first
    }

    /// A subdirectory of the root at `slot`, one cluster, with `.` and `..`.
    fn add_dir(&mut self, slot: u64, name: &[u8; 11]) -> u32 {
        let c = self.chain(1);
        let at = self.bpb.cluster_sector(c) as u64 * 512;
        let mut data = vec![0u8; self.bpb.cluster_bytes() as usize];
        DirEntry { name: *b".          ", attr: ATTR_DIRECTORY, cluster: c, ..DirEntry::default() }.write(&mut data[0..]);
        DirEntry { name: *b"..         ", attr: ATTR_DIRECTORY, cluster: 0, ..DirEntry::default() }.write(&mut data[32..]);
        self.file().write_all_at(&data, at).unwrap();
        let mut b = [0u8; 32];
        DirEntry { name: *name, attr: ATTR_DIRECTORY, cluster: c, ..DirEntry::default() }.write(&mut b);
        self.root_slot(slot, &b);
        c
    }

    fn check(&self, mode: Mode, force: bool) -> u8 {
        check(self.path.to_str().unwrap(), mode, force, false).unwrap()
    }

    /// dosfstools agrees the volume is consistent (when installed).
    fn fsck_fat_agrees(&self) {
        match std::process::Command::new("fsck.fat").arg("-n").arg(&self.path).output() {
            Ok(out) => assert!(out.status.success(), "fsck.fat -n: {}", String::from_utf8_lossy(&out.stdout)),
            Err(_) => eprintln!("(no fsck.fat on the host; skipped)"),
        }
    }

    fn mark_dirty(&mut self) {
        let e1 = self.get(0, 1) & !self.kind.clean_bit().unwrap_or(0);
        self.set_all(1, e1);
    }
}

const TYPES: [(FatType, u32); 3] = [(FatType::Fat12, 8192), (FatType::Fat16, 65_536), (FatType::Fat32, 81_920)];

#[test]
fn fresh_volumes_are_clean() {
    for (kind, sectors) in TYPES {
        let mut img = Img::new(kind, sectors);
        img.add_file(0, b"HELLO   TXT", 1, 5);
        img.add_dir(1, b"SUB        ");
        assert_eq!(img.check(Mode::No, true), EXIT_OK, "{kind:?}");
        img.fsck_fat_agrees();
    }
}

#[test]
fn preen_skips_a_clean_volume_and_marks_a_checked_one() {
    let mut img = Img::new(FatType::Fat16, 65_536);
    img.mark_dirty();
    // -n reports the volume isn't clean but changes nothing.
    assert_eq!(img.check(Mode::No, false), EXIT_OK);
    assert_eq!(img.get(0, 1) & 0x8000, 0);
    assert_eq!(img.check(Mode::Preen, false), EXIT_OK);
    assert_ne!(img.get(0, 1) & 0x8000, 0);
    assert_ne!(img.get(1, 1) & 0x8000, 0);
}

#[test]
fn preen_repairs_what_a_crash_leaves() {
    for (kind, sectors) in TYPES {
        let mut img = Img::new(kind, sectors);
        let cb = img.bpb.cluster_bytes();
        // A chain longer than its file, one shorter, lost clusters, FATs that differ, an
        // orphaned long-name entry.
        let long = img.add_file(0, b"LONG    BIN", 3, cb);
        img.add_file(1, b"SHORT   BIN", 1, cb * 2);
        let lost = img.chain(2);
        img.set(1, lost, 0);
        let mut lfn = [0u8; 32];
        let name: Vec<u16> = "orphan".encode_utf16().collect();
        write_lfn_entry(&mut lfn, &name, 0, 0x55);
        img.root_slot(2, &lfn);
        img.mark_dirty();
        assert_eq!(img.check(Mode::Preen, false), EXIT_OK, "{kind:?}");
        assert_eq!(img.get(0, long), kind.eoc(), "{kind:?}: LONG.BIN truncated to one cluster");
        assert_eq!(img.get(1, lost), img.get(0, lost), "FATs the same again");
        img.fsck_fat_agrees();
        // The lost chain is LOST.DIR/FILE0000.CHK now; a second run finds nothing.
        assert_eq!(img.check(Mode::No, true), EXIT_OK, "{kind:?}");
    }
}

#[test]
fn cross_links_need_y() {
    for (kind, sectors) in TYPES {
        let mut img = Img::new(kind, sectors);
        let cb = img.bpb.cluster_bytes();
        let a = img.add_file(0, b"A       BIN", 2, cb * 2);
        let b = img.add_file(1, b"B       BIN", 2, cb * 2);
        // B's chain joins A's at A's second cluster.
        img.set_all(b, a + 1);
        assert_eq!(img.check(Mode::Preen, true), EXIT_UNRESOLVED, "{kind:?}");
        assert_eq!(img.check(Mode::Yes, true), EXIT_OK, "{kind:?}");
        img.fsck_fat_agrees();
        assert_eq!(img.check(Mode::No, true), EXIT_OK, "{kind:?}");
    }
}

#[test]
fn bad_dot_dot_and_out_of_range() {
    let mut img = Img::new(FatType::Fat32, 81_920);
    let sub = img.add_dir(0, b"SUB        ");
    // `..` naming the subdirectory itself, and a file whose chain runs off the volume.
    let at = img.bpb.cluster_sector(sub) as u64 * 512 + 32;
    let mut b = [0u8; 32];
    DirEntry { name: *b"..         ", attr: ATTR_DIRECTORY, cluster: sub, ..DirEntry::default() }.write(&mut b);
    img.file().write_all_at(&b, at).unwrap();
    let f = img.add_file(1, b"F       BIN", 1, 10);
    img.set_all(f, 0x0FFF_FFF0);
    assert_eq!(img.check(Mode::Preen, true), EXIT_UNRESOLVED);
    assert_eq!(img.check(Mode::No, true), EXIT_UNRESOLVED);
    assert_eq!(img.check(Mode::Yes, true), EXIT_OK);
    img.fsck_fat_agrees();
    assert_eq!(img.check(Mode::No, true), EXIT_OK);
}

#[test]
fn fsinfo_is_corrected() {
    let mut img = Img::new(FatType::Fat32, 81_920);
    let at = img.bpb.fsinfo_sector as u64 * 512 + 488;
    img.file().write_all_at(&7u32.to_le_bytes(), at).unwrap();
    assert_eq!(img.check(Mode::Preen, true), EXIT_OK);
    let mut w = [0u8; 4];
    img.file().read_exact_at(&mut w, at).unwrap();
    assert_eq!(u32::from_le_bytes(w), img.bpb.clusters().unwrap() - 1);
    img.mark_dirty();
    assert_eq!(img.check(Mode::No, false), EXIT_OK);
}

#[test]
fn lost_dir_grows() {
    // More lost chains than one cluster of LOST.DIR holds (512-byte clusters: 16 entries).
    let mut img = Img::new(FatType::Fat16, 65_536);
    img.bpb = Bpb::layout(&Layout { kind: Some(FatType::Fat16), sectors_per_cluster: 1, ..Layout::new(65_536) }).unwrap_or(img.bpb);
    for _ in 0..40 {
        img.chain(1);
    }
    assert_eq!(img.check(Mode::Yes, true), EXIT_OK);
    img.fsck_fat_agrees();
    assert_eq!(img.check(Mode::No, true), EXIT_OK);
}
