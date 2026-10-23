//! mkimg's images, read back by libpart (INSTALLER.md §11 step 8): the tables mkimg writes are
//! the ones gpart and the installer read and edit.

use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::process::Command;

use part::{Kind, Scheme};

struct FileDisk {
    file: std::fs::File,
    ss: u32,
}

impl part::Disk for FileDisk {
    fn sector_size(&self) -> u32 {
        self.ss
    }
    fn sectors(&self) -> u64 {
        self.file.metadata().unwrap().len() / self.ss as u64
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.file.read_exact_at(buf, lba * self.ss as u64).is_ok()
    }
}

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("mkimg-tables-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Runs mkimg with `args` into `name`, then reads its table.
fn image(name: &str, ss: u32, args: &[&str]) -> part::Table {
    let out = dir().join(name);
    let status = Command::new(env!("CARGO_BIN_EXE_mkimg")).arg("-o").arg(&out).args(args).status().unwrap();
    assert!(status.success(), "mkimg {args:?}");
    let mut disk = FileDisk { file: std::fs::File::open(&out).unwrap(), ss };
    part::read(&mut disk).unwrap().expect("a table")
}

fn part_file(name: &str, bytes: usize) -> String {
    let p = dir().join(name);
    std::fs::write(&p, vec![0x5au8; bytes]).unwrap();
    p.to_str().unwrap().to_string()
}

#[test]
fn a_gpt_image() {
    let (a, b) = (part_file("a", 3 << 20), part_file("b", 100_000));
    let (esp, root) = (format!("efi/esp:={b}"), format!("oxfs/rootfs:={a}"));
    let t = image("gpt.img", 512, &["-s", "gpt", "-p", &esp, "-p", &root, "-p", "bios::1m"]);
    assert_eq!(t.scheme, Scheme::Gpt);
    assert!(!t.from_backup);
    let kinds: Vec<(u32, Kind, &str, u64)> = t.entries.iter().map(|e| (e.index, e.kind(), e.label.as_str(), e.first)).collect();
    assert_eq!(kinds, [(1, Kind::Efi, "esp", 2048), (2, Kind::Oxfs, "rootfs", 4096), (3, Kind::BiosBoot, "", 4096 + 3 * 2048)]);
    assert_eq!(t.entry(2).unwrap().sectors, (3 << 20) / 512);
    // The table it read writes back as it was: nothing lost or changed.
    let mut again = t.clone();
    again.from_backup = false;
    assert_eq!(part::parse(&concat_head(&t), &[], 512, t.disk_sectors), Some(again));
}

/// A table's first sectors as `write` lays them out.
fn concat_head(t: &part::Table) -> Vec<u8> {
    let (n, _) = part::head_and_tail_sectors(t.sector_size);
    let mut head = vec![0u8; (n * t.sector_size as u64) as usize];
    for (lba, bytes) in t.write() {
        let at = (lba * t.sector_size as u64) as usize;
        if at + bytes.len() <= head.len() {
            head[at..at + bytes.len()].copy_from_slice(&bytes);
        }
    }
    head
}

#[test]
fn a_4kn_gpt_image() {
    let a = part_file("k", 1 << 20);
    let t = image("4kn.img", 4096, &["-s", "gpt", "-S", "4096", "-p", &format!("oxfs/k4:={a}")]);
    assert_eq!((t.sector_size, t.first_usable), (4096, 6));
    assert_eq!((t.entries[0].first, t.entries[0].sectors), (256, 256));
}

#[test]
fn an_mbr_image() {
    let a = part_file("m", 1 << 20);
    let t = image("mbr.img", 512, &["-s", "mbr", "-p", &format!("fat32lba:={a}"), "-p", "oxfs::4m", "-p", "fat16b::1m"]);
    assert_eq!(t.scheme, Scheme::Mbr);
    let kinds: Vec<(Kind, u64, u64)> = t.entries.iter().map(|e| (e.kind(), e.first, e.sectors)).collect();
    assert_eq!(kinds, [(Kind::MsBasicData, 2048, 2048), (Kind::Oxfs, 4096, 8192), (Kind::MsBasicData, 12288, 2048)]);
    assert_eq!(t.entries[2].code, part::TypeCode::Mbr(0x06), "fat16b keeps its own type");
}
