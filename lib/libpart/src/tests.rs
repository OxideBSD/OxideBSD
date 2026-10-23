use super::*;
use alloc::vec;

/// A disk in memory.
struct Mem {
    ss: u32,
    data: Vec<u8>,
}

impl Mem {
    fn new(ss: u32, bytes: u64) -> Mem {
        Mem { ss, data: vec![0; bytes as usize] }
    }

    fn apply(&mut self, writes: &[(u64, Vec<u8>)]) {
        for (lba, bytes) in writes {
            let at = (*lba * self.ss as u64) as usize;
            self.data[at..at + bytes.len()].copy_from_slice(bytes);
        }
    }

    fn table(&mut self) -> Option<Table> {
        read(self).unwrap()
    }
}

impl Disk for Mem {
    fn sector_size(&self) -> u32 {
        self.ss
    }
    fn sectors(&self) -> u64 {
        self.data.len() as u64 / self.ss as u64
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let at = (lba * self.ss as u64) as usize;
        match self.data.get(at..at + buf.len()) {
            Some(src) => {
                buf.copy_from_slice(src);
                true
            }
            None => false,
        }
    }
}

const MIB: u64 = 1 << 20;

fn gpt_disk(ss: u32, bytes: u64) -> (Mem, Table) {
    let mem = Mem::new(ss, bytes);
    let t = Table::new(Scheme::Gpt, ss, mem.sectors(), guid_from(b"disk")).unwrap();
    (mem, t)
}

fn code(k: Kind, s: Scheme) -> TypeCode {
    k.code(s).unwrap()
}

#[test]
fn a_gpt_round_trips() {
    let (mut mem, mut t) = gpt_disk(512, 64 * MIB);
    let efi = t.add(code(Kind::Efi, Scheme::Gpt), "efi", None, Some(8 * MIB / 512), guid_from(b"1")).unwrap();
    let root = t.add(code(Kind::Oxfs, Scheme::Gpt), "rootfs", None, None, guid_from(b"2")).unwrap();
    assert_eq!((efi, root), (1, 2));
    assert_eq!(t.entry(1).unwrap().first, 2048, "the first starts at 1 MiB");
    assert_eq!(t.entry(2).unwrap().first, 2048 + 16384);
    mem.apply(&t.write());
    let back = mem.table().unwrap();
    assert_eq!(back, t);
    assert_eq!(back.entry(2).unwrap().kind(), Kind::Oxfs);
    assert_eq!(back.entry(2).unwrap().label, "rootfs");
}

#[test]
fn a_4kn_gpt_round_trips() {
    let (mut mem, mut t) = gpt_disk(4096, 64 * MIB);
    assert_eq!(t.first_usable, 2 + 4, "128 entries take 4 sectors of 4 KiB");
    t.add(code(Kind::Oxfs, Scheme::Gpt), "k4", None, None, guid_from(b"x")).unwrap();
    assert_eq!(t.entry(1).unwrap().first, 256, "1 MiB in 4 KiB sectors");
    mem.apply(&t.write());
    assert_eq!(mem.table().unwrap(), t);
}

#[test]
fn a_damaged_primary_gpt_is_read_from_its_backup() {
    let (mut mem, mut t) = gpt_disk(512, 32 * MIB);
    t.add(code(Kind::Oxfs, Scheme::Gpt), "a", None, None, guid_from(b"a")).unwrap();
    mem.apply(&t.write());
    mem.data[512 + 60] ^= 0xff; // in the disk GUID, under the header's CRC
    let back = mem.table().unwrap();
    assert!(back.from_backup);
    assert_eq!(back.entries, t.entries);
    // Writing it repairs the primary.
    mem.apply(&back.write());
    assert!(!mem.table().unwrap().from_backup);
}

#[test]
fn both_gpt_headers_damaged_read_as_the_mbr() {
    let (mut mem, mut t) = gpt_disk(512, 32 * MIB);
    t.add(code(Kind::Oxfs, Scheme::Gpt), "a", None, None, guid_from(b"a")).unwrap();
    mem.apply(&t.write());
    mem.data[512] = b'X';
    let end = mem.data.len();
    mem.data[end - 512] = b'X';
    let back = mem.table().unwrap();
    assert_eq!(back.scheme, Scheme::Mbr);
    assert!(back.entries.is_empty(), "the protective entry isn't a partition");
}

#[test]
fn an_mbr_round_trips_with_its_boot_code() {
    let mut mem = Mem::new(512, 64 * MIB);
    let mut t = Table::new(Scheme::Mbr, 512, mem.sectors(), [0; 16]).unwrap();
    t.boot[..4].copy_from_slice(b"BOOT");
    t.boot[440..444].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    t.add(code(Kind::MsBasicData, Scheme::Mbr), "", None, Some(16 * MIB / 512), [0; 16]).unwrap();
    t.add(TypeCode::Mbr(0x83), "", None, None, [0; 16]).unwrap();
    t.set_active(2, true).unwrap();
    mem.apply(&t.write());
    let back = mem.table().unwrap();
    assert_eq!(back, t);
    assert_eq!(back.entry(2).unwrap().kind(), Kind::LinuxData);
    assert!(back.entry(2).unwrap().active && !back.entry(1).unwrap().active);
    assert_eq!(&mem.data[..4], b"BOOT");
}

#[test]
fn placement_alignment_and_sizes() {
    let (_, mut t) = gpt_disk(512, 64 * MIB);
    // A size is whole 4 KiB blocks.
    t.add(code(Kind::Swap, Scheme::Gpt), "", None, Some(1000), guid_from(b"s")).unwrap();
    assert_eq!(t.entry(1).unwrap().sectors, 1000 / 8 * 8);
    assert_eq!(t.add(code(Kind::Swap, Scheme::Gpt), "", None, Some(7), [1; 16]), Err(Error::BadSize));
    // The next aligns up to the next 1 MiB, leaving the gap free.
    t.add(code(Kind::Oxfs, Scheme::Gpt), "", None, Some(2048), guid_from(b"o")).unwrap();
    assert_eq!(t.entry(2).unwrap().first, 4096);
    assert_eq!(t.free()[0], (34, 2048 - 34), "before the first 1 MiB");
    assert_eq!(t.free()[1], (2048 + 1000 / 8 * 8, 4096 - 2048 - 1000 / 8 * 8));
    // At an exact start, inside free space only.
    assert_eq!(t.add(code(Kind::Oxfs, Scheme::Gpt), "", Some(4096 + 10), None, [2; 16]), Err(Error::NoSpace));
    let i = t.add(code(Kind::Oxfs, Scheme::Gpt), "", Some(3200), Some(8), guid_from(b"e")).unwrap();
    assert_eq!(t.entry(i).unwrap().first, 3200);
}

#[test]
fn delete_and_resize() {
    let (_, mut t) = gpt_disk(512, 64 * MIB);
    t.add(code(Kind::Oxfs, Scheme::Gpt), "a", None, Some(4096), guid_from(b"a")).unwrap();
    t.add(code(Kind::Oxfs, Scheme::Gpt), "b", None, Some(4096), guid_from(b"b")).unwrap();
    // Growing into the next partition is refused; to all the free space after the last, allowed.
    assert_eq!(t.resize(1, Some(8192)), Err(Error::Overlap));
    t.resize(2, None).unwrap();
    assert_eq!(t.entry(2).unwrap().end(), t.last_usable + 1 - (t.last_usable + 1 - t.entry(2).unwrap().first) % 8);
    // Deleting the second lets the first grow into its place.
    t.delete(2).unwrap();
    t.resize(1, Some(8192)).unwrap();
    assert_eq!(t.entry(1).unwrap().sectors, 8192);
    assert_eq!(t.delete(9), Err(Error::NoSuchPartition));
    // The freed number is used again first.
    assert_eq!(t.add(code(Kind::Swap, Scheme::Gpt), "", None, Some(2048), [3; 16]), Ok(2));
}

#[test]
fn refusals() {
    let mut t = Table::new(Scheme::Mbr, 512, 64 * MIB / 512, [0; 16]).unwrap();
    for _ in 0..4 {
        t.add(code(Kind::Oxfs, Scheme::Mbr), "", None, Some(2048), [0; 16]).unwrap();
    }
    assert_eq!(t.add(code(Kind::Oxfs, Scheme::Mbr), "", None, Some(2048), [0; 16]), Err(Error::TableFull));
    assert_eq!(t.modify(1, None, Some("name")), Err(Error::BadLabel), "MBR has no names");
    assert_eq!(Kind::BiosBoot.code(Scheme::Mbr), None);
    assert_eq!(t.modify(1, Some(TypeCode::Gpt([1; 16])), None), Err(Error::WrongScheme));
    let (_, mut g) = gpt_disk(512, 8 * MIB);
    assert_eq!(g.add(code(Kind::Oxfs, Scheme::Gpt), &"x".repeat(37), None, None, [0; 16]), Err(Error::BadLabel));
    assert_eq!(g.add(code(Kind::Oxfs, Scheme::Gpt), "", None, Some(64 * MIB / 512), [0; 16]), Err(Error::NoSpace));
    assert_eq!(g.set_active(1, true), Err(Error::WrongScheme));
    assert_eq!(Table::new(Scheme::Gpt, 512, 40, [0; 16]), Err(Error::DiskTooSmall));
    // MBR's 32-bit fields: a 3 TiB disk's table ends at 2 TiB.
    let big = Table::new(Scheme::Mbr, 512, 3 << 31, [0; 16]).unwrap();
    assert_eq!(big.last_usable, u32::MAX as u64);
}

#[test]
fn damaged_or_hostile_tables() {
    // No signature: no table.
    assert_eq!(parse(&[0; 34 * 512], &[], 512, 1 << 20), None);
    // A GPT header claiming more entries than it can hold, or entries past the buffer.
    let (mut mem, mut t) = gpt_disk(512, 16 * MIB);
    t.add(code(Kind::Oxfs, Scheme::Gpt), "", None, None, guid_from(b"z")).unwrap();
    mem.apply(&t.write());
    let mut h = mem.data[512..1024].to_vec();
    h[80..84].copy_from_slice(&1_000_000u32.to_le_bytes());
    h[16..20].fill(0);
    let crc = crc32(&h[..92]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    let mut head = mem.data[..34 * 512].to_vec();
    head[512..1024].copy_from_slice(&h);
    let parsed = parse(&head, &[], 512, mem.sectors()).unwrap();
    assert_eq!(parsed.scheme, Scheme::Mbr, "refused, not trusted");
    // A short buffer, any sector size: never a panic.
    for len in [0, 511, 512, 1023, 4096] {
        let _ = parse(&head[..len.min(head.len())], &[], 512, mem.sectors());
        let _ = parse(&head[..len.min(head.len())], &head, 4096, 3);
    }
    // An entry ending before it starts is left out.
    let (mut mem, mut t) = gpt_disk(512, 16 * MIB);
    t.add(code(Kind::Oxfs, Scheme::Gpt), "", None, None, guid_from(b"q")).unwrap();
    t.entries[0].sectors = 0; // written as last = first - 1
    mem.apply(&t.write());
    assert!(mem.table().unwrap().entries.is_empty());
}

#[test]
fn a_hybrid_mbr_beside_a_broken_gpt_reads_its_other_entries() {
    let mut mem = Mem::new(512, 16 * MIB);
    let mut sector0 = vec![0u8; 512];
    mbr_entry(&mut sector0, 0, MBR_GPT_PROTECTIVE, 1, 100, false);
    mbr_entry(&mut sector0, 1, 0x0C, 2048, 4096, true);
    mem.apply(&[(0, sector0)]);
    let t = mem.table().unwrap();
    assert_eq!(t.scheme, Scheme::Mbr);
    assert_eq!(t.entries.len(), 1);
    assert_eq!((t.entries[0].index, t.entries[0].first, t.entries[0].kind()), (2, 2048, Kind::MsBasicData));
}

#[test]
fn destroying_leaves_no_table() {
    let (mut mem, mut t) = gpt_disk(512, 16 * MIB);
    t.add(code(Kind::Oxfs, Scheme::Gpt), "", None, None, guid_from(b"d")).unwrap();
    mem.apply(&t.write());
    mem.apply(&t.destroy());
    assert_eq!(mem.table(), None);
}

#[test]
fn names() {
    for (n, k) in Kind::NAMED {
        assert_eq!(Kind::parse(n), Some(k));
        assert_eq!(k.name(), n);
    }
    assert_eq!(Kind::parse("!0x07"), Some(Kind::MsBasicData), "NTFS reads as Windows'");
    let other = Kind::parse("!0x9f").unwrap();
    assert_eq!(other, Kind::Other(TypeCode::Mbr(0x9f)));
    assert_eq!(other.name(), "!0x9f");
    let g = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
    assert_eq!(Kind::parse(&alloc::format!("!{g}")), Some(Kind::Efi));
    assert_eq!(guid_string(&parse_guid(g).unwrap()), g);
    assert_eq!(parse_guid("not-a-guid"), None);
    assert_eq!(Kind::parse("ufs"), None);
}
