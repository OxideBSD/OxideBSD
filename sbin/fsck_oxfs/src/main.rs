//! `fsck_oxfs(8)`: checks and repairs an oxfs file system through its raw device (OxideBSD-doc
//! `RAM_FLOOR.md` §3.4.2-3). `/etc/rc` runs it (through `fsck(8)`) while the root is still
//! mounted read-only, when the superblock says the last shutdown wasn't clean.
//!
//! ```text
//! fsck_oxfs [-fnpy] device
//! ```
//!
//! Phases, after FreeBSD's `fsck_ffs`: (1) every inode's block pointers are checked against the
//! file system's size and against each other (a block claimed twice); (2) the tree is walked
//! from the root, checking every directory record; (3) unreferenced inodes are found; (4) link
//! counts are compared with the names found; (5) the block bitmap is rebuilt from the blocks the
//! surviving inodes hold. Then the superblock is marked clean.
//!
//! The crash this is for (§3.3) can only leave inconsistencies of a few kinds -- blocks marked
//! used that nothing holds, inodes with no name, a link count off by the names a rename or an
//! unlink didn't finish -- and `-p` (preen) repairs exactly those without asking. Anything else
//! (a pointer out of range, a block claimed twice, a record naming a free inode) means something
//! worse; preen stops with status 8 and leaves it to `-y` (repair everything: clear bad inodes
//! and records) or `-n` (report only, open the device read-only). Unreferenced inodes are freed,
//! not reconnected: there's no `lost+found` yet.
//!
//! The on-disk format is oxfs's (`sys/modules/oxfs/src/lib.rs`: `SUPERBLOCK_VERSION`,
//! `pack_inode`, `write_dir_record`, `layout_for`); keep this reader in step with it until the
//! format lives in a crate both share (RAM_FLOOR.md §4).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

const BLOCK: usize = 4096;
const MAGIC: &[u8; 4] = b"OXFS";
const VERSION: u32 = 6;
const SB_STATE: usize = 20;
const SB_CLEAN: u32 = 1;
const SB_INODE_FILE: usize = 128;
const INODE_STRIDE: usize = 128;
const INODES_PER_BLOCK: usize = BLOCK / INODE_STRIDE;
const BITS_PER_BITMAP_BLOCK: u32 = (BLOCK * 8) as u32;
const BITMAP_START: u32 = 1;
const DIRECT: usize = 12;
const PTRS: usize = BLOCK / 4;
const NO_BLOCK: u32 = u32::MAX;
const NAME_MAX: usize = 255;
const RECORD: usize = 6 + NAME_MAX;
const RECORDS_PER_BLOCK: usize = BLOCK / RECORD;
const ROOT: u32 = 0;
/// Inode kinds (`pack_inode`'s tag byte).
const FREE: u8 = 0;
const DIR: u8 = 2;

/// Exit statuses, as `fsck_ffs`'s.
const EXIT_OK: u8 = 0;
const EXIT_UNRESOLVED: u8 = 8;
const EXIT_USAGE: u8 = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `-p`: repair what a crash leaves without asking; stop at anything worse.
    Preen,
    /// `-y`: repair everything.
    Yes,
    /// `-n`: report only.
    No,
}

/// One inode record's fields fsck looks at; the record's bytes are kept to write back.
#[derive(Clone)]
struct Inode {
    raw: [u8; INODE_STRIDE],
}

impl Inode {
    fn kind(&self) -> u8 {
        self.raw[0]
    }
    fn direct(&self, i: usize) -> u32 {
        u32_at(&self.raw, 9 + i * 4)
    }
    fn indirect(&self) -> u32 {
        u32_at(&self.raw, 57)
    }
    fn double_indirect(&self) -> u32 {
        u32_at(&self.raw, 61)
    }
    fn nlink(&self) -> u16 {
        u16::from_le_bytes([self.raw[75], self.raw[76]])
    }
    fn set_nlink(&mut self, n: u16) {
        self.raw[75..77].copy_from_slice(&n.to_le_bytes());
    }
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

struct Fs {
    dev: File,
    writable: bool,
    data_blocks: u32,
    data_offset: u32,
    bitmap_blocks: u32,
    sb: [u8; BLOCK],
    inode_file: Inode,
    inodes: Vec<Inode>,
    /// Inode numbers whose records changed, to write back.
    dirty_inodes: BTreeSet<u32>,
    errors: u32,
}

impl Fs {
    fn read_device_block(&self, n: u64) -> std::io::Result<[u8; BLOCK]> {
        let mut b = [0u8; BLOCK];
        self.dev.read_exact_at(&mut b, n * BLOCK as u64)?;
        Ok(b)
    }

    fn write_device_block(&self, n: u64, b: &[u8; BLOCK]) -> std::io::Result<()> {
        self.dev.write_all_at(b, n * BLOCK as u64)
    }

    fn read_block(&self, n: u32) -> std::io::Result<[u8; BLOCK]> {
        self.read_device_block(self.data_offset as u64 + n as u64)
    }

    fn write_block(&self, n: u32, b: &[u8; BLOCK]) -> std::io::Result<()> {
        self.write_device_block(self.data_offset as u64 + n as u64, b)
    }

    /// Every block `inode` holds, data and index alike, in file order for the data, or the first
    /// pointer out of range.
    fn blocks_of(&self, inode: &Inode) -> Result<(Vec<u32>, Vec<u32>), u32> {
        let (mut data, mut index) = (Vec::new(), Vec::new());
        let ok = |b: u32| b < self.data_blocks;
        for i in 0..DIRECT {
            let b = inode.direct(i);
            if b != NO_BLOCK {
                if !ok(b) {
                    return Err(b);
                }
                data.push(b);
            }
        }
        if inode.indirect() != NO_BLOCK {
            self.walk_index(inode.indirect(), 0, &mut data, &mut index)?;
        }
        if inode.double_indirect() != NO_BLOCK {
            self.walk_index(inode.double_indirect(), 1, &mut data, &mut index)?;
        }
        Ok((data, index))
    }

    /// Index block `ib` and what it points at: data blocks at `depth` 0, more index blocks above.
    fn walk_index(&self, ib: u32, depth: u32, data: &mut Vec<u32>, index: &mut Vec<u32>) -> Result<(), u32> {
        if ib >= self.data_blocks {
            return Err(ib);
        }
        index.push(ib);
        let block = self.read_block(ib).map_err(|_| ib)?;
        for slot in 0..PTRS {
            let p = u32_at(&block, slot * 4);
            if p == NO_BLOCK {
                continue;
            }
            if depth == 0 {
                if p >= self.data_blocks {
                    return Err(p);
                }
                data.push(p);
            } else {
                self.walk_index(p, depth - 1, data, index)?;
            }
        }
        Ok(())
    }

    /// Where inode `n`'s record is: its inode-file data block and byte offset.
    fn inode_location(&self, n: u32) -> Option<(u32, usize)> {
        let (data, _) = self.blocks_of(&self.inode_file).ok()?;
        let block = *data.get(n as usize / INODES_PER_BLOCK)?;
        Some((block, n as usize % INODES_PER_BLOCK * INODE_STRIDE))
    }

    fn problem(&mut self, what: &str) {
        println!("{what}");
        self.errors += 1;
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: fsck_oxfs [-fnpy] device");
    ExitCode::from(EXIT_USAGE)
}

fn main() -> ExitCode {
    let (mut mode, mut force) = (Mode::Yes, false);
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
    match check(&device, mode, force) {
        Ok(status) => ExitCode::from(status),
        Err(e) => {
            eprintln!("fsck_oxfs: {device}: {e}");
            ExitCode::from(EXIT_UNRESOLVED)
        }
    }
}

fn check(device: &str, mode: Mode, force: bool) -> Result<u8, String> {
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
    let mut sb = [0u8; BLOCK];
    dev.read_exact_at(&mut sb, 0).map_err(|e| format!("can't read the superblock: {e}"))?;
    if &sb[0..4] != MAGIC {
        return Err("not an oxfs file system (no superblock)".into());
    }
    let version = u32_at(&sb, 4);
    if version != VERSION {
        return Err(format!("superblock version {version}; this fsck_oxfs reads {VERSION}"));
    }
    let clean = u32_at(&sb, SB_STATE) == SB_CLEAN;
    if clean && mode == Mode::Preen && !force {
        println!("{device}: clean");
        return Ok(EXIT_OK);
    }
    let data_blocks = u32_at(&sb, 8);
    let bitmap_blocks = data_blocks.div_ceil(BITS_PER_BITMAP_BLOCK);
    let count = u32_at(&sb, 12);
    let mut inode_file = Inode { raw: [0; INODE_STRIDE] };
    inode_file.raw.copy_from_slice(&sb[SB_INODE_FILE..SB_INODE_FILE + INODE_STRIDE]);
    let mut fs = Fs {
        dev,
        writable,
        data_blocks,
        data_offset: BITMAP_START + bitmap_blocks,
        bitmap_blocks,
        sb,
        inode_file,
        inodes: Vec::new(),
        dirty_inodes: BTreeSet::new(),
        errors: 0,
    };
    println!("** {device}{}", if writable { "" } else { " (NO WRITE)" });
    println!("** {} data blocks, {} inodes", data_blocks, count);

    // The inode file itself.
    let (inode_file_data, inode_file_index) = fs
        .blocks_of(&fs.inode_file)
        .map_err(|b| format!("the inode file points at block {b}, past the end"))?;
    let mut data = [0u8; BLOCK];
    for n in 0..count {
        let Some(&block) = inode_file_data.get(n as usize / INODES_PER_BLOCK) else {
            return Err(format!("the inode file is shorter than its {count} inodes"));
        };
        let off = n as usize % INODES_PER_BLOCK * INODE_STRIDE;
        if off == 0 {
            data = fs.read_block(block).map_err(|e| e.to_string())?;
        }
        let mut raw = [0u8; INODE_STRIDE];
        raw.copy_from_slice(&data[off..off + INODE_STRIDE]);
        fs.inodes.push(Inode { raw });
    }
    let mut serious = false;

    println!("** Phase 1 - Check Blocks and Sizes");
    let mut owner: BTreeMap<u32, u32> = BTreeMap::new();
    for b in inode_file_data.iter().chain(&inode_file_index) {
        owner.insert(*b, u32::MAX);
    }
    for n in 0..count {
        if fs.inodes[n as usize].kind() == FREE {
            continue;
        }
        let inode = fs.inodes[n as usize].clone();
        let bad = match fs.blocks_of(&inode) {
            Err(b) => Some(format!("inode {n}: block {b} past the end of the file system")),
            Ok((data, index)) => {
                let all: Vec<u32> = data.into_iter().chain(index).collect();
                match all.iter().find_map(|b| owner.get(b).map(|o| (*b, *o))) {
                    Some((b, other)) => Some(format!("inode {n}: block {b} also held by inode {other}")),
                    None => {
                        for b in all {
                            owner.insert(b, n);
                        }
                        None
                    }
                }
            }
        };
        if let Some(why) = bad {
            fs.problem(&why);
            serious = true;
            if mode == Mode::Yes {
                println!("  CLEARED inode {n}");
                fs.inodes[n as usize].raw = [0; INODE_STRIDE];
                fs.dirty_inodes.insert(n);
            }
        }
    }

    println!("** Phase 2 - Check Pathnames");
    let mut names = vec![0u32; count as usize];
    let mut reached = vec![false; count as usize];
    let mut queue = vec![(ROOT, ROOT)];
    reached[ROOT as usize] = fs.inodes.get(ROOT as usize).is_some_and(|i| i.kind() == DIR);
    if !reached[ROOT as usize] {
        return Err("the root inode isn't a directory".into());
    }
    while let Some((dir, parent)) = queue.pop() {
        let inode = fs.inodes[dir as usize].clone();
        let Ok((data, _)) = fs.blocks_of(&inode) else { continue };
        for block in data {
            let mut buf = fs.read_block(block).map_err(|e| e.to_string())?;
            let mut changed = false;
            for r in 0..RECORDS_PER_BLOCK {
                let off = r * RECORD;
                if buf[off] == 0 {
                    continue;
                }
                let len = buf[off + 1] as usize;
                let target = u32_at(&buf, off + 2);
                let name = String::from_utf8_lossy(&buf[off + 6..off + 6 + len.min(NAME_MAX)]).into_owned();
                let bad = if len == 0 || len > NAME_MAX {
                    Some(format!("directory {dir}: a record with a bad name length {len}"))
                } else if target >= count || fs.inodes[target as usize].kind() == FREE {
                    Some(format!("directory {dir}: {name} names inode {target}, which is free"))
                } else if name == "." && target != dir {
                    Some(format!("directory {dir}: . names inode {target}"))
                } else if name == ".." && target != parent {
                    Some(format!("directory {dir}: .. names inode {target}, not {parent}"))
                } else {
                    None
                };
                if let Some(why) = bad {
                    fs.problem(&why);
                    serious = true;
                    if mode == Mode::Yes {
                        println!("  REMOVED");
                        buf[off] = 0;
                        changed = true;
                    }
                    continue;
                }
                if name == "." || name == ".." {
                    continue;
                }
                names[target as usize] += 1;
                if fs.inodes[target as usize].kind() == DIR {
                    if reached[target as usize] {
                        fs.problem(&format!("directory {target} ({name}) has more than one name"));
                        serious = true;
                        continue;
                    }
                    reached[target as usize] = true;
                    queue.push((target, dir));
                }
            }
            if changed && fs.writable {
                fs.write_block(block, &buf).map_err(|e| e.to_string())?;
            }
        }
    }

    // Preen repairs only what a crash leaves; past phases 1-2 it would act on a tree it can't
    // trust (a broken record makes a whole directory look unreferenced, and its files would be
    // freed). Stop with nothing written.
    if serious && mode == Mode::Preen {
        println!("\nUNEXPECTED INCONSISTENCY; RUN fsck_oxfs MANUALLY (with -y to repair).");
        return Ok(EXIT_UNRESOLVED);
    }

    println!("** Phase 3 - Check Connectivity");
    for n in 1..count {
        let unreferenced = fs.inodes[n as usize].kind() != FREE && names[n as usize] == 0;
        if unreferenced {
            // A file whose last name went away (or never came) before a crash: what preen frees.
            println!("UNREF inode {n}{}", if mode == Mode::No { "" } else { " (CLEARED)" });
            fs.errors += 1;
            if mode != Mode::No {
                fs.inodes[n as usize].raw = [0; INODE_STRIDE];
                fs.dirty_inodes.insert(n);
            }
        }
    }

    println!("** Phase 4 - Check Reference Counts");
    for n in 0..count {
        let inode = &fs.inodes[n as usize];
        if inode.kind() == FREE {
            continue;
        }
        let want = if inode.kind() == DIR { 1 } else { names[n as usize].max(1) as u16 };
        if inode.nlink() != want {
            println!(
                "LINK COUNT inode {n}: {} should be {want}{}",
                inode.nlink(),
                if mode == Mode::No { "" } else { " (ADJUSTED)" }
            );
            fs.errors += 1;
            if mode != Mode::No {
                fs.inodes[n as usize].set_nlink(want);
                fs.dirty_inodes.insert(n);
            }
        }
    }

    println!("** Phase 5 - Check Block Bitmap");
    let mut used = vec![false; data_blocks as usize];
    for b in inode_file_data.iter().chain(&inode_file_index) {
        used[*b as usize] = true;
    }
    for inode in fs.inodes.iter().filter(|i| i.kind() != FREE) {
        if let Ok((data, index)) = fs.blocks_of(inode) {
            for b in data.iter().chain(&index) {
                used[*b as usize] = true;
            }
        }
    }
    let mut differences = 0u64;
    let mut free = 0u64;
    for index in 0..fs.bitmap_blocks {
        let mut block = fs.read_device_block((BITMAP_START + index) as u64).map_err(|e| e.to_string())?;
        let mut changed = false;
        let base = index * BITS_PER_BITMAP_BLOCK;
        for bit in 0..BITS_PER_BITMAP_BLOCK.min(data_blocks - base) {
            let n = (base + bit) as usize;
            let on_disk = block[bit as usize / 8] & (1 << (bit % 8)) != 0;
            if !used[n] {
                free += 1;
            }
            if on_disk != used[n] {
                differences += 1;
                block[bit as usize / 8] ^= 1 << (bit % 8);
                changed = true;
            }
        }
        if changed && fs.writable {
            fs.write_device_block((BITMAP_START + index) as u64, &block).map_err(|e| e.to_string())?;
        }
    }
    if differences > 0 {
        println!("BLOCK BITMAP: {differences} differences{}", if fs.writable { " (FIXED)" } else { "" });
        fs.errors += 1;
    }

    if fs.writable {
        // Inode records, written back a whole block at a time.
        let mut blocks: BTreeMap<u32, [u8; BLOCK]> = BTreeMap::new();
        for &n in &fs.dirty_inodes {
            let Some((block, off)) = fs.inode_location(n) else { continue };
            if !blocks.contains_key(&block) {
                blocks.insert(block, fs.read_block(block).map_err(|e| e.to_string())?);
            }
            blocks.get_mut(&block).unwrap()[off..off + INODE_STRIDE].copy_from_slice(&fs.inodes[n as usize].raw);
        }
        for (block, data) in &blocks {
            fs.write_block(*block, data).map_err(|e| e.to_string())?;
        }
    }

    let in_use = fs.inodes.iter().filter(|i| i.kind() != FREE).count();
    println!("{in_use} files, {} used, {free} free", data_blocks as u64 - free);
    if serious && mode != Mode::Yes {
        println!("\nUNEXPECTED INCONSISTENCY; RUN fsck_oxfs MANUALLY (with -y to repair).");
        return Ok(EXIT_UNRESOLVED);
    }
    if fs.writable {
        let mut sb = fs.sb;
        sb[SB_STATE..SB_STATE + 4].copy_from_slice(&SB_CLEAN.to_le_bytes());
        fs.write_device_block(0, &sb).map_err(|e| e.to_string())?;
        if fs.errors > 0 {
            println!("\n***** FILE SYSTEM WAS MODIFIED *****");
        }
    } else if fs.errors > 0 {
        return Ok(EXIT_UNRESOLVED);
    }
    Ok(EXIT_OK)
}
