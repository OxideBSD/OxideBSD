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
//! and records) or `-n` (report only, open the device read-only). An unreferenced directory, or
//! file with links left, is reconnected in `/lost+found` as `#<inode>` (made if missing, as
//! newfs makes it); a file with no links left was removed while open, and is freed.
//!
//! The on-disk format is `lib/liboxfs`'s, shared with the oxfs module (RAM_FLOOR.md §4.1).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

use oxfs_format::*;

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

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

struct Fs {
    dev: File,
    writable: bool,
    data_blocks: u32,
    data_offset: u32,
    bitmap_blocks: u32,
    sb: Superblock,
    inode_file: Inode,
    inodes: Vec<Inode>,
    /// Inode numbers whose records changed, to write back.
    dirty_inodes: BTreeSet<u32>,
    errors: u32,
}

impl Fs {
    fn read_device_block(&self, n: u64) -> std::io::Result<[u8; BLOCK_SIZE]> {
        let mut b = [0u8; BLOCK_SIZE];
        self.dev.read_exact_at(&mut b, n * BLOCK_SIZE as u64)?;
        Ok(b)
    }

    fn write_device_block(&self, n: u64, b: &[u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.dev.write_all_at(b, n * BLOCK_SIZE as u64)
    }

    fn read_block(&self, n: u32) -> std::io::Result<[u8; BLOCK_SIZE]> {
        self.read_device_block(self.data_offset as u64 + n as u64)
    }

    fn write_block(&self, n: u32, b: &[u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.write_device_block(self.data_offset as u64 + n as u64, b)
    }

    /// Every block `inode` holds, data and index alike, in file order for the data, or the first
    /// pointer out of range.
    fn blocks_of(&self, inode: &Inode) -> Result<(Vec<u32>, Vec<u32>), u32> {
        let (mut data, mut index) = (Vec::new(), Vec::new());
        let ok = |b: u32| b < self.data_blocks;
        for i in 0..DIRECT_BLOCKS {
            let b = inode.direct[i];
            if b != NO_BLOCK {
                if !ok(b) {
                    return Err(b);
                }
                data.push(b);
            }
        }
        if inode.indirect != NO_BLOCK {
            self.walk_index(inode.indirect, 0, &mut data, &mut index)?;
        }
        if inode.double_indirect != NO_BLOCK {
            self.walk_index(inode.double_indirect, 1, &mut data, &mut index)?;
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
        for slot in 0..PTRS_PER_INDIRECT {
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

/// Names and reachability found by the tree walk.
struct Tree {
    /// Names each inode has, `.` and `..` aside.
    names: Vec<u32>,
    /// Directories reached from the root (or reconnected).
    reached: Vec<bool>,
    /// Something preen mustn't repair was found.
    serious: bool,
}

/// `/lost+found`, once found or made.
struct LostFound {
    inode: Option<u32>,
    /// Making it was tried (and maybe failed): don't try again.
    tried: bool,
}

/// Walks directory `dir` and everything under it, counting names, checking every record:
/// `.` must name `dir`, `..` must name `parent` (when given), and every record a live inode.
/// Bad records are removed under `-y`.
fn walk(fs: &mut Fs, tree: &mut Tree, dir: u32, parent: Option<u32>, mode: Mode) -> Result<(), String> {
    let count = fs.inodes.len() as u32;
    let mut queue = vec![(dir, parent)];
    while let Some((dir, parent)) = queue.pop() {
        let inode = fs.inodes[dir as usize].clone();
        let Ok((data, _)) = fs.blocks_of(&inode) else { continue };
        // Names already met in this directory: a second record of one is an error.
        let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
        for block in data {
            let mut buf = fs.read_block(block).map_err(|e| e.to_string())?;
            let mut changed = false;
            for r in 0..RECORDS_PER_BLOCK {
                if !dir_record_used(&buf, r) {
                    continue;
                }
                let len = dir_record_name_len(&buf, r);
                let target = dir_record_inode(&buf, r);
                let name = String::from_utf8_lossy(dir_record_name(&buf, r)).into_owned();
                let bad = if len == 0 {
                    Some(format!("directory {dir}: a record with a bad name length {len}"))
                } else if target >= count || fs.inodes[target as usize].kind == InodeKind::Free {
                    Some(format!("directory {dir}: {name} names inode {target}, which is free"))
                } else if name == "." && target != dir {
                    Some(format!("directory {dir}: . names inode {target}"))
                } else if name == ".." && parent.is_some_and(|p| target != p) {
                    Some(format!("directory {dir}: .. names inode {target}, not {}", parent.unwrap()))
                } else if !seen.insert(dir_record_name(&buf, r).to_vec()) {
                    Some(format!("directory {dir}: a second record named {name} (inode {target})"))
                } else {
                    None
                };
                if let Some(why) = bad {
                    fs.problem(&why);
                    tree.serious = true;
                    if mode == Mode::Yes {
                        println!("  REMOVED");
                        clear_dir_record(&mut buf, r);
                        changed = true;
                    }
                    continue;
                }
                if name == "." || name == ".." {
                    continue;
                }
                tree.names[target as usize] += 1;
                if fs.inodes[target as usize].kind == InodeKind::Dir {
                    if tree.reached[target as usize] {
                        fs.problem(&format!("directory {target} ({name}) has more than one name"));
                        tree.serious = true;
                        continue;
                    }
                    tree.reached[target as usize] = true;
                    queue.push((target, Some(dir)));
                }
            }
            if changed && fs.writable {
                fs.write_block(block, &buf).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// The inode directory `dir`'s `..` record names, if it has one.
fn dotdot(fs: &Fs, dir: u32) -> Option<u32> {
    let (data, _) = fs.blocks_of(&fs.inodes[dir as usize]).ok()?;
    for block in data {
        let buf = fs.read_block(block).ok()?;
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&buf, r) && dir_record_name(&buf, r) == b".." {
                return Some(dir_record_inode(&buf, r));
            }
        }
    }
    None
}

/// Points directory `dir`'s `..` record at `parent`.
fn set_dotdot(fs: &Fs, dir: u32, parent: u32) -> Result<(), String> {
    let (data, _) = fs.blocks_of(&fs.inodes[dir as usize]).map_err(|b| format!("bad block {b}"))?;
    for block in data {
        let mut buf = fs.read_block(block).map_err(|e| e.to_string())?;
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&buf, r) && dir_record_name(&buf, r) == b".." {
                write_dir_record(&mut buf, r, b"..", parent);
                return fs.write_block(block, &buf).map_err(|e| e.to_string());
            }
        }
    }
    Ok(())
}

/// `/lost+found`: the root's record of that name, if it's a directory phase 2 reached.
fn find_lost_found(fs: &Fs, tree: &Tree) -> Result<Option<u32>, String> {
    let (data, _) = fs.blocks_of(&fs.inodes[ROOT_INODE as usize]).map_err(|b| format!("bad block {b}"))?;
    for block in data {
        let buf = fs.read_block(block).map_err(|e| e.to_string())?;
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&buf, r) && dir_record_name(&buf, r) == b"lost+found" {
                let n = dir_record_inode(&buf, r);
                let ok = (n as usize) < fs.inodes.len() && fs.inodes[n as usize].kind == InodeKind::Dir && tree.reached[n as usize];
                return Ok(ok.then_some(n));
            }
        }
    }
    Ok(None)
}

/// A free block (not in `used`), now marked used; the bitmap is rebuilt in phase 5.
fn take_block(used: &mut [bool]) -> Option<u32> {
    let n = used.iter().rposition(|&u| !u)?;
    used[n] = true;
    Some(n as u32)
}

/// Adds the record `name -> target` to directory `dir`, growing it by a block (direct pointers
/// only) if it's full. `false` when it can't grow.
fn insert_record(fs: &mut Fs, used: &mut [bool], dir: u32, name: &[u8], target: u32) -> Result<bool, String> {
    let (data, _) = fs.blocks_of(&fs.inodes[dir as usize]).map_err(|b| format!("bad block {b}"))?;
    for block in data {
        let mut buf = fs.read_block(block).map_err(|e| e.to_string())?;
        if let Some(r) = (0..RECORDS_PER_BLOCK).find(|&r| !dir_record_used(&buf, r)) {
            write_dir_record(&mut buf, r, name, target);
            fs.write_block(block, &buf).map_err(|e| e.to_string())?;
            return Ok(true);
        }
    }
    let Some(slot) = (0..DIRECT_BLOCKS).find(|&i| fs.inodes[dir as usize].direct[i] == NO_BLOCK) else {
        return Ok(false);
    };
    let Some(block) = take_block(used) else { return Ok(false) };
    let mut buf = [0u8; BLOCK_SIZE];
    write_dir_record(&mut buf, 0, name, target);
    fs.write_block(block, &buf).map_err(|e| e.to_string())?;
    fs.inodes[dir as usize].direct[slot] = block;
    fs.dirty_inodes.insert(dir);
    Ok(true)
}

/// Makes `/lost+found` (mode 0700) in a free inode slot and a free block, as newfs would have.
fn make_lost_found(fs: &mut Fs, tree: &mut Tree, used: &mut [bool]) -> Result<Option<u32>, String> {
    let Some(n) = (1..fs.inodes.len() as u32).find(|&n| fs.inodes[n as usize].kind == InodeKind::Free) else {
        return Ok(None);
    };
    let Some(block) = take_block(used) else { return Ok(None) };
    let mut buf = [0u8; BLOCK_SIZE];
    for (r, (name, target)) in [(&b"."[..], n), (&b".."[..], ROOT_INODE)].into_iter().enumerate() {
        write_dir_record(&mut buf, r, name, target);
    }
    fs.write_block(block, &buf).map_err(|e| e.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut inode = Inode::new(InodeKind::Dir, now);
    inode.direct[0] = block;
    inode.mode = 0o700;
    fs.inodes[n as usize] = inode;
    fs.dirty_inodes.insert(n);
    if !insert_record(fs, used, ROOT_INODE, b"lost+found", n)? {
        fs.inodes[n as usize] = Inode::FREE;
        return Ok(None);
    }
    tree.reached[n as usize] = true;
    tree.names[n as usize] = 1;
    println!("CREATED /lost+found (inode {n})");
    Ok(Some(n))
}

/// Makes `/lost+found` the first time it's needed, if it's missing (not under `-n`).
fn ensure_lost_found(fs: &mut Fs, tree: &mut Tree, lost: &mut LostFound, used: &mut [bool], mode: Mode) -> Result<(), String> {
    if mode != Mode::No && lost.inode.is_none() && !lost.tried {
        lost.tried = true;
        lost.inode = make_lost_found(fs, tree, used)?;
    }
    Ok(())
}

/// Gives inode `n` the name `#<n>` in `/lost+found` (made if need be), counting it. Under `-n`
/// only says where it would go. `None` when there's no lost+found and none can be made.
fn reconnect(
    fs: &mut Fs,
    tree: &mut Tree,
    lost: &mut LostFound,
    used: &mut [bool],
    n: u32,
    mode: Mode,
) -> Result<Option<u32>, String> {
    if mode == Mode::No {
        tree.names[n as usize] += 1;
        return Ok(Some(lost.inode.unwrap_or(ROOT_INODE)));
    }
    ensure_lost_found(fs, tree, lost, used, mode)?;
    let Some(lf) = lost.inode else { return Ok(None) };
    if !insert_record(fs, used, lf, format!("#{n}").as_bytes(), n)? {
        return Ok(None);
    }
    tree.names[n as usize] += 1;
    Ok(Some(lf))
}

fn usage() -> ExitCode {
    eprintln!("usage: fsck_oxfs [-fnpy] device");
    ExitCode::from(EXIT_USAGE)
}

pub(crate) fn main() -> ExitCode {
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
    let mut block = [0u8; BLOCK_SIZE];
    dev.read_exact_at(&mut block, 0).map_err(|e| format!("can't read the superblock: {e}"))?;
    let sb = match Superblock::decode(&block) {
        Ok(sb) => sb,
        Err(SuperblockError::NotOxfs) => return Err("not an oxfs file system (no superblock)".into()),
        Err(SuperblockError::Version(v)) => {
            return Err(format!("superblock version {v}; this fsck_oxfs reads {SUPERBLOCK_VERSION}"));
        }
    };
    if sb.clean && mode == Mode::Preen && !force {
        println!("{device}: clean");
        return Ok(EXIT_OK);
    }
    let data_blocks = sb.data_blocks;
    let bitmap_blocks = sb.bitmap_blocks();
    let count = sb.inode_count;
    let mut fs = Fs {
        dev,
        writable,
        data_blocks,
        data_offset: sb.data_block_offset(),
        bitmap_blocks,
        sb,
        inode_file: sb.inode_file,
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
    let mut data = [0u8; BLOCK_SIZE];
    for n in 0..count {
        let Some(&block) = inode_file_data.get(n as usize / INODES_PER_BLOCK) else {
            return Err(format!("the inode file is shorter than its {count} inodes"));
        };
        let off = n as usize % INODES_PER_BLOCK * INODE_STRIDE;
        if off == 0 {
            data = fs.read_block(block).map_err(|e| e.to_string())?;
        }
        fs.inodes.push(unpack_inode(&data[off..off + INODE_STRIDE]));
    }
    let mut serious = false;

    println!("** Phase 1 - Check Blocks and Sizes");
    let mut owner: BTreeMap<u32, u32> = BTreeMap::new();
    for b in inode_file_data.iter().chain(&inode_file_index) {
        owner.insert(*b, u32::MAX);
    }
    for n in 0..count {
        if fs.inodes[n as usize].kind == InodeKind::Free {
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
                fs.inodes[n as usize] = Inode::FREE;
                fs.dirty_inodes.insert(n);
            }
        }
    }

    println!("** Phase 2 - Check Pathnames");
    if fs.inodes.get(ROOT_INODE as usize).is_none_or(|i| i.kind != InodeKind::Dir) {
        return Err("the root inode isn't a directory".into());
    }
    let mut tree = Tree { names: vec![0; count as usize], reached: vec![false; count as usize], serious: false };
    tree.reached[ROOT_INODE as usize] = true;
    walk(&mut fs, &mut tree, ROOT_INODE, Some(ROOT_INODE), mode)?;
    serious |= tree.serious;

    // Preen repairs only what a crash leaves; past phases 1-2 it would act on a tree it can't
    // trust (a broken record makes a whole directory look unreferenced). Stop with nothing
    // written.
    if serious && mode == Mode::Preen {
        println!("\nUNEXPECTED INCONSISTENCY; RUN fsck_oxfs MANUALLY (with -y to repair).");
        return Ok(EXIT_UNRESOLVED);
    }

    println!("** Phase 3 - Check Connectivity");
    // Blocks in use, for growing or making lost+found: what phase 1 found held.
    let mut used: Vec<bool> = vec![false; data_blocks as usize];
    for &b in owner.keys() {
        used[b as usize] = true;
    }
    let mut lost = LostFound { inode: find_lost_found(&fs, &tree)?, tried: false };
    // Directories first, each at the top of the subtree that lost its way to the root: a directory
    // whose `..` names another unreachable one comes back through it. Its contents are walked as
    // phase 2 walks the tree, so they have their names again.
    loop {
        let pending: Vec<u32> = (1..count)
            .filter(|&n| fs.inodes[n as usize].kind == InodeKind::Dir && !tree.reached[n as usize])
            .collect();
        let Some(&first) = pending.first() else { break };
        let top = pending
            .iter()
            .copied()
            .find(|&n| !dotdot(&fs, n).is_some_and(|p| p != n && pending.contains(&p)))
            .unwrap_or(first);
        tree.reached[top as usize] = true;
        ensure_lost_found(&mut fs, &mut tree, &mut lost, &mut used, mode)?;
        print!("UNREF directory {top}");
        let parent = match reconnect(&mut fs, &mut tree, &mut lost, &mut used, top, mode)? {
            Some(lf) => {
                println!("{}", if mode == Mode::No { " (would RECONNECT)" } else { " (RECONNECTED)" });
                if fs.writable {
                    set_dotdot(&fs, top, lf)?;
                }
                Some(lf)
            }
            None => {
                println!(" (NO lost+found; LEFT ALONE)");
                None
            }
        };
        fs.errors += 1;
        let expected_parent = if fs.writable { parent } else { None };
        walk(&mut fs, &mut tree, top, expected_parent, mode)?;
    }
    // Then files: one still linked lost its name to the crash and goes to lost+found; one with no
    // links left was unlinked while open, and is freed, as the kernel's orphan sweep would.
    for n in 1..count {
        let inode = &fs.inodes[n as usize];
        if inode.kind == InodeKind::Free || inode.kind == InodeKind::Dir || tree.names[n as usize] > 0 {
            continue;
        }
        fs.errors += 1;
        if inode.nlink == 0 {
            println!("UNREF inode {n}{}", if mode == Mode::No { "" } else { " (CLEARED)" });
            if mode != Mode::No {
                fs.inodes[n as usize] = Inode::FREE;
                fs.dirty_inodes.insert(n);
            }
            continue;
        }
        ensure_lost_found(&mut fs, &mut tree, &mut lost, &mut used, mode)?;
        print!("UNREF inode {n}");
        match reconnect(&mut fs, &mut tree, &mut lost, &mut used, n, mode)? {
            Some(_) => println!("{}", if mode == Mode::No { " (would RECONNECT)" } else { " (RECONNECTED)" }),
            None => println!(" (NO lost+found; LEFT ALONE)"),
        }
    }

    println!("** Phase 4 - Check Reference Counts");
    for n in 0..count {
        let inode = &fs.inodes[n as usize];
        if inode.kind == InodeKind::Free {
            continue;
        }
        let want = if inode.kind == InodeKind::Dir { 1 } else { tree.names[n as usize].max(1) as u16 };
        if inode.nlink != want {
            println!(
                "LINK COUNT inode {n}: {} should be {want}{}",
                inode.nlink,
                if mode == Mode::No { "" } else { " (ADJUSTED)" }
            );
            fs.errors += 1;
            if mode != Mode::No {
                fs.inodes[n as usize].nlink = want;
                fs.dirty_inodes.insert(n);
            }
        }
    }

    println!("** Phase 5 - Check Block Bitmap");
    let mut used = vec![false; data_blocks as usize];
    for b in inode_file_data.iter().chain(&inode_file_index) {
        used[*b as usize] = true;
    }
    for inode in fs.inodes.iter().filter(|i| i.kind != InodeKind::Free) {
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
        let mut blocks: BTreeMap<u32, [u8; BLOCK_SIZE]> = BTreeMap::new();
        for &n in &fs.dirty_inodes {
            let Some((block, off)) = fs.inode_location(n) else { continue };
            if !blocks.contains_key(&block) {
                blocks.insert(block, fs.read_block(block).map_err(|e| e.to_string())?);
            }
            pack_inode(&fs.inodes[n as usize], &mut blocks.get_mut(&block).unwrap()[off..off + INODE_STRIDE]);
        }
        for (block, data) in &blocks {
            fs.write_block(*block, data).map_err(|e| e.to_string())?;
        }
    }

    let in_use = fs.inodes.iter().filter(|i| i.kind != InodeKind::Free).count();
    println!("{in_use} files, {} used, {free} free", data_blocks as u64 - free);
    if serious && mode != Mode::Yes {
        println!("\nUNEXPECTED INCONSISTENCY; RUN fsck_oxfs MANUALLY (with -y to repair).");
        return Ok(EXIT_UNRESOLVED);
    }
    if fs.writable {
        let mut block = [0u8; BLOCK_SIZE];
        Superblock { clean: true, ..fs.sb }.encode(&mut block);
        fs.write_device_block(0, &block).map_err(|e| e.to_string())?;
        if fs.errors > 0 {
            println!("\n***** FILE SYSTEM WAS MODIFIED *****");
        }
    } else if fs.errors > 0 {
        return Ok(EXIT_UNRESOLVED);
    }
    Ok(EXIT_OK)
}
