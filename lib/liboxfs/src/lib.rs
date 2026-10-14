//! oxfs's on-disk format (OxideBSD-doc `RAM_FLOOR.md` §4.1), shared by the oxfs kernel module
//! (`sys/modules/oxfs`), the kernel's partition code (`sys/drivers/part.rs`), `fsck_oxfs(8)` and
//! the host image tools, so none of them keeps its own copy of a layout constant or a pack
//! routine. A change to anything here changes the format: bump `SUPERBLOCK_VERSION`.
//!
//! `no_std` and allocation-free (kernel modules have no `alloc`); builds for the kernel, the
//! target and the host alike.

#![no_std]

pub const BLOCK_SIZE: usize = 4096;
/// The mode every fresh inode starts with, before `chmod` or a creation mode sets it.
pub const FIXED_PERM: u32 = 0o755;
pub const BITS_PER_BITMAP_BLOCK: u32 = (BLOCK_SIZE * 8) as u32;
/// Block numbers from here up belong to no disk: the largest oxfs is just under this many data
/// blocks (~15 TiB), and the oxfs module numbers its in-memory tmpfs blocks from here.
pub const MAX_DISK_BLOCKS: u32 = 0xF000_0000;

pub const DIRECT_BLOCKS: usize = 12;
pub const PTRS_PER_INDIRECT: usize = BLOCK_SIZE / 4;
/// A double-indirect block's own fan-out: `PTRS_PER_INDIRECT` pointers to *index* blocks, each in
/// turn holding `PTRS_PER_INDIRECT` pointers to real data blocks -- `1024 * 1024 = 1,048,576` data
/// blocks reachable through one double-indirect pointer, i.e. exactly `1024^2 * BLOCK_SIZE` = 4
/// GiB. See `Inode::double_indirect`'s own doc comment for why this (and not a bigger, triple-
/// indirect scheme) is the right amount of addressing to add.
pub const PTRS_PER_DOUBLE_INDIRECT: usize = PTRS_PER_INDIRECT * PTRS_PER_INDIRECT;
/// Real per-file addressing ceiling once `Inode::double_indirect` is in play: `DIRECT_BLOCKS` +
/// one single-indirect block's worth + one double-indirect block's worth of data blocks, all
/// `BLOCK_SIZE` bytes each -- `(12 + 1024 + 1048576) * 4096` = 4,299,198,464 bytes, ~4.1 GiB.
/// Informational only (nothing indexes by it directly; `inode_block_at`/`inode_ensure_block_at`
/// derive the same three tiers from `DIRECT_BLOCKS`/`PTRS_PER_INDIRECT`/`PTRS_PER_DOUBLE_INDIRECT`
/// directly) -- kept as a single named place this file's own doc comments can point at.
pub const MAX_FILE_SIZE: usize =
    (DIRECT_BLOCKS + PTRS_PER_INDIRECT + PTRS_PER_DOUBLE_INDIRECT) * BLOCK_SIZE;
/// Sentinel for "no block"/"no indirect block" -- block numbers are plain indices into `BLOCKS`
/// starting at `0` (unlike FAT32's cluster numbering, which reserves `0`/`1`), so `0` itself can't
/// double as the sentinel the way it does there.
pub const NO_BLOCK: u32 = u32::MAX;

pub const ROOT_INODE: u32 = 0;

// --- Real disk persistence (see src/ata.rs) --------------------------------------------------
//
// Physical disk block layout: block `0` is the superblock (which also holds the inode file's own
// inode record, see `InodeTable`), `[BITMAP_START,
// BITMAP_START + bitmap_blocks())` is the block-used bitmap, and data starts at
// `data_block_offset()` -- data block `i` is device block `data_block_offset() + i`. Inodes are packed at a fixed
// 128-byte stride, `INODES_PER_BLOCK` to a block of the inode file (real packed content is 106 bytes -- 1 tag + 8 size + 48 direct + 4 indirect + 4
// double_indirect + 2 mode + 4 uid + 4 gid + 2 nlink + 4 rdev + 1 device_char + 8 mtime + 8 ctime +
// 8 atime -- rounded up to a power-of-two stride that divides BLOCK_SIZE evenly, leaving headroom
// for future fields); one bitmap bit per data block, sized with the filesystem (`layout_for`).

/// Marks a real, formatted oxfs disk. Absence/mismatch (an unformatted/all-zero disk, or one some
/// other filesystem wrote) means the same thing either way: format fresh rather than try to
/// interpret unknown content -- see `mount_from_disk`.
pub const SUPERBLOCK_MAGIC: [u8; 4] = *b"OXFS";
/// Bumped 1 -> 2 for the real max-file-size redesign: `Inode`'s own packed on-disk shape changed
/// (`size` widened to 64-bit, a new `double_indirect` block pointer added -- see that field's own
/// doc comment), and the block-used bitmap's own on-disk span changed (`BITMAP_BLOCKS`, no longer
/// hardcoded to one block). A disk formatted under version 1 has the wrong bytes at every offset
/// this build now expects -- `mount_from_disk`'s own layout check (below) already treats any
/// mismatch here exactly like a `NUM_BLOCKS` change: a clean, automatic reformat, not
/// a crash or silent misread. Any content on an existing `target/oxfs_disk.img` besides the
/// seeded-at-boot roster (BusyBox/musl/Clang/LLVM/POSIX corpus, all reseeded fresh on format) is
/// lost.
///
/// Bumped 2 -> 3 for `NAME_MAX` 40 -> 255 (see that constant's own doc comment) -- `DIR_RECORD_SIZE`
/// changed (`6 + NAME_MAX`, 46 -> 261 bytes), so every existing directory record's on-disk stride
/// is wrong under the old layout. Same automatic-reformat treatment as the 1 -> 2 bump.
///
/// Bumped 3 -> 4 for the dynamic inode table: inodes live in an inode file in the block pool
/// (`InodeTable`), whose own inode record is in the superblock; the fixed inode-table region after
/// the superblock is gone, so the bitmap now starts at block 1.
///
/// Bumped 4 -> 5 for `Inode::shm`, one byte after `atime` in the packed inode.
///
/// Bumped 5 -> 6 for the buffer cache (`OxideBSD-doc/RAM_FLOOR.md` §3.1.3): the filesystem spans
/// the whole device, its size (in the superblock) sets the bitmap's length, and data starts after
/// that many bitmap blocks instead of after a fixed 1 GiB pool's.
pub const SUPERBLOCK_VERSION: u32 = 6;

/// Real packed size (see the section doc comment above) -- **never** a raw transmute/memcpy of
/// `Inode` itself, since it isn't `#[repr(C)]` and `InodeKind` has no explicit discriminant, so its
/// true in-memory layout isn't guaranteed across compiler versions/profiles. `pack_inode`/
/// `unpack_inode` do this by hand instead, the same raw-byte-offset idiom `write_dir_record`/
/// `dir_record_inode` already established for directory records.
pub const INODE_STRIDE: usize = 128;
pub const INODES_PER_BLOCK: usize = BLOCK_SIZE / INODE_STRIDE;
/// The bitmap's first device block, right after the superblock.
pub const BITMAP_START: u32 = 1;

// 26 -> 40 (`DIR_RECORD_SIZE` 32 -> 46 alongside it, `6 + NAME_MAX`): the full Open POSIX Test
// Suite corpus (see `build.rs`'s `discover_posix_test_files`) seeds real directory names up to 32
// bytes (`pthread_mutexattr_setprioceiling`/`pthread_mutexattr_getprioceiling`) -- found live as a
// real `module_init` panic when the pilot corpus expanded past the old 488-file curated subset
// (which happened to never include a name that long).
//
// 40 -> 255 (real musl `NAME_MAX`, `external/mit/musl/include/limits.h`) -- found live
// self-hosting bmake's own build (see CLAUDE.md's bmake section): `dir_insert`'s own length check
// silently rejected `varname-dot-make-meta-ignore_patterns.exp` (41 bytes, one past the old
// limit), and returning `EINVAL` for it (see that check's own fix, `NameTooLong` not
// `InvalidPath`) was enough to abort BusyBox tar's whole extraction rather than being skipped or
// reported as `ENAMETOOLONG`. Matching musl's own compiled-in `NAME_MAX` closes the mismatch for
// real, not just this one filename -- any future seeded/user-created name up to what musl itself
// tells userland is legal should actually be legal here too. `RECORDS_PER_BLOCK` drops from 89 to
// 15 as a result (`DIR_RECORD_SIZE` growing 46 -> 261) -- a real, accepted directory-density
// tradeoff for genuinely supporting POSIX's real name-length ceiling, not a bug.
pub const NAME_MAX: usize = 255;
pub const DIR_RECORD_SIZE: usize = 6 + NAME_MAX;
pub const RECORDS_PER_BLOCK: usize = BLOCK_SIZE / DIR_RECORD_SIZE;

/// `(data blocks, bitmap blocks)` for a device of `device_blocks` blocks: the superblock, then
/// as few bitmap blocks as cover the data blocks after them. Capped below `MAX_DISK_BLOCKS`.
pub fn layout_for(device_blocks: u64) -> (u32, u32) {
    let usable = device_blocks.saturating_sub(BITMAP_START as u64).min(MAX_DISK_BLOCKS as u64 - 1);
    let bitmap = usable.div_ceil(BITS_PER_BITMAP_BLOCK as u64 + 1);
    ((usable - bitmap) as u32, bitmap as u32)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    Free,
    File,
    Dir,
    /// A real symlink -- its target path string is stored exactly like a regular file's content
    /// (`write_inode_data`/`read_inode_at`, `inode.size` = target byte length), no separate
    /// storage mechanism needed. See `resolve_path_impl`'s own doc comment for how this is
    /// followed during path resolution.
    Symlink,
    /// A real, listable device node (`SYS_MKNOD`) -- unlike `/dev/{random,urandom,null,zero}`'s
    /// existing magic-path interception in `dev_open` (not backed by any inode at all), this is a
    /// genuine directory entry reporting `S_IFCHR`/`S_IFBLK` and a real `st_rdev` via `stat`. See
    /// `oxfs_mknod`'s own doc comment for the (deliberately small) set of major:minor pairs that
    /// actually work when opened.
    Device,
    /// A named pipe (`mkfifo`). Holds no data of its own: `open()` hands it to the kernel's pipe
    /// code, keyed by inode number.
    Fifo,
    /// A local socket's name (`bind(2)` on an `AF_UNIX` path, UNIX.md §5.2). Holds no data; the
    /// kernel maps the inode number to the socket bound to it, if any.
    Socket,
}

#[derive(Clone, Copy)]
pub struct Inode {
    pub kind: InodeKind,
    /// Real content length in bytes. Widened `u32` -> `u64` alongside `double_indirect` below --
    /// `MAX_FILE_SIZE` (~4.1 GiB) exceeds `u32::MAX` by design (a 4 GiB file wouldn't otherwise be
    /// representable at all), so this has to grow with the addressing scheme it now needs to
    /// describe.
    pub size: u64,
    pub direct: [u32; DIRECT_BLOCKS],
    pub indirect: u32,
    /// Real double-indirect block pointer, added alongside `size`'s widening to close this
    /// filesystem's real max-file-size gap: `direct` + `indirect` alone address only
    /// `(DIRECT_BLOCKS + PTRS_PER_INDIRECT) * BLOCK_SIZE` ~= 4.04 MiB per file -- an arbitrary,
    /// far-too-low architectural cap unrelated to how much of the real block pool is actually
    /// free. One double-indirect pointer (an index block of `PTRS_PER_INDIRECT` pointers, each to
    /// its own index block of `PTRS_PER_INDIRECT` pointers to real data blocks) adds exactly
    /// `PTRS_PER_INDIRECT^2 * BLOCK_SIZE` = 4 GiB of further addressable space -- chosen
    /// specifically because `1024^2` (`PTRS_PER_INDIRECT` squared) lands on exactly 4 GiB with
    /// this filesystem's existing `BLOCK_SIZE`/4-byte-pointer shape, satisfying "at least 4 GiB"
    /// with one added tier rather than needing a third, triple-indirect one. See
    /// `inode_block_at`/`inode_ensure_block_at` for how the three tiers (direct, single-, double-
    /// indirect) are actually walked/allocated, and `MAX_FILE_SIZE`'s own doc comment for the real,
    /// combined total. `NO_BLOCK` until a file's own content actually reaches past the single-
    /// indirect tier -- the overwhelming majority of real files here never allocate this at all.
    pub double_indirect: u32,
    /// Real per-inode permission bits, setuid/setgid/sticky included (creation takes the low nine,
    /// less the umask; `chmod` sets all twelve, see `set_mode`). Defaults to `FIXED_PERM` (`0o755`),
    /// the same fixed value every inode used to report unconditionally before this field existed
    /// -- so a freshly seeded/created file behaves identically to the old hardcoded-everywhere
    /// scheme until something actually calls `chmod`.
    pub mode: u16,
    /// Real per-inode ownership -- `0` (root) by default, matching every seeded boot file (there's
    /// no login mechanism, so root is the only uid that has ever created anything on this
    /// filesystem so far). See `check_access`'s own doc comment for how these two fields, plus the
    /// caller's own uid/gid (via `oxidebsd_current_uid`/`_gid`), combine into an actual permission
    /// decision.
    pub uid: u32,
    pub gid: u32,
    /// Real hard-link count -- meaningful only for `File`/`Device` (see `SYS_LINK`'s own doc
    /// comment); `Dir`/`Symlink` keep reporting their existing hardcoded `write_stat` values
    /// unchanged (real subdirectory-count-based `Dir` nlink stays a documented, separate gap).
    /// `Inode::new` seeds this to `1` (the one directory entry about to be inserted for it);
    /// `write_stat` floors a decoded `0` (an on-disk inode written before this field existed, whose
    /// zero-padded stride tail decodes as `0`) back up to `1` rather than reporting a bogus
    /// zero-link count.
    pub nlink: u16,
    /// Packed major/minor for an `InodeKind::Device` entry (`0` for everything else) -- decoded
    /// from the caller's raw `dev` argument using the same formula musl's own
    /// `makedev()`/`major()`/`minor()` macros use. See `oxfs_mknod`'s own doc comment.
    pub rdev: u32,
    /// `true` for a character device, `false` for a block device -- only meaningful for
    /// `InodeKind::Device`.
    pub device_char: bool,
    /// Real, whole-second Unix epoch `st_mtime`/`st_ctime` (`oxidebsd_unix_time`, see that
    /// import's own doc comment) -- previously both hardcoded `0` in `write_stat` (no clock/RTC
    /// source existed at the time). `write_inode_data`/`resize_inode_data` are this filesystem's
    /// only two real content-mutation choke points (every write -- a plain `write()`'s deferred
    /// commit, `fsync`/`close`, and a real fd-backed `MAP_SHARED` mapping's own `msync`/`munmap`/
    /// exit writeback via `oxfs_inode_content_write` -- ultimately goes through one of them), so
    /// bumping both there covers every real write path uniformly, mmap included (`mmap/14-1.c` in
    /// the POSIX conformance pilot). Real POSIX ties `st_mtime`/`st_ctime` to slightly different
    /// events (`st_ctime` also updates on a pure metadata change like `chmod`/`chown`, with no
    /// content write at all) -- not implemented here, a separate, narrower gap than what this field
    /// closes: nothing in this port's roster checks `st_ctime` after a metadata-only change.
    pub mtime: i64,
    pub ctime: i64,
    /// Real, whole-second Unix epoch `st_atime` -- previously a permanent `0` placeholder (see this
    /// field's own prior doc comment, now stale: "no test or real caller in this port needs it").
    /// `mmap/13-1.c` (Open POSIX Test Suite) is a genuine, real POSIX "shall" requirement this
    /// kernel was actually violating: "The initial read or write reference to a mapped region shall
    /// cause the file's st_atime field to be marked for update if it has not already been marked
    /// for update" (the same clause also explicitly permits marking it "at any time between the
    /// mmap() call and the corresponding munmap() call" -- this kernel doesn't do real demand
    /// paging for file-backed mmap (every covered page is eagerly populated at `mmap()` time, see
    /// `process::mm::do_mmap_file_backed`), so bumping atime at that one real population read,
    /// rather than tracking each page's own first-touch, is a spec-legal choice, not a shortcut).
    /// Bumped by `touch_atime` from two real read paths: `oxfs_read`'s own `OpenFile::FileRead` arm
    /// (a plain `read()`) and `oxfs_inode_content_read` (the `mmap` population/re-population read
    /// `process::mm::do_mmap_file_backed` calls by content identity, see that accessor's own doc
    /// comment) -- both real "read reference" events, not just this one pilot test's own narrow
    /// need. `touch_atime` skips the write-through if the whole-second value hasn't changed since
    /// the last touch (a real, common Unix optimization, not a fake pass condition -- POSIX only
    /// requires atime be "marked for update," not persisted with per-read precision).
    pub atime: i64,
    /// A POSIX shared memory object: a file created in `/dev/shm` (musl's `shm_open`). Set once at
    /// creation and kept after `shm_unlink`, since the usual idiom unlinks at once and keeps using
    /// the fd; `process::mm::do_mmap_file_backed` bounds a mapping of one at its size. Packed after
    /// `atime`; a slot written before it existed reads `false`.
    pub shm: bool,
}

impl Inode {
    pub const FREE: Inode = Inode {
        kind: InodeKind::Free,
        size: 0,
        direct: [NO_BLOCK; DIRECT_BLOCKS],
        indirect: NO_BLOCK,
        double_indirect: NO_BLOCK,
        mode: FIXED_PERM as u16,
        uid: 0,
        gid: 0,
        nlink: 0,
        rdev: 0,
        device_char: false,
        mtime: 0,
        ctime: 0,
        atime: 0,
        shm: false,
    };

    /// A fresh inode of `kind` with one link, its times all `now` (Unix seconds).
    pub fn new(kind: InodeKind, now: i64) -> Inode {
        Inode {
            kind,
            size: 0,
            direct: [NO_BLOCK; DIRECT_BLOCKS],
            indirect: NO_BLOCK,
            double_indirect: NO_BLOCK,
            mode: FIXED_PERM as u16,
            uid: 0,
            gid: 0,
            nlink: 1,
            rdev: 0,
            device_char: false,
            mtime: now,
            ctime: now,
            atime: now,
            shm: false,
        }
    }
}

pub fn dir_record_used(block: &[u8; BLOCK_SIZE], idx: usize) -> bool {
    block[idx * DIR_RECORD_SIZE] != 0
}

pub fn dir_record_name_len(block: &[u8; BLOCK_SIZE], idx: usize) -> usize {
    block[idx * DIR_RECORD_SIZE + 1] as usize
}

pub fn dir_record_name(block: &[u8; BLOCK_SIZE], idx: usize) -> &[u8] {
    let len = dir_record_name_len(block, idx);
    let start = idx * DIR_RECORD_SIZE + 6;
    &block[start..start + len]
}

pub fn dir_record_inode(block: &[u8; BLOCK_SIZE], idx: usize) -> u32 {
    let off = idx * DIR_RECORD_SIZE + 2;
    u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]])
}

pub fn write_dir_record(block: &mut [u8; BLOCK_SIZE], idx: usize, name: &[u8], inode: u32) {
    let off = idx * DIR_RECORD_SIZE;
    block[off] = 1;
    block[off + 1] = name.len() as u8;
    block[off + 2..off + 6].copy_from_slice(&inode.to_le_bytes());
    block[off + 6..off + 6 + name.len()].copy_from_slice(name);
}

pub fn clear_dir_record(block: &mut [u8; BLOCK_SIZE], idx: usize) {
    block[idx * DIR_RECORD_SIZE] = 0;
}

/// Packs one `Inode` into `out` (exactly `INODE_STRIDE` bytes) using explicit byte offsets, the
/// same idiom `write_dir_record` already established for directory records -- see
/// `INODE_STRIDE`'s own doc comment for why this can't be a raw transmute/memcpy.
pub fn pack_inode(inode: &Inode, out: &mut [u8]) {
    out[0] = match inode.kind {
        InodeKind::Free => 0,
        InodeKind::File => 1,
        InodeKind::Dir => 2,
        InodeKind::Symlink => 3,
        InodeKind::Device => 4,
        InodeKind::Fifo => 5,
        InodeKind::Socket => 6,
    };
    // `size` widened 4 -> 8 bytes (real `u64`, see `Inode::size`'s own doc comment) -- every offset
    // from here on shifts +4 relative to `SUPERBLOCK_VERSION`'s prior (version 1) on-disk shape.
    out[1..9].copy_from_slice(&inode.size.to_le_bytes());
    for (i, d) in inode.direct.iter().enumerate() {
        let off = 9 + i * 4;
        out[off..off + 4].copy_from_slice(&d.to_le_bytes());
    }
    let indirect_off = 9 + DIRECT_BLOCKS * 4;
    out[indirect_off..indirect_off + 4].copy_from_slice(&inode.indirect.to_le_bytes());
    // New field (see `Inode::double_indirect`'s own doc comment) -- inserted right after
    // `indirect`, shifting every following offset +4 again relative to version 1.
    let double_indirect_off = indirect_off + 4;
    out[double_indirect_off..double_indirect_off + 4]
        .copy_from_slice(&inode.double_indirect.to_le_bytes());
    let mode_off = double_indirect_off + 4;
    out[mode_off..mode_off + 2].copy_from_slice(&inode.mode.to_le_bytes());
    let uid_off = mode_off + 2;
    out[uid_off..uid_off + 4].copy_from_slice(&inode.uid.to_le_bytes());
    let gid_off = uid_off + 4;
    out[gid_off..gid_off + 4].copy_from_slice(&inode.gid.to_le_bytes());
    let nlink_off = gid_off + 4;
    out[nlink_off..nlink_off + 2].copy_from_slice(&inode.nlink.to_le_bytes());
    let rdev_off = nlink_off + 2;
    out[rdev_off..rdev_off + 4].copy_from_slice(&inode.rdev.to_le_bytes());
    let device_char_off = rdev_off + 4;
    out[device_char_off] = inode.device_char as u8;
    let mtime_off = device_char_off + 1;
    out[mtime_off..mtime_off + 8].copy_from_slice(&inode.mtime.to_le_bytes());
    let ctime_off = mtime_off + 8;
    out[ctime_off..ctime_off + 8].copy_from_slice(&inode.ctime.to_le_bytes());
    let atime_off = ctime_off + 8;
    out[atime_off..atime_off + 8].copy_from_slice(&inode.atime.to_le_bytes());
    let shm_off = atime_off + 8;
    out[shm_off] = inode.shm as u8;
    for b in &mut out[shm_off + 1..] {
        *b = 0;
    }
}

/// `pack_inode`'s inverse.
pub fn unpack_inode(data: &[u8]) -> Inode {
    let kind = match data[0] {
        1 => InodeKind::File,
        2 => InodeKind::Dir,
        3 => InodeKind::Symlink,
        4 => InodeKind::Device,
        5 => InodeKind::Fifo,
        6 => InodeKind::Socket,
        _ => InodeKind::Free,
    };
    let size = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let mut direct = [NO_BLOCK; DIRECT_BLOCKS];
    for (i, d) in direct.iter_mut().enumerate() {
        let off = 9 + i * 4;
        *d = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    }
    let indirect_off = 9 + DIRECT_BLOCKS * 4;
    let indirect = u32::from_le_bytes([
        data[indirect_off],
        data[indirect_off + 1],
        data[indirect_off + 2],
        data[indirect_off + 3],
    ]);
    let double_indirect_off = indirect_off + 4;
    let double_indirect = u32::from_le_bytes([
        data[double_indirect_off],
        data[double_indirect_off + 1],
        data[double_indirect_off + 2],
        data[double_indirect_off + 3],
    ]);
    let mode_off = double_indirect_off + 4;
    let mode = u16::from_le_bytes([data[mode_off], data[mode_off + 1]]);
    let uid_off = mode_off + 2;
    let uid = u32::from_le_bytes([
        data[uid_off],
        data[uid_off + 1],
        data[uid_off + 2],
        data[uid_off + 3],
    ]);
    let gid_off = uid_off + 4;
    let gid = u32::from_le_bytes([
        data[gid_off],
        data[gid_off + 1],
        data[gid_off + 2],
        data[gid_off + 3],
    ]);
    let nlink_off = gid_off + 4;
    let nlink = u16::from_le_bytes([data[nlink_off], data[nlink_off + 1]]);
    let rdev_off = nlink_off + 2;
    let rdev = u32::from_le_bytes([
        data[rdev_off],
        data[rdev_off + 1],
        data[rdev_off + 2],
        data[rdev_off + 3],
    ]);
    let device_char_off = rdev_off + 4;
    let device_char = data[device_char_off] != 0;
    let mtime_off = device_char_off + 1;
    let mtime = i64::from_le_bytes(data[mtime_off..mtime_off + 8].try_into().unwrap());
    let ctime_off = mtime_off + 8;
    let ctime = i64::from_le_bytes(data[ctime_off..ctime_off + 8].try_into().unwrap());
    // A pre-existing on-disk inode written before this field existed decodes a zeroed tail here --
    // an honest `0` (Unix epoch), not an invalid value the way a decoded `nlink == 0` would be, so
    // no flooring is needed the way Inode::nlink's own doc comment describes for that field.
    let atime_off = ctime_off + 8;
    let atime = i64::from_le_bytes(data[atime_off..atime_off + 8].try_into().unwrap());
    let shm = data[atime_off + 8] != 0;
    Inode {
        kind,
        size,
        direct,
        indirect,
        double_indirect,
        mode,
        uid,
        gid,
        nlink,
        rdev,
        device_char,
        mtime,
        ctime,
        atime,
        shm,
    }
}

// --- The superblock (device block 0) -------------------------------------------------------

/// Where the superblock keeps the disk inode file's own inode record.
pub const SB_INODE_FILE: usize = 128;
/// The superblock's state word: `SB_CLEAN` when the last shutdown was orderly.
pub const SB_STATE: usize = 20;
pub const SB_CLEAN: u32 = 1;

/// The superblock's fields, as `Superblock::decode` reads them and `encode` writes them.
#[derive(Clone, Copy)]
pub struct Superblock {
    /// Data blocks: the filesystem's size (`layout_for`).
    pub data_blocks: u32,
    /// Inode slots in the inode file.
    pub inode_count: u32,
    pub root_inode: u32,
    /// The last shutdown was orderly (`SB_CLEAN`).
    pub clean: bool,
    /// The inode file's own inode record.
    pub inode_file: Inode,
}

/// Why a superblock didn't decode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuperblockError {
    /// No `SUPERBLOCK_MAGIC`: not an oxfs (or never formatted).
    NotOxfs,
    /// Formatted by a build with another `SUPERBLOCK_VERSION`; carries that version.
    Version(u32),
}

impl Superblock {
    pub fn decode(block: &[u8; BLOCK_SIZE]) -> Result<Superblock, SuperblockError> {
        if block[0..4] != SUPERBLOCK_MAGIC {
            return Err(SuperblockError::NotOxfs);
        }
        let word = |off: usize| u32::from_le_bytes(block[off..off + 4].try_into().unwrap());
        if word(4) != SUPERBLOCK_VERSION {
            return Err(SuperblockError::Version(word(4)));
        }
        Ok(Superblock {
            data_blocks: word(8),
            inode_count: word(12),
            root_inode: word(16),
            clean: word(SB_STATE) == SB_CLEAN,
            inode_file: unpack_inode(&block[SB_INODE_FILE..SB_INODE_FILE + INODE_STRIDE]),
        })
    }

    pub fn encode(&self, block: &mut [u8; BLOCK_SIZE]) {
        block.fill(0);
        block[0..4].copy_from_slice(&SUPERBLOCK_MAGIC);
        block[4..8].copy_from_slice(&SUPERBLOCK_VERSION.to_le_bytes());
        block[8..12].copy_from_slice(&self.data_blocks.to_le_bytes());
        block[12..16].copy_from_slice(&self.inode_count.to_le_bytes());
        block[16..20].copy_from_slice(&self.root_inode.to_le_bytes());
        let state = if self.clean { SB_CLEAN } else { 0 };
        block[SB_STATE..SB_STATE + 4].copy_from_slice(&state.to_le_bytes());
        pack_inode(&self.inode_file, &mut block[SB_INODE_FILE..SB_INODE_FILE + INODE_STRIDE]);
    }

    /// Bitmap blocks for this filesystem: one bit per data block.
    pub fn bitmap_blocks(&self) -> u32 {
        self.data_blocks.div_ceil(BITS_PER_BITMAP_BLOCK)
    }

    /// Device block holding data block `0`: right after the superblock and the bitmap.
    pub fn data_block_offset(&self) -> u32 {
        BITMAP_START + self.bitmap_blocks()
    }
}

// --- Partition types (RAM_FLOOR.md §3.4.5) ---------------------------------------------------

/// oxfs's GPT partition type GUID, generated for OxideBSD (2026-10-13), as text:
/// `06026785-76ab-42c2-afe2-66ea3af562b8`.
pub const OXFS_TYPE_GUID: [u8; 16] =
    guid_bytes(0x0602_6785, 0x76ab, 0x42c2, [0xaf, 0xe2, 0x66, 0xea, 0x3a, 0xf5, 0x62, 0xb8]);
/// oxfs's MBR partition type byte.
pub const OXFS_MBR_TYPE: u8 = 0xA2;

/// A GUID's on-disk bytes: the first three fields little-endian, the rest as written.
pub const fn guid_bytes(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_round_trips() {
        let mut inode = Inode::new(InodeKind::Symlink, 1_760_000_000);
        inode.size = 5 << 30;
        inode.direct[3] = 77;
        inode.double_indirect = 9;
        inode.mode = 0o4755;
        inode.uid = 1001;
        inode.gid = 0;
        inode.nlink = 3;
        inode.rdev = 0x1234;
        inode.device_char = true;
        inode.atime = -5;
        inode.shm = true;
        let mut raw = [0xAAu8; INODE_STRIDE];
        pack_inode(&inode, &mut raw);
        let back = unpack_inode(&raw);
        let mut again = [0u8; INODE_STRIDE];
        pack_inode(&back, &mut again);
        assert_eq!(raw, again);
        assert!(back.kind == InodeKind::Symlink && back.size == 5 << 30 && back.shm);
    }

    #[test]
    fn superblock_round_trips() {
        let sb = Superblock {
            data_blocks: 200_000,
            inode_count: 4096,
            root_inode: ROOT_INODE,
            clean: true,
            inode_file: Inode::new(InodeKind::File, 0),
        };
        let mut block = [0u8; BLOCK_SIZE];
        sb.encode(&mut block);
        let back = Superblock::decode(&block).unwrap();
        assert_eq!((back.data_blocks, back.inode_count, back.clean), (200_000, 4096, true));
        assert_eq!(back.bitmap_blocks(), 7);
        assert_eq!(back.data_block_offset(), BITMAP_START + 7);
        block[4] ^= 1;
        assert_eq!(Superblock::decode(&block).err(), Some(SuperblockError::Version(SUPERBLOCK_VERSION ^ 1)));
        assert_eq!(Superblock::decode(&[0; BLOCK_SIZE]).err(), Some(SuperblockError::NotOxfs));
    }

    #[test]
    fn layout_covers_the_device() {
        for device in [2, 100, 32_769, 262_144, 1 << 30] {
            let (data, bitmap) = layout_for(device);
            assert!(data.div_ceil(BITS_PER_BITMAP_BLOCK) <= bitmap);
            assert!(BITMAP_START as u64 + bitmap as u64 + data as u64 <= device);
        }
    }

    #[test]
    fn dir_records() {
        let mut block = [0u8; BLOCK_SIZE];
        let long = [b'x'; NAME_MAX];
        write_dir_record(&mut block, RECORDS_PER_BLOCK - 1, &long, 42);
        assert!(dir_record_used(&block, RECORDS_PER_BLOCK - 1));
        assert_eq!(dir_record_name(&block, RECORDS_PER_BLOCK - 1), &long);
        assert_eq!(dir_record_inode(&block, RECORDS_PER_BLOCK - 1), 42);
        clear_dir_record(&mut block, RECORDS_PER_BLOCK - 1);
        assert!(!dir_record_used(&block, RECORDS_PER_BLOCK - 1));
    }
}
