//! `oxfs`: OxideBSD's disk file system (inodes with direct, single- and double-indirect block
//! pointers, directories as ordinary inodes holding fixed-size records).
//!
//! Since the VFS (OxideBSD-doc `VFS.md` §11 step 2b) this module serves vnode operations
//! (`vfs.rs`): the kernel does path lookup (`namei`), the path system calls, mounts and the cwd,
//! and asks oxfs for one directory's component (`vop_lookup`), a file's attributes, its contents.
//! A vnode's file ID is the inode number. What's left here is storage: blocks, inodes, directory
//! records.
//!
//! The on-disk format is `lib/liboxfs`'s. This module only mounts: a file system is made by
//! `newfs_oxfs(8)` or installed from a system image built by `makefs(8)` from
//! `distrib/install.mtree` (`OxideBSD-doc/RAM_FLOOR.md` §4). Each mount is its own `Fs`, so the
//! root and any number of other oxfs partitions may be mounted at once.
//!
//! **Storage**: blocks through the kernel's buffer cache (`buf.rs`), and inodes packed into an
//! inode file in that pool, which grows as needed (`InodeTable`). An inode addresses its data via `DIRECT_BLOCKS` direct block numbers, one
//! single-indirect block, and one double-indirect block -- `MAX_FILE_SIZE` (~4.1 GiB) is the
//! ceiling on any one file.
//!
//! **Directories are ordinary inodes** whose data blocks hold fixed `DIR_RECORD_SIZE`-byte records
//! (`{ used, name_len, inode, name: [u8; NAME_MAX] }`, `RECORDS_PER_BLOCK` per block); a directory
//! that fills its blocks grows another. **The root is inode `ROOT_INODE = 0`**, its `..` itself.
#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use kern_mod as _;

mod buf;
mod vfs;

// The on-disk format: layout constants, `Inode`, `pack_inode`/`unpack_inode`, directory records
// and the superblock (`lib/liboxfs`, shared with fsck_oxfs and the host tools).
use oxfs_format::*;

unsafe extern "C" {
    fn oxidebsd_log(ptr: *const u8, len: u64);
    /// Moves up to `len` bytes between this module's buffer `kbuf` and a read or write transfer
    /// (`uio`, opaque here; kernel tree: `crate::kern::subr_uio`, USERMEM.md §4.4). The count
    /// moved, or `-errno`.
    fn oxidebsd_uiomove(kbuf: *mut u8, len: u64, uio: u64) -> i64;
    /// Bytes a transfer still has to move.
    fn oxidebsd_uio_resid(uio: u64) -> u64;
    /// A transfer's file offset: every read and write here is at one.
    fn oxidebsd_uio_offset(uio: u64) -> u64;
    /// Moves a transfer to `offset` (`O_APPEND`: the end of the file).
    fn oxidebsd_uio_set_offset(uio: u64, offset: u64);
    /// Real Unix epoch seconds, whole-second precision -- see `sys/cpu/rtc.rs`'s own doc comment
    /// on `oxidebsd_unix_time`. Backs real `st_mtime`/`st_ctime` (`write_inode_data`/
    /// `resize_inode_data`).
    fn oxidebsd_unix_time() -> i64;
    /// Makes every call into this module take the kernel's filesystem lock.
    fn oxidebsd_module_serialize();
    /// Tells the kernel whether the root is mounted read-write (`1`) or read-only.
    fn oxidebsd_root_mounted_rw(rw: u64);
}

/// Changes whenever a file this module embeds changes (`build.rs`'s `build_module_crate`); reading
/// it makes rustc rebuild the module then, which the embedded paths alone didn't reliably do.

/// Real POSIX `st_mode` file-type bits (`S_IFREG`/`S_IFDIR`/`S_IFLNK`) -- these are the type bits
/// only, ORed with an inode's own real `mode` field (permission bits) when building a `stat`
/// result. `FIXED_PERM` remains the default *value* every fresh inode's `mode` starts at
/// (`0o755`), not a hardcoded stand-in for permissions any more -- see `SYS_CHMOD`'s own doc
/// comment (`oxfs_chmod`) for how it actually changes now.
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
/// Real POSIX value, no Linux/BSD divergence -- backs `InodeKind::Symlink`.
const S_IFLNK: u32 = 0o120000;
/// Real POSIX values, no Linux/BSD divergence -- back `InodeKind::Device`'s two flavors (see
/// `oxfs_mknod`'s own doc comment).
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;

const ENOENT: i64 = 2;
const ENOSPC: i64 = 28;
const EIO: i64 = 5;
/// Real value, no Linux/BSD divergence -- returned when a real, whole path argument exceeds
/// `OXFS_PATH_MAX` (see that constant's own doc comment). Distinct from `NAME_MAX`'s own
/// per-component `InvalidPath`/`EINVAL` check in `resolve_parent` below -- real POSIX uses
/// `ENAMETOOLONG` specifically for *this* case.
const ENAMETOOLONG: i64 = 36;

/// One mounted oxfs: its device and what mounting read from it (OxideBSD-doc `RAM_FLOOR.md` §4.8).
/// The kernel's mount points at it (`mnt_data`, `vfs::fs`); each mount has its own, so any number
/// of oxfs partitions may be mounted at once, each on its own device. Everything else lives on the
/// disk and comes in through the cache (`buf`).
pub(crate) struct Fs {
    /// The block device (`MountArgs::dev`).
    dev: u64,
    /// The kernel's mount, whose vnodes `vfs::inode_busy` and `vfs::inode_freed` ask about.
    mp: *mut vfs_if::Mount,
    /// Whether this is the root (`MNT_ROOTFS`): the kernel learns its read-write state from oxfs.
    root: bool,
    /// The size in data blocks, from the superblock. (Until the 128 MB floor,
    /// `OxideBSD-doc/RAM_FLOOR.md` §3.1.3, this was a compile-time 1 GiB `NUM_BLOCKS`, every block
    /// of it held in RAM.)
    data_blocks: u32,
    /// Bitmap blocks: one bit per data block, `BITS_PER_BITMAP_BLOCK` to a block.
    bitmap_blocks: u32,
    /// Device block holding data block `0`: right after the superblock and the bitmap.
    data_block_offset: u32,
    /// Free blocks in each bitmap block (`BITS_PER_BITMAP_BLOCK` data blocks), resident so the
    /// allocator and `statfs` never read a full bitmap block to learn it's full. Counted at mount.
    free_counts: Vec<u32>,
    inodes: InodeTable,
    /// The regular file whose writes are being delayed (§3.3.2), `NO_OWNER` when none: set by
    /// `delayed` for the length of a write, resize or atime update of that file.
    delay_owner: u32,
    /// Where `alloc_block` starts looking (see its doc comment).
    next_free_block: u32,
    /// Mounted read-only (`OxideBSD-doc/RAM_FLOOR.md` §3.4.3): the root from boot until `/etc/rc`
    /// remounts it read-write (`mount -u`), or any mount after a remount read-only. The kernel
    /// refuses every change with `EROFS`.
    rdonly: bool,
    /// Clean on the disk (§3.4.1): cleared by a read-write mount before anything else is written,
    /// set by unmounting once every delayed write is out.
    clean: bool,
    /// The volume label read at mount (`newfs_oxfs -L`), written back with every superblock.
    label: [u8; SB_LABEL_LEN],
}

/// A fresh inode of `kind`, stamped with the current time.
fn fresh_inode(kind: InodeKind) -> Inode {
    Inode::new(kind, unsafe { oxidebsd_unix_time() })
}

/// The inodes: an inode file whose data blocks hold packed inodes (`INODES_PER_BLOCK` per block,
/// inode number `n` at byte `n * INODE_STRIDE`). The file's own inode record isn't numbered: it's
/// kept in the superblock. The table grows a block (32 inodes) at a time when no slot is free; freshly
/// allocated blocks are zeroed, and a zeroed record decodes as `InodeKind::Free`.
#[derive(Clone, Copy)]
struct InodeTable {
    file: Inode,
    /// Slots in the file (`file.size / INODE_STRIDE`).
    count: u32,
    /// Slots holding `InodeKind::Free`, kept exact by `write_inode`.
    free: u32,
    /// Where `alloc_inode` starts looking.
    hint: u32,
}

impl InodeTable {
    const EMPTY: InodeTable = InodeTable { file: Inode::FREE, count: 0, free: 0, hint: 0 };
}

const NO_OWNER: u32 = u32::MAX;

/// Bitmap block and bit for disk block `n`.
fn bitmap_position(n: u32) -> (u32, usize) {
    (n / BITS_PER_BITMAP_BLOCK, (n % BITS_PER_BITMAP_BLOCK) as usize)
}

impl Fs {
    /// A mount of device `dev` by the kernel's mount `mp`, nothing read yet (`mount_from_disk`).
    fn new(dev: u64, mp: *mut vfs_if::Mount, root: bool) -> Fs {
        Fs {
            dev,
            mp,
            root,
            data_blocks: 0,
            bitmap_blocks: 0,
            data_block_offset: 0,
            free_counts: Vec::new(),
            inodes: InodeTable::EMPTY,
            delay_owner: NO_OWNER,
            next_free_block: 0,
            rdonly: false,
            clean: false,
            label: [0; SB_LABEL_LEN],
        }
    }

    fn set_layout(&mut self, data_blocks: u32, bitmap: u32) {
        self.data_blocks = data_blocks;
        self.bitmap_blocks = bitmap;
        self.data_block_offset = BITMAP_START + bitmap;
    }

    /// Runs `f` on block `n` in place, for reads that don't want `read_block`'s 4 KiB copy (index
    /// blocks, inode records). `f` must not touch another block: a disk block is lent from the cache.
    fn with_block<R>(&self, n: u32, f: impl FnOnce(&[u8; BLOCK_SIZE]) -> R) -> R {
        buf::with(self.dev, self.data_block_offset + n, f)
    }

    fn read_block(&self, n: u32) -> [u8; BLOCK_SIZE] {
        self.with_block(n, |b| *b)
    }

    fn delay_owner(&self) -> Option<u32> {
        (self.delay_owner != NO_OWNER).then_some(self.delay_owner)
    }

    /// Runs `f` with the data blocks, index blocks and inode record of `n` written back later
    /// instead of at once -- if `n` is a regular file. Everything else (directories, symlinks,
    /// names, the bitmap) stays synchronous (§3.3.1).
    fn delayed<R>(&mut self, n: u32, f: impl FnOnce(&mut Fs) -> R) -> R {
        let previous = self.delay_owner;
        if self.read_inode(n).kind == InodeKind::File {
            self.delay_owner = n;
        }
        let r = f(self);
        self.delay_owner = previous;
        r
    }

    /// Stores block `n`. Inside `delayed`, it's that file's data: left dirty in the cache.
    /// Otherwise it reaches the disk before the system call returns.
    fn write_block(&self, n: u32, data: &[u8; BLOCK_SIZE]) {
        let at = self.data_block_offset + n;
        match self.delay_owner() {
            Some(owner) => buf::store(self.dev, at, data, buf::Kind::Data(owner)),
            None => buf::write(self.dev, at, data, buf::Kind::Meta),
        }
    }

    /// `write_block` for an index (indirect) block: delayed as that file's index block, so it can't
    /// reach the disk before the data blocks it points at.
    fn write_index_block(&self, n: u32, data: &[u8; BLOCK_SIZE]) {
        let at = self.data_block_offset + n;
        match self.delay_owner() {
            Some(owner) => buf::store(self.dev, at, data, buf::Kind::Index(owner)),
            None => buf::write(self.dev, at, data, buf::Kind::Meta),
        }
    }

    /// Marks block `n` used or free: a read-modify-write of its bitmap block through the cache, with
    /// that block's free count kept in step.
    fn set_block_used(&mut self, n: u32, used: bool) {
        let (index, bit) = bitmap_position(n);
        let mut block = buf::read(self.dev, BITMAP_START + index);
        let was = block[bit / 8] & (1 << (bit % 8)) != 0;
        if was == used {
            return;
        }
        block[bit / 8] ^= 1 << (bit % 8);
        buf::write(self.dev, BITMAP_START + index, &block, buf::Kind::Meta);
        let count = &mut self.free_counts[index as usize];
        if used { *count -= 1 } else { *count += 1 }
    }

    /// Where inode `n`'s record is: its inode-file block and byte offset. `None` past the table.
    fn inode_location(&self, n: u32) -> Option<(u32, usize)> {
        if n >= self.inodes.count {
            return None;
        }
        let block = self.inode_block_at(&self.inodes.file, n as usize / INODES_PER_BLOCK)?;
        Some((block, n as usize % INODES_PER_BLOCK * INODE_STRIDE))
    }

    /// Inode `n`, or a free one if `n` is past its table.
    fn read_inode(&self, n: u32) -> Inode {
        match self.inode_location(n) {
            Some((block, off)) => self.with_block(block, |b| unpack_inode(&b[off..off + INODE_STRIDE])),
            None => Inode::FREE,
        }
    }

    /// Stores inode `n` (persisted with its block, like any data), keeping the table's free count.
    /// `n` must be in its table: numbers come from `alloc_inode`.
    fn write_inode(&mut self, n: u32, inode: Inode) {
        let Some((block, off)) = self.inode_location(n) else {
            return;
        };
        let was_free = self.with_block(block, |b| b[off] == 0);
        let mut data = self.read_block(block);
        pack_inode(&inode, &mut data[off..off + INODE_STRIDE]);
        // An inode-file block: written after the dirty data and index blocks of the inodes in it (the
        // cache's ordering, `buf`); left dirty only for the file whose writes are being delayed.
        let kind = buf::Kind::Inodes(n - n % INODES_PER_BLOCK as u32);
        let at = self.data_block_offset + block;
        if self.delay_owner() == Some(n) {
            buf::store(self.dev, at, &data, kind);
        } else {
            buf::write(self.dev, at, &data, kind);
        }
        let is_free = inode.kind == InodeKind::Free;
        match (was_free, is_free) {
            (true, false) => self.inodes.free -= 1,
            (false, true) => self.inodes.free += 1,
            _ => {}
        }
    }

    /// Finds and claims the first free block, starting from `next_free_block` rather than always
    /// rescanning from `0`: a forward cursor, stepped back by `free_block`, so a run of allocations
    /// is linear rather than `O(n^2)` over a large disk (the same class of bug
    /// `memory::BootInfoFrameAllocator`'s doc comment warns about for the physical frame
    /// allocator). Full bitmap blocks are skipped on their resident free counts.
    fn alloc_block(&mut self) -> Option<u32> {
        let start = self.next_free_block;
        let total = self.data_blocks;
        let mut index = start / BITS_PER_BITMAP_BLOCK;
        while index < self.bitmap_blocks {
            // A full bitmap block is skipped on its resident count, without reading it.
            if self.free_counts[index as usize] > 0 {
                let base = index * BITS_PER_BITMAP_BLOCK;
                let from = start.max(base) - base;
                let end = (total - base).min(BITS_PER_BITMAP_BLOCK);
                let found = buf::with(self.dev, BITMAP_START + index, |b| {
                    (from..end).find(|&bit| b[bit as usize / 8] & (1 << (bit % 8)) == 0)
                });
                if let Some(bit) = found {
                    let n = base + bit;
                    self.set_block_used(n, true);
                    self.write_block(n, &[0u8; BLOCK_SIZE]);
                    self.next_free_block = n + 1;
                    return Some(n);
                }
            }
            index += 1;
        }
        None
    }

    /// Like `alloc_block`, but fills the fresh block with `0xFF` bytes, not zero -- required for an
    /// indirect block specifically: each 4-byte slot is a block-number pointer, and a plain
    /// zero-filled block would decode every slot as block `0` (a real, valid block), not `NO_BLOCK`
    /// ("no pointer here yet").
    fn alloc_indirect_block(&mut self) -> Option<u32> {
        let n = self.alloc_block()?;
        self.write_index_block(n, &[0xFFu8; BLOCK_SIZE]);
        Some(n)
    }

    // --- Reclamation -------------------------------------------------------------------------
    //
    // An inode is freed, with every block it addresses, once nothing refers to it: no name
    // (`nlink == 0`) and no vnode of it in use (`vfs::inode_busy`: a descriptor, a working or root
    // directory, a mapping, a running program, a bound socket file -- every kernel holder holds a
    // vnode). Its last vnode going inactive asks again (`vfs::oxfs_vop_inactive`). One left over at
    // a reboot (open when the system stopped) is freed by the sweep after mounting
    // (`sweep_unnamed_inodes`), and its vnode, if any, recycled (`vfs::inode_freed`).

    /// Returns block `n` to the pool; the allocation cursor steps back so it's reused.
    fn free_block(&mut self, n: u32) {
        buf::discard(self.dev, self.data_block_offset + n);
        self.set_block_used(n, false);
        if n < self.next_free_block {
            self.next_free_block = n;
        }
    }

    /// Frees index block `ib` and the data blocks it points to.
    fn free_index_block(&mut self, ib: u32) {
        for slot in 0..PTRS_PER_INDIRECT {
            let b = self.read_index_ptr(ib, slot);
            if b != NO_BLOCK {
                self.free_block(b);
            }
        }
        self.free_block(ib);
    }

    /// Frees every block `inode` addresses, index blocks included.
    fn free_inode_blocks(&mut self, inode: &Inode) {
        for &b in &inode.direct {
            if b != NO_BLOCK {
                self.free_block(b);
            }
        }
        if inode.indirect != NO_BLOCK {
            self.free_index_block(inode.indirect);
        }
        if inode.double_indirect != NO_BLOCK {
            for slot in 0..PTRS_PER_INDIRECT {
                let inner = self.read_index_ptr(inode.double_indirect, slot);
                if inner != NO_BLOCK {
                    self.free_index_block(inner);
                }
            }
            self.free_block(inode.double_indirect);
        }
    }

    /// Frees inode `n` if nothing refers to it any more (see the section comment); keeps it as an
    /// orphan if only the kernel does.
    fn maybe_release(&mut self, n: u32) {
        let inode = self.read_inode(n);
        // A file in use (open, a cwd, mapped, running, a lookup in progress) keeps its storage until
        // its vnode goes inactive (`vfs::oxfs_vop_inactive`), which asks again: every holder in the
        // kernel holds a vnode now (VFS.md §11 step 2c).
        if n == ROOT_INODE || inode.kind == InodeKind::Free || inode.nlink > 0 || vfs::inode_busy(self.mp, n) {
            return;
        }
        self.release_inode(n, inode);
    }

    /// Frees inode `n` (whose record is `inode`) and its blocks. The record goes first: interrupted
    /// between the two, the disk leaks blocks rather than keeping an inode that points at blocks
    /// someone else may be given.
    fn release_inode(&mut self, n: u32, inode: Inode) {
        // Its unwritten data and index blocks are about to be freed: never write them.
        buf::discard_owned(self.dev, n);
        self.write_inode(n, Inode::FREE);
        self.free_inode_blocks(&inode);
        self.trim_inode_table();
        // The number may be handed out again: a vnode left of the old file must not answer for it.
        vfs::inode_freed(self.mp, n);
    }

    /// After mounting read-write: frees every inode left without a name by the last boot (open,
    /// mapped or a working directory when it went down). Nothing can refer to one yet.
    fn sweep_unnamed_inodes(&mut self) {
        let count = self.inodes.count;
        let mut freed: u32 = 0;
        for n in 1..count {
            let inode = self.read_inode(n);
            if inode.kind != InodeKind::Free && inode.nlink == 0 {
                self.release_inode(n, inode);
                freed += 1;
            }
        }
        if freed > 0 {
            let mut msg_buf = [0u8; 64];
            let mut msg = ByteBuf { buf: &mut msg_buf, len: 0 };
            msg.push_bytes(b"[oxfs] freed ");
            msg.push_decimal(freed);
            msg.push_bytes(if freed == 1 { b" unnamed inode" } else { b" unnamed inodes" });
            msg.push_bytes(b" left by the last boot\n");
            let len = msg.len;
            log_bytes(&msg_buf[..len]);
        }
    }

    /// Clears slot `slot` of index block `ib` and returns the block number it held.
    fn clear_index_ptr(&mut self, ib: u32, slot: usize) -> u32 {
        let mut data = self.read_block(ib);
        let b = u32::from_le_bytes(data[slot * 4..slot * 4 + 4].try_into().unwrap());
        data[slot * 4..slot * 4 + 4].copy_from_slice(&NO_BLOCK.to_le_bytes());
        self.write_block(ib, &data);
        b
    }

    /// Clears inode-file block `index`'s pointer in `file` and frees the block, along with any index
    /// block that pointer was the first entry of. Only the table's last block is ever unmapped, so an
    /// index block whose first entry goes has no others left.
    fn unmap_last_block(&mut self, file: &mut Inode, index: usize) {
        if index < DIRECT_BLOCKS {
            self.free_block(file.direct[index]);
            file.direct[index] = NO_BLOCK;
            return;
        }
        let i = index - DIRECT_BLOCKS;
        if i < PTRS_PER_INDIRECT {
            let b = self.clear_index_ptr(file.indirect, i);
            self.free_block(b);
            if i == 0 {
                self.free_block(file.indirect);
                file.indirect = NO_BLOCK;
            }
            return;
        }
        let i = i - PTRS_PER_INDIRECT;
        let (outer, inner) = (i / PTRS_PER_INDIRECT, i % PTRS_PER_INDIRECT);
        let inner_block = self.read_index_ptr(file.double_indirect, outer);
        let b = self.clear_index_ptr(inner_block, inner);
        self.free_block(b);
        if inner == 0 {
            self.clear_index_ptr(file.double_indirect, outer);
            self.free_block(inner_block);
            if outer == 0 {
                self.free_block(file.double_indirect);
                file.double_indirect = NO_BLOCK;
            }
        }
    }

    /// Gives the table's last blocks back to the pool while they hold only free inodes (the first
    /// block, holding the root, always stays). The disk table's new shape goes to the superblock
    /// before its blocks are freed, so an interruption can only leak them.
    fn trim_inode_table(&mut self) {
        let per_block = INODES_PER_BLOCK as u32;
        loop {
            let table = self.inodes;
            if table.count <= per_block {
                return;
            }
            let first = table.count - per_block;
            if (first..table.count).any(|slot| self.read_inode(slot).kind != InodeKind::Free) {
                return;
            }
            let mut file = table.file;
            file.size = first as u64 * INODE_STRIDE as u64;
            let t = &mut self.inodes;
            t.count = first;
            t.free -= per_block;
            t.hint = t.hint.min(first);
            t.file.size = file.size;
            self.write_superblock();
            self.unmap_last_block(&mut file, first as usize / INODES_PER_BLOCK);
            self.inodes.file = file;
            self.write_superblock();
        }
    }

    /// A free inode number, growing the table by a block when none is free. The caller writes the
    /// new inode.
    fn alloc_inode(&mut self) -> Option<u32> {
        if self.inodes.free == 0 {
            self.grow_inode_table()?;
        }
        let table = self.inodes;
        let start = table.hint.min(table.count);
        let slot = (start..table.count)
            .chain(0..start)
            .find(|&slot| self.read_inode(slot).kind == InodeKind::Free)?;
        self.inodes.hint = slot + 1;
        Some(slot)
    }

    /// Adds a block of free inodes to the table (`None` when the disk is out of blocks or the number
    /// range is used up). The table's new shape goes to the superblock.
    fn grow_inode_table(&mut self) -> Option<()> {
        let table = self.inodes;
        if table.count as u64 + INODES_PER_BLOCK as u64 > MAX_DISK_INODES as u64 {
            return None;
        }
        let mut file = table.file;
        // A fresh block from `alloc_block` is zeroed: `INODES_PER_BLOCK` free records.
        self.ensure_block(&mut file, table.count as usize / INODES_PER_BLOCK)?;
        let count = table.count + INODES_PER_BLOCK as u32;
        file.size = count as u64 * INODE_STRIDE as u64;
        let t = &mut self.inodes;
        t.file = file;
        t.count = count;
        t.free += INODES_PER_BLOCK as u32;
        self.write_superblock();
        Some(())
    }

    /// Reads a block-number pointer out of index block `ib_num` at slot `slot` (4 bytes, little
    /// endian), at every indirection tier.
    fn read_index_ptr(&self, ib_num: u32, slot: usize) -> u32 {
        let off = slot * 4;
        self.with_block(ib_num, |ib| u32::from_le_bytes([ib[off], ib[off + 1], ib[off + 2], ib[off + 3]]))
    }

    /// Reads the block number backing `inode`'s logical block `index` -- direct, then (past
    /// `DIRECT_BLOCKS`) via the single-indirect block, then (past that) via the double-indirect block
    /// (see `Inode::double_indirect`'s own doc comment for the three-tier addressing scheme this
    /// implements) -- or `None` if that block was never allocated.
    fn inode_block_at(&self, inode: &Inode, index: usize) -> Option<u32> {
        if index < DIRECT_BLOCKS {
            let b = inode.direct[index];
            return (b != NO_BLOCK).then_some(b);
        }
        let index = index - DIRECT_BLOCKS;
        if index < PTRS_PER_INDIRECT {
            if inode.indirect == NO_BLOCK {
                return None;
            }
            let b = self.read_index_ptr(inode.indirect, index);
            return (b != NO_BLOCK).then_some(b);
        }
        let index = index - PTRS_PER_INDIRECT;
        if inode.double_indirect == NO_BLOCK || index >= PTRS_PER_DOUBLE_INDIRECT {
            return None;
        }
        let outer_slot = index / PTRS_PER_INDIRECT;
        let inner_slot = index % PTRS_PER_INDIRECT;
        let inner_block = self.read_index_ptr(inode.double_indirect, outer_slot);
        if inner_block == NO_BLOCK {
            return None;
        }
        let b = self.read_index_ptr(inner_block, inner_slot);
        (b != NO_BLOCK).then_some(b)
    }

    /// Like `inode_block_at`, but allocates a fresh block (and, if needed, a fresh indirect block)
    /// when `index` isn't backed by one yet -- used by both real file writes and directory growth.
    /// Takes an inode *number*: the record is copied in and out around the allocation.
    fn inode_ensure_block_at(&mut self, inode_num: u32, index: usize) -> Option<u32> {
        let mut inode = self.read_inode(inode_num);
        let result = self.ensure_block(&mut inode, index);
        self.write_inode(inode_num, inode);
        result
    }

    /// `inode_ensure_block_at` on an inode record held by the caller (the inode file's own record
    /// isn't numbered).
    fn ensure_block(&mut self, inode: &mut Inode, index: usize) -> Option<u32> {
        if index < DIRECT_BLOCKS {
            if inode.direct[index] == NO_BLOCK {
                inode.direct[index] = self.alloc_block()?;
            }
            Some(inode.direct[index])
        } else if index - DIRECT_BLOCKS < PTRS_PER_INDIRECT {
            let indirect_index = index - DIRECT_BLOCKS;
            if inode.indirect == NO_BLOCK {
                inode.indirect = self.alloc_indirect_block()?;
            }
            self.ensure_index_slot(inode.indirect, indirect_index)
        } else {
            // Double-indirect tier -- see `Inode::double_indirect`'s own doc comment. `outer_slot`
            // picks (allocating if needed) the one inner index block covering `inner_slot`'s own
            // range, then `ensure_index_slot` allocates the data block one level deeper.
            let index = index - DIRECT_BLOCKS - PTRS_PER_INDIRECT;
            if index >= PTRS_PER_DOUBLE_INDIRECT {
                return None;
            }
            let outer_slot = index / PTRS_PER_INDIRECT;
            let inner_slot = index % PTRS_PER_INDIRECT;
            if inode.double_indirect == NO_BLOCK {
                inode.double_indirect = self.alloc_indirect_block()?;
            }
            let mut outer = self.read_block(inode.double_indirect);
            let outer_off = outer_slot * 4;
            let mut inner_block = u32::from_le_bytes(outer[outer_off..outer_off + 4].try_into().unwrap());
            if inner_block == NO_BLOCK {
                inner_block = self.alloc_indirect_block()?;
                outer[outer_off..outer_off + 4].copy_from_slice(&inner_block.to_le_bytes());
                self.write_index_block(inode.double_indirect, &outer);
            }
            self.ensure_index_slot(inner_block, inner_slot)
        }
    }

    /// Shared by `ensure_block`'s single-indirect branch and its double-indirect branch's inner
    /// tier: reads index block `ib_num`'s pointer at `slot`, allocating and writing back a fresh
    /// data-block pointer if that slot is still `NO_BLOCK`.
    fn ensure_index_slot(&mut self, ib_num: u32, slot: usize) -> Option<u32> {
        let mut ib = self.read_block(ib_num);
        let off = slot * 4;
        let existing = u32::from_le_bytes(ib[off..off + 4].try_into().unwrap());
        if existing != NO_BLOCK {
            return Some(existing);
        }
        let nb = self.alloc_block()?;
        ib[off..off + 4].copy_from_slice(&nb.to_le_bytes());
        self.write_index_block(ib_num, &ib);
        Some(nb)
    }

    /// Reads up to `out.len()` bytes starting at `position` within `inode_num`'s data, honoring its
    /// stored `size` (real files only -- directories never call this, they walk raw records instead).
    /// Returns the number of bytes actually read (`0` at or past EOF).
    fn read_inode_at(&self, inode_num: u32, position: usize, out: &mut [u8]) -> usize {
        let mut written = 0;
        let _ = self.read_inode_with(inode_num, position, out.len(), |chunk| {
            out[written..written + chunk.len()].copy_from_slice(chunk);
            written += chunk.len();
            Ok(())
        });
        written
    }

    /// `read_inode_at` into a read transfer (`uio`): straight from the block pool, no buffer in
    /// between. `Ok(count)` or `Err(-errno)`.
    fn read_inode_uio(&self, inode_num: u32, position: usize, uio: u64) -> Result<usize, i64> {
        self.read_inode_with(inode_num, position, uio_resid(uio), |chunk| uio_out(uio, chunk).map(|_| ()))
    }

    /// The block walk `read_inode_at` and `read_inode_uio` share: hands `sink` up to `max` bytes of
    /// `inode_num`'s content from `position`, one block's worth at a time. Stops at end of file, or
    /// at a missing block. `Ok(count)`, or the first error `sink` returns.
    fn read_inode_with(
        &self,
        inode_num: u32,
        position: usize,
        max: usize,
        mut sink: impl FnMut(&[u8]) -> Result<(), i64>,
    ) -> Result<usize, i64> {
        let inode = self.read_inode(inode_num);
        let size = inode.size as usize;
        if position >= size {
            return Ok(0);
        }
        let n = max.min(size - position);
        let mut written = 0;
        while written < n {
            let file_off = position + written;
            let block_index = file_off / BLOCK_SIZE;
            let in_block_off = file_off % BLOCK_SIZE;
            let Some(blk) = self.inode_block_at(&inode, block_index) else {
                break;
            };
            let block = self.read_block(blk);
            let chunk = (n - written).min(BLOCK_SIZE - in_block_off);
            sink(&block[in_block_off..in_block_off + chunk])?;
            written += chunk;
        }
        Ok(written)
    }

    /// Writes `content` as `inode_num`'s complete contents (replacing whatever was there before),
    /// allocating whatever blocks are needed and setting `size`: a symlink's target.
    fn write_inode_data(&mut self, inode_num: u32, content: &[u8]) -> bool {
        let block_count = content.len().div_ceil(BLOCK_SIZE);
        for i in 0..block_count {
            let Some(blk) = self.inode_ensure_block_at(inode_num, i) else {
                return false;
            };
            let start = i * BLOCK_SIZE;
            let end = (start + BLOCK_SIZE).min(content.len());
            let mut buf = [0u8; BLOCK_SIZE];
            buf[..end - start].copy_from_slice(&content[start..end]);
            self.write_block(blk, &buf);
        }
        let mut inode = self.read_inode(inode_num);
        inode.size = content.len() as u64;
        let now = unsafe { oxidebsd_unix_time() };
        inode.mtime = now;
        inode.ctime = now;
        self.write_inode(inode_num, inode);
        true
    }

    /// Real `st_atime` update -- see `Inode::atime`'s own doc comment for the POSIX text this
    /// implements. Skips the write entirely if the whole-second value hasn't changed since the last
    /// touch (POSIX only requires atime be "marked for update"), which keeps a tight read loop from
    /// rewriting the same inode-file block on every call. Never on a read-only mount.
    fn touch_atime(&mut self, inode_num: u32) {
        if self.rdonly {
            return;
        }
        self.delayed(inode_num, |fs| {
            let mut inode = fs.read_inode(inode_num);
            let now = unsafe { oxidebsd_unix_time() };
            if inode.atime != now {
                inode.atime = now;
                fs.write_inode(inode_num, inode);
            }
        })
    }

    /// `ftruncate`/`posix_fallocate`'s work: resizes `inode_num`'s content to exactly `new_size`
    /// bytes without ever holding the file's content in one buffer. Growing zero-fills only the
    /// newly added region, block by block; shrinking touches no block content at all (bytes past
    /// the new `size` become unreachable, and a later grow back past them zero-fills over them
    /// again, POSIX's "grow into a hole reads as zero").
    fn resize_inode_data(&mut self, inode_num: u32, new_size: usize) -> bool {
        self.delayed(inode_num, |fs| {
            let old_size = fs.read_inode(inode_num).size as usize;
            let mut pos = old_size;
            while pos < new_size {
                let block_index = pos / BLOCK_SIZE;
                let in_block_off = pos % BLOCK_SIZE;
                let Some(blk) = fs.inode_ensure_block_at(inode_num, block_index) else {
                    return false;
                };
                let mut block = fs.read_block(blk);
                let chunk = (new_size - pos).min(BLOCK_SIZE - in_block_off);
                block[in_block_off..in_block_off + chunk].fill(0);
                fs.write_block(blk, &block);
                pos += chunk;
            }
            let mut inode = fs.read_inode(inode_num);
            inode.size = new_size as u64;
            let now = unsafe { oxidebsd_unix_time() };
            inode.mtime = now;
            inode.ctime = now;
            fs.write_inode(inode_num, inode);
            true
        })
    }

    /// A write transfer (`uio`) into `inode_num` at `position`: straight into the block pool. The
    /// count written, short when the filesystem fills or a fault stops it partway, as `write(2)`
    /// reports.
    fn write_inode_uio(&mut self, inode_num: u32, position: usize, uio: u64) -> Result<usize, i64> {
        let n = uio_resid(uio);
        self.write_inode_with(inode_num, position, n, |dst| uio_in(uio, dst).map(|_| ()))
    }

    /// The block walk of a write: `fill` supplies each block's share of the `len` bytes written at
    /// `position`. Returns how many bytes were written; an error (`-ENOSPC` when a block can't be
    /// allocated, or the first error `fill` returns) only when that's none. The size and times
    /// cover whatever was written.
    fn write_inode_with(
        &mut self,
        inode_num: u32,
        position: usize,
        len: usize,
        mut fill: impl FnMut(&mut [u8]) -> Result<(), i64>,
    ) -> Result<usize, i64> {
        let (written, result) = self.delayed(inode_num, |fs| {
            let old_size = fs.read_inode(inode_num).size as usize;
            if position > old_size && !fs.resize_inode_data(inode_num, position) {
                return (0, Err(-ENOSPC));
            }
            let mut pos = position;
            let mut written = 0;
            let mut result = Ok(());
            while written < len {
                let block_index = pos / BLOCK_SIZE;
                let in_block_off = pos % BLOCK_SIZE;
                let Some(blk) = fs.inode_ensure_block_at(inode_num, block_index) else {
                    result = Err(-ENOSPC);
                    break;
                };
                let mut block = fs.read_block(blk);
                let chunk = (len - written).min(BLOCK_SIZE - in_block_off);
                // A failed fill may have half-written `block`: it isn't stored.
                if let Err(e) = fill(&mut block[in_block_off..in_block_off + chunk]) {
                    result = Err(e);
                    break;
                }
                // A regular file's data stays dirty in the cache (`delayed`) and goes to the disk
                // later, in long runs; anything else is written now.
                fs.write_block(blk, &block);
                pos += chunk;
                written += chunk;
            }
            let mut inode = fs.read_inode(inode_num);
            if pos > inode.size as usize {
                inode.size = pos as u64;
            }
            let now = unsafe { oxidebsd_unix_time() };
            inode.mtime = now;
            inode.ctime = now;
            fs.write_inode(inode_num, inode);
            (written, result)
        });
        // Back-pressure (§3.2.5): a writer that has filled half the cache with unwritten blocks waits
        // for them, rather than leave eviction to write them a block at a time.
        if buf::mostly_dirty() {
            buf::flush_all(self.dev);
        }
        match result {
            Err(e) if written == 0 => Err(e),
            _ => Ok(written),
        }
    }

    /// Inode `inode_num`'s `struct stat` (`vop_getattr` takes its link count and device from it).
    fn inode_stat(&self, inode_num: u32) -> MuslStat {
        let inode = self.read_inode(inode_num);
        // `File`/`Device` report a real, tracked link count (floored at `1` -- see `Inode::nlink`'s
        // own doc comment for why a decoded `0` means "written before this field existed", not "no
        // links at all"). `Dir`/`Symlink` keep their existing hardcoded values.
        let (type_bits, nlink) = match inode.kind {
            InodeKind::Dir => (S_IFDIR, 2u64),
            InodeKind::Symlink => (S_IFLNK, 1u64),
            InodeKind::Device => (
                if inode.device_char { S_IFCHR } else { S_IFBLK },
                inode.nlink.max(1) as u64,
            ),
            InodeKind::Fifo => (S_IFIFO, inode.nlink.max(1) as u64),
            InodeKind::Socket => (S_IFSOCK, inode.nlink.max(1) as u64),
            _ => (S_IFREG, inode.nlink.max(1) as u64),
        };
        let mode = type_bits | inode.mode as u32;
        let size = inode.size as i64;
        let dev = 1;
        let rdev = if inode.kind == InodeKind::Device {
            inode.rdev as u64
        } else {
            0
        };
        MuslStat {
            st_dev: dev,
            st_ino: inode_num as u64,
            st_nlink: nlink,
            st_mode: mode,
            st_uid: inode.uid,
            st_gid: inode.gid,
            __pad0: 0,
            st_rdev: rdev,
            st_size: size,
            st_blksize: BLOCK_SIZE as i64,
            st_blocks: (size + 511) / 512,
            st_atime_sec: inode.atime,
            st_atime_nsec: 0,
            st_mtime_sec: inode.mtime,
            st_mtime_nsec: 0,
            st_ctime_sec: inode.ctime,
            st_ctime_nsec: 0,
            __unused: [0; 3],
        }
    }

    /// The group a new file, directory, node or symlink in `parent` gets: `parent`'s, as on all
    /// three BSDs (POSIX allows this or the creator's group). Its owner is always the creator.
    fn new_entry_gid(&self, parent: u32) -> u32 {
        self.read_inode(parent).gid
    }

    /// Looks `name` up directly inside `dir_inode` (path walking is the kernel's `namei`). `name`
    /// may be `.`/`..`, both stored as real records like any other (self-referencing for the root).
    fn dir_lookup(&self, dir_inode: u32, name: &[u8]) -> Option<u32> {
        let inode = self.read_inode(dir_inode);
        let mut i = 0;
        while let Some(blk) = self.inode_block_at(&inode, i) {
            let block = self.read_block(blk);
            for r in 0..RECORDS_PER_BLOCK {
                if dir_record_used(&block, r) && dir_record_name(&block, r) == name {
                    return Some(dir_record_inode(&block, r));
                }
            }
            i += 1;
        }
        None
    }

    /// Marks `dir_inode` changed after an entry was added or removed: POSIX has `creat`, `mkdir`,
    /// `link`, `symlink`, `mknod`, `unlink`, `rmdir` and `rename` update the directory's `st_mtime`
    /// and `st_ctime`, and programs rely on it to notice a directory's contents changed (cron(8)
    /// rereads `/etc/cron.d` when its time moves). Like `touch_atime`, skips the write when the
    /// stamp already holds this second, which keeps seeding thousands of files cheap.
    fn touch_dir(&mut self, dir_inode: u32) {
        let mut inode = self.read_inode(dir_inode);
        let now = unsafe { oxidebsd_unix_time() };
        if inode.mtime == now && inode.ctime == now {
            return;
        }
        inode.mtime = now;
        inode.ctime = now;
        self.write_inode(dir_inode, inode);
    }

    /// Inserts a new `(name, target_inode)` record into `dir_inode`, reusing the first free (cleared
    /// by a previous `dir_remove`) or never-yet-used record slot -- growing `dir_inode` with a fresh
    /// block via `inode_ensure_block_at` if every existing block is full.
    fn dir_insert(&mut self, dir_inode: u32, name: &[u8], target_inode: u32) -> Result<(), OxfsError> {
        // `ENAMETOOLONG`, not `EINVAL`: BusyBox tar's extraction loop aborted the whole archive on
        // the wrong errno for a too-long name instead of skipping just that one file.
        if name.len() > NAME_MAX {
            return Err(OxfsError::NameTooLong);
        }
        let inode = self.read_inode(dir_inode);
        let mut i = 0;
        loop {
            match self.inode_block_at(&inode, i) {
                Some(blk) => {
                    let mut block = self.read_block(blk);
                    for r in 0..RECORDS_PER_BLOCK {
                        if !dir_record_used(&block, r) {
                            write_dir_record(&mut block, r, name, target_inode);
                            self.write_block(blk, &block);
                            self.touch_dir(dir_inode);
                            return Ok(());
                        }
                    }
                    i += 1;
                }
                None => {
                    let Some(blk) = self.inode_ensure_block_at(dir_inode, i) else {
                        return Err(OxfsError::DiskFull);
                    };
                    // inode_ensure_block_at hands back a freshly zeroed block (record 0 is free) --
                    // no need to scan it first.
                    let mut block = [0u8; BLOCK_SIZE];
                    write_dir_record(&mut block, 0, name, target_inode);
                    self.write_block(blk, &block);
                    self.touch_dir(dir_inode);
                    return Ok(());
                }
            }
        }
    }

    /// Clears the record named `name` inside `dir_inode` (the inode it names is the caller's to
    /// release). `Err(NotFound)` if no such record exists.
    fn dir_remove(&mut self, dir_inode: u32, name: &[u8]) -> Result<(), OxfsError> {
        let inode = self.read_inode(dir_inode);
        let mut i = 0;
        while let Some(blk) = self.inode_block_at(&inode, i) {
            let mut block = self.read_block(blk);
            for r in 0..RECORDS_PER_BLOCK {
                if dir_record_used(&block, r) && dir_record_name(&block, r) == name {
                    clear_dir_record(&mut block, r);
                    self.write_block(blk, &block);
                    self.dir_trim(dir_inode);
                    self.touch_dir(dir_inode);
                    return Ok(());
                }
            }
            i += 1;
        }
        Err(OxfsError::NotFound)
    }

    /// Gives back a directory's trailing blocks that no longer hold a record (never its first), as
    /// FFS truncates a directory's empty end: a directory that once held many names doesn't keep
    /// their blocks for good. Only trailing ones: a directory is read until its first missing block,
    /// so a hole would hide what follows it. Each pointer is cleared on the disk before its block is
    /// freed (`OxideBSD-doc/RAM_FLOOR.md` §3.3.1).
    fn dir_trim(&mut self, dir_inode: u32) {
        loop {
            let inode = self.read_inode(dir_inode);
            let mut count = 0;
            while self.inode_block_at(&inode, count).is_some() {
                count += 1;
            }
            if count <= 1 {
                return;
            }
            let last = count - 1;
            let Some(blk) = self.inode_block_at(&inode, last) else { return };
            if self.with_block(blk, |b| (0..RECORDS_PER_BLOCK).any(|r| dir_record_used(b, r))) {
                return;
            }
            if !self.clear_last_block_pointer(dir_inode, last) {
                return;
            }
            self.free_block(blk);
        }
    }

    /// Clears the pointer to block `index`, the last of inode `n`'s blocks, freeing the single-index
    /// block too when that leaves it empty. `false` past the single-indirect range (not trimmed).
    fn clear_last_block_pointer(&mut self, n: u32, index: usize) -> bool {
        let mut inode = self.read_inode(n);
        if index < DIRECT_BLOCKS {
            inode.direct[index] = NO_BLOCK;
            self.write_inode(n, inode);
            return true;
        }
        let slot = index - DIRECT_BLOCKS;
        if slot >= PTRS_PER_INDIRECT || inode.indirect == NO_BLOCK {
            return false;
        }
        let mut ib = self.read_block(inode.indirect);
        ib[slot * 4..slot * 4 + 4].copy_from_slice(&NO_BLOCK.to_le_bytes());
        self.write_index_block(inode.indirect, &ib);
        if slot == 0 {
            // Its last pointer gone: the index block goes too.
            let index_block = inode.indirect;
            inode.indirect = NO_BLOCK;
            self.write_inode(n, inode);
            self.free_block(index_block);
        }
        true
    }

    /// Counts live records in `dir_inode`, `.`/`..` included -- an otherwise-empty directory always
    /// has exactly `2` (`rmdir`'s check).
    fn dir_entry_count(&self, dir_inode: u32) -> usize {
        let inode = self.read_inode(dir_inode);
        let mut count = 0;
        let mut i = 0;
        while let Some(blk) = self.inode_block_at(&inode, i) {
            let block = self.read_block(blk);
            count += (0..RECORDS_PER_BLOCK).filter(|&r| dir_record_used(&block, r)).count();
            i += 1;
        }
        count
    }

    /// Returns the `n`th (0-indexed) used record inside `dir_inode`, walking blocks in the same
    /// order `dir_lookup`/`dir_entry_count` do, `.`/`..` included. `None` once `n` reaches the
    /// record count: `readdir`'s end.
    fn dir_nth_used_record(&self, dir_inode: u32, n: usize) -> Option<(u32, [u8; NAME_MAX], u8)> {
        let inode = self.read_inode(dir_inode);
        let mut seen = 0usize;
        let mut i = 0;
        while let Some(blk) = self.inode_block_at(&inode, i) {
            let block = self.read_block(blk);
            for r in 0..RECORDS_PER_BLOCK {
                if dir_record_used(&block, r) {
                    if seen == n {
                        let name = dir_record_name(&block, r);
                        let mut buf = [0u8; NAME_MAX];
                        buf[..name.len()].copy_from_slice(name);
                        return Some((dir_record_inode(&block, r), buf, name.len() as u8));
                    }
                    seen += 1;
                }
            }
            i += 1;
        }
        None
    }

    /// Puts regular file `n`'s delayed writes on the disk: its data, its index blocks, then its
    /// inode record (§3.3.5). Nothing to do for anything else, which is never delayed.
    fn sync_file(&self, n: u32) {
        buf::flush_file(self.dev, n);
    }

    /// `mount -u` (RAM_FLOOR.md §3.4.3), to read-only or read-write.
    ///
    /// To read-write: the cache is dropped whole (`fsck_oxfs` may have changed the disk underneath
    /// it, through the raw device) and the layout, free counts and inode table reread, as at mount;
    /// then the clean flag is cleared on the disk and the orphans a read-only mount left are swept.
    /// To read-only (the kernel refuses with `EBUSY` while a file on it is open for writing): every
    /// delayed write goes out and the file system is marked clean.
    fn remount(&mut self, rdonly: bool) -> i64 {
        if rdonly == self.rdonly {
            return 0;
        }
        if rdonly {
            buf::flush_all(self.dev);
            self.clean = true;
            self.write_superblock();
            self.set_rdonly(true);
            log("[oxfs] remounted read-only\n");
            return 0;
        }
        buf::invalidate_all(self.dev);
        if !self.mount_from_disk() {
            return -EIO;
        }
        self.set_rdonly(false);
        self.clean = false;
        self.write_superblock();
        self.sweep_unnamed_inodes();
        log("[oxfs] remounted read-write\n");
        0
    }

    /// Records the mount's mode; the root's goes to the kernel too (raw writes to the partition are
    /// refused while it's read-write; the kernel tracks other mounts' itself).
    fn set_rdonly(&mut self, rdonly: bool) {
        self.rdonly = rdonly;
        if self.root {
            // SAFETY: FFI call to a kernel-exported function, matching its declared signature.
            unsafe { oxidebsd_root_mounted_rw(!rdonly as u64) };
        }
    }

    fn write_superblock(&self) {
        let sb = Superblock {
            data_blocks: self.data_blocks,
            inode_count: self.inodes.count,
            root_inode: ROOT_INODE,
            clean: self.clean,
            label: self.label,
            inode_file: self.inodes.file,
        };
        let mut block = [0u8; BLOCK_SIZE];
        sb.encode(&mut block);
        // Written straight to the disk, never through the cache: nothing reads it after mount.
        if !buf::write_direct(self.dev, 0, &block) {
            log("[oxfs] superblock: write failed\n");
        }
    }

    /// Reads a formatted device in: checks the superblock, takes the layout from it, and counts each
    /// bitmap block's free blocks. Nothing else is read: every other block comes from the disk on
    /// first use, through the cache. `false` for a missing or mismatched superblock (an unformatted
    /// device, another file system, or a layout from another `SUPERBLOCK_VERSION`).
    fn mount_from_disk(&mut self) -> bool {
        let mut sb = [0u8; BLOCK_SIZE];
        if !buf::read_direct(self.dev, 0, &mut sb) {
            return false;
        }
        let sb = match Superblock::decode(&sb) {
            Ok(sb) => sb,
            Err(SuperblockError::NotOxfs) => return false,
            Err(SuperblockError::Version(_)) => {
                log("[oxfs] mount: the on-disk layout doesn't match this build\n");
                return false;
            }
        };
        let data_blocks = sb.data_blocks;
        let (_, bitmap_most) = layout_for(buf::device_blocks(self.dev));
        let bitmap = sb.bitmap_blocks();
        if bitmap > bitmap_most {
            log("[oxfs] mount: the file system is larger than its device\n");
            return false;
        }
        self.set_layout(data_blocks, bitmap);
        self.free_counts.clear();
        if self.free_counts.try_reserve_exact(bitmap as usize).is_err() {
            log("[oxfs] mount: out of memory for the free counts\n");
            return false;
        }
        self.free_counts.resize(bitmap as usize, 0);
        self.label = sb.label;
        self.next_free_block = 0;
        if !sb.clean {
            log("[oxfs] mount: filesystem was not cleanly unmounted\n");
        }
        let mut used = 0u32;
        for index in 0..bitmap {
            let base = index * BITS_PER_BITMAP_BLOCK;
            let bits = (data_blocks - base).min(BITS_PER_BITMAP_BLOCK);
            let set = buf::with(self.dev, BITMAP_START + index, |b| {
                (0..bits).filter(|&bit| b[bit as usize / 8] & (1 << (bit % 8)) != 0).count() as u32
            });
            self.free_counts[index as usize] = bits - set;
            used += set;
        }

        let count = sb.inode_count;
        self.inodes = InodeTable { file: sb.inode_file, count, free: 0, hint: 0 };
        let free = (0..count).filter(|&n| self.read_inode(n).kind == InodeKind::Free).count() as u32;
        self.inodes.free = free;

        let mut msg_buf = [0u8; 192];
        let mut msg = ByteBuf {
            buf: &mut msg_buf,
            len: 0,
        };
        msg.push_bytes(b"[oxfs] mounted existing filesystem from disk (");
        msg.push_decimal(used);
        msg.push_bytes(b" of ");
        msg.push_decimal(data_blocks);
        msg.push_bytes(b" blocks used, ");
        msg.push_decimal(count - free);
        msg.push_bytes(b" inodes in use)\n");
        let len = msg.len;
        log_bytes(&msg_buf[..len]);
        true
    }

    /// Directory `name` in `parent`, made (with its `.` and `..`) if it isn't there: devfs's mount
    /// point, `/dev`, on the root.
    fn ensure_dir(&mut self, parent: u32, name: &[u8]) -> u32 {
        if let Some(existing) = self.dir_lookup(parent, name) {
            return existing;
        }
        let inode = self.alloc_inode().expect("oxfs: failed to allocate a directory inode");
        self.write_inode(inode, fresh_inode(InodeKind::Dir));
        self.dir_insert(inode, b".", inode).expect("oxfs: failed to seed a directory's . entry");
        self.dir_insert(inode, b"..", parent).expect("oxfs: failed to seed a directory's .. entry");
        self.dir_insert(parent, name, inode)
            .expect("oxfs: failed to insert a new directory into its parent");
        inode
    }
}

/// Moves `data` out to a read transfer. `Ok(count)` or `Err(-errno)`.
fn uio_out(uio: u64, data: &[u8]) -> Result<usize, i64> {
    // SAFETY: FFI call to a kernel-exported function; a read transfer only reads `data`.
    let r = unsafe { oxidebsd_uiomove(data.as_ptr() as *mut u8, data.len() as u64, uio) };
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

/// Moves bytes in from a write transfer into `buf`. `Ok(count)` or `Err(-errno)`.
fn uio_in(uio: u64, buf: &mut [u8]) -> Result<usize, i64> {
    // SAFETY: FFI call to a kernel-exported function, with this module's own buffer.
    let r = unsafe { oxidebsd_uiomove(buf.as_mut_ptr(), buf.len() as u64, uio) };
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

fn uio_resid(uio: u64) -> usize {
    // SAFETY: FFI call to a kernel-exported function.
    unsafe { oxidebsd_uio_resid(uio) as usize }
}

/// `Ok(count)` / `Err(-errno)` as an operation's return value.
fn uio_ret(r: Result<usize, i64>) -> i64 {
    match r {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// Byte-exact mirror of musl's `struct stat` for x86_64 (`arch/x86_64/bits/stat.h` in
/// `external/mit/musl`): every field at its natural alignment and the size a multiple of 8, so
/// there are no implicit padding bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct MuslStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime_sec: i64,
    st_atime_nsec: i64,
    st_mtime_sec: i64,
    st_mtime_nsec: i64,
    st_ctime_sec: i64,
    st_ctime_nsec: i64,
    __unused: [i64; 3],
}

const _: () = assert!(core::mem::size_of::<MuslStat>() == 144);

#[derive(Debug, Clone, Copy)]
enum OxfsError {
    NotFound,
    DiskFull,
    /// A name longer than `NAME_MAX`.
    NameTooLong,
}

fn errno_for(e: OxfsError) -> i64 {
    -match e {
        OxfsError::NotFound => ENOENT,
        OxfsError::DiskFull => ENOSPC,
        OxfsError::NameTooLong => ENAMETOOLONG,
    }
}

/// An arbitrary but recognizable magic (`"OXFS"` as big-endian ASCII bytes) -- no applet in this
/// port's roster branches on `f_type`'s specific value, so any fixed constant would do.
const OXFS_STATFS_MAGIC: u64 = 0x4f584653;

/// POSIX `{PATH_MAX}` (musl's, `external/mit/musl/include/limits.h`): the longest symlink target
/// `readlink` returns.
const OXFS_PATH_MAX: usize = 4096;

/// `S_ISUID | S_ISGID`.
const SETID_BITS: u16 = 0o6000;

fn log_bytes(bytes: &[u8]) {
    unsafe { oxidebsd_log(bytes.as_ptr(), bytes.len() as u64) };
}

fn log(message: &str) {
    log_bytes(message.as_bytes());
}

/// A minimal, `core::fmt`-free byte-buffer builder (module code avoids `core::fmt::Write`/`write!`:
/// it reintroduces `GOTPCREL` relocations and pulls in a large fraction of `core::fmt`'s tables).
struct ByteBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl ByteBuf<'_> {
    fn push_bytes(&mut self, bytes: &[u8]) {
        let available = self.buf.len() - self.len;
        let n = bytes.len().min(available);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn push_decimal(&mut self, value: u32) {
        if value == 0 {
            self.push_bytes(b"0");
            return;
        }
        let mut digits = [0u8; 10];
        let mut count = 0;
        let mut remaining = value;
        while remaining > 0 {
            digits[count] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            count += 1;
        }
        digits[..count].reverse();
        self.push_bytes(&digits[..count]);
    }
}

/// Real module entry point (`#[unsafe(no_mangle)]`, discovered by `build.rs`'s relocatable-link
/// step and called by `sys/module.rs::load`): registers the type, which mounts the root.
#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // One system call at a time inside oxfs, even once a call sleeps for the disk: every call into
    // this module takes the kernel's filesystem lock (`OxideBSD-doc/RAM_FLOOR.md` §3.5.2).
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_module_serialize() };

    // The type (`vfs`), which mounts the root as it registers. Without a root there's nothing to
    // boot: fail the load (the kernel then stops).
    // SAFETY: FFI call to a kernel-exported function, with a static table.
    unsafe {
        if vfs_if::oxidebsd_vfs_register(&vfs::OXFS_VFSCONF) != 0 || vfs::root_mount().is_null() {
            return -1;
        }
    }

    // The path calls are the kernel's (`kern::vfs_syscalls`, registered by the `vfs` module); a
    // file's contents reach the page cache and exec through its vnode (`vfs.rs`).
    0
}
