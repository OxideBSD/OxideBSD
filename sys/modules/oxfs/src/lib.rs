//! `oxfs`: OxideBSD's disk file system (inodes with direct, single- and double-indirect block
//! pointers, directories as ordinary inodes holding fixed-size records).
//!
//! Since the VFS (OxideBSD-doc `VFS.md` §11 step 2b) this module serves vnode operations
//! (`vfs.rs`): the kernel does path lookup (`namei`), the path system calls, mounts and the cwd,
//! and asks oxfs for one directory's component (`vop_lookup`), a file's attributes, its contents.
//! A vnode's file ID is the inode number. What's left here is storage: blocks, inodes, directory
//! records.
//!
//! The on-disk format is `lib/liboxfs`'s. This module only mounts: the root file system is made
//! by `newfs_oxfs(8)` or installed from a system image built by `makefs(8)` from
//! `distrib/install.mtree` (`OxideBSD-doc/RAM_FLOOR.md` §4).
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
    /// Real, kernel-allocated (not baked into this module's own object file) storage -- see
    /// `BLOCKS_PTR`'s own doc comment for why. Returns a zeroed, kernel-VA-mapped
    /// pointer to `size_bytes` of fresh memory, or `0` on failure (only ever called once each,
    /// from `module_init`, which reboots the whole system on any failure here the same as any
    /// other `module_init` failure -- see this module's own `fatal_on_panic = true` in
    /// `sys/kernel_main.rs`, kernel tree).
    fn oxidebsd_module_alloc_zeroed(size_bytes: u64) -> u64;
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

/// The disk filesystem's size in data blocks, from its superblock (or, at format, from the
/// device: `layout_for`). (Until the 128 MB floor,
/// `OxideBSD-doc/RAM_FLOOR.md` §3.1.3, this was a compile-time 1 GiB `NUM_BLOCKS`, every block of
/// it held in RAM.)
static mut DISK_BLOCKS: u32 = 0;
/// Bitmap blocks: one bit per data block, `BITS_PER_BITMAP_BLOCK` to a block.
static mut BITMAP_BLOCKS: u32 = 0;
/// Device block holding data block `0`: right after the superblock and the bitmap.
static mut DATA_BLOCK_OFFSET: u32 = 0;

fn disk_blocks() -> u32 {
    // SAFETY: set once at mount or format, inside `module_init`.
    unsafe { *core::ptr::addr_of!(DISK_BLOCKS) }
}

fn bitmap_blocks() -> u32 {
    // SAFETY: as `disk_blocks`.
    unsafe { *core::ptr::addr_of!(BITMAP_BLOCKS) }
}

fn data_block_offset() -> u32 {
    // SAFETY: as `disk_blocks`.
    unsafe { *core::ptr::addr_of!(DATA_BLOCK_OFFSET) }
}


fn set_layout(data_blocks: u32, bitmap: u32) {
    // SAFETY: inside `module_init`, before any syscall.
    unsafe {
        *core::ptr::addr_of_mut!(DISK_BLOCKS) = data_blocks;
        *core::ptr::addr_of_mut!(BITMAP_BLOCKS) = bitmap;
        *core::ptr::addr_of_mut!(DATA_BLOCK_OFFSET) = BITMAP_START + bitmap;
    }
}

/// Gates `write_block`/`write_inode`/`set_block_used`'s own write-through persistence (see those
/// functions below). `false` while `mount_from_disk` reads the filesystem in; `module_init` sets it
/// once, before any system call is reachable, and from then on every write is a running process's
/// and belongs on the disk.
static mut PERSISTENCE_READY: bool = false;

fn persistence_ready() -> bool {
    unsafe { *core::ptr::addr_of!(PERSISTENCE_READY) }
}

fn set_persistence_ready(ready: bool) {
    unsafe { *core::ptr::addr_of_mut!(PERSISTENCE_READY) = ready };
}

/// Whether a real data disk is attached this boot at all -- the outer gate `persist_*_if_present`
/// (below) checks alongside `persistence_ready()`. A plain wrapper around the kernel-exported probe
/// result so call sites read naturally.
fn block_device_present() -> bool {
    buf::present()
}


/// Real POSIX `{PATH_MAX}` (musl's own compiled value, `external/mit/musl/include/limits.h`) --
/// the real whole-path-length limit, real `ENAMETOOLONG` when exceeded. Distinct from `NAME_MAX`'s
/// own per-*component* check in `resolve_parent` below (`InvalidPath`/`EINVAL`) -- this is real
/// POSIX text for the *whole* path, not any one component of it. Bigger than `MAX_CWD_PATH` (256,
/// a real but much smaller internal buffer for formatting *this filesystem's own* absolute cwd
/// string) -- the two serve unrelated purposes and were never meant to be the same number.
///
/// **Does not close `shm_open/39-2.c`/`shm_unlink/10-2.c`** (Open POSIX Test Suite pilot), the two
/// tests that originally flagged this gap -- investigated, not a kernel bug: both construct a name
/// with *embedded* `/` characters to build a genuinely `PATH_MAX`-length string, but real, upstream
/// musl's own `__shm_mapname()` (`external/mit/musl/src/mman/shm_open.c`) rejects any embedded `/`
/// as `EINVAL` *before* ever checking length -- real POSIX explicitly leaves embedded-slash
/// handling in a `shm_open()` name implementation-defined, so this is legitimate, spec-legal musl
/// behavior, not a bug to patch around. This check is still real and correct for what it actually
/// covers: an ordinary, non-shm path (a plain `open()`/`unlink()`/`mkdir()`/... on a genuinely
/// too-long path with no embedded weirdness) now gets the real `ENAMETOOLONG` POSIX requires,
/// where it previously fell through to whatever `resolve_parent`'s own component walk happened to
/// produce instead.
const OXFS_PATH_MAX: usize = 4096;

/// `static mut`, not `static` -- same requirement `modules/fat32`'s own `DISK`/`OPEN_FILES` have
/// (see that module's doc comment): every read happens from within this module's own exported,
/// syscall-reachable functions, whose results feed observably into `oxidebsd_log`/syscall return
/// values, so the optimizer can't treat any write as an unobservable dead store. All-zero initial
/// values place these in `.bss` (not baked into the merged object's own size).
/// Free blocks in each bitmap block (`BITS_PER_BITMAP_BLOCK` data blocks), resident so the
/// allocator and `statfs` never read a full bitmap block to learn it's full. Allocated in
/// `init_pools` for the largest filesystem the device can hold; counts are set at mount/format.
static mut FREE_COUNTS: *mut u32 = core::ptr::null_mut();
/// A fresh inode of `kind`, stamped with the current time.
fn fresh_inode(kind: InodeKind) -> Inode {
    Inode::new(kind, unsafe { oxidebsd_unix_time() })
}

/// Bitmap block `index`'s free count.
fn free_count(index: u32) -> &'static mut u32 {
    // SAFETY: `index < bitmap_blocks()`, inside the `init_pools` allocation.
    unsafe { &mut *FREE_COUNTS.add(index as usize) }
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
    /// Where `alloc_inode_from` starts looking.
    hint: u32,
}

impl InodeTable {
    const EMPTY: InodeTable = InodeTable { file: Inode::FREE, count: 0, free: 0, hint: 0 };
}

static mut DISK_INODES: InodeTable = InodeTable::EMPTY;

fn inode_table() -> &'static mut InodeTable {
    // SAFETY: single-core, syscall-serialized access (as every pool here); callers never hold the
    // reference across a call that takes it again.
    unsafe { &mut *core::ptr::addr_of_mut!(DISK_INODES) }
}

/// Claims real kernel-allocated storage for the cache and `FREE_COUNTS` -- must run
/// first, before
/// `module_init`'s mount-or-format decision (or anything else) ever calls `read_block`/
/// `write_block`. Returns `false` on failure (kernel out of memory), which
/// `module_init` treats as a fatal `module_init` failure like any other -- this module's own
/// `fatal_on_panic = true` (see `sys/kernel_main.rs`, kernel tree) reboots rather than resuming
/// with a filesystem that has nowhere to actually store a block.
fn init_pools() -> bool {
    let device_blocks = buf::device_blocks();
    if !buf::init() {
        return false;
    }
    let (_, most_bitmap_blocks) = layout_for(device_blocks);
    let counts = unsafe { oxidebsd_module_alloc_zeroed(most_bitmap_blocks.max(1) as u64 * 4) };
    if counts == 0 {
        return false;
    }
    // SAFETY: inside `module_init`, before any syscall.
    unsafe { FREE_COUNTS = counts as *mut u32 };
    true
}

/// Runs `f` on block `n` in place, for reads that don't want `read_block`'s 4 KiB copy (index
/// blocks, inode records). `f` must not touch another block: a disk block is lent from the cache.
fn with_block<R>(n: u32, f: impl FnOnce(&[u8; BLOCK_SIZE]) -> R) -> R {
    buf::with(data_block_offset() + n, f)
}

fn read_block(n: u32) -> [u8; BLOCK_SIZE] {
    with_block(n, |b| *b)
}

/// The regular file whose writes are being delayed (§3.3.2), `NO_OWNER` when none: set by
/// `delay_writes_of` for the length of a write, resize or atime update of that file.
static mut DELAY_OWNER: u32 = NO_OWNER;
const NO_OWNER: u32 = u32::MAX;

fn delay_owner() -> Option<u32> {
    // SAFETY: single-core, syscall-serialized.
    let owner = unsafe { *core::ptr::addr_of!(DELAY_OWNER) };
    (owner != NO_OWNER).then_some(owner)
}

/// Restores the previous delay context when dropped.
struct Delayed(u32);

impl Drop for Delayed {
    fn drop(&mut self) {
        // SAFETY: as `delay_owner`.
        unsafe { *core::ptr::addr_of_mut!(DELAY_OWNER) = self.0 };
    }
}

/// Until the returned guard drops, the data blocks, index blocks and inode record of `n` are
/// written back later instead of at once -- if `n` is a regular file on the disk. Everything
/// else (directories, symlinks, names, the bitmap) stays synchronous (§3.3.1).
fn delay_writes_of(n: u32) -> Delayed {
    // SAFETY: as `delay_owner`.
    let previous = unsafe { *core::ptr::addr_of!(DELAY_OWNER) };
    if read_inode(n).kind == InodeKind::File {
        unsafe { *core::ptr::addr_of_mut!(DELAY_OWNER) = n };
    }
    Delayed(previous)
}

/// Stores block `n`. Inside `delay_writes_of`, it's that file's data: left dirty in the cache.
/// Otherwise it reaches the disk before the system call returns.
fn write_block(n: u32, data: &[u8; BLOCK_SIZE]) {
    if let Some(owner) = delay_owner() {
        buf::store(data_block_offset() + n, data, buf::Kind::Data(owner));
    } else {
        buf::write(data_block_offset() + n, data, buf::Kind::Meta);
    }
}

/// `write_block` for an index (indirect) block: delayed as that file's index block, so it can't
/// reach the disk before the data blocks it points at.
fn write_index_block(n: u32, data: &[u8; BLOCK_SIZE]) {
    if let Some(owner) = delay_owner() {
        buf::store(data_block_offset() + n, data, buf::Kind::Index(owner));
    } else {
        buf::write(data_block_offset() + n, data, buf::Kind::Meta);
    }
}

/// Bitmap block and bit for disk block `n`.
fn bitmap_position(n: u32) -> (u32, usize) {
    (n / BITS_PER_BITMAP_BLOCK, (n % BITS_PER_BITMAP_BLOCK) as usize)
}


/// Marks block `n` used or free: a read-modify-write of its bitmap block through the cache, with
/// that block's free count kept in step.
fn set_block_used(n: u32, used: bool) {
    let (index, bit) = bitmap_position(n);
    let mut block = buf::read(BITMAP_START + index);
    let was = block[bit / 8] & (1 << (bit % 8)) != 0;
    if was == used {
        return;
    }
    block[bit / 8] ^= 1 << (bit % 8);
    buf::write(BITMAP_START + index, &block, buf::Kind::Meta);
    let count = free_count(index);
    if used { *count -= 1 } else { *count += 1 }
}

/// Where inode `n`'s record is: its inode-file block and byte offset. `None` past the table.
fn inode_location(n: u32) -> Option<(u32, usize)> {
    let slot = n;
    let table = inode_table();
    if slot >= table.count {
        return None;
    }
    let block = inode_block_at(&table.file, slot as usize / INODES_PER_BLOCK)?;
    Some((block, slot as usize % INODES_PER_BLOCK * INODE_STRIDE))
}

/// Inode `n`, or a free one if `n` is past its table.
fn read_inode(n: u32) -> Inode {
    match inode_location(n) {
        Some((block, off)) => with_block(block, |b| unpack_inode(&b[off..off + INODE_STRIDE])),
        None => Inode::FREE,
    }
}

/// Stores inode `n` (persisted with its block, like any data), keeping the table's free count.
/// `n` must be in its table: numbers come from `alloc_inode_from`.
fn write_inode(n: u32, inode: Inode) {
    let Some((block, off)) = inode_location(n) else {
        return;
    };
    let was_free = with_block(block, |b| b[off] == 0);
    let mut data = read_block(block);
    pack_inode(&inode, &mut data[off..off + INODE_STRIDE]);
    // An inode-file block: written after the dirty data and index blocks of the inodes in it (the
    // cache's ordering, `buf`); left dirty only for the file whose writes are being delayed.
    let kind = buf::Kind::Inodes(n - n % INODES_PER_BLOCK as u32);
    let dev = data_block_offset() + block;
    if delay_owner() == Some(n) {
        buf::store(dev, &data, kind);
    } else {
        buf::write(dev, &data, kind);
    }
    let is_free = inode.kind == InodeKind::Free;
    let table = inode_table();
    match (was_free, is_free) {
        (true, false) => table.free -= 1,
        (false, true) => table.free += 1,
        _ => {}
    }
}

/// Resume-scan cursor for `alloc_block` -- see that function's own doc comment for why a bare
/// linear-from-`0` scan (this module's original design) stopped being viable once `NUM_BLOCKS`
/// grew large enough for real big-file writes to actually matter.
static mut NEXT_FREE_BLOCK: u32 = 0;

/// Finds and claims the first free block, starting from `NEXT_FREE_BLOCK` rather
/// than always rescanning from `0` -- this module's blocks are **never freed** in normal operation
/// (`unlink`/`rmdir` only clear a directory record's `used` byte, matching this module's own
/// blanket "no deallocation anywhere" stance) -- so once
/// this cursor passes a block, no future call can ever need to look at it again, making this a real
/// bump allocator in practice (the loop below only ever iterates more than once during whatever
/// startup seeding leaves a stale cursor behind, e.g. right after `mount_from_disk` loads a bitmap
/// with a real prefix already marked used). A bare rescan-from-`0` scan (this function's original
/// design, "fine at this module's scale" when `NUM_BLOCKS` was in the low thousands) becomes a real
/// `O(n^2)` cost filling the whole pool once `NUM_BLOCKS` is large enough for a genuinely big real
/// file to matter -- the same class of bug `memory::BootInfoFrameAllocator`'s own doc comment
/// already warns about for the physical frame allocator, fixed here the same way: cursor state, not
/// a rebuilt-each-call scan.
fn alloc_block() -> Option<u32> {
    let start = unsafe { *core::ptr::addr_of!(NEXT_FREE_BLOCK) };
    let total = disk_blocks();
    let mut index = start / BITS_PER_BITMAP_BLOCK;
    while index < bitmap_blocks() {
        // A full bitmap block is skipped on its resident count, without reading it.
        if *free_count(index) > 0 {
            let base = index * BITS_PER_BITMAP_BLOCK;
            let from = start.max(base) - base;
            let end = (total - base).min(BITS_PER_BITMAP_BLOCK);
            let found = buf::with(BITMAP_START + index, |b| {
                (from..end).find(|&bit| b[bit as usize / 8] & (1 << (bit % 8)) == 0)
            });
            if let Some(bit) = found {
                let n = base + bit;
                set_block_used(n, true);
                write_block(n, &[0u8; BLOCK_SIZE]);
                unsafe { *core::ptr::addr_of_mut!(NEXT_FREE_BLOCK) = n + 1 };
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
fn alloc_indirect_block() -> Option<u32> {
    let n = alloc_block()?;
    write_index_block(n, &[0xFFu8; BLOCK_SIZE]);
    Some(n)
}

fn alloc_inode() -> Option<u32> {
    alloc_inode_from()
}

// --- Reclamation -----------------------------------------------------------------------------
//
// An inode is freed, with every block it addresses, once nothing refers to it: no name
// (`nlink == 0`) and no vnode of it in use (`vfs::inode_busy`: a descriptor, a working or root
// directory, a mapping, a running program, a bound socket file -- every kernel holder holds a
// vnode). Its last vnode going inactive asks again (`vfs::oxfs_vop_inactive`). One left over at a
// reboot (open when the system stopped) is freed by the sweep after mounting
// (`sweep_unnamed_inodes`), and its vnode, if any, recycled (`vfs::inode_freed`).

/// Returns block `n` to its pool; the disk pool's allocation cursor steps back so it's reused.
fn free_block(n: u32) {
    buf::discard(data_block_offset() + n);
    set_block_used(n, false);
    // SAFETY: single-core, syscall-serialized, as `alloc_block`.
    unsafe {
        let cursor = &mut *core::ptr::addr_of_mut!(NEXT_FREE_BLOCK);
        if n < *cursor {
            *cursor = n;
        }
    }
}

/// Frees index block `ib` and the data blocks it points to.
fn free_index_block(ib: u32) {
    for slot in 0..PTRS_PER_INDIRECT {
        let b = read_index_ptr(ib, slot);
        if b != NO_BLOCK {
            free_block(b);
        }
    }
    free_block(ib);
}

/// Frees every block `inode` addresses, index blocks included.
fn free_inode_blocks(inode: &Inode) {
    for &b in &inode.direct {
        if b != NO_BLOCK {
            free_block(b);
        }
    }
    if inode.indirect != NO_BLOCK {
        free_index_block(inode.indirect);
    }
    if inode.double_indirect != NO_BLOCK {
        for slot in 0..PTRS_PER_INDIRECT {
            let inner = read_index_ptr(inode.double_indirect, slot);
            if inner != NO_BLOCK {
                free_index_block(inner);
            }
        }
        free_block(inode.double_indirect);
    }
}

/// Frees inode `n` if nothing refers to it any more (see the section comment); keeps it as an
/// orphan if only the kernel does.
fn maybe_release(n: u32) {
    let inode = read_inode(n);
    // A file in use (open, a cwd, mapped, running, a lookup in progress) keeps its storage until
    // its vnode goes inactive (`vfs::oxfs_vop_inactive`), which asks again: every holder in the
    // kernel holds a vnode now (VFS.md §11 step 2c).
    if n == ROOT_INODE || inode.kind == InodeKind::Free || inode.nlink > 0 || vfs::inode_busy(n) {
        return;
    }
    release_inode(n, inode);
}

/// Frees inode `n` (whose record is `inode`) and its blocks. The record goes first: interrupted
/// between the two, the disk leaks blocks rather than keeping an inode that points at blocks
/// someone else may be given.
fn release_inode(n: u32, inode: Inode) {
    // Its unwritten data and index blocks are about to be freed: never write them.
    buf::discard_owned(n);
    write_inode(n, Inode::FREE);
    free_inode_blocks(&inode);
    trim_inode_table();
    // The number may be handed out again: a vnode left of the old file must not answer for it.
    vfs::inode_freed(n);
}

/// After mounting: frees every inode left without a name by the last boot (open, mapped or a
/// working directory when it went down). Nothing can refer to one yet. Runs once persistence is
/// on, so the frees and any trimming of the inode file reach the disk.
fn sweep_unnamed_inodes() {
    let count = inode_table().count;
    let mut freed: u32 = 0;
    for n in 1..count {
        let inode = read_inode(n);
        if inode.kind != InodeKind::Free && inode.nlink == 0 {
            release_inode(n, inode);
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

/// Clears inode-file block `index`'s pointer in `file` and frees the block, along with any index
/// block that pointer was the first entry of. Only the table's last block is ever unmapped, so an
/// index block whose first entry goes has no others left.
fn unmap_last_block(file: &mut Inode, index: usize) {
    if index < DIRECT_BLOCKS {
        free_block(file.direct[index]);
        file.direct[index] = NO_BLOCK;
        return;
    }
    let clear = |ib: u32, slot: usize| {
        let mut data = read_block(ib);
        let b = u32::from_le_bytes(data[slot * 4..slot * 4 + 4].try_into().unwrap());
        data[slot * 4..slot * 4 + 4].copy_from_slice(&NO_BLOCK.to_le_bytes());
        write_block(ib, &data);
        b
    };
    let i = index - DIRECT_BLOCKS;
    if i < PTRS_PER_INDIRECT {
        free_block(clear(file.indirect, i));
        if i == 0 {
            free_block(file.indirect);
            file.indirect = NO_BLOCK;
        }
        return;
    }
    let i = i - PTRS_PER_INDIRECT;
    let (outer, inner) = (i / PTRS_PER_INDIRECT, i % PTRS_PER_INDIRECT);
    let inner_block = read_index_ptr(file.double_indirect, outer);
    free_block(clear(inner_block, inner));
    if inner == 0 {
        clear(file.double_indirect, outer);
        free_block(inner_block);
        if outer == 0 {
            free_block(file.double_indirect);
            file.double_indirect = NO_BLOCK;
        }
    }
}

/// Gives the table's last blocks back to the pool while they hold only free inodes (the first
/// block, holding the root, always stays). The disk table's new shape goes to the superblock
/// before its blocks are freed, so an interruption can only leak them.
fn trim_inode_table() {
    let per_block = INODES_PER_BLOCK as u32;
    loop {
        let table = *inode_table();
        if table.count <= per_block {
            return;
        }
        let first = table.count - per_block;
        if (first..table.count).any(|slot| read_inode(slot).kind != InodeKind::Free) {
            return;
        }
        let mut file = table.file;
        file.size = first as u64 * INODE_STRIDE as u64;
        {
            let t = inode_table();
            t.count = first;
            t.free -= per_block;
            t.hint = t.hint.min(first);
            t.file.size = file.size;
        }
        if persistence_ready() && block_device_present() {
            write_superblock();
        }
        unmap_last_block(&mut file, first as usize / INODES_PER_BLOCK);
        inode_table().file = file;
        if persistence_ready() && block_device_present() {
            write_superblock();
        }
    }
}

/// A free inode number, growing the table by a block when none is free. The caller writes the new
/// inode.
fn alloc_inode_from() -> Option<u32> {
    if inode_table().free == 0 {
        grow_inode_table()?;
    }
    let table = *inode_table();
    let start = table.hint.min(table.count);
    let slot = (start..table.count)
        .chain(0..start)
        .find(|&slot| read_inode(slot).kind == InodeKind::Free)?;
    inode_table().hint = slot + 1;
    Some(slot)
}

/// Adds a block of free inodes to the table (`None` when the disk is out of blocks or the number
/// range is used up). The table's new shape goes to the superblock.
fn grow_inode_table() -> Option<()> {
    let table = *inode_table();
    if table.count as u64 + INODES_PER_BLOCK as u64 > MAX_DISK_INODES as u64 {
        return None;
    }
    let mut file = table.file;
    // A fresh block from `alloc_block` is zeroed: `INODES_PER_BLOCK` free records.
    ensure_block(&mut file, table.count as usize / INODES_PER_BLOCK)?;
    let count = table.count + INODES_PER_BLOCK as u32;
    file.size = count as u64 * INODE_STRIDE as u64;
    let t = inode_table();
    t.file = file;
    t.count = count;
    t.free += INODES_PER_BLOCK as u32;
    if persistence_ready() && block_device_present() {
        write_superblock();
    }
    Some(())
}

/// A new inode for an entry in `parent`.
fn alloc_inode_in(_parent: u32) -> Option<u32> {
    alloc_inode()
}

/// Reads a real block-number pointer out of index block `ib_num` at slot `slot` -- the same
/// 4-byte-little-endian-pointer decoding `inode_block_at`/`inode_ensure_block_at` need at every
/// indirection tier (a single-indirect block's own slots, and both levels of a double-indirect
/// block's own two-level slot chain), factored out once there were three call sites instead of one.
fn read_index_ptr(ib_num: u32, slot: usize) -> u32 {
    let off = slot * 4;
    with_block(ib_num, |ib| u32::from_le_bytes([ib[off], ib[off + 1], ib[off + 2], ib[off + 3]]))
}

/// Reads the block number backing `inode`'s logical block `index` -- direct, then (past
/// `DIRECT_BLOCKS`) via the single-indirect block, then (past that) via the double-indirect block
/// (see `Inode::double_indirect`'s own doc comment for the three-tier addressing scheme this
/// implements) -- or `None` if that block was never allocated.
fn inode_block_at(inode: &Inode, index: usize) -> Option<u32> {
    if index < DIRECT_BLOCKS {
        let b = inode.direct[index];
        return (b != NO_BLOCK).then_some(b);
    }
    let index = index - DIRECT_BLOCKS;
    if index < PTRS_PER_INDIRECT {
        if inode.indirect == NO_BLOCK {
            return None;
        }
        let b = read_index_ptr(inode.indirect, index);
        return (b != NO_BLOCK).then_some(b);
    }
    let index = index - PTRS_PER_INDIRECT;
    if inode.double_indirect == NO_BLOCK || index >= PTRS_PER_DOUBLE_INDIRECT {
        return None;
    }
    let outer_slot = index / PTRS_PER_INDIRECT;
    let inner_slot = index % PTRS_PER_INDIRECT;
    let inner_block = read_index_ptr(inode.double_indirect, outer_slot);
    if inner_block == NO_BLOCK {
        return None;
    }
    let b = read_index_ptr(inner_block, inner_slot);
    (b != NO_BLOCK).then_some(b)
}

/// Like `inode_block_at`, but allocates a fresh block (and, if needed, a fresh indirect block)
/// when `index` isn't backed by one yet -- used by both real file writes and directory growth.
/// Takes an inode *number*, not `&mut Inode`: every access to `INODES`/`BLOCKS` in this module
/// goes through the copy-in/copy-out helpers above, so no reference to either static is ever held
/// across a nested call (`alloc_block` here) that itself touches them.
fn inode_ensure_block_at(inode_num: u32, index: usize) -> Option<u32> {
    let mut inode = read_inode(inode_num);
    let result = ensure_block(&mut inode, index);
    write_inode(inode_num, inode);
    result
}

/// `inode_ensure_block_at` on an inode record held by the caller (the inode files' own records
/// aren't numbered).
fn ensure_block(inode: &mut Inode, index: usize) -> Option<u32> {
    if index < DIRECT_BLOCKS {
        if inode.direct[index] == NO_BLOCK {
            inode.direct[index] = alloc_block()?;
        }
        Some(inode.direct[index])
    } else if index - DIRECT_BLOCKS < PTRS_PER_INDIRECT {
        let indirect_index = index - DIRECT_BLOCKS;
        if inode.indirect == NO_BLOCK {
            inode.indirect = alloc_indirect_block()?;
        }
        ensure_index_slot(inode.indirect, indirect_index)
    } else {
        // Double-indirect tier -- see `Inode::double_indirect`'s own doc comment. `outer_slot`
        // picks (allocating if needed) the one inner index block covering `inner_slot`'s own
        // range, then `ensure_index_slot` does the same real-block allocation `inode_ensure_block_
        // at`'s single-indirect branch above already does, just one level deeper.
        let index = index - DIRECT_BLOCKS - PTRS_PER_INDIRECT;
        if index >= PTRS_PER_DOUBLE_INDIRECT {
            return None;
        }
        let outer_slot = index / PTRS_PER_INDIRECT;
        let inner_slot = index % PTRS_PER_INDIRECT;
        if inode.double_indirect == NO_BLOCK {
            inode.double_indirect = alloc_indirect_block()?;
        }
        let mut outer = read_block(inode.double_indirect);
        let outer_off = outer_slot * 4;
        let mut inner_block = u32::from_le_bytes(
            outer[outer_off..outer_off + 4].try_into().unwrap(),
        );
        if inner_block == NO_BLOCK {
            inner_block = alloc_indirect_block()?;
            outer[outer_off..outer_off + 4].copy_from_slice(&inner_block.to_le_bytes());
            write_index_block(inode.double_indirect, &outer);
        }
        ensure_index_slot(inner_block, inner_slot)
    }
}

/// Shared by `inode_ensure_block_at`'s single-indirect branch and its double-indirect branch's own
/// inner tier: reads index block `ib_num`'s pointer at `slot`, allocating and writing back a fresh
/// data-block pointer if that slot is still `NO_BLOCK`.
fn ensure_index_slot(ib_num: u32, slot: usize) -> Option<u32> {
    let mut ib = read_block(ib_num);
    let off = slot * 4;
    let existing = u32::from_le_bytes(ib[off..off + 4].try_into().unwrap());
    if existing != NO_BLOCK {
        return Some(existing);
    }
    let nb = alloc_block()?;
    ib[off..off + 4].copy_from_slice(&nb.to_le_bytes());
    write_index_block(ib_num, &ib);
    Some(nb)
}

/// Reads up to `out.len()` bytes starting at `position` within `inode_num`'s data, honoring its
/// stored `size` (real files only -- directories never call this, they walk raw records instead).
/// Returns the number of bytes actually read (`0` at or past EOF).
fn read_inode_at(inode_num: u32, position: usize, out: &mut [u8]) -> usize {
    let mut written = 0;
    let _ = read_inode_with(inode_num, position, out.len(), |chunk| {
        out[written..written + chunk.len()].copy_from_slice(chunk);
        written += chunk.len();
        Ok(())
    });
    written
}

/// `read_inode_at` into a read transfer (`uio`): straight from the block pool, no buffer in
/// between. `Ok(count)` or `Err(-errno)`.
fn read_inode_uio(inode_num: u32, position: usize, uio: u64) -> Result<usize, i64> {
    read_inode_with(inode_num, position, uio_resid(uio), |chunk| uio_out(uio, chunk).map(|_| ()))
}

/// The block walk `read_inode_at` and `read_inode_uio` share: hands `sink` up to `max` bytes of
/// `inode_num`'s content from `position`, one block's worth at a time. Stops at end of file, or at
/// a missing block. `Ok(count)`, or the first error `sink` returns.
fn read_inode_with(
    inode_num: u32,
    position: usize,
    max: usize,
    mut sink: impl FnMut(&[u8]) -> Result<(), i64>,
) -> Result<usize, i64> {
    let inode = read_inode(inode_num);
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
        let Some(blk) = inode_block_at(&inode, block_index) else {
            break;
        };
        let block = read_block(blk);
        let chunk = (n - written).min(BLOCK_SIZE - in_block_off);
        sink(&block[in_block_off..in_block_off + chunk])?;
        written += chunk;
    }
    Ok(written)
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

// --- User memory (`OxideBSD-doc/USERMEM.md`) ----------------------------------------------------
//
// A system call's pointer arguments are user addresses: never dereferenced here, only copied in
// and out through the kernel's `oxidebsd_copyin`/`oxidebsd_copyout`, which fail with `EFAULT`
// instead of faulting.

/// Writes `content` as `inode_num`'s complete contents (replacing whatever was there before),
/// allocating whatever blocks are needed and setting `size`. `write(2)` writes positionally
/// (`write_inode_uio`); this whole-content-replace shape is right for its one real caller, `oxfs_inode_content_write` (real fd-backed `MAP_SHARED`
/// mmap writeback, which always supplies a mapping's complete current content).
fn write_inode_data(inode_num: u32, content: &[u8]) -> bool {
    let block_count = content.len().div_ceil(BLOCK_SIZE);
    for i in 0..block_count {
        let Some(blk) = inode_ensure_block_at(inode_num, i) else {
            return false;
        };
        let start = i * BLOCK_SIZE;
        let end = (start + BLOCK_SIZE).min(content.len());
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..end - start].copy_from_slice(&content[start..end]);
        write_block(blk, &buf);
    }
    let mut inode = read_inode(inode_num);
    inode.size = content.len() as u64;
    let now = unsafe { oxidebsd_unix_time() };
    inode.mtime = now;
    inode.ctime = now;
    write_inode(inode_num, inode);
    true
}

/// Real `st_atime` update -- see `Inode::atime`'s own doc comment for the POSIX text this
/// implements and why bumping it here (rather than tracking each mmap'd page's own first-touch)
/// is spec-legal. Skips the write-through entirely if the whole-second value hasn't changed since
/// the last touch -- a real, common Unix optimization (POSIX only requires atime be "marked for
/// update," not persisted with per-read precision), not a fake pass condition; keeps a tight read
/// loop from re-persisting the same inode-table block on every single call.
fn touch_atime(inode_num: u32) {
    if read_only_at(inode_num) {
        return;
    }
    let _delayed = delay_writes_of(inode_num);
    let mut inode = read_inode(inode_num);
    let now = unsafe { oxidebsd_unix_time() };
    if inode.atime == now {
        return;
    }
    inode.atime = now;
    write_inode(inode_num, inode);
}

/// `SYS_FTRUNCATE`/`SYS_FALLOCATE`'s real logic -- resizes `inode_num`'s content to exactly
/// `new_size` bytes without ever materializing the file's complete old-or-new content in one
/// buffer the way `write_inode_data` does: growing zero-fills only the newly-added region,
/// block by block, via the same `inode_ensure_block_at`/`write_block` primitives
/// `write_inode_data` itself uses internally; shrinking touches no block content at all (bytes
/// past the new `size` simply become unreachable -- `read_inode_at` already never reads past
/// `inode.size`, and a later grow back past the old size would zero-fill over them again, matching
/// real POSIX "grow into a hole reads as zero" semantics either way). Load-bearing for staying
/// off the stack: this filesystem's real per-file addressing ceiling is `MAX_FILE_SIZE` (~4.1
/// GiB, see `Inode::double_indirect`'s own doc comment), far past what this kernel's 128 KiB
/// kernel-stack floor could ever hold as one local buffer.
fn resize_inode_data(inode_num: u32, new_size: usize) -> bool {
    let _delayed = delay_writes_of(inode_num);
    let old_size = read_inode(inode_num).size as usize;
    if new_size > old_size {
        let mut pos = old_size;
        while pos < new_size {
            let block_index = pos / BLOCK_SIZE;
            let in_block_off = pos % BLOCK_SIZE;
            let Some(blk) = inode_ensure_block_at(inode_num, block_index) else {
                return false;
            };
            let mut block = read_block(blk);
            let chunk = (new_size - pos).min(BLOCK_SIZE - in_block_off);
            for b in &mut block[in_block_off..in_block_off + chunk] {
                *b = 0;
            }
            write_block(blk, &block);
            pos += chunk;
        }
    }
    let mut inode = read_inode(inode_num);
    inode.size = new_size as u64;
    let now = unsafe { oxidebsd_unix_time() };
    inode.mtime = now;
    inode.ctime = now;
    write_inode(inode_num, inode);
    true
}

/// `write_inode_at` from a write transfer (`uio`): straight into the block pool. The count
/// written, short when the filesystem fills or a fault stops it partway, as `write(2)` reports.
fn write_inode_uio(inode_num: u32, position: usize, uio: u64) -> Result<usize, i64> {
    let n = uio_resid(uio);
    write_inode_with(inode_num, position, n, |dst| uio_in(uio, dst).map(|_| ()))
}

/// The block walk `write_inode_at` and `write_inode_uio` share: `fill` supplies each block's
/// share of the `len` bytes written at `position`. Returns how many bytes were written; an error
/// (`-ENOSPC` when a block can't be allocated, or the first error `fill` returns) only when that's
/// none. The size and times cover whatever was written.
fn write_inode_with(
    inode_num: u32,
    position: usize,
    len: usize,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), i64>,
) -> Result<usize, i64> {
    let _delayed = delay_writes_of(inode_num);
    let old_size = read_inode(inode_num).size as usize;
    if position > old_size && !resize_inode_data(inode_num, position) {
        return Err(-ENOSPC);
    }
    let mut pos = position;
    let mut written = 0;
    let mut result = Ok(());
    while written < len {
        let block_index = pos / BLOCK_SIZE;
        let in_block_off = pos % BLOCK_SIZE;
        let Some(blk) = inode_ensure_block_at(inode_num, block_index) else {
            result = Err(-ENOSPC);
            break;
        };
        let mut block = read_block(blk);
        let chunk = (len - written).min(BLOCK_SIZE - in_block_off);
        // A failed fill may have half-written `block`: it isn't stored.
        if let Err(e) = fill(&mut block[in_block_off..in_block_off + chunk]) {
            result = Err(e);
            break;
        }
        // A regular file's data stays dirty in the cache (`delay_writes_of`) and goes to the
        // disk later, in long runs; anything else is written now.
        write_block(blk, &block);
        pos += chunk;
        written += chunk;
    }
    let mut inode = read_inode(inode_num);
    if pos > inode.size as usize {
        inode.size = pos as u64;
    }
    let now = unsafe { oxidebsd_unix_time() };
    inode.mtime = now;
    inode.ctime = now;
    write_inode(inode_num, inode);
    // Back-pressure (§3.2.5): a writer that has filled half the cache with unwritten blocks waits
    // for them, rather than leave eviction to write them a block at a time.
    if buf::mostly_dirty() {
        buf::flush_all();
    }
    match result {
        Err(e) if written == 0 => Err(e),
        _ => Ok(written),
    }
}

/// Byte-exact mirror of musl's `struct stat` for x86_64 (`arch/x86_64/bits/stat.h` in
/// `external/mit/musl`) -- `dev_t`/`ino_t`/`nlink_t`/`off_t`/`blksize_t`/`blkcnt_t` are all 64-bit
/// on this target, and `struct timespec`'s `{tv_sec, tv_nsec}` is bit-identical to two raw `i64`s
/// here, so this `repr(C)` struct's natural layout already matches the real one field-for-field --
/// no manual padding needed beyond `__pad0` (which upstream also has explicitly, between the
/// `u32` id fields and the next `u64`). `src/stat/{stat,fstat,lstat}.c` on the `oxidebsd` musl
/// branch write straight into this shape, bypassing musl's usual `fstatat`/`kstat` indirection
/// entirely (same "patch the entry point, not the generic multiplexer" pattern `open()`/`chdir()`/
/// `mkdir()` already established -- see `CLAUDE.md`'s musl section). Every field sits at its
/// natural alignment and the size is a multiple of 8, so there are no implicit padding bytes to
/// leak when it's copied out.
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

/// `write_stat`'s `struct stat`.
fn inode_stat(inode_num: u32) -> MuslStat {
    let inode = read_inode(inode_num);
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

/// Real POSIX permission check: `uid == 0` (root) bypasses every bit entirely, same as every real
/// Unix — this kernel's own single-user reality (root is the only uid that has ever existed so
/// far, see `Process::uid`'s own doc comment in `sys/process.rs`) means this always evaluates to
/// `true` today, but the logic is real, not a stub — it'll start mattering the moment `setuid`
/// actually gets used to drop privilege. Otherwise picks the owner/group/other rwx triplet by
/// comparing against the inode's own `uid`/`gid` (first match wins, real Unix semantics: being in
/// the owning group doesn't fall through to "other" just because the group bits happen to deny
/// it), then requires every bit in `want` (`R_OK`/`W_OK`/`X_OK`, singly or combined — real
/// `access(2)`'s own encoding, see the constants above) to be set. `oxfs_open`'s own existing
/// callers only ever pass a single bit (`R_OK` or `W_OK`); `oxfs_access` below is the one caller
/// that can pass a real combination.
/// The group a new file, directory, node or symlink in `parent` gets: `parent`'s, as on all
/// three BSDs (POSIX allows this or the creator's group). Its owner is always the creator.
fn new_entry_gid(parent: u32) -> u32 {
    read_inode(parent).gid
}



/// Looks `name` up directly inside `dir_inode` (path walking is the kernel's `namei`). `name` may
/// be `.`/`..`, both stored as real records like any other (self-referencing for the root).
fn dir_lookup(dir_inode: u32, name: &[u8]) -> Option<u32> {
    let inode = read_inode(dir_inode);
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) && dir_record_name(&block, r) == name {
                return Some(dir_record_inode(&block, r));
            }
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum OxfsError {
    NotFound,
    DiskFull,
    /// A real, whole path argument exceeded `OXFS_PATH_MAX` -- see that constant's own doc comment.
    NameTooLong,
}

fn errno_for(e: OxfsError) -> i64 {
    -match e {
        OxfsError::NotFound => ENOENT,
        OxfsError::DiskFull => ENOSPC,
        OxfsError::NameTooLong => ENAMETOOLONG,
    }
}

/// Marks `dir_inode` changed after an entry was added or removed: POSIX has `creat`, `mkdir`,
/// `link`, `symlink`, `mknod`, `unlink`, `rmdir` and `rename` update the directory's `st_mtime`
/// and `st_ctime`, and programs rely on it to notice a directory's contents changed (cron(8)
/// rereads `/etc/cron.d` when its time moves). Like `touch_atime`, skips the write when the
/// stamp already holds this second, which keeps seeding thousands of files cheap.
fn touch_dir(dir_inode: u32) {
    let mut inode = read_inode(dir_inode);
    let now = unsafe { oxidebsd_unix_time() };
    if inode.mtime == now && inode.ctime == now {
        return;
    }
    inode.mtime = now;
    inode.ctime = now;
    write_inode(dir_inode, inode);
}

/// Inserts a new `(name, target_inode)` record into `dir_inode`, reusing the first free (cleared
/// by a previous `dir_remove`) or never-yet-used record slot -- growing `dir_inode` with a fresh
/// block via `inode_ensure_block_at` if every existing block is full. This is the "a directory can
/// grow past its first cluster" fix over `modules/fat32`'s own `DirectoryFull`/`ENOSPC` dead end.
fn dir_insert(dir_inode: u32, name: &[u8], target_inode: u32) -> Result<(), OxfsError> {
    // Real `ENAMETOOLONG`, not `EINVAL` -- see `NAME_MAX`'s own doc comment above for the real bug
    // this was: BusyBox tar's own extraction loop aborted the whole archive on the wrong errno for
    // a too-long name instead of skipping/reporting just that one file.
    if name.len() > NAME_MAX {
        return Err(OxfsError::NameTooLong);
    }
    let inode = read_inode(dir_inode);
    let mut i = 0;
    loop {
        match inode_block_at(&inode, i) {
            Some(blk) => {
                let mut block = read_block(blk);
                for r in 0..RECORDS_PER_BLOCK {
                    if !dir_record_used(&block, r) {
                        write_dir_record(&mut block, r, name, target_inode);
                        write_block(blk, &block);
                        touch_dir(dir_inode);
                        return Ok(());
                    }
                }
                i += 1;
            }
            None => {
                let Some(blk) = inode_ensure_block_at(dir_inode, i) else {
                    return Err(OxfsError::DiskFull);
                };
                // inode_ensure_block_at hands back a freshly zeroed block (record 0 is free) --
                // no need to scan it first.
                let mut block = [0u8; BLOCK_SIZE];
                write_dir_record(&mut block, 0, name, target_inode);
                write_block(blk, &block);
                touch_dir(dir_inode);
                return Ok(());
            }
        }
    }
}

/// Clears the record named `name` inside `dir_inode` -- the underlying inode/blocks are *not*
/// freed (see the module doc comment). `Err(NotFound)` if no such record exists (callers normally
/// check via `dir_lookup` first, so this mostly can't fail in practice).
fn dir_remove(dir_inode: u32, name: &[u8]) -> Result<(), OxfsError> {
    let inode = read_inode(dir_inode);
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let mut block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) && dir_record_name(&block, r) == name {
                clear_dir_record(&mut block, r);
                write_block(blk, &block);
                dir_trim(dir_inode);
                touch_dir(dir_inode);
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
fn dir_trim(dir_inode: u32) {
    loop {
        let inode = read_inode(dir_inode);
        let mut count = 0;
        while inode_block_at(&inode, count).is_some() {
            count += 1;
        }
        if count <= 1 {
            return;
        }
        let last = count - 1;
        let Some(blk) = inode_block_at(&inode, last) else { return };
        if with_block(blk, |b| (0..RECORDS_PER_BLOCK).any(|r| dir_record_used(b, r))) {
            return;
        }
        if !clear_last_block_pointer(dir_inode, last) {
            return;
        }
        free_block(blk);
    }
}

/// Clears the pointer to block `index`, the last of inode `n`'s blocks, freeing the single-index
/// block too when that leaves it empty. `false` past the single-indirect range (not trimmed).
fn clear_last_block_pointer(n: u32, index: usize) -> bool {
    let mut inode = read_inode(n);
    if index < DIRECT_BLOCKS {
        inode.direct[index] = NO_BLOCK;
        write_inode(n, inode);
        return true;
    }
    let slot = index - DIRECT_BLOCKS;
    if slot >= PTRS_PER_INDIRECT || inode.indirect == NO_BLOCK {
        return false;
    }
    let mut ib = read_block(inode.indirect);
    ib[slot * 4..slot * 4 + 4].copy_from_slice(&NO_BLOCK.to_le_bytes());
    write_index_block(inode.indirect, &ib);
    if slot == 0 {
        // Its last pointer gone: the index block goes too.
        let index_block = inode.indirect;
        inode.indirect = NO_BLOCK;
        write_inode(n, inode);
        free_block(index_block);
    }
    true
}

/// Counts live records in `dir_inode`, `.`/`..` included -- an otherwise-empty directory always
/// has exactly `2` (used by `oxfs_rmdir`).
fn dir_entry_count(dir_inode: u32) -> usize {
    let inode = read_inode(dir_inode);
    let mut count = 0;
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
        for r in 0..RECORDS_PER_BLOCK {
            if dir_record_used(&block, r) {
                count += 1;
            }
        }
        i += 1;
    }
    count
}

/// Returns the `n`th (0-indexed) used record inside `dir_inode`, walking blocks in the same
/// order `dir_lookup`/`dir_entry_count` do -- `.`/`..` included, unlike `open_dir_listing`'s own
/// pretty-printed summary, since `SYS_GETDENTS`'s real callers (`opendir`/`readdir`) expect every
/// real record. `None` once `n` reaches the record count -- `oxfs_getdents`'s own EOF signal.
fn dir_nth_used_record(dir_inode: u32, n: usize) -> Option<(u32, [u8; NAME_MAX], u8)> {
    let inode = read_inode(dir_inode);
    let mut seen = 0usize;
    let mut i = 0;
    while let Some(blk) = inode_block_at(&inode, i) {
        let block = read_block(blk);
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

/// Puts regular file `n`'s delayed writes on the disk: its data, its index blocks, then its inode
/// record (§3.3.5). Nothing to do for anything else, which is never delayed.
fn sync_file(n: u32) {
    buf::flush_file(n);
}

/// An arbitrary but recognizable magic (`"OXFS"` as big-endian ASCII bytes) -- no applet in this
/// port's roster branches on `f_type`'s specific value, so any fixed constant would do.
const OXFS_STATFS_MAGIC: u64 = 0x4f584653;


/// Copies `src` into a fixed `[u8; MAX_MOUNT_PATH]` for `MountEntry`'s own display-only `path`/
/// `source` fields, truncating if `src` is longer -- these are never compared against (matching by
/// inode, see `oxfs_umount2`), only ever formatted back out for `/proc/mounts`, so silent
/// truncation of a pathologically long path is a cosmetic degradation, not a correctness bug.
// --- The `*at()` family ----------------------------------------------------------------------
//
// Every `*at()` call resolves a path relative to a directory fd (`dirfd`) instead of the cwd;
// `AT_FDCWD` or an absolute path makes it identical to the plain call. This ABI carries at most 4
// register arguments and passes paths length-prefixed, so a `(dirfd, path)` pair can't ride in
// registers for the two-path calls (`linkat`/`renameat2` need 2 dirfds + 2 paths + flags). Instead
// each pair is one `RawAtPath` in the caller's memory -- the same "small struct in user memory"
// convention `RawArgvEntry` already uses for `execve`'s argv. musl builds it
// (`src/internal/oxidebsd_at.h` on the `oxidebsd` branch).
//
// Single-base calls delegate to the ordinary path handler under an `AtBaseGuard` (see its doc
// comment), so `/proc`, mounts, chroot containment and every errno path behave exactly like the
// plain call. `link`/`rename` take each side's base explicitly (`link_impl`/`rename_impl`).

/// `S_ISUID | S_ISGID`.
const SETID_BITS: u16 = 0o6000;

/// `mount -u` of `/` (RAM_FLOOR.md §3.4.3), to read-only or read-write.
///
/// To read-write: the cache is dropped whole (`fsck_oxfs` may have changed the disk underneath
/// it, through the raw device) and the layout, free counts and inode table reread, as at mount;
/// then the clean flag is cleared on the disk and the orphans a read-only boot left are swept.
/// To read-only (the kernel refuses with `EBUSY` while a file on it is open for writing): every
/// delayed write goes out and the file system is marked clean.
fn remount_root(rdonly: bool) -> i64 {
    if rdonly == root_rdonly() {
        return 0;
    }
    if rdonly {
        // The kernel refused already if a file on it is open for writing (`vfs_mount::update_root`).
        buf::flush_all();
        set_clean(true);
        write_superblock();
        set_root_rdonly(true);
        log("[oxfs] root remounted read-only\n");
        return 0;
    }
    buf::invalidate_all();
    if !mount_from_disk() {
        return -EIO;
    }
    set_root_rdonly(false);
    set_clean(false);
    write_superblock();
    sweep_unnamed_inodes();
    log("[oxfs] root remounted read-write\n");
    0
}

fn log_bytes(bytes: &[u8]) {
    unsafe { oxidebsd_log(bytes.as_ptr(), bytes.len() as u64) };
}

fn log(message: &str) {
    log_bytes(message.as_bytes());
}

/// A minimal, `core::fmt`-free byte-buffer builder -- see `modules/fat32`'s own doc comment for
/// why module code avoids `core::fmt::Write`/`write!` entirely (it reintroduces `GOTPCREL`
/// relocations and pulls in a large fraction of `core::fmt`'s tables).
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
        self.push_decimal_u64(value as u64);
    }

    /// `push_decimal`'s 64-bit counterpart -- needed once `Inode::size` widened to `u64` (a real
    /// file can now legitimately report a size past `u32::MAX`), see this method's one real caller
    /// (`oxfs_getdents`'s human-readable directory listing).
    fn push_decimal_u64(&mut self, value: u64) {
        if value == 0 {
            self.push_bytes(b"0");
            return;
        }
        let mut digits = [0u8; 20];
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

// --- Real disk persistence: on-disk (de)serialization, mount, format-flush, write-through ------
//
// See this file's own "Real disk persistence" constants section (near `ROOT_INODE`) for the
// physical block layout these functions read/write.



/// Whether the root file system is mounted read-only (`OxideBSD-doc/RAM_FLOOR.md` §3.4.3): from
/// boot on the real boot path until `/etc/rc` remounts it read-write (`mount -u`), or after a
/// remount read-only. Every change to it is refused with `EROFS`.
static mut ROOT_RDONLY: bool = false;

fn root_rdonly() -> bool {
    // SAFETY: single-core, under the filesystem lock.
    unsafe { *core::ptr::addr_of!(ROOT_RDONLY) }
}

/// Whether a change at inode `n` (the file, or the directory a name goes in) is refused: it's on
/// the root file system, mounted read-only.
fn read_only_at(_n: u32) -> bool {
    root_rdonly()
}

/// Records the root's mode, and tells the kernel (raw writes to the partition are refused while
/// it's read-write).
fn set_root_rdonly(rdonly: bool) {
    // SAFETY: as `root_rdonly`.
    unsafe { *core::ptr::addr_of_mut!(ROOT_RDONLY) = rdonly };
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_root_mounted_rw(!rdonly as u64) };
}

/// Whether the filesystem is clean on the disk (§3.4.1): cleared by mount, before anything else is
/// written, and set by an orderly shutdown (`oxfs_shutdown`) once every delayed write is out.
static mut CLEAN: bool = false;

fn set_clean(clean: bool) {
    // SAFETY: single-core, syscall-serialized.
    unsafe { *core::ptr::addr_of_mut!(CLEAN) = clean };
}

/// The volume label read at mount (`newfs_oxfs -L`), written back with every superblock; none
/// for a filesystem the kernel formatted.
static mut LABEL: [u8; SB_LABEL_LEN] = [0; SB_LABEL_LEN];

fn write_superblock() {
    let table = inode_table();
    let sb = Superblock {
        data_blocks: disk_blocks(),
        inode_count: table.count,
        root_inode: ROOT_INODE,
        // SAFETY: as `set_clean`.
        clean: unsafe { *core::ptr::addr_of!(CLEAN) },
        // SAFETY: as `set_clean`.
        label: unsafe { *core::ptr::addr_of!(LABEL) },
        inode_file: table.file,
    };
    let mut block = [0u8; BLOCK_SIZE];
    sb.encode(&mut block);
    // Written straight to the disk, never through the cache: nothing reads it after mount.
    if !buf::write_direct(0, &block) {
        log("[oxfs] superblock: write failed\n");
    }
}


/// Mounts a formatted disk: checks the superblock, takes the layout from it, and counts each
/// bitmap block's free blocks. Nothing else is read: every other block comes from the disk on
/// first use, through the cache. `false` for a missing or mismatched superblock (an unformatted
/// disk, another filesystem, or a layout from another `SUPERBLOCK_VERSION`), and the caller
/// formats instead.
fn mount_from_disk() -> bool {
    let mut sb = [0u8; BLOCK_SIZE];
    if !buf::read_direct(0, &mut sb) {
        return false;
    }
    let sb = match Superblock::decode(&sb) {
        Ok(sb) => sb,
        Err(SuperblockError::NotOxfs) => return false,
        Err(SuperblockError::Version(_)) => {
            log("[oxfs] mount: on-disk layout doesn't match this build or disk -- falling back to format\n");
            return false;
        }
    };
    let data_blocks = sb.data_blocks;
    let (_, bitmap_most) = layout_for(buf::device_blocks());
    let bitmap = sb.bitmap_blocks();
    if bitmap > bitmap_most {
        log("[oxfs] mount: on-disk layout doesn't match this build or disk -- falling back to format\n");
        return false;
    }
    set_layout(data_blocks, bitmap);
    // SAFETY: inside `module_init` or a remount, before anything writes a superblock.
    unsafe { *core::ptr::addr_of_mut!(LABEL) = sb.label };
    if !sb.clean {
        log("[oxfs] mount: filesystem was not cleanly unmounted\n");
    }
    let mut used = 0u32;
    for index in 0..bitmap {
        let base = index * BITS_PER_BITMAP_BLOCK;
        let bits = (data_blocks - base).min(BITS_PER_BITMAP_BLOCK);
        let set = buf::with(BITMAP_START + index, |b| {
            (0..bits).filter(|&bit| b[bit as usize / 8] & (1 << (bit % 8)) != 0).count() as u32
        });
        *free_count(index) = bits - set;
        used += set;
    }

    let count = sb.inode_count;
    *inode_table() = InodeTable { file: sb.inode_file, count, free: 0, hint: 0 };
    let free = (0..count).filter(|&n| read_inode(n).kind == InodeKind::Free).count() as u32;
    inode_table().free = free;

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
/// point, `/dev`.
fn ensure_dir(parent: u32, name: &[u8]) -> u32 {
    if let Some(existing) = dir_lookup(parent, name) {
        return existing;
    }
    let inode = alloc_inode().expect("oxfs: failed to allocate a directory inode");
    write_inode(inode, fresh_inode(InodeKind::Dir));
    dir_insert(inode, b".", inode).expect("oxfs: failed to seed a directory's . entry");
    dir_insert(inode, b"..", parent).expect("oxfs: failed to seed a directory's .. entry");
    dir_insert(parent, name, inode)
        .expect("oxfs: failed to insert a new directory into its parent");
    inode
}




















/// Real module entry point (`#[unsafe(no_mangle)]`, discovered by `build.rs`'s relocatable-link
/// step and called by `sys/module.rs::load`). Decides between mounting an already-formatted disk
/// and formatting a fresh one (or running purely in-memory, if no data disk is attached at all --
/// see `src/ata.rs`), then performs the state every path needs regardless: resetting the boot-time
/// cwd and registering every syscall this module owns. Must never early-return before that tail --
/// skipping syscall registration on any path would silently ship a filesystem no process could
/// actually use.
#[unsafe(no_mangle)]
pub extern "C" fn module_init() -> i32 {
    // One system call at a time inside oxfs, even once a call sleeps for the disk: every call into
    // this module takes the kernel's filesystem lock (`OxideBSD-doc/RAM_FLOOR.md` §3.5.2).
    // SAFETY: FFI call to a kernel-exported function, matching its declared signature exactly.
    unsafe { oxidebsd_module_serialize() };
    if !init_pools() {
        return -1;
    }

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
