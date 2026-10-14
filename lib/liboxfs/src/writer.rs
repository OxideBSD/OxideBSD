//! Building an oxfs from outside the kernel: `newfs_oxfs(8)` formats with it, and the host image
//! tools fill a filesystem through it (OxideBSD-doc `RAM_FLOOR.md` §4.1-4.2). It allocates blocks
//! and inodes, grows directories and maps file blocks by the same rules as the oxfs module, so the
//! module mounts what it writes and `fsck_oxfs` finds nothing to repair.
//!
//! Every block goes through a `BlockDevice`; nothing is kept in memory but the superblock and two
//! allocation cursors, so a caller wanting speed gives it a caching device.

use crate::*;

/// Where a filesystem lives: device blocks of `BLOCK_SIZE` bytes, numbered from the start of the
/// partition (block 0 is the superblock).
pub trait BlockDevice {
    type Error;
    fn read_block(&mut self, n: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Self::Error>;
    fn write_block(&mut self, n: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum Error<E> {
    Device(E),
    /// The device is too small to hold a filesystem.
    TooSmall,
    /// No free data block left.
    NoSpace,
    /// The inode table can't grow (no blocks, or the inode numbers are used up).
    NoInodes,
    /// A name longer than `NAME_MAX`, or empty.
    BadName,
    /// The label is longer than `SB_LABEL_LEN`.
    LabelTooLong,
    /// A superblock that doesn't decode.
    Superblock(SuperblockError),
}

impl<E> From<E> for Error<E> {
    fn from(e: E) -> Self {
        Error::Device(e)
    }
}

/// What `Writer::format` makes.
pub struct FormatOptions<'a> {
    /// The volume label (`newfs_oxfs -L`); empty for none.
    pub label: &'a [u8],
    /// Inode slots to create up front (`newfs_oxfs -i`); the table grows on demand past them,
    /// as it always does. Rounded up to a whole inode-file block.
    pub inodes: u32,
    /// The time stamped on the root and `lost+found` (Unix seconds).
    pub now: i64,
}

/// An oxfs being built on `D`.
pub struct Writer<D: BlockDevice> {
    pub(crate) dev: D,
    pub(crate) sb: Superblock,
    /// Where `alloc_block` starts looking.
    pub(crate) next_block: u32,
    /// Where `alloc_inode` starts looking.
    pub(crate) next_inode: u32,
}

impl<D: BlockDevice> BlockDevice for &mut D {
    type Error = D::Error;
    fn read_block(&mut self, n: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Self::Error> {
        (**self).read_block(n, buf)
    }
    fn write_block(&mut self, n: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), Self::Error> {
        (**self).write_block(n, buf)
    }
}

impl<D: BlockDevice> Writer<D> {
    /// Formats `device_blocks` blocks of `dev`: the superblock, an empty bitmap, the inode file,
    /// the root directory (inode `ROOT_INODE`) and `/lost+found` (mode 0700), as the kernel's own
    /// format does. The superblock stays unwritten until `finish`, so an interrupted format leaves
    /// no filesystem rather than a half-made one.
    pub fn format(mut dev: D, device_blocks: u64, opts: &FormatOptions) -> Result<Self, Error<D::Error>> {
        if opts.label.len() > SB_LABEL_LEN {
            return Err(Error::LabelTooLong);
        }
        let (data_blocks, bitmap) = layout_for(device_blocks);
        // Room for the root, lost+found, and the first inode-file block.
        if data_blocks < 4 {
            return Err(Error::TooSmall);
        }
        let blank = [0u8; BLOCK_SIZE];
        dev.write_block(0, &blank)?;
        for index in 0..bitmap {
            dev.write_block((BITMAP_START + index) as u64, &blank)?;
        }
        let mut label = [0u8; SB_LABEL_LEN];
        label[..opts.label.len()].copy_from_slice(opts.label);
        let sb = Superblock {
            data_blocks,
            inode_count: 0,
            root_inode: ROOT_INODE,
            clean: false,
            label,
            inode_file: Inode::FREE,
        };
        let mut w = Writer { dev, sb, next_block: 0, next_inode: 0 };
        while w.sb.inode_count < opts.inodes.max(1) {
            w.grow_inode_table()?;
        }

        let root = w.alloc_inode()?;
        debug_assert_eq!(root, ROOT_INODE);
        w.write_inode(root, &Inode::new(InodeKind::Dir, opts.now))?;
        w.dir_insert(root, b".", root, opts.now)?;
        w.dir_insert(root, b"..", root, opts.now)?;
        let lost = w.mkdir(root, b"lost+found", opts.now)?;
        let mut inode = w.read_inode(lost)?;
        inode.mode = 0o700;
        w.write_inode(lost, &inode)?;
        Ok(w)
    }

    /// Writes the superblock, marked clean, and hands the device back.
    pub fn finish(mut self) -> Result<D, Error<D::Error>> {
        self.sb.clean = true;
        let mut block = [0u8; BLOCK_SIZE];
        self.sb.encode(&mut block);
        self.dev.write_block(0, &block)?;
        Ok(self.dev)
    }

    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    fn data_offset(&self) -> u64 {
        self.sb.data_block_offset() as u64
    }

    /// Data block `n`.
    pub fn read_data(&mut self, n: u32) -> Result<[u8; BLOCK_SIZE], Error<D::Error>> {
        let mut b = [0u8; BLOCK_SIZE];
        self.dev.read_block(self.data_offset() + n as u64, &mut b)?;
        Ok(b)
    }

    pub fn write_data(&mut self, n: u32, b: &[u8; BLOCK_SIZE]) -> Result<(), Error<D::Error>> {
        let at = self.data_offset() + n as u64;
        Ok(self.dev.write_block(at, b)?)
    }

    /// A free data block, marked used and filled with `fill` bytes (`0xFF` for an index block,
    /// whose slots must read `NO_BLOCK`), or left as it is (`None`) for one the caller writes
    /// whole.
    fn alloc_block_filled(&mut self, fill: Option<u8>) -> Result<u32, Error<D::Error>> {
        let total = self.sb.data_blocks;
        let mut index = self.next_block / BITS_PER_BITMAP_BLOCK;
        while index < self.sb.bitmap_blocks() {
            let mut bitmap = [0u8; BLOCK_SIZE];
            self.dev.read_block((BITMAP_START + index) as u64, &mut bitmap)?;
            let base = index * BITS_PER_BITMAP_BLOCK;
            let from = self.next_block.max(base) - base;
            let end = (total - base).min(BITS_PER_BITMAP_BLOCK);
            if let Some(bit) = (from..end).find(|&bit| bitmap[bit as usize / 8] & (1 << (bit % 8)) == 0) {
                bitmap[bit as usize / 8] |= 1 << (bit % 8);
                self.dev.write_block((BITMAP_START + index) as u64, &bitmap)?;
                let n = base + bit;
                if let Some(fill) = fill {
                    self.write_data(n, &[fill; BLOCK_SIZE])?;
                }
                self.next_block = n + 1;
                return Ok(n);
            }
            index += 1;
        }
        Err(Error::NoSpace)
    }

    pub fn alloc_block(&mut self) -> Result<u32, Error<D::Error>> {
        self.alloc_block_filled(Some(0))
    }

    /// The data block holding `inode`'s block `index`, allocating it (and any index block on the
    /// way) when it has none: direct, single-indirect, then double-indirect, as the module's
    /// `ensure_block`.
    pub fn ensure_block(&mut self, inode: &mut Inode, index: usize) -> Result<u32, Error<D::Error>> {
        self.ensure_block_filled(inode, index, Some(0))
    }

    /// `ensure_block`, with a new data block filled as `alloc_block_filled` says.
    fn ensure_block_filled(&mut self, inode: &mut Inode, index: usize, fill: Option<u8>) -> Result<u32, Error<D::Error>> {
        if index < DIRECT_BLOCKS {
            if inode.direct[index] == NO_BLOCK {
                inode.direct[index] = self.alloc_block_filled(fill)?;
            }
            return Ok(inode.direct[index]);
        }
        let index = index - DIRECT_BLOCKS;
        if index < PTRS_PER_INDIRECT {
            if inode.indirect == NO_BLOCK {
                inode.indirect = self.alloc_block_filled(Some(0xFF))?;
            }
            return self.ensure_slot(inode.indirect, index, fill);
        }
        let index = index - PTRS_PER_INDIRECT;
        if index >= PTRS_PER_DOUBLE_INDIRECT {
            return Err(Error::NoSpace);
        }
        if inode.double_indirect == NO_BLOCK {
            inode.double_indirect = self.alloc_block_filled(Some(0xFF))?;
        }
        let (outer, inner) = (index / PTRS_PER_INDIRECT, index % PTRS_PER_INDIRECT);
        let mut ob = self.read_data(inode.double_indirect)?;
        let mut inner_block = u32::from_le_bytes(ob[outer * 4..outer * 4 + 4].try_into().unwrap());
        if inner_block == NO_BLOCK {
            inner_block = self.alloc_block_filled(Some(0xFF))?;
            ob[outer * 4..outer * 4 + 4].copy_from_slice(&inner_block.to_le_bytes());
            self.write_data(inode.double_indirect, &ob)?;
        }
        self.ensure_slot(inner_block, inner, fill)
    }

    /// Index block `ib`'s pointer at `slot`, allocating a data block for it if it has none.
    fn ensure_slot(&mut self, ib: u32, slot: usize, fill: Option<u8>) -> Result<u32, Error<D::Error>> {
        let mut b = self.read_data(ib)?;
        let existing = u32::from_le_bytes(b[slot * 4..slot * 4 + 4].try_into().unwrap());
        if existing != NO_BLOCK {
            return Ok(existing);
        }
        let n = self.alloc_block_filled(fill)?;
        b[slot * 4..slot * 4 + 4].copy_from_slice(&n.to_le_bytes());
        self.write_data(ib, &b)?;
        Ok(n)
    }

    /// `inode`'s block `index`, if it has one.
    pub fn block_at(&mut self, inode: &Inode, index: usize) -> Result<Option<u32>, Error<D::Error>> {
        let ptr = |w: &mut Self, ib: u32, slot: usize| -> Result<u32, Error<D::Error>> {
            let b = w.read_data(ib)?;
            Ok(u32::from_le_bytes(b[slot * 4..slot * 4 + 4].try_into().unwrap()))
        };
        let n = if index < DIRECT_BLOCKS {
            inode.direct[index]
        } else if index - DIRECT_BLOCKS < PTRS_PER_INDIRECT {
            match inode.indirect {
                NO_BLOCK => NO_BLOCK,
                ib => ptr(self, ib, index - DIRECT_BLOCKS)?,
            }
        } else {
            let index = index - DIRECT_BLOCKS - PTRS_PER_INDIRECT;
            if index >= PTRS_PER_DOUBLE_INDIRECT || inode.double_indirect == NO_BLOCK {
                NO_BLOCK
            } else {
                match ptr(self, inode.double_indirect, index / PTRS_PER_INDIRECT)? {
                    NO_BLOCK => NO_BLOCK,
                    ib => ptr(self, ib, index % PTRS_PER_INDIRECT)?,
                }
            }
        };
        Ok((n != NO_BLOCK).then_some(n))
    }

    /// Adds a block of free inode slots to the inode file.
    fn grow_inode_table(&mut self) -> Result<(), Error<D::Error>> {
        if self.sb.inode_count as u64 + INODES_PER_BLOCK as u64 > MAX_DISK_INODES as u64 {
            return Err(Error::NoInodes);
        }
        let mut file = self.sb.inode_file;
        let index = self.sb.inode_count as usize / INODES_PER_BLOCK;
        self.ensure_block(&mut file, index).map_err(|e| match e {
            Error::NoSpace => Error::NoInodes,
            e => e,
        })?;
        self.sb.inode_count += INODES_PER_BLOCK as u32;
        if file.kind == InodeKind::Free {
            file.kind = InodeKind::File;
        }
        file.size = self.sb.inode_count as u64 * INODE_STRIDE as u64;
        self.sb.inode_file = file;
        Ok(())
    }

    /// Where inode `n`'s record is: its inode-file block and byte offset.
    fn inode_location(&mut self, n: u32) -> Result<(u32, usize), Error<D::Error>> {
        let file = self.sb.inode_file;
        let block = self
            .block_at(&file, n as usize / INODES_PER_BLOCK)?
            .ok_or(Error::NoInodes)?;
        Ok((block, n as usize % INODES_PER_BLOCK * INODE_STRIDE))
    }

    pub fn read_inode(&mut self, n: u32) -> Result<Inode, Error<D::Error>> {
        let (block, off) = self.inode_location(n)?;
        let b = self.read_data(block)?;
        Ok(unpack_inode(&b[off..off + INODE_STRIDE]))
    }

    pub fn write_inode(&mut self, n: u32, inode: &Inode) -> Result<(), Error<D::Error>> {
        let (block, off) = self.inode_location(n)?;
        let mut b = self.read_data(block)?;
        pack_inode(inode, &mut b[off..off + INODE_STRIDE]);
        self.write_data(block, &b)
    }

    /// A free inode number (its slot still `Free` until the caller writes it), growing the table
    /// when every slot is taken.
    pub fn alloc_inode(&mut self) -> Result<u32, Error<D::Error>> {
        loop {
            for n in self.next_inode..self.sb.inode_count {
                if self.read_inode(n)?.kind == InodeKind::Free {
                    self.next_inode = n + 1;
                    return Ok(n);
                }
            }
            self.next_inode = self.sb.inode_count;
            self.grow_inode_table()?;
        }
    }

    /// Adds the record `name -> target` to directory `dir`, in its first free slot or a new block,
    /// and stamps the directory's times with `now`.
    pub fn dir_insert(&mut self, dir: u32, name: &[u8], target: u32, now: i64) -> Result<(), Error<D::Error>> {
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(Error::BadName);
        }
        let mut inode = self.read_inode(dir)?;
        let mut i = 0;
        loop {
            match self.block_at(&inode, i)? {
                Some(blk) => {
                    let mut b = self.read_data(blk)?;
                    if let Some(r) = (0..RECORDS_PER_BLOCK).find(|&r| !dir_record_used(&b, r)) {
                        write_dir_record(&mut b, r, name, target);
                        self.write_data(blk, &b)?;
                        break;
                    }
                    i += 1;
                }
                None => {
                    let blk = self.ensure_block(&mut inode, i)?;
                    let mut b = [0u8; BLOCK_SIZE];
                    write_dir_record(&mut b, 0, name, target);
                    self.write_data(blk, &b)?;
                    break;
                }
            }
        }
        inode.mtime = now;
        inode.ctime = now;
        self.write_inode(dir, &inode)
    }

    /// Makes directory `name` in `parent` (mode `FIXED_PERM`, owned by root), with its `.` and
    /// `..` records.
    pub fn mkdir(&mut self, parent: u32, name: &[u8], now: i64) -> Result<u32, Error<D::Error>> {
        let n = self.alloc_inode()?;
        self.write_inode(n, &Inode::new(InodeKind::Dir, now))?;
        self.dir_insert(n, b".", n, now)?;
        self.dir_insert(n, b"..", parent, now)?;
        self.dir_insert(parent, name, n, now)?;
        Ok(n)
    }

    /// Makes `name` in `parent` from `inode` (its kind, mode, owner and times; one link), with
    /// `.` and `..` records for a directory. Its parent's times become `inode`'s mtime.
    pub fn create(&mut self, parent: u32, name: &[u8], inode: &Inode) -> Result<u32, Error<D::Error>> {
        let n = self.alloc_inode()?;
        let mut fresh = *inode;
        fresh.nlink = 1;
        self.write_inode(n, &fresh)?;
        if inode.kind == InodeKind::Dir {
            self.dir_insert(n, b".", n, inode.mtime)?;
            self.dir_insert(n, b"..", parent, inode.mtime)?;
            // dir_insert stamped it; keep the times asked for.
            let mut back = self.read_inode(n)?;
            back.mtime = inode.mtime;
            back.ctime = inode.ctime;
            self.write_inode(n, &back)?;
        }
        self.dir_insert(parent, name, n, inode.mtime)?;
        Ok(n)
    }

    /// Writes block `index` of a file whose record the caller holds (`inode`, written back by
    /// the caller once the whole file is in): a block it writes whole, so a new one isn't zeroed
    /// first. Its size is the caller's to set.
    pub fn put_block(&mut self, inode: &mut Inode, index: usize, data: &[u8; BLOCK_SIZE]) -> Result<(), Error<D::Error>> {
        let n = self.ensure_block_filled(inode, index, None)?;
        self.write_data(n, data)
    }

    /// Gives inode `n` another name, `name` in `parent`.
    pub fn link(&mut self, parent: u32, name: &[u8], n: u32, now: i64) -> Result<(), Error<D::Error>> {
        self.dir_insert(parent, name, n, now)?;
        let mut inode = self.read_inode(n)?;
        inode.nlink += 1;
        self.write_inode(n, &inode)
    }

    /// Sets directory `dir`'s times (after its entries went in, which stamped them).
    pub fn set_times(&mut self, n: u32, mtime: i64, ctime: i64, atime: i64) -> Result<(), Error<D::Error>> {
        let mut inode = self.read_inode(n)?;
        (inode.mtime, inode.ctime, inode.atime) = (mtime, ctime, atime);
        self.write_inode(n, &inode)
    }
}
