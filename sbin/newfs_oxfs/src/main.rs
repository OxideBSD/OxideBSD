//! `newfs_oxfs(8)`: makes an empty oxfs on a partition or an image file (OxideBSD-doc
//! `RAM_FLOOR.md` §4.2). The kernel never formats; this does, on the target and on the host.
//!
//! ```text
//! newfs_oxfs [-N] [-L volname] [-i bytes] [-s size] special
//! ```
//!
//! - `-N`: print the layout, write nothing.
//! - `-L volname`: a volume label, up to 32 characters: letters, digits, `-`, `_` and `.`.
//! - `-i bytes`: one inode slot per `bytes` of the filesystem, made up front. oxfs grows its inode
//!   file on demand, so without `-i` only the first inode-file block is made.
//! - `-s size`: use the first `size` 512-byte sectors of `special`, not all of it.
//!
//! The size of a disk device comes from `ioctl(DIOCGMEDIASIZE)`, of an image file from its
//! length. The result is what the kernel's format made: the root (inode 0) and `/lost+found`
//! (mode 0700), marked clean.

use oxfs_format::{BLOCK_SIZE, BlockDevice, FormatOptions, INODES_PER_BLOCK, SB_LABEL_LEN, Writer, layout_for};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

/// `ioctl(2)`'s answer for a descriptor that isn't a disk (musl's `ENOTTY`).
const ENOTTY: i32 = 25;

fn usage() -> ExitCode {
    eprintln!("usage: newfs_oxfs [-N] [-L volname] [-i bytes] [-s size] special");
    ExitCode::from(1)
}

/// The device, a block at a time.
struct Dev(File);

impl BlockDevice for Dev {
    type Error = std::io::Error;
    fn read_block(&mut self, n: u64, buf: &mut [u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0.read_exact_at(buf, n * BLOCK_SIZE as u64)
    }
    fn write_block(&mut self, n: u64, buf: &[u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0.write_all_at(buf, n * BLOCK_SIZE as u64)
    }
}

/// `special`'s size in bytes: a regular file's length, else the disk's size.
fn media_size(f: &File) -> std::io::Result<u64> {
    if f.metadata()?.is_file() {
        return Ok(f.metadata()?.len());
    }
    disk_size(f)
}

#[cfg(target_os = "oxidebsd")]
fn disk_size(f: &File) -> std::io::Result<u64> {
    use std::os::fd::AsRawFd;
    /// `<sys/disk.h>`'s `DIOCGMEDIASIZE`, as the kernel defines it (`sys/drivers/disk.rs`).
    const DIOCGMEDIASIZE: libc::c_int = 0x8008_6481_u32 as libc::c_int;
    let mut size: i64 = 0;
    // SAFETY: the request writes one i64 through the pointer.
    if unsafe { libc::ioctl(f.as_raw_fd(), DIOCGMEDIASIZE as _, &mut size) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(size as u64)
}

/// A host block device: its end.
#[cfg(not(target_os = "oxidebsd"))]
fn disk_size(mut f: &File) -> std::io::Result<u64> {
    use std::io::{Seek, SeekFrom};
    f.seek(SeekFrom::End(0))
}

fn describe(e: oxfs_format::Error<std::io::Error>) -> String {
    use oxfs_format::Error;
    match e {
        Error::Device(e) => e.to_string(),
        Error::TooSmall => "too small for a file system".into(),
        Error::NoSpace => "out of blocks".into(),
        Error::NoInodes => "too many inodes for its size (-i)".into(),
        Error::LabelTooLong => "volume label too long".into(),
        Error::BadName | Error::Superblock(_) => format!("{e:?}"),
    }
}

fn number(s: &str) -> Option<u64> {
    s.parse().ok().filter(|&n| n > 0)
}

fn main() -> ExitCode {
    let (mut dry_run, mut label, mut bytes_per_inode, mut sectors) = (false, String::new(), None, None);
    let mut special = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-N" => dry_run = true,
            "-L" | "-i" | "-s" => {
                let Some(value) = args.next() else { return usage() };
                match arg.as_str() {
                    "-L" => label = value,
                    "-i" => match number(&value) {
                        Some(n) => bytes_per_inode = Some(n),
                        None => return usage(),
                    },
                    _ => match number(&value) {
                        Some(n) => sectors = Some(n),
                        None => return usage(),
                    },
                }
            }
            _ if arg.starts_with('-') => return usage(),
            _ if special.is_none() => special = Some(arg),
            _ => return usage(),
        }
    }
    let Some(special) = special else { return usage() };
    if label.len() > SB_LABEL_LEN || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        eprintln!("newfs_oxfs: bad volume label: up to {SB_LABEL_LEN} letters, digits, '-', '_' or '.'");
        return ExitCode::from(1);
    }
    match newfs(&special, dry_run, label.as_bytes(), bytes_per_inode, sectors) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("newfs_oxfs: {special}: {e}");
            ExitCode::from(1)
        }
    }
}

fn newfs(special: &str, dry_run: bool, label: &[u8], bytes_per_inode: Option<u64>, sectors: Option<u64>) -> Result<(), String> {
    let file = OpenOptions::new().read(true).write(!dry_run).open(special).map_err(|e| e.to_string())?;
    let mut bytes = media_size(&file).map_err(|e| match e.raw_os_error() {
        Some(ENOTTY) => "not a disk device or a file".to_string(),
        _ => format!("can't get its size: {e}"),
    })?;
    if let Some(sectors) = sectors {
        if sectors * 512 > bytes {
            return Err(format!("-s {sectors} is larger than the device ({} sectors)", bytes / 512));
        }
        bytes = sectors * 512;
    }
    let device_blocks = bytes / BLOCK_SIZE as u64;
    let (data_blocks, bitmap_blocks) = layout_for(device_blocks);
    if data_blocks < 4 {
        return Err(describe(oxfs_format::Error::TooSmall));
    }
    let inodes = bytes_per_inode.map_or(0, |b| bytes / b).min(u32::MAX as u64) as u32;
    let made = inodes.max(1).div_ceil(INODES_PER_BLOCK as u32) * INODES_PER_BLOCK as u32;
    println!(
        "{special}: {:.1}MB ({} sectors) block size {BLOCK_SIZE}, {data_blocks} data blocks, {bitmap_blocks} bitmap blocks, {made} inodes",
        bytes as f64 / (1 << 20) as f64,
        bytes / 512,
    );
    if dry_run {
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let opts = FormatOptions { label, inodes, now };
    let w = Writer::format(Dev(file), device_blocks, &opts).map_err(describe)?;
    let dev = w.finish().map_err(describe)?;
    dev.0.sync_all().map_err(|e| e.to_string())
}
