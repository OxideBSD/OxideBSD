//! `growfs(8)`: grows an oxfs to fill its partition, after the partition was made larger
//! (OxideBSD-doc `INSTALLER.md` §8.2; FreeBSD's name, for UFS there). The file system must be
//! unmounted and clean.
//!
//! ```text
//! growfs [-Ny] [-s size] special
//! ```
//!
//! - `-N`: say what would be done, write nothing.
//! - `-y`: don't ask first (the installer's way); without it, the question is asked on the
//!   terminal, and anything but `yes` stops.
//! - `-s size`: grow to the first `size` 512-byte sectors of `special`, not all of it.
//!
//! Growing past the bitmap's last block moves every used data block (`oxfs_format::grow`): not
//! safe against a crash, so it is asked about first.

use oxfs_format::{BLOCK_SIZE, BlockDevice, GrowError, grow, grow_plan};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Write};
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: growfs [-Ny] [-s size] special");
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

fn describe(e: GrowError<std::io::Error>) -> String {
    match e {
        GrowError::Device(e) => e.to_string(),
        GrowError::Superblock(_) => "not an oxfs of this version".into(),
        GrowError::NotClean => "not marked clean: check it with fsck_oxfs first".into(),
        GrowError::NoRoom => "the device holds no more than the file system already has".into(),
    }
}

/// `n` blocks as MiB.
fn mib(n: u32) -> u64 {
    n as u64 * BLOCK_SIZE as u64 >> 20
}

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut dry, mut yes, mut sectors) = (false, false, None::<u64>);
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i].len() > 1 {
        match args[i].as_str() {
            "-N" => dry = true,
            "-y" => yes = true,
            "-Ny" | "-yN" => (dry, yes) = (true, true),
            "-s" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()).filter(|&n: &u64| n > 0) {
                    Some(n) => sectors = Some(n),
                    None => return usage(),
                }
            }
            _ => return usage(),
        }
        i += 1;
    }
    let [special] = &args[i..] else { return usage() };
    let file = match OpenOptions::new().read(true).write(!dry).open(special) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("growfs: {special}: {e}");
            return ExitCode::from(1);
        }
    };
    let bytes = match media_size(&file) {
        Ok(n) => sectors.map_or(n, |s| (s * 512).min(n)),
        Err(e) => {
            eprintln!("growfs: {special}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut dev = Dev(file);
    let device_blocks = bytes / BLOCK_SIZE as u64;
    let plan = match grow_plan(&mut dev, device_blocks) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("growfs: {special}: {}", describe(e));
            return ExitCode::from(1);
        }
    };
    println!(
        "{special}: {} MiB to {} MiB{}",
        mib(plan.old_blocks),
        mib(plan.new_blocks),
        if plan.moved_by > 0 { ", every used block moved: a crash in the move damages the file system" } else { "" }
    );
    if dry {
        return ExitCode::SUCCESS;
    }
    if !yes {
        print!("Grow it? [yes/no] ");
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        let _ = std::io::stdin().lock().read_line(&mut answer);
        if answer.trim() != "yes" {
            println!("growfs: not grown");
            return ExitCode::from(1);
        }
    }
    // The kernel refuses writes to a device a file system has mounted read-write: block 0,
    // written back as it is, finds that out before anything moves.
    let mut sb = [0u8; BLOCK_SIZE];
    if let Err(e) = dev.read_block(0, &mut sb).and_then(|_| dev.write_block(0, &sb)) {
        eprintln!("growfs: {special}: {e} (is it mounted?)");
        return ExitCode::from(1);
    }
    match grow(&mut dev, device_blocks).and_then(|g| dev.0.sync_all().map(|_| g).map_err(GrowError::Device)) {
        Ok(g) => {
            println!("growfs: {special}: {} MiB", mib(g.new_blocks));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("growfs: {special}: {}", describe(e));
            ExitCode::from(1)
        }
    }
}
