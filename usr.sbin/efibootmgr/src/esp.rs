//! Between a file on an EFI system partition, as this system names it (`/boot/efi/EFI/OxideBSD/
//! BOOTX64.EFI`), and the firmware's device path for it (`HD(1,GPT,<guid>,0x800,0x82000)/
//! \EFI\OxideBSD\BOOTX64.EFI`): the partition is found by its GPT entry (`lib/libpart`), the
//! mount by the device it's mounted from -- the partition's node by its device number, or its
//! label's (`/dev/gpt/<label>`, a node of its own, another number) by the GPT name, its
//! `/dev/gptid/<guid>` by the GUID.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::process::Command;

use efivar::devpath;

const DIOCGSECTORSIZE: u64 = 0x8004_6480;
const DIOCGMEDIASIZE: u64 = 0x8008_6481;

/// A GPT partition of one of the machine's disks.
pub struct Part {
    /// Its device, `/dev/<disk>p<index>`.
    pub dev: String,
    pub index: u32,
    /// Its GPT name: `/dev/gpt/<label>` names it too.
    pub label: String,
    /// Where it starts and its length, in the disk's sectors.
    pub first: u64,
    pub sectors: u64,
    pub guid: [u8; 16],
}

struct Disk {
    file: File,
    sector_size: u32,
    sectors: u64,
}

impl part::Disk for Disk {
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        self.file.read_exact_at(buf, lba * self.sector_size as u64).is_ok()
    }
}

fn sysctl(name: &str) -> Option<String> {
    let out = Command::new("/sbin/sysctl").args(["-n", name]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Every GPT partition of every disk (`kern.disks`, CD drives left out).
pub fn partitions() -> Vec<Part> {
    let mut out = Vec::new();
    for name in sysctl("kern.disks").unwrap_or_default().split_whitespace() {
        if sysctl(&format!("kern.disk.{name}.kind")).as_deref() != Some("disk") {
            continue;
        }
        let Ok(file) = File::open(format!("/dev/{name}")) else { continue };
        let (mut ss, mut bytes) = (0u32, 0i64);
        // SAFETY: each request writes one value of the type passed.
        let ok = unsafe {
            libc::ioctl(file.as_raw_fd(), DIOCGSECTORSIZE as _, &mut ss) == 0
                && libc::ioctl(file.as_raw_fd(), DIOCGMEDIASIZE as _, &mut bytes) == 0
        };
        if !ok || ss < 512 || !ss.is_power_of_two() {
            continue;
        }
        let mut disk = Disk { file, sector_size: ss, sectors: bytes as u64 / ss as u64 };
        let Ok(Some(table)) = part::read(&mut disk) else { continue };
        if table.scheme != part::Scheme::Gpt {
            continue;
        }
        for e in &table.entries {
            out.push(Part {
                dev: format!("/dev/{name}p{}", e.index),
                index: e.index,
                label: e.label.clone(),
                first: e.first,
                sectors: e.sectors,
                guid: e.guid,
            });
        }
    }
    out
}

fn rdev(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.rdev())
}

/// Whether device `spec` (a mount's) is partition `p`: its own node, its label's or its GUID's.
fn names(spec: &str, p: &Part) -> bool {
    if let Some(id) = spec.strip_prefix("/dev/gptid/") {
        return part::parse_guid(id) == Some(p.guid);
    }
    match spec.strip_prefix("/dev/gpt/") {
        Some(label) => !p.label.is_empty() && label == p.label,
        None => rdev(spec).is_some_and(|d| rdev(&p.dev) == Some(d)),
    }
}

/// The firmware's device path for `path`, a file on a mounted EFI system partition (msdosfs), and
/// that partition.
pub fn device_path(path: &str) -> Result<(Vec<u8>, Part), String> {
    let full = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
    let full = full.to_string_lossy().into_owned();
    let mount = fstab::mounted()
        .into_iter()
        .filter(|m| m.vfstype == "msdosfs")
        .filter(|m| full == m.file || full.starts_with(&format!("{}/", m.file.trim_end_matches('/'))))
        .max_by_key(|m| m.file.len())
        .ok_or(format!("{path}: not on a mounted EFI system partition"))?;
    let part = partitions()
        .into_iter()
        .find(|p| names(&mount.spec, p))
        .ok_or(format!("{path}: {} isn't a GPT partition", mount.spec))?;
    let rel = full[mount.file.trim_end_matches('/').len()..].replace('/', "\\");
    let mut dp = devpath::hard_drive_gpt(part.index, part.first, part.sectors, part.guid);
    dp.extend(devpath::file_path(&rel));
    dp.extend(devpath::end());
    Ok((dp, part))
}

/// Where a device path's partition is on this machine: its device, and where its file is under
/// the partition's mount point, if mounted.
pub fn unix_path(dp: &[u8]) -> Option<(String, Option<String>)> {
    let (_, _, _, guid) = devpath::hard_drive(dp)?;
    let part = partitions().into_iter().find(|p| p.guid == guid.0)?;
    let file = devpath::file(dp).map(|f| f.replace('\\', "/"));
    let mount = fstab::mounted().into_iter().find(|m| m.vfstype == "msdosfs" && names(&m.spec, &part));
    let under = match (mount, file) {
        (Some(m), Some(f)) => Some(format!("{}{}", m.file.trim_end_matches('/'), f)),
        (Some(m), None) => Some(m.file),
        _ => None,
    };
    Some((part.dev, under))
}
