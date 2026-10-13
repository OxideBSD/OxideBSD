//! `/boot/fsconf` (`fsconf(5)`): the binary form of `/etc/fstab` that `fsconf_mkdb(8)` writes and
//! the boot loader loads beside the kernel, so the kernel knows which device holds the root file
//! system before it has mounted anything (OxideBSD-doc `RAM_FLOOR.md` §3.4.5).

use alloc::string::String;
use alloc::vec::Vec;

const MAGIC: &[u8; 8] = b"OXFSCONF";
const VERSION: u32 = 1;

/// One `/etc/fstab` line.
pub struct Entry {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: String,
}

/// The entries of `bytes`, or `None` if it isn't a version 1 fsconf.
pub fn parse(bytes: &[u8]) -> Option<Vec<Entry>> {
    let mut at = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let s = bytes.get(at..at.checked_add(n)?)?;
        at += n;
        Some(s)
    };
    if take(8)? != MAGIC || u32::from_le_bytes(take(4)?.try_into().ok()?) != VERSION {
        return None;
    }
    let count = u32::from_le_bytes(take(4)?.try_into().ok()?);
    let mut entries = Vec::new();
    for _ in 0..count {
        let mut field = || -> Option<String> {
            let len = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
            Some(String::from(core::str::from_utf8(take(len)?).ok()?))
        };
        let (device, mount_point, fs_type, options) = (field()?, field()?, field()?, field()?);
        take(8)?; // dump frequency, fsck pass
        entries.push(Entry { device, mount_point, fs_type, options });
    }
    Some(entries)
}

/// The root file system's device as `/boot/fsconf` names it (`/dev/gpt/rootfs`), if the boot
/// loader loaded a valid one with an entry for `/`.
pub fn root_device() -> Option<String> {
    let entries = parse(crate::boot::boot_module("/boot/fsconf")?)?;
    entries.into_iter().find(|e| e.mount_point == "/").map(|e| e.device)
}
