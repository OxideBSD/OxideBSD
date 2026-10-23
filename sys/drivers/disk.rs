//! The disk registry (`OxideBSD-doc/INSTALLER.md` §5): `init` registers every disk the kernel
//! drives at boot -- each virtio-blk device (`virt0`, `virt1`, ... in PCI order), then each IDE
//! disk or CD drive (`ide0`, ... in the order primary master, primary slave, secondary master,
//! secondary slave; ATA by bus-master DMA when the controller can, else PIO; ATAPI by PIO), then
//! each AHCI disk or CD drive (`sata<C>.<P>`, `sata<C>.<P>.<M>`: by controller, port and port
//! multiplier port, `ahci`), then each virtio-scsi disk or CD drive (`scsi0`, ... in controller,
//! target order) -- with the partitions of each (`part`: GPT, else MBR). Disks are named by bus,
//! one counter per bus except AHCI's, optical drives counted with disks (their kind is in
//! `kern.disk.<name>.kind`); partitions are `<disk>p<N>` (GPT) or
//! `<disk>s<N>` (MBR), and labelled GPT partitions are also `gpt/<label>` (FreeBSD's `glabel`;
//! the first of a label wins). Each becomes a block device (`kern::vfs_bdev`) and a raw device in
//! `/dev`, readable and writable by root, except that a device overlapping one a file system has
//! mounted read-write can't be written (RAM_FLOOR.md §3.4.3: the writes would go around its
//! cache).
//!
//! The root is oxfs's partition `/boot/fsconf` names, on any disk, else the first oxfs partition
//! in registration order (RAM_FLOOR.md §3.4.5). The kernel never partitions or formats a disk
//! (RAM_FLOOR.md §4.2.1): with no oxfs partition anywhere, like no disk at all, oxfs gets the
//! memory disk (`md0`), empty until the mfsroot fills it. oxfs never knows which.
//!
//! The block layer addresses every disk in 512-byte sectors; a disk with larger ones (a CD's
//! 2048, INSTALLER.md §5.4) is translated here, partial sectors read whole (and written back
//! whole).
//!
//! A drive pulled out of a running system (AHCI hot plug, INSTALLER.md §5.3) is retired: its
//! file systems unmounted by force, its devices gone, its entry kept (gone) for a drive plugged
//! into the same place to take back with the same name. The root's going panics, unless
//! `kern.disk.root_lost` is `eio`.
//!
//! File systems reach their devices through `kern::vfs_bdev` and the buffer cache
//! (`kern::vfs_bio`); this file finds the disks and serves the raw `/dev` nodes.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use x86_64::VirtAddr;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};

use super::ata::{Channel, Drive};
use super::part::Partition;
use crate::kern::subr_devctl as devctl;
use crate::serial_println;

/// Which driver serves a disk, and which of its devices it is.
#[derive(Clone, Copy)]
enum Backend {
    Ata(Channel, Drive),
    Atapi(Channel, Drive),
    /// A SATA disk or ATAPI drive (`Unit::atapi`).
    Ahci(super::ahci::Unit),
    Virtio(usize),
    Scsi(super::virtio_scsi::Unit),
    Memory,
}

/// Runs `f` with the SCSI transport a backend speaks (`drivers::scsi`), if it speaks SCSI.
fn with_scsi<R>(backend: Backend, f: impl FnOnce(&dyn super::scsi::Transport) -> R) -> Option<R> {
    match backend {
        Backend::Atapi(channel, drive) => Some(f(&super::ata::Atapi(channel, drive))),
        Backend::Scsi(unit) => Some(f(&unit)),
        Backend::Ahci(unit) if unit.atapi() => Some(f(&unit)),
        _ => None,
    }
}

/// What a disk is (`kern.disk.<name>.kind`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Disk,
    Cd,
    Memory,
}

impl Backend {
    /// Its bus, for device events (`DEVD.md` §3.3).
    fn bus(self) -> &'static str {
        match self {
            Backend::Ata(..) | Backend::Atapi(..) => "ata",
            Backend::Ahci(_) => "ahci",
            Backend::Virtio(_) => "virtio_blk",
            Backend::Scsi(_) => "virtio_scsi",
            Backend::Memory => "md",
        }
    }
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Disk => "disk",
            Kind::Cd => "cd",
            Kind::Memory => "memory",
        }
    }
}

/// One registered disk.
struct Disk {
    name: String,
    backend: Backend,
    kind: Kind,
    /// Its size in 512-byte sectors (the block layer's unit).
    sectors: u64,
    /// Its own sector size in bytes, a multiple of 512.
    sector_size: u32,
    model: String,
    /// Its serial number, where the driver reads one (AHCI's, to tell a drive swapped in).
    serial: String,
    /// Plugged in: `false` once retired, until a drive comes back to the same place.
    present: bool,
    /// Its device numbers' major and unit (minor `unit << 8`), and the whole disk's block device.
    major: u32,
    unit: u32,
    whole: u32,
    /// The block devices and `/dev` nodes (`major`, `minor`) of its partitions and their labels,
    /// replaced when a CD's disc changes (`media_check`).
    parts: Vec<(u32, u32, u32)>,
}

/// Every disk, in registration order: a disk's index here is its number for `kern::vfs_bdev`.
/// Grow-only: a retired disk's entry stays, not `present`.
static DISKS: Mutex<Vec<Disk>> = Mutex::new(Vec::new());
/// Whether oxfs should mount the root read-only at boot (`set_root_readonly_at_boot`).
static ROOT_READONLY_AT_BOOT: AtomicBool = AtomicBool::new(false);
/// `kern.disk.root_lost`: the root's drive going leaves the root failing with `EIO` (`true`)
/// instead of panicking.
pub static ROOT_LOST_EIO: AtomicBool = AtomicBool::new(false);

/// Device numbers (Linux's majors, `OxideBSD-doc/DEVFS.md` §3.5), one major per driver: minor
/// `unit << 8` for a whole disk, `unit << 8 | N` for its partition N.
const IDE_MAJOR: u32 = 3;
const SCSI_MAJOR: u32 = 8;
/// AHCI's unit is the drive's place (`ahci::Unit::number`), not a counter.
const SATA_MAJOR: u32 = 251;
const VIRTIO_MAJOR: u32 = 252;
/// `/dev/gpt/<label>`: another name for a labelled GPT partition, minors in the order found.
const GPT_LABEL_MAJOR: u32 = 253;
static NEXT_LABEL_MINOR: AtomicU32 = AtomicU32::new(0);

/// Open raw devices: `real_fd -> block device handle` (`kern::vfs_bdev`). The offset is the
/// file's (`fs::fd`).
static RAW_OPEN: Mutex<alloc::collections::BTreeMap<u64, u32>> = Mutex::new(alloc::collections::BTreeMap::new());

/// Adds a disk to the registry, or gives a retired one's entry of the same name (the same place)
/// to it; its index.
fn register(
    name: String,
    backend: Backend,
    kind: Kind,
    sectors: u64,
    sector_size: u32,
    model: String,
    major: u32,
    unit: u32,
) -> u32 {
    let mut disks = DISKS.lock();
    let disk = Disk {
        name: name.clone(),
        backend,
        kind,
        sectors,
        sector_size,
        model,
        serial: String::new(),
        present: true,
        major,
        unit,
        whole: 0,
        parts: Vec::new(),
    };
    if let Some(i) = disks.iter().position(|d| !d.present && d.name == name) {
        disks[i] = disk;
        return i as u32;
    }
    disks.push(disk);
    let index = (disks.len() - 1) as u32;
    drop(disks);
    crate::kern::kern_sysctl::disk_registered(name, index);
    index
}

/// Registers every disk: virtio-blk first, then the IDE disks (setting up their DMA), AHCI's and
/// virtio-scsi's; then their partitions and `/dev` nodes, and the root (else a memory disk).
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) {
    let mut found = Vec::new();
    for (unit, sectors) in super::virtio_blk::init(frame_allocator, mapper, phys_mem_offset).into_iter().enumerate() {
        let name = alloc::format!("virt{unit}");
        let model = String::from("virtio-blk");
        found.push(register(name, Backend::Virtio(unit), Kind::Disk, sectors, 512, model, VIRTIO_MAJOR, unit as u32));
    }
    super::ata::init();
    super::ata::init_dma(frame_allocator, phys_mem_offset);
    let mut unit = 0;
    for (channel, drive) in super::ata::POSITIONS {
        let name = alloc::format!("ide{unit}");
        let model = super::ata::model(channel, drive);
        if super::ata::present(channel, drive) {
            let sectors = super::ata::capacity_sectors(channel, drive);
            found.push(register(name, Backend::Ata(channel, drive), Kind::Disk, sectors, 512, model, IDE_MAJOR, unit));
        } else if super::ata::atapi_present(channel, drive) {
            found.push(register_cd(name, Backend::Atapi(channel, drive), model, IDE_MAJOR, unit));
        } else {
            continue;
        }
        unit += 1;
    }
    for f in super::ahci::init(frame_allocator, mapper, phys_mem_offset) {
        found.push(register_ahci(f));
    }
    let mut unit = 0;
    for f in super::virtio_scsi::init(frame_allocator, mapper, phys_mem_offset) {
        let name = alloc::format!("scsi{unit}");
        let backend = Backend::Scsi(f.unit);
        match f.device_type {
            super::scsi::TYPE_CDROM => found.push(register_cd(name, backend, f.model, SCSI_MAJOR, unit)),
            super::scsi::TYPE_DISK => match super::scsi::capacity(&f.unit).0 {
                Some((blocks, size)) if (512..=4096).contains(&size) && size.is_power_of_two() => {
                    let sectors = blocks * (size as u64 / 512);
                    found.push(register(name, backend, Kind::Disk, sectors, size, f.model, SCSI_MAJOR, unit));
                }
                _ => {
                    serial_println!("[boot] disk: {}: no medium, or sectors of a size not driven -- left out", name);
                    continue;
                }
            },
            t => {
                serial_println!("[boot] disk: {}: SCSI device type {:#04x} isn't a disk or CD -- left out", name, t);
                continue;
            }
        }
        unit += 1;
    }

    let mut parts = Vec::new();
    for disk in found {
        attach(disk, &mut parts);
    }
    // oxfs's 4 KiB blocks: its partition must start on one (`Partition::blocks`).
    match choose_root(&parts).and_then(|r| Some((r, r.part.blocks()?))) {
        Some((r, (_, blocks))) => {
            crate::kern::vfs_bdev::set_root(r.handle);
            serial_println!("[boot] disk: oxfs on {} ({} MiB)", r.name, blocks / 256);
        }
        None => {
            serial_println!(
                "[boot] disk: no usable oxfs partition on any disk (partition and newfs_oxfs one, or install a system image)"
            );
            init_memory(phys_mem_offset);
        }
    }
}

/// Registers an AHCI drive; its index.
fn register_ahci(f: super::ahci::Found) -> u32 {
    let (name, number, backend) = (f.unit.name(), f.unit.number(), Backend::Ahci(f.unit));
    let disk = if f.unit.atapi() {
        register_cd(name, backend, f.model, SATA_MAJOR, number)
    } else {
        let sectors = f.sectors * (f.sector_size as u64 / 512);
        register(name, backend, Kind::Disk, sectors, f.sector_size, f.model, SATA_MAJOR, number)
    };
    DISKS.lock()[disk as usize].serial = f.serial;
    disk
}

/// A drive plugged into a running system: registered with its partitions and `/dev` nodes, as at
/// boot. The caller holds the giant lock (its partition table is read).
pub(crate) fn hot_attach(f: super::ahci::Found) {
    let disk = register_ahci(f);
    attach(disk, &mut Vec::new());
    let d = &DISKS.lock()[disk as usize];
    serial_println!(
        "[disk] {}: attached, {} \"{}\"{}",
        d.name,
        d.kind.name(),
        d.model,
        if d.kind == Kind::Cd { String::new() } else { alloc::format!(", {} MiB", d.sectors / 2048) }
    );
}

/// The registered (present) drives on AHCI controller `c`'s port `port`, behind a multiplier or
/// not: `(disk, unit)` each.
pub(crate) fn ahci_drives(c: u8, port: u8) -> Vec<(u32, super::ahci::Unit)> {
    let disks = DISKS.lock();
    let mut drives = Vec::new();
    for (i, d) in disks.iter().enumerate() {
        if let Backend::Ahci(unit) = d.backend
            && d.present
            && unit.place().0 == c
            && unit.place().1 == port
        {
            drives.push((i as u32, unit));
        }
    }
    drives
}

/// What AHCI drive `disk` said it was when it registered, for `ahci::same_drive`.
pub(crate) fn ahci_identity(disk: u32) -> Option<super::ahci::Found> {
    let disks = DISKS.lock();
    let d = disks.get(disk as usize).filter(|d| d.present)?;
    let Backend::Ahci(unit) = d.backend else { return None };
    let sectors = if d.kind == Kind::Cd { 0 } else { d.sectors / (d.sector_size as u64 / 512) };
    Some(super::ahci::Found { unit, model: d.model.clone(), serial: d.serial.clone(), sectors, sector_size: d.sector_size })
}

/// Disk `disk` was pulled out: it's marked gone first (so the forced unmounts' writes fail at
/// once, not after a command timeout each), then every file system on its devices is unmounted by
/// force -- the root's going panics, or with `kern.disk.root_lost=eio` leaves the root failing
/// with `EIO` -- and its devices and `/dev` nodes go; open raw descriptors fail with `EIO`. The
/// caller holds the giant lock.
pub(crate) fn retire(disk: u32) {
    use crate::kern::{vfs_bdev, vfs_bio, vfs_mount};
    let (name, whole, parts, major, minor, bus) = {
        let mut disks = DISKS.lock();
        let Some(d) = disks.get_mut(disk as usize).filter(|d| d.present) else { return };
        d.present = false;
        (d.name.clone(), d.whole, core::mem::take(&mut d.parts), d.major, d.unit << 8, d.backend.bus())
    };
    let handles: Vec<u32> = core::iter::once(whole).chain(parts.iter().map(|&(h, _, _)| h)).collect();
    for mp in vfs_mount::mounts() {
        // SAFETY: a mounted mount.
        let (dev, root) = unsafe { ((*mp).mnt_dev, (*mp).mnt_flag & vfs_if::MNT_ROOTFS != 0) };
        if !handles.iter().any(|&h| h as u64 == dev) {
            continue;
        }
        if root {
            if !ROOT_LOST_EIO.load(Ordering::Relaxed) {
                panic!("root device {} is gone", name);
            }
            serial_println!("[disk] {}: the root's drive is gone -- the root fails with EIO from now on", name);
            devctl::event("lost", "root").field("name", &name).field("policy", "eio").post();
            continue;
        }
        // SAFETY: as above.
        let on = unsafe { String::from(String::from_utf8_lossy(&(*mp).mnt_onname).trim_end_matches('\0')) };
        vfs_mount::force_unmount(mp);
        serial_println!("[disk] {}: {} unmounted by force", name, on);
    }
    for &h in &handles {
        vfs_bio::binvalall(h);
        vfs_bdev::retire(h);
    }
    for &(_, major, minor) in &parts {
        let _ = crate::fs::devfs::destroy_dev(major, minor);
    }
    let _ = crate::fs::devfs::destroy_dev(major, minor);
    serial_println!("[disk] {}: detached", name);
    devctl::event("detach", "disk").field("name", &name).field("bus", bus).post();
}

/// `debug.disk.unplug`: pulls disk `name` out in software, as if unplugged, and then looks at its
/// place again (so a drive still there comes back, with the same name). AHCI drives only.
pub fn simulate_unplug(name: &str) -> Result<(), i64> {
    let backend = DISKS.lock().iter().find(|d| d.present && d.name == name).map(|d| d.backend);
    match backend {
        Some(Backend::Ahci(unit)) => {
            super::ahci::simulate_unplug(&unit);
            Ok(())
        }
        Some(_) => Err(crate::syscall::ENOTSUP as i64),
        None => Err(crate::syscall::ENOENT as i64),
    }
}

/// A partition found at boot: its `/dev` name, its block device, and where it is.
struct Found {
    name: String,
    handle: u32,
    part: Partition,
}

/// Registers disk `disk`'s block device and raw `/dev` node, then its partitions'
/// (`attach_partitions`), adding them to `parts`.
fn attach(disk: u32, parts: &mut Vec<Found>) {
    use crate::kern::vfs_bdev;
    let (name, major, minor, sectors, kind, event) = {
        let d = &DISKS.lock()[disk as usize];
        let mut event = devctl::event("attach", "disk")
            .field("name", &d.name)
            .field("bus", d.backend.bus())
            .field("model", &d.model)
            .field("kind", d.kind.name())
            .field("sectors", d.sectors)
            .field("sector_size", d.sector_size);
        if let Backend::Ahci(unit) = d.backend {
            let (controller, port, pmp) = unit.place();
            event = event.field("controller", controller).field("port", port);
            if let Some(pmp) = pmp {
                event = event.field("pmp", pmp);
            }
        }
        (d.name.clone(), d.major, d.unit << 8, d.sectors, d.kind, event)
    };
    // DEVD.md §3.3: the drive, then its nodes.
    event.post();
    let whole = vfs_bdev::register(&name, major, minor, 0, sectors, disk);
    DISKS.lock()[disk as usize].whole = whole;
    let _ = crate::fs::devfs::make_dev(&name, major, minor, 0, 0, 0o600, raw_open);
    if kind == Kind::Cd && sectors != 0 {
        media_event(&name, sectors);
    }
    attach_partitions(disk, parts);
}

/// `media cd`: a disc of `sectors` found in drive `name`, or (0) its disc gone.
fn media_event(name: &str, sectors: u64) {
    let event = devctl::event("media", "cd").field("name", name);
    if sectors == 0 {
        event.field("state", "ejected").post();
    } else {
        event.field("state", "inserted").field("sectors", sectors).post();
    }
}

/// Registers a CD drive, empty or with a disc: its size now, checked again at each open
/// (`media_check`).
fn register_cd(name: String, backend: Backend, model: String, major: u32, unit: u32) -> u32 {
    let (sectors, size) = cd_capacity(backend).0;
    if sectors == 0 {
        serial_println!("[boot] disk: {}: CD drive, no disc", name);
    } else {
        serial_println!("[boot] disk: {}: CD drive, disc of {} MiB", name, sectors / 2048);
    }
    register(name, backend, Kind::Cd, sectors, size, model, major, unit)
}

/// The size of the disc in a CD drive, `(512-byte sectors, sector size)` (`(0, 2048)` when it's
/// empty), and whether the disc changed since the drive was last asked. A drive reporting a
/// sector size a data disc doesn't have (2352, raw; or 0) is read in 2048-byte sectors.
fn cd_capacity(backend: Backend) -> ((u64, u32), bool) {
    const CD_SECTOR: u32 = 2048;
    let (capacity, changed) = with_scsi(backend, super::scsi::capacity).unwrap_or((None, false));
    let capacity = capacity.map_or((0, CD_SECTOR), |(n, size)| {
        let size = if (512..=CD_SECTOR).contains(&size) && size.is_power_of_two() { size } else { CD_SECTOR };
        (n * (size as u64 / 512), size)
    });
    (capacity, changed)
}

/// Reads disk `disk`'s partition table and registers each partition's block device and raw `/dev`
/// node (and its label's), adding them to `parts`. A disk's table counts in its own sectors; a
/// CD's is read as a USB stick's would be: a hybrid image's MBR or GPT counts 512-byte sectors.
fn attach_partitions(disk: u32, parts: &mut Vec<Found>) {
    use crate::kern::vfs_bdev;
    let (name, major, minor, sectors, table_sector) = {
        let d = &DISKS.lock()[disk as usize];
        let table_sector = if d.kind == Kind::Cd { 512 } else { d.sector_size as usize };
        (d.name.clone(), d.major, d.unit << 8, d.sectors, table_sector)
    };
    let mut nodes = Vec::new();
    let mut head = alloc::vec![0u8; 34 * table_sector];
    let table = if read_sectors(disk, 0, &mut head) { super::part::read(&head, table_sector) } else { Vec::new() };
    for p in table {
        if p.index > 0xff || p.first_lba.checked_add(p.sectors).is_none_or(|end| end > sectors) {
            serial_println!("[boot] disk: {}: partition {} lies outside the disk -- ignored", name, p.index);
            continue;
        }
        let dev = alloc::format!("{name}{}", p.suffix());
        let handle = vfs_bdev::register(&dev, major, minor | p.index, p.first_lba, p.sectors, disk);
        let _ = crate::fs::devfs::make_dev(&dev, major, minor | p.index, 0, 0, 0o600, raw_open);
        nodes.push((handle, major, minor | p.index));
        if let Some(label) = &p.label {
            let label_dev = alloc::format!("gpt/{label}");
            let label_minor = NEXT_LABEL_MINOR.fetch_add(1, Ordering::Relaxed);
            if crate::fs::devfs::make_dev(&label_dev, GPT_LABEL_MAJOR, label_minor, 0, 0, 0o600, raw_open).is_ok() {
                let h = vfs_bdev::register(&label_dev, GPT_LABEL_MAJOR, label_minor, p.first_lba, p.sectors, disk);
                nodes.push((h, GPT_LABEL_MAJOR, label_minor));
            } else {
                serial_println!("[boot] disk: {}: label {} is taken -- only {} names it", name, label_dev, dev);
            }
        }
        parts.push(Found { name: dev, handle, part: p });
    }
    DISKS.lock()[disk as usize].parts = nodes;
}

/// Before device `major`/`minor` is opened or mounted: if it's on a CD drive and nothing on the
/// drive is mounted, asks the drive whether its disc changed (or came or went), and if so takes
/// the new size and partitions, the old partitions' devices gone (their open descriptors read
/// nothing more). INSTALLER.md §5.3: discs change without a reboot.
pub(crate) fn media_check(major: u32, minor: u32) {
    use crate::kern::vfs_bdev;
    let Some((_, _, disk)) = vfs_bdev::find(major, minor).and_then(vfs_bdev::extent) else { return };
    let (backend, whole, old_parts, old_sectors) = {
        let disks = DISKS.lock();
        let Some(d) = disks.get(disk as usize).filter(|d| d.kind == Kind::Cd) else { return };
        (d.backend, d.whole, d.parts.clone(), d.sectors)
    };
    let in_use = core::iter::once(whole)
        .chain(old_parts.iter().map(|&(h, _, _)| h))
        .any(|h| crate::kern::vfs_mount::dev_in_use(h as u64));
    if in_use {
        return;
    }
    let ((sectors, size), changed) = cd_capacity(backend);
    if !changed && sectors == old_sectors {
        return;
    }
    for &(handle, major, minor) in &old_parts {
        vfs_bdev::retire(handle);
        let _ = crate::fs::devfs::destroy_dev(major, minor);
    }
    {
        let mut disks = DISKS.lock();
        let d = &mut disks[disk as usize];
        d.sectors = sectors;
        d.sector_size = size;
        d.parts.clear();
    }
    vfs_bdev::set_sectors(whole, sectors);
    let name = DISKS.lock()[disk as usize].name.clone();
    if sectors == 0 {
        serial_println!("[disk] {}: no disc", name);
    } else {
        serial_println!("[disk] {}: disc of {} MiB", name, sectors / 2048);
    }
    // A disc swapped for another goes, then the new one comes.
    if old_sectors != 0 {
        media_event(&name, 0);
    }
    if sectors != 0 {
        media_event(&name, sectors);
    }
    attach_partitions(disk, &mut Vec::new());
}

/// A file system mounted (`true`) or unmounted device `handle` (called once the mount list says
/// so): a CD drive's tray is locked while anything on it is mounted.
pub(crate) fn mounted(handle: u32, mounted: bool) {
    let Some((_, _, disk)) = crate::kern::vfs_bdev::extent(handle) else { return };
    let (backend, whole, parts) = {
        let disks = DISKS.lock();
        // A drive pulled out has no tray to unlock (`retire` unmounts what was on it).
        let Some(d) = disks.get(disk as usize).filter(|d| d.kind == Kind::Cd && d.present) else { return };
        (d.backend, d.whole, d.parts.clone())
    };
    let still = core::iter::once(whole)
        .chain(parts.iter().map(|&(h, _, _)| h))
        .any(|h| crate::kern::vfs_mount::dev_in_use(h as u64));
    if mounted || !still {
        with_scsi(backend, |t| super::scsi::lock(t, mounted));
    }
}

/// The root's partition: the device `/boot/fsconf` names (`/dev/virt0p1`, or `/dev/gpt/<label>`),
/// on whichever disk; else the first oxfs partition, with a word when there are several to choose
/// from (an `/etc/fstab` root entry settles it).
fn choose_root(parts: &[Found]) -> Option<&Found> {
    if let Some(device) = crate::kern::fsconf::root_device() {
        let spec = device.strip_prefix("/dev/").unwrap_or(&device);
        let named = parts.iter().find(|f| {
            f.name == spec || f.part.label.as_deref().is_some_and(|l| spec.strip_prefix("gpt/") == Some(l))
        });
        match named {
            Some(f) => {
                serial_println!("[boot] disk: root {} (from /boot/fsconf)", device);
                return Some(f);
            }
            None => {
                serial_println!(
                    "[boot] disk: root {} (from /boot/fsconf) isn't on any disk -- using the first oxfs partition",
                    device
                );
            }
        }
    }
    let mut oxfs = parts.iter().filter(|f| f.part.oxfs);
    let first = oxfs.next()?;
    if oxfs.next().is_some() {
        serial_println!(
            "[boot] disk: several oxfs partitions and no root entry in /boot/fsconf -- using {}; add a root entry to /etc/fstab",
            first.name
        );
    }
    Some(first)
}

/// Makes a memory disk of a quarter of RAM the root (`md0`): with no oxfs partition on any disk, or
/// with `no-ata`, where real disks aren't probed at all.
pub fn init_memory(phys_mem_offset: VirtAddr) {
    let blocks = crate::memory::usable_ram_bytes() / 4 / 4096;
    super::md::init(blocks, phys_mem_offset);
    let model = String::from("memory disk");
    let disk = register(String::from("md0"), Backend::Memory, Kind::Memory, blocks * 8, 512, model, 0, 0);
    let handle = crate::kern::vfs_bdev::register("md0", 0, 0, 0, blocks * 8, disk);
    crate::kern::vfs_bdev::set_root(handle);
    serial_println!(
        "[boot] disk: no data disk -- a {} MiB memory disk this boot, nothing persists",
        blocks / 256
    );
}

/// `(transfers, completion interrupts)` on the disks so far, for the boot log.
pub fn stats() -> (u64, u64) {
    let (ata_transfers, ata_irqs) = super::ata::dma_stats();
    let (virtio_transfers, virtio_irqs) = super::virtio_blk::stats();
    let (scsi_requests, scsi_irqs) = super::virtio_scsi::stats();
    let (ahci_commands, ahci_irqs) = super::ahci::stats();
    (
        ata_transfers + virtio_transfers + scsi_requests + ahci_commands,
        ata_irqs + virtio_irqs + scsi_irqs + ahci_irqs,
    )
}

/// The space-separated names of the registered disks (`kern.disks`).
pub fn names() -> String {
    let disks = DISKS.lock();
    let names: Vec<&str> = disks.iter().filter(|d| d.present).map(|d| d.name.as_str()).collect();
    names.join(" ")
}

/// Disk `disk`'s `(kind, size in bytes, sector size, model)` (`kern.disk.<name>`).
pub fn describe(disk: u32) -> Option<(&'static str, u64, u32, String)> {
    let disks = DISKS.lock();
    let d = disks.get(disk as usize).filter(|d| d.present)?;
    Some((d.kind.name(), d.sectors * 512, d.sector_size, d.model.clone()))
}

/// Whether disk `disk` is the memory disk.
fn is_memory(disk: u32) -> bool {
    DISKS.lock().get(disk as usize).is_some_and(|d| d.kind == Kind::Memory)
}

/// Disk `disk`'s driver and sector size, while it's plugged in. The registry's lock is dropped
/// before any I/O: a transfer may sleep.
fn backend(disk: u32) -> Option<(Backend, u64)> {
    DISKS.lock().get(disk as usize).filter(|d| d.present).map(|d| (d.backend, d.sector_size as u64))
}

/// Reads whole device sectors (of `ss` bytes) from device sector `lba`.
fn device_read(backend: Backend, ss: u64, lba: u64, buf: &mut [u8]) -> bool {
    match backend {
        Backend::Ata(channel, drive) => super::ata::read_disk_sectors(channel, drive, lba, buf).is_ok(),
        Backend::Atapi(channel, drive) => super::ata::atapi_read(channel, drive, lba, buf).is_ok(),
        Backend::Ahci(unit) if unit.atapi() => {
            super::scsi::read(&unit, lba, ss as usize, unit.max_blocks(ss as usize), buf).is_ok()
        }
        Backend::Ahci(unit) => super::ahci::read(&unit, lba, ss as usize, buf).is_ok(),
        Backend::Scsi(unit) => {
            super::scsi::read(&unit, lba, ss as usize, unit.max_blocks(ss as usize), buf).is_ok()
        }
        Backend::Virtio(unit) => super::virtio_blk::read_sectors(unit, lba, buf),
        Backend::Memory => super::md::read_sectors(lba, buf),
    }
}

/// Writes whole device sectors (of `ss` bytes) at device sector `lba`, durably.
fn device_write(backend: Backend, ss: u64, lba: u64, buf: &[u8]) -> bool {
    match backend {
        Backend::Ata(channel, drive) => super::ata::write_disk_sectors(channel, drive, lba, buf).is_ok(),
        Backend::Atapi(..) => false, // read-only
        Backend::Ahci(unit) if unit.atapi() => false,
        Backend::Ahci(unit) => super::ahci::write(&unit, lba, ss as usize, buf).is_ok(),
        Backend::Scsi(unit) => {
            super::scsi::write(&unit, lba, ss as usize, unit.max_blocks(ss as usize), buf).is_ok()
        }
        Backend::Virtio(unit) => super::virtio_blk::write_sectors(unit, lba, buf),
        Backend::Memory => super::md::write_sectors(lba, buf),
    }
}

/// The device sectors `[first, first + count)` (of `sector_size` bytes) covering 512-byte
/// sectors `[lba, lba + n)`, and the byte offset of `lba` in the first.
fn covering(sector_size: u64, lba: u64, n: u64) -> (u64, u64, usize) {
    let per = sector_size / 512;
    let first = lba / per;
    (first, (lba + n).div_ceil(per) - first, ((lba % per) * 512) as usize)
}

/// Reads whole 512-byte sectors from `lba` of disk `disk` into `buf`: the block layer's way down
/// (`kern::vfs_bdev`), unbounded -- the handle bounds it.
pub(crate) fn read_sectors(disk: u32, lba: u64, buf: &mut [u8]) -> bool {
    let Some((backend, sector_size)) = backend(disk) else { return false };
    let (first, count, at) = covering(sector_size, lba, buf.len() as u64 / 512);
    if at == 0 && buf.len() as u64 == count * sector_size {
        return device_read(backend, sector_size, first, buf);
    }
    let mut whole = alloc::vec![0u8; (count * sector_size) as usize];
    if !device_read(backend, sector_size, first, &mut whole) {
        return false;
    }
    buf.copy_from_slice(&whole[at..at + buf.len()]);
    true
}

/// Writes whole 512-byte sectors at `lba` of disk `disk`, durably; a partial device sector is
/// read, patched and written back.
pub(crate) fn write_sectors(disk: u32, lba: u64, buf: &[u8]) -> bool {
    let Some((backend, sector_size)) = backend(disk) else { return false };
    let (first, count, at) = covering(sector_size, lba, buf.len() as u64 / 512);
    if at == 0 && buf.len() as u64 == count * sector_size {
        return device_write(backend, sector_size, first, buf);
    }
    let mut whole = alloc::vec![0u8; (count * sector_size) as usize];
    if !device_read(backend, sector_size, first, &mut whole) {
        return false;
    }
    whole[at..at + buf.len()].copy_from_slice(buf);
    device_write(backend, sector_size, first, &whole)
}

/// Asks oxfs to mount the root read-only (the real boot path, `kernel_main`).
pub fn set_root_readonly_at_boot() {
    ROOT_READONLY_AT_BOOT.store(true, Ordering::Relaxed);
}

/// For oxfs: `1` when it should mount the root read-only at boot. Never for the memory disk:
/// formatted moments ago, it has nothing to check, and no raw device to check it through.
pub extern "C" fn oxidebsd_root_readonly_at_boot() -> u64 {
    let on_memory = crate::kern::vfs_bdev::root()
        .and_then(crate::kern::vfs_bdev::extent)
        .is_some_and(|(_, _, disk)| is_memory(disk));
    (ROOT_READONLY_AT_BOOT.load(Ordering::Relaxed) && !on_memory) as u64
}

/// For oxfs: it has its partition mounted read-write (`rw != 0`) or read-only.
pub extern "C" fn oxidebsd_root_mounted_rw(rw: u64) {
    if let Some(h) = crate::kern::vfs_bdev::root() {
        crate::kern::vfs_bdev::oxidebsd_bdev_set_mounted(h as u64, rw);
    }
}

/// Whether raw device `handle` overlaps a device a file system has mounted read-write.
fn overlaps_mounted(handle: u32) -> bool {
    crate::kern::vfs_bdev::extent(handle)
        .is_some_and(|(first, sectors, disk)| crate::kern::vfs_bdev::overlaps_mounted_rw(first, sectors, disk))
}

/// Opens raw device `major:minor` (a CD drive's disc checked first, `media_check`). Writing is
/// refused on a CD (`EROFS`), and (`EPERM`) for a device overlapping one a file system has mounted
/// read-write: the writes would go around its cache (RAM_FLOOR.md
/// §3.4.3). `fsck_oxfs` writes the root while it's read-only.
extern "C" fn raw_open(major: u64, minor: u64, flags: u64) -> i64 {
    // A disk driver's lock may be held by a process asleep under the giant lock (an oxfs
    // transfer): take that first, or spin on the driver's lock with the sleeper never run again.
    let _giant = crate::fs::fslock::Giant::enter();
    const O_ACCMODE: u64 = 3;
    media_check(major as u32, minor as u32);
    let Some(handle) = crate::kern::vfs_bdev::find(major as u32, minor as u32) else {
        return -(crate::syscall::ENXIO as i64);
    };
    let read_only = crate::kern::vfs_bdev::extent(handle)
        .is_some_and(|(_, _, disk)| DISKS.lock().get(disk as usize).is_some_and(|d| d.kind == Kind::Cd));
    if flags & O_ACCMODE != 0 && read_only {
        return -(crate::syscall::EROFS as i64);
    }
    if flags & O_ACCMODE != 0 && overlaps_mounted(handle) {
        return -(crate::syscall::EPERM as i64);
    }
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -(e as i64);
    }
    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    RAW_OPEN.lock().insert(real_fd, handle);
    crate::fs::fd::finstall(real_fd, &RAW_OPS, 0, crate::fs::fd::open_flag(flags), crate::fs::fd::FdKind::Module)
}

/// A raw disk or partition device's file operations: seekable, the kernel keeping the offset.
static RAW_OPS: crate::fs::fd::FileOps = crate::fs::fd::FileOps {
    flags: crate::fs::fd::DFLAG_SEEKABLE,
    read: Some(raw_read),
    write: Some(raw_write),
    close: Some(raw_close),
    ioctl: Some(raw_ioctl),
    sync: Some(raw_sync),
    ..crate::fs::fd::FileOps::NONE
};

/// `FileOps::ioctl`: the disk requests (`ioctl` below); `ENOTTY` for any other.
extern "C" fn raw_ioctl(real_fd: u64, request: u64, argp: u64) -> i64 {
    match ioctl(real_fd, request, argp) {
        Some(Ok(v)) => v as i64,
        Some(Err(e)) => -(e as i64),
        None => -(crate::syscall::ENOTTY as i64),
    }
}

/// `FileOps::sync`: nothing to do, every raw write goes straight to the disk.
extern "C" fn raw_sync(_real_fd: u64, _data_only: u64) -> i64 {
    0
}

/// Reads from the device at the descriptor's position (or `pread`'s offset), the whole sectors it
/// covers, stopping at the device's end. Uncached, as FreeBSD's raw devices are.
extern "C" fn raw_read(real_fd: u64, uio: *mut crate::kern::subr_uio::Uio, _flags: u64) -> i64 {
    // A disk driver's lock may be held by a process asleep under the giant lock (an oxfs
    // transfer): take that first, or spin on the driver's lock with the sleeper never run again.
    let _giant = crate::fs::fslock::Giant::enter();
    use crate::kern::vfs_bdev;
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let Some(handle) = RAW_OPEN.lock().get(&real_fd).copied() else {
        return -(crate::syscall::EBADF as i64);
    };
    let Some((_, sectors, _)) = vfs_bdev::extent(handle) else {
        return -(crate::syscall::EBADF as i64);
    };
    if vfs_bdev::retired(handle) {
        return -(crate::syscall::EIO as i64); // its drive was pulled out, or its disc changed
    }
    // Seekable: the uio is always at an offset (FOF_OFFSET or FOF_NEXTOFF).
    let offset = uio.offset();
    let len = uio.resid().min((sectors * vfs_bdev::SECTOR).saturating_sub(offset));
    if len == 0 {
        return 0;
    }
    let (first, count) = covering_sectors(offset, len);
    let mut buf = alloc::vec![0u8; (count * vfs_bdev::SECTOR) as usize];
    if vfs_bdev::read(handle, first, &mut buf).is_err() {
        return -(crate::syscall::EIO as i64);
    }
    let at = (offset - first * vfs_bdev::SECTOR) as usize;
    match uio.uiomove_out(&buf[at..at + len as usize]) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

/// The sectors `[first, first + count)` covering `len` bytes at byte `offset`.
fn covering_sectors(offset: u64, len: u64) -> (u64, u64) {
    let sector = crate::kern::vfs_bdev::SECTOR;
    let first = offset / sector;
    (first, (offset + len).div_ceil(sector) - first)
}

/// Writes at the descriptor's position (or `pwrite`'s offset), the sectors it covers read,
/// patched and written back, stopping at the device's end. Refused again if a file system
/// mounted the device (or one overlapping it) read-write since the open.
extern "C" fn raw_write(real_fd: u64, uio: *mut crate::kern::subr_uio::Uio, _flags: u64) -> i64 {
    // A disk driver's lock may be held by a process asleep under the giant lock (an oxfs
    // transfer): take that first, or spin on the driver's lock with the sleeper never run again.
    let _giant = crate::fs::fslock::Giant::enter();
    use crate::kern::vfs_bdev;
    // SAFETY: the fd layer passes the live transfer of this call.
    let uio = unsafe { &mut *uio };
    let Some(handle) = RAW_OPEN.lock().get(&real_fd).copied() else {
        return -(crate::syscall::EBADF as i64);
    };
    if overlaps_mounted(handle) {
        return -(crate::syscall::EPERM as i64);
    }
    let Some((_, sectors, _)) = vfs_bdev::extent(handle) else {
        return -(crate::syscall::EBADF as i64);
    };
    if vfs_bdev::retired(handle) {
        return -(crate::syscall::EIO as i64); // its drive was pulled out, or its disc changed
    }
    let offset = uio.offset();
    let len = uio.resid().min((sectors * vfs_bdev::SECTOR).saturating_sub(offset));
    if len == 0 {
        return if uio.resid() == 0 { 0 } else { -(crate::syscall::ENOSPC as i64) };
    }
    let (first, count) = covering_sectors(offset, len);
    let mut buf = alloc::vec![0u8; (count * vfs_bdev::SECTOR) as usize];
    if vfs_bdev::read(handle, first, &mut buf).is_err() {
        return -(crate::syscall::EIO as i64);
    }
    let at = (offset - first * vfs_bdev::SECTOR) as usize;
    let n = match uio.uiomove_in(&mut buf[at..at + len as usize]) {
        Ok(n) => n,
        Err(e) => return -(e as i64),
    };
    if vfs_bdev::write(handle, first, &buf).is_err() {
        return -(crate::syscall::EIO as i64);
    }
    n as i64
}

/// `DIOCGSECTORSIZE`: a raw device's sector size (`u32`: its disk's, 512 or a CD's 2048).
/// FreeBSD's name in `<sys/disk.h>`; the number is OxideBSD's own, `_IOR('d', 128, u32)` in musl's
/// encoding.
pub const DIOCGSECTORSIZE: u64 = 0x8004_6480;
/// `DIOCGMEDIASIZE`: a raw device's size in bytes (`i64`, FreeBSD's `off_t`), so `newfs_oxfs`
/// can lay a filesystem out over it. `_IOR('d', 129, i64)`.
pub const DIOCGMEDIASIZE: u64 = 0x8008_6481;

/// The disk requests `ioctl(2)` answers on a raw device descriptor; `None` when `real_fd` isn't
/// one or `request` isn't a disk request, so `sys_ioctl` goes on to the others.
pub fn ioctl(real_fd: u64, request: u64, argp: u64) -> Option<Result<u64, u64>> {
    use crate::memory::usercopy::{UserPtr, copyout_val};
    if request != DIOCGSECTORSIZE && request != DIOCGMEDIASIZE {
        return None;
    }
    let handle = RAW_OPEN.lock().get(&real_fd).copied()?;
    let (_, sectors, disk) = crate::kern::vfs_bdev::extent(handle)?;
    Some(if request == DIOCGSECTORSIZE {
        let sector_size = backend(disk).map_or(512, |(_, size)| size as u32);
        copyout_val(&sector_size, UserPtr::new(argp)).map(|()| 0)
    } else {
        copyout_val(&((sectors * 512) as i64), UserPtr::new(argp)).map(|()| 0)
    })
}

extern "C" fn raw_close(real_fd: u64) -> i64 {
    RAW_OPEN.lock().remove(&real_fd);
    0
}
