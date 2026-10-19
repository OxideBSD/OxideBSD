//! A minimal legacy IDE disk driver: LBA28/LBA48, PIO or bus-master DMA. See
//! <https://wiki.osdev.org/ATA_PIO_Mode> and <https://wiki.osdev.org/ATA/ATAPI_using_DMA>.
//!
//! **PIO is slow under virtualization.** Every word of a PIO transfer is an `outsw`/`insw`
//! through the data port, and each one traps to QEMU: a fresh oxfs format (~259 MiB) took ~17
//! minutes, with the guest's instruction pointer sampled inside `outsw` nearly every time. So
//! when the IDE controller is a PCI bus master (`init_dma`), the disks' transfers go by DMA
//! through a bounce buffer below 4 GiB, finishing with the channel's IRQ (`dma::wait_for_disk`:
//! the process sleeps, or `hlt`/polling outside one). PIO remains the fallback.
//!
//! Any PIO wait uses `core::hint::spin_loop()` against a `crate::tsc` deadline, never `hlt()`:
//! these calls run inside syscall handlers with interrupts masked (oxfs's write-through
//! persistence), where a tick-based wait can never elapse (CLAUDE.md, "Real networking").
//!
//! **Legacy fixed ports, no PCI probing.** QEMU's default `i440fx` machine type's PIIX3 IDE
//! controller (and every real PC chipset before it) exposes the primary/secondary channels at
//! fixed, well-known port ranges regardless of PCI enumeration -- 0x1F0-0x1F7/0x3F6 (primary,
//! IRQ14) and 0x170-0x177/0x376 (secondary, IRQ15). Unlike `rtl8139`, there's nothing to discover.
//!
//! **Every drive is a disk** (`OxideBSD-doc/INSTALLER.md` §5.1): `init` probes all four
//! positions, and `drivers::disk` registers each ATA drive that answers, in the order primary
//! master, primary slave, secondary master, secondary slave (`ide0`, `ide1`, ...). Each channel
//! with a disk gets its own bus-master DMA (`init_dma`); the two drives on a channel share it, and
//! every command on a channel holds its lock. Commands are LBA28 where they fit and LBA48 above
//! (on drives that support it), so disks past 128 GiB work.
//!
//! **ATAPI** (optical drives, INSTALLER.md §5.3): a packet device is registered as a CD, with its
//! own counter position among the disks. Its commands are SCSI ones (MMC) sent as a 12-byte
//! packet through the `PACKET` command, data moved by PIO in blocks of up to 31 sectors (the byte
//! count limit), read-only: `TEST UNIT READY` (with `REQUEST SENSE` to tell "no disc" from
//! "becoming ready"), `READ CAPACITY(10)`, `READ(10)` and `PREVENT ALLOW MEDIUM REMOVAL`.

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use spin::Mutex;
use x86_64::instructions::port::Port;

use crate::serial_println;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Primary,
    Secondary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drive {
    Master,
    Slave,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaError {
    /// The status register read back `0xFF` (floating bus) or `0x00` immediately after selecting
    /// this drive -- nothing is wired up at this channel/drive at all.
    NoDevice,
    /// `BSY` never cleared / `DRQ` never set within the timeout budget -- a genuinely stuck or
    /// misbehaving drive, not absence (see `NoDevice`). Returned rather than spinning forever, the
    /// same reasoning CLAUDE.md documents for `net`'s own poll/connect/ARP deadline fixes.
    Timeout,
    /// `ERR` or `DF` (device fault) was set in the status register; the byte itself is kept for
    /// diagnostics.
    DeviceError(u8),
    /// The sectors asked for lie past the drive's end, or past what its addressing reaches (LBA28
    /// on a drive without LBA48).
    OutOfRange,
    /// A packet command failed: the SCSI sense key, additional sense code and qualifier
    /// (`REQUEST SENSE`).
    Sense(u8, u8, u8),
}

/// A channel's ports. Reading its status register (`io_base + 7`) acknowledges the drive's pending
/// `INTRQ`, which the DMA path's IRQ handler relies on; the control block's first register reads
/// as the alternate status (no acknowledgement) and writes as the device control register
/// (`nIEN` is bit 1).
struct ChannelPorts {
    io_base: u16,
    control: u16,
    irq: u8,
    /// The channel's bus-master registers, from the controller's BAR4.
    bm_offset: u16,
}

const PRIMARY: ChannelPorts = ChannelPorts { io_base: 0x1F0, control: 0x3F6, irq: 14, bm_offset: 0 };
const SECONDARY: ChannelPorts = ChannelPorts { io_base: 0x170, control: 0x376, irq: 15, bm_offset: 8 };

fn ports(channel: Channel) -> ChannelPorts {
    match channel {
        Channel::Primary => PRIMARY,
        Channel::Secondary => SECONDARY,
    }
}

fn channel_index(channel: Channel) -> usize {
    match channel {
        Channel::Primary => 0,
        Channel::Secondary => 1,
    }
}

/// The four positions, in probe (and naming) order.
pub const POSITIONS: [(Channel, Drive); 4] = [
    (Channel::Primary, Drive::Master),
    (Channel::Primary, Drive::Slave),
    (Channel::Secondary, Drive::Master),
    (Channel::Secondary, Drive::Slave),
];

fn position(channel: Channel, drive: Drive) -> usize {
    channel_index(channel) * 2 + (drive == Drive::Slave) as usize
}

// Register offsets from a channel's `io_base`.
const REG_DATA: u16 = 0;
const REG_SECTOR_COUNT: u16 = 2;
const REG_LBA_LOW: u16 = 3;
const REG_LBA_MID: u16 = 4;
const REG_LBA_HIGH: u16 = 5;
const REG_DRIVE_HEAD: u16 = 6;
const REG_STATUS_COMMAND: u16 = 7;

const STATUS_ERR: u8 = 0x01;
const STATUS_DRQ: u8 = 0x08;
const STATUS_DF: u8 = 0x20;
const STATUS_BSY: u8 = 0x80;

const CMD_READ_SECTORS: u8 = 0x20;
const CMD_READ_SECTORS_EXT: u8 = 0x24;
const CMD_READ_DMA: u8 = 0xC8;
const CMD_READ_DMA_EXT: u8 = 0x25;
const CMD_WRITE_SECTORS: u8 = 0x30;
const CMD_WRITE_SECTORS_EXT: u8 = 0x34;
const CMD_WRITE_DMA: u8 = 0xCA;
const CMD_WRITE_DMA_EXT: u8 = 0x35;
const CMD_CACHE_FLUSH: u8 = 0xE7;
const CMD_CACHE_FLUSH_EXT: u8 = 0xEA;
const CMD_IDENTIFY: u8 = 0xEC;
const CMD_PACKET: u8 = 0xA0;
const CMD_IDENTIFY_PACKET: u8 = 0xA1;

/// The error register (read) and features register (write).
const REG_ERROR_FEATURES: u16 = 1;

/// LBA28's reach: sectors below this address with the short command forms.
const LBA28_LIMIT: u64 = 1 << 28;
/// LBA48's.
const LBA48_LIMIT: u64 = 1 << 48;

/// Generous but bounded -- real/emulated PIO commands complete in microseconds to low
/// milliseconds; this only guards against a genuinely stuck or absent device, not real timing.
const TIMEOUT_MS: u64 = 3000;

/// What `IDENTIFY` told of one position's drive, set once by `init`.
struct DriveInfo {
    present: AtomicBool,
    /// A packet (ATAPI) device: an optical drive.
    atapi: AtomicBool,
    lba48: AtomicBool,
    /// Its size in 512-byte sectors (the LBA48 count where it has one).
    sectors: AtomicU64,
}

static DRIVES: [DriveInfo; 4] = [const {
    DriveInfo {
        present: AtomicBool::new(false),
        atapi: AtomicBool::new(false),
        lba48: AtomicBool::new(false),
        sectors: AtomicU64::new(0),
    }
}; 4];
/// Each drive's model string (`IDENTIFY` words 27-46), for `kern.disk.<name>.model`.
static MODELS: Mutex<[Option<String>; 4]> = Mutex::new([const { None }; 4]);

fn info(channel: Channel, drive: Drive) -> &'static DriveInfo {
    &DRIVES[position(channel, drive)]
}

fn read_status(io_base: u16) -> u8 {
    unsafe { Port::<u8>::new(io_base + REG_STATUS_COMMAND).read() }
}

/// Polls until `BSY` clears, bounded by `TIMEOUT_MS`. The status byte the loop stopped on is
/// returned for callers checking `DF`/`ERR` after a command completes.
fn wait_while_busy(io_base: u16) -> Result<u8, AtaError> {
    let deadline = crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(TIMEOUT_MS);
    loop {
        let status = read_status(io_base);
        if status == 0xFF {
            return Err(AtaError::NoDevice);
        }
        if status & STATUS_BSY == 0 {
            return Ok(status);
        }
        if crate::cpu::tsc::now() >= deadline {
            return Err(AtaError::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// Polls until the drive is ready to transfer a data block (`BSY` clear, `DRQ` set), bounded by
/// `TIMEOUT_MS`. Distinct from `wait_while_busy`: a command that doesn't move data (e.g. `CACHE
/// FLUSH`) only ever needs the latter.
fn wait_for_data(io_base: u16) -> Result<(), AtaError> {
    let deadline = crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(TIMEOUT_MS);
    loop {
        let status = read_status(io_base);
        if status == 0xFF {
            return Err(AtaError::NoDevice);
        }
        if status & (STATUS_ERR | STATUS_DF) != 0 {
            return Err(AtaError::DeviceError(status));
        }
        if status & STATUS_BSY == 0 && status & STATUS_DRQ != 0 {
            return Ok(());
        }
        if crate::cpu::tsc::now() >= deadline {
            return Err(AtaError::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// Selects `drive` on the channel (`head`: the drive/head register's other bits), then waits the
/// 400 ns a drive needs before its status is valid: four reads of the alternate status register,
/// ~100 ns each.
fn select(p: &ChannelPorts, drive: Drive, head: u8) {
    let drive_bit = if drive == Drive::Slave { 0x10 } else { 0 };
    unsafe {
        Port::<u8>::new(p.io_base + REG_DRIVE_HEAD).write(head | drive_bit);
        for _ in 0..4 {
            Port::<u8>::new(p.control).read();
        }
    }
}

/// Selects the drive and loads the task file for `sector_count` sectors at `lba`: LBA28 when the
/// whole transfer fits below 128 GiB, else LBA48 (`Err` on a drive without it). Whether the
/// command must be an `_EXT` one.
fn setup_command(channel: Channel, drive: Drive, lba: u64, sector_count: u8) -> Result<bool, AtaError> {
    let p = ports(channel);
    let ext = lba + sector_count as u64 > LBA28_LIMIT;
    if ext && (!info(channel, drive).lba48.load(Ordering::Relaxed) || lba + sector_count as u64 > LBA48_LIMIT) {
        return Err(AtaError::OutOfRange);
    }
    // 0xA0: the obsolete always-one bits; 0x40: LBA addressing.
    let head = if ext { 0xE0 } else { 0xE0 | ((lba >> 24) & 0x0F) as u8 };
    select(&p, drive, head);
    wait_while_busy(p.io_base)?;
    unsafe {
        if ext {
            // The high halves first: each register is a two-deep FIFO.
            Port::<u8>::new(p.io_base + REG_SECTOR_COUNT).write(0);
            Port::<u8>::new(p.io_base + REG_LBA_LOW).write((lba >> 24) as u8);
            Port::<u8>::new(p.io_base + REG_LBA_MID).write((lba >> 32) as u8);
            Port::<u8>::new(p.io_base + REG_LBA_HIGH).write((lba >> 40) as u8);
        }
        Port::<u8>::new(p.io_base + REG_SECTOR_COUNT).write(sector_count);
        Port::<u8>::new(p.io_base + REG_LBA_LOW).write(lba as u8);
        Port::<u8>::new(p.io_base + REG_LBA_MID).write((lba >> 8) as u8);
        Port::<u8>::new(p.io_base + REG_LBA_HIGH).write((lba >> 16) as u8);
    }
    Ok(ext)
}

fn command(channel: Channel, cmd: u8) {
    unsafe { Port::<u8>::new(ports(channel).io_base + REG_STATUS_COMMAND).write(cmd) };
}

/// Transfers `word_count` 16-bit words from `port` into `buf` (must hold `word_count * 2` bytes)
/// via a single `rep insw`. **Why not `x86_64::instructions::port::Port`'s `read()` in a loop**:
/// that's what this replaced -- under QEMU's TCG, each individually decoded/trapped `in`
/// instruction ends the current translated block, while a single `rep insw` is one instruction
/// whose whole repeat count is serviced in one trap, the standard OSDev-wiki-recommended technique
/// for PIO sector transfers. `INSW` targets `ES:(E)DI`; safe only because this kernel runs with a
/// flat segment model (`ES` base `0`), so the linear address is just `buf`. Guarded by an explicit
/// `cld` rather than trusting the SysV ABI's "DF clear on entry" convention, since this is the one
/// place a stray `std` elsewhere would silently corrupt every disk transfer.
unsafe fn insw(port: u16, buf: *mut u8, word_count: usize) {
    unsafe {
        core::arch::asm!(
            "cld",
            "rep insw",
            in("dx") port,
            inout("rdi") buf => _,
            inout("rcx") word_count => _,
            options(nostack, preserves_flags),
        );
    }
}

/// `insw`'s write counterpart -- `OUTSW` reads from `DS:(E)SI`, same flat-segment reasoning.
unsafe fn outsw(port: u16, buf: *const u8, word_count: usize) {
    unsafe {
        core::arch::asm!(
            "cld",
            "rep outsw",
            in("dx") port,
            inout("rsi") buf => _,
            inout("rcx") word_count => _,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads `sector_count` consecutive 512-byte sectors starting at `lba` from `channel`/`drive` into
/// `buf` (must be exactly `sector_count as usize * 512` bytes) in a single command -- the drive
/// command/LBA setup and busy-wait happen once, not once per sector (only the per-sector `DRQ`
/// wait is inherent to the ATA protocol and can't be batched away). `sector_count` `0` addresses
/// 256 sectors on real hardware (never used here).
fn pio_read_sectors(channel: Channel, drive: Drive, lba: u64, sector_count: u8, buf: &mut [u8]) -> Result<(), AtaError> {
    debug_assert_eq!(buf.len(), sector_count as usize * 512);
    let p = ports(channel);
    let ext = setup_command(channel, drive, lba, sector_count)?;
    command(channel, if ext { CMD_READ_SECTORS_EXT } else { CMD_READ_SECTORS });
    for sector in 0..sector_count as usize {
        wait_for_data(p.io_base)?;
        let sector_buf = &mut buf[sector * 512..(sector + 1) * 512];
        unsafe {
            insw(p.io_base + REG_DATA, sector_buf.as_mut_ptr(), 256);
        }
    }
    Ok(())
}

/// Writes `sector_count` consecutive sectors at `lba` by PIO, without flushing (`write_sectors`
/// adds the `CACHE FLUSH`). Same one-command-for-the-batch shape as `pio_read_sectors`.
fn pio_write_sectors(channel: Channel, drive: Drive, lba: u64, sector_count: u8, buf: &[u8]) -> Result<(), AtaError> {
    debug_assert_eq!(buf.len(), sector_count as usize * 512);
    let p = ports(channel);
    let ext = setup_command(channel, drive, lba, sector_count)?;
    command(channel, if ext { CMD_WRITE_SECTORS_EXT } else { CMD_WRITE_SECTORS });
    for sector in 0..sector_count as usize {
        wait_for_data(p.io_base)?;
        let sector_buf = &buf[sector * 512..(sector + 1) * 512];
        unsafe {
            outsw(p.io_base + REG_DATA, sector_buf.as_ptr(), 256);
        }
    }

    wait_while_busy(p.io_base)?;
    Ok(())
}

/// `CACHE FLUSH` (`FLUSH CACHE EXT` on an LBA48 drive): everything written so far is durable in
/// the backing image once this returns -- otherwise QEMU's write-back caching could reorder a
/// write past a later read of the same sector through another path. Checks `ERR`/`DF` once `BSY`
/// clears (`wait_while_busy` alone doesn't), so a flush the drive reports as failed isn't mistaken
/// for success.
fn cache_flush(channel: Channel, drive: Drive) -> Result<(), AtaError> {
    let p = ports(channel);
    select(&p, drive, 0xE0);
    wait_while_busy(p.io_base)?;
    let ext = info(channel, drive).lba48.load(Ordering::Relaxed);
    command(channel, if ext { CMD_CACHE_FLUSH_EXT } else { CMD_CACHE_FLUSH });
    let status = wait_while_busy(p.io_base)?;
    if status & (STATUS_ERR | STATUS_DF) != 0 {
        return Err(AtaError::DeviceError(status));
    }
    Ok(())
}

/// Reads `sector_count` (1-255) sectors at `lba` into `buf` (`sector_count * 512` bytes): by DMA
/// when the channel has it (`init_dma`), else by PIO.
pub fn read_sectors(channel: Channel, drive: Drive, lba: u64, sector_count: u8, buf: &mut [u8]) -> Result<(), AtaError> {
    let guard = CHANNELS[channel_index(channel)].lock();
    match guard.as_ref() {
        Some(bm) => dma_transfer(bm, channel, drive, lba, sector_count, Direction::Read(buf)),
        None => pio_read_sectors(channel, drive, lba, sector_count, buf),
    }
}

/// Writes `sector_count` (1-255) sectors at `lba` from `buf`, then `CACHE FLUSH`es, so they're
/// durable when this returns. DMA or PIO as `read_sectors`.
pub fn write_sectors(channel: Channel, drive: Drive, lba: u64, sector_count: u8, buf: &[u8]) -> Result<(), AtaError> {
    let guard = CHANNELS[channel_index(channel)].lock();
    write_sectors_unflushed(guard.as_ref(), channel, drive, lba, sector_count, buf)?;
    cache_flush(channel, drive)
}

/// `write_sectors` without the flush, the channel's lock held by the caller (`bm`: its bus
/// master, if it has DMA).
fn write_sectors_unflushed(
    bm: Option<&BusMaster>,
    channel: Channel,
    drive: Drive,
    lba: u64,
    sector_count: u8,
    buf: &[u8],
) -> Result<(), AtaError> {
    match bm {
        Some(bm) => dma_transfer(bm, channel, drive, lba, sector_count, Direction::Write(buf)),
        None => pio_write_sectors(channel, drive, lba, sector_count, buf),
    }
}

/// Reads one 512-byte sector at `lba` from `channel`/`drive`. A thin `read_sectors(..., 1, ...)`
/// wrapper kept for callers that only ever want one sector at a time (`tests/ata_smoke.rs`).
pub fn read_sector(channel: Channel, drive: Drive, lba: u64, buf: &mut [u8; 512]) -> Result<(), AtaError> {
    read_sectors(channel, drive, lba, 1, buf)
}

/// Writes one 512-byte sector at `lba` to `channel`/`drive`. A thin `write_sectors(..., 1, ...)`
/// wrapper kept for callers that only ever want one sector at a time.
pub fn write_sector(channel: Channel, drive: Drive, lba: u64, buf: &[u8; 512]) -> Result<(), AtaError> {
    write_sectors(channel, drive, lba, 1, buf)
}

/// What answered `IDENTIFY` at one position.
enum Identified {
    Nothing,
    /// An ATA disk: its size in sectors, whether it speaks LBA48, its model.
    Ata { sectors: u64, lba48: bool, model: String },
    /// A packet (ATAPI) device: an optical drive, and its model.
    Atapi { model: String },
}

/// Issues `IDENTIFY` against `channel`/`drive`. An ATA drive answers with 256 words: its capacity
/// (words 60-61, or 100-103 with LBA48, word 83 bit 10), its model (words 27-46, two characters
/// per word, high byte first). The whole payload is drained either way: the data port must be
/// emptied to leave the channel clean for the next command. A packet device aborts the command
/// and leaves its signature (`0x14`/`0xEB`, SATA's `0x69`/`0x96`) in the LBA mid/high registers;
/// `IDENTIFY PACKET DEVICE` then gives the same 256 words for it.
fn identify(channel: Channel, drive: Drive) -> Identified {
    let p = ports(channel);
    select(&p, drive, 0xA0);
    unsafe {
        Port::<u8>::new(p.io_base + REG_SECTOR_COUNT).write(0);
        Port::<u8>::new(p.io_base + REG_LBA_LOW).write(0);
        Port::<u8>::new(p.io_base + REG_LBA_MID).write(0);
        Port::<u8>::new(p.io_base + REG_LBA_HIGH).write(0);
    }

    let status = read_status(p.io_base);
    if status == 0 || status == 0xFF {
        // Nothing at all wired up at this channel/drive (or no channel).
        return Identified::Nothing;
    }

    command(channel, CMD_IDENTIFY);
    if read_status(p.io_base) == 0 || wait_while_busy(p.io_base).is_err() {
        return Identified::Nothing;
    }
    let signature = unsafe {
        (Port::<u8>::new(p.io_base + REG_LBA_MID).read(), Port::<u8>::new(p.io_base + REG_LBA_HIGH).read())
    };
    match signature {
        (0, 0) => {}
        (0x14, 0xEB) | (0x69, 0x96) => {
            select(&p, drive, 0xA0);
            command(channel, CMD_IDENTIFY_PACKET);
            return match identify_words(&p) {
                Some(words) => Identified::Atapi { model: model_of(&words) },
                None => Identified::Atapi { model: String::new() },
            };
        }
        _ => return Identified::Nothing,
    }
    let Some(words) = identify_words(&p) else {
        return Identified::Nothing;
    };
    let lba48 = words[83] & (1 << 10) != 0;
    let sectors = if lba48 {
        (0..4).fold(0u64, |acc, i| acc | (words[100 + i] as u64) << (16 * i))
    } else {
        words[60] as u64 | (words[61] as u64) << 16
    };
    Identified::Ata { sectors, lba48, model: model_of(&words) }
}

/// The 256 words an `IDENTIFY` (or `IDENTIFY PACKET DEVICE`) just issued returns.
fn identify_words(p: &ChannelPorts) -> Option<[u16; 256]> {
    wait_for_data(p.io_base).ok()?;
    let mut words = [0u16; 256];
    // SAFETY: draining the payload the drive just signalled ready.
    unsafe { insw(p.io_base + REG_DATA, words.as_mut_ptr() as *mut u8, 256) };
    Some(words)
}

/// The model string in identify words 27-46, two characters per word, high byte first.
fn model_of(words: &[u16; 256]) -> String {
    let model: String = words[27..47]
        .iter()
        .flat_map(|w| [(w >> 8) as u8, *w as u8])
        .map(|b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '?' })
        .collect();
    String::from(model.trim())
}

/// Probes all four legacy channel/drive combinations via `IDENTIFY`, logging each. Never panics on
/// absence -- a boot with no IDE disk at all must still succeed.
pub fn init() {
    const LABELS: [&str; 4] = ["primary master", "primary slave", "secondary master", "secondary slave"];
    for (i, (channel, drive)) in POSITIONS.into_iter().enumerate() {
        match identify(channel, drive) {
            Identified::Ata { sectors, lba48, model } => {
                serial_println!(
                    "[boot] ata: {}: {} MiB{}, \"{}\"",
                    LABELS[i],
                    sectors / 2048,
                    if lba48 { ", LBA48" } else { "" },
                    model
                );
                let d = info(channel, drive);
                d.sectors.store(sectors, Ordering::Relaxed);
                d.lba48.store(lba48, Ordering::Relaxed);
                d.present.store(true, Ordering::Relaxed);
                MODELS.lock()[i] = Some(model);
            }
            Identified::Atapi { model } => {
                serial_println!("[boot] ata: {}: ATAPI, \"{}\"", LABELS[i], model);
                info(channel, drive).atapi.store(true, Ordering::Relaxed);
                MODELS.lock()[i] = Some(model);
            }
            Identified::Nothing => {
                serial_println!("[boot] ata: {} not present", LABELS[i]);
            }
        }
    }
}

/// Whether an ATA disk at `channel`/`drive` answered `IDENTIFY` at boot.
pub fn present(channel: Channel, drive: Drive) -> bool {
    info(channel, drive).present.load(Ordering::Relaxed)
}

/// Whether an ATAPI (optical) drive at `channel`/`drive` answered at boot.
pub fn atapi_present(channel: Channel, drive: Drive) -> bool {
    info(channel, drive).atapi.load(Ordering::Relaxed)
}

/// The disk's size in 512-byte sectors (`0` for none).
pub fn capacity_sectors(channel: Channel, drive: Drive) -> u64 {
    info(channel, drive).sectors.load(Ordering::Relaxed)
}

/// The disk's model string, as it reported it.
pub fn model(channel: Channel, drive: Drive) -> String {
    MODELS.lock()[position(channel, drive)].clone().unwrap_or_default()
}

/// Blocks per command: `31 * 8 = 248` sectors, under the 255-per-command ceiling (`0` meaning
/// 256 is never used), and the size of each channel's DMA bounce buffer.
const MAX_BLOCKS_PER_COMMAND: u64 = 31;

/// Reads the disk's sectors from `lba` into `buf` (a whole number of 512-byte sectors), one
/// command per `MAX_BLOCKS_PER_COMMAND` blocks' worth -- the per-command overhead (drive select,
/// status polling) is fixed, so fewer, larger commands are faster. Bounded by the disk's size.
pub fn read_disk_sectors(channel: Channel, drive: Drive, lba: u64, buf: &mut [u8]) -> Result<(), AtaError> {
    check_range(channel, drive, lba, buf.len())?;
    let per_command = (MAX_BLOCKS_PER_COMMAND * 8) as usize;
    for (i, chunk) in buf.chunks_mut(per_command * 512).enumerate() {
        let at = lba + (i * per_command) as u64;
        let sectors = (chunk.len() / 512) as u8;
        read_sectors(channel, drive, at, sectors, chunk)?;
    }
    Ok(())
}

/// Writes the disk's sectors at `lba` from `buf` (whole sectors), then one `CACHE FLUSH`, all
/// under the channel's lock.
pub fn write_disk_sectors(channel: Channel, drive: Drive, lba: u64, buf: &[u8]) -> Result<(), AtaError> {
    check_range(channel, drive, lba, buf.len())?;
    let guard = CHANNELS[channel_index(channel)].lock();
    let per_command = (MAX_BLOCKS_PER_COMMAND * 8) as usize;
    for (i, chunk) in buf.chunks(per_command * 512).enumerate() {
        let at = lba + (i * per_command) as u64;
        let sectors = (chunk.len() / 512) as u8;
        write_sectors_unflushed(guard.as_ref(), channel, drive, at, sectors, chunk)?;
    }
    cache_flush(channel, drive)
}

fn check_range(channel: Channel, drive: Drive, lba: u64, len: usize) -> Result<(), AtaError> {
    let end = lba.checked_add(len as u64 / 512).ok_or(AtaError::OutOfRange)?;
    if !present(channel, drive) || end > capacity_sectors(channel, drive) {
        return Err(AtaError::OutOfRange);
    }
    Ok(())
}

// --- ATAPI ------------------------------------------------------------------------------------

/// A CD's sector size.
pub const CD_SECTOR: usize = 2048;
/// Sectors per `READ(10)`, and the byte count limit of one data block: 31 * 2048 = 63488, under
/// the register pair's 65534.
const ATAPI_MAX_SECTORS: usize = 31;
/// A packet command's budget: a drive spinning a disc up takes seconds.
const ATAPI_TIMEOUT_MS: u64 = 10_000;
/// How long `atapi_capacity` waits for a drive whose disc is "becoming ready".
const ATAPI_READY_MS: u64 = 8_000;

const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_REQUEST_SENSE: u8 = 0x03;
const SCSI_PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;

const SENSE_NOT_READY: u8 = 0x02;
const SENSE_UNIT_ATTENTION: u8 = 0x06;
/// Additional sense code "medium not present".
const ASC_NO_MEDIUM: u8 = 0x3A;

/// Polls the status until `BSY` clears, bounded by `ms`.
fn wait_not_busy(io_base: u16, ms: u64) -> Result<u8, AtaError> {
    let deadline = crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(ms);
    loop {
        let status = read_status(io_base);
        if status == 0xFF {
            return Err(AtaError::NoDevice);
        }
        if status & STATUS_BSY == 0 {
            return Ok(status);
        }
        if crate::cpu::tsc::now() >= deadline {
            return Err(AtaError::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// Sends `cdb` to the packet device at `channel`/`drive` and reads what it returns into `data`
/// (at most `data.len()` bytes; any more is drained and dropped), by PIO, the channel's lock held
/// by the caller. The bytes read, or the sense of a failed command.
fn packet_locked(channel: Channel, drive: Drive, cdb: &[u8; 12], data: &mut [u8]) -> Result<usize, AtaError> {
    let p = ports(channel);
    select(&p, drive, 0xA0);
    wait_not_busy(p.io_base, ATAPI_TIMEOUT_MS)?;
    let limit = (ATAPI_MAX_SECTORS * CD_SECTOR) as u16;
    unsafe {
        Port::<u8>::new(p.io_base + REG_ERROR_FEATURES).write(0); // PIO, no overlap
        Port::<u8>::new(p.io_base + REG_LBA_MID).write(limit as u8);
        Port::<u8>::new(p.io_base + REG_LBA_HIGH).write((limit >> 8) as u8);
    }
    command(channel, CMD_PACKET);
    let status = wait_not_busy(p.io_base, ATAPI_TIMEOUT_MS)?;
    if status & STATUS_ERR != 0 {
        return Err(sense_from_error(&p));
    }
    if status & STATUS_DRQ == 0 {
        return Err(AtaError::DeviceError(status));
    }
    // SAFETY: the drive asked for the packet (DRQ); a 12-byte CDB is six words.
    unsafe { outsw(p.io_base + REG_DATA, cdb.as_ptr(), 6) };
    let mut done = 0;
    loop {
        // 400 ns before the status means anything.
        for _ in 0..4 {
            unsafe { Port::<u8>::new(p.control).read() };
        }
        let status = wait_not_busy(p.io_base, ATAPI_TIMEOUT_MS)?;
        if status & STATUS_ERR != 0 {
            return Err(sense_from_error(&p));
        }
        if status & STATUS_DRQ == 0 {
            return Ok(done);
        }
        let count = unsafe {
            Port::<u8>::new(p.io_base + REG_LBA_MID).read() as usize
                | (Port::<u8>::new(p.io_base + REG_LBA_HIGH).read() as usize) << 8
        };
        let words = count.div_ceil(2);
        let take = words.min((data.len() - done) / 2);
        // SAFETY: the drive has `count` bytes ready; `take` words fit in `data`.
        unsafe { insw(p.io_base + REG_DATA, data[done..].as_mut_ptr(), take) };
        for _ in take..words {
            unsafe { Port::<u16>::new(p.io_base + REG_DATA).read() };
        }
        done += take * 2;
    }
}

/// The sense key a failed packet command left in the error register's high nibble (no ASC: the
/// caller asks `REQUEST SENSE` when it needs one).
fn sense_from_error(p: &ChannelPorts) -> AtaError {
    let error = unsafe { Port::<u8>::new(p.io_base + REG_ERROR_FEATURES).read() };
    AtaError::Sense(error >> 4, 0, 0)
}

/// `packet_locked` under the channel's lock; a failed command's sense filled in by `REQUEST
/// SENSE`.
fn packet(channel: Channel, drive: Drive, cdb: &[u8; 12], data: &mut [u8]) -> Result<usize, AtaError> {
    let _guard = CHANNELS[channel_index(channel)].lock();
    match packet_locked(channel, drive, cdb, data) {
        Err(AtaError::Sense(key, _, _)) => {
            let mut sense = [0u8; 18];
            let cdb = [SCSI_REQUEST_SENSE, 0, 0, 0, sense.len() as u8, 0, 0, 0, 0, 0, 0, 0];
            match packet_locked(channel, drive, &cdb, &mut sense) {
                Ok(n) if n >= 14 => Err(AtaError::Sense(sense[2] & 0x0F, sense[12], sense[13])),
                _ => Err(AtaError::Sense(key, 0, 0)),
            }
        }
        other => other,
    }
}

/// Whether a disc is in the drive and readable, and if so its size: `(sectors, sector size)` from
/// `READ CAPACITY(10)`; and whether the drive reported a unit attention (the disc changed, or the
/// drive was reset) since it was last asked. Waits out a disc spinning up; `None` at once for an
/// empty drive.
pub fn atapi_capacity(channel: Channel, drive: Drive) -> (Option<(u64, u32)>, bool) {
    let deadline = crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(ATAPI_READY_MS);
    let mut changed = false;
    loop {
        match packet(channel, drive, &[SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut []) {
            Ok(_) => break,
            Err(AtaError::Sense(SENSE_UNIT_ATTENTION, _, _)) if crate::cpu::tsc::now() < deadline => changed = true,
            Err(AtaError::Sense(SENSE_NOT_READY, ASC_NO_MEDIUM, _)) => return (None, changed),
            Err(AtaError::Sense(SENSE_NOT_READY, _, _)) if crate::cpu::tsc::now() < deadline => {
                core::hint::spin_loop();
            }
            Err(_) => return (None, changed),
        }
    }
    let mut cap = [0u8; 8];
    let cdb = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    match packet(channel, drive, &cdb, &mut cap) {
        Ok(8) => {}
        _ => return (None, changed),
    }
    let last = u32::from_be_bytes(cap[0..4].try_into().unwrap()) as u64;
    let size = u32::from_be_bytes(cap[4..8].try_into().unwrap());
    // Some drives report 2352 (raw) or 0 for a data disc; READ(10) moves 2048-byte sectors.
    // A sector size other than 512's multiples up to 2048 isn't a data disc's.
    let size = if size == 0 || size > CD_SECTOR as u32 || size % 512 != 0 { CD_SECTOR as u32 } else { size };
    (Some((last + 1, size)), changed)
}

/// Reads whole 2048-byte sectors from `lba` into `buf`, one `READ(10)` per `ATAPI_MAX_SECTORS`.
pub fn atapi_read(channel: Channel, drive: Drive, lba: u64, buf: &mut [u8]) -> Result<(), AtaError> {
    for (i, chunk) in buf.chunks_mut(ATAPI_MAX_SECTORS * CD_SECTOR).enumerate() {
        let at = lba + (i * ATAPI_MAX_SECTORS) as u64;
        let count = (chunk.len() / CD_SECTOR) as u16;
        let at32 = u32::try_from(at).map_err(|_| AtaError::OutOfRange)?;
        let a = at32.to_be_bytes();
        let c = count.to_be_bytes();
        let cdb = [SCSI_READ_10, 0, a[0], a[1], a[2], a[3], 0, c[0], c[1], 0, 0, 0];
        if packet(channel, drive, &cdb, chunk)? != chunk.len() {
            return Err(AtaError::DeviceError(0));
        }
    }
    Ok(())
}

/// Locks (`true`) or unlocks the drive's tray: a mounted disc can't be ejected from the drive.
pub fn atapi_lock(channel: Channel, drive: Drive, lock: bool) {
    let cdb = [SCSI_PREVENT_ALLOW_MEDIUM_REMOVAL, 0, 0, 0, lock as u8, 0, 0, 0, 0, 0, 0, 0];
    let _ = packet(channel, drive, &cdb, &mut []);
}

// --- bus-master DMA --------------------------------------------------------------------------

const BM_COMMAND: u16 = 0;
const BM_STATUS: u16 = 2;
const BM_PRDT: u16 = 4;
const BM_CMD_START: u8 = 1 << 0;
/// Direction: the controller writes memory (a disk read).
const BM_CMD_TO_MEMORY: u8 = 1 << 3;
const BM_STATUS_ERROR: u8 = 1 << 1;
const BM_STATUS_INTERRUPT: u8 = 1 << 2;
/// Physical Region Descriptors must not cross a 64 KiB boundary.
const PRD_BOUNDARY: u64 = 0x1_0000;
const PRD_END_OF_TABLE: u32 = 1 << 31;

struct BusMaster {
    /// The channel's bus-master register block.
    base: u16,
    prdt: crate::drivers::dma::DmaBuffer,
    buffer: crate::drivers::dma::DmaBuffer,
}

/// Each channel's lock, held for every command on it, and its bus master once `init_dma` set one
/// up.
static CHANNELS: [Mutex<Option<BusMaster>>; 2] = [const { Mutex::new(None) }; 2];
/// Each channel's bus-master register block, for its IRQ handler (which can't take `CHANNELS`: it
/// may interrupt a holder). `0` until `init_dma` succeeds.
static BM_BASE: [AtomicU16; 2] = [const { AtomicU16::new(0) }; 2];
/// Set by a channel's IRQ handler when it raised its interrupt; cleared before each transfer.
static DMA_IRQ_SEEN: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
static DMA_TRANSFERS: AtomicU64 = AtomicU64::new(0);
static DMA_IRQS: AtomicU64 = AtomicU64::new(0);

/// `(transfers, completion interrupts)` by DMA so far, both channels -- how much the interrupt
/// path is used.
pub fn dma_stats() -> (u64, u64) {
    (DMA_TRANSFERS.load(Ordering::Relaxed), DMA_IRQS.load(Ordering::Relaxed))
}

fn bm_read_status(base: u16) -> u8 {
    unsafe { Port::<u8>::new(base + BM_STATUS).read() }
}

/// Clears the status register's write-1-to-clear error and interrupt bits, keeping the rest.
fn bm_clear_status(base: u16) {
    let status = bm_read_status(base);
    unsafe { Port::<u8>::new(base + BM_STATUS).write(status | BM_STATUS_ERROR | BM_STATUS_INTERRUPT) };
}

/// A channel's IRQ: it finished a DMA transfer (or a PIO command raised `INTRQ`). Reads the drive's
/// status register, which acknowledges `INTRQ`, and clears the bus-master interrupt bit, so the
/// line drops before EOI.
fn channel_irq(channel: Channel) {
    let i = channel_index(channel);
    let io_base = ports(channel).io_base;
    let base = BM_BASE[i].load(Ordering::Relaxed);
    if base == 0 {
        let _ = read_status(io_base);
        return;
    }
    if bm_read_status(base) & BM_STATUS_INTERRUPT != 0 {
        let _ = read_status(io_base);
        bm_clear_status(base);
        DMA_IRQ_SEEN[i].store(true, Ordering::Release);
        DMA_IRQS.fetch_add(1, Ordering::Relaxed);
        crate::drivers::dma::wake_disk_waiters(&mut crate::process::table().lock());
    }
}

fn primary_irq_handler() {
    channel_irq(Channel::Primary);
}

fn secondary_irq_handler() {
    channel_irq(Channel::Secondary);
}

/// Sets up bus-master DMA on each channel with a disk, if the IDE controller is a PCI bus master
/// and DMA buffers below 4 GiB can be had. Call after `init`. Logged either way; a channel without
/// it keeps using PIO.
pub fn init_dma(
    frame_allocator: &mut impl x86_64::structures::paging::FrameAllocator<x86_64::structures::paging::Size4KiB>,
    phys_mem_offset: x86_64::VirtAddr,
) {
    use crate::drivers::dma::DmaBuffer;
    let used = |channel| present(channel, Drive::Master) || present(channel, Drive::Slave);
    if !used(Channel::Primary) && !used(Channel::Secondary) {
        return;
    }
    // Mass storage (0x01), IDE (0x01); prog-if bit 7: bus-master capable.
    let Some(ide) = crate::drivers::pci::find_by_class(0x01, 0x01) else {
        serial_println!("[boot] ata: no PCI IDE controller -- disks use PIO");
        return;
    };
    let Some(bar4) = ide.io_bar(4).filter(|_| ide.prog_if & 0x80 != 0) else {
        serial_println!("[boot] ata: IDE controller isn't a bus master -- disks use PIO");
        return;
    };
    ide.enable_bus_mastering();
    for channel in [Channel::Primary, Channel::Secondary] {
        if !used(channel) {
            continue;
        }
        let p = ports(channel);
        let prdt = DmaBuffer::alloc(frame_allocator, phys_mem_offset, 1, true);
        let buffer = DmaBuffer::alloc(frame_allocator, phys_mem_offset, MAX_BLOCKS_PER_COMMAND as usize, true);
        let (Some(prdt), Some(buffer)) = (prdt, buffer) else {
            serial_println!("[boot] ata: no DMA buffer below 4 GiB -- {:?} channel uses PIO", channel);
            continue;
        };
        let base = bar4 + p.bm_offset;

        // The Physical Region Descriptor table for the whole bounce buffer, split at 64 KiB
        // boundaries. A transfer shorter than the buffer ends early; the controller stops at the
        // drive's byte count, not the table's.
        let entries = prdt.as_mut_ptr::<u32>();
        let mut addr = buffer.phys.as_u64();
        let end = addr + buffer.len as u64;
        let mut i = 0;
        while addr < end {
            let len = (PRD_BOUNDARY - addr % PRD_BOUNDARY).min(end - addr);
            let last = addr + len == end;
            // SAFETY: a few entries in a zeroed 4 KiB table this driver owns.
            unsafe {
                entries.add(i * 2).write_volatile(addr as u32);
                entries.add(i * 2 + 1).write_volatile((len as u32 & 0xFFFF) | if last { PRD_END_OF_TABLE } else { 0 });
            }
            addr += len;
            i += 1;
        }

        unsafe {
            Port::<u8>::new(base + BM_COMMAND).write(0);
            Port::<u32>::new(base + BM_PRDT).write(prdt.phys.as_u64() as u32);
            // nIEN clear: the drive raises INTRQ when a command completes.
            Port::<u8>::new(p.control).write(0);
        }
        bm_clear_status(base);
        *CHANNELS[channel_index(channel)].lock() = Some(BusMaster { base, prdt, buffer });
        let handler: fn() = if channel == Channel::Primary { primary_irq_handler } else { secondary_irq_handler };
        x86_64::instructions::interrupts::without_interrupts(|| {
            crate::cpu::interrupts::register_irq_handler(p.irq, handler);
            BM_BASE[channel_index(channel)].store(base, Ordering::Release);
            // SAFETY: the handler is registered just above.
            unsafe { crate::cpu::pic::unmask_irq(p.irq) };
        });
        serial_println!(
            "[boot] ata: bus-master DMA on {:02x}:{:02x}.{}, {:?} channel (registers {:#06x}, IRQ {})",
            ide.bus,
            ide.device,
            ide.function,
            channel,
            base,
            p.irq
        );
    }
}

enum Direction<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

/// One DMA command on `channel`/`drive` through the channel's bounce buffer, its lock held by the
/// caller.
fn dma_transfer(bm: &BusMaster, channel: Channel, drive: Drive, lba: u64, sector_count: u8, dir: Direction) -> Result<(), AtaError> {
    let len = sector_count as usize * 512;
    assert!(len <= bm.buffer.len);
    let to_memory = matches!(dir, Direction::Read(_));
    if let Direction::Write(src) = &dir {
        // SAFETY: the controller is idle between transfers.
        unsafe { bm.buffer.slice_mut(0, len) }.copy_from_slice(&src[..len]);
    }

    let i = channel_index(channel);
    let io_base = ports(channel).io_base;
    let ext = setup_command(channel, drive, lba, sector_count)?;
    unsafe {
        Port::<u8>::new(bm.base + BM_COMMAND).write(if to_memory { BM_CMD_TO_MEMORY } else { 0 });
        Port::<u32>::new(bm.base + BM_PRDT).write(bm.prdt.phys.as_u64() as u32);
    }
    bm_clear_status(bm.base);
    DMA_IRQ_SEEN[i].store(false, Ordering::Release);
    let cmd = match (to_memory, ext) {
        (true, false) => CMD_READ_DMA,
        (true, true) => CMD_READ_DMA_EXT,
        (false, false) => CMD_WRITE_DMA,
        (false, true) => CMD_WRITE_DMA_EXT,
    };
    command(channel, cmd);
    unsafe {
        Port::<u8>::new(bm.base + BM_COMMAND).write(BM_CMD_START | if to_memory { BM_CMD_TO_MEMORY } else { 0 });
    }

    // Done once the drive raised its interrupt: seen by the IRQ handler, or still set in the
    // bus-master status when interrupts are masked.
    let base = bm.base;
    let finished = crate::drivers::dma::wait_for_disk(TIMEOUT_MS, || {
        DMA_IRQ_SEEN[i].load(Ordering::Acquire) || bm_read_status(base) & (BM_STATUS_INTERRUPT | BM_STATUS_ERROR) != 0
    });
    let bm_status = bm_read_status(base);
    unsafe { Port::<u8>::new(base + BM_COMMAND).write(0) };
    let status = wait_while_busy(io_base)?; // also acknowledges INTRQ
    bm_clear_status(base);
    DMA_TRANSFERS.fetch_add(1, Ordering::Relaxed);
    if !finished {
        return Err(AtaError::Timeout);
    }
    if bm_status & BM_STATUS_ERROR != 0 || status & (STATUS_ERR | STATUS_DF) != 0 {
        return Err(AtaError::DeviceError(status));
    }
    if let Direction::Read(dst) = dir {
        // SAFETY: the transfer is over.
        dst[..len].copy_from_slice(unsafe { bm.buffer.slice_mut(0, len) });
    }
    Ok(())
}
