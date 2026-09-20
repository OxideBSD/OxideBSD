//! A minimal ATA PIO (Programmable I/O) disk driver -- classic legacy IDE, LBA28, polling only,
//! no IRQ. See <https://wiki.osdev.org/ATA_PIO_Mode>. This kernel's first real block device.
//!
//! **Polling, not IRQ-driven, deliberately.** PIO is inherently synchronous and CPU-driven (the
//! CPU itself shuttles every word across the data port -- there's no DMA to wait on), and this
//! code must be safely callable from inside a real syscall handler with `RFLAGS::INTERRUPT_FLAG`
//! masked (oxfs's write-through persistence runs on every file write). Any wait here uses
//! `core::hint::spin_loop()` against a `crate::tsc`-based deadline, never `hlt()` -- see
//! `src/tsc.rs`'s own doc comment for why a tick-based wait can never elapse inside a syscall, and
//! CLAUDE.md's "Real networking" section for the `hlt()`-in-syscall freeze this exact mistake
//! caused there.
//!
//! **Legacy fixed ports, no PCI probing.** QEMU's default `i440fx` machine type's PIIX3 IDE
//! controller (and every real PC chipset before it) exposes the primary/secondary channels at
//! fixed, well-known port ranges regardless of PCI enumeration -- 0x1F0-0x1F7/0x3F6 (primary,
//! IRQ14) and 0x170-0x177/0x376 (secondary, IRQ15). Unlike `rtl8139`, there's nothing to discover.
//!
//! **One fixed target: secondary channel, master.** `bootimage` always attaches this kernel's own
//! boot image as `-drive format=raw,file=<image>` with no explicit `if=`, which QEMU resolves to
//! the *primary* IDE master by default -- so the block API below (`oxidebsd_block_*`) targets the
//! secondary channel's master drive specifically, to guarantee it can never be the same device the
//! kernel itself booted from. See `Cargo.toml`'s `run-args`/`test-args` for the matching
//! `-device ide-hd,bus=ide.1,unit=0` pinning.

use core::sync::atomic::{AtomicBool, Ordering};

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
}

/// Only `io_base` is used -- polling reads the regular status register (`io_base + 7`), never the
/// alt-status/device-control register at each channel's separate control-base address (0x3F6
/// primary / 0x376 secondary), so there's nothing here to read/write there. Reading the regular
/// status register does have the side effect of acknowledging a pending IRQ, which would matter to
/// an IRQ-driven driver -- irrelevant here since this driver never unmasks IRQ14/15 in the first
/// place (see this module's own doc comment on why polling, not IRQs).
struct ChannelPorts {
    io_base: u16,
}

const PRIMARY: ChannelPorts = ChannelPorts { io_base: 0x1F0 };
const SECONDARY: ChannelPorts = ChannelPorts { io_base: 0x170 };

fn ports(channel: Channel) -> ChannelPorts {
    match channel {
        Channel::Primary => PRIMARY,
        Channel::Secondary => SECONDARY,
    }
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
const CMD_WRITE_SECTORS: u8 = 0x30;
const CMD_CACHE_FLUSH: u8 = 0xE7;
const CMD_IDENTIFY: u8 = 0xEC;

/// Generous but bounded -- real/emulated PIO commands complete in microseconds to low
/// milliseconds; this only guards against a genuinely stuck or absent device, not real timing.
const TIMEOUT_MS: u64 = 3000;

/// The one channel/drive `oxidebsd_block_read`/`_write` target -- see this module's own doc
/// comment for why secondary/master specifically.
const DATA_DISK_CHANNEL: Channel = Channel::Secondary;
const DATA_DISK_DRIVE: Drive = Drive::Master;

/// Set by `init()` once, read by `oxidebsd_block_device_present` -- whether the one fixed
/// channel/drive this driver's block API targets actually responded to `IDENTIFY` at boot.
static DATA_DISK_PRESENT: AtomicBool = AtomicBool::new(false);

fn read_status(io_base: u16) -> u8 {
    unsafe { Port::<u8>::new(io_base + REG_STATUS_COMMAND).read() }
}

/// Polls until `BSY` clears, bounded by `TIMEOUT_MS`. The status byte the loop stopped on is
/// discarded by every caller here, but returning it costs nothing and matches the shape a future
/// caller checking `DF`/`ERR` after a command completes might want.
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

/// Selects a drive for an LBA28 command, addressing the top 4 LBA bits via the drive/head
/// register's own low nibble (the classic LBA28 encoding this whole driver uses).
fn select_drive_lba28(io_base: u16, drive: Drive, lba: u32) {
    let drive_bit: u8 = match drive {
        Drive::Master => 0xE0,
        Drive::Slave => 0xF0,
    };
    let head = drive_bit | (((lba >> 24) & 0x0F) as u8);
    unsafe {
        Port::<u8>::new(io_base + REG_DRIVE_HEAD).write(head);
    }
}

fn setup_lba28(io_base: u16, lba: u32, sector_count: u8) {
    unsafe {
        Port::<u8>::new(io_base + REG_SECTOR_COUNT).write(sector_count);
        Port::<u8>::new(io_base + REG_LBA_LOW).write((lba & 0xFF) as u8);
        Port::<u8>::new(io_base + REG_LBA_MID).write(((lba >> 8) & 0xFF) as u8);
        Port::<u8>::new(io_base + REG_LBA_HIGH).write(((lba >> 16) & 0xFF) as u8);
    }
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

/// Reads `sector_count` consecutive 512-byte sectors starting at `lba` (LBA28) from
/// `channel`/`drive` into `buf` (must be exactly `sector_count as usize * 512` bytes) in a single
/// command -- the drive command/LBA setup and busy-wait happen once, not once per sector (only the
/// per-sector `DRQ` wait is inherent to the ATA protocol and can't be batched away). `sector_count`
/// `0` addresses 256 sectors on real hardware (unused by this driver's own callers, which never
/// batch past 8).
pub fn read_sectors(
    channel: Channel,
    drive: Drive,
    lba: u32,
    sector_count: u8,
    buf: &mut [u8],
) -> Result<(), AtaError> {
    debug_assert_eq!(buf.len(), sector_count as usize * 512);
    let p = ports(channel);
    select_drive_lba28(p.io_base, drive, lba);
    wait_while_busy(p.io_base)?;
    setup_lba28(p.io_base, lba, sector_count);
    unsafe {
        Port::<u8>::new(p.io_base + REG_STATUS_COMMAND).write(CMD_READ_SECTORS);
    }
    for sector in 0..sector_count as usize {
        wait_for_data(p.io_base)?;
        let sector_buf = &mut buf[sector * 512..(sector + 1) * 512];
        unsafe {
            insw(p.io_base + REG_DATA, sector_buf.as_mut_ptr(), 256);
        }
    }
    Ok(())
}

/// Writes `sector_count` consecutive 512-byte sectors starting at `lba` (LBA28) to
/// `channel`/`drive` from `buf`, followed by a single real `CACHE FLUSH` covering the whole batch
/// (not one per sector) so every sector in it is durable in the backing image before this returns
/// -- otherwise QEMU's own write-back caching could reorder a write past a later read of the same
/// sector via a different code path. Same one-command/one-flush-for-the-whole-batch reasoning as
/// `read_sectors`.
pub fn write_sectors(
    channel: Channel,
    drive: Drive,
    lba: u32,
    sector_count: u8,
    buf: &[u8],
) -> Result<(), AtaError> {
    debug_assert_eq!(buf.len(), sector_count as usize * 512);
    let p = ports(channel);
    select_drive_lba28(p.io_base, drive, lba);
    wait_while_busy(p.io_base)?;
    setup_lba28(p.io_base, lba, sector_count);
    unsafe {
        Port::<u8>::new(p.io_base + REG_STATUS_COMMAND).write(CMD_WRITE_SECTORS);
    }
    for sector in 0..sector_count as usize {
        wait_for_data(p.io_base)?;
        let sector_buf = &buf[sector * 512..(sector + 1) * 512];
        unsafe {
            outsw(p.io_base + REG_DATA, sector_buf.as_ptr(), 256);
        }
    }

    unsafe {
        Port::<u8>::new(p.io_base + REG_STATUS_COMMAND).write(CMD_CACHE_FLUSH);
    }
    // `wait_while_busy` only waits for BSY to clear -- it doesn't check ERR/DF (unlike
    // `wait_for_data`, which does), so a real flush failure the drive reports once BSY clears
    // used to be silently treated as success: this write-through persistence path (and everything
    // above it, up through oxfs's own commit logic) would believe a block reached stable storage
    // when the hardware actually reported otherwise.
    let status = wait_while_busy(p.io_base)?;
    if status & (STATUS_ERR | STATUS_DF) != 0 {
        return Err(AtaError::DeviceError(status));
    }
    Ok(())
}

/// Reads one 512-byte sector at `lba` (LBA28) from `channel`/`drive`. A thin `read_sectors(...,
/// 1, ...)` wrapper kept for callers that only ever want one sector at a time (`tests/ata_smoke.rs`).
pub fn read_sector(
    channel: Channel,
    drive: Drive,
    lba: u32,
    buf: &mut [u8; 512],
) -> Result<(), AtaError> {
    read_sectors(channel, drive, lba, 1, buf)
}

/// Writes one 512-byte sector at `lba` (LBA28) to `channel`/`drive`. A thin `write_sectors(..., 1,
/// ...)` wrapper kept for callers that only ever want one sector at a time.
pub fn write_sector(
    channel: Channel,
    drive: Drive,
    lba: u32,
    buf: &[u8; 512],
) -> Result<(), AtaError> {
    write_sectors(channel, drive, lba, 1, buf)
}

/// Issues `IDENTIFY` against `channel`/`drive` and reports whether a real ATA drive answered.
/// Drains (but doesn't interpret) the 256-word IDENTIFY payload on success -- this driver doesn't
/// need any of it yet, but the data port must be emptied to leave the channel clean for the next
/// command.
fn identify(channel: Channel, drive: Drive) -> bool {
    let p = ports(channel);
    let select: u8 = match drive {
        Drive::Master => 0xA0,
        Drive::Slave => 0xB0,
    };
    unsafe {
        Port::<u8>::new(p.io_base + REG_DRIVE_HEAD).write(select);
        Port::<u8>::new(p.io_base + REG_SECTOR_COUNT).write(0);
        Port::<u8>::new(p.io_base + REG_LBA_LOW).write(0);
        Port::<u8>::new(p.io_base + REG_LBA_MID).write(0);
        Port::<u8>::new(p.io_base + REG_LBA_HIGH).write(0);
    }

    if read_status(p.io_base) == 0 {
        // Nothing at all wired up at this channel/drive -- the common, expected case for three
        // of the four combos probed at boot.
        return false;
    }

    unsafe {
        Port::<u8>::new(p.io_base + REG_STATUS_COMMAND).write(CMD_IDENTIFY);
    }

    match wait_for_data(p.io_base) {
        Ok(()) => {
            let mut data_port: Port<u16> = Port::new(p.io_base + REG_DATA);
            for _ in 0..256 {
                unsafe {
                    let _ = data_port.read();
                }
            }
            true
        }
        Err(_) => false,
    }
}

/// Probes all four legacy channel/drive combinations via `IDENTIFY`, logging each. Never panics on
/// absence -- a boot with no attached disk (most `cargo test` runs) must still succeed, oxfs simply
/// falls back to its original pure-in-memory behavior (see `oxidebsd_block_device_present`).
pub fn init() {
    const COMBOS: [(Channel, Drive, &str); 4] = [
        (Channel::Primary, Drive::Master, "primary master"),
        (Channel::Primary, Drive::Slave, "primary slave"),
        (Channel::Secondary, Drive::Master, "secondary master"),
        (Channel::Secondary, Drive::Slave, "secondary slave"),
    ];
    for (channel, drive, label) in COMBOS {
        if identify(channel, drive) {
            serial_println!("[boot] ata: {} present", label);
            if channel == DATA_DISK_CHANNEL && drive == DATA_DISK_DRIVE {
                DATA_DISK_PRESENT.store(true, Ordering::Relaxed);
            }
        } else {
            serial_println!("[boot] ata: {} not present", label);
        }
    }
    if !DATA_DISK_PRESENT.load(Ordering::Relaxed) {
        serial_println!(
            "[boot] ata: no data disk attached at {:?}/{:?} -- oxfs will run in-memory only this boot",
            DATA_DISK_CHANNEL,
            DATA_DISK_DRIVE
        );
    }
}

/// Whether the data disk (`oxidebsd_block_read`/`_write`'s fixed target) is present this boot.
/// Exported to modules -- see `src/module.rs`'s `resolve_external_symbol`. `0`/`1`, not
/// `bool`/`Result`: matches every other `oxidebsd_*` module-boundary function's plain-integer
/// convention (modules have no `alloc`, so richer return types can't cross this boundary).
pub extern "C" fn oxidebsd_block_device_present() -> i64 {
    if DATA_DISK_PRESENT.load(Ordering::Relaxed) {
        1
    } else {
        0
    }
}

/// Reads oxfs block `block_no` (4096 bytes) into `buf_ptr` as a single real 8-sector `READ
/// SECTORS` command (see `read_sectors`'s own doc comment for why this beats 8 separate
/// single-sector commands) against the fixed data-disk channel/drive. `-1` on any failure (no
/// device, timeout, device error) or if no data disk is attached at all; `0` on success. `buf_ptr`
/// is a raw pointer into the calling module's own memory (a `static mut` block buffer, in oxfs's
/// case, always exactly `BLOCK_SIZE = 4096` bytes) -- modules have no `alloc`, so this is the same
/// `ptr`+implicit-fixed-length convention every other `oxidebsd_*` bulk-data function here already
/// uses.
pub extern "C" fn oxidebsd_block_read(block_no: u64, buf_ptr: u64) -> i64 {
    if !DATA_DISK_PRESENT.load(Ordering::Relaxed) {
        return -1;
    }
    let base_lba = (block_no * 8) as u32;
    // SAFETY: caller (oxfs) always passes a pointer to a live 4096-byte `static mut` block buffer.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 4096) };
    match read_sectors(DATA_DISK_CHANNEL, DATA_DISK_DRIVE, base_lba, 8, buf) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Writes oxfs block `block_no` (4096 bytes) from `buf_ptr` to disk as a single real 8-sector
/// `WRITE SECTORS` command with one `CACHE FLUSH` covering the whole block (see `write_sectors`'s
/// own doc comment) against the fixed data-disk channel/drive. Same `-1`/`0` and `buf_ptr`
/// conventions as `oxidebsd_block_read`.
pub extern "C" fn oxidebsd_block_write(block_no: u64, buf_ptr: u64) -> i64 {
    if !DATA_DISK_PRESENT.load(Ordering::Relaxed) {
        return -1;
    }
    let base_lba = (block_no * 8) as u32;
    // SAFETY: caller (oxfs) always passes a pointer to a live 4096-byte block buffer.
    let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, 4096) };
    match write_sectors(DATA_DISK_CHANNEL, DATA_DISK_DRIVE, base_lba, 8, buf) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Blocks per `read_sectors`/`write_sectors` command `oxidebsd_block_{read,write}_batch` chunk
/// their transfer into -- `31 * 8 = 248` sectors, comfortably under LBA28's 255-sector-per-command
/// ceiling (`sector_count: u8`, where `0` means 256 -- deliberately never hit, avoids that special
/// case entirely) while still batching almost the maximum a single command can carry.
const MAX_BLOCKS_PER_COMMAND: u64 = 31;

/// Real, multi-block counterpart to `oxidebsd_block_read` -- reads `count` *consecutive* oxfs
/// blocks starting at `start_block` into `buf_ptr` (`count * 4096` contiguous bytes) as one real
/// `READ SECTORS` command per `MAX_BLOCKS_PER_COMMAND`-sized chunk, rather than one command (and,
/// for the write side, one `CACHE FLUSH`) per individual 4 KiB block. Found live: `mount_from_disk`/
/// `flush_all_to_disk` calling the single-block API in a loop across tens of thousands of blocks
/// made a fresh-format-and-flush (or a full mount) measurably slow under QEMU's software TCG --
/// each real ATA command/flush has fixed per-command overhead (drive select, `BSY`/`DRQ` polling)
/// independent of how much data it carries, so batching directly cuts the number of commands (and,
/// for writes, flushes) by up to `MAX_BLOCKS_PER_COMMAND`x for any contiguous run. Same `-1`/`0`
/// and `buf_ptr` conventions as `oxidebsd_block_read`; a run's own contiguity is the caller's
/// responsibility (this function's own `block_no` space has no concept of "not really adjacent").
pub extern "C" fn oxidebsd_block_read_batch(start_block: u64, count: u64, buf_ptr: u64) -> i64 {
    if !DATA_DISK_PRESENT.load(Ordering::Relaxed) {
        return -1;
    }
    let mut remaining = count;
    let mut block = start_block;
    let mut offset: u64 = 0;
    while remaining > 0 {
        let chunk = remaining.min(MAX_BLOCKS_PER_COMMAND);
        let base_lba = (block * 8) as u32;
        let byte_len = (chunk * 4096) as usize;
        // SAFETY: caller guarantees buf_ptr points to `count * 4096` live, writable bytes.
        let buf = unsafe {
            core::slice::from_raw_parts_mut((buf_ptr + offset) as *mut u8, byte_len)
        };
        if read_sectors(
            DATA_DISK_CHANNEL,
            DATA_DISK_DRIVE,
            base_lba,
            (chunk * 8) as u8,
            buf,
        )
        .is_err()
        {
            return -1;
        }
        remaining -= chunk;
        block += chunk;
        offset += byte_len as u64;
    }
    0
}

/// Write counterpart to `oxidebsd_block_read_batch` -- see that function's own doc comment for the
/// real, measured problem this solves. Each `MAX_BLOCKS_PER_COMMAND`-sized chunk gets its own
/// single `CACHE FLUSH` (via `write_sectors`), not one per individual 4 KiB block.
pub extern "C" fn oxidebsd_block_write_batch(start_block: u64, count: u64, buf_ptr: u64) -> i64 {
    if !DATA_DISK_PRESENT.load(Ordering::Relaxed) {
        return -1;
    }
    let mut remaining = count;
    let mut block = start_block;
    let mut offset: u64 = 0;
    while remaining > 0 {
        let chunk = remaining.min(MAX_BLOCKS_PER_COMMAND);
        let base_lba = (block * 8) as u32;
        let byte_len = (chunk * 4096) as usize;
        // SAFETY: caller guarantees buf_ptr points to `count * 4096` live, readable bytes.
        let buf = unsafe { core::slice::from_raw_parts((buf_ptr + offset) as *const u8, byte_len) };
        if write_sectors(
            DATA_DISK_CHANNEL,
            DATA_DISK_DRIVE,
            base_lba,
            (chunk * 8) as u8,
            buf,
        )
        .is_err()
        {
            return -1;
        }
        remaining -= chunk;
        block += chunk;
        offset += byte_len as u64;
    }
    0
}
