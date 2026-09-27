//! A minimal legacy IDE disk driver: LBA28, PIO or bus-master DMA. See
//! <https://wiki.osdev.org/ATA_PIO_Mode> and <https://wiki.osdev.org/ATA/ATAPI_using_DMA>.
//!
//! **PIO is slow under virtualization.** Every word of a PIO transfer is an `outsw`/`insw`
//! through the data port, and each one traps to QEMU: a fresh oxfs format (~259 MiB) took ~17
//! minutes, with the guest's instruction pointer sampled inside `outsw` nearly every time. So
//! when the IDE controller is a PCI bus master (`init_dma`), the data disk's transfers go by DMA
//! through a bounce buffer below 4 GiB, finishing with IRQ 15 (`dma::wait_until`: `hlt` when
//! interrupts are enabled, polling inside syscalls). PIO remains the fallback, and serves the
//! other channel/drive combinations `tests/ata_smoke.rs` can name.
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

/// A channel's command block. Reading its status register (`io_base + 7`) acknowledges the
/// drive's pending `INTRQ`, which the DMA path's IRQ 15 handler relies on; only `init_dma` touches
/// the device control register (to clear `nIEN`).
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
const CMD_READ_DMA: u8 = 0xC8;
const CMD_WRITE_DMA: u8 = 0xCA;
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
fn pio_read_sectors(
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

/// Writes `sector_count` consecutive sectors at `lba` by PIO, without flushing (`write_sectors`
/// adds the `CACHE FLUSH`). Same one-command-for-the-batch shape as `pio_read_sectors`.
fn pio_write_sectors(
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

    wait_while_busy(p.io_base)?;
    Ok(())
}

/// `CACHE FLUSH`: everything written so far is durable in the backing image once this returns --
/// otherwise QEMU's write-back caching could reorder a write past a later read of the same sector
/// through another path. Checks `ERR`/`DF` once `BSY` clears (`wait_while_busy` alone doesn't),
/// so a flush the drive reports as failed isn't mistaken for success.
fn cache_flush(channel: Channel, drive: Drive) -> Result<(), AtaError> {
    let p = ports(channel);
    select_drive_lba28(p.io_base, drive, 0);
    wait_while_busy(p.io_base)?;
    unsafe {
        Port::<u8>::new(p.io_base + REG_STATUS_COMMAND).write(CMD_CACHE_FLUSH);
    }
    let status = wait_while_busy(p.io_base)?;
    if status & (STATUS_ERR | STATUS_DF) != 0 {
        return Err(AtaError::DeviceError(status));
    }
    Ok(())
}

/// Reads `sector_count` (1-255) sectors at `lba` into `buf` (`sector_count * 512` bytes): by DMA
/// when this is the data disk and `init_dma` succeeded, else by PIO.
pub fn read_sectors(
    channel: Channel,
    drive: Drive,
    lba: u32,
    sector_count: u8,
    buf: &mut [u8],
) -> Result<(), AtaError> {
    if (channel, drive) == (DATA_DISK_CHANNEL, DATA_DISK_DRIVE) && dma_ready() {
        return dma_transfer(lba, sector_count, Direction::Read(buf));
    }
    pio_read_sectors(channel, drive, lba, sector_count, buf)
}

/// Writes `sector_count` (1-255) sectors at `lba` from `buf`, then `CACHE FLUSH`es, so they're
/// durable when this returns. DMA or PIO as `read_sectors`.
pub fn write_sectors(
    channel: Channel,
    drive: Drive,
    lba: u32,
    sector_count: u8,
    buf: &[u8],
) -> Result<(), AtaError> {
    write_sectors_unflushed(channel, drive, lba, sector_count, buf)?;
    cache_flush(channel, drive)
}

fn write_sectors_unflushed(
    channel: Channel,
    drive: Drive,
    lba: u32,
    sector_count: u8,
    buf: &[u8],
) -> Result<(), AtaError> {
    if (channel, drive) == (DATA_DISK_CHANNEL, DATA_DISK_DRIVE) && dma_ready() {
        return dma_transfer(lba, sector_count, Direction::Write(buf));
    }
    pio_write_sectors(channel, drive, lba, sector_count, buf)
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

/// Whether the data disk (secondary master) answered `IDENTIFY` at boot.
pub fn present() -> bool {
    DATA_DISK_PRESENT.load(Ordering::Relaxed)
}

/// Blocks per command: `31 * 8 = 248` sectors, under LBA28's 255-per-command ceiling (`0`
/// meaning 256 is never used), and the size of the DMA bounce buffer.
const MAX_BLOCKS_PER_COMMAND: u64 = 31;

/// Reads `count` consecutive 4 KiB blocks from `start_block` into `buf` (`count * 4096` bytes),
/// one command per `MAX_BLOCKS_PER_COMMAND` -- the per-command overhead (drive select, status
/// polling) is fixed, so fewer, larger commands are faster.
pub fn read_blocks(start_block: u64, buf: &mut [u8]) -> Result<(), AtaError> {
    for (i, chunk) in buf.chunks_mut((MAX_BLOCKS_PER_COMMAND * 4096) as usize).enumerate() {
        let block = start_block + i as u64 * MAX_BLOCKS_PER_COMMAND;
        let sectors = (chunk.len() / 512) as u8;
        read_sectors(DATA_DISK_CHANNEL, DATA_DISK_DRIVE, (block * 8) as u32, sectors, chunk)?;
    }
    Ok(())
}

/// Writes `count` consecutive blocks from `buf`, then one `CACHE FLUSH` for all of them.
pub fn write_blocks(start_block: u64, buf: &[u8]) -> Result<(), AtaError> {
    for (i, chunk) in buf.chunks((MAX_BLOCKS_PER_COMMAND * 4096) as usize).enumerate() {
        let block = start_block + i as u64 * MAX_BLOCKS_PER_COMMAND;
        let sectors = (chunk.len() / 512) as u8;
        write_sectors_unflushed(DATA_DISK_CHANNEL, DATA_DISK_DRIVE, (block * 8) as u32, sectors, chunk)?;
    }
    cache_flush(DATA_DISK_CHANNEL, DATA_DISK_DRIVE)
}

// --- bus-master DMA --------------------------------------------------------------------------

/// The secondary channel's bus-master registers, at `BAR4 + 8`.
const BM_SECONDARY: u16 = 8;
const BM_COMMAND: u16 = 0;
const BM_STATUS: u16 = 2;
const BM_PRDT: u16 = 4;
const BM_CMD_START: u8 = 1 << 0;
/// Direction: the controller writes memory (a disk read).
const BM_CMD_TO_MEMORY: u8 = 1 << 3;
const BM_STATUS_ERROR: u8 = 1 << 1;
const BM_STATUS_INTERRUPT: u8 = 1 << 2;
/// The secondary channel's device control register (`nIEN` is bit 1).
const SECONDARY_CONTROL: u16 = 0x376;
/// The secondary channel's legacy IRQ.
const SECONDARY_IRQ: u8 = 15;
/// Physical Region Descriptors must not cross a 64 KiB boundary.
const PRD_BOUNDARY: u64 = 0x1_0000;
const PRD_END_OF_TABLE: u32 = 1 << 31;

struct BusMaster {
    /// The data channel's bus-master register block.
    base: u16,
    prdt: crate::drivers::dma::DmaBuffer,
    buffer: crate::drivers::dma::DmaBuffer,
}

static BUS_MASTER: spin::Mutex<Option<BusMaster>> = spin::Mutex::new(None);
/// The data channel's bus-master register block, for the IRQ handler (which can't take
/// `BUS_MASTER`: it may interrupt a holder). `0` until `init_dma` succeeds.
static BM_BASE: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
/// Set by the IRQ handler when the channel raised its interrupt; cleared before each transfer.
static DMA_IRQ_SEEN: AtomicBool = AtomicBool::new(false);
static DMA_TRANSFERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static DMA_IRQS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn dma_ready() -> bool {
    BM_BASE.load(Ordering::Relaxed) != 0
}

/// `(transfers, completion interrupts)` by DMA so far -- how much the interrupt path is used.
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

/// IRQ 15: the data channel finished (or a PIO command raised `INTRQ`). Reads the drive's status
/// register, which acknowledges `INTRQ`, and clears the bus-master interrupt bit, so the line
/// drops before EOI.
fn secondary_irq_handler() {
    let base = BM_BASE.load(Ordering::Relaxed);
    if base == 0 {
        let _ = read_status(SECONDARY.io_base);
        return;
    }
    if bm_read_status(base) & BM_STATUS_INTERRUPT != 0 {
        let _ = read_status(SECONDARY.io_base);
        bm_clear_status(base);
        DMA_IRQ_SEEN.store(true, Ordering::Release);
        DMA_IRQS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Sets up bus-master DMA for the data disk, if the IDE controller is a PCI bus master and a
/// DMA buffer below 4 GiB can be had. Call after `init`. Logged either way; without it the data
/// disk keeps using PIO.
pub fn init_dma(
    frame_allocator: &mut impl x86_64::structures::paging::FrameAllocator<x86_64::structures::paging::Size4KiB>,
    phys_mem_offset: x86_64::VirtAddr,
) {
    use crate::drivers::dma::DmaBuffer;
    if !present() {
        return;
    }
    // Mass storage (0x01), IDE (0x01); prog-if bit 7: bus-master capable.
    let Some(ide) = crate::drivers::pci::find_by_class(0x01, 0x01) else {
        serial_println!("[boot] ata: no PCI IDE controller -- data disk uses PIO");
        return;
    };
    let Some(bar4) = ide.io_bar(4).filter(|_| ide.prog_if & 0x80 != 0) else {
        serial_println!("[boot] ata: IDE controller isn't a bus master -- data disk uses PIO");
        return;
    };
    let prdt = DmaBuffer::alloc(frame_allocator, phys_mem_offset, 1, true);
    let buffer = DmaBuffer::alloc(frame_allocator, phys_mem_offset, MAX_BLOCKS_PER_COMMAND as usize, true);
    let (Some(prdt), Some(buffer)) = (prdt, buffer) else {
        serial_println!("[boot] ata: no DMA buffer below 4 GiB -- data disk uses PIO");
        return;
    };
    ide.enable_bus_mastering();
    let base = bar4 + BM_SECONDARY;

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
        Port::<u8>::new(SECONDARY_CONTROL).write(0);
    }
    bm_clear_status(base);
    *BUS_MASTER.lock() = Some(BusMaster { base, prdt, buffer });
    x86_64::instructions::interrupts::without_interrupts(|| {
        crate::cpu::interrupts::register_irq_handler(SECONDARY_IRQ, secondary_irq_handler);
        BM_BASE.store(base, Ordering::Release);
        // SAFETY: the handler is registered just above.
        unsafe { crate::cpu::pic::unmask_irq(SECONDARY_IRQ) };
    });
    serial_println!(
        "[boot] ata: bus-master DMA on {:02x}:{:02x}.{} (registers {:#06x}, IRQ {}) -- data disk uses DMA",
        ide.bus,
        ide.device,
        ide.function,
        base,
        SECONDARY_IRQ
    );
}

enum Direction<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

/// One DMA command on the data disk, through the bounce buffer.
fn dma_transfer(lba: u32, sector_count: u8, dir: Direction) -> Result<(), AtaError> {
    let guard = BUS_MASTER.lock();
    let bm = guard.as_ref().expect("dma_ready without a bus master");
    let len = sector_count as usize * 512;
    assert!(len <= bm.buffer.len);
    let to_memory = matches!(dir, Direction::Read(_));
    if let Direction::Write(src) = &dir {
        // SAFETY: the controller is idle between transfers.
        unsafe { bm.buffer.slice_mut(0, len) }.copy_from_slice(&src[..len]);
    }

    let io_base = ports(DATA_DISK_CHANNEL).io_base;
    select_drive_lba28(io_base, DATA_DISK_DRIVE, lba);
    wait_while_busy(io_base)?;
    unsafe {
        Port::<u8>::new(bm.base + BM_COMMAND).write(if to_memory { BM_CMD_TO_MEMORY } else { 0 });
        Port::<u32>::new(bm.base + BM_PRDT).write(bm.prdt.phys.as_u64() as u32);
    }
    bm_clear_status(bm.base);
    DMA_IRQ_SEEN.store(false, Ordering::Release);
    setup_lba28(io_base, lba, sector_count);
    unsafe {
        Port::<u8>::new(io_base + REG_STATUS_COMMAND).write(if to_memory { CMD_READ_DMA } else { CMD_WRITE_DMA });
        Port::<u8>::new(bm.base + BM_COMMAND).write(BM_CMD_START | if to_memory { BM_CMD_TO_MEMORY } else { 0 });
    }

    // Done once the drive raised its interrupt: seen by the IRQ handler, or still set in the
    // bus-master status when interrupts are masked.
    let base = bm.base;
    let finished = crate::drivers::dma::wait_until(TIMEOUT_MS, || {
        DMA_IRQ_SEEN.load(Ordering::Acquire) || bm_read_status(base) & (BM_STATUS_INTERRUPT | BM_STATUS_ERROR) != 0
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
