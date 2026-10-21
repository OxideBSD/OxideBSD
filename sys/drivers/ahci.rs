//! AHCI: SATA host adapters (Serial ATA AHCI 1.3.1), each drive on them a disk in the registry
//! (`drivers::disk`), named by where it's plugged in: `sata<C>.<P>` for controller `C` (in PCI
//! order) port `P`, `sata<C>.<P>.<M>` behind a port multiplier's port `M`
//! (`OxideBSD-doc/INSTALLER.md` §5.1, §5.3). ATA disks are read and written here by DMA (`READ/
//! WRITE DMA EXT`, or the 28-bit forms on a drive without LBA48); ATAPI drives are SCSI transports
//! (`drivers::scsi`), their packet commands carried by DMA too.
//!
//! One command at a time per controller (slot 0 of the port's command list, the controller's lock
//! held), its data through the controller's bounce buffer; no NCQ. Completion is interrupt-driven
//! with a polling fallback, as the other disk drivers' (`dma::wait_for_disk`): the interrupt
//! handler records and acknowledges each port's interrupt status (`EVENTS`) and wakes the waiters,
//! who decide from the port's registers.
//!
//! At boot, for each controller: the firmware is asked to let go of it (BIOS/OS handoff, when the
//! controller offers that), AHCI mode is switched on, and every implemented port is stopped, given
//! its own command list and received-FIS area, its link reset (`COMRESET`) and, when a drive
//! answers, started. A controller without 64-bit addressing gets all its DMA memory below 4 GiB.
//! With port multiplier support (`CAP.SPM`), a soft reset to the multiplier's control port tells a
//! multiplier from a drive; each of a multiplier's ports is then reset and probed in turn
//! (command-based switching: one drive at a time, which is all one command at a time needs).
//! QEMU emulates no multiplier: that path is untested.
//!
//! No hot plug yet: a drive plugged in after boot isn't seen (INSTALLER.md §11, after kernel
//! threads).

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::dma::DmaBuffer;
use super::scsi::{Data, ScsiError, Transport};
use crate::cpu::tsc;
use crate::serial_println;

/// PCI: mass storage, SATA, AHCI 1.0 interface; the registers are BAR 5 (`ABAR`).
const CLASS_STORAGE: u8 = 0x01;
const SUBCLASS_SATA: u8 = 0x06;
const PROG_IF_AHCI: u8 = 0x01;
const ABAR: usize = 5;
/// The registers: 0x100 of the controller's, then 0x80 per port, 32 ports.
const ABAR_PAGES: u64 = 2;

// Generic host control (§3.1).
const HBA_CAP: u64 = 0x00;
const HBA_GHC: u64 = 0x04;
const HBA_IS: u64 = 0x08;
const HBA_PI: u64 = 0x0C;
const HBA_VS: u64 = 0x10;
const HBA_CAP2: u64 = 0x24;
const HBA_BOHC: u64 = 0x28;

const CAP_S64A: u32 = 1 << 31;
const CAP_SSS: u32 = 1 << 27;
const CAP_SCLO: u32 = 1 << 24;
const CAP_SPM: u32 = 1 << 17;
const CAP2_BOH: u32 = 1 << 0;
const GHC_AE: u32 = 1 << 31;
const GHC_IE: u32 = 1 << 1;
const BOHC_BOS: u32 = 1 << 0;
const BOHC_OOS: u32 = 1 << 1;
const BOHC_BB: u32 = 1 << 4;

// Port registers (§3.3), at 0x100 + port * 0x80.
const PX_CLB: u64 = 0x00;
const PX_CLBU: u64 = 0x04;
const PX_FB: u64 = 0x08;
const PX_FBU: u64 = 0x0C;
const PX_IS: u64 = 0x10;
const PX_IE: u64 = 0x14;
const PX_CMD: u64 = 0x18;
const PX_TFD: u64 = 0x20;
const PX_SIG: u64 = 0x24;
const PX_SSTS: u64 = 0x28;
const PX_SCTL: u64 = 0x2C;
const PX_SERR: u64 = 0x30;
const PX_CI: u64 = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_CLO: u32 = 1 << 3;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const CMD_PMA: u32 = 1 << 17;
const CMD_ATAPI: u32 = 1 << 24;

/// `PxIS`: the errors that end a command (task file, host bus data, host bus fatal, interface
/// fatal).
const IS_ERRORS: u32 = (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27);
/// `PxIE`: the FISes that complete a command (D2H register, PIO setup, DMA setup, set device
/// bits), and the errors.
const IE_COMPLETION: u32 = 0x0F | IS_ERRORS;

const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;

/// `PxSSTS.DET`: a device there, and the link up.
const DET_PRESENT: u32 = 3;

const SIG_ATAPI: u32 = 0xEB14_0101;
const SIG_PMP: u32 = 0x9669_0101;

// Command header flags (§4.2.2): ATAPI, write, reset, clear busy on R_OK.
const HDR_ATAPI: u32 = 1 << 5;
const HDR_WRITE: u32 = 1 << 6;
const HDR_RESET: u32 = 1 << 8;
const HDR_CLEAR_BUSY: u32 = 1 << 10;
/// The command FIS's length in dwords (an H2D register FIS: 20 bytes).
const HDR_CFL: u32 = 5;

const FIS_H2D: u8 = 0x27;
/// H2D register FIS byte 1: this FIS carries a command (else it's a device control update).
const FIS_COMMAND: u8 = 0x80;
const ATA_IDENTIFY: u8 = 0xEC;
const ATA_IDENTIFY_PACKET: u8 = 0xA1;
const ATA_PACKET: u8 = 0xA0;
const ATA_READ_DMA: u8 = 0xC8;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA: u8 = 0xCA;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH: u8 = 0xE7;
const ATA_FLUSH_EXT: u8 = 0xEA;
const ATA_READ_PM: u8 = 0xE4;
const ATA_WRITE_PM: u8 = 0xE8;
/// The device control register's soft reset bit.
const CONTROL_SRST: u8 = 0x04;
/// The LBA mode bit of the device register.
const DEVICE_LBA: u8 = 0x40;

/// A port multiplier's control port (its own registers), and how many device ports it has at most.
const PMP_CONTROL: u8 = 15;
const PMP_MAX_PORTS: u32 = 15;
/// The multiplier's registers (SATA port multiplier 1.2): `GSCR[2]`, its number of device ports;
/// each device port's `PSCR[0..3]`, its SStatus, SError and SControl.
const GSCR_PORTS: u16 = 2;
const PSCR_SSTATUS: u16 = 0;
const PSCR_SERROR: u16 = 1;
const PSCR_SCONTROL: u16 = 2;

// Each port's page: its command list (32 headers of 32 bytes; slot 0 used), its received FISes,
// and slot 0's command table (the command FIS, the ATAPI command, one PRD entry).
const CL_AT: usize = 0x000;
const RFIS_AT: usize = 0x400;
/// The last D2H register FIS, in the received-FIS area.
const RFIS_D2H: usize = RFIS_AT + 0x40;
const CT_AT: usize = 0x800;
const CT_ACMD: usize = 0x40;
const CT_PRDT: usize = 0x80;

/// The bounce buffer, in pages (256 KiB): what one command moves at most.
const BUFFER_PAGES: usize = 64;
const TIMEOUT_MS: u64 = 10_000;
/// How long a drive gets to finish spinning up after its link comes up.
const READY_MS: u64 = 10_000;
const MAX_CONTROLLERS: usize = 8;
const MAX_PORTS: usize = 32;
/// The ATAPI command: every SCSI command an optical drive takes fits in 12 bytes.
const PACKET_LEN: usize = 12;
const SCSI_REQUEST_SENSE: u8 = 0x03;

/// Why a command failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The drive refused it: its error register.
    Device(u8),
    Timeout,
    /// It couldn't be sent: no such drive, or more data than the bounce buffer holds.
    Unsent,
}

struct Controller {
    /// Its number (`sata<C>`), and its registers.
    index: usize,
    regs: VirtAddr,
    cap: u32,
    /// Each implemented port's page (command list, received FISes, command table).
    pages: [Option<DmaBuffer>; MAX_PORTS],
    buffer: DmaBuffer,
}

/// The controllers, set once by `init`.
static CONTROLLERS: spin::Once<Vec<Mutex<Controller>>> = spin::Once::new();
/// Each controller's registers, for the interrupt handler (`0` past those started).
static ABARS: [AtomicU64; MAX_CONTROLLERS] = [const { AtomicU64::new(0) }; MAX_CONTROLLERS];
/// Each port's interrupt status since its command was issued, as the interrupt handler found it
/// (and acknowledged it).
static EVENTS: [[AtomicU32; MAX_PORTS]; MAX_CONTROLLERS] =
    [const { [const { AtomicU32::new(0) }; MAX_PORTS] }; MAX_CONTROLLERS];
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static IRQS: AtomicU64 = AtomicU64::new(0);

/// `(commands, completion interrupts)` so far.
pub fn stats() -> (u64, u64) {
    (REQUESTS.load(Ordering::Relaxed), IRQS.load(Ordering::Relaxed))
}

fn port_reg(port: u8, reg: u64) -> u64 {
    0x100 + port as u64 * 0x80 + reg
}

fn mmio_read(regs: u64, offset: u64) -> u32 {
    // SAFETY: a mapped register of a started controller.
    unsafe { ((regs + offset) as *const u32).read_volatile() }
}

fn mmio_write(regs: u64, offset: u64, value: u32) {
    // SAFETY: as above.
    unsafe { ((regs + offset) as *mut u32).write_volatile(value) }
}

fn irq_handler() {
    let mut any = false;
    for (c, abar) in ABARS.iter().enumerate() {
        let regs = abar.load(Ordering::Relaxed);
        if regs == 0 {
            continue;
        }
        let pending = mmio_read(regs, HBA_IS);
        if pending == 0 {
            continue;
        }
        for port in 0..MAX_PORTS as u8 {
            if pending & 1 << port != 0 {
                let status = mmio_read(regs, port_reg(port, PX_IS));
                EVENTS[c][port as usize].fetch_or(status, Ordering::Relaxed);
                mmio_write(regs, port_reg(port, PX_IS), status);
            }
        }
        mmio_write(regs, HBA_IS, pending);
        any = true;
    }
    if any {
        IRQS.fetch_add(1, Ordering::Relaxed);
        super::dma::wake_disk_waiters(&mut crate::process::table().lock());
    }
}

/// Polls `cond` until it holds, for up to `ms`.
fn poll(ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = tsc::now() + tsc::ms_to_cycles(ms);
    loop {
        if cond() {
            return true;
        }
        if tsc::now() >= deadline {
            return cond();
        }
        core::hint::spin_loop();
    }
}

fn delay_ms(ms: u64) {
    poll(ms, || false);
}

/// One drive: a SATA disk or an ATAPI drive (then a SCSI transport, `drivers::scsi`).
#[derive(Clone, Copy)]
pub struct Unit {
    controller: u8,
    port: u8,
    /// Its port on a port multiplier, if it's behind one.
    pmp: Option<u8>,
    atapi: bool,
    lba48: bool,
}

impl Unit {
    /// Its name: `sata<C>.<P>`, or `sata<C>.<P>.<M>` behind a port multiplier.
    pub fn name(&self) -> String {
        match self.pmp {
            Some(m) => alloc::format!("sata{}.{}.{}", self.controller, self.port, m),
            None => alloc::format!("sata{}.{}", self.controller, self.port),
        }
    }

    /// Its unit number for the device numbers (`drivers::disk`): controller, port and multiplier
    /// port (`PMP_CONTROL` for none: no drive is ever there), 12 bits.
    pub fn number(&self) -> u32 {
        (self.controller as u32) << 9 | (self.port as u32) << 4 | self.pmp.unwrap_or(PMP_CONTROL) as u32
    }

    pub fn atapi(&self) -> bool {
        self.atapi
    }

    /// Blocks of `block_size` bytes one command moves at most: the bounce buffer's worth, and 256
    /// for the 28-bit commands.
    pub fn max_blocks(&self, block_size: usize) -> usize {
        let n = (BUFFER_PAGES * 4096 / block_size).max(1);
        if self.atapi || self.lba48 { n } else { n.min(256) }
    }

    /// The command header's and FIS's port multiplier port.
    fn pm_port(&self) -> u8 {
        self.pmp.unwrap_or(0)
    }
}

fn controller(index: u8) -> Option<&'static Mutex<Controller>> {
    CONTROLLERS.get()?.get(index as usize)
}

/// A drive found at boot: what it is, its model, and (a disk's) size in its own sectors.
pub struct Found {
    pub unit: Unit,
    pub model: String,
    pub sectors: u64,
    pub sector_size: u32,
}

/// One command: an H2D register FIS (byte 1's port multiplier field filled in from `pmp`), the
/// ATAPI command if it's a packet, `len` bytes of data through the bounce buffer (out of it with
/// `write`), and any more command header flags.
struct Command {
    pmp: u8,
    fis: [u8; 20],
    packet: Option<[u8; PACKET_LEN]>,
    len: usize,
    write: bool,
    flags: u32,
}

impl Command {
    fn new(pmp: u8, fis: [u8; 20]) -> Command {
        Command { pmp, fis, packet: None, len: 0, write: false, flags: 0 }
    }
}

/// An H2D register FIS carrying ATA command `command`.
fn ata_fis(command: u8) -> [u8; 20] {
    let mut fis = [0u8; 20];
    fis[0] = FIS_H2D;
    fis[1] = FIS_COMMAND;
    fis[2] = command;
    fis
}

impl Controller {
    fn read(&self, offset: u64) -> u32 {
        mmio_read(self.regs.as_u64(), offset)
    }

    fn write(&self, offset: u64, value: u32) {
        mmio_write(self.regs.as_u64(), offset, value)
    }

    fn pread(&self, port: u8, reg: u64) -> u32 {
        self.read(port_reg(port, reg))
    }

    fn pwrite(&self, port: u8, reg: u64, value: u32) {
        self.write(port_reg(port, reg), value)
    }

    /// Runs `cmd` on `port` in slot 0 and waits for it; the bytes the drive moved. A command that
    /// fails or times out leaves the port restarted (`recover`), ready for the next.
    fn issue(&self, port: u8, cmd: &Command) -> Result<usize, Error> {
        let page = self.pages[port as usize].as_ref().ok_or(Error::Unsent)?;
        if cmd.len > self.buffer.len {
            return Err(Error::Unsent);
        }
        if cmd.flags & HDR_RESET == 0 && !poll(TIMEOUT_MS, || self.pread(port, PX_TFD) & (TFD_BSY | TFD_DRQ) == 0) {
            self.recover(port);
            return Err(Error::Timeout);
        }
        let pmp = (cmd.pmp & 0x0F) as u32;
        let mut dw0 = HDR_CFL | pmp << 12 | ((cmd.len > 0) as u32) << 16 | cmd.flags;
        if cmd.packet.is_some() {
            dw0 |= HDR_ATAPI;
        }
        if cmd.write {
            dw0 |= HDR_WRITE;
        }
        let table = page.phys.as_u64() + CT_AT as u64;
        // SAFETY: this port's own page, idle between commands (the controller's lock is held).
        let header = unsafe { page.slice_mut(CL_AT, 32) };
        header.fill(0);
        header[0..4].copy_from_slice(&dw0.to_le_bytes());
        header[8..12].copy_from_slice(&(table as u32).to_le_bytes());
        header[12..16].copy_from_slice(&((table >> 32) as u32).to_le_bytes());
        // SAFETY: as above.
        let t = unsafe { page.slice_mut(CT_AT, CT_PRDT + 16) };
        t.fill(0);
        t[..20].copy_from_slice(&cmd.fis);
        t[1] = (t[1] & FIS_COMMAND) | pmp as u8;
        if let Some(packet) = &cmd.packet {
            t[CT_ACMD..CT_ACMD + PACKET_LEN].copy_from_slice(packet);
        }
        if cmd.len > 0 {
            let data = self.buffer.phys.as_u64();
            t[CT_PRDT..CT_PRDT + 4].copy_from_slice(&(data as u32).to_le_bytes());
            t[CT_PRDT + 4..CT_PRDT + 8].copy_from_slice(&((data >> 32) as u32).to_le_bytes());
            // The byte count less one (an even count: bit 0 set), and no interrupt per entry.
            let count = cmd.len.next_multiple_of(2) as u32 - 1;
            t[CT_PRDT + 12..CT_PRDT + 16].copy_from_slice(&count.to_le_bytes());
        }
        let events = &EVENTS[self.index][port as usize];
        events.store(0, Ordering::Relaxed);
        self.pwrite(port, PX_IS, u32::MAX);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.pwrite(port, PX_CI, 1);
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let failed = || (events.load(Ordering::Relaxed) | self.pread(port, PX_IS)) & IS_ERRORS != 0;
        let finished = super::dma::wait_for_disk(TIMEOUT_MS, || self.pread(port, PX_CI) & 1 == 0 || failed());
        let tfd = self.pread(port, PX_TFD);
        if !finished || failed() || tfd & TFD_ERR != 0 {
            self.recover(port);
            return Err(if finished { Error::Device((tfd >> 8) as u8) } else { Error::Timeout });
        }
        // SAFETY: the command is done; the header's byte count is the drive's.
        let header = unsafe { page.slice_mut(CL_AT, 8) };
        Ok(u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize)
    }

    /// After a failed command: stops the port, clears its errors, frees a drive stuck busy (a
    /// command list override, else a link reset) and starts it again (§6.2.2).
    fn recover(&self, port: u8) {
        self.stop(port, false);
        self.pwrite(port, PX_SERR, u32::MAX);
        self.pwrite(port, PX_IS, u32::MAX);
        if self.pread(port, PX_TFD) & (TFD_BSY | TFD_DRQ) != 0 {
            if self.cap & CAP_SCLO != 0 {
                self.pwrite(port, PX_CMD, self.pread(port, PX_CMD) | CMD_CLO);
                poll(500, || self.pread(port, PX_CMD) & CMD_CLO == 0);
            } else {
                self.comreset(port);
            }
        }
        self.start(port);
    }

    /// Stops the port's command list (and, with `fis_too`, its FIS receiving), waiting for it to
    /// stop.
    fn stop(&self, port: u8, fis_too: bool) {
        let cmd = self.pread(port, PX_CMD);
        self.pwrite(port, PX_CMD, cmd & !CMD_ST);
        poll(500, || self.pread(port, PX_CMD) & CMD_CR == 0);
        if fis_too {
            self.pwrite(port, PX_CMD, self.pread(port, PX_CMD) & !CMD_FRE);
            poll(500, || self.pread(port, PX_CMD) & CMD_FR == 0);
        }
    }

    fn start(&self, port: u8) {
        self.pwrite(port, PX_CMD, self.pread(port, PX_CMD) | CMD_ST);
    }

    /// Resets the port's link (`COMRESET`); whether a drive came up on it. An empty port shows
    /// no device at all within a few milliseconds; a present one gets a second to bring its link
    /// up.
    fn comreset(&self, port: u8) -> bool {
        // DET = 1 (reset), IPM = 3 (no partial or slumber power states), then DET = 0.
        let sctl = self.pread(port, PX_SCTL) & !0xF0F;
        self.pwrite(port, PX_SCTL, sctl | 0x301);
        delay_ms(2);
        self.pwrite(port, PX_SCTL, sctl | 0x300);
        poll(20, || self.pread(port, PX_SSTS) & 0xF != 0)
            && poll(1000, || self.pread(port, PX_SSTS) & 0xF == DET_PRESENT)
    }

    /// Gives `port` its page, resets its link, and starts it if a drive answers; whether one did.
    fn bring_up(&self, port: u8) -> bool {
        let Some(page) = &self.pages[port as usize] else { return false };
        self.stop(port, true);
        let base = page.phys.as_u64();
        self.pwrite(port, PX_CLB, (base + CL_AT as u64) as u32);
        self.pwrite(port, PX_CLBU, ((base + CL_AT as u64) >> 32) as u32);
        self.pwrite(port, PX_FB, (base + RFIS_AT as u64) as u32);
        self.pwrite(port, PX_FBU, ((base + RFIS_AT as u64) >> 32) as u32);
        self.pwrite(port, PX_SERR, u32::MAX);
        self.pwrite(port, PX_IS, u32::MAX);
        let mut cmd = self.pread(port, PX_CMD) | CMD_FRE | CMD_POD;
        if self.cap & CAP_SSS != 0 {
            cmd |= CMD_SUD; // staggered spin-up: this port's drive spins up now
        }
        self.pwrite(port, PX_CMD, cmd & !CMD_PMA);
        self.pwrite(port, PX_IE, IE_COMPLETION);
        if !self.comreset(port) {
            return false;
        }
        self.pwrite(port, PX_SERR, u32::MAX);
        if !poll(READY_MS, || self.pread(port, PX_TFD) & (TFD_BSY | TFD_DRQ) == 0) {
            serial_println!("[boot] ahci: sata{}.{}: the drive stays busy -- not used", self.index, port);
            return false;
        }
        true
    }

    /// A soft reset of the drive at multiplier port `pmp` (or the multiplier itself, at
    /// `PMP_CONTROL`), the port started; its signature (§10.4.1).
    fn soft_reset(&self, port: u8, pmp: u8) -> Option<u32> {
        let mut fis = [0u8; 20];
        fis[0] = FIS_H2D;
        fis[15] = CONTROL_SRST;
        let mut cmd = Command::new(pmp, fis);
        cmd.flags = HDR_RESET | HDR_CLEAR_BUSY;
        self.issue(port, &cmd).ok()?;
        delay_ms(1);
        cmd.fis[15] = 0;
        cmd.flags = 0;
        self.issue(port, &cmd).ok()?;
        Some(self.d2h_value(port))
    }

    /// The count and LBA low/mid/high bytes of the port's last D2H register FIS, as one value: a
    /// signature, or a port multiplier register.
    fn d2h_value(&self, port: u8) -> u32 {
        let Some(page) = &self.pages[port as usize] else { return 0 };
        // SAFETY: the port is idle; the drive wrote its answer.
        let d2h = unsafe { page.slice_mut(RFIS_D2H, 20) };
        d2h[12] as u32 | (d2h[4] as u32) << 8 | (d2h[5] as u32) << 16 | (d2h[6] as u32) << 24
    }

    /// Port multiplier register `reg` of multiplier port `pm_port` (`PMP_CONTROL`: its own).
    fn pm_read(&self, port: u8, pm_port: u8, reg: u16) -> Option<u32> {
        let mut fis = ata_fis(ATA_READ_PM);
        fis[3] = reg as u8;
        fis[7] = pm_port;
        fis[11] = (reg >> 8) as u8;
        self.issue(port, &Command::new(PMP_CONTROL, fis)).ok()?;
        Some(self.d2h_value(port))
    }

    fn pm_write(&self, port: u8, pm_port: u8, reg: u16, value: u32) -> bool {
        let mut fis = ata_fis(ATA_WRITE_PM);
        fis[3] = reg as u8;
        fis[4] = (value >> 8) as u8;
        fis[5] = (value >> 16) as u8;
        fis[6] = (value >> 24) as u8;
        fis[7] = pm_port;
        fis[11] = (reg >> 8) as u8;
        fis[12] = value as u8;
        self.issue(port, &Command::new(PMP_CONTROL, fis)).is_ok()
    }

    /// The drives on the port multiplier at `port`: each device port's link reset through the
    /// multiplier, then soft reset for its signature. `(multiplier port, signature)` each.
    fn multiplier_ports(&self, port: u8) -> Vec<(u8, u32)> {
        let mut found = Vec::new();
        let Some(n) = self.pm_read(port, PMP_CONTROL, GSCR_PORTS) else { return found };
        for m in 0..(n & 0xF).min(PMP_MAX_PORTS) as u8 {
            self.pm_write(port, m, PSCR_SCONTROL, 0x301);
            delay_ms(2);
            self.pm_write(port, m, PSCR_SCONTROL, 0x300);
            let det = || self.pm_read(port, m, PSCR_SSTATUS).map_or(0, |s| s & 0xF);
            if !poll(20, || det() != 0) || !poll(1000, || det() == DET_PRESENT) {
                continue;
            }
            self.pm_write(port, m, PSCR_SERROR, u32::MAX);
            self.pwrite(port, PX_SERR, u32::MAX);
            if let Some(sig) = self.soft_reset(port, m) {
                found.push((m, sig));
            }
        }
        found
    }

    /// `IDENTIFY (PACKET) DEVICE` of the drive at multiplier port `pmp`.
    fn identify(&self, port: u8, pmp: u8, atapi: bool) -> Option<[u16; 256]> {
        let mut cmd = Command::new(pmp, ata_fis(if atapi { ATA_IDENTIFY_PACKET } else { ATA_IDENTIFY }));
        cmd.len = 512;
        if self.issue(port, &cmd).ok()? < 512 {
            return None;
        }
        // SAFETY: the command is done; the drive is through with the buffer.
        let bytes = unsafe { self.buffer.slice_mut(0, 512) };
        let mut words = [0u16; 256];
        for (w, b) in words.iter_mut().zip(bytes.chunks_exact(2)) {
            *w = u16::from_le_bytes([b[0], b[1]]);
        }
        Some(words)
    }

    /// What answers on multiplier port `pmp` of `port`, given its signature: a disk or an ATAPI
    /// drive, logged; `None` (logged) for anything else.
    fn probe(&self, port: u8, pmp: Option<u8>, sig: u32) -> Option<Found> {
        let atapi = sig == SIG_ATAPI;
        let mut unit = Unit { controller: self.index as u8, port, pmp, atapi, lba48: false };
        let name = unit.name();
        let Some(words) = self.identify(port, unit.pm_port(), atapi) else {
            serial_println!("[boot] ahci: {}: signature {:#010x}, no answer to IDENTIFY -- not used", name, sig);
            return None;
        };
        let model = super::ata::model_of(&words);
        if atapi {
            if pmp.is_none() {
                self.pwrite(port, PX_CMD, self.pread(port, PX_CMD) | CMD_ATAPI);
            }
            serial_println!("[boot] ahci: {}: CD drive \"{}\"", name, model);
            return Some(Found { unit, model, sectors: 0, sector_size: 2048 });
        }
        unit.lba48 = words[83] & 1 << 10 != 0;
        let sectors = if unit.lba48 {
            words[100..104].iter().rev().fold(0u64, |n, &w| n << 16 | w as u64)
        } else {
            words[60] as u64 | (words[61] as u64) << 16
        };
        // Word 106 valid (bits 15:14 = 01) and saying the logical sector is longer than 256 words:
        // its length in words 117-118, in words.
        let sector_size = if words[106] & 0xC000 == 0x4000 && words[106] & 1 << 12 != 0 {
            (words[117] as u32 | (words[118] as u32) << 16) * 2
        } else {
            512
        };
        if !(512..=4096).contains(&sector_size) || !sector_size.is_power_of_two() {
            serial_println!("[boot] ahci: {}: sectors of {} bytes aren't driven -- not used", name, sector_size);
            return None;
        }
        serial_println!(
            "[boot] ahci: {}: disk \"{}\", {} MiB{}{}",
            name,
            model,
            sectors * sector_size as u64 >> 20,
            if unit.lba48 { ", LBA48" } else { "" },
            if sector_size != 512 { alloc::format!(", {sector_size}-byte sectors") } else { String::new() }
        );
        Some(Found { unit, model, sectors, sector_size })
    }

    /// The disk at `unit`'s `count` sectors at `lba`, by DMA through the bounce buffer: read into
    /// it, or written from it.
    fn transfer(&self, unit: &Unit, write: bool, lba: u64, count: usize, len: usize) -> Result<(), Error> {
        let mut fis = ata_fis(match (write, unit.lba48) {
            (false, true) => ATA_READ_DMA_EXT,
            (false, false) => ATA_READ_DMA,
            (true, true) => ATA_WRITE_DMA_EXT,
            (true, false) => ATA_WRITE_DMA,
        });
        fis[4] = lba as u8;
        fis[5] = (lba >> 8) as u8;
        fis[6] = (lba >> 16) as u8;
        if unit.lba48 {
            fis[7] = DEVICE_LBA;
            fis[8] = (lba >> 24) as u8;
            fis[9] = (lba >> 32) as u8;
            fis[10] = (lba >> 40) as u8;
            fis[13] = (count >> 8) as u8;
        } else {
            fis[7] = DEVICE_LBA | ((lba >> 24) & 0xF) as u8;
        }
        fis[12] = count as u8; // 0 is 256 (or 65536)
        let mut cmd = Command::new(unit.pm_port(), fis);
        cmd.len = len;
        cmd.write = write;
        if self.issue(unit.port, &cmd)? != len {
            return Err(Error::Device(0));
        }
        Ok(())
    }

    /// `FLUSH CACHE (EXT)`: everything written so far is durable.
    fn flush(&self, unit: &Unit) -> Result<(), Error> {
        let fis = ata_fis(if unit.lba48 { ATA_FLUSH_EXT } else { ATA_FLUSH });
        self.issue(unit.port, &Command::new(unit.pm_port(), fis)).map(|_| ())
    }

    /// Sends `packet` to the ATAPI drive at `unit` with `data`; the bytes moved.
    fn packet(&self, unit: &Unit, packet: &[u8; PACKET_LEN], data: Data) -> Result<usize, Error> {
        let (len, write) = match &data {
            Data::None => (0, false),
            Data::In(b) => (b.len(), false),
            Data::Out(b) => (b.len(), true),
        };
        if len > self.buffer.len {
            return Err(Error::Unsent);
        }
        if let Data::Out(b) = &data {
            // SAFETY: the buffer is idle between commands (the controller's lock is held).
            unsafe { self.buffer.slice_mut(0, len) }.copy_from_slice(b);
        }
        let mut fis = ata_fis(ATA_PACKET);
        fis[3] = (len > 0) as u8; // the data by DMA
        // The byte count limit, for a drive that moves the data by PIO anyway.
        let limit = len.min(0xFFFE) as u16;
        fis[5] = limit as u8;
        fis[6] = (limit >> 8) as u8;
        let mut cmd = Command::new(unit.pm_port(), fis);
        cmd.packet = Some(*packet);
        cmd.len = len;
        cmd.write = write;
        let moved = self.issue(unit.port, &cmd)?.min(len);
        if let Data::In(b) = data {
            // SAFETY: the command is done; the drive is through with the buffer.
            b[..moved].copy_from_slice(unsafe { self.buffer.slice_mut(0, moved) });
        }
        Ok(moved)
    }
}

impl Transport for Unit {
    /// A command padded to a 12-byte packet; a failed command's sense from `REQUEST SENSE`.
    fn command(&self, cdb: &[u8], data: Data) -> Result<usize, ScsiError> {
        if !self.atapi || cdb.len() > PACKET_LEN {
            return Err(ScsiError::Transport);
        }
        let Some(c) = controller(self.controller) else { return Err(ScsiError::Transport) };
        let c = c.lock();
        let mut packet = [0u8; PACKET_LEN];
        packet[..cdb.len()].copy_from_slice(cdb);
        match c.packet(self, &packet, data) {
            Ok(n) => Ok(n),
            Err(Error::Device(error)) => {
                let mut sense = [0u8; 18];
                let mut request = [0u8; PACKET_LEN];
                request[0] = SCSI_REQUEST_SENSE;
                request[4] = sense.len() as u8;
                match c.packet(self, &request, Data::In(&mut sense)) {
                    Ok(n) if n >= 14 => Err(ScsiError::Sense(sense[2] & 0x0F, sense[12], sense[13])),
                    _ => Err(ScsiError::Sense(error >> 4, 0, 0)),
                }
            }
            Err(_) => Err(ScsiError::Transport),
        }
    }
}

/// Reads whole sectors of `sector_size` bytes from `lba` of the disk at `unit` into `buf`.
pub fn read(unit: &Unit, lba: u64, sector_size: usize, buf: &mut [u8]) -> Result<(), Error> {
    let c = controller(unit.controller).ok_or(Error::Unsent)?;
    let max = unit.max_blocks(sector_size);
    for (i, chunk) in buf.chunks_mut(max * sector_size).enumerate() {
        let c = c.lock();
        c.transfer(unit, false, lba + (i * max) as u64, chunk.len() / sector_size, chunk.len())?;
        // SAFETY: the transfer is done; the drive is through with the buffer.
        chunk.copy_from_slice(unsafe { c.buffer.slice_mut(0, chunk.len()) });
    }
    Ok(())
}

/// Writes whole sectors from `buf` at `lba` of the disk at `unit`, then flushes its cache, so
/// they're durable when this returns.
pub fn write(unit: &Unit, lba: u64, sector_size: usize, buf: &[u8]) -> Result<(), Error> {
    let c = controller(unit.controller).ok_or(Error::Unsent)?;
    let max = unit.max_blocks(sector_size);
    for (i, chunk) in buf.chunks(max * sector_size).enumerate() {
        let c = c.lock();
        // SAFETY: the buffer is idle between commands (the controller's lock is held).
        unsafe { c.buffer.slice_mut(0, chunk.len()) }.copy_from_slice(chunk);
        c.transfer(unit, true, lba + (i * max) as u64, chunk.len() / sector_size, chunk.len())?;
    }
    c.lock().flush(unit)
}

/// Finds and starts every AHCI controller, and probes its ports; the drives found, in controller
/// and port order.
pub fn init(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Vec<Found> {
    let pcis: Vec<_> = super::pci::find_all_by_class(CLASS_STORAGE, SUBCLASS_SATA)
        .into_iter()
        .filter(|p| p.prog_if == PROG_IF_AHCI)
        .collect();
    let mut controllers = Vec::new();
    let mut found = Vec::new();
    for pci in pcis {
        if controllers.len() == MAX_CONTROLLERS {
            serial_println!("[boot] ahci: more than {} controllers -- the rest not used", MAX_CONTROLLERS);
            break;
        }
        if let Some(c) = start(pci, controllers.len(), frame_allocator, mapper, phys_mem_offset) {
            found.extend(probe_ports(&c));
            controllers.push(Mutex::new(c));
        }
    }
    CONTROLLERS.call_once(|| controllers);
    found
}

/// Starts the controller at `pci` as number `n`: takes it from the firmware, switches AHCI mode
/// on, gives each implemented port its page, and takes its interrupt. `None` (logged) if it can't.
fn start(
    pci: super::pci::PciDevice,
    n: usize,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    phys_mem_offset: VirtAddr,
) -> Option<Controller> {
    let fail = |why: &str| {
        serial_println!("[boot] ahci at {:02x}:{:02x}.{}: {} -- not used", pci.bus, pci.device, pci.function, why);
        None
    };
    let Some(abar) = pci.mem_bar(ABAR).filter(|&a| a != 0) else {
        return fail("no register BAR");
    };
    pci.enable_memory_and_bus_mastering();
    let regs = super::pci::map_mmio(mapper, frame_allocator, phys_mem_offset, PhysAddr::new(abar), ABAR_PAGES);
    let r = |offset| mmio_read(regs.as_u64(), offset);
    let w = |offset, value| mmio_write(regs.as_u64(), offset, value);

    // BIOS/OS handoff (§10.6.3): ask for ownership, give the firmware 25 ms to let go, and 2 s
    // more if it says it's busy.
    if r(HBA_CAP2) & CAP2_BOH != 0 {
        w(HBA_BOHC, r(HBA_BOHC) | BOHC_OOS);
        let let_go = poll(25, || r(HBA_BOHC) & BOHC_BOS == 0);
        if !let_go && r(HBA_BOHC) & BOHC_BB != 0 {
            poll(2000, || r(HBA_BOHC) & BOHC_BOS == 0);
        }
        if r(HBA_BOHC) & BOHC_BOS != 0 {
            serial_println!("[boot] ahci: controller {}: the firmware didn't let go of it -- taking it anyway", n);
        }
    }
    w(HBA_GHC, r(HBA_GHC) | GHC_AE);
    let cap = r(HBA_CAP);
    let s64 = cap & CAP_S64A != 0;
    let implemented = r(HBA_PI);
    let Some(buffer) = DmaBuffer::alloc(frame_allocator, phys_mem_offset, BUFFER_PAGES, !s64) else {
        return fail("no DMA buffer");
    };
    let mut pages = [const { None }; MAX_PORTS];
    for (port, page) in pages.iter_mut().enumerate() {
        if implemented & 1 << port != 0 {
            *page = DmaBuffer::alloc(frame_allocator, phys_mem_offset, 1, !s64);
            if page.is_none() {
                return fail("no DMA memory for its ports");
            }
        }
    }
    let c = Controller { index: n, regs, cap, pages, buffer };

    // The interrupt before the ports are probed: the probe's commands complete by it.
    let irq = pci.interrupt_line;
    let irq_ok = (3..16).contains(&irq);
    ABARS[n].store(regs.as_u64(), Ordering::Release);
    w(HBA_IS, u32::MAX);
    if irq_ok {
        x86_64::instructions::interrupts::without_interrupts(|| {
            crate::cpu::interrupts::register_irq_handler(irq, irq_handler);
            // SAFETY: the handler is registered just above.
            unsafe { crate::cpu::pic::unmask_irq(irq) };
        });
        w(HBA_GHC, r(HBA_GHC) | GHC_IE);
    }
    let vs = r(HBA_VS);
    serial_println!(
        "[boot] ahci: controller {} at {:02x}:{:02x}.{}: AHCI {:x}.{:x}, {} ports (implemented {:#010x}), {}-bit DMA, port multipliers {}, {}",
        n,
        pci.bus,
        pci.device,
        pci.function,
        vs >> 16,
        (vs >> 8) & 0xFF,
        (cap & 0x1F) + 1,
        implemented,
        if s64 { 64 } else { 32 },
        if cap & CAP_SPM != 0 { "supported" } else { "not supported" },
        if irq_ok { alloc::format!("IRQ {irq}") } else { String::from("no IRQ, polling") }
    );
    Some(c)
}

/// Brings up each implemented port of `c` and probes what answers: a drive, or a port multiplier
/// and the drives behind it.
fn probe_ports(c: &Controller) -> Vec<Found> {
    let mut found = Vec::new();
    for port in 0..MAX_PORTS as u8 {
        if c.pages[port as usize].is_none() || !c.bring_up(port) {
            continue;
        }
        if c.cap & CAP_SPM == 0 {
            c.start(port);
            found.extend(c.probe(port, None, c.pread(port, PX_SIG)));
            continue;
        }
        // A soft reset to the multiplier's control port: a multiplier answers with its
        // signature, a drive with its own (PMA may only change while the port is stopped).
        c.pwrite(port, PX_CMD, c.pread(port, PX_CMD) | CMD_PMA);
        c.start(port);
        let sig = c.soft_reset(port, PMP_CONTROL);
        if sig == Some(SIG_PMP) {
            let drives = c.multiplier_ports(port);
            serial_println!("[boot] ahci: sata{}.{}: port multiplier, {} drives", c.index, port, drives.len());
            for (m, sig) in drives {
                found.extend(c.probe(port, Some(m), sig));
            }
            continue;
        }
        c.stop(port, false);
        c.pwrite(port, PX_CMD, c.pread(port, PX_CMD) & !CMD_PMA);
        c.start(port);
        found.extend(c.probe(port, None, sig.unwrap_or_else(|| c.pread(port, PX_SIG))));
    }
    found
}
