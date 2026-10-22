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
//! Hot plug (INSTALLER.md §5.3): once the boot probe is done, a port's connection changes
//! (`PxIS.PCS`, `PxIS.PRCS`) and a port multiplier's asynchronous notifications (a Set Device Bits
//! FIS from its control port) interrupt; the handler enqueues the port's task (`hotplug`) on
//! `taskqueue_thread`, which lets the link settle, then registers what arrived and retires what
//! went (`drivers::disk`). The task holds the giant lock (`fslock`) before it takes a controller's
//! lock -- a process asleep in `issue` holds both -- and never sleeps holding a controller's
//! alone.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, Mapper, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::dma::DmaBuffer;
use super::scsi::{Data, ScsiError, Transport};
use crate::cpu::tsc;
use crate::kern::subr_taskqueue::{self, TASKQUEUE_THREAD, Task};
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
const CAP_SSNTF: u32 = 1 << 29;
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
const PX_SNTF: u64 = 0x3C;

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
/// `PxIS`: a Set Device Bits FIS came (a multiplier's notification among them).
const IS_SDBS: u32 = 1 << 3;
/// `PxIS` and `PxIE`: port connect change, PhyRdy change -- hot plug.
const IS_PCS: u32 = 1 << 6;
const IS_PRCS: u32 = 1 << 22;
const IE_HOTPLUG: u32 = IS_PCS | IS_PRCS;
/// `PxSERR.DIAG`: PhyRdy changed (`N`), a device exchanged (`X`); `PCS`/`PRCS` stay set (and the
/// level-triggered interrupt asserted) until they're cleared.
const SERR_DIAG_N: u32 = 1 << 16;
const SERR_DIAG_X: u32 = 1 << 26;

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
/// `GSCR[32]`: the device ports whose `PSCR[1]` has a bit `GSCR[33]` selects; `GSCR[64]`/`[96]`:
/// the features the multiplier has and has enabled, bit 3 asynchronous notification.
const GSCR_ERROR: u16 = 32;
const GSCR_ERROR_EN: u16 = 33;
const GSCR_FEATURES: u16 = 64;
const GSCR_FEATURES_EN: u16 = 96;
const FEATURE_NOTIFY: u32 = 1 << 3;

// Each port's page: its command list (32 headers of 32 bytes; slot 0 used), its received FISes,
// and slot 0's command table (the command FIS, the ATAPI command, one PRD entry).
const CL_AT: usize = 0x000;
const RFIS_AT: usize = 0x400;
/// The last D2H register FIS, in the received-FIS area, and the last Set Device Bits FIS (byte 1:
/// bit 7 its notification bit, bits 0-3 the multiplier port it came from).
const RFIS_D2H: usize = RFIS_AT + 0x40;
const RFIS_SDB: usize = RFIS_AT + 0x58;
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
/// How long a hot plugged link gets to settle before the port task looks at it, in ticks (500 ms).
const SETTLE_TICKS: u64 = 50;
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
    /// It has its interrupt: hot plug is on (polling controllers don't see it).
    irq: bool,
}

/// The controllers, set once by `init`.
static CONTROLLERS: spin::Once<Vec<Mutex<Controller>>> = spin::Once::new();
/// Each controller's registers, for the interrupt handler (`0` past those started).
static ABARS: [AtomicU64; MAX_CONTROLLERS] = [const { AtomicU64::new(0) }; MAX_CONTROLLERS];
/// Each port's interrupt status since its command was issued, as the interrupt handler found it
/// (and acknowledged it).
static EVENTS: [[AtomicU32; MAX_PORTS]; MAX_CONTROLLERS] =
    [const { [const { AtomicU32::new(0) }; MAX_PORTS] }; MAX_CONTROLLERS];
/// Each controller's `CAP`, and each port's received-FIS area, for the interrupt handler.
static CAPS: [AtomicU32; MAX_CONTROLLERS] = [const { AtomicU32::new(0) }; MAX_CONTROLLERS];
static RFIS: [[AtomicU64; MAX_PORTS]; MAX_CONTROLLERS] =
    [const { [const { AtomicU64::new(0) }; MAX_PORTS] }; MAX_CONTROLLERS];
/// Each controller's ports with a port multiplier on them.
static MULTIPLIERS: [AtomicU32; MAX_CONTROLLERS] = [const { AtomicU32::new(0) }; MAX_CONTROLLERS];
/// Each controller's ports whose drives the port task retires before it looks
/// (`simulate_unplug`).
static UNPLUG: [AtomicU32; MAX_CONTROLLERS] = [const { AtomicU32::new(0) }; MAX_CONTROLLERS];
/// Each port's hot plug task, controller-major (argument: its index here).
static TASKS: [Task; MAX_CONTROLLERS * MAX_PORTS] = port_tasks();

const fn port_tasks() -> [Task; MAX_CONTROLLERS * MAX_PORTS] {
    let mut tasks = [const { Task::new(hotplug, 0) }; MAX_CONTROLLERS * MAX_PORTS];
    let mut i = 0;
    while i < tasks.len() {
        tasks[i] = Task::new(hotplug, i);
        i += 1;
    }
    tasks
}

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static IRQS: AtomicU64 = AtomicU64::new(0);
/// The boot probe is done: what's found from now on is hot plugged (the log says so).
static PROBED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The probe's log prefix: the boot log's, or hot plug's.
fn tag() -> &'static str {
    if PROBED.load(Ordering::Relaxed) { "[ahci]" } else { "[boot] ahci:" }
}

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
                let mut changed = status & IE_HOTPLUG != 0;
                if changed {
                    mmio_write(regs, port_reg(port, PX_SERR), SERR_DIAG_N | SERR_DIAG_X);
                }
                mmio_write(regs, port_reg(port, PX_IS), status);
                if status & IS_SDBS != 0 && MULTIPLIERS[c].load(Ordering::Relaxed) & 1 << port != 0 {
                    changed |= multiplier_notified(c, port, regs);
                }
                if changed {
                    subr_taskqueue::enqueue(&TASKQUEUE_THREAD, &TASKS[c * MAX_PORTS + port as usize]);
                }
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

/// Whether the multiplier on `port` of controller `c` sent a notification (its control port's
/// Set Device Bits FIS with the notification bit), which this clears: from `PxSNTF` with
/// `CAP.SSNTF`, else from the received FIS.
fn multiplier_notified(c: usize, port: u8, regs: u64) -> bool {
    if CAPS[c].load(Ordering::Relaxed) & CAP_SSNTF != 0 {
        let sntf = mmio_read(regs, port_reg(port, PX_SNTF));
        mmio_write(regs, port_reg(port, PX_SNTF), sntf);
        return sntf & 1 << PMP_CONTROL != 0;
    }
    let rfis = RFIS[c][port as usize].load(Ordering::Relaxed);
    if rfis == 0 {
        return false;
    }
    let flags = (rfis + (RFIS_SDB - RFIS_AT) as u64 + 1) as *mut u8;
    // SAFETY: byte 1 of the port's received Set Device Bits FIS, in its own page.
    let v = unsafe { flags.read_volatile() };
    if v & 0x80 == 0 {
        return false;
    }
    // SAFETY: as above.
    unsafe { flags.write_volatile(v & 0x7F) };
    v & 0x0F == PMP_CONTROL
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

    /// Where it's plugged in: controller, port, multiplier port.
    pub fn place(&self) -> (u8, u8, Option<u8>) {
        (self.controller, self.port, self.pmp)
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
    pub serial: String,
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

    /// Gives `port` its page, resets its link, and starts it if a drive answers and comes ready
    /// (spinning: the boot probe's way); whether one did.
    fn bring_up(&self, port: u8) -> bool {
        if !self.link_up(port) {
            return false;
        }
        if !poll(READY_MS, || self.ready(port)) {
            serial_println!("{} sata{}.{}: the drive stays busy -- not used", tag(), self.index, port);
            return false;
        }
        true
    }

    /// The drive on `port` is ready for a command: neither busy nor waiting for data.
    fn ready(&self, port: u8) -> bool {
        self.pread(port, PX_TFD) & (TFD_BSY | TFD_DRQ) == 0
    }

    /// Gives `port` its page and resets its link, hot plug's interrupts off (`arm_hotplug` puts
    /// them back); whether a drive's link came up.
    fn link_up(&self, port: u8) -> bool {
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
        true
    }

    /// Turns `port`'s hot plug interrupts on, the changes so far (the driver's own resets')
    /// forgotten. A controller without its interrupt has none.
    fn arm_hotplug(&self, port: u8) {
        if !self.irq || self.pages[port as usize].is_none() {
            return;
        }
        self.pwrite(port, PX_SERR, u32::MAX);
        self.pwrite(port, PX_IS, u32::MAX);
        self.pwrite(port, PX_IE, IE_COMPLETION | IE_HOTPLUG);
    }

    /// Whether `port`'s link is up with a device on it.
    fn link_present(&self, port: u8) -> bool {
        self.pread(port, PX_SSTS) & 0xF == DET_PRESENT
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
            if let Some(sig) = self.multiplier_port(port, m) {
                found.push((m, sig));
            }
        }
        found
    }

    /// Resets the link of the multiplier's device port `m` and, if a drive comes up on it, soft
    /// resets the drive; its signature.
    fn multiplier_port(&self, port: u8, m: u8) -> Option<u32> {
        self.pm_write(port, m, PSCR_SCONTROL, 0x301);
        delay_ms(2);
        self.pm_write(port, m, PSCR_SCONTROL, 0x300);
        let det = || self.pm_read(port, m, PSCR_SSTATUS).map_or(0, |s| s & 0xF);
        if !poll(20, || det() != 0) || !poll(1000, || det() == DET_PRESENT) {
            return None;
        }
        self.pm_write(port, m, PSCR_SERROR, u32::MAX);
        self.pwrite(port, PX_SERR, u32::MAX);
        self.soft_reset(port, m)
    }

    /// Asks the multiplier on `port` to notify the host of its device ports' PhyRdy changes
    /// (asynchronous notification, `GSCR[96]` bit 3, for `PSCR[1]`'s `DIAG.N`); whether it will.
    fn multiplier_notify(&self, port: u8) -> bool {
        let Some(features) = self.pm_read(port, PMP_CONTROL, GSCR_FEATURES) else { return false };
        if features & FEATURE_NOTIFY == 0 {
            return false;
        }
        let enabled = self.pm_read(port, PMP_CONTROL, GSCR_FEATURES_EN).unwrap_or(0);
        self.pm_write(port, PMP_CONTROL, GSCR_ERROR_EN, SERR_DIAG_N)
            && self.pm_write(port, PMP_CONTROL, GSCR_FEATURES_EN, enabled | FEATURE_NOTIFY)
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
        let name = Unit { controller: self.index as u8, port, pmp, atapi, lba48: false }.name();
        let Some(words) = self.identify(port, pmp.unwrap_or(0), atapi) else {
            serial_println!("{} {}: signature {:#010x}, no answer to IDENTIFY -- not used", tag(), name, sig);
            return None;
        };
        if atapi && pmp.is_none() {
            self.pwrite(port, PX_CMD, self.pread(port, PX_CMD) | CMD_ATAPI);
        }
        let found = self.identity(port, pmp, atapi, &words);
        match &found {
            Ok(f) if atapi => {
                serial_println!("{} {}: CD drive \"{}\"", tag(), name, f.model);
            }
            Ok(f) => {
                serial_println!(
                    "{} {}: disk \"{}\", {} MiB{}{}",
                    tag(),
                    name,
                    f.model,
                    f.sectors * f.sector_size as u64 >> 20,
                    if f.unit.lba48 { ", LBA48" } else { "" },
                    if f.sector_size != 512 { alloc::format!(", {}-byte sectors", f.sector_size) } else { String::new() }
                );
            }
            Err(size) => {
                serial_println!("{} {}: sectors of {} bytes aren't driven -- not used", tag(), name, size);
            }
        }
        found.ok()
    }

    /// The drive `IDENTIFY (PACKET) DEVICE` answered `words` for, at multiplier port `pmp` of
    /// `port`; `Err` with its sector size if that isn't one driven.
    fn identity(&self, port: u8, pmp: Option<u8>, atapi: bool, words: &[u16; 256]) -> Result<Found, u32> {
        let mut unit = Unit { controller: self.index as u8, port, pmp, atapi, lba48: false };
        let model = super::ata::model_of(words);
        let serial = super::ata::serial_of(words);
        if atapi {
            return Ok(Found { unit, model, serial, sectors: 0, sector_size: 2048 });
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
            return Err(sector_size);
        }
        Ok(Found { unit, model, serial, sectors, sector_size })
    }

    /// Whether the drive at `unit` is still the one `was` describes: it answers `IDENTIFY` with
    /// the same model, serial number and size.
    fn same_drive(&self, unit: &Unit, was: &Found) -> bool {
        let Some(words) = self.identify(unit.port, unit.pm_port(), unit.atapi) else { return false };
        self.identity(unit.port, unit.pmp, unit.atapi, &words).is_ok_and(|now| {
            now.model == was.model
                && now.serial == was.serial
                && (unit.atapi || (now.sectors == was.sectors && now.sector_size == was.sector_size))
        })
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
            for port in 0..MAX_PORTS as u8 {
                c.arm_hotplug(port);
            }
            controllers.push(Mutex::new(c));
        }
    }
    CONTROLLERS.call_once(|| controllers);
    PROBED.store(true, Ordering::Relaxed);
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
    for (port, page) in pages.iter().enumerate() {
        if let Some(page) = page {
            RFIS[n][port].store(page.virt.as_u64() + RFIS_AT as u64, Ordering::Relaxed);
        }
    }
    CAPS[n].store(cap, Ordering::Relaxed);
    let irq = pci.interrupt_line;
    let irq_ok = (3..16).contains(&irq);
    let c = Controller { index: n, regs, cap, pages, buffer, irq: irq_ok };

    // The interrupt before the ports are probed: the probe's commands complete by it.
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
        if c.pages[port as usize].is_some() && c.bring_up(port) {
            found.extend(c.probe_port(port));
        }
    }
    found
}

impl Controller {
    /// Probes what answers on `port`, its link up and the drive ready: a drive, or a port
    /// multiplier and the drives behind it.
    fn probe_port(&self, port: u8) -> Vec<Found> {
        let mut found = Vec::new();
        MULTIPLIERS[self.index].fetch_and(!(1 << port), Ordering::Relaxed);
        if self.cap & CAP_SPM == 0 {
            self.start(port);
            found.extend(self.probe(port, None, self.pread(port, PX_SIG)));
            return found;
        }
        // A soft reset to the multiplier's control port: a multiplier answers with its
        // signature, a drive with its own (PMA may only change while the port is stopped).
        self.pwrite(port, PX_CMD, self.pread(port, PX_CMD) | CMD_PMA);
        self.start(port);
        let sig = self.soft_reset(port, PMP_CONTROL);
        if sig == Some(SIG_PMP) {
            let drives = self.multiplier_ports(port);
            let notify = self.irq && self.multiplier_notify(port);
            if notify {
                MULTIPLIERS[self.index].fetch_or(1 << port, Ordering::Relaxed);
            }
            serial_println!(
                "{} sata{}.{}: port multiplier, {} drives{}",
                tag(),
                self.index,
                port,
                drives.len(),
                if notify { "" } else { " (no notification: drives plugged into it later aren't seen)" }
            );
            for (m, sig) in drives {
                found.extend(self.probe(port, Some(m), sig));
            }
            return found;
        }
        self.stop(port, false);
        self.pwrite(port, PX_CMD, self.pread(port, PX_CMD) & !CMD_PMA);
        self.start(port);
        found.extend(self.probe(port, None, sig.unwrap_or_else(|| self.pread(port, PX_SIG))));
        found
    }
}

/// Runs `f` on controller `c`, holding the giant lock and then its lock (the module doc's order).
fn locked<R>(c: &Mutex<Controller>, f: impl FnOnce(&Controller) -> R) -> R {
    let _giant = crate::fs::fslock::Giant::enter();
    f(&c.lock())
}

/// Hands each drive found to the disk registry (the giant lock held: it reads their partitions).
fn attach(found: Vec<Found>) {
    let _giant = crate::fs::fslock::Giant::enter();
    for f in found {
        super::disk::hot_attach(f);
    }
}

/// Retires the registered drives at controller `c` port `port`: all of them with `m` `None`, else
/// the one at multiplier port `m` (`Some(None)`: the one plugged into the port itself).
fn retire(c: u8, port: u8, m: Option<Option<u8>>) {
    let _giant = crate::fs::fslock::Giant::enter();
    for (disk, unit) in super::disk::ahci_drives(c, port) {
        if m.is_none_or(|m| unit.place().2 == m) {
            super::disk::retire(disk);
        }
    }
}

/// A port's hot plug task (`TASKS`; `arg` is `controller * MAX_PORTS + port`), run on
/// `taskqueue_thread`: once the link settles, a port with no link has its drives retired; one with
/// a multiplier on it has the multiplier's changed ports looked at; one with a drive registered has
/// it identified again (a different drive is the old one's retiring and the new one's arriving;
/// the same one, nothing); an empty one with a link is brought up and probed as at boot, sleeping
/// while the drive comes ready.
extern "C" fn hotplug(arg: usize, _pending: u32) {
    let (index, port) = (arg / MAX_PORTS, (arg % MAX_PORTS) as u8);
    let Some(c) = controller(index as u8) else { return };
    let unplug = UNPLUG[index].fetch_and(!(1 << port), Ordering::Relaxed) & 1 << port != 0;
    if unplug {
        // Everything on the port goes, a multiplier's drives too: the port is probed whole again.
        MULTIPLIERS[index].fetch_and(!(1 << port), Ordering::Relaxed);
        retire(index as u8, port, None);
    } else {
        crate::kern::kern_synch::pause(SETTLE_TICKS);
    }
    if !locked(c, |c| c.link_present(port)) {
        MULTIPLIERS[index].fetch_and(!(1 << port), Ordering::Relaxed);
        retire(index as u8, port, None);
        return;
    }
    if MULTIPLIERS[index].load(Ordering::Relaxed) & 1 << port != 0 {
        multiplier_changed(c, index as u8, port);
        return;
    }
    let drives = super::disk::ahci_drives(index as u8, port);
    if let Some((disk, unit)) = drives.first() {
        let Some(was) = super::disk::ahci_identity(*disk) else { return };
        if locked(c, |c| c.same_drive(unit, &was)) {
            return;
        }
        retire(index as u8, port, None);
    }
    if !locked(c, |c| c.link_up(port)) {
        locked(c, |c| c.arm_hotplug(port));
        return;
    }
    let deadline = tsc::now() + tsc::ms_to_cycles(READY_MS);
    while !locked(c, |c| c.ready(port)) {
        if tsc::now() >= deadline {
            serial_println!("[ahci] sata{}.{}: the drive stays busy -- not used", index, port);
            locked(c, |c| c.arm_hotplug(port));
            return;
        }
        crate::kern::kern_synch::pause(1);
    }
    let found = locked(c, |c| {
        let found = c.probe_port(port);
        c.arm_hotplug(port);
        found
    });
    attach(found);
    // A change while the port's interrupts were off: look again.
    if !locked(c, |c| c.link_present(port)) {
        subr_taskqueue::enqueue(&TASKQUEUE_THREAD, &TASKS[arg]);
    }
}

/// The multiplier on `port` notified a change: each device port it says changed (`GSCR[32]`) has
/// its `PSCR[1]` cleared, then its drive retired if its link went, identified again if it stayed
/// (a different one replaces it), or probed if one arrived.
fn multiplier_changed(c: &Mutex<Controller>, index: u8, port: u8) {
    let changed: Vec<(u8, bool)> = locked(c, |c| {
        let bits = c.pm_read(port, PMP_CONTROL, GSCR_ERROR).unwrap_or(0);
        (0..PMP_MAX_PORTS as u8)
            .filter(|m| bits & 1 << m != 0)
            .map(|m| {
                c.pm_write(port, m, PSCR_SERROR, u32::MAX);
                (m, c.pm_read(port, m, PSCR_SSTATUS).is_some_and(|s| s & 0xF == DET_PRESENT))
            })
            .collect()
    });
    for (m, up) in changed {
        let drive = super::disk::ahci_drives(index, port).into_iter().find(|(_, u)| u.place().2 == Some(m));
        if let Some((disk, unit)) = drive {
            let same = up && super::disk::ahci_identity(disk).is_some_and(|was| locked(c, |c| c.same_drive(&unit, &was)));
            if same {
                continue;
            }
            retire(index, port, Some(Some(m)));
        }
        if up {
            let found = locked(c, |c| c.multiplier_port(port, m).and_then(|sig| c.probe(port, Some(m), sig)));
            attach(found.into_iter().collect());
        }
    }
}

/// Pulls the drives on `unit`'s port out in software (`debug.disk.unplug`): its task retires
/// them, then finds the port as it is -- the drives still there -- and registers them again.
pub fn simulate_unplug(unit: &Unit) {
    UNPLUG[unit.controller as usize].fetch_or(1 << unit.port, Ordering::Relaxed);
    subr_taskqueue::enqueue(&TASKQUEUE_THREAD, &TASKS[unit.controller as usize * MAX_PORTS + unit.port as usize]);
}
