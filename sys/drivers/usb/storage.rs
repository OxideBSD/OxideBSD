//! USB mass storage over `super::xhci`: the Bulk-Only Transport (BOT, USB Mass Storage Class Bulk-
//! Only Transport 1.0) carrying `drivers::scsi` commands, so a USB stick or disk becomes a disk in
//! the registry (`drivers::disk`: `usb0`, `usb1`, ...). Only BOT (bInterfaceProtocol `0x50`) with
//! the SCSI transparent command set (`0x06`); UAS is a later step (`INSTALLER.md` §5.3).
//!
//! A command is three bulk transfers: a 31-byte Command Block Wrapper out, an optional data stage
//! in or out, and a 13-byte Command Status Wrapper in (BOT 1.0 §5.1). A failed command (CSW status
//! 1) is followed by `REQUEST SENSE` here, so `command` returns `scsi::ScsiError::Sense` with the
//! real sense -- the autosense `drivers::scsi` expects, the same virtio-scsi gives.
//!
//! **The transfers themselves are driven by `super`'s Event Ring service** (interrupt or tick):
//! `super::storage_xfer` enqueues one stage on the device's bulk ring and sleeps (`dma`) until the
//! completion is recorded, so a disk read schedules other work instead of spinning. Enumeration
//! (control transfers on ep0) runs synchronously at bring-up, before the ring has a service owner,
//! exactly as `hid_keyboard`'s does.

use alloc::string::String;

use x86_64::structures::paging::{FrameAllocator, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use super::super::dma::DmaBuffer;
use super::super::scsi::{self, Data, ScsiError, Transport};
use super::enumerate::EnumeratedDevice;
use super::xhci::{
    EndpointType, TrbRing, Xhci, alloc_zeroed_page, endpoint_dci, write_endpoint_context,
    write_input_control_context, write_slot_context,
};
use crate::serial_println;

// Standard USB requests and descriptor types (USB 2.0 §9.4), as this file needs them.
const REQ_SET_CONFIGURATION: u8 = 0x09;
const BM_STD_HOST_TO_DEV: u8 = 0x00;

// Mass-storage class (USB Mass Storage Class spec), interface descriptor fields.
const CLASS_MASS_STORAGE: u8 = 0x08;
const SUBCLASS_SCSI_TRANSPARENT: u8 = 0x06;
const PROTOCOL_BULK_ONLY: u8 = 0x50;

// Bulk-Only Transport wrappers (BOT 1.0 §5.1/5.2).
const CBW_SIGNATURE: u32 = 0x4342_5355; // "USBC" little-endian
const CSW_SIGNATURE: u32 = 0x5342_5355; // "USBS"
const CBW_LEN: usize = 31;
const CSW_LEN: usize = 13;
const CBW_FLAG_DATA_IN: u8 = 0x80;

// CSW bStatus.
const CSW_PASSED: u8 = 0;
const CSW_FAILED: u8 = 1;

/// The data bounce buffer, in pages, past page 0 (which holds the CBW and CSW). One SCSI data
/// transfer moves at most this much; `scsi::read`/`write` chunk larger requests to it.
const DATA_PAGES: usize = 32; // 128 KiB
const REQUEST_SENSE: u8 = 0x03;

/// A configured mass-storage device: its slot, its two bulk endpoints and their transfer rings,
/// a DMA buffer, and the completion slot `super`'s Event Ring service writes (one BOT command is
/// in flight at a time, so one slot suffices).
pub(crate) struct StorageDevice {
    slot_id: u8,
    in_dci: u8,
    out_dci: u8,
    in_ring: TrbRing,
    out_ring: TrbRing,
    buffer: DmaBuffer,
    /// The endpoint DCI a transfer is outstanding on (0 = none); set before ringing the doorbell,
    /// cleared when the completion is recorded.
    pending_ep: u8,
    done: bool,
    ok: bool,
    residual: u32,
}

impl StorageDevice {
    pub(crate) fn slot_id(&self) -> u8 {
        self.slot_id
    }

    /// A lightweight, `Copy` transport handle for this device: everything `command` needs that
    /// never changes (the mutable rings and completion flags stay here, reached by `slot_id`).
    pub(crate) fn unit(&self) -> MsdUnit {
        MsdUnit {
            slot_id: self.slot_id,
            in_dci: self.in_dci,
            out_dci: self.out_dci,
            buf_phys: self.buffer.phys,
            buf_virt: self.buffer.virt,
        }
    }

    pub(crate) fn ring_for(&mut self, ep_dci: u8) -> &mut TrbRing {
        if ep_dci == self.in_dci {
            &mut self.in_ring
        } else {
            &mut self.out_ring
        }
    }

    /// Arms the device to wait for a completion on `ep_dci` (called under the state lock, just
    /// before ringing the doorbell).
    pub(crate) fn arm(&mut self, ep_dci: u8) {
        self.pending_ep = ep_dci;
        self.done = false;
    }

    /// Records an Event Ring TRB if it's this device's outstanding completion; `true` if it was.
    /// Called by `super::service` for each drained event.
    pub(crate) fn handle_event(&mut self, evt: super::xhci::RawTrb) -> bool {
        if self.pending_ep == 0
            || !evt.is_transfer_event()
            || evt.slot_id() != self.slot_id
            || evt.endpoint_id() != self.pending_ep
        {
            return false;
        }
        self.ok = evt.is_success();
        self.residual = evt.transfer_residual();
        self.done = true;
        self.pending_ep = 0;
        true
    }

    /// Whether the outstanding transfer has completed, and its `(success, residual)`.
    pub(crate) fn completion(&self) -> Option<(bool, u32)> {
        self.done.then_some((self.ok, self.residual))
    }
}

/// A transport handle to one mass-storage device (`drivers::scsi::Transport`). `Copy` and free of
/// the device's mutable state, which lives in `super`'s `StorageDevice`, reached by `slot_id`.
#[derive(Clone, Copy)]
pub(crate) struct MsdUnit {
    pub(crate) slot_id: u8,
    in_dci: u8,
    out_dci: u8,
    buf_phys: PhysAddr,
    buf_virt: VirtAddr,
}

/// The data region's capacity (one SCSI data transfer's worth).
const DATA_CAPACITY: usize = DATA_PAGES * 4096;

impl MsdUnit {
    /// Blocks of `block_size` bytes one command moves at most -- the data region's worth, matching
    /// `virtio_scsi::Unit::max_blocks`.
    pub(crate) fn max_blocks(&self, block_size: usize) -> usize {
        (DATA_CAPACITY / block_size).max(1)
    }

    fn cbw_phys(&self) -> PhysAddr {
        self.buf_phys
    }
    fn csw_phys(&self) -> PhysAddr {
        self.buf_phys + 64u64
    }
    fn data_phys(&self) -> PhysAddr {
        self.buf_phys + 4096u64
    }

    /// Writes `n` bytes of the DMA buffer at `offset` (volatile; the region is device-visible).
    fn write_buf(&self, offset: usize, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            unsafe {
                core::ptr::write_volatile(self.buf_virt.as_mut_ptr::<u8>().add(offset + i), b)
            };
        }
    }
    fn read_buf(&self, offset: usize, out: &mut [u8]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = unsafe { core::ptr::read_volatile(self.buf_virt.as_ptr::<u8>().add(offset + i)) };
        }
    }

    /// One raw Bulk-Only transaction: CBW out, optional data, CSW in. Returns the bytes moved in
    /// the data stage. `Err(Some(status))` is a CSW status (1 failed, 2 phase error); `Err(None)`
    /// is a transport failure (timeout, stall, bad CSW). Does no sense recovery -- `command` does.
    fn transaction(&self, cdb: &[u8], dir_in: bool, dlen: usize) -> Result<usize, Option<u8>> {
        if dlen > DATA_CAPACITY || cdb.len() > 16 {
            return Err(None);
        }
        let tag = super::next_storage_tag();
        // Command Block Wrapper.
        let mut cbw = [0u8; CBW_LEN];
        cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(dlen as u32).to_le_bytes());
        cbw[12] = if dir_in { CBW_FLAG_DATA_IN } else { 0 };
        cbw[13] = 0; // LUN 0
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        self.write_buf(0, &cbw);

        // Stage 1: CBW on bulk-OUT.
        if super::storage_xfer(
            self.slot_id,
            self.out_dci,
            self.cbw_phys(),
            CBW_LEN as u32,
            false,
        )
        .is_err()
        {
            crate::serial_println!("[usb] BOT slot {}: CBW stage failed", self.slot_id);
            return Err(None);
        }

        // Stage 2: data (device-visible buffer at `data_phys`).
        let mut moved = 0;
        if dlen > 0 {
            let ep = if dir_in { self.in_dci } else { self.out_dci };
            let residual =
                match super::storage_xfer(self.slot_id, ep, self.data_phys(), dlen as u32, true) {
                    Ok(r) => r,
                    Err(_) => {
                        crate::serial_println!(
                            "[usb] BOT slot {}: data stage failed",
                            self.slot_id
                        );
                        return Err(None);
                    }
                };
            moved = dlen - (residual as usize).min(dlen);
        }

        // Stage 3: CSW on bulk-IN.
        if super::storage_xfer(
            self.slot_id,
            self.in_dci,
            self.csw_phys(),
            CSW_LEN as u32,
            false,
        )
        .is_err()
        {
            crate::serial_println!("[usb] BOT slot {}: CSW stage failed", self.slot_id);
            return Err(None);
        }
        let mut csw = [0u8; CSW_LEN];
        self.read_buf(64, &mut csw);
        let sig = u32::from_le_bytes(csw[0..4].try_into().unwrap());
        let rtag = u32::from_le_bytes(csw[4..8].try_into().unwrap());
        if sig != CSW_SIGNATURE || rtag != tag {
            crate::serial_println!(
                "[usb] BOT slot {}: bad CSW sig {:#x} tag {:#x} (want {:#x})",
                self.slot_id,
                sig,
                rtag,
                tag
            );
            return Err(None);
        }
        let status = csw[12];
        if status == CSW_PASSED {
            Ok(moved)
        } else {
            Err(Some(status))
        }
    }
}

impl Transport for MsdUnit {
    fn command(&self, cdb: &[u8], data: Data) -> Result<usize, ScsiError> {
        let _serialize = super::storage_command_lock();
        let (dir_in, dlen) = match &data {
            Data::None => (false, 0),
            Data::In(b) => (true, b.len()),
            Data::Out(b) => (false, b.len()),
        };
        if let Data::Out(b) = &data {
            self.write_buf(4096, b);
        }
        match self.transaction(cdb, dir_in, dlen) {
            Ok(moved) => {
                if let Data::In(b) = data {
                    self.read_buf(4096, &mut b[..moved]);
                }
                Ok(moved)
            }
            Err(Some(CSW_FAILED)) => Err(self.request_sense()),
            Err(_) => Err(ScsiError::Transport), // phase error or transport failure
        }
    }
}

impl MsdUnit {
    /// `REQUEST SENSE` after a failed command, so the caller gets real sense data. A failure here
    /// is itself a transport error.
    fn request_sense(&self) -> ScsiError {
        let cdb = [REQUEST_SENSE, 0, 0, 0, 18, 0];
        match self.transaction(&cdb, true, 18) {
            Ok(n) if n >= 14 => {
                let mut sense = [0u8; 18];
                self.read_buf(4096, &mut sense);
                ScsiError::Sense(sense[2] & 0x0F, sense[12], sense[13])
            }
            _ => ScsiError::Transport,
        }
    }
}

/// A mass-storage device found and configured at boot.
pub(crate) struct Found {
    pub(crate) device_type: u8,
    pub(crate) model: String,
    pub(crate) unit: MsdUnit,
}

/// One interface's BOT endpoints, parsed from a configuration descriptor.
struct BotConfig {
    config_value: u8,
    interface_number: u8,
    in_ep: u8,
    out_ep: u8,
    in_max_packet: u16,
    out_max_packet: u16,
}

/// Walks a configuration descriptor for a Bulk-Only mass-storage interface and its bulk IN/OUT
/// endpoints. `None` if the device isn't BOT mass storage.
fn parse_bot_config(bytes: &[u8]) -> Option<BotConfig> {
    if bytes.len() < 9 || bytes[1] != 2 {
        return None;
    }
    let config_value = bytes[5];
    let mut i = bytes[0] as usize; // past the config header
    let mut in_interface = false;
    let mut interface_number = 0u8;
    let (mut in_ep, mut out_ep) = (0u8, 0u8);
    let (mut in_mp, mut out_mp) = (0u16, 0u16);
    while i + 2 <= bytes.len() {
        let len = bytes[i] as usize;
        let dtype = bytes[i + 1];
        if len < 2 || i + len > bytes.len() {
            break;
        }
        match dtype {
            4 if len >= 9 => {
                // Interface descriptor.
                in_interface = bytes[i + 5] == CLASS_MASS_STORAGE
                    && bytes[i + 6] == SUBCLASS_SCSI_TRANSPARENT
                    && bytes[i + 7] == PROTOCOL_BULK_ONLY;
                if in_interface {
                    interface_number = bytes[i + 2];
                    in_ep = 0;
                    out_ep = 0;
                }
            }
            5 if len >= 7 && in_interface => {
                // Endpoint descriptor: bulk (attributes bits 1:0 == 0b10) only.
                let addr = bytes[i + 2];
                let attrs = bytes[i + 3];
                let max_packet = u16::from_le_bytes([bytes[i + 4], bytes[i + 5]]) & 0x7FF;
                if attrs & 0x3 == 2 {
                    if addr & 0x80 != 0 {
                        in_ep = addr;
                        in_mp = max_packet;
                    } else {
                        out_ep = addr;
                        out_mp = max_packet;
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    (in_ep != 0 && out_ep != 0).then_some(BotConfig {
        config_value,
        interface_number,
        in_ep,
        out_ep,
        in_max_packet: in_mp,
        out_max_packet: out_mp,
    })
}

/// Finishes a device already enumerated (`super::enumerate`) as a BOT mass-storage device:
/// `SET_CONFIGURATION` and configure both bulk endpoints. `None` if it isn't BOT mass storage
/// (before anything is configured, so the caller can try another driver on the same slot) or on
/// failure.
pub(crate) fn finish(
    controller: &mut Xhci,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    phys_mem_offset: VirtAddr,
    dev: &mut EnumeratedDevice,
) -> Option<StorageDevice> {
    let bot = parse_bot_config(&dev.config)?;
    serial_println!(
        "[usb] port {}: BOT mass storage (VID:PID {:04x}:{:04x}), interface {}, bulk IN {:#04x} OUT {:#04x}",
        dev.port,
        dev.vendor,
        dev.product,
        bot.interface_number,
        bot.in_ep,
        bot.out_ep
    );

    controller.control_transfer_in(
        &mut dev.ep0_ring,
        dev.slot_id,
        BM_STD_HOST_TO_DEV,
        REQ_SET_CONFIGURATION,
        bot.config_value as u16,
        0,
        None,
    )?;

    // Configure both bulk endpoints in one Configure Endpoint command.
    let in_dci = endpoint_dci(bot.in_ep & 0x0F, true);
    let out_dci = endpoint_dci(bot.out_ep & 0x0F, false);
    let (in_virt, in_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
    let (out_virt, out_phys) = alloc_zeroed_page(frame_allocator, phys_mem_offset)?;
    let in_ring = TrbRing::new(in_virt, in_phys);
    let out_ring = TrbRing::new(out_virt, out_phys);
    let max_dci = in_dci.max(out_dci);

    write_input_control_context(dev.input_virt, (1 << 0) | (1 << in_dci) | (1 << out_dci), 0);
    write_slot_context(dev.input_virt + 32, dev.speed, dev.port, max_dci);
    write_endpoint_context(
        dev.input_virt + 32 * (in_dci as u64 + 1),
        EndpointType::BulkIn,
        bot.in_max_packet.max(8),
        0,
        in_ring.initial_dequeue_pointer(),
    );
    write_endpoint_context(
        dev.input_virt + 32 * (out_dci as u64 + 1),
        EndpointType::BulkOut,
        bot.out_max_packet.max(8),
        0,
        out_ring.initial_dequeue_pointer(),
    );
    if !controller.configure_endpoint(dev.slot_id, dev.input_phys) {
        serial_println!(
            "[usb] port {}: Configure Endpoint failed (storage)",
            dev.port
        );
        return None;
    }

    let buffer = DmaBuffer::alloc(frame_allocator, phys_mem_offset, 1 + DATA_PAGES, false)?;
    Some(StorageDevice {
        slot_id: dev.slot_id,
        in_dci,
        out_dci,
        in_ring,
        out_ring,
        buffer,
        pending_ep: 0,
        done: false,
        ok: false,
        residual: 0,
    })
}

/// Probes a configured device for its logical unit (LUN 0): INQUIRY, then whether it's usable.
/// `None` if `INQUIRY` finds nothing. The bulk transfers run through `super`'s Event Ring service.
pub(crate) fn probe(unit: MsdUnit) -> Option<Found> {
    let (device_type, _removable, model) = scsi::inquiry(&unit)?;
    Some(Found {
        device_type,
        model,
        unit,
    })
}
