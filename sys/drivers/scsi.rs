//! SCSI commands (SPC, SBC, MMC), over whatever carries them (`Transport`): ATAPI packets on IDE
//! (`ata`), virtio-scsi requests (`virtio_scsi`), and later AHCI and USB mass storage
//! (`OxideBSD-doc/INSTALLER.md` §5.3). A transport moves one command descriptor block and its
//! data; this file builds the commands and reads their answers.
//!
//! Sense data is fixed-format (SPC 4.5.3): key, additional sense code and qualifier. A transport
//! returns it with a failed command: autosense (virtio-scsi) or a `REQUEST SENSE` of its own
//! (ATAPI).

use alloc::string::String;

/// A command's data phase.
pub enum Data<'a> {
    None,
    /// The device sends: read into the buffer.
    In(&'a mut [u8]),
    /// The device receives the buffer.
    Out(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScsiError {
    /// The command failed with this sense: key, additional sense code, qualifier.
    Sense(u8, u8, u8),
    /// The transport failed: no device, a timeout, a bus error.
    Transport,
}

/// What carries a command to one logical unit.
pub trait Transport {
    /// Sends `cdb` with `data`; the bytes moved, or why it failed.
    fn command(&self, cdb: &[u8], data: Data) -> Result<usize, ScsiError>;
}

const TEST_UNIT_READY: u8 = 0x00;
const INQUIRY: u8 = 0x12;
const PREVENT_ALLOW_MEDIUM_REMOVAL: u8 = 0x1E;
const READ_CAPACITY_10: u8 = 0x25;
const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2A;
const SYNCHRONIZE_CACHE_10: u8 = 0x35;
const READ_16: u8 = 0x88;
const WRITE_16: u8 = 0x8A;
const SERVICE_ACTION_IN_16: u8 = 0x9E;
const READ_CAPACITY_16: u8 = 0x10;

pub const SENSE_NOT_READY: u8 = 0x02;
pub const SENSE_UNIT_ATTENTION: u8 = 0x06;
/// Additional sense code "medium not present".
pub const ASC_NO_MEDIUM: u8 = 0x3A;

/// Peripheral device types (`INQUIRY` byte 0).
pub const TYPE_DISK: u8 = 0x00;
pub const TYPE_CDROM: u8 = 0x05;

/// How long `capacity` waits for a unit whose medium is "becoming ready".
const READY_MS: u64 = 8_000;

/// A unit's `INQUIRY`: its peripheral device type, whether its medium is removable, and its
/// vendor and product, trimmed. `None` if there's no unit there (or the qualifier says the type
/// isn't connected).
pub fn inquiry(t: &dyn Transport) -> Option<(u8, bool, String)> {
    let mut d = [0u8; 36];
    let n = t.command(&[INQUIRY, 0, 0, 0, d.len() as u8, 0], Data::In(&mut d)).ok()?;
    if n < 32 || d[0] >> 5 != 0 {
        return None;
    }
    let text = |b: &[u8]| -> String {
        let s: String = b.iter().map(|&c| if c.is_ascii_graphic() || c == b' ' { c as char } else { '?' }).collect();
        String::from(s.trim())
    };
    let (vendor, product) = (text(&d[8..16]), text(&d[16..32]));
    let model = if vendor.is_empty() { product } else { alloc::format!("{vendor} {product}") };
    Some((d[0] & 0x1F, d[1] & 0x80 != 0, model))
}

/// Whether a medium is in the unit and readable, and if so its size: `(blocks, block size)`, from
/// `READ CAPACITY(10)`, or `(16)` past what it reaches; and whether the unit reported a unit
/// attention (the medium changed, or the unit was reset) since it was last asked. Waits out a
/// medium spinning up; `None` at once for an empty drive.
pub fn capacity(t: &dyn Transport) -> (Option<(u64, u32)>, bool) {
    let deadline = crate::cpu::tsc::now() + crate::cpu::tsc::ms_to_cycles(READY_MS);
    let mut changed = false;
    loop {
        match t.command(&[TEST_UNIT_READY, 0, 0, 0, 0, 0], Data::None) {
            Ok(_) => break,
            Err(ScsiError::Sense(SENSE_UNIT_ATTENTION, _, _)) if crate::cpu::tsc::now() < deadline => changed = true,
            Err(ScsiError::Sense(SENSE_NOT_READY, ASC_NO_MEDIUM, _)) => return (None, changed),
            Err(ScsiError::Sense(SENSE_NOT_READY, _, _)) if crate::cpu::tsc::now() < deadline => {
                core::hint::spin_loop();
            }
            Err(_) => return (None, changed),
        }
    }
    let mut cap = [0u8; 8];
    match t.command(&[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::In(&mut cap)) {
        Ok(8) => {}
        _ => return (None, changed),
    }
    let mut last = u32::from_be_bytes(cap[0..4].try_into().unwrap()) as u64;
    let mut size = u32::from_be_bytes(cap[4..8].try_into().unwrap());
    if last == 0xFFFF_FFFF {
        // Past 2^32 blocks: the 16-byte form.
        let mut cap = [0u8; 32];
        let mut cdb = [0u8; 16];
        cdb[0] = SERVICE_ACTION_IN_16;
        cdb[1] = READ_CAPACITY_16;
        cdb[13] = cap.len() as u8;
        match t.command(&cdb, Data::In(&mut cap)) {
            Ok(n) if n >= 12 => {
                last = u64::from_be_bytes(cap[0..8].try_into().unwrap());
                size = u32::from_be_bytes(cap[8..12].try_into().unwrap());
            }
            _ => return (None, changed),
        }
    }
    (Some((last + 1, size)), changed)
}

/// The `READ`/`WRITE` command for `count` blocks at `lba`: the 10-byte form where it reaches, else
/// the 16-byte one. Its length in `cdb`.
fn rw_cdb(write: bool, lba: u64, count: u32, cdb: &mut [u8; 16]) -> usize {
    *cdb = [0; 16];
    if lba + count as u64 <= u32::MAX as u64 && count <= u16::MAX as u32 {
        cdb[0] = if write { WRITE_10 } else { READ_10 };
        cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
        cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
        10
    } else {
        cdb[0] = if write { WRITE_16 } else { READ_16 };
        cdb[2..10].copy_from_slice(&lba.to_be_bytes());
        cdb[10..14].copy_from_slice(&count.to_be_bytes());
        16
    }
}

/// Reads whole blocks of `block_size` bytes from `lba` into `buf`, `max_blocks` per command.
pub fn read(t: &dyn Transport, lba: u64, block_size: usize, max_blocks: usize, buf: &mut [u8]) -> Result<(), ScsiError> {
    for (i, chunk) in buf.chunks_mut(max_blocks * block_size).enumerate() {
        let at = lba + (i * max_blocks) as u64;
        let mut cdb = [0u8; 16];
        let len = rw_cdb(false, at, (chunk.len() / block_size) as u32, &mut cdb);
        let want = chunk.len();
        if t.command(&cdb[..len], Data::In(chunk))? != want {
            return Err(ScsiError::Transport);
        }
    }
    Ok(())
}

/// Writes whole blocks from `buf` at `lba`, `max_blocks` per command, then `SYNCHRONIZE CACHE`s,
/// so they're durable when this returns.
pub fn write(t: &dyn Transport, lba: u64, block_size: usize, max_blocks: usize, buf: &[u8]) -> Result<(), ScsiError> {
    for (i, chunk) in buf.chunks(max_blocks * block_size).enumerate() {
        let at = lba + (i * max_blocks) as u64;
        let mut cdb = [0u8; 16];
        let len = rw_cdb(true, at, (chunk.len() / block_size) as u32, &mut cdb);
        t.command(&cdb[..len], Data::Out(chunk))?;
    }
    t.command(&[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None).map(|_| ())
}

/// Locks (`true`) or unlocks a removable medium in its drive.
pub fn lock(t: &dyn Transport, lock: bool) {
    let _ = t.command(&[PREVENT_ALLOW_MEDIUM_REMOVAL, 0, 0, 0, lock as u8, 0], Data::None);
}
