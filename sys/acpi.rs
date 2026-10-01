//! ACPI tables: finding them, and the one thing the kernel needs from AML, the `\_S5` (soft-off)
//! sleep type for powering the machine off.
//!
//! **Tables.** Limine hands over the RSDP (`boot::rsdp_address`); from it, the XSDT (ACPI 2.0+) or
//! the RSDT (1.0) lists every other table's physical address, each read through the direct map
//! and trusted only once its checksum validates. `cpu::hpet` finds its table here.
//!
//! **Powering off** (`reboot::poweroff`) means writing `SLP_TYPa | SLP_EN` to the PM1a control
//! register, and `SLP_TYPb | SLP_EN` to PM1b if there is one. The register ports come from the FADT
//! (`"FACP"`); the sleep types for S5 are AML, a `Name (_S5, Package () { a, b, ... })` in the
//! DSDT, which [`init`] finds by scanning the DSDT's bytes rather than interpreting AML -- as most
//! small kernels do. The scan accepts the encodings firmware actually emits for those integers
//! (`ZeroOp`, `OneOp`, `BytePrefix n`, and a bare byte). Everything is found once, at boot, and
//! logged; absence is never fatal, `poweroff` falls back to halting.

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::instructions::port::Port;

use crate::serial_println;

/// The 36-byte header every ACPI table but the RSDP starts with.
#[repr(C, packed)]
pub(crate) struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

const SDT_HEADER_SIZE: u64 = core::mem::size_of::<SdtHeader>() as u64;

/// The RSDP's first 20 bytes, common to every revision; a revision 2 RSDP continues with
/// `length: u32`, `xsdt_address: u64`, `extended_checksum: u8`.
#[repr(C, packed)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// Whether the `len` bytes at `virt` sum to zero, as every ACPI table's must.
fn checksum_ok(virt: VirtAddr, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        // SAFETY: the caller passes a table's own extent, inside the direct map.
        sum = sum.wrapping_add(unsafe { *(virt + i as u64).as_ptr::<u8>() });
    }
    sum == 0
}

fn read<T>(virt: VirtAddr) -> T {
    // SAFETY: callers read inside a table whose extent they have already checked.
    unsafe { core::ptr::read_unaligned(virt.as_ptr::<T>()) }
}

/// The table at physical `phys`, if it has signature `want` and a valid checksum.
fn table_at(hhdm: u64, phys: u64, want: &[u8; 4]) -> Option<VirtAddr> {
    if phys == 0 {
        return None;
    }
    let virt = VirtAddr::new(hhdm + phys);
    let header: SdtHeader = read(virt);
    if &header.signature != want {
        return None;
    }
    let length = header.length;
    if (length as u64) < SDT_HEADER_SIZE || !checksum_ok(virt, length as usize) {
        serial_println!(
            "[acpi] {} at {:#x} fails its checksum, ignored",
            core::str::from_utf8(want).unwrap_or("?"),
            phys
        );
        return None;
    }
    Some(virt)
}

/// The XSDT, or the RSDT on ACPI 1.0 firmware: its address and its entries' size.
fn root_table(hhdm: u64) -> Option<(VirtAddr, u64)> {
    let rsdp_virt = VirtAddr::new(crate::boot::rsdp_address()?);
    let rsdp: RsdpV1 = read(rsdp_virt);
    if &rsdp.signature != b"RSD PTR " || !checksum_ok(rsdp_virt, core::mem::size_of::<RsdpV1>()) {
        serial_println!("[acpi] the RSDP is invalid; no ACPI tables");
        return None;
    }
    if rsdp.revision >= 2 {
        let ext = rsdp_virt + core::mem::size_of::<RsdpV1>() as u64;
        let len: u32 = read(ext);
        let xsdt: u64 = read(ext + 4u64);
        if checksum_ok(rsdp_virt, len as usize)
            && let Some(v) = table_at(hhdm, xsdt, b"XSDT")
        {
            return Some((v, 8));
        }
    }
    table_at(hhdm, rsdp.rsdt_address as u64, b"RSDT").map(|v| (v, 4))
}

/// Finds the table with signature `sig` through the XSDT or RSDT. `hhdm` is the direct map's
/// offset. (The DSDT isn't listed there; the FADT points at it.)
pub fn find_table(hhdm: u64, sig: &[u8; 4]) -> Option<VirtAddr> {
    let (root, entry_size) = root_table(hhdm)?;
    let header: SdtHeader = read(root);
    let length = header.length as u64;
    let entries = length.saturating_sub(SDT_HEADER_SIZE) / entry_size;
    (0..entries).find_map(|i| {
        let at = root + SDT_HEADER_SIZE + i * entry_size;
        let phys = if entry_size == 8 {
            read::<u64>(at)
        } else {
            read::<u32>(at) as u64
        };
        table_at(hhdm, phys, sig)
    })
}

/// What powering off needs, from the FADT and the DSDT.
#[derive(Clone, Copy, Debug)]
pub struct SoftOff {
    pub pm1a_cnt: u16,
    /// 0 when the machine has no PM1b block.
    pub pm1b_cnt: u16,
    pub slp_typa: u16,
    pub slp_typb: u16,
    /// Where to write `acpi_enable` to put the chipset in ACPI mode, if the firmware hasn't
    /// (0: the machine is always in ACPI mode).
    pub smi_cmd: u32,
    pub acpi_enable: u8,
}

static SOFT_OFF: Mutex<Option<SoftOff>> = Mutex::new(None);

// FADT field offsets (ACPI 6.5, table 5.9).
const FADT_DSDT: u64 = 40;
const FADT_SMI_CMD: u64 = 48;
const FADT_ACPI_ENABLE: u64 = 52;
const FADT_PM1A_CNT_BLK: u64 = 64;
const FADT_PM1B_CNT_BLK: u64 = 68;
const FADT_X_DSDT: u64 = 140;
const FADT_X_PM1A_CNT_BLK: u64 = 172;
const FADT_X_PM1B_CNT_BLK: u64 = 184;
/// A Generic Address Structure's address space for I/O ports.
const GAS_SYSTEM_IO: u8 = 1;

/// A PM1 control block's port: the 32-bit field, or else the extended Generic Address Structure
/// when it is in I/O space.
fn pm1_port(fadt: VirtAddr, len: u64, legacy: u64, extended: u64) -> u16 {
    let port: u32 = read(fadt + legacy);
    if port != 0 {
        return port as u16;
    }
    if len >= extended + 12 && read::<u8>(fadt + extended) == GAS_SYSTEM_IO {
        return read::<u64>(fadt + extended + 4u64) as u16;
    }
    0
}

/// One AML integer at `aml[i]`: its value and its length. Besides the real encodings
/// (`ZeroOp`, `OneOp`, `BytePrefix n`, `WordPrefix n`, `DWordPrefix n`), a bare byte 2-7 is taken
/// as itself, as some firmware writes sleep types that way; prefixes 0x0D-0x0E (string, qword) are
/// not sleep types.
fn aml_integer(aml: &[u8], i: usize) -> Option<(u16, usize)> {
    let byte = |k: usize| aml.get(i + k).copied();
    match byte(0)? {
        0x00 => Some((0, 1)),
        0x01 => Some((1, 1)),
        0x0A => Some((byte(1)? as u16, 2)),
        0x0B => Some((u16::from_le_bytes([byte(1)?, byte(2)?]), 3)),
        0x0C => Some((u16::from_le_bytes([byte(1)?, byte(2)?]), 5)),
        b @ 0x02..=0x07 => Some((b as u16, 1)),
        _ => None,
    }
}

/// `SLP_TYPa` and `SLP_TYPb` from `Name (_S5, Package () { a, b, ... })` in the AML `aml`:
/// a `NameOp` (0x08, optionally followed by a root `\`) before `_S5_`, then `PackageOp` (0x12),
/// its `PkgLength` (1 to 4 bytes, the first byte's top two bits saying how many follow), the
/// element count, and the integers.
pub fn find_s5(aml: &[u8]) -> Option<(u16, u16)> {
    let mut at = 0;
    while let Some(pos) = aml[at..].windows(4).position(|w| w == b"_S5_") {
        let i = at + pos;
        at = i + 1;
        let named =
            (i >= 1 && aml[i - 1] == 0x08) || (i >= 2 && aml[i - 1] == b'\\' && aml[i - 2] == 0x08);
        if !named || aml.get(i + 4) != Some(&0x12) {
            continue;
        }
        let lead = *aml.get(i + 5)?;
        let mut j = i + 5 + 1 + (lead >> 6) as usize; // past PkgLength
        j += 1; // NumElements
        let (a, len) = aml_integer(aml, j)?;
        j += len;
        let (b, _) = aml_integer(aml, j)?;
        return Some((a, b));
    }
    None
}

/// Finds what powering off needs; called once at boot. Logs what it found or why not.
pub fn init(hhdm: u64) {
    let Some(fadt) = find_table(hhdm, b"FACP") else {
        serial_println!("[acpi] no FADT; poweroff will only halt");
        return;
    };
    let len = read::<SdtHeader>(fadt).length as u64;
    let pm1a_cnt = pm1_port(fadt, len, FADT_PM1A_CNT_BLK, FADT_X_PM1A_CNT_BLK);
    let pm1b_cnt = pm1_port(fadt, len, FADT_PM1B_CNT_BLK, FADT_X_PM1B_CNT_BLK);
    let x_dsdt = if len >= FADT_X_DSDT + 8 {
        read::<u64>(fadt + FADT_X_DSDT)
    } else {
        0
    };
    let dsdt_phys = if x_dsdt != 0 {
        x_dsdt
    } else {
        read::<u32>(fadt + FADT_DSDT) as u64
    };
    let Some(dsdt) = table_at(hhdm, dsdt_phys, b"DSDT") else {
        serial_println!("[acpi] no valid DSDT; poweroff will only halt");
        return;
    };
    let dsdt_len = read::<SdtHeader>(dsdt).length as u64;
    // SAFETY: the DSDT's extent, checksum-validated by `table_at`.
    let aml = unsafe {
        core::slice::from_raw_parts(
            (dsdt + SDT_HEADER_SIZE).as_ptr::<u8>(),
            (dsdt_len - SDT_HEADER_SIZE) as usize,
        )
    };
    let Some((slp_typa, slp_typb)) = find_s5(aml) else {
        serial_println!("[acpi] no \\_S5 in the DSDT; poweroff will only halt");
        return;
    };
    if pm1a_cnt == 0 {
        serial_println!("[acpi] the FADT has no PM1a control block; poweroff will only halt");
        return;
    }
    let off = SoftOff {
        pm1a_cnt,
        pm1b_cnt,
        slp_typa,
        slp_typb,
        smi_cmd: read(fadt + FADT_SMI_CMD),
        acpi_enable: read(fadt + FADT_ACPI_ENABLE),
    };
    serial_println!(
        "[acpi] S5: PM1a_CNT {:#x}, PM1b_CNT {:#x}, SLP_TYPa {}, SLP_TYPb {}",
        off.pm1a_cnt,
        off.pm1b_cnt,
        off.slp_typa,
        off.slp_typb
    );
    *SOFT_OFF.lock() = Some(off);
}

/// What [`init`] found, if powering off is possible.
pub fn soft_off() -> Option<SoftOff> {
    *SOFT_OFF.lock()
}

/// `SCI_EN`, bit 0 of PM1 control: set when the chipset is in ACPI mode.
const SCI_EN: u16 = 1 << 0;
/// `SLP_EN`, bit 13: starts the transition to the sleep state in `SLP_TYP` (bits 10-12).
const SLP_EN: u16 = 1 << 13;

/// Enters S5 (soft off). Returns only if the machine is still running afterwards.
pub fn enter_s5() {
    let Some(off) = soft_off() else { return };
    let mut pm1a = Port::<u16>::new(off.pm1a_cnt);
    // SAFETY: ports the firmware's own FADT names for exactly this.
    unsafe {
        if pm1a.read() & SCI_EN == 0 && off.smi_cmd != 0 && off.acpi_enable != 0 {
            Port::<u8>::new(off.smi_cmd as u16).write(off.acpi_enable);
            // The firmware sets SCI_EN when it has switched; a bounded wait (interrupts may be off,
            // so no timer).
            for _ in 0..1_000_000 {
                if pm1a.read() & SCI_EN != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
        }
        let keep = pm1a.read() & !(0b111 << 10);
        pm1a.write(keep | ((off.slp_typa & 0b111) << 10) | SLP_EN);
        if off.pm1b_cnt != 0 {
            let mut pm1b = Port::<u16>::new(off.pm1b_cnt);
            let keep = pm1b.read() & !(0b111 << 10);
            pm1b.write(keep | ((off.slp_typb & 0b111) << 10) | SLP_EN);
        }
    }
    // The transition isn't instant; give it a moment before the caller falls back.
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }
}
