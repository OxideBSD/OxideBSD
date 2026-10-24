//! UEFI runtime services (OxideBSD-doc `EFIRT.md`): the firmware functions that stay callable
//! after boot, reached through the EFI system table Limine hands over (`boot::efi_system_table`).
//!
//! The firmware runs at its physical addresses (no `SetVirtualAddressMap`, §4.1): `init` builds a
//! page table of its own for it, the kernel's half shared and every runtime region of the EFI
//! memory map mapped one to one below it, which is the CR3 only while a call runs (`call`). Code
//! is executable and data not, finer where the firmware's memory attributes table says (code
//! read-only); without that table, a runtime code region is writable and executable, as old
//! firmware needs. The lower half is supervisor-only: SMEP and SMAP hold during a call.
//!
//! A call: one at a time (`LOCK`), interrupts off, the interrupted process's FPU/SSE state saved
//! and the firmware given a clean one (it uses SSE; the kernel never does), CR3 switched, the
//! function called in the Microsoft x64 convention through `efirt_call`, which keeps a recovery
//! point. A fault inside the firmware resumes there (`fixup_fault`, from the trap handlers): the
//! call fails, and runtime services are off for the rest of the boot (`DEAD`) rather than the
//! fault rebooting the machine.
//!
//! Variables (`get_variable`, `next_variable_name`, `set_variable`) reach userland through
//! `/dev/efi` (`efi(4)`, EFIRT.md §5), here beside them as `/dev/devctl` is beside its queue:
//! FreeBSD's requests with OxideBSD's numbers, setting root's and only the boot manager's
//! variables and OxideBSD's own unless `machdep.efi.unsafe_writes` (`may_write`).
//!
//! Under BIOS there's no system table, and nothing here does anything.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use x86_64::PhysAddr;
use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
};

use crate::memory::GlobalFrameAllocator;
use crate::serial_println;

/// `EFI_MEMORY_DESCRIPTOR`'s attribute bits and types (UEFI 2.10 §7.2).
const EFI_MEMORY_UC: u64 = 0x1;
const EFI_MEMORY_XP: u64 = 0x4000;
const EFI_MEMORY_RO: u64 = 0x20000;
const EFI_MEMORY_RUNTIME: u64 = 1 << 63;
const RUNTIME_SERVICES_CODE: u32 = 5;
const MEMORY_MAPPED_IO: u32 = 11;
const MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;

/// `EFI_MEMORY_ATTRIBUTES_TABLE_GUID`, `dcfa911d-26eb-469f-a220-38b7dc461220`, as stored.
const MEMORY_ATTRIBUTES_TABLE: [u8; 16] =
    [0x1d, 0x91, 0xfa, 0xdc, 0xeb, 0x26, 0x9f, 0x46, 0xa2, 0x20, 0x38, 0xb7, 0xdc, 0x46, 0x12, 0x20];

/// `EFI_RUNTIME_SERVICES`' function pointers, by slot after its 24-byte header (§8).
#[derive(Clone, Copy)]
#[repr(usize)]
enum Service {
    GetTime = 0,
    GetVariable = 6,
    GetNextVariableName = 7,
    SetVariable = 8,
    ResetSystem = 10,
}

/// The firmware's answer when the call itself faulted (`efirt_fault`): not a real `EFI_STATUS`.
const FAULTED: u64 = u64::MAX;

/// `EFI_TIME` (§8.3).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pad1: u8,
    pub nanosecond: u32,
    pub time_zone: i16,
    pub daylight: u8,
    pad2: u8,
}

/// `EFI_RESET_TYPE`.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum ResetKind {
    Cold = 0,
    Shutdown = 2,
}

/// What `init` found: the firmware's page table and its runtime services table's functions
/// (physical addresses, which the firmware runs at).
struct Firmware {
    /// The EFI page table's level 4 frame.
    l4: PhysFrame<Size4KiB>,
    /// `EFI_RUNTIME_SERVICES`, through the HHDM.
    services: u64,
    vendor: String,
    /// The vendor's own firmware revision (`FirmwareRevision`).
    revision: u32,
    /// The UEFI specification's (the system table header's), `major << 16 | minor`: 2.70 is
    /// UEFI 2.7.
    uefi: u32,
}

static FIRMWARE: spin::Once<Option<Firmware>> = spin::Once::new();
/// One call at a time (the specification's rule), and none from inside another.
static LOCK: spin::Mutex<()> = spin::Mutex::new(());
/// A call faulted: the firmware isn't called again this boot.
static DEAD: AtomicBool = AtomicBool::new(false);
/// A call is running on this CPU (`fixup_fault`).
static ACTIVE: AtomicBool = AtomicBool::new(false);

// `efirt_call(func, a0, a1, a2, a3, a4, a5)`: calls `func(a0..a5)` in the Microsoft x64
// convention (four arguments in RCX, RDX, R8, R9 over 32 bytes of shadow space, then the stack;
// RSP 16-byte aligned at the call), keeping the System V callee-saved registers. The stack
// pointer after its pushes is the recovery point (`EFIRT_RECOVER_RSP`): a fault in the firmware
// resumes at `efirt_fault`, which goes back to it and returns `FAULTED`.
core::arch::global_asm!(
    ".pushsection .text.oxidebsd_efirt,\"ax\",@progbits",
    ".global efirt_call",
    "efirt_call:",
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov [rip + EFIRT_RECOVER_RSP], rsp",
    "    mov rax, rdi",
    "    mov r11, rcx",
    "    mov rcx, rsi",
    "    mov r10, r9",
    "    mov r9, r8",
    "    mov r8, r11",
    "    mov r11, [rsp + 56]",
    "    sub rsp, 56",
    "    mov [rsp + 32], r10",
    "    mov [rsp + 40], r11",
    "    cld",
    "    call rax",
    "    add rsp, 56",
    "    jmp 2f",
    ".global efirt_fault",
    "efirt_fault:",
    "    mov rsp, [rip + EFIRT_RECOVER_RSP]",
    "    mov rax, -1",
    "2:",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",
    ".popsection",
);

#[unsafe(no_mangle)]
static EFIRT_RECOVER_RSP: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn efirt_call(func: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64;
    static efirt_fault: u8;
}

/// From the trap handlers, before anything else looks at a ring-0 fault: when it happened inside
/// a firmware call, the call ends there (`efirt_fault`) and the firmware is switched off. Returns
/// whether it did.
pub fn fixup_fault(frame: &mut crate::cpu::trap::TrapFrame) -> bool {
    if frame.from_user() || !ACTIVE.load(Ordering::Relaxed) {
        return false;
    }
    DEAD.store(true, Ordering::Relaxed);
    ACTIVE.store(false, Ordering::Relaxed);
    serial_println!(
        "[efirt] the firmware faulted (vector {}, error {:#x}, ip {:#x}): runtime services are off until reboot",
        frame.vector,
        frame.error_code,
        frame.rip
    );
    frame.rip = (&raw const efirt_fault) as u64;
    true
}

/// A kernel virtual address's bytes, if it's mapped: the firmware's tables are read through the
/// HHDM, and a firmware that put one outside what Limine mapped mustn't fault the kernel.
fn mapped(va: u64, len: u64) -> bool {
    let end = va.saturating_add(len.max(1) - 1);
    (va & !0xfff..=end).step_by(4096).all(|p| crate::memory::translate_kernel(p).is_some())
}

fn hhdm(pa: u64) -> u64 {
    crate::memory::phys_mem_offset().as_u64() + pa
}

/// A `u64` at kernel virtual address `va`, if mapped.
fn read_u64(va: u64) -> Option<u64> {
    // SAFETY: checked mapped; the firmware's tables are plain memory.
    mapped(va, 8).then(|| unsafe { (va as *const u64).read_unaligned() })
}

/// The firmware's UCS-2 vendor string at physical `pa`, up to its NUL.
fn vendor_string(pa: u64) -> String {
    let mut s = String::new();
    for i in 0..64u64 {
        let va = hhdm(pa) + i * 2;
        if !mapped(va, 2) {
            break;
        }
        // SAFETY: checked mapped.
        let c = unsafe { (va as *const u16).read_unaligned() };
        if c == 0 {
            break;
        }
        s.push(char::from_u32(c as u32).unwrap_or('?'));
    }
    s
}

/// The memory attributes table's descriptors (`EFI_MEMORY_ATTRIBUTES_TABLE`, §4.6), from the
/// system table's configuration tables, as `(physical start, pages, attributes)`.
fn attributes_table(st: u64) -> alloc::vec::Vec<(u64, u64, u64)> {
    let mut out = alloc::vec::Vec::new();
    let (Some(count), Some(tables)) = (read_u64(st + 104), read_u64(st + 112)) else { return out };
    for i in 0..count.min(256) {
        let entry = hhdm(tables) + i * 24;
        if !mapped(entry, 24) {
            break;
        }
        // SAFETY: checked mapped.
        let guid = unsafe { (entry as *const [u8; 16]).read_unaligned() };
        if guid != MEMORY_ATTRIBUTES_TABLE {
            continue;
        }
        let Some(table) = read_u64(entry + 16).map(hhdm) else { break };
        if !mapped(table, 16) {
            break;
        }
        // SAFETY: checked mapped: Version, NumberOfEntries, DescriptorSize, Reserved (u32 each).
        let (n, size) = unsafe { ((table as *const u32).add(1).read_unaligned() as u64, (table as *const u32).add(2).read_unaligned() as u64) };
        if size < 40 || !mapped(table + 16, n * size) {
            break;
        }
        for d in 0..n.min(4096) {
            let at = table + 16 + d * size;
            // SAFETY: checked mapped: an `EFI_MEMORY_DESCRIPTOR`.
            unsafe {
                let start = ((at + 8) as *const u64).read_unaligned();
                let pages = ((at + 24) as *const u64).read_unaligned();
                let attr = ((at + 32) as *const u64).read_unaligned();
                out.push((start, pages, attr));
            }
        }
        break;
    }
    out
}

/// Builds the EFI page table from the EFI memory map's runtime regions (and the memory attributes
/// table's finer ones), and reads the system table: once, at boot, after `boot::snapshot`.
pub fn init() {
    FIRMWARE.call_once(|| {
        let st = crate::boot::efi_system_table()?;
        let (map, desc_size) = crate::boot::efi_memory_map()?;
        if *desc_size < 40 || !mapped(st, 120) {
            serial_println!("[efirt] the EFI system table or memory map is unusable: no runtime services");
            return None;
        }
        // SAFETY: checked mapped: `EFI_SYSTEM_TABLE`'s header revision (u32 at 8) and
        // FirmwareRevision (u32 at 32).
        let (uefi, revision) = unsafe { (((st + 8) as *const u32).read_unaligned(), ((st + 32) as *const u32).read_unaligned()) };
        let vendor = read_u64(st + 24).map(vendor_string).unwrap_or_default();
        let services_pa = read_u64(st + 88)?;
        let services = hhdm(services_pa);
        if !mapped(services, 24 + 14 * 8) {
            serial_println!("[efirt] the runtime services table isn't mapped: no runtime services");
            return None;
        }

        // Each runtime page's flags, by physical page: the memory map's regions first, then the
        // attributes table's, which split code regions into read-only code and data.
        let nx = crate::cpu::nx::no_execute();
        let base = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let mut pages: BTreeMap<u64, PageTableFlags> = BTreeMap::new();
        let mut rwx = 0u64;
        for d in map.chunks_exact(*desc_size) {
            let ty = u32::from_le_bytes(d[0..4].try_into().unwrap());
            let start = u64::from_le_bytes(d[8..16].try_into().unwrap());
            let count = u64::from_le_bytes(d[24..32].try_into().unwrap());
            let attr = u64::from_le_bytes(d[32..40].try_into().unwrap());
            if attr & EFI_MEMORY_RUNTIME == 0 || count > 1 << 20 {
                continue;
            }
            let flags = match ty {
                RUNTIME_SERVICES_CODE => base,
                MEMORY_MAPPED_IO | MEMORY_MAPPED_IO_PORT_SPACE => {
                    base | nx | PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH
                }
                _ if attr & EFI_MEMORY_UC != 0 => base | nx | PageTableFlags::NO_CACHE,
                _ => base | nx,
            };
            for i in 0..count {
                pages.insert(start + i * 4096, flags);
            }
        }
        let refined = attributes_table(st);
        for &(start, count, attr) in &refined {
            for i in 0..count.min(1 << 20) {
                let p = start + i * 4096;
                let Some(f) = pages.get_mut(&p) else { continue };
                if attr & EFI_MEMORY_RO != 0 {
                    f.remove(PageTableFlags::WRITABLE);
                }
                if attr & EFI_MEMORY_XP != 0 {
                    *f |= nx;
                }
            }
        }
        for f in pages.values() {
            if f.contains(PageTableFlags::WRITABLE) && !f.contains(PageTableFlags::NO_EXECUTE) {
                rwx += 1;
            }
        }
        // The system table and the runtime services table, at their physical addresses too.
        for pa in [st - crate::memory::phys_mem_offset().as_u64(), services_pa] {
            pages.entry(pa & !0xfff).or_insert(base | nx);
            pages.entry((pa + 0x200) & !0xfff).or_insert(base | nx);
        }

        let mut fa = GlobalFrameAllocator;
        let l4 = fa.allocate_frame()?;
        let offset = crate::memory::phys_mem_offset();
        // SAFETY: a fresh frame, reached through the physical-memory window, nothing else using it.
        let table = unsafe { &mut *(offset + l4.start_address().as_u64()).as_mut_ptr::<PageTable>() };
        table.zero();
        // SAFETY: as above; the table is ours alone until a call loads it.
        let mut mapper = unsafe { OffsetPageTable::new(table, offset) };
        let parents = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        for (&pa, &flags) in &pages {
            if pa >= crate::memory::usercopy::VM_MAXUSER {
                continue;
            }
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(pa));
            let frame = PhysFrame::containing_address(PhysAddr::new(pa));
            // SAFETY: the firmware's own memory, mapped where the firmware expects it, in a table
            // only it runs on.
            match unsafe { mapper.map_to_with_table_flags(page, frame, flags, parents, &mut fa) } {
                Ok(flush) => flush.ignore(),
                Err(_) => {
                    serial_println!("[efirt] couldn't map the firmware's page {:#x}: no runtime services", pa);
                    return None;
                }
            }
        }
        serial_println!(
            "[efirt] UEFI {}.{}, {} (firmware {:#x}): {} runtime pages mapped one to one ({}{} writable and executable)",
            uefi >> 16,
            (uefi & 0xffff) / 10,
            vendor,
            revision,
            pages.len(),
            rwx,
            if refined.is_empty() { ", no memory attributes table" } else { "" }
        );
        Some(Firmware { l4, services, vendor, revision, uefi })
    });
}

/// Whether runtime services can be called.
pub fn available() -> bool {
    FIRMWARE.get().is_some_and(|f| f.is_some()) && !DEAD.load(Ordering::Relaxed)
}

/// The firmware's vendor, its own revision, and the UEFI specification's (`major << 16 |
/// minor`), if runtime services were found.
pub fn firmware() -> Option<(&'static str, u32, u32)> {
    FIRMWARE.get()?.as_ref().map(|f| (f.vendor.as_str(), f.revision, f.uefi))
}

/// Calls runtime service `service` with `args`: its `EFI_STATUS`, or `None` when runtime
/// services are unavailable or the call faulted. Not from interrupt context, and holding no spin
/// lock of the kernel's (EFIRT.md §4.4).
fn call(service: Service, args: [u64; 6]) -> Option<u64> {
    let fw = FIRMWARE.get()?.as_ref()?;
    let _guard = LOCK.try_lock()?;
    if DEAD.load(Ordering::Relaxed) {
        return None;
    }
    let func = read_u64(fw.services + 24 + service as u64 * 8)?;
    let status = x86_64::instructions::interrupts::without_interrupts(|| {
        let offset = crate::memory::phys_mem_offset();
        let (kernel_l4, kernel_bits) = Cr3::read_raw();
        // The kernel's half as it is now (a level 4 slot may have filled since `init`).
        // SAFETY: both tables are live and reached through the physical-memory window; only
        // the EFI table, which nothing runs on yet, is written.
        unsafe {
            let kernel = &*(offset + kernel_l4.start_address().as_u64()).as_ptr::<PageTable>();
            let efi = &mut *(offset + fw.l4.start_address().as_u64()).as_mut_ptr::<PageTable>();
            for i in 256..512 {
                efi[i] = kernel[i].clone();
            }
        }
        let mut fpu = crate::cpu::fpu::FxSaveArea([0; 512]);
        let clean = crate::cpu::fpu::clean_state();
        // SAFETY: aligned save areas on this stack; the firmware gets the reset FPU state the
        // specification asks for (x87 control word 0x37f, MXCSR 0x1f80), and the interrupted
        // process's state comes back after.
        unsafe {
            crate::cpu::fpu::save(&mut fpu);
            crate::cpu::fpu::restore(&clean);
            Cr3::write_raw(fw.l4, 0);
        }
        ACTIVE.store(true, Ordering::Relaxed);
        // SAFETY: the firmware's own function, at the address it runs at, on its page table.
        let status = unsafe { efirt_call(func, args[0], args[1], args[2], args[3], args[4], args[5]) };
        ACTIVE.store(false, Ordering::Relaxed);
        // SAFETY: back to the kernel's table, then the process's FPU state.
        unsafe {
            Cr3::write_raw(kernel_l4, kernel_bits);
            crate::cpu::fpu::restore(&fpu);
        }
        status
    });
    (status != FAULTED).then_some(status)
}

/// The firmware's clock (`GetTime`).
pub fn get_time() -> Option<EfiTime> {
    let mut t = EfiTime::default();
    match call(Service::GetTime, [&raw mut t as u64, 0, 0, 0, 0, 0])? {
        0 => Some(t),
        _ => None,
    }
}

/// Resets or powers off through the firmware (`ResetSystem`), the fallback when ACPI's and the
/// keyboard controller's ways don't take (EFIRT.md §9). Returns only if it couldn't.
pub fn reset(kind: ResetKind) {
    let _ = call(Service::ResetSystem, [kind as u64, 0, 0, 0, 0, 0]);
}

/// Calls the firmware at a bad address, to check `fixup_fault` (tests only): runtime services are
/// off afterwards.
#[doc(hidden)]
pub fn fault_for_test() -> bool {
    let Some(fw) = FIRMWARE.get().and_then(|f| f.as_ref()) else { return false };
    let Some(_guard) = LOCK.try_lock() else { return false };
    x86_64::instructions::interrupts::without_interrupts(|| {
        let (kernel_l4, kernel_bits) = Cr3::read_raw();
        let mut fpu = crate::cpu::fpu::FxSaveArea([0; 512]);
        // SAFETY: as `call`; address 0x10 is mapped by nothing in the EFI table, so the call
        // faults at once on its first instruction fetch.
        unsafe {
            crate::cpu::fpu::save(&mut fpu);
            Cr3::write_raw(fw.l4, 0);
            ACTIVE.store(true, Ordering::Relaxed);
            let status = efirt_call(0x10, 0, 0, 0, 0, 0, 0);
            ACTIVE.store(false, Ordering::Relaxed);
            Cr3::write_raw(kernel_l4, kernel_bits);
            crate::cpu::fpu::restore(&fpu);
            status == FAULTED
        }
    })
}

/// At boot: builds the EFI page table and proves the firmware answers, logging its clock.
pub fn init_and_log() {
    init();
    if !available() {
        return;
    }
    make_device();
    match get_time() {
        Some(t) => {
            serial_println!(
                "[efirt] firmware clock: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                t.year,
                t.month,
                t.day,
                t.hour,
                t.minute,
                t.second
            );
        }
        None => {
            serial_println!("[efirt] GetTime failed");
        }
    }
}

// ---- Variables ---------------------------------------------------------------------------------

/// `EFI_GLOBAL_VARIABLE`, `8be4df61-93ca-11d2-aa0d-00e098032b8c`, as stored.
pub const GLOBAL_GUID: [u8; 16] = [0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c];
/// OxideBSD's own vendor GUID, `916e441e-ead7-4301-9aaf-6e0ba5a85339`, as stored.
pub const OXIDEBSD_GUID: [u8; 16] = [0x1e, 0x44, 0x6e, 0x91, 0xd7, 0xea, 0x01, 0x43, 0x9a, 0xaf, 0x6e, 0x0b, 0xa5, 0xa8, 0x53, 0x39];

/// `EFI_STATUS` errors (high bit set, Appendix D) a variable call may return.
const EFI_ERROR: u64 = 1 << 63;
const EFI_INVALID_PARAMETER: u64 = EFI_ERROR | 2;
const EFI_UNSUPPORTED: u64 = EFI_ERROR | 3;
const EFI_BUFFER_TOO_SMALL: u64 = EFI_ERROR | 5;
const EFI_DEVICE_ERROR: u64 = EFI_ERROR | 7;
const EFI_WRITE_PROTECTED: u64 = EFI_ERROR | 8;
const EFI_OUT_OF_RESOURCES: u64 = EFI_ERROR | 9;
const EFI_NOT_FOUND: u64 = EFI_ERROR | 14;
const EFI_SECURITY_VIOLATION: u64 = EFI_ERROR | 26;

// musl's errno values.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EIO: i64 = 5;
const ENXIO: i64 = 6;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ENOSPC: i64 = 28;
const EROFS: i64 = 30;
const EOVERFLOW: i64 = 75;
const ENOTSUP: i64 = 95;

/// A firmware status as an errno (FreeBSD's `efi_status_to_errno`); `ENXIO` when the firmware
/// couldn't be called at all.
fn errno(status: Option<u64>) -> i64 {
    match status {
        None => ENXIO,
        Some(EFI_INVALID_PARAMETER) => EINVAL,
        Some(EFI_UNSUPPORTED) => ENOTSUP,
        Some(EFI_BUFFER_TOO_SMALL) => EOVERFLOW,
        Some(EFI_WRITE_PROTECTED) => EROFS,
        Some(EFI_OUT_OF_RESOURCES) => ENOSPC,
        Some(EFI_NOT_FOUND) => ENOENT,
        Some(EFI_SECURITY_VIOLATION) => EPERM,
        Some(EFI_DEVICE_ERROR) | Some(_) => EIO,
    }
}

/// Variable `name` (UTF-16, its NUL included) of vendor `guid` into `data`: its attributes and
/// size. A too-small `data` fails with `EOVERFLOW` and the size it needs.
pub fn get_variable(name: &[u16], guid: &[u8; 16], data: &mut [u8]) -> Result<(u32, usize), (i64, usize)> {
    let mut attrib: u32 = 0;
    let mut size: u64 = data.len() as u64;
    let status = call(
        Service::GetVariable,
        [name.as_ptr() as u64, guid.as_ptr() as u64, &raw mut attrib as u64, &raw mut size as u64, data.as_mut_ptr() as u64, 0],
    );
    match status {
        Some(0) => Ok((attrib, size as usize)),
        s => Err((errno(s), size as usize)),
    }
}

/// The variable after `name` (in `name`'s buffer, its NUL included; empty for the first) and
/// `guid`, replacing both: the new name's size in bytes. A too-small buffer fails with
/// `EOVERFLOW` and the size it needs; past the last, `ENOENT`.
pub fn next_variable_name(name: &mut [u16], guid: &mut [u8; 16]) -> Result<usize, (i64, usize)> {
    let mut size: u64 = (name.len() * 2) as u64;
    let status = call(Service::GetNextVariableName, [&raw mut size as u64, name.as_mut_ptr() as u64, guid.as_mut_ptr() as u64, 0, 0, 0]);
    match status {
        Some(0) => Ok(size as usize),
        s => Err((errno(s), size as usize)),
    }
}

/// Sets (empty `data`: deletes) variable `name` of `guid`. The allow-list (`may_write`) is the
/// caller's.
pub fn set_variable(name: &[u16], guid: &[u8; 16], attrib: u32, data: &[u8]) -> Result<(), i64> {
    let status = call(
        Service::SetVariable,
        [name.as_ptr() as u64, guid.as_ptr() as u64, attrib as u64, data.len() as u64, data.as_ptr() as u64, 0],
    );
    match status {
        Some(0) => Ok(()),
        s => Err(errno(s)),
    }
}

/// `machdep.efi.unsafe_writes`: any variable may be written, not only the boot manager's.
static UNSAFE_WRITES: AtomicBool = AtomicBool::new(false);

pub fn unsafe_writes() -> bool {
    UNSAFE_WRITES.load(Ordering::Relaxed)
}

pub fn set_unsafe_writes(on: bool) {
    UNSAFE_WRITES.store(on, Ordering::Relaxed);
}

/// Whether variable `name` (UTF-16, without its NUL) of `guid` may be written by default
/// (EFIRT.md §5.2): the boot manager's (`Boot####`, `BootOrder`, `BootNext`, `Timeout`,
/// `Driver####`, `DriverOrder`, and `OsIndications`, which asks for the firmware's setup screens
/// at the next boot) and anything of OxideBSD's own GUID.
pub fn may_write(name: &[u16], guid: &[u8; 16]) -> bool {
    if *guid == OXIDEBSD_GUID {
        return true;
    }
    if *guid != GLOBAL_GUID {
        return false;
    }
    let Ok(name) = String::from_utf16(name) else { return false };
    let numbered = |prefix: &str| {
        name.strip_prefix(prefix).is_some_and(|n| n.len() == 4 && n.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()))
    };
    matches!(name.as_str(), "BootOrder" | "BootNext" | "Timeout" | "DriverOrder" | "OsIndications") || numbered("Boot") || numbered("Driver")
}

// ---- /dev/efi (efi(4)) -------------------------------------------------------------------------

/// `/dev/efi`'s number, beside `klog` and `devctl` (DEVFS.md §3).
pub const EFI_DEVICE: (u32, u32) = (7, 2);

/// The device's requests (EFIRT.md §5.1; FreeBSD's shapes, OxideBSD's numbers).
const EFIIOC_GET_TIME: u64 = 0x6f78_4502;
const EFIIOC_VAR_GET: u64 = 0x6f78_4504;
const EFIIOC_VAR_NEXT: u64 = 0x6f78_4505;
const EFIIOC_VAR_SET: u64 = 0x6f78_4506;

/// The longest name and value a request takes: past any firmware's variable size.
const NAME_MAX_BYTES: u64 = 1024;
const DATA_MAX: u64 = 64 << 10;

/// `EFIIOC_VAR_*`'s argument: the name in UTF-16 with its NUL (`namesize` in bytes), the vendor
/// GUID, the attributes, and the data (`datasize` bytes); the pointers are the caller's.
#[repr(C)]
#[derive(Clone, Copy)]
struct VarIoc {
    name: u64,
    namesize: u64,
    vendor: [u8; 16],
    attrib: u32,
    pad: u32,
    data: u64,
    datasize: u64,
}

// SAFETY: plain integers and bytes, with `pad` making the padding explicit.
unsafe impl crate::memory::usercopy::Pod for VarIoc {}
// SAFETY: as above.
unsafe impl crate::memory::usercopy::Pod for EfiTime {}

/// Registers `/dev/efi`, root's alone, when the firmware has runtime services.
fn make_device() {
    let _ = crate::fs::devfs::make_dev("efi", EFI_DEVICE.0, EFI_DEVICE.1, 0, 0, 0o600, dev_open);
}

extern "C" fn dev_open(_major: u64, _minor: u64, flags: u64) -> i64 {
    if let Err(e) = crate::fs::fd::check_room(1) {
        return -e;
    }
    let real_fd = crate::fs::fd::oxidebsd_alloc_fd();
    crate::fs::fd::finstall(real_fd, &EFI_OPS, 0, crate::fs::fd::open_flag(flags), crate::fs::fd::FdKind::Module)
}

static EFI_OPS: crate::fs::fd::FileOps = crate::fs::fd::FileOps { ioctl: Some(dev_ioctl), ..crate::fs::fd::FileOps::NONE };

extern "C" fn dev_ioctl(real_fd: u64, request: u64, argp: u64) -> i64 {
    match ioctl(real_fd, request, argp) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

/// The caller's UTF-16 name, NUL-terminated within `namesize` bytes.
fn name_in(v: &VarIoc) -> Result<Vec<u16>, i64> {
    use crate::memory::usercopy::{UserPtr, copyin};
    if v.namesize < 2 || v.namesize % 2 != 0 || v.namesize > NAME_MAX_BYTES {
        return Err(EINVAL);
    }
    let mut bytes = alloc::vec![0u8; v.namesize as usize];
    copyin(UserPtr::new(v.name), &mut bytes).map_err(|e| e as i64)?;
    let mut name: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let end = name.iter().position(|&c| c == 0).ok_or(EINVAL)?;
    name.truncate(end + 1);
    Ok(name)
}

fn ioctl(real_fd: u64, request: u64, argp: u64) -> Result<(), i64> {
    use crate::memory::usercopy::{UserPtr, copyin, copyin_val, copyout, copyout_val};
    if !available() {
        return Err(ENXIO);
    }
    let arg = UserPtr::new(argp);
    match request {
        EFIIOC_GET_TIME => {
            let t = get_time().ok_or(EIO)?;
            copyout_val(&t, arg).map_err(|e| e as i64)
        }
        EFIIOC_VAR_GET => {
            let mut v: VarIoc = copyin_val(arg).map_err(|e| e as i64)?;
            let name = name_in(&v)?;
            let mut data = Vec::new();
            data.try_reserve_exact(v.datasize.min(DATA_MAX) as usize).map_err(|_| ENOMEM)?;
            data.resize(v.datasize.min(DATA_MAX) as usize, 0);
            let r = get_variable(&name, &v.vendor, &mut data);
            match r {
                Ok((attrib, size)) => {
                    copyout(&data[..size], UserPtr::new(v.data)).map_err(|e| e as i64)?;
                    v.attrib = attrib;
                    v.datasize = size as u64;
                    copyout_val(&v, arg).map_err(|e| e as i64)
                }
                Err((EOVERFLOW, need)) => {
                    v.datasize = need as u64;
                    copyout_val(&v, arg).map_err(|e| e as i64)?;
                    Err(EOVERFLOW)
                }
                Err((e, _)) => Err(e),
            }
        }
        EFIIOC_VAR_NEXT => {
            let mut v: VarIoc = copyin_val(arg).map_err(|e| e as i64)?;
            let mut name = name_in(&v)?;
            // The firmware writes the next name into the caller's whole buffer.
            name.resize(v.namesize as usize / 2, 0);
            let mut guid = v.vendor;
            match next_variable_name(&mut name, &mut guid) {
                Ok(size) => {
                    let bytes: Vec<u8> = name.iter().take(size / 2).flat_map(|c| c.to_le_bytes()).collect();
                    copyout(&bytes, UserPtr::new(v.name)).map_err(|e| e as i64)?;
                    v.vendor = guid;
                    v.namesize = size as u64;
                    copyout_val(&v, arg).map_err(|e| e as i64)
                }
                Err((EOVERFLOW, need)) => {
                    v.namesize = need as u64;
                    copyout_val(&v, arg).map_err(|e| e as i64)?;
                    Err(EOVERFLOW)
                }
                Err((e, _)) => Err(e),
            }
        }
        EFIIOC_VAR_SET => {
            // Written only through a descriptor open for writing, as FreeBSD's efi(4) asks.
            if !crate::fs::fd::file_of(real_fd).is_some_and(|(_, flag, _, _)| flag & crate::fs::fd::FWRITE != 0) {
                return Err(EBADF);
            }
            if !crate::process::identity::current_cred().privileged() {
                return Err(EPERM);
            }
            let v: VarIoc = copyin_val(arg).map_err(|e| e as i64)?;
            let name = name_in(&v)?;
            if !unsafe_writes() && !may_write(&name[..name.len() - 1], &v.vendor) {
                return Err(EPERM);
            }
            if v.datasize > DATA_MAX {
                return Err(EINVAL);
            }
            let mut data = Vec::new();
            data.try_reserve_exact(v.datasize as usize).map_err(|_| ENOMEM)?;
            data.resize(v.datasize as usize, 0);
            copyin(UserPtr::new(v.data), &mut data).map_err(|e| e as i64)?;
            set_variable(&name, &v.vendor, v.attrib, &data)
        }
        _ => Err(ENOTTY),
    }
}
