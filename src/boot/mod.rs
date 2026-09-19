//! Limine boot-protocol glue: the request statics Limine scans for at load time, plus a thin
//! `BootInfo` shim and a `limine_entry_point!` macro that together replace the old `bootloader`
//! crate's `entry_point!(fn) -> fn(&'static BootInfo) -> !` calling convention with a byte-
//! compatible one -- every existing call site across `src/main.rs`/`src/lib.rs`/every
//! `tests/*.rs` file keeps dereferencing `boot_info.physical_memory_offset` unchanged; only the
//! `use`/macro-invocation lines at the top of each file need to change. See CLAUDE.md's boot
//! section for why: Limine's HHDM offset and memory map are direct analogs of the old
//! `bootloader::BootInfo`'s `physical_memory_offset`/`memory_map` fields, and everything
//! downstream of `oxidebsd::init` (GDT/IDT/frame allocator/heap) already treated those two values
//! as the only real inputs from the bootloader.

#[cfg(feature = "multiboot2")]
pub mod multiboot2;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use limine::framebuffer::Framebuffer;
use limine::memmap::Entry;
use limine::request::{
    ExecutableCmdlineRequest, FramebufferRequest, HhdmRequest, MemmapRequest, RsdpRequest,
};
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker};

#[used]
#[unsafe(link_section = ".requests_start")]
static REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();

#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[unsafe(link_section = ".requests")]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new();

#[unsafe(link_section = ".requests")]
static CMDLINE_REQUEST: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();

#[unsafe(link_section = ".requests")]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[unsafe(link_section = ".requests")]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
#[unsafe(link_section = ".requests_end")]
static REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

/// Replaces `bootloader::BootInfo`. Field name `physical_memory_offset` (not `hhdm_offset`) is
/// deliberate: every existing call site (`src/main.rs`, every `tests/*.rs` file) dereferences
/// exactly this field name today, and keeping it means none of those lines need to change --
/// only the `use`/entry-point-macro lines do. `memory_map` is Limine's own entry-pointer-array
/// shape (`&[&Entry]`, not `&[Entry]` -- Limine's wire format is an array of pointers, see
/// `limine::request::MemmapRespData::entries`), consumed directly by
/// `memory::BootInfoFrameAllocator`.
pub struct BootInfo {
    pub physical_memory_offset: u64,
    pub memory_map: &'static [&'static Entry],
}

/// A second, simpler copy of the HHDM offset (also carried on `BootInfo` itself), set the same
/// moment `read_boot_info` runs -- needed because `src/console/vga.rs`'s `WRITER` is a
/// `spin::Lazy`, initialized on its *first* access, which is the very first `serial_println!`/
/// `serial_print!` call in `kernel_main` -- before `oxidebsd::init(boot_info)` (and thus before
/// anything could plumb the real `BootInfo` value into `vga.rs` as a normal argument) ever runs.
/// A plain `AtomicU64` (not another `static mut` dance) since this only ever needs a single
/// plain integer, set once, read from arbitrary places thereafter.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Limine's Higher-Half Direct Map offset -- the amount to add to a real physical address to get
/// a virtual address the kernel can dereference. **Real physical memory below 1 MiB (the VGA text
/// buffer at physical `0xb8000`, in particular) is not identity-mapped under Limine the way
/// `bootloader` v0.9 used to map it** -- found live: `vga.rs`'s old bare `0xb8000` pointer
/// page-faulted with an empty IDT still installed (this runs before `cpu::interrupts::init_idt`),
/// escalating straight to a triple fault. Every direct physical-memory access from here on needs
/// to go through this offset instead of assuming a fixed low address is directly dereferenceable.
/// Panics if called before `read_boot_info` has run -- true only for code that would run before
/// `kmain` itself, which doesn't exist in this kernel.
pub fn hhdm_offset() -> u64 {
    let offset = HHDM_OFFSET.load(Ordering::Relaxed);
    assert_ne!(offset, 0, "hhdm_offset() called before read_boot_info()");
    offset
}

/// The first framebuffer Limine reports, if any -- unlike the legacy VGA text buffer, a real,
/// Limine-mapped linear framebuffer genuinely exists under both BIOS and UEFI (Limine sets one up
/// itself either way, no legacy hardware assumption involved), and `Framebuffer::address()` is
/// already a valid, directly dereferenceable pointer -- no HHDM offset math needed, unlike every
/// other raw physical address this file hands out. Backs `console::framebuffer`, which rasterizes
/// `console::vga`'s own real ANSI/VT100-driven text buffer onto it: the real VGA text buffer at
/// physical `0xb8000` isn't backed by anything at all under Limine (found live: a bare
/// `0xb8000`-based pointer page-faulted with no IDT installed yet, escalating to a triple fault,
/// confirmed under both BIOS and UEFI -- `bootloader` v0.9's own `map_physical_memory` feature
/// used to map literally all of physical memory, legacy MMIO holes included, so this never came
/// up before), so `console::vga::Writer` now targets a plain in-memory shadow buffer instead (see
/// that module's own `SHADOW_BUFFER` doc comment) and this framebuffer is what actually makes its
/// content visible.
pub fn primary_framebuffer() -> Option<&'static Framebuffer> {
    FRAMEBUFFER_REQUEST
        .response()
        .and_then(|r| r.framebuffers().first().copied())
}

/// The real ACPI RSDP (Root System Description Pointer)'s address, if Limine found one -- the
/// entry point `cpu::hpet::init` walks (RSDP -> RSDT/XSDT -> the `"HPET"` table) to find the real
/// HPET hardware, if any. **Already a directly dereferenceable virtual pointer, not a physical
/// one** -- unlike everything the RSDP itself then points to (RSDT/XSDT and every subsequent ACPI
/// table address are real physical addresses, needing `hhdm_offset()` like any other raw physical
/// access in this codebase). Confirmed via the vendored `limine` crate's own doc comment: its
/// `RsdpRequest`/`RsdpResponse` say the returned address is physical **only** at base revision 3
/// specifically -- every other revision, including this project's own `BaseRevision::
/// MAX_SUPPORTED` (`6`, see `BASE_REVISION` above), gets a virtual one, same as
/// `primary_framebuffer`'s own address above. `None` if Limine's own ACPI/firmware probe found no
/// RSDP at all (not expected on any real or QEMU x86_64 target, but handled the same "absence
/// logged, not fatal" way every other optional hardware probe in this codebase already is).
pub fn rsdp_address() -> Option<u64> {
    RSDP_REQUEST.response().map(|r| r.address as u64)
}

/// Whether the kernel was booted with `no-ata` on its Limine command line (`limine.conf`'s
/// `kernel_cmdline:`, or the equivalent on real hardware boot media) -- a real, deliberate safety
/// gate for a first attempt at booting on real hardware, not something this codebase's own QEMU-
/// based workflow ever needs to set. `src/drivers/ata.rs`'s legacy IDE PIO driver probes fixed
/// legacy ports (`0x1F0`-`0x1F7`/`0x170`-`0x177`) unconditionally, and `modules/oxfs`'s mount-or-
/// format logic will genuinely *format* (destructively overwrite) whatever real disk it finds
/// there if the superblock doesn't already match this exact build -- safe under QEMU, where those
/// ports are either genuinely absent or a predictable, disposable emulated disk, but a real risk
/// on physical hardware that still exposes a legacy-IDE-compatible/CSM mode mapping an actual
/// drive onto those same ports. Set this flag (rather than trusting real hardware's own firmware
/// CSM/legacy-IDE setting alone) to skip `ata::init()` entirely and force `oxfs` into its
/// original, always-safe, pure-in-memory fallback. Checked once by `src/main.rs`'s own
/// `#[cfg(not(test))] kernel_main`, right before it would otherwise call `ata::init()`.
static ATA_DISABLED: AtomicBool = AtomicBool::new(false);

pub fn ata_disabled() -> bool {
    ATA_DISABLED.load(Ordering::Relaxed)
}

/// Panics if Limine didn't honor the requested base revision -- called once, first thing, from
/// `limine_entry_point!`'s generated `kmain`, before anything else touches a Limine response.
pub fn check_base_revision() {
    if !BASE_REVISION.is_supported() {
        panic!(
            "Limine did not support the requested base revision (actual: {:?})",
            BASE_REVISION.actual_revision()
        );
    }
}

/// Reads Limine's HHDM and memory-map responses into a genuinely `'static` `BootInfo` -- backed
/// by a `static mut` write-once slot (same idiom `cpu::gdt.rs`'s own ring-0 stacks use: a plain
/// `static` never written through a real `&mut` gets interned into `.rodata` by the optimizer and
/// would make this whole function pointless, since the point is to actually construct the value
/// at runtime from Limine's responses). Called exactly once, from `limine_entry_point!`'s
/// generated `kmain`, before `oxidebsd::init` ever runs.
pub fn read_boot_info() -> &'static BootInfo {
    static mut BOOT_INFO: Option<BootInfo> = None;

    let hhdm = HHDM_REQUEST
        .response()
        .expect("Limine did not answer the HHDM request");
    let memmap = MEMMAP_REQUEST
        .response()
        .expect("Limine did not answer the memory map request");
    let has_no_ata_flag = CMDLINE_REQUEST
        .response()
        .is_some_and(|r| r.cmdline().split_whitespace().any(|tok| tok == "no-ata"));

    HHDM_OFFSET.store(hhdm.offset, Ordering::Relaxed);
    ATA_DISABLED.store(has_no_ata_flag, Ordering::Relaxed);

    unsafe {
        BOOT_INFO = Some(BootInfo {
            physical_memory_offset: hhdm.offset,
            memory_map: memmap.entries(),
        });
        (&raw const BOOT_INFO).as_ref().unwrap().as_ref().unwrap()
    }
}

/// Drop-in replacement for `bootloader::entry_point!`. Expands to a real `kmain` symbol (matching
/// the new kernel linker script's `ENTRY(kmain)`) that checks the base revision, reads
/// `BootInfo`, and calls through to `$path` with the exact same `fn(&'static BootInfo) -> !`
/// shape every caller already uses -- so migrating a call site is exactly two lines:
/// `use bootloader::{BootInfo, entry_point};` -> `use oxidebsd::boot::BootInfo; use
/// oxidebsd::limine_entry_point;`, and `entry_point!(main);` -> `limine_entry_point!(main);`.
#[macro_export]
macro_rules! limine_entry_point {
    ($path:path) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn kmain() -> ! {
            $crate::boot::check_base_revision();
            let boot_info: &'static $crate::boot::BootInfo = $crate::boot::read_boot_info();
            let f: fn(&'static $crate::boot::BootInfo) -> ! = $path;
            f(boot_info)
        }
    };
}
