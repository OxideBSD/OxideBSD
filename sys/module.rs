//! A dynamic kernel-module loader: takes a relocatable (`ET_REL`) object file -- produced by
//! `build.rs`'s `build_module_crate` from a plain `#![no_std]` `lib` crate under `modules/`,
//! already merged against the exact `core`/`alloc`/`compiler_builtins` the kernel's own
//! `-Z build-std` produced -- maps its `SHF_ALLOC` sections into the kernel's own, currently
//! active address space, applies its relocations, resolves its few remaining undefined symbols
//! against a small hand-curated kernel API, and calls its `module_init` entry point.
//!
//! This is a genuinely different job from `src/elf.rs`: that file loads a handful of `PT_LOAD`
//! segments from a statically-linked, non-relocatable `ET_EXEC` userland binary with zero
//! relocations. A relocatable object has no program headers at all (`ET_REL`'s `e_phnum` is
//! always 0) -- what it has instead is potentially hundreds of small linker sections (one per
//! function/global, before any `--gc-sections` pruning -- not attempted here, see `CLAUDE.md`),
//! a symbol table, and relocation entries that must be resolved and applied by hand. Only the
//! low-level "read an ELF64 field" helpers are shared with `elf.rs` (`crate::process::elf::read_u{16,32,
//! 64}`); the loading logic below is independent.
//!
//! Module code never runs in ring 3 and is mapped without `USER_ACCESSIBLE` -- it's invoked only
//! from kernel context (`module_init` at load time, and, once the native ABI becomes a module
//! itself, via syscall-registry callbacks the kernel calls into directly). See `CLAUDE.md`'s
//! module-loading section for the full design, including the empirical findings (relocation
//! types actually observed, why a build-time partial relink is necessary, the panic-entry-point
//! answer, a `static mut`-dead-store gotcha distinct from `gdt.rs`'s) that shaped this file.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use spin::Mutex;
use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTableFlags, Size4KiB,
};

use crate::memory::BootInfoFrameAllocator;
use crate::process::elf::{read_u16, read_u32, read_u64};
use crate::{serial_print, serial_println};

const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const CLASS_64: u8 = 2;
const DATA_LITTLE_ENDIAN: u8 = 1;
const TYPE_REL: u16 = 1;
const MACHINE_X86_64: u16 = 62;

const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;

const SHF_ALLOC: u64 = 0x2;

const SHN_UNDEF: u16 = 0;

const R_X86_64_64: u32 = 1;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_GOTPCREL: u32 = 9;
const R_X86_64_32: u32 = 10;
const R_X86_64_32S: u32 = 11;

const EHDR_SIZE: usize = 64;
const SHDR_SIZE: usize = 64;
const SYM_SIZE: usize = 24;
const RELA_SIZE: usize = 24;

const PAGE_SIZE: u64 = 4096;

/// Fixed base of the kernel-module virtual address region, and its ceiling. Modules are mapped
/// into the kernel's own, currently active address space (not a separate one -- unlike userland
/// demos, module code always runs in kernel context).
///
/// **Moved into the kernel's own top-2-GiB canonical region (the Limine migration -- see
/// CLAUDE.md's boot section) from the old low `0x2000_0000..0x8000_0000` range.** `build.rs`
/// compiles every module with `-C relocation-model=static`, eliminating GOT-indirected
/// relocations entirely (a real GOT would need lazy-vs-eager-binding decisions and its own
/// alignment bookkeeping this loader doesn't implement) in exchange for every kernel-API call/
/// reference compiling as a plain **PC-relative** 32-bit relocation (`R_X86_64_PC32`/`PLT32`) --
/// only reachable when module code and the kernel function it's calling are within `+-2 GiB` of
/// each other. That was true for free under `bootloader` v0.9 (kernel also lived at a low
/// address); found live, the hard way, once the kernel moved to a genuine higher-half address
/// (`0xffffffff80000000`+, per the Limine protocol): the first `module::load` call
/// (`hello`) failed with `RelocationOverflow` on exactly this class of relocation, since a
/// call site down at `0x2000_0000` is *~18 exabytes* away from a kernel function up at
/// `0xffffffff80000000` -- nowhere close to representable in 32 bits. Fixed by moving the module
/// region itself into the same top-2-GiB canonical range as the kernel, comfortably above the
/// kernel image's own current end (confirmed via `readelf -l target/x86_64-oxidebsd/debug/oxidebsd
/// | grep -A1 LOAD`, same re-derivation method `regress/ring3-smoke/linker.ld`'s own doc comment
/// documents for the analogous userland-side constraint) -- keeping every module-to-kernel
/// PC-relative reference within the real `+-2 GiB` window `R_X86_64_PC32`/`PLT32` can encode.
/// **Absolute** relocations (`R_X86_64_32S`, sign-extended) also still work at this new home: any
/// address in the canonical top-2-GiB range sign-extends losslessly from its low 32 bits by
/// construction -- the same property that makes `-mcmodel=kernel`-style addressing work for real
/// kernels generally, not something specific to this fix. Plain **unsigned** absolute
/// (`R_X86_64_32`) is the one relocation type this new placement *doesn't* help (a huge canonical
/// address is nowhere near representable as an unsigned 32-bit value either) -- not observed in
/// practice for any module so far, but `apply_relocation`'s own overflow check would still catch
/// it loudly rather than silently corrupt if one ever appears.
///
/// **Moved up from `0xffff_ffff_9000_0000` (and the ceiling from `0xffff_ffff_f000_0000`)** once
/// the debug kernel image itself grew past 256 MiB (embedding `/bin/sh` and `/sbin/init_sh`) and
/// overlapped the old base -- surfaced as `MappingFailed` on the very first module load. The
/// kernel image can now reach 512 MiB. Module *data* pools no longer live here at all: see
/// `MODULE_DATA_BASE`.
const MODULE_VA_BASE: u64 = 0xffff_ffff_a000_0000;
const MODULE_REGION_CEILING: u64 = 0xffff_ffff_ff00_0000;

static NEXT_MODULE_PAGE: Mutex<u64> = Mutex::new(MODULE_VA_BASE);

/// A separate kernel window for `oxidebsd_module_alloc_zeroed`'s large runtime pools (oxfs's
/// ~1 GiB block pool and its write buffers). Those are reached only through pointers, never by a
/// relocation, so they don't need the `+-2 GiB`-of-the-kernel placement module *code* does --
/// sharing the code region with them left it within a few MiB of full. L4 slot 384, far from the
/// HHDM (`0xffff_8000_0000_0000`, slot 256 up) and the kernel/module slot (511). Mapped at boot,
/// before any process exists, so every address space (which aliases kernel-only L4 entries, see
/// `memory::address_space`) sees it.
const MODULE_DATA_BASE: u64 = 0xffff_c000_0000_0000;
const MODULE_DATA_CEILING: u64 = MODULE_DATA_BASE + (64 << 30);

static NEXT_MODULE_DATA_PAGE: Mutex<u64> = Mutex::new(MODULE_DATA_BASE);

/// One entry per successfully relocated module, in load order -- backs `/proc/modules`
/// (`oxidebsd_proc_modules` below, synthesized by `sys/modules/oxfs`) the same way real Linux's own
/// `/proc/modules` reflects its loaded-module list. `name` is `&'static str` rather than an owned
/// `String`: every call site in `sys/main.rs` passes a string literal, so there's never a real
/// owned string to store in the first place.
struct LoadedModuleInfo {
    name: &'static str,
    base: u64,
    size: u64,
    /// Whether a panic anywhere in this module's code should reboot the whole system
    /// (`module_panic_trampoline` below) rather than just halting. `true` for filesystem modules:
    /// with no disk attached their entire state is the in-memory filesystem itself, nothing safe
    /// to resume into; with one attached (see `src/ata.rs`), a panic mid-mount/mid-format risks a
    /// torn superblock/inode-table write, which is worse to resume past than a purely in-memory
    /// panic ever was -- so `true` is if anything more justified once a backing store exists, not
    /// less. `false` for everything else, pending real per-module restart.
    fatal_on_panic: bool,
}

static LOADED_MODULES: Mutex<Vec<LoadedModuleInfo>> = Mutex::new(Vec::new());

/// Whether the module code currently executing (if any) should reboot the whole system on panic --
/// set right before every call into module code (`load`'s own `module_init` call below, and
/// `syscall::dispatch`'s call into a registered `SyscallHandler`) and read by
/// `module_panic_trampoline` if that call panics. `static mut`, not a `Mutex`: same reasoning as
/// `gdt.rs`'s `CURRENT_RSP0` -- a lock held across the very call that might panic would still be
/// held (spin locks don't unwind) when the trampoline tried to read it. Sound only because this
/// kernel is single-core and every call site sets this immediately before a call that either
/// returns normally (nothing else touches this flag in between) or panics (handled by the
/// trampoline before anything else runs) -- no real concurrent access is possible. Starts `true`
/// (reboot) so that any call path that forgot to set this defensively fails toward safety rather
/// than toward silently hanging.
static mut CURRENT_MODULE_FATAL: bool = true;

/// Records `fatal` as the "should this panic reboot the system" answer for whatever module code
/// is about to run. See `CURRENT_MODULE_FATAL`'s own doc comment for why this is safe despite
/// being a bare `static mut`.
fn set_current_module_fatal(fatal: bool) {
    unsafe {
        CURRENT_MODULE_FATAL = fatal;
    }
}

/// Same as `set_current_module_fatal`, but looks the answer up from `handler_addr` (an
/// already-resolved `SyscallHandler` function pointer) by finding which loaded module's
/// `[base, base+size)` range contains it -- used by `syscall::dispatch` right before calling a
/// registered handler, since dispatch only has the function pointer, not which module registered
/// it. Defaults to `true` (reboot) if no loaded module's range contains the address: every real
/// `SyscallHandler` was resolved from a loaded module's own relocated code, so this should never
/// actually happen, but a fatal default is the safe direction for a case that "can't happen".
pub(crate) fn mark_active_module_by_address(handler_addr: u64) {
    let modules = LOADED_MODULES.lock();
    let fatal = modules
        .iter()
        .find(|m| handler_addr >= m.base && handler_addr < m.base + m.size)
        .map(|m| m.fatal_on_panic)
        .unwrap_or(true);
    drop(modules);
    set_current_module_fatal(fatal);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleError {
    TooShort,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndianness,
    UnsupportedType,
    UnsupportedMachine,
    SectionHeaderOutOfBounds,
    MissingSymbolOrStringTable,
    OutOfMemory,
    MappingFailed,
    RegionExhausted,
    UnresolvedSymbol,
    UnsupportedRelocation(u32),
    RelocationOverflow,
    MissingEntryPoint,
}

struct Section {
    sh_type: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
}

struct Symbol {
    name_off: u32,
    shndx: u16,
    value: u64,
}

struct RelaSectionMeta {
    offset: u64,
    size: u64,
    target_section: usize,
}

struct Relocation {
    offset: u64,
    symbol: u32,
    reloc_type: u32,
    addend: i64,
}

/// A parsed view over an in-memory `ET_REL` object file's sections, symbol table, and relocation
/// sections.
struct Object<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    strtab: &'a [u8],
    rela_sections: Vec<RelaSectionMeta>,
}

impl<'a> Object<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, ModuleError> {
        if bytes.len() < EHDR_SIZE {
            return Err(ModuleError::TooShort);
        }
        if bytes[0..4] != MAGIC {
            return Err(ModuleError::BadMagic);
        }
        if bytes[4] != CLASS_64 {
            return Err(ModuleError::UnsupportedClass);
        }
        if bytes[5] != DATA_LITTLE_ENDIAN {
            return Err(ModuleError::UnsupportedEndianness);
        }
        if read_u16(bytes, 16) != TYPE_REL {
            return Err(ModuleError::UnsupportedType);
        }
        if read_u16(bytes, 18) != MACHINE_X86_64 {
            return Err(ModuleError::UnsupportedMachine);
        }

        let e_shoff = read_u64(bytes, 40) as usize;
        let e_shentsize = read_u16(bytes, 58) as usize;
        let e_shnum = read_u16(bytes, 60) as usize;

        if e_shentsize < SHDR_SIZE {
            return Err(ModuleError::SectionHeaderOutOfBounds);
        }
        let shdrs_size = e_shentsize
            .checked_mul(e_shnum)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        let shdrs_end = e_shoff
            .checked_add(shdrs_size)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        if shdrs_end > bytes.len() {
            return Err(ModuleError::SectionHeaderOutOfBounds);
        }

        let mut sections = Vec::with_capacity(e_shnum);
        for i in 0..e_shnum {
            let off = e_shoff + i * e_shentsize;
            let raw = &bytes[off..off + SHDR_SIZE];
            sections.push(Section {
                sh_type: read_u32(raw, 4),
                flags: read_u64(raw, 8),
                offset: read_u64(raw, 24),
                size: read_u64(raw, 32),
                link: read_u32(raw, 40),
                info: read_u32(raw, 44),
                addralign: read_u64(raw, 48),
            });
        }

        // The (first) SHT_SYMTAB section names its own string table via sh_link -- no separate
        // section-header string table lookup is needed anywhere in this loader, since nothing
        // here needs a *section's* name, only symbol names (via the symtab's own strtab).
        let symtab_index = sections
            .iter()
            .position(|s| s.sh_type == SHT_SYMTAB)
            .ok_or(ModuleError::MissingSymbolOrStringTable)?;
        let symtab = &sections[symtab_index];
        let strtab_section = sections
            .get(symtab.link as usize)
            .ok_or(ModuleError::MissingSymbolOrStringTable)?;
        let strtab_start = strtab_section.offset as usize;
        let strtab_end = strtab_start
            .checked_add(strtab_section.size as usize)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        let strtab = bytes
            .get(strtab_start..strtab_end)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;

        let sym_start = symtab.offset as usize;
        let sym_end = sym_start
            .checked_add(symtab.size as usize)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        let sym_bytes = bytes
            .get(sym_start..sym_end)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        let sym_count = sym_bytes.len() / SYM_SIZE;
        let mut symbols = Vec::with_capacity(sym_count);
        for i in 0..sym_count {
            let raw = &sym_bytes[i * SYM_SIZE..i * SYM_SIZE + SYM_SIZE];
            symbols.push(Symbol {
                name_off: read_u32(raw, 0),
                shndx: read_u16(raw, 6),
                value: read_u64(raw, 8),
            });
        }

        let rela_sections = sections
            .iter()
            .filter(|s| s.sh_type == SHT_RELA)
            .map(|s| RelaSectionMeta {
                offset: s.offset,
                size: s.size,
                target_section: s.info as usize,
            })
            .collect();

        Ok(Object {
            bytes,
            sections,
            symbols,
            strtab,
            rela_sections,
        })
    }

    fn section_bytes(&self, section: &Section) -> Result<&'a [u8], ModuleError> {
        let start = section.offset as usize;
        let end = start
            .checked_add(section.size as usize)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        self.bytes
            .get(start..end)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)
    }

    fn relocations(
        &self,
        meta: &RelaSectionMeta,
    ) -> Result<impl Iterator<Item = Relocation> + '_, ModuleError> {
        let start = meta.offset as usize;
        let end = start
            .checked_add(meta.size as usize)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        let raw = self
            .bytes
            .get(start..end)
            .ok_or(ModuleError::SectionHeaderOutOfBounds)?;
        let count = raw.len() / RELA_SIZE;
        Ok((0..count).map(move |i| {
            let entry = &raw[i * RELA_SIZE..i * RELA_SIZE + RELA_SIZE];
            let info = read_u64(entry, 8);
            Relocation {
                offset: read_u64(entry, 0),
                symbol: (info >> 32) as u32,
                reloc_type: info as u32,
                addend: read_u64(entry, 16) as i64,
            }
        }))
    }

    fn symbol_name(&self, index: usize) -> Result<&'a str, ModuleError> {
        let symbol = self
            .symbols
            .get(index)
            .ok_or(ModuleError::UnresolvedSymbol)?;
        read_str(self.strtab, symbol.name_off as usize).ok_or(ModuleError::UnresolvedSymbol)
    }

    fn find_defined_symbol(&self, name: &str) -> Option<usize> {
        self.symbols.iter().position(|s| {
            s.shndx != SHN_UNDEF && read_str(self.strtab, s.name_off as usize) == Some(name)
        })
    }
}

fn read_str(strtab: &[u8], offset: usize) -> Option<&str> {
    let bytes = strtab.get(offset..)?;
    let end = bytes.iter().position(|&b| b == 0)?;
    core::str::from_utf8(&bytes[..end]).ok()
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

/// Loads `object_bytes` (a merged, relocatable module object -- see `build.rs`'s
/// `build_module_crate`), maps it into the kernel's own address space via `mapper`, resolves and
/// applies its relocations, then calls its `module_init` entry point and returns whatever it
/// returned. `panic_symbol` is the exact mangled name `build.rs` discovered for this specific
/// module's merged panic-entry reference (empty string if the module's code never references
/// one) -- see `resolve_external_symbol`. `fatal_on_panic` is recorded on this module's
/// `LoadedModuleInfo` entry and consulted by `module_panic_trampoline` -- see
/// `CURRENT_MODULE_FATAL`'s own doc comment.
pub fn load(
    name: &'static str,
    object_bytes: &[u8],
    panic_symbol: &str,
    fatal_on_panic: bool,
    mapper: &mut OffsetPageTable<'static>,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<i32, ModuleError> {
    serial_println!(
        "[module] {}: loading ({} byte object)",
        name,
        object_bytes.len()
    );

    let object = Object::parse(object_bytes)?;

    // Pass 1: decide where each SHF_ALLOC section (the sections that actually consume runtime
    // memory -- .text/.rodata/.data/.bss equivalents, as opposed to e.g. relocation or symbol
    // sections themselves) lands within this module's own region, respecting each section's own
    // alignment. Section count is unpredictable and can be large (hundreds, pre-optimization) --
    // nothing here assumes a small, fixed number the way elf.rs's PT_LOAD handling can.
    let mut placements: BTreeMap<usize, u64> = BTreeMap::new();
    let mut cursor: u64 = 0;
    for (index, section) in object.sections.iter().enumerate() {
        if section.flags & SHF_ALLOC == 0 || section.size == 0 {
            continue;
        }
        cursor = align_up(cursor, section.addralign);
        placements.insert(index, cursor);
        cursor += section.size;
    }

    // A minimal GOT, appended after every placed section: one 8-byte slot per R_X86_64_GOTPCREL
    // relocation (no dedup -- a module has at most a handful, not worth the bookkeeping),
    // eagerly populated during relocation application below rather than lazily bound, since every
    // symbol is already fully resolved at load time and there's no dynamic linker-style deferral
    // to gain from doing otherwise. See CLAUDE.md's module-loading section for why this turned
    // out to be a real requirement rather than the optional complexity earlier drafts of this
    // design deliberately avoided: `core::panicking::panic_bounds_check`'s own internal message
    // formatting references a numeric `Display::fmt` impl via GOTPCREL, unavoidably, in any module
    // whose code does ordinary slice indexing -- essentially all of them.
    let mut got_slots_needed: u64 = 0;
    for rela_section in &object.rela_sections {
        for rela in object.relocations(rela_section)? {
            if rela.reloc_type == R_X86_64_GOTPCREL {
                got_slots_needed += 1;
            }
        }
    }
    let got_base = align_up(cursor, 8);
    cursor = got_base + got_slots_needed * 8;

    let region_size = align_up(cursor, PAGE_SIZE);

    let base = allocate_region(region_size)?;
    map_region(base, region_size, mapper, frame_allocator)?;

    // map_region zeroes every page it maps, which already satisfies SHT_NOBITS (.bss-equivalent)
    // sections; copy real (SHT_PROGBITS) section bytes in on top.
    for (&index, &offset) in &placements {
        let section = &object.sections[index];
        if section.sh_type == SHT_NOBITS {
            continue;
        }
        let src = object.section_bytes(section)?;
        let dst = (base + offset) as *mut u8;
        // SAFETY: dst falls within the region map_region just mapped PRESENT | WRITABLE, and
        // src/dst don't overlap (src is a view into the immutable object_bytes input).
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
    }

    // Every defined symbol's now-known absolute address (section-relative offset + this module's
    // base), used both to resolve internal relocations and to find `module_init` below.
    let mut symbol_addrs: BTreeMap<usize, u64> = BTreeMap::new();
    for (index, symbol) in object.symbols.iter().enumerate() {
        if symbol.shndx == SHN_UNDEF {
            continue;
        }
        let Some(&section_offset) = placements.get(&(symbol.shndx as usize)) else {
            // Defined in a section this loader didn't place (not SHF_ALLOC -- e.g. leftover
            // debug info) -- irrelevant, no code will ever reference it via a placed relocation.
            continue;
        };
        symbol_addrs.insert(index, base + section_offset + symbol.value);
    }

    let mut next_got_slot = base + got_base;
    for rela_section in &object.rela_sections {
        let Some(&target_offset) = placements.get(&rela_section.target_section) else {
            continue;
        };
        for rela in object.relocations(rela_section)? {
            let symbol_index = rela.symbol as usize;
            let resolved = match symbol_addrs.get(&symbol_index) {
                Some(&addr) => addr,
                None => {
                    let sym_name = object.symbol_name(symbol_index)?;
                    resolve_external_symbol(sym_name, panic_symbol)
                        .ok_or(ModuleError::UnresolvedSymbol)?
                }
            };
            let site = base + target_offset + rela.offset;
            if rela.reloc_type == R_X86_64_GOTPCREL {
                // SAFETY: slot falls within the GOT region reserved above, inside this module's
                // own just-mapped-writable pages.
                let slot = next_got_slot;
                next_got_slot += 8;
                unsafe { core::ptr::write_unaligned(slot as *mut u64, resolved) };
                // R_X86_64_GOTPCREL's formula (G + GOT + A - P) is exactly R_X86_64_PC32's own
                // formula with the GOT slot's address standing in for the symbol's address --
                // reuse apply_relocation's PC32 branch rather than duplicating the arithmetic.
                apply_relocation(site, R_X86_64_PC32, slot, rela.addend)?;
            } else {
                apply_relocation(site, rela.reloc_type, resolved, rela.addend)?;
            }
        }
    }

    let init_symbol = object
        .find_defined_symbol("module_init")
        .ok_or(ModuleError::MissingEntryPoint)?;
    let init_addr = *symbol_addrs
        .get(&init_symbol)
        .ok_or(ModuleError::MissingEntryPoint)?;

    serial_println!(
        "[module] {}: relocated at {:#x}, calling module_init",
        name,
        base
    );
    // Recorded before module_init runs, not after -- matches real Linux's own "present in
    // /proc/modules the instant relocation finishes" timing, and lets a module's own boot
    // self-check (see sys/modules/oxfs's) see itself already listed.
    LOADED_MODULES.lock().push(LoadedModuleInfo {
        name,
        base,
        size: region_size,
        fatal_on_panic,
    });
    // SAFETY: init_addr was computed above from module_init's own symbol table entry plus this
    // module's now-fully-relocated base -- every relocation touching its code has already been
    // applied, and module_init's real signature (established by every module crate's own
    // #[unsafe(no_mangle)] pub extern "C" fn module_init() -> i32) matches this transmute.
    let module_init: extern "C" fn() -> i32 = unsafe { core::mem::transmute(init_addr) };
    set_current_module_fatal(fatal_on_panic);
    // SAFETY: module loading is single-threaded and never re-entrant (one `load` call runs to
    // completion, including its own `module_init`, before another can start) -- safe to stash raw
    // pointers here for `oxidebsd_module_alloc_zeroed` (see its own doc comment) to use for
    // exactly the duration of this one `module_init()` call, cleared immediately after.
    unsafe {
        CURRENT_LOAD_MAPPER = mapper;
        CURRENT_LOAD_FRAME_ALLOCATOR = frame_allocator;
    }
    let result = module_init();
    unsafe {
        CURRENT_LOAD_MAPPER = core::ptr::null_mut();
        CURRENT_LOAD_FRAME_ALLOCATOR = core::ptr::null_mut();
    }
    serial_println!("[module] {}: module_init returned {}", name, result);

    Ok(result)
}

/// Raw pointers to the currently-active mapper/frame_allocator, valid only for the duration of a
/// module's own `module_init()` call (see `load`'s own call site, right above). Lets
/// `oxidebsd_module_alloc_zeroed` -- an exported kernel API a module calls *from inside*
/// `module_init` -- reach the same `allocate_region`/`map_region` machinery `load` itself already
/// used for the module's own code/data, without threading them through `module_init`'s fixed,
/// parameterless `extern "C" fn() -> i32` signature. Single-core, sequential module loading only
/// -- never concurrent, never re-entrant.
static mut CURRENT_LOAD_MAPPER: *mut OffsetPageTable<'static> = core::ptr::null_mut();
static mut CURRENT_LOAD_FRAME_ALLOCATOR: *mut BootInfoFrameAllocator = core::ptr::null_mut();

/// Kernel API exposed to modules (resolved via `resolve_external_symbol`, called from a module's
/// own `module_init`): hands back a fresh, zeroed, kernel-VA-mapped buffer of `size_bytes`, backed
/// by real physical frames from the frame allocator -- the same `map_region` machinery `load`
/// uses for a module's own code/data, but in the separate `MODULE_DATA_BASE` window, reachable
/// from *inside* `module_init`. Exists so a module with a large runtime storage need (e.g. oxfs's own block
/// pool) doesn't have to declare that storage as a `static mut` array baked into its own object
/// file -- see CLAUDE.md's oxfs section for why that was a real, measured problem (a single
/// module's own mapped region reaching into the GiB range purely from empty, never-yet-written
/// pool storage). Returns 0 on failure (region exhausted, out of physical memory, or called
/// outside a module's own `module_init` -- the last case is a caller bug, not a real runtime
/// condition).
pub(crate) extern "C" fn oxidebsd_module_alloc_zeroed(size_bytes: u64) -> u64 {
    // SAFETY: only ever non-null for the duration of some module's own `module_init`, on this
    // same single core -- never concurrent, never re-entrant (see the statics' own doc comment).
    let mapper = unsafe { CURRENT_LOAD_MAPPER.as_mut() };
    let frame_allocator = unsafe { CURRENT_LOAD_FRAME_ALLOCATOR.as_mut() };
    let (Some(mapper), Some(frame_allocator)) = (mapper, frame_allocator) else {
        serial_println!("[module] oxidebsd_module_alloc_zeroed: called outside module_init");
        return 0;
    };
    let region_size = align_up(size_bytes, PAGE_SIZE);
    let base = match allocate_data_region(region_size) {
        Ok(base) => base,
        Err(_) => return 0,
    };
    match map_region(base, region_size, mapper, frame_allocator) {
        Ok(()) => base,
        Err(_) => 0,
    }
}

/// `/proc/modules` -- real Linux's own seven-space-separated-field format per line (`name size
/// refcount deps state address`), just with fixed placeholders for the three fields this loader
/// has no equivalent concept for: `refcount` (no module ever tracks how many things reference it),
/// `deps` (no inter-module dependency graph -- see `CLAUDE.md`'s own "no inter-module direct
/// calls" note), and `state` (always `Live` -- no module unload exists, so nothing is ever
/// `Unloading`). Listed most-recently-loaded first, matching real `lsmod`/`/proc/modules`
/// ordering (real `insmod` prepends to the kernel's own module list). `size` is the mapped region
/// size in bytes (`region_size` at load time -- page-aligned, includes the GOT), not the raw
/// object-file size `[module] name: loading (N byte object)` logs at boot -- the real Linux
/// "Size" column is a memory footprint, not an on-disk size, and this is the closer analog.
pub(crate) extern "C" fn oxidebsd_proc_modules(buf_ptr: *mut u8, buf_cap: u64) -> i64 {
    let modules = LOADED_MODULES.lock();
    let mut out = Vec::new();
    for entry in modules.iter().rev() {
        out.extend_from_slice(entry.name.as_bytes());
        out.push(b' ');
        crate::process::push_decimal(&mut out, entry.size);
        out.extend_from_slice(b" 0 - Live 0x");
        push_hex(&mut out, entry.base);
        out.push(b'\n');
    }
    drop(modules);
    crate::process::copy_into(&out, buf_ptr, buf_cap)
}

/// Appends `value`'s lowercase hex representation (no leading zeros, no `0x` prefix -- callers add
/// that themselves, matching real `/proc/modules`' own `0x...` address column).
fn push_hex(out: &mut Vec<u8>, value: u64) {
    if value == 0 {
        out.push(b'0');
        return;
    }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut digits = [0u8; 16];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        digits[n] = DIGITS[(v % 16) as usize];
        v /= 16;
        n += 1;
    }
    out.extend(digits[..n].iter().rev());
}

/// Claims `size` bytes of the kernel-module virtual address region, bump-allocator style --
/// mirrors `BootInfoFrameAllocator`'s own "hand out forward, never reuse" philosophy (no module
/// unload/reload exists yet, so there's nothing to reclaim). Errors loudly rather than silently
/// wrapping past `MODULE_REGION_CEILING`, since addresses past it would violate the
/// relocation-model-static assumptions relocations below rely on.
fn allocate_region(size: u64) -> Result<u64, ModuleError> {
    let mut next = NEXT_MODULE_PAGE.lock();
    let base = *next;
    let end = base.checked_add(size).ok_or(ModuleError::RegionExhausted)?;
    if end > MODULE_REGION_CEILING {
        return Err(ModuleError::RegionExhausted);
    }
    *next = end;
    Ok(base)
}

/// `allocate_region` for the module data window (`MODULE_DATA_BASE`).
fn allocate_data_region(size: u64) -> Result<u64, ModuleError> {
    let mut next = NEXT_MODULE_DATA_PAGE.lock();
    let base = *next;
    let end = base.checked_add(size).ok_or(ModuleError::RegionExhausted)?;
    if end > MODULE_DATA_CEILING {
        return Err(ModuleError::RegionExhausted);
    }
    *next = end;
    Ok(base)
}

fn map_region(
    base: u64,
    size: u64,
    mapper: &mut OffsetPageTable<'static>,
    frame_allocator: &mut BootInfoFrameAllocator,
) -> Result<(), ModuleError> {
    if size == 0 {
        return Ok(());
    }
    let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base));
    let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(base + size - 1));
    // No USER_ACCESSIBLE: module code runs only in kernel context, never executed directly by
    // ring-3 code. Every page gets WRITABLE, including ones backing .text-equivalent sections --
    // relocation application below must patch bytes inside them, and this kernel doesn't
    // implement NO_EXECUTE/W^X anywhere yet (the same simplification elf.rs's own doc comment
    // already calls out), so there's no protection benefit to a stricter per-section split today.
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    for page in Page::range_inclusive(start_page, end_page) {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(ModuleError::OutOfMemory)?;
        // SAFETY: frame was just allocated (unused, per BootInfoFrameAllocator's contract), and
        // page falls within this module's freshly bump-allocated, previously-unmapped region.
        unsafe {
            // `.ignore()`, not `.flush()`: same reasoning as `allocator::init_heap`'s own
            // identical fix -- a page this bump-allocator (`allocate_region`) hands out has never
            // been mapped before, so there's no stale TLB entry to invalidate. Load-bearing once
            // any single module's object grows into the tens-of-thousands-of-pages range (a real
            // multi-minute stall under QEMU's software TCG otherwise, one trapped `invlpg` per
            // page) -- `sys/modules/oxfs`'s own object crossed that threshold once its embedded
            // BusyBox roster grew to ~300 applets (see CLAUDE.md's BusyBox section).
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(|_| ModuleError::MappingFailed)?
                .ignore();
        }
        // Freshly allocated physical frames aren't guaranteed zeroed. Written through the page's
        // own, now-mapped virtual address directly: unlike elf.rs (which maps into a *different*,
        // not-yet-active address space and must therefore write through the physical-memory-
        // offset window instead), module pages are mapped into the *currently active* kernel
        // table, so this pointer is immediately valid to dereference.
        let page_ptr = page.start_address().as_mut_ptr::<u8>();
        unsafe { core::ptr::write_bytes(page_ptr, 0, PAGE_SIZE as usize) };
    }
    Ok(())
}

/// Applies one relocation at `site` (an absolute virtual address within this module's now-mapped
/// region) for `reloc_type`, given the already-resolved address (for `R_X86_64_GOTPCREL`, the
/// address of the GOT slot the caller already populated, not the symbol itself -- see `load`'s
/// GOTPCREL handling) and the relocation's addend. These are the complete set of types observed
/// empirically across every module build tried so far (plain calls/data references,
/// `core::fmt`-heavy code including what `core::panicking::panic_bounds_check` itself references,
/// large static-buffer fills/copies) -- see `CLAUDE.md`'s module-loading section. An unrecognized
/// type is reported, not silently ignored: a module built with different codegen (a different
/// optimization level, say) could plausibly need one this loader doesn't handle yet.
fn apply_relocation(
    site: u64,
    reloc_type: u32,
    symbol_addr: u64,
    addend: i64,
) -> Result<(), ModuleError> {
    let value = (symbol_addr as i64).wrapping_add(addend);
    match reloc_type {
        R_X86_64_64 => {
            // SAFETY: site was computed from a placed section's offset within this module's own,
            // just-mapped-writable region (see map_region) plus an in-bounds relocation offset.
            unsafe { core::ptr::write_unaligned(site as *mut u64, value as u64) };
        }
        R_X86_64_32 => {
            let unsigned = value as u64;
            if unsigned > u32::MAX as u64 {
                return Err(ModuleError::RelocationOverflow);
            }
            unsafe { core::ptr::write_unaligned(site as *mut u32, unsigned as u32) };
        }
        R_X86_64_32S => {
            let signed = i32::try_from(value).map_err(|_| ModuleError::RelocationOverflow)?;
            unsafe { core::ptr::write_unaligned(site as *mut u32, signed as u32) };
        }
        R_X86_64_PC32 | R_X86_64_PLT32 => {
            // No real PLT/lazy binding exists here, or is needed: PLT32 is resolved exactly like
            // PC32, direct-referencing the real target -- correct whenever there's no lazy
            // binding to preserve, true for every eagerly-relocated module this loader handles.
            let pc_relative = value.wrapping_sub(site as i64);
            let signed = i32::try_from(pc_relative).map_err(|_| ModuleError::RelocationOverflow)?;
            unsafe { core::ptr::write_unaligned(site as *mut u32, signed as u32) };
        }
        other => return Err(ModuleError::UnsupportedRelocation(other)),
    }
    Ok(())
}

/// The kernel's hand-curated API surface for module code to call into, resolved by name against
/// each module's undefined symbols. Deliberately small and explicit, not an automatically
/// enumerated kernel symbol table -- see `CLAUDE.md`'s module-loading section for why modules
/// avoid `alloc`/`Vec`/`BTreeMap` (so this table doesn't need to expose the internal, unstable
/// `__rust_alloc`-family ABI `#[global_allocator]` wires up) and instead get an explicit
/// `oxidebsd_*` C-ABI surface plus the fixed panic-entry trampoline every module needs whether it
/// calls anything else here or not.
fn resolve_external_symbol(name: &str, panic_symbol: &str) -> Option<u64> {
    if !panic_symbol.is_empty() && name == panic_symbol {
        return Some(module_panic_trampoline as *const () as u64);
    }
    match name {
        "oxidebsd_log" => Some(oxidebsd_log as *const () as u64),
        "oxidebsd_register_syscall" => {
            Some(crate::syscall::oxidebsd_register_syscall as *const () as u64)
        }
        "oxidebsd_module_alloc_zeroed" => Some(oxidebsd_module_alloc_zeroed as *const () as u64),
        "oxidebsd_sys_exit" => Some(crate::syscall::oxidebsd_sys_exit as *const () as u64),
        "oxidebsd_sys_exit_group" => {
            Some(crate::syscall::oxidebsd_sys_exit_group as *const () as u64)
        }
        "oxidebsd_sys_read" => Some(crate::syscall::oxidebsd_sys_read as *const () as u64),
        "oxidebsd_sys_write" => Some(crate::syscall::oxidebsd_sys_write as *const () as u64),
        "oxidebsd_sys_fork" => Some(crate::syscall::oxidebsd_sys_fork as *const () as u64),
        "oxidebsd_sys_clone" => Some(crate::syscall::oxidebsd_sys_clone as *const () as u64),
        "oxidebsd_sys_wait4" => Some(crate::syscall::oxidebsd_sys_wait4 as *const () as u64),
        "oxidebsd_sys_execve" => Some(crate::syscall::oxidebsd_sys_execve as *const () as u64),
        "oxidebsd_sys_execveat" => {
            Some(crate::syscall::oxidebsd_sys_execveat as *const () as u64)
        }
        "oxidebsd_sys_getpid" => Some(crate::syscall::oxidebsd_sys_getpid as *const () as u64),
        "oxidebsd_sys_getppid" => Some(crate::syscall::oxidebsd_sys_getppid as *const () as u64),
        "oxidebsd_sys_mmap" => Some(crate::syscall::oxidebsd_sys_mmap as *const () as u64),
        "oxidebsd_sys_munmap" => Some(crate::syscall::oxidebsd_sys_munmap as *const () as u64),
        "oxidebsd_sys_brk" => Some(crate::syscall::oxidebsd_sys_brk as *const () as u64),
        "oxidebsd_sys_mprotect" => Some(crate::syscall::oxidebsd_sys_mprotect as *const () as u64),
        "oxidebsd_sys_msync" => Some(crate::syscall::oxidebsd_sys_msync as *const () as u64),
        "oxidebsd_sys_mlock" => Some(crate::syscall::oxidebsd_sys_mlock as *const () as u64),
        "oxidebsd_sys_munlock" => Some(crate::syscall::oxidebsd_sys_munlock as *const () as u64),
        "oxidebsd_sys_mlockall" => Some(crate::syscall::oxidebsd_sys_mlockall as *const () as u64),
        "oxidebsd_sys_munlockall" => {
            Some(crate::syscall::oxidebsd_sys_munlockall as *const () as u64)
        }
        "oxidebsd_sys_set_fs_base" => {
            Some(crate::syscall::oxidebsd_sys_set_fs_base as *const () as u64)
        }
        "oxidebsd_sys_writev" => Some(crate::syscall::oxidebsd_sys_writev as *const () as u64),
        "oxidebsd_sys_pwritev2" => Some(crate::syscall::oxidebsd_sys_pwritev2 as *const () as u64),
        "oxidebsd_sys_readv" => Some(crate::syscall::oxidebsd_sys_readv as *const () as u64),
        "oxidebsd_sys_pread" => Some(crate::syscall::oxidebsd_sys_pread as *const () as u64),
        "oxidebsd_sys_pwrite" => Some(crate::syscall::oxidebsd_sys_pwrite as *const () as u64),
        "oxidebsd_sys_pipe" => Some(crate::syscall::oxidebsd_sys_pipe as *const () as u64),
        "oxidebsd_sys_pipe2" => Some(crate::syscall::oxidebsd_sys_pipe2 as *const () as u64),
        "oxidebsd_sys_dup2" => Some(crate::syscall::oxidebsd_sys_dup2 as *const () as u64),
        "oxidebsd_alloc_fd" => Some(crate::fs::fd::oxidebsd_alloc_fd as *const () as u64),
        "oxidebsd_register_fd_ops" => {
            Some(crate::fs::fd::oxidebsd_register_fd_ops as *const () as u64)
        }
        "oxidebsd_register_fd_ops_with_content_id" => {
            Some(crate::fs::fd::oxidebsd_register_fd_ops_with_content_id as *const () as u64)
        }
        "oxidebsd_register_content_accessors" => {
            Some(crate::fs::fd::oxidebsd_register_content_accessors as *const () as u64)
        }
        "oxidebsd_close_fd" => Some(crate::fs::fd::oxidebsd_close_fd as *const () as u64),
        "oxidebsd_set_fd_cloexec" => {
            Some(crate::fs::fd::oxidebsd_set_fd_cloexec as *const () as u64)
        }
        "oxidebsd_set_fd_pread_pwrite" => {
            Some(crate::fs::fd::oxidebsd_set_fd_pread_pwrite as *const () as u64)
        }
        "oxidebsd_set_fd_access_mode" => {
            Some(crate::fs::fd::oxidebsd_set_fd_access_mode as *const () as u64)
        }
        "oxidebsd_set_fd_append" => Some(crate::fs::fd::oxidebsd_set_fd_append as *const () as u64),
        "oxidebsd_set_fd_fb_geometry" => {
            Some(crate::fs::fd::oxidebsd_set_fd_fb_geometry as *const () as u64)
        }
        "oxidebsd_get_cwd" => Some(crate::process::oxidebsd_get_cwd as *const () as u64),
        "oxidebsd_set_cwd" => Some(crate::process::oxidebsd_set_cwd as *const () as u64),
        "oxidebsd_get_root" => Some(crate::process::oxidebsd_get_root as *const () as u64),
        "oxidebsd_set_root" => Some(crate::process::oxidebsd_set_root as *const () as u64),
        "oxidebsd_sys_kill" => Some(crate::syscall::oxidebsd_sys_kill as *const () as u64),
        "oxidebsd_sys_sigaction" => {
            Some(crate::syscall::oxidebsd_sys_sigaction as *const () as u64)
        }
        "oxidebsd_sys_sigprocmask" => {
            Some(crate::syscall::oxidebsd_sys_sigprocmask as *const () as u64)
        }
        "oxidebsd_sys_sigpending" => {
            Some(crate::syscall::oxidebsd_sys_sigpending as *const () as u64)
        }
        "oxidebsd_sys_tkill" => Some(crate::syscall::oxidebsd_sys_tkill as *const () as u64),
        "oxidebsd_sys_sigaltstack" => {
            Some(crate::syscall::oxidebsd_sys_sigaltstack as *const () as u64)
        }
        "oxidebsd_sys_pause" => Some(crate::syscall::oxidebsd_sys_pause as *const () as u64),
        "oxidebsd_sys_sigsuspend" => {
            Some(crate::syscall::oxidebsd_sys_sigsuspend as *const () as u64)
        }
        "oxidebsd_sys_setpgid" => Some(crate::syscall::oxidebsd_sys_setpgid as *const () as u64),
        "oxidebsd_sys_getpgid" => Some(crate::syscall::oxidebsd_sys_getpgid as *const () as u64),
        "oxidebsd_sys_setsid" => Some(crate::syscall::oxidebsd_sys_setsid as *const () as u64),
        "oxidebsd_sys_getsid" => Some(crate::syscall::oxidebsd_sys_getsid as *const () as u64),
        "oxidebsd_sys_ioctl" => Some(crate::syscall::oxidebsd_sys_ioctl as *const () as u64),
        "oxidebsd_sys_get_keyevent" => {
            Some(crate::syscall::oxidebsd_sys_get_keyevent as *const () as u64)
        }
        "oxidebsd_sys_dup" => Some(crate::syscall::oxidebsd_sys_dup as *const () as u64),
        "oxidebsd_sys_uname" => Some(crate::syscall::oxidebsd_sys_uname as *const () as u64),
        "oxidebsd_sys_socketpair" => {
            Some(crate::syscall::oxidebsd_sys_socketpair as *const () as u64)
        }
        "oxidebsd_sys_set_tid_address" => {
            Some(crate::syscall::oxidebsd_sys_set_tid_address as *const () as u64)
        }
        "oxidebsd_sys_fcntl" => Some(crate::syscall::oxidebsd_sys_fcntl as *const () as u64),
        "oxidebsd_sys_shutdown" => Some(crate::syscall::oxidebsd_sys_shutdown as *const () as u64),
        "oxidebsd_random_bytes" => Some(crate::random::oxidebsd_random_bytes as *const () as u64),
        "oxidebsd_fb_geometry" => {
            Some(crate::drivers::fbdev::oxidebsd_fb_geometry as *const () as u64)
        }
        "oxidebsd_sys_clock_gettime" => {
            Some(crate::syscall::oxidebsd_sys_clock_gettime as *const () as u64)
        }
        "oxidebsd_sys_clock_getres" => {
            Some(crate::syscall::oxidebsd_sys_clock_getres as *const () as u64)
        }
        "oxidebsd_sys_clock_settime" => {
            Some(crate::syscall::oxidebsd_sys_clock_settime as *const () as u64)
        }
        "oxidebsd_sys_clock_nanosleep" => {
            Some(crate::syscall::oxidebsd_sys_clock_nanosleep as *const () as u64)
        }
        "oxidebsd_sys_nanosleep" => {
            Some(crate::syscall::oxidebsd_sys_nanosleep as *const () as u64)
        }
        "oxidebsd_sys_setitimer" => {
            Some(crate::syscall::oxidebsd_sys_setitimer as *const () as u64)
        }
        "oxidebsd_sys_getitimer" => {
            Some(crate::syscall::oxidebsd_sys_getitimer as *const () as u64)
        }
        "oxidebsd_real_fd_of" => Some(crate::fs::fd::oxidebsd_real_fd_of as *const () as u64),
        "oxidebsd_proc_exists" => Some(crate::process::oxidebsd_proc_exists as *const () as u64),
        "oxidebsd_proc_pid_at" => Some(crate::process::oxidebsd_proc_pid_at as *const () as u64),
        "oxidebsd_proc_stat_line" => {
            Some(crate::process::oxidebsd_proc_stat_line as *const () as u64)
        }
        "oxidebsd_proc_cmdline" => Some(crate::process::oxidebsd_proc_cmdline as *const () as u64),
        "oxidebsd_proc_status" => Some(crate::process::oxidebsd_proc_status as *const () as u64),
        "oxidebsd_proc_meminfo" => Some(crate::process::oxidebsd_proc_meminfo as *const () as u64),
        "oxidebsd_proc_uptime" => Some(crate::process::oxidebsd_proc_uptime as *const () as u64),
        "oxidebsd_proc_stat_global" => {
            Some(crate::process::oxidebsd_proc_stat_global as *const () as u64)
        }
        "oxidebsd_proc_modules" => Some(oxidebsd_proc_modules as *const () as u64),
        "oxidebsd_fd_at" => Some(crate::fs::fd::oxidebsd_fd_at as *const () as u64),
        "oxidebsd_sys_socket" => Some(crate::net::udp::oxidebsd_sys_socket as *const () as u64),
        "oxidebsd_sys_bind" => Some(crate::net::udp::oxidebsd_sys_bind as *const () as u64),
        "oxidebsd_sys_sendto" => Some(crate::net::udp::oxidebsd_sys_sendto as *const () as u64),
        "oxidebsd_sys_recvfrom" => Some(crate::net::udp::oxidebsd_sys_recvfrom as *const () as u64),
        "oxidebsd_sys_setsockopt" => {
            Some(crate::net::udp::oxidebsd_sys_setsockopt as *const () as u64)
        }
        "oxidebsd_sys_connect" => Some(crate::net::tcp::oxidebsd_sys_connect as *const () as u64),
        "oxidebsd_sys_listen" => Some(crate::net::tcp::oxidebsd_sys_listen as *const () as u64),
        "oxidebsd_sys_accept" => Some(crate::net::tcp::oxidebsd_sys_accept as *const () as u64),
        "oxidebsd_sys_getsockname" => {
            Some(crate::net::udp::oxidebsd_sys_getsockname as *const () as u64)
        }
        "oxidebsd_sys_poll" => Some(crate::net::oxidebsd_sys_poll as *const () as u64),
        "oxidebsd_sys_ppoll" => Some(crate::net::oxidebsd_sys_ppoll as *const () as u64),
        "oxidebsd_sys_getuid" => Some(crate::syscall::oxidebsd_sys_getuid as *const () as u64),
        "oxidebsd_sys_geteuid" => Some(crate::syscall::oxidebsd_sys_geteuid as *const () as u64),
        "oxidebsd_sys_getgid" => Some(crate::syscall::oxidebsd_sys_getgid as *const () as u64),
        "oxidebsd_sys_getegid" => Some(crate::syscall::oxidebsd_sys_getegid as *const () as u64),
        "oxidebsd_sys_setuid" => Some(crate::syscall::oxidebsd_sys_setuid as *const () as u64),
        "oxidebsd_sys_setresuid" => {
            Some(crate::syscall::oxidebsd_sys_setresuid as *const () as u64)
        }
        "oxidebsd_sys_setgid" => Some(crate::syscall::oxidebsd_sys_setgid as *const () as u64),
        "oxidebsd_sys_getgroups" => {
            Some(crate::syscall::oxidebsd_sys_getgroups as *const () as u64)
        }
        "oxidebsd_sys_setgroups" => {
            Some(crate::syscall::oxidebsd_sys_setgroups as *const () as u64)
        }
        "oxidebsd_sys_prlimit64" => {
            Some(crate::syscall::oxidebsd_sys_prlimit64 as *const () as u64)
        }
        "oxidebsd_sys_setpriority" => {
            Some(crate::syscall::oxidebsd_sys_setpriority as *const () as u64)
        }
        "oxidebsd_sys_getpriority" => {
            Some(crate::syscall::oxidebsd_sys_getpriority as *const () as u64)
        }
        "oxidebsd_sys_umask" => Some(crate::syscall::oxidebsd_sys_umask as *const () as u64),
        "oxidebsd_sys_sched_setscheduler" => {
            Some(crate::syscall::oxidebsd_sys_sched_setscheduler as *const () as u64)
        }
        "oxidebsd_sys_sched_setparam" => {
            Some(crate::syscall::oxidebsd_sys_sched_setparam as *const () as u64)
        }
        "oxidebsd_sys_sched_getscheduler" => {
            Some(crate::syscall::oxidebsd_sys_sched_getscheduler as *const () as u64)
        }
        "oxidebsd_sys_sched_getparam" => {
            Some(crate::syscall::oxidebsd_sys_sched_getparam as *const () as u64)
        }
        "oxidebsd_sys_sched_getaffinity" => {
            Some(crate::syscall::oxidebsd_sys_sched_getaffinity as *const () as u64)
        }
        "oxidebsd_sys_sched_get_priority_max" => {
            Some(crate::syscall::oxidebsd_sys_sched_get_priority_max as *const () as u64)
        }
        "oxidebsd_sys_sched_get_priority_min" => {
            Some(crate::syscall::oxidebsd_sys_sched_get_priority_min as *const () as u64)
        }
        "oxidebsd_sys_sched_rr_get_interval" => {
            Some(crate::syscall::oxidebsd_sys_sched_rr_get_interval as *const () as u64)
        }
        "oxidebsd_sys_sched_yield" => {
            Some(crate::syscall::oxidebsd_sys_sched_yield as *const () as u64)
        }
        "oxidebsd_sys_reboot" => Some(crate::syscall::oxidebsd_sys_reboot as *const () as u64),
        "oxidebsd_sys_futex" => Some(crate::syscall::oxidebsd_sys_futex as *const () as u64),
        "oxidebsd_sys_futex_requeue" => {
            Some(crate::syscall::oxidebsd_sys_futex_requeue as *const () as u64)
        }
        "oxidebsd_sys_getrusage" => {
            Some(crate::syscall::oxidebsd_sys_getrusage as *const () as u64)
        }
        "oxidebsd_sys_times" => Some(crate::syscall::oxidebsd_sys_times as *const () as u64),
        "oxidebsd_sys_getrandom" => {
            Some(crate::syscall::oxidebsd_sys_getrandom as *const () as u64)
        }
        "oxidebsd_sys_sysinfo" => Some(crate::syscall::oxidebsd_sys_sysinfo as *const () as u64),
        "oxidebsd_sys_timer_create" => {
            Some(crate::syscall::oxidebsd_sys_timer_create as *const () as u64)
        }
        "oxidebsd_sys_timer_settime" => {
            Some(crate::syscall::oxidebsd_sys_timer_settime as *const () as u64)
        }
        "oxidebsd_sys_timer_gettime" => {
            Some(crate::syscall::oxidebsd_sys_timer_gettime as *const () as u64)
        }
        "oxidebsd_sys_timer_getoverrun" => {
            Some(crate::syscall::oxidebsd_sys_timer_getoverrun as *const () as u64)
        }
        "oxidebsd_sys_timer_delete" => {
            Some(crate::syscall::oxidebsd_sys_timer_delete as *const () as u64)
        }
        "oxidebsd_sys_select" => Some(crate::net::oxidebsd_sys_select as *const () as u64),
        "oxidebsd_sys_mq_open" => Some(crate::syscall::oxidebsd_sys_mq_open as *const () as u64),
        "oxidebsd_sys_mq_unlink" => {
            Some(crate::syscall::oxidebsd_sys_mq_unlink as *const () as u64)
        }
        "oxidebsd_sys_mq_timedsend" => {
            Some(crate::syscall::oxidebsd_sys_mq_timedsend as *const () as u64)
        }
        "oxidebsd_sys_mq_timedreceive" => {
            Some(crate::syscall::oxidebsd_sys_mq_timedreceive as *const () as u64)
        }
        "oxidebsd_sys_mq_notify" => {
            Some(crate::syscall::oxidebsd_sys_mq_notify as *const () as u64)
        }
        "oxidebsd_sys_mq_getsetattr" => {
            Some(crate::syscall::oxidebsd_sys_mq_getsetattr as *const () as u64)
        }
        "oxidebsd_sys_msgget" => Some(crate::syscall::oxidebsd_sys_msgget as *const () as u64),
        "oxidebsd_sys_msgsnd" => Some(crate::syscall::oxidebsd_sys_msgsnd as *const () as u64),
        "oxidebsd_sys_msgrcv" => Some(crate::syscall::oxidebsd_sys_msgrcv as *const () as u64),
        "oxidebsd_sys_msgctl" => Some(crate::syscall::oxidebsd_sys_msgctl as *const () as u64),
        "oxidebsd_sys_semget" => Some(crate::syscall::oxidebsd_sys_semget as *const () as u64),
        "oxidebsd_sys_semop" => Some(crate::syscall::oxidebsd_sys_semop as *const () as u64),
        "oxidebsd_sys_semctl" => Some(crate::syscall::oxidebsd_sys_semctl as *const () as u64),
        "oxidebsd_sys_semtimedop" => {
            Some(crate::syscall::oxidebsd_sys_semtimedop as *const () as u64)
        }
        "oxidebsd_sys_sigtimedwait" => {
            Some(crate::syscall::oxidebsd_sys_sigtimedwait as *const () as u64)
        }
        "oxidebsd_sys_sigqueue" => Some(crate::syscall::oxidebsd_sys_sigqueue as *const () as u64),
        "oxidebsd_sys_shmget" => Some(crate::syscall::oxidebsd_sys_shmget as *const () as u64),
        "oxidebsd_sys_shmat" => Some(crate::syscall::oxidebsd_sys_shmat as *const () as u64),
        "oxidebsd_sys_shmctl" => Some(crate::syscall::oxidebsd_sys_shmctl as *const () as u64),
        "oxidebsd_sys_shmdt" => Some(crate::syscall::oxidebsd_sys_shmdt as *const () as u64),
        "oxidebsd_current_uid" => Some(crate::process::oxidebsd_current_uid as *const () as u64),
        "oxidebsd_current_gid" => Some(crate::process::oxidebsd_current_gid as *const () as u64),
        "oxidebsd_current_umask" => {
            Some(crate::process::oxidebsd_current_umask as *const () as u64)
        }
        "oxidebsd_unix_time" => Some(crate::cpu::rtc::oxidebsd_unix_time as *const () as u64),
        "oxidebsd_block_device_present" => {
            Some(crate::drivers::ata::oxidebsd_block_device_present as *const () as u64)
        }
        "oxidebsd_block_read" => Some(crate::drivers::ata::oxidebsd_block_read as *const () as u64),
        "oxidebsd_block_write" => {
            Some(crate::drivers::ata::oxidebsd_block_write as *const () as u64)
        }
        "oxidebsd_block_read_batch" => {
            Some(crate::drivers::ata::oxidebsd_block_read_batch as *const () as u64)
        }
        "oxidebsd_block_write_batch" => {
            Some(crate::drivers::ata::oxidebsd_block_write_batch as *const () as u64)
        }
        _ => None,
    }
}

/// Writes `len` bytes at `ptr` to the kernel's serial/VGA console. Modules don't use `alloc`, so
/// there's no `&str`/`String` to pass across the module boundary directly -- a raw pointer and
/// length is the simplest shape that survives relocation without a shared ABI crate, matching how
/// the userland ELF boundary already hand-duplicates syscall constants rather than sharing one.
///
/// `extern "C"`, not `#[unsafe(no_mangle)]`: no external object ever needs to find this by
/// symbol name through the system linker (modules resolve against it purely via
/// `resolve_external_symbol`'s own name match, at module-load time, in Rust code) -- only the
/// calling *convention* needs to match what a module's `unsafe extern "C" { fn oxidebsd_log(...);
/// }` declaration expects.
extern "C" fn oxidebsd_log(ptr: *const u8, len: u64) {
    // SAFETY: modules only reach this via a relocated `call`, always passing a pointer/length
    // pair the module itself owns (e.g. a `&str`'s raw parts) -- same trust boundary as
    // sys_write's existing, documented pointer-validation gap in sys/syscall.rs.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
    if let Ok(s) = core::str::from_utf8(bytes) {
        serial_print!("{s}");
    }
}

/// The kernel-side replacement for every loaded module's merged `rust_begin_unwind` reference:
/// every panicking-path function in a module's `core`/`alloc` code ultimately calls this (wired
/// up by `resolve_external_symbol`, keyed off the exact mangled name `build.rs` discovers per
/// module). A module can't define its own `#[panic_handler]` -- only `bin` crates may, and this
/// target's `panic-strategy = "abort"` means there's no unwinding to reason about regardless -- so
/// there's no way to resume the syscall (or `module_init` call) that was in progress.
///
/// The only decision left is what happens *next*: `CURRENT_MODULE_FATAL` (set immediately before
/// every call into module code -- see its own doc comment) says whether the module that just
/// panicked is one whose state can't be safely discarded (today, only filesystem modules --
/// `oxfs`'s entire in-memory filesystem, with no backing store to fall back to). If so, this
/// reboots the same way the fatal exception handlers in `interrupts.rs`
/// (`page_fault_handler`/`general_protection_fault_handler`/...) already do: kernel state after an
/// unrecovered panic can't be trusted, so restarting clean is the safer default. Otherwise it
/// falls back to `hlt_loop()` -- still fully fatal (no per-module restart exists yet), just not
/// worth resetting the whole system over. Restarting only the crashed module in place, without
/// either of these, is a real future direction but needs a saved recovery point to return control
/// to (this trampoline is `-> !`, it never returns today) -- not attempted here.
///
/// `extern "Rust"` (not `"C"`) to match how `core::panicking` itself declares this symbol --
/// relying on both sides being compiled by the very same rustc invocation's ABI for a plain
/// single-reference-argument function, which isn't an officially stable guarantee but holds in
/// practice within one compiler version, same toolchain on both sides.
extern "Rust" fn module_panic_trampoline(info: &core::panic::PanicInfo<'_>) -> ! {
    serial_println!("[module] panic: {}", info);
    // SAFETY: single-core, no concurrent writer -- see CURRENT_MODULE_FATAL's own doc comment.
    if unsafe { CURRENT_MODULE_FATAL } {
        crate::reboot::reboot();
    } else {
        crate::hlt_loop();
    }
}
