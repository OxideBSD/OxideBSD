//! A hand-rolled, minimal ELF64 parser and loader.
//!
//! Deliberately not a dependency (see `CLAUDE.md`'s dependency notes): this only needs to handle
//! the narrow slice of the format our own toolchain produces — a non-relocatable `ET_EXEC` or
//! `ET_DYN` binary with a handful of `PT_LOAD` segments, optionally one `PT_INTERP`, and nothing
//! else — which is small and mechanical enough to own outright. Still no real *relocation
//! processing* here (no `R_X86_64_RELATIVE`/GOT/PLT patching) — `load()` does support a real,
//! caller-chosen additive `bias` applied to every segment's `p_vaddr`. Three real callers exist:
//! every fixed-address `ET_EXEC` main binary passes `bias: 0` (matching its own `linker.ld` load
//! address); a `PT_INTERP` interpreter is loaded at the fixed `INTERP_LOAD_BASE` bias (see
//! `load()`'s own doc comment for why this arithmetic is real and necessary — a naturally-linked
//! `ET_DYN` image's own `.dynamic`/`.rela.dyn` entries are stored *as if* loaded at bias `0`, and
//! it's the loaded image's own userspace bootstrap code, real musl `ldso/dlstart.c`, that applies
//! the real runtime bias at startup, reading it back from `AT_BASE`); and a no-`PT_INTERP` `ET_DYN`
//! main binary (a real PIE) is loaded at a real, kernel-chosen bias randomized fresh on every
//! `execve()` (see `process::aslr::pick_bias`) — no userspace bootstrap exists for this third case
//! (no `ld.so`), so it relies instead on the build-time zero-relocation guarantee
//! (`build.rs`'s `assert_zero_relocations`): this file's only job in every case is to place the
//! image correctly and report that same bias truthfully, never to touch a relocation table itself.
//!
//! Multi-byte fields are read via explicit `from_le_bytes` on byte slices rather than casting the
//! input to a `#[repr(C)]` struct: `include_bytes!` output has no alignment guarantee, and an
//! unaligned struct cast would be undefined behavior.

use alloc::collections::BTreeMap;

use x86_64::VirtAddr;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB, mapper::MapToError,
};

const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const CLASS_64: u8 = 2;
const DATA_LITTLE_ENDIAN: u8 = 1;
const TYPE_EXEC: u16 = 2;
const TYPE_DYN: u16 = 3;
const MACHINE_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_WRITE: u32 = 1 << 1;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const PAGE_SIZE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    UnsupportedClass,
    UnsupportedEndianness,
    UnsupportedType,
    UnsupportedMachine,
    ProgramHeaderOutOfBounds,
    SegmentOutOfBounds,
    OutOfMemory,
    MappingFailed,
}

/// A parsed view over an in-memory ELF64 executable's header and program headers.
pub struct Elf<'a> {
    bytes: &'a [u8],
    entry: u64,
    e_type: u16,
    phoff: usize,
    phnum: usize,
    phentsize: usize,
}

struct ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

impl<'a> Elf<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ElfError> {
        if bytes.len() < EHDR_SIZE {
            return Err(ElfError::TooShort);
        }
        if bytes[0..4] != MAGIC {
            return Err(ElfError::BadMagic);
        }
        if bytes[4] != CLASS_64 {
            return Err(ElfError::UnsupportedClass);
        }
        if bytes[5] != DATA_LITTLE_ENDIAN {
            return Err(ElfError::UnsupportedEndianness);
        }
        let e_type = read_u16(bytes, 16);
        // ET_DYN covers two real, distinct cases today: a PT_INTERP dynamic-linker image (always
        // ET_DYN, loaded at the fixed `INTERP_LOAD_BASE` bias — see `load()`'s own doc comment),
        // and a no-PT_INTERP main executable built as a genuine PIE (loaded at a real, kernel-
        // chosen, per-`execve()`-randomized bias — see `process::aslr`). Neither case involves the
        // kernel processing any relocation table itself: both rely on the disciplined "never store
        // an address as data" coding style (verified at build time — see `build.rs`'s
        // `assert_zero_relocations`) that makes a plain bias-and-map load correct with zero
        // `R_X86_64_RELATIVE` fixups needed.
        if e_type != TYPE_EXEC && e_type != TYPE_DYN {
            return Err(ElfError::UnsupportedType);
        }
        if read_u16(bytes, 18) != MACHINE_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }

        let e_entry = read_u64(bytes, 24);
        let e_phoff = read_u64(bytes, 32) as usize;
        let e_phentsize = read_u16(bytes, 54) as usize;
        let e_phnum = read_u16(bytes, 56) as usize;

        let phdrs_size = e_phentsize
            .checked_mul(e_phnum)
            .ok_or(ElfError::ProgramHeaderOutOfBounds)?;
        let phdrs_end = e_phoff
            .checked_add(phdrs_size)
            .ok_or(ElfError::ProgramHeaderOutOfBounds)?;
        if e_phentsize < PHDR_SIZE || phdrs_end > bytes.len() {
            return Err(ElfError::ProgramHeaderOutOfBounds);
        }

        Ok(Elf {
            bytes,
            entry: e_entry,
            e_type,
            phoff: e_phoff,
            phnum: e_phnum,
            phentsize: e_phentsize,
        })
    }

    pub fn entry_point(&self) -> VirtAddr {
        VirtAddr::new(self.entry)
    }

    /// `true` for a real `ET_DYN` image — either a `PT_INTERP` interpreter or a no-`PT_INTERP`
    /// PIE main binary (see `do_execve`, which distinguishes the two via `interpreter()`).
    pub fn is_dynamic(&self) -> bool {
        self.e_type == TYPE_DYN
    }

    /// The raw `e_phoff`/`e_phnum`/`e_phentsize` header fields — needed for `AT_PHDR`/`AT_PHENT`/
    /// `AT_PHNUM` in a musl-compatible initial stack (see `src/user_stack.rs`), which musl's own
    /// `__init_tls` walks to find the `PT_TLS` segment. Exposed as plain accessors rather than one
    /// struct: `user_stack.rs` needs all three independently, and none of them are sensitive
    /// internal state the way `bytes`/`phoff` staying private otherwise protects.
    pub fn phoff(&self) -> u64 {
        self.phoff as u64
    }

    pub fn phnum(&self) -> u64 {
        self.phnum as u64
    }

    pub fn phentsize(&self) -> u64 {
        self.phentsize as u64
    }

    /// The runtime virtual address of the program header table itself (`AT_PHDR`) — the standard
    /// derivation is `(load bias) + e_phoff`, where "load bias" is the virtual address that file
    /// offset `0` would map to (`p_vaddr - p_offset`, constant across every `PT_LOAD` segment of a
    /// well-formed ELF, so any one of them gives the same answer). Computed from the segment with
    /// the *smallest* `p_offset` rather than requiring one with `p_offset == 0` exactly: this
    /// codebase's own minimal `regress/*/linker.ld` scripts (unlike a normal linker's default
    /// script) don't map the ELF header/program header table into any `PT_LOAD` segment at all —
    /// their first segment typically starts at file offset `0x1000`, not `0` — so the computed
    /// value there points at memory that was never actually mapped. That's fine: `ring3-smoke`/
    /// `stsh`/`fork-exec-smoke` never read `AT_PHDR` (they're hand-written `_start` functions that
    /// ignore the whole initial stack) — only a real libc (musl) built with an ordinary linker
    /// script, which *does* map the headers, ever dereferences this. `0` if there are no `PT_LOAD`
    /// segments at all (degenerate; `elf::load` itself would have mapped nothing).
    pub fn phdr_vaddr(&self) -> u64 {
        self.program_headers()
            .filter(|h| h.p_type == PT_LOAD)
            .min_by_key(|h| h.p_offset)
            .map(|h| (h.p_vaddr - h.p_offset) + self.phoff as u64)
            .unwrap_or(0)
    }

    /// The highest virtual address any `PT_LOAD` segment reaches (`p_vaddr + p_memsz`, page-aligned
    /// up) — where a fresh heap should start growing from. `0` if there are no `PT_LOAD` segments
    /// at all (never true in practice for a real `ET_EXEC`, but a harmless base case).
    pub fn highest_loaded_address(&self) -> u64 {
        let highest = self
            .program_headers()
            .filter(|h| h.p_type == PT_LOAD)
            .map(|h| h.p_vaddr + h.p_memsz)
            .max()
            .unwrap_or(0);
        highest.div_ceil(PAGE_SIZE) * PAGE_SIZE
    }

    /// The `PT_INTERP` segment's content, if present — the NUL-terminated interpreter path a real
    /// dynamically-linked binary embeds (e.g. `/lib/ld-musl-x86_64.so.1`). Trims exactly the one
    /// trailing NUL `p_filesz` always includes (a real interpreter string), returning the bare
    /// path bytes. Bounds-checked the same way `elf::load`'s own `PT_LOAD` handling is — this data
    /// comes from the same untrusted file bytes.
    pub fn interpreter(&self) -> Result<Option<&'a [u8]>, ElfError> {
        for header in self.program_headers() {
            if header.p_type != PT_INTERP {
                continue;
            }
            let end = header
                .p_offset
                .checked_add(header.p_filesz)
                .ok_or(ElfError::SegmentOutOfBounds)?;
            if end as usize > self.bytes.len() {
                return Err(ElfError::SegmentOutOfBounds);
            }
            let mut path = &self.bytes[header.p_offset as usize..end as usize];
            if path.last() == Some(&0) {
                path = &path[..path.len() - 1];
            }
            return Ok(Some(path));
        }
        Ok(None)
    }

    fn program_headers(&self) -> impl Iterator<Item = ProgramHeader> + '_ {
        (0..self.phnum).map(move |i| {
            let offset = self.phoff + i * self.phentsize;
            let raw = &self.bytes[offset..offset + PHDR_SIZE];
            ProgramHeader {
                p_type: read_u32(raw, 0),
                p_flags: read_u32(raw, 4),
                p_offset: read_u64(raw, 8),
                p_vaddr: read_u64(raw, 16),
                p_filesz: read_u64(raw, 32),
                p_memsz: read_u64(raw, 40),
            }
        })
    }
}

/// Maps and copies every `PT_LOAD` segment of `elf` into `mapper`'s address space, returning the
/// real runtime entry point (`elf.entry_point() + bias`). `physical_memory_offset` is used to
/// write segment bytes into freshly allocated frames directly (rather than through `mapper`'s own
/// mapping, which may be read-only, and which may belong to an address space that isn't active
/// yet) — the same technique used throughout `sys/memory.rs` and `src/address_space.rs`.
///
/// `bias` is added to every segment's `p_vaddr` (and to the returned entry point) before mapping —
/// `0` for every fixed-address `ET_EXEC` main binary (its own `p_vaddr`s already *are* its real,
/// fixed runtime addresses, matching its own `linker.ld`); a real, kernel-chosen nonzero value for
/// a `PT_INTERP` interpreter (`lifecycle.rs`'s `do_execve`, fixed `INTERP_LOAD_BASE`); and a real,
/// per-`execve()`-randomized nonzero value for a no-`PT_INTERP` PIE main binary (same `do_execve`,
/// `process::aslr::pick_bias()` — note that whoever builds this binary's own initial stack, i.e.
/// `user_stack::build`, must also add this same bias to `AT_PHDR`/`AT_ENTRY`, since `Elf::
/// phdr_vaddr()`/`entry_point()` report unbiased file-relative values). **Found the hard way, via
/// a real page fault, why the interpreter case can't just use bias `0` too** (which was this file's original
/// milestone-1 design): a naturally-linked `ET_DYN` shared object's own `.rela.dyn`/`DT_RELA`
/// table already stores addresses "as if loaded at bias `0`" — its own userspace bootstrap
/// (`ldso/dlstart.c`, real musl) computes `real_addr = AT_BASE + stored_value`, so mapping it at a
/// *fixed link-time* base (via `-Wl,-Ttext-segment=`, as if it needed no further adjustment) bakes
/// *already-absolute* addresses into that same table — and reporting that fixed base as `AT_BASE`
/// then double-counts it, producing a wild pointer (confirmed directly: `readelf -r` on such a
/// build showed `.rela.dyn` entries already absolute, e.g. `Offset=00000c0aab20`, not
/// zero-based — and the observed fault address matched `AT_BASE + that_same_value` almost
/// exactly). The fix is this real, if small, bias: link the interpreter *naturally* (near-zero
/// base, like any ordinary `.so`), let this function shift it to wherever the kernel actually
/// wants it, and report that same shift as `AT_BASE` — exactly the same math a real kernel's own
/// ELF loader performs for a `PT_INTERP` interpreter, not a shortcut.
pub fn load(
    elf: &Elf,
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    physical_memory_offset: VirtAddr,
    bias: u64,
) -> Result<VirtAddr, ElfError> {
    // Tiny binaries routinely have multiple PT_LOAD segments (e.g. `.text` then `.rodata`)
    // sharing a page, since segments aren't aligned to each other, just each internally aligned
    // to `p_align`. Track which pages this call has already mapped so a later segment reuses the
    // same frame instead of re-mapping (which fails: the page is already present) or re-zeroing
    // it (which would wipe out an earlier segment's bytes already written there).
    let mut mapped_pages: BTreeMap<Page<Size4KiB>, PhysFrame<Size4KiB>> = BTreeMap::new();

    for header in elf.program_headers() {
        if header.p_type != PT_LOAD {
            continue;
        }
        if header.p_filesz > header.p_memsz {
            return Err(ElfError::SegmentOutOfBounds);
        }
        let file_end = header
            .p_offset
            .checked_add(header.p_filesz)
            .ok_or(ElfError::SegmentOutOfBounds)?;
        if file_end as usize > elf.bytes.len() {
            return Err(ElfError::SegmentOutOfBounds);
        }

        let mem_start = header
            .p_vaddr
            .checked_add(bias)
            .ok_or(ElfError::SegmentOutOfBounds)?;
        let mem_end = mem_start
            .checked_add(header.p_memsz)
            .ok_or(ElfError::SegmentOutOfBounds)?;
        // The file-backed portion of the segment; anything in [file_backed_end, mem_end) is BSS.
        let file_backed_end = mem_start + header.p_filesz;

        let start_page = Page::<Size4KiB>::containing_address(VirtAddr::new(mem_start));
        let end_page = Page::<Size4KiB>::containing_address(VirtAddr::new(
            mem_end.saturating_sub(1).max(mem_start),
        ));

        let flags = PageTableFlags::PRESENT
            | PageTableFlags::USER_ACCESSIBLE
            | if header.p_flags & PF_WRITE != 0 {
                PageTableFlags::WRITABLE
            } else {
                PageTableFlags::empty()
            };

        for page in Page::range_inclusive(start_page, end_page) {
            let frame = match mapped_pages.get(&page) {
                Some(&frame) => frame,
                None => {
                    let frame = frame_allocator
                        .allocate_frame()
                        .ok_or(ElfError::OutOfMemory)?;
                    unsafe {
                        mapper
                            .map_to(page, frame, flags, frame_allocator)
                            .map_err(|_: MapToError<Size4KiB>| ElfError::MappingFailed)?
                            .flush();
                    }

                    // Zero the whole frame (covers BSS and any partial-page padding) before any
                    // segment's bytes get copied in below.
                    let frame_ptr = (physical_memory_offset + frame.start_address().as_u64())
                        .as_mut_ptr::<u8>();
                    unsafe { core::ptr::write_bytes(frame_ptr, 0, PAGE_SIZE as usize) };

                    mapped_pages.insert(page, frame);
                    frame
                }
            };
            let frame_ptr =
                (physical_memory_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();

            let page_start = page.start_address().as_u64();
            let page_end = page_start + PAGE_SIZE;
            let copy_start = mem_start.max(page_start);
            let copy_end = file_backed_end.min(page_end);
            if copy_start < copy_end {
                let file_offset = (header.p_offset + (copy_start - mem_start)) as usize;
                let len = (copy_end - copy_start) as usize;
                let dst = unsafe { frame_ptr.add((copy_start - page_start) as usize) };
                let src = &elf.bytes[file_offset..file_offset + len];
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, len) };
            }
        }
    }

    Ok(VirtAddr::new(elf.entry_point().as_u64().wrapping_add(bias)))
}

// pub(crate), not private: sys/module.rs's ET_REL parser reads the same little-endian ELF64
// field shapes and reuses these rather than duplicating them -- everything past "read a field",
// section-header/symbol-table parsing and relocation application, is genuinely different from
// this file's PT_LOAD-segment loading and stays separate (see sys/module.rs's own doc comment).
pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
