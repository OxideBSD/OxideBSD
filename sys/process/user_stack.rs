//! Builds the System V AMD64 initial-process stack image (`argc`/`argv[]`/`envp[]`/auxv) a real
//! libc's `_start` (musl's `crt1`, specifically — see `CLAUDE.md`'s musl section) reads directly
//! off the stack before `main` ever runs. Every native-ABI binary run by hand in this codebase so
//! far (`ring3-smoke`, `stsh`, `fork-exec-smoke`) ignores whatever's on its stack entirely, so
//! adding real content here is safe for everything already working — this only becomes
//! load-bearing once a real libc actually reads it.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use x86_64::VirtAddr;
use x86_64::structures::paging::{Page, PhysFrame, Size4KiB};

use crate::process::elf::Elf;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_HWCAP: u64 = 16;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;

const PAGE_SIZE: u64 = 4096;

/// Builds the stack image for `elf` (used for `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_ENTRY`) with the
/// given `argv`/`envp` byte strings (a NUL is appended automatically — don't include one), and
/// writes it into the top of the already-mapped user stack described by `mapped_pages` (the same
/// `(Page, PhysFrame)` map `elf::load`'s own BSS-zeroing loop builds — see `process.rs`'s
/// `map_user_stack`), via the phys-offset technique used throughout this codebase for writing into
/// a not-necessarily-active address space. `interp_base`, when `Some`, is a `PT_INTERP`
/// interpreter's own real runtime bias (`sys/process.rs`'s `INTERP_LOAD_BASE`, the same value
/// passed as `elf::load`'s own `bias` parameter when loading it) and becomes `AT_BASE`; `None` for
/// every binary with no interpreter (a fixed-address `ET_EXEC`, or a no-`PT_INTERP` PIE main
/// binary), which keeps `AT_BASE` at `0`. This isn't just "no bias to report" — musl's own
/// dynamic-linker bootstrap treats `AT_BASE == 0` as "I was invoked directly as the main program,
/// not as someone else's interpreter," so passing a real base here is required, not cosmetic,
/// once a caller starts loading an interpreter.
///
/// `main_bias` is entirely separate from `interp_base`: it's the *main binary's own* real runtime
/// bias (`0` for a fixed-address `ET_EXEC`, or `process::aslr::pick_bias()`'s real random value
/// for a PIE main binary — see `do_execve`), and must be added to `AT_PHDR`/`AT_ENTRY` below.
/// `elf.phdr_vaddr()`/`elf.entry_point()` report unbiased, file-relative values — a real bug this
/// codebase hit and fixed: before `main_bias` existed, these were silently correct only because
/// the main binary's bias was always `0`.
///
/// Returns the final, 16-byte-aligned `RSP`.
///
/// # Panics
///
/// Panics if the built image doesn't fit within `[stack_bottom, stack_top)` — indicates a binary
/// this codebase's loader doesn't claim to support (see `elf.rs`'s own "narrow slice of the
/// format" framing), not a runtime condition legitimate callers should ever hit.
#[allow(clippy::too_many_arguments)] // real System V argv/envp/auxv stack shape, not arbitrary
pub fn build(
    elf: &Elf,
    argv: &[&[u8]],
    envp: &[&[u8]],
    stack_top: VirtAddr,
    stack_bottom: VirtAddr,
    mapped_pages: &BTreeMap<Page<Size4KiB>, PhysFrame<Size4KiB>>,
    physical_memory_offset: VirtAddr,
    interp_base: Option<u64>,
    main_bias: u64,
) -> VirtAddr {
    let phdr_vaddr = elf.phdr_vaddr() + main_bias;

    // 16 fresh bytes per exec: musl seeds its stack-protector canary (and Rust std its hashmap
    // keys) from these, so a fixed value would make every canary on the system predictable.
    let mut random_bytes = [0u8; 16];
    crate::random::oxidebsd_random_bytes(random_bytes.as_mut_ptr() as u64, 16);

    // --- Strings first (argv, then envp, then AT_RANDOM's 16 bytes), each remembering where it
    // landed so the pointer arrays built below can reference them. ---
    let mut strings: Vec<u8> = Vec::new();
    let mut argv_offsets: Vec<usize> = Vec::with_capacity(argv.len());
    for &s in argv {
        argv_offsets.push(strings.len());
        strings.extend_from_slice(s);
        strings.push(0);
    }
    let mut envp_offsets: Vec<usize> = Vec::with_capacity(envp.len());
    for &s in envp {
        envp_offsets.push(strings.len());
        strings.extend_from_slice(s);
        strings.push(0);
    }
    let random_offset = strings.len();
    strings.extend_from_slice(&random_bytes);

    // Fixed auxv entries -- AT_SECURE/AT_RANDOM are appended separately below (AT_RANDOM's value
    // depends on where the strings block ends up, resolved only once image_start is known), then
    // AT_NULL terminates the vector.
    let auxv: [(u64, u64); 11] = [
        (AT_PHDR, phdr_vaddr),
        (AT_PHENT, elf.phentsize()),
        (AT_PHNUM, elf.phnum()),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, interp_base.unwrap_or(0)),
        (AT_ENTRY, elf.entry_point().as_u64() + main_bias),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_HWCAP, 0),
    ];

    // argc + argv[]+NULL + envp[]+NULL + (auxv entries + AT_SECURE + AT_RANDOM + AT_NULL) pairs.
    let array_len_qwords = 1 + (argv.len() + 1) + (envp.len() + 1) + (auxv.len() + 2 + 1) * 2;
    let arrays_len = array_len_qwords * 8;
    let strings_len = strings.len();
    let total_len = arrays_len + strings_len;

    // Round down to a 16-byte boundary so RSP (which will point at the very start of this image,
    // the arrays block) satisfies System V's initial-process-stack alignment requirement.
    let image_start = (stack_top.as_u64() - total_len as u64) & !0xf;
    let strings_base = image_start + arrays_len as u64;

    assert!(
        image_start >= stack_bottom.as_u64(),
        "user_stack::build: argv/envp/auxv image ({total_len} bytes) doesn't fit in the mapped \
         user stack region"
    );

    let mut image = Vec::with_capacity((stack_top.as_u64() - image_start) as usize);
    image.extend_from_slice(&(argv.len() as u64).to_le_bytes());
    for &off in &argv_offsets {
        image.extend_from_slice(&(strings_base + off as u64).to_le_bytes());
    }
    image.extend_from_slice(&0u64.to_le_bytes());
    for &off in &envp_offsets {
        image.extend_from_slice(&(strings_base + off as u64).to_le_bytes());
    }
    image.extend_from_slice(&0u64.to_le_bytes());
    for &(tag, value) in &auxv {
        image.extend_from_slice(&tag.to_le_bytes());
        image.extend_from_slice(&value.to_le_bytes());
    }
    image.extend_from_slice(&AT_SECURE.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&AT_RANDOM.to_le_bytes());
    image.extend_from_slice(&(strings_base + random_offset as u64).to_le_bytes());
    image.extend_from_slice(&AT_NULL.to_le_bytes());
    image.extend_from_slice(&0u64.to_le_bytes());
    image.extend_from_slice(&strings);

    debug_assert_eq!(
        image.len(),
        total_len,
        "user_stack::build: length mismatch while building the image"
    );

    write_image(
        &image,
        VirtAddr::new(image_start),
        mapped_pages,
        physical_memory_offset,
    );

    VirtAddr::new(image_start)
}

/// Copies `image` into the physical frames backing `[at, at + image.len())`, looking each covered
/// page up in `mapped_pages` — the same per-page phys-offset-write technique `elf::load` uses,
/// generalized to a byte range that isn't necessarily page-aligned at either end (unlike a
/// `PT_LOAD` segment's own zeroing, which always fills whole pages).
fn write_image(
    image: &[u8],
    at: VirtAddr,
    mapped_pages: &BTreeMap<Page<Size4KiB>, PhysFrame<Size4KiB>>,
    physical_memory_offset: VirtAddr,
) {
    let mut written = 0usize;
    while written < image.len() {
        let addr = at + written as u64;
        let page = Page::<Size4KiB>::containing_address(addr);
        let frame = mapped_pages
            .get(&page)
            .expect("user_stack::write_image: target page not present in the mapped user stack");
        let page_offset = (addr.as_u64() - page.start_address().as_u64()) as usize;
        let chunk_len = (PAGE_SIZE as usize - page_offset).min(image.len() - written);
        let dst = (physical_memory_offset + frame.start_address().as_u64()).as_mut_ptr::<u8>();
        // SAFETY: frame is a live, present physical frame backing `page` (from mapped_pages, built
        // by the caller's own mapping loop); physical_memory_offset is the bootloader's phys-memory
        // mapping, giving a valid pointer to write through.
        unsafe {
            core::ptr::copy_nonoverlapping(
                image[written..written + chunk_len].as_ptr(),
                dst.add(page_offset),
                chunk_len,
            );
        }
        written += chunk_len;
    }
}
