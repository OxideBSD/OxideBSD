/* Multiboot2 boot-path linker script -- second, standalone sibling of x86_64-oxidebsd.ld, used
 * only by smoke/multiboot2-boot-smoke. Never touches the existing script or the main kernel
 * binary/58 existing tests/*.rs files.
 *
 * "Higher Half Bare Bones" AT()-offset idiom: a low `boot32` PHDR holds the Multiboot2 header and
 * the 32-bit trampoline (`src/boot/multiboot2.rs`'s `_start32`) at its natural physical load
 * address; `.text`/`.rodata`/`.data`/`.bss` then keep the *exact same* VMA
 * (0xffffffff80000000) the plain-Limine kernel script uses -- their LMA (physical load address)
 * is what actually moves, down to just above the trampoline, via explicit `AT()`. This is why a
 * virtual address inside the compiled kernel's own image translates to a physical one via a
 * single, constant offset (`VA - 0xffffffff80000000 + _kernel_phys_start`), used by
 * `boot::multiboot2`'s final page-table construction.
 *
 * `_kernel_phys_start`/`_kernel_phys_end` bound the main kernel image's own physical footprint
 * (NOT including the tiny `boot32` trampoline before it) -- `boot::multiboot2` sizes both its
 * temporary and final "kernel higher-half" page-table window from these, dynamically, rather than
 * a hardcoded guess. This matters more than it looks: this kernel's own embedded BusyBox/musl/
 * TinyCC/Clang+LLVM/POSIX-conformance-corpus content makes the real image's `.rodata` alone
 * upward of 100 MiB already (confirmed via `readelf -l` against a real release build) and grows
 * over time -- see CLAUDE.md's userland-load-base-floor gotcha for the same class of "embedded
 * corpus outgrew a fixed constant" bug hitting repeatedly elsewhere in this codebase.
 */
OUTPUT_FORMAT(elf64-x86-64)

ENTRY(_start32)

PHDRS
{
    boot32 PT_LOAD FLAGS(7); /* R+W+X -- the 32-bit trampoline needs to write its own temporary
                                 page tables/GDT, held in .boot32.data/.boot32.bss */
    text   PT_LOAD FLAGS(5); /* R+X */
    rodata PT_LOAD FLAGS(4); /* R   */
    data   PT_LOAD FLAGS(6); /* R+W */
}

SECTIONS
{
    /* Physical load address for the trampoline: the standard "Higher Half Bare Bones" 1 MiB,
     * comfortably above the real-mode IVT/BDA and typical Multiboot2 info-structure placement. */
    . = 0x100000;

    .multiboot_header : {
        KEEP(*(.multiboot_header))
    } :boot32

    .boot32.text : {
        *(.boot32.text)
    } :boot32

    .boot32.data : {
        *(.boot32.data)
    } :boot32

    /* Real BSS (zero-filled by any spec-compliant ELF loader, GRUB/Limine included) -- the
     * trampoline's own temporary GDT/page-table scratch space. Not `(NOLOAD)`: this PHDR still
     * needs a real memsz > filesz gap for the loader to zero, which a `(NOLOAD)` section (excluded
     * from PT_LOAD entirely) would not get. */
    .boot32.bss : {
        *(.boot32.bss)
    } :boot32

    /* 2 MiB-align the main kernel image's own physical load address -- required so the temporary
     * and final page tables below can map it with plain 2 MiB huge pages without needing a
     * separate, non-huge-page-aligned leading fragment. Wastes at most ~2 MiB of boot-ISO space. */
    . = ALIGN(0x200000);
    _kernel_phys_base = .;

    /* Reset the VMA counter to the exact same higher-half base the plain-Limine script uses --
     * *not* a "." += VMA_BASE" relative to the trampoline's own end, which would shift .text's own
     * VMA away from where every kernel-side absolute address/symbol already assumes it lives. */
    . = 0xffffffff80000000;

    .text : AT(_kernel_phys_base) {
        _kernel_phys_start = LOADADDR(.text);
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : AT(_kernel_phys_base + (ADDR(.rodata) - ADDR(.text))) {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : AT(_kernel_phys_base + (ADDR(.data) - ADDR(.text))) {
        *(.data .data.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got)
        *(.relro_padding)
    } :data

    .bss : AT(_kernel_phys_base + (ADDR(.bss) - ADDR(.text))) {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    _kernel_phys_end = _kernel_phys_base + (ADDR(.bss) - ADDR(.text)) + SIZEOF(.bss);

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment)
    }
}
