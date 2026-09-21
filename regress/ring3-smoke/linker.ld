/* Forces a load base clear of the kernel's own image, the kernel heap (0x444444440000), and the
 * physical-memory-offset window (~0x18000000000) -- see src/address_space.rs for why those
 * regions matter: a new address space starts as a shallow copy of the kernel's own page tables,
 * so this binary's segments must not collide with them.
 *
 * Also clear of the bootloader's own identity-mapped low-memory region: the `bootloader` crate
 * (v0.9) identity-maps at least the first ~6 MiB of physical memory (kernel-only, not
 * USER_ACCESSIBLE) as part of its own bootstrap -- confirmed empirically (PD entries 0-2 present
 * at boot, entry 3+ not) back when the kernel's own image was only ~0x237000 (~2.2 MiB), i.e. the
 * bootloader's own fixed identity-map was the binding constraint, not the kernel's size. That
 * inverted once `sys/modules/oxfs` started embedding every BusyBox applet's own ELF bytes (~300 of
 * them -- see CLAUDE.md's BusyBox section) via `include_bytes!`, itself embedded into the
 * *kernel's own* binary the same way: the kernel's image crossed ~0x162c530 (~22.7 MiB), now
 * comfortably the larger of the two. Since every fresh address space shallow-copies/aliases
 * whatever's kernel-only in the currently active table (see `AddressSpace::fork`/
 * `new_excluding_user` in `src/address_space.rs`), a user ELF loaded inside either region collides
 * with it (`MapToError::PageAlreadyMapped`) the moment anything tries to `execve` it into a
 * freshly built address space -- this used to be 0x400000, which sat squarely inside the
 * bootloader's own fixed region and only broke once `process::do_execve` started actually
 * exercising this path via `stsh`'s `execve` support; then 0x800000, which was clear of *that* but
 * got swallowed by the kernel's own growth in turn (confirmed live: `hush`, at a different but
 * similarly low fixed address, started failing to spawn as pid 1 with exactly this error once
 * `sys/modules/oxfs`'s roster grew), then 0x4080000 (64 MiB + 0x80000), which got swallowed the same
 * way again once the POSIX conformance pilot's own full-corpus expansion (see `build.rs`'s
 * `discover_posix_test_files`) roughly doubled the kernel image's own embedded content again.
 * 0x8080000 (128 MiB + 0x80000) leaves real headroom over the kernel's *current* size, not just
 * barely enough -- re-derive this by hand (`readelf -l target/x86_64-oxidebsd/debug/oxidebsd |
 * grep -A1 LOAD`, highest `VirtAddr + MemSiz`) before adding anything with a fixed load address
 * below this floor. Confirmed clear the same way `stsh`'s own 0x8000000 and
 * `fork-exec-smoke`'s 0x8040000 already are. */
ENTRY(_start)

SECTIONS
{
    . = 0x8080000;

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    .data : {
        *(.data*)
    }

    .bss : {
        *(.bss*)
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note*)
    }
}
