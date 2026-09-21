/* Forces a load base clear of the kernel's own image, the kernel heap (0x444444440000), the
 * physical-memory-offset window (~0x18000000000), the bootloader's own identity-mapped
 * low-memory region (see ring3-smoke/linker.ld's comment for why the kernel's own image, not the
 * bootloader's fixed ~6 MiB, is the actually-binding one of those two today), and every other
 * userland crate's own fixed base (ring3-smoke 0x8080000, stsh 0x8000000) -- see
 * src/address_space.rs for why those regions matter: a new address space starts
 * as a shallow copy of the kernel's own page tables, so this binary's segments must not collide
 * with them. 0x8040000 (128 MiB + 0x40000), not the original 0x700000 or the later 0x4040000 --
 * see ring3-smoke/linker.ld's comment for the full story of why this floor moved (twice) and how
 * to re-derive it. */
ENTRY(_start)

SECTIONS
{
    . = 0x8040000;

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
